/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: deterministic regression for the two-node mutual-dial deadlock,
 * the core's lower-static-key tie-break, and the configured-inbound
 * header-sync rule (services/configured_sync_peers.h).
 *
 * Each model node owns a real struct connman with its Noise identity and its
 * -addnode targets. A connection is a real outbound p2p_node on the dialer
 * and a real inbound p2p_node on the listener, joined by a real in-memory
 * Noise XX handshake with each node's static key. The sealed eviction
 * (connman_evict_same_ip_inbound_when_outbound) runs at exactly the two
 * points msg_version.c calls it: the listener's inbound VERSION and the
 * dialer's VERACK. A closed session reaches the other side as the socket
 * reactor's remote close. A reconnect cycle asks the core's own addnode
 * picker whether each node would dial again. The header-sync decision is the
 * product entry point syncsvc_begin_peer_sync. The identity prober and the
 * clocks are injected, so no model case depends on sockets or wall-clock
 * timing. The probe cases run the real prober against loopback listeners
 * (Noise, silent, trickling, holding) and the real probe thread with a gated
 * prober; every wait there is bounded, and none is a sleep.
 * Part of the sync_service group (test_sync_service.c calls the entry). */

#include "test/test_core.h"
#include "chain/chain.h"
#include "chain/chainparams.h"
#include "core/uint256.h"
#include "jobs/tip_finalize_stage.h"
#include "net/connman.h"
#include "net/download.h"
#include "net/net.h"
#include "net/noise_transport.h"
#include "services/body_backfill_service.h"
#include "services/configured_sync_peers.h"
#include "storage/body_history.h"
#include "storage/progress_store.h"
#include "sync/sync_planner.h"
#include "sync/sync_state.h"
#include "platform/socket_compat.h"
#include "platform/time_compat.h"
#include "util/safe_alloc.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"

#include <inttypes.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

#define MODEL_MAX_NODES 4
#define MODEL_MAX_CONNS 16
#define MODEL_RECONNECT_CYCLES 4

struct model_node {
    const char *name;
    uint8_t ip[4];
    uint16_t port;
    uint8_t priv[32];
    uint8_t pub[32];
    bool up;
    struct connman cm;
};

struct model_conn {
    struct model_node *dialer;
    struct model_node *listener;
    struct p2p_node *out;   /* on dialer->cm */
    struct p2p_node *in;    /* on listener->cm */
    bool verack_sent;       /* the listener processed VERSION and replied */
};

static struct model_node *g_model[MODEL_MAX_NODES];
static size_t g_model_count;
static int64_t g_model_now = 1000;
static int g_probe_calls;
static uint8_t g_probe_priv[32];

static int64_t model_clock(void) { return g_model_now; }

static void model_key(uint8_t out[32], uint8_t seed)
{
    for (int i = 0; i < 32; i++)
        out[i] = (uint8_t)(seed * 31 + i * 7 + 1);
}

/* A real Noise XX handshake between two static keys, in memory. */
static bool noise_pair(const uint8_t init_priv[32], const uint8_t resp_priv[32],
                       struct noise_transport **init_out,
                       struct noise_transport **resp_out)
{
    const unsigned char *magic = chain_params_get()->pchMessageStart;
    uint8_t *m1 = NULL, *m2 = NULL, *m3 = NULL, *m4 = NULL;
    uint8_t *p = NULL;
    size_t m1n = 0, m2n = 0, m3n = 0, m4n = 0, pn = 0;
    struct noise_transport *i =
        noise_transport_begin(true, init_priv, magic, &m1, &m1n);
    struct noise_transport *r =
        noise_transport_begin(false, resp_priv, magic, NULL, NULL);
    bool ok = i && r &&
              noise_transport_feed(r, m1, m1n, &m2, &m2n, &p, &pn);
    free(p); p = NULL;
    ok = ok && noise_transport_feed(i, m2, m2n, &m3, &m3n, &p, &pn);
    free(p); p = NULL;
    ok = ok && noise_transport_feed(r, m3, m3n, &m4, &m4n, &p, &pn);
    free(p);
    free(m1); free(m2); free(m3); free(m4);
    struct noise_transport_snapshot si, sr;
    ok = ok && noise_transport_snapshot(i, &si) &&
         noise_transport_snapshot(r, &sr);
    if (!ok) {
        noise_transport_free(i);
        noise_transport_free(r);
        return false;
    }
    *init_out = i;
    *resp_out = r;
    return true;
}

static bool model_public_key(const uint8_t priv[32], uint8_t pub[32])
{
    uint8_t other[32];
    model_key(other, 250);
    struct noise_transport *i = NULL, *r = NULL;
    if (!noise_pair(other, priv, &i, &r))
        return false;
    struct noise_transport_snapshot si;
    bool ok = noise_transport_snapshot(i, &si);
    if (ok)
        memcpy(pub, si.remote_static, 32);
    noise_transport_free(i);
    noise_transport_free(r);
    return ok;
}

/* The injected prober: complete XX against the node listening at `target`. */
static bool model_prober(const struct net_service *target, uint8_t out[32])
{
    g_probe_calls++;
    for (size_t k = 0; k < g_model_count; k++) {
        struct model_node *m = g_model[k];
        struct net_service svc;
        memset(&svc, 0, sizeof(svc));
        net_addr_set_ipv4(&svc.addr, m->ip);
        svc.port = m->port;
        if (!m->up || !net_service_eq(&svc, target))
            continue;
        struct noise_transport *i = NULL, *r = NULL;
        if (!noise_pair(g_probe_priv, m->priv, &i, &r))
            return false;
        struct noise_transport_snapshot si;
        bool ok = noise_transport_snapshot(i, &si);
        if (ok)
            memcpy(out, si.remote_static, 32);
        noise_transport_free(i);
        noise_transport_free(r);
        return ok;
    }
    return false;
}

static bool model_node_init(struct model_node *m, const char *name,
                            uint8_t last_octet, uint16_t port, uint8_t key)
{
    memset(m, 0, sizeof(*m));
    m->name = name;
    m->ip[0] = 198; m->ip[1] = 51; m->ip[2] = 100; m->ip[3] = last_octet;
    m->port = port;
    m->up = true;
    model_key(m->priv, key);
    struct node_signals sigs;
    memset(&sigs, 0, sizeof(sigs));
    if (!connman_init(&m->cm, chain_params_get(), &sigs))
        return false;
    /* connman_init leaves the node array to its first accept; the model
     * attaches nodes directly, as the connman fixtures do. */
    m->cm.manager.nodes = zcl_calloc(MODEL_MAX_CONNS * 2,
                                     sizeof(*m->cm.manager.nodes),
                                     "configured_inbound_model_nodes");
    m->cm.manager.nodes_cap = MODEL_MAX_CONNS * 2;
    if (g_model_count < MODEL_MAX_NODES)
        g_model[g_model_count++] = m;
    if (!m->cm.manager.nodes || !model_public_key(m->priv, m->pub))
        return false;
    memcpy(m->cm.manager.identity_priv, m->priv, 32);
    memcpy(m->cm.manager.identity_pub, m->pub, 32);
    m->cm.manager.noise_enabled = true;
    return true;
}

static void model_swap_keys(struct model_node *x, struct model_node *y)
{
    uint8_t priv[32], pub[32];
    memcpy(priv, x->priv, 32);
    memcpy(pub, x->pub, 32);
    memcpy(x->priv, y->priv, 32);
    memcpy(x->pub, y->pub, 32);
    memcpy(y->priv, priv, 32);
    memcpy(y->pub, pub, 32);
    memcpy(x->cm.manager.identity_priv, x->priv, 32);
    memcpy(x->cm.manager.identity_pub, x->pub, 32);
    memcpy(y->cm.manager.identity_priv, y->priv, 32);
    memcpy(y->cm.manager.identity_pub, y->pub, 32);
}

/* Give `lo` the lower Noise static public key of the two. */
static void model_order_keys(struct model_node *lo, struct model_node *hi)
{
    if (memcmp(lo->pub, hi->pub, 32) > 0)
        model_swap_keys(lo, hi);
}

static void model_reset(void)
{
    for (size_t k = 0; k < g_model_count; k++)
        connman_free(&g_model[k]->cm);
    g_model_count = 0;
    configured_sync_peers_reset_for_testing();
    configured_sync_peers_set_prober_for_testing(model_prober);
    configured_sync_peers_set_clock_for_testing(model_clock);
    g_probe_calls = 0;
    g_model_now = 1000;
    model_key(g_probe_priv, 200);
}

/* `m` names `target` with -addnode: an addnode entry in m's connman and an
 * operator-named sync peer. The sync-peer table is process-wide; each model
 * node owns a distinct target set by construction in these scenarios. */
static bool model_configure(struct model_node *m, const struct model_node *target)
{
    struct net_address addr;
    net_address_init(&addr);
    net_addr_set_ipv4(&addr.svc.addr, target->ip);
    addr.svc.port = target->port;
    bool listed = false;
    for (int ai = 0; ai < m->cm.num_addnodes; ai++)
        listed = listed || net_service_eq(&m->cm.addnodes[ai].svc, &addr.svc);
    if (!listed && m->cm.num_addnodes >= MAX_ADDNODES)
        return false;
    if (!listed)
        m->cm.addnodes[m->cm.num_addnodes++] = addr;
    return configured_sync_peer_note(&addr.svc);
}

static struct p2p_node *model_attach(struct model_node *m,
                                     const uint8_t ip[4], uint16_t port,
                                     bool inbound,
                                     struct noise_transport *transport)
{
    struct net_address addr;
    net_address_init(&addr);
    net_addr_set_ipv4(&addr.svc.addr, ip);
    addr.svc.port = port;
    struct p2p_node *n = m->cm.manager.num_nodes < m->cm.manager.nodes_cap
        ? p2p_node_create(&m->cm.manager, ZCL_INVALID_SOCKET, &addr, m->name,
                          inbound)
        : NULL;
    if (!n) {
        noise_transport_free(transport);
        return NULL;
    }
    n->state = PEER_VERSION_SENT;
    n->starting_height = 100;
    n->services = NODE_NETWORK;
    n->transport = transport;
    m->cm.manager.nodes[m->cm.manager.num_nodes++] = n;
    return n;
}

/* `dialer` opens a TCP connection to `listener` presenting `key_priv` as its
 * Noise static (normally its own key; an impostor sharing the dialer's IP
 * presents another). `noise` false models a plaintext session. */
static bool model_connect(struct model_conn *c, struct model_node *dialer,
                          struct model_node *listener,
                          const uint8_t key_priv[32], bool noise,
                          uint16_t source_port)
{
    struct noise_transport *ti = NULL, *tr = NULL;
    if (noise && !noise_pair(key_priv, listener->priv, &ti, &tr))
        return false;
    c->dialer = dialer;
    c->listener = listener;
    c->out = model_attach(dialer, listener->ip, listener->port, false, ti);
    c->in = model_attach(listener, dialer->ip, source_port, true, tr);
    c->verack_sent = false;
    return c->out && c->in;
}

/* msg_version.c: the listener marks the inbound session complete after
 * processing the dialer's VERSION, then runs the sealed eviction. */
static void ev_inbound_version(struct model_conn *c)
{
    /* An inbound session already evicted never processes the VERSION, so it
     * never sends the VERSION+VERACK the dialer is waiting for. */
    if (c->in->disconnect || c->out->disconnect)
        return;
    c->in->state = PEER_HANDSHAKE_COMPLETE;
    c->verack_sent = true;
    connman_evict_same_ip_inbound_when_outbound(&c->listener->cm, c->in);
}

/* msg_version.c: the dialer completes on VERACK, then runs the eviction.
 * The VERACK exists only once the listener processed the VERSION. */
static void ev_outbound_verack(struct model_conn *c)
{
    if (!c->verack_sent || c->out->disconnect)
        return;
    c->out->state = PEER_HANDSHAKE_COMPLETE;
    connman_evict_same_ip_inbound_when_outbound(&c->dialer->cm, c->out);
}

/* A side that was disconnected closes the socket, so the other side sees a
 * remote close (the socket reactor reports it for a pre-handshake addnode
 * dial); msg_send_messages then promotes survivors to ACTIVE. */
static void model_settle(struct model_conn *conns, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        bool in_gone = conns[i].in->disconnect || !conns[i].listener->up;
        bool out_gone = conns[i].out->disconnect || !conns[i].dialer->up;
        if (in_gone && !out_gone)
            connman_note_addnode_prehandshake_disconnect(
                &conns[i].dialer->cm, conns[i].out, "remote-close");
        if (in_gone || out_gone) {
            conns[i].in->disconnect = true;
            conns[i].out->disconnect = true;
        }
    }
    for (size_t i = 0; i < n; i++) {
        if (!conns[i].in->disconnect &&
            conns[i].in->state == PEER_HANDSHAKE_COMPLETE)
            conns[i].in->state = PEER_ACTIVE;
        if (!conns[i].out->disconnect &&
            conns[i].out->state == PEER_HANDSHAKE_COMPLETE)
            conns[i].out->state = PEER_ACTIVE;
    }
}

/* One product tick for `n`: may it become a header source? */
static bool model_begin(struct p2p_node *n)
{
    sync_set_state(SYNC_IDLE, "configured inbound model reset");
    (void)sync_set_state(SYNC_FINDING_PEERS, "configured inbound model");
    bool began = syncsvc_begin_peer_sync(n, 0, 0);
    if (began)
        n->state = PEER_ACTIVE;
    return began;
}

/* Does `m` have at least one live session it may sync headers from? Two
 * ticks: the first may schedule the identity probe (synchronous here). */
static bool model_has_header_source(struct model_node *m)
{
    for (int tick = 0; tick < 2; tick++) {
        for (size_t i = 0; i < m->cm.manager.num_nodes; i++) {
            struct p2p_node *n = m->cm.manager.nodes[i];
            if (n->disconnect || n->state != PEER_ACTIVE)
                continue;
            if (model_begin(n))
                return true;
        }
    }
    return false;
}

static size_t model_live_sessions(const struct model_conn *conns, size_t n)
{
    size_t live = 0;
    for (size_t i = 0; i < n; i++)
        live += !conns[i].in->disconnect && conns[i].in->state == PEER_ACTIVE;
    return live;
}

/* Exactly one session is live, both of its halves are ACTIVE, and `dialer`
 * dialed it. */
static bool model_only_session_dialed_by(const struct model_conn *conns,
                                         size_t n,
                                         const struct model_node *dialer)
{
    size_t live = 0;
    bool by_dialer = false;
    for (size_t i = 0; i < n; i++) {
        bool in_live = !conns[i].in->disconnect &&
                       conns[i].in->state == PEER_ACTIVE;
        bool out_live = !conns[i].out->disconnect &&
                        conns[i].out->state == PEER_ACTIVE;
        if (in_live != out_live)
            return false;             /* the two sides disagree */
        if (in_live) {
            live++;
            by_dialer = conns[i].dialer == dialer;
        }
    }
    return live == 1 && by_dialer;
}

/* The target the core's addnode picker would dial next for `m` once every
 * cooldown has elapsed, or NULL when every addnode target is connected. */
static struct model_node *model_redial_target(struct model_node *m)
{
    for (int ai = 0; ai < m->cm.num_addnodes; ai++) {
        m->cm.addnode_last_attempt[ai] = 0;
        m->cm.addnode_backoff_sec[ai] = 0;
        m->cm.addnode_retired[ai] = false;
    }
    size_t cursor = 0, index = SIZE_MAX;
    struct addr_info info;
    enum connman_outbound_target_source source = CONNMAN_TARGET_NONE;
    if (!connman_pick_next_outbound_target(&m->cm, &cursor, &info, &source,
                                           &index) ||
        source != CONNMAN_TARGET_ADDNODE)
        return NULL;
    for (size_t k = 0; k < g_model_count; k++) {
        struct net_service svc;
        memset(&svc, 0, sizeof(svc));
        net_addr_set_ipv4(&svc.addr, g_model[k]->ip);
        svc.port = g_model[k]->port;
        if (net_service_eq(&svc, &info.addr.svc))
            return g_model[k];
    }
    return NULL;
}

/* One reconnect cycle: every live node whose picker names a target dials it
 * with its own key; the new connection runs VERSION, then VERACK unless the
 * listener evicted the inbound and `lose` drops the reply. Returns the number
 * of dials, or SIZE_MAX when the model runs out of room. */
static size_t model_reconnect_cycle(struct model_conn *conns, size_t *n,
                                    bool lose)
{
    size_t dials = 0;
    for (size_t k = 0; k < g_model_count; k++) {
        struct model_node *m = g_model[k];
        struct model_node *t = m->up ? model_redial_target(m) : NULL;
        if (!t)
            continue;
        dials++;
        if (!t->up)
            continue;                 /* the TCP connect fails */
        if (*n >= MODEL_MAX_CONNS)
            return SIZE_MAX;
        struct model_conn *c = &conns[*n];
        if (!model_connect(c, m, t, m->priv, true,
                           (uint16_t)(41000 + *n)))
            return SIZE_MAX;
        (*n)++;
        ev_inbound_version(c);
        if (!(lose && c->in->disconnect))
            ev_outbound_verack(c);
        model_settle(conns, *n);
    }
    return dials;
}

/* Redials over MODEL_RECONNECT_CYCLES cycles; SIZE_MAX on model overflow. */
static size_t model_reconnect_cycles(struct model_conn *conns, size_t *n,
                                     bool lose)
{
    size_t total = 0;
    for (int cycle = 0; cycle < MODEL_RECONNECT_CYCLES; cycle++) {
        size_t dials = model_reconnect_cycle(conns, n, lose);
        if (dials == SIZE_MAX)
            return SIZE_MAX;
        total += dials;
    }
    return total;
}

/* Apply the four handshake events in `order` (0=V1 1=K1 2=V2 3=K2). A
 * VERACK already on the wire when its inbound half was evicted is delivered
 * or lost per `lose` (bit i for connection i): TCP may hand it over before
 * the close or not. */
static void apply_handshake_events(struct model_conn conns[2],
                                   const int order[4], unsigned lose)
{
    for (int e = 0; e < 4; e++) {
        struct model_conn *c = &conns[order[e] / 2];
        bool lost = c->in->disconnect && (lose & (1u << (order[e] / 2)));
        if (order[e] % 2 == 0)
            ev_inbound_version(c);
        else if (!lost)
            ev_outbound_verack(c);
    }
}

static const int k_orders[][4] = {
    {0, 1, 2, 3}, {0, 2, 1, 3}, {0, 2, 3, 1},
    {2, 0, 1, 3}, {2, 0, 3, 1}, {2, 3, 0, 1},
};
#define MODEL_ORDER_COUNT (sizeof(k_orders) / sizeof(k_orders[0]))

struct interleaving_tally {
    size_t runs;
    size_t zero_survivors;   /* no session left after the handshakes */
    size_t wrong_session;    /* a survivor other than the lower key's dial */
    size_t no_source;        /* a node without a header source */
    size_t redials;          /* picker dials over the reconnect cycles */
    size_t unstable;         /* not exactly the lower key's dial afterwards */
};

/* Two nodes that addnode each other, one dial in each direction. `a_lower`
 * gives A the lower static key. */
static bool run_two_node_interleaving(const int order[4], unsigned lose,
                                      bool a_lower,
                                      struct interleaving_tally *t)
{
    static struct model_node a, b;
    struct model_conn conns[MODEL_MAX_CONNS];
    size_t n = 2;
    model_reset();
    bool ok = model_node_init(&a, "A", 7, 18233, 1) &&
              model_node_init(&b, "B", 8, 18234, 2);
    if (ok && a_lower)
        model_order_keys(&a, &b);
    else if (ok)
        model_order_keys(&b, &a);
    ok = ok && model_configure(&a, &b) && model_configure(&b, &a) &&
         model_connect(&conns[0], &a, &b, a.priv, true, 40001) &&
         model_connect(&conns[1], &b, &a, b.priv, true, 40002);
    if (!ok) {
        model_reset();
        return false;
    }
    const struct model_node *lower = a_lower ? &a : &b;
    t->runs++;
    apply_handshake_events(conns, order, lose);
    model_settle(conns, 2);
    if (model_live_sessions(conns, 2) == 0) {
        t->zero_survivors++;
    } else {
        t->wrong_session += !model_only_session_dialed_by(conns, 2, lower);
        bool a_src = model_has_header_source(&a);
        bool b_src = model_has_header_source(&b);
        if (!a_src || !b_src) {
            printf("\n  order=%d%d%d%d lose=%u: A source=%d B source=%d",
                   order[0], order[1], order[2], order[3], lose, a_src, b_src);
            t->no_source++;
        }
    }
    size_t redials = model_reconnect_cycles(conns, &n, lose & 1u);
    ok = redials != SIZE_MAX;
    t->redials += ok ? redials : 0;
    t->unstable += !model_only_session_dialed_by(conns, n, lower);
    model_reset();
    return ok;
}

static int test_configured_inbound_every_interleaving(void)
{
    int failures = 0;
    TEST("mutual dial: every A/B handshake interleaving, with either node "
         "holding the lower key, keeps exactly the lower key's dial on both "
         "sides, gives both nodes a header source, and never redials over "
         "the reconnect cycles") {
        struct interleaving_tally t;
        memset(&t, 0, sizeof(t));
        for (int lower = 0; lower < 2; lower++)
            for (size_t o = 0; o < MODEL_ORDER_COUNT; o++)
                for (unsigned lose = 0; lose < 4; lose++)
                    ASSERT(run_two_node_interleaving(k_orders[o], lose,
                                                     lower == 0, &t));
        printf("[%zu interleavings: %zu no session, %zu wrong session, "
               "%zu without a source, %zu redials, %zu unstable] ",
               t.runs, t.zero_survivors, t.wrong_session, t.no_source,
               t.redials, t.unstable);
        ASSERT(t.runs == 2 * MODEL_ORDER_COUNT * 4);
        ASSERT(t.zero_survivors == 0);
        ASSERT(t.wrong_session == 0);
        ASSERT(t.no_source == 0);
        ASSERT(t.redials == 0);
        ASSERT(t.unstable == 0);
        PASS();
    } _test_next:;
    return failures;
}

static int test_mutual_dial_plaintext_unchanged(void)
{
    int failures = 0;
    TEST("mutual dial: plaintext sessions keep the same-IP eviction exactly: "
         "a handshaked outbound evicts every inbound from its IP, so 8 of "
         "the 24 interleavings still leave no session") {
        struct interleaving_tally t;
        memset(&t, 0, sizeof(t));
        for (size_t o = 0; o < MODEL_ORDER_COUNT; o++) {
            for (unsigned lose = 0; lose < 4; lose++) {
                static struct model_node a, b;
                struct model_conn conns[2];
                model_reset();
                ASSERT(model_node_init(&a, "A", 7, 18233, 1));
                ASSERT(model_node_init(&b, "B", 8, 18234, 2));
                ASSERT(model_configure(&a, &b) && model_configure(&b, &a));
                ASSERT(model_connect(&conns[0], &a, &b, a.priv, false, 40001));
                ASSERT(model_connect(&conns[1], &b, &a, b.priv, false, 40002));
                apply_handshake_events(conns, k_orders[o], lose);
                /* Today's rule: a node holding a handshaked outbound keeps
                 * no inbound from the same IP. */
                for (int c = 0; c < 2; c++) {
                    const struct p2p_node *listener_out = conns[1 - c].out;
                    ASSERT(listener_out->disconnect ||
                           listener_out->state < PEER_HANDSHAKE_COMPLETE ||
                           conns[c].in->disconnect);
                }
                model_settle(conns, 2);
                t.runs++;
                t.zero_survivors += model_live_sessions(conns, 2) == 0;
                model_reset();
            }
        }
        printf("[%zu plaintext interleavings, %zu with no session] ", t.runs,
               t.zero_survivors);
        ASSERT(t.runs == 24);
        ASSERT(t.zero_survivors == 8);
        PASS();
    } _test_next:;
    model_reset();
    return failures;
}

/* A (the lower key) and B configure each other. One dials and settles, then
 * the other dials back; `lose` drops a VERACK whose inbound half was
 * evicted. Returns the first failed step, or NULL. */
static const char *model_serial_dials(struct model_node *a,
                                      struct model_node *b,
                                      struct model_conn conns[2],
                                      bool lower_first, bool lose)
{
    model_reset();
    if (!model_node_init(a, "A", 7, 18233, 1) ||
        !model_node_init(b, "B", 8, 18234, 2))
        return "init";
    model_order_keys(a, b);
    if (!model_configure(a, b) || !model_configure(b, a))
        return "configure";
    struct model_node *d1 = lower_first ? a : b;
    struct model_node *d2 = lower_first ? b : a;
    if (!model_connect(&conns[0], d1, d2, d1->priv, true, 40001))
        return "first dial";
    ev_inbound_version(&conns[0]);
    ev_outbound_verack(&conns[0]);
    model_settle(conns, 1);
    if (!model_connect(&conns[1], d2, d1, d2->priv, true, 40002))
        return "second dial";
    ev_inbound_version(&conns[1]);
    if (!(lose && conns[1].in->disconnect))
        ev_outbound_verack(&conns[1]);
    model_settle(conns, 2);
    return NULL;
}

static const char *run_serial_dials(bool lower_first, bool lose)
{
    static struct model_node a, b;
    struct model_conn conns[MODEL_MAX_CONNS];
    size_t n = 2;
    const char *why = model_serial_dials(&a, &b, conns, lower_first, lose);
    if (why)
        return why;
    if (!model_only_session_dialed_by(conns, 2, &a))
        return "exactly A's dial survives on both sides";
    /* B holds only A's inbound session: the deadlock shape. */
    struct p2p_node *kept_in = conns[lower_first ? 0 : 1].in;
    if (!model_has_header_source(&a) || !model_has_header_source(&b))
        return "both nodes have a header source";
    if (g_probe_calls != 1 || !syncsvc_peer_is_configured_inbound(kept_in))
        return "B proves A's identity on the kept inbound";
    if (model_reconnect_cycles(conns, &n, lose) != 0 || n != 2)
        return "no redial over the reconnect cycles";
    model_reset();
    return NULL;
}

static int test_mutual_dial_lower_key_dials_first(void)
{
    int failures = 0;
    TEST("mutual dial: the lower-key node dials first — both keep its dial, "
         "the inbound-only side syncs from the proven identity and never "
         "redials") {
        for (int lose = 0; lose < 2; lose++) {
            const char *why = run_serial_dials(true, lose);
            if (why)
                printf("\n  lose=%d: %s", lose, why);
            ASSERT(!why);
        }
        PASS();
    } _test_next:;
    model_reset();
    return failures;
}

static int test_mutual_dial_higher_key_dials_first(void)
{
    int failures = 0;
    TEST("mutual dial: the higher-key node dials first — when the lower-key "
         "node dials back, both keep the lower key's dial and the higher-key "
         "node never redials") {
        for (int lose = 0; lose < 2; lose++) {
            const char *why = run_serial_dials(false, lose);
            if (why)
                printf("\n  lose=%d: %s", lose, why);
            ASSERT(!why);
        }
        PASS();
    } _test_next:;
    model_reset();
    return failures;
}

static int test_mutual_dial_simultaneous(void)
{
    int failures = 0;
    TEST("mutual dial: simultaneous dials, where both VERSIONs cross before "
         "either VERACK, keep exactly the lower key's dial on both sides") {
        static const int crossed[][4] = {
            {0, 2, 1, 3}, {0, 2, 3, 1}, {2, 0, 1, 3}, {2, 0, 3, 1},
        };
        struct interleaving_tally t;
        memset(&t, 0, sizeof(t));
        for (int lower = 0; lower < 2; lower++)
            for (size_t o = 0; o < 4; o++)
                for (unsigned lose = 0; lose < 4; lose++)
                    ASSERT(run_two_node_interleaving(crossed[o], lose,
                                                     lower == 0, &t));
        printf("[%zu crossed dials: %zu no session, %zu wrong session] ",
               t.runs, t.zero_survivors, t.wrong_session);
        ASSERT(t.zero_survivors == 0 && t.wrong_session == 0);
        ASSERT(t.no_source == 0 && t.redials == 0 && t.unstable == 0);
        PASS();
    } _test_next:;
    model_reset();
    return failures;
}

static int test_mutual_dial_decision_log_rate_limited(void)
{
    int failures = 0;
    TEST("mutual dial: each tie-break decision logs one named line, and a "
         "flapping peer's repeats are rate limited") {
        static struct model_node lo, hi;
        model_reset();
        ASSERT(model_node_init(&lo, "L", 7, 18233, 30));
        ASSERT(model_node_init(&hi, "H", 8, 18234, 31));
        model_order_keys(&lo, &hi);
        struct model_conn c[MODEL_MAX_CONNS];
        uint64_t before = connman_mutual_dial_log_lines_for_test();
        /* H decides for six flaps of the same pair: one line. */
        for (size_t i = 0; i + 1 < 12; i += 2) {
            ASSERT(model_connect(&c[i], &hi, &lo, hi.priv, true,
                                 (uint16_t)(42000 + i)));
            ASSERT(model_connect(&c[i + 1], &lo, &hi, lo.priv, true,
                                 (uint16_t)(42001 + i)));
            c[i].out->state = PEER_HANDSHAKE_COMPLETE;
            c[i + 1].in->state = PEER_HANDSHAKE_COMPLETE;
            connman_evict_same_ip_inbound_when_outbound(&hi.cm, c[i + 1].in);
            ASSERT(c[i].out->disconnect && !c[i + 1].in->disconnect);
            c[i].in->disconnect = c[i + 1].in->disconnect = true;
            c[i + 1].out->disconnect = true;
        }
        ASSERT(connman_mutual_dial_log_lines_for_test() - before == 1);
        /* L's decision names the other key: its own line. */
        ASSERT(model_connect(&c[12], &lo, &hi, lo.priv, true, 42100));
        ASSERT(model_connect(&c[13], &hi, &lo, hi.priv, true, 42101));
        c[12].out->state = PEER_HANDSHAKE_COMPLETE;
        c[13].in->state = PEER_HANDSHAKE_COMPLETE;
        connman_evict_same_ip_inbound_when_outbound(&lo.cm, c[13].in);
        ASSERT(!c[12].out->disconnect && c[13].in->disconnect);
        ASSERT(connman_mutual_dial_log_lines_for_test() - before == 2);
        PASS();
    } _test_next:;
    model_reset();
    return failures;
}

/* Two configured nodes, A with the lower key, settled on A's dial. */
static bool model_converged_pair(struct model_node *a, struct model_node *b,
                                 struct model_conn *conns, size_t *n)
{
    model_reset();
    if (!model_node_init(a, "A", 7, 18233, 1) ||
        !model_node_init(b, "B", 8, 18234, 2))
        return false;
    model_order_keys(a, b);
    if (!model_configure(a, b) || !model_configure(b, a) ||
        !model_connect(&conns[0], a, b, a->priv, true, 40001) ||
        !model_connect(&conns[1], b, a, b->priv, true, 40002))
        return false;
    static const int simultaneous[4] = {0, 2, 1, 3};
    apply_handshake_events(conns, simultaneous, 0);
    model_settle(conns, 2);
    *n = 2;
    return model_only_session_dialed_by(conns, 2, a);
}

static int test_mutual_dial_reconnect_after_publisher_loss(void)
{
    int failures = 0;
    TEST("mutual dial: after either node is lost and returns, the pair "
         "settles on the lower key's dial again and then stops dialing") {
        for (int lost = 0; lost < 2; lost++) {
            static struct model_node a, b;
            struct model_conn conns[MODEL_MAX_CONNS];
            size_t n = 0;
            ASSERT(model_converged_pair(&a, &b, conns, &n));
            struct model_node *gone = lost == 0 ? &a : &b;
            gone->up = false;
            model_settle(conns, n);
            ASSERT(model_live_sessions(conns, n) == 0);
            /* The survivor keeps asking for its target while it is away. */
            struct model_node *survivor = lost == 0 ? &b : &a;
            ASSERT(model_redial_target(survivor) == gone);
            gone->up = true;
            size_t first = model_reconnect_cycle(conns, &n, true);
            ASSERT(first != SIZE_MAX && first >= 1);
            size_t later = model_reconnect_cycles(conns, &n, true);
            ASSERT(later != SIZE_MAX);
            size_t settled = model_reconnect_cycles(conns, &n, true);
            printf("[lost %s: %zu, %zu, then %zu dials] ", gone->name, first,
                   later, settled);
            ASSERT(settled == 0);
            ASSERT(model_only_session_dialed_by(conns, n, &a));
            ASSERT(model_has_header_source(&a));
            ASSERT(model_has_header_source(&b));
            model_reset();
        }
        PASS();
    } _test_next:;
    model_reset();
    return failures;
}

static int test_mutual_dial_impostor_has_no_privilege(void)
{
    int failures = 0;
    TEST("mutual dial: a lower key at the configured IP that is not the "
         "target's key neither displaces the outbound nor holds the target") {
        static struct model_node a, b, impostor;
        model_reset();
        ASSERT(model_node_init(&a, "A", 7, 18233, 1));
        ASSERT(model_node_init(&b, "B", 8, 18234, 2));
        ASSERT(model_node_init(&impostor, "X", 7, 18299, 9)); /* A's IP */
        model_order_keys(&a, &b);
        model_order_keys(&impostor, &b);      /* X's key is below B's */
        ASSERT(memcmp(impostor.pub, b.pub, 32) < 0);
        ASSERT(model_configure(&b, &a));
        struct model_conn c[3];

        /* B holds its own handshaked dial to A; X dials B from A's IP. */
        ASSERT(model_connect(&c[0], &b, &a, b.priv, true, 40001));
        ev_inbound_version(&c[0]);
        ev_outbound_verack(&c[0]);
        ASSERT(model_connect(&c[1], &a, &b, impostor.priv, true, 40002));
        ev_inbound_version(&c[1]);
        ASSERT(c[1].in->disconnect);              /* today's eviction */
        ASSERT(!c[0].out->disconnect);
        model_settle(c, 2);
        ASSERT(model_redial_target(&b) == NULL);

        /* B learned A's key when it yielded to A's dial. Once A's session is
         * gone, X's session from A's IP does not stand in for the target. */
        struct model_conn conns[MODEL_MAX_CONNS];
        size_t n = 0;
        ASSERT(model_converged_pair(&a, &b, conns, &n));
        ASSERT(model_redial_target(&b) == NULL);
        ASSERT(model_node_init(&impostor, "X", 7, 18299, 9));
        for (uint8_t seed = 10;                 /* any key below B's */
             memcmp(impostor.pub, b.pub, 32) >= 0 && seed < 64; seed++) {
            model_key(impostor.priv, seed);
            ASSERT(model_public_key(impostor.priv, impostor.pub));
        }
        ASSERT(memcmp(impostor.pub, b.pub, 32) < 0 &&
               memcmp(impostor.pub, a.pub, 32) != 0);
        conns[0].in->disconnect = conns[0].out->disconnect = true;
        ASSERT(model_connect(&conns[n], &a, &b, impostor.priv, true, 40003));
        ev_inbound_version(&conns[n]);
        n++;
        model_settle(conns, n);
        ASSERT(!conns[n - 1].in->disconnect);
        ASSERT(model_redial_target(&b) == &a);
        PASS();
    } _test_next:;
    model_reset();
    return failures;
}

static int test_mutual_dial_target_binds_the_dialed_key(void)
{
    int failures = 0;
    TEST("mutual dial: only an inbound carrying the exact key this node "
         "authenticated on its own dial to the target satisfies the target — "
         "another key at the target's address, or that key from another "
         "address, leaves the target to redial") {
        static struct model_node a, b, foreign;
        struct model_conn conns[MODEL_MAX_CONNS];
        size_t n = 0;
        /* B yields to A's dial and records the key it authenticated. */
        ASSERT(model_converged_pair(&a, &b, conns, &n));
        ASSERT(model_node_init(&foreign, "F", 66, 18237, 10));
        uint8_t x_priv[32], x_pub[32];
        for (uint8_t seed = 10;             /* a key below B's, not A's */
             seed < 64; seed++) {
            model_key(x_priv, seed);
            ASSERT(model_public_key(x_priv, x_pub));
            if (memcmp(x_pub, b.pub, 32) < 0 && memcmp(x_pub, a.pub, 32) != 0)
                break;
        }
        ASSERT(memcmp(x_pub, b.pub, 32) < 0 && memcmp(x_pub, a.pub, 32) != 0);
        conns[0].in->disconnect = conns[0].out->disconnect = true;
        model_settle(conns, n);

        /* Another key at the target's address does not hold the target. */
        ASSERT(model_connect(&conns[n], &a, &b, x_priv, true, 40003));
        ev_inbound_version(&conns[n]);
        n++;
        model_settle(conns, n);
        ASSERT(!conns[n - 1].in->disconnect);
        ASSERT(model_redial_target(&b) == &a);

        /* The recorded key from another address does not hold it either. */
        conns[n - 1].in->disconnect = conns[n - 1].out->disconnect = true;
        model_settle(conns, n);
        ASSERT(model_connect(&conns[n], &foreign, &b, a.priv, true, 40004));
        ev_inbound_version(&conns[n]);
        n++;
        model_settle(conns, n);
        ASSERT(!conns[n - 1].in->disconnect);
        ASSERT(model_redial_target(&b) == &a);

        /* The recorded key at the target's address does. */
        conns[n - 1].in->disconnect = conns[n - 1].out->disconnect = true;
        model_settle(conns, n);
        ASSERT(model_connect(&conns[n], &a, &b, a.priv, true, 40005));
        ev_inbound_version(&conns[n]);
        n++;
        model_settle(conns, n);
        ASSERT(!conns[n - 1].in->disconnect);
        ASSERT(model_redial_target(&b) == NULL);
        PASS();
    } _test_next:;
    model_reset();
    return failures;
}

static int test_mutual_dial_kept_side_stays_quiet(void)
{
    int failures = 0;
    TEST("mutual dial: after the tie-break neither side redials, even with "
         "every cooldown elapsed — the loser's target is satisfied by the "
         "kept inbound and the winner's own outbound is the kept session") {
        static struct model_node a, b;
        struct model_conn conns[MODEL_MAX_CONNS];
        size_t n = 0;
        model_reset();
        ASSERT(model_converged_pair(&a, &b, conns, &n));
        ASSERT(model_only_session_dialed_by(conns, n, &a));
        /* The winner keeps its own outbound, and that session holds the
         * target. */
        ASSERT(!conns[0].out->disconnect &&
               conns[0].out->state == PEER_ACTIVE);
        ASSERT(model_redial_target(&a) == NULL);
        /* The loser's target is satisfied by the kept inbound. */
        ASSERT(!conns[0].in->disconnect && conns[0].in->state == PEER_ACTIVE);
        ASSERT(model_redial_target(&b) == NULL);
        /* The quiet is the kept session itself: once it is gone, both sides
         * name the target again. */
        conns[0].in->disconnect = conns[0].out->disconnect = true;
        model_settle(conns, n);
        ASSERT(model_redial_target(&a) == &b);
        ASSERT(model_redial_target(&b) == &a);
        PASS();
    } _test_next:;
    model_reset();
    return failures;
}

static int test_mutual_dial_unconfigured_peer(void)
{
    int failures = 0;
    TEST("mutual dial: between unconfigured peers the tie-break still keeps "
         "one session, the configured-inbound rule stays off, and a "
         "stranger's inbound is not evicted") {
        static struct model_node a, b, stranger;
        model_reset();
        ASSERT(model_node_init(&a, "A", 7, 18233, 1));
        ASSERT(model_node_init(&b, "B", 8, 18234, 2));
        ASSERT(model_node_init(&stranger, "S", 66, 18236, 4));
        model_order_keys(&a, &b);
        struct model_conn c[3];
        ASSERT(model_connect(&c[0], &a, &b, a.priv, true, 40001));
        ASSERT(model_connect(&c[1], &b, &a, b.priv, true, 40002));
        static const int simultaneous[4] = {2, 0, 3, 1};
        apply_handshake_events(c, simultaneous, 0);
        model_settle(c, 2);
        ASSERT(model_only_session_dialed_by(c, 2, &a));
        ASSERT(!syncsvc_peer_is_configured_inbound(c[0].in));
        ASSERT(model_redial_target(&a) == NULL);
        ASSERT(model_redial_target(&b) == NULL);

        /* A stranger's authenticated inbound shares no IP with B's dials. */
        ASSERT(model_connect(&c[2], &stranger, &b, stranger.priv, true, 40003));
        ev_inbound_version(&c[2]);
        ev_outbound_verack(&c[2]);
        model_settle(c, 3);
        ASSERT(!c[2].in->disconnect && c[2].in->state == PEER_ACTIVE);
        ASSERT(model_live_sessions(c, 3) == 2);
        PASS();
    } _test_next:;
    model_reset();
    return failures;
}

static int test_configured_inbound_reconnect_reproves(void)
{
    int failures = 0;
    TEST("configured inbound: a reconnect proves the identity again; an "
         "impostor at the configured IP and a plaintext session are refused") {
        static struct model_node a, b, impostor;
        model_reset();
        ASSERT(model_node_init(&a, "A", 7, 18233, 1));
        ASSERT(model_node_init(&b, "B", 8, 18234, 2));
        ASSERT(model_node_init(&impostor, "X", 7, 18299, 9)); /* A's IP */
        impostor.up = false;  /* never answers at the configured address */
        ASSERT(model_configure(&b, &a));
        struct model_conn c[4];
        ASSERT(model_connect(&c[0], &a, &b, a.priv, true, 40001));
        ev_inbound_version(&c[0]);
        ev_outbound_verack(&c[0]);
        model_settle(c, 1);
        ASSERT(model_has_header_source(&b));
        ASSERT(g_probe_calls == 1);

        /* Drop. The same IP comes back with another static key. */
        c[0].in->disconnect = c[0].out->disconnect = true;
        ASSERT(model_connect(&c[1], &a, &b, impostor.priv, true, 40002));
        ev_inbound_version(&c[1]);
        model_settle(&c[1], 1);
        c[1].out->state = PEER_ACTIVE;
        ASSERT(!syncsvc_peer_is_configured_inbound(c[1].in));
        ASSERT(!model_begin(c[1].in));
        ASSERT(g_probe_calls == 1);          /* inside the retry window */
        g_model_now += CONFIGURED_SYNC_PEER_PROBE_RETRY_SECS;
        ASSERT(!model_begin(c[1].in));       /* re-probe still finds A's key */
        ASSERT(g_probe_calls == 2);
        ASSERT(!model_begin(c[1].in));
        ASSERT(g_probe_calls == 2);          /* bounded: one per window */

        /* A plaintext session from the configured IP never binds. */
        c[1].in->disconnect = c[1].out->disconnect = true;
        ASSERT(model_connect(&c[2], &a, &b, a.priv, false, 40003));
        ev_inbound_version(&c[2]);
        model_settle(&c[2], 1);
        ASSERT(!syncsvc_peer_is_configured_inbound(c[2].in));
        ASSERT(!model_begin(c[2].in));

        /* A's own key over a fresh session binds with no new probe. */
        c[2].in->disconnect = c[2].out->disconnect = true;
        ASSERT(model_connect(&c[3], &a, &b, a.priv, true, 40004));
        ev_inbound_version(&c[3]);
        model_settle(&c[3], 1);
        ASSERT(model_begin(c[3].in));
        ASSERT(g_probe_calls == 2);
        PASS();
    } _test_next:;
    model_reset();
    return failures;
}

static int test_configured_inbound_publisher_loss(void)
{
    int failures = 0;
    TEST("configured inbound: after A disappears, B still syncs from its "
         "other configured peer C") {
        static struct model_node a, b, cnode;
        model_reset();
        ASSERT(model_node_init(&a, "A", 7, 18233, 1));
        ASSERT(model_node_init(&b, "B", 8, 18234, 2));
        ASSERT(model_node_init(&cnode, "C", 9, 18235, 3));
        model_order_keys(&a, &b);
        model_order_keys(&cnode, &b);            /* B holds the highest key */
        ASSERT(model_configure(&b, &a) && model_configure(&b, &cnode));
        ASSERT(model_configure(&cnode, &b));
        struct model_conn c[4];
        /* A and C both win their races against B: B is inbound-only, and the
         * tie-break keeps C's lower-key dial over B's. */
        ASSERT(model_connect(&c[0], &a, &b, a.priv, true, 40001));
        ev_inbound_version(&c[0]);
        ev_outbound_verack(&c[0]);
        ASSERT(model_connect(&c[1], &cnode, &b, cnode.priv, true, 40002));
        ev_inbound_version(&c[1]);
        ev_outbound_verack(&c[1]);
        ASSERT(model_connect(&c[2], &b, &cnode, b.priv, true, 40003));
        ev_inbound_version(&c[2]);          /* C evicts B's dial */
        model_settle(c, 3);
        ASSERT(model_has_header_source(&b));

        /* The publisher goes away. */
        a.up = false;
        model_settle(c, 3);
        ASSERT(c[0].in->disconnect);
        ASSERT(!c[1].in->disconnect);
        ASSERT(syncsvc_peer_is_configured_inbound(c[1].in) ||
               model_begin(c[1].in));
        ASSERT(model_has_header_source(&b));
        ASSERT(model_has_header_source(&cnode));
        PASS();
    } _test_next:;
    model_reset();
    return failures;
}

static int test_configured_inbound_refusals(void)
{
    int failures = 0;
    TEST("configured inbound: unconfigured, mismatched, non-ACTIVE, "
         "loopback and onion inbound sessions are refused") {
        static struct model_node a, b, stranger;
        model_reset();
        ASSERT(model_node_init(&a, "A", 7, 18233, 1));
        ASSERT(model_node_init(&b, "B", 8, 18234, 2));
        ASSERT(model_node_init(&stranger, "S", 66, 18236, 4));
        ASSERT(model_configure(&b, &a));
        struct model_conn c[3];

        /* Unconfigured: a stranger's authenticated session. */
        ASSERT(model_connect(&c[0], &stranger, &b, stranger.priv, true, 40001));
        ev_inbound_version(&c[0]);
        model_settle(c, 1);
        ASSERT(!model_begin(c[0].in));
        ASSERT(g_probe_calls == 0);

        /* Configured IP, identity that is not the one at the address. */
        ASSERT(model_connect(&c[1], &a, &b, stranger.priv, true, 40002));
        ev_inbound_version(&c[1]);
        model_settle(&c[1], 1);
        ASSERT(!model_begin(c[1].in));
        ASSERT(g_probe_calls == 1);
        uint8_t learned[32];
        struct net_service target;
        memset(&target, 0, sizeof(target));
        net_addr_set_ipv4(&target.addr, a.ip);
        target.port = a.port;
        ASSERT(configured_sync_peer_identity(&target, learned));
        ASSERT(memcmp(learned, a.pub, 32) == 0);

        /* The right identity, but not PEER_ACTIVE. */
        ASSERT(model_connect(&c[2], &a, &b, a.priv, true, 40003));
        c[2].in->state = PEER_HANDSHAKE_COMPLETE;
        ASSERT(syncsvc_peer_is_configured_inbound(c[2].in));
        ASSERT(!syncsvc_should_begin_peer_sync(c[2].in, 0, 0,
                                               SYNC_FINDING_PEERS));
        c[2].in->state = PEER_ACTIVE;
        ASSERT(syncsvc_should_begin_peer_sync(c[2].in, 0, 0,
                                              SYNC_FINDING_PEERS));

        /* Loopback and Tor targets are never recorded, so a loopback or
         * onion inbound never binds. */
        struct net_service loop;
        memset(&loop, 0, sizeof(loop));
        net_addr_set_ipv4(&loop.addr, (const unsigned char[4]){127, 0, 0, 1});
        loop.port = 18233;
        ASSERT(!configured_sync_peer_note(&loop));
        struct net_service onion;
        memset(&onion, 0, sizeof(onion));
        onion.addr.has_torv3 = true;
        onion.addr.torv3[0] = 0x5a;
        ASSERT(!configured_sync_peer_note(&onion));
        PASS();
    } _test_next:;
    model_reset();
    return failures;
}

static int test_configured_inbound_same_limits_as_outbound(void)
{
    int failures = 0;
    TEST("configured inbound: request cadence, block assignment, stale-header "
         "and body-stall rules match an outbound twin") {
        static struct model_node a, b;
        model_reset();
        ASSERT(model_node_init(&a, "A", 7, 18233, 1));
        ASSERT(model_node_init(&b, "B", 8, 18234, 2));
        ASSERT(model_configure(&b, &a));
        struct model_conn c[2];
        ASSERT(model_connect(&c[0], &a, &b, a.priv, true, 40001));
        ev_inbound_version(&c[0]);
        model_settle(c, 1);
        ASSERT(model_begin(c[0].in));
        struct p2p_node *in = c[0].in;
        /* An outbound twin at the same heights and state. */
        ASSERT(model_connect(&c[1], &b, &a, b.priv, true, 40002));
        struct p2p_node *out = c[1].out;
        static const int heights[] = {0, 50, 100, 5000};
        static const enum peer_state states[] = {
            PEER_SYNCING_HEADERS, PEER_SYNCING_BLOCKS,
        };
        for (size_t s = 0; s < 2; s++) {
            for (size_t h = 0; h < 4; h++) {
                in->state = out->state = states[s];
                in->starting_height = out->starting_height = 100000;
                in->time_connected = out->time_connected = 1;
                in->last_getheaders_time = out->last_getheaders_time = 0;
                ASSERT(syncsvc_should_request_headers(in, heights[h], 500) ==
                       syncsvc_should_request_headers(out, heights[h], 500));
                struct sync_block_assignment pi, po;
                syncsvc_plan_block_assignment(&pi, in, 3, heights[h]);
                syncsvc_plan_block_assignment(&po, out, 3, heights[h]);
                ASSERT(pi.should_assign == po.should_assign);
                ASSERT(pi.max_assign == po.max_assign);
                ASSERT(syncsvc_should_disconnect_stale_header_peer(
                           in, heights[h], heights[h], 0, 500) ==
                       syncsvc_should_disconnect_stale_header_peer(
                           out, heights[h], heights[h], 0, 500));
                /* Rules C and D: the configured inbound peer answers exactly
                 * what the core's outbound evaluation answers. */
                int64_t now = 1000000;
                in->time_connected = out->time_connected =
                    now - (SYNC_BODY_STALL_TIMEOUT_SECS + 5);
                ASSERT(syncsvc_configured_inbound_body_stalled(
                           in, heights[h], 0, SYNC_BODY_STALL_MIN_TIMEOUTS,
                           0, SYNC_BODY_STALL_MIN_TIMEOUTS, 0, now) ==
                       (syncsvc_should_disconnect_body_stalled_peer(
                            out, heights[h], 0, SYNC_BODY_STALL_MIN_TIMEOUTS,
                            now) ||
                        syncsvc_should_disconnect_body_dark_peer(
                            out, heights[h], 0, SYNC_BODY_STALL_MIN_TIMEOUTS,
                            0, now)));
            }
        }
        /* The same deadbeat evidence against an unconfigured inbound peer
         * changes nothing: the core exempts it and so does this rule. */
        in->state = PEER_SYNCING_HEADERS;
        ASSERT(syncsvc_configured_inbound_body_stalled(
            in, 0, 0, SYNC_BODY_STALL_MIN_TIMEOUTS, 0,
            SYNC_BODY_STALL_MIN_TIMEOUTS, 0, 1000000));
        configured_sync_peers_reset_for_testing();
        ASSERT(!syncsvc_configured_inbound_body_stalled(
            in, 0, 0, SYNC_BODY_STALL_MIN_TIMEOUTS, 0,
            SYNC_BODY_STALL_MIN_TIMEOUTS, 0, 1000000));
        PASS();
    } _test_next:;
    model_reset();
    return failures;
}

static int test_configured_inbound_outbound_unchanged(void)
{
    int failures = 0;
    TEST("configured inbound: outbound begin-sync answers do not depend on "
         "the configured set") {
        static struct model_node a, b;
        model_reset();
        ASSERT(model_node_init(&a, "A", 7, 18233, 1));
        ASSERT(model_node_init(&b, "B", 8, 18234, 2));
        struct model_conn c;
        ASSERT(model_connect(&c, &b, &a, b.priv, true, 40001));
        static const enum sync_state states[] = {
            SYNC_IDLE, SYNC_FINDING_PEERS, SYNC_HEADERS_DOWNLOAD,
            SYNC_BLOCKS_DOWNLOAD, SYNC_AT_TIP,
        };
        static const int heights[] = {0, 99, 100, 101};
        static const enum peer_state peer_states[] = {
            PEER_HANDSHAKE_COMPLETE, PEER_ACTIVE, PEER_SYNCING_HEADERS,
        };
        for (size_t ps = 0; ps < 3; ps++) {
            for (size_t st = 0; st < 5; st++) {
                for (size_t h = 0; h < 4; h++) {
                    c.out->state = peer_states[ps];
                    configured_sync_peers_reset_for_testing();
                    bool b0 = syncsvc_should_begin_peer_sync(
                        c.out, heights[h], heights[h], states[st]);
                    bool r0 = syncsvc_should_request_headers(
                        c.out, heights[h], 1000);
                    ASSERT(model_configure(&b, &a));
                    configured_sync_peer_observe_outbound(c.out);
                    ASSERT(syncsvc_should_begin_peer_sync(
                               c.out, heights[h], heights[h], states[st]) ==
                           b0);
                    ASSERT(syncsvc_should_request_headers(
                               c.out, heights[h], 1000) == r0);
                    ASSERT(!syncsvc_peer_is_configured_inbound(c.out));
                }
            }
        }
        /* The outbound session to the exact target taught its identity. */
        uint8_t learned[32];
        struct net_service target;
        memset(&target, 0, sizeof(target));
        net_addr_set_ipv4(&target.addr, a.ip);
        target.port = a.port;
        ASSERT(configured_sync_peer_identity(&target, learned));
        ASSERT(memcmp(learned, a.pub, 32) == 0);
        ASSERT(g_probe_calls == 0);
        PASS();
    } _test_next:;
    model_reset();
    return failures;
}

/* ── below-tip body re-fetch over the configured inbound ─────────────── */

static void model_body_hash(struct uint256 *out, int64_t h)
{
    memset(out, 0, sizeof(*out));
    for (size_t i = 0; i < 8; i++)
        out->data[i] = (uint8_t)((uint64_t)h >> (8 * i));
    out->data[31] = 0x9C;
}

/* The chain a kill-restore leaves when its disk ancestry rebuild stops on
 * the first unreadable header: the block index holds every row of the tip's
 * ancestry, active_chain_install_tip_slot publishes the tip slot and the
 * height, and every slot below stays NULL. Bodies are header-only in
 * [missing_lo, missing_hi]. */
static bool model_kill_restore_chain(struct main_state *ms, int tip,
                                     int missing_lo, int missing_hi)
{
    struct block_index *previous = NULL;
    for (int h = 0; h <= tip; h++) {
        struct uint256 hash;
        model_body_hash(&hash, h);
        struct block_index *bi = chainstate_insert_block_index(
            (struct chainstate *)ms, &hash);
        if (!bi)
            return false;
        bi->nHeight = h;
        bi->pprev = previous;
        bi->nStatus = BLOCK_VALID_SCRIPTS;
        if (h < missing_lo || h > missing_hi)
            bi->nStatus |= BLOCK_HAVE_DATA;
        block_index_build_skip(bi);
        previous = bi;
    }
    return active_chain_install_tip_slot(&ms->chain_active, previous);
}

/* Queue [lo, hi] into a fresh manager's history lane, as the census-driven
 * backfill does. Returns false when the manager refuses an entry. */
static bool model_queue_history_range(struct download_manager *dm, int lo,
                                      int hi)
{
    for (int h = lo; h <= hi; h++) {
        struct uint256 hash;
        int32_t height = h;
        model_body_hash(&hash, h);
        if (dl_queue_blocks_class(dm, &hash, &height, 1, DL_WORK_HISTORY) != 1)
            return false;
    }
    return true;
}

/* Deliver `total` history-lane bodies to `peer` the way msg_send_messages
 * does: one assignment batch per message cycle, each body received and
 * persisted, heights verified in [lo, hi]. `first`/`first_n` replay a batch
 * already assigned to the peer. Returns bodies delivered; `ok` is false when
 * any step violated the contract. */
static size_t model_deliver_history_over_peer(
    struct download_manager *dm, const struct p2p_node *peer,
    struct main_state *ms, int lo, int hi, const struct uint256 *first,
    size_t first_n, size_t total, bool *ok)
{
    struct uint256 got[DL_WINDOW_SIZE];
    size_t delivered = 0;
    size_t cycles = 0;
    *ok = true;
    while (delivered < total && *ok) {
        size_t n = 0;
        if (cycles == 0) {
            while (n < first_n) {
                got[n] = first[n];
                n++;
            }
        } else {
            struct sync_block_batch more = {0};
            syncsvc_assign_peer_blocks(&more, dm, peer, got, DL_WINDOW_SIZE,
                                       hi);
            n = more.assigned;
        }
        cycles++;
        for (size_t i = 0; i < n && delivered < total; i++) {
            struct block_index *bi =
                block_map_find(&ms->map_block_index, &got[i]);
            *ok = dl_mark_received(dm, &got[i]) == (uint32_t)peer->id &&
                  bi && bi->nHeight >= lo && bi->nHeight <= hi;
            if (!*ok)
                break;
            bi->nStatus |= BLOCK_HAVE_DATA;
            delivered++;
        }
    }
    return delivered;
}

/* Re-probe until the census verdict every at-tip gate demands is proven, or
 * eight passes pass without one. */
static bool model_history_goes_proven(struct main_state *ms,
                                      struct download_manager *dm)
{
    struct body_history_verdict v;
    for (int pass = 0; pass < 8; pass++) {
        if (body_backfill_pass(ms, dm, false, false, NULL, NULL) != 0)
            return false;
        if (body_history_get_verdict(&v) && body_history_verdict_is_proven(&v))
            return true;
    }
    return false;
}

static int test_configured_inbound_refetches_missing_bodies(void)
{
    int failures = 0;
    TEST("configured inbound: a node whose only session is a configured "
         "inbound measures the below-tip bodies its kill-restore left "
         "header-only, requests them over that session, and draws the same "
         "assignment an outbound twin draws") {
        static struct model_node a, b;
        model_reset();
        ASSERT(model_node_init(&a, "A", 7, 18233, 1));
        ASSERT(model_node_init(&b, "B", 8, 18234, 2));
        ASSERT(model_configure(&b, &a));
        struct model_conn c, twin;
        ASSERT(model_connect(&c, &a, &b, a.priv, true, 40001));
        ev_inbound_version(&c);
        model_settle(&c, 1);
        ASSERT(model_begin(c.in));
        struct p2p_node *in = c.in;
        ASSERT(in->inbound && syncsvc_peer_is_configured_inbound(in));
        ASSERT(b.cm.manager.num_nodes == 1);
        in->starting_height = 145;

        struct main_state *ms = calloc(1, sizeof(*ms));
        ASSERT(ms);
        main_state_init(ms);
        ASSERT(model_kill_restore_chain(ms, 145, 121, 124));
        ASSERT(active_chain_at(&ms->chain_active, 145) != NULL);
        ASSERT(active_chain_at(&ms->chain_active, 121) == NULL);
        struct download_manager dm;
        dl_init(&dm);
        body_history_reset();

        /* The census burst must measure the below-tip range through the
         * tip's ancestry, not report the holed window unmeasured. */
        for (int pass = 0;
             pass < 64 && !body_history_window_fully_measured(); pass++)
            ASSERT(body_backfill_pass(ms, &dm, false, true, NULL, NULL) == 0);
        struct body_history_verdict v;
        ASSERT(body_history_get_verdict(&v));
        ASSERT(v.status == BODY_HISTORY_INCOMPLETE);
        ASSERT(v.lowest_missing == 121 && v.missing_count == 4);
        ASSERT(body_backfill_pass(ms, &dm, false, false, NULL, NULL) == 4);
        ASSERT(dm.queue_len == 4);

        /* The only session — the configured inbound — draws the same
         * getdata window an outbound twin draws from the same queue shape.
         * The history lane hands any peer at most DL_MAX_HISTORY_PER_PEER
         * hashes per message cycle, inbound or outbound alike. */
        struct sync_block_batch bin, bout;
        struct uint256 hin[DL_WINDOW_SIZE], hout[DL_WINDOW_SIZE];
        syncsvc_assign_peer_blocks(&bin, &dm, in, hin, DL_WINDOW_SIZE, 145);
        ASSERT(bin.should_assign && bin.assigned > 0);
        struct download_manager dm2;
        dl_init(&dm2);
        ASSERT(model_queue_history_range(&dm2, 121, 124));
        ASSERT(model_connect(&twin, &b, &a, b.priv, true, 40002));
        struct p2p_node *out = twin.out;
        out->state = PEER_ACTIVE;
        out->starting_height = 145;
        syncsvc_assign_peer_blocks(&bout, &dm2, out, hout, DL_WINDOW_SIZE,
                                   145);
        ASSERT(bout.should_assign == bin.should_assign);
        ASSERT(bout.assigned == bin.assigned);
        for (size_t i = 0; i < bin.assigned; i++)
            ASSERT(uint256_eq(&hin[i], &hout[i]));

        /* Message cycles deliver all four bodies over the inbound session,
         * then the census re-probes them as held and the verdict every
         * at-tip gate demands goes proven. */
        bool delivered_ok = false;
        size_t delivered = model_deliver_history_over_peer(
            &dm, in, ms, 121, 124, hin, bin.assigned, 4, &delivered_ok);
        ASSERT(delivered_ok && delivered == 4);
        ASSERT(model_history_goes_proven(ms, &dm));
        printf("[configured-inbound body refetch] missing=4 delivered=%zu "
               "assigned_inbound=%zu assigned_outbound=%zu proven=yes\n",
               delivered, bin.assigned, bout.assigned);
        dl_free(&dm);
        dl_free(&dm2);
        main_state_free(ms);
        free(ms);
        body_history_reset();
        PASS();
    } _test_next:;
    model_reset();
    body_history_reset();
    return failures;
}

/* ── the hollow container a partial restore leaves behind the authority ── */

/* The tip authority a live node registers through tip_finalize: the census
 * takes its window bound from active_chain_height, so this stub models the
 * boot where the authority names tip 145 while the chain[] container is
 * hollow. The flag withdraws the stub after the scenario — the registry has
 * no unregister call, and a stale authoritative stub would answer for every
 * later test in this process. */
static bool model_authority_on;
static bool model_authority_hash_ok = true;
static int64_t model_authority_height = -1;
static struct uint256 model_authority_hash;

static int64_t model_authority_get_height(void)
{
    return model_authority_on ? model_authority_height : -1;
}

static bool model_authority_get_hash(uint8_t out[32])
{
    if (!model_authority_on || !model_authority_hash_ok)
        return false;
    memcpy(out, model_authority_hash.data, 32);
    return true;
}

static bool model_authority_is_authoritative(void)
{
    return model_authority_on;
}

static int test_configured_inbound_hollow_window_still_measures(void)
{
    int failures = 0;
    TEST("configured inbound: a returned node whose chain[] container is "
         "hollow behind the tip authority still measures its below-tip "
         "bodies, requests them over the configured inbound, and proves "
         "its history") {
        static struct model_node a, b;
        model_reset();
        model_authority_on = false;
        model_authority_hash_ok = true;
        ASSERT(model_node_init(&a, "A", 7, 18235, 1));
        ASSERT(model_node_init(&b, "B", 8, 18236, 2));
        ASSERT(model_configure(&b, &a));
        struct model_conn c;
        ASSERT(model_connect(&c, &a, &b, a.priv, true, 40003));
        ev_inbound_version(&c);
        model_settle(&c, 1);
        ASSERT(model_begin(c.in));
        struct p2p_node *in = c.in;
        ASSERT(in->inbound && syncsvc_peer_is_configured_inbound(in));
        ASSERT(b.cm.manager.num_nodes == 1);
        in->starting_height = 145;

        struct main_state *ms = calloc(1, sizeof(*ms));
        ASSERT(ms);
        main_state_init(ms);
        ASSERT(model_kill_restore_chain(ms, 145, 121, 124));
        /* The partial restore: the height the authority publishes stays,
         * the tip slot itself does not. Every chain[] read now misses. */
        zcl_mutex_lock(&ms->chain_active.write_lock);
        ms->chain_active.chain[145] = NULL;
        zcl_mutex_unlock(&ms->chain_active.write_lock);
        ASSERT(active_chain_at(&ms->chain_active, 145) == NULL);

        model_body_hash(&model_authority_hash, 145);
        model_authority_height = 145;
        struct active_chain_authority auth = {
            .get_height = model_authority_get_height,
            .get_hash = model_authority_get_hash,
            .is_authoritative = model_authority_is_authoritative,
        };
        active_chain_register_block_map(&ms->map_block_index);
        active_chain_register_authority(&auth);
        model_authority_on = true;

        struct download_manager dm;
        dl_init(&dm);
        body_history_reset();

        /* The census must measure through the authority tip's ancestry even
         * though no chain[] slot answers. */
        for (int pass = 0;
             pass < 64 && !body_history_window_fully_measured(); pass++)
            ASSERT(body_backfill_pass(ms, &dm, false, true, NULL, NULL) == 0);
        struct body_history_verdict v;
        ASSERT(body_history_get_verdict(&v));
        ASSERT(v.status == BODY_HISTORY_INCOMPLETE);
        ASSERT(v.lowest_missing == 121 && v.missing_count == 4);
        ASSERT(body_backfill_pass(ms, &dm, false, false, NULL, NULL) == 4);
        ASSERT(dm.queue_len == 4);

        struct sync_block_batch bin;
        struct uint256 hin[DL_WINDOW_SIZE];
        syncsvc_assign_peer_blocks(&bin, &dm, in, hin, DL_WINDOW_SIZE, 145);
        ASSERT(bin.should_assign && bin.assigned > 0);

        bool delivered_ok = false;
        size_t delivered = model_deliver_history_over_peer(
            &dm, in, ms, 121, 124, hin, bin.assigned, 4, &delivered_ok);
        ASSERT(delivered_ok && delivered == 4);
        ASSERT(model_history_goes_proven(ms, &dm));
        printf("[configured-inbound hollow window] missing=4 delivered=%zu "
               "assigned_inbound=%zu proven=yes\n",
               delivered, bin.assigned);

        model_authority_on = false;
        model_authority_height = -1;
        dl_free(&dm);
        main_state_free(ms);
        free(ms);
        body_history_reset();
        PASS();
    } _test_next:;
    model_reset();
    model_authority_on = false;
    body_history_reset();
    return failures;
}

/* ── the durable pair a hollow restore leaves as the only tip witness ──
 *
 * The other hollow boot: the authority answers the height yet names no
 * hash, no chain[] slot answers any height, and the only surviving tip
 * witness is the durable tip_finalize pair — the shape a kill leaves when
 * the disk ancestry rebuild stops early (populated=0) while the finalized
 * log still holds the tip. The census must anchor on that same durable
 * pair the window bound already falls back to, not report the whole window
 * unmeasured. */
static int test_configured_inbound_durable_anchor_window_measures(void)
{
    int failures = 0;
    TEST("configured inbound: a returned node whose authority answers the "
         "tip height but names no hash — chain[] hollow, durable "
         "tip_finalize pair intact — still measures its below-tip bodies, "
         "requests them over the configured inbound, and proves its "
         "history") {
        static struct model_node a, b;
        model_reset();
        model_authority_on = false;
        model_authority_hash_ok = true;
        model_authority_height = -1;
        ASSERT(model_node_init(&a, "A", 7, 18237, 1));
        ASSERT(model_node_init(&b, "B", 8, 18238, 2));
        ASSERT(model_configure(&b, &a));
        struct model_conn c;
        ASSERT(model_connect(&c, &a, &b, a.priv, true, 40005));
        ev_inbound_version(&c);
        model_settle(&c, 1);
        ASSERT(model_begin(c.in));
        struct p2p_node *in = c.in;
        ASSERT(in->inbound && syncsvc_peer_is_configured_inbound(in));
        in->starting_height = 145;

        struct main_state *ms = calloc(1, sizeof(*ms));
        ASSERT(ms);
        main_state_init(ms);

        /* The durable pair a finalized tip leaves behind: the real progress
         * store, the tip_finalize stage (its cursor owns the durable-tip
         * resolver's read), and a seeded anchor at 145 carrying the block's
         * own hash — the same recipe the seed-from-finalized loader test
         * uses. Empty container at init time, so init takes its fresh-store
         * path and stamps nothing itself. */
        char dir[128];
        test_fmt_tmpdir(dir, sizeof(dir), "cfgib_durable", "main");
        mkdir("./test-tmp", 0755);
        mkdir(dir, 0755);
        progress_store_close();
        ASSERT(progress_store_open(dir));
        ASSERT(tip_finalize_stage_init(ms));
        struct uint256 tip_hash;
        model_body_hash(&tip_hash, 145);
        ASSERT(tip_finalize_stage_seed_anchor(145, tip_hash.data, true));

        /* The partial restore: every ancestry row present in the map, the
         * tip slot installed then emptied, the published height kept at 145
         * by an authority that names no hash — no tip row answers. */
        ASSERT(model_kill_restore_chain(ms, 145, 121, 124));
        zcl_mutex_lock(&ms->chain_active.write_lock);
        ms->chain_active.chain[145] = NULL;
        zcl_mutex_unlock(&ms->chain_active.write_lock);
        ASSERT(active_chain_at(&ms->chain_active, 145) == NULL);

        model_authority_height = 145;
        model_authority_hash_ok = false;
        struct active_chain_authority auth = {
            .get_height = model_authority_get_height,
            .get_hash = model_authority_get_hash,
            .is_authoritative = model_authority_is_authoritative,
        };
        active_chain_register_authority(&auth);
        model_authority_on = true;
        ASSERT(active_chain_tip(&ms->chain_active) == NULL);
        ASSERT(active_chain_height(&ms->chain_active) == 145);

        struct download_manager dm;
        dl_init(&dm);
        body_history_reset();

        /* The census must anchor on the durable pair and measure through
         * the ancestry it names. */
        for (int pass = 0;
             pass < 64 && !body_history_window_fully_measured(); pass++)
            ASSERT(body_backfill_pass(ms, &dm, false, true, NULL, NULL) == 0);
        struct body_history_verdict v;
        ASSERT(body_history_get_verdict(&v));
        ASSERT(v.status == BODY_HISTORY_INCOMPLETE);
        ASSERT(v.lowest_missing == 121 && v.missing_count == 4);
        ASSERT(body_backfill_pass(ms, &dm, false, false, NULL, NULL) == 4);
        ASSERT(dm.queue_len == 4);

        /* The only session — the configured inbound — draws the assignment
         * and message cycles deliver all four bodies, then the verdict goes
         * proven against the durable anchor. */
        struct sync_block_batch bin;
        struct uint256 hin[DL_WINDOW_SIZE];
        syncsvc_assign_peer_blocks(&bin, &dm, in, hin, DL_WINDOW_SIZE, 145);
        ASSERT(bin.should_assign && bin.assigned > 0);

        bool delivered_ok = false;
        size_t delivered = model_deliver_history_over_peer(
            &dm, in, ms, 121, 124, hin, bin.assigned, 4, &delivered_ok);
        ASSERT(delivered_ok && delivered == 4);
        ASSERT(model_history_goes_proven(ms, &dm));
        printf("[configured-inbound durable anchor] missing=4 delivered=%zu "
               "assigned_inbound=%zu proven=yes\n",
               delivered, bin.assigned);

        model_authority_on = false;
        model_authority_hash_ok = true;
        model_authority_height = -1;
        dl_free(&dm);
        tip_finalize_stage_shutdown();
        progress_store_close();
        main_state_free(ms);
        free(ms);
        body_history_reset();
        test_cleanup_tmpdir(dir);
        PASS();
    } _test_next:;
    model_reset();
    model_authority_on = false;
    model_authority_hash_ok = true;
    body_history_reset();
    tip_finalize_stage_shutdown();
    progress_store_close();
    return failures;
}

/* ── the network prober's socket path, over loopback ─────────────────── */

enum listener_mode {
    LISTEN_NOISE,    /* answer as the Noise XX responder */
    LISTEN_CLOSE,    /* accept, then close without a byte */
    LISTEN_TRICKLE,  /* answer XX message 2 one byte at a time */
    LISTEN_HOLD,     /* accept and never send, until the probe closes */
};

struct probe_listener {
    platform_socket_t fd;
    uint16_t port;
    enum listener_mode mode;
    uint8_t priv[32];
    bool established;          /* the responder saw XX message 3 */
    uint8_t seen_static[32];   /* the initiator static it authenticated */
    size_t trickled;           /* bytes of message 2 sent in trickle mode */
    size_t msg2_len;
    pthread_mutex_t mu;
    pthread_cond_t cv;
    bool accepted;
};

static bool probe_listener_open(struct probe_listener *l)
{
    pthread_mutex_init(&l->mu, NULL);
    pthread_cond_init(&l->cv, NULL);
    l->fd = platform_socket_open(AF_INET, SOCK_STREAM, 0, true, false);
    if (l->fd == PLATFORM_SOCKET_INVALID)
        return false;
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    size_t slen = sizeof(sa);
    if (platform_socket_bind(l->fd, (struct sockaddr *)&sa, sizeof(sa)) != 0 ||
        platform_socket_listen(l->fd, 4) != 0 ||
        platform_socket_local_address(l->fd, (struct sockaddr *)&sa,
                                      &slen) != 0)
        return false;
    l->port = ntohs(sa.sin_port);
    return l->port != 0;
}

/* Answer one connection as the Noise XX responder, as net_listen.c arms an
 * inbound session, until the handshake completes or the peer closes. */
static void probe_listener_respond(struct probe_listener *l,
                                   platform_socket_t s)
{
    struct noise_transport *t = noise_transport_begin(
        false, l->priv, chain_params_get()->pchMessageStart, NULL, NULL);
    uint8_t buf[256];
    while (t) {
        int n = platform_socket_receive(s, buf, sizeof(buf));
        uint8_t *wire = NULL, *plain = NULL;
        size_t wire_len = 0, plain_len = 0;
        bool fed = n > 0 && noise_transport_feed(t, buf, (size_t)n, &wire,
                                                 &wire_len, &plain,
                                                 &plain_len);
        if (fed && wire_len)
            fed = platform_socket_send_all(s, wire, wire_len);
        free(wire);
        free(plain);
        struct noise_transport_snapshot snap;
        if (fed && noise_transport_snapshot(t, &snap)) {
            l->established = true;
            memcpy(l->seen_static, snap.remote_static, 32);
        }
        if (!fed || l->established)
            break;
    }
    noise_transport_free(t);
}

/* Read XX message 1, then send the real message 2 one byte per 50 ms of
 * silence from the probe; stop as soon as the probe closes or answers. */
static void probe_listener_trickle(struct probe_listener *l,
                                   platform_socket_t s)
{
    struct noise_transport *t = noise_transport_begin(
        false, l->priv, chain_params_get()->pchMessageStart, NULL, NULL);
    uint8_t buf[256];
    uint8_t *wire = NULL, *plain = NULL;
    size_t wire_len = 0, plain_len = 0;
    int n = platform_socket_receive(s, buf, sizeof(buf));
    bool fed = t && n > 0 && noise_transport_feed(t, buf, (size_t)n, &wire,
                                                  &wire_len, &plain,
                                                  &plain_len);
    l->msg2_len = fed ? wire_len : 0;
    for (size_t i = 0; fed && i < wire_len; i++) {
        if (platform_socket_wait_readable(s, 50) != 0 ||
            platform_socket_send(s, wire + i, 1) != 1)
            break;
        l->trickled++;
    }
    free(wire);
    free(plain);
    noise_transport_free(t);
}

/* Hold the connection open without a byte until the probe closes it. */
static void probe_listener_hold(platform_socket_t s)
{
    uint8_t buf[64];
    for (int i = 0; i < 30; i++) {
        if (platform_socket_wait_readable(s, 1000) > 0 &&
            platform_socket_receive(s, buf, sizeof(buf)) <= 0)
            return;
    }
}

static void *probe_listener_main(void *arg)
{
    struct probe_listener *l = arg;
    struct sockaddr_in peer;
    size_t plen = sizeof(peer);
    platform_socket_t s =
        platform_socket_accept(l->fd, (struct sockaddr *)&peer, &plen);
    pthread_mutex_lock(&l->mu);
    l->accepted = s != PLATFORM_SOCKET_INVALID;
    pthread_cond_broadcast(&l->cv);
    pthread_mutex_unlock(&l->mu);
    if (s == PLATFORM_SOCKET_INVALID)
        return NULL;
    (void)platform_socket_set_receive_timeout(s, 5000);
    if (l->mode == LISTEN_NOISE)
        probe_listener_respond(l, s);
    else if (l->mode == LISTEN_TRICKLE)
        probe_listener_trickle(l, s);
    else if (l->mode == LISTEN_HOLD)
        probe_listener_hold(s);
    (void)platform_socket_close(s);
    return NULL;
}

static void probe_listener_finish(struct probe_listener *l, pthread_t tid)
{
    /* Wakes a listener still blocked in accept when the dial never came. */
    (void)platform_socket_shutdown_both(l->fd);
    (void)pthread_join(tid, NULL);
    (void)platform_socket_close(l->fd);
    pthread_mutex_destroy(&l->mu);
    pthread_cond_destroy(&l->cv);
}

static void loopback_target(struct net_service *target, uint16_t port)
{
    memset(target, 0, sizeof(*target));
    net_addr_set_ipv4(&target->addr, (const unsigned char[4]){127, 0, 0, 1});
    target->port = port;
}

/* Run the real prober against one loopback listener. */
static bool probe_loopback(struct probe_listener *l, const uint8_t probe_priv[32],
                           uint8_t out[32])
{
    pthread_t tid;
    if (!probe_listener_open(l) ||
        pthread_create(&tid, NULL, probe_listener_main, l) != 0)
        return false;
    struct net_service target;
    loopback_target(&target, l->port);
    bool ok = configured_sync_peer_probe_socket_for_testing(
        &target, probe_priv, chain_params_get()->pchMessageStart, out);
    probe_listener_finish(l, tid);
    return ok;
}

/* ── the most-corrupted restore: neither anchor answers ────────────────
 * The two anchor arms above pin that a census CAN measure through the
 * authority tip and through the durable pair. This arm pins the failure
 * shape those arms cannot: a hollow restore whose durable tip_finalize
 * pair is gone too — a kill before the first finalize, or a progress
 * store that lost its ok rows. bb_durable_anchor is documented
 * fail-closed on exactly this ("no progress store, no resolvable pair …
 * leaves the anchor NULL and the window honestly unmeasured"), but no
 * regression held it: a later "simplification" that reads a NULL anchor
 * as an empty window would hand back missing_count=0 with a complete
 * verdict — the original hollow-restore hole reborn through a second
 * door, and corrupted history would become an earned PASS. */
static int test_configured_inbound_no_anchor_window_stays_honest(void)
{
    int failures = 0;
    TEST("configured inbound: a hollow restore whose durable pair is also "
         "gone — neither the chain[] tip nor tip_finalize answers — keeps "
         "its body-history census honestly unmeasured, never complete") {
        static struct model_node a, b;
        model_reset();
        model_authority_on = false;
        model_authority_hash_ok = true;
        model_authority_height = -1;
        ASSERT(model_node_init(&a, "A", 7, 18237, 1));
        ASSERT(model_node_init(&b, "B", 8, 18238, 2));
        ASSERT(model_configure(&b, &a));
        struct model_conn c;
        ASSERT(model_connect(&c, &a, &b, a.priv, true, 40007));
        ev_inbound_version(&c);
        model_settle(&c, 1);
        ASSERT(model_begin(c.in));
        struct p2p_node *in = c.in;
        ASSERT(in->inbound && syncsvc_peer_is_configured_inbound(in));
        in->starting_height = 145;

        struct main_state *ms = calloc(1, sizeof(*ms));
        ASSERT(ms);
        main_state_init(ms);

        /* A real, EMPTY progress store: the durable-tip resolver has a
         * database to read and finds no ok=1 finalize pair in it. */
        char dir[128];
        test_fmt_tmpdir(dir, sizeof(dir), "cfgib_noanchor", "main");
        mkdir("./test-tmp", 0755);
        mkdir(dir, 0755);
        progress_store_close();
        ASSERT(progress_store_open(dir));
        ASSERT(tip_finalize_stage_init(ms));

        /* The partial restore: ancestry rows in the map, tip slot emptied,
         * published height 145 from an authority that names no hash. */
        ASSERT(model_kill_restore_chain(ms, 145, 121, 124));
        zcl_mutex_lock(&ms->chain_active.write_lock);
        ms->chain_active.chain[145] = NULL;
        zcl_mutex_unlock(&ms->chain_active.write_lock);
        ASSERT(active_chain_at(&ms->chain_active, 145) == NULL);

        model_authority_height = 145;
        model_authority_hash_ok = false;
        struct active_chain_authority auth = {
            .get_height = model_authority_get_height,
            .get_hash = model_authority_get_hash,
            .is_authoritative = model_authority_is_authoritative,
        };
        active_chain_register_authority(&auth);
        model_authority_on = true;
        ASSERT(active_chain_tip(&ms->chain_active) == NULL);
        ASSERT(active_chain_height(&ms->chain_active) == 145);

        struct download_manager dm;
        dl_init(&dm);
        body_history_reset();

        /* Neither anchor answers, so no pass may manufacture a measured
         * window out of nothing. */
        for (int pass = 0; pass < 64; pass++)
            ASSERT(body_backfill_pass(ms, &dm, false, true, NULL, NULL) == 0);
        ASSERT(!body_history_window_fully_measured());
        struct body_history_verdict v;
        ASSERT(body_history_get_verdict(&v));
        ASSERT(v.status != BODY_HISTORY_COMPLETE);
        printf("[configured-inbound no anchor] verdict=%d missing=%" PRId64 " — "
               "honestly unmeasured, no earned PASS\n",
               (int)v.status, v.missing_count);

        model_authority_on = false;
        model_authority_hash_ok = true;
        model_authority_height = -1;
        dl_free(&dm);
        tip_finalize_stage_shutdown();
        progress_store_close();
        main_state_free(ms);
        free(ms);
        body_history_reset();
        test_cleanup_tmpdir(dir);
        PASS();
    } _test_next:;
    model_reset();
    model_authority_on = false;
    model_authority_hash_ok = true;
    body_history_reset();
    tip_finalize_stage_shutdown();
    progress_store_close();
    return failures;
}

static int test_configured_inbound_probe_socket(void)
{
    int failures = 0;
    TEST("configured inbound: the identity probe completes Noise XX over a "
         "real socket and returns the responder's static key; a listener "
         "that never speaks Noise yields no identity") {
        uint8_t probe_priv[32], probe_pub[32], out[32];
        model_key(probe_priv, 201);
        ASSERT(model_public_key(probe_priv, probe_pub));

        struct probe_listener noise_l;
        memset(&noise_l, 0, sizeof(noise_l));
        noise_l.mode = LISTEN_NOISE;
        model_key(noise_l.priv, 1);
        uint8_t want[32];
        ASSERT(model_public_key(noise_l.priv, want));
        memset(out, 0, sizeof(out));
        ASSERT(probe_loopback(&noise_l, probe_priv, out));
        ASSERT(memcmp(out, want, 32) == 0);
        /* The responder completed too, and authenticated the probe key. */
        ASSERT(noise_l.established);
        ASSERT(memcmp(noise_l.seen_static, probe_pub, 32) == 0);

        struct probe_listener mute_l;
        memset(&mute_l, 0, sizeof(mute_l));
        mute_l.mode = LISTEN_CLOSE;
        ASSERT(!probe_loopback(&mute_l, probe_priv, out));
        PASS();
    } _test_next:;
    return failures;
}

/* A probe clock that moves one second per reading. */
static _Atomic int64_t g_fake_probe_ms;
static int64_t fake_probe_clock_ms(void)
{
    return atomic_fetch_add(&g_fake_probe_ms, 1000) + 1000;
}

static int test_configured_inbound_probe_deadline(void)
{
    int failures = 0;
    TEST("configured inbound: a target that trickles XX message 2 one byte "
         "at a time ends the probe at its absolute deadline") {
        uint8_t probe_priv[32], out[32];
        model_key(probe_priv, 201);
        struct probe_listener l;
        memset(&l, 0, sizeof(l));
        l.mode = LISTEN_TRICKLE;
        model_key(l.priv, 1);
        atomic_store(&g_fake_probe_ms, 0);
        configured_sync_peers_set_probe_clock_ms_for_testing(fake_probe_clock_ms);
        int64_t real_start = platform_time_monotonic_us();
        bool ok = probe_loopback(&l, probe_priv, out);
        int64_t real_ms = (platform_time_monotonic_us() - real_start) / 1000;
        configured_sync_peers_set_probe_clock_ms_for_testing(NULL);
        ASSERT(!ok);
        /* The deadline, not the peer, ended it: bytes kept arriving, the
         * whole message never did, and the probe clock passed the deadline. */
        ASSERT(l.msg2_len > 0);
        ASSERT(l.trickled > 0 && l.trickled < l.msg2_len);
        ASSERT(atomic_load(&g_fake_probe_ms) >=
               CONFIGURED_SYNC_PEER_PROBE_DEADLINE_MS);
        ASSERT(real_ms < CONFIGURED_SYNC_PEER_PROBE_DEADLINE_MS);
        PASS();
    } _test_next:;
    configured_sync_peers_set_probe_clock_ms_for_testing(NULL);
    return failures;
}

struct socket_probe_run {
    struct net_service target;
    uint8_t priv[32];
    bool ok;
};

static void *socket_probe_main(void *arg)
{
    struct socket_probe_run *run = arg;
    uint8_t out[32];
    run->ok = configured_sync_peer_probe_socket_for_testing(
        &run->target, run->priv, chain_params_get()->pchMessageStart, out);
    return NULL;
}

static bool listener_wait_accepted(struct probe_listener *l)
{
    struct timespec until;
    clock_gettime(CLOCK_REALTIME, &until);
    until.tv_sec += 5;
    pthread_mutex_lock(&l->mu);
    while (!l->accepted &&
           pthread_cond_timedwait(&l->cv, &l->mu, &until) == 0) {
    }
    bool accepted = l->accepted;
    pthread_mutex_unlock(&l->mu);
    return accepted;
}

static int test_configured_inbound_probe_stop(void)
{
    int failures = 0;
    TEST("configured inbound: a stop request ends a probe waiting on a silent "
         "target within a wait slice") {
        struct probe_listener l;
        memset(&l, 0, sizeof(l));
        l.mode = LISTEN_HOLD;
        pthread_t ltid, ptid;
        ASSERT(probe_listener_open(&l));
        ASSERT(pthread_create(&ltid, NULL, probe_listener_main, &l) == 0);
        struct socket_probe_run run;
        memset(&run, 0, sizeof(run));
        loopback_target(&run.target, l.port);
        model_key(run.priv, 201);
        bool started = pthread_create(&ptid, NULL, socket_probe_main, &run) == 0;
        bool accepted = started && listener_wait_accepted(&l);
        int64_t stop_at = platform_time_monotonic_us();
        configured_sync_peers_stop();
        if (started)
            (void)pthread_join(ptid, NULL);
        int64_t stop_ms = (platform_time_monotonic_us() - stop_at) / 1000;
        probe_listener_finish(&l, ltid);
        configured_sync_peers_reset_for_testing();
        ASSERT(started && accepted);
        ASSERT(!run.ok);
        /* Far inside the per-target deadline the probe would otherwise use. */
        ASSERT(stop_ms < 2000);
        PASS();
    } _test_next:;
    configured_sync_peers_reset_for_testing();
    return failures;
}

/* A threaded test prober held at a gate until the test opens it or a stop
 * request arrives. */
static pthread_mutex_t g_gate_mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_gate_cv = PTHREAD_COND_INITIALIZER;
static bool g_gate_open;
static int g_gate_calls;
static bool g_gate_saw_stop;

static bool gate_prober(const struct net_service *target, uint8_t out[32])
{
    pthread_mutex_lock(&g_gate_mu);
    g_gate_calls++;
    pthread_cond_broadcast(&g_gate_cv);
    while (!g_gate_open && !configured_sync_peers_probe_should_stop()) {
        struct timespec until;
        clock_gettime(CLOCK_REALTIME, &until);
        until.tv_nsec += 10 * 1000 * 1000;
        if (until.tv_nsec >= 1000000000L) {
            until.tv_sec++;
            until.tv_nsec -= 1000000000L;
        }
        (void)pthread_cond_timedwait(&g_gate_cv, &g_gate_mu, &until);
    }
    g_gate_saw_stop = configured_sync_peers_probe_should_stop();
    pthread_mutex_unlock(&g_gate_mu);
    return !g_gate_saw_stop && model_prober(target, out);
}

static void gate_set(bool open)
{
    pthread_mutex_lock(&g_gate_mu);
    g_gate_open = open;
    pthread_cond_broadcast(&g_gate_cv);
    pthread_mutex_unlock(&g_gate_mu);
}

static bool gate_wait_calls(int calls)
{
    struct timespec until;
    clock_gettime(CLOCK_REALTIME, &until);
    until.tv_sec += 5;
    pthread_mutex_lock(&g_gate_mu);
    while (g_gate_calls < calls &&
           pthread_cond_timedwait(&g_gate_cv, &g_gate_mu, &until) == 0) {
    }
    bool reached = g_gate_calls >= calls;
    pthread_mutex_unlock(&g_gate_mu);
    return reached;
}

static int test_configured_inbound_probe_thread(void)
{
    int failures = 0;
    TEST("configured inbound: one probe thread at a time, joined before the "
         "next spawns, and joined by stop while it waits") {
        static struct model_node a, b, x;
        model_reset();
        configured_sync_peers_set_prober_for_testing(NULL);
        configured_sync_peers_set_threaded_prober_for_testing(gate_prober);
        g_gate_calls = 0;
        g_gate_saw_stop = false;
        gate_set(false);
        ASSERT(model_node_init(&a, "A", 7, 18233, 1));
        ASSERT(model_node_init(&b, "B", 8, 18234, 2));
        ASSERT(model_node_init(&x, "X", 7, 18299, 9));
        x.up = false;
        ASSERT(model_configure(&b, &a));
        struct model_conn c[2];
        ASSERT(model_connect(&c[0], &a, &b, a.priv, true, 40001));
        ASSERT(model_connect(&c[1], &a, &b, x.priv, true, 40002));
        c[0].in->state = c[1].in->state = PEER_ACTIVE;

        ASSERT(configured_sync_peer_request_probe(c[0].in) == 1);
        ASSERT(gate_wait_calls(1));
        ASSERT(configured_sync_peer_request_probe(c[0].in) == 0);  /* busy */
        ASSERT(!syncsvc_peer_is_configured_inbound(c[0].in));
        gate_set(true);
        ASSERT(configured_sync_peers_join_probe_for_testing());
        ASSERT(syncsvc_peer_is_configured_inbound(c[0].in));

        /* The impostor session asks again after the retry spacing: a new
         * thread spawns, learns A's key again, and the impostor stays out. */
        g_model_now += CONFIGURED_SYNC_PEER_PROBE_RETRY_SECS;
        ASSERT(configured_sync_peer_request_probe(c[1].in) == 1);
        ASSERT(configured_sync_peers_join_probe_for_testing());
        ASSERT(g_gate_calls == 2);
        ASSERT(!syncsvc_peer_is_configured_inbound(c[1].in));

        /* Stop ends a probe held at the gate and joins its thread. */
        gate_set(false);
        g_model_now += CONFIGURED_SYNC_PEER_PROBE_RETRY_SECS;
        ASSERT(configured_sync_peer_request_probe(c[1].in) == 1);
        ASSERT(gate_wait_calls(3));
        configured_sync_peers_stop();
        ASSERT(g_gate_saw_stop);
        ASSERT(!configured_sync_peers_join_probe_for_testing());
        g_model_now += CONFIGURED_SYNC_PEER_PROBE_RETRY_SECS;
        ASSERT(configured_sync_peer_request_probe(c[1].in) == 0);

        /* Restart the runtime service after its stop callback. A fresh probe
         * must be admitted without resetting the configured target table. */
        struct net_manager restarted_network;
        memset(&restarted_network, 0, sizeof(restarted_network));
        configured_sync_peers_start(&restarted_network);
        gate_set(true);
        g_model_now += CONFIGURED_SYNC_PEER_PROBE_RETRY_SECS;
        ASSERT(configured_sync_peer_request_probe(c[1].in) == 1);
        ASSERT(configured_sync_peers_join_probe_for_testing());
        ASSERT(g_gate_calls == 4);
        PASS();
    } _test_next:;
    gate_set(true);
    configured_sync_peers_set_threaded_prober_for_testing(NULL);
    model_reset();
    return failures;
}

static int test_configured_inbound_revocation(void)
{
    int failures = 0;
    TEST("configured inbound: addnode remove revokes a bound session at the "
         "next check, and a probe that learns a new key revokes the old one") {
        static struct model_node a, b, a2;
        model_reset();
        ASSERT(model_node_init(&a, "A", 7, 18233, 1));
        ASSERT(model_node_init(&b, "B", 8, 18234, 2));
        ASSERT(model_configure(&b, &a));
        struct model_conn c[2];
        ASSERT(model_connect(&c[0], &a, &b, a.priv, true, 40001));
        ev_inbound_version(&c[0]);
        model_settle(c, 1);
        ASSERT(model_begin(c[0].in));
        struct net_service target;
        memset(&target, 0, sizeof(target));
        net_addr_set_ipv4(&target.addr, a.ip);
        target.port = a.port;
        ASSERT(configured_sync_peer_forget(&target));
        ASSERT(!syncsvc_peer_is_configured_inbound(c[0].in));
        ASSERT(!model_begin(c[0].in));

        /* Re-added; then the host at A's address changes its key. */
        ASSERT(model_configure(&b, &a));
        ASSERT(model_begin(c[0].in));
        a.up = false;
        ASSERT(model_node_init(&a2, "A2", 7, 18233, 11));
        ASSERT(model_connect(&c[1], &a2, &b, a2.priv, true, 40002));
        ev_inbound_version(&c[1]);
        model_settle(&c[1], 1);
        g_model_now += CONFIGURED_SYNC_PEER_PROBE_RETRY_SECS;
        ASSERT(model_begin(c[1].in));
        ASSERT(!syncsvc_peer_is_configured_inbound(c[0].in));
        PASS();
    } _test_next:;
    model_reset();
    return failures;
}

static int test_configured_inbound_probe_generation(void)
{
    int failures = 0;
    TEST("configured inbound: a removed target rejects its old in-flight probe") {
        static struct model_node a, b;
        model_reset();
        configured_sync_peers_set_prober_for_testing(NULL);
        configured_sync_peers_set_threaded_prober_for_testing(gate_prober);
        g_gate_calls = 0;
        g_gate_saw_stop = false;
        gate_set(false);
        ASSERT(model_node_init(&a, "A", 7, 18233, 1));
        ASSERT(model_node_init(&b, "B", 8, 18234, 2));
        ASSERT(model_configure(&b, &a));
        struct model_conn c;
        ASSERT(model_connect(&c, &a, &b, a.priv, true, 40001));
        c.in->state = PEER_ACTIVE;
        ASSERT(configured_sync_peer_request_probe(c.in) == 1);
        ASSERT(gate_wait_calls(1));

        struct net_service target;
        memset(&target, 0, sizeof(target));
        net_addr_set_ipv4(&target.addr, a.ip);
        target.port = a.port;
        ASSERT(configured_sync_peer_forget(&target));
        ASSERT(configured_sync_peer_note(&target));
        gate_set(true);
        ASSERT(configured_sync_peers_join_probe_for_testing());
        uint8_t learned[32];
        ASSERT(!configured_sync_peer_identity(&target, learned));

        ASSERT(configured_sync_peer_request_probe(c.in) == 1);
        ASSERT(configured_sync_peers_join_probe_for_testing());
        ASSERT(configured_sync_peer_identity(&target, learned));
        PASS();
    } _test_next:;
    gate_set(true);
    configured_sync_peers_set_threaded_prober_for_testing(NULL);
    model_reset();
    return failures;
}

int check_sync_service_configured_inbound(void)
{
    int failures = 0;
    chain_params_select(CHAIN_REGTEST);
    failures += test_configured_inbound_every_interleaving();
    failures += test_mutual_dial_plaintext_unchanged();
    failures += test_mutual_dial_lower_key_dials_first();
    failures += test_mutual_dial_higher_key_dials_first();
    failures += test_mutual_dial_simultaneous();
    failures += test_mutual_dial_reconnect_after_publisher_loss();
    failures += test_mutual_dial_impostor_has_no_privilege();
    failures += test_mutual_dial_target_binds_the_dialed_key();
    failures += test_mutual_dial_kept_side_stays_quiet();
    failures += test_mutual_dial_unconfigured_peer();
    failures += test_mutual_dial_decision_log_rate_limited();
    failures += test_configured_inbound_reconnect_reproves();
    failures += test_configured_inbound_publisher_loss();
    failures += test_configured_inbound_refusals();
    failures += test_configured_inbound_same_limits_as_outbound();
    failures += test_configured_inbound_refetches_missing_bodies();
    failures += test_configured_inbound_hollow_window_still_measures();
    failures += test_configured_inbound_durable_anchor_window_measures();
    failures += test_configured_inbound_no_anchor_window_stays_honest();
    failures += test_configured_inbound_outbound_unchanged();
    failures += test_configured_inbound_probe_socket();
    failures += test_configured_inbound_probe_deadline();
    failures += test_configured_inbound_probe_stop();
    failures += test_configured_inbound_probe_thread();
    failures += test_configured_inbound_revocation();
    failures += test_configured_inbound_probe_generation();
    model_reset();
    configured_sync_peers_set_prober_for_testing(NULL);
    configured_sync_peers_set_clock_for_testing(NULL);
    sync_set_state(SYNC_IDLE, "configured inbound done");
    return failures;
}
