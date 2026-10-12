/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * directlink punch state machine, driven through the deterministic datagram
 * network with NAT models. Reflexive addresses are learned the way a paired
 * peer would report them: one datagram to a public observer, which reads the
 * source address it sees. */

#include "test/test_core.h"

#include "crypto/hmac_sha3.h"
#include "gamelink/directlink_punch.h"
#include "test/directlink_netsim.h"

#include <string.h>

#define STEP_MS 10
#define RUN_LIMIT_MS 6000

struct endpoint {
    struct ns *net;
    int node;
};

struct side {
    struct endpoint ep;
    struct directlink_punch punch;
    struct directlink_addr host;
    struct directlink_addr reflexive;
    struct directlink_addr external; /* what the peer should end up using */
};

struct scene {
    struct ns net;
    int observer;
    struct side a;
    struct side b;
};

static const uint8_t k_key[32] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
                                  15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
                                  26, 27, 28, 29, 30, 31, 32};
static const uint8_t k_session[16] = {0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5,
                                      0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB,
                                      0xAC, 0xAD, 0xAE, 0xAF};

static bool ep_send(void *ctx, const struct directlink_addr *to,
                    const uint8_t *bytes, size_t len)
{
    struct endpoint *ep = ctx;
    return ns_send(ep->net, ep->node, to, bytes, len);
}

static int64_t ep_now(void *ctx)
{
    return ((struct endpoint *)ctx)->net->now_ms;
}

static void add_side(struct scene *sc, struct side *side, uint8_t id,
                     enum ns_nat_kind kind)
{
    uint8_t ext[4] = {45, 20, 113, id};
    if (kind == NS_NAT_NONE) {
        side->host = ns_ip4(45, 10, 100, id, 5000);
        side->ep.node = ns_add_public(&sc->net, side->host, 20);
    } else {
        side->host = ns_ip4(10, 0, id, 2, 5000);
        side->ep.node = ns_add_natted(&sc->net, side->host, 20, kind, ext, 30000);
    }
    side->ep.net = &sc->net;
}

/* The observer reports the source address it saw. */
static void discover(struct scene *sc, struct side *side)
{
    struct directlink_addr observer = ns_ip4(45, 30, 2, 1, 3478);
    struct ns_dgram d;
    (void)ns_send(&sc->net, side->ep.node, &observer, (const uint8_t *)"?", 1);
    ns_advance(&sc->net, sc->net.now_ms + 100);
    side->reflexive = side->host;
    if (ns_recv(&sc->net, sc->observer, &d))
        side->reflexive = d.from;
}

static void arm(struct side *me, const struct side *peer,
                bool initiator, int64_t delay_ms)
{
    struct directlink_punch_ops ops = {ep_send, ep_now, &me->ep};
    struct directlink_punch_config cfg;
    memset(&cfg, 0, sizeof cfg);
    memcpy(cfg.session_id, k_session, sizeof k_session);
    memcpy(cfg.key, k_key, sizeof k_key);
    cfg.initiator = initiator;
    cfg.allow_internal = true;
    cfg.remote[0] = peer->host;
    cfg.remote[1] = peer->reflexive;
    cfg.remote_count = directlink_addr_equal(&peer->host, &peer->reflexive) ? 1u : 2u;
    cfg.start_delay_ms = delay_ms;
    (void)directlink_punch_start(&me->punch, &ops, &cfg);
}

static void scene_build(struct scene *sc, uint64_t seed, uint32_t loss_ppm,
                        enum ns_nat_kind ka, enum ns_nat_kind kb)
{
    memset(sc, 0, sizeof *sc);
    ns_init(&sc->net, seed, 0);
    sc->observer = ns_add_public(&sc->net, ns_ip4(45, 30, 2, 1, 3478), 20);
    add_side(sc, &sc->a, 10, ka);
    add_side(sc, &sc->b, 20, kb);
    discover(sc, &sc->a);
    discover(sc, &sc->b);
    sc->net.loss_ppm = loss_ppm;
    arm(&sc->a, &sc->b, true, 50);
    arm(&sc->b, &sc->a, false, 50);
}

static void pump(struct scene *sc, struct side *me)
{
    struct ns_dgram d;
    while (ns_recv(&sc->net, me->ep.node, &d))
        directlink_punch_on_datagram(&me->punch, &d.from, d.bytes, d.len);
}

static bool both_done(const struct scene *sc)
{
    return sc->a.punch.outcome != DIRECTLINK_OUTCOME_PENDING &&
           sc->b.punch.outcome != DIRECTLINK_OUTCOME_PENDING;
}

static void run(struct scene *sc)
{
    int64_t end = sc->net.now_ms + RUN_LIMIT_MS;
    while (!both_done(sc) && sc->net.now_ms < end) {
        directlink_punch_tick(&sc->a.punch);
        directlink_punch_tick(&sc->b.punch);
        ns_advance(&sc->net, sc->net.now_ms + STEP_MS);
        pump(sc, &sc->a);
        pump(sc, &sc->b);
    }
}

/* Both ends direct, each pointing at the other's real external address. */
static bool both_direct_to_truth(const struct scene *sc)
{
    struct directlink_addr wa, wb;
    if (!directlink_punch_result(&sc->a.punch, &wa) ||
        !directlink_punch_result(&sc->b.punch, &wb))
        return false;
    return directlink_addr_same_host(&wa, &sc->b.reflexive) &&
           directlink_addr_same_host(&wb, &sc->a.reflexive);
}

static int dlp_case_cone_cone(void)
{
    int failures = 0;
    TEST_CASE("punch: (full cone, full cone) connects directly") {
        struct scene sc;
        scene_build(&sc, 1, 0, NS_NAT_FULL_CONE, NS_NAT_FULL_CONE);
        run(&sc);
        ASSERT_EQ((int)sc.a.punch.outcome, (int)DIRECTLINK_OUTCOME_DIRECT);
        ASSERT_EQ((int)sc.b.punch.outcome, (int)DIRECTLINK_OUTCOME_DIRECT);
        ASSERT(both_direct_to_truth(&sc));
        struct directlink_addr w;
        ASSERT(directlink_punch_result(&sc.a.punch, &w));
        ASSERT(directlink_addr_equal(&w, &sc.b.reflexive));
        ASSERT_EQ(directlink_punch_keepalive_ms(&sc.a.punch),
                  (int64_t)DIRECTLINK_PUNCH_DEFAULT_KEEPALIVE_MS);
    } TEST_END;
    return failures;
}

static int dlp_case_restricted(void)
{
    int failures = 0;
    TEST_CASE("punch: (port-restricted, port-restricted) needs simultaneous open") {
        struct scene sc;
        scene_build(&sc, 1, 0, NS_NAT_PORT_RESTRICTED, NS_NAT_PORT_RESTRICTED);
        run(&sc);
        ASSERT_EQ((int)sc.a.punch.state, (int)DIRECTLINK_PUNCH_SUCCEEDED);
        ASSERT_EQ((int)sc.b.punch.state, (int)DIRECTLINK_PUNCH_SUCCEEDED);
        ASSERT(both_direct_to_truth(&sc));
        /* B starts late: A's early probes meet a NAT with no permission. */
        struct scene late;
        scene_build(&late, 1, 0, NS_NAT_PORT_RESTRICTED, NS_NAT_PORT_RESTRICTED);
        arm(&late.b, &late.a, false, 400);
        run(&late);
        ASSERT(late.net.dropped_nat > 0);
        ASSERT(both_direct_to_truth(&late));
        struct directlink_addr w;
        ASSERT(directlink_punch_result(&sc.b.punch, &w));
        ASSERT(directlink_addr_equal(&w, &sc.a.reflexive));
    } TEST_END;
    return failures;
}

static int dlp_case_open_restricted(void)
{
    int failures = 0;
    TEST_CASE("punch: (open, port-restricted) connects directly") {
        struct scene sc;
        scene_build(&sc, 1, 0, NS_NAT_NONE, NS_NAT_PORT_RESTRICTED);
        run(&sc);
        ASSERT_EQ((int)sc.a.punch.outcome, (int)DIRECTLINK_OUTCOME_DIRECT);
        ASSERT_EQ((int)sc.b.punch.outcome, (int)DIRECTLINK_OUTCOME_DIRECT);
        ASSERT(both_direct_to_truth(&sc));
        struct directlink_addr w;
        ASSERT(directlink_punch_result(&sc.b.punch, &w));
        ASSERT(directlink_addr_equal(&w, &sc.a.host));
    } TEST_END;
    return failures;
}

static int dlp_case_symmetric_fallback(void)
{
    int failures = 0;
    TEST_CASE("punch: (symmetric, symmetric) falls back within the timeout") {
        struct scene sc;
        scene_build(&sc, 1, 0, NS_NAT_SYMMETRIC, NS_NAT_SYMMETRIC);
        int64_t started = sc.net.now_ms;
        run(&sc);
        ASSERT_EQ((int)sc.a.punch.outcome,
                  (int)DIRECTLINK_OUTCOME_FALLBACK_TO_ONION);
        ASSERT_EQ((int)sc.b.punch.outcome,
                  (int)DIRECTLINK_OUTCOME_FALLBACK_TO_ONION);
        ASSERT_EQ((int)sc.a.punch.state, (int)DIRECTLINK_PUNCH_FAILED);
        struct directlink_addr w;
        ASSERT(!directlink_punch_result(&sc.a.punch, &w));
        int64_t budget = 50 + (int64_t)DIRECTLINK_PUNCH_DEFAULT_ROUNDS *
                                  DIRECTLINK_PUNCH_DEFAULT_INTERVAL_MS +
                         DIRECTLINK_PUNCH_DEFAULT_GRACE_MS + STEP_MS;
        ASSERT(sc.a.punch.finished_ms - started <= budget);
        ASSERT(sc.a.punch.finished_ms >= sc.a.punch.deadline_ms);
        /* Probing is bounded by the retry budget. */
        ASSERT(sc.a.punch.stats.probes_sent <=
               DIRECTLINK_PUNCH_DEFAULT_ROUNDS * 2u);
        /* Symmetric on one side only still cannot reach a port-restricted peer. */
        struct scene mixed;
        scene_build(&mixed, 1, 0, NS_NAT_SYMMETRIC, NS_NAT_PORT_RESTRICTED);
        run(&mixed);
        ASSERT_EQ((int)mixed.a.punch.outcome,
                  (int)DIRECTLINK_OUTCOME_FALLBACK_TO_ONION);
    } TEST_END;
    return failures;
}

static int dlp_case_symmetric_cone(void)
{
    int failures = 0;
    TEST_CASE("punch: (symmetric, full cone) succeeds via the learned source port") {
        struct scene sc;
        scene_build(&sc, 1, 0, NS_NAT_SYMMETRIC, NS_NAT_FULL_CONE);
        run(&sc);
        ASSERT_EQ((int)sc.a.punch.outcome, (int)DIRECTLINK_OUTCOME_DIRECT);
        ASSERT_EQ((int)sc.b.punch.outcome, (int)DIRECTLINK_OUTCOME_DIRECT);
        ASSERT(sc.b.punch.stats.learned >= 1);
        struct directlink_addr w;
        ASSERT(directlink_punch_result(&sc.a.punch, &w));
        ASSERT(directlink_addr_equal(&w, &sc.b.reflexive));
        /* B reaches A on the port A's NAT opened toward B, not the observer's. */
        ASSERT(directlink_punch_result(&sc.b.punch, &w));
        ASSERT(w.port != sc.a.reflexive.port);
    } TEST_END;
    return failures;
}

static int dlp_case_loss(void)
{
    int failures = 0;
    TEST_CASE("punch: 20% loss still connects within the retry budget") {
        uint32_t lost = 0;
        for (uint64_t seed = 1; seed <= 24; seed++) {
            struct scene sc;
            scene_build(&sc, seed, 200000, NS_NAT_PORT_RESTRICTED,
                        NS_NAT_PORT_RESTRICTED);
            run(&sc);
            ASSERT_EQ((int)sc.a.punch.outcome, (int)DIRECTLINK_OUTCOME_DIRECT);
            ASSERT_EQ((int)sc.b.punch.outcome, (int)DIRECTLINK_OUTCOME_DIRECT);
            ASSERT(both_direct_to_truth(&sc));
            lost += sc.net.dropped_loss;
        }
        ASSERT(lost > 0);
    } TEST_END;
    return failures;
}

static int dlp_case_determinism(void)
{
    int failures = 0;
    TEST_CASE("punch: the same seed gives the same event trace") {
        struct scene one, two, other;
        scene_build(&one, 7, 200000, NS_NAT_PORT_RESTRICTED, NS_NAT_PORT_RESTRICTED);
        scene_build(&two, 7, 200000, NS_NAT_PORT_RESTRICTED, NS_NAT_PORT_RESTRICTED);
        scene_build(&other, 8, 200000, NS_NAT_PORT_RESTRICTED,
                    NS_NAT_PORT_RESTRICTED);
        run(&one);
        run(&two);
        run(&other);
        ASSERT(one.net.events > 0);
        ASSERT_EQ(one.net.events, two.net.events);
        ASSERT_EQ(one.net.digest, two.net.digest);
        ASSERT_EQ(one.net.dropped_loss, two.net.dropped_loss);
        ASSERT_EQ(one.a.punch.finished_ms, two.a.punch.finished_ms);
        ASSERT(one.net.digest != other.net.digest);
    } TEST_END;
    return failures;
}

static void forge(struct directlink_punch *p, uint8_t type, uint8_t role,
                  const uint8_t *session, uint32_t seq, uint8_t mac_fill,
                  const struct directlink_addr *from)
{
    uint8_t wire[DIRECTLINK_PROBE_BYTES];
    memset(wire, 0, sizeof wire);
    memcpy(wire, "ZDP", 3);
    wire[3] = 1;
    wire[4] = type;
    wire[5] = role;
    memcpy(wire + 6, session, 16);
    wire[22] = (uint8_t)seq;
    memset(wire + 26, mac_fill, 16);
    directlink_punch_on_datagram(p, from, wire, sizeof wire);
}

static int dlp_case_attacker(void)
{
    int failures = 0;
    TEST_CASE("punch: an off-path attacker cannot succeed or choose the address") {
        struct directlink_addr evil = ns_ip4(45, 10, 100, 66, 6666);
        /* Forged replies and probes against a machine that cannot connect. */
        struct scene sc;
        scene_build(&sc, 1, 0, NS_NAT_SYMMETRIC, NS_NAT_SYMMETRIC);
        while (sc.net.now_ms < 400) {
            directlink_punch_tick(&sc.a.punch);
            ns_advance(&sc.net, sc.net.now_ms + STEP_MS);
            for (uint32_t seq = 0; seq < 8; seq++) {
                forge(&sc.a.punch, 2, 0, k_session, seq, 0x11, &evil);
                forge(&sc.a.punch, 1, 0, k_session, seq, 0xEE, &evil);
                forge(&sc.a.punch, 2, 0, k_session, seq, 0xEE, &evil);
            }
            uint8_t other_session[16] = {0};
            forge(&sc.a.punch, 2, 0, other_session, 0, 0x11, &evil);
            uint8_t junk[7] = {1, 2, 3, 4, 5, 6, 7};
            directlink_punch_on_datagram(&sc.a.punch, &evil, junk, sizeof junk);
        }
        ASSERT_EQ((int)sc.a.punch.outcome, (int)DIRECTLINK_OUTCOME_PENDING);
        ASSERT(sc.a.punch.stats.dropped_mac > 0);
        ASSERT(sc.a.punch.stats.dropped_session > 0);
        ASSERT(sc.a.punch.stats.dropped_malformed > 0);
        ASSERT_EQ(sc.a.punch.stats.replies_sent, (uint32_t)0);
        ASSERT_EQ(sc.a.punch.learned_count, (size_t)0);
        while (!both_done(&sc)) {
            directlink_punch_tick(&sc.a.punch);
            directlink_punch_tick(&sc.b.punch);
            ns_advance(&sc.net, sc.net.now_ms + STEP_MS);
        }
        ASSERT_EQ((int)sc.a.punch.outcome,
                  (int)DIRECTLINK_OUTCOME_FALLBACK_TO_ONION);
        /* A connectable pair under attack still ends on the real peer. */
        struct scene ok;
        scene_build(&ok, 1, 0, NS_NAT_FULL_CONE, NS_NAT_FULL_CONE);
        while (!both_done(&ok) && ok.net.now_ms < RUN_LIMIT_MS) {
            directlink_punch_tick(&ok.a.punch);
            directlink_punch_tick(&ok.b.punch);
            forge(&ok.a.punch, 2, 0, k_session, 0, 0x11, &evil);
            forge(&ok.b.punch, 2, 1, k_session, 0, 0x11, &evil);
            ns_advance(&ok.net, ok.net.now_ms + STEP_MS);
            pump(&ok, &ok.a);
            pump(&ok, &ok.b);
        }
        ASSERT(both_direct_to_truth(&ok));
        struct directlink_addr w;
        ASSERT(directlink_punch_result(&ok.a.punch, &w));
        ASSERT(!directlink_addr_equal(&w, &evil));
    } TEST_END;
    return failures;
}

struct capture {
    uint8_t wire[DIRECTLINK_PROBE_BYTES];
    size_t count;
};

static bool capture_send(void *ctx, const struct directlink_addr *to,
                         const uint8_t *bytes, size_t len)
{
    struct capture *c = ctx;
    (void)to;
    if (c->count++ == 0 && len == sizeof c->wire)
        memcpy(c->wire, bytes, len);
    return true;
}

static int64_t fixed_now(void *ctx)
{
    (void)ctx;
    return 1000;
}

static int dlp_case_reflection_and_args(void)
{
    int failures = 0;
    TEST_CASE("punch: reflected and wrong-key datagrams are dropped, bad config refused") {
        struct capture cap;
        memset(&cap, 0, sizeof cap);
        struct directlink_punch_ops ops = {capture_send, fixed_now, &cap};
        struct directlink_punch_config cfg;
        memset(&cfg, 0, sizeof cfg);
        memcpy(cfg.session_id, k_session, sizeof k_session);
        memcpy(cfg.key, k_key, sizeof k_key);
        cfg.initiator = true;
        cfg.remote[0] = ns_ip4(45, 20, 113, 20, 40000);
        cfg.remote_count = 1;
        struct directlink_punch p;
        ASSERT(directlink_punch_start(&p, &ops, &cfg));
        directlink_punch_tick(&p);
        ASSERT_EQ(cap.count, (size_t)1);
        /* Our own probe, mirrored back, carries a valid MAC and our role. */
        struct directlink_addr from = ns_ip4(45, 20, 113, 20, 40000);
        directlink_punch_on_datagram(&p, &from, cap.wire, sizeof cap.wire);
        ASSERT_EQ(p.stats.dropped_role, (uint32_t)1);
        ASSERT_EQ(p.stats.replies_sent, (uint32_t)0);
        ASSERT_EQ((int)p.outcome, (int)DIRECTLINK_OUTCOME_PENDING);
        /* A peer holding another key produces a datagram that fails the MAC. */
        struct directlink_punch_config other = cfg;
        other.key[0] ^= 0x01;
        other.initiator = false;
        struct capture cap2;
        memset(&cap2, 0, sizeof cap2);
        struct directlink_punch_ops ops2 = {capture_send, fixed_now, &cap2};
        struct directlink_punch q;
        ASSERT(directlink_punch_start(&q, &ops2, &other));
        directlink_punch_tick(&q);
        directlink_punch_on_datagram(&p, &from, cap2.wire, sizeof cap2.wire);
        ASSERT_EQ(p.stats.dropped_mac, (uint32_t)1);
        ASSERT_EQ((int)p.outcome, (int)DIRECTLINK_OUTCOME_PENDING);
        /* Configuration is validated. */
        struct directlink_punch_config bad = cfg;
        bad.remote_count = 0;
        ASSERT(!directlink_punch_start(&p, &ops, &bad));
        bad = cfg;
        bad.remote[0].port = 0;
        ASSERT(!directlink_punch_start(&p, &ops, &bad));
        bad = cfg;
        bad.remote_count = DIRECTLINK_OFFER_CANDIDATES_MAX + 1;
        ASSERT(!directlink_punch_start(&p, &ops, &bad));
        struct directlink_punch_ops none = {NULL, NULL, NULL};
        ASSERT(!directlink_punch_start(&p, &none, &cfg));
        ASSERT(!directlink_punch_start(NULL, &ops, &cfg));
        cfg.keepalive_ms = 9000;
        ASSERT(directlink_punch_start(&p, &ops, &cfg));
        ASSERT_EQ(directlink_punch_keepalive_ms(&p), (int64_t)9000);
        ASSERT_STR_EQ(directlink_outcome_label(DIRECTLINK_OUTCOME_FALLBACK_TO_ONION),
                      "fallback_to_onion");
    } TEST_END;
    return failures;
}

struct tctx {
    int64_t now;
    size_t sent;
};

static bool tctx_send(void *ctx, const struct directlink_addr *to,
                      const uint8_t *bytes, size_t len)
{
    (void)to;
    (void)bytes;
    (void)len;
    ((struct tctx *)ctx)->sent++;
    return true;
}

static int64_t tctx_now(void *ctx)
{
    return ((struct tctx *)ctx)->now;
}

/* A datagram with a correct MAC, built independently of the implementation. */
static void valid_wire(uint8_t type, uint8_t role, uint32_t seq,
                       uint8_t out[DIRECTLINK_PROBE_BYTES])
{
    memcpy(out, "ZDP", 3);
    out[3] = 1;
    out[4] = type;
    out[5] = role;
    memcpy(out + 6, k_session, 16);
    out[22] = (uint8_t)seq;
    out[23] = (uint8_t)(seq >> 8);
    out[24] = (uint8_t)(seq >> 16);
    out[25] = (uint8_t)(seq >> 24);
    struct hmac_sha3_256_ctx h;
    unsigned char mac[HMAC_SHA3_256_OUTPUT_SIZE];
    hmac_sha3_256_init(&h, k_key, sizeof k_key);
    hmac_sha3_256_write(&h, out, 26);
    hmac_sha3_256_finalize(&h, mac);
    memcpy(out + 26, mac, 16);
}

static void feed(struct directlink_punch *p, const struct directlink_addr *from,
                 uint8_t type, uint32_t seq)
{
    uint8_t wire[DIRECTLINK_PROBE_BYTES];
    valid_wire(type, 0, seq, wire);
    directlink_punch_on_datagram(p, from, wire, sizeof wire);
}

static struct directlink_punch_config base_config(bool internal)
{
    struct directlink_punch_config cfg;
    memset(&cfg, 0, sizeof cfg);
    memcpy(cfg.session_id, k_session, sizeof k_session);
    memcpy(cfg.key, k_key, sizeof k_key);
    cfg.initiator = true;
    cfg.remote[0] = ns_ip4(45, 20, 113, 20, 40000);
    cfg.remote_count = 1;
    cfg.allow_internal = internal;
    return cfg;
}

static int dlp_case_scope_sources(void)
{
    int failures = 0;
    TEST_CASE("punch: sources outside the scope are neither answered nor learned") {
        struct tctx t = {.now = 0};
        struct directlink_punch_ops ops = {tctx_send, tctx_now, &t};
        struct directlink_punch_config cfg = base_config(false);
        struct directlink_punch p;
        ASSERT(directlink_punch_start(&p, &ops, &cfg));
        directlink_punch_tick(&p);
        struct directlink_addr lan = ns_ip4(10, 0, 0, 9, 1234);
        struct directlink_addr loop = ns_ip4(127, 0, 0, 1, 9);
        feed(&p, &lan, 1, 0);
        feed(&p, &loop, 1, 0);
        ASSERT_EQ(p.stats.replies_sent, (uint32_t)0);
        ASSERT_EQ(p.stats.dropped_source, (uint32_t)2);
        ASSERT_EQ(p.learned_count, (size_t)0);
        /* A reply from an internal source cannot complete the punch either. */
        feed(&p, &lan, 2, 0);
        ASSERT_EQ((int)p.outcome, (int)DIRECTLINK_OUTCOME_PENDING);
        /* Intra scope answers and learns a private source, never loopback. */
        struct directlink_punch_config intra = base_config(true);
        struct directlink_punch q;
        ASSERT(directlink_punch_start(&q, &ops, &intra));
        directlink_punch_tick(&q);
        feed(&q, &lan, 1, 0);
        feed(&q, &loop, 1, 0);
        ASSERT_EQ(q.stats.replies_sent, (uint32_t)1);
        ASSERT_EQ(q.learned_count, (size_t)1);
        ASSERT(directlink_addr_equal(&q.learned[0], &lan));
    } TEST_END;
    return failures;
}

static int dlp_case_learned_cap_and_budget(void)
{
    int failures = 0;
    TEST_CASE("punch: the learned cap and the reply budget hold") {
        struct tctx t = {.now = 0};
        struct directlink_punch_ops ops = {tctx_send, tctx_now, &t};
        struct directlink_punch_config cfg = base_config(false);
        struct directlink_punch p;
        ASSERT(directlink_punch_start(&p, &ops, &cfg));
        directlink_punch_tick(&p);
        for (uint8_t i = 1; i <= 6; i++) {
            struct directlink_addr src = ns_ip4(45, 30, 1, i, 5000);
            feed(&p, &src, 1, i);
        }
        ASSERT_EQ(p.learned_count, (size_t)DIRECTLINK_PUNCH_LEARNED_MAX);
        ASSERT_EQ(p.stats.learned, (uint32_t)DIRECTLINK_PUNCH_LEARNED_MAX);
        ASSERT_EQ(p.stats.replies_sent, (uint32_t)6);
        /* After completion nothing is learned and replies stop at the budget. */
        feed(&p, &cfg.remote[0], 2, 0);
        ASSERT_EQ((int)p.outcome, (int)DIRECTLINK_OUTCOME_DIRECT);
        struct directlink_addr fixed = p.working;
        struct directlink_addr other = ns_ip4(45, 30, 9, 9, 6000);
        feed(&p, &other, 2, 0);
        ASSERT(directlink_addr_equal(&p.working, &fixed));
        for (uint32_t i = 0; i < 300; i++)
            feed(&p, &other, 1, i);
        ASSERT_EQ(p.stats.replies_sent, (uint32_t)DIRECTLINK_PUNCH_REPLY_BUDGET);
        ASSERT(p.stats.dropped_budget > 0);
        ASSERT_EQ(p.learned_count, (size_t)DIRECTLINK_PUNCH_LEARNED_MAX);
        ASSERT_EQ(t.sent, (size_t)(1 + DIRECTLINK_PUNCH_REPLY_BUDGET));
        /* A completed punch learns nothing, whatever the cap. */
        struct directlink_punch done;
        ASSERT(directlink_punch_start(&done, &ops, &cfg));
        directlink_punch_tick(&done);
        feed(&done, &cfg.remote[0], 2, 0);
        ASSERT_EQ((int)done.outcome, (int)DIRECTLINK_OUTCOME_DIRECT);
        feed(&done, &other, 1, 0);
        ASSERT_EQ(done.learned_count, (size_t)0);
        ASSERT_EQ(done.stats.learned, (uint32_t)0);
    } TEST_END;
    return failures;
}

static int dlp_case_after_failure(void)
{
    int failures = 0;
    TEST_CASE("punch: nothing changes after failure and unsent sequence numbers do not complete") {
        struct tctx t = {.now = 0};
        struct directlink_punch_ops ops = {tctx_send, tctx_now, &t};
        struct directlink_punch_config cfg = base_config(false);
        struct directlink_punch p;
        ASSERT(directlink_punch_start(&p, &ops, &cfg));
        /* Before any probe is sent, no sequence number was sent. */
        feed(&p, &cfg.remote[0], 2, 0);
        ASSERT_EQ((int)p.outcome, (int)DIRECTLINK_OUTCOME_PENDING);
        directlink_punch_tick(&p);
        ASSERT_EQ(p.next_seq, (uint32_t)1);
        feed(&p, &cfg.remote[0], 2, 5);
        feed(&p, &cfg.remote[0], 2, 1);
        ASSERT_EQ((int)p.outcome, (int)DIRECTLINK_OUTCOME_PENDING);
        ASSERT_EQ(p.stats.dropped_unsolicited, (uint32_t)3);
        t.now = 100000;
        directlink_punch_tick(&p);
        ASSERT_EQ((int)p.outcome, (int)DIRECTLINK_OUTCOME_FALLBACK_TO_ONION);
        struct directlink_punch_stats before = p.stats;
        size_t sent = t.sent;
        feed(&p, &cfg.remote[0], 2, 0);
        feed(&p, &cfg.remote[0], 1, 0);
        directlink_punch_tick(&p);
        ASSERT(memcmp(&before, &p.stats, sizeof before) == 0);
        ASSERT_EQ(t.sent, sent);
        ASSERT_EQ((int)p.outcome, (int)DIRECTLINK_OUTCOME_FALLBACK_TO_ONION);
        struct directlink_addr w;
        ASSERT(!directlink_punch_result(&p, &w));
    } TEST_END;
    return failures;
}

static int dlp_case_config_bounds(void)
{
    int failures = 0;
    TEST_CASE("punch: timing floors and ceilings and the scope are enforced at start") {
        struct tctx t = {.now = 0};
        struct directlink_punch_ops ops = {tctx_send, tctx_now, &t};
        struct directlink_punch p;
        struct directlink_punch_config c = base_config(false);
        ASSERT(directlink_punch_start(&p, &ops, &c));
        c.interval_ms = DIRECTLINK_PUNCH_INTERVAL_MIN_MS - 1;
        ASSERT(!directlink_punch_start(&p, &ops, &c));
        c.interval_ms = DIRECTLINK_PUNCH_INTERVAL_MIN_MS;
        ASSERT(directlink_punch_start(&p, &ops, &c));
        c.interval_ms = DIRECTLINK_PUNCH_INTERVAL_MAX_MS + 1;
        ASSERT(!directlink_punch_start(&p, &ops, &c));
        c = base_config(false);
        c.max_rounds = DIRECTLINK_PUNCH_ROUNDS_MAX + 1;
        ASSERT(!directlink_punch_start(&p, &ops, &c));
        c.max_rounds = DIRECTLINK_PUNCH_ROUNDS_MAX;
        ASSERT(directlink_punch_start(&p, &ops, &c));
        c = base_config(false);
        c.reply_grace_ms = DIRECTLINK_PUNCH_GRACE_MAX_MS + 1;
        ASSERT(!directlink_punch_start(&p, &ops, &c));
        c = base_config(false);
        c.start_delay_ms = (int64_t)DIRECTLINK_OFFER_DELAY_MAX_MS + 1;
        ASSERT(!directlink_punch_start(&p, &ops, &c));
        c = base_config(false);
        c.remote[0] = ns_ip4(10, 0, 0, 2, 5000);
        ASSERT(!directlink_punch_start(&p, &ops, &c));
        c.remote[0] = ns_ip4(127, 0, 0, 1, 5000);
        ASSERT(!directlink_punch_start(&p, &ops, &c));
        c.allow_internal = true;
        ASSERT(directlink_punch_start(&p, &ops, &c));
    } TEST_END;
    return failures;
}

int test_directlink_punch(void)
{
    int failures = 0;
    failures += dlp_case_cone_cone();
    failures += dlp_case_restricted();
    failures += dlp_case_open_restricted();
    failures += dlp_case_symmetric_fallback();
    failures += dlp_case_symmetric_cone();
    failures += dlp_case_loss();
    failures += dlp_case_determinism();
    failures += dlp_case_attacker();
    failures += dlp_case_reflection_and_args();
    failures += dlp_case_scope_sources();
    failures += dlp_case_learned_cap_and_budget();
    failures += dlp_case_after_failure();
    failures += dlp_case_config_bounds();
    return failures;
}
