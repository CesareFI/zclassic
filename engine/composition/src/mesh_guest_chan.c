/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: The guest byte-channel adapter. Carries up to four device ports
 * over mesh streams named "guest.chan", gated by one authorisation function
 * that is evaluated before every action (see the header).
 *
 * LOCK ORDER (frozen): mesh lane lock, then the adapter mutex, then the
 * device; never the reverse. Stream callbacks arrive under the lane lock
 * and take the adapter mutex. Host ops (called by the device pump, no lane
 * lock) take only the adapter mutex and never call a device op or a stream
 * verb: they validate the token, move bytes between the device and the
 * bounded per-port buffers and queue work. The adapter pump and the stream
 * callbacks perform the queued work: device write/end/resume/accept calls,
 * and mesh_stream_send/_grant/_close/_release on the port's own stream.
 * mesh_stream_open and mesh_stream_visit are called only from the pump and
 * from set_enabled, with no adapter mutex held.
 *
 * The adapter mutex is re-entrant per thread: closing a stream from inside
 * the adapter re-enters on_close/on_release, which then see that the
 * adapter is already ending the port.
 *
 * Outbound bytes from the guest are copied by from_guest into a per-port
 * buffer of one frame and sent from the pump or on_tick, because
 * mesh_stream_send needs the lane lock the device pump does not hold.
 *
 * All state is static and bounded; nothing is allocated. The adapter's only
 * outward path is the stream primitive.
 */

#include "config/mesh_guest_chan.h"

#include "config/mesh_stream.h"
#include "config/runtime.h"
#include "models/mesh_pairing.h"
#include "platform/time_compat.h"
#include "util/log_macros.h"
#include "util/sync.h"

#include <stdatomic.h>
#include <string.h>

#define GC_PORTS GUEST_CHAN_PORTS_MAX
#define GC_BUF GUEST_CHAN_RUN_MAX
#define GC_PAIRING_ROWS 64

struct gc_port {
    bool used;         /* the index is reserved */
    bool live;         /* the token is valid for host ops */
    bool outbound;
    bool open_queued;  /* outbound OPEN waits for the pump */
    bool open_decided; /* outbound: the pump's open check has run and passed */
    bool bound;        /* a stream's service_state points here */
    bool self_closing; /* the adapter is closing this port's stream */
    bool end_sent;     /* device end() was called */
    bool end_pending;  /* ended by a host op; the pump settles it */
    bool reoffer;      /* writable or drained arrived */
    bool out_stalled;  /* from_guest took less than offered */
    enum guest_chan_end end_why;
    uint32_t generation;
    uint8_t peer[32];
    size_t in_off;     /* suffix the device has not taken: in_buf[in_off..in_len) */
    size_t in_len;
    size_t out_len;
    uint64_t delivered; /* taken by the device, not yet reported drained */
    uint64_t owed;      /* drained, not yet granted back */
    int64_t last_activity;
    uint8_t in_buf[GC_BUF];
    uint8_t out_buf[GC_BUF];
};

static struct {
    zcl_mutex_t lock;
    bool attached;
    bool enabled;
    struct guest_chan_device_ops ops;
    guest_chan_peer_accept_v2_fn accept_peer;
    void *dev;
    struct mesh_guest_chan_limits lim;
    struct mesh_guest_chan_stats stats;
    int64_t clock;
    struct gc_port ports[GC_PORTS];
} g;

static _Atomic int g_lock_state;
static _Thread_local unsigned t_depth;

static void gc_lock(void)
{
    if (t_depth++ != 0)
        return;
    if (atomic_load_explicit(&g_lock_state, memory_order_acquire) != 2) {
        int expected = 0;
        if (atomic_compare_exchange_strong_explicit(
                &g_lock_state, &expected, 1, memory_order_acq_rel,
                memory_order_acquire)) {
            zcl_mutex_init(&g.lock);
            atomic_store_explicit(&g_lock_state, 2, memory_order_release);
        } else {
            while (atomic_load_explicit(&g_lock_state,
                                        memory_order_acquire) != 2)
                ;
        }
    }
    zcl_mutex_lock(&g.lock);
}

static void gc_unlock(void)
{
    if (--t_depth == 0)
        zcl_mutex_unlock(&g.lock);
}

/* ── helpers (adapter mutex held) ────────────────────────────────────── */

static int64_t gc_clock(void)
{
    return g.clock > 0 ? g.clock : (int64_t)platform_time_wall_time_t();
}

static struct guest_chan_port gc_token(const struct gc_port *p)
{
    struct guest_chan_port t = {(uint32_t)(p - g.ports), p->generation};
    return t;
}

static struct gc_port *gc_port_of(const struct mesh_stream *st)
{
    uintptr_t v = st ? (uintptr_t)st->service_state : 0;
    uintptr_t lo = (uintptr_t)&g.ports[0];
    uintptr_t hi = (uintptr_t)&g.ports[GC_PORTS];
    if (v < lo || v >= hi)
        return NULL;
    return (struct gc_port *)v;
}

static struct gc_port *gc_find_live(struct guest_chan_port tok)
{
    if (tok.index < GC_PORTS && tok.generation != 0) {
        struct gc_port *p = &g.ports[tok.index];
        if (p->used && p->live && p->generation == tok.generation)
            return p;
    }
    g.stats.stale_token_dropped++;
    return NULL;
}

static size_t gc_pending(const struct gc_port *p)
{
    return p->in_len - p->in_off;
}

static size_t gc_buffered(void)
{
    size_t total = 0;
    for (size_t i = 0; i < GC_PORTS; i++)
        if (g.ports[i].used)
            total += gc_pending(&g.ports[i]) + g.ports[i].out_len;
    return total;
}

static void gc_free(struct gc_port *p)
{
    memset(p, 0, sizeof(*p));
}

/* The authorisation function. A fresh read of the pairing rows, the same
 * read the stream primitive makes before on_open: revocation is a database
 * update, so the database is the serialisation point. */
static bool gc_pairing_allows(const uint8_t peer[32])
{
    struct node_db *ndb = app_runtime_node_db();
    if (!ndb)
        return false;
    struct db_mesh_pairing rows[GC_PAIRING_ROWS];
    int count = db_mesh_pairing_list(ndb, rows, GC_PAIRING_ROWS);
    int64_t now = (int64_t)platform_time_wall_time_t();
    for (int i = 0; i < count; i++) {
        if (memcmp(rows[i].peer_noise_pubkey, peer, 32) != 0)
            continue;
        if (mesh_pairing_allows(&rows[i], MESH_PAIRING_CAP_GUEST_CHAN, now))
            return true;
    }
    return false;
}

static bool guest_chan_allowed(const uint8_t peer[32])
{
    return g.enabled && gc_pairing_allows(peer);
}

static void gc_count_end(enum guest_chan_end why)
{
    switch (why) {
    case GUEST_CHAN_END_REVOKED:
        g.stats.ended_revoked++;
        break;
    case GUEST_CHAN_END_PROTOCOL:
        g.stats.ended_protocol++;
        break;
    case GUEST_CHAN_END_IDLE:
        g.stats.ended_idle++;
        break;
    default:
        break;
    }
}

/* Tell the device the port ended, exactly once. A reason queued by a host
 * op wins over the one the settling code passes. */
static void gc_tell_device_end(struct gc_port *p, enum guest_chan_end why)
{
    if (p->end_sent)
        return;
    if (p->end_pending)
        why = p->end_why;
    p->end_sent = true;
    p->live = false;
    p->open_queued = false;
    gc_count_end(why);
    g.ops.end(g.dev, gc_token(p), why);
}

/* End a port from a stream context (or with no stream at all). After this
 * returns the port may have been released: the caller must not touch it. */
static void gc_finish(struct gc_port *p, struct mesh_stream *st,
                      enum guest_chan_end why)
{
    gc_tell_device_end(p, why);
    if (st && !p->self_closing) {
        p->self_closing = true;
        mesh_stream_close(st, MESH_STREAM_CLOSED_BY_SERVICE, NULL, 0);
        mesh_stream_release(st); /* on_release frees the port */
        return;
    }
    if (!p->bound)
        gc_free(p);
}

/* Queue an end from a host op: the token stops being live at once, the
 * device is told and the stream closed from the pump. */
static void gc_mark_end(struct gc_port *p, enum guest_chan_end why)
{
    if (!p->live)
        return;
    p->live = false;
    p->open_queued = false;
    p->end_pending = true;
    p->end_why = why;
}

/* A stream layer verdict as the device sees it. Every named refusal (the
 * peer says unpaired, no such service, over a cap, not connected, ...) is
 * UNAVAILABLE so the guest can tell a refusal from a clean close; only a
 * close the service itself asked for, or none at all, is NORMAL. */
static enum guest_chan_end gc_map_close(enum mesh_stream_refusal reason)
{
    if (reason >= MESH_STREAM_REFUSED_LINK_NOT_NOISE &&
        reason <= MESH_STREAM_REFUSED_PEER_NOT_CONNECTED)
        return GUEST_CHAN_END_UNAVAILABLE;
    switch (reason) {
    case MESH_STREAM_ENDED_SESSION_LOST:
        return GUEST_CHAN_END_SESSION_LOST;
    case MESH_STREAM_ENDED_SHUTDOWN:
        return GUEST_CHAN_END_SHUTDOWN;
    case MESH_STREAM_ENDED_IDLE:
        return GUEST_CHAN_END_IDLE;
    default:
        return GUEST_CHAN_END_NORMAL;
    }
}

/* ── per-port work (adapter mutex held, stream in hand) ──────────────── */

/* False means the port ended and must not be touched again. */
static bool gc_gate(struct gc_port *p, struct mesh_stream *st)
{
    if (!p->live) {
        gc_finish(p, st, p->end_why);
        return false;
    }
    if (!g.enabled) {
        gc_finish(p, st, GUEST_CHAN_END_SHUTDOWN);
        return false;
    }
    if (!guest_chan_allowed(p->peer)) {
        gc_finish(p, st, GUEST_CHAN_END_REVOKED);
        return false;
    }
    return true;
}

static bool gc_idle_ok(struct gc_port *p, struct mesh_stream *st, int64_t now)
{
    if (g.lim.idle_seconds != 0 &&
        now - p->last_activity >= (int64_t)g.lim.idle_seconds) {
        gc_finish(p, st, GUEST_CHAN_END_IDLE);
        return false;
    }
    return true;
}

static void gc_note_taken(struct gc_port *p, size_t k)
{
    p->delivered += k;
    g.stats.bytes_to_guest += k;
    if (k)
        p->last_activity = gc_clock();
}

/* Offer the held suffix to the device once. */
static bool gc_reoffer(struct gc_port *p, struct mesh_stream *st)
{
    size_t pending = gc_pending(p);
    if (!p->reoffer)
        return true;
    p->reoffer = false;
    if (pending == 0)
        return true;
    size_t k = g.ops.write(g.dev, gc_token(p), p->in_buf + p->in_off, pending);
    if (k > pending) {
        gc_finish(p, st, GUEST_CHAN_END_PROTOCOL);
        return false;
    }
    gc_note_taken(p, k);
    p->in_off += k;
    if (p->in_off == p->in_len)
        p->in_off = p->in_len = 0;
    return true;
}

/* Credit goes back only for bytes the device reported drained, and only
 * while the aggregate buffered across ports is within the pump bound. */
static void gc_grant_step(struct gc_port *p, struct mesh_stream *st)
{
    if (p->owed == 0 || gc_buffered() > g.lim.pump_bytes_max)
        return;
    uint32_t head = st->recv_credit >= g.lim.window
                        ? 0
                        : g.lim.window - st->recv_credit;
    uint32_t amount = p->owed < head ? (uint32_t)p->owed : head;
    if (amount == 0)
        return;
    /* The credit leaves `owed` only when the grant went out. The primitive
     * records the room locally before it tries the wire, so on a failed
     * send that local record is undone and the credit stays owed for the
     * next pass: a failed grant never loses credit. */
    uint32_t before = st->recv_credit;
    if (mesh_stream_grant(st, amount)) {
        p->owed -= amount;
    } else if (st->recv_credit == before + amount) {
        st->recv_credit = before;
    }
}

static void gc_send_step(struct gc_port *p, struct mesh_stream *st)
{
    if (p->out_len > 0) {
        size_t n = p->out_len;
        if (n > (size_t)st->send_credit)
            n = (size_t)st->send_credit;
        if (n > MESH_STREAM_PAYLOAD_MAX)
            n = MESH_STREAM_PAYLOAD_MAX;
        if (n > 0 && mesh_stream_send(st, p->out_buf, n)) {
            memmove(p->out_buf, p->out_buf + n, p->out_len - n);
            p->out_len -= n;
            g.stats.bytes_from_guest += n;
            p->last_activity = gc_clock();
        }
    }
    if (p->out_stalled && p->out_len == 0) {
        if (!gc_gate(p, st)) /* the resume below is a device callback */
            return;
        p->out_stalled = false;
        g.ops.resume(g.dev, gc_token(p));
    }
}

static void gc_step(struct gc_port *p, struct mesh_stream *st, int64_t now)
{
    if (!gc_gate(p, st) || !gc_idle_ok(p, st, now) || !gc_reoffer(p, st))
        return;
    /* The device write above is a callback: authority is read again
     * before the grant verb and again before the send verb. */
    if (!gc_gate(p, st))
        return;
    gc_grant_step(p, st);
    if (!gc_gate(p, st))
        return;
    gc_send_step(p, st);
}

/* ── stream callbacks (lane lock held by the caller) ─────────────────── */

static size_t gc_count_ports(const uint8_t *peer)
{
    size_t n = 0;
    for (size_t i = 0; i < GC_PORTS; i++)
        if (g.ports[i].used &&
            (!peer || memcmp(g.ports[i].peer, peer, 32) == 0))
            n++;
    return n;
}

static bool gc_bounds_ok(const uint8_t *peer)
{
    if (gc_count_ports(NULL) >= g.lim.total_max ||
        gc_count_ports(peer) >= g.lim.per_peer_max) {
        g.stats.refused_bound++;
        return false;
    }
    return true;
}

static bool gc_token_free(struct guest_chan_port tok)
{
    return tok.index < GC_PORTS && tok.generation != 0 &&
           !g.ports[tok.index].used;
}

/* The device handed accept() a token that cannot be a new port: index out
 * of range, generation 0, or an index already in use. The header says the
 * port ends with PROTOCOL, so the device is told. A token that names a
 * port already live here is that same port: it is ended (queued, settled
 * by the pump) rather than answered with a second end() on the same
 * token. Any other bad token is ended directly; it names no port of ours. */
static void gc_reject_token(struct guest_chan_port tok)
{
    struct gc_port *live = tok.index < GC_PORTS ? &g.ports[tok.index] : NULL;
    if (live && live->used && live->live && tok.generation != 0 &&
        live->generation == tok.generation) {
        gc_mark_end(live, GUEST_CHAN_END_PROTOCOL);
        return;
    }
    gc_count_end(GUEST_CHAN_END_PROTOCOL);
    g.ops.end(g.dev, tok, GUEST_CHAN_END_PROTOCOL);
}

static void gc_claim(struct gc_port *p, uint32_t generation,
                     const uint8_t peer[32], bool outbound)
{
    gc_free(p);
    p->used = true;
    p->live = true;
    p->outbound = outbound;
    p->generation = generation;
    memcpy(p->peer, peer, 32);
    p->last_activity = gc_clock();
    if (outbound)
        p->open_queued = true;
    else
        p->bound = true;
}

static bool gc_reply_valid(size_t produced, size_t capacity, const uint8_t *reply,
    const size_t *reply_length)
{
    return produced <= capacity && (!produced || (reply && reply_length));
}
static enum mesh_stream_refusal gc_admit(struct mesh_stream *st,
    const uint8_t *payload, size_t length, uint8_t *reply, size_t capacity,
    size_t *reply_length)
{
    if (!g.attached || !g.enabled) {
        g.stats.refused_disabled++;
        return MESH_STREAM_REFUSED_UNAVAILABLE;
    }
    if (st->recv_credit > g.lim.window) {
        g.stats.refused_bound++;
        return MESH_STREAM_REFUSED_CAP;
    }
    if (!gc_pairing_allows(st->peer_static)) {
        g.stats.refused_unpaired++;
        return MESH_STREAM_REFUSED_UNAVAILABLE;
    }
    if (!gc_bounds_ok(st->peer_static))
        return MESH_STREAM_REFUSED_CAP;
    struct guest_chan_port tok = {0, 0};
    size_t produced = 0;
    bool accepted = g.accept_peer
        ? g.accept_peer(g.dev, st->peer_static, payload, length, reply,
                        capacity, &produced, &tok)
        : g.ops.accept(g.dev, &tok);
    if (!gc_reply_valid(produced, capacity, reply, reply_length)) {
        if (accepted) gc_reject_token(tok);
        return MESH_STREAM_REFUSED_UNAVAILABLE;
    }
    if (!accepted) {
        g.stats.refused_bound++;
        return MESH_STREAM_REFUSED_UNAVAILABLE;
    }
    if (!gc_token_free(tok)) {
        gc_reject_token(tok);
        return MESH_STREAM_REFUSED_UNAVAILABLE;
    }
    if (g.accept_peer && !guest_chan_allowed(st->peer_static)) {
        g.ops.end(g.dev, tok, GUEST_CHAN_END_REVOKED);
        return MESH_STREAM_REFUSED_UNAVAILABLE;
    }
    gc_claim(&g.ports[tok.index], tok.generation, st->peer_static, false);
    g.stats.opened++;
    st->service_state = &g.ports[tok.index];
    if (reply_length) *reply_length = produced;
    return MESH_STREAM_OK;
}

static enum mesh_stream_refusal gc_on_open(struct mesh_stream *st,
                                           const uint8_t *payload, size_t len,
                                           uint8_t *reply, size_t reply_cap,
                                           size_t *reply_len, void *ctx)
{
    (void)ctx;
    if (reply_len) *reply_len = 0;
    gc_lock();
    enum mesh_stream_refusal r = gc_admit(st, payload, len, reply, reply_cap, reply_len);
    gc_unlock();
    return r;
}

static bool gc_append_in(struct gc_port *p, const uint8_t *data, size_t n)
{
    if (p->in_off > 0) {
        memmove(p->in_buf, p->in_buf + p->in_off, gc_pending(p));
        p->in_len -= p->in_off;
        p->in_off = 0;
    }
    if (n > GC_BUF - p->in_len)
        return false;
    memcpy(p->in_buf + p->in_len, data, n);
    p->in_len += n;
    return true;
}

/* False means the port ended. */
static bool gc_deliver(struct gc_port *p, struct mesh_stream *st,
                       const uint8_t *data, size_t n)
{
    if (gc_pending(p) > 0) {
        if (gc_append_in(p, data, n))
            return true;
        gc_finish(p, st, GUEST_CHAN_END_BOUND);
        return false;
    }
    size_t k = g.ops.write(g.dev, gc_token(p), data, n);
    if (k > n) {
        gc_finish(p, st, GUEST_CHAN_END_PROTOCOL);
        return false;
    }
    gc_note_taken(p, k);
    if (k < n) {
        (void)gc_append_in(p, data + k, n - k); /* empty buffer: always fits */
        p->reoffer = false; /* offer nothing until writable or drained */
    }
    return true;
}

static void gc_on_data(struct mesh_stream *st, const uint8_t *payload,
                       size_t len, void *ctx)
{
    (void)ctx;
    struct gc_port *p = gc_port_of(st);
    if (!p || !payload || len == 0 || len > GC_BUF)
        return;
    gc_lock();
    if (p->used && p->bound && gc_gate(p, st))
        (void)gc_deliver(p, st, payload, len);
    gc_unlock();
}

static void gc_on_close(struct mesh_stream *st,
                        enum mesh_stream_refusal reason,
                        const uint8_t *payload, size_t len, void *ctx)
{
    (void)payload;
    (void)len;
    (void)ctx;
    struct gc_port *p = gc_port_of(st);
    if (!p)
        return;
    gc_lock();
    if (p->used && p->bound && !p->self_closing)
        gc_finish(p, st, gc_map_close(reason));
    gc_unlock();
}

static void gc_on_tick(struct mesh_stream *st, int64_t now_unix, void *ctx)
{
    (void)ctx;
    struct gc_port *p = gc_port_of(st);
    if (!p)
        return;
    gc_lock();
    if (p->used && p->bound)
        gc_step(p, st, now_unix);
    gc_unlock();
}

static void gc_on_release(struct mesh_stream *st, void *ctx)
{
    (void)ctx;
    struct gc_port *p = gc_port_of(st);
    if (!p)
        return;
    gc_lock();
    if (p->used) {
        gc_tell_device_end(p, GUEST_CHAN_END_SHUTDOWN);
        gc_free(p);
    }
    st->service_state = NULL;
    gc_unlock();
}

/* ── host ops (device pump; no lane lock; no device or stream calls) ─── */

/* One port, one reason. An outbound port whose open has not been decided
 * yet is judged in ONE place, the pump's open check (gc_do_open), which
 * ends it UNAVAILABLE. Until then a host op must not pre-empt that verdict
 * with REVOKED: it buffers within the bound and leaves the decision to the
 * pump. */
static bool gc_authority_decided(const struct gc_port *p)
{
    return !p->outbound || p->open_decided;
}

static bool gc_h_opened(void *host, struct guest_chan_port port,
                        const uint8_t peer[GUEST_CHAN_PEER_ID_BYTES])
{
    (void)host;
    if (!peer)
        return false;
    gc_lock();
    bool ok = false;
    if (!g.attached || !g.enabled)
        g.stats.refused_disabled++;
    else if (!gc_token_free(port))
        g.stats.stale_token_dropped++; /* not a live-able token: drop only */
    else if (gc_bounds_ok(peer)) {
        gc_claim(&g.ports[port.index], port.generation, peer, true);
        g.stats.opened++;
        ok = true;
    }
    gc_unlock();
    return ok;
}

static size_t gc_h_from_guest(void *host, struct guest_chan_port port,
                              const uint8_t *bytes, size_t n)
{
    (void)host;
    size_t taken = 0;
    gc_lock();
    struct gc_port *p = gc_find_live(port);
    if (p && (n > GUEST_CHAN_RUN_MAX || (n && !bytes)))
        gc_mark_end(p, GUEST_CHAN_END_PROTOCOL);
    else if (p && gc_authority_decided(p) && !guest_chan_allowed(p->peer))
        gc_mark_end(p, GUEST_CHAN_END_REVOKED);
    else if (p) {
        taken = GC_BUF - p->out_len;
        if (taken > n)
            taken = n;
        if (taken)
            memcpy(p->out_buf + p->out_len, bytes, taken);
        p->out_len += taken;
        if (taken < n)
            p->out_stalled = true;
        if (taken)
            p->last_activity = gc_clock();
    }
    gc_unlock();
    return taken;
}

static void gc_h_drained(void *host, struct guest_chan_port port, size_t n)
{
    (void)host;
    gc_lock();
    struct gc_port *p = gc_find_live(port);
    if (p && (uint64_t)n > p->delivered)
        gc_mark_end(p, GUEST_CHAN_END_PROTOCOL);
    else if (p && gc_authority_decided(p) && !guest_chan_allowed(p->peer))
        gc_mark_end(p, GUEST_CHAN_END_REVOKED);
    else if (p) {
        p->delivered -= n;
        p->owed += n;
        p->reoffer = true;
        p->last_activity = gc_clock();
    }
    gc_unlock();
}

static void gc_h_writable(void *host, struct guest_chan_port port)
{
    (void)host;
    gc_lock();
    struct gc_port *p = gc_find_live(port);
    if (p)
        p->reoffer = true;
    gc_unlock();
}

static void gc_h_closed(void *host, struct guest_chan_port port)
{
    (void)host;
    gc_lock();
    struct gc_port *p = gc_find_live(port);
    if (p)
        gc_mark_end(p, GUEST_CHAN_END_NORMAL);
    gc_unlock();
}

static const struct guest_chan_host_ops g_host_ops = {
    .opened = gc_h_opened,
    .from_guest = gc_h_from_guest,
    .drained = gc_h_drained,
    .writable = gc_h_writable,
    .closed = gc_h_closed,
};

/* ── pump ────────────────────────────────────────────────────────────── */

static bool gc_visit_step(struct mesh_stream *st, void *ctx)
{
    const int64_t *now = ctx;
    struct gc_port *p = gc_port_of(st);
    if (!p)
        return true;
    gc_lock();
    if (p->used && p->bound)
        gc_step(p, st, *now);
    gc_unlock();
    return true;
}

static void gc_do_open(size_t index, uint32_t generation,
                       const uint8_t peer[32], uint32_t window)
{
    gc_lock();
    bool allowed = guest_chan_allowed(peer);
    gc_unlock();
    uint64_t id = 0;
    enum mesh_stream_refusal r =
        allowed ? mesh_stream_open(MESH_GUEST_CHAN_SERVICE_NAME, peer, window,
                                   NULL, 0, &g.ports[index], &id)
                : MESH_STREAM_REFUSED_UNAVAILABLE;
    gc_lock();
    struct gc_port *p = &g.ports[index];
    if (r == MESH_STREAM_OK) {
        if (p->used && p->generation == generation)
            p->open_decided = true;
        gc_unlock();
        return;
    }
    if (p->used && p->generation == generation) {
        p->bound = false;
        gc_finish(p, NULL, GUEST_CHAN_END_UNAVAILABLE);
    }
    gc_unlock();
}

static void gc_pump_opens(void)
{
    for (size_t i = 0; i < GC_PORTS; i++) {
        struct gc_port *p = &g.ports[i];
        uint8_t peer[32] = {0};
        uint32_t generation = 0;
        uint32_t window = 0;
        bool go = false;
        gc_lock();
        if (g.attached && p->used && p->live && p->open_queued) {
            p->open_queued = false;
            p->bound = true;
            memcpy(peer, p->peer, 32);
            generation = p->generation;
            window = g.lim.window;
            go = true;
        }
        gc_unlock();
        if (go)
            gc_do_open(i, generation, peer, window);
    }
}

/* Ports with no stream whose end a host op queued. */
static void gc_pump_orphans(void)
{
    gc_lock();
    for (size_t i = 0; i < GC_PORTS; i++) {
        struct gc_port *p = &g.ports[i];
        if (p->used && !p->bound && !p->live)
            gc_finish(p, NULL, p->end_why);
    }
    gc_unlock();
}

void mesh_guest_chan_pump(int64_t now_unix)
{
    gc_lock();
    bool attached = g.attached;
    if (attached)
        g.clock = now_unix;
    gc_unlock();
    if (!attached)
        return;
    gc_pump_opens();
    mesh_stream_visit(MESH_GUEST_CHAN_SERVICE_NAME, gc_visit_step, &now_unix);
    gc_pump_orphans();
}

/* ── lifecycle ───────────────────────────────────────────────────────── */

static uint32_t gc_or(uint32_t v, uint32_t dflt)
{
    return v ? v : dflt;
}

static bool gc_limits_valid(const struct mesh_guest_chan_limits *l)
{
    return l->total_max <= GC_PORTS && l->per_peer_max <= GC_PORTS &&
           l->window <= MESH_STREAM_INITIAL_WINDOW &&
           l->pump_bytes_max <= GC_PORTS * GC_BUF * 2u;
}

bool mesh_guest_chan_attach(const struct guest_chan_device_ops *ops, void *dev,
                            const struct mesh_guest_chan_limits *limits_or_null,
                            const struct guest_chan_host_ops **host_ops_out,
                            void **host_out)
{
    struct mesh_guest_chan_limits l;
    memset(&l, 0, sizeof(l));
    if (limits_or_null)
        l = *limits_or_null;
    if (!ops || !ops->accept || !ops->write || !ops->resume || !ops->end ||
        !host_ops_out || !host_out)
        LOG_FAIL("guest_chan", "attach: missing device op or out pointer");
    if (!gc_limits_valid(&l))
        LOG_FAIL("guest_chan", "attach: limit out of range");
    gc_lock();
    if (g.attached) {
        gc_unlock();
        LOG_FAIL("guest_chan", "attach: already attached");
    }
    for (size_t i = 0; i < GC_PORTS; i++)
        gc_free(&g.ports[i]);
    g.ops = *ops;
    g.accept_peer = NULL;
    g.dev = dev;
    g.lim.per_peer_max = gc_or(l.per_peer_max, 2u);
    g.lim.total_max = gc_or(l.total_max, 4u);
    g.lim.window = gc_or(l.window, 65536u);
    g.lim.idle_seconds = gc_or(l.idle_seconds, 120u);
    g.lim.pump_bytes_max = gc_or(l.pump_bytes_max, 262144u);
    memset(&g.stats, 0, sizeof(g.stats));
    g.clock = 0;
    g.enabled = false;
    g.attached = true;
    gc_unlock();
    *host_ops_out = &g_host_ops;
    *host_out = &g;
    return true;
}

bool mesh_guest_chan_attach_peer_v2(const struct guest_chan_device_ops *ops,
    guest_chan_peer_accept_v2_fn accept_peer, void *dev,
    const struct mesh_guest_chan_limits *limits,
    const struct guest_chan_host_ops **host_ops_out, void **host_out)
{
    if (!accept_peer)
        LOG_FAIL("guest_chan", "peer attach: missing admission handler");
    if (!mesh_guest_chan_attach(ops, dev, limits, host_ops_out, host_out))
        return false;
    gc_lock();
    g.accept_peer = accept_peer;
    gc_unlock();
    return true;
}

static bool gc_visit_shutdown(struct mesh_stream *st, void *ctx)
{
    (void)ctx;
    struct gc_port *p = gc_port_of(st);
    if (!p)
        return true;
    gc_lock();
    if (p->used && p->bound)
        gc_finish(p, st, GUEST_CHAN_END_SHUTDOWN);
    gc_unlock();
    return true;
}

static bool gc_enable(void)
{
    gc_lock();
    bool ready = g.attached;
    bool was = g.enabled;
    if (ready)
        g.enabled = true;
    gc_unlock();
    if (!ready)
        LOG_FAIL("guest_chan", "enable: no device attached");
    if (was)
        return true;
    struct mesh_stream_service svc;
    memset(&svc, 0, sizeof(svc));
    svc.name = MESH_GUEST_CHAN_SERVICE_NAME;
    svc.required_pairing_capability = MESH_PAIRING_CAP_GUEST_CHAN;
    svc.on_open = gc_on_open;
    svc.on_data = gc_on_data;
    svc.on_close = gc_on_close;
    svc.on_tick = gc_on_tick;
    svc.on_release = gc_on_release;
    if (mesh_stream_service_register(&svc))
        return true;
    gc_lock();
    g.enabled = false;
    gc_unlock();
    LOG_FAIL("guest_chan", "enable: service registration refused");
}

static void gc_disable(void)
{
    gc_lock();
    bool was = g.enabled;
    g.enabled = false;
    gc_unlock();
    if (!was)
        return;
    mesh_stream_visit(MESH_GUEST_CHAN_SERVICE_NAME, gc_visit_shutdown, NULL);
    gc_lock();
    for (size_t i = 0; i < GC_PORTS; i++)
        if (g.ports[i].used && !g.ports[i].bound)
            gc_finish(&g.ports[i], NULL, GUEST_CHAN_END_SHUTDOWN);
    gc_unlock();
    mesh_stream_service_unregister(MESH_GUEST_CHAN_SERVICE_NAME);
}

bool mesh_guest_chan_set_enabled(bool on)
{
    if (on)
        return gc_enable();
    gc_disable();
    return true;
}

bool mesh_guest_chan_enabled(void)
{
    gc_lock();
    bool on = g.enabled;
    gc_unlock();
    return on;
}

void mesh_guest_chan_detach(void)
{
    gc_disable();
    gc_lock();
    g.attached = false;
    for (size_t i = 0; i < GC_PORTS; i++)
        gc_free(&g.ports[i]);
    gc_unlock();
}

void mesh_guest_chan_stats(struct mesh_guest_chan_stats *out)
{
    if (!out)
        return;
    gc_lock();
    *out = g.stats;
    gc_unlock();
}

#ifdef ZCL_TESTING
size_t mesh_guest_chan_test_buffered(void)
{
    gc_lock();
    size_t n = gc_buffered();
    gc_unlock();
    return n;
}
#endif
