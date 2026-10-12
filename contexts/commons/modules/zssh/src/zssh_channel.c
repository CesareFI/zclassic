/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * zssh_channel — the single direct-tcpip channel, windows, EOF/CLOSE (layer d).
 *
 * Contract: zssh_internal.h section (d). RFC 4254 5.1 (open), 5.2 (data and
 * window), 5.3 (close), 7.2 (direct-tcpip). Every payload handled here
 * includes its leading message-number byte (that is what zssh_pkt_open hands
 * CONN) and every builder writes it. Parsing uses the sticky-error reader;
 * a message is read completely and tested once. No allocation, no I/O.
 *
 * Window invariant (kept by on_data / recv / window_adjust_sent):
 *   recv_window + ring_len + freed_unreported == ZSSH_CHAN_WINDOW
 * so a window the peer is allowed to use can never overflow the ring. */

#include "zssh_internal.h"

#include <string.h>

static const char CHAN_TYPE[] = "direct-tcpip";
static const char ORIG_ADDR[] = "0.0.0.0";

static bool str_is(const uint8_t *s, size_t n, const char *lit)
{
    size_t m = strlen(lit);
    return n == m && (m == 0 || memcmp(s, lit, m) == 0);
}

void zssh_chan_init(struct zssh_chan *c)
{
    memset(c, 0, sizeof *c);
    c->state = ZSSH_CH_IDLE;
}

void zssh_chan_scrub(struct zssh_chan *c)
{
    memory_cleanse(c->ring, sizeof c->ring);
    c->ring_head = 0;
    c->ring_len = 0;
}

void zssh_chan_wipe(struct zssh_chan *c)
{
    memory_cleanse(c, sizeof *c);
}

/* ---- builders ----------------------------------------------------------- */

/* Builder rule (the header states none, so this layer fixes it): a builder
 * that fails rolls w->off back to where it started and leaves the sticky
 * `bad` flag SET, so the caller sees the failure through zssh_wr_ok and a
 * partial message is never mistaken for a whole one. */
static void wr_rollback(struct zssh_wr *w, size_t start)
{
    if (w->bad)
        w->off = start;
}

void zssh_chan_build_open(struct zssh_wr *w)
{
    size_t start = w->off;
    zssh_wr_u8(w, ZSSH_MSG_CHANNEL_OPEN);
    zssh_wr_cstr(w, CHAN_TYPE);
    zssh_wr_u32(w, 0);                       /* sender channel: always 0 */
    zssh_wr_u32(w, ZSSH_CHAN_WINDOW);
    zssh_wr_u32(w, ZSSH_CHAN_MAX_PACKET);
    zssh_wr_cstr(w, ZSSH_FWD_HOST);
    zssh_wr_u32(w, ZSSH_FWD_PORT);
    zssh_wr_cstr(w, ORIG_ADDR);
    zssh_wr_u32(w, 0);
    wr_rollback(w, start);
}

void zssh_chan_build_open_confirm(const struct zssh_chan *c, struct zssh_wr *w)
{
    size_t start = w->off;
    zssh_wr_u8(w, ZSSH_MSG_CHANNEL_OPEN_CONFIRMATION);
    zssh_wr_u32(w, c->remote_id);
    zssh_wr_u32(w, 0);
    zssh_wr_u32(w, ZSSH_CHAN_WINDOW);
    zssh_wr_u32(w, ZSSH_CHAN_MAX_PACKET);
    wr_rollback(w, start);
}

void zssh_chan_build_open_failure(uint32_t recipient, uint32_t reason, struct zssh_wr *w)
{
    size_t start = w->off;
    zssh_wr_u8(w, ZSSH_MSG_CHANNEL_OPEN_FAILURE);
    zssh_wr_u32(w, recipient);
    zssh_wr_u32(w, reason);
    zssh_wr_string(w, nullptr, 0);           /* description */
    zssh_wr_string(w, nullptr, 0);           /* language tag */
    wr_rollback(w, start);
}

void zssh_chan_build_window_adjust(const struct zssh_chan *c, uint32_t add, struct zssh_wr *w)
{
    size_t start = w->off;
    zssh_wr_u8(w, ZSSH_MSG_CHANNEL_WINDOW_ADJUST);
    zssh_wr_u32(w, c->remote_id);
    zssh_wr_u32(w, add);
    wr_rollback(w, start);
}

void zssh_chan_build_eof(const struct zssh_chan *c, struct zssh_wr *w)
{
    size_t start = w->off;
    zssh_wr_u8(w, ZSSH_MSG_CHANNEL_EOF);
    zssh_wr_u32(w, c->remote_id);
    wr_rollback(w, start);
}

void zssh_chan_build_close(const struct zssh_chan *c, struct zssh_wr *w)
{
    size_t start = w->off;
    zssh_wr_u8(w, ZSSH_MSG_CHANNEL_CLOSE);
    zssh_wr_u32(w, c->remote_id);
    wr_rollback(w, start);
}

/* Despite the name this is the per-channel CHANNEL_FAILURE (RFC 4254 5.4),
 * the answer to a CHANNEL_REQUEST with want_reply. The GLOBAL_REQUEST answer
 * (REQUEST_FAILURE, one byte 82) has no channel and is built by CONN. */
void zssh_chan_build_request_failure(const struct zssh_chan *c, struct zssh_wr *w)
{
    size_t start = w->off;
    zssh_wr_u8(w, ZSSH_MSG_CHANNEL_FAILURE);
    zssh_wr_u32(w, c->remote_id);
    wr_rollback(w, start);
}

/* ---- transaction marks (called by CONN only after the queue commit) ------ */

void zssh_chan_send_commit(struct zssh_chan *c, size_t take)
{
    uint32_t t = take > c->send_window ? c->send_window : (uint32_t)take;
    c->send_window -= t;                     /* never underflows */
}

void zssh_chan_mark_open_sent(struct zssh_chan *c)
{
    if (c->state == ZSSH_CH_IDLE)
        c->state = ZSSH_CH_OPEN_SENT;
}

void zssh_chan_mark_eof_sent(struct zssh_chan *c)
{
    c->sent_eof = true;
}

void zssh_chan_mark_close_sent(struct zssh_chan *c)
{
    c->sent_close = true;
    if (c->recv_close)
        c->state = ZSSH_CH_CLOSED;
}

/* ---- open / confirmation ------------------------------------------------ */

/* Parse "tail" of a direct-tcpip open (after maxpkt) and match the target. */
static enum zssh_error open_check_target(struct zssh_rd *r)
{
    const uint8_t *host, *oaddr;
    size_t hn, on;
    host = oaddr = nullptr;
    hn = on = 0;
    zssh_rd_string(r, &host, &hn);
    uint32_t port = zssh_rd_u32(r);
    zssh_rd_string(r, &oaddr, &on);
    (void)zssh_rd_u32(r);                    /* originator port: informational */
    if (!zssh_rd_done(r))
        ZSSH_FAIL(ZSSH_E_PROTOCOL, "malformed direct-tcpip open");
    if (!str_is(host, hn, ZSSH_FWD_HOST) || port != ZSSH_FWD_PORT)
        return ZSSH_E_CHANNEL_REFUSED;
    return ZSSH_E_NONE;
}

/* What a CHANNEL_OPEN said, plus the out-parameters server_open reports. */
struct open_req {
    uint32_t sender, window, maxpkt;
    uint32_t echo_id;                        /* *remote_id for the caller */
    uint32_t reason;                         /* *refuse_reason for the caller */
};

/* Validate a CHANNEL_OPEN payload against channel state c (read only).
 * Fills q->echo_id / q->reason as the header specifies for each outcome. */
static enum zssh_error open_validate(const struct zssh_chan *c, const uint8_t *payload,
                                     size_t len, struct open_req *q)
{
    struct zssh_rd r;
    zssh_rd_init(&r, payload, len);
    uint8_t msg = zssh_rd_u8(&r);
    const uint8_t *type = nullptr;
    size_t tn = 0;
    zssh_rd_string(&r, &type, &tn);
    q->sender = zssh_rd_u32(&r);
    q->window = zssh_rd_u32(&r);
    q->maxpkt = zssh_rd_u32(&r);
    if (!zssh_rd_ok(&r) || msg != ZSSH_MSG_CHANNEL_OPEN || q->maxpkt == 0)
        ZSSH_FAIL(ZSSH_E_PROTOCOL, "malformed CHANNEL_OPEN");
    q->echo_id = q->sender;
    if (!str_is(type, tn, CHAN_TYPE)) {
        q->reason = ZSSH_OPEN_UNKNOWN_CHANNEL_TYPE;
        ZSSH_FAIL(ZSSH_E_CHANNEL_REFUSED, "refused channel type (len %zu)", tn);
    }
    enum zssh_error e = open_check_target(&r);
    if (e == ZSSH_E_CHANNEL_REFUSED) {
        q->reason = ZSSH_OPEN_ADMIN_PROHIBITED;
        ZSSH_FAIL(e, "refused direct-tcpip target");
    }
    if (e != ZSSH_E_NONE) {
        q->echo_id = 0;
        return e;
    }
    if (c->state != ZSSH_CH_IDLE) {
        q->reason = ZSSH_OPEN_RESOURCE_SHORTAGE;
        ZSSH_FAIL(ZSSH_E_CHANNEL_REFUSED, "second channel refused");
    }
    return ZSSH_E_NONE;
}

enum zssh_error zssh_chan_server_open(struct zssh_chan *c, const uint8_t *payload,
        size_t len, uint32_t *remote_id, uint32_t *refuse_reason)
{
    struct open_req q = { 0 };
    enum zssh_error e = open_validate(c, payload, len, &q);
    if (remote_id) *remote_id = q.echo_id;
    if (refuse_reason) *refuse_reason = q.reason;
    if (e != ZSSH_E_NONE)
        return e;
    c->remote_id = q.sender;
    c->send_window = q.window;
    c->send_maxpkt = q.maxpkt > ZSSH_CHAN_MAX_PACKET ? ZSSH_CHAN_MAX_PACKET : q.maxpkt;
    c->recv_window = ZSSH_CHAN_WINDOW;
    c->state = ZSSH_CH_OPEN;
    return ZSSH_E_NONE;
}

enum zssh_error zssh_chan_client_confirm(struct zssh_chan *c,
                                         const uint8_t *payload, size_t len)
{
    struct zssh_rd r;
    zssh_rd_init(&r, payload, len);
    uint8_t msg = zssh_rd_u8(&r);
    uint32_t recipient = zssh_rd_u32(&r);
    uint32_t sender = zssh_rd_u32(&r);
    uint32_t window = zssh_rd_u32(&r);
    uint32_t maxpkt = zssh_rd_u32(&r);
    if (!zssh_rd_done(&r) || msg != ZSSH_MSG_CHANNEL_OPEN_CONFIRMATION || maxpkt == 0)
        ZSSH_FAIL(ZSSH_E_PROTOCOL, "malformed OPEN_CONFIRMATION");
    if (recipient != 0 || c->state != ZSSH_CH_OPEN_SENT)
        ZSSH_FAIL(ZSSH_E_PROTOCOL, "unexpected OPEN_CONFIRMATION (recipient %u state %d)",
                  (unsigned)recipient, (int)c->state);
    c->remote_id = sender;
    c->send_window = window;
    c->send_maxpkt = maxpkt > ZSSH_CHAN_MAX_PACKET ? ZSSH_CHAN_MAX_PACKET : maxpkt;
    c->recv_window = ZSSH_CHAN_WINDOW;
    c->state = ZSSH_CH_OPEN;
    return ZSSH_E_NONE;
}

enum zssh_error zssh_chan_client_open_failure(struct zssh_chan *c,
                                              const uint8_t *payload, size_t len)
{
    struct zssh_rd r;
    zssh_rd_init(&r, payload, len);
    uint8_t msg = zssh_rd_u8(&r);
    uint32_t recipient = zssh_rd_u32(&r);
    uint32_t reason = zssh_rd_u32(&r);
    const uint8_t *s;
    size_t n;
    zssh_rd_string(&r, &s, &n);              /* description */
    zssh_rd_string(&r, &s, &n);              /* language tag */
    if (!zssh_rd_done(&r) || msg != ZSSH_MSG_CHANNEL_OPEN_FAILURE)
        ZSSH_FAIL(ZSSH_E_PROTOCOL, "malformed OPEN_FAILURE");
    if (recipient != 0 || c->state != ZSSH_CH_OPEN_SENT)
        ZSSH_FAIL(ZSSH_E_PROTOCOL, "unexpected OPEN_FAILURE");
    c->state = ZSSH_CH_CLOSED;
    ZSSH_FAIL(ZSSH_E_CHANNEL_REFUSED, "peer refused channel open (reason %u)",
              (unsigned)reason);
}

/* ---- peer messages in state OPEN ---------------------------------------- */

/* Common prefix: message byte and recipient == 0 (our only channel id). */
static enum zssh_error peer_hdr(const struct zssh_chan *c, struct zssh_rd *r,
                                const uint8_t *payload, size_t len, uint8_t want)
{
    zssh_rd_init(r, payload, len);
    uint8_t msg = zssh_rd_u8(r);
    uint32_t recipient = zssh_rd_u32(r);
    if (!zssh_rd_ok(r) || msg != want)
        ZSSH_FAIL(ZSSH_E_PROTOCOL, "malformed channel message %u", (unsigned)want);
    if (recipient != 0)
        ZSSH_FAIL(ZSSH_E_PROTOCOL, "unknown recipient channel %u", (unsigned)recipient);
    if (c->state != ZSSH_CH_OPEN)
        ZSSH_FAIL(ZSSH_E_PROTOCOL, "channel message %u in state %d", (unsigned)want, (int)c->state);
    return ZSSH_E_NONE;
}

enum zssh_error zssh_chan_on_data(struct zssh_chan *c, const uint8_t *payload, size_t len)
{
    struct zssh_rd r;
    enum zssh_error e = peer_hdr(c, &r, payload, len, ZSSH_MSG_CHANNEL_DATA);
    if (e != ZSSH_E_NONE)
        return e;
    const uint8_t *data = nullptr;
    size_t n = 0;
    zssh_rd_string(&r, &data, &n);
    if (!zssh_rd_done(&r))
        ZSSH_FAIL(ZSSH_E_PROTOCOL, "malformed CHANNEL_DATA");
    if (c->recv_eof || c->recv_close)
        ZSSH_FAIL(ZSSH_E_PROTOCOL, "CHANNEL_DATA after EOF/CLOSE");
    if (n > ZSSH_CHAN_MAX_PACKET || n > c->recv_window)
        ZSSH_FAIL(ZSSH_E_WINDOW, "CHANNEL_DATA %zu exceeds window %u / max packet",
                  n, (unsigned)c->recv_window);
    if (n > ZSSH_CHAN_WINDOW - c->ring_len)
        ZSSH_FAIL(ZSSH_E_INTERNAL, "rx ring invariant broken");
    uint32_t tail = (c->ring_head + c->ring_len) % ZSSH_CHAN_WINDOW;
    size_t first = n < ZSSH_CHAN_WINDOW - tail ? n : ZSSH_CHAN_WINDOW - tail;
    if (n > 0) {
        memcpy(c->ring + tail, data, first);
        memcpy(c->ring, data + first, n - first);
    }
    c->ring_len += (uint32_t)n;
    c->recv_window -= (uint32_t)n;
    return ZSSH_E_NONE;
}

enum zssh_error zssh_chan_on_window_adjust(struct zssh_chan *c, const uint8_t *payload, size_t len)
{
    struct zssh_rd r;
    enum zssh_error e = peer_hdr(c, &r, payload, len, ZSSH_MSG_CHANNEL_WINDOW_ADJUST);
    if (e != ZSSH_E_NONE)
        return e;
    uint32_t add = zssh_rd_u32(&r);
    if (!zssh_rd_done(&r))
        ZSSH_FAIL(ZSSH_E_PROTOCOL, "malformed WINDOW_ADJUST");
    if (c->recv_close)
        ZSSH_FAIL(ZSSH_E_PROTOCOL, "WINDOW_ADJUST after CLOSE");
    if (add > UINT32_MAX - c->send_window)
        ZSSH_FAIL(ZSSH_E_PROTOCOL, "WINDOW_ADJUST overflows 2^32-1 (%u + %u)",
                  (unsigned)c->send_window, (unsigned)add);
    c->send_window += add;
    return ZSSH_E_NONE;
}

enum zssh_error zssh_chan_on_eof(struct zssh_chan *c, const uint8_t *payload, size_t len)
{
    struct zssh_rd r;
    enum zssh_error e = peer_hdr(c, &r, payload, len, ZSSH_MSG_CHANNEL_EOF);
    if (e != ZSSH_E_NONE)
        return e;
    if (!zssh_rd_done(&r))
        ZSSH_FAIL(ZSSH_E_PROTOCOL, "malformed CHANNEL_EOF");
    if (c->recv_eof || c->recv_close)
        ZSSH_FAIL(ZSSH_E_PROTOCOL, "duplicate CHANNEL_EOF");
    c->recv_eof = true;
    return ZSSH_E_NONE;
}

enum zssh_error zssh_chan_on_close(struct zssh_chan *c, const uint8_t *payload, size_t len)
{
    struct zssh_rd r;
    enum zssh_error e = peer_hdr(c, &r, payload, len, ZSSH_MSG_CHANNEL_CLOSE);
    if (e != ZSSH_E_NONE)
        return e;
    if (!zssh_rd_done(&r))
        ZSSH_FAIL(ZSSH_E_PROTOCOL, "malformed CHANNEL_CLOSE");
    if (c->recv_close)
        ZSSH_FAIL(ZSSH_E_PROTOCOL, "duplicate CHANNEL_CLOSE");
    c->recv_close = true;
    if (c->sent_close)
        c->state = ZSSH_CH_CLOSED;
    return ZSSH_E_NONE;
}

/* ---- application side --------------------------------------------------- */

size_t zssh_chan_recv(struct zssh_chan *c, uint8_t *buf, size_t cap)
{
    size_t n = cap < c->ring_len ? cap : c->ring_len;
    if (n == 0 || buf == nullptr)
        return 0;
    size_t first = n < ZSSH_CHAN_WINDOW - c->ring_head ? n : ZSSH_CHAN_WINDOW - c->ring_head;
    memcpy(buf, c->ring + c->ring_head, first);
    memcpy(buf + first, c->ring, n - first);
    c->ring_head = (uint32_t)((c->ring_head + n) % ZSSH_CHAN_WINDOW);
    c->ring_len -= (uint32_t)n;
    c->freed_unreported += (uint32_t)n;
    return n;
}

static bool can_send(const struct zssh_chan *c)
{
    return c->state == ZSSH_CH_OPEN && !c->sent_eof && !c->sent_close && !c->recv_close;
}

static size_t send_limit(const struct zssh_chan *c)
{
    size_t lim = c->send_window;
    if (lim > c->send_maxpkt) lim = c->send_maxpkt;
    if (lim > ZSSH_CHAN_MAX_PACKET) lim = ZSSH_CHAN_MAX_PACKET;
    return lim;
}

size_t zssh_chan_send_plan(const struct zssh_chan *c, size_t n, size_t room_for_payload)
{
    if (!can_send(c))
        return 0;
    size_t take = send_limit(c);
    if (take > n) take = n;
    if (take > room_for_payload) take = room_for_payload;
    return take;
}

enum zssh_error zssh_chan_send_build(struct zssh_chan *c, const uint8_t *data,
                                     size_t take, struct zssh_wr *w)
{
    if (!can_send(c))
        ZSSH_FAIL(ZSSH_E_PROTOCOL, "send on channel not writable (state %d eof %d close %d)",
                  (int)c->state, (int)c->sent_eof, (int)c->sent_close);
    if (take == 0 || data == nullptr || take > send_limit(c))
        ZSSH_FAIL(ZSSH_E_INTERNAL, "bad send size %zu (limit %zu)", take, send_limit(c));
    size_t start = w->off;
    zssh_wr_u8(w, ZSSH_MSG_CHANNEL_DATA);
    zssh_wr_u32(w, c->remote_id);
    zssh_wr_string(w, data, take);
    if (!zssh_wr_ok(w)) {
        wr_rollback(w, start);
        ZSSH_FAIL(ZSSH_E_INTERNAL, "send buffer too small for %zu bytes", take);
    }
    /* No window charge here: CONN calls zssh_chan_send_commit after queueing. */
    return ZSSH_E_NONE;
}

uint32_t zssh_chan_window_adjust_due(const struct zssh_chan *c)
{
    if (c->state != ZSSH_CH_OPEN || c->sent_close || c->recv_close)
        return 0;
    return c->freed_unreported >= ZSSH_CHAN_WINDOW / 2 ? c->freed_unreported : 0;
}

void zssh_chan_window_adjust_sent(struct zssh_chan *c, uint32_t add)
{
    if (add > c->freed_unreported)
        add = c->freed_unreported;           /* never credit more than was freed */
    c->freed_unreported -= add;
    c->recv_window += add;
}

void zssh_chan_flags(const struct zssh_chan *c, struct zssh_channel_flags *out)
{
    out->sent_eof = c->sent_eof;
    out->recv_eof = c->recv_eof;
    out->sent_close = c->sent_close;
    out->recv_close = c->recv_close;
    out->send_window = c->send_window;
    out->recv_window = c->recv_window;
}
