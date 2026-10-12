/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * zssh_conn — public API and the state machine tying layers a-d (layer e).
 *
 * Flow. zssh_init queues our identification line and our KEXINIT (cookie from
 * rand). The input assembler (version line, then one binary packet at a time)
 * feeds zssh_conn_dispatch. Every outbound packet follows the atomic admission
 * recipe: reserve, build the payload in the reservation, seal into it,
 * commit the exact sealed size; a commit that returns false is terminal
 * (ZSSH_E_INTERNAL) because seal already advanced the sequence number.
 *
 * Key hold. A direction's key switches at an exact point (see the header):
 * tx at the queue commit of our NEWKEYS, rx when the peer's NEWKEYS is
 * processed. The rx key is not stored anywhere in derived form; the exchange
 * secret K stays in struct zssh_kex until the peer's NEWKEYS and the keys are
 * derived a second time (deterministic) for rx. zssh_kex_wipe then runs at
 * that point, and on every failure/close path through
 * zssh_conn_wipe_secrets.
 *
 * Field reuse. prebanner_lines counts pre-banner lines only until the version
 * line is accepted; afterwards it is the count of UNIMPLEMENTED replies sent
 * (UNIMPL_SENT), which bounds that reply to one per connection. */

#include "zssh_internal.h"

#include <string.h>

#define UNIMPL_SENT(s)  ((s)->prebanner_lines)
#define DATA_HDR        9u   /* CHANNEL_DATA: msg + recipient + string length */
/* Largest app control packet we queue (EOF, CLOSE, WINDOW_ADJUST). */
#define SMALL_WIRE      ZSSH_TX_SMALL_WIRE
#define BIT64(n)        (1ull << (n))
#define SEND_MIN_FRAGMENT 1024u  /* smallest room-limited DATA packet queued */

/* ======================================================================== *
 * names, reasons, message table                                            *
 * ======================================================================== */

static const char *const k_state_names[] = {
    [ZSSH_STATE_VERSION] = "VERSION", [ZSSH_STATE_KEX] = "KEX",
    [ZSSH_STATE_AUTH] = "AUTH", [ZSSH_STATE_OPEN] = "OPEN",
    [ZSSH_STATE_CHANNEL] = "CHANNEL", [ZSSH_STATE_CLOSED] = "CLOSED",
    [ZSSH_STATE_FAILED] = "FAILED",
};

static const char *const k_error_names[ZSSH_E_TRUNCATED + 1] = {
    [ZSSH_E_NONE] = "NONE", [ZSSH_E_CONFIG] = "CONFIG",
    [ZSSH_E_INTERNAL] = "INTERNAL", [ZSSH_E_RANDOM] = "RANDOM",
    [ZSSH_E_VERSION] = "VERSION", [ZSSH_E_PROTOCOL] = "PROTOCOL",
    [ZSSH_E_MAC] = "MAC", [ZSSH_E_TOO_LARGE] = "TOO_LARGE",
    [ZSSH_E_KEX_NO_MATCH] = "KEX_NO_MATCH", [ZSSH_E_KEX_FAILED] = "KEX_FAILED",
    [ZSSH_E_STRICT_KEX_REQUIRED] = "STRICT_KEX_REQUIRED",
    [ZSSH_E_HOST_KEY_MISMATCH] = "HOST_KEY_MISMATCH",
    [ZSSH_E_HOST_SIG] = "HOST_SIG", [ZSSH_E_AUTH_REFUSED] = "AUTH_REFUSED",
    [ZSSH_E_CHANNEL_REFUSED] = "CHANNEL_REFUSED", [ZSSH_E_WINDOW] = "WINDOW",
    [ZSSH_E_REKEY_UNSUPPORTED] = "REKEY_UNSUPPORTED",
    [ZSSH_E_REKEY_LIMIT] = "REKEY_LIMIT",
    [ZSSH_E_PEER_DISCONNECT] = "PEER_DISCONNECT",
    [ZSSH_E_NOT_IMPLEMENTED] = "NOT_IMPLEMENTED",
    [ZSSH_E_TRUNCATED] = "TRUNCATED",
};

const char *zssh_state_name(enum zssh_state s)
{
    return (unsigned)s <= (unsigned)ZSSH_STATE_FAILED ? k_state_names[s] : "UNKNOWN";
}

const char *zssh_error_name(enum zssh_error e)
{
    if ((unsigned)e <= (unsigned)ZSSH_E_TRUNCATED && k_error_names[e])
        return k_error_names[e];
    return "UNKNOWN";
}

/* RFC 4253 11.1 reason sent with a best-effort DISCONNECT; 0 = PROTOCOL_ERROR. */
static const uint8_t k_reason[ZSSH_E_TRUNCATED + 1] = {
    [ZSSH_E_MAC] = ZSSH_DISC_MAC_ERROR,
    [ZSSH_E_KEX_NO_MATCH] = ZSSH_DISC_KEY_EXCHANGE_FAILED,
    [ZSSH_E_KEX_FAILED] = ZSSH_DISC_KEY_EXCHANGE_FAILED,
    [ZSSH_E_STRICT_KEX_REQUIRED] = ZSSH_DISC_KEY_EXCHANGE_FAILED,
    [ZSSH_E_REKEY_UNSUPPORTED] = ZSSH_DISC_KEY_EXCHANGE_FAILED,
    [ZSSH_E_HOST_KEY_MISMATCH] = ZSSH_DISC_HOST_KEY_NOT_VERIFIABLE,
    [ZSSH_E_HOST_SIG] = ZSSH_DISC_HOST_KEY_NOT_VERIFIABLE,
    [ZSSH_E_AUTH_REFUSED] = ZSSH_DISC_NO_MORE_AUTH_METHODS,
};

static enum zssh_disconnect_reason reason_of(enum zssh_error e)
{
    uint8_t r = (unsigned)e < sizeof k_reason ? k_reason[e] : 0;
    return r ? (enum zssh_disconnect_reason)r : ZSSH_DISC_PROTOCOL_ERROR;
}

/* Message numbers this engine knows by name (RFC 4253 11.4: anything else is
 * answered with UNIMPLEMENTED after the key exchange). */
static bool msg_known(uint8_t m)
{
    static const uint64_t lo =
        BIT64(1) | BIT64(2) | BIT64(3) | BIT64(4) | BIT64(5) | BIT64(6) | BIT64(7) |
        BIT64(20) | BIT64(21) | BIT64(30) | BIT64(31) |
        BIT64(50) | BIT64(51) | BIT64(52) | BIT64(53) | BIT64(60);
    static const uint64_t hi =   /* bit (m - 64) */
        BIT64(80 - 64) | BIT64(81 - 64) | BIT64(82 - 64) |
        BIT64(90 - 64) | BIT64(91 - 64) | BIT64(92 - 64) | BIT64(93 - 64) |
        BIT64(94 - 64) | BIT64(95 - 64) | BIT64(96 - 64) | BIT64(97 - 64) |
        BIT64(98 - 64) | BIT64(99 - 64) | BIT64(100 - 64);
    if (m < 64) return (lo >> m) & 1u;
    if (m < 128) return (hi >> (m - 64)) & 1u;
    return false;
}

static bool ns_eq(struct zssh_namelist l, const char *lit)
{
    size_t n = strlen(lit);
    return l.len == n && (n == 0 || memcmp(l.p, lit, n) == 0);
}

/* ======================================================================== *
 * send path: begin / commit / fail                                         *
 * ======================================================================== */

static enum zssh_error begin_sized(struct zssh_impl *s, struct zssh_wr *w, size_t pcap)
{
    uint8_t *p = zssh_txq_reserve(&s->txq,
                                  ZSSH_PKT_HDR + pcap + ZSSH_PAD_RANDOM_MAX + ZSSH_TAG_LEN);
    if (!p) {
        zssh_wr_init(w, nullptr, 0);
        ZSSH_FAIL(ZSSH_E_TOO_LARGE, "output queue has no room for a reservation");
    }
    zssh_wr_init(w, p + ZSSH_PKT_HDR, pcap);
    return ZSSH_E_NONE;
}

enum zssh_error zssh_conn_begin(struct zssh_impl *s, struct zssh_wr *w)
{
    return begin_sized(s, w, ZSSH_TX_MAX_PAYLOAD);
}

enum zssh_error zssh_conn_begin_ctrl(struct zssh_impl *s, struct zssh_wr *w)
{
    return begin_sized(s, w, ZSSH_TX_CTRL_PAYLOAD);
}

/* Control senders inside dispatch: the reply reserve guarantees room, so a
 * refusal is an engine invariant violation. */
static enum zssh_error ctrl_begin(struct zssh_impl *s, struct zssh_wr *w)
{
    if (zssh_conn_begin_ctrl(s, w) != ZSSH_E_NONE)
        ZSSH_FAIL(ZSSH_E_INTERNAL, "reply reserve violated");
    return ZSSH_E_NONE;
}

enum zssh_error zssh_conn_commit(struct zssh_impl *s, const struct zssh_wr *w)
{
    uint8_t pad[ZSSH_PAD_RANDOM_MAX];
    size_t total = 0;
    if (!w || !w->p || w->off == 0) ZSSH_FAIL(ZSSH_E_INTERNAL, "no payload to commit");
    if (!zssh_wr_ok(w)) ZSSH_FAIL(ZSSH_E_TOO_LARGE, "payload builder overflowed");
    uint8_t *base = w->p - ZSSH_PKT_HDR;
    size_t cap = ZSSH_PKT_HDR + w->cap + ZSSH_PAD_RANDOM_MAX + ZSSH_TAG_LEN;
    if (!s->rand(s->rand_ctx, pad, sizeof pad)) {
        memory_cleanse(pad, sizeof pad);
        ZSSH_FAIL(ZSSH_E_RANDOM, "padding draw failed");
    }
    enum zssh_error e = zssh_pkt_seal(&s->tx, base, cap, w->off, pad, &total);
    memory_cleanse(pad, sizeof pad);
    if (e != ZSSH_E_NONE) return e;
    /* seal advanced seq: a refused commit cannot be retried. */
    if (!zssh_txq_commit(&s->txq, total))
        ZSSH_FAIL(ZSSH_E_INTERNAL, "commit refused after seal");
    return ZSSH_E_NONE;
}

static enum zssh_error queue_disconnect(struct zssh_impl *s, enum zssh_disconnect_reason r)
{
    struct zssh_wr w;
    enum zssh_error e = zssh_conn_begin_ctrl(s, &w);
    if (e != ZSSH_E_NONE) return e;
    zssh_wr_u8(&w, ZSSH_MSG_DISCONNECT);
    zssh_wr_u32(&w, (uint32_t)r);
    zssh_wr_cstr(&w, "");
    zssh_wr_cstr(&w, "");
    e = zssh_conn_commit(s, &w);
    if (e == ZSSH_E_NONE) s->disconnect_queued = true;
    return e;
}

void zssh_conn_wipe_secrets(struct zssh_impl *s)
{
    zssh_kex_wipe(&s->kex);
    zssh_pkt_dir_init(&s->tx);
    zssh_pkt_dir_init(&s->rx);
    memory_cleanse(s->host_seed, sizeof s->host_seed);
    memory_cleanse(s->user_seed, sizeof s->user_seed);
    memory_cleanse(s->rxbuf, sizeof s->rxbuf);
    s->rxlen = 0;
    s->rx_total = 0;
}

static bool no_disconnect(enum zssh_error e)
{
    return e == ZSSH_E_RANDOM || e == ZSSH_E_TRUNCATED || e == ZSSH_E_PEER_DISCONNECT;
}

enum zssh_error zssh_conn_fail(struct zssh_impl *s, enum zssh_error err,
                               enum zssh_disconnect_reason reason)
{
    if (s->state == ZSSH_STATE_FAILED) return err;   /* first error wins */
    s->error = err;
    if (!no_disconnect(err) && s->version_done && !s->disconnect_queued &&
        zssh_txq_room(&s->txq) >= ZSSH_TX_CTRL_WIRE)
        (void)queue_disconnect(s, reason);           /* best effort */
    s->state = ZSSH_STATE_FAILED;
    zssh_conn_wipe_secrets(s);
    zssh_chan_scrub(&s->chan);
    return err;
}

static enum zssh_error fail_err(struct zssh_impl *s, enum zssh_error e)
{
    return zssh_conn_fail(s, e, reason_of(e));
}

static enum zssh_result api_fail(struct zssh_impl *s, enum zssh_error e)
{
    (void)fail_err(s, e);
    return ZSSH_FAILED;
}

/* Clean shutdown: DISCONNECT(BY_APPLICATION), CLOSED, secrets gone; unread
 * ring data stays readable. */
static enum zssh_error finish_close(struct zssh_impl *s)
{
    enum zssh_error e = queue_disconnect(s, ZSSH_DISC_BY_APPLICATION);
    if (e != ZSSH_E_NONE) return e;
    s->state = ZSSH_STATE_CLOSED;
    zssh_conn_wipe_secrets(s);
    return ZSSH_E_NONE;
}

/* ======================================================================== *
 * message senders (each: begin, build, commit)                             *
 * ======================================================================== */

static enum zssh_error send_byte_msg(struct zssh_impl *s, uint8_t m)
{
    struct zssh_wr w;
    enum zssh_error e = ctrl_begin(s, &w);
    if (e != ZSSH_E_NONE) return e;
    zssh_wr_u8(&w, m);
    return zssh_conn_commit(s, &w);
}

static enum zssh_error send_unimplemented(struct zssh_impl *s)
{
    struct zssh_wr w;
    enum zssh_error e = ctrl_begin(s, &w);
    if (e != ZSSH_E_NONE) return e;
    zssh_wr_u8(&w, ZSSH_MSG_UNIMPLEMENTED);
    zssh_wr_u32(&w, s->rx.seq - 1u);   /* the packet just opened */
    return zssh_conn_commit(s, &w);
}

static enum zssh_error send_service(struct zssh_impl *s, bool accept)
{
    struct zssh_wr w;
    enum zssh_error e = ctrl_begin(s, &w);
    if (e != ZSSH_E_NONE) return e;
    if (accept) zssh_auth_build_service_accept(&w, ZSSH_SERVICE_USERAUTH);
    else zssh_auth_build_service_request(&w, ZSSH_SERVICE_USERAUTH);
    return zssh_conn_commit(s, &w);
}

static enum zssh_error send_auth_request(struct zssh_impl *s)
{
    struct zssh_wr w;
    enum zssh_error e = ctrl_begin(s, &w);
    if (e != ZSSH_E_NONE) return e;
    e = zssh_auth_build_request(&w, s->user, s->kex.session_id, s->user_seed, s->user_pk);
    if (e != ZSSH_E_NONE) return e;
    return zssh_conn_commit(s, &w);
}

static enum zssh_error send_auth_verdict(struct zssh_impl *s, enum zssh_auth_verdict v,
                                         const struct zssh_auth_request *req)
{
    struct zssh_wr w;
    enum zssh_error e = ctrl_begin(s, &w);
    if (e != ZSSH_E_NONE) return e;
    if (v == ZSSH_AUTH_V_SUCCESS) zssh_auth_build_success(&w);
    else if (v == ZSSH_AUTH_V_PK_OK) zssh_auth_build_pk_ok(&w, req);
    else zssh_auth_build_failure(&w);
    return zssh_conn_commit(s, &w);
}

/* Channel control messages; the channel mark runs only after the commit. */
enum chan_msg { CM_OPEN, CM_CONFIRM, CM_EOF, CM_CLOSE, CM_REQ_FAIL };

static enum zssh_error send_chan_msg(struct zssh_impl *s, enum chan_msg k)
{
    struct zssh_wr w;
    enum zssh_error e = ctrl_begin(s, &w);
    if (e != ZSSH_E_NONE) return e;
    switch (k) {
    case CM_OPEN: zssh_chan_build_open(&w); break;
    case CM_CONFIRM: zssh_chan_build_open_confirm(&s->chan, &w); break;
    case CM_EOF: zssh_chan_build_eof(&s->chan, &w); break;
    case CM_CLOSE: zssh_chan_build_close(&s->chan, &w); break;
    default: zssh_chan_build_request_failure(&s->chan, &w); break;
    }
    e = zssh_conn_commit(s, &w);
    if (e != ZSSH_E_NONE) return e;
    /* state announced by the message changes only after the commit */
    if (k == CM_OPEN) zssh_chan_mark_open_sent(&s->chan);
    else if (k == CM_EOF) zssh_chan_mark_eof_sent(&s->chan);
    else if (k == CM_CLOSE) zssh_chan_mark_close_sent(&s->chan);
    return ZSSH_E_NONE;
}

static enum zssh_error send_open_failure(struct zssh_impl *s, uint32_t rid, uint32_t reason)
{
    struct zssh_wr w;
    enum zssh_error e = ctrl_begin(s, &w);
    if (e != ZSSH_E_NONE) return e;
    zssh_chan_build_open_failure(rid, reason, &w);
    return zssh_conn_commit(s, &w);
}

static enum zssh_error send_window_adjust(struct zssh_impl *s, uint32_t add)
{
    struct zssh_wr w;
    enum zssh_error e = ctrl_begin(s, &w);
    if (e != ZSSH_E_NONE) return e;
    zssh_chan_build_window_adjust(&s->chan, add, &w);
    e = zssh_conn_commit(s, &w);
    if (e == ZSSH_E_NONE) zssh_chan_window_adjust_sent(&s->chan, add);
    return e;
}

/* room test of the admission rule: room - wire >= reserve */
static bool admit(const struct zssh_impl *s, size_t wire)
{
    return zssh_txq_room(&s->txq) >= wire + ZSSH_TXQ_RESERVE;
}

/* Queue the WINDOW_ADJUST that reads made due, if there is room; otherwise
 * it is retried by the next input/pump/recv/send call. */
static enum zssh_error flush_window_adjust(struct zssh_impl *s)
{
    if (s->state != ZSSH_STATE_CHANNEL || s->chan.sent_close || s->chan.recv_close)
        return ZSSH_E_NONE;
    uint32_t add = zssh_chan_window_adjust_due(&s->chan);
    if (add == 0 || !admit(s, SMALL_WIRE)) return ZSSH_E_NONE;
    return send_window_adjust(s, add);
}

/* ======================================================================== *
 * key exchange                                                             *
 * ======================================================================== */

/* Our KEXINIT, queued at init: cookie from rand, payload kept as I_C / I_S. */
static enum zssh_error queue_kexinit(struct zssh_impl *s)
{
    uint8_t cookie[16];
    struct zssh_wr w;
    if (!s->rand(s->rand_ctx, cookie, sizeof cookie)) ZSSH_FAIL(ZSSH_E_RANDOM, "cookie draw failed");
    enum zssh_error e = ctrl_begin(s, &w);
    if (e == ZSSH_E_NONE) e = zssh_kex_build_kexinit(&s->policy, cookie, &w);
    if (e == ZSSH_E_NONE && (!zssh_wr_ok(&w) || w.off > ZSSH_KEXINIT_MAX))
        e = ZSSH_E_TOO_LARGE;
    if (e == ZSSH_E_NONE) {
        uint8_t *dst = s->role == ZSSH_ROLE_CLIENT ? s->kex.i_c : s->kex.i_s;
        memcpy(dst, w.p, w.off);
        if (s->role == ZSSH_ROLE_CLIENT) s->kex.i_c_len = w.off;
        else s->kex.i_s_len = w.off;
        e = zssh_conn_commit(s, &w);
    }
    return e;
}

static const uint8_t *tx_key(const struct zssh_impl *s, const struct zssh_keys *k)
{
    return s->role == ZSSH_ROLE_CLIENT ? k->c2s : k->s2c;
}

static const uint8_t *rx_key(const struct zssh_impl *s, const struct zssh_keys *k)
{
    return s->role == ZSSH_ROLE_CLIENT ? k->s2c : k->c2s;
}

/* Seal+commit NEWKEYS with the OLD tx state, then install the new tx key and
 * reset tx.seq in the same step. */
static enum zssh_error send_newkeys(struct zssh_impl *s)
{
    struct zssh_keys keys;
    struct zssh_wr w;
    enum zssh_error e = zssh_kex_derive_keys(&s->kex, &keys);
    if (e != ZSSH_E_NONE) {
        memory_cleanse(&keys, sizeof keys);
        return e;
    }
    e = ctrl_begin(s, &w);
    if (e == ZSSH_E_NONE) {
        zssh_wr_u8(&w, ZSSH_MSG_NEWKEYS);
        e = zssh_conn_commit(s, &w);
    }
    if (e == ZSSH_E_NONE)
        e = zssh_pkt_set_cipher(&s->tx, ZSSH_CIPHER_CHACHA20_POLY1305, tx_key(s, &keys), true);
    memory_cleanse(&keys, sizeof keys);
    if (e != ZSSH_E_NONE) return e;
    s->sent_newkeys = true;
    s->kex_phase = ZSSH_KP_WAIT_NEWKEYS;
    return ZSSH_E_NONE;
}

static enum zssh_error on_kexinit(struct zssh_impl *s, const uint8_t *p, size_t len)
{
    struct zssh_kexinit_view v;
    struct zssh_neg neg;
    if (s->recv_kexinit || s->kex_phase != ZSSH_KP_WAIT_KEXINIT)
        ZSSH_FAIL(ZSSH_E_PROTOCOL, "unexpected KEXINIT");
    if (len > ZSSH_KEXINIT_MAX) ZSSH_FAIL(ZSSH_E_TOO_LARGE, "KEXINIT too large");
    enum zssh_error e = zssh_kex_parse_kexinit(p, len, &v);
    if (e == ZSSH_E_NONE) e = zssh_kex_negotiate(&s->policy, &v, &neg);
    if (e != ZSSH_E_NONE) return e;
    if (!neg.strict) ZSSH_FAIL(ZSSH_E_STRICT_KEX_REQUIRED, "strict KEX not negotiated");
    s->kex.neg = neg;
    if (s->role == ZSSH_ROLE_CLIENT) {
        memcpy(s->kex.i_s, p, len);
        s->kex.i_s_len = len;
    } else {
        memcpy(s->kex.i_c, p, len);
        s->kex.i_c_len = len;
    }
    s->recv_kexinit = true;
    if (s->role == ZSSH_ROLE_SERVER) {
        s->kex_phase = ZSSH_KP_WAIT_INIT;
        return ZSSH_E_NONE;
    }
    struct zssh_wr w;
    e = ctrl_begin(s, &w);
    if (e == ZSSH_E_NONE) e = zssh_kex_client_init(&s->kex, s->rand, s->rand_ctx, &w);
    if (e == ZSSH_E_NONE) e = zssh_conn_commit(s, &w);
    if (e == ZSSH_E_NONE) s->kex_phase = ZSSH_KP_WAIT_REPLY;
    return e;
}

/* SERVER: client INIT (30) -> REPLY (31) + NEWKEYS. */
static enum zssh_error on_kex_init(struct zssh_impl *s, const uint8_t *p, size_t len)
{
    struct zssh_wr w;
    if (s->role != ZSSH_ROLE_SERVER || s->kex_phase != ZSSH_KP_WAIT_INIT)
        ZSSH_FAIL(ZSSH_E_PROTOCOL, "unexpected kex init");
    enum zssh_error e = ctrl_begin(s, &w);
    if (e == ZSSH_E_NONE)
        e = zssh_kex_server_reply(&s->kex, p, len, s->host_pk, s->host_seed,
                                  s->rand, s->rand_ctx, &w);
    if (e == ZSSH_E_NONE) e = zssh_conn_commit(s, &w);
    if (e == ZSSH_E_NONE) e = send_newkeys(s);
    return e;
}

/* CLIENT: server REPLY (31): pin, math and signature checked by KEX before
 * any credential; then our NEWKEYS. */
static enum zssh_error on_kex_reply(struct zssh_impl *s, const uint8_t *p, size_t len)
{
    if (s->role != ZSSH_ROLE_CLIENT || s->kex_phase != ZSSH_KP_WAIT_REPLY)
        ZSSH_FAIL(ZSSH_E_PROTOCOL, "unexpected kex reply");
    enum zssh_error e = zssh_kex_client_finish(&s->kex, p, len, s->host_pk);
    if (e == ZSSH_E_NONE) e = send_newkeys(s);
    return e;
}

/* Peer NEWKEYS: install the rx key (seq reset) before the next length is
 * peeked, then the exchange secrets go. */
static enum zssh_error on_newkeys(struct zssh_impl *s, size_t len)
{
    struct zssh_keys keys;
    if (len != 1 || s->kex_phase != ZSSH_KP_WAIT_NEWKEYS || !s->sent_newkeys)
        ZSSH_FAIL(ZSSH_E_PROTOCOL, "unexpected NEWKEYS");
    enum zssh_error e = zssh_kex_derive_keys(&s->kex, &keys);
    if (e == ZSSH_E_NONE)
        e = zssh_pkt_set_cipher(&s->rx, ZSSH_CIPHER_CHACHA20_POLY1305, rx_key(s, &keys), true);
    memory_cleanse(&keys, sizeof keys);
    if (e != ZSSH_E_NONE) return e;
    zssh_kex_wipe(&s->kex);
    s->recv_newkeys = true;
    s->kex_phase = ZSSH_KP_DONE;
    s->state = ZSSH_STATE_AUTH;
    if (s->role == ZSSH_ROLE_CLIENT) return send_service(s, false);
    return ZSSH_E_NONE;
}

static enum zssh_error dispatch_kex(struct zssh_impl *s, const uint8_t *p, size_t len)
{
    uint8_t m = p[0];
    if (m == ZSSH_MSG_DISCONNECT) return ZSSH_E_PEER_DISCONNECT;
    if (!zssh_kex_msg_allowed(m, s->kex_phase)) {
        if (s->kex_phase == ZSSH_KP_WAIT_KEXINIT)
            ZSSH_FAIL(ZSSH_E_STRICT_KEX_REQUIRED, "message %u before KEXINIT", (unsigned)m);
        ZSSH_FAIL(ZSSH_E_PROTOCOL, "message %u not allowed during key exchange", (unsigned)m);
    }
    if (m == ZSSH_MSG_KEXINIT) return on_kexinit(s, p, len);
    if (m == ZSSH_MSG_KEX_INIT_30) return on_kex_init(s, p, len);
    if (m == ZSSH_MSG_KEX_REPLY_31) return on_kex_reply(s, p, len);
    if (m == ZSSH_MSG_NEWKEYS) return on_newkeys(s, len);
    ZSSH_FAIL(ZSSH_E_PROTOCOL, "message %u unexpected during key exchange", (unsigned)m);
}

/* ======================================================================== *
 * service, authentication                                                  *
 * ======================================================================== */

static enum zssh_error handle_service(struct zssh_impl *s, uint8_t m,
                                      const uint8_t *p, size_t len)
{
    struct zssh_namelist svc;
    bool server = s->role == ZSSH_ROLE_SERVER;
    if (s->state != ZSSH_STATE_AUTH || s->service_accepted ||
        (m == ZSSH_MSG_SERVICE_REQUEST) != server)
        ZSSH_FAIL(ZSSH_E_PROTOCOL, "unexpected service message %u", (unsigned)m);
    enum zssh_error e = zssh_auth_parse_service(p, len, m, &svc);
    if (e != ZSSH_E_NONE) return e;
    if (!ns_eq(svc, ZSSH_SERVICE_USERAUTH)) ZSSH_FAIL(ZSSH_E_PROTOCOL, "unknown service");
    s->service_accepted = true;
    if (server) return send_service(s, true);
    s->auth_failures = 1;   /* client: requests sent */
    return send_auth_request(s);
}

static enum zssh_error server_auth(struct zssh_impl *s, const uint8_t *p, size_t len)
{
    struct zssh_auth_request req;
    enum zssh_error e = zssh_auth_parse_request(p, len, &req);
    if (e != ZSSH_E_NONE) return e;
    if (req.kind != ZSSH_AUTH_PUBLICKEY) {
        if (s->auth_none >= ZSSH_MAX_AUTH_NONE)
            ZSSH_FAIL(ZSSH_E_AUTH_REFUSED, "too many none requests");
        s->auth_none++;
        return send_auth_verdict(s, ZSSH_AUTH_V_FAILURE, &req);
    }
    if (s->auth_failures >= ZSSH_MAX_AUTH_ATTEMPTS)
        ZSSH_FAIL(ZSSH_E_AUTH_REFUSED, "too many publickey requests");
    s->auth_failures++;                 /* probes count too */
    enum zssh_auth_verdict v = zssh_auth_server_decide(&req, s->kex.session_id,
                                                       s->user, s->user_pk);
    e = send_auth_verdict(s, v, &req);
    if (e == ZSSH_E_NONE && v == ZSSH_AUTH_V_SUCCESS) {
        s->authenticated = true;
        s->state = ZSSH_STATE_OPEN;
    }
    return e;
}

static enum zssh_error client_auth(struct zssh_impl *s, const uint8_t *p, size_t len)
{
    bool success = false, pk_ok = false;
    enum zssh_error e = zssh_auth_client_result_ex(p, len, &success, &pk_ok);
    if (e != ZSSH_E_NONE) return e;
    if (pk_ok) ZSSH_FAIL(ZSSH_E_PROTOCOL, "unsolicited PK_OK");
    if (!success) return ZSSH_E_NONE;   /* banner */
    s->authenticated = true;
    s->state = ZSSH_STATE_OPEN;
    return send_chan_msg(s, CM_OPEN);
}

static enum zssh_error handle_auth(struct zssh_impl *s, uint8_t m,
                                   const uint8_t *p, size_t len)
{
    if (s->role == ZSSH_ROLE_SERVER && m == ZSSH_MSG_USERAUTH_REQUEST) {
        if (s->state == ZSSH_STATE_OPEN || s->state == ZSSH_STATE_CHANNEL)
            return ZSSH_E_NONE;          /* RFC 4252 5.1: ignored after success */
        if (s->state != ZSSH_STATE_AUTH || !s->service_accepted)
            ZSSH_FAIL(ZSSH_E_PROTOCOL, "userauth before service accept");
        return server_auth(s, p, len);
    }
    if (s->role == ZSSH_ROLE_CLIENT && m != ZSSH_MSG_USERAUTH_REQUEST &&
        s->state == ZSSH_STATE_AUTH && s->service_accepted)
        return client_auth(s, p, len);
    ZSSH_FAIL(ZSSH_E_PROTOCOL, "unexpected auth message %u", (unsigned)m);
}

/* ======================================================================== *
 * channel messages                                                         *
 * ======================================================================== */

static enum zssh_error handle_global(struct zssh_impl *s, uint8_t m,
                                     const uint8_t *p, size_t len)
{
    struct zssh_rd r;
    const uint8_t *name;
    size_t nlen;
    if (m != ZSSH_MSG_GLOBAL_REQUEST ||
        (s->state != ZSSH_STATE_OPEN && s->state != ZSSH_STATE_CHANNEL))
        ZSSH_FAIL(ZSSH_E_PROTOCOL, "unexpected global message %u", (unsigned)m);
    zssh_rd_init(&r, p, len);
    (void)zssh_rd_u8(&r);
    zssh_rd_string(&r, &name, &nlen);
    bool want = zssh_rd_bool(&r);
    if (!zssh_rd_ok(&r)) ZSSH_FAIL(ZSSH_E_PROTOCOL, "malformed global request");
    return want ? send_byte_msg(s, ZSSH_MSG_REQUEST_FAILURE) : ZSSH_E_NONE;
}

static enum zssh_error chan_request(struct zssh_impl *s, const uint8_t *p, size_t len)
{
    struct zssh_rd r;
    const uint8_t *type;
    size_t tlen;
    zssh_rd_init(&r, p, len);
    (void)zssh_rd_u8(&r);
    uint32_t recipient = zssh_rd_u32(&r);
    zssh_rd_string(&r, &type, &tlen);
    bool want = zssh_rd_bool(&r);
    if (!zssh_rd_ok(&r) || recipient != 0)
        ZSSH_FAIL(ZSSH_E_PROTOCOL, "malformed channel request");
    return want ? send_chan_msg(s, CM_REQ_FAIL) : ZSSH_E_NONE;
}

/* Peer CLOSE: answer with our CLOSE exactly once, then DISCONNECT + CLOSED. */
static enum zssh_error peer_close(struct zssh_impl *s, const uint8_t *p, size_t len)
{
    enum zssh_error e = zssh_chan_on_close(&s->chan, p, len);
    if (e != ZSSH_E_NONE) return e;
    if (!s->chan.sent_close) {
        e = send_chan_msg(s, CM_CLOSE);
        if (e != ZSSH_E_NONE) return e;
    }
    if (s->chan.state != ZSSH_CH_CLOSED) ZSSH_FAIL(ZSSH_E_INTERNAL, "channel not closed after both CLOSEs");
    return finish_close(s);
}

/* CHANNEL_OPEN at the server. First open refused: the session closes
 * (policy); a further open while a channel exists is refused and ignored. */
static enum zssh_error server_open(struct zssh_impl *s, const uint8_t *p, size_t len)
{
    uint32_t rid = 0, reason = 0;
    bool first = s->state == ZSSH_STATE_OPEN;
    if (s->role != ZSSH_ROLE_SERVER) ZSSH_FAIL(ZSSH_E_PROTOCOL, "CHANNEL_OPEN at client");
    enum zssh_error e = zssh_chan_server_open(&s->chan, p, len, &rid, &reason);
    if (e == ZSSH_E_CHANNEL_REFUSED) {
        enum zssh_error se = send_open_failure(s, rid, reason);
        if (se != ZSSH_E_NONE) return se;
        return first ? ZSSH_E_CHANNEL_REFUSED : ZSSH_E_NONE;
    }
    if (e != ZSSH_E_NONE) return e;
    if (!first) ZSSH_FAIL(ZSSH_E_INTERNAL, "open accepted in a live channel");
    e = send_chan_msg(s, CM_CONFIRM);
    if (e == ZSSH_E_NONE) s->state = ZSSH_STATE_CHANNEL;
    return e;
}

static enum zssh_error client_open_reply(struct zssh_impl *s, uint8_t m,
                                         const uint8_t *p, size_t len)
{
    enum zssh_error e;
    if (s->role != ZSSH_ROLE_CLIENT) ZSSH_FAIL(ZSSH_E_PROTOCOL, "open reply at server");
    if (m == ZSSH_MSG_CHANNEL_OPEN_CONFIRMATION) {
        e = zssh_chan_client_confirm(&s->chan, p, len);
        if (e == ZSSH_E_NONE) s->state = ZSSH_STATE_CHANNEL;
        return e;
    }
    if (m == ZSSH_MSG_CHANNEL_OPEN_FAILURE) {
        e = zssh_chan_client_open_failure(&s->chan, p, len);
        return e != ZSSH_E_NONE ? e : ZSSH_E_CHANNEL_REFUSED;
    }
    ZSSH_FAIL(ZSSH_E_PROTOCOL, "unexpected message %u awaiting channel open", (unsigned)m);
}

static enum zssh_error handle_channel(struct zssh_impl *s, uint8_t m,
                                      const uint8_t *p, size_t len)
{
    if (s->state == ZSSH_STATE_OPEN) {
        if (m == ZSSH_MSG_CHANNEL_OPEN) return server_open(s, p, len);
        return client_open_reply(s, m, p, len);
    }
    if (s->state != ZSSH_STATE_CHANNEL)
        ZSSH_FAIL(ZSSH_E_PROTOCOL, "channel message %u before authentication", (unsigned)m);
    switch (m) {
    case ZSSH_MSG_CHANNEL_DATA: return zssh_chan_on_data(&s->chan, p, len);
    case ZSSH_MSG_CHANNEL_WINDOW_ADJUST: return zssh_chan_on_window_adjust(&s->chan, p, len);
    case ZSSH_MSG_CHANNEL_EOF: return zssh_chan_on_eof(&s->chan, p, len);
    case ZSSH_MSG_CHANNEL_CLOSE: return peer_close(s, p, len);
    case ZSSH_MSG_CHANNEL_REQUEST: return chan_request(s, p, len);
    case ZSSH_MSG_CHANNEL_OPEN: return server_open(s, p, len);
    default: break;   /* EXTENDED_DATA, SUCCESS, FAILURE, confirm/failure */
    }
    ZSSH_FAIL(ZSSH_E_PROTOCOL, "unexpected channel message %u", (unsigned)m);
}

/* ======================================================================== *
 * dispatch                                                                 *
 * ======================================================================== */

/* RFC 4253 11.4: answer an unknown message once, then ignore (no state change). */
static enum zssh_error unimplemented_once(struct zssh_impl *s)
{
    if (UNIMPL_SENT(s)) return ZSSH_E_NONE;
    UNIMPL_SENT(s) = 1;
    return send_unimplemented(s);
}

static enum zssh_error dispatch_post(struct zssh_impl *s, const uint8_t *p, size_t len)
{
    uint8_t m = p[0];
    if (!msg_known(m)) return unimplemented_once(s);
    if (m == ZSSH_MSG_DISCONNECT) return ZSSH_E_PEER_DISCONNECT;
    if (m == ZSSH_MSG_IGNORE || m == ZSSH_MSG_DEBUG) return ZSSH_E_NONE;
    if (m == ZSSH_MSG_KEXINIT)
        ZSSH_FAIL(ZSSH_E_REKEY_UNSUPPORTED, "peer KEXINIT after NEWKEYS");
    if (m == ZSSH_MSG_SERVICE_REQUEST || m == ZSSH_MSG_SERVICE_ACCEPT)
        return handle_service(s, m, p, len);
    if (m >= ZSSH_MSG_USERAUTH_REQUEST && m <= ZSSH_MSG_USERAUTH_PK_OK)
        return handle_auth(s, m, p, len);
    if (m >= ZSSH_MSG_GLOBAL_REQUEST && m <= ZSSH_MSG_REQUEST_FAILURE)
        return handle_global(s, m, p, len);
    if (m >= ZSSH_MSG_CHANNEL_OPEN) return handle_channel(s, m, p, len);
    ZSSH_FAIL(ZSSH_E_PROTOCOL, "message %u not valid here", (unsigned)m);
}

enum zssh_error zssh_conn_dispatch(struct zssh_impl *s, const uint8_t *payload, size_t len)
{
    if (!payload || len == 0) ZSSH_FAIL(ZSSH_E_PROTOCOL, "empty payload");
    if (s->kex_phase != ZSSH_KP_DONE) return dispatch_kex(s, payload, len);
    return dispatch_post(s, payload, len);
}

/* ======================================================================== *
 * input assembler                                                          *
 * ======================================================================== */

static enum zssh_error version_store(struct zssh_impl *s, size_t len)
{
    memcpy(s->peer_version, s->rxbuf, len);
    s->peer_version[len] = 0;
    s->peer_version_len = len;
    if (s->role == ZSSH_ROLE_CLIENT) {
        memcpy(s->kex.v_s, s->rxbuf, len);
        s->kex.v_s_len = len;
    } else {
        memcpy(s->kex.v_c, s->rxbuf, len);
        s->kex.v_c_len = len;
    }
    s->version_done = true;
    s->prebanner_lines = 0;     /* becomes the UNIMPLEMENTED counter */
    s->rxlen = 0;
    s->rx_total = 0;
    s->state = ZSSH_STATE_KEX;
    s->kex_phase = ZSSH_KP_WAIT_KEXINIT;
    return ZSSH_E_NONE;
}

/* LF seen: rxbuf[0..rxlen) is the line without LF. */
static enum zssh_error version_line_done(struct zssh_impl *s)
{
    size_t n = s->rxlen;
    bool cr = n > 0 && s->rxbuf[n - 1] == '\r';
    size_t len = cr ? n - 1 : n;
    if (len < 4 || memcmp(s->rxbuf, "SSH-", 4) != 0) {
        /* RFC 4253 4.2: only a client tolerates text before the banner. */
        if (s->role != ZSSH_ROLE_CLIENT || s->prebanner_lines >= ZSSH_MAX_PREBANNER_LINES)
            ZSSH_FAIL(ZSSH_E_VERSION, "no identification string");
        s->prebanner_lines++;
        s->rxlen = 0;
        return ZSSH_E_NONE;
    }
    if (!cr || len <= 8 || memcmp(s->rxbuf, "SSH-2.0-", 8) != 0)
        ZSSH_FAIL(ZSSH_E_VERSION, "unsupported identification string");
    for (size_t i = 0; i < len; i++)
        if (s->rxbuf[i] < 0x20 || s->rxbuf[i] > 0x7e)
            ZSSH_FAIL(ZSSH_E_VERSION, "control byte in identification string");
    return version_store(s, len);
}

static enum zssh_error version_byte(struct zssh_impl *s, uint8_t b)
{
    if (b == '\n') return version_line_done(s);
    /* 255 bytes including CR LF: 253 + CR here, LF handled above */
    if (s->rxlen >= ZSSH_MAX_VERSION_LINE - 1u)
        ZSSH_FAIL(ZSSH_E_VERSION, "identification line too long");
    s->rxbuf[s->rxlen++] = b;
    return ZSSH_E_NONE;
}

static enum zssh_error feed_version(struct zssh_impl *s, const uint8_t *d, size_t avail,
                                    size_t *used)
{
    size_t i = 0;
    enum zssh_error e = ZSSH_E_NONE;
    while (i < avail && e == ZSSH_E_NONE && !s->version_done) {
        e = version_byte(s, d[i]);
        i++;
    }
    *used = i;
    return e;
}

static bool pkt_complete(const struct zssh_impl *s)
{
    return s->rx_total != 0 && s->rxlen == s->rx_total;
}

static enum zssh_error rx_take(struct zssh_impl *s, const uint8_t *d, size_t avail,
                               size_t *used)
{
    size_t need = s->rx_total ? s->rx_total : zssh_pkt_need_len();
    size_t take = need - s->rxlen;
    if (take > avail) take = avail;
    memcpy(s->rxbuf + s->rxlen, d, take);
    s->rxlen += take;
    *used = take;
    if (s->rx_total == 0 && s->rxlen == zssh_pkt_need_len()) {
        size_t total = 0;
        enum zssh_error e = zssh_pkt_peek_total(&s->rx, s->rxbuf, &total);
        if (e != ZSSH_E_NONE) return e;
        if (total > sizeof s->rxbuf || total <= zssh_pkt_need_len())
            ZSSH_FAIL(ZSSH_E_TOO_LARGE, "packet size outside the buffer");
        s->rx_total = total;
    }
    return ZSSH_E_NONE;
}

static enum zssh_error rx_dispatch(struct zssh_impl *s)
{
    const uint8_t *pl = nullptr;
    size_t pln = 0;
    size_t total = s->rx_total;
    enum zssh_error e = zssh_pkt_open(&s->rx, s->rxbuf, total, &pl, &pln);
    if (e == ZSSH_E_NONE) e = zssh_conn_dispatch(s, pl, pln);
    memory_cleanse(s->rxbuf, total);
    s->rxlen = 0;
    s->rx_total = 0;
    return e;
}

/* One step of the packet assembler. *blocked: no room for the reply reserve. */
static enum zssh_error pkt_step(struct zssh_impl *s, const uint8_t *d, size_t avail,
                                size_t *used, bool *blocked)
{
    *used = 0;
    *blocked = false;
    bool complete = pkt_complete(s);
    bool no_room = zssh_txq_room(&s->txq) < ZSSH_TXQ_RESERVE;
    if ((complete || s->rxlen == 0) && no_room) {
        *blocked = true;
        return ZSSH_E_NONE;
    }
    if (!complete) {
        enum zssh_error e = rx_take(s, d, avail, used);
        if (e != ZSSH_E_NONE) return e;
        complete = pkt_complete(s);
    }
    if (!complete) return ZSSH_E_NONE;
    if (no_room) {
        *blocked = true;
        return ZSSH_E_NONE;
    }
    return rx_dispatch(s);
}

static bool live(const struct zssh_impl *s)
{
    return s->state != ZSSH_STATE_FAILED && s->state != ZSSH_STATE_CLOSED;
}

static void input_core(struct zssh_impl *s, const uint8_t *d, size_t n, size_t *consumed)
{
    static const uint8_t none[1] = { 0 };
    size_t pos = 0;
    *consumed = 0;
    if (!d) d = none;               /* n == 0 resume: no NULL pointer arithmetic */
    if (!live(s)) return;
    enum zssh_error e = flush_window_adjust(s);
    while (e == ZSSH_E_NONE && live(s)) {
        size_t used = 0;
        bool blocked = false;
        if (!s->version_done) {
            if (pos >= n) break;
            e = feed_version(s, d + pos, n - pos, &used);
        } else {
            if (pos >= n && !pkt_complete(s)) break;
            e = pkt_step(s, d + pos, n - pos, &used, &blocked);
        }
        pos += used;
        if (blocked) break;
    }
    *consumed = pos;
    if (e != ZSSH_E_NONE) (void)fail_err(s, e);
}

/* stopped: the engine left offered input unconsumed (consumed < n) on a live
 * session; that is NEED_OUTPUT even if the pump's output copy emptied the queue. */
static enum zssh_status status_of(const struct zssh_impl *s, bool stopped)
{
    if (s->state == ZSSH_STATE_FAILED) return ZSSH_STATUS_FAILED;
    if (s->state == ZSSH_STATE_CLOSED) return ZSSH_CLOSED;
    if (stopped || zssh_txq_pending(&s->txq) > 0) return ZSSH_NEED_OUTPUT;
    return s->state == ZSSH_STATE_CHANNEL ? ZSSH_CHANNEL_READY : ZSSH_NEED_INPUT;
}

static struct zssh_impl *impl_ok(struct zssh_conn *c)
{
    if (!c) return nullptr;
    struct zssh_impl *s = zssh_impl_of(c);
    return s->magic == ZSSH_IMPL_MAGIC ? s : nullptr;
}

static const struct zssh_impl *impl_ok_const(const struct zssh_conn *c)
{
    if (!c) return nullptr;
    const struct zssh_impl *s = zssh_impl_of_const(c);
    return s->magic == ZSSH_IMPL_MAGIC ? s : nullptr;
}

enum zssh_status zssh_input(struct zssh_conn *conn, const uint8_t *data, size_t n,
                            size_t *consumed)
{
    if (consumed) *consumed = 0;
    struct zssh_impl *s = impl_ok(conn);
    if (!s || !consumed || (n > 0 && !data)) return ZSSH_STATUS_BAD_CALL;
    input_core(s, data, n, consumed);
    return status_of(s, *consumed < n);
}

enum zssh_status zssh_pump(struct zssh_conn *conn, const uint8_t *in, size_t in_len,
                           size_t *consumed, uint8_t *out, size_t out_cap, size_t *produced)
{
    if (consumed) *consumed = 0;
    if (produced) *produced = 0;
    struct zssh_impl *s = impl_ok(conn);
    if (!s || !consumed || !produced || (in_len > 0 && !in) || (out_cap > 0 && !out))
        return ZSSH_STATUS_BAD_CALL;
    input_core(s, in, in_len, consumed);
    const uint8_t *p = nullptr;
    size_t pend = 0;
    zssh_txq_peek(&s->txq, &p, &pend);
    size_t k = pend < out_cap ? pend : out_cap;
    if (k > 0) {
        memcpy(out, p, k);
        (void)zssh_txq_consume(&s->txq, k);
    }
    *produced = k;
    return status_of(s, *consumed < in_len);
}

enum zssh_result zssh_output_peek(const struct zssh_conn *conn, const uint8_t **p, size_t *n)
{
    if (p) *p = nullptr;
    if (n) *n = 0;
    const struct zssh_impl *s = impl_ok_const(conn);
    if (!s || !p || !n) return ZSSH_BAD_CALL;
    zssh_txq_peek(&s->txq, p, n);
    if (!*p) *p = s->txq.buf;   /* non-NULL even when empty */
    return ZSSH_OK;
}

enum zssh_result zssh_output_consume(struct zssh_conn *conn, size_t n)
{
    struct zssh_impl *s = impl_ok(conn);
    if (!s || n > zssh_txq_pending(&s->txq)) return ZSSH_BAD_CALL;
    return zssh_txq_consume(&s->txq, n) ? ZSSH_OK : ZSSH_BAD_CALL;
}

/* ======================================================================== *
 * channel API                                                              *
 * ======================================================================== */

static enum zssh_error send_data_packet(struct zssh_impl *s, const uint8_t *data, size_t take)
{
    struct zssh_wr w;
    enum zssh_error e = begin_sized(s, &w, DATA_HDR + take);
    if (e != ZSSH_E_NONE) return ZSSH_E_INTERNAL;
    e = zssh_chan_send_build(&s->chan, data, take, &w);
    if (e == ZSSH_E_NONE) e = zssh_conn_commit(s, &w);
    if (e == ZSSH_E_NONE) zssh_chan_send_commit(&s->chan, take);
    return e;
}

/* Payload bytes the next DATA packet would carry with `room` free queue bytes
 * and `left` bytes still to send; 0 = no packet (no window, no room, or a
 * room-limited runt that must wait for the drain). */
static size_t send_take(const struct zssh_impl *s, size_t room, size_t left)
{
    const size_t overhead = ZSSH_TXQ_RESERVE + ZSSH_PKT_HDR + DATA_HDR +
                            ZSSH_PAD_RANDOM_MAX + ZSSH_TAG_LEN;
    size_t avail = room > overhead ? room - overhead : 0;
    size_t take = zssh_chan_send_plan(&s->chan, left, avail);
    /* Queue room (not the window or the data) is the limit and it is
     * tiny: wait for the drain instead of queueing a runt packet. */
    if (take == avail && take < left && take < SEND_MIN_FRAGMENT) return 0;
    return take;
}

/* Admission before mutation: a due WINDOW_ADJUST is queued only if it fits and
 * the DATA packet send_loop will then build still fits behind it. */
static enum zssh_error flush_adjust_for_send(struct zssh_impl *s, size_t n)
{
    if (zssh_chan_window_adjust_due(&s->chan) == 0 || !admit(s, SMALL_WIRE))
        return ZSSH_E_NONE;
    if (send_take(s, zssh_txq_room(&s->txq) - SMALL_WIRE, n) == 0)
        return ZSSH_E_NONE;
    return flush_window_adjust(s);
}

static enum zssh_result send_loop(struct zssh_impl *s, const uint8_t *data, size_t n,
                                  size_t *accepted)
{
    size_t done = 0;
    while (done < n) {
        size_t take = send_take(s, zssh_txq_room(&s->txq), n - done);
        if (take == 0) break;
        enum zssh_error e = send_data_packet(s, data + done, take);
        if (e != ZSSH_E_NONE) {
            *accepted = done;
            return api_fail(s, e);
        }
        done += take;
    }
    *accepted = done;
    return done > 0 ? ZSSH_OK : ZSSH_AGAIN;
}

enum zssh_result zssh_channel_send(struct zssh_conn *conn, const uint8_t *data, size_t n,
                                   size_t *accepted)
{
    if (accepted) *accepted = 0;
    struct zssh_impl *s = impl_ok(conn);
    if (!s || !accepted || (n > 0 && !data)) return ZSSH_BAD_CALL;
    if (s->state == ZSSH_STATE_FAILED) return ZSSH_FAILED;
    if (s->state == ZSSH_STATE_CLOSED || s->chan.recv_close) return ZSSH_EOF;
    if (s->state != ZSSH_STATE_CHANNEL || s->chan.sent_eof || s->chan.sent_close)
        return ZSSH_BAD_CALL;
    if (n == 0) return ZSSH_OK;
    enum zssh_error e = flush_adjust_for_send(s, n);
    if (e != ZSSH_E_NONE) return api_fail(s, e);
    return send_loop(s, data, n, accepted);
}

enum zssh_result zssh_channel_recv(struct zssh_conn *conn, uint8_t *buf, size_t cap,
                                   size_t *got)
{
    if (got) *got = 0;
    struct zssh_impl *s = impl_ok(conn);
    if (!s || !got || (cap > 0 && !buf)) return ZSSH_BAD_CALL;
    if (s->state == ZSSH_STATE_FAILED) return ZSSH_FAILED;
    if (s->state != ZSSH_STATE_CHANNEL && s->state != ZSSH_STATE_CLOSED)
        return ZSSH_BAD_CALL;
    if (cap == 0) return ZSSH_OK;
    size_t g = zssh_chan_recv(&s->chan, buf, cap);
    *got = g;
    if (g == 0) return (s->chan.recv_eof || s->chan.recv_close) ? ZSSH_EOF : ZSSH_AGAIN;
    enum zssh_error e = flush_window_adjust(s);   /* only after data was read */
    return e != ZSSH_E_NONE ? api_fail(s, e) : ZSSH_OK;
}

enum zssh_result zssh_channel_send_eof(struct zssh_conn *conn)
{
    struct zssh_impl *s = impl_ok(conn);
    if (!s) return ZSSH_BAD_CALL;
    if (s->state == ZSSH_STATE_FAILED) return ZSSH_FAILED;
    if (s->state == ZSSH_STATE_CLOSED) return ZSSH_OK;
    if (s->state != ZSSH_STATE_CHANNEL) return ZSSH_BAD_CALL;
    if (s->chan.sent_eof || s->chan.sent_close) return ZSSH_OK;
    if (!admit(s, SMALL_WIRE)) return ZSSH_AGAIN;
    enum zssh_error e = send_chan_msg(s, CM_EOF);
    return e == ZSSH_E_NONE ? ZSSH_OK : api_fail(s, e);
}

enum zssh_result zssh_channel_close(struct zssh_conn *conn)
{
    struct zssh_impl *s = impl_ok(conn);
    if (!s) return ZSSH_BAD_CALL;
    if (s->state == ZSSH_STATE_FAILED) return ZSSH_FAILED;
    if (s->state == ZSSH_STATE_CLOSED) return ZSSH_OK;
    if (s->state != ZSSH_STATE_CHANNEL) return ZSSH_BAD_CALL;
    if (s->chan.sent_close) return ZSSH_OK;
    /* EOF + CLOSE are one all-or-nothing step as far as room goes */
    if (!admit(s, (s->chan.sent_eof ? 1u : 2u) * SMALL_WIRE)) return ZSSH_AGAIN;
    enum zssh_error e = ZSSH_E_NONE;
    if (!s->chan.sent_eof) e = send_chan_msg(s, CM_EOF);
    if (e == ZSSH_E_NONE) e = send_chan_msg(s, CM_CLOSE);
    if (e == ZSSH_E_NONE && s->chan.state == ZSSH_CH_CLOSED) e = finish_close(s);
    return e == ZSSH_E_NONE ? ZSSH_OK : api_fail(s, e);
}

enum zssh_result zssh_channel_flags_get(const struct zssh_conn *conn,
                                        struct zssh_channel_flags *out)
{
    const struct zssh_impl *s = impl_ok_const(conn);
    if (!s || !out) return ZSSH_BAD_CALL;
    zssh_chan_flags(&s->chan, out);
    return ZSSH_OK;
}

/* ======================================================================== *
 * getters, evidence, teardown                                              *
 * ======================================================================== */

enum zssh_state zssh_state(const struct zssh_conn *conn)
{
    const struct zssh_impl *s = impl_ok_const(conn);
    return s ? s->state : ZSSH_STATE_FAILED;
}

enum zssh_error zssh_error(const struct zssh_conn *conn)
{
    const struct zssh_impl *s = impl_ok_const(conn);
    return s ? s->error : ZSSH_E_INTERNAL;
}

enum zssh_result zssh_session_info_get(const struct zssh_conn *conn,
                                       struct zssh_session_info *out)
{
    const struct zssh_impl *s = impl_ok_const(conn);
    if (!s || !out) return ZSSH_BAD_CALL;
    memset(out, 0, sizeof *out);
    if (!(s->sent_newkeys && s->recv_newkeys && s->kex.have_session_id)) return ZSSH_OK;
    const char *nm = zssh_kex_alg_name(s->kex.neg.alg);
    size_t nl = strlen(nm);
    if (nl >= sizeof out->kex_name) nl = sizeof out->kex_name - 1u;
    memcpy(out->kex_name, nm, nl);
    out->valid = true;
    out->post_quantum = s->kex.neg.alg == ZSSH_KEXALG_MLKEM768X25519;
    out->kex_generation = s->kex.generation;
    out->strict_kex = s->kex.neg.strict;
    memcpy(out->peer_version, s->peer_version, s->peer_version_len);
    memcpy(out->host_key, s->host_pk, ZSSH_ED25519_PK_LEN);
    zssh_auth_fingerprint(s->kex.host_blob, out->host_key_sha256);
    return ZSSH_OK;
}

/* Transport EOF is a clean end only when nothing can have been lost: our
 * CHANNEL_CLOSE is queued and fully taken by the caller, the peer's EOF or
 * CLOSE was received, and no bytes of a partial packet are buffered. */
static bool eof_is_clean(const struct zssh_impl *s)
{
    if (s->state != ZSSH_STATE_CHANNEL || !s->chan.sent_close) return false;
    if (!s->chan.recv_eof && !s->chan.recv_close) return false;
    return zssh_txq_pending(&s->txq) == 0 && s->rxlen == 0;
}

enum zssh_result zssh_transport_eof(struct zssh_conn *conn)
{
    struct zssh_impl *s = impl_ok(conn);
    if (!s) return ZSSH_BAD_CALL;
    if (s->state == ZSSH_STATE_CLOSED) return ZSSH_OK;
    if (eof_is_clean(s)) {
        s->state = ZSSH_STATE_CLOSED;           /* no DISCONNECT: transport is gone */
        zssh_conn_wipe_secrets(s);              /* unread ring data stays readable */
        return ZSSH_OK;
    }
    if (s->state != ZSSH_STATE_FAILED)
        (void)zssh_conn_fail(s, ZSSH_E_TRUNCATED, ZSSH_DISC_BY_APPLICATION);
    return ZSSH_FAILED;
}

void zssh_wipe(struct zssh_conn *conn)
{
    if (!conn) return;
    struct zssh_impl *s = zssh_impl_of(conn);
    if (s->magic != ZSSH_IMPL_MAGIC) {
        memory_cleanse(conn, sizeof *conn);
        return;
    }
    if (s->state != ZSSH_STATE_CLOSED && s->state != ZSSH_STATE_FAILED) {
        s->state = ZSSH_STATE_FAILED;
        s->error = ZSSH_E_INTERNAL;
    }
    zssh_conn_wipe_secrets(s);
    zssh_chan_scrub(&s->chan);
    memory_cleanse(&s->kex, sizeof s->kex);
    memory_cleanse(s->peer_version, sizeof s->peer_version);
    memory_cleanse(&s->txq, sizeof s->txq);
    zssh_txq_init(&s->txq);
    s->sent_newkeys = false;
    s->recv_newkeys = false;
}

/* ======================================================================== *
 * init                                                                     *
 * ======================================================================== */

/* Exactly one identity block per role, the other pointers NULL. */
static bool identity_matches_role(const struct zssh_config *c)
{
    if (c->role == ZSSH_ROLE_SERVER)
        return c->host_seed && c->authorized_user_pk && !c->pinned_host_pk && !c->user_seed;
    return c->pinned_host_pk && c->user_seed && !c->host_seed && !c->authorized_user_pk;
}

static enum zssh_error init_check_identity(const struct zssh_config *c)
{
    if (c->role != ZSSH_ROLE_SERVER && c->role != ZSSH_ROLE_CLIENT)
        ZSSH_FAIL(ZSSH_E_CONFIG, "bad role");
    if (!identity_matches_role(c)) ZSSH_FAIL(ZSSH_E_CONFIG, "identity block does not match the role");
    if (c->user && strnlen(c->user, ZSSH_MAX_USER + 1u) > ZSSH_MAX_USER)
        ZSSH_FAIL(ZSSH_E_CONFIG, "user name too long");
    return ZSSH_E_NONE;
}

static enum zssh_error init_check_kex(const struct zssh_config *c)
{
    const uint32_t known = ZSSH_KEX_MLKEM768X25519_SHA256 | ZSSH_KEX_CURVE25519_SHA256;
    if (!c->rand) ZSSH_FAIL(ZSSH_E_CONFIG, "rand required");
    if (c->kex_allowed == 0 || (c->kex_allowed & ~known) != 0)
        ZSSH_FAIL(ZSSH_E_CONFIG, "bad kex set");
    if (c->require_pq && !(c->kex_allowed & ZSSH_KEX_MLKEM768X25519_SHA256))
        ZSSH_FAIL(ZSSH_E_CONFIG, "require_pq without the hybrid");
    if (c->version_comment) {
        size_t n = strnlen(c->version_comment, ZSSH_MAX_COMMENT + 1u);
        if (n > ZSSH_MAX_COMMENT) ZSSH_FAIL(ZSSH_E_CONFIG, "comment too long");
        for (size_t i = 0; i < n; i++) {
            unsigned char ch = (unsigned char)c->version_comment[i];
            if (ch < 0x20 || ch > 0x7e) ZSSH_FAIL(ZSSH_E_CONFIG, "comment byte not printable");
        }
    }
    return ZSSH_E_NONE;
}

static void init_copy_identity(struct zssh_impl *s, const struct zssh_config *c)
{
    uint8_t scratch[ZSSH_ED25519_SEED_LEN];
    if (c->role == ZSSH_ROLE_SERVER) {
        memcpy(s->host_seed, c->host_seed, ZSSH_ED25519_SEED_LEN);
        ed25519_keypair(s->host_pk, scratch, s->host_seed);
        memcpy(s->user_pk, c->authorized_user_pk, ZSSH_ED25519_PK_LEN);
    } else {
        memcpy(s->host_pk, c->pinned_host_pk, ZSSH_ED25519_PK_LEN);
        memcpy(s->user_seed, c->user_seed, ZSSH_ED25519_SEED_LEN);
        ed25519_keypair(s->user_pk, scratch, s->user_seed);
    }
    memory_cleanse(scratch, sizeof scratch);
    if (c->user) memcpy(s->user, c->user, strnlen(c->user, ZSSH_MAX_USER));
    if (c->version_comment)
        memcpy(s->comment, c->version_comment, strnlen(c->version_comment, ZSSH_MAX_COMMENT));
}

/* "SSH-2.0-zssh_1[ comment]" kept as our V_C / V_S, queued with CR LF. */
static enum zssh_error init_queue_version(struct zssh_impl *s)
{
    uint8_t line[ZSSH_MAX_VERSION_LINE + 1u];
    size_t n = strlen(ZSSH_VERSION_PREFIX);
    memcpy(line, ZSSH_VERSION_PREFIX, n);
    if (s->comment[0]) {
        size_t cl = strlen(s->comment);
        line[n++] = ' ';
        memcpy(line + n, s->comment, cl);
        n += cl;
    }
    uint8_t *dst = s->role == ZSSH_ROLE_CLIENT ? s->kex.v_c : s->kex.v_s;
    memcpy(dst, line, n);
    if (s->role == ZSSH_ROLE_CLIENT) s->kex.v_c_len = n;
    else s->kex.v_s_len = n;
    line[n++] = '\r';
    line[n++] = '\n';
    if (!zssh_txq_append(&s->txq, line, n)) ZSSH_FAIL(ZSSH_E_INTERNAL, "version line does not fit");
    return ZSSH_E_NONE;
}

static void init_failed(struct zssh_impl *s, enum zssh_error e)
{
    s->state = ZSSH_STATE_FAILED;
    s->error = e;
    zssh_conn_wipe_secrets(s);
    zssh_chan_wipe(&s->chan);
    memory_cleanse(&s->txq, sizeof s->txq);
    zssh_txq_init(&s->txq);
    memory_cleanse(&s->kex, sizeof s->kex);
}

enum zssh_result zssh_init(struct zssh_conn *conn, const struct zssh_config *cfg)
{
    if (!conn || !cfg) return ZSSH_BAD_CALL;
    /* Fail closed: both roles need a user name (the server never accepts
     * "any" user). A refused call leaves conn untouched. */
    if (!cfg->user || cfg->user[0] == 0) return ZSSH_BAD_CALL;
    memset(conn, 0, sizeof *conn);
    struct zssh_impl *s = zssh_impl_of(conn);
    s->magic = ZSSH_IMPL_MAGIC;
    s->state = ZSSH_STATE_FAILED;
    enum zssh_error e = init_check_identity(cfg);
    if (e == ZSSH_E_NONE) e = init_check_kex(cfg);
    if (e != ZSSH_E_NONE) {
        init_failed(s, ZSSH_E_CONFIG);
        return ZSSH_FAILED;
    }
    s->role = cfg->role;
    s->rand = cfg->rand;
    s->rand_ctx = cfg->rand_ctx;
    s->policy = (struct zssh_kex_policy){ cfg->role, cfg->kex_allowed, cfg->require_pq };
    s->kex.role = cfg->role;
    s->kex.generation = 0;
    zssh_pkt_dir_init(&s->tx);
    zssh_pkt_dir_init(&s->rx);
    zssh_txq_init(&s->txq);
    zssh_chan_init(&s->chan);
    init_copy_identity(s, cfg);
    e = init_queue_version(s);
    if (e == ZSSH_E_NONE) e = queue_kexinit(s);
    if (e != ZSSH_E_NONE) {
        init_failed(s, e);
        return ZSSH_FAILED;
    }
    s->state = ZSSH_STATE_VERSION;
    s->error = ZSSH_E_NONE;
    return ZSSH_OK;
}
