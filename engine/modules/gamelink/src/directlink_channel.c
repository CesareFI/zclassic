/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * directlink channel: key derivation, address confirmation and sealed
 * datagrams over the punch machine and the gamelink session. See
 * directlink_channel.h for the composition and its guarantees. */

#include "gamelink/directlink_channel.h"

#include "base/cleanse.h"
#include "crypto/hkdf_sha3.h"

#include <string.h>

#define LABEL_PSK "z23/directlink/v1/psk"
#define LABEL_CHANNEL "z23/directlink/v1/channel"
#define LABEL_PROBE "z23/directlink/v1/probe"

#define FRAME_CONFIRM_INITIATOR 0x01u
#define FRAME_DATA 0x02u
#define FRAME_CONFIRM_RESPONDER 0x03u
#define FRAME_ACK_INITIATOR 0x05u
#define FRAME_ACK_RESPONDER 0x07u

const char *directlink_channel_status_label(enum directlink_channel_status status)
{
    switch (status) {
    case DIRECTLINK_CHANNEL_OK: return "ok";
    case DIRECTLINK_CHANNEL_ARGUMENT: return "argument";
    case DIRECTLINK_CHANNEL_NO_PSK: return "pairing_secret_required";
    case DIRECTLINK_CHANNEL_DERIVE: return "derive_failed";
    case DIRECTLINK_CHANNEL_SECRET_USED: return "secret_consumed";
    case DIRECTLINK_CHANNEL_ADDRESS: return "address_refused";
    case DIRECTLINK_CHANNEL_PUNCH: return "punch_refused";
    case DIRECTLINK_CHANNEL_LINK: return "link_refused";
    case DIRECTLINK_CHANNEL_NOT_OPEN: return "not_open";
    case DIRECTLINK_CHANNEL_TOO_LARGE: return "payload_too_large";
    case DIRECTLINK_CHANNEL_REKEY: return "rekey_required";
    case DIRECTLINK_CHANNEL_SEND_FAILED: return "send_failed";
    }
    return "unknown";
}

/* ── key derivation ──────────────────────────────────────────────────── */

static bool all_zero(const uint8_t *bytes, size_t len)
{
    uint8_t acc = 0;
    for (size_t i = 0; i < len; i++)
        acc |= bytes[i];
    return acc == 0;
}

static bool psk_is_none(const uint8_t psk[DIRECTLINK_CHANNEL_SECRET_BYTES])
{
    return all_zero(psk, DIRECTLINK_CHANNEL_SECRET_BYTES);
}

static bool secrets_valid(const struct directlink_channel_secrets *in)
{
    return in && in->handshake &&
           in->handshake_len >= DIRECTLINK_CHANNEL_HANDSHAKE_MIN &&
           in->handshake_len <= DIRECTLINK_CHANNEL_HANDSHAKE_MAX &&
           (in->scope == DIRECTLINK_SCOPE_INTRA_FLEET ||
            in->scope == DIRECTLINK_SCOPE_INTER_FLEET);
}

#define INFO_BYTES (1u + DIRECTLINK_OFFER_SESSION_BYTES + 64u)

/* info = scope (1 byte) || attempt (16) || initiator id (32) || responder id (32) */
static void put_info(const struct directlink_channel_secrets *in,
                     uint8_t info[INFO_BYTES])
{
    info[0] = (uint8_t)in->scope;
    memcpy(info + 1, in->attempt, DIRECTLINK_OFFER_SESSION_BYTES);
    memcpy(info + 1 + DIRECTLINK_OFFER_SESSION_BYTES, in->initiator_id, 32);
    memcpy(info + 1 + DIRECTLINK_OFFER_SESSION_BYTES + 32, in->responder_id, 32);
}

static bool expand(const char *label, size_t label_len, const uint8_t *ikm,
                   size_t ikm_len, const uint8_t info[INFO_BYTES],
                   uint8_t out[32])
{
    return hkdf_sha3_256((const uint8_t *)label, label_len, ikm, ikm_len, info,
                         INFO_BYTES, out, 32);
}

enum directlink_channel_status directlink_channel_derive(
    const struct directlink_channel_secrets *in,
    struct directlink_channel_keys *out)
{
    if (!out || !secrets_valid(in))
        return DIRECTLINK_CHANNEL_ARGUMENT;
    if (all_zero(in->handshake, in->handshake_len))
        return DIRECTLINK_CHANNEL_SECRET_USED;
    if (in->scope == DIRECTLINK_SCOPE_INTRA_FLEET && psk_is_none(in->psk))
        return DIRECTLINK_CHANNEL_NO_PSK;
    uint8_t info[INFO_BYTES];
    put_info(in, info);
    /* The pairing secret is hashed with the attempt id first, so a channel
     * key never exposes it and two attempts see unrelated contributions. */
    uint8_t ikm[DIRECTLINK_CHANNEL_HANDSHAKE_MAX + 32];
    memcpy(ikm, in->handshake, in->handshake_len);
    bool ok = hkdf_sha3_256((const uint8_t *)LABEL_PSK, sizeof LABEL_PSK - 1,
                            in->psk, sizeof in->psk, in->attempt,
                            sizeof in->attempt, ikm + in->handshake_len, 32);
    size_t ikm_len = in->handshake_len + 32;
    ok = ok && expand(LABEL_CHANNEL, sizeof LABEL_CHANNEL - 1, ikm, ikm_len,
                      info, out->material);
    ok = ok && expand(LABEL_PROBE, sizeof LABEL_PROBE - 1, ikm, ikm_len, info,
                      out->probe_key);
    memory_cleanse(ikm, sizeof ikm);
    if (!ok)
        memory_cleanse(out, sizeof *out);
    return ok ? DIRECTLINK_CHANNEL_OK : DIRECTLINK_CHANNEL_DERIVE;
}

/* ── clock and addresses ─────────────────────────────────────────────── */

static int64_t now_ms(const struct directlink_channel *ch)
{
    int64_t ns = ch->clock && ch->clock->now_monotonic_ns
                     ? ch->clock->now_monotonic_ns(ch->clock->self)
                     : clock_now_monotonic_ns();
    return ns / INT64_C(1000000);
}

static bool addr_v4(const struct directlink_addr *a, uint8_t ip[4])
{
    if (a->family != DIRECTLINK_V4)
        return false;
    memcpy(ip, a->ip, 4);
    return true;
}

static bool punch_send(void *ctx, const struct directlink_addr *to,
                       const uint8_t *bytes, size_t len)
{
    const struct directlink_channel *ch = ctx;
    uint8_t ip[4];
    return addr_v4(to, ip) &&
           ch->net.send(ch->net.ctx, ip, to->port, bytes, len) ==
               (int)len;
}

static int64_t punch_now(void *ctx)
{
    return now_ms(ctx);
}

/* The seam the session sees: sends go to the caller's network, receives
 * return the one datagram the channel has already vetted. */
static int link_send(void *ctx, const uint8_t addr[4], uint16_t port,
                     const void *data, size_t len)
{
    const struct directlink_channel *ch = ctx;
    return ch->net.send(ch->net.ctx, addr, port, data, len);
}

static int link_recv(void *ctx, void *data, size_t cap, uint8_t addr[4],
                     uint16_t *port)
{
    struct directlink_channel *ch = ctx;
    if (ch->pending_len == 0 || ch->pending_len > cap)
        return 0;
    size_t len = ch->pending_len;
    memcpy(data, ch->pending, len);
    memcpy(addr, ch->pending_from.ip, 4);
    *port = ch->pending_from.port;
    ch->pending_len = 0;
    return (int)len;
}

/* ── frames ──────────────────────────────────────────────────────────── */

static void send_frame(struct directlink_channel *ch, uint8_t frame)
{
    if (gamelink_send(&ch->link, &frame, 1, NULL) == GAMELINK_OK)
        ch->stats.confirms_sent++;
}

static void send_confirm(struct directlink_channel *ch)
{
    send_frame(ch, ch->initiator ? FRAME_CONFIRM_INITIATOR
                                 : FRAME_CONFIRM_RESPONDER);
}

/* A confirm from the peer proves its datagrams reach us: open, and answer
 * with an ack, which is never answered, so the exchange cannot loop. An ack
 * proves the peer received our confirm. */
static void on_confirm(struct directlink_channel *ch, uint8_t frame)
{
    uint8_t confirm = ch->initiator ? FRAME_CONFIRM_RESPONDER
                                    : FRAME_CONFIRM_INITIATOR;
    uint8_t ack = ch->initiator ? FRAME_ACK_RESPONDER : FRAME_ACK_INITIATOR;
    if ((frame != confirm && frame != ack) ||
        (ch->state != DIRECTLINK_CHANNEL_CONFIRMING &&
         ch->state != DIRECTLINK_CHANNEL_OPEN))
        return;
    if (ch->state == DIRECTLINK_CHANNEL_CONFIRMING) {
        ch->last_rx_ms = now_ms(ch);
        ch->seen_recv = ch->link.stats.recv;
    }
    ch->state = DIRECTLINK_CHANNEL_OPEN;
    if (frame == confirm)
        send_frame(ch, ch->initiator ? FRAME_ACK_INITIATOR
                                     : FRAME_ACK_RESPONDER);
}

static void on_frame(void *user, uint64_t seq, const uint8_t *payload,
                     size_t len)
{
    struct directlink_channel *ch = user;
    (void)seq;
    if (len == 0)
        return;
    if (len == 1 && (payload[0] & 1u)) {
        on_confirm(ch, payload[0]);
    } else if (payload[0] == FRAME_DATA && ch->state == DIRECTLINK_CHANNEL_OPEN) {
        ch->stats.delivered++;
        if (ch->deliver)
            ch->deliver(ch->deliver_user, payload + 1, len - 1);
    } else if (payload[0] == FRAME_DATA) {
        ch->stats.dropped_unconfirmed++;
    }
}

/* ── retiring ────────────────────────────────────────────────────────── */

/* End the channel in `state` and destroy every key it still holds. */
static void retire(struct directlink_channel *ch,
                   enum directlink_channel_state state)
{
    if (ch->link.open)
        gamelink_close(&ch->link);
    memory_cleanse(ch->material, sizeof ch->material);
    memory_cleanse(ch->punch.cfg.key, sizeof ch->punch.cfg.key);
    ch->state = state;
}

/* ── open ────────────────────────────────────────────────────────────── */

static void init_common(struct directlink_channel *ch,
                        const struct directlink_channel_config *cfg,
                        const struct directlink_channel_keys *keys)
{
    ch->initiator = cfg->initiator;
    memcpy(ch->attempt, cfg->secrets.attempt, sizeof ch->attempt);
    memcpy(ch->material, keys->material, sizeof ch->material);
    ch->net = cfg->net;
    ch->clock = cfg->clock;
    ch->confirm_interval_ms = cfg->confirm_interval_ms > 0
                                  ? cfg->confirm_interval_ms
                                  : DIRECTLINK_CHANNEL_DEFAULT_CONFIRM_INTERVAL_MS;
    ch->confirm_timeout_ms = cfg->confirm_timeout_ms > 0
                                 ? cfg->confirm_timeout_ms
                                 : DIRECTLINK_CHANNEL_DEFAULT_CONFIRM_TIMEOUT_MS;
    ch->keepalive_ms = cfg->keepalive_ms > 0
                           ? cfg->keepalive_ms
                           : DIRECTLINK_PUNCH_DEFAULT_KEEPALIVE_MS;
}

/* Open the sealed session toward `working` and begin confirming it. The
 * channel material is destroyed as soon as the session holds its own keys. */
static enum directlink_channel_status begin_confirm(
    struct directlink_channel *ch, const struct directlink_addr *working)
{
    uint8_t ip[4];
    if (!addr_v4(working, ip) || working->port == 0)
        return DIRECTLINK_CHANNEL_ARGUMENT;
    struct gamelink_ops seam = {.send = link_send, .recv = link_recv, .ctx = ch};
    enum gamelink_status opened = gamelink_open_ops(
        &ch->link, ch->material, sizeof ch->material, ch->initiator, ip,
        working->port, &seam, ch->clock);
    memory_cleanse(ch->material, sizeof ch->material);
    if (opened != GAMELINK_OK)
        return DIRECTLINK_CHANNEL_LINK;
    int64_t now = now_ms(ch);
    ch->working = *working;
    ch->state = DIRECTLINK_CHANNEL_CONFIRMING;
    ch->confirm_deadline_ms = now + ch->confirm_timeout_ms;
    ch->next_confirm_ms = now + ch->confirm_interval_ms;
    ch->next_keepalive_ms = now + ch->keepalive_ms;
    send_confirm(ch);
    return DIRECTLINK_CHANNEL_OK;
}

/* The same classification the punch layer applies: invalid and reserved
 * addresses never; private only inside one owner's fleet; loopback only when
 * the caller says the transport sits below the NAT layer. */
static bool working_allowed(const struct directlink_channel_config *cfg,
                            const struct directlink_addr *addr)
{
    switch (directlink_addr_classify(addr)) {
    case DIRECTLINK_ADDR_PUBLIC: return true;
    case DIRECTLINK_ADDR_PRIVATE:
        return cfg->secrets.scope == DIRECTLINK_SCOPE_INTRA_FLEET;
    case DIRECTLINK_ADDR_LOOPBACK: return cfg->allow_loopback;
    default: return false;
    }
}

/* Reset `ch` to CLOSED, derive, and copy the keys in. */
static enum directlink_channel_status prepare(
    struct directlink_channel *ch, const struct directlink_channel_config *cfg,
    struct directlink_channel_keys *keys)
{
    memset(keys, 0, sizeof *keys);
    memset(ch, 0, sizeof *ch);
    ch->link.socket = -1;
    ch->state = DIRECTLINK_CHANNEL_CLOSED;
    if (!cfg || !cfg->net.send || !cfg->net.recv)
        return DIRECTLINK_CHANNEL_ARGUMENT;
    enum directlink_channel_status status =
        directlink_channel_derive(&cfg->secrets, keys);
    if (status == DIRECTLINK_CHANNEL_OK)
        init_common(ch, cfg, keys);
    return status;
}

/* Destroy the caller's copy of the handshake and pairing secrets. */
static void consume(struct directlink_channel_config *cfg)
{
    if (!cfg)
        return;
    memory_cleanse(cfg->secrets.psk, sizeof cfg->secrets.psk);
    if (cfg->secrets.handshake &&
        cfg->secrets.handshake_len <= DIRECTLINK_CHANNEL_HANDSHAKE_MAX)
        memory_cleanse(cfg->secrets.handshake, cfg->secrets.handshake_len);
}

static enum directlink_channel_status open_at_impl(
    struct directlink_channel *ch, const struct directlink_channel_config *cfg,
    const struct directlink_addr *working)
{
    struct directlink_channel_keys keys;
    if (!working)
        return DIRECTLINK_CHANNEL_ARGUMENT;
    enum directlink_channel_status status = prepare(ch, cfg, &keys);
    memory_cleanse(&keys, sizeof keys);
    if (status != DIRECTLINK_CHANNEL_OK)
        return status;
    status = working_allowed(cfg, working) ? begin_confirm(ch, working)
                                           : DIRECTLINK_CHANNEL_ADDRESS;
    if (status != DIRECTLINK_CHANNEL_OK)
        retire(ch, DIRECTLINK_CHANNEL_CLOSED);
    return status;
}

enum directlink_channel_status directlink_channel_open_at(
    struct directlink_channel *ch, struct directlink_channel_config *cfg,
    const struct directlink_addr *working)
{
    enum directlink_channel_status status =
        ch ? open_at_impl(ch, cfg, working) : DIRECTLINK_CHANNEL_ARGUMENT;
    consume(cfg);
    return status;
}

static bool punch_arm(struct directlink_channel *ch,
                      const struct directlink_channel_config *cfg,
                      const struct directlink_channel_keys *keys)
{
    struct directlink_punch_config pc;
    memset(&pc, 0, sizeof pc);
    memcpy(pc.session_id, cfg->secrets.attempt, sizeof pc.session_id);
    memcpy(pc.key, keys->probe_key, sizeof pc.key);
    pc.initiator = cfg->initiator;
    if (cfg->remote_count > DIRECTLINK_OFFER_CANDIDATES_MAX)
        return false;
    pc.remote_count = cfg->remote_count;
    for (size_t i = 0; i < cfg->remote_count; i++)
        pc.remote[i] = cfg->remote[i];
    pc.interval_ms = cfg->punch_interval_ms;
    pc.max_rounds = cfg->punch_rounds;
    pc.keepalive_ms = cfg->keepalive_ms;
    pc.allow_internal = cfg->secrets.scope == DIRECTLINK_SCOPE_INTRA_FLEET;
    struct directlink_punch_ops ops = {
        .send = punch_send, .now_ms = punch_now, .ctx = ch};
    bool armed = directlink_punch_start(&ch->punch, &ops, &pc);
    memory_cleanse(pc.key, sizeof pc.key);
    return armed;
}

static enum directlink_channel_status open_impl(
    struct directlink_channel *ch, const struct directlink_channel_config *cfg)
{
    struct directlink_channel_keys keys;
    enum directlink_channel_status status = prepare(ch, cfg, &keys);
    if (status == DIRECTLINK_CHANNEL_OK) {
        ch->state = DIRECTLINK_CHANNEL_PUNCHING;
        if (!punch_arm(ch, cfg, &keys))
            status = DIRECTLINK_CHANNEL_PUNCH;
    }
    memory_cleanse(&keys, sizeof keys);
    if (status != DIRECTLINK_CHANNEL_OK)
        retire(ch, DIRECTLINK_CHANNEL_CLOSED);
    return status;
}

enum directlink_channel_status directlink_channel_open(
    struct directlink_channel *ch, struct directlink_channel_config *cfg)
{
    enum directlink_channel_status status =
        ch ? open_impl(ch, cfg) : DIRECTLINK_CHANNEL_ARGUMENT;
    consume(cfg);
    return status;
}

/* ── poll ────────────────────────────────────────────────────────────── */

static void settle_punch(struct directlink_channel *ch)
{
    if (ch->state != DIRECTLINK_CHANNEL_PUNCHING)
        return;
    struct directlink_addr working;
    if (directlink_punch_result(&ch->punch, &working)) {
        if (begin_confirm(ch, &working) != DIRECTLINK_CHANNEL_OK)
            retire(ch, DIRECTLINK_CHANNEL_FALLBACK);
    } else if (ch->punch.state == DIRECTLINK_PUNCH_FAILED) {
        retire(ch, DIRECTLINK_CHANNEL_FALLBACK);
    }
}

static void settle_confirm(struct directlink_channel *ch, int64_t now)
{
    if (ch->state != DIRECTLINK_CHANNEL_CONFIRMING)
        return;
    if (now >= ch->confirm_deadline_ms) {
        retire(ch, DIRECTLINK_CHANNEL_FALLBACK);
    } else if (now >= ch->next_confirm_ms) {
        send_confirm(ch);
        ch->next_confirm_ms = now + ch->confirm_interval_ms;
    }
}

/* Keepalive and liveness. Both ends ping every keepalive interval, so any
 * authenticated datagram counts as proof of life. After
 * DIRECTLINK_CHANNEL_DEAD_INTERVALS intervals without one the path is
 * declared dead and the channel falls back. */
static void keepalive(struct directlink_channel *ch, int64_t now)
{
    if (ch->state != DIRECTLINK_CHANNEL_OPEN)
        return;
    if (ch->link.stats.recv != ch->seen_recv) {
        ch->seen_recv = ch->link.stats.recv;
        ch->last_rx_ms = now;
    } else if (now - ch->last_rx_ms >
               (int64_t)DIRECTLINK_CHANNEL_DEAD_INTERVALS * ch->keepalive_ms) {
        ch->stats.path_lost++;
        retire(ch, DIRECTLINK_CHANNEL_FALLBACK);
        return;
    }
    if (now >= ch->next_keepalive_ms) {
        (void)gamelink_ping(&ch->link);
        ch->next_keepalive_ms = now + ch->keepalive_ms;
    }
}

static bool is_probe(const uint8_t *bytes, size_t len)
{
    return len == DIRECTLINK_PROBE_BYTES && bytes[0] == 'Z' &&
           bytes[1] == 'D' && bytes[2] == 'P';
}

static void dispatch(struct directlink_channel *ch,
                     const struct directlink_addr *from, const uint8_t *bytes,
                     size_t len)
{
    if (is_probe(bytes, len)) {
        directlink_punch_on_datagram(&ch->punch, from, bytes, len);
        return;
    }
    if (ch->state != DIRECTLINK_CHANNEL_CONFIRMING &&
        ch->state != DIRECTLINK_CHANNEL_OPEN) {
        ch->stats.dropped_early++;
        return;
    }
    if (!directlink_addr_equal(from, &ch->working)) {
        ch->stats.dropped_source++;
        return;
    }
    if (len > sizeof ch->pending) {
        ch->stats.dropped_early++;
        return;
    }
    memcpy(ch->pending, bytes, len);
    ch->pending_len = len;
    ch->pending_from = *from;
    (void)gamelink_poll(&ch->link, on_frame, ch);
    ch->pending_len = 0;
}

static void drain(struct directlink_channel *ch)
{
    for (unsigned i = 0; i < 256u; i++) {
        uint8_t buffer[GAMELINK_MAX_DATAGRAM];
        struct directlink_addr from;
        uint8_t ip[4];
        uint16_t port = 0;
        int n = ch->net.recv(ch->net.ctx, buffer, sizeof buffer, ip, &port);
        if (n <= 0)
            return;
        if ((size_t)n > sizeof buffer) { /* the seam over-reported */
            ch->stats.dropped_early++;
            continue;
        }
        memset(&from, 0, sizeof from);
        from.family = DIRECTLINK_V4;
        memcpy(from.ip, ip, 4);
        from.port = port;
        dispatch(ch, &from, buffer, (size_t)n);
        settle_punch(ch);
    }
}

size_t directlink_channel_poll(struct directlink_channel *ch,
                               directlink_channel_recv_fn fn, void *user)
{
    if (!ch || (ch->state != DIRECTLINK_CHANNEL_PUNCHING &&
                ch->state != DIRECTLINK_CHANNEL_CONFIRMING &&
                ch->state != DIRECTLINK_CHANNEL_OPEN))
        return 0;
    ch->deliver = fn;
    ch->deliver_user = user;
    uint32_t before = ch->stats.delivered;
    if (ch->state == DIRECTLINK_CHANNEL_PUNCHING)
        directlink_punch_tick(&ch->punch);
    settle_punch(ch);
    drain(ch);
    int64_t now = now_ms(ch);
    settle_confirm(ch, now);
    keepalive(ch, now);
    ch->deliver = NULL;
    ch->deliver_user = NULL;
    return ch->stats.delivered - before;
}

/* ── send, state, close ──────────────────────────────────────────────── */

enum directlink_channel_status directlink_channel_send(
    struct directlink_channel *ch, const uint8_t *payload, size_t len)
{
    if (!ch || (!payload && len > 0))
        return DIRECTLINK_CHANNEL_ARGUMENT;
    if (ch->state != DIRECTLINK_CHANNEL_OPEN)
        return DIRECTLINK_CHANNEL_NOT_OPEN;
    if (len > DIRECTLINK_CHANNEL_MAX_PAYLOAD)
        return DIRECTLINK_CHANNEL_TOO_LARGE;
    if (ch->link.send_seq >= DIRECTLINK_CHANNEL_REKEY_DATAGRAMS)
        return DIRECTLINK_CHANNEL_REKEY;
    uint8_t frame[GAMELINK_MAX_PAYLOAD];
    frame[0] = FRAME_DATA;
    if (len > 0)
        memcpy(frame + 1, payload, len);
    return gamelink_send(&ch->link, frame, len + 1, NULL) == GAMELINK_OK
               ? DIRECTLINK_CHANNEL_OK
               : DIRECTLINK_CHANNEL_SEND_FAILED;
}

enum directlink_channel_state directlink_channel_state(
    const struct directlink_channel *ch)
{
    return ch ? ch->state : DIRECTLINK_CHANNEL_CLOSED;
}

void directlink_channel_close(struct directlink_channel *ch)
{
    if (ch)
        retire(ch, DIRECTLINK_CHANNEL_CLOSED);
}
