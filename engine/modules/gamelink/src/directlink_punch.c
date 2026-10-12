/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * directlink punch state machine. The datagram format and the acceptance
 * rules are stated in gamelink/directlink_punch.h. */

#include "gamelink/directlink_punch.h"

#include "codec/cursor.h"
#include "crypto/hmac_sha3.h"
#include "gamelink_internal.h"

#include <string.h>

#define PROBE_VERSION 1u
#define PROBE_TYPE_PROBE 1u
#define PROBE_TYPE_REPLY 2u
#define PROBE_MAC_INPUT_BYTES 26u

static const uint8_t k_probe_magic[3] = {'Z', 'D', 'P'};

const char *directlink_outcome_label(enum directlink_outcome outcome)
{
    switch (outcome) {
    case DIRECTLINK_OUTCOME_PENDING: return "pending";
    case DIRECTLINK_OUTCOME_DIRECT: return "direct";
    case DIRECTLINK_OUTCOME_FALLBACK_TO_ONION: return "fallback_to_onion";
    }
    return "unknown";
}

static void probe_mac(const uint8_t key[32], const uint8_t *msg,
                      uint8_t out[DIRECTLINK_PROBE_MAC_BYTES])
{
    struct hmac_sha3_256_ctx ctx;
    unsigned char full[HMAC_SHA3_256_OUTPUT_SIZE];
    hmac_sha3_256_init(&ctx, key, 32);
    hmac_sha3_256_write(&ctx, msg, PROBE_MAC_INPUT_BYTES);
    hmac_sha3_256_finalize(&ctx, full);
    memcpy(out, full, DIRECTLINK_PROBE_MAC_BYTES);
    memset(full, 0, sizeof full);
}

static bool probe_build(const struct directlink_punch *p, uint8_t type,
                        uint32_t seq, uint8_t out[DIRECTLINK_PROBE_BYTES])
{
    struct zcl_codec_writer w;
    zcl_codec_writer_init(&w, out, DIRECTLINK_PROBE_BYTES);
    if (!zcl_codec_write_bytes(&w, k_probe_magic, sizeof k_probe_magic) ||
        !zcl_codec_write_u8(&w, PROBE_VERSION) || !zcl_codec_write_u8(&w, type) ||
        !zcl_codec_write_u8(&w, p->cfg.initiator ? 1u : 0u) ||
        !zcl_codec_write_bytes(&w, p->cfg.session_id,
                               sizeof p->cfg.session_id) ||
        !zcl_codec_write_u32le(&w, seq))
        return false;
    uint8_t mac[DIRECTLINK_PROBE_MAC_BYTES];
    probe_mac(p->cfg.key, out, mac);
    return zcl_codec_write_bytes(&w, mac, sizeof mac);
}

static void send_datagram(struct directlink_punch *p,
                          const struct directlink_addr *to, uint8_t type,
                          uint32_t seq)
{
    uint8_t wire[DIRECTLINK_PROBE_BYTES];
    if (!probe_build(p, type, seq, wire) ||
        !p->ops.send(p->ops.ctx, to, wire, sizeof wire)) {
        p->stats.send_failures++;
        return;
    }
    if (type == PROBE_TYPE_PROBE)
        p->stats.probes_sent++;
    else
        p->stats.replies_sent++;
}

static bool remote_valid(const struct directlink_punch_config *cfg)
{
    for (size_t i = 0; i < cfg->remote_count; i++) {
        enum directlink_addr_class cls = directlink_addr_classify(&cfg->remote[i]);
        if (cfg->remote[i].port == 0 || cls == DIRECTLINK_ADDR_INVALID)
            return false;
        if (!cfg->allow_internal && cls != DIRECTLINK_ADDR_PUBLIC)
            return false;
    }
    return true;
}

static bool timing_valid(const struct directlink_punch_config *cfg)
{
    if (cfg->start_delay_ms < 0 ||
        cfg->start_delay_ms > (int64_t)DIRECTLINK_OFFER_DELAY_MAX_MS)
        return false;
    if (cfg->interval_ms != 0 &&
        (cfg->interval_ms < DIRECTLINK_PUNCH_INTERVAL_MIN_MS ||
         cfg->interval_ms > DIRECTLINK_PUNCH_INTERVAL_MAX_MS))
        return false;
    if (cfg->max_rounds > DIRECTLINK_PUNCH_ROUNDS_MAX ||
        cfg->reply_grace_ms < 0 ||
        cfg->reply_grace_ms > DIRECTLINK_PUNCH_GRACE_MAX_MS ||
        cfg->keepalive_ms < 0)
        return false;
    return true;
}

static bool config_valid(const struct directlink_punch_ops *ops,
                         const struct directlink_punch_config *cfg)
{
    if (!ops || !cfg || !ops->send || !ops->now_ms || cfg->remote_count == 0 ||
        cfg->remote_count > DIRECTLINK_OFFER_CANDIDATES_MAX)
        return false;
    return timing_valid(cfg) && remote_valid(cfg);
}

static void apply_defaults(struct directlink_punch_config *c)
{
    if (c->interval_ms <= 0)
        c->interval_ms = DIRECTLINK_PUNCH_DEFAULT_INTERVAL_MS;
    if (c->max_rounds == 0)
        c->max_rounds = DIRECTLINK_PUNCH_DEFAULT_ROUNDS;
    if (c->reply_grace_ms <= 0)
        c->reply_grace_ms = DIRECTLINK_PUNCH_DEFAULT_GRACE_MS;
    if (c->keepalive_ms <= 0)
        c->keepalive_ms = DIRECTLINK_PUNCH_DEFAULT_KEEPALIVE_MS;
}

bool directlink_punch_start(struct directlink_punch *punch,
                            const struct directlink_punch_ops *ops,
                            const struct directlink_punch_config *cfg)
{
    if (!punch || !config_valid(ops, cfg))
        return false;
    memset(punch, 0, sizeof *punch);
    punch->ops = *ops;
    punch->cfg = *cfg;
    apply_defaults(&punch->cfg);
    punch->start_at_ms = ops->now_ms(ops->ctx) + punch->cfg.start_delay_ms;
    punch->next_send_ms = punch->start_at_ms;
    punch->deadline_ms = punch->start_at_ms +
                         (int64_t)punch->cfg.max_rounds * punch->cfg.interval_ms +
                         punch->cfg.reply_grace_ms;
    punch->state = DIRECTLINK_PUNCH_WAITING;
    return true;
}

static void send_round(struct directlink_punch *p)
{
    for (size_t i = 0; i < p->cfg.remote_count; i++)
        send_datagram(p, &p->cfg.remote[i], PROBE_TYPE_PROBE, p->next_seq++);
    for (size_t i = 0; i < p->learned_count; i++)
        send_datagram(p, &p->learned[i], PROBE_TYPE_PROBE, p->next_seq++);
    p->round++;
}

void directlink_punch_tick(struct directlink_punch *p)
{
    if (!p || (p->state != DIRECTLINK_PUNCH_WAITING &&
               p->state != DIRECTLINK_PUNCH_PROBING))
        return;
    int64_t now = p->ops.now_ms(p->ops.ctx);
    if (now >= p->deadline_ms) {
        p->state = DIRECTLINK_PUNCH_FAILED;
        p->outcome = DIRECTLINK_OUTCOME_FALLBACK_TO_ONION;
        p->finished_ms = now;
        return;
    }
    if (p->state == DIRECTLINK_PUNCH_WAITING && now >= p->start_at_ms)
        p->state = DIRECTLINK_PUNCH_PROBING;
    if (p->state == DIRECTLINK_PUNCH_PROBING && p->round < p->cfg.max_rounds &&
        now >= p->next_send_ms) {
        send_round(p);
        p->next_send_ms = now + p->cfg.interval_ms;
    }
}

struct probe_view {
    uint8_t type;
    uint32_t seq;
};

/* Parse and authenticate one datagram. On false the matching drop counter has
 * been raised. */
static bool probe_accept(struct directlink_punch *p, const uint8_t *bytes,
                         size_t len, struct probe_view *view)
{
    if (!bytes || len != DIRECTLINK_PROBE_BYTES ||
        !gamelink_ct_equal(bytes, k_probe_magic, sizeof k_probe_magic) ||
        bytes[3] != PROBE_VERSION ||
        (bytes[4] != PROBE_TYPE_PROBE && bytes[4] != PROBE_TYPE_REPLY) ||
        bytes[5] > 1u) {
        p->stats.dropped_malformed++;
        return false;
    }
    if (!gamelink_ct_equal(bytes + 6, p->cfg.session_id,
                           sizeof p->cfg.session_id)) {
        p->stats.dropped_session++;
        return false;
    }
    uint8_t mac[DIRECTLINK_PROBE_MAC_BYTES];
    probe_mac(p->cfg.key, bytes, mac);
    if (!gamelink_ct_equal(mac, bytes + PROBE_MAC_INPUT_BYTES, sizeof mac)) {
        p->stats.dropped_mac++;
        return false;
    }
    if ((bytes[5] == 1u) == p->cfg.initiator) {
        p->stats.dropped_role++;
        return false;
    }
    view->type = bytes[4];
    struct zcl_codec_reader seq_reader;
    zcl_codec_reader_init(&seq_reader, bytes + 22, 4);
    return zcl_codec_read_u32le(&seq_reader, &view->seq);
}

/* Whether a datagram source may be answered and learned under the scope. */
static bool source_allowed(const struct directlink_punch *p,
                           const struct directlink_addr *from)
{
    enum directlink_addr_class cls = directlink_addr_classify(from);
    if (from->port == 0 || cls == DIRECTLINK_ADDR_INVALID)
        return false;
    return cls == DIRECTLINK_ADDR_PUBLIC ||
           (p->cfg.allow_internal && cls == DIRECTLINK_ADDR_PRIVATE);
}

/* A valid probe from an address outside the target lists becomes a target
 * while the punch is still running. Loopback sources are never learned. */
static void learn_source(struct directlink_punch *p,
                         const struct directlink_addr *from)
{
    if ((p->state != DIRECTLINK_PUNCH_WAITING &&
         p->state != DIRECTLINK_PUNCH_PROBING) ||
        p->learned_count >= DIRECTLINK_PUNCH_LEARNED_MAX)
        return;
    for (size_t i = 0; i < p->cfg.remote_count; i++)
        if (directlink_addr_equal(from, &p->cfg.remote[i]))
            return;
    for (size_t i = 0; i < p->learned_count; i++)
        if (directlink_addr_equal(from, &p->learned[i]))
            return;
    p->learned[p->learned_count++] = *from;
    p->stats.learned++;
}

static void accept_reply(struct directlink_punch *p,
                         const struct directlink_addr *from, uint32_t seq)
{
    if (p->state != DIRECTLINK_PUNCH_PROBING || seq >= p->next_seq) {
        p->stats.dropped_unsolicited++;
        return;
    }
    if (!source_allowed(p, from)) {
        p->stats.dropped_source++;
        return;
    }
    p->working = *from;
    p->state = DIRECTLINK_PUNCH_SUCCEEDED;
    p->outcome = DIRECTLINK_OUTCOME_DIRECT;
    p->finished_ms = p->ops.now_ms(p->ops.ctx);
}

static void answer_probe(struct directlink_punch *p,
                         const struct directlink_addr *from, uint32_t seq)
{
    if (!source_allowed(p, from)) {
        p->stats.dropped_source++;
        return;
    }
    if (p->stats.replies_sent >= DIRECTLINK_PUNCH_REPLY_BUDGET) {
        p->stats.dropped_budget++;
        return;
    }
    send_datagram(p, from, PROBE_TYPE_REPLY, seq);
    learn_source(p, from);
}

void directlink_punch_on_datagram(struct directlink_punch *p,
                                  const struct directlink_addr *from,
                                  const uint8_t *bytes, size_t len)
{
    if (!p || !from || (p->state != DIRECTLINK_PUNCH_PROBING &&
                        p->state != DIRECTLINK_PUNCH_WAITING &&
                        p->state != DIRECTLINK_PUNCH_SUCCEEDED))
        return;
    struct probe_view view;
    if (!probe_accept(p, bytes, len, &view))
        return;
    if (view.type == PROBE_TYPE_PROBE)
        answer_probe(p, from, view.seq);
    else
        accept_reply(p, from, view.seq);
}

bool directlink_punch_result(const struct directlink_punch *p,
                             struct directlink_addr *remote)
{
    if (!p || !remote || p->outcome != DIRECTLINK_OUTCOME_DIRECT)
        return false;
    *remote = p->working;
    return true;
}

int64_t directlink_punch_keepalive_ms(const struct directlink_punch *p)
{
    return p ? p->cfg.keepalive_ms : 0;
}
