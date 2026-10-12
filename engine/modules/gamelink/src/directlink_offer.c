/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * directlink punch-coordination message codec and replay cache. The wire
 * format, the authentication rule and the candidate rules are stated in
 * gamelink/directlink_offer.h. */

#include "gamelink/directlink_offer.h"

#include "codec/cursor.h"

#include <string.h>

static bool peer_usable(const struct directlink_peer *peer)
{
    static const uint8_t zero[32];
    return peer && memcmp(peer->identity, zero, sizeof zero) != 0;
}

static enum directlink_status policy_gate(
    const struct directlink_policy *policy, const struct directlink_peer *peer,
    enum directlink_refusal *reason)
{
    if (reason)
        *reason = DIRECTLINK_ALLOW;
    if (!policy || !peer_usable(peer))
        return DIRECTLINK_ERR_ARGUMENT;
    enum directlink_refusal verdict = directlink_policy_decide(policy, peer);
    if (reason)
        *reason = verdict;
    return verdict == DIRECTLINK_ALLOW ? DIRECTLINK_OK : DIRECTLINK_ERR_POLICY;
}

#define INTERNAL_ALLOW (DIRECTLINK_ALLOW_PRIVATE | DIRECTLINK_ALLOW_LOOPBACK)

static unsigned scope_allow(enum directlink_scope scope)
{
    return scope == DIRECTLINK_SCOPE_INTRA_FLEET ? INTERNAL_ALLOW
                                                 : DIRECTLINK_ALLOW_PUBLIC_ONLY;
}

static bool kind_valid(uint32_t kind)
{
    return kind >= DIRECTLINK_CANDIDATE_HOST &&
           kind <= DIRECTLINK_CANDIDATE_MAPPED;
}

static bool timing_valid(uint32_t ttl_ms, uint32_t delay_ms)
{
    return ttl_ms >= 1 && ttl_ms <= DIRECTLINK_OFFER_TTL_MAX_MS &&
           delay_ms <= DIRECTLINK_OFFER_DELAY_MAX_MS && delay_ms < ttl_ms;
}

static bool is_internal(const struct directlink_addr *addr)
{
    enum directlink_addr_class cls = directlink_addr_classify(addr);
    return cls == DIRECTLINK_ADDR_PRIVATE || cls == DIRECTLINK_ADDR_LOOPBACK;
}

static bool has_duplicate(const struct directlink_candidate *list, size_t count)
{
    for (size_t i = 0; i < count; i++)
        for (size_t j = i + 1; j < count; j++)
            if (directlink_addr_equal(&list[i].addr, &list[j].addr))
                return true;
    return false;
}

/* Keep the candidates the scope allows. A structurally invalid candidate
 * (unspecified, multicast, port 0, unknown kind) is an error, not a drop. */
static enum directlink_status filter_candidates(
    const struct directlink_offer *offer, bool intra,
    struct directlink_candidate *kept, size_t *kept_count)
{
    *kept_count = 0;
    if (offer->candidate_count == 0 ||
        offer->candidate_count > DIRECTLINK_OFFER_CANDIDATES_MAX ||
        has_duplicate(offer->candidate, offer->candidate_count))
        return DIRECTLINK_ERR_FIELD;
    for (size_t i = 0; i < offer->candidate_count; i++) {
        const struct directlink_candidate *c = &offer->candidate[i];
        if (!kind_valid((uint32_t)c->kind))
            return DIRECTLINK_ERR_FIELD;
        uint8_t scratch[32];
        struct zcl_codec_writer probe;
        zcl_codec_writer_init(&probe, scratch, sizeof scratch);
        enum directlink_status st = directlink_addr_write(&probe, &c->addr, INTERNAL_ALLOW);
        if (st != DIRECTLINK_OK)
            return st == DIRECTLINK_ERR_CAPACITY ? DIRECTLINK_ERR_FIELD : st;
        if (!intra && is_internal(&c->addr))
            continue;
        kept[(*kept_count)++] = *c;
    }
    return *kept_count == 0 ? DIRECTLINK_ERR_ADDRESS : DIRECTLINK_OK;
}

static enum directlink_status write_offer(
    struct zcl_codec_writer *w, const struct directlink_peer *peer,
    const struct directlink_offer *offer, const struct directlink_candidate *kept,
    size_t kept_count)
{
    if (!zcl_codec_write_u8(w, DIRECTLINK_OFFER_VERSION) ||
        !zcl_codec_write_u8(w, (uint8_t)peer->scope) ||
        !zcl_codec_write_bytes(w, offer->session_id, sizeof offer->session_id) ||
        !zcl_codec_write_u64le(w, offer->nonce) ||
        !zcl_codec_write_u32le(w, offer->ttl_ms) ||
        !zcl_codec_write_u32le(w, offer->start_delay_ms) ||
        !zcl_codec_write_u8(w, (uint8_t)kept_count))
        return DIRECTLINK_ERR_CAPACITY;
    for (size_t i = 0; i < kept_count; i++) {
        if (!zcl_codec_write_u8(w, (uint8_t)kept[i].kind))
            return DIRECTLINK_ERR_CAPACITY;
        enum directlink_status st = directlink_addr_write(
            w, &kept[i].addr, scope_allow(peer->scope));
        if (st != DIRECTLINK_OK)
            return st;
    }
    return DIRECTLINK_OK;
}

enum directlink_status directlink_offer_encode(
    const struct directlink_policy *policy, const struct directlink_peer *peer,
    const struct directlink_offer *offer, uint8_t *out, size_t cap,
    size_t *out_len, enum directlink_refusal *reason)
{
    if (out_len)
        *out_len = 0;
    enum directlink_status status = policy_gate(policy, peer, reason);
    if (status != DIRECTLINK_OK)
        return status;
    if (!offer || !out || !out_len)
        return DIRECTLINK_ERR_ARGUMENT;
    if (!timing_valid(offer->ttl_ms, offer->start_delay_ms))
        return DIRECTLINK_ERR_FIELD;
    struct directlink_candidate kept[DIRECTLINK_OFFER_CANDIDATES_MAX];
    size_t kept_count = 0;
    status = filter_candidates(offer, peer->scope == DIRECTLINK_SCOPE_INTRA_FLEET,
                               kept, &kept_count);
    if (status != DIRECTLINK_OK)
        return status;
    uint8_t buf[DIRECTLINK_OFFER_MAX_BYTES];
    struct zcl_codec_writer writer;
    zcl_codec_writer_init(&writer, buf, sizeof buf);
    status = write_offer(&writer, peer, offer, kept, kept_count);
    size_t written = 0;
    if (status != DIRECTLINK_OK)
        return status;
    if (!zcl_codec_writer_finish(&writer, &written) || written > cap)
        return DIRECTLINK_ERR_CAPACITY;
    memcpy(out, buf, written);
    *out_len = written;
    return DIRECTLINK_OK;
}

static enum directlink_status read_header(struct zcl_codec_reader *r,
                                          struct directlink_offer *o,
                                          uint8_t *count)
{
    uint8_t version = 0;
    uint8_t scope = 0;
    if (!zcl_codec_read_u8(r, &version) || !zcl_codec_read_u8(r, &scope) ||
        !zcl_codec_read_bytes(r, o->session_id, sizeof o->session_id) ||
        !zcl_codec_read_u64le(r, &o->nonce) ||
        !zcl_codec_read_u32le(r, &o->ttl_ms) ||
        !zcl_codec_read_u32le(r, &o->start_delay_ms) ||
        !zcl_codec_read_u8(r, count))
        return DIRECTLINK_ERR_TRUNCATED;
    if (version != DIRECTLINK_OFFER_VERSION)
        return DIRECTLINK_ERR_VERSION;
    if (scope >= DIRECTLINK_SCOPE_COUNT)
        return DIRECTLINK_ERR_FIELD;
    o->scope = (enum directlink_scope)scope;
    if (!timing_valid(o->ttl_ms, o->start_delay_ms) || *count == 0 ||
        *count > DIRECTLINK_OFFER_CANDIDATES_MAX)
        return DIRECTLINK_ERR_FIELD;
    return DIRECTLINK_OK;
}

static enum directlink_status read_candidates(struct zcl_codec_reader *r,
                                              struct directlink_offer *o,
                                              uint8_t count, bool intra)
{
    for (uint8_t i = 0; i < count; i++) {
        uint8_t kind = 0;
        if (!zcl_codec_read_u8(r, &kind))
            return DIRECTLINK_ERR_TRUNCATED;
        if (!kind_valid(kind))
            return DIRECTLINK_ERR_FIELD;
        o->candidate[i].kind = (enum directlink_candidate_kind)kind;
        enum directlink_status st =
            directlink_addr_read(r, &o->candidate[i].addr, intra ? INTERNAL_ALLOW : 0u);
        if (st != DIRECTLINK_OK)
            return st;
    }
    o->candidate_count = count;
    return has_duplicate(o->candidate, count) ? DIRECTLINK_ERR_FIELD
                                              : DIRECTLINK_OK;
}

enum directlink_status directlink_offer_decode(
    const struct directlink_policy *policy, const struct directlink_peer *peer,
    const uint8_t *in, size_t len, struct directlink_offer *out,
    enum directlink_refusal *reason)
{
    enum directlink_status status = policy_gate(policy, peer, reason);
    if (status != DIRECTLINK_OK)
        return status;
    if (!in || !out)
        return DIRECTLINK_ERR_ARGUMENT;
    struct directlink_offer tmp;
    memset(&tmp, 0, sizeof tmp);
    struct zcl_codec_reader reader;
    zcl_codec_reader_init(&reader, in, len);
    uint8_t count = 0;
    status = read_header(&reader, &tmp, &count);
    if (status != DIRECTLINK_OK)
        return status;
    if (tmp.scope != peer->scope)
        return DIRECTLINK_ERR_SCOPE;
    status = read_candidates(&reader, &tmp, count,
                             peer->scope == DIRECTLINK_SCOPE_INTRA_FLEET);
    if (status != DIRECTLINK_OK)
        return status;
    if (!zcl_codec_reader_finish(&reader))
        return DIRECTLINK_ERR_TRAILING;
    *out = tmp;
    return DIRECTLINK_OK;
}

/* ── Replay cache ────────────────────────────────────────────────────── */

void directlink_replay_init(struct directlink_replay *cache)
{
    if (cache)
        memset(cache, 0, sizeof *cache);
}

static bool slot_matches(const struct directlink_replay_slot *s,
                         const struct directlink_peer *peer,
                         const struct directlink_offer *offer)
{
    return s->nonce == offer->nonce &&
           memcmp(s->peer, peer->identity, sizeof s->peer) == 0 &&
           memcmp(s->session_id, offer->session_id, sizeof s->session_id) == 0;
}

enum directlink_status directlink_replay_admit(
    struct directlink_replay *cache, const struct directlink_peer *peer,
    const struct directlink_offer *offer, int64_t now_ms)
{
    if (!cache || !peer_usable(peer) || !offer)
        return DIRECTLINK_ERR_ARGUMENT;
    struct directlink_replay_slot *free_slot = NULL;
    unsigned held = 0;
    for (size_t i = 0; i < DIRECTLINK_REPLAY_SLOTS; i++) {
        struct directlink_replay_slot *s = &cache->slot[i];
        if (s->used && now_ms >= s->expires_ms)
            s->used = false;
        if (!s->used) {
            if (!free_slot)
                free_slot = s;
        } else {
            if (slot_matches(s, peer, offer))
                return DIRECTLINK_ERR_REPLAY;
            if (memcmp(s->peer, peer->identity, sizeof s->peer) == 0)
                held++;
        }
    }
    if (!free_slot || held >= DIRECTLINK_REPLAY_PER_PEER)
        return DIRECTLINK_ERR_CACHE_FULL;
    free_slot->used = true;
    memcpy(free_slot->peer, peer->identity, sizeof free_slot->peer);
    memcpy(free_slot->session_id, offer->session_id, sizeof free_slot->session_id);
    free_slot->nonce = offer->nonce;
    free_slot->expires_ms = now_ms + DIRECTLINK_REPLAY_RETENTION_MS;
    return DIRECTLINK_OK;
}
