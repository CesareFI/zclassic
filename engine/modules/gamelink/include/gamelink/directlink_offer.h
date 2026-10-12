/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * directlink punch-coordination message ("offer") and its replay cache.
 *
 * AUTHENTICATION. An offer has no signature, MAC or key of its own. It is
 * only ever carried inside the already-authenticated paired stream
 * (engine/composition/src/mesh_stream.c over the Noise session), and the
 * stream's peer identity is the only authority for who sent it. For that
 * reason both entry points take the authenticated peer identity as a required
 * argument and refuse a missing or all-zero identity. Bytes that did not
 * arrive on an authenticated paired stream must never be passed to the
 * decoder.
 *
 * POLICY. The encoder evaluates the link policy for the destination peer
 * first. When the policy refuses it returns DIRECTLINK_ERR_POLICY with the
 * named reason, writes no byte and reports length 0. The decoder applies the
 * same policy to the sender before it parses anything.
 *
 * CANDIDATES. Private and loopback candidates are admitted only when the
 * peer's scope is intra_fleet. Unspecified, multicast and reserved addresses
 * and port 0 are never admitted. The encoder drops candidates the scope does
 * not allow; the decoder rejects the message when any candidate is not
 * allowed, so a peer cannot smuggle an internal address into an inter-fleet
 * exchange.
 *
 * Wire format, version 1 (little-endian):
 *
 *   0   version         u8   1
 *   1   scope           u8   0 = intra_fleet, 1 = inter_fleet; must equal
 *                            the scope of the authenticated peer
 *   2   session_id      16 bytes, random
 *   18  nonce           u64
 *   26  ttl_ms          u32  1..DIRECTLINK_OFFER_TTL_MAX_MS: how long after
 *                            receipt the offer may still be used
 *   30  start_delay_ms  u32  0..DIRECTLINK_OFFER_DELAY_MAX_MS and below
 *                            ttl_ms: probing starts this long after receipt
 *   34  count           u8   1..DIRECTLINK_OFFER_CANDIDATES_MAX
 *   35  count x { kind u8 (1 host, 2 reflexive, 3 mapped),
 *                 family u8, port u16, ip 4|16 bytes }
 *
 * No shared clock is assumed: ttl and start delay are durations measured from
 * the receiver's own receipt time.
 */

#ifndef ZCL_GAMELINK_DIRECTLINK_OFFER_H
#define ZCL_GAMELINK_DIRECTLINK_OFFER_H

#include "gamelink/directlink_addr.h"
#include "gamelink/directlink_policy.h"

#include <stddef.h>
#include <stdint.h>

#define DIRECTLINK_OFFER_VERSION 1u
#define DIRECTLINK_OFFER_CANDIDATES_MAX 8u
#define DIRECTLINK_OFFER_SESSION_BYTES 16u
#define DIRECTLINK_OFFER_TTL_MAX_MS 30000u
#define DIRECTLINK_OFFER_DELAY_MAX_MS 10000u
#define DIRECTLINK_OFFER_MAX_BYTES \
    (35u + DIRECTLINK_OFFER_CANDIDATES_MAX * 20u)

enum directlink_candidate_kind {
    DIRECTLINK_CANDIDATE_HOST = 1,
    DIRECTLINK_CANDIDATE_REFLEXIVE = 2,
    DIRECTLINK_CANDIDATE_MAPPED = 3
};

struct directlink_candidate {
    enum directlink_candidate_kind kind;
    struct directlink_addr addr; /* UDP */
};

struct directlink_offer {
    enum directlink_scope scope;
    uint8_t session_id[DIRECTLINK_OFFER_SESSION_BYTES];
    uint64_t nonce;
    uint32_t ttl_ms;
    uint32_t start_delay_ms;
    uint8_t candidate_count;
    struct directlink_candidate candidate[DIRECTLINK_OFFER_CANDIDATES_MAX];
};

/* Encode `offer` for `peer` (the destination). `offer->scope` is ignored: the
 * peer's scope is written. On any failure `*out_len` is 0 and `out` is
 * untouched. `*reason` (may be NULL) receives the policy refusal. */
enum directlink_status directlink_offer_encode(
    const struct directlink_policy *policy, const struct directlink_peer *peer,
    const struct directlink_offer *offer, uint8_t *out, size_t cap,
    size_t *out_len, enum directlink_refusal *reason);

/* Strict decode of a whole offer received from `peer` (the authenticated
 * sender). `*out` is written only on success. */
enum directlink_status directlink_offer_decode(
    const struct directlink_policy *policy, const struct directlink_peer *peer,
    const uint8_t *in, size_t len, struct directlink_offer *out,
    enum directlink_refusal *reason);

/* ── Replay cache ────────────────────────────────────────────────────── */

/* The cache is what bounds offer-driven probing: each admitted offer may start
 * one punch attempt, so at most DIRECTLINK_REPLAY_PER_PEER attempts per peer
 * and DIRECTLINK_REPLAY_SLOTS in all can start within the retention window.
 *
 * Rules for the code that wires the codec to a stream:
 *   - An offer carries no issue time. The carrying stream must reject its own
 *     replays; this cache only refuses a repeated (peer, session, nonce).
 *   - The probe key and the session id must be unique per punch attempt, never
 *     reused for a later attempt with the same peer.
 *   - A working address reported by the punch machine is only a candidate
 *     path. It must be confirmed by the encrypted session handshake over that
 *     path before any application data uses it.
 *   - The punch deadline must be clamped so it does not outlive the offer
 *     ttl_ms counted from receipt. */

#define DIRECTLINK_REPLAY_SLOTS 64u
#define DIRECTLINK_REPLAY_PER_PEER 8u
#define DIRECTLINK_REPLAY_RETENTION_MS (5 * 60 * 1000)

struct directlink_replay_slot {
    bool used;
    uint8_t peer[32];
    uint8_t session_id[DIRECTLINK_OFFER_SESSION_BYTES];
    uint64_t nonce;
    int64_t expires_ms;
};

struct directlink_replay {
    struct directlink_replay_slot slot[DIRECTLINK_REPLAY_SLOTS];
};

void directlink_replay_init(struct directlink_replay *cache);

/* Record (peer, session, nonce) for DIRECTLINK_REPLAY_RETENTION_MS. Expired
 * entries are reclaimed first. Returns DIRECTLINK_OK when the offer is new,
 * DIRECTLINK_ERR_REPLAY when it was seen and DIRECTLINK_ERR_CACHE_FULL when
 * the peer already holds DIRECTLINK_REPLAY_PER_PEER live entries or every slot
 * is live. The per-peer quota keeps one peer from filling the cache and
 * blocking the others. A full cache refuses rather than evicting, because an
 * evicted entry would let its offer be replayed. */
enum directlink_status directlink_replay_admit(
    struct directlink_replay *cache, const struct directlink_peer *peer,
    const struct directlink_offer *offer, int64_t now_ms);

#endif /* ZCL_GAMELINK_DIRECTLINK_OFFER_H */
