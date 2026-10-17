/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Chain-bound short-lived ZID delegation for the ZCODE DHT. */

#ifndef ZCL_VCS_ZCODE_DHT_DELEGATION_H
#define ZCL_VCS_ZCODE_DHT_DELEGATION_H

#include "zid/zid.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define VCS_ZCODE_DHT_DELEGATION_TAG "ZIDN"
#define VCS_ZCODE_DHT_DELEGATION_BODY_BYTES 144u
#define VCS_ZCODE_DHT_DELEGATION_WIRE_BYTES \
    (1u + 32u + 8u + 8u + 2u + VCS_ZCODE_DHT_DELEGATION_BODY_BYTES + 64u)
#define VCS_ZCODE_DHT_DELEGATION_DEFAULT_SECONDS UINT64_C(259200)

/* Roster mode (codec only; no verify path accepts it yet). The chain form
 * above is frozen byte-for-byte. The roster body is distinct: it begins with
 * the roster signing domain string instead of "ZIDN", is a different length
 * (139 vs 144 bytes), and carries an explicit mode byte, so the chain parser
 * refuses it (tag and length) and a roster signature never covers a chain
 * body or vice versa (zid_doc signs the whole body). It carries NO beacon
 * field. Body: DOMAIN(34) mode(1) genesis(32) online(32) noise(32)
 * not_before u64 LE(8). */
#define VCS_ZCODE_DHT_DELEGATION_ROSTER_DOMAIN \
    "z23-zcode-dht-delegation-roster-v1"
#define VCS_ZCODE_DHT_DELEGATION_MODE_CHAIN 0u
#define VCS_ZCODE_DHT_DELEGATION_MODE_ROSTER 1u
#define VCS_ZCODE_DHT_DELEGATION_ROSTER_BODY_BYTES 139u
#define VCS_ZCODE_DHT_DELEGATION_ROSTER_WIRE_BYTES \
    (1u + 32u + 8u + 8u + 2u + VCS_ZCODE_DHT_DELEGATION_ROSTER_BODY_BYTES + 64u)
/* Roster validity: expiry - not_before must be > 0 and <= 7 days. The renew
 * window default stays VCS_ZCODE_DHT_DELEGATION_DEFAULT_SECONDS (3 days). */
#define VCS_ZCODE_DHT_DELEGATION_ROSTER_MAX_SECONDS UINT64_C(604800)

struct vcs_zcode_dht_delegation {
    struct zid_doc doc;
    uint8_t network_genesis[32];
    uint8_t online_pubkey[32];
    uint8_t noise_static_pubkey[32];
    uint32_t beacon_height;
    uint8_t beacon_hash[32];
    uint64_t not_before;
    /* VCS_ZCODE_DHT_DELEGATION_MODE_*; zero (chain) for every chain codec
     * path. Set only by the roster decode and sign. */
    uint8_t mode;
};

enum vcs_zcode_dht_delegation_error {
    VCS_ZCODE_DHT_DELEGATION_OK = 0,
    VCS_ZCODE_DHT_DELEGATION_NULL,
    VCS_ZCODE_DHT_DELEGATION_SIZE,
    VCS_ZCODE_DHT_DELEGATION_BODY,
    VCS_ZCODE_DHT_DELEGATION_ZERO_KEY,
    VCS_ZCODE_DHT_DELEGATION_WINDOW,
    VCS_ZCODE_DHT_DELEGATION_NOT_YET_VALID,
    VCS_ZCODE_DHT_DELEGATION_SIGNATURE,
    VCS_ZCODE_DHT_DELEGATION_NETWORK,
    VCS_ZCODE_DHT_DELEGATION_NOISE_KEY,
    VCS_ZCODE_DHT_DELEGATION_BEACON,
    /* doc->expiry <= now_unix specifically, distinguished from a bad
     * signature: expiry is expected lifecycle (renew/evict), a signature
     * failure is tampering or corruption. Checked before the signature so
     * a doc that is both expired AND has an unrelated bad body still
     * reports the actionable one. */
    VCS_ZCODE_DHT_DELEGATION_EXPIRED,
    /* A roster-mode delegation reached a chain verify path: refused. */
    VCS_ZCODE_DHT_DELEGATION_ROSTER_MODE,
};

const char *vcs_zcode_dht_delegation_error_string(
    enum vcs_zcode_dht_delegation_error error);

/* Sign canonical zcode_dht_delegation.v1. The enclosing zid_doc contributes
 * master_pubkey, seq, expiry and the master signature. */
enum vcs_zcode_dht_delegation_error vcs_zcode_dht_delegation_sign(
    struct vcs_zcode_dht_delegation *out,
    const uint8_t network_genesis[32],
    const uint8_t online_pubkey[32],
    const uint8_t noise_static_pubkey[32],
    uint32_t beacon_height, const uint8_t beacon_hash[32],
    uint64_t not_before, uint64_t expiry, uint64_t sequence,
    const uint8_t master_seed[32]);

enum vcs_zcode_dht_delegation_error vcs_zcode_dht_delegation_encode(
    const struct vcs_zcode_dht_delegation *delegation,
    uint8_t out[VCS_ZCODE_DHT_DELEGATION_WIRE_BYTES]);

enum vcs_zcode_dht_delegation_error vcs_zcode_dht_delegation_decode(
    struct vcs_zcode_dht_delegation *out, const uint8_t *wire,
    size_t wire_len);

/* Cryptographic and structural verification. Chain projection checks remain
 * a caller obligation: the caller must additionally require doc.master_pubkey
 * ACTIVE and beacon_height/hash equal to the selected active chain. Optional
 * expected values are checked when non-NULL/non-zero. */
enum vcs_zcode_dht_delegation_error vcs_zcode_dht_delegation_verify(
    const struct vcs_zcode_dht_delegation *delegation,
    const uint8_t expected_genesis[32],
    const uint8_t expected_noise_static[32],
    uint32_t expected_beacon_height,
    const uint8_t expected_beacon_hash[32], uint64_t now_unix);

/* Roster-mode codec. beacon_height/beacon_hash exist only so a caller that
 * supplies any chain-anchored value is refused (BEACON): height must be 0 and
 * beacon_hash NULL or all zero. Validity (not_before, expiry] must be > 0 and
 * <= VCS_ZCODE_DHT_DELEGATION_ROSTER_MAX_SECONDS, else WINDOW. */
enum vcs_zcode_dht_delegation_error vcs_zcode_dht_delegation_roster_sign(
    struct vcs_zcode_dht_delegation *out,
    const uint8_t network_genesis[32],
    const uint8_t online_pubkey[32],
    const uint8_t noise_static_pubkey[32],
    uint32_t beacon_height, const uint8_t *beacon_hash,
    uint64_t not_before, uint64_t expiry, uint64_t sequence,
    const uint8_t master_seed[32]);

enum vcs_zcode_dht_delegation_error vcs_zcode_dht_delegation_roster_encode(
    const struct vcs_zcode_dht_delegation *delegation,
    uint8_t out[VCS_ZCODE_DHT_DELEGATION_ROSTER_WIRE_BYTES]);

enum vcs_zcode_dht_delegation_error vcs_zcode_dht_delegation_roster_decode(
    struct vcs_zcode_dht_delegation *out, const uint8_t *wire,
    size_t wire_len);

/* Structural and signature check of a roster delegation. Pure codec: no
 * production verify path calls it yet; vcs_zcode_dht_delegation_verify
 * refuses roster mode with VCS_ZCODE_DHT_DELEGATION_ROSTER_MODE. */
enum vcs_zcode_dht_delegation_error vcs_zcode_dht_delegation_roster_check(
    const struct vcs_zcode_dht_delegation *delegation,
    const uint8_t expected_genesis[32],
    const uint8_t expected_noise_static[32], uint64_t now_unix);

/* Stable node identity: genesis + active master key + the finality-delayed
 * beacon block (roster mode: genesis + master only). Renewals and online-key
 * rotations leave this unchanged. */
bool vcs_zcode_dht_delegation_node_id(
    uint8_t out[32], const struct vcs_zcode_dht_delegation *delegation);

#endif /* ZCL_VCS_ZCODE_DHT_DELEGATION_H */
