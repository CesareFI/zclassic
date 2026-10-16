/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * authority_projection_pair — PURE contract deciding whether an
 * authority (coins_kv) snapshot and a projection (utxos) snapshot may be
 * compared as the SAME chain state by authority_projection_audit.
 *
 * Each side is sampled twice (before and after the recompute window). The
 * pair is comparable only if both reads succeeded, no overlay is active, no
 * side moved across the window (height, tip hash, generation), the two sides
 * agree on height, and both carry a tip hash that is byte-identical (so an
 * equal-height pair on different branches is never compared).
 *
 * No I/O, no globals, no locks: unit-testable and not wired into any service.
 *
 * LIVE STATUS: AP_PAIR_COMPARABLE is UNREACHABLE live until (OPEN follow-ups)
 *   1. the projection cursor records its block hash in the same transaction
 *      as the mirror sync, and
 *   2. the authority exposes a reorg-bound identity (tip hash for its applied
 *      height).
 * Until both land, live callers can only build has_tip_hash=false identities,
 * so live verdicts are AP_PAIR_BRANCH_UNKNOWN BY DESIGN. */

#ifndef ZCL_SERVICES_AUTHORITY_PROJECTION_PAIR_H
#define ZCL_SERVICES_AUTHORITY_PROJECTION_PAIR_H

#include <stdbool.h>
#include <stdint.h>

struct ap_pair_identity {
    int64_t  applied_height;
    bool     has_tip_hash;
    uint8_t  tip_hash[32];
    uint64_t generation;
    bool     overlay_active;
    bool     read_ok;
};

enum ap_pair_verdict {
    AP_PAIR_COMPARABLE,
    AP_PAIR_READ_ERROR,
    AP_PAIR_OVERLAY_ACTIVE,
    AP_PAIR_HEIGHT_MISMATCH,
    AP_PAIR_BRANCH_UNKNOWN,
    AP_PAIR_BRANCH_MISMATCH,
    AP_PAIR_MOVED
};

/* Stable lower-case name; "unknown" for an out-of-range value. Never NULL. */
const char *ap_pair_verdict_name(enum ap_pair_verdict v);

/* Classify the four samples. First match wins:
 *   any NULL argument or !read_ok          -> READ_ERROR
 *   any overlay_active                     -> OVERLAY_ACTIVE
 *   a side differs before/after (height,
 *     has_tip_hash, tip_hash bytes, gen)   -> MOVED
 *   auth height != proj height             -> HEIGHT_MISMATCH
 *   either side lacks a tip hash           -> BRANCH_UNKNOWN
 *   tip hashes differ                      -> BRANCH_MISMATCH
 *   otherwise                              -> COMPARABLE
 * Pure. */
enum ap_pair_verdict ap_pair_check(const struct ap_pair_identity *auth_before,
                                   const struct ap_pair_identity *proj_before,
                                   const struct ap_pair_identity *auth_after,
                                   const struct ap_pair_identity *proj_after);

#endif /* ZCL_SERVICES_AUTHORITY_PROJECTION_PAIR_H */
