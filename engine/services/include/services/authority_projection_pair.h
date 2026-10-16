/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * authority_projection_pair — PURE endpoint-predicate classifier.
 * COMPARABLE means only that the supplied identities satisfy the checks below;
 * it does not prove common capture, snapshot coherence or ABA exclusion.
 * No I/O, globals or locks; this helper is not wired into any service.
 *
 * Caller prerequisites, not established by this function:
 * - read_ok certifies successful reads and valid, available height/generation
 *   fields. Zero generation may be valid, but must not mean unavailable.
 *   Hash presence is represented only by has_tip_hash, not its byte contents.
 * - Both sides use one explicitly agreed frontier convention and hash binding.
 *   This helper chooses neither last-applied versus next-unapplied height nor
 *   the corresponding block. Actual production semantics remain OPEN.
 * - Scanned rows and metadata belong to the claimed pinned snapshots, and
 *   before/after samples bracket the scans.
 * - Each side's generation changes on every relevant mutation, including
 *   reorg/reversal, without reuse or wrap within the observation window.
 *   Generations are side-local and need not equal each other.
 *
 * A hidden A->B->A with identical endpoint identities cannot be detected here.
 * LIVE STATUS: no runtime acceptance is claimed. OPEN producer work includes
 * transactional projection branch identity, authority identity bound to the
 * durable frontier, and the snapshot/generation guarantees above. Missing
 * branch hashes yield BRANCH_UNKNOWN only when no earlier rule wins. */

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
