/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: Box-level receiver index of signed observation leaves.
 *
 * Canonical lifecycle item 3 (docs/work/FORWARD_PLAN.md): reuse of
 * unchanged unit evidence across candidates is permitted "only when its
 * exact input closure and receiver policy permit it". The receiver's half
 * of that contract is a durable, verified, receiver-local basis of
 * observations seen on this box — the index the reuse admission and the
 * coverage queries classify against.
 *
 * Explicit callers merge a pair's durable observation CAS into this index;
 * proof publication does not automatically populate it. Every row is a
 * self-verifying (root, wire) pair:
 * the root re-derives from the wire, so a tampered row is named on read
 * and never silently re-derived. Contradictory and ineligible leaves are
 * preserved, not collapsed: classification time refuses unresolved
 * eligible conflicts, exactly like the per-pair projection.
 *
 * The index is a rebuildable projection, not authority: merge failures are
 * named and reported but never block an already-proven publication. */

#ifndef ZCL_DEV_PROOF_OBSERVATION_INDEX_H
#define ZCL_DEV_PROOF_OBSERVATION_INDEX_H

#include "dev_proof_observation_walk.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Index wire: magic[8] "Z23OIDX\0" || version u32 = 1 || row_count u32 ||
 * reserved[16] = zero || rows sorted by root, each root[32] || leaf wire
 * [ZCL_DEV_VERDICT_LEAF_WIRE_BYTES]. */
#define ZCL_DEV_OBSERVATION_INDEX_WIRE_BYTES 32u
#define ZCL_DEV_OBSERVATION_INDEX_ROW_BYTES \
    (ZCL_DEV_PROOF_ROOT_BYTES + ZCL_DEV_VERDICT_LEAF_WIRE_BYTES)
#define ZCL_DEV_OBSERVATION_INDEX_MAX_ROWS 8192u

#define ZCL_DEV_OBSERVATION_INDEX_WHY_ARGUMENTS "observation_index_arguments"
#define ZCL_DEV_OBSERVATION_INDEX_WHY_INVALID "observation_index_invalid"
#define ZCL_DEV_OBSERVATION_INDEX_WHY_TOO_MANY "observation_index_too_many"

/* Merge every leaf of one per-pair observation CAS into the box index.
 * Read-modify-write under an exclusive lock; existing rows are verified
 * before the union and the result is written atomically. An absent store
 * merges nothing; a nonempty store creates an absent index. Refuses by name on any
 * unverifiable byte; the caller decides whether the refusal is fatal. */
bool zcl_dev_observation_index_merge(const char *index_path,
    const char *store_root, char *why, size_t why_len);

/* Load and verify the index into observation leaves (root re-derived,
 * signature eligibility decided per leaf). An absent index is not an
 * error: *present_out is false and the projection is empty. */
bool zcl_dev_observation_index_load(const char *index_path,
    struct zcl_dev_observation_leaf **leaves_out, size_t *count_out,
    bool *present_out, char *why, size_t why_len);

/* ── Box-level query (the lifecycle query interface) ────────────────────
 * Summarizes what this box has observed: totals, eligibility, the
 * observed age range, and per-(group, key) newest eligible verdicts with
 * preserved-conflict flags. An absent index answers empty; corrupt bytes
 * refuse by name. `group_filter` names one group exactly and scopes
 * every count to it, or NULL sums the whole index. Named groups are
 * sorted by (group, key) for a deterministic reply; `truncated` reports
 * when the cap cut the list. */
#define ZCL_DEV_OBSERVATION_QUERY_MAX_GROUPS 32u
struct zcl_dev_observation_group_summary {
    char group[ZCL_DEV_VERDICT_LEAF_GROUP_BYTES];
    uint8_t group_len;
    uint8_t key[ZCL_DEV_VERDICT_LEAF_KEY_BYTES];
    uint8_t verdict;         /* newest eligible verdict (PASS/FAIL) */
    uint64_t observed_unix;  /* newest eligible observation */
    uint32_t observations;   /* eligible leaves at this exact input key */
    bool conflict;           /* eligible PASS and FAIL both preserved */
};
struct zcl_dev_observation_query_report {
    uint64_t total;
    uint64_t eligible;
    uint64_t ineligible;
    uint64_t oldest_observed_unix; /* 0 when nothing was observed */
    uint64_t newest_observed_unix;
    uint32_t groups_named;
    uint32_t conflicted_groups; /* capped at the aggregation capacity */
    bool truncated;
    struct zcl_dev_observation_group_summary
        groups[ZCL_DEV_OBSERVATION_QUERY_MAX_GROUPS];
};
bool zcl_dev_observation_index_query(const char *index_path,
    const char *group_filter,
    struct zcl_dev_observation_query_report *out, char *why, size_t why_len);

#endif
