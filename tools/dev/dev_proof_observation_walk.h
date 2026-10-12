/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: Verified read-only walk of one signed-observation CAS.
 *
 * The observation CAS layout is owned by vcs_object.c (the write
 * authority); this walk is its one reader. This translation unit is kept
 * free of vcs_object calls so the pre-push hook can link it: the hook
 * verifies coverage manifests against a pair store on every push and must
 * not drag the writable-object machinery into its no-build binary. */

#ifndef ZCL_DEV_PROOF_OBSERVATION_WALK_H
#define ZCL_DEV_PROOF_OBSERVATION_WALK_H

#include "dev_proof_receipt.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* A complete, verified enumeration of one observation CAS. Every listed
 * object must load, re-derive to its address, and parse as a leaf; one
 * corrupt object makes the whole projection incomplete, exactly like a
 * missing chunk in a receiver index. Signature eligibility is decided per
 * leaf but does not affect completeness. An absent store is not an error:
 * *present_out is false and the projection is empty. The returned array is
 * heap-allocated; release it with zcl_dev_observation_release(). */
struct zcl_dev_observation_leaf {
    uint8_t root[ZCL_DEV_PROOF_ROOT_BYTES];
    struct zcl_dev_verdict_leaf_v1 leaf;
    bool eligible;
};
bool zcl_dev_observation_enumerate(const char *store_root,
    struct zcl_dev_observation_leaf **leaves_out, size_t *count_out,
    bool *present_out, char *why, size_t why_len);
void zcl_dev_observation_release(struct zcl_dev_observation_leaf *leaves);
bool zcl_dev_observation_group_matches(const struct zcl_dev_verdict_leaf_v1 *leaf,
    uint8_t group_len, const char *group);

#endif
