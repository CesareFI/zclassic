/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * authority_projection_pair — see services/authority_projection_pair.h.
 * Pure: no I/O, no globals. */

#include "services/authority_projection_pair.h"

#include <stddef.h>
#include <string.h>

const char *ap_pair_verdict_name(enum ap_pair_verdict v)
{
    switch (v) {
    case AP_PAIR_COMPARABLE:      return "comparable";
    case AP_PAIR_READ_ERROR:      return "read_error";
    case AP_PAIR_OVERLAY_ACTIVE:  return "overlay_active";
    case AP_PAIR_HEIGHT_MISMATCH: return "height_mismatch";
    case AP_PAIR_BRANCH_UNKNOWN:  return "branch_unknown";
    case AP_PAIR_BRANCH_MISMATCH: return "branch_mismatch";
    case AP_PAIR_MOVED:           return "moved";
    }
    return "unknown";
}

static bool ap_pair_same_identity(const struct ap_pair_identity *a,
                                  const struct ap_pair_identity *b)
{
    if (a->applied_height != b->applied_height ||
        a->generation != b->generation ||
        a->has_tip_hash != b->has_tip_hash)
        return false;
    return !a->has_tip_hash ||
           memcmp(a->tip_hash, b->tip_hash, sizeof a->tip_hash) == 0;
}

enum ap_pair_verdict ap_pair_check(const struct ap_pair_identity *auth_before,
                                   const struct ap_pair_identity *proj_before,
                                   const struct ap_pair_identity *auth_after,
                                   const struct ap_pair_identity *proj_after)
{
    const struct ap_pair_identity *all[4] = {
        auth_before, proj_before, auth_after, proj_after
    };
    for (size_t i = 0; i < 4; i++)
        if (all[i] == NULL || !all[i]->read_ok)
            return AP_PAIR_READ_ERROR;
    for (size_t i = 0; i < 4; i++)
        if (all[i]->overlay_active)
            return AP_PAIR_OVERLAY_ACTIVE;
    if (!ap_pair_same_identity(auth_before, auth_after) ||
        !ap_pair_same_identity(proj_before, proj_after))
        return AP_PAIR_MOVED;
    if (auth_before->applied_height != proj_before->applied_height)
        return AP_PAIR_HEIGHT_MISMATCH;
    if (!auth_before->has_tip_hash || !proj_before->has_tip_hash)
        return AP_PAIR_BRANCH_UNKNOWN;
    if (memcmp(auth_before->tip_hash, proj_before->tip_hash,
               sizeof auth_before->tip_hash) != 0)
        return AP_PAIR_BRANCH_MISMATCH;
    return AP_PAIR_COMPARABLE;
}
