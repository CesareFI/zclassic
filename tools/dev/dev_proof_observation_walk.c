/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: Verified read-only walk of one signed-observation CAS.
 *
 * The observation CAS layout is owned by vcs_object.c (the write
 * authority); this walk is its one reader. This translation unit is kept
 * free of vcs_object calls so the pre-push hook can link it: the hook
 * verifies coverage manifests against a pair store on every push and must
 * not drag the writable-object machinery into its no-build binary. */
#include "dev_proof_observation_walk.h"

#include "base/hex.h"
#include "base/safe_alloc.h"
#include "platform/directory_compat.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define OBSERVATION_MAX_ROOTS 8192u

static bool obs_fail(char *why, size_t cap, const char *reason)
{
    if (why && cap) (void)snprintf(why, cap, "%s", reason);
    return false;
}

/* The observation CAS layout owned by vcs_object.c. */
#define OBS_OBJECTS_SUBDIR ".zvcs/objects"
#define OBS_LEAF_HEX (ZCL_DEV_PROOF_ROOT_BYTES * 2u)
#define OBS_SHARD_HEX 2u
#define OBS_NAME_HEX (OBS_LEAF_HEX - OBS_SHARD_HEX)

static bool obs_leaf_load(const char *path,
    const uint8_t root[ZCL_DEV_PROOF_ROOT_BYTES],
    struct zcl_dev_verdict_leaf_v1 *leaf, bool *eligible)
{
    *eligible = false;
    FILE *f = fopen(path, "rb");
    if (!f) return false;
    uint8_t wire[ZCL_DEV_VERDICT_LEAF_WIRE_BYTES];
    size_t got = fread(wire, 1, sizeof(wire), f);
    int extra = fgetc(f);
    (void)fclose(f);
    if (got != sizeof(wire) || extra != EOF) return false;
    char why[80];
    uint8_t derived[ZCL_DEV_PROOF_ROOT_BYTES];
    if (!zcl_dev_verdict_leaf_parse(wire, sizeof(wire), leaf,
                                    why, sizeof(why)) ||
        !zcl_dev_verdict_leaf_root(leaf, derived, why, sizeof(why)) ||
        memcmp(derived, root, sizeof(derived)) != 0)
        return false;
    char group[ZCL_DEV_VERDICT_LEAF_GROUP_BYTES];
    (void)memcpy(group, leaf->group, leaf->group_len);
    group[leaf->group_len] = 0;
    *eligible = zcl_dev_verdict_leaf_verify(leaf, leaf->key, group,
                                            why, sizeof(why));
    return true;
}

/* One shard of the store: every listed file must be a well-formed addressed
 * leaf; one corrupt object makes the whole projection incomplete. */
static bool obs_enumerate_shard(struct zcl_dev_observation_leaf **leaves,
    size_t *count, size_t *cap, const char *shard_path,
    const char *shard_name, char *why, size_t why_len)
{
    struct platform_directory_list files = {0};
    if (!platform_directory_list_regular_sorted(shard_path, &files))
        return obs_fail(why, why_len, "observation_store_incomplete");
    bool ok = true;
    for (size_t i = 0; i < files.count && ok; i++) {
        if (strlen(shard_name) != OBS_SHARD_HEX ||
            strlen(files.entries[i].name) != OBS_NAME_HEX) {
            ok = obs_fail(why, why_len, "observation_store_incomplete");
            break;
        }
        if (*count >= OBSERVATION_MAX_ROOTS) {
            ok = obs_fail(why, why_len, "observation_store_too_many_roots");
            break;
        }
        if (*count == *cap) {
            *cap *= 2;
            struct zcl_dev_observation_leaf *grown =
                zcl_realloc(*leaves, *cap * sizeof(**leaves),
                            "dev-observation-leaves-grow");
            if (!grown) {
                ok = obs_fail(why, why_len, "observation_store_incomplete");
                break;
            }
            *leaves = grown;
        }
        struct zcl_dev_observation_leaf *slot = &(*leaves)[*count];
        char hex[OBS_LEAF_HEX + 1];
        (void)memcpy(hex, shard_name, OBS_SHARD_HEX);
        (void)memcpy(hex + OBS_SHARD_HEX, files.entries[i].name,
                     OBS_NAME_HEX);
        hex[OBS_LEAF_HEX] = 0;
        char leaf_path[4096];
        int n = snprintf(leaf_path, sizeof(leaf_path), "%s/%s", shard_path,
                         files.entries[i].name);
        if (n < 0 || n >= (int)sizeof(leaf_path) ||
            !zcl_hex_decode(hex, slot->root, ZCL_DEV_PROOF_ROOT_BYTES) ||
            !obs_leaf_load(leaf_path, slot->root, &slot->leaf,
                           &slot->eligible))
            ok = obs_fail(why, why_len, "observation_store_incomplete");
        else
            (*count)++;
    }
    platform_directory_list_free(&files);
    return ok;
}

static bool obs_enumerate_shards(const char *store_root, char *objects_path,
    size_t objects_path_cap, struct zcl_dev_observation_leaf **leaves,
    size_t *count, char *why, size_t why_len)
{
    if (snprintf(objects_path, objects_path_cap, "%s/%s", store_root,
                 OBS_OBJECTS_SUBDIR) >= (int)objects_path_cap)
        return obs_fail(why, why_len, ZCL_DEV_VERDICT_WHY_ARGUMENTS);
    /* A store root that exists but never held leaves (a pair whose test
     * dimension ran zero groups, a freshly ensured directory) enumerates
     * empty; only a present-but-unreadable objects dir is incomplete. */
    enum platform_directory_probe_result objects_probe =
        platform_directory_probe_real(objects_path);
    if (objects_probe == PLATFORM_DIRECTORY_PROBE_REFUSED)
        return obs_fail(why, why_len, "observation_store_incomplete");
    if (objects_probe == PLATFORM_DIRECTORY_PROBE_MISSING) {
        *leaves = NULL;
        *count = 0;
        if (why && why_len) why[0] = 0;
        return true;
    }
    struct platform_directory_list shards = {0};
    if (!platform_directory_list_real_sorted(objects_path, &shards))
        return obs_fail(why, why_len, "observation_store_incomplete");
    size_t cap = 256;
    *leaves = zcl_malloc(cap * sizeof(**leaves), "dev-observation-leaves");
    if (!*leaves) {
        platform_directory_list_free(&shards);
        return obs_fail(why, why_len, "observation_store_incomplete");
    }
    *count = 0;
    bool ok = true;
    for (size_t s = 0; s < shards.count && ok; s++) {
        /* The store's own tmp/ staging pool lives beside the shards; it is
         * part of the layout, never an observation object. */
        if (strcmp(shards.entries[s].name, "tmp") == 0) continue;
        char shard_path[4096];
        int n = snprintf(shard_path, sizeof(shard_path), "%s/%s",
                         objects_path, shards.entries[s].name);
        if (n < 0 || n >= (int)sizeof(shard_path)) {
            ok = obs_fail(why, why_len, "observation_store_incomplete");
            break;
        }
        ok = obs_enumerate_shard(leaves, count, &cap, shard_path,
                                 shards.entries[s].name, why, why_len);
    }
    platform_directory_list_free(&shards);
    if (!ok) {
        free(*leaves);
        *leaves = NULL;
    }
    return ok;
}

bool zcl_dev_observation_enumerate(const char *store_root,
    struct zcl_dev_observation_leaf **leaves_out, size_t *count_out,
    bool *present_out, char *why, size_t why_len)
{
    if (!leaves_out || !count_out || !present_out ||
        !store_root || !store_root[0]) {
        if (why && why_len)
            (void)snprintf(why, why_len, "%s",
                           ZCL_DEV_VERDICT_WHY_ARGUMENTS);
        return false;
    }
    *leaves_out = NULL;
    *count_out = 0;
    *present_out = false;
    enum platform_directory_probe_result probe =
        platform_directory_probe_real(store_root);
    if (probe == PLATFORM_DIRECTORY_PROBE_REFUSED)
        return obs_fail(why, why_len, "observation_store_incomplete");
    if (probe == PLATFORM_DIRECTORY_PROBE_MISSING) return true; /* absent */
    *present_out = true;

    char objects_path[4096];
    if (!obs_enumerate_shards(store_root, objects_path, sizeof(objects_path),
                              leaves_out, count_out, why, why_len))
        return false;
    if (why && why_len) why[0] = 0;
    return true;
}

void zcl_dev_observation_release(struct zcl_dev_observation_leaf *leaves)
{
    free(leaves);
}

bool zcl_dev_observation_group_matches(
    const struct zcl_dev_verdict_leaf_v1 *leaf, uint8_t group_len,
    const char *group)
{
    return leaf->group_len == group_len &&
           memcmp(leaf->group, group, group_len) == 0;
}
