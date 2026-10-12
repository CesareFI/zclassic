/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "blue_zip32_child.h"

#include "blue_fs_ct.h"
#include "blue_mod256.h"
#include "blue_storage.h"
#include "blue_zip32_fvk.h"
#include "crypto/blake2b.h"
#include "sapling/jubjub.h"

#include <string.h>

static const uint8_t expand_personal[16] = {
    'Z','c','a','s','h','_','E','x','p','a','n','d','S','e','e','d'
};

[[gnu::noinline]] static bool child_root(uint8_t output[64],
    const struct zip32_xsk *parent,
    const struct zip32_fvk *fvk, uint32_t index) {
    uint8_t tag = index & ZIP32_HARDENED_KEY_LIMIT ? 0x11 : 0x12;
    uint8_t le_index[4] = {(uint8_t)index, (uint8_t)(index >> 8),
        (uint8_t)(index >> 16), (uint8_t)(index >> 24)};
    const uint8_t *first = tag == 0x11 ? parent->expsk.ask : fvk->ak;
    const uint8_t *second = tag == 0x11 ? parent->expsk.nsk : fvk->nk;
    const uint8_t *third = tag == 0x11 ? parent->expsk.ovk : fvk->ovk;
    struct blake2b_ctx hash = {0};
    bool valid = blake2b_init_salt_personal(&hash, 64,
        NULL, 0, NULL, expand_personal) == 0 &&
        blake2b_update(&hash, parent->chain_code, 32) == 0 &&
        blake2b_update(&hash, &tag, 1) == 0 &&
        blake2b_update(&hash, first, 32) == 0 &&
        blake2b_update(&hash, second, 32) == 0 &&
        blake2b_update(&hash, third, 32) == 0 &&
        blake2b_update(&hash, parent->dk, 32) == 0 &&
        blake2b_update(&hash, le_index, sizeof le_index) == 0 &&
        blake2b_final(&hash, output, 64) == 0;
    blue_mod256_wipe(&hash, sizeof hash);
    return valid;
}

static bool child_expand(uint8_t output[64], const uint8_t key[32],
    uint8_t tag, const uint8_t *suffix, size_t suffix_length) {
    struct blake2b_ctx hash = {0};
    bool valid = blake2b_init_salt_personal(&hash, 64,
        NULL, 0, NULL, expand_personal) == 0 &&
        blake2b_update(&hash, key, 32) == 0 &&
        blake2b_update(&hash, &tag, 1) == 0;
    if (valid && suffix_length)
        valid = blake2b_update(&hash, suffix, suffix_length) == 0;
    if (valid) valid = blake2b_final(&hash, output, 64) == 0;
    blue_mod256_wipe(&hash, sizeof hash);
    return valid;
}

static bool derive_scalar(uint8_t output[32], const uint8_t parent[32],
    const uint8_t key[32], uint8_t tag) {
    uint8_t digest[64] = {0}, delta[32] = {0};
    struct fs base = {0}, increment = {0}, sum = {0};
    bool valid = blue_fs_from_bytes_canonical(&base, parent) &&
        child_expand(digest, key, tag, NULL, 0);
    if (valid) jubjub_to_scalar(digest, delta);
    if (valid) valid = blue_fs_from_bytes_canonical(&increment, delta);
    if (valid) {
        blue_fs_add_ct(&sum, &base, &increment);
        blue_fs_to_bytes(output, &sum);
    }
    blue_mod256_wipe(&base, sizeof base);
    blue_mod256_wipe(&increment, sizeof increment);
    blue_mod256_wipe(&sum, sizeof sum);
    blue_mod256_wipe(delta, sizeof delta);
    blue_mod256_wipe(digest, sizeof digest);
    return valid;
}

static bool derive_keys(struct zip32_xsk *child,
    const struct zip32_xsk *parent, const uint8_t key[32]) {
    bool valid = derive_scalar(child->expsk.ask,
        parent->expsk.ask, key, 0x13) &&
        derive_scalar(child->expsk.nsk,
            parent->expsk.nsk, key, 0x14);
    uint8_t digest[64] = {0};
    if (valid) valid = child_expand(digest, key, 0x15,
        parent->expsk.ovk, 32);
    if (valid) memcpy(child->expsk.ovk, digest, 32);
    if (valid) valid = child_expand(digest, key, 0x16,
        parent->dk, 32);
    if (valid) memcpy(child->dk, digest, 32);
    blue_mod256_wipe(digest, sizeof digest);
    return valid;
}

static bool storage_overlaps(const struct zip32_xsk *child,
    const struct zip32_xsk *parent, const blue_zip32_workspace *scratch) {
    return blue_storage_overlaps(child, sizeof *child,
            parent, parent ? sizeof *parent : 0) ||
        blue_storage_overlaps(child, sizeof *child,
            scratch, scratch ? sizeof *scratch : 0) ||
        blue_storage_overlaps(parent, parent ? sizeof *parent : 0,
            scratch, scratch ? sizeof *scratch : 0);
}

bool blue_zip32_derive_child(struct zip32_xsk *child,
    const struct zip32_xsk *parent, uint32_t index,
    blue_zip32_workspace *scratch) {
    if (!child) return false;
    if (storage_overlaps(child, parent, scratch)) return false;
    bool valid = parent && scratch && parent->depth < 255 &&
        blue_zip32_fvk_from_expsk(&scratch->fvk, &parent->expsk);
    uint32_t parent_tag = 0;
    if (valid) valid = blue_zip32_fvk_tag(&parent_tag, &scratch->fvk) &&
        child_root(scratch->root, parent, &scratch->fvk, index);
    if (valid) {
        memset(child, 0, sizeof *child);
        child->depth = parent->depth + 1;
        child->parent_fvk_tag = parent_tag;
        child->child_index = index;
        memcpy(child->chain_code, scratch->root + 32, 32);
        valid = derive_keys(child, parent, scratch->root);
    }
    if (!valid) blue_mod256_wipe(child, sizeof *child);
    if (scratch) blue_mod256_wipe(scratch, sizeof *scratch);
    return valid;
}
