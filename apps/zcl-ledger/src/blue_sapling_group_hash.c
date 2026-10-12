/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "blue_sapling_group_hash.h"
#include "blue_jubjub_arithmetic.h"
#include "blue_mod256.h"
#include "crypto/blake2s.h"

#include <string.h>

static bool overlaps(const void *a, size_t a_len,
    const void *b, size_t b_len) {
    uintptr_t left = (uintptr_t)a, right = (uintptr_t)b;
    return left <= right ? right - left < a_len :
        left - right < b_len;
}

static bool disjoint_inputs(struct jub_point *point,
    blue_jubjub_decode_workspace *workspace,
    const uint8_t personal[8], const uint8_t *tag, size_t tag_len) {
    if (!point || !workspace || !personal || !tag || tag_len > 11)
        return false;
    return !overlaps(point, sizeof *point, workspace, sizeof *workspace) &&
        !overlaps(personal, 8, point, sizeof *point) &&
        !overlaps(personal, 8, workspace, sizeof *workspace) &&
        !overlaps(tag, tag_len, point, sizeof *point) &&
        !overlaps(tag, tag_len, workspace, sizeof *workspace);
}

bool blue_sapling_group_hash(struct jub_point *point,
    blue_jubjub_decode_workspace *workspace,
    const uint8_t personal[8], const uint8_t *tag, size_t tag_len) {
    static const uint8_t rigidity[] =
        "096b36a5804bfacef1691e173c366a47ff5ba84a44f26ddd7e8d9f79d5b42df0";
    if (!disjoint_inputs(point, workspace, personal, tag, tag_len))
        return false;
    struct blake2s_ctx hash;
    uint8_t digest[32];
    bool valid = blake2s_init_personal(&hash, sizeof digest, personal) == 0 &&
        blake2s_update(&hash, rigidity, sizeof rigidity - 1) == 0 &&
        blake2s_update(&hash, tag, tag_len) == 0 &&
        blake2s_final(&hash, digest, sizeof digest) == 0;
    if (valid) valid = blue_jubjub_decode_public(point, workspace, digest);
    if (valid)
        for (unsigned i = 0; i < 3; ++i) blue_jub_double(point, point);
    if (!valid) memset(point, 0, sizeof *point);
    blue_mod256_wipe(&hash, sizeof hash);
    blue_mod256_wipe(digest, sizeof digest);
    blue_mod256_wipe(workspace, sizeof *workspace);
    return valid;
}

bool blue_sapling_find_group_hash(struct jub_point *point,
    blue_jubjub_decode_workspace *workspace,
    const uint8_t personal[8], const uint8_t *tag, size_t tag_len) {
    if (!point || !workspace || !personal || !tag || tag_len > 4 ||
        !disjoint_inputs(point, workspace, personal, tag, tag_len))
        return false;
    uint8_t input[5] = {0};
    memcpy(input, tag, tag_len);
    for (unsigned counter = 0; counter < 256; ++counter) {
        input[tag_len] = (uint8_t)counter;
        if (blue_sapling_group_hash(point, workspace, personal,
                input, tag_len + 1)) {
            blue_mod256_wipe(input, sizeof input);
            return true;
        }
    }
    blue_mod256_wipe(input, sizeof input);
    return false;
}
