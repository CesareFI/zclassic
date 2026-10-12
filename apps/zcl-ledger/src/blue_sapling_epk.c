/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "blue_sapling_epk.h"
#include "blue_jubjub_arithmetic.h"
#include "blue_jubjub_decode.h"
#include "blue_jubjub_encode.h"
#include "blue_jubjub_lowmem.h"
#include "blue_mod256.h"
#include "blue_sapling_group_hash.h"

#include <string.h>

static bool overlaps(const void *a, size_t a_len,
    const void *b, size_t b_len) {
    uintptr_t left = (uintptr_t)a, right = (uintptr_t)b;
    return left <= right ? right - left < a_len :
        left - right < b_len;
}

bool blue_sapling_epk_matches(const uint8_t diversifier[11],
    const uint8_t esk[32], const uint8_t epk[32],
    blue_sapling_epk_workspace *workspace) {
    if (!workspace) return false;
    if ((diversifier && overlaps(workspace, sizeof *workspace,
            diversifier, 11)) ||
        (esk && overlaps(workspace, sizeof *workspace, esk, 32)) ||
        (epk && overlaps(workspace, sizeof *workspace, epk, 32)))
        return false;
    memset(workspace, 0, sizeof *workspace);
    struct jub_point point;
    uint8_t encoded[32];
    static const uint8_t personal[8] =
        {'Z','c','a','s','h','_','g','d'};
    bool valid = diversifier && esk && epk &&
        blue_sapling_group_hash(&point, workspace, personal,
            diversifier, 11) &&
        blue_jubjub_scalar_mul_lowmem(&point, &point, esk) &&
        blue_jubjub_encode(encoded, &point) &&
        memcmp(encoded, epk, sizeof encoded) == 0;
    blue_mod256_wipe(&point, sizeof point);
    blue_mod256_wipe(encoded, sizeof encoded);
    blue_mod256_wipe(workspace, sizeof *workspace);
    return valid;
}
