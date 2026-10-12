/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "blue_jubjub_decode.h"
#include "blue_fr_ct.h"
#include "blue_fr_sqrt.h"
#include "blue_jubjub_arithmetic.h"
#include "blue_mod256.h"

#include <string.h>

static const struct fr montgomery_one = {.d = {
    0x00000001fffffffeULL, 0x5884b7fa00034802ULL,
    0x998c4fefecbc4ff5ULL, 0x1824b159acc5056fULL
}};

static const struct fr curve_d = {.d = {
    0x2a522455b974f6b0ULL, 0xfc6cc9ef0d9acab3ULL,
    0x7a08fb94c27628d1ULL, 0x57f8f6a8fe0e262eULL
}};

static_assert(sizeof(blue_jubjub_decode_workspace) == 544,
    "Jubjub decode workspace exceeds its bounded-memory budget");

static bool is_zero(const struct fr *value) {
    uint64_t combined = 0;
    for (unsigned i = 0; i < 4; ++i) combined |= value->d[i];
    return combined == 0;
}

static bool small_order(blue_jubjub_decode_workspace *workspace) {
    blue_jub_double(&workspace->multiple, &workspace->point);
    blue_jub_double(&workspace->multiple, &workspace->multiple);
    blue_jub_double(&workspace->multiple, &workspace->multiple);
    bool identity = is_zero(&workspace->multiple.x) &&
        is_zero(&workspace->multiple.t) &&
        memcmp(&workspace->multiple.y, &workspace->multiple.z,
            sizeof workspace->multiple.y) == 0;
    return identity;
}

static bool recover_x(blue_jubjub_decode_workspace *workspace,
    unsigned sign) {
    blue_fr_mul_ct(&workspace->y2, &workspace->y, &workspace->y);
    blue_fr_sub_ct(&workspace->numerator, &workspace->y2,
        &montgomery_one);
    blue_fr_mul_ct(&workspace->denominator, &curve_d, &workspace->y2);
    blue_fr_add_ct(&workspace->denominator,
        &workspace->denominator, &montgomery_one);
    if (!blue_fr_inverse_fixed(&workspace->inverse,
            &workspace->denominator)) return false;
    blue_fr_mul_ct(&workspace->x2, &workspace->numerator,
        &workspace->inverse);
    if (!blue_fr_sqrt_public(&workspace->x, &workspace->x2)) return false;
    blue_fr_to_bytes(workspace->x_bytes, &workspace->x);
    if ((workspace->x_bytes[0] & 1u) != sign)
        blue_fr_neg_ct(&workspace->x, &workspace->x);
    blue_fr_to_bytes(workspace->x_bytes, &workspace->x);
    return (workspace->x_bytes[0] & 1u) == sign;
}

bool blue_jubjub_decode_public(struct jub_point *result,
    blue_jubjub_decode_workspace *workspace, const uint8_t encoded[32]) {
    if (!result) {
        if (workspace) blue_mod256_wipe(workspace, sizeof *workspace);
        return false;
    }
    memset(result, 0, sizeof *result);
    if (!workspace) return false;
    if (!encoded) {
        blue_mod256_wipe(workspace, sizeof *workspace);
        return false;
    }
    memset(workspace, 0, sizeof *workspace);
    memcpy(workspace->y_bytes, encoded, sizeof workspace->y_bytes);
    unsigned sign = workspace->y_bytes[31] >> 7;
    workspace->y_bytes[31] &= 0x7fu;
    bool valid = blue_fr_from_bytes_canonical(&workspace->y,
        workspace->y_bytes);
    if (valid) valid = recover_x(workspace, sign);
    if (valid) {
        workspace->point.x = workspace->x;
        workspace->point.y = workspace->y;
        workspace->point.z = montgomery_one;
        blue_fr_mul_ct(&workspace->point.t, &workspace->x, &workspace->y);
        valid = !small_order(workspace);
        if (valid) *result = workspace->point;
    }
    blue_mod256_wipe(workspace, sizeof *workspace);
    return valid;
}
