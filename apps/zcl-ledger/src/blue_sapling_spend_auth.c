/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "blue_sapling_spend_auth.h"

#include "blue_fs_ct.h"
#include "blue_jubjub_encode.h"
#include "blue_jubjub_lowmem.h"
#include "blue_mod256.h"
#include "blue_redjubjub_sign_isolated.h"
#include "blue_sapling_generators.h"

#include <stddef.h>
#include <stdint.h>

static bool overlap(const void *left, size_t left_size,
    const void *right, size_t right_size) {
    if (!left || !right || !left_size || !right_size) return false;
    uintptr_t a = (uintptr_t)left, b = (uintptr_t)right;
    return a <= b ? b - a < left_size : a - b < right_size;
}

static inline bool disjoint_from_inputs(const void *output, size_t length,
    const uint8_t ask[32], const uint8_t ar[32],
    const uint8_t expected_rk[32], const uint8_t entropy[80],
    const uint8_t digest[32]) {
    return !overlap(output, length, ask, 32) &&
        !overlap(output, length, ar, 32) &&
        !overlap(output, length, expected_rk, 32) &&
        !overlap(output, length, entropy, 80) &&
        !overlap(output, length, digest, 32);
}

static bool storage_disjoint(const uint8_t signature[64],
    const blue_sapling_spend_workspace *workspace,
    const uint8_t ask[32], const uint8_t ar[32],
    const uint8_t expected_rk[32], const uint8_t entropy[80],
    const uint8_t digest[32]) {
    return !overlap(signature, 64, workspace, sizeof *workspace) &&
        disjoint_from_inputs(signature, 64, ask, ar,
            expected_rk, entropy, digest) &&
        disjoint_from_inputs(workspace, sizeof *workspace, ask, ar,
            expected_rk, entropy, digest);
}

static bool scalar_nonzero(const uint8_t scalar[32]) {
    uint8_t combined = 0;
    for (unsigned i = 0; i < 32; ++i) combined |= scalar[i];
    return combined != 0;
}

static bool matches_rk(const uint8_t actual[32],
    const uint8_t expected[32]) {
    uint8_t difference = 0;
    for (unsigned i = 0; i < 32; ++i)
        difference |= actual[i] ^ expected[i];
    return difference == 0;
}

static bool derive_rsk(uint8_t rsk[32],
    blue_sapling_spend_workspace *workspace, const uint8_t ask[32],
    const uint8_t ar[32]) {
    unsigned valid = blue_fs_from_bytes_canonical(&workspace->scalars.ask,
        ask);
    valid &= blue_fs_from_bytes_canonical(&workspace->scalars.ar, ar);
    blue_fs_add_ct(&workspace->scalars.rsk,
        &workspace->scalars.ask, &workspace->scalars.ar);
    blue_fs_to_bytes(rsk, &workspace->scalars.rsk);
    valid &= scalar_nonzero(rsk);
    return valid;
}

bool blue_sapling_spend_auth_sign(uint8_t signature[64],
    blue_sapling_spend_workspace *workspace, const uint8_t ask[32],
    const uint8_t ar[32], const uint8_t expected_rk[32],
    const uint8_t entropy[80], const uint8_t digest[32]) {
    if (!storage_disjoint(signature, workspace, ask, ar,
            expected_rk, entropy, digest)) return false;
    if (workspace) blue_mod256_wipe(workspace, sizeof *workspace);
    if (!signature) return false;
    blue_mod256_wipe(signature, 64);
    if (!workspace) return false;
    if (!ask || !ar || !expected_rk || !entropy || !digest) return false;
    uint8_t rsk[32] = {0};
    unsigned valid = derive_rsk(rsk, workspace, ask, ar);
    blue_mod256_wipe(workspace, sizeof *workspace);
    valid &= blue_jubjub_scalar_mul_lowmem(&workspace->point,
        &blue_spending_key_generator, rsk);
    valid &= blue_jubjub_encode(signature, &workspace->point);
    valid &= matches_rk(signature, expected_rk);
    valid &= blue_redjubjub_sign_isolated(signature, rsk, entropy, digest);
    volatile uint8_t mask = (uint8_t)(0u - valid);
    for (unsigned i = 0; i < 64; ++i) signature[i] &= mask;
    blue_mod256_wipe(workspace, sizeof *workspace);
    blue_mod256_wipe(rsk, sizeof rsk);
    return valid;
}
