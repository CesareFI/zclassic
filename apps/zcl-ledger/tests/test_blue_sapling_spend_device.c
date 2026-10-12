/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "blue_sapling_spend_device.h"
#include "blue_mod256.h"

#undef NDEBUG
#include <assert.h>
#include <string.h>

static int pin_valid;
static bool revoke_during_sign;
static unsigned fail_stage;
static unsigned master_calls, child_calls, rng_calls, sign_calls;

int os_global_pin_is_validated(void) { return pin_valid; }

bool blue_zip32_device_master(struct zip32_xsk *result,
    blue_zip32_seed_workspace *scratch) {
    ++master_calls;
    memset(result, 0xa5, sizeof *result);
    blue_mod256_wipe(scratch, sizeof *scratch);
    if (fail_stage == 5) pin_valid = 0;
    return fail_stage != 1;
}

bool blue_zip32_derive_child(struct zip32_xsk *child,
    const struct zip32_xsk *parent, uint32_t index,
    blue_zip32_workspace *scratch) {
    ++child_calls;
    assert(parent && index == ZIP32_HARDENED_KEY_LIMIT);
    memset(child, 0x5a, sizeof *child);
    blue_mod256_wipe(scratch, sizeof *scratch);
    if (fail_stage == 6) pin_valid = 0;
    return fail_stage != 2;
}

bool blue_sapling_device_entropy(uint8_t entropy[80]) {
    ++rng_calls;
    memset(entropy, 0x3c, 80);
    if (fail_stage == 7) pin_valid = 0;
    return fail_stage != 3;
}

bool blue_sapling_spend_auth_sign(uint8_t signature[64],
    blue_sapling_spend_workspace *scratch, const uint8_t ask[32],
    const uint8_t ar[32], const uint8_t expected_rk[32],
    const uint8_t entropy[80], const uint8_t digest[32]) {
    ++sign_calls;
    assert(ask[0] == 0x5a && ar[0] == 1 && expected_rk[0] == 2 &&
        entropy[0] == 0x3c && digest[0] == 3);
    memset(scratch, 0x7e, sizeof *scratch);
    memset(signature, 0x9b, 64);
    if (revoke_during_sign) pin_valid = 0;
    return fail_stage != 4;
}

static bool all_byte(const void *buffer, size_t length, uint8_t value) {
    const uint8_t *bytes = buffer;
    for (size_t i = 0; i < length; ++i)
        if (bytes[i] != value) return false;
    return true;
}

int main(void) {
    static const uint8_t ar[32] = {1}, rk[32] = {2}, digest[32] = {3};
    static uint8_t signature[64];
    static blue_sapling_device_spend_workspace workspace;
    pin_valid = 1;
    assert(blue_sapling_device_spend_sign(signature, &workspace,
        0, ar, rk, digest));
    assert(master_calls == 1 && child_calls == 1 && rng_calls == 1 &&
        sign_calls == 1);
    assert(all_byte(signature, sizeof signature, 0x9b));
    assert(all_byte(&workspace, sizeof workspace, 0));

    revoke_during_sign = true;
    memset(signature, 0xa5, sizeof signature);
    assert(!blue_sapling_device_spend_sign(signature, &workspace,
        0, ar, rk, digest));
    assert(sign_calls == 2 && !pin_valid);
    assert(all_byte(signature, sizeof signature, 0));
    assert(all_byte(&workspace, sizeof workspace, 0));

    pin_valid = 1;
    assert(!blue_sapling_device_spend_sign(signature, &workspace,
        ZIP32_HARDENED_KEY_LIMIT, ar, rk, digest));
    assert(master_calls == 2 && all_byte(signature, sizeof signature, 0));
    assert(all_byte(&workspace, sizeof workspace, 0));

    memset(signature, 0xa5, sizeof signature);
    memset(&workspace, 0x5a, sizeof workspace);
    assert(!blue_sapling_device_spend_sign(signature, &workspace,
        0, ar, rk, workspace.entropy));
    assert(all_byte(signature, sizeof signature, 0xa5));
    assert(all_byte(&workspace, sizeof workspace, 0x5a));

    revoke_during_sign = false;
    for (fail_stage = 1; fail_stage <= 7; ++fail_stage) {
        unsigned before_master = master_calls, before_child = child_calls;
        unsigned before_rng = rng_calls, before_sign = sign_calls;
        pin_valid = 1;
        memset(signature, 0xa5, sizeof signature);
        memset(&workspace, 0x5a, sizeof workspace);
        assert(!blue_sapling_device_spend_sign(signature, &workspace,
            0, ar, rk, digest));
        assert(all_byte(signature, sizeof signature, 0));
        assert(all_byte(&workspace, sizeof workspace, 0));
        assert(master_calls == before_master + 1);
        assert(child_calls == before_child +
            (unsigned)(fail_stage != 1 && fail_stage != 5));
        assert(rng_calls == before_rng +
            (unsigned)(fail_stage == 3 || fail_stage == 4 ||
                       fail_stage == 7));
        assert(sign_calls == before_sign + (unsigned)(fail_stage == 4));
    }
    return 0;
}
