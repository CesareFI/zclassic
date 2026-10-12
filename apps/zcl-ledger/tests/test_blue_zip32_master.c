/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "blue_zip32_master.h"
#include "blue_zip32_seed_device.h"
#include "os.h"

#undef NDEBUG
#include <assert.h>
#include <string.h>

static int pin_valid;
static unsigned derive_count;
static bool revoke_during_derive;

int os_global_pin_is_validated(void) {
    return pin_valid;
}

void os_perso_derive_node_bip32(unsigned curve, const unsigned int *path,
    unsigned length, uint8_t raw[32], uint8_t chain[32]) {
    assert(pin_valid && curve == CX_CURVE_256K1 && length == 3);
    assert(path[0] == 0x80000020u && path[1] == 0x80000093u &&
        path[2] == 0x80000000u);
    ++derive_count;
    for (unsigned i = 0; i < 32; ++i) {
        raw[i] = (uint8_t)i;
        chain[i] = (uint8_t)(i + 32);
    }
    if (revoke_during_derive) pin_valid = 0;
}

static void test_device_bridge(void) {
    static const uint8_t mapped_seed[32] = {
        0x2d,0x26,0x76,0x85,0xb1,0x14,0x36,0x26,
        0x95,0x83,0xfd,0x90,0xcf,0x71,0xa4,0x13,
        0xfe,0x25,0xc4,0x6a,0x9d,0x67,0x0a,0x06,
        0x9f,0x4c,0xe7,0x52,0xbb,0xa3,0x4e,0x1e
    };
    struct zip32_xsk result, expected;
    blue_zip32_seed_workspace workspace;
    pin_valid = 0;
    derive_count = 0;
    memset(&result, 0xa5, sizeof result);
    assert(!blue_zip32_device_master(&result, &workspace));
    const uint8_t zero_result[sizeof result] = {0};
    assert(memcmp(&result, zero_result, sizeof result) == 0);
    assert(derive_count == 0);
    pin_valid = 1;
    assert(blue_zip32_device_master(&result, &workspace));
    assert(blue_zip32_master_xsk(&expected, mapped_seed));
    assert(derive_count == 1);
    assert(memcmp(&result, &expected, sizeof result) == 0);
    const uint8_t zero_workspace[sizeof workspace] = {0};
    assert(memcmp(&workspace, zero_workspace, sizeof workspace) == 0);
    memset(&workspace, 0xa5, sizeof workspace);
    assert(!blue_zip32_master_from_bip32(NULL, &workspace, NULL, NULL));
    assert(memcmp(&workspace, zero_workspace, sizeof workspace) == 0);
    assert(derive_count == 1);
    pin_valid = 1;
    revoke_during_derive = true;
    memset(&result, 0xa5, sizeof result);
    memset(&workspace, 0xa5, sizeof workspace);
    assert(!blue_zip32_device_master(&result, &workspace));
    assert(derive_count == 2 && !pin_valid);
    assert(memcmp(&result, zero_result, sizeof result) == 0);
    assert(memcmp(&workspace, zero_workspace, sizeof workspace) == 0);
    revoke_during_derive = false;
}

static void test_reference_vector(void) {
    static const uint8_t ask[32] = {
        0xb6,0xc0,0x0c,0x93,0xd3,0x60,0x32,0xb9,
        0xa2,0x68,0xe9,0x9e,0x86,0xa8,0x60,0x77,
        0x65,0x60,0xbf,0x0e,0x83,0xc1,0xa1,0x0b,
        0x51,0xf6,0x07,0xc9,0x54,0x74,0x25,0x06
    };
    static const uint8_t nsk[32] = {
        0x82,0x04,0xed,0xe8,0x3b,0x2f,0x1f,0xbd,
        0x84,0xf9,0xb4,0x5d,0x7f,0x99,0x6e,0x2e,
        0xbd,0x0a,0x03,0x0a,0xd2,0x43,0xb4,0x8e,
        0xd3,0x9f,0x74,0x8a,0x88,0x21,0xea,0x06
    };
    static const uint8_t ovk[32] = {
        0x39,0x58,0x84,0x89,0x03,0x23,0xb9,0xd4,
        0x93,0x3c,0x02,0x1d,0xb8,0x9b,0xcf,0x76,
        0x7d,0xf2,0x19,0x77,0xb2,0xff,0x06,0x83,
        0x84,0x83,0x21,0xa4,0xdf,0x4a,0xfb,0x21
    };
    static const uint8_t chain[32] = {
        0xd0,0x94,0x7c,0x4b,0x03,0xbf,0x72,0xa3,
        0x7a,0xb4,0x4f,0x72,0x27,0x6d,0x1c,0xf3,
        0xfd,0xcd,0x7e,0xbf,0x3e,0x73,0x34,0x8b,
        0x7e,0x55,0x0d,0x75,0x20,0x18,0x66,0x8e
    };
    static const uint8_t dk[32] = {
        0x77,0xc1,0x7c,0xb7,0x5b,0x77,0x96,0xaf,
        0xb3,0x9f,0x0f,0x3e,0x91,0xc9,0x24,0x60,
        0x7d,0xa5,0x6f,0xa9,0xa2,0x0e,0x28,0x35,
        0x09,0xbc,0x8a,0x3e,0xf9,0x96,0xa1,0x72
    };
    uint8_t seed[32];
    for (unsigned i = 0; i < sizeof seed; ++i) seed[i] = (uint8_t)i;
    struct zip32_expsk result;
    assert(blue_zip32_master_expsk(&result, seed));
    assert(memcmp(result.ask, ask, 32) == 0);
    assert(memcmp(result.nsk, nsk, 32) == 0);
    assert(memcmp(result.ovk, ovk, 32) == 0);
    struct zip32_xsk full;
    assert(blue_zip32_master_xsk(&full, seed));
    assert(full.depth == 0 && full.parent_fvk_tag == 0 &&
        full.child_index == 0);
    assert(memcmp(full.chain_code, chain, 32) == 0);
    assert(memcmp(&full.expsk, &result, sizeof result) == 0);
    assert(memcmp(full.dk, dk, 32) == 0);
    memset(&full, 0xa5, sizeof full);
    assert(!blue_zip32_master_xsk(&full, NULL));
    const uint8_t full_zero[sizeof full] = {0};
    assert(memcmp(&full, full_zero, sizeof full) == 0);
    assert(!blue_zip32_master_xsk(NULL, seed));
    memset(&result, 0xa5, sizeof result);
    assert(!blue_zip32_master_expsk(&result, NULL));
    const uint8_t zero[sizeof result] = {0};
    assert(memcmp(&result, zero, sizeof result) == 0);
    assert(!blue_zip32_master_expsk(NULL, seed));
}

int main(void) {
    test_reference_vector();
    test_device_bridge();
    return 0;
}
