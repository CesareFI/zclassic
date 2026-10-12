/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "blue_redjubjub_nonce.h"

#undef NDEBUG
#include <assert.h>
#include <string.h>

static void check_aliases(const uint8_t vkbar[32],
    const uint8_t message[32]) {
    uint8_t storage[96], original[96], entropy[80] = {1};
    for (unsigned i = 0; i < sizeof storage; ++i)
        storage[i] = (uint8_t)(i + 1);
    memcpy(original, storage, sizeof original);
    assert(!blue_redjubjub_nonce_from_entropy(storage, storage,
        vkbar, message));
    assert(memcmp(storage, original, sizeof storage) == 0);
    assert(!blue_redjubjub_nonce_from_entropy(storage + 16, storage,
        vkbar, message));
    assert(memcmp(storage, original, sizeof storage) == 0);
    assert(!blue_redjubjub_nonce_from_entropy(storage + 16, entropy,
        storage + 8, message));
    assert(memcmp(storage, original, sizeof storage) == 0);
    assert(!blue_redjubjub_nonce_from_entropy(storage + 16, entropy,
        vkbar, storage + 8));
    assert(memcmp(storage, original, sizeof storage) == 0);
}

int main(void) {
    static const uint8_t vkbar[32] = {
        0x86,0x52,0xaf,0x3e,0xd8,0xbf,0x43,0xbb,
        0x9b,0xbf,0x4c,0x26,0x90,0x50,0xb7,0x63,
        0x32,0xe2,0xc4,0xa3,0x88,0x46,0xfe,0x78,
        0x03,0xa5,0x17,0x82,0xdf,0xa9,0xbc,0xcd
    };
    static const uint8_t expected[32] = {
        0x92,0x35,0x70,0xe9,0x16,0x04,0x8b,0x7c,
        0x59,0xac,0x0e,0x27,0xaf,0xfb,0x7a,0x1d,
        0xb7,0xac,0xf6,0xe2,0xfb,0xb4,0xd1,0xbe,
        0x2b,0x90,0x77,0x46,0x6e,0x48,0xf8,0x06
    };
    uint8_t seed[80], message[32], actual[32];
    for (unsigned i = 0; i < 80; ++i) seed[i] = (uint8_t)i;
    for (unsigned i = 0; i < 32; ++i) message[i] = (uint8_t)i;
    assert(blue_redjubjub_nonce_from_entropy(actual, seed,
        vkbar, message));
    assert(memcmp(actual, expected, 32) == 0);
    seed[1] ^= 1u;
    assert(blue_redjubjub_nonce_from_entropy(actual, seed,
        vkbar, message));
    assert(memcmp(actual, expected, 32) != 0);
    seed[1] ^= 1u;
    message[0] ^= 1u;
    assert(blue_redjubjub_nonce_from_entropy(actual, seed,
        vkbar, message));
    assert(memcmp(actual, expected, 32) != 0);
    memset(seed, 0, sizeof seed);
    memset(actual, 0xa5, sizeof actual);
    assert(!blue_redjubjub_nonce_from_entropy(actual, seed,
        vkbar, message));
    for (unsigned i = 0; i < sizeof actual; ++i)
        assert(actual[i] == 0);
    assert(!blue_redjubjub_nonce_from_entropy(actual, NULL,
        vkbar, message));
    for (unsigned i = 0; i < sizeof actual; ++i)
        assert(actual[i] == 0);
    check_aliases(vkbar, message);
    return 0;
}
