/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "blue_redjubjub_challenge.h"

#undef NDEBUG
#include <assert.h>
#include <string.h>

int main(void) {
    static const uint8_t expected[32] = {
        0x17,0xb7,0xba,0x4d,0xf1,0x8c,0xc1,0x00,
        0x26,0x14,0x3e,0xd7,0x2d,0x67,0xbf,0x35,
        0x5a,0x7d,0xac,0x21,0x16,0x49,0x51,0xed,
        0xb1,0x21,0x64,0x3d,0x55,0x1d,0x4d,0x0b
    };
    uint8_t rbar[32], vkbar[32], message[32], result[32];
    for (unsigned i = 0; i < 32; ++i) {
        rbar[i] = (uint8_t)i;
        vkbar[i] = (uint8_t)(i + 32);
        message[i] = (uint8_t)(i + 64);
    }
    assert(blue_redjubjub_challenge(result, rbar, vkbar, message));
    assert(memcmp(result, expected, sizeof result) == 0);
    rbar[31] ^= 1u;
    assert(blue_redjubjub_challenge(result, rbar, vkbar, message));
    assert(memcmp(result, expected, sizeof result) != 0);
    rbar[31] ^= 1u;
    vkbar[31] ^= 1u;
    assert(blue_redjubjub_challenge(result, rbar, vkbar, message));
    assert(memcmp(result, expected, sizeof result) != 0);
    vkbar[31] ^= 1u;
    message[0] ^= 1u;
    assert(blue_redjubjub_challenge(result, rbar, vkbar, message));
    assert(memcmp(result, expected, sizeof result) != 0);
    memset(result, 0xa5, sizeof result);
    assert(!blue_redjubjub_challenge(result, NULL, vkbar, message));
    for (unsigned i = 0; i < sizeof result; ++i)
        assert(result[i] == 0xa5);
    return 0;
}
