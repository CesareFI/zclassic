/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "blue_sapling_kdf.h"
#include "zcl_zip243_host.h"

#undef NDEBUG
#include <assert.h>
#include <stdio.h>
#include <string.h>

static bool fail_final(void *context, uint8_t digest[32]) {
    (void)context;
    memset(digest, 0xa5, 32);
    return false;
}

int main(void) {
    static const uint8_t expected[32] = {
        0xb1,0x3a,0xcd,0x7c,0xe4,0x08,0xed,0xc6,
        0x8b,0x21,0x00,0x12,0xb8,0xb6,0x3e,0x1d,
        0x48,0xd5,0x25,0x5b,0xd6,0x1b,0x28,0xe1,
        0x2b,0x7c,0x39,0xfa,0x43,0x83,0xf4,0x27
    };
    uint8_t dh[32], epk[32], key[32];
    for (unsigned i = 0; i < 32; ++i) {
        dh[i] = (uint8_t)i;
        epk[i] = (uint8_t)(i + 128);
    }
    struct blake2b_ctx context;
    zcl_zip243_hasher hasher = zcl_zip243_host_hasher(&context);
    assert(blue_sapling_kdf(key, dh, epk, &hasher));
    assert(memcmp(key, expected, sizeof key) == 0);
    uint8_t dh_alias[33];
    memcpy(dh_alias, dh, sizeof dh);
    dh_alias[32] = 0xa5;
    assert(!blue_sapling_kdf(dh_alias + 1, dh_alias, epk, &hasher));
    assert(memcmp(dh_alias, dh, sizeof dh) == 0 && dh_alias[32] == 0xa5);
    uint8_t saved_epk[32];
    memcpy(saved_epk, epk, sizeof saved_epk);
    assert(!blue_sapling_kdf(epk, dh, epk, &hasher));
    assert(memcmp(epk, saved_epk, sizeof epk) == 0);
    epk[0] ^= 1u;
    assert(blue_sapling_kdf(key, dh, epk, &hasher));
    assert(memcmp(key, expected, sizeof key) != 0);
    epk[0] ^= 1u;
    dh[0] ^= 1u;
    assert(blue_sapling_kdf(key, dh, epk, &hasher));
    assert(memcmp(key, expected, sizeof key) != 0);
    dh[0] ^= 1u;
    hasher.final = fail_final;
    assert(!blue_sapling_kdf(key, dh, epk, &hasher));
    for (unsigned i = 0; i < sizeof key; ++i) assert(key[i] == 0);
    assert(!blue_sapling_kdf(key, dh, epk, NULL));
    for (unsigned i = 0; i < sizeof key; ++i) assert(key[i] == 0);
    memset(&context, 0, sizeof context);
    memset(key, 0, sizeof key);
    puts("Blue Sapling note key: passed");
    return 0;
}
