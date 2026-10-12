/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "blue_zip32_master.h"

#include "blue_mod256.h"
#include "blue_storage.h"
#include "crypto/blake2b.h"
#include "sapling/jubjub.h"

#include <string.h>

static bool expand(uint8_t output[64], const uint8_t root[32],
    uint8_t tag) {
    static const uint8_t personal[16] = {
        'Z','c','a','s','h','_','E','x','p','a','n','d','S','e','e','d'
    };
    struct blake2b_ctx hash = {0};
    bool valid = blake2b_init_salt_personal(&hash, 64,
        NULL, 0, NULL, personal) == 0 &&
        blake2b_update(&hash, root, 32) == 0 &&
        blake2b_update(&hash, &tag, 1) == 0 &&
        blake2b_final(&hash, output, 64) == 0;
    blue_mod256_wipe(&hash, sizeof hash);
    return valid;
}

static bool master_root(uint8_t master[64], const uint8_t seed[32]) {
    static const uint8_t personal[16] = {
        'Z','c','a','s','h','I','P','3','2','S','a','p','l','i','n','g'
    };
    struct blake2b_ctx hash = {0};
    bool valid = blake2b_init_salt_personal(&hash, 64,
        NULL, 0, NULL, personal) == 0 &&
        blake2b_update(&hash, seed, 32) == 0 &&
        blake2b_final(&hash, master, 64) == 0;
    blue_mod256_wipe(&hash, sizeof hash);
    return valid;
}

static bool expanded_key(struct zip32_expsk *result,
    uint8_t dk[32], const uint8_t master[64]) {
    uint8_t expanded[64] = {0};
    bool valid = expand(expanded, master, 0);
    if (valid) jubjub_to_scalar(expanded, result->ask);
    if (valid) valid = expand(expanded, master, 1);
    if (valid) jubjub_to_scalar(expanded, result->nsk);
    if (valid) valid = expand(expanded, master, 2);
    if (valid) memcpy(result->ovk, expanded, 32);
    if (valid && dk) valid = expand(expanded, master, 0x10);
    if (valid && dk) memcpy(dk, expanded, 32);
    if (!valid) blue_mod256_wipe(result, sizeof *result);
    blue_mod256_wipe(expanded, sizeof expanded);
    return valid;
}

bool blue_zip32_master_expsk(struct zip32_expsk *result,
    const uint8_t seed[32]) {
    if (!result) return false;
    if (blue_storage_overlaps(result, sizeof *result, seed, 32))
        return false;
    uint8_t master[64] = {0};
    bool valid = seed && master_root(master, seed) &&
        expanded_key(result, NULL, master);
    if (!valid) blue_mod256_wipe(result, sizeof *result);
    blue_mod256_wipe(master, sizeof master);
    return valid;
}

bool blue_zip32_master_xsk(struct zip32_xsk *result,
    const uint8_t seed[32]) {
    if (!result) return false;
    if (blue_storage_overlaps(result, sizeof *result, seed, 32))
        return false;
    uint8_t master[64] = {0};
    bool valid = seed && master_root(master, seed);
    if (valid) {
        memset(result, 0, sizeof *result);
        memcpy(result->chain_code, master + 32, 32);
        valid = expanded_key(&result->expsk, result->dk, master);
    }
    if (!valid) blue_mod256_wipe(result, sizeof *result);
    blue_mod256_wipe(master, sizeof master);
    return valid;
}
