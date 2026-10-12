/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "blue_zip32_fvk.h"

#include "blue_jubjub_encode.h"
#include "blue_jubjub_lowmem.h"
#include "blue_mod256.h"
#include "blue_storage.h"
#include "blue_sapling_generators.h"
#include "crypto/blake2b.h"

#include <string.h>

static bool encode_scalar_point(uint8_t encoded[32],
    const struct jub_point *generator, const uint8_t scalar[32]) {
    struct jub_point point = {0};
    bool valid = blue_jubjub_scalar_mul_lowmem(&point, generator, scalar);
    if (valid) valid = blue_jubjub_encode(encoded, &point);
    blue_mod256_wipe(&point, sizeof point);
    return valid;
}

bool blue_zip32_fvk_from_expsk(struct zip32_fvk *result,
    const struct zip32_expsk *secret) {
    if (!result) return false;
    if (blue_storage_overlaps(result, sizeof *result,
            secret, secret ? sizeof *secret : 0)) return false;
    bool valid = secret &&
        encode_scalar_point(result->ak, &blue_spending_key_generator,
            secret->ask) &&
        encode_scalar_point(result->nk, &blue_proof_generation_generator,
            secret->nsk);
    if (valid) memcpy(result->ovk, secret->ovk, 32);
    else blue_mod256_wipe(result, sizeof *result);
    return valid;
}

bool blue_zip32_fvk_tag(uint32_t *tag, const struct zip32_fvk *fvk) {
    if (!tag) return false;
    if (blue_storage_overlaps(tag, sizeof *tag,
            fvk, fvk ? sizeof *fvk : 0)) return false;
    *tag = 0;
    if (!fvk) return false;
    static const uint8_t personal[16] = {
        'Z','c','a','s','h','S','a','p','l','i','n','g','F','V','F','P'
    };
    struct blake2b_ctx hash = {0};
    uint8_t digest[32] = {0};
    bool valid = blake2b_init_salt_personal(&hash, 32,
        NULL, 0, NULL, personal) == 0 &&
        blake2b_update(&hash, fvk->ak, 32) == 0 &&
        blake2b_update(&hash, fvk->nk, 32) == 0 &&
        blake2b_update(&hash, fvk->ovk, 32) == 0 &&
        blake2b_final(&hash, digest, sizeof digest) == 0;
    if (valid) *tag = (uint32_t)digest[0] |
        ((uint32_t)digest[1] << 8) |
        ((uint32_t)digest[2] << 16) |
        ((uint32_t)digest[3] << 24);
    blue_mod256_wipe(digest, sizeof digest);
    blue_mod256_wipe(&hash, sizeof hash);
    return valid;
}
