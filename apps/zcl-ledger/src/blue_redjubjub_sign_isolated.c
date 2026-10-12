/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "blue_redjubjub_sign_isolated.h"

#include "blue_jubjub_encode.h"
#include "blue_jubjub_lowmem.h"
#include "blue_mod256.h"
#include "blue_redjubjub_challenge.h"
#include "blue_redjubjub_nonce.h"
#include "blue_redjubjub_response.h"
#include "blue_sapling_generators.h"
#include "blue_storage.h"

static bool point_from_scalar(uint8_t encoded[32],
    const uint8_t scalar[32]) {
    struct jub_point point = {0};
    unsigned success = blue_jubjub_scalar_mul_lowmem(&point,
        &blue_spending_key_generator, scalar);
    success &= blue_jubjub_encode(encoded, &point);
    blue_mod256_wipe(&point, sizeof point);
    return success;
}

bool blue_redjubjub_sign_isolated(uint8_t signature[64],
    const uint8_t secret[32], const uint8_t entropy[80],
    const uint8_t transaction_digest[32]) {
    if (!signature) return false;
    if (blue_storage_overlaps(signature, 64, secret, 32) ||
        blue_storage_overlaps(signature, 64, entropy, 80) ||
        blue_storage_overlaps(signature, 64, transaction_digest, 32))
        return false;
    if (!secret || !entropy || !transaction_digest) {
        blue_mod256_wipe(signature, 64);
        return false;
    }
    uint8_t nonce[32] = {0};
    uint8_t candidate[64] = {0};
    unsigned success = point_from_scalar(candidate + 32, secret);
    success &= blue_redjubjub_nonce_from_entropy(nonce,
        entropy, candidate + 32, transaction_digest);
    success &= point_from_scalar(candidate, nonce);
    success &= blue_redjubjub_challenge(candidate + 32,
        candidate, candidate + 32, transaction_digest);
    success &= blue_redjubjub_response(candidate + 32,
        nonce, candidate + 32, secret);
    volatile uint8_t mask = (uint8_t)(0u - success);
    for (unsigned i = 0; i < sizeof candidate; ++i)
        signature[i] = candidate[i] & mask;
    blue_mod256_wipe(nonce, sizeof nonce);
    blue_mod256_wipe(candidate, sizeof candidate);
    return success;
}
