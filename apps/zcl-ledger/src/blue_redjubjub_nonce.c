/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "blue_redjubjub_nonce.h"

#include "blue_storage.h"
#include "crypto/blake2b.h"
#include "sapling/jubjub.h"

#include <stddef.h>

static void wipe(void *memory, size_t length) {
    volatile uint8_t *bytes = memory;
    for (size_t i = 0; i < length; ++i) bytes[i] = 0;
}

static bool output_disjoint(const uint8_t scalar[32],
    const uint8_t entropy[80], const uint8_t vkbar[32],
    const uint8_t transaction_digest[32]) {
    return !blue_storage_overlaps(scalar, 32, entropy, 80) &&
        !blue_storage_overlaps(scalar, 32, vkbar, 32) &&
        !blue_storage_overlaps(scalar, 32, transaction_digest, 32);
}

bool blue_redjubjub_nonce_from_entropy(uint8_t scalar[32],
    const uint8_t entropy[80], const uint8_t vkbar[32],
    const uint8_t transaction_digest[32]) {
    static const uint8_t personal[16] = {
        'Z','c','a','s','h','_','R','e','d','J','u','b','j','u','b','H'
    };
    if (!scalar) return false;
    if (!output_disjoint(scalar, entropy, vkbar,
            transaction_digest)) return false;
    if (!entropy || !vkbar || !transaction_digest) {
        wipe(scalar, 32);
        return false;
    }
    uint8_t entropy_nonzero = 0;
    for (unsigned i = 0; i < 80; ++i) entropy_nonzero |= entropy[i];
    struct blake2b_ctx hash = {0};
    uint8_t digest[64] = {0};
    wipe(scalar, 32);
    bool success = blake2b_init_salt_personal(&hash, sizeof digest,
        NULL, 0, NULL, personal) == 0;
    if (success) success = blake2b_update(&hash, entropy, 80) == 0;
    if (success) success = blake2b_update(&hash, vkbar, 32) == 0;
    if (success) success = blake2b_update(&hash,
        transaction_digest, 32) == 0;
    if (success) success = blake2b_final(&hash, digest,
        sizeof digest) == 0;
    if (success) jubjub_to_scalar(digest, scalar);
    uint8_t scalar_nonzero = 0;
    for (unsigned i = 0; i < 32; ++i) scalar_nonzero |= scalar[i];
    unsigned valid = success & (entropy_nonzero != 0) &
        (scalar_nonzero != 0);
    volatile uint8_t mask = (uint8_t)(0u - valid);
    for (unsigned i = 0; i < 32; ++i) scalar[i] &= mask;
    wipe(digest, sizeof digest);
    wipe(&hash, sizeof hash);
    return valid;
}
