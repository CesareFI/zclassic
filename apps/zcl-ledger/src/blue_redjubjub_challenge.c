/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "blue_redjubjub_challenge.h"

#include "crypto/blake2b.h"
#include "sapling/jubjub.h"

#include <stddef.h>

static void wipe(void *memory, size_t length) {
    volatile uint8_t *bytes = memory;
    for (size_t i = 0; i < length; ++i) bytes[i] = 0;
}

bool blue_redjubjub_challenge(uint8_t result[32],
    const uint8_t rbar[32], const uint8_t vkbar[32],
    const uint8_t transaction_digest[32]) {
    static const uint8_t personal[16] = {
        'Z','c','a','s','h','_','R','e','d','J','u','b','j','u','b','H'
    };
    if (!result || !rbar || !vkbar || !transaction_digest) return false;
    struct blake2b_ctx ctx = {0};
    uint8_t digest[64] = {0};
    bool success = blake2b_init_salt_personal(&ctx, sizeof digest,
        NULL, 0, NULL, personal) == 0;
    if (success) success = blake2b_update(&ctx, rbar, 32) == 0;
    if (success) success = blake2b_update(&ctx, vkbar, 32) == 0;
    if (success) success = blake2b_update(&ctx, transaction_digest, 32) == 0;
    if (success) success = blake2b_final(&ctx, digest, sizeof digest) == 0;
    if (success) jubjub_to_scalar(digest, result);
    wipe(digest, sizeof digest);
    wipe(&ctx, sizeof ctx);
    return success;
}
