/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#ifndef ZCL_BLUE_REDJUBJUB_NONCE_H
#define ZCL_BLUE_REDJUBJUB_NONCE_H

#include <stdbool.h>
#include <stdint.h>

/* Derive r = H*(T || vkbar || message) for a 32-byte transaction digest.
 * T must be a fresh 80-byte output from the device CSPRNG for every call.
 * No APDU may supply T; a caller must erase it after use. This helper does
 * not establish the quality or freshness of T. The output must not overlap
 * an input. Overlap rejection preserves all storage; other rejected calls
 * clear a non-null output. */
bool blue_redjubjub_nonce_from_entropy(uint8_t scalar[32],
    const uint8_t entropy[80], const uint8_t vkbar[32],
    const uint8_t transaction_digest[32]);

#endif
