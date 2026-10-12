/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#ifndef ZCL_BLUE_REDJUBJUB_RESPONSE_H
#define ZCL_BLUE_REDJUBJUB_RESPONSE_H

#include <stdbool.h>
#include <stdint.h>

/* Compute S = r + c * sk mod Fs from canonical little-endian scalars.
 * The caller must obtain r from fresh device entropy and authorize the
 * transaction before releasing a signature. This isolated helper has no
 * access to device keys, APDUs, or the touchscreen. Rejected non-null scalar
 * inputs leave response bytes unchanged. The caller must initialize all
 * response bytes before calling because masked output release reads them. */
bool blue_redjubjub_response(uint8_t response[32],
    const uint8_t nonce[32], const uint8_t challenge[32],
    const uint8_t secret[32]);

#endif
