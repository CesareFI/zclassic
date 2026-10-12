/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#ifndef ZCL_BLUE_REDJUBJUB_SIGN_ISOLATED_H
#define ZCL_BLUE_REDJUBJUB_SIGN_ISOLATED_H

#include <stdbool.h>
#include <stdint.h>

/* Produce a SpendAuth RedJubjub signature over a 32-byte transaction digest.
 * The caller must supply fresh device CSPRNG entropy, a protected canonical
 * secret scalar, and an independently reviewed and approved digest. This
 * isolated candidate is not wired to BOLOS keys or an APDU; target timing
 * has not been validated for secret device material. The caller retains and
 * must erase its secret and entropy buffers. The signature buffer must not
 * overlap any input. On an overlap rejection, inputs and output are
 * preserved; other rejected calls clear a non-null signature buffer. */
bool blue_redjubjub_sign_isolated(uint8_t signature[64],
    const uint8_t secret[32], const uint8_t entropy[80],
    const uint8_t transaction_digest[32]);

#endif
