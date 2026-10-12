/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#ifndef ZCL_BLUE_PAYMENT_HOST_VERIFY_H
#define ZCL_BLUE_PAYMENT_HOST_VERIFY_H

#include "blue_payment_sign.h"

typedef bool (*blue_payment_verify_signature_fn)(void *context,
    const uint8_t public_key[33], const uint8_t digest[32],
    const uint8_t *der, size_t der_length);

typedef struct {
    uint8_t index, path;
    uint8_t digest[32];
    uint8_t public_key[33];
    uint8_t der[BLUE_ECDSA_DER_MAX];
    uint8_t der_length;
} blue_payment_verified_signature;

/* Accepts one INS 29 response only for the expected reviewed input.
 * The verifier callback must check ECDSA over the exact ZIP-243 digest.
 * Result must be disjoint from the reply, expected hash, and digest. An
 * overlap fails before writing either buffer; callers must ignore result on
 * failure. Reply, hash, and digest inputs must stay unchanged through both
 * callbacks. Callback-facing copies must also stay unchanged. No reply bytes
 * are copied to a disjoint result unless every check passes. */
bool blue_payment_host_verify(const uint8_t *reply, size_t reply_length,
    uint8_t expected_index, uint8_t expected_path,
    const uint8_t expected_hash160[20], const uint8_t digest[32],
    blue_payment_pubkey_hash_fn hash,
    blue_payment_verify_signature_fn verify, void *verify_context,
    blue_payment_verified_signature *result);

#endif
