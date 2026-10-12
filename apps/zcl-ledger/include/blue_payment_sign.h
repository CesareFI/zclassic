/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#ifndef ZCL_BLUE_PAYMENT_SIGN_H
#define ZCL_BLUE_PAYMENT_SIGN_H

#include "blue_payment_apdu.h"
#include "blue_ecdsa_der.h"

enum { BLUE_PAYMENT_SIGN_REPLY_MAX = 36 + BLUE_ECDSA_DER_MAX };

typedef bool (*blue_payment_sign_digest_fn)(void *context, uint8_t path,
    const uint8_t digest[32], uint8_t public_key[33],
    uint8_t signature[BLUE_ECDSA_DER_MAX], size_t *signature_length);
typedef bool (*blue_payment_pubkey_hash_fn)(const uint8_t public_key[33],
    uint8_t hash160[20]);

/* Consumes the next touchscreen-approved digest and emits index, path,
 * compressed public key, DER length, and canonical low-S DER signature.
 * The caller must independently verify the signature and append SIGHASH_ALL
 * when assembling a transparent scriptSig. State, owned hashes, reply, and
 * reply-length storage must be disjoint. Any failure aborts the review. */
bool blue_payment_sign_next(blue_payment_apdu *state, uint8_t index,
    const blue_payment_owned_hashes *owned,
    blue_payment_sign_digest_fn signer, void *signer_context,
    blue_payment_pubkey_hash_fn hash,
    uint8_t *reply, size_t capacity, size_t *reply_length);

/* Candidate CLA A5 / INS 29 command: exactly one input-index byte. The
 * device routes it only after the final touchscreen signing approval.
 * Request and reply may share the APDU buffer, but neither may overlap
 * state or owned hashes; reply length must be disjoint from all buffers. */
uint16_t blue_payment_sign_command(blue_payment_apdu *state,
    const uint8_t *apdu, size_t apdu_length,
    const blue_payment_owned_hashes *owned,
    blue_payment_sign_digest_fn signer, void *signer_context,
    blue_payment_pubkey_hash_fn hash,
    uint8_t *reply, size_t capacity, size_t *reply_length);

#endif
