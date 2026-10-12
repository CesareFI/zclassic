/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#ifndef ZCL_BLUE_WALLET_SIGNER_DEVICE_H
#define ZCL_BLUE_WALLET_SIGNER_DEVICE_H

#include "blue_payment_sign.h"

/* Derives only m/44'/147'/0'/0/0 or m/44'/147'/0'/1/0. Context must point
 * to the account hashes independently derived at app startup. The public
 * key must match the selected account hash before ECDSA runs. Must run under
 * the app's BOLOS exception cleanup frame. Output buffers and length must
 * not overlap each other, the reviewed digest, or account hashes. Overlap
 * returns false without writing caller storage. */
bool blue_wallet_sign_digest(void *context, uint8_t path,
    const uint8_t digest[32], uint8_t public_key[33],
    uint8_t signature[BLUE_ECDSA_DER_MAX], size_t *signature_length);
bool blue_wallet_public_hash160(const uint8_t compressed[33],
    uint8_t hash160[20]);
void blue_wallet_signer_wipe(void);

#endif
