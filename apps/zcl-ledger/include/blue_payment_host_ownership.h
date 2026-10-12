/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#ifndef ZCL_BLUE_PAYMENT_HOST_OWNERSHIP_H
#define ZCL_BLUE_PAYMENT_HOST_OWNERSHIP_H

#include "blue_payment_screen.h"
#include "zcl_tx_prevout.h"

typedef struct {
    zcl_tx_transparent_facts facts;
    uint8_t paths[ZCL_TX_PREFLIGHT_MAX_INPUTS];
    uint8_t hashes[ZCL_TX_PREFLIGHT_MAX_INPUTS][20];
} blue_payment_host_ownership;

/* Classifies every hash-bound P2PKH input against the two fixed Blue paths.
 * The caller must obtain both hashes from validated device public keys and
 * independently verify UTXO status and chain state. This grants no signing
 * authority. On failure, result is unchanged. */
bool blue_payment_host_classify_inputs(const uint8_t *wire, size_t length,
    const zcl_tx_previous_transaction *previous, size_t previous_count,
    zcl_tx_sha256_fn sha256, const uint8_t external[20],
    const uint8_t internal[20], blue_payment_host_ownership *result);

/* Proposes the fixed internal path for a hash-bound input that does not match
 * the validated external key. The result is NOT proof of internal ownership.
 * A caller may sign only after the Blue independently binds every previous
 * output to its own keys and each returned signature verifies against the
 * original previous-output hash and digest. Failure leaves result unchanged. */
bool blue_payment_host_propose_paths(const uint8_t *wire, size_t length,
    const zcl_tx_previous_transaction *previous, size_t previous_count,
    zcl_tx_sha256_fn sha256, const uint8_t external[20],
    blue_payment_host_ownership *result);

#endif
