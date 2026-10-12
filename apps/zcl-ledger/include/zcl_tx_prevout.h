/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#ifndef ZCL_TX_PREVOUT_H
#define ZCL_TX_PREVOUT_H

#include "zcl_zip243.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#if !defined(__STDC_VERSION__) || __STDC_VERSION__ < 202311L
#error "ZCL prevout binding requires ISO C23"
#endif

enum { ZCL_TX_PREFLIGHT_MAX_INPUTS = 16 };

typedef bool (*zcl_tx_sha256_fn)(const uint8_t *bytes, size_t length,
                                  uint8_t digest[32]);

typedef struct {
    const uint8_t *wire;
    size_t length;
} zcl_tx_previous_transaction;

typedef struct {
    uint32_t transparent_inputs;
    uint32_t transparent_outputs;
    uint64_t input_zat;
    uint64_t output_zat;
    uint64_t fee_zat;
} zcl_tx_transparent_facts;

/* Binds every input to a supplied v1-v4 previous transaction by SHA-256d txid,
 * selects its P2PKH output, and derives the total and fee. This establishes
 * byte identity, not UTXO existence, chain inclusion, maturity, or ownership.
 * Only unsigned, all-transparent v4 P2PKH-input transactions with standard
 * P2PKH/P2SH outputs are accepted. Failure leaves facts untouched. */
int zcl_tx_transparent_preflight(const uint8_t *wire, size_t length,
    const zcl_tx_previous_transaction *previous, size_t previous_count,
    zcl_tx_sha256_fn sha256, zcl_tx_transparent_facts *facts);

/* Computes ZIP-243 SIGHASH_ALL with script and amount taken from a hash-bound
 * v1-v4 P2PKH prevout. The caller must still verify chain state and branch ID;
 * this function grants no signing authority. */
int zcl_tx_hash_bound_digest(const uint8_t *wire, size_t length,
    uint32_t input_index, zcl_tx_previous_transaction previous,
    uint32_t branch_id, zcl_tx_sha256_fn sha256,
    const zcl_zip243_hasher *hasher, uint8_t digest[32]);

/* Atomically binds every input to its supplied previous transaction, derives
 * the fee, and computes one ZIP-243 SIGHASH_ALL digest per input. On failure,
 * facts and digests remain unchanged. The caller must independently establish
 * UTXO status, ownership, and the active consensus branch before signing. */
int zcl_tx_transparent_bound_digests(const uint8_t *wire, size_t length,
    const zcl_tx_previous_transaction *previous, size_t previous_count,
    uint32_t branch_id, zcl_tx_sha256_fn sha256,
    const zcl_zip243_hasher *hasher, zcl_tx_transparent_facts *facts,
    uint8_t (*digests)[32], size_t digest_capacity);

#endif
