/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#ifndef ZCL_BLUE_SHIELDED_REVIEW_CLIENT_H
#define ZCL_BLUE_SHIELDED_REVIEW_CLIENT_H

#include "zcl_tx_review.h"

#include <stdbool.h>

typedef bool (*blue_shielded_exchange_fn)(void *context,
    const uint8_t *apdu, size_t apdu_length,
    uint8_t *reply, size_t capacity, size_t *reply_length);

/* Snapshots the Sapling-v4 wire, replays that copy six times, and checks
 * every device reply against the independent host parser and ZIP-243
 * implementation. The caller keeps the wire stable through return. Failure
 * after a valid local parse sends a best-effort erase command and leaves
 * outputs zero. Outputs must not overlap each other or the wire; rejected
 * overlap leaves all buffers untouched and sends no command. No signing or
 * trusted chain-tip decision is provided by this read-only client. */
bool blue_shielded_review_client_run(const uint8_t *wire, size_t length,
    uint32_t branch, blue_shielded_exchange_fn exchange, void *context,
    zcl_tx_review *review, uint8_t digest[32]);

typedef struct {
    zcl_tx_review facts;
    uint8_t zip243_digest[32];
    uint8_t wire_sha256[32];
    uint32_t branch_id;
    uint32_t wire_length;
} blue_shielded_review_receipt;

/* Keeps the checked facts, branch, length, digest, and full-wire SHA-256 in
 * one result. Output may not overlap wire; overlap rejection preserves both.
 * Other failures clear the entire receipt. The caller must recheck mutable
 * wire before later use. This read-only receipt grants no signing approval. */
bool blue_shielded_review_client_run_receipt(const uint8_t *wire,
    size_t length, uint32_t branch, blue_shielded_exchange_fn exchange,
    void *context, blue_shielded_review_receipt *receipt);

#endif
