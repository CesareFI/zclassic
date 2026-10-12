/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#ifndef ZCL_TX_PREVIOUS_STREAM_H
#define ZCL_TX_PREVIOUS_STREAM_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#if !defined(__STDC_VERSION__) || __STDC_VERSION__ < 202311L
#error "ZCL previous-transaction streaming requires ISO C23"
#endif

enum { ZCL_TX_PREVIOUS_STREAM_MAX_BYTES = 2 * 1024 * 1024 };

typedef struct {
    void *context;
    bool (*init)(void *context);
    bool (*update)(void *context, const uint8_t *bytes, size_t length);
    bool (*final)(void *context, uint8_t digest[32]);
} zcl_tx_previous_sha256;

typedef struct {
    uint64_t value_zat;
    uint8_t script[25];
} zcl_tx_previous_p2pkh;

typedef struct {
    zcl_tx_previous_sha256 hash;
    uint32_t expected, received, version, selected_index, index, count;
    uint32_t item_remaining;
    uint64_t var_value, total_zat, value_zat;
    uint8_t field[36], selected_script[25];
    uint8_t field_need, field_used, phase, var_width, var_used;
    bool selected, shielded, joinsplits, failed, finished;
    uint64_t selected_value_zat;
} zcl_tx_previous_stream;

/* Streams an exact v1-v4 previous transaction with bounded state. Finish
 * returns a selected P2PKH output only when the complete SHA-256d wire ID
 * equals expected_txid. The result says nothing about UTXO status, proofs,
 * signatures, maturity, or ownership. Failure leaves output unchanged. */
bool zcl_tx_previous_stream_begin(zcl_tx_previous_stream *stream,
    uint32_t expected_length, uint32_t selected_index,
    zcl_tx_previous_sha256 hash);
bool zcl_tx_previous_stream_feed(zcl_tx_previous_stream *stream,
    const uint8_t *bytes, size_t length);
bool zcl_tx_previous_stream_finish(zcl_tx_previous_stream *stream,
    const uint8_t expected_txid[32], zcl_tx_previous_p2pkh *output);
void zcl_tx_previous_stream_abort(zcl_tx_previous_stream *stream);

#endif
