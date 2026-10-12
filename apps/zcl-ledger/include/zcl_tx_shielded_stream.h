/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#ifndef ZCL_TX_SHIELDED_STREAM_H
#define ZCL_TX_SHIELDED_STREAM_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#if !defined(__STDC_VERSION__) || __STDC_VERSION__ < 202311L
#error "Shielded transaction streaming requires ISO C23"
#endif

typedef enum {
    ZCL_SHIELDED_HEADER,
    ZCL_SHIELDED_PREVOUT,
    ZCL_SHIELDED_SEQUENCE,
    ZCL_SHIELDED_OUTPUT,
    ZCL_SHIELDED_TAIL,
    ZCL_SHIELDED_SPEND,
    ZCL_SHIELDED_SOUTPUT,
    ZCL_SHIELDED_JOINSPLIT
} zcl_tx_shielded_span;

typedef bool (*zcl_tx_shielded_span_fn)(void *context,
    zcl_tx_shielded_span span, const uint8_t *bytes, size_t length);

typedef struct {
    uint32_t transparent_inputs, transparent_outputs;
    uint32_t sapling_spends, sapling_outputs, sprout_joinsplits;
    uint64_t transparent_output_zat;
    int64_t value_balance_zat;
    uint32_t lock_time, expiry_height;
} zcl_tx_shielded_facts;

typedef struct {
    zcl_tx_shielded_facts facts;
    uint32_t expected, received, field_need, field_used, item_index;
    uint64_t var_value;
    uint8_t field[8], phase, var_width, var_used;
    bool failed, finished;
} zcl_tx_shielded_stream;

/* Callbacks receive provisional byte spans; only finish authenticates the
 * structural scan. A signer must also bind repeated passes to identical wire
 * bytes and verify the active consensus branch before using any digest. */
bool zcl_tx_shielded_stream_begin(zcl_tx_shielded_stream *state,
    uint32_t expected_length);
bool zcl_tx_shielded_stream_feed(zcl_tx_shielded_stream *state,
    const uint8_t *bytes, size_t length,
    zcl_tx_shielded_span_fn span, void *context);
bool zcl_tx_shielded_stream_finish(zcl_tx_shielded_stream *state,
    zcl_tx_shielded_facts *facts);

#endif
