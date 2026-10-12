/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#ifndef ZCL_TX_STREAM_H
#define ZCL_TX_STREAM_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#if !defined(__STDC_VERSION__) || __STDC_VERSION__ < 202311L
#error "ZCL streaming transaction parsing requires ISO C23"
#endif

enum { ZCL_TX_STREAM_MAX_INPUTS = 16,
       ZCL_TX_STREAM_MAX_BYTES = 2 * 1024 * 1024 };

typedef enum {
    ZCL_TX_STREAM_P2PKH,
    ZCL_TX_STREAM_P2SH
} zcl_tx_stream_output_type;

typedef struct {
    uint32_t inputs;
    uint32_t outputs;
    uint64_t output_zat;
    uint32_t lock_time;
    uint32_t expiry_height;
} zcl_tx_stream_facts;

typedef bool (*zcl_tx_stream_input_fn)(void *context, uint32_t index,
    const uint8_t outpoint[36], uint32_t sequence);
typedef bool (*zcl_tx_stream_output_fn)(void *context, uint32_t index,
    uint64_t amount_zat, zcl_tx_stream_output_type type,
    const uint8_t hash160[20]);

typedef struct {
    uint32_t expected, received, input_index, output_index;
    zcl_tx_stream_facts facts;
    uint64_t var_value, amount;
    uint8_t outpoint[36], field[36];
    uint8_t phase, field_need, field_used, var_width, var_used;
    bool failed, finished;
} zcl_tx_stream;

/* Input/output callbacks receive provisional facts during upload. Only a
 * successful finish makes the returned aggregate facts usable. A callback
 * must copy bytes it needs after return. Any failure invalidates the stream. */
bool zcl_tx_stream_begin(zcl_tx_stream *stream, uint32_t expected_length);
bool zcl_tx_stream_feed(zcl_tx_stream *stream, const uint8_t *bytes,
    size_t length, zcl_tx_stream_input_fn input,
    zcl_tx_stream_output_fn output, void *context);
bool zcl_tx_stream_finish(zcl_tx_stream *stream,
    zcl_tx_stream_facts *facts);

#endif
