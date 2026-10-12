/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "zcl_tx_stream.h"

#include <string.h>

enum { ZCL_MAX_MONEY_ZAT = 2100000000000000ULL };
static_assert(sizeof(zcl_tx_stream) <= 160,
              "Streaming state exceeds the Blue review budget");

typedef enum {
    HEADER, INPUT_COUNT, OUTPOINT, INPUT_SCRIPT_LENGTH, SEQUENCE,
    OUTPUT_COUNT, AMOUNT, OUTPUT_SCRIPT_LENGTH, OUTPUT_SCRIPT,
    LOCK_TIME, EXPIRY_HEIGHT, VALUE_BALANCE, SAPLING_SPENDS,
    SAPLING_OUTPUTS, JOIN_SPLITS, DONE
} phase;

static bool fail(zcl_tx_stream *stream) {
    memset(stream, 0, sizeof *stream);
    stream->failed = true;
    return false;
}

static void fixed(zcl_tx_stream *stream, phase next, uint8_t length) {
    stream->phase = (uint8_t)next;
    stream->field_need = length;
    stream->field_used = 0;
}

static void compact(zcl_tx_stream *stream, phase next) {
    stream->phase = (uint8_t)next;
    stream->var_value = 0;
    stream->var_width = stream->var_used = 0;
}

static uint32_t little_u32(const uint8_t *bytes) {
    return (uint32_t)bytes[0] | ((uint32_t)bytes[1] << 8) |
           ((uint32_t)bytes[2] << 16) | ((uint32_t)bytes[3] << 24);
}

static uint64_t little_u64(const uint8_t *bytes) {
    uint64_t value = 0;
    for (unsigned i = 0; i < 8; ++i) value |= (uint64_t)bytes[i] << (8 * i);
    return value;
}

static bool output_done(zcl_tx_stream *stream,
    zcl_tx_stream_output_fn output, void *context) {
    zcl_tx_stream_output_type type;
    const uint8_t *hash;
    if (stream->field_need == 25 && stream->field[0] == 0x76 &&
        stream->field[1] == 0xa9 && stream->field[2] == 0x14 &&
        stream->field[23] == 0x88 && stream->field[24] == 0xac) {
        type = ZCL_TX_STREAM_P2PKH;
        hash = stream->field + 3;
    } else if (stream->field_need == 23 && stream->field[0] == 0xa9 &&
               stream->field[1] == 0x14 && stream->field[22] == 0x87) {
        type = ZCL_TX_STREAM_P2SH;
        hash = stream->field + 2;
    } else return false;
    if (output && !output(context, stream->output_index, stream->amount,
                          type, hash)) return false;
    ++stream->output_index;
    if (stream->output_index < stream->facts.outputs)
        fixed(stream, AMOUNT, 8);
    else fixed(stream, LOCK_TIME, 4);
    return true;
}

static bool input_done(zcl_tx_stream *stream,
    zcl_tx_stream_input_fn input, void *context) {
    if (input && !input(context, stream->input_index, stream->outpoint,
                        little_u32(stream->field))) return false;
    ++stream->input_index;
    if (stream->input_index < stream->facts.inputs)
        fixed(stream, OUTPOINT, 36);
    else compact(stream, OUTPUT_COUNT);
    return true;
}

static bool amount_done(zcl_tx_stream *stream) {
    stream->amount = little_u64(stream->field);
    if (stream->amount > ZCL_MAX_MONEY_ZAT ||
        stream->amount > ZCL_MAX_MONEY_ZAT - stream->facts.output_zat)
        return false;
    stream->facts.output_zat += stream->amount;
    compact(stream, OUTPUT_SCRIPT_LENGTH);
    return true;
}

static bool fixed_done(zcl_tx_stream *stream,
    zcl_tx_stream_input_fn input, zcl_tx_stream_output_fn output,
    void *context) {
    static const uint8_t header[8] = {
        4, 0, 0, 0x80, 0x85, 0x20, 0x2f, 0x89
    };
    switch ((phase)stream->phase) {
    case HEADER:
        if (memcmp(stream->field, header, sizeof header)) return false;
        compact(stream, INPUT_COUNT);
        return true;
    case OUTPOINT:
        memcpy(stream->outpoint, stream->field, sizeof stream->outpoint);
        compact(stream, INPUT_SCRIPT_LENGTH);
        return true;
    case SEQUENCE:
        return input_done(stream, input, context);
    case AMOUNT:
        return amount_done(stream);
    case OUTPUT_SCRIPT:
        return output_done(stream, output, context);
    case LOCK_TIME:
        stream->facts.lock_time = little_u32(stream->field);
        fixed(stream, EXPIRY_HEIGHT, 4);
        return true;
    case EXPIRY_HEIGHT:
        stream->facts.expiry_height = little_u32(stream->field);
        fixed(stream, VALUE_BALANCE, 8);
        return true;
    case VALUE_BALANCE:
        if (little_u64(stream->field)) return false;
        compact(stream, SAPLING_SPENDS);
        return true;
    default:
        return false;
    }
}

static bool compact_count_done(zcl_tx_stream *stream) {
    switch ((phase)stream->phase) {
    case INPUT_COUNT:
        if (!stream->var_value ||
            stream->var_value > ZCL_TX_STREAM_MAX_INPUTS) return false;
        stream->facts.inputs = (uint32_t)stream->var_value;
        fixed(stream, OUTPOINT, 36);
        return true;
    case INPUT_SCRIPT_LENGTH:
        if (stream->var_value) return false;
        fixed(stream, SEQUENCE, 4);
        return true;
    case OUTPUT_COUNT:
        if (!stream->var_value || stream->var_value > 65536) return false;
        stream->facts.outputs = (uint32_t)stream->var_value;
        fixed(stream, AMOUNT, 8);
        return true;
    case OUTPUT_SCRIPT_LENGTH:
        if (stream->var_value != 23 && stream->var_value != 25) return false;
        fixed(stream, OUTPUT_SCRIPT, (uint8_t)stream->var_value);
        return true;
    default:
        return false;
    }
}

static bool compact_done(zcl_tx_stream *stream) {
    if (stream->phase == INPUT_COUNT || stream->phase == INPUT_SCRIPT_LENGTH ||
        stream->phase == OUTPUT_COUNT || stream->phase == OUTPUT_SCRIPT_LENGTH)
        return compact_count_done(stream);
    switch ((phase)stream->phase) {
    case SAPLING_SPENDS:
        if (stream->var_value) return false;
        compact(stream, SAPLING_OUTPUTS);
        return true;
    case SAPLING_OUTPUTS:
        if (stream->var_value) return false;
        compact(stream, JOIN_SPLITS);
        return true;
    case JOIN_SPLITS:
        if (stream->var_value) return false;
        stream->phase = DONE;
        return true;
    default:
        return false;
    }
}

static bool compact_phase(uint8_t current) {
    return current == INPUT_COUNT || current == INPUT_SCRIPT_LENGTH ||
           current == OUTPUT_COUNT || current == OUTPUT_SCRIPT_LENGTH ||
           current == SAPLING_SPENDS || current == SAPLING_OUTPUTS ||
           current == JOIN_SPLITS;
}

static bool compact_byte(zcl_tx_stream *stream, uint8_t byte);

static bool consume_byte(zcl_tx_stream *stream, uint8_t byte,
    zcl_tx_stream_input_fn input, zcl_tx_stream_output_fn output,
    void *context) {
    if (stream->phase == DONE) return false;
    if (compact_phase(stream->phase)) return compact_byte(stream, byte);
    stream->field[stream->field_used++] = byte;
    return stream->field_used < stream->field_need ||
           fixed_done(stream, input, output, context);
}

static bool compact_byte(zcl_tx_stream *stream, uint8_t byte) {
    if (!stream->var_width) {
        if (byte < 0xfd) {
            stream->var_value = byte;
            return compact_done(stream);
        }
        stream->var_width = byte == 0xfd ? 2 : byte == 0xfe ? 4 : 8;
        return true;
    }
    stream->var_value |= (uint64_t)byte << (8u * stream->var_used++);
    if (stream->var_used != stream->var_width) return true;
    if ((stream->var_width == 2 && stream->var_value < 0xfd) ||
        (stream->var_width == 4 && stream->var_value <= UINT16_MAX) ||
        (stream->var_width == 8 && stream->var_value <= UINT32_MAX))
        return false;
    return compact_done(stream);
}

bool zcl_tx_stream_begin(zcl_tx_stream *stream, uint32_t expected_length) {
    if (!stream) return false;
    memset(stream, 0, sizeof *stream);
    if (expected_length < 29 || expected_length > ZCL_TX_STREAM_MAX_BYTES)
        return fail(stream);
    stream->expected = expected_length;
    fixed(stream, HEADER, 8);
    return true;
}

bool zcl_tx_stream_feed(zcl_tx_stream *stream, const uint8_t *bytes,
    size_t length, zcl_tx_stream_input_fn input,
    zcl_tx_stream_output_fn output, void *context) {
    if (!stream) return false;
    if (stream->failed || stream->finished || !bytes || !length ||
        stream->received > stream->expected ||
        length > stream->expected - stream->received) return fail(stream);
    for (size_t i = 0; i < length; ++i) {
        if (!consume_byte(stream, bytes[i], input, output, context))
            return fail(stream);
        ++stream->received;
    }
    return true;
}

bool zcl_tx_stream_finish(zcl_tx_stream *stream,
    zcl_tx_stream_facts *facts) {
    if (!stream) return false;
    if (!facts) return fail(stream);
    if (stream->failed || stream->finished || stream->phase != DONE ||
        stream->received != stream->expected) return fail(stream);
    *facts = stream->facts;
    stream->finished = true;
    return true;
}
