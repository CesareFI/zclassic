/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "zcl_tx_previous_stream.h"

#include <string.h>

enum { MAX_MONEY_ZAT = 2100000000000000ULL };

typedef enum {
    HEADER, GROUP, INPUT_COUNT, INPUT_OUTPOINT, INPUT_SCRIPT_LENGTH,
    INPUT_SCRIPT, SEQUENCE, OUTPUT_COUNT, AMOUNT, OUTPUT_SCRIPT_LENGTH,
    OUTPUT_SCRIPT, LOCK_TIME, EXPIRY, BALANCE, SPEND_COUNT, SPEND_ITEMS,
    SHIELDED_OUTPUT_COUNT, SHIELDED_OUTPUT_ITEMS, JOIN_COUNT, JOIN_ITEMS,
    JOIN_AUTH, BINDING, DONE
} phase;

static_assert(sizeof(zcl_tx_previous_stream) <= 192,
              "Previous-transaction streaming state exceeds Blue budget");

void zcl_tx_previous_stream_abort(zcl_tx_previous_stream *stream) {
    if (!stream) return;
    memset(stream, 0, sizeof *stream);
    stream->failed = true;
}

static void fixed(zcl_tx_previous_stream *stream, phase next, uint8_t count) {
    stream->phase = (uint8_t)next;
    stream->field_need = count;
    stream->field_used = 0;
}

static void compact(zcl_tx_previous_stream *stream, phase next) {
    stream->phase = (uint8_t)next;
    stream->var_value = 0;
    stream->var_width = 0;
    stream->var_used = 0;
}

static void skip(zcl_tx_previous_stream *stream, phase next, uint32_t count) {
    stream->phase = (uint8_t)next;
    stream->item_remaining = count;
}

static uint32_t little_u32(const uint8_t *bytes) {
    return (uint32_t)bytes[0] | ((uint32_t)bytes[1] << 8) |
        ((uint32_t)bytes[2] << 16) | ((uint32_t)bytes[3] << 24);
}

static uint64_t little_u64(const uint8_t *bytes) {
    uint64_t result = 0;
    for (unsigned i = 0; i < 8; ++i)
        result |= (uint64_t)bytes[i] << (8 * i);
    return result;
}

static void after_joins(zcl_tx_previous_stream *stream) {
    if (stream->shielded) skip(stream, BINDING, 64);
    else stream->phase = DONE;
}

static bool previous_output_done(zcl_tx_previous_stream *stream) {
    if (stream->index == stream->selected_index) {
        const uint8_t *script = stream->selected_script;
        if (stream->item_remaining != 0 ||
            script[0] != 0x76 || script[1] != 0xa9 ||
            script[2] != 0x14 || script[23] != 0x88 ||
            script[24] != 0xac) return false;
        stream->selected = true;
        stream->selected_value_zat = stream->value_zat;
    }
    ++stream->index;
    if (stream->index < stream->count) fixed(stream, AMOUNT, 8);
    else fixed(stream, LOCK_TIME, 4);
    return true;
}

static bool skip_done(zcl_tx_previous_stream *stream) {
    switch ((phase)stream->phase) {
    case INPUT_OUTPOINT: compact(stream, INPUT_SCRIPT_LENGTH); return true;
    case INPUT_SCRIPT: fixed(stream, SEQUENCE, 4); return true;
    case OUTPUT_SCRIPT: return previous_output_done(stream);
    case SPEND_ITEMS: compact(stream, SHIELDED_OUTPUT_COUNT); return true;
    case SHIELDED_OUTPUT_ITEMS: compact(stream, JOIN_COUNT); return true;
    case JOIN_ITEMS: skip(stream, JOIN_AUTH, 96); return true;
    case JOIN_AUTH: after_joins(stream); return true;
    case BINDING: stream->phase = DONE; return true;
    default: return false;
    }
}

static bool header_done(zcl_tx_previous_stream *stream) {
    uint32_t header = little_u32(stream->field);
    stream->version = header == 1 || header == 2 ? header :
        header == 0x80000003 ? 3 : header == 0x80000004 ? 4 : 0;
    if (!stream->version) return false;
    if (stream->version >= 3) fixed(stream, GROUP, 4);
    else compact(stream, INPUT_COUNT);
    return true;
}

static bool fixed_tail_done(zcl_tx_previous_stream *stream) {
    switch ((phase)stream->phase) {
    case LOCK_TIME:
        if (stream->version >= 3) fixed(stream, EXPIRY, 4);
        else if (stream->version == 2) compact(stream, JOIN_COUNT);
        else stream->phase = DONE;
        return true;
    case EXPIRY:
        if (stream->version == 4) fixed(stream, BALANCE, 8);
        else compact(stream, JOIN_COUNT);
        return true;
    case BALANCE: {
        uint64_t balance = little_u64(stream->field);
        if (balance > MAX_MONEY_ZAT &&
            balance < UINT64_MAX - MAX_MONEY_ZAT + 1) return false;
        compact(stream, SPEND_COUNT);
        return true;
    }
    default: return false;
    }
}

static bool fixed_done(zcl_tx_previous_stream *stream) {
    switch ((phase)stream->phase) {
    case HEADER: return header_done(stream);
    case GROUP:
        if (little_u32(stream->field) !=
            (stream->version == 3 ? 0x03c48270u : 0x892f2085u))
            return false;
        compact(stream, INPUT_COUNT);
        return true;
    case SEQUENCE:
        ++stream->index;
        if (stream->index < stream->count)
            skip(stream, INPUT_OUTPOINT, 36);
        else compact(stream, OUTPUT_COUNT);
        return true;
    case AMOUNT:
        stream->value_zat = little_u64(stream->field);
        if (stream->value_zat > MAX_MONEY_ZAT - stream->total_zat)
            return false;
        stream->total_zat += stream->value_zat;
        compact(stream, OUTPUT_SCRIPT_LENGTH);
        return true;
    default: return fixed_tail_done(stream);
    }
}

static bool vector_count(zcl_tx_previous_stream *stream,
    phase items, uint32_t width, phase next) {
    if (stream->var_value > 4096 ||
        stream->var_value > (stream->expected - stream->received) / width)
        return false;
    if (stream->var_value) skip(stream, items,
                                (uint32_t)stream->var_value * width);
    else compact(stream, next);
    return true;
}

static bool compact_wire_done(zcl_tx_previous_stream *stream) {
    switch ((phase)stream->phase) {
    case INPUT_COUNT:
        if (stream->var_value > 65536) return false;
        stream->count = (uint32_t)stream->var_value;
        stream->index = 0;
        if (stream->count) skip(stream, INPUT_OUTPOINT, 36);
        else compact(stream, OUTPUT_COUNT);
        return true;
    case INPUT_SCRIPT_LENGTH:
        if (stream->var_value > 10000) return false;
        if (stream->var_value)
            skip(stream, INPUT_SCRIPT, (uint32_t)stream->var_value);
        else fixed(stream, SEQUENCE, 4);
        return true;
    case OUTPUT_COUNT:
        if (stream->var_value > 65536 ||
            stream->selected_index >= stream->var_value) return false;
        stream->count = (uint32_t)stream->var_value;
        stream->index = 0;
        fixed(stream, AMOUNT, 8);
        return true;
    case OUTPUT_SCRIPT_LENGTH:
        if (stream->var_value > 10000 ||
            (stream->index == stream->selected_index &&
             stream->var_value != sizeof stream->selected_script))
            return false;
        if (!stream->var_value) return previous_output_done(stream);
        skip(stream, OUTPUT_SCRIPT, (uint32_t)stream->var_value);
        return true;
    default: return false;
    }
}

static bool compact_tail_done(zcl_tx_previous_stream *stream) {
    switch ((phase)stream->phase) {
    case SPEND_COUNT:
        stream->shielded = stream->var_value != 0;
        return vector_count(stream, SPEND_ITEMS, 384,
                            SHIELDED_OUTPUT_COUNT);
    case SHIELDED_OUTPUT_COUNT:
        stream->shielded |= stream->var_value != 0;
        return vector_count(stream, SHIELDED_OUTPUT_ITEMS, 948, JOIN_COUNT);
    case JOIN_COUNT:
        stream->joinsplits = stream->var_value != 0;
        if (!stream->joinsplits) { after_joins(stream); return true; }
        return vector_count(stream, JOIN_ITEMS,
                            stream->version == 4 ? 1634 : 1738, JOIN_AUTH);
    default: return false;
    }
}

static bool previous_compact_done(zcl_tx_previous_stream *stream) {
    return stream->phase <= OUTPUT_SCRIPT_LENGTH ?
        compact_wire_done(stream) : compact_tail_done(stream);
}

static bool compact_phase(uint8_t current) {
    return current == INPUT_COUNT || current == INPUT_SCRIPT_LENGTH ||
        current == OUTPUT_COUNT || current == OUTPUT_SCRIPT_LENGTH ||
        current == SPEND_COUNT || current == SHIELDED_OUTPUT_COUNT ||
        current == JOIN_COUNT;
}

static bool compact_byte(zcl_tx_previous_stream *stream, uint8_t byte) {
    if (!stream->var_width) {
        if (byte < 0xfd) {
            stream->var_value = byte;
            return previous_compact_done(stream);
        }
        stream->var_width = byte == 0xfd ? 2 : byte == 0xfe ? 4 : 8;
        return true;
    }
    stream->var_value |= (uint64_t)byte << (8u * stream->var_used++);
    if (stream->var_used < stream->var_width) return true;
    if ((stream->var_width == 2 && stream->var_value < 0xfd) ||
        (stream->var_width == 4 && stream->var_value <= UINT16_MAX) ||
        (stream->var_width == 8 && stream->var_value <= UINT32_MAX))
        return false;
    return previous_compact_done(stream);
}

static bool skip_phase(uint8_t current) {
    return current == INPUT_OUTPOINT || current == INPUT_SCRIPT ||
        current == OUTPUT_SCRIPT || current == SPEND_ITEMS ||
        current == SHIELDED_OUTPUT_ITEMS || current == JOIN_ITEMS ||
        current == JOIN_AUTH || current == BINDING;
}

static bool consume_byte(zcl_tx_previous_stream *stream, uint8_t byte) {
    if (stream->phase == DONE) return false;
    if (compact_phase(stream->phase)) return compact_byte(stream, byte);
    if (skip_phase(stream->phase)) {
        if (stream->phase == OUTPUT_SCRIPT &&
            stream->index == stream->selected_index)
            stream->selected_script[25 - stream->item_remaining] = byte;
        if (!--stream->item_remaining) return skip_done(stream);
        return true;
    }
    stream->field[stream->field_used++] = byte;
    return stream->field_used < stream->field_need || fixed_done(stream);
}

bool zcl_tx_previous_stream_begin(zcl_tx_previous_stream *stream,
    uint32_t expected_length, uint32_t selected_index,
    zcl_tx_previous_sha256 hash) {
    if (!stream) return false;
    zcl_tx_previous_stream_abort(stream);
    if (expected_length < 10 ||
        expected_length > ZCL_TX_PREVIOUS_STREAM_MAX_BYTES ||
        !hash.context || !hash.init || !hash.update || !hash.final ||
        !hash.init(hash.context)) return false;
    stream->failed = false;
    stream->expected = expected_length;
    stream->selected_index = selected_index;
    stream->hash = hash;
    fixed(stream, HEADER, 4);
    return true;
}

bool zcl_tx_previous_stream_feed(zcl_tx_previous_stream *stream,
    const uint8_t *bytes, size_t length) {
    if (!stream) return false;
    if (stream->failed || stream->finished || !bytes || !length ||
        stream->received > stream->expected ||
        length > stream->expected - stream->received ||
        !stream->hash.update(stream->hash.context, bytes, length)) {
        zcl_tx_previous_stream_abort(stream);
        return false;
    }
    for (size_t i = 0; i < length; ++i) {
        if (!consume_byte(stream, bytes[i])) {
            zcl_tx_previous_stream_abort(stream);
            return false;
        }
        ++stream->received;
    }
    return true;
}

bool zcl_tx_previous_stream_finish(zcl_tx_previous_stream *stream,
    const uint8_t expected_txid[32], zcl_tx_previous_p2pkh *output) {
    if (!stream) return false;
    if (!expected_txid || !output || stream->failed || stream->finished ||
        stream->phase != DONE || stream->received != stream->expected ||
        !stream->selected) {
        zcl_tx_previous_stream_abort(stream);
        return false;
    }
    uint8_t first[32], txid[32];
    bool valid = stream->hash.final(stream->hash.context, first) &&
        stream->hash.init(stream->hash.context) &&
        stream->hash.update(stream->hash.context, first, sizeof first) &&
        stream->hash.final(stream->hash.context, txid) &&
        memcmp(txid, expected_txid, sizeof txid) == 0;
    memset(first, 0, sizeof first);
    memset(txid, 0, sizeof txid);
    if (!valid) {
        zcl_tx_previous_stream_abort(stream);
        return false;
    }
    *output = (zcl_tx_previous_p2pkh){.value_zat = stream->selected_value_zat};
    memcpy(output->script, stream->selected_script, sizeof output->script);
    stream->finished = true;
    return true;
}
