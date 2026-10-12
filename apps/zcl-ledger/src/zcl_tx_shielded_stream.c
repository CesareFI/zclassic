/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "zcl_tx_shielded_stream.h"

#include <string.h>

enum { ZCL_MAX_WIRE = 2 * 1024 * 1024 };
enum { ZCL_MAX_MONEY_ZAT = 2100000000000000ULL };

typedef enum {
    HEADER, INPUT_COUNT, OUTPOINT, INPUT_SCRIPT_LENGTH, INPUT_SCRIPT,
    SEQUENCE, OUTPUT_COUNT, AMOUNT, OUTPUT_SCRIPT_LENGTH, OUTPUT_SCRIPT,
    LOCK_TIME, EXPIRY_HEIGHT, VALUE_BALANCE, SPEND_COUNT, SPEND_ITEM,
    SOUTPUT_COUNT, SOUTPUT_ITEM, JOIN_COUNT, JOIN_ITEM, JOIN_PUBKEY,
    JOIN_SIGNATURE, BINDING_SIGNATURE, DONE
} phase;

static_assert(sizeof(zcl_tx_shielded_stream) <= 112,
    "Shielded stream state exceeds its bounded-memory budget");

static bool fail(zcl_tx_shielded_stream *state) {
    memset(state, 0, sizeof *state);
    state->failed = true;
    return false;
}

static void fixed(zcl_tx_shielded_stream *state, phase next,
    uint32_t length) {
    state->phase = (uint8_t)next;
    state->field_need = length;
    state->field_used = 0;
}

static void compact(zcl_tx_shielded_stream *state, phase next) {
    state->phase = (uint8_t)next;
    state->var_value = 0;
    state->var_width = state->var_used = 0;
}

static uint32_t little_u32(const uint8_t *bytes) {
    return (uint32_t)bytes[0] | ((uint32_t)bytes[1] << 8) |
        ((uint32_t)bytes[2] << 16) | ((uint32_t)bytes[3] << 24);
}

static uint64_t little_u64(const uint8_t *bytes) {
    uint64_t value = 0;
    for (unsigned i = 0; i < 8; ++i)
        value |= (uint64_t)bytes[i] << (8 * i);
    return value;
}

static bool compact_phase(uint8_t current) {
    return current == INPUT_COUNT || current == INPUT_SCRIPT_LENGTH ||
        current == OUTPUT_COUNT || current == OUTPUT_SCRIPT_LENGTH ||
        current == SPEND_COUNT || current == SOUTPUT_COUNT ||
        current == JOIN_COUNT;
}

static bool output_complete(zcl_tx_shielded_stream *state) {
    if (++state->item_index < state->facts.transparent_outputs)
        fixed(state, AMOUNT, 8);
    else fixed(state, LOCK_TIME, 4);
    return true;
}

static bool input_complete(zcl_tx_shielded_stream *state) {
    if (++state->item_index < state->facts.transparent_inputs)
        fixed(state, OUTPOINT, 36);
    else compact(state, OUTPUT_COUNT);
    return true;
}

static bool binding_or_done(zcl_tx_shielded_stream *state) {
    if (state->facts.sapling_spends || state->facts.sapling_outputs)
        fixed(state, BINDING_SIGNATURE, 64);
    else state->phase = DONE;
    return true;
}

static bool transparent_count(zcl_tx_shielded_stream *state) {
    uint64_t count = state->var_value;
    switch ((phase)state->phase) {
    case INPUT_COUNT:
        if (count > 65536 || count > state->expected / 41) return false;
        state->facts.transparent_inputs = (uint32_t)count;
        state->item_index = 0;
        if (count) fixed(state, OUTPOINT, 36);
        else compact(state, OUTPUT_COUNT);
        return true;
    case INPUT_SCRIPT_LENGTH:
        if (count > state->expected) return false;
        if (count) fixed(state, INPUT_SCRIPT, (uint32_t)count);
        else fixed(state, SEQUENCE, 4);
        return true;
    case OUTPUT_COUNT:
        if (count > 65536 || count > state->expected / 9) return false;
        state->facts.transparent_outputs = (uint32_t)count;
        state->item_index = 0;
        if (count) fixed(state, AMOUNT, 8);
        else fixed(state, LOCK_TIME, 4);
        return true;
    case OUTPUT_SCRIPT_LENGTH:
        if (count > state->expected) return false;
        if (count) fixed(state, OUTPUT_SCRIPT, (uint32_t)count);
        else return output_complete(state);
        return true;
    default: return false;
    }
}

static bool shielded_count(zcl_tx_shielded_stream *state) {
    uint64_t count = state->var_value;
    switch ((phase)state->phase) {
    case SPEND_COUNT:
        if (count > 4096 || count > state->expected / 384) return false;
        state->facts.sapling_spends = (uint32_t)count;
        state->item_index = 0;
        if (count) fixed(state, SPEND_ITEM, 384);
        else compact(state, SOUTPUT_COUNT);
        return true;
    case SOUTPUT_COUNT:
        if (count > 4096 || count > state->expected / 948) return false;
        state->facts.sapling_outputs = (uint32_t)count;
        state->item_index = 0;
        if (count) fixed(state, SOUTPUT_ITEM, 948);
        else compact(state, JOIN_COUNT);
        return true;
    case JOIN_COUNT:
        if (count > 4096 || count > state->expected / 1634) return false;
        state->facts.sprout_joinsplits = (uint32_t)count;
        state->item_index = 0;
        if (count) fixed(state, JOIN_ITEM, 1634);
        else return binding_or_done(state);
        return true;
    default: return false;
    }
}

static bool compact_done(zcl_tx_shielded_stream *state) {
    if (state->phase <= OUTPUT_SCRIPT_LENGTH)
        return transparent_count(state);
    return shielded_count(state);
}

static bool compact_byte(zcl_tx_shielded_stream *state, uint8_t byte) {
    if (!state->var_width) {
        if (byte < 0xfd) {
            state->var_value = byte;
            return compact_done(state);
        }
        state->var_width = byte == 0xfd ? 2 : byte == 0xfe ? 4 : 8;
        return true;
    }
    state->var_value |= (uint64_t)byte << (8u * state->var_used++);
    if (state->var_used != state->var_width) return true;
    if ((state->var_width == 2 && state->var_value < 0xfd) ||
        (state->var_width == 4 && state->var_value <= UINT16_MAX) ||
        (state->var_width == 8 && state->var_value <= UINT32_MAX))
        return false;
    return compact_done(state);
}

static bool transparent_fixed(zcl_tx_shielded_stream *state) {
    static const uint8_t header[8] = {
        4, 0, 0, 0x80, 0x85, 0x20, 0x2f, 0x89
    };
    switch ((phase)state->phase) {
    case HEADER:
        if (memcmp(state->field, header, sizeof header)) return false;
        compact(state, INPUT_COUNT);
        return true;
    case OUTPOINT: compact(state, INPUT_SCRIPT_LENGTH); return true;
    case INPUT_SCRIPT: fixed(state, SEQUENCE, 4); return true;
    case SEQUENCE: return input_complete(state);
    case AMOUNT: {
        uint64_t amount = little_u64(state->field);
        if (amount > ZCL_MAX_MONEY_ZAT ||
            amount > ZCL_MAX_MONEY_ZAT -
                state->facts.transparent_output_zat) return false;
        state->facts.transparent_output_zat += amount;
        compact(state, OUTPUT_SCRIPT_LENGTH);
        return true;
    }
    case OUTPUT_SCRIPT: return output_complete(state);
    default: return false;
    }
}

static bool shielded_fixed(zcl_tx_shielded_stream *state) {
    switch ((phase)state->phase) {
    case LOCK_TIME:
        state->facts.lock_time = little_u32(state->field);
        fixed(state, EXPIRY_HEIGHT, 4);
        return true;
    case EXPIRY_HEIGHT:
        state->facts.expiry_height = little_u32(state->field);
        fixed(state, VALUE_BALANCE, 8);
        return true;
    case VALUE_BALANCE: {
        uint64_t balance = little_u64(state->field);
        if (balance > ZCL_MAX_MONEY_ZAT &&
            balance < UINT64_MAX - ZCL_MAX_MONEY_ZAT + 1) return false;
        state->facts.value_balance_zat = balance <= ZCL_MAX_MONEY_ZAT
            ? (int64_t)balance : -(int64_t)(~balance + 1);
        compact(state, SPEND_COUNT);
        return true;
    }
    case SPEND_ITEM:
        if (++state->item_index < state->facts.sapling_spends)
            fixed(state, SPEND_ITEM, 384);
        else compact(state, SOUTPUT_COUNT);
        return true;
    case SOUTPUT_ITEM:
        if (++state->item_index < state->facts.sapling_outputs)
            fixed(state, SOUTPUT_ITEM, 948);
        else compact(state, JOIN_COUNT);
        return true;
    default: return false;
    }
}

static bool joinsplit_fixed(zcl_tx_shielded_stream *state) {
    switch ((phase)state->phase) {
    case JOIN_ITEM:
        if (++state->item_index < state->facts.sprout_joinsplits)
            fixed(state, JOIN_ITEM, 1634);
        else fixed(state, JOIN_PUBKEY, 32);
        return true;
    case JOIN_PUBKEY: fixed(state, JOIN_SIGNATURE, 64); return true;
    case JOIN_SIGNATURE: return binding_or_done(state);
    case BINDING_SIGNATURE: state->phase = DONE; return true;
    default: return false;
    }
}

static bool fixed_done(zcl_tx_shielded_stream *state) {
    if (state->phase <= OUTPUT_SCRIPT)
        return transparent_fixed(state);
    if (state->phase <= SOUTPUT_ITEM)
        return shielded_fixed(state);
    return joinsplit_fixed(state);
}

static bool stored_phase(uint8_t current) {
    return current == HEADER || current == AMOUNT || current == LOCK_TIME ||
        current == EXPIRY_HEIGHT || current == VALUE_BALANCE;
}

static bool fixed_byte(zcl_tx_shielded_stream *state, uint8_t byte) {
    if (stored_phase(state->phase)) state->field[state->field_used] = byte;
    ++state->field_used;
    return state->field_used < state->field_need || fixed_done(state);
}

static bool span_kind(const zcl_tx_shielded_stream *state,
    zcl_tx_shielded_span *kind) {
    switch ((phase)state->phase) {
    case HEADER: *kind = ZCL_SHIELDED_HEADER; return true;
    case OUTPOINT: *kind = ZCL_SHIELDED_PREVOUT; return true;
    case SEQUENCE: *kind = ZCL_SHIELDED_SEQUENCE; return true;
    case AMOUNT:
    case OUTPUT_SCRIPT_LENGTH:
    case OUTPUT_SCRIPT: *kind = ZCL_SHIELDED_OUTPUT; return true;
    case LOCK_TIME:
    case EXPIRY_HEIGHT:
    case VALUE_BALANCE: *kind = ZCL_SHIELDED_TAIL; return true;
    case SPEND_ITEM:
        *kind = ZCL_SHIELDED_SPEND;
        return state->field_used < 320;
    case SOUTPUT_ITEM: *kind = ZCL_SHIELDED_SOUTPUT; return true;
    case JOIN_ITEM:
    case JOIN_PUBKEY: *kind = ZCL_SHIELDED_JOINSPLIT; return true;
    default: return false;
    }
}

bool zcl_tx_shielded_stream_begin(zcl_tx_shielded_stream *state,
    uint32_t expected_length) {
    if (!state) return false;
    memset(state, 0, sizeof *state);
    if (expected_length < 29 || expected_length > ZCL_MAX_WIRE)
        return fail(state);
    state->expected = expected_length;
    fixed(state, HEADER, 8);
    return true;
}

static bool valid_feed(const zcl_tx_shielded_stream *state,
    const uint8_t *bytes, size_t length,
    zcl_tx_shielded_span_fn span, const void *context) {
    return !state->failed && !state->finished && bytes && length &&
        state->received <= state->expected &&
        length <= state->expected - state->received &&
        (!span || context);
}

static bool consume_one(zcl_tx_shielded_stream *state,
    const uint8_t *byte, zcl_tx_shielded_span_fn span, void *context) {
    zcl_tx_shielded_span kind;
    if (state->phase == DONE ||
        (span && span_kind(state, &kind) &&
         !span(context, kind, byte, 1))) return false;
    return compact_phase(state->phase)
        ? compact_byte(state, *byte) : fixed_byte(state, *byte);
}

bool zcl_tx_shielded_stream_feed(zcl_tx_shielded_stream *state,
    const uint8_t *bytes, size_t length,
    zcl_tx_shielded_span_fn span, void *context) {
    if (!state) return false;
    if (!valid_feed(state, bytes, length, span, context))
        return fail(state);
    for (size_t i = 0; i < length; ++i) {
        if (!consume_one(state, bytes + i, span, context))
            return fail(state);
        ++state->received;
    }
    return true;
}

bool zcl_tx_shielded_stream_finish(zcl_tx_shielded_stream *state,
    zcl_tx_shielded_facts *facts) {
    if (!state) return false;
    if (!facts || state->failed || state->finished ||
        state->phase != DONE || state->received != state->expected)
        return fail(state);
    *facts = state->facts;
    state->finished = true;
    return true;
}
