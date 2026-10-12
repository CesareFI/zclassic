/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "zcl_tx_shielded_replay.h"

#include <string.h>

static const uint8_t section_personal[6][17] = {
    "ZcashPrevoutHash", "ZcashSequencHash", "ZcashOutputsHash",
    "ZcashJSplitsHash", "ZcashSSpendsHash", "ZcashSOutputHash"
};

static const zcl_tx_shielded_span selected_span[6] = {
    ZCL_SHIELDED_PREVOUT, ZCL_SHIELDED_SEQUENCE, ZCL_SHIELDED_OUTPUT,
    ZCL_SHIELDED_JOINSPLIT, ZCL_SHIELDED_SPEND, ZCL_SHIELDED_SOUTPUT
};

enum { SPEND_RK_OFFSET = 3 * 32, SPEND_RK_LENGTH = 32 };
static_assert(sizeof(zcl_tx_shielded_output_capture) == 756,
    "Sapling output capture must contain only selected wire fields");

static_assert(sizeof(zcl_tx_shielded_replay) <= 576,
    "Shielded replay state exceeds its bounded-memory budget");

static void wipe_bytes(void *memory, size_t length) {
    volatile uint8_t *bytes = memory;
    for (size_t i = 0; i < length; ++i) bytes[i] = 0;
}

static bool overlap(const void *left, size_t left_size,
    const void *right, size_t right_size) {
    if (!left || !right || !left_size || !right_size) return false;
    uintptr_t a = (uintptr_t)left, b = (uintptr_t)right;
    return a <= b ? b - a < left_size : a - b < right_size;
}

static bool buffers_disjoint(zcl_tx_shielded_replay *state,
    const zcl_zip243_hasher *blake, uint8_t *rk,
    zcl_tx_shielded_output_capture *output) {
    if (!state || !blake) return true;
    if (overlap(state, sizeof *state, blake, sizeof *blake) ||
        overlap(state, sizeof *state, rk, 32) ||
        overlap(state, sizeof *state, output, sizeof *output) ||
        overlap(blake, sizeof *blake, rk, 32) ||
        overlap(blake, sizeof *blake, output, sizeof *output) ||
        overlap(rk, 32, output, sizeof *output)) return false;
    return !overlap(blake->context, 1, state, sizeof *state) &&
        !overlap(blake->context, 1, blake, sizeof *blake) &&
        !overlap(blake->context, 1, rk, 32) &&
        !overlap(blake->context, 1, output, sizeof *output);
}

void zcl_tx_shielded_replay_abort(zcl_tx_shielded_replay *state) {
    if (!state) return;
    if (state->spend_rk) wipe_bytes(state->spend_rk, 32);
    if (state->output_capture)
        wipe_bytes(state->output_capture, sizeof *state->output_capture);
    wipe_bytes(state, sizeof *state);
}

static bool fail(zcl_tx_shielded_replay *state) {
    zcl_tx_shielded_replay_abort(state);
    state->failed = true;
    return false;
}

static bool start_pass(zcl_tx_shielded_replay *state) {
    zsha256_init(&state->sha);
    return zcl_tx_shielded_stream_begin(&state->wire, state->expected) &&
        state->blake.init(state->blake.context,
            section_personal[state->pass - 1]);
}

static bool captures_valid(const zcl_tx_shielded_replay *state,
    const zcl_tx_shielded_facts *facts) {
    bool spend_ok = !state->spend_rk ||
        (state->spend_index < facts->sapling_spends &&
         state->rk_used == SPEND_RK_LENGTH);
    bool output_ok = !state->output_capture ||
        (state->output_index < facts->sapling_outputs &&
         state->output_used == sizeof *state->output_capture);
    return spend_ok && output_ok;
}

static void capture_output(zcl_tx_shielded_replay *state, uint8_t byte) {
    if (state->pass != 1 || !state->output_capture ||
        state->wire.item_index != state->output_index) return;
    uint32_t offset = state->wire.field_used;
    if (offset >= sizeof *state->output_capture) return;
    ((uint8_t *)state->output_capture)[offset] = byte;
    ++state->output_used;
}

static bool capture_spend_rk(zcl_tx_shielded_replay *state,
    zcl_tx_shielded_span span, const uint8_t *bytes, size_t length) {
    if (state->pass != 1 || !state->spend_rk ||
        span != ZCL_SHIELDED_SPEND ||
        state->wire.item_index != state->spend_index ||
        state->wire.field_used < SPEND_RK_OFFSET ||
        state->wire.field_used >= SPEND_RK_OFFSET + SPEND_RK_LENGTH)
        return true;
    if (length != 1) return false;
    state->spend_rk[state->wire.field_used - SPEND_RK_OFFSET] = bytes[0];
    ++state->rk_used;
    return true;
}

static bool observe(void *context, zcl_tx_shielded_span span,
    const uint8_t *bytes, size_t length) {
    zcl_tx_shielded_replay *state = context;
    if (span == ZCL_SHIELDED_SOUTPUT && length == 1)
        capture_output(state, bytes[0]);
    if (!capture_spend_rk(state, span, bytes, length)) return false;
    if (state->pass == 1 && span == ZCL_SHIELDED_HEADER) {
        if (length > sizeof state->header - state->header_used)
            return false;
        memcpy(state->header + state->header_used, bytes, length);
        state->header_used = (uint8_t)(state->header_used + length);
    }
    if (state->pass == 1 && span == ZCL_SHIELDED_TAIL) {
        if (length > sizeof state->tail - state->tail_used)
            return false;
        memcpy(state->tail + state->tail_used, bytes, length);
        state->tail_used = (uint8_t)(state->tail_used + length);
    }
    return span != selected_span[state->pass - 1] ||
        state->blake.update(state->blake.context, bytes, length);
}

bool zcl_tx_shielded_replay_begin_rk(zcl_tx_shielded_replay *state,
    uint32_t expected_length, uint32_t branch_id,
    const zcl_zip243_hasher *blake, uint32_t spend_index,
    uint8_t spend_rk[32]) {
    if (!state) {
        if (spend_rk) wipe_bytes(spend_rk, 32);
        return false;
    }
    if (!buffers_disjoint(state, blake, spend_rk, NULL)) return false;
    wipe_bytes(state, sizeof *state);
    if (spend_rk) wipe_bytes(spend_rk, 32);
    state->spend_rk = spend_rk;
    state->spend_index = spend_index;
    if (!blake || !blake->context || !blake->init || !blake->update ||
        !blake->final || (spend_rk && spend_index >= 4096))
        return fail(state);
    state->blake = *blake;
    state->expected = expected_length;
    state->branch_id = branch_id;
    state->pass = 1;
    return start_pass(state) ? true : fail(state);
}

bool zcl_tx_shielded_replay_begin(zcl_tx_shielded_replay *state,
    uint32_t expected_length, uint32_t branch_id,
    const zcl_zip243_hasher *blake) {
    return zcl_tx_shielded_replay_begin_rk(state, expected_length,
        branch_id, blake, 0, NULL);
}

bool zcl_tx_shielded_replay_begin_output(zcl_tx_shielded_replay *state,
    uint32_t expected_length, uint32_t branch_id,
    const zcl_zip243_hasher *blake, uint32_t output_index,
    zcl_tx_shielded_output_capture *output) {
    if (!buffers_disjoint(state, blake, NULL, output)) return false;
    if (output) wipe_bytes(output, sizeof *output);
    if (!state) return false;
    if (!zcl_tx_shielded_replay_begin(state, expected_length,
            branch_id, blake)) return false;
    if (!output || output_index >= 4096) {
        zcl_tx_shielded_replay_abort(state);
        return false;
    }
    state->output_capture = output;
    state->output_index = output_index;
    return true;
}

bool zcl_tx_shielded_replay_begin_captures(zcl_tx_shielded_replay *state,
    uint32_t expected_length, uint32_t branch_id,
    const zcl_zip243_hasher *blake, uint32_t spend_index,
    uint8_t spend_rk[32], uint32_t output_index,
    zcl_tx_shielded_output_capture *output) {
    if (!buffers_disjoint(state, blake, spend_rk, output)) return false;
    if (output) wipe_bytes(output, sizeof *output);
    if (!state) {
        if (spend_rk) wipe_bytes(spend_rk, 32);
        return false;
    }
    if (!zcl_tx_shielded_replay_begin_rk(state, expected_length,
            branch_id, blake, spend_index, spend_rk)) return false;
    if (!spend_rk || !output || output_index >= 4096) {
        zcl_tx_shielded_replay_abort(state);
        return false;
    }
    state->output_capture = output;
    state->output_index = output_index;
    return true;
}

bool zcl_tx_shielded_replay_feed(zcl_tx_shielded_replay *state,
    const uint8_t *bytes, size_t length) {
    if (!state) return false;
    if (overlap(bytes, length, state, sizeof *state) ||
        overlap(bytes, length, state->spend_rk, 32) ||
        overlap(bytes, length, state->output_capture,
            sizeof *state->output_capture) ||
        state->failed || state->pass < 1 || state->pass > 6 ||
        !zcl_tx_shielded_stream_feed(&state->wire, bytes, length,
            observe, state)) return fail(state);
    zsha256_update(&state->sha, bytes, length);
    return true;
}

static bool complete_pass(zcl_tx_shielded_replay *state) {
    zcl_tx_shielded_facts checked;
    uint8_t sha_digest[32];
    if (!zcl_tx_shielded_stream_finish(&state->wire, &checked))
        return false;
    zsha256_final(&state->sha, sha_digest);
    if (state->pass == 1) {
        if (state->header_used != 8 || state->tail_used != 16)
            return false;
        if (!captures_valid(state, &checked)) return false;
        memcpy(state->commitment, sha_digest, sizeof sha_digest);
        state->facts = checked;
    } else if (zsha256_compare(state->commitment, sha_digest) != 0)
        return false;
    uint8_t *part = state->parts[state->pass - 1];
    if (!state->blake.final(state->blake.context, part)) return false;
    if ((state->pass == 4 && !checked.sprout_joinsplits) ||
        (state->pass == 5 && !checked.sapling_spends) ||
        (state->pass == 6 && !checked.sapling_outputs))
        memset(part, 0, 32);
    return true;
}

bool zcl_tx_shielded_replay_next(zcl_tx_shielded_replay *state) {
    if (!state) return false;
    if (state->failed || state->pass < 1 || state->pass > 5 ||
        !complete_pass(state)) return fail(state);
    ++state->pass;
    return start_pass(state) ? true : fail(state);
}

static bool final_digest(zcl_tx_shielded_replay *state,
    uint8_t digest[32]) {
    uint8_t personal[16] = "ZcashSigHash";
    for (unsigned i = 0; i < 4; ++i)
        personal[12 + i] = (uint8_t)(state->branch_id >> (8 * i));
    zcl_zip243_hasher *hash = &state->blake;
    if (!hash->init(hash->context, personal) ||
        !hash->update(hash->context, state->header, 8)) return false;
    for (unsigned i = 0; i < 6; ++i)
        if (!hash->update(hash->context, state->parts[i], 32))
            return false;
    return hash->update(hash->context, state->tail, 16) &&
        hash->update(hash->context,
            (const uint8_t[]){1, 0, 0, 0}, 4) &&
        hash->final(hash->context, digest);
}

static bool finish_buffers_disjoint(const zcl_tx_shielded_replay *state,
    const zcl_tx_shielded_facts *facts, const uint8_t digest[32]) {
    if (overlap(facts, sizeof *facts, digest, 32)) return false;
    const void *outputs[2] = {facts, digest};
    const size_t lengths[2] = {sizeof *facts, 32};
    for (unsigned i = 0; i < 2; ++i) {
        if (overlap(outputs[i], lengths[i], state, sizeof *state) ||
            overlap(outputs[i], lengths[i], state->spend_rk, 32) ||
            overlap(outputs[i], lengths[i], state->output_capture,
                sizeof *state->output_capture) ||
            overlap(outputs[i], lengths[i], state->blake.context, 1))
            return false;
    }
    return true;
}

bool zcl_tx_shielded_replay_finish(zcl_tx_shielded_replay *state,
    zcl_tx_shielded_facts *facts, uint8_t digest[32]) {
    if (!state) return false;
    uint8_t result[32];
    if (!facts || !digest || state->failed || state->pass != 6 ||
        !finish_buffers_disjoint(state, facts, digest) ||
        !complete_pass(state) || !final_digest(state, result))
        return fail(state);
    *facts = state->facts;
    memcpy(digest, result, sizeof result);
    wipe_bytes(result, sizeof result);
    wipe_bytes(state, sizeof *state);
    state->pass = 7;
    return true;
}
