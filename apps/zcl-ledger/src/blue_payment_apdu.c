/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "blue_payment_apdu.h"
#include "blue_mainnet_branch.h"

#include <string.h>

static uint32_t read_u32(const uint8_t *bytes) {
    return (uint32_t)bytes[0] | ((uint32_t)bytes[1] << 8) |
        ((uint32_t)bytes[2] << 16) | ((uint32_t)bytes[3] << 24);
}

static void put_u64(uint8_t bytes[8], uint64_t value) {
    for (unsigned i = 0; i < 8; ++i)
        bytes[i] = (uint8_t)(value >> (i * 8));
}

static void wipe(void *memory, size_t length) {
    volatile uint8_t *bytes = memory;
    for (size_t i = 0; i < length; ++i) bytes[i] = 0;
}

static bool overlap(const void *left, size_t left_size,
    const void *right, size_t right_size) {
    if (!left || !right || !left_size || !right_size) return false;
    uintptr_t a = (uintptr_t)left, b = (uintptr_t)right;
    return a <= b ? b - a < left_size : a - b < right_size;
}

static bool command_storage_valid(const blue_payment_apdu *state,
    const uint8_t *apdu, size_t apdu_length,
    const uint8_t *reply, size_t capacity, const size_t *reply_length,
    const blue_payment_owned_hashes *owned) {
    return !overlap(state, sizeof *state, owned, sizeof *owned) &&
        !overlap(state, sizeof *state, apdu, apdu_length) &&
        !overlap(state, sizeof *state, reply, capacity) &&
        !overlap(state, sizeof *state, reply_length,
            sizeof *reply_length) &&
        !overlap(owned, sizeof *owned, apdu, apdu_length) &&
        !overlap(owned, sizeof *owned, reply, capacity) &&
        !overlap(owned, sizeof *owned, reply_length,
            sizeof *reply_length) &&
        !overlap(apdu, apdu_length, reply_length,
            sizeof *reply_length) &&
        !overlap(reply, capacity, reply_length, sizeof *reply_length);
}

static void reject_command_storage(blue_payment_apdu *state,
    const uint8_t *apdu, size_t apdu_length,
    uint8_t *reply, size_t capacity, size_t *reply_length,
    const blue_payment_owned_hashes *owned) {
    if (reply && !overlap(state, sizeof *state, reply, capacity) &&
        !overlap(owned, sizeof *owned, reply, capacity))
        wipe(reply, capacity);
    if (reply_length &&
        !overlap(state, sizeof *state, reply_length,
            sizeof *reply_length) &&
        !overlap(owned, sizeof *owned, reply_length,
            sizeof *reply_length) &&
        !overlap(apdu, apdu_length, reply_length,
            sizeof *reply_length) &&
        !overlap(reply, capacity, reply_length, sizeof *reply_length))
        *reply_length = 0;
    blue_payment_apdu_abort(state);
}

static bool capture_input(void *context, uint32_t index,
    const uint8_t outpoint[36], uint32_t sequence) {
    blue_payment_apdu *state = context;
    if (index != state->input_count ||
        index >= ZCL_TX_STREAM_MAX_INPUTS) return false;
    for (uint32_t i = 0; i < index; ++i)
        if (memcmp(state->input_record[i], outpoint, 36) == 0) return false;
    memcpy(state->input_record[index], outpoint, 36);
    state->sequences[index] = sequence;
    ++state->input_count;
    return true;
}

void blue_payment_apdu_abort(blue_payment_apdu *state) {
    if (!state) return;
    wipe(state, sizeof *state);
    state->review.replay.wire.failed = true;
}

static bool bound_paths_valid(const blue_payment_apdu *state) {
    uint8_t paths = 0;
    for (uint32_t i = 0; i < state->input_count; ++i) {
        uint8_t path = state->input_record[i][32];
        if (path != BLUE_PAYMENT_INPUT_EXTERNAL &&
            path != BLUE_PAYMENT_INPUT_INTERNAL) return false;
        paths |= path;
    }
    return paths == state->input_paths;
}

static bool totals_consistent(const blue_payment_apdu *state) {
    return state->own_output_zat <= state->output_zat &&
        state->input_zat >= state->output_zat &&
        state->fee_zat == state->input_zat - state->output_zat;
}

static bool ready_for_final_touch(const blue_payment_apdu *state) {
    if (!state || !state->review.verified || !state->fee_ready ||
        state->active || state->previous_active || state->approved ||
        state->review_confirmed ||
        state->next_sign_index || !state->input_count ||
        state->bound_inputs != state->input_count ||
        !totals_consistent(state) ||
        !bound_paths_valid(state)) return false;
    return true;
}

bool blue_payment_apdu_touch_confirm(blue_payment_apdu *state) {
    if (!ready_for_final_touch(state)) return false;
    state->review_confirmed = true;
    return true;
}

bool blue_payment_apdu_touch_approve(blue_payment_apdu *state) {
    if (!ready_for_final_touch(state)) return false;
    state->approved = true;
    return true;
}

static bool ready_to_take_digest(const blue_payment_apdu *state,
    uint32_t index) {
    return state && state->approved && !state->review_confirmed &&
        state->review.verified && state->fee_ready &&
        !state->active && !state->previous_active &&
        totals_consistent(state) &&
        state->bound_inputs == state->input_count &&
        index == state->next_sign_index && index < state->input_count;
}

bool blue_payment_apdu_take_digest(blue_payment_apdu *state,
    uint32_t index, uint8_t digest[32], uint8_t *path) {
    if (!digest || !path || !ready_to_take_digest(state, index))
        return false;
    uint8_t *record = state->input_record[index];
    if (record[32] != BLUE_PAYMENT_INPUT_EXTERNAL &&
        record[32] != BLUE_PAYMENT_INPUT_INTERNAL) return false;
    memcpy(digest, record, 32);
    *path = record[32];
    wipe(record, 36);
    ++state->next_sign_index;
    if (state->next_sign_index == state->input_count)
        state->approved = false;
    return true;
}

bool blue_payment_apdu_touch_continue(blue_payment_apdu *state,
    const blue_payment_owned_hashes *owned) {
    if (!state || !state->active || !owned) return false;
    const blue_payment_output *pending =
        blue_payment_review_pending(&state->review);
    blue_payment_account_relation relation = blue_payment_account_classify(
        pending, owned->external, owned->internal, true);
    if (relation == BLUE_PAYMENT_ACCOUNT_UNKNOWN) return false;
    bool own = relation == BLUE_PAYMENT_THIS_ACCOUNT ||
               relation == BLUE_PAYMENT_OWN_INTERNAL;
    if (own && pending->amount_zat >
            2100000000000000ULL - state->own_output_zat) return false;
    uint64_t amount = pending->amount_zat;
    if (!blue_payment_review_acknowledge(&state->review)) return false;
    if (own) state->own_output_zat += amount;
    memset(&state->screen, 0, sizeof state->screen);
    return true;
}

static uint16_t begin(blue_payment_apdu *state, const uint8_t *body,
    uint8_t length, const zcl_zip243_hasher *blake,
    const zcl_tx_replay_sha256 *sha) {
    if (length != 12) return 0x6700;
    if (!blue_mainnet_branch_is_known(read_u32(body + 8))) return 0x6a80;
    blue_payment_apdu_abort(state);
    if (!blue_payment_review_begin(&state->review, read_u32(body),
            read_u32(body + 4), read_u32(body + 8), blake, sha) ||
        !zcl_tx_replay_zip243_observe_inputs(&state->review.replay,
            capture_input, state))
        return 0x6a80;
    state->active = true;
    return 0x9000;
}

static uint16_t feed(blue_payment_apdu *state, const uint8_t *body,
    uint8_t length, uint8_t *reply, size_t capacity, size_t *reply_length,
    blue_payment_hash_fn hash) {
    if (!state->active) return 0x6985;
    if (!length || capacity < 2) return 0x6700;
    if (!blue_payment_review_feed(&state->review, body, length)) return 0x6a80;
    const blue_payment_output *pending =
        blue_payment_review_pending(&state->review);
    if (pending && !blue_payment_screen_format(pending,
            state->review.total_outputs, hash, &state->screen)) return 0x6a80;
    reply[0] = state->review.replay.pass;
    reply[1] = pending ? 1 : 0;
    *reply_length = 2;
    return 0x9000;
}

static uint16_t next(blue_payment_apdu *state,
    uint8_t length, uint8_t *reply, size_t capacity, size_t *reply_length) {
    if (!state->active) return 0x6985;
    if (length || capacity < 2) return 0x6700;
    if (!blue_payment_review_next_pass(&state->review)) return 0x6a80;
    reply[0] = state->review.replay.pass;
    reply[1] = (uint8_t)state->review.total_outputs;
    *reply_length = 2;
    return 0x9000;
}

static uint16_t finish(blue_payment_apdu *state, uint8_t length,
    uint8_t *reply, size_t capacity, size_t *reply_length) {
    if (!state->active) return 0x6985;
    if (length || capacity < 33) return 0x6700;
    zcl_tx_stream_facts facts;
    uint8_t unused_digest[32];
    if (!blue_payment_review_finish(&state->review, NULL, 0, 0,
            &facts, unused_digest) || facts.inputs != state->input_count ||
        state->own_output_zat > facts.output_zat)
        return 0x6a80;
    state->active = false;
    state->output_zat = facts.output_zat;
    reply[0] = (uint8_t)facts.outputs;
    memcpy(reply + 1, state->review.replay.commitment, 32);
    *reply_length = 33;
    return 0x9000;
}

static uint16_t previous_begin(blue_payment_apdu *state,
    const uint8_t *body, uint8_t length,
    const zcl_tx_replay_sha256 *sha) {
    if (length != 4) return 0x6700;
    if (!sha || !sha->context || !sha->init || !sha->update || !sha->final ||
        !state->review.verified || state->active ||
        state->previous_active || state->fee_ready ||
        state->bound_inputs >= state->input_count) return 0x6985;
    zcl_tx_previous_sha256 hash = {.context = sha->context,
        .init = sha->init, .update = sha->update, .final = sha->final};
    if (!zcl_tx_previous_stream_begin(&state->previous,
            read_u32(body),
            read_u32(state->input_record[state->bound_inputs] + 32),
            hash)) return 0x6a80;
    state->previous_active = true;
    return 0x9000;
}

static uint16_t previous_feed(blue_payment_apdu *state,
    const uint8_t *body, uint8_t length) {
    if (!state->previous_active) return 0x6985;
    if (!length) return 0x6700;
    return zcl_tx_previous_stream_feed(&state->previous, body, length)
        ? 0x9000 : 0x6a80;
}

static uint16_t previous_finish(blue_payment_apdu *state, uint8_t length,
    uint8_t *reply, size_t capacity, size_t *reply_length,
    const blue_payment_owned_hashes *owned) {
    if (!state->previous_active) return 0x6985;
    if (length || capacity < 43) return 0x6700;
    zcl_tx_previous_p2pkh output;
    uint8_t *record = state->input_record[state->bound_inputs];
    const uint8_t *txid = record;
    uint8_t digest[32];
    if (!zcl_tx_previous_stream_finish(&state->previous, txid, &output) ||
        !owned) return 0x6a80;
    uint8_t path = memcmp(output.script + 3, owned->external, 20) == 0
        ? BLUE_PAYMENT_INPUT_EXTERNAL :
        memcmp(output.script + 3, owned->internal, 20) == 0
        ? BLUE_PAYMENT_INPUT_INTERNAL : 0;
    if (!path ||
        output.value_zat > 2100000000000000ULL - state->input_zat ||
        !zcl_tx_replay_zip243_bound_digest(&state->review.replay,
            txid, state->sequences[state->bound_inputs], output.script,
            output.value_zat, digest))
        return 0x6a80;
    memcpy(record, digest, sizeof digest);
    record[32] = path;
    memset(record + 33, 0, 3);
    state->sequences[state->bound_inputs] = 0;
    state->input_zat += output.value_zat;
    state->input_paths |= path;
    ++state->bound_inputs;
    state->previous_active = false;
    if (state->bound_inputs == state->input_count) {
        if (state->input_zat < state->output_zat) return 0x6a80;
        state->fee_zat = state->input_zat - state->output_zat;
        state->fee_ready = true;
    }
    reply[0] = (uint8_t)state->bound_inputs;
    reply[1] = (uint8_t)state->input_count;
    reply[2] = state->fee_ready;
    put_u64(reply + 3, state->fee_zat);
    memcpy(reply + 11, digest, sizeof digest);
    *reply_length = 43;
    return 0x9000;
}

static uint16_t status(const blue_payment_apdu *state, uint8_t length,
    uint8_t *reply, size_t capacity, size_t *reply_length) {
    if (length || capacity < 6) return 0x6700;
    reply[0] = state->active;
    reply[1] = state->review.replay.pass;
    reply[2] = state->review.pending;
    reply[3] = state->review.verified;
    reply[4] = (uint8_t)state->review.total_outputs;
    reply[5] = (uint8_t)state->review.acknowledged;
    *reply_length = 6;
    return 0x9000;
}

static uint16_t dispatch(blue_payment_apdu *state, const uint8_t *apdu,
    uint8_t *reply, size_t capacity, size_t *reply_length,
    const zcl_zip243_hasher *blake, const zcl_tx_replay_sha256 *sha,
    blue_payment_hash_fn hash, const blue_payment_owned_hashes *owned) {
    const uint8_t *body = apdu + 5;
    uint8_t length = apdu[4];
    switch (apdu[1]) {
    case 0x20: return begin(state, body, length, blake, sha);
    case 0x21: return feed(state, body, length, reply, capacity,
                           reply_length, hash);
    case 0x22: return next(state, length, reply, capacity, reply_length);
    case 0x23: return finish(state, length, reply, capacity, reply_length);
    case 0x24:
        if (length) return 0x6700;
        blue_payment_apdu_abort(state);
        return 0x9000;
    case 0x25: return status(state, length, reply, capacity, reply_length);
    case 0x26: return previous_begin(state, body, length, sha);
    case 0x27: return previous_feed(state, body, length);
    case 0x28: return previous_finish(state, length, reply, capacity,
                                      reply_length, owned);
    default: return 0x6d00;
    }
}

static uint16_t finish_reply(blue_payment_apdu *state, uint8_t *reply,
    size_t capacity, size_t *reply_length, uint16_t status) {
    if (status != 0x9000 || *reply_length > capacity) {
        blue_payment_apdu_abort(state);
        wipe(reply, capacity);
        *reply_length = 0;
        return status == 0x9000 ? 0x6f00 : status;
    }
    wipe(reply + *reply_length, capacity - *reply_length);
    return status;
}

uint16_t blue_payment_apdu_handle(blue_payment_apdu *state,
    const uint8_t *apdu, size_t apdu_length,
    uint8_t *reply, size_t reply_capacity, size_t *reply_length,
    const zcl_zip243_hasher *blake, const zcl_tx_replay_sha256 *sha,
    blue_payment_hash_fn hash, const blue_payment_owned_hashes *owned) {
    if (!state || !apdu || !reply || !reply_length || !hash ||
        !command_storage_valid(state, apdu, apdu_length,
            reply, reply_capacity, reply_length, owned)) {
        reject_command_storage(state, apdu, apdu_length,
            reply, reply_capacity, reply_length, owned);
        return 0x6f00;
    }
    *reply_length = 0;
    uint16_t result = 0x9000;
    if (apdu_length < 5 || apdu_length != (size_t)apdu[4] + 5)
        result = 0x6700;
    else if (apdu[0] != 0xa5) result = 0x6e00;
    else if (apdu[2] || apdu[3]) result = 0x6b00;
    else result = dispatch(state, apdu, reply, reply_capacity,
                           reply_length, blake, sha, hash, owned);
    return finish_reply(state, reply, reply_capacity, reply_length, result);
}
