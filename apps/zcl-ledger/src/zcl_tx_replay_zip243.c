/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "zcl_tx_replay_zip243.h"

#include <string.h>

enum { ZCL_MAX_MONEY_ZAT = 2100000000000000ULL };
static const uint8_t personal[3][17] = {
    "ZcashPrevoutHash", "ZcashSequencHash", "ZcashOutputsHash"
};

static bool fail(zcl_tx_replay_zip243 *state) {
    memset(state, 0, sizeof *state);
    state->wire.failed = true;
    return false;
}

static bool overlaps(const void *left, size_t left_length,
    const void *right, size_t right_length) {
    uintptr_t a = (uintptr_t)left, b = (uintptr_t)right;
    return a <= b ? b - a < left_length : a - b < right_length;
}

static void put_u32(uint8_t bytes[4], uint32_t value) {
    for (unsigned i = 0; i < 4; ++i) bytes[i] = (uint8_t)(value >> (8 * i));
}

static void put_u64(uint8_t bytes[8], uint64_t value) {
    for (unsigned i = 0; i < 8; ++i) bytes[i] = (uint8_t)(value >> (8 * i));
}

static bool start_pass(zcl_tx_replay_zip243 *state) {
    return zcl_tx_stream_begin(&state->wire, state->expected) &&
        state->blake.init(state->blake.context, personal[state->pass - 1]) &&
        state->sha.init(state->sha.context);
}

typedef struct {
    zcl_tx_replay_zip243 *state;
    zcl_tx_replay_output_fn observer;
    void *observer_context;
} callback_context;

bool zcl_tx_replay_zip243_begin(zcl_tx_replay_zip243 *state,
    uint32_t expected_length, uint32_t selected_index, uint32_t branch_id,
    const zcl_zip243_hasher *blake, const zcl_tx_replay_sha256 *sha) {
    if (!state) return false;
    memset(state, 0, sizeof *state);
    if (!blake || !blake->context || !blake->init || !blake->update ||
        !blake->final || !sha || !sha->context || !sha->init ||
        !sha->update || !sha->final || blake->context == sha->context)
        return fail(state);
    state->blake = *blake;
    state->sha = *sha;
    state->expected = expected_length;
    state->selected_index = selected_index;
    state->branch_id = branch_id;
    state->pass = 1;
    return start_pass(state) ? true : fail(state);
}

bool zcl_tx_replay_zip243_observe_inputs(zcl_tx_replay_zip243 *state,
    zcl_tx_replay_input_fn observer, void *context) {
    if (!state || !observer || !context || state->pass != 1 ||
        state->wire.received || state->wire.failed) return false;
    state->input_observer = observer;
    state->input_context = context;
    return true;
}

static bool input_seen(void *context, uint32_t index,
    const uint8_t outpoint[36], uint32_t sequence) {
    zcl_tx_replay_zip243 *state = ((callback_context *)context)->state;
    if (state->pass == 1)
        return state->blake.update(state->blake.context, outpoint, 36) &&
            (!state->input_observer || state->input_observer(
                state->input_context, index, outpoint, sequence));
    uint8_t bytes[4];
    put_u32(bytes, sequence);
    if (state->pass == 2)
        return state->blake.update(state->blake.context, bytes, 4);
    if (index == state->selected_index) {
        memcpy(state->selected, outpoint, 36);
        memcpy(state->selected + 36, bytes, 4);
        state->selected_found = true;
    }
    return true;
}

static bool output_seen(void *context, uint32_t index, uint64_t amount,
    zcl_tx_stream_output_type type, const uint8_t hash160[20]) {
    callback_context *callback = context;
    zcl_tx_replay_zip243 *state = callback->state;
    if (state->pass != 3) return true;
    uint8_t bytes[9], script[25];
    put_u64(bytes, amount);
    bytes[8] = type == ZCL_TX_STREAM_P2PKH ? 25 : 23;
    size_t length = bytes[8];
    if (type == ZCL_TX_STREAM_P2PKH) {
        script[0] = 0x76;
        script[1] = 0xa9;
        script[2] = 0x14;
        memcpy(script + 3, hash160, 20);
        script[23] = 0x88;
        script[24] = 0xac;
    } else {
        script[0] = 0xa9;
        script[1] = 0x14;
        memcpy(script + 2, hash160, 20);
        script[22] = 0x87;
    }
    return state->blake.update(state->blake.context, bytes, sizeof bytes) &&
           state->blake.update(state->blake.context, script, length) &&
           (!callback->observer || callback->observer(callback->observer_context,
               index, amount, type, hash160));
}

bool zcl_tx_replay_zip243_feed(zcl_tx_replay_zip243 *state,
    const uint8_t *bytes, size_t length) {
    return zcl_tx_replay_zip243_feed_review(state, bytes, length, NULL, NULL);
}

bool zcl_tx_replay_zip243_feed_review(zcl_tx_replay_zip243 *state,
    const uint8_t *bytes, size_t length,
    zcl_tx_replay_output_fn observer, void *observer_context) {
    if (!state) return false;
    if (bytes && length && overlaps(state, sizeof *state, bytes, length))
        return fail(state);
    callback_context callback = {.state = state, .observer = observer,
                                 .observer_context = observer_context};
    if (state->pass < 1 || state->pass > 3 ||
        !zcl_tx_stream_feed(&state->wire, bytes, length,
                            input_seen, output_seen, &callback) ||
        !state->sha.update(state->sha.context, bytes, length))
        return fail(state);
    return true;
}

static bool complete_pass(zcl_tx_replay_zip243 *state,
    zcl_tx_stream_facts *facts, uint8_t part[32]) {
    uint8_t wire_hash[32];
    if (!zcl_tx_stream_finish(&state->wire, facts) ||
        !state->sha.final(state->sha.context, wire_hash)) return false;
    if (state->pass == 1)
        memcpy(state->commitment, wire_hash, sizeof wire_hash);
    else if (memcmp(state->commitment, wire_hash, sizeof wire_hash))
        return false;
    return state->blake.final(state->blake.context, part);
}

bool zcl_tx_replay_zip243_next(zcl_tx_replay_zip243 *state) {
    if (!state) return false;
    zcl_tx_stream_facts facts;
    uint8_t part[32];
    if (state->pass < 1 || state->pass > 2 ||
        !complete_pass(state, &facts, part)) return fail(state);
    memcpy(state->pass == 1 ? state->prevouts : state->sequences,
           part, sizeof part);
    ++state->pass;
    return start_pass(state) ? true : fail(state);
}

static size_t script_prefix(size_t length, uint8_t prefix[5]) {
    if (length < 0xfd) { prefix[0] = (uint8_t)length; return 1; }
    if (length <= UINT16_MAX) {
        prefix[0] = 0xfd;
        prefix[1] = (uint8_t)length;
        prefix[2] = (uint8_t)(length >> 8);
        return 3;
    }
    prefix[0] = 0xfe;
    put_u32(prefix + 1, (uint32_t)length);
    return 5;
}

static bool append_parts(zcl_tx_replay_zip243 *state,
    const uint8_t outputs[32]) {
    static const uint8_t zero[32] = {0};
    zcl_zip243_hasher *hash = &state->blake;
    if (!hash->update(hash->context, state->prevouts, 32) ||
        !hash->update(hash->context, state->sequences, 32) ||
        !hash->update(hash->context, outputs, 32)) return false;
    for (unsigned i = 0; i < 3; ++i)
        if (!hash->update(hash->context, zero, sizeof zero)) return false;
    return true;
}

static bool final_digest(zcl_tx_replay_zip243 *state,
    const uint8_t selected[40],
    const uint8_t *script_code, size_t script_code_length,
    uint64_t amount_zat, const zcl_tx_stream_facts *facts,
    const uint8_t outputs[32], uint8_t digest[32]) {
    static const uint8_t header[8] = {4, 0, 0, 0x80, 0x85, 0x20, 0x2f, 0x89};
    static const uint8_t sighash_all[4] = {1, 0, 0, 0};
    uint8_t personal_final[16] = "ZcashSigHash";
    uint8_t tail[16] = {0}, amount[8], prefix[5];
    put_u32(personal_final + 12, state->branch_id);
    put_u32(tail, facts->lock_time);
    put_u32(tail + 4, facts->expiry_height);
    put_u64(amount, amount_zat);
    size_t prefix_length = script_prefix(script_code_length, prefix);
    zcl_zip243_hasher *hash = &state->blake;
    return hash->init(hash->context, personal_final) &&
        hash->update(hash->context, header, sizeof header) &&
        append_parts(state, outputs) &&
        hash->update(hash->context, tail, sizeof tail) &&
        hash->update(hash->context, sighash_all, sizeof sighash_all) &&
        hash->update(hash->context, selected, 36) &&
        hash->update(hash->context, prefix, prefix_length) &&
        (!script_code_length || hash->update(hash->context, script_code,
                                              script_code_length)) &&
        hash->update(hash->context, amount, sizeof amount) &&
        hash->update(hash->context, selected + 36, 4) &&
        hash->final(hash->context, digest);
}

static bool finish_buffers_disjoint(const zcl_tx_replay_zip243 *state,
    const uint8_t *script_code, size_t script_length,
    const zcl_tx_stream_facts *facts, const uint8_t digest[32]) {
    if (overlaps(state, sizeof *state, facts, sizeof *facts) ||
        overlaps(state, sizeof *state, digest, 32) ||
        overlaps(facts, sizeof *facts, digest, 32)) return false;
    return !script_length || !script_code ||
        (!overlaps(state, sizeof *state, script_code, script_length) &&
         !overlaps(facts, sizeof *facts, script_code, script_length) &&
         !overlaps(digest, 32, script_code, script_length));
}

bool zcl_tx_replay_zip243_finish(zcl_tx_replay_zip243 *state,
    const uint8_t *script_code, size_t script_code_length,
    uint64_t amount_zat, zcl_tx_stream_facts *facts, uint8_t digest[32]) {
    if (!state) return false;
    if (!facts || !digest) return fail(state);
    if (!finish_buffers_disjoint(state, script_code, script_code_length,
            facts, digest)) return fail(state);
    memset(facts, 0, sizeof *facts);
    memset(digest, 0, 32);
    zcl_tx_stream_facts checked;
    uint8_t result[32];
    if (state->pass != 3 || !state->selected_found ||
        (script_code_length && !script_code) ||
        script_code_length > ZCL_TX_STREAM_MAX_BYTES ||
        amount_zat > ZCL_MAX_MONEY_ZAT ||
        !complete_pass(state, &checked, state->outputs) ||
        !final_digest(state, state->selected, script_code,
                      script_code_length, amount_zat, &checked,
                      state->outputs, result)) return fail(state);
    *facts = checked;
    memcpy(digest, result, 32);
    state->pass = 4;
    return true;
}

static bool bound_digest_disjoint(const zcl_tx_replay_zip243 *state,
    const uint8_t outpoint[36], const uint8_t script_code[25],
    const uint8_t digest[32]) {
    return !overlaps(state, sizeof *state, script_code, 25) &&
        !overlaps(digest, 32, state, sizeof *state) &&
        !overlaps(digest, 32, outpoint, 36) &&
        !overlaps(digest, 32, script_code, 25);
}

bool zcl_tx_replay_zip243_bound_digest(zcl_tx_replay_zip243 *state,
    const uint8_t outpoint[36], uint32_t sequence,
    const uint8_t script_code[25], uint64_t amount_zat,
    uint8_t digest[32]) {
    if (!state || !outpoint || !script_code || !digest) return false;
    if (!bound_digest_disjoint(state, outpoint, script_code, digest))
        return false;
    if (state->pass != 4 || !state->wire.finished ||
        amount_zat > ZCL_MAX_MONEY_ZAT ||
        script_code[0] != 0x76 || script_code[1] != 0xa9 ||
        script_code[2] != 0x14 || script_code[23] != 0x88 ||
        script_code[24] != 0xac) return false;
    uint8_t selected[40], result[32];
    memcpy(selected, outpoint, 36);
    put_u32(selected + 36, sequence);
    if (!final_digest(state, selected, script_code, 25, amount_zat,
            &state->wire.facts, state->outputs, result)) return fail(state);
    memcpy(digest, result, sizeof result);
    return true;
}
