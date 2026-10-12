/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "zcl_tx_stream_zip243.h"

#include <string.h>

enum { ZCL_MAX_MONEY_ZAT = 2100000000000000ULL };

static const uint8_t prevouts_personal[] = "ZcashPrevoutHash";
static const uint8_t sequences_personal[] = "ZcashSequencHash";
static const uint8_t outputs_personal[] = "ZcashOutputsHash";

static bool fail(zcl_tx_stream_zip243 *state) {
    memset(state, 0, sizeof *state);
    state->wire.failed = true;
    return false;
}

static bool valid_hasher(const zcl_zip243_hasher *hasher) {
    return hasher && hasher->context && hasher->init &&
           hasher->update && hasher->final;
}

static void put_u32(uint8_t bytes[4], uint32_t value) {
    for (unsigned i = 0; i < 4; ++i) bytes[i] = (uint8_t)(value >> (8 * i));
}

static void put_u64(uint8_t bytes[8], uint64_t value) {
    for (unsigned i = 0; i < 8; ++i) bytes[i] = (uint8_t)(value >> (8 * i));
}

static bool input_seen(void *context, uint32_t index,
    const uint8_t outpoint[36], uint32_t sequence) {
    zcl_tx_stream_zip243 *state = context;
    uint8_t bytes[4];
    put_u32(bytes, sequence);
    if (index == state->selected_index) {
        memcpy(state->selected, outpoint, 36);
        memcpy(state->selected + 36, bytes, 4);
        state->selected_found = true;
    }
    return state->first.update(state->first.context, outpoint, 36) &&
           state->second.update(state->second.context, bytes, 4);
}

static bool output_seen(void *context, uint32_t index, uint64_t amount,
    zcl_tx_stream_output_type type, const uint8_t hash160[20]) {
    zcl_tx_stream_zip243 *state = context;
    (void)index;
    if (!state->outputs_started) {
        if (!state->first.final(state->first.context, state->prevouts) ||
            !state->second.final(state->second.context, state->sequences) ||
            !state->first.init(state->first.context, outputs_personal))
            return false;
        state->outputs_started = true;
    }
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
    return state->first.update(state->first.context, bytes, sizeof bytes) &&
           state->first.update(state->first.context, script, length);
}

bool zcl_tx_stream_zip243_begin(zcl_tx_stream_zip243 *state,
    uint32_t expected_length, uint32_t selected_index, uint32_t branch_id,
    const zcl_zip243_hasher *first, const zcl_zip243_hasher *second) {
    if (!state) return false;
    memset(state, 0, sizeof *state);
    if (!valid_hasher(first) || !valid_hasher(second) ||
        first->context == second->context ||
        !zcl_tx_stream_begin(&state->wire, expected_length)) return fail(state);
    state->first = *first;
    state->second = *second;
    state->selected_index = selected_index;
    state->branch_id = branch_id;
    if (!first->init(first->context, prevouts_personal) ||
        !second->init(second->context, sequences_personal)) return fail(state);
    return true;
}

bool zcl_tx_stream_zip243_feed(zcl_tx_stream_zip243 *state,
    const uint8_t *bytes, size_t length) {
    if (!state) return false;
    if (!zcl_tx_stream_feed(&state->wire, bytes, length,
                            input_seen, output_seen, state)) return fail(state);
    return true;
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

static bool append_hashes(zcl_tx_stream_zip243 *state,
    const zcl_zip243_hasher *hash, const uint8_t output_hash[32]) {
    static const uint8_t zero[32] = {0};
    if (!hash->update(hash->context, state->prevouts, 32) ||
        !hash->update(hash->context, state->sequences, 32) ||
        !hash->update(hash->context, output_hash, 32)) return false;
    for (unsigned i = 0; i < 3; ++i)
        if (!hash->update(hash->context, zero, sizeof zero)) return false;
    return true;
}

static bool final_digest(zcl_tx_stream_zip243 *state,
    const uint8_t *script_code, size_t script_code_length,
    uint64_t amount_zat, const zcl_tx_stream_facts *facts,
    uint8_t digest[32]) {
    static const uint8_t header[8] = {4, 0, 0, 0x80, 0x85, 0x20, 0x2f, 0x89};
    uint8_t personal[16] = "ZcashSigHash";
    uint8_t tail[16] = {0}, amount[8], prefix[5];
    put_u32(personal + 12, state->branch_id);
    put_u32(tail, facts->lock_time);
    put_u32(tail + 4, facts->expiry_height);
    put_u64(amount, amount_zat);
    size_t prefix_length = script_prefix(script_code_length, prefix);
    zcl_zip243_hasher *hash = &state->first;
    if (!hash->init(hash->context, personal) ||
        !hash->update(hash->context, header, sizeof header) ||
        !append_hashes(state, hash, digest)) return false;
    static const uint8_t sighash_all[4] = {1, 0, 0, 0};
    return hash->update(hash->context, tail, sizeof tail) &&
           hash->update(hash->context, sighash_all, sizeof sighash_all) &&
           hash->update(hash->context, state->selected, 36) &&
           hash->update(hash->context, prefix, prefix_length) &&
           (!script_code_length || hash->update(hash->context, script_code,
                                                 script_code_length)) &&
           hash->update(hash->context, amount, sizeof amount) &&
           hash->update(hash->context, state->selected + 36, 4) &&
           hash->final(hash->context, digest);
}

bool zcl_tx_stream_zip243_finish(zcl_tx_stream_zip243 *state,
    const uint8_t *script_code, size_t script_code_length,
    uint64_t amount_zat, zcl_tx_stream_facts *facts, uint8_t digest[32]) {
    if (!state) return false;
    if (!facts || !digest) return fail(state);
    memset(facts, 0, sizeof *facts);
    memset(digest, 0, 32);
    zcl_tx_stream_facts checked;
    uint8_t hash[32];
    if ((script_code_length && !script_code) ||
        script_code_length > ZCL_TX_STREAM_MAX_BYTES ||
        amount_zat > ZCL_MAX_MONEY_ZAT || !state->outputs_started ||
        !state->selected_found || !zcl_tx_stream_finish(&state->wire, &checked) ||
        !state->first.final(state->first.context, hash) ||
        !final_digest(state, script_code, script_code_length, amount_zat,
                       &checked, hash)) return fail(state);
    *facts = checked;
    memcpy(digest, hash, sizeof hash);
    return true;
}
