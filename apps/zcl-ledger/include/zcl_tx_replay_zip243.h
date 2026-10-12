/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#ifndef ZCL_TX_REPLAY_ZIP243_H
#define ZCL_TX_REPLAY_ZIP243_H

#include "zcl_tx_stream.h"
#include "zcl_zip243.h"

#if !defined(__STDC_VERSION__) || __STDC_VERSION__ < 202311L
#error "Replay-bound ZIP-243 requires ISO C23"
#endif

typedef struct {
    void *context;
    bool (*init)(void *context);
    bool (*update)(void *context, const uint8_t *bytes, size_t length);
    bool (*final)(void *context, uint8_t digest[32]);
} zcl_tx_replay_sha256;

typedef bool (*zcl_tx_replay_input_fn)(void *context, uint32_t index,
    const uint8_t outpoint[36], uint32_t sequence);

typedef struct {
    zcl_tx_stream wire;
    zcl_zip243_hasher blake;
    zcl_tx_replay_sha256 sha;
    uint8_t commitment[32], prevouts[32], sequences[32], outputs[32];
    uint8_t selected[40];
    uint32_t expected, selected_index, branch_id;
    zcl_tx_replay_input_fn input_observer;
    void *input_context;
    uint8_t pass;
    bool selected_found;
} zcl_tx_replay_zip243;

typedef bool (*zcl_tx_replay_output_fn)(void *context, uint32_t index,
    uint64_t amount_zat, zcl_tx_stream_output_type type,
    const uint8_t hash160[20]);

/* Upload the identical unsigned transaction three times. Each complete pass
 * is parsed and SHA-256 checked against the first pass before its ZIP-243
 * subhash is accepted. No partial or mismatched pass returns a digest.
 * script_code, spent amount, and branch ID still need trusted provenance. */
bool zcl_tx_replay_zip243_begin(zcl_tx_replay_zip243 *state,
    uint32_t expected_length, uint32_t selected_index, uint32_t branch_id,
    const zcl_zip243_hasher *blake, const zcl_tx_replay_sha256 *sha);
/* The observer receives provisional pass-one outpoints. Their caller must
 * defer use until the full three-pass replay succeeds. */
bool zcl_tx_replay_zip243_observe_inputs(zcl_tx_replay_zip243 *state,
    zcl_tx_replay_input_fn observer, void *context);
bool zcl_tx_replay_zip243_feed(zcl_tx_replay_zip243 *state,
    const uint8_t *bytes, size_t length);
/* The observer sees provisional output facts only during pass three. It must
 * not treat them as authenticated until the final pass succeeds. Feed bytes
 * must be disjoint from replay state; overlap aborts before parsing. */
bool zcl_tx_replay_zip243_feed_review(zcl_tx_replay_zip243 *state,
    const uint8_t *bytes, size_t length,
    zcl_tx_replay_output_fn observer, void *observer_context);
bool zcl_tx_replay_zip243_next(zcl_tx_replay_zip243 *state);
/* Fact and digest outputs must be disjoint from each other, the replay state,
 * and a nonempty script input. The script must be disjoint from replay state.
 * An overlap aborts the replay before a digest can be reported. */
bool zcl_tx_replay_zip243_finish(zcl_tx_replay_zip243 *state,
    const uint8_t *script_code, size_t script_code_length,
    uint64_t amount_zat, zcl_tx_stream_facts *facts, uint8_t digest[32]);

/* After a complete three-pass replay, computes SIGHASH_ALL for one supplied
 * input. The caller must bind outpoint and sequence to the replayed input,
 * script and amount to its exact previous wire, and branch to consensus.
 * This read-only result grants no signing authority. Digest output must be
 * disjoint from replay state, outpoint, and script; script must be disjoint
 * from replay state. Invalid requests leave
 * digest unchanged; a hash failure invalidates the replay. */
bool zcl_tx_replay_zip243_bound_digest(zcl_tx_replay_zip243 *state,
    const uint8_t outpoint[36], uint32_t sequence,
    const uint8_t script_code[25], uint64_t amount_zat,
    uint8_t digest[32]);

#endif
