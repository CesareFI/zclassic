/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#ifndef ZCL_TX_STREAM_ZIP243_H
#define ZCL_TX_STREAM_ZIP243_H

#include "zcl_tx_stream.h"
#include "zcl_zip243.h"

#if !defined(__STDC_VERSION__) || __STDC_VERSION__ < 202311L
#error "Streaming ZIP-243 requires ISO C23"
#endif

typedef struct {
    zcl_tx_stream wire;
    zcl_zip243_hasher first, second;
    uint8_t prevouts[32], sequences[32], selected[40];
    uint32_t selected_index, branch_id;
    bool outputs_started, selected_found;
} zcl_tx_stream_zip243;

/* Both hashers need separate contexts. They may be reused after finalization.
 * script_code and amount at finish must come from a verified previous output;
 * this component checks neither their provenance nor the consensus branch. */
bool zcl_tx_stream_zip243_begin(zcl_tx_stream_zip243 *state,
    uint32_t expected_length, uint32_t selected_index, uint32_t branch_id,
    const zcl_zip243_hasher *first, const zcl_zip243_hasher *second);
bool zcl_tx_stream_zip243_feed(zcl_tx_stream_zip243 *state,
    const uint8_t *bytes, size_t length);
bool zcl_tx_stream_zip243_finish(zcl_tx_stream_zip243 *state,
    const uint8_t *script_code, size_t script_code_length,
    uint64_t amount_zat, zcl_tx_stream_facts *facts, uint8_t digest[32]);

#endif
