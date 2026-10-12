/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "zcl_tx_prevout.h"
#include "zcl_tx_review.h"
#include "zcl_tx_script_facts.h"

#include <string.h>

enum { ZCL_MAX_MONEY_ZAT = 2100000000000000ULL };

typedef struct {
    uint32_t index;
    zcl_tx_input input;
    bool found;
} input_selection;

typedef struct {
    const zcl_tx_previous_transaction *previous;
    size_t count;
    zcl_tx_sha256_fn sha256;
    uint8_t used[ZCL_TX_PREFLIGHT_MAX_INPUTS][36];
    uint64_t input_zat;
} input_check;

static bool select_input(void *context, const zcl_tx_input *input) {
    input_selection *selection = context;
    if (input->index == selection->index) {
        selection->input = *input;
        selection->found = true;
    }
    return true;
}

static bool bind_prevout(const zcl_tx_input *input,
                         zcl_tx_previous_transaction previous,
                         zcl_tx_sha256_fn sha256,
                         zcl_tx_previous_output *output) {
    if (!previous.wire || !sha256) return false;
    uint8_t first[32], txid[32];
    if (!sha256(previous.wire, previous.length, first) ||
        !sha256(first, sizeof first, txid) ||
        memcmp(input->previous_txid, txid, sizeof txid)) return false;
    if (zcl_tx_previous_output_select(previous.wire, previous.length,
            input->previous_output_index, output) < 0) return false;
    const uint8_t *script = output->script;
    return output->script_length == 25 && script[0] == 0x76 &&
        script[1] == 0xa9 && script[2] == 0x14 &&
        script[23] == 0x88 && script[24] == 0xac;
}

static bool check_input(void *context, const zcl_tx_input *input) {
    input_check *check = context;
    if (input->index >= check->count || input->script_length) return false;
    for (uint32_t i = 0; i < input->index; ++i)
        if (!memcmp(check->used[i], input->previous_txid, 36)) return false;
    zcl_tx_previous_output output;
    if (!bind_prevout(input, check->previous[input->index],
                      check->sha256, &output) ||
        output.value_zat > ZCL_MAX_MONEY_ZAT - check->input_zat) return false;
    memcpy(check->used[input->index], input->previous_txid, 36);
    check->input_zat += output.value_zat;
    return true;
}

static bool standard_output(void *context, const zcl_tx_output *output) {
    (void)context;
    return output->type == ZCL_TX_OUTPUT_P2PKH ||
           output->type == ZCL_TX_OUTPUT_P2SH;
}

static bool transparent_only(const zcl_tx_review *review) {
    return review->transparent_inputs && review->transparent_outputs &&
        review->transparent_inputs <= ZCL_TX_PREFLIGHT_MAX_INPUTS &&
        !review->sapling_spends && !review->sapling_outputs &&
        !review->sprout_joinsplits && !review->value_balance_zat;
}

int zcl_tx_transparent_preflight(const uint8_t *wire, size_t length,
    const zcl_tx_previous_transaction *previous, size_t previous_count,
    zcl_tx_sha256_fn sha256, zcl_tx_transparent_facts *facts) {
    if (!wire || !previous || !sha256 || !facts) return -1;
    zcl_tx_review review;
    if (zcl_tx_review_parse(wire, length, &review) < 0 ||
        !transparent_only(&review) ||
        previous_count != review.transparent_inputs ||
        zcl_tx_outputs_visit(wire, length, standard_output, NULL) < 0)
        return -1;
    input_check check = {.previous = previous, .count = previous_count,
                         .sha256 = sha256};
    if (zcl_tx_inputs_visit(wire, length, check_input, &check) < 0 ||
        check.input_zat < review.transparent_output_zat) return -1;
    *facts = (zcl_tx_transparent_facts){
        .transparent_inputs = review.transparent_inputs,
        .transparent_outputs = review.transparent_outputs,
        .input_zat = check.input_zat,
        .output_zat = review.transparent_output_zat,
        .fee_zat = check.input_zat - review.transparent_output_zat
    };
    return 0;
}

int zcl_tx_hash_bound_digest(const uint8_t *wire, size_t length,
    uint32_t input_index, zcl_tx_previous_transaction previous,
    uint32_t branch_id, zcl_tx_sha256_fn sha256,
    const zcl_zip243_hasher *hasher, uint8_t digest[32]) {
    if (!wire || !hasher || !digest) return -1;
    zcl_tx_review review;
    if (zcl_tx_review_parse(wire, length, &review) < 0 ||
        !transparent_only(&review) ||
        input_index >= review.transparent_inputs ||
        zcl_tx_outputs_visit(wire, length, standard_output, NULL) < 0)
        return -1;
    input_selection selection = {.index = input_index};
    zcl_tx_previous_output output;
    if (zcl_tx_inputs_visit(wire, length, select_input, &selection) < 0 ||
        !selection.found || selection.input.script_length ||
        !bind_prevout(&selection.input, previous, sha256, &output)) return -1;
    return zcl_zip243_transparent_digest(wire, length, input_index,
        output.script, output.script_length, output.value_zat,
        branch_id, hasher, digest);
}

int zcl_tx_transparent_bound_digests(const uint8_t *wire, size_t length,
    const zcl_tx_previous_transaction *previous, size_t previous_count,
    uint32_t branch_id, zcl_tx_sha256_fn sha256,
    const zcl_zip243_hasher *hasher, zcl_tx_transparent_facts *facts,
    uint8_t (*digests)[32], size_t digest_capacity) {
    if (!facts || !digests || !hasher || !previous ||
        !previous_count || previous_count > ZCL_TX_PREFLIGHT_MAX_INPUTS ||
        digest_capacity < previous_count) return -1;
    zcl_tx_transparent_facts checked;
    uint8_t checked_digests[ZCL_TX_PREFLIGHT_MAX_INPUTS][32];
    if (zcl_tx_transparent_preflight(wire, length, previous,
            previous_count, sha256, &checked) < 0) return -1;
    for (size_t i = 0; i < previous_count; ++i) {
        if (zcl_tx_hash_bound_digest(wire, length, (uint32_t)i,
                previous[i], branch_id, sha256, hasher,
                checked_digests[i]) < 0) return -1;
    }
    *facts = checked;
    memcpy(digests, checked_digests, previous_count * sizeof *digests);
    return 0;
}
