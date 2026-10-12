/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "blue_payment_host_ownership.h"
#include "zcl_tx_review.h"
#include "zcl_tx_script_facts.h"

#include <string.h>

typedef struct {
    const zcl_tx_previous_transaction *previous;
    const uint8_t *external, *internal;
    blue_payment_host_ownership *result;
    size_t count;
} ownership_visit;

static bool classify_input(void *context, const zcl_tx_input *input) {
    ownership_visit *visit = context;
    if (!input || input->index != visit->count ||
        visit->count >= ZCL_TX_PREFLIGHT_MAX_INPUTS) return false;
    zcl_tx_previous_output output;
    if (zcl_tx_previous_output_select(visit->previous[input->index].wire,
            visit->previous[input->index].length,
            input->previous_output_index, &output) != 0 ||
        output.script_length != 25) return false;
    const uint8_t *hash = output.script + 3;
    bool external = memcmp(hash, visit->external, 20) == 0;
    bool internal = visit->internal ?
        memcmp(hash, visit->internal, 20) == 0 : !external;
    if (external == internal) return false;
    visit->result->paths[input->index] = external ?
        BLUE_PAYMENT_INPUT_EXTERNAL : BLUE_PAYMENT_INPUT_INTERNAL;
    memcpy(visit->result->hashes[input->index], hash, 20);
    ++visit->count;
    return true;
}

static bool classify_inputs(const uint8_t *wire, size_t length,
    const zcl_tx_previous_transaction *previous, size_t previous_count,
    zcl_tx_sha256_fn sha256, const uint8_t external[20],
    const uint8_t internal[20], blue_payment_host_ownership *result) {
    if (!wire || !previous || !sha256 || !external || !result ||
        !previous_count || previous_count > ZCL_TX_PREFLIGHT_MAX_INPUTS ||
        (internal && memcmp(external, internal, 20) == 0)) return false;
    blue_payment_host_ownership checked = {0};
    if (zcl_tx_transparent_preflight(wire, length, previous, previous_count,
            sha256, &checked.facts) != 0) return false;
    ownership_visit visit = {.previous = previous, .external = external,
        .internal = internal, .result = &checked};
    if (zcl_tx_inputs_visit(wire, length, classify_input, &visit) != 0 ||
        visit.count != previous_count) return false;
    *result = checked;
    return true;
}

bool blue_payment_host_classify_inputs(const uint8_t *wire, size_t length,
    const zcl_tx_previous_transaction *previous, size_t previous_count,
    zcl_tx_sha256_fn sha256, const uint8_t external[20],
    const uint8_t internal[20], blue_payment_host_ownership *result) {
    return classify_inputs(wire, length, previous, previous_count,
        sha256, external, internal, result);
}

bool blue_payment_host_propose_paths(const uint8_t *wire, size_t length,
    const zcl_tx_previous_transaction *previous, size_t previous_count,
    zcl_tx_sha256_fn sha256, const uint8_t external[20],
    blue_payment_host_ownership *result) {
    return classify_inputs(wire, length, previous, previous_count,
        sha256, external, NULL, result);
}
