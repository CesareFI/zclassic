/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "zcl_tx_review.h"
#include "zcl_tx_script_facts.h"
#include "zcl_zip243.h"
#include "zcl_zip243_host.h"
#include "crypto/blake2b.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

typedef struct { uint32_t count; } visit_count;

static bool check_input(void *context, const zcl_tx_input *input) {
    visit_count *seen = context;
    if (input->index != seen->count++) abort();
    return true;
}

static bool check_output(void *context, const zcl_tx_output *output) {
    visit_count *seen = context;
    if (output->index != seen->count++) abort();
    return true;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    zcl_tx_review review;
    if (zcl_tx_review_parse(data, size, &review) < 0) return 0;
    visit_count inputs = {0}, outputs = {0};
    zcl_tx_script_facts scripts;
    if (zcl_tx_inputs_visit(data, size, check_input, &inputs) < 0 ||
        zcl_tx_outputs_visit(data, size, check_output, &outputs) < 0 ||
        zcl_tx_script_facts_parse(data, size, &scripts) < 0 ||
        inputs.count != review.transparent_inputs ||
        outputs.count != review.transparent_outputs) abort();
    struct blake2b_ctx context;
    zcl_zip243_hasher hasher = zcl_zip243_host_hasher(&context);
    uint8_t digest[32];
    if (zcl_zip243_shielded_digest(data, size, 0x76b809bb,
                                    &hasher, digest) < 0) abort();
    return 0;
}
