/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "zcl_tx_review.h"

#include <stdint.h>
#include <stdlib.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (!size) return 0;
    uint32_t index = data[0];
    const uint8_t *wire = data + 1;
    size_t length = size - 1;
    zcl_tx_previous_output output = {
        .script = data, .script_length = SIZE_MAX, .value_zat = UINT64_MAX
    };
    int result = zcl_tx_previous_output_select(wire, length, index, &output);
    if (result < 0) {
        if (output.script != data || output.script_length != SIZE_MAX ||
            output.value_zat != UINT64_MAX) abort();
        return 0;
    }
    uintptr_t begin = (uintptr_t)wire;
    uintptr_t end = begin + length;
    uintptr_t script = (uintptr_t)output.script;
    if (end < begin || script < begin || script > end ||
        output.script_length > end - script ||
        output.script_length > 10000 ||
        output.value_zat > 2100000000000000ULL) abort();
    return 0;
}
