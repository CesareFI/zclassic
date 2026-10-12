/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "zcl_tx_script_facts.h"
#include "zcl_tx_review.h"

#include <string.h>

typedef struct {
    const uint8_t *wire;
    size_t length;
    size_t offset;
} cursor;

static bool take(cursor *input, uint64_t count, const uint8_t **bytes) {
    if (count > input->length - input->offset) return false;
    *bytes = input->wire + input->offset;
    input->offset += (size_t)count;
    return true;
}

static bool compact_size(cursor *input, uint64_t *value) {
    const uint8_t *bytes;
    if (!take(input, 1, &bytes)) return false;
    if (*bytes < 0xfd) { *value = *bytes; return true; }
    unsigned width = *bytes == 0xfd ? 2 : *bytes == 0xfe ? 4 : 8;
    if (!take(input, width, &bytes)) return false;
    *value = 0;
    for (unsigned i = 0; i < width; ++i)
        *value |= (uint64_t)bytes[i] << (8 * i);
    return true;
}

static bool script(cursor *input, const uint8_t **bytes, size_t *length) {
    uint64_t count;
    if (!compact_size(input, &count) || !take(input, count, bytes))
        return false;
    *length = (size_t)count;
    return true;
}

static bool read_u64(cursor *input, uint64_t *value) {
    const uint8_t *bytes;
    if (!take(input, 8, &bytes)) return false;
    *value = 0;
    for (unsigned i = 0; i < 8; ++i)
        *value |= (uint64_t)bytes[i] << (8 * i);
    return true;
}

static uint32_t read_u32_bytes(const uint8_t *bytes) {
    return (uint32_t)bytes[0] | ((uint32_t)bytes[1] << 8) |
           ((uint32_t)bytes[2] << 16) | ((uint32_t)bytes[3] << 24);
}

static bool read_inputs(cursor *input, zcl_tx_input_visitor visitor,
                        void *context) {
    uint64_t count;
    if (!compact_size(input, &count) || count > 65536) return false;
    for (uint64_t i = 0; i < count; ++i) {
        const uint8_t *outpoint, *script_bytes, *sequence;
        size_t script_length;
        if (!take(input, 36, &outpoint) ||
            !script(input, &script_bytes, &script_length) ||
            !take(input, 4, &sequence)) return false;
        zcl_tx_input parsed = {
            .index = (uint32_t)i,
            .previous_txid = outpoint,
            .previous_output_index = read_u32_bytes(outpoint + 32),
            .script = script_bytes, .script_length = script_length,
            .sequence = read_u32_bytes(sequence)
        };
        if (visitor && !visitor(context, &parsed)) return false;
    }
    return true;
}

static bool zslp_marker(const uint8_t *script_bytes, size_t length) {
    static const uint8_t marker[] = {'S', 'L', 'P', 0};
    static const uint8_t headers[][5] = {
        {4}, {0x4c, 4}, {0x4d, 4, 0}, {0x4e, 4, 0, 0, 0}
    };
    static const size_t widths[] = {1, 2, 3, 5};
    if (!length || script_bytes[0] != 0x6a) return false;
    for (size_t i = 0; i < sizeof widths / sizeof widths[0]; ++i) {
        size_t prefix = 1 + widths[i];
        if (length >= prefix + sizeof marker &&
            memcmp(script_bytes + 1, headers[i], widths[i]) == 0 &&
            memcmp(script_bytes + prefix, marker, sizeof marker) == 0)
            return true;
    }
    return false;
}

static zcl_tx_output_type output_type(const uint8_t *bytes, size_t length) {
    if (length == 25 && bytes[0] == 0x76 && bytes[1] == 0xa9 &&
        bytes[2] == 0x14 && bytes[23] == 0x88 && bytes[24] == 0xac)
        return ZCL_TX_OUTPUT_P2PKH;
    if (length == 23 && bytes[0] == 0xa9 && bytes[1] == 0x14 &&
        bytes[22] == 0x87) return ZCL_TX_OUTPUT_P2SH;
    return length && bytes[0] == 0x6a ? ZCL_TX_OUTPUT_OP_RETURN :
        ZCL_TX_OUTPUT_OTHER;
}

static bool read_outputs(cursor *input, zcl_tx_output_visitor visitor,
                         void *context) {
    uint64_t count;
    const uint8_t *bytes;
    size_t length;
    if (!compact_size(input, &count) || count > 65536) return false;
    for (uint64_t i = 0; i < count; ++i) {
        uint64_t value;
        if (!read_u64(input, &value) || !script(input, &bytes, &length))
            return false;
        zcl_tx_output output = {
            .index = (uint32_t)i, .value_zat = value, .script = bytes,
            .script_length = length, .type = output_type(bytes, length)
        };
        if (!visitor(context, &output)) return false;
    }
    return true;
}

int zcl_tx_outputs_visit(const uint8_t *wire, size_t length,
                          zcl_tx_output_visitor visitor, void *context) {
    if (!visitor || zcl_tx_review_parse(wire, length,
                                         &(zcl_tx_review){0}) < 0)
        return -1;
    cursor input = {.wire = wire, .length = length, .offset = 8};
    return read_inputs(&input, NULL, NULL) &&
           read_outputs(&input, visitor, context) ?
        0 : -1;
}

int zcl_tx_inputs_visit(const uint8_t *wire, size_t length,
                        zcl_tx_input_visitor visitor, void *context) {
    if (!visitor || zcl_tx_review_parse(wire, length,
                                         &(zcl_tx_review){0}) < 0)
        return -1;
    cursor input = {.wire = wire, .length = length, .offset = 8};
    return read_inputs(&input, visitor, context) ? 0 : -1;
}

static bool collect_fact(void *context, const zcl_tx_output *output) {
    zcl_tx_script_facts *facts = context;
    switch (output->type) {
    case ZCL_TX_OUTPUT_P2PKH: ++facts->p2pkh_outputs; break;
    case ZCL_TX_OUTPUT_P2SH: ++facts->p2sh_outputs; break;
    case ZCL_TX_OUTPUT_OP_RETURN:
        ++facts->op_return_outputs;
        if (output->index == 0)
            facts->zslp_marker = zslp_marker(output->script,
                                              output->script_length);
        break;
    case ZCL_TX_OUTPUT_OTHER: ++facts->other_outputs; break;
    }
    return true;
}

int zcl_tx_script_facts_parse(const uint8_t *wire, size_t length,
                              zcl_tx_script_facts *facts) {
    if (!facts) return -1;
    zcl_tx_script_facts parsed = {0};
    if (zcl_tx_outputs_visit(wire, length, collect_fact, &parsed) < 0)
        return -1;
    *facts = parsed;
    return 0;
}
