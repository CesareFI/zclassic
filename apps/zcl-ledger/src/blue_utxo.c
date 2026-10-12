/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "blue_utxo.h"
#include "blue_chain_tip.h"
#include "zcl_tx_review.h"
#include "zcl_tx_script_facts.h"
#include "json/json.h"
#include "zsha256/zsha256.h"

#include <limits.h>
#include <stdio.h>
#include <string.h>

static const struct json_value *field(const struct json_value *object,
                                      const char *name) {
    if (!object || object->type != JSON_OBJ) return NULL;
    const struct json_value *found = NULL;
    for (size_t i = 0; i < object->num_children; ++i) {
        if (strcmp(object->keys[i], name) != 0) continue;
        if (found) return NULL;
        found = &object->children[i];
    }
    return found;
}

static bool amount_zat(const char *text, uint64_t *value) {
    if (!text || !value) return false;
    uint64_t whole = 0, fraction = 0;
    size_t digits = 0;
    while (*text >= '0' && *text <= '9' && digits < 8) {
        whole = whole * 10 + (unsigned)(*text++ - '0');
        ++digits;
    }
    if (!digits || *text++ != '.') return false;
    for (unsigned i = 0; i < 8; ++i) {
        if (*text < '0' || *text > '9') return false;
        fraction = fraction * 10 + (unsigned)(*text++ - '0');
    }
    if (*text || whole > 21000000) return false;
    *value = whole * 100000000 + fraction;
    return *value <= 2100000000000000ULL;
}

static bool row_matches(const struct json_value *row, uint64_t value_zat,
                        size_t script_length, const char script_hash[65]) {
    const struct json_value *spent = field(row, "spent");
    const struct json_value *amount = field(row, "amount");
    const struct json_value *size = field(row, "script_size");
    const struct json_value *hash = field(row, "script_sha256");
    uint64_t parsed = 0;
    return spent && spent->type == JSON_BOOL && !spent->val.b &&
        amount && amount->type == JSON_STR &&
        amount_zat(amount->val.s, &parsed) && parsed == value_zat &&
        size && size->type == JSON_INT &&
        size->val.i == (int64_t)script_length && hash &&
        hash->type == JSON_STR &&
        strcmp(hash->val.s, script_hash) == 0;
}

static bool output_matches(const struct json_value *result,
                           uint32_t index, uint64_t value_zat,
                           size_t script_length,
                           const char script_hash[65]) {
    const struct json_value *outputs = field(result, "outputs");
    const struct json_value *count = field(result, "num_outputs");
    if (!outputs || outputs->type != JSON_ARR || !count ||
        count->type != JSON_INT || count->val.i <= index ||
        count->val.i != (int64_t)outputs->num_children) return false;
    bool found = false;
    for (size_t i = 0; i < outputs->num_children; ++i) {
        const struct json_value *row = json_at(outputs, i);
        const struct json_value *n = field(row, "n");
        if (!n || n->type != JSON_INT || n->val.i != index) continue;
        if (found || !row_matches(row, value_zat, script_length,
                                  script_hash)) return false;
        found = true;
    }
    return found;
}

static bool metadata_matches(const struct json_value *result,
                             const char *txid_hex, uint32_t next_height) {
    const struct json_value *txid = field(result, "txid");
    const struct json_value *height = field(result, "height");
    const struct json_value *coinbase = field(result, "coinbase");
    if (!txid || txid->type != JSON_STR ||
        strcmp(txid->val.s, txid_hex) != 0 ||
        !height || height->type != JSON_INT || height->val.i <= 0 ||
        height->val.i >= next_height ||
        !coinbase || coinbase->type != JSON_BOOL) return false;
    return !coinbase->val.b ||
        next_height - (uint32_t)height->val.i >= 100;
}

static bool valid_query(const char *reply, size_t length,
                        const char *txid_hex, const uint8_t *script,
                        uint32_t next_height) {
    return reply && length && length <= 65535 && txid_hex &&
        strlen(txid_hex) == 64 && script && next_height;
}

bool blue_utxo_parse(const char *reply, size_t length, const char *txid_hex,
                     uint32_t output_index, uint64_t value_zat,
                     const uint8_t *script, size_t script_length,
                     uint32_t next_height) {
    if (!valid_query(reply, length, txid_hex, script, next_height))
        return false;
    char script_hash[65];
    zsha256_hex(script, script_length, script_hash);
    struct json_value root = {0};
    bool valid = json_read(&root, reply, length);
    const struct json_value *result = valid ? field(&root, "result") : NULL;
    const struct json_value *error = valid ? field(&root, "error") : NULL;
    valid = result && result->type == JSON_OBJ && error &&
        error->type == JSON_NULL &&
        metadata_matches(result, txid_hex, next_height) &&
        output_matches(result, output_index, value_zat, script_length,
                       script_hash);
    json_free(&root);
    return valid;
}

typedef struct {
    const char *rpc_binary;
    const zcl_tx_previous_transaction *previous;
    size_t count;
    uint32_t next_height;
} utxo_check;

static bool check_input(void *context, const zcl_tx_input *input) {
    utxo_check *check = context;
    if (input->index >= check->count) return false;
    zcl_tx_previous_output output;
    zcl_tx_previous_transaction previous = check->previous[input->index];
    if (zcl_tx_previous_output_select(previous.wire, previous.length,
            input->previous_output_index, &output) < 0) return false;
    static const char hex[] = "0123456789abcdef";
    char txid[65], argument[68];
    for (size_t i = 0; i < 32; ++i) {
        uint8_t byte = input->previous_txid[31 - i];
        txid[2 * i] = hex[byte >> 4];
        txid[2 * i + 1] = hex[byte & 15];
    }
    txid[64] = 0;
    if (snprintf(argument, sizeof argument, "\"%s\"", txid) != 66)
        return false;
    char reply[65536];
    size_t length = 0;
    return blue_rpc_capture(check->rpc_binary, "gettxdetail", argument,
                            reply, sizeof reply, &length) &&
        blue_utxo_parse(reply, length, txid, input->previous_output_index,
                        output.value_zat, output.script,
                        output.script_length,
                        check->next_height);
}

bool blue_utxo_check_inputs(const char *rpc_binary, const uint8_t *wire,
                            size_t length,
                            const zcl_tx_previous_transaction *previous,
                            size_t previous_count, uint32_t next_height) {
    if (!rpc_binary || !wire || !previous || !previous_count ||
        previous_count > ZCL_TX_PREFLIGHT_MAX_INPUTS) return false;
    utxo_check check = {.rpc_binary = rpc_binary, .previous = previous,
                        .count = previous_count, .next_height = next_height};
    return zcl_tx_inputs_visit(wire, length, check_input, &check) == 0;
}

bool blue_utxo_recheck_at_tip(const char *rpc_binary,
                              const blue_chain_tip *initial,
                              const uint8_t *wire, size_t length,
                              const zcl_tx_previous_transaction *previous,
                              size_t previous_count) {
    return initial && blue_chain_tip_still_current(rpc_binary, initial) &&
        blue_utxo_check_inputs(rpc_binary, wire, length, previous,
                               previous_count, initial->next_height) &&
        blue_chain_tip_still_current(rpc_binary, initial);
}
