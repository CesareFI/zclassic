/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "zcl_tx_previous_stream.h"
#include "zcl_tx_review.h"

#include <openssl/evp.h>
#include <openssl/sha.h>
#include <stdlib.h>
#include <string.h>

static bool hash_init(void *context) {
    return EVP_DigestInit_ex(context, EVP_sha256(), NULL) == 1;
}

static bool hash_update(void *context, const uint8_t *bytes, size_t count) {
    return EVP_DigestUpdate(context, bytes, count) == 1;
}

static bool hash_final(void *context, uint8_t digest[32]) {
    unsigned int count = 0;
    return EVP_DigestFinal_ex(context, digest, &count) == 1 && count == 32;
}

static bool p2pkh(const zcl_tx_previous_output *output) {
    const uint8_t *script = output->script;
    return output->script_length == 25 && script[0] == 0x76 &&
        script[1] == 0xa9 && script[2] == 0x14 &&
        script[23] == 0x88 && script[24] == 0xac;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 2 || size - 1 > ZCL_TX_PREVIOUS_STREAM_MAX_BYTES) return 0;
    uint32_t index = data[0];
    const uint8_t *wire = data + 1;
    size_t length = size - 1;
    zcl_tx_previous_output direct = {0};
    bool expected = zcl_tx_previous_output_select(wire, length,
        index, &direct) == 0 && p2pkh(&direct);
    uint8_t first[32], txid[32];
    if (!SHA256(wire, length, first) ||
        !SHA256(first, sizeof first, txid)) abort();
    EVP_MD_CTX *context = EVP_MD_CTX_new();
    if (!context) abort();
    zcl_tx_previous_sha256 hash = {.context = context,
        .init = hash_init, .update = hash_update, .final = hash_final};
    zcl_tx_previous_stream stream;
    bool actual = zcl_tx_previous_stream_begin(&stream,
        (uint32_t)length, index, hash);
    size_t chunk = 1 + (size % 127);
    for (size_t offset = 0; actual && offset < length; offset += chunk) {
        size_t count = length - offset < chunk ? length - offset : chunk;
        actual = zcl_tx_previous_stream_feed(&stream, wire + offset, count);
    }
    zcl_tx_previous_p2pkh selected = {0};
    if (actual) actual = zcl_tx_previous_stream_finish(&stream,
                                                       txid, &selected);
    EVP_MD_CTX_free(context);
    if (actual != expected ||
        (actual && (selected.value_zat != direct.value_zat ||
                    memcmp(selected.script, direct.script, 25)))) abort();
    return 0;
}
