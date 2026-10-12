/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "zcl_tx_stream.h"
#include "zcl_tx_review.h"
#include "zcl_tx_script_facts.h"
#include "zcl_tx_stream_zip243.h"
#include "zcl_tx_replay_zip243.h"
#include "zcl_zip243_host.h"
#include "crypto/blake2b.h"

#include <openssl/evp.h>

#include <stdlib.h>
#include <string.h>

typedef struct {
    uint32_t inputs, outputs;
    uint64_t output_zat;
} observations;

static bool see_input(void *context, uint32_t index,
                      const uint8_t outpoint[36], uint32_t sequence) {
    observations *seen = context;
    (void)outpoint;
    (void)sequence;
    if (index != seen->inputs++) abort();
    return true;
}

static bool see_output(void *context, uint32_t index, uint64_t amount,
                       zcl_tx_stream_output_type type,
                       const uint8_t hash160[20]) {
    observations *seen = context;
    (void)hash160;
    if (index != seen->outputs++ ||
        (type != ZCL_TX_STREAM_P2PKH && type != ZCL_TX_STREAM_P2SH)) abort();
    seen->output_zat += amount;
    return true;
}

static bool parse_stream(const uint8_t *data, size_t size,
    observations *seen, zcl_tx_stream_facts *facts) {
    zcl_tx_stream stream;
    if (!zcl_tx_stream_begin(&stream, (uint32_t)size)) return false;
    for (size_t offset = 0; offset < size;) {
        size_t chunk = 1 + data[offset] % 64;
        if (chunk > size - offset) chunk = size - offset;
        if (!zcl_tx_stream_feed(&stream, data + offset, chunk,
                                see_input, see_output, seen)) return false;
        offset += chunk;
    }
    return zcl_tx_stream_finish(&stream, facts);
}

static void compare_types(const zcl_tx_review *full,
    const zcl_tx_script_facts *scripts, uint32_t outputs) {
    if (scripts->p2pkh_outputs + scripts->p2sh_outputs != outputs ||
        full->sapling_spends || full->sapling_outputs ||
        full->sprout_joinsplits || full->value_balance_zat) abort();
}

static bool sha_start(void *context) {
    return EVP_DigestInit_ex(context, EVP_sha256(), NULL) == 1;
}

static bool sha_update(void *context, const uint8_t *bytes, size_t length) {
    return EVP_DigestUpdate(context, bytes, length) == 1;
}

static bool sha_finish(void *context, uint8_t digest[32]) {
    unsigned length = 0;
    return EVP_DigestFinal_ex(context, digest, &length) == 1 && length == 32;
}

static void compare_replay(const uint8_t *data, size_t size,
    const uint8_t script[25], const uint8_t expected[32]) {
    struct blake2b_ctx blake_context;
    EVP_MD_CTX *sha_context = EVP_MD_CTX_new();
    if (!sha_context) abort();
    zcl_zip243_hasher blake = zcl_zip243_host_hasher(&blake_context);
    zcl_tx_replay_sha256 sha = {.context = sha_context, .init = sha_start,
        .update = sha_update, .final = sha_finish};
    zcl_tx_replay_zip243 state;
    if (!zcl_tx_replay_zip243_begin(&state, (uint32_t)size, 0,
                                    0x76b809bb, &blake, &sha)) abort();
    for (unsigned pass = 0; pass < 3; ++pass) {
        for (size_t offset = 0; offset < size;) {
            size_t chunk = 1 + data[offset] % 64;
            if (chunk > size - offset) chunk = size - offset;
            if (!zcl_tx_replay_zip243_feed(&state, data + offset, chunk)) abort();
            offset += chunk;
        }
        if (pass < 2 && !zcl_tx_replay_zip243_next(&state)) abort();
    }
    zcl_tx_stream_facts facts;
    uint8_t digest[32];
    if (!zcl_tx_replay_zip243_finish(&state, script, 25,
          50000000, &facts, digest) || memcmp(digest, expected, 32)) abort();
    EVP_MD_CTX_free(sha_context);
}

static void compare_review(const uint8_t *data, size_t size,
    const observations *seen, const zcl_tx_stream_facts *facts) {
    zcl_tx_review full;
    zcl_tx_script_facts scripts;
    if (zcl_tx_review_parse(data, size, &full) < 0 ||
        zcl_tx_script_facts_parse(data, size, &scripts) < 0 ||
        facts->inputs != full.transparent_inputs ||
        facts->outputs != full.transparent_outputs ||
        facts->output_zat != full.transparent_output_zat ||
        facts->lock_time != full.lock_time ||
        facts->expiry_height != full.expiry_height ||
        facts->inputs != seen->inputs || facts->outputs != seen->outputs ||
        facts->output_zat != seen->output_zat) abort();
    compare_types(&full, &scripts, facts->outputs);
}

static void compare_digest(const uint8_t *data, size_t size,
    const zcl_tx_stream_facts *facts) {
    static const uint8_t script[25] = {
        0x76, 0xa9, 0x14, 0x50, 0x71, 0x73, 0x52, 0x7b,
        0x4c, 0x33, 0x18, 0xa2, 0xae, 0xcd, 0x79, 0x3b,
        0xf1, 0xcf, 0xed, 0x70, 0x59, 0x50, 0xcf, 0x88,
        0xac
    };
    struct blake2b_ctx first_context, second_context, complete_context;
    zcl_zip243_hasher first = zcl_zip243_host_hasher(&first_context);
    zcl_zip243_hasher second = zcl_zip243_host_hasher(&second_context);
    zcl_zip243_hasher complete = zcl_zip243_host_hasher(&complete_context);
    zcl_tx_stream_zip243 hashed;
    if (!zcl_tx_stream_zip243_begin(&hashed, (uint32_t)size, 0,
                                    0x76b809bb, &first, &second)) abort();
    for (size_t offset = 0; offset < size;) {
        size_t chunk = 1 + data[offset] % 64;
        if (chunk > size - offset) chunk = size - offset;
        if (!zcl_tx_stream_zip243_feed(&hashed, data + offset, chunk)) abort();
        offset += chunk;
    }
    zcl_tx_stream_facts hashed_facts;
    uint8_t actual[32], expected[32];
    if (!zcl_tx_stream_zip243_finish(&hashed, script, sizeof script,
          50000000, &hashed_facts, actual) ||
        zcl_zip243_transparent_digest(data, size, 0, script, sizeof script,
          50000000, 0x76b809bb, &complete, expected) < 0 ||
        hashed_facts.inputs != facts->inputs ||
        hashed_facts.outputs != facts->outputs ||
        hashed_facts.output_zat != facts->output_zat ||
        memcmp(actual, expected, sizeof actual)) abort();
    compare_replay(data, size, script, expected);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size > ZCL_TX_STREAM_MAX_BYTES) return 0;
    observations seen = {0};
    zcl_tx_stream_facts facts;
    if (!parse_stream(data, size, &seen, &facts)) return 0;
    compare_review(data, size, &seen, &facts);
    compare_digest(data, size, &facts);
    return 0;
}
