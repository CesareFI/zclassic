/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "zcl_tx_previous_stream.h"
#include "zcl_tx_review.h"

#include <openssl/evp.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(condition) do { if (!(condition)) { \
    fprintf(stderr, "check failed at line %d: %s\n", __LINE__, #condition); \
    abort(); \
} } while (0)

typedef struct {
    uint8_t bytes[6000];
    size_t length, selected_script;
} transaction;

static void put_bytes(transaction *tx, const uint8_t *bytes, size_t count) {
    CHECK(tx->length + count <= sizeof tx->bytes);
    memcpy(tx->bytes + tx->length, bytes, count);
    tx->length += count;
}

static void zeros(transaction *tx, size_t count) {
    CHECK(tx->length + count <= sizeof tx->bytes);
    memset(tx->bytes + tx->length, 0, count);
    tx->length += count;
}

static void put_u32(transaction *tx, uint32_t value) {
    for (unsigned i = 0; i < 4; ++i)
        tx->bytes[tx->length++] = (uint8_t)(value >> (8 * i));
}

static void put_u64(transaction *tx, uint64_t value) {
    for (unsigned i = 0; i < 8; ++i)
        tx->bytes[tx->length++] = (uint8_t)(value >> (8 * i));
}

static transaction fixture(unsigned version) {
    transaction tx = {0};
    put_u32(&tx, version >= 3 ? 0x80000000u | version : version);
    if (version >= 3)
        put_u32(&tx, version == 3 ? 0x03c48270u : 0x892f2085u);
    tx.bytes[tx.length++] = 1;
    zeros(&tx, 32);
    put_u32(&tx, UINT32_MAX);
    tx.bytes[tx.length++] = 2;
    tx.bytes[tx.length++] = 1;
    tx.bytes[tx.length++] = 1;
    put_u32(&tx, UINT32_MAX);
    tx.bytes[tx.length++] = 2;
    put_u64(&tx, 0);
    tx.bytes[tx.length++] = 1;
    tx.bytes[tx.length++] = 0x6a;
    put_u64(&tx, 50000000);
    tx.bytes[tx.length++] = 25;
    tx.selected_script = tx.length;
    static const uint8_t prefix[] = {0x76, 0xa9, 0x14};
    static const uint8_t suffix[] = {0x88, 0xac};
    put_bytes(&tx, prefix, sizeof prefix);
    for (unsigned i = 0; i < 20; ++i) tx.bytes[tx.length++] = 0x11;
    put_bytes(&tx, suffix, sizeof suffix);
    put_u32(&tx, 0);
    if (version >= 3) put_u32(&tx, 0);
    if (version == 4) {
        put_u64(&tx, 0);
        tx.bytes[tx.length++] = 1;
        zeros(&tx, 384);
        tx.bytes[tx.length++] = 1;
        zeros(&tx, 948);
    }
    if (version >= 2) {
        tx.bytes[tx.length++] = 1;
        zeros(&tx, version == 4 ? 1634 : 1738);
        zeros(&tx, 96);
    }
    if (version == 4) zeros(&tx, 64);
    return tx;
}

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

static void txid(const transaction *tx, uint8_t digest[32]) {
    uint8_t first[32];
    CHECK(SHA256(tx->bytes, tx->length, first));
    CHECK(SHA256(first, sizeof first, digest));
}

static bool stream_select(const transaction *tx, size_t chunk,
    const uint8_t expected_txid[32], uint32_t index,
    zcl_tx_previous_p2pkh *output) {
    EVP_MD_CTX *context = EVP_MD_CTX_new();
    CHECK(context);
    zcl_tx_previous_sha256 hash = {.context = context,
        .init = hash_init, .update = hash_update, .final = hash_final};
    zcl_tx_previous_stream stream;
    bool valid = zcl_tx_previous_stream_begin(&stream,
        (uint32_t)tx->length, index, hash);
    for (size_t offset = 0; valid && offset < tx->length; offset += chunk) {
        size_t count = tx->length - offset < chunk ?
            tx->length - offset : chunk;
        valid = zcl_tx_previous_stream_feed(&stream,
            tx->bytes + offset, count);
    }
    if (valid) valid = zcl_tx_previous_stream_finish(&stream,
                                                     expected_txid, output);
    EVP_MD_CTX_free(context);
    return valid;
}

static void check_version(unsigned version) {
    transaction tx = fixture(version);
    uint8_t expected[32];
    txid(&tx, expected);
    zcl_tx_previous_output direct;
    CHECK(zcl_tx_previous_output_select(tx.bytes, tx.length, 1,
                                        &direct) == 0);
    for (size_t chunk = 1; chunk <= 128; chunk = chunk == 1 ? 7 : 128) {
        zcl_tx_previous_p2pkh output = {0};
        CHECK(stream_select(&tx, chunk, expected, 1, &output));
        CHECK(output.value_zat == direct.value_zat);
        CHECK(memcmp(output.script, direct.script, sizeof output.script) == 0);
        if (chunk == 128) break;
    }
    zcl_tx_previous_p2pkh unchanged = {.value_zat = 17};
    memset(unchanged.script, 0x5a, sizeof unchanged.script);
    zcl_tx_previous_p2pkh output = unchanged;
    expected[0] ^= 1;
    CHECK(!stream_select(&tx, 128, expected, 1, &output));
    CHECK(output.value_zat == unchanged.value_zat);
    CHECK(memcmp(output.script, unchanged.script, sizeof output.script) == 0);
    expected[0] ^= 1;
    CHECK(!stream_select(&tx, 128, expected, 0, &output));
    CHECK(!stream_select(&tx, 128, expected, 2, &output));
    tx.bytes[tx.selected_script] = 0x6a;
    txid(&tx, expected);
    CHECK(!stream_select(&tx, 128, expected, 1, &output));
}

int main(void) {
    for (unsigned version = 1; version <= 4; ++version)
        check_version(version);
    return 0;
}
