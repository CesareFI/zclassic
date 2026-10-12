/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "zcl_zip243.h"
#include "zcl_tx_review.h"
#include "zcl_tx_stream_zip243.h"
#include "zcl_tx_replay_zip243.h"
#include "crypto/blake2b.h"
#include "zcl_zip243_host.h"

#include <openssl/evp.h>

#undef NDEBUG
#include <assert.h>
#include <stdio.h>
#include <string.h>

static int nibble(char value) {
    if (value >= '0' && value <= '9') return value - '0';
    if (value >= 'a' && value <= 'f') return value - 'a' + 10;
    return -1;
}

static size_t read_vector(const char *path, uint8_t wire[8192]) {
    FILE *file = fopen(path, "r");
    assert(file);
    static char line[16384];
    while (fgets(line, sizeof line, file) && line[0] == '#') {}
    assert(!ferror(file) && line[0] != '#');
    size_t length = strcspn(line, "\r\n");
    assert(length % 2 == 0 && length > 0 && length <= 16384);
    for (size_t i = 0; i < length / 2; ++i) {
        int hi = nibble(line[2 * i]), lo = nibble(line[2 * i + 1]);
        assert(hi >= 0 && lo >= 0);
        wire[i] = (uint8_t)((hi << 4) | lo);
    }
    assert(fclose(file) == 0);
    return length / 2;
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

static void ready_replay(zcl_tx_replay_zip243 *state,
    const uint8_t *wire, size_t length, const zcl_zip243_hasher *blake,
    const zcl_tx_replay_sha256 *sha) {
    assert(zcl_tx_replay_zip243_begin(state, (uint32_t)length, 0,
        0x76b809bb, blake, sha));
    for (unsigned pass = 0; pass < 3; ++pass) {
        assert(zcl_tx_replay_zip243_feed(state, wire, length));
        if (pass < 2) assert(zcl_tx_replay_zip243_next(state));
    }
}

static void replay_rejects_finish_alias(const uint8_t *wire, size_t length) {
    struct blake2b_ctx blake_context;
    EVP_MD_CTX *sha_context = EVP_MD_CTX_new();
    assert(sha_context);
    zcl_zip243_hasher blake = zcl_zip243_host_hasher(&blake_context);
    zcl_tx_replay_sha256 sha = {.context = sha_context, .init = sha_start,
        .update = sha_update, .final = sha_finish};
    zcl_tx_replay_zip243 state;
    ready_replay(&state, wire, length, &blake, &sha);
    union {
        zcl_tx_stream_facts facts;
        uint8_t bytes[sizeof(zcl_tx_stream_facts) + 32];
    } aliased;
    memset(&aliased, 0xa5, sizeof aliased);
    assert(!zcl_tx_replay_zip243_finish(&state, NULL, 0, 0,
        &aliased.facts, aliased.bytes + 1));
    assert(state.wire.failed);
    for (size_t i = 0; i < sizeof aliased.bytes; ++i)
        assert(aliased.bytes[i] == 0xa5);
    ready_replay(&state, wire, length, &blake, &sha);
    uint8_t digest[32];
    memset(digest, 0xa5, sizeof digest);
    assert(!zcl_tx_replay_zip243_finish(&state, NULL, 0, 0,
        &state.wire.facts, digest));
    assert(state.wire.failed);
    for (size_t i = 0; i < sizeof digest; ++i)
        assert(digest[i] == 0xa5);
    ready_replay(&state, wire, length, &blake, &sha);
    zcl_tx_stream_facts facts;
    memset(&facts, 0xa5, sizeof facts);
    assert(!zcl_tx_replay_zip243_finish(&state, state.outputs, 25, 0,
        &facts, digest));
    assert(state.wire.failed);
    for (size_t i = 0; i < sizeof facts; ++i)
        assert(((const uint8_t *)&facts)[i] == 0xa5);
    EVP_MD_CTX_free(sha_context);
}

static void replay_rejects_feed_alias(const uint8_t *wire, size_t length) {
    struct blake2b_ctx blake_context;
    EVP_MD_CTX *sha_context = EVP_MD_CTX_new();
    assert(sha_context);
    zcl_zip243_hasher blake = zcl_zip243_host_hasher(&blake_context);
    zcl_tx_replay_sha256 sha = {.context = sha_context, .init = sha_start,
        .update = sha_update, .final = sha_finish};
    zcl_tx_replay_zip243 state;
    assert(zcl_tx_replay_zip243_begin(&state, (uint32_t)length, 0,
        0x76b809bb, &blake, &sha));
    assert(zcl_tx_replay_zip243_feed(&state, wire, 1));
    state.commitment[0] = wire[1];
    assert(!zcl_tx_replay_zip243_feed(&state, state.commitment, 1));
    assert(state.wire.failed && state.wire.received == 0);
    assert(zcl_tx_replay_zip243_begin(&state, (uint32_t)length, 0,
        0x76b809bb, &blake, &sha));
    assert(zcl_tx_replay_zip243_feed(&state, wire, 1));
    state.commitment[31] = wire[1];
    state.prevouts[0] = wire[2];
    assert(!zcl_tx_replay_zip243_feed(&state, state.commitment + 31, 2));
    assert(state.wire.failed && state.wire.received == 0);
    assert(zcl_tx_replay_zip243_begin(&state, (uint32_t)length, 0,
        0x76b809bb, &blake, &sha));
    assert(zcl_tx_replay_zip243_feed(&state, wire, length));
    EVP_MD_CTX_free(sha_context);
}

static void replay_chunks(const uint8_t *wire, size_t length, size_t chunk,
    const uint8_t script_code[25], const uint8_t expected[32]) {
    struct blake2b_ctx blake_context;
    EVP_MD_CTX *sha_context = EVP_MD_CTX_new();
    assert(sha_context);
    zcl_zip243_hasher blake = zcl_zip243_host_hasher(&blake_context);
    zcl_tx_replay_sha256 sha = {.context = sha_context, .init = sha_start,
        .update = sha_update, .final = sha_finish};
    zcl_tx_replay_zip243 state;
    assert(zcl_tx_replay_zip243_begin(&state, (uint32_t)length, 0,
        0x76b809bb, &blake, &sha));
    for (unsigned pass = 0; pass < 3; ++pass) {
        for (size_t offset = 0; offset < length;) {
            size_t count = length - offset < chunk ? length - offset : chunk;
            assert(zcl_tx_replay_zip243_feed(&state, wire + offset, count));
            offset += count;
        }
        if (pass < 2) assert(zcl_tx_replay_zip243_next(&state));
    }
    zcl_tx_stream_facts facts;
    uint8_t digest[32];
    assert(zcl_tx_replay_zip243_finish(&state, script_code, 25,
        50000000, &facts, digest));
    assert(!memcmp(digest, expected, 32));
    assert(facts.inputs == 1 && facts.outputs == 2);
    assert(!zcl_tx_replay_zip243_finish(&state, script_code, 25,
        50000000, &facts, digest));
    EVP_MD_CTX_free(sha_context);
}

static void replay_rejects_changes(const uint8_t *wire, size_t length) {
    struct blake2b_ctx blake_context;
    EVP_MD_CTX *sha_context = EVP_MD_CTX_new();
    assert(sha_context);
    zcl_zip243_hasher blake = zcl_zip243_host_hasher(&blake_context);
    zcl_tx_replay_sha256 sha = {.context = sha_context, .init = sha_start,
        .update = sha_update, .final = sha_finish};
    zcl_tx_replay_zip243 state;
    assert(zcl_tx_replay_zip243_begin(&state, (uint32_t)length, 0,
        0x76b809bb, &blake, &sha));
    assert(zcl_tx_replay_zip243_feed(&state, wire, length));
    assert(zcl_tx_replay_zip243_next(&state));
    uint8_t changed[8192];
    memcpy(changed, wire, length);
    changed[20] ^= 1;
    assert(zcl_tx_replay_zip243_feed(&state, changed, length));
    assert(!zcl_tx_replay_zip243_next(&state));
    assert(!zcl_tx_replay_zip243_feed(&state, wire, length));
    assert(zcl_tx_replay_zip243_begin(&state, (uint32_t)length, 0,
        0x76b809bb, &blake, &sha));
    assert(zcl_tx_replay_zip243_feed(&state, wire, length - 1));
    assert(!zcl_tx_replay_zip243_next(&state));
    EVP_MD_CTX_free(sha_context);
}

static void shielded_byte_binding(uint8_t *wire, size_t length,
    size_t offset, bool bound, const uint8_t expected[32],
    const zcl_zip243_hasher *hasher) {
    wire[offset] ^= 1;
    uint8_t digest[32];
    assert(zcl_zip243_shielded_digest(wire, length, 0x76b809bb,
                                      hasher, digest) == 0);
    assert((memcmp(digest, expected, sizeof digest) != 0) == bound);
    wire[offset] ^= 1;
}

static void shielded_section_binding(uint8_t *wire, size_t length,
    const uint8_t expected[32], const zcl_zip243_hasher *hasher) {
    enum { OUTPUT_AMOUNT = 10, VALUE_BALANCE = 47, SPEND_CV = 56,
        SAPLING_OUTPUT_CV = 1209 };
    assert(length == 4118 && wire[8] == 0 && wire[9] == 2 &&
           wire[18] == 9 && wire[36] == 2 && wire[55] == 3 &&
           wire[1208] == 3 && wire[4053] == 0);
    shielded_byte_binding(wire, length, OUTPUT_AMOUNT, true,
                          expected, hasher);
    shielded_byte_binding(wire, length, VALUE_BALANCE, true,
                          expected, hasher);
    for (size_t i = 0; i < 3; ++i) {
        shielded_byte_binding(wire, length, SPEND_CV + i * 384,
                              true, expected, hasher);
        shielded_byte_binding(wire, length, SPEND_CV + 320 + i * 384,
                              false, expected, hasher);
        shielded_byte_binding(wire, length, SAPLING_OUTPUT_CV + i * 948,
                              true, expected, hasher);
    }
}

static void replay_rejects_missing_input(const uint8_t *wire, size_t length,
    const uint8_t script_code[25]) {
    struct blake2b_ctx blake_context;
    EVP_MD_CTX *sha_context = EVP_MD_CTX_new();
    assert(sha_context);
    zcl_zip243_hasher blake = zcl_zip243_host_hasher(&blake_context);
    zcl_tx_replay_sha256 sha = {.context = sha_context, .init = sha_start,
        .update = sha_update, .final = sha_finish};
    zcl_tx_replay_zip243 state;
    assert(zcl_tx_replay_zip243_begin(&state, (uint32_t)length, 1,
        0x76b809bb, &blake, &sha));
    for (unsigned pass = 0; pass < 3; ++pass) {
        assert(zcl_tx_replay_zip243_feed(&state, wire, length));
        if (pass < 2) assert(zcl_tx_replay_zip243_next(&state));
    }
    zcl_tx_stream_facts facts = {.inputs = 99};
    uint8_t digest[32];
    memset(digest, 0xff, sizeof digest);
    assert(!zcl_tx_replay_zip243_finish(&state, script_code, 25,
        50000000, &facts, digest));
    assert(facts.inputs == 0);
    for (size_t i = 0; i < sizeof digest; ++i) assert(digest[i] == 0);
    EVP_MD_CTX_free(sha_context);
}

static void test_streaming(const uint8_t *wire, size_t length,
    const uint8_t script_code[25]) {
    uint8_t unsigned_wire[8192];
    assert(length < sizeof unsigned_wire && wire[45] == 107);
    memcpy(unsigned_wire, wire, 46);
    memcpy(unsigned_wire + 46, wire + 46 + 107, length - 46 - 107);
    unsigned_wire[45] = 0;
    length -= 107;
    struct blake2b_ctx reference_context;
    zcl_zip243_hasher reference = zcl_zip243_host_hasher(&reference_context);
    uint8_t expected[32];
    assert(zcl_zip243_transparent_digest(unsigned_wire, length, 0,
        script_code, 25, 50000000, 0x76b809bb, &reference, expected) == 0);
    for (size_t chunk = 1; chunk <= length; ++chunk) {
        struct blake2b_ctx first_context, second_context;
        zcl_zip243_hasher first = zcl_zip243_host_hasher(&first_context);
        zcl_zip243_hasher second = zcl_zip243_host_hasher(&second_context);
        zcl_tx_stream_zip243 state;
        zcl_tx_stream_facts facts;
        uint8_t digest[32];
        assert(zcl_tx_stream_zip243_begin(&state, (uint32_t)length, 0,
            0x76b809bb, &first, &second));
        for (size_t offset = 0; offset < length;) {
            size_t count = length - offset < chunk ? length - offset : chunk;
            assert(zcl_tx_stream_zip243_feed(&state, unsigned_wire + offset,
                                            count));
            offset += count;
        }
        assert(zcl_tx_stream_zip243_finish(&state, script_code, 25,
            50000000, &facts, digest));
        assert(memcmp(digest, expected, 32) == 0);
        assert(facts.inputs == 1 && facts.outputs == 2);
        assert(facts.output_zat == 49999755);
        assert(!zcl_tx_stream_zip243_finish(&state, script_code, 25,
            50000000, &facts, digest));
        replay_chunks(unsigned_wire, length, chunk, script_code, expected);
    }
    replay_rejects_changes(unsigned_wire, length);
    replay_rejects_finish_alias(unsigned_wire, length);
    replay_rejects_feed_alias(unsigned_wire, length);
    replay_rejects_missing_input(unsigned_wire, length, script_code);
    struct blake2b_ctx first_context, second_context;
    zcl_zip243_hasher first = zcl_zip243_host_hasher(&first_context);
    zcl_zip243_hasher second = zcl_zip243_host_hasher(&second_context);
    zcl_tx_stream_zip243 state;
    zcl_tx_stream_facts facts = {.inputs = 99};
    uint8_t digest[32];
    memset(digest, 0xff, sizeof digest);
    assert(!zcl_tx_stream_zip243_begin(&state, (uint32_t)length, 0,
        0x76b809bb, &first, &first));
    assert(zcl_tx_stream_zip243_begin(&state, (uint32_t)length, 1,
        0x76b809bb, &first, &second));
    assert(zcl_tx_stream_zip243_feed(&state, unsigned_wire, length));
    assert(!zcl_tx_stream_zip243_finish(&state, script_code, 25,
        50000000, &facts, digest));
    assert(facts.inputs == 0);
    for (size_t i = 0; i < sizeof digest; ++i) assert(digest[i] == 0);
    assert(zcl_tx_stream_zip243_begin(&state, (uint32_t)length, 0,
        0x76b809bb, &first, &second));
    assert(zcl_tx_stream_zip243_feed(&state, unsigned_wire, length - 1));
    assert(!zcl_tx_stream_zip243_finish(&state, script_code, 25,
        50000000, &facts, digest));
}

static void mixed_sapling_binding(const uint8_t *transparent,
    size_t length, const uint8_t script_code[25],
    const zcl_zip243_hasher *hasher) {
    enum { OUTPUT_SIZE = 948, BINDING_SIZE = 64 };
    uint8_t wire[8192];
    assert(length + OUTPUT_SIZE + BINDING_SIZE < sizeof wire);
    assert(transparent[length - 3] == 0 &&
           transparent[length - 2] == 0 &&
           transparent[length - 1] == 0);
    memcpy(wire, transparent, length - 2);
    wire[length - 2] = 1;
    for (size_t i = 0; i < OUTPUT_SIZE; ++i)
        wire[length - 1 + i] = (uint8_t)(i * 17 + 3);
    wire[length - 1 + OUTPUT_SIZE] = 0;
    memset(wire + length + OUTPUT_SIZE, 0x5a, BINDING_SIZE);
    size_t mixed_length = length + OUTPUT_SIZE + BINDING_SIZE;
    zcl_tx_review review;
    assert(zcl_tx_review_parse(wire, mixed_length, &review) == 0);
    assert(review.sapling_spends == 0 && review.sapling_outputs == 1);
    zcl_tx_stream device_stream;
    assert(zcl_tx_stream_begin(&device_stream, (uint32_t)mixed_length));
    assert(!zcl_tx_stream_feed(&device_stream, wire, mixed_length,
                               NULL, NULL, NULL));
    uint8_t expected[32], digest[32];
    assert(zcl_zip243_transparent_digest(wire, mixed_length, 0,
        script_code, 25, 50000000, 0x76b809bb,
        hasher, expected) == 0);
    wire[length - 1] ^= 1;
    assert(zcl_zip243_transparent_digest(wire, mixed_length, 0,
        script_code, 25, 50000000, 0x76b809bb,
        hasher, digest) == 0 && memcmp(digest, expected, 32));
    wire[length - 1] ^= 1;
    wire[length + OUTPUT_SIZE - 2] ^= 1;
    assert(zcl_zip243_transparent_digest(wire, mixed_length, 0,
        script_code, 25, 50000000, 0x76b809bb,
        hasher, digest) == 0 && memcmp(digest, expected, 32));
    wire[length + OUTPUT_SIZE - 2] ^= 1;
    wire[mixed_length - 1] ^= 1;
    assert(zcl_zip243_transparent_digest(wire, mixed_length, 0,
        script_code, 25, 50000000, 0x76b809bb,
        hasher, digest) == 0 && !memcmp(digest, expected, 32));
}

int main(int argc, char **argv) {
    assert(argc == 3);
    static uint8_t wire[8192];
    struct blake2b_ctx context;
    zcl_zip243_hasher hasher = zcl_zip243_host_hasher(&context);
    size_t length = read_vector(argv[1], wire);
    assert(length == 4118);
    static const uint8_t expected[32] = {
        0x63, 0xd1, 0x85, 0x34, 0xde, 0x5f, 0x2d, 0x1c,
        0x9e, 0x16, 0x9b, 0x73, 0xf9, 0xc7, 0x83, 0x71,
        0x8a, 0xdb, 0xef, 0x5c, 0x8a, 0x7d, 0x55, 0xb5,
        0xe7, 0xa3, 0x7a, 0xff, 0xa1, 0xdd, 0x3f, 0xf3
    };
    uint8_t digest[32];
    assert(zcl_zip243_shielded_digest(wire, length, 0x76b809bb,
                                      &hasher, digest) == 0);
    assert(memcmp(digest, expected, 32) == 0);
    shielded_section_binding(wire, length, expected, &hasher);
    wire[length - 1] ^= 1;
    assert(zcl_zip243_shielded_digest(wire, length, 0x76b809bb,
                                      &hasher, digest) == 0);
    assert(memcmp(digest, expected, 32) == 0);
    wire[20] ^= 1;
    assert(zcl_zip243_shielded_digest(wire, length, 0x76b809bb,
                                      &hasher, digest) == 0);
    assert(memcmp(digest, expected, 32) != 0);
    wire[20] ^= 1;
    assert(zcl_zip243_shielded_digest(wire, length, 0x930b540d,
                                      &hasher, digest) == 0);
    assert(memcmp(digest, expected, 32) != 0);
    assert(zcl_zip243_shielded_digest(wire, length - 1, 0x76b809bb,
                                      &hasher, digest) < 0);
    length = read_vector(argv[2], wire);
    assert(length == 245);
    static const uint8_t script_code[25] = {
        0x76, 0xa9, 0x14, 0x50, 0x71, 0x73, 0x52, 0x7b,
        0x4c, 0x33, 0x18, 0xa2, 0xae, 0xcd, 0x79, 0x3b,
        0xf1, 0xcf, 0xed, 0x70, 0x59, 0x50, 0xcf, 0x88,
        0xac
    };
    static const uint8_t transparent_expected[32] = {
        0xf3, 0x14, 0x8f, 0x80, 0xdf, 0xab, 0x5e, 0x57,
        0x3d, 0x5e, 0xdf, 0xe7, 0xa8, 0x50, 0xf5, 0xfd,
        0x39, 0x23, 0x4f, 0x80, 0xb5, 0x42, 0x9d, 0x3a,
        0x57, 0xed, 0xcc, 0x11, 0xe3, 0x4c, 0x58, 0x5b
    };
    assert(zcl_zip243_transparent_digest(wire, length, 0,
                                         script_code, sizeof script_code,
                                         50000000, 0x76b809bb,
                                         &hasher, digest) == 0);
    assert(memcmp(digest, transparent_expected, 32) == 0);
    mixed_sapling_binding(wire, length, script_code, &hasher);
    test_streaming(wire, length, script_code);
    assert(zcl_zip243_transparent_digest(wire, length, 0,
                                         script_code, sizeof script_code,
                                         50000001, 0x76b809bb,
                                         &hasher, digest) == 0);
    assert(memcmp(digest, transparent_expected, 32) != 0);
    uint8_t changed_script[sizeof script_code];
    memcpy(changed_script, script_code, sizeof changed_script);
    changed_script[3] ^= 1;
    assert(zcl_zip243_transparent_digest(wire, length, 0,
                                         changed_script, sizeof changed_script,
                                         50000000, 0x76b809bb,
                                         &hasher, digest) == 0);
    assert(memcmp(digest, transparent_expected, 32) != 0);
    assert(zcl_zip243_transparent_digest(wire, length, 0,
                                         script_code, sizeof script_code,
                                         50000000, 0x930b540d,
                                         &hasher, digest) == 0);
    assert(memcmp(digest, transparent_expected, 32) != 0);
    assert(zcl_zip243_transparent_digest(wire, length, 1,
                                         script_code, sizeof script_code,
                                         50000000, 0x76b809bb,
                                         &hasher, digest) < 0);
    assert(zcl_zip243_transparent_digest(wire, length, 0,
                                         script_code, sizeof script_code,
                                         2100000000000001ULL, 0x76b809bb,
                                         &hasher, digest) < 0);
    assert(zcl_zip243_transparent_digest(wire, length, 0,
                                         NULL, sizeof script_code,
                                         50000000, 0x76b809bb,
                                         &hasher, digest) < 0);
    return 0;
}
