/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "blue_shielded_review_apdu.h"
#include "blue_review_screen.h"
#include "zcl_zip243.h"
#include "zcl_zip243_host.h"

#undef NDEBUG
#include <assert.h>
#include <stdio.h>
#include <string.h>

enum { BRANCH = 0x76b809bb, WIRE_MAX = 8192 };

static int nibble(char value) {
    if (value >= '0' && value <= '9') return value - '0';
    if (value >= 'a' && value <= 'f') return value - 'a' + 10;
    return -1;
}

static size_t read_vector(const char *path, uint8_t wire[WIRE_MAX]) {
    FILE *file = fopen(path, "r");
    assert(file);
    static char line[WIRE_MAX * 2 + 1];
    while (fgets(line, sizeof line, file) && line[0] == '#') {}
    size_t digits = strcspn(line, "\r\n");
    assert(digits && !(digits & 1u) && digits < sizeof line);
    for (size_t i = 0; i < digits / 2; ++i) {
        int high = nibble(line[i * 2]);
        int low = nibble(line[i * 2 + 1]);
        assert(high >= 0 && low >= 0);
        wire[i] = (uint8_t)((high << 4) | low);
    }
    assert(!ferror(file) && fclose(file) == 0);
    return digits / 2;
}

static uint32_t read_u32(const uint8_t *bytes) {
    return (uint32_t)bytes[0] | ((uint32_t)bytes[1] << 8) |
        ((uint32_t)bytes[2] << 16) | ((uint32_t)bytes[3] << 24);
}

static uint16_t command(blue_shielded_review_state *state,
    const zcl_zip243_hasher *hasher, uint8_t apdu[260],
    size_t length, size_t *reply_length) {
    uint16_t status = blue_shielded_review_handle(state, apdu, length,
        apdu, 255, reply_length, hasher);
    assert(*reply_length <= 255);
    for (size_t i = *reply_length; i < 255; ++i) assert(apdu[i] == 0);
    return status;
}

static void start(blue_shielded_review_state *state,
    const zcl_zip243_hasher *hasher, size_t wire_length) {
    uint8_t apdu[260] = {0xa5, 0x20, 0, 0, 8};
    size_t reply_length = 255;
    for (unsigned i = 0; i < 4; ++i) {
        apdu[5 + i] = (uint8_t)(wire_length >> (8 * i));
        apdu[9 + i] = (uint8_t)(BRANCH >> (8 * i));
    }
    assert(command(state, hasher, apdu, 13, &reply_length) == 0x9000);
    assert(reply_length == 0 && state->active && !state->complete);
}

static void upload(blue_shielded_review_state *state,
    const zcl_zip243_hasher *hasher, const uint8_t *wire,
    size_t wire_length, unsigned pass) {
    uint8_t apdu[260];
    size_t reply_length;
    for (size_t offset = 0; offset < wire_length; offset += 220) {
        size_t take = wire_length - offset < 220 ?
            wire_length - offset : 220;
        memcpy(apdu, (uint8_t[]){0xa5, 0x21, 0, 0,
            (uint8_t)take}, 5);
        memcpy(apdu + 5, wire + offset, take);
        assert(command(state, hasher, apdu, take + 5,
            &reply_length) == 0x9000);
        assert(reply_length == 5 && apdu[0] == pass);
        assert(read_u32(apdu + 1) == offset + take);
    }
}

static void advance(blue_shielded_review_state *state,
    const zcl_zip243_hasher *hasher, unsigned next_pass) {
    uint8_t apdu[260] = {0xa5, 0x22, 0, 0, 0};
    size_t reply_length;
    assert(command(state, hasher, apdu, 5, &reply_length) == 0x9000);
    assert(reply_length == 1 && apdu[0] == next_pass);
}

static void assert_erased(const blue_shielded_review_state *state) {
    const uint8_t *bytes = (const uint8_t *)state;
    for (size_t i = 0; i < sizeof *state; ++i) assert(bytes[i] == 0);
}

static void reject_state_alias(size_t wire_length) {
    struct blake2b_ctx context;
    zcl_zip243_hasher hasher = zcl_zip243_host_hasher(&context);
    blue_shielded_review_state state = {0};
    uint8_t reply[255];
    size_t reply_length = 99;
    start(&state, &hasher, wire_length);
    memcpy(state.digest, (uint8_t[]){0xa5, 0x01, 0, 0, 0}, 5);
    memset(reply, 0xa5, sizeof reply);
    assert(blue_shielded_review_handle(&state, state.digest, 5,
        reply, sizeof reply, &reply_length, &hasher) == 0x6a80);
    assert(reply_length == 0);
    for (size_t i = 0; i < sizeof reply; ++i) assert(reply[i] == 0);
    assert_erased(&state);
    start(&state, &hasher, wire_length);
    uint8_t identify[5] = {0xa5, 0x01, 0, 0, 0};
    assert(blue_shielded_review_handle(&state, identify, sizeof identify,
        state.digest, 5, &reply_length, &hasher) == 0x6a80);
    assert(reply_length == 0);
    assert_erased(&state);
    union {
        blue_shielded_review_state review;
        size_t aliased_length;
    } shared = {0};
    start(&shared.review, &hasher, wire_length);
    assert(blue_shielded_review_handle(&shared.review, identify,
        sizeof identify, reply, sizeof reply,
        &shared.aliased_length, &hasher) == 0x6a80);
    assert_erased(&shared.review);
}

static void successful_review(const uint8_t *wire, size_t wire_length) {
    struct blake2b_ctx context;
    zcl_zip243_hasher hasher = zcl_zip243_host_hasher(&context);
    blue_shielded_review_state state = {0};
    uint8_t apdu[260] = {0xa5, 0x01, 0, 0, 0};
    size_t reply_length;
    assert(command(&state, &hasher, apdu, 5,
        &reply_length) == 0x9000);
    assert(reply_length == 5 &&
        memcmp(apdu, "ZCL\x08\x40", 5) == 0);
    start(&state, &hasher, wire_length);
    char lines[ZCL_BLUE_REVIEW_LINES][ZCL_BLUE_REVIEW_LINE_SIZE];
    assert(blue_review_screen_progress(1, 0, (uint32_t)wire_length,
        lines));
    assert(strcmp(lines[0], "REVIEW PASS: 1/6") == 0);
    assert(strcmp(lines[1], "UPLOAD BYTES: 0/4118") == 0);
    assert(strcmp(lines[4], "READ ONLY; NO SIGNING") == 0);
    for (unsigned pass = 1; pass <= 6; ++pass) {
        upload(&state, &hasher, wire, wire_length, pass);
        assert(blue_review_screen_progress((uint8_t)pass,
            state.replay.wire.received, state.replay.expected, lines));
        assert(strstr(lines[1], "/4118") != NULL);
        if (pass < 6) advance(&state, &hasher, pass + 1);
    }
    memcpy(apdu, (uint8_t[]){0xa5, 0x23, 0, 0, 0}, 5);
    assert(command(&state, &hasher, apdu, 5,
        &reply_length) == 0x9000);
    assert(reply_length == 108 && !state.active && state.complete);
    assert(read_u32(apdu) == state.facts.transparent_inputs);
    assert(read_u32(apdu + 4) == state.facts.transparent_outputs);
    assert(read_u32(apdu + 8) == state.facts.sapling_spends);
    assert(read_u32(apdu + 12) == state.facts.sapling_outputs);
    assert(memcmp(apdu + 44, state.digest, 32) == 0);
    uint8_t expected[32];
    assert(zcl_zip243_shielded_digest(wire, wire_length, BRANCH,
        &hasher, expected) == 0);
    assert(memcmp(apdu + 44, expected, 32) == 0);
    zsha256_ctx sha;
    zsha256_init(&sha);
    zsha256_update(&sha, wire, wire_length);
    zsha256_final(&sha, expected);
    assert(memcmp(apdu + 76, expected, 32) == 0);
    assert(blue_review_screen_zip243(apdu, lines));
    assert(strncmp(lines[5], "ZIP243 PREFIX: ", 15) == 0);
    assert(strcmp(lines[4], "SHIELDED HIDDEN; NO SIGNING") == 0);
    assert(strncmp(lines[3], "FEE UNKNOWN", 11) == 0);
    assert(!blue_review_screen_progress(7, 0,
        (uint32_t)wire_length, lines));
    memcpy(apdu, (uint8_t[]){0xa5, 0x30, 0, 0, 0}, 5);
    assert(command(&state, &hasher, apdu, 5,
        &reply_length) == 0x6d00);
    assert(reply_length == 0);
    assert_erased(&state);
}

static void rejected_review(const uint8_t *wire, size_t wire_length) {
    struct blake2b_ctx context;
    zcl_zip243_hasher hasher = zcl_zip243_host_hasher(&context);
    blue_shielded_review_state state = {0};
    uint8_t apdu[260] = {0xa5, 0x22, 0, 0, 0};
    size_t reply_length;
    assert(command(&state, &hasher, apdu, 5,
        &reply_length) == 0x6985);
    for (size_t i = 0; i < 76; ++i) assert(apdu[i] == 0);
    assert_erased(&state);
    start(&state, &hasher, wire_length);
    memcpy(apdu, (uint8_t[]){0xa5, 0x22, 0, 0, 0}, 5);
    assert(command(&state, &hasher, apdu, 5,
        &reply_length) == 0x6a80);
    assert_erased(&state);
    start(&state, &hasher, wire_length);
    memcpy(apdu, (uint8_t[]){0xa5, 0x21, 0, 0, 221}, 5);
    memset(apdu + 5, 0, 221);
    assert(command(&state, &hasher, apdu, 226,
        &reply_length) == 0x6700);
    assert_erased(&state);
    start(&state, &hasher, wire_length);
    memcpy(apdu, (uint8_t[]){0xa5, 0x21, 0, 0, 1}, 5);
    apdu[5] = wire[0];
    assert(command(&state, &hasher, apdu, 5,
        &reply_length) == 0x6700);
    assert_erased(&state);
    start(&state, &hasher, wire_length);
    upload(&state, &hasher, wire, wire_length, 1);
    advance(&state, &hasher, 2);
    memcpy(apdu, (uint8_t[]){0xa5, 0x24, 0, 0, 0}, 5);
    assert(command(&state, &hasher, apdu, 5,
        &reply_length) == 0x9000);
    assert_erased(&state);
}

static void substituted_pass(const uint8_t *wire,
    size_t wire_length, size_t changed_offset) {
    struct blake2b_ctx context;
    zcl_zip243_hasher hasher = zcl_zip243_host_hasher(&context);
    blue_shielded_review_state state = {0};
    uint8_t changed[WIRE_MAX], apdu[260];
    size_t reply_length;
    assert(wire_length <= sizeof changed && changed_offset < wire_length);
    memcpy(changed, wire, wire_length);
    changed[changed_offset] ^= 1u;
    for (unsigned changed_pass = 2; changed_pass <= 6;
         ++changed_pass) {
        start(&state, &hasher, wire_length);
        for (unsigned pass = 1; pass <= changed_pass; ++pass) {
            upload(&state, &hasher,
                pass == changed_pass ? changed : wire,
                wire_length, pass);
            if (pass < changed_pass)
                advance(&state, &hasher, pass + 1);
        }
        memcpy(apdu, (uint8_t[]){0xa5,
            changed_pass == 6 ? 0x23 : 0x22, 0, 0, 0}, 5);
        assert(command(&state, &hasher, apdu, 5,
            &reply_length) == 0x6a80);
        assert(reply_length == 0);
        assert_erased(&state);
    }
}

static void substituted_binding_signature(const uint8_t *wire,
    size_t wire_length) {
    struct blake2b_ctx context;
    zcl_zip243_hasher hasher = zcl_zip243_host_hasher(&context);
    uint8_t changed[WIRE_MAX], original_digest[32], changed_digest[32];
    assert(wire_length && wire_length <= sizeof changed);
    memcpy(changed, wire, wire_length);
    changed[wire_length - 1] ^= 1u;
    assert(zcl_zip243_shielded_digest(wire, wire_length, BRANCH,
        &hasher, original_digest) == 0);
    assert(zcl_zip243_shielded_digest(changed, wire_length, BRANCH,
        &hasher, changed_digest) == 0);
    assert(memcmp(original_digest, changed_digest, 32) == 0);
    substituted_pass(wire, wire_length, wire_length - 1);
}

static void reject_branch(size_t wire_length) {
    struct blake2b_ctx context;
    zcl_zip243_hasher hasher = zcl_zip243_host_hasher(&context);
    blue_shielded_review_state state = {0};
    uint8_t apdu[260] = {0xa5, 0x20, 0, 0, 8};
    size_t reply_length;
    for (unsigned i = 0; i < 4; ++i)
        apdu[5 + i] = (uint8_t)(wire_length >> (8 * i));
    assert(command(&state, &hasher, apdu, 13,
        &reply_length) == 0x6a80);
    assert_erased(&state);
}

static uint32_t random_word(uint32_t *seed) {
    *seed = *seed * 1664525u + 1013904223u;
    return *seed;
}

static void random_commands(size_t wire_length) {
    struct blake2b_ctx context;
    zcl_zip243_hasher hasher = zcl_zip243_host_hasher(&context);
    blue_shielded_review_state state = {0};
    uint8_t apdu[260];
    uint32_t seed = 0x5a23c0de;
    for (unsigned trial = 0; trial < 10000; ++trial) {
        if (!(trial % 17)) start(&state, &hasher, wire_length);
        size_t length = random_word(&seed) % (sizeof apdu + 1u);
        for (size_t i = 0; i < length; ++i)
            apdu[i] = (uint8_t)(random_word(&seed) >> 24);
        size_t reply_length = 255;
        uint16_t status = command(&state, &hasher, apdu,
            length, &reply_length);
        if (status == 0x9000) assert(reply_length <= 255);
        else {
            assert(reply_length == 0);
            assert_erased(&state);
        }
    }
}

static void interrupted_upload(const uint8_t *wire,
    size_t wire_length) {
    struct blake2b_ctx context;
    zcl_zip243_hasher hasher = zcl_zip243_host_hasher(&context);
    blue_shielded_review_state state = {0};
    uint8_t apdu[260] = {0xa5, 0x21, 0, 0, 220};
    size_t reply_length;
    start(&state, &hasher, wire_length);
    memcpy(apdu + 5, wire, 220);
    assert(command(&state, &hasher, apdu, 225,
        &reply_length) == 0x9000);
    blue_shielded_review_abort(&state);
    assert_erased(&state);
    memcpy(apdu, (uint8_t[]){0xa5, 0x23, 0, 0, 0}, 5);
    assert(command(&state, &hasher, apdu, 5,
        &reply_length) == 0x6985);
    assert_erased(&state);
    start(&state, &hasher, wire_length);
    upload(&state, &hasher, wire, wire_length, 1);
    advance(&state, &hasher, 2);
}

int main(int argc, char **argv) {
    assert(argc == 2);
    uint8_t wire[WIRE_MAX];
    size_t length = read_vector(argv[1], wire);
    assert(length == 4118);
    successful_review(wire, length);
    rejected_review(wire, length);
    reject_state_alias(length);
    substituted_pass(wire, length, length / 2);
    substituted_binding_signature(wire, length);
    reject_branch(length);
    interrupted_upload(wire, length);
    random_commands(length);
    puts("six-pass Blue APDU review and fail-closed interactions: passed");
    return 0;
}
