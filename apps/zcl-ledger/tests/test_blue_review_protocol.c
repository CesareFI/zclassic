/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "blue_review_protocol.h"
#include "blue_review_screen.h"
#include "zcl_zip243_host.h"

#undef NDEBUG
#include <assert.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <string.h>

static int nibble(char value) {
    if (value >= '0' && value <= '9') return value - '0';
    if (value >= 'a' && value <= 'f') return value - 'a' + 10;
    return -1;
}

static size_t read_vector(const char *path, uint8_t wire[245]) {
    FILE *file = fopen(path, "r");
    assert(file);
    char line[512];
    bool found = false;
    while (fgets(line, sizeof line, file)) {
        if (line[0] != '#') { found = true; break; }
    }
    assert(found);
    size_t length = strcspn(line, "\r\n");
    assert(!ferror(file) && length == 490);
    for (size_t i = 0; i < 245; ++i) {
        int hi = nibble(line[2 * i]), lo = nibble(line[2 * i + 1]);
        assert(hi >= 0 && lo >= 0);
        wire[i] = (uint8_t)((hi << 4) | lo);
    }
    assert(fclose(file) == 0);
    return length / 2;
}

static bool transaction_digest(const uint8_t *wire, size_t length,
                               uint8_t digest[32]) {
    return SHA256(wire, length, digest) != NULL;
}

static uint16_t call(blue_review_state *state, uint8_t *apdu, size_t length,
                     size_t *reply_length) {
    struct blake2b_ctx context;
    zcl_zip243_hasher hasher = zcl_zip243_host_hasher(&context);
    return blue_review_handle(state, apdu, length, apdu, 255,
                              reply_length, transaction_digest,
                              &hasher);
}

static void test_minimal_review(void) {
    blue_review_state state = {0};
    uint8_t apdu[260] = {0xa5, 0x01};
    size_t reply_length = 0;
    assert(call(&state, apdu, 5, &reply_length) == 0x9000);
    assert(reply_length == 5 && memcmp(apdu, "ZCL\x06\x40", 5) == 0);

    const uint8_t begin[] = {0xa5, 0x10, 0, 0, 2, 29, 0};
    memcpy(apdu, begin, sizeof begin);
    assert(call(&state, apdu, sizeof begin, &reply_length) == 0x9000);
    assert(reply_length == 0);
    const uint8_t header[] = {4, 0, 0, 0x80, 0x85, 0x20, 0x2f, 0x89};
    memset(apdu, 0, sizeof apdu);
    apdu[0] = 0xa5;
    apdu[1] = 0x11;
    apdu[4] = 29;
    memcpy(apdu + 5, header, sizeof header);
    assert(call(&state, apdu, 34, &reply_length) == 0x9000);
    static const uint8_t zip_command[] = {
        0xa5, 0x14, 0, 0, 4, 0xbb, 0x09, 0xb8, 0x76
    };
    memcpy(apdu, zip_command, sizeof zip_command);
    assert(call(&state, apdu, sizeof zip_command, &reply_length) == 0x9000);
    assert(reply_length == 32);
    uint8_t zip_digest[32];
    uint8_t zip_wire[29] = {4, 0, 0, 0x80, 0x85, 0x20, 0x2f, 0x89};
    struct blake2b_ctx context;
    zcl_zip243_hasher hasher = zcl_zip243_host_hasher(&context);
    assert(zcl_zip243_shielded_digest(zip_wire, sizeof zip_wire, 0x76b809bb,
                                      &hasher, zip_digest) == 0);
    assert(memcmp(apdu, zip_digest, 32) == 0);
    memcpy(apdu, (uint8_t[]){0xa5, 0x12, 0, 0, 0}, 5);
    assert(call(&state, apdu, 5, &reply_length) == 0x9000);
    assert(reply_length == 76);
    assert(state.reviewed_length == 29);
    for (size_t i = 0; i < 44; ++i) assert(apdu[i] == 0);
    char lines[ZCL_BLUE_REVIEW_LINES][ZCL_BLUE_REVIEW_LINE_SIZE];
    assert(blue_review_screen_format(apdu, lines));
    assert(strcmp(lines[0], "PUBLIC IN/OUT: 0/0") == 0);
    assert(strcmp(lines[5], "TX SHA256: 0ba4f12d34aa8160") == 0);
    static const uint8_t digest[32] = {
        0x0b, 0xa4, 0xf1, 0x2d, 0x34, 0xaa, 0x81, 0x60,
        0x56, 0x3c, 0xe2, 0xe3, 0x4b, 0x46, 0x2b, 0xc3,
        0x91, 0xc7, 0x8e, 0xbb, 0x37, 0x1c, 0x4a, 0xe5,
        0x72, 0xc5, 0x46, 0xc1, 0xea, 0xde, 0xeb, 0xfd
    };
    assert(memcmp(apdu + 44, digest, sizeof digest) == 0);
    assert(call(&state, apdu, 5, &reply_length) == 0x6e00);
    memcpy(apdu, begin, sizeof begin);
    assert(call(&state, apdu, sizeof begin, &reply_length) == 0x9000);
    assert(state.reviewed_length == 0);
    for (size_t i = 0; i < sizeof state.wire; ++i)
        assert(state.wire[i] == 0);
}

static void test_state_and_bounds(void) {
    blue_review_state state = {0};
    uint8_t apdu[260] = {0xa5, 0x12};
    size_t reply_length = 9;
    assert(call(&state, apdu, 5, &reply_length) == 0x6985);
    assert(reply_length == 0);
    apdu[1] = 0x10;
    apdu[4] = 2;
    apdu[5] = (uint8_t)ZCL_BLUE_REVIEW_MAX_BYTES;
    apdu[6] = (uint8_t)(ZCL_BLUE_REVIEW_MAX_BYTES >> 8);
    assert(call(&state, apdu, 7, &reply_length) == 0x9000);
    assert(state.expected == ZCL_BLUE_REVIEW_MAX_BYTES);
    apdu[5]++;
    assert(call(&state, apdu, 7, &reply_length) == 0x6a80);
    apdu[5] = 1;
    assert(call(&state, apdu, 7, &reply_length) == 0x6a80);
    assert(state.expected == 0);
    assert(state.reviewed_length == 0);
    apdu[5] = 29;
    apdu[6] = 0;
    assert(call(&state, apdu, 7, &reply_length) == 0x9000);
    apdu[1] = 0x11;
    apdu[4] = 30;
    assert(call(&state, apdu, 35, &reply_length) == 0x6a80);
    assert(state.expected == 0);
    apdu[1] = 0x12;
    apdu[4] = 0;
    assert(call(&state, apdu, 5, &reply_length) == 0x6985);
    apdu[0] = 0;
    assert(call(&state, apdu, 5, &reply_length) == 0x6e00);
    struct blake2b_ctx context;
    zcl_zip243_hasher hasher = zcl_zip243_host_hasher(&context);
    assert(blue_review_handle(NULL, apdu, 5, apdu, 255,
                              &reply_length, transaction_digest,
                              &hasher) == 0x6a80);
}

static void assert_cleared(const blue_review_state *state) {
    const uint8_t *bytes = (const uint8_t *)state;
    for (size_t i = 0; i < sizeof *state; ++i) assert(bytes[i] == 0);
}

static void test_rejected_command_erases_review(void) {
    blue_review_state state = {0};
    uint8_t apdu[260] = {0xa5, 0x10, 0, 0, 2, 29, 0};
    size_t reply_length = 0;
    assert(call(&state, apdu, 7, &reply_length) == 0x9000);
    memcpy(apdu, (uint8_t[]){0xa5, 0x11, 0, 0, 8,
                            4, 0, 0, 0x80, 0x85, 0x20, 0x2f, 0x89}, 13);
    assert(call(&state, apdu, 13, &reply_length) == 0x9000);
    assert(state.received == 8 && state.wire[3] == 0x80);
    apdu[0] = 0;
    assert(call(&state, apdu, 13, &reply_length) == 0x6e00);
    assert(reply_length == 0);
    assert_cleared(&state);
    memcpy(apdu, (uint8_t[]){0xa5, 0x12, 0, 0, 0}, 5);
    assert(call(&state, apdu, 5, &reply_length) == 0x6985);

    memcpy(apdu, (uint8_t[]){0xa5, 0x10, 0, 0, 2, 29, 0}, 7);
    assert(call(&state, apdu, 7, &reply_length) == 0x9000);
    memset(apdu, 0, 34);
    apdu[0] = 0xa5;
    apdu[1] = 0x11;
    apdu[4] = 29;
    memcpy(apdu + 5, (uint8_t[]){4, 0, 0, 0x80, 0x85, 0x20, 0x2f, 0x89}, 8);
    assert(call(&state, apdu, 34, &reply_length) == 0x9000);
    memcpy(apdu, (uint8_t[]){0xa5, 0x12, 0, 0, 0}, 5);
    assert(call(&state, apdu, 5, &reply_length) == 0x9000);
    assert(state.reviewed_length == 29 && state.wire[3] == 0x80);
    memcpy(apdu, (uint8_t[]){0xa5, 0xff, 0, 0, 0}, 5);
    assert(call(&state, apdu, 5, &reply_length) == 0x6d00);
    assert(reply_length == 0);
    assert_cleared(&state);
}

static void test_published_transaction(const char *path) {
    uint8_t wire[245];
    size_t length = read_vector(path, wire);
    blue_review_state state = {0};
    uint8_t apdu[260] = {0xa5, 0x10, 0, 0, 2, 245, 0};
    size_t reply_length;
    assert(call(&state, apdu, 7, &reply_length) == 0x9000);
    for (size_t offset = 0; offset < length; offset += 220) {
        size_t count = length - offset < 220 ? length - offset : 220;
        apdu[1] = 0x11;
        apdu[4] = (uint8_t)count;
        memcpy(apdu + 5, wire + offset, count);
        assert(call(&state, apdu, 5 + count, &reply_length) == 0x9000);
    }
    static const uint8_t branch[] = {
        0xa5, 0x14, 0, 0, 4, 0xbb, 0x09, 0xb8, 0x76
    };
    memcpy(apdu, branch, sizeof branch);
    assert(call(&state, apdu, sizeof branch, &reply_length) == 0x9000);
    assert(reply_length == 32);
    memcpy(apdu, (const uint8_t[]){0xa5, 0x12, 0, 0, 0}, 5);
    assert(call(&state, apdu, 5, &reply_length) == 0x9000);
    assert(reply_length == 76 && state.reviewed_length == 245);
    char lines[ZCL_BLUE_REVIEW_LINES][ZCL_BLUE_REVIEW_LINE_SIZE];
    assert(blue_review_screen_format(apdu, lines));
    assert(strcmp(lines[0], "PUBLIC IN/OUT: 1/2") == 0);
    assert(strcmp(lines[1], "PUB OUT: 0.49999755 ZCL") == 0);
}

int main(int argc, char **argv) {
    assert(argc == 2);
    test_minimal_review();
    test_state_and_bounds();
    test_rejected_command_erases_review();
    test_published_transaction(argv[1]);
    return 0;
}
