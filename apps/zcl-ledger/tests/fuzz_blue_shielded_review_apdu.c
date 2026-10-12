/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "blue_shielded_review_app.h"
#include "blue_sapling_fixture.h"
#include "zcl_zip243_host.h"

#include <stdlib.h>
#include <string.h>

static void check_lines(const blue_shielded_review_app *app) {
    for (unsigned i = 0; i < ZCL_BLUE_REVIEW_LINES; ++i)
        if (!memchr(app->lines[i], 0, ZCL_BLUE_REVIEW_LINE_SIZE)) abort();
}

static void check_reply_memory(const uint8_t *apdu,
    const uint8_t reply[260], size_t length, size_t capacity,
    size_t reply_length, bool shared, uint16_t status) {
    if (reply_length > capacity) abort();
    if (shared)
        for (size_t i = capacity; i < length; ++i)
            if (reply[i] != apdu[i]) abort();
    size_t untouched = shared && length > capacity ? length : capacity;
    for (size_t i = untouched; i < 260; ++i)
        if (reply[i] != 0xa5) abort();
    size_t cleared_from = status == 0x9000 ? reply_length : 0;
    for (size_t i = cleared_from; i < capacity; ++i)
        if (reply[i]) abort();
}

static void check_rejected(const blue_shielded_review_app *app,
    size_t reply_length) {
    if (reply_length || app->transaction.active ||
        app->transaction.complete ||
        strcmp(app->lines[0], "CONNECT Z23")) abort();
    const uint8_t *state = (const uint8_t *)&app->transaction;
    for (size_t i = 0; i < sizeof app->transaction; ++i)
        if (state[i]) abort();
    for (size_t i = 0; i < sizeof app->reply; ++i)
        if (app->reply[i]) abort();
}

static uint16_t send(blue_shielded_review_app *app,
    const zcl_zip243_hasher *hasher, const uint8_t *apdu,
    size_t length, size_t capacity, bool shared) {
    uint8_t reply[260];
    memset(reply, 0xa5, sizeof reply);
    if (shared) memcpy(reply, apdu, length);
    size_t reply_length = 255;
    uint16_t status = blue_shielded_review_app_command(app,
        shared ? reply : apdu,
        length, reply, capacity, &reply_length, hasher);
    check_reply_memory(apdu, reply, length, capacity,
        reply_length, shared, status);
    if (status != 0x9000) check_rejected(app, reply_length);
    check_lines(app);
    return status;
}

static void send_seed(blue_shielded_review_app *app,
    const zcl_zip243_hasher *hasher, const uint8_t *apdu,
    size_t length) {
    if (send(app, hasher, apdu, length, 78, true) != 0x9000) abort();
}

static void seed_review(blue_shielded_review_app *app,
    const zcl_zip243_hasher *hasher, unsigned stage) {
    uint8_t wire[BLUE_SYNTHETIC_SAPLING_BYTES];
    blue_sapling_fixture(wire);
    uint8_t begin[13] = {0xa5, 0x20, 0, 0, 8,
        0x91, 0x05, 0, 0, 0xbb, 0x09, 0xb8, 0x76};
    send_seed(app, hasher, begin, sizeof begin);
    if (stage == 1) return;
    for (unsigned pass = 1; pass <= 6; ++pass) {
        for (size_t offset = 0; offset < sizeof wire; offset += 220) {
            size_t take = sizeof wire - offset;
            if (take > 220) take = 220;
            uint8_t apdu[225] = {0xa5, 0x21, 0, 0, (uint8_t)take};
            memcpy(apdu + 5, wire + offset, take);
            send_seed(app, hasher, apdu, take + 5);
            if (stage == 2) return;
        }
        if (pass < 6) {
            const uint8_t next[5] = {0xa5, 0x22, 0, 0, 0};
            send_seed(app, hasher, next, sizeof next);
        }
    }
    const uint8_t finish[5] = {0xa5, 0x23, 0, 0, 0};
    send_seed(app, hasher, finish, sizeof finish);
    if (!app->transaction.complete) abort();
}

static void fuzz_commands(blue_shielded_review_app *app,
    const zcl_zip243_hasher *hasher, const uint8_t *data,
    size_t size) {
    for (size_t offset = 1; offset + 2 <= size;) {
        uint8_t control = data[offset++];
        size_t length = data[offset++];
        if (length > size - offset) length = size - offset;
        size_t capacity = (control & 31u) * 3u;
        if (capacity > 78) capacity = 78;
        send(app, hasher, data + offset, length, capacity,
            (control & 0x80u) != 0);
        offset += length;
        switch ((control >> 5) & 3u) {
        case 1: (void)blue_shielded_review_app_next(app); break;
        case 2: blue_shielded_review_app_toggle_text(app); break;
        case 3: blue_shielded_review_app_toggle_dark(app); break;
        default: break;
        }
        if (control & 0x10u) blue_shielded_review_app_reset(app);
        check_lines(app);
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (!data || !size || size > 4096) return 0;
    struct blake2b_ctx context;
    zcl_zip243_hasher hasher = zcl_zip243_host_hasher(&context);
    blue_shielded_review_app app = {0};
    blue_shielded_review_app_reset(&app);
    if (data[0] & 3u) seed_review(&app, &hasher, data[0] & 3u);
    fuzz_commands(&app, &hasher, data, size);
    blue_shielded_review_app_reset(&app);
    return 0;
}
