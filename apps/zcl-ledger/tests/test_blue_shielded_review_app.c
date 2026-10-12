/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "blue_shielded_review_app.h"
#include "blue_sapling_fixture.h"
#include "zcl_zip243_host.h"

#undef NDEBUG
#include <assert.h>
#include <stdio.h>
#include <string.h>

enum { BRANCH = 0x76b809bb };

static uint16_t command(blue_shielded_review_app *app,
    const zcl_zip243_hasher *hasher, uint8_t apdu[260],
    size_t length, size_t *reply_length) {
    uint16_t status = blue_shielded_review_app_command(app, apdu, length,
        apdu, 255, reply_length, hasher);
    assert(*reply_length <= 255);
    for (size_t i = *reply_length; i < 255; ++i) assert(apdu[i] == 0);
    return status;
}

static void begin(blue_shielded_review_app *app,
    const zcl_zip243_hasher *hasher) {
    uint8_t apdu[260] = {0xa5, 0x20, 0, 0, 8};
    size_t reply_length;
    for (unsigned i = 0; i < 4; ++i) {
        apdu[5 + i] = (uint8_t)(BLUE_SYNTHETIC_SAPLING_BYTES >> (8 * i));
        apdu[9 + i] = (uint8_t)(BRANCH >> (8 * i));
    }
    assert(command(app, hasher, apdu, 13, &reply_length) == 0x9000);
    assert(reply_length == 0 && app->transaction.active);
    assert(strcmp(app->lines[0], "REVIEW PASS: 1/6") == 0);
}

static void upload(blue_shielded_review_app *app,
    const zcl_zip243_hasher *hasher, const uint8_t *wire,
    unsigned pass) {
    uint8_t apdu[260];
    size_t reply_length;
    for (size_t offset = 0; offset < BLUE_SYNTHETIC_SAPLING_BYTES;
         offset += 220) {
        size_t take = BLUE_SYNTHETIC_SAPLING_BYTES - offset;
        if (take > 220) take = 220;
        memcpy(apdu, (uint8_t[]){0xa5, 0x21, 0, 0,
            (uint8_t)take}, 5);
        memcpy(apdu + 5, wire + offset, take);
        assert(command(app, hasher, apdu, take + 5,
            &reply_length) == 0x9000);
        assert(reply_length == 5);
    }
    char expected[32];
    assert(snprintf(expected, sizeof expected, "REVIEW PASS: %u/6",
        pass) > 0);
    assert(strcmp(app->lines[0], expected) == 0);
    assert(strcmp(app->lines[1], "UPLOAD BYTES: 1425/1425") == 0);
}

static void advance(blue_shielded_review_app *app,
    const zcl_zip243_hasher *hasher, unsigned pass) {
    uint8_t apdu[260] = {0xa5, 0x22, 0, 0, 0};
    size_t reply_length;
    assert(command(app, hasher, apdu, 5, &reply_length) == 0x9000);
    assert(reply_length == 1 && apdu[0] == pass);
}

static void review(blue_shielded_review_app *app,
    const zcl_zip243_hasher *hasher, const uint8_t *wire) {
    begin(app, hasher);
    for (unsigned pass = 1; pass <= 6; ++pass) {
        upload(app, hasher, wire, pass);
        if (pass < 6) advance(app, hasher, pass + 1);
    }
    uint8_t apdu[260] = {0xa5, 0x23, 0, 0, 0};
    size_t reply_length;
    assert(command(app, hasher, apdu, 5, &reply_length) == 0x9000);
    assert(reply_length == 108 && app->transaction.complete &&
        app->transaction.branch_id == 0x76b809bb);
    assert(strcmp(app->lines[0], "PUBLIC IN/OUT: 0/0") == 0);
    assert(strcmp(app->lines[2], "SHIELDED SPEND/OUT: 1/1") == 0);
    assert(strncmp(app->lines[3], "FEE UNKNOWN", 11) == 0);
    assert(strcmp(app->lines[4], "SHIELDED HIDDEN; NO SIGNING") == 0);
    assert(strncmp(app->lines[5], "ZIP243 PREFIX: ", 15) == 0);
}

static void inspect_pages(blue_shielded_review_app *app) {
    assert(blue_shielded_review_app_next(app));
    assert(app->page == 1 &&
        strcmp(app->lines[0], "ZIP243 BRANCH 0x76B809BB") == 0);
    assert(strlen(app->lines[1]) == 16);
    assert(strcmp(app->lines[5], "CHAIN UNCHECKED; NO SIGNING") == 0);
    assert(blue_shielded_review_app_next(app));
    assert(app->page == 2 &&
        strcmp(app->lines[0], "FULL WIRE SHA-256") == 0);
    assert(strcmp(app->lines[5], "READ ONLY; NO SIGNING") == 0);
    assert(blue_shielded_review_app_next(app));
    assert(app->page == 0 &&
        strcmp(app->lines[0], "PUBLIC IN/OUT: 0/0") == 0);
    blue_shielded_review_app_toggle_text(app);
    blue_shielded_review_app_toggle_dark(app);
    assert(app->large_text && app->dark);
    assert(blue_shielded_review_app_next(app));
    assert(app->detail == 1);
}

static void formatted_failure(blue_shielded_review_app *app,
    const zcl_zip243_hasher *hasher, const uint8_t *wire) {
    begin(app, hasher);
    app->transaction.replay.expected = 0;
    uint8_t apdu[260] = {0xa5, 0x21, 0, 0, 1};
    apdu[5] = wire[0];
    size_t reply_length = 255;
    assert(command(app, hasher, apdu, 6, &reply_length) == 0x6a80);
    assert(reply_length == 0);
    for (size_t i = 0; i < 255; ++i)
        assert(apdu[i] == 0);
    assert(!app->transaction.active && !app->transaction.complete);
    assert(strcmp(app->lines[0], "CONNECT Z23") == 0);
}

static void reject_app_alias(blue_shielded_review_app *app,
    const zcl_zip243_hasher *hasher) {
    begin(app, hasher);
    memcpy(app->reply, (uint8_t[]){0xa5, 0x01, 0, 0, 0}, 5);
    uint8_t reply[255];
    memset(reply, 0xa5, sizeof reply);
    size_t reply_length = 255;
    assert(blue_shielded_review_app_command(app, app->reply, 5,
        reply, sizeof reply, &reply_length, hasher) == 0x6a80);
    assert(reply_length == 0);
    for (size_t i = 0; i < sizeof reply; ++i) assert(reply[i] == 0);
    assert(!app->transaction.active);
    begin(app, hasher);
    uint8_t identify[5] = {0xa5, 0x01, 0, 0, 0};
    assert(blue_shielded_review_app_command(app, identify,
        sizeof identify, app->reply, sizeof app->reply,
        &reply_length, hasher) == 0x6a80);
    assert(reply_length == 0 && !app->transaction.active);
}

static void interrupted_review(blue_shielded_review_app *app,
    const zcl_zip243_hasher *hasher, const uint8_t *wire) {
    for (unsigned stop = 1; stop <= 6; ++stop) {
        blue_shielded_review_app_reset(app);
        begin(app, hasher);
        for (unsigned pass = 1; pass <= stop; ++pass) {
            upload(app, hasher, wire, pass);
            if (pass < stop) advance(app, hasher, pass + 1);
        }
        uint8_t apdu[260] = {0xa5, 0x23, 0, 0, 0};
        size_t reply_length = 255;
        if (stop & 1u) {
            apdu[4] = 1;
            assert(command(app, hasher, apdu, 5, &reply_length) == 0x6700);
            assert(reply_length == 0);
        } else blue_shielded_review_app_reset(app);
        assert(!app->transaction.active && !app->transaction.complete);
        assert(strcmp(app->lines[0], "CONNECT Z23") == 0);
        const uint8_t *state = (const uint8_t *)&app->transaction;
        for (size_t i = 0; i < sizeof app->transaction; ++i)
            assert(state[i] == 0);
        for (size_t i = 0; i < sizeof app->reply; ++i)
            assert(app->reply[i] == 0);
        if (app->large_text) {
            assert(blue_shielded_review_app_next(app));
            assert(app->detail == 1);
        } else assert(!blue_shielded_review_app_next(app));
        memcpy(apdu, (uint8_t[]){0xa5, 0x23, 0, 0, 0}, 5);
        assert(command(app, hasher, apdu, 5, &reply_length) == 0x6985);
        assert(reply_length == 0);
        assert(strcmp(app->lines[0], "CONNECT Z23") == 0);
    }
    review(app, hasher, wire);
    uint8_t sign[260] = {0xa5, 0x29, 0, 0, 1, 0};
    size_t reply_length = 255;
    assert(command(app, hasher, sign, 6, &reply_length) == 0x6d00);
    assert(reply_length == 0 && !app->transaction.complete);
    assert(strcmp(app->lines[0], "CONNECT Z23") == 0);
}

int main(void) {
    uint8_t wire[BLUE_SYNTHETIC_SAPLING_BYTES];
    blue_sapling_fixture(wire);
    struct blake2b_ctx context;
    zcl_zip243_hasher hasher = zcl_zip243_host_hasher(&context);
    blue_shielded_review_app app = {0};
    blue_shielded_review_app_reset(&app);
    assert(strcmp(app.lines[0], "CONNECT Z23") == 0);
    review(&app, &hasher, wire);
    inspect_pages(&app);
    formatted_failure(&app, &hasher, wire);
    reject_app_alias(&app, &hasher);
    interrupted_review(&app, &hasher, wire);
    puts("Blue shielded review screens and interactions: passed");
    return 0;
}
