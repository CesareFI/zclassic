/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "blue_review_simulate.h"
#include "blue_review_app.h"
#include "zcl_zip243_host.h"

#include <openssl/sha.h>
#include <string.h>

static bool sha256(const uint8_t *bytes, size_t length, uint8_t out[32]) {
    return SHA256(bytes, length, out) != NULL;
}

static bool exchange(blue_review_app *app, uint8_t apdu[260], size_t length,
                     const uint8_t *expected, size_t expected_length) {
    struct blake2b_ctx context;
    zcl_zip243_hasher hasher = zcl_zip243_host_hasher(&context);
    size_t reply_length = 0;
    uint16_t status = blue_review_app_command(app, apdu, length, apdu, 255,
                                              &reply_length, sha256, &hasher);
    return status == 0x9000 && reply_length == expected_length &&
           (!expected_length || memcmp(apdu, expected, expected_length) == 0);
}

static bool upload(blue_review_app *app, const uint8_t *wire, size_t length) {
    uint8_t apdu[260] = {0xa5, 0x10, 0, 0, 2,
                         (uint8_t)length, (uint8_t)(length >> 8)};
    if (!exchange(app, apdu, 7, NULL, 0)) return false;
    for (size_t offset = 0; offset < length; offset += 220) {
        size_t count = length - offset < 220 ? length - offset : 220;
        apdu[1] = 0x11;
        apdu[4] = (uint8_t)count;
        memcpy(apdu + 5, wire + offset, count);
        if (!exchange(app, apdu, count + 5, NULL, 0)) return false;
    }
    return true;
}

static bool compare_digest(blue_review_app *app, uint32_t branch_id,
                           const uint8_t expected[32]) {
    uint8_t apdu[260] = {0xa5, 0x14, 0, 0, 4};
    for (unsigned i = 0; i < 4; ++i)
        apdu[5 + i] = (uint8_t)(branch_id >> (8 * i));
    return exchange(app, apdu, 9, expected, 32);
}

static bool compare_summary(blue_review_app *app, const uint8_t *wire,
                            size_t length, const zcl_tx_review *review) {
    uint8_t expected[76];
    blue_review_encode_summary(review, expected);
    if (!SHA256(wire, length, expected + 44)) return false;
    uint8_t apdu[260] = {0xa5, 0x12, 0, 0, 0};
    return exchange(app, apdu, 5, expected, sizeof expected);
}

static bool review_pages(blue_review_app *app,
                         const zcl_tx_review *review,
                         blue_review_page_fn page, void *context) {
    if (!blue_review_app_next(app, sha256) ||
        strcmp(app->lines[4], "SHIELDED HIDDEN; NO SIGNING") != 0 ||
        (page && !page(app, context)))
        return false;
    for (uint32_t i = 0; i < review->transparent_outputs; ++i)
        if (!blue_review_app_next(app, sha256) ||
            strncmp(app->lines[0], "OUTPUT ", 7) != 0 ||
            (page && !page(app, context)))
        return false;
    return blue_review_app_next(app, sha256) &&
           strncmp(app->lines[0], "PUBLIC IN/OUT: ", 15) == 0 &&
           (!page || page(app, context));
}

static bool simulate(const uint8_t *wire, size_t length,
    const zcl_tx_review *review, bool has_branch, uint32_t branch_id,
    const uint8_t zip_digest[32], blue_review_page_fn page, void *context) {
    if (!wire || !review || length > ZCL_BLUE_REVIEW_MAX_BYTES) return false;
    blue_review_app app = {0};
    blue_review_app_reset(&app);
    if (page && !page(&app, context)) return false;
    uint8_t probe[260] = {0xa5, 1, 0, 0, 0};
    static const uint8_t identity[] = {'Z', 'C', 'L', 6, 0x40};
    return exchange(&app, probe, 5, identity, sizeof identity) &&
           upload(&app, wire, length) &&
           (!has_branch ||
            (zip_digest && compare_digest(&app, branch_id, zip_digest))) &&
           compare_summary(&app, wire, length, review) &&
           review_pages(&app, review, page, context);
}

bool blue_review_simulate(const uint8_t *wire, size_t length,
    const zcl_tx_review *review, bool has_branch, uint32_t branch_id,
    const uint8_t zip_digest[32]) {
    return simulate(wire, length, review, has_branch, branch_id,
                    zip_digest, NULL, NULL);
}

bool blue_review_simulate_pages(const uint8_t *wire, size_t length,
    const zcl_tx_review *review, blue_review_page_fn page, void *context) {
    if (!page) return false;
    return simulate(wire, length, review, false, 0, NULL, page, context);
}
