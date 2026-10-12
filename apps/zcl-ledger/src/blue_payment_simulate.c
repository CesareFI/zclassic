/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "blue_payment_simulate.h"
#include "zcl_zip243_host.h"
#include "zsha256/zsha256.h"

#include "crypto/blake2b.h"
#include <string.h>

static bool sha_init(void *context) {
    if (!context) return false;
    zsha256_init(context);
    return true;
}

static bool sha_update(void *context, const uint8_t *bytes, size_t length) {
    if (!context || (!bytes && length)) return false;
    zsha256_update(context, bytes, length);
    return true;
}

static bool sha_final(void *context, uint8_t digest[32]) {
    if (!context || !digest) return false;
    zsha256_final(context, digest);
    return true;
}

static bool screen_hash(const uint8_t *bytes, size_t length,
    uint8_t digest[32]) {
    if ((!bytes && length) || !digest) return false;
    zsha256(bytes, length, digest);
    return true;
}

static bool feed_complete(blue_payment_review *review,
    const uint8_t *wire, size_t length) {
    for (size_t position = 0; position < length;) {
        size_t count = length - position < 128 ? length - position : 128;
        if (!blue_payment_review_feed(review, wire + position, count))
            return false;
        position += count;
    }
    return true;
}

static bool feed_outputs(blue_payment_review *review,
    const uint8_t *wire, size_t length,
    blue_payment_screen screens[BLUE_PAYMENT_REVIEW_MAX_OUTPUTS]) {
    for (size_t position = 0; position < length; ++position) {
        if (!blue_payment_review_feed(review, wire + position, 1))
            return false;
        const blue_payment_output *output = blue_payment_review_pending(review);
        if (!output) continue;
        if (output->index >= BLUE_PAYMENT_REVIEW_MAX_OUTPUTS ||
            !blue_payment_screen_format(output, review->total_outputs,
                screen_hash, &screens[output->index]) ||
            !blue_payment_review_acknowledge(review)) return false;
    }
    return true;
}

bool blue_payment_simulate(const uint8_t *wire, size_t length,
    uint32_t branch_id,
    blue_payment_screen screens[BLUE_PAYMENT_REVIEW_MAX_OUTPUTS],
    uint32_t *screen_count) {
    if (screen_count) *screen_count = 0;
    if (!screens || !screen_count) return false;
    memset(screens, 0, sizeof *screens * BLUE_PAYMENT_REVIEW_MAX_OUTPUTS);
    if (!wire || !length || length > ZCL_TX_STREAM_MAX_BYTES) return false;
    zsha256_ctx sha_context;
    struct blake2b_ctx blake_context;
    zcl_zip243_hasher blake = zcl_zip243_host_hasher(&blake_context);
    zcl_tx_replay_sha256 sha = {.context = &sha_context, .init = sha_init,
        .update = sha_update, .final = sha_final};
    blue_payment_review review;
    bool valid = blue_payment_review_begin(&review, (uint32_t)length, 0,
        branch_id, &blake, &sha);
    for (unsigned pass = 0; valid && pass < 2; ++pass)
        valid = feed_complete(&review, wire, length) &&
            blue_payment_review_next_pass(&review);
    if (valid) valid = feed_outputs(&review, wire, length, screens);
    zcl_tx_stream_facts facts;
    uint8_t unused_digest[32];
    if (valid) valid = blue_payment_review_finish(&review, NULL, 0, 0,
        &facts, unused_digest);
    if (valid) *screen_count = facts.outputs;
    else memset(screens, 0,
        sizeof *screens * BLUE_PAYMENT_REVIEW_MAX_OUTPUTS);
    blue_payment_review_abort(&review);
    memset(&sha_context, 0, sizeof sha_context);
    return valid;
}
