/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "blue_payment_review.h"

#include <string.h>

static bool overlaps(const void *left, size_t left_length,
    const void *right, size_t right_length) {
    uintptr_t a = (uintptr_t)left, b = (uintptr_t)right;
    return a <= b ? b - a < left_length : a - b < right_length;
}

void blue_payment_review_abort(blue_payment_review *review) {
    if (!review) return;
    volatile uint8_t *bytes = (volatile uint8_t *)review;
    for (size_t i = 0; i < sizeof *review; ++i) bytes[i] = 0;
    review->replay.wire.failed = true;
}

bool blue_payment_review_begin(blue_payment_review *review,
    uint32_t expected_length, uint32_t selected_index, uint32_t branch_id,
    const zcl_zip243_hasher *blake, const zcl_tx_replay_sha256 *sha) {
    if (!review) return false;
    memset(review, 0, sizeof *review);
    if (!zcl_tx_replay_zip243_begin(&review->replay, expected_length,
            selected_index, branch_id, blake, sha)) {
        blue_payment_review_abort(review);
        return false;
    }
    return true;
}

static bool capture_output(void *context, uint32_t index,
    uint64_t amount_zat, zcl_tx_stream_output_type type,
    const uint8_t hash160[20]) {
    blue_payment_review *review = context;
    if (review->pending || index != review->acknowledged ||
        index >= review->total_outputs) return false;
    review->output.index = index;
    review->output.amount_zat = amount_zat;
    review->output.type = type;
    memcpy(review->output.hash160, hash160, 20);
    review->output_end = review->replay.wire.received + 1;
    review->pending = true;
    return true;
}

bool blue_payment_review_feed(blue_payment_review *review,
    const uint8_t *bytes, size_t length) {
    if (!review) return false;
    if ((bytes && length && overlaps(review, sizeof *review, bytes, length)) ||
        review->pending || review->verified ||
        !zcl_tx_replay_zip243_feed_review(&review->replay, bytes, length,
                                           capture_output, review) ||
        (review->pending && review->replay.wire.received !=
                            review->output_end)) {
        blue_payment_review_abort(review);
        return false;
    }
    return true;
}

bool blue_payment_review_next_pass(blue_payment_review *review) {
    if (!review) return false;
    uint8_t pass = review->replay.pass;
    uint32_t count = review->replay.wire.facts.outputs;
    if (review->pending || review->verified ||
        (pass == 1 && (!count || count > BLUE_PAYMENT_REVIEW_MAX_OUTPUTS)) ||
        (pass == 2 && count != review->total_outputs) ||
        !zcl_tx_replay_zip243_next(&review->replay)) {
        blue_payment_review_abort(review);
        return false;
    }
    if (pass == 1) review->total_outputs = count;
    return true;
}

const blue_payment_output *blue_payment_review_pending(
    const blue_payment_review *review) {
    return review && review->pending ? &review->output : NULL;
}

bool blue_payment_review_acknowledge(blue_payment_review *review) {
    if (!review || !review->pending || review->verified ||
        review->replay.pass != 3) return false;
    review->pending = false;
    review->output_end = 0;
    memset(&review->output, 0, sizeof review->output);
    ++review->acknowledged;
    return true;
}

static bool finish_disjoint(const blue_payment_review *review,
    const uint8_t *script_code, size_t script_length,
    const zcl_tx_stream_facts *facts, const uint8_t digest[32]) {
    if (overlaps(review, sizeof *review, facts, sizeof *facts) ||
        overlaps(review, sizeof *review, digest, 32) ||
        overlaps(facts, sizeof *facts, digest, 32)) return false;
    return !script_length || !script_code ||
        (!overlaps(review, sizeof *review, script_code, script_length) &&
         !overlaps(facts, sizeof *facts, script_code, script_length) &&
         !overlaps(digest, 32, script_code, script_length));
}

bool blue_payment_review_finish(blue_payment_review *review,
    const uint8_t *script_code, size_t script_code_length,
    uint64_t amount_zat, zcl_tx_stream_facts *facts, uint8_t digest[32]) {
    if (!review) return false;
    if (!facts || !digest ||
        !finish_disjoint(review, script_code, script_code_length,
            facts, digest)) {
        blue_payment_review_abort(review);
        return false;
    }
    memset(facts, 0, sizeof *facts);
    memset(digest, 0, 32);
    if (review->pending || review->verified ||
        review->replay.pass != 3 ||
        review->acknowledged != review->total_outputs ||
        !zcl_tx_replay_zip243_finish(&review->replay, script_code,
            script_code_length, amount_zat, facts, digest) ||
        facts->outputs != review->acknowledged) {
        blue_payment_review_abort(review);
        memset(facts, 0, sizeof *facts);
        memset(digest, 0, 32);
        return false;
    }
    review->verified = true;
    return true;
}
