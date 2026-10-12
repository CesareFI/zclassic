/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "blue_payment_live.h"
#include "zcl_tx_previous_stream.h"
#include "zsha256/zsha256.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    zcl_tx_stream *stream;
    blue_payment_live_plan *plan;
    uint32_t seen;
} output_capture;

typedef struct {
    blue_payment_live_plan plan;
    uint8_t wire[];
} live_snapshot;

typedef struct {
    const uint8_t *wire;
    size_t length;
    uint8_t digest[32];
} previous_identity;

static bool overlaps(const void *left, size_t left_length,
    const void *right, size_t right_length) {
    if (!left || !right || !left_length || !right_length) return false;
    uintptr_t a = (uintptr_t)left, b = (uintptr_t)right;
    return a <= b ? b - a < left_length : a - b < right_length;
}

static bool same_plan(const blue_payment_live_plan *left,
    const blue_payment_live_plan *right) {
    if (left->count != right->count || left->inputs != right->inputs ||
        left->branch_id != right->branch_id ||
        left->wire_length != right->wire_length ||
        memcmp(left->wire_hash, right->wire_hash, 32)) return false;
    for (uint32_t i = 0; i < left->count; ++i)
        if (left->output_end[i] != right->output_end[i] ||
            memcmp(&left->screens[i], &right->screens[i],
                sizeof left->screens[i])) return false;
    return true;
}

static bool source_unchanged(const uint8_t *wire, size_t length,
    const blue_payment_live_plan *plan,
    const blue_payment_live_plan *canonical) {
    uint8_t hash[32];
    zsha256(wire, length, hash);
    return memcmp(hash, canonical->wire_hash, sizeof hash) == 0 &&
        same_plan(plan, canonical);
}

static bool review_status_header(const uint8_t *reply, size_t length,
    uint32_t index, uint32_t total) {
    return reply && length == 8 && total &&
        total <= BLUE_PAYMENT_REVIEW_MAX_OUTPUTS && index < total &&
        reply[0] == 1 && reply[1] == 3 && reply[3] == 0 &&
        reply[4] == total && reply[6] == 0x90 && reply[7] == 0;
}

int blue_payment_live_review_status(const uint8_t *reply, size_t length,
    uint32_t index, uint32_t total) {
    if (!review_status_header(reply, length, index, total)) return -1;
    if (reply[2] == 1 && reply[5] == index) return 0;
    if (reply[2] == 0 && reply[5] == index + 1) return 1;
    return -1;
}

static bool capture_end(void *context, uint32_t index,
    uint64_t amount_zat, zcl_tx_stream_output_type type,
    const uint8_t hash160[20]) {
    output_capture *capture = context;
    (void)amount_zat;
    (void)type;
    (void)hash160;
    if (index != capture->seen || index >= capture->plan->count)
        return false;
    capture->plan->output_end[index] = capture->stream->received + 1;
    ++capture->seen;
    return true;
}

bool blue_payment_live_prepare(const uint8_t *wire, size_t length,
    uint32_t branch_id, blue_payment_live_plan *plan) {
    if (!plan || overlaps(plan, sizeof *plan, wire, length)) return false;
    memset(plan, 0, sizeof *plan);
    blue_payment_live_plan checked = {0};
    zcl_tx_stream parser;
    zcl_tx_stream_facts facts;
    checked.branch_id = branch_id;
    checked.wire_length = (uint32_t)length;
    output_capture capture = {.stream = &parser, .plan = &checked};
    if (!wire || !length || length > ZCL_TX_STREAM_MAX_BYTES ||
        !blue_payment_simulate(wire, length, branch_id,
            checked.screens, &checked.count) ||
        !zcl_tx_stream_begin(&parser, (uint32_t)length) ||
        !zcl_tx_stream_feed(&parser, wire, length, NULL,
            capture_end, &capture) ||
        !zcl_tx_stream_finish(&parser, &facts) ||
        capture.seen != checked.count || facts.outputs != checked.count)
        return false;
    zsha256(wire, length, checked.wire_hash);
    checked.inputs = facts.inputs;
    *plan = checked;
    return true;
}

static bool send_command(blue_payment_live_exchange exchange, void *context,
    uint8_t instruction, const uint8_t *body, uint8_t length,
    const uint8_t *expected, size_t expected_length) {
    uint8_t apdu[5 + 128] = {0xa5, instruction, 0, 0, length};
    uint8_t reply[64];
    size_t reply_length = 0;
    if (length) memcpy(apdu + 5, body, length);
    return exchange(context, apdu, 5 + length, reply, sizeof reply,
                    &reply_length) &&
        reply_length == expected_length + 2 &&
        (!expected_length || !memcmp(reply, expected, expected_length)) &&
        reply[expected_length] == 0x90 && reply[expected_length + 1] == 0;
}

bool blue_payment_live_abort(blue_payment_live_exchange exchange,
    void *context) {
    return exchange && send_command(exchange, context, 0x24,
                                    NULL, 0, NULL, 0);
}

static bool review_identity(blue_payment_live_exchange exchange,
    void *context) {
    static const uint8_t apdu[5] = {0xa5, 0x01, 0, 0, 0};
    static const uint8_t prefix[3] = {'Z', 'C', 'L'};
    uint8_t reply[7];
    size_t length = 0;
    return exchange(context, apdu, sizeof apdu, reply, sizeof reply,
            &length) && length == sizeof reply &&
        memcmp(reply, prefix, sizeof prefix) == 0 &&
        ((reply[3] == 11 && reply[4] == 15) ||
         (reply[3] == 12 && reply[4] == 31)) &&
        reply[5] == 0x90 && reply[6] == 0;
}

static void put_u32(uint8_t bytes[4], uint32_t value) {
    for (unsigned i = 0; i < 4; ++i) bytes[i] = (uint8_t)(value >> (i * 8));
}

static void put_u64(uint8_t bytes[8], uint64_t value) {
    for (unsigned i = 0; i < 8; ++i) bytes[i] = (uint8_t)(value >> (i * 8));
}

static bool feed_range(const uint8_t *wire, size_t start, size_t end,
    uint8_t pass, bool output_at_end,
    blue_payment_live_exchange exchange, void *context) {
    if (end <= start) return false;
    while (start < end) {
        size_t count = end - start < 128 ? end - start : 128;
        uint8_t expected[2] = {pass,
            output_at_end && start + count == end ? 1 : 0};
        if (!send_command(exchange, context, 0x21, wire + start,
                (uint8_t)count, expected, sizeof expected)) return false;
        start += count;
    }
    return true;
}

static bool first_two_passes(const uint8_t *wire, size_t length,
    uint8_t outputs, blue_payment_live_exchange exchange, void *context) {
    for (uint8_t pass = 1; pass <= 2; ++pass) {
        uint8_t expected[2] = {(uint8_t)(pass + 1), outputs};
        if (!feed_range(wire, 0, length, pass, false, exchange, context) ||
            !send_command(exchange, context, 0x22, NULL, 0,
                          expected, sizeof expected)) return false;
    }
    return true;
}

static bool remaining_outputs(const uint8_t *wire, size_t length,
    const blue_payment_live_plan *plan,
    blue_payment_live_exchange exchange,
    blue_payment_live_continue continuation, void *context) {
    size_t position = 0;
    for (uint32_t index = 0; index < plan->count; ++index) {
        size_t end = plan->output_end[index];
        uint8_t expected[6] = {1, 3, 0, 0,
            (uint8_t)plan->count, (uint8_t)(index + 1)};
        if (end <= position || end > length ||
            !feed_range(wire, position, end, 3, true,
                        exchange, context) ||
            !continuation(context, index, &plan->screens[index]) ||
            !send_command(exchange, context, 0x25, NULL, 0,
                          expected, sizeof expected)) return false;
        position = end;
    }
    return position == length ||
        feed_range(wire, position, length, 3, false, exchange, context);
}

static live_snapshot *snapshot_create(const uint8_t *wire, size_t length,
    const blue_payment_live_plan *plan) {
    if (!wire || !plan ||
        !plan->count || plan->count > BLUE_PAYMENT_REVIEW_MAX_OUTPUTS ||
        !length || length > ZCL_TX_STREAM_MAX_BYTES ||
        length > SIZE_MAX - sizeof(live_snapshot) ||
        length != plan->wire_length ||
        overlaps(plan, sizeof *plan, wire, length)) return NULL;
    live_snapshot *snapshot = malloc(sizeof *snapshot + length);
    if (!snapshot) return NULL;
    memcpy(snapshot->wire, wire, length);
    if (!blue_payment_live_prepare(snapshot->wire, length,
            plan->branch_id, &snapshot->plan) ||
        !same_plan(plan, &snapshot->plan)) {
        free(snapshot);
        return NULL;
    }
    return snapshot;
}

static bool review_snapshot(const uint8_t *wire, size_t length,
    const blue_payment_live_plan *plan, const live_snapshot *snapshot,
    blue_payment_live_exchange exchange,
    blue_payment_live_continue continuation, void *context) {
    uint8_t begin[12];
    put_u32(begin, (uint32_t)length);
    put_u32(begin + 4, 0);
    put_u32(begin + 8, snapshot->plan.branch_id);
    if (!send_command(exchange, context, 0x20, begin, sizeof begin,
                      NULL, 0)) {
        (void)send_command(exchange, context, 0x24, NULL, 0, NULL, 0);
        return false;
    }
    bool valid = first_two_passes(snapshot->wire, length,
                    (uint8_t)snapshot->plan.count,
                    exchange, context) &&
        remaining_outputs(snapshot->wire, length, &snapshot->plan,
                          exchange, continuation, context);
    uint8_t commitment[33] = {(uint8_t)snapshot->plan.count};
    memcpy(commitment + 1, snapshot->plan.wire_hash, 32);
    if (valid) valid = send_command(exchange, context, 0x23, NULL, 0,
                                    commitment, sizeof commitment);
    if (valid) valid = source_unchanged(wire, length, plan,
        &snapshot->plan);
    if (!valid) (void)send_command(exchange, context, 0x24, NULL, 0, NULL, 0);
    return valid;
}

bool blue_payment_live_run(const uint8_t *wire, size_t length,
    const blue_payment_live_plan *plan,
    blue_payment_live_exchange exchange,
    blue_payment_live_continue continuation, void *context) {
    if (!exchange || !continuation) return false;
    live_snapshot *snapshot = snapshot_create(wire, length, plan);
    if (!snapshot) return false;
    bool valid = review_identity(exchange, context) &&
        source_unchanged(wire, length, plan, &snapshot->plan) &&
        review_snapshot(wire, length, plan, snapshot,
            exchange, continuation, context);
    free(snapshot);
    return valid;
}

static bool send_previous(zcl_tx_previous_transaction previous,
    uint8_t index, uint8_t total, uint64_t fee_zat,
    const uint8_t digest[32],
    blue_payment_live_exchange exchange, void *context) {
    if (!previous.wire || !previous.length ||
        previous.length > ZCL_TX_PREVIOUS_STREAM_MAX_BYTES) return false;
    uint8_t length[4];
    put_u32(length, (uint32_t)previous.length);
    if (!send_command(exchange, context, 0x26, length, sizeof length,
                      NULL, 0)) return false;
    for (size_t offset = 0; offset < previous.length;) {
        size_t count = previous.length - offset < 128 ?
            previous.length - offset : 128;
        if (!send_command(exchange, context, 0x27,
                previous.wire + offset, (uint8_t)count, NULL, 0))
            return false;
        offset += count;
    }
    uint8_t expected[43] = {index, total, index == total};
    if (index == total) put_u64(expected + 3, fee_zat);
    memcpy(expected + 11, digest, 32);
    return send_command(exchange, context, 0x28, NULL, 0,
                        expected, sizeof expected);
}

static bool previous_identity_capture(previous_identity *identity,
    const zcl_tx_previous_transaction *caller) {
    if (!caller->wire || !caller->length ||
        caller->length > ZCL_TX_PREVIOUS_STREAM_MAX_BYTES) return false;
    identity->wire = caller->wire;
    identity->length = caller->length;
    zsha256(identity->wire, identity->length, identity->digest);
    return true;
}

static bool previous_identity_matches(const previous_identity *identity,
    const zcl_tx_previous_transaction *caller) {
    if (caller->wire != identity->wire ||
        caller->length != identity->length) return false;
    uint8_t digest[32];
    zsha256(caller->wire, caller->length, digest);
    return memcmp(digest, identity->digest, sizeof digest) == 0;
}

static bool previous_identities_match(const previous_identity *identities,
    const zcl_tx_previous_transaction *previous, size_t count) {
    for (size_t i = 0; i < count; ++i)
        if (!previous_identity_matches(&identities[i], &previous[i]))
            return false;
    return true;
}

static bool send_previous_stable(const zcl_tx_previous_transaction *caller,
    const previous_identity *identity,
    uint8_t index, uint8_t total, uint64_t fee_zat,
    const uint8_t digest[32],
    blue_payment_live_exchange exchange, void *context) {
    if (!previous_identity_matches(identity, caller)) return false;
    zcl_tx_previous_transaction original = *caller;
    uint8_t *copy = malloc(original.length);
    if (!copy) return false;
    memcpy(copy, original.wire, original.length);
    zcl_tx_previous_transaction frozen = {
        .wire = copy, .length = original.length};
    bool valid = send_previous(frozen, index, total, fee_zat, digest,
        exchange, context);
    if (valid) valid = previous_identity_matches(identity, caller) &&
        caller->length == original.length &&
        memcmp(original.wire, copy, original.length) == 0;
    free(copy);
    return valid;
}

static bool upload_bound_previous(const uint8_t *wire, size_t length,
    const blue_payment_live_plan *plan, const blue_payment_live_plan *frozen,
    const zcl_tx_previous_transaction *previous,
    const previous_identity *identities, size_t previous_count,
    uint64_t expected_fee_zat, const uint8_t (*expected_digests)[32],
    const uint8_t (*digests)[32], blue_payment_live_exchange exchange,
    void *context) {
    if (!previous_identities_match(identities, previous, previous_count))
        return false;
    for (size_t i = 0; i < previous_count; ++i) {
        if (!source_unchanged(wire, length, plan, frozen) ||
            memcmp(expected_digests, digests,
                previous_count * sizeof digests[0]) ||
            !send_previous_stable(&previous[i], &identities[i],
                           (uint8_t)(i + 1),
                           (uint8_t)previous_count, expected_fee_zat,
                           digests[i], exchange, context) ||
            !source_unchanged(wire, length, plan, frozen) ||
            memcmp(expected_digests, digests,
                previous_count * sizeof digests[0])) return false;
    }
    return true;
}

bool blue_payment_live_run_bound(const uint8_t *wire, size_t length,
    const blue_payment_live_plan *plan,
    const zcl_tx_previous_transaction *previous, size_t previous_count,
    uint64_t expected_fee_zat, const uint8_t (*expected_digests)[32],
    blue_payment_live_exchange exchange,
    blue_payment_live_continue continuation, void *context) {
    if (!plan || !previous || !expected_digests || !previous_count ||
        previous_count != plan->inputs ||
        previous_count > ZCL_TX_PREFLIGHT_MAX_INPUTS || !exchange)
        return false;
    previous_identity identities[ZCL_TX_PREFLIGHT_MAX_INPUTS];
    for (size_t i = 0; i < previous_count; ++i)
        if (!previous_identity_capture(&identities[i], &previous[i]))
            return false;
    blue_payment_live_plan frozen = *plan;
    uint8_t digests[ZCL_TX_PREFLIGHT_MAX_INPUTS][32];
    memcpy(digests, expected_digests, previous_count * sizeof digests[0]);
    if (!blue_payment_live_run(wire, length, &frozen,
            exchange, continuation, context)) return false;
    bool valid = upload_bound_previous(wire, length, plan, &frozen,
        previous, identities, previous_count, expected_fee_zat,
        expected_digests, (const uint8_t (*)[32])digests, exchange, context);
    if (!valid)
        (void)send_command(exchange, context, 0x24, NULL, 0, NULL, 0);
    return valid;
}
