/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "blue_payment_host_ownership.h"
#include "blue_payment_fixture.h"
#include "zsha256/zsha256.h"

#undef NDEBUG
#include <assert.h>
#include <string.h>

static bool hash_sha256(const uint8_t *bytes, size_t length,
    uint8_t digest[32]) {
    if (!bytes || !digest) return false;
    zsha256(bytes, length, digest);
    return true;
}

int main(void) {
    uint8_t external[20], internal[20], other[20];
    memset(external, 0x33, sizeof external);
    memset(internal, 0x44, sizeof internal);
    memset(other, 0x55, sizeof other);
    blue_payment_fixture first, second;
    assert(blue_payment_fixture_make(external, &first));
    assert(blue_payment_fixture_make(internal, &second));
    uint8_t spend[BLUE_PAYMENT_FIXTURE_MAX_WIRE] = {0};
    memcpy(spend, first.unsigned_wire, first.unsigned_length);
    memmove(spend + 91, spend + 50, first.unsigned_length - 50);
    memcpy(spend + 50, second.unsigned_wire + 9, 41);
    spend[8] = 2;
    size_t length = first.unsigned_length + 41;
    zcl_tx_previous_transaction previous[2] = {
        {.wire = first.previous, .length = first.previous_length},
        {.wire = second.previous, .length = second.previous_length}
    };
    blue_payment_host_ownership result = {0};
    assert(blue_payment_host_classify_inputs(spend, length, previous, 2,
        hash_sha256, external, internal, &result));
    assert(result.facts.transparent_inputs == 2 &&
        result.facts.input_zat == 800000000 &&
        result.facts.fee_zat == 500000000 &&
        result.paths[0] == BLUE_PAYMENT_INPUT_EXTERNAL &&
        result.paths[1] == BLUE_PAYMENT_INPUT_INTERNAL &&
        memcmp(result.hashes[0], external, 20) == 0 &&
        memcmp(result.hashes[1], internal, 20) == 0);
    blue_payment_host_ownership proposed = {0};
    assert(blue_payment_host_propose_paths(spend, length, previous, 2,
        hash_sha256, external, &proposed));
    assert(memcmp(&proposed, &result, sizeof proposed) == 0);
    blue_payment_host_ownership original = result;
    assert(!blue_payment_host_classify_inputs(spend, length, previous, 2,
        hash_sha256, external, other, &result));
    assert(memcmp(&result, &original, sizeof result) == 0);
    assert(!blue_payment_host_classify_inputs(spend, length, previous, 2,
        hash_sha256, external, external, &result));
    assert(memcmp(&result, &original, sizeof result) == 0);
    second.previous[second.previous_length - 5] ^= 1;
    assert(!blue_payment_host_classify_inputs(spend, length, previous, 2,
        hash_sha256, external, internal, &result));
    assert(memcmp(&result, &original, sizeof result) == 0);
    return 0;
}
