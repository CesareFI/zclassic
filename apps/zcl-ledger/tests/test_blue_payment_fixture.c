/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "blue_payment_fixture.h"
#include "blue_payment_live.h"
#include "zcl_tx_prevout.h"
#include "zcl_zip243_host.h"
#include "crypto/blake2b.h"
#include "zsha256/zsha256.h"

#undef NDEBUG
#include <assert.h>
#include <string.h>

static bool hash_sha256(const uint8_t *bytes, size_t length,
    uint8_t digest[32]) {
    if ((!bytes && length) || !digest) return false;
    zsha256(bytes, length, digest);
    return true;
}

int main(void) {
    uint8_t device_hash[20];
    memset(device_hash, 0x33, sizeof device_hash);
    blue_payment_fixture fixture;
    assert(!blue_payment_fixture_make(NULL, &fixture));
    assert(!blue_payment_fixture_make(device_hash, NULL));
    assert(blue_payment_fixture_make(device_hash, &fixture));
    assert(fixture.previous_length == 85 && fixture.unsigned_length == 136);
    blue_payment_live_plan plan;
    assert(blue_payment_live_prepare(fixture.unsigned_wire,
        fixture.unsigned_length, BLUE_PAYMENT_FIXTURE_BRANCH, &plan));
    assert(plan.count == 2 && plan.inputs == 1);
    zcl_tx_previous_transaction previous = {
        .wire = fixture.previous, .length = fixture.previous_length};
    struct blake2b_ctx blake_context;
    zcl_zip243_hasher hasher = zcl_zip243_host_hasher(&blake_context);
    zcl_tx_transparent_facts facts;
    uint8_t digests[ZCL_TX_PREFLIGHT_MAX_INPUTS][32];
    assert(zcl_tx_transparent_bound_digests(fixture.unsigned_wire,
        fixture.unsigned_length, &previous, 1,
        BLUE_PAYMENT_FIXTURE_BRANCH, hash_sha256, &hasher,
        &facts, digests, ZCL_TX_PREFLIGHT_MAX_INPUTS) == 0);
    assert(facts.transparent_inputs == 1 &&
        facts.transparent_outputs == 2 && facts.input_zat == 400000000 &&
        facts.output_zat == 300000000 && facts.fee_zat == 100000000);
    uint8_t original[32];
    memcpy(original, digests[0], sizeof original);
    fixture.previous[fixture.previous_length - 5] ^= 1;
    assert(zcl_tx_transparent_bound_digests(fixture.unsigned_wire,
        fixture.unsigned_length, &previous, 1,
        BLUE_PAYMENT_FIXTURE_BRANCH, hash_sha256, &hasher,
        &facts, digests, ZCL_TX_PREFLIGHT_MAX_INPUTS) < 0);
    assert(memcmp(original, digests[0], sizeof original) == 0);
    return 0;
}
