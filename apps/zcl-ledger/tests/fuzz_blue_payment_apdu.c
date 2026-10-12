/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "blue_payment_apdu.h"
#include "zcl_zip243_host.h"
#include "zsha256/zsha256.h"

#include "crypto/blake2b.h"

#include <stdlib.h>
#include <string.h>

static bool sha_init(void *context) {
    zsha256_init(context);
    return true;
}

static bool sha_update(void *context, const uint8_t *bytes, size_t length) {
    zsha256_update(context, bytes, length);
    return true;
}

static bool sha_final(void *context, uint8_t digest[32]) {
    zsha256_final(context, digest);
    return true;
}

static bool screen_hash(const uint8_t *bytes, size_t length,
    uint8_t digest[32]) {
    zsha256(bytes, length, digest);
    return true;
}

static bool seed_pending_output(blue_payment_apdu *state,
    const zcl_zip243_hasher *blake, const zcl_tx_replay_sha256 *sha,
    const blue_payment_owned_hashes *owned) {
    uint8_t tx[104] = {0};
    tx[0] = 4; tx[3] = 0x80;
    tx[4] = 0x85; tx[5] = 0x20; tx[6] = 0x2f; tx[7] = 0x89;
    tx[8] = 1;
    memset(tx + 9, 0xaa, 32);
    tx[46] = 0xfe; tx[47] = tx[48] = tx[49] = 0xff;
    tx[50] = 1;
    tx[52] = 0xe1; tx[53] = 0xf5; tx[54] = 0x05;
    tx[59] = 25; tx[60] = 0x76; tx[61] = 0xa9; tx[62] = 0x14;
    memset(tx + 63, 0x11, 20);
    tx[83] = 0x88; tx[84] = 0xac;
    tx[85] = 100; tx[89] = 200;
    uint8_t frame[260] = {0xa5, 0x20, 0, 0, 12,
        sizeof tx, 0, 0, 0, 0, 0, 0, 0, 0xbb, 0x09, 0xb8, 0x76};
    size_t reply_length = 0;
    if (blue_payment_apdu_handle(state, frame, 17, frame, sizeof frame,
            &reply_length, blake, sha, screen_hash, owned) != 0x9000)
        return false;
    for (unsigned pass = 1; pass <= 3; ++pass) {
        frame[0] = 0xa5; frame[1] = 0x21;
        frame[2] = frame[3] = 0;
        frame[4] = pass == 3 ? 85 : sizeof tx;
        memcpy(frame + 5, tx, frame[4]);
        if (blue_payment_apdu_handle(state, frame, frame[4] + 5,
                frame, sizeof frame, &reply_length, blake, sha,
                screen_hash, owned) != 0x9000) return false;
        if (pass == 3) break;
        frame[0] = 0xa5; frame[1] = 0x22;
        frame[2] = frame[3] = 0;
        frame[4] = 0;
        if (blue_payment_apdu_handle(state, frame, 5, frame,
                sizeof frame, &reply_length, blake, sha,
                screen_hash, owned) != 0x9000) return false;
    }
    return state->review.pending && state->review.output.index == 0;
}

static void fuzz_commands(const uint8_t *data, size_t size, size_t offset,
    blue_payment_apdu *state, const zcl_zip243_hasher *blake,
    const zcl_tx_replay_sha256 *sha,
    const blue_payment_owned_hashes *owned) {
    while (offset < size) {
        size_t length = data[offset++];
        if (length > size - offset) length = size - offset;
        uint8_t frame[260] = {0};
        memcpy(frame, data + offset, length);
        size_t reply_length = sizeof frame;
        uint16_t status = blue_payment_apdu_handle(state, frame, length,
            frame, sizeof frame, &reply_length, blake, sha,
            screen_hash, owned);
        if (reply_length > sizeof frame || state->approved ||
            state->review_confirmed ||
            (status != 0x9000 &&
             (reply_length || state->active || state->previous_active ||
              state->fee_ready || state->review.verified))) abort();
        offset += length;
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size > 4096) return 0;
    struct blake2b_ctx blake_context;
    zsha256_ctx sha_context;
    zcl_zip243_hasher blake = zcl_zip243_host_hasher(&blake_context);
    zcl_tx_replay_sha256 sha = {.context = &sha_context,
        .init = sha_init, .update = sha_update, .final = sha_final};
    blue_payment_apdu state = {0};
    blue_payment_owned_hashes owned = {0};
    size_t offset = 0;
    if (size && (data[0] & 2)) {
        if (!seed_pending_output(&state, &blake, &sha, &owned)) abort();
        offset = 1;
    } else if (size && (data[0] & 1)) {
        uint8_t begin[17] = {0xa5, 0x20, 0, 0, 12,
            128, 0, 0, 0, 0, 0, 0, 0, 0xbb, 0x09, 0xb8, 0x76};
        size_t reply_length = 0;
        if (blue_payment_apdu_handle(&state, begin, sizeof begin,
                begin, sizeof begin, &reply_length, &blake, &sha,
                screen_hash, &owned) != 0x9000 || reply_length)
            abort();
        offset = 1;
    }
    fuzz_commands(data, size, offset, &state, &blake, &sha, &owned);
    return 0;
}
