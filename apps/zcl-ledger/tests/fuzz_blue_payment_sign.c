/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "blue_payment_sign.h"

#include <stdlib.h>
#include <string.h>

typedef struct {
    unsigned calls;
    uint8_t mode;
} signer_fixture;

static bool sign_fixture(void *context, uint8_t path,
    const uint8_t digest[32], uint8_t public_key[33],
    uint8_t signature[BLUE_ECDSA_DER_MAX], size_t *signature_length) {
    signer_fixture *fixture = context;
    ++fixture->calls;
    if (path != BLUE_PAYMENT_INPUT_EXTERNAL || !digest ||
        fixture->mode == 1) return false;
    static const uint8_t der[] = {0x30, 6, 2, 1, 1, 2, 1, 1};
    memset(public_key, 0x11, 33);
    public_key[0] = fixture->mode == 3 ? 4 : 2;
    memcpy(signature, der, sizeof der);
    if (fixture->mode == 2) signature[0] = 0x31;
    *signature_length = sizeof der;
    return true;
}

static bool hash_fixture(const uint8_t public_key[33],
    uint8_t hash160[20]) {
    if (!public_key) return false;
    memset(hash160, 0x22, 20);
    return true;
}

static void initialize_review(blue_payment_apdu *state, bool approve) {
    memset(state, 0, sizeof *state);
    state->review.verified = true;
    state->fee_ready = true;
    state->input_count = state->bound_inputs = 1;
    state->input_zat = 2;
    state->output_zat = state->fee_zat = 1;
    state->input_paths = BLUE_PAYMENT_INPUT_EXTERNAL;
    memset(state->input_record[0], 0x33, 32);
    state->input_record[0][32] = BLUE_PAYMENT_INPUT_EXTERNAL;
    if (approve && !blue_payment_apdu_touch_approve(state)) abort();
}

static size_t make_request(const uint8_t *data, size_t size,
    uint8_t frame[BLUE_PAYMENT_SIGN_REPLY_MAX]) {
    if (!size || (data[0] & 2)) {
        static const uint8_t valid[] = {0xa5, 0x29, 0, 0, 1, 0};
        memcpy(frame, valid, sizeof valid);
        if (size > 3 && (data[2] & 1))
            frame[data[2] % sizeof valid] ^= data[3];
        return sizeof valid;
    }
    size_t length = size > 1 ? size - 1 : 0;
    if (length > BLUE_PAYMENT_SIGN_REPLY_MAX)
        length = BLUE_PAYMENT_SIGN_REPLY_MAX;
    if (length) memcpy(frame, data + 1, length);
    return length;
}

static void check_signed(size_t length, size_t capacity,
    const uint8_t *reply, const blue_payment_apdu *state,
    const signer_fixture *fixture, bool approved) {
    static const uint8_t der[] = {0x30, 6, 2, 1, 1, 2, 1, 1};
    if (!approved || fixture->mode || length != 44 ||
        fixture->calls != 1 || state->approved ||
        state->next_sign_index != 1 || reply[0] ||
        reply[1] != BLUE_PAYMENT_INPUT_EXTERNAL ||
        reply[2] != 2 || reply[35] != sizeof der ||
        memcmp(reply + 36, der, sizeof der)) abort();
    for (size_t i = length; i < capacity; ++i)
        if (reply[i]) abort();
}

static void check_rejected(size_t length, size_t capacity,
    const uint8_t *reply, const blue_payment_apdu *state) {
    if (length || state->approved || state->fee_ready ||
        state->review.verified) abort();
    for (size_t i = 0; i < capacity; ++i)
        if (reply[i]) abort();
}

static void check_result(uint16_t status, size_t length, size_t capacity,
    const uint8_t *reply, const blue_payment_apdu *state,
    const signer_fixture *fixture, bool approved, bool must_sign) {
    if (length > capacity || fixture->calls > 1) abort();
    if (must_sign && status != 0x9000) abort();
    if (status == 0x9000)
        check_signed(length, capacity, reply, state, fixture, approved);
    else check_rejected(length, capacity, reply, state);
}

static void check_single_use(blue_payment_apdu *state,
    const blue_payment_owned_hashes *owned, signer_fixture *fixture) {
    uint8_t request[6] = {0xa5, 0x29, 0, 0, 1, 0};
    uint8_t reply[BLUE_PAYMENT_SIGN_REPLY_MAX];
    size_t length = SIZE_MAX;
    uint16_t status = blue_payment_sign_command(state, request,
        sizeof request, owned, sign_fixture, fixture, hash_fixture,
        reply, sizeof reply, &length);
    if (status != 0x6985 || length || fixture->calls != 1 ||
        state->approved || state->fee_ready) abort();
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size > 512) return 0;
    uint8_t flags = size ? data[0] : 3;
    bool approved = (flags & 1) != 0;
    blue_payment_apdu state;
    initialize_review(&state, approved);
    blue_payment_owned_hashes owned = {0};
    memset(owned.external, 0x22, sizeof owned.external);
    signer_fixture fixture = {.mode = size > 6 ? data[6] & 3 : 0};
    uint8_t frame[BLUE_PAYMENT_SIGN_REPLY_MAX] = {0};
    size_t frame_length = make_request(data, size, frame);
    uint8_t separate[BLUE_PAYMENT_SIGN_REPLY_MAX];
    memset(separate, 0xa5, sizeof separate);
    bool alias = size > 5 && (data[5] & 1);
    uint8_t *reply = alias ? frame : separate;
    size_t capacity = size > 4 && (data[4] & 1) ?
        data[4] % (BLUE_PAYMENT_SIGN_REPLY_MAX + 1) :
        BLUE_PAYMENT_SIGN_REPLY_MAX;
    size_t reply_length = SIZE_MAX;
    uint16_t status = blue_payment_sign_command(&state, frame, frame_length,
        &owned, sign_fixture, &fixture, hash_fixture, reply, capacity,
        &reply_length);
    bool unchanged = size <= 3 || !(data[2] & 1) || !data[3];
    bool must_sign = approved && (flags & 2) && unchanged &&
        capacity == BLUE_PAYMENT_SIGN_REPLY_MAX && fixture.mode == 0;
    check_result(status, reply_length, capacity, reply, &state,
        &fixture, approved, must_sign);
    if (status == 0x9000) check_single_use(&state, &owned, &fixture);
    return 0;
}
