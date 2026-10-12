/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "blue_payment_sign.h"

#include <stdint.h>
#include <string.h>

static void wipe(void *memory, size_t length) {
    volatile uint8_t *bytes = memory;
    for (size_t i = 0; i < length; ++i) bytes[i] = 0;
}

static bool overlap(const void *left, size_t left_size,
    const void *right, size_t right_size) {
    if (!left || !right || !left_size || !right_size) return false;
    uintptr_t a = (uintptr_t)left, b = (uintptr_t)right;
    return a <= b ? b - a < left_size : a - b < right_size;
}

static bool sign_storage_valid(const blue_payment_apdu *state,
    const blue_payment_owned_hashes *owned, const uint8_t *reply,
    size_t capacity, const size_t *reply_length) {
    return !overlap(state, sizeof *state, owned, sizeof *owned) &&
        !overlap(state, sizeof *state, reply, capacity) &&
        !overlap(state, sizeof *state, reply_length,
            sizeof *reply_length) &&
        !overlap(owned, sizeof *owned, reply, capacity) &&
        !overlap(owned, sizeof *owned, reply_length,
            sizeof *reply_length) &&
        !overlap(reply, capacity, reply_length, sizeof *reply_length);
}

static void reject_sign_storage(blue_payment_apdu *state,
    const blue_payment_owned_hashes *owned, const uint8_t *apdu,
    size_t apdu_length, uint8_t *reply, size_t capacity,
    size_t *reply_length) {
    if (reply && !overlap(state, sizeof *state, reply, capacity) &&
        !overlap(owned, sizeof *owned, reply, capacity))
        memset(reply, 0, capacity);
    if (reply_length &&
        !overlap(state, sizeof *state, reply_length,
            sizeof *reply_length) &&
        !overlap(owned, sizeof *owned, reply_length,
            sizeof *reply_length) &&
        !overlap(apdu, apdu_length, reply_length,
            sizeof *reply_length) &&
        !overlap(reply, capacity, reply_length, sizeof *reply_length))
        *reply_length = 0;
    blue_payment_apdu_abort(state);
}

static bool account_matches(uint8_t path, const uint8_t public_key[33],
    const uint8_t hash160[20], const blue_payment_owned_hashes *owned) {
    if (public_key[0] != 2 && public_key[0] != 3) return false;
    if (path == BLUE_PAYMENT_INPUT_EXTERNAL)
        return memcmp(hash160, owned->external, 20) == 0;
    if (path == BLUE_PAYMENT_INPUT_INTERNAL)
        return memcmp(hash160, owned->internal, 20) == 0;
    return false;
}

bool blue_payment_sign_next(blue_payment_apdu *state, uint8_t index,
    const blue_payment_owned_hashes *owned,
    blue_payment_sign_digest_fn signer, void *signer_context,
    blue_payment_pubkey_hash_fn hash,
    uint8_t *reply, size_t capacity, size_t *reply_length) {
    if (!state || !owned || !signer || !hash || !reply ||
        !reply_length || capacity < BLUE_PAYMENT_SIGN_REPLY_MAX ||
        !sign_storage_valid(state, owned, reply, capacity, reply_length)) {
        reject_sign_storage(state, owned, NULL, 0,
            reply, capacity, reply_length);
        return false;
    }
    *reply_length = 0;
    memset(reply, 0, capacity);
    uint8_t digest[32] = {0}, public_key[33] = {0},
        signature[BLUE_ECDSA_DER_MAX] = {0},
        normalized[BLUE_ECDSA_DER_MAX] = {0}, hash160[20] = {0};
    uint8_t path = 0;
    size_t signature_length = 0, normalized_length = 0;
    bool valid = blue_payment_apdu_take_digest(state, index, digest, &path) &&
        signer(signer_context, path, digest, public_key,
               signature, &signature_length) &&
        hash(public_key, hash160) &&
        account_matches(path, public_key, hash160, owned) &&
        blue_ecdsa_der_low_s(signature, signature_length,
                             normalized, &normalized_length);
    if (valid) {
        reply[0] = index;
        reply[1] = path;
        memcpy(reply + 2, public_key, 33);
        reply[35] = (uint8_t)normalized_length;
        memcpy(reply + 36, normalized, normalized_length);
        *reply_length = 36 + normalized_length;
    } else blue_payment_apdu_abort(state);
    wipe(digest, sizeof digest);
    wipe(signature, sizeof signature);
    wipe(normalized, sizeof normalized);
    wipe(public_key, sizeof public_key);
    wipe(hash160, sizeof hash160);
    return valid;
}

static uint16_t command_frame_status(const uint8_t *apdu,
    size_t apdu_length, size_t reply_capacity) {
    if (apdu_length != 6 || apdu[4] != 1 ||
        reply_capacity < BLUE_PAYMENT_SIGN_REPLY_MAX) return 0x6700;
    if (apdu[0] != 0xa5) return 0x6e00;
    if (apdu[2] || apdu[3]) return 0x6b00;
    if (apdu[1] != 0x29) return 0x6d00;
    return 0x9000;
}

static bool command_storage_valid(const blue_payment_apdu *state,
    const uint8_t *apdu, size_t apdu_length,
    const blue_payment_owned_hashes *owned,
    const uint8_t *reply, size_t capacity,
    const size_t *reply_length) {
    return sign_storage_valid(state, owned, reply, capacity,
            reply_length) &&
        !overlap(state, sizeof *state, apdu, apdu_length) &&
        !overlap(owned, sizeof *owned, apdu, apdu_length) &&
        !overlap(apdu, apdu_length, reply_length,
            sizeof *reply_length);
}

uint16_t blue_payment_sign_command(blue_payment_apdu *state,
    const uint8_t *apdu, size_t apdu_length,
    const blue_payment_owned_hashes *owned,
    blue_payment_sign_digest_fn signer, void *signer_context,
    blue_payment_pubkey_hash_fn hash,
    uint8_t *reply, size_t capacity, size_t *reply_length) {
    if (!state || !apdu || !owned || !signer || !hash ||
        !reply || !reply_length ||
        !command_storage_valid(state, apdu, apdu_length, owned,
            reply, capacity, reply_length)) {
        reject_sign_storage(state, owned, apdu, apdu_length,
            reply, capacity, reply_length);
        return 0x6f00;
    }
    *reply_length = 0;
    uint16_t status = command_frame_status(apdu, apdu_length, capacity);
    uint8_t index = status == 0x9000 ? apdu[5] : 0;
    if (status == 0x9000 && !blue_payment_sign_next(state, index, owned,
            signer, signer_context, hash, reply, capacity, reply_length))
        status = 0x6985;
    if (status != 0x9000) {
        memset(reply, 0, capacity);
        blue_payment_apdu_abort(state);
        *reply_length = 0;
    }
    return status;
}
