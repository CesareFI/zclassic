/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "blue_payment_host_verify.h"

#include <stdint.h>
#include <string.h>

static bool overlaps(const void *left, size_t left_length,
    const void *right, size_t right_length) {
    if (!left || !right || !left_length || !right_length) return false;
    uintptr_t a = (uintptr_t)left, b = (uintptr_t)right;
    return a <= b ? b - a < left_length : a - b < right_length;
}

static bool result_disjoint(const blue_payment_verified_signature *result,
    const uint8_t *reply, size_t reply_length,
    const uint8_t expected_hash160[20], const uint8_t digest[32]) {
    return !overlaps(result, sizeof *result, reply, reply_length) &&
        !overlaps(result, sizeof *result, expected_hash160, 20) &&
        !overlaps(result, sizeof *result, digest, 32);
}

static bool inputs_valid(const uint8_t *reply, size_t reply_length,
    uint8_t expected_index, uint8_t expected_path,
    const uint8_t expected_hash160[20], const uint8_t digest[32],
    blue_payment_pubkey_hash_fn hash,
    blue_payment_verify_signature_fn verify) {
    return reply && expected_hash160 && digest && hash && verify &&
        expected_index < ZCL_TX_STREAM_MAX_INPUTS &&
        (expected_path == BLUE_PAYMENT_INPUT_EXTERNAL ||
         expected_path == BLUE_PAYMENT_INPUT_INTERNAL) &&
        reply_length >= 46 &&
        reply_length <= BLUE_PAYMENT_SIGN_REPLY_MAX + 2;
}

static bool frame_valid(const uint8_t *reply, size_t reply_length,
    uint8_t expected_index, uint8_t expected_path) {
    size_t der_length = reply[35];
    return reply[0] == expected_index && reply[1] == expected_path &&
        (reply[2] == 2 || reply[2] == 3) &&
        der_length >= 8 && der_length <= BLUE_ECDSA_DER_MAX &&
        reply_length == 36 + der_length + 2 &&
        reply[reply_length - 2] == 0x90 && reply[reply_length - 1] == 0;
}

static bool canonical_der(const uint8_t *der, size_t der_length) {
    uint8_t normalized[BLUE_ECDSA_DER_MAX];
    size_t normalized_length = 0;
    return blue_ecdsa_der_low_s(der, der_length,
        normalized, &normalized_length) &&
        normalized_length == der_length &&
        memcmp(normalized, der, der_length) == 0;
}

static bool inputs_unchanged(const uint8_t *reply,
    const uint8_t *trusted_reply, const uint8_t *callback_reply,
    size_t reply_length, const uint8_t expected_hash160[20],
    const uint8_t trusted_hash160[20], const uint8_t digest[32],
    const uint8_t trusted_digest[32],
    const uint8_t callback_digest[32]) {
    return memcmp(reply, trusted_reply, reply_length) == 0 &&
        memcmp(callback_reply, trusted_reply, reply_length) == 0 &&
        memcmp(expected_hash160, trusted_hash160, 20) == 0 &&
        memcmp(digest, trusted_digest, 32) == 0 &&
        memcmp(callback_digest, trusted_digest, 32) == 0;
}

bool blue_payment_host_verify(const uint8_t *reply, size_t reply_length,
    uint8_t expected_index, uint8_t expected_path,
    const uint8_t expected_hash160[20], const uint8_t digest[32],
    blue_payment_pubkey_hash_fn hash,
    blue_payment_verify_signature_fn verify, void *verify_context,
    blue_payment_verified_signature *result) {
    if (!result || !result_disjoint(result, reply, reply_length,
            expected_hash160, digest)) return false;
    memset(result, 0, sizeof *result);
    if (!inputs_valid(reply, reply_length, expected_index,
            expected_path, expected_hash160, digest, hash, verify))
        return false;
    uint8_t trusted_reply[BLUE_PAYMENT_SIGN_REPLY_MAX + 2];
    uint8_t callback_reply[BLUE_PAYMENT_SIGN_REPLY_MAX + 2];
    uint8_t trusted_hash160[20], trusted_digest[32], callback_digest[32];
    memcpy(trusted_reply, reply, reply_length);
    memcpy(callback_reply, reply, reply_length);
    memcpy(trusted_hash160, expected_hash160, sizeof trusted_hash160);
    memcpy(trusted_digest, digest, sizeof trusted_digest);
    memcpy(callback_digest, digest, sizeof callback_digest);
    if (!frame_valid(trusted_reply, reply_length, expected_index,
            expected_path) ||
        !canonical_der(trusted_reply + 36, trusted_reply[35])) return false;
    uint8_t hash160[20];
    if (!hash(callback_reply + 2, hash160) ||
        memcmp(hash160, trusted_hash160, sizeof hash160) != 0 ||
        !verify(verify_context, callback_reply + 2, callback_digest,
            callback_reply + 36, trusted_reply[35]) ||
        !inputs_unchanged(reply, trusted_reply, callback_reply,
            reply_length, expected_hash160, trusted_hash160,
            digest, trusted_digest, callback_digest)) return false;
    size_t der_length = trusted_reply[35];
    result->index = expected_index;
    result->path = expected_path;
    memcpy(result->digest, trusted_digest, sizeof result->digest);
    memcpy(result->public_key, trusted_reply + 2,
        sizeof result->public_key);
    memcpy(result->der, trusted_reply + 36, der_length);
    result->der_length = (uint8_t)der_length;
    return true;
}
