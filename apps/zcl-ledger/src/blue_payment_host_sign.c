/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "blue_payment_host_sign.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    uint8_t paths[ZCL_TX_STREAM_MAX_INPUTS];
    uint8_t hashes[ZCL_TX_STREAM_MAX_INPUTS][20];
    uint8_t digests[ZCL_TX_STREAM_MAX_INPUTS][32];
} signing_expectations;

static bool overlaps(const void *left, size_t left_length,
    const void *right, size_t right_length) {
    if (!left || !right || !left_length || !right_length) return false;
    uintptr_t a = (uintptr_t)left, b = (uintptr_t)right;
    return a <= b ? b - a < left_length : a - b < right_length;
}

static bool result_disjoint(size_t count, const uint8_t *paths,
    const uint8_t (*hashes)[20], const uint8_t (*digests)[32],
    const blue_payment_verified_signature *signatures) {
    size_t length = count * sizeof *signatures;
    return !overlaps(signatures, length, paths, count) &&
        !overlaps(signatures, length, hashes, count * sizeof *hashes) &&
        !overlaps(signatures, length, digests, count * sizeof *digests);
}

static bool signing_identity(blue_payment_live_exchange exchange,
    void *context) {
    static const uint8_t request[5] = {0xa5, 0x01, 0, 0, 0};
    static const uint8_t expected[7] = {'Z', 'C', 'L', 12, 31, 0x90, 0};
    uint8_t reply[7];
    size_t length = 0;
    return exchange(context, request, sizeof request, reply, sizeof reply,
        &length) && length == sizeof expected &&
        memcmp(reply, expected, sizeof expected) == 0;
}

static void abort_review(blue_payment_live_exchange exchange,
    void *context) {
    static const uint8_t request[5] = {0xa5, 0x24, 0, 0, 0};
    uint8_t reply[2];
    size_t length = 0;
    (void)exchange(context, request, sizeof request, reply, sizeof reply,
        &length);
}

static void abort_and_clear(blue_payment_live_exchange exchange,
    void *context, blue_payment_verified_signature *signatures,
    size_t count, bool clear) {
    if (exchange) abort_review(exchange, context);
    if (clear) memset(signatures, 0, count * sizeof *signatures);
}

static bool request_signature(size_t index, const uint8_t *paths,
    const uint8_t (*hashes)[20], const uint8_t (*digests)[32],
    blue_payment_live_exchange exchange, void *device_context,
    blue_payment_pubkey_hash_fn hash,
    blue_payment_verify_signature_fn verify, void *verify_context,
    blue_payment_verified_signature *result) {
    uint8_t request[6] = {0xa5, 0x29, 0, 0, 1, (uint8_t)index};
    uint8_t reply[BLUE_PAYMENT_SIGN_REPLY_MAX + 2];
    size_t length = 0;
    return exchange(device_context, request, sizeof request,
            reply, sizeof reply, &length) &&
        blue_payment_host_verify(reply, length, (uint8_t)index,
            paths[index], hashes[index], digests[index], hash, verify,
            verify_context, result);
}

static bool signing_arguments_valid(size_t count, const uint8_t *paths,
    const uint8_t (*hashes)[20], const uint8_t (*digests)[32],
    blue_payment_live_exchange exchange,
    blue_payment_host_approval approval,
    blue_payment_pubkey_hash_fn hash,
    blue_payment_verify_signature_fn verify,
    blue_payment_verified_signature *signatures) {
    return signatures && count && count <= ZCL_TX_STREAM_MAX_INPUTS &&
        paths && hashes && digests && exchange && approval && hash && verify;
}

static void freeze_expectations(signing_expectations *frozen,
    size_t count, const uint8_t *paths,
    const uint8_t (*hashes)[20], const uint8_t (*digests)[32]) {
    memcpy(frozen->paths, paths, count);
    memcpy(frozen->hashes, hashes, count * sizeof frozen->hashes[0]);
    memcpy(frozen->digests, digests, count * sizeof frozen->digests[0]);
}

static bool expectations_unchanged(const signing_expectations *frozen,
    size_t count, const uint8_t *paths,
    const uint8_t (*hashes)[20], const uint8_t (*digests)[32]) {
    return memcmp(paths, frozen->paths, count) == 0 &&
        memcmp(hashes, frozen->hashes,
            count * sizeof frozen->hashes[0]) == 0 &&
        memcmp(digests, frozen->digests,
            count * sizeof frozen->digests[0]) == 0;
}

static void erase_expectations(signing_expectations *frozen) {
    volatile uint8_t *bytes = (volatile uint8_t *)frozen;
    for (size_t i = 0; i < sizeof *frozen; ++i) bytes[i] = 0;
}

static void erase_collected(blue_payment_verified_signature *collected,
    size_t count) {
    volatile uint8_t *bytes = (volatile uint8_t *)collected;
    for (size_t i = 0; i < count * sizeof *collected; ++i) bytes[i] = 0;
}

static bool collect_signatures(size_t count,
    const signing_expectations *frozen, const uint8_t *paths,
    const uint8_t (*hashes)[20], const uint8_t (*digests)[32],
    blue_payment_live_exchange exchange, void *device_context,
    blue_payment_pubkey_hash_fn hash,
    blue_payment_verify_signature_fn verify, void *verify_context,
    blue_payment_verified_signature *collected) {
    for (size_t i = 0; i < count; ++i) {
        if (!request_signature(i, frozen->paths,
                (const uint8_t (*)[20])frozen->hashes,
                (const uint8_t (*)[32])frozen->digests, exchange,
                device_context, hash, verify, verify_context,
                &collected[i]) ||
            !expectations_unchanged(frozen, count, paths, hashes, digests))
            return false;
    }
    return true;
}

bool blue_payment_host_sign(size_t count, const uint8_t *paths,
    const uint8_t (*hashes)[20], const uint8_t (*digests)[32],
    blue_payment_live_exchange exchange,
    blue_payment_host_approval approval, void *device_context,
    blue_payment_pubkey_hash_fn hash,
    blue_payment_verify_signature_fn verify, void *verify_context,
    blue_payment_verified_signature *signatures) {
    bool bounded = signatures && count && count <= ZCL_TX_STREAM_MAX_INPUTS;
    bool disjoint = bounded && result_disjoint(count, paths, hashes,
        digests, signatures);
    if (disjoint) memset(signatures, 0, count * sizeof *signatures);
    if (!disjoint ||
        !signing_arguments_valid(count, paths, hashes, digests,
            exchange, approval, hash, verify, signatures)) {
        abort_and_clear(exchange, device_context, signatures, count,
            disjoint);
        return false;
    }
    signing_expectations frozen;
    freeze_expectations(&frozen, count, paths, hashes, digests);
    blue_payment_verified_signature *collected =
        calloc(count, sizeof *collected);
    bool valid = collected &&
        signing_identity(exchange, device_context) &&
        expectations_unchanged(&frozen, count, paths, hashes, digests) &&
        approval(device_context) &&
        expectations_unchanged(&frozen, count, paths, hashes, digests);
    if (valid) valid = collect_signatures(count, &frozen, paths, hashes,
        digests, exchange, device_context, hash, verify, verify_context,
        collected);
    if (valid) {
        memcpy(signatures, collected, count * sizeof *signatures);
    } else {
        abort_and_clear(exchange, device_context, signatures, count, true);
    }
    if (collected) {
        erase_collected(collected, count);
        free(collected);
    }
    erase_expectations(&frozen);
    return valid;
}
