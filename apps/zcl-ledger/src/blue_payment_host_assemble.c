/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "blue_payment_host_assemble.h"
#include "zcl_tx_review.h"
#include "zcl_tx_script_facts.h"
#include "zsha256/zsha256.h"

#include <stdlib.h>
#include <string.h>

typedef struct {
    const uint8_t *wire;
    size_t offsets[ZCL_TX_STREAM_MAX_INPUTS];
    size_t script_lengths[ZCL_TX_STREAM_MAX_INPUTS];
    size_t count;
} input_offsets;

typedef struct {
    blue_payment_verified_signature signatures[ZCL_TX_STREAM_MAX_INPUTS];
    uint8_t digests[ZCL_TX_STREAM_MAX_INPUTS][32];
    uint8_t hashes[ZCL_TX_STREAM_MAX_INPUTS][20];
    uint8_t paths[ZCL_TX_STREAM_MAX_INPUTS];
    uint8_t reviewed_hash[32];
    uint8_t wire[];
} authenticated_snapshot;

static bool overlaps(const void *left, size_t left_length,
    const void *right, size_t right_length) {
    if (!left || !right || !left_length || !right_length) return false;
    uintptr_t a = (uintptr_t)left, b = (uintptr_t)right;
    return a <= b ? b - a < left_length : a - b < right_length;
}

static bool collect_empty_input(void *context, const zcl_tx_input *input) {
    input_offsets *offsets = context;
    if (!input || input->index != offsets->count ||
        offsets->count >= ZCL_TX_STREAM_MAX_INPUTS ||
        input->script_length || input->script <= offsets->wire)
        return false;
    size_t position = (size_t)(input->script - offsets->wire) - 1;
    if (offsets->wire[position] != 0) return false;
    offsets->offsets[offsets->count++] = position;
    return true;
}

static bool collect_signed_input(void *context, const zcl_tx_input *input) {
    input_offsets *offsets = context;
    if (!input || input->index != offsets->count ||
        offsets->count >= ZCL_TX_STREAM_MAX_INPUTS ||
        input->script <= offsets->wire || input->script_length > 252)
        return false;
    size_t position = (size_t)(input->script - offsets->wire) - 1;
    if (offsets->wire[position] != input->script_length) return false;
    offsets->offsets[offsets->count] = position;
    offsets->script_lengths[offsets->count++] = input->script_length;
    return true;
}

static bool canonical_signature(
    const blue_payment_verified_signature *signature) {
    if ((signature->public_key[0] != 2 && signature->public_key[0] != 3) ||
        signature->der_length < 8 ||
        signature->der_length > BLUE_ECDSA_DER_MAX) return false;
    uint8_t normalized[BLUE_ECDSA_DER_MAX];
    size_t length = 0;
    return blue_ecdsa_der_low_s(signature->der, signature->der_length,
               normalized, &length) &&
           length == signature->der_length &&
           memcmp(normalized, signature->der, length) == 0;
}

static size_t put_script(uint8_t *output,
    const blue_payment_verified_signature *signature) {
    size_t length = signature->der_length;
    output[0] = (uint8_t)(length + 36);
    output[1] = (uint8_t)(length + 1);
    memcpy(output + 2, signature->der, length);
    output[length + 2] = 1;
    output[length + 3] = 33;
    memcpy(output + length + 4, signature->public_key, 33);
    return length + 37;
}

static bool unsigned_v4(const uint8_t *wire, size_t length, size_t count) {
    return wire && count && count <= ZCL_TX_STREAM_MAX_INPUTS &&
        length >= 8 && length <= ZCL_TX_REVIEW_MAX_BYTES &&
        wire[0] == 4 && !wire[1] && !wire[2] && wire[3] == 0x80 &&
        memcmp(wire + 4, "\x85\x20\x2f\x89", 4) == 0;
}

static bool review_unsigned(const uint8_t *wire, size_t length,
    size_t count, zcl_tx_review *review, input_offsets *offsets) {
    return zcl_tx_review_parse(wire, length, review) == 0 &&
        review->transparent_inputs == count &&
        review->transparent_outputs && !review->sapling_spends &&
        !review->sapling_outputs && !review->sprout_joinsplits &&
        !review->value_balance_zat &&
        zcl_tx_inputs_visit(wire, length,
            collect_empty_input, offsets) == 0 && offsets->count == count;
}

static bool assembled_length(const blue_payment_verified_signature *signatures,
    const uint8_t (*expected_digests)[32], size_t count,
    size_t unsigned_length, size_t capacity, size_t *needed) {
    size_t size = unsigned_length;
    for (size_t i = 0; i < count; ++i) {
        size_t added = (size_t)signatures[i].der_length + 36;
        if (signatures[i].index != i ||
            (signatures[i].path != BLUE_PAYMENT_INPUT_EXTERNAL &&
             signatures[i].path != BLUE_PAYMENT_INPUT_INTERNAL) ||
            memcmp(signatures[i].digest, expected_digests[i], 32) != 0 ||
            !canonical_signature(&signatures[i]) ||
            size > capacity || size > ZCL_TX_REVIEW_MAX_BYTES ||
            added > capacity - size ||
            added > ZCL_TX_REVIEW_MAX_BYTES - size)
            return false;
        size += added;
    }
    *needed = size;
    return true;
}

static size_t write_scripts(const uint8_t *wire, size_t length,
    const input_offsets *offsets,
    const blue_payment_verified_signature *signatures,
    uint8_t *output) {
    size_t read = 0, written = 0;
    for (size_t i = 0; i < offsets->count; ++i) {
        size_t bytes = offsets->offsets[i] - read;
        memcpy(output + written, wire + read, bytes);
        written += bytes;
        written += put_script(output + written, &signatures[i]);
        read = offsets->offsets[i] + 1;
    }
    memcpy(output + written, wire + read, length - read);
    return written + length - read;
}

static bool same_review(const uint8_t *output, size_t length,
    const zcl_tx_review *original) {
    zcl_tx_review signed_review;
    return zcl_tx_review_parse(output, length, &signed_review) == 0 &&
        signed_review.transparent_inputs == original->transparent_inputs &&
        signed_review.transparent_outputs == original->transparent_outputs &&
        signed_review.transparent_output_zat ==
            original->transparent_output_zat &&
        signed_review.lock_time == original->lock_time &&
        signed_review.expiry_height == original->expiry_height &&
        !signed_review.sapling_spends && !signed_review.sapling_outputs &&
        !signed_review.sprout_joinsplits &&
        !signed_review.value_balance_zat;
}

static bool same_wire_except_scripts(const uint8_t *unsigned_wire,
    size_t unsigned_length, const input_offsets *original,
    const uint8_t *signed_wire, size_t signed_length,
    const blue_payment_verified_signature *signatures) {
    input_offsets signed_inputs = {.wire = signed_wire};
    if (zcl_tx_inputs_visit(signed_wire, signed_length,
            collect_signed_input, &signed_inputs) != 0 ||
        signed_inputs.count != original->count) return false;
    size_t source = 0, result = 0;
    for (size_t i = 0; i < original->count; ++i) {
        size_t span = original->offsets[i] - source;
        if (signed_inputs.offsets[i] - result != span ||
            memcmp(unsigned_wire + source, signed_wire + result, span) != 0 ||
            signed_inputs.script_lengths[i] !=
                (size_t)signatures[i].der_length + 36)
            return false;
        source = original->offsets[i] + 1;
        result = signed_inputs.offsets[i] + 1 +
            signed_inputs.script_lengths[i];
    }
    return signed_length - result == unsigned_length - source &&
        memcmp(unsigned_wire + source, signed_wire + result,
            unsigned_length - source) == 0;
}

static bool length_storage_valid(const size_t *output_length,
    const uint8_t *unsigned_wire, size_t unsigned_length,
    const blue_payment_verified_signature *signatures,
    const uint8_t (*expected_digests)[32], size_t count,
    const uint8_t *output, size_t capacity) {
    return output_length && count <= ZCL_TX_STREAM_MAX_INPUTS &&
        !overlaps(output_length, sizeof *output_length,
            unsigned_wire, unsigned_length) &&
        !overlaps(output_length, sizeof *output_length,
            signatures, count * sizeof *signatures) &&
        !overlaps(output_length, sizeof *output_length,
            expected_digests, count * sizeof *expected_digests) &&
        !overlaps(output_length, sizeof *output_length, output, capacity);
}

bool blue_payment_host_assemble(const uint8_t *unsigned_wire,
    size_t unsigned_length,
    const blue_payment_verified_signature *signatures,
    const uint8_t (*expected_digests)[32], size_t count,
    uint8_t *output, size_t capacity, size_t *output_length) {
    if (!length_storage_valid(output_length, unsigned_wire, unsigned_length,
            signatures, expected_digests, count, output, capacity))
        return false;
    *output_length = 0;
    if (!signatures || !expected_digests || !output ||
        !unsigned_v4(unsigned_wire, unsigned_length, count)) return false;
    zcl_tx_review review;
    input_offsets offsets = {.wire = unsigned_wire};
    size_t needed = 0;
    if (!review_unsigned(unsigned_wire, unsigned_length, count,
            &review, &offsets) ||
        !assembled_length(signatures, expected_digests, count, unsigned_length,
            capacity, &needed) ||
        overlaps(unsigned_wire, unsigned_length, output, needed) ||
        overlaps(signatures, count * sizeof *signatures, output, needed) ||
        overlaps(expected_digests, count * sizeof *expected_digests,
            output, needed)) return false;
    size_t written = write_scripts(unsigned_wire, unsigned_length,
        &offsets, signatures, output);
    if (written != needed || !same_review(output, written, &review) ||
        !same_wire_except_scripts(unsigned_wire, unsigned_length, &offsets,
            output, written, signatures)) {
        memset(output, 0, written);
        return false;
    }
    *output_length = written;
    return true;
}

static void clear_output(uint8_t *output, size_t capacity,
    size_t *output_length) {
    volatile uint8_t *bytes = output;
    for (size_t i = 0; i < capacity; ++i) bytes[i] = 0;
    *output_length = 0;
}

bool blue_payment_host_assemble_reviewed(const uint8_t *unsigned_wire,
    size_t unsigned_length, const uint8_t reviewed_wire_hash[32],
    const blue_payment_verified_signature *signatures,
    const uint8_t (*expected_digests)[32], size_t count,
    uint8_t *output, size_t capacity, size_t *output_length) {
    if (!unsigned_wire || !reviewed_wire_hash || !output ||
        capacity > ZCL_TX_REVIEW_MAX_BYTES ||
        unsigned_length > ZCL_TX_REVIEW_MAX_BYTES ||
        !length_storage_valid(output_length, unsigned_wire,
            unsigned_length, signatures, expected_digests,
            count, output, capacity) ||
        overlaps(reviewed_wire_hash, 32, output, capacity) ||
        overlaps(reviewed_wire_hash, 32, output_length,
            sizeof *output_length) ||
        overlaps(unsigned_wire, unsigned_length, output, capacity) ||
        overlaps(signatures, count * sizeof *signatures,
            output, capacity) ||
        overlaps(expected_digests, count * sizeof *expected_digests,
            output, capacity)) return false;
    clear_output(output, capacity, output_length);
    uint8_t actual_hash[32];
    zsha256(unsigned_wire, unsigned_length, actual_hash);
    return memcmp(actual_hash, reviewed_wire_hash, sizeof actual_hash) == 0 &&
        blue_payment_host_assemble(unsigned_wire, unsigned_length,
            signatures, expected_digests, count,
            output, capacity, output_length);
}

static bool authenticated_inputs(
    const blue_payment_verified_signature *signatures,
    const uint8_t (*expected_digests)[32],
    const uint8_t *expected_paths, const uint8_t (*expected_hashes)[20],
    size_t count, blue_payment_pubkey_hash_fn hash,
    blue_payment_verify_signature_fn verify, void *verify_context) {
    for (size_t i = 0; i < count; ++i) {
        const blue_payment_verified_signature *signature = &signatures[i];
        uint8_t actual_hash[20];
        if (signature->index != i ||
            (expected_paths[i] != BLUE_PAYMENT_INPUT_EXTERNAL &&
             expected_paths[i] != BLUE_PAYMENT_INPUT_INTERNAL) ||
            signature->path != expected_paths[i] ||
            memcmp(signature->digest, expected_digests[i], 32) != 0 ||
            !canonical_signature(signature) ||
            !hash(signature->public_key, actual_hash) ||
            memcmp(actual_hash, expected_hashes[i], 20) != 0 ||
            !verify(verify_context, signature->public_key,
                expected_digests[i], signature->der,
                signature->der_length)) return false;
    }
    return true;
}

static bool authenticated_storage(const uint8_t *unsigned_wire,
    size_t unsigned_length, const uint8_t reviewed_wire_hash[32],
    const blue_payment_verified_signature *signatures,
    const uint8_t (*expected_digests)[32],
    const uint8_t *expected_paths, const uint8_t (*expected_hashes)[20],
    size_t count, uint8_t *output, size_t capacity,
    size_t *output_length) {
    return length_storage_valid(output_length, unsigned_wire,
            unsigned_length, signatures, expected_digests,
            count, output, capacity) && count &&
        !overlaps(reviewed_wire_hash, 32, output, capacity) &&
        !overlaps(reviewed_wire_hash, 32, output_length,
            sizeof *output_length) &&
        !overlaps(expected_paths, count, output, capacity) &&
        !overlaps(expected_hashes, count * sizeof *expected_hashes,
            output, capacity) &&
        !overlaps(unsigned_wire, unsigned_length, output, capacity) &&
        !overlaps(signatures, count * sizeof *signatures,
            output, capacity) &&
        !overlaps(expected_digests, count * sizeof *expected_digests,
            output, capacity) &&
        !overlaps(output_length, sizeof *output_length,
            expected_paths, count) &&
        !overlaps(output_length, sizeof *output_length,
            expected_hashes, count * sizeof *expected_hashes);
}

static authenticated_snapshot *snapshot_authenticated_inputs(
    const uint8_t *wire, size_t wire_length,
    const uint8_t reviewed_hash[32],
    const blue_payment_verified_signature *signatures,
    const uint8_t (*digests)[32], const uint8_t *paths,
    const uint8_t (*hashes)[20], size_t count) {
    if (wire_length > SIZE_MAX - sizeof(authenticated_snapshot))
        return NULL;
    authenticated_snapshot *copy = malloc(sizeof *copy + wire_length);
    if (!copy) return NULL;
    memcpy(copy->wire, wire, wire_length);
    memcpy(copy->reviewed_hash, reviewed_hash, 32);
    memcpy(copy->signatures, signatures, count * sizeof *signatures);
    memcpy(copy->digests, digests, count * sizeof *digests);
    memcpy(copy->paths, paths, count);
    memcpy(copy->hashes, hashes, count * sizeof *hashes);
    return copy;
}

static bool authenticated_inputs_unchanged(
    const authenticated_snapshot *copy, const uint8_t *wire,
    size_t wire_length, const uint8_t reviewed_hash[32],
    const blue_payment_verified_signature *signatures,
    const uint8_t (*digests)[32], const uint8_t *paths,
    const uint8_t (*hashes)[20], size_t count) {
    return memcmp(copy->wire, wire, wire_length) == 0 &&
        memcmp(copy->reviewed_hash, reviewed_hash, 32) == 0 &&
        memcmp(copy->signatures, signatures,
            count * sizeof *signatures) == 0 &&
        memcmp(copy->digests, digests, count * sizeof *digests) == 0 &&
        memcmp(copy->paths, paths, count) == 0 &&
        memcmp(copy->hashes, hashes, count * sizeof *hashes) == 0;
}

static bool authenticated_arguments_valid(const uint8_t *unsigned_wire,
    size_t unsigned_length, const uint8_t reviewed_wire_hash[32],
    const blue_payment_verified_signature *signatures,
    const uint8_t (*expected_digests)[32],
    const uint8_t *expected_paths, const uint8_t (*expected_hashes)[20],
    size_t count, blue_payment_pubkey_hash_fn hash,
    blue_payment_verify_signature_fn verify,
    uint8_t *output, size_t capacity, size_t *output_length) {
    return unsigned_wire && reviewed_wire_hash && signatures &&
        expected_digests && expected_paths && expected_hashes &&
        hash && verify && output &&
        unsigned_length <= ZCL_TX_REVIEW_MAX_BYTES &&
        capacity <= ZCL_TX_REVIEW_MAX_BYTES &&
        authenticated_storage(unsigned_wire, unsigned_length,
            reviewed_wire_hash, signatures, expected_digests,
            expected_paths, expected_hashes, count,
            output, capacity, output_length);
}

bool blue_payment_host_assemble_authenticated(const uint8_t *unsigned_wire,
    size_t unsigned_length, const uint8_t reviewed_wire_hash[32],
    const blue_payment_verified_signature *signatures,
    const uint8_t (*expected_digests)[32],
    const uint8_t *expected_paths, const uint8_t (*expected_hashes)[20],
    size_t count, blue_payment_pubkey_hash_fn hash,
    blue_payment_verify_signature_fn verify, void *verify_context,
    uint8_t *output, size_t capacity, size_t *output_length) {
    if (!authenticated_arguments_valid(unsigned_wire, unsigned_length,
            reviewed_wire_hash, signatures, expected_digests,
            expected_paths, expected_hashes, count, hash, verify,
            output, capacity, output_length)) return false;
    authenticated_snapshot *copy = snapshot_authenticated_inputs(
        unsigned_wire, unsigned_length, reviewed_wire_hash, signatures,
        expected_digests, expected_paths, expected_hashes, count);
    if (!copy) {
        clear_output(output, capacity, output_length);
        return false;
    }
    uint8_t actual_hash[32];
    zsha256(copy->wire, unsigned_length, actual_hash);
    bool valid = memcmp(actual_hash, copy->reviewed_hash,
            sizeof actual_hash) == 0 &&
        authenticated_inputs(copy->signatures,
            (const uint8_t (*)[32])copy->digests, copy->paths,
            (const uint8_t (*)[20])copy->hashes, count,
            hash, verify, verify_context) &&
        authenticated_inputs_unchanged(copy, unsigned_wire,
            unsigned_length, reviewed_wire_hash, signatures,
            expected_digests, expected_paths, expected_hashes, count);
    if (valid) {
        clear_output(output, capacity, output_length);
        valid = blue_payment_host_assemble(copy->wire,
            unsigned_length, copy->signatures,
            (const uint8_t (*)[32])copy->digests, count,
            output, capacity, output_length);
    }
    free(copy);
    if (!valid) clear_output(output, capacity, output_length);
    return valid;
}
