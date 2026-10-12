/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "blue_fs_ct.h"

#undef NDEBUG
#include <assert.h>
#include <string.h>

typedef void (*scalar_binary)(struct fs *, const struct fs *, const struct fs *);

static void reference_sub(struct fs *result, const struct fs *a,
    const struct fs *b) {
    struct fs negative;
    fs_neg(&negative, b);
    fs_add(result, a, &negative);
}

static void check_binary(scalar_binary reference, scalar_binary candidate,
    const struct fs *a, const struct fs *b) {
    struct fs expected, actual, alias_a = *a, alias_b = *b;
    reference(&expected, a, b);
    candidate(&actual, a, b);
    assert(memcmp(&actual, &expected, sizeof actual) == 0);
    candidate(&alias_a, &alias_a, b);
    assert(memcmp(&alias_a, &expected, sizeof alias_a) == 0);
    candidate(&alias_b, a, &alias_b);
    assert(memcmp(&alias_b, &expected, sizeof alias_b) == 0);
}

static void check_pair(const struct fs *a, const struct fs *b) {
    check_binary(fs_add, blue_fs_add_ct, a, b);
    check_binary(reference_sub, blue_fs_sub_ct, a, b);
    check_binary(fs_mul, blue_fs_mul_ct, a, b);
    struct fs expected, actual, alias = *a;
    fs_neg(&expected, a);
    blue_fs_neg_ct(&actual, a);
    assert(memcmp(&actual, &expected, sizeof actual) == 0);
    blue_fs_neg_ct(&alias, &alias);
    assert(memcmp(&alias, &expected, sizeof alias) == 0);
}

static struct fs random_scalar(uint64_t *state) {
    uint8_t bytes[32];
    for (size_t i = 0; i < sizeof bytes; ++i) {
        *state = *state * 6364136223846793005ULL +
            1442695040888963407ULL;
        bytes[i] = (uint8_t)(*state >> 56);
    }
    bytes[31] &= 0x07u;
    struct fs value;
    assert(fs_from_bytes(&value, bytes));
    return value;
}

static void check_encoding(const struct fs *value) {
    uint8_t encoded[32], expected[32];
    struct fs decoded;
    blue_fs_to_bytes(encoded, value);
    fs_to_bytes(expected, value);
    assert(memcmp(encoded, expected, sizeof encoded) == 0);
    assert(blue_fs_from_bytes_canonical(&decoded, encoded));
    assert(memcmp(&decoded, value, sizeof decoded) == 0);
}

static void check_invalid_encoding(void) {
    static const uint8_t order[32] = {
        0xb7,0x2c,0xf7,0xd6,0x5e,0x0e,0x97,0xd0,
        0x82,0x10,0xc8,0xcc,0x93,0x20,0x68,0xa6,
        0x00,0x3b,0x34,0x01,0x01,0x3b,0x67,0x06,
        0xa9,0xaf,0x33,0x65,0xea,0xb4,0x7d,0x0e
    };
    struct fs decoded;
    memset(&decoded, 0xa5, sizeof decoded);
    assert(!blue_fs_from_bytes_canonical(&decoded, order));
    const struct fs zero = {0};
    assert(memcmp(&decoded, &zero, sizeof decoded) == 0);
    memset(&decoded, 0xa5, sizeof decoded);
    assert(!blue_fs_from_bytes_canonical(&decoded, NULL));
    assert(memcmp(&decoded, &zero, sizeof decoded) == 0);
    assert(!blue_fs_from_bytes_canonical(NULL, order));
}

static void check_random_encodings(uint64_t *state) {
    const struct fs zero = {0};
    for (unsigned sample = 0; sample < 4096; ++sample) {
        uint8_t bytes[32];
        for (size_t i = 0; i < sizeof bytes; ++i) {
            *state = *state * 6364136223846793005ULL +
                1442695040888963407ULL;
            bytes[i] = (uint8_t)(*state >> 56);
        }
        struct fs reference = {0}, decoded = {0};
        bool valid = fs_from_bytes(&reference, bytes);
        assert(blue_fs_from_bytes_canonical(&decoded, bytes) == valid);
        assert(memcmp(&decoded, valid ? &reference : &zero,
            sizeof decoded) == 0);
    }
}

static void check_decoder_overlap(void) {
    struct {
        struct fs result;
        uint8_t tail[32];
    } storage;
    memset(&storage, 0xa5, sizeof storage);
    uint8_t original[sizeof storage];
    memcpy(original, &storage, sizeof original);
    assert(!blue_fs_from_bytes_canonical(&storage.result,
        (const uint8_t *)&storage.result));
    assert(memcmp(&storage, original, sizeof storage) == 0);
    assert(!blue_fs_from_bytes_canonical(&storage.result,
        (const uint8_t *)&storage.result + 16));
    assert(memcmp(&storage, original, sizeof storage) == 0);
}

int main(void) {
    struct fs zero, one;
    fs_zero(&zero);
    fs_one(&one);
    const struct fs max = {.d = {
        0xd0970e5ed6f72cb6ULL, 0xa6682093ccc81082ULL,
        0x06673b0101343b00ULL, 0x0e7db4ea6533afa9ULL
    }};
    const struct fs *edges[] = {&zero, &one, &max};
    check_invalid_encoding();
    check_decoder_overlap();
    for (size_t i = 0; i < 3; ++i) check_encoding(edges[i]);
    for (size_t i = 0; i < 3; ++i)
        for (size_t j = 0; j < 3; ++j) check_pair(edges[i], edges[j]);
    uint64_t state = 0x23c1a55b7e491dc3ULL;
    check_random_encodings(&state);
    for (size_t sample = 0; sample < 4096; ++sample) {
        struct fs a = random_scalar(&state), b = random_scalar(&state);
        check_encoding(&a);
        check_pair(&a, &b);
        check_pair(&a, &a);
    }
    return 0;
}
