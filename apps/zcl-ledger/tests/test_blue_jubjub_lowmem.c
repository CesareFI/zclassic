/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "blue_jubjub_lowmem.h"
#include "blue_jubjub_decode.h"
#include "blue_jubjub_encode.h"
#include "blue_spend_generator_fixture.h"

#undef NDEBUG
#include <assert.h>
#include <stdio.h>
#include <string.h>

static struct jub_point test_point(void) {
    struct jub_point point;
    uint8_t encoded[32] = {0};
    for (unsigned value = 1; value < 256; ++value) {
        encoded[0] = (uint8_t)value;
        if (!jub_from_bytes(&point, encoded)) continue;
        jub_mul_by_cofactor(&point, &point);
        if (!jub_is_identity(&point)) return point;
    }
    assert(false);
    return (struct jub_point){0};
}

static void check_scalar(const struct jub_point *point,
    const uint8_t scalar[32]) {
    struct jub_point expected, actual;
    uint8_t reference[32], result[32];
    jub_scalar_mul(&expected, point, scalar);
    assert(blue_jubjub_scalar_mul_lowmem(&actual, point, scalar));
    jub_to_bytes(reference, &expected);
    jub_to_bytes(result, &actual);
    assert(memcmp(reference, result, sizeof result) == 0);
}

static void check_boundaries(const struct jub_point *point) {
    uint8_t scalar[32] = {0};
    check_scalar(point, scalar);
    memset(scalar, 0xff, sizeof scalar);
    check_scalar(point, scalar);
    memset(scalar, 0, sizeof scalar);
    scalar[0] = 1;
    check_scalar(point, scalar);
    memset(scalar, 0, sizeof scalar);
    scalar[31] = 0x80;
    check_scalar(point, scalar);
}

static void check_random(const struct jub_point *point,
    const struct jub_point *doubled, const struct jub_point *negated,
    uint8_t scalar[32]) {
    uint64_t random = 0x23c1a55b7e491dc3ULL;
    for (unsigned sample = 0; sample < 64; ++sample) {
        for (size_t i = 0; i < 32; ++i) {
            random = random * 6364136223846793005ULL +
                1442695040888963407ULL;
            scalar[i] = (uint8_t)(random >> 56);
        }
        check_scalar(point, scalar);
        check_scalar(doubled, scalar);
        check_scalar(negated, scalar);
    }
}

static void check_alias_and_null(const struct jub_point *point,
    const uint8_t scalar[32]) {
    struct jub_point aliased = *point, expected;
    jub_scalar_mul(&expected, point, scalar);
    assert(blue_jubjub_scalar_mul_lowmem(&aliased, &aliased, scalar));
    uint8_t reference[32], result[32];
    jub_to_bytes(reference, &expected);
    jub_to_bytes(result, &aliased);
    assert(memcmp(reference, result, sizeof result) == 0);
    assert(!blue_jubjub_scalar_mul_lowmem(NULL, point, scalar));
    assert(!blue_jubjub_scalar_mul_lowmem(&aliased, NULL, scalar));
    assert(!blue_jubjub_scalar_mul_lowmem(&aliased, point, NULL));
    struct jub_point overwritten = *point;
    struct jub_point original = overwritten;
    const uint8_t *overlapping_scalar =
        (const uint8_t *)&overwritten + sizeof overwritten - 32;
    assert(!blue_jubjub_scalar_mul_lowmem(&overwritten, point,
        overlapping_scalar));
    assert(memcmp(&overwritten, &original, sizeof original) == 0);
}

static void decode_reversed(uint8_t out[32], const char hex[65]) {
    for (size_t i = 0; i < 32; ++i) {
        unsigned int value;
        assert(sscanf(hex + 2 * i, "%2x", &value) == 1);
        out[31 - i] = (uint8_t)value;
    }
}

static void check_spend_auth_vector(void) {
    uint8_t ask[32], expected[32], actual[32];
    decode_reversed(ask,
        "06880e0df04583674f05d25dcf1119cf18f84420407823aa47a53e474aa14885");
    decode_reversed(expected,
        "2016f18efa0efd770776328095bad71f793a5d8c58c298303e27e10f38ec44f3");
    struct jub_point point, derived;
    assert(jub_from_bytes(&point, blue_spend_generator_fixture));
    assert(blue_jubjub_scalar_mul_lowmem(&derived, &point, ask));
    jub_to_bytes(actual, &derived);
    assert(memcmp(actual, expected, sizeof actual) == 0);
}

static void check_decode(const struct jub_point *base) {
    const struct jub_point zero = {0};
    const blue_jubjub_decode_workspace empty = {0};
    blue_jubjub_decode_workspace workspace;
    for (unsigned scalar = 1; scalar <= 32; ++scalar) {
        uint8_t factor[32] = {(uint8_t)scalar};
        uint8_t encoded[32], repeated[32];
        struct jub_point point, decoded, reference;
        jub_scalar_mul(&point, base, factor);
        jub_to_bytes(encoded, &point);
        assert(jub_from_bytes(&reference, encoded));
        assert(blue_jubjub_decode_public(&decoded, &workspace, encoded));
        assert(memcmp(&workspace, &empty, sizeof empty) == 0);
        jub_to_bytes(repeated, &decoded);
        assert(memcmp(repeated, encoded, sizeof encoded) == 0);
        assert(memcmp(&decoded, &reference, sizeof decoded) == 0);
        assert(blue_jubjub_encode(repeated, &decoded));
        assert(memcmp(repeated, encoded, sizeof encoded) == 0);
    }
    uint8_t identity[32] = {1};
    struct jub_point rejected;
    assert(!blue_jubjub_decode_public(&rejected, &workspace, identity));
    assert(memcmp(&rejected, &zero, sizeof zero) == 0);
    identity[31] = 0x80;
    assert(!blue_jubjub_decode_public(&rejected, &workspace, identity));
    uint8_t modulus[32] = {
        0x01,0x00,0x00,0x00,0xff,0xff,0xff,0xff,
        0xfe,0x5b,0xfe,0xff,0x02,0xa4,0xbd,0x53,
        0x05,0xd8,0xa1,0x09,0x08,0xd8,0x39,0x33,
        0x48,0x7d,0x9d,0x29,0x53,0xa7,0xed,0x73
    };
    assert(!blue_jubjub_decode_public(&rejected, &workspace, modulus));
    assert(memcmp(&rejected, &zero, sizeof zero) == 0);
    assert(memcmp(&workspace, &empty, sizeof empty) == 0);
    --modulus[0];
    assert(!blue_jubjub_decode_public(&rejected, &workspace, modulus));
    assert(memcmp(&rejected, &zero, sizeof zero) == 0);
    ++modulus[0];
    uint8_t off_curve[32] = {2};
    assert(!jub_from_bytes(&rejected, off_curve));
    assert(!blue_jubjub_decode_public(&rejected, &workspace, off_curve));
    assert(memcmp(&rejected, &zero, sizeof zero) == 0);
    memset(&workspace, 0xa5, sizeof workspace);
    assert(!blue_jubjub_decode_public(&rejected, &workspace, NULL));
    assert(!blue_jubjub_decode_public(&rejected, NULL, modulus));
    assert(!blue_jubjub_decode_public(NULL, &workspace, modulus));
    assert(memcmp(&workspace, &empty, sizeof empty) == 0);
}

int main(void) {
    struct jub_point point = test_point(), doubled, negated;
    uint8_t scalar[32];
    jub_double(&doubled, &point);
    jub_neg(&negated, &point);
    check_boundaries(&point);
    check_random(&point, &doubled, &negated, scalar);
    check_alias_and_null(&point, scalar);
    check_spend_auth_vector();
    check_decode(&point);
    return 0;
}
