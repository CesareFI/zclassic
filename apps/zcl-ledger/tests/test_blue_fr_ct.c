/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "blue_fr_ct.h"
#include "blue_fr_sqrt.h"

#undef NDEBUG
#include <assert.h>
#include <string.h>

typedef void (*field_binary)(struct fr *, const struct fr *, const struct fr *);

static void check_binary(field_binary reference, field_binary candidate,
    const struct fr *a, const struct fr *b) {
    struct fr expected, actual, alias_a = *a, alias_b = *b;
    reference(&expected, a, b);
    candidate(&actual, a, b);
    assert(memcmp(&actual, &expected, sizeof actual) == 0);
    candidate(&alias_a, &alias_a, b);
    assert(memcmp(&alias_a, &expected, sizeof alias_a) == 0);
    candidate(&alias_b, a, &alias_b);
    assert(memcmp(&alias_b, &expected, sizeof alias_b) == 0);
}

static void check_pair(const struct fr *a, const struct fr *b) {
    check_binary(fr_add, blue_fr_add_ct, a, b);
    check_binary(fr_sub, blue_fr_sub_ct, a, b);
    check_binary(fr_mul, blue_fr_mul_ct, a, b);
    struct fr expected, actual, aliased = *a;
    fr_neg(&expected, a);
    blue_fr_neg_ct(&actual, a);
    assert(memcmp(&actual, &expected, sizeof actual) == 0);
    blue_fr_neg_ct(&aliased, &aliased);
    assert(memcmp(&aliased, &expected, sizeof aliased) == 0);
}

static struct fr random_field(uint64_t *state) {
    uint8_t bytes[32];
    for (size_t i = 0; i < sizeof bytes; ++i) {
        *state = *state * 6364136223846793005ULL +
            1442695040888963407ULL;
        bytes[i] = (uint8_t)(*state >> 56);
    }
    bytes[31] &= 0x3fu;
    struct fr value;
    assert(fr_from_bytes(&value, bytes));
    return value;
}

static void check_codec(const uint8_t bytes[32], bool valid) {
    struct fr expected, actual;
    uint8_t restored[32];
    assert(blue_fr_from_bytes_canonical(&actual, bytes) == valid);
    if (!valid) {
        const struct fr zero = {0};
        assert(memcmp(&actual, &zero, sizeof zero) == 0);
        return;
    }
    assert(fr_from_bytes(&expected, bytes));
    assert(memcmp(&actual, &expected, sizeof actual) == 0);
    blue_fr_to_bytes(restored, &actual);
    assert(memcmp(restored, bytes, sizeof restored) == 0);
}

static void check_sqrt(const struct fr *value) {
    struct fr expected, actual, squared, alias = *value;
    assert(fr_sqrt(&expected, value));
    assert(blue_fr_sqrt_public(&actual, value));
    blue_fr_mul_ct(&squared, &actual, &actual);
    assert(memcmp(&squared, value, sizeof squared) == 0);
    assert(blue_fr_sqrt_public(&alias, &alias));
    blue_fr_mul_ct(&squared, &alias, &alias);
    assert(memcmp(&squared, value, sizeof squared) == 0);
}

static void check_inverse(const struct fr *value) {
    struct fr expected, actual, aliased = *value;
    fr_inv(&expected, value);
    assert(blue_fr_inverse_fixed(&actual, value));
    assert(memcmp(&actual, &expected, sizeof actual) == 0);
    assert(blue_fr_inverse_fixed(&aliased, &aliased));
    assert(memcmp(&aliased, &expected, sizeof aliased) == 0);
}

int main(void) {
    struct fr zero, one, minus_one;
    fr_zero(&zero);
    fr_one(&one);
    uint8_t p_minus_one[32] = {
        0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
        0xfe, 0x5b, 0xfe, 0xff, 0x02, 0xa4, 0xbd, 0x53,
        0x05, 0xd8, 0xa1, 0x09, 0x08, 0xd8, 0x39, 0x33,
        0x48, 0x7d, 0x9d, 0x29, 0x53, 0xa7, 0xed, 0x73
    };
    assert(fr_from_bytes(&minus_one, p_minus_one));
    uint8_t boundary[32] = {0};
    check_codec(boundary, true);
    boundary[0] = 1;
    check_codec(boundary, true);
    check_codec(p_minus_one, true);
    memcpy(boundary, p_minus_one, sizeof boundary);
    ++boundary[0];
    check_codec(boundary, false);
    ++boundary[0];
    check_codec(boundary, false);
    struct fr cleared = minus_one;
    assert(!blue_fr_from_bytes_canonical(&cleared, NULL));
    assert(memcmp(&cleared, &zero, sizeof zero) == 0);
    assert(!blue_fr_from_bytes_canonical(NULL, boundary));
    check_sqrt(&zero);
    check_sqrt(&one);
    check_inverse(&one);
    cleared = minus_one;
    assert(!blue_fr_inverse_fixed(&cleared, &zero));
    assert(memcmp(&cleared, &zero, sizeof zero) == 0);
    assert(!blue_fr_inverse_fixed(&cleared, NULL));
    assert(!blue_fr_inverse_fixed(NULL, &one));
    const uint8_t five_bytes[32] = {5};
    struct fr five, nonsquare = one;
    assert(fr_from_bytes(&five, five_bytes));
    assert(!fr_sqrt(&cleared, &five));
    assert(!blue_fr_sqrt_public(&nonsquare, &five));
    assert(memcmp(&nonsquare, &zero, sizeof zero) == 0);
    assert(!blue_fr_sqrt_public(&nonsquare, NULL));
    assert(!blue_fr_sqrt_public(NULL, &five));
    const struct fr *edges[] = {&zero, &one, &minus_one};
    for (size_t i = 0; i < 3; ++i)
        for (size_t j = 0; j < 3; ++j) check_pair(edges[i], edges[j]);
    uint64_t state = 0x23c1a55b7e491dc3ULL;
    for (size_t sample = 0; sample < 4096; ++sample) {
        struct fr a = random_field(&state), b = random_field(&state);
        uint8_t encoded[32];
        fr_to_bytes(encoded, &a);
        check_codec(encoded, true);
        check_pair(&a, &b);
        check_pair(&a, &a);
        if (sample < 16) {
            struct fr square;
            fr_mul(&square, &a, &a);
            check_sqrt(&square);
        }
        if (sample < 32) check_inverse(&a);
    }
    return 0;
}
