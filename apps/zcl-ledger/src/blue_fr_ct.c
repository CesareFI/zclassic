/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "blue_fr_ct.h"
#include "blue_mod256.h"

static const struct blue_mod256 fr_field = {
    .modulus = {
        0x00000001u, 0xffffffffu, 0xfffe5bfeu, 0x53bda402u,
        0x09a1d805u, 0x3339d808u, 0x299d7d48u, 0x73eda753u
    },
    .negative_inverse = 0xffffffffu
};

static const struct fr montgomery_r2 = {.d = {
    0xc999e990f3f29c6dULL, 0x2b6cedcb87925c23ULL,
    0x05d314967254398fULL, 0x0748d9d99f59ff11ULL
}};

static const struct fr montgomery_one = {.d = {
    0x00000001fffffffeULL, 0x5884b7fa00034802ULL,
    0x998c4fefecbc4ff5ULL, 0x1824b159acc5056fULL
}};

static const uint64_t modulus_minus_two[4] = {
    0xfffffffeffffffffULL, 0x53bda402fffe5bfeULL,
    0x3339d80809a1d805ULL, 0x73eda753299d7d48ULL
};

bool blue_fr_from_bytes_canonical(struct fr *result,
    const uint8_t bytes[32]) {
    if (!result) return false;
    *result = (struct fr){0};
    if (!bytes) return false;
    struct fr raw = {0};
    for (unsigned i = 0; i < 32; ++i)
        raw.d[i / 8] |= (uint64_t)bytes[i] << (8u * (i % 8));
    bool canonical = false;
    for (int i = 3; i >= 0; --i) {
        uint64_t modulus = (uint64_t)fr_field.modulus[2 * i] |
            (uint64_t)fr_field.modulus[2 * i + 1] << 32;
        if (raw.d[i] != modulus) {
            canonical = raw.d[i] < modulus;
            break;
        }
    }
    if (canonical) blue_fr_mul_ct(result, &raw, &montgomery_r2);
    blue_mod256_wipe(&raw, sizeof raw);
    return canonical;
}

void blue_fr_to_bytes(uint8_t bytes[32], const struct fr *value) {
    const struct fr one = {.d = {1}};
    struct fr raw;
    blue_fr_mul_ct(&raw, value, &one);
    for (unsigned i = 0; i < 32; ++i)
        bytes[i] = (uint8_t)(raw.d[i / 8] >> (8u * (i % 8)));
    blue_mod256_wipe(&raw, sizeof raw);
}

bool blue_fr_inverse_fixed(struct fr *result, const struct fr *value) {
    if (!result) return false;
    if (!value) {
        *result = (struct fr){0};
        return false;
    }
    struct fr input = *value;
    *result = (struct fr){0};
    uint64_t nonzero = 0;
    for (unsigned i = 0; i < 4; ++i) nonzero |= input.d[i];
    if (!nonzero) {
        blue_mod256_wipe(&input, sizeof input);
        return false;
    }
    struct fr inverse = montgomery_one;
    for (int bit = 255; bit >= 0; --bit) {
        blue_fr_mul_ct(&inverse, &inverse, &inverse);
        if ((modulus_minus_two[bit / 64] >> (bit % 64)) & 1u)
            blue_fr_mul_ct(&inverse, &inverse, &input);
    }
    *result = inverse;
    blue_mod256_wipe(&inverse, sizeof inverse);
    blue_mod256_wipe(&input, sizeof input);
    return true;
}

void blue_fr_add_ct(struct fr *result, const struct fr *a,
    const struct fr *b) {
    blue_mod256_add(result->d, a->d, b->d, &fr_field);
}

void blue_fr_sub_ct(struct fr *result, const struct fr *a,
    const struct fr *b) {
    blue_mod256_sub(result->d, a->d, b->d, &fr_field);
}

void blue_fr_neg_ct(struct fr *result, const struct fr *a) {
    const struct fr zero = {0};
    blue_fr_sub_ct(result, &zero, a);
}

void blue_fr_mul_ct(struct fr *result, const struct fr *a,
    const struct fr *b) {
    blue_mod256_mont_mul(result->d, a->d, b->d, &fr_field);
}
