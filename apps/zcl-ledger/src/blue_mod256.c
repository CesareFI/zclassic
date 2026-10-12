/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "blue_mod256.h"

void blue_mod256_wipe(void *memory, size_t length) {
    volatile uint8_t *bytes = memory;
    for (size_t i = 0; i < length; ++i) bytes[i] = 0;
}

static void unpack(uint32_t out[8], const uint64_t input[4]) {
    for (size_t i = 0; i < 4; ++i) {
        out[2 * i] = (uint32_t)input[i];
        out[2 * i + 1] = (uint32_t)(input[i] >> 32);
    }
}

static void pack(uint64_t out[4], const uint32_t input[8]) {
    for (size_t i = 0; i < 4; ++i) {
        out[i] = (uint64_t)input[2 * i] |
            ((uint64_t)input[2 * i + 1] << 32);
    }
}

static uint32_t subtract(uint32_t out[8], const uint32_t a[8],
    const uint32_t b[8]) {
    uint32_t borrow = 0;
    for (size_t i = 0; i < 8; ++i) {
        uint64_t difference = (uint64_t)a[i] - b[i] - borrow;
        out[i] = (uint32_t)difference;
        borrow = (uint32_t)(difference >> 63);
    }
    return borrow;
}

static uint32_t add(uint32_t out[8], const uint32_t a[8],
    const uint32_t b[8]) {
    uint64_t carry = 0;
    for (size_t i = 0; i < 8; ++i) {
        uint64_t sum = (uint64_t)a[i] + b[i] + carry;
        out[i] = (uint32_t)sum;
        carry = sum >> 32;
    }
    return (uint32_t)carry;
}

static void select_limbs(uint32_t out[8], const uint32_t chosen[8],
    const uint32_t other[8], uint32_t choose) {
    volatile uint32_t mask = 0u - choose;
    for (size_t i = 0; i < 8; ++i) {
        uint32_t bits = mask;
        out[i] = (chosen[i] & bits) | (other[i] & ~bits);
    }
}

void blue_mod256_add(uint64_t result[4], const uint64_t a[4],
    const uint64_t b[4], const struct blue_mod256 *field) {
    uint32_t x[8], y[8], sum[8], reduced[8];
    unpack(x, a);
    unpack(y, b);
    uint32_t carry = add(sum, x, y);
    uint32_t borrow = subtract(reduced, sum, field->modulus);
    select_limbs(sum, reduced, sum, carry | (borrow ^ 1u));
    pack(result, sum);
    blue_mod256_wipe(x, sizeof x);
    blue_mod256_wipe(y, sizeof y);
    blue_mod256_wipe(sum, sizeof sum);
    blue_mod256_wipe(reduced, sizeof reduced);
}

void blue_mod256_sub(uint64_t result[4], const uint64_t a[4],
    const uint64_t b[4], const struct blue_mod256 *field) {
    uint32_t x[8], y[8], difference[8], adjusted[8];
    unpack(x, a);
    unpack(y, b);
    uint32_t borrow = subtract(difference, x, y);
    add(adjusted, difference, field->modulus);
    select_limbs(difference, adjusted, difference, borrow);
    pack(result, difference);
    blue_mod256_wipe(x, sizeof x);
    blue_mod256_wipe(y, sizeof y);
    blue_mod256_wipe(difference, sizeof difference);
    blue_mod256_wipe(adjusted, sizeof adjusted);
}

static void montgomery_round(uint64_t t[9], const uint32_t a[8],
    uint32_t multiplier, const struct blue_mod256 *field) {
    uint64_t carry = 0;
    for (size_t j = 0; j < 8; ++j) {
        uint64_t product = (uint64_t)a[j] * multiplier + t[j] + carry;
        t[j] = (uint32_t)product;
        carry = product >> 32;
    }
    t[8] += carry;
    uint32_t reduction = (uint32_t)t[0] * field->negative_inverse;
    carry = 0;
    for (size_t j = 0; j < 8; ++j) {
        uint64_t product = (uint64_t)reduction * field->modulus[j] +
            t[j] + carry;
        if (j != 0) t[j - 1] = (uint32_t)product;
        carry = product >> 32;
    }
    uint64_t final = t[8] + carry;
    t[7] = (uint32_t)final;
    t[8] = final >> 32;
}

void blue_mod256_mont_mul(uint64_t result[4], const uint64_t a[4],
    const uint64_t b[4], const struct blue_mod256 *field) {
    uint32_t x[8], y[8], raw[8], reduced[8];
    uint64_t t[9] = {0};
    unpack(x, a);
    unpack(y, b);
    for (size_t i = 0; i < 8; ++i)
        montgomery_round(t, x, y[i], field);
    for (size_t i = 0; i < 8; ++i) raw[i] = (uint32_t)t[i];
    uint32_t borrow = subtract(reduced, raw, field->modulus);
    select_limbs(raw, reduced, raw,
        (uint32_t)t[8] | (borrow ^ 1u));
    pack(result, raw);
    blue_mod256_wipe(x, sizeof x);
    blue_mod256_wipe(y, sizeof y);
    blue_mod256_wipe(raw, sizeof raw);
    blue_mod256_wipe(reduced, sizeof reduced);
    blue_mod256_wipe(t, sizeof t);
}
