/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "blue_jubjub_lowmem.h"
#include "blue_jubjub_arithmetic.h"
#include "blue_storage.h"

#include <stddef.h>

static void select_field(struct fr *dest, const struct fr *source,
    uint64_t mask) {
    volatile uint64_t selected = mask;
    for (size_t i = 0; i < 4; ++i) {
        uint64_t bits = selected;
        dest->d[i] = (dest->d[i] & ~bits) | (source->d[i] & bits);
    }
}

static void select_point(struct jub_point *dest,
    const struct jub_point *source, uint64_t mask) {
    select_field(&dest->x, &source->x, mask);
    select_field(&dest->y, &source->y, mask);
    select_field(&dest->z, &source->z, mask);
    select_field(&dest->t, &source->t, mask);
}

static void wipe(void *memory, size_t length) {
    volatile uint8_t *bytes = memory;
    for (size_t i = 0; i < length; ++i) bytes[i] = 0;
}

static void multiply_distinct(struct jub_point *result,
    const struct jub_point *point, const uint8_t scalar[32]) {
    struct jub_point sum;
    blue_jub_identity(result);
    for (int bit = 255; bit >= 0; --bit) {
        blue_jub_double(result, result);
        blue_jub_add(&sum, result, point);
        uint64_t selected = (scalar[bit / 8] >> (bit % 8)) & 1u;
        select_point(result, &sum, (uint64_t)0 - selected);
    }
    wipe(&sum, sizeof sum);
}

[[gnu::noinline]] static void multiply_alias(struct jub_point *result,
    const uint8_t scalar[32]) {
    struct jub_point input = *result;
    multiply_distinct(result, &input, scalar);
    wipe(&input, sizeof input);
}

bool blue_jubjub_scalar_mul_lowmem(struct jub_point *result,
    const struct jub_point *point, const uint8_t scalar[32]) {
    if (!result || !point || !scalar) return false;
    if (blue_storage_overlaps(result, sizeof *result, scalar, 32) ||
        (result != point && blue_storage_overlaps(result, sizeof *result,
            point, sizeof *point))) return false;
    if (result == point) multiply_alias(result, scalar);
    else multiply_distinct(result, point, scalar);
    return true;
}
