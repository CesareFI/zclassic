/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#ifndef ZCL_BLUE_MOD256_H
#define ZCL_BLUE_MOD256_H

#include <stddef.h>
#include <stdint.h>

struct blue_mod256 {
    uint32_t modulus[8];
    uint32_t negative_inverse;
};

void blue_mod256_add(uint64_t result[4], const uint64_t a[4],
    const uint64_t b[4], const struct blue_mod256 *field);
void blue_mod256_sub(uint64_t result[4], const uint64_t a[4],
    const uint64_t b[4], const struct blue_mod256 *field);
void blue_mod256_mont_mul(uint64_t result[4], const uint64_t a[4],
    const uint64_t b[4], const struct blue_mod256 *field);
void blue_mod256_wipe(void *memory, size_t length);

#endif
