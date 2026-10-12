/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#ifndef ZCL_BLUE_STORAGE_H
#define ZCL_BLUE_STORAGE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

static inline bool blue_storage_overlaps(const void *left, size_t left_size,
    const void *right, size_t right_size) {
    if (!left || !right || !left_size || !right_size) return false;
    uintptr_t a = (uintptr_t)left, b = (uintptr_t)right;
    return a <= b ? b - a < left_size : a - b < right_size;
}

#endif
