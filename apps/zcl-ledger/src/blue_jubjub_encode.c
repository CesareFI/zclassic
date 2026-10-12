/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "blue_jubjub_encode.h"
#include "blue_fr_ct.h"

#include <stddef.h>
#include <string.h>

static void wipe(void *memory, size_t length) {
    volatile uint8_t *bytes = memory;
    for (size_t i = 0; i < length; ++i) bytes[i] = 0;
}

static bool field_nonzero(const struct fr *value) {
    uint64_t combined = 0;
    for (unsigned i = 0; i < 4; ++i) combined |= value->d[i];
    return combined != 0;
}

bool blue_jubjub_encode(uint8_t out[32], const struct jub_point *point) {
    if (!out || !point || !field_nonzero(&point->z)) return false;
    struct fr inverse, x, y;
    uint8_t encoded[32], x_bytes[32];
    if (!blue_fr_inverse_fixed(&inverse, &point->z)) return false;
    blue_fr_mul_ct(&x, &point->x, &inverse);
    blue_fr_mul_ct(&y, &point->y, &inverse);
    blue_fr_to_bytes(encoded, &y);
    blue_fr_to_bytes(x_bytes, &x);
    encoded[31] |= (uint8_t)((x_bytes[0] & 1u) << 7);
    memcpy(out, encoded, 32);
    wipe(&inverse, sizeof inverse);
    wipe(&x, sizeof x);
    wipe(&y, sizeof y);
    wipe(encoded, sizeof encoded);
    wipe(x_bytes, sizeof x_bytes);
    return true;
}
