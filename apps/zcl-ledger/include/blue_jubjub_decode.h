/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#ifndef ZCL_BLUE_JUBJUB_DECODE_H
#define ZCL_BLUE_JUBJUB_DECODE_H

#include "sapling/fr.h"

typedef struct {
    struct fr y, y2, numerator, denominator, inverse, x2, x;
    struct jub_point point, multiple;
    uint8_t y_bytes[32], x_bytes[32];
} blue_jubjub_decode_workspace;

/* Decode a canonical compressed public Jubjub point and reject small order.
 * Failure clears the result. This does not clear the point's cofactor;
 * callers must apply protocol-specific cofactor rules before key agreement.
 * Runtime depends on public input; do not use for a secret point. The caller
 * owns disjoint result, workspace, and input buffers; workspace is erased. */
bool blue_jubjub_decode_public(struct jub_point *result,
    blue_jubjub_decode_workspace *workspace, const uint8_t encoded[32]);

#endif
