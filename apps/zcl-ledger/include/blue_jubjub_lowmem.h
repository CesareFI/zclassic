/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#ifndef ZCL_BLUE_JUBJUB_LOWMEM_H
#define ZCL_BLUE_JUBJUB_LOWMEM_H

#include "sapling/fr.h"

/* Fixed-iteration scalar multiplication candidate for a memory-limited
 * signer. It has no precomputed point table. Its portable field path lacks
 * target timing validation and must not process secret device scalars.
 * The result may equal the input point, but any other result/point overlap
 * or result/scalar overlap is rejected before writes. It is not connected
 * to a device key or Sapling signing command. */
bool blue_jubjub_scalar_mul_lowmem(struct jub_point *result,
    const struct jub_point *point, const uint8_t scalar[32]);

#endif
