/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#ifndef ZCL_BLUE_JUBJUB_ENCODE_H
#define ZCL_BLUE_JUBJUB_ENCODE_H

#include "sapling/fr.h"

/* Encode a valid projective Jubjub point without the host field backend.
 * The caller must supply a point from trusted group arithmetic. */
bool blue_jubjub_encode(uint8_t out[32], const struct jub_point *point);

#endif
