/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#ifndef ZCL_BLUE_ZIP32_MASTER_H
#define ZCL_BLUE_ZIP32_MASTER_H

#include "sapling/zip32.h"

#include <stdbool.h>
#include <stdint.h>

/* Derive the ZIP32 master expanded spending key from a 32-byte seed.
 * The caller owns and must erase the seed and result. No device seed source
 * or account path is selected here. Failure clears a disjoint non-null
 * result; overlap with seed is rejected before either buffer changes. */
bool blue_zip32_master_expsk(struct zip32_expsk *result,
    const uint8_t seed[32]);

/* Derive a complete ZIP32 master record for later account derivation.
 * The caller owns and must erase the result. Failure clears a disjoint
 * result; overlap with seed is rejected before either buffer changes. */
bool blue_zip32_master_xsk(struct zip32_xsk *result,
    const uint8_t seed[32]);

#endif
