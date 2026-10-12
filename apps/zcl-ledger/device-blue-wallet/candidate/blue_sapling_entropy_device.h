/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#ifndef ZCL_BLUE_SAPLING_ENTROPY_DEVICE_H
#define ZCL_BLUE_SAPLING_ENTROPY_DEVICE_H

#include <stdbool.h>
#include <stdint.h>

enum { BLUE_SAPLING_ENTROPY_BYTES = 80 };

/* Fill a caller-owned buffer from the Blue CSPRNG after PIN checks.
 * Any returned failure clears the buffer. The caller must clear it after
 * use and on a BOLOS exception. This adapter grants no signing authority. */
bool blue_sapling_device_entropy(
    uint8_t entropy[BLUE_SAPLING_ENTROPY_BYTES]);

#endif
