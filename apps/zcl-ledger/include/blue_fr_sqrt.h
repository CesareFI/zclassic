/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#ifndef ZCL_BLUE_FR_SQRT_H
#define ZCL_BLUE_FR_SQRT_H

#include "sapling/fr.h"

/* Public-field Tonelli-Shanks square root for Jubjub point decoding.
 * The input must be a canonical Montgomery field element.
 * Returns false and clears result for a nonsquare or invalid pointer.
 * Runtime depends on the public input; do not use with a secret field value. */
bool blue_fr_sqrt_public(struct fr *result, const struct fr *value);

#endif
