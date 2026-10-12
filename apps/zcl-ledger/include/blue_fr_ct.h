/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#ifndef ZCL_BLUE_FR_CT_H
#define ZCL_BLUE_FR_CT_H

#include "sapling/fr.h"

/* Isolated Cortex-M0/M3 field candidate. Arithmetic inputs must be canonical
 * Montgomery elements. No device key or signing command calls these functions. */
bool blue_fr_from_bytes_canonical(struct fr *result, const uint8_t bytes[32]);
void blue_fr_to_bytes(uint8_t bytes[32], const struct fr *value);
/* Fixed-exponent inversion; timing has not been validated for device secrets. */
bool blue_fr_inverse_fixed(struct fr *result, const struct fr *value);
void blue_fr_add_ct(struct fr *result, const struct fr *a, const struct fr *b);
void blue_fr_sub_ct(struct fr *result, const struct fr *a, const struct fr *b);
void blue_fr_neg_ct(struct fr *result, const struct fr *a);
void blue_fr_mul_ct(struct fr *result, const struct fr *a, const struct fr *b);

#endif
