/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#ifndef ZCL_BLUE_JUBJUB_ARITHMETIC_H
#define ZCL_BLUE_JUBJUB_ARITHMETIC_H

#include "sapling/fr.h"

/* Isolated projective arithmetic for a fixed, trusted Jubjub base point. */
void blue_jub_identity(struct jub_point *result);
void blue_jub_add(struct jub_point *result, const struct jub_point *a,
    const struct jub_point *b);
void blue_jub_double(struct jub_point *result, const struct jub_point *a);

#endif
