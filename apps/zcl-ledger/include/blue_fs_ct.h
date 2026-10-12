/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#ifndef ZCL_BLUE_FS_CT_H
#define ZCL_BLUE_FS_CT_H

#include "sapling/fr.h"

#include <stdbool.h>
#include <stdint.h>

/* Isolated raw scalar-field candidate. Inputs must be canonical Fs values. */
void blue_fs_add_ct(struct fs *result, const struct fs *a, const struct fs *b);
void blue_fs_sub_ct(struct fs *result, const struct fs *a, const struct fs *b);
void blue_fs_neg_ct(struct fs *result, const struct fs *a);
void blue_fs_mul_ct(struct fs *result, const struct fs *a, const struct fs *b);
/* Reject source/result overlap before modifying either buffer. */
bool blue_fs_from_bytes_canonical(struct fs *result,
    const uint8_t bytes[32]);
void blue_fs_to_bytes(uint8_t bytes[32], const struct fs *value);

#endif
