/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#ifndef ZCL_BLUE_SAPLING_GROUP_HASH_H
#define ZCL_BLUE_SAPLING_GROUP_HASH_H

#include "blue_jubjub_decode.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Derive a public Jubjub point using Sapling GroupHash. A hash that is not a
 * nonidentity curve point returns false. Inputs, output, and workspace must
 * be disjoint; the workspace is erased after each attempt. */
bool blue_sapling_group_hash(struct jub_point *point,
    blue_jubjub_decode_workspace *workspace,
    const uint8_t personal[8], const uint8_t *tag, size_t tag_len);

/* Append a counter byte to a tag of at most four bytes and try all values. */
bool blue_sapling_find_group_hash(struct jub_point *point,
    blue_jubjub_decode_workspace *workspace,
    const uint8_t personal[8], const uint8_t *tag, size_t tag_len);

#endif
