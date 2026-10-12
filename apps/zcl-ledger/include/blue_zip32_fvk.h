/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#ifndef ZCL_BLUE_ZIP32_FVK_H
#define ZCL_BLUE_ZIP32_FVK_H

#include "sapling/zip32.h"

#include <stdbool.h>
#include <stdint.h>

/* Project an expanded spending key to its full viewing key. The output
 * must not overlap the input. A rejected overlap leaves both unchanged;
 * other failures clear a non-null output. The caller must erase the viewing
 * key after use because it contains the OVK. */
bool blue_zip32_fvk_from_expsk(struct zip32_fvk *result,
    const struct zip32_expsk *secret);

/* Return the ZIP32 parent fingerprint tag in host integer form.
 * Overlap with the input leaves both unchanged. */
bool blue_zip32_fvk_tag(uint32_t *tag, const struct zip32_fvk *fvk);

#endif
