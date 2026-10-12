/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#ifndef ZCL_BLUE_ZIP32_CHILD_H
#define ZCL_BLUE_ZIP32_CHILD_H

#include "sapling/zip32.h"

#include <stdbool.h>
#include <stdint.h>

typedef union {
    struct zip32_fvk fvk;
    uint8_t root[64];
} blue_zip32_workspace;

/* Derive one ZIP32 child from a locally held parent. The full viewing key
 * is recomputed from the parent secret, never supplied by the host.
 * Child, parent, and scratch must not overlap. A rejected overlap preserves
 * every buffer. Calls with a non-null child and disjoint buffers clear
 * scratch on exit; other rejected requests clear the child output. */
bool blue_zip32_derive_child(struct zip32_xsk *child,
    const struct zip32_xsk *parent, uint32_t index,
    blue_zip32_workspace *scratch);

#endif
