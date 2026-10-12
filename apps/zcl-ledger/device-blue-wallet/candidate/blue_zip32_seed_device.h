/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#ifndef ZCL_BLUE_ZIP32_SEED_DEVICE_H
#define ZCL_BLUE_ZIP32_SEED_DEVICE_H

#include "blue_zip32_seed_bridge.h"

/* Derive a Ledger-specific Sapling root with Blue PIN validation before and
 * after BOLOS key derivation. A late PIN loss clears the result and scratch.
 * The caller must clear result and workspace on a BOLOS exception. */
bool blue_zip32_device_master(struct zip32_xsk *result,
    blue_zip32_seed_workspace *workspace);

#endif
