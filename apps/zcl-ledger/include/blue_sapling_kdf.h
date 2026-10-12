/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#ifndef BLUE_SAPLING_KDF_H
#define BLUE_SAPLING_KDF_H

#include "zcl_zip243.h"

/* Derive a Sapling note cipher key from a supplied DH result and epk.
 * A key overlapping an input, hasher descriptor, or context base is
 * rejected before any write. Other failures erase the key. The caller
 * must keep the entire hash context disjoint from inputs and output,
 * verify the output description, and erase the key and context after use. */
bool blue_sapling_kdf(uint8_t key[32], const uint8_t dh[32],
    const uint8_t epk[32], const zcl_zip243_hasher *hasher);

#endif
