/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#ifndef ZCL_BLUE_SAPLING_OCK_H
#define ZCL_BLUE_SAPLING_OCK_H

#include "zcl_zip243.h"

/* Derive a Sapling outgoing cipher key. A key overlapping an input, hasher
 * descriptor, or context base is rejected before any write. Other failures
 * erase the key. The caller must keep the entire hash context disjoint from
 * inputs and output, and erase the key and context after use. */
bool blue_sapling_ock(uint8_t key[32], const uint8_t ovk[32],
    const uint8_t cv[32], const uint8_t cm[32], const uint8_t epk[32],
    const zcl_zip243_hasher *hasher);

#endif
