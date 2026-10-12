/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#ifndef ZCL_BLUE_SAPLING_SPEND_DEVICE_H
#define ZCL_BLUE_SAPLING_SPEND_DEVICE_H

#include "blue_sapling_entropy_device.h"
#include "blue_sapling_spend_auth.h"
#include "blue_zip32_child.h"
#include "blue_zip32_seed_bridge.h"

#include <stdbool.h>
#include <stdint.h>

typedef struct {
    union {
        blue_zip32_seed_workspace seed;
        blue_zip32_workspace child;
    } derivation;
    union {
        struct zip32_xsk master;
        blue_sapling_spend_workspace auth;
    } parent;
    struct zip32_xsk child;
    uint8_t entropy[BLUE_SAPLING_ENTROPY_BYTES];
} blue_sapling_device_spend_workspace;

/* Synthetic-seed fixture only. The scalar multiplier and signer have not
 * passed target side-channel validation; the implementation rejects builds
 * without ZCL_BLUE_SYNTHETIC_SEED_FIXTURE or with the Wallet's BOLOS stack
 * canary build flag. No device app or APDU may call it.
 * Inputs, signature, and workspace must be disjoint. A rejected overlap
 * preserves all buffers; other returned failures erase both outputs.
 * BOLOS exceptions require outer cleanup of both buffers. */
bool blue_sapling_device_spend_sign(uint8_t signature[64],
    blue_sapling_device_spend_workspace *workspace, uint32_t account,
    const uint8_t ar[32], const uint8_t expected_rk[32],
    const uint8_t digest[32]);

#endif
