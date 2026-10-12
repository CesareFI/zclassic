/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#ifndef ZCL_BLUE_SAPLING_SPEND_AUTH_H
#define ZCL_BLUE_SAPLING_SPEND_AUTH_H

#include "sapling/fr.h"
#include "sapling/jubjub.h"

#include <stdbool.h>
#include <stdint.h>

typedef union {
    struct {
        struct fs ask, ar, rsk;
    } scalars;
    struct jub_point point;
} blue_sapling_spend_workspace;

/* Sign a reviewed ZIP243 digest with rsk = ask + ar only when the device
 * recomputes the rk embedded in that transaction. Inputs and outputs must
 * not overlap. An overlap fails before writing either output; callers must
 * ignore both outputs on failure. The caller must supply fresh device
 * entropy and a device-verified digest and rk. No APDU or approval route
 * calls this candidate. */
bool blue_sapling_spend_auth_sign(uint8_t signature[64],
    blue_sapling_spend_workspace *workspace, const uint8_t ask[32],
    const uint8_t ar[32], const uint8_t expected_rk[32],
    const uint8_t entropy[80], const uint8_t digest[32]);

#endif
