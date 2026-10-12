/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: assert separate binary32 rounding in the real aircraft object. */
#include "sky_combat/models/aircraft.h"
#include <float.h>
#include <inttypes.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static_assert(FLT_RADIX == 2 && FLT_MANT_DIG == 24 && sizeof(float) == 4,
              "the aircraft rounding contract requires binary32");

int main(void)
{
    /* 150 * dt rounds to 1 in binary32. Fusing its addition to -1 instead
     * retains 0x32d00000. Call the separately compiled game object: copying
     * its expression here would only test this fixture's compiler flags. */
    volatile float dt = 0x1.b4e81cp-8f;
    aircraft_t aircraft = {.position = {0.0f, 200.0f, 0.0f},
                           .yaw = -1.0f, .speed = AIRCRAFT_BASE_SPEED};
    aircraft_update(&aircraft, 1.0f, 0.0f, dt);
    float fused = fmaf(AIRCRAFT_TURN_RATE, dt, -1.0f);
    uint32_t actual_bits, fused_bits;
    memcpy(&actual_bits, &aircraft.yaw, sizeof(actual_bits));
    memcpy(&fused_bits, &fused, sizeof(fused_bits));
    if (actual_bits != UINT32_C(0) || fused_bits != UINT32_C(0x32d00000)) {
        fprintf(stderr, "skycombat_fp_contract: yaw=%08" PRIx32
                " expected=00000000 fused=%08" PRIx32 " expected=32d00000\n",
                actual_bits, fused_bits);
        return 1;
    }
    puts("skycombat_fp_contract: yaw=00000000 fused=32d00000 PASS");
    return 0;
}
