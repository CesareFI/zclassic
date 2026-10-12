/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#ifndef ZCL_BLUE_PAYMENT_SIMULATE_H
#define ZCL_BLUE_PAYMENT_SIMULATE_H

#include "blue_payment_screen.h"

/* Host-only read-only simulation. Each acknowledgement is a simulated touch.
 * Screens are returned only after the entire replay commitment validates. */
bool blue_payment_simulate(const uint8_t *wire, size_t length,
    uint32_t branch_id,
    blue_payment_screen screens[BLUE_PAYMENT_REVIEW_MAX_OUTPUTS],
    uint32_t *screen_count);

#endif
