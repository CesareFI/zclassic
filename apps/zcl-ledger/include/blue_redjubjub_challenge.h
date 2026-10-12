/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#ifndef ZCL_BLUE_REDJUBJUB_CHALLENGE_H
#define ZCL_BLUE_REDJUBJUB_CHALLENGE_H

#include <stdbool.h>
#include <stdint.h>

/* RedJubjub H*(Rbar || vkbar || 32-byte transaction digest). */
bool blue_redjubjub_challenge(uint8_t result[32],
    const uint8_t rbar[32], const uint8_t vkbar[32],
    const uint8_t transaction_digest[32]);

#endif
