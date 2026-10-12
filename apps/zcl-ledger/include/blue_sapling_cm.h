/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#ifndef ZCL_BLUE_SAPLING_CM_H
#define ZCL_BLUE_SAPLING_CM_H

#include "blue_jubjub_decode.h"

#include <stdbool.h>
#include <stdint.h>

typedef struct {
    blue_jubjub_decode_workspace decode;
    struct jub_point sum, base, term;
    union {
        uint8_t contents[72];
        struct {
            struct fr inverse, x;
        } field;
    } scratch;
} blue_sapling_cm_workspace;

/* Check the note commitment of a decrypted Sapling v1 note against an output
 * captured from the exact transaction. Inputs and workspace must be disjoint.
 * The workspace is wiped after a non-overlapping call. This relation alone
 * does not establish recipient ownership or authorize signing. */
bool blue_sapling_cm_matches(const uint8_t note[564],
    const uint8_t pk_d[32], const uint8_t expected_cm[32],
    blue_sapling_cm_workspace *workspace);

#endif
