/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#ifndef ZCL_BLUE_SAPLING_EPK_H
#define ZCL_BLUE_SAPLING_EPK_H

#include <stdbool.h>
#include <stdint.h>
#include "blue_jubjub_decode.h"

typedef blue_jubjub_decode_workspace blue_sapling_epk_workspace;

/* Verify epk = [esk] GroupHash("Zcash_gd", diversifier). The outgoing
 * plaintext, note plaintext, and captured transaction output must already
 * have been authenticated by their respective callers. This public-point
 * operation does not authorize a payment or establish the note commitment.
 * Workspace and inputs must not overlap. Workspace is wiped after any
 * non-overlapping call, including failure. */
bool blue_sapling_epk_matches(const uint8_t diversifier[11],
    const uint8_t esk[32], const uint8_t epk[32],
    blue_sapling_epk_workspace *workspace);

#endif
