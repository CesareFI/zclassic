/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "os.h"
#include "blue_sapling_entropy_device.h"

#include "blue_mod256.h"

bool blue_sapling_device_entropy(
    uint8_t entropy[BLUE_SAPLING_ENTROPY_BYTES]) {
    if (!entropy) return false;
    blue_mod256_wipe(entropy, BLUE_SAPLING_ENTROPY_BYTES);
    if (!os_global_pin_is_validated()) return false;
    bool valid = cx_rng(entropy, BLUE_SAPLING_ENTROPY_BYTES) == entropy &&
        os_global_pin_is_validated();
    uint8_t nonzero = 0;
    for (unsigned i = 0; i < BLUE_SAPLING_ENTROPY_BYTES; ++i)
        nonzero |= entropy[i];
    if (!valid || !nonzero)
        blue_mod256_wipe(entropy, BLUE_SAPLING_ENTROPY_BYTES);
    return valid && nonzero != 0;
}
