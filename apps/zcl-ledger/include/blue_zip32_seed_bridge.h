/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#ifndef ZCL_BLUE_ZIP32_SEED_BRIDGE_H
#define ZCL_BLUE_ZIP32_SEED_BRIDGE_H

#include "sapling/zip32.h"

#include <stdbool.h>
#include <stdint.h>

typedef union {
    struct {
        uint8_t private_key[32];
        uint8_t chain_code[32];
    } node;
    uint8_t bytes[64];
    uint8_t root[32];
} blue_zip32_seed_workspace;

typedef bool (*blue_zip32_bip32_source)(void *context,
    const uint32_t path[3], uint8_t private_key[32],
    uint8_t chain_code[32]);

/* Map a device-derived hardened BIP32 node into a Ledger-specific ZIP32
 * master. This root differs from the standard ZIP32 root of a wallet seed.
 * The source must enforce device unlock and keep the node out of APDU replies.
 * Result and workspace must not overlap. A rejected overlap leaves both
 * buffers unchanged; all other calls clear a non-null workspace on exit. */
bool blue_zip32_master_from_bip32(struct zip32_xsk *result,
    blue_zip32_seed_workspace *workspace,
    blue_zip32_bip32_source source, void *context);

#endif
