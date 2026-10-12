/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "os.h"
#include "blue_zip32_seed_device.h"

#include <stddef.h>

static bool derive_node(void *context, const uint32_t path[3],
    uint8_t private_key[32], uint8_t chain_code[32]) {
    (void)context;
    if (!os_global_pin_is_validated()) return false;
    unsigned int device_path[3] = {path[0], path[1], path[2]};
    os_perso_derive_node_bip32(CX_CURVE_256K1, device_path, 3,
        private_key, chain_code);
    return os_global_pin_is_validated();
}

bool blue_zip32_device_master(struct zip32_xsk *result,
    blue_zip32_seed_workspace *workspace) {
    return blue_zip32_master_from_bip32(result, workspace,
        derive_node, NULL);
}
