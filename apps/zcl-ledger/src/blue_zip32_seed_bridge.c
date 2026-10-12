/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "blue_zip32_seed_bridge.h"

#include "blue_mod256.h"
#include "blue_storage.h"
#include "blue_zip32_master.h"
#include "crypto/blake2b.h"

#include <stddef.h>

static bool root_from_node(uint8_t root[32], const uint8_t node[64]) {
    static const uint8_t personal[16] = {
        'Z','2','3','B','l','u','e','S','a','p','l','i','n','g','V','1'
    };
    struct blake2b_ctx hash = {0};
    bool valid = blake2b_init_salt_personal(&hash, 32,
        NULL, 0, NULL, personal) == 0 &&
        blake2b_update(&hash, node, 64) == 0 &&
        blake2b_final(&hash, root, 32) == 0;
    blue_mod256_wipe(&hash, sizeof hash);
    return valid;
}

bool blue_zip32_master_from_bip32(struct zip32_xsk *result,
    blue_zip32_seed_workspace *workspace,
    blue_zip32_bip32_source source, void *context) {
    if (!result) {
        if (workspace) blue_mod256_wipe(workspace, sizeof *workspace);
        return false;
    }
    if (blue_storage_overlaps(result, sizeof *result,
            workspace, workspace ? sizeof *workspace : 0))
        return false;
    if (!workspace || !source) {
        blue_mod256_wipe(result, sizeof *result);
        return false;
    }
    static const uint32_t path[3] = {
        0x80000020u, 0x80000093u, 0x80000000u
    };
    blue_mod256_wipe(workspace, sizeof *workspace);
    bool valid = source(context, path, workspace->node.private_key,
        workspace->node.chain_code);
    if (valid) valid = root_from_node(workspace->root, workspace->bytes);
    if (valid) valid = blue_zip32_master_xsk(result, workspace->root);
    if (!valid) blue_mod256_wipe(result, sizeof *result);
    blue_mod256_wipe(workspace, sizeof *workspace);
    return valid;
}
