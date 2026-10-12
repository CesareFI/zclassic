/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#if !defined(ZCL_BLUE_SYNTHETIC_SEED_FIXTURE) || \
    defined(HAVE_BOLOS_APP_STACK_CANARY)
#error "Device-derived Sapling signing awaits target side-channel validation"
#endif

#include "os.h"
#include "blue_sapling_spend_device.h"

#include "blue_mod256.h"
#include "blue_storage.h"
#include "blue_zip32_seed_device.h"

#include <stddef.h>

static bool disjoint(const uint8_t signature[64],
    const blue_sapling_device_spend_workspace *workspace,
    const uint8_t ar[32], const uint8_t expected_rk[32],
    const uint8_t digest[32]) {
    size_t length = workspace ? sizeof *workspace : 0;
    return !blue_storage_overlaps(signature, 64, workspace, length) &&
        !blue_storage_overlaps(signature, 64, ar, 32) &&
        !blue_storage_overlaps(signature, 64, expected_rk, 32) &&
        !blue_storage_overlaps(signature, 64, digest, 32) &&
        !blue_storage_overlaps(workspace, length, ar, 32) &&
        !blue_storage_overlaps(workspace, length, expected_rk, 32) &&
        !blue_storage_overlaps(workspace, length, digest, 32);
}

static bool derive_account(blue_sapling_device_spend_workspace *workspace,
    uint32_t account) {
    bool valid = blue_zip32_device_master(&workspace->parent.master,
        &workspace->derivation.seed);
    if (valid) valid = os_global_pin_is_validated();
    if (valid) valid = blue_zip32_derive_child(&workspace->child,
        &workspace->parent.master, account | ZIP32_HARDENED_KEY_LIMIT,
        &workspace->derivation.child);
    if (valid) valid = os_global_pin_is_validated();
    blue_mod256_wipe(&workspace->parent, sizeof workspace->parent);
    return valid;
}

static bool request_ready(const uint8_t signature[64], uint32_t account,
    const uint8_t ar[32], const uint8_t expected_rk[32],
    const uint8_t digest[32]) {
    return signature && ar && expected_rk && digest &&
        account < ZIP32_HARDENED_KEY_LIMIT &&
        os_global_pin_is_validated();
}

bool blue_sapling_device_spend_sign(uint8_t signature[64],
    blue_sapling_device_spend_workspace *workspace, uint32_t account,
    const uint8_t ar[32], const uint8_t expected_rk[32],
    const uint8_t digest[32]) {
    if (!disjoint(signature, workspace, ar, expected_rk, digest))
        return false;
    if (signature) blue_mod256_wipe(signature, 64);
    if (!workspace) return false;
    blue_mod256_wipe(workspace, sizeof *workspace);
    bool valid = request_ready(signature, account, ar, expected_rk,
        digest);
    if (valid) valid = derive_account(workspace, account);
    if (valid) valid = blue_sapling_device_entropy(workspace->entropy);
    if (valid) valid = os_global_pin_is_validated();
    if (valid) valid = blue_sapling_spend_auth_sign(signature,
        &workspace->parent.auth, workspace->child.expsk.ask,
        ar, expected_rk, workspace->entropy, digest);
    if (valid) valid = os_global_pin_is_validated();
    if (!valid && signature) blue_mod256_wipe(signature, 64);
    blue_mod256_wipe(workspace, sizeof *workspace);
    return valid;
}
