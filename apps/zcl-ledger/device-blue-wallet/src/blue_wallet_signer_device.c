/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "os.h"
#include "blue_wallet_signer_device.h"

#include <stdint.h>
#include <string.h>

typedef struct {
    uint8_t raw[32], chain[32];
    cx_ecfp_private_key_t key;
} private_material;

static private_material secret;
static cx_ecfp_public_key_t public_point;

static void wipe(void *memory, size_t length) {
    volatile uint8_t *bytes = memory;
    for (size_t i = 0; i < length; ++i) bytes[i] = 0;
}

static bool overlaps(const void *left, size_t left_size,
    const void *right, size_t right_size) {
    if (!left || !right) return false;
    uintptr_t a = (uintptr_t)left, b = (uintptr_t)right;
    return a <= b ? b - a < left_size : a - b < right_size;
}

static bool signer_storage_disjoint(const blue_payment_owned_hashes *owned,
    const uint8_t *digest, const uint8_t *public_key,
    const uint8_t *signature, const size_t *signature_length) {
    return !overlaps(digest, 32, public_key, 33) &&
        !overlaps(digest, 32, signature, BLUE_ECDSA_DER_MAX) &&
        !overlaps(digest, 32, signature_length, sizeof *signature_length) &&
        !overlaps(owned, sizeof *owned, public_key, 33) &&
        !overlaps(owned, sizeof *owned, signature, BLUE_ECDSA_DER_MAX) &&
        !overlaps(owned, sizeof *owned, signature_length,
            sizeof *signature_length) &&
        !overlaps(public_key, 33, signature, BLUE_ECDSA_DER_MAX) &&
        !overlaps(public_key, 33, signature_length,
            sizeof *signature_length) &&
        !overlaps(signature, BLUE_ECDSA_DER_MAX, signature_length,
            sizeof *signature_length);
}

void blue_wallet_signer_wipe(void) {
    wipe(&secret, sizeof secret);
    wipe(&public_point, sizeof public_point);
}

static bool request_valid(uint8_t path, const uint8_t *digest,
    const uint8_t *public_key, const uint8_t *signature,
    const blue_payment_owned_hashes *owned) {
    return digest && public_key && signature && owned &&
        (path == BLUE_PAYMENT_INPUT_EXTERNAL ||
         path == BLUE_PAYMENT_INPUT_INTERNAL) &&
        os_global_pin_is_validated();
}

static bool prepare_signer(const blue_payment_owned_hashes *owned,
    uint8_t path, const uint8_t digest[32], uint8_t public_key[33],
    uint8_t signature[BLUE_ECDSA_DER_MAX], size_t *signature_length) {
    blue_wallet_signer_wipe();
    if (!signer_storage_disjoint(owned, digest, public_key, signature,
            signature_length)) return false;
    if (public_key) memset(public_key, 0, 33);
    if (signature) memset(signature, 0, BLUE_ECDSA_DER_MAX);
    if (!signature_length) return false;
    *signature_length = 0;
    return request_valid(path, digest, public_key, signature, owned);
}

static bool derive_pair(uint8_t path) {
    const unsigned int bip32_path[5] = {
        0x8000002c, 0x80000093, 0x80000000,
        path == BLUE_PAYMENT_INPUT_EXTERNAL ? 0u : 1u, 0u
    };
    os_perso_derive_node_bip32(CX_CURVE_256K1, bip32_path, 5,
        secret.raw, secret.chain);
    int initialized = cx_ecfp_init_private_key(CX_CURVE_256K1, secret.raw, 32,
        &secret.key);
    wipe(secret.raw, sizeof secret.raw);
    wipe(secret.chain, sizeof secret.chain);
    return initialized >= 0 && secret.key.curve == CX_CURVE_256K1 &&
        secret.key.d_len == 32 &&
        cx_ecfp_generate_pair(CX_CURVE_256K1, &public_point,
                              &secret.key, 1) == 0 &&
        public_point.W_len == 65 && public_point.W[0] == 4;
}

bool blue_wallet_sign_digest(void *context, uint8_t path,
    const uint8_t digest[32], uint8_t public_key[33],
    uint8_t signature[BLUE_ECDSA_DER_MAX], size_t *signature_length) {
    const blue_payment_owned_hashes *owned = context;
    if (!prepare_signer(owned, path, digest, public_key, signature,
            signature_length)) return false;
    bool valid = derive_pair(path) && os_global_pin_is_validated();
    if (valid) {
        public_key[0] = (uint8_t)(2u | (public_point.W[64] & 1u));
        memcpy(public_key + 1, public_point.W + 1, 32);
        uint8_t hash160[20] = {0};
        const uint8_t *expected = path == BLUE_PAYMENT_INPUT_EXTERNAL ?
            owned->external : owned->internal;
        valid = blue_wallet_public_hash160(public_key, hash160) &&
            memcmp(hash160, expected, sizeof hash160) == 0;
        wipe(hash160, sizeof hash160);
    }
    if (valid && os_global_pin_is_validated()) {
        unsigned int info = 0;
        int count = (cx_ecdsa_sign)(&secret.key, CX_RND_RFC6979,
            CX_SHA256, digest, 32, signature, BLUE_ECDSA_DER_MAX, &info);
        valid = count >= 8 && count <= BLUE_ECDSA_DER_MAX &&
            os_global_pin_is_validated();
        if (valid) *signature_length = (size_t)count;
    } else valid = false;
    blue_wallet_signer_wipe();
    if (!valid) {
        *signature_length = 0;
        memset(public_key, 0, 33);
        memset(signature, 0, BLUE_ECDSA_DER_MAX);
    }
    return valid;
}
