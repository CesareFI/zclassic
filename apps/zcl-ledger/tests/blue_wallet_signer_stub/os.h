/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#ifndef ZCL_BLUE_WALLET_SIGNER_TEST_OS_H
#define ZCL_BLUE_WALLET_SIGNER_TEST_OS_H

#include <stdint.h>

enum { CX_CURVE_256K1 = 1, CX_RND_RFC6979 = 2, CX_SHA256 = 3 };

typedef struct {
    unsigned curve, d_len;
    uint8_t d[32];
} cx_ecfp_private_key_t;

typedef struct {
    unsigned curve, W_len;
    uint8_t W[65];
} cx_ecfp_public_key_t;

int os_global_pin_is_validated(void);
void os_perso_derive_node_bip32(unsigned curve, const unsigned int *path,
    unsigned length, uint8_t raw[32], uint8_t chain[32]);
int cx_ecfp_init_private_key(unsigned curve, const uint8_t raw[32],
    unsigned length, cx_ecfp_private_key_t *key);
int cx_ecfp_generate_pair(unsigned curve, cx_ecfp_public_key_t *public_key,
    cx_ecfp_private_key_t *private_key, int keepprivate);
int cx_ecdsa_sign(const cx_ecfp_private_key_t *private_key, int mode,
    int hash_id, const uint8_t *digest, unsigned digest_length,
    uint8_t *signature, unsigned signature_capacity, unsigned *info);

#endif
