/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#ifndef ZCL_HOST_CRYPTO_H
#define ZCL_HOST_CRYPTO_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#if !defined(__STDC_VERSION__) || __STDC_VERSION__ < 202311L
#error "ZCL host crypto requires ISO C23"
#endif

bool zcl_host_pubkey_valid(const uint8_t public_key[33]);
bool zcl_host_hash160(const uint8_t public_key[33], uint8_t hash160[20]);
bool zcl_host_verify_signature(void *context,
    const uint8_t public_key[33], const uint8_t digest[32],
    const uint8_t *der, size_t der_length);

#endif
