/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#ifndef ZCL_LEDGER_ADDRESS_H
#define ZCL_LEDGER_ADDRESS_H

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

#if !defined(__STDC_VERSION__) || __STDC_VERSION__ < 202311L
#error "The ZCL address codec requires ISO C23"
#endif

enum { ZCL_COMPRESSED_PUBKEY_SIZE = 33, ZCL_HASH160_SIZE = 20,
       ZCL_ADDRESS_SIZE = 64 };

/* Mainnet transparent address from a validated 20-byte script or key hash. */
int zcl_address_from_hash160(const uint8_t hash[ZCL_HASH160_SIZE],
                              bool script_hash,
                              char address[ZCL_ADDRESS_SIZE]);

/* Mainnet transparent P2PKH address; rejects off-curve public keys. */
int zcl_address_from_pubkey(const uint8_t pubkey[ZCL_COMPRESSED_PUBKEY_SIZE],
                            char address[ZCL_ADDRESS_SIZE]);

#endif
