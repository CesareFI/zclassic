/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "zcl_address.h"
#include "zcl_base58.h"
#include "zcl_host_crypto.h"
#include "zsha256/zsha256.h"

#include <string.h>

int zcl_address_from_hash160(const uint8_t hash[ZCL_HASH160_SIZE],
                              bool script_hash,
                              char address[ZCL_ADDRESS_SIZE]) {
    if (!hash || !address) return -1;
    uint8_t digest[32], checksum[32];
    uint8_t payload[26];
    payload[0] = 0x1c;
    payload[1] = script_hash ? 0xbd : 0xb8;
    memcpy(payload + 2, hash, ZCL_HASH160_SIZE);
    zsha256(payload, 22, digest);
    zsha256(digest, sizeof digest, checksum);
    memcpy(payload + 22, checksum, 4);
    return zcl_base58_encode(payload, sizeof payload, address,
                             ZCL_ADDRESS_SIZE);
}

int zcl_address_from_pubkey(const uint8_t pubkey[ZCL_COMPRESSED_PUBKEY_SIZE],
                            char address[ZCL_ADDRESS_SIZE]) {
    if (!pubkey || !address || !zcl_host_pubkey_valid(pubkey)) return -1;
    uint8_t hash[ZCL_HASH160_SIZE];
    if (!zcl_host_hash160(pubkey, hash)) return -1;
    return zcl_address_from_hash160(hash, false, address);
}
