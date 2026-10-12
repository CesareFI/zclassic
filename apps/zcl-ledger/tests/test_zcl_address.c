/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "zcl_address.h"
#include "zcl_base58.h"

#undef NDEBUG
#include <assert.h>
#include <string.h>

int main(void) {
    const uint8_t leading_zeros[] = {0, 0, 1};
    char base58[ZCL_ADDRESS_SIZE];
    assert(zcl_base58_encode(leading_zeros, sizeof leading_zeros,
                             base58, sizeof base58) == 0);
    assert(strcmp(base58, "112") == 0);
    assert(zcl_base58_encode(leading_zeros, sizeof leading_zeros,
                             base58, 3) < 0);
    assert(zcl_base58_encode(NULL, sizeof leading_zeros,
                             base58, sizeof base58) < 0);
    const uint8_t generator[ZCL_COMPRESSED_PUBKEY_SIZE] = {
        0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb,
        0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b,
        0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28,
        0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98
    };
    char address[ZCL_ADDRESS_SIZE];
    assert(zcl_address_from_pubkey(generator, address) == 0);
    assert(strcmp(address, "t1UYsZVJkLPeMjxEtACvSxfWuNmddpWfxzs") == 0);
    static const uint8_t foundation_script_hash[ZCL_HASH160_SIZE] = {
        0x7d, 0x46, 0xa7, 0x30, 0xd3, 0x1f, 0x97, 0xb1,
        0x93, 0x0d, 0x33, 0x68, 0xa9, 0x67, 0xc3, 0x09,
        0xbd, 0x4d, 0x13, 0x6a
    };
    assert(zcl_address_from_hash160(foundation_script_hash, true,
                                    address) == 0);
    assert(strcmp(address, "t3Vz22vK5z2LcKEdg16Yv4FFneEL1zg9ojd") == 0);
    assert(zcl_address_from_hash160(NULL, true, address) < 0);
    assert(zcl_address_from_hash160(foundation_script_hash, true, NULL) < 0);
    uint8_t negative_generator[ZCL_COMPRESSED_PUBKEY_SIZE];
    memcpy(negative_generator, generator, sizeof negative_generator);
    negative_generator[0] = 3;
    assert(zcl_address_from_pubkey(negative_generator, address) == 0);
    assert(strcmp(address, "t1ZiwD6uYW8ku8DSCM4f11BwsDateqtG7yz") == 0);
    uint8_t invalid[ZCL_COMPRESSED_PUBKEY_SIZE] = {0};
    assert(zcl_address_from_pubkey(invalid, address) < 0);
    memcpy(invalid, generator, sizeof invalid);
    invalid[0] = 4;
    assert(zcl_address_from_pubkey(invalid, address) < 0);
    memset(invalid + 1, 0xff, sizeof invalid - 1);
    invalid[0] = 2;
    assert(zcl_address_from_pubkey(invalid, address) < 0);
    assert(zcl_address_from_pubkey(NULL, address) < 0);
    assert(zcl_address_from_pubkey(generator, NULL) < 0);
    return 0;
}
