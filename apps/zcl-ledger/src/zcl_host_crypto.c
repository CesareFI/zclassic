/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "zcl_host_crypto.h"

#include "zripemd/zripemd.h"
#include "zsha256/zsha256.h"

#include <secp256k1.h>

bool zcl_host_pubkey_valid(const uint8_t public_key[33]) {
    if (!public_key || (public_key[0] != 2 && public_key[0] != 3))
        return false;
    secp256k1_context *context =
        secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    if (!context) return false;
    secp256k1_pubkey parsed;
    bool valid = secp256k1_ec_pubkey_parse(context, &parsed,
        public_key, 33) == 1;
    secp256k1_context_destroy(context);
    return valid;
}

bool zcl_host_hash160(const uint8_t public_key[33],
    uint8_t hash160[20]) {
    if (!public_key || !hash160) return false;
    uint8_t digest[32];
    zsha256(public_key, 33, digest);
    zripemd160(digest, sizeof digest, hash160);
    return true;
}

bool zcl_host_verify_signature(void *unused,
    const uint8_t public_key[33], const uint8_t digest[32],
    const uint8_t *der, size_t der_length) {
    (void)unused;
    if (!public_key || !digest || !der ||
        (public_key[0] != 2 && public_key[0] != 3) ||
        der_length < 8 || der_length > 72) return false;
    secp256k1_context *context =
        secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    if (!context) return false;
    secp256k1_pubkey key;
    secp256k1_ecdsa_signature signature;
    bool valid = secp256k1_ec_pubkey_parse(context, &key,
            public_key, 33) == 1 &&
        secp256k1_ecdsa_signature_parse_der(context,
            &signature, der, der_length) == 1 &&
        secp256k1_ecdsa_verify(context, &signature,
            digest, &key) == 1;
    secp256k1_context_destroy(context);
    return valid;
}
