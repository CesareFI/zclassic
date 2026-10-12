/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "os.h"
#include "blue_payment_sign.h"

#undef NDEBUG
#include <assert.h>
#include <stdbool.h>
#include <string.h>

static bool pin_valid = true, fail_init_status, fail_pair, fail_sign, fail_hash, bad_public,
    bad_sign_length, drop_pin_pair, drop_pin_hash, drop_pin_sign;
static unsigned derive_calls, sign_calls, last_path[5];
static blue_payment_owned_hashes owned;

int os_global_pin_is_validated(void) { return pin_valid; }

void os_perso_derive_node_bip32(unsigned curve, const unsigned int *path,
    unsigned length, uint8_t raw[32], uint8_t chain[32]) {
    assert(curve == CX_CURVE_256K1 && length == 5);
    memcpy(last_path, path, sizeof last_path);
    ++derive_calls;
    memset(raw, 0x42, 32);
    memset(chain, 0x24, 32);
}

int cx_ecfp_init_private_key(unsigned curve, const uint8_t raw[32],
    unsigned length, cx_ecfp_private_key_t *key) {
    assert(curve == CX_CURVE_256K1 && length == 32);
    key->curve = curve;
    key->d_len = length;
    memcpy(key->d, raw, length);
    return fail_init_status ? -1 : 32;
}

int cx_ecfp_generate_pair(unsigned curve, cx_ecfp_public_key_t *public_key,
    cx_ecfp_private_key_t *private_key, int keepprivate) {
    assert(curve == CX_CURVE_256K1 && private_key->d_len == 32);
    assert(keepprivate == 1);
    if (fail_pair) return -1;
    public_key->curve = curve;
    public_key->W_len = 65;
    public_key->W[0] = 4;
    if (bad_public) public_key->W[0] = 3;
    memset(public_key->W + 1, last_path[3] ? 0x32 : 0x31, 64);
    public_key->W[64] = 1;
    if (drop_pin_pair) pin_valid = false;
    return 0;
}

int cx_ecdsa_sign(const cx_ecfp_private_key_t *private_key, int mode,
    int hash_id, const uint8_t *digest, unsigned digest_length,
    uint8_t *signature, unsigned signature_capacity, unsigned *info) {
    assert(private_key->d_len == 32 && mode == CX_RND_RFC6979);
    assert(hash_id == CX_SHA256 && digest_length == 32);
    assert(digest[0] == 0xa5 && signature_capacity == BLUE_ECDSA_DER_MAX);
    ++sign_calls;
    if (fail_sign) return 0;
    if (bad_sign_length) return BLUE_ECDSA_DER_MAX + 1;
    static const uint8_t der[] = {
        0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01
    };
    memcpy(signature, der, sizeof der);
    *info = 0;
    if (drop_pin_sign) pin_valid = false;
    return sizeof der;
}

bool blue_wallet_public_hash160(const uint8_t compressed[33],
    uint8_t hash160[20]) {
    if (fail_hash || (compressed[1] != 0x31 && compressed[1] != 0x32))
        return false;
    memset(hash160, compressed[1] == 0x31 ? 0x11 : 0x22, 20);
    if (drop_pin_hash) pin_valid = false;
    return true;
}

#include "../device-blue-wallet/src/blue_wallet_signer_device.c"

static void expect_wiped(void) {
    const uint8_t *bytes = (const uint8_t *)&secret;
    for (size_t i = 0; i < sizeof secret; ++i) assert(bytes[i] == 0);
    bytes = (const uint8_t *)&public_point;
    for (size_t i = 0; i < sizeof public_point; ++i)
        assert(bytes[i] == 0);
}

static void test_paths(void) {
    uint8_t digest[32] = {0xa5}, public_key[33], signature[72];
    size_t length = 0;
    assert(blue_wallet_sign_digest(&owned, BLUE_PAYMENT_INPUT_EXTERNAL,
        digest, public_key, signature, &length));
    assert(length == 8 && public_key[0] == 3);
    assert(last_path[0] == 0x8000002c && last_path[1] == 0x80000093);
    assert(last_path[2] == 0x80000000 && last_path[3] == 0 &&
           last_path[4] == 0);
    expect_wiped();
    assert(blue_wallet_sign_digest(&owned, BLUE_PAYMENT_INPUT_INTERNAL,
        digest, public_key, signature, &length));
    assert(last_path[3] == 1 && derive_calls == 2 && sign_calls == 2);
    expect_wiped();
}

static void test_fail_closed(void) {
    uint8_t digest[32] = {0xa5}, public_key[33], signature[72];
    size_t length = 99;
    memset(public_key, 0xcc, sizeof public_key);
    memset(signature, 0xcc, sizeof signature);
    pin_valid = false;
    assert(!blue_wallet_sign_digest(&owned, BLUE_PAYMENT_INPUT_EXTERNAL,
        digest, public_key, signature, &length));
    assert(length == 0 && derive_calls == 2);
    for (size_t i = 0; i < sizeof public_key; ++i)
        assert(public_key[i] == 0);
    for (size_t i = 0; i < sizeof signature; ++i)
        assert(signature[i] == 0);
    pin_valid = true;
    assert(!blue_wallet_sign_digest(&owned, 3, digest,
        public_key, signature, &length));
    assert(derive_calls == 2);
    fail_pair = true;
    assert(!blue_wallet_sign_digest(&owned, BLUE_PAYMENT_INPUT_EXTERNAL,
        digest, public_key, signature, &length));
    assert(length == 0 && sign_calls == 2);
    expect_wiped();
    fail_pair = false;
    fail_sign = true;
    assert(!blue_wallet_sign_digest(&owned, BLUE_PAYMENT_INPUT_EXTERNAL,
        digest, public_key, signature, &length));
    assert(length == 0 && sign_calls == 3);
    for (size_t i = 0; i < sizeof public_key; ++i)
        assert(public_key[i] == 0);
    for (size_t i = 0; i < sizeof signature; ++i)
        assert(signature[i] == 0);
    expect_wiped();
}

static void test_exception_cleanup(void) {
    memset(&secret, 0x5a, sizeof secret);
    memset(&public_point, 0x5a, sizeof public_point);
    blue_wallet_signer_wipe();
    expect_wiped();
}

static void test_pin_lost_during_signing(void) {
    uint8_t digest[32] = {0xa5}, public_key[33], signature[72];
    size_t length = 99;
    pin_valid = true;
    fail_pair = fail_sign = fail_hash = bad_public = bad_sign_length = false;
    unsigned before = sign_calls;
    drop_pin_pair = true;
    assert(!blue_wallet_sign_digest(&owned, BLUE_PAYMENT_INPUT_EXTERNAL,
        digest, public_key, signature, &length));
    assert(length == 0 && sign_calls == before);
    for (size_t i = 0; i < sizeof public_key; ++i)
        assert(public_key[i] == 0);
    for (size_t i = 0; i < sizeof signature; ++i)
        assert(signature[i] == 0);
    expect_wiped();
    drop_pin_pair = false;
    pin_valid = true;
    drop_pin_hash = true;
    assert(!blue_wallet_sign_digest(&owned, BLUE_PAYMENT_INPUT_EXTERNAL,
        digest, public_key, signature, &length));
    assert(length == 0 && sign_calls == before);
    expect_wiped();
    drop_pin_hash = false;
    pin_valid = true;
    drop_pin_sign = true;
    assert(!blue_wallet_sign_digest(&owned, BLUE_PAYMENT_INPUT_EXTERNAL,
        digest, public_key, signature, &length));
    assert(length == 0 && sign_calls == before + 1);
    for (size_t i = 0; i < sizeof public_key; ++i)
        assert(public_key[i] == 0);
    for (size_t i = 0; i < sizeof signature; ++i)
        assert(signature[i] == 0);
    expect_wiped();
    drop_pin_sign = false;
    pin_valid = true;
}

static void test_malformed_sdk_results(void) {
    uint8_t digest[32] = {0xa5}, public_key[33], signature[72];
    size_t length = 99;
    unsigned before = sign_calls;
    fail_init_status = true;
    assert(!blue_wallet_sign_digest(&owned, BLUE_PAYMENT_INPUT_EXTERNAL,
        digest, public_key, signature, &length));
    assert(length == 0 && sign_calls == before);
    expect_wiped();
    fail_init_status = false;
    bad_public = true;
    assert(!blue_wallet_sign_digest(&owned, BLUE_PAYMENT_INPUT_EXTERNAL,
        digest, public_key, signature, &length));
    assert(length == 0);
    expect_wiped();
    bad_public = false;
    bad_sign_length = true;
    assert(!blue_wallet_sign_digest(&owned, BLUE_PAYMENT_INPUT_EXTERNAL,
        digest, public_key, signature, &length));
    assert(length == 0);
    for (size_t i = 0; i < sizeof public_key; ++i)
        assert(public_key[i] == 0);
    for (size_t i = 0; i < sizeof signature; ++i)
        assert(signature[i] == 0);
    expect_wiped();
}

static void test_account_guard(void) {
    uint8_t digest[32] = {0xa5}, public_key[33], signature[72];
    size_t length = 99;
    unsigned before = sign_calls;
    owned.external[0] ^= 1u;
    assert(!blue_wallet_sign_digest(&owned, BLUE_PAYMENT_INPUT_EXTERNAL,
        digest, public_key, signature, &length));
    assert(length == 0 && sign_calls == before);
    owned.external[0] ^= 1u;
    for (size_t i = 0; i < sizeof public_key; ++i)
        assert(public_key[i] == 0);
    for (size_t i = 0; i < sizeof signature; ++i)
        assert(signature[i] == 0);
    expect_wiped();
    fail_hash = true;
    assert(!blue_wallet_sign_digest(&owned, BLUE_PAYMENT_INPUT_INTERNAL,
        digest, public_key, signature, &length));
    assert(sign_calls == before);
    fail_hash = false;
    assert(!blue_wallet_sign_digest(NULL, BLUE_PAYMENT_INPUT_EXTERNAL,
        digest, public_key, signature, &length));
    assert(sign_calls == before);
    expect_wiped();
}

static void test_storage_aliases(void) {
    uint8_t digest_and_signature[BLUE_ECDSA_DER_MAX];
    uint8_t public_key[33];
    memset(digest_and_signature, 0xa5, sizeof digest_and_signature);
    memset(public_key, 0x5a, sizeof public_key);
    size_t length = 99;
    unsigned before = sign_calls;
    assert(!blue_wallet_sign_digest(&owned, BLUE_PAYMENT_INPUT_EXTERNAL,
        digest_and_signature, public_key, digest_and_signature, &length));
    assert(sign_calls == before && length == 99);
    for (size_t i = 0; i < sizeof digest_and_signature; ++i)
        assert(digest_and_signature[i] == 0xa5);
    for (size_t i = 0; i < sizeof public_key; ++i)
        assert(public_key[i] == 0x5a);
    expect_wiped();

    uint8_t signature[BLUE_ECDSA_DER_MAX];
    memset(signature, 0x5a, sizeof signature);
    assert(!blue_wallet_sign_digest(&owned, BLUE_PAYMENT_INPUT_EXTERNAL,
        digest_and_signature, digest_and_signature, signature, &length));
    assert(sign_calls == before && length == 99);
    for (size_t i = 0; i < sizeof digest_and_signature; ++i)
        assert(digest_and_signature[i] == 0xa5);
    expect_wiped();

    struct {
        blue_payment_owned_hashes hashes;
        uint8_t rest[BLUE_ECDSA_DER_MAX];
    } account = {.hashes = owned};
    uint8_t digest[32] = {0xa5};
    assert(!blue_wallet_sign_digest(&account.hashes,
        BLUE_PAYMENT_INPUT_EXTERNAL, digest, public_key,
        (uint8_t *)&account, &length));
    assert(memcmp(&account.hashes, &owned, sizeof owned) == 0 &&
        sign_calls == before && length == 99);
    expect_wiped();

    union { size_t value; uint8_t bytes[32]; } length_alias;
    memset(length_alias.bytes, 0xa5, sizeof length_alias.bytes);
    assert(!blue_wallet_sign_digest(&owned, BLUE_PAYMENT_INPUT_EXTERNAL,
        length_alias.bytes, public_key, signature, &length_alias.value));
    for (size_t i = 0; i < sizeof length_alias.bytes; ++i)
        assert(length_alias.bytes[i] == 0xa5);
    assert(sign_calls == before);
    expect_wiped();
}

int main(void) {
    memset(owned.external, 0x11, sizeof owned.external);
    memset(owned.internal, 0x22, sizeof owned.internal);
    test_paths();
    test_fail_closed();
    test_exception_cleanup();
    test_pin_lost_during_signing();
    test_malformed_sdk_results();
    test_account_guard();
    test_storage_aliases();
    return 0;
}
