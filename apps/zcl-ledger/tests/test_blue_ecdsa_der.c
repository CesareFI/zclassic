/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "blue_ecdsa_der.h"

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/sha.h>

#undef NDEBUG
#include <assert.h>
#include <string.h>

static EVP_PKEY *test_key(void) {
    static char group[] = "secp256k1";
    OSSL_PARAM params[] = {
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, group,
                               sizeof group - 1),
        OSSL_PARAM_END
    };
    EVP_PKEY_CTX *context = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
    EVP_PKEY *key = NULL;
    assert(context && EVP_PKEY_keygen_init(context) > 0);
    assert(EVP_PKEY_CTX_set_params(context, params) > 0);
    assert(EVP_PKEY_generate(context, &key) > 0);
    EVP_PKEY_CTX_free(context);
    return key;
}

static void test_real_signatures(void) {
    EVP_PKEY *key = test_key();
    EVP_PKEY_CTX *signer = EVP_PKEY_CTX_new(key, NULL);
    EVP_PKEY_CTX *verifier = EVP_PKEY_CTX_new(key, NULL);
    assert(signer && verifier);
    assert(EVP_PKEY_sign_init(signer) > 0);
    assert(EVP_PKEY_verify_init(verifier) > 0);
    assert(EVP_PKEY_CTX_set_signature_md(signer, EVP_sha256()) > 0);
    assert(EVP_PKEY_CTX_set_signature_md(verifier, EVP_sha256()) > 0);
    for (unsigned i = 0; i < 32; ++i) {
        uint8_t message[] = {'B', 'l', 'u', 'e', (uint8_t)i};
        uint8_t digest[32], signature[BLUE_ECDSA_DER_MAX], normalized[72];
        size_t signature_length = sizeof signature, normalized_length = 0;
        assert(SHA256(message, sizeof message, digest));
        assert(EVP_PKEY_sign(signer, signature, &signature_length,
            digest, sizeof digest) > 0);
        assert(blue_ecdsa_der_low_s(signature, signature_length,
            normalized, &normalized_length));
        assert(EVP_PKEY_verify(verifier, normalized, normalized_length,
            digest, sizeof digest) == 1);
        uint8_t repeated[72];
        size_t repeated_length = 0;
        assert(blue_ecdsa_der_low_s(normalized, normalized_length,
            repeated, &repeated_length));
        assert(repeated_length == normalized_length);
        assert(memcmp(repeated, normalized, repeated_length) == 0);
    }
    EVP_PKEY_CTX_free(verifier);
    EVP_PKEY_CTX_free(signer);
    EVP_PKEY_free(key);
}

static void test_bounds_and_canonical_encoding(void) {
    static const uint8_t one[] = {0x30, 0x06, 0x02, 0x01,
                                  0x01, 0x02, 0x01, 0x01};
    uint8_t output[BLUE_ECDSA_DER_MAX];
    size_t length = 99;
    assert(blue_ecdsa_der_low_s(one, sizeof one, output, &length));
    assert(length == sizeof one && memcmp(output, one, length) == 0);
    uint8_t high[BLUE_ECDSA_DER_MAX] = {
        0x30, 0x26, 0x02, 0x01, 0x01, 0x02, 0x21, 0
    };
    static const uint8_t order_minus_one[32] = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
        0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b,
        0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x40
    };
    memcpy(high + 8, order_minus_one, 32);
    assert(blue_ecdsa_der_low_s(high, 40, high, &length));
    assert(length == sizeof one && memcmp(high, one, length) == 0);
    uint8_t zero[sizeof one];
    memcpy(zero, one, sizeof zero);
    zero[4] = 0;
    assert(!blue_ecdsa_der_low_s(zero, sizeof zero, output, &length));
    const uint8_t nonminimal[] = {
        0x30, 0x07, 0x02, 0x02, 0x00, 0x01, 0x02, 0x01, 0x01
    };
    assert(!blue_ecdsa_der_low_s(nonminimal, sizeof nonminimal,
        output, &length));
    uint8_t out_of_range[40] = {0x30, 0x26, 0x02, 0x21, 0};
    memcpy(out_of_range + 5, order_minus_one, 32);
    ++out_of_range[36];
    out_of_range[37] = 0x02;
    out_of_range[38] = 0x01;
    out_of_range[39] = 0x01;
    assert(!blue_ecdsa_der_low_s(out_of_range, sizeof out_of_range,
        output, &length));
    uint8_t bad[sizeof one];
    for (size_t i = 0; i < sizeof one; ++i) {
        memcpy(bad, one, sizeof bad);
        bad[i] = 0xff;
        length = 99;
        assert(!blue_ecdsa_der_low_s(bad, sizeof bad, output, &length));
        assert(length == 0);
    }
    assert(!blue_ecdsa_der_low_s(one, sizeof one - 1, output, &length));
    assert(length == 0);
    assert(!blue_ecdsa_der_low_s(NULL, sizeof one, output, &length));
    assert(length == 0);
}

static void test_random_malformed(void) {
    uint32_t random = 0x23c0ffee;
    uint8_t bytes[BLUE_ECDSA_DER_MAX], output[BLUE_ECDSA_DER_MAX];
    for (unsigned trial = 0; trial < 10000; ++trial) {
        size_t length = trial % (sizeof bytes + 1);
        for (size_t i = 0; i < length; ++i) {
            random = random * 1664525u + 1013904223u;
            bytes[i] = (uint8_t)(random >> 24);
        }
        size_t output_length = 99;
        bool valid = blue_ecdsa_der_low_s(bytes, length,
            output, &output_length);
        assert(output_length <= sizeof output);
        if (!valid) assert(output_length == 0);
    }
}

int main(void) {
    test_bounds_and_canonical_encoding();
    test_real_signatures();
    test_random_malformed();
    return 0;
}
