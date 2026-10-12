/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "blue_fs_ct.h"
#include "blue_jubjub_lowmem.h"
#include "blue_jubjub_encode.h"
#include "blue_jubjub_arithmetic.h"
#include "blue_redjubjub_challenge.h"
#include "blue_redjubjub_response.h"
#include "blue_redjubjub_sign_isolated.h"
#include "blue_sapling_generators.h"
#include "blue_zip32_fvk.h"
#include "blue_zip32_child.h"
#include "blue_zip32_master.h"
#include "blue_zip32_seed_bridge.h"
#include "blue_sapling_spend_auth.h"
#include "blue_mod256.h"
#include "blue_spend_generator_fixture.h"
#include "blue_sapling_fixture.h"
#include "blue_consensus_spend_fixture.h"
#include "zcl_tx_review.h"
#include "zcl_tx_shielded_replay.h"
#include "zcl_zip243.h"
#include "zcl_zip243_host.h"
#include "crypto/blake2b.h"
#include "sapling/jubjub.h"

#undef NDEBUG
#include <assert.h>
#include <stdio.h>
#include <string.h>

static void check_case(const struct jub_point *generator,
    uint64_t secret, uint64_t nonce, uint64_t challenge) {
    struct fs sk = {.d = {secret}}, r = {.d = {nonce}};
    struct fs c = {.d = {challenge}}, product, response;
    uint8_t sk_bytes[32], r_bytes[32], c_bytes[32], s_bytes[32];
    fs_to_bytes(sk_bytes, &sk);
    fs_to_bytes(r_bytes, &r);
    fs_to_bytes(c_bytes, &c);
    struct jub_point vk, commitment, s_g, c_vk, expected;
    assert(blue_jubjub_scalar_mul_lowmem(&vk, generator, sk_bytes));
    assert(blue_jubjub_scalar_mul_lowmem(&commitment, generator, r_bytes));
    uint8_t encoded[32], reference[32];
    assert(blue_jubjub_encode(encoded, &vk));
    jub_to_bytes(reference, &vk);
    assert(memcmp(encoded, reference, 32) == 0);
    assert(blue_jubjub_encode(encoded, &commitment));
    jub_to_bytes(reference, &commitment);
    assert(memcmp(encoded, reference, 32) == 0);
    blue_fs_mul_ct(&product, &c, &sk);
    blue_fs_add_ct(&response, &r, &product);
    fs_to_bytes(s_bytes, &response);
    jub_scalar_mul(&s_g, generator, s_bytes);
    jub_scalar_mul(&c_vk, &vk, c_bytes);
    jub_add(&expected, &commitment, &c_vk);
    uint8_t left[32], right[32];
    jub_to_bytes(left, &s_g);
    jub_to_bytes(right, &expected);
    assert(memcmp(left, right, sizeof left) == 0);
    s_bytes[0] ^= 1u;
    jub_scalar_mul(&s_g, generator, s_bytes);
    jub_to_bytes(left, &s_g);
    assert(memcmp(left, right, sizeof left) != 0);
}

static void check_encoded_points(const struct jub_point *generator) {
    uint32_t state = 0x3c6ef372u;
    for (unsigned sample = 0; sample < 32; ++sample) {
        uint8_t scalar[32], encoded[32], reference[32];
        for (unsigned i = 0; i < 32; ++i) {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            scalar[i] = (uint8_t)state;
        }
        struct jub_point point;
        assert(blue_jubjub_scalar_mul_lowmem(&point, generator, scalar));
        assert(blue_jubjub_encode(encoded, &point));
        jub_to_bytes(reference, &point);
        assert(memcmp(encoded, reference, 32) == 0);
    }
}

static bool verify_public_signature(const struct jub_point *generator,
    const uint8_t rbar[32], const uint8_t vkbar[32],
    const uint8_t message[32], const uint8_t sbar[32]) {
    static const uint8_t personal[16] = {
        'Z','c','a','s','h','_','R','e','d','J','u','b','j','u','b','H'
    };
    struct fs canonical;
    struct jub_point r, vk, c_vk, s_g, negative, sum, cleared;
    if (!fs_from_bytes(&canonical, sbar) ||
        !jub_from_bytes(&r, rbar) || !jub_from_bytes(&vk, vkbar))
        return false;
    struct blake2b_ctx hash;
    uint8_t digest[64], challenge[32];
    if (blake2b_init_salt_personal(&hash, 64, NULL, 0, NULL,
            personal) != 0 ||
        blake2b_update(&hash, rbar, 32) != 0 ||
        blake2b_update(&hash, vkbar, 32) != 0 ||
        blake2b_update(&hash, message, 32) != 0 ||
        blake2b_final(&hash, digest, 64) != 0) return false;
    jubjub_to_scalar(digest, challenge);
    jub_scalar_mul(&c_vk, &vk, challenge);
    jub_scalar_mul(&s_g, generator, sbar);
    jub_neg(&negative, &s_g);
    jub_add(&sum, &r, &c_vk);
    jub_add(&sum, &sum, &negative);
    jub_mul_by_cofactor(&cleared, &sum);
    return jub_is_identity(&cleared);
}

static void check_message_signature(const struct jub_point *generator) {
    static const uint8_t scalar_order[32] = {
        0xb7,0x2c,0xf7,0xd6,0x5e,0x0e,0x97,0xd0,
        0x82,0x10,0xc8,0xcc,0x93,0x20,0x68,0xa6,
        0x00,0x3b,0x34,0x01,0x01,0x3b,0x67,0x06,
        0xa9,0xaf,0x33,0x65,0xea,0xb4,0x7d,0x0e
    };
    struct fs secret = {.d = {23}}, nonce = {.d = {97}};
    struct fs challenge, product, response;
    uint8_t secret_bytes[32], nonce_bytes[32], challenge_bytes[32];
    uint8_t vkbar[32], rbar[32], sbar[32], message[32];
    fs_to_bytes(secret_bytes, &secret);
    fs_to_bytes(nonce_bytes, &nonce);
    for (unsigned i = 0; i < 32; ++i) message[i] = (uint8_t)i;
    struct jub_point vk, r;
    assert(blue_jubjub_scalar_mul_lowmem(&vk, generator, secret_bytes));
    assert(blue_jubjub_scalar_mul_lowmem(&r, generator, nonce_bytes));
    assert(blue_jubjub_encode(vkbar, &vk));
    assert(blue_jubjub_encode(rbar, &r));
    assert(blue_redjubjub_challenge(challenge_bytes, rbar,
        vkbar, message));
    uint8_t in_place[32];
    memcpy(in_place, vkbar, sizeof in_place);
    assert(blue_redjubjub_challenge(in_place, rbar,
        in_place, message));
    assert(memcmp(in_place, challenge_bytes, sizeof in_place) == 0);
    assert(fs_from_bytes(&challenge, challenge_bytes));
    blue_fs_mul_ct(&product, &challenge, &secret);
    blue_fs_add_ct(&response, &nonce, &product);
    fs_to_bytes(sbar, &response);
    uint8_t candidate[32] = {0};
    assert(blue_redjubjub_response(candidate, nonce_bytes,
        challenge_bytes, secret_bytes));
    assert(memcmp(candidate, sbar, sizeof candidate) == 0);
    assert(blue_redjubjub_response(in_place, nonce_bytes,
        in_place, secret_bytes));
    assert(memcmp(in_place, sbar, sizeof in_place) == 0);
    assert(verify_public_signature(generator, rbar, vkbar, message, sbar));
    sbar[0] ^= 1u;
    assert(!verify_public_signature(generator, rbar, vkbar, message, sbar));
    sbar[0] ^= 1u;
    message[0] ^= 1u;
    assert(!verify_public_signature(generator, rbar, vkbar, message, sbar));
    assert(!verify_public_signature(generator, rbar, vkbar, message,
        scalar_order));
}

static void check_response_rejection(void) {
    static const uint8_t order[32] = {
        0xb7,0x2c,0xf7,0xd6,0x5e,0x0e,0x97,0xd0,
        0x82,0x10,0xc8,0xcc,0x93,0x20,0x68,0xa6,
        0x00,0x3b,0x34,0x01,0x01,0x3b,0x67,0x06,
        0xa9,0xaf,0x33,0x65,0xea,0xb4,0x7d,0x0e
    };
    uint8_t one[32] = {1}, zero[32] = {0}, output[32];
    memset(output, 0xa5, sizeof output);
    assert(!blue_redjubjub_response(output, zero, one, one));
    assert(!blue_redjubjub_response(output, one, one, zero));
    assert(!blue_redjubjub_response(output, order, one, one));
    assert(!blue_redjubjub_response(output, one, order, one));
    assert(!blue_redjubjub_response(output, one, one, order));
    assert(!blue_redjubjub_response(output, one, one, NULL));
    for (size_t i = 0; i < sizeof output; ++i)
        assert(output[i] == 0xa5);
    assert(blue_redjubjub_response(output, one, zero, one));
    assert(memcmp(output, one, sizeof output) == 0);
}

static void check_signer_aliases(const uint8_t secret[32],
    const uint8_t entropy[80], const uint8_t message[32]) {
    uint8_t storage[128], before[128];
    memset(storage, 0xa5, sizeof storage);
    memcpy(storage, secret, 32);
    memcpy(before, storage, sizeof storage);
    assert(!blue_redjubjub_sign_isolated(storage, storage,
        entropy, message));
    assert(memcmp(storage, before, sizeof storage) == 0);

    memset(storage, 0xa5, sizeof storage);
    memcpy(storage + 48, secret, 32);
    memcpy(before, storage, sizeof storage);
    assert(!blue_redjubjub_sign_isolated(storage, storage + 48,
        entropy, message));
    assert(memcmp(storage, before, sizeof storage) == 0);

    memset(storage, 0xa5, sizeof storage);
    memcpy(storage + 16, entropy, 80);
    memcpy(before, storage, sizeof storage);
    assert(!blue_redjubjub_sign_isolated(storage, secret,
        storage + 16, message));
    assert(memcmp(storage, before, sizeof storage) == 0);

    memset(storage, 0xa5, sizeof storage);
    memcpy(storage + 48, message, 32);
    memcpy(before, storage, sizeof storage);
    assert(!blue_redjubjub_sign_isolated(storage, secret,
        entropy, storage + 48));
    assert(memcmp(storage, before, sizeof storage) == 0);
}

static void check_entropy_signature_isolated(
    const struct jub_point *generator) {
    struct fs secret = {.d = {23}};
    uint8_t secret_bytes[32], entropy[80], message[32], signature[64];
    uint8_t vkbar[32];
    struct jub_point key;
    fs_to_bytes(secret_bytes, &secret);
    for (unsigned i = 0; i < sizeof entropy; ++i)
        entropy[i] = (uint8_t)i;
    for (unsigned i = 0; i < sizeof message; ++i)
        message[i] = (uint8_t)i;
    jub_scalar_mul(&key, generator, secret_bytes);
    jub_to_bytes(vkbar, &key);
    assert(blue_redjubjub_sign_isolated(signature, secret_bytes,
        entropy, message));
    static const uint8_t expected_r[32] = {
        0x8f,0x40,0x69,0x68,0x90,0x37,0x7c,0xb1,
        0xa4,0x14,0x6a,0x71,0x17,0xd9,0xce,0xec,
        0xd6,0x01,0x4d,0x91,0x36,0xde,0x23,0xf2,
        0xf7,0x78,0x1a,0xd1,0x0f,0x88,0x50,0xd2
    };
    static const uint8_t expected_s[32] = {
        0xff,0xe3,0xa8,0x9b,0x2c,0x21,0x05,0xc9,
        0xb2,0x16,0x07,0x02,0x88,0xb5,0x19,0xe6,
        0x8c,0x82,0x9a,0x95,0xaa,0x9f,0xca,0x33,
        0x07,0x61,0x1d,0x6d,0xd2,0x77,0xd3,0x06
    };
    assert(memcmp(signature, expected_r, 32) == 0);
    assert(memcmp(signature + 32, expected_s, 32) == 0);
    check_signer_aliases(secret_bytes, entropy, message);
    assert(verify_public_signature(generator, signature, vkbar,
        message, signature + 32));
    message[0] ^= 1u;
    assert(!verify_public_signature(generator, signature, vkbar,
        message, signature + 32));
    message[0] ^= 1u;
    signature[32] ^= 1u;
    assert(!verify_public_signature(generator, signature, vkbar,
        message, signature + 32));
    signature[32] ^= 1u;
    uint8_t changed_signature[64];
    entropy[1] ^= 1u;
    assert(blue_redjubjub_sign_isolated(changed_signature, secret_bytes,
        entropy, message));
    assert(memcmp(changed_signature, signature,
        sizeof signature) != 0);
    assert(verify_public_signature(generator, changed_signature, vkbar,
        message, changed_signature + 32));
    memset(entropy, 0, sizeof entropy);
    memset(signature, 0xa5, sizeof signature);
    assert(!blue_redjubjub_sign_isolated(signature, secret_bytes,
        entropy, message));
    for (unsigned i = 0; i < sizeof signature; ++i)
        assert(signature[i] == 0);
    memset(signature, 0xa5, sizeof signature);
    entropy[0] = 1;
    memset(secret_bytes, 0xff, sizeof secret_bytes);
    assert(!blue_redjubjub_sign_isolated(signature, secret_bytes,
        entropy, message));
    for (unsigned i = 0; i < sizeof signature; ++i)
        assert(signature[i] == 0);
    memset(signature, 0xa5, sizeof signature);
    memset(secret_bytes, 0, sizeof secret_bytes);
    assert(!blue_redjubjub_sign_isolated(signature, secret_bytes,
        entropy, message));
    for (unsigned i = 0; i < sizeof signature; ++i)
        assert(signature[i] == 0);
    memset(signature, 0xa5, sizeof signature);
    assert(!blue_redjubjub_sign_isolated(signature, NULL,
        entropy, message));
    for (unsigned i = 0; i < sizeof signature; ++i)
        assert(signature[i] == 0);
}

static void check_sapling_digest_signature(
    const struct jub_point *generator) {
    uint8_t wire[BLUE_SYNTHETIC_SAPLING_BYTES];
    blue_sapling_fixture(wire);
    zcl_tx_review review;
    assert(zcl_tx_review_parse(wire, sizeof wire, &review) == 0);
    assert(review.sapling_spends == 1 && review.sapling_outputs == 1);
    struct blake2b_ctx context;
    zcl_zip243_hasher hasher = zcl_zip243_host_hasher(&context);
    uint8_t digest[32], changed[32], signature[64], entropy[80];
    assert(zcl_zip243_shielded_digest(wire, sizeof wire,
        0x76b809bb, &hasher, digest) == 0);
    static const uint8_t expected_digest[32] = {
        0xdf,0x7c,0x3c,0x4c,0x47,0xac,0x47,0xfb,
        0x23,0x84,0x4b,0x19,0x6c,0x89,0x5a,0xbc,
        0x56,0x40,0xef,0x2f,0xb0,0x4a,0x0c,0xe5,
        0xb7,0x92,0xcc,0x2c,0x98,0x71,0x42,0x4e
    };
    assert(memcmp(digest, expected_digest, sizeof digest) == 0);
    for (unsigned i = 0; i < sizeof entropy; ++i)
        entropy[i] = (uint8_t)i;
    uint8_t secret[32] = {23}, vkbar[32];
    struct jub_point key;
    jub_scalar_mul(&key, generator, secret);
    jub_to_bytes(vkbar, &key);
    assert(blue_redjubjub_sign_isolated(signature, secret,
        entropy, digest));
    assert(verify_public_signature(generator, signature, vkbar,
        digest, signature + 32));
    wire[412] ^= 1u;
    assert(zcl_zip243_shielded_digest(wire, sizeof wire,
        0x76b809bb, &hasher, changed) == 0);
    assert(memcmp(changed, digest, 32) != 0);
    assert(!verify_public_signature(generator, signature, vkbar,
        changed, signature + 32));
    wire[412] ^= 1u;
    wire[27 + 320] ^= 1u;
    assert(zcl_zip243_shielded_digest(wire, sizeof wire,
        0x76b809bb, &hasher, changed) == 0);
    assert(memcmp(changed, digest, 32) == 0);
    wire[27 + 320] ^= 1u;
    wire[1361] ^= 1u;
    assert(zcl_zip243_shielded_digest(wire, sizeof wire,
        0x76b809bb, &hasher, changed) == 0);
    assert(memcmp(changed, digest, 32) == 0);
    wire[1361] ^= 1u;
    assert(zcl_zip243_shielded_digest(wire, sizeof wire,
        0x930b540d, &hasher, changed) == 0);
    assert(memcmp(changed, digest, 32) != 0);
    assert(!verify_public_signature(generator, signature, vkbar,
        changed, signature + 32));
}

static void check_zip32_fvk(void) {
    static const uint8_t expected_ak[32] = {
        0x93,0x44,0x2e,0x5f,0xef,0xfb,0xff,0x16,
        0xe7,0x21,0x72,0x02,0xdc,0x73,0x06,0x72,
        0x9f,0xff,0xfe,0x85,0xaf,0x56,0x83,0xbc,
        0xe2,0x64,0x2e,0x3e,0xeb,0x5d,0x38,0x71
    };
    static const uint8_t expected_nk[32] = {
        0xdc,0xe8,0xe7,0xed,0xec,0xe0,0x4b,0x89,
        0x50,0x41,0x7f,0x85,0xba,0x57,0x69,0x1b,
        0x78,0x3c,0x45,0xb1,0xa2,0x74,0x22,0xdb,
        0x16,0x93,0xdc,0xeb,0x67,0xb1,0x01,0x06
    };
    static const uint8_t proof_generator[32] = {
        0xe7,0xe8,0x5d,0xe0,0xf7,0xf9,0x7a,0x46,
        0xd2,0x49,0xa1,0xf5,0xea,0x51,0xdf,0x50,
        0xcc,0x48,0x49,0x0f,0x84,0x01,0xc9,0xde,
        0x7a,0x2a,0xdf,0x18,0x07,0xd1,0xb6,0xd4
    };
    uint8_t seed[32];
    for (unsigned i = 0; i < sizeof seed; ++i) seed[i] = (uint8_t)i;
    struct zip32_xsk master;
    struct zip32_fvk fvk;
    assert(blue_zip32_master_xsk(&master, seed));
    assert(blue_zip32_fvk_from_expsk(&fvk, &master.expsk));
    assert(memcmp(fvk.ak, expected_ak, 32) == 0);
    assert(memcmp(fvk.nk, expected_nk, 32) == 0);
    uint32_t tag = 0;
    assert(blue_zip32_fvk_tag(&tag, &fvk));
    assert(memcmp(fvk.ovk, master.expsk.ovk, 32) == 0);
    struct jub_point generator, result;
    uint8_t reference[32];
    assert(jub_from_bytes(&generator, blue_spend_generator_fixture));
    jub_scalar_mul(&result, &generator, master.expsk.ask);
    jub_to_bytes(reference, &result);
    assert(memcmp(fvk.ak, reference, 32) == 0);
    assert(jub_from_bytes(&generator, proof_generator));
    jub_scalar_mul(&result, &generator, master.expsk.nsk);
    jub_to_bytes(reference, &result);
    assert(memcmp(fvk.nk, reference, 32) == 0);
    assert(tag == 0x3a71c214u);
    memset(&fvk, 0xa5, sizeof fvk);
    assert(!blue_zip32_fvk_from_expsk(&fvk, NULL));
    const uint8_t zero[sizeof fvk] = {0};
    assert(memcmp(&fvk, zero, sizeof fvk) == 0);
    tag = 0xa5a5a5a5u;
    assert(!blue_zip32_fvk_tag(&tag, NULL) && tag == 0);
}

static unsigned hex_nibble(char value) {
    if (value >= '0' && value <= '9') return (unsigned)(value - '0');
    if (value >= 'a' && value <= 'f') return (unsigned)(value - 'a' + 10);
    return 0xffu;
}

static bool matches_hex32(const uint8_t bytes[32], const char hex[65]) {
    for (unsigned i = 0; i < 32; ++i) {
        unsigned high = hex_nibble(hex[i * 2]);
        unsigned low = hex_nibble(hex[i * 2 + 1]);
        if (high > 15 || low > 15 ||
            bytes[i] != (uint8_t)((high << 4) | low)) return false;
    }
    return hex[64] == 0;
}

static void check_zip32_child(void) {
    uint8_t seed[32];
    for (unsigned i = 0; i < sizeof seed; ++i) seed[i] = (uint8_t)i;
    struct zip32_xsk master, m1, m12;
    blue_zip32_workspace scratch;
    assert(blue_zip32_master_xsk(&master, seed));
    assert(blue_zip32_derive_child(&m1, &master, 1, &scratch));
    assert(m1.depth == 1 && m1.parent_fvk_tag == 0x3a71c214u &&
        m1.child_index == 1);
    assert(matches_hex32(m1.chain_code,
        "0147110c691a03b9d9f0ba9005c5e790a595b7f04e3329d2fa438a6705dabce6"));
    assert(matches_hex32(m1.expsk.ask,
        "282bc197a516287c8ea8f68c424abad302b45cdf95407961d7b8b455267a350c"));
    assert(matches_hex32(m1.expsk.nsk,
        "e7a32988fdca1efcd6d1c4c562e629c2e96b2c3f7eda04ac4efd1810ff6bba01"));
    assert(matches_hex32(m1.expsk.ovk,
        "5f1381fc8886da6a02dffeefcf503c40fa8f5a36f7a7142fd81b5518c5a47474"));
    assert(matches_hex32(m1.dk,
        "e04de832a2d791ec129ab9002b91c9e9cdeed79241a7c4960e5178d870c1b4dc"));
    assert(blue_zip32_derive_child(&m12, &m1, 0x80000002u, &scratch));
    assert(m12.depth == 2 && m12.parent_fvk_tag == 0x079e99dbu &&
        m12.child_index == 0x80000002u);
    assert(matches_hex32(m12.chain_code,
        "97ce15f4ed1b9739b0262a463bcb3dc9b3bd2323a9baa441ca42777383a8d435"));
    assert(matches_hex32(m12.expsk.ask,
        "8be8113cee3413a71f82c41fc8da517be134049832e6825c92da6b84fee4c60d"));
    assert(matches_hex32(m12.expsk.nsk,
        "3778059dc569e7d0d32391573f951bbde92fc6b9cf614773661c5c273aa6990c"));
    assert(matches_hex32(m12.expsk.ovk,
        "cf81182e96223c028ce3d6eb4794d3113b95069d14c57588e193b65efc2813bc"));
    assert(matches_hex32(m12.dk,
        "a3eda19f9eff46ca12dfa1bf10371b48d1b4a40c4d05a0d8dce0e7dc62b07b37"));
    const uint8_t zero_fvk[sizeof scratch] = {0};
    assert(memcmp(&scratch, zero_fvk, sizeof scratch) == 0);
    assert(!blue_zip32_derive_child(&master, &master, 2, &scratch));
    assert(!blue_zip32_derive_child(&m12, &m1, 2,
        (blue_zip32_workspace *)&m12));
    assert(!blue_zip32_derive_child(&m12, &m1, 2,
        (blue_zip32_workspace *)&m1));
    assert(m1.depth == 1);
    assert(!blue_zip32_derive_child(&m12, NULL, 2, &scratch));
    const uint8_t zero_xsk[sizeof m12] = {0};
    assert(memcmp(&m12, zero_xsk, sizeof m12) == 0);
}

static bool fixture_bip32_node(void *context, const uint32_t path[3],
    uint8_t private_key[32], uint8_t chain_code[32]) {
    bool allowed = *(bool *)context;
    assert(path[0] == 0x80000020u && path[1] == 0x80000093u &&
        path[2] == 0x80000000u);
    for (unsigned i = 0; i < 32; ++i) {
        private_key[i] = (uint8_t)i;
        chain_code[i] = (uint8_t)(i + 32);
    }
    return allowed;
}

static void check_zip32_seed_bridge(void) {
    static const uint8_t expected_root[32] = {
        0x2d,0x26,0x76,0x85,0xb1,0x14,0x36,0x26,
        0x95,0x83,0xfd,0x90,0xcf,0x71,0xa4,0x13,
        0xfe,0x25,0xc4,0x6a,0x9d,0x67,0x0a,0x06,
        0x9f,0x4c,0xe7,0x52,0xbb,0xa3,0x4e,0x1e
    };
    blue_zip32_seed_workspace workspace;
    struct zip32_xsk actual, expected;
    bool allowed = true;
    assert(blue_zip32_master_from_bip32(&actual, &workspace,
        fixture_bip32_node, &allowed));
    assert(blue_zip32_master_xsk(&expected, expected_root));
    assert(actual.depth == expected.depth &&
        actual.parent_fvk_tag == expected.parent_fvk_tag &&
        actual.child_index == expected.child_index &&
        memcmp(actual.chain_code, expected.chain_code, 32) == 0 &&
        memcmp(actual.dk, expected.dk, 32) == 0 &&
        memcmp(&actual.expsk, &expected.expsk, sizeof actual.expsk) == 0);
    const uint8_t zero_workspace[sizeof workspace] = {0};
    assert(memcmp(&workspace, zero_workspace, sizeof workspace) == 0);
    allowed = false;
    assert(!blue_zip32_master_from_bip32(&actual, &workspace,
        fixture_bip32_node, &allowed));
    const uint8_t zero_xsk[sizeof actual] = {0};
    assert(memcmp(&actual, zero_xsk, sizeof actual) == 0);
    assert(memcmp(&workspace, zero_workspace, sizeof workspace) == 0);
    assert(!blue_zip32_master_from_bip32(&actual, &workspace,
        NULL, NULL));
    assert(memcmp(&actual, zero_xsk, sizeof actual) == 0);
    blue_mod256_wipe(&expected, sizeof expected);
}

static void check_child_spend_signature(const struct jub_point *generator) {
    uint8_t seed[32], entropy[80], digest[32], changed[32];
    uint8_t signature[64];
    uint8_t wire[BLUE_SYNTHETIC_SAPLING_BYTES];
    for (unsigned i = 0; i < sizeof seed; ++i) seed[i] = (uint8_t)i;
    for (unsigned i = 0; i < sizeof entropy; ++i) entropy[i] = (uint8_t)i;
    blue_sapling_fixture(wire);
    struct blake2b_ctx context;
    zcl_zip243_hasher hasher = zcl_zip243_host_hasher(&context);
    assert(zcl_zip243_shielded_digest(wire, sizeof wire,
        0x76b809bb, &hasher, digest) == 0);
    assert(matches_hex32(digest,
        "df7c3c4c47ac47fb23844b196c895abc5640ef2fb04a0ce5b792cc2c9871424e"));
    struct zip32_xsk master = {0}, child = {0};
    struct zip32_fvk fvk = {0};
    blue_zip32_workspace scratch = {0};
    assert(blue_zip32_master_xsk(&master, seed));
    assert(blue_zip32_derive_child(&child, &master, 1, &scratch));
    assert(blue_zip32_fvk_from_expsk(&fvk, &child.expsk));
    assert(blue_redjubjub_sign_isolated(signature, child.expsk.ask,
        entropy, digest));
    assert(matches_hex32(signature,
        "40396e53f8d178f819ef67c1c2f5fb80c9abd4754a01efde1583a22a697d420c"));
    assert(matches_hex32(signature + 32,
        "8978be725870ca472723d2b2917558a5a2d2fb9745590c710573286d126ad707"));
    assert(verify_public_signature(generator, signature, fvk.ak,
        digest, signature + 32));
    wire[412] ^= 1u;
    assert(zcl_zip243_shielded_digest(wire, sizeof wire,
        0x76b809bb, &hasher, changed) == 0);
    assert(memcmp(changed, digest, sizeof changed) != 0);
    assert(!verify_public_signature(generator, signature, fvk.ak,
        changed, signature + 32));
    blue_mod256_wipe(&master, sizeof master);
    blue_mod256_wipe(&child, sizeof child);
    blue_mod256_wipe(&fvk, sizeof fvk);
    blue_mod256_wipe(&scratch, sizeof scratch);
    blue_mod256_wipe(seed, sizeof seed);
    blue_mod256_wipe(entropy, sizeof entropy);
    blue_mod256_wipe(signature, sizeof signature);
}

static void check_rejected_spend_randomizers(const uint8_t ask[32],
    const uint8_t rk[32], const uint8_t entropy[80],
    const uint8_t digest[32]) {
    static const uint8_t order[32] = {
        0xb7,0x2c,0xf7,0xd6,0x5e,0x0e,0x97,0xd0,
        0x82,0x10,0xc8,0xcc,0x93,0x20,0x68,0xa6,
        0x00,0x3b,0x34,0x01,0x01,0x3b,0x67,0x06,
        0xa9,0xaf,0x33,0x65,0xea,0xb4,0x7d,0x0e
    };
    blue_sapling_spend_workspace workspace;
    uint8_t signature[64];
    assert(!blue_sapling_spend_auth_sign(signature, &workspace,
        ask, order, rk, entropy, digest));
    const uint8_t zero_signature[sizeof signature] = {0};
    assert(memcmp(signature, zero_signature, sizeof signature) == 0);
    memset(signature, 0xa5, sizeof signature);
    assert(!blue_sapling_spend_auth_sign(signature, &workspace,
        order, ask, rk, entropy, digest));
    assert(memcmp(signature, zero_signature, sizeof signature) == 0);
    const uint8_t zero_workspace[sizeof workspace] = {0};
    assert(memcmp(&workspace, zero_workspace, sizeof workspace) == 0);
    struct fs secret, negative;
    assert(fs_from_bytes(&secret, ask));
    fs_neg(&negative, &secret);
    uint8_t canceling_ar[32];
    fs_to_bytes(canceling_ar, &negative);
    assert(!blue_sapling_spend_auth_sign(signature, &workspace,
        ask, canceling_ar, rk, entropy, digest));
    assert(memcmp(signature, zero_signature, sizeof signature) == 0);
    blue_mod256_wipe(canceling_ar, sizeof canceling_ar);
}

static void replay_fixture_spend(const uint8_t *wire, size_t length,
    uint8_t rk[32], uint8_t digest[32]) {
    struct blake2b_ctx context;
    zcl_zip243_hasher hasher = zcl_zip243_host_hasher(&context);
    zcl_tx_shielded_replay replay;
    assert(zcl_tx_shielded_replay_begin_rk(&replay,
        (uint32_t)length, 0x76b809bb, &hasher, 0, rk));
    for (unsigned pass = 1; pass <= 6; ++pass) {
        for (size_t offset = 0; offset < length; offset += 63) {
            size_t take = length - offset < 63 ? length - offset : 63;
            assert(zcl_tx_shielded_replay_feed(&replay,
                wire + offset, take));
        }
        if (pass < 6) assert(zcl_tx_shielded_replay_next(&replay));
    }
    zcl_tx_shielded_facts facts;
    assert(zcl_tx_shielded_replay_finish(&replay, &facts, digest));
    assert(facts.sapling_spends == 1 && facts.sapling_outputs == 1);
    zcl_tx_shielded_replay_abort(&replay);
}

static size_t read_hex_record(FILE *file, uint8_t *bytes, size_t capacity) {
    char line[16384];
    while (fgets(line, sizeof line, file)) {
        if (line[0] == '#') continue;
        size_t count = strcspn(line, "\r\n");
        assert(count && !(count & 1u) && count / 2 <= capacity);
        for (size_t i = 0; i < count / 2; ++i) {
            unsigned high = hex_nibble(line[2 * i]);
            unsigned low = hex_nibble(line[2 * i + 1]);
            assert(high <= 15 && low <= 15);
            bytes[i] = (uint8_t)((high << 4) | low);
        }
        return count / 2;
    }
    assert(!ferror(file));
    assert(0 && "missing hex record");
    return 0;
}

static void read_consensus_fixture(const char *wire_path,
    uint8_t wire[8192]) {
    FILE *file = fopen(wire_path, "r");
    assert(file);
    assert(read_hex_record(file, wire, 8192) ==
        BLUE_CONSENSUS_SPEND_WIRE_BYTES);
    assert(fclose(file) == 0);
}

static void check_consensus_spend_signature(
    const struct jub_point *generator, const char *wire_path) {
    uint8_t wire[8192], rk[32], digest[32];
    uint8_t signature[64], entropy[80], changed[32];
    blue_sapling_spend_workspace auth;
    read_consensus_fixture(wire_path, wire);
    replay_fixture_spend(wire, BLUE_CONSENSUS_SPEND_WIRE_BYTES, rk, digest);
    assert(memcmp(rk, wire + 27 + 96, sizeof rk) == 0);
    assert(memcmp(rk, blue_consensus_rk, sizeof rk) == 0);
    assert(memcmp(digest, blue_consensus_digest, sizeof digest) == 0);
    const uint8_t *original = wire + 27 + 320;
    assert(verify_public_signature(generator, original, rk,
        digest, original + 32));
    for (unsigned i = 0; i < sizeof entropy; ++i)
        entropy[i] = (uint8_t)i;
    assert(blue_sapling_spend_auth_sign(signature, &auth,
        blue_consensus_ask, blue_consensus_ar, rk, entropy, digest));
    assert(memcmp(signature, blue_consensus_signature,
        sizeof signature) == 0);
    assert(verify_public_signature(generator, signature, rk,
        digest, signature + 32));
    memcpy(changed, digest, sizeof changed);
    changed[0] ^= 1u;
    assert(!verify_public_signature(generator, signature, rk,
        changed, signature + 32));
    rk[0] ^= 1u;
    assert(!blue_sapling_spend_auth_sign(signature, &auth,
        blue_consensus_ask, blue_consensus_ar, rk, entropy, digest));
    const uint8_t zero_signature[sizeof signature] = {0};
    assert(memcmp(signature, zero_signature, sizeof signature) == 0);
    const uint8_t zero_auth[sizeof auth] = {0};
    assert(memcmp(&auth, zero_auth, sizeof auth) == 0);
    blue_mod256_wipe(&auth, sizeof auth);
}

static void check_spend_auth_storage_alias(void) {
    uint8_t entropy[80], shared[64], original[64];
    for (unsigned i = 0; i < sizeof entropy; ++i)
        entropy[i] = (uint8_t)i;
    memset(shared, 0xa5, sizeof shared);
    memcpy(shared, blue_consensus_rk, sizeof blue_consensus_rk);
    shared[0] ^= 1u;
    memcpy(original, shared, sizeof original);
    blue_sapling_spend_workspace workspace;
    assert(!blue_sapling_spend_auth_sign(shared, &workspace,
        blue_consensus_ask, blue_consensus_ar, shared,
        entropy, blue_consensus_digest));
    assert(memcmp(shared, original, sizeof shared) == 0);

    union {
        blue_sapling_spend_workspace workspace;
        uint8_t bytes[sizeof(blue_sapling_spend_workspace)];
    } aliased = {0};
    memcpy(aliased.bytes, blue_consensus_ask, sizeof blue_consensus_ask);
    uint8_t ask_copy[32], signature[64];
    memcpy(ask_copy, aliased.bytes, sizeof ask_copy);
    assert(!blue_sapling_spend_auth_sign(signature, &aliased.workspace,
        aliased.bytes, blue_consensus_ar, blue_consensus_rk,
        entropy, blue_consensus_digest));
    assert(memcmp(aliased.bytes, ask_copy, sizeof ask_copy) == 0);

    uint8_t key_reply[64] = {0};
    memcpy(key_reply, blue_consensus_ask, sizeof ask_copy);
    assert(!blue_sapling_spend_auth_sign(key_reply, &workspace,
        key_reply, blue_consensus_ar, blue_consensus_rk,
        entropy, blue_consensus_digest));
    assert(memcmp(key_reply, ask_copy, sizeof ask_copy) == 0);
}

static void check_spend_auth_digest_alias(void) {
    uint8_t entropy[80], reply[64], original[64];
    for (unsigned i = 0; i < sizeof entropy; ++i)
        entropy[i] = (uint8_t)i;
    memset(reply, 0xa5, sizeof reply);
    memcpy(reply, blue_consensus_digest, sizeof blue_consensus_digest);
    memcpy(original, reply, sizeof original);
    blue_sapling_spend_workspace workspace;
    assert(!blue_sapling_spend_auth_sign(reply, &workspace,
        blue_consensus_ask, blue_consensus_ar, blue_consensus_rk,
        entropy, reply));
    assert(memcmp(reply, original, sizeof reply) == 0);
}

static void check_mapped_spend_signature(const struct jub_point *generator) {
    uint8_t wire[BLUE_SYNTHETIC_SAPLING_BYTES], digest[32], entropy[80];
    uint8_t ar[32] = {7}, rk[32], captured_rk[32], signature[64];
    for (unsigned i = 0; i < sizeof entropy; ++i) entropy[i] = (uint8_t)i;
    blue_sapling_fixture(wire);
    struct zip32_xsk master = {0}, child = {0};
    struct zip32_fvk fvk = {0};
    blue_zip32_seed_workspace node = {0};
    blue_zip32_workspace child_space = {0};
    blue_sapling_spend_workspace auth = {0};
    bool allowed = true;
    assert(blue_zip32_master_from_bip32(&master, &node,
        fixture_bip32_node, &allowed));
    assert(blue_zip32_derive_child(&child, &master,
        0x80000000u, &child_space));
    assert(blue_zip32_fvk_from_expsk(&fvk, &child.expsk));
    struct jub_point ak, ar_point, randomized;
    assert(jub_from_bytes(&ak, fvk.ak));
    jub_scalar_mul(&ar_point, generator, ar);
    jub_add(&randomized, &ak, &ar_point);
    jub_to_bytes(rk, &randomized);
    memcpy(wire + 27 + 96, rk, sizeof rk);
    replay_fixture_spend(wire, sizeof wire, captured_rk, digest);
    assert(memcmp(captured_rk, rk, sizeof rk) == 0);
    assert(blue_sapling_spend_auth_sign(signature, &auth,
        child.expsk.ask, ar, captured_rk, entropy, digest));
    assert(matches_hex32(digest,
        "44c7db79d6045d0ebddb2f3b2f3b1fefccdb19824d72d3577f4beec19303e97d"));
    assert(matches_hex32(rk,
        "14cc33d540194d86c536072eba2fb2d5cd89e552243d5804f12ed21a53cf830f"));
    assert(matches_hex32(signature,
        "d0f960eaff1d0883efdaf4972e8393fa4b08426e3b6721758c0f2e3292c71bad"));
    assert(matches_hex32(signature + 32,
        "306569f4adfe9d09e708a61efc3ac2d86e10f8e4d783a404c1453ee21dacd20b"));
    assert(verify_public_signature(generator, signature, rk,
        digest, signature + 32));
    rk[0] ^= 1u;
    assert(!blue_sapling_spend_auth_sign(signature, &auth,
        child.expsk.ask, ar, rk, entropy, digest));
    const uint8_t zero_signature[sizeof signature] = {0};
    assert(memcmp(signature, zero_signature, sizeof signature) == 0);
    const uint8_t zero_auth[sizeof auth] = {0};
    assert(memcmp(&auth, zero_auth, sizeof auth) == 0);
    memset(&auth, 0xa5, sizeof auth);
    assert(!blue_sapling_spend_auth_sign(signature, &auth,
        NULL, ar, rk, entropy, digest));
    assert(memcmp(&auth, zero_auth, sizeof auth) == 0);
    assert(memcmp(signature, zero_signature, sizeof signature) == 0);
    check_rejected_spend_randomizers(child.expsk.ask, rk,
        entropy, digest);
    blue_mod256_wipe(&master, sizeof master);
    blue_mod256_wipe(&child, sizeof child);
    blue_mod256_wipe(&fvk, sizeof fvk);
    blue_mod256_wipe(&node, sizeof node);
    blue_mod256_wipe(&child_space, sizeof child_space);
}

typedef union {
    struct zip32_xsk xsk;
    uint32_t aligned;
    uint8_t bytes[512];
} zip32_alias_area;

static void check_master_storage_overlap(void) {
    zip32_alias_area area;
    uint8_t original[sizeof area];
    memset(&area, 0xa5, sizeof area);
    memcpy(original, &area, sizeof area);
    assert(!blue_zip32_master_expsk(
        (struct zip32_expsk *)(void *)area.bytes, area.bytes + 4));
    assert(memcmp(&area, original, sizeof area) == 0);
    assert(!blue_zip32_master_xsk(&area.xsk, area.bytes + 4));
    assert(memcmp(&area, original, sizeof area) == 0);
}

static void check_bridge_storage_overlap(void) {
    zip32_alias_area area;
    uint8_t original[sizeof area];
    bool allowed = true;
    memset(&area, 0xa5, sizeof area);
    memcpy(original, &area, sizeof area);
    blue_zip32_seed_workspace *workspace = (void *)
        (area.bytes + sizeof area.xsk - 16);
    assert(!blue_zip32_master_from_bip32(&area.xsk, workspace,
        fixture_bip32_node, &allowed));
    assert(memcmp(&area, original, sizeof area) == 0);
}

static void check_viewing_key_storage_overlap(void) {
    zip32_alias_area area;
    uint8_t original[sizeof area];
    memset(&area, 0xa5, sizeof area);
    memcpy(original, &area, sizeof area);
    assert(!blue_zip32_fvk_from_expsk(
        (struct zip32_fvk *)(void *)area.bytes,
        (const struct zip32_expsk *)(const void *)(area.bytes + 4)));
    assert(memcmp(&area, original, sizeof area) == 0);
    assert(!blue_zip32_fvk_tag(
        (uint32_t *)(void *)(area.bytes + 4),
        (const struct zip32_fvk *)(const void *)area.bytes));
    assert(memcmp(&area, original, sizeof area) == 0);
}

static void check_child_storage_overlap(void) {
    zip32_alias_area area;
    struct zip32_xsk separate;
    blue_zip32_workspace scratch;
    uint8_t original[sizeof area];
    uint8_t separate_original[sizeof separate];
    uint8_t scratch_original[sizeof scratch];
    memset(&area, 0xa5, sizeof area);
    memset(&separate, 0x5a, sizeof separate);
    memset(&scratch, 0x3c, sizeof scratch);
    memcpy(original, &area, sizeof area);
    memcpy(separate_original, &separate, sizeof separate);
    memcpy(scratch_original, &scratch, sizeof scratch);
    assert(!blue_zip32_derive_child(
        (struct zip32_xsk *)(void *)(area.bytes + 4),
        &area.xsk, 1, &scratch));
    assert(memcmp(&area, original, sizeof area) == 0);
    assert(memcmp(&scratch, scratch_original, sizeof scratch) == 0);
    assert(!blue_zip32_derive_child(&separate, &area.xsk, 1,
        (blue_zip32_workspace *)(void *)(area.bytes + 4)));
    assert(memcmp(&area, original, sizeof area) == 0);
    assert(memcmp(&separate, separate_original, sizeof separate) == 0);
    assert(!blue_zip32_derive_child(&area.xsk, &separate, 1,
        (blue_zip32_workspace *)(void *)(area.bytes + 4)));
    assert(memcmp(&area, original, sizeof area) == 0);
    assert(memcmp(&separate, separate_original, sizeof separate) == 0);
}

int main(int argc, char **argv) {
    assert(argc == 2);
    check_zip32_fvk();
    check_zip32_child();
    check_zip32_seed_bridge();
    check_master_storage_overlap();
    check_bridge_storage_overlap();
    check_viewing_key_storage_overlap();
    check_child_storage_overlap();
    struct jub_point generator;
    assert(jub_from_bytes(&generator, blue_spend_generator_fixture));
    uint8_t encoded[32];
    assert(blue_jubjub_encode(encoded, &generator));
    assert(memcmp(encoded, blue_spend_generator_fixture, 32) == 0);
    struct jub_point identity;
    blue_jub_identity(&identity);
    assert(blue_jubjub_encode(encoded, &identity));
    assert(encoded[0] == 1);
    for (unsigned i = 1; i < sizeof encoded; ++i)
        assert(encoded[i] == 0);
    struct jub_point invalid = generator;
    invalid.z = (struct fr){0};
    memset(encoded, 0xa5, sizeof encoded);
    assert(!blue_jubjub_encode(encoded, &invalid));
    for (unsigned i = 0; i < sizeof encoded; ++i)
        assert(encoded[i] == 0xa5);
    check_case(&generator, 1, 7, 11);
    check_case(&generator, 23, 97, 31337);
    check_case(&generator, 0x12345678, 0xabcdef, 0x33445566);
    check_encoded_points(&generator);
    check_message_signature(&generator);
    check_response_rejection();
    check_entropy_signature_isolated(&generator);
    check_sapling_digest_signature(&generator);
    check_child_spend_signature(&generator);
    check_mapped_spend_signature(&generator);
    check_consensus_spend_signature(&generator, argv[1]);
    check_spend_auth_storage_alias();
    check_spend_auth_digest_alias();
    return 0;
}
