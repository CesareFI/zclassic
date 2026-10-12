/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "blue_payment_sign.h"
#include "blue_payment_host_verify.h"
#include "zcl_host_crypto.h"

#include <openssl/core_names.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/sha.h>

#undef NDEBUG
#include <assert.h>
#include <stddef.h>
#include <string.h>

typedef struct {
    EVP_PKEY *key;
    uint8_t public_key[33];
    unsigned calls;
    bool refuse, malformed;
} signer_fixture;

static void initialize_signer(signer_fixture *fixture) {
    static char group[] = "secp256k1";
    OSSL_PARAM params[] = {
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, group,
                               sizeof group - 1),
        OSSL_PARAM_END
    };
    EVP_PKEY_CTX *context = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
    assert(context && EVP_PKEY_keygen_init(context) > 0);
    assert(EVP_PKEY_CTX_set_params(context, params) > 0);
    assert(EVP_PKEY_generate(context, &fixture->key) > 0);
    EVP_PKEY_CTX_free(context);
    uint8_t uncompressed[65];
    size_t length = 0;
    assert(EVP_PKEY_get_octet_string_param(fixture->key,
        OSSL_PKEY_PARAM_PUB_KEY, uncompressed, sizeof uncompressed,
        &length) > 0);
    assert(length == 65 && uncompressed[0] == 4);
    fixture->public_key[0] = (uint8_t)(2u | (uncompressed[64] & 1u));
    memcpy(fixture->public_key + 1, uncompressed + 1, 32);
}

static bool hash_public_key(const uint8_t public_key[33],
    uint8_t hash160[20]) {
    uint8_t first[32];
    unsigned length = 0;
    return SHA256(public_key, 33, first) != NULL &&
        EVP_Digest(first, sizeof first, hash160, &length,
                   EVP_ripemd160(), NULL) == 1 && length == 20;
}

static bool verify_host_signature(void *context,
    const uint8_t public_key[33], const uint8_t digest[32],
    const uint8_t *der, size_t der_length) {
    signer_fixture *fixture = context;
    if (memcmp(public_key, fixture->public_key, 33) != 0) return false;
    EVP_PKEY_CTX *verify = EVP_PKEY_CTX_new(fixture->key, NULL);
    bool valid = verify && EVP_PKEY_verify_init(verify) > 0 &&
        EVP_PKEY_CTX_set_signature_md(verify, EVP_sha256()) > 0 &&
        EVP_PKEY_verify(verify, der, der_length, digest, 32) == 1;
    EVP_PKEY_CTX_free(verify);
    return valid;
}

static void expect_host_rejection(const uint8_t *reply, size_t reply_length,
    const uint8_t digest[32], const uint8_t hash160[20],
    signer_fixture *signer) {
    blue_payment_verified_signature result;
    memset(&result, 0xcc, sizeof result);
    assert(!blue_payment_host_verify(reply, reply_length, 0,
        BLUE_PAYMENT_INPUT_EXTERNAL, hash160, digest, hash_public_key,
        verify_host_signature, signer, &result));
    blue_payment_verified_signature empty;
    memset(&empty, 0, sizeof empty);
    assert(memcmp(&result, &empty, sizeof result) == 0);
}

static void test_host_result_alias(const uint8_t *reply, size_t length,
    const uint8_t digest[32], const uint8_t hash160[20],
    signer_fixture *signer) {
    union {
        blue_payment_verified_signature result;
        uint8_t digest[32];
    } aliased = {0};
    memcpy(aliased.digest, digest, 32);
    assert(!blue_payment_host_verify(reply, length, 0,
        BLUE_PAYMENT_INPUT_EXTERNAL, hash160, aliased.digest,
        hash_public_key, verify_host_signature, signer, &aliased.result));
    assert(memcmp(aliased.digest, digest, 32) == 0);
}

typedef struct {
    signer_fixture *signer;
    uint8_t *changed_byte;
} mutating_verifier;

static bool verify_then_mutate(void *context, const uint8_t public_key[33],
    const uint8_t digest[32], const uint8_t *der, size_t der_length) {
    mutating_verifier *test = context;
    bool valid = verify_host_signature(test->signer, public_key, digest,
        der, der_length);
    if (valid && test->changed_byte) *test->changed_byte ^= 1;
    else if (valid) ((uint8_t *)der)[0] ^= 1;
    return valid;
}

static void test_host_callback_mutation(const uint8_t *reply, size_t length,
    const uint8_t digest[32], const uint8_t hash160[20],
    signer_fixture *signer) {
    for (unsigned target = 0; target < 4; ++target) {
        uint8_t frame[BLUE_PAYMENT_SIGN_REPLY_MAX + 2];
        uint8_t expected_digest[32], expected_hash[20];
        memcpy(frame, reply, length);
        frame[length] = 0x90;
        frame[length + 1] = 0;
        memcpy(expected_digest, digest, sizeof expected_digest);
        memcpy(expected_hash, hash160, sizeof expected_hash);
        mutating_verifier test = {.signer = signer,
            .changed_byte = target == 0 ? frame + 36 :
                target == 1 ? expected_digest :
                target == 2 ? expected_hash : NULL};
        blue_payment_verified_signature result;
        memset(&result, 0xcc, sizeof result);
        assert(!blue_payment_host_verify(frame, length + 2, 0,
            BLUE_PAYMENT_INPUT_EXTERNAL, expected_hash, expected_digest,
            hash_public_key, verify_then_mutate, &test, &result));
        blue_payment_verified_signature empty = {0};
        assert(memcmp(&result, &empty, sizeof result) == 0);
    }
}

static void test_high_s_reply(const uint8_t *reply, size_t length,
    const uint8_t digest[32], const uint8_t hash160[20],
    signer_fixture *signer) {
    const uint8_t *cursor = reply + 36;
    ECDSA_SIG *parsed = d2i_ECDSA_SIG(NULL, &cursor, reply[35]);
    assert(parsed && cursor == reply + length);
    const BIGNUM *r = NULL, *s = NULL;
    ECDSA_SIG_get0(parsed, &r, &s);
    BIGNUM *order = NULL, *high = BN_new(), *copy = BN_dup(r);
    assert(BN_hex2bn(&order,
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141")
        == 64);
    assert(high && copy && BN_sub(high, order, s) == 1);
    assert(ECDSA_SIG_set0(parsed, copy, high) == 1);
    BN_free(order);
    uint8_t frame[BLUE_PAYMENT_SIGN_REPLY_MAX + 2];
    memcpy(frame, reply, 36);
    int der_length = i2d_ECDSA_SIG(parsed, NULL);
    assert(der_length >= 8 && der_length <= BLUE_ECDSA_DER_MAX);
    uint8_t *output = frame + 36;
    assert(i2d_ECDSA_SIG(parsed, &output) == der_length);
    frame[35] = (uint8_t)der_length;
    frame[36 + der_length] = 0x90;
    frame[37 + der_length] = 0;
    assert(verify_host_signature(signer, signer->public_key, digest,
        frame + 36, (size_t)der_length));
    expect_host_rejection(frame, (size_t)der_length + 38,
        digest, hash160, signer);
    ECDSA_SIG_free(parsed);
}

static void test_host_reply(const uint8_t *reply, size_t length,
    const uint8_t digest[32], const blue_payment_owned_hashes *owned,
    signer_fixture *signer) {
    uint8_t frame[BLUE_PAYMENT_SIGN_REPLY_MAX + 2];
    memcpy(frame, reply, length);
    frame[length] = 0x90;
    frame[length + 1] = 0;
    blue_payment_verified_signature result;
    assert(blue_payment_host_verify(frame, length + 2, 0,
        BLUE_PAYMENT_INPUT_EXTERNAL, owned->external, digest,
        hash_public_key, verify_host_signature, signer, &result));
    test_host_result_alias(frame, length + 2, digest,
        owned->external, signer);
    test_host_callback_mutation(reply, length, digest,
        owned->external, signer);
    uint8_t portable_hash[20];
    assert(zcl_host_pubkey_valid(signer->public_key));
    assert(zcl_host_hash160(signer->public_key, portable_hash));
    assert(memcmp(portable_hash, owned->external,
        sizeof portable_hash) == 0);
    assert(zcl_host_verify_signature(NULL, signer->public_key,
        digest, reply + 36, reply[35]));
    blue_payment_verified_signature portable_result;
    assert(blue_payment_host_verify(frame, length + 2, 0,
        BLUE_PAYMENT_INPUT_EXTERNAL, owned->external, digest,
        zcl_host_hash160, zcl_host_verify_signature,
        NULL, &portable_result));
    assert(memcmp(&portable_result, &result, sizeof result) == 0);
    assert(result.index == 0 &&
        result.path == BLUE_PAYMENT_INPUT_EXTERNAL &&
        memcmp(result.digest, digest, 32) == 0 &&
        result.der_length == reply[35] &&
        memcmp(result.public_key, reply + 2, 33) == 0 &&
        memcmp(result.der, reply + 36, result.der_length) == 0);
    test_high_s_reply(reply, length, digest, owned->external, signer);
    expect_host_rejection(frame, length + 1, digest, owned->external, signer);
    frame[length] = 0x69;
    expect_host_rejection(frame, length + 2, digest, owned->external, signer);
    frame[length] = 0x90;
    frame[0] = 1;
    expect_host_rejection(frame, length + 2, digest, owned->external, signer);
    frame[0] = 0;
    frame[1] = BLUE_PAYMENT_INPUT_INTERNAL;
    expect_host_rejection(frame, length + 2, digest, owned->external, signer);
    frame[1] = BLUE_PAYMENT_INPUT_EXTERNAL;
    frame[35]++;
    expect_host_rejection(frame, length + 2, digest, owned->external, signer);
    frame[35]--;
    frame[36] = 0x31;
    expect_host_rejection(frame, length + 2, digest, owned->external, signer);
    frame[36] = 0x30;
    uint8_t wrong_digest[32], wrong_hash[20];
    memcpy(wrong_digest, digest, sizeof wrong_digest);
    memcpy(wrong_hash, owned->external, sizeof wrong_hash);
    wrong_digest[0] ^= 1;
    wrong_hash[0] ^= 1;
    assert(!zcl_host_verify_signature(NULL, signer->public_key,
        wrong_digest, reply + 36, reply[35]));
    expect_host_rejection(frame, length + 2, wrong_digest,
        owned->external, signer);
    expect_host_rejection(frame, length + 2, digest, wrong_hash, signer);
}

static bool sign_digest(void *context, uint8_t path,
    const uint8_t digest[32], uint8_t public_key[33],
    uint8_t signature[BLUE_ECDSA_DER_MAX], size_t *signature_length) {
    signer_fixture *fixture = context;
    ++fixture->calls;
    if (fixture->refuse || path != BLUE_PAYMENT_INPUT_EXTERNAL) return false;
    EVP_PKEY_CTX *signer = EVP_PKEY_CTX_new(fixture->key, NULL);
    *signature_length = BLUE_ECDSA_DER_MAX;
    bool valid = signer && EVP_PKEY_sign_init(signer) > 0 &&
        EVP_PKEY_CTX_set_signature_md(signer, EVP_sha256()) > 0 &&
        EVP_PKEY_sign(signer, signature, signature_length,
                      digest, 32) > 0;
    EVP_PKEY_CTX_free(signer);
    if (!valid) return false;
    memcpy(public_key, fixture->public_key, 33);
    if (fixture->malformed) signature[0] = 0x31;
    return true;
}

static void initialize_review(blue_payment_apdu *state,
    uint8_t digest[32]) {
    memset(state, 0, sizeof *state);
    static const uint8_t message[] = "reviewed transparent input 0";
    assert(SHA256(message, sizeof message - 1, digest));
    state->review.verified = true;
    state->fee_ready = true;
    state->input_count = state->bound_inputs = 1;
    state->input_zat = 400000000;
    state->output_zat = 300000000;
    state->fee_zat = 100000000;
    state->input_paths = BLUE_PAYMENT_INPUT_EXTERNAL;
    memcpy(state->input_record[0], digest, 32);
    state->input_record[0][32] = BLUE_PAYMENT_INPUT_EXTERNAL;
}

static void test_signed_reply(signer_fixture *signer,
    const blue_payment_owned_hashes *owned) {
    blue_payment_apdu state;
    uint8_t digest[32], reply[BLUE_PAYMENT_SIGN_REPLY_MAX];
    initialize_review(&state, digest);
    assert(blue_payment_apdu_touch_approve(&state));
    size_t length = 0;
    assert(blue_payment_sign_next(&state, 0, owned, sign_digest, signer,
        hash_public_key, reply, sizeof reply, &length));
    assert(length >= 44 && length <= sizeof reply);
    assert(reply[0] == 0 && reply[1] == BLUE_PAYMENT_INPUT_EXTERNAL);
    assert(memcmp(reply + 2, signer->public_key, 33) == 0);
    assert(reply[35] == length - 36);
    uint8_t normalized[BLUE_ECDSA_DER_MAX];
    size_t normalized_length = 0;
    assert(blue_ecdsa_der_low_s(reply + 36, reply[35],
        normalized, &normalized_length));
    assert(normalized_length == reply[35]);
    assert(memcmp(normalized, reply + 36, normalized_length) == 0);
    EVP_PKEY_CTX *verify = EVP_PKEY_CTX_new(signer->key, NULL);
    assert(verify && EVP_PKEY_verify_init(verify) > 0);
    assert(EVP_PKEY_CTX_set_signature_md(verify, EVP_sha256()) > 0);
    assert(EVP_PKEY_verify(verify, reply + 36, reply[35],
                           digest, sizeof digest) == 1);
    EVP_PKEY_CTX_free(verify);
    test_host_reply(reply, length, digest, owned, signer);
    assert(!state.approved && state.next_sign_index == 1);
    uint8_t zero[36] = {0};
    assert(memcmp(state.input_record[0], zero, sizeof zero) == 0);
    assert(!blue_payment_sign_next(&state, 0, owned, sign_digest, signer,
        hash_public_key, reply, sizeof reply, &length));
    assert(length == 0 && !state.fee_ready);
    assert(signer->calls == 1);
}

static void expect_failed_reply(const blue_payment_apdu *state,
    const uint8_t reply[BLUE_PAYMENT_SIGN_REPLY_MAX], size_t length) {
    assert(length == 0 && !state->fee_ready);
    blue_payment_apdu erased;
    memset(&erased, 0, sizeof erased);
    erased.review.replay.wire.failed = true;
    assert(memcmp(state, &erased, sizeof erased) == 0);
    for (size_t i = 0; i < BLUE_PAYMENT_SIGN_REPLY_MAX; ++i)
        assert(reply[i] == 0);
}

static void test_fail_closed(signer_fixture *signer,
    const blue_payment_owned_hashes *owned) {
    blue_payment_apdu state;
    uint8_t digest[32], reply[BLUE_PAYMENT_SIGN_REPLY_MAX];
    size_t length = 99;
    unsigned prior_calls = signer->calls;
    initialize_review(&state, digest);
    assert(!blue_payment_sign_next(&state, 0, owned, sign_digest, signer,
        hash_public_key, reply, sizeof reply, &length));
    expect_failed_reply(&state, reply, length);
    assert(signer->calls == prior_calls);
    initialize_review(&state, digest);
    assert(blue_payment_apdu_touch_approve(&state));
    assert(!blue_payment_sign_next(&state, 1, owned, sign_digest, signer,
        hash_public_key, reply, sizeof reply, &length));
    expect_failed_reply(&state, reply, length);
    assert(signer->calls == prior_calls);
    initialize_review(&state, digest);
    assert(blue_payment_apdu_touch_approve(&state));
    signer->refuse = true;
    assert(!blue_payment_sign_next(&state, 0, owned, sign_digest, signer,
        hash_public_key, reply, sizeof reply, &length));
    expect_failed_reply(&state, reply, length);
    signer->refuse = false;
    initialize_review(&state, digest);
    assert(blue_payment_apdu_touch_approve(&state));
    signer->malformed = true;
    assert(!blue_payment_sign_next(&state, 0, owned, sign_digest, signer,
        hash_public_key, reply, sizeof reply, &length));
    expect_failed_reply(&state, reply, length);
    signer->malformed = false;
    blue_payment_owned_hashes wrong = *owned;
    wrong.external[0] ^= 1;
    initialize_review(&state, digest);
    assert(blue_payment_apdu_touch_approve(&state));
    assert(!blue_payment_sign_next(&state, 0, &wrong, sign_digest, signer,
        hash_public_key, reply, sizeof reply, &length));
    expect_failed_reply(&state, reply, length);
}

static void test_changed_totals_after_approval(signer_fixture *signer,
    const blue_payment_owned_hashes *owned) {
    static const uint8_t request[6] = {0xa5, 0x29, 0, 0, 1, 0};
    for (unsigned field = 0; field < 4; ++field) {
        blue_payment_apdu state;
        uint8_t digest[32], reply[BLUE_PAYMENT_SIGN_REPLY_MAX];
        initialize_review(&state, digest);
        assert(blue_payment_apdu_touch_approve(&state));
        switch (field) {
        case 0: --state.input_zat; break;
        case 1: ++state.output_zat; break;
        case 2: ++state.fee_zat; break;
        default: state.own_output_zat = state.output_zat + 1; break;
        }
        memset(reply, 0xa5, sizeof reply);
        size_t length = 99;
        unsigned calls = signer->calls;
        assert(blue_payment_sign_command(&state, request,
            sizeof request, owned, sign_digest, signer,
            hash_public_key, reply, sizeof reply, &length) == 0x6985);
        assert(signer->calls == calls);
        expect_failed_reply(&state, reply, length);
    }
}

static void test_changed_totals_between_inputs(signer_fixture *signer,
    const blue_payment_owned_hashes *owned) {
    static const uint8_t first[6] = {0xa5, 0x29, 0, 0, 1, 0};
    static const uint8_t second[6] = {0xa5, 0x29, 0, 0, 1, 1};
    blue_payment_apdu state;
    uint8_t digest[32], reply[BLUE_PAYMENT_SIGN_REPLY_MAX];
    initialize_review(&state, digest);
    state.input_count = state.bound_inputs = 2;
    memcpy(state.input_record[1], digest, sizeof digest);
    state.input_record[1][0] ^= 1;
    state.input_record[1][32] = BLUE_PAYMENT_INPUT_EXTERNAL;
    assert(blue_payment_apdu_touch_approve(&state));
    size_t length = 0;
    assert(blue_payment_sign_command(&state, first, sizeof first, owned,
        sign_digest, signer, hash_public_key, reply, sizeof reply,
        &length) == 0x9000);
    assert(state.approved && state.next_sign_index == 1);
    ++state.fee_zat;
    unsigned calls = signer->calls;
    assert(blue_payment_sign_command(&state, second, sizeof second, owned,
        sign_digest, signer, hash_public_key, reply, sizeof reply,
        &length) == 0x6985);
    assert(signer->calls == calls);
    expect_failed_reply(&state, reply, length);
}

static void test_readonly_confirmation(signer_fixture *signer,
    const blue_payment_owned_hashes *owned) {
    blue_payment_apdu state;
    uint8_t digest[32];
    uint8_t frame[BLUE_PAYMENT_SIGN_REPLY_MAX] = {0xa5, 0x29, 0, 0, 1, 0};
    initialize_review(&state, digest);
    assert(blue_payment_apdu_touch_confirm(&state));
    assert(state.review_confirmed && !state.approved);
    assert(!blue_payment_apdu_touch_approve(&state));
    unsigned calls = signer->calls;
    size_t length = 99;
    assert(blue_payment_sign_command(&state, frame, 6, owned,
        sign_digest, signer, hash_public_key, frame, sizeof frame,
        &length) == 0x6985);
    assert(signer->calls == calls);
    expect_failed_reply(&state, frame, length);
}

static void test_sign_command(signer_fixture *signer,
    const blue_payment_owned_hashes *owned) {
    blue_payment_apdu state;
    uint8_t digest[32], frame[BLUE_PAYMENT_SIGN_REPLY_MAX] =
        {0xa5, 0x29, 0, 0, 1, 0};
    initialize_review(&state, digest);
    assert(blue_payment_apdu_touch_approve(&state));
    size_t length = 0;
    unsigned calls = signer->calls;
    assert(blue_payment_sign_command(&state, frame, 6, owned,
        sign_digest, signer, hash_public_key, frame, sizeof frame,
        &length) == 0x9000);
    assert(signer->calls == calls + 1 && length >= 44);
    assert(frame[0] == 0 && frame[1] == BLUE_PAYMENT_INPUT_EXTERNAL);
    EVP_PKEY_CTX *verify = EVP_PKEY_CTX_new(signer->key, NULL);
    assert(verify && EVP_PKEY_verify_init(verify) > 0);
    assert(EVP_PKEY_CTX_set_signature_md(verify, EVP_sha256()) > 0);
    assert(EVP_PKEY_verify(verify, frame + 36, frame[35],
                           digest, sizeof digest) == 1);
    EVP_PKEY_CTX_free(verify);
    static const uint8_t request[6] = {0xa5, 0x29, 0, 0, 1, 0};
    memcpy(frame, request, sizeof request);
    assert(blue_payment_sign_command(&state, frame, sizeof request, owned,
        sign_digest, signer, hash_public_key, frame, sizeof frame,
        &length) == 0x6985);
    assert(length == 0 && signer->calls == calls + 1);
    for (size_t i = 0; i < sizeof frame; ++i) assert(frame[i] == 0);
}

typedef struct {
    uint8_t prefix[8];
    size_t reply_length;
    uint8_t suffix[BLUE_PAYMENT_SIGN_REPLY_MAX];
} aliased_sign_frame;
static_assert(offsetof(aliased_sign_frame, reply_length) == 8);

static void test_aliased_reply_length(signer_fixture *signer,
    const blue_payment_owned_hashes *owned) {
    for (unsigned command = 0; command < 2; ++command) {
        blue_payment_apdu state;
        uint8_t digest[32];
        aliased_sign_frame storage = {0};
        uint8_t *frame = (uint8_t *)&storage;
        initialize_review(&state, digest);
        assert(blue_payment_apdu_touch_approve(&state));
        memcpy(frame, (uint8_t[]){0xa5, 0x29, 0, 0, 1, 0}, 6);
        storage.reply_length = 99;
        unsigned calls = signer->calls;
        if (command) {
            assert(blue_payment_sign_command(&state, frame, 6, owned,
                sign_digest, signer, hash_public_key, frame,
                BLUE_PAYMENT_SIGN_REPLY_MAX,
                &storage.reply_length) == 0x6f00);
        } else {
            assert(!blue_payment_sign_next(&state, 0, owned,
                sign_digest, signer, hash_public_key, frame,
                BLUE_PAYMENT_SIGN_REPLY_MAX, &storage.reply_length));
        }
        assert(signer->calls == calls && !state.fee_ready);
        for (size_t i = 0; i < BLUE_PAYMENT_SIGN_REPLY_MAX; ++i)
            assert(frame[i] == 0);
    }
}

static void test_aliased_sign_storage(signer_fixture *signer,
    const blue_payment_owned_hashes *owned) {
    static const uint8_t request[6] = {0xa5, 0x29, 0, 0, 1, 0};
    blue_payment_apdu state;
    uint8_t digest[32], reply[BLUE_PAYMENT_SIGN_REPLY_MAX];
    size_t length = 99;
    unsigned calls = signer->calls;
    initialize_review(&state, digest);
    assert(blue_payment_apdu_touch_approve(&state));
    memcpy(state.input_record[1], request, sizeof request);
    assert(blue_payment_sign_command(&state, state.input_record[1],
        sizeof request, owned, sign_digest, signer, hash_public_key,
        reply, sizeof reply, &length) == 0x6f00);
    assert(length == 0 && signer->calls == calls && !state.fee_ready);
    for (size_t i = 0; i < sizeof reply; ++i) assert(reply[i] == 0);

    initialize_review(&state, digest);
    assert(blue_payment_apdu_touch_approve(&state));
    length = 99;
    assert(blue_payment_sign_command(&state, request, sizeof request,
        owned, sign_digest, signer, hash_public_key, (uint8_t *)&state,
        BLUE_PAYMENT_SIGN_REPLY_MAX, &length) == 0x6f00);
    assert(length == 0 && signer->calls == calls && !state.fee_ready);

    struct {
        blue_payment_owned_hashes owned;
        uint8_t spare[BLUE_PAYMENT_SIGN_REPLY_MAX];
    } storage = {.owned = *owned};
    initialize_review(&state, digest);
    assert(blue_payment_apdu_touch_approve(&state));
    length = 99;
    assert(blue_payment_sign_command(&state, request, sizeof request,
        &storage.owned, sign_digest, signer, hash_public_key,
        (uint8_t *)&storage, BLUE_PAYMENT_SIGN_REPLY_MAX,
        &length) == 0x6f00);
    assert(length == 0 && signer->calls == calls && !state.fee_ready);
    assert(memcmp(&storage.owned, owned, sizeof *owned) == 0);
}

static void test_interrupted_two_input_signing(signer_fixture *signer,
    const blue_payment_owned_hashes *owned) {
    static const uint8_t first[6] = {0xa5, 0x29, 0, 0, 1, 0};
    static const uint8_t second[6] = {0xa5, 0x29, 0, 0, 1, 1};
    blue_payment_apdu state;
    uint8_t digest[32], reply[BLUE_PAYMENT_SIGN_REPLY_MAX];
    initialize_review(&state, digest);
    state.input_count = state.bound_inputs = 2;
    memcpy(state.input_record[1], digest, sizeof digest);
    state.input_record[1][0] ^= 1;
    state.input_record[1][32] = BLUE_PAYMENT_INPUT_EXTERNAL;
    assert(blue_payment_apdu_touch_approve(&state));
    size_t reply_length = 0;
    unsigned prior_calls = signer->calls;
    assert(blue_payment_sign_command(&state, first, sizeof first, owned,
        sign_digest, signer, hash_public_key, reply, sizeof reply,
        &reply_length) == 0x9000);
    assert(reply_length >= 44 && signer->calls == prior_calls + 1);
    assert(state.approved && state.next_sign_index == 1);
    blue_payment_apdu_abort(&state); /* USB reset or app restart. */
    memset(reply, 0xcc, sizeof reply);
    reply_length = 99;
    assert(blue_payment_sign_command(&state, second, sizeof second, owned,
        sign_digest, signer, hash_public_key, reply, sizeof reply,
        &reply_length) == 0x6985);
    assert(reply_length == 0 && signer->calls == prior_calls + 1);
    for (size_t i = 0; i < sizeof reply; ++i) assert(reply[i] == 0);
}

static void test_ordered_two_input_signing(signer_fixture *signer,
    const blue_payment_owned_hashes *owned) {
    static const uint8_t first[6] = {0xa5, 0x29, 0, 0, 1, 0};
    static const uint8_t second[6] = {0xa5, 0x29, 0, 0, 1, 1};
    blue_payment_apdu state;
    uint8_t digest[32], second_digest[32], reply[BLUE_PAYMENT_SIGN_REPLY_MAX];
    initialize_review(&state, digest);
    memcpy(second_digest, digest, sizeof digest);
    second_digest[0] ^= 1;
    state.input_count = state.bound_inputs = 2;
    memcpy(state.input_record[1], second_digest, sizeof second_digest);
    state.input_record[1][32] = BLUE_PAYMENT_INPUT_EXTERNAL;
    assert(blue_payment_apdu_touch_approve(&state));
    size_t length = 0;
    unsigned calls = signer->calls;
    assert(blue_payment_sign_command(&state, first, sizeof first, owned,
        sign_digest, signer, hash_public_key, reply, sizeof reply,
        &length) == 0x9000);
    assert(reply[0] == 0 && state.approved && state.next_sign_index == 1);
    assert(blue_payment_sign_command(&state, second, sizeof second, owned,
        sign_digest, signer, hash_public_key, reply, sizeof reply,
        &length) == 0x9000);
    assert(reply[0] == 1 && signer->calls == calls + 2 &&
        !state.approved && state.next_sign_index == 2);
    EVP_PKEY_CTX *verify = EVP_PKEY_CTX_new(signer->key, NULL);
    assert(verify && EVP_PKEY_verify_init(verify) > 0);
    assert(EVP_PKEY_CTX_set_signature_md(verify, EVP_sha256()) > 0);
    assert(EVP_PKEY_verify(verify, reply + 36, reply[35],
        second_digest, sizeof second_digest) == 1);
    EVP_PKEY_CTX_free(verify);
}

static void reject_sign_command(signer_fixture *signer,
    const blue_payment_owned_hashes *owned, const uint8_t request[6],
    size_t request_length, size_t capacity, uint16_t expected,
    bool approve) {
    blue_payment_apdu state;
    uint8_t digest[32], frame[BLUE_PAYMENT_SIGN_REPLY_MAX];
    initialize_review(&state, digest);
    if (approve) assert(blue_payment_apdu_touch_approve(&state));
    memset(frame, 0xcc, sizeof frame);
    memcpy(frame, request, 6);
    unsigned calls = signer->calls;
    size_t length = 99;
    assert(blue_payment_sign_command(&state, frame, request_length, owned,
        sign_digest, signer, hash_public_key, frame, capacity,
        &length) == expected);
    assert(calls == signer->calls && length == 0 && !state.fee_ready);
    for (size_t i = 0; i < capacity; ++i) assert(frame[i] == 0);
}

static void test_sign_command_rejections(signer_fixture *signer,
    const blue_payment_owned_hashes *owned) {
    const uint8_t valid[6] = {0xa5, 0x29, 0, 0, 1, 0};
    reject_sign_command(signer, owned, valid, 6, BLUE_PAYMENT_SIGN_REPLY_MAX,
        0x6985, false);
    reject_sign_command(signer, owned, valid, 5, BLUE_PAYMENT_SIGN_REPLY_MAX,
        0x6700, true);
    reject_sign_command(signer, owned, valid, 7, BLUE_PAYMENT_SIGN_REPLY_MAX,
        0x6700, true);
    reject_sign_command(signer, owned, valid, 6,
        BLUE_PAYMENT_SIGN_REPLY_MAX - 1, 0x6700, true);
    uint8_t malformed[6];
    memcpy(malformed, valid, sizeof malformed);
    malformed[4] = 0;
    reject_sign_command(signer, owned, malformed, 6,
        BLUE_PAYMENT_SIGN_REPLY_MAX, 0x6700, true);
    memcpy(malformed, valid, sizeof malformed);
    malformed[0] = 0xa4;
    reject_sign_command(signer, owned, malformed, 6,
        BLUE_PAYMENT_SIGN_REPLY_MAX, 0x6e00, true);
    memcpy(malformed, valid, sizeof malformed);
    malformed[1] = 0x28;
    reject_sign_command(signer, owned, malformed, 6,
        BLUE_PAYMENT_SIGN_REPLY_MAX, 0x6d00, true);
    memcpy(malformed, valid, sizeof malformed);
    malformed[2] = 1;
    reject_sign_command(signer, owned, malformed, 6,
        BLUE_PAYMENT_SIGN_REPLY_MAX, 0x6b00, true);
    memcpy(malformed, valid, sizeof malformed);
    malformed[3] = 1;
    reject_sign_command(signer, owned, malformed, 6,
        BLUE_PAYMENT_SIGN_REPLY_MAX, 0x6b00, true);
    memcpy(malformed, valid, sizeof malformed);
    malformed[5] = 1;
    reject_sign_command(signer, owned, malformed, 6,
        BLUE_PAYMENT_SIGN_REPLY_MAX, 0x6985, true);
}

static void test_wrong_indices(signer_fixture *signer,
    const blue_payment_owned_hashes *owned) {
    uint8_t request[6] = {0xa5, 0x29, 0, 0, 1, 0};
    for (unsigned index = 1; index <= UINT8_MAX; ++index) {
        request[5] = (uint8_t)index;
        reject_sign_command(signer, owned, request, sizeof request,
            BLUE_PAYMENT_SIGN_REPLY_MAX, 0x6985, true);
    }
}

static void test_malformed_command_fuzz(signer_fixture *signer,
    const blue_payment_owned_hashes *owned) {
    uint32_t random = 0x75c10d23;
    const uint8_t valid[6] = {0xa5, 0x29, 0, 0, 1, 0};
    for (unsigned trial = 0; trial < 10000; ++trial) {
        uint8_t request[8];
        for (size_t i = 0; i < sizeof request; ++i) {
            random = random * 1664525u + 1013904223u;
            request[i] = (uint8_t)(random >> 24);
        }
        size_t length = random % (sizeof request + 1);
        if (length == 6 && memcmp(request, valid, 6) == 0)
            request[5] = 1;
        blue_payment_apdu state;
        uint8_t digest[32], frame[BLUE_PAYMENT_SIGN_REPLY_MAX];
        initialize_review(&state, digest);
        assert(blue_payment_apdu_touch_approve(&state));
        memset(frame, 0xcc, sizeof frame);
        memcpy(frame, request, sizeof request);
        size_t reply_length = 99;
        unsigned calls = signer->calls;
        assert(blue_payment_sign_command(&state, frame, length, owned,
            sign_digest, signer, hash_public_key, frame, sizeof frame,
            &reply_length) != 0x9000);
        assert(reply_length == 0 && signer->calls == calls);
        assert(!state.fee_ready);
        for (size_t i = 0; i < sizeof frame; ++i)
            assert(frame[i] == 0);
    }
}

int main(void) {
    signer_fixture signer = {0};
    initialize_signer(&signer);
    blue_payment_owned_hashes owned = {0};
    assert(hash_public_key(signer.public_key, owned.external));
    test_signed_reply(&signer, &owned);
    test_fail_closed(&signer, &owned);
    test_changed_totals_after_approval(&signer, &owned);
    test_changed_totals_between_inputs(&signer, &owned);
    test_readonly_confirmation(&signer, &owned);
    test_sign_command(&signer, &owned);
    test_aliased_reply_length(&signer, &owned);
    test_aliased_sign_storage(&signer, &owned);
    test_interrupted_two_input_signing(&signer, &owned);
    test_ordered_two_input_signing(&signer, &owned);
    test_sign_command_rejections(&signer, &owned);
    test_wrong_indices(&signer, &owned);
    test_malformed_command_fuzz(&signer, &owned);
    EVP_PKEY_free(signer.key);
    return 0;
}
