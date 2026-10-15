/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "test/test_core.h"
#include "sha3/shake_wrap.h"
#include "crypto/sha256.h"
#include "base/hex.h"
#include <stdio.h>
#include <string.h>

struct wrap_vector { unsigned mode; size_t index, ad_len, plaintext_len; const char *digest; };
#include "test_shake_wrap_vectors.h"
static void wrap_test_key(uint8_t key[SHAKE_WRAP_KEY_SIZE])
{
    for (size_t i = 0; i < SHAKE_WRAP_KEY_SIZE; ++i) key[i] = (uint8_t)i;
}
static bool wrap_vector_record(const struct wrap_vector *vector,
    struct shake_wrap_state *sender, struct shake_wrap_state *receiver)
{
    uint8_t ad[4096], plaintext[4096], ciphertext[4160], output[4096], sentinel[4096];
    for (size_t i = 0; i < sizeof(ad); ++i) {
        ad[i] = (uint8_t)(i * 7 + vector->index + 1);
        plaintext[i] = (uint8_t)(i * 13 + vector->index + 3);
    }
    if (!shake_wrap_seal(sender, ad, vector->ad_len, plaintext, vector->plaintext_len,
        ciphertext, sizeof(ciphertext))) return false;
    struct sha256_ctx digest;
    uint8_t bytes[32]; char hex[65];
    sha256_init(&digest);
    sha256_write(&digest, ciphertext, vector->plaintext_len + SHAKE_WRAP_TAG_SIZE);
    sha256_finalize(&digest, bytes); zcl_hex_encode(bytes, sizeof(bytes), hex);
    if (strcmp(hex, vector->digest)) {
        fprintf(stderr, "Wrap oracle mismatch mode=%u index=%zu AD=%zu P=%zu actual=%s\n",
            vector->mode, vector->index, vector->ad_len, vector->plaintext_len, hex);
        return false;
    }
    struct shake_wrap_state before = *receiver;
    memset(output, 0xa5, sizeof(output)); memcpy(sentinel, output, sizeof(output));
    ciphertext[vector->plaintext_len + SHAKE_WRAP_TAG_SIZE - 1] ^= 1;
    bool rejected = !shake_wrap_open(receiver, ad, vector->ad_len, ciphertext,
        vector->plaintext_len + SHAKE_WRAP_TAG_SIZE, output, sizeof(output));
    if (!rejected || memcmp(receiver, &before, sizeof(before)) ||
        memcmp(output, sentinel, sizeof(output))) return false;
    ciphertext[vector->plaintext_len + SHAKE_WRAP_TAG_SIZE - 1] ^= 1;
    if (!shake_wrap_open(receiver, ad, vector->ad_len, ciphertext,
        vector->plaintext_len + SHAKE_WRAP_TAG_SIZE, output, sizeof(output))) return false;
    return !memcmp(output, plaintext, vector->plaintext_len) && !memcmp(sender, receiver, sizeof(*sender));
}
static int wrap_oracle_vectors(void)
{
    int failures = 0;
    uint8_t key[SHAKE_WRAP_KEY_SIZE]; wrap_test_key(key);
    struct shake_wrap_state sender = {0}, receiver = {0};
    TEST_CASE("SHAKE256-Wrap: independent 392 fresh and chained oracle records with authenticated continuation") {
        ASSERT_EQ(sizeof(wrap_vectors) / sizeof(wrap_vectors[0]), 392);
        for (size_t i = 0; i < sizeof(wrap_vectors) / sizeof(wrap_vectors[0]); ++i) {
            const struct wrap_vector *vector = &wrap_vectors[i];
            if (!vector->mode || !vector->index) {
                ASSERT(shake_wrap_init(&sender, key));
                ASSERT(shake_wrap_init(&receiver, key));
            }
            ASSERT(wrap_vector_record(vector, &sender, &receiver));
        }
    } TEST_END
    shake_wrap_destroy(&sender); shake_wrap_destroy(&receiver);
    return failures;
}
/* Snapshot complete state/output, not merely an ok flag or plaintext prefix. */
static bool wrap_refuses_unchanged(struct shake_wrap_state *state,
    const uint8_t *ad, size_t ad_len, const uint8_t *ciphertext, size_t length)
{
    struct shake_wrap_state before = *state;
    uint8_t output[4096], sentinel[4096];
    memset(output, 0x6d, sizeof(output)); memcpy(sentinel, output, sizeof(output));
    bool ok = shake_wrap_open(state, ad, ad_len, ciphertext, length, output, sizeof(output));
    return !ok && !memcmp(state, &before, sizeof(before)) && !memcmp(output, sentinel, sizeof(output));
}
static int wrap_authentication_refusals(void)
{
    int failures = 0;
    uint8_t key[32], ad[129], plaintext[257], ciphertext[321];
    wrap_test_key(key); memset(ad, 0x17, sizeof(ad)); memset(plaintext, 0x29, sizeof(plaintext));
    struct shake_wrap_state sender = {0}, receiver = {0}, wrong_key = {0};
    TEST_CASE("SHAKE256-Wrap: key, AD, ciphertext, every tag byte and record geometry refuse before release") {
        ASSERT(shake_wrap_init(&sender, key)); ASSERT(shake_wrap_init(&receiver, key));
        ASSERT(shake_wrap_seal(&sender, ad, sizeof(ad), plaintext, sizeof(plaintext), ciphertext, sizeof(ciphertext)));
        key[0] ^= 1; ASSERT(shake_wrap_init(&wrong_key, key));
        ASSERT(wrap_refuses_unchanged(&wrong_key, ad, sizeof(ad), ciphertext, sizeof(ciphertext)));
        ad[128] ^= 1; ASSERT(wrap_refuses_unchanged(&receiver, ad, sizeof(ad), ciphertext, sizeof(ciphertext))); ad[128] ^= 1;
        ciphertext[128] ^= 1; ASSERT(wrap_refuses_unchanged(&receiver, ad, sizeof(ad), ciphertext, sizeof(ciphertext))); ciphertext[128] ^= 1;
        for (size_t i = sizeof(plaintext); i < sizeof(ciphertext); ++i) {
            ciphertext[i] ^= 1;
            ASSERT(wrap_refuses_unchanged(&receiver, ad, sizeof(ad), ciphertext, sizeof(ciphertext)));
            ciphertext[i] ^= 1;
        }
        ASSERT(wrap_refuses_unchanged(&receiver, ad, sizeof(ad) - 1, ciphertext, sizeof(ciphertext)));
        ASSERT(wrap_refuses_unchanged(&receiver, ad, sizeof(ad), ciphertext, sizeof(ciphertext) - 1));
        uint8_t output[257];
        ASSERT(shake_wrap_open(&receiver, ad, sizeof(ad), ciphertext, sizeof(ciphertext), output, sizeof(output)));
        ASSERT(!memcmp(output, plaintext, sizeof(output)));
        /* A record cannot authenticate again in the advanced chaining state. */
        ASSERT(wrap_refuses_unchanged(&receiver, ad, sizeof(ad), ciphertext, sizeof(ciphertext)));
    } TEST_END
    shake_wrap_destroy(&sender); shake_wrap_destroy(&receiver); shake_wrap_destroy(&wrong_key);
    return failures;
}
struct wrap_invalid_case { const uint8_t *ad; size_t ad_len; const uint8_t *input; size_t input_len; uint8_t *output; size_t capacity; };
static int wrap_seal_bounds(void)
{
    int failures = 0;
    uint8_t key[32], input[4097], ad[4097], output[4160];
    wrap_test_key(key); memset(input, 0x21, sizeof(input)); memset(ad, 0x43, sizeof(ad)); memset(output, 0x65, sizeof(output));
    struct shake_wrap_state state = {0};
    TEST_CASE("SHAKE256-Wrap: seal bounds, NULLs and every storage overlap preserve all caller bytes") {
        ASSERT(shake_wrap_init(&state, key));
        struct shake_wrap_state before = state;
        const struct wrap_invalid_case cases[] = {
            {ad, 1, input, 4097, output, sizeof(output)}, {ad, 4097, input, 1, output, sizeof(output)},
            {NULL, 1, input, 1, output, sizeof(output)}, {ad, 1, NULL, 1, output, sizeof(output)},
            {ad, 1, input, 1, NULL, 65}, {ad, 1, input, 1, output, 64},
            {ad, 1, input, 1, output, SIZE_MAX}, {ad, 1, input, 1, input, sizeof(input)},
            {ad, 1, input, 1, ad, sizeof(ad)}, {input, 1, input, 1, output, sizeof(output)},
            {state.bytes, 1, input, 1, output, sizeof(output)}, {ad, 1, state.bytes, 1, output, sizeof(output)},
            {ad, 1, input, 1, state.bytes, sizeof(state.bytes)},
        };
        uint8_t saved_input[4097], saved_ad[4097], saved_output[4160];
        memcpy(saved_input, input, sizeof(input)); memcpy(saved_ad, ad, sizeof(ad)); memcpy(saved_output, output, sizeof(output));
        for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
            const struct wrap_invalid_case *c = &cases[i];
            ASSERT(!shake_wrap_seal(&state, c->ad, c->ad_len, c->input, c->input_len, c->output, c->capacity));
            ASSERT(!memcmp(&state, &before, sizeof(state)));
            ASSERT(!memcmp(input, saved_input, sizeof(input))); ASSERT(!memcmp(ad, saved_ad, sizeof(ad)));
            ASSERT(!memcmp(output, saved_output, sizeof(output)));
        }
        ASSERT(!shake_wrap_init(&state, state.bytes)); ASSERT(!memcmp(&state, &before, sizeof(state)));
        ASSERT(!shake_wrap_init(&state, NULL)); ASSERT(!memcmp(&state, &before, sizeof(state)));
        ASSERT(!shake_wrap_init(NULL, key));
        uint8_t shared[256], saved_shared[256];
        memset(shared, 0x87, sizeof(shared)); memcpy(saved_shared, shared, sizeof(shared));
        /* Written output would end at 65; the capacity overlaps AD at 160. */
        ASSERT(!shake_wrap_seal(&state, shared + 160, 1, input, 1, shared, 192));
        ASSERT(!memcmp(shared, saved_shared, sizeof(shared)));
        ASSERT(!memcmp(&state, &before, sizeof(state)));
    } TEST_END
    shake_wrap_destroy(&state);
    return failures;
}
static int wrap_open_bounds(void)
{
    int failures = 0;
    uint8_t key[32], plaintext[128], ad[128], ciphertext[192], output[128];
    wrap_test_key(key); memset(plaintext, 0x21, sizeof(plaintext)); memset(ad, 0x43, sizeof(ad)); memset(output, 0x65, sizeof(output));
    struct shake_wrap_state sender = {0}, state = {0};
    TEST_CASE("SHAKE256-Wrap: open bounds and aliases refuse without changing ciphertext, AD, output or state") {
        ASSERT(shake_wrap_init(&sender, key)); ASSERT(shake_wrap_init(&state, key));
        ASSERT(shake_wrap_seal(&sender, ad, sizeof(ad), plaintext, sizeof(plaintext), ciphertext, sizeof(ciphertext)));
        const struct wrap_invalid_case cases[] = {
            {ad, sizeof(ad), ciphertext, 63, output, sizeof(output)},
            {ad, sizeof(ad), ciphertext, 4161, output, sizeof(output)},
            {ad, 4097, ciphertext, sizeof(ciphertext), output, sizeof(output)},
            {NULL, 1, ciphertext, sizeof(ciphertext), output, sizeof(output)},
            {ad, sizeof(ad), NULL, sizeof(ciphertext), output, sizeof(output)},
            {ad, sizeof(ad), ciphertext, sizeof(ciphertext), NULL, sizeof(output)},
            {ad, sizeof(ad), ciphertext, sizeof(ciphertext), output, sizeof(output) - 1},
            {ad, sizeof(ad), ciphertext, sizeof(ciphertext), ciphertext, sizeof(ciphertext)},
            {ad, sizeof(ad), ciphertext, sizeof(ciphertext), ad, sizeof(ad)},
            {ciphertext, 1, ciphertext, sizeof(ciphertext), output, sizeof(output)},
            {state.bytes, 1, ciphertext, sizeof(ciphertext), output, sizeof(output)},
            {ad, sizeof(ad), state.bytes, sizeof(ciphertext), output, sizeof(output)},
            {ad, sizeof(ad), ciphertext, sizeof(ciphertext), state.bytes, sizeof(state.bytes)},
        };
        struct shake_wrap_state before = state;
        uint8_t saved_c[192], saved_ad[128], saved_output[128];
        memcpy(saved_c, ciphertext, sizeof(ciphertext)); memcpy(saved_ad, ad, sizeof(ad)); memcpy(saved_output, output, sizeof(output));
        for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
            const struct wrap_invalid_case *c = &cases[i];
            ASSERT(!shake_wrap_open(&state, c->ad, c->ad_len, c->input, c->input_len, c->output, c->capacity));
            ASSERT(!memcmp(&state, &before, sizeof(state))); ASSERT(!memcmp(ciphertext, saved_c, sizeof(ciphertext)));
            ASSERT(!memcmp(ad, saved_ad, sizeof(ad))); ASSERT(!memcmp(output, saved_output, sizeof(output)));
        }
    } TEST_END
    shake_wrap_destroy(&sender); shake_wrap_destroy(&state);
    return failures;
}
static int wrap_empty_and_destroy(void)
{
    int failures = 0;
    uint8_t key[32], ciphertext[64]; wrap_test_key(key);
    struct shake_wrap_state sender = {0}, receiver = {0}, zero = {0};
    TEST_CASE("SHAKE256-Wrap: explicit empty spans authenticate and destroy wipes the complete state") {
        ASSERT(!shake_wrap_seal(&sender, NULL, 0, NULL, 0, ciphertext, sizeof(ciphertext)));
        ASSERT(shake_wrap_init(&sender, key)); ASSERT(shake_wrap_init(&receiver, key));
        ASSERT(shake_wrap_seal(&sender, NULL, 0, NULL, 0, ciphertext, sizeof(ciphertext)));
        ASSERT(shake_wrap_open(&receiver, NULL, 0, ciphertext, sizeof(ciphertext), NULL, 0));
        ASSERT(!memcmp(&sender, &receiver, sizeof(sender)));
        shake_wrap_destroy(&sender); shake_wrap_destroy(&receiver); shake_wrap_destroy(NULL);
        ASSERT(!memcmp(&sender, &zero, sizeof(sender))); ASSERT(!memcmp(&receiver, &zero, sizeof(receiver)));
        ASSERT(!shake_wrap_open(&receiver, NULL, 0, ciphertext, sizeof(ciphertext), NULL, 0));
        ASSERT(shake_wrap_init(&receiver, key));
        receiver.offset = 65;
        struct shake_wrap_state corrupted = receiver;
        ASSERT(!shake_wrap_open(&receiver, NULL, 0, ciphertext, sizeof(ciphertext), NULL, 0));
        ASSERT(!memcmp(&receiver, &corrupted, sizeof(receiver)));
        receiver.offset = 0; receiver.initialized ^= 1;
        corrupted = receiver;
        ASSERT(!shake_wrap_open(&receiver, NULL, 0, ciphertext, sizeof(ciphertext), NULL, 0));
        ASSERT(!memcmp(&receiver, &corrupted, sizeof(receiver)));
    } TEST_END
    shake_wrap_destroy(&sender); shake_wrap_destroy(&receiver);
    return failures;
}
int test_shake_wrap(void);
int test_shake_wrap(void)
{
    int failures = wrap_oracle_vectors();
    failures += wrap_authentication_refusals(); failures += wrap_seal_bounds();
    failures += wrap_open_bounds(); failures += wrap_empty_and_destroy();
    return failures;
}
