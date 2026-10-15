/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: MIT
 * Fixed independently implemented SHAKE256-Wrap (Daemen et al., EuroS&P 2025).
 * OD domains follow the published construction; no vendor runtime is imported. */
#include "sha3/shake_wrap.h"
#include "sha3/sha3.h"
#include "base/cleanse.h"
#include <string.h>

#define WRAP_RHO 128u
#define WRAP_INITIALIZED UINT32_C(0x57524150)
struct wrap_span { const void *pointer; size_t size; };
static bool wrap_spans_valid(const struct wrap_span *spans, size_t count)
{
    for (size_t i = 0; i < count; ++i) {
        uintptr_t start = (uintptr_t)spans[i].pointer;
        if (!spans[i].size) continue;
        if (!start || spans[i].size > UINTPTR_MAX - start) return false;
        for (size_t j = 0; j < i; ++j) {
            if (!spans[j].size) continue;
            uintptr_t prior = (uintptr_t)spans[j].pointer;
            if (start < prior + spans[j].size && prior < start + spans[i].size) return false;
        }
    }
    return true;
}
static void wrap_permute(struct shake_wrap_state *state)
{
    uint64_t lanes[25] = {0};
    for (size_t i = 0; i < 200; ++i)
        lanes[i / 8] |= (uint64_t)state->bytes[i] << (8 * (i % 8));
    sha3_keccakf_scalar(lanes);
    for (size_t i = 0; i < 200; ++i)
        state->bytes[i] = (uint8_t)(lanes[i / 8] >> (8 * (i % 8)));
    memory_cleanse(lanes, sizeof(lanes));
}
/* OD overwrites the rho bytes, pads partial blocks, and XORs a 64-bit
 * trailer. E concatenates its leading-one encoding with full-block bit.
 * SHAKE's domain separation is 0x1f in the trailer's final byte. */
static void wrap_duplex(struct shake_wrap_state *state, const uint8_t *input,
    size_t length, unsigned domain)
{
    memset(state->bytes, 0, WRAP_RHO);
    if (length) memcpy(state->bytes, input, length);
    if (length < WRAP_RHO) state->bytes[length] = 1;
    unsigned leading = domain < 2 ? 1u : 4u;
    state->bytes[WRAP_RHO] ^= (uint8_t)(domain + leading * (length == WRAP_RHO ? 2u : 1u));
    state->bytes[WRAP_RHO + 7] ^= 0x9fu;
    wrap_permute(state);
    state->offset = 0;
}
static void wrap_extract(struct shake_wrap_state *state, const uint8_t *input,
    uint8_t *output, size_t length)
{
    for (size_t i = 0; i < length; ++i)
        output[i] = state->bytes[state->offset + i] ^ input[i];
    state->offset += (uint32_t)length;
}
/* Same duplex schedule for seal/open: feedback always contains ciphertext.
 * Keep the first squeezed block distinct: without AD it is rho-tag bytes. */
static void wrap_record(struct shake_wrap_state *state, const uint8_t *ad,
    size_t ad_len, const uint8_t *input, size_t length, uint8_t *output,
    uint8_t tag[SHAKE_WRAP_TAG_SIZE], bool opening)
{
    while (ad_len > WRAP_RHO) {
        wrap_duplex(state, ad, WRAP_RHO, 5);
        ad += WRAP_RHO; ad_len -= WRAP_RHO;
    }
    if (!length) {
        wrap_duplex(state, ad, ad_len, 7);
    } else {
        size_t first_limit = WRAP_RHO - SHAKE_WRAP_TAG_SIZE;
        if (ad_len) {
            wrap_duplex(state, ad, ad_len, 5);
            first_limit = WRAP_RHO;
        }
        size_t block = length < first_limit ? length : first_limit;
        wrap_extract(state, input, output, block);
        size_t position = block;
        while (position < length) {
            const uint8_t *feedback = opening ? input : output;
            wrap_duplex(state, feedback + position - block, block, 4);
            block = length - position;
            if (block > WRAP_RHO) block = WRAP_RHO;
            wrap_extract(state, input + position, output + position, block);
            position += block;
        }
        const uint8_t *feedback = opening ? input : output;
        wrap_duplex(state, feedback + position - block, block, 6);
    }
    memcpy(tag, state->bytes, SHAKE_WRAP_TAG_SIZE);
    state->offset = SHAKE_WRAP_TAG_SIZE;
}
static bool wrap_operation_valid(struct shake_wrap_state *state,
    const uint8_t *ad, size_t ad_len, const uint8_t *input, size_t input_len,
    uint8_t *output, size_t capacity, size_t required)
{
    if (!state || ad_len > SHAKE_WRAP_MAX_AD || capacity < required) return false;
    const struct wrap_span spans[] = {{state, sizeof(*state)}, {ad, ad_len},
        {input, input_len}, {output, capacity}};
    if (!wrap_spans_valid(spans, sizeof(spans) / sizeof(spans[0]))) return false;
    return state->initialized == WRAP_INITIALIZED &&
        (state->offset == 0 || state->offset == SHAKE_WRAP_TAG_SIZE);
}
bool shake_wrap_init(struct shake_wrap_state *state, const uint8_t key[SHAKE_WRAP_KEY_SIZE])
{
    const struct wrap_span spans[] = {{state, sizeof(*state)}, {key, SHAKE_WRAP_KEY_SIZE}};
    if (!wrap_spans_valid(spans, sizeof(spans) / sizeof(spans[0]))) return false;
    struct shake_wrap_state trial = {0};
    wrap_duplex(&trial, key, SHAKE_WRAP_KEY_SIZE, 1);
    trial.initialized = WRAP_INITIALIZED;
    *state = trial;
    memory_cleanse(&trial, sizeof(trial));
    return true;
}
bool shake_wrap_seal(struct shake_wrap_state *state,
    const uint8_t *ad, size_t ad_len, const uint8_t *plaintext, size_t plaintext_len,
    uint8_t *ciphertext, size_t capacity)
{
    if (plaintext_len > SHAKE_WRAP_MAX_PLAINTEXT) return false;
    size_t written = plaintext_len + SHAKE_WRAP_TAG_SIZE;
    if (!wrap_operation_valid(state, ad, ad_len, plaintext, plaintext_len,
        ciphertext, capacity, written)) return false;
    struct shake_wrap_state trial = *state;
    wrap_record(&trial, ad, ad_len, plaintext, plaintext_len, ciphertext,
        ciphertext + plaintext_len, false);
    *state = trial;
    memory_cleanse(&trial, sizeof(trial));
    return true;
}
static bool wrap_tag_equal(const uint8_t *left, const uint8_t *right)
{
    unsigned difference = 0;
    for (size_t i = 0; i < SHAKE_WRAP_TAG_SIZE; ++i) difference |= left[i] ^ right[i];
    return difference == 0;
}
bool shake_wrap_open(struct shake_wrap_state *state,
    const uint8_t *ad, size_t ad_len, const uint8_t *ciphertext, size_t ciphertext_len,
    uint8_t *plaintext, size_t capacity)
{
    if (ciphertext_len < SHAKE_WRAP_TAG_SIZE ||
        ciphertext_len > SHAKE_WRAP_MAX_PLAINTEXT + SHAKE_WRAP_TAG_SIZE) return false;
    size_t length = ciphertext_len - SHAKE_WRAP_TAG_SIZE;
    if (!wrap_operation_valid(state, ad, ad_len, ciphertext, ciphertext_len,
        plaintext, capacity, length)) return false;
    struct shake_wrap_state trial = *state;
    uint8_t private_plaintext[SHAKE_WRAP_MAX_PLAINTEXT], tag[SHAKE_WRAP_TAG_SIZE];
    wrap_record(&trial, ad, ad_len, ciphertext, length, private_plaintext, tag, true);
    bool authenticated = wrap_tag_equal(tag, ciphertext + length);
    if (authenticated) {
        if (length) memcpy(plaintext, private_plaintext, length);
        *state = trial;
    }
    memory_cleanse(private_plaintext, sizeof(private_plaintext));
    memory_cleanse(tag, sizeof(tag));
    memory_cleanse(&trial, sizeof(trial));
    return authenticated;
}
void shake_wrap_destroy(struct shake_wrap_state *state)
{
    if (state) memory_cleanse(state, sizeof(*state));
}
