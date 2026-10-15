/* purpose: Define fixed SHAKE256-Wrap record protection with transactional refusal semantics. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: MIT */
#ifndef ZCL_SHA3_SHAKE_WRAP_H
#define ZCL_SHA3_SHAKE_WRAP_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define SHAKE_WRAP_KEY_SIZE 32u
#define SHAKE_WRAP_TAG_SIZE 64u
#define SHAKE_WRAP_MAX_PLAINTEXT 4096u
#define SHAKE_WRAP_MAX_AD 4096u

/* Fixed published SHAKE256-Wrap: rho=128, c=512, full Keccak-f[1600].
 * A state owns secrets; do not serialize, log, or share it concurrently.
 * Sender/receiver maintain separate states with matching ordered records.
 * No nonce, transport, replay policy, provisioning, or forward secrecy is
 * supplied here. For real use, a caller must provide unique initial AD
 * (including a session nonce) for every independent stream under a key, and
 * distinguish directional keys/contexts. The primitive does not enforce that
 * protocol obligation. This profile makes no 256-bit quantum security claim. */
struct shake_wrap_state {
    uint8_t bytes[200];
    uint32_t offset;
    uint32_t initialized;
};

/* All nonempty spans must be valid independently owned objects, pairwise
 * disjoint (state, AD, input, and the entire output capacity). init's key and
 * state must also be disjoint. NULL is allowed only for a zero-length span.
 * init replaces a fresh/unshared state; invalid init leaves it unchanged.
 * seal writes plaintext_len+TAG_SIZE bytes. open writes ciphertext_len-TAG_SIZE
 * bytes only after tag verification. Capacity may exceed the written length.
 * Every refusal leaves original state and caller output unchanged. Successful
 * records advance state, including empty plaintext records. All trial state
 * and private plaintext are cleansed. destroy accepts NULL and wipes state.
 * Caller retains exclusive lifetime and storage custody throughout each call. */
bool shake_wrap_init(struct shake_wrap_state *state, const uint8_t key[SHAKE_WRAP_KEY_SIZE]);
bool shake_wrap_seal(struct shake_wrap_state *state,
    const uint8_t *ad, size_t ad_len, const uint8_t *plaintext, size_t plaintext_len,
    uint8_t *ciphertext, size_t capacity);
bool shake_wrap_open(struct shake_wrap_state *state,
    const uint8_t *ad, size_t ad_len, const uint8_t *ciphertext, size_t ciphertext_len,
    uint8_t *plaintext, size_t capacity);
void shake_wrap_destroy(struct shake_wrap_state *state);
#endif
