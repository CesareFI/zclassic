/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#ifndef ZCL_BLUE_SAPLING_AEAD_H
#define ZCL_BLUE_SAPLING_AEAD_H

#include <stdbool.h>
#include <stdint.h>

enum {
    BLUE_SAPLING_OUT_PLAIN_BYTES = 64,
    BLUE_SAPLING_OUT_CIPHER_BYTES = 80,
    BLUE_SAPLING_NOTE_PLAIN_BYTES = 564,
    BLUE_SAPLING_NOTE_CIPHER_BYTES = 580
};

/* Authenticate and decrypt a Sapling 80-byte outgoing ciphertext under a
 * previously derived OCK. The 64-byte result is pk_d || esk. Failure clears
 * the result. Inputs and output must be disjoint; the caller must erase the
 * OCK and result after checking epk and the note commitment. Overlap with
 * the key or ciphertext is rejected before writing either buffer. */
bool blue_sapling_out_open(uint8_t plaintext[BLUE_SAPLING_OUT_PLAIN_BYTES],
    const uint8_t key[32],
    const uint8_t ciphertext[BLUE_SAPLING_OUT_CIPHER_BYTES]);

/* Authenticate before replacing the 80-byte captured ciphertext with its
 * 64-byte outgoing plaintext. Success clears the trailing tag. Failure
 * clears all 80 bytes, except key overlap, which rejects without writes. */
bool blue_sapling_out_open_inplace(
    uint8_t ciphertext[BLUE_SAPLING_OUT_CIPHER_BYTES],
    const uint8_t key[32]);

/* Authenticate and decrypt a Sapling 580-byte note ciphertext under a
 * previously derived note key. The 564-byte result contains a leading byte,
 * diversifier, value, randomness, and memo. It is not an approved payment fact
 * until the caller verifies epk, the note commitment, and recipient policy.
 * Failure clears the result unless it overlaps an input, which is rejected
 * before writing either buffer. Buffers must be disjoint and erased by caller. */
bool blue_sapling_note_open(uint8_t plaintext[BLUE_SAPLING_NOTE_PLAIN_BYTES],
    const uint8_t key[32],
    const uint8_t ciphertext[BLUE_SAPLING_NOTE_CIPHER_BYTES]);

/* Authenticate before replacing the 580-byte captured ciphertext with its
 * 564-byte note plaintext. Success clears the trailing tag. Failure clears
 * all 580 bytes, except key overlap, which rejects without writes. */
bool blue_sapling_note_open_inplace(
    uint8_t ciphertext[BLUE_SAPLING_NOTE_CIPHER_BYTES],
    const uint8_t key[32]);

#endif
