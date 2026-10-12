/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0.
 * Fixed-size embedded form of Z23's C23 ChaCha20-Poly1305 arithmetic.
 * Sapling outgoing and note plaintexts have fixed sizes, no associated data,
 * and a zero nonce; this form needs no allocator, threads, or logging. */
#include "blue_sapling_aead.h"

#include <stddef.h>
#include <string.h>

#if !defined(__STDC_VERSION__) || __STDC_VERSION__ < 202311L
#error "The Blue Sapling decryptor requires ISO C23"
#endif

static void wipe(void *memory, size_t length) {
    volatile uint8_t *bytes = memory;
    for (size_t i = 0; i < length; ++i) bytes[i] = 0;
}

static bool overlaps(const void *left, size_t left_length,
    const void *right, size_t right_length) {
    uintptr_t a = (uintptr_t)left, b = (uintptr_t)right;
    return a <= b ? b - a < left_length : a - b < right_length;
}

static uint32_t load32(const uint8_t bytes[4]) {
    return (uint32_t)bytes[0] | (uint32_t)bytes[1] << 8 |
        (uint32_t)bytes[2] << 16 | (uint32_t)bytes[3] << 24;
}

static void store32(uint8_t bytes[4], uint32_t word) {
    for (unsigned i = 0; i < 4; ++i)
        bytes[i] = (uint8_t)(word >> (8u * i));
}

static uint32_t rotate(uint32_t word, unsigned shift) {
    return (word << shift) | (word >> (32u - shift));
}

#define QR(a, b, c, d) \
    (a) += (b); (d) = rotate((d) ^ (a), 16); \
    (c) += (d); (b) = rotate((b) ^ (c), 12); \
    (a) += (b); (d) = rotate((d) ^ (a), 8); \
    (c) += (d); (b) = rotate((b) ^ (c), 7)

static void chacha_block(const uint8_t key[32], uint32_t counter,
    uint8_t output[64]) {
    uint32_t state[16] = {0x61707865u, 0x3320646eu,
        0x79622d32u, 0x6b206574u};
    for (unsigned i = 0; i < 8; ++i) state[4 + i] = load32(key + 4 * i);
    state[12] = counter;
    uint32_t working[16];
    memcpy(working, state, sizeof working);
    for (unsigned i = 0; i < 10; ++i) {
        QR(working[0], working[4], working[8], working[12]);
        QR(working[1], working[5], working[9], working[13]);
        QR(working[2], working[6], working[10], working[14]);
        QR(working[3], working[7], working[11], working[15]);
        QR(working[0], working[5], working[10], working[15]);
        QR(working[1], working[6], working[11], working[12]);
        QR(working[2], working[7], working[8], working[13]);
        QR(working[3], working[4], working[9], working[14]);
    }
    for (unsigned i = 0; i < 16; ++i)
        store32(output + 4 * i, working[i] + state[i]);
    wipe(working, sizeof working);
    wipe(state, sizeof state);
}

#undef QR

typedef struct {
    uint32_t r[5], h[5], pad[4];
} poly_state;

static void poly_init(poly_state *state, const uint8_t key[32]) {
    state->r[0] = load32(key) & 0x3ffffffu;
    state->r[1] = (load32(key + 3) >> 2) & 0x3ffff03u;
    state->r[2] = (load32(key + 6) >> 4) & 0x3ffc0ffu;
    state->r[3] = (load32(key + 9) >> 6) & 0x3f03fffu;
    state->r[4] = (load32(key + 12) >> 8) & 0x00fffffu;
    memset(state->h, 0, sizeof state->h);
    for (unsigned i = 0; i < 4; ++i)
        state->pad[i] = load32(key + 16 + 4 * i);
}

static void poly_blocks(poly_state *state, const uint8_t *data,
    size_t length) {
    uint32_t r0 = state->r[0], r1 = state->r[1], r2 = state->r[2];
    uint32_t r3 = state->r[3], r4 = state->r[4];
    uint32_t s1 = r1 * 5u, s2 = r2 * 5u, s3 = r3 * 5u, s4 = r4 * 5u;
    uint32_t h0 = state->h[0], h1 = state->h[1], h2 = state->h[2];
    uint32_t h3 = state->h[3], h4 = state->h[4];
    while (length >= 16) {
        h0 += load32(data) & 0x3ffffffu;
        h1 += (load32(data + 3) >> 2) & 0x3ffffffu;
        h2 += (load32(data + 6) >> 4) & 0x3ffffffu;
        h3 += (load32(data + 9) >> 6) & 0x3ffffffu;
        h4 += (load32(data + 12) >> 8) | (1u << 24);
        uint64_t d0 = (uint64_t)h0*r0 + (uint64_t)h1*s4 +
            (uint64_t)h2*s3 + (uint64_t)h3*s2 + (uint64_t)h4*s1;
        uint64_t d1 = (uint64_t)h0*r1 + (uint64_t)h1*r0 +
            (uint64_t)h2*s4 + (uint64_t)h3*s3 + (uint64_t)h4*s2;
        uint64_t d2 = (uint64_t)h0*r2 + (uint64_t)h1*r1 +
            (uint64_t)h2*r0 + (uint64_t)h3*s4 + (uint64_t)h4*s3;
        uint64_t d3 = (uint64_t)h0*r3 + (uint64_t)h1*r2 +
            (uint64_t)h2*r1 + (uint64_t)h3*r0 + (uint64_t)h4*s4;
        uint64_t d4 = (uint64_t)h0*r4 + (uint64_t)h1*r3 +
            (uint64_t)h2*r2 + (uint64_t)h3*r1 + (uint64_t)h4*r0;
        uint32_t carry;
        carry = (uint32_t)(d0 >> 26); h0 = (uint32_t)d0 & 0x3ffffffu; d1 += carry;
        carry = (uint32_t)(d1 >> 26); h1 = (uint32_t)d1 & 0x3ffffffu; d2 += carry;
        carry = (uint32_t)(d2 >> 26); h2 = (uint32_t)d2 & 0x3ffffffu; d3 += carry;
        carry = (uint32_t)(d3 >> 26); h3 = (uint32_t)d3 & 0x3ffffffu; d4 += carry;
        carry = (uint32_t)(d4 >> 26); h4 = (uint32_t)d4 & 0x3ffffffu;
        h0 += carry * 5u;
        carry = h0 >> 26; h0 &= 0x3ffffffu; h1 += carry;
        data += 16;
        length -= 16;
    }
    state->h[0] = h0; state->h[1] = h1; state->h[2] = h2;
    state->h[3] = h3; state->h[4] = h4;
}

static void poly_finish(poly_state *state, uint8_t tag[16]) {
    uint32_t h0 = state->h[0], h1 = state->h[1], h2 = state->h[2];
    uint32_t h3 = state->h[3], h4 = state->h[4];
    uint32_t carry;
    carry = h1 >> 26; h1 &= 0x3ffffffu; h2 += carry;
    carry = h2 >> 26; h2 &= 0x3ffffffu; h3 += carry;
    carry = h3 >> 26; h3 &= 0x3ffffffu; h4 += carry;
    carry = h4 >> 26; h4 &= 0x3ffffffu; h0 += carry * 5u;
    carry = h0 >> 26; h0 &= 0x3ffffffu; h1 += carry;
    uint32_t g0 = h0 + 5u; carry = g0 >> 26; g0 &= 0x3ffffffu;
    uint32_t g1 = h1 + carry; carry = g1 >> 26; g1 &= 0x3ffffffu;
    uint32_t g2 = h2 + carry; carry = g2 >> 26; g2 &= 0x3ffffffu;
    uint32_t g3 = h3 + carry; carry = g3 >> 26; g3 &= 0x3ffffffu;
    uint32_t g4 = h4 + carry - (1u << 26);
    uint32_t mask = (g4 >> 31) - 1u;
    g0 &= mask; g1 &= mask; g2 &= mask; g3 &= mask; g4 &= mask;
    mask = ~mask;
    h0 = (h0 & mask) | g0;
    h1 = (h1 & mask) | g1;
    h2 = (h2 & mask) | g2;
    h3 = (h3 & mask) | g3;
    h4 = (h4 & mask) | g4;
    h0 |= h1 << 26;
    h1 = (h1 >> 6) | (h2 << 20);
    h2 = (h2 >> 12) | (h3 << 14);
    h3 = (h3 >> 18) | (h4 << 8);
    uint64_t word;
    word = (uint64_t)h0 + state->pad[0]; h0 = (uint32_t)word;
    word = (uint64_t)h1 + state->pad[1] + (word >> 32); h1 = (uint32_t)word;
    word = (uint64_t)h2 + state->pad[2] + (word >> 32); h2 = (uint32_t)word;
    word = (uint64_t)h3 + state->pad[3] + (word >> 32); h3 = (uint32_t)word;
    store32(tag, h0); store32(tag + 4, h1);
    store32(tag + 8, h2); store32(tag + 12, h3);
}

static bool authentic(const uint8_t key[32],
    const uint8_t *ciphertext, size_t plain_length) {
    uint8_t block[64], tag[16], tail[16] = {0}, lengths[16] = {0};
    poly_state state;
    chacha_block(key, 0, block);
    poly_init(&state, block);
    size_t full = plain_length & ~(size_t)15;
    poly_blocks(&state, ciphertext, full);
    size_t remaining = plain_length - full;
    if (remaining) {
        memcpy(tail, ciphertext + full, remaining);
        poly_blocks(&state, tail, sizeof tail);
    }
    for (unsigned i = 0; i < 8; ++i)
        lengths[8 + i] = (uint8_t)((uint64_t)plain_length >> (8u * i));
    poly_blocks(&state, lengths, sizeof lengths);
    poly_finish(&state, tag);
    uint8_t difference = 0;
    for (unsigned i = 0; i < 16; ++i)
        difference |= tag[i] ^ ciphertext[plain_length + i];
    wipe(&state, sizeof state);
    wipe(block, sizeof block);
    wipe(tag, sizeof tag);
    wipe(tail, sizeof tail);
    return difference == 0;
}

static void decrypt(uint8_t *plaintext, const uint8_t key[32],
    const uint8_t *ciphertext, size_t plain_length) {
    uint8_t block[64];
    for (size_t offset = 0; offset < plain_length; offset += 64) {
        chacha_block(key, 1u + (uint32_t)(offset / 64), block);
        size_t take = plain_length - offset < 64 ?
            plain_length - offset : 64;
        for (size_t i = 0; i < take; ++i)
            plaintext[offset + i] = ciphertext[offset + i] ^ block[i];
    }
    wipe(block, sizeof block);
}

static bool open(uint8_t *plaintext, size_t plain_length,
    const uint8_t key[32], const uint8_t *ciphertext) {
    if (!plaintext) return false;
    if ((key && overlaps(plaintext, plain_length, key, 32)) ||
        (ciphertext && overlaps(plaintext, plain_length, ciphertext,
            plain_length + 16))) return false;
    memset(plaintext, 0, plain_length);
    if (!key || !ciphertext || !authentic(key, ciphertext, plain_length))
        return false;
    decrypt(plaintext, key, ciphertext, plain_length);
    return true;
}

static bool open_inplace(uint8_t *ciphertext, size_t plain_length,
    const uint8_t key[32]) {
    if (!ciphertext) return false;
    size_t total = plain_length + 16;
    if (key && overlaps(ciphertext, total, key, 32)) return false;
    if (!key || !authentic(key, ciphertext, plain_length)) {
        wipe(ciphertext, total);
        return false;
    }
    decrypt(ciphertext, key, ciphertext, plain_length);
    wipe(ciphertext + plain_length, 16);
    return true;
}

bool blue_sapling_out_open(uint8_t plaintext[BLUE_SAPLING_OUT_PLAIN_BYTES],
    const uint8_t key[32],
    const uint8_t ciphertext[BLUE_SAPLING_OUT_CIPHER_BYTES]) {
    return open(plaintext, BLUE_SAPLING_OUT_PLAIN_BYTES, key, ciphertext);
}

bool blue_sapling_out_open_inplace(
    uint8_t ciphertext[BLUE_SAPLING_OUT_CIPHER_BYTES],
    const uint8_t key[32]) {
    return open_inplace(ciphertext, BLUE_SAPLING_OUT_PLAIN_BYTES, key);
}

bool blue_sapling_note_open(uint8_t plaintext[BLUE_SAPLING_NOTE_PLAIN_BYTES],
    const uint8_t key[32],
    const uint8_t ciphertext[BLUE_SAPLING_NOTE_CIPHER_BYTES]) {
    return open(plaintext, BLUE_SAPLING_NOTE_PLAIN_BYTES, key, ciphertext);
}

bool blue_sapling_note_open_inplace(
    uint8_t ciphertext[BLUE_SAPLING_NOTE_CIPHER_BYTES],
    const uint8_t key[32]) {
    return open_inplace(ciphertext, BLUE_SAPLING_NOTE_PLAIN_BYTES, key);
}
