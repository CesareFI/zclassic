/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#ifndef ZCL_BLUE_SAPLING_MEMO_H
#define ZCL_BLUE_SAPLING_MEMO_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#if !defined(__STDC_VERSION__) || __STDC_VERSION__ < 202311L
#error "The Blue Sapling memo inspector requires ISO C23"
#endif

enum { BLUE_SAPLING_MEMO_BYTES = 512 };

typedef enum {
    BLUE_SAPLING_MEMO_TEXT,
    BLUE_SAPLING_MEMO_NONE,
    BLUE_SAPLING_MEMO_OPAQUE,
    BLUE_SAPLING_MEMO_FUTURE,
    BLUE_SAPLING_MEMO_INVALID_TEXT
} blue_sapling_memo_kind;

typedef struct {
    blue_sapling_memo_kind kind;
    size_t text_length;
    bool contains_nul;
    uint8_t sha256[32];
} blue_sapling_memo_info;

/* Classify a decrypted 512-byte Sapling memo using ZIP 302. Text length
 * excludes trailing zero padding and may include embedded NUL bytes; a UI
 * must use the explicit length and flag. The hash covers all 512 bytes.
 * This result remains provisional until note commitment, epk, recipient,
 * and transaction binding are verified by the device. No classification
 * grants signing authority. Null-input failure clears info. Overlapping
 * memo and info are rejected without writes so input bytes remain intact. */
bool blue_sapling_memo_inspect(
    const uint8_t memo[BLUE_SAPLING_MEMO_BYTES],
    blue_sapling_memo_info *info);

#endif
