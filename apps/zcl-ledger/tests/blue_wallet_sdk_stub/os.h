/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#ifndef ZCL_BLUE_WALLET_TEST_OS_H
#define ZCL_BLUE_WALLET_TEST_OS_H

#include <stddef.h>
#include <stdint.h>

enum {
    BAGL_RECTANGLE = 1, BAGL_LABEL = 2, BAGL_BUTTON = 3,
    BAGL_FLAG_TOUCHABLE = 0x80, BAGL_FILL = 1,
    BAGL_FONT_OPEN_SANS_LIGHT_14px = 1,
    BAGL_FONT_OPEN_SANS_LIGHT_16_22PX = 2,
    BAGL_FONT_ALIGNMENT_CENTER = 0x100,
    BAGL_FONT_ALIGNMENT_MIDDLE = 0x200,
    CX_BLAKE2B = 1, CX_SHA256 = 2, CX_LAST = 1
};

typedef struct bagl_element_s bagl_element_t;
struct bagl_element_s {
    struct {
        int type, userid, x, y, width, height, radius, fill;
        uint32_t fgcolor, bgcolor, font_id;
    } component;
    const char *text;
    uint32_t overfgcolor, overbgcolor;
    const bagl_element_t *(*tap)(const bagl_element_t *);
};

#ifdef BLUE_WALLET_TEST_REAL_HASH
#include "crypto/blake2b.h"
#include "zsha256/zsha256.h"
typedef struct blake2b_ctx cx_blake2b_t;
typedef zsha256_ctx cx_sha256_t;
#elif defined(BLUE_REVIEW_TEST_CONTEXT)
typedef struct { uint8_t bytes[256]; } cx_blake2b_t;
typedef struct { uint8_t unused; } cx_sha256_t;
#else
typedef struct { uint8_t unused; } cx_blake2b_t;
typedef struct { uint8_t unused; } cx_sha256_t;
#endif
typedef struct { unsigned curve, d_len; uint8_t d[32]; }
    cx_ecfp_private_key_t;
typedef struct { unsigned curve, W_len; uint8_t W[65]; }
    cx_ecfp_public_key_t;

int cx_blake2b_init2(void *context, unsigned bits, const void *key,
    size_t key_length, const uint8_t *personal, size_t personal_length);
int cx_hash_sha256(const uint8_t *bytes, unsigned length, uint8_t digest[32]);
int cx_hash(void *context, unsigned mode, const uint8_t *bytes,
    unsigned length, uint8_t *digest, unsigned digest_length);
int cx_sha256_init(void *context);
int os_global_pin_is_validated(void);
void os_sched_exit(unsigned code);

#endif
