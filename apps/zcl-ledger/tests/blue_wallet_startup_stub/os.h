/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#ifndef ZCL_BLUE_WALLET_STARTUP_OS_H
#define ZCL_BLUE_WALLET_STARTUP_OS_H

#include "../blue_wallet_sdk_stub/os.h"
#include <setjmp.h>
#include <stdlib.h>

enum {
    CX_CURVE_256K1 = 3, CX_RIPEMD160 = 4,
    IO_SEPROXYHAL_BUFFER_SIZE_B = 128,
    CHANNEL_SPI = 1, CHANNEL_APDU = 2,
    IO_RETURN_AFTER_TX = 4, IO_FLAGS = 4,
    INVALID_PARAMETER = 1
};

typedef struct { int header; } cx_ripemd160_t;
typedef struct { uint8_t unused; } ux_state_t;
extern unsigned char G_io_apdu_buffer[260];

int os_global_pin_is_validated(void);
void os_perso_derive_node_bip32(unsigned curve, const unsigned *path,
    unsigned length, uint8_t raw[32], uint8_t chain[32]);
int cx_ecfp_init_private_key(unsigned curve, const uint8_t raw[32],
    unsigned length, cx_ecfp_private_key_t *key);
int cx_ecfp_generate_pair(unsigned curve, cx_ecfp_public_key_t *public_key,
    cx_ecfp_private_key_t *private_key, int keepprivate);
int cx_ripemd160_init(cx_ripemd160_t *context);
int cx_hash5(void *context, unsigned mode, const uint8_t *bytes,
    unsigned length, uint8_t *digest);
#define cx_hash(context, mode, bytes, length, digest) \
    cx_hash5(context, mode, bytes, length, digest)
void os_boot(void);
unsigned short io_exchange(unsigned char channel, unsigned short tx_length);

typedef struct blue_try_context {
    jmp_buf jump;
    volatile unsigned code;
    struct blue_try_context *previous;
} blue_try_context;

void blue_try_enter(blue_try_context *context);
void blue_try_leave(void);
blue_try_context *blue_try_current(void);
[[noreturn]] void blue_throw(unsigned error);

#define BEGIN_TRY { blue_try_context blue_try;
#define TRY blue_try_enter(&blue_try); \
    if (setjmp(blue_try.jump) == 0) {
#define CATCH_OTHER(error) goto blue_finally; } else { \
    unsigned error = blue_try.code; blue_try.code = 0;
#define FINALLY goto blue_finally; } blue_finally: \
    if (blue_try_current() == &blue_try) blue_try_leave();
#define END_TRY if (blue_try.code) blue_throw(blue_try.code); }
#define CLOSE_TRY blue_try_leave()
#define THROW(error) blue_throw(error)

#endif
