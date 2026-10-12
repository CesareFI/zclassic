/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#ifndef ZCL_BLUE_WALLET_PROTOCOL_H
#define ZCL_BLUE_WALLET_PROTOCOL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#if !defined(__STDC_VERSION__) || __STDC_VERSION__ < 202311L
#error "The Blue wallet protocol requires ISO C23"
#endif

enum { BLUE_WALLET_PUBLIC_KEY_SIZE = 33, BLUE_WALLET_PROTOCOL_VERSION = 12,
       BLUE_WALLET_CAPABILITIES = 31 };

typedef struct {
    bool address_ready;
    uint8_t public_key[BLUE_WALLET_PUBLIC_KEY_SIZE];
} blue_wallet_state;

/* Accepts receive-only v8, read-only v11, and signing-candidate v12. */
bool blue_wallet_identity_matches(const uint8_t *reply, size_t length);

uint16_t blue_wallet_handle(const blue_wallet_state *state,
                            const uint8_t *apdu, size_t apdu_length,
                            uint8_t *reply, size_t reply_capacity,
                            size_t *reply_length);

#endif
