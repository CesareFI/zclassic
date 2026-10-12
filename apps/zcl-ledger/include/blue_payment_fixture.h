/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#ifndef ZCL_BLUE_PAYMENT_FIXTURE_H
#define ZCL_BLUE_PAYMENT_FIXTURE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#if !defined(__STDC_VERSION__) || __STDC_VERSION__ < 202311L
#error "The Blue payment fixture requires ISO C23"
#endif

enum { BLUE_PAYMENT_FIXTURE_BRANCH = 0x76b809bb,
       BLUE_PAYMENT_FIXTURE_MAX_WIRE = 256 };

typedef struct {
    uint8_t previous[BLUE_PAYMENT_FIXTURE_MAX_WIRE];
    uint8_t unsigned_wire[BLUE_PAYMENT_FIXTURE_MAX_WIRE];
    size_t previous_length, unsigned_length;
} blue_payment_fixture;

/* Builds an intentionally synthetic test scenario from a device-derived
 * P2PKH hash. The previous wire has no established chain provenance; never
 * broadcast the spend. It sends 1 ZCL to that hash and 2 ZCL to a fixed
 * P2SH test address with a 1 ZCL fee. No private key enters this builder. */
bool blue_payment_fixture_make(const uint8_t device_hash160[20],
    blue_payment_fixture *fixture);

#endif
