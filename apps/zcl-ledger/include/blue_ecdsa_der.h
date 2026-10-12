/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#ifndef ZCL_BLUE_ECDSA_DER_H
#define ZCL_BLUE_ECDSA_DER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#if !defined(__STDC_VERSION__) || __STDC_VERSION__ < 202311L
#error "Blue ECDSA DER handling requires ISO C23"
#endif

enum { BLUE_ECDSA_DER_MAX = 72 };

/* Accepts strict positive secp256k1 ECDSA integers and emits canonical
 * low-S DER. Input and output may overlap; output length is zero on failure. */
bool blue_ecdsa_der_low_s(const uint8_t *der, size_t length,
    uint8_t out[BLUE_ECDSA_DER_MAX], size_t *out_length);

#endif
