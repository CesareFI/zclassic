/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#ifndef ZCL_BASE58_H
#define ZCL_BASE58_H

#include <stddef.h>
#include <stdint.h>

#if !defined(__STDC_VERSION__) || __STDC_VERSION__ < 202311L
#error "ZCL Base58 encoding requires ISO C23"
#endif

enum { ZCL_BASE58_MAX_BYTES = 26 };

/* Encodes up to 26 bytes, preserving leading zero bytes as Base58 '1'. */
int zcl_base58_encode(const uint8_t *input, size_t length,
                      char *output, size_t capacity);

#endif
