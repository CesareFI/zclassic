/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#ifndef ZCL_BLUE_SAPLING_DEVICE_TEST_OS_H
#define ZCL_BLUE_SAPLING_DEVICE_TEST_OS_H

#include <stdint.h>

enum { CX_CURVE_256K1 = 1 };

int os_global_pin_is_validated(void);
unsigned char *cx_rng(unsigned char *buffer, unsigned int length);
void os_perso_derive_node_bip32(unsigned curve, const unsigned int *path,
    unsigned length, uint8_t raw[32], uint8_t chain[32]);

#endif
