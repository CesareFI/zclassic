/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#ifndef ZCL_BLUE_SAPLING_FIXTURE_H
#define ZCL_BLUE_SAPLING_FIXTURE_H

#include <stdint.h>
#include <string.h>

enum { BLUE_SYNTHETIC_SAPLING_BYTES = 1425 };

/* Structurally valid v4 wire: one spend and output with arbitrary proof bytes. */
static void blue_sapling_fixture(
    uint8_t wire[BLUE_SYNTHETIC_SAPLING_BYTES]) {
    memset(wire, 0, BLUE_SYNTHETIC_SAPLING_BYTES);
    memcpy(wire, (const uint8_t[]){4, 0, 0, 0x80,
        0x85, 0x20, 0x2f, 0x89}, 8);
    wire[14] = 0x20;
    wire[15] = 0xa1;
    wire[16] = 0x07;
    wire[26] = 1;
    for (unsigned i = 0; i < 384; ++i)
        wire[27 + i] = (uint8_t)(i * 3u + 1u);
    wire[411] = 1;
    for (unsigned i = 0; i < 948; ++i)
        wire[412 + i] = (uint8_t)(i * 17u + 3u);
    for (unsigned i = 0; i < 64; ++i)
        wire[1361 + i] = (uint8_t)(i + 5u);
}

#endif
