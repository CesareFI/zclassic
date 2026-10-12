/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "blue_redjubjub_response.h"

#include "blue_fs_ct.h"
#include "blue_mod256.h"

#include <stddef.h>

static uint32_t nonzero(const uint8_t bytes[32]) {
    uint32_t combined = 0;
    for (unsigned i = 0; i < 32; ++i) combined |= bytes[i];
    return (combined | (0u - combined)) >> 31;
}

bool blue_redjubjub_response(uint8_t response[32],
    const uint8_t nonce[32], const uint8_t challenge[32],
    const uint8_t secret[32]) {
    if (!response || !nonce || !challenge || !secret) return false;
    struct fs r = {0}, c = {0}, sk = {0}, product = {0}, sum = {0};
    /* Non-null inputs take the same arithmetic path before output release. */
    uint32_t valid = blue_fs_from_bytes_canonical(&r, nonce);
    valid &= blue_fs_from_bytes_canonical(&c, challenge);
    valid &= blue_fs_from_bytes_canonical(&sk, secret);
    valid &= nonzero(nonce) & nonzero(secret);
    blue_fs_mul_ct(&product, &c, &sk);
    blue_fs_add_ct(&sum, &r, &product);
    volatile uint8_t mask = (uint8_t)(0u - valid);
    for (unsigned i = 0; i < 32; ++i) {
        uint8_t value = (uint8_t)(sum.d[i / 8] >> (8u * (i % 8)));
        response[i] = (response[i] & (uint8_t)~mask) | (value & mask);
    }
    blue_mod256_wipe(&r, sizeof r);
    blue_mod256_wipe(&c, sizeof c);
    blue_mod256_wipe(&sk, sizeof sk);
    blue_mod256_wipe(&product, sizeof product);
    blue_mod256_wipe(&sum, sizeof sum);
    return valid == 1;
}
