/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "zcl_base58.h"

static const char alphabet[] =
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

static bool encode_digits(const uint8_t *input, size_t length,
                          uint8_t digits[40], size_t *used) {
    for (size_t i = 0; i < length; ++i) {
        unsigned carry = input[i];
        for (size_t j = 0; j < *used; ++j) {
            carry += (unsigned)digits[j] * 256u;
            digits[j] = (uint8_t)(carry % 58u);
            carry /= 58u;
        }
        while (carry) {
            if (*used == 40) return false;
            digits[(*used)++] = (uint8_t)(carry % 58u);
            carry /= 58u;
        }
    }
    return true;
}

int zcl_base58_encode(const uint8_t *input, size_t length,
                      char *output, size_t capacity) {
    if (!input || !output || !length || length > ZCL_BASE58_MAX_BYTES ||
        !capacity) return -1;
    uint8_t digits[40] = {0};
    size_t used = 1;
    if (!encode_digits(input, length, digits, &used)) return -1;
    size_t zeros = 0;
    while (zeros < length && !input[zeros]) ++zeros;
    while (used && !digits[used - 1]) --used;
    if (zeros + used >= capacity) return -1;
    size_t position = 0;
    while (zeros--) output[position++] = '1';
    while (used) output[position++] = alphabet[digits[--used]];
    output[position] = 0;
    return 0;
}
