/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "blue_ecdsa_der.h"

#include <string.h>

static const uint8_t order[32] = {
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b,
    0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41
};

static const uint8_t half_order[32] = {
    0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d,
    0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b, 0x20, 0xa0
};

static bool parse_integer(const uint8_t *der, size_t length,
    size_t *position, uint8_t value[32]) {
    if (*position + 2 > length || der[*position] != 0x02) return false;
    size_t count = der[*position + 1];
    *position += 2;
    if (!count || count > 33 || count > length - *position) return false;
    const uint8_t *bytes = der + *position;
    if ((bytes[0] & 0x80) ||
        (count > 1 && bytes[0] == 0 && !(bytes[1] & 0x80)) ||
        (count == 33 && bytes[0] != 0)) return false;
    memset(value, 0, 32);
    size_t used = count == 33 ? 32 : count;
    memcpy(value + 32 - used, bytes + count - used, used);
    uint8_t nonzero = 0;
    for (size_t i = 0; i < 32; ++i) nonzero |= value[i];
    *position += count;
    return nonzero && memcmp(value, order, 32) < 0;
}

static void make_low_s(uint8_t value[32]) {
    if (memcmp(value, half_order, 32) <= 0) return;
    unsigned borrow = 0;
    for (size_t i = 32; i-- > 0;) {
        unsigned subtrahend = (unsigned)value[i] + borrow;
        unsigned minuend = order[i];
        value[i] = (uint8_t)(minuend - subtrahend);
        borrow = minuend < subtrahend;
    }
}

static size_t encode_integer(uint8_t *out, const uint8_t value[32]) {
    size_t first = 0;
    while (first < 31 && value[first] == 0) ++first;
    size_t count = 32 - first;
    bool prefix = (value[first] & 0x80) != 0;
    out[0] = 0x02;
    out[1] = (uint8_t)(count + prefix);
    if (prefix) out[2] = 0;
    memcpy(out + 2 + prefix, value + first, count);
    return 2 + count + prefix;
}

bool blue_ecdsa_der_low_s(const uint8_t *der, size_t length,
    uint8_t out[BLUE_ECDSA_DER_MAX], size_t *out_length) {
    if (!out_length) return false;
    *out_length = 0;
    if (!der || !out || length < 8 || length > BLUE_ECDSA_DER_MAX ||
        der[0] != 0x30 || der[1] != length - 2) return false;
    uint8_t r[32], s[32];
    size_t position = 2;
    if (!parse_integer(der, length, &position, r) ||
        !parse_integer(der, length, &position, s) ||
        position != length) return false;
    make_low_s(s);
    size_t used = 2;
    used += encode_integer(out + used, r);
    used += encode_integer(out + used, s);
    out[0] = 0x30;
    out[1] = (uint8_t)(used - 2);
    *out_length = used;
    return true;
}
