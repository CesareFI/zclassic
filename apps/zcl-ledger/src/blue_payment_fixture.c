/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "blue_payment_fixture.h"
#include "zsha256/zsha256.h"

#include <string.h>

typedef struct {
    uint8_t *bytes;
    size_t length, capacity;
} writer;

static bool append(writer *out, const void *bytes, size_t length) {
    if (!out || !bytes || length > out->capacity - out->length)
        return false;
    memcpy(out->bytes + out->length, bytes, length);
    out->length += length;
    return true;
}

static bool append_u32(writer *out, uint32_t value) {
    uint8_t bytes[4];
    for (unsigned i = 0; i < 4; ++i)
        bytes[i] = (uint8_t)(value >> (8 * i));
    return append(out, bytes, sizeof bytes);
}

static bool append_u64(writer *out, uint64_t value) {
    uint8_t bytes[8];
    for (unsigned i = 0; i < 8; ++i)
        bytes[i] = (uint8_t)(value >> (8 * i));
    return append(out, bytes, sizeof bytes);
}

static bool p2pkh(writer *out, const uint8_t hash160[20]) {
    static const uint8_t prefix[] = {25, 0x76, 0xa9, 20};
    static const uint8_t suffix[] = {0x88, 0xac};
    return append(out, prefix, sizeof prefix) &&
        append(out, hash160, 20) &&
        append(out, suffix, sizeof suffix);
}

static bool previous_wire(writer *out, const uint8_t hash160[20]) {
    uint8_t zero[32] = {0};
    static const uint8_t one = 1, empty = 0;
    return append_u32(out, 1) && append(out, &one, 1) &&
        append(out, zero, sizeof zero) && append_u32(out, UINT32_MAX) &&
        append(out, &empty, 1) && append_u32(out, UINT32_MAX) &&
        append(out, &one, 1) && append_u64(out, 400000000) &&
        p2pkh(out, hash160) && append_u32(out, 0);
}

static bool spend_input(writer *out, const uint8_t txid[32]) {
    static const uint8_t one = 1, empty = 0;
    return append_u32(out, 0x80000004) &&
        append_u32(out, 0x892f2085) && append(out, &one, 1) &&
        append(out, txid, 32) && append_u32(out, 0) &&
        append(out, &empty, 1) && append_u32(out, UINT32_MAX - 1);
}

static bool spend_outputs(writer *out, const uint8_t hash160[20]) {
    uint8_t other[20];
    memset(other, 0x22, sizeof other);
    static const uint8_t two = 2;
    static const uint8_t p2sh_prefix[] = {23, 0xa9, 20};
    static const uint8_t p2sh_suffix = 0x87;
    return append(out, &two, 1) && append_u64(out, 100000000) &&
        p2pkh(out, hash160) && append_u64(out, 200000000) &&
        append(out, p2sh_prefix, sizeof p2sh_prefix) &&
        append(out, other, sizeof other) &&
        append(out, &p2sh_suffix, 1);
}

static bool spend_wire(writer *out, const uint8_t txid[32],
    const uint8_t hash160[20]) {
    static const uint8_t empty = 0;
    return spend_input(out, txid) && spend_outputs(out, hash160) &&
        append_u32(out, 100) && append_u32(out, 200) &&
        append_u64(out, 0) && append(out, &empty, 1) &&
        append(out, &empty, 1) && append(out, &empty, 1);
}

bool blue_payment_fixture_make(const uint8_t device_hash160[20],
    blue_payment_fixture *fixture) {
    if (!fixture) return false;
    memset(fixture, 0, sizeof *fixture);
    if (!device_hash160) return false;
    blue_payment_fixture built = {0};
    writer previous = {.bytes = built.previous,
        .capacity = sizeof built.previous};
    if (!previous_wire(&previous, device_hash160)) return false;
    uint8_t first[32], txid[32];
    zsha256(built.previous, previous.length, first);
    zsha256(first, sizeof first, txid);
    writer spend = {.bytes = built.unsigned_wire,
        .capacity = sizeof built.unsigned_wire};
    if (!spend_wire(&spend, txid, device_hash160)) return false;
    built.previous_length = previous.length;
    built.unsigned_length = spend.length;
    *fixture = built;
    return true;
}
