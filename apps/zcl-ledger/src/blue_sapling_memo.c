/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "blue_sapling_memo.h"
#include "zsha256/zsha256.h"

#include <string.h>

static bool continuation(uint8_t byte) {
    return byte >= 0x80 && byte <= 0xbf;
}

static unsigned sequence_length(uint8_t first) {
    if (first >= 0xc2 && first <= 0xdf) return 2;
    if (first >= 0xe0 && first <= 0xef) return 3;
    if (first >= 0xf0 && first <= 0xf4) return 4;
    return 0;
}

static bool second_valid(uint8_t first, uint8_t second) {
    if (first == 0xe0) return second >= 0xa0;
    if (first == 0xed) return second <= 0x9f;
    if (first == 0xf0) return second >= 0x90;
    if (first == 0xf4) return second <= 0x8f;
    return true;
}

static bool text_valid(const uint8_t *bytes, size_t length,
    bool *contains_nul) {
    *contains_nul = false;
    for (size_t i = 0; i < length;) {
        uint8_t first = bytes[i];
        if (first < 0x80) {
            if (!first) *contains_nul = true;
            ++i;
            continue;
        }
        unsigned count = sequence_length(first);
        if (!count || count > length - i) return false;
        for (unsigned j = 1; j < count; ++j)
            if (!continuation(bytes[i + j])) return false;
        if (!second_valid(first, bytes[i + 1])) return false;
        i += count;
    }
    return true;
}

bool blue_sapling_memo_inspect(
    const uint8_t memo[BLUE_SAPLING_MEMO_BYTES],
    blue_sapling_memo_info *info) {
    if (!info) return false;
    if (memo) {
        uintptr_t a = (uintptr_t)memo, b = (uintptr_t)info;
        if (a <= b ? b - a < BLUE_SAPLING_MEMO_BYTES :
            a - b < sizeof *info) return false;
    }
    memset(info, 0, sizeof *info);
    if (!memo) return false;
    zsha256(memo, BLUE_SAPLING_MEMO_BYTES, info->sha256);
    if (memo[0] <= 0xf4) {
        size_t length = BLUE_SAPLING_MEMO_BYTES;
        while (length && !memo[length - 1]) --length;
        info->text_length = length;
        info->kind = text_valid(memo, length, &info->contains_nul)
            ? BLUE_SAPLING_MEMO_TEXT : BLUE_SAPLING_MEMO_INVALID_TEXT;
    } else if (memo[0] == 0xf6) {
        bool empty = true;
        for (size_t i = 1; i < BLUE_SAPLING_MEMO_BYTES; ++i)
            empty &= memo[i] == 0;
        info->kind = empty ? BLUE_SAPLING_MEMO_NONE :
            BLUE_SAPLING_MEMO_FUTURE;
    } else if (memo[0] == 0xf5 || memo[0] == 0xff) {
        info->kind = BLUE_SAPLING_MEMO_OPAQUE;
    } else {
        info->kind = BLUE_SAPLING_MEMO_FUTURE;
    }
    return true;
}
