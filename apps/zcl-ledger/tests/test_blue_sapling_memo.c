/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "blue_sapling_memo.h"

#undef NDEBUG
#include <assert.h>
#include <string.h>

static void check_text(void) {
    uint8_t memo[BLUE_SAPLING_MEMO_BYTES] = {0};
    blue_sapling_memo_info info;
    memcpy(memo, "Hello", 5);
    assert(blue_sapling_memo_inspect(memo, &info));
    assert(info.kind == BLUE_SAPLING_MEMO_TEXT &&
        info.text_length == 5 && !info.contains_nul);
    uint8_t original_hash[32];
    memcpy(original_hash, info.sha256, sizeof original_hash);
    memo[511] = 'x';
    assert(blue_sapling_memo_inspect(memo, &info));
    assert(info.kind == BLUE_SAPLING_MEMO_TEXT &&
        info.text_length == BLUE_SAPLING_MEMO_BYTES &&
        memcmp(info.sha256, original_hash, sizeof original_hash) != 0);
    memset(memo, 0, sizeof memo);
    memcpy(memo, (const uint8_t[]){'A', 0, 'B'}, 3);
    memo[3] = 0;
    assert(blue_sapling_memo_inspect(memo, &info));
    assert(info.kind == BLUE_SAPLING_MEMO_TEXT &&
        info.text_length == 3 && info.contains_nul);
    memset(memo, 0, sizeof memo);
    memcpy(memo, (const uint8_t[]){0x41, 0xe2, 0x82, 0xac}, 4);
    memo[4] = 0;
    assert(blue_sapling_memo_inspect(memo, &info));
    assert(info.kind == BLUE_SAPLING_MEMO_TEXT &&
        info.text_length == 4);
    memo[0] = 0;
    assert(blue_sapling_memo_inspect(memo, &info));
    assert(info.kind == BLUE_SAPLING_MEMO_TEXT &&
        info.text_length == 4);
}

static void check_invalid_utf8(void) {
    static const struct {
        uint8_t bytes[4];
        size_t length;
    } invalid[] = {
        {{'A', 0xc0}, 2},
        {{'A', 0xed, 0xa0, 0x80}, 4},
        {{'A', 0xf4, 0x90, 0x80}, 4},
        {{'A', 0xe2, 0x82}, 3},
        {{'A', 0xe2, 0x41}, 3}
    };
    blue_sapling_memo_info info;
    for (size_t i = 0; i < sizeof invalid / sizeof invalid[0]; ++i) {
        uint8_t memo[BLUE_SAPLING_MEMO_BYTES] = {0};
        memcpy(memo, invalid[i].bytes, invalid[i].length);
        assert(blue_sapling_memo_inspect(memo, &info));
        assert(info.kind == BLUE_SAPLING_MEMO_INVALID_TEXT);
    }
}

static void check_nontext(void) {
    uint8_t memo[BLUE_SAPLING_MEMO_BYTES] = {0};
    blue_sapling_memo_info info;
    memo[0] = 0xf6;
    assert(blue_sapling_memo_inspect(memo, &info));
    assert(info.kind == BLUE_SAPLING_MEMO_NONE && !info.text_length);
    memo[511] = 1;
    assert(blue_sapling_memo_inspect(memo, &info));
    assert(info.kind == BLUE_SAPLING_MEMO_FUTURE);
    memo[511] = 0;
    memo[0] = 0xf7;
    assert(blue_sapling_memo_inspect(memo, &info));
    assert(info.kind == BLUE_SAPLING_MEMO_FUTURE);
    memo[0] = 0xfe;
    assert(blue_sapling_memo_inspect(memo, &info));
    assert(info.kind == BLUE_SAPLING_MEMO_FUTURE);
    memo[0] = 0xf5;
    assert(blue_sapling_memo_inspect(memo, &info));
    assert(info.kind == BLUE_SAPLING_MEMO_OPAQUE);
    memo[0] = 0xff;
    assert(blue_sapling_memo_inspect(memo, &info));
    assert(info.kind == BLUE_SAPLING_MEMO_OPAQUE);
}

int main(void) {
    blue_sapling_memo_info info;
    memset(&info, 0xa5, sizeof info);
    assert(!blue_sapling_memo_inspect(NULL, &info));
    const uint8_t empty[sizeof info] = {0};
    assert(memcmp(&info, empty, sizeof info) == 0);
    uint8_t memo[BLUE_SAPLING_MEMO_BYTES] = {0};
    assert(!blue_sapling_memo_inspect(memo, NULL));
    union {
        uint8_t memo[BLUE_SAPLING_MEMO_BYTES];
        blue_sapling_memo_info info;
    } shared;
    memset(&shared, 0xa5, sizeof shared);
    assert(!blue_sapling_memo_inspect(shared.memo, &shared.info));
    for (size_t i = 0; i < sizeof shared.memo; ++i)
        assert(shared.memo[i] == 0xa5);
    check_text();
    check_invalid_utf8();
    check_nontext();
    return 0;
}
