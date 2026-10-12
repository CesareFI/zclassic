/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Regression test: parse_script() must bound-check a "0x..." token's byte_len
 * against MAX_SCRIPT_SIZE before ParseHex writes into the stack buffer
 * `raw[MAX_SCRIPT_SIZE]` (core/math/src/core_io.c).
 *
 * A "0x" token of 30000 'a' chars (byte_len 15000) must return false with
 * out->size within bounds; a valid "0xdeadbeef" still parses to 4 bytes.
 */

#include "test/test_core.h"
#include "coins/undo.h"
#include "core/core_io.h"
#include "script/script.h"
#include <stdlib.h>
#include <string.h>

int test_parse_script_oversize_hex(void)
{
    int failures = 0;
    TEST_CASE("parse_script rejects oversize 0x hex without overflow") {
        /* "0x" + 30000 'a' -> byte_len 15000 > MAX_SCRIPT_SIZE (10000). */
        size_t hex_chars = 30000;
        char *big = zcl_malloc(hex_chars + 3, "test_oversize_hex");
        ASSERT(big != NULL);
        big[0] = '0';
        big[1] = 'x';
        memset(big + 2, 'a', hex_chars);
        big[hex_chars + 2] = '\0';

        struct script s;
        bool ok = parse_script(big, &s);
        free(big);

        /* Returns false with no overflow. */
        ASSERT(ok == false);
        /* Output never advanced past the fixed-size script buffer. */
        ASSERT(s.size <= MAX_SCRIPT_SIZE);

        /* A valid short hex token still parses to its exact byte length. */
        struct script v;
        bool ok2 = parse_script("0xdeadbeef", &v);
        ASSERT(ok2 == true);
        ASSERT(v.size == 4);
        ASSERT(v.data[0] == 0xde);
        ASSERT(v.data[1] == 0xad);
        ASSERT(v.data[2] == 0xbe);
        ASSERT(v.data[3] == 0xef);
    } TEST_END
    return failures;
}
