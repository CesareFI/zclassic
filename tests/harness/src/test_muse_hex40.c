/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: exact-format coverage for muse_hex40(), the predicate that
 * decides whether a git identity string is usable as an equality key.
 * Its contract: exactly 40 lowercase hex digits and nothing else — an
 * identity that is not 40 hex is unread rather than partially compared.
 * Zero test references existed. */

#include "test/test_core.h"

#include "services/muse_run_audit.h"

#include <string.h>

static int test_mh_exact_40_lowercase_hex(void)
{
    int failures = 0;
    TEST("muse hex40: exactly 40 lowercase hex digits accept") {
        ASSERT(muse_hex40("0123456789abcdef0123456789abcdef01234567"));
        ASSERT(muse_hex40("ffffffffffffffffffffffffffffffffffffffff"));
        ASSERT(muse_hex40("0000000000000000000000000000000000000000"));
        PASS();
    } _test_next:;
    return failures;
}

static int test_mh_refusal_matrix(void)
{
    int failures = 0;
    TEST("muse hex40: everything else refuses") {
        ASSERT(!muse_hex40(NULL));
        ASSERT(!muse_hex40(""));                       /* empty */
        ASSERT(!muse_hex40("0123"));                   /* short */
        ASSERT(!muse_hex40("0123456789abcdef0123456789abcdef0123456"));
                                                       /* 39 chars */
        ASSERT(!muse_hex40("0123456789abcdef0123456789abcdef012345678"));
                                                       /* 41 chars */
        /* uppercase is not lowercase hex */
        ASSERT(!muse_hex40("0123456789abcdef0123456789abcdef0123456G"));
        ASSERT(!muse_hex40("0123456789ABCDEF0123456789abcdef01234567"));
        /* non-hex at the last position */
        ASSERT(!muse_hex40("0123456789abcdef0123456789abcdef0123456/"));
        PASS();
    } _test_next:;
    return failures;
}

int test_muse_hex40(void)
{
    int failures = 0;
    failures += test_mh_exact_40_lowercase_hex();
    failures += test_mh_refusal_matrix();
    printf("=== muse_hex40: %d failures ===\n", failures);
    return failures;
}
