/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: runs the platform/modules/mlkem self-test (NIST ACVP vectors,
 * round trips, bit-flip rejection, input validation) as a harness group. */

#include "test/test_core.h"

#include <stdio.h>

#define main mlkem_module_main
#include "../../../platform/modules/mlkem/tests/test_mlkem.c"
#undef main

int test_mlkem(void);
int test_mlkem(void)
{
    int failures = 0;
    TEST("mlkem module: NIST vectors, round trips, bit flips, validation") {
        ASSERT(mlkem_module_main() == 0);
        PASS();
    } _test_next:;
    return failures;
}
