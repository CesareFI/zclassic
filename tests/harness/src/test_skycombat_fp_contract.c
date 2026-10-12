/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: verify the game's separately compiled aircraft rounding policy. */
#include "test/test_core.h"
#include "test/host_tool_capture.h"
#include <string.h>

int test_skycombat_fp_contract(void);
int test_skycombat_fp_contract(void)
{
    int failures = 0;
    TEST("SkyCombat: actual aircraft object does not contract the yaw update") {
#if defined(_WIN32)
        const char *argv[] = {"build/bin/skycombat-fp-contract.exe", NULL};
#else
        const char *argv[] = {"build/bin/skycombat-fp-contract", NULL};
#endif
        char output[256] = {0};
        int rc = test_host_tool_capture(argv, output, sizeof(output), 5000);
        if (rc != 0) fprintf(stderr, "%s", output);
        ASSERT_EQ(rc, 0);
        ASSERT(strstr(output, "yaw=00000000 fused=32d00000 PASS") != NULL);
        PASS();
    } _test_next:;
    return failures;
}
