/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: Observe bounded native SSH fixture pipe transport preparation. */
#include "test/test_core.h"
#include "util/spawn.h"
#include <stdio.h>
#include <string.h>

int test_rvmachine_freebsd_ssh_fd(void);
int test_rvmachine_freebsd_ssh_fd(void)
{
#ifndef _WIN32
    const char *const argv[] = {"build/bin/z23-machine-freebsd-ssh", "--selftest", NULL};
    char output[16384];
    struct zcl_spawn_binary_observation observed = {0};
    int failures = 0;
    TEST("native duplex fixture preserves suffixes and observes child status") {
        struct zcl_result result = zcl_spawn_capture_binary_merged(argv, output,
            sizeof(output) - 1, 25000, &observed);
        bool emitted = fwrite(output, 1, observed.output_len, stdout) == observed.output_len &&
            fflush(stdout) == 0;
        ASSERT(emitted);
        ASSERT(result.ok);
        ASSERT(!observed.timed_out);
        ASSERT(!observed.overflow);
        ASSERT(observed.eof);
        ASSERT(observed.exit_observed);
        ASSERT(observed.exit_code == 0);
        output[observed.output_len] = '\0';
        ASSERT(strstr(output, "PUBLIC_SSH_NATIVE_FD_PROOF bytes=4097 short_rx=1 cat_exit=0 false_nonzero=1 eagain=1 epipe=1 low_fd=1 lost_child=1\n") != NULL);
        PASS();
    } _test_next:;
    return failures;
#else
    fputs("UNOBSERVED: native SSH pipe preparation unavailable on Windows\n", stderr);
    return 1;
#endif
}
