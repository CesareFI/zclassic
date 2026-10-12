/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: Run the shipped guest SSH launcher and record its fixed options.
 */
#include "test/test_core.h"
#include "util/spawn.h"
#include <stdio.h>
#include <string.h>

static int launcher_lines_present(const char *text)
{
    static const char *const lines[] = {
        "asserted KexAlgorithms=mlkem768x25519-sha256\n",
        "asserted StrictHostKeyChecking=yes\n",
        "asserted UserKnownHostsFile=/usr/local/etc/z23-fixture/known_hosts\n",
        "asserted PasswordAuthentication=no\n",
        "asserted ForwardAgent=no\n",
        "asserted ProxyCommand=/usr/local/libexec/z23-guest-port /dev/vtcon/z23.l0.t\n",
        "PASS native launcher mode 0\n",
        "PASS native launcher mode 14\n",
        "PASS PTY/FD observer only; SSH execution and guest acceptance not exercised\n"
    };
    for (size_t i = 0; i < sizeof(lines) / sizeof(lines[0]); i++) {
        if (strstr(text, lines[i]) == NULL) {
            printf("missing launcher line: %s", lines[i]);
            return 0;
        }
    }
    return 1;
}

static int run_shipped_launcher(const char *dir)
{
    const char *const argv[] = {"build/bin/test-guest-ssh-fixture", dir, NULL};
    char output[65536];
    struct zcl_spawn_binary_observation observed = {0};
    struct zcl_result result = zcl_spawn_capture_binary_merged(argv, output,
        sizeof(output) - 1, 30000, &observed);
    if (observed.output_len < sizeof(output))
        output[observed.output_len] = '\0';
    else
        output[sizeof(output) - 1] = '\0';
    if (fwrite(output, 1, strlen(output), stdout) != strlen(output) || fflush(stdout) != 0)
        return 1;
    if (!result.ok || observed.exit_code != 0 || observed.overflow)
        return 1;
    return launcher_lines_present(output) ? 0 : 1;
}

static int run_missing_console(void)
{
    const char *const argv[] = {"build/bin/guest-ssh-fixture", NULL};
    char output[4096];
    struct zcl_spawn_binary_observation observed = {0};
    struct zcl_result result = zcl_spawn_capture_binary_merged(argv, output,
        sizeof(output) - 1, 10000, &observed);
    if (observed.output_len < sizeof(output))
        output[observed.output_len] = '\0';
    else
        output[sizeof(output) - 1] = '\0';
    if (fwrite(output, 1, strlen(output), stdout) != strlen(output) || fflush(stdout) != 0)
        return 1;
    if (result.ok || observed.exit_code != 1)
        return 1;
    return strstr(output, "guest-ssh-fixture: P_RAW_REFUSED\n") != NULL ? 0 : 1;
}

static int test_launcher_options(const char *dir)
{
    int failures = 0;
    TEST("shipped launcher requests hybrid KEX, pinning, and the guest port") {
        ASSERT(run_shipped_launcher(dir) == 0);
        PASS();
    } _test_next:;
    return failures;
}

static int test_missing_port(void)
{
    int failures = 0;
    TEST("shipped launcher refuses a missing guest console port") {
        ASSERT(run_missing_console() == 0);
        PASS();
    } _test_next:;
    return failures;
}

int test_guest_ssh_fixture(void);
int test_guest_ssh_fixture(void)
{
#ifndef _WIN32
    char dir[512];
    test_make_tmpdir(dir, sizeof(dir), "guest_ssh", "fixture");
    int failures = test_launcher_options(dir) + test_missing_port();
    test_rm_rf(dir);
    return failures;
#else
    fputs("UNOBSERVED: guest SSH fixture unavailable on Windows\n", stderr);
    return 1;
#endif
}
