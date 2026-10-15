/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * Purpose: fleet usability of the hash-PSK HOST tunnel: the supervised
 * receiver example unit and the --input-file source it reads. */
#include "test/test_core.h"
#include "command/native_command.h"
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

extern int repo_path(char *out, size_t outsz, const char *rel);
extern int read_entire_file(const char *path, char **out_buf);

static int shell_receiver_unit(void)
{
    int failures = 0;
    char *unit = NULL, *env = NULL;
    TEST_CASE("device_host_shell: receiver example unit restarts bounded runs") {
        char path[4096];
        ASSERT(repo_path(path, sizeof(path), "platform/deploy/examples/z23-tunnel-receiver.service") == 0);
        ASSERT(read_entire_file(path, &unit) == 0);
        ASSERT(strstr(unit, "\nRestart=always\n") != NULL);
        ASSERT(strstr(unit, "\nRestartSec=2\n") != NULL);
        ASSERT(strstr(unit, "\nNoNewPrivileges=yes\n") != NULL);
        ASSERT(strstr(unit, "\nProtectSystem=strict\n") != NULL);
        /* Lifetime expiry exits 1; refused input (2) must not loop. */
        ASSERT(strstr(unit, "\nSuccessExitStatus=1\n") != NULL);
        ASSERT(strstr(unit, "\nRestartPreventExitStatus=2 3\n") != NULL);
        ASSERT(strstr(unit, "\nEnvironmentFile=%h/") != NULL);
        ASSERT(strstr(unit, "\nEnvironmentFile=-") == NULL);
        ASSERT(strstr(unit, " ops mesh device host receiver --input-file=${Z23_TUNNEL_RECEIVER_INPUT}\n") != NULL);
        ASSERT(repo_path(path, sizeof(path), "platform/deploy/examples/z23-tunnel-receiver.env.example") == 0);
        ASSERT(read_entire_file(path, &env) == 0);
        ASSERT(strstr(env, "\"lifetime_ms\":600000") != NULL);
        ASSERT(strstr(env, "\"max_sessions\":64") != NULL);
        ASSERT(strstr(env, "\"max_active\":4") != NULL);
        ASSERT(strstr(env, "\nZ23_TUNNEL_RECEIVER_INPUT=/") != NULL);
    } TEST_END
    free(unit); free(env);
    return failures;
}

#if defined(__linux__)
static bool shell_write(const char *path, const char *text, mode_t mode)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0) return false;
    size_t length = strlen(text);
    bool ok = write(fd, text, length) == (ssize_t)length && fchmod(fd, mode) == 0;
    return close(fd) == 0 && ok;
}

static int shell_input_file(void)
{
    int failures = 0;
    char directory[1024] = {0};
    TEST_CASE("device_host_shell: --input-file reads only an owner regular file") {
        ASSERT(test_mkdtemp(directory, sizeof(directory), "device-host-input"));
        char good[1200], link[1200], wide[1200], big[1200], text[64];
        size_t length = 99;
        snprintf(good, sizeof(good), "%s/route.json", directory);
        ASSERT(shell_write(good, "{\"a\":1}\n", 0600));
        ASSERT(zcl_native_device_host_input_file_read(good, text, sizeof(text), &length));
        ASSERT_EQ(length, 7u); ASSERT_STR_EQ(text, "{\"a\":1}");
        ASSERT(!zcl_native_device_host_input_file_read("route.json", text, sizeof(text), &length));
        ASSERT_EQ(length, 0u);
        snprintf(link, sizeof(link), "%s/link.json", directory);
        ASSERT(symlink(good, link) == 0);
        ASSERT(!zcl_native_device_host_input_file_read(link, text, sizeof(text), &length));
        ASSERT(!zcl_native_device_host_input_file_read(directory, text, sizeof(text), &length));
        snprintf(wide, sizeof(wide), "%s/wide.json", directory);
        ASSERT(shell_write(wide, "{\"a\":1}", 0622));
        ASSERT(!zcl_native_device_host_input_file_read(wide, text, sizeof(text), &length));
        snprintf(big, sizeof(big), "%s/big.json", directory);
        ASSERT(shell_write(big, "{\"a\":\"0123456789012345678901234567890123456789012345678901234567\"}", 0600));
        ASSERT(!zcl_native_device_host_input_file_read(big, text, sizeof(text), &length));
        ASSERT_STR_EQ(text, "");
    } TEST_END
    if (directory[0]) test_rm_rf(directory);
    return failures;
}
#endif

int test_device_host_shell(void);
int test_device_host_shell(void)
{
    int failures = shell_receiver_unit();
#if defined(__linux__)
    failures += shell_input_file();
#endif
    return failures;
}
