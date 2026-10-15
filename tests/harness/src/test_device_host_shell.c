/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * Purpose: fleet usability of the hash-PSK HOST tunnel: the supervised
 * receiver example unit, the --input-file source it reads, psk.new and the
 * injection-proof ssh argv of host.shell. */
#include "test/test_core.h"
#include "command/native_command.h"
#include "config/command_catalog.h"
#include "json/json.h"
#include "base/hex.h"
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

/* Drive the registered leaf exactly as dispatch would: catalog spec plus one
 * {"key": path} input object. */
static bool psk_new_call(const char *path, struct zcl_command_reply *reply)
{
    const struct zcl_command_spec *spec = zcl_command_registry_find(zcl_command_catalog(), "ops.mesh.device.psk.new", NULL);
    if (!spec || spec->handler != zcl_native_handle_ops_mesh_device_psk_new) return false;
    struct json_value input = {0};
    json_set_object(&input);
    bool pushed = json_push_kv_str(&input, "key", path);
    zcl_command_reply_init(reply, spec->output_schema);
    struct zcl_command_request request = {.spec = spec, .input = &input};
    if (pushed) zcl_native_handle_ops_mesh_device_psk_new(&request, reply);
    json_free(&input);
    return pushed;
}

static const char *psk_reply_str(const struct zcl_command_reply *reply, const char *key)
{
    return json_get_str(json_get(&reply->data, key));
}

static int shell_psk_fingerprint(void)
{
    int failures = 0;
    TEST_CASE("device_host_shell: psk fingerprint is a stable domain-separated SHA3-256 prefix") {
        uint8_t key[32];
        for (size_t i = 0; i < sizeof(key); ++i) key[i] = (uint8_t)i;
        char first[17], second[17], prefix[65];
        zcl_native_device_psk_fingerprint(key, first);
        zcl_native_device_psk_fingerprint(key, second);
        /* openssl dgst -sha3-256 over "z23.device.host.psk.fingerprint.v1\0" || 00..1f */
        ASSERT_STR_EQ(first, "fa5ecb987676c68b");
        ASSERT_STR_EQ(first, second);
        zcl_hex_encode(key, 32, prefix);
        ASSERT(strncmp(first, prefix, 16) != 0);
        key[31] ^= 1;
        zcl_native_device_psk_fingerprint(key, second);
        ASSERT(strcmp(first, second) != 0);
    } TEST_END
    return failures;
}

static int shell_psk_new(void)
{
    int failures = 0;
    char directory[1024] = {0};
    struct zcl_command_reply reply = {0};
    TEST_CASE("device_host_shell: psk.new creates one 0600 32-byte key and refuses reuse or symlink") {
        ASSERT(test_mkdtemp(directory, sizeof(directory), "device-host-psk"));
        char path[1200], link[1200], target[1200], hex[65];
        snprintf(path, sizeof(path), "%s/host.psk", directory);
        ASSERT(psk_new_call(path, &reply));
        ASSERT_EQ(reply.status, ZCL_COMMAND_STATUS_PASSED);
        ASSERT(reply.error.mutated);
        struct stat st;
        ASSERT(lstat(path, &st) == 0);
        ASSERT(S_ISREG(st.st_mode)); ASSERT_EQ(st.st_mode & 0777, 0600u); ASSERT_EQ(st.st_size, 32);
        uint8_t key[32]; char expect[17];
        int fd = open(path, O_RDONLY | O_CLOEXEC);
        ASSERT(fd >= 0);
        ASSERT_EQ(read(fd, key, sizeof(key)), 32); close(fd);
        zcl_native_device_psk_fingerprint(key, expect);
        const char *fingerprint = psk_reply_str(&reply, "psk_fingerprint");
        ASSERT(fingerprint != NULL); ASSERT_STR_EQ(fingerprint, expect);
        zcl_hex_encode(key, 32, hex);
        ASSERT(strncmp(fingerprint, hex, 16) != 0);
        /* The reply names no key bytes and no path. */
        char wire[1024];
        ASSERT(json_write(&reply.data, wire, sizeof(wire)) > 0);
        bool leaked = strstr(wire, hex) != NULL || strstr(wire, "host.psk") != NULL;
        ASSERT(!leaked);
        memset(key, 0, sizeof(key));
        zcl_command_reply_free(&reply); memset(&reply, 0, sizeof(reply));

        ASSERT(psk_new_call(path, &reply));
        ASSERT_EQ(reply.status, ZCL_COMMAND_STATUS_FAILED);
        ASSERT_STR_EQ(reply.error.code, "PSK_KEY_EXISTS");
        ASSERT(!reply.error.mutated);
        ASSERT(lstat(path, &st) == 0); ASSERT_EQ(st.st_size, 32);
        zcl_command_reply_free(&reply); memset(&reply, 0, sizeof(reply));

        snprintf(target, sizeof(target), "%s/absent-target", directory);
        snprintf(link, sizeof(link), "%s/link.psk", directory);
        ASSERT(symlink(target, link) == 0);
        ASSERT(psk_new_call(link, &reply));
        ASSERT_EQ(reply.status, ZCL_COMMAND_STATUS_FAILED);
        ASSERT_STR_EQ(reply.error.code, "PSK_KEY_EXISTS");
        ASSERT(lstat(target, &st) != 0);
        zcl_command_reply_free(&reply); memset(&reply, 0, sizeof(reply));

        ASSERT(chmod(directory, 0755) == 0);
        snprintf(path, sizeof(path), "%s/open.psk", directory);
        ASSERT(psk_new_call(path, &reply));
        ASSERT_STR_EQ(reply.error.code, "PSK_KEY_PARENT_NOT_PRIVATE");
        ASSERT(lstat(path, &st) != 0);
        ASSERT(chmod(directory, 0700) == 0);
    } TEST_END
    zcl_command_reply_free(&reply);
    if (directory[0]) { (void)chmod(directory, 0700); test_rm_rf(directory); }
    return failures;
}

static bool shell_argv_equal(const struct zcl_native_host_shell_argv *plan, const char *const *want, size_t count)
{
    if (plan->argc != count || plan->argv[count] != NULL) return false;
    for (size_t i = 0; i < count; ++i) if (!plan->argv[i] || strcmp(plan->argv[i], want[i])) return false;
    return true;
}

static int shell_dry_run_argv(void)
{
    int failures = 0;
    char directory[1024] = {0};
    TEST_CASE("device_host_shell: dry_run argv is the exact fixed ssh vector") {
        ASSERT(test_mkdtemp(directory, sizeof(directory), "device-host-shell"));
        char route[1200], proxy[2400];
        snprintf(route, sizeof(route), "%s/route.json", directory);
        ASSERT(shell_write(route, "{}", 0600));
        snprintf(proxy, sizeof(proxy), "ProxyCommand=/opt/z23/bin/z23 ops mesh device host client --input-file=%s", route);
        struct zcl_native_host_shell_argv plan; const char *refusal = "unset";
        ASSERT(zcl_native_device_host_shell_argv("/opt/z23/bin/z23", "rhett", "r2.lan", route, false, &plan, &refusal));
        ASSERT(refusal == NULL);
        const char *const sntrup[] = {"ssh", "-o", "KexAlgorithms=sntrup761x25519-sha512@openssh.com",
            "-o", "StrictHostKeyChecking=yes", "-o", "ControlPath=none", "-o", proxy, "--", "rhett@r2.lan"};
        ASSERT(shell_argv_equal(&plan, sntrup, sizeof(sntrup) / sizeof(sntrup[0])));
        ASSERT(zcl_native_device_host_shell_argv("/opt/z23/bin/z23", "rhett", "r2.lan", route, true, &plan, &refusal));
        const char *const both[] = {"ssh", "-o", "KexAlgorithms=mlkem768x25519-sha256,sntrup761x25519-sha512@openssh.com",
            "-o", "StrictHostKeyChecking=yes", "-o", "ControlPath=none", "-o", proxy, "--", "rhett@r2.lan"};
        ASSERT(shell_argv_equal(&plan, both, sizeof(both) / sizeof(both[0])));
        struct json_value out = {0};
        ASSERT(zcl_native_device_host_shell_json(&plan, &out));
        ASSERT_STR_EQ(json_get_str(json_get(&out, "schema")), "zcl.device.host.shell.v1");
        const struct json_value *list = json_get(&out, "argv");
        bool same = list && list->type == JSON_ARR && list->num_children == plan.argc;
        for (size_t i = 0; same && i < plan.argc; ++i) same = !strcmp(json_get_str(json_at(list, i)), both[i]);
        json_free(&out);
        ASSERT(same);
    } TEST_END
    if (directory[0]) test_rm_rf(directory);
    return failures;
}

struct shell_refusal { const char *user, *host, *route, *self, *field; };

static int shell_injection_refused(void)
{
    int failures = 0;
    char directory[1024] = {0};
    TEST_CASE("device_host_shell: shell, ssh-token and option injection refuse before any argv") {
        ASSERT(test_mkdtemp(directory, sizeof(directory), "device-host-shell"));
        char route[1200], linked[1200];
        snprintf(route, sizeof(route), "%s/route.json", directory);
        ASSERT(shell_write(route, "{}", 0600));
        snprintf(linked, sizeof(linked), "%s/linked.json", directory);
        ASSERT(symlink(route, linked) == 0);
        const char *self = "/opt/z23/bin/z23";
        const struct shell_refusal cases[] = {
            {"a;id", "h", route, self, "user_refused"}, {"$(id)", "h", route, self, "user_refused"},
            {"`id`", "h", route, self, "user_refused"}, {"a b", "h", route, self, "user_refused"},
            {"a%h", "h", route, self, "user_refused"}, {"a\nb", "h", route, self, "user_refused"},
            {"-oProxyCommand=id", "h", route, self, "user_refused"}, {"", "h", route, self, "user_refused"},
            {"a'b", "h", route, self, "user_refused"}, {"a\"b", "h", route, self, "user_refused"},
            {"u", "h;id", route, self, "host_refused"}, {"u", "$(id)", route, self, "host_refused"},
            {"u", "`id`", route, self, "host_refused"}, {"u", "h h", route, self, "host_refused"},
            {"u", "%h", route, self, "host_refused"}, {"u", "h\n", route, self, "host_refused"},
            {"u", "-oProxyCommand=id", route, self, "host_refused"}, {"u", "a@b", route, self, "host_refused"},
            {"u", "h", "route.json", self, "route_input_refused"},
            {"u", "h", "/x/a;id", self, "route_input_refused"}, {"u", "h", "/x/$(id)", self, "route_input_refused"},
            {"u", "h", "/x/`id`", self, "route_input_refused"}, {"u", "h", "/x/a b", self, "route_input_refused"},
            {"u", "h", "/x/%h", self, "route_input_refused"}, {"u", "h", "/x/a\nb", self, "route_input_refused"},
            {"u", "h", "/x/'q'", self, "route_input_refused"},
            {"u", "h", directory, self, "route_input_refused"}, {"u", "h", linked, self, "route_input_refused"},
            {"u", "h", "/nonexistent/route.json", self, "route_input_refused"},
            {"u", "h", route, "/opt/z23/bin/z23 (deleted)", "self_refused"},
            {"u", "h", route, "z23", "self_refused"}, {"u", "h", route, "/opt/$(id)/z23", "self_refused"},
        };
        for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
            struct zcl_native_host_shell_argv plan; const char *refusal = NULL;
            bool built = zcl_native_device_host_shell_argv(cases[i].self, cases[i].user, cases[i].host,
                cases[i].route, false, &plan, &refusal);
            if (built || !refusal || strcmp(refusal, cases[i].field) || plan.argc != 0)
                printf("injection case %zu admitted (refusal=%s)\n", i, refusal ? refusal : "none");
            ASSERT(!built); ASSERT(refusal != NULL); ASSERT_STR_EQ(refusal, cases[i].field); ASSERT_EQ(plan.argc, 0u);
        }
        char longest[300]; memset(longest, 'a', sizeof(longest) - 1); longest[sizeof(longest) - 1] = '\0';
        struct zcl_native_host_shell_argv plan; const char *refusal = NULL;
        ASSERT(!zcl_native_device_host_shell_argv(self, "u", longest, route, false, &plan, &refusal));
        ASSERT_STR_EQ(refusal, "host_refused");
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
    failures += shell_input_file() + shell_psk_fingerprint() + shell_psk_new();
    failures += shell_dry_run_argv() + shell_injection_refused();
#endif
    return failures;
}
