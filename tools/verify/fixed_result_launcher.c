/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0.
 * Root-owned fixed-result launcher preflight over the test_fast profile and
 * pins v2 (z23verify.fixed_result.v2). No observation is issued by
 * this binary until the separate worker/ACK and publisher protocol qualifies. */
#define _GNU_SOURCE
#include "base/hex.h"
#include "platform/os_proc.h"
#include "sha3/sha3.h"
#include "verify/fixed_result_contract.h"
#include "verify/fixed_result_source.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define POLICY "/etc/z23verify/fixed_result.policy"
#define PINS "/etc/z23verify/fixed_result.pins"
#define ARGS "/etc/z23verify/fixed_result_fast.args"
#define FILTER "/etc/z23verify/fixed_result.seccomp.bpf"
#define WORKER "/usr/local/libexec/z23-fixed-result-worker"
#define BWRAP "/usr/bin/bwrap"
#define TREE "/usr/local/libexec/z23-tree-closure"
#define SOURCE_IMAGE "/var/lib/z23verify/images/fixed_result/source"
#define TOOL_IMAGE "/var/lib/z23verify/images/fixed_result/tool"
#define CHECK_IMAGE "/var/lib/z23verify/images/fixed_result/check"

static const char *const policy_text =
    "z23verify.fixed_result.policy.v1\n"
    "compiler_uid=60093\n"
    "compiler_gid=60093\n"
    "recorded_cwd=/zclassic23\n"
    "source_image=" SOURCE_IMAGE "\n"
    "tool_image=" TOOL_IMAGE "\n"
    "check_image=" CHECK_IMAGE "\n"
    "worker=" WORKER "\n"
    "bwrap=" BWRAP "\n"
    "tree_closure=" TREE "\n"
    "seccomp_filter=" FILTER "\n"
    "launches=/var/lib/z23verify/launches\n"
    "socket=/run/z23verify/fixed_result.launch.sock\n"
    "request_timeout_ms=30000\n"
    "worker_timeout_ms=30000\n"
    "mounts=tool_ro,source_ro,work_private_tmpfs,tmp_private_tmpfs,dev_null\n"
    "namespaces=user,mount,net,pid,ipc,uts,cgroup\n"
    "network=none\n"
    "fd_inheritance=stdio_only\n";

static int refuse(const char *reason)
{
    fprintf(stderr, "fixed_result_launcher_refuse=%s\n", reason);
    return 2;
}

/* Walk every ancestor; a safe leaf under a writable/symlinked directory is
 * not a root pin. This also refuses a fixture under the shared checkout. */
static bool owned_component(const char *path, uid_t owner, bool directory)
{
    struct stat st;
    if (lstat(path, &st) != 0 || st.st_uid != owner ||
        (st.st_mode & 0022) != 0) return false;
    if (directory) return S_ISDIR(st.st_mode);
    return S_ISREG(st.st_mode) && st.st_nlink == 1;
}

static bool trusted_path(const char *path, uid_t owner, bool directory)
{
    char part[PATH_MAX];
    size_t len = strlen(path);
    if (len < 2 || len >= sizeof(part) || path[0] != '/') return false;
    memcpy(part, path, len + 1);
    if (!owned_component("/", owner, true)) return false;
    for (size_t i = 1; i <= len; i++) {
        if (part[i] != '/' && part[i] != '\0') continue;
        char saved = part[i];
        part[i] = '\0';
        if (!owned_component(part, owner, saved != '\0' || directory))
            return false;
        part[i] = saved;
    }
    return true;
}

static bool safe_root_file(const struct stat *st, off_t limit)
{
    return S_ISREG(st->st_mode) && st->st_uid == 0 && st->st_nlink == 1 &&
           (st->st_mode & 0022) == 0 &&
           st->st_size >= 0 && st->st_size <= limit;
}

static bool stable_file(const struct stat *a, const struct stat *b)
{
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino &&
           a->st_size == b->st_size &&
           a->st_mtim.tv_sec == b->st_mtim.tv_sec &&
           a->st_mtim.tv_nsec == b->st_mtim.tv_nsec &&
           a->st_ctim.tv_sec == b->st_ctim.tv_sec &&
           a->st_ctim.tv_nsec == b->st_ctim.tv_nsec;
}

static bool hash_stream(int fd, off_t limit, struct sha3_256_ctx *h)
{
    uint8_t bytes[16384];
    off_t count = 0;
    for (;;) {
        ssize_t n = read(fd, bytes, sizeof(bytes));
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) return false;
        if (n == 0) return count == limit;
        count += n;
        if (count > limit) return false;
        sha3_256_write(h, bytes, (size_t)n);
    }
}

static bool hash_fd(int fd, char out[65])
{
    struct stat before, after;
    if (fstat(fd, &before) != 0 ||
        !safe_root_file(&before, 128 * 1024 * 1024)) return false;
    struct sha3_256_ctx h;
    sha3_256_init(&h);
    bool ok = hash_stream(fd, before.st_size, &h);
    bool after_ok = fstat(fd, &after) == 0;
    if (!ok || !after_ok || !stable_file(&before, &after)) return false;
    uint8_t digest[32];
    sha3_256_finalize(&h, digest);
    zcl_hex_encode(digest, sizeof(digest), out);
    return true;
}

static bool hash_file(const char *path, char out[65])
{
    if (!trusted_path(path, 0, false)) return false;
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0) return false;
    bool ok = hash_fd(fd, out);
    return close(fd) == 0 && ok;
}

static bool read_fixed_bytes(int fd, char *out, size_t length)
{
    size_t at = 0;
    while (at < length) {
        ssize_t n = read(fd, out + at, length - at);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return false;
        at += (size_t)n;
    }
    return true;
}

static bool read_exact_root_file(const char *path, uint8_t *out, size_t cap,
                                 size_t *length)
{
    if (!trusted_path(path, 0, false)) return false;
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0) return false;
    struct stat before, after;
    bool ok = fstat(fd, &before) == 0 &&
              safe_root_file(&before, (off_t)cap - 1) && before.st_size > 0;
    if (ok) ok = read_fixed_bytes(fd, (char *)out, (size_t)before.st_size);
    bool after_ok = fstat(fd, &after) == 0;
    int close_result = close(fd);
    if (!ok || !after_ok || close_result != 0 ||
        !stable_file(&before, &after) || !safe_root_file(&after, (off_t)cap - 1))
        return false;
    *length = (size_t)before.st_size;
    return true;
}

static bool pin_file(const char *path, const uint8_t expected[32])
{
    char actual[65], want[65];
    zcl_hex_encode(expected, 32u, want);
    return hash_file(path, actual) && strcmp(actual, want) == 0;
}

static bool pin_self(const uint8_t expected[32])
{
    if (os_proc_self_exe_identity() != OS_PROC_IMAGE_IDENTITY_RUNNING_IMAGE)
        return false;
    FILE *image = os_proc_open_self_exe();
    if (!image) return false;
    char actual[65], want[65];
    bool ok = hash_fd(fileno(image), actual);
    if (fclose(image) != 0) return false;
    zcl_hex_encode(expected, 32u, want);
    return ok && strcmp(actual, want) == 0;
}

static void exec_tree_child(int write_fd, const char *path)
{
    if (dup2(write_fd, STDOUT_FILENO) < 0) _exit(127);
    if (close_range(3, ~0u, 0) != 0) _exit(127);
    char *const args[] = {(char *)TREE, "hash", (char *)path, "0", NULL};
    char *const env[] = {"LC_ALL=C", "PATH=/usr/bin:/bin", NULL};
    execve(TREE, args, env);
    _exit(127);
}

static bool capture_tree(int fd, char output[512], size_t *used)
{
    *used = 0;
    for (;;) {
        struct pollfd ready = {.fd = fd, .events = POLLIN};
        if (poll(&ready, 1, 120000) <= 0) return false;
        ssize_t n = read(fd, output + *used, 511 - *used);
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) return false;
        if (n == 0) return true;
        *used += (size_t)n;
        if (*used == 511) return false;
    }
}

static bool wait_tree(pid_t pid, bool captured)
{
    if (!captured) (void)kill(pid, SIGKILL);
    int status = 0;
    pid_t done;
    do { done = waitpid(pid, &status, 0); }
    while (done < 0 && errno == EINTR);
    return captured && done == pid && WIFEXITED(status) &&
           WEXITSTATUS(status) == 0;
}

/* The tree checker prints "tree_sha3=<64> content_sha3=<64> ...". Its tree
 * root is the image pin. The source_content pin is not its content root:
 * it is the source content root v2 over the fixed chain, measured below by
 * the same reader and definition the proof receiver uses. */
static bool tree_line_matches(const char *output, size_t used,
                              const uint8_t tree[32])
{
    static const char t[] = "tree_sha3=", c[] = " content_sha3=";
    const size_t t_len = sizeof(t) - 1u, c_len = sizeof(c) - 1u;
    char want[65];
    if (used < t_len + 64u + c_len + 64u + 1u ||
        strncmp(output, t, t_len) != 0 ||
        strncmp(output + t_len + 64u, c, c_len) != 0 ||
        output[t_len + 64u + c_len + 64u] != ' ')
        return false;
    zcl_hex_encode(tree, 32u, want);
    return memcmp(output + t_len, want, 64u) == 0;
}

static bool tree_root_matches(const char *path, const uint8_t tree[32])
{
    if (!trusted_path(path, 0, true)) return false;
    int pipefd[2];
    if (pipe2(pipefd, O_CLOEXEC) != 0) return false;
    pid_t pid = fork();
    if (pid < 0) { close(pipefd[0]); close(pipefd[1]); return false; }
    if (pid == 0) exec_tree_child(pipefd[1], path);
    close(pipefd[1]);
    char output[512];
    size_t used = 0;
    bool ok = capture_tree(pipefd[0], output, &used);
    close(pipefd[0]);
    if (!wait_tree(pid, ok)) return false;
    output[used] = '\0';
    return tree_line_matches(output, used, tree);
}

/* The source content root v2 of the fixed chain beneath `dir`. */
static const char *source_content_of(const char *dir, uint8_t out[32])
{
    int fd = open(dir, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return "source_content_unreadable";
    const char *why = zcl_fr_source_chain_root(fd, out);
    close(fd);
    return why;
}

/* Pins v2 (fixed_result_contract.h): a v1 text pins file, a strict
 * profile digest or any framing fault refuses by its contract token. */
static const char *check_policy_and_pins(struct zcl_fixed_result_v2_roots *pins)
{
    uint8_t pins_bytes[2048], policy_bytes[2048];
    size_t pins_length = 0, policy_length = 0;
    const char *why = NULL;
    if (!read_exact_root_file(PINS, pins_bytes, sizeof(pins_bytes),
                              &pins_length)) return "pins_unsafe";
    if (!zcl_fr_pins_parse(pins_bytes, pins_length, pins, &why)) return why;
    if (!read_exact_root_file(POLICY, policy_bytes, sizeof(policy_bytes),
                              &policy_length) ||
        policy_length != strlen(policy_text) ||
        memcmp(policy_bytes, policy_text, policy_length) != 0 ||
        !pin_file(POLICY, pins->policy)) return "policy_mismatch";
    return NULL;
}

/* zcl_fr_pins_parse already refused any environment root but the fixed
 * v2 environment and any profile digest but the fast profile. */
static const char *check_files(const struct zcl_fixed_result_v2_roots *pins)
{
    if (!pin_file(ARGS, pins->profile_args)) return "fast_args_mismatch";
    if (!pin_file(WORKER, pins->worker)) return "worker_mismatch";
    if (!pin_self(pins->launcher)) return "launcher_mismatch";
    if (!pin_file(FILTER, pins->seccomp_filter)) return "filter_mismatch";
    if (!pin_file(BWRAP, pins->bwrap)) return "bwrap_mismatch";
    if (!pin_file(TREE, pins->tree_checker)) return "tree_checker_mismatch";
    return NULL;
}

static const char *check_images(const struct zcl_fixed_result_v2_roots *pins)
{
    uint8_t content[32];
    if (!tree_root_matches(SOURCE_IMAGE, pins->source_image))
        return "source_image_mismatch";
    if (source_content_of(SOURCE_IMAGE, content) != NULL ||
        memcmp(content, pins->source_content, 32u) != 0)
        return "source_content_mismatch";
    if (!tree_root_matches(TOOL_IMAGE, pins->tool_image))
        return "tool_image_mismatch";
    if (!tree_root_matches(CHECK_IMAGE, pins->check_image))
        return "check_image_mismatch";
    return NULL;
}

/* source-content DIR : the source_content pin value (the first root given
 * to pins-encode) for the source image at DIR, as 64 lowercase hex. Needs
 * no privilege; preflight measures the installed image the same way. */
static int source_content(int count, char **dir)
{
    uint8_t root[32];
    char hex[65];
    if (count != 1) return refuse("request_shape_unsupported");
    const char *why = source_content_of(dir[0], root);
    if (why) return refuse(why);
    zcl_hex_encode(root, 32u, hex);
    return printf("%s\n", hex) == 65 && fflush(stdout) == 0
               ? 0 : refuse("source_content_write_failed");
}

/* pins-encode HEX... : the twelve roots in pins v2 order, written to
 * stdout as a pins v2 file for root to stage. The first, source_content,
 * is what `source-content <source image>` prints. Needs no privilege and
 * trusts nothing; preflight re-checks every root against the files. */
static int pins_encode(int count, char **hex)
{
    struct zcl_fixed_result_v2_roots pins;
    uint8_t out[2048];
    size_t len = 0;
    const char *why = NULL;
    if (count != (int)ZCL_FR_ROOT_COUNT)
        return refuse("request_shape_unsupported");
    for (size_t i = 0; i < ZCL_FR_ROOT_COUNT; i++)
        if (strlen(hex[i]) != 64u ||
            !zcl_hex_decode_lower(hex[i], zcl_fr_root_slot(&pins, i), 32u))
            return refuse(ZCL_FR_WHY_FIELD_MALFORMED);
    if (!zcl_fr_pins_encode(&pins, out, sizeof(out), &len, &why))
        return refuse(why);
    return fwrite(out, 1, len, stdout) == len && fflush(stdout) == 0
               ? 0 : refuse("pins_write_failed");
}

int main(int argc, char **argv)
{
    if (argc >= 2 && strcmp(argv[1], "source-content") == 0)
        return source_content(argc - 2, argv + 2);
    if (argc >= 2 && strcmp(argv[1], "pins-encode") == 0)
        return pins_encode(argc - 2, argv + 2);
    if (argc != 2 || strcmp(argv[1], "preflight") != 0)
        return refuse("request_shape_unsupported");
    if (getuid() != 0 || geteuid() != 0) return refuse("root_required");
    struct zcl_fixed_result_v2_roots pins;
    const char *reason = check_policy_and_pins(&pins);
    if (reason == NULL) reason = check_files(&pins);
    if (reason == NULL) reason = check_images(&pins);
    if (reason != NULL) return refuse(reason);
    puts("pinned_material_ok=1 attest_eligible=0");
    return refuse("isolation_unqualified");
}
