/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0.
 * Local prerequisites only. No same-account result authorizes attestation.
 * Self-test for tools/verify/tree_closure.c and fixed_result_closure.c.
 * Run from the repository root through tools/verify/tree_closure_probe.sh,
 * which passes its own name as argv[1]. */
#define _GNU_SOURCE
#include "sha3/sha3.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define PROBE "tree_closure_probe"
#define TEXT_MAX 1024

struct tree_hash {
    char text[TEXT_MAX];
    char tree[65];
    char content[65];
};

static char g_work[PATH_MAX];
static char g_uid[24];
static char g_zeros[65];
static char g_ones[65];
static char g_baseline[65];
static char g_path_env[PATH_MAX + 16];
static const char *g_name;
static const char *g_cc;
static const char *g_std;
static struct tree_hash g_first;


static volatile sig_atomic_t g_cleaning;
static volatile sig_atomic_t g_sig;

static void tcp_signal_set(sigset_t *set)
{
    sigemptyset(set);
    sigaddset(set, SIGINT);
    sigaddset(set, SIGTERM);
    sigaddset(set, SIGHUP);
}

static int tcp_rm_entry(const char *path, const struct stat *, int,
                        struct FTW *)
{
    return remove(path);
}

static void tcp_cleanup(void)
{
    sigset_t set;
    tcp_signal_set(&set);
    sigprocmask(SIG_BLOCK, &set, nullptr);
    if (g_cleaning || !g_work[0]) return;
    g_cleaning = 1;
    nftw(g_work, tcp_rm_entry, 16, FTW_DEPTH | FTW_PHYS);
}

/* The handler only records the signal; the main path acts on it. */
static void tcp_on_signal(int sig)
{
    g_sig = sig;
}

static void tcp_on_child(int sig)
{
    (void)sig;
}

static _Noreturn void tcp_die(int sig)
{
    struct sigaction sa = { .sa_handler = SIG_DFL };
    sigset_t set;
    tcp_cleanup();
    sigemptyset(&sa.sa_mask);
    sigaction(sig, &sa, nullptr);
    tcp_signal_set(&set);
    sigprocmask(SIG_UNBLOCK, &set, nullptr);
    raise(sig);
    _exit(128 + sig);
}

static void tcp_poll(void)
{
    if (g_sig) tcp_die(g_sig);
}

static void tcp_install_handlers(void)
{
    const int sigs[] = { SIGINT, SIGTERM, SIGHUP, SIGCHLD };
    struct sigaction sa = { .sa_flags = 0 };
    sigemptyset(&sa.sa_mask);
    for (size_t i = 0; i < sizeof sigs / sizeof sigs[0]; i++) {
        sa.sa_handler = sigs[i] == SIGCHLD ? tcp_on_child : tcp_on_signal;
        sigaction(sigs[i], &sa, nullptr);
    }
}

static void tcp_check(bool ok, const char *what)
{
    tcp_poll();
    if (ok) return;
    fprintf(stderr, "%s: failed: %s\n", PROBE, what);
    exit(1);
}

static const char *tcp_wp(const char *rel)
{
    static char ring[8][2 * PATH_MAX];
    static unsigned next;
    char *b = ring[next++ % 8];
    snprintf(b, 2 * PATH_MAX, "%s/%s", g_work, rel);
    return b;
}

static void tcp_redirect(int fd, const char *path)
{
    if (!path) return;
    int f = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (f < 0 || dup2(f, fd) < 0) _exit(127);
    close(f);
}
/* Forward the recorded signal, allow the child 5 s to exit, then kill it. */
static void tcp_reap_forwarded(pid_t pid, int sig)
{
    int st;
    kill(pid, sig);
    for (int i = 0; i < 500; i++) {
        if (waitpid(pid, &st, WNOHANG) != 0) return;
        nanosleep(&(struct timespec){ .tv_nsec = 10000000 }, nullptr);
    }
    kill(pid, SIGKILL);
    while (waitpid(pid, &st, 0) < 0 && errno == EINTR) {}
}

/* Signals stay blocked except inside sigsuspend, so none slips between the
 * check and the wait. */
static int tcp_wait(pid_t pid, const sigset_t *old)
{
    int st;
    for (;;) {
        pid_t r = waitpid(pid, &st, WNOHANG);
        if (r == pid) break;
        if (r < 0 && errno != EINTR) tcp_check(false, "waitpid");
        if (g_sig) {
            tcp_reap_forwarded(pid, g_sig);
            tcp_die(g_sig);
        }
        sigsuspend(old);
    }
    return WIFEXITED(st) ? WEXITSTATUS(st) : -1;
}

static int tcp_run(const char *const argv[], const char *out, const char *err,
                   char *const env[])
{
    tcp_poll();
    fflush(nullptr);
    sigset_t block, held;
    tcp_signal_set(&block);
    sigaddset(&block, SIGCHLD);
    sigprocmask(SIG_BLOCK, &block, &held);
    pid_t pid = fork();
    if (pid < 0) {
        sigprocmask(SIG_SETMASK, &held, nullptr);
        tcp_check(false, "fork");
    }
    if (pid == 0) {
        struct sigaction sa = { .sa_handler = SIG_DFL };
        sigemptyset(&sa.sa_mask);
        sigaction(SIGINT, &sa, nullptr);
        sigaction(SIGTERM, &sa, nullptr);
        sigaction(SIGHUP, &sa, nullptr);
        sigaction(SIGCHLD, &sa, nullptr);
        sigprocmask(SIG_SETMASK, &held, nullptr);
        tcp_redirect(1, out);
        tcp_redirect(2, err);
        for (size_t i = 0; env && env[i]; i++) putenv(env[i]);
        execv(argv[0], (char *const *)argv);
        _exit(127);
    }
    int rc = tcp_wait(pid, &held);
    sigprocmask(SIG_SETMASK, &held, nullptr);
    tcp_poll();
    return rc;
}

static void tcp_slurp(const char *path, char *buf, size_t cap)
{
    FILE *f = fopen(path, "r");
    size_t n = f ? fread(buf, 1, cap - 1, f) : 0;
    buf[n] = '\0';
    tcp_poll();
    if (f) {
        tcp_check(fgetc(f) == EOF, "output exceeds buffer");
        fclose(f);
    }
}

static void tcp_write_text(const char *path, const char *text)
{
    FILE *f = fopen(path, "w");
    tcp_check(f && fputs(text, f) >= 0 && fclose(f) == 0, "write file");
}

static void tcp_copy_file(const char *src, const char *dst)
{
    int in = open(src, O_RDONLY);
    struct stat st;
    tcp_check(in >= 0 && fstat(in, &st) == 0, "copy source");
    int out = open(dst, O_WRONLY | O_CREAT | O_EXCL, 0600);
    tcp_check(out >= 0, "copy destination");
    char buf[4096];
    ssize_t n;
    while ((n = read(in, buf, sizeof buf)) > 0)
        tcp_check(write(out, buf, (size_t)n) == n, "copy write");
    tcp_check(n == 0 && fchmod(out, st.st_mode & 07777) == 0, "copy finish");
    close(in);
    close(out);
}

static bool tcp_hex64(const char *p)
{
    for (int i = 0; i < 64; i++)
        if (!isxdigit((unsigned char)p[i]) || isupper((unsigned char)p[i]))
            return false;
    return true;
}

static bool tcp_field(const char *text, const char *key, bool bol, char end,
                  char out[65])
{
    for (const char *p = strstr(text, key); p; p = strstr(p + 1, key)) {
        if (bol && p != text && p[-1] != '\n') continue;
        const char *v = p + strlen(key);
        if (!tcp_hex64(v) || v[64] != end) continue;
        memcpy(out, v, 64);
        out[64] = '\0';
        return true;
    }
    return false;
}

static bool tcp_has_line(const char *text, const char *line)
{
    size_t n = strlen(line);
    for (const char *p = text; *p;) {
        size_t len = strcspn(p, "\n");
        if (len == n && memcmp(p, line, n) == 0) return true;
        p += len + (p[len] ? 1 : 0);
    }
    return false;
}

static int tcp_tree_hash(const char *dir, const char *uid, struct tree_hash *h)
{
    const char *argv[] = { tcp_wp("tree-closure"), "hash", dir, uid, nullptr };
    int rc = tcp_run(argv, tcp_wp("hash.out"), tcp_wp("hash.err"), nullptr);
    tcp_slurp(tcp_wp("hash.out"), h->text, sizeof h->text);
    h->tree[0] = h->content[0] = '\0';
    if (rc == 0)
        tcp_check(tcp_field(h->text, "tree_sha3=", true, ' ', h->tree) &&
              tcp_field(h->text, " content_sha3=", false, ' ', h->content),
              "tree digests");
    return rc;
}

static void tcp_hash_ok(const char *dir, struct tree_hash *h)
{
    tcp_check(tcp_tree_hash(dir, g_uid, h) == 0, "tree hash");
}

static void tcp_refuse_as(const char *dir, const char *uid, const char *reason)
{
    struct tree_hash h;
    tcp_check(tcp_tree_hash(dir, uid, &h) != 0, reason);
    char err[TEXT_MAX], want[128];
    tcp_slurp(tcp_wp("hash.err"), err, sizeof err);
    snprintf(want, sizeof want, "tree_closure_refuse=%s", reason);
    tcp_check(tcp_has_line(err, want), want);
}

static void tcp_refuse(const char *reason)
{
    tcp_refuse_as(tcp_wp("root"), g_uid, reason);
}

static void tcp_closure(const char *five, char *const env[], char out[65])
{
    struct tree_hash tool, root;
    tcp_hash_ok(tcp_wp("tool"), &tool);
    tcp_hash_ok(tcp_wp("root"), &root);
    char cwd[PATH_MAX];
    tcp_check(getcwd(cwd, sizeof cwd) != nullptr, "getcwd");
    const char *argv[] = { tcp_wp("fixed-result-closure"), "combine",
        tool.content, root.content, tool.tree, root.tree, five, g_zeros, cwd,
        nullptr };
    const char *outp = tcp_wp("combine.out");
    tcp_check(tcp_run(argv, outp, nullptr, env) == 0, "combine");
    char text[TEXT_MAX];
    tcp_slurp(outp, text, sizeof text);
    tcp_check(tcp_field(text, "closure_sha3=", true, '\n', out), "closure digest");
}

static void tcp_compile(const char *const sources[], size_t n, const char *out)
{
    const char *argv[24] = { g_cc, g_std, "-Wall", "-Wextra", "-Werror",
        "-pedantic", "-Iplatform/modules/sha3/include",
        "-Iplatform/modules/base/include" };
    size_t k = 8;
    for (size_t i = 0; i < n; i++) argv[k++] = sources[i];
    argv[k++] = "-o";
    argv[k++] = out;
    argv[k] = nullptr;
    tcp_check(tcp_run(argv, nullptr, nullptr, nullptr) == 0, "compile tool");
}

static void tcp_build_tools(void)
{
    const char *tree[] = { "tools/verify/tree_closure.c",
        "platform/modules/sha3/src/sha3.c",
        "platform/modules/base/src/safe_alloc.c" };
    const char *fixed[] = { "tools/verify/fixed_result_closure.c",
        "platform/modules/sha3/src/sha3.c" };
    tcp_compile(tree, 3, tcp_wp("tree-closure"));
    tcp_compile(fixed, 2, tcp_wp("fixed-result-closure"));
}

static void tcp_stage_green(void)
{
    tcp_write_text(tcp_wp("root/cc1"), "backend-one\n");
    tcp_write_text(tcp_wp("tool/cc1"), "backend-one\n");
    tcp_write_text(tcp_wp("root/result.c"), "#include \"base.h\"\n");
    tcp_write_text(tcp_wp("root/base.h"), "int result(void);\n");
    tcp_hash_ok(tcp_wp("root"), &g_first);
    tcp_check(strstr(g_first.text, "attest_eligible=0"), "attest_eligible=0");
    struct tree_hash again, clone;
    tcp_hash_ok(tcp_wp("root"), &again);
    tcp_check(!strcmp(g_first.tree, again.tree), "repeat tree digest");
    tcp_check(!strcmp(g_first.content, again.content), "repeat content digest");
    tcp_check(mkdir(tcp_wp("clone"), 0700) == 0, "mkdir clone");
    const char *names[] = { "cc1", "result.c", "base.h" };
    for (int i = 0; i < 3; i++) {
        char rel[64];
        snprintf(rel, sizeof rel, "root/%s", names[i]);
        char src[PATH_MAX];
        snprintf(src, sizeof src, "%s", tcp_wp(rel));
        snprintf(rel, sizeof rel, "clone/%s", names[i]);
        tcp_copy_file(src, tcp_wp(rel));
    }
    tcp_hash_ok(tcp_wp("clone"), &clone);
    tcp_check(!strcmp(clone.content, g_first.content), "portable content");
    tcp_refuse_as(tcp_wp("root"), "60092", "unsafe_root");
}

static void tcp_stage_closure(void)
{
    snprintf(g_path_env, sizeof g_path_env, "COMPILER_PATH=%s",
             tcp_wp("red-tool"));
    char *const env[] = { g_path_env, nullptr };
    char other[65];
    tcp_closure(g_zeros, nullptr, g_baseline);
    tcp_check(g_baseline[0], "baseline closure");
    tcp_closure(g_zeros, env, other);
    tcp_check(!strcmp(other, g_baseline), "policy claim stable");
    tcp_closure(g_ones, nullptr, other);
    tcp_check(strcmp(other, g_baseline), "policy claim changes closure");
}

static void tcp_stage_optional(void)
{
    struct tree_hash h;
    char c[65];
    tcp_write_text(tcp_wp("root/optional.h"), "int optional(void);\n");
    tcp_hash_ok(tcp_wp("root"), &h);
    tcp_check(strcmp(h.tree, g_first.tree), "optional header changes tree");
    tcp_closure(g_zeros, nullptr, c);
    tcp_check(strcmp(c, g_baseline), "optional header changes closure");
    tcp_check(unlink(tcp_wp("root/optional.h")) == 0, "remove optional");
    tcp_hash_ok(tcp_wp("root"), &h);
    tcp_check(!strcmp(h.tree, g_first.tree), "optional removal restores tree");
    tcp_closure(g_zeros, nullptr, c);
    tcp_check(!strcmp(c, g_baseline), "optional removal restores closure");
}

static void tcp_stage_backend(void)
{
    struct tree_hash h;
    char c[65];
    tcp_write_text(tcp_wp("root/cc1"), "backend-two\n");
    tcp_hash_ok(tcp_wp("root"), &h);
    tcp_check(strcmp(h.tree, g_first.tree), "backend replacement changes tree");
    tcp_write_text(tcp_wp("root/cc1"), "backend-one\n");
    tcp_write_text(tcp_wp("tool/cc1"), "backend-two\n");
    tcp_closure(g_zeros, nullptr, c);
    tcp_check(strcmp(c, g_baseline), "tool replacement changes closure");
    tcp_write_text(tcp_wp("tool/cc1"), "backend-one\n");
}

static void tcp_stage_unsafe(void)
{
    struct tree_hash h;
    char link[PATH_MAX];
    snprintf(link, sizeof link, "%s", tcp_wp("root/backend-link"));
    tcp_check(chmod(tcp_wp("root/cc1"), 0666) == 0, "chmod 666");
    tcp_refuse("writable_entry");
    tcp_check(chmod(tcp_wp("root/cc1"), 0600) == 0, "chmod 600");
    tcp_check(symlink("cc1", link) == 0, "symlink inside");
    tcp_hash_ok(tcp_wp("root"), &h);
    tcp_check(unlink(link) == 0 && symlink("/etc/passwd", link) == 0, "relink");
    tcp_refuse("symlink_absolute");
    tcp_check(unlink(link) == 0, "unlink");
    tcp_write_text(tcp_wp("outside"), "outside\n");
    tcp_check(symlink("../outside", link) == 0, "symlink outside");
    tcp_refuse("symlink_escapes_root");
    tcp_check(unlink(link) == 0, "unlink");
    tcp_check(mkfifo(tcp_wp("root/pipe"), 0666) == 0, "mkfifo");
    tcp_refuse("special_entry");
    tcp_check(unlink(tcp_wp("root/pipe")) == 0, "unlink fifo");
}

static void tcp_file_digest(const char *path, unsigned char out[32])
{
    FILE *f = fopen(path, "rb");
    tcp_check(f != nullptr, "open driver");
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    unsigned char buf[65536];
    size_t n;
    while ((n = fread(buf, 1, sizeof buf, f)) > 0)
        sha3_256_write(&ctx, buf, n);
    tcp_check(!ferror(f), "read driver");
    fclose(f);
    sha3_256_finalize(&ctx, out);
}

static void tcp_stage_red(void)
{
    char real_cc1[PATH_MAX];
    const char *pn[] = { g_cc, "-print-prog-name=cc1", nullptr };
    tcp_check(tcp_run(pn, tcp_wp("cc1.path"), nullptr, nullptr) == 0, "prog-name");
    tcp_slurp(tcp_wp("cc1.path"), real_cc1, sizeof real_cc1);
    real_cc1[strcspn(real_cc1, "\n")] = '\0';
    tcp_check(real_cc1[0], "cc1 path");
    tcp_write_text(tcp_wp("red-tool/cc1"), "#!/bin/sh\n"
               "printf 'invoked\\n' > \"$RED_MARKER\"\n"
               "exec \"$REAL_CC1\" \"$@\"\n");
    tcp_check(chmod(tcp_wp("red-tool/cc1"), 0700) == 0, "chmod wrapper");
    tcp_write_text(tcp_wp("unit.c"), "int z23_red(void) { return 7; }\n");
    unsigned char before[32], after[32];
    tcp_file_digest(g_cc, before);
    char marker[PATH_MAX + 16], real[PATH_MAX + 16];
    snprintf(marker, sizeof marker, "RED_MARKER=%s", tcp_wp("cc1.marker"));
    snprintf(real, sizeof real, "REAL_CC1=%s", real_cc1);
    char *const env[] = { marker, real, g_path_env, nullptr };
    const char *cc[] = { g_cc, g_std, "-c", tcp_wp("unit.c"), "-o",
                         tcp_wp("unit.o"), nullptr };
    tcp_check(tcp_run(cc, nullptr, nullptr, env) == 0, "red compile");
    tcp_file_digest(g_cc, after);
    struct stat st;
    tcp_check(stat(tcp_wp("cc1.marker"), &st) == 0 && st.st_size > 0, "marker");
    tcp_check(!memcmp(before, after, sizeof before), "driver unchanged");
}

static void tcp_make_work(void)
{
    umask(077);
    const char *home = getenv("HOME");
    tcp_check(home && *home, "HOME");
    char templ[PATH_MAX];
    int n = snprintf(templ, sizeof templ, "%s/.z23-verify-tree-probe.XXXXXX",
                     home);
    tcp_check(n > 0 && (size_t)n < sizeof templ, "HOME length");
    tcp_install_handlers();
    sigset_t set, old;
    tcp_signal_set(&set);
    sigprocmask(SIG_BLOCK, &set, &old);
    bool made = mkdtemp(templ) != nullptr;
    if (made) {
        memcpy(g_work, templ, (size_t)n + 1);
        atexit(tcp_cleanup);
    }
    sigprocmask(SIG_SETMASK, &old, nullptr);
    tcp_check(made, "mkdtemp");
    const char *dirs[] = { "root", "tool", "red-tool" };
    for (int i = 0; i < 3; i++)
        tcp_check(mkdir(tcp_wp(dirs[i]), 0700) == 0, "mkdir");
    snprintf(g_uid, sizeof g_uid, "%u", (unsigned)getuid());
    memset(g_zeros, '0', 64);
    memset(g_ones, '0', 63);
    g_ones[63] = '1';
    if (getenv("TREE_CLOSURE_PROBE_READY")) fputs("ready\n", stderr);
}

int main(int argc, char **argv)
{
    g_name = argc > 1 ? argv[1] : "tree_closure_probe";
    bool ok = argc == 4 && !strcmp(argv[2], "/usr/bin/gcc") &&
              (!strcmp(argv[3], "-std=c2x") || !strcmp(argv[3], "-std=c23"));
    if (!ok) {
        fprintf(stderr, "usage: %s /usr/bin/gcc -std=c2x|-std=c23\n", g_name);
        return 2;
    }
    g_cc = argv[2];
    g_std = argv[3];
    tcp_make_work();
    tcp_build_tools();
    tcp_stage_green();
    tcp_stage_closure();
    tcp_stage_optional();
    tcp_stage_backend();
    tcp_stage_unsafe();
    tcp_stage_red();
    puts("tree_green=1 portable_content_equal=1 uid_mismatch_red=1 "
         "negative_header_red=1 backend_replacement_red=1 policy_claim_red=1 "
         "unsafe_entry_refusals=4");
    puts("compiler_path_red=1 unchanged_driver=1 fixed_env_claim_stable=1 "
         "gcc_driver_invocations=4 actual_compiles=3 "
         "proof_launches_avoided=0 attestation_eligible=0");
    return 0;
}
