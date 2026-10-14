/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0.
 * Local prerequisites only. No same-account result authorizes attestation.
 * Self-test for tools/verify/tree_closure.c and fixed_result_closure.c.
 * Run from the repository root through tools/verify/tree_closure_probe.sh,
 * which passes its own name as argv[1]. */
#define _GNU_SOURCE
#include "sha3/sha3.h"

#include <ctype.h>
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

static void check(bool ok, const char *what)
{
    if (ok) return;
    fprintf(stderr, "%s: failed: %s\n", PROBE, what);
    exit(1);
}

static const char *wp(const char *rel)
{
    static char ring[8][2 * PATH_MAX];
    static unsigned next;
    char *b = ring[next++ % 8];
    snprintf(b, 2 * PATH_MAX, "%s/%s", g_work, rel);
    return b;
}

static void redirect(int fd, const char *path)
{
    if (!path) return;
    int f = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (f < 0 || dup2(f, fd) < 0) _exit(127);
    close(f);
}

static volatile sig_atomic_t g_cleaning;

static void block_signals(sigset_t *old)
{
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGINT);
    sigaddset(&set, SIGTERM);
    sigaddset(&set, SIGHUP);
    sigprocmask(SIG_BLOCK, &set, old);
}

static int run(const char *const argv[], const char *out, const char *err,
               char *const env[])
{
    fflush(nullptr);
    sigset_t held;
    block_signals(&held);
    pid_t pid = fork();
    check(pid >= 0, "fork");
    if (pid == 0) {
        signal(SIGINT, SIG_DFL);
        signal(SIGTERM, SIG_DFL);
        signal(SIGHUP, SIG_DFL);
        sigprocmask(SIG_SETMASK, &held, nullptr);
        redirect(1, out);
        redirect(2, err);
        for (size_t i = 0; env && env[i]; i++) putenv(env[i]);
        execv(argv[0], (char *const *)argv);
        _exit(127);
    }
    sigprocmask(SIG_SETMASK, &held, nullptr);
    int st;
    check(waitpid(pid, &st, 0) == pid, "waitpid");
    return WIFEXITED(st) ? WEXITSTATUS(st) : -1;
}

static void slurp(const char *path, char *buf, size_t cap)
{
    FILE *f = fopen(path, "r");
    size_t n = f ? fread(buf, 1, cap - 1, f) : 0;
    buf[n] = '\0';
    if (f) {
        check(fgetc(f) == EOF, "output exceeds buffer");
        fclose(f);
    }
}

static void write_text(const char *path, const char *text)
{
    FILE *f = fopen(path, "w");
    check(f && fputs(text, f) >= 0 && fclose(f) == 0, "write file");
}

static void copy_file(const char *src, const char *dst)
{
    int in = open(src, O_RDONLY);
    struct stat st;
    check(in >= 0 && fstat(in, &st) == 0, "copy source");
    int out = open(dst, O_WRONLY | O_CREAT | O_EXCL, 0600);
    check(out >= 0, "copy destination");
    char buf[4096];
    ssize_t n;
    while ((n = read(in, buf, sizeof buf)) > 0)
        check(write(out, buf, (size_t)n) == n, "copy write");
    check(n == 0 && fchmod(out, st.st_mode & 07777) == 0, "copy finish");
    close(in);
    close(out);
}

static bool hex64(const char *p)
{
    for (int i = 0; i < 64; i++)
        if (!isxdigit((unsigned char)p[i]) || isupper((unsigned char)p[i]))
            return false;
    return true;
}

static bool field(const char *text, const char *key, bool bol, char end,
                  char out[65])
{
    for (const char *p = strstr(text, key); p; p = strstr(p + 1, key)) {
        if (bol && p != text && p[-1] != '\n') continue;
        const char *v = p + strlen(key);
        if (!hex64(v) || v[64] != end) continue;
        memcpy(out, v, 64);
        out[64] = '\0';
        return true;
    }
    return false;
}

static bool has_line(const char *text, const char *line)
{
    size_t n = strlen(line);
    for (const char *p = text; *p;) {
        size_t len = strcspn(p, "\n");
        if (len == n && memcmp(p, line, n) == 0) return true;
        p += len + (p[len] ? 1 : 0);
    }
    return false;
}

static int tree_hash(const char *dir, const char *uid, struct tree_hash *h)
{
    const char *argv[] = { wp("tree-closure"), "hash", dir, uid, nullptr };
    int rc = run(argv, wp("hash.out"), wp("hash.err"), nullptr);
    slurp(wp("hash.out"), h->text, sizeof h->text);
    h->tree[0] = h->content[0] = '\0';
    if (rc == 0)
        check(field(h->text, "tree_sha3=", true, ' ', h->tree) &&
              field(h->text, " content_sha3=", false, ' ', h->content),
              "tree digests");
    return rc;
}

static void hash_ok(const char *dir, struct tree_hash *h)
{
    check(tree_hash(dir, g_uid, h) == 0, "tree hash");
}

static void refuse_as(const char *dir, const char *uid, const char *reason)
{
    struct tree_hash h;
    check(tree_hash(dir, uid, &h) != 0, reason);
    char err[TEXT_MAX], want[128];
    slurp(wp("hash.err"), err, sizeof err);
    snprintf(want, sizeof want, "tree_closure_refuse=%s", reason);
    check(has_line(err, want), want);
}

static void refuse(const char *reason)
{
    refuse_as(wp("root"), g_uid, reason);
}

static void closure(const char *five, char *const env[], char out[65])
{
    struct tree_hash tool, root;
    hash_ok(wp("tool"), &tool);
    hash_ok(wp("root"), &root);
    char cwd[PATH_MAX];
    check(getcwd(cwd, sizeof cwd) != nullptr, "getcwd");
    const char *argv[] = { wp("fixed-result-closure"), "combine",
        tool.content, root.content, tool.tree, root.tree, five, g_zeros, cwd,
        nullptr };
    const char *outp = wp("combine.out");
    check(run(argv, outp, nullptr, env) == 0, "combine");
    char text[TEXT_MAX];
    slurp(outp, text, sizeof text);
    check(field(text, "closure_sha3=", true, '\n', out), "closure digest");
}

static void compile(const char *const sources[], size_t n, const char *out)
{
    const char *argv[24] = { g_cc, g_std, "-Wall", "-Wextra", "-Werror",
        "-pedantic", "-Iplatform/modules/sha3/include",
        "-Iplatform/modules/base/include" };
    size_t k = 8;
    for (size_t i = 0; i < n; i++) argv[k++] = sources[i];
    argv[k++] = "-o";
    argv[k++] = out;
    argv[k] = nullptr;
    check(run(argv, nullptr, nullptr, nullptr) == 0, "compile tool");
}

static void build_tools(void)
{
    const char *tree[] = { "tools/verify/tree_closure.c",
        "platform/modules/sha3/src/sha3.c",
        "platform/modules/base/src/safe_alloc.c" };
    const char *fixed[] = { "tools/verify/fixed_result_closure.c",
        "platform/modules/sha3/src/sha3.c" };
    compile(tree, 3, wp("tree-closure"));
    compile(fixed, 2, wp("fixed-result-closure"));
}

static void stage_green(void)
{
    write_text(wp("root/cc1"), "backend-one\n");
    write_text(wp("tool/cc1"), "backend-one\n");
    write_text(wp("root/result.c"), "#include \"base.h\"\n");
    write_text(wp("root/base.h"), "int result(void);\n");
    hash_ok(wp("root"), &g_first);
    check(strstr(g_first.text, "attest_eligible=0"), "attest_eligible=0");
    struct tree_hash again, clone;
    hash_ok(wp("root"), &again);
    check(!strcmp(g_first.tree, again.tree), "repeat tree digest");
    check(!strcmp(g_first.content, again.content), "repeat content digest");
    check(mkdir(wp("clone"), 0700) == 0, "mkdir clone");
    const char *names[] = { "cc1", "result.c", "base.h" };
    for (int i = 0; i < 3; i++) {
        char rel[64];
        snprintf(rel, sizeof rel, "root/%s", names[i]);
        char src[PATH_MAX];
        snprintf(src, sizeof src, "%s", wp(rel));
        snprintf(rel, sizeof rel, "clone/%s", names[i]);
        copy_file(src, wp(rel));
    }
    hash_ok(wp("clone"), &clone);
    check(!strcmp(clone.content, g_first.content), "portable content");
    refuse_as(wp("root"), "60092", "unsafe_root");
}

static void stage_closure(void)
{
    snprintf(g_path_env, sizeof g_path_env, "COMPILER_PATH=%s",
             wp("red-tool"));
    char *const env[] = { g_path_env, nullptr };
    char other[65];
    closure(g_zeros, nullptr, g_baseline);
    check(g_baseline[0], "baseline closure");
    closure(g_zeros, env, other);
    check(!strcmp(other, g_baseline), "policy claim stable");
    closure(g_ones, nullptr, other);
    check(strcmp(other, g_baseline), "policy claim changes closure");
}

static void stage_optional(void)
{
    struct tree_hash h;
    char c[65];
    write_text(wp("root/optional.h"), "int optional(void);\n");
    hash_ok(wp("root"), &h);
    check(strcmp(h.tree, g_first.tree), "optional header changes tree");
    closure(g_zeros, nullptr, c);
    check(strcmp(c, g_baseline), "optional header changes closure");
    check(unlink(wp("root/optional.h")) == 0, "remove optional");
    hash_ok(wp("root"), &h);
    check(!strcmp(h.tree, g_first.tree), "optional removal restores tree");
    closure(g_zeros, nullptr, c);
    check(!strcmp(c, g_baseline), "optional removal restores closure");
}

static void stage_backend(void)
{
    struct tree_hash h;
    char c[65];
    write_text(wp("root/cc1"), "backend-two\n");
    hash_ok(wp("root"), &h);
    check(strcmp(h.tree, g_first.tree), "backend replacement changes tree");
    write_text(wp("root/cc1"), "backend-one\n");
    write_text(wp("tool/cc1"), "backend-two\n");
    closure(g_zeros, nullptr, c);
    check(strcmp(c, g_baseline), "tool replacement changes closure");
    write_text(wp("tool/cc1"), "backend-one\n");
}

static void stage_unsafe(void)
{
    struct tree_hash h;
    char link[PATH_MAX];
    snprintf(link, sizeof link, "%s", wp("root/backend-link"));
    check(chmod(wp("root/cc1"), 0666) == 0, "chmod 666");
    refuse("writable_entry");
    check(chmod(wp("root/cc1"), 0600) == 0, "chmod 600");
    check(symlink("cc1", link) == 0, "symlink inside");
    hash_ok(wp("root"), &h);
    check(unlink(link) == 0 && symlink("/etc/passwd", link) == 0, "relink");
    refuse("symlink_absolute");
    check(unlink(link) == 0, "unlink");
    write_text(wp("outside"), "outside\n");
    check(symlink("../outside", link) == 0, "symlink outside");
    refuse("symlink_escapes_root");
    check(unlink(link) == 0, "unlink");
    check(mkfifo(wp("root/pipe"), 0666) == 0, "mkfifo");
    refuse("special_entry");
    check(unlink(wp("root/pipe")) == 0, "unlink fifo");
}

static void file_digest(const char *path, unsigned char out[32])
{
    FILE *f = fopen(path, "rb");
    check(f != nullptr, "open driver");
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    unsigned char buf[65536];
    size_t n;
    while ((n = fread(buf, 1, sizeof buf, f)) > 0)
        sha3_256_write(&ctx, buf, n);
    check(!ferror(f), "read driver");
    fclose(f);
    sha3_256_finalize(&ctx, out);
}

static void stage_red(void)
{
    char real_cc1[PATH_MAX];
    const char *pn[] = { g_cc, "-print-prog-name=cc1", nullptr };
    check(run(pn, wp("cc1.path"), nullptr, nullptr) == 0, "prog-name");
    slurp(wp("cc1.path"), real_cc1, sizeof real_cc1);
    real_cc1[strcspn(real_cc1, "\n")] = '\0';
    check(real_cc1[0], "cc1 path");
    write_text(wp("red-tool/cc1"), "#!/bin/sh\n"
               "printf 'invoked\\n' > \"$RED_MARKER\"\n"
               "exec \"$REAL_CC1\" \"$@\"\n");
    check(chmod(wp("red-tool/cc1"), 0700) == 0, "chmod wrapper");
    write_text(wp("unit.c"), "int z23_red(void) { return 7; }\n");
    unsigned char before[32], after[32];
    file_digest(g_cc, before);
    char marker[PATH_MAX + 16], real[PATH_MAX + 16];
    snprintf(marker, sizeof marker, "RED_MARKER=%s", wp("cc1.marker"));
    snprintf(real, sizeof real, "REAL_CC1=%s", real_cc1);
    char *const env[] = { marker, real, g_path_env, nullptr };
    const char *cc[] = { g_cc, g_std, "-c", wp("unit.c"), "-o",
                         wp("unit.o"), nullptr };
    check(run(cc, nullptr, nullptr, env) == 0, "red compile");
    file_digest(g_cc, after);
    struct stat st;
    check(stat(wp("cc1.marker"), &st) == 0 && st.st_size > 0, "marker");
    check(!memcmp(before, after, sizeof before), "driver unchanged");
}

static int rm_entry(const char *path, const struct stat *, int,
                    struct FTW *)
{
    return remove(path);
}

static void cleanup(void)
{
    if (g_cleaning || !g_work[0]) return;
    g_cleaning = 1;
    sigset_t old;
    block_signals(&old);
    nftw(g_work, rm_entry, 16, FTW_DEPTH | FTW_PHYS);
}

static void on_signal(int sig)
{
    if (!g_cleaning) cleanup();
    raise(sig);
}

static void install_handlers(void)
{
    struct sigaction sa = { .sa_handler = on_signal,
                            .sa_flags = SA_RESETHAND | SA_NODEFER };
    sigemptyset(&sa.sa_mask);
    const int sigs[] = { SIGINT, SIGTERM, SIGHUP };
    for (size_t i = 0; i < sizeof sigs / sizeof sigs[0]; i++)
        sigaction(sigs[i], &sa, nullptr);
}

static void make_work(void)
{
    umask(077);
    const char *home = getenv("HOME");
    check(home && *home, "HOME");
    snprintf(g_work, sizeof g_work, "%s/.z23-verify-tree-probe.XXXXXX", home);
    check(mkdtemp(g_work) != nullptr, "mkdtemp");
    atexit(cleanup);
    install_handlers();
    const char *dirs[] = { "root", "tool", "red-tool" };
    for (int i = 0; i < 3; i++) check(mkdir(wp(dirs[i]), 0700) == 0, "mkdir");
    snprintf(g_uid, sizeof g_uid, "%u", (unsigned)getuid());
    memset(g_zeros, '0', 64);
    memset(g_ones, '0', 63);
    g_ones[63] = '1';
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
    make_work();
    build_tools();
    stage_green();
    stage_closure();
    stage_optional();
    stage_backend();
    stage_unsafe();
    stage_red();
    puts("tree_green=1 portable_content_equal=1 uid_mismatch_red=1 "
         "negative_header_red=1 backend_replacement_red=1 policy_claim_red=1 "
         "unsafe_entry_refusals=4");
    puts("compiler_path_red=1 unchanged_driver=1 fixed_env_claim_stable=1 "
         "gcc_driver_invocations=4 actual_compiles=3 "
         "proof_launches_avoided=0 attestation_eligible=0");
    return 0;
}
