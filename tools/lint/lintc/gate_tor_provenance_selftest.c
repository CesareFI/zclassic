/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: selftest of check-tor-provenance. Builds a throwaway repository
 * root whose compiler, helper binary and identity tool are shell fixtures,
 * and proves: the helper receives the compiler statuses and logs, the
 * manifest check receives the vendor/tor commit and the derived compiler
 * identity, a failing helper stops the gate with status 1, and SIGINT (once
 * and twice), SIGTERM and SIGHUP delivered after a readiness handshake over
 * a pipe stop the compiler child, including one that ignores the signal,
 * remove the scratch directory and re-raise the signal.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include "gate_tor_provenance_priv.h"
#include "lintc.h"

enum { TPS_BUF = 8192 };

struct tps_fx {
    char base[TP_PATH];
    char root[TP_PATH + 16];
    char calls[TP_PATH + 32];
};

static int tps_fail(const char *what)
{
    fprintf(stderr, "check_tor_provenance selftest: FAIL - %s\n", what);
    return 1;
}

static int tps_put(const char *path, const char *text, mode_t mode)
{
    FILE *f = fopen(path, "w");
    if (!f)
        return -1;
    fputs(text, f);
    if (fclose(f) != 0)
        return -1;
    return chmod(path, mode);
}

static int tps_path(char *out, size_t cap, const char *a, const char *b)
{
    return snprintf(out, cap, "%s/%s", a, b) >= (int)cap ? -1 : 0;
}

static const char k_tps_cc[] =
    "#!/bin/sh\n"
    "case \"$TPS_MODE\" in\n"
    "hold) echo \"$$\" >&\"$TPS_READY_FD\"; exec sleep 30;;\n"
    "stubborn) trap '' INT TERM HUP; echo \"$$\" >&\"$TPS_READY_FD\"\n"
    "  while :; do sleep 1; done;;\n"
    "esac\n"
    "case \" $* \" in *base/include*) exit 0;; esac\n"
    "echo 'error: base include is missing' >&2\n"
    "exit 1\n";

static const char k_tps_tool[] =
    "#!/bin/sh\n"
    "echo \"$*\" >> \"$TPS_CALLS\"\n"
    "if [ \"$1\" = check-compiler-results ]; then cat \"$4\" \"$5\" >> \"$TPS_CALLS\"\n"
    "  [ \"$TPS_FAIL\" = 1 ] && exit 1; fi\n"
    "exit 0\n";

static const char k_tps_id[] = "#!/bin/sh\necho \"ID:$2\"\n";

static int tps_git(const char *vendor)
{
    char cmd[TP_PATH * 3], q[TP_PATH * 2], out[TPS_BUF];
    int code = 0;
    if (sh_single_quote(vendor, q, sizeof q)
        || snprintf(cmd, sizeof cmd,
                    "cd %s && GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null "
                    "git init -q . && GIT_AUTHOR_NAME=t GIT_AUTHOR_EMAIL=t@t "
                    "GIT_COMMITTER_NAME=t GIT_COMMITTER_EMAIL=t@t "
                    "git -c commit.gpgsign=false commit -q --allow-empty -m x 2>&1",
                    q) >= (int)sizeof cmd)
        return -1;
    return capture_cmd(cmd, out, sizeof out, &code) == 0 && code == 0 ? 0 : -1;
}

/* Absolute scratch parent: an absolute TMPDIR, else <root>/test-tmp. */
static int tps_scratch_parent(char *out, size_t cap)
{
    const char *tmp = getenv("TMPDIR");
    char root[TP_PATH], probe[TP_PATH + 32];
    if (tmp && tmp[0] == '/')
        return snprintf(out, cap, "%s", tmp) >= (int)cap ? -1 : 0;
    if (cic_repo_root(root, sizeof root)
        || snprintf(probe, sizeof probe, "%s/test-tmp/x", root) >= (int)sizeof probe
        || csr_mkdirs(probe) != 0)
        return -1;
    return snprintf(out, cap, "%s/test-tmp", root) >= (int)cap ? -1 : 0;
}

static int tps_build(struct tps_fx *fx)
{
    char p[TP_PATH * 2], d[TP_PATH * 2], parent[TP_PATH];
    if (tps_scratch_parent(parent, sizeof parent) != 0
        || snprintf(fx->base, sizeof fx->base, "%s/tor-gate-selftest.XXXXXX", parent)
               >= (int)sizeof fx->base
        || !mkdtemp(fx->base))
        return -1;
    snprintf(fx->root, sizeof fx->root, "%s/root", fx->base);
    snprintf(fx->calls, sizeof fx->calls, "%s/calls.txt", fx->base);
    static const char *const dirs[] = { "root", "root/tools", "root/tools/dev", "root/build",
                                        "root/build/bin", "root/vendor", "root/vendor/tor" };
    for (size_t i = 0; i < sizeof dirs / sizeof dirs[0]; i++) {
        if (tps_path(d, sizeof d, fx->base, dirs[i]) || mkdir(d, 0700) != 0)
            return -1;
    }
    if (tps_path(p, sizeof p, fx->base, "cc.sh") || tps_put(p, k_tps_cc, 0700))
        return -1;
    if (tps_path(p, sizeof p, fx->root, "build/bin/z23-tor-provenance")
        || tps_put(p, k_tps_tool, 0700))
        return -1;
    if (tps_path(p, sizeof p, fx->root, "tools/dev/build-epoch-key.sh")
        || tps_put(p, k_tps_id, 0700))
        return -1;
    tps_path(p, sizeof p, fx->root, "vendor/tor");
    return tps_git(p);
}

static void tps_env(const struct tps_fx *fx, const char *mode, int ready_fd)
{
    char cc[TP_PATH + 16], fd[16];
    snprintf(cc, sizeof cc, "%s/cc.sh", fx->base);
    snprintf(fd, sizeof fd, "%d", ready_fd);
    setenv("CC", cc, 1);
    setenv("VENDOR_CC", cc, 1);
    setenv("TMPDIR", fx->base, 1);
    setenv("TPS_CALLS", fx->calls, 1);
    setenv("TPS_MODE", mode, 1);
    setenv("TPS_READY_FD", fd, 1);
}

static int tps_slurp(const char *path, char *buf, size_t cap)
{
    FILE *f = fopen(path, "r");
    size_t n = f ? fread(buf, 1, cap - 1, f) : 0;
    if (f)
        fclose(f);
    buf[n] = '\0';
    return f ? 0 : -1;
}

static int tps_scratch_left(const char *base)
{
    DIR *d = opendir(base);
    struct dirent *e;
    int left = 0;
    while (d && (e = readdir(d)) != NULL)
        left += strncmp(e->d_name, "tor-compiler.", 13) == 0;
    if (d)
        closedir(d);
    return left;
}

static pid_t tps_fork_gate(const struct tps_fx *fx, const char *mode, int *rfd, int grace)
{
    int fds[2];
    if (pipe(fds) != 0)
        return -1;
    pid_t pid = fork();
    if (pid == 0) {
        close(fds[0]);
        tps_env(fx, mode, fds[1]);
        _exit(tp_gate(fx->root, grace));
    }
    close(fds[1]);
    *rfd = fds[0];
    return pid;
}

static int tps_normal(const struct tps_fx *fx, int fail)
{
    char buf[TPS_BUF];
    int rfd, st = 0;
    unlink(fx->calls);
    setenv("TPS_FAIL", fail ? "1" : "0", 1);
    pid_t pid = tps_fork_gate(fx, "ok", &rfd, TP_GRACE_MS);
    if (pid < 0 || waitpid(pid, &st, 0) != pid)
        return tps_fail("the gate child did not finish");
    close(rfd);
    if (!WIFEXITED(st) || WEXITSTATUS(st) != (fail ? 1 : 0))
        return tps_fail("the gate exit status does not follow the helper");
    if (tps_slurp(fx->calls, buf, sizeof buf))
        return tps_fail("the helper was never called");
    if (!strstr(buf, "check-compiler-results 0 1 ") || !strstr(buf, "error: base include is missing"))
        return tps_fail("the helper did not get both compiler statuses and the negative log");
    if (fail)
        return strstr(buf, "--selftest") ? tps_fail("a failing helper did not stop the gate") : 0;
    if (!strstr(buf, "--selftest") || !strstr(buf, "--tor-commit ") || !strstr(buf, "--compiler-id ID:"))
        return tps_fail("the manifest check did not get the commit and compiler identity");
    return 0;
}

static int tps_read_pid(int rfd, pid_t *child)
{
    char line[64];
    size_t used = 0;
    while (used + 1 < sizeof line) {
        ssize_t n = read(rfd, line + used, 1);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0 || line[used] == '\n')
            break;
        used++;
    }
    line[used] = '\0';
    *child = (pid_t)atoi(line);
    return *child > 0 ? 0 : -1;
}

static int tps_signal(const struct tps_fx *fx, const char *mode, int sig, int times)
{
    int rfd, st = 0;
    pid_t gate = tps_fork_gate(fx, mode, &rfd, 300), cc = 0;
    if (gate < 0)
        return tps_fail("fork failed");
    int ready = tps_read_pid(rfd, &cc);
    close(rfd);
    for (int i = 0; ready == 0 && i < times; i++)
        kill(gate, sig);
    if (waitpid(gate, &st, 0) != gate || ready != 0)
        return tps_fail("the gate never reached the compiler");
    if (!WIFSIGNALED(st) || WTERMSIG(st) != sig)
        return tps_fail("the gate did not re-raise the signal");
    if (tps_scratch_left(fx->base))
        return tps_fail("the scratch directory outlived the signal");
    return kill(cc, 0) == 0 ? tps_fail("the compiler child outlived the gate") : 0;
}

static int tps_cc_parse(void)
{
    char out[64];
    if (!tp_cc_from_line("CC = gcc -O2", out, sizeof out) || strcmp(out, "gcc -O2") != 0)
        return tps_fail("CC = value");
    if (!tp_cc_from_line("CC\t=\t clang", out, sizeof out) || strcmp(out, "clang") != 0)
        return tps_fail("CC with tabs");
    if (!tp_cc_from_line("CC=a=b", out, sizeof out) || strcmp(out, "a") != 0)
        return tps_fail("CC stops at the second equals sign");
    if (tp_cc_from_line("CCASFLAGS = x", out, sizeof out) || tp_cc_from_line(" CC = x", out, sizeof out))
        return tps_fail("only a line that starts with CC and an equals sign matches");
    return 0;
}

static int tps_all(const struct tps_fx *fx)
{
    return tps_normal(fx, 0) || tps_normal(fx, 1)
        || tps_signal(fx, "hold", SIGINT, 1) || tps_signal(fx, "hold", SIGINT, 2)
        || tps_signal(fx, "hold", SIGTERM, 1) || tps_signal(fx, "hold", SIGHUP, 1)
        || tps_signal(fx, "stubborn", SIGTERM, 1);
}

int check_tor_provenance_selftest(void)
{
    struct tps_fx fx = { { 0 }, { 0 }, { 0 } };
    int rc = tps_cc_parse();
    if (rc == 0 && tps_build(&fx) != 0)
        rc = tps_fail("cannot build the fixture root");
    if (rc == 0)
        rc = tps_all(&fx);
    if (fx.base[0] && access(fx.base, F_OK) == 0)
        rap_rm_rf(fx.base);
    if (rc == 0)
        puts("check_tor_provenance selftest: ok (cc parsing, helper hand-off, "
             "signal cleanup)");
    return rc;
}
