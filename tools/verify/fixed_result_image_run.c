/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0.
 * purpose: Process and trace plumbing for the fixed-result image builder:
 *          runs one compiler command with an exact environment and stdio
 *          files, runs it under strace -ff, and parses every per-process
 *          trace into the set of paths the compile found or missed. Any
 *          line it cannot account for refuses instead of being skipped. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "fixed_result_image.h"

#include "base/safe_alloc.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#define FRR_STRACE "/usr/bin/strace"
#define FRR_MAX_ARGS 256u

static int frr_open_out(const char *path)
{
    if (!path) return open("/dev/null", O_WRONLY | O_CLOEXEC);
    return open(path, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC,
                0600);
}

static void frr_child(const struct zcl_fri_run *r)
{
    int in = open("/dev/null", O_RDONLY | O_CLOEXEC);
    int out = frr_open_out(r->out_path);
    int err = frr_open_out(r->err_path);
    if (in < 0 || out < 0 || err < 0 || (r->cwd && chdir(r->cwd) != 0) ||
        dup2(in, STDIN_FILENO) < 0 || dup2(out, STDOUT_FILENO) < 0 ||
        dup2(err, STDERR_FILENO) < 0 || close_range(3, ~0u, 0) != 0)
        _exit(127);
    execve(r->path, r->argv, r->envp);
    _exit(127);
}

bool zcl_fri_run_wait(const struct zcl_fri_run *r, int *exit_code)
{
    *exit_code = -1;
    pid_t pid = fork();
    if (pid < 0) return false;
    if (pid == 0) frr_child(r);
    int status = 0;
    pid_t done;
    do { done = waitpid(pid, &status, 0); } while (done < 0 && errno == EINTR);
    if (done != pid) return false;
    if (WIFEXITED(status)) *exit_code = WEXITSTATUS(status);
    else if (WIFSIGNALED(status)) *exit_code = 128 + WTERMSIG(status);
    return true;
}

static bool frr_executable(const char *path)
{
    struct stat st;
    return path && path[0] && stat(path, &st) == 0 && S_ISREG(st.st_mode) &&
           (st.st_mode & 0111) != 0;
}

/* Distro path first. A PATH entry is used only when that file is absent. */
static bool frr_strace_from_path(char *out, size_t cap)
{
    const char *env = getenv("PATH");
    if (!env || !out || cap < 2) return false;
    char scratch[PATH_MAX];
    size_t i = 0;
    while (env[i]) {
        size_t start = i;
        while (env[i] && env[i] != ':') i++;
        size_t len = i - start;
        if (env[i] == ':') i++;
        if (len == 0 || len + 8 >= sizeof scratch) continue;
        memcpy(scratch, env + start, len);
        memcpy(scratch + len, "/strace", 8);
        if (!frr_executable(scratch)) continue;
        if (strlen(scratch) >= cap) return false;
        memcpy(out, scratch, strlen(scratch) + 1);
        return true;
    }
    return false;
}

static char frr_strace_buf[PATH_MAX];

static const char *frr_strace_path(void)
{
    if (frr_executable(FRR_STRACE)) return FRR_STRACE;
    if (!frr_strace_from_path(frr_strace_buf, sizeof frr_strace_buf))
        return NULL;
    return frr_strace_buf;
}

bool zcl_fri_strace_available(void)
{
    return frr_strace_path() != NULL;
}

bool zcl_fri_trace_run(const struct zcl_fri_run *r, const char *trace_dir,
                       int *exit_code)
{
    const char *strace = frr_strace_path();
    char out[PATH_MAX];
    char *argv[FRR_MAX_ARGS + 16u];
    size_t n = 0;
    if (!strace || snprintf(out, sizeof(out), "%s/t", trace_dir) >= PATH_MAX)
        return false;
    char *head[] = {(char *)strace, "-f", "-ff", "-qq", "-s", "4096", "-e",
                    "trace=%file,%process", "-o", out, "--"};
    for (size_t i = 0; i < sizeof(head) / sizeof(*head); i++) argv[n++] = head[i];
    for (size_t i = 0; r->argv[i]; i++) {
        if (n == FRR_MAX_ARGS + 15u) return false;
        argv[n++] = r->argv[i];
    }
    argv[n] = NULL;
    struct zcl_fri_run traced = *r;
    traced.argv = argv;
    traced.path = strace;
    return zcl_fri_run_wait(&traced, exit_code);
}

/* ── strace line parser ──────────────────────────────────────────────── */

static const char *const k_frr_path_calls[] = {
    "open", "openat", "openat2", "creat", "stat", "lstat", "newfstatat",
    "statx", "access", "faccessat", "faccessat2", "readlink", "readlinkat",
    "execve", "execveat", "chdir", "mkdir", "mkdirat", "unlink", "unlinkat",
    "rmdir", "rename", "renameat", "renameat2", "link", "linkat", "symlink",
    "symlinkat", "chmod", "fchmodat", "chown", "lchown", "fchownat",
    "truncate", "utimensat", "statfs", "mknod", "mknodat", "getxattr",
    "lgetxattr", "listxattr", "llistxattr", "setxattr", "lsetxattr",
    "removexattr", "lremovexattr", "inotify_add_watch", "getcwd"
};
static const char *const k_frr_write_calls[] = {
    "creat", "mkdir", "mkdirat", "unlink", "unlinkat", "rmdir", "rename",
    "renameat", "renameat2", "link", "linkat", "symlink", "symlinkat",
    "chmod", "fchmodat", "chown", "lchown", "fchownat", "truncate",
    "utimensat", "mknod", "mknodat", "setxattr", "lsetxattr", "removexattr",
    "lremovexattr"
};
/* %process calls that carry no path. */
static const char *const k_frr_process_calls[] = {
    "clone", "clone3", "fork", "vfork", "exit", "exit_group", "wait4",
    "waitid", "kill", "tkill", "tgkill", "pidfd_open", "pidfd_send_signal",
    "rt_sigqueueinfo", "rt_tgsigqueueinfo", "pidfd_getfd"
};

/* Bounded copy that truncates on purpose (a diagnostic, a short field). */
static void frr_set(char *dst, size_t cap, const char *src)
{
    size_t n = strnlen(src, cap - 1u);
    memcpy(dst, src, n);
    dst[n] = '\0';
}

static bool frr_in(const char *name, const char *const *set, size_t n)
{
    for (size_t i = 0; i < n; i++) if (strcmp(name, set[i]) == 0) return true;
    return false;
}

static bool frr_fail(struct zcl_fri_trace *t, const char *why, const char *line)
{
    if (!t->why) {
        t->why = why;
        frr_set(t->why_line, sizeof(t->why_line), line);
    }
    return false;
}

struct frr_call {
    char name[32];
    char dirfd[32];
    char path[PATH_MAX];
    bool has_path, write;
};

static bool frr_name(const char *line, struct frr_call *c, const char **rest)
{
    size_t n = strspn(line, "abcdefghijklmnopqrstuvwxyz0123456789_");
    if (n == 0 || n >= sizeof(c->name) || line[n] != '(') return false;
    memcpy(c->name, line, n);
    c->name[n] = '\0';
    *rest = line + n + 1;
    return true;
}

/* The first quoted argument, refusing escapes and strace truncation. */
static bool frr_quoted(const char *args, struct frr_call *c)
{
    const char *q = strchr(args, '"');
    if (!q) return false;
    size_t pre = (size_t)(q - args);
    if (pre >= sizeof(c->dirfd)) pre = sizeof(c->dirfd) - 1u;
    memcpy(c->dirfd, args, pre);
    c->dirfd[pre] = '\0';
    const char *end = strchr(q + 1, '"');
    if (!end) return false;
    size_t len = (size_t)(end - q - 1);
    if (len >= sizeof(c->path) || memchr(q + 1, '\\', len) ||
        strncmp(end + 1, "...", 3) == 0) return false;
    memcpy(c->path, q + 1, len);
    c->path[len] = '\0';
    c->has_path = true;
    return true;
}

static void frr_write_flag(const char *args, struct frr_call *c)
{
    c->write = frr_in(c->name, k_frr_write_calls,
                      sizeof(k_frr_write_calls) / sizeof(*k_frr_write_calls));
    if (strcmp(c->name, "open") == 0 || strcmp(c->name, "openat") == 0 ||
        strcmp(c->name, "openat2") == 0)
        c->write = strstr(args, "O_WRONLY") || strstr(args, "O_RDWR") ||
                   strstr(args, "O_CREAT") || strstr(args, "O_TRUNC");
}

/* -1 when ignorable ("?"), 0 present, 1 absent, 2 unexpected errno. */
static int frr_result(const char *line, const char *name)
{
    const char *eq = strstr(line, ") = ");
    const char *next;
    while (eq && (next = strstr(eq + 1, ") = ")) != NULL) eq = next;
    if (!eq) eq = strstr(line, " = ");
    if (!eq) return 2;
    const char *v = strchr(eq, '=') + 2;
    if (*v == '?') return -1;
    if (strncmp(v, "-1 ", 3) != 0) return (*v >= '0' && *v <= '9') ? 0 : 2;
    v += 3;
    if (strncmp(v, "ENOENT", 6) == 0 || strncmp(v, "ENOTDIR", 7) == 0) return 1;
    if (strncmp(v, "EINVAL", 6) == 0 && strncmp(name, "readlink", 8) == 0)
        return 0;
    return 2;
}

static bool frr_add(struct zcl_fri_trace *t, const char *path, int state,
                    bool write)
{
    for (size_t i = 0; i < t->count; i++)
        if (t->v[i].state == state && t->v[i].write == write &&
            strcmp(t->v[i].path, path) == 0) return true;
    if (t->count == t->cap) {
        size_t next = t->cap ? t->cap * 2u : 256u;
        struct zcl_fri_access *grown =
            zcl_realloc(t->v, next * sizeof(*grown), "frr_accesses");
        if (!grown) return frr_fail(t, ZCL_FRI_WHY_ALLOC, path);
        t->v = grown;
        t->cap = next;
    }
    t->v[t->count].path = zcl_strdup(path, "frr_access_path");
    if (!t->v[t->count].path) return frr_fail(t, ZCL_FRI_WHY_ALLOC, path);
    t->v[t->count].state = state;
    t->v[t->count].write = write;
    t->count++;
    return true;
}

static bool frr_record(struct zcl_fri_trace *t, const struct frr_call *c,
                       const char *line, const char *cwd)
{
    int result = frr_result(line, c->name);
    if (result < 0 || strcmp(c->name, "getcwd") == 0) return true;
    if (result == 2) return frr_fail(t, ZCL_FRI_WHY_TRACE_ERRNO, line);
    if (!c->path[0]) return true; /* AT_EMPTY_PATH: an fd, not a path */
    if (strcmp(c->name, "chdir") == 0) return frr_fail(t, ZCL_FRI_WHY_TRACE, line);
    char path[PATH_MAX];
    if (c->path[0] != '/') {
        if (c->dirfd[0] && strcmp(c->dirfd, "AT_FDCWD, ") != 0)
            return frr_fail(t, ZCL_FRI_WHY_TRACE, line);
        if (snprintf(path, sizeof(path), "%s/%s", cwd, c->path) >= PATH_MAX)
            return frr_fail(t, ZCL_FRI_WHY_LIMIT, line);
    } else {
        snprintf(path, sizeof(path), "%s", c->path);
    }
    return frr_add(t, path, result == 0 ? ZCL_FRI_PRESENT : ZCL_FRI_ABSENT,
                   c->write);
}

static bool frr_resumed(struct zcl_fri_trace *t, const char *line,
                        const char *cwd, char pending[512])
{
    struct frr_call c = {0};
    const char *name = line + 5;
    const char *end = strstr(name, " resumed>");
    if (!end) return frr_fail(t, ZCL_FRI_WHY_TRACE, line);
    size_t n = (size_t)(end - name);
    if (n >= sizeof(c.name)) return frr_fail(t, ZCL_FRI_WHY_TRACE, line);
    memcpy(c.name, name, n);
    if (!pending[0] || strcmp(pending, c.name) != 0) {
        pending[0] = '\0';
        return frr_in(c.name, k_frr_process_calls,
                      sizeof(k_frr_process_calls) / sizeof(*k_frr_process_calls))
            || frr_fail(t, ZCL_FRI_WHY_TRACE, line);
    }
    /* pending: name NUL dirfd NUL write NUL path */
    const char *dirfd = pending + strlen(pending) + 1;
    const char *write = dirfd + strlen(dirfd) + 1;
    frr_set(c.dirfd, sizeof(c.dirfd), dirfd);
    c.write = write[0] == '1';
    frr_set(c.path, sizeof(c.path), write + 2);
    c.has_path = true;
    pending[0] = '\0';
    return frr_record(t, &c, line, cwd);
}

static bool frr_pend(const struct frr_call *c, char pending[512])
{
    int n = snprintf(pending, 512, "%s%c%s%c%c%c%s", c->name, 0, c->dirfd, 0,
                     c->write ? '1' : '0', 0, c->path);
    return n > 0 && n < 512;
}

bool zcl_fri_trace_parse_line(struct zcl_fri_trace *t, const char *line,
                              const char *cwd, char pending[512])
{
    if (!line[0] || strncmp(line, "+++", 3) == 0 || strncmp(line, "---", 3) == 0)
        return true;
    if (strncmp(line, "<... ", 5) == 0) return frr_resumed(t, line, cwd, pending);
    struct frr_call c = {0};
    const char *args = NULL;
    if (!frr_name(line, &c, &args)) return frr_fail(t, ZCL_FRI_WHY_TRACE, line);
    if (frr_in(c.name, k_frr_process_calls,
               sizeof(k_frr_process_calls) / sizeof(*k_frr_process_calls)))
        return true;
    if (!frr_in(c.name, k_frr_path_calls,
                sizeof(k_frr_path_calls) / sizeof(*k_frr_path_calls)) ||
        !frr_quoted(args, &c))
        return frr_fail(t, ZCL_FRI_WHY_TRACE, line);
    frr_write_flag(args, &c);
    if (strstr(line, "<unfinished ...>"))
        return frr_pend(&c, pending) || frr_fail(t, ZCL_FRI_WHY_LIMIT, line);
    return frr_record(t, &c, line, cwd);
}

static bool frr_parse_file(struct zcl_fri_trace *t, const char *path,
                           const char *cwd)
{
    FILE *f = fopen(path, "re");
    if (!f) return frr_fail(t, ZCL_FRI_WHY_TRACE, path);
    char *line = NULL, pending[512] = {0};
    size_t cap = 0;
    ssize_t n;
    bool ok = true;
    while (ok && (n = getline(&line, &cap, f)) > 0) {
        if (line[n - 1] != '\n') { ok = frr_fail(t, ZCL_FRI_WHY_TRACE, line); break; }
        line[n - 1] = '\0';
        ok = zcl_fri_trace_parse_line(t, line, cwd, pending);
    }
    if (ok && (ferror(f) || pending[0])) ok = frr_fail(t, ZCL_FRI_WHY_TRACE, path);
    free(line);
    if (fclose(f) != 0) ok = false;
    return ok;
}

bool zcl_fri_trace_parse_dir(struct zcl_fri_trace *t, const char *dir,
                             const char *cwd)
{
    DIR *d = opendir(dir);
    if (!d) return frr_fail(t, ZCL_FRI_WHY_TRACE, dir);
    struct dirent *ent;
    unsigned files = 0;
    bool ok = true;
    while (ok && (ent = readdir(d)) != NULL) {
        if (strncmp(ent->d_name, "t.", 2) != 0) continue;
        char path[PATH_MAX];
        if (snprintf(path, sizeof(path), "%s/%s", dir, ent->d_name) >= PATH_MAX)
            ok = frr_fail(t, ZCL_FRI_WHY_LIMIT, ent->d_name);
        else ok = frr_parse_file(t, path, cwd);
        files++;
    }
    closedir(d);
    return ok && (files > 0 || frr_fail(t, ZCL_FRI_WHY_TRACE, dir));
}

void zcl_fri_trace_free(struct zcl_fri_trace *t)
{
    for (size_t i = 0; i < t->count; i++) free(t->v[i].path);
    free(t->v);
    memset(t, 0, sizeof(*t));
}
