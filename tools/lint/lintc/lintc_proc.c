/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: implementation of lintc_proc.h. The wait loop keeps the gate's
 * termination signals blocked and lets pselect() unblock them atomically, so
 * a pending signal is always seen before the loop sleeps and every sleep is
 * bounded.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include "lintc_proc.h"
#include "lintc_sig.h"

enum { LCP_POLL_MIN_US = 1000, LCP_POLL_MAX_US = 20000 };

struct lcp_io {
    int fd;
    struct lcp_buf *out;
    size_t used;
    size_t cap;
};

static int lcp_code(int st)
{
    return WIFEXITED(st) ? WEXITSTATUS(st) : 128 + (WIFSIGNALED(st) ? WTERMSIG(st) : 0);
}

static void lcp_redirect(enum lcp_mode mode, int wfd)
{
    int null = open("/dev/null", O_WRONLY);
    int out = (mode == LCP_OUT || mode == LCP_BOTH || mode == LCP_OUT_ERRPASS) ? wfd
              : (mode == LCP_PASS ? 1 : null);
    int err = (mode == LCP_BOTH || mode == LCP_ERR) ? wfd
              : (mode == LCP_PASS || mode == LCP_OUT_ERRPASS ? 2 : null);
    if (null < 0 || dup2(out, 1) < 0 || dup2(err, 2) < 0)
        _exit(127);
}

static void lcp_child(const struct lcp_spec *s, int wfd)
{
    static const char msg[] = "z23-lint: cannot execute a child process\n";
    setpgid(0, 0);
    lsc_reset_in_child();
    for (const char *const *e = s->unsetenv; e && *e; e++)
        unsetenv(*e);
    for (const char *const *e = s->setenv; e && *e; e++) {
        const char *eq = strchr(*e, '=');
        char *name = eq ? strndup(*e, (size_t)(eq - *e)) : NULL;
        if (!name || setenv(name, eq + 1, 1) != 0)
            _exit(127);
        free(name);
    }
    if (s->stdin_path) {
        int in = open(s->stdin_path, O_RDONLY);
        if (in < 0 || dup2(in, 0) < 0)
            _exit(127);
    }
    lcp_redirect(s->mode, wfd);
    execvp(s->argv[0], s->argv);
    (void)!write(2, msg, sizeof msg - 1);
    _exit(127);
}

/* Appends n bytes; what does not fit under LCP_CAP or in memory is dropped
 * and recorded in b->lost. */
static void lcp_append(struct lcp_io *io, const char *buf, size_t n)
{
    struct lcp_buf *b = io->out;
    if (!b || b->lost == LCP_LOST_NOMEM)
        return;
    if (io->used + n > LCP_CAP) {
        n = LCP_CAP - io->used;
        b->lost = LCP_LOST_TRUNCATED;
    }
    if (io->used + n + 1 > io->cap) {
        size_t want = io->used + n + 1, cap = io->cap * 2 > want ? io->cap * 2 : want;
        char *p = realloc(b->data, cap < 4096 ? 4096 : cap); // raw-alloc-ok:lint-runtime
        if (!p) {
            b->lost = LCP_LOST_NOMEM;
            return;
        }
        b->data = p;
        io->cap = cap < 4096 ? 4096 : cap;
    }
    memcpy(b->data + io->used, buf, n);
    io->used += n;
    b->len = io->used;
    b->data[io->used] = '\0';
}

/* Reads until the pipe would block; closes it at end of file. Bytes that
 * cannot be kept are still read so the child never sees a broken pipe. */
static void lcp_drain(struct lcp_io *io)
{
    char buf[8192];
    while (io->fd >= 0) {
        ssize_t n = read(io->fd, buf, sizeof buf);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0) {
            if (n == 0 || errno != EAGAIN) {
                close(io->fd);
                io->fd = -1;
            }
            return;
        }
        lcp_append(io, buf, (size_t)n);
    }
}

static void lcp_nap_us(long us)
{
    struct timespec ts = { 0, us * 1000L };
    nanosleep(&ts, NULL);
}

/* Signals the group, waits up to grace_ms for the leader, then kills the
 * whole group, which also takes members that ignored the signal, and reaps
 * the leader. */
static void lcp_stop(pid_t pid, int sig, int grace_ms)
{
    int st, reaped = 0;
    kill(-pid, sig);
    for (int waited = 0; waited < grace_ms && !reaped; waited += 10) {
        reaped = waitpid(pid, &st, WNOHANG) == pid;
        if (!reaped)
            lcp_nap_us(10000);
    }
    kill(-pid, SIGKILL);
    while (!reaped && waitpid(pid, &st, 0) < 0 && errno == EINTR)
        ;
}

static void lcp_sleep_unblocked(struct lcp_io *io, long us)
{
    struct timespec ts = { 0, us * 1000L };
    fd_set rd;
    sigset_t none;
    sigemptyset(&none);
    FD_ZERO(&rd);
    if (io->fd >= 0)
        FD_SET(io->fd, &rd);
    if (pselect(io->fd >= 0 ? io->fd + 1 : 0, io->fd >= 0 ? &rd : NULL, NULL, NULL, &ts, &none) > 0)
        lcp_drain(io);
}

static int lcp_wait(pid_t pid, struct lcp_io *io, int grace_ms, int *code)
{
    long us = LCP_POLL_MIN_US;
    for (;;) {
        int st;
        pid_t r = waitpid(pid, &st, WNOHANG);
        if (r == pid) {
            lcp_drain(io);
            *code = lcp_code(st);
            return 0;
        }
        if (r < 0 && errno != EINTR)
            return -1;
        if (lsc_pending()) {
            lcp_stop(pid, lsc_pending(), grace_ms);
            return 1;
        }
        lcp_sleep_unblocked(io, us);
        us = us * 2 > LCP_POLL_MAX_US ? LCP_POLL_MAX_US : us * 2;
    }
}

int lcp_run(const struct lcp_spec *s, struct lcp_buf *out, int *code)
{
    int fds[2] = { -1, -1 }, rc;
    struct lcp_io io = { -1, out, 0, 0 };
    if (out) {
        out->data = NULL;
        out->len = 0;
        out->lost = LCP_LOST_NONE;
    }
    if (pipe(fds) != 0)
        return -1;
    fcntl(fds[0], F_SETFD, FD_CLOEXEC);
    fcntl(fds[1], F_SETFD, FD_CLOEXEC);
    fcntl(fds[0], F_SETFL, O_NONBLOCK);
    pid_t pid = fork();
    if (pid == 0)
        lcp_child(s, fds[1]);
    close(fds[1]);
    if (pid < 0) {
        close(fds[0]);
        return -1;
    }
    setpgid(pid, pid);
    io.fd = fds[0];
    rc = lcp_wait(pid, &io, s->grace_ms, code);
    if (io.fd >= 0)
        close(io.fd);
    return rc;
}

void lcp_buf_free(struct lcp_buf *b)
{
    free(b->data);
    b->data = NULL;
    b->len = 0;
}

void lcp_buf_subst(struct lcp_buf *b)
{
    size_t w = 0;
    for (size_t r = 0; r < b->len; r++) {
        if (b->data[r] != '\0')
            b->data[w++] = b->data[r];
    }
    while (w && b->data[w - 1] == '\n')
        w--;
    if (b->data)
        b->data[w] = '\0';
    b->len = w;
}
