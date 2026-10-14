/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: process and signal support for check-fleet-observations: a growable
 * buffer, whole-file reads, and a child runner that stops and reaps its child
 * when INT, TERM or HUP arrives. The signals stay blocked except inside the
 * runner's pselect waits, so a signal that arrives earlier is held and then
 * delivered there, never lost between a check and a blocking call.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include "gate_fleet_observations_priv.h"

extern char **environ;

static volatile sig_atomic_t fo_seen_signal;
static sigset_t fo_wait_mask;

static const int k_fo_signals[3] = { SIGINT, SIGTERM, SIGHUP };

void fo_buf_put(struct fo_buf *b, const char *s, size_t n)
{
    if (b->err)
        return;
    if (b->n + n + 1 > b->cap) {
        size_t nc = b->cap ? b->cap : 256;
        while (nc < b->n + n + 1)
            nc *= 2;
        char *np = realloc(b->p, nc); // raw-alloc-ok:lint-runtime
        if (!np) {
            b->err = 1;
            return;
        }
        b->p = np;
        b->cap = nc;
    }
    if (n)
        memcpy(b->p + b->n, s, n);
    b->n += n;
    b->p[b->n] = '\0';
}

void fo_buf_puts(struct fo_buf *b, const char *s)
{
    fo_buf_put(b, s, strlen(s));
}

void fo_buf_free(struct fo_buf *b)
{
    free(b->p);
    memset(b, 0, sizeof *b);
}

int fo_slurp(const char *path, struct fo_buf *out)
{
    FILE *fp = fopen(path, "rb");
    if (!fp)
        return -1;
    char chunk[16384];
    size_t got;
    while ((got = fread(chunk, 1, sizeof chunk, fp)) > 0)
        fo_buf_put(out, chunk, got);
    int bad = ferror(fp) || out->err;
    fclose(fp);
    return bad ? -1 : 0;
}

static void fo_on_signal(int sig)
{
    fo_seen_signal = sig;
}

int fo_stopped(void)
{
    return fo_seen_signal != 0;
}

void fo_sigs_arm(struct fo_sigs *s)
{
    sigset_t block;
    sigemptyset(&block);
    for (int i = 0; i < 3; i++)
        sigaddset(&block, k_fo_signals[i]);
    sigprocmask(SIG_BLOCK, &block, &s->old);
    fo_wait_mask = s->old;
    for (int i = 0; i < 3; i++)
        sigdelset(&fo_wait_mask, k_fo_signals[i]);
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = fo_on_signal;
    sigemptyset(&sa.sa_mask);
    for (int i = 0; i < 3; i++)
        sigaction(k_fo_signals[i], &sa, &s->prev[i]);
}

/* Restores the dispositions and the mask; a recorded signal is raised with
 * the default action so the caller dies by it after its cleanup. */
int fo_finish(struct fo_sigs *s, int rc)
{
    int sig = fo_seen_signal;
    if (sig) {
        struct sigaction dfl;
        memset(&dfl, 0, sizeof dfl);
        dfl.sa_handler = SIG_DFL;
        sigemptyset(&dfl.sa_mask);
        sigaction(sig, &dfl, NULL);
        sigprocmask(SIG_SETMASK, &s->old, NULL);
        raise(sig);
        return 128 + sig;
    }
    for (int i = 0; i < 3; i++)
        sigaction(k_fo_signals[i], &s->prev[i], NULL);
    sigprocmask(SIG_SETMASK, &s->old, NULL);
    return rc;
}

static void fo_nap(long ms)
{
    struct timespec ts = { .tv_sec = ms / 1000, .tv_nsec = (ms % 1000) * 1000000L };
    (void)pselect(0, NULL, NULL, NULL, &ts, &fo_wait_mask);
}

static void fo_pump(int fd, struct fo_buf *out)
{
    char chunk[8192];
    while (!fo_stopped()) {
        fd_set rd;
        FD_ZERO(&rd);
        FD_SET(fd, &rd);
        if (pselect(fd + 1, &rd, NULL, NULL, NULL, &fo_wait_mask) < 0) {
            if (errno == EINTR)
                continue;
            return;
        }
        ssize_t n = read(fd, chunk, sizeof chunk);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            return;
        if (out)
            fo_buf_put(out, chunk, (size_t)n);
    }
}

static int fo_decode(int status)
{
    if (WIFEXITED(status))
        return WEXITSTATUS(status);
    return WIFSIGNALED(status) ? 128 + WTERMSIG(status) : 127;
}

/* Waits for pid. A recorded signal is forwarded once; a child still alive
 * five seconds later is killed. */
static int fo_reap(pid_t pid)
{
    int status = 0, forwarded = 0, killed = 0;
    long waited = 0;
    for (;;) {
        pid_t r = waitpid(pid, &status, WNOHANG);
        if (r == pid)
            break;
        if (r < 0 && errno != EINTR)
            return 127;
        if (fo_stopped() && !forwarded) {
            kill(pid, fo_seen_signal);
            forwarded = 1;
        }
        if (forwarded && !killed && waited >= 5000) {
            kill(pid, SIGKILL);
            killed = 1;
        }
        fo_nap(5);
        if (forwarded)
            waited += 5;
    }
    return fo_stopped() ? FO_INTERRUPTED : fo_decode(status);
}

static int fo_spawn(const char *bin, char *const argv[], int wfd, pid_t *pid)
{
    posix_spawn_file_actions_t fa;
    posix_spawnattr_t at;
    sigset_t none, dfl;
    sigemptyset(&none);
    sigemptyset(&dfl);
    for (int i = 0; i < 3; i++)
        sigaddset(&dfl, k_fo_signals[i]);
    posix_spawn_file_actions_init(&fa);
    posix_spawn_file_actions_adddup2(&fa, wfd, STDOUT_FILENO);
    posix_spawn_file_actions_adddup2(&fa, wfd, STDERR_FILENO);
    posix_spawnattr_init(&at);
    posix_spawnattr_setsigmask(&at, &none);
    posix_spawnattr_setsigdefault(&at, &dfl);
    posix_spawnattr_setflags(&at, POSIX_SPAWN_SETSIGMASK | POSIX_SPAWN_SETSIGDEF);
    int rc = posix_spawnp(pid, bin, &fa, &at, argv, environ);
    posix_spawn_file_actions_destroy(&fa);
    posix_spawnattr_destroy(&at);
    return rc;
}

int fo_run(const char *bin, char *const argv[], struct fo_buf *out)
{
    int pfd[2];
    pid_t pid;
    fo_nap(0);
    if (fo_stopped())
        return FO_INTERRUPTED;
    if (pipe(pfd) != 0)
        return FO_SPAWN_FAILED;
    (void)fcntl(pfd[0], F_SETFD, FD_CLOEXEC);
    (void)fcntl(pfd[1], F_SETFD, FD_CLOEXEC);
    int sr = fo_spawn(bin, argv, pfd[1], &pid);
    close(pfd[1]);
    if (sr != 0) {
        close(pfd[0]);
        return FO_SPAWN_FAILED;
    }
    fo_pump(pfd[0], out);
    close(pfd[0]);
    return fo_reap(pid);
}
