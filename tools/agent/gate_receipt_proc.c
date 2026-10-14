/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * gate_receipt - exits, signal handling, temporary-file cleanup and child
 * processes.
 *
 * SIGINT, SIGTERM and SIGHUP are blocked except while the wrapper waits. The
 * handler only records the signal. The wait loop forwards it to the running
 * child, waits up to 5 s, sends SIGKILL, reaps the child, removes the
 * wrapper's temporary files with signals blocked, restores the default
 * disposition and re-raises the signal.
 */
#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200809L

#include "gate_receipt.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

constexpr size_t GTR_CHUNK = 65536;
constexpr long GTR_KILL_GRACE_MS = 5000;
constexpr long GTR_TICK_MS = 1000;

/* ---- exits -------------------------------------------------------------- */

void gtr_cleanup(void);

[[noreturn]] static void gtr_vexit(int code, const char *fmt, va_list ap)
{
    fputs("gate-receipt: ", stderr);
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    gtr_cleanup();
    exit(code);
}

void gtr_die(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    gtr_vexit(GTR_EXIT_USAGE, fmt, ap);
}

/* A directory that cannot be made or entered exits 1, as the shell did. */
void gtr_fail(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    gtr_vexit(1, fmt, ap);
}

/* ---- signals and temporary files ---------------------------------------- */

static volatile sig_atomic_t gtr_sig;
static int gtr_fatal;
static sigset_t gtr_orig_mask;
static sigset_t gtr_main_mask;
static sigset_t gtr_wait_mask;
static const int gtr_handled[] = {SIGINT, SIGTERM, SIGHUP};
static bool gtr_was_ignored[3];
static struct sigaction gtr_old_pipe;

static char *gtr_tmp_files[2];
static char *gtr_tmp_dir;

static void gtr_on_signal(int sig)
{
    gtr_sig = sig;
}

static void gtr_on_child(int sig)
{
    (void)sig;
}

void gtr_track_file(size_t slot, const char *path)
{
    gtr_tmp_files[slot] = gtr_fmt("%s", path);
}

void gtr_untrack_file(size_t slot)
{
    free(gtr_tmp_files[slot]);
    gtr_tmp_files[slot] = nullptr;
}

void gtr_track_dir(const char *path)
{
    gtr_tmp_dir = gtr_fmt("%s", path);
}

/* Callers hold the signal block, so this never races the handler. */
void gtr_cleanup(void)
{
    for (size_t i = 0; i < sizeof gtr_tmp_files / sizeof gtr_tmp_files[0]; i++) {
        if (gtr_tmp_files[i] != nullptr)
            unlink(gtr_tmp_files[i]);
        gtr_tmp_files[i] = nullptr;
    }
    if (gtr_tmp_dir != nullptr)
        rmdir(gtr_tmp_dir);
    gtr_tmp_dir = nullptr;
}

void gtr_signals_init(void)
{
    struct sigaction act = {.sa_handler = gtr_on_signal};
    struct sigaction ign = {.sa_handler = SIG_IGN};
    sigset_t block;

    sigemptyset(&block);
    sigemptyset(&act.sa_mask);
    sigemptyset(&ign.sa_mask);
    for (size_t i = 0; i < 3; i++)
        sigaddset(&block, gtr_handled[i]);
    sigaddset(&block, SIGCHLD);
    sigprocmask(SIG_BLOCK, &block, &gtr_orig_mask);
    sigprocmask(SIG_BLOCK, nullptr, &gtr_main_mask);
    gtr_wait_mask = gtr_orig_mask;
    for (int s = 1; s < NSIG; s++)
        if (sigismember(&block, s))
            sigdelset(&gtr_wait_mask, s);
    for (size_t i = 0; i < 3; i++) {
        struct sigaction old;

        sigaction(gtr_handled[i], nullptr, &old);
        gtr_was_ignored[i] = old.sa_handler == SIG_IGN;
        if (!gtr_was_ignored[i])
            sigaction(gtr_handled[i], &act, nullptr);
    }
    act.sa_handler = gtr_on_child;
    sigaction(SIGCHLD, &act, nullptr);
    sigaction(SIGPIPE, &ign, &gtr_old_pipe);
}

/* Runs in the forked child before exec: default dispositions for the
 * signals the wrapper handles (ignored ones stay ignored), the caller's
 * SIGPIPE disposition, and the caller's signal mask. */
static void gtr_child_reset(void)
{
    struct sigaction dfl = {.sa_handler = SIG_DFL};

    sigemptyset(&dfl.sa_mask);
    for (size_t i = 0; i < 3; i++)
        if (!gtr_was_ignored[i])
            sigaction(gtr_handled[i], &dfl, nullptr);
    sigaction(SIGCHLD, &dfl, nullptr);
    sigaction(SIGPIPE, &gtr_old_pipe, nullptr);
    sigprocmask(SIG_SETMASK, &gtr_orig_mask, nullptr);
}

[[noreturn]] static void gtr_finish_signal(int sig)
{
    struct sigaction dfl = {.sa_handler = SIG_DFL};
    sigset_t one;

    gtr_cleanup();
    sigemptyset(&dfl.sa_mask);
    sigaction(sig, &dfl, nullptr);
    sigemptyset(&one);
    sigaddset(&one, sig);
    sigprocmask(SIG_UNBLOCK, &one, nullptr);
    raise(sig);
    _exit(128 + sig);
}

/* Lets a pending signal run the handler, then blocks again. */
void gtr_poll(void)
{
    sigprocmask(SIG_SETMASK, &gtr_wait_mask, nullptr);
    sigprocmask(SIG_SETMASK, &gtr_main_mask, nullptr);
    if (gtr_sig != 0)
        gtr_finish_signal((int)gtr_sig);
}

/* Sleeps up to `ms` with signals deliverable. */
void gtr_nap(long ms)
{
    struct timespec ts = {.tv_sec = ms / 1000, .tv_nsec = (ms % 1000) * 1000000L};

    pselect(0, nullptr, nullptr, nullptr, &ts, &gtr_wait_mask);
    if (gtr_sig != 0)
        gtr_finish_signal((int)gtr_sig);
}

/* ---- child processes ---------------------------------------------------- */

static int gtr_exit_code(int status)
{
    if (WIFEXITED(status))
        return WEXITSTATUS(status);
    return WIFSIGNALED(status) ? 128 + WTERMSIG(status) : 1;
}

static void gtr_child_say(const char *name, const char *what)
{
    static const char head[] = "gate-receipt: ";
    ssize_t r;

    r = write(2, head, sizeof head - 1);
    r = write(2, name, strlen(name));
    r = write(2, ": ", 2);
    r = write(2, what, strlen(what));
    r = write(2, "\n", 1);
    (void)r;
}

[[noreturn]] static void gtr_child_exec(const struct gtr_job *job, const int pf[2])
{
    gtr_child_reset();
    if (job->in_fd >= 0)
        dup2(job->in_fd, 0);
    if (job->capture) {
        dup2(pf[1], 1);
        if (job->err == GTR_ERR_MERGE)
            dup2(pf[1], 2);
    } else if (job->out_to_err) {
        dup2(2, 1);
    }
    if (job->err == GTR_ERR_NULL) {
        int nul = open("/dev/null", O_WRONLY);

        if (nul >= 0)
            dup2(nul, 2);
    }
    execvp(job->argv[0], job->argv);
    if (errno == ENOENT)
        gtr_child_say(job->argv[0], "command not found");
    else
        gtr_child_say(job->argv[0], strerror(errno));
    _exit(errno == ENOENT ? 127 : 126);
}

static pid_t gtr_fork(const struct gtr_job *job, int pf[2])
{
    pid_t pid;

    pf[0] = pf[1] = -1;
    if (job->capture) {
        if (pipe(pf) != 0)
            gtr_die("cannot create pipe: %s", strerror(errno));
        fcntl(pf[0], F_SETFD, FD_CLOEXEC);
        fcntl(pf[1], F_SETFD, FD_CLOEXEC);
    }
    pid = fork();
    if (pid < 0)
        gtr_die("cannot fork: %s", strerror(errno));
    if (pid == 0)
        gtr_child_exec(job, pf);
    if (pf[1] >= 0) {
        close(pf[1]);
        pf[1] = -1;
    }
    return pid;
}

static long gtr_now_ms(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts); // platform-ok: standalone tool, 5 s signal grace deadline
    return (long)ts.tv_sec * 1000L + ts.tv_nsec / 1000000L;
}

/* One signal recorded by the handler is forwarded to the child; the child
 * then has GTR_KILL_GRACE_MS to exit before SIGKILL. */
struct gtr_wait {
    pid_t pid;
    bool reaped;
    bool killed;
    long deadline;
    int status;
};

static void gtr_wait_signal(struct gtr_wait *w)
{
    int sig = (int)gtr_sig;

    gtr_sig = 0;
    gtr_fatal = sig;
    if (w->reaped)
        return;
    kill(w->pid, sig);
    if (w->deadline == 0)
        w->deadline = gtr_now_ms() + GTR_KILL_GRACE_MS;
}

static void gtr_wait_reap(struct gtr_wait *w)
{
    pid_t r;

    if (w->reaped)
        return;
    r = waitpid(w->pid, &w->status, WNOHANG);
    if (r == w->pid)
        w->reaped = true;
    else if (r < 0 && errno != EINTR)
        gtr_die("wait failed: %s", strerror(errno));
}

static long gtr_wait_timeout(struct gtr_wait *w)
{
    long left = GTR_TICK_MS;

    if (w->deadline != 0 && !w->reaped) {
        long rest = w->deadline - gtr_now_ms();

        if (rest <= 0 && !w->killed) {
            kill(w->pid, SIGKILL);
            w->killed = true;
        }
        if (rest < left)
            left = rest > 0 ? rest : 1;
    }
    return left;
}

/* Returns false at end of input. */
static bool gtr_pump_read(int rfd, const struct gtr_job *job)
{
    static char buf[GTR_CHUNK];
    ssize_t n = read(rfd, buf, sizeof buf);

    if (n < 0 && (errno == EINTR || errno == EAGAIN))
        return true;
    if (n < 0)
        gtr_die("read failed: %s", strerror(errno));
    if (n == 0)
        return false;
    job->sink(job->ctx, buf, (size_t)n);
    return true;
}

static bool gtr_pump_wait(int rfd, long ms)
{
    fd_set rs;
    struct timespec ts = {.tv_sec = ms / 1000, .tv_nsec = (ms % 1000) * 1000000L};
    int n;

    FD_ZERO(&rs);
    if (rfd >= 0)
        FD_SET(rfd, &rs);
    n = pselect(rfd >= 0 ? rfd + 1 : 0, rfd >= 0 ? &rs : nullptr, nullptr, nullptr, &ts,
                &gtr_wait_mask);
    return n > 0 && rfd >= 0 && FD_ISSET(rfd, &rs);
}

static int gtr_pump(pid_t pid, int rfd, const struct gtr_job *job)
{
    struct gtr_wait w = {.pid = pid};

    for (;;) {
        if (gtr_sig != 0)
            gtr_wait_signal(&w);
        gtr_wait_reap(&w);
        if (w.reaped && (rfd < 0 || gtr_fatal != 0))
            break;
        if (gtr_pump_wait(rfd, gtr_wait_timeout(&w)) && !gtr_pump_read(rfd, job)) {
            close(rfd);
            rfd = -1;
        }
    }
    if (rfd >= 0)
        close(rfd);
    return w.status;
}

/* Runs a child to completion and returns its exit code. Does not return when
 * a signal arrived: the child is stopped and the wrapper re-raises it. */
int gtr_run(const struct gtr_job *job)
{
    int pf[2];
    pid_t pid = gtr_fork(job, pf);
    int status = gtr_pump(pid, pf[0], job);

    if (gtr_fatal != 0)
        gtr_finish_signal(gtr_fatal);
    gtr_poll();
    return gtr_exit_code(status);
}

int gtr_write_all(int fd, const char *p, size_t n)
{
    while (n > 0) {
        ssize_t w = write(fd, p, n);

        if (w < 0 && errno == EINTR)
            continue;
        if (w < 0)
            return -1;
        p += w;
        n -= (size_t)w;
    }
    return 0;
}

/* Forwards output without ever blocking inside a write the signal could not
 * interrupt: waits for writability with signals deliverable, writes at most
 * PIPE_BUF bytes. Returns -1 once the consumer is gone. */
int gtr_mirror(int fd, const char *p, size_t n)
{
    while (n > 0 && gtr_sig == 0 && gtr_fatal == 0) {
        fd_set ws;
        struct timespec tick = {.tv_sec = 1};
        size_t part = n < PIPE_BUF ? n : PIPE_BUF;
        ssize_t w;
        int ready;

        FD_ZERO(&ws);
        FD_SET(fd, &ws);
        ready = pselect(fd + 1, nullptr, &ws, nullptr, &tick, &gtr_wait_mask);
        if (ready < 0 && errno != EINTR)
            return -1;
        if (ready <= 0)
            continue;
        w = write(fd, p, part);
        if (w < 0 && (errno == EINTR || errno == EAGAIN))
            continue;
        if (w < 0)
            return -1;
        p += w;
        n -= (size_t)w;
    }
    return 0;
}
