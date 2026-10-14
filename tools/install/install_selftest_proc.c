/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * install_selftest - exits, signal handling, scratch-root cleanup and child
 * processes.
 *
 * SIGINT, SIGTERM, SIGHUP and SIGCHLD are blocked except while the harness
 * waits. The handler only records the signal. The wait loop forwards it to
 * the running child, waits up to 5 s, sends SIGKILL, reaps the child, removes
 * the scratch root with signals blocked, restores the default disposition
 * and re-raises the signal. A further signal during the wait is absorbed.
 */
#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "install_selftest.h"

extern char **environ;

constexpr long ISF_KILL_GRACE_MS = 5000;
constexpr long ISF_TICK_MS = 1000;

static volatile sig_atomic_t isf_sig;
static char *isf_root;
static sigset_t isf_orig_mask;
static sigset_t isf_main_mask;
static sigset_t isf_wait_mask;
static const int isf_handled[] = {SIGINT, SIGTERM, SIGHUP};
static bool isf_was_ignored[3];

/* ---- exits and messages ------------------------------------------------- */

void isf_say(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    fputs("install_selftest: ", stderr);
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    va_end(ap);
}

void isf_set_root(const char *path)
{
    isf_root = isf_fmt("%s", path);
}

/* Callers hold the signal block, so this never races the handler. */
void isf_cleanup(void)
{
    if (isf_root != nullptr)
        isf_rm_rf(isf_root);
    isf_root = nullptr;
}

[[noreturn]] void isf_finish(int code)
{
    isf_cleanup();
    isf_heap_release();
    exit(code);
}

void isf_die(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    fputs("install_selftest: FAIL: ", stderr);
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    va_end(ap);
    isf_finish(1);
}

/* ---- signals ------------------------------------------------------------ */

static void isf_on_signal(int sig)
{
    isf_sig = sig;
}

static void isf_on_child(int sig)
{
    (void)sig;
}

void isf_signals_init(void)
{
    struct sigaction act = {.sa_handler = isf_on_signal};
    sigset_t block;

    sigemptyset(&block);
    sigemptyset(&act.sa_mask);
    for (size_t i = 0; i < 3; i++)
        sigaddset(&block, isf_handled[i]);
    sigaddset(&block, SIGCHLD);
    sigprocmask(SIG_BLOCK, &block, &isf_orig_mask);
    sigprocmask(SIG_BLOCK, nullptr, &isf_main_mask);
    isf_wait_mask = isf_orig_mask;
    for (size_t i = 0; i < 3; i++)
        sigdelset(&isf_wait_mask, isf_handled[i]);
    sigdelset(&isf_wait_mask, SIGCHLD);
    for (size_t i = 0; i < 3; i++) {
        struct sigaction old;

        sigaction(isf_handled[i], nullptr, &old);
        isf_was_ignored[i] = old.sa_handler == SIG_IGN;
        if (!isf_was_ignored[i])
            sigaction(isf_handled[i], &act, nullptr);
    }
    act.sa_handler = isf_on_child;
    sigaction(SIGCHLD, &act, nullptr);
}

/* Runs in the forked child before exec: default dispositions for the
 * signals the harness handles (ignored ones stay ignored) and the caller's
 * signal mask. */
static void isf_child_reset(bool all)
{
    struct sigaction dfl = {.sa_handler = SIG_DFL};

    sigemptyset(&dfl.sa_mask);
    for (size_t i = 0; i < 3; i++)
        if (all || !isf_was_ignored[i])
            sigaction(isf_handled[i], &dfl, nullptr);
    sigaction(SIGCHLD, &dfl, nullptr);
    sigprocmask(SIG_SETMASK, &isf_orig_mask, nullptr);
}

[[noreturn]] static void isf_finish_signal(int sig)
{
    struct sigaction dfl = {.sa_handler = SIG_DFL};
    sigset_t one;

    isf_cleanup();
    sigemptyset(&dfl.sa_mask);
    sigaction(sig, &dfl, nullptr);
    sigemptyset(&one);
    sigaddset(&one, sig);
    sigprocmask(SIG_UNBLOCK, &one, nullptr);
    raise(sig);
    _exit(128 + sig);
}

/* Lets a pending signal run the handler, then blocks again. */
void isf_poll(void)
{
    sigprocmask(SIG_SETMASK, &isf_wait_mask, nullptr);
    sigprocmask(SIG_SETMASK, &isf_main_mask, nullptr);
    if (isf_sig != 0)
        isf_finish_signal((int)isf_sig);
}

static void isf_sleep_deliverable(long ms)
{
    struct timespec ts = {.tv_sec = ms / 1000, .tv_nsec = (ms % 1000) * 1000000L};

    pselect(0, nullptr, nullptr, nullptr, &ts, &isf_wait_mask);
}

/* Sleeps up to `ms` with signals deliverable. */
void isf_nap(long ms)
{
    isf_sleep_deliverable(ms);
    if (isf_sig != 0)
        isf_finish_signal((int)isf_sig);
}

long isf_now_ms(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts); // platform-ok: standalone tool, 5 s signal grace deadline
    return (long)ts.tv_sec * 1000L + ts.tv_nsec / 1000000L;
}

/* Waits up to `timeout_ms` for `fd` to become readable. */
bool isf_wait_readable(int fd, long timeout_ms)
{
    long end = isf_now_ms() + timeout_ms;

    for (;;) {
        fd_set rd;
        long left = end - isf_now_ms();
        struct timespec ts = {.tv_sec = left > 0 ? left / 1000 : 0,
                              .tv_nsec = left > 0 ? (left % 1000) * 1000000L : 0};
        int n;

        FD_ZERO(&rd);
        FD_SET(fd, &rd);
        n = pselect(fd + 1, &rd, nullptr, nullptr, &ts, &isf_wait_mask);
        if (isf_sig != 0)
            isf_finish_signal((int)isf_sig);
        if (n > 0)
            return true;
        if (n == 0 || left <= 0)
            return false;
    }
}

/* ---- child processes ---------------------------------------------------- */

static void isf_child_say(const char *path)
{
    static const char head[] = "install_selftest: cannot execute ";
    ssize_t r;

    r = write(2, head, sizeof head - 1);
    r = write(2, path, strlen(path));
    r = write(2, "\n", 1);
    (void)r;
}

static void isf_child_redirect(int target, const char *path)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0666);

    if (fd < 0 || dup2(fd, target) < 0)
        _exit(1);
    close(fd);
}

[[noreturn]] static void isf_child_exec(const struct isf_job *job)
{
    isf_child_reset(job->default_signals);
    if (job->out_path != nullptr)
        isf_child_redirect(1, job->out_path);
    if (job->err_path != nullptr)
        isf_child_redirect(2, job->err_path);
    execve(job->path, job->argv, job->envp != nullptr ? job->envp : environ);
    isf_child_say(job->path);
    _exit(errno == ENOENT ? 127 : 126);
}

/* Signals are blocked here, across fork, so no signal is lost between the
 * fork and the child's reset. */
pid_t isf_spawn(const struct isf_job *job)
{
    pid_t pid = fork();

    if (pid < 0)
        isf_die("cannot fork: %s", strerror(errno));
    if (pid == 0)
        isf_child_exec(job);
    return pid;
}

struct isf_wait {
    pid_t pid;
    bool reaped;
    bool killed;
    long deadline;
    int status;
    int sig;
};

static void isf_wait_signal(struct isf_wait *w)
{
    int sig = (int)isf_sig;

    isf_sig = 0;
    if (w->sig != 0 || w->reaped)
        return;
    w->sig = sig;
    kill(w->pid, sig);
    w->deadline = isf_now_ms() + ISF_KILL_GRACE_MS;
}

static void isf_wait_reap(struct isf_wait *w)
{
    pid_t r = waitpid(w->pid, &w->status, WNOHANG);

    if (r == w->pid)
        w->reaped = true;
    else if (r < 0 && errno != EINTR)
        isf_die("wait failed: %s", strerror(errno));
}

static long isf_wait_timeout(struct isf_wait *w)
{
    long left = ISF_TICK_MS;
    long rest;

    if (w->deadline == 0)
        return left;
    rest = w->deadline - isf_now_ms();
    if (rest <= 0 && !w->killed) {
        kill(w->pid, SIGKILL);
        w->killed = true;
    }
    if (rest <= 0)
        return 1;
    return rest < left ? rest : left;
}

/* Waits for `pid` and returns its wait status. A signal received meanwhile
 * is forwarded to it; once it is reaped the harness cleans up and re-raises
 * that signal instead of returning. */
int isf_wait_status(pid_t pid)
{
    struct isf_wait w = {.pid = pid};

    for (;;) {
        isf_wait_reap(&w);
        if (w.reaped)
            break;
        if (isf_sig != 0)
            isf_wait_signal(&w);
        isf_sleep_deliverable(isf_wait_timeout(&w));
    }
    if (w.sig != 0)
        isf_finish_signal(w.sig);
    isf_poll();
    return w.status;
}

/* The exit status of the child, 128 + signal when it was killed, as a shell
 * reports it. */
int isf_run(const struct isf_job *job)
{
    int status = isf_wait_status(isf_spawn(job));

    if (WIFEXITED(status))
        return WEXITSTATUS(status);
    return WIFSIGNALED(status) ? 128 + WTERMSIG(status) : 1;
}
