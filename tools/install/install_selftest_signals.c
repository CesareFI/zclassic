/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * install_selftest - signal qualification.
 *
 * `--selftest` runs this harness against itself. Each case starts the
 * harness in hold mode: it creates its scratch root, starts a child that
 * announces readiness over a pipe, and waits. The case signals the harness
 * only after that announcement, then requires that the harness died of the
 * first signal, left no scratch behind and reaped its child.
 */
#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "install_selftest.h"

constexpr char ISF_HOLD_ENV[] = "Z23_INSTALL_SELFTEST_HOLD";
constexpr char ISF_READY_ENV[] = "Z23_INSTALL_SELFTEST_READY_FD";
constexpr long ISF_READY_MS = 15000;
constexpr long ISF_POLITE_LIMIT_MS = 4000;
constexpr long ISF_SECOND_SIGNAL_MS = 300;

struct isf_sigcase {
    const char *name;
    const char *mode;
    int sig;
    int count;
};

bool isf_hold_requested(void)
{
    return getenv(ISF_HOLD_ENV) != nullptr;
}

/* ---- the harness under test --------------------------------------------- */

/* The held child: says it is running, then waits to be signalled. A
 * "stubborn" child ignores the signals the harness forwards, so only
 * SIGKILL ends it. */
void isf_hold_child(const char *mode)
{
    const char *fd_text = getenv(ISF_READY_ENV);
    char line[32];
    int n = snprintf(line, sizeof line, "%ld\n", (long)getpid());
    ssize_t w;

    if (strcmp(mode, "stubborn") == 0) {
        signal(SIGINT, SIG_IGN);
        signal(SIGTERM, SIG_IGN);
        signal(SIGHUP, SIG_IGN);
    }
    if (fd_text == nullptr)
        _exit(2);
    do
        w = write(atoi(fd_text), line, (size_t)n);
    while (w < 0 && errno == EINTR);
    for (;;)
        pause();
}

int isf_hold_main(const char *self)
{
    char *argv[] = {(char *)self, (char *)"--hold-child", (char *)getenv(ISF_HOLD_ENV), nullptr};
    struct isf_job job = {.path = self, .argv = argv};
    int status = isf_wait_status(isf_spawn(&job));

    return WIFEXITED(status) ? WEXITSTATUS(status) : 1;
}

/* ---- the cases ---------------------------------------------------------- */

static pid_t isf_start_held(const char *self, const char *scratch, const struct isf_sigcase *c,
                            int ready[2])
{
    char *argv[] = {(char *)self, nullptr};
    struct isf_env env = {};
    struct isf_job job = {.path = self, .argv = argv, .default_signals = true};

    if (pipe(ready) != 0)
        isf_die("%s: cannot create pipe: %s", c->name, strerror(errno));
    isf_env_from_environ(&env);
    isf_env_set(&env, "TMPDIR", scratch);
    isf_env_set(&env, ISF_HOLD_ENV, c->mode);
    isf_env_set(&env, ISF_READY_ENV, isf_fmt("%d", ready[1]));
    job.envp = env.kv;
    pid_t pid = isf_spawn(&job);
    close(ready[1]);
    return pid;
}

/* Ends a failed case: the harness and its held child are killed and reaped
 * first, so a failure leaves no process behind. */
[[noreturn]] static void isf_fail_case(pid_t pid, bool reaped, pid_t held, const struct isf_sigcase *c,
                                       const char *what)
{
    if (!reaped) {
        kill(pid, SIGKILL);
        waitpid(pid, nullptr, 0);
    }
    if (held > 0)
        kill(held, SIGKILL);
    isf_die("%s: %s", c->name, what);
}

/* Blocks until the held child announces itself; returns its pid. */
static pid_t isf_await_ready(pid_t pid, const struct isf_sigcase *c, int fd)
{
    char line[32] = {0};
    ssize_t n;

    if (!isf_wait_readable(fd, ISF_READY_MS))
        isf_fail_case(pid, false, 0, c, "the held child never announced readiness");
    n = read(fd, line, sizeof line - 1);
    if (n <= 0)
        isf_fail_case(pid, false, 0, c, "the harness ended before its child was ready");
    return (pid_t)strtol(line, nullptr, 10);
}

static const char *isf_outcome_error(const struct isf_sigcase *c, int status, pid_t held, const char *scratch,
                                     long elapsed)
{
    if (!WIFSIGNALED(status) || WTERMSIG(status) != c->sig)
        return "the harness did not die of the signal sent";
    if (!isf_dir_empty(scratch))
        return "the harness left scratch state behind";
    if (kill(held, 0) == 0 || errno != ESRCH)
        return "the held child was not reaped";
    if (strcmp(c->mode, "polite") == 0 && elapsed > ISF_POLITE_LIMIT_MS)
        return "the signal was not forwarded to the child";
    return nullptr;
}

static void isf_run_sigcase(const char *self, const char *scratch, const struct isf_sigcase *c)
{
    int ready[2];
    long start;
    int status;
    const char *error;
    pid_t pid = isf_start_held(self, scratch, c, ready);
    pid_t held = isf_await_ready(pid, c, ready[0]);

    close(ready[0]);
    start = isf_now_ms();
    for (int i = 0; i < c->count; i++) {
        kill(pid, c->sig);
        if (i + 1 < c->count)
            isf_nap(ISF_SECOND_SIGNAL_MS);
    }
    status = isf_wait_status(pid);
    error = isf_outcome_error(c, status, held, scratch, isf_now_ms() - start);
    if (error != nullptr)
        isf_fail_case(pid, true, held, c, error);
    isf_say("PASS %s", c->name);
}

int isf_signals_selftest(const char *self)
{
    static const struct isf_sigcase cases[] = {
        {"SIGINT once reaches the child and removes scratch", "polite", SIGINT, 1},
        {"SIGHUP once reaches the child and removes scratch", "polite", SIGHUP, 1},
        {"SIGTERM twice escalates to SIGKILL and removes scratch", "stubborn", SIGTERM, 2},
    };
    const char *tmp = getenv("TMPDIR");
    char *scratch = isf_fmt("%s/z23-front-door-signals.XXXXXX", tmp != nullptr && *tmp != '\0' ? tmp : "/tmp");

    if (mkdtemp(scratch) == nullptr)
        isf_die("mkdtemp failed: %s", strerror(errno));
    isf_set_root(scratch);
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++)
        isf_run_sigcase(self, scratch, &cases[i]);
    isf_say("signal selftest PASS");
    return 0;
}
