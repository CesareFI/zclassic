/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Deterministic terminal-observation regression for the actual verifier.
 * Include the implementation to exercise its private wait loop, not a copy.
 * Link in place of package_verify.o using the verifier's own dependencies. */
#define main pv_tool_main
#include "package_verify.c"
#undef main

static bool terminal_deadline_matches(const struct pv_run *run, bool late,
                                     bool fix, bool preview, bool signalled,
                                     int child_exit, int status, bool reaped)
{
    bool expected_timeout = late && (fix || preview);
    int expected_outcome = expected_timeout || signalled ? 5 : child_exit ? 10 : 0;
    bool terminal_matches = signalled ? WIFSIGNALED(status) && WTERMSIG(status) == SIGTERM :
        WIFEXITED(status) && WEXITSTATUS(status) == child_exit;
    return reaped && terminal_matches && run->timed_out == expected_timeout &&
           pv_fix_admit_outcome(run) == expected_outcome;
}

static bool terminal_deadline_row(const char *name, bool fix, bool preview,
                                 bool late, int child_exit, bool signalled)
{
    struct pv_run storage = {0};
    struct pv_run *run = &storage;
    pid_t pid = fork();
    if (pid < 0) {
        fprintf(stderr, "deadline selftest %s: fork failed: %s\n", name, strerror(errno));
        return false;
    }
    if (pid == 0) {
        if (setpgid(0, 0) != 0) _exit(125);
        if (signalled) {
            (void)raise(SIGTERM);
            _exit(125);
        }
        _exit(child_exit);
    }
    (void)setpgid(pid, pid);
    /* First establish a terminal child without reaping it. This eliminates
     * scheduler timing and preserves the group's kernel identity, just as
     * the production loop requires before signalling that group. */
    siginfo_t si;
    memset(&si, 0, sizeof(si));
    int peeked;
    do {
        peeked = waitid(P_PID, (id_t)pid, &si, WEXITED | WNOWAIT);
    } while (peeked < 0 && errno == EINTR);
    if (peeked != 0 || si.si_pid != pid) {
        fprintf(stderr, "deadline selftest %s: terminal peek failed\n", name);
        (void)kill(pid, SIGKILL);
        (void)waitpid(pid, NULL, 0);
        return false;
    }
    g_pv_fix_admit = fix;
    g_pv_preview_control = preview ? "unused-terminal-control" : NULL;
    int64_t now = clock_now_monotonic_ns();
    int64_t deadline = late ? now - 1 : now + INT64_C(5000000000);
    int pipes[2] = {-1, -1}; /* Terminal branch must not read pipes. */
    size_t out_len = 0, err_len = 0;
    int status = 0;
    bool reaped = false;
    struct rusage usage;
    memset(&usage, 0, sizeof(usage));
    run->launched = true;
    pv_run_child_wait_loop(pid, pipes, pipes, deadline, run, &out_len, &err_len,
                           &status, &reaped, &usage);
    if (!run->timed_out) pv_run_child_classify_status(status, run);
    bool ok = terminal_deadline_matches(run, late, fix, preview, signalled,
                                       child_exit, status, reaped);
    if (!ok) {
        fprintf(stderr, "deadline selftest %s: reaped=%d status=%d timed_out=%d\n",
                name, reaped, status, run->timed_out);
    } else {
        printf("deadline selftest %s: PASS\n", name);
    }
    return ok;
}

int main(void)
{
    if (!terminal_deadline_row("fix-late-red", true, false, true, 1, false) ||
        !terminal_deadline_row("fix-late-green", true, false, true, 0, false) ||
        !terminal_deadline_row("fix-late-other-exit", true, false, true, 42, false) ||
        !terminal_deadline_row("fix-late-signal", true, false, true, 0, true) ||
        !terminal_deadline_row("fix-on-time-red", true, false, false, 1, false) ||
        !terminal_deadline_row("fix-on-time-green", true, false, false, 0, false) ||
        !terminal_deadline_row("preview-late-red", false, true, true, 1, false) ||
        !terminal_deadline_row("ordinary-late-red", false, false, true, 1, false))
        return 1;
    puts("deadline selftest: PASS (real terminal-child wait loop; no confinement claim)");
    return 0;
}
