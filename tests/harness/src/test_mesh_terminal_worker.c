/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Live acceptance for the confined terminal worker (mesh_terminal_worker):
 * spawn the granted fbsh on a PTY inside its cage and drive it the way the
 * mesh serving layer will — keyboard in, screen out, resize, budgets, and
 * every ending named. The budget cases are the heart: lifetime and idle
 * are enforced with an INJECTED clock (no sleeping on the harness), the
 * byte budgets bite on real frames, and every kill is proven complete by
 * the process-group census returning to zero.
 *
 * Marker discipline: command markers are written quote-split
 * (Z23TER"M"_OK) so the PTY's echo of the raw typed line can never match
 * the executed output (Z23TERM_OK) — a shell that dies before executing
 * cannot fake a pass.
 *
 * fbsh cases SKIP (never fail) when build/bin/fbsh is absent, mirroring
 * test_freebsd_sh and test_terminal_worker_sandbox.
 */

#define _GNU_SOURCE /* pthread/posix bits, if any — must precede includes */

#if defined(__linux__)
#define geometry_in_bounds tw_fixture_geometry
#define mesh_terminal_win_env_name tw_fixture_win_env_name
#define mesh_terminal_worker_error_string tw_fixture_error_string
#define mesh_terminal_worker_budget_would_overrun tw_fixture_budget_overrun
#define mesh_terminal_worker_spawn tw_fixture_spawn
#define mesh_terminal_worker_input tw_fixture_input
#define mesh_terminal_worker_output tw_fixture_output
#define mesh_terminal_worker_resize tw_fixture_resize
#define mesh_terminal_worker_budget_exceeded tw_fixture_budget_exceeded
#define mesh_terminal_worker_alive tw_fixture_alive
#define mesh_terminal_worker_kill tw_fixture_kill
#endif

#include "test/test_core.h"
#include "platform/os_sandbox.h"
#include "platform/time_compat.h"
#include "session/mesh_terminal_worker.h"

#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <unistd.h>

#define FBSH_BIN "build/bin/fbsh"

#if defined(__linux__)
#include <errno.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
static bool partial_active;
static unsigned partial_writes, partial_polls;
static ssize_t partial_write(int fd, const void *buf, size_t n)
{
    if (!partial_active) return write(fd, buf, n);
    if (++partial_writes == 1) return write(fd, buf, n < 3 ? n : 3);
    errno = EAGAIN;
    return -1;
}
static int partial_poll(struct pollfd *fds, nfds_t n, int timeout)
{
    if (!partial_active) return poll(fds, n, timeout);
    ++partial_polls;
    return 0;
}
static int partial_kill(pid_t pid, int sig)
{
    if (!partial_active) return kill(pid, sig);
    return 0;
}
static bool tw_interrupt_wait;
static unsigned tw_blocking_calls;
static pid_t tw_waited_pid;
static struct mesh_terminal_worker *tw_waiting_worker;
static bool tw_owned_on_retry;
static pid_t tw_fixture_waitpid(pid_t pid, int *status, int options)
{
    if (partial_active) { *status = 0; return pid; }
    if (!tw_interrupt_wait) return waitpid(pid, status, options);
    if (options == WNOHANG) return 0;
    tw_waited_pid = pid;
    if (++tw_blocking_calls == 1) { errno = EINTR; return -1; }
    tw_owned_on_retry = !tw_waiting_worker || tw_waiting_worker->running;
    return waitpid(pid, status, options);
}
/* Compile the production callers with deterministic syscall observations. */
#define write partial_write
#define poll partial_poll
#define kill partial_kill
#define waitpid tw_fixture_waitpid
#include "../../../cognition/modules/session/src/mesh_terminal_worker.c"
#undef waitpid
#undef kill
#undef poll
#undef write
#endif

static char g_dir[160];
static char g_fbsh[600];

/* Budgets used by the live cases: 4 KiB in, 64 KiB out, 60 s lifetime,
 * 30 s idle. Individual cases override the one under test. */
static void live_config(struct mesh_terminal_worker_config *cfg)
{
    memset(cfg, 0, sizeof(*cfg));
    cfg->shell_path = g_fbsh;
    cfg->workdir = g_dir;
    cfg->cols = 80;
    cfg->rows = 24;
    cfg->max_bytes_in = 4096;
    cfg->max_bytes_out = 65536;
    cfg->lifetime_seconds = 60;
    cfg->idle_seconds = 30;
}

static int check(int failures, bool ok, const char *label);

#if defined(__linux__)

static int partial_input_effects(void)
{
    int failures = 0, fds[2];
    if (pipe2(fds, O_NONBLOCK | O_CLOEXEC) != 0)
        return check(failures, false, "partial input pipe setup");
    struct mesh_terminal_worker w = { .pid = 1, .pgid = 1,
        .master_fd = fds[1], .running = true, .max_bytes_in = 8,
        .last_activity_unix = 10 };
    const uint8_t bytes[] = "abcdefgh";
    partial_active = true;
    partial_writes = partial_polls = 0;
    struct zcl_result r = mesh_terminal_worker_input(&w, bytes, 8, 20);
    failures = check(failures, !r.ok && r.code == MESH_TERMINAL_WORKER_ERR_IO,
                     "partial input reports stalled IO");
    failures = check(failures, w.bytes_in == 3 && w.last_activity_unix == 20 && w.running,
                     "partial input charges accepted prefix and activity");
    uint8_t got[8];
    failures = check(failures, read(fds[0], got, sizeof got) == 3 &&
                     memcmp(got, bytes, 3) == 0 && partial_writes == 2 && partial_polls == 1,
                     "partial input transfers exactly three bytes before timeout");
    r = mesh_terminal_worker_input(&w, bytes, 6, 30);
    failures = check(failures, !r.ok && r.code == MESH_TERMINAL_WORKER_ERR_BYTE_LIMIT &&
                     partial_writes == 2 && w.bytes_in == 3 && w.last_activity_unix == 20,
                     "partial input retry refused before another write");
    mesh_terminal_worker_kill(&w);
    partial_active = false;
    close(fds[0]);
    return failures;
}

/* Drain worker output into a rolling buffer until `needle` appears or the
 * deadline passes. Returns true when found. `err` (optional) captures a
 * terminal worker error (BYTE_LIMIT ends the output-budget case with the
 * needle possibly never arriving). On failure the caller can print `saw`. */
static bool drain_until(struct mesh_terminal_worker *w, const char *needle,
                        int timeout_seconds, struct zcl_result *err,
                        char *saw, size_t saw_cap)
{
    char rolling[MESH_TERMINAL_WORKER_IO_CHUNK + 1];
    size_t cap = sizeof rolling - 1;
    size_t fill = 0;
    rolling[0] = '\0';
    time_t deadline = platform_time_wall_time_t() + timeout_seconds;
    while (platform_time_wall_time_t() < deadline) {
        uint8_t chunk[MESH_TERMINAL_WORKER_IO_CHUNK];
        size_t n = 0;
        struct zcl_result r = mesh_terminal_worker_output(
            w, chunk, sizeof chunk, &n,
            (int64_t)platform_time_wall_time_t());
        if (!r.ok && r.code != MESH_TERMINAL_WORKER_ERR_NONE) {
            if (err) *err = r;
            break;
        }
        if (n > 0) {
            size_t append = n;
            if (append > cap)
                append = cap;
            if (fill + append > cap) {
                size_t shift = fill + append - cap;
                if (shift > fill)
                    shift = fill;
                memmove(rolling, rolling + shift, fill - shift);
                fill -= shift;
            }
            memcpy(rolling + fill, chunk, append);
            fill += append;
            rolling[fill] = '\0';
            if (strstr(rolling, needle))
                return true;
            continue;
        }
        usleep(20000);
    }
    if (saw && saw_cap != 0) {
        size_t copy = fill < saw_cap - 1 ? fill : saw_cap - 1;
        memcpy(saw, rolling, copy);
        saw[copy] = '\0';
    }
    return strstr(rolling, needle) != NULL;
}

static bool wait_exit(struct mesh_terminal_worker *w, int timeout_seconds)
{
    time_t deadline = platform_time_wall_time_t() + timeout_seconds;
    while (platform_time_wall_time_t() < deadline) {
        if (!mesh_terminal_worker_alive(w))
            return true;
        usleep(20000);
    }
    return false;
}

#endif

static int check(int failures, bool ok, const char *label)
{
    printf("mesh_terminal_worker: %s... %s\n", label, ok ? "OK" : "FAIL");
    return ok ? failures : failures + 1;
}

#if defined(__linux__)
static int test_interrupted_reaping(void)
{
    int failures = 0, status = 0;
    pid_t pid = fork();
    if (pid == 0) _exit(0);
    failures = check(failures, pid > 0, "reaping fixture fork");
    if (pid < 0) return failures;
    struct mesh_terminal_worker w = {
        .pid = pid, .pgid = pid, .master_fd = -1, .running = true
    };
    tw_interrupt_wait = true;
    tw_blocking_calls = 0;
    tw_waiting_worker = &w;
    tw_owned_on_retry = false;
    mesh_terminal_worker_kill(&w);
    tw_interrupt_wait = false;
    failures = check(failures, tw_blocking_calls >= 2 && tw_owned_on_retry &&
                     !w.running, "kill retries EINTR before releasing ownership");
    pid_t got = waitpid(pid, &status, WNOHANG);
    failures = check(failures, got == -1 && errno == ECHILD,
                     "kill actually reaped the child");
    if (got == 0) { (void)kill(pid, SIGKILL); (void)tw_wait_settled(pid, &status); }
    return failures;
}
static int test_interrupted_startup_reaping(void)
{
    int failures = 0, status = 0;
    struct mesh_terminal_worker w;
    struct mesh_terminal_worker_config cfg = {
        .shell_path = "/dev/null", .workdir = "/dev/null", .cols = 80,
        .rows = 24, .max_bytes_in = 8, .max_bytes_out = 8, .lifetime_seconds = 1
    };
    tw_waiting_worker = NULL;
    tw_blocking_calls = 0;
    tw_waited_pid = 0;
    tw_interrupt_wait = true;
    struct zcl_result r = mesh_terminal_worker_spawn(&cfg, 0, &w);
    tw_interrupt_wait = false;
    failures = check(failures, !r.ok && r.code == MESH_TERMINAL_WORKER_ERR_CONFIG &&
                     !w.running && w.master_fd == -1 && tw_blocking_calls >= 2,
                     "failed startup retries interrupted reap");
    pid_t got = tw_waited_pid > 0 ? waitpid(tw_waited_pid, &status, WNOHANG) : 0;
    failures = check(failures, got == -1 && errno == ECHILD,
                     "failed startup leaves no waitable child");
    if (got == 0 && tw_waited_pid > 0)
        (void)tw_wait_settled(tw_waited_pid, &status);
    return failures;
}
#endif

/* Platform-neutral bookkeeping: geometry_in_bounds and
 * mesh_terminal_worker_budget_would_overrun are pure functions shared by every
 * platform arm (including the Windows ConPTY arm), so no shell or PTY is
 * needed. */
static int test_mesh_terminal_worker_bookkeeping(void)
{
    printf("\n=== mesh terminal worker bookkeeping (platform-neutral) ===\n");
    int failures = 0;

    failures = check(failures, !geometry_in_bounds(0, 24),
                     "geometry: zero cols refused");
    failures = check(failures, !geometry_in_bounds(80, 0),
                     "geometry: zero rows refused");
    failures = check(failures,
                     !geometry_in_bounds(
                         (uint16_t)(MESH_TERMINAL_MAX_COLS + 1), 24),
                     "geometry: cols over proto max refused");
    failures = check(failures,
                     !geometry_in_bounds(
                         80, (uint16_t)(MESH_TERMINAL_MAX_ROWS + 1)),
                     "geometry: rows over proto max refused");
    failures = check(failures,
                     geometry_in_bounds(MESH_TERMINAL_MAX_COLS,
                                        MESH_TERMINAL_MAX_ROWS),
                     "geometry: proto max accepted");
    failures = check(failures, geometry_in_bounds(1, 1),
                     "geometry: 1x1 accepted");

    failures = check(failures,
                     !mesh_terminal_worker_budget_would_overrun(0, 16, 16),
                     "budget: exactly at the cap is not an overrun");
    failures = check(failures,
                     !mesh_terminal_worker_budget_would_overrun(15, 16, 1),
                     "budget: the last byte under the cap fits");
    failures = check(failures,
                     mesh_terminal_worker_budget_would_overrun(0, 16, 17),
                     "budget: one byte past an empty cap overruns");
    failures = check(failures,
                     mesh_terminal_worker_budget_would_overrun(16, 16, 1),
                     "budget: any byte past an already-full cap overruns");
    failures = check(failures,
                     mesh_terminal_worker_budget_would_overrun(17, 16, 0),
                     "budget: already over the cap overruns even on 0 more");
    failures = check(failures,
                     !mesh_terminal_worker_budget_would_overrun(
                         UINT64_MAX - 1, UINT64_MAX, 1),
                     "budget: exact headroom at the top of the range fits "
                     "(no wraparound in max-used)");
    failures = check(failures,
                     mesh_terminal_worker_budget_would_overrun(
                         UINT64_MAX, UINT64_MAX, 1),
                     "budget: no headroom left at the top of the range");

    printf("mesh_terminal_worker bookkeeping: %d failures\n", failures);
    return failures;
}

/* The platform gate: flag off on Windows stays refused; flag on admits
 * Windows with the owner-accepted marker; flag on elsewhere is refused by
 * name; POSIX with the flag off is not gated. */
static int test_mesh_terminal_confinement_gate(void)
{
    const enum mesh_terminal_platform win = MESH_TERMINAL_PLATFORM_WINDOWS;
    const enum mesh_terminal_platform posix = MESH_TERMINAL_PLATFORM_POSIX;
    int failures = 0;
    failures = check(failures,
                     mesh_terminal_confinement_refusal(win, false) != NULL,
                     "windows, flag off: lane refused");
    failures = check(failures,
                     mesh_terminal_confinement_refusal(win, true) == NULL,
                     "windows, flag on: lane admitted");
    failures = check(failures,
                     strcmp(mesh_terminal_confinement_marker(win, true),
                            "unconfined-owner-accepted") == 0,
                     "windows, flag on: owner-accepted marker");
    failures = check(failures,
                     strcmp(mesh_terminal_confinement_marker(win, false),
                            "confined") == 0,
                     "windows, flag off: no unconfined marker");
    failures = check(failures,
                     mesh_terminal_confinement_refusal(posix, true) != NULL,
                     "non-windows, flag on: refused by name");
    failures = check(failures,
                     strcmp(mesh_terminal_confinement_marker(posix, true),
                            "confined") == 0,
                     "non-windows, flag on: never marked unconfined");
    failures = check(failures,
                     mesh_terminal_confinement_refusal(posix, false) == NULL,
                     "non-windows, flag off: not gated");
    return failures;
}

struct shell_path_case {
    enum mesh_terminal_platform platform;
    const char *path;
    bool valid;
    const char *label;
};

/* Table: every row is judged by the grammar it names, on any host. */
static int test_mesh_terminal_shell_path_table(void)
{
    printf("\n=== mesh terminal shell path grammar (platform-neutral) ===\n");
    static const struct shell_path_case cases[] = {
        { MESH_TERMINAL_PLATFORM_POSIX, "/bin/sh", true, "posix absolute" },
        { MESH_TERMINAL_PLATFORM_POSIX, "bin/sh", false, "posix relative" },
        { MESH_TERMINAL_PLATFORM_POSIX, "", false, "posix empty" },
        { MESH_TERMINAL_PLATFORM_POSIX, "C:\\Windows\\cmd.exe", false,
          "posix refuses a drive path" },
        { MESH_TERMINAL_PLATFORM_WINDOWS, "C:\\Windows\\System32\\cmd.exe",
          true, "windows drive path" },
        { MESH_TERMINAL_PLATFORM_WINDOWS, "d:/Tools/pwsh.EXE", true,
          "windows forward slashes, lower drive, upper suffix" },
        { MESH_TERMINAL_PLATFORM_WINDOWS,
          "C:\\Program Files\\PowerShell\\7\\pwsh.exe", true,
          "windows path with spaces" },
        { MESH_TERMINAL_PLATFORM_WINDOWS, "/bin/sh", false,
          "windows refuses a POSIX path" },
        { MESH_TERMINAL_PLATFORM_WINDOWS, "\\\\host\\share\\sh.exe", false,
          "windows refuses UNC" },
        { MESH_TERMINAL_PLATFORM_WINDOWS, "\\\\?\\C:\\sh.exe", false,
          "windows refuses a device prefix" },
        { MESH_TERMINAL_PLATFORM_WINDOWS, "sh.exe", false,
          "windows refuses a bare name" },
        { MESH_TERMINAL_PLATFORM_WINDOWS, "C:sh.exe", false,
          "windows refuses a drive-relative path" },
        { MESH_TERMINAL_PLATFORM_WINDOWS, "\\sh.exe", false,
          "windows refuses a rooted path with no drive" },
        { MESH_TERMINAL_PLATFORM_WINDOWS, "C:\\a\\..\\b\\sh.exe", false,
          "windows refuses a parent segment" },
        { MESH_TERMINAL_PLATFORM_WINDOWS, "C:\\a\\.\\sh.exe", false,
          "windows refuses a dot segment" },
        { MESH_TERMINAL_PLATFORM_WINDOWS, "C:\\a\\\\sh.exe", false,
          "windows refuses an empty segment" },
        { MESH_TERMINAL_PLATFORM_WINDOWS, "C:\\a\\sh.exe\\", false,
          "windows refuses a trailing separator" },
        { MESH_TERMINAL_PLATFORM_WINDOWS, "C:\\a\\sh.exe -NoProfile", false,
          "windows refuses an argument" },
        { MESH_TERMINAL_PLATFORM_WINDOWS, "C:\\a\\\"sh.exe", false,
          "windows refuses a quote" },
        { MESH_TERMINAL_PLATFORM_WINDOWS, "C:\\a\\sh.exe:stream.exe", false,
          "windows refuses a stream designator" },
        { MESH_TERMINAL_PLATFORM_WINDOWS, "C:\\a\\s*.exe", false,
          "windows refuses a wildcard" },
        { MESH_TERMINAL_PLATFORM_WINDOWS, "C:\\a \\sh.exe", false,
          "windows refuses a trailing-space segment" },
        { MESH_TERMINAL_PLATFORM_WINDOWS, "C:\\a\\sh.bat", false,
          "windows requires an exe image" },
        { MESH_TERMINAL_PLATFORM_WINDOWS, "C:\\a\\nul.exe", false,
          "windows refuses a reserved device stem" },
        { MESH_TERMINAL_PLATFORM_WINDOWS, "C:\\a\\COM1.exe", false,
          "windows refuses a reserved stem in any case" },
        { MESH_TERMINAL_PLATFORM_WINDOWS, "C:\\a\\lpt9.txt.exe", false,
          "windows refuses a reserved stem before the first dot" },
        { MESH_TERMINAL_PLATFORM_WINDOWS, "C:\\con\\sh.exe", false,
          "windows refuses a reserved directory name" },
        { MESH_TERMINAL_PLATFORM_WINDOWS, "C:\\a\\com0.exe", true,
          "com0 is not a reserved device" },
        { MESH_TERMINAL_PLATFORM_WINDOWS, "C:\\a\\console.exe", true,
          "a longer name sharing a reserved prefix is allowed" },
        { MESH_TERMINAL_PLATFORM_WINDOWS, "C:\\", false,
          "windows refuses the bare root" },
        { MESH_TERMINAL_PLATFORM_WINDOWS, "", false, "windows empty" },
    };
    int failures = 0;
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
        failures = check(failures,
                         mesh_terminal_shell_path_valid(
                             cases[i].platform, cases[i].path) ==
                             cases[i].valid,
                         cases[i].label);

    char longpath[MESH_TERMINAL_SHELL_PATH_MAX_POSIX + 16];
    memset(longpath, 'a', sizeof(longpath));
    memcpy(longpath, "C:\\", 3);
    memcpy(longpath + MESH_TERMINAL_SHELL_PATH_MAX_WINDOWS, ".exe", 5);
    failures = check(failures,
                     !mesh_terminal_shell_path_valid(
                         MESH_TERMINAL_PLATFORM_WINDOWS, longpath),
                     "windows refuses an over-long path");
    memset(longpath, 'a', sizeof(longpath));
    longpath[0] = '/';
    longpath[MESH_TERMINAL_SHELL_PATH_MAX_POSIX] = '\0';
    failures = check(failures,
                     !mesh_terminal_shell_path_valid(
                         MESH_TERMINAL_PLATFORM_POSIX, longpath),
                     "posix refuses a path the lane buffer would truncate");
    failures = check(failures,
                     !mesh_terminal_shell_path_valid(
                         MESH_TERMINAL_PLATFORM_POSIX, NULL),
                     "null refused");
    bool sorted = true, has_path = false, leak = false;
    size_t count = 0;
    for (const char *n; (n = mesh_terminal_win_env_name(count)); count++) {
        const char *prev = count ? mesh_terminal_win_env_name(count - 1) : NULL;
        sorted = sorted && (!prev || strcasecmp(prev, n) < 0);
        has_path = has_path || strcmp(n, "PATH") == 0;
        leak = leak || strstr(n, "KEY") || strstr(n, "TOKEN") ||
               strstr(n, "SECRET");
    }
    failures = check(failures, sorted && count == 11 && has_path && !leak,
                     "environment allow-list is sorted, includes PATH, and "
                     "names no credential variable");
    return failures + test_mesh_terminal_confinement_gate();
}

#if !defined(__linux__)

/* The worker must refuse honestly on platforms with no confinement
 * stack — every entry by name, never a simulated success. */
static int test_mesh_terminal_worker_platform_arm(void)
{
    printf("\n=== mesh terminal worker tests ===\n");
    int failures = 0;
    struct mesh_terminal_worker_config cfg;
    struct mesh_terminal_worker w;
    live_config(&cfg);

    struct zcl_result r = mesh_terminal_worker_spawn(&cfg, 0, &w);
    failures = check(failures,
                     !r.ok && r.code == MESH_TERMINAL_WORKER_ERR_UNSUPPORTED,
                     "spawn refuses honestly (unsupported)");
    uint8_t buf[16];
    size_t n = 99;
    r = mesh_terminal_worker_output(&w, buf, sizeof buf, &n, 0);
    failures = check(failures, !r.ok && n == 0, "output refuses honestly");
    r = mesh_terminal_worker_input(&w, buf, 1, 0);
    failures = check(failures, !r.ok, "input refuses honestly");
    r = mesh_terminal_worker_resize(&w, 80, 24);
    failures = check(failures, !r.ok, "resize refuses honestly");
    failures = check(failures,
                     mesh_terminal_worker_budget_exceeded(&w, 0),
                     "budget_exceeded: no session is over");
    failures = check(failures, !mesh_terminal_worker_alive(&w),
                     "alive: false with no session");
    mesh_terminal_worker_kill(&w); /* no-op */
    printf("mesh_terminal_worker: %d failures (unsupported platform)\n",
           failures);
    return failures;
}

#else /* __linux__ */

/* Live: the shell's exit status reaches the worker record. */
static int live_exit_status(void)
{
    int failures = 0;
    /* ── live: the remote status survives to the worker record ─────── */
    {
        static const struct {
            const char *line;
            int exit_code;
            int signal;
            const char *label;
        } cases[] = {
            { "exit 3\n", 3, 0, "exit 3 -> exit_code 3, no signal" },
            { "kill -KILL $$\n", 137, 9,
              "SIGKILL death -> exit_code 137, signal 9" },
            { "exit 143\n", 143, 0,
              "exit 143 is a code, not a signal" },
        };
        for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
            struct mesh_terminal_worker_config cfg;
            struct mesh_terminal_worker w;
            live_config(&cfg);
            int64_t t0 = (int64_t)platform_time_wall_time_t();
            struct zcl_result r = mesh_terminal_worker_spawn(&cfg, t0, &w);
            failures = check(failures, r.ok, "spawn for exit status");
            if (r.ok) {
                r = mesh_terminal_worker_input(
                    &w, (const uint8_t *)cases[i].line,
                    strlen(cases[i].line), t0 + 1);
                failures = check(failures, r.ok && wait_exit(&w, 5) &&
                                     w.close_reason ==
                                         MESH_TERMINAL_CLOSE_WORKER_EXITED &&
                                     w.exit_code == cases[i].exit_code &&
                                     w.term_signal == cases[i].signal,
                                 cases[i].label);
            }
            mesh_terminal_worker_kill(&w);
        }
    }

    return failures;
}

/* Live: an explicit argv replaces the shell inside the same cage. */
static int live_explicit_argv(void)
{
    int failures = 0;
    struct mesh_terminal_worker_config cfg;
    struct mesh_terminal_worker w;
    char outside[160];
    char outside_dir[160];
    test_make_tmpdir(outside_dir, sizeof outside_dir, "terminal_worker_live", "outside");
    snprintf(outside, sizeof outside, "%s/leak", outside_dir);
    unlink(outside);
    char script[240];
    snprintf(script, sizeof script, "echo leaked > %s; exit 6", outside);
    const char *const run[] = { g_fbsh, "-c", script, NULL };
    live_config(&cfg);
    cfg.argv = run;
    int64_t t0 = (int64_t)platform_time_wall_time_t();
    struct zcl_result r = mesh_terminal_worker_spawn(&cfg, t0, &w);
    failures = check(failures, r.ok, "argv: spawn");
    if (r.ok)
        failures = check(failures, wait_exit(&w, 5) && w.exit_code == 6 &&
                         w.close_reason == MESH_TERMINAL_CLOSE_WORKER_EXITED,
                         "argv: the program ran and its exit code 6 propagates");
    mesh_terminal_worker_kill(&w);
    struct stat st;
    failures = check(failures, stat(outside, &st) != 0,
                     "argv: a write outside the granted workdir is denied");
    unlink(outside);

    static const char *const relative[] = { "fbsh", "-c", "exit 0", NULL };
    static const char *const empty[] = { NULL };
    static const char *const missing[] = { "/nonexistent/z23-prog", NULL };
    static const char *const too_many[] = { "/a", "/a", "/a", "/a", "/a", "/a", "/a", "/a", "/a",
                                            "/a", "/a", "/a", "/a", "/a", "/a", "/a", "/a", NULL };
    static const struct { const char *const *argv; int code; const char *label; } bad[] = {
        { relative, MESH_TERMINAL_WORKER_ERR_CONFIG, "argv: a relative argv[0] -> config" },
        { empty, MESH_TERMINAL_WORKER_ERR_CONFIG, "argv: an empty argv -> config" },
        { too_many, MESH_TERMINAL_WORKER_ERR_CONFIG, "argv: 17 strings -> config" },
        { missing, MESH_TERMINAL_WORKER_ERR_EXEC, "argv: a missing program -> exec, by name" },
    };
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        live_config(&cfg);
        cfg.argv = bad[i].argv;
        r = mesh_terminal_worker_spawn(&cfg, t0, &w);
        failures = check(failures, !r.ok && r.code == bad[i].code, bad[i].label);
        mesh_terminal_worker_kill(&w);
    }
    return failures;
}

/* Live: a dynamically linked program runs in the cage (ld.so maps its
 * libraries with file-backed PROT_EXEC mmap); exit codes propagate. */
static int live_dynamic_argv(void)
{
    static const struct { const char *path; int code; } progs[] = {
        { "/usr/bin/true", 0 }, { "/usr/bin/false", 1 },
    };
    int failures = 0;
    for (size_t i = 0; i < sizeof progs / sizeof progs[0]; i++) {
        struct stat st;
        if (stat(progs[i].path, &st) != 0 || (st.st_mode & S_IXUSR) == 0) {
            printf("mesh_terminal_worker: SKIP dynamic argv %s (absent)\n",
                   progs[i].path);
            continue;
        }
        const char *const run[] = { progs[i].path, NULL };
        struct mesh_terminal_worker_config cfg;
        struct mesh_terminal_worker w;
        live_config(&cfg);
        cfg.argv = run;
        int64_t t0 = (int64_t)platform_time_wall_time_t();
        struct zcl_result r = mesh_terminal_worker_spawn(&cfg, t0, &w);
        failures = check(failures, r.ok, "dynamic argv: spawn");
        if (r.ok)
            failures = check(failures, wait_exit(&w, 5) &&
                             w.term_signal == 0 && w.exit_code == progs[i].code &&
                             w.close_reason == MESH_TERMINAL_CLOSE_WORKER_EXITED,
                             progs[i].code ? "dynamic argv: /usr/bin/false exits 1"
                                           : "dynamic argv: /usr/bin/true exits 0");
        mesh_terminal_worker_kill(&w);
    }
    return failures;
}

/* Live: 2 MiB of output under the service byte budget. */
static int live_two_mib_output(void)
{
    int failures = 0;
    /* ── live: 2 MiB of output under the service budget ────────────── */
    {
        struct mesh_terminal_worker_config cfg;
        struct mesh_terminal_worker w;
        live_config(&cfg);
        cfg.max_bytes_out = UINT64_C(1) << 30; /* the service default */
        cfg.max_bytes_in = UINT64_C(16) << 20;
        int64_t t0 = (int64_t)platform_time_wall_time_t();
        struct zcl_result r = mesh_terminal_worker_spawn(&cfg, t0, &w);
        failures = check(failures, r.ok, "spawn for 2 MiB output");
        if (r.ok) {
            const uint8_t line[] =
                "a=0123456789abcdef;a=$a$a;a=$a$a;a=$a$a;a=$a$a;a=$a$a;a=$a$a;"
                "i=0;while [ $i -lt 2100 ];do echo $a;i=$((i+1));done;"
                "echo ZZZ$((1+1))END\n";
            r = mesh_terminal_worker_input(&w, line, sizeof line - 1, t0 + 1);
            failures = check(failures, r.ok, "2 MiB command input accepted");
            size_t total = 0, biggest = 0;
            bool end_seen = false, failed = false;
            char tail[16] = "";
            time_t deadline = platform_time_wall_time_t() + 30;
            while (!end_seen && !failed &&
                   platform_time_wall_time_t() < deadline) {
                uint8_t chunk[MESH_TERMINAL_WORKER_IO_CHUNK];
                size_t n = 0;
                r = mesh_terminal_worker_output(
                    &w, chunk, sizeof chunk, &n,
                    (int64_t)platform_time_wall_time_t());
                if (!r.ok && r.code != MESH_TERMINAL_WORKER_ERR_NONE) {
                    failed = true;
                    break;
                }
                if (n == 0) {
                    usleep(2000);
                    continue;
                }
                total += n;
                if (n > biggest)
                    biggest = n;
                char probe[sizeof tail * 2];
                size_t keep = strlen(tail);
                memcpy(probe, tail, keep);
                size_t take = n < sizeof tail - 1 ? n : sizeof tail - 1;
                memcpy(probe + keep, chunk + n - take, take);
                probe[keep + take] = '\0';
                end_seen = strstr(probe, "ZZZ2END") != NULL;
                size_t tl = keep + take < sizeof tail - 1 ? keep + take
                                                          : sizeof tail - 1;
                memmove(tail, probe + keep + take - tl, tl);
                tail[tl] = '\0';
            }
            failures = check(failures, !failed && end_seen,
                             "2 MiB session was not ended by byte-limit");
            failures = check(failures, total >= 2097152 &&
                                 w.close_reason !=
                                     MESH_TERMINAL_CLOSE_BYTE_LIMIT,
                             "2 MiB of output delivered, reason not "
                             "byte-limit");
            failures = check(failures, biggest <= (size_t)(
                                 MESH_TERMINAL_WORKER_IO_CHUNK),
                             "memory bounded: every read fits the fixed "
                             "chunk");
        }
        mesh_terminal_worker_kill(&w);
    }

    return failures;
}

static int test_mesh_terminal_worker_platform_arm(void)
{
    printf("\n=== mesh terminal worker tests ===\n");
    int failures = 0;

    test_make_tmpdir(g_dir, sizeof g_dir, "terminal_worker_live", "live");
    if (!test_abs_path(FBSH_BIN, g_fbsh, sizeof g_fbsh))
        g_fbsh[0] = '\0';
    struct stat st;
    bool fbsh = g_fbsh[0] && stat(FBSH_BIN, &st) == 0 &&
                (st.st_mode & S_IXUSR) != 0;

    /* ── config refusals (by name; no fbsh needed) ─────────────────── */
    {
        struct mesh_terminal_worker_config cfg;
        struct mesh_terminal_worker w;
        live_config(&cfg);
        struct zcl_result r = mesh_terminal_worker_spawn(NULL, 0, &w);
        failures = check(failures,
                         !r.ok && r.code == MESH_TERMINAL_WORKER_ERR_NULL,
                         "spawn(NULL) -> null");
        r = mesh_terminal_worker_spawn(&cfg, 0, NULL);
        failures = check(failures,
                         !r.ok && r.code == MESH_TERMINAL_WORKER_ERR_NULL,
                         "spawn(out=NULL) -> null");

        static const char *relative = "build/bin/fbsh";
        cfg.shell_path = relative;
        r = mesh_terminal_worker_spawn(&cfg, 0, &w);
        failures = check(failures,
                         !r.ok && r.code == MESH_TERMINAL_WORKER_ERR_CONFIG,
                         "relative shell_path -> config");
        live_config(&cfg);
        static char relative_dir[] = "test-tmp";
        cfg.workdir = relative_dir;
        r = mesh_terminal_worker_spawn(&cfg, 0, &w);
        failures = check(failures,
                         !r.ok && r.code == MESH_TERMINAL_WORKER_ERR_CONFIG,
                         "relative workdir -> config");
        live_config(&cfg);
        cfg.max_bytes_in = 0;
        r = mesh_terminal_worker_spawn(&cfg, 0, &w);
        failures = check(failures,
                         !r.ok && r.code == MESH_TERMINAL_WORKER_ERR_CONFIG,
                         "zero input budget -> config");
        live_config(&cfg);
        cfg.lifetime_seconds = 0;
        r = mesh_terminal_worker_spawn(&cfg, 0, &w);
        failures = check(failures,
                         !r.ok && r.code == MESH_TERMINAL_WORKER_ERR_CONFIG,
                         "zero lifetime -> config");
        live_config(&cfg);
        cfg.cols = 0;
        r = mesh_terminal_worker_spawn(&cfg, 0, &w);
        failures = check(failures,
                         !r.ok && r.code == MESH_TERMINAL_WORKER_ERR_CONFIG,
                         "zero cols -> config");
    }

    if (!fbsh) {
        printf("mesh_terminal_worker: " FBSH_BIN
               " not built — SKIP the live cases (run `make fbsh`)\n");
        printf("mesh_terminal_worker: %d failures\n", failures);
        return failures;
    }

    /* ── live: interactive roundtrip + census ──────────────────────── */
    {
        struct mesh_terminal_worker_config cfg;
        struct mesh_terminal_worker w;
        live_config(&cfg);
        int64_t t0 = (int64_t)platform_time_wall_time_t();
        struct zcl_result r = mesh_terminal_worker_spawn(&cfg, t0, &w);
        failures = check(failures, r.ok, "spawn fbsh in the cage");
        if (r.ok) {
            failures = check(failures, w.pid > 0 && w.pgid == w.pid &&
                                         w.master_fd >= 0,
                             "spawn fills pid/pgid/master");
            failures = check(failures,
                             os_sandbox_process_group_census(w.pgid) >= 1,
                             "census sees the session's process group");
            const uint8_t line[] = "echo Z23TER\"M\"_OK\n";
            r = mesh_terminal_worker_input(&w, line, sizeof line - 1, t0 + 1);
            failures = check(failures, r.ok, "input accepted");
            char saw[256] = {0};
            bool found = drain_until(&w, "Z23TERM_OK", 5, NULL,
                                     saw, sizeof saw);
            failures = check(failures, found,
                             "shell executed the typed line (echo output)");
            if (!found) {
                printf("  saw %.200s\n", saw);
                failures = check(failures, mesh_terminal_worker_alive(&w),
                                 "shell was alive during the drain");
            }
            failures = check(failures, w.bytes_in == sizeof line - 1,
                             "input byte accounting");
        }
        mesh_terminal_worker_kill(&w);
        failures = check(failures,
                         os_sandbox_process_group_census(w.pgid) == 0,
                         "kill leaves an empty process group");
        const uint8_t more[] = "x";
        r = mesh_terminal_worker_input(&w, more, 1, t0 + 2);
        failures = check(failures,
                         !r.ok &&
                             r.code == MESH_TERMINAL_WORKER_ERR_NOT_RUNNING,
                         "input after kill -> not-running");
    }

    /* ── live: natural exit is reaped and named ────────────────────── */
    {
        struct mesh_terminal_worker_config cfg;
        struct mesh_terminal_worker w;
        live_config(&cfg);
        int64_t t0 = (int64_t)platform_time_wall_time_t();
        struct zcl_result r = mesh_terminal_worker_spawn(&cfg, t0, &w);
        failures = check(failures, r.ok, "spawn for natural exit");
        if (r.ok) {
            const uint8_t line[] = "exit\n";
            r = mesh_terminal_worker_input(&w, line, sizeof line - 1,
                                           t0 + 1);
            failures = check(failures, r.ok,
                             "exit command input accepted");
            failures = check(failures, wait_exit(&w, 5),
                             "shell exits on `exit`");
            failures = check(failures,
                             !w.running &&
                                 w.close_reason ==
                                     MESH_TERMINAL_CLOSE_WORKER_EXITED &&
                                 w.exit_code == 0,
                             "natural exit named worker-exited (code 0)");
            /* Enforcement after death reports over but keeps the exit's
             * name — reap wins over the timeout checks. */
            bool over = mesh_terminal_worker_budget_exceeded(&w,
                                                             t0 + 100000);
            failures = check(failures, over &&
                                           w.close_reason ==
                                               MESH_TERMINAL_CLOSE_WORKER_EXITED,
                             "enforce after exit keeps worker-exited");
        }
        mesh_terminal_worker_kill(&w);
    }

    failures += live_exit_status();
    failures += live_explicit_argv();
    failures += live_dynamic_argv();
    failures += live_two_mib_output();

    /* ── live: input byte budget ───────────────────────────────────── */
    {
        struct mesh_terminal_worker_config cfg;
        struct mesh_terminal_worker w;
        live_config(&cfg);
        cfg.max_bytes_in = 16;
        int64_t t0 = (int64_t)platform_time_wall_time_t();
        struct zcl_result r = mesh_terminal_worker_spawn(&cfg, t0, &w);
        failures = check(failures, r.ok, "spawn for input budget");
        if (r.ok) {
            const uint8_t exact[16] = {0};
            r = mesh_terminal_worker_input(&w, exact, sizeof exact, t0 + 1);
            failures = check(failures, r.ok,
                             "input exactly at budget accepted");
            const uint8_t one[] = "a";
            r = mesh_terminal_worker_input(&w, one, 1, t0 + 2);
            failures = check(failures,
                             !r.ok &&
                                 r.code ==
                                     MESH_TERMINAL_WORKER_ERR_BYTE_LIMIT &&
                                 w.close_reason ==
                                     MESH_TERMINAL_CLOSE_BYTE_LIMIT,
                             "input over budget -> byte-limit");
            failures = check(failures, !mesh_terminal_worker_alive(&w),
                             "budget kill ended the session");
            failures = check(failures,
                             os_sandbox_process_group_census(w.pgid) == 0,
                             "budget kill emptied the process group");
        }
        mesh_terminal_worker_kill(&w);
    }

    /* ── live: output byte budget ──────────────────────────────────── */
    {
        struct mesh_terminal_worker_config cfg;
        struct mesh_terminal_worker w;
        live_config(&cfg);
        cfg.max_bytes_out = 64;
        int64_t t0 = (int64_t)platform_time_wall_time_t();
        struct zcl_result r = mesh_terminal_worker_spawn(&cfg, t0, &w);
        failures = check(failures, r.ok, "spawn for output budget");
        if (r.ok) {
            const uint8_t line[] =
                "echo 0123456789012345678901234567890123456789"
                "0123456789012345678901234567890123456789\n";
            r = mesh_terminal_worker_input(&w, line, sizeof line - 1,
                                           t0 + 1);
            failures = check(failures, r.ok,
                             "output-budget command input accepted");
            struct zcl_result err = { .ok = true };
            (void)drain_until(&w, "ZZZ_NEVER", 5, &err, NULL, 0);
            failures = check(failures,
                             !err.ok &&
                                 err.code ==
                                     MESH_TERMINAL_WORKER_ERR_BYTE_LIMIT,
                             "output over budget -> byte-limit");
            failures = check(failures, w.bytes_out > 64,
                             "output bytes were accounted before the kill");
            failures = check(failures,
                             os_sandbox_process_group_census(w.pgid) == 0,
                             "output budget kill emptied the group");
        }
        mesh_terminal_worker_kill(&w);
    }

    /* ── lifetime + idle: injected clock, no sleeping ──────────────── */
    {
        struct mesh_terminal_worker_config cfg;
        struct mesh_terminal_worker w;
        live_config(&cfg);
        cfg.idle_seconds = 0; /* isolate the lifetime check: at t0+59 the
                               * idle window (30 s) would otherwise fire
                               * first and name the kill idle-timeout */
        int64_t t0 = (int64_t)platform_time_wall_time_t();
        struct zcl_result r = mesh_terminal_worker_spawn(&cfg, t0, &w);
        failures = check(failures, r.ok, "spawn for lifetime budget");
        if (r.ok) {
            failures = check(failures,
                             !mesh_terminal_worker_budget_exceeded(&w,
                                                                   t0 + 59),
                             "one tick inside the lifetime still alive");
            bool over = mesh_terminal_worker_budget_exceeded(&w, t0 + 61);
            failures = check(failures, over &&
                                           w.close_reason ==
                                               MESH_TERMINAL_CLOSE_LIFETIME_LIMIT,
                             "lifetime exceeded -> lifetime-limit");
            failures = check(failures,
                             os_sandbox_process_group_census(w.pgid) == 0,
                             "lifetime kill emptied the group");
        }
        mesh_terminal_worker_kill(&w);

        live_config(&cfg);
        cfg.idle_seconds = 30; /* unchanged; lifetime stays 60 (> 31) */
        r = mesh_terminal_worker_spawn(&cfg, t0, &w);
        failures = check(failures, r.ok, "spawn for idle budget");
        if (r.ok) {
            failures = check(failures,
                             !mesh_terminal_worker_budget_exceeded(&w,
                                                                   t0 + 29),
                             "one tick inside the idle window alive");
            bool over = mesh_terminal_worker_budget_exceeded(&w, t0 + 31);
            failures = check(failures, over &&
                                           w.close_reason ==
                                               MESH_TERMINAL_CLOSE_IDLE_TIMEOUT,
                             "idle exceeded -> idle-timeout");
        }
        mesh_terminal_worker_kill(&w);
    }

    /* ── live: resize bounds + confinement through the terminal ────── */
    {
        struct mesh_terminal_worker_config cfg;
        struct mesh_terminal_worker w;
        live_config(&cfg);
        int64_t t0 = (int64_t)platform_time_wall_time_t();
        struct zcl_result r = mesh_terminal_worker_spawn(&cfg, t0, &w);
        failures = check(failures, r.ok, "spawn for resize/confinement");
        if (r.ok) {
            r = mesh_terminal_worker_resize(&w, MESH_TERMINAL_MAX_COLS,
                                            MESH_TERMINAL_MAX_ROWS);
            failures = check(failures, r.ok, "resize to proto max");
            r = mesh_terminal_worker_resize(&w, 0, 24);
            failures = check(failures,
                             !r.ok &&
                                 r.code == MESH_TERMINAL_WORKER_ERR_GEOMETRY,
                             "resize zero cols -> geometry");
            r = mesh_terminal_worker_resize(
                &w, (uint16_t)(MESH_TERMINAL_MAX_COLS + 1), 24);
            failures = check(failures,
                             !r.ok &&
                                 r.code == MESH_TERMINAL_WORKER_ERR_GEOMETRY,
                             "resize over max cols -> geometry");

            /* Attack through the shell: cat is NOT granted, so the read
             * cannot happen — and nothing secret may appear on screen. */
            const uint8_t shadow[] = "cat /etc/shadow\n";
            r = mesh_terminal_worker_input(&w, shadow,
                                           sizeof shadow - 1, t0 + 1);
            failures = check(failures, r.ok,
                             "confined attack input accepted");
            struct zcl_result err = { .ok = true };
            (void)drain_until(&w, "not found", 5, &err, NULL, 0);
            (void)err;

            /* The shell must still be alive and working after the
             * refusal — confined is not broken. */
            failures = check(failures, mesh_terminal_worker_alive(&w),
                             "shell survived the refused attack");
            const uint8_t probe[] = "echo A$((6*7))B\n";
            r = mesh_terminal_worker_input(&w, probe, sizeof probe - 1,
                                           t0 + 2);
            failures = check(failures, r.ok, "probe accepted after refusal");
            bool found = drain_until(&w, "A42B", 5, NULL, NULL, 0);
            failures = check(failures, found,
                             "shell still executes after the refusal");
        }
        mesh_terminal_worker_kill(&w);
        failures = check(failures,
                         os_sandbox_process_group_census(w.pgid) == 0,
                         "final kill emptied the group");
    }

    printf("mesh_terminal_worker: %d failures\n", failures);
    return failures;
}

#endif /* __linux__ */

int test_mesh_terminal_worker(void)
{
    int failures = test_mesh_terminal_worker_bookkeeping();
    failures += test_mesh_terminal_shell_path_table();
#if defined(__linux__)
    failures += partial_input_effects();
    failures += test_interrupted_reaping();
    failures += test_interrupted_startup_reaping();
#endif
    failures += test_mesh_terminal_worker_platform_arm();
    return failures;
}
