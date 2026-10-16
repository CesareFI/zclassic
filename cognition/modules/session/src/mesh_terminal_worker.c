/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: The confined terminal worker implementation — see the header
 * for the contract. Linux uses a PTY; Windows uses ConPTY; the stub
 * refuses by name on every other platform. */

#define _GNU_SOURCE /* ptsname_r, pipe2 — must precede every include */

#include "session/mesh_terminal_worker.h"

#if defined(__linux__)
#include "platform/os_sandbox.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <termios.h> /* struct winsize */
#include <unistd.h>
#elif defined(_WIN32)
/* ConPTY (CreatePseudoConsole/ResizePseudoConsole/ClosePseudoConsole) and
 * PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE are declared by the mingw-w64 and
 * MSVC headers only once NTDDI_VERSION names the Windows 10 October 2018
 * Update (RS5, NTDDI_WIN10_RS5 == 0x0A000006) or newer. Z23's native
 * baseline is already Windows 10 (ZCL_PLATFORM_CPPFLAGS pins
 * -D_WIN32_WINNT=0x0A00), but <sdkddkver.h> derives a LOWER default
 * NTDDI_VERSION from _WIN32_WINNT alone, which leaves ConPTY undeclared —
 * confirmed against the installed mingw-w64 headers while writing this
 * arm. Pin NTDDI_VERSION explicitly here, the same way
 * platform/modules/platform/src/logical_cpu.c pins its own per-TU
 * _WIN32_WINNT floor, so a standalone TU check (check-windows-cross-syntax
 * compiles this file on its own) sees the same API surface a real build
 * would, and refuse a lower floor set some other way rather than silently
 * compiling against an older, ConPTY-less SDK target. */
#if !defined(NTDDI_VERSION)
#define NTDDI_VERSION 0x0A000006
#elif NTDDI_VERSION < 0x0A000006
#error "mesh_terminal_worker's Windows arm requires NTDDI_WIN10_RS5 (ConPTY) or newer"
#endif
#if !defined(_WIN32_WINNT)
#define _WIN32_WINNT 0x0A00
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <bcrypt.h>
#include <sddl.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#include "util/safe_alloc.h" /* zcl_malloc: checked, logged OOM */
#endif

/* The default subtree process budget, enforced by the parent's
 * process-group census (RLIMIT_NPROC cannot do this job — it counts the
 * whole uid's tasks — so the census is the only escape-proof accounting).
 * A pipeline, command substitution, and a couple of subshells stay well
 * under it. */
#define MESH_TERMINAL_WORKER_MAX_PROCESSES 32u

/* Child-side failure stages, staged back through the close-on-exec pipe
 * so spawn() can refuse BY NAME instead of "the child went away". */
enum {
    TW_STAGE_TTY = 1,        /* slave open / ctty / winsize / dup2 */
    TW_STAGE_CHDIR = 2,      /* workdir chdir */
    TW_STAGE_CONFINEMENT = 3,/* sandbox enter */
    TW_STAGE_EXEC = 4,       /* execve */
};

const char *mesh_terminal_worker_error_string(
    enum mesh_terminal_worker_error error)
{
    switch (error) {
    case MESH_TERMINAL_WORKER_ERR_NONE: return "ok";
    case MESH_TERMINAL_WORKER_ERR_NULL: return "null";
    case MESH_TERMINAL_WORKER_ERR_CONFIG: return "config";
    case MESH_TERMINAL_WORKER_ERR_PTY: return "pty";
    case MESH_TERMINAL_WORKER_ERR_SPAWN: return "spawn";
    case MESH_TERMINAL_WORKER_ERR_CONFINEMENT: return "confinement";
    case MESH_TERMINAL_WORKER_ERR_EXEC: return "exec";
    case MESH_TERMINAL_WORKER_ERR_TTY: return "tty";
    case MESH_TERMINAL_WORKER_ERR_NOT_RUNNING: return "not-running";
    case MESH_TERMINAL_WORKER_ERR_BYTE_LIMIT: return "byte-limit";
    case MESH_TERMINAL_WORKER_ERR_IO: return "io";
    case MESH_TERMINAL_WORKER_ERR_GEOMETRY: return "geometry";
    case MESH_TERMINAL_WORKER_ERR_UNSUPPORTED: return "unsupported";
    case MESH_TERMINAL_WORKER_ERR_JOB_ASSIGN: return "job-assign";
    }
    return "unknown";
}

/* ── Platform-neutral bookkeeping, shared by every arm below ───────────
 * Pure functions of primitive types, so a Linux-hosted unit test can
 * prove the boundary itself without spawning a shell (or a mingw build)
 * on any host. */

/* Bounds-check requested terminal geometry against the proto's wire
 * limits. Only moved out of the Linux arm (unchanged body, unchanged
 * call sites there) so the Windows arm below can call the same copy
 * instead of a second one drifting from it. Kept non-static: on a
 * platform that is neither Linux nor Windows only the honest-refusal
 * stub arm compiles, which calls neither this nor the budget helper
 * below, and a static function unused in that translation unit is
 * exactly what -Wunused-function (-Werror) exists to catch — the same
 * reason mesh_terminal_worker_budget_would_overrun is not static. */
bool geometry_in_bounds(uint16_t cols, uint16_t rows)
{
    return cols != 0 && cols <= MESH_TERMINAL_MAX_COLS && rows != 0 &&
           rows <= MESH_TERMINAL_MAX_ROWS;
}

/* True when accepting `n` more bytes on top of `used` bytes already
 * charged against `max` would cross the budget. The POSIX arm inlines
 * this exact test in mesh_terminal_worker_input_platform_arm (left
 * byte-for-byte unchanged there, so this copy is genuinely unused in a
 * Linux build's own object — kept non-static, like
 * mesh_terminal_worker_error_string, rather than static+unused, so
 * -Wunused-function never fires there); the Windows arm's input path
 * below calls this one copy, and it is declared in the header so the
 * Linux-hosted unit test can call it directly without a spawned shell or
 * a mingw build. */
bool mesh_terminal_worker_budget_would_overrun(uint64_t used, uint64_t max,
                                               size_t n)
{
    return used > max || n > max - used;
}

enum tw_env_source { TW_ENV_PASS, TW_ENV_WORKDIR, TW_ENV_TERM };

struct tw_env_entry {
    const char *name;
    enum tw_env_source source;
};

static const struct tw_env_entry tw_env_table[] = {
    { "APPDATA", TW_ENV_PASS },        { "ComSpec", TW_ENV_PASS },
    { "HOME", TW_ENV_WORKDIR },        { "LOCALAPPDATA", TW_ENV_PASS },
    { "PATH", TW_ENV_PASS },           { "SystemRoot", TW_ENV_PASS },
    { "TEMP", TW_ENV_PASS },           { "TERM", TW_ENV_TERM },
    { "TMP", TW_ENV_PASS },            { "USERPROFILE", TW_ENV_WORKDIR },
    { "windir", TW_ENV_PASS },
};

const char *mesh_terminal_win_env_name(size_t index)
{
    if (index >= sizeof(tw_env_table) / sizeof(tw_env_table[0]))
        return NULL;
    return tw_env_table[index].name;
}

#if !defined(__linux__) && !defined(_WIN32)

/* Honest refusal on platforms with no Landlock/seccomp cage: never a
 * simulated success, never a degraded shell. */
static struct zcl_result mesh_terminal_worker_spawn_platform_arm(
    const struct mesh_terminal_worker_config *cfg, int64_t now_unix,
    struct mesh_terminal_worker *out)
{
    (void)cfg; (void)now_unix; (void)out;
    return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_UNSUPPORTED,
                   "terminal worker requires the Linux confinement stack");
}

static struct zcl_result mesh_terminal_worker_input_platform_arm(struct mesh_terminal_worker *w,
                                             const uint8_t *bytes, size_t n,
                                             int64_t now_unix)
{
    (void)w; (void)bytes; (void)n; (void)now_unix;
    return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_UNSUPPORTED,
                   "terminal worker requires the Linux confinement stack");
}

static struct zcl_result mesh_terminal_worker_output_platform_arm(struct mesh_terminal_worker *w,
                                              uint8_t *buf, size_t cap,
                                              size_t *out_len,
                                              int64_t now_unix)
{
    (void)w; (void)buf; (void)cap; (void)now_unix;
    if (out_len) *out_len = 0;
    return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_UNSUPPORTED,
                   "terminal worker requires the Linux confinement stack");
}

static struct zcl_result mesh_terminal_worker_resize_platform_arm(struct mesh_terminal_worker *w,
                                              uint16_t cols, uint16_t rows)
{
    (void)w; (void)cols; (void)rows;
    return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_UNSUPPORTED,
                   "terminal worker requires the Linux confinement stack");
}

static bool mesh_terminal_worker_budget_exceeded_platform_arm(struct mesh_terminal_worker *w,
                                          int64_t now_unix)
{
    (void)w; (void)now_unix;
    return true; /* no session could ever be started */
}

static bool mesh_terminal_worker_alive_platform_arm(struct mesh_terminal_worker *w)
{
    (void)w;
    return false;
}

static void mesh_terminal_worker_kill_platform_arm(struct mesh_terminal_worker *w)
{
    (void)w;
}

#elif defined(__linux__) /* __linux__ */

/* Record a natural or forced exit; keeps an enforcement reason that a
 * previous call already set (byte-limit, lifetime, ...) — a named kill
 * must never be overwritten by the generic worker-exited. */
static void tw_record_exit(struct mesh_terminal_worker *w, int status)
{
    if (WIFEXITED(status))
        w->exit_code = WEXITSTATUS(status);
    else if (WIFSIGNALED(status)) {
        w->exit_code = 128 + WTERMSIG(status);
        w->term_signal = WTERMSIG(status);
    }
    w->running = false;
    if (w->close_reason == MESH_TERMINAL_CLOSE_REQUESTED)
        w->close_reason = MESH_TERMINAL_CLOSE_WORKER_EXITED;
}

/* Non-blocking reap; returns true when the shell has exited. */
static bool tw_reap(struct mesh_terminal_worker *w)
{
    if (!w->running)
        return true;
    int status = 0;
    pid_t got = waitpid(w->pid, &status, WNOHANG);
    if (got == w->pid) {
        tw_record_exit(w, status);
        return true;
    }
    if (got < 0 && errno == ECHILD) {
        /* Nobody to wait for: treat as exited (should not happen). */
        w->running = false;
        if (w->close_reason == MESH_TERMINAL_CLOSE_REQUESTED)
            w->close_reason = MESH_TERMINAL_CLOSE_INTERNAL;
        return true;
    }
    return false;
}

/* A signal interruption does not settle child ownership. */
static pid_t tw_wait_settled(pid_t pid, int *status)
{
    pid_t got;
    do {
        got = waitpid(pid, status, 0);
    } while (got < 0 && errno == EINTR);
    return got;
}

/* The granted binary: an explicit argv names it, otherwise the shell. */
static const char *tw_binary(const struct mesh_terminal_worker_config *cfg)
{
    return cfg->argv ? cfg->argv[0] : cfg->shell_path;
}

#define TW_RULES_MAX 6u

/* The cage's filesystem grants: the workdir read/write, the one binary
 * read/execute, and for an explicit argv the standard library directories
 * that exist, read/execute. The seccomp set is unchanged except that W^X
 * becomes "file-backed exec allowed" for an explicit argv. */
static size_t tw_grant_rules(const struct mesh_terminal_worker_config *cfg,
                             struct os_sandbox_path_rule *rules)
{
    static const char *const libs[] = { "/lib", "/lib64", "/usr/lib", "/usr/lib64" };
    rules[0] = (struct os_sandbox_path_rule){ .path = cfg->workdir,
        .allow_read = true, .allow_write = true, .allow_execute = true,
        .allow_create = true };
    rules[1] = (struct os_sandbox_path_rule){ .path = tw_binary(cfg),
        .allow_read = true, .allow_execute = true };
    size_t n = 2;
    for (size_t i = 0; cfg->argv && i < sizeof libs / sizeof libs[0]; i++)
        if (access(libs[i], F_OK) == 0)
            rules[n++] = (struct os_sandbox_path_rule){ .path = libs[i],
                .allow_read = true, .allow_execute = true };
    return n;
}

/* The child half of spawn: never returns; stages failures by name. */
static void tw_child(const struct mesh_terminal_worker_config *cfg,
                     const char *slave_path, int master, int stage_fd)
{
    /* Nothing here may return into the parent's execution state; every
     * path ends in _exit. */
    close(master);

    if (setsid() < 0)
        goto tty_fail;
    int slave = open(slave_path, O_RDWR);
    if (slave < 0)
        goto tty_fail;
    /* The shell wants a controlling terminal for job control. */
    if (ioctl(slave, TIOCSCTTY, NULL) < 0)
        goto tty_fail;
    struct winsize ws = { .ws_col = cfg->cols, .ws_row = cfg->rows };
    if (ioctl(slave, TIOCSWINSZ, &ws) < 0)
        goto tty_fail;
    if (dup2(slave, STDIN_FILENO) < 0 || dup2(slave, STDOUT_FILENO) < 0 ||
        dup2(slave, STDERR_FILENO) < 0)
        goto tty_fail;
    if (slave > STDERR_FILENO)
        close(slave);

    if (chdir(cfg->workdir) < 0) {
        uint8_t stage = TW_STAGE_CHDIR;
        ssize_t reported = write(stage_fd, &stage, 1); /* pre-exit stage report: the parent names this failure from its own EOF read */
        (void)reported;
        _exit(126);
    }

    /* The grant IS the filesystem: the per-terminal workdir (the child's
     * cwd and HOME) plus the one granted binary (and, for an explicit argv,
     * the standard library directories). */
    struct os_sandbox_path_rule rules[TW_RULES_MAX];
    size_t n_rules = tw_grant_rules(cfg, rules);
    struct os_sandbox_profile profile =
        os_sandbox_terminal_worker_profile(rules, n_rules);
    /* An explicit argv may be dynamically linked: let ld.so map libraries
     * (file-backed PROT_EXEC mmap) while anonymous/mprotect exec stays killed. */
    if (cfg->argv)
        profile.seccomp_deny_exec_mmap = OS_SANDBOX_WX_FILE_EXEC;
    if (!os_sandbox_enter(&profile).ok) {
        uint8_t stage = TW_STAGE_CONFINEMENT;
        ssize_t reported = write(stage_fd, &stage, 1); /* pre-exit stage report: the parent names this failure from its own EOF read */
        (void)reported;
        _exit(126);
    }

    /* Deliberately minimal environment: no PATH to leak a search order,
     * HOME/PWD pinned to the grant so no rc file outside it is read. */
    char home[512 + 8], pwd[512 + 8];
    (void)snprintf(home, sizeof home, "HOME=%s", cfg->workdir);
    (void)snprintf(pwd, sizeof pwd, "PWD=%s", cfg->workdir);
    char *const envp[] = { (char *)"TERM=xterm", home, pwd, NULL };
    char *const default_argv[] = { (char *)cfg->shell_path, NULL };
    char *const *exec_argv = cfg->argv ? (char *const *)cfg->argv : default_argv;
    execve(tw_binary(cfg), exec_argv, envp);

    {
        uint8_t stage = TW_STAGE_EXEC;
        ssize_t reported = write(stage_fd, &stage, 1); /* pre-exit stage report: the parent names this failure from its own EOF read */
        (void)reported;
    }
    _exit(127);

tty_fail:
    {
        uint8_t stage = TW_STAGE_TTY;
        ssize_t reported = write(stage_fd, &stage, 1); /* pre-exit stage report: the parent names this failure from its own EOF read */
        (void)reported;
    }
    _exit(126);
}

static struct zcl_result mesh_terminal_worker_spawn_platform_arm(
    const struct mesh_terminal_worker_config *cfg, int64_t now_unix,
    struct mesh_terminal_worker *out)
{
    if (!cfg || !out)
        return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_NULL,
                       "spawn: cfg/out required");
    memset(out, 0, sizeof(*out));
    out->master_fd = -1;
    if (!cfg->shell_path || cfg->shell_path[0] != '/' || !cfg->workdir ||
        cfg->workdir[0] != '/')
        return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_CONFIG,
                       "spawn: shell_path and workdir must be absolute");
    if (!geometry_in_bounds(cfg->cols, cfg->rows))
        return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_CONFIG,
                       "spawn: cols/rows out of proto bounds");
    if (cfg->max_bytes_in == 0 || cfg->max_bytes_out == 0 ||
        cfg->lifetime_seconds == 0)
        return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_CONFIG,
                       "spawn: byte and lifetime budgets must be nonzero");
    if (strlen(cfg->workdir) >= 512)
        return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_CONFIG,
                       "spawn: workdir path too long");

    out->pid = 0;
    out->pgid = 0;
    out->max_bytes_in = cfg->max_bytes_in;
    out->max_bytes_out = cfg->max_bytes_out;
    out->lifetime_seconds = cfg->lifetime_seconds;
    out->idle_seconds = cfg->idle_seconds;
    out->close_reason = MESH_TERMINAL_CLOSE_REQUESTED;

    int master = posix_openpt(O_RDWR | O_NOCTTY | O_CLOEXEC);
    if (master < 0)
        return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_PTY,
                       "posix_openpt failed errno=%d", errno);
    if (grantpt(master) != 0 || unlockpt(master) != 0) {
        close(master);
        return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_PTY,
                       "grantpt/unlockpt failed errno=%d", errno);
    }
    char slave_path[128];
    if (ptsname_r(master, slave_path, sizeof(slave_path)) != 0) {
        close(master);
        return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_PTY,
                       "ptsname failed errno=%d", errno);
    }

    /* The staging pipe tells the parent WHICH named stage failed, and its
     * O_CLOEXEC turns EOF into the exec-succeeded signal. */
    int stage_pipe[2];
    if (pipe2(stage_pipe, O_CLOEXEC) != 0) {
        close(master);
        return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_SPAWN,
                       "stage pipe failed errno=%d", errno);
    }

    pid_t pid = fork();
    if (pid < 0) {
        close(master);
        close(stage_pipe[0]);
        close(stage_pipe[1]);
        return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_SPAWN,
                       "fork failed errno=%d", errno);
    }
    if (pid == 0) {
        close(stage_pipe[0]);
        tw_child(cfg, slave_path, master, stage_pipe[1]);
        _exit(127); /* unreachable */
    }

    /* Parent: read the staging pipe to EOF — zero bytes means the child
     * execed (the pipe closed with the exec), one byte names the stage
     * that failed. */
    close(stage_pipe[1]);
    uint8_t stage = 0;
    for (;;) {
        ssize_t n = read(stage_pipe[0], &stage, 1);
        if (n > 0)
            break;
        if (n == 0) {
            stage = 0;
            break;
        }
        if (errno != EINTR) {
            stage = 0;
            break;
        }
    }
    close(stage_pipe[0]);

    if (stage != 0) {
        int status = 0;
        (void)tw_wait_settled(pid, &status);
        close(master);
        enum mesh_terminal_worker_error code =
            MESH_TERMINAL_WORKER_ERR_SPAWN;
        const char *what = "unknown stage";
        switch (stage) {
        case TW_STAGE_TTY:
            code = MESH_TERMINAL_WORKER_ERR_TTY;
            what = "pty slave/ctty/winsize setup";
            break;
        case TW_STAGE_CHDIR:
            code = MESH_TERMINAL_WORKER_ERR_CONFIG;
            what = "workdir chdir";
            break;
        case TW_STAGE_CONFINEMENT:
            code = MESH_TERMINAL_WORKER_ERR_CONFINEMENT;
            what = "sandbox enter";
            break;
        case TW_STAGE_EXEC:
            code = MESH_TERMINAL_WORKER_ERR_EXEC;
            what = "execve";
            break;
        default:
            break;
        }
        return ZCL_ERR(code, "worker child failed at %s (stage %u)",
                       what, (unsigned)stage);
    }

    /* Best effort: pin the child's group even if setsid lost the race
     * (the child's setsid is authoritative; EACCES just means it already
     * became its own leader). */
    (void)setpgid(pid, pid);

    int flags = fcntl(master, F_GETFL, 0);
    if (flags >= 0)
        (void)fcntl(master, F_SETFL, flags | O_NONBLOCK);

    out->pid = pid;
    out->pgid = pid; /* setsid() in the child makes pgid == pid */
    out->master_fd = master;
    out->started_unix = now_unix;
    out->last_activity_unix = now_unix;
    out->running = true;
    return ZCL_OK;
}

static struct zcl_result mesh_terminal_worker_input_platform_arm(struct mesh_terminal_worker *w,
                                             const uint8_t *bytes, size_t n,
                                             int64_t now_unix)
{
    if (!w)
        return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_NULL,
                       "input: worker required");
    if (n == 0)
        return ZCL_OK;
    if (!bytes)
        return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_NULL,
                       "input: bytes required");
    if (!w->running || w->master_fd < 0)
        return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_NOT_RUNNING,
                       "input: session is over (%s)",
                       mesh_terminal_close_reason_string(w->close_reason));
    if (mesh_terminal_worker_budget_would_overrun(
            w->bytes_in, w->max_bytes_in, n)) {
        mesh_terminal_worker_kill(w);
        w->close_reason = MESH_TERMINAL_CLOSE_BYTE_LIMIT;
        return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_BYTE_LIMIT,
                       "input budget %llu exceeded (%llu used, %zu offered)",
                       (unsigned long long)w->max_bytes_in,
                       (unsigned long long)w->bytes_in, n);
    }

    size_t total = 0;
    while (total < n) {
        ssize_t wr = write(w->master_fd, bytes + total, n - total);
        if (wr > 0) {
            total += (size_t)wr;
            w->bytes_in += (size_t)wr;
            w->last_activity_unix = now_unix;
            continue;
        }
        if (wr < 0 && errno == EINTR)
            continue;
        if (wr < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            /* The shell is not draining: bounded wait, then hand the
             * decision back to the caller — a stalled shell is the
             * lifetime/idle enforcement's kill, not a write error. */
            struct pollfd pfd = { .fd = w->master_fd, .events = POLLOUT };
            int pr = poll(&pfd, 1, 1000);
            if (pr > 0)
                continue;
            return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_IO,
                           "pty input stalled (wrote %zu/%zu)",
                           total, n);
        }
        return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_IO,
                       "pty write failed errno=%d", errno);
    }
    return ZCL_OK;
}

static struct zcl_result mesh_terminal_worker_output_platform_arm(struct mesh_terminal_worker *w,
                                              uint8_t *buf, size_t cap,
                                              size_t *out_len,
                                              int64_t now_unix)
{
    if (out_len)
        *out_len = 0;
    if (!w || !buf || !out_len)
        return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_NULL,
                       "output: worker/buf/out_len required");
    if (cap == 0)
        return ZCL_OK;
    if (w->master_fd < 0)
        return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_NOT_RUNNING,
                       "output: pty closed");

    ssize_t n = read(w->master_fd, buf, cap);
    if (n > 0) {
        *out_len = (size_t)n;
        w->bytes_out += (uint64_t)n;
        w->last_activity_unix = now_unix;
        if (w->bytes_out > w->max_bytes_out) {
            mesh_terminal_worker_kill(w);
            w->close_reason = MESH_TERMINAL_CLOSE_BYTE_LIMIT;
            return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_BYTE_LIMIT,
                           "output budget %llu exceeded (%llu produced)",
                           (unsigned long long)w->max_bytes_out,
                           (unsigned long long)w->bytes_out);
        }
        return ZCL_OK;
    }
    if (n == 0)
        return ZCL_OK; /* EOF: budget_exceeded() reaps the exit */
    if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
        return ZCL_OK;
    if (errno == EIO)
        return ZCL_OK; /* slave gone: same as EOF for the pump loop */
    return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_IO,
                   "pty read failed errno=%d", errno);
}

static struct zcl_result mesh_terminal_worker_resize_platform_arm(struct mesh_terminal_worker *w,
                                              uint16_t cols, uint16_t rows)
{
    if (!w)
        return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_NULL,
                       "resize: worker required");
    if (w->master_fd < 0)
        return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_NOT_RUNNING,
                       "resize: pty closed");
    if (!geometry_in_bounds(cols, rows))
        return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_GEOMETRY,
                       "resize: cols/rows out of proto bounds");
    struct winsize ws = { .ws_col = cols, .ws_row = rows };
    if (ioctl(w->master_fd, TIOCSWINSZ, &ws) != 0)
        return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_IO,
                       "TIOCSWINSZ failed errno=%d", errno);
    /* The kernel raises SIGWINCH on the foreground group; nothing to
     * forward by hand. */
    return ZCL_OK;
}

static bool mesh_terminal_worker_budget_exceeded_platform_arm(struct mesh_terminal_worker *w,
                                          int64_t now_unix)
{
    if (!w)
        return true;
    if (tw_reap(w))
        return true;
    if (w->lifetime_seconds != 0 &&
        now_unix - w->started_unix >= (int64_t)w->lifetime_seconds) {
        w->close_reason = MESH_TERMINAL_CLOSE_LIFETIME_LIMIT;
        mesh_terminal_worker_kill(w);
        return true;
    }
    if (w->idle_seconds != 0 &&
        now_unix - w->last_activity_unix >= (int64_t)w->idle_seconds) {
        w->close_reason = MESH_TERMINAL_CLOSE_IDLE_TIMEOUT;
        mesh_terminal_worker_kill(w);
        return true;
    }
    /* The subtree process budget: escape-proof because a pgid is
     * inherited across fork and survives reparenting, so a fork bomb
     * inside the cage is visible here the moment it exists. */
    if (os_sandbox_process_group_census(w->pgid) >
        MESH_TERMINAL_WORKER_MAX_PROCESSES) {
        w->close_reason = MESH_TERMINAL_CLOSE_SESSION_LOST;
        mesh_terminal_worker_kill(w);
        return true;
    }
    return false;
}

static bool mesh_terminal_worker_alive_platform_arm(struct mesh_terminal_worker *w)
{
    if (!w)
        return false;
    tw_reap(w);
    return w->running;
}

static void mesh_terminal_worker_kill_platform_arm(struct mesh_terminal_worker *w)
{
    if (!w)
        return;
    if (w->master_fd >= 0) {
        close(w->master_fd);
        w->master_fd = -1;
    }
    if (!w->running)
        return;

    /* Whole GROUP first — the session's process subtree dies together,
     * then the shell itself in case the group signal raced. */
    (void)kill(-w->pgid, SIGKILL);
    (void)kill(w->pid, SIGKILL);

    /* Census-verified teardown: bounded loop so a wedged (D-state) task
     * cannot hang the node, with a blocking reap at the end so no zombie
     * leaks even then. */
    int status = 0;
    for (int i = 0; i < 100; i++) {
        pid_t got = waitpid(w->pid, &status, WNOHANG);
        if (got == w->pid) {
            tw_record_exit(w, status);
            return;
        }
        if (os_sandbox_process_group_census(w->pgid) == 0 && got < 0)
            break;
        usleep(2000);
    }
    pid_t got = tw_wait_settled(w->pid, &status);
    if (got == w->pid)
        tw_record_exit(w, status);
    else {
        w->running = false;
        if (w->close_reason == MESH_TERMINAL_CLOSE_REQUESTED)
            w->close_reason = MESH_TERMINAL_CLOSE_INTERNAL;
    }
}

#elif defined(_WIN32) /* _WIN32 */

/* Every path this worker widens is bounded well under MAX_PATH-class
 * limits by spawn's own refusal below; a fixed stack buffer needs no
 * heap and adds no failure mode beyond "too long", which spawn already
 * refuses by name. */
#define MESH_TERMINAL_WIN_PATH_MAX 512u

/* Windows path shape check for the working directory, mirroring the POSIX
 * arm's absolute-path refusal: a drive-letter root ("C:\" or "C:/") or a
 * UNC root ("\\server\share"). The shell image is judged by the stricter
 * mesh_terminal_shell_path_valid. */
static bool win_path_is_absolute(const char *path)
{
    if (!path || !path[0])
        return false;
    if (path[0] == '\\' && path[1] == '\\')
        return true;
    bool letter = (path[0] >= 'A' && path[0] <= 'Z') ||
                  (path[0] >= 'a' && path[0] <= 'z');
    return letter && path[1] == ':' && (path[2] == '\\' || path[2] == '/');
}

static bool win_widen(const char *utf8, wchar_t *out, size_t out_count)
{
    if (!utf8 || !out || out_count == 0)
        return false;
    int n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, utf8, -1, out,
                                (int)out_count);
    return n > 0;
}

/* Append one "KEY=VALUE\0" entry to a CreateProcessW environment block;
 * silently a no-op past `cap` so a caller that sized the block generously
 * (as spawn does) never overruns it. Returns the offset of the NEXT free
 * slot. */
static size_t win_env_put(wchar_t *block, size_t cap, size_t off,
                          const wchar_t *key, const wchar_t *value)
{
    size_t klen = wcslen(key), vlen = wcslen(value);
    if (off + klen + 1u + vlen + 1u > cap)
        return off;
    wmemcpy(block + off, key, klen);
    off += klen;
    block[off++] = L'=';
    wmemcpy(block + off, value, vlen);
    off += vlen;
    block[off++] = L'\0';
    return off;
}

static void tw_win_close(void **handle)
{
    if (!handle)
        return;
    if (*handle && *handle != INVALID_HANDLE_VALUE)
        CloseHandle((HANDLE)*handle);
    *handle = NULL;
}

/* The pipe buffer both directions share: generous headroom over one wire
 * DATA frame's payload (MESH_TERMINAL_DATA_PAYLOAD_MAX, 3072 bytes) so an
 * ordinary mesh_terminal_worker_input() write completes without the shell
 * having to drain first. */
#define MESH_TERMINAL_WIN_PIPE_BYTES 65536ul

/* How long one input write may wait for a shell that has stopped reading
 * its console, mirroring the POSIX arm's poll(POLLOUT, 1000 ms). */
#define MESH_TERMINAL_WIN_WRITE_WAIT_MS 1000u

/* Kill-on-close Job Object holding the shell and everything it starts.
 * Closing the last handle, or TerminateJobObject, ends the whole tree, so a
 * shell that forks and exits leaves nothing behind. The live-process limit
 * is the POSIX arm's census budget. */
static HANDLE tw_win_job_create(void)
{
    HANDLE job = CreateJobObjectW(NULL, NULL);
    if (!job)
        return NULL;
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits;
    memset(&limits, 0, sizeof(limits));
    limits.BasicLimitInformation.LimitFlags =
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
    limits.BasicLimitInformation.ActiveProcessLimit =
        MESH_TERMINAL_WORKER_MAX_PROCESSES;
    if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation,
                                 &limits, sizeof(limits))) {
        CloseHandle(job);
        return NULL;
    }
    return job;
}

/* SDDL granting full access to the current user and nobody else. */
static bool tw_win_owner_sddl(wchar_t *out, size_t cap)
{
    HANDLE token = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
        return false;
    union {
        TOKEN_USER user;
        char raw[256];
    } info;
    DWORD got = 0;
    wchar_t *sid_text = NULL;
    bool ok = GetTokenInformation(token, TokenUser, &info, sizeof(info),
                                  &got) &&
              ConvertSidToStringSidW(info.user.User.Sid, &sid_text) &&
              swprintf(out, cap, L"D:P(A;;GA;;;%ls)", sid_text) > 0;
    if (sid_text)
        LocalFree(sid_text);
    CloseHandle(token);
    return ok;
}

/* A pipe name nobody can predict: process id plus 64 bits from the system
 * generator. */
static bool tw_win_pipe_name(wchar_t *name, size_t cap)
{
    unsigned long random[2];
    if (BCryptGenRandom(NULL, (PUCHAR)random, sizeof(random),
                        BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0)
        return false;
    return swprintf(name, cap, L"\\\\.\\pipe\\z23-terminal-%lu-%08lx%08lx",
                    GetCurrentProcessId(), random[0], random[1]) > 0;
}

/* The shell's input pipe: a named pipe opened overlapped on OUR end, so a
 * write can be abandoned after a bounded wait (an anonymous pipe cannot be
 * opened overlapped). The shell's end is a plain synchronous read handle.
 * The pipe has an unpredictable name, one instance, no remote client, and a
 * DACL that admits only the current user. */
static bool tw_win_input_pipe(HANDLE *write_end, HANDLE *read_end)
{
    wchar_t name[96], sddl[160];
    SECURITY_ATTRIBUTES sa = { .nLength = sizeof(sa), .bInheritHandle = FALSE };
    if (!tw_win_pipe_name(name, sizeof(name) / sizeof(name[0])) ||
        !tw_win_owner_sddl(sddl, sizeof(sddl) / sizeof(sddl[0])) ||
        !ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl, SDDL_REVISION_1, &sa.lpSecurityDescriptor, NULL))
        return false;
    HANDLE server = CreateNamedPipeW(
        name,
        PIPE_ACCESS_OUTBOUND | FILE_FLAG_OVERLAPPED |
            FILE_FLAG_FIRST_PIPE_INSTANCE,
        PIPE_TYPE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS, 1,
        (DWORD)MESH_TERMINAL_WIN_PIPE_BYTES, 0, 0, &sa);
    LocalFree(sa.lpSecurityDescriptor);
    if (server == INVALID_HANDLE_VALUE)
        return false;
    HANDLE client = CreateFileW(name, GENERIC_READ, 0, NULL, OPEN_EXISTING,
                                FILE_ATTRIBUTE_NORMAL, NULL);
    if (client == INVALID_HANDLE_VALUE) {
        CloseHandle(server);
        return false;
    }
    *write_end = server;
    *read_end = client;
    return true;
}

/* Our two retained pipe ends plus the pseudoconsole they feed. */
struct tw_win_pty {
    HPCON console;
    HANDLE input_write;
    HANDLE output_read;
};

static void tw_win_pty_close(struct tw_win_pty *pty)
{
    /* Our pipe ends first: the pseudoconsole host may otherwise block on a
     * reader that will never come. */
    if (pty->input_write)
        CloseHandle(pty->input_write);
    if (pty->output_read)
        CloseHandle(pty->output_read);
    if (pty->console)
        ClosePseudoConsole(pty->console);
    memset(pty, 0, sizeof(*pty));
}

static struct zcl_result tw_win_pty_open(uint16_t cols, uint16_t rows,
                                         struct tw_win_pty *pty)
{
    memset(pty, 0, sizeof(*pty));
    HANDLE conin_read = NULL, conout_write = NULL;
    if (!tw_win_input_pipe(&pty->input_write, &conin_read))
        return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_PTY,
                       "input pipe failed error=%lu", GetLastError());
    if (!CreatePipe(&pty->output_read, &conout_write, NULL,
                    (DWORD)MESH_TERMINAL_WIN_PIPE_BYTES)) {
        DWORD error = GetLastError();
        CloseHandle(conin_read);
        tw_win_pty_close(pty);
        return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_PTY,
                       "CreatePipe(output) failed error=%lu", error);
    }
    COORD size = { .X = (SHORT)cols, .Y = (SHORT)rows };
    HRESULT hr =
        CreatePseudoConsole(size, conin_read, conout_write, 0, &pty->console);
    /* ConPTY duplicates whichever ends it needs; our copies of the ends it
     * now owns are always closed, success or failure. */
    CloseHandle(conin_read);
    CloseHandle(conout_write);
    if (FAILED(hr)) {
        pty->console = NULL;
        tw_win_pty_close(pty);
        return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_PTY,
                       "CreatePseudoConsole failed hr=0x%lx",
                       (unsigned long)hr);
    }
    return ZCL_OK;
}

/* The shell's environment, drawn only from tw_env_table: nothing else of
 * the node's environment crosses, so no credential or token variable can
 * leak. Variables the node lacks are omitted. The block is sorted because
 * the table is. Caller frees. */
#define MESH_TERMINAL_WIN_ENV_CHARS 65536u
#define MESH_TERMINAL_WIN_ENV_VALUE_CHARS 32768u

static bool tw_win_env_value(const struct tw_env_entry *e,
                             const wchar_t *workdir, wchar_t *scratch,
                             const wchar_t **value)
{
    wchar_t wname[32];
    if (e->source == TW_ENV_WORKDIR)
        *value = workdir;
    else if (e->source == TW_ENV_TERM)
        *value = L"xterm";
    else {
        DWORD n;
        if (!win_widen(e->name, wname, 32))
            return false;
        n = GetEnvironmentVariableW(wname, scratch,
                                    MESH_TERMINAL_WIN_ENV_VALUE_CHARS);
        if (n == 0 || n >= MESH_TERMINAL_WIN_ENV_VALUE_CHARS)
            return false;
        *value = scratch;
    }
    return true;
}

static wchar_t *tw_win_env_build(const wchar_t *workdir)
{
    wchar_t *block = zcl_malloc(MESH_TERMINAL_WIN_ENV_CHARS * sizeof(wchar_t),
                                "mesh_terminal_worker_win_env");
    wchar_t *scratch = zcl_malloc(
        MESH_TERMINAL_WIN_ENV_VALUE_CHARS * sizeof(wchar_t),
        "mesh_terminal_worker_win_env_value");
    size_t off = 0;
    for (size_t i = 0; block && scratch &&
                       i < sizeof(tw_env_table) / sizeof(tw_env_table[0]);
         i++) {
        wchar_t wkey[32];
        const wchar_t *value = NULL;
        if (tw_win_env_value(&tw_env_table[i], workdir, scratch, &value) &&
            win_widen(tw_env_table[i].name, wkey, 32))
            off = win_env_put(block, MESH_TERMINAL_WIN_ENV_CHARS - 1u, off,
                              wkey, value);
    }
    free(scratch);
    if (block && off > 0)
        block[off] = L'\0'; /* final NUL terminates the block */
    else {
        free(block);
        block = NULL;
    }
    return block;
}

/* Start the shell SUSPENDED on the pseudoconsole so the caller can place it
 * in the job before it runs a single instruction. */
static struct zcl_result tw_win_create_shell(HPCON console,
                                             const wchar_t *wshell,
                                             const wchar_t *wworkdir,
                                             PROCESS_INFORMATION *pi)
{
    SIZE_T attr_size = 0;
    (void)InitializeProcThreadAttributeList(NULL, 1, 0, &attr_size);
    void *attr_buf = attr_size ? zcl_malloc(attr_size, "mesh_terminal_worker_win_attr_list") : NULL;
    LPPROC_THREAD_ATTRIBUTE_LIST attr_list =
        (LPPROC_THREAD_ATTRIBUTE_LIST)attr_buf;
    if (!attr_buf)
        return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_SPAWN,
                       "attribute list allocation failed");
    if (!InitializeProcThreadAttributeList(attr_list, 1, 0, &attr_size) ||
        !UpdateProcThreadAttribute(attr_list, 0,
                                   PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE,
                                   console, sizeof(console), NULL, NULL)) {
        DWORD error = GetLastError();
        free(attr_buf);
        return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_SPAWN,
                       "attribute list setup failed error=%lu", error);
    }

    wchar_t *env = tw_win_env_build(wworkdir);
    if (!env) {
        DeleteProcThreadAttributeList(attr_list);
        free(attr_buf);
        return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_SPAWN,
                       "environment block allocation failed");
    }
    wchar_t cmdline[MESH_TERMINAL_WIN_PATH_MAX + 2u];
    size_t shell_len = wcslen(wshell);
    cmdline[0] = L'"';
    wmemcpy(cmdline + 1, wshell, shell_len);
    cmdline[1 + shell_len] = L'"';
    cmdline[2 + shell_len] = L'\0';

    STARTUPINFOEXW startup;
    memset(&startup, 0, sizeof(startup));
    startup.StartupInfo.cb = sizeof(startup);
    startup.lpAttributeList = attr_list;
    memset(pi, 0, sizeof(*pi));
    DWORD flags = EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT |
                  CREATE_SUSPENDED;
    BOOL started = CreateProcessW(wshell, cmdline, NULL, NULL, FALSE, flags,
                                  env, wworkdir, &startup.StartupInfo, pi);
    DWORD error = started ? 0 : GetLastError();
    DeleteProcThreadAttributeList(attr_list);
    free(attr_buf);
    free(env);
    if (!started)
        return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_EXEC,
                       "CreateProcessW failed error=%lu", error);
    return ZCL_OK;
}

/* Put the suspended shell in the job, then let it run. A shell that cannot
 * be contained never runs: it is terminated and the spawn is refused by
 * name. */
static struct zcl_result tw_win_contain_and_resume(HANDLE job,
                                                   PROCESS_INFORMATION *pi)
{
    if (!AssignProcessToJobObject(job, pi->hProcess)) {
        DWORD error = GetLastError();
        (void)TerminateProcess(pi->hProcess, 137);
        return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_JOB_ASSIGN,
                       "job-object-assign: the shell could not join its job "
                       "(the node may run inside a job that forbids "
                       "nesting; start it outside a restrictive job) "
                       "error=%lu", error);
    }
    if (ResumeThread(pi->hThread) == (DWORD)-1) {
        DWORD error = GetLastError();
        (void)TerminateJobObject(job, 137);
        return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_SPAWN,
                       "ResumeThread failed error=%lu", error);
    }
    return ZCL_OK;
}

static struct zcl_result tw_win_spawn_config_check(
    const struct mesh_terminal_worker_config *cfg)
{
    if (!cfg->shell_path ||
        !mesh_terminal_shell_path_valid(MESH_TERMINAL_PLATFORM_WINDOWS,
                                        cfg->shell_path) ||
        !cfg->workdir || !win_path_is_absolute(cfg->workdir))
        return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_CONFIG,
                       "spawn: shell_path and workdir must be absolute");
    if (!geometry_in_bounds(cfg->cols, cfg->rows))
        return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_CONFIG,
                       "spawn: cols/rows out of proto bounds");
    if (cfg->max_bytes_in == 0 || cfg->max_bytes_out == 0 ||
        cfg->lifetime_seconds == 0)
        return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_CONFIG,
                       "spawn: byte and lifetime budgets must be nonzero");
    if (strlen(cfg->workdir) >= MESH_TERMINAL_WIN_PATH_MAX)
        return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_CONFIG,
                       "spawn: workdir path too long");
    return ZCL_OK;
}

static struct zcl_result mesh_terminal_worker_spawn_platform_arm(
    const struct mesh_terminal_worker_config *cfg, int64_t now_unix,
    struct mesh_terminal_worker *out)
{
    if (!cfg || !out)
        return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_NULL,
                       "spawn: cfg/out required");
    memset(out, 0, sizeof(*out));
    out->master_fd = -1;
    struct zcl_result checked = tw_win_spawn_config_check(cfg);
    if (!checked.ok)
        return checked;
    wchar_t wshell[MESH_TERMINAL_WIN_PATH_MAX];
    wchar_t wworkdir[MESH_TERMINAL_WIN_PATH_MAX];
    if (!win_widen(cfg->shell_path, wshell, MESH_TERMINAL_WIN_PATH_MAX) ||
        !win_widen(cfg->workdir, wworkdir, MESH_TERMINAL_WIN_PATH_MAX))
        return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_CONFIG,
                       "spawn: shell_path/workdir is not valid UTF-8");

    HANDLE job = tw_win_job_create();
    if (!job)
        return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_CONFINEMENT,
                       "job object setup failed error=%lu", GetLastError());
    struct tw_win_pty pty;
    struct zcl_result r = tw_win_pty_open(cfg->cols, cfg->rows, &pty);
    PROCESS_INFORMATION pi;
    if (r.ok)
        r = tw_win_create_shell(pty.console, wshell, wworkdir, &pi);
    if (r.ok) {
        r = tw_win_contain_and_resume(job, &pi);
        CloseHandle(pi.hThread);
        if (!r.ok)
            CloseHandle(pi.hProcess);
    }
    if (!r.ok) {
        if (pty.console || pty.input_write || pty.output_read)
            tw_win_pty_close(&pty);
        CloseHandle(job);
        return r;
    }

    out->pid = (pid_t)pi.dwProcessId;
    out->pgid = out->pid; /* the job is the group; see kill */
    out->win_pc = pty.console;
    out->win_job = job;
    out->win_process = pi.hProcess;
    out->win_input_write = pty.input_write;
    out->win_output_read = pty.output_read;
    out->max_bytes_in = cfg->max_bytes_in;
    out->max_bytes_out = cfg->max_bytes_out;
    out->lifetime_seconds = cfg->lifetime_seconds;
    out->idle_seconds = cfg->idle_seconds;
    out->close_reason = MESH_TERMINAL_CLOSE_REQUESTED;
    out->started_unix = now_unix;
    out->last_activity_unix = now_unix;
    out->running = true;
    return ZCL_OK;
}

enum tw_win_write_outcome {
    TW_WIN_WRITE_OK,
    TW_WIN_WRITE_STALLED,
    TW_WIN_WRITE_FAILED
};

/* One overlapped write bounded by MESH_TERMINAL_WIN_WRITE_WAIT_MS. A write
 * still pending at the deadline is cancelled and reports STALLED together
 * with however many bytes the pipe did take; the caller decides, and the
 * session's lifetime/idle enforcement owns any kill. */
static enum tw_win_write_outcome tw_win_write_bounded(
    HANDLE pipe, const uint8_t *bytes, size_t n, DWORD *wrote, DWORD *error)
{
    *wrote = 0;
    *error = 0;
    OVERLAPPED op;
    memset(&op, 0, sizeof(op));
    op.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!op.hEvent) {
        *error = GetLastError();
        return TW_WIN_WRITE_FAILED;
    }
    enum tw_win_write_outcome outcome = TW_WIN_WRITE_OK;
    if (!WriteFile(pipe, bytes, (DWORD)n, NULL, &op) &&
        GetLastError() != ERROR_IO_PENDING) {
        *error = GetLastError();
        outcome = TW_WIN_WRITE_FAILED;
    } else {
        if (WaitForSingleObject(op.hEvent, MESH_TERMINAL_WIN_WRITE_WAIT_MS) !=
            WAIT_OBJECT_0) {
            (void)CancelIoEx(pipe, &op);
            outcome = TW_WIN_WRITE_STALLED;
        }
        if (!GetOverlappedResult(pipe, &op, wrote, TRUE) &&
            outcome == TW_WIN_WRITE_OK) {
            *error = GetLastError();
            outcome = TW_WIN_WRITE_FAILED;
        }
    }
    CloseHandle(op.hEvent);
    return outcome;
}

static struct zcl_result mesh_terminal_worker_input_platform_arm(struct mesh_terminal_worker *w,
                                             const uint8_t *bytes, size_t n,
                                             int64_t now_unix)
{
    if (!w || (!bytes && n != 0))
        return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_NULL,
                       "input: worker/bytes required");
    if (n == 0)
        return ZCL_OK;
    if (!w->running || !w->win_input_write)
        return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_NOT_RUNNING,
                       "input: session is over (%s)",
                       mesh_terminal_close_reason_string(w->close_reason));
    if (mesh_terminal_worker_budget_would_overrun(w->bytes_in,
                                                  w->max_bytes_in, n)) {
        mesh_terminal_worker_kill(w);
        w->close_reason = MESH_TERMINAL_CLOSE_BYTE_LIMIT;
        return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_BYTE_LIMIT,
                       "input budget %llu exceeded (%llu used, %zu offered)",
                       (unsigned long long)w->max_bytes_in,
                       (unsigned long long)w->bytes_in, n);
    }

    /* The POSIX arm's bounded-wait shape: a shell that stops reading its
     * console is an IO refusal after MESH_TERMINAL_WIN_WRITE_WAIT_MS per
     * write, never an unbounded block of the caller's tick. */
    size_t total = 0;
    while (total < n) {
        DWORD wrote = 0, error = 0;
        enum tw_win_write_outcome outcome = tw_win_write_bounded(
            (HANDLE)w->win_input_write, bytes + total, n - total, &wrote,
            &error);
        total += wrote;
        w->bytes_in += wrote;
        if (wrote != 0)
            w->last_activity_unix = now_unix;
        if (outcome == TW_WIN_WRITE_FAILED)
            return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_IO,
                           "pty input failed error=%lu (wrote %zu/%zu)",
                           error, total, n);
        if (outcome == TW_WIN_WRITE_STALLED || wrote == 0)
            return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_IO,
                           "pty input stalled (wrote %zu/%zu)", total, n);
    }
    return ZCL_OK;
}

static struct zcl_result mesh_terminal_worker_output_platform_arm(struct mesh_terminal_worker *w,
                                              uint8_t *buf, size_t cap,
                                              size_t *out_len,
                                              int64_t now_unix)
{
    if (out_len)
        *out_len = 0;
    if (!w || !buf || !out_len)
        return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_NULL,
                       "output: worker/buf/out_len required");
    if (cap == 0)
        return ZCL_OK;
    if (!w->win_output_read)
        return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_NOT_RUNNING,
                       "output: pty closed");

    /* PeekNamedPipe first, then read only what is already buffered: the
     * same "check, then take what is there, never wait for more" shape
     * as the POSIX arm's O_NONBLOCK read, and the natural fit for a
     * synchronous 100ms tick that polls every live session in a plain
     * loop. Overlapped ReadFile is not an option on an anonymous pipe
     * (see the input function above) and would in any case need
     * per-worker OVERLAPPED/event state the tick has no slot for;
     * PeekNamedPipe needs none. */
    DWORD available = 0;
    if (!PeekNamedPipe((HANDLE)w->win_output_read, NULL, 0, NULL, &available,
                       NULL)) {
        DWORD err = GetLastError();
        if (err == ERROR_BROKEN_PIPE || err == ERROR_HANDLE_EOF)
            return ZCL_OK; /* far end gone: budget_exceeded() reaps the exit */
        return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_IO,
                       "PeekNamedPipe failed error=%lu", err);
    }
    if (available == 0)
        return ZCL_OK;
    DWORD want = (DWORD)cap;
    if (available < want)
        want = available;
    DWORD got = 0;
    if (!ReadFile((HANDLE)w->win_output_read, buf, want, &got, NULL)) {
        DWORD err = GetLastError();
        if (err == ERROR_BROKEN_PIPE || err == ERROR_HANDLE_EOF)
            return ZCL_OK;
        return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_IO,
                       "pty read failed error=%lu", err);
    }
    *out_len = (size_t)got;
    w->bytes_out += (uint64_t)got;
    w->last_activity_unix = now_unix;
    if (w->bytes_out > w->max_bytes_out) {
        mesh_terminal_worker_kill(w);
        w->close_reason = MESH_TERMINAL_CLOSE_BYTE_LIMIT;
        return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_BYTE_LIMIT,
                       "output budget %llu exceeded (%llu produced)",
                       (unsigned long long)w->max_bytes_out,
                       (unsigned long long)w->bytes_out);
    }
    return ZCL_OK;
}

static struct zcl_result mesh_terminal_worker_resize_platform_arm(struct mesh_terminal_worker *w,
                                              uint16_t cols, uint16_t rows)
{
    if (!w)
        return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_NULL,
                       "resize: worker required");
    if (!w->win_pc)
        return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_NOT_RUNNING,
                       "resize: pty closed");
    if (!geometry_in_bounds(cols, rows))
        return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_GEOMETRY,
                       "resize: cols/rows out of proto bounds");
    COORD size = { .X = (SHORT)cols, .Y = (SHORT)rows };
    HRESULT hr = ResizePseudoConsole((HPCON)w->win_pc, size);
    if (FAILED(hr))
        return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_IO,
                       "ResizePseudoConsole failed hr=0x%lx",
                       (unsigned long)hr);
    /* The console host raises its own resize signal to the child; nothing
     * to forward by hand, mirroring the POSIX arm's SIGWINCH comment. */
    return ZCL_OK;
}

static bool mesh_terminal_worker_budget_exceeded_platform_arm(struct mesh_terminal_worker *w,
                                          int64_t now_unix)
{
    if (!w)
        return true;
    if (!w->running)
        return true;
    DWORD code = 0;
    if (w->win_process &&
        GetExitCodeProcess((HANDLE)w->win_process, &code) &&
        code != STILL_ACTIVE) {
        w->exit_code = (int)code;
        w->running = false;
        if (w->close_reason == MESH_TERMINAL_CLOSE_REQUESTED)
            w->close_reason = MESH_TERMINAL_CLOSE_WORKER_EXITED;
        return true;
    }
    if (w->lifetime_seconds != 0 &&
        now_unix - w->started_unix >= (int64_t)w->lifetime_seconds) {
        w->close_reason = MESH_TERMINAL_CLOSE_LIFETIME_LIMIT;
        mesh_terminal_worker_kill(w);
        return true;
    }
    if (w->idle_seconds != 0 &&
        now_unix - w->last_activity_unix >= (int64_t)w->idle_seconds) {
        w->close_reason = MESH_TERMINAL_CLOSE_IDLE_TIMEOUT;
        mesh_terminal_worker_kill(w);
        return true;
    }
    /* The subtree size is bounded by the job's live-process limit rather
     * than a census: a spawn past it fails inside the job. */
    return false;
}

static bool mesh_terminal_worker_alive_platform_arm(struct mesh_terminal_worker *w)
{
    if (!w || !w->running)
        return false;
    DWORD code = 0;
    if (w->win_process && GetExitCodeProcess((HANDLE)w->win_process, &code) &&
        code != STILL_ACTIVE) {
        w->exit_code = (int)code;
        w->running = false;
        if (w->close_reason == MESH_TERMINAL_CLOSE_REQUESTED)
            w->close_reason = MESH_TERMINAL_CLOSE_WORKER_EXITED;
        return false;
    }
    return w->running;
}

/* Release the console side. The job has already ended the shell, and our
 * pipe ends are closed before the pseudoconsole so its host cannot block
 * on a reader that will never come. */
static void tw_win_release_console(struct mesh_terminal_worker *w)
{
    tw_win_close(&w->win_input_write);
    tw_win_close(&w->win_output_read);
    if (w->win_pc) {
        ClosePseudoConsole((HPCON)w->win_pc);
        w->win_pc = NULL;
    }
}

/* Wait (bounded) for the terminated shell and record its exit code. */
static void tw_win_reap(struct mesh_terminal_worker *w)
{
    DWORD code = 0;
    DWORD waited = WaitForSingleObject((HANDLE)w->win_process, 2000);
    if (waited == WAIT_OBJECT_0 &&
        GetExitCodeProcess((HANDLE)w->win_process, &code))
        w->exit_code = (int)code;
    else
        w->exit_code = 137;
}

/* Ends the whole process tree: TerminateJobObject takes the shell and every
 * descendant, and closing the kill-on-close job afterwards takes anything
 * that raced it. Safe to call again and after the shell exited on its own,
 * when it still removes the descendants that outlived it. */
static void mesh_terminal_worker_kill_platform_arm(struct mesh_terminal_worker *w)
{
    if (!w)
        return;
    /* 128 + SIGKILL(9), matching the POSIX arm's forced-kill exit code
     * convention so a caller reading exit_code cannot tell the two arms
     * apart. */
    if (w->win_job)
        (void)TerminateJobObject((HANDLE)w->win_job, 137);
    else if (w->running && w->win_process)
        (void)TerminateProcess((HANDLE)w->win_process, 137);
    if (w->running && w->win_process)
        tw_win_reap(w);
    tw_win_release_console(w);
    tw_win_close(&w->win_job);
    tw_win_close(&w->win_process);
    if (!w->running)
        return;
    w->running = false;
    if (w->close_reason == MESH_TERMINAL_CLOSE_REQUESTED)
        w->close_reason = MESH_TERMINAL_CLOSE_INTERNAL;
}

#endif /* __linux__ / _WIN32 */

/* An explicit argv is bounded and its program is an absolute path; the
 * program is the ONE binary the cage grants (plus the standard library
 * directories). Windows has no argv grant. NULL when acceptable, otherwise
 * the reason. */
static const char *tw_argv_refusal(const struct mesh_terminal_worker_config *cfg,
                                  int *code)
{
    if (!cfg->argv)
        return NULL;
#if defined(_WIN32)
    (void)code;
    return "spawn: an explicit argv is POSIX-only";
#else
    size_t n = 0;
    while (n <= MESH_TERMINAL_WORKER_ARGV_MAX && cfg->argv[n])
        n++;
    if (n == 0 || n > MESH_TERMINAL_WORKER_ARGV_MAX)
        return "spawn: argv must hold 1..16 strings";
    if (!mesh_terminal_shell_path_valid(MESH_TERMINAL_PLATFORM_POSIX, cfg->argv[0]))
        return "spawn: argv[0] must be an absolute path";
    if (access(cfg->argv[0], X_OK) != 0) {
        *code = MESH_TERMINAL_WORKER_ERR_EXEC;
        return "spawn: argv[0] is not an executable file";
    }
    return NULL;
#endif
}

struct zcl_result mesh_terminal_worker_spawn(
    const struct mesh_terminal_worker_config *cfg, int64_t now_unix,
    struct mesh_terminal_worker *out)
{
    int bad_code = MESH_TERMINAL_WORKER_ERR_CONFIG;
    const char *bad = cfg ? tw_argv_refusal(cfg, &bad_code) : NULL;
    if (bad)
        return ZCL_ERR(bad_code, "%s", bad);
    return mesh_terminal_worker_spawn_platform_arm(cfg, now_unix, out);
}

struct zcl_result mesh_terminal_worker_input(struct mesh_terminal_worker *w,
                                             const uint8_t *bytes, size_t n,
                                             int64_t now_unix)
{
    return mesh_terminal_worker_input_platform_arm(w, bytes, n, now_unix);
}

struct zcl_result mesh_terminal_worker_output(struct mesh_terminal_worker *w,
                                              uint8_t *buf, size_t cap,
                                              size_t *out_len,
                                              int64_t now_unix)
{
    return mesh_terminal_worker_output_platform_arm(
        w, buf, cap, out_len, now_unix);
}

struct zcl_result mesh_terminal_worker_resize(struct mesh_terminal_worker *w,
                                              uint16_t cols, uint16_t rows)
{
    return mesh_terminal_worker_resize_platform_arm(w, cols, rows);
}

bool mesh_terminal_worker_budget_exceeded(struct mesh_terminal_worker *w,
                                          int64_t now_unix)
{
    return mesh_terminal_worker_budget_exceeded_platform_arm(w, now_unix);
}

bool mesh_terminal_worker_alive(struct mesh_terminal_worker *w)
{
    return mesh_terminal_worker_alive_platform_arm(w);
}

void mesh_terminal_worker_kill(struct mesh_terminal_worker *w)
{
    mesh_terminal_worker_kill_platform_arm(w);
}
