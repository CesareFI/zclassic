/* Copyright 2026 Rhett Creighton - Apache-2.0
 * Purpose: confined half of the exact resident launch (handshake, fd sweep, exec confirmation) */
/* Purpose: the confined-launch pieces of resident_launch.c.
 *
 * Split out of resident_launch.c (which keeps acceptance, spawn orchestration,
 * IPC frames and cancellation): the CLOEXEC status-pipe handshake and its
 * deadline, the bounded kill-and-reap, the confined child's descriptor sweep
 * and sandbox arming, and the parent's exec confirmation (the traced child
 * stops at its exec; /proc/<pid>/exe must match the pinned image).
 */
#if !defined(_WIN32) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif
#include "resident_launch_confined.h"

#if !defined(_WIN32)
#include "base/hex.h"
#include "base/safe_alloc.h"
#include "platform/os_sandbox.h"
#include "platform/positioned_file.h"
#include "sha3/sha3.h"
#include "platform/time_compat.h"
#include "util/log_macros.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#if defined(__linux__)
/* Only the Linux re-proof and spawn paths report through this helper. */
static void rlc_fail(char *error, size_t error_size, const char *fmt, ...)
{
    if (!error || !error_size) return;
    va_list args;
    va_start(args, fmt);
    (void)vsnprintf(error, error_size, fmt, args);
    va_end(args);
}
#endif

bool resident_sha3_positioned(const struct platform_positioned_file *file,
                              unsigned char out[32])
{
    struct sha3_256_ctx ctx;
    uint64_t offset = 0;
    unsigned char *chunk = zcl_malloc(RESIDENT_HASH_CHUNK, "resident-hash");
    if (!chunk) return false;
    sha3_256_init(&ctx);
    for (;;) {
        int64_t got = platform_positioned_file_read(file, chunk,
                                                    RESIDENT_HASH_CHUNK, offset);
        if (got < 0) {
            free(chunk);
            return false;
        }
        if (got == 0) break;
        sha3_256_write(&ctx, chunk, (size_t)got);
        offset += (uint64_t)got;
    }
    free(chunk);
    sha3_256_finalize(&ctx, out);
    return true;
}
/* Status byte a confined child writes when the OS sandbox could not be armed.
 * Real errno values fit in 7 bits, so it cannot collide with an exec errno. */
#define RESIDENT_SANDBOX_STAGE_BYTE 0xFEu
/* Marker a confined child writes once its sandbox is armed, immediately
 * before the exec. Marker then EOF means ARMED_EXEC_UNCERTAIN: the CLOEXEC
 * pipe also closes when the child dies, so EOF cannot prove the exec. */
#define RESIDENT_ARMED_MARKER 0xA5u
/* Stage byte for a child that could not ask to be traced (PTRACE_TRACEME
 * refused, e.g. under a ptrace_scope policy): the exec can then never be
 * confirmed, which is NOT a sandbox-arm failure. */
#define RESIDENT_TRACE_STAGE_BYTE 0xFDu

/* Monotonic ns. On a clock error this returns UINT64_MAX ("infinitely late"),
 * so every deadline test reads as EXPIRED: a failed clock can only shorten a
 * wait, never extend one. Deadlines are never computed from it unchecked
 * (resident_default_deadline refuses). */
uint64_t resident_mono_ns(void)
{
    int64_t us = platform_time_monotonic_us();
    return us > 0 ? (uint64_t)us * UINT64_C(1000) : UINT64_MAX;
}

bool resident_default_deadline(uint64_t *out)
{
    uint64_t now = resident_mono_ns();
    if (now == UINT64_MAX) return false;
    *out = now + (uint64_t)RESIDENT_CONFINED_SPAWN_DEFAULT_MS * UINT64_C(1000000);
    return true;
}

/* Poll budget for an absolute deadline: -1 = block forever (no deadline). */
static int resident_poll_budget_ms(uint64_t deadline_ns)
{
    if (!deadline_ns) return -1;
    uint64_t now = resident_mono_ns();
    if (now >= deadline_ns) return 0;
    uint64_t ms = (deadline_ns - now + UINT64_C(999999)) / UINT64_C(1000000);
    return ms > INT_MAX ? INT_MAX : (int)ms;
}

enum resident_byte_kind { RB_BYTE, RB_EOF, RB_TIMEOUT, RB_ERROR };
struct resident_byte {
    enum resident_byte_kind kind;
    unsigned char value;
    int err;
};

/* Wait for readability; true = readable, false = *out holds timeout/error. */
static bool resident_wait_readable(int fd, uint64_t deadline_ns,
                                   struct resident_byte *out)
{
    for (;;) {
        struct pollfd waiter = {.fd = fd, .events = POLLIN};
        int ready = poll(&waiter, 1, resident_poll_budget_ms(deadline_ns));
        if (ready < 0 && errno == EINTR) continue;
        if (ready < 0) {
            *out = (struct resident_byte){RB_ERROR, 0, errno};
            return false;
        }
        if (ready == 0) {
            if (deadline_ns && resident_mono_ns() < deadline_ns) continue;
            out->kind = RB_TIMEOUT;
            return false;
        }
        if (waiter.revents & POLLNVAL) {
            *out = (struct resident_byte){RB_ERROR, 0, EBADF};
            return false;
        }
        return true;
    }
}

/* One status byte under an absolute deadline. EOF, timeout and a read error
 * are three different answers; none collapses into "got a byte". */
static struct resident_byte resident_read_byte_until(int fd, uint64_t deadline_ns)
{
    struct resident_byte result = {RB_ERROR, 0, 0};
    for (;;) {
        if (!resident_wait_readable(fd, deadline_ns, &result)) return result;
        ssize_t got = read(fd, &result.value, 1);
        if (got == 1) { result.kind = RB_BYTE; return result; }
        if (got == 0) { result.kind = RB_EOF; return result; }
        if (errno == EINTR || errno == EAGAIN) continue;
        result.kind = RB_ERROR;
        result.err = errno;
        return result;
    }
}

/* Unconfined launches keep their original semantics exactly: a blocking
 * read, EOF = the exec happened, and ANY byte or read error is an exec
 * failure (errno byte, or 0 = ENOEXEC). */
static struct resident_handshake_result resident_handshake_unconfined(int fd)
{
    unsigned char code = 0;
    ssize_t got;
    do {
        got = read(fd, &code, 1);
    } while (got < 0 && errno == EINTR);
    if (got == 0)
        return (struct resident_handshake_result){RESIDENT_EXEC_NONE, 0, true};
    return (struct resident_handshake_result){
        RESIDENT_EXEC_FAILED, got == 1 ? (int)code : 0, false};
}

static struct resident_handshake_result resident_handshake_stop(
    const struct resident_byte *byte, bool after_marker)
{
    if (byte->kind == RB_TIMEOUT)
        return (struct resident_handshake_result){RESIDENT_EXEC_TIMEOUT, 0, false};
    if (byte->kind == RB_ERROR)
        return (struct resident_handshake_result){
            RESIDENT_EXEC_STATUS_ERROR, byte->err, false};
    if (byte->kind == RB_EOF && after_marker)
        return (struct resident_handshake_result){
            RESIDENT_EXEC_ARMED_UNCERTAIN, 0, true};
    return (struct resident_handshake_result){RESIDENT_EXEC_CHILD_DIED, 0, false};
}

struct resident_handshake_result resident_handshake_interpret(
    bool confined, int fd, uint64_t deadline_ns)
{
    if (!confined) return resident_handshake_unconfined(fd);
    struct resident_byte first = resident_read_byte_until(fd, deadline_ns);
    if (first.kind != RB_BYTE) return resident_handshake_stop(&first, false);
    if (first.value == RESIDENT_SANDBOX_STAGE_BYTE)
        return (struct resident_handshake_result){
            RESIDENT_EXEC_SANDBOX_FAILED, 0, false};
    if (first.value == RESIDENT_TRACE_STAGE_BYTE)
        return (struct resident_handshake_result){
            RESIDENT_EXEC_CONFIRM_UNAVAILABLE, 0, false};
    if (first.value != RESIDENT_ARMED_MARKER)
        return (struct resident_handshake_result){
            RESIDENT_EXEC_FAILED, first.value, false};
    struct resident_byte second = resident_read_byte_until(fd, deadline_ns);
    if (second.kind == RB_BYTE)
        return (struct resident_handshake_result){
            RESIDENT_EXEC_FAILED, second.value, false};
    return resident_handshake_stop(&second, true);
}

bool resident_launch_kill_reap(uint64_t pid64, uint32_t grace_ms, int *status)
{
    pid_t pid = (pid_t)pid64;
    if (pid <= 1) LOG_FAIL("resident.launch", "refusing to signal pid %lld", (long long)pid);
    (void)kill(-pid, SIGKILL); /* the child is its own group leader after setsid */
    (void)kill(pid, SIGKILL);
    uint64_t began = resident_mono_ns();
    /* clock error: began == UINT64_MAX, end wraps to a tiny value, so the loop
     * gives up after one reap attempt instead of waiting */
    uint64_t end = began + (uint64_t)grace_ms * UINT64_C(1000000);
    for (;;) {
        int st = 0;
        pid_t got = waitpid(pid, &st, WNOHANG);
        if (got == pid) {
            if (status) *status = st;
            return true;
        }
        if (got < 0 && errno == ECHILD) return true; /* already reaped */
        if (got < 0 && errno != EINTR)
            LOG_FAIL("resident.launch", "reap of pid %lld failed: %s", (long long)pid, strerror(errno));
        if (resident_mono_ns() >= end)
            LOG_FAIL("resident.launch", "pid %lld not reaped within %u ms of SIGKILL", (long long)pid, (unsigned)grace_ms);
        struct timespec nap = {0, 1000000};
        nanosleep(&nap, NULL);
    }
}

#if defined(__linux__)
#if !defined(__APPLE__)
/* True only when the mapped image matches the pinned one: identity (volume,
 * inode, size) AND the content hash both agree. Any read or hash failure is
 * "not proved" (false), never a pass. */
static bool resident_reproof_matches(const struct resident_launch *launch,
                                     const struct platform_positioned_file *mapped,
                                     const struct platform_positioned_file_snapshot *snap)
{
    bool identity_ok =
        snap->volume == launch->pinned_snapshot.volume &&
        snap->file_low == launch->pinned_snapshot.file_low &&
        snap->file_high == launch->pinned_snapshot.file_high &&
        snap->size == launch->pinned_snapshot.size;
    unsigned char digest[32];
    char hex[RESIDENT_LAUNCH_DIGEST_HEX + 1] = {0};
    if (!identity_ok) return false;
#ifdef ZCL_TESTING
    if (launch->debug_fail_reproof_hash) return false; /* test seam: hash failure */
#endif
    if (!resident_sha3_positioned(mapped, digest)) return false;
    zcl_hex_encode(digest, sizeof(digest), hex);
    return strcmp(hex, launch->accepted.image_sha3_hex) == 0;
}

#endif
/* Second, independent mapped-image proof where the platform offers one.
 * Upgrades the receipt's proof name on success; refuses (killing the
 * child) only when a READABLE /proc/<pid>/exe triple disagrees — a
 * vanished child merely skips this proof (fexecve already bound the
 * inode). Linux-only; other POSIX hosts have no /proc analogue. */
#if defined(__linux__)
static bool resident_reproof_linux(pid_t pid, struct resident_launch *launch,
                                 struct resident_receipt *receipt,
                                 char *error, size_t error_size)
{
    char exe_path[64];
    (void)snprintf(exe_path, sizeof(exe_path), "/proc/%llu/exe",
                   (unsigned long long)pid);
    struct platform_positioned_file mapped;
    struct platform_positioned_file_snapshot mapped_snapshot;
    platform_positioned_file_init(&mapped);
    /* /proc/<pid>/exe is a kernel magic link the no-follow open refuses with
     * ELOOP; this fixed compiled-in location uses the open_resolved contract. */
    if (!platform_positioned_file_open_resolved(&mapped, exe_path)) return true;
    bool proved =
        platform_positioned_file_snapshot(&mapped, &mapped_snapshot);
    if (!proved) {
        platform_positioned_file_close(&mapped);
        return true; /* child gone: skip, the first proof holds */
    }
    /* Compare inode IDENTITY plus a content re-hash, never timestamps
     * (multigrain-ctime kernels make them indistinguishable); the executing
     * inode is write-locked, so this is exactly what the kernel mapped. */
    bool matches = resident_reproof_matches(launch, &mapped, &mapped_snapshot);
    platform_positioned_file_close(&mapped);
    if (!matches) {
        (void)kill(pid, SIGKILL);
        int status = 0;
        while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
        close((int)launch->ipc_native);
        launch->ipc_native = (uintptr_t)-1;
        launch->spawned = false;
        errno = ESTALE;
        rlc_fail(error, error_size,
                      "resident launch: mapped image identity could not be"
                      " re-proved; child refused");
        return false;
    }
    (void)snprintf(receipt->mapped_proof, sizeof(receipt->mapped_proof),
                   "proc_exe_triple");
    if (launch->exec_state == RESIDENT_EXEC_ARMED_UNCERTAIN)
        launch->exec_state = RESIDENT_EXEC_CONFIRMED;
    return true;
}
#endif

bool resident_reproof_mapped(pid_t pid, struct resident_launch *launch,
                             struct resident_receipt *receipt,
                             char *error, size_t error_size)
{
#if defined(__linux__)
    return resident_reproof_linux(pid, launch, receipt, error, error_size);
#else
    (void)pid; (void)launch; (void)receipt; (void)error; (void)error_size;
    return true; /* no second proof on this platform; the first holds */
#endif
}

#if defined(__linux__)
/* Descriptors a confined child keeps through the close sweep: stdio, the IPC
 * slot, the pinned exec fd, the status pipe and every pre-opened grant fd
 * (Landlock still needs those until the sandbox is armed). */
#define RESIDENT_KEEP_MAX 48u
#ifndef __NR_close_range
#define __NR_close_range 436
#endif

static size_t resident_keep_collect(const struct resident_child_plan *plan,
                                    int keep[RESIDENT_KEEP_MAX])
{
    size_t n = 0;
    keep[n++] = 0;
    keep[n++] = 1;
    keep[n++] = 2;
    keep[n++] = RESIDENT_LAUNCH_CHILD_FD;
    for (size_t i = 0; i < plan->n_extra; ++i) {
        if (n >= RESIDENT_KEEP_MAX) _exit(126);
        keep[n++] = RESIDENT_LAUNCH_CHILD_FD + 1 + (int)i;
    }
    keep[n++] = plan->pinned_fd;
    keep[n++] = plan->status_write;
    for (size_t i = 0; plan->profile && i < plan->profile->n_fs_rules; ++i) {
        const struct os_sandbox_path_rule *rule = &plan->profile->fs_rules[i];
        if (!rule->has_fd) continue;
        if (n >= RESIDENT_KEEP_MAX) _exit(126); /* more grants than the sweep can name */
        keep[n++] = rule->fd;
    }
    for (size_t i = 1; i < n; ++i) { /* insertion sort, no allocation */
        int value = keep[i];
        size_t j = i;
        for (; j > 0 && keep[j - 1] > value; --j) keep[j] = keep[j - 1];
        keep[j] = value;
    }
    return n;
}

/* Close [lo, hi] with close_range(2); false when the kernel refuses it. */
static bool resident_close_span(unsigned lo, unsigned hi)
{
    if (lo > hi) return true;
    return syscall(__NR_close_range, lo, hi, 0u) == 0;
}

struct resident_dirent64 {
    uint64_t ino;
    int64_t off;
    unsigned short reclen;
    unsigned char type;
    char name[];
};

static bool resident_fd_kept(const int *keep, size_t n, int fd)
{
    for (size_t i = 0; i < n; ++i)
        if (keep[i] == fd) return true;
    return false;
}

/* Close the descriptor a /proc/self/fd entry names unless it is kept or is the
 * directory handle itself. True when a descriptor was closed. */
static bool resident_close_entry(const struct resident_dirent64 *d, int dir,
                                 const int *keep, size_t n)
{
    if (d->name[0] < '0' || d->name[0] > '9') return false; /* . and .. */
    int fd = atoi(d->name);
    if (fd == dir || resident_fd_kept(keep, n, fd)) return false;
    return close(fd) == 0;
}

/* Close every descriptor of THIS process not in keep, found by listing the
 * proc fd directory (no allocation, no libc stream). Not bounded by
 * RLIMIT_NOFILE, which a limit reduction can leave below an open descriptor.
 * Repeats until a pass closes nothing; false = the directory is unusable. */
static bool resident_close_listed(const int *keep, size_t n)
{
    int dir = open("/proc/self/fd", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dir < 0) return false;
    bool closed_any = true, usable = true;
    for (int pass = 0; closed_any && pass < 64; ++pass) {
        char buf[2048];
        long got;
        closed_any = false;
        if (lseek(dir, 0, SEEK_SET) < 0) { usable = false; break; }
        while ((got = syscall(SYS_getdents64, dir, buf, sizeof(buf))) > 0) {
            for (long off = 0; off < got;) {
                const struct resident_dirent64 *d = (const void *)(buf + off);
                off += d->reclen;
                if (resident_close_entry(d, dir, keep, n)) closed_any = true;
            }
        }
        if (got < 0) { usable = false; break; }
    }
    close(dir);
    return usable && !closed_any;
}

/* Landlock does not revoke an already-open descriptor, so a confined child
 * must not inherit any the caller did not name. close_range first; if it is
 * unavailable, enumerate the open descriptors instead. When neither works the
 * launch is refused (sandbox-stage byte, exit) rather than run with leaks. */
void resident_child_close_inherited(const struct resident_child_plan *plan)
{
    int keep[RESIDENT_KEEP_MAX];
    size_t n = resident_keep_collect(plan, keep);
    unsigned next = 0;
    bool swept = true;
#ifdef ZCL_TESTING
    if (plan->no_close_range) swept = false; /* test seam: close_range unavailable */
#endif
    for (size_t i = 0; swept && i < n; ++i) {
        if (keep[i] < 0 || (unsigned)keep[i] < next) continue;
        if ((unsigned)keep[i] > next)
            swept = resident_close_span(next, (unsigned)keep[i] - 1u);
        next = (unsigned)keep[i] + 1u;
    }
    swept = swept && resident_close_span(next, UINT_MAX);
    if (swept || resident_close_listed(keep, n)) return;
    unsigned char stage = RESIDENT_SANDBOX_STAGE_BYTE;
    ssize_t told = write(plan->status_write, &stage, 1);
    (void)told;
    _exit(127);
}


static bool resident_traceme_refused(const struct resident_child_plan *plan)
{
#ifdef ZCL_TESTING
    if (plan->fail_traceme) return true; /* test seam: force the refusal */
#else
    (void)plan;
#endif
    return ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0;
}

/* Arm the OS sandbox AFTER the descriptor sweep and BEFORE the exec. The
 * profile was built before fork. Reports a refusal on the status pipe, then
 * the armed marker; the exec (or its errno) follows. */
void resident_child_arm(const struct resident_child_plan *plan)
{
    /* The exec is confirmed by the parent: the child asks to be traced, so the
     * kernel stops it with SIGTRAP right after a successful exec and before the
     * app runs a single instruction. Must precede seccomp (ptrace is denied
     * afterwards). */
    if (resident_traceme_refused(plan)) {
        unsigned char stage = RESIDENT_TRACE_STAGE_BYTE;
        ssize_t told = write(plan->status_write, &stage, 1);
        (void)told;
        _exit(127);
    }
    struct zcl_result armed = os_sandbox_enter(plan->profile);
    if (!zcl_result_is_ok(armed)) {
        unsigned char stage = RESIDENT_SANDBOX_STAGE_BYTE;
        ssize_t told = write(plan->status_write, &stage, 1); /* names the sandbox refusal to the parent */
        (void)told;
        _exit(127);
    }
#ifdef ZCL_TESTING
    if (plan->stall_ms) {
        struct timespec nap = {.tv_sec = plan->stall_ms / 1000u,
                               .tv_nsec = (long)(plan->stall_ms % 1000u) * 1000000L};
        while (nanosleep(&nap, &nap) < 0 && errno == EINTR) {}
    }
#endif
    unsigned char marker = RESIDENT_ARMED_MARKER;
    ssize_t told = write(plan->status_write, &marker, 1); /* armed; exec follows */
    if (told != 1) _exit(126);
#ifdef ZCL_TESTING
    if (plan->die_after_marker) _exit(125);
#endif
}

/* Outcome of waiting for the child's stop right after its exec. */
enum resident_stop { RS_EXEC_STOP, RS_GONE, RS_TIMEOUT, RS_OTHER };

/* The traced confined child stops with SIGTRAP at the end of a successful
 * exec. Exit or death before that stop proves the exec did NOT happen. */
static enum resident_stop resident_wait_exec_stop(pid_t pid, uint64_t deadline_ns)
{
    for (;;) {
        int st = 0;
        pid_t got = waitpid(pid, &st, WNOHANG);
        if (got == pid) {
            if (!WIFSTOPPED(st)) return RS_GONE;
            return WSTOPSIG(st) == SIGTRAP ? RS_EXEC_STOP : RS_OTHER;
        }
        if (got < 0 && errno != EINTR) return RS_GONE;
        if (resident_mono_ns() >= deadline_ns) return RS_TIMEOUT; /* clock error = expired */
        struct timespec nap = {0, 200000};
        nanosleep(&nap, NULL);
    }
}

/* Confined launches report success only after CONFIRMED: the child stopped at
 * its exec and /proc/<pid>/exe re-proved the pinned image. Anything else is a
 * typed ARMED_EXEC_UNCERTAIN refusal with the child killed and reaped. */
bool resident_confirm_exec(struct resident_launch *launch, pid_t pid,
                                  uint64_t deadline_ns, struct resident_receipt *receipt,
                                  char *error, size_t error_size)
{
    enum resident_stop stop = resident_wait_exec_stop(pid, deadline_ns);
    if (stop == RS_EXEC_STOP) {
#ifdef ZCL_TESTING
        if (launch->debug_reproof_delay_ms) { /* test seam: a slow reproof */
            struct timespec slow = {.tv_sec = launch->debug_reproof_delay_ms / 1000u,
                .tv_nsec = (long)(launch->debug_reproof_delay_ms % 1000u) * 1000000L};
            while (nanosleep(&slow, &slow) < 0 && errno == EINTR) {}
        }
#endif
        if (!resident_reproof_mapped(pid, launch, receipt, error, error_size))
            return false; /* identity mismatch: already killed and reaped */
        if (launch->exec_state == RESIDENT_EXEC_CONFIRMED) {
            /* The reproof spends budget: the child may start only inside it. */
            if (resident_mono_ns() >= deadline_ns) stop = RS_TIMEOUT;
            else if (ptrace(PTRACE_DETACH, pid, NULL, NULL) == 0) return true;
        }
    }
    bool reaped = stop == RS_GONE ||
        resident_launch_kill_reap((uint64_t)pid, RESIDENT_REAP_GRACE_MS, NULL);
    close((int)launch->ipc_native);
    launch->ipc_native = (uintptr_t)-1;
    launch->spawned = false;
    launch->exec_state = stop == RS_TIMEOUT ? RESIDENT_EXEC_TIMEOUT : RESIDENT_EXEC_ARMED_UNCERTAIN;
    errno = stop == RS_TIMEOUT ? ETIMEDOUT : EPROTO;
    rlc_fail(error, error_size,
                  "resident launch: EXEC_UNCERTAIN: pid %lld was armed but its exec"
                  " was never confirmed; killed%s, no exit status is the app's",
                  (long long)pid, reaped ? " and reaped" : "; REAP_FAILED");
    return false;
}
#endif /* __linux__ */
#endif /* !__APPLE__ */
#endif /* !_WIN32 */
