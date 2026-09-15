/* Copyright 2026 Rhett Creighton - Apache-2.0
 * Purpose: launcher half of the exact resident launch (Linux arm + shared codec) */
/* Purpose: exact resident process launch bound to an accepted artifact.
 *
 * The launcher half of the app-run seam. See resident_launch.h for the
 * contract. This file carries the shared pieces (acceptance re-proof, IPC
 * frame codec, cancellation, stale-result rejection) and the Linux spawn
 * arm (fork + fexecve on the pinned descriptor). The Darwin arm lives in
 * resident_launch_mac.c: it suspends the child before its first instruction
 * and proves the mapped image's CodeDirectory hash equals the hash the
 * kernel returns for the pinned descriptor, so a pathname swap between
 * check and spawn surfaces as a mismatch and the child dies unexecuted.
 * Windows refuses by name, exactly like os_binary_slots: reconstructing a
 * pathname and exec'ing it is a TOCTOU hole, and a guarantee-shaped launch
 * that cannot be proven is worse than a loud refusal.
 */
#if !defined(_WIN32) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif
#include "platform/resident_launch.h"

#include "platform/os_proc.h"
#include "platform/positioned_file.h"
#include "platform/process_compat.h"
#include "platform/rng.h"
#include "base/hex.h"
#include "base/safe_alloc.h"
#include "sha3/sha3.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#if !defined(_WIN32)
#include <poll.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

#define RESIDENT_FRAME_MAGIC_RESULT "z23-res-run-v1"
#define RESIDENT_FRAME_MAGIC_STOP "z23-res-stop-v1"
#define RESIDENT_HASH_CHUNK 65536u

#if defined(_WIN32)
#define RESIDENT_WIN_REFUSAL                                                  \
    "resident exact launch is disabled on Windows pending a descriptor-bound" \
    " execution primitive: a pathname exec here would be a TOCTOU hole, not"  \
    " an exact launch"
#endif

#if defined(__APPLE__)
#include "resident_launch_internal.h"
#endif

static void resident_fail(char *error, size_t error_size, const char *fmt,
                          ...) {
    if (!error || !error_size) return;
    va_list args;
    va_start(args, fmt);
    (void)vsnprintf(error, error_size, fmt, args);
    va_end(args);
}

void resident_launch_init(struct resident_launch *launch)
{
    if (!launch) return;
    memset(launch, 0, sizeof(*launch));
    launch->pinned_native = (uintptr_t)-1;
    launch->ipc_native = (uintptr_t)-1;
}

/* Exact-count stream I/O over the IPC socket. Returns false on EOF/error;
 * EINTR is retried, a partial transfer never counts as done. */
#if !defined(_WIN32)
static bool resident_io_exact(int fd, void *data, size_t size, bool write,
                              bool *peer_closed)
{
    unsigned char *p = data;
    size_t done = 0;
    if (peer_closed) *peer_closed = false;
    while (done < size) {
        ssize_t part;
        if (write) {
            part = send(fd, p + done, size - done, MSG_NOSIGNAL);
        } else {
            part = recv(fd, p + done, size - done, 0);
        }
        if (part > 0) {
            done += (size_t)part;
            continue;
        }
        if (part == 0) {
            if (peer_closed) *peer_closed = true;
            return false;
        }
        if (errno == EINTR) continue;
        return false;
    }
    return true;
}

static bool resident_sha3_positioned(const struct platform_positioned_file *file,
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
#endif /* !defined(_WIN32) */

#if !defined(_WIN32)
/* Opens the image, proves it is an executable regular file, hashes it
 * through the handle with a stability re-check, and refuses unless the
 * live bytes and positioned-file identity equal the accepted record.
 * Returns the pinned handle the caller owns (resident_launch_close), or
 * NULL with errno and `error` set. */
static struct platform_positioned_file *resident_open_accepted(
    const char *image_path, const struct resident_launch_accepted *accepted,
    struct platform_positioned_file_snapshot *snapshot_out,
    char *error, size_t error_size)
{
    struct platform_positioned_file *file =
        zcl_malloc(sizeof(*file), "resident-launch-image");
    if (!file) {
        resident_fail(error, error_size,
                      "resident launch: image state allocation failed");
        return NULL;
    }
    platform_positioned_file_init(file);
    if (!platform_positioned_file_open(file, image_path)) {
        int saved = errno;
        free(file);
        errno = saved;
        resident_fail(error, error_size,
                      "resident launch: cannot open accepted image at %s: %s",
                      image_path, strerror(saved));
        return NULL;
    }
    struct platform_positioned_file_snapshot before, after;
    if (!platform_positioned_file_is_executable(file) ||
        !platform_positioned_file_snapshot(file, &before)) {
        platform_positioned_file_close(file);
        free(file);
        errno = ENOEXEC;
        resident_fail(error, error_size,
                      "resident launch: %s is not a regular executable image",
                      image_path);
        return NULL;
    }
    /* Hash through the HANDLE, then prove the handle still names the same
     * bytes: a writer that swapped the content mid-read surfaces as a
     * snapshot change and the launch refuses (the dev_activation idiom). */
    unsigned char digest[32];
    if (!resident_sha3_positioned(file, digest) ||
        !platform_positioned_file_snapshot(file, &after) ||
        !platform_positioned_file_snapshot_equal(&before, &after)) {
        platform_positioned_file_close(file);
        free(file);
        errno = ESTALE;
        resident_fail(error, error_size,
                      "resident launch: image changed while being proved at %s",
                      image_path);
        return NULL;
    }
    char digest_hex[RESIDENT_LAUNCH_DIGEST_HEX + 1] = {0};
    zcl_hex_encode(digest, sizeof(digest), digest_hex);
    if (before.volume != accepted->image_volume ||
        before.file_low != accepted->image_low ||
        before.file_high != accepted->image_high ||
        before.size != accepted->image_size ||
        strcmp(digest_hex, accepted->image_sha3_hex) != 0) {
        platform_positioned_file_close(file);
        free(file);
        errno = ESTALE;
        resident_fail(error, error_size,
                      "resident launch: live image does not match the accepted"
                      " record (digest or positioned-file identity differs)");
        return NULL;
    }
    *snapshot_out = before;
    return file;
}
#endif

bool resident_launch_prepare(struct resident_launch *launch,
                             const char *image_path,
                             const struct resident_launch_accepted *accepted,
                             char *error, size_t error_size)
{
#if defined(_WIN32)
    (void)launch; (void)image_path; (void)accepted;
    errno = ENOTSUP;
    resident_fail(error, error_size, "%s", RESIDENT_WIN_REFUSAL);
    return false;
#else
    if (!launch || !image_path || !image_path[0] || !accepted ||
        !accepted->image_sha3_hex[0]) {
        errno = EINVAL;
        resident_fail(error, error_size, "resident launch: invalid argument");
        return false;
    }
    struct platform_positioned_file_snapshot snapshot;
    struct platform_positioned_file *file = resident_open_accepted(
        image_path, accepted, &snapshot, error, error_size);
    if (!file) return false;
    unsigned char nonce_bytes[32];
    if (!rng_fill(nonce_bytes, sizeof(nonce_bytes))) {
        platform_positioned_file_close(file);
        free(file);
        errno = EIO;
        resident_fail(error, error_size,
                      "resident launch: launch nonce generation failed");
        return false;
    }
    resident_launch_init(launch);
    launch->pinned_native = (uintptr_t)file;
    launch->pinned_snapshot = snapshot;
    launch->accepted = *accepted;
    zcl_hex_encode(nonce_bytes, sizeof(nonce_bytes), launch->nonce);
    return true;
#endif
}

#if !defined(_WIN32)
/* Second, independent mapped-image proof where the platform offers one.
 * Upgrades the receipt's proof name on success; refuses (killing the
 * child) only when a READABLE /proc/<pid>/exe triple disagrees — a
 * vanished child merely skips this proof (fexecve already bound the
 * inode). Linux-only; other POSIX hosts have no /proc analogue. */
#if defined(__linux__)
static bool resident_reproof_mapped(pid_t pid, struct resident_launch *launch,
                                    struct resident_receipt *receipt,
                                    char *error, size_t error_size)
{
    char exe_path[64];
    (void)snprintf(exe_path, sizeof(exe_path), "/proc/%llu/exe",
                   (unsigned long long)pid);
    struct platform_positioned_file mapped;
    struct platform_positioned_file_snapshot mapped_snapshot;
    platform_positioned_file_init(&mapped);
    /* LINUX PORT: /proc/<pid>/exe is a kernel-managed magic link, so the
     * no-follow content-path open always refuses it with ELOOP and the
     * re-proof silently never ran (the receipt could never carry
     * "proc_exe_triple" on Linux). This is a fixed, compiled-in kernel
     * location — the open_resolved trusted-location contract applies. */
    if (!platform_positioned_file_open_resolved(&mapped, exe_path)) return true;
    bool proved =
        platform_positioned_file_snapshot(&mapped, &mapped_snapshot);
    if (!proved) {
        platform_positioned_file_close(&mapped);
        return true; /* child gone: skip, the first proof holds */
    }
    /* Compare inode IDENTITY fields, never timestamps: multigrain-ctime
     * kernels (>=6.6) make same-jiffy metadata indistinguishable, and a
     * same-UID writer can bump ctime post-exec with chmod/unlink without
     * ever touching the mapped bytes (the kernel refuses those writes
     * with ETXTBSY). The binding proof is identity plus a content digest
     * re-hash — exactly what the kernel mapped, since the executing inode
     * is write-locked. */
    bool identity_differs =
        mapped_snapshot.volume != launch->pinned_snapshot.volume ||
        mapped_snapshot.file_low != launch->pinned_snapshot.file_low ||
        mapped_snapshot.file_high != launch->pinned_snapshot.file_high ||
        mapped_snapshot.size != launch->pinned_snapshot.size;
    unsigned char mapped_digest[32];
    char mapped_hex[RESIDENT_LAUNCH_DIGEST_HEX + 1] = {0};
    bool hashed = !identity_differs &&
        resident_sha3_positioned(&mapped, mapped_digest);
    platform_positioned_file_close(&mapped);
    if (hashed)
        zcl_hex_encode(mapped_digest, sizeof(mapped_digest), mapped_hex);
    if (identity_differs ||
        (hashed && strcmp(mapped_hex, launch->accepted.image_sha3_hex) != 0)) {
        (void)kill(pid, SIGKILL);
        int status = 0;
        while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
        close((int)launch->ipc_native);
        launch->ipc_native = (uintptr_t)-1;
        launch->spawned = false;
        errno = ESTALE;
        resident_fail(error, error_size,
                      "resident launch: mapped image identity could not be"
                      " re-proved; child refused");
        return false;
    }
    (void)snprintf(receipt->mapped_proof, sizeof(receipt->mapped_proof),
                   "proc_exe_triple");
    return true;
}
#else
static bool resident_reproof_mapped(pid_t pid, struct resident_launch *launch,
                                    struct resident_receipt *receipt,
                                    char *error, size_t error_size)
{
    (void)pid; (void)launch; (void)receipt; (void)error; (void)error_size;
    return true; /* no second proof on this platform; the first holds */
}
#endif

/* The launch channel pair: the IPC socket (parent keeps one end, the
 * child inherits the other at the fixed slot) and the exec-status pipe
 * whose write end is CLOEXEC (a successful exec closes it; a failed exec
 * writes its errno first). */
static bool resident_spawn_channels(int ipc[2], int status_pipe[2],
                                    char *error, size_t error_size)
{
    ipc[0] = ipc[1] = -1;
    status_pipe[0] = status_pipe[1] = -1;
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, ipc) != 0 ||
        pipe2(status_pipe, O_CLOEXEC) != 0) {
        int saved = errno;
        if (ipc[0] >= 0) close(ipc[0]);
        if (ipc[1] >= 0) close(ipc[1]);
        if (status_pipe[0] >= 0) close(status_pipe[0]);
        if (status_pipe[1] >= 0) close(status_pipe[1]);
        errno = saved;
        resident_fail(error, error_size,
                      "resident launch: IPC channel creation failed: %s",
                      strerror(saved));
        return false;
    }
    return true;
}

/* The child's side of a Linux spawn: new session, exactly one inherited
 * descriptor (the IPC socket at RESIDENT_LAUNCH_CHILD_FD), then exec the
 * pinned inode. Only ever returns on exec failure; the errno byte on the
 * status pipe is the parent's synchronous exec outcome. */
static void resident_child_exec(int pinned_fd, int ipc_child,
                                char *const argv[], char *const envp[],
                                int status_write)
{
    if (setsid() < 0) _exit(126);
    /* The pinned image fd must not sit on the fixed IPC slot: dup2 of the
     * socket onto it would clobber the very inode we are about to exec. */
    if (pinned_fd == RESIDENT_LAUNCH_CHILD_FD) {
        int moved = fcntl(pinned_fd, F_DUPFD_CLOEXEC,
                          RESIDENT_LAUNCH_CHILD_FD + 1);
        if (moved < 0) _exit(126);
        pinned_fd = moved;
    }
    if (ipc_child != RESIDENT_LAUNCH_CHILD_FD) {
        if (dup2(ipc_child, RESIDENT_LAUNCH_CHILD_FD) < 0) _exit(126);
        close(ipc_child);
    } else {
        (void)fcntl(ipc_child, F_SETFD, 0);
    }
    if (platform_execve_fd(pinned_fd, argv, envp) < 0) {
        int why = errno ? errno : ENOEXEC;
        unsigned char code = (unsigned char)(why & 0xff);
        (void)write(status_write, &code, 1);
        _exit(127);
    }
    _exit(126); /* unreachable: execve returns only on failure */
}

static bool resident_spawn_linux(struct resident_launch *launch,
                                 char *const argv[], char *const envp[],
                                 struct resident_receipt *receipt,
                                 char *error, size_t error_size)
{
    struct platform_positioned_file *file =
        (struct platform_positioned_file *)(void *)launch->pinned_native;
    int pinned_fd = (int)platform_positioned_file_native_fd(file);
    if (pinned_fd < 0) {
        errno = EINVAL;
        resident_fail(error, error_size,
                      "resident launch: pinned image descriptor is gone");
        return false;
    }
    /* Re-prove the pinned BYTES before fork. The positioned-file triple
     * alone cannot do this on multigrain-timestamp kernels (>=6.6): a
     * same-jiffy, same-size content swap between prepare and spawn leaves
     * mtime/ctime indistinguishable, so a metadata check can wave the
     * wrong bytes through. The content digest has no such granularity,
     * and refusing here means no process ever exists for a swapped image
     * (stronger than a post-spawn kill). Metadata-only changes — rename,
     * unlink, chmod — do not alter the pinned bytes and do not refuse:
     * fexecve still maps exactly the accepted inode. */
    unsigned char preflight_digest[32];
    char preflight_hex[RESIDENT_LAUNCH_DIGEST_HEX + 1] = {0};
    if (!resident_sha3_positioned(file, preflight_digest)) {
        errno = EIO;
        resident_fail(error, error_size,
                      "resident launch: pinned image re-read failed");
        return false;
    }
    zcl_hex_encode(preflight_digest, sizeof(preflight_digest), preflight_hex);
    if (strcmp(preflight_hex, launch->accepted.image_sha3_hex) != 0) {
        errno = ESTALE;
        resident_fail(error, error_size,
                      "resident launch: image bytes changed after prepare;"
                      " refusing before fork");
        return false;
    }
    int ipc[2] = {-1, -1}, status_pipe[2] = {-1, -1};
    if (!resident_spawn_channels(ipc, status_pipe, error, error_size))
        return false;
    pid_t pid = fork();
    if (pid < 0) {
        int saved = errno;
        close(ipc[0]); close(ipc[1]);
        close(status_pipe[0]); close(status_pipe[1]);
        errno = saved;
        resident_fail(error, error_size, "resident launch: fork failed: %s",
                      strerror(saved));
        return false;
    }
    if (pid == 0) {
        /* status_pipe's write end is CLOEXEC: a successful exec closes it
         * and the parent reads EOF; a failed exec writes the errno first. */
        resident_child_exec(pinned_fd, ipc[1], argv, envp, status_pipe[1]);
        _exit(126);
    }
    close(ipc[1]);
    close(status_pipe[1]);
    unsigned char exec_errno = 0;
    ssize_t got;
    do {
        got = read(status_pipe[0], &exec_errno, 1);
    } while (got < 0 && errno == EINTR);
    close(status_pipe[0]);
    if (got != 0) {
        int status = 0;
        while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
        close(ipc[0]);
        errno = exec_errno ? exec_errno : ENOEXEC;
        resident_fail(error, error_size,
                      "resident launch: exec of the pinned image failed: %s",
                      strerror(errno));
        return false;
    }
    launch->ipc_native = (uintptr_t)ipc[0];
    launch->spawned = true;
    launch->pid = (uint64_t)pid;
    if (!os_proc_pid_start_token(launch->pid, &launch->start_token)) {
        launch->start_token = 0;
    }
    /* fexecve maps the exact inode this launcher pinned, so the exec itself
     * is the mapped-image proof. Where the child lives long enough, the
     * /proc/<pid>/exe triple is re-derived as an independent second proof;
     * a readable-but-different triple is refused loudly, a vanished child
     * merely skips the second proof (the first still holds). */
    (void)snprintf(receipt->mapped_proof, sizeof(receipt->mapped_proof),
                   "fexecve_inode");
    return resident_reproof_mapped(pid, launch, receipt, error, error_size);
}
#endif /* !defined(_WIN32) */

bool resident_launch_spawn(struct resident_launch *launch,
                           char *const argv[], char *const envp[],
                           struct resident_receipt *receipt,
                           char *error, size_t error_size)
{
#if defined(_WIN32)
    (void)launch; (void)argv; (void)envp; (void)receipt;
    errno = ENOTSUP;
    resident_fail(error, error_size, "%s", RESIDENT_WIN_REFUSAL);
    return false;
#else
    if (!launch || launch->pinned_native == (uintptr_t)-1 ||
        launch->spawned || !argv || !argv[0] || !receipt) {
        errno = EINVAL;
        resident_fail(error, error_size,
                      "resident launch: spawn needs a prepared, unspawned"
                      " launch with an argv");
        return false;
    }
    memset(receipt, 0, sizeof(*receipt));
#if defined(__APPLE__)
    if (!resident_spawn_darwin(launch, argv, envp, receipt,
                               error, error_size))
        return false;
#else
    if (!resident_spawn_linux(launch, argv, envp, receipt,
                              error, error_size))
        return false;
#endif
    (void)snprintf(receipt->nonce, sizeof(receipt->nonce), "%s",
                   launch->nonce);
    (void)snprintf(receipt->image_sha3_hex, sizeof(receipt->image_sha3_hex),
                   "%s", launch->accepted.image_sha3_hex);
    receipt->pid = launch->pid;
    receipt->start_token = launch->start_token;
    receipt->image_volume = launch->accepted.image_volume;
    receipt->image_low = launch->accepted.image_low;
    receipt->image_high = launch->accepted.image_high;
    receipt->image_size = launch->accepted.image_size;
    return true;
#endif
}

bool resident_launch_cancel(struct resident_launch *launch,
                            uint32_t timeout_ms,
                            char *error, size_t error_size)
{
#if defined(_WIN32)
    (void)launch; (void)timeout_ms;
    errno = ENOTSUP;
    resident_fail(error, error_size, "%s", RESIDENT_WIN_REFUSAL);
    return false;
#else
    if (!launch || !launch->spawned) {
        errno = EINVAL;
        resident_fail(error, error_size,
                      "resident launch: cancel needs a spawned launch");
        return false;
    }
    pid_t pid = (pid_t)launch->pid;
    /* Ask first over the IPC channel (a cooperative app stops on the stop
     * frame), then apply the deadline, then kill the process group the
     * child's setsid created. */
    if (launch->ipc_native != (uintptr_t)-1) {
        struct {
            char magic[16];
            char nonce[RESIDENT_LAUNCH_NONCE_HEX + 1u];
        } stop;
        memset(&stop, 0, sizeof(stop));
        (void)snprintf(stop.magic, sizeof(stop.magic), "%s",
                       RESIDENT_FRAME_MAGIC_STOP);
        (void)snprintf(stop.nonce, sizeof(stop.nonce), "%s", launch->nonce);
        bool peer_closed = false;
        (void)resident_io_exact((int)launch->ipc_native, &stop, sizeof(stop),
                                true, &peer_closed);
    }
    uint32_t waited_ms = 0;
    int status = 0;
    while (waitpid(pid, &status, WNOHANG) == 0) {
        if (waited_ms >= timeout_ms) break;
        struct timespec pause = {.tv_sec = 0, .tv_nsec = 10 * 1000 * 1000};
        nanosleep(&pause, NULL);
        waited_ms += 10;
    }
    if (waitpid(pid, &status, WNOHANG) == 0) {
        (void)kill(-pid, SIGKILL); /* the child is its own group leader */
        (void)kill(pid, SIGKILL);
    }
    while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
    launch->spawned = false;
    return true;
#endif
}

#if !defined(_WIN32)
/* Frame admission policy: right magic, THIS launch's nonce, payload within
 * the caller's buffer. Everything else — including a frame from a
 * superseded launch — is refused by name. */
static bool resident_result_validate(const struct resident_launch *launch,
                                     const struct resident_result_header *wire,
                                     const void *payload, size_t payload_cap,
                                     char *error, size_t error_size)
{
    if (memcmp(wire->magic, RESIDENT_FRAME_MAGIC_RESULT,
               sizeof(RESIDENT_FRAME_MAGIC_RESULT)) != 0) {
        errno = EBADMSG;
        resident_fail(error, error_size,
                      "resident launch: result frame has a bad magic");
        return false;
    }
    if (memcmp(wire->nonce, launch->nonce, sizeof(wire->nonce)) != 0) {
        errno = ESTALE;
        resident_fail(error, error_size,
                      "result_stale_launch: frame carries another launch's"
                      " nonce");
        return false;
    }
    if (wire->payload_len > payload_cap || (!payload && wire->payload_len)) {
        errno = EMSGSIZE;
        resident_fail(error, error_size,
                      "resident launch: result payload %u exceeds the %zu"
                      " byte buffer",
                      (unsigned)wire->payload_len, payload_cap);
        return false;
    }
    return true;
}
#endif

#if !defined(_WIN32)
/* One absolute deadline covers every fragment of one result frame. */
struct resident_result_deadline {
    uint64_t end_ns;
    uint32_t timeout_ms;
};

static bool resident_result_now(uint64_t *now, char *error, size_t error_size)
{
    struct timespec value;
    if (clock_gettime(CLOCK_MONOTONIC, &value) != 0) {
        resident_fail(error, error_size, "resident launch: result clock failed: %s", strerror(errno));
        return false;
    }
    *now = (uint64_t)value.tv_sec * UINT64_C(1000000000) + (uint64_t)value.tv_nsec;
    return true;
}

static bool resident_result_timeout(const struct resident_result_deadline *deadline,
                                    char *error, size_t error_size)
{
    errno = ETIMEDOUT;
    resident_fail(error, error_size, "resident launch: result timed out after %u ms",
                  (unsigned)deadline->timeout_ms);
    return false;
}

static bool resident_result_wait(int fd, const struct resident_result_deadline *deadline,
                                 char *error, size_t error_size)
{
    for (;;) {
        uint64_t now;
        if (!resident_result_now(&now, error, error_size)) return false;
        if (deadline->timeout_ms && now >= deadline->end_ns)
            return resident_result_timeout(deadline, error, error_size);
        uint64_t remaining = now < deadline->end_ns ? deadline->end_ns - now : 0;
        uint64_t ms = remaining / UINT64_C(1000000) + (remaining % UINT64_C(1000000) != 0);
        int wait_ms = ms > INT_MAX ? INT_MAX : (int)ms;
        struct pollfd waiter = {.fd = fd, .events = POLLIN};
        int ready = poll(&waiter, 1, wait_ms);
        if (ready > 0) return true; /* recv distinguishes data, EOF and socket errors. */
        if (ready == 0) {
            if (!deadline->timeout_ms) return resident_result_timeout(deadline, error, error_size);
            continue; /* A capped poll interval may end before a long deadline. */
        }
        if (errno == EINTR && deadline->timeout_ms) continue;
        if (errno == EINTR) return resident_result_timeout(deadline, error, error_size);
        resident_fail(error, error_size, "resident launch: result poll failed: %s", strerror(errno));
        return false;
    }
}

static bool resident_result_live(const struct resident_result_deadline *deadline,
                                 char *error, size_t error_size)
{
    if (!deadline->timeout_ms) return true; /* Zero retains nonblocking drain semantics. */
    uint64_t now;
    if (!resident_result_now(&now, error, error_size)) return false;
    return now < deadline->end_ns || resident_result_timeout(deadline, error, error_size);
}

static bool resident_result_fragment(int fd, void *data, size_t size,
    const struct resident_result_deadline *deadline, bool header,
    char *error, size_t error_size)
{
    unsigned char *bytes = data;
    size_t done = 0;
    while (done < size) {
        if (!resident_result_live(deadline, error, error_size)) return false;
        /* MSG_DONTWAIT also bounds readers whose caller did not set O_NONBLOCK. */
        ssize_t got = recv(fd, bytes + done, size - done, MSG_DONTWAIT);
        if (got > 0) { done += (size_t)got; continue; }
        if (got < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) {
            if (!deadline->timeout_ms) return resident_result_timeout(deadline, error, error_size);
            if (!resident_result_wait(fd, deadline, error, error_size)) return false;
            continue;
        }
        errno = ECONNRESET;
        resident_fail(error, error_size, "%s",
            header && got == 0 ? "resident launch: resident closed the channel" :
            header ? "resident launch: truncated result header" :
                     "resident launch: truncated result payload");
        return false;
    }
    return true;
}
#endif

bool resident_result_read(struct resident_launch *launch,
                          struct resident_result_header *header,
                          void *payload, size_t payload_cap,
                          uint32_t timeout_ms,
                          char *error, size_t error_size)
{
#if defined(_WIN32)
    (void)launch; (void)header; (void)payload; (void)payload_cap;
    (void)timeout_ms;
    errno = ENOTSUP;
    resident_fail(error, error_size, "%s", RESIDENT_WIN_REFUSAL);
    return false;
#else
    if (!launch || !header || launch->ipc_native == (uintptr_t)-1) {
        errno = EINVAL;
        resident_fail(error, error_size,
                      "resident launch: result read needs a live launch");
        return false;
    }
    uint64_t now;
    if (!resident_result_now(&now, error, error_size)) return false;
    struct resident_result_deadline deadline = {
        .end_ns = now + (uint64_t)timeout_ms * UINT64_C(1000000),
        .timeout_ms = timeout_ms
    };
    int fd = (int)launch->ipc_native;
    struct resident_result_header wire;
    if (!resident_result_fragment(fd, &wire, sizeof(wire), &deadline, true,
                                   error, error_size)) return false;
    if (!resident_result_validate(launch, &wire, payload, payload_cap,
                                  error, error_size)) return false;
    if (wire.payload_len && !resident_result_fragment(fd, payload, wire.payload_len,
            &deadline, false, error, error_size)) return false;
    *header = wire;
    return true;
#endif
}

void resident_launch_close(struct resident_launch *launch)
{
    if (!launch) return;
#if !defined(_WIN32)
    if (launch->ipc_native != (uintptr_t)-1 &&
        launch->ipc_native != UINTPTR_MAX) {
        close((int)launch->ipc_native);
    }
#endif
    if (launch->pinned_native != (uintptr_t)-1 &&
        launch->pinned_native != UINTPTR_MAX) {
        struct platform_positioned_file *file =
            (struct platform_positioned_file *)(void *)launch->pinned_native;
        platform_positioned_file_close(file);
        free(file);
    }
    resident_launch_init(launch);
}
