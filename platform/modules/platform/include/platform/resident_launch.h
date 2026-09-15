/* Copyright 2026 Rhett Creighton - Apache-2.0
 * Purpose: exact resident process launch bound to an accepted artifact */
/* Exact resident process launch bound to an accepted artifact.
 *
 * The launcher half of the app-run seam: given an artifact the caller has
 * ALREADY accepted (content root + positioned-file identity), prepare()
 * re-proves the live bytes and handle identity, spawn() executes exactly
 * that inode via fexecve(2) — never a pathname re-open — hands the child
 * one inherited IPC socket at a fixed descriptor, and returns a receipt
 * binding pid + start token + nonce + image identity. Result frames the
 * child sends back are accepted only while they carry this launch's nonce,
 * so a superseded launch's late results are rejected by name.
 *
 * Platform posture follows os_binary_slots: there is no descriptor-bound
 * execution on macOS or Windows (platform_execve_fd refuses ENOTSUP by
 * design), so spawn() refuses by name there rather than reconstructing a
 * pathname — a TOCTOU hole dressed as a launch. Only Linux proves a mapped
 * image today; the receipt says which proof it carries.
 */
#ifndef ZCL_PLATFORM_RESIDENT_LAUNCH_H
#define ZCL_PLATFORM_RESIDENT_LAUNCH_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "platform/positioned_file.h"

#define RESIDENT_LAUNCH_NONCE_HEX 64u
#define RESIDENT_LAUNCH_DIGEST_HEX 64u
#define RESIDENT_LAUNCH_ERROR_MAX 256u
/* The one descriptor the resident child receives: the IPC socket, dup2'd to
 * this fixed number before exec so an app never has to discover it. */
#define RESIDENT_LAUNCH_CHILD_FD 3

/* What the caller must already hold from acceptance time: the artifact's
 * SHA3-256 content root and the positioned-file identity triple captured
 * over the accepted handle. prepare() refuses any image whose live bytes,
 * size or triple differ — fail-closed BEFORE any process exists. */
struct resident_launch_accepted {
    char image_sha3_hex[RESIDENT_LAUNCH_DIGEST_HEX + 1u];
    uint64_t image_volume, image_low, image_high, image_size;
};

/* Binds one resident OS process to the exact accepted image. `start_token`
 * is the kernel's per-process start stamp, so the handle survives pid
 * reuse. `mapped_proof` names what was proven: "fexecve_inode" (the kernel
 * mapped the exact inode this launcher pinned) on every Linux spawn, or
 * "proc_exe_triple" when the child lived long enough for the post-spawn
 * /proc/<pid>/exe re-proof as well. */
struct resident_receipt {
    char nonce[RESIDENT_LAUNCH_NONCE_HEX + 1u];
    char image_sha3_hex[RESIDENT_LAUNCH_DIGEST_HEX + 1u];
    uint64_t pid;
    uint64_t start_token;
    uint64_t image_volume, image_low, image_high, image_size;
    char mapped_proof[24];
};

/* Every frame on the IPC socket starts with this wire header. The child
 * echoes the launch nonce it received; the parent accepts a frame only
 * while that nonce is the current launch's. */
struct resident_result_header {
    char magic[16]; /* "z23-res-run-v1\0" */
    char nonce[RESIDENT_LAUNCH_NONCE_HEX + 1u];
    uint32_t payload_len;
};

struct resident_launch {
    uintptr_t pinned_native;    /* struct platform_positioned_file * */
    uintptr_t ipc_native;       /* parent socket end (or -1) */
    struct platform_positioned_file_snapshot pinned_snapshot;
    struct resident_launch_accepted accepted;
    char nonce[RESIDENT_LAUNCH_NONCE_HEX + 1u];
    uint64_t pid;
    uint64_t start_token;
    bool spawned;
};

void resident_launch_init(struct resident_launch *launch);
/* Opens, hashes and identity-checks the image against `accepted`. No fd is
 * inheritable yet; nothing is spawned. */
bool resident_launch_prepare(struct resident_launch *launch,
                             const char *image_path,
                             const struct resident_launch_accepted *accepted,
                             char *error, size_t error_size);
/* fork + fexecve(pinned fd); the child inherits exactly one descriptor:
 * the IPC socket at RESIDENT_LAUNCH_CHILD_FD. Returns only after the exec
 * outcome is known (exec failure is reported here, not silently lost) and
 * the receipt is complete. */
bool resident_launch_spawn(struct resident_launch *launch,
                           char *const argv[], char *const envp[],
                           struct resident_receipt *receipt,
                           char *error, size_t error_size);
/* Sends the nonce-bound stop frame, waits up to timeout_ms for exit, then
 * escalates to SIGKILL of the child's process group and reaps. Idempotent
 * for an already-exited child. */
bool resident_launch_cancel(struct resident_launch *launch,
                            uint32_t timeout_ms,
                            char *error, size_t error_size);
/* Reads one result frame and accepts it only under the current nonce;
 * stale or malformed frames are refused by name in `error`. A single absolute
 * monotonic timeout covers the complete header and payload, including partial
 * reads, EAGAIN and EINTR; fragments never renew it. timeout_ms == 0 drains
 * only immediately available bytes and refuses an incomplete frame. */
bool resident_result_read(struct resident_launch *launch,
                          struct resident_result_header *header,
                          void *payload, size_t payload_cap,
                          uint32_t timeout_ms,
                          char *error, size_t error_size);
/* Resource cleanup only — closes descriptors and frees state. It does NOT
 * stop a live child: cancellation is an explicit lifecycle act. */
void resident_launch_close(struct resident_launch *launch);

#endif
