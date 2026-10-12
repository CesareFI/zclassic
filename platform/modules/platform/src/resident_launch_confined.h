/* Copyright 2026 Rhett Creighton - Apache-2.0
 * Purpose: internal seam between resident_launch.c and its confined-launch half */
/* Internal to platform/modules/platform/src: the confined pieces of the exact
 * resident launch (status-pipe handshake, descriptor sweep, sandbox arming,
 * exec confirmation, bounded reap) split out of resident_launch.c. Not a
 * public header; resident_launch.h carries the public surface. */
#ifndef ZCL_PLATFORM_RESIDENT_LAUNCH_CONFINED_H
#define ZCL_PLATFORM_RESIDENT_LAUNCH_CONFINED_H

#include "platform/resident_launch.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#if !defined(_WIN32)
#include <sys/types.h>
#endif

#define RESIDENT_HASH_CHUNK 65536u

#if !defined(_WIN32)
/* Monotonic ns; UINT64_MAX on a clock error (every deadline then reads as
 * expired). resident_default_deadline refuses (false) on a clock error. */
uint64_t resident_mono_ns(void);
bool resident_default_deadline(uint64_t *out);
bool resident_sha3_positioned(const struct platform_positioned_file *file,
                              unsigned char out[32]);
#endif

#if !defined(_WIN32) && !defined(__APPLE__)
/* /proc/<pid>/exe second proof; upgrades the receipt and CONFIRMED on a match. */
bool resident_reproof_mapped(pid_t pid, struct resident_launch *launch,
                             struct resident_receipt *receipt,
                             char *error, size_t error_size);
#endif

#if !defined(_WIN32) && !defined(__APPLE__)
/* What the forked child needs, gathered BEFORE the fork so the child path
 * allocates nothing. */
struct resident_child_plan {
    int pinned_fd, ipc_child, status_write;
    const struct os_sandbox_profile *profile;
#ifdef ZCL_TESTING
    uint32_t stall_ms;
    bool die_after_marker;
    bool fail_traceme;
    bool no_close_range; /* force the proc-fd enumeration fallback */
#endif
};
#endif

#if defined(__linux__)

/* Child side: close every descriptor not named, then arm the sandbox and
 * write the armed marker (or a stage byte on refusal; never returns on error). */
void resident_child_close_inherited(const struct resident_child_plan *plan);
void resident_child_arm(const struct resident_child_plan *plan);

/* Parent side: wait for the child's exec stop and re-prove the image. */
bool resident_confirm_exec(struct resident_launch *launch, pid_t pid,
                           uint64_t deadline_ns, struct resident_receipt *receipt,
                           char *error, size_t error_size);
#endif

#endif
