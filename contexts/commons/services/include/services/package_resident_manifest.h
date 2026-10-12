/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: translate a minimal run manifest into an OS sandbox profile and run
 * a pinned native image confined, to exit. */
#ifndef ZCL_SERVICES_PACKAGE_RESIDENT_MANIFEST_H
#define ZCL_SERVICES_PACKAGE_RESIDENT_MANIFEST_H

#include "base/result.h"
#include "platform/os_sandbox.h"
#include "services/package_resident.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define PACKAGE_RESIDENT_MANIFEST_PATHS 8u
#define PACKAGE_RESIDENT_MANIFEST_ARGS 8u
#define PACKAGE_RESIDENT_MANIFEST_PATH_MAX 1024u
#define PACKAGE_RESIDENT_RUN_TIMEOUT_MAX_MS 600000u

/* Finite defaults every confined run gets from _init (conservative, sized for
 * a short-lived static native tool; callers may only RAISE them knowingly).


 * DOCUMENTED EXCEPTION: the manifest NPROC is KEEP and exempt by name from the
 * unbounded-limit refusal. NPROC is per-uid in Linux; processes are denied by
 * seccomp, threads are bounded by RLIMIT_AS (user stacks) and by a thread
 * budget: when the profile is built the uid's live task count is read and the
 * child gets RLIMIT_NPROC = count + PACKAGE_RESIDENT_DEFAULT_THREADS. If the
 * count cannot be read the profile is REFUSED. RACE: other processes of the uid
 * may grow after the count, so thread creation can fail with EAGAIN earlier; that
 * only denies, it never widens the budget. An explicit manifest nproc is used
 * as given. The budget is a uid-wide CEILING (the uid's task count at launch
 * plus PACKAGE_RESIDENT_DEFAULT_THREADS), shared with every other process of
 * the uid; it is NOT a guaranteed per-app thread cap. */
#define PACKAGE_RESIDENT_DEFAULT_THREADS UINT64_C(256)
#define PACKAGE_RESIDENT_DEFAULT_AS_BYTES (UINT64_C(1) << 30)   /* 1 GiB address space */
#define PACKAGE_RESIDENT_DEFAULT_CPU_SECONDS UINT64_C(60)       /* SIGXCPU then KILL */
#define PACKAGE_RESIDENT_DEFAULT_NOFILE UINT64_C(64)
#define PACKAGE_RESIDENT_DEFAULT_FSIZE_BYTES (UINT64_C(64) << 20) /* 64 MiB */

/* STDIO GRANT: descriptors 0, 1 and 2 are inherited from the caller by design
 * (the CLI needs the app's output), so a confined app reads the caller's stdin
 * and writes to the caller's stdout and stderr. That is an explicit grant, not
 * an oversight; every other descriptor is closed before the sandbox arms.
 *
 * CHILDREN: seccomp denies fork, vfork, setsid, setpgid and every clone that
 * lacks CLONE_THREAD, so a confined app can start threads (which die with the
 * process-group kill at timeout) but never a process. clone3 answers ENOSYS so
 * libc falls back to clone. io_uring is denied (it can reach the network with
 * no syscall seccomp can see). Threads are bounded by RLIMIT_AS and the
 * NPROC thread budget above, so they work on default limits.
 *
 * EXEC PROOF: a run is reported only after the exec was confirmed (the child
 * stops at the exec and /proc/<pid>/exe matches the pinned image); otherwise
 * the result is a typed resident-confined-exec-uncertain refusal. */

/* Internal, minimal input (a struct, not a public schema): the zcl.app.
 * manifest.v2 contract of ADR 0004 has no parser in the tree yet, so this is
 * the narrow shape the sandbox needs until it does. Paths are absolute, never
 * contain a ".." segment and must exist. Read paths are read-only; write
 * paths are read/write/create. Zero-init is NOT valid: call _init first. */
struct package_resident_manifest {
    const char *read_paths[PACKAGE_RESIDENT_MANIFEST_PATHS];
    size_t n_read;
    const char *write_paths[PACKAGE_RESIDENT_MANIFEST_PATHS];
    size_t n_write;
    /* _init sets the finite PACKAGE_RESIDENT_DEFAULT_* limits. A field set to
     * OS_SANDBOX_RLIMIT_KEEP (untouched) is REFUSED unless the manifest also
     * sets allow_unbounded_limits, which is logged as an explicit opt-out. */
    struct os_sandbox_rlimits rlimits;
    bool allow_unbounded_limits;
    /* Descendant processes. Refused: full containment (a cgroup, or a
     * subreaper with kill-all on the timeout path) is not implemented, so the
     * seccomp policy denies fork/vfork/clone/clone3/setsid/setpgid and a
     * manifest asking for children is rejected by name. */
    bool allow_children;
};

/* The built profile and the storage its pointers reference. Must stay at a
 * stable address from build until the spawn returns. */
struct package_resident_confinement {
    struct os_sandbox_profile profile;
    struct os_sandbox_path_rule rules[2u * PACKAGE_RESIDENT_MANIFEST_PATHS + 8u];
    char image_path[PACKAGE_RESIDENT_MANIFEST_PATH_MAX];
    /* Grant objects opened in the parent (O_PATH, no symlink in any
     * component) and bound to the rules above; the caller releases them. */
    int grant_fds[2u * PACKAGE_RESIDENT_MANIFEST_PATHS + 8u];
    size_t n_grant_fds;
};

/* Close the grant descriptors _profile opened. Safe on a failed or already
 * released confinement. */
void package_resident_confinement_release(struct package_resident_confinement *c);

void package_resident_manifest_init(struct package_resident_manifest *m);

/* Validate `m` and build the profile BEFORE any fork. Grants the image
 * (read+execute) and the manifest paths ONLY - no loader or runtime directory,
 * because images are static PIE (ADR-0004) and a PT_INTERP image is refused at
 * spawn. Core dumps are disabled unless the manifest sets core_bytes. fd 3 is
 * inherited, not a path. Each grant is opened here with O_PATH and no symlink
 * in any component, then bound to its rule by descriptor, so the object the
 * child is confined to is the one validated. The caller must release. */
struct zcl_result package_resident_manifest_profile(
    const struct package_resident_manifest *m, const char *image_path,
    struct package_resident_confinement *out);

struct package_resident_exit {
    bool exited;      /* normal exit; `code` is valid */
    bool signaled;    /* killed by `signal` (SIGSYS = seccomp policy kill) */
    bool timed_out;   /* the wall budget elapsed and the child was killed */
    int code;
    int signal;
};

/* Spawn the prepared app's pinned image under the manifest's profile with an
 * empty environment, wait for it to exit (killing its process group at
 * timeout_ms), and reap it. Refuses by name when Landlock/seccomp are
 * unavailable. The app must be prepared and unspawned. */
struct zcl_result package_resident_run_confined(
    struct package_resident *app, const struct package_resident_manifest *m,
    const char *const *args, size_t n_args, uint32_t timeout_ms,
    struct package_resident_exit *out);

#ifdef ZCL_TESTING
/* Make grant opening report ENOTSUP, as an openat2-less kernel does, so the
 * grant-pinning-unavailable refusal can be exercised. */
void package_resident_manifest_force_unpinned_grants_for_testing(bool on);
#endif

#endif
