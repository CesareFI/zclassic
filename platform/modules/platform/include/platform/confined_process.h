/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: the Windows confinement backend for one bounded executor child.
 *
 * WHAT IT IS. The POSIX dev worker confines its executor with fork plus
 * RLIMIT_CPU/RLIMIT_AS plus a wall-clock SIGKILL. Windows has no fork and no
 * rlimits, so the same caps are expressed here as ONE launch: a fresh child
 * image started suspended under a restricted, low-integrity token, placed in
 * a kill-on-close Job Object that carries the memory, CPU-time and
 * active-process caps, and resumed only once every piece is in place. The
 * caller keeps the wall clock and kills the whole job on timeout.
 *
 * FAIL CLOSED. Every piece is mandatory. When one cannot be established on
 * this host the launch does not happen and the typed missing capability is
 * returned; there is no degraded, unconfined, or partially confined launch.
 * On a non-Windows host every entry reports PLATFORM_CONFINE_MISSING_OS.
 *
 * WRITE SCOPE. The child runs at LOW integrity, so the mandatory
 * no-write-up policy denies it every object labelled medium or higher —
 * which is every file a user owns by default. The caller names the exact
 * directory trees the child may write; each is relabelled low (inheritable)
 * for the run and relabelled medium again by platform_confined_release_roots.
 * Reads are NOT scoped: low integrity may read whatever the user may read.
 */
#ifndef ZCL_PLATFORM_CONFINED_PROCESS_H
#define ZCL_PLATFORM_CONFINED_PROCESS_H

#include "platform/process_lifecycle.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* The one missing capability that refused a confined launch. ARMED means
 * nothing is missing. Names are stable machine words (see _name below). */
enum platform_confine_missing {
    PLATFORM_CONFINE_ARMED = 0,
    PLATFORM_CONFINE_MISSING_OS,               /* not a Windows host */
    PLATFORM_CONFINE_MISSING_JOB_OBJECT,       /* job or one of its limits */
    PLATFORM_CONFINE_MISSING_RESTRICTED_TOKEN, /* CreateRestrictedToken */
    PLATFORM_CONFINE_MISSING_LOW_INTEGRITY,    /* low label on the token */
    PLATFORM_CONFINE_MISSING_WRITE_LABEL,      /* low label on a write root */
    PLATFORM_CONFINE_MISSING_HANDLE_LIST,      /* explicit inherit list */
    PLATFORM_CONFINE_MISSING_LAUNCH,           /* create/assign/resume */
    PLATFORM_CONFINE_BAD_SPEC                  /* caller input refused */
};

/* "armed", "os", "job-object", "restricted-token", "low-integrity",
 * "write-label", "handle-list", "launch", "bad-spec". Never NULL. */
const char *platform_confine_missing_name(enum platform_confine_missing m);

/* One confined launch. image/argv/cwd/env follow platform_process_options:
 * absolute UTF-8 image, explicit NULL-terminated argv (argv[0] explicit) and
 * env (KEY=VALUE, nothing inherited implicitly). No handle is inherited
 * except the NUL device as stdin/stdout/stderr. Every cap must be nonzero. */
struct platform_confined_spec {
    const char *image;
    const char *const *argv;
    const char *cwd;
    const char *const *env;
    const char *const *write_roots; /* absolute directories, 1..8 */
    size_t write_root_count;
    uint64_t memory_bytes;     /* job-wide committed-memory cap */
    uint64_t cpu_seconds;      /* job-wide user-mode CPU time cap */
    uint32_t active_processes; /* live processes in the job, child included */
};

/* What the job observed, read after the child exited or was killed. */
struct platform_confined_report {
    uint32_t exit_code;
    bool crashed;            /* exit code is an NTSTATUS error (exception) */
    bool cpu_limit_hit;      /* job user time reached the CPU cap */
    uint64_t peak_memory_bytes;
};

/* Probe without launching: the job with every limit, the restricted
 * low-integrity token, and the label descriptors. ARMED or the first
 * missing capability. */
enum platform_confine_missing platform_confined_probe(void);

/* Label every write root, build the token and job, and start the child
 * suspended; assign, then resume. On ARMED the process owns the job (see
 * platform_process_terminate / platform_process_close). On any other value
 * nothing ran and every root this call labelled is relabelled medium. */
enum platform_confine_missing platform_confined_start(
    struct platform_process *process,
    const struct platform_confined_spec *spec);

/* After platform_process_wait reported EXITED (or after terminate + wait).
 * False when the job cannot be queried. */
bool platform_confined_report(const struct platform_process *process,
                              struct platform_confined_report *report);

/* Relabel each root medium again (inheritable), undoing the run's grant on
 * every object that inherited it. True only when every root succeeded. */
bool platform_confined_release_roots(const char *const *roots, size_t count);

/* Child side, before any work: ARMED only when this process sits in a job
 * that carries kill-on-close plus the memory, CPU and active-process caps,
 * with a memory cap no larger than max_memory_bytes, and its token is at
 * low integrity or below with the Administrators group not enabled. */
enum platform_confine_missing platform_confined_self_check(
    uint64_t max_memory_bytes);

/* Pure: true when a Windows exit code is an NTSTATUS error — an unhandled
 * exception, a stack-cookie or fast-fail abort — the Windows analogue of a
 * POSIX death by signal. Portable so it is testable on every host. */
bool platform_confined_exit_is_crash(uint32_t exit_code);

#endif
