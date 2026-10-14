/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0.
 * purpose: Process, file and scratch-directory helpers shared by the
 *          unprivileged verifier probes (fixed_result_launcher_probe.c and
 *          real_tu_probe.c). Local qualification only; no authority. */
#ifndef ZCL_TOOLS_VERIFY_PROBE_UTIL_H
#define ZCL_TOOLS_VERIFY_PROBE_UTIL_H

#include <stdbool.h>
#include <stddef.h>

#define PU_PATH_MAX 4096u
#define PU_ARGV_MAX 256u

/* Argument vector builder; the vector stays NULL-terminated. */
struct pu_argv {
    const char *v[PU_ARGV_MAX + 1u];
    size_t n;
};

void pu_argv_add(struct pu_argv *a, const char *arg);
void pu_argv_addv(struct pu_argv *a, const char *const *args);

/* Run argv[0] (resolved through PATH). stdout and stderr go to the named
 * files when non-NULL and are inherited otherwise. Returns the exit status,
 * or -1 when the command could not start or died on a signal. */
int pu_run(const struct pu_argv *a, const char *out_path, const char *err_path);

/* Join dir and name into one of eight rotating buffers. */
const char *pu_at(const char *dir, const char *name);

/* Read a file (at most cap-1 bytes) and NUL-terminate; false on error.
 * With trim, trailing newlines are removed. */
bool pu_read(const char *path, char *buf, size_t cap, size_t *len, bool trim);

bool pu_has_line(const char *path, const char *line);
bool pu_same_file(const char *a, const char *b);
bool pu_copy(const char *src, const char *dst);
bool pu_mkdirs(const char *path);

/* Create a private directory from a mkdtemp template into out. */
bool pu_scratch_make(const char *templ, char *out, size_t cap);
void pu_scratch_remove(const char *path);

/* Absolute path of the enclosing git work tree, from the current directory. */
bool pu_repo_root(char *out, size_t cap);

/* Act on a recorded SIGINT, SIGTERM or SIGHUP: remove the scratch trees and
 * end the process by that signal. Called after every helper step. */
void pu_poll_signal(void);

long long pu_now_ns(void);

/* Self-test of the helpers; prints one result line and returns 0 on success. */
int pu_selftest(void);

#endif
