/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0.
 * purpose: Pinned compile-profile helpers shared by the result.c witness
 *          probes (fixed_result_gcc14_probe.c, fixed_result_fast_probe.c):
 *          line vectors, @CWD@ expansion, SHA3-256 of a file, the checkout
 *          preflight and timed child runs. Local qualification only. */
#ifndef ZCL_TOOLS_VERIFY_FIXED_RESULT_PROFILE_H
#define ZCL_TOOLS_VERIFY_FIXED_RESULT_PROFILE_H

#include "verify/probe_util.h"

#include <stdbool.h>
#include <stddef.h>

/* Owned lines without their terminating newline. */
struct frp_lines {
    char **v;
    size_t n;
};

/* Child process time measured around one run. */
struct frp_timing {
    double wall, user, sys;
};

bool frp_lines_add(struct frp_lines *l, const char *text);
void frp_lines_free(struct frp_lines *l);

/* Split a file into lines: a final line without newline counts, an empty
 * file has none. False when the file cannot be read. */
bool frp_lines_load(const char *path, struct frp_lines *out);

/* Copy of the first count lines with every @CWD@ replaced by cwd. */
bool frp_expand(const struct frp_lines *in, size_t count, const char *cwd,
                struct frp_lines *out);

/* Whole-string shell glob match in which * also matches '/'. */
bool frp_glob(const char *text, const char *pattern);

/* Lowercase SHA3-256 hex of a file's bytes; out is empty when the file
 * cannot be read. */
bool frp_sha3_file(const char *path, char out[65]);

/* NULL when the current directory is the physical repository root, else the
 * refusal token. Exits 128 when git cannot name the work tree. */
const char *frp_checkout(char *repo, size_t cap);

/* File size, or -1. */
long long frp_size(const char *path);

/* Append: env -i LC_ALL=C TZ=UTC TMPDIR=/tmp PATH=/usr/bin:/bin, then args. */
void frp_env_argv(struct pu_argv *a, const struct frp_lines *args);

/* pu_run from dir (the current directory when NULL), with timing. */
int frp_run(const char *dir, const struct pu_argv *a, const char *out,
            const char *err, struct frp_timing *t);

/* Self-test of the helpers; prints one result line and returns 0 on success. */
int frp_selftest(void);

#endif
