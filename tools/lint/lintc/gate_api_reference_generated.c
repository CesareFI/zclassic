/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: gate family — check-api-reference-generated. docs/API_REFERENCE.md
 * must be the exact output of tools/gen_api_reference.c over the .def catalogs
 * it includes. The reference used to be transcribed by hand and drifted: a doc
 * that names a `ready` command that is actually `planned` costs an agent a
 * whole loop.
 *
 * Mechanism: compile the generator, run it into a scratch directory, compare
 * bytes. No make is invoked and nothing here reads git, so the gate behaves
 * the same inside the lint sandbox copy. The scan set is exactly what the
 * generator #includes, not a glob of the commands directory: a glob misses
 * the nested bundles and counts .def files the generator never reads.
 *
 * To fix a failure: edit a .def under engine/composition/commands or
 * docs/API_REFERENCE.md.in, then run `make docs-api-reference`. Never edit
 * docs/API_REFERENCE.md by hand. The selftest lives in
 * gate_api_reference_generated_selftest.c.
 *
 * Exit codes: 0 clean, 1 drift, 2 fatal. The scratch directory is removed on
 * every path; a termination signal is recorded, the directory is removed, and
 * the signal is re-raised with its default disposition.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <limits.h>
#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "gate_api_reference_generated_priv.h"
#include "lintc.h"
#include "lintc_proc.h"
#include "lintc_sig.h"

enum { ARG_FLOOR_DEFS = 20, ARG_FLOOR_ENTRIES = 200, ARG_DIFF_HEAD = 60,
       ARG_GRACE_MS = 2000 };

const char arg_gen_src[] = "tools/gen_api_reference.c";
const char arg_template[] = "docs/API_REFERENCE.md.in";
const char arg_doc[] = "docs/API_REFERENCE.md";
/* The POSIX default scratch parent when TMPDIR is unset. */
const char arg_tmp_default[] = { '/', 't', 'm', 'p', '\0' };

static const char arg_name[] = "check_api_reference_generated";
static const char arg_def_pattern[] =
    "^[[:space:]]*#include[[:space:]]+\"\\.\\./"
    "(engine/composition/commands/[A-Za-z0-9_/]+\\.def)\"";

static int arg_cmp(const void *a, const void *b)
{
    return strcmp(a, b);
}

static int arg_add_def(struct arg_defs *d, const char *line, const regmatch_t *m)
{
    size_t len = (size_t)(m->rm_eo - m->rm_so);
    if (len >= ARG_DEF_PATH || d->n >= ARG_DEF_MAX)
        return die("check_api_reference_generated: too many or too long .def paths: %s\n", line);
    memcpy(d->path[d->n], line + m->rm_so, len);
    d->path[d->n][len] = '\0';
    d->n++;
    return 0;
}

static void arg_dedupe(struct arg_defs *d)
{
    size_t w = 0;
    qsort(d->path, d->n, sizeof d->path[0], arg_cmp);
    for (size_t r = 0; r < d->n; r++)
        if (w == 0 || strcmp(d->path[w - 1], d->path[r]) != 0) {
            if (w != r)
                memcpy(d->path[w], d->path[r], sizeof d->path[0]);
            w++;
        }
    d->n = w;
}

int arg_def_list(struct arg_defs *d)
{
    regex_t re;
    regmatch_t m[2];
    char *line = NULL;
    size_t cap = 0;
    int rc = 0;
    d->n = 0;
    FILE *f = fopen(arg_gen_src, "r");
    if (!f)
        return die("z23-lint: cannot open %s\n", arg_gen_src);
    if (regcomp(&re, arg_def_pattern, REG_EXTENDED) != 0) {
        fclose(f);
        return die("z23-lint: bad pattern %s\n", arg_def_pattern);
    }
    while (rc == 0 && getline(&line, &cap, f) >= 0)
        if (regexec(&re, line, 2, m, 0) == 0)
            rc = arg_add_def(d, line, &m[1]);
    regfree(&re);
    rc = fin(f, line, arg_gen_src, rc);
    arg_dedupe(d);
    return rc;
}

static int arg_preflight(const struct arg_io *io, struct arg_defs *d)
{
    const char *const req[] = { arg_gen_src, arg_template, arg_doc };
    for (size_t i = 0; i < sizeof req / sizeof req[0]; i++)
        if (access(req[i], F_OK) != 0) {
            fprintf(io->err, "%s: FATAL — missing %s\n", arg_name, req[i]);
            return 2;
        }
    if (arg_def_list(d) != 0)
        return 2;
    int missing = 0;
    for (size_t i = 0; i < d->n; i++)
        if (access(d->path[i], F_OK) != 0) {
            fprintf(io->err, "%s: FATAL — %s includes %s, which does not exist\n",
                    arg_name, arg_gen_src, d->path[i]);
            missing = 1;
        }
    if (missing)
        return 2;
    return gate_require_scanned((int)d->n, ARG_FLOOR_DEFS, arg_name,
                                "no .def catalogs included by "
                                "tools/gen_api_reference.c — the command catalog moved?");
}

/* Writes the buffer's lines, each prefixed by four spaces; limit 0 is no cap. */
void arg_indent(FILE *out, const char *data, size_t limit)
{
    size_t lines = 0;
    while (data && *data && (limit == 0 || lines < limit)) {
        const char *nl = strchr(data, '\n');
        size_t n = nl ? (size_t)(nl - data) : strlen(data);
        fprintf(out, "    %.*s\n", (int)n, data);
        data += n + (nl ? 1 : 0);
        lines++;
    }
}

/* Runs argv; 0 with *code set, 1 when a signal ended the run, 2 when it
 * could not start. */
static int arg_exec(char *const *argv, enum lcp_mode mode, struct lcp_buf *out,
                    int *code)
{
    struct lcp_spec s = { .argv = argv, .mode = mode, .grace_ms = ARG_GRACE_MS };
    int rc = lcp_run(&s, out, code);
    return rc < 0 ? 2 : rc;
}

int arg_open_scratch(struct arg_scratch *s)
{
    const char *tmp = env_or("TMPDIR", arg_tmp_default);
    int n = snprintf(s->dir, sizeof s->dir, "%s/zcl-apiref.XXXXXX", tmp);
    if (n < 0 || (size_t)n >= sizeof s->dir || !mkdtemp(s->dir)) {
        s->dir[0] = '\0';
        return -1;
    }
    snprintf(s->bin, sizeof s->bin, "%s/gen_api_reference", s->dir);
    snprintf(s->expected, sizeof s->expected, "%s/expected.md", s->dir);
    return 0;
}

static int arg_build(const struct arg_io *io, const struct arg_scratch *s)
{
    char *const argv[] = { (char *)env_or("CC", "cc"), (char *)"-std=c23", (char *)"-O0",
        (char *)"-Wall", (char *)"-Wextra", (char *)"-Werror",
        (char *)"-Iengine/modules/kernel/include", (char *)"-Iplatform/modules/json/include",
        (char *)"-Iplatform/modules/base/include", (char *)"-o", (char *)s->bin,
        (char *)arg_gen_src, NULL };
    struct lcp_buf log = { 0 };
    int code = 0, rc = arg_exec(argv, LCP_ERR, &log, &code);
    if (rc == 0 && code != 0)
        rc = 2;
    if (rc == 2) {
        fprintf(io->err, "%s: FATAL — %s does not compile:\n", arg_name, arg_gen_src);
        arg_indent(io->err, log.data, 0);
    }
    lcp_buf_free(&log);
    return rc;
}

/* Length of the digits when the line is `gen_api_reference: N catalog entries...`, else 0. */
static size_t arg_entry_digits(const char *line)
{
    static const char head[] = "gen_api_reference: ";
    static const char tail[] = " catalog entries";
    if (strncmp(line, head, sizeof head - 1) != 0)
        return 0;
    const char *d = line + sizeof head - 1;
    size_t n = strspn(d, "0123456789");
    return strncmp(d + n, tail, sizeof tail - 1) == 0 ? n : 0;
}

/* The first matching line's number as digits, empty when none matches. */
static void arg_entries(const char *log, char *digits, size_t cap)
{
    digits[0] = '\0';
    while (*log) {
        size_t n = arg_entry_digits(log);
        if (n > 0 && n < cap) {
            memcpy(digits, log + strlen("gen_api_reference: "), n);
            digits[n] = '\0';
            return;
        }
        const char *nl = strchr(log, '\n');
        log = nl ? nl + 1 : log + strlen(log);
    }
}

static int arg_entry_floor(const char *digits)
{
    long long v = digits[0] ? strtoll(digits, NULL, 10) : 0;
    return v > INT_MAX ? INT_MAX : (int)v;
}

static int arg_generate(const struct arg_io *io, struct arg_scratch *s)
{
    char *const argv[] = { s->bin, (char *)arg_template, s->expected, NULL };
    struct lcp_buf log = { 0 };
    int code = 0, rc = arg_exec(argv, LCP_ERR, &log, &code);
    if (rc == 0 && code != 0)
        rc = 2;
    if (rc == 2) {
        fprintf(io->err, "%s: FATAL — the generator failed:\n", arg_name);
        arg_indent(io->err, log.data, 0);
    } else if (rc == 0) {
        arg_entries(log.data ? log.data : "", s->entries, sizeof s->entries);
        rc = gate_require_scanned(arg_entry_floor(s->entries), ARG_FLOOR_ENTRIES, arg_name,
                                  "the generator emitted almost no catalog entries — "
                                  "the X-macro expansion broke");
    }
    lcp_buf_free(&log);
    return rc;
}

/* 0 when both streams reach EOF together, 1 on a differing byte, 2 on a read error. */
static int arg_compare_streams(FILE *fa, FILE *fb)
{
    int ca = 0, cb = 0;
    while (ca == cb && ca != EOF) {
        ca = fgetc(fa);
        cb = fgetc(fb);
    }
    if (ferror(fa) || ferror(fb))
        return 2;
    return ca == cb ? 0 : 1;
}

/* Like arg_compare_streams; *bad names the file that could not be read. */
static int arg_compare(const char *a, const char *b, const char **bad)
{
    FILE *fa = fopen(a, "rb"), *fb = fopen(b, "rb");
    int rc = 2;
    *bad = fa ? b : a;
    if (fa && fb) {
        rc = arg_compare_streams(fa, fb);
        *bad = ferror(fa) ? a : b;
    }
    if (fa)
        fclose(fa);
    if (fb)
        fclose(fb);
    return rc;
}

static int arg_drift(const struct arg_io *io, const struct arg_scratch *s)
{
    char *const argv[] = { (char *)"diff", (char *)"-u", (char *)arg_doc,
                           (char *)s->expected, NULL };
    struct lcp_buf diff = { 0 };
    int code = 0, rc = arg_exec(argv, LCP_BOTH, &diff, &code);
    if (rc == 1) {
        lcp_buf_free(&diff);
        return 1;
    }
    fprintf(io->err, "FAIL: %s is not what tools/gen_api_reference.c produces.\n\n"
            "  %s is GENERATED output. Do not edit it by hand.\n"
            "  Change the catalog (engine/composition/commands/*.def) or the editorial template\n"
            "  (%s), then regenerate:\n\n"
            "      make docs-api-reference\n\n"
            "  Drift (checked-in '-' vs generated '+'), first %d lines:\n",
            arg_doc, arg_doc, arg_template, ARG_DIFF_HEAD);
    arg_indent(io->err, diff.data, ARG_DIFF_HEAD);
    lcp_buf_free(&diff);
    return 1;
}

static int arg_steps(const struct arg_io *io, struct arg_scratch *s, size_t ndefs)
{
    int rc = arg_build(io, s);
    if (rc == 0 && lsc_pending() == 0)
        rc = arg_generate(io, s);
    if (rc != 0 || lsc_pending())
        return rc ? rc : 1;
    const char *bad = arg_doc;
    int cmp = arg_compare(arg_doc, s->expected, &bad);
    if (cmp == 2) {
        fprintf(io->err, "%s: FATAL — cannot read %s\n", arg_name, bad);
        return 2;
    }
    if (cmp == 1)
        return arg_drift(io, s);
    fprintf(io->out, "%s: clean — %s matches the generator over %zu .def catalog(s) / %s entries\n",
            arg_name, arg_doc, ndefs, s->entries);
    return 0;
}

int arg_gate(const struct arg_io *io)
{
    struct arg_defs defs;
    struct arg_scratch s = { .dir = "" };
    int rc = arg_preflight(io, &defs), owned = 0;
    if (rc == 0 && arg_open_scratch(&s) != 0) {
        fprintf(io->err, "z23-lint: cannot create a scratch directory under %s\n",
                env_or("TMPDIR", arg_tmp_default));
        rc = 2;
    } else if (rc == 0) {
        owned = 1;
        rc = arg_steps(io, &s, defs.n);
    }
    if (owned)
        (void)rap_rm_rf(s.dir);
    return rc;
}

int check_api_reference_generated_run(int argc, char **argv)
{
    struct arg_io io = { stdout, stderr };
    (void)argc;
    (void)argv;
    if (lsc_install() != 0)
        return die("z23-lint: cannot install signal handlers\n", "");
    int rc = arg_gate(&io);
    fflush(stdout);
    int sig = lsc_pending();
    if (sig)
        lsc_finish(sig);
    return rc;
}
