/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: --selftest for check-fleet-observations (gate_fleet_observations.c).
 * Regenerates the .def from the fixture ledger with the real generator in a
 * scratch directory and proves a fresh regeneration checks clean, a hand-edited
 * row and a missing file fail --check, and five malformed ledger columns are
 * refused with exit 2 and the output untouched. INT, TERM and HUP stop the
 * running generator, remove the scratch directory and re-raise.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <dirent.h>
#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "gate_fleet_observations_priv.h"

enum { FOS_PASS = 0, FOS_FAILED = 1, FOS_STOPPED = 2 };

struct fos {
    struct fo_cfg c;
    char tmp[FO_PATH];
    char good[FO_PATH + 16];
    char bad[FO_PATH + 16];
    int fails;
};

static const char *const k_fos_mutations[] = { "leading", "repeated", "trailing", "empty", "extra" };

static int fos_gen(const struct fos *s, const char *ledger, const char *out_path, int days,
                   int check, struct fo_buf *cap)
{
    char a_ledger[FO_PATH + 16], a_out[FO_PATH + 32], a_days[] = "--days=7", a_check[] = "--check";
    if (snprintf(a_ledger, sizeof a_ledger, "--ledger=%s", ledger) >= (int)sizeof a_ledger
        || snprintf(a_out, sizeof a_out, "--out=%s", out_path) >= (int)sizeof a_out)
        return FO_SPAWN_FAILED;
    char *argv[6];
    int n = 0;
    argv[n++] = (char *)s->c.bin;
    argv[n++] = a_ledger;
    if (days)
        argv[n++] = a_days;
    argv[n++] = a_out;
    if (check)
        argv[n++] = a_check;
    argv[n] = NULL;
    int st = fo_run(s->c.bin, argv, cap);
    return st;
}

static int fos_write(const char *path, const struct fo_buf *b)
{
    FILE *f = fopen(path, "wb");
    if (!f)
        return -1;
    int short_write = b->n && fwrite(b->p, 1, b->n, f) != b->n;
    int close_failed = fclose(f) != 0;
    return short_write || close_failed ? -1 : 0;
}

static int fos_fail(const char *what)
{
    fprintf(stderr, "%s: SELFTEST FAILED — %s\n", k_fo_gate, what);
    return FOS_FAILED;
}

static void fos_soft_fail(struct fos *s, const char *what)
{
    fprintf(stderr, "%s: SELFTEST FAILED — %s\n", k_fo_gate, what);
    s->fails++;
}

/* The text with the first ", 3, 7, " of every line widened to ", 30, 7, ". */
static void fos_widen_rows(const char *text, size_t len, struct fo_buf *out)
{
    static const char pat[] = ", 3, 7, ";
    for (size_t pos = 0; pos < len;) {
        const char *nl = memchr(text + pos, '\n', len - pos);
        size_t ln = nl ? (size_t)(nl - (text + pos)) : len - pos;
        const char *line = text + pos;
        const char *hit = NULL;
        for (size_t i = 0; i + 8 <= ln && !hit; i++) {
            if (memcmp(line + i, pat, 8) == 0)
                hit = line + i;
        }
        if (hit) {
            fo_buf_put(out, line, (size_t)(hit - line));
            fo_buf_puts(out, ", 30, 7, ");
            fo_buf_put(out, hit + 8, ln - (size_t)(hit + 8 - line));
        } else {
            fo_buf_put(out, line, ln);
        }
        if (nl)
            fo_buf_puts(out, "\n");
        pos += ln + (nl ? 1 : 0);
    }
}

/* Third tab-separated column emptied, padding short records to three. */
static void fos_empty_third(const char *line, size_t n, struct fo_buf *out)
{
    size_t pos = 0;
    int idx = 0;
    for (;;) {
        const char *t = memchr(line + pos, '\t', n - pos);
        size_t e = t ? (size_t)(t - line) : n;
        if (idx != 2)
            fo_buf_put(out, line + pos, e - pos);
        if (!t)
            break;
        fo_buf_puts(out, "\t");
        pos = e + 1;
        idx++;
    }
    for (; idx < 2; idx++)
        fo_buf_puts(out, "\t");
}

static void fos_mutate_line(const char *mut, const char *line, size_t n, struct fo_buf *out)
{
    const char *tab = memchr(line, '\t', n);
    if (strcmp(mut, "leading") == 0) {
        fo_buf_puts(out, "\t");
        fo_buf_put(out, line, n);
    } else if (strcmp(mut, "repeated") == 0 && tab) {
        fo_buf_put(out, line, (size_t)(tab - line) + 1);
        fo_buf_put(out, tab, n - (size_t)(tab - line));
    } else if (strcmp(mut, "trailing") == 0) {
        fo_buf_put(out, line, n);
        fo_buf_puts(out, "\t");
    } else if (strcmp(mut, "empty") == 0) {
        fos_empty_third(line, n, out);
    } else if (strcmp(mut, "extra") == 0) {
        fo_buf_put(out, line, n);
        fo_buf_puts(out, "\textra");
    } else {
        fo_buf_put(out, line, n);
    }
}

/* The ledger with its second line mutated; every line ends in a newline. */
static void fos_mutate_ledger(const char *mut, const char *text, size_t len, struct fo_buf *out)
{
    int row = 0;
    for (size_t pos = 0; pos < len;) {
        const char *nl = memchr(text + pos, '\n', len - pos);
        size_t ln = nl ? (size_t)(nl - (text + pos)) : len - pos;
        if (++row == 2)
            fos_mutate_line(mut, text + pos, ln, out);
        else
            fo_buf_put(out, text + pos, ln);
        fo_buf_puts(out, "\n");
        pos += ln + (nl ? 1 : 0);
    }
}

static int fos_same_file(const char *a, const char *b)
{
    struct fo_buf x = { 0 }, y = { 0 };
    int ra = fo_slurp(a, &x), rb = fo_slurp(b, &y);
    int same = ra == 0 && rb == 0 && x.n == y.n && (x.n == 0 || memcmp(x.p, y.p, x.n) == 0);
    fo_buf_free(&x);
    fo_buf_free(&y);
    return same;
}

static int fos_refused_at_row_two(const char *captured)
{
    regex_t re;
    if (regcomp(&re, "rows.tsv:2:", REG_NOSUB) != 0)
        return 0;
    int hit = regexec(&re, captured, 0, NULL, 0) == 0;
    regfree(&re);
    return hit;
}

static int fos_one_mutation(struct fos *s, const char *mut, const struct fo_buf *fixture)
{
    char ledger[FO_PATH + 32], what[128];
    struct fo_buf body = { 0 }, cap = { 0 }, good = { 0 };
    snprintf(ledger, sizeof ledger, "%s/%s.tsv", s->tmp, mut);
    fos_mutate_ledger(mut, fixture->p, fixture->n, &body);
    (void)fo_slurp(s->good, &good);
    int rc = fos_write(ledger, &body) || fos_write(s->bad, &good);
    int st = rc ? FO_SPAWN_FAILED : fos_gen(s, ledger, s->bad, 0, 0, &cap);
    if (st == FO_INTERRUPTED) {
        rc = FOS_STOPPED;
    } else if (st == 2 && fos_refused_at_row_two(cap.p ? cap.p : "")
               && fos_same_file(s->good, s->bad)) {
        printf("  selftest ok: %s column refused without changing output\n", mut);
        rc = FOS_PASS;
    } else {
        snprintf(what, sizeof what, "%s column was not safely refused", mut);
        fos_soft_fail(s, what);
        rc = FOS_PASS;
    }
    fo_buf_free(&body);
    fo_buf_free(&cap);
    fo_buf_free(&good);
    return rc;
}

static int fos_mutations(struct fos *s)
{
    struct fo_buf fixture = { 0 };
    if (fo_slurp(s->c.fixture, &fixture) != 0 || fixture.err) {
        fo_buf_free(&fixture);
        return fos_fail("the fixture ledger could not be read");
    }
    int rc = FOS_PASS;
    for (size_t i = 0; rc == FOS_PASS && i < sizeof k_fos_mutations / sizeof k_fos_mutations[0]; i++)
        rc = fos_one_mutation(s, k_fos_mutations[i], &fixture);
    fo_buf_free(&fixture);
    return rc;
}

static int fos_hand_edit(struct fos *s)
{
    struct fo_buf good = { 0 }, edited = { 0 };
    (void)fo_slurp(s->good, &good);
    fos_widen_rows(good.p ? good.p : "", good.n, &edited);
    int changed = edited.n != good.n || (good.n && memcmp(good.p, edited.p, good.n) != 0);
    int rc = FOS_PASS;
    if (!changed) {
        fos_soft_fail(s, "the sed edit did not change the fixture copy");
    } else if (fos_write(s->bad, &edited) != 0) {
        rc = fos_fail("cannot write the edited copy");
    } else {
        int st = fos_gen(s, s->c.fixture, s->bad, 1, 1, NULL);
        if (st == FO_INTERRUPTED)
            rc = FOS_STOPPED;
        else if (st == 0)
            fos_soft_fail(s, "a hand-edited row passed --check");
        else
            printf("  selftest ok: a hand-edited row fails --check\n");
    }
    fo_buf_free(&good);
    fo_buf_free(&edited);
    return rc;
}

static int fos_regenerate(struct fos *s)
{
    snprintf(s->good, sizeof s->good, "%s/good.def", s->tmp);
    snprintf(s->bad, sizeof s->bad, "%s/bad.def", s->tmp);
    if (fos_gen(s, s->c.fixture, s->good, 1, 0, NULL) == FO_INTERRUPTED)
        return FOS_STOPPED;
    struct stat st;
    if (stat(s->good, &st) != 0 || st.st_size == 0)
        return fos_fail("a clean regeneration from the fixture produced nothing");
    int chk = fos_gen(s, s->c.fixture, s->good, 1, 1, NULL);
    if (chk == FO_INTERRUPTED)
        return FOS_STOPPED;
    if (chk == 0)
        printf("  selftest ok: a fresh regeneration matches itself\n");
    else
        fos_soft_fail(s, "a regeneration did not --check clean against itself");
    return FOS_PASS;
}

static int fos_missing_def(struct fos *s)
{
    char missing[FO_PATH + 32];
    snprintf(missing, sizeof missing, "%s/missing.def", s->tmp);
    int st = fos_gen(s, s->c.fixture, missing, 1, 1, NULL);
    if (st == FO_INTERRUPTED)
        return FOS_STOPPED;
    if (st == 0)
        fos_soft_fail(s, "a missing committed file passed --check");
    else
        printf("  selftest ok: a missing committed file fails --check\n");
    return FOS_PASS;
}

static int fos_steps(struct fos *s)
{
    int rc = fos_regenerate(s);
    if (rc == FOS_PASS)
        rc = fos_hand_edit(s);
    if (rc == FOS_PASS)
        rc = fos_missing_def(s);
    if (rc == FOS_PASS)
        rc = fos_mutations(s);
    return rc;
}

static void fos_remove_dir(const char *dir)
{
    DIR *d = opendir(dir);
    struct dirent *de;
    while (d && (de = readdir(d)) != NULL) {
        char path[FO_PATH + 300];
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
            continue;
        if (snprintf(path, sizeof path, "%s/%s", dir, de->d_name) < (int)sizeof path)
            (void)unlink(path);
    }
    if (d)
        closedir(d);
    (void)rmdir(dir);
}

static int fos_run(struct fos *s)
{
    if (access(s->c.bin, X_OK) != 0) {
        fprintf(stderr, "%s: SELFTEST FAILED — generator binary '%s' is missing or not executable\n",
                k_fo_gate, s->c.bin);
        return FOS_FAILED;
    }
    struct stat st;
    if (stat(s->c.fixture, &st) != 0 || !S_ISREG(st.st_mode)) {
        fprintf(stderr, "%s: SELFTEST FAILED — fixture ledger '%s' is missing\n", k_fo_gate,
                s->c.fixture);
        return FOS_FAILED;
    }
    const char *base = env_or("TMPDIR", "test-tmp");
    (void)mkdir(base, 0777);
    if (snprintf(s->tmp, sizeof s->tmp, "%s/z23-fleet-obs.XXXXXX", base) >= (int)sizeof s->tmp
        || !mkdtemp(s->tmp)) {
        fprintf(stderr, "%s: SELFTEST FAILED — cannot create a scratch directory\n", k_fo_gate);
        return FOS_FAILED;
    }
    int rc = fos_steps(s);
    fos_remove_dir(s->tmp);
    return rc;
}

int check_fleet_observations_selftest(void)
{
    struct fos s;
    memset(&s, 0, sizeof s);
    int rc = fo_cfg_load(&s.c);
    if (rc)
        return rc;
    struct fo_sigs sigs;
    fo_sigs_arm(&sigs);
    rc = fos_run(&s);
    if (rc == FOS_PASS && s.fails == 0)
        printf("[%s] SELFTEST PASS (a fresh regeneration checks clean; a hand-edited row and a "
               "missing file both fail --check)\n", k_fo_gate);
    fflush(stdout);
    return fo_finish(&sigs, rc != FOS_PASS || s.fails ? 1 : 0);
}
