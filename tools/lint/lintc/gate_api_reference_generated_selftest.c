/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: selftest of check-api-reference-generated. Copies exactly what the
 * gate reads into a scratch tree, proves the gate passes on it, then flips
 * one availability cell of the copied reference and proves the gate fails and
 * names docs/API_REFERENCE.md, so the gate cannot decay into a no-op.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "gate_api_reference_generated_priv.h"
#include "lintc.h"
#include "lintc_sig.h"

enum { ARS_LOG = 65536 };

static const char ars_planted_from[] = "| planned |";
static const char ars_planted_to[] = "| ready |";
static const char ars_name[] = "check_api_reference_generated selftest";

static const char *const ars_fixed[] = {
    "engine/modules/kernel/include/kernel/command_registry.h",
    "platform/modules/json/include/json/json.h",
    "platform/modules/base/include/base/cleanse.h",
};

static int ars_copy(const char *root, const char *rel)
{
    char dst[PATH_MAX + 256], buf[8192];
    size_t n;
    int rc = 0;
    snprintf(dst, sizeof dst, "%s/%s", root, rel);
    FILE *in = fopen(rel, "rb");
    if (!in)
        return die("z23-lint: cannot open %s\n", rel);
    char *slash = strrchr(dst, '/');
    *slash = '\0';
    rc = csr_mkdirs(dst);
    *slash = '/';
    FILE *out = rc ? NULL : fopen(dst, "wb");
    while (out && (n = fread(buf, 1, sizeof buf, in)) > 0)
        if (fwrite(buf, 1, n, out) != n)
            rc = die("z23-lint: write failed: %s\n", dst);
    if (!out && rc == 0)
        rc = die("z23-lint: cannot open %s\n", dst);
    if (out && fclose(out) != 0 && rc == 0)
        rc = die("z23-lint: write failed: %s\n", dst);
    fclose(in);
    return rc;
}

static int ars_populate(const char *root)
{
    struct arg_defs d;
    int rc = arg_def_list(&d);
    for (size_t i = 0; rc == 0 && i < d.n; i++)
        rc = ars_copy(root, d.path[i]);
    for (size_t i = 0; rc == 0 && i < sizeof ars_fixed / sizeof ars_fixed[0]; i++)
        rc = ars_copy(root, ars_fixed[i]);
    const char *const own[] = { arg_gen_src, arg_template, arg_doc };
    for (size_t i = 0; rc == 0 && i < sizeof own / sizeof own[0]; i++)
        rc = ars_copy(root, own[i]);
    return rc;
}

/* Runs the gate in root with all output captured into log (a tmpfile). */
static int ars_run(const char *root, const char *home, FILE *log)
{
    struct arg_io io = { log, log };
    if (chdir(root) != 0)
        return 2;
    int rc = arg_gate(&io);
    if (chdir(home) != 0)
        return 2;
    fflush(log);
    rewind(log);
    return rc;
}

/* Copies src to dst, rewriting the first planted cell; *found says whether it did. */
static int ars_rewrite(FILE *src, FILE *dst, int *found)
{
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    int bad = 0;
    *found = 0;
    while (!bad && (n = getline(&line, &cap, src)) >= 0) {
        char *at = *found ? NULL : strstr(line, ars_planted_from);
        if (at) {
            *at = '\0';
            bad = fprintf(dst, "%s%s%s", line, ars_planted_to, at + sizeof ars_planted_from - 1) < 0;
            *found = 1;
        } else {
            bad = fwrite(line, 1, (size_t)n, dst) != (size_t)n;
        }
    }
    free(line);
    return bad || ferror(src);
}

static int ars_flip(const char *root)
{
    char path[PATH_MAX + 64], next[PATH_MAX + 80];
    int found = 0;
    snprintf(path, sizeof path, "%s/%s", root, arg_doc);
    snprintf(next, sizeof next, "%s.next", path);
    FILE *in = fopen(path, "rb"), *out = fopen(next, "wb");
    int bad = !in || !out || ars_rewrite(in, out, &found);
    if (in)
        fclose(in);
    if (out && fclose(out) != 0)
        bad = 1;
    if (bad || !found || rename(next, path) != 0) {
        fprintf(stderr, "%s: FAIL — no 'planned' row\n  to tamper with; the fixture assumption broke.\n",
                ars_name);
        return 1;
    }
    return 0;
}

static int ars_expect(const char *root, const char *home, int tampered)
{
    FILE *log = tmpfile();
    if (!log)
        return die("z23-lint: cannot create a temporary file\n", "");
    char text[ARS_LOG];
    int rc = ars_run(root, home, log);
    if (csr_slurp(log, text, sizeof text) != 0)
        text[0] = '\0';
    fclose(log);
    int bad = tampered ? (rc == 0 || !strstr(text, arg_doc)) : rc != 0;
    if (bad) {
        fprintf(stderr, tampered ? (rc == 0 ? "%s: FAIL — a hand edit to\n  %s did NOT trip the gate. The gate is hollow.\n"
                                            : "%s: FAIL — the failure did\n  not name %s:\n")
                                 : "%s: FAIL — the gate did not\n  pass on an unmodified copy of the tree (%s):\n",
                ars_name, arg_doc);
        if (rc != 0 || !tampered)
            arg_indent(stderr, text, 0);
    }
    return bad;
}

static int ars_cases(const char *root, const char *home)
{
    if (ars_populate(root) != 0)
        return 1;
    if (ars_expect(root, home, 0) || lsc_pending())
        return 1;
    if (ars_flip(root) != 0)
        return 1;
    return ars_expect(root, home, 1);
}

int check_api_reference_generated_selftest(void)
{
    char home[PATH_MAX], root[PATH_MAX + 32], sandbox[PATH_MAX + 48];
    if (cic_repo_root(home, sizeof home) != 0 || chdir(home) != 0 || lsc_install() != 0)
        return 2;
    if (snprintf(root, sizeof root, "%s/zcl-apiref-selftest.XXXXXX",
                 env_or("TMPDIR", arg_tmp_default)) >= (int)sizeof root || !mkdtemp(root))
        return die("z23-lint: cannot create a scratch directory\n", "");
    snprintf(sandbox, sizeof sandbox, "%s/repo", root);
    int rc = csr_mkdirs(sandbox) != 0 ? 1 : ars_cases(sandbox, home);
    int sig = lsc_pending();
    (void)rap_rm_rf(root);
    if (sig)
        lsc_finish(sig);
    if (rc == 0)
        printf("%s: PASS — clean tree passes, a planted hand edit fails and names %s\n",
               ars_name, arg_doc);
    return rc;
}
