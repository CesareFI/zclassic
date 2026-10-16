/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: self-test of check-accel-oracle-pinned. Builds a synthetic
 * repository (two ISA-dispatched implementations reached from core/, their
 * oracles, a registry and a test group catalog) in a scratch directory,
 * proves it passes, then proves each failure class is rejected: an
 * unregistered ISA file, a malformed row, a stale row, a missing marker, an
 * unregistered test group, an oracle naming no export, and a collapsed scan
 * floor or missing registry (exit 2). The scratch directory is removed on
 * exit and after SIGINT, SIGTERM or SIGHUP.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "gate_accel_oracle_pinned_priv.h"
#include "lintc.h"
#include "lintc_sig.h"

enum { AOPS_PATH = 4096, AOPS_OUT = 16384 };

struct aops_file { const char *path; const char *text; };

#define AOPS_SHA "core/modules/crypto/src/sha.c"
#define AOPS_FAST "core/modules/crypto/src/fast_avx.c"
#define AOPS_REG "tools/lint/accel_oracle_registry.txt"
#define AOPS_CAT "tools/dev/test_group_catalog.def"

static const char k_aops_reg_sha[] =
    "# registry\n" AOPS_SHA " tests/sha_oracle.c sha_group\n";
static const char k_aops_reg_full[] =
    "# registry\n" AOPS_SHA " tests/sha_oracle.c sha_group\n"
    AOPS_FAST " tests/fast_oracle.c fast_group  # trailing comment\n";

static const struct aops_file k_aops_base[] = {
    { "core/consensus/src/a.c", "#include \"crypto/sha.h\"\nint a(void) { return 0; }\n" },
    { "core/modules/crypto/include/crypto/sha.h", "int sha_digest(int x);\n" },
    { "core/modules/crypto/include/crypto/fast.h", "int fast_hash(int x);\n" },
    { AOPS_SHA, "#include \"crypto/fast.h\"\n#include \"sha_priv.h\"\n"
                "int sha_digest(int x) {\n    return fast_hash(x);\n}\n"
                "static int sha_helper(void) {\n    return 0;\n}\n" },
    { "core/modules/crypto/src/sha_priv.h", "#include <immintrin.h>\n" },
    { AOPS_FAST, "int fast_hash(int x) {\n"
                 "    return __builtin_cpu_supports(\"avx2\") ? x : -x;\n}\n" },
    { "tests/sha_oracle.c", "/* ACCEL-ORACLE: " AOPS_SHA " */\n"
                            "int t(void) { return sha_digest(1); }\n" },
    { "tests/fast_oracle.c", "/* ACCEL-ORACLE: " AOPS_FAST " */\n"
                             "int t(void) { return fast_hash(1); }\n" },
    { AOPS_REG, k_aops_reg_full },
    { AOPS_CAT, "ZCL_TEST_GROUP(sha_group)\nZCL_TEST_GROUP(fast_group)\n" },
};

struct aops_case {
    const char *name;
    const char *path;
    const char *text;
    const struct aop_cfg *cfg;
    int want_rc;
    const char *needle;
};

static const struct aop_cfg k_aops_cfg = { AOPS_REG, AOPS_CAT, 2, 2, 2, 2, 1 };
static const struct aop_cfg k_aops_cfg_hollow = { AOPS_REG, AOPS_CAT, 100, 2, 2, 2, 1 };
static const struct aop_cfg k_aops_cfg_nolist = { "tools/lint/absent.txt", AOPS_CAT, 2, 2, 2, 2, 1 };

static const struct aops_case k_aops_cases[] = {
    { "the synthetic tree passes", NULL, NULL, &k_aops_cfg, 0, "OK: 2 ISA-dispatched" },
    { "an unregistered ISA file", AOPS_REG, k_aops_reg_sha, &k_aops_cfg, 1,
      AOPS_FAST " is ISA-dispatched and reachable" },
    { "a malformed row", AOPS_REG, "# registry\n" AOPS_SHA " tests/sha_oracle.c sha_group\nbad.c oracle.c\n",
      &k_aops_cfg, 1, "malformed row" },
    { "a stale row", AOPS_REG,
      "# registry\n" AOPS_SHA " tests/sha_oracle.c sha_group\n"
      AOPS_FAST " tests/fast_oracle.c fast_group\n"
      "core/modules/crypto/src/gone.c tests/gone.c g\n",
      &k_aops_cfg, 1, "gone.c', which does not exist" },
    { "a missing marker", "tests/fast_oracle.c", "int t(void) { return fast_hash(1); }\n",
      &k_aops_cfg, 1, "does not carry the marker line" },
    { "an unregistered group", AOPS_CAT, "ZCL_TEST_GROUP(sha_group)\n",
      &k_aops_cfg, 1, "test group 'fast_group'" },
    { "an oracle naming no export", "tests/sha_oracle.c",
      "/* ACCEL-ORACLE: " AOPS_SHA " */\nint t(void) { return sha_digestx(1); }\n",
      &k_aops_cfg, 1, "references no function exported" },
    { "a collapsed header floor", NULL, NULL, &k_aops_cfg_hollow, 2, "FATAL" },
    { "a missing registry", NULL, NULL, &k_aops_cfg_nolist, 2, "FATAL — missing" },
};

static int aops_fail(const char *what, const char *detail)
{
    fprintf(stderr, "check_accel_oracle_pinned: selftest FAIL: %s%s%s\n", what,
            detail[0] ? ": " : "", detail);
    return 1;
}

static int aops_put_base(const char *path)
{
    for (size_t i = 0; i < sizeof k_aops_base / sizeof k_aops_base[0]; i++)
        if (strcmp(k_aops_base[i].path, path) == 0)
            return csr_write(path, k_aops_base[i].text);
    return 2;
}

static int aops_populate(void)
{
    for (size_t i = 0; i < sizeof k_aops_base / sizeof k_aops_base[0]; i++)
        if (csr_write(k_aops_base[i].path, k_aops_base[i].text) != 0)
            return 2;
    return 0;
}

static int aops_git_track(void)
{
    char out[1024];
    int code = 0;
    int rc = capture_cmd("env -u GIT_DIR -u GIT_INDEX_FILE -u GIT_WORK_TREE "
                         "GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null "
                         "sh -c 'git init -q . && git add -A' 2>&1", out, sizeof out, &code);
    return rc == 0 && code == 0 ? 0 : 2;
}

/* Runs the gate with stdout and stderr captured into out. */
static int aops_run(const struct aop_cfg *cfg, char *out, size_t cap)
{
    int so = dup(1), se = dup(2);
    int fd = open("capture.txt", O_WRONLY | O_CREAT | O_TRUNC, 0600);
    int rc = -1;
    size_t n = 0;
    FILE *f;
    out[0] = '\0';
    if (so < 0 || se < 0 || fd < 0)
        return -1;
    fflush(stdout);
    fflush(stderr);
    if (dup2(fd, 1) >= 0 && dup2(fd, 2) >= 0)
        rc = aop_run_cfg(cfg);
    fflush(stdout);
    fflush(stderr);
    dup2(so, 1);
    dup2(se, 2);
    close(so);
    close(se);
    close(fd);
    f = fopen("capture.txt", "r");
    if (f) {
        n = fread(out, 1, cap - 1, f);
        fclose(f);
    }
    out[n] = '\0';
    return rc;
}

static int aops_case(const struct aops_case *k)
{
    char out[AOPS_OUT];
    int rc;
    if (k->path && csr_write(k->path, k->text) != 0)
        return aops_fail(k->name, "cannot write the mutation");
    rc = aops_run(k->cfg, out, sizeof out);
    if (k->path && aops_put_base(k->path) != 0)
        return aops_fail(k->name, "cannot restore the fixture");
    if (rc != k->want_rc) {
        fprintf(stderr, "%s", out);
        return aops_fail(k->name, "unexpected exit code");
    }
    if (!strstr(out, k->needle)) {
        fprintf(stderr, "%s", out);
        return aops_fail(k->name, "expected message missing");
    }
    return 0;
}

static int aops_cases(void)
{
    for (size_t i = 0; i < sizeof k_aops_cases / sizeof k_aops_cases[0]; i++) {
        int rc = aops_case(&k_aops_cases[i]);
        if (rc || lsc_pending())
            return rc;
    }
    return 0;
}

static int aops_in_fixture(const char *dir)
{
    char old[AOPS_PATH];
    int rc;
    if (!getcwd(old, sizeof old) || chdir(dir) != 0)
        return aops_fail("cannot enter the scratch directory", dir);
    rc = aops_populate() || aops_git_track()
        ? aops_fail("cannot build the synthetic tree", dir) : aops_cases();
    if (chdir(old) != 0)
        rc = rc ? rc : aops_fail("cannot return to the working directory", old);
    return rc;
}

static int aops_scratch(char *dir, size_t cap)
{
    const char *tmp = env_or("TMPDIR", "test-tmp");
    if (csr_mkdirs(tmp) != 0
        || snprintf(dir, cap, "%s/accel-oracle-pinned.XXXXXX", tmp) >= (int)cap)
        return -1;
    return mkdtemp(dir) ? 0 : -1;
}

int check_accel_oracle_pinned_selftest(void)
{
    char dir[AOPS_PATH];
    int rc, sig;
    if (lsc_install() != 0 || aops_scratch(dir, sizeof dir) != 0)
        return aops_fail("cannot create the scratch directory", "");
    lsc_unblock();
    rc = aops_in_fixture(dir);
    lsc_block();
    rap_rm_rf(dir);
    sig = lsc_pending();
    if (sig)
        lsc_finish(sig);
    if (rc == 0)
        puts("check_accel_oracle_pinned: selftest OK (pass, unregistered ISA file, "
             "malformed row, stale row, missing marker, unregistered group, "
             "unwired oracle, collapsed floor, missing registry)");
    return rc;
}
