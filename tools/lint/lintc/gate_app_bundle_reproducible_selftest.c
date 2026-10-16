/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: selftests of the check-app-bundle-reproducible gate family.
 * abr_unit_checks runs on every host: it plants a tampered file in a fake
 * bundle tree and requires the manifest compare to name it, requires a probe
 * printing the wrong value (or exiting nonzero) to be rejected and the right
 * one accepted, and pins the mode string. abr_selftest_darwin is the bash
 * gate's --selftest on a real signed bundle: tampered PkgInfo named, flipped
 * Mach-O byte rejected by codesign, wrong probe value rejected.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "gate_app_bundle_reproducible_priv.h"
#include "lintc.h"
#include "lintc_sig.h"

enum { ABR_FLIP_OFFSET = 4096 };

static int abr_st_fail(const char *what)
{
    fprintf(stderr, "%s: FAIL (selftest) — %s\n", ABR_GATE, what);
    return ABR_FAIL;
}

/* Runs compare on two manifest files with the diagnostics captured into
 * *msg (caller frees); ABR_OK means the compare accepted them. */
static int abr_compare_captured(const char *a, const char *b, char **msg)
{
    size_t len = 0;
    FILE *mem = open_memstream(msg, &len);
    if (!mem)
        return abr_fatal("out of memory");
    int rc = abr_compare("selftest", a, b, mem);
    fclose(mem);
    return rc;
}

/* A tampered file must be caught and named. */
static int abr_st_tamper(const char *good_m, const char *bad_m)
{
    char *msg = NULL;
    int rc = abr_compare_captured(good_m, bad_m, &msg);
    if (rc == ABR_OK)
        rc = abr_st_fail("the manifest compare ACCEPTED a tampered PkgInfo");
    else if (rc == ABR_FAIL && !strstr(msg ? msg : "", "PkgInfo")) {
        rc = abr_st_fail("the manifest compare caught a difference but did not name the file:");
        fputs(msg ? msg : "", stderr);
    } else if (rc == ABR_FAIL)
        rc = ABR_OK;
    free(msg);
    return rc;
}

static int abr_st_tree(const char *root, const char *pkginfo)
{
    static const char *const dirs[] = { "", "/Contents", "/Contents/MacOS" };
    static const char *const names[] = { "Info.plist", "MacOS/x", "CodeResources" };
    char p[ABR_PATH];
    int rc;
    for (size_t i = 0; i < 3; i++) {
        if ((rc = abr_pathf(p, "%s%s", root, dirs[i])))
            return rc;
        if (mkdir(p, 0777) != 0)
            return abr_fatal("cannot create %s", p);
    }
    for (size_t i = 0; i < 3; i++) {
        if ((rc = abr_pathf(p, "%s/Contents/%s", root, names[i]))
            || (rc = abr_write_file(p, names[i], strlen(names[i]))))
            return rc;
    }
    if ((rc = abr_pathf(p, "%s/Contents/PkgInfo", root)))
        return rc;
    return abr_write_file(p, pkginfo, strlen(pkginfo));
}

static int abr_unit_manifest(const char *tmp)
{
    char good[ABR_PATH], bad[ABR_PATH], gm[ABR_PATH], bm[ABR_PATH];
    int lines, rc = abr_pathf(good, "%s/good", tmp);
    char sha[ZSHA256_HEX_LEN];
    if (rc || (rc = abr_pathf(bad, "%s/bad", tmp)) || (rc = abr_st_tree(good, "APPL????"))
        || (rc = abr_st_tree(bad, "APPL??XX")))
        return rc;
    if ((rc = abr_manifest_tree(good, tmp, "g", &lines, sha))
        || (rc = abr_manifest_tree(bad, tmp, "b", &lines, sha)))
        return rc;
    if (lines != 4)
        return abr_st_fail("the manifest does not list the four files of the fake bundle");
    if ((rc = abr_pathf(gm, "%s/content.g", tmp)) || (rc = abr_pathf(bm, "%s/content.b", tmp)))
        return rc;
    return abr_st_tamper(gm, bm);
}

static int abr_unit_probe(const char *tmp)
{
    struct abr_ctx c = { .app = "x" };
    char exe[ABR_PATH], right[ABR_PATH], wrong[ABR_PATH];
    static const char script[] = "#!/bin/sh\nsed -n 's/.*\"b\":\"\\([^\"]*\\)\".*/\\1/p'\n";
    static const char r[] = ABR_PROBE_JSON, w[] = "{\"a\":{\"b\":\"not-the-expected-value\"}}";
    int rc = abr_pathf(exe, "%s/probe.sh", tmp);
    if (rc || (rc = abr_pathf(right, "%s/right.json", tmp)) || (rc = abr_pathf(wrong, "%s/wrong.json", tmp))
        || (rc = abr_write_file(exe, script, strlen(script))) || (rc = abr_write_file(right, r, strlen(r)))
        || (rc = abr_write_file(wrong, w, strlen(w))))
        return rc;
    if (chmod(exe, 0755) != 0)
        return abr_fatal("cannot chmod %s", exe);
    if (abr_probe(&c, exe, wrong, NULL) != ABR_FAIL)
        return abr_st_fail("the launch probe ACCEPTED a wrong probe value");
    if (abr_probe(&c, exe, right, NULL) != ABR_OK)
        return abr_st_fail("the launch probe now rejects a CORRECT probe value");
    c.bin = exe;
    c.probe_expect = "absent-token";
    return abr_probe(&c, exe, right, NULL) == ABR_FAIL
        ? ABR_OK : abr_st_fail("the --bin probe ACCEPTED output without the expected string");
}

static int abr_unit_mode(void)
{
    char m[11];
    abr_mode_string(0100755, m);
    if (strcmp(m, "-rwxr-xr-x") != 0)
        return abr_st_fail("mode string of 0755 is not -rwxr-xr-x");
    abr_mode_string(0104644, m);
    return strcmp(m, "-rwSr--r--") == 0 ? ABR_OK : abr_st_fail("setuid mode string is wrong");
}

static int abr_unit_run(void)
{
    char tmp[ABR_PATH];
    const char *base = env_or("TMPDIR", "test-tmp");
    int rc = csr_mkdirs(base) != 0 ? abr_fatal("could not create a temp dir")
                                   : abr_pathf(tmp, "%s/zcl-app-bundle-unit.XXXXXX", base);
    if (rc || !mkdtemp(tmp))
        return rc ? rc : abr_fatal("could not create a temp dir");
    rc = abr_unit_mode();
    if (!rc)
        rc = abr_unit_manifest(tmp);
    if (!rc)
        rc = abr_unit_probe(tmp);
    if (rap_rm_rf(tmp) != 0 && !rc)
        rc = abr_fatal("could not remove %s", tmp);
    return rc;
}

/* Host-independent checks of the manifest compare, the probe and the mode
 * string. Returns 0 when all hold. A termination signal received meanwhile
 * is re-raised after the scratch directory is gone. */
int abr_unit_checks(void)
{
    int rc, sig;
    if (lsc_install() != 0)
        return abr_fatal("could not install the signal handlers");
    rc = abr_unit_run();
    fflush(stdout);
    lsc_unblock();
    sig = lsc_pending();
    if (sig)
        lsc_finish(sig);
    return rc;
}

static int abr_st_flip(const char *exe)
{
    int fd = open(exe, O_WRONLY);
    ssize_t n = fd < 0 ? -1 : pwrite(fd, "X", 1, ABR_FLIP_OFFSET);
    if (fd >= 0)
        close(fd);
    return n == 1 ? ABR_OK : abr_fatal("cannot modify %s", exe);
}

/* A broken embedded signature must be caught by the verify step. */
static int abr_st_signature(const struct abr_ctx *c, const char *st, const char *bundle)
{
    char tampered[ABR_PATH], exe[ABR_PATH];
    int rc = abr_pathf(tampered, "%s/tampered", st);
    if (rc || (rc = abr_copy_tree(bundle, tampered))
        || (rc = abr_pathf(exe, "%s/Contents/MacOS/%s", tampered, c->app)) || (rc = abr_st_flip(exe)))
        return rc;
    rc = abr_verify_signature(tampered, NULL);
    if (rc == ABR_OK)
        return abr_st_fail("the signature check ACCEPTED a Mach-O with a flipped byte");
    return rc == ABR_FAIL ? ABR_OK : rc;
}

/* A probe printing the WRONG value must be rejected, the right one accepted. */
static int abr_st_probe(const struct abr_ctx *c, const char *st, const char *good)
{
    char exe[ABR_PATH], wrong[ABR_PATH], right[ABR_PATH];
    static const char w[] = "{\"a\":{\"b\":\"not-the-expected-value\"}}";
    int rc = abr_pathf(exe, "%s/Contents/MacOS/%s", good, c->app);
    if (rc || (rc = abr_pathf(wrong, "%s/wrong.json", st)) || (rc = abr_pathf(right, "%s/right.json", st))
        || (rc = abr_write_file(wrong, w, strlen(w)))
        || (rc = abr_write_file(right, ABR_PROBE_JSON, strlen(ABR_PROBE_JSON))))
        return rc;
    rc = abr_probe(c, exe, wrong, NULL);
    if (rc == ABR_OK)
        return abr_st_fail("the launch probe ACCEPTED a wrong probe value");
    if (rc != ABR_FAIL)
        return rc;
    rc = abr_probe(c, exe, right, stderr);
    return rc == ABR_FAIL ? abr_st_fail("the launch probe now rejects a CORRECT probe value") : rc;
}

static int abr_st_bundles(struct abr_ctx *c, const char *st, char bundle[ABR_PATH],
                          char good[ABR_PATH], char bad[ABR_PATH])
{
    char exe[ABR_PATH];
    int rc = abr_pathf(exe, "%s/%s", st, c->app);
    if (rc || (rc = abr_compile_subject(exe))
        || (rc = abr_bundle(c, exe, st, bundle, "bundler failed during selftest"))
        || (rc = abr_pathf(good, "%s/good", st)) || (rc = abr_pathf(bad, "%s/bad", st))
        || (rc = abr_copy_tree(bundle, good)))
        return rc;
    return abr_copy_tree(bundle, bad);
}

static int abr_st_pkginfo(const char *st, const char *good, const char *bad)
{
    char p[ABR_PATH], gm[ABR_PATH], bm[ABR_PATH];
    struct abr_text t = { 0 };
    int rc = abr_pathf(p, "%s/Contents/PkgInfo", bad);
    if (rc || (rc = abr_write_file(p, "APPL??XX", 8)) || (rc = abr_pathf(gm, "%s/good.m", st))
        || (rc = abr_pathf(bm, "%s/bad.m", st)))
        return rc;
    if (!(rc = abr_content_manifest(good, &t)) && !(rc = abr_write_file(gm, t.p, t.n))) {
        abr_text_free(&t);
        if (!(rc = abr_content_manifest(bad, &t)))
            rc = abr_write_file(bm, t.p, t.n);
    }
    abr_text_free(&t);
    return rc ? rc : abr_st_tamper(gm, bm);
}

/* The bash gate's --selftest: every negative must be catchable. */
int abr_selftest_darwin(struct abr_ctx *c)
{
    char st[ABR_PATH], bundle[ABR_PATH], good[ABR_PATH], bad[ABR_PATH];
    int rc = abr_pathf(st, "%s/selftest", c->tmp);
    if (rc)
        return rc;
    if (mkdir(st, 0777) != 0)
        return abr_fatal("could not create %s", st);
    if ((rc = abr_st_bundles(c, st, bundle, good, bad)) || (rc = abr_st_pkginfo(st, good, bad))
        || (rc = abr_st_signature(c, st, bundle)) || (rc = abr_st_probe(c, st, good)))
        return rc;
    puts(ABR_GATE ": selftest OK — tampered file named, flipped-byte signature rejected, "
         "wrong probe value rejected");
    return ABR_OK;
}
