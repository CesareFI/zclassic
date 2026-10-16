/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: selftests of the check-app-bundle-reproducible gate family.
 * abr_unit_checks runs on every host: it plants a tampered file in a fake
 * bundle tree and requires the manifest compare to name it, requires a probe
 * printing the wrong value (or exiting nonzero) to be rejected and the right
 * one accepted, pins the mode string, and drives the directory walk through
 * an injected readdir error and an over-deep tree. abr_selftest_darwin is the bash
 * gate's --selftest on a real signed bundle: tampered PkgInfo named, flipped
 * Mach-O byte rejected by codesign, wrong probe value rejected.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <errno.h>
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
    char *msg = NULL;
    rc = abr_compare_captured(gm, gm, &msg);
    free(msg);
    if (rc != ABR_OK)
        return abr_st_fail("the manifest compare REJECTED two identical manifests");
    return abr_st_tamper(gm, bm);
}

/* Writes an executable stub script (body is the sh text after the shebang). */
static int abr_unit_stub(const char *tmp, const char *name, const char *body, char exe[ABR_PATH])
{
    char text[256];
    int rc = abr_pathf(exe, "%s/%s", tmp, name);
    if (rc || (rc = abr_pathf(text, "#!/bin/sh\n%s\n", body))
        || (rc = abr_write_file(exe, text, strlen(text))))
        return rc;
    return chmod(exe, 0755) == 0 ? ABR_OK : abr_fatal("cannot chmod %s", exe);
}

/* Exit status, and the --bin non-empty-output rule without --probe-expect. */
static int abr_unit_bin(const char *tmp)
{
    struct abr_ctx c = { .app = "x" };
    char exe[ABR_PATH];
    int rc = abr_unit_stub(tmp, "exit3.sh", "echo hello-bundle; exit 3", exe);
    if (rc)
        return rc;
    if (abr_probe(&c, exe, "/dev/null", NULL) != ABR_FAIL)
        return abr_st_fail("the launch probe ACCEPTED a nonzero exit with the right output");
    c.bin = exe;
    c.probe_expect = ABR_PROBE_EXPECT;
    if (abr_probe(&c, exe, "/dev/null", NULL) != ABR_FAIL)
        return abr_st_fail("the --bin probe ACCEPTED a nonzero exit with the right output");
    c.probe_expect = NULL;
    if (abr_probe(&c, exe, "/dev/null", NULL) != ABR_FAIL)
        return abr_st_fail("the --bin probe ACCEPTED a nonzero exit without --probe-expect");
    if ((rc = abr_unit_stub(tmp, "hello.sh", "echo hello-bundle", exe)))
        return rc;
    c.bin = exe;
    c.probe_expect = "absent-token";
    if (abr_probe(&c, exe, "/dev/null", NULL) != ABR_FAIL)
        return abr_st_fail("the --bin probe ACCEPTED output without the expected string");
    c.probe_expect = ABR_PROBE_EXPECT;
    if (abr_probe(&c, exe, "/dev/null", NULL) != ABR_OK)
        return abr_st_fail("the --bin probe rejected output containing the expected string");
    c.probe_expect = NULL;
    if ((rc = abr_unit_stub(tmp, "silent.sh", "exit 0", exe)))
        return rc;
    c.bin = exe;
    if (abr_probe(&c, exe, "/dev/null", NULL) != ABR_FAIL)
        return abr_st_fail("the --bin probe ACCEPTED empty output without --probe-expect");
    if ((rc = abr_unit_stub(tmp, "noisy.sh", "echo anything", exe)))
        return rc;
    c.bin = exe;
    return abr_probe(&c, exe, "/dev/null", NULL) == ABR_OK
        ? ABR_OK : abr_st_fail("the --bin probe rejected non-empty output without --probe-expect");
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
    return abr_unit_bin(tmp);
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

#ifdef ZCL_TESTING
/* Redirects stderr into file for the duration of one call; abr_err_read
 * restores it and copies the captured text into out. */
static int abr_err_redirect(const char *file, int *saved)
{
    int fd = open(file, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    fflush(stderr);
    *saved = fd < 0 ? -1 : dup(STDERR_FILENO);
    if (*saved >= 0)
        dup2(fd, STDERR_FILENO);
    if (fd >= 0)
        close(fd);
    return *saved >= 0 ? ABR_OK : abr_fatal("cannot capture diagnostics");
}

static void abr_err_read(const char *file, int saved, char out[ABR_PATH])
{
    size_t n = 0;
    FILE *f;
    fflush(stderr);
    dup2(saved, STDERR_FILENO);
    close(saved);
    f = fopen(file, "r");
    if (f) {
        n = fread(out, 1, ABR_PATH - 1, f);
        fclose(f);
    }
    out[n] = '\0';
}

/* Walks root with the seam armed; the diagnostics land in *msg. */
static int abr_unit_walk(const char *root, const char *tmp, const char *tag, struct abr_seam arm,
                         char msg[ABR_PATH])
{
    char log[ABR_PATH];
    int saved, lines, rc = abr_pathf(log, "%s/walk.log", tmp);
    char sha[ZSHA256_HEX_LEN];
    if (rc || (rc = abr_err_redirect(log, &saved)))
        return rc;
    abr_seam = arm;
    rc = abr_manifest_tree(root, tmp, tag, &lines, sha);
    abr_err_read(log, saved, msg);
    return rc;
}

static int abr_unit_no_manifest(const char *tmp, const char *tag)
{
    char p[ABR_PATH];
    int rc = abr_pathf(p, "%s/content.%s", tmp, tag);
    if (rc)
        return rc;
    return access(p, F_OK) != 0 ? ABR_OK
        : abr_st_fail("a refused walk left a partial content manifest");
}

static int abr_unit_balanced(void)
{
    return abr_seam.opened == abr_seam.closed ? ABR_OK
        : abr_st_fail("the walk leaked a directory handle");
}

static int abr_unit_walk_tree(const char *tmp, char root[ABR_PATH])
{
    char p[ABR_PATH];
    int rc = abr_pathf(root, "%s/walk", tmp);
    if (rc || (mkdir(root, 0777) != 0))
        return rc ? rc : abr_fatal("cannot create %s", root);
    for (const char *n = "ab"; *n; n++) {
        if ((rc = abr_pathf(p, "%s/%c", root, *n)) || (rc = abr_write_file(p, "x", 1)))
            return rc;
    }
    return ABR_OK;
}

/* A readdir that fails mid-listing must refuse the walk, name the directory
 * and leave no manifest; one that succeeds with errno left set must not. */
static int abr_unit_readdir(const char *tmp)
{
    char root[ABR_PATH], msg[ABR_PATH];
    int rc = abr_unit_walk_tree(tmp, root);
    if (rc)
        return rc;
    rc = abr_unit_walk(root, tmp, "e", (struct abr_seam){ .fail_at = 2 }, msg);
    if (rc != ABR_FATAL)
        rc = abr_st_fail("a readdir error mid-listing did not refuse the walk");
    else if (!strstr(msg, root))
        rc = abr_st_fail("the readdir refusal does not name the directory");
    else if (!(rc = abr_unit_no_manifest(tmp, "e")))
        rc = abr_unit_balanced();
    if (rc)
        return rc;
    rc = abr_unit_walk(root, tmp, "s", (struct abr_seam){ .dirty_at = 1 }, msg);
    if (rc != ABR_OK)
        return abr_st_fail("a stale errno at the end of a listing refused a good walk");
    return abr_unit_balanced();
}

/* Builds root/d/d/... levels deep. */
static int abr_unit_chain(const char *root, int levels)
{
    char p[ABR_PATH];
    int rc = abr_pathf(p, "%s", root);
    for (int i = 0; !rc && i < levels; i++) {
        size_t n = strlen(p);
        if (n + 3 >= sizeof p)
            return abr_fatal("path too long");
        memcpy(p + n, "/d", 3);
        if (mkdir(p, 0777) != 0)
            return abr_fatal("cannot create %s", p);
    }
    return rc;
}

/* Past ABR_DEPTH the walk refuses before opening a directory. */
static int abr_unit_depth(const char *tmp)
{
    char root[ABR_PATH], msg[ABR_PATH];
    int rc = abr_pathf(root, "%s/deep", tmp);
    if (rc || mkdir(root, 0777) != 0 || (rc = abr_unit_chain(root, ABR_DEPTH + 2)))
        return rc ? rc : abr_fatal("cannot create %s", root);
    rc = abr_unit_walk(root, tmp, "d", (struct abr_seam){ 0 }, msg);
    if (rc != ABR_FATAL)
        return abr_st_fail("a tree nested past the depth limit was not refused");
    if (abr_seam.opened != ABR_DEPTH + 1)
        return abr_st_fail("the walk opened a directory past the depth limit");
    if (!(rc = abr_unit_no_manifest(tmp, "d")))
        rc = abr_unit_balanced();
    return rc;
}

static int abr_unit_walks(const char *tmp)
{
    int rc = abr_unit_readdir(tmp);
    if (!rc)
        rc = abr_unit_depth(tmp);
    abr_seam = (struct abr_seam){ 0 };
    return rc;
}
#else
static int abr_unit_walks(const char *tmp)
{
    (void)tmp;
    return abr_st_fail("built without ZCL_TESTING: the walk seam cases cannot run");
}
#endif

static int abr_unit_run(void)
{
    char tmp[ABR_PATH];
    const char *base = env_or("TMPDIR", ABR_TMP_DEFAULT);
    int rc = csr_mkdirs(base) != 0 ? abr_fatal("could not create a temp dir")
                                   : abr_pathf(tmp, "%s/zcl-app-bundle-unit.XXXXXX", base);
    if (rc || !mkdtemp(tmp))
        return rc ? rc : abr_fatal("could not create a temp dir");
    rc = abr_unit_mode();
    if (!rc)
        rc = abr_unit_walks(tmp);
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
