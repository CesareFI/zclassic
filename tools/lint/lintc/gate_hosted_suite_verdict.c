/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: gate family — hosted-suite cold-verdict verification
 * (check-hosted-suite-verdict), the C23 port of
 * tools/lint/check_hosted_suite_verdict.sh. Holds the hosted test job to one
 * non-vacuous cold-suite verdict: exactly one SUITE VERDICT line whose fields
 * are well-formed, complete, non-duplicated and numerically coherent, plus
 * exactly one cold ALL TESTS PASSED headline and no cached or failure
 * headline. A substring grep is insufficient: "ALL TESTS PASSED (CACHED)"
 * deliberately contains the old pass token and can describe a run that
 * executed zero groups.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <dirent.h>
#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "base/safe_alloc.h"
#include "lintc.h"

/* Every static name carries the hsv_ prefix: the code index links test
 * closures by symbol name. */

static const char *const k_hsv_fields[] = {
    "mode", "groups_total", "groups_ran", "groups_cached", "groups_gated",
    "groups_failed", "self_skips", "env_unobserved", "toolkey"
};
enum { HSV_FIELDS = sizeof k_hsv_fields / sizeof k_hsv_fields[0] };
enum { HSV_MODE = 0, HSV_TOTAL = 1, HSV_RAN = 2, HSV_CACHED = 3,
       HSV_GATED = 4, HSV_FAILED = 5, HSV_SKIPS = 6, HSV_UNOBS = 7,
       HSV_TOOLKEY = 8 };

static const char k_hsv_verdict_prefix[] = "SUITE VERDICT ";
static const char k_hsv_pass_prefix[] = "ALL TESTS PASSED \xE2\x80\x94 ";
static const char k_hsv_cached_prefix[] = "ALL TESTS PASSED (CACHED)";
static const char k_hsv_failed_prefix[] = "SOME TESTS FAILED";

/* fail() sink: stderr normally; the self-test redirects both streams for
 * its rejecting-mutation runs, exactly as the script's 2>&1 did. */
static FILE *g_hsv_err = NULL;

static void hsv_fail(const char *fmt, ...)
{
    va_list ap;
    if (!g_hsv_err)
        return;
    fputs("hosted-suite-verdict: FAIL: ", g_hsv_err);
    va_start(ap, fmt);
    vfprintf(g_hsv_err, fmt, ap);
    va_end(ap);
    fputc('\n', g_hsv_err);
}

static bool hsv_prefix_at(const char *line, size_t len, const char *pre)
{
    size_t n = strlen(pre);
    return len >= n && memcmp(line, pre, n) == 0;
}

/* Read the whole file. Returns NULL with a message already printed when the
 * file cannot be read (the script's `[ -r "$log" ]` guard). */
static char *hsv_read_file(const char *path, size_t *out_size)
{
    FILE *f = fopen(path, "rb");
    char *buf;
    size_t cap = 1 << 16, used = 0;
    *out_size = 0;
    if (!f) {
        hsv_fail("suite log is not readable: %s", path);
        return NULL;
    }
    buf = zcl_malloc(cap, "hsv_log_buffer");
    if (!buf) {
        fclose(f);
        hsv_fail("suite log is not readable: %s", path);
        return NULL;
    }
    for (;;) {
        size_t got;
        if (used == cap) {
            char *grown;
            if (cap > (size_t)-1 / 2)
                break;
            cap *= 2;
            grown = zcl_realloc(buf, cap, "hsv_log_buffer");
            if (!grown)
                break;
            buf = grown;
        }
        got = fread(buf + used, 1, cap - used, f);
        used += got;
        if (got == 0)
            break;
    }
    fclose(f);
    if (used == cap) {
        free(buf);
        hsv_fail("suite log is not readable: %s", path);
        return NULL;
    }
    buf[used] = '\0';
    *out_size = used;
    return buf;
}

/* Parse a digits-only string with the same 64-bit wrap arithmetic bash used
 * (`$((10#...))` evaluates in intmax_t): accumulate in unsigned 64-bit and
 * compare through signed 64-bit, so absurdly long digit strings behave
 * exactly as the script's arithmetic did instead of clamping. */
static long long hsv_parse_wrapped(const char *s)
{
    unsigned long long v = 0;
    for (; *s; s++)
        v = v * 10u + (unsigned long long)(*s - '0');
    return (long long)v;
}

static bool hsv_is_digits(const char *s)
{
    if (!*s)
        return false;
    for (; *s; s++)
        if (*s < '0' || *s > '9')
            return false;
    return true;
}

static bool hsv_is_lower_hex12(const char *s)
{
    size_t i;
    if (strlen(s) != 12)
        return false;
    for (i = 0; i < 12; i++) {
        char c = s[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
            return false;
    }
    return true;
}

struct hsv_values {
    char *v[HSV_FIELDS];      /* pointers into the verdict-line copy */
    bool present[HSV_FIELDS];
};

/* Walk the whitespace-split tokens of the remainder, mirroring the script's
 * `for token in ${verdict#SUITE VERDICT }` word splitting. */
static void hsv_parse_tokens(char *rest, struct hsv_values *vals, int *bad)
{
    char *p = rest;
    while (*p) {
        char *tok, *eq, *datum;
        const char *key;
        int idx = -1;
        while (*p == ' ' || *p == '\t')
            p++;
        if (!*p)
            break;
        tok = p;
        while (*p && *p != ' ' && *p != '\t')
            p++;
        if (*p)
            *p++ = '\0';
        eq = strchr(tok, '=');
        if (!eq) {
            hsv_fail("suite verdict token is not key=value: %s", tok);
            *bad = 1;
            continue;
        }
        *eq = '\0';
        key = tok;
        datum = eq + 1;
        for (int i = 0; i < (int)HSV_FIELDS; i++)
            if (strcmp(key, k_hsv_fields[i]) == 0)
                idx = i;
        if (idx < 0) {
            hsv_fail("unknown suite verdict field: %s", key);
            *bad = 1;
            continue;
        }
        if (vals->present[idx]) {
            hsv_fail("duplicate suite verdict field: %s", key);
            *bad = 1;
            continue;
        }
        vals->present[idx] = true;
        vals->v[idx] = datum;
    }
}

/* The value to show in diagnostics: the stored value, or "missing" when the
 * field never landed — the script's `${value[$key]-missing}`. */
static const char *hsv_show(const struct hsv_values *vals, int idx)
{
    return vals->present[idx] ? vals->v[idx] : "missing";
}

/* One log-line scan: counts the verdict and headline shapes exactly as the
 * script's three greps did (a trailing chunk without a newline still counts
 * as a line). Only the first verdict line is kept for token parsing — with
 * more than one the script never parsed tokens at all. */
struct hsv_scan {
    size_t verdict_count;
    char *verdict_line;        /* owned copy of the first verdict line */
    size_t pass_headlines;
    bool cached_headline, failed_headline;
};

static void hsv_scan_lines(char *buf, size_t size, struct hsv_scan *sc)
{
    size_t i = 0;
    memset(sc, 0, sizeof *sc);
    while (i < size) {
        size_t end = i, len;
        char *line;
        while (end < size && buf[end] != '\n')
            end++;
        len = end - i;            /* provably <= size: keeps the copy's
                                   * bounds visible to the compiler */
        line = buf + i;
        if (hsv_prefix_at(line, len, k_hsv_verdict_prefix)) {
            sc->verdict_count++;
            if (!sc->verdict_line) {
                /* Terminate the line in place: end<size means that byte
                 * was the '\n' this scanner owns; end==size means the
                 * buffer already ends NUL. No copy is needed. */
                buf[end] = '\0';
                sc->verdict_line = line;
            }
        }
        if (hsv_prefix_at(line, len, k_hsv_pass_prefix))
            sc->pass_headlines++;
        if (hsv_prefix_at(line, len, k_hsv_cached_prefix))
            sc->cached_headline = true;
        if (hsv_prefix_at(line, len, k_hsv_failed_prefix))
            sc->failed_headline = true;
        if (end == size)
            break;
        i = end + 1;
    }
}

/* Missing-field, mode, numeric-format and toolkey diagnostics, in the
 * script's exact order. */
static void hsv_validate_fields(const struct hsv_values *vals, int *bad)
{
    for (int i = 0; i < (int)HSV_FIELDS; i++)
        if (!vals->present[i]) {
            hsv_fail("suite verdict is missing field: %s", k_hsv_fields[i]);
            *bad = 1;
        }
    if (strcmp(hsv_show(vals, HSV_MODE), "cold") != 0) {
        hsv_fail("suite mode is '%s', expected cold",
                 hsv_show(vals, HSV_MODE));
        *bad = 1;
    }
    for (int i = HSV_TOTAL; i <= HSV_UNOBS; i++) {
        const char *s = hsv_show(vals, i);
        if (!hsv_is_digits(s)) {
            hsv_fail("suite field %s is not a non-negative integer: %s",
                     k_hsv_fields[i], s);
            *bad = 1;
        }
    }
    if (!hsv_is_lower_hex12(hsv_show(vals, HSV_TOOLKEY))) {
        hsv_fail("suite toolkey is not 12 lowercase hex characters: %s",
                 hsv_show(vals, HSV_TOOLKEY));
        *bad = 1;
    }
}

/* The arithmetic coherence block, only reached when nothing earlier failed,
 * in the script's exact order. */
static void hsv_validate_counts(const struct hsv_values *vals, int *bad)
{
    long long total_n = hsv_parse_wrapped(vals->v[HSV_TOTAL]);
    long long ran_n = hsv_parse_wrapped(vals->v[HSV_RAN]);
    long long cached_n = hsv_parse_wrapped(vals->v[HSV_CACHED]);
    long long gated_n = hsv_parse_wrapped(vals->v[HSV_GATED]);
    long long failed_n = hsv_parse_wrapped(vals->v[HSV_FAILED]);
    long long skips_n = hsv_parse_wrapped(vals->v[HSV_SKIPS]);
    long long unobserved_n = hsv_parse_wrapped(vals->v[HSV_UNOBS]);
    /* Bash `$((ran + gated))` wraps in 64-bit; reproduce that wrap. */
    long long sum_n = (long long)((unsigned long long)ran_n
        + (unsigned long long)gated_n);
    if (total_n == 0 || ran_n == 0) {
        hsv_fail("suite executed no groups (total=%lld ran=%lld)",
                 total_n, ran_n);
        *bad = 1;
    }
    if (cached_n != 0) {
        hsv_fail("suite reused %lld cached group(s); hosted proof must "
                 "be cold", cached_n);
        *bad = 1;
    }
    if (failed_n != 0) {
        hsv_fail("suite reports %lld failed group(s)", failed_n);
        *bad = 1;
    }
    if (unobserved_n != 0) {
        hsv_fail("suite reports %lld environment-unobserved group(s)",
                 unobserved_n);
        *bad = 1;
    }
    if (sum_n != total_n) {
        hsv_fail("suite accounting is incomplete: ran=%lld gated=%lld "
                 "total=%lld", ran_n, gated_n, total_n);
        *bad = 1;
    }
    if (skips_n > ran_n) {
        hsv_fail("suite self-skips exceed executed groups: skips=%lld "
                 "ran=%lld", skips_n, ran_n);
        *bad = 1;
    }
}

static int hsv_check_log(const char *path, FILE *out)
{
    size_t size;
    char *buf = hsv_read_file(path, &size);
    struct hsv_scan sc;
    struct hsv_values vals;
    int bad = 0;
    if (!buf)
        return 1;
    hsv_scan_lines(buf, size, &sc);
    memset(&vals, 0, sizeof vals);
    if (sc.verdict_count != 1) {
        hsv_fail("expected exactly one SUITE VERDICT line, found %zu",
                 sc.verdict_count);
        bad = 1;
    } else if (sc.verdict_line) {
        /* The grep prefix guarantees the first two words are SUITE and
         * VERDICT, so like the script's read, that check cannot fail here;
         * tokenize the remainder after the prefix. */
        hsv_parse_tokens(sc.verdict_line + strlen(k_hsv_verdict_prefix),
                         &vals, &bad);
    }
    hsv_validate_fields(&vals, &bad);
    if (!bad)
        hsv_validate_counts(&vals, &bad);
    if (sc.pass_headlines != 1) {
        hsv_fail("expected exactly one cold ALL TESTS PASSED headline");
        bad = 1;
    }
    if (sc.cached_headline) {
        hsv_fail("cached pass headline is not hosted cold-suite evidence");
        bad = 1;
    }
    if (sc.failed_headline) {
        hsv_fail("failure headline is present");
        bad = 1;
    }
    if (!bad && out)
        fprintf(out,
            "hosted-suite-verdict: PASS: cold groups_total=%s groups_ran=%s "
            "groups_gated=%s self_skips=%s\n",
            vals.v[HSV_TOTAL], vals.v[HSV_RAN], vals.v[HSV_GATED],
            vals.v[HSV_SKIPS]);
    free(buf);
    return bad ? 1 : 0;
}

/* ── self-test ────────────────────────────────────────────────────────── */

static volatile sig_atomic_t g_hsv_signal;
static char g_hsv_fixture_dir[4096];

static void hsv_on_signal(int sig)
{
    g_hsv_signal = sig;
}

static int hsv_rm_tree(const char *path)
{
    struct stat st;
    DIR *d;
    struct dirent *de;
    int rc = 0;
    if (lstat(path, &st) != 0)
        return 0;
    if (!S_ISDIR(st.st_mode))
        return unlink(path) == 0 ? 0 : -1;
    d = opendir(path);
    if (!d)
        return -1;
    while ((de = readdir(d)) != NULL) {
        char child[4096];
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
            continue;
        if (snprintf(child, sizeof child, "%s/%s", path, de->d_name)
            >= (int)sizeof child) {
            rc = -1;
            continue;
        }
        if (hsv_rm_tree(child) != 0)
            rc = -1;
    }
    closedir(d);
    if (rmdir(path) != 0)
        rc = -1;
    return rc;
}

/* Remove the fixture tree with the recorded signal delivered afterwards:
 * the handler only records, cleanup runs with the signal blocked, then the
 * disposition is restored and the signal re-raised, as the EXIT trap's
 * cleanup-on-signal death did. */
static void hsv_cleanup_and_raise(void)
{
    int sig = (int)g_hsv_signal;
    sigset_t all, old;
    sigfillset(&all);
    sigprocmask(SIG_BLOCK, &all, &old);
    if (g_hsv_fixture_dir[0]) {
        hsv_rm_tree(g_hsv_fixture_dir);
        g_hsv_fixture_dir[0] = '\0';
    }
    if (sig) {
        signal(sig, SIG_DFL);
        sigprocmask(SIG_SETMASK, &old, NULL);
        raise(sig);
        _exit(128 + sig);
    }
    sigprocmask(SIG_SETMASK, &old, NULL);
}

static int hsv_write_fixture(const char *dir, const char *name,
                             const char *const *lines, size_t n)
{
    char path[4096];
    FILE *f;
    size_t i;
    if (snprintf(path, sizeof path, "%s/%s", dir, name)
        >= (int)sizeof path)
        return -1;
    f = fopen(path, "w");
    if (!f)
        return -1;
    for (i = 0; i < n; i++)
        if (fprintf(f, "%s\n", lines[i]) < 0) {
            fclose(f);
            return -1;
        }
    return fclose(f) == 0 ? 0 : -1;
}

/* The five fixtures, byte-for-byte the script's self-test logs. */
static const char *const k_hsv_fx_good[] = {
    "SUITE VERDICT mode=cold groups_total=1050 groups_ran=1041 "
    "groups_cached=0 groups_gated=9 groups_failed=0 self_skips=20 "
    "env_unobserved=0 toolkey=34e55dd75397",
    "ALL TESTS PASSED \xE2\x80\x94 0/1041 groups failed, 20 skipped"
};
static const char *const k_hsv_fx_cached[] = {
    "SUITE VERDICT mode=cached groups_total=1050 groups_ran=0 "
    "groups_cached=1041 groups_gated=9 groups_failed=0 self_skips=0 "
    "env_unobserved=0 toolkey=34e55dd75397",
    "ALL TESTS PASSED (CACHED) \xE2\x80\x94 0/1041 groups failed, "
    "0 skipped"
};
static const char *const k_hsv_fx_zero_run[] = {
    "SUITE VERDICT mode=cold groups_total=9 groups_ran=0 "
    "groups_cached=0 groups_gated=9 groups_failed=0 self_skips=0 "
    "env_unobserved=0 toolkey=34e55dd75397",
    "ALL TESTS PASSED \xE2\x80\x94 0/0 groups failed, 0 skipped"
};
static const char *const k_hsv_fx_duplicate[] = {
    "SUITE VERDICT mode=cold groups_total=1050 groups_ran=1041 "
    "groups_cached=0 groups_gated=9 groups_failed=0 groups_failed=0 "
    "self_skips=20 env_unobserved=0 toolkey=34e55dd75397",
    "ALL TESTS PASSED \xE2\x80\x94 0/1041 groups failed, 20 skipped"
};
static const char *const k_hsv_fx_unobserved[] = {
    "SUITE VERDICT mode=cold groups_total=1050 groups_ran=1041 "
    "groups_cached=0 groups_gated=9 groups_failed=0 self_skips=20 "
    "env_unobserved=1 toolkey=34e55dd75397",
    "ALL TESTS PASSED \xE2\x80\x94 0/1041 groups failed, 20 skipped"
};

static int hsv_selftest_dir(void)
{
    struct sigaction sa;
    sigset_t block, old;
    char template[4096];
    char *dir;
    const char *tmp;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = hsv_on_signal;
    sigemptyset(&sa.sa_mask);
    sigaddset(&sa.sa_mask, SIGINT);
    sigaddset(&sa.sa_mask, SIGTERM);
    sigaddset(&sa.sa_mask, SIGHUP);
    sa.sa_flags = 0;              /* no SA_RESTART, no SA_RESETHAND */
    if (sigaction(SIGINT, &sa, NULL) != 0
        || sigaction(SIGTERM, &sa, NULL) != 0
        || sigaction(SIGHUP, &sa, NULL) != 0) {
        hsv_fail("self-test cannot install signal handlers");
        return -1;
    }
    /* Keep the mkdtemp plus its registration atomic against signals. */
    sigemptyset(&block);
    sigaddset(&block, SIGINT);
    sigaddset(&block, SIGTERM);
    sigaddset(&block, SIGHUP);
    sigprocmask(SIG_BLOCK, &block, &old);
    tmp = env_or("TMPDIR", "/tmp");
    if (snprintf(template, sizeof template,
                  "%s/zcl-hosted-suite-verdict.XXXXXX", tmp)
        >= (int)sizeof template) {
        sigprocmask(SIG_SETMASK, &old, NULL);
        hsv_fail("self-test cannot build the fixture template path");
        return -1;
    }
    dir = mkdtemp(template);
    if (!dir) {
        sigprocmask(SIG_SETMASK, &old, NULL);
        hsv_fail("self-test cannot create the fixture directory");
        return -1;
    }
    snprintf(g_hsv_fixture_dir, sizeof g_hsv_fixture_dir, "%s", dir);
    sigprocmask(SIG_SETMASK, &old, NULL);
    return 0;
}

static int hsv_selftest_fixtures(void)
{
    static const struct {
        const char *name;
        const char *const *lines;
    } fixtures[] = {
        { "good.log", k_hsv_fx_good },
        { "cached.log", k_hsv_fx_cached },
        { "zero-run.log", k_hsv_fx_zero_run },
        { "duplicate.log", k_hsv_fx_duplicate },
        { "unobserved.log", k_hsv_fx_unobserved }
    };
    for (size_t i = 0; i < sizeof fixtures / sizeof fixtures[0]; i++)
        if (hsv_write_fixture(g_hsv_fixture_dir, fixtures[i].name,
                              fixtures[i].lines, 2) != 0) {
            hsv_fail("self-test cannot write fixtures");
            return -1;
        }
    return 0;
}

static bool hsv_fixture_rejects(const char *name)
{
    char path[4096];
    FILE *saved_err = g_hsv_err;
    int rc;
    if (snprintf(path, sizeof path, "%s/%s", g_hsv_fixture_dir, name)
        >= (int)sizeof path)
        return true;
    g_hsv_err = NULL;             /* the script's 2>&1 into the void */
    rc = hsv_check_log(path, NULL);
    g_hsv_err = saved_err;
    return rc != 0;
}

/* Each rejecting mutation keeps the script's exact failure sentence. */
static int hsv_selftest_rejections(void)
{
    static const struct {
        const char *name, *msg;
    } cases[] = {
        { "cached.log", "cached zero-run log was admitted" },
        { "zero-run.log", "cold zero-run log was admitted" },
        { "duplicate.log", "duplicate verdict field was admitted" },
        { "unobserved.log", "environment-unobserved run was admitted" }
    };
    char path[4096];
    /* The valid fixture must pass with stdout discarded (stderr, which a
     * passing run never writes, still flows). */
    if (snprintf(path, sizeof path, "%s/good.log", g_hsv_fixture_dir)
        >= (int)sizeof path) {
        hsv_fail("self-test cannot address the good fixture");
        return -1;
    }
    if (hsv_check_log(path, NULL) != 0) {
        hsv_fail("self-test rejected the valid cold fixture");
        return -1;
    }
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++)
        if (!hsv_fixture_rejects(cases[i].name)) {
            hsv_fail("self-test mutation survived: %s", cases[i].msg);
            return -1;
        }
    return 0;
}

int check_hosted_suite_verdict_selftest(void)
{
    int failed;
    if (hsv_selftest_dir() != 0)
        return 1;
    if (g_hsv_signal)
        hsv_cleanup_and_raise();
    failed = hsv_selftest_fixtures() != 0;
    if (g_hsv_signal)
        hsv_cleanup_and_raise();
    if (!failed)
        failed = hsv_selftest_rejections() != 0;
    if (g_hsv_signal)
        hsv_cleanup_and_raise();
    hsv_cleanup_and_raise();      /* fixture tree removed on the normal path */
    if (failed)
        return 1;
    printf("hosted-suite-verdict self-test: PASS "
           "(valid cold + 4 rejecting mutations)\n");
    return 0;
}

int check_hosted_suite_verdict_run(int argc, char **argv)
{
    g_hsv_err = stderr;
    if (argc == 1 && strcmp(argv[0], "--self-test") == 0)
        return check_hosted_suite_verdict_selftest();
    if (argc == 1 && argv[0][0])
        return hsv_check_log(argv[0], stdout);
    hsv_fail("usage: check_hosted_suite_verdict.sh --self-test | LOG");
    return 2;
}
