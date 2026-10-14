/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: selftest of check-orient-facts. Plants broken fact rows in a
 * scratch facts directory and proves the gate trips on each, proves a true
 * row passes, and proves the scratch directory is removed when the process
 * is stopped by SIGINT (once and twice), SIGTERM or SIGHUP after a readiness
 * handshake over a pipe.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include "gate_orient_facts_priv.h"
#include "lintc.h"
#include "lintc_sig.h"

static const char k_ofs_index[] =
    "ZCL_FACT_TOPIC(\"t.ok\", \"b\")\n#include \"t_ok.def\"\n";
static const char k_ofs_good[] =
    "ZCL_FACT(\"t.ok\", \"k\",\n \"c\",\n \"Makefile\",\n \"LINT_GATES\")\n";

static int ofs_fail(const char *what)
{
    fprintf(stderr, "SELFTEST FAIL: %s\n", what);
    return 1;
}

static int ofs_write(const char *dir, const char *name, const char *text)
{
    char path[4600];
    snprintf(path, sizeof path, "%s/%s", dir, name);
    FILE *f = fopen(path, "w");
    if (!f)
        return -1;
    fputs(text, f);
    return fclose(f);
}

static int ofs_scratch_open(char *dir, size_t cap)
{
    char base[4200], root[4096];
    const char *tmp = getenv("TMPDIR");
    if (tmp && tmp[0]) {
        snprintf(base, sizeof base, "%s", tmp);
    } else {
        if (cic_repo_root(root, sizeof root))
            return -1;
        snprintf(base, sizeof base, "%s/build/scratch", root);
    }
    char probe[4300];
    if (snprintf(probe, sizeof probe, "%s/x", base) >= (int)sizeof probe
        || csr_mkdirs(probe) != 0)
        return -1;
    if (snprintf(dir, cap, "%s/orientfacts.XXXXXX", base) >= (int)cap)
        return -1;
    return mkdtemp(dir) ? 0 : -1;
}

static void ofs_scratch_close(const char *dir)
{
    lsc_block();
    rap_rm_rf(dir);
}

static int ofs_scan_quiet(const char *dir)
{
    FILE *sink = fopen("/dev/null", "w");
    int rc = of_scan(dir, sink ? sink : stdout, sink ? sink : stderr);
    if (sink)
        fclose(sink);
    return rc;
}

/* One fixture: the facts dir holds the index and one topic file. */
static int ofs_expect(const char *dir, const char *index, const char *topic,
                      int want_fail, const char *what)
{
    char facts[4400];
    snprintf(facts, sizeof facts, "%s/facts", dir);
    (void)mkdir(facts, 0700);
    if (ofs_write(facts, "index.def", index) || ofs_write(facts, "t_ok.def", topic))
        return ofs_fail("cannot write the fixture");
    return (ofs_scan_quiet(facts) != 0) == want_fail ? 0 : ofs_fail(what);
}

struct ofs_case { const char *topic; const char *what; };

static int ofs_trips(const char *dir)
{
    static const struct ofs_case cases[] = {
        { "ZCL_FACT(\"t.ok\", \"k\",\n \"c\",\n \"Makefile\",\n \"no-such-anchor-ZZQ9\")\n",
          "a missing anchor did not trip the gate" },
        { "ZCL_FACT(\"t.ok\", \"k\",\n \"c\",\n \"Makefile\")\n",
          "a four-field row did not trip the gate" },
        { "ZCL_FACT(\"t.zz\", \"k\",\n \"c\",\n \"Makefile\",\n \"LINT_GATES\")\n",
          "an undeclared topic did not trip the gate" },
        { "ZCL_FACT(\"t.ok\", \"k\",\n \"c\",\n \"no/such/file\",\n \"x\")\n",
          "a missing path did not trip the gate" },
        { "ZCL_FACT(\"t.ok\", \"k\",\n\t\"c\",\n \"Makefile\",\n \"LINT_GATES\")\n",
          "a tab did not trip the gate" },
        { "ZCL_FACT(\"t.ok\", \"k\", \"c\", \"Makefile\", \"LINT_GATES\")\n"
          "ZCL_FACT(\"t.ok\", \"k\", \"d\", \"Makefile\", \"LINT_GATES\")\n",
          "a duplicate key did not trip the gate" },
        { "ZCL_FACT(\"t.ok\", \"0123456789012345678901234567890123456789012345678\","
          " \"c\", \"Makefile\", \"LINT_GATES\")\n",
          "an over-long key did not trip the gate" },
        { "/* no rows */\n", "an empty topic file did not trip the scan floor" },
    };
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        if (ofs_expect(dir, k_ofs_index, cases[i].topic, 1, cases[i].what))
            return 1;
    }
    if (ofs_expect(dir, "ZCL_FACT_TOPIC(\"t.ok\", \"b\")\n", k_ofs_good, 1,
                   "an index without includes did not trip the gate"))
        return 1;
    return ofs_expect(dir, k_ofs_index, k_ofs_good, 0, "a true row did not pass");
}

static int ofs_fields(void)
{
    char a[] = "1|2|3|4|5|", b[] = "1|2|3|4|5||", c[] = "1|2|3";
    char *f[5];
    of_split_fields(a, f);
    if (strcmp(f[4], "5") != 0)
        return ofs_fail("a single trailing separator is dropped from the last field");
    of_split_fields(b, f);
    if (strcmp(f[4], "5||") != 0)
        return ofs_fail("repeated trailing separators stay in the last field");
    of_split_fields(c, f);
    return f[3][0] == '\0' && f[4][0] == '\0' ? 0 : ofs_fail("short rows leave empty fields");
}

/* Child of the signal test: create a scratch directory, report its path over
 * the pipe, then wait for a signal and finish through the shared cleanup. */
static void ofs_hold(int wfd)
{
    char dir[4096];
    struct timespec ts = { 0, 5 * 1000 * 1000 };
    if (lsc_install() != 0 || ofs_scratch_open(dir, sizeof dir) != 0)
        _exit(2);
    lsc_unblock();
    size_t n = strlen(dir);
    dir[n] = '\n';
    if (write(wfd, dir, n + 1) != (ssize_t)(n + 1))
        _exit(2);
    dir[n] = '\0';
    for (int i = 0; i < 4000 && !lsc_pending(); i++)
        nanosleep(&ts, NULL);
    int sig = lsc_pending();
    ofs_scratch_close(dir);
    if (sig)
        lsc_finish(sig);
    _exit(3);
}

static int ofs_read_path(int rfd, char *dir, size_t cap)
{
    size_t used = 0;
    while (used + 1 < cap) {
        ssize_t n = read(rfd, dir + used, 1);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0 || dir[used] == '\n')
            break;
        used++;
    }
    dir[used] = '\0';
    return used ? 0 : -1;
}

static int ofs_signal_case(int sig, int times)
{
    int fds[2];
    char dir[4096];
    int st = 0;
    if (pipe(fds) != 0)
        return ofs_fail("pipe failed");
    pid_t pid = fork();
    if (pid < 0)
        return ofs_fail("fork failed");
    if (pid == 0) {
        close(fds[0]);
        ofs_hold(fds[1]);
    }
    close(fds[1]);
    int ready = ofs_read_path(fds[0], dir, sizeof dir);
    close(fds[0]);
    for (int i = 0; ready == 0 && i < times; i++)
        kill(pid, sig);
    if (waitpid(pid, &st, 0) != pid || ready != 0)
        return ofs_fail("the signal-test child did not finish");
    if (!WIFSIGNALED(st) || WTERMSIG(st) != sig)
        return ofs_fail("the stopped process did not re-raise its signal");
    return access(dir, F_OK) == 0 ? ofs_fail("the scratch directory outlived the signal") : 0;
}

static int ofs_signals(void)
{
    return ofs_signal_case(SIGINT, 1) || ofs_signal_case(SIGINT, 2)
        || ofs_signal_case(SIGTERM, 1) || ofs_signal_case(SIGHUP, 1);
}

int check_orient_facts_selftest(void)
{
    char root[4096], dir[4096];
    int rc;
    if (cic_repo_root(root, sizeof root) || chdir(root) != 0)
        return ofs_fail("cannot enter the repository root");
    if (lsc_install() != 0 || ofs_scratch_open(dir, sizeof dir) != 0)
        return ofs_fail("cannot create the scratch directory");
    lsc_unblock();
    rc = ofs_fields() || ofs_trips(dir);
    ofs_scratch_close(dir);
    if (lsc_pending())
        lsc_finish(lsc_pending());
    if (rc == 0)
        rc = ofs_signals();
    if (rc == 0)
        puts("selftest ok: a broken anchor fails, a true row passes");
    return rc;
}
