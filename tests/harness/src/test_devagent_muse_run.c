/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: prove the Muse executor without a model, a build, or a
 * network. A scripted MSP host stands in for `muse serve`, a shell
 * fixture stands in for the registered runner, and a real git worktree
 * stands in for the claimed workspace: struct-API validation, the
 * receipt-only restart pre-check, verdict mapping (completed is never
 * pass by itself; verbs are lowercase closed-vocabulary), receipt shape
 * the reaper reads, and the full result contract the result row needs.
 * A's queue files (locks, outcome rows) are never touched here: claim,
 * retry, and reap belong to A's loop. */
#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif
#include "test/test_core.h"
#include "test/muse_fake_host.h"
#include "services/muse_run.h"
#include "command/native_devagent.h"
#if !defined(_WIN32)
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MR_CHECK(label, expression) do { \
    bool ok = (expression); \
    printf("muse_run: %s... %s\n", label, ok ? "OK" : "FAIL"); \
    if (!ok) ++failures; \
} while (0)

#if defined(_WIN32)
int test_devagent_muse_run(void)
{
    printf("muse_run: POSIX-only worker (fork/git)... SKIP\n");
    return 0;
}
#else

struct mr_dirs {
    char root[4096];
    char run[4096];
    char wt[4096];
};

static bool mr_write(const char *path, const char *text, mode_t mode)
{
    FILE *f = fopen(path, "wb");
    bool ok;
    if (!f) return false;
    ok = fwrite(text, 1, strlen(text), f) == strlen(text);
    if (fclose(f) != 0) ok = false;
    if (ok && mode) (void)chmod(path, mode);
    return ok;
}

static char *mr_read(const char *path)
{
    FILE *f = fopen(path, "rb");
    long n;
    char *buf;
    if (!f) return NULL;
    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return NULL;
    }
    n = ftell(f);
    if (n < 0 || n > 1048576) {
        fclose(f);
        return NULL;
    }
    (void)fseek(f, 0, SEEK_SET);
    buf = malloc((size_t)n + 1);
    if (!buf) {
        fclose(f);
        return NULL;
    }
    if (n > 0 && fread(buf, 1, (size_t)n, f) != (size_t)n) {
        free(buf);
        fclose(f);
        return NULL;
    }
    buf[n] = '\0';
    fclose(f);
    return buf;
}

static bool mr_mkdir_p(const char *path)
{
    char tmp[4096];
    size_t n = strlen(path);
    if (n == 0 || n >= sizeof(tmp)) return false;
    memcpy(tmp, path, n + 1);
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            (void)mkdir(tmp, 0755);
            *p = '/';
        }
    }
    return mkdir(tmp, 0755) == 0 || errno == EEXIST;
}

static bool mr_git(const char *dir, const char *arg)
{
    pid_t pid = fork();
    if (pid < 0) return false;
    if (pid == 0) {
        int devnull = open("/dev/null", O_WRONLY | O_CLOEXEC);
        if (devnull >= 0) {
            (void)dup2(devnull, STDOUT_FILENO);
            (void)dup2(devnull, STDERR_FILENO);
            close(devnull);
        }
        execlp("git", "git", "-C", dir, arg, (char *)NULL);
        _exit(127);
    }
    int status = 0;
    (void)waitpid(pid, &status, 0);
    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

static bool mr_git3(const char *dir, const char *a1, const char *a2,
    const char *a3)
{
    pid_t pid = fork();
    if (pid < 0) return false;
    if (pid == 0) {
        int devnull = open("/dev/null", O_WRONLY | O_CLOEXEC);
        if (devnull >= 0) {
            (void)dup2(devnull, STDOUT_FILENO);
            (void)dup2(devnull, STDERR_FILENO);
            close(devnull);
        }
        execlp("git", "git", "-C", dir, a1, a2, a3, (char *)NULL);
        _exit(127);
    }
    int status = 0;
    (void)waitpid(pid, &status, 0);
    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

/* One isolated lane: run dir plus a git worktree whose build output is
 * ignored and committed, mirroring prod primed worktrees. No queue dir:
 * the executor never reads A's claim state. */
static bool mr_lane(struct mr_dirs *d)
{
    char tmp[4096];
    if (!test_mkdtemp(tmp, sizeof(tmp), "muse_run")) return false;
    if (snprintf(d->root, sizeof(d->root), "%s", tmp) >=
        (int)sizeof(d->root))
        return false;
    if (snprintf(d->run, sizeof(d->run), "%s/run", tmp) >=
        (int)sizeof(d->run))
        return false;
    if (snprintf(d->wt, sizeof(d->wt), "%s/wt", tmp) >=
        (int)sizeof(d->wt))
        return false;
    if (!mr_mkdir_p(d->run) || !mr_mkdir_p(d->wt) ||
        !mr_git(d->wt, "init"))
        return false;
    {
        char ignore[8192];
        if (snprintf(ignore, sizeof(ignore), "%s/.gitignore", d->wt) >=
            (int)sizeof(ignore))
            return false;
        return mr_write(ignore, "build/\n", 0) &&
            mr_git3(d->wt, "config", "user.email", "t@t.t") &&
            mr_git3(d->wt, "config", "user.name", "t") &&
            mr_git3(d->wt, "add", "-A", ".") &&
            mr_git3(d->wt, "commit", "-m", "x");
    }
}

/* One composed file in the leaf format: the queue: header rides along
 * and must be tolerated, never consulted. */
static bool mr_task_file(const struct mr_dirs *d)
{
    char path[8192], task[8192];
    if (snprintf(path, sizeof(path), "%s/task.txt", d->run) >=
        (int)sizeof(path))
        return false;
    if (snprintf(task, sizeof(task),
            "kind: muse\nseq: 7\nname: u1\nattempt: 1\ngroup: task_document\n"
            "scope: src/\nworktree: %s\nrundir: %s\nqueue: /q\nmodel: \n"
            "=== BRIEF: /b.md ===\nDo the thing.\n",
            d->wt, d->run) >= (int)sizeof(task))
        return false;
    return mr_write(path, task, 0);
}

static bool mr_gate_script(const struct mr_dirs *d, const char *verdict,
    const char *headline, const char *marker)
{
    char dir[8192], path[8192], text[2048];
    if (snprintf(dir, sizeof(dir), "%s/build/bin", d->wt) >=
        (int)sizeof(dir))
        return false;
    if (!mr_mkdir_p(dir)) return false;
    if (snprintf(path, sizeof(path), "%s/test_parallel", dir) >=
        (int)sizeof(path))
        return false;
    if (snprintf(text, sizeof(text),
            "#!/bin/sh\nprintf '%%s\\n' '%s'\nprintf '%%s\\n' '%s'\n%s\n"
            "exit 0\n",
            verdict, headline,
            marker && marker[0] ? marker : ":") >= (int)sizeof(text))
        return false;
    return mr_write(path, text, 0755);
}

static const char *mr_verdict_pass =
    "SUITE VERDICT mode=cold groups_total=1 groups_ran=1 groups_cached=0 "
    "groups_gated=1 groups_failed=0 self_skips=0 env_unobserved=0 "
    "toolkey=abc123";
static const char *mr_head_pass = "ALL TESTS PASSED";
static const char *mr_verdict_fail =
    "SUITE VERDICT mode=cold groups_total=1 groups_ran=1 groups_cached=0 "
    "groups_gated=1 groups_failed=1 self_skips=0 env_unobserved=0 "
    "toolkey=abc123";
static const char *mr_head_fail = "ALL TESTS FAILED";

/* spawn_fake/close_fake live in the shared header for the adapter suite;
 * this file forks raw transports instead, so reference them to keep
 * -Wunused-function quiet without duplicating a line of harness. */
static const void *mr_fake_lifecycle_refs[2] = {
    (const void *)&spawn_fake, (const void *)&close_fake
};

static bool mr_hex40(const char *s)
{
    if (!s) return false;
    for (int i = 0; i < 40; i++) {
        char c = s[i];
        bool hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
        if (!hex) return false;
    }
    return s[40] == '\0';
}

/* Fill the struct task the way A's loop would: ref, worker, workspace,
 * scope, gate, model, prompt, rundir, budgets. */
static bool mr_task_for(const struct mr_dirs *d, struct muse_run_task *t,
    const char *worker, const char *model,
    const struct muse_run_budgets *budgets)
{
    memset(t, 0, sizeof(*t));
    t->ref.seq = 7;
    if (snprintf(t->ref.name, sizeof(t->ref.name), "u1") >=
        (int)sizeof(t->ref.name))
        return false;
    t->ref.attempt = 1;
    if (snprintf(t->worker, sizeof(t->worker), "%s",
            worker ? worker : "w1") >= (int)sizeof(t->worker))
        return false;
    if (snprintf(t->workspace, sizeof(t->workspace), "%s", d->wt) >=
        (int)sizeof(t->workspace))
        return false;
    if (snprintf(t->scope, sizeof(t->scope), "src/") >=
        (int)sizeof(t->scope))
        return false;
    if (snprintf(t->gate, sizeof(t->gate), "task_document") >=
        (int)sizeof(t->gate))
        return false;
    if (snprintf(t->model, sizeof(t->model), "%s", model ? model : "") >=
        (int)sizeof(t->model))
        return false;
    t->prompt = "Do the thing.\n";
    if (snprintf(t->rundir, sizeof(t->rundir), "%s", d->run) >=
        (int)sizeof(t->rundir))
        return false;
    if (budgets) {
        t->budgets = *budgets;
    } else {
        t->budgets.turn_timeout_ms = 30000;
        t->budgets.gate_timeout_ms = 60000;
    }
    return true;
}

static int mr_failures_validate(void)
{
    int failures = 0;
    struct mr_dirs d;
    struct muse_run_task t;
    struct muse_run_result r;
    char err[MUSE_RUN_ERROR_MAX];
    MR_CHECK("lane", mr_lane(&d));
    MR_CHECK("task", mr_task_for(&d, &t, NULL, NULL, NULL));
    /* Null surfaces refuse without touching anything. */
    err[0] = '\0';
    MR_CHECK("null task refuses", muse_run_task(NULL, &r, err) == 1);
    err[0] = '\0';
    MR_CHECK("null result refuses", muse_run_task(&t, NULL, err) == 1);
    /* Bad worker identity refuses: it rides the result row. */
    if (snprintf(t.worker, sizeof(t.worker), "not a worker") >=
        (int)sizeof(t.worker))
        MR_CHECK("worker overflow", false);
    else {
        err[0] = '\0';
        MR_CHECK("bad worker refuses", muse_run_task(&t, &r, err) == 1);
    }
    MR_CHECK("task", mr_task_for(&d, &t, NULL, NULL, NULL));
    /* Escaping scope refuses: the turn must stay inside the workspace. */
    if (snprintf(t.scope, sizeof(t.scope), "../out") >=
        (int)sizeof(t.scope))
        MR_CHECK("scope overflow", false);
    else {
        err[0] = '\0';
        MR_CHECK("escaping scope refuses", muse_run_task(&t, &r, err) == 1);
    }
    MR_CHECK("task", mr_task_for(&d, &t, NULL, NULL, NULL));
    if (snprintf(t.workspace, sizeof(t.workspace), "/nonexistent-wt") >=
        (int)sizeof(t.workspace))
        MR_CHECK("workspace overflow", false);
    else {
        err[0] = '\0';
        MR_CHECK("missing workspace refuses",
            muse_run_task(&t, &r, err) == 1);
    }
    return failures;
}

static int mr_failures_parse(void)
{
    int failures = 0;
    struct mr_dirs d;
    char err[MUSE_RUN_ERROR_MAX];
    MR_CHECK("lane", mr_lane(&d));
    /* Unknown kind. */
    {
        char path[8192];
        (void)snprintf(path, sizeof(path), "%s/task.txt", d.run);
        MR_CHECK("write bad task",
            mr_write(path, "kind: file\nseq: 1\n", 0));
        err[0] = '\0';
        MR_CHECK("bad kind refused", muse_run_task_file(path, NULL, err)
            == 1);
    }
    /* Missing headers. */
    {
        char path[8192];
        (void)snprintf(path, sizeof(path), "%s/task.txt", d.run);
        MR_CHECK("write short task",
            mr_write(path, "kind: muse\nseq: 1\n", 0));
        err[0] = '\0';
        MR_CHECK("short task refused",
            muse_run_task_file(path, NULL, err) == 1);
    }
    /* Empty brief. */
    {
        char path[8192];
        (void)snprintf(path, sizeof(path), "%s/task.txt", d.run);
        MR_CHECK("write empty brief",
            mr_write(path,
                "kind: muse\nseq: 1\nname: u1\nattempt: 1\ngroup: g\n"
                "scope: src/\nworktree: /w\nrundir: /r\nqueue: /q\nmodel: \n"
                "=== BRIEF: /b.md ===\n", 0));
        err[0] = '\0';
        MR_CHECK("empty brief refused",
            muse_run_task_file(path, NULL, err) == 1);
    }
    /* A recorded ref short-circuits through the file path too: the
     * queue: header is tolerated and no host ever spawns. */
    {
        char path[8192], receipt[8192];
        (void)snprintf(path, sizeof(path), "%s/task.txt", d.run);
        (void)snprintf(receipt, sizeof(receipt), "%s/receipt.json",
            d.run);
        MR_CHECK("write task", mr_task_file(&d));
        MR_CHECK("seed receipt",
            mr_write(receipt,
                "{\"verdict\":\"pass\",\"seq\":7,\"name\":\"u1\","
                "\"attempt\":1}\n",
                0));
        err[0] = '\0';
        MR_CHECK("file short-circuits",
            muse_run_task_file(path, NULL, err) == 0);
    }
    return failures;
}

/* Forks the scripted host and hands the transport to the core under
 * test. The core owns the session afterwards, including close/reap. */
static bool mr_fork_fake(enum fake_mode mode, int ev_read, int *to_fd,
    int *from_fd, pid_t *child)
{
    int to_child[2], from_child[2];
    pid_t pid;
    if (pipe(to_child) != 0 || pipe(from_child) != 0) return false;
    pid = fork();
    if (pid < 0) {
        close(to_child[0]); close(to_child[1]);
        close(from_child[0]); close(from_child[1]);
        return false;
    }
    if (pid == 0) {
        close(to_child[1]);
        close(from_child[0]);
        close(ev_read);
        (void)dup2(to_child[0], STDIN_FILENO);
        (void)dup2(from_child[1], STDOUT_FILENO);
        close(to_child[0]);
        close(from_child[1]);
        fake_main(mode);
        _exit(0);
    }
    close(to_child[0]);
    close(from_child[1]);
    *to_fd = to_child[1];
    *from_fd = from_child[0];
    *child = pid;
    return true;
}

/* Runs one execute() case over the struct boundary. Worker/model NULL
 * take the lane defaults; budgets NULL takes the case defaults. */
static int mr_execute(enum fake_mode mode, struct mr_dirs *d,
    const char *gate_verdict, const char *gate_headline,
    const char *gate_marker, bool dirty, const char *worker,
    const char *model, const struct muse_run_budgets *budgets,
    bool claimed, struct muse_run_result *res,
    char err[MUSE_RUN_ERROR_MAX], int *rc_out, char **evidence_out)
{
    int ev[2], to_fd = -1, from_fd = -1;
    pid_t child = -1;
    int rc;
    if (pipe(ev) != 0) return -1;
    s_evidence_fd = ev[1];
    if (!mr_lane(d)) {
        close(ev[0]); close(ev[1]);
        return -1;
    }
    {
        struct muse_run_task t;
        if (!mr_task_for(d, &t, worker, model, budgets)) {
            close(ev[0]); close(ev[1]);
            return -1;
        }
        t.caller_holds_claim = claimed;
        if (gate_verdict &&
            !mr_gate_script(d, gate_verdict,
                gate_headline ? gate_headline : "", gate_marker)) {
            close(ev[0]); close(ev[1]);
            return -1;
        }
        if (dirty) {
            char f[8192];
            if (snprintf(f, sizeof(f), "%s/edit.txt", d->wt) >=
                (int)sizeof(f)) {
                close(ev[0]); close(ev[1]);
                return -1;
            }
            if (!mr_write(f, "changed\n", 0)) {
                close(ev[0]); close(ev[1]);
                return -1;
            }
        }
        if (!mr_fork_fake(mode, ev[0], &to_fd, &from_fd, &child)) {
            close(ev[0]); close(ev[1]);
            return -1;
        }
        rc = muse_run_task_on_transport(&t, child, to_fd, from_fd, res,
            err);
    }
    close(ev[1]);
    s_evidence_fd = -1;
    *evidence_out = read_evidence(ev[0]);
    close(ev[0]);
    if (rc_out) *rc_out = rc;
    return 0;
}

static int mr_failures_precheck(void)
{
    int failures = 0;
    struct mr_dirs d;
    struct muse_run_task t;
    struct muse_run_result r;
    char err[MUSE_RUN_ERROR_MAX], receipt[8192];
    int ev[2];
    pid_t child = -1;
    int to_fd = -1, from_fd = -1;
    char *evidence = NULL;
    MR_CHECK("lane", mr_lane(&d));
    MR_CHECK("task", mr_task_for(&d, &t, NULL, NULL, NULL));
    (void)snprintf(receipt, sizeof(receipt), "%s/receipt.json", d.run);
    /* A receipt with a terminal verdict short-circuits: rc 0, no turn,
     * no rewrite. No queue files exist in this lane at all. */
    MR_CHECK("seed receipt",
        mr_write(receipt,
            "{\"verdict\":\"pass\",\"seq\":7,\"name\":\"u1\","
            "\"attempt\":1}\n",
            0));
    if (pipe(ev) != 0) {
        MR_CHECK("evidence pipe", false);
        return failures + 1;
    }
    s_evidence_fd = ev[1];
    if (!mr_fork_fake(FAKE_JOURNEY, ev[0], &to_fd, &from_fd, &child)) {
        MR_CHECK("fork fake", false);
        close(ev[0]); close(ev[1]);
        return failures + 1;
    }
    memset(&r, 0, sizeof(r));
    err[0] = '\0';
    MR_CHECK("recorded ref short-circuits",
        muse_run_task_on_transport(&t, child, to_fd, from_fd, &r, err)
        == 0);
    /* The short-circuit never touches the transport: close it so the
     * forked host sees EOF and exits, then reap it. */
    close(to_fd);
    close(from_fd);
    {
        int status = 0;
        (void)waitpid(child, &status, 0);
    }
    close(ev[1]);
    s_evidence_fd = -1;
    evidence = read_evidence(ev[0]);
    close(ev[0]);
    MR_CHECK("no turn started",
        evidence && !strstr(evidence, "turn-cmd:"));
    MR_CHECK("verdict carried", strcmp(r.verdict, "pass") == 0);
    MR_CHECK("rc zero", r.rc == 0);
    free(evidence);
    {
        char *rtext = mr_read(receipt);
        MR_CHECK("receipt untouched", rtext &&
            strstr(rtext, "\"verdict\":\"pass\""));
        free(rtext);
    }
    return failures;
}

/* No gate runner: refused, but the turn ran and was recorded. */
static int mr_exec_no_runner(void)
{
    int failures = 0;
    struct mr_dirs d;
    struct muse_run_result r;
    char err[MUSE_RUN_ERROR_MAX] = {0};
    char *evidence = NULL;
    int rc = -1;
    memset(&r, 0, sizeof(r));
    MR_CHECK("refused run", mr_execute(FAKE_JOURNEY, &d, NULL, NULL,
        NULL, false, NULL, NULL, NULL, false, &r, err, &rc, &evidence) == 0);
    MR_CHECK("refused rc", rc == 1 && r.rc == 1);
    {
        char receipt[8192];
        char *rtext = NULL;
        (void)snprintf(receipt, sizeof(receipt), "%s/receipt.json",
            d.run);
        rtext = mr_read(receipt);
        MR_CHECK("refused receipt", rtext &&
            strstr(rtext, "\"verdict\":\"refused\"") &&
            strstr(rtext, "\"name\":\"u1\"") &&
            strstr(rtext, "\"attempt\":1"));
        free(rtext);
    }
    {
        char facts[8192];
        char *ftext = NULL;
        (void)snprintf(facts, sizeof(facts), "%s/muse.json", d.run);
        ftext = mr_read(facts);
        MR_CHECK("facts carry turn+tokens", ftext &&
            strstr(ftext, "\"turn\"") &&
            strstr(ftext, "\"total\":15") &&
            strstr(ftext, "\"worker\":\"w1\"") &&
            strstr(ftext, "\"model_resolved\":\"m-test\""));
        free(ftext);
    }
    {
        char turns[8192];
        char *ttext = NULL;
        (void)snprintf(turns, sizeof(turns), "%s/muse-turn.jsonl",
            d.run);
        ttext = mr_read(turns);
        MR_CHECK("admission recorded", ttext &&
            strstr(ttext, "\"turnId\""));
        free(ttext);
    }
    MR_CHECK("scope denied foreign paths", evidence &&
        evidence_has(evidence, "decide:c-deny") &&
        evidence_count(evidence, "decide:c-deny") == 2 &&
        evidence_count(evidence, "decide:c-allow") == 0);
    free(evidence);
    return failures;
}

/* Gate passes but nothing changed: failed, never pass. The engine
 * name rides the evidence, not the verdict. */
static int mr_exec_no_change(void)
{
    int failures = 0;
    struct mr_dirs d;
    struct muse_run_result r;
    char err[MUSE_RUN_ERROR_MAX] = {0};
    char *evidence = NULL;
    int rc = -1;
    memset(&r, 0, sizeof(r));
    MR_CHECK("no-change run", mr_execute(FAKE_JOURNEY, &d,
        mr_verdict_pass, mr_head_pass, NULL, false, NULL, NULL, NULL, false, &r, err,
        &rc, &evidence) == 0);
    MR_CHECK("no-change rc", rc == 1 && r.rc == 1);
    {
        char receipt[8192];
        char *rtext = NULL;
        (void)snprintf(receipt, sizeof(receipt), "%s/receipt.json",
            d.run);
        rtext = mr_read(receipt);
        MR_CHECK("no-change verdict", rtext &&
            strstr(rtext, "\"verdict\":\"failed\""));
        free(rtext);
    }
    {
        char facts[8192];
        char *ftext = NULL;
        (void)snprintf(facts, sizeof(facts), "%s/muse.json", d.run);
        ftext = mr_read(facts);
        MR_CHECK("no-change engine named", ftext &&
            strstr(ftext, "\"engine\":\"NO-CHANGE\""));
        free(ftext);
    }
    free(evidence);
    return failures;
}

/* Completed turn, failing gate: failed. Completed is not pass. */
static int mr_exec_failing_gate(void)
{
    int failures = 0;
    struct mr_dirs d;
    struct muse_run_result r;
    char err[MUSE_RUN_ERROR_MAX] = {0};
    char *evidence = NULL;
    int rc = -1;
    memset(&r, 0, sizeof(r));
    MR_CHECK("fail run", mr_execute(FAKE_JOURNEY, &d, mr_verdict_fail,
        mr_head_fail, NULL, true, NULL, NULL, NULL, false, &r, err, &rc, &evidence) == 0);
    MR_CHECK("fail rc", rc == 1 && r.rc == 1);
    {
        char receipt[8192];
        char *rtext = NULL;
        (void)snprintf(receipt, sizeof(receipt), "%s/receipt.json",
            d.run);
        rtext = mr_read(receipt);
        MR_CHECK("fail verdict", rtext &&
            strstr(rtext, "\"verdict\":\"failed\""));
        free(rtext);
    }
    free(evidence);
    return failures;
}

/* The named candidate artifact the gate checks for existence. */
static int mr_pass_candidate(const struct mr_dirs *d,
    const struct muse_run_result *r)
{
    int failures = 0;
    char cf[8192];
    size_t cn = strlen(r->candidate_file);
    bool named = cn > 15 &&
        strncmp(r->candidate_file, "candidate-", 10) == 0 &&
        strcmp(r->candidate_file + cn - 5, ".diff") == 0;
    MR_CHECK("pass candidate named", named);
    (void)snprintf(cf, sizeof(cf), "%s/%s", d->run,
        r->candidate_file);
    MR_CHECK("pass candidate on disk",
        named && access(cf, F_OK) == 0);
    return failures;
}

/* The facts file a passing run leaves behind. */
static int mr_pass_facts(const struct mr_dirs *d)
{
    int failures = 0;
    char facts[8192];
    char *ftext = NULL;
    (void)snprintf(facts, sizeof(facts), "%s/muse.json", d->run);
    ftext = mr_read(facts);
    MR_CHECK("pass evidence", ftext &&
        strstr(ftext, "\"verdict\":\"pass\"") &&
        strstr(ftext, "\"candidate\":\"") &&
        strstr(ftext, "\"verdict\":\"SUITE VERDICT"));
    free(ftext);
    return failures;
}

/* Passing gate plus a real diff: pass, rc 0, full contract. */
static int mr_exec_pass(void)
{
    int failures = 0;
    struct mr_dirs d;
    struct muse_run_result r;
    char err[MUSE_RUN_ERROR_MAX] = {0};
    char *evidence = NULL;
    int rc = -1;
    memset(&r, 0, sizeof(r));
    MR_CHECK("pass run", mr_execute(FAKE_JOURNEY, &d, mr_verdict_pass,
        mr_head_pass, NULL, true, NULL, NULL, NULL, false, &r, err, &rc, &evidence) == 0);
    MR_CHECK("pass rc", rc == 0 && r.rc == 0);
    MR_CHECK("pass verdict", strcmp(r.verdict, "pass") == 0);
    MR_CHECK("pass terminal", strcmp(r.terminal, "completed") == 0);
    MR_CHECK("pass identity", mr_hex40(r.base) &&
        mr_hex40(r.candidate) && r.session[0] &&
        r.turn[0] && r.turn_command[0]);
    MR_CHECK("pass gate token",
        strcmp(r.gate_evidence, "task_document:1/0") == 0 &&
        r.gate_present && r.gate_ran == 1 && r.gate_failed == 0);
    failures += mr_pass_candidate(&d, &r);
    MR_CHECK("pass tokens", r.total_tokens == 15 &&
        r.input_tokens == 10 && r.output_tokens == 5);
    failures += mr_pass_facts(&d);
    free(evidence);
    return failures;
}

/* Cancelled turn: cancelled without running the gate at all. */
static int mr_exec_cancelled(void)
{
    int failures = 0;
    struct mr_dirs d;
    struct muse_run_result r;
    char err[MUSE_RUN_ERROR_MAX] = {0};
    char *evidence = NULL;
    int rc = -1;
    memset(&r, 0, sizeof(r));
    MR_CHECK("cancelled run", mr_execute(FAKE_CANCELLED, &d,
        mr_verdict_pass, mr_head_pass,
        "touch \"$0.marker\"", true, NULL, NULL, NULL, false, &r, err, &rc,
        &evidence) == 0);
    MR_CHECK("cancelled rc", rc == 1 && r.rc == 1);
    {
        char receipt[8192];
        char *rtext = NULL;
        (void)snprintf(receipt, sizeof(receipt), "%s/receipt.json",
            d.run);
        rtext = mr_read(receipt);
        MR_CHECK("cancelled verdict", rtext &&
            strstr(rtext, "\"verdict\":\"cancelled\""));
        free(rtext);
    }
    {
        char marker[8192];
        (void)snprintf(marker, sizeof(marker),
            "%s/build/bin/test_parallel.marker", d.wt);
        MR_CHECK("gate never ran", access(marker, F_OK) != 0);
    }
    free(evidence);
    return failures;
}

/* Unknown host notification mid-turn: ignored, the turn completes. */
static int mr_exec_unknown_frame(void)
{
    int failures = 0;
    struct mr_dirs d;
    struct muse_run_result r;
    char err[MUSE_RUN_ERROR_MAX] = {0};
    char *evidence = NULL;
    int rc = -1;
    memset(&r, 0, sizeof(r));
    MR_CHECK("unknown frame run", mr_execute(FAKE_UNKNOWN, &d,
        mr_verdict_pass, mr_head_pass, NULL, true, NULL, NULL, NULL, false, &r, err,
        &rc, &evidence) == 0);
    MR_CHECK("unknown frame pass", rc == 0 && r.rc == 0 &&
        strcmp(r.verdict, "pass") == 0);
    free(evidence);
    return failures;
}

/* Malformed frame mid-turn: fail closed, refused, gate never runs. */
static int mr_exec_garbage(void)
{
    int failures = 0;
    struct mr_dirs d;
    struct muse_run_result r;
    char err[MUSE_RUN_ERROR_MAX] = {0};
    char *evidence = NULL;
    int rc = -1;
    memset(&r, 0, sizeof(r));
    MR_CHECK("garbage run", mr_execute(FAKE_GARBAGE, &d, NULL, NULL,
        NULL, false, NULL, NULL, NULL, false, &r, err, &rc, &evidence) == 0);
    MR_CHECK("garbage refused", rc == 1 && r.rc == 1 &&
        strcmp(r.verdict, "refused") == 0);
    {
        char receipt[8192];
        char *rtext = NULL;
        (void)snprintf(receipt, sizeof(receipt), "%s/receipt.json",
            d.run);
        rtext = mr_read(receipt);
        MR_CHECK("garbage receipt", rtext &&
            strstr(rtext, "\"verdict\":\"refused\""));
        free(rtext);
    }
    free(evidence);
    return failures;
}

/* Host exits mid-turn with no terminal: refused, never pass. */
static int mr_exec_host_exit(void)
{
    int failures = 0;
    struct mr_dirs d;
    struct muse_run_result r;
    char err[MUSE_RUN_ERROR_MAX] = {0};
    char *evidence = NULL;
    int rc = -1;
    memset(&r, 0, sizeof(r));
    MR_CHECK("host-exit run", mr_execute(FAKE_EXIT, &d, NULL, NULL,
        NULL, false, NULL, NULL, NULL, false, &r, err, &rc, &evidence) == 0);
    MR_CHECK("host-exit refused", rc == 1 && r.rc == 1 &&
        strcmp(r.verdict, "refused") == 0);
    free(evidence);
    return failures;
}

/* Silent host: the turn bound trips, the turn is cancelled first,
 * and the verdict is timeout. */
static int mr_exec_timeout(void)
{
    int failures = 0;
    struct mr_dirs d;
    struct muse_run_result r;
    struct muse_run_budgets b;
    char err[MUSE_RUN_ERROR_MAX] = {0};
    char *evidence = NULL;
    int rc = -1;
    memset(&r, 0, sizeof(r));
    memset(&b, 0, sizeof(b));
    b.turn_timeout_ms = 1500;
    b.gate_timeout_ms = 60000;
    MR_CHECK("timeout run", mr_execute(FAKE_HANG, &d, NULL,
        NULL, NULL, false, NULL, NULL, &b, false, &r, err, &rc, &evidence) == 0);
    MR_CHECK("timeout verdict", rc == 1 && r.rc == 1 &&
        strcmp(r.verdict, "timeout") == 0);
    MR_CHECK("timeout cancels first", evidence &&
        evidence_has(evidence, "cancel:"));
    free(evidence);
    return failures;
}

/* Token cap below the first usage report: refused mid-turn, and
 * the turn is cancelled first like a timeout. */
static int mr_exec_token_cap(void)
{
    int failures = 0;
    struct mr_dirs d;
    struct muse_run_result r;
    struct muse_run_budgets b;
    char err[MUSE_RUN_ERROR_MAX] = {0};
    char *evidence = NULL;
    int rc = -1;
    memset(&r, 0, sizeof(r));
    memset(&b, 0, sizeof(b));
    b.turn_timeout_ms = 30000;
    b.gate_timeout_ms = 60000;
    b.max_total_tokens = 10;
    MR_CHECK("cap run", mr_execute(FAKE_JOURNEY, &d, NULL,
        NULL, NULL, false, NULL, NULL, &b, false, &r, err, &rc, &evidence) == 0);
    MR_CHECK("cap refused", rc == 1 && r.rc == 1 &&
        strcmp(r.verdict, "refused") == 0);
    MR_CHECK("cap cancels first", evidence &&
        evidence_has(evidence, "cancel:"));
    free(evidence);
    return failures;
}

/* Model substitution: the run proceeds, both names are recorded. */
static int mr_exec_model_substitution(void)
{
    int failures = 0;
    struct mr_dirs d;
    struct muse_run_result r;
    char err[MUSE_RUN_ERROR_MAX] = {0};
    char *evidence = NULL;
    int rc = -1;
    const char *saved = s_fake_model;
    memset(&r, 0, sizeof(r));
    s_fake_model = "m-other";
    MR_CHECK("mismatch run", mr_execute(FAKE_JOURNEY, &d,
        mr_verdict_pass, mr_head_pass, NULL, true, NULL, "m-want", NULL, false, &r,
        err, &rc, &evidence) == 0);
    MR_CHECK("mismatch proceeds", rc == 0 && r.rc == 0);
    MR_CHECK("mismatch visible",
        strcmp(r.model_requested, "m-want") == 0 &&
        strcmp(r.model_resolved, "m-other") == 0);
    MR_CHECK("mismatch selects", evidence &&
        evidence_has(evidence, "model:m-want"));
    s_fake_model = saved;
    free(evidence);
    return failures;
}

/* Claim-held callers skip the receipt pre-check: a seeded receipt
 * does not stop the turn, and no receipt is written beside it.
 * The candidate artifact and muse.json still land. */
static int mr_exec_claim_held(void)
{
    int failures = 0;
    struct mr_dirs d;
    struct muse_run_result r;
    char err[MUSE_RUN_ERROR_MAX] = {0};
    char *evidence = NULL;
    char receipt[8192], *seed = NULL;
    int rc = -1;
    memset(&r, 0, sizeof(r));
    MR_CHECK("claimed run", mr_execute(FAKE_JOURNEY, &d,
        mr_verdict_pass, mr_head_pass, NULL, true, NULL, NULL,
        NULL, true, &r, err, &rc, &evidence) == 0);
    MR_CHECK("claimed proceeds", rc == 0 && r.rc == 0 &&
        strcmp(r.verdict, "pass") == 0);
    MR_CHECK("claimed turned", evidence &&
        evidence_has(evidence, "turn-cmd:"));
    (void)snprintf(receipt, sizeof(receipt), "%s/receipt.json",
        d.run);
    seed = mr_read(receipt);
    MR_CHECK("claimed writes no receipt", seed == NULL);
    free(seed);
    {
        char cf[8192];
        (void)snprintf(cf, sizeof(cf), "%s/%s", d.run,
            r.candidate_file);
        MR_CHECK("claimed names artifact",
            r.candidate_file[0] && access(cf, F_OK) == 0);
    }
    free(evidence);
    return failures;
}

/* The claim-held turn itself, over a transport this case owns so the
 * seeded receipt can be read back byte-for-byte afterwards. */
static int mr_claim_seed_turn(struct mr_dirs *d, const char *receipt,
    const char *seed_text)
{
    int failures = 0;
    struct muse_run_result r;
    struct muse_run_task t;
    char err[MUSE_RUN_ERROR_MAX] = {0};
    char *evidence = NULL;
    int ev2[2], to_fd = -1, from_fd = -1;
    pid_t child = -1;
    int rc = -1;
    memset(&r, 0, sizeof(r));
    if (pipe(ev2) != 0) {
        MR_CHECK("claimed pipe", false);
        return failures;
    }
    s_evidence_fd = ev2[1];
    if (!mr_task_for(d, &t, NULL, NULL, NULL)) {
        MR_CHECK("claimed task", false);
        close(ev2[0]); close(ev2[1]);
        return failures;
    }
    t.caller_holds_claim = true;
    if (!mr_fork_fake(FAKE_JOURNEY, ev2[0], &to_fd, &from_fd, &child)) {
        MR_CHECK("claimed fork", false);
        close(ev2[0]); close(ev2[1]);
        return failures;
    }
    err[0] = '\0';
    rc = muse_run_task_on_transport(&t, child, to_fd, from_fd, &r, err);
    close(to_fd);
    close(from_fd);
    {
        int status = 0;
        (void)waitpid(child, &status, 0);
    }
    close(ev2[1]);
    s_evidence_fd = -1;
    evidence = read_evidence(ev2[0]);
    close(ev2[0]);
    MR_CHECK("claimed seed ignored", rc == 0 &&
        strcmp(r.verdict, "pass") == 0);
    MR_CHECK("claimed seed turned", evidence &&
        evidence_has(evidence, "turn-cmd:"));
    {
        char *rtext = mr_read(receipt);
        MR_CHECK("claimed seed intact", rtext &&
            strcmp(rtext, seed_text) == 0);
        free(rtext);
    }
    free(evidence);
    return failures;
}

/* Claim-held with a seeded receipt: the turn still runs and the
 * seed is left byte-identical. */
static int mr_exec_claim_seed(void)
{
    int failures = 0;
    struct mr_dirs d;
    char receipt[8192];
    static const char seed_text[] =
        "{\"verdict\":\"failed\",\"seq\":7,\"name\":\"u1\","
        "\"attempt\":1}\n";
    MR_CHECK("claimed lane", mr_lane(&d));
    (void)snprintf(receipt, sizeof(receipt), "%s/receipt.json",
        d.run);
    MR_CHECK("claimed seed", mr_write(receipt, seed_text, 0));
    MR_CHECK("claimed gate",
        mr_gate_script(&d, mr_verdict_pass, mr_head_pass, NULL));
    {
        char f[8192];
        (void)snprintf(f, sizeof(f), "%s/edit.txt", d.wt);
        MR_CHECK("claimed dirty", mr_write(f, "changed\n", 0));
    }
    failures += mr_claim_seed_turn(&d, receipt, seed_text);
    return failures;
}

static int mr_failures_execute(void)
{
    int failures = 0;
    failures += mr_exec_no_runner();
    failures += mr_exec_no_change();
    failures += mr_exec_failing_gate();
    failures += mr_exec_pass();
    failures += mr_exec_cancelled();
    failures += mr_exec_unknown_frame();
    failures += mr_exec_garbage();
    failures += mr_exec_host_exit();
    failures += mr_exec_timeout();
    failures += mr_exec_token_cap();
    failures += mr_exec_model_substitution();
    failures += mr_exec_claim_held();
    failures += mr_exec_claim_seed();
    return failures;
}

/* The production glue refuses without a host whenever direction is
 * missing or unusable. These cases prove the refusal happens before
 * any model submission: no fake host is forked at all. */
static int mr_glue_job(struct wkr_job *job, const struct mr_dirs *d,
    const char *task)
{
    memset(job, 0, sizeof(*job));
    if (snprintf(job->rundir, sizeof(job->rundir), "%s", d->run) >=
        (int)sizeof(job->rundir))
        return -1;
    if (snprintf(job->name, sizeof(job->name), "u1") >=
        (int)sizeof(job->name))
        return -1;
    if (snprintf(job->kind, sizeof(job->kind), "leaf") >=
        (int)sizeof(job->kind))
        return -1;
    job->attempt = 1;
    job->seq = 7;
    if (snprintf(job->task, sizeof(job->task), "%s", task) >=
        (int)sizeof(job->task))
        return -1;
    job->token_cap = 200000;
    job->time_cap_s = 600;
    return 0;
}

static int mr_failures_glue(void)
{
    int failures = 0;
    struct mr_dirs d;
    struct wkr_job job;
    struct wkr_result res;
    MR_CHECK("glue lane", mr_lane(&d));
    memset(&res, 0, sizeof(res));
    MR_CHECK("glue null job",
        zcl_devagent_worker_muse_executor(NULL, &res) == false);
    memset(&job, 0, sizeof(job));
    MR_CHECK("glue null res",
        zcl_devagent_worker_muse_executor(&job, NULL) == false);
    /* No muse direction at all: refused, reason names the header. */
    MR_CHECK("glue task",
        mr_glue_job(&job, &d,
            "name=u1\nkind=leaf\nattempt=1\nmodel=\n\nJust do it.\n")
        == 0);
    memset(&res, 0, sizeof(res));
    MR_CHECK("glue bare refused",
        zcl_devagent_worker_muse_executor(&job, &res) == true);
    MR_CHECK("glue bare verdict", strcmp(res.terminal, "refused") == 0 &&
        res.rc == 1);
    MR_CHECK("glue bare reason",
        strstr(res.evidence, "muse-workspace") != NULL);
    /* Unusable workspace: refused before any host. */
    MR_CHECK("glue task",
        mr_glue_job(&job, &d,
            "name=u1\nkind=leaf\nattempt=1\nmodel=\n"
            "muse-workspace: /nonexistent-wt\nmuse-scope: src/\n"
            "muse-gate: g\n\nDo it.\n") == 0);
    memset(&res, 0, sizeof(res));
    MR_CHECK("glue workspace refused",
        zcl_devagent_worker_muse_executor(&job, &res) == true);
    MR_CHECK("glue workspace verdict", strcmp(res.terminal, "refused")
        == 0 && res.rc == 1);
    /* Missing rundir: refused before any host. */
    MR_CHECK("glue task",
        mr_glue_job(&job, &d,
            "name=u1\nkind=leaf\nattempt=1\nmodel=\n"
            "muse-workspace: /tmp\nmuse-scope: src/\n"
            "muse-gate: g\n\nDo it.\n") == 0);
    if (snprintf(job.rundir, sizeof(job.rundir), "/nonexistent-run")
        >= (int)sizeof(job.rundir)) {
        MR_CHECK("glue rundir fit", false);
    } else {
        memset(&res, 0, sizeof(res));
        MR_CHECK("glue rundir refused",
            zcl_devagent_worker_muse_executor(&job, &res) == true);
        MR_CHECK("glue rundir verdict", strcmp(res.terminal, "refused")
            == 0 && res.rc == 1);
    }
    /* Zero token cap: refused, never unbounded. */
    MR_CHECK("glue task",
        mr_glue_job(&job, &d,
            "name=u1\nkind=leaf\nattempt=1\nmodel=\n"
            "muse-workspace: /tmp\nmuse-scope: src/\n"
            "muse-gate: g\n\nDo it.\n") == 0);
    job.token_cap = 0;
    memset(&res, 0, sizeof(res));
    MR_CHECK("glue cap refused",
        zcl_devagent_worker_muse_executor(&job, &res) == true);
    MR_CHECK("glue cap verdict", strcmp(res.terminal, "refused") == 0 &&
        res.rc == 1);
    return failures;
}

int test_devagent_muse_run(void)
{
    int failures = 0;
    (void)mr_fake_lifecycle_refs;
    failures += mr_failures_validate();
    failures += mr_failures_parse();
    failures += mr_failures_precheck();
    failures += mr_failures_execute();
    failures += mr_failures_glue();
    if (failures == 0) printf("muse_run: all groups green\n");
    return failures;
}
#endif
