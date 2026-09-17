/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: dev.agent.worker — the resident DEV-ONLY loop that consumes
 *          dev.agent.queue continuously. post/next/reap/status/cancel stay
 *          the only scheduler; this leaf is the caller the queue contract
 *          leaves to the operator: claim ONE job, run the wired executor,
 *          judge it through the required gate, record receipt plus run.out
 *          for the existing reap, and post a result mail row under the SAME
 *          ref. Then repeat until the deadline, the idle limit, or the job
 *          cap.
 *
 * ── CONTRACT ─────────────────────────────────────────────────────────────
 *
 * STANDALONE, DEV-ONLY. This leaf never touches consensus, wallet,
 * deployment, or the canonical node: only the owner-private state root
 * (queue, engine run dirs, mail outbox) plus one worker.lock beside the
 * queue. No yolo, no API fallback, no wallet, no deploy, no push
 * authority anywhere in this file. The model is never polled: the loop
 * waits on local queue files with bounded sleep/backoff between claims.
 *
 * ONE ACTIVE JOB PER WORKER. worker.lock (flock, non-blocking, held for
 * the whole drive) refuses a second concurrent drive on the same queue.
 * The executor runs in a forked child under RLIMIT_CPU/RLIMIT_AS with a
 * wall-clock watchdog; the parent never blocks past the job cap.
 *
 * CLAIM BEFORE SUBMISSION. dev.agent.queue claim persists claim.json
 * (submitted:false) before this leaf ever sees the job; the leaf flips it
 * to submitted:true immediately before forking the executor. A restart
 * adopts orphans by that flag: submitted:false with no receipt is safe to
 * run exactly once; submitted:true (or an unreadable claim) with no
 * receipt is crash-recorded and NEVER resubmitted. Finished names are
 * refused by claim itself (CLAIM_COMPLETED).
 *
 * COMPLETION. A model terminal of "completed" is not PASS. The leaf
 * writes receipt verdict "pass" only when the executor's own word is
 * pass/PASS with rc 0 AND the candidate artifact exists AND evidence is
 * present AND tokens fit the cap; everything else keeps its own word
 * (failed, gate-refused, timeout, crashed, no-receipt, limit-exceeded)
 * and stays incomplete under the shared closed predicate. crash and no
 * receipt follow the existing policy: reap records them incomplete, no
 * requeue is invented here. Queued cancel prevents claim (the row is
 * gone); a running row refuses cancel and stays the worker's own
 * shutdown business (SIGTERM finishes nothing new: no new claims, the
 * in-flight job is crash-recorded).
 *
 * EXECUTOR SEAM. wkr_executor_fn is the whole production seam. The leaf
 * wires zcl_devagent_worker_no_executor (always refuses) until operator
 * relay supplies C's muse_session; the drive, gate, limits, receipts,
 * mail, and restart rules do not change when it drops in. Tests wire
 * fixtures through zcl_devagent_worker_drive directly.
 */

#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif

#include "command/native_command.h"
#include "command/native_devagent.h"

#include "base/safe_alloc.h"
#include "config/command_catalog.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "platform/state_root.h"
#include "platform/time_compat.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#if !defined(_WIN32)
#include <sys/file.h>
#include <sys/resource.h>
#include <sys/wait.h>
#endif

#define WKR_LEAF "dev.agent.worker"
#define WKR_RESULT_FILE "executor_result.json"
#define WKR_CLAIM_FILE "claim.json"
#define WKR_RECEIPT_FILE "receipt.json"
#define WKR_RUNOUT_FILE "run.out"
#define WKR_LOCK_FILE "worker.lock"
#define WKR_FILE_CAP (64u * 1024u)
#define WKR_TASK_BRIEF_CAP (32u * 1024u)
#define WKR_SLICE_NS (25u * 1000u * 1000u)

/* SIGTERM asks for shutdown between jobs; the wait slices also honor it
 * so an in-flight job is crash-recorded instead of orphaned. */
static volatile sig_atomic_t g_wkr_term = 0;

static void wkr_on_term(int sig)
{
    (void)sig;
    g_wkr_term = 1;
}

static void wkr_fail(struct zcl_command_reply *reply, const char *code,
                     const char *phase, const char *msg, const char *evidence)
{
    (void)json_push_kv_str(&reply->data, "leaf", WKR_LEAF);
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                           ZCL_COMMAND_EXIT_FAILED, code, phase, false,
                           false, msg, evidence);
    reply->error.human_action_required = true;
}

/* ── sibling sub-dispatch (same in-process shape the CLI takes) ────────── */

struct wkr_sub {
    struct json_value input;
    struct zcl_command_request request;
    struct zcl_command_reply reply;
    bool ran;
    bool valid;
};

static void wkr_sub_begin(struct wkr_sub *s, const char *schema,
                          const char *sib_path)
{
    json_init(&s->input);
    json_set_object(&s->input);
    memset(&s->request, 0, sizeof(s->request));
    s->request.input = &s->input;
    s->request.spec =
        zcl_command_registry_find(zcl_command_catalog(), sib_path, NULL);
    s->request.view = "normal";
    zcl_command_reply_init(&s->reply, schema);
    s->ran = false;
    s->valid = s->request.spec != NULL;
}

static void wkr_sub_end(struct wkr_sub *s)
{
    zcl_command_reply_free(&s->reply);
    json_free(&s->input);
    s->ran = false;
}

static bool wkr_sub_input(struct wkr_sub *s, const char *text)
{
    struct json_value tmp;
    if (!s || !text)
        return false;
    json_init(&tmp);
    if (!json_read(&tmp, text, strlen(text))) {
        json_free(&tmp);
        return false;
    }
    json_free(&s->input);
    s->input = tmp;
    s->request.input = &s->input;
    return true;
}

static bool wkr_sub_ok(const struct wkr_sub *s)
{
    return s && s->ran && s->reply.status == ZCL_COMMAND_STATUS_PASSED;
}

static const char *wkr_sub_str(const struct wkr_sub *s, const char *key)
{
    const struct json_value *v;
    if (!s || !key)
        return "";
    v = json_get(&s->reply.data, key);
    return (v && v->type == JSON_STR) ? json_get_str(v) : "";
}

static long long wkr_sub_int(const struct wkr_sub *s, const char *key,
                             long long dflt)
{
    const struct json_value *v;
    if (!s || !key)
        return dflt;
    v = json_get(&s->reply.data, key);
    if (!v || v->type != JSON_INT)
        return dflt;
    return (long long)json_get_int(v);
}

/* ── state dirs and bounded files ──────────────────────────────────────── */

static bool wkr_state_dir(char *out, size_t cap, const char *leaf)
{
    char root[4096];
    if (!out || cap == 0 || !leaf)
        return false;
    if (!platform_state_root(root, sizeof(root)))
        return false;
    if (snprintf(out, cap, "%s/%s", root, leaf) >= (int)cap)
        return false;
    return true;
}

static bool wkr_read_file(const char *path, char *out, size_t cap)
{
    FILE *f;
    size_t n;
    if (!path || !out || cap == 0)
        return false;
    f = fopen(path, "rb");
    if (!f)
        return false;
    n = fread(out, 1, cap - 1, f);
    if (ferror(f)) {
        (void)fclose(f);
        return false;
    }
    if (!feof(f)) {
        (void)fclose(f);
        return false;
    }
    out[n] = '\0';
    (void)fclose(f);
    return true;
}

static bool wkr_file_exists(const char *path)
{
    struct stat st;
    return path && stat(path, &st) == 0;
}

/* Atomic small write: temp in the same dir renamed over the target, so a
 * crash never leaves a half claim behind. */
static bool wkr_write_atomic(const char *path, const char *text, size_t len)
{
    char tmp[4096 + 32];
    FILE *f;
    if (!path || !text)
        return false;
    if (snprintf(tmp, sizeof(tmp), "%s.tmp", path) >= (int)sizeof(tmp))
        return false;
    f = fopen(tmp, "wb");
    if (!f)
        return false;
    if (len > 0 && fwrite(text, 1, len, f) != len) {
        (void)fclose(f);
        (void)unlink(tmp);
        return false;
    }
    if (fclose(f) != 0) {
        (void)unlink(tmp);
        return false;
    }
    if (rename(tmp, path) != 0) {
        (void)unlink(tmp);
        return false;
    }
    return true;
}

/* JSON string escape for the small files this leaf writes. */
static bool wkr_escape(const char *in, char *out, size_t cap)
{
    size_t used = 0;
    if (!in || !out || cap == 0)
        return false;
    for (; *in; in++) {
        unsigned char c = (unsigned char)*in;
        const char *rep = NULL;
        char tmp[8];
        if (c == '"')
            rep = "\\\"";
        else if (c == '\\')
            rep = "\\\\";
        else if (c == '\n')
            rep = "\\n";
        else if (c == '\t')
            rep = "\\t";
        else if (c < 0x20) {
            (void)snprintf(tmp, sizeof(tmp), "\\u%04x", c);
            rep = tmp;
        }
        if (rep) {
            size_t n = strlen(rep);
            if (used + n >= cap)
                return false;
            memcpy(out + used, rep, n);
            used += n;
        } else {
            if (used + 1 >= cap)
                return false;
            out[used++] = (char)c;
        }
    }
    if (used >= cap)
        return false;
    out[used] = '\0';
    return true;
}

/* ── reap: settle whatever finished since the last pass ────────────────── */

static void wkr_reap(void)
{
    struct wkr_sub sub;
    wkr_sub_begin(&sub, "zcl.agent_queue.v1", "dev.agent.queue");
    if (!sub.valid) {
        wkr_sub_end(&sub);
        return;
    }
    if (!wkr_sub_input(&sub, "{\"action\":\"reap\"}")) {
        wkr_sub_end(&sub);
        return;
    }
    zcl_native_handle_dev_agent_queue(&sub.request, &sub.reply);
    sub.ran = true;
    wkr_sub_end(&sub);
}

/* ── claim: take the oldest unfinished row ──────────────────────────────
 * Returns 1 with job filled, 0 when the queue is empty, -1 when claim
 * refuses (completed name, bad input, or a ledger failure). */

static void wkr_fill_job_from_claim(const struct wkr_sub *sub,
                                    const struct wkr_drive_opts *opts,
                                    struct wkr_job *job)
{
    const char *s;
    memset(job, 0, sizeof(*job));
    s = wkr_sub_str(sub, "rundir");
    (void)snprintf(job->rundir, sizeof(job->rundir), "%s", s);
    s = wkr_sub_str(sub, "name");
    (void)snprintf(job->name, sizeof(job->name), "%s", s);
    s = wkr_sub_str(sub, "kind");
    (void)snprintf(job->kind, sizeof(job->kind), "%s", s);
    job->attempt = wkr_sub_int(sub, "attempt", 1);
    job->seq = wkr_sub_int(sub, "seq", 0);
    s = wkr_sub_str(sub, "model");
    if (!s[0])
        s = opts->model;
    (void)snprintf(job->model, sizeof(job->model), "%s", s ? s : "");
    job->token_cap = opts->token_cap;
    job->time_cap_s = opts->time_cap_s;
}

/* Executor-ready text: identity lines plus the brief file head for
 * doc/file kinds. A missing brief degrades to identity lines only —
 * the executor decides whether that suffices, the gate still judges. */
static void wkr_compose_task(const struct wkr_sub *sub, struct wkr_job *job)
{
    const char *brief = wkr_sub_str(sub, "brief");
    char head[WKR_TASK_BRIEF_CAP];
    int w = snprintf(job->task, sizeof(job->task),
                     "name=%s\nkind=%s\nattempt=%lld\nmodel=%s\n",
                     job->name, job->kind, job->attempt, job->model);
    if (w <= 0 || (size_t)w >= sizeof(job->task)) {
        job->task[0] = '\0';
        return;
    }
    if (!brief[0])
        return;
    if (!wkr_read_file(brief, head, sizeof(head)))
        return;
    {
        size_t used = strlen(job->task);
        size_t room = sizeof(job->task) - used - 1;
        size_t n = strlen(head);
        if (n > room)
            n = room;
        memcpy(job->task + used, head, n);
        job->task[used + n] = '\0';
    }
}

static int wkr_claim_job(const struct wkr_drive_opts *opts,
                         struct wkr_job *job)
{
    struct wkr_sub sub;
    char input[512];
    const char *state;
    int rc = -1;
    if (!opts || !job)
        return -1;
    if (snprintf(input, sizeof(input),
                 "{\"action\":\"claim\",\"worker\":\"%.48s\","
                 "\"session\":\"%.48s\",\"model\":\"%.128s\"}",
                 opts->worker, opts->session, opts->model) >=
        (int)sizeof(input))
        return -1;
    wkr_sub_begin(&sub, "zcl.agent_queue.v1", "dev.agent.queue");
    if (!sub.valid) {
        wkr_sub_end(&sub);
        return -1;
    }
    if (!wkr_sub_input(&sub, input)) {
        wkr_sub_end(&sub);
        return -1;
    }
    zcl_native_handle_dev_agent_queue(&sub.request, &sub.reply);
    sub.ran = true;
    if (!wkr_sub_ok(&sub)) {
        wkr_sub_end(&sub);
        return -1;
    }
    state = wkr_sub_str(&sub, "state");
    if (strcmp(state, "empty") == 0)
        rc = 0;
    else if (strcmp(state, "running") == 0) {
        wkr_fill_job_from_claim(&sub, opts, job);
        wkr_compose_task(&sub, job);
        rc = (job->rundir[0] && job->name[0]) ? 1 : -1;
    }
    wkr_sub_end(&sub);
    return rc;
}

/* ── claim.json: the submitted flag ──────────────────────────────────────
 * -1 unreadable/unparseable (fail closed: never submit), 0 submitted:false
 * (safe to run exactly once), 1 submitted:true (never resubmit). */

static int wkr_claim_submitted(const char *rundir)
{
    char path[4096 + 32], text[2048];
    const char *p;
    if (!rundir)
        return -1;
    if (snprintf(path, sizeof(path), "%s/%s", rundir, WKR_CLAIM_FILE) >=
        (int)sizeof(path))
        return -1;
    if (!wkr_read_file(path, text, sizeof(text)))
        return -1;
    p = strstr(text, "\"submitted\":");
    if (!p)
        return -1;
    p += strlen("\"submitted\":");
    if (strncmp(p, "true", 4) == 0)
        return 1;
    if (strncmp(p, "false", 5) == 0)
        return 0;
    return -1;
}

/* Flip submitted:false to submitted:true, atomically, immediately before
 * the executor fork. False when the flag is absent (nothing to flip —
 * the caller treats that as un-runnable, never as un-submitted). */
static bool wkr_set_submitted(const char *rundir)
{
    char path[4096 + 32], text[2048];
    const char *hit;
    if (!rundir)
        return false;
    if (snprintf(path, sizeof(path), "%s/%s", rundir, WKR_CLAIM_FILE) >=
        (int)sizeof(path))
        return false;
    if (!wkr_read_file(path, text, sizeof(text)))
        return false;
    hit = strstr(text, "\"submitted\":false");
    if (!hit)
        return false;
    {
        char out[2048];
        size_t pre = (size_t)(hit - text);
        size_t rest = strlen(hit + strlen("\"submitted\":false"));
        const char *mid = "\"submitted\":true";
        if (pre + strlen(mid) + rest >= sizeof(out))
            return false;
        memcpy(out, text, pre);
        memcpy(out + pre, mid, strlen(mid));
        memcpy(out + pre + strlen(mid), hit + strlen("\"submitted\":false"),
               rest + 1);
        return wkr_write_atomic(path, out, strlen(out));
    }
}

/* ── adopt: resume an orphaned running row ───────────────────────────────
 * A running worker row with no receipt and no run.out belongs to a dead
 * drive (this drive holds worker.lock, so no other drive can own it).
 * submitted:false runs exactly once; anything else crash-records without
 * ever submitting. Returns 1 with job filled, 0 when no orphan waits. */

static bool wkr_row_is_orphan(const char *rundir)
{
    char path[4096 + 32];
    if (!rundir)
        return false;
    if (snprintf(path, sizeof(path), "%s/%s", rundir, WKR_RECEIPT_FILE) >=
        (int)sizeof(path))
        return false;
    if (wkr_file_exists(path))
        return false;
    if (snprintf(path, sizeof(path), "%s/%s", rundir, WKR_RUNOUT_FILE) >=
        (int)sizeof(path))
        return false;
    return !wkr_file_exists(path);
}

static long long wkr_row_attempt(const struct json_value *v)
{
    if (!v || v->type != JSON_INT)
        return 0;
    return (long long)json_get_int(v);
}

/* A worker-owned running row with a usable name and attempt. */
static bool wkr_row_mine(const struct json_value *r, const char **name,
                         long long *attempt)
{
    const struct json_value *v;
    const char *owner;
    if (!r || r->type != JSON_OBJ || !name || !attempt)
        return false;
    v = json_get(r, "pid_or_unit");
    owner = (v && v->type == JSON_STR) ? json_get_str(v) : "";
    if (strncmp(owner, "worker:", 7) != 0)
        return false;
    v = json_get(r, "name");
    *name = (v && v->type == JSON_STR) ? json_get_str(v) : "";
    *attempt = wkr_row_attempt(json_get(r, "attempt"));
    return (*name)[0] != '\0' && *attempt >= 1;
}

static void wkr_adopt_fill(const struct json_value *r, const char *rundir,
                           const char *name, long long attempt,
                           const struct wkr_drive_opts *opts,
                           struct wkr_job *job, int *submitted)
{
    const struct json_value *v = json_get(r, "kind");
    memset(job, 0, sizeof(*job));
    (void)snprintf(job->rundir, sizeof(job->rundir), "%s", rundir);
    (void)snprintf(job->name, sizeof(job->name), "%s", name);
    job->attempt = attempt;
    (void)snprintf(job->kind, sizeof(job->kind), "%s",
                   (v && v->type == JSON_STR) ? json_get_str(v) : "leaf");
    (void)snprintf(job->model, sizeof(job->model), "%s", opts->model);
    job->token_cap = opts->token_cap;
    job->time_cap_s = opts->time_cap_s;
    *submitted = wkr_claim_submitted(rundir);
}

/* One running row examined for adoption: a worker-owned orphan fills
 * the job. Returns 1 adopted, 0 not an orphan. */
static int wkr_adopt_row(const struct json_value *r, const char *enginedir,
                         const struct wkr_drive_opts *opts,
                         struct wkr_job *job, int *submitted)
{
    const char *name = NULL;
    long long attempt = 0;
    char rundir[4096];
    if (!enginedir || !opts || !job || !submitted)
        return 0;
    if (!wkr_row_mine(r, &name, &attempt))
        return 0;
    if (snprintf(rundir, sizeof(rundir), "%s/%s/a%lld", enginedir, name,
                 attempt) >= (int)sizeof(rundir))
        return 0;
    if (!wkr_row_is_orphan(rundir))
        return 0;
    wkr_adopt_fill(r, rundir, name, attempt, opts, job, submitted);
    return 1;
}

static int wkr_adopt_job(const struct wkr_drive_opts *opts,
                         struct wkr_job *job, int *submitted)
{
    struct wkr_sub sub;
    const struct json_value *arr;
    char enginedir[4096];
    size_t n, i;
    int rc = 0;
    if (!opts || !job || !submitted)
        return -1;
    if (!wkr_state_dir(enginedir, sizeof(enginedir), "engine"))
        return -1;
    wkr_sub_begin(&sub, "zcl.agent_queue.v1", "dev.agent.queue");
    if (!sub.valid) {
        wkr_sub_end(&sub);
        return -1;
    }
    if (!wkr_sub_input(&sub, "{\"action\":\"status\",\"json\":true}")) {
        wkr_sub_end(&sub);
        return -1;
    }
    zcl_native_handle_dev_agent_queue(&sub.request, &sub.reply);
    sub.ran = true;
    if (!wkr_sub_ok(&sub)) {
        wkr_sub_end(&sub);
        return -1;
    }
    arr = json_get(&sub.reply.data, "running");
    if (arr && arr->type == JSON_ARR) {
        n = json_size(arr);
        for (i = 0; i < n && rc == 0; i++)
            rc = wkr_adopt_row(json_at(arr, i), enginedir, opts, job,
                               submitted);
    }
    wkr_sub_end(&sub);
    return rc;
}

/* ── spawn: run the executor bounded ─────────────────────────────────────
 * The child takes RLIMIT_CPU/RLIMIT_AS, runs the wired executor, writes
 * executor_result.json, and exits. The parent watches the wall clock in
 * slices and kills past the cap. Outcomes: 1 ran (result file or not —
 * the caller parses), 0 timed out (killed), -1 launch/wait failure.
 * A crashed child is a ran-without-result: no receipt, reap records it
 * incomplete. SIGTERM in flight kills the child and crash-records. */

struct wkr_spawn_out {
    int status;          /* 1 ran, 0 timeout, -1 failed */
    long long wall_ms;
    bool signaled;
};

#if defined(_WIN32)
static struct wkr_spawn_out wkr_spawn(const struct wkr_drive_opts *opts,
                                      const struct wkr_job *job,
                                      wkr_executor_fn exec)
{
    struct wkr_spawn_out out;
    (void)opts;
    (void)job;
    (void)exec;
    memset(&out, 0, sizeof(out));
    out.status = -1;
    return out;
}
#else

/* Child side only: confine, run, record, exit. Never returns. */
static void wkr_child_run(const struct wkr_drive_opts *opts,
                          const struct wkr_job *job, wkr_executor_fn exec)
{
    struct wkr_result res;
    struct rlimit rl;
    char path[4096 + 64], e_term[96], e_cand[512], e_ev[8192], line[12288];
    int w;
    if (opts->cpu_s > 0) {
        rl.rlim_cur = rl.rlim_max = (rlim_t)opts->cpu_s;
        (void)setrlimit(RLIMIT_CPU, &rl);
    }
    if (opts->mem_mb > 0) {
        rl.rlim_cur = rl.rlim_max =
            (rlim_t)opts->mem_mb * 1024u * 1024u;
        (void)setrlimit(RLIMIT_AS, &rl);
    }
    memset(&res, 0, sizeof(res));
    if (!exec(job, &res))
        _exit(125);
    if (!wkr_escape(res.terminal, e_term, sizeof(e_term)) ||
        !wkr_escape(res.candidate, e_cand, sizeof(e_cand)) ||
        !wkr_escape(res.evidence, e_ev, sizeof(e_ev)))
        _exit(126);
    w = snprintf(line, sizeof(line),
                 "{\"terminal\":\"%s\",\"rc\":%lld,\"candidate\":\"%s\","
                 "\"evidence\":\"%s\",\"tokens_used\":%lld,\"wall_ms\":%lld}\n",
                 e_term, res.rc, e_cand, e_ev, res.tokens_used,
                 res.wall_ms);
    if (w <= 0 || (size_t)w >= sizeof(line))
        _exit(126);
    if (snprintf(path, sizeof(path), "%s/%s", job->rundir,
                 WKR_RESULT_FILE) >= (int)sizeof(path))
        _exit(126);
    if (!wkr_write_atomic(path, line, (size_t)w))
        _exit(126);
    _exit(res.rc >= 0 && res.rc <= 125 ? (int)res.rc : 125);
}

/* Parent wait in slices: wall cap, SIGTERM, crash, and exit capture.
 * Seconds through the unclassified platform seam, never a raw syscall. */
static struct wkr_spawn_out wkr_wait_child(pid_t pid, long long cap_s,
                                           long long t0_s)
{
    struct wkr_spawn_out out;
    memset(&out, 0, sizeof(out));
    out.status = -1;
    for (;;) {
        int st = 0;
        pid_t got;
        struct timespec slice;
        long long now_s = platform_time_wall_unix();
        if (g_wkr_term) {
            (void)kill(pid, SIGKILL);
            (void)waitpid(pid, &st, 0);
            out.signaled = true;
            break;
        }
        if (cap_s > 0 && now_s - t0_s >= cap_s) {
            (void)kill(pid, SIGKILL);
            (void)waitpid(pid, &st, 0);
            out.status = 0;
            break;
        }
        got = waitpid(pid, &st, WNOHANG);
        if (got == pid) {
            out.status = 1;
            out.signaled = WIFSIGNALED(st) ? true : false;
            break;
        }
        if (got < 0 && errno != EINTR)
            break;
        slice.tv_sec = 0;
        slice.tv_nsec = WKR_SLICE_NS;
        (void)nanosleep(&slice, NULL);
    }
    out.wall_ms = (platform_time_wall_unix() - t0_s) * 1000LL;
    return out;
}

static struct wkr_spawn_out wkr_spawn(const struct wkr_drive_opts *opts,
                                      const struct wkr_job *job,
                                      wkr_executor_fn exec)
{
    struct wkr_spawn_out out;
    pid_t pid;
    long long t0_s;
    memset(&out, 0, sizeof(out));
    out.status = -1;
    if (!opts || !job || !exec)
        return out;
    t0_s = platform_time_wall_unix();
    pid = fork();
    if (pid < 0)
        return out;
    if (pid == 0)
        wkr_child_run(opts, job, exec);
    out = wkr_wait_child(pid, opts->time_cap_s, t0_s);
    return out;
}
#endif

/* ── result parse ────────────────────────────────────────────────────────
 * True when executor_result.json carries a usable outcome. The executor's
 * own word is preserved verbatim (bounded charset); "completed" stays
 * "completed" here and the gate refuses to upgrade it. */

static bool wkr_word_ok(const char *s)
{
    size_t i;
    if (!s || !s[0] || strlen(s) > 24)
        return false;
    for (i = 0; s[i]; i++) {
        char c = s[i];
        if ((c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && c != '-' &&
            c != '_')
            return false;
    }
    return true;
}

/* Success-sounding executor words that are NOT the closed pass
 * vocabulary. The gate refuses to carry them into the receipt: only
 * pass/PASS gate to pass, everything else that sounds finished gates to
 * gate-refused so no reader mistakes it for completion. */
static bool wkr_success_alias(const char *s)
{
    static const char *const aliases[] = {
        "completed", "complete", "done", "finished", "success",
        "succeeded", "successful", "ok",
    };
    size_t i;
    if (!s)
        return false;
    for (i = 0; i < sizeof(aliases) / sizeof(aliases[0]); i++) {
        if (strcmp(s, aliases[i]) == 0)
            return true;
    }
    return false;
}

/* One raw string field copied out of the result text, unescaped. */
static void wkr_result_field(const char *text, const char *key, char *out,
                             size_t cap)
{
    char pat[64];
    const char *p;
    size_t n = 0;
    if (!text || !key || !out || cap == 0)
        return;
    out[0] = '\0';
    if (snprintf(pat, sizeof(pat), "\"%s\":\"", key) >= (int)sizeof(pat))
        return;
    p = strstr(text, pat);
    if (!p)
        return;
    p += strlen(pat);
    while (p[n] && p[n] != '"' && n + 1 < cap) {
        out[n] = p[n];
        n++;
    }
    out[n] = '\0';
}

static long long wkr_result_int(const char *text, const char *key,
                                long long dflt)
{
    char pat[64];
    const char *p;
    if (!text || !key)
        return dflt;
    if (snprintf(pat, sizeof(pat), "\"%s\":", key) >= (int)sizeof(pat))
        return dflt;
    p = strstr(text, pat);
    if (!p)
        return dflt;
    return strtoll(p + strlen(pat), NULL, 10);
}

static bool wkr_parse_result(const char *rundir, struct wkr_result *res)
{
    char path[4096 + 64], text[12288];
    char word[32];
    if (!rundir || !res)
        return false;
    if (snprintf(path, sizeof(path), "%s/%s", rundir, WKR_RESULT_FILE) >=
        (int)sizeof(path))
        return false;
    if (!wkr_read_file(path, text, sizeof(text)))
        return false;
    memset(res, 0, sizeof(*res));
    wkr_result_field(text, "terminal", word, sizeof(word));
    if (!wkr_word_ok(word))
        return false;
    (void)snprintf(res->terminal, sizeof(res->terminal), "%s", word);
    wkr_result_field(text, "candidate", res->candidate,
                     sizeof(res->candidate));
    wkr_result_field(text, "evidence", res->evidence,
                     sizeof(res->evidence));
    res->rc = wkr_result_int(text, "rc", -1);
    res->tokens_used = wkr_result_int(text, "tokens_used", 0);
    res->wall_ms = wkr_result_int(text, "wall_ms", 0);
    return true;
}

/* ── gate: the required Z23 judgment ─────────────────────────────────────
 * "pass" is written only when every condition holds: the executor's own
 * word is already pass/PASS, rc is 0, a candidate is named AND present
 * under the run dir, evidence is present, and tokens fit the cap. A
 * model "completed" with rc 0 and a candidate still gates to
 * "gate-refused": only the gate plus the closed predicate reap success.
 * Returns the receipt rc (0 on pass, nonzero otherwise). */

/* Every pass condition at once: the executor's own pass/PASS word, a
 * clean exit, a named candidate that exists under the run dir, evidence,
 * and tokens inside the cap. */
static bool wkr_gate_ready(const struct wkr_job *job,
                           const struct wkr_result *res)
{
    char candpath[4096 + 256];
    bool word, clean, named, evidenced, budgeted;
    if (!job || !res)
        return false;
    word = strcmp(res->terminal, "pass") == 0 ||
           strcmp(res->terminal, "PASS") == 0;
    clean = res->rc == 0;
    named = res->candidate[0] != '\0';
    evidenced = res->evidence[0] != '\0';
    budgeted = res->tokens_used >= 0 && res->tokens_used <= job->token_cap;
    if (!word || !clean || !named || !evidenced || !budgeted)
        return false;
    if (snprintf(candpath, sizeof(candpath), "%s/%s", job->rundir,
                 res->candidate) >= (int)sizeof(candpath))
        return false;
    return wkr_file_exists(candpath);
}

static long long wkr_gate(const struct wkr_job *job,
                          const struct wkr_result *res, char *verdict,
                          size_t cap)
{
    bool word;
    if (!job || !res || !verdict || cap == 0)
        return 1;
    if (wkr_gate_ready(job, res)) {
        (void)snprintf(verdict, cap, "%s", res->terminal);
        return 0;
    }
    word = strcmp(res->terminal, "pass") == 0 ||
           strcmp(res->terminal, "PASS") == 0;
    if (!wkr_word_ok(res->terminal) || res->terminal[0] == '\0')
        (void)snprintf(verdict, cap, "%s", "failed");
    else if (word || wkr_success_alias(res->terminal))
        (void)snprintf(verdict, cap, "%s", "gate-refused");
    else
        (void)snprintf(verdict, cap, "%s", res->terminal);
    return 1;
}

/* ── finish: run.out always, receipt only on a gated outcome ─────────────
 * run.out carries rc=N for the existing reap scan; receipt.json carries
 * the verdict reap judges. Crash/timeout/no-result write run.out alone,
 * so reap records them incomplete without inventing a verdict. */

static void wkr_write_runout(const struct wkr_job *job, long long rc,
                             const char *note)
{
    char path[4096 + 32], text[4096];
    int w;
    if (!job || !note)
        return;
    if (snprintf(path, sizeof(path), "%s/%s", job->rundir,
                 WKR_RUNOUT_FILE) >= (int)sizeof(path))
        return;
    w = snprintf(text, sizeof(text), "rc=%lld\n%s\n", rc, note);
    if (w <= 0 || (size_t)w >= sizeof(text))
        return;
    (void)wkr_write_atomic(path, text, (size_t)w);
}

static void wkr_write_receipt(const struct wkr_drive_opts *opts,
                              const struct wkr_job *job, const char *verdict,
                              const struct wkr_result *res)
{
    char path[4096 + 32], text[4096];
    char e_cand[512];
    int w;
    if (!opts || !job || !verdict || !res)
        return;
    if (snprintf(path, sizeof(path), "%s/%s", job->rundir,
                 WKR_RECEIPT_FILE) >= (int)sizeof(path))
        return;
    if (!wkr_escape(res->candidate, e_cand, sizeof(e_cand)))
        return;
    w = snprintf(text, sizeof(text),
                 "{\"verdict\":\"%s\",\"worker\":\"%.48s\","
                 "\"session\":\"%.48s\",\"model\":\"%.128s\","
                 "\"candidate\":\"%s\",\"tokens\":%lld,\"wall_ms\":%lld,"
                 "\"ts\":%lld}\n",
                 verdict, opts->worker, opts->session, job->model, e_cand,
                 res->tokens_used, res->wall_ms,
                 (long long)platform_time_wall_unix());
    if (w <= 0 || (size_t)w >= sizeof(text))
        return;
    (void)wkr_write_atomic(path, text, (size_t)w);
}

/* Result mail under the SAME ref: flat scanner-safe key=value lines, no
 * absolute paths (the mail leaf refuses paths outside the checkout).
 * Best-effort: the outcome row is the record; mail is its readable
 * copy for brief/evidence. */

static void wkr_mail_result(const struct wkr_drive_opts *opts,
                            const struct wkr_job *job, const char *terminal,
                            const char *candidate, const char *verdict,
                            long long rc, long long tokens, long long wall_ms)
{
    struct wkr_sub sub;
    char body[2048], ebody[8192], eref[192], input[9216];
    int w;
    if (!opts || !job || !terminal || !verdict)
        return;
    if (!candidate)
        candidate = "";
    w = snprintf(body, sizeof(body),
                 "ref=%s\nworker=%s\nsession=%s\nmodel=%s\nattempt=%lld\n"
                 "terminal=%s\ncandidate=%s\ngate=%s\nrc=%lld\ntokens=%lld\n"
                 "wall_ms=%lld\n",
                 job->name, opts->worker, opts->session, job->model,
                 job->attempt, terminal, candidate, verdict, rc, tokens,
                 wall_ms);
    if (w <= 0 || (size_t)w >= sizeof(body))
        return;
    if (!wkr_escape(body, ebody, sizeof(ebody)) ||
        !wkr_escape(job->name, eref, sizeof(eref)))
        return;
    if (snprintf(input, sizeof(input),
                 "{\"action\":\"post\",\"to\":\"*\",\"kind\":\"result\","
                 "\"body\":\"%s\",\"ref\":\"%s\",\"from\":\"%.48s\"}",
                 ebody, eref, opts->worker) >= (int)sizeof(input))
        return;
    wkr_sub_begin(&sub, "zcl.agent_mail.v1", "dev.agent.mail");
    if (!sub.valid) {
        wkr_sub_end(&sub);
        return;
    }
    if (!wkr_sub_input(&sub, input)) {
        wkr_sub_end(&sub);
        return;
    }
    zcl_native_handle_dev_agent_mail(&sub.request, &sub.reply);
    sub.ran = true;
    wkr_sub_end(&sub);
}

/* ── run one job ─────────────────────────────────────────────────────────
 * fresh: flip submitted pre-fork, spawn, gate, finish, mail. adopted
 * with submitted!=false: crash-record without ever submitting. Returns
 * 1 processed, 0 when there was no executor to run. */

static long long wkr_run_fresh(const struct wkr_drive_opts *opts,
                               const struct wkr_job *job,
                               wkr_executor_fn exec)
{
    struct wkr_spawn_out out;
    struct wkr_result res;
    char verdict[32];
    long long rc;
    bool have_res = false;
    if (!wkr_set_submitted(job->rundir)) {
        wkr_write_runout(job, 101, "claim-identity-unwritable");
        wkr_mail_result(opts, job, "claim-identity-unwritable", "",
                        "no-receipt", 101, 0, 0);
        return 1;
    }
    out = wkr_spawn(opts, job, exec);
    if (out.status == 0) {
        wkr_write_runout(job, 124, "executor-time-cap");
        wkr_mail_result(opts, job, "timeout", "", "no-receipt", 124, 0,
                        out.wall_ms);
        return 1;
    }
    if (out.status < 0) {
        wkr_write_runout(job, 127, "executor-launch-failed");
        wkr_mail_result(opts, job, "launch-failed", "", "no-receipt", 127,
                        0, out.wall_ms);
        return 1;
    }
    if (out.signaled || g_wkr_term) {
        wkr_write_runout(job, 130, "executor-signaled");
        wkr_mail_result(opts, job, "crashed", "", "no-receipt", 130, 0,
                        out.wall_ms);
        return 1;
    }
    have_res = wkr_parse_result(job->rundir, &res);
    if (!have_res) {
        wkr_write_runout(job, 100, "executor-no-result");
        wkr_mail_result(opts, job, "no-result", "", "no-receipt", 100, 0,
                        out.wall_ms);
        return 1;
    }
    res.wall_ms = out.wall_ms;
    rc = wkr_gate(job, &res, verdict, sizeof(verdict));
    wkr_write_runout(job, rc, res.evidence);
    wkr_write_receipt(opts, job, verdict, &res);
    wkr_mail_result(opts, job, res.terminal, res.candidate, verdict, rc,
                    res.tokens_used, res.wall_ms);
    return 1;
}

static long long wkr_run_job(const struct wkr_drive_opts *opts,
                             const struct wkr_job *job,
                             wkr_executor_fn exec, bool adopted,
                             int submitted)
{
    if (!opts || !job || !exec)
        return 0;
    if (adopted && submitted != 0) {
        /* A previous drive submitted (or the claim is unreadable): the
         * model may already have run, so never submit again. Record
         * the loss; reap marks it incomplete. */
        wkr_write_runout(job, 99, "worker-lost-after-submit");
        wkr_mail_result(opts, job, "worker-lost-after-submit", "",
                        "no-receipt", 99, 0, 0);
        return 1;
    }
    /* Fresh claims arrive submitted:false; adoptions with submitted==0
     * are proven un-submitted. The production stub refuses here so no
     * job runs without C's adapter wired. */
    if (exec == zcl_devagent_worker_no_executor)
        return 0;
    return wkr_run_fresh(opts, job, exec);
}

bool zcl_devagent_worker_no_executor(const struct wkr_job *job,
                                     struct wkr_result *res)
{
    (void)job;
    (void)res;
    return false;
}

static long long wkr_idle_sleep(long long wait_s)
{
    long long t0_s = platform_time_wall_unix();
    while (platform_time_wall_unix() - t0_s < wait_s) {
        struct timespec slice;
        if (g_wkr_term)
            break;
        slice.tv_sec = 0;
        slice.tv_nsec = 100u * 1000u * 1000u;
        (void)nanosleep(&slice, NULL);
    }
    return platform_time_wall_unix() - t0_s;
}

/* Bounded idle with doubling backoff. True when the idle streak hit
 * the limit and the drive should stop. */
static bool wkr_drive_idle(const struct wkr_drive_opts *opts,
                           long long *idle_streak, long long *wait_s)
{
    if (!opts || !idle_streak || !wait_s)
        return true;
    *idle_streak += wkr_idle_sleep(*wait_s);
    if (*idle_streak >= opts->idle_limit_s)
        return true;
    *wait_s *= 2;
    if (*wait_s > opts->idle_limit_s)
        *wait_s = opts->idle_limit_s;
    if (*wait_s < 1)
        *wait_s = 1;
    return false;
}

/* One drive step: at most one adoption or claim and its run. Returns
 * jobs processed (0 when the queue is empty). The loop reaps first. */
static long long wkr_drive_step(const struct wkr_drive_opts *opts,
                                wkr_executor_fn exec)
{
    struct wkr_job job;
    int submitted = 0;
    int got;
    if (!opts || !exec)
        return 0;
    got = wkr_adopt_job(opts, &job, &submitted);
    if (got < 0)
        got = 0;
    if (got == 1)
        return wkr_run_job(opts, &job, exec, true, submitted);
    if (wkr_claim_job(opts, &job) == 1)
        return wkr_run_job(opts, &job, exec, false, 0);
    return 0;
}

/* ── drive ─────────────────────────────────────────────────────────────── */

long long zcl_devagent_worker_drive(const struct wkr_drive_opts *opts,
                                    wkr_executor_fn exec)
{
    char queuedir[4096], lockpath[4096 + 32];
    void (*old_term)(int) = SIG_DFL;
    int lockfd = -1;
    long long t0_s;
    long long jobs = 0, idle_streak = 0, wait_s;
    if (!opts || !exec)
        return -1;
    if (!wkr_state_dir(queuedir, sizeof(queuedir), "queue"))
        return -1;
    if (snprintf(lockpath, sizeof(lockpath), "%s/%s", queuedir,
                 WKR_LOCK_FILE) >= (int)sizeof(lockpath))
        return -1;
    lockfd = open(lockpath, O_CREAT | O_RDWR, 0600);
    if (lockfd < 0)
        return -1;
#if !defined(_WIN32)
    if (flock(lockfd, LOCK_EX | LOCK_NB) != 0) {
        (void)close(lockfd);
        return -1;
    }
#else
    (void)close(lockfd);
    return -1;
#endif
    old_term = signal(SIGTERM, wkr_on_term);
    t0_s = platform_time_wall_unix();
    wait_s = opts->idle_start_s > 0 ? opts->idle_start_s : 1;
    while (!g_wkr_term) {
        long long done;
        if (platform_time_wall_unix() - t0_s >= opts->deadline_s)
            break;
        if (opts->max_jobs > 0 && jobs >= opts->max_jobs)
            break;
        wkr_reap();
        /* A refused seam processes nothing: idle instead of re-adopting
         * the same orphan in a tight loop. */
        done = wkr_drive_step(opts, exec);
        jobs += done;
        if (done > 0) {
            idle_streak = 0;
            wait_s = opts->idle_start_s > 0 ? opts->idle_start_s : 1;
            continue;
        }
        if (wkr_drive_idle(opts, &idle_streak, &wait_s))
            break;
    }
    (void)signal(SIGTERM, old_term);
#if !defined(_WIN32)
    (void)flock(lockfd, LOCK_UN);
#endif
    (void)close(lockfd);
    return jobs;
}

/* ── leaf ──────────────────────────────────────────────────────────────── */

static long long wkr_leaf_int(const struct zcl_command_request *req,
                              const char *key, long long dflt, long long lo,
                              long long hi)
{
    const struct json_value *v;
    long long n;
    if (!req || !req->input || !key)
        return dflt;
    v = json_get(req->input, key);
    if (!v || v->type != JSON_INT)
        return dflt;
    n = (long long)json_get_int(v);
    if (n < lo)
        return lo;
    if (n > hi)
        return hi;
    return n;
}

static const char *wkr_leaf_str(const struct zcl_command_request *req,
                                const char *key)
{
    const struct json_value *v;
    if (!req || !req->input || !key)
        return "";
    v = json_get(req->input, key);
    return (v && v->type == JSON_STR) ? json_get_str(v) : "";
}

void zcl_native_handle_dev_agent_worker(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    struct wkr_drive_opts opts;
    const char *action, *worker, *session, *model;
    char sess_default[56];
    long long jobs;
    if (!reply)
        return;
#if defined(_WIN32)
    wkr_fail(reply, "WORKER_WINDOWS_UNAVAILABLE", "run",
             "dev.agent.worker needs POSIX fork and rlimits",
             "run the worker on a POSIX host");
    return;
#else
    if (!request || !request->input) {
        wkr_fail(reply, "BAD_INPUT", "run",
                 "dev.agent.worker run needs a worker identity",
                 "request.input was missing");
        return;
    }
    action = wkr_leaf_str(request, "action");
    if (strcmp(action, "run") != 0) {
        wkr_fail(reply, "BAD_INPUT", "run",
                 "action is exactly run",
                 "input.action missing or unknown");
        return;
    }
    worker = wkr_leaf_str(request, "worker");
    if (!worker[0] || strlen(worker) > 48) {
        wkr_fail(reply, "BAD_INPUT", "run",
                 "worker names the resident worker, 1-48 characters",
                 "input.worker missing or too long");
        return;
    }
    memset(&opts, 0, sizeof(opts));
    session = wkr_leaf_str(request, "session");
    if (!session[0]) {
        (void)snprintf(sess_default, sizeof(sess_default), "s%lld-%ld",
                       (long long)platform_time_wall_unix(),
                       (long)getpid());
        session = sess_default;
    }
    if (strlen(session) > (sizeof(opts.session) - 1)) {
        wkr_fail(reply, "BAD_INPUT", "run",
                 "session names this worker run, at most 55 characters",
                 "input.session too long");
        return;
    }
    model = wkr_leaf_str(request, "model");
    (void)snprintf(opts.worker, sizeof(opts.worker), "%s", worker);
    (void)snprintf(opts.session, sizeof(opts.session), "%s", session);
    (void)snprintf(opts.model, sizeof(opts.model), "%s", model);
    opts.deadline_s = wkr_leaf_int(request, "deadline_s", 300, 1, 3600);
    opts.idle_start_s = wkr_leaf_int(request, "idle_start_s", 1, 1, 30);
    opts.idle_limit_s = wkr_leaf_int(request, "idle_limit_s", 60, 1, 600);
    opts.max_jobs = wkr_leaf_int(request, "max_jobs", 0, 0, 1000);
    opts.time_cap_s = wkr_leaf_int(request, "time_cap_s", 600, 1, 3600);
    opts.cpu_s = wkr_leaf_int(request, "cpu_s", 600, 1, 3600);
    opts.mem_mb = wkr_leaf_int(request, "mem_mb", 1024, 64, 8192);
    opts.token_cap = wkr_leaf_int(request, "token_cap", 32000, 1, 1000000);
    jobs = zcl_devagent_worker_drive(&opts,
                                     zcl_devagent_worker_muse_executor);
    if (jobs < 0) {
        wkr_fail(reply, "WORKER_BUSY", "run",
                 "another worker holds this queue, or the state root refuses",
                 "worker.lock exclusive");
        return;
    }
    (void)json_push_kv_str(&reply->data, "leaf", WKR_LEAF);
    (void)json_push_kv_str(&reply->data, "state", "done");
    (void)json_push_kv_int(&reply->data, "jobs", jobs);
    (void)json_push_kv_str(&reply->data, "worker", opts.worker);
    (void)json_push_kv_str(&reply->data, "session", opts.session);
    reply->status = ZCL_COMMAND_STATUS_PASSED;
    reply->exit_code = 0;
#endif
}
