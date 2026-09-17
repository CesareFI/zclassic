/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: C's production executor for A's resident worker loop. This
 * is the ONLY Muse entry the worker drives: it adapts one claimed
 * wkr_job to one bounded muse_run_task and maps the structured result
 * back to wkr_result. It owns no queue, no ledger, no scheduler, and
 * no lifecycle state: claim/attempt/retry, the gate predicate, reap,
 * and result mail all stay in native_devagent_worker.c, which calls
 * this function through the wkr_executor_fn seam (never the reverse).
 *
 * TASK CARRIER. The worker hands executor-ready text: identity lines
 * plus the brief head. Muse direction rides a machine header at the
 * TOP of the brief file (inside the worker's 32 KiB head cap):
 *
 *   muse-workspace: /abs/path/to/worktree
 *   muse-scope: src/
 *   muse-gate: group_name
 *   muse-model: model-id-or-empty
 *
 *   <free prose prompt for the model...>
 *
 * Missing or malformed direction refuses WITHOUT spawning any host:
 * the result carries terminal "refused" through the normal channel.
 *
 * BOUNDS. job->token_cap (<=0 refuses: no unbounded runs) becomes the
 * MSP at-most-N cap. The wall cap splits 80/15: the turn gets
 * (cap-10)s with a 5s floor so a timeout verdict pre-empts the
 * worker's SIGKILL; the gate gets the rest. Caps under 30s refuse:
 * a model turn cannot honestly fit.
 *
 * SILENCE. The child wrapper captures the outcome through
 * executor_result.json, never this process's stdout: stdout is
 * pointed at /dev/null across the call so executor chatter can never
 * pollute the worker's streams. run.out comes from the worker.
 */
#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif

#include "command/native_devagent.h"
#include "services/muse_run.h"

#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define MX_EVIDENCE_MAX 2047

/* One "muse-key: value" header line at a line start; value trimmed of
 * trailing blanks. False when the key is absent. */
static bool mx_header_line(const char *task, const char *key, char *out,
    size_t cap)
{
    size_t kl = strlen(key);
    const char *p = task;
    if (!task || !key || !out || cap == 0) return false;
    for (;;) {
        const char *eol = strchr(p, '\n');
        size_t len = eol ? (size_t)(eol - p) : strlen(p);
        /* The header block ends at the first blank line; the prose
         * prompt below is never parsed for direction. */
        if (len == 0 || (len == 1 && (p[0] == '\r'))) return false;
        if (len > kl + 2 && strncmp(p, key, kl) == 0 && p[kl] == ':' &&
            (p[kl + 1] == ' ' || p[kl + 1] == '\t')) {
            const char *v = p + kl + 2;
            size_t vn = len - (kl + 2);
            while (vn > 0 &&
                (v[vn - 1] == ' ' || v[vn - 1] == '\t' ||
                    v[vn - 1] == '\r'))
                vn--;
            if (vn == 0 || vn >= cap) return false;
            memcpy(out, v, vn);
            out[vn] = '\0';
            return true;
        }
        if (!eol) return false;
        p = eol + 1;
    }
}

/* The prompt is everything after the header block's blank line. */
static const char *mx_prompt(const char *task)
{
    const char *p;
    if (!task) return NULL;
    p = task;
    for (;;) {
        const char *eol = strchr(p, '\n');
        size_t len = eol ? (size_t)(eol - p) : strlen(p);
        if (len == 0) {
            const char *body = eol ? eol + 1 : p + strlen(p);
            while (*body == '\n' || *body == '\r') body++;
            return *body ? body : NULL;
        }
        if (len >= 9 && strncmp(p, "=== BRIEF", 9) == 0) return NULL;
        if (!eol) return NULL;
        p = eol + 1;
    }
}

/* Best-effort claim identity for provenance: worker/session out of
 * <rundir>/claim.json. Never blocks a run when unreadable. */
static void mx_claim_who(const char *rundir, char *worker, size_t wcap,
    char *session, size_t scap)
{
    char path[8192];
    FILE *f;
    char *text;
    long n;
    const char *p;
    if (worker && wcap > 0) worker[0] = '\0';
    if (session && scap > 0) session[0] = '\0';
    if (!rundir ||
        snprintf(path, sizeof(path), "%s/claim.json", rundir) >=
        (int)sizeof(path))
        return;
    f = fopen(path, "rb");
    if (!f) return;
    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return;
    }
    n = ftell(f);
    if (n <= 0 || n > 4096) {
        fclose(f);
        return;
    }
    (void)fseek(f, 0, SEEK_SET);
    text = malloc((size_t)n + 1);
    if (!text) {
        fclose(f);
        return;
    }
    if (fread(text, 1, (size_t)n, f) != (size_t)n) {
        free(text);
        fclose(f);
        return;
    }
    text[n] = '\0';
    fclose(f);
    p = strstr(text, "\"worker\":\"");
    if (p && worker && wcap > 0) {
        const char *v = p + strlen("\"worker\":\"");
        const char *q = strchr(v, '"');
        if (q && (size_t)(q - v) < wcap) {
            memcpy(worker, v, (size_t)(q - v));
            worker[q - v] = '\0';
        }
    }
    p = strstr(text, "\"session\":\"");
    if (p && session && scap > 0) {
        const char *v = p + strlen("\"session\":\"");
        const char *q = strchr(v, '"');
        if (q && (size_t)(q - v) < scap) {
            memcpy(session, v, (size_t)(q - v));
            session[q - v] = '\0';
        }
    }
    free(text);
}

static bool mx_dir_ok(const char *path)
{
    struct stat st;
    return path && path[0] && stat(path, &st) == 0 && S_ISDIR(st.st_mode);
}

/* Fill a refused outcome through the normal channel (the worker still
 * writes run.out + receipt + mail for it). Always true: the executor
 * ran and the refusal is the result. */
static bool mx_refuse(struct wkr_result *res, const char *reason)
{
    if (!res) return false;
    memset(res, 0, sizeof(*res));
    (void)snprintf(res->terminal, sizeof(res->terminal), "refused");
    res->rc = 1;
    if (reason)
        (void)snprintf(res->evidence, sizeof(res->evidence), "%s",
            reason);
    return true;
}

bool zcl_devagent_worker_muse_executor(const struct wkr_job *job,
    struct wkr_result *res)
{
    char workspace[4096], scope[512], gate[128], model[160];
    const char *prompt;
    char cworker[64], csession[64];
    struct muse_run_task t;
    struct muse_run_result mres;
    char err[MUSE_RUN_ERROR_MAX];
    char evidence[MX_EVIDENCE_MAX + 1];
    int devnull, saved_out, rc, w;
    if (!job || !res) return false;
    memset(res, 0, sizeof(*res));
    if (!mx_dir_ok(job->rundir))
        return mx_refuse(res, "refused: rundir is not a directory");
    if (!mx_header_line(job->task, "muse-workspace", workspace,
            sizeof(workspace)))
        return mx_refuse(res,
            "refused: brief carries no muse-workspace line");
    if (workspace[0] != '/' || !mx_dir_ok(workspace))
        return mx_refuse(res,
            "refused: muse-workspace is not an absolute directory");
    if (!mx_header_line(job->task, "muse-scope", scope, sizeof(scope)))
        return mx_refuse(res, "refused: brief carries no muse-scope line");
    if (!mx_header_line(job->task, "muse-gate", gate, sizeof(gate)))
        return mx_refuse(res, "refused: brief carries no muse-gate line");
    prompt = mx_prompt(job->task);
    if (!prompt)
        return mx_refuse(res, "refused: brief carries no prompt body");
    if (job->token_cap <= 0)
        return mx_refuse(res, "refused: token cap is not positive");
    if (job->time_cap_s < 30)
        return mx_refuse(res, "refused: time cap too small to attempt");
    if (!mx_header_line(job->task, "muse-model", model, sizeof(model))) {
        if (snprintf(model, sizeof(model), "%s", job->model) >=
            (int)sizeof(model))
            return mx_refuse(res, "refused: model does not fit");
    }
    mx_claim_who(job->rundir, cworker, sizeof(cworker), csession,
        sizeof(csession));
    memset(&t, 0, sizeof(t));
    t.ref.seq = job->seq;
    if (snprintf(t.ref.name, sizeof(t.ref.name), "%s", job->name) >=
        (int)sizeof(t.ref.name))
        return mx_refuse(res, "refused: ref name does not fit");
    t.ref.attempt = job->attempt;
    if (snprintf(t.worker, sizeof(t.worker), "%s", cworker) >=
        (int)sizeof(t.worker))
        return mx_refuse(res, "refused: worker identity does not fit");
    if (snprintf(t.workspace, sizeof(t.workspace), "%s", workspace) >=
        (int)sizeof(t.workspace))
        return mx_refuse(res, "refused: workspace does not fit");
    if (snprintf(t.scope, sizeof(t.scope), "%s", scope) >=
        (int)sizeof(t.scope))
        return mx_refuse(res, "refused: scope does not fit");
    if (snprintf(t.gate, sizeof(t.gate), "%s", gate) >=
        (int)sizeof(t.gate))
        return mx_refuse(res, "refused: gate does not fit");
    if (snprintf(t.model, sizeof(t.model), "%s", model) >=
        (int)sizeof(t.model))
        return mx_refuse(res, "refused: model does not fit");
    t.prompt = prompt;
    if (snprintf(t.rundir, sizeof(t.rundir), "%s", job->rundir) >=
        (int)sizeof(t.rundir))
        return mx_refuse(res, "refused: rundir does not fit");
    /* 80/15 split of the wall cap: the turn verdict pre-empts the
     * worker's SIGKILL so a timeout reports instead of vanishing. */
    t.budgets.turn_timeout_ms = (int64_t)(job->time_cap_s - 10) * 1000;
    if (t.budgets.turn_timeout_ms < 5000)
        t.budgets.turn_timeout_ms = 5000;
    t.budgets.gate_timeout_ms = (int)(job->time_cap_s * 150);
    if (t.budgets.gate_timeout_ms < 2000)
        t.budgets.gate_timeout_ms = 2000;
    t.budgets.max_total_tokens = (uint64_t)job->token_cap;
    t.caller_holds_claim = true;
    /* The child wrapper owns the outcome file: executor chatter must
     * never reach the worker's streams. */
    devnull = open("/dev/null", O_WRONLY);
    saved_out = -1;
    if (devnull >= 0) {
        saved_out = dup(STDOUT_FILENO);
        (void)dup2(devnull, STDOUT_FILENO);
        close(devnull);
    }
    memset(&mres, 0, sizeof(mres));
    err[0] = '\0';
    rc = muse_run_task(&t, &mres, err);
    if (saved_out >= 0) {
        (void)dup2(saved_out, STDOUT_FILENO);
        close(saved_out);
    }
    if (csession[0])
        (void)snprintf(mres.worker_session, sizeof(mres.worker_session),
            "%s", csession);
    (void)snprintf(res->terminal, sizeof(res->terminal), "%s",
        mres.verdict[0] ? mres.verdict : "refused");
    res->rc = rc == 0 ? 0 : 1;
    if (mres.candidate_file[0])
        (void)snprintf(res->candidate, sizeof(res->candidate), "%s",
            mres.candidate_file);
    res->tokens_used = (long long)mres.total_tokens;
    res->wall_ms = mres.wall_ms;
    w = snprintf(evidence, sizeof(evidence),
        "ref=%lld/%s/%lld\nworker=%s\nverdict=%s\nterminal=%s\n"
        "tokens=%llu\nfiles=%lld\nbase=%.12s\ncandidate=%s\ngate=%s\n"
        "gate_evidence=%s\nmodel=%s\nsession=%s\nturn=%s\nwall_ms=%lld\n"
        "reason=%s\n",
        mres.ref.seq, mres.ref.name, mres.ref.attempt,
        mres.worker[0] ? mres.worker : "-",
        mres.verdict[0] ? mres.verdict : "refused",
        mres.terminal[0] ? mres.terminal : "none",
        (unsigned long long)mres.total_tokens, mres.files_changed,
        mres.base[0] ? mres.base : "none",
        mres.candidate_file[0] ? mres.candidate_file : "none",
        mres.gate[0] ? mres.gate : "-",
        mres.gate_evidence[0] ? mres.gate_evidence : "-",
        mres.model_resolved[0] ? mres.model_resolved : "-",
        mres.session[0] ? mres.session : "-",
        mres.turn[0] ? mres.turn : "-",
        mres.wall_ms,
        mres.reason[0] ? mres.reason : (err[0] ? err : "-"));
    if (w > 0)
        (void)snprintf(res->evidence, sizeof(res->evidence), "%s",
            evidence);
    return true;
}
