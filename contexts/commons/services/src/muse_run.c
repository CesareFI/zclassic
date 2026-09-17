/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: queue row -> Muse turn -> registered gate -> receipt. See header. */
#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif

#include "services/muse_run.h"
#include "services/muse_session.h"
#include "engine/engine_verdict.h"
#include "json/json.h"
#include "util/spawn.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define MR_TURN_DEFAULT_MS 1500000
#define MR_GATE_DEFAULT_MS 900000
#define MR_TOKEN_DEFAULT 200000u
#define MR_TEXT_DEFAULT (64u * 1024u)
#define MR_GATE_LOG_MAX (256u * 1024u)
#define MR_LINE_MAX (1024u * 1024u)
#define MR_GIT_TIMEOUT_MS 60000

static const char *mr_verdict_pass = "pass";
static const char *mr_verdict_failed = "failed";
static const char *mr_verdict_timeout = "timeout";
static const char *mr_verdict_cancelled = "cancelled";
static const char *mr_verdict_refused = "refused";

static bool mr_is_terminal_verdict(const char *v)
{
    return v && (strcmp(v, mr_verdict_pass) == 0 ||
        strcmp(v, mr_verdict_failed) == 0 ||
        strcmp(v, mr_verdict_timeout) == 0 ||
        strcmp(v, mr_verdict_cancelled) == 0 ||
        strcmp(v, mr_verdict_refused) == 0);
}

/* --- small utils --------------------------------------------------------- */

static int64_t mr_monotonic_ms(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return 0;
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static char *mr_read_file(const char *path, size_t cap)
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
    if (n < 0 || (size_t)n > cap) {
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

/* Atomic write: temp file in the same directory plus rename, so a
 * kill can never leave a partial evidence file for a gate to read. */
static bool mr_write_atomic(const char *path, const char *text)
{
    char tmp[8192];
    FILE *f;
    size_t n;
    if (!path || !text) return false;
    if (snprintf(tmp, sizeof(tmp), "%s.tmp-%d", path,
            (int)getpid()) >= (int)sizeof(tmp))
        return false;
    f = fopen(tmp, "wb");
    if (!f) return false;
    n = strlen(text);
    if (n > 0 && fwrite(text, 1, n, f) != n) {
        fclose(f);
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

static bool mr_append_line(const char *path, const char *line)
{
    FILE *f = fopen(path, "ab");
    bool ok;
    if (!f) return false;
    ok = fprintf(f, "%s\n", line) > 0;
    if (fclose(f) != 0) ok = false;
    return ok;
}

/* JSON string escaper for evidence fields (host- and model-minted text). */
static void mr_esc(const char *s, char *out, size_t cap)
{
    size_t n = 0;
    if (!s) s = "";
    while (*s && n + 6 < cap) {
        unsigned char c = (unsigned char)*s++;
        if (c == '"' || c == '\\') {
            out[n++] = '\\';
            out[n++] = (char)c;
        } else if (c < 0x20) {
            int w = snprintf(out + n, cap - n, "\\u%04x", c);
            if (w <= 0 || (size_t)w >= cap - n) break;
            n += (size_t)w;
        } else {
            out[n++] = (char)c;
        }
    }
    out[n] = '\0';
}

static bool mr_copy(char *out, size_t cap, const char *v, size_t vn)
{
    if (!out || cap == 0) return false;
    if (vn >= cap) return false;
    memcpy(out, v, vn);
    out[vn] = '\0';
    return true;
}

static bool mr_dir_ok(const char *path)
{
    struct stat st;
    return path && path[0] && stat(path, &st) == 0 && S_ISDIR(st.st_mode);
}

/* Identity token: one path segment, never "." or "..". */
static bool mr_token_ok(const char *s)
{
    size_t n;
    if (!s || s[0] == '\0') return false;
    n = strlen(s);
    if (n >= MUSE_RUN_NAME_MAX) return false;
    if (strcmp(s, ".") == 0 || strcmp(s, "..") == 0) return false;
    for (size_t i = 0; i < n; i++) {
        char c = s[i];
        bool ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
            (c >= '0' && c <= '9') || c == '_' || c == '.' || c == '-';
        if (!ok) return false;
    }
    return true;
}

/* --- validation ------------------------------------------------------------ */

static int mr_validate(const struct muse_run_task *t,
    char err[MUSE_RUN_ERROR_MAX])
{
    size_t prompt_len;
    if (!t) {
        if (err)
            (void)snprintf(err, MUSE_RUN_ERROR_MAX, "task is missing");
        return -1;
    }
    if (t->ref.seq < 0 || t->ref.attempt < 1 ||
        !mr_token_ok(t->ref.name)) {
        if (err)
            (void)snprintf(err, MUSE_RUN_ERROR_MAX, "ref is unusable");
        return -1;
    }
    if (t->worker[0] && !mr_token_ok(t->worker)) {
        if (err)
            (void)snprintf(err, MUSE_RUN_ERROR_MAX,
                "worker identity is unusable");
        return -1;
    }
    if (!mr_dir_ok(t->workspace)) {
        if (err)
            (void)snprintf(err, MUSE_RUN_ERROR_MAX,
                "workspace is not a directory");
        return -1;
    }
    if (!t->scope[0] || t->scope[0] == '/' ||
        strstr(t->scope, "..") != NULL ||
        strlen(t->scope) >= sizeof(t->scope)) {
        if (err)
            (void)snprintf(err, MUSE_RUN_ERROR_MAX,
                "scope escapes the workspace");
        return -1;
    }
    if (!t->gate[0]) {
        if (err)
            (void)snprintf(err, MUSE_RUN_ERROR_MAX,
                "no gate names the judge");
        return -1;
    }
    if (!t->prompt || !t->prompt[0]) {
        if (err)
            (void)snprintf(err, MUSE_RUN_ERROR_MAX, "prompt is empty");
        return -1;
    }
    prompt_len = strlen(t->prompt);
    if (prompt_len > MUSE_RUN_PROMPT_MAX) {
        if (err)
            (void)snprintf(err, MUSE_RUN_ERROR_MAX,
                "prompt exceeds its bound");
        return -1;
    }
    if (!mr_dir_ok(t->rundir)) {
        if (err)
            (void)snprintf(err, MUSE_RUN_ERROR_MAX,
                "rundir is not a directory");
        return -1;
    }
    return 0;
}

/* --- restart pre-check ----------------------------------------------------- */

/* True when the rundir already owns a receipt with a terminal verdict;
 * the run happened, whatever A's queue says. The queue's own locks and
 * outcome rows are A's state machine and are never read here. */
static bool mr_receipt_verdict(const char *rundir, char *out, size_t cap)
{
    char path[8192];
    char *text;
    const char *p;
    if (snprintf(path, sizeof(path), "%s/receipt.json", rundir) >=
        (int)sizeof(path))
        return false;
    text = mr_read_file(path, 65536);
    if (!text) return false;
    p = strstr(text, "\"verdict\":\"");
    if (p) {
        const char *v = p + strlen("\"verdict\":\"");
        const char *q = strchr(v, '"');
        bool ok = false;
        if (q && (size_t)(q - v) < cap) {
            char verb[32];
            size_t n = (size_t)(q - v);
            if (n < sizeof(verb)) {
                memcpy(verb, v, n);
                verb[n] = '\0';
                if (mr_is_terminal_verdict(verb)) {
                    (void)snprintf(out, cap, "%s", verb);
                    ok = true;
                }
            }
        }
        free(text);
        return ok;
    }
    free(text);
    return false;
}

/* 1 = already recorded (do NOT start a turn), 0 = clear. Any verdict
 * receipt counts: either reap saw it or reap is about to. */
static int mr_already_recorded(const struct muse_run_task *t,
    struct muse_run_result *out)
{
    char verb[MUSE_RUN_VERDICT_MAX];
    if (!mr_receipt_verdict(t->rundir, verb, sizeof(verb))) return 0;
    if (out) {
        (void)snprintf(out->verdict, sizeof(out->verdict), "%s", verb);
        out->rc = 0;
    }
    return 1;
}

static void mr_report_short(const struct muse_run_task *t,
    const struct muse_run_result *out)
{
    printf("ref=%lld/%s/%lld already recorded; no turn started\n",
        t->ref.seq, t->ref.name, t->ref.attempt);
    printf("rc=0\n");
    (void)out;
}

/* --- measured helpers ------------------------------------------------------ */

static long long mr_files_changed(const char *workspace)
{
    const char *argv[] = { "git", "-C", workspace, "status", "--porcelain",
                           NULL };
    char *buf = malloc(MR_GATE_LOG_MAX);
    long long count = 0;
    int rc;
    if (!buf) return -1;
    buf[0] = '\0';
    rc = zcl_spawn_capture(argv, buf, MR_GATE_LOG_MAX, MR_GIT_TIMEOUT_MS);
    if (rc != 0) {
        free(buf);
        return -1;
    }
    for (const char *p = buf; *p; p++) {
        if (*p == '\n') count++;
    }
    free(buf);
    return count;
}

/* One captured git line, trailing newline trimmed. False on any failure;
 * identity is evidence, never judgement, so failure degrades to "none". */
static bool mr_git_line(char *out, size_t cap, const char *workspace,
    const char *a1, const char *a2, const char *a3)
{
    const char *argv[] = { "git", "-C", workspace, a1, a2, a3, NULL };
    char *buf = malloc(65536);
    int rc;
    size_t n;
    if (!buf || !out || cap == 0) {
        free(buf);
        return false;
    }
    buf[0] = '\0';
    rc = zcl_spawn_capture(argv, buf, 65536, MR_GIT_TIMEOUT_MS);
    if (rc != 0) {
        free(buf);
        return false;
    }
    n = strlen(buf);
    while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == '\r')) buf[--n] =
        '\0';
    if (n == 0 || n >= cap) {
        free(buf);
        return false;
    }
    memcpy(out, buf, n + 1);
    free(buf);
    return true;
}

static bool mr_hex40(const char *s)
{
    int i;
    if (!s) return false;
    for (i = 0; i < 40; i++) {
        char c = s[i];
        bool hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
        if (!hex) return false;
    }
    return s[40] == '\0';
}

/* HEAD before the turn: the source half of the diff identity. */
static void mr_base_commit(const char *workspace, char *out, size_t cap)
{
    if (!mr_git_line(out, cap, workspace, "rev-parse", "HEAD", NULL))
        (void)snprintf(out, cap, "none");
}

/* Dequote one C-quoted porcelain path in place ("a b" -> a b, with
 * backslash escapes resolved best-effort). Returns the dequoted path. */
static char *mr_dequote(char *path)
{
    char *w;
    size_t n = strlen(path);
    if (n < 2 || path[0] != '"' || path[n - 1] != '"') return path;
    path[n - 1] = '\0';
    w = path;
    for (char *p = path + 1; *p; p++) {
        if (*p == '\\' && p[1]) {
            p++;
            if (*p >= '0' && *p <= '7') {
                int v = 0, k = 0;
                while (k < 3 && *p >= '0' && *p <= '7') {
                    v = v * 8 + (*p - '0');
                    p++;
                    k++;
                }
                p--;
                *w++ = (char)v;
            } else {
                switch (*p) {
                case 'n': *w++ = '\n'; break;
                case 't': *w++ = '\t'; break;
                default: *w++ = *p; break;
                }
            }
        } else {
            *w++ = *p;
        }
    }
    *w = '\0';
    return path;
}

/* Append "path hash" lines for every untracked path: the content half
 * of the change set that `git diff` never shows. */
static void mr_fold_others(const char *workspace, char *acc, size_t acc_cap,
    size_t *used)
{
    const char *argv[] = { "git", "-C", workspace, "ls-files", "--others",
                           "--exclude-standard", NULL };
    char *list = malloc(65536);
    int rc;
    if (!list) return;
    list[0] = '\0';
    rc = zcl_spawn_capture(argv, list, 65536, MR_GIT_TIMEOUT_MS);
    if (rc != 0) {
        free(list);
        return;
    }
    for (char *line = strtok(list, "\n"); line;
        line = strtok(NULL, "\n")) {
        char h[128];
        char *path = mr_dequote(line);
        int w = snprintf(acc + *used, acc_cap - *used, "?? %s ",
            path);
        if (w <= 0 || (size_t)w >= acc_cap - *used) break;
        *used += (size_t)w;
        if (mr_git_line(h, sizeof(h), workspace, "hash-object", "--",
                path)) {
            w = snprintf(acc + *used, acc_cap - *used, "%s\n", h);
        } else {
            w = snprintf(acc + *used, acc_cap - *used, "missing\n");
        }
        if (w <= 0 || (size_t)w >= acc_cap - *used) break;
        *used += (size_t)w;
    }
    free(list);
}

/* SHA-1 over the post-run change set: the tracked diff plus one
 * content hash per untracked path, hashed once more so the token is
 * fixed-width. Empty diffs hash deterministically; "none" only when
 * git itself fails. The fold passes through a rundir tempfile because
 * the capture helper is text-oriented. On success the fold is also
 * published as <rundir>/candidate-<hex>.diff (atomic): the named
 * artifact a gate checks for existence. file_out takes that filename
 * ("" when nothing is named). */
static void mr_candidate(const char *workspace, const char *rundir,
    char *out, size_t cap, char *file_out, size_t file_cap)
{
    const char *diff_argv[] = { "git", "-C", workspace, "diff", "HEAD",
                                "--", NULL };
    char *acc = malloc(MR_GATE_LOG_MAX);
    char tmp[8192], h[128];
    size_t used = 0;
    int rc;
    FILE *f;
    (void)snprintf(out, cap, "none");
    if (!acc) return;
    acc[0] = '\0';
    rc = zcl_spawn_capture(diff_argv, acc, MR_GATE_LOG_MAX,
        MR_GIT_TIMEOUT_MS);
    if (rc != 0) {
        free(acc);
        return;
    }
    used = strlen(acc);
    if (used + 2 < MR_GATE_LOG_MAX) {
        acc[used++] = '\n';
        acc[used] = '\0';
    }
    mr_fold_others(workspace, acc, MR_GATE_LOG_MAX, &used);
    if (used < MR_GATE_LOG_MAX) acc[used] = '\0';
    if (file_out && file_cap > 0) file_out[0] = '\0';
    if (snprintf(tmp, sizeof(tmp), "%s/.candidate.in", rundir) >=
        (int)sizeof(tmp)) {
        free(acc);
        return;
    }
    f = fopen(tmp, "wb");
    if (!f) {
        free(acc);
        return;
    }
    if (used > 0 && fwrite(acc, 1, used, f) != used) {
        fclose(f);
        (void)unlink(tmp);
        free(acc);
        return;
    }
    fclose(f);
    {
        const char *h_argv[] = { "git", "hash-object", tmp, NULL };
        char *hbuf = malloc(128);
        if (!hbuf) {
            (void)unlink(tmp);
            free(acc);
            return;
        }
        hbuf[0] = '\0';
        rc = zcl_spawn_capture(h_argv, hbuf, 128, MR_GIT_TIMEOUT_MS);
        (void)unlink(tmp);
        if (rc != 0) {
            free(hbuf);
            free(acc);
            return;
        }
        hbuf[strcspn(hbuf, "\r\n")] = '\0';
        if (mr_hex40(hbuf) && strlen(hbuf) < cap) {
            (void)snprintf(h, sizeof(h), "%s", hbuf);
            (void)snprintf(out, cap, "%s", h);
            /* Publish the fold as the named artifact. */
            if (file_out && file_cap > 0) {
                char art[8192], fname[192];
                if (snprintf(fname, sizeof(fname), "candidate-%s.diff",
                        h) < (int)sizeof(fname) &&
                    snprintf(art, sizeof(art), "%s/%s", rundir,
                        fname) < (int)sizeof(art) &&
                    strlen(fname) < file_cap &&
                    mr_write_atomic(art, acc)) {
                    (void)snprintf(file_out, file_cap, "%s", fname);
                }
            }
        }
        free(hbuf);
    }
    free(acc);
}

/* Runs the named registered group through the workspace's own runner,
 * parses the machine verdict line, and reports through engine_gate_read.
 * Missing or unrunnable runner is a refusal input, never a pass. */
static bool mr_run_gate(const char *workspace, const char *group,
    int timeout_ms, char *log, size_t logcap, long long *elapsed_ms,
    struct engine_gate_reading *reading)
{
    char runner[8192];
    const char *argv[8];
    char selector[128];
    int64_t t0;
    int rc;
    if (!workspace || !group || !log || !logcap || !elapsed_ms || !reading)
        return false;
    memset(reading, 0, sizeof(*reading));
    if (snprintf(runner, sizeof(runner), "%s/build/bin/test_parallel",
            workspace) >= (int)sizeof(runner))
        return false;
    if (access(runner, X_OK) != 0) return false;
    if (snprintf(selector, sizeof(selector), "--exact=%s", group) >=
        (int)sizeof(selector))
        return false;
    argv[0] = runner;
    argv[1] = selector;
    argv[2] = "--no-cache";
    argv[3] = NULL;
    log[0] = '\0';
    t0 = mr_monotonic_ms();
    rc = zcl_spawn_capture(argv, log, logcap, timeout_ms);
    *elapsed_ms = (long long)(mr_monotonic_ms() - t0);
    (void)rc;
    return engine_gate_read(log, strlen(log), reading);
}

/* Last SUITE VERDICT line, verbatim: same keep-last rule as the reader. */
static void mr_last_verdict_line(const char *log, char *out, size_t cap)
{
    const char *cur;
    out[0] = '\0';
    if (!log || cap == 0) return;
    cur = log;
    for (;;) {
        const char *nl = strchr(cur, '\n');
        size_t n = nl ? (size_t)(nl - cur) : strlen(cur);
        if (n >= 13 && n < cap && memcmp(cur, "SUITE VERDICT", 13) == 0) {
            memcpy(out, cur, n);
            out[n] = '\0';
        }
        if (!nl) break;
        cur = nl + 1;
    }
}

/* FAIL(HOLLOW) and FAIL(NO-CHANGE) report the inner name; the verdict
 * stays a lowercase verb and the engine detail rides the evidence. */
static const char *mr_engine_short(const char *name, char *buf, size_t cap)
{
    size_t n;
    if (!name) name = "UNKNOWN";
    n = strlen(name);
    if (n > 6 && strncmp(name, "FAIL(", 5) == 0 && name[n - 1] == ')') {
        size_t inner = n - 6;
        if (inner < cap) {
            memcpy(buf, name + 5, inner);
            buf[inner] = '\0';
            return buf;
        }
    }
    return name;
}

/* --- writers --------------------------------------------------------------- */

static void mr_write_receipt(const struct muse_run_task *t,
    const struct muse_run_result *r)
{
    char path[8192], body[4096], esc_reason[1024], esc_engine[128];
    mr_esc(r->reason, esc_reason, sizeof(esc_reason));
    mr_esc(r->engine, esc_engine, sizeof(esc_engine));
    if (snprintf(path, sizeof(path), "%s/receipt.json",
            t->rundir) >= (int)sizeof(path))
        return;
    (void)snprintf(body, sizeof(body),
        "{\"verdict\":\"%s\",\"seq\":%lld,\"name\":\"%s\",\"attempt\":%lld,"
        "\"group\":\"%s\",\"turn\":\"%s\",\"reason\":\"%s\","
        "\"engine\":\"%s\",\"tokens\":%llu,\"files_changed\":%lld}",
        r->verdict, t->ref.seq, t->ref.name, t->ref.attempt, t->gate,
        r->terminal, esc_reason, esc_engine,
        r->total_tokens, r->files_changed);
    (void)mr_write_atomic(path, body);
}

static void mr_write_facts(const struct muse_run_task *t,
    const struct muse_run_result *r)
{
    char path[8192];
    char *body = malloc(65536);
    char esc_reason[1024], esc_engine[128], esc_verdict[2048];
    char esc_model[512], esc_gate[512];
    if (!body) return;
    mr_esc(r->reason, esc_reason, sizeof(esc_reason));
    mr_esc(r->engine, esc_engine, sizeof(esc_engine));
    mr_esc(r->gate_verdict, esc_verdict, sizeof(esc_verdict));
    mr_esc(r->model_resolved, esc_model, sizeof(esc_model));
    mr_esc(t->gate, esc_gate, sizeof(esc_gate));
    if (snprintf(path, sizeof(path), "%s/muse.json",
            t->rundir) >= (int)sizeof(path)) {
        free(body);
        return;
    }
    (void)snprintf(body, 65536,
        "{\"ref\":{\"seq\":%lld,\"name\":\"%s\",\"attempt\":%lld},"
        "\"worker\":\"%s\",\"group\":\"%s\",\"scope\":\"%s\","
        "\"model_requested\":\"%s\",\"model_resolved\":\"%s\","
        "\"provider\":\"%s\",\"session\":\"%s\",\"turn\":\"%s\","
        "\"commands\":{\"start\":\"%s\",\"turn\":\"%s\"},"
        "\"terminal\":\"%s\",\"verdict\":\"%s\",\"rc\":%d,"
        "\"reason\":\"%s\",\"engine\":\"%s\","
        "\"base\":\"%s\",\"candidate\":\"%s\","
        "\"gate\":{\"name\":\"%s\",\"evidence\":\"%s\","
        "\"verdict\":\"%s\",\"present\":%s,\"ran\":%lld,\"failed\":%lld,"
        "\"ms\":%lld},"
        "\"tokens\":{\"input\":%llu,\"output\":%llu,\"total\":%llu},"
        "\"duration_ms\":%lld,\"wall_ms\":%lld,\"files_changed\":%lld,"
        "\"prior_unresolved\":%s}",
        t->ref.seq, t->ref.name, t->ref.attempt,
        t->worker, esc_gate, t->scope,
        t->model, esc_model,
        r->provider, r->session, r->turn,
        r->start_command, r->turn_command,
        r->terminal, r->verdict, r->rc,
        esc_reason, esc_engine,
        r->base, r->candidate,
        esc_gate, r->gate_evidence,
        esc_verdict, r->gate_present ? "true" : "false",
        r->gate_ran, r->gate_failed, r->gate_ms,
        r->input_tokens, r->output_tokens, r->total_tokens,
        r->duration_ms, r->wall_ms, r->files_changed,
        r->prior_unresolved ? "true" : "false");
    (void)mr_write_atomic(path, body);
    free(body);
}

/* --- the run --------------------------------------------------------------- */

struct mr_core {
    const struct muse_run_task *task;
    struct muse_run_result *res;
    int64_t t0;
    int64_t turn_timeout_ms;
    int gate_timeout_ms;
    uint64_t max_tokens;
};

static int mr_finish(struct mr_core *c, struct muse_session *s,
    const char *open_err, char err[MUSE_RUN_ERROR_MAX])
{
    struct muse_run_task const *t = c->task;
    struct muse_run_result *r = c->res;
    struct muse_session_policy policy;
    struct muse_turn_outcome out;
    struct engine_gate_reading gate;
    char gate_log_stack[MR_GATE_LOG_MAX];
    char *gate_log = gate_log_stack;
    const char *allow[1];
    const char *engine_name = "UNKNOWN";
    char engine_buf[64];
    int rc = 1;
    memset(&policy, 0, sizeof(policy));
    r->duration_ms = -1;
    r->files_changed = -1;
    r->gate_ran = -1;
    r->gate_failed = -1;
    (void)snprintf(r->verdict, sizeof(r->verdict), "%s",
        mr_verdict_refused);
    (void)snprintf(r->reason, sizeof(r->reason),
        "breakdown before judgement");
    r->rc = 1;
    if (!s) {
        (void)snprintf(r->reason, sizeof(r->reason), "%s",
            open_err && open_err[0] ? open_err : "serve host unavailable");
        goto write;
    }
    /* Prior admitted turn without a terminal: a fresh host cannot cancel
     * a dead host's turn (sessionNotLoaded), so the gate still judges
     * the final diff and this note preserves the fact. */
    {
        char turns[8192];
        if (snprintf(turns, sizeof(turns), "%s/muse-turn.jsonl",
                t->rundir) < (int)sizeof(turns)) {
            char *old = mr_read_file(turns, 65536);
            if (old) {
                if (strstr(old, "\"turnId\":") && !strstr(old,
                        "\"terminal\":"))
                    r->prior_unresolved = true;
                free(old);
            }
        }
    }
    /* Source half of the diff identity, taken before the turn lands. */
    mr_base_commit(t->workspace, r->base, sizeof(r->base));
    allow[0] = t->scope;
    policy.approval_mode = "denyUnmatched";
    policy.model = t->model[0] ? t->model : NULL;
    policy.allow_paths = allow;
    policy.allow_path_count = 1;
    if (!muse_session_command_id(r->start_command) ||
        muse_session_start(s, r->start_command, t->workspace, &policy,
            r->session, r->provider, r->model_resolved) != 0) {
        (void)snprintf(r->reason, sizeof(r->reason), "%s",
            muse_session_last_error(s));
        goto write;
    }
    if (!muse_session_command_id(r->turn_command) ||
        muse_session_turn(s, r->turn_command, r->session, t->prompt,
            r->turn) != 0) {
        (void)snprintf(r->reason, sizeof(r->reason), "%s",
            muse_session_last_error(s));
        goto write;
    }
    /* Admission is durable before waiting: a restart sees this line and
     * never mistakes the turn for unsubmitted. */
    {
        char line[1024];
        char turns[8192];
        (void)snprintf(line, sizeof(line),
            "{\"sessionId\":\"%s\",\"turnId\":\"%s\",\"commandId\":\"%s\"}",
            r->session, r->turn, r->turn_command);
        if (snprintf(turns, sizeof(turns), "%s/muse-turn.jsonl",
                t->rundir) < (int)sizeof(turns))
            (void)mr_append_line(turns, line);
    }
    memset(&out, 0, sizeof(out));
    if (muse_session_wait(s, r->session, r->turn, &policy, &out) != 0) {
        const char *kind = muse_session_last_kind(s);
        /* A bound trip stops the turn first: the timeout owns its
         * verdict, a token trip keeps "refused" with the budget
         * reason, and anything else reports the host error. */
        if (strcmp(kind, "timeout") == 0 ||
            strcmp(kind, "tokenBudget") == 0) {
            char cc[MUSE_COMMAND_ID_MAX];
            if (muse_session_command_id(cc))
                (void)muse_session_cancel(s, cc, r->session, r->turn);
        }
        if (strcmp(kind, "timeout") == 0) {
            (void)snprintf(r->verdict, sizeof(r->verdict), "%s",
                mr_verdict_timeout);
            (void)snprintf(r->reason, sizeof(r->reason),
                "turn exceeded its bound");
        } else {
            (void)snprintf(r->reason, sizeof(r->reason), "%s",
                muse_session_last_error(s));
        }
        r->wall_ms = (long long)(mr_monotonic_ms() - c->t0);
        goto write;
    }
    (void)snprintf(r->terminal, sizeof(r->terminal), "%s", out.terminal);
    r->input_tokens = out.input_tokens;
    r->output_tokens = out.output_tokens;
    r->total_tokens = out.total_tokens;
    r->duration_ms = out.duration_ms;
    muse_turn_outcome_free(&out);
    if (strcmp(r->terminal, "completed") != 0) {
        if (strcmp(r->terminal, "cancelled") == 0) {
            (void)snprintf(r->verdict, sizeof(r->verdict), "%s",
                mr_verdict_cancelled);
            (void)snprintf(r->reason, sizeof(r->reason),
                "turn cancelled");
        } else {
            (void)snprintf(r->verdict, sizeof(r->verdict), "%s",
                mr_verdict_failed);
            (void)snprintf(r->reason, sizeof(r->reason),
                "turn did not complete");
        }
        r->wall_ms = (long long)(mr_monotonic_ms() - c->t0);
        goto write;
    }
    /* THE GATE DECIDES. The turn text is evidence, never a verdict input. */
    r->files_changed = mr_files_changed(t->workspace);
    if (r->files_changed < 0) {
        (void)snprintf(r->reason, sizeof(r->reason),
            "worktree diff unmeasurable");
    } else if (!mr_run_gate(t->workspace, t->gate, c->gate_timeout_ms,
                 gate_log, sizeof(gate_log_stack), &r->gate_ms, &gate)) {
        (void)snprintf(r->reason, sizeof(r->reason),
            "registered runner unrunnable");
    } else {
        enum engine_verdict v;
        r->gate_present = gate.saw_verdict_line;
        r->gate_ran = gate.groups_ran;
        r->gate_failed = gate.groups_failed;
        mr_last_verdict_line(gate_log, r->gate_verdict,
            sizeof(r->gate_verdict));
        (void)snprintf(r->gate_evidence, sizeof(r->gate_evidence),
            "%s:%lld/%lld", t->gate, r->gate_ran, r->gate_failed);
        v = engine_verdict_of(&gate, (size_t)r->files_changed, false,
            true);
        engine_name = mr_engine_short(engine_verdict_name(v), engine_buf,
            sizeof(engine_buf));
        if (v == ENGINE_VERDICT_PASS) {
            (void)snprintf(r->verdict, sizeof(r->verdict), "%s",
                mr_verdict_pass);
            (void)snprintf(r->reason, sizeof(r->reason), "gate passed");
            rc = 0;
        } else {
            (void)snprintf(r->verdict, sizeof(r->verdict), "%s",
                mr_verdict_failed);
            (void)snprintf(r->reason, sizeof(r->reason),
                "gate refused: %s", engine_name);
        }
    }
    r->wall_ms = (long long)(mr_monotonic_ms() - c->t0);
    goto write;
write:
    (void)snprintf(r->engine, sizeof(r->engine), "%s",
        engine_name);
    r->rc = rc;
    mr_candidate(t->workspace, t->rundir, r->candidate,
        sizeof(r->candidate), r->candidate_file,
        sizeof(r->candidate_file));
    /* The claim-holding caller's receipt is canonical: never lay ours
     * beside it. Evidence (muse.json, candidate artifact, admission)
     * is still written. */
    if (!t->caller_holds_claim)
        mr_write_receipt(t, r);
    mr_write_facts(t, r);
    printf("ref=%lld/%s/%lld verdict=%s tokens=%llu files=%lld wall_ms=%lld\n",
        t->ref.seq, t->ref.name, t->ref.attempt, r->verdict,
        (unsigned long long)r->total_tokens, r->files_changed,
        r->wall_ms);
    printf("rc=%d\n", rc);
    if (s) muse_session_close(s);
    (void)err;
    return rc;
}

static int mr_open_run(struct mr_core *c, char err[MUSE_RUN_ERROR_MAX])
{
    struct muse_session_limits sl;
    struct muse_session *s;
    char serr[MUSE_ERROR_MAX];
    memset(&sl, 0, sizeof(sl));
    sl.turn_timeout_ms = c->turn_timeout_ms;
    sl.max_total_tokens = c->max_tokens;
    sl.max_text_bytes = MR_TEXT_DEFAULT;
    serr[0] = '\0';
    s = muse_session_open("muse", &sl, serr);
    return mr_finish(c, s, serr, err);
}

/* 1 = already recorded (result carries the earlier verdict, rc 0),
 * 0 = clear to run, -1 = fail closed. */
static int mr_prepare(const struct muse_run_task *t,
    struct muse_run_result *out, struct mr_core *c,
    char err[MUSE_RUN_ERROR_MAX])
{
    c->task = t;
    c->res = out;
    c->t0 = mr_monotonic_ms();
    c->turn_timeout_ms = t->budgets.turn_timeout_ms > 0
        ? t->budgets.turn_timeout_ms : MR_TURN_DEFAULT_MS;
    c->gate_timeout_ms = t->budgets.gate_timeout_ms > 0
        ? (int)t->budgets.gate_timeout_ms : MR_GATE_DEFAULT_MS;
    c->max_tokens = t->budgets.max_total_tokens;
    if (c->max_tokens == 0) c->max_tokens = MR_TOKEN_DEFAULT;
    if (mr_validate(t, err) != 0) return -1;
    out->ref = t->ref;
    (void)snprintf(out->worker, sizeof(out->worker), "%s", t->worker);
    (void)snprintf(out->gate, sizeof(out->gate), "%s", t->gate);
    (void)snprintf(out->model_requested, sizeof(out->model_requested),
        "%s", t->model);
    /* The claim-holding caller (A's worker) is the at-most-once
     * guarantee: its claim.json decides submission, never this
     * receipt. Direct callers keep the fail-closed receipt check. */
    if (t->caller_holds_claim) return 0;
    {
        int recorded = mr_already_recorded(t, out);
        if (recorded != 0) {
            if (recorded > 0) {
                mr_report_short(t, out);
                return 1;
            }
            return -1;
        }
    }
    return 0;
}

static int mr_begin(struct mr_core *c, char err[MUSE_RUN_ERROR_MAX])
{
    int prep = mr_prepare(c->task, c->res, c, err);
    if (prep != 0) return prep > 0 ? 0 : 1;
    return mr_open_run(c, err);
}

int muse_run_task(const struct muse_run_task *task,
    struct muse_run_result *out, char err[MUSE_RUN_ERROR_MAX])
{
    struct mr_core c;
    if (!task || !out) {
        if (err)
            (void)snprintf(err, MUSE_RUN_ERROR_MAX, "task/result missing");
        return 1;
    }
    memset(out, 0, sizeof(*out));
    memset(&c, 0, sizeof(c));
    c.task = task;
    c.res = out;
    return mr_begin(&c, err);
}

/* --- composed file --------------------------------------------------------- */

static bool mr_file_header(const char *text, const char *key, char *out,
    size_t cap)
{
    size_t kl = strlen(key);
    const char *p = text;
    for (;;) {
        const char *eol = strchr(p, '\n');
        size_t len = eol ? (size_t)(eol - p) : strlen(p);
        /* Headers end at the titled brief marker the composer emits
         * ("=== BRIEF: <path> ==="); never parse the prompt body. */
        if (len >= 9 && strncmp(p, "=== BRIEF", 9) == 0) return false;
        if (len > kl + 2 && strncmp(p, key, kl) == 0 && p[kl] == ':' &&
            p[kl + 1] == ' ') {
            const char *v = p + kl + 2;
            size_t vn = len - (kl + 2);
            while (vn > 0 &&
                (v[vn - 1] == ' ' || v[vn - 1] == '\t' ||
                    v[vn - 1] == '\r'))
                vn--;
            return mr_copy(out, cap, v, vn);
        }
        if (!eol) return false;
        p = eol + 1;
    }
}

/* File layout mirrors the queue composer: machine headers, one group
 * line, then the titled brief whose body is the prompt. The queue:
 * header is accepted and ignored; worker defaults to "cli". */
static int mr_parse_file(const char *taskpath, struct muse_run_task *t,
    char **prompt, char err[MUSE_RUN_ERROR_MAX])
{
    char *text = mr_read_file(taskpath, MR_LINE_MAX);
    char kind[32], seq[32], attempt[32];
    const char *body;
    if (!text) {
        if (err)
            (void)snprintf(err, MUSE_RUN_ERROR_MAX,
                "cannot read task file");
        return -1;
    }
    memset(t, 0, sizeof(*t));
    t->ref.seq = -1;
    t->ref.attempt = -1;
    if (!mr_file_header(text, "kind", kind, sizeof(kind)) ||
        strcmp(kind, "muse") != 0) {
        if (err)
            (void)snprintf(err, MUSE_RUN_ERROR_MAX,
                "task is not kind: muse");
        free(text);
        return -1;
    }
    if (!mr_file_header(text, "seq", seq, sizeof(seq)) ||
        !mr_file_header(text, "name", t->ref.name,
            sizeof(t->ref.name)) ||
        !mr_file_header(text, "attempt", attempt, sizeof(attempt)) ||
        !mr_file_header(text, "group", t->gate, sizeof(t->gate)) ||
        !mr_file_header(text, "scope", t->scope, sizeof(t->scope)) ||
        !mr_file_header(text, "worktree", t->workspace,
            sizeof(t->workspace)) ||
        !mr_file_header(text, "rundir", t->rundir,
            sizeof(t->rundir))) {
        if (err)
            (void)snprintf(err, MUSE_RUN_ERROR_MAX,
                "task headers incomplete");
        free(text);
        return -1;
    }
    t->ref.seq = strtoll(seq, NULL, 10);
    t->ref.attempt = strtoll(attempt, NULL, 10);
    (void)mr_file_header(text, "model", t->model, sizeof(t->model));
    if (snprintf(t->worker, sizeof(t->worker), "cli") >=
        (int)sizeof(t->worker)) {
        free(text);
        return -1;
    }
    body = strstr(text, "=== BRIEF");
    if (!body) {
        if (err)
            (void)snprintf(err, MUSE_RUN_ERROR_MAX, "task has no brief");
        free(text);
        return -1;
    }
    body = strchr(body, '\n');
    if (!body) {
        if (err)
            (void)snprintf(err, MUSE_RUN_ERROR_MAX,
                "task brief is empty");
        free(text);
        return -1;
    }
    body++;
    while (*body == '\n' || *body == '\r') body++;
    if (!*body) {
        if (err)
            (void)snprintf(err, MUSE_RUN_ERROR_MAX,
                "task brief is empty");
        free(text);
        return -1;
    }
    *prompt = malloc(strlen(body) + 1);
    if (!*prompt) {
        if (err)
            (void)snprintf(err, MUSE_RUN_ERROR_MAX, "out of memory");
        free(text);
        return -1;
    }
    memcpy(*prompt, body, strlen(body) + 1);
    free(text);
    return 0;
}

int muse_run_task_file(const char *taskpath,
    const struct muse_run_budgets *budgets, char err[MUSE_RUN_ERROR_MAX])
{
    struct muse_run_task t;
    struct muse_run_result out;
    char *prompt = NULL;
    int rc;
    if (!taskpath) {
        if (err)
            (void)snprintf(err, MUSE_RUN_ERROR_MAX, "task path missing");
        return 1;
    }
    if (mr_parse_file(taskpath, &t, &prompt, err) != 0) {
        free(prompt);
        return 1;
    }
    if (budgets) t.budgets = *budgets;
    t.prompt = prompt;
    memset(&out, 0, sizeof(out));
    rc = muse_run_task(&t, &out, err);
    free(prompt);
    return rc;
}

#ifdef ZCL_TESTING
int muse_run_task_on_transport(const struct muse_run_task *task,
    pid_t child, int to_fd, int from_fd, struct muse_run_result *out,
    char err[MUSE_RUN_ERROR_MAX])
{
    struct mr_core c;
    struct muse_session *s;
    struct muse_session_limits sl;
    if (!task || !out) {
        if (err)
            (void)snprintf(err, MUSE_RUN_ERROR_MAX, "task/result missing");
        return 1;
    }
    memset(out, 0, sizeof(*out));
    memset(&c, 0, sizeof(c));
    c.task = task;
    c.res = out;
    {
        int prep = mr_prepare(task, out, &c, err);
        if (prep != 0) return prep > 0 ? 0 : 1;
    }
    memset(&sl, 0, sizeof(sl));
    sl.turn_timeout_ms = c.turn_timeout_ms;
    sl.max_total_tokens = c.max_tokens;
    sl.max_text_bytes = MR_TEXT_DEFAULT;
    s = muse_session_attach(child, to_fd, from_fd, &sl);
    if (!s && err) {
        (void)snprintf(err, MUSE_RUN_ERROR_MAX, "transport attach failed");
        return 1;
    }
    return mr_finish(&c, s, "", err);
}
#endif
