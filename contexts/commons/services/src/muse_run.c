/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: queue row -> Muse turn -> registered gate -> receipt. See header. */
#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif

#include "services/muse_run.h"
#include "services/muse_session.h"
#include "base/safe_alloc.h"
#include "engine/engine_verdict.h"
#include "json/json.h"
#include "platform/clock.h"
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
/* Bound on one porcelain capture. zcl_spawn_capture discards whatever
 * overruns its buffer and still reports the child's exit status, so a
 * capture that fills its bound is INDISTINGUISHABLE from a complete one
 * and must be treated as unmeasurable, never as a short change set. */
#define MR_AUDIT_MAX (256u * 1024u)

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
    return clock_now_monotonic_ns() / 1000000;
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
    buf = zcl_malloc((size_t)n + 1, "muse_run.file");
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

/* One identity character: ASCII alphanumeric plus `_`, `.` and `-`. */
static bool mr_token_char(char c)
{
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
        (c >= '0' && c <= '9') || c == '_' || c == '.' || c == '-';
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
        if (!mr_token_char(s[i])) return false;
    }
    return true;
}

/* --- validation ------------------------------------------------------------ */

/* The queue row's identity: the ref triple plus the optional worker name. */
static int mr_validate_ref(const struct muse_run_task *t,
    char err[MUSE_RUN_ERROR_MAX])
{
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
    return 0;
}

/* The place the turn edits: an existing workspace and a scope that cannot
 * escape it. */
static int mr_validate_workspace(const struct muse_run_task *t,
    char err[MUSE_RUN_ERROR_MAX])
{
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
    return 0;
}

/* The judge and the model's instruction: a named gate and a bounded
 * prompt. */
static int mr_validate_work(const struct muse_run_task *t,
    char err[MUSE_RUN_ERROR_MAX])
{
    size_t prompt_len;
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
    return 0;
}

static int mr_validate(const struct muse_run_task *t,
    char err[MUSE_RUN_ERROR_MAX])
{
    if (!t) {
        if (err)
            (void)snprintf(err, MUSE_RUN_ERROR_MAX, "task is missing");
        return -1;
    }
    if (mr_validate_ref(t, err) != 0) return -1;
    if (mr_validate_workspace(t, err) != 0) return -1;
    if (mr_validate_work(t, err) != 0) return -1;
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

/* True when a capture filled its bound: the helper silently discards the
 * overrun, so a full buffer proves only that the measurement is unknown. */
static bool mr_capture_truncated(const char *buf, size_t cap)
{
    return cap == 0 || strlen(buf) + 1 >= cap;
}

/* -1 is UNMEASURABLE and is never the same answer as 0, which is a
 * measured clean tree: a failed spawn, a non-zero git, or a capture that
 * filled its bound all refuse rather than under-report the count. */
static long long mr_files_changed(const char *workspace)
{
    const char *argv[] = { "git", "-C", workspace, "status", "--porcelain",
                           NULL };
    char *buf = zcl_malloc(MR_AUDIT_MAX, "muse_run.git_out");
    long long count = 0;
    int rc;
    if (!buf) return -1;
    buf[0] = '\0';
    rc = zcl_spawn_capture(argv, buf, MR_AUDIT_MAX, MR_GIT_TIMEOUT_MS);
    if (rc != 0 || mr_capture_truncated(buf, MR_AUDIT_MAX)) {
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
    char *buf = zcl_malloc(65536, "muse_run.git_line");
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

/* HEAD, as one 40-hex identity. False when git could not name it, and the
 * field degrades to the literal "none" so no reader mistakes an unread
 * identity for a match. An identity that is not 40 hex is unread: this is
 * an equality test later, and a partial answer would compare unequal for
 * the wrong reason. */
static bool mr_head_at(const char *workspace, char *out, size_t cap)
{
    if (mr_git_line(out, cap, workspace, "rev-parse", "HEAD", NULL) &&
        mr_hex40(out))
        return true;
    (void)snprintf(out, cap, "none");
    return false;
}

/* The escapes git emits after a backslash in a C-quoted path, paired with
 * the byte each one stands for. Anything else is a row this parser did not
 * write, so it cannot claim to have read it either. */
static const char mr_escape_from[] = "abfnrtv\\\"";
static const char mr_escape_to[] = "\a\b\f\n\r\t\v\\\"";

/* One backslash escape, resolved into *w. p points at the character AFTER
 * the backslash; returns the last character consumed, or NULL when the
 * escape is not one git emits. */
static const char *mr_unescape(const char *p, char **w)
{
    const char *hit;
    if (!*p) return NULL;
    if (*p >= '0' && *p <= '7') {
        int v = 0, k = 0;
        while (k < 3 && *p >= '0' && *p <= '7') {
            v = v * 8 + (*p - '0');
            p++;
            k++;
        }
        *(*w)++ = (char)v;
        return p - 1;
    }
    hit = strchr(mr_escape_from, *p);
    if (!hit) return NULL;
    *(*w)++ = mr_escape_to[hit - mr_escape_from];
    return p;
}

/* Dequote one C-quoted porcelain path in place ("a b" -> a b). False when
 * the quoting is MALFORMED — an unterminated quote, a backslash with
 * nothing after it, or an escape git never emits. A best-effort path out
 * of a broken row is a path this audit cannot claim to have measured, and
 * every caller turns that into a refusal rather than a judgement. */
static bool mr_dequote(char *path)
{
    char *w;
    size_t n = strlen(path);
    if (n == 0) return true;
    if (path[0] != '"') return strchr(path, '"') == NULL;
    if (n < 2 || path[n - 1] != '"') return false;
    path[n - 1] = '\0';
    w = path;
    for (const char *p = path + 1; *p; p++) {
        if (*p != '\\') {
            *w++ = *p;
            continue;
        }
        if (!p[1]) return false;
        p = mr_unescape(p + 1, &w);
        if (!p) return false;
    }
    *w = '\0';
    return true;
}

/* Append "path hash" lines for every untracked path: the content half
 * of the change set that `git diff` never shows. */
static void mr_fold_others(const char *workspace, char *acc, size_t acc_cap,
    size_t *used)
{
    const char *argv[] = { "git", "-C", workspace, "ls-files", "--others",
                           "--exclude-standard", NULL };
    char *list = zcl_malloc(65536, "muse_run.others");
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
        const char *path = line;
        int w;
        /* A path whose quoting will not read is not folded as a
         * best-effort guess: the identity must name what was measured or
         * name nothing, and the scope audit refuses the same row. */
        if (!mr_dequote(line)) break;
        w = snprintf(acc + *used, acc_cap - *used, "?? %s ",
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

/* --- the scope audit ------------------------------------------------------
 * THE MODEL PROPOSES. THE GATE DECIDES — and the SCOPE is decided here, by
 * measured output. The allow prefix handed to the session binds only the
 * moment the model asks for approval; it proves nothing about what the
 * workspace holds afterwards. So the run re-measures the change set through
 * the SAME `git status --porcelain` invocation mr_files_changed counts, and
 * judges every path it names. */

/* Inside the declared scope: the path IS the scope, or it lives under it.
 * A scope naming a directory admits its contents and never a sibling whose
 * name merely starts the same way ("docs/" never admits "docsevil/x"), and
 * any path carrying ".." or a leading '/' is outside by definition. */
static bool mr_in_scope(const char *path, const char *scope)
{
    size_t n;
    if (!path || !path[0] || !scope || !scope[0]) return false;
    if (path[0] == '/' || strstr(path, "..") != NULL) return false;
    n = strlen(scope);
    while (n > 0 && scope[n - 1] == '/') n--;
    if (n == 0) return false;
    if (strncmp(path, scope, n) != 0) return false;
    if (path[n] == '\0') return true;
    return path[n] == '/';
}

/* Appends one escaped element to a bounded JSON array body. False once the
 * bound is reached: one run's change set can never write without limit, and
 * the body stays valid JSON at every truncation point. */
static bool mr_list_push(char *buf, size_t cap, size_t *used,
    const char *path)
{
    char esc[1024];
    int w;
    if (!buf || cap == 0 || *used >= cap) return false;
    mr_esc(path, esc, sizeof(esc));
    w = snprintf(buf + *used, cap - *used, "%s\"%s\"",
        *used > 0 ? "," : "", esc);
    if (w <= 0 || (size_t)w >= cap - *used) {
        buf[*used] = '\0';
        return false;
    }
    *used += (size_t)w;
    return true;
}

/* One measurement pass. scope NULL records the paths without judging them:
 * that is the pre-state pass, where any path at all is already a refusal. */
struct mr_audit {
    const char *scope;
    char *list;
    size_t list_cap;
    size_t list_used;
    char *outside;
    size_t outside_cap;
    size_t outside_used;
    long long total;
    long long outside_total;
    /* Rows the parser could not read. Silently dropping one would hide a
     * path, so any non-zero value makes the whole pass unmeasurable. */
    long long unreadable;
};

static void mr_audit_init(struct mr_audit *a, const char *scope, char *list,
    size_t list_cap, char *outside, size_t outside_cap)
{
    memset(a, 0, sizeof(*a));
    a->scope = scope;
    a->list = list;
    a->list_cap = list_cap;
    a->outside = outside;
    a->outside_cap = outside_cap;
    if (list && list_cap > 0) list[0] = '\0';
    if (outside && outside_cap > 0) outside[0] = '\0';
}

/* One measured path: counted in full, recorded while the bound allows, and
 * judged against the scope. A row that names nothing is unreadable, never
 * an absence. */
static void mr_audit_path(struct mr_audit *a, const char *path)
{
    if (!path || !path[0]) {
        a->unreadable++;
        return;
    }
    a->total++;
    (void)mr_list_push(a->list, a->list_cap, &a->list_used, path);
    if (!a->scope || mr_in_scope(path, a->scope)) return;
    a->outside_total++;
    (void)mr_list_push(a->outside, a->outside_cap, &a->outside_used, path);
}

/* Every status character porcelain v1 can print in either column. */
static bool mr_status_char(char c)
{
    return c == ' ' || c == 'M' || c == 'T' || c == 'A' || c == 'D' ||
        c == 'R' || c == 'C' || c == 'U' || c == '?' || c == '!';
}

/* The row's fixed-width prefix, exactly: two legal status characters and
 * the single space that always follows them. '?' and '!' only ever appear
 * doubled, and two blanks mean "unmodified in both columns", which this
 * seam never prints. A line that is not that shape did not come out of
 * the porcelain this audit measures, so the caller counts it unreadable
 * instead of trusting the path it appears to carry: length alone is not a
 * shape, and a blind fixed skip over a line of the wrong shape invents a
 * path out of whatever follows. */
static bool mr_row_status_ok(const char *line)
{
    if (!line || strlen(line) < 4) return false;
    if (!mr_status_char(line[0]) || !mr_status_char(line[1])) return false;
    if (line[2] != ' ') return false;
    if ((line[0] == '?') != (line[1] == '?')) return false;
    if ((line[0] == '!') != (line[1] == '!')) return false;
    return line[0] != ' ' || line[1] != ' ';
}

/* Whether the status names a second path. Rename and copy carry " -> " in
 * either column; nothing else does. */
static bool mr_row_names_two(const char *line)
{
    return line[0] == 'R' || line[0] == 'C' ||
        line[1] == 'R' || line[1] == 'C';
}

/* One porcelain row -> the path or paths it names. A rename row names two
 * paths and BOTH are judged: moving a file out of scope changes it just as
 * surely as editing it does. The shape must AGREE with the status: an
 * R/C row without its separator, or a separator on a status that cannot
 * carry one, is unreadable rather than one lucky path — either way the
 * row names something this parser did not identify, and a path it did not
 * identify is a path it did not judge. A literal " -> " inside a single
 * unquoted filename is ambiguous by the same rule and refuses too. */
static void mr_audit_row(struct mr_audit *a, char *line)
{
    char *arrow;
    bool two;
    if (!mr_row_status_ok(line)) {
        a->unreadable++;
        return;
    }
    two = mr_row_names_two(line);
    line += 3;
    arrow = strstr(line, " -> ");
    if (two != (arrow != NULL)) {
        a->unreadable++;
        return;
    }
    if (arrow) {
        *arrow = '\0';
        if (!mr_dequote(line)) {
            a->unreadable++;
            return;
        }
        mr_audit_path(a, line);
        line = arrow + 4;
    }
    if (!mr_dequote(line)) {
        a->unreadable++;
        return;
    }
    mr_audit_path(a, line);
}

/* The measured change set, through the porcelain seam the diff count
 * already uses. False when the change set could not be MEASURED: a failed
 * allocation, a failed spawn, a non-zero or timed-out git, a capture that
 * filled its bound, or a row the parser could not read. Every one of those
 * is a refusal input. None of them may ever read as "clean" or as "nothing
 * outside scope" — a silent default there turns this whole audit from a
 * guarantee into decoration. */
static bool mr_audit_scan(const char *workspace, struct mr_audit *a)
{
    /* -uall on purpose: the default collapses a wholly untracked
     * directory to its own name, and while that is still sound for the
     * judgement (the directory name is a prefix of everything inside it,
     * so a collapse can never hide an out-of-scope path), the changed
     * list IS the proof that the permission was respected. Name the
     * files. Same seam, same binary, one flag. */
    const char *argv[] = { "git", "-C", workspace, "status", "--porcelain",
                           "-uall", NULL };
    char *buf = zcl_malloc(MR_AUDIT_MAX, "muse_run.audit");
    int rc;
    bool ok;
    if (!buf) return false;
    buf[0] = '\0';
    rc = zcl_spawn_capture(argv, buf, MR_AUDIT_MAX, MR_GIT_TIMEOUT_MS);
    if (rc != 0 || mr_capture_truncated(buf, MR_AUDIT_MAX)) {
        free(buf);
        return false;
    }
    for (char *line = strtok(buf, "\n"); line; line = strtok(NULL, "\n"))
        mr_audit_row(a, line);
    ok = a->unreadable == 0;
    free(buf);
    return ok;
}

/* SHA-1 over the post-run change set: the tracked diff plus one
 * content hash per untracked path, hashed once more so the token is
 * fixed-width. Empty diffs hash deterministically; "none" only when
 * git itself fails. The fold passes through a rundir tempfile because
 * the capture helper is text-oriented. On success the fold is also
 * published as <rundir>/candidate-<hex>.diff (atomic): the named
 * artifact a gate checks for existence. file_out takes that filename
 * ("" when nothing is named). */
/* Lays the fold down in a rundir tempfile, because the capture helper the
 * hash goes through is text-oriented. False when it could not be written. */
static bool mr_fold_tempfile(const char *rundir, char *tmp, size_t tmpcap,
    const char *acc, size_t used)
{
    FILE *f;
    if (snprintf(tmp, tmpcap, "%s/.candidate.in", rundir) >= (int)tmpcap)
        return false;
    f = fopen(tmp, "wb");
    if (!f) return false;
    if (used > 0 && fwrite(acc, 1, used, f) != used) {
        fclose(f);
        (void)unlink(tmp);
        return false;
    }
    fclose(f);
    return true;
}

/* git hash-object over the fold tempfile, which is removed either way. The
 * 40-hex token lands in out; false on any git failure. */
static bool mr_hash_fold(const char *tmp, char *out, size_t cap)
{
    const char *h_argv[] = { "git", "hash-object", tmp, NULL };
    char *hbuf = zcl_malloc(128, "muse_run.hash");
    bool ok = false;
    int rc;
    if (!hbuf) {
        (void)unlink(tmp);
        return false;
    }
    hbuf[0] = '\0';
    rc = zcl_spawn_capture(h_argv, hbuf, 128, MR_GIT_TIMEOUT_MS);
    (void)unlink(tmp);
    if (rc == 0) {
        hbuf[strcspn(hbuf, "\r\n")] = '\0';
        if (mr_hex40(hbuf) && strlen(hbuf) < cap) {
            (void)snprintf(out, cap, "%s", hbuf);
            ok = true;
        }
    }
    free(hbuf);
    return ok;
}

/* Publishes the fold as the named artifact. */
static void mr_publish_candidate(const char *rundir, const char *h,
    const char *acc, char *file_out, size_t file_cap)
{
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

static void mr_candidate(const char *workspace, const char *rundir,
    char *out, size_t cap, char *file_out, size_t file_cap)
{
    const char *diff_argv[] = { "git", "-C", workspace, "diff", "HEAD",
                                "--", NULL };
    char *acc = zcl_malloc(MR_GATE_LOG_MAX, "muse_run.candidate");
    char tmp[8192];
    size_t used = 0;
    int rc;
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
    if (!mr_fold_tempfile(rundir, tmp, sizeof(tmp), acc, used)) {
        free(acc);
        return;
    }
    if (mr_hash_fold(tmp, out, cap) && file_out && file_cap > 0)
        mr_publish_candidate(rundir, out, acc, file_out, file_cap);
    free(acc);
}

/* --- the gate's own process ------------------------------------------------
 * WHAT THE LOG SAYS IS NOT WHAT THE PROCESS DID. A runner that is killed
 * on its deadline, or that exits non-zero, still leaves behind whatever it
 * had already written — and the reader keeps the LAST SUITE VERDICT line
 * it finds, which a half-finished run can easily have printed with
 * groups_failed=0. Discarding the spawn status turns every such death into
 * a pass. So the status is carried, not dropped, and the log is read only
 * for a process that finished normally and successfully.
 *
 * What the capture seam can actually tell apart, and nothing more:
 * a launch that never happened, a deadline this side enforced, a
 * wait status that was never trustworthy, a complete or truncated
 * capture, and one exit number. That number cannot separate a child
 * killed by signal N from a child that called exit(128+N) — both arrive
 * as 128+N — and no distinction is invented here that the seam does not
 * support. Both are non-zero, so both refuse. */
struct mr_spawn_outcome {
    bool attempted;      /* the runner was found and the capture was tried */
    bool launched;       /* the child ran at all */
    bool exit_observed;  /* a trustworthy wait status was obtained */
    bool timed_out;      /* this side killed it on the deadline */
    bool complete;       /* stdout reached EOF without filling the bound */
    int exit_code;       /* normal exit 0..255, or 128+signal; -1 unknown */
};

/* True only for the one outcome whose log may be believed. */
static bool mr_spawn_normal(const struct mr_spawn_outcome *o)
{
    return o->attempted && o->launched && o->exit_observed &&
        !o->timed_out && o->complete && o->exit_code == 0;
}

/* Names the outcome for the evidence, so a refusal says what the process
 * did and never only that the gate "refused". */
static void mr_spawn_outcome_name(const struct mr_spawn_outcome *o,
    char *out, size_t cap)
{
    if (!o->attempted)
        (void)snprintf(out, cap, "runner-unrunnable");
    else if (!o->launched)
        (void)snprintf(out, cap, "launch-failed");
    else if (o->timed_out)
        (void)snprintf(out, cap, "timeout");
    else if (!o->exit_observed)
        (void)snprintf(out, cap, "status-unobserved");
    else if (!o->complete)
        (void)snprintf(out, cap, "log-truncated exit=%d", o->exit_code);
    else
        (void)snprintf(out, cap, "exit=%d", o->exit_code);
}

/* One bounded capture with its outcome preserved. The exact-binary seam is
 * the only capture in the tree that reports the deadline, the wait status
 * and the completeness of the read separately; the plain capture folds all
 * three into one int where a timeout and a clean exit 0 can look alike.
 * It does not terminate the buffer, so that is done here. */
static void mr_gate_capture(const char *const argv[], char *log,
    size_t logcap, int timeout_ms, struct mr_spawn_outcome *o)
{
    struct zcl_spawn_binary_observation obs;
    memset(o, 0, sizeof(*o));
    memset(&obs, 0, sizeof(obs));
    obs.exit_code = -1;
    o->exit_code = -1;
    o->attempted = true;
    log[0] = '\0';
    /* The rolled-up result says only that SOMETHING was wrong; the
     * observation beside it says which thing, and that is the fact the
     * refusal has to name. */
    ZCL_IGNORE_RESULT(
        zcl_spawn_capture_binary(argv, log, logcap - 1, timeout_ms, &obs),
        "the observation below carries every outcome this refuses on");
    log[obs.output_len < logcap ? obs.output_len : logcap - 1] = '\0';
    o->timed_out = obs.timed_out;
    o->exit_observed = obs.exit_observed;
    o->complete = obs.eof && !obs.overflow;
    o->exit_code = obs.exit_code;
    /* A refused launch captures nothing and observes nothing; anything
     * that reached a deadline or a wait status did run. */
    o->launched = obs.timed_out || obs.exit_observed || obs.output_len > 0;
}

/* Runs the named registered group through the workspace's own runner and,
 * ONLY for a normal successful exit, reports the machine verdict line
 * through engine_gate_read. Missing or unrunnable runner, a failed launch,
 * a deadline, an unobserved status, a truncated log and any non-zero exit
 * are all refusal inputs, never a pass — whatever the captured log says. */
static bool mr_run_gate(const char *workspace, const char *group,
    int timeout_ms, char *log, size_t logcap, long long *elapsed_ms,
    struct engine_gate_reading *reading, struct mr_spawn_outcome *o)
{
    char runner[8192];
    const char *argv[8];
    char selector[128];
    int64_t t0;
    memset(o, 0, sizeof(*o));
    o->exit_code = -1;
    if (!workspace || !group || !log || logcap < 2 || !elapsed_ms ||
        !reading || timeout_ms <= 0)
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
    t0 = mr_monotonic_ms();
    mr_gate_capture(argv, log, logcap, timeout_ms, o);
    *elapsed_ms = (long long)(mr_monotonic_ms() - t0);
    if (!mr_spawn_normal(o)) return false;
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
    char *body = zcl_malloc(65536, "muse_run.facts");
    char esc_reason[1024], esc_engine[128], esc_verdict[2048];
    char esc_model[512], esc_gate[512], esc_spawn[192];
    if (!body) return;
    mr_esc(r->gate_spawn, esc_spawn, sizeof(esc_spawn));
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
        "\"head\":{\"pinned\":\"%s\",\"observed\":\"%s\","
        "\"measured\":%s},"
        "\"gate\":{\"name\":\"%s\",\"evidence\":\"%s\","
        "\"verdict\":\"%s\",\"present\":%s,\"ran\":%lld,\"failed\":%lld,"
        "\"ms\":%lld,\"spawn\":\"%s\",\"exit\":%d,\"normal\":%s},"
        "\"tokens\":{\"input\":%llu,\"output\":%llu,\"total\":%llu},"
        "\"duration_ms\":%lld,\"wall_ms\":%lld,\"files_changed\":%lld,"
        "\"scope_audit\":{\"pre_measured\":%s,\"pre_clean\":%s,"
        "\"pre_count\":%lld,\"pre\":[%s],\"changed_measured\":%s,"
        "\"changed_count\":%lld,\"changed\":[%s],"
        "\"outside_count\":%lld,\"outside\":[%s]},"
        "\"prior_unresolved\":%s}",
        t->ref.seq, t->ref.name, t->ref.attempt,
        t->worker, esc_gate, t->scope,
        t->model, esc_model,
        r->provider, r->session, r->turn,
        r->start_command, r->turn_command,
        r->terminal, r->verdict, r->rc,
        esc_reason, esc_engine,
        r->base, r->candidate,
        r->base, r->head_observed,
        r->head_measured ? "true" : "false",
        esc_gate, r->gate_evidence,
        esc_verdict, r->gate_present ? "true" : "false",
        r->gate_ran, r->gate_failed, r->gate_ms,
        esc_spawn, r->gate_exit, r->gate_normal ? "true" : "false",
        r->input_tokens, r->output_tokens, r->total_tokens,
        r->duration_ms, r->wall_ms, r->files_changed,
        r->scope_pre_measured ? "true" : "false",
        r->scope_pre_clean ? "true" : "false",
        r->scope_pre_count, r->scope_pre,
        r->scope_changed_measured ? "true" : "false",
        r->scope_changed_count, r->scope_changed,
        r->scope_outside_count, r->scope_outside,
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

/* BEFORE the turn. A workspace that is already dirty can prove nothing,
 * because its pre-existing edits would count toward the non-empty diff a
 * pass requires. So this refuses before a single token is spent: no
 * session, no turn, and the offending paths named in the evidence.
 * `build/` is gitignored, so an already-built workspace is still clean.
 * "refused" is the verb, not "failed": this file already spends "refused"
 * on every breakdown that stops the run BEFORE judgement (no host, no
 * submit, unmeasurable diff), and nothing was judged here either. The
 * detail rides the evidence, never the verdict string. */
static bool mr_prestate_clean(struct mr_core *c)
{
    const struct muse_run_task *t = c->task;
    struct muse_run_result *r = c->res;
    struct mr_audit a;
    mr_audit_init(&a, NULL, r->scope_pre, sizeof(r->scope_pre), NULL, 0);
    if (!mr_audit_scan(t->workspace, &a)) {
        /* UNMEASURABLE, which is not clean: the count stays -1 so the
         * evidence can never be read as a measured empty tree. */
        r->scope_pre_measured = false;
        r->scope_pre_count = -1;
        r->scope_pre_clean = false;
        (void)snprintf(r->verdict, sizeof(r->verdict), "%s",
            mr_verdict_refused);
        (void)snprintf(r->reason, sizeof(r->reason),
            "workspace pre-state unmeasurable: %lld unreadable row(s)",
            a.unreadable);
        return false;
    }
    r->scope_pre_measured = true;
    r->scope_pre_count = a.total;
    r->scope_pre_clean = a.total == 0;
    if (r->scope_pre_clean) return true;
    (void)snprintf(r->verdict, sizeof(r->verdict), "%s",
        mr_verdict_refused);
    (void)snprintf(r->reason, sizeof(r->reason),
        "workspace dirty before the turn: %lld path(s) [%s]",
        a.total, r->scope_pre);
    return false;
}

/* AFTER the turn. Every measured path must be inside the declared scope.
 * Measured BEFORE the gate is run, so what is judged is the model's own
 * output and never the gate's side effects. The changed list is the proof
 * that the permission was actually respected: that is the whole point.
 * "failed" is the verb here, not "refused": the turn ran, produced output,
 * and that output was judged and rejected. */
static bool mr_scope_clean(struct mr_core *c)
{
    const struct muse_run_task *t = c->task;
    struct muse_run_result *r = c->res;
    struct mr_audit a;
    mr_audit_init(&a, t->scope, r->scope_changed, sizeof(r->scope_changed),
        r->scope_outside, sizeof(r->scope_outside));
    if (!mr_audit_scan(t->workspace, &a)) {
        /* UNMEASURABLE, which is not "nothing outside scope": both counts
         * stay -1 and the verdict stays the refused this file already
         * spends on a breakdown before judgement. */
        r->scope_changed_measured = false;
        r->scope_changed_count = -1;
        r->scope_outside_count = -1;
        (void)snprintf(r->reason, sizeof(r->reason),
            "workspace change set unmeasurable: %lld unreadable row(s)",
            a.unreadable);
        return false;
    }
    r->scope_changed_measured = true;
    r->scope_changed_count = a.total;
    r->scope_outside_count = a.outside_total;
    if (a.outside_total == 0) return true;
    (void)snprintf(r->verdict, sizeof(r->verdict), "%s",
        mr_verdict_failed);
    (void)snprintf(r->reason, sizeof(r->reason),
        "%lld path(s) outside scope %s: [%s]", a.outside_total,
        t->scope, r->scope_outside);
    return false;
}

/* Two identities that were both read and DISAGREE. Unreadable is a
 * separate fact with its own refusal: "cannot tell" and "definitely
 * different" are not the same answer, and the evidence must not blur
 * them into one. */
static bool mr_head_moved(const char *pinned, const char *observed)
{
    return mr_hex40(pinned) && mr_hex40(observed) &&
        strcmp(pinned, observed) != 0;
}

/* AFTER the turn, BEFORE the gate. The change set audit proves the scope
 * only while the commit it is measured against holds still: a model that
 * COMMITS its work leaves a porcelain tree with nothing in it, so the
 * audit measures nothing and every count reads as a spotless run. The
 * pinned pre-turn HEAD is the only thing that catches that.
 *
 * Measured beside mr_scope_clean for the same reason that one is: what is
 * judged must be the model's own output and never the gate's side
 * effects. A moved HEAD is "failed" — the turn ran, produced something,
 * and that something was judged and rejected. An identity that could not
 * be read at either end is "refused": nothing was judged, because there
 * was nothing to compare. Either way the run can never reach pass. */
static bool mr_head_pinned(struct mr_core *c)
{
    const struct muse_run_task *t = c->task;
    struct muse_run_result *r = c->res;
    r->head_measured = false;
    if (!mr_head_at(t->workspace, r->head_observed,
            sizeof(r->head_observed))) {
        (void)snprintf(r->verdict, sizeof(r->verdict), "%s",
            mr_verdict_refused);
        (void)snprintf(r->reason, sizeof(r->reason),
            "HEAD unreadable after the turn; pinned %s", r->base);
        return false;
    }
    if (!mr_hex40(r->base)) {
        (void)snprintf(r->verdict, sizeof(r->verdict), "%s",
            mr_verdict_refused);
        (void)snprintf(r->reason, sizeof(r->reason),
            "HEAD unreadable before the turn; observed %s",
            r->head_observed);
        return false;
    }
    if (mr_head_moved(r->base, r->head_observed)) {
        (void)snprintf(r->verdict, sizeof(r->verdict), "%s",
            mr_verdict_failed);
        (void)snprintf(r->reason, sizeof(r->reason),
            "HEAD moved during the turn: pinned %s, observed %s",
            r->base, r->head_observed);
        return false;
    }
    r->head_measured = true;
    return true;
}

/* Prior admitted turn without a terminal: a fresh host cannot cancel
 * a dead host's turn (sessionNotLoaded), so the gate still judges
 * the final diff and this note preserves the fact. */
static void mr_note_prior_turn(const struct muse_run_task *t,
    struct muse_run_result *r)
{
    char turns[8192];
    char *old;
    if (snprintf(turns, sizeof(turns), "%s/muse-turn.jsonl", t->rundir) >=
        (int)sizeof(turns))
        return;
    old = mr_read_file(turns, 65536);
    if (!old) return;
    if (strstr(old, "\"turnId\":") && !strstr(old, "\"terminal\":"))
        r->prior_unresolved = true;
    free(old);
}

/* session/start then turn/start. False with the host's reason recorded. */
static bool mr_submit(struct mr_core *c, struct muse_session *s,
    const struct muse_session_policy *policy)
{
    const struct muse_run_task *t = c->task;
    struct muse_run_result *r = c->res;
    if (!muse_session_command_id(r->start_command) ||
        muse_session_start(s, r->start_command, t->workspace, policy,
            r->session, r->provider, r->model_resolved) != 0) {
        (void)snprintf(r->reason, sizeof(r->reason), "%s",
            muse_session_last_error(s));
        return false;
    }
    if (!muse_session_command_id(r->turn_command) ||
        muse_session_turn(s, r->turn_command, r->session, t->prompt,
            r->turn) != 0) {
        (void)snprintf(r->reason, sizeof(r->reason), "%s",
            muse_session_last_error(s));
        return false;
    }
    return true;
}

/* Admission is durable before waiting: a restart sees this line and
 * never mistakes the turn for unsubmitted. */
static void mr_record_admission(const struct muse_run_task *t,
    const struct muse_run_result *r)
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

/* A bound trip stops the turn first: the timeout owns its verdict, a
 * token trip keeps "refused" with the budget reason, and anything else
 * reports the host error. */
static void mr_wait_failed(struct mr_core *c, struct muse_session *s)
{
    struct muse_run_result *r = c->res;
    const char *kind = muse_session_last_kind(s);
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
}

/* A terminal that is not "completed" settles the verdict without a gate. */
static void mr_settle_terminal(struct mr_core *c)
{
    struct muse_run_result *r = c->res;
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
}

/* THE CLOSED PASS PREDICATE. Every fact a pass rests on, measured, in one
 * conjunction: the gate passed over a measured non-empty diff; the
 * workspace was measurably clean before the turn; the change set after it
 * was measured and holds nothing outside the declared scope; the pre-turn
 * HEAD was pinned and had not moved when the change set was measured; and
 * the gate's own process exited normally with status 0, so its log is
 * evidence rather than debris. This is a predicate, not a second decision
 * site: mr_judge below is the only place that acts on it. Nothing here may
 * ever be defaulted — an unmeasured fact is false, never true. */
static bool mr_pass_closed(const struct muse_run_result *r,
    enum engine_verdict v)
{
    return v == ENGINE_VERDICT_PASS && r->scope_pre_measured &&
        r->scope_pre_clean && r->scope_changed_measured &&
        r->scope_outside_count == 0 && r->head_measured && r->gate_normal;
}

/* Everything measured before the gate is allowed to run: the diff count,
 * the change set against the declared scope, and the pinned HEAD. Each one
 * writes its own verdict and reason on refusal. */
static bool mr_measured_before_gate(struct mr_core *c)
{
    struct muse_run_result *r = c->res;
    r->files_changed = mr_files_changed(c->task->workspace);
    if (r->files_changed < 0) {
        (void)snprintf(r->reason, sizeof(r->reason),
            "worktree diff unmeasurable");
        return false;
    }
    /* Measured before the gate runs: the change set judged here is the
     * model's output, never the gate's own side effects. */
    if (!mr_scope_clean(c)) return false;
    return mr_head_pinned(c);
}

/* THE GATE DECIDES. The turn text is evidence, never a verdict input.
 * Returns the rc the run reports and names the engine verdict. */
static int mr_judge(struct mr_core *c, char *gate_log, size_t logcap,
    const char **engine_name, char *engine_buf, size_t engine_cap)
{
    const struct muse_run_task *t = c->task;
    struct muse_run_result *r = c->res;
    struct engine_gate_reading gate;
    struct mr_spawn_outcome spawn;
    enum engine_verdict v;
    if (!mr_measured_before_gate(c)) return 1;
    if (!mr_run_gate(t->workspace, t->gate, c->gate_timeout_ms, gate_log,
            logcap, &r->gate_ms, &gate, &spawn)) {
        /* The log may well hold a passing verdict line. It is not read,
         * because the process that wrote it did not finish normally. */
        mr_spawn_outcome_name(&spawn, r->gate_spawn, sizeof(r->gate_spawn));
        r->gate_exit = spawn.exit_code;
        (void)snprintf(r->reason, sizeof(r->reason),
            "gate did not pass a readable verdict: %s", r->gate_spawn);
        return 1;
    }
    mr_spawn_outcome_name(&spawn, r->gate_spawn, sizeof(r->gate_spawn));
    r->gate_exit = spawn.exit_code;
    r->gate_normal = true;
    r->gate_present = gate.saw_verdict_line;
    r->gate_ran = gate.groups_ran;
    r->gate_failed = gate.groups_failed;
    mr_last_verdict_line(gate_log, r->gate_verdict,
        sizeof(r->gate_verdict));
    (void)snprintf(r->gate_evidence, sizeof(r->gate_evidence),
        "%s:%lld/%lld", t->gate, r->gate_ran, r->gate_failed);
    v = engine_verdict_of(&gate, (size_t)r->files_changed, false, true);
    *engine_name = mr_engine_short(engine_verdict_name(v), engine_buf,
        engine_cap);
    if (mr_pass_closed(r, v)) {
        (void)snprintf(r->verdict, sizeof(r->verdict), "%s",
            mr_verdict_pass);
        (void)snprintf(r->reason, sizeof(r->reason), "gate passed");
        return 0;
    }
    (void)snprintf(r->verdict, sizeof(r->verdict), "%s",
        mr_verdict_failed);
    (void)snprintf(r->reason, sizeof(r->reason),
        "gate refused: %s", *engine_name);
    return 1;
}

/* The receipt, evidence and report every exit path shares. */
static void mr_report(struct mr_core *c, struct muse_session *s,
    const char *engine_name, int rc)
{
    const struct muse_run_task *t = c->task;
    struct muse_run_result *r = c->res;
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
}

static int mr_finish(struct mr_core *c, struct muse_session *s,
    const char *open_err, char err[MUSE_RUN_ERROR_MAX])
{
    struct muse_run_task const *t = c->task;
    struct muse_run_result *r = c->res;
    struct muse_session_policy policy;
    struct muse_turn_outcome out;
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
    /* -1 until measured: an exit path that never reached an enumeration
     * must not publish a zero that reads as a measured clean tree. */
    r->scope_pre_count = -1;
    r->scope_changed_count = -1;
    r->scope_outside_count = -1;
    /* No trustworthy gate status yet, and -1 is not a measured 0. */
    r->gate_exit = -1;
    (void)snprintf(r->gate_spawn, sizeof(r->gate_spawn), "none");
    (void)snprintf(r->head_observed, sizeof(r->head_observed), "none");
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
    mr_note_prior_turn(t, r);
    /* Source half of the diff identity, PINNED before the turn lands. An
     * anchor that could not be read can never be compared afterwards, so
     * the run stops here rather than judging an unanchored change set —
     * and it stops before a token is spent, for the same reason baseline
     * dirt does. */
    if (!mr_head_at(t->workspace, r->base, sizeof(r->base))) {
        (void)snprintf(r->reason, sizeof(r->reason),
            "HEAD unreadable before the turn: base %s", r->base);
        goto write;
    }
    /* The workspace must be measurably clean BEFORE the turn: baseline
     * dirt could otherwise satisfy the non-empty diff a pass requires.
     * No session, no turn, no tokens. */
    if (!mr_prestate_clean(c)) goto write;
    allow[0] = t->scope;
    policy.approval_mode = "denyUnmatched";
    policy.model = t->model[0] ? t->model : NULL;
    policy.allow_paths = allow;
    policy.allow_path_count = 1;
    if (!mr_submit(c, s, &policy)) goto write;
    mr_record_admission(t, r);
    memset(&out, 0, sizeof(out));
    if (muse_session_wait(s, r->session, r->turn, &policy, &out) != 0) {
        mr_wait_failed(c, s);
        goto write;
    }
    (void)snprintf(r->terminal, sizeof(r->terminal), "%s", out.terminal);
    r->input_tokens = out.input_tokens;
    r->output_tokens = out.output_tokens;
    r->total_tokens = out.total_tokens;
    r->duration_ms = out.duration_ms;
    muse_turn_outcome_free(&out);
    if (strcmp(r->terminal, "completed") != 0) {
        mr_settle_terminal(c);
        goto write;
    }
    rc = mr_judge(c, gate_log, sizeof(gate_log_stack), &engine_name,
        engine_buf, sizeof(engine_buf));
    r->wall_ms = (long long)(mr_monotonic_ms() - c->t0);
    goto write;
write:
    mr_report(c, s, engine_name, rc);
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

/* The machine headers the composer always emits. The queue: header is
 * accepted and ignored; model is optional and read separately. */
static bool mr_parse_headers(const char *text, struct muse_run_task *t,
    char *seq, size_t seqcap, char *attempt, size_t attcap)
{
    return mr_file_header(text, "seq", seq, seqcap) &&
        mr_file_header(text, "name", t->ref.name,
            sizeof(t->ref.name)) &&
        mr_file_header(text, "attempt", attempt, attcap) &&
        mr_file_header(text, "group", t->gate, sizeof(t->gate)) &&
        mr_file_header(text, "scope", t->scope, sizeof(t->scope)) &&
        mr_file_header(text, "worktree", t->workspace,
            sizeof(t->workspace)) &&
        mr_file_header(text, "rundir", t->rundir,
            sizeof(t->rundir));
}

/* The prompt body: everything past the titled brief marker's own line.
 * NULL with the reason named when the brief is absent or empty. */
static const char *mr_brief_body(const char *text, const char **why)
{
    const char *body = strstr(text, "=== BRIEF");
    if (!body) {
        *why = "task has no brief";
        return NULL;
    }
    body = strchr(body, '\n');
    if (!body) {
        *why = "task brief is empty";
        return NULL;
    }
    body++;
    while (*body == '\n' || *body == '\r') body++;
    if (!*body) {
        *why = "task brief is empty";
        return NULL;
    }
    return body;
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
    const char *why = NULL;
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
    if (!mr_parse_headers(text, t, seq, sizeof(seq), attempt,
            sizeof(attempt))) {
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
    body = mr_brief_body(text, &why);
    if (!body) {
        if (err)
            (void)snprintf(err, MUSE_RUN_ERROR_MAX, "%s", why);
        free(text);
        return -1;
    }
    *prompt = zcl_malloc(strlen(body) + 1, "muse_run.prompt");
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
