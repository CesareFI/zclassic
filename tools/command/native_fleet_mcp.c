/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: fleet.mcp — the thin remote-MCP adapter over the existing
 *          authenticated fleet mail, queue, board and receipt leaves.
 *
 * ── CONTRACT (this file is the whole implementation) ──────────────────────
 *
 * WHY. ChatGPT (or any remote MCP client) must steer the fleet without a
 * human relaying chat messages. This file is the smallest surface that
 * proves the connection: fleet.mcp.brief (one call: who is working on
 * what, blockers, capacity, candidates, evidence refs, changes since a
 * cursor) plus fleet.mcp.send (one bounded batch of directives to named
 * agents with per-item acceptance). fleet.mcp.evidence returns one
 * bounded object by exact reference, never a log; fleet.mcp.grant mints
 * and revokes the adapter's scoped bearer grants. No new scheduler, no
 * new ledger, no parallel workflow: composition only.
 *
 * HOW IT COMPOSES. Every fact comes from a sibling leaf called in-process
 * with the caller's context, exactly as the CLI would after input
 * validation: dev.agent.mail (post/pull/ack files), dev.agent.queue
 * (status), fleet.board.list/show (node RPC, fail-closed without a node),
 * fleet.ledger.status (local chains). Each sibling validates its own inputs
 * and enforces its own permissions; nothing here re-implements their
 * stores. A sibling that fails (no node, no delegation, empty state) is
 * reported in `missing[]` with its age — an unreachable source never reads
 * as an idle fleet.
 *
 * AUTHORIZATION. Two paths, never mixed:
 *   - Local operator: no `grant` key. Dispatch already gated on
 *     AUTH_OPERATOR (brief/send/evidence) or AUTH_OWNER (grant mint/revoke).
 *   - Remote bearer: a `grant` key naming one row in <state>/mcp/grants.jsonl
 *     minted by the operator. The row carries a scope subset of
 *     brief|send|evidence, created/expires unix times (expires 0 = never),
 *     a revoked flag and a label. Expired, revoked, unknown or
 *     insufficient-scope grants fail closed with MCP_GRANT_* — writes are
 *     never disguised as reads, and no credential is ever echoed back.
 * This adapter is NOT wallet authority (see agent_session for spend grants)
 * and NOT fleet key roles (see fleet.roles grant/revoke/check, which govern
 * fleet leaves by key fingerprint and need node delegation to mint). It
 * governs only fleet.mcp verbs; minting needs no delegation, only the
 * owner. Bearer ids are 128-bit CSPRNG hex via zcl_random_secret_bytes.
 *
 * IDEMPOTENCY. send items carry a caller-chosen idempotency_key. The first
 * accept appends the mail row and records key->seq in <state>/mcp/sent.jsonl;
 * a retry with the same key returns the recorded accept with duplicate:true
 * and appends nothing. Retries reconcile; they never duplicate work.
 *
 * STATES. queued (send accepted into the outbox), delivered (visible in
 * pull), acknowledged (seq at or below the receiver's mail ack cursor),
 * completed (a queue outcome names the ref with a pass-like verdict, or a
 * board result references it). Four different facts; absence of evidence is
 * reported as the earlier state, never skipped ahead.
 *
 * STATE. <platform_state_root()>/mcp (0700): grants.jsonl, sent.jsonl.
 * Single O_APPEND writes; revoke rewrites grants via tmp+rename like the
 * mail ack cursor. Nothing here blocks on a peer or a model.
 *
 * BOUNDS. brief changes[] default 25, max 100; agents/work/candidates 32;
 * blockers 16; body leads 160 chars; send at most 8 items, body at most
 * 2048 bytes each (under mail's own 4096 ceiling and refusal scanners,
 * which still apply). Mail bodies over-long or tripping refusal rules come
 * back per-item as refused, never as a crash.
 *
 * PROCESS RULE. No spawn, no shell, no popen()/system(), no sleep, no poll
 * loop. Only in-process sibling calls and local filesystem operations.
 */

#include "command/native_command.h"

#include "base/hex.h"
#include "base/safe_alloc.h"
#include "command/native_devagent.h"
#include "command/native_fleet.h"
#include "config/command_catalog.h"
#include "crypto/random_secret.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "platform/clock.h"
#include "platform/directory_compat.h"
#include "platform/private_directory.h"
#include "platform/state_root.h"
#include "platform/time_compat.h"
#include "util/log_macros.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

#define FMC_LEAF "fleet.mcp"
#define FMC_GRANT_LEAF "fleet.mcp.grant"
#define FMC_LOG "fleet.mcp"
#define FMC_DIR_MODE 0700

#define FMC_SEND_MAX 8u
#define FMC_BODY_MAX 2048u
#define FMC_KEY_MAX 128u
#define FMC_NAME_MAX 64u
#define FMC_REF_MAX 128u
#define FMC_LEAD_MAX 160u
#define FMC_LIST_CAP 32u
#define FMC_BLOCKER_CAP 16u
#define FMC_CHANGES_DEFAULT 25
#define FMC_CHANGES_MAX 100
#define FMC_LINE_CAP 8192
#define FMC_INPUT_CAP 65536
#define FMC_GRANT_TTL_MAX (30LL * 24 * 60 * 60)

/* ── failure (every error return logs context) ─────────────────────────── */

static void fmc_fail(struct zcl_command_reply *reply, const char *code,
                     const char *message, const char *evidence)
{
    LOG_ERROR(FMC_LOG, "%s: %s (%s)", code, message,
              evidence ? evidence : FMC_LEAF);
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                           ZCL_COMMAND_EXIT_FAILED, code, "execute", false,
                           false, message, evidence ? evidence : FMC_LEAF);
}

/* ── input getters ─────────────────────────────────────────────────────── */

static const char *fmc_str(const struct zcl_command_request *req,
                           const char *key)
{
    const struct json_value *v;
    if (!req || !req->input || !key)
        return NULL;
    v = json_get(req->input, key);
    if (!v || v->type != JSON_STR)
        return NULL;
    return json_get_str(v);
}

static bool fmc_int(const struct zcl_command_request *req, const char *key,
                    long long *out)
{
    const struct json_value *v;
    if (!req || !req->input || !key || !out)
        return false;
    v = json_get(req->input, key);
    if (!v)
        return false;
    if (v->type == JSON_INT) {
        *out = (long long)json_get_int(v);
        return true;
    }
    return false;
}

/* ── small string helpers (no locale, no allocation) ───────────────────── */

static bool fmc_is_token_char(char c)
{
    return isalnum((unsigned char)c) != 0 || c == '.' || c == '_' ||
           c == '-' || c == '*';
}

/* Caller tokens: agent names, idempotency keys, refs. Empty, over-long or
 * off-alphabet input is rejected so it can never become a filename or a
 * cursor path. `*` is allowed only when star_ok (broadcast recipients). */
static bool fmc_is_token(const char *s, size_t max, bool star_ok)
{
    size_t i;
    if (!s || s[0] == '\0' || strlen(s) > max)
        return false;
    for (i = 0; s[i]; i++) {
        if (s[i] == '*') {
            if (!star_ok)
                return false;
        } else if (!fmc_is_token_char(s[i])) {
            return false;
        }
    }
    return true;
}

/* JSON string escape into a bounded buffer. False when the budget runs out. */
static bool fmc_escape(const char *in, char *out, size_t cap)
{
    size_t o = 0;
    static const char *const hexd = "0123456789abcdef";
    if (!in || !out || cap == 0)
        return false;
    for (; *in; in++) {
        unsigned char c = (unsigned char)*in;
        if (c == '"' || c == '\\') {
            if (o + 2 >= cap)
                return false;
            out[o++] = '\\';
            out[o++] = (char)c;
        } else if (c == '\n') {
            if (o + 2 >= cap)
                return false;
            out[o++] = '\\';
            out[o++] = 'n';
        } else if (c < 0x20) {
            if (o + 6 >= cap)
                return false;
            out[o++] = '\\';
            out[o++] = 'u';
            out[o++] = '0';
            out[o++] = '0';
            out[o++] = hexd[(c >> 4) & 0xf];
            out[o++] = hexd[c & 0xf];
        } else {
            if (o + 1 >= cap)
                return false;
            out[o++] = (char)c;
        }
    }
    if (o >= cap)
        return false;
    out[o] = '\0';
    return true;
}

/* Lead: first FMC_LEAD_MAX bytes, cut at a newline, for change lists. The
 * full body is always one evidence call away; the brief never carries it. */
static void fmc_lead(const char *body, char *out, size_t cap)
{
    size_t i = 0;
    if (!body || !out || cap == 0)
        return;
    while (body[i] && i + 1 < cap && i < FMC_LEAD_MAX) {
        if (body[i] == '\n' || body[i] == '\r')
            break;
        out[i] = body[i];
        i++;
    }
    out[i] = '\0';
}

/* ── owner-private mcp dir ─────────────────────────────────────────────── */

static bool fmc_dirs(char *mcpdir, size_t cap)
{
    char root[4096];
    int n;
    if (!mcpdir || cap == 0)
        return false;
    if (!platform_state_root(root, sizeof(root)))
        return false;
    n = snprintf(mcpdir, cap, "%s/mcp", root);
    if (n <= 0 || (size_t)n >= cap)
        return false;
    if (!platform_private_directory_ensure(mcpdir))
        return false;
    return true;
}

static bool fmc_append_line(const char *path, const char *line, size_t len)
{
    int fd;
    ssize_t w;
    if (!path || !line || len == 0)
        return false;
    fd = open(path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
    if (fd < 0)
        return false;
    w = write(fd, line, len);
    (void)close(fd);
    return w == (ssize_t)len;
}

/* ── grant store ───────────────────────────────────────────────────────── */

struct fmc_grant {
    char id[33];
    char scopes[64];
    long long created;
    long long expires;
    int revoked;
};

/* True when the comma-token scope list names want as a whole token. */
static bool fmc_scope_has(const char *scopes, const char *want)
{
    size_t wn;
    const char *p;
    if (!scopes || !want || !want[0])
        return false;
    wn = strlen(want);
    for (p = scopes; *p;) {
        while (*p == ',' || *p == ' ')
            p++;
        if (*p == '\0')
            break;
        if (strncmp(p, want, wn) == 0 && (p[wn] == '\0' || p[wn] == ',' ||
                                          p[wn] == ' ')) {
            return true;
        }
        while (*p && *p != ',')
            p++;
    }
    return false;
}

static bool fmc_grant_line_str(const char *line, const char *key, char *out,
                               size_t cap)
{
    /* Minimal flat-JSON string/int extractor for our own grant rows.
     * Rows are machine-written by mint below, so "key":"value" and
     * "key":number shapes are exact; anything else fails closed. */
    char pat[64];
    const char *p, *q;
    size_t n;
    int r;
    if (!line || !key || !out || cap == 0)
        return false;
    r = snprintf(pat, sizeof(pat), "\"%s\":\"", key);
    if (r <= 0 || (size_t)r >= sizeof(pat))
        return false;
    p = strstr(line, pat);
    if (!p)
        return false;
    p += strlen(pat);
    q = strchr(p, '"');
    if (!q)
        return false;
    n = (size_t)(q - p);
    if (n == 0 || n >= cap)
        return false;
    memcpy(out, p, n);
    out[n] = '\0';
    return true;
}

static bool fmc_grant_line_int(const char *line, const char *key,
                               long long *out)
{
    char pat[64];
    const char *p;
    char *end = NULL;
    long long v;
    int r;
    if (!line || !key || !out)
        return false;
    r = snprintf(pat, sizeof(pat), "\"%s\":", key);
    if (r <= 0 || (size_t)r >= sizeof(pat))
        return false;
    p = strstr(line, pat);
    if (!p)
        return false;
    p += strlen(pat);
    if (*p == '"')
        return false;
    v = strtoll(p, &end, 10);
    if (end == p || v < 0)
        return false;
    *out = v;
    return true;
}

static bool fmc_grant_parse(const char *line, struct fmc_grant *g)
{
    char revoked[16];
    if (!line || !g)
        return false;
    memset(g, 0, sizeof(*g));
    if (!fmc_grant_line_str(line, "id", g->id, sizeof(g->id)))
        return false;
    if (!fmc_grant_line_str(line, "scopes", g->scopes, sizeof(g->scopes)))
        return false;
    if (!fmc_grant_line_int(line, "created", &g->created))
        return false;
    if (!fmc_grant_line_int(line, "expires", &g->expires))
        return false;
    g->revoked = 0;
    if (fmc_grant_line_str(line, "revoked", revoked, sizeof(revoked)))
        g->revoked = strcmp(revoked, "1") == 0 ? 1 : 0;
    if (strlen(g->id) != 32)
        return false;
    return true;
}

/* Find the LAST row naming id (later rows supersede). False when absent. */
static bool fmc_grant_find(const char *path, const char *id,
                           struct fmc_grant *out)
{
    FILE *f;
    char line[FMC_LINE_CAP];
    bool found = false;
    struct fmc_grant g;
    if (!path || !id || !out)
        return false;
    f = fopen(path, "rb");
    if (!f)
        return false;
    while (fgets(line, sizeof(line), f)) {
        if (!fmc_grant_parse(line, &g))
            continue;
        if (strcmp(g.id, id) == 0) {
            *out = g;
            found = true;
        }
    }
    (void)fclose(f);
    return found;
}

/* Validate a presented bearer for one verb scope. NULL/empty grant means
 * the local operator path, which dispatch already authorized. */
static const char *fmc_grant_check(const char *grant, const char *scope)
{
    char mcpdir[4096], path[4096 + 32];
    struct fmc_grant g;
    time_t now;
    int n;
    if (!grant || !grant[0])
        return NULL;
    if (!scope || !scope[0])
        return "MCP_GRANT_SCOPE";
    if (strlen(grant) != 32)
        return "MCP_GRANT_UNKNOWN";
    if (!fmc_dirs(mcpdir, sizeof(mcpdir)))
        return "MCP_GRANT_STORE";
    n = snprintf(path, sizeof(path), "%s/grants.jsonl", mcpdir);
    if (n <= 0 || (size_t)n >= sizeof(path))
        return "MCP_GRANT_STORE";
    if (!fmc_grant_find(path, grant, &g))
        return "MCP_GRANT_UNKNOWN";
    if (g.revoked)
        return "MCP_GRANT_REVOKED";
    now = platform_time_wall_time_t();
    if (g.expires != 0 && (long long)now >= g.expires)
        return "MCP_GRANT_EXPIRED";
    if (!fmc_scope_has(g.scopes, scope))
        return "MCP_GRANT_SCOPE";
    return NULL;
}

/* ── idempotency store ─────────────────────────────────────────────────── */

static bool fmc_sent_find(const char *path, const char *key, long long *seq)
{
    FILE *f;
    char line[FMC_LINE_CAP];
    long long s = -1;
    bool found = false;
    const char *p;
    char *end = NULL;
    if (!path || !key || !seq)
        return false;
    f = fopen(path, "rb");
    if (!f)
        return false;
    while (fgets(line, sizeof(line), f)) {
        char pat[256];
        int r = snprintf(pat, sizeof(pat), "\"key\":\"%s\"", key);
        if (r <= 0 || (size_t)r >= sizeof(pat))
            continue;
        if (!strstr(line, pat))
            continue;
        p = strstr(line, "\"seq\":");
        if (!p)
            continue;
        s = strtoll(p + 6, &end, 10);
        if (end == p + 6 || s < 0)
            continue;
        *seq = s;
        found = true;
    }
    (void)fclose(f);
    return found;
}

/* ── in-process sibling calls ────────────────────────────────────────────
 *
 * Each sibling validates its own input and enforces its own permissions.
 * A sibling that fails (no node, no delegation, empty state) is not an
 * error here: the caller records it in missing[] with its age. */

struct fmc_sub {
    struct json_value input;
    struct zcl_command_request request;
    struct zcl_command_reply reply;
    bool ran;
    /* False when the sibling path does not resolve: siblings (notably the
     * board list's projection helper) dereference request->spec, so a call
     * without one would crash instead of failing. Callers treat this as a
     * missing source, never as a dispatch. */
    bool valid;
};

static void fmc_sub_begin(struct fmc_sub *s, const char *schema,
                          const struct zcl_command_request *parent,
                          const char *sib_path)
{
    json_init(&s->input);
    json_set_object(&s->input);
    memset(&s->request, 0, sizeof(s->request));
    s->request.input = &s->input;
    if (parent)
        s->request.context = parent->context;
    /* Exactly what dispatch supplies: the sibling's own spec (projection
     * and paging read it) and a normal view. */
    s->request.spec =
        zcl_command_registry_find(zcl_command_catalog(), sib_path, NULL);
    s->request.view = "normal";
    zcl_command_reply_init(&s->reply, schema);
    s->ran = false;
    s->valid = s->request.spec != NULL;
}

static void fmc_sub_end(struct fmc_sub *s)
{
    zcl_command_reply_free(&s->reply);
    json_free(&s->input);
    s->ran = false;
}

/* Build the sub-input object from one JSON text. False when it does not
 * parse (caller fails closed with BAD_INPUT, never dispatches garbage). */
static bool fmc_sub_input(struct fmc_sub *s, const char *text)
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

static bool fmc_sub_ok(const struct fmc_sub *s)
{
    return s && s->ran && s->reply.status == ZCL_COMMAND_STATUS_PASSED;
}

static long long fmc_sub_int(const struct fmc_sub *s, const char *key,
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

/* Push one {source, reason} row onto missing[] and note the observation age
 * of the attempt in ms. Small and single-purpose for the complexity gate. */
static void fmc_note_missing(struct json_value *missing, const char *source,
                             const char *reason, long long age_ms)
{
    struct json_value item;
    json_init(&item);
    json_set_object(&item);
    if (json_push_kv_str(&item, "source", source) &&
        json_push_kv_str(&item, "reason", reason) &&
        json_push_kv_int(&item, "age_ms", age_ms))
        (void)json_push_back(missing, &item);
    json_free(&item);
}

/* Push one distinct string onto a capped array. Returns true when the value
 * is now represented (already present or appended). */
static bool fmc_push_distinct(struct json_value *arr, const char *s,
                              size_t cap)
{
    size_t n, i;
    struct json_value item;
    if (!arr || !s || !s[0])
        return false;
    n = json_size(arr);
    for (i = 0; i < n; i++) {
        const struct json_value *e = json_at(arr, i);
        const char *es;
        if (!e || e->type != JSON_STR)
            continue;
        es = json_get_str(e);
        if (es && strcmp(es, s) == 0)
            return true;
    }
    if (n >= cap)
        return true;
    json_init(&item);
    json_set_str(&item, s);
    (void)json_push_back(arr, &item);
    json_free(&item);
    return true;
}

/* Receiver ack cursor from the mail leaf's cursor.<agent> file. Sanitized
 * to the mail leaf's own alphabet so a `to` name can never escape the mail
 * dir. Returns -1 when the receiver never acked (nothing acknowledged). */
static long long fmc_ack_cursor(const char *agent)
{
    char root[4096], path[4096 + 64];
    char clean[FMC_NAME_MAX + 1];
    size_t i, o = 0;
    FILE *f;
    char buf[32];
    char *end = NULL;
    long long v;
    int n;
    if (!agent || !agent[0])
        return -1;
    for (i = 0; agent[i] && o < sizeof(clean) - 1; i++) {
        char c = agent[i];
        if (isalnum((unsigned char)c) || c == '.' || c == '_' || c == '-')
            clean[o++] = c;
    }
    clean[o] = '\0';
    if (clean[0] == '\0')
        return -1;
    if (!platform_state_root(root, sizeof(root)))
        return -1;
    n = snprintf(path, sizeof(path), "%s/mail/cursor.%s", root, clean);
    if (n <= 0 || (size_t)n >= sizeof(path))
        return -1;
    f = fopen(path, "rb");
    if (!f)
        return -1;
    buf[0] = '\0';
    (void)fgets(buf, sizeof(buf), f);
    (void)fclose(f);
    v = strtoll(buf, &end, 10);
    if (end == buf || v < 0)
        return -1;
    return v;
}

/* Pass-like queue verdicts. reap writes the receipt's own verdict string,
 * or "unknown"/"no-receipt" when none exists; only an explicit fail-like
 * word or a nonzero rc withholds completion. Documented heuristic: the
 * outcome row is always cited in evidence so the caller verifies. */
static bool fmc_verdict_pass(const char *verdict, long long rc)
{
    if (!verdict)
        return false;
    if (strcmp(verdict, "pass") == 0)
        return true;
    if (strcmp(verdict, "fail") == 0 || strcmp(verdict, "failed") == 0 ||
        strcmp(verdict, "error") == 0 || strcmp(verdict, "unknown") == 0 ||
        strcmp(verdict, "no-receipt") == 0)
        return false;
    if (strncmp(verdict, "no-", 3) == 0)
        return false;
    return rc == 0;
}

/* ── brief: mail section ─────────────────────────────────────────────────
 *
 * Pulls mail (since=0; filters locally so multi-inbox ambiguity never
 * refuses), collects agents, directives-as-work and bounded changes with
 * per-row lifecycle states. Returns the pull cursor, or -1 with a missing[]
 * note when the sibling failed. */

struct fmc_mail_view {
    long long cursor;
    long long count;
};

static long long fmc_brief_mail(const struct zcl_command_request *req,
                                struct json_value *agents,
                                struct json_value *work,
                                struct json_value *changes, long long since,
                                long long changes_cap,
                                struct json_value *missing,
                                struct fmc_mail_view *view)
{
    struct fmc_sub sub;
    const struct json_value *rows;
    size_t n, i;
    long long shown = 0;
    int64_t t0, t1;
    view->cursor = -1;
    view->count = 0;
    fmc_sub_begin(&sub, "zcl.agent_mail.v1", req, "dev.agent.mail");
    if (!sub.valid) {
        fmc_note_missing(missing, "dev.agent.mail", "unknown_sibling", 0);
        fmc_sub_end(&sub);
        return -1;
    }
    if (!fmc_sub_input(&sub, "{\"action\":\"pull\",\"since\":0}")) {
        fmc_note_missing(missing, "dev.agent.mail", "input_encode", 0);
        fmc_sub_end(&sub);
        return -1;
    }
    t0 = clock_now_wall_ms();
    zcl_native_handle_dev_agent_mail(&sub.request, &sub.reply);
    t1 = clock_now_wall_ms();
    sub.ran = true;
    if (!fmc_sub_ok(&sub)) {
        fmc_note_missing(missing, "dev.agent.mail", "sibling_refused",
                         t1 - t0);
        fmc_sub_end(&sub);
        return -1;
    }
    view->cursor = fmc_sub_int(&sub, "cursor", -1);
    view->count = fmc_sub_int(&sub, "count", 0);
    rows = json_get(&sub.reply.data, "rows");
    if (!rows || rows->type != JSON_ARR) {
        fmc_sub_end(&sub);
        return view->cursor;
    }
    n = json_size(rows);
    /* Newest-first walk from the tail: changes[] carries the latest rows
     * above `since`, each with its lifecycle state. */
    for (i = n; i > 0; i--) {
        const struct json_value *r = json_at(rows, i - 1);
        const struct json_value *v;
        const char *from, *to, *kind, *body, *ref;
        long long seq;
        struct json_value item;
        char lead[FMC_LEAD_MAX + 1];
        long long ack;
        const char *state;
        if (!r || r->type != JSON_OBJ)
            continue;
        v = json_get(r, "seq");
        if (!v || v->type != JSON_INT)
            continue;
        seq = (long long)json_get_int(v);
        v = json_get(r, "from");
        from = (v && v->type == JSON_STR) ? json_get_str(v) : "";
        v = json_get(r, "to");
        to = (v && v->type == JSON_STR) ? json_get_str(v) : "";
        v = json_get(r, "kind");
        kind = (v && v->type == JSON_STR) ? json_get_str(v) : "";
        v = json_get(r, "body");
        body = (v && v->type == JSON_STR) ? json_get_str(v) : "";
        v = json_get(r, "ref");
        ref = (v && v->type == JSON_STR) ? json_get_str(v) : "";
        if (from && from[0])
            (void)fmc_push_distinct(agents, from, FMC_LIST_CAP);
        if (to && to[0] && strcmp(to, "*") != 0)
            (void)fmc_push_distinct(agents, to, FMC_LIST_CAP);
        if (kind && strcmp(kind, "directive") == 0 && body && body[0]) {
            char w[128];
            int wlen = snprintf(w, sizeof(w), "directive %s->%s %.64s", from,
                                to, ref ? ref : "");
            if (wlen > 0 && (size_t)wlen < sizeof(w))
                (void)fmc_push_distinct(work, w, FMC_LIST_CAP);
        }
        if (seq <= since)
            continue;
        if (shown >= changes_cap)
            continue;
        /* delivered is established (the row is in pull); acknowledged iff
         * the receiver's cursor covers it; completed is resolved later
         * against queue outcomes and board results. */
        ack = fmc_ack_cursor(to);
        state = (ack >= 0 && seq <= ack) ? "acknowledged" : "delivered";
        json_init(&item);
        json_set_object(&item);
        fmc_lead(body, lead, sizeof(lead));
        if (json_push_kv_int(&item, "seq", seq) &&
            json_push_kv_str(&item, "from", from ? from : "") &&
            json_push_kv_str(&item, "to", to ? to : "") &&
            json_push_kv_str(&item, "kind", kind ? kind : "") &&
            json_push_kv_str(&item, "ref", ref ? ref : "") &&
            json_push_kv_str(&item, "lead", lead) &&
            json_push_kv_str(&item, "state", state))
            (void)json_push_back(changes, &item);
        json_free(&item);
        shown++;
    }
    fmc_sub_end(&sub);
    return view->cursor;
}

/* One queue row name into a capped list. Split out so the queue walker
 * stays under the complexity gate. */
static void fmc_queue_row_name(const struct json_value *r,
                               struct json_value *list)
{
    const struct json_value *v;
    const char *name;
    if (!r || r->type != JSON_OBJ || !list)
        return;
    v = json_get(r, "name");
    if (!v || v->type != JSON_STR)
        return;
    name = json_get_str(v);
    if (name && name[0])
        (void)fmc_push_distinct(list, name, FMC_LIST_CAP);
}

/* ── brief: queue section ────────────────────────────────────────────────
 *
 * Running/queued names become work + candidates; non-pass outcomes become
 * blockers; pool numbers become capacity. Completed-by-ref matching reads
 * the outcomes array for name==ref with a pass-like verdict. */

struct fmc_queue_view {
    long long queued;
    long long running;
    long long pool_total;
    long long pool_free;
};

static void fmc_brief_queue(const struct zcl_command_request *req,
                            struct json_value *work,
                            struct json_value *candidates,
                            struct json_value *blockers,
                            struct json_value *missing,
                            struct fmc_queue_view *view,
                            struct json_value *outcomes_keep)
{
    struct fmc_sub sub;
    const struct json_value *arr;
    size_t n, i;
    int64_t t0, t1;
    memset(view, 0, sizeof(*view));
    fmc_sub_begin(&sub, "zcl.agent_queue.v1", req, "dev.agent.queue");
    if (!sub.valid) {
        fmc_note_missing(missing, "dev.agent.queue", "unknown_sibling", 0);
        fmc_sub_end(&sub);
        return;
    }
    if (!fmc_sub_input(&sub,
                       "{\"action\":\"status\",\"json\":true}")) {
        fmc_note_missing(missing, "dev.agent.queue", "input_encode", 0);
        fmc_sub_end(&sub);
        return;
    }
    t0 = clock_now_wall_ms();
    zcl_native_handle_dev_agent_queue(&sub.request, &sub.reply);
    t1 = clock_now_wall_ms();
    sub.ran = true;
    if (!fmc_sub_ok(&sub)) {
        fmc_note_missing(missing, "dev.agent.queue", "sibling_refused",
                         t1 - t0);
        fmc_sub_end(&sub);
        return;
    }
    arr = json_get(&sub.reply.data, "queued");
    if (arr && arr->type == JSON_ARR) {
        n = json_size(arr);
        view->queued = (long long)n;
        for (i = 0; i < n; i++) {
            fmc_queue_row_name(json_at(arr, i), candidates);
            fmc_queue_row_name(json_at(arr, i), work);
        }
    }
    arr = json_get(&sub.reply.data, "running");
    if (arr && arr->type == JSON_ARR) {
        n = json_size(arr);
        view->running = (long long)n;
        for (i = 0; i < n; i++) {
            fmc_queue_row_name(json_at(arr, i), candidates);
            fmc_queue_row_name(json_at(arr, i), work);
        }
    }
    arr = json_get(&sub.reply.data, "outcomes");
    if (arr && arr->type == JSON_ARR) {
        /* Retained for completed-by-ref matching after the sub reply is
         * freed: copy the whole array, bounded by the sibling's own cap. */
        json_copy(outcomes_keep, arr);
        n = json_size(arr);
        for (i = 0; i < n && i < FMC_BLOCKER_CAP * 4; i++) {
            const struct json_value *r = json_at(arr, i);
            const struct json_value *v;
            const char *verdict, *name;
            long long rc;
            char b[160];
            int wlen;
            if (!r || r->type != JSON_OBJ)
                continue;
            v = json_get(r, "verdict");
            verdict = (v && v->type == JSON_STR) ? json_get_str(v) : "";
            v = json_get(r, "rc");
            rc = (v && v->type == JSON_INT) ? (long long)json_get_int(v)
                                            : -1;
            if (!verdict || fmc_verdict_pass(verdict, rc))
                continue;
            v = json_get(r, "name");
            name = (v && v->type == JSON_STR) ? json_get_str(v) : "?";
            wlen = snprintf(b, sizeof(b), "outcome %s %s rc=%lld",
                            name ? name : "?", verdict ? verdict : "?",
                            rc);
            if (wlen <= 0 || (size_t)wlen >= sizeof(b))
                continue;
            {
                struct json_value item;
                json_init(&item);
                json_set_str(&item, b);
                if (json_size(blockers) < FMC_BLOCKER_CAP)
                    (void)json_push_back(blockers, &item);
                json_free(&item);
            }
        }
    }
    {
        const struct json_value *pool = json_get(&sub.reply.data, "pool");
        const struct json_value *v;
        if (pool && pool->type == JSON_OBJ) {
            v = json_get(pool, "total");
            if (v && v->type == JSON_INT)
                view->pool_total = (long long)json_get_int(v);
            v = json_get(pool, "free");
            if (v && v->type == JSON_INT)
                view->pool_free = (long long)json_get_int(v);
        }
    }
    fmc_sub_end(&sub);
}

/* True when a retained queue outcome completes ref (name match, pass-like).
 * The matching outcome's evidence pointer (name/verdict) is returned for
 * the changes[] upgrade. */
static bool fmc_outcome_completes(const struct json_value *outcomes,
                                  const char *ref)
{
    size_t n, i;
    if (!outcomes || outcomes->type != JSON_ARR || !ref || !ref[0])
        return false;
    n = json_size(outcomes);
    for (i = 0; i < n; i++) {
        const struct json_value *r = json_at(outcomes, i);
        const struct json_value *v;
        const char *name, *verdict;
        long long rc;
        if (!r || r->type != JSON_OBJ)
            continue;
        v = json_get(r, "name");
        name = (v && v->type == JSON_STR) ? json_get_str(v) : NULL;
        if (!name || strcmp(name, ref) != 0)
            continue;
        v = json_get(r, "verdict");
        verdict = (v && v->type == JSON_STR) ? json_get_str(v) : "";
        v = json_get(r, "rc");
        rc = (v && v->type == JSON_INT) ? (long long)json_get_int(v) : -1;
        if (fmc_verdict_pass(verdict, rc))
            return true;
    }
    return false;
}

/* One board post's agent/kind/text/ref into the brief lists. Open problems
 * and needs are blockers; claims and results are candidates; every agent
 * name joins the roster. Bounded text only — the full post stays behind
 * fleet.board.show. */
static void fmc_board_post_lists(const struct json_value *post,
                                 struct json_value *agents,
                                 struct json_value *blockers,
                                 struct json_value *candidates)
{
    const struct json_value *v;
    const char *agent, *kind, *text, *ref;
    char b[192];
    int wlen;
    if (!post || post->type != JSON_OBJ)
        return;
    v = json_get(post, "agent");
    agent = (v && v->type == JSON_STR) ? json_get_str(v) : "";
    v = json_get(post, "kind");
    kind = (v && v->type == JSON_STR) ? json_get_str(v) : "";
    v = json_get(post, "text");
    text = (v && v->type == JSON_STR) ? json_get_str(v) : "";
    v = json_get(post, "ref");
    ref = (v && v->type == JSON_STR) ? json_get_str(v) : "";
    if (agent && agent[0])
        (void)fmc_push_distinct(agents, agent, FMC_LIST_CAP);
    if (!kind || !kind[0])
        return;
    if (strcmp(kind, "problem") == 0 || strcmp(kind, "need") == 0) {
        char lead[FMC_LEAD_MAX + 1];
        fmc_lead(text ? text : "", lead, sizeof(lead));
        wlen = snprintf(b, sizeof(b), "board %s %.96s %.64s", kind,
                        lead, ref ? ref : "");
        if (wlen > 0 && (size_t)wlen < sizeof(b)) {
            struct json_value item;
            json_init(&item);
            json_set_str(&item, b);
            if (json_size(blockers) < FMC_BLOCKER_CAP)
                (void)json_push_back(blockers, &item);
            json_free(&item);
        }
    } else if (strcmp(kind, "claim") == 0 || strcmp(kind, "result") == 0) {
        if (ref && ref[0])
            (void)fmc_push_distinct(candidates, ref, FMC_LIST_CAP);
    }
}

/* ── brief: board section ────────────────────────────────────────────────
 *
 * Open board posts via node RPC. No node (or an old binary) fails closed
 * inside the sibling; here that becomes a missing[] entry, never an empty
 * board masquerading as good news. */

static void fmc_brief_board(const struct zcl_command_request *req,
                            struct json_value *agents,
                            struct json_value *blockers,
                            struct json_value *candidates,
                            struct json_value *missing,
                            struct json_value *post_ids)
{
    struct fmc_sub sub;
    const struct json_value *posts;
    size_t n, i;
    int64_t t0, t1;
    fmc_sub_begin(&sub, "zcl.fleet_board_list.v1", req, "fleet.board.list");
    if (!sub.valid) {
        fmc_note_missing(missing, "fleet.board", "unknown_sibling", 0);
        fmc_sub_end(&sub);
        return;
    }
    if (!fmc_sub_input(&sub, "{\"open\":true,\"limit\":20}")) {
        fmc_note_missing(missing, "fleet.board", "input_encode", 0);
        fmc_sub_end(&sub);
        return;
    }
    t0 = clock_now_wall_ms();
    zcl_native_handle_fleet_board_list(&sub.request, &sub.reply);
    t1 = clock_now_wall_ms();
    sub.ran = true;
    if (!fmc_sub_ok(&sub)) {
        const char *code = "sibling_refused";
        if (sub.reply.error.code[0] &&
            strstr(sub.reply.error.code, "NODE_UNAVAILABLE"))
            code = "node_unavailable";
        else if (sub.reply.error.code[0] &&
                 strstr(sub.reply.error.code, "METHOD_NOT_FOUND"))
            code = "node_predates_board_rpc";
        fmc_note_missing(missing, "fleet.board", code, t1 - t0);
        fmc_sub_end(&sub);
        return;
    }
    posts = json_get(&sub.reply.data, "posts");
    if (!posts || posts->type != JSON_ARR) {
        fmc_sub_end(&sub);
        return;
    }
    n = json_size(posts);
    for (i = 0; i < n; i++) {
        const struct json_value *post = json_at(posts, i);
        const struct json_value *v;
        const char *id;
        fmc_board_post_lists(post, agents, blockers, candidates);
        if (!post || post->type != JSON_OBJ)
            continue;
        v = json_get(post, "id");
        id = (v && v->type == JSON_STR) ? json_get_str(v) : NULL;
        if (id && id[0])
            (void)fmc_push_distinct(post_ids, id, FMC_LIST_CAP);
    }
    fmc_sub_end(&sub);
}

/* ── brief: ledger section ───────────────────────────────────────────────
 *
 * Chain counts and replica staleness only — row contents never leave the
 * ledger leaf, and they do not leave through this one either. */

static void fmc_brief_ledger(const struct zcl_command_request *req,
                             struct json_value *missing,
                             long long *boxes, long long *rows)
{
    struct fmc_sub sub;
    int64_t t0, t1;
    *boxes = -1;
    *rows = -1;
    fmc_sub_begin(&sub, "zcl.fleet_ledger_status.v1", req, "fleet.ledger.status");
    if (!sub.valid) {
        fmc_note_missing(missing, "fleet.ledger", "unknown_sibling", 0);
        fmc_sub_end(&sub);
        return;
    }
    if (!fmc_sub_input(&sub, "{}")) {
        fmc_note_missing(missing, "fleet.ledger", "input_encode", 0);
        fmc_sub_end(&sub);
        return;
    }
    t0 = clock_now_wall_ms();
    zcl_native_handle_fleet_ledger_status(&sub.request, &sub.reply);
    t1 = clock_now_wall_ms();
    sub.ran = true;
    if (!fmc_sub_ok(&sub)) {
        fmc_note_missing(missing, "fleet.ledger", "sibling_refused",
                         t1 - t0);
        fmc_sub_end(&sub);
        return;
    }
    *boxes = fmc_sub_int(&sub, "boxes", -1);
    *rows = fmc_sub_int(&sub, "rows_loaded", -1);
    fmc_sub_end(&sub);
}

/* Replace a string member in place (json_push_kv appends, so an upgrade
 * must overwrite the existing slot or the old value stays visible). */
static void fmc_replace_str(struct json_value *obj, const char *key,
                            const char *s)
{
    size_t i;
    struct json_value nv;
    if (!obj || obj->type != JSON_OBJ || !key || !s)
        return;
    json_init(&nv);
    json_set_str(&nv, s);
    for (i = 0; i < obj->num_children; i++) {
        if (obj->keys[i] && strcmp(obj->keys[i], key) == 0) {
            json_free(&obj->children[i]);
            obj->children[i] = nv;
            return;
        }
    }
    (void)json_push_kv(obj, key, &nv);
    json_free(&nv);
}

/* Upgrade delivered change rows to completed when a retained queue outcome
 * completes their ref. Single-purpose loop for the complexity gate. */
static void fmc_apply_completed(struct json_value *changes,
                                const struct json_value *outcomes)
{
    size_t n, i;
    if (!changes || changes->type != JSON_ARR)
        return;
    n = json_size(changes);
    for (i = 0; i < n; i++) {
        struct json_value *item = (struct json_value *)json_at(changes, i);
        const struct json_value *v;
        const char *ref, *state;
        if (!item || item->type != JSON_OBJ)
            continue;
        v = json_get(item, "state");
        state = (v && v->type == JSON_STR) ? json_get_str(v) : "";
        if (!state || strcmp(state, "completed") == 0)
            continue;
        v = json_get(item, "ref");
        ref = (v && v->type == JSON_STR) ? json_get_str(v) : "";
        if (ref && ref[0] && fmc_outcome_completes(outcomes, ref))
            fmc_replace_str(item, "state", "completed");
    }
}

/* ── brief entry ───────────────────────────────────────────────────────── */

static void fmc_do_brief(const struct zcl_command_request *req,
                         struct zcl_command_reply *reply)
{
    struct json_value agents, work, blockers, candidates, changes, missing;
    struct json_value capacity, evidence, post_ids, outcomes;
    struct fmc_mail_view mv;
    struct fmc_queue_view qv;
    long long since = 0, changes_cap = FMC_CHANGES_DEFAULT;
    long long mail_cursor, boxes, rows;
    long long tmp;
    char ts[32];
    struct tm tm_utc;
    time_t now;
    json_init(&agents);
    json_set_array(&agents);
    json_init(&work);
    json_set_array(&work);
    json_init(&blockers);
    json_set_array(&blockers);
    json_init(&candidates);
    json_set_array(&candidates);
    json_init(&changes);
    json_set_array(&changes);
    json_init(&missing);
    json_set_array(&missing);
    json_init(&capacity);
    json_set_object(&capacity);
    json_init(&evidence);
    json_set_object(&evidence);
    json_init(&post_ids);
    json_set_array(&post_ids);
    json_init(&outcomes);
    json_set_array(&outcomes);
    if (fmc_int(req, "since", &tmp) && tmp >= 0)
        since = tmp;
    if (fmc_int(req, "limit", &tmp) && tmp > 0)
        changes_cap = tmp > FMC_CHANGES_MAX ? FMC_CHANGES_MAX : tmp;
    mail_cursor = fmc_brief_mail(req, &agents, &work, &changes, since,
                                 changes_cap, &missing, &mv);
    fmc_brief_queue(req, &work, &candidates, &blockers, &missing, &qv,
                    &outcomes);
    fmc_brief_board(req, &agents, &blockers, &candidates, &missing,
                    &post_ids);
    fmc_brief_ledger(req, &missing, &boxes, &rows);
    fmc_apply_completed(&changes, &outcomes);
    (void)json_push_kv_int(&capacity, "pool_total", qv.pool_total);
    (void)json_push_kv_int(&capacity, "pool_free", qv.pool_free);
    (void)json_push_kv_int(&capacity, "queued", qv.queued);
    (void)json_push_kv_int(&capacity, "running", qv.running);
    (void)json_push_kv_int(&evidence, "mail_cursor", mail_cursor);
    (void)json_push_kv_int(&evidence, "mail_count", mv.count);
    (void)json_push_kv_int(&evidence, "ledger_boxes", boxes);
    (void)json_push_kv_int(&evidence, "ledger_rows", rows);
    (void)json_push_kv(&evidence, "post_ids", &post_ids);
    now = platform_time_wall_time_t();
    if (platform_time_utc_tm(now, &tm_utc) &&
        strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%SZ", &tm_utc) != 0)
        (void)json_push_kv_str(&evidence, "observed_at", ts);
    (void)json_push_kv_str(&reply->data, "leaf", FMC_LEAF);
    (void)json_push_kv(&reply->data, "agents", &agents);
    (void)json_push_kv(&reply->data, "work", &work);
    (void)json_push_kv(&reply->data, "blockers", &blockers);
    (void)json_push_kv(&reply->data, "capacity", &capacity);
    (void)json_push_kv(&reply->data, "candidates", &candidates);
    (void)json_push_kv(&reply->data, "evidence", &evidence);
    (void)json_push_kv(&reply->data, "changes", &changes);
    (void)json_push_kv(&reply->data, "missing", &missing);
    (void)json_push_kv_int(&reply->data, "cursor", mail_cursor);
    reply->status = ZCL_COMMAND_STATUS_PASSED;
    reply->exit_code = 0;
    json_free(&agents);
    json_free(&work);
    json_free(&blockers);
    json_free(&candidates);
    json_free(&changes);
    json_free(&missing);
    json_free(&capacity);
    json_free(&evidence);
    json_free(&post_ids);
    json_free(&outcomes);
}

/* ── send ────────────────────────────────────────────────────────────────
 *
 * One bounded batch of directives to named agents. Each item carries a
 * caller idempotency key: the first accept posts one mail row and records
 * key->seq; a retry returns the recorded accept with duplicate:true and
 * posts nothing. Per-item outcomes; the batch fails outright only on bad
 * batch input or a bad grant. */

/* Post one directive through the mail sibling. Returns the accepted seq,
 * or -1 with `why` (caller buffer) naming the sibling's refusal. The code
 * is copied out before the sub reply is freed: it never points at it. */
static long long fmc_post_directive(const struct zcl_command_request *req,
                                    const char *to, const char *body,
                                    const char *ref, const char *from,
                                    char *why, size_t why_cap)
{
    struct fmc_sub sub;
    char input[FMC_INPUT_CAP];
    char eto[128], ebody[4096], eref[256], efrom[128];
    int n;
    long long seq;
    if (why && why_cap > 0)
        (void)snprintf(why, why_cap, "sibling_refused");
    if (!fmc_escape(to, eto, sizeof(eto)) ||
        !fmc_escape(body, ebody, sizeof(ebody)) ||
        !fmc_escape(ref ? ref : "", eref, sizeof(eref)))
        return -1;
    fmc_sub_begin(&sub, "zcl.agent_mail.v1", req, "dev.agent.mail");
    if (!sub.valid) {
        fmc_sub_end(&sub);
        return -1;
    }
    if (from && from[0]) {
        if (!fmc_escape(from, efrom, sizeof(efrom))) {
            fmc_sub_end(&sub);
            return -1;
        }
        n = snprintf(input, sizeof(input),
                     "{\"action\":\"post\",\"to\":\"%s\",\"kind\":\"directive\","
                     "\"body\":\"%s\",\"ref\":\"%s\",\"from\":\"%s\"}",
                     eto, ebody, eref, efrom);
    } else {
        n = snprintf(input, sizeof(input),
                     "{\"action\":\"post\",\"to\":\"%s\",\"kind\":\"directive\","
                     "\"body\":\"%s\",\"ref\":\"%s\"}",
                     eto, ebody, eref);
    }
    if (n <= 0 || (size_t)n >= sizeof(input)) {
        fmc_sub_end(&sub);
        return -1;
    }
    if (!fmc_sub_input(&sub, input)) {
        fmc_sub_end(&sub);
        return -1;
    }
    zcl_native_handle_dev_agent_mail(&sub.request, &sub.reply);
    sub.ran = true;
    if (!fmc_sub_ok(&sub)) {
        if (why && why_cap > 0) {
            if (sub.reply.error.code[0])
                (void)snprintf(why, why_cap, "%s",
                               sub.reply.error.code);
            else
                (void)snprintf(why, why_cap, "sibling_refused");
        }
        fmc_sub_end(&sub);
        return -1;
    }
    seq = fmc_sub_int(&sub, "seq", -1);
    fmc_sub_end(&sub);
    return seq;
}

/* One send item: validate, reconcile idempotency, post, record. Emits its
 * result object onto items[]. */
static void fmc_send_item(const struct zcl_command_request *req,
                          const struct json_value *it, size_t index,
                          const char *from, const char *sent_path,
                          struct json_value *items)
{
    struct json_value item;
    const struct json_value *v;
    const char *to, *body, *ref, *key;
    long long seq;
    char why[64];
    char sent_line[4096];
    int n;
    json_init(&item);
    json_set_object(&item);
    (void)json_push_kv_int(&item, "index", (long long)index);
    if (!it || it->type != JSON_OBJ) {
        (void)json_push_kv_str(&item, "state", "refused");
        (void)json_push_kv_str(&item, "error", "BAD_INPUT");
        (void)json_push_back(items, &item);
        json_free(&item);
        return;
    }
    v = json_get(it, "to");
    to = (v && v->type == JSON_STR) ? json_get_str(v) : NULL;
    v = json_get(it, "body");
    body = (v && v->type == JSON_STR) ? json_get_str(v) : NULL;
    v = json_get(it, "ref");
    ref = (v && v->type == JSON_STR) ? json_get_str(v) : "";
    v = json_get(it, "idempotency_key");
    key = (v && v->type == JSON_STR) ? json_get_str(v) : NULL;
    if (!to || !fmc_is_token(to, FMC_NAME_MAX, true) ||
        !body || body[0] == '\0' || strlen(body) > FMC_BODY_MAX || !key ||
        !fmc_is_token(key, FMC_KEY_MAX, false) || !ref ||
        strlen(ref) > FMC_REF_MAX ||
        (from && (strlen(from) > FMC_NAME_MAX ||
                  !fmc_is_token(from, FMC_NAME_MAX, false)))) {
        (void)json_push_kv_str(&item, "state", "refused");
        (void)json_push_kv_str(&item, "error", "BAD_INPUT");
        (void)json_push_kv_str(&item, "to", to ? to : "");
        (void)json_push_back(items, &item);
        json_free(&item);
        return;
    }
    (void)json_push_kv_str(&item, "to", to);
    if (fmc_sent_find(sent_path, key, &seq)) {
        /* Reconcile: same key, same accept, no second row. */
        (void)json_push_kv_str(&item, "state", "queued");
        (void)json_push_kv_int(&item, "seq", seq);
        (void)json_push_kv_bool(&item, "duplicate", true);
        (void)json_push_back(items, &item);
        json_free(&item);
        return;
    }
    why[0] = '\0';
    seq = fmc_post_directive(req, to, body, ref, from, why, sizeof(why));
    if (seq < 0) {
        (void)json_push_kv_str(&item, "state", "refused");
        (void)json_push_kv_str(&item, "error",
                               why[0] ? why : "POST_FAILED");
        (void)json_push_back(items, &item);
        json_free(&item);
        return;
    }
    n = snprintf(sent_line, sizeof(sent_line),
                 "{\"key\":\"%s\",\"to\":\"%s\",\"seq\":%lld,\"state\":"
                 "\"queued\"}\n",
                 key, to, seq);
    if (n > 0 && (size_t)n < sizeof(sent_line) &&
        fmc_append_line(sent_path, sent_line, (size_t)n)) {
        (void)json_push_kv_str(&item, "state", "queued");
        (void)json_push_kv_int(&item, "seq", seq);
        (void)json_push_kv_bool(&item, "duplicate", false);
    } else {
        /* The mail row exists but the receipt did not persist: report the
         * seq honestly and let the caller's retry reconcile by key on a
         * best-effort basis. Never claim a duplicate that is not one. */
        LOG_ERROR(FMC_LOG, "send: sent.jsonl append failed (to=%s seq=%lld)",
                  to, seq);
        (void)json_push_kv_str(&item, "state", "queued");
        (void)json_push_kv_int(&item, "seq", seq);
        (void)json_push_kv_bool(&item, "duplicate", false);
        (void)json_push_kv_str(&item, "warning", "SENT_RECORD_LOST");
    }
    (void)json_push_back(items, &item);
    json_free(&item);
}

static void fmc_do_send(const struct zcl_command_request *req,
                        struct zcl_command_reply *reply)
{
    const struct json_value *v;
    const struct json_value *arr;
    const char *from;
    char mcpdir[4096], sent_path[4096 + 32];
    struct json_value items;
    size_t n, i;
    int n2;
    v = json_get(req->input, "items");
    if (!v || v->type != JSON_ARR) {
        fmc_fail(reply, "BAD_INPUT", "send needs items[]",
                 "missing items array");
        return;
    }
    arr = v;
    n = json_size(arr);
    if (n == 0 || n > FMC_SEND_MAX) {
        fmc_fail(reply, "BAD_INPUT", "send takes 1..8 items",
                 "batch bound");
        return;
    }
    from = fmc_str(req, "from");
    if (!fmc_dirs(mcpdir, sizeof(mcpdir))) {
        fmc_fail(reply, "STATE_DIR_FAILED",
                 "cannot resolve the owner-private state root",
                 "platform_state_root");
        return;
    }
    n2 = snprintf(sent_path, sizeof(sent_path), "%s/sent.jsonl", mcpdir);
    if (n2 <= 0 || (size_t)n2 >= sizeof(sent_path)) {
        fmc_fail(reply, "STATE_DIR_FAILED", "sent path exceeds its bound",
                 mcpdir);
        return;
    }
    json_init(&items);
    json_set_array(&items);
    for (i = 0; i < n; i++)
        fmc_send_item(req, json_at(arr, i), i, from, sent_path, &items);
    (void)json_push_kv_str(&reply->data, "leaf", FMC_LEAF);
    (void)json_push_kv(&reply->data, "items", &items);
    (void)json_push_kv_int(&reply->data, "accepted",
                           (long long)json_size(&items));
    reply->status = ZCL_COMMAND_STATUS_PASSED;
    reply->exit_code = 0;
    json_free(&items);
}

/* ── evidence ────────────────────────────────────────────────────────────
 *
 * One bounded object by exact reference, never a log: a mail row with
 * ref==ref, a queue row/outcome with name==ref, or one board post by id. */

/* Copy one whole JSON value onto the reply under "object". The sources are
 * already bounded by their own leaves (mail bodies <= 4KiB, one post). */
static void fmc_emit_object(struct zcl_command_reply *reply,
                            const char *type, const struct json_value *obj)
{
    (void)json_push_kv_str(&reply->data, "leaf", FMC_LEAF);
    (void)json_push_kv_str(&reply->data, "type", type);
    (void)json_push_kv(&reply->data, "object", obj);
    reply->status = ZCL_COMMAND_STATUS_PASSED;
    reply->exit_code = 0;
}

static void fmc_evidence_mail(const struct zcl_command_request *req,
                              struct zcl_command_reply *reply,
                              const char *ref)
{
    struct fmc_sub sub;
    const struct json_value *rows;
    size_t n, i;
    fmc_sub_begin(&sub, "zcl.agent_mail.v1", req, "dev.agent.mail");
    if (!sub.valid) {
        fmc_fail(reply, "EVIDENCE_UNAVAILABLE", "the mail sibling is unknown", "dev.agent.mail");
        fmc_sub_end(&sub);
        return;
    }
    if (!fmc_sub_input(&sub, "{\"action\":\"pull\",\"since\":0}")) {
        fmc_fail(reply, "BAD_INPUT", "cannot encode the mail lookup",
                 "input_encode");
        fmc_sub_end(&sub);
        return;
    }
    zcl_native_handle_dev_agent_mail(&sub.request, &sub.reply);
    sub.ran = true;
    if (!fmc_sub_ok(&sub)) {
        fmc_fail(reply, "EVIDENCE_UNAVAILABLE",
                 "the mail store did not answer", "dev.agent.mail");
        fmc_sub_end(&sub);
        return;
    }
    rows = json_get(&sub.reply.data, "rows");
    if (rows && rows->type == JSON_ARR) {
        n = json_size(rows);
        for (i = 0; i < n; i++) {
            const struct json_value *r = json_at(rows, i);
            const struct json_value *v;
            const char *rref;
            if (!r || r->type != JSON_OBJ)
                continue;
            v = json_get(r, "ref");
            rref = (v && v->type == JSON_STR) ? json_get_str(v) : "";
            if (rref && strcmp(rref, ref) == 0) {
                fmc_emit_object(reply, "mail", r);
                fmc_sub_end(&sub);
                return;
            }
        }
    }
    fmc_fail(reply, "EVIDENCE_NOT_FOUND", "no mail row carries that ref",
             ref);
    fmc_sub_end(&sub);
}

static void fmc_evidence_queue(const struct zcl_command_request *req,
                               struct zcl_command_reply *reply,
                               const char *ref)
{
    struct fmc_sub sub;
    static const char *const sections[] = {"queued", "running", "outcomes"};
    size_t s;
    fmc_sub_begin(&sub, "zcl.agent_queue.v1", req, "dev.agent.queue");
    if (!sub.valid) {
        fmc_fail(reply, "EVIDENCE_UNAVAILABLE", "the queue sibling is unknown", "dev.agent.queue");
        fmc_sub_end(&sub);
        return;
    }
    if (!fmc_sub_input(&sub, "{\"action\":\"status\",\"json\":true}")) {
        fmc_fail(reply, "BAD_INPUT", "cannot encode the queue lookup",
                 "input_encode");
        fmc_sub_end(&sub);
        return;
    }
    zcl_native_handle_dev_agent_queue(&sub.request, &sub.reply);
    sub.ran = true;
    if (!fmc_sub_ok(&sub)) {
        fmc_fail(reply, "EVIDENCE_UNAVAILABLE",
                 "the queue did not answer", "dev.agent.queue");
        fmc_sub_end(&sub);
        return;
    }
    for (s = 0; s < sizeof(sections) / sizeof(sections[0]); s++) {
        const struct json_value *arr = json_get(&sub.reply.data,
                                                sections[s]);
        size_t n, i;
        if (!arr || arr->type != JSON_ARR)
            continue;
        n = json_size(arr);
        for (i = 0; i < n; i++) {
            const struct json_value *r = json_at(arr, i);
            const struct json_value *v;
            const char *name;
            if (!r || r->type != JSON_OBJ)
                continue;
            v = json_get(r, "name");
            name = (v && v->type == JSON_STR) ? json_get_str(v) : "";
            if (name && strcmp(name, ref) == 0) {
                fmc_emit_object(reply, "queue", r);
                fmc_sub_end(&sub);
                return;
            }
        }
    }
    fmc_fail(reply, "EVIDENCE_NOT_FOUND",
             "no queue row or outcome carries that name", ref);
    fmc_sub_end(&sub);
}

static void fmc_evidence_board(const struct zcl_command_request *req,
                               struct zcl_command_reply *reply,
                               const char *ref)
{
    struct fmc_sub sub;
    char input[512];
    char eref[256];
    int n;
    const struct json_value *post;
    if (!fmc_escape(ref, eref, sizeof(eref))) {
        fmc_fail(reply, "BAD_INPUT", "ref too large to encode",
                 "escape budget");
        return;
    }
    n = snprintf(input, sizeof(input), "{\"id\":\"%s\"}", eref);
    if (n <= 0 || (size_t)n >= sizeof(input)) {
        fmc_fail(reply, "BAD_INPUT", "ref too large to encode",
                 "input bound");
        return;
    }
    fmc_sub_begin(&sub, "zcl.fleet_board_post.v1", req, "fleet.board.show");
    if (!sub.valid) {
        fmc_fail(reply, "EVIDENCE_UNAVAILABLE", "the board sibling is unknown", "fleet.board.show");
        fmc_sub_end(&sub);
        return;
    }
    if (!fmc_sub_input(&sub, input)) {
        fmc_fail(reply, "BAD_INPUT", "cannot encode the board lookup",
                 "input_encode");
        fmc_sub_end(&sub);
        return;
    }
    zcl_native_handle_fleet_board_show(&sub.request, &sub.reply);
    sub.ran = true;
    if (!fmc_sub_ok(&sub)) {
        if (sub.reply.error.code[0] &&
            strstr(sub.reply.error.code, "NODE_UNAVAILABLE"))
            fmc_fail(reply, "EVIDENCE_UNAVAILABLE",
                     "no local node answered the board call",
                     "fleet.board.show");
        else
            fmc_fail(reply, "EVIDENCE_NOT_FOUND",
                     "this node holds no post with that id",
                     "fleet.board.show");
        fmc_sub_end(&sub);
        return;
    }
    post = json_get(&sub.reply.data, "post");
    if (!post || post->type != JSON_OBJ)
        post = &sub.reply.data;
    fmc_emit_object(reply, "board", post);
    fmc_sub_end(&sub);
}

static void fmc_do_evidence(const struct zcl_command_request *req,
                            struct zcl_command_reply *reply)
{
    const char *type;
    const char *ref;
    type = fmc_str(req, "type");
    ref = fmc_str(req, "ref");
    if (!type || !ref || !ref[0] || strlen(ref) > FMC_REF_MAX) {
        fmc_fail(reply, "BAD_INPUT", "evidence needs type and ref",
                 "type in {mail,queue,board}, ref exact");
        return;
    }
    if (strcmp(type, "mail") == 0)
        fmc_evidence_mail(req, reply, ref);
    else if (strcmp(type, "queue") == 0)
        fmc_evidence_queue(req, reply, ref);
    else if (strcmp(type, "board") == 0)
        fmc_evidence_board(req, reply, ref);
    else
        fmc_fail(reply, "BAD_INPUT", "unknown evidence type",
                 "type in {mail,queue,board}");
}

/* ── grants ──────────────────────────────────────────────────────────────
 *
 * Mint and revoke the adapter's own bearer grants. Mint draws 128 CSPRNG
 * bits per id and appends one row; revoke appends a superseding revoked
 * row (the store is append-only; the last row for an id wins). The id is
 * returned exactly once at mint and never echoed by any other verb. */

static bool fmc_scopes_valid(const char *scopes)
{
    /* Closed vocabulary, whole tokens only: brief, send, evidence. */
    const char *p;
    if (!scopes || !scopes[0] || strlen(scopes) >= 64)
        return false;
    for (p = scopes; *p;) {
        while (*p == ',' || *p == ' ')
            p++;
        if (*p == '\0')
            break;
        if (strncmp(p, "brief", 5) == 0 &&
            (p[5] == '\0' || p[5] == ',' || p[5] == ' ')) {
            p += 5;
            continue;
        }
        if (strncmp(p, "send", 4) == 0 &&
            (p[4] == '\0' || p[4] == ',' || p[4] == ' ')) {
            p += 4;
            continue;
        }
        if (strncmp(p, "evidence", 8) == 0 &&
            (p[8] == '\0' || p[8] == ',' || p[8] == ' ')) {
            p += 8;
            continue;
        }
        return false;
    }
    return true;
}

static void fmc_grant_mint(const struct zcl_command_request *req,
                           struct zcl_command_reply *reply)
{
    const char *scopes;
    const char *label;
    long long ttl = 0;
    long long tmp;
    time_t now;
    long long expires;
    uint8_t raw[16];
    char id[33];
    char mcpdir[4096], path[4096 + 32];
    char line[512];
    int n;
    scopes = fmc_str(req, "scopes");
    if (!scopes || !fmc_scopes_valid(scopes)) {
        fmc_fail(reply, "BAD_INPUT",
                 "scopes is a subset of brief,send,evidence",
                 "closed scope vocabulary");
        return;
    }
    if (fmc_int(req, "ttl_seconds", &tmp)) {
        if (tmp < 0 || tmp > FMC_GRANT_TTL_MAX) {
            fmc_fail(reply, "BAD_INPUT", "ttl_seconds is 0..2592000",
                     "grant lifetime bound");
            return;
        }
        ttl = tmp;
    }
    label = fmc_str(req, "label");
    if (label && (strlen(label) > FMC_NAME_MAX ||
                  !fmc_is_token(label, FMC_NAME_MAX, false))) {
        fmc_fail(reply, "BAD_INPUT", "label is a short token",
                 "label bound");
        return;
    }
    if (!zcl_random_secret_bytes(raw, sizeof(raw), "fleet.mcp.grant")) {
        fmc_fail(reply, "GRANT_MINT_FAILED",
                 "the CSPRNG did not yield grant material",
                 "zcl_random_secret_bytes");
        return;
    }
    zcl_hex_encode(raw, sizeof(raw), id);
    if (!fmc_dirs(mcpdir, sizeof(mcpdir))) {
        fmc_fail(reply, "STATE_DIR_FAILED",
                 "cannot resolve the owner-private state root",
                 "platform_state_root");
        return;
    }
    n = snprintf(path, sizeof(path), "%s/grants.jsonl", mcpdir);
    if (n <= 0 || (size_t)n >= sizeof(path)) {
        fmc_fail(reply, "STATE_DIR_FAILED", "grant path exceeds its bound",
                 mcpdir);
        return;
    }
    now = platform_time_wall_time_t();
    expires = ttl == 0 ? 0 : (long long)now + ttl;
    n = snprintf(line, sizeof(line),
                 "{\"id\":\"%s\",\"scopes\":\"%s\",\"created\":%lld,"
                 "\"expires\":%lld,\"revoked\":\"0\",\"label\":\"%s\"}\n",
                 id, scopes, (long long)now, expires,
                 label ? label : "");
    if (n <= 0 || (size_t)n >= sizeof(line)) {
        fmc_fail(reply, "GRANT_MINT_FAILED", "grant row exceeds its bound",
                 "row budget");
        return;
    }
    if (!fmc_append_line(path, line, (size_t)n)) {
        fmc_fail(reply, "GRANT_MINT_FAILED",
                 "cannot append the owner-private grant store", path);
        return;
    }
    (void)json_push_kv_str(&reply->data, "leaf", FMC_GRANT_LEAF);
    (void)json_push_kv_str(&reply->data, "id", id);
    (void)json_push_kv_str(&reply->data, "scopes", scopes);
    (void)json_push_kv_int(&reply->data, "expires", expires);
    reply->status = ZCL_COMMAND_STATUS_PASSED;
    reply->exit_code = 0;
}

static void fmc_grant_revoke(const struct zcl_command_request *req,
                             struct zcl_command_reply *reply)
{
    const char *id;
    char mcpdir[4096], path[4096 + 32];
    struct fmc_grant g;
    char line[512];
    time_t now;
    int n, m;
    id = fmc_str(req, "id");
    if (!id || strlen(id) != 32) {
        fmc_fail(reply, "BAD_INPUT", "revoke needs the 32-hex grant id",
                 "id bound");
        return;
    }
    if (!fmc_dirs(mcpdir, sizeof(mcpdir))) {
        fmc_fail(reply, "STATE_DIR_FAILED",
                 "cannot resolve the owner-private state root",
                 "platform_state_root");
        return;
    }
    n = snprintf(path, sizeof(path), "%s/grants.jsonl", mcpdir);
    if (n <= 0 || (size_t)n >= sizeof(path)) {
        fmc_fail(reply, "STATE_DIR_FAILED", "grant path exceeds its bound",
                 mcpdir);
        return;
    }
    /* Revoking an unknown id is refused, not silently accepted: the caller
     * must know which credential they just killed. */
    if (!fmc_grant_find(path, id, &g)) {
        fmc_fail(reply, "MCP_GRANT_UNKNOWN", "no grant carries that id",
                 "revoke exact id");
        return;
    }
    now = platform_time_wall_time_t();
    m = snprintf(line, sizeof(line),
                 "{\"id\":\"%s\",\"scopes\":\"%s\",\"created\":%lld,"
                 "\"expires\":%lld,\"revoked\":\"1\",\"label\":\"revoked\"}\n",
                 id, g.scopes, (long long)now, g.expires);
    if (m <= 0 || (size_t)m >= sizeof(line)) {
        fmc_fail(reply, "GRANT_MINT_FAILED", "grant row exceeds its bound",
                 "row budget");
        return;
    }
    if (!fmc_append_line(path, line, (size_t)m)) {
        fmc_fail(reply, "GRANT_MINT_FAILED",
                 "cannot append the owner-private grant store", path);
        return;
    }
    (void)json_push_kv_str(&reply->data, "leaf", FMC_GRANT_LEAF);
    (void)json_push_kv_str(&reply->data, "id", id);
    (void)json_push_kv_bool(&reply->data, "revoked", true);
    reply->status = ZCL_COMMAND_STATUS_PASSED;
    reply->exit_code = 0;
}

/* ── public entry points ─────────────────────────────────────────────────
 *
 * One thin wrapper per leaf: check the verb's grant scope, then run. The
 * grant key is optional; without one the call is the local operator's own,
 * which dispatch already authorized per leaf. */

static void fmc_enter(const struct zcl_command_request *request,
                      struct zcl_command_reply *reply, const char *scope,
                      const char *need,
                      void (*run)(const struct zcl_command_request *,
                                  struct zcl_command_reply *))
{
    const char *grant;
    const char *refused;
    if (!request || !request->input) {
        fmc_fail(reply, "BAD_INPUT", need, "request.input was missing");
        return;
    }
    grant = fmc_str(request, "grant");
    refused = fmc_grant_check(grant, scope);
    if (refused) {
        fmc_fail(reply, refused, "the grant does not allow this verb",
                 "grant scope/expiry/revocation");
        return;
    }
    run(request, reply);
}

void zcl_native_handle_fleet_mcp_brief(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    fmc_enter(request, reply, "brief", "fleet.mcp.brief takes grant,since,limit",
              fmc_do_brief);
}

void zcl_native_handle_fleet_mcp_send(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    fmc_enter(request, reply, "send", "fleet.mcp.send takes grant,items,from",
              fmc_do_send);
}

void zcl_native_handle_fleet_mcp_evidence(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    fmc_enter(request, reply, "evidence",
              "fleet.mcp.evidence takes grant,type,ref", fmc_do_evidence);
}

void zcl_native_handle_fleet_mcp_grant(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    const char *action;
    if (!request || !request->input) {
        fmc_fail(reply, "BAD_INPUT", "fleet.mcp.grant needs action",
                 "request.input was missing");
        return;
    }
    action = fmc_str(request, "action");
    if (!action) {
        fmc_fail(reply, "BAD_INPUT",
                 "fleet.mcp.grant needs action mint|revoke",
                 "missing action");
        return;
    }
    if (strcmp(action, "mint") == 0)
        fmc_grant_mint(request, reply);
    else if (strcmp(action, "revoke") == 0)
        fmc_grant_revoke(request, reply);
    else
        fmc_fail(reply, "BAD_INPUT", "unknown action (mint|revoke)",
                 "action");
}
