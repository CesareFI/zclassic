/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: dev.agent.receive — the resident RECEIVER loop that turns a
 *          directive arriving in this box's agent mail into real work
 *          without a human typing anything. It composes the EXISTING
 *          leaves only: dev.agent.mail carries directives in and answers
 *          out, dev.agent.queue is the one work ledger, fleet.steer's
 *          owner-minted grant store is the one permission system, and
 *          dev.agent.worker (a separate resident) executes and posts the
 *          result. This file adds no scheduler, no credential, no ledger
 *          and no executor.
 *
 * ── CONTRACT (this file is the whole implementation) ──────────────────────
 *
 * WHY. Cross-box work still needed a human to read a message and then run
 * a command. One beat of this loop closes that gap: intake, admission,
 * to-work, answer. The receiver never executes anything, so a long model
 * turn can never block intake, status, or delivery.
 *
 * ONE BEAT.
 *   1. INTAKE. dev.agent.mail is called in-process (the same shape
 *      fleet.steer uses) with action=pull, since=0, kind=directive. since
 *      is ALWAYS 0: a positive scalar cursor is refused outright once
 *      several .jsonl streams exist, because their sequence spaces are
 *      independent, so the filtering happens here instead. Pulled rows are
 *      never echoed into this leaf's own reply.
 *   2. ADMISSION, fail-closed, re-derived every beat so a revocation takes
 *      effect on the next one. A row is admitted only when ALL hold:
 *        - `to` names this receiver or is the broadcast "*";
 *        - `ref` is non-empty and matches [A-Za-z0-9_.-]{1,64}. An empty
 *          ref is invalid for coordinated work: one ref names one exact
 *          piece of work, and nothing can be reconciled or answered under
 *          a name that does not exist;
 *        - `from` is the label of a LIVE grant in <state>/steer/grants.jsonl
 *          carrying the "send" scope, read through the one shared helper
 *          zcl_fleet_steer_grant_label_live() so this file cannot drift
 *          from the store's own semantics;
 *        - the body parses as a well-formed Muse task direction (below).
 *      Anything else is refused with a typed reason and executes nothing.
 *   3. TO WORK. The directive body is written verbatim to
 *      <state>/receive/brief/<ref>.brief and posted through dev.agent.queue
 *      with name=<ref>, so the QUEUE ROW is the record. The queue requires
 *      `brief` to be an existing file for kind=doc|file, which is why the
 *      file is written first.
 *   4. IDEMPOTENCE AND CONFLICT, with no work ledger of its own. A ref is
 *      "known" when a queue row, a run directory, or an outcome names it.
 *      For a known ref the stored brief bytes decide: byte-identical body
 *      reconciles (nothing is queued again, nothing executes again, the
 *      existing state is re-answered); a different body is refused as a
 *      CONFLICT, because one ref names one exact piece of work.
 *   5. ANSWER. Only after the queue actually accepted the row (or an
 *      existing one was reconciled) does an accept row go back to the
 *      sender under the SAME ref, carrying the queue seq and the brief
 *      digest. An accept is never posted because bytes arrived. A refusal
 *      answers under the same ref too, with its reason.
 *   6. EXECUTION belongs to dev.agent.worker's own resident loop, which
 *      already gates the run and posts the result mail row under the same
 *      ref through the closed pass predicate. Nothing here reimplements
 *      execution, gating, receipts, retry, or the result mail.
 *
 * DIRECTION FORMAT. The Muse executor's machine header at the top of the
 * body, then a blank line, then the prompt:
 *
 *   muse-workspace: /abs/path/to/worktree     (absolute, existing dir)
 *   muse-scope: src/                          (repo-relative, no "..")
 *   muse-gate: group_name                     (a test group name)
 *   muse-model: model-id                      (optional)
 *   muse-kind: file|doc                       (optional, default file)
 *
 *   <prompt>
 *
 * A malformed direction is refused here, before any row is queued, so
 * nothing is ever spawned for it. muse-scope becomes the queue row's
 * `path` and muse-gate its `group`.
 *
 * SINGLE INSTANCE. <state>/receive/receive.lock (flock, non-blocking, held
 * for the whole drive), the same precedent as the worker's worker.lock. A
 * second drive refuses immediately with RECEIVE_BUSY and never waits.
 *
 * RESTART SAFETY. Nothing is remembered in memory between beats: every
 * decision is re-derived from files — the mail dir, the grant store, the
 * queue, the run dirs, the outcomes, and the stored brief. A crash between
 * the brief write and the queue post leaves a brief with no row, and the
 * next beat writes the identical brief and posts once. A crash between the
 * queue post and the answer leaves a known ref whose stored brief matches,
 * and the next beat reconciles and answers. Work is therefore executed at
 * most once per ref; an answer may be posted more than once if this process
 * dies mid-answer, which is the honest side to fail on.
 *
 * ANSWER MARKERS. <state>/receive/answered/<row digest> is a zero-length
 * marker meaning "this receiver has already answered this exact directive
 * row". It is de-duplication for MAIL only: it holds no work state, no
 * verdict and no lifecycle, and every idempotence/conflict decision above
 * is taken from the queue, the run dirs, the outcomes and the stored brief
 * rather than from it. It lives under the owner-private state root and not
 * in the mail dir precisely so that a peer able to write an inbox file
 * cannot forge one and suppress an answer.
 *
 * BOUNDED IDLE AND WAKE. The loop waits on <state>/mail through
 * platform_directory_watcher_open/_wait/_close, so a delivered inbox file
 * wakes it immediately, and a wait that times out beats anyway. There is no
 * busy poll, no sleep loop and no timer: the wait is the only place this
 * leaf blocks, and its ceiling is `wait_ms`. The mail directory is created
 * before the watch is armed so a box that has never had mail can still be
 * watched. A watcher that cannot be opened refuses the run, and a watch
 * lost mid-flight ends the drive: there is deliberately no fallback path,
 * because any fallback that returned without waiting would be a busy poll.
 *
 * SIGTERM. The handler sets one flag. The loop stops taking new work at the
 * next check, the watcher wait is interrupted within its 50 ms stop-sample
 * slice, and the drive returns after finishing the beat it is in. A ref's
 * record cannot be corrupted by that: the brief is installed by rename and
 * the queue row is the queue's own single append.
 *
 * WHAT THIS AUTHORITY DOES NOT PROVE — read this before trusting it.
 * An inbox.<peer>.jsonl row's provenance is its FILENAME plus whatever
 * transport wrote the file. Nothing in this tree signs or verifies a peer's
 * mail row today: roles.def's signed-peer ingress covers only
 * fleet.ledger.replicate and fleet.board.post, and
 * engine/composition/remote_command_classes.def is a classification that no
 * transport reads. So admission here means exactly "an owner-minted grant
 * names this sender", and NOT "this peer was cryptographically
 * authenticated". Anyone who can write a file into this box's mail
 * directory can claim any `from`. The narrowing that makes that bounded is
 * the grant store — the owner has to have minted a grant under that label
 * with the send scope — plus the queue's own path, name and brief
 * containment rules, plus the worker's gate. The future path is the signed
 * board ingress in roles.def: when a mail row carries a verified peer
 * signature, admission can bind the grant to a key fingerprint instead of a
 * name. Until then, do not describe this as authenticated delivery.
 *
 * PROCESS RULE. No spawn, no shell, no popen()/system(), no sleep, no busy
 * poll, no network. Only in-process sibling calls, local filesystem
 * operations, one flock, and one directory watcher wait. Execution is
 * dev.agent.worker's business and happens in its own resident process.
 */

#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif

#include "command/native_command.h"
#include "command/native_devagent.h"
#include "command/native_fleet.h"

#include "base/hex.h"
#include "config/command_catalog.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "platform/directory_watcher.h"
#include "platform/private_directory.h"
#include "platform/state_root.h"
#include "platform/time_compat.h"
#include "sha3/sha3.h"
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
#include <unistd.h>
#if !defined(_WIN32)
#include <signal.h>
#include <sys/file.h>
#endif

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

#define RCV_LEAF "dev.agent.receive"
#define RCV_LOG "dev.agent.receive"
#define RCV_LOCK_FILE "receive.lock"
#define RCV_SCOPE "send"
#define RCV_ROWS_MAX 128u
#define RCV_BODY_MAX 4097u
#define RCV_REF_MAX 64u
#define RCV_NAME_MAX 48u
#define RCV_INPUT_CAP 16384u

/* ── failure (every error return logs context) ─────────────────────────── */

static void rcv_fail(struct zcl_command_reply *reply, const char *code,
                     const char *phase, const char *msg, const char *evidence)
{
    LOG_ERROR(RCV_LOG, "%s: %s (%s)", code, msg,
              evidence ? evidence : RCV_LEAF);
    (void)json_push_kv_str(&reply->data, "leaf", RCV_LEAF);
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                           ZCL_COMMAND_EXIT_FAILED, code, phase, false,
                           false, msg, evidence ? evidence : RCV_LEAF);
}

/* ── input getters ─────────────────────────────────────────────────────── */

static const char *rcv_in_str(const struct zcl_command_request *req,
                              const char *key)
{
    const struct json_value *v;
    if (!req || !req->input || !key)
        return "";
    v = json_get(req->input, key);
    return (v && v->type == JSON_STR && json_get_str(v)) ? json_get_str(v)
                                                         : "";
}

static long long rcv_in_int(const struct zcl_command_request *req,
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
    return n > hi ? hi : n;
}

/* ── alphabets ─────────────────────────────────────────────────────────── */

/* The queue's own name alphabet, which is also the fleet ref alphabet:
 * [A-Za-z0-9_.-]{1,64}, never "." or "..". An empty ref never passes. */
static bool rcv_ref_ok(const char *s)
{
    size_t i, n;
    if (!s || !s[0])
        return false;
    n = strlen(s);
    if (n > RCV_REF_MAX)
        return false;
    if (strcmp(s, ".") == 0 || strcmp(s, "..") == 0)
        return false;
    for (i = 0; i < n; i++) {
        char c = s[i];
        if (!isalnum((unsigned char)c) && c != '.' && c != '_' && c != '-')
            return false;
    }
    return true;
}

/* A receiver or agent name: the mail leaf's cursor alphabet, bounded. */
static bool rcv_name_ok(const char *s)
{
    size_t i, n;
    if (!s || !s[0])
        return false;
    n = strlen(s);
    if (n > RCV_NAME_MAX)
        return false;
    for (i = 0; i < n; i++) {
        char c = s[i];
        if (!isalnum((unsigned char)c) && c != '.' && c != '_' && c != '-')
            return false;
    }
    return true;
}

/* A test group name, the queue's own group alphabet. */
static bool rcv_group_ok(const char *s)
{
    size_t i, n;
    if (!s || !s[0])
        return false;
    n = strlen(s);
    if (n >= 64)
        return false;
    for (i = 0; i < n; i++) {
        char c = s[i];
        if (!isalnum((unsigned char)c) && c != '_' && c != '-')
            return false;
    }
    return true;
}

/* A repo-relative scope: never absolute, never carrying a ".." segment. */
static bool rcv_scope_ok(const char *s)
{
    size_t i, n;
    if (!s || !s[0])
        return false;
    n = strlen(s);
    if (n >= 512 || s[0] == '/' || s[0] == '\\')
        return false;
    for (i = 0; i + 1 < n; i++) {
        if (s[i] != '.' || s[i + 1] != '.')
            continue;
        if (i == 0 || s[i - 1] == '/')
            return false;
    }
    return true;
}

/* ── one pulled directive row ──────────────────────────────────────────── */

/* String members borrow the sibling reply and are valid until the sub call
 * ends; nothing here outlives one beat. */
struct rcv_row {
    long long seq;
    const char *ts;
    const char *from;
    const char *to;
    const char *kind;
    const char *body;
    const char *ref;
};

/* ── digests ───────────────────────────────────────────────────────────── */

/* Row identity for the answer marker: FNV-1a/64 over
 * ts|seq|from|to|kind|ref|body with NUL separators, printed as 16 hex. The
 * stamp and sequence are IN the identity on purpose. Without them a
 * genuine retry — the sender asking again because the first answer never
 * reached it — would look like the row this receiver already answered and
 * would get silence. With them, re-reading one row every beat answers once
 * and a new row always gets an answer. An equality check for
 * de-duplication, never a security boundary: a forged row is refused by
 * admission, not by this digest. */
static void rcv_row_digest(const struct rcv_row *v, char out[17])
{
    uint64_t h = 1469598103934665603ULL;
    char seq[32];
    const char *parts[7];
    size_t i;
    (void)snprintf(seq, sizeof(seq), "%lld", v->seq);
    parts[0] = v->ts;
    parts[1] = seq;
    parts[2] = v->from;
    parts[3] = v->to;
    parts[4] = v->kind;
    parts[5] = v->ref;
    parts[6] = v->body;
    for (i = 0; i < 7; i++) {
        const unsigned char *p = (const unsigned char *)parts[i];
        while (*p) {
            h ^= (uint64_t)*p++;
            h *= 1099511628211ULL;
        }
        h ^= 0ULL;
        h *= 1099511628211ULL;
    }
    (void)snprintf(out, 17, "%016llx", (unsigned long long)h);
}

/* The brief digest carried in an accept: SHA3-256 of the exact body bytes,
 * so a sender can prove which text this box briefed. */
static void rcv_brief_digest(const char *body, char out[65])
{
    struct sha3_256_ctx ctx;
    unsigned char sum[SHA3_256_OUTPUT_SIZE];
    sha3_256_init(&ctx);
    sha3_256_write(&ctx, (const unsigned char *)(body ? body : ""),
                   body ? strlen(body) : 0u);
    sha3_256_finalize(&ctx, sum);
    zcl_hex_encode(sum, sizeof(sum), out);
}

/* ── state paths ───────────────────────────────────────────────────────── */

struct rcv_paths {
    char root[3072];      /* <state> */
    char dir[3200];       /* <state>/receive */
    char briefdir[3264];  /* <state>/receive/brief */
    char ansdir[3264];    /* <state>/receive/answered */
    char maildir[3200];   /* <state>/mail */
    char enginedir[3200]; /* <state>/engine */
    char outcomes[3264];  /* <state>/queue/outcomes.jsonl */
};

/* Resolve every path this leaf reads or writes. Creates nothing: the
 * writing paths call rcv_dirs_ensure() afterwards, and the read-only
 * status action deliberately never does. */
static bool rcv_paths_resolve(struct rcv_paths *p)
{
    if (!p)
        return false;
    memset(p, 0, sizeof(*p));
    if (!platform_state_root(p->root, sizeof(p->root)))
        return false;
    if (snprintf(p->dir, sizeof(p->dir), "%s/receive", p->root) <= 0)
        return false;
    if (snprintf(p->briefdir, sizeof(p->briefdir), "%s/brief", p->dir) <= 0)
        return false;
    if (snprintf(p->ansdir, sizeof(p->ansdir), "%s/answered", p->dir) <= 0)
        return false;
    if (snprintf(p->maildir, sizeof(p->maildir), "%s/mail", p->root) <= 0)
        return false;
    if (snprintf(p->enginedir, sizeof(p->enginedir), "%s/engine", p->root) <=
        0)
        return false;
    if (snprintf(p->outcomes, sizeof(p->outcomes), "%s/queue/outcomes.jsonl",
                 p->root) <= 0)
        return false;
    return true;
}

/* The mail directory is ensured here as well, with the same owner-only mode
 * the mail leaf uses: a watcher cannot be armed on a directory that does not
 * exist, and this loop refuses to run without a watcher rather than poll. */
static bool rcv_dirs_ensure(const struct rcv_paths *p)
{
    return platform_private_directory_ensure(p->dir) &&
           platform_private_directory_ensure(p->briefdir) &&
           platform_private_directory_ensure(p->ansdir) &&
           platform_private_directory_ensure(p->maildir);
}

static bool rcv_exists(const char *path)
{
    struct stat st;
    return path && path[0] && stat(path, &st) == 0;
}

static bool rcv_is_dir(const char *path)
{
    struct stat st;
    return path && path[0] && stat(path, &st) == 0 && S_ISDIR(st.st_mode);
}

/* Read a whole small file. False when absent, unreadable, or larger than
 * cap — a truncated brief must never compare equal to a body. */
static bool rcv_read_file(const char *path, char *out, size_t cap)
{
    FILE *f;
    size_t n;
    if (!path || !out || cap == 0)
        return false;
    out[0] = '\0';
    f = fopen(path, "rb");
    if (!f)
        return false;
    n = fread(out, 1, cap - 1, f);
    if (ferror(f) || !feof(f)) {
        (void)fclose(f);
        out[0] = '\0';
        return false;
    }
    out[n] = '\0';
    (void)fclose(f);
    return true;
}

/* Install small file contents by rename, so a crash never leaves a half
 * brief for the queue to hand an executor. */
static bool rcv_write_atomic(const char *path, const char *text, size_t len)
{
    char tmp[4096];
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
        (void)remove(tmp);
        return false;
    }
    if (fclose(f) != 0) {
        (void)remove(tmp);
        return false;
    }
    if (rename(tmp, path) != 0) {
        (void)remove(tmp);
        return false;
    }
    return true;
}

/* JSON string escape for the small sibling inputs this leaf builds. */
static bool rcv_escape(const char *in, char *out, size_t cap)
{
    size_t used = 0;
    if (!in || !out || cap == 0)
        return false;
    for (; *in; in++) {
        unsigned char c = (unsigned char)*in;
        const char *rep = NULL;
        char tmp[8];
        size_t n;
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
        if (!rep) {
            if (used + 1 >= cap)
                return false;
            out[used++] = (char)c;
            continue;
        }
        n = strlen(rep);
        if (used + n >= cap)
            return false;
        memcpy(out + used, rep, n);
        used += n;
    }
    if (used >= cap)
        return false;
    out[used] = '\0';
    return true;
}

/* ── in-process sibling calls (the shape fleet.steer uses) ─────────────── */

struct rcv_sub {
    struct json_value input;
    struct zcl_command_request request;
    struct zcl_command_reply reply;
    bool ran;
    bool valid;
};

static void rcv_sub_begin(struct rcv_sub *s, const char *schema,
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

static void rcv_sub_end(struct rcv_sub *s)
{
    zcl_command_reply_free(&s->reply);
    json_free(&s->input);
    s->ran = false;
}

static bool rcv_sub_input(struct rcv_sub *s, const char *text)
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

static bool rcv_sub_ok(const struct rcv_sub *s)
{
    return s && s->ran && s->reply.status == ZCL_COMMAND_STATUS_PASSED;
}

static long long rcv_sub_int(const struct rcv_sub *s, const char *key,
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

/* ── the Muse task direction ───────────────────────────────────────────── */

struct rcv_direction {
    char workspace[1024];
    char scope[512];
    char gate[64];
    char model[160];
    char kind[8];
    const char *prompt; /* borrows the pulled row's body */
    char why[48];       /* refusal detail: a bare token, never a path */
};

/* Copy one header value, trimming trailing blanks and a CR. */
static bool rcv_dir_value(const char *v, size_t len, char *out, size_t cap)
{
    while (len > 0 && (v[0] == ' ' || v[0] == '\t')) {
        v++;
        len--;
    }
    while (len > 0 && (v[len - 1] == ' ' || v[len - 1] == '\t' ||
                       v[len - 1] == '\r'))
        len--;
    if (len == 0 || len >= cap)
        return false;
    memcpy(out, v, len);
    out[len] = '\0';
    return true;
}

/* One "muse-<key>: <value>" header line. False (with d->why set) when the
 * line is not a known header in that exact shape. */
static bool rcv_dir_header(const char *line, size_t len,
                           struct rcv_direction *d)
{
    static const char pre[] = "muse-";
    const char *colon;
    size_t klen;
    if (len <= sizeof(pre) - 1 || memcmp(line, pre, sizeof(pre) - 1) != 0) {
        (void)snprintf(d->why, sizeof(d->why), "not-a-muse-header");
        return false;
    }
    colon = memchr(line, ':', len);
    if (!colon) {
        (void)snprintf(d->why, sizeof(d->why), "header-has-no-colon");
        return false;
    }
    klen = (size_t)(colon - line) - (sizeof(pre) - 1);
    {
        const char *k = line + sizeof(pre) - 1;
        const char *v = colon + 1;
        size_t vlen = len - (size_t)(v - line);
        struct {
            const char *name;
            char *out;
            size_t cap;
        } rows[] = {
            {"workspace", d->workspace, sizeof(d->workspace)},
            {"scope", d->scope, sizeof(d->scope)},
            {"gate", d->gate, sizeof(d->gate)},
            {"model", d->model, sizeof(d->model)},
            {"kind", d->kind, sizeof(d->kind)},
        };
        size_t i;
        for (i = 0; i < sizeof(rows) / sizeof(rows[0]); i++) {
            if (strlen(rows[i].name) != klen ||
                memcmp(k, rows[i].name, klen) != 0)
                continue;
            if (rcv_dir_value(v, vlen, rows[i].out, rows[i].cap))
                return true;
            (void)snprintf(d->why, sizeof(d->why), "empty-or-long-%s",
                           rows[i].name);
            return false;
        }
    }
    (void)snprintf(d->why, sizeof(d->why), "unknown-muse-header");
    return false;
}

/* The three required fields plus the two optional ones. */
static bool rcv_dir_fields_ok(struct rcv_direction *d)
{
    if (!d->workspace[0] || d->workspace[0] != '/' ||
        !rcv_is_dir(d->workspace)) {
        (void)snprintf(d->why, sizeof(d->why), "muse-workspace");
        return false;
    }
    if (!rcv_scope_ok(d->scope)) {
        (void)snprintf(d->why, sizeof(d->why), "muse-scope");
        return false;
    }
    if (!rcv_group_ok(d->gate)) {
        (void)snprintf(d->why, sizeof(d->why), "muse-gate");
        return false;
    }
    if (d->model[0] && strlen(d->model) > 128) {
        (void)snprintf(d->why, sizeof(d->why), "muse-model");
        return false;
    }
    if (!d->kind[0])
        (void)snprintf(d->kind, sizeof(d->kind), "file");
    if (strcmp(d->kind, "file") != 0 && strcmp(d->kind, "doc") != 0) {
        (void)snprintf(d->why, sizeof(d->why), "muse-kind");
        return false;
    }
    return true;
}

static const char *rcv_skip_blank(const char *p)
{
    while (*p == '\n' || *p == '\r' || *p == ' ' || *p == '\t')
        p++;
    return p;
}

/* Parse the machine header, the blank line, and the prompt. False (with
 * d->why naming the field) refuses the directive before anything is
 * written, queued, or spawned. */
static bool rcv_direction_parse(const char *body, struct rcv_direction *d)
{
    const char *p = body;
    if (!d)
        return false;
    memset(d, 0, sizeof(*d));
    (void)snprintf(d->why, sizeof(d->why), "empty-body");
    if (!body || !body[0])
        return false;
    for (;;) {
        const char *nl = strchr(p, '\n');
        size_t len = nl ? (size_t)(nl - p) : strlen(p);
        if (len > 0 && p[len - 1] == '\r')
            len--;
        if (len == 0) {
            p = nl ? nl + 1 : p + strlen(p);
            break;
        }
        if (!rcv_dir_header(p, len, d))
            return false;
        if (!nl) {
            (void)snprintf(d->why, sizeof(d->why), "no-prompt-after-header");
            return false;
        }
        p = nl + 1;
    }
    d->prompt = rcv_skip_blank(p);
    if (!d->prompt[0]) {
        (void)snprintf(d->why, sizeof(d->why), "no-prompt-after-header");
        return false;
    }
    return rcv_dir_fields_ok(d);
}

/* ── reading one pulled directive row ──────────────────────────────────── */

static const char *rcv_field(const struct json_value *r, const char *key)
{
    const struct json_value *v = json_get(r, key);
    if (!v || v->type != JSON_STR || !json_get_str(v))
        return "";
    return json_get_str(v);
}

static bool rcv_row_parse(const struct json_value *r, struct rcv_row *v)
{
    const struct json_value *s;
    if (!r || r->type != JSON_OBJ || !v)
        return false;
    s = json_get(r, "seq");
    if (!s || s->type != JSON_INT)
        return false;
    v->seq = (long long)json_get_int(s);
    v->ts = rcv_field(r, "ts");
    v->from = rcv_field(r, "from");
    v->to = rcv_field(r, "to");
    v->kind = rcv_field(r, "kind");
    v->body = rcv_field(r, "body");
    v->ref = rcv_field(r, "ref");
    return true;
}

/* ── known-ref derivation (the queue is the only work ledger) ──────────── */

struct rcv_known {
    bool known;
    long long seq;
    char stage[16]; /* queued | running | engine | outcome */
};

static void rcv_known_from_array(const struct json_value *arr, const char *ref,
                                 const char *stage, struct rcv_known *k)
{
    size_t n, i;
    if (k->known || !arr || arr->type != JSON_ARR)
        return;
    n = json_size(arr);
    for (i = 0; i < n; i++) {
        const struct json_value *r = json_at(arr, i);
        const struct json_value *v;
        if (!r || r->type != JSON_OBJ)
            continue;
        if (strcmp(rcv_field(r, "name"), ref) != 0)
            continue;
        k->known = true;
        (void)snprintf(k->stage, sizeof(k->stage), "%s", stage);
        v = json_get(r, "seq");
        k->seq = (v && v->type == JSON_INT) ? (long long)json_get_int(v) : -1;
        return;
    }
}

/* True when any outcome row names ref. Read straight from the queue's own
 * outcomes file because the status projection keeps only the newest rows. */
static bool rcv_outcome_names(const char *path, const char *ref)
{
    FILE *f;
    char line[8192];
    char pat[96];
    bool found = false;
    if (snprintf(pat, sizeof(pat), "\"name\":\"%s\"", ref) >= (int)sizeof(pat))
        return false;
    f = fopen(path, "rb");
    if (!f)
        return false;
    while (!found && fgets(line, sizeof(line), f))
        found = strstr(line, pat) != NULL;
    (void)fclose(f);
    return found;
}

/* ── the beat ──────────────────────────────────────────────────────────── */

struct rcv_ctx {
    struct rcv_paths p;
    char receiver[RCV_NAME_MAX + 1];
    bool dry; /* status: decide and count, write and post nothing */
    struct rcv_beat_stats *st;
};

/* Ask the queue whether it already holds this ref, then the run dirs, then
 * the outcomes. Every source is existing state; nothing is cached. */
static void rcv_ref_known(struct rcv_ctx *c, const char *ref,
                          struct rcv_known *k)
{
    struct rcv_sub sub;
    char dir[4096];
    memset(k, 0, sizeof(*k));
    k->seq = -1;
    rcv_sub_begin(&sub, "zcl.agent_queue.v1", "dev.agent.queue");
    if (sub.valid && rcv_sub_input(&sub, "{\"action\":\"status\","
                                         "\"json\":true}")) {
        zcl_native_handle_dev_agent_queue(&sub.request, &sub.reply);
        sub.ran = true;
        if (rcv_sub_ok(&sub)) {
            rcv_known_from_array(json_get(&sub.reply.data, "queued"), ref,
                                 "queued", k);
            rcv_known_from_array(json_get(&sub.reply.data, "running"), ref,
                                 "running", k);
        }
    }
    rcv_sub_end(&sub);
    if (k->known)
        return;
    if (snprintf(dir, sizeof(dir), "%s/%s", c->p.enginedir, ref) <
            (int)sizeof(dir) &&
        rcv_is_dir(dir)) {
        k->known = true;
        (void)snprintf(k->stage, sizeof(k->stage), "engine");
        return;
    }
    if (rcv_outcome_names(c->p.outcomes, ref)) {
        k->known = true;
        (void)snprintf(k->stage, sizeof(k->stage), "outcome");
    }
}

/* Post one answer row to the sender under the SAME ref. Flat scanner-safe
 * key=value lines with no path and no slash of any kind: the mail leaf
 * refuses a body carrying a filesystem path, and the brief lives outside
 * the checkout by design. Best-effort — the queue row is the record. */
static void rcv_answer(struct rcv_ctx *c, const struct rcv_row *v,
                       const char *kind, const char *body)
{
    struct rcv_sub sub;
    char ebody[8192], eref[256], eto[128];
    char input[RCV_INPUT_CAP];
    const char *to = (v->from && v->from[0]) ? v->from : "*";
    if (c->dry)
        return;
    if (!rcv_escape(body, ebody, sizeof(ebody)) ||
        !rcv_escape(rcv_ref_ok(v->ref) ? v->ref : "", eref, sizeof(eref)) ||
        !rcv_escape(to, eto, sizeof(eto)))
        return;
    if (snprintf(input, sizeof(input),
                 "{\"action\":\"post\",\"to\":\"%s\",\"kind\":\"%s\","
                 "\"body\":\"%s\",\"ref\":\"%s\",\"from\":\"%s\"}",
                 eto, kind, ebody, eref, c->receiver) >= (int)sizeof(input))
        return;
    rcv_sub_begin(&sub, "zcl.agent_mail.v1", "dev.agent.mail");
    if (sub.valid && rcv_sub_input(&sub, input)) {
        zcl_native_handle_dev_agent_mail(&sub.request, &sub.reply);
        sub.ran = true;
        if (!rcv_sub_ok(&sub))
            LOG_WARN(RCV_LOG, "answer refused by dev.agent.mail for ref %s",
                     rcv_ref_ok(v->ref) ? v->ref : "(invalid)");
    }
    rcv_sub_end(&sub);
}

static void rcv_answer_refuse(struct rcv_ctx *c, const struct rcv_row *v,
                              const char *src, const char *reason,
                              const char *detail)
{
    char body[1024];
    c->st->refused++;
    LOG_WARN(RCV_LOG, "refused directive src=%s: %s (%s)", src, reason,
             detail);
    if (snprintf(body, sizeof(body),
                 "receiver=%s\nstate=refused\nsrc=%s\nreason=%s\n"
                 "detail=%s\n",
                 c->receiver, src, reason, detail) >= (int)sizeof(body))
        return;
    rcv_answer(c, v, "problem", body);
}

static void rcv_answer_accept(struct rcv_ctx *c, const struct rcv_row *v,
                              const char *src, const struct rcv_direction *d,
                              long long seq, const char *stage)
{
    char body[1024];
    char sha[65];
    rcv_brief_digest(v->body, sha);
    if (snprintf(body, sizeof(body),
                 "receiver=%s\nstate=accepted\nsrc=%s\nqueue_seq=%lld\n"
                 "stage=%s\nkind=%s\ngate=%s\nbrief_sha3=%s\n",
                 c->receiver, src, seq, stage, d->kind, d->gate, sha) >=
        (int)sizeof(body))
        return;
    rcv_answer(c, v, "claim", body);
}

/* Post the brief through the EXISTING queue. Returns the accepted seq, or
 * -1 when the queue refused (its own name, path, group, brief containment
 * and model rules all still apply, unchanged). */
static long long rcv_queue_post(const char *ref, const struct rcv_direction *d,
                                const char *briefpath)
{
    struct rcv_sub sub;
    char ebrief[8192];
    char input[RCV_INPUT_CAP];
    long long seq = -1;
    if (!rcv_escape(briefpath, ebrief, sizeof(ebrief)))
        return -1;
    if (snprintf(input, sizeof(input),
                 "{\"action\":\"post\",\"kind\":\"%s\",\"name\":\"%s\","
                 "\"group\":\"%s\",\"path\":\"%s\",\"brief\":\"%s\","
                 "\"model\":\"%s\"}",
                 d->kind, ref, d->gate, d->scope, ebrief,
                 d->model[0] ? d->model : "") >= (int)sizeof(input))
        return -1;
    rcv_sub_begin(&sub, "zcl.agent_queue.v1", "dev.agent.queue");
    if (sub.valid && rcv_sub_input(&sub, input)) {
        zcl_native_handle_dev_agent_queue(&sub.request, &sub.reply);
        sub.ran = true;
        if (rcv_sub_ok(&sub))
            seq = rcv_sub_int(&sub, "seq", -1);
    }
    rcv_sub_end(&sub);
    return seq;
}

/* The ref is already known to the queue, a run dir, or an outcome. Exactly
 * two answers: the byte-identical body reconciles against the existing
 * record and queues nothing; a different body is a conflict and executes
 * nothing. */
static void rcv_reconcile(struct rcv_ctx *c, const struct rcv_row *v,
                          const char *src, const struct rcv_direction *d,
                          const struct rcv_known *k, const char *briefpath)
{
    char stored[RCV_BODY_MAX];
    if (!rcv_read_file(briefpath, stored, sizeof(stored))) {
        rcv_answer_refuse(c, v, src, "RECEIVE_REF_CONFLICT",
                          "ref-claimed-without-a-brief-from-this-receiver");
        return;
    }
    if (strcmp(stored, v->body) != 0) {
        rcv_answer_refuse(c, v, src, "RECEIVE_REF_CONFLICT",
                          "stored-brief-differs");
        return;
    }
    c->st->reconciled++;
    rcv_answer_accept(c, v, src, d, k->seq, k->stage);
}

/* Write the brief, post the queue row, then answer — in that order, so an
 * accept can never be posted before the queue actually holds the work. */
static void rcv_to_work(struct rcv_ctx *c, const struct rcv_row *v,
                        const char *src, const struct rcv_direction *d)
{
    char briefpath[4096];
    struct rcv_known k;
    long long seq;
    if (snprintf(briefpath, sizeof(briefpath), "%s/%s.brief", c->p.briefdir,
                 v->ref) >= (int)sizeof(briefpath)) {
        rcv_answer_refuse(c, v, src, "RECEIVE_STATE_UNWRITABLE",
                          "brief-path-too-long");
        return;
    }
    rcv_ref_known(c, v->ref, &k);
    if (k.known) {
        rcv_reconcile(c, v, src, d, &k, briefpath);
        return;
    }
    if (c->dry) {
        c->st->admitted++;
        return;
    }
    if (!rcv_write_atomic(briefpath, v->body, strlen(v->body))) {
        rcv_answer_refuse(c, v, src, "RECEIVE_STATE_UNWRITABLE",
                          "brief-store");
        return;
    }
    seq = rcv_queue_post(v->ref, d, briefpath);
    if (seq < 0) {
        rcv_answer_refuse(c, v, src, "RECEIVE_QUEUE_REFUSED",
                          "queue-post-refused");
        return;
    }
    c->st->admitted++;
    rcv_answer_accept(c, v, src, d, seq, "queued");
}

/* The three admission tests, in the order that refuses earliest. */
static void rcv_admit(struct rcv_ctx *c, const struct rcv_row *v,
                      const char *src)
{
    struct rcv_direction d;
    const char *why;
    if (!rcv_ref_ok(v->ref)) {
        rcv_answer_refuse(c, v, src, "RECEIVE_REF_INVALID",
                          "ref-must-match-64-name-alphabet");
        return;
    }
    why = zcl_fleet_steer_grant_label_live(v->from, RCV_SCOPE);
    if (why) {
        rcv_answer_refuse(c, v, src, "RECEIVE_SENDER_UNGRANTED", why);
        return;
    }
    if (!rcv_direction_parse(v->body, &d)) {
        rcv_answer_refuse(c, v, src, "RECEIVE_DIRECTION_MALFORMED", d.why);
        return;
    }
    rcv_to_work(c, v, src, &d);
}

/* Has this receiver already answered this exact row? */
static bool rcv_answered(const struct rcv_ctx *c, const char *src, char *path,
                         size_t cap)
{
    if (snprintf(path, cap, "%s/%s", c->p.ansdir, src) >= (int)cap)
        return true; /* cannot be recorded, so never answer it twice */
    return rcv_exists(path);
}

static void rcv_row_handle(struct rcv_ctx *c, const struct json_value *r)
{
    struct rcv_row v;
    char src[17];
    char marker[4096];
    if (!rcv_row_parse(r, &v))
        return;
    if (strcmp(v.to, c->receiver) != 0 && strcmp(v.to, "*") != 0)
        return;
    c->st->seen++;
    rcv_row_digest(&v, src);
    if (rcv_answered(c, src, marker, sizeof(marker))) {
        c->st->already++;
        return;
    }
    rcv_admit(c, &v, src);
    /* The marker is written AFTER the answer: a crash in between costs one
     * duplicate answer on the next beat, never a duplicate queue row. */
    if (!c->dry)
        (void)rcv_write_atomic(marker, "", 0);
}

/* One beat: pull, then decide each row from files alone. */
static void rcv_beat(struct rcv_ctx *c)
{
    struct rcv_sub sub;
    const struct json_value *rows;
    size_t n, i;
    c->st->beats++;
    if (c->dry && !rcv_is_dir(c->p.maildir))
        return;
    rcv_sub_begin(&sub, "zcl.agent_mail.v1", "dev.agent.mail");
    /* since is ALWAYS 0: a positive scalar cursor is refused once several
     * .jsonl streams exist, because their sequence spaces are independent. */
    if (sub.valid && rcv_sub_input(&sub, "{\"action\":\"pull\",\"since\":0,"
                                         "\"kind\":\"directive\"}")) {
        zcl_native_handle_dev_agent_mail(&sub.request, &sub.reply);
        sub.ran = true;
    }
    if (!rcv_sub_ok(&sub)) {
        rcv_sub_end(&sub);
        c->st->intake_failed++;
        return;
    }
    rows = json_get(&sub.reply.data, "rows");
    n = (rows && rows->type == JSON_ARR) ? json_size(rows) : 0u;
    for (i = 0; i < n && i < RCV_ROWS_MAX; i++)
        rcv_row_handle(c, json_at(rows, i));
    rcv_sub_end(&sub);
}

/* ── the resident drive ────────────────────────────────────────────────── */

#if !defined(_WIN32)

/* SIGTERM asks for shutdown. The flag is checked between beats and sampled
 * by the watcher wait, so a stop is honoured within one wait slice. */
static volatile sig_atomic_t g_rcv_term;

static void rcv_on_term(int sig)
{
    (void)sig;
    g_rcv_term = 1;
}

static bool rcv_stop(void *opaque)
{
    (void)opaque;
    return g_rcv_term != 0;
}

static int rcv_lock_acquire(const char *path)
{
    int fd = open(path, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
    if (fd < 0)
        return -1;
    if (flock(fd, LOCK_EX | LOCK_NB) != 0) {
        (void)close(fd);
        return -1;
    }
    return fd;
}

/* True when the loop should keep going. */
static bool rcv_loop_live(const struct rcv_drive_opts *opts,
                          const struct rcv_beat_stats *st, long long t0)
{
    if (g_rcv_term)
        return false;
    if (opts->max_beats > 0 && st->beats >= opts->max_beats)
        return false;
    return platform_time_wall_unix() - t0 < opts->deadline_s;
}

/* Wait for new mail. Returns false when the wait says stop. A watcher that
 * was never opened, or that errors, still returns true: the caller beats
 * again on the bounded ceiling rather than stalling. */
/* The one place this loop blocks. It parks in the directory-watcher wait for
 * at most wait_ms; a delivered inbox file wakes it early, a quiet window
 * times out and beats anyway. There is no fallback that returns without
 * waiting, because that fallback would be a busy poll. */
static bool rcv_wait(struct platform_directory_watcher *w,
                     uint32_t wait_ms, bool *watch_lost)
{
    enum platform_directory_watch_result r;
    r = platform_directory_watcher_wait(w, wait_ms, rcv_stop, NULL);
    if (r == PLATFORM_DIRECTORY_WATCH_STOPPED)
        return false;
    if (r == PLATFORM_DIRECTORY_WATCH_ERROR)
        *watch_lost = true;
    return !g_rcv_term;
}

static long long rcv_drive_posix(const struct rcv_drive_opts *opts,
                                 struct rcv_beat_stats *st)
{
    struct rcv_ctx c;
    struct platform_directory_watcher watcher;
    char lockpath[4096];
    void (*old_term)(int) = SIG_DFL;
    bool watch_lost = false;
    int lockfd;
    long long t0;
    memset(&c, 0, sizeof(c));
    if (!rcv_paths_resolve(&c.p) || !rcv_dirs_ensure(&c.p))
        return -1;
    if (snprintf(lockpath, sizeof(lockpath), "%s/%s", c.p.dir,
                 RCV_LOCK_FILE) >= (int)sizeof(lockpath))
        return -1;
    lockfd = rcv_lock_acquire(lockpath);
    if (lockfd < 0)
        return -1;
    (void)snprintf(c.receiver, sizeof(c.receiver), "%s", opts->receiver);
    c.st = st;
    g_rcv_term = 0;
    old_term = signal(SIGTERM, rcv_on_term);
    t0 = platform_time_wall_unix();
    /* The watcher is armed before the first beat, so a directive that lands
     * while that beat runs still wakes the next wait instead of being missed
     * until the ceiling expires. */
    platform_directory_watcher_init(&watcher);
    if (!platform_directory_watcher_open(&watcher, c.p.maildir)) {
        LOG_WARN(RCV_LOG, "cannot watch the mail dir; refusing to run rather "
                          "than poll for mail");
        (void)signal(SIGTERM, old_term);
        (void)flock(lockfd, LOCK_UN);
        (void)close(lockfd);
        return -2;
    }
    rcv_beat(&c);
    while (rcv_loop_live(opts, st, t0)) {
        if (!rcv_wait(&watcher, (uint32_t)opts->wait_ms, &watch_lost))
            break;
        if (watch_lost) {
            /* Losing the watch removes the only bounded wait this loop has,
             * so the drive ends here with every ref's record intact; the
             * service unit's Restart=on-failure brings it back. */
            LOG_WARN(RCV_LOG, "mail watch lost; ending this drive cleanly");
            break;
        }
        if (!rcv_loop_live(opts, st, t0))
            break;
        rcv_beat(&c);
    }
    platform_directory_watcher_close(&watcher);
    (void)signal(SIGTERM, old_term);
    (void)flock(lockfd, LOCK_UN);
    (void)close(lockfd);
    return st->beats;
}

/* Lock state without creating anything: O_RDONLY and no O_CREAT, so the
 * read-only status action never brings the lock file into existence. */
static const char *rcv_lock_state(const struct rcv_paths *p)
{
    char path[4096];
    const char *state;
    int fd;
    if (snprintf(path, sizeof(path), "%s/%s", p->dir, RCV_LOCK_FILE) >=
        (int)sizeof(path))
        return "unknown";
    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return "never-run";
    state = flock(fd, LOCK_EX | LOCK_NB) == 0 ? "free" : "held";
    if (strcmp(state, "free") == 0)
        (void)flock(fd, LOCK_UN);
    (void)close(fd);
    return state;
}

#else /* _WIN32 */

static long long rcv_drive_posix(const struct rcv_drive_opts *opts,
                                 struct rcv_beat_stats *st)
{
    (void)opts;
    (void)st;
    return -1;
}

static const char *rcv_lock_state(const struct rcv_paths *p)
{
    (void)p;
    return "unavailable";
}

#endif /* _WIN32 */

/* ONE definition of the public entry point, above the platform split: the
 * arms differ only in how the singleton and the watch are held, and two
 * non-static bodies for one name is what check-arm-symbol-single refuses. */
long long zcl_devagent_receive_drive(const struct rcv_drive_opts *opts,
                                     struct rcv_beat_stats *st)
{
    struct rcv_beat_stats local;
    if (!opts || !rcv_name_ok(opts->receiver))
        return -1;
    if (!st) {
        memset(&local, 0, sizeof(local));
        st = &local;
    }
    return rcv_drive_posix(opts, st);
}

/* ── status: facts only, writes nothing ────────────────────────────────── */

long long zcl_devagent_receive_survey(const char *receiver,
                                      struct rcv_beat_stats *st)
{
    struct rcv_ctx c;
    memset(&c, 0, sizeof(c));
    if (!receiver || !rcv_name_ok(receiver) || !st)
        return -1;
    memset(st, 0, sizeof(*st));
    if (!rcv_paths_resolve(&c.p))
        return -1;
    (void)snprintf(c.receiver, sizeof(c.receiver), "%s", receiver);
    c.dry = true;
    c.st = st;
    rcv_beat(&c);
    return st->beats;
}

/* ── leaf ──────────────────────────────────────────────────────────────── */

static void rcv_push_stats(struct zcl_command_reply *reply,
                           const struct rcv_beat_stats *st)
{
    (void)json_push_kv_int(&reply->data, "beats", st->beats);
    (void)json_push_kv_int(&reply->data, "seen", st->seen);
    (void)json_push_kv_int(&reply->data, "admitted", st->admitted);
    (void)json_push_kv_int(&reply->data, "reconciled", st->reconciled);
    (void)json_push_kv_int(&reply->data, "refused", st->refused);
    (void)json_push_kv_int(&reply->data, "already_answered", st->already);
    (void)json_push_kv_int(&reply->data, "intake_failed", st->intake_failed);
}

static void rcv_status(const char *receiver, struct zcl_command_reply *reply)
{
    struct rcv_beat_stats st;
    struct rcv_paths p;
    if (!rcv_paths_resolve(&p)) {
        rcv_fail(reply, "STATE_DIR_FAILED", "status",
                 "cannot resolve the owner-private state root",
                 "platform_state_root");
        return;
    }
    if (zcl_devagent_receive_survey(receiver, &st) < 0) {
        rcv_fail(reply, "RECEIVE_SURVEY_FAILED", "status",
                 "cannot survey the receiver state", p.dir);
        return;
    }
    (void)json_push_kv_str(&reply->data, "leaf", RCV_LEAF);
    (void)json_push_kv_str(&reply->data, "state", "surveyed");
    (void)json_push_kv_str(&reply->data, "receiver", receiver);
    (void)json_push_kv_str(&reply->data, "lock", rcv_lock_state(&p));
    (void)json_push_kv_str(&reply->data, "mail",
                           rcv_is_dir(p.maildir) ? "present" : "absent");
    (void)json_push_kv_str(&reply->data, "scope", RCV_SCOPE);
    rcv_push_stats(reply, &st);
    reply->status = ZCL_COMMAND_STATUS_PASSED;
    reply->exit_code = 0;
}

static void rcv_run(const struct zcl_command_request *request,
                    const char *receiver, struct zcl_command_reply *reply)
{
    struct rcv_drive_opts opts;
    struct rcv_beat_stats st;
    long long beats;
    memset(&opts, 0, sizeof(opts));
    memset(&st, 0, sizeof(st));
    (void)snprintf(opts.receiver, sizeof(opts.receiver), "%s", receiver);
    opts.deadline_s = rcv_in_int(request, "deadline_s", 300, 1, 86400);
    opts.wait_ms = rcv_in_int(request, "wait_ms", 1000, 50, 60000);
    opts.max_beats = rcv_in_int(request, "max_beats", 0, 0, 1000000);
    beats = zcl_devagent_receive_drive(&opts, &st);
    if (beats == -2) {
        rcv_fail(reply, "RECEIVE_WATCH_UNAVAILABLE", "run",
                 "this box cannot watch its mail directory, and this loop "
                 "waits on that watch instead of polling",
                 "platform_directory_watcher_open refused the mail dir");
        return;
    }
    if (beats < 0) {
        rcv_fail(reply, "RECEIVE_BUSY", "run",
                 "another receiver holds this loop, or the state root refuses",
                 "receive.lock exclusive");
        return;
    }
    (void)json_push_kv_str(&reply->data, "leaf", RCV_LEAF);
    (void)json_push_kv_str(&reply->data, "state", "done");
    (void)json_push_kv_str(&reply->data, "receiver", opts.receiver);
    rcv_push_stats(reply, &st);
    reply->status = ZCL_COMMAND_STATUS_PASSED;
    reply->exit_code = 0;
}

void zcl_native_handle_dev_agent_receive(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    const char *action, *receiver;
    if (!reply)
        return;
    if (!request || !request->input) {
        rcv_fail(reply, "BAD_INPUT", "run",
                 "dev.agent.receive needs an action and a receiver identity",
                 "request.input was missing");
        return;
    }
    action = rcv_in_str(request, "action");
    receiver = rcv_in_str(request, "receiver");
    if (!rcv_name_ok(receiver)) {
        rcv_fail(reply, "BAD_INPUT", "run",
                 "receiver names this box's mail identity, 1-48 of "
                 "[A-Za-z0-9_.-]",
                 "input.receiver missing or misspelled");
        return;
    }
    if (strcmp(action, "status") == 0) {
        rcv_status(receiver, reply);
        return;
    }
    if (strcmp(action, "run") != 0) {
        rcv_fail(reply, "BAD_INPUT", "run", "action is one of run|status",
                 "input.action missing or unknown");
        return;
    }
#if defined(_WIN32)
    rcv_fail(reply, "RECEIVE_WINDOWS_UNAVAILABLE", "run",
             "the resident receiver needs POSIX flock and signals",
             "run the receiver on a POSIX host");
#else
    rcv_run(request, receiver, reply);
#endif
}
