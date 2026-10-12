/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: Native-goal write-ahead and no-replay primitives. Transport and
 * persistence callbacks belong to existing executor/action authorities. */
#include "command/native_devagent_codex_goal.h"
#include "base/hex.h"
#include "zutf8/zutf8.h"

#include <stdio.h>
#include <string.h>

static enum cga_result cga_fail(enum cga_result result, char *why,
    size_t cap, const char *message)
{
    if (why && cap) (void)snprintf(why, cap, "%s", message);
    fprintf(stderr, "codex goal adapter: %s\n", message);
    return result;
}

static bool cga_utf8(const unsigned char *s, size_t n)
{
    return !memchr(s, '\0', n) && zutf8_validate_n((const char *)s, n);
}

static bool cga_text(const char *s, size_t cap, bool empty)
{
    const char *end = memchr(s, '\0', cap);
    return end && (empty || s[0] != '\0') &&
        cga_utf8((const unsigned char *)s, (size_t)(end - s));
}

static bool cga_hash(const char s[65])
{
    if (s[64] != '\0') return false;
    for (size_t i = 0; i < 64; i++)
        if (!((s[i] >= '0' && s[i] <= '9') ||
              (s[i] >= 'a' && s[i] <= 'f'))) return false;
    return true;
}

static bool cga_valid_target(const struct cga_command *c)
{
    return cga_text(c->id, sizeof(c->id), false) &&
        cga_text(c->thread_id, sizeof(c->thread_id), false) &&
        cga_text(c->turn_id, sizeof(c->turn_id), c->operation != CGA_INTERRUPT) &&
        cga_text(c->expected_revision, sizeof(c->expected_revision), false) &&
        cga_text(c->workspace, sizeof(c->workspace), false) &&
        c->workspace[0] == '/' &&
        cga_text(c->job_id, sizeof(c->job_id), false) && c->attempt >= 0;
}

static bool cga_valid_process(const struct cga_command *c)
{
    return cga_text(c->executable, sizeof(c->executable), false) &&
        c->executable[0] == '/' && cga_hash(c->executable_sha256) &&
        cga_hash(c->environment_sha256) &&
        cga_text(c->model, sizeof(c->model), false) &&
        cga_text(c->effort, sizeof(c->effort), false) &&
        cga_text(c->effective_model, sizeof(c->effective_model), false) &&
        cga_text(c->effective_effort, sizeof(c->effective_effort), false) &&
        strcmp(c->model, c->effective_model) == 0 &&
        strcmp(c->effort, c->effective_effort) == 0;
}

static bool cga_valid_goal(const struct cga_command *c)
{
    return c->operation >= CGA_SET && c->operation <= CGA_INTERRUPT &&
        c->goal_len <= CGA_GOAL_CAP &&
        (c->operation == CGA_SET ? (c->goal_len > 0 && c->token_budget > 0 &&
            cga_utf8(c->goal, c->goal_len)) : c->goal_len == 0);
}

static bool cga_valid(const struct cga_command *c)
{
    return c && cga_valid_target(c) && cga_valid_process(c) && cga_valid_goal(c);
}

static bool cga_same_target(const struct cga_command *a,
    const struct cga_command *b)
{
    return a->operation == b->operation && a->goal_len == b->goal_len &&
        a->token_budget == b->token_budget &&
        strcmp(a->id, b->id) == 0 && strcmp(a->thread_id, b->thread_id) == 0 &&
        strcmp(a->turn_id, b->turn_id) == 0 &&
        strcmp(a->expected_revision, b->expected_revision) == 0 &&
        strcmp(a->workspace, b->workspace) == 0 &&
        strcmp(a->job_id, b->job_id) == 0 && a->attempt == b->attempt;
}

static bool cga_same_process(const struct cga_command *a,
    const struct cga_command *b)
{
    return strcmp(a->executable, b->executable) == 0 &&
        strcmp(a->executable_sha256, b->executable_sha256) == 0 &&
        strcmp(a->environment_sha256, b->environment_sha256) == 0 &&
        strcmp(a->model, b->model) == 0 && strcmp(a->effort, b->effort) == 0 &&
        strcmp(a->effective_model, b->effective_model) == 0 &&
        strcmp(a->effective_effort, b->effective_effort) == 0;
}

static bool cga_same(const struct cga_command *a, const struct cga_command *b)
{
    return cga_same_target(a, b) && cga_same_process(a, b) &&
        memcmp(a->goal, b->goal, a->goal_len) == 0;
}

struct cga_writer { char *out; size_t cap; size_t used; bool failed; };

static void cga_append(struct cga_writer *w, const char *s, size_t n)
{
    if (w->failed) return;
    if (n >= w->cap - w->used) { w->failed = true; return; }
    memcpy(w->out + w->used, s, n);
    w->used += n;
    w->out[w->used] = '\0';
}

static void cga_literal(struct cga_writer *w, const char *s)
{
    cga_append(w, s, strlen(s));
}

static void cga_quoted(struct cga_writer *w, const unsigned char *s, size_t n)
{
    cga_literal(w, "\"");
    for (size_t i = 0; i < n && !w->failed; i++) {
        unsigned char b = s[i];
        if (b == '"' || b == '\\') {
            char pair[2] = {'\\', (char)b};
            cga_append(w, pair, 2);
        } else if (b == '\n' || b == '\r' || b == '\t' ||
            b == '\010' || b == '\f') {
            char pair[2] = {'\\', b == '\n' ? 'n' : b == '\r' ? 'r' :
                b == '\t' ? 't' : b == '\010' ? 'b' : 'f'};
            cga_append(w, pair, sizeof(pair));
        } else if (b < 0x20) {
            char escape[7] = {'\\', 'u', '0', '0', 0, 0, 0};
            zcl_hex_encode(&b, 1, escape + 4);
            cga_append(w, escape, sizeof(escape) - 1);
        } else {
            char raw = (char)b;
            cga_append(w, &raw, 1);
        }
    }
    cga_literal(w, "\"");
}

static void cga_string(struct cga_writer *w, const char *s)
{
    cga_quoted(w, (const unsigned char *)s, strlen(s));
}

static bool cga_native_ids(const struct cga_command *c)
{
    return cga_utf8((const unsigned char *)c->id, strlen(c->id)) &&
        cga_utf8((const unsigned char *)c->thread_id, strlen(c->thread_id)) &&
        cga_utf8((const unsigned char *)c->turn_id, strlen(c->turn_id));
}

static void cga_set_params(struct cga_writer *w, const struct cga_command *c)
{
    cga_literal(w, ",\"objective\":");
    cga_quoted(w, c->goal, c->goal_len);
    cga_literal(w, ",\"status\":\"active\",\"tokenBudget\":");
    char number[32];
    int length = snprintf(number, sizeof(number), "%lld",
        (long long)c->token_budget);
    if (length < 1 || (size_t)length >= sizeof(number)) w->failed = true;
    else cga_append(w, number, (size_t)length);
}

enum cga_result cga_wire_request(const struct cga_command *c,
    char *out, size_t out_cap, char *why, size_t why_cap)
{
    if (out && out_cap) out[0] = '\0';
    if (!out || !out_cap || !cga_valid(c))
        return cga_fail(CGA_INVALID, why, why_cap, "invalid request encoding input");
    /* JSON string input must be losslessly representable too, not just goal. */
    if (!cga_native_ids(c))
        return cga_fail(CGA_INVALID, why, why_cap, "invalid UTF-8 native identity");
    struct cga_writer w = {out, out_cap, 0, false};
    cga_literal(&w, "{\"jsonrpc\":\"2.0\",\"id\":"); cga_string(&w, c->id);
    cga_literal(&w, ",\"method\":");
    cga_string(&w, c->operation == CGA_SET ? "thread/goal/set" :
        c->operation == CGA_CLEAR ? "thread/goal/clear" : "turn/interrupt");
    cga_literal(&w, ",\"params\":{\"threadId\":");
    cga_string(&w, c->thread_id);
    if (c->operation == CGA_SET) {
        cga_set_params(&w, c);
    } else if (c->operation == CGA_INTERRUPT) {
        cga_literal(&w, ",\"turnId\":"); cga_string(&w, c->turn_id);
    }
    cga_literal(&w, "}}\n");
    if (w.failed) {
        out[0] = '\0';
        return cga_fail(CGA_INVALID, why, why_cap,
            "request exceeds output bound; no partial request permitted");
    }
    if (why && why_cap) why[0] = '\0';
    return CGA_OK;
}

static enum cga_result cga_qualified(const struct cga_io *io,
    char *why, size_t cap)
{
    if (!io || !io->save || !io->read || !io->send)
        return cga_fail(CGA_INVALID, why, cap, "missing owner callbacks");
    if (!io->caps.version || strcmp(io->caps.version, "0.160.0") != 0 ||
        !io->caps.native_goal_methods || !io->caps.runtime_qualified)
        return cga_fail(CGA_UNSUPPORTED, why, cap,
            "native Goals version or runtime capability is unqualified");
    if (!io->caps.exclusive_thread)
        return cga_fail(CGA_AUTHORITY, why, cap,
            "exclusive native thread authority is required; protocol has no CAS");
    return CGA_OK;
}

static bool cga_observed_text(const struct cga_observation *o)
{
    return cga_text(o->thread_id, sizeof(o->thread_id), false) &&
        cga_text(o->turn_id, sizeof(o->turn_id), true) &&
        cga_text(o->revision, sizeof(o->revision), false) &&
        cga_text(o->effective_model, sizeof(o->effective_model), false) &&
        cga_text(o->effective_effort, sizeof(o->effective_effort), false);
}

static bool cga_observed_accounting(const struct cga_observation *o)
{
    return !o->accounting_present || (o->created_at >= 0 &&
        o->updated_at >= o->created_at && o->tokens_used >= 0 &&
        o->time_used_seconds >= 0);
}

static bool cga_observed(const struct cga_observation *o,
    const struct cga_command *c)
{
    return cga_observed_text(o) && o->goal_len <= CGA_GOAL_CAP &&
        o->status >= CGA_ABSENT && o->status <= CGA_COMPLETE &&
        cga_observed_accounting(o) &&
        strcmp(o->thread_id, c->thread_id) == 0 &&
        strcmp(o->effective_model, c->effective_model) == 0 &&
        strcmp(o->effective_effort, c->effective_effort) == 0;
}

static bool cga_exhausted(const struct cga_command *c,
    const struct cga_observation *o)
{
    return c->operation == CGA_SET &&
        (o->status == CGA_USAGE_LIMITED || o->status == CGA_BUDGET_LIMITED);
}

static bool cga_blocked_set(const struct cga_command *c,
    const struct cga_observation *o)
{
    return c->operation == CGA_SET && o->status == CGA_BLOCKED;
}

/* A refusal is subordinate evidence, saved through the same existing owner.
 * It is sticky for this command ID: resetting its budget is a new authorized
 * action, not automatic replay of a refused submission. */
/* Failed callbacks retain the pre-call record. Only a successful durable
 * save lets the caller install next; callback aliases cannot clear fences. */
static bool cga_save_bound(const struct cga_io *io,
    const struct cga_record *next, struct cga_record *live)
{
    const struct cga_record frozen = *live;
    bool saved = io->save(io->ctx, next);
    *live = frozen;
    return saved;
}

static enum cga_result cga_refuse_limit(const struct cga_io *io,
    const struct cga_command *c, const struct cga_observation *o,
    struct cga_record *r, char *why, size_t cap)
{
    struct cga_record next = {0};
    next.command = *c;
    next.observation = *o;
    next.accepted = true;
    next.admission_refused = true;
    if (!cga_save_bound(io, &next, r))
        return cga_fail(CGA_STORAGE, why, cap,
            "native limits exhausted; cannot persist refusal; no effect submitted");
    *r = next;
    return cga_fail(CGA_LIMIT, why, cap,
        "native goal usage or budget exhausted; SET admission refused");
}

static bool cga_readback_matches(const struct cga_command *c,
    const struct cga_observation *o)
{
    if (c->operation == CGA_SET)
        return o->goal_present && o->goal_len == c->goal_len &&
            o->token_budget == c->token_budget && o->status != CGA_ABSENT &&
            memcmp(o->goal, c->goal, c->goal_len) == 0;
    if (c->operation == CGA_CLEAR)
        return !o->goal_present && o->status == CGA_ABSENT;
    return strcmp(o->turn_id, c->turn_id) == 0 && o->turn_terminal;
}

static bool cga_readback_terminal(const struct cga_command *c,
    const struct cga_observation *o)
{
    return c->operation == CGA_INTERRUPT ? o->turn_terminal :
        c->operation == CGA_SET && o->status == CGA_COMPLETE;
}

/* Validate bounded command strings before comparing them. Ignore struct
 * padding; each durable lifecycle fact retains its independent identity. */
static bool cga_record_binding(const struct cga_record *live,
    const struct cga_record *frozen)
{
    return cga_valid(&live->command) && cga_same(&live->command, &frozen->command) &&
        live->accepted == frozen->accepted && live->uncertain == frozen->uncertain &&
        live->applied == frozen->applied && live->readback == frozen->readback &&
        live->terminal == frozen->terminal && live->quiescent == frozen->quiescent &&
        live->admission_refused == frozen->admission_refused;
}

/* A callback may retain an alias to the caller's record. Preserve the
 * entry-time durable fence even when it poisons that alias or fails to read. */
static bool cga_read_bound(const struct cga_io *io, struct cga_record *live,
    const struct cga_record *frozen, struct cga_observation *out)
{
    bool read = io->read(io->ctx, out);
    bool bound = cga_record_binding(live, frozen);
    *live = *frozen;
    return read && bound;
}

enum cga_result cga_reconcile(const struct cga_io *io,
    struct cga_record *r, char *why, size_t cap)
{
    enum cga_result qualified = cga_qualified(io, why, cap);
    if (qualified != CGA_OK) return qualified;
    if (!r || !r->accepted || !cga_valid(&r->command))
        return cga_fail(CGA_INVALID, why, cap, "no valid durable intent to reconcile");
    if (r->admission_refused)
        return cga_fail(CGA_LIMIT, why, cap, "durable exhaustion refusal; no replay");
    const struct cga_record frozen = *r;
    struct cga_observation o = {0};
    if (!cga_read_bound(io, r, &frozen, &o) ||
        !cga_observed(&o, &frozen.command))
        return cga_fail(CGA_UNCERTAIN, why, cap,
            "native readback unavailable or mismatched; do not resend");
    const struct cga_command *c = &frozen.command;
    if (!cga_readback_matches(c, &o))
        return cga_fail(CGA_UNCERTAIN, why, cap,
            "readback differs from requested effect; absence does not authorize retry");
    struct cga_record next = frozen;
    next.observation = o;
    next.readback = true;
    next.terminal = next.terminal || cga_readback_terminal(c, &o);
    if (!cga_save_bound(io, &next, r))
        return cga_fail(CGA_STORAGE, why, cap, "cannot persist native readback");
    *r = next;
    if (why && cap) why[0] = '\0';
    return CGA_OK;
}
static bool cga_possible_effect(const struct cga_record *r)
{
    return r->uncertain || r->applied || r->readback ||
        r->terminal || r->quiescent || r->admission_refused;
}

static enum cga_result cga_recovered(const struct cga_command *c,
    const struct cga_record *r, char *why, size_t cap)
{
    if (!r->accepted && cga_possible_effect(r))
        return cga_fail(CGA_INVALID, why, cap,
            "contradictory recovered state; possible effect cannot be downgraded");
    if (!r->accepted) return CGA_OK;
    if (!cga_valid(&r->command) || !cga_same(c, &r->command))
        return cga_fail(CGA_CONFLICT, why, cap,
            "durable command binding conflicts; use existing action authority");
    if (r->admission_refused)
        return cga_fail(CGA_LIMIT, why, cap, "durable exhaustion refusal; no replay");
    return CGA_OK;
}

static bool cga_target_matches(const struct cga_command *c,
    const struct cga_observation *o)
{
    return strcmp(o->revision, c->expected_revision) == 0 &&
        (c->operation != CGA_INTERRUPT || strcmp(o->turn_id, c->turn_id) == 0);
}

static enum cga_result cga_prepare(const struct cga_io *io,
    const struct cga_command *c, struct cga_record *r, char *why, size_t cap)
{
    struct cga_record frozen;
    memcpy(&frozen, r, sizeof(frozen));
    struct cga_observation o = {0};
    bool read = io->read(io->ctx, &o);
    bool bound = memcmp(r, &frozen, sizeof(frozen)) == 0;
    memcpy(r, &frozen, sizeof(frozen));
    if (!read || !bound || !cga_observed(&o, c))
        return cga_fail(CGA_UNCERTAIN, why, cap, "initial native observation unavailable");
    if (!cga_target_matches(c, &o))
        return cga_fail(CGA_STALE, why, cap, "expected native target or observation differs");
    if (cga_blocked_set(c, &o))
        return cga_fail(CGA_UNSUPPORTED, why, cap,
            "blocked goal requires owning changed-input admission unavailable in this API");
    if (cga_exhausted(c, &o))
        return cga_refuse_limit(io, c, &o, r, why, cap);
    struct cga_record next = {0};
    next.command = *c;
    next.accepted = true;
    if (!r->accepted) {
        if (!cga_save_bound(io, &next, r))
            return cga_fail(CGA_STORAGE, why, cap, "cannot persist command intent");
        *r = next;
    }
    next.uncertain = true;
    if (!cga_save_bound(io, &next, r))
        return cga_fail(CGA_STORAGE, why, cap, "cannot persist possible submission");
    *r = next;
    return CGA_OK;
}

static bool cga_ack_matches(const struct cga_ack *ack,
    const struct cga_command *c)
{
    return cga_text(ack->command_id, sizeof(ack->command_id), false) &&
        cga_text(ack->thread_id, sizeof(ack->thread_id), false) &&
        cga_text(ack->turn_id, sizeof(ack->turn_id), true) &&
        strcmp(ack->command_id, c->id) == 0 &&
        strcmp(ack->thread_id, c->thread_id) == 0 &&
        (c->operation != CGA_INTERRUPT || strcmp(ack->turn_id, c->turn_id) == 0);
}

static bool cga_submit_binding(const struct cga_command *caller,
    const struct cga_record *live, const struct cga_record *frozen)
{
    return cga_valid(caller) && cga_same(caller, &frozen->command) &&
        cga_record_binding(live, frozen);
}

static enum cga_result cga_submit(const struct cga_io *io,
    const struct cga_command *c, struct cga_record *r, char *why, size_t cap)
{
    struct cga_record next = *r;
    const struct cga_command intent = r->command;
    /* Revalidate after durable intent. Exclusive authority remains required;
     * this readback does not pretend to provide a server-side CAS primitive. */
    struct cga_observation o = {0};
    if (!cga_read_bound(io, r, &next, &o) || !cga_observed(&o, &intent) ||
        !cga_target_matches(&intent, &o) ||
        !cga_submit_binding(c, r, &next))
        return cga_fail(CGA_UNCERTAIN, why, cap,
            "pre-effect target changed; durable intent retained without replay");
    if (cga_blocked_set(&intent, &o) || cga_exhausted(&intent, &o))
        return cga_fail(CGA_UNCERTAIN, why, cap,
            "pre-effect state changed after durable intent; no refusal and no resend");
    struct cga_ack ack = {0};
    enum cga_send_result sent = io->send(io->ctx, &intent, &ack);
    *r = next;
    if (sent != CGA_SEND_APPLIED || !cga_ack_matches(&ack, &intent))
        return cga_fail(CGA_UNCERTAIN, why, cap,
            "native response lost or mismatched; reconcile before any new effect");
    next.applied = true;
    next.uncertain = false;
    if (!cga_save_bound(io, &next, r))
        return cga_fail(CGA_STORAGE, why, cap,
            "effect acknowledged but persistence failed; reconcile durable intent");
    *r = next;
    return cga_reconcile(io, r, why, cap);
}

enum cga_result cga_execute(const struct cga_io *io,
    const struct cga_command *c, struct cga_record *r, char *why, size_t cap)
{
    enum cga_result result = cga_qualified(io, why, cap);
    if (result != CGA_OK) return result;
    if (!r || !cga_valid(c))
        return cga_fail(CGA_INVALID, why, cap, "invalid or unrepresentable command");
    /* Validation and both durable saves use one entry-time value. Retain the
     * caller alias only to refuse callback mutation before effect submission. */
    const struct cga_command *caller = c;
    const struct cga_command pinned = *c;
    c = &pinned;
    result = cga_recovered(c, r, why, cap);
    if (result != CGA_OK) return result;
    if (r->accepted && cga_possible_effect(r))
        return cga_reconcile(io, r, why, cap);
    result = cga_prepare(io, c, r, why, cap);
    if (result != CGA_OK) return result;
    return cga_submit(io, caller, r, why, cap);
}
