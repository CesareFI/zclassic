/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: Decode correlated native-reported goal facts without effects. */
#include "command/native_devagent_codex_observation_decode.h"
#include "json/json.h"
#include "base/hex.h"
#include "crypto/sha256.h"
#include "base/safe_alloc.h"
#include "zutf8/zutf8.h"
#include <stdio.h>
#include <string.h>

/* Validate the original bytes before parsing can erase their wire spelling. */
static bool cgo_json_read(struct json_value *root, const char *bytes, size_t length)
{
    return bytes && zutf8_validate_n(bytes, length) && json_read(root, bytes, length);
}

static enum cga_result cgo_fail(char *why, size_t cap, const char *message)
{
    if (why && cap) (void)snprintf(why, cap, "%s", message);
    fprintf(stderr, "codex goal observation: %s\n", message);
    return CGA_INVALID;
}

static void cgo_hash(struct cgo_digest *out, const char *bytes, size_t length)
{
    struct sha256_ctx ctx;
    unsigned char digest[SHA256_OUTPUT_SIZE];
    sha256_init(&ctx);
    sha256_write(&ctx, (const unsigned char *)bytes, length);
    sha256_finalize(&ctx, digest);
    zcl_hex_encode(digest, sizeof(digest), out->value);
    out->state = CGO_KNOWN;
}

static bool cgo_unique_object(const struct json_value *v)
{
    if (!v || v->type != JSON_OBJ) return false;
    for (size_t i = 0; i < v->num_children; i++)
        for (size_t j = i + 1; j < v->num_children; j++)
            if (strcmp(v->keys[i], v->keys[j]) == 0) return false;
    return true;
}

static bool cgo_object_keys(const struct json_value *v,
    const char *const *keys, size_t count)
{
    if (!v || v->type != JSON_OBJ || v->num_children > count ||
        !cgo_unique_object(v)) return false;
    for (size_t i = 0; i < v->num_children; i++) {
        bool found = false;
        for (size_t j = 0; j < count; j++)
            if (strcmp(v->keys[i], keys[j]) == 0) found = true;
        if (!found) return false;
    }
    return true;
}

static bool cgo_matches(const struct json_value *v, const char *expected,
    size_t length)
{
    return v && v->type == JSON_STR && strlen(v->val.s) == length &&
        memcmp(v->val.s, expected, length) == 0;
}

static bool cgo_expected_text(const char *bytes, size_t length)
{
    if (!zutf8_validate_n(bytes, length)) return false;
    char text[CGA_ID_CAP], encoded[CGA_ID_CAP * 6u + 3u];
    memcpy(text, bytes, length);
    text[length] = '\0';
    struct json_value value = { .type = JSON_STR, .val.s = text };
    size_t written = json_write(&value, encoded, sizeof(encoded));
    return written < sizeof(encoded) && json_valid(encoded, written);
}

static void cgo_id_copy(struct cgo_id *out, const char *value, size_t length)
{
    memcpy(out->value, value, length);
    out->value[length] = '\0';
    out->state = CGO_KNOWN;
}

static bool cgo_integer(const struct json_value *goal, const char *key,
    bool nullable, struct cgo_integer *out)
{
    const struct json_value *v = json_get(goal, key);
    if (!v) return true;
    if (nullable && v->type == JSON_NULL) { out->state = CGO_ABSENT; return true; }
    if (v->type != JSON_INT || v->val.i < 0) return false;
    out->state = CGO_KNOWN;
    out->value = v->val.i;
    return true;
}

static bool cgo_accounting(const struct json_value *goal, struct cgo_snapshot *s)
{
    bool valid = cgo_integer(goal, "tokenBudget", true, &s->token_budget) &&
        cgo_integer(goal, "tokensUsed", false, &s->tokens_used) &&
        cgo_integer(goal, "timeUsedSeconds", false, &s->time_used_seconds) &&
        cgo_integer(goal, "createdAt", false, &s->created_at_unix_seconds) &&
        cgo_integer(goal, "updatedAt", false, &s->updated_at_unix_seconds);
    if (!valid) return false;
    return s->created_at_unix_seconds.state != CGO_KNOWN ||
        s->updated_at_unix_seconds.state != CGO_KNOWN ||
        s->created_at_unix_seconds.value <= s->updated_at_unix_seconds.value;
}

static bool cgo_status(const struct json_value *goal, struct cgo_snapshot *s)
{
    const char *names[] = { "active", "paused", "blocked", "usageLimited",
        "budgetLimited", "complete" };
    const struct json_value *v = json_get(goal, "status");
    if (!v) return true;
    if (v->type != JSON_STR) return false;
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++)
        if (strcmp(v->val.s, names[i]) == 0) {
            s->goal_status_state = CGO_KNOWN;
            s->goal_status = (enum cga_goal_status)(CGA_ACTIVE + i);
            return true;
        }
    return false;
}

static bool cgo_objective(const struct json_value *goal, struct cgo_snapshot *s)
{
    const struct json_value *v = json_get(goal, "objective");
    if (!v) return true;
    if (v->type != JSON_STR) return false;
    size_t length = strlen(v->val.s);
    if (length > CGA_GOAL_CAP || !zutf8_validate_n(v->val.s, length)) return false;
    cgo_hash(&s->objective_sha256, v->val.s, length);
    s->objective_length.state = CGO_KNOWN;
    s->objective_length.value = (int64_t)length;
    return true;
}

static bool cgo_goal(const struct json_value *result,
    const char *thread, size_t length, struct cgo_snapshot *s)
{
    const struct json_value *goal = json_get(result, "goal");
    if (!goal) return true;
    if (goal->type == JSON_NULL) { s->goal_present = CGO_FALSE; return true; }
    const char *keys[] = { "threadId", "objective", "status", "tokenBudget",
        "tokensUsed", "timeUsedSeconds", "createdAt", "updatedAt" };
    if (!cgo_object_keys(goal, keys, sizeof(keys) / sizeof(keys[0])) ||
        !cgo_matches(json_get(goal, "threadId"), thread, length)) return false;
    s->goal_present = CGO_TRUE;
    return cgo_objective(goal, s) && cgo_status(goal, s) && cgo_accounting(goal, s);
}

static bool cgo_decode(const struct json_value *root,
    const char *request, size_t request_len, const char *thread, size_t thread_len,
    struct cgo_snapshot *s)
{
    const char *keys[] = { "id", "result", "jsonrpc" };
    if (!cgo_object_keys(root, keys, sizeof(keys) / sizeof(keys[0])) ||
        !cgo_matches(json_get(root, "id"), request, request_len)) return false;
    const struct json_value *rpc_version = json_get(root, "jsonrpc");
    if (rpc_version && !cgo_matches(rpc_version, "2.0", 3)) return false;
    const struct json_value *result = json_get(root, "result");
    const char *result_keys[] = { "goal" };
    if (!cgo_object_keys(result, result_keys, 1) ||
        !cgo_goal(result, thread, thread_len, s))
        return false;
    cgo_id_copy(&s->request_id, request, request_len);
    /* A null/missing goal has no returned thread binding; never manufacture it. */
    if (s->goal_present == CGO_TRUE) cgo_id_copy(&s->thread_id, thread, thread_len);
    s->readback = CGO_TRUE;
    return true;
}

static bool cgo_expected_id(const char *text, size_t length)
{
    return text && length > 0 && length < CGA_ID_CAP &&
        !memchr(text, '\0', length) && cgo_expected_text(text, length);
}

static bool cgo_input_bounds(const char *raw, size_t length,
    const char *request, size_t request_length, const char *thread, size_t thread_length)
{
    return raw && length <= CGO_RESPONSE_CAP && !memchr(raw, '\0', length) &&
        cgo_expected_id(request, request_length) &&
        cgo_expected_id(thread, thread_length);
}

static bool cgo_required_native(const struct json_value *root)
{
    const struct json_value *goal = json_get(json_get(root, "result"), "goal");
    if (!goal || goal->type == JSON_NULL) return true;
    const char *keys[] = { "threadId", "objective", "status", "tokensUsed",
        "timeUsedSeconds", "createdAt", "updatedAt" };
    for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); i++)
        if (!json_get(goal, keys[i])) return false;
    return true;
}

static void cgo_absent_goal(struct cgo_snapshot *s)
{
    s->goal_status_state = CGO_ABSENT;
    s->objective_sha256.state = CGO_ABSENT;
    s->objective_length.state = CGO_ABSENT;
    s->token_budget.state = CGO_ABSENT;
    s->tokens_used.state = CGO_ABSENT;
    s->time_used_seconds.state = CGO_ABSENT;
    s->created_at_unix_seconds.state = CGO_ABSENT;
    s->updated_at_unix_seconds.state = CGO_ABSENT;
}

static enum cga_result cgo_decode_bound(const char *raw, size_t raw_len,
    const char *request, size_t request_len, const char *thread, size_t thread_len,
    bool strict, struct cgo_snapshot *out, char *why, size_t why_cap)
{
    if (out) memset(out, 0, sizeof(*out));
    if (!out || !cgo_input_bounds(raw, raw_len, request, request_len, thread, thread_len))
        return cgo_fail(why, why_cap, "bounded response or expected identity invalid");
    struct json_value root = {0};
    struct cgo_snapshot next = {0};
    bool parsed = cgo_json_read(&root, raw, raw_len);
    bool valid = parsed && cgo_decode(&root, request, request_len, thread, thread_len, &next) &&
        (!strict || cgo_required_native(&root));
    json_free(&root);
    if (!valid) return cgo_fail(why, why_cap, "native response malformed or uncorrelated");
    if (strict && next.goal_present == CGO_FALSE) cgo_absent_goal(&next);
    cgo_hash(&next.response_sha256, raw, raw_len);
    *out = next;
    return CGA_OK;
}

enum cga_result cgo_decode_goal_get(const char *raw, size_t raw_len,
    const char *request, size_t request_len, const char *thread, size_t thread_len,
    struct cgo_snapshot *out, char *why, size_t why_cap)
{
    return cgo_decode_bound(raw, raw_len, request, request_len, thread, thread_len,
        false, out, why, why_cap);
}

enum cga_result cgo_decode_input_v2(enum cgo_input_domain domain,
    const struct cgo_decode_context *context, const char *raw, size_t length,
    struct cgo_snapshot *out, char *why, size_t why_cap)
{
    if (out) memset(out, 0, sizeof(*out));
    if (domain != CGO_NATIVE_GOAL_GET || !context ||
        memcmp(context->protocol_version, "0.160.0", sizeof(context->protocol_version))) {
        if (why && why_cap) (void)snprintf(why, why_cap,
            "input domain/version has no qualified decoder binding");
        fprintf(stderr, "codex goal observation: unsupported input domain/version\n");
        return CGA_UNSUPPORTED;
    }
    return cgo_decode_goal_get(raw, length, context->request_id,
        context->request_length, context->thread_id, context->thread_length,
        out, why, why_cap);
}

enum cga_result cgo_decode_input_v3(enum cgo_input_domain domain,
    const struct cgo_decode_context *context, const char *raw, size_t length,
    struct cgo_snapshot *out, char *why, size_t why_cap)
{
    if (domain != CGO_NATIVE_GOAL_GET || !context ||
        memcmp(context->protocol_version, "0.160.0", sizeof(context->protocol_version)))
        return cgo_decode_input_v2(domain, context, raw, length, out, why, why_cap);
    return cgo_decode_bound(raw, length, context->request_id,
        context->request_length, context->thread_id, context->thread_length,
        true, out, why, why_cap);
}

static bool cgo_pair_request(const struct json_value *root,
    const struct cgo_decode_context *context)
{
    const char *keys[] = { "jsonrpc", "id", "method", "params" };
    const char *params_keys[] = { "threadId" };
    if (!cgo_object_keys(root, keys, 4) ||
        !cgo_matches(json_get(root, "id"), context->request_id, context->request_length) ||
        !cgo_matches(json_get(root, "method"), "thread/goal/get", 15)) return false;
    const struct json_value *version = json_get(root, "jsonrpc");
    if (version && !cgo_matches(version, "2.0", 3)) return false;
    const struct json_value *params = json_get(root, "params");
    return cgo_object_keys(params, params_keys, 1) &&
        cgo_matches(json_get(params, "threadId"), context->thread_id, context->thread_length);
}

enum cga_result cgo_decode_journal_pair_v1(
    const struct cgo_decode_context *context,
    const char *request, size_t request_length,
    const char *response, size_t response_length,
    struct cgo_journal_pair *out, char *why, size_t why_cap)
{
    if (out) memset(out, 0, sizeof(*out));
    if (!out || !context)
        return cgo_fail(why, why_cap, "journal pair output/context missing");
    if (memcmp(context->protocol_version, "0.160.0", sizeof(context->protocol_version))) {
        fprintf(stderr, "codex goal observation: unsupported journal pair version\n");
        if (why && why_cap) (void)snprintf(why, why_cap, "unsupported journal pair version");
        return CGA_UNSUPPORTED;
    }
    if (!cgo_input_bounds(request, request_length, context->request_id,
        context->request_length, context->thread_id, context->thread_length))
        return cgo_fail(why, why_cap, "journal request bounds/selection invalid");
    struct json_value root = {0};
    bool valid = cgo_json_read(&root, request, request_length) && cgo_pair_request(&root, context);
    json_free(&root);
    if (!valid) return cgo_fail(why, why_cap, "journal request malformed or uncorrelated");
    struct cgo_journal_pair next = {0};
    enum cga_result result = cgo_decode_input_v3(CGO_NATIVE_GOAL_GET, context,
        response, response_length, &next.observation, why, why_cap);
    if (result != CGA_OK) return result;
    cgo_hash(&next.request_sha256, request, request_length);
    next.response_sha256 = next.observation.response_sha256;
    *out = next;
    return CGA_OK;
}

static bool cgo_passive_selection(const struct cgo_decode_context *s)
{
    return s && !memcmp(s->protocol_version, "0.160.0", sizeof(s->protocol_version)) &&
        cgo_expected_id(s->request_id, s->request_length) &&
        cgo_expected_id(s->thread_id, s->thread_length);
}

static size_t cgo_passive_quote(const char *bytes, size_t length, char *out, size_t cap)
{
    char text[CGA_ID_CAP];
    memcpy(text, bytes, length);
    text[length] = '\0';
    struct json_value v = { .type = JSON_STR, .val.s = text };
    return json_write(&v, out, cap);
}

enum cga_result cgo_passive_request_v1(enum cgo_passive_method method,
    const struct cgo_decode_context *s, char *raw, size_t cap,
    size_t *length, char *why, size_t why_cap)
{
    if (length) *length = 0;
    if (raw && cap) raw[0] = '\0';
    if (!raw || !length || !cgo_passive_selection(s) ||
        method < CGO_PASSIVE_READ || method > CGO_PASSIVE_TURNS)
        return cgo_fail(why, why_cap, "passive method/selection unsupported");
    const char *names[] = { "thread/read", "thread/goal/get", "thread/turns/list" };
    const char *suffix[] = { ",\"includeTurns\":false", "",
        ",\"limit\":1,\"sortDirection\":\"desc\",\"itemsView\":\"notLoaded\"" };
    char id[CGA_ID_CAP * 6u + 3u], thread[CGA_ID_CAP * 6u + 3u];
    (void)cgo_passive_quote(s->request_id, s->request_length, id, sizeof(id));
    (void)cgo_passive_quote(s->thread_id, s->thread_length, thread, sizeof(thread));
    int n = snprintf(raw, cap, "{\"jsonrpc\":\"2.0\",\"id\":%s,\"method\":\"%s\","
        "\"params\":{\"threadId\":%s%s}}", id, names[method], thread, suffix[method]);
    if (n < 0 || (size_t)n >= cap) {
        if (cap) raw[0] = '\0';
        return cgo_fail(why, why_cap, "passive request capacity insufficient");
    }
    *length = (size_t)n;
    return CGA_OK;
}

static bool cgo_passive_same(const struct json_value *a, const struct json_value *b)
{
    if (!a || !b || a->type != b->type) return false;
    if (a->type == JSON_STR) return !strcmp(a->val.s, b->val.s);
    if (a->type == JSON_BOOL) return a->val.b == b->val.b;
    if (a->type == JSON_INT) return a->val.i == b->val.i;
    if (a->type != JSON_OBJ || !cgo_unique_object(a) ||
        a->num_children != b->num_children) return false;
    for (size_t i = 0; i < b->num_children; i++)
        if (!cgo_passive_same(json_get(a, b->keys[i]), &b->children[i])) return false;
    return true;
}

static bool cgo_passive_request_matches(const struct cgo_passive_leg *leg, size_t method)
{
    char expected[CGA_ID_CAP * 12u + 256u], why[160];
    size_t length = 0;
    if (cgo_passive_request_v1((enum cgo_passive_method)method, &leg->selection,
        expected, sizeof(expected), &length, why, sizeof(why)) != CGA_OK ||
        !cgo_input_bounds(leg->request, leg->request_length,
            leg->selection.request_id, leg->selection.request_length,
            leg->selection.thread_id, leg->selection.thread_length)) return false;
    struct json_value actual = {0}, canonical = {0};
    bool valid = cgo_json_read(&actual, leg->request, leg->request_length) &&
        cgo_json_read(&canonical, expected, length) && cgo_passive_same(&actual, &canonical);
    json_free(&actual);
    json_free(&canonical);
    return valid;
}

static bool cgo_passive_unique_tree(const struct json_value *v);

static bool cgo_passive_error(const struct json_value *error)
{
    const char *keys[] = { "code", "message", "data" };
    const struct json_value *code = json_get(error, "code");
    const struct json_value *message = json_get(error, "message");
    return cgo_object_keys(error, keys, 3) && cgo_passive_unique_tree(error) &&
        code && code->type == JSON_INT && message && message->type == JSON_STR;
}

static bool cgo_passive_envelope(const struct json_value *root)
{
    const struct json_value *version = json_get(root, "jsonrpc");
    const struct json_value *result = json_get(root, "result");
    const struct json_value *error = json_get(root, "error");
    return (!version || cgo_matches(version, "2.0", 3)) &&
        ((result && !error && result->type == JSON_OBJ) ||
         (!result && error && cgo_passive_error(error)));
}

static bool cgo_passive_reply(const struct cgo_passive_leg *leg,
    struct cgo_passive_trace *trace)
{
    if (!leg->response && !leg->response_length) return true;
    if (!cgo_input_bounds(leg->response, leg->response_length,
        leg->selection.request_id, leg->selection.request_length,
        leg->selection.thread_id, leg->selection.thread_length)) return false;
    struct json_value root = {0};
    const char *keys[] = { "jsonrpc", "id", "result", "error" };
    bool valid = cgo_json_read(&root, leg->response, leg->response_length) &&
        cgo_object_keys(&root, keys, 4) &&
        cgo_matches(json_get(&root, "id"), leg->selection.request_id,
            leg->selection.request_length);
    const struct json_value *result = json_get(&root, "result");
    valid = valid && cgo_passive_envelope(&root);
    if (valid) {
        cgo_hash(&trace->response_sha256, leg->response, leg->response_length);
        trace->response_length = leg->response_length;
        if (result) trace->readback = CGO_TRUE;
    }
    json_free(&root);
    return valid;
}

static bool cgo_passive_unique_tree(const struct json_value *v)
{
    if (v->type == JSON_OBJ && !cgo_unique_object(v)) return false;
    for (size_t i = 0; i < v->num_children; i++)
        if (!cgo_passive_unique_tree(&v->children[i])) return false;
    return true;
}

static bool cgo_passive_named(const struct json_value *v, const char *const *names,
    size_t count, struct cgo_id *out)
{
    if (!v || v->type != JSON_STR) return false;
    for (size_t i = 0; i < count; i++)
        if (!strcmp(v->val.s, names[i])) {
            cgo_id_copy(out, v->val.s, strlen(v->val.s));
            return true;
        }
    return false;
}

static bool cgo_passive_thread(const struct json_value *result,
    const struct cgo_decode_context *selection, struct cgo_passive_capture *out)
{
    const char *keys[] = { "thread" };
    if (!cgo_object_keys(result, keys, 1)) return false;
    const struct json_value *thread = json_get(result, "thread");
    if (!cgo_unique_object(thread) || !cgo_matches(json_get(thread, "id"),
        selection->thread_id, selection->thread_length)) return false;
    const struct json_value *status = json_get(thread, "status");
    const char *names[] = { "notLoaded", "idle", "systemError", "active" };
    return cgo_unique_object(status) && cgo_passive_named(json_get(status, "type"),
        names, 4, &out->thread_status);
}

static bool cgo_passive_turns(const struct json_value *result,
    struct cgo_passive_capture *out)
{
    const char *keys[] = { "data", "nextCursor", "backwardsCursor" };
    if (!cgo_object_keys(result, keys, 3)) return false;
    const struct json_value *data = json_get(result, "data");
    if (!data || data->type != JSON_ARR || data->num_children > 1) return false;
    if (!data->num_children) {
        out->turn_id.state = CGO_ABSENT;
        out->turn_status.state = CGO_ABSENT;
        return true;
    }
    const struct json_value *turn = &data->children[0];
    const struct json_value *id = json_get(turn, "id");
    const struct json_value *items = json_get(turn, "items");
    const char *names[] = { "completed", "interrupted", "failed", "inProgress" };
    if (!cgo_unique_object(turn) || !id || id->type != JSON_STR ||
        !cgo_expected_id(id->val.s, strlen(id->val.s)) || !items ||
        items->type != JSON_ARR || items->num_children ||
        !cgo_matches(json_get(turn, "itemsView"), "notLoaded", 9) ||
        !cgo_passive_named(json_get(turn, "status"), names, 4, &out->turn_status)) return false;
    cgo_id_copy(&out->turn_id, id->val.s, strlen(id->val.s));
    return true;
}

static bool cgo_passive_facts(const struct cgo_passive_leg *leg, size_t method,
    struct cgo_passive_capture *out)
{
    if (method == CGO_PASSIVE_GOAL || out->trace[method].readback != CGO_TRUE) return true;
    struct json_value root = {0};
    bool valid = cgo_json_read(&root, leg->response, leg->response_length) &&
        cgo_passive_unique_tree(&root);
    const struct json_value *result = json_get(&root, "result");
    if (valid) valid = method == CGO_PASSIVE_READ ?
        cgo_passive_thread(result, &leg->selection, out) : cgo_passive_turns(result, out);
    json_free(&root);
    return valid;
}

static bool cgo_passive_selections_distinct(const struct cgo_passive_leg legs[3])
{
    for (size_t i = 0; i < 3; i++) {
        if (!cgo_passive_selection(&legs[i].selection)) return false;
        for (size_t j = 0; j < i; j++)
            if (legs[i].selection.request_length == legs[j].selection.request_length &&
                !memcmp(legs[i].selection.request_id, legs[j].selection.request_id,
                    legs[i].selection.request_length)) return false;
    }
    return true;
}

static bool cgo_passive_leg_valid(const struct cgo_passive_leg legs[3], size_t i,
    struct cgo_passive_capture *out)
{
    return cgo_passive_request_matches(&legs[i], i) &&
        legs[i].selection.thread_length == legs[0].selection.thread_length &&
        !memcmp(legs[i].selection.thread_id, legs[0].selection.thread_id,
            legs[0].selection.thread_length) &&
        cgo_passive_reply(&legs[i], &out->trace[i]) &&
        cgo_passive_facts(&legs[i], i, out);
}

enum cga_result cgo_passive_capture_v1(const struct cgo_passive_leg legs[3],
    int64_t started, int64_t completed, int64_t max_age,
    struct cgo_passive_capture *out, char *why, size_t why_cap)
{
    if (out) memset(out, 0, sizeof(*out));
    if (!out || !legs || started < 0 || completed < started || max_age <= 0 ||
        !cgo_passive_selections_distinct(legs))
        return cgo_fail(why, why_cap, "passive capture interval invalid");
    struct cgo_passive_capture next = {0};
    for (size_t i = 0; i < 3; i++) {
        if (!cgo_passive_leg_valid(legs, i, &next))
            return cgo_fail(why, why_cap, "passive trace malformed or uncorrelated");
        cgo_hash(&next.trace[i].request_sha256, legs[i].request, legs[i].request_length);
        next.trace[i].request_length = legs[i].request_length;
    }
    if (next.trace[CGO_PASSIVE_GOAL].readback == CGO_TRUE &&
        cgo_decode_input_v3(CGO_NATIVE_GOAL_GET, &legs[1].selection,
            legs[1].response, legs[1].response_length, &next.goal, why, why_cap) != CGA_OK)
        return CGA_INVALID;
    next.capture_started_at_ms = started;
    next.capture_completed_at_ms = completed;
    next.maximum_age_ms = max_age;
    *out = next;
    return CGA_OK;
}

/* Per-invocation owned caller; never a controller ledger or authority token. */
struct cgo_passive_owned {
    struct cgo_passive_caller_view view;
    char ids[3][CGA_ID_CAP];
    char requests[3][CGA_ID_CAP * 12u + 256u];
    char *responses[3], *initialize_response, *objective;
};
static const char cgo_caller_initialize[] =
    "{\"jsonrpc\":\"2.0\",\"id\":\"initialize\",\"method\":\"initialize\","
    "\"params\":{\"clientInfo\":{\"name\":\"z23-passive-m1\",\"version\":\"1\"},"
    "\"capabilities\":{\"experimentalApi\":true}}}";
static const char cgo_caller_initialized[] =
    "{\"jsonrpc\":\"2.0\",\"method\":\"initialized\"}";

const struct cgo_passive_caller_view *cgo_passive_caller_view_v1(
    const struct cgo_passive_owned *owned)
{
    return owned ? &owned->view : NULL;
}

void cgo_passive_caller_free_v1(struct cgo_passive_owned *owned)
{
    if (!owned) return;
    for (size_t i = 0; i < 3; i++) free(owned->responses[i]);
    free(owned->initialize_response);
    free(owned->objective);
    free(owned);
}

static bool cgo_caller_ids(const struct cgo_passive_caller_request *request)
{
    for (size_t i = 0; i < 3; i++) {
        if (!cgo_expected_id(request->request_ids[i], request->request_id_lengths[i]) ||
            (request->request_id_lengths[i] == 10 &&
             !memcmp(request->request_ids[i], "initialize", 10))) return false;
        for (size_t j = 0; j < i; j++)
            if (request->request_id_lengths[i] == request->request_id_lengths[j] &&
                !memcmp(request->request_ids[i], request->request_ids[j],
                    request->request_id_lengths[i])) return false;
    }
    return true;
}

static bool cgo_caller_selection(const struct cgo_passive_caller_request *request)
{
    return request && request->capability == CGO_PASSIVE_LOCAL_M1 &&
        request->host && request->host_length == sizeof(CGO_PASSIVE_M1_HOST) - 1 &&
        !memcmp(request->host, CGO_PASSIVE_M1_HOST, request->host_length) &&
        request->thread && request->thread_length == sizeof(CGO_PASSIVE_M1_THREAD) - 1 &&
        !memcmp(request->thread, CGO_PASSIVE_M1_THREAD, request->thread_length) &&
        cgo_caller_ids(request);
}

static bool cgo_caller_port(const struct cgo_passive_caller_io *io)
{
    return io && io->begin && io->exchange && io->release && io->end && io->clock;
}

static enum cga_result cgo_caller_prepare(struct cgo_passive_owned *owned,
    const struct cgo_passive_caller_request *request, const char *thread, size_t thread_length,
    char *why, size_t cap)
{
    owned->view.initialize_request = cgo_caller_initialize;
    owned->view.initialize_request_length = sizeof(cgo_caller_initialize) - 1;
    owned->view.initialized_request = cgo_caller_initialized;
    owned->view.initialized_request_length = sizeof(cgo_caller_initialized) - 1;
    for (size_t i = 0; i < 3; i++) {
        memcpy(owned->ids[i], request->request_ids[i], request->request_id_lengths[i]);
        owned->ids[i][request->request_id_lengths[i]] = '\0';
        struct cgo_passive_leg *leg = &owned->view.legs[i];
        leg->selection = (struct cgo_decode_context){ "0.160.0", owned->ids[i],
            request->request_id_lengths[i], thread, thread_length };
        enum cga_result result = cgo_passive_request_v1((enum cgo_passive_method)i,
            &leg->selection, owned->requests[i], sizeof(owned->requests[i]),
            &leg->request_length, why, cap);
        if (result != CGA_OK) return result;
        leg->request = owned->requests[i];
    }
    return CGA_OK;
}

static enum cga_result cgo_caller_copy_reply(const struct cgo_passive_caller_io *io,
    char *reply, size_t length, char **copy, char *why, size_t cap)
{
    enum cga_result result = CGA_OK;
    if (!reply && length) result = cgo_fail(why, cap, "caller reply length without bytes");
    else if (length > CGO_RESPONSE_CAP) result = CGA_LIMIT;
    else if (reply) {
        *copy = zcl_malloc(length + 1, "codex.passive.reply");
        if (!*copy) result = CGA_LIMIT;
        else { memcpy(*copy, reply, length); (*copy)[length] = '\0'; }
    }
    if (reply) io->release(io->context, reply, length);
    if (result == CGA_LIMIT) {
        fprintf(stderr, "codex passive caller: reply allocation/size limit\n");
        if (why && cap) (void)snprintf(why, cap, "reply allocation/size limit");
    }
    return result;
}

/* Private direct-link port helper; not an observation/admission API. */
enum cga_result cgo_caller_initialize_reply(const char *raw, size_t length,
    char *why, size_t cap)
{
    if (!raw || !length || length > CGO_RESPONSE_CAP || memchr(raw, 0, length))
        return cgo_fail(why, cap, "initialization reply unavailable or invalid");
    struct json_value root = {0};
    const char *keys[] = { "id", "jsonrpc", "result", "error" };
    bool valid = cgo_json_read(&root, raw, length) && cgo_object_keys(&root, keys, 4) &&
        cgo_passive_unique_tree(&root) && cgo_matches(json_get(&root, "id"), "initialize", 10) &&
        cgo_passive_envelope(&root);
    bool unavailable = valid && json_get(&root, "error");
    json_free(&root);
    if (!valid) return cgo_fail(why, cap, "initialization reply malformed/uncorrelated");
    if (unavailable) {
        fprintf(stderr, "codex passive caller: initialization native error\n");
        if (why && cap) (void)snprintf(why, cap, "initialization native error");
        return CGA_UNSUPPORTED;
    }
    return CGA_OK;
}

static enum cga_result cgo_caller_begin(struct cgo_passive_owned *owned,
    const struct cgo_passive_caller_io *io, char *why, size_t cap)
{
    char *reply = NULL;
    size_t length = 0;
    enum cga_result result = io->begin(io->context, cgo_caller_initialize,
        sizeof(cgo_caller_initialize) - 1, cgo_caller_initialized,
        sizeof(cgo_caller_initialized) - 1, &reply, &length, why, cap);
    enum cga_result copied = cgo_caller_copy_reply(io, reply, length,
        &owned->initialize_response, why, cap);
    owned->view.initialize_response = owned->initialize_response;
    if (copied != CGA_OK) return copied;
    owned->view.initialize_response_length = length;
    if (result != CGA_OK) return result;
    return cgo_caller_initialize_reply(owned->initialize_response, length, why, cap);
}

static enum cga_result cgo_caller_exchange(struct cgo_passive_owned *owned,
    const struct cgo_passive_caller_io *io, size_t i, char *why, size_t cap)
{
    struct cgo_passive_leg *leg = &owned->view.legs[i];
    char *reply = NULL;
    size_t length = 0;
    enum cga_result result = io->exchange(io->context, (enum cgo_passive_method)i,
        leg->request, leg->request_length, &reply, &length, why, cap);
    enum cga_result copied = cgo_caller_copy_reply(io, reply, length,
        &owned->responses[i], why, cap);
    leg->response = owned->responses[i];
    if (copied != CGA_OK) return copied;
    leg->response_length = length;
    if (result != CGA_OK) return result;
    struct cgo_passive_capture check = {0};
    if (!cgo_passive_leg_valid(owned->view.legs, i, &check))
        return cgo_fail(why, cap, "caller native reply malformed/uncorrelated");
    if (i == CGO_PASSIVE_GOAL && check.trace[i].readback == CGO_TRUE)
        return cgo_decode_input_v3(CGO_NATIVE_GOAL_GET, &leg->selection,
            leg->response, leg->response_length, &check.goal, why, cap);
    return CGA_OK;
}

static enum cga_result cgo_caller_objective(struct cgo_passive_owned *owned,
    char *why, size_t cap)
{
    if (owned->view.observation.goal.goal_present != CGO_TRUE) return CGA_OK;
    struct json_value root = {0};
    const struct cgo_passive_leg *leg = &owned->view.legs[CGO_PASSIVE_GOAL];
    if (!cgo_json_read(&root, leg->response, leg->response_length))
        return cgo_fail(why, cap, "caller objective reread allocation failed");
    const struct json_value *goal = json_get(json_get(&root, "result"), "goal");
    const struct json_value *objective = json_get(goal, "objective");
    size_t length = strlen(objective->val.s); /* strict V3 already validated */
    owned->objective = zcl_malloc(length + 1, "codex.passive.objective");
    if (owned->objective) memcpy(owned->objective, objective->val.s, length + 1);
    json_free(&root);
    if (!owned->objective) {
        fprintf(stderr, "codex passive caller: objective allocation failed\n");
        if (why && cap) (void)snprintf(why, cap, "objective allocation failed");
        return CGA_LIMIT;
    }
    owned->view.objective = owned->objective;
    owned->view.objective_length = length;
    return CGA_OK;
}

static enum cga_result cgo_caller_run(struct cgo_passive_owned *owned,
    const struct cgo_passive_caller_io *io, int64_t *wall_end, char *why, size_t cap)
{
    enum cga_result result = cgo_caller_begin(owned, io, why, cap);
    for (size_t i = 0; i < 3 && result == CGA_OK; i++)
        result = cgo_caller_exchange(owned, io, i, why, cap);
    io->end(io->context);
    if (!io->clock(io->context, wall_end, &owned->view.completed_monotonic_ms) ||
        *wall_end < 0 || owned->view.completed_monotonic_ms < owned->view.started_monotonic_ms)
        return cgo_fail(why, cap, "caller completion clock invalid");
    return result;
}

static enum cga_result cgo_caller_finish(struct cgo_passive_owned *owned,
    enum cga_result result, int64_t start, int64_t end, char *why, size_t cap)
{
    if (result == CGA_OK)
        result = cgo_passive_capture_v1(owned->view.legs, start, end,
            CGO_PASSIVE_DIAGNOSTIC_MAX_AGE_MS, &owned->view.observation, why, cap);
    if (result == CGA_OK) result = cgo_caller_objective(owned, why, cap);
    if (result != CGA_OK) {
        memset(&owned->view.observation, 0, sizeof(owned->view.observation));
        owned->view.objective = NULL;
        owned->view.objective_length = 0;
        fprintf(stderr, "codex passive caller: read-only capture refused (%d)\n", result);
    }
    owned->view.result = result;
    return result;
}

static enum cga_result cgo_caller_selected(const struct cgo_passive_caller_request *request,
    const char *thread, size_t thread_length, const struct cgo_passive_caller_io *io,
    struct cgo_passive_owned **out, char *why, size_t cap)
{
    if (out) *out = NULL;
    if (!out || !cgo_caller_port(io)) return cgo_fail(why, cap, "caller output/port missing");
    struct cgo_passive_owned *owned = zcl_calloc(1, sizeof(*owned), "codex.passive.caller");
    if (!owned) {
        fprintf(stderr, "codex passive caller: owned allocation failed\n");
        if (why && cap) (void)snprintf(why, cap, "owned allocation failed");
        return CGA_LIMIT;
    }
    int64_t start = 0, end = 0;
    enum cga_result result = cgo_caller_prepare(owned, request, thread, thread_length, why, cap);
    if (result == CGA_OK && (!io->clock(io->context, &start, &owned->view.started_monotonic_ms) ||
        start < 0 || owned->view.started_monotonic_ms < 0))
        result = cgo_fail(why, cap, "caller initial clock invalid");
    if (result != CGA_OK) { cgo_passive_caller_free_v1(owned); return result; }
    result = cgo_caller_run(owned, io, &end, why, cap);
    result = cgo_caller_finish(owned, result, start, end, why, cap);
    *out = owned;
    return result;
}

static enum cga_result cgo_caller_authority(char *why, size_t cap)
{
    fprintf(stderr, "codex passive caller: disabled or wrong bound selection\n");
    if (why && cap) (void)snprintf(why, cap, "disabled or wrong bound selection");
    return CGA_AUTHORITY;
}

enum cga_result cgo_passive_caller_v1(const struct cgo_passive_caller_request *request,
    const struct cgo_passive_caller_io *io, struct cgo_passive_owned **out,
    char *why, size_t cap)
{
    if (out) *out = NULL;
    if (!out || !cgo_caller_port(io)) return cgo_fail(why, cap, "caller output/port missing");
    if (!cgo_caller_selection(request)) return cgo_caller_authority(why, cap);
    return cgo_caller_selected(request, CGO_PASSIVE_M1_THREAD,
        sizeof(CGO_PASSIVE_M1_THREAD) - 1, io, out, why, cap);
}

enum cga_result cgo_passive_rhett2_caller_v1(
    const struct cgo_passive_rhett2_request_v1 *request,
    const struct cgo_passive_caller_io *io, struct cgo_passive_owned **out,
    char *why, size_t cap)
{
    if (out) *out = NULL;
    if (!out || !cgo_caller_port(io)) return cgo_fail(why, cap, "caller output/port missing");
    if (!request || !request->enabled) return cgo_caller_authority(why, cap);
    const struct cgo_passive_caller_request ids = {
        .request_ids = { request->request_ids[0], request->request_ids[1], request->request_ids[2] },
        .request_id_lengths = { request->request_id_lengths[0], request->request_id_lengths[1], request->request_id_lengths[2] }
    };
    if (!cgo_caller_ids(&ids)) return cgo_caller_authority(why, cap);
    return cgo_caller_selected(&ids, CGO_PASSIVE_RHETT2_THREAD,
        sizeof(CGO_PASSIVE_RHETT2_THREAD) - 1, io, out, why, cap);
}

enum cga_result cgo_passive_caller_project_v1(const struct cgo_passive_owned *owned,
    int64_t now, struct cgo_passive_capture *out, char *why, size_t cap)
{
    if (out) memset(out, 0, sizeof(*out));
    if (!owned || !out || now < owned->view.completed_monotonic_ms)
        return cgo_fail(why, cap, "caller diagnostic clock/context invalid");
    if (owned->view.result != CGA_OK) {
        fprintf(stderr, "codex passive caller: refused capture cannot project\n");
        if (why && cap) (void)snprintf(why, cap, "refused capture cannot project");
        return owned->view.result;
    }
    if (now - owned->view.started_monotonic_ms >= CGO_PASSIVE_DIAGNOSTIC_MAX_AGE_MS) {
        fprintf(stderr, "codex passive caller: diagnostic capture expired\n");
        if (why && cap) (void)snprintf(why, cap, "diagnostic capture expired");
        return CGA_STALE;
    }
    *out = owned->view.observation;
    return CGA_OK;
}
