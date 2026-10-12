/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Acceptance tests for dev.agent.mail.wait
 * (tools/command/native_devagent_mail_wait.c), run against an isolated
 * platform state root. Rows are appended through the real dev.agent.mail
 * post action, from this thread or from a second one while a wait blocks. */

#include "test/test_core.h"

#include "command/native_command.h"
#include "config/command_catalog.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "platform/private_directory.h"
#include "platform/time_compat.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
int test_devagent_mail_wait(void);
int test_devagent_mail_wait(void)
{
    printf("test_devagent_mail_wait: skipped on Windows\n");
    return 0;
}
#else
#include <pthread.h>

#define DWX_WAIT_PATH "dev.agent.mail.wait"

struct dwx_call {
    struct json_value input;
    struct zcl_command_request request;
    struct zcl_command_reply reply;
    int64_t elapsed_ms;
};

static void dwx_begin(struct dwx_call *c, const char *path, const char *schema)
{
    json_init(&c->input);
    json_set_object(&c->input);
    memset(&c->request, 0, sizeof(c->request));
    c->request.input = &c->input;
    c->request.spec =
        zcl_command_registry_find(zcl_command_catalog(), path, NULL);
    zcl_command_reply_init(&c->reply, schema);
    c->elapsed_ms = 0;
}

static void dwx_end(struct dwx_call *c)
{
    zcl_command_reply_free(&c->reply);
    json_free(&c->input);
}

static void dwx_post(const char *to, const char *ref, const char *body)
{
    struct dwx_call c;
    dwx_begin(&c, "dev.agent.mail", "zcl.agent_mail.v1");
    (void)json_push_kv_str(&c.input, "action", "post");
    (void)json_push_kv_str(&c.input, "from", "poster");
    (void)json_push_kv_str(&c.input, "to", to);
    (void)json_push_kv_str(&c.input, "kind", "note");
    (void)json_push_kv_str(&c.input, "ref", ref);
    (void)json_push_kv_str(&c.input, "body", body);
    zcl_native_handle_dev_agent_mail(&c.request, &c.reply);
    if (c.reply.status != ZCL_COMMAND_STATUS_PASSED) {
        fprintf(stderr, "devagent_mail_wait fixture: post refused: %s\n",
                c.reply.error.code);
        abort();
    }
    dwx_end(&c);
}

/* since_text NULL -> omit since; since_text "N" -> integer N when all digits
 * and no bar, else the token string. */
static void dwx_wait(struct dwx_call *c, const char *since_text,
                     const char *to, const char *ref, int64_t timeout_ms)
{
    int64_t t0;
    dwx_begin(c, DWX_WAIT_PATH, "zcl.agent_mail.v1");
    if (since_text && !strchr(since_text, '|'))
        (void)json_push_kv_int(&c->input, "since", atoll(since_text));
    else if (since_text)
        (void)json_push_kv_str(&c->input, "since", since_text);
    if (to)
        (void)json_push_kv_str(&c->input, "to", to);
    if (ref)
        (void)json_push_kv_str(&c->input, "ref", ref);
    if (timeout_ms > 0)
        (void)json_push_kv_int(&c->input, "timeout_ms", timeout_ms);
    t0 = platform_time_monotonic_ms();
    zcl_native_handle_dev_agent_mail_wait(&c->request, &c->reply);
    c->elapsed_ms = platform_time_monotonic_ms() - t0;
}

static bool dwx_ok(const struct dwx_call *c)
{
    return c->reply.status == ZCL_COMMAND_STATUS_PASSED;
}

/* Exercise the real envelope serializer, including its next-action rules. */
static bool dwx_registry_wait(const struct json_value *input,
                              struct json_value *out,
                              enum zcl_command_exit *exit_code)
{
    const struct zcl_command_registry *registry = zcl_command_catalog();
    const struct zcl_command_spec *spec =
        zcl_command_registry_find(registry, DWX_WAIT_PATH, NULL);
    struct zcl_command_context context = {
        .registry = registry,
        .granted_capabilities = ~(uint64_t)0,
        .authority_ceiling = ZCL_COMMAND_AUTH_OWNER,
    };
    char serialized[8192];
    if (!spec) return false;
    /* The public test catalog omits dev adapters; bind the actual adapter
     * while retaining its catalog schema/policy and real next validation. */
    struct zcl_command_spec executable = *spec;
    executable.handler = zcl_native_handle_dev_agent_mail_wait;
    size_t n = zcl_command_registry_execute_json(
        registry, &executable, &context, input, false, DWX_WAIT_PATH, "normal",
        0, 0, NULL, serialized, sizeof(serialized), exit_code);
    return n > 0 && json_read(out, serialized, n);
}

static int64_t dwx_count(const struct dwx_call *c)
{
    const struct json_value *v = json_get(&c->reply.data, "count");
    return v && v->type == JSON_INT ? json_get_int(v) : -1;
}

static const char *dwx_next(const struct dwx_call *c, char *out, size_t cap)
{
    const struct json_value *v = json_get(&c->reply.data, "next_since");
    (void)snprintf(out, cap, "%s",
                   v && v->type == JSON_STR ? json_get_str(v) : "");
    return out;
}

static bool dwx_row_body_has(const struct dwx_call *c, size_t i,
                             const char *needle)
{
    const struct json_value *rows = json_get(&c->reply.data, "rows");
    const char *body;
    if (!rows || rows->type != JSON_ARR || i >= json_size(rows))
        return false;
    body = json_get_str(json_get(json_at(rows, i), "body"));
    return body && strstr(body, needle) != NULL;
}

/* ── delayed poster ──────────────────────────────────────────────────────── */

struct dwx_poster {
    int delay_ms;
    const char *to;
    const char *ref;
    const char *body;
    const char *to2; /* optional second post, same delay again */
    const char *ref2;
    const char *body2;
};

static void *dwx_poster_main(void *arg)
{
    const struct dwx_poster *p = arg;
    platform_sleep_ms(p->delay_ms);
    dwx_post(p->to, p->ref, p->body);
    if (p->to2) {
        platform_sleep_ms(p->delay_ms);
        dwx_post(p->to2, p->ref2, p->body2);
    }
    return NULL;
}

static void dwx_wait_with_poster(struct dwx_call *c, const char *since,
                                 const char *to, const char *ref,
                                 int64_t timeout_ms, struct dwx_poster *p)
{
    pthread_t th;
    bool started = pthread_create(&th, NULL, dwx_poster_main, p) == 0;
    dwx_wait(c, since, to, ref, timeout_ms);
    if (started)
        (void)pthread_join(th, NULL);
}

/* ── isolated state root ─────────────────────────────────────────────────── */

static char g_dwx_saved[4096];
static bool g_dwx_had;

static void dwx_isolate(void)
{
    char base[512], state[1024];
    const char *old = getenv("XDG_STATE_HOME");
    g_dwx_had = old != NULL;
    if (old)
        (void)snprintf(g_dwx_saved, sizeof(g_dwx_saved), "%s", old);
    test_make_tmpdir(base, sizeof(base), "devagent_mail_wait", "rig");
    (void)snprintf(state, sizeof(state), "%s/state", base);
    if (!platform_private_directory_ensure(state) ||
        setenv("XDG_STATE_HOME", state, 1) != 0) {
        fprintf(stderr, "devagent_mail_wait fixture: cannot isolate\n");
        abort();
    }
}

static void dwx_restore(void)
{
    if (g_dwx_had)
        (void)setenv("XDG_STATE_HOME", g_dwx_saved, 1);
    else
        (void)unsetenv("XDG_STATE_HOME");
}

int test_devagent_mail_wait(void);
int test_devagent_mail_wait(void)
{
    int failures = 0;
    char token[4096];
    char token2[4096];
    struct dwx_call c;
    struct json_value envelope = {0};
    enum zcl_command_exit registry_exit;

    dwx_isolate();

    TEST("mail.wait: registered with since and timeout_ms keys") {
        const struct zcl_command_spec *spec = zcl_command_registry_find(
            zcl_command_catalog(), DWX_WAIT_PATH, NULL);
        ASSERT(spec != NULL);
        ASSERT(spec->input_keys && strstr(spec->input_keys, "since") != NULL);
        ASSERT(spec->input_keys &&
               strstr(spec->input_keys, "timeout_ms") != NULL);
        PASS();
    }

    TEST("mail.wait: returns at once when a matching row already exists") {
        dwx_post("bob", "r1", "first row");
        dwx_wait(&c, "0", "bob", NULL, 20000);
        ASSERT(dwx_ok(&c));
        ASSERT_EQ(dwx_count(&c), (int64_t)1);
        ASSERT(dwx_row_body_has(&c, 0, "first row"));
        ASSERT(c.elapsed_ms < 1500);
        (void)dwx_next(&c, token, sizeof(token));
        ASSERT(token[0] != '\0');
        dwx_end(&c);
        PASS();
    }

    TEST("mail.wait: blocks, then returns when another thread posts") {
        struct dwx_poster p = {.delay_ms = 400, .to = "bob", .ref = "r2",
                               .body = "second row"};
        dwx_wait_with_poster(&c, token, "bob", NULL, 20000, &p);
        ASSERT(dwx_ok(&c));
        ASSERT_EQ(dwx_count(&c), (int64_t)1);
        ASSERT(dwx_row_body_has(&c, 0, "second row"));
        ASSERT(c.elapsed_ms >= 300);
        ASSERT(c.elapsed_ms < 5000);
        (void)dwx_next(&c, token, sizeof(token));
        dwx_end(&c);
        PASS();
    }

    TEST("mail.wait: rows that miss the filters do not end the wait") {
        struct dwx_poster p = {.delay_ms = 200, .to = "carol", .ref = "want",
                               .body = "wrong recipient",
                               .to2 = "bob", .ref2 = "other",
                               .body2 = "wrong ref"};
        dwx_wait_with_poster(&c, token, "bob", "want", 1200, &p);
        ASSERT(!dwx_ok(&c));
        ASSERT_STR_EQ(c.reply.error.code, "WAIT_TIMEOUT");
        ASSERT_EQ((int)c.reply.status, (int)ZCL_COMMAND_STATUS_BLOCKED);
        ASSERT(c.elapsed_ms >= 1100);
        ASSERT(c.elapsed_ms <= 1200 + 1000);
        ASSERT(strstr(c.reply.error.evidence, "since=") != NULL);
        dwx_end(&c);
        PASS();
    }

    TEST("mail.wait: following next_since never returns a row twice") {
        dwx_post("bob", "r3", "third row");
        dwx_post("bob", "r4", "fourth row");
        dwx_wait(&c, token, "bob", NULL, 20000);
        ASSERT(dwx_ok(&c));
        ASSERT_EQ(dwx_count(&c), (int64_t)3);
        (void)dwx_next(&c, token2, sizeof(token2));
        dwx_end(&c);
        dwx_wait(&c, token2, "bob", NULL, 600);
        ASSERT(!dwx_ok(&c));
        ASSERT_STR_EQ(c.reply.error.code, "WAIT_TIMEOUT");
        dwx_end(&c);
        dwx_post("bob", "r5", "fifth row");
        dwx_wait(&c, token2, "bob", NULL, 20000);
        ASSERT(dwx_ok(&c));
        ASSERT_EQ(dwx_count(&c), (int64_t)1);
        ASSERT(dwx_row_body_has(&c, 0, "fifth row"));
        dwx_end(&c);
        PASS();
    }

    TEST("mail.wait: refuses timeout_ms over the maximum and a missing since") {
        dwx_wait(&c, "0", "bob", NULL, 600001);
        ASSERT(!dwx_ok(&c));
        ASSERT_STR_EQ(c.reply.error.code, "INVALID_INPUT");
        dwx_end(&c);
        dwx_wait(&c, NULL, "bob", NULL, 100);
        ASSERT(!dwx_ok(&c));
        ASSERT_STR_EQ(c.reply.error.code, "INVALID_INPUT");
        dwx_end(&c);
        PASS();
    }

    TEST("mail.wait: registry timeout preserves typed cursor and all filters") {
        dwx_begin(&c, DWX_WAIT_PATH, "zcl.agent_mail.v1");
        ASSERT(json_push_kv_str(&c.input, "since", token2));
        ASSERT(json_push_kv_str(&c.input, "to", "unmatched"));
        ASSERT(json_push_kv_str(&c.input, "ref", "quoted\"\\ref"));
        ASSERT(json_push_kv_str(&c.input, "from", "poster"));
        ASSERT(json_push_kv_str(&c.input, "kind", "note"));
        ASSERT(json_push_kv_int(&c.input, "timeout_ms", 1));
        ASSERT(dwx_registry_wait(&c.input, &envelope, &registry_exit));
        ASSERT_STR_EQ(json_get_str(json_get(json_get(&envelope, "error"),
                                            "code")), "WAIT_TIMEOUT");
        ASSERT_EQ(registry_exit, ZCL_COMMAND_EXIT_BLOCKED);
        const struct json_value *next = json_get(&envelope, "next");
        ASSERT(next && next->type == JSON_ARR && next->num_children == 1);
        const struct json_value *item = &next->children[0];
        ASSERT_STR_EQ(json_get_str(json_get(item, "command")), "dev.agent.mail");
        const struct json_value *pull = json_get(item, "input");
        ASSERT_STR_EQ(json_get_str(json_get(pull, "action")), "pull");
        const char *keys[] = {"since", "to", "ref", "from", "kind"};
        for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); ++i)
            ASSERT_STR_EQ(json_get_str(json_get(pull, keys[i])),
                          json_get_str(json_get(&c.input, keys[i])));
        ASSERT(!json_get(pull, "timeout_ms"));
        json_free(&envelope);
        dwx_end(&c);
        PASS();
    }

    TEST("mail.wait: oversized optional next cannot corrupt timeout envelope") {
        char long_ref[700];
        memset(long_ref, 'x', sizeof(long_ref) - 1);
        long_ref[sizeof(long_ref) - 1] = '\0';
        dwx_begin(&c, DWX_WAIT_PATH, "zcl.agent_mail.v1");
        ASSERT(json_push_kv_int(&c.input, "since", 0));
        ASSERT(json_push_kv_str(&c.input, "to", "unmatched"));
        ASSERT(json_push_kv_str(&c.input, "ref", long_ref));
        ASSERT(json_push_kv_int(&c.input, "timeout_ms", 1));
        ASSERT(dwx_registry_wait(&c.input, &envelope, &registry_exit));
        ASSERT_EQ(registry_exit, ZCL_COMMAND_EXIT_BLOCKED);
        ASSERT_STR_EQ(json_get_str(json_get(json_get(&envelope, "error"),
                                            "code")), "WAIT_TIMEOUT");
        const struct json_value *next = json_get(&envelope, "next");
        ASSERT(next && next->type == JSON_ARR && next->num_children == 1);
        const struct json_value *item = &next->children[0];
        ASSERT_STR_EQ(json_get_str(json_get(item, "command")),
                      "discover.describe");
        ASSERT_STR_EQ(json_get_str(json_get(json_get(item, "input"), "path")),
                      DWX_WAIT_PATH);
        json_free(&envelope);
        dwx_end(&c);
        dwx_wait(&c, token2, "bob", NULL, 100);
        ASSERT(dwx_ok(&c));
        ASSERT_EQ(dwx_count(&c), (int64_t)1);
        ASSERT(dwx_row_body_has(&c, 0, "fifth row"));
        dwx_end(&c);
        PASS();
    }

_test_next:;
    json_free(&envelope);
    dwx_restore();
    if (failures == 0)
        printf("test_devagent_mail_wait: all passed\n");
    else
        printf("test_devagent_mail_wait: %d FAILED\n", failures);
    return failures;
}
#endif
