/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ACCEPTANCE BAR for fleet.triggers (tools/command/native_fleet_triggers_*.c).
 *
 * Every case runs against an isolated XDG_STATE_HOME/HOME and a fixed injected
 * clock, proving the evaluator's own behavior — cursor advance, dry-run,
 * truncation, absent fields, JSON shape, stamped clock.
 *
 * Handlers are called directly, with the input also validated through the
 * real registry so a key the .def never declared is caught here.
 */

#include "test/test_core.h"

#include "command/native_command.h"
#include "command/native_fleet_triggers.h"
#include "config/command_catalog.h"
#include "controllers/rpc_client.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "platform/clock.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#if !defined(_WIN32)
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>
#endif

#define FTX_PATH "fleet.triggers.check"

/* ── isolated state root ─────────────────────────────────────────────── */

static char g_ftx_state[PATH_MAX];
static char g_ftx_home[PATH_MAX];
static char g_ftx_saved_xdg[PATH_MAX];
static char g_ftx_saved_home[PATH_MAX];
static bool g_ftx_saved;

static void ftx_isolate(const char *tag)
{
    char base[PATH_MAX - 64];
    test_make_tmpdir(base, sizeof(base), "fleet_triggers", tag);
    if (!g_ftx_saved) {
        g_ftx_saved = true;
        const char *xdg = getenv("XDG_STATE_HOME");
        const char *home = getenv("HOME");
        (void)snprintf(g_ftx_saved_xdg, sizeof(g_ftx_saved_xdg), "%s",
                      xdg ? xdg : "");
        (void)snprintf(g_ftx_saved_home, sizeof(g_ftx_saved_home), "%s",
                      home ? home : "");
    }
    (void)snprintf(g_ftx_state, sizeof(g_ftx_state), "%s/state", base);
    (void)snprintf(g_ftx_home, sizeof(g_ftx_home), "%s/home", base);
    setenv("XDG_STATE_HOME", g_ftx_state, 1);
    setenv("HOME", g_ftx_home, 1);
}

static void ftx_restore(void)
{
    if (!g_ftx_saved)
        return;
    if (g_ftx_saved_xdg[0])
        setenv("XDG_STATE_HOME", g_ftx_saved_xdg, 1);
    else
        unsetenv("XDG_STATE_HOME");
    if (g_ftx_saved_home[0])
        setenv("HOME", g_ftx_saved_home, 1);
    else
        unsetenv("HOME");
}

static void ftx_mkdir_p(const char *path)
{
    char copy[PATH_MAX];
    size_t length = strlen(path);
    if (!length || length >= sizeof copy)
        return;
    memcpy(copy, path, length + 1u);
    for (char *p = copy + (copy[0] == '/' ? 1 : 0); ; p++) {
        if (*p != '/' && *p != '\0')
            continue;
        char saved = *p;
        *p = '\0';
        if (copy[0])
            (void)mkdir(copy, 0700);
        *p = saved;
        if (!saved)
            break;
    }
}

/* Write `content` to the path a source resolves to, creating parent
 * directories first. */
static void ftx_write_file(const char *path, const char *content)
{
    char dir[PATH_MAX];
    (void)snprintf(dir, sizeof dir, "%s", path);
    char *slash = strrchr(dir, '/');
    if (slash)
        *slash = 0;
    ftx_mkdir_p(dir);
    FILE *f = fopen(path, "wb");
    if (!f)
        return;
    (void)fputs(content, f);
    fclose(f);
}

/* ── fixed clock: every "ts" this run stamps must be exactly this ──────── */

#define FTX_FAKE_WALL_MS  1757000000000LL /* 2025-09-04T15:33:20Z */
#define FTX_FAKE_TS_ISO  "2025-09-04T15:33:20Z"

static int64_t ftx_fake_now_mono(void *self)
{
    (void)self;
    return 1;
}

static int64_t ftx_fake_now_wall(void *self)
{
    (void)self;
    return FTX_FAKE_WALL_MS;
}

static void ftx_install_clock(void)
{
    static const clock_iface_t iface = {
        .now_monotonic_ns = ftx_fake_now_mono,
        .now_wall_ms = ftx_fake_now_wall,
        .self = NULL,
    };
    clock_set_default(&iface);
}

/* ── one in-process `fleet.triggers.check` call ─────────────────────────── */

struct ftx_call {
    struct json_value input;
    struct zcl_command_request request;
    struct zcl_command_reply reply;
};

static void ftx_begin(struct ftx_call *c, bool dry_run, int64_t since_s)
{
    json_init(&c->input);
    json_set_object(&c->input);
    if (dry_run)
        (void)json_push_kv_bool(&c->input, "dry-run", true);
    if (since_s > 0)
        (void)json_push_kv_int(&c->input, "since", since_s);
    memset(&c->request, 0, sizeof(c->request));
    c->request.input = &c->input;
    c->request.spec = zcl_command_registry_find(zcl_command_catalog(),
                                                FTX_PATH, NULL);
    zcl_command_reply_init(&c->reply, "zcl.fleet_triggers_check.v1");
}

static bool ftx_run(struct ftx_call *c)
{
    char why[256];
    if (c->request.spec &&
        !zcl_command_registry_input_validate(c->request.spec, &c->input, why,
                                             sizeof(why))) {
        printf("[input rejected: %s] ", why);
        return false;
    }
    zcl_native_handle_fleet_triggers_check(&c->request, &c->reply);
    return true;
}

static void ftx_end(struct ftx_call *c)
{
    zcl_command_reply_free(&c->reply);
    json_free(&c->input);
}

static int64_t ftx_int(const struct ftx_call *c, const char *key)
{
    const struct json_value *v = json_get(&c->reply.data, key);
    return v ? json_get_int(v) : -1;
}

/* ── fired.jsonl line counting, without trusting any parser but our own
 * newline count ─────────────────────────────────────────────────────── */

static size_t ftx_count_lines(const char *path)
{
    FILE *f = fopen(path, "rb");
    if (!f)
        return 0;
    size_t n = 0;
    int ch;
    while ((ch = fgetc(f)) != EOF)
        if (ch == '\n')
            n++;
    fclose(f);
    return n;
}

static bool ftx_file_contains(const char *path, const char *needle)
{
    FILE *f = fopen(path, "rb");
    if (!f)
        return false;
    char buf[8192];
    size_t n = fread(buf, 1, sizeof buf - 1, f);
    fclose(f);
    buf[n] = 0;
    return strstr(buf, needle) != NULL;
}

/* Capture stdout around one ftx_run call, into a caller buffer. */
static bool ftx_run_captured(struct ftx_call *c, char *out, size_t cap)
{
    fflush(stdout);
    FILE *capture = tmpfile();
    if (!capture)
        return false;
    int saved_out = dup(STDOUT_FILENO);
    if (saved_out < 0 || dup2(fileno(capture), STDOUT_FILENO) < 0) {
        if (saved_out >= 0)
            close(saved_out);
        fclose(capture);
        return false;
    }
    bool ran = ftx_run(c);
    fflush(stdout);
    (void)dup2(saved_out, STDOUT_FILENO);
    close(saved_out);
    rewind(capture);
    size_t n = fread(out, 1, cap - 1, capture);
    out[n] = 0;
    fclose(capture);
    return ran;
}

/* Each case below is one property of the acceptance bar above, split out to
 * keep per-function cyclomatic complexity under the cap. */

static int ftx_case_landed_ledger_once(void)
{
    int failures = 0;
    char landing_path[PATH_MAX], fired_path[PATH_MAX];

    ftx_isolate("landed_ledger_once");
    ftx_install_clock();
    ASSERT(zcl_trigger_landing_path(landing_path, sizeof landing_path));
    ASSERT(zcl_trigger_fired_ledger_path(fired_path, sizeof fired_path));
    ftx_write_file(landing_path,
                  "{\"seq\":1,\"ts\":\"2026-09-06T10:00:00Z\","
                  "\"state\":\"landed\",\"note\":\"demo\"}\n");

    printf("fleet_triggers: landed row ledgers exactly once across two "
          "runs... ");
    struct ftx_call c1;
    ftx_begin(&c1, false, 0);
    ASSERT(ftx_run(&c1));
    ASSERT_EQ(ftx_int(&c1, "checked"), 1);
    ASSERT_EQ(ftx_int(&c1, "fired"), 1);
    ftx_end(&c1);
    ASSERT_EQ((int64_t)ftx_count_lines(fired_path), 1);
    ASSERT(ftx_file_contains(fired_path, "landing_landed_to_ledger"));

    struct ftx_call c2;
    ftx_begin(&c2, false, 0);
    ASSERT(ftx_run(&c2));
    ASSERT_EQ(ftx_int(&c2, "checked"), 0);
    ASSERT_EQ(ftx_int(&c2, "fired"), 0);
    ftx_end(&c2);
    ASSERT_EQ((int64_t)ftx_count_lines(fired_path), 1);
    clock_reset_default();
    PASS();
_test_next:;
    return failures;
}

static int ftx_case_failed_prints(void)
{
    int failures = 0;
    char landing_path[PATH_MAX], fired_path[PATH_MAX];

    ftx_isolate("failed_prints");
    ASSERT(zcl_trigger_landing_path(landing_path, sizeof landing_path));
    ASSERT(zcl_trigger_fired_ledger_path(fired_path, sizeof fired_path));
    ftx_write_file(landing_path,
                  "{\"seq\":1,\"ts\":\"2026-09-06T10:00:00Z\","
                  "\"state\":\"failed\",\"note\":\"demo\"}\n");

    printf("fleet_triggers: failed row prints, does not ledger... ");
    struct ftx_call c;
    ftx_begin(&c, false, 0);
    char out[4096];
    ASSERT(ftx_run_captured(&c, out, sizeof out));
    ASSERT(strstr(out, "TRIGGER landing_failed_print landing_outcomes "
                      "state=failed") != NULL);
    ASSERT_EQ(ftx_int(&c, "fired"), 1);
    ftx_end(&c);
    /* print never writes the ledger file at all. */
    FILE *never = fopen(fired_path, "rb");
    ASSERT(never == NULL);
    PASS();
_test_next:;
    return failures;
}

static int ftx_case_dry_run_no_advance(void)
{
    int failures = 0;
    char landing_path[PATH_MAX];

    ftx_isolate("dry_run_no_advance");
    ASSERT(zcl_trigger_landing_path(landing_path, sizeof landing_path));
    ftx_write_file(landing_path,
                  "{\"seq\":1,\"ts\":\"2026-09-06T10:00:00Z\","
                  "\"state\":\"landed\",\"note\":\"demo\"}\n");

    printf("fleet_triggers: --dry-run fires but never advances the "
          "cursor... ");
    struct ftx_call c1;
    ftx_begin(&c1, true, 0);
    ASSERT(ftx_run(&c1));
    ASSERT_EQ(ftx_int(&c1, "checked"), 1);
    ASSERT_EQ(ftx_int(&c1, "fired"), 1);
    ftx_end(&c1);

    struct ftx_call c2;
    ftx_begin(&c2, true, 0);
    ASSERT(ftx_run(&c2));
    ASSERT_EQ(ftx_int(&c2, "checked"), 1);
    ASSERT_EQ(ftx_int(&c2, "fired"), 1);
    ftx_end(&c2);
    PASS();
_test_next:;
    return failures;
}

static int ftx_case_truncated_restarts(void)
{
    int failures = 0;
    char landing_path[PATH_MAX];

    ftx_isolate("truncated_restarts");
    ASSERT(zcl_trigger_landing_path(landing_path, sizeof landing_path));
    ftx_write_file(landing_path,
                  "{\"seq\":1,\"ts\":\"2026-09-06T10:00:00Z\","
                  "\"state\":\"landed\",\"note\":\"one\"}\n");

    printf("fleet_triggers: a shrunk source restarts from byte zero... ");
    struct ftx_call c1;
    ftx_begin(&c1, false, 0);
    ASSERT(ftx_run(&c1));
    ASSERT_EQ(ftx_int(&c1, "checked"), 1);
    ftx_end(&c1);

    /* Shrink the file (a rotated/replaced outcomes.jsonl), then write a
     * single fresh row shorter than what the cursor last saw. */
    ftx_write_file(landing_path,
                  "{\"seq\":1,\"ts\":\"2026-09-06T10:01:00Z\","
                  "\"state\":\"landed\"}\n");
    struct ftx_call c2;
    ftx_begin(&c2, false, 0);
    ASSERT(ftx_run(&c2));
    ASSERT_EQ(ftx_int(&c2, "checked"), 1);
    ASSERT_EQ(ftx_int(&c2, "fired"), 1);
    ftx_end(&c2);
    PASS();
_test_next:;
    return failures;
}

static int ftx_case_unknown_field_never_fires(void)
{
    int failures = 0;
    char landing_path[PATH_MAX];

    ftx_isolate("unknown_field_never_fires");
    ASSERT(zcl_trigger_landing_path(landing_path, sizeof landing_path));
    /* No "state" key: every trigger reading "state" sees it as absent and
     * never fires, "ne" included. */
    ftx_write_file(landing_path,
                  "{\"seq\":1,\"ts\":\"2026-09-06T10:00:00Z\","
                  "\"note\":\"no state field\"}\n");

    printf("fleet_triggers: a row missing the matched field never "
          "fires... ");
    struct ftx_call c;
    ftx_begin(&c, false, 0);
    ASSERT(ftx_run(&c));
    ASSERT_EQ(ftx_int(&c, "checked"), 1);
    ASSERT_EQ(ftx_int(&c, "fired"), 0);
    ftx_end(&c);
    PASS();
_test_next:;
    return failures;
}

static int ftx_case_board_and_experiment_sources(void)
{
    int failures = 0;
    char board_path[PATH_MAX], exp_path[PATH_MAX];

    ftx_isolate("board_and_experiment_sources");
    ASSERT(zcl_trigger_board_path(board_path, sizeof board_path));
    ASSERT(zcl_trigger_experiment_path(exp_path, sizeof exp_path));
    ftx_write_file(board_path,
                  "{\"ts\":\"2026-09-06T10:00:00Z\",\"id\":\"a1\","
                  "\"host\":\"h\",\"agent\":\"x\",\"kind\":\"need\","
                  "\"ref\":\"\",\"text\":\"help\"}\n");
    ftx_write_file(
        exp_path,
        "ts\tkind\tbox\ttask_id\ttask_class\tstory\texecutor\tharness\t"
        "model\teffort\ttokens_in\ttokens_out\ttokens_cache\t"
        "tokens_reasoning\ttool_uses\tturns\twall_s\toutcome\t"
        "lines_added\tlines_removed\tdefects\tnote\n"
        "2026-09-06T10:00:00Z\tresult\tnode1\tt1\tread\ts\te\th\tm\tlow\t"
        "1\t1\t0\t0\t0\t1\t1\ttimeout\t0\t0\t0\tn\n");

    printf("fleet_triggers: board need and experiment timeout both "
          "fire... ");
    struct ftx_call c;
    ftx_begin(&c, false, 0);
    ASSERT(ftx_run(&c));
    ASSERT_EQ(ftx_int(&c, "checked"), 2);
    ASSERT_EQ(ftx_int(&c, "fired"), 2);
    ftx_end(&c);
    PASS();
_test_next:;
    return failures;
}

static int ftx_case_json_well_formed(void)
{
    int failures = 0;
    char landing_path[PATH_MAX];

    ftx_isolate("json_well_formed");
    ASSERT(zcl_trigger_landing_path(landing_path, sizeof landing_path));
    ftx_write_file(landing_path,
                  "{\"seq\":1,\"ts\":\"2026-09-06T10:00:00Z\","
                  "\"state\":\"landed\"}\n");

    printf("fleet_triggers: the check reply serializes and re-parses "
          "cleanly... ");
    struct ftx_call c;
    ftx_begin(&c, false, 0);
    ASSERT(ftx_run(&c));
    char buf[65536];
    size_t n = json_write(&c.reply.data, buf, sizeof buf);
    ASSERT(n > 0 && n < sizeof buf);
    struct json_value reread;
    ASSERT(json_read(&reread, buf, n));
    ASSERT(reread.type == JSON_OBJ);
    ASSERT(json_get(&reread, "checked") != NULL);
    ASSERT(json_get(&reread, "fired_ids") != NULL);
    json_free(&reread);
    ftx_end(&c);
    PASS();
_test_next:;
    return failures;
}

static int ftx_case_clock_stamps_ts(void)
{
    int failures = 0;
    char landing_path[PATH_MAX], fired_path[PATH_MAX];

    ftx_isolate("clock_stamps_ts");
    ftx_install_clock();
    ASSERT(zcl_trigger_landing_path(landing_path, sizeof landing_path));
    ASSERT(zcl_trigger_fired_ledger_path(fired_path, sizeof fired_path));
    ftx_write_file(landing_path,
                  "{\"seq\":1,\"ts\":\"2026-09-06T10:00:00Z\","
                  "\"state\":\"landed\"}\n");

    printf("fleet_triggers: the injected clock stamps the ledger row's "
          "ts... ");
    struct ftx_call c;
    ftx_begin(&c, false, 0);
    ASSERT(ftx_run(&c));
    ftx_end(&c);
    ASSERT(ftx_file_contains(fired_path, "\"ts\":\"" FTX_FAKE_TS_ISO "\""));
    clock_reset_default();
    PASS();
_test_next:;
    return failures;
}

/* Exercises `fleet.triggers.list`, so the registry accessor and its
 * rendering are proven too, not only `check`. */
static int ftx_case_list_enumerates(void)
{
    int failures = 0;

    printf("fleet_triggers: list enumerates the closed registry... ");
    struct zcl_command_request req;
    struct zcl_command_reply reply;
    struct json_value input;
    json_init(&input);
    json_set_object(&input);
    memset(&req, 0, sizeof req);
    req.input = &input;
    zcl_command_reply_init(&reply, "zcl.fleet_triggers_list.v1");
    zcl_native_handle_fleet_triggers_list(&req, &reply);
    ASSERT(reply.status == ZCL_COMMAND_STATUS_PASSED);
    ASSERT_EQ((int64_t)json_get_int(json_get(&reply.data, "count")),
             (int64_t)zcl_trigger_count());
    ASSERT(zcl_trigger_count() >= 6);
    zcl_command_reply_free(&reply);
    json_free(&input);
    PASS();
_test_next:;
    return failures;
}

/* ── github_comments ingest + board_post ─────────────────────────────── */

static void ftx_ingest_call(const char *source, const char *file,
                            struct zcl_command_reply *reply)
{
    struct json_value input;
    json_init(&input);
    json_set_object(&input);
    if (source)
        (void)json_push_kv_str(&input, "source", source);
    if (file)
        (void)json_push_kv_str(&input, "file", file);
    struct zcl_command_request req;
    memset(&req, 0, sizeof req);
    req.input = &input;
    req.spec = zcl_command_registry_find(zcl_command_catalog(),
                                         "fleet.triggers.ingest", NULL);
    zcl_command_reply_init(reply, "zcl.fleet_triggers_ingest.v1");
    char why[256];
    if (!req.spec ||
        zcl_command_registry_input_validate(req.spec, &input, why,
                                            sizeof why))
        zcl_native_handle_fleet_triggers_ingest(&req, reply);
    else
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                              ZCL_COMMAND_EXIT_INVALID, "INPUT_REJECTED",
                              "validate", false, false, why, "input");
    json_free(&input);
}

/* Refusals: an unknown source, and a missing file. Neither touches the
 * github_comments file at all. */
static int ftx_case_ingest_refuses(void)
{
    int failures = 0;

    printf("fleet_triggers: ingest refuses an unknown source and a missing "
          "file... ");
    ftx_isolate("ingest_refuses");

    struct zcl_command_reply reply;
    ftx_ingest_call("slack", "/tmp/whatever.jsonl", &reply);
    ASSERT(reply.status != ZCL_COMMAND_STATUS_PASSED);
    zcl_command_reply_free(&reply);

    ftx_ingest_call("github", NULL, &reply);
    ASSERT(reply.status != ZCL_COMMAND_STATUS_PASSED);
    zcl_command_reply_free(&reply);

    char comments_path[PATH_MAX];
    ASSERT(zcl_trigger_github_comments_path(comments_path,
                                            sizeof comments_path));
    struct stat st;
    ASSERT(stat(comments_path, &st) != 0);
    PASS();
_test_next:;
    return failures;
}

/* A line missing a required field is skipped, not fatal; a well-formed line
 * is appended. */
static int ftx_case_ingest_skips_malformed(void)
{
    int failures = 0;

    printf("fleet_triggers: ingest skips a malformed line, keeps a good "
          "one... ");
    ftx_isolate("ingest_skips_malformed");

    char base[PATH_MAX];
    test_make_tmpdir(base, sizeof base, "fleet_triggers_ingest", "src");
    char src_path[PATH_MAX];
    (void)snprintf(src_path, sizeof src_path, "%s/comments.jsonl", base);
    ftx_write_file(src_path,
                  "{\"kind\":\"comment\",\"owner\":\"z23c\"}\n"
                  "{\"kind\":\"comment\",\"owner\":\"z23c\",\"repo\":\"z23\","
                  "\"number\":\"47\",\"comment_id\":\"c1\","
                  "\"author\":\"a-reviewer\",\"url\":\"https://example.invalid/"
                  "c1\",\"body\":\"first watch row\","
                  "\"ts\":\"2026-09-06T10:00:00Z\"}\n");

    struct zcl_command_reply reply;
    ftx_ingest_call("github", src_path, &reply);
    ASSERT(reply.status == ZCL_COMMAND_STATUS_PASSED);
    ASSERT_EQ(json_get_int(json_get(&reply.data, "appended")), 1);
    zcl_command_reply_free(&reply);

    char comments_path[PATH_MAX];
    ASSERT(zcl_trigger_github_comments_path(comments_path,
                                            sizeof comments_path));
    ASSERT_EQ((int64_t)ftx_count_lines(comments_path), 1);
    ASSERT(ftx_file_contains(comments_path, "first watch row"));
    PASS();
_test_next:;
    return failures;
}

/* The board_post action reaches the same native call `fleet board post` uses
 * (the `fleet_board` RPC method), and a fired trigger's text is templated
 * over the row's own "body" field. */
static char g_ftx_board_method[64];
static char g_ftx_board_params[FLEET_BOARD_LINE_MAX + 256];
static int g_ftx_board_calls;

static char *ftx_board_rpc_hook(const char *method, const char *params_json)
{
    g_ftx_board_calls++;
    (void)snprintf(g_ftx_board_method, sizeof g_ftx_board_method, "%s",
                  method ? method : "");
    (void)snprintf(g_ftx_board_params, sizeof g_ftx_board_params, "%s",
                  params_json ? params_json : "");
    if (method && strcmp(method, "fleet_board") == 0)
        return strdup("{\"ok\":true,\"id\":\""
                     "0000000000000000000000000000000000000000000000000000"
                     "000000000000\",\"kind\":\"note\"}");
    return NULL;
}

static int ftx_case_github_comment_fires_board_post(void)
{
    int failures = 0;

    printf("fleet_triggers: an ingested github comment fires a board "
          "post... ");
    ftx_isolate("github_board_post");
    ftx_install_clock();

    char base[PATH_MAX];
    test_make_tmpdir(base, sizeof base, "fleet_triggers_ingest", "fire");
    char src_path[PATH_MAX];
    (void)snprintf(src_path, sizeof src_path, "%s/comments.jsonl", base);
    ftx_write_file(src_path,
                  "{\"kind\":\"comment\",\"owner\":\"z23c\",\"repo\":\"z23\","
                  "\"number\":\"47\",\"comment_id\":\"c9\","
                  "\"author\":\"a-reviewer\",\"url\":\"https://example.invalid/"
                  "c9\",\"body\":\"new comment on discussion 47\","
                  "\"ts\":\"2025-09-04T15:00:00Z\"}\n");
    struct zcl_command_reply ingest_reply;
    ftx_ingest_call("github", src_path, &ingest_reply);
    ASSERT(ingest_reply.status == ZCL_COMMAND_STATUS_PASSED);
    zcl_command_reply_free(&ingest_reply);

    g_ftx_board_calls = 0;
    node_rpc_client_set_test_hook(ftx_board_rpc_hook);
    struct ftx_call c;
    ftx_begin(&c, false, 0);
    ASSERT(ftx_run(&c));
    ASSERT(c.reply.status == ZCL_COMMAND_STATUS_PASSED);
    ASSERT_EQ(ftx_int(&c, "fired"), 1);
    ftx_end(&c);
    node_rpc_client_set_test_hook(NULL);

    ASSERT_EQ(g_ftx_board_calls, 1);
    ASSERT(strcmp(g_ftx_board_method, "fleet_board") == 0);
    ASSERT(strstr(g_ftx_board_params, "\"kind\":\"note\"") != NULL);
    ASSERT(strstr(g_ftx_board_params, "new comment on discussion 47") !=
          NULL);
    ASSERT(strstr(g_ftx_board_params, "github_comment_to_board") != NULL);
    clock_reset_default();
    PASS();
_test_next:;
    return failures;
}

static char *ftx_no_node_rpc_hook(const char *method, const char *params_json)
{
    (void)method;
    (void)params_json;
    return NULL; /* node_rpc_call's own "nothing answered" convention */
}

/* No node answering: the action fails closed. The row is not fired, the
 * cursor holds before it, and `check` exits non-zero with a typed refusal
 * naming the trigger. */
static int ftx_case_board_post_no_node(void)
{
    int failures = 0;

    printf("fleet_triggers: with no node running, board_post refuses and "
          "holds the cursor... ");
    ftx_isolate("github_no_node");
    ftx_install_clock();

    char base[PATH_MAX];
    test_make_tmpdir(base, sizeof base, "fleet_triggers_ingest", "nonode");
    char src_path[PATH_MAX];
    (void)snprintf(src_path, sizeof src_path, "%s/comments.jsonl", base);
    ftx_write_file(src_path,
                  "{\"kind\":\"comment\",\"owner\":\"z23c\",\"repo\":\"z23\","
                  "\"number\":\"47\",\"comment_id\":\"c10\","
                  "\"author\":\"a-reviewer\",\"url\":\"https://example.invalid/"
                  "c10\",\"body\":\"no node is running\","
                  "\"ts\":\"2025-09-04T15:00:00Z\"}\n");
    struct zcl_command_reply ingest_reply;
    ftx_ingest_call("github", src_path, &ingest_reply);
    ASSERT(ingest_reply.status == ZCL_COMMAND_STATUS_PASSED);
    zcl_command_reply_free(&ingest_reply);

    node_rpc_client_set_test_hook(ftx_no_node_rpc_hook);
    struct ftx_call c1;
    ftx_begin(&c1, false, 0);
    ASSERT(ftx_run(&c1));
    ASSERT(c1.reply.status != ZCL_COMMAND_STATUS_PASSED);
    ASSERT(c1.reply.exit_code != ZCL_COMMAND_EXIT_OK);
    ASSERT_EQ(ftx_int(&c1, "checked"), 1);
    ASSERT_EQ(ftx_int(&c1, "fired"), 0);
    ASSERT_EQ(ftx_int(&c1, "failed"), 1);
    ASSERT(strstr(c1.reply.error.message, "github_comment_to_board") != NULL);
    ftx_end(&c1);

    /* The cursor held: a second check with the same failing node still
     * sees the same row and fails the same way, not "checked 0". */
    struct ftx_call c2;
    ftx_begin(&c2, false, 0);
    ASSERT(ftx_run(&c2));
    ASSERT(c2.reply.status != ZCL_COMMAND_STATUS_PASSED);
    ASSERT_EQ(ftx_int(&c2, "checked"), 1);
    ASSERT_EQ(ftx_int(&c2, "fired"), 0);
    ASSERT_EQ(ftx_int(&c2, "failed"), 1);
    ftx_end(&c2);
    node_rpc_client_set_test_hook(NULL);
    clock_reset_default();
    PASS();
_test_next:;
    return failures;
}

/* Once the node answers, the same held row fires exactly once and the cursor
 * advances: a failed action is retried, not lost or double-fired. */
static int ftx_case_board_post_retries_then_fires(void)
{
    int failures = 0;

    printf("fleet_triggers: a held row retries and fires once the node "
          "answers... ");
    ftx_isolate("github_retry_fires");
    ftx_install_clock();

    char base[PATH_MAX];
    test_make_tmpdir(base, sizeof base, "fleet_triggers_ingest", "retry");
    char src_path[PATH_MAX];
    (void)snprintf(src_path, sizeof src_path, "%s/comments.jsonl", base);
    ftx_write_file(src_path,
                  "{\"kind\":\"comment\",\"owner\":\"z23c\",\"repo\":\"z23\","
                  "\"number\":\"47\",\"comment_id\":\"c11\","
                  "\"author\":\"a-reviewer\",\"url\":\"https://example.invalid/"
                  "c11\",\"body\":\"retry me\","
                  "\"ts\":\"2025-09-04T15:00:00Z\"}\n");
    struct zcl_command_reply ingest_reply;
    ftx_ingest_call("github", src_path, &ingest_reply);
    ASSERT(ingest_reply.status == ZCL_COMMAND_STATUS_PASSED);
    zcl_command_reply_free(&ingest_reply);

    node_rpc_client_set_test_hook(ftx_no_node_rpc_hook);
    struct ftx_call c1;
    ftx_begin(&c1, false, 0);
    ASSERT(ftx_run(&c1));
    ASSERT(c1.reply.status != ZCL_COMMAND_STATUS_PASSED);
    ASSERT_EQ(ftx_int(&c1, "fired"), 0);
    ASSERT_EQ(ftx_int(&c1, "failed"), 1);
    ftx_end(&c1);

    g_ftx_board_calls = 0;
    node_rpc_client_set_test_hook(ftx_board_rpc_hook);
    struct ftx_call c2;
    ftx_begin(&c2, false, 0);
    ASSERT(ftx_run(&c2));
    ASSERT(c2.reply.status == ZCL_COMMAND_STATUS_PASSED);
    ASSERT_EQ(ftx_int(&c2, "checked"), 1);
    ASSERT_EQ(ftx_int(&c2, "fired"), 1);
    ASSERT_EQ(ftx_int(&c2, "failed"), 0);
    ftx_end(&c2);
    ASSERT_EQ(g_ftx_board_calls, 1);

    /* The cursor advanced: a third check sees nothing new. */
    struct ftx_call c3;
    ftx_begin(&c3, false, 0);
    ASSERT(ftx_run(&c3));
    ASSERT(c3.reply.status == ZCL_COMMAND_STATUS_PASSED);
    ASSERT_EQ(ftx_int(&c3, "checked"), 0);
    ASSERT_EQ(ftx_int(&c3, "fired"), 0);
    ftx_end(&c3);
    node_rpc_client_set_test_hook(NULL);
    clock_reset_default();
    PASS();
_test_next:;
    return failures;
}

/* A later row waits behind a failed one: only the first is counted
 * (checked=1) until it succeeds. */
static int ftx_case_later_row_waits_behind_failed(void)
{
    int failures = 0;

    printf("fleet_triggers: a later row waits behind a failed one... ");
    ftx_isolate("github_later_waits");
    ftx_install_clock();

    char base[PATH_MAX];
    test_make_tmpdir(base, sizeof base, "fleet_triggers_ingest", "waits");
    char src_path[PATH_MAX];
    (void)snprintf(src_path, sizeof src_path, "%s/comments.jsonl", base);
    ftx_write_file(src_path,
                  "{\"kind\":\"comment\",\"owner\":\"z23c\",\"repo\":\"z23\","
                  "\"number\":\"47\",\"comment_id\":\"c12\","
                  "\"author\":\"a-reviewer\",\"url\":\"https://example.invalid/"
                  "c12\",\"body\":\"first, will fail\","
                  "\"ts\":\"2025-09-04T15:00:00Z\"}\n"
                  "{\"kind\":\"comment\",\"owner\":\"z23c\",\"repo\":\"z23\","
                  "\"number\":\"47\",\"comment_id\":\"c13\","
                  "\"author\":\"a-reviewer\",\"url\":\"https://example.invalid/"
                  "c13\",\"body\":\"second, waits\","
                  "\"ts\":\"2025-09-04T15:00:01Z\"}\n");
    struct zcl_command_reply ingest_reply;
    ftx_ingest_call("github", src_path, &ingest_reply);
    ASSERT(ingest_reply.status == ZCL_COMMAND_STATUS_PASSED);
    ASSERT_EQ(json_get_int(json_get(&ingest_reply.data, "appended")), 2);
    zcl_command_reply_free(&ingest_reply);

    node_rpc_client_set_test_hook(ftx_no_node_rpc_hook);
    struct ftx_call c1;
    ftx_begin(&c1, false, 0);
    ASSERT(ftx_run(&c1));
    ASSERT(c1.reply.status != ZCL_COMMAND_STATUS_PASSED);
    ASSERT_EQ(ftx_int(&c1, "checked"), 1);
    ASSERT_EQ(ftx_int(&c1, "fired"), 0);
    ASSERT_EQ(ftx_int(&c1, "failed"), 1);
    ftx_end(&c1);

    /* Once the node answers, the first row fires and, in the same run, the second. */
    g_ftx_board_calls = 0;
    node_rpc_client_set_test_hook(ftx_board_rpc_hook);
    struct ftx_call c2;
    ftx_begin(&c2, false, 0);
    ASSERT(ftx_run(&c2));
    ASSERT(c2.reply.status == ZCL_COMMAND_STATUS_PASSED);
    ASSERT_EQ(ftx_int(&c2, "checked"), 2);
    ASSERT_EQ(ftx_int(&c2, "fired"), 2);
    ASSERT_EQ(ftx_int(&c2, "failed"), 0);
    ftx_end(&c2);
    ASSERT_EQ(g_ftx_board_calls, 2);
    node_rpc_client_set_test_hook(NULL);
    clock_reset_default();
    PASS();
_test_next:;
    return failures;
}

#define FTX_TSV8 "a\ta\ta\ta\ta\ta\ta\ta"
#define FTX_TSV32 FTX_TSV8 "\t" FTX_TSV8 "\t" FTX_TSV8 "\t" FTX_TSV8
#define FTX_RECORD(s) { s, sizeof(s) - 1 }
static int ftx_case_tsv_records(void)
{
    int failures = 0;
    char path[PATH_MAX];
    const struct { const char *bytes; size_t len; } cases[] = {
        FTX_RECORD("a\0\tb\n"), FTX_RECORD(FTX_TSV32 "\ta\n"),
        FTX_RECORD("a\n" FTX_TSV32 "\ta\n"), FTX_RECORD("a\nx\0junk\n"),
        FTX_RECORD(FTX_TSV32 "\n" FTX_TSV32),
        FTX_RECORD(FTX_TSV32 "\n" FTX_TSV32 "\n"), FTX_RECORD(FTX_TSV32)
    };
    printf("fleet_triggers: TSV byte extent and column bounds... ");
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        ftx_isolate("tsv_records");
        ASSERT(zcl_trigger_experiment_path(path, sizeof path));
        ftx_write_file(path, "");
        FILE *f = fopen(path, "wb");
        ASSERT(f != NULL);
        ASSERT_EQ(fwrite(cases[i].bytes, 1, cases[i].len, f), cases[i].len);
        ASSERT_EQ(fclose(f), 0);
        struct ftx_call c;
        ftx_begin(&c, true, 0);
        ASSERT(ftx_run(&c));
        ASSERT_EQ(ftx_int(&c, "failed"), i < 4 ? 1 : 0);
        ASSERT_EQ(ftx_int(&c, "checked"), i == 4 || i == 5 ? 1 : 0);
        ASSERT_EQ(ftx_int(&c, "fired"), 0);
        ftx_end(&c);
    }
    PASS();
_test_next:;
    return failures;
}
#undef FTX_RECORD
#undef FTX_TSV32
#undef FTX_TSV8
static int ftx_case_cursor_extent(void)
{
    int failures = 0;
    char path[PATH_MAX], cursor[PATH_MAX], raw[256];
    const char *tails[] = {"", "\n", " 999\n", "\nextra\n", "\0junk\n", "", "", ""};
    const size_t sizes[] = {0, 1, 5, 7, 6, 0, 150, 0};
    ftx_install_clock();
    ftx_isolate("cursor_extent");
    ASSERT(zcl_trigger_landing_path(path, sizeof path));
    ftx_write_file(path, "{\"state\":\"landed\"}\n");
    struct ftx_call c;
    ftx_begin(&c, false, 0);
    ASSERT(ftx_run(&c));
    ftx_end(&c);
    ASSERT(zcl_trigger_cursor_path("landing_outcomes", cursor, sizeof cursor));
    struct stat st;
    ASSERT_EQ(stat(path, &st), 0);
    for (size_t i = 0; i < sizeof sizes / sizeof sizes[0]; i++) {
        int n = snprintf(raw, sizeof raw, "%llu %llu %llu 1",
                         (unsigned long long)st.st_ino,
                         (unsigned long long)st.st_size,
                         (unsigned long long)st.st_size);
        ASSERT(n > 0 && (size_t)n + sizes[i] < sizeof raw);
        if (i == 7) raw[n - 2] = '\n';
        if (i == 5) n--; /* incomplete fourth scalar */
        if (i == 6) memset(raw + n, 'x', sizes[i]);
        else memcpy(raw + n, tails[i], sizes[i]);
        FILE *f = fopen(cursor, "wb");
        ASSERT(f != NULL);
        ASSERT_EQ(fwrite(raw, 1, (size_t)n + sizes[i], f), (size_t)n + sizes[i]);
        ASSERT_EQ(fclose(f), 0);
        ftx_begin(&c, true, 0);
        ASSERT(ftx_run(&c));
        ASSERT_EQ(ftx_int(&c, "checked"), i < 2 ? 0 : 1);
        ftx_end(&c);
    }
_test_next:;
    clock_reset_default();
    return failures;
}

static int ftx_case_cursor_capacity(void)
{
    int failures = 0;
    char path[PATH_MAX], cursor[PATH_MAX], raw[128];
    printf("fleet_triggers: 127-byte cursor accepted, 128-byte refused... ");
    ftx_install_clock();
    ftx_isolate("cursor_capacity");
    ASSERT(zcl_trigger_landing_path(path, sizeof path));
    ftx_write_file(path, "{\"state\":\"landed\"}\n");
    ASSERT(zcl_trigger_cursor_path("landing_outcomes", cursor, sizeof cursor));
    /* Resolving a cursor path does not create its parent directories. */
    ftx_write_file(cursor, "");
    struct stat st;
    ASSERT_EQ(stat(path, &st), 0);
    int n = snprintf(raw, sizeof raw, "%llu %llu %llu 1",
                     (unsigned long long)st.st_ino,
                     (unsigned long long)st.st_size,
                     (unsigned long long)st.st_size);
    ASSERT(n > 0 && (size_t)n < 127);
    memset(raw + n, ' ', sizeof raw - (size_t)n);
    for (size_t len = 127; len <= sizeof raw; len++) {
        FILE *f = fopen(cursor, "wb");
        ASSERT(f != NULL);
        size_t written = fwrite(raw, 1, len, f);
        int closed = fclose(f);
        ASSERT_EQ(written, len);
        ASSERT_EQ(closed, 0);
        struct ftx_call c;
        ftx_begin(&c, true, 0);
        ASSERT(ftx_run(&c));
        int64_t checked = ftx_int(&c, "checked");
        ftx_end(&c);
        ASSERT_EQ(checked, len == 127 ? 0 : 1);
    }
    PASS();
_test_next:;
    clock_reset_default();
    return failures;
}

static int ftx_cursor_scalar_row(const char *cursor, const struct stat *st,
                                 const char *scalar, int expected)
{
    int failures = 0;
    char raw[256];
    printf("fleet_triggers: cursor scalar %s... ", scalar);
    int n = snprintf(raw, sizeof raw, "%llu %llu %llu %s",
                     (unsigned long long)st->st_ino,
                     (unsigned long long)st->st_size,
                     (unsigned long long)st->st_size, scalar);
    ASSERT(n > 0 && (size_t)n < sizeof raw);
    ftx_write_file(cursor, raw);
    struct ftx_call c;
    ftx_begin(&c, true, 0);
    ASSERT(ftx_run(&c));
    int checked = ftx_int(&c, "checked");
    ftx_end(&c);
    ASSERT_EQ(checked, expected);
_test_next:;
    return failures;
}

static int ftx_case_cursor_scalar_range(void)
{
    int failures = 0;
    char path[PATH_MAX], cursor[PATH_MAX];
    const char *scalars[] = {
        "18446744073709551615", "18446744073709551615 \t\r\n",
        "18446744073709551616", "184467440737095516160000000000",
        "+1", "-1"
    };
    ftx_install_clock();
    ftx_isolate("cursor_scalar_range");
    ASSERT(zcl_trigger_landing_path(path, sizeof path));
    ftx_write_file(path, "{\"state\":\"landed\"}\n");
    ASSERT(zcl_trigger_cursor_path("landing_outcomes", cursor, sizeof cursor));
    struct stat st;
    ASSERT_EQ(stat(path, &st), 0);
    for (size_t i = 0; i < sizeof scalars / sizeof scalars[0]; i++) {
        failures += ftx_cursor_scalar_row(cursor, &st, scalars[i], i < 2 ? 0 : 1);
    }
_test_next:;
    clock_reset_default();
    return failures;
}

static int ftx_record_cursor(size_t expected_offset, unsigned expected_rows)
{
    int failures = 0;
    char cursor[PATH_MAX];
    unsigned long long ino, size, offset, rows;
    ASSERT(zcl_trigger_cursor_path("landing_outcomes", cursor, sizeof cursor));
    FILE *f = fopen(cursor, "rb");
    ASSERT(f != NULL);
    int fields = fscanf(f, "%llu %llu %llu %llu", &ino, &size, &offset, &rows);
    int closed = fclose(f);
    ASSERT_EQ(fields, 4);
    ASSERT_EQ(closed, 0);
    ASSERT_EQ(offset, expected_offset);
    ASSERT_EQ(rows, expected_rows);
_test_next:;
    return failures;
}

/* Byte-counted tails also exercise embedded NULs through the real evaluator. */
static int ftx_case_json_record(const char *tag, const char *tail,
                                 size_t tail_len, const char *reason)
{
    int failures = 0;
    char path[PATH_MAX], why[256];
    uint64_t checked, fired, failed;
    const char *prefix = "{\"state\":\"landed\"}\n";
    bool valid = reason == NULL;
    ftx_isolate(tag);
    ftx_install_clock();
    ASSERT(zcl_trigger_landing_path(path, sizeof path));
    ftx_write_file(path, "");
    FILE *f = fopen(path, "wb");
    ASSERT(f != NULL);
    int prefix_written = fputs(prefix, f);
    size_t tail_written = fwrite(tail, 1, tail_len, f);
    int closed = fclose(f);
    ASSERT(prefix_written >= 0);
    ASSERT_EQ(tail_written, tail_len);
    ASSERT_EQ(closed, 0);
    printf("fleet_triggers: %s... ", tag);
    ASSERT_EQ(zcl_trigger_check_run(false, 0, &checked, &fired, &failed,
                                    NULL, why, sizeof why), valid);
    ASSERT_EQ(checked, valid ? 2 : 1);
    ASSERT_EQ(fired, valid ? 2 : 1);
    ASSERT_EQ(failed, 0);
    if (!valid)
        ASSERT(strstr(why, reason) != NULL);
    failures += ftx_record_cursor(strlen(prefix) + (valid ? tail_len : 0),
                                  valid ? 2 : 1);
    /* A second check must neither replay the prefix nor cross a refused tail. */
    ASSERT_EQ(zcl_trigger_check_run(false, 0, &checked, &fired, &failed,
                                    NULL, why, sizeof why), valid);
    ASSERT_EQ(checked, 0);
    ASSERT_EQ(fired, 0);
    ASSERT_EQ(failed, 0);
    PASS();
_test_next:;
    clock_reset_default();
    return failures;
}

static int ftx_case_scan_framing(void)
{
    int failures = 0;
    const char suffix[] = "\n{\"state\":\"landed\"}\n";
    char oversized[8192 + sizeof suffix - 1];
    memset(oversized, 'x', 8192);
    memcpy(oversized + 8192, suffix, sizeof suffix - 1);
    failures += ftx_case_json_record("oversized", oversized, sizeof oversized,
                                     "oversized");
    return failures;
}

/* A local refusal can follow a successful ledger append. The command must
 * report that prefix's mutation even though no success data is returned. */
static int ftx_case_command_prefix_refusal(void)
{
    int failures = 0;
    char path[PATH_MAX], ledger[PATH_MAX];
    const char *prefix = "{\"state\":\"landed\"}\n";
    struct ftx_call c;
    ftx_isolate("command_prefix_refusal");
    ftx_install_clock();
    ftx_begin(&c, false, 0);
    ASSERT(c.request.spec != NULL);
    ASSERT(zcl_trigger_landing_path(path, sizeof path));
    ASSERT(zcl_trigger_fired_ledger_path(ledger, sizeof ledger));
    ftx_write_file(path, "{\"state\":\"landed\"}\n{\"state\":\n");
    printf("fleet_triggers: source refusal reports ledger prefix mutation... ");
    ASSERT(ftx_run(&c));
    ASSERT_EQ(c.reply.status, ZCL_COMMAND_STATUS_FAILED);
    ASSERT_EQ(c.reply.exit_code, ZCL_COMMAND_EXIT_INTERNAL);
    ASSERT_STR_EQ(c.reply.error.code, "CHECK_FAILED");
    ASSERT(c.reply.error.mutated);
    ASSERT(strstr(c.reply.error.message, "malformed JSON") != NULL);
    ASSERT_EQ(ftx_count_lines(ledger), 1);
    ASSERT_EQ(ftx_record_cursor(strlen(prefix), 1), 0);
    PASS();
_test_next:;
    ftx_end(&c);
    clock_reset_default();
    return failures;
}

static int ftx_case_scan_read_error(void)
{
    int failures = 0;
    char path[PATH_MAX], why[256];
    uint64_t checked, fired, failed;
    printf("fleet_triggers: unreadable source refuses... ");
    ftx_isolate("scan_read_error");
    ftx_install_clock();
    ASSERT(zcl_trigger_landing_path(path, sizeof path));
    ftx_write_file(path, "");
    ASSERT_EQ(unlink(path), 0);
    ASSERT_EQ(mkdir(path, 0700), 0);
    ASSERT(!zcl_trigger_check_run(false, 0, &checked, &fired, &failed,
                                  NULL, why, sizeof why));
    ASSERT(strstr(why, "read error") != NULL);
    ASSERT_EQ(checked, 0);
    ASSERT_EQ(fired, 0);
    ASSERT_EQ(failed, 0);
    PASS();
_test_next:;
    clock_reset_default();
    return failures;
}

static int ftx_case_json_records(void)
{
    int failures = 0;
    const struct { const char *tag, *tail; size_t len; const char *reason; } cases[] = {
        { "incomplete_lf", "{\"state\":\n", sizeof "{\"state\":\n" - 1,
          "malformed JSON" },
        { "trailing_bytes", "{\"state\":\"landed\"}x\n",
          sizeof "{\"state\":\"landed\"}x\n" - 1, "malformed JSON" },
        { "incomplete_eof", "{\"state\":", sizeof "{\"state\":" - 1,
          "malformed JSON" },
        { "complete_eof", "{\"state\":\"landed\"}",
          sizeof "{\"state\":\"landed\"}" - 1, NULL },
        { "invalid_utf8", "{\"state\":\"landed\",\"note\":\"\xff\"}\n",
          sizeof "{\"state\":\"landed\",\"note\":\"\xff\"}\n" - 1, "malformed JSON" },
        { "embedded_nul", "{\"state\":\"landed\"}\0junk\n",
          sizeof "{\"state\":\"landed\"}\0junk\n" - 1, "malformed or oversized" }
    };
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++)
        failures += ftx_case_json_record(cases[i].tag, cases[i].tail,
                                         cases[i].len, cases[i].reason);
    return failures;
}

#if !defined(_WIN32)
/* Read the complete saved cursor, so an early refusal cannot rewrite even
 * its inode/size fields while leaving offset and row count unchanged. */
static int ftx_source_cursor(const char *source, char *raw, size_t cap)
{
    int failures = 0;
    char path[PATH_MAX];
    ASSERT(zcl_trigger_cursor_path(source, path, sizeof path));
    FILE *f = fopen(path, "rb");
    ASSERT(f != NULL);
    size_t n = fread(raw, 1, cap - 1, f);
    bool complete = !ferror(f) && feof(f);
    int closed = fclose(f);
    ASSERT(complete);
    ASSERT_EQ(closed, 0);
    raw[n] = 0;
_test_next:;
    return failures;
}

static int ftx_saved_cursor(char *raw, size_t cap)
{
    return ftx_source_cursor("landing_outcomes", raw, cap);
}

/* A bound Unix socket has a stat-able pathname that cannot be opened as a
 * FILE, even by a privileged process. Bind relative to its isolated parent
 * so the fixture does not depend on the absolute sun_path length limit. */
static int ftx_open_failure_call(const char *path, bool expected)
{
    int failures = 0, fd = -1;
    char cwd[PATH_MAX], parent[PATH_MAX];
    struct sockaddr_un address = { .sun_family = AF_UNIX };
    char why[256];
    uint64_t checked = 99, fired = 99, failed = 99;
    ASSERT(getcwd(cwd, sizeof cwd) != NULL);
    ASSERT(strlen(path) < sizeof parent);
    memcpy(parent, path, strlen(path) + 1);
    char *name = strrchr(parent, '/');
    ASSERT(name != NULL);
    *name++ = 0;
    ASSERT(strlen(name) < sizeof address.sun_path);
    memcpy(address.sun_path, name, strlen(name) + 1);
    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    ASSERT(fd >= 0);
    ASSERT_EQ(unlink(path), 0);
    ASSERT_EQ(chdir(parent), 0);
    int bound = bind(fd, (const struct sockaddr *)&address, sizeof address);
    int restored = chdir(cwd);
    ASSERT_EQ(restored, 0);
    ASSERT_EQ(bound, 0);
    struct stat st;
    ASSERT_EQ(stat(path, &st), 0);
    FILE *probe = fopen(path, "rb");
    bool opened = probe != NULL;
    if (probe)
        fclose(probe);
    ASSERT(!opened);
    bool result = zcl_trigger_check_run(false, 0, &checked, &fired, &failed,
                                        NULL, why, sizeof why);
    ASSERT_EQ(result, expected);
    ASSERT_EQ(checked, 0);
    ASSERT_EQ(fired, 0);
    ASSERT_EQ(failed, 0);
    ASSERT_STR_EQ(why, expected ? "" : "trigger source read error");
_test_next:;
    if (fd >= 0 && close(fd) != 0)
        failures++;
    return failures;
}

static int ftx_case_source_open_error(bool tsv)
{
    int failures = 0;
    char path[PATH_MAX], cursor[PATH_MAX], before[128], after[128];
    const char *source = tsv ? "experiment_rows" : "landing_outcomes";
    struct stat st;
    ftx_isolate(tsv ? "tsv_open_skip" : "json_open_refusal");
    ASSERT(tsv ? zcl_trigger_experiment_path(path, sizeof path)
               : zcl_trigger_landing_path(path, sizeof path));
    ftx_write_file(path, tsv
        ? "ts\tkind\tbox\ttask_id\ttask_class\tstory\texecutor\tharness\t"
          "model\teffort\ttokens_in\ttokens_out\ttokens_cache\t"
          "tokens_reasoning\ttool_uses\tturns\twall_s\toutcome\t"
          "lines_added\tlines_removed\tdefects\tnote\n"
          "2026-09-06T10:00:00Z\tresult\tnode1\tt1\tread\ts\te\th\tm\tlow\t"
          "1\t1\t0\t0\t0\t1\t1\ttimeout\t0\t0\t0\tn\n"
        : "{\"state\":\"landed\"}\n");
    ASSERT_EQ(stat(path, &st), 0);
    ASSERT(zcl_trigger_cursor_path(source, cursor, sizeof cursor));
    ftx_write_file(cursor, "0 0 0 0\n");
    ASSERT_EQ(ftx_source_cursor(source, before, sizeof before), 0);
    failures += ftx_open_failure_call(path, tsv);
    ASSERT_EQ(ftx_source_cursor(source, after, sizeof after), 0);
    ASSERT_STR_EQ(before, after);
    PASS();
_test_next:;
    return failures;
}

/* mode 0 is action-only; mode 1 adds malformed board JSON; mode 2 adds
 * a board setup error. Both sources must keep their pending row at zero. */
static int ftx_case_action_then_refusal(int mode)
{
    int failures = 0;
    char landing[PATH_MAX], board[PATH_MAX], ledger[PATH_MAX], why[256];
    char cursor[PATH_MAX], before[128], after[128];
    uint64_t checked, fired, failed;
    ftx_isolate(mode == 0 ? "action_only" : mode == 1 ? "action_then_json"
                                                    : "action_then_setup");
    ftx_install_clock();
    ASSERT(zcl_trigger_landing_path(landing, sizeof landing));
    ASSERT(zcl_trigger_board_path(board, sizeof board));
    ASSERT(zcl_trigger_fired_ledger_path(ledger, sizeof ledger));
    ftx_write_file(landing, "{\"state\":\"landed\"}\n");
    ftx_write_file(ledger, "");
    ASSERT_EQ(unlink(ledger), 0);
    ASSERT_EQ(mkdir(ledger, 0700), 0);
    if (mode != 0) {
        ftx_write_file(board, "{\"broken\":\n");
        ASSERT(zcl_trigger_cursor_path("board_rows", cursor, sizeof cursor));
        ftx_write_file(cursor, "0 0 0 0\n");
        ASSERT_EQ(ftx_source_cursor("board_rows", before, sizeof before), 0);
    }
    if (mode == 2) {
        ASSERT_EQ(unlink(board), 0);
        ASSERT_EQ(symlink(board, board), 0);
    }
    ASSERT_EQ(zcl_trigger_check_run(false, 0, &checked, &fired, &failed,
                                    NULL, why, sizeof why), mode == 0);
    ASSERT_EQ(checked, 1);
    ASSERT_EQ(fired, 0);
    ASSERT_EQ(failed, 1);
    const char *reason = mode == 0 ? "ledger append failed"
                         : mode == 1 ? "malformed JSON" : "read error";
    ASSERT(strstr(why, reason) != NULL);
    ASSERT_EQ(ftx_record_cursor(0, 0), 0);
    if (mode != 0) {
        ASSERT_EQ(ftx_source_cursor("board_rows", after, sizeof after), 0);
        /* Scanning malformed JSON saves identity but must not consume it. */
        if (mode == 2)
            ASSERT_STR_EQ(before, after);
        else {
            unsigned long long ino, size, offset, rows;
            ASSERT_EQ(sscanf(after, "%llu %llu %llu %llu", &ino, &size,
                              &offset, &rows), 4);
            ASSERT_EQ(offset, 0);
            ASSERT_EQ(rows, 0);
        }
    }
    PASS();
_test_next:;
    clock_reset_default();
    return failures;
}

static int ftx_setup_refusal(void)
{
    int failures = 0;
    char why[256];
    uint64_t checked = 99, fired = 99, failed = 99;
    ASSERT(!zcl_trigger_check_run(false, 0, &checked, &fired, &failed,
                                  NULL, why, sizeof why));
    ASSERT(strstr(why, "read error") != NULL);
    ASSERT_EQ(checked, 0);
    ASSERT_EQ(fired, 0);
    ASSERT_EQ(failed, 0);
_test_next:;
    return failures;
}

/* A source file used as the state base makes path resolution fail without
 * permissions, process privileges, or an injected production-only seam. */
static int ftx_case_source_path_error(void)
{
    int failures = 0;
    char path[PATH_MAX], probe[PATH_MAX], before[128], after[128], why[256];
    uint64_t checked, fired, failed;
    ftx_isolate("source_path_error");
    ftx_install_clock();
    ASSERT(zcl_trigger_landing_path(path, sizeof path));
    ftx_write_file(path, "{\"state\":\"landed\"}\n");
    ASSERT(zcl_trigger_check_run(false, 0, &checked, &fired, &failed,
                                 NULL, why, sizeof why));
    ASSERT_EQ(ftx_saved_cursor(before, sizeof before), 0);
    ASSERT_EQ(setenv("XDG_STATE_HOME", path, 1), 0);
    ASSERT(!zcl_trigger_landing_path(probe, sizeof probe));
    failures += ftx_setup_refusal();
    ASSERT_EQ(setenv("XDG_STATE_HOME", g_ftx_state, 1), 0);
    ASSERT_EQ(ftx_saved_cursor(after, sizeof after), 0);
    ASSERT_STR_EQ(before, after);
    PASS();
_test_next:;
    if (setenv("XDG_STATE_HOME", g_ftx_state, 1) != 0)
        failures++;
    clock_reset_default();
    return failures;
}

/* A self-referencing source symlink gives stat ELOOP even as root. */
static int ftx_case_source_stat_error(void)
{
    int failures = 0;
    char path[PATH_MAX], before[128], after[128], why[256];
    uint64_t checked, fired, failed;
    struct stat st;
    ftx_isolate("source_stat_error");
    ftx_install_clock();
    ASSERT(zcl_trigger_landing_path(path, sizeof path));
    /* ENOENT is still a successful empty source. */
    ASSERT(zcl_trigger_check_run(false, 0, &checked, &fired, &failed,
                                 NULL, why, sizeof why));
    ASSERT_EQ(checked, 0);
    ftx_write_file(path, "{\"state\":\"landed\"}\n");
    ASSERT(zcl_trigger_check_run(false, 0, &checked, &fired, &failed,
                                 NULL, why, sizeof why));
    ASSERT_EQ(ftx_saved_cursor(before, sizeof before), 0);
    ASSERT_EQ(unlink(path), 0);
    ASSERT_EQ(symlink(path, path), 0);
    ASSERT_EQ(stat(path, &st), -1);
    ASSERT_EQ(errno, ELOOP);
    failures += ftx_setup_refusal();
    ASSERT_EQ(ftx_saved_cursor(after, sizeof after), 0);
    ASSERT_STR_EQ(before, after);
    ASSERT_EQ(unlink(path), 0);
    PASS();
_test_next:;
    clock_reset_default();
    return failures;
}

/* Holding both FIFO ends open avoids a blocking source open; fseek then
 * refuses with ESPIPE before any byte can be scored or cursor saved. */
static int ftx_case_source_seek_error(void)
{
    int failures = 0;
    char path[PATH_MAX], before[128], after[128], why[256];
    uint64_t checked, fired, failed;
    int anchor = -1;
    ftx_isolate("source_seek_error");
    ftx_install_clock();
    ASSERT(zcl_trigger_landing_path(path, sizeof path));
    ftx_write_file(path, "{\"state\":\"landed\"}\n");
    ASSERT(zcl_trigger_check_run(false, 0, &checked, &fired, &failed,
                                 NULL, why, sizeof why));
    ASSERT_EQ(ftx_saved_cursor(before, sizeof before), 0);
    ASSERT_EQ(unlink(path), 0);
    ASSERT_EQ(mkfifo(path, 0600), 0);
    anchor = open(path, O_RDWR | O_NONBLOCK);
    ASSERT(anchor >= 0);
    ASSERT_EQ(lseek(anchor, 0, SEEK_SET), -1);
    ASSERT_EQ(errno, ESPIPE);
    failures += ftx_setup_refusal();
    ASSERT_EQ(ftx_saved_cursor(after, sizeof after), 0);
    ASSERT_STR_EQ(before, after);
    ASSERT_EQ(unlink(path), 0);
    PASS();
_test_next:;
    if (anchor >= 0 && close(anchor) != 0)
        failures++;
    clock_reset_default();
    return failures;
}
#endif

int test_fleet_triggers(void);
int test_fleet_triggers(void)
{
    int failures = 0;
    failures += ftx_case_command_prefix_refusal();
#if !defined(_WIN32)
    failures += ftx_case_source_open_error(true);
    failures += ftx_case_source_open_error(false);
    failures += ftx_case_action_then_refusal(0);
    failures += ftx_case_action_then_refusal(1);
    failures += ftx_case_action_then_refusal(2);
    failures += ftx_case_source_path_error();
    failures += ftx_case_source_stat_error();
    failures += ftx_case_source_seek_error();
#endif
    failures += ftx_case_scan_framing();
    failures += ftx_case_scan_read_error();
    failures += ftx_case_json_records();
    failures += ftx_case_cursor_extent();
    failures += ftx_case_cursor_capacity();
    failures += ftx_case_cursor_scalar_range();
    failures += ftx_case_landed_ledger_once();
    failures += ftx_case_failed_prints();
    failures += ftx_case_dry_run_no_advance();
    failures += ftx_case_truncated_restarts();
    failures += ftx_case_unknown_field_never_fires();
    failures += ftx_case_board_and_experiment_sources();
    failures += ftx_case_json_well_formed();
    failures += ftx_case_clock_stamps_ts();
    failures += ftx_case_list_enumerates();
    failures += ftx_case_ingest_refuses();
    failures += ftx_case_ingest_skips_malformed();
    failures += ftx_case_github_comment_fires_board_post();
    failures += ftx_case_board_post_no_node();
    failures += ftx_case_board_post_retries_then_fires();
    failures += ftx_case_later_row_waits_behind_failed();
    failures += ftx_case_tsv_records();

    ftx_restore();
    if (failures == 0)
        printf("test_fleet_triggers: all passed\n");
    else
        printf("test_fleet_triggers: %d FAILED\n", failures);
    return failures;
}
