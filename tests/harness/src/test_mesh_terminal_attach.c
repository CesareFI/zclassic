/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Focused test for the mesh terminal attach bridge
 * (tools/command/mesh_terminal_attach.c). The bridge runs unchanged against
 * a scripted fake of the node's mesh_terminal_* RPC answers and a scripted
 * fake terminal. Each case is its own static function (the shared ASSERT()
 * macro hardcodes `goto _test_next`, so one label per function). */

#include "test/test_core.h"

#include "base/hex.h"
#include "command/mesh_terminal_attach.h"
#include "json/json.h"

#include "command/native_command.h"
#include "platform/time_compat.h"

#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PAIRING "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
#define TERMINAL "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
#define CAP 512

struct fake_node {
    /* script */
    const char *open_error_code;   /* open refused with this code */
    bool transport_error;          /* RPC client envelope, node unreachable */
    const char *open_message;      /* refusal message override */
    const char *refused_verdict;   /* poll reports refused with this verdict */
    int opening_polls;             /* polls that answer "opening" first */
    const char *output;            /* delivered on the first live read */
    int end_at_read;               /* 1-based read that reports "ended"; 0 never */
    const char *evidence_reason;   /* CLOSED receipt evidence, or NULL */
    /* observations */
    int opens, polls, reads, writes, resizes, closes, calls;
    unsigned open_cols, open_rows, resize_cols, resize_rows;
    bool open_has_geometry;
    char sent[CAP];
    size_t sent_len;
    bool ended;
};

struct fake_term {
    struct fake_node *node;
    /* script */
    const char *inputs[8];     /* chunks, delivered one per read_input call */
    size_t input_count, input_next;
    bool eof_after_inputs;
    int resize_at_call;        /* take_resize true on this stop_requested call */
    int stop_at_call;          /* stop_requested true from this call on */
    unsigned window_cols, window_rows;
    /* observations */
    int calls, raw_on_count, raw_off_count;
    bool raw_state;
    int min_timeout_ms;
    int64_t clock_ms;
    char out[CAP], err[CAP * 2];
    size_t out_len;
};

static char *fake_dup(const char *s)
{
    char *p = malloc(strlen(s) + 1u);
    if (p)
        strcpy(p, s);
    return p;
}

static const struct json_value *params_obj(const struct json_value *arr)
{
    return json_at(arr, 0);
}

static char *fake_poll(struct fake_node *n)
{
    char b[512];
    const char *state = n->ended ? "ended" : "live";
    n->polls++;
    if (n->polls <= n->opening_polls)
        state = "opening";
    if (n->refused_verdict)
        snprintf(b, sizeof(b),
                 "{\"ok\":true,\"state\":\"refused\",\"verdict\":\"%s\"}",
                 n->refused_verdict);
    else if (n->ended && n->evidence_reason)
        snprintf(b, sizeof(b),
                 "{\"ok\":true,\"state\":\"ended\",\"verdict\":\"closed\","
                 "\"bytes_in\":%zu,\"bytes_out\":7,\"close_evidence\":"
                 "{\"bytes_in\":%zu,\"bytes_out\":7,\"duration_s\":2,"
                 "\"reason\":\"%s\"}}",
                 n->sent_len, n->sent_len, n->evidence_reason);
    else
        snprintf(b, sizeof(b), "{\"ok\":true,\"state\":\"%s\",\"bytes_in\":%zu}",
                 state, n->sent_len);
    return fake_dup(b);
}

static char *fake_read(struct fake_node *n)
{
    char b[CAP];
    n->reads++;
    if (n->end_at_read && n->reads >= n->end_at_read) {
        n->ended = true;
        return fake_dup("{\"ok\":true,\"state\":\"ended\",\"output_bytes\":0}");
    }
    if (n->reads == 1 && n->output) {
        char hex[CAP];
        zcl_hex_encode((const uint8_t *)n->output, strlen(n->output), hex);
        snprintf(b, sizeof(b),
                 "{\"ok\":true,\"state\":\"live\",\"output_bytes\":%zu,"
                 "\"output_hex\":\"%s\"}",
                 strlen(n->output), hex);
        return fake_dup(b);
    }
    return fake_dup("{\"ok\":true,\"state\":\"live\",\"output_bytes\":0}");
}

static char *fake_write(struct fake_node *n, const struct json_value *in)
{
    const char *hex = json_get_str(json_get(in, "input_hex"));
    size_t len = hex ? strlen(hex) / 2u : 0;
    n->writes++;
    if (len && n->sent_len + len <= sizeof(n->sent) &&
        zcl_hex_decode_lower(hex, (uint8_t *)n->sent + n->sent_len, len))
        n->sent_len += len;
    return fake_dup("{\"ok\":true,\"bytes_sent\":1}");
}

static char *fake_open_refusal(const struct fake_node *n)
{
    char b[CAP];
    snprintf(b, sizeof(b),
             "{\"ok\":false,\"code\":\"peer_not_connected\",\"message\":\"%s\"}",
             n->open_message ? n->open_message
                             : "the paired peer has no established Noise "
                               "session; no dial is attempted");
    return fake_dup(b);
}

static char *fake_rpc(void *ctx, const char *method, const char *params)
{
    struct fake_node *n = ctx;
    struct json_value arr;
    json_init(&arr);
    if (!json_read(&arr, params, strlen(params)))
        return NULL;
    const struct json_value *in = params_obj(&arr);
    char *answer = NULL;
    n->calls++;
    if (strcmp(method, "mesh_terminal_open") == 0) {
        n->opens++;
        const struct json_value *cols = json_get(in, "cols");
        n->open_has_geometry = cols != NULL;
        n->open_cols = cols ? (unsigned)json_get_int(cols) : 0;
        n->open_rows = (unsigned)json_get_int(json_get(in, "rows"));
        if (n->transport_error) {
            json_free(&arr);
            return fake_dup("{\"error\":{\"code\":-32603,\"message\":"
                            "\"socket failed\"}}");
        }
        answer = n->open_error_code
                     ? fake_open_refusal(n)
                     : fake_dup("{\"ok\":true,\"state\":\"opening\","
                                "\"terminal_id\":\"" TERMINAL "\","
                                "\"receipt_timeout_seconds\":35}");
    } else if (strcmp(method, "mesh_terminal_poll") == 0) {
        answer = fake_poll(n);
    } else if (strcmp(method, "mesh_terminal_read") == 0) {
        answer = fake_read(n);
    } else if (strcmp(method, "mesh_terminal_write") == 0) {
        answer = fake_write(n, in);
    } else if (strcmp(method, "mesh_terminal_resize") == 0) {
        n->resizes++;
        n->resize_cols = (unsigned)json_get_int(json_get(in, "cols"));
        n->resize_rows = (unsigned)json_get_int(json_get(in, "rows"));
        answer = fake_dup("{\"ok\":true}");
    } else if (strcmp(method, "mesh_terminal_close") == 0) {
        n->closes++;
        answer = fake_dup("{\"ok\":true,\"state\":\"ended\"}");
    }
    json_free(&arr);
    return answer;
}

static long tty_read(void *ctx, uint8_t *buf, size_t cap, int timeout_ms)
{
    struct fake_term *t = ctx;
    if (t->min_timeout_ms == 0 || timeout_ms < t->min_timeout_ms)
        t->min_timeout_ms = timeout_ms;
    if (t->input_next < t->input_count) {
        const char *chunk = t->inputs[t->input_next++];
        size_t len = strlen(chunk);
        memcpy(buf, chunk, len < cap ? len : cap);
        return (long)len;
    }
    return t->eof_after_inputs ? -1 : 0;
}

static bool tty_write(void *ctx, const uint8_t *buf, size_t len)
{
    struct fake_term *t = ctx;
    if (t->out_len + len > sizeof(t->out))
        return false;
    memcpy(t->out + t->out_len, buf, len);
    t->out_len += len;
    return true;
}

static bool tty_window(void *ctx, uint16_t *cols, uint16_t *rows)
{
    struct fake_term *t = ctx;
    *cols = (uint16_t)t->window_cols;
    *rows = (uint16_t)t->window_rows;
    return true;
}

static bool tty_take_resize(void *ctx)
{
    struct fake_term *t = ctx;
    if (t->resize_at_call && t->calls == t->resize_at_call) {
        t->window_cols = 120;
        t->window_rows = 50;
        return true;
    }
    return false;
}

static bool tty_stop(void *ctx)
{
    struct fake_term *t = ctx;
    t->calls++;
    /* A runaway loop is cut off after 400 cycles and reported as a stop. */
    return (t->stop_at_call && t->calls >= t->stop_at_call) || t->calls > 400;
}

static void tty_raw(void *ctx, bool on)
{
    struct fake_term *t = ctx;
    t->raw_state = on;
    if (on)
        t->raw_on_count++;
    else
        t->raw_off_count++;
}

static void tty_pause(void *ctx, int ms)
{
    struct fake_term *t = ctx;
    t->clock_ms += ms;
}

static int64_t tty_now(void *ctx)
{
    struct fake_term *t = ctx;
    return t->clock_ms;
}

static void tty_diag(void *ctx, const char *line)
{
    struct fake_term *t = ctx;
    size_t used = strlen(t->err);
    snprintf(t->err + used, sizeof(t->err) - used, "%s\n", line);
}

static void fake_init(struct fake_node *n, struct fake_term *t)
{
    memset(n, 0, sizeof(*n));
    memset(t, 0, sizeof(*t));
    t->node = n;
    t->window_cols = 100;
    t->window_rows = 40;
}

static int run(struct fake_node *n, struct fake_term *t, bool interactive,
               const char *pairing)
{
    const struct mesh_terminal_attach_tty tty = {
        .ctx = t,
        .read_input = tty_read,
        .write_output = tty_write,
        .window = tty_window,
        .take_resize = tty_take_resize,
        .stop_requested = tty_stop,
        .raw = tty_raw,
        .pause_ms = tty_pause,
        .now_ms = tty_now,
        .diagnostic = tty_diag,
    };
    const struct mesh_terminal_attach_config config = {
        .pairing_id = pairing, .interactive = interactive};
    return mesh_terminal_attach_run(&config, fake_rpc, n, &tty);
}

static bool sent_is(const struct fake_node *n, const char *want)
{
    return n->sent_len == strlen(want) && memcmp(n->sent, want, n->sent_len) == 0;
}

static int test_data_both_ways(void)
{
    int failures = 0;
    TEST("mesh terminal attach: keystrokes reach the remote, screen bytes "
         "reach stdout only, the close evidence lands on stderr") {
        struct fake_node n;
        struct fake_term t;
        fake_init(&n, &t);
        n.output = "hello\r\n";
        n.end_at_read = 3;
        n.evidence_reason = "worker-exited";
        t.inputs[0] = "ls\n";
        t.input_count = 1;
        int rc = run(&n, &t, true, PAIRING);
        ASSERT_EQ(rc, 0);
        ASSERT(sent_is(&n, "ls\n"));
        ASSERT_EQ(t.out_len, (size_t)7);
        ASSERT(memcmp(t.out, "hello\r\n", 7) == 0);
        ASSERT(strstr(t.err, "reason=worker-exited bytes_in=3 bytes_out=7 "
                             "duration_s=2") != NULL);
        ASSERT(n.open_has_geometry);
        ASSERT_EQ(n.open_cols, 100u);
        ASSERT_EQ(n.open_rows, 40u);
        ASSERT_EQ(t.raw_on_count, 1);
        ASSERT_EQ(t.raw_off_count, 1);
        ASSERT(!t.raw_state);
        ASSERT(t.min_timeout_ms >= 20);
        PASS();
    } _test_next:;
    return failures;
}

static int test_resize(void)
{
    int failures = 0;
    TEST("mesh terminal attach: a window change is sent as a resize") {
        struct fake_node n;
        struct fake_term t;
        fake_init(&n, &t);
        n.end_at_read = 6;
        n.evidence_reason = "worker-exited";
        t.resize_at_call = 3;
        int rc = run(&n, &t, true, PAIRING);
        ASSERT_EQ(rc, 0);
        ASSERT_EQ(n.resizes, 1);
        ASSERT_EQ(n.resize_cols, 120u);
        ASSERT_EQ(n.resize_rows, 50u);
        PASS();
    } _test_next:;
    return failures;
}

static int test_detach_escape(void)
{
    int failures = 0;
    TEST("mesh terminal attach: ~. at line start detaches, ~~ sends one "
         "tilde, a mid-line ~. is data") {
        struct fake_node n;
        struct fake_term t;
        fake_init(&n, &t);
        t.inputs[0] = "a~.\n";
        t.inputs[1] = "~~b\n";
        t.inputs[2] = "~x\n";
        t.inputs[3] = "~.";
        t.input_count = 4;
        int rc = run(&n, &t, true, PAIRING);
        ASSERT_EQ(rc, 0);
        ASSERT(sent_is(&n, "a~.\n~b\n~x\n"));
        ASSERT_EQ(n.closes, 1);
        ASSERT(strstr(t.err, "z23: detached") != NULL);
        ASSERT_EQ(t.raw_off_count, 1);
        ASSERT(!t.raw_state);
        PASS();
    } _test_next:;
    return failures;
}

static int test_remote_close_classes(void)
{
    int failures = 0;
    TEST("mesh terminal attach: a limit close exits 5 and still prints the "
         "evidence") {
        struct fake_node n;
        struct fake_term t;
        fake_init(&n, &t);
        n.end_at_read = 2;
        n.evidence_reason = "idle-timeout";
        int rc = run(&n, &t, true, PAIRING);
        ASSERT_EQ(rc, 5);
        ASSERT(strstr(t.err, "reason=idle-timeout") != NULL);
        ASSERT_EQ(n.closes, 0);
        PASS();
    } _test_next:;
    return failures;
}

static int test_non_interactive(void)
{
    int failures = 0;
    TEST("mesh terminal attach: piped stdin sends the bytes then one EOT, "
         "never goes raw, leaves stdout to the remote") {
        struct fake_node n;
        struct fake_term t;
        fake_init(&n, &t);
        n.output = "hi\n";
        n.end_at_read = 4;
        n.evidence_reason = "worker-exited";
        t.inputs[0] = "echo hi\n";
        t.input_count = 1;
        t.eof_after_inputs = true;
        int rc = run(&n, &t, false, PAIRING);
        ASSERT_EQ(rc, 0);
        ASSERT(sent_is(&n, "echo hi\n\x04"));
        ASSERT_EQ(t.out_len, (size_t)3);
        ASSERT(memcmp(t.out, "hi\n", 3) == 0);
        ASSERT_EQ(t.raw_on_count, 0);
        ASSERT(!n.open_has_geometry);
        ASSERT(strstr(t.err, "attached") == NULL);
        ASSERT(strstr(t.err, "z23: terminal closed:") != NULL);
        PASS();
    } _test_next:;
    return failures;
}

static int test_refusals(void)
{
    int failures = 0;
    TEST("mesh terminal attach: an open refusal is printed verbatim and "
         "classed transient") {
        struct fake_node n;
        struct fake_term t;
        fake_init(&n, &t);
        n.open_error_code = "peer_not_connected";
        int rc = run(&n, &t, true, PAIRING);
        ASSERT_EQ(rc, 5);
        ASSERT(strstr(t.err, "z23: refused: peer_not_connected: the paired "
                             "peer has no established Noise session") != NULL);
        ASSERT_EQ(n.polls, 0);
        ASSERT_EQ(t.raw_on_count, 0);
        ASSERT_EQ(t.out_len, (size_t)0);
        PASS();
    } _test_next:;
    return failures;
}

static int test_hostile_text(void)
{
    int failures = 0;
    TEST("mesh terminal attach: control bytes in node and responder text "
         "never reach the terminal") {
        struct fake_node n;
        struct fake_term t;
        fake_init(&n, &t);
        n.open_error_code = "peer_not_connected";
        n.open_message = "\\u001b[31mred\\u0007";
        ASSERT_EQ(run(&n, &t, true, PAIRING), 5);
        ASSERT(strchr(t.err, 0x1b) == NULL);
        ASSERT(strchr(t.err, 0x07) == NULL);
        ASSERT(strstr(t.err, "?[31mred?") != NULL);
        fake_init(&n, &t);
        n.end_at_read = 2;
        n.evidence_reason = "x\\u001b[2J";
        run(&n, &t, true, PAIRING);
        ASSERT(strchr(t.err, 0x1b) == NULL);
        ASSERT(strstr(t.err, "reason=x?[2J") != NULL);
        PASS();
    } _test_next:;
    return failures;
}

static int test_blocked_writer_stops(void)
{
    int failures = 0;
    int fds[2] = {-1, -1};
    TEST("mesh terminal attach: a stalled output write gives up at once "
         "when a stop is pending") {
        ASSERT_EQ(pipe(fds), 0);
        ASSERT(fcntl(fds[1], F_SETFL, O_NONBLOCK) == 0);
        uint8_t fill[4096];
        memset(fill, 'x', sizeof(fill));
        while (write(fds[1], fill, sizeof(fill)) > 0) {
        }
        zcl_native_mesh_terminal_test_set_stop(true);
        int64_t start = platform_time_monotonic_ms();
        bool wrote = zcl_native_mesh_terminal_write_all(fds[1], fill, 16);
        int64_t took = platform_time_monotonic_ms() - start;
        zcl_native_mesh_terminal_test_set_stop(false);
        ASSERT(!wrote);
        ASSERT(took < 1000);
        PASS();
    } _test_next:;
    zcl_native_mesh_terminal_test_set_stop(false);
    if (fds[0] >= 0) {
        close(fds[0]);
        close(fds[1]);
    }
    return failures;
}

static int test_node_unreachable(void)
{
    int failures = 0;
    TEST("mesh terminal attach: an unreachable node is named from the RPC "
         "client's own words and classed transient") {
        struct fake_node n;
        struct fake_term t;
        fake_init(&n, &t);
        n.transport_error = true;
        ASSERT_EQ(run(&n, &t, true, PAIRING), 5);
        ASSERT(strstr(t.err, "z23: refused: NODE_UNAVAILABLE: socket failed") !=
               NULL);
        ASSERT_EQ(t.out_len, (size_t)0);
        PASS();
    } _test_next:;
    return failures;
}

static int test_refusal_verdict(void)
{
    int failures = 0;
    TEST("mesh terminal attach: a responder verdict is printed by name, "
         "classed denied, and the session is released") {
        struct fake_node n;
        struct fake_term t;
        fake_init(&n, &t);
        n.refused_verdict = "capability-unavailable";
        int rc = run(&n, &t, true, PAIRING);
        ASSERT_EQ(rc, 4);
        ASSERT(strstr(t.err, "z23: refused: capability-unavailable:") != NULL);
        ASSERT_EQ(n.closes, 1);
        ASSERT_EQ(t.raw_on_count, 0);
        PASS();
    } _test_next:;
    return failures;
}

static int test_refusal_confinement(void)
{
    int failures = 0;
    TEST("mesh terminal attach: confinement-unavailable is classed blocked") {
        struct fake_node n;
        struct fake_term t;
        fake_init(&n, &t);
        n.refused_verdict = "confinement-unavailable";
        ASSERT_EQ(run(&n, &t, true, PAIRING), 3);
        PASS();
    } _test_next:;
    return failures;
}

static int test_refusal_concurrency(void)
{
    int failures = 0;
    TEST("mesh terminal attach: concurrency-limit is classed transient") {
        struct fake_node n;
        struct fake_term t;
        fake_init(&n, &t);
        n.refused_verdict = "concurrency-limit";
        ASSERT_EQ(run(&n, &t, true, PAIRING), 5);
        PASS();
    } _test_next:;
    return failures;
}

static int test_stop(void)
{
    int failures = 0;
    TEST("mesh terminal attach: a termination signal closes the session, "
         "restores the terminal and exits 130") {
        struct fake_node n;
        struct fake_term t;
        fake_init(&n, &t);
        t.stop_at_call = 4;
        int rc = run(&n, &t, true, PAIRING);
        ASSERT_EQ(rc, 130);
        ASSERT_EQ(n.closes, 1);
        ASSERT(strstr(t.err, "z23: interrupted") != NULL);
        ASSERT_EQ(t.raw_on_count, 1);
        ASSERT_EQ(t.raw_off_count, 1);
        ASSERT(!t.raw_state);
        PASS();
    } _test_next:;
    return failures;
}

static int test_timeout(void)
{
    int failures = 0;
    TEST("mesh terminal attach: an unanswered open ends at the answer "
         "window with a bounded number of polls") {
        struct fake_node n;
        struct fake_term t;
        fake_init(&n, &t);
        n.opening_polls = 100000;
        int rc = run(&n, &t, true, PAIRING);
        ASSERT_EQ(rc, 5);
        ASSERT(strstr(t.err, "OPEN_TIMEOUT") != NULL);
        ASSERT(n.polls <= 360);
        ASSERT_EQ(n.closes, 1);
        PASS();
    } _test_next:;
    return failures;
}

static int test_bad_pairing(void)
{
    int failures = 0;
    TEST("mesh terminal attach: a malformed pairing id never reaches the "
         "node") {
        struct fake_node n;
        struct fake_term t;
        fake_init(&n, &t);
        ASSERT_EQ(run(&n, &t, true, "ABC\",\"x\":\"y"), 2);
        ASSERT_EQ(n.calls, 0);
        ASSERT(strstr(t.err, "INVALID_PAIRING_ID") != NULL);
        PASS();
    } _test_next:;
    return failures;
}

int test_mesh_terminal_attach(void)
{
    int failures = 0;
    failures += test_data_both_ways();
    failures += test_resize();
    failures += test_detach_escape();
    failures += test_remote_close_classes();
    failures += test_non_interactive();
    failures += test_refusals();
    failures += test_node_unreachable();
    failures += test_blocked_writer_stops();
    failures += test_hostile_text();
    failures += test_refusal_verdict();
    failures += test_refusal_confinement();
    failures += test_refusal_concurrency();
    failures += test_stop();
    failures += test_timeout();
    failures += test_bad_pairing();
    return failures;
}
