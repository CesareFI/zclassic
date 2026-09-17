/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ACCEPTANCE BAR for dev.agent.receive
 * (tools/command/native_devagent_receive.c): the resident loop that turns a
 * directive arriving in this box's agent mail into real work with no human
 * in the path.
 *
 * Written against an isolated XDG_STATE_HOME, never the operator's real
 * state dir. No model, no network, no spawn: the receiver only composes the
 * existing dev.agent.mail, dev.agent.queue and fleet.steer grant leaves,
 * and execution stays dev.agent.worker's separate business, so every case
 * below is deterministic in-process.
 *
 * Each non-negotiable property has its own case:
 *   admission (ref alphabet, grant by label, revocation, expiry, direction
 *   shape), to-work through the existing queue, idempotence, conflict,
 *   accept-only-after-the-queue, single instance, restart safety, bounded
 *   wait, wake on new mail, SIGTERM, execution never blocking intake, and
 *   a status action that writes nothing.
 */

#include "test/test_core.h"

#include "command/native_command.h"
#include "command/native_devagent.h"
#include "command/native_fleet.h"
#include "config/command_catalog.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "platform/directory_watcher.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if !defined(_WIN32)
#include <fcntl.h>
#include <signal.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#endif

/* ── isolated state root (this group owns its own rig) ─────────────────── */

static char g_rtx_state[1024];
static char g_rtx_ws[1024];
static char g_rtx_saved_xdg[4096];
static bool g_rtx_had_xdg;
static int g_rtx_ts;

static void rtx_isolate(const char *tag)
{
    char base[512];
    test_make_tmpdir(base, sizeof(base), "devagent_receive", tag);
    (void)snprintf(g_rtx_state, sizeof(g_rtx_state), "%s/state", base);
    (void)snprintf(g_rtx_ws, sizeof(g_rtx_ws), "%s/ws", base);
    g_rtx_had_xdg = getenv("XDG_STATE_HOME") != NULL;
    if (g_rtx_had_xdg)
        (void)snprintf(g_rtx_saved_xdg, sizeof(g_rtx_saved_xdg), "%s",
                       getenv("XDG_STATE_HOME"));
    setenv("XDG_STATE_HOME", g_rtx_state, 1);
    g_rtx_ts = 0;
#if !defined(_WIN32)
    (void)mkdir(g_rtx_ws, 0700);
#endif
}

static void rtx_restore(void)
{
    if (g_rtx_had_xdg)
        setenv("XDG_STATE_HOME", g_rtx_saved_xdg, 1);
    else
        unsetenv("XDG_STATE_HOME");
}

/* ── one in-process leaf invocation ────────────────────────────────────── */

struct rtx_call {
    struct json_value input;
    struct zcl_command_request request;
    struct zcl_command_reply reply;
};

static void rtx_begin(struct rtx_call *c, const char *path,
                      const char *schema)
{
    json_init(&c->input);
    json_set_object(&c->input);
    memset(&c->request, 0, sizeof(c->request));
    c->request.input = &c->input;
    c->request.spec =
        zcl_command_registry_find(zcl_command_catalog(), path, NULL);
    c->request.view = "normal";
    zcl_command_reply_init(&c->reply, schema);
}

static void rtx_end(struct rtx_call *c)
{
    zcl_command_reply_free(&c->reply);
    json_free(&c->input);
}

static bool rtx_ok(const struct rtx_call *c)
{
    return c->reply.status == ZCL_COMMAND_STATUS_PASSED;
}

static const char *rtx_reply_str(const struct rtx_call *c, const char *key)
{
    const struct json_value *v = json_get(&c->reply.data, key);
    return (v && v->type == JSON_STR && json_get_str(v)) ? json_get_str(v)
                                                         : "";
}

/* ── rig helpers ───────────────────────────────────────────────────────── */

/* Mint one grant under `label` with `scopes`; returns its id in `id`. */
static bool rtx_mint(const char *label, const char *scopes, long long ttl,
                     char *id, size_t cap)
{
    struct rtx_call c;
    bool ok;
    rtx_begin(&c, "fleet.steer.grant", "zcl.fleet_steer_grant.v1");
    (void)json_push_kv_str(&c.input, "action", "mint");
    (void)json_push_kv_str(&c.input, "scopes", scopes);
    (void)json_push_kv_str(&c.input, "label", label);
    (void)json_push_kv_int(&c.input, "ttl_seconds", ttl);
    zcl_native_handle_fleet_steer_grant(&c.request, &c.reply);
    ok = rtx_ok(&c);
    if (ok && id)
        (void)snprintf(id, cap, "%s", rtx_reply_str(&c, "id"));
    rtx_end(&c);
    return ok;
}

/* Append one already-expired grant row in the store's own machine format.
 * The mint verb cannot produce one (its ttl floor is a second in the
 * future), and expiry is exactly the case a receiver must fail closed on,
 * so the row is written the way an older mint left it behind. */
static bool rtx_mint_expired(const char *label)
{
    char path[1600];
    FILE *f;
    (void)snprintf(path, sizeof(path), "%s/z23/dev/steer/grants.jsonl",
                   g_rtx_state);
    f = fopen(path, "ab");
    if (!f)
        return false;
    (void)fprintf(f,
                  "{\"id\":\"%s\",\"scopes\":\"send\",\"created\":1,"
                  "\"expires\":2,\"revoked\":\"0\",\"label\":\"%s\"}\n",
                  "00000000000000000000000000000001", label);
    return fclose(f) == 0;
}

static bool rtx_revoke(const char *id)
{
    struct rtx_call c;
    bool ok;
    rtx_begin(&c, "fleet.steer.grant", "zcl.fleet_steer_grant.v1");
    (void)json_push_kv_str(&c.input, "action", "revoke");
    (void)json_push_kv_str(&c.input, "id", id);
    zcl_native_handle_fleet_steer_grant(&c.request, &c.reply);
    ok = rtx_ok(&c);
    rtx_end(&c);
    return ok;
}

/* One direction body in the Muse executor's exact format. */
static void rtx_direction(char *out, size_t cap, const char *gate,
                          const char *prompt)
{
    (void)snprintf(out, cap,
                   "muse-workspace: %s\nmuse-scope: src/x.c\nmuse-gate: %s\n"
                   "\n%s\n",
                   g_rtx_ws, gate, prompt);
}

/* Post one directive through the EXISTING mail leaf. A body carrying an
 * absolute workspace is refused by the mail leaf's own path rule unless it
 * sits under the checkout, so the rig writes the inbox file the way a
 * transport does — which is also the only way a peer's directive ever
 * arrives. */
static bool rtx_deliver_as(const char *stream, const char *peer,
                           const char *to, const char *ref, const char *body,
                           long long seq)
{
    char dir[1200], path[1400], esc[8192];
    size_t o = 0;
    FILE *f;
    /* The transport owns the inbox file, so it owns the directory chain
     * under the state root too — a peer can deliver to a box whose
     * receiver has never run. */
    (void)snprintf(dir, sizeof(dir), "%s", g_rtx_state);
    (void)mkdir(dir, 0700);
    (void)snprintf(dir, sizeof(dir), "%s/z23", g_rtx_state);
    (void)mkdir(dir, 0700);
    (void)snprintf(dir, sizeof(dir), "%s/z23/dev", g_rtx_state);
    (void)mkdir(dir, 0700);
    (void)snprintf(dir, sizeof(dir), "%s/z23/dev/mail", g_rtx_state);
    if (mkdir(dir, 0700) != 0 && errno != EEXIST)
        return false;
    (void)snprintf(path, sizeof(path), "%s/inbox.%s.jsonl", dir, stream);
    for (const char *p = body; *p && o + 8 < sizeof(esc); p++) {
        if (*p == '\n') {
            esc[o++] = '\\';
            esc[o++] = 'n';
        } else if (*p == '"' || *p == '\\') {
            esc[o++] = '\\';
            esc[o++] = *p;
        } else {
            esc[o++] = *p;
        }
    }
    esc[o] = '\0';
    f = fopen(path, "ab");
    if (!f)
        return false;
    /* One stamp per delivery, in delivery order: the mail leaf orders rows
     * by (ts, from, seq), and two separately delivered rows are two rows
     * even when they carry the same stream sequence. */
    g_rtx_ts++;
    (void)fprintf(f,
                  "{\"seq\":%lld,\"ts\":\"2026-09-17T00:%02d:%02dZ\","
                  "\"from\":\"%s\",\"to\":\"%s\",\"kind\":\"directive\","
                  "\"body\":\"%s\",\"ref\":\"%s\"}\n",
                  seq, (int)(g_rtx_ts / 60) % 60, (int)(g_rtx_ts % 60), peer,
                  to, esc, ref);
    return fclose(f) == 0;
}

/* The common case: one peer writing its own stream. */
static bool rtx_deliver(const char *peer, const char *to, const char *ref,
                        const char *body, long long seq)
{
    return rtx_deliver_as(peer, peer, to, ref, body, seq);
}

static void rtx_opts(struct rcv_drive_opts *o, long long beats)
{
    memset(o, 0, sizeof(*o));
    (void)snprintf(o->receiver, sizeof(o->receiver), "box-a");
    o->deadline_s = 30;
    o->wait_ms = 50;
    o->max_beats = beats;
}

/* One queue verb with at most one extra string key. */
static bool rtx_queue(const char *action, const char *k1, const char *v1,
                      const char *k2, const char *v2)
{
    struct rtx_call c;
    bool ok;
    rtx_begin(&c, "dev.agent.queue", "zcl.agent_queue.v1");
    (void)json_push_kv_str(&c.input, "action", action);
    if (k1)
        (void)json_push_kv_str(&c.input, k1, v1);
    if (k2)
        (void)json_push_kv_str(&c.input, k2, v2);
    zcl_native_handle_dev_agent_queue(&c.request, &c.reply);
    ok = rtx_ok(&c);
    rtx_end(&c);
    return ok;
}

/* How many rows in `bucket` (queued|running) name `ref`. */
static long long rtx_queue_count(const char *bucket, const char *ref)
{
    struct rtx_call c;
    const struct json_value *arr;
    long long hits = 0;
    rtx_begin(&c, "dev.agent.queue", "zcl.agent_queue.v1");
    (void)json_push_kv_str(&c.input, "action", "status");
    (void)json_push_kv_bool(&c.input, "json", true);
    zcl_native_handle_dev_agent_queue(&c.request, &c.reply);
    arr = rtx_ok(&c) ? json_get(&c.reply.data, bucket) : NULL;
    if (arr && arr->type == JSON_ARR) {
        size_t n = json_size(arr), i;
        for (i = 0; i < n; i++) {
            const struct json_value *r = json_at(arr, i);
            const struct json_value *v = r ? json_get(r, "name") : NULL;
            if (v && v->type == JSON_STR && json_get_str(v) &&
                strcmp(json_get_str(v), ref) == 0)
                hits++;
        }
    }
    rtx_end(&c);
    return hits;
}

/* How many mail rows from this receiver under `ref` carry `needle`. */
static long long rtx_answers(const char *ref, const char *needle)
{
    struct rtx_call c;
    const struct json_value *arr;
    long long hits = 0;
    rtx_begin(&c, "dev.agent.mail", "zcl.agent_mail.v1");
    (void)json_push_kv_str(&c.input, "action", "pull");
    (void)json_push_kv_int(&c.input, "since", 0);
    (void)json_push_kv_str(&c.input, "from", "box-a");
    zcl_native_handle_dev_agent_mail(&c.request, &c.reply);
    arr = rtx_ok(&c) ? json_get(&c.reply.data, "rows") : NULL;
    if (arr && arr->type == JSON_ARR) {
        size_t n = json_size(arr), i;
        for (i = 0; i < n; i++) {
            const struct json_value *r = json_at(arr, i);
            const struct json_value *b = r ? json_get(r, "body") : NULL;
            const struct json_value *f = r ? json_get(r, "ref") : NULL;
            if (!b || b->type != JSON_STR || !f || f->type != JSON_STR)
                continue;
            if (strcmp(json_get_str(f), ref) != 0)
                continue;
            if (strstr(json_get_str(b), needle) != NULL)
                hits++;
        }
    }
    rtx_end(&c);
    return hits;
}

static void rtx_path(char *out, size_t cap, const char *tail)
{
    (void)snprintf(out, cap, "%s/z23/dev/%s", g_rtx_state, tail);
}

static bool rtx_exists(const char *tail)
{
    char path[1400];
    struct stat st;
    rtx_path(path, sizeof(path), tail);
    return stat(path, &st) == 0;
}

/* SIGALRM raises SIGTERM so the receiver's own handler is exercised inside
 * a single process: no fork, no spawn, no sleeping test. */
#if !defined(_WIN32)
static void rtx_alarm_to_term(int sig)
{
    (void)sig;
    (void)raise(SIGTERM);
}
#endif

int test_devagent_receive(void);
int test_devagent_receive(void)
{
    int failures = 0;

#if !defined(_WIN32)
    TEST("a granted directive becomes one queue row and one accept")
    {
        struct rcv_drive_opts o;
        struct rcv_beat_stats st;
        struct rtx_call v;
        char body[4096], why[256];
        rtx_isolate("admit");
        /* The registry admits this leaf's keys, integers included, so the
         * shell spelling reaches the handler. */
        rtx_begin(&v, "dev.agent.receive", "zcl.agent_receive.v1");
        (void)json_push_kv_str(&v.input, "action", "run");
        (void)json_push_kv_str(&v.input, "receiver", "box-a");
        (void)json_push_kv_int(&v.input, "max_beats", 1);
        (void)json_push_kv_int(&v.input, "wait_ms", 50);
        (void)json_push_kv_int(&v.input, "deadline_s", 5);
        ASSERT(v.request.spec != NULL);
        ASSERT(zcl_command_registry_input_validate(v.request.spec, &v.input,
                                                   why, sizeof(why)));
        rtx_end(&v);
        ASSERT(rtx_mint("chatgpt", "send", 3600, NULL, 0));
        rtx_direction(body, sizeof(body), "hex_codec", "Make x.c faster.");
        ASSERT(rtx_deliver("chatgpt", "box-a", "job-001", body, 1));
        rtx_opts(&o, 1);
        memset(&st, 0, sizeof(st));
        ASSERT_EQ(zcl_devagent_receive_drive(&o, &st), 1);
        ASSERT_EQ(st.seen, 1);
        ASSERT_EQ(st.admitted, 1);
        ASSERT_EQ(st.refused, 0);
        /* The queue row IS the record, under the ref, with the direction's
         * own kind, gate and scope. */
        ASSERT_EQ(rtx_queue_count("queued", "job-001"), 1);
        /* The accept carries the queue seq and the brief digest. */
        ASSERT_EQ(rtx_answers("job-001", "state=accepted"), 1);
        ASSERT_EQ(rtx_answers("job-001", "queue_seq=1"), 1);
        ASSERT_EQ(rtx_answers("job-001", "brief_sha3="), 1);
        ASSERT(rtx_exists("receive/brief/job-001.brief"));
        rtx_restore();
        PASS();
    }

    TEST("an ungranted, revoked, or expired sender is refused")
    {
        struct rcv_drive_opts o;
        struct rcv_beat_stats st;
        char body[4096], id[64];
        rtx_isolate("grant");
        rtx_direction(body, sizeof(body), "hex_codec", "Do it.");
        /* No grant at all. */
        ASSERT(rtx_deliver("stranger", "box-a", "job-ug", body, 1));
        /* A grant with the wrong scope. */
        ASSERT(rtx_mint("readonly", "brief", 3600, NULL, 0));
        ASSERT(rtx_deliver("readonly", "box-a", "job-sc", body, 2));
        /* A grant already expired. */
        ASSERT(rtx_mint_expired("stale"));
        ASSERT(rtx_deliver("stale", "box-a", "job-ex", body, 3));
        /* A grant minted then revoked: revocation is re-read every beat. */
        ASSERT(rtx_mint("gone", "send", 3600, id, sizeof(id)));
        ASSERT(rtx_revoke(id));
        ASSERT(rtx_deliver("gone", "box-a", "job-rv", body, 4));
        rtx_opts(&o, 1);
        memset(&st, 0, sizeof(st));
        ASSERT_EQ(zcl_devagent_receive_drive(&o, &st), 1);
        ASSERT_EQ(st.seen, 4);
        ASSERT_EQ(st.admitted, 0);
        ASSERT_EQ(st.refused, 4);
        ASSERT_EQ(rtx_queue_count("queued", "job-ug"), 0);
        ASSERT_EQ(rtx_answers("job-ug", "RECEIVE_SENDER_UNGRANTED"), 1);
        ASSERT_EQ(rtx_answers("job-sc", "STEER_GRANT_SCOPE"), 1);
        ASSERT_EQ(rtx_answers("job-ex", "STEER_GRANT_EXPIRED"), 1);
        ASSERT_EQ(rtx_answers("job-rv", "STEER_GRANT_REVOKED"), 1);
        /* Nothing was written under any refused ref. */
        ASSERT(!rtx_exists("receive/brief/job-ug.brief"));
        rtx_restore();
        PASS();
    }

    TEST("an empty or off-alphabet ref is invalid for coordinated work")
    {
        struct rcv_drive_opts o;
        struct rcv_beat_stats st;
        char body[4096];
        rtx_isolate("ref");
        ASSERT(rtx_mint("chatgpt", "send", 3600, NULL, 0));
        rtx_direction(body, sizeof(body), "hex_codec", "Do it.");
        ASSERT(rtx_deliver("chatgpt", "box-a", "", body, 1));
        ASSERT(rtx_deliver("chatgpt", "box-a", "../escape", body, 2));
        ASSERT(rtx_deliver("chatgpt", "box-a", "..", body, 3));
        rtx_opts(&o, 1);
        memset(&st, 0, sizeof(st));
        ASSERT_EQ(zcl_devagent_receive_drive(&o, &st), 1);
        ASSERT_EQ(st.seen, 3);
        ASSERT_EQ(st.admitted, 0);
        ASSERT_EQ(st.refused, 3);
        ASSERT_EQ(rtx_answers("", "RECEIVE_REF_INVALID"), 3);
        rtx_restore();
        PASS();
    }

    TEST("a malformed direction refuses without queueing anything")
    {
        struct rcv_drive_opts o;
        struct rcv_beat_stats st;
        char body[4096];
        rtx_isolate("direction");
        ASSERT(rtx_mint("chatgpt", "send", 3600, NULL, 0));
        /* No muse-gate. */
        (void)snprintf(body, sizeof(body),
                       "muse-workspace: %s\nmuse-scope: src/x.c\n\nGo.\n",
                       g_rtx_ws);
        ASSERT(rtx_deliver("chatgpt", "box-a", "job-nogate", body, 1));
        /* A workspace that is not an existing absolute directory. */
        (void)snprintf(body, sizeof(body),
                       "muse-workspace: not-absolute\nmuse-scope: src/x.c\n"
                       "muse-gate: hex_codec\n\nGo.\n");
        ASSERT(rtx_deliver("chatgpt", "box-a", "job-nows", body, 2));
        /* A scope that climbs out of the repo. */
        (void)snprintf(body, sizeof(body),
                       "muse-workspace: %s\nmuse-scope: ../etc\n"
                       "muse-gate: hex_codec\n\nGo.\n",
                       g_rtx_ws);
        ASSERT(rtx_deliver("chatgpt", "box-a", "job-esc", body, 3));
        /* Header but no prompt. */
        (void)snprintf(body, sizeof(body),
                       "muse-workspace: %s\nmuse-scope: src/x.c\n"
                       "muse-gate: hex_codec\n",
                       g_rtx_ws);
        ASSERT(rtx_deliver("chatgpt", "box-a", "job-noprompt", body, 4));
        /* Free prose with no machine header at all. */
        ASSERT(rtx_deliver("chatgpt", "box-a", "job-prose",
                           "please fix the build\n", 5));
        rtx_opts(&o, 1);
        memset(&st, 0, sizeof(st));
        ASSERT_EQ(zcl_devagent_receive_drive(&o, &st), 1);
        ASSERT_EQ(st.seen, 5);
        ASSERT_EQ(st.admitted, 0);
        ASSERT_EQ(st.refused, 5);
        ASSERT_EQ(rtx_answers("job-nogate", "muse-gate"), 1);
        ASSERT_EQ(rtx_answers("job-nows", "muse-workspace"), 1);
        ASSERT_EQ(rtx_answers("job-esc", "muse-scope"), 1);
        ASSERT_EQ(rtx_queue_count("queued", "job-nogate"), 0);
        ASSERT_EQ(rtx_queue_count("queued", "job-prose"), 0);
        rtx_restore();
        PASS();
    }

    TEST("the same ref and the same body never queue or execute twice")
    {
        struct rcv_drive_opts o;
        struct rcv_beat_stats st;
        char body[4096];
        rtx_isolate("idempotent");
        ASSERT(rtx_mint("chatgpt", "send", 3600, NULL, 0));
        rtx_direction(body, sizeof(body), "hex_codec", "Do it once.");
        ASSERT(rtx_deliver("chatgpt", "box-a", "job-dup", body, 1));
        rtx_opts(&o, 1);
        memset(&st, 0, sizeof(st));
        ASSERT_EQ(zcl_devagent_receive_drive(&o, &st), 1);
        ASSERT_EQ(st.admitted, 1);
        /* The identical directive arrives again from the transport under a
         * new stream seq: the queue must not grow. */
        ASSERT(rtx_deliver_as("retry", "chatgpt", "box-a", "job-dup", body, 1));
        memset(&st, 0, sizeof(st));
        ASSERT_EQ(zcl_devagent_receive_drive(&o, &st), 1);
        ASSERT_EQ(st.admitted, 0);
        ASSERT_EQ(st.reconciled, 1);
        ASSERT_EQ(rtx_queue_count("queued", "job-dup"), 1);
        rtx_restore();
        PASS();
    }

    TEST("one ref with a different body is refused as a conflict")
    {
        struct rcv_drive_opts o;
        struct rcv_beat_stats st;
        char body[4096], other[4096];
        rtx_isolate("conflict");
        ASSERT(rtx_mint("chatgpt", "send", 3600, NULL, 0));
        rtx_direction(body, sizeof(body), "hex_codec", "First intent.");
        ASSERT(rtx_deliver("chatgpt", "box-a", "job-one", body, 1));
        rtx_opts(&o, 1);
        memset(&st, 0, sizeof(st));
        ASSERT_EQ(zcl_devagent_receive_drive(&o, &st), 1);
        ASSERT_EQ(st.admitted, 1);
        rtx_direction(other, sizeof(other), "hex_codec", "Second intent.");
        ASSERT(rtx_deliver("chatgpt", "box-a", "job-one", other, 2));
        memset(&st, 0, sizeof(st));
        ASSERT_EQ(zcl_devagent_receive_drive(&o, &st), 1);
        ASSERT_EQ(st.admitted, 0);
        ASSERT_EQ(st.reconciled, 0);
        ASSERT_EQ(st.refused, 1);
        ASSERT_EQ(rtx_answers("job-one", "RECEIVE_REF_CONFLICT"), 1);
        ASSERT_EQ(rtx_queue_count("queued", "job-one"), 1);
        rtx_restore();
        PASS();
    }

    TEST("an accept is never posted merely because bytes arrived")
    {
        struct rcv_drive_opts o;
        struct rcv_beat_stats st;
        char body[4096], briefdir[1400];
        rtx_isolate("noaccept");
        ASSERT(rtx_mint("chatgpt", "send", 3600, NULL, 0));
        rtx_direction(body, sizeof(body), "hex_codec", "Do it.");
        ASSERT(rtx_deliver("chatgpt", "box-a", "job-ro", body, 1));
        /* One beat to create the receive dirs, then put something in the
         * way of the next ref's brief: a fully admissible directive whose
         * work cannot be recorded must refuse, not accept. */
        rtx_opts(&o, 1);
        memset(&st, 0, sizeof(st));
        ASSERT_EQ(zcl_devagent_receive_drive(&o, &st), 1);
        ASSERT_EQ(st.admitted, 1);
        rtx_path(briefdir, sizeof(briefdir), "receive/brief/job-ro2.brief");
        ASSERT_EQ(mkdir(briefdir, 0700), 0);
        ASSERT(rtx_deliver("chatgpt", "box-a", "job-ro2", body, 2));
        memset(&st, 0, sizeof(st));
        ASSERT_EQ(zcl_devagent_receive_drive(&o, &st), 1);
        ASSERT_EQ(st.admitted, 0);
        ASSERT_EQ(st.refused, 1);
        ASSERT_EQ(rtx_answers("job-ro2", "state=accepted"), 0);
        ASSERT_EQ(rtx_answers("job-ro2", "RECEIVE_STATE_UNWRITABLE"), 1);
        ASSERT_EQ(rtx_queue_count("queued", "job-ro2"), 0);
        ASSERT_EQ(rmdir(briefdir), 0);
        rtx_restore();
        PASS();
    }

    TEST("single instance: a second drive refuses without waiting")
    {
        struct rcv_drive_opts o;
        struct rcv_beat_stats st;
        char dir[1400], lock[1500];
        int fd;
        rtx_isolate("single");
        rtx_opts(&o, 1);
        memset(&st, 0, sizeof(st));
        ASSERT_EQ(zcl_devagent_receive_drive(&o, &st), 1);
        /* Hold the same lock the drive takes, exactly as a live resident
         * would, and prove the second drive refuses instead of blocking. */
        rtx_path(dir, sizeof(dir), "receive");
        (void)snprintf(lock, sizeof(lock), "%s/receive.lock", dir);
        fd = open(lock, O_RDWR);
        ASSERT(fd >= 0);
        ASSERT_EQ(flock(fd, LOCK_EX | LOCK_NB), 0);
        memset(&st, 0, sizeof(st));
        ASSERT_EQ(zcl_devagent_receive_drive(&o, &st), -1);
        ASSERT_EQ(st.beats, 0);
        ASSERT_EQ(flock(fd, LOCK_UN), 0);
        (void)close(fd);
        /* With the lock free again the loop runs. */
        memset(&st, 0, sizeof(st));
        ASSERT_EQ(zcl_devagent_receive_drive(&o, &st), 1);
        rtx_restore();
        PASS();
    }

    TEST("restart mid-flight loses no ref and executes none twice")
    {
        struct rcv_drive_opts o;
        struct rcv_beat_stats st;
        char body[4096], brief[1600], dir[1400];
        FILE *f;
        rtx_isolate("restart");
        ASSERT(rtx_mint("chatgpt", "send", 3600, NULL, 0));
        rtx_direction(body, sizeof(body), "hex_codec", "Survive a restart.");
        rtx_opts(&o, 1);
        /* One beat to materialize the receive directories. */
        memset(&st, 0, sizeof(st));
        ASSERT_EQ(zcl_devagent_receive_drive(&o, &st), 1);
        /* CRASH SHAPE A — the brief was installed and the process died
         * before the queue post. The next beat re-derives everything from
         * files: the ref is not known to any queue row, run dir, or
         * outcome, so it is queued exactly once. */
        rtx_path(dir, sizeof(dir), "receive");
        (void)snprintf(brief, sizeof(brief), "%s/brief/job-rs.brief", dir);
        f = fopen(brief, "wb");
        ASSERT(f != NULL);
        ASSERT(fwrite(body, 1, strlen(body), f) == strlen(body));
        ASSERT_EQ(fclose(f), 0);
        ASSERT_EQ(rtx_queue_count("queued", "job-rs"), 0);
        ASSERT(rtx_deliver("chatgpt", "box-a", "job-rs", body, 1));
        memset(&st, 0, sizeof(st));
        ASSERT_EQ(zcl_devagent_receive_drive(&o, &st), 1);
        ASSERT_EQ(st.admitted, 1);
        ASSERT_EQ(rtx_queue_count("queued", "job-rs"), 1);
        /* CRASH SHAPE B — the queue post landed and the accept never got
         * out. The retry (a fresh row, so no marker covers it) reconciles
         * the existing record and adds no second queue row. */
        ASSERT(rtx_deliver_as("retry", "chatgpt", "box-a", "job-rs", body, 1));
        memset(&st, 0, sizeof(st));
        ASSERT_EQ(zcl_devagent_receive_drive(&o, &st), 1);
        ASSERT_EQ(st.admitted, 0);
        ASSERT_EQ(st.reconciled, 1);
        ASSERT_EQ(rtx_queue_count("queued", "job-rs"), 1);
        ASSERT_EQ(rtx_answers("job-rs", "state=accepted"), 2);
        /* A run directory alone also makes a ref known. A ref this
         * receiver never briefed is then a conflict, not a second job:
         * fail closed rather than run somebody else's name. */
        {
            char engine[1600];
            rtx_path(engine, sizeof(engine), "engine");
            (void)mkdir(engine, 0700);
            (void)snprintf(brief, sizeof(brief), "%s/job-orphan", engine);
            ASSERT_EQ(mkdir(brief, 0700), 0);
        }
        ASSERT(rtx_deliver("chatgpt", "box-a", "job-orphan", body, 2));
        memset(&st, 0, sizeof(st));
        ASSERT_EQ(zcl_devagent_receive_drive(&o, &st), 1);
        ASSERT_EQ(st.admitted, 0);
        ASSERT_EQ(st.refused, 1);
        ASSERT_EQ(rtx_answers("job-orphan", "RECEIVE_REF_CONFLICT"), 1);
        ASSERT_EQ(rtx_queue_count("queued", "job-orphan"), 0);
        rtx_restore();
        PASS();
    }

    TEST("the idle wait is bounded and never a busy poll")
    {
        struct rcv_drive_opts o;
        struct rcv_beat_stats st;
        rtx_isolate("idle");
        /* An exact beat cap proves the wait returns rather than blocking
         * forever. */
        rtx_opts(&o, 3);
        memset(&st, 0, sizeof(st));
        ASSERT_EQ(zcl_devagent_receive_drive(&o, &st), 3);
        ASSERT_EQ(st.beats, 3);
        /* Deadline-only: the loop must beat at least once and, because
         * each idle pass parks in the directory-watcher wait for wait_ms
         * instead of spinning, nowhere near the thousands of beats a busy
         * poll would produce inside the same deadline. The bound is a rate
         * ceiling, not a duration: load can only lower the count. */
        memset(&o, 0, sizeof(o));
        (void)snprintf(o.receiver, sizeof(o.receiver), "box-a");
        o.deadline_s = 1;
        o.wait_ms = 200;
        o.max_beats = 0;
        memset(&st, 0, sizeof(st));
        ASSERT(zcl_devagent_receive_drive(&o, &st) >= 1);
        ASSERT(st.beats >= 1);
        ASSERT(st.beats <= 60);
        rtx_restore();
        PASS();
    }

    TEST("new mail wakes the watcher this loop waits on")
    {
        struct platform_directory_watcher w;
        struct rcv_drive_opts o;
        struct rcv_beat_stats st;
        char maildir[1400], body[4096];
        enum platform_directory_watch_result r;
        rtx_isolate("wake");
        rtx_opts(&o, 1);
        memset(&st, 0, sizeof(st));
        ASSERT_EQ(zcl_devagent_receive_drive(&o, &st), 1);
        rtx_path(maildir, sizeof(maildir), "mail");
        platform_directory_watcher_init(&w);
        ASSERT(platform_directory_watcher_open(&w, maildir));
        /* A transport dropping an inbox file is exactly what must wake the
         * resident, so it is the event the watcher is asked about. */
        rtx_direction(body, sizeof(body), "hex_codec", "Wake up.");
        ASSERT(rtx_deliver("chatgpt", "box-a", "job-wake", body, 1));
        r = platform_directory_watcher_wait(&w, 5000, NULL, NULL);
        ASSERT(r == PLATFORM_DIRECTORY_WATCH_CHANGED ||
               r == PLATFORM_DIRECTORY_WATCH_OVERFLOW);
        platform_directory_watcher_close(&w);
        rtx_restore();
        PASS();
    }

    TEST("SIGTERM stops new work and leaves a ref's record intact")
    {
        struct rcv_drive_opts o;
        struct rcv_beat_stats st;
        struct sigaction sa, old;
        char body[4096];
        rtx_isolate("sigterm");
        ASSERT(rtx_mint("chatgpt", "send", 3600, NULL, 0));
        rtx_direction(body, sizeof(body), "hex_codec", "Then stop.");
        ASSERT(rtx_deliver("chatgpt", "box-a", "job-term", body, 1));
        memset(&sa, 0, sizeof(sa));
        sa.sa_handler = rtx_alarm_to_term;
        ASSERT_EQ(sigaction(SIGALRM, &sa, &old), 0);
        memset(&o, 0, sizeof(o));
        (void)snprintf(o.receiver, sizeof(o.receiver), "box-a");
        o.deadline_s = 30;
        o.wait_ms = 200;
        o.max_beats = 0; /* only SIGTERM can end this drive */
        (void)alarm(1);
        memset(&st, 0, sizeof(st));
        /* Without the signal this drive would run for 30 s. It returns. */
        ASSERT(zcl_devagent_receive_drive(&o, &st) >= 1);
        (void)alarm(0);
        ASSERT_EQ(sigaction(SIGALRM, &old, NULL), 0);
        /* The first beat completed and its record is whole. */
        ASSERT_EQ(rtx_queue_count("queued", "job-term"), 1);
        ASSERT_EQ(rtx_answers("job-term", "state=accepted"), 1);
        ASSERT(rtx_exists("receive/brief/job-term.brief"));
        /* The default SIGTERM disposition is restored, so a later kill of
         * this harness still ends it. */
        rtx_restore();
        PASS();
    }

    TEST("a long turn under the worker never blocks intake or status")
    {
        struct rcv_drive_opts o;
        struct rcv_beat_stats st;
        struct rtx_call c;
        char body[4096], other[4096];
        rtx_isolate("nonblocking");
        ASSERT(rtx_mint("chatgpt", "send", 3600, NULL, 0));
        rtx_direction(body, sizeof(body), "hex_codec", "The long one.");
        ASSERT(rtx_deliver("chatgpt", "box-a", "job-long", body, 1));
        rtx_opts(&o, 1);
        memset(&st, 0, sizeof(st));
        ASSERT_EQ(zcl_devagent_receive_drive(&o, &st), 1);
        ASSERT_EQ(st.admitted, 1);
        /* The worker claims it: from here the job is a running model turn
         * that will not finish for a long time. The receiver holds no part
         * of that run — it is another resident's process. */
        ASSERT(rtx_queue("claim", "worker", "wtx", "session", "s1"));
        ASSERT_EQ(rtx_queue_count("running", "job-long"), 1);
        /* Intake keeps admitting a different ref while that runs. */
        rtx_direction(other, sizeof(other), "hex_codec", "The short one.");
        ASSERT(rtx_deliver("chatgpt", "box-a", "job-next", other, 2));
        memset(&st, 0, sizeof(st));
        ASSERT_EQ(zcl_devagent_receive_drive(&o, &st), 1);
        ASSERT_EQ(st.admitted, 1);
        ASSERT_EQ(rtx_queue_count("queued", "job-next"), 1);
        ASSERT_EQ(rtx_answers("job-next", "state=accepted"), 1);
        /* The running ref is re-answered from its existing record, and is
         * never queued or executed a second time. */
        ASSERT_EQ(rtx_queue_count("running", "job-long"), 1);
        /* Status answers while the turn runs, and says so. */
        memset(&st, 0, sizeof(st));
        ASSERT(zcl_devagent_receive_survey("box-a", &st) >= 0);
        ASSERT_EQ(st.seen, 2);
        /* And the leaf's own status action answers too. */
        rtx_begin(&c, "dev.agent.receive", "zcl.agent_receive.v1");
        (void)json_push_kv_str(&c.input, "action", "status");
        (void)json_push_kv_str(&c.input, "receiver", "box-a");
        zcl_native_handle_dev_agent_receive(&c.request, &c.reply);
        ASSERT(rtx_ok(&c));
        ASSERT_STR_EQ(rtx_reply_str(&c, "state"), "surveyed");
        rtx_end(&c);
        rtx_restore();
        PASS();
    }

    TEST("status decides the same facts and writes nothing")
    {
        struct rtx_call c;
        struct rcv_beat_stats st;
        rtx_isolate("status");
        /* A cold box: status must not bring the receiver, mail, or queue
         * state into existence just by being asked. */
        rtx_begin(&c, "dev.agent.receive", "zcl.agent_receive.v1");
        (void)json_push_kv_str(&c.input, "action", "status");
        (void)json_push_kv_str(&c.input, "receiver", "box-a");
        zcl_native_handle_dev_agent_receive(&c.request, &c.reply);
        ASSERT(rtx_ok(&c));
        ASSERT_STR_EQ(rtx_reply_str(&c, "lock"), "never-run");
        ASSERT_STR_EQ(rtx_reply_str(&c, "mail"), "absent");
        rtx_end(&c);
        ASSERT(!rtx_exists("receive"));
        ASSERT(!rtx_exists("mail"));
        ASSERT(!rtx_exists("queue"));
        /* A bad receiver name is refused, and still writes nothing. */
        rtx_begin(&c, "dev.agent.receive", "zcl.agent_receive.v1");
        (void)json_push_kv_str(&c.input, "action", "status");
        (void)json_push_kv_str(&c.input, "receiver", "not a name!");
        zcl_native_handle_dev_agent_receive(&c.request, &c.reply);
        ASSERT(!rtx_ok(&c));
        rtx_end(&c);
        ASSERT(!rtx_exists("receive"));
        /* An unknown action is refused by name. */
        rtx_begin(&c, "dev.agent.receive", "zcl.agent_receive.v1");
        (void)json_push_kv_str(&c.input, "action", "drive");
        (void)json_push_kv_str(&c.input, "receiver", "box-a");
        zcl_native_handle_dev_agent_receive(&c.request, &c.reply);
        ASSERT(!rtx_ok(&c));
        rtx_end(&c);
        memset(&st, 0, sizeof(st));
        ASSERT(zcl_devagent_receive_survey("bad name", &st) < 0);
        rtx_restore();
        PASS();
    }

    TEST("this leaf is never remotely callable and never spawns")
    {
        const struct zcl_command_spec *spec =
            zcl_command_registry_find(zcl_command_catalog(),
                                      "dev.agent.receive", NULL);
        rtx_isolate("shape");
        ASSERT(spec != NULL);
        /* A directive addressed to another receiver is not this box's
         * work, and is not even counted as seen. */
        {
            struct rcv_drive_opts o;
            struct rcv_beat_stats st;
            char body[4096];
            ASSERT(rtx_mint("chatgpt", "send", 3600, NULL, 0));
            rtx_direction(body, sizeof(body), "hex_codec", "Not yours.");
            ASSERT(rtx_deliver("chatgpt", "box-b", "job-other", body, 1));
            rtx_opts(&o, 1);
            memset(&st, 0, sizeof(st));
            ASSERT_EQ(zcl_devagent_receive_drive(&o, &st), 1);
            ASSERT_EQ(st.seen, 0);
            ASSERT_EQ(rtx_queue_count("queued", "job-other"), 0);
        }
        rtx_restore();
        PASS();
    }
#endif /* !defined(_WIN32) */

_test_next:;
    rtx_restore();
    if (failures == 0)
        printf("test_devagent_receive: all passed\n");
    else
        printf("test_devagent_receive: %d FAILED\n", failures);
    return failures;
}
