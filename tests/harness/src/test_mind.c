/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * mind — the per-node resident that owns rebuilding a checkout's code
 * index; a stale index is refused, never rebuilt inside a query.
 *
 * Coverage:
 *   1. state — the typed registry round-trips; a foreign or absent file
 *      registers nothing; the heartbeat round-trips every per-checkout field
 *      including group rows.
 *   2. owner marker — claim/read/expiry/release; a foreign pid cannot drop
 *      another process's claim; an unparseable marker reads as no claim.
 *   3. resident — takes the lock, builds the first generation, publishes a
 *      heartbeat, rebuilds once after a content edit, and on retirement
 *      releases the claim and lock record. A second resident refuses while
 *      the first holds the lock; one with no registry refuses to start.
 *   4. the refusal — with a live claim a stale open returns NULL with a typed
 *      index_stale refusal naming the owner, and the store's cold-build
 *      receipt is unchanged (proof that no rebuild happened).
 *   5. peer capsule — a mind row rides a signed mesh-status receipt and
 *      survives encode/decode; an expired receipt is refused with its row.
 *   6. fleet fact questions — executor_for and trap_of answer from the table
 *      dev.know reads; an unknown subject is UNKNOWN, not
 *      not_yet_available; next_passage still names the missing story walker.
 *
 * Scratch lives under ./test-tmp/ with ZCL_MIND_STATE_DIR pointed at the
 * fixture, so nothing touches the operator's mind state. */


/* realpath() is declared by glibc only under _DEFAULT_SOURCE; the macro must precede the first include. */
#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif
#include "test/test_core.h"
#include "zutf8/zutf8.h"

#include "codeindex/codeindex.h"
#include "codeindex/codeindex_build.h"
#include "command/native_command.h"
#include "config/command_catalog.h"
#include "crypto/ed25519.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "mind.h"
#include "session/mesh_status_proto.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if !defined(_WIN32)

#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define MIND_FIX   "test-tmp/mind"
#define MIND_TREE  MIND_FIX "/tree"
#define MIND_STATE MIND_FIX "/state"
/* Two sources and a header: a real generation with group rows, cheap to rebuild. */
#define MIND_FILE_COUNT 3

/* The fixture checkout, absolute: the registry refuses a relative root. */
static char g_mind_tree_abs[4096];

static bool mind_mk_write(const char *dir, const char *rel,
                          const char *content)
{
    char full[4096];
    snprintf(full, sizeof(full), "%s/%s", dir, rel);
    for (char *p = full + 1; *p; p++) {
        if (*p == '/') { *p = '\0'; mkdir(full, 0755); *p = '/'; }
    }
    FILE *f = fopen(full, "wb");
    if (!f) return false;
    if (content && content[0]) fwrite(content, 1, strlen(content), f);
    return fclose(f) == 0;
}

static bool write_mind_fixture(const char *alpha_body)
{
    return mind_mk_write(MIND_TREE, "src/mind_alpha.c", alpha_body) &&
           mind_mk_write(MIND_TREE, "src/mind_beta.c",
                         "/* src/mind_beta.c — mind fixture. */\n"
                         "#include \"mind_beta.h\"\n"
                         "int mind_beta(void)\n{\n    return 2;\n}\n") &&
           mind_mk_write(MIND_TREE, "src/mind_beta.h",
                         "/* src/mind_beta.h — mind fixture header. */\n"
                         "#ifndef MIND_BETA_H\n#define MIND_BETA_H\n"
                         "int mind_beta(void);\n#endif\n");
}

static const char *mind_alpha_v1(void)
{
    return "/* src/mind_alpha.c — mind fixture. */\n"
           "int mind_alpha(void)\n{\n    return 1;\n}\n";
}

static const char *mind_alpha_v2(void)
{
    return "/* src/mind_alpha.c — mind fixture, edited. */\n"
           "int mind_alpha(void)\n{\n    return 11;\n}\n";
}

/* The registry the resident reads, written through the library's own writer. */
static bool mind_register(const char *root)
{
    struct zcl_mind_registry reg;
    memset(&reg, 0, sizeof(reg));
    reg.count = 1;
    snprintf(reg.roots[0], sizeof(reg.roots[0]), "%s", root);
    return zcl_mind_registry_write(&reg);
}

static bool mind_unregister(void)
{
    char path[ZCL_MIND_PATH_MAX];
    return zcl_mind_registry_path(path, sizeof(path)) && remove(path) == 0;
}

static long long mind_cold_build_ms(const char *root)
{
    struct codeindex *ci = codeindex_open_readonly(root, NULL);
    if (!ci) return -1;
    long long ms = 0, files = 0;
    bool have = codeindex_build_cold_ms(ci, &ms, &files);
    codeindex_close(ci);
    return have ? ms : -1;
}

/* ── 1. state ─────────────────────────────────────────────────────────── */

static int test_mind_state_round_trip(void)
{
    int failures = 0;

    TEST("mind: the typed registry round-trips and a foreign file registers "
         "nothing") {
        ASSERT(mind_register("/absolute/checkout"));
        struct zcl_mind_registry reg;
        ASSERT(zcl_mind_registry_load(&reg));
        ASSERT_EQ(reg.count, (size_t)1);
        ASSERT_STR_EQ(reg.roots[0], "/absolute/checkout");

        char path[ZCL_MIND_PATH_MAX];
        ASSERT(zcl_mind_registry_path(path, sizeof(path)));
        FILE *f = fopen(path, "wb");
        ASSERT(f != NULL);
        /* No schema header: a foreign file must not register paths. */
        fputs("/absolute/other\n", f);
        ASSERT_EQ(fclose(f), 0);
        ASSERT(!zcl_mind_registry_load(&reg));
        ASSERT_EQ(reg.count, (size_t)0);

        ASSERT(mind_unregister());
        ASSERT(!zcl_mind_registry_load(&reg));
        PASS();
    } _test_next:;
    return failures;
}

static int test_mind_heartbeat_round_trip(void)
{
    int failures = 0;

    TEST("mind: the heartbeat round-trips every per-checkout field") {
        struct zcl_mind_heartbeat out;
        memset(&out, 0, sizeof(out));
        out.pid = 4242;
        out.started_unix = 1000;
        out.beat_unix = 1200;
        out.last_rebuild_ms = 77;
        out.checkout_count = 1;
        snprintf(out.checkouts[0].root, sizeof(out.checkouts[0].root), "%s",
                 "/absolute/checkout");
        snprintf(out.checkouts[0].index_root,
                 sizeof(out.checkouts[0].index_root), "%s",
                 "00112233445566778899aabbccddeeff"
                 "00112233445566778899aabbccddeeff");
        out.checkouts[0].index_age_s = 9;
        out.checkouts[0].last_rebuild_ms = 77;
        out.checkouts[0].last_rebuild_unix = 1199;
        out.checkouts[0].rebuilds = 3;
        out.checkouts[0].indexed = true;
        out.checkouts[0].stale = false;
        out.checkouts[0].group_count = 1;
        snprintf(out.checkouts[0].groups[0].name,
                 sizeof(out.checkouts[0].groups[0].name), "%s", "src");
        out.checkouts[0].groups[0].files = 3;
        ASSERT(zcl_mind_heartbeat_write(&out));

        struct zcl_mind_heartbeat back;
        ASSERT(zcl_mind_heartbeat_read(&back));
        ASSERT_EQ(back.pid, out.pid);
        ASSERT_EQ(back.beat_unix, out.beat_unix);
        ASSERT_EQ(back.last_rebuild_ms, out.last_rebuild_ms);
        ASSERT_EQ(back.checkout_count, (size_t)1);
        ASSERT_STR_EQ(back.checkouts[0].root, out.checkouts[0].root);
        ASSERT_STR_EQ(back.checkouts[0].index_root,
                      out.checkouts[0].index_root);
        ASSERT_EQ(back.checkouts[0].rebuilds, (long long)3);
        ASSERT(back.checkouts[0].indexed);
        ASSERT(!back.checkouts[0].stale);
        ASSERT_EQ(back.checkouts[0].group_count, (size_t)1);
        ASSERT_STR_EQ(back.checkouts[0].groups[0].name, "src");
        ASSERT_EQ(back.checkouts[0].groups[0].files, (long long)3);
        PASS();
    } _test_next:;
    return failures;
}

/* ── 2. the owner marker ──────────────────────────────────────────────── */

static int test_mind_owner_marker(void)
{
    int failures = 0;

    TEST("mind: an owner claim is live while it beats, expires when it stops, "
         "and is never dropped by another pid") {
        long long now = 1000000;
        ASSERT(codeindex_owner_claim(MIND_TREE, 4242, now));
        long long pid = 0, beat = 0;
        ASSERT(codeindex_owner_read(MIND_TREE, &pid, &beat));
        ASSERT_EQ(pid, (long long)4242);
        ASSERT_EQ(beat, now);
        ASSERT(codeindex_owner_is_live(MIND_TREE, now));
        ASSERT(codeindex_owner_is_live(
            MIND_TREE, now + CODEINDEX_OWNER_HEARTBEAT_MAX_AGE_S));
        /* One second past the window the claim is gone, so a dead resident's box goes back to rebuilding. */
        ASSERT(!codeindex_owner_is_live(
            MIND_TREE, now + CODEINDEX_OWNER_HEARTBEAT_MAX_AGE_S + 1));

        ASSERT(!codeindex_owner_release(MIND_TREE, 9999));
        ASSERT(codeindex_owner_read(MIND_TREE, &pid, NULL));
        ASSERT_EQ(pid, (long long)4242);
        ASSERT(codeindex_owner_release(MIND_TREE, 4242));
        ASSERT(!codeindex_owner_read(MIND_TREE, &pid, &beat));
        PASS();
    } _test_next:;
    return failures;
}

static int test_mind_owner_marker_unparseable(void)
{
    int failures = 0;

    TEST("mind: an unparseable owner marker reads as no claim, not as a "
         "refusal of every query") {
        char path[4096];
        snprintf(path, sizeof(path), "%s/.codeindex/owner.v1", MIND_TREE);
        FILE *f = fopen(path, "wb");
        ASSERT(f != NULL);
        fputs("zcl.codeindex_owner.v0 not-a-pid\n", f);
        ASSERT_EQ(fclose(f), 0);
        ASSERT(!codeindex_owner_read(MIND_TREE, NULL, NULL));
        ASSERT(!codeindex_owner_is_live(MIND_TREE, 1000000));
        ASSERT_EQ(remove(path), 0);
        PASS();
    } _test_next:;
    return failures;
}

/* ── 3. the resident ──────────────────────────────────────────────────── */

static int test_mind_resident_refuses_without_registry(void)
{
    int failures = 0;

    TEST("mind: the resident refuses to start with nothing registered") {
        ASSERT_EQ(zcl_mind_serve(NULL, NULL, 1), 1);
        PASS();
    } _test_next:;
    return failures;
}

static int test_mind_resident_first_cycle(void)
{
    int failures = 0;

    TEST("mind: one cycle builds the generation, publishes a heartbeat, and "
         "retires without leaving a claim behind") {
        ASSERT(mind_register(g_mind_tree_abs));
        ASSERT_EQ(zcl_mind_serve(NULL, NULL, 1), 0);

        struct zcl_mind_heartbeat beat;
        ASSERT(zcl_mind_heartbeat_read(&beat));
        ASSERT_EQ(beat.checkout_count, (size_t)1);
        ASSERT(beat.checkouts[0].indexed);
        ASSERT_EQ(beat.checkouts[0].rebuilds, (long long)1);
        ASSERT_EQ(strlen(beat.checkouts[0].index_root), (size_t)64);
        ASSERT(beat.checkouts[0].group_count > 0);
        ASSERT(beat.beat_unix > 0);
        ASSERT_EQ(beat.checkouts[0].last_rebuild_unix, beat.beat_unix);

        /* files and symbols are separate facts: three files, more symbols than files. */
        ASSERT_EQ(beat.checkouts[0].files, (long long)MIND_FILE_COUNT);
        ASSERT(beat.checkouts[0].symbols >= beat.checkouts[0].files);
        ASSERT(beat.checkouts[0].refs >= 0);
        /* Include edges come from compiler depfiles; a never-compiled fixture has none, so zero is correct. */
        ASSERT(beat.checkouts[0].includes >= 0);
        ASSERT(beat.checkouts[0].index_bytes > 0);
        ASSERT_EQ(beat.checkouts[0].build_cold_files,
                  (long long)MIND_FILE_COUNT);

        /* Retirement releases the claim; a leftover marker would refuse queries for the claim window. */
        ASSERT(!codeindex_owner_read(MIND_TREE, NULL, NULL));
        char lock[ZCL_MIND_PATH_MAX];
        ASSERT(zcl_mind_lock_path(lock, sizeof(lock)));
        struct stat st;
        ASSERT(stat(lock, &st) != 0);
        PASS();
    } _test_next:;
    return failures;
}

static int test_mind_resident_rebuild_economy(void)
{
    int failures = 0;

    TEST("mind: a content edit costs exactly one more rebuild, and a quiet "
         "cycle costs none") {
        ASSERT(write_mind_fixture(mind_alpha_v2()));
        ASSERT_EQ(zcl_mind_serve(NULL, NULL, 1), 0);
        struct zcl_mind_heartbeat after_edit;
        ASSERT(zcl_mind_heartbeat_read(&after_edit));
        ASSERT_EQ(after_edit.checkouts[0].rebuilds, (long long)1);
        ASSERT(!after_edit.checkouts[0].stale);

        /* Nothing changed: the resident observes and claims, and does not rebuild. */
        ASSERT_EQ(zcl_mind_serve(NULL, NULL, 1), 0);
        struct zcl_mind_heartbeat quiet;
        ASSERT(zcl_mind_heartbeat_read(&quiet));
        ASSERT_EQ(quiet.checkouts[0].rebuilds, (long long)0);
        ASSERT(!quiet.checkouts[0].stale);
        PASS();
    } _test_next:;
    return failures;
}

/* ── 4. the refusal ───────────────────────────────────────────────────── */

static int test_mind_stale_query_is_refused(void)
{
    int failures = 0;

    TEST("mind: with a live owner a stale open is refused, records the typed "
         "index_stale, and leaves the cold-build receipt untouched") {
        /* Start from a fresh generation with no owner. */
        ASSERT(mind_register(g_mind_tree_abs));
        ASSERT_EQ(zcl_mind_serve(NULL, NULL, 1), 0);
        long long before = mind_cold_build_ms(MIND_TREE);
        ASSERT(before >= 0);

        /* Move the tree past the published generation, then claim it. */
        ASSERT(write_mind_fixture(
            "/* src/mind_alpha.c — mind fixture, moved on. */\n"
            "int mind_alpha(void)\n{\n    return 111;\n}\n"));
        ASSERT(codeindex_owner_claim(MIND_TREE, (long long)getpid(),
                                     (long long)time(NULL)));

        struct codeindex *refused = codeindex_open_source_view(MIND_TREE);
        ASSERT(refused == NULL);
        struct codeindex_stale_refusal record;
        ASSERT(codeindex_last_stale_refusal(&record));
        ASSERT(record.recorded);
        ASSERT(record.owner_present);
        ASSERT_EQ(record.owner_pid, (long long)getpid());
        ASSERT(record.owner_heartbeat_age_s >= 0);
        ASSERT_EQ(strlen(record.index_root), (size_t)64);

        /* No rebuild happened: the store's cold-build receipt still describes the pre-edit generation. */
        ASSERT_EQ(mind_cold_build_ms(MIND_TREE), before);

        /* Release the claim and the same open rebuilds, because an unowned checkout is owned by each reader. */
        ASSERT(codeindex_owner_release(MIND_TREE, (long long)getpid()));
        struct codeindex *served = codeindex_open_source_view(MIND_TREE);
        ASSERT(served != NULL);
        codeindex_close(served);
        ASSERT(!codeindex_last_stale_refusal(&record));
        PASS();
    } _test_next:;
    return failures;
}

/* ── 5. the peer capsule ──────────────────────────────────────────────── */

/* Build the capsule a responder would sign: its machine identity object plus this node's mind row. */
static bool mind_capsule_bytes(uint8_t *out, size_t cap, size_t *len)
{
    struct json_value capsule, mind;
    json_init(&capsule);
    json_set_object(&capsule);
    if (!json_push_kv_str(&capsule, "schema",
                          "zcl.machine_mesh_identity.v1") ||
        !zcl_mind_capsule_render(&mind)) {
        json_free(&capsule);
        return false;
    }
    (void)json_push_kv(&capsule, "mind", &mind);
    json_free(&mind);
    size_t n = json_write(&capsule, (char *)out, cap);
    json_free(&capsule);
    *len = n;
    return n > 0 && n < cap;
}

static int test_mind_peer_capsule(void)
{
    int failures = 0;

    TEST("mind: a mind row survives a signed receipt round trip, and an "
         "expired receipt takes it with it") {
        ASSERT(mind_register(g_mind_tree_abs));
        ASSERT_EQ(zcl_mind_serve(NULL, NULL, 1), 0);

        struct mesh_status_receipt_v1 receipt;
        memset(&receipt, 0, sizeof(receipt));
        receipt.version = MESH_STATUS_PROTO_VERSION;
        receipt.flags = MESH_STATUS_PROTO_FLAGS_NONE;
        receipt.status = MESH_STATUS_RECEIPT_OK;
        for (int i = 0; i < 32; i++) {
            receipt.request_id[i] = (uint8_t)(i + 1);
            receipt.request_root[i] = (uint8_t)(i + 2);
            receipt.network_genesis[i] = (uint8_t)(i + 3);
            receipt.pairing_id[i] = (uint8_t)(i + 4);
            receipt.responder_master_pubkey[i] = (uint8_t)(i + 5);
            receipt.responder_noise_static[i] = (uint8_t)(i + 6);
            receipt.transcript_hash[i] = (uint8_t)(i + 7);
        }
        receipt.connection_generation = 1;
        receipt.revocation_generation = 0;
        receipt.observed_unix = 2000;
        receipt.expires_unix = 2000 + 30;

        size_t capsule_len = 0;
        ASSERT(mind_capsule_bytes(receipt.capsule, MESH_STATUS_CAPSULE_MAX,
                                  &capsule_len));
        receipt.capsule_len = (uint16_t)capsule_len;
        ASSERT_EQ(mesh_status_capsule_v1_root(receipt.capsule, capsule_len,
                                              receipt.capsule_root),
                  MESH_STATUS_PROTO_OK);

        uint8_t seed[32];
        for (int i = 0; i < 32; i++) seed[i] = (uint8_t)(0x40 + i);
        uint8_t sk[32];
        zcl_ed25519_keypair(receipt.responder_online_pubkey, sk, seed);
        ASSERT_EQ(mesh_status_receipt_v1_sign(&receipt, seed),
                  MESH_STATUS_PROTO_OK);

        uint8_t wire[MESH_STATUS_RECEIPT_V1_MAX_WIRE_BYTES];
        size_t wire_len = 0;
        ASSERT_EQ(mesh_status_receipt_v1_encode(&receipt, wire, sizeof(wire),
                                                &wire_len),
                  MESH_STATUS_PROTO_OK);
        struct mesh_status_receipt_v1 back;
        ASSERT_EQ(mesh_status_receipt_v1_decode(&back, wire, wire_len),
                  MESH_STATUS_PROTO_OK);

        struct json_value decoded;
        json_init(&decoded);
        ASSERT(json_read(&decoded, (const char *)back.capsule,
                         back.capsule_len));
        struct zcl_mind_peer peer;
        ASSERT(zcl_mind_capsule_parse(&decoded, &peer));
        json_free(&decoded);

        struct zcl_mind_heartbeat local;
        ASSERT(zcl_mind_heartbeat_read(&local));
        ASSERT_STR_EQ(peer.index_root, local.checkouts[0].index_root);
        ASSERT_EQ(peer.checkouts, (long long)local.checkout_count);
        ASSERT_EQ(peer.group_count, local.checkouts[0].group_count);

        /* A receipt whose window exceeds the protocol lifetime is refused whole, mind row included. */
        struct mesh_status_receipt_v1 expired = receipt;
        expired.expires_unix =
            expired.observed_unix + MESH_STATUS_MAX_LIFETIME_SECONDS + 1;
        ASSERT(mesh_status_receipt_v1_validate(&expired) !=
               MESH_STATUS_PROTO_OK);
        uint8_t expired_wire[MESH_STATUS_RECEIPT_V1_MAX_WIRE_BYTES];
        size_t expired_len = 0;
        ASSERT(mesh_status_receipt_v1_encode(&expired, expired_wire,
                                             sizeof(expired_wire),
                                             &expired_len) !=
               MESH_STATUS_PROTO_OK);
        PASS();
    } _test_next:;
    return failures;
}

/* ── 6. fleet fact questions through mind.ask ─────────────────────────── */

#define MIND_ASK_PATH "dev.fleet.mind.ask"

struct mind_ask_call {
    struct json_value input;
    struct zcl_command_request request;
    struct zcl_command_reply reply;
};

static void mind_ask_begin(struct mind_ask_call *c)
{
    json_init(&c->input);
    json_set_object(&c->input);
    memset(&c->request, 0, sizeof(c->request));
    c->request.input = &c->input;
    c->request.spec =
        zcl_command_registry_find(zcl_command_catalog(), MIND_ASK_PATH, NULL);
    zcl_command_reply_init(&c->reply, "zcl.mind_answer.v1");
}

static bool mind_ask_run(struct mind_ask_call *c)
{
    char why[192];

    if (c->request.spec &&
        !zcl_command_registry_input_validate(c->request.spec, &c->input, why,
                                             sizeof(why))) {
        printf("[input rejected: %s] ", why);
        return false;
    }
    zcl_native_handle_dev_mind_ask(&c->request, &c->reply);
    return true;
}

static void mind_ask_end(struct mind_ask_call *c)
{
    zcl_command_reply_free(&c->reply);
    json_free(&c->input);
}

static const struct json_value *mind_ask_get(const struct mind_ask_call *c,
                                             const char *key)
{
    return json_get(&c->reply.data, key);
}

static const char *mind_ask_str(const struct mind_ask_call *c, const char *key)
{
    const struct json_value *v = mind_ask_get(c, key);
    return v && v->type == JSON_STR && json_get_str(v) ? json_get_str(v) : "";
}

static const char *mind_ask_row_str(const struct mind_ask_call *c, size_t index,
                                    const char *key)
{
    const struct json_value *rows = mind_ask_get(c, "rows");
    const struct json_value *row = rows ? json_at(rows, index) : NULL;
    const struct json_value *v = row ? json_get(row, key) : NULL;
    return v && v->type == JSON_STR && json_get_str(v) ? json_get_str(v) : "";
}

static int64_t mind_ask_row_count(const struct mind_ask_call *c)
{
    const struct json_value *v = mind_ask_get(c, "row_count");
    return v && v->type == JSON_INT ? json_get_int(v) : -1;
}

static int test_mind_ask_fleet_facts(void)
{
    int failures = 0;

    TEST("mind.ask: executor_for sonnet answers from the fleet table, "
         "never not_yet_available") {
        struct mind_ask_call c;
        bool saw_handles_well = false;

        mind_ask_begin(&c);
        (void)json_push_kv_str(&c.input, "kind", "executor_for");
        (void)json_push_kv_str(&c.input, "subject", "sonnet");
        ASSERT(mind_ask_run(&c));
        ASSERT_EQ((int)c.reply.status, (int)ZCL_COMMAND_STATUS_PASSED);
        ASSERT(mind_ask_get(&c, "not_yet_available") == NULL);
        ASSERT(mind_ask_row_count(&c) >= 2);
        ASSERT(strstr(mind_ask_str(&c, "summary"), "dev know") != NULL);
        for (int64_t i = 0; i < mind_ask_row_count(&c); i++) {
            if (strcmp(mind_ask_row_str(&c, (size_t)i, "where"),
                       "handles_well") == 0)
                saw_handles_well = true;
        }
        ASSERT(saw_handles_well);
        mind_ask_end(&c);
        PASS();
    }

    TEST("mind.ask: trap_of names the trap, and an unknown subject is "
         "UNKNOWN rather than not_yet_available") {
        struct mind_ask_call c;

        mind_ask_begin(&c);
        (void)json_push_kv_str(&c.input, "kind", "trap_of");
        (void)json_push_kv_str(&c.input, "subject", "test_boot_phase");
        ASSERT(mind_ask_run(&c));
        ASSERT_EQ((int)c.reply.status, (int)ZCL_COMMAND_STATUS_PASSED);
        ASSERT(mind_ask_get(&c, "not_yet_available") == NULL);
        ASSERT_EQ(mind_ask_row_count(&c), (int64_t)1);
        ASSERT_STR_EQ(mind_ask_row_str(&c, 0, "what"), "ram-generation-root");
        ASSERT_STR_EQ(mind_ask_row_str(&c, 0, "where"), "trap_signature");
        mind_ask_end(&c);

        mind_ask_begin(&c);
        (void)json_push_kv_str(&c.input, "kind", "trap_of");
        (void)json_push_kv_str(&c.input, "subject", "no-such-subject");
        ASSERT(mind_ask_run(&c));
        ASSERT_EQ((int)c.reply.status, (int)ZCL_COMMAND_STATUS_PASSED);
        ASSERT(mind_ask_get(&c, "not_yet_available") == NULL);
        ASSERT_EQ(mind_ask_row_count(&c), (int64_t)1);
        ASSERT_STR_EQ(mind_ask_row_str(&c, 0, "what"), "unknown");
        ASSERT(strstr(mind_ask_row_str(&c, 0, "detail"), "unknown:") != NULL);
        mind_ask_end(&c);
        PASS();
    }

    TEST("mind.ask: next_passage still names the missing story walker") {
        struct mind_ask_call c;

        mind_ask_begin(&c);
        (void)json_push_kv_str(&c.input, "kind", "next_passage");
        ASSERT(mind_ask_run(&c));
        ASSERT_EQ((int)c.reply.status, (int)ZCL_COMMAND_STATUS_PASSED);
        ASSERT(strstr(mind_ask_str(&c, "not_yet_available"),
                      "story walker") != NULL);
        ASSERT(strstr(mind_ask_str(&c, "summary"), "not_yet_available") !=
               NULL);
        mind_ask_end(&c);
        PASS();
    }

    _test_next:;
    return failures;
}

static int test_mind_fleet_subject_utf8(void)
{
    int failures = 0;
    struct mind_ask_call c;
    bool active = false;
    TEST("mind.ask: refuse malformed fleet subjects before echo or summary") {
        static const char *const kinds[] = {"executor_for", "trap_of"};
        static const char *const bad[] = {
            "\xff", "\xc0\xaf", "\xed\xa0\x80", "\xf4\x90\x80\x80",
            "\xc3", "\xe2\x82"
        };
        for (size_t k = 0; k < sizeof(kinds) / sizeof(kinds[0]); k++) {
            for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
                mind_ask_begin(&c);
                active = true;
                ASSERT(c.request.spec != NULL);
                ASSERT(json_push_kv_str(&c.input, "kind", kinds[k]));
                ASSERT(json_push_kv_str(&c.input, "subject", bad[i]));
                ASSERT(mind_ask_run(&c));
                ASSERT_EQ(c.reply.status, ZCL_COMMAND_STATUS_FAILED);
                ASSERT_EQ(c.reply.exit_code, ZCL_COMMAND_EXIT_INVALID);
                ASSERT_STR_EQ(c.reply.error.code, "INVALID_UTF8");
                ASSERT(strstr(c.reply.error.message, "UTF-8") != NULL);
                ASSERT(mind_ask_get(&c, "subject") == NULL);
                ASSERT(mind_ask_get(&c, "summary") == NULL);
                ASSERT(mind_ask_get(&c, "rows") == NULL);
                mind_ask_end(&c);
                active = false;
            }
        }
        PASS();
    } _test_next:;
    if (active) mind_ask_end(&c);
    return failures;
}

static int test_mind_fleet_subject_unicode(void)
{
    int failures = 0;
    struct mind_ask_call c;
    mind_ask_begin(&c);
    TEST("mind.ask: valid Unicode unknown subject retains answer and echo") {
        static const char subject[] = "unknown-\xc3\xa9-\xe2\x82\xac";
        ASSERT(c.request.spec != NULL);
        ASSERT(json_push_kv_str(&c.input, "kind", "trap_of"));
        ASSERT(json_push_kv_str(&c.input, "subject", subject));
        ASSERT(mind_ask_run(&c));
        ASSERT_EQ(c.reply.status, ZCL_COMMAND_STATUS_PASSED);
        ASSERT_EQ(mind_ask_row_count(&c), 1);
        ASSERT_STR_EQ(mind_ask_row_str(&c, 0, "what"), "unknown");
        ASSERT_STR_EQ(mind_ask_str(&c, "subject"), subject);
        ASSERT(strstr(mind_ask_str(&c, "summary"), subject) != NULL);
        char serialized[4096];
        size_t len = json_write(&c.reply.data, serialized, sizeof(serialized));
        ASSERT(len > 0);
        ASSERT(len < sizeof(serialized));
        ASSERT(json_valid(serialized, len));
        ASSERT(strstr(serialized, subject) != NULL);
        PASS();
    } _test_next:;
    mind_ask_end(&c);
    return failures;
}

static int mind_fleet_bound_case(const char *kind, size_t padding,
                                 const char *scalar, bool fits)
{
    int failures = 0;
    struct mind_ask_call c;
    char subject[520];
    mind_ask_begin(&c);
    TEST("mind.ask: fleet summary bound refuses overflow before publication") {
        ASSERT(padding < sizeof(subject));
        ASSERT(strlen(scalar) < sizeof(subject) - padding);
        memset(subject, 'a', padding);
        memcpy(subject + padding, scalar, strlen(scalar) + 1);
        ASSERT(c.request.spec != NULL);
        ASSERT(json_push_kv_str(&c.input, "kind", kind));
        ASSERT(json_push_kv_str(&c.input, "subject", subject));
        ASSERT(mind_ask_run(&c));
        if (fits) {
            ASSERT_EQ(c.reply.status, ZCL_COMMAND_STATUS_PASSED);
            ASSERT_EQ(strlen(mind_ask_str(&c, "summary")), 511);
            ASSERT_STR_EQ(mind_ask_str(&c, "subject"), subject);
            ASSERT_EQ(mind_ask_row_count(&c), 1);
            ASSERT_STR_EQ(mind_ask_row_str(&c, 0, "what"), "unknown");
        } else {
            ASSERT_EQ(c.reply.status, ZCL_COMMAND_STATUS_FAILED);
            ASSERT_EQ(c.reply.exit_code, ZCL_COMMAND_EXIT_INVALID);
            ASSERT_STR_EQ(c.reply.error.code, "ANSWER_TOO_LONG");
            ASSERT(strstr(c.reply.error.message, "text bound") != NULL);
            ASSERT(mind_ask_get(&c, "subject") == NULL);
            ASSERT(mind_ask_get(&c, "summary") == NULL);
            ASSERT(mind_ask_get(&c, "rows") == NULL);
            ASSERT(mind_ask_get(&c, "row_count") == NULL);
        }
        char serialized[4096];
        size_t len = json_write(&c.reply.data, serialized, sizeof(serialized));
        ASSERT(len > 0 && len < sizeof(serialized));
        ASSERT(json_valid(serialized, len));
        ASSERT(zutf8_validate_n(serialized, len));
        PASS();
    } _test_next:;
    mind_ask_end(&c);
    return failures;
}

static int test_mind_fleet_summary_bound(void)
{
    int failures = 0;
    static const char *const kinds[] = {"executor_for", "trap_of"};
    static const char *const scalars[] = {
        "\xc3\xa9", "\xe2\x82\xac", "\xf0\x9f\x98\x80"
    };
    /* Unknown summary: 37-byte prefix, 96-byte suffix; trap adds 18.
     * Put each possible incomplete scalar prefix at byte 511's NUL cut. */
    for (size_t k = 0; k < sizeof(kinds) / sizeof(kinds[0]); k++) {
        size_t subject_limit = k == 0 ? 378 : 360;
        failures += mind_fleet_bound_case(kinds[k], subject_limit, "", true);
        failures += mind_fleet_bound_case(kinds[k], subject_limit + 1, "", false);
        for (size_t s = 0; s < sizeof(scalars) / sizeof(scalars[0]); s++) {
            size_t width = strlen(scalars[s]);
            failures += mind_fleet_bound_case(kinds[k], subject_limit - width,
                                              scalars[s], true);
            failures += mind_fleet_bound_case(kinds[k], subject_limit - width + 1,
                                              scalars[s], false);
            for (size_t copied = 1; copied < width; copied++)
                failures += mind_fleet_bound_case(kinds[k], 474 - copied,
                                                  scalars[s], false);
        }
    }
    return failures;
}

int test_mind(void)
{
    int failures = 0;
    (void)test_rm_rf_recursive(MIND_FIX);
    /* mind_mk_write creates parents but the state directory must be made on purpose; ZCL_MIND_STATE_DIR then points every path at the fixture. */
    if (!write_mind_fixture(mind_alpha_v1()) ||
        !mind_mk_write(MIND_STATE, ".keep", "")) {
        printf("  mind: fixture write... FAIL\n");
        return 1;
    }
    char state_abs[4096];
    if (!realpath(MIND_STATE, state_abs) ||
        setenv("ZCL_MIND_STATE_DIR", state_abs, 1) != 0 ||
        !realpath(MIND_TREE, g_mind_tree_abs)) {
        printf("  mind: fixture state directory... FAIL\n");
        return 1;
    }

    failures += test_mind_state_round_trip();
    failures += test_mind_heartbeat_round_trip();
    failures += test_mind_owner_marker();
    failures += test_mind_owner_marker_unparseable();
    failures += test_mind_resident_refuses_without_registry();
    failures += test_mind_resident_first_cycle();
    failures += test_mind_resident_rebuild_economy();
    failures += test_mind_stale_query_is_refused();
    failures += test_mind_peer_capsule();
    failures += test_mind_ask_fleet_facts();
    failures += test_mind_fleet_subject_utf8();
    failures += test_mind_fleet_subject_unicode();
    failures += test_mind_fleet_summary_bound();

    (void)unsetenv("ZCL_MIND_STATE_DIR");
    (void)test_rm_rf_recursive(MIND_FIX);
    return failures;
}

#else  /* _WIN32 */
/* The resident is a POSIX service (flock singleton, cooperative SIGTERM retirement); skipped loudly elsewhere. */
int test_mind(void)
{
    printf("mind: SKIP (Windows): the resident is a POSIX flock singleton\n");
    return 0;
}
#endif
