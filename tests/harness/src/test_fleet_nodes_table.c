/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: contract coverage for fleet.nodes.table
 * (tools/command/native_fleet_nodes_table.c) through the registered dispatch:
 * exact JSON types and counts, an existing empty table against absent,
 * corrupt and schema-incomplete stores, distinct pairing states, grouping by
 * the full master fingerprint, uncombined capability masks, the 64-pairing
 * bound, redaction and the owner authority gate. Fixtures are real node.db
 * files in a private temporary directory. */

#include "test/test_core.h"

#include "base/hex.h"
#include "config/command_catalog.h"
#include "crypto/sha3.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "models/database.h"
#include "models/mesh_pairing.h"

#include <sqlite3.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define NT_PATH "fleet.nodes.table"
#define NT_FUTURE INT64_C(4000000000)
#define NT_PAST INT64_C(1000000)
#define NT_PAIRED INT64_C(900000)
#define NT_TEXT_MAX 131072u

struct nt_fixture {
    char dir[512];
    struct node_db db;
};

struct nt_spec {
    uint32_t master;
    uint8_t noise;
    uint64_t mask;
    int64_t paired_at;
    int64_t expires_at;
    int64_t revoked_at;
};

struct nt_reply {
    struct json_value root;
    enum zcl_command_exit exit_code;
    bool parsed;
};

static char g_nt_text[NT_TEXT_MAX];

static bool nt_open(struct nt_fixture *f)
{
    char path[544];
    memset(f, 0, sizeof(*f));
    if (!test_mkdtemp(f->dir, sizeof(f->dir), "fleet_nodes_table"))
        return false;
    int n = snprintf(path, sizeof(path), "%s/node.db", f->dir);
    return n > 0 && (size_t)n < sizeof(path) && node_db_open(&f->db, path);
}

static void nt_close_db(struct nt_fixture *f)
{
    if (f->db.open)
        node_db_close(&f->db);
}

static void nt_close(struct nt_fixture *f)
{
    nt_close_db(f);
    if (f->dir[0])
        test_cleanup_tmpdir(f->dir);
}

static void nt_master_key(uint32_t master, uint8_t key[32])
{
    memset(key, 0x5A, 32);
    key[0] = (uint8_t)(master >> 24);
    key[1] = (uint8_t)(master >> 16);
    key[2] = (uint8_t)(master >> 8);
    key[3] = (uint8_t)master;
}

static void nt_fingerprint(uint32_t master, char out[65])
{
    static const char domain[] = "zcl.mesh.master.fingerprint.v1";
    uint8_t key[32], digest[32];
    struct sha3_256_ctx ctx;
    nt_master_key(master, key);
    sha3_256_init(&ctx);
    sha3_256_write(&ctx, (const uint8_t *)domain, strlen(domain));
    sha3_256_write(&ctx, key, sizeof(key));
    sha3_256_finalize(&ctx, digest);
    zcl_hex_encode(digest, sizeof(digest), out);
}

static bool nt_add(struct nt_fixture *f, const struct nt_spec *s)
{
    struct db_mesh_pairing row;
    memset(&row, 0, sizeof(row));
    memset(row.network_genesis, 0x11, 32);
    nt_master_key(s->master, row.peer_master_pubkey);
    memset(row.peer_noise_pubkey, s->noise, 32);
    row.capability_mask = s->mask;
    row.delegation_sequence = 7;
    row.paired_at = s->paired_at;
    row.expires_at = s->expires_at;
    row.revoked_at = s->revoked_at;
    row.revocation_generation = s->revoked_at ? 1 : 0;
    return mesh_pairing_id_derive(row.network_genesis, row.peer_master_pubkey,
                                  row.peer_noise_pubkey, row.pairing_id) &&
           db_mesh_pairing_insert(&f->db, &row);
}

static struct nt_spec nt_active(uint32_t master, uint8_t noise)
{
    return (struct nt_spec){ .master = master, .noise = noise,
                             .mask = MESH_PAIRING_CAP_STATUS_READ,
                             .paired_at = NT_PAIRED,
                             .expires_at = NT_FUTURE };
}

static bool nt_call(const char *datadir, enum zcl_command_authority ceiling,
                    struct nt_reply *r)
{
    const struct zcl_command_registry *reg = zcl_command_catalog();
    const struct zcl_command_spec *spec =
        zcl_command_registry_find(reg, NT_PATH, NULL);
    struct zcl_command_context ctx = { .registry = reg,
                                       .granted_capabilities = ~(uint64_t)0,
                                       .authority_ceiling = ceiling };
    struct json_value input;
    json_init(&r->root);
    r->parsed = false;
    if (!spec)
        return false;
    json_init(&input);
    json_set_object(&input);
    if (datadir)
        (void)json_push_kv_str(&input, "datadir", datadir);
    size_t n = zcl_command_registry_execute_json(
        reg, spec, &ctx, &input, false, NT_PATH, "full", 0, 0, NULL,
        g_nt_text, sizeof(g_nt_text), &r->exit_code);
    json_free(&input);
    r->parsed = n > 0 && n < sizeof(g_nt_text) &&
                json_read(&r->root, g_nt_text, n);
    return r->parsed;
}

static bool nt_owner(const char *datadir, struct nt_reply *r)
{
    return nt_call(datadir, ZCL_COMMAND_AUTH_OWNER, r);
}

static const struct json_value *nt_data(const struct nt_reply *r)
{
    return json_get(&r->root, "data");
}

static bool nt_ok(const struct nt_reply *r)
{
    const struct json_value *ok = json_get(&r->root, "ok");
    return ok && ok->type == JSON_BOOL && json_get_bool(ok);
}

static const char *nt_str(const struct json_value *obj, const char *key)
{
    const struct json_value *v = obj ? json_get(obj, key) : NULL;
    return v && v->type == JSON_STR ? json_get_str(v) : "";
}

static int64_t nt_int(const struct json_value *obj, const char *key)
{
    const struct json_value *v = obj ? json_get(obj, key) : NULL;
    return v && v->type == JSON_INT ? json_get_int(v) : INT64_MIN;
}

static const char *nt_error(const struct nt_reply *r)
{
    return nt_str(json_get(&r->root, "error"), "code");
}

static const struct json_value *nt_rows(const struct nt_reply *r)
{
    const struct json_value *rows = json_get(nt_data(r), "rows");
    return rows && rows->type == JSON_ARR ? rows : NULL;
}

static const struct json_value *nt_row(const struct nt_reply *r,
                                       const char *fingerprint)
{
    const struct json_value *rows = nt_rows(r);
    for (size_t i = 0; rows && i < rows->num_children; i++)
        if (strcmp(nt_str(&rows->children[i], "peer_master_fingerprint"),
                   fingerprint) == 0)
            return &rows->children[i];
    return NULL;
}

static size_t nt_pairings(const struct json_value *row)
{
    const struct json_value *p = row ? json_get(row, "pairings") : NULL;
    return p && p->type == JSON_ARR ? p->num_children : 0;
}

static const struct json_value *nt_pairing(const struct json_value *row,
                                           size_t index)
{
    return &json_get(row, "pairings")->children[index];
}

static int test_nt_empty_table(void)
{
    int failures = 0;
    struct nt_fixture f = {0};
    struct nt_reply r = {0};
    TEST("fleet nodes table: an existing empty table is a success with zero "
         "rows and exact types") {
        ASSERT(nt_open(&f));
        nt_close_db(&f);
        ASSERT(nt_owner(f.dir, &r));
        ASSERT(nt_ok(&r));
        const struct json_value *d = nt_data(&r);
        ASSERT_STR_EQ(nt_str(d, "schema"), "zcl.fleet_nodes_table.v1");
        ASSERT_STR_EQ(nt_str(d, "source"), "local_pairing_store");
        ASSERT_STR_EQ(nt_str(d, "selection"), "recorded_pairings");
        ASSERT(nt_int(d, "observed_at") > INT64_C(1700000000));
        ASSERT_EQ(nt_int(d, "pairing_count"), 0);
        ASSERT_EQ(nt_int(d, "node_count"), 0);
        ASSERT(nt_rows(&r) != NULL);
        ASSERT_EQ(nt_rows(&r)->num_children, (size_t)0);
        PASS();
    } _test_next:;
    json_free(&r.root);
    nt_close(&f);
    return failures;
}

static bool nt_write_file(const char *dir, const char *name, const char *text)
{
    char path[600];
    (void)snprintf(path, sizeof(path), "%s/%s", dir, name);
    FILE *file = fopen(path, "wb");
    bool ok = file && fputs(text, file) >= 0;
    return file && fclose(file) == 0 && ok;
}

static bool nt_foreign_db(const char *dir)
{
    char path[600];
    sqlite3 *db = NULL;
    (void)snprintf(path, sizeof(path), "%s/node.db", dir);
    bool ok = sqlite3_open(path, &db) == SQLITE_OK &&
              sqlite3_exec(db, "CREATE TABLE unrelated(x INTEGER)", NULL, NULL,
                           NULL) == SQLITE_OK;
    sqlite3_close(db);
    return ok;
}

static int test_nt_unreadable_stores(void)
{
    int failures = 0;
    struct nt_fixture f = {0};
    struct nt_reply r = {0};
    TEST("fleet nodes table: absent, corrupt and schema-incomplete stores "
         "are refusals, never an empty success") {
        ASSERT(nt_open(&f));
        nt_close_db(&f);
        char path[600];
        (void)snprintf(path, sizeof(path), "%s/node.db", f.dir);
        ASSERT(remove(path) == 0);
        ASSERT(nt_owner(f.dir, &r));
        ASSERT(!nt_ok(&r));
        ASSERT(nt_data(&r) == NULL);
        ASSERT_STR_EQ(nt_error(&r), "NODE_DB_UNAVAILABLE");
        json_free(&r.root);

        ASSERT(nt_write_file(f.dir, "node.db", "not a database at all\n"));
        ASSERT(nt_owner(f.dir, &r));
        ASSERT(!nt_ok(&r));
        ASSERT(nt_data(&r) == NULL);
        ASSERT_STR_EQ(nt_error(&r), "NODE_DB_UNREADABLE");
        json_free(&r.root);

        ASSERT(remove(path) == 0);
        ASSERT(nt_foreign_db(f.dir));
        ASSERT(nt_owner(f.dir, &r));
        ASSERT(!nt_ok(&r));
        ASSERT(nt_data(&r) == NULL);
        ASSERT_STR_EQ(nt_error(&r), "NODES_TABLE_READ_FAILED");
        PASS();
    } _test_next:;
    json_free(&r.root);
    nt_close(&f);
    return failures;
}

static int test_nt_states(void)
{
    int failures = 0;
    struct nt_fixture f = {0};
    struct nt_reply r = {0};
    TEST("fleet nodes table: active, expired and revoked stay distinct") {
        ASSERT(nt_open(&f));
        struct nt_spec active = nt_active(1, 1);
        struct nt_spec expired = nt_active(2, 2);
        struct nt_spec revoked = nt_active(3, 3);
        expired.expires_at = NT_PAST;
        revoked.revoked_at = NT_PAIRED + 5;
        ASSERT(nt_add(&f, &active) && nt_add(&f, &expired) &&
               nt_add(&f, &revoked));
        nt_close_db(&f);
        ASSERT(nt_owner(f.dir, &r));
        ASSERT(nt_ok(&r));
        ASSERT_EQ(nt_int(nt_data(&r), "pairing_count"), 3);
        ASSERT_EQ(nt_int(nt_data(&r), "node_count"), 3);
        char fp[65];
        nt_fingerprint(1, fp);
        const struct json_value *a = nt_pairing(nt_row(&r, fp), 0);
        ASSERT_STR_EQ(nt_str(a, "state"), "active");
        ASSERT_EQ(nt_int(a, "revoked_at"), 0);
        ASSERT_EQ(nt_int(a, "revocation_generation"), 0);
        ASSERT_EQ(nt_int(a, "expires_at"), NT_FUTURE);
        nt_fingerprint(2, fp);
        const struct json_value *e = nt_pairing(nt_row(&r, fp), 0);
        ASSERT_STR_EQ(nt_str(e, "state"), "expired");
        ASSERT_EQ(nt_int(e, "expires_at"), NT_PAST);
        nt_fingerprint(3, fp);
        const struct json_value *v = nt_pairing(nt_row(&r, fp), 0);
        ASSERT_STR_EQ(nt_str(v, "state"), "revoked");
        ASSERT_EQ(nt_int(v, "revoked_at"), NT_PAIRED + 5);
        ASSERT_EQ(nt_int(v, "revocation_generation"), 1);
        ASSERT_EQ(nt_int(v, "delegation_sequence"), 7);
        ASSERT_EQ(nt_int(v, "paired_at"), NT_PAIRED);
        PASS();
    } _test_next:;
    json_free(&r.root);
    nt_close(&f);
    return failures;
}

static int test_nt_one_master_two_noise(void)
{
    int failures = 0;
    struct nt_fixture f = {0};
    struct nt_reply r = {0};
    TEST("fleet nodes table: two Noise identities under one master give one "
         "row with two pairings in store order") {
        ASSERT(nt_open(&f));
        struct nt_spec first = nt_active(9, 1);
        struct nt_spec second = nt_active(9, 2);
        first.paired_at = NT_PAIRED + 50;
        second.paired_at = NT_PAIRED + 10;
        ASSERT(nt_add(&f, &first) && nt_add(&f, &second));
        nt_close_db(&f);
        ASSERT(nt_owner(f.dir, &r));
        ASSERT(nt_ok(&r));
        ASSERT_EQ(nt_int(nt_data(&r), "pairing_count"), 2);
        ASSERT_EQ(nt_int(nt_data(&r), "node_count"), 1);
        ASSERT_EQ(nt_rows(&r)->num_children, (size_t)1);
        const struct json_value *row = &nt_rows(&r)->children[0];
        ASSERT_EQ(nt_pairings(row), (size_t)2);
        ASSERT_EQ(nt_int(nt_pairing(row, 0), "paired_at"), NT_PAIRED + 10);
        ASSERT_EQ(nt_int(nt_pairing(row, 1), "paired_at"), NT_PAIRED + 50);
        ASSERT(strcmp(nt_str(nt_pairing(row, 0), "peer_noise_fingerprint"),
                      nt_str(nt_pairing(row, 1), "peer_noise_fingerprint")) != 0);
        ASSERT(strcmp(nt_str(nt_pairing(row, 0), "pairing_id"),
                      nt_str(nt_pairing(row, 1), "pairing_id")) != 0);
        PASS();
    } _test_next:;
    json_free(&r.root);
    nt_close(&f);
    return failures;
}

/* Finds two master ids whose fingerprints share their first 8 hex digits. */
static bool nt_find_prefix_pair(uint32_t *first, uint32_t *second)
{
    enum { SLOTS = 1 << 18, TRIES = 600000 };
    uint32_t *seen = calloc(SLOTS, sizeof(*seen));
    bool found = false;
    for (uint32_t id = 1; seen && !found && id < TRIES; id++) {
        char fp[65], head[9];
        nt_fingerprint(id, fp);
        memcpy(head, fp, 8);
        head[8] = '\0';
        uint32_t slot = (uint32_t)strtoul(head, NULL, 16) & (SLOTS - 1);
        for (uint32_t probes = 0; seen[slot] != 0 && !found;
             slot = (slot + 1) & (SLOTS - 1)) {
            if (++probes > SLOTS) {
                free(seen);
                return false;
            }
            char other[65];
            nt_fingerprint(seen[slot], other);
            found = memcmp(fp, other, 8) == 0;
            if (found) {
                *first = seen[slot];
                *second = id;
            }
        }
        if (!found)
            seen[slot] = id;
    }
    free(seen);
    return found;
}

static int test_nt_prefix_masters(void)
{
    int failures = 0;
    struct nt_fixture f = {0};
    struct nt_reply r = {0};
    TEST("fleet nodes table: masters sharing a fingerprint prefix stay "
         "separate rows sorted by the full fingerprint") {
        uint32_t a = 0, b = 0;
        ASSERT(nt_find_prefix_pair(&a, &b));
        char fa[65], fb[65];
        nt_fingerprint(a, fa);
        nt_fingerprint(b, fb);
        ASSERT(memcmp(fa, fb, 8) == 0 && strcmp(fa, fb) != 0);
        ASSERT(nt_open(&f));
        struct nt_spec sa = nt_active(a, 1);
        struct nt_spec sb = nt_active(b, 1);
        ASSERT(nt_add(&f, &sa) && nt_add(&f, &sb));
        nt_close_db(&f);
        ASSERT(nt_owner(f.dir, &r));
        ASSERT(nt_ok(&r));
        ASSERT_EQ(nt_int(nt_data(&r), "node_count"), 2);
        ASSERT_EQ(nt_int(nt_data(&r), "pairing_count"), 2);
        ASSERT(nt_row(&r, fa) != NULL && nt_row(&r, fb) != NULL);
        ASSERT_EQ(nt_pairings(nt_row(&r, fa)), (size_t)1);
        ASSERT_EQ(nt_pairings(nt_row(&r, fb)), (size_t)1);
        const char *low = strcmp(fa, fb) < 0 ? fa : fb;
        ASSERT_STR_EQ(nt_str(&nt_rows(&r)->children[0],
                             "peer_master_fingerprint"), low);
        PASS();
    } _test_next:;
    json_free(&r.root);
    nt_close(&f);
    return failures;
}

static int test_nt_row_order(void)
{
    int failures = 0;
    struct nt_fixture f = {0};
    struct nt_reply r = {0};
    TEST("fleet nodes table: rows ascend by full fingerprint whatever the "
         "insertion order") {
        static const uint32_t masters[] = { 30, 10, 50, 20, 40, 60 };
        ASSERT(nt_open(&f));
        for (size_t i = 0; i < sizeof(masters) / sizeof(masters[0]); i++) {
            struct nt_spec s = nt_active(masters[i], 1);
            s.paired_at = NT_PAIRED + (int64_t)i;
            ASSERT(nt_add(&f, &s));
        }
        nt_close_db(&f);
        ASSERT(nt_owner(f.dir, &r));
        ASSERT(nt_ok(&r));
        const struct json_value *rows = nt_rows(&r);
        ASSERT_EQ(rows->num_children, (size_t)6);
        for (size_t i = 1; i < rows->num_children; i++)
            ASSERT(strcmp(nt_str(&rows->children[i - 1],
                                 "peer_master_fingerprint"),
                          nt_str(&rows->children[i],
                                 "peer_master_fingerprint")) < 0);
        PASS();
    } _test_next:;
    json_free(&r.root);
    nt_close(&f);
    return failures;
}

static int test_nt_tie_order(void)
{
    int failures = 0;
    struct nt_fixture f = {0};
    struct nt_reply r = {0};
    TEST("fleet nodes table: pairings with equal paired_at come out ordered "
         "by pairing_id") {
        ASSERT(nt_open(&f));
        for (uint8_t noise = 1; noise <= 4; noise++) {
            struct nt_spec s = nt_active(8, noise);
            ASSERT(nt_add(&f, &s));
        }
        nt_close_db(&f);
        ASSERT(nt_owner(f.dir, &r));
        ASSERT(nt_ok(&r));
        const struct json_value *row = &nt_rows(&r)->children[0];
        ASSERT_EQ(nt_pairings(row), (size_t)4);
        for (size_t i = 1; i < 4; i++)
            ASSERT(strcmp(nt_str(nt_pairing(row, i - 1), "pairing_id"),
                          nt_str(nt_pairing(row, i), "pairing_id")) < 0);
        PASS();
    } _test_next:;
    json_free(&r.root);
    nt_close(&f);
    return failures;
}

static int test_nt_masks_uncombined(void)
{
    int failures = 0;
    struct nt_fixture f = {0};
    struct nt_reply r = {0};
    TEST("fleet nodes table: capability masks are reported per pairing and "
         "never combined") {
        ASSERT(nt_open(&f));
        struct nt_spec status = nt_active(4, 1);
        struct nt_spec terminal = nt_active(4, 2);
        status.paired_at = NT_PAIRED;
        terminal.paired_at = NT_PAIRED + 1;
        terminal.mask = MESH_PAIRING_CAP_STATUS_READ |
                        MESH_PAIRING_CAP_TERMINAL_EXEC;
        ASSERT(nt_add(&f, &status) && nt_add(&f, &terminal));
        nt_close_db(&f);
        ASSERT(nt_owner(f.dir, &r));
        ASSERT(nt_ok(&r));
        const struct json_value *row = &nt_rows(&r)->children[0];
        ASSERT_EQ(nt_pairings(row), (size_t)2);
        ASSERT_EQ(nt_int(nt_pairing(row, 0), "capability_mask"), 1);
        ASSERT_EQ(nt_int(nt_pairing(row, 1), "capability_mask"), 3);
        ASSERT(json_get(row, "capability_mask") == NULL);
        PASS();
    } _test_next:;
    json_free(&r.root);
    nt_close(&f);
    return failures;
}

static int test_nt_bound(void)
{
    int failures = 0;
    struct nt_fixture f = {0};
    struct nt_reply r = {0};
    TEST("fleet nodes table: 64 pairings succeed and 65 are refused with no "
         "rows") {
        ASSERT(nt_open(&f));
        for (uint32_t i = 1; i <= 64; i++) {
            struct nt_spec s = nt_active(i, 1);
            s.paired_at = NT_PAIRED + (int64_t)i;
            ASSERT(nt_add(&f, &s));
        }
        nt_close_db(&f);
        ASSERT(nt_owner(f.dir, &r));
        ASSERT(nt_ok(&r));
        ASSERT_EQ(nt_int(nt_data(&r), "pairing_count"), 64);
        ASSERT_EQ(nt_int(nt_data(&r), "node_count"), 64);
        ASSERT_EQ(nt_rows(&r)->num_children, (size_t)64);
        json_free(&r.root);

        char path[600];
        (void)snprintf(path, sizeof(path), "%s/node.db", f.dir);
        ASSERT(node_db_open(&f.db, path));
        struct nt_spec extra = nt_active(65, 1);
        ASSERT(nt_add(&f, &extra));
        nt_close_db(&f);
        ASSERT(nt_owner(f.dir, &r));
        ASSERT(!nt_ok(&r));
        ASSERT_STR_EQ(nt_error(&r), "NODES_TABLE_TOO_LARGE");
        ASSERT(nt_rows(&r) == NULL);
        PASS();
    } _test_next:;
    json_free(&r.root);
    nt_close(&f);
    return failures;
}

static int test_nt_redaction(void)
{
    int failures = 0;
    struct nt_fixture f = {0};
    struct nt_reply r = {0};
    TEST("fleet nodes table: no raw key material and no key fields appear") {
        ASSERT(nt_open(&f));
        struct nt_spec s = nt_active(6, 0xC3);
        ASSERT(nt_add(&f, &s));
        nt_close_db(&f);
        ASSERT(nt_owner(f.dir, &r));
        ASSERT(nt_ok(&r));
        uint8_t key[32];
        char hex[65];
        nt_master_key(6, key);
        zcl_hex_encode(key, sizeof(key), hex);
        ASSERT(strstr(g_nt_text, hex) == NULL);
        memset(key, 0xC3, sizeof(key));
        zcl_hex_encode(key, sizeof(key), hex);
        ASSERT(strstr(g_nt_text, hex) == NULL);
        ASSERT(strstr(g_nt_text, "pubkey") == NULL);
        ASSERT(strstr(g_nt_text, "genesis") == NULL);
        PASS();
    } _test_next:;
    json_free(&r.root);
    nt_close(&f);
    return failures;
}

static int test_nt_authority_and_input(void)
{
    int failures = 0;
    struct nt_fixture f = {0};
    struct nt_reply r = {0};
    TEST("fleet nodes table: weaker authority is denied; unknown keys and "
         "wrong types are rejected") {
        ASSERT(nt_open(&f));
        nt_close_db(&f);
        ASSERT(nt_call(f.dir, ZCL_COMMAND_AUTH_OPERATOR, &r));
        ASSERT(!nt_ok(&r));
        ASSERT_STR_EQ(nt_error(&r), "AUTHORITY_DENIED");
        ASSERT(nt_data(&r) == NULL);
        json_free(&r.root);
        ASSERT(nt_call(f.dir, ZCL_COMMAND_AUTH_PUBLIC, &r));
        ASSERT_STR_EQ(nt_error(&r), "AUTHORITY_DENIED");
        json_free(&r.root);

        const struct zcl_command_spec *spec = zcl_command_registry_find(
            zcl_command_catalog(), NT_PATH, NULL);
        ASSERT(spec != NULL);
        ASSERT_EQ(spec->authority, ZCL_COMMAND_AUTH_OWNER);
        struct json_value input;
        char why[192];
        json_init(&input);
        json_set_object(&input);
        (void)json_push_kv_str(&input, "datadir", f.dir);
        ASSERT(zcl_command_registry_input_validate(spec, &input, why,
                                                   sizeof(why)));
        (void)json_push_kv_int(&input, "bogus", 1);
        bool unknown_ok = zcl_command_registry_input_validate(
            spec, &input, why, sizeof(why));
        json_free(&input);
        ASSERT(!unknown_ok);
        json_init(&input);
        json_set_object(&input);
        (void)json_push_kv_int(&input, "datadir", 5);
        bool typed_ok = zcl_command_registry_input_validate(
            spec, &input, why, sizeof(why));
        json_free(&input);
        ASSERT(!typed_ok);
        PASS();
    } _test_next:;
    json_free(&r.root);
    nt_close(&f);
    return failures;
}

int test_fleet_nodes_table(void);
int test_fleet_nodes_table(void)
{
    int failures = 0;
    failures += test_nt_empty_table();
    failures += test_nt_unreadable_stores();
    failures += test_nt_states();
    failures += test_nt_one_master_two_noise();
    failures += test_nt_prefix_masters();
    failures += test_nt_row_order();
    failures += test_nt_tie_order();
    failures += test_nt_masks_uncombined();
    failures += test_nt_bound();
    failures += test_nt_redaction();
    failures += test_nt_authority_and_input();
    if (failures == 0)
        printf("test_fleet_nodes_table: all passed\n");
    else
        printf("test_fleet_nodes_table: %d FAILED\n", failures);
    return failures;
}
