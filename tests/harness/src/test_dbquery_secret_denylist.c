/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tests for the native dbquery secret-material denylist
 * (engine/controllers/src/dbquery_controller.c: dbq_secret_hit()).
 *
 * `dbquery` is SELECT-only; the denylist decides which SELECTs are safe.
 * These tests call diag_rpc_dbquery() against a real ":memory:" node.db
 * opened through node_db_open() / db_service_* / app_runtime_set_current(). */

#include "test/test_core.h"
#include "json/json.h"
#include "models/database.h"
#include "controllers/diagnostics_internal.h"
#include "config/db_service.h"
#include "config/runtime.h"

#define DDT_RUN(name, expr) do { \
    printf("%s... ", (name));    \
    bool _ok = (expr);           \
    if (_ok) printf("OK\n");     \
    else { printf("FAIL\n"); failures++; } \
} while (0)

struct ddt_fixture {
    struct node_db ndb;
    struct db_service dbsvc;
    struct app_runtime_context runtime;
};

static bool ddt_fixture_init(struct ddt_fixture *f)
{
    memset(f, 0, sizeof(*f));
    if (!node_db_open(&f->ndb, ":memory:"))
        return false;
    db_service_init(&f->dbsvc);
    if (!db_service_attach(&f->dbsvc, &f->ndb)) return false;
    if (!db_service_start(&f->dbsvc)) return false;
    f->runtime.db_service = &f->dbsvc;
    app_runtime_set_current(&f->runtime);
    return true;
}

static void ddt_fixture_tear_down(struct ddt_fixture *f)
{
    app_runtime_set_current(NULL);
    db_service_stop(&f->dbsvc);
    node_db_close(&f->ndb);
}

/* Runs `sql` through the real dbquery RPC handler. Returns the
 * handler's own bool result (true = executed, false = rejected at
 * validation) and hands back the JSON body it produced. */
static bool ddt_query(const char *sql, struct json_value *result)
{
    struct json_value params;
    struct json_value sql_v;
    json_init(&params);
    json_init(&sql_v);
    json_set_array(&params);
    json_set_str(&sql_v, sql);
    json_push_back(&params, &sql_v);
    json_free(&sql_v);

    json_init(result);
    bool rc = diag_rpc_dbquery(&params, /*help=*/false, result);
    json_free(&params);
    return rc;
}

/* 1. The three secret tables are denied wholesale (`SELECT * FROM <table>`). */
static int t_secret_table_denied(void)
{
    int failures = 0;
    static const char *tables[] = {
        "wallet_keys", "wallet_sapling_keys", "wallet_seed",
    };
    for (size_t i = 0; i < sizeof(tables) / sizeof(tables[0]); i++) {
        char sql[128];
        snprintf(sql, sizeof(sql), "SELECT * FROM %s LIMIT 1", tables[i]);
        struct json_value result;
        bool rc = ddt_query(sql, &result);
        char label[160];
        snprintf(label, sizeof(label), "dbquery: SELECT * FROM %s denied",
                 tables[i]);
        DDT_RUN(label, !rc && result.type == JSON_STR &&
                strstr(json_get_str(&result), "secret") != NULL);
        json_free(&result);
    }
    return failures;
}

/* 2. Named secret columns are denied, including the reported repro string. */
static int t_secret_column_denied(void)
{
    int failures = 0;

    struct json_value result;
    bool rc = ddt_query("SELECT privkey FROM wallet_keys", &result);
    DDT_RUN("dbquery: SELECT privkey FROM wallet_keys denied (repro)",
            !rc && result.type == JSON_STR);
    json_free(&result);

    rc = ddt_query("SELECT xsk FROM wallet_sapling_keys", &result);
    DDT_RUN("dbquery: SELECT xsk (spending key) denied", !rc);
    json_free(&result);

    rc = ddt_query("SELECT seed FROM wallet_seed", &result);
    DDT_RUN("dbquery: SELECT seed (HD seed) denied", !rc);
    json_free(&result);

    /* A secret-named column is caught even beside non-secret columns. */
    rc = ddt_query("SELECT pubkey_hash, privkey FROM wallet_keys", &result);
    DDT_RUN("dbquery: privkey denied even mixed with public columns", !rc);
    json_free(&result);

    return failures;
}

/* 3. Ordinary queries still work, including the sqlite_master probe from
 *    test_syncdiag_rpc.c, which must not collide with the "master" keyword
 *    (underscore word-boundary). */
static int t_normal_query_allowed(void)
{
    int failures = 0;

    struct json_value result;
    bool rc = ddt_query("SELECT * FROM blocks LIMIT 1", &result);
    DDT_RUN("dbquery: SELECT * FROM blocks LIMIT 1 still works",
            rc && result.type == JSON_OBJ &&
            json_get(&result, "columns") != NULL);
    json_free(&result);

    rc = ddt_query("SELECT txid FROM wallet_transactions LIMIT 1", &result);
    DDT_RUN("dbquery: non-secret wallet table (wallet_transactions) allowed",
            rc && result.type == JSON_OBJ);
    json_free(&result);

    rc = ddt_query(
        "SELECT name FROM sqlite_master WHERE type='table' LIMIT 5",
        &result);
    DDT_RUN("dbquery: sqlite_master probe not blocked by 'master' keyword",
            rc && result.type == JSON_OBJ);
    json_free(&result);

    return failures;
}

/* 4. Obfuscated references (whitespace, case, aliases, quoted identifiers,
 *    subqueries) are caught or rejected; every case is denied, none leaks. */
static int t_obfuscation_denied(void)
{
    int failures = 0;
    static const char *sqls[] = {
        /* extra / irregular whitespace */
        "SELECT   *    FROM     wallet_keys",
        "SELECT *\nFROM\twallet_keys",
        /* case variation */
        "select PrivKey from Wallet_Keys",
        /* table alias + qualified column reference */
        "SELECT w.privkey FROM wallet_keys AS w",
        /* nested subquery wrapping the secret table */
        "SELECT * FROM (SELECT privkey FROM wallet_keys) t",
        /* bracket-quoted identifier */
        "SELECT * FROM [wallet_keys]",
        /* double-quoted identifier */
        "SELECT * FROM \"wallet_keys\"",
        /* CTE form: rejected by the "must start with SELECT" gate. */
        "WITH x AS (SELECT privkey FROM wallet_keys) SELECT * FROM x",
    };
    for (size_t i = 0; i < sizeof(sqls) / sizeof(sqls[0]); i++) {
        struct json_value result;
        bool rc = ddt_query(sqls[i], &result);
        char label[192];
        snprintf(label, sizeof(label), "dbquery: obfuscation case %zu denied",
                 i);
        DDT_RUN(label, !rc && result.type != JSON_OBJ);
        json_free(&result);
    }
    return failures;
}

/* 5. Authorizing material that is not a private key.
 *
 *    `agent_sessions.session_id` is a bearer grant (ZCL_AGENT_SESSION), and
 *    `zswp_contracts.secret` is an HTLC preimage; reading either is spend
 *    authority. Redacted views remain: `vault session list`, `app swap list`. */
static int t_authorizing_material_denied(struct ddt_fixture *f)
{
    int failures = 0;

    /* Plant real authorizing material so the denial is proven against
     * existing rows. */
    (void)node_db_exec(&f->ndb,
        "INSERT OR REPLACE INTO principals"
        "(address,pubkey_hex,key_kind,znam_name,role,granted_capabilities,"
        " created_at,last_login,status,sybil_proof_height)"
        " VALUES('t1CustodyTestPrincipal','00',0,'','owner',0,1,0,'active',-1)");
    (void)node_db_exec(&f->ndb,
        "INSERT OR REPLACE INTO agent_sessions"
        "(session_id,account,max_per_tx_zat,max_per_window_zat,window_seconds,"
        " window_start_epoch,spent_in_window_zat,recipient_allowlist,"
        " created_at,expires_at,revoked)"
        " VALUES('deadbeefdeadbeefdeadbeefdeadbeef','t1CustodyTestPrincipal',"
        " 100000000,100000000,3600,1,0,'',1,0,0)");
    (void)node_db_exec(&f->ndb,
        "INSERT OR REPLACE INTO zswp_contracts"
        "(swap_id,role,state,chain,secret_hash,secret,amount,locktime,"
        " my_address,counter_address,redeem_script,redeem_script_len,"
        " p2sh_address,created_at)"
        " VALUES('swap-custody-test',0,0,0,x'00',x'0badc0de',1,1,'a','b',"
        " x'00',1,'p',1)");

    static const struct { const char *sql; const char *label; } cases[] = {
        { "SELECT session_id FROM agent_sessions",
          "dbquery: agent grant token (session_id) denied" },
        { "SELECT * FROM agent_sessions",
          "dbquery: SELECT * FROM agent_sessions denied" },
        { "SELECT session_id, max_per_tx_zat FROM agent_sessions "
          "ORDER BY max_per_tx_zat DESC",
          "dbquery: widest-grant token hunt denied" },
        { "select SESSION_ID from Agent_Sessions",
          "dbquery: agent grant token denied case-insensitively" },
        { "SELECT * FROM (SELECT session_id FROM agent_sessions) t",
          "dbquery: agent grant token denied inside a subquery" },
        { "SELECT secret FROM zswp_contracts",
          "dbquery: HTLC preimage (secret) denied" },
        { "SELECT * FROM zswp_contracts",
          "dbquery: SELECT * FROM zswp_contracts denied" },
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        struct json_value result;
        bool rc = ddt_query(cases[i].sql, &result);
        DDT_RUN(cases[i].label,
                !rc && result.type == JSON_STR &&
                strstr(json_get_str(&result), "secret") != NULL);
        json_free(&result);
    }

    /* Public tables stay readable: `secret_hash` is a public commitment and
     * must survive the `secret` word-boundary. */
    struct json_value result;
    bool rc = ddt_query("SELECT secret_hash FROM zswp_swaps_public_probe",
                        &result);
    DDT_RUN("dbquery: 'secret_hash' not caught by the 'secret' word",
            !rc && result.type == JSON_STR &&
            strstr(json_get_str(&result), "references secret") == NULL);
    json_free(&result);

    rc = ddt_query("SELECT address, role FROM principals LIMIT 1", &result);
    DDT_RUN("dbquery: principals (public identity) still readable",
            rc && result.type == JSON_OBJ);
    json_free(&result);

    return failures;
}

int test_dbquery_secret_denylist(void)
{
    printf("\n=== dbquery secret denylist tests ===\n");
    int failures = 0;

    struct ddt_fixture f;
    if (!ddt_fixture_init(&f)) {
        printf("dbquery_secret_denylist: fixture init failed\n");
        return 1;
    }

    failures += t_secret_table_denied();
    failures += t_secret_column_denied();
    failures += t_normal_query_allowed();
    failures += t_obfuscation_denied();
    failures += t_authorizing_material_denied(&f);

    ddt_fixture_tear_down(&f);
    return failures;
}
