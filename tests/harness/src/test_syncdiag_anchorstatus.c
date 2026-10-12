/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * getsyncdiag / anchorstatus / getsyncwatchdog cases: the JSON envelope is well formed on a dirty stack, and the mint-anchor backlog is reported as stale or active from the durable sample cadence.
 */

#include "test/syncdiag_rpc_fixture.h"

#define EXPECTED_MISSING_KEYS \
    "schema,api_version,build_commit,read_only," \
    "process_identity_available,process_identity_reason,datadir," \
    "captured_at_unix,progress_path,progress_present," \
    "progress_size_bytes,progress_mtime_unix,progress_age_seconds," \
    "snapshot_path,snapshot_present,snapshot_size_bytes," \
    "snapshot_mtime_unix,anchor_height,anchor_utxo_count," \
    "snapshot_header_readable,snapshot_payload_sha3_verified," \
    "snapshot_checkpoint_sha3_match,snapshot_version,snapshot_height," \
    "snapshot_utxo_count,snapshot_total_supply,snapshot_payload_sha3," \
    "snapshot_digest_source,progress_wal_path,progress_wal_present," \
    "progress_wal_size_bytes,progress_wal_mtime_unix," \
    "progress_wal_age_seconds,progress_activity_mtime_unix," \
    "progress_activity_age_seconds,progress_activity_source," \
    "progress_sample_interval_seconds,progress_stale_after_seconds," \
    "progress_recent,eta,producer_import_preflight," \
    "body_position_preflight,status,fold_recently_active,summary," \
    "agent_next_action"
#define EXPECTED_UNREADABLE_KEYS \
    "schema,api_version,build_commit,read_only," \
    "process_identity_available,process_identity_reason,datadir," \
    "captured_at_unix,progress_path,progress_present," \
    "progress_size_bytes,progress_mtime_unix,progress_age_seconds," \
    "snapshot_path,snapshot_present,snapshot_size_bytes," \
    "snapshot_mtime_unix,anchor_height,anchor_utxo_count," \
    "snapshot_header_readable,snapshot_payload_sha3_verified," \
    "snapshot_checkpoint_sha3_match,snapshot_version,snapshot_height," \
    "snapshot_utxo_count,snapshot_total_supply,snapshot_payload_sha3," \
    "snapshot_digest_source,progress_wal_path,progress_wal_present," \
    "progress_wal_size_bytes,progress_wal_mtime_unix," \
    "progress_wal_age_seconds,progress_activity_mtime_unix," \
    "progress_activity_age_seconds,progress_activity_source," \
    "progress_sample_interval_seconds,progress_stale_after_seconds," \
    "progress_recent,eta,producer_import_preflight," \
    "body_position_preflight,status,fold_recently_active,summary," \
    "agent_next_action,sqlite_error"
#include <sys/stat.h>
#include <unistd.h>

/* Comma-joined object keys in insertion order. */
static void anchor_case_keys(const struct json_value *obj, char *out,
                             size_t cap)
{
    out[0] = '\0';
    for (size_t i = 0; i < obj->num_children; i++) {
        size_t used = strlen(out);
        snprintf(out + used, cap - used, "%s%s", i ? "," : "",
                 obj->keys[i]);
    }
}

static bool anchor_case_has_duplicate_key(const struct json_value *obj)
{
    for (size_t i = 0; i < obj->num_children; i++)
        for (size_t j = i + 1; j < obj->num_children; j++)
            if (strcmp(obj->keys[i], obj->keys[j]) == 0)
                return true;
    return false;
}

static bool anchor_case_run(const char *dir, struct json_value *result)
{
    struct json_value params, arg;
    json_init(&params);
    json_set_array(&params);
    json_init(&arg);
    json_set_str(&arg, dir);
    json_push_back(&params, &arg);
    json_free(&arg);
    json_init(result);
    bool ok = rpc_agent_anchor_status(&params, false, result);
    json_free(&params);
    return ok && result->type == JSON_OBJ;
}

static bool anchor_case_str_is(const struct json_value *obj, const char *key,
                               const char *want)
{
    const char *got = json_get_str(json_get(obj, key));
    return got && strcmp(got, want) == 0;
}

/* The import-preflight argv names "<datadir>/node.db" as its last element. */
static bool anchor_case_preflight_names(const struct json_value *result,
                                        const char *dir)
{
    const struct json_value *prep =
        json_get(result, "producer_import_preflight");
    const struct json_value *argv = prep ? json_get(prep, "argv") : NULL;
    const struct json_value *node_db = argv ? json_at(argv, 3) : NULL;
    char want[512];
    snprintf(want, sizeof(want), "%s/node.db", dir);
    return node_db && strcmp(json_get_str(node_db), want) == 0;
}

static bool anchor_case_set_meta_sql(const char *dir, const char *sql)
{
    char path[512];
    snprintf(path, sizeof(path), "%s/progress.kv", dir);
    sqlite3 *db = NULL;
    bool ok = sqlite3_open(path, &db) == SQLITE_OK &&
              syncdiag_exec_sql(db, sql);
    sqlite3_close(db);
    return ok;
}

static int anchor_case_missing_progress(void)
{
    printf("anchorstatus: missing progress store reports key order, "
           "datadir and summary... ");
    char dir[256], keys[4096];
    test_make_tmpdir(dir, sizeof(dir), "syncdiag_anchorstatus", "missing");
    struct json_value result;
    bool ok = anchor_case_run(dir, &result);
    anchor_case_keys(&result, keys, sizeof(keys));
    ok = ok && !anchor_case_has_duplicate_key(&result);
    ok = ok && strcmp(keys, EXPECTED_MISSING_KEYS) == 0;
    ok = ok && anchor_case_str_is(&result, "status", "missing");
    ok = ok && anchor_case_str_is(&result, "summary",
                                  "progress_store_missing");
    ok = ok && anchor_case_str_is(&result, "agent_next_action",
                                  "start_anchor_mint_on_full_history_datadir");
    ok = ok && anchor_case_str_is(&result, "datadir", dir);
    ok = ok && !json_get_bool(json_get(&result, "progress_present"));
    ok = ok && !json_get_bool(json_get(&result, "fold_recently_active"));
    ok = ok && anchor_case_preflight_names(&result, dir);
    if (!ok)
        printf("\n  keys=%s\n", keys);
    json_free(&result);
    test_cleanup_tmpdir(dir);
    printf("%s\n", ok ? "OK" : "FAIL");
    return ok ? 0 : 1;
}

static int anchor_case_path_too_long(void)
{
    printf("anchorstatus: over-long datadir reports path_too_long... ");
    char dir[1300];
    memset(dir, 'a', sizeof(dir) - 1);
    dir[0] = '/';
    dir[sizeof(dir) - 1] = '\0';
    struct json_value result;
    bool ok = anchor_case_run(dir, &result);
    ok = ok && anchor_case_str_is(&result, "status", "error");
    ok = ok && anchor_case_str_is(&result, "summary", "path_too_long");
    ok = ok && anchor_case_str_is(&result, "agent_next_action",
                                  "use_bounded_datadir_and_snapshot_paths");
    ok = ok && json_get(&result, "progress_path") == NULL;
    json_free(&result);
    printf("%s\n", ok ? "OK" : "FAIL");
    return ok ? 0 : 1;
}

static bool anchor_case_open_failed_ok(const struct json_value *result,
                                       const char *dir)
{
    char keys[4096];
    anchor_case_keys(result, keys, sizeof(keys));
    bool ok = !anchor_case_has_duplicate_key(result) &&
              strcmp(keys, EXPECTED_UNREADABLE_KEYS) == 0;
    if (!ok)
        printf("\n  keys=%s\n", keys);
    ok = ok && anchor_case_str_is(result, "status", "error");
    ok = ok && anchor_case_str_is(result, "summary",
                                  "progress_store_open_failed");
    ok = ok && anchor_case_str_is(
        result, "agent_next_action",
        "inspect_progress_store_permissions_or_locking");
    ok = ok && json_get_str(json_get(result, "sqlite_error")) != NULL;
    ok = ok && !json_get_bool(json_get(result, "fold_recently_active"));
    ok = ok && json_get_bool(json_get(result, "progress_present"));
    return ok && anchor_case_preflight_names(result, dir);
}

static int anchor_case_unreadable_store(void)
{
    printf("anchorstatus: unreadable progress store reports open failure... ");
    if (geteuid() == 0) {
        printf("SKIP (root ignores file modes)\n");
        return 0;
    }
    char dir[256], path[512];
    test_make_tmpdir(dir, sizeof(dir), "syncdiag_anchorstatus", "unreadable");
    snprintf(path, sizeof(path), "%s/progress.kv", dir);
    bool ok = syncdiag_seed_anchorstatus_progress(dir) &&
              chmod(path, 0) == 0;
    struct json_value result;
    ok = ok && anchor_case_run(dir, &result);
    if (ok) {
        ok = anchor_case_open_failed_ok(&result, dir);
        json_free(&result);
    }
    (void)chmod(path, 0600);
    test_cleanup_tmpdir(dir);
    printf("%s\n", ok ? "OK" : "FAIL");
    return ok ? 0 : 1;
}

static int anchor_case_applied_height(const char *tag, const char *sql,
                                      int64_t want_applied,
                                      int64_t want_durable)
{
    printf("anchorstatus: coins_applied_height %s... ", tag);
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "syncdiag_anchorstatus", tag);
    checkpoints_reset_sha3_override_for_test();
    bool ok = syncdiag_seed_anchorstatus_progress(dir) &&
              anchor_case_set_meta_sql(dir, sql);
    struct json_value result;
    ok = ok && anchor_case_run(dir, &result);
    if (ok) {
        ok = ok && anchor_case_str_is(&result, "status", "ok");
        ok = ok && json_get_int(json_get(&result, "coins_applied_height")) ==
            want_applied;
        ok = ok && json_get_int(json_get(
            &result, "durable_applied_through_height")) == want_durable;
        json_free(&result);
    }
    test_cleanup_tmpdir(dir);
    printf("%s\n", ok ? "OK" : "FAIL");
    return ok ? 0 : 1;
}

int syncdiag_cases_anchorstatus(void)
{
    int failures = 0;

    printf("rpc_getsyncdiag: returns valid JSON without abort "
           "(RED)... ");
    {
        dirty_stack_region();

        struct rpc_table tbl;
        rpc_table_init(&tbl);
        rpc_health_set_state(NULL, NULL, NULL, NULL);
        register_health_rpc_commands(&tbl);
        sync_monitor_init();
        sync_monitor_record_snapshot_resnapshot(
            100, 110, 4, 101, 111,
            "block_failed_mask_exhausted",
            "condition:tip_wedged_resnapshot");
        if (rpc_is_in_warmup(NULL, 0))
            set_rpc_warmup_finished();

        struct json_value params;
        json_init(&params);
        json_set_array(&params);

        struct json_value result;
        json_init(&result);

        bool executed = rpc_table_execute(&tbl, "getsyncdiag",
                                          &params, &result);

        bool ok = executed && result.type == JSON_OBJ;

        const struct json_value *wd  = json_get(&result, "watchdog");
        const struct json_value *hdr = json_get(&result, "headers");
        ok = ok && wd  && wd->type  == JSON_OBJ && wd->num_children  > 0;
        ok = ok && hdr && hdr->type == JSON_OBJ && hdr->num_children > 0;
        ok = ok && json_get(wd, "last_recovery_reason") != NULL;
        ok = ok && json_get(wd, "last_recovery_local_height") != NULL;
        ok = ok && json_get(wd, "last_recovery_peer_height") != NULL;
        ok = ok && json_get(wd, "last_recovery_peer_count") != NULL;
        ok = ok && json_get(wd, "last_recovery_target_height") != NULL;
        ok = ok && json_get(wd, "last_recovery_manifest_height") != NULL;
        ok = ok && json_get(wd, "last_recovery_trigger") != NULL;
        ok = ok && json_get(wd, "recoveries_total") != NULL &&
            json_get_int(json_get(wd, "recoveries_total")) == 1;
        ok = ok && json_get(wd, "last_recovery") != NULL &&
            strcmp(json_get_str(json_get(wd, "last_recovery")),
                   "SNAPSHOT_RESNAPSHOT") == 0;
        ok = ok && strcmp(json_get_str(json_get(
            wd, "last_recovery_reason")),
            "condition:tip_wedged_resnapshot") == 0;
        ok = ok && json_get_int(json_get(
            wd, "last_recovery_local_height")) == 100;
        ok = ok && json_get_int(json_get(
            wd, "last_recovery_peer_height")) == 110;
        ok = ok && json_get_int(json_get(
            wd, "last_recovery_peer_count")) == 4;
        ok = ok && json_get_int(json_get(
            wd, "last_recovery_target_height")) == 101;
        ok = ok && json_get_int(json_get(
            wd, "last_recovery_manifest_height")) == 111;
        ok = ok && strcmp(json_get_str(json_get(
            wd, "last_recovery_trigger")),
            "block_failed_mask_exhausted") == 0;

        ok = ok && json_get(&result, "sync_state")         != NULL;
        ok = ok && json_get(&result, "chain_height")       != NULL;
        ok = ok && json_get(&result, "best_header_height") != NULL;

        json_free(&params);
        json_free(&result);

        if (ok) printf("OK\n");
        else    { printf("FAIL\n"); failures++; }
    }

    printf("anchorstatus: names stale anchor mint UTXO backlog blocker "
           "(RED)... ");
    {
        checkpoints_reset_sha3_override_for_test();
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "syncdiag_anchorstatus",
                         "backlog");
        bool ok = syncdiag_seed_anchorstatus_progress(dir);
        ok = ok && syncdiag_set_progress_mtime_seconds_ago(dir, 3600);

        struct json_value params;
        json_init(&params);
        json_set_array(&params);
        struct json_value arg;
        json_init(&arg);
        json_set_str(&arg, dir);
        json_push_back(&params, &arg);
        json_free(&arg);

        struct json_value result;
        json_init(&result);
        ok = ok && rpc_agent_anchor_status(&params, false, &result);
        ok = ok && result.type == JSON_OBJ;
        ok = ok && json_get(&result, "schema") != NULL &&
            strcmp(json_get_str(json_get(&result, "schema")),
                   "zcl.anchor_mint_status.v1") == 0;
        ok = ok && json_get(&result, "status") != NULL &&
            strcmp(json_get_str(json_get(&result, "status")), "ok") == 0;
        ok = ok && json_get(&result, "captured_at_unix") != NULL &&
            json_get_int(json_get(&result, "captured_at_unix")) > 0;
        ok = ok && json_get(&result, "progress_age_seconds") != NULL &&
            json_get_int(json_get(&result, "progress_age_seconds")) > 300;
        ok = ok && json_get(&result, "progress_recent") != NULL &&
            !json_get_bool(json_get(&result, "progress_recent"));
        ok = ok && json_get(&result, "progress_wal_present") != NULL &&
            !json_get_bool(json_get(&result, "progress_wal_present"));
        ok = ok && strcmp(json_get_str(json_get(
            &result, "progress_activity_source")), "progress.kv") == 0;
        ok = ok && json_get_int(json_get(
            &result, "progress_sample_interval_seconds")) == 60;
        ok = ok && json_get_int(json_get(
            &result, "progress_stale_after_seconds")) == 300;
        ok = ok && json_get(&result, "fold_recently_active") != NULL &&
            !json_get_bool(json_get(&result, "fold_recently_active"));
        ok = ok && json_get(&result, "summary") != NULL &&
            strcmp(json_get_str(json_get(&result, "summary")),
                   "mint_utxo_apply_far_behind_validated_backlog") == 0;
        ok = ok && json_get(&result, "agent_next_action") != NULL &&
            strcmp(json_get_str(json_get(&result, "agent_next_action")),
                   "inspect_utxo_apply_idle_reason_before_waiting_more") == 0;
        ok = ok && json_get(&result, "mint_marker_present") != NULL &&
            json_get_bool(json_get(&result, "mint_marker_present"));
        ok = ok && json_get(&result, "mint_marker_matches_checkpoint") != NULL &&
            json_get_bool(json_get(&result,
                                   "mint_marker_matches_checkpoint"));
        ok = ok && json_get(&result, "refold_in_progress_present") != NULL &&
            json_get_bool(json_get(&result, "refold_in_progress_present"));
        ok = ok && json_get(&result, "coins_applied_height") != NULL &&
            json_get_int(json_get(&result, "coins_applied_height")) == 164000;
        ok = ok && json_get(&result, "durable_applied_through_height") != NULL &&
            json_get_int(json_get(&result,
                                  "durable_applied_through_height")) == 163999;
        ok = ok && json_get(&result, "validated_backlog_blocks") != NULL &&
            json_get_int(json_get(&result,
                                  "validated_backlog_blocks")) == 2627000;
        ok = ok && json_get(&result, "stale_header_rows_above_anchor") != NULL &&
            json_get_int(json_get(&result,
                                  "stale_header_rows_above_anchor")) == 1;
        ok = ok && json_get(&result, "stale_rows_above_anchor") != NULL &&
            json_get_bool(json_get(&result, "stale_rows_above_anchor"));
        ok = ok && json_get(&result, "utxo_apply_probe_next_action") != NULL &&
            strcmp(json_get_str(json_get(&result,
                                         "utxo_apply_probe_next_action")),
                   "inspect_anchor_mint_liveness_and_durable_activity") == 0;

        const struct json_value *probe =
            json_get(&result, "utxo_apply_probe");
        ok = ok && probe != NULL && probe->type == JSON_OBJ;
        ok = ok && json_get(probe, "next_height") != NULL &&
            json_get_int(json_get(probe, "next_height")) == 164000;
        ok = ok && json_get(probe, "previous_height") != NULL &&
            json_get_int(json_get(probe, "previous_height")) == 163999;
        ok = ok && json_get(probe, "previous_row_expected") != NULL &&
            json_get_bool(json_get(probe, "previous_row_expected"));
        ok = ok && json_get(probe, "next_diagnosis") != NULL &&
            strcmp(json_get_str(json_get(probe, "next_diagnosis")),
                   "utxo_apply_idle_after_validated_row") == 0;
        ok = ok && json_get(probe, "history_diagnosis") != NULL &&
            strcmp(json_get_str(json_get(probe, "history_diagnosis")),
                   "utxo_apply_history_consistent") == 0;
        ok = ok && json_get(probe, "next_action") != NULL &&
            strcmp(json_get_str(json_get(probe, "next_action")),
                   "inspect_anchor_mint_liveness_and_durable_activity") == 0;

        const struct json_value *proof_next =
            json_get(probe, "proof_validate_at_next");
        ok = ok && proof_next != NULL;
        ok = ok && json_get(proof_next, "row_present") != NULL &&
            json_get_bool(json_get(proof_next, "row_present"));
        ok = ok && json_get(proof_next, "ok") != NULL &&
            json_get_int(json_get(proof_next, "ok")) == 1;

        const struct json_value *utxo_next =
            json_get(probe, "utxo_apply_at_next");
        ok = ok && utxo_next != NULL;
        ok = ok && json_get(utxo_next, "row_present") != NULL &&
            !json_get_bool(json_get(utxo_next, "row_present"));

        const struct json_value *utxo =
            find_object_with_str(json_get(&result, "stages"),
                                 "name", "utxo_apply");
        ok = ok && utxo != NULL;
        ok = ok && json_get(utxo, "cursor") != NULL &&
            json_get_int(json_get(utxo, "cursor")) == 164000;
        ok = ok && json_get(utxo, "log_max_height") != NULL &&
            json_get_int(json_get(utxo, "log_max_height")) == 163999;

        const struct json_value *eta = json_get(&result, "eta");
        ok = ok && eta != NULL && eta->type == JSON_OBJ;
        ok = ok && json_get(eta, "available") != NULL &&
            json_get_bool(json_get(eta, "available"));
        ok = ok && json_get(eta, "older_height") != NULL &&
            json_get_int(json_get(eta, "older_height")) == 0;
        ok = ok && json_get(eta, "newer_height") != NULL &&
            json_get_int(json_get(eta, "newer_height")) == 163999;
        ok = ok && json_get(eta, "eta_seconds") != NULL &&
            json_get_int(json_get(eta, "eta_seconds")) > 0;

        /* Add a valid empty-body USS fixture so the existing typed offline
         * anchorstatus command proves it reports a digest only after the
         * read-only loader verifies the payload. */
        ok = ok && syncdiag_write_empty_anchor_snapshot(dir);
        ok = ok && syncdiag_seed_body_position_hazard(dir);
        struct json_value snapshot_result;
        json_init(&snapshot_result);
        ok = ok && rpc_agent_anchor_status(&params, false, &snapshot_result);
        ok = ok && json_get(&snapshot_result, "read_only") != NULL &&
            json_get_bool(json_get(&snapshot_result, "read_only"));
        ok = ok && json_get(&snapshot_result,
                            "process_identity_available") != NULL &&
            !json_get_bool(json_get(&snapshot_result,
                                    "process_identity_available"));
        ok = ok && json_get(&snapshot_result,
                            "snapshot_payload_sha3_verified") != NULL &&
            json_get_bool(json_get(&snapshot_result,
                                   "snapshot_payload_sha3_verified"));
        const char *payload_sha3 = json_get_str(json_get(
            &snapshot_result, "snapshot_payload_sha3"));
        ok = ok && payload_sha3 && strlen(payload_sha3) == 64;
        const struct json_value *snapshot_eta =
            json_get(&snapshot_result, "eta");
        ok = ok && snapshot_eta &&
            json_get_bool(json_get(snapshot_eta, "available"));
        const struct json_value *prep =
            json_get(&snapshot_result, "producer_import_preflight");
        /* --importblockindex is now scanned anywhere in argv (engine/entry/main.c),
         * so this field is correctly `false` — see
         * agent_cure_status_helpers.c and
         * test_importblockindex_cli_dispatch.c's nonfirst-position case for
         * the live proof. */
        ok = ok && prep &&
            json_get(prep, "importblockindex_must_be_argv1") != NULL &&
            !json_get_bool(json_get(prep,
                                    "importblockindex_must_be_argv1"));
        ok = ok && strstr(json_get_str(json_get(prep, "exact_template")),
                          "BIN --importblockindex") != NULL;
        const struct json_value *body_position =
            json_get(&snapshot_result, "body_position_preflight");
        ok = ok && body_position &&
            json_get_bool(json_get(body_position, "suspected"));
        ok = ok && strcmp(json_get_str(json_get(body_position,
                                                "classification")),
                          "header_only_import_body_position_unproven") == 0;
        json_free(&snapshot_result);

        json_free(&params);
        json_free(&result);
        test_cleanup_tmpdir(dir);

        if (ok) printf("OK\n");
        else    { printf("FAIL\n"); failures++; }
    }

    printf("anchorstatus: treats recent anchor mint backlog as active "
           "(RED)... ");
    {
        checkpoints_reset_sha3_override_for_test();
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "syncdiag_anchorstatus",
                         "active");
        bool ok = syncdiag_seed_anchorstatus_progress(dir);

        struct json_value params;
        json_init(&params);
        json_set_array(&params);
        struct json_value arg;
        json_init(&arg);
        json_set_str(&arg, dir);
        json_push_back(&params, &arg);
        json_free(&arg);

        struct json_value result;
        json_init(&result);
        ok = ok && rpc_agent_anchor_status(&params, false, &result);
        ok = ok && result.type == JSON_OBJ;
        ok = ok && json_get(&result, "status") != NULL &&
            strcmp(json_get_str(json_get(&result, "status")), "ok") == 0;
        ok = ok && json_get(&result, "progress_age_seconds") != NULL &&
            json_get_int(json_get(&result, "progress_age_seconds")) >= 0 &&
            json_get_int(json_get(&result, "progress_age_seconds")) <= 300;
        ok = ok && json_get(&result, "progress_recent") != NULL &&
            json_get_bool(json_get(&result, "progress_recent"));
        ok = ok && json_get(&result, "fold_recently_active") != NULL &&
            json_get_bool(json_get(&result, "fold_recently_active"));
        ok = ok && json_get(&result, "summary") != NULL &&
            strcmp(json_get_str(json_get(&result, "summary")),
                   "mint_in_progress_recent") == 0;
        ok = ok && json_get(&result, "agent_next_action") != NULL &&
            strcmp(json_get_str(json_get(&result, "agent_next_action")),
                   "observe_anchor_mint_progress") == 0;
        ok = ok && json_get(&result, "utxo_apply_probe_next_action") != NULL &&
            strcmp(json_get_str(json_get(&result,
                                         "utxo_apply_probe_next_action")),
                   "observe_anchor_mint_progress") == 0;

        const struct json_value *probe =
            json_get(&result, "utxo_apply_probe");
        ok = ok && probe != NULL && probe->type == JSON_OBJ;
        ok = ok && json_get(probe, "next_diagnosis") != NULL &&
            strcmp(json_get_str(json_get(probe, "next_diagnosis")),
                   "utxo_apply_idle_after_validated_row") == 0;
        ok = ok && json_get(probe, "next_action") != NULL &&
            strcmp(json_get_str(json_get(probe, "next_action")),
                   "observe_anchor_mint_progress") == 0;

        json_free(&params);
        json_free(&result);
        test_cleanup_tmpdir(dir);

        if (ok) printf("OK\n");
        else    { printf("FAIL\n"); failures++; }
    }

    printf("anchorstatus: treats a fresh WAL as producer activity "
           "(RED)... ");
    {
        checkpoints_reset_sha3_override_for_test();
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "syncdiag_anchorstatus",
                         "wal_active");
        bool ok = syncdiag_seed_anchorstatus_progress(dir);
        sqlite3 *wal_db = NULL;
        ok = ok && syncdiag_open_fresh_progress_wal(dir, &wal_db);
        ok = ok && syncdiag_set_progress_mtime_seconds_ago(dir, 3600);

        struct json_value params;
        json_init(&params);
        json_set_array(&params);
        struct json_value arg;
        json_init(&arg);
        json_set_str(&arg, dir);
        json_push_back(&params, &arg);
        json_free(&arg);

        struct json_value result;
        json_init(&result);
        ok = ok && rpc_agent_anchor_status(&params, false, &result);
        ok = ok && json_get_int(json_get(
            &result, "progress_age_seconds")) > 300;
        ok = ok && json_get_bool(json_get(
            &result, "progress_wal_present"));
        ok = ok && json_get_int(json_get(
            &result, "progress_wal_size_bytes")) > 0;
        int64_t wal_age = json_get_int(json_get(
            &result, "progress_wal_age_seconds"));
        ok = ok && wal_age >= 0 && wal_age <= 30;
        ok = ok && strcmp(json_get_str(json_get(
            &result, "progress_activity_source")), "progress.kv-wal") == 0;
        ok = ok && json_get_bool(json_get(&result, "progress_recent"));
        ok = ok && json_get_bool(json_get(
            &result, "fold_recently_active"));
        ok = ok && strcmp(json_get_str(json_get(&result, "summary")),
                          "mint_in_progress_recent") == 0;
        ok = ok && strcmp(json_get_str(json_get(
            &result, "utxo_apply_probe_next_action")),
            "observe_anchor_mint_progress") == 0;

        json_free(&params);
        json_free(&result);
        sqlite3_close(wal_db);
        test_cleanup_tmpdir(dir);

        if (ok) printf("OK\n");
        else    { printf("FAIL\n"); failures++; }
    }

    printf("anchorstatus: honors durable sample cadence beyond 300 seconds "
           "(RED)... ");
    {
        checkpoints_reset_sha3_override_for_test();
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "syncdiag_anchorstatus",
                         "cadence_active");
        bool ok = syncdiag_seed_anchorstatus_progress(dir);
        ok = ok && syncdiag_set_utxo_sample_ages(dir, 800, 200);
        ok = ok && syncdiag_set_progress_mtime_seconds_ago(dir, 3600);

        struct json_value params;
        json_init(&params);
        json_set_array(&params);
        struct json_value arg;
        json_init(&arg);
        json_set_str(&arg, dir);
        json_push_back(&params, &arg);
        json_free(&arg);

        struct json_value result;
        json_init(&result);
        ok = ok && rpc_agent_anchor_status(&params, false, &result);
        ok = ok && json_get_int(json_get(
            &result, "progress_age_seconds")) > 300;
        ok = ok && !json_get_bool(json_get(
            &result, "progress_wal_present"));
        ok = ok && strcmp(json_get_str(json_get(
            &result, "progress_activity_source")),
            "durable_utxo_apply_sample") == 0;
        int64_t activity_age = json_get_int(json_get(
            &result, "progress_activity_age_seconds"));
        ok = ok && activity_age >= 190 && activity_age <= 240;
        ok = ok && json_get_int(json_get(
            &result, "progress_sample_interval_seconds")) == 600;
        ok = ok && json_get_int(json_get(
            &result, "progress_stale_after_seconds")) == 1200;
        ok = ok && json_get_bool(json_get(&result, "progress_recent"));
        ok = ok && json_get_bool(json_get(
            &result, "fold_recently_active"));
        ok = ok && strcmp(json_get_str(json_get(&result, "summary")),
                          "mint_in_progress_recent") == 0;
        ok = ok && strcmp(json_get_str(json_get(
            &result, "utxo_apply_probe_next_action")),
            "observe_anchor_mint_progress") == 0;

        json_free(&params);
        json_free(&result);
        test_cleanup_tmpdir(dir);

        if (ok) printf("OK\n");
        else    { printf("FAIL\n"); failures++; }
    }

    printf("getsyncwatchdog: exposes last recovery context "
           "(RED)... ");
    {
        struct rpc_table tbl;
        rpc_table_init(&tbl);
        register_health_rpc_commands(&tbl);
        sync_monitor_init();
        sync_monitor_record_snapshot_resnapshot(
            120, 130, 2, 121, 131,
            "local_import_exhausted",
            "condition:tip_wedged_resnapshot");
        if (rpc_is_in_warmup(NULL, 0))
            set_rpc_warmup_finished();

        struct json_value params;
        json_init(&params);
        json_set_array(&params);

        struct json_value result;
        json_init(&result);

        bool ok = rpc_table_execute(&tbl, "getsyncwatchdog",
                                    &params, &result);

        ok = ok && result.type == JSON_OBJ;
        ok = ok && json_get(&result, "enabled") != NULL;
        ok = ok && json_get(&result, "recoveries_total") != NULL &&
            json_get_int(json_get(&result, "recoveries_total")) == 1;
        ok = ok && json_get(&result, "last_recovery") != NULL &&
            strcmp(json_get_str(json_get(&result, "last_recovery")),
                   "SNAPSHOT_RESNAPSHOT") == 0;
        ok = ok && json_get(&result, "last_recovery_time") != NULL &&
            json_get_int(json_get(&result, "last_recovery_time")) > 0;
        ok = ok && json_get(&result, "last_recovery_reason") != NULL &&
            strcmp(json_get_str(json_get(
            &result, "last_recovery_reason")),
            "condition:tip_wedged_resnapshot") == 0;
        ok = ok && json_get(&result, "last_recovery_local_height") != NULL &&
            json_get_int(json_get(
            &result, "last_recovery_local_height")) == 120;
        ok = ok && json_get(&result, "last_recovery_peer_height") != NULL &&
            json_get_int(json_get(
            &result, "last_recovery_peer_height")) == 130;
        ok = ok && json_get(&result, "last_recovery_peer_count") != NULL &&
            json_get_int(json_get(
            &result, "last_recovery_peer_count")) == 2;
        ok = ok && json_get(
            &result, "last_recovery_target_height") != NULL &&
            json_get_int(json_get(
            &result, "last_recovery_target_height")) == 121;
        ok = ok && json_get(
            &result, "last_recovery_manifest_height") != NULL &&
            json_get_int(json_get(
            &result, "last_recovery_manifest_height")) == 131;
        ok = ok && json_get(&result, "last_recovery_trigger") != NULL &&
            strcmp(json_get_str(json_get(
            &result, "last_recovery_trigger")),
            "local_import_exhausted") == 0;

        json_free(&params);
        json_free(&result);

        if (ok) printf("OK\n");
        else    { printf("FAIL\n"); failures++; }
    }

    printf("rpc_http response envelope: dirty stack still builds JSON "
           "(RED)... ");
    {
        dirty_stack_region();

        struct json_value result;
        json_init(&result);
        json_set_object(&result);
        json_push_kv_str(&result, "watchdog", "ok");

        struct json_value id;
        json_init(&id);
        json_set_int(&id, 1);

        struct json_value response;
        bool ok = rpc_http_test_build_response_envelope(
            true, "getsyncdiag", &result, &id, &response);

        ok = ok && response.type == JSON_OBJ;
        ok = ok && json_get(&response, "result") != NULL;
        ok = ok && json_get(&response, "error") != NULL;
        ok = ok && json_get(&response, "id") != NULL;

        json_free(&result);
        json_free(&id);
        json_free(&response);

        if (ok) printf("OK\n");
        else    { printf("FAIL\n"); failures++; }
    }

    failures += anchor_case_missing_progress();
    failures += anchor_case_path_too_long();
    failures += anchor_case_unreadable_store();
    failures += anchor_case_applied_height(
        "zero", "UPDATE progress_meta SET value=zeroblob(8) "
                "WHERE key='coins_applied_height'", 0, -1);
    failures += anchor_case_applied_height(
        "absent", "DELETE FROM progress_meta "
                  "WHERE key='coins_applied_height'", -1, -1);

    return failures;
}
