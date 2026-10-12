/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Read-only, node-free status projection for a consensus-state producer. */

#include "config/consensus_state_producer_receipt.h"

#include "base/bytes.h"
#include "storage/consensus_db.h"    /* consensus_db_kernel_store_path */
#include "storage/consensus_state_bundle_codec.h"
#include "storage/cure_progress_read.h"
#include "base/text_fit.h"

#include <errno.h>
#include <limits.h>
#include <sqlite3.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

static bool status_set_err(char *err, size_t err_size, const char *msg)
{
    if (err && err_size)
        (void)zcl_text_fit(err, err_size, msg, "producer_status", "error");
    return false; /* raw-return-ok:bounded status reason returned to caller */
}

static bool status_set_sqlite_err(char *err, size_t err_size,
                                  sqlite3 *db, const char *operation)
{
    char why[256];
    snprintf(why, sizeof(why), "producer status: %s: %s", operation,
             db ? sqlite3_errmsg(db) : "sqlite handle unavailable");
    return status_set_err(err, err_size, why);
}

/* Every projection in one status response must describe the same durable
 * producer generation.  In WAL mode, an explicit read transaction pins the
 * snapshot established by the first SELECT while the producer keeps writing. */
static bool pkv_read_transaction(sqlite3 *db, const char *sql,
                                 const char *operation,
                                 char *err, size_t err_size)
{
    int rc = sqlite3_exec(db, sql, NULL, NULL, NULL); // raw-sql-ok:read-only-introspection
    if (rc != SQLITE_OK)
        return status_set_sqlite_err(err, err_size, db, operation);
    return true;
}

#ifdef ZCL_TESTING
static void (*g_status_after_first_cursor_hook)(void *ctx);
static void *g_status_after_first_cursor_ctx;

void consensus_state_producer_status_test_set_after_first_cursor_hook(
    void (*hook)(void *), void *ctx);

void consensus_state_producer_status_test_set_after_first_cursor_hook(
    void (*hook)(void *), void *ctx)
{
    g_status_after_first_cursor_hook = hook;
    g_status_after_first_cursor_ctx = ctx;
}
#endif

enum pkv_read_result {
    PKV_READ_ERROR = -1,
    PKV_READ_ABSENT = 0,
    PKV_READ_PRESENT = 1,
};

/* An old/empty progress.kv may legitimately predate a projection table. Once
 * a table exists, however, every read is strict: SQL errors and malformed
 * values are corruption/unreadability, never silently projected as absence. */
static bool pkv_table_exists(sqlite3 *db, const char *table, bool *exists,
                             char *err, size_t err_size)
{
    static const char sql[] =
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema "
        "WHERE type='table' AND name=?1)";
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK)
        return status_set_sqlite_err(err, err_size, db,
                                     "inspect schema prepare");
    if (sqlite3_bind_text(st, 1, table, -1, SQLITE_STATIC) != SQLITE_OK) {
        sqlite3_finalize(st);
        return status_set_sqlite_err(err, err_size, db,
                                     "inspect schema bind");
    }
    int rc = sqlite3_step(st); // raw-sql-ok:read-only-introspection
    bool ok = rc == SQLITE_ROW && sqlite3_column_type(st, 0) == SQLITE_INTEGER;
    int64_t value = ok ? sqlite3_column_int64(st, 0) : -1;
    if (ok)
        ok = sqlite3_step(st) == SQLITE_DONE; // raw-sql-ok:read-only-introspection
    int finalize_rc = sqlite3_finalize(st);
    if (!ok || finalize_rc != SQLITE_OK || (value != 0 && value != 1))
        return status_set_sqlite_err(err, err_size, db,
                                     "inspect schema result");
    *exists = value == 1;
    return true;
}

static enum pkv_read_result pkv_query_i64(sqlite3 *db, const char *table,
                                          const char *sql, int64_t *out,
                                          char *err, size_t err_size)
{
    bool table_present = false;
    if (!pkv_table_exists(db, table, &table_present, err, err_size))
        return PKV_READ_ERROR;
    if (!table_present)
        return PKV_READ_ABSENT;

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK) {
        status_set_sqlite_err(err, err_size, db, "integer query prepare");
        return PKV_READ_ERROR;
    }
    int rc = sqlite3_step(st); // raw-sql-ok:read-only-introspection
    if (rc == SQLITE_DONE) {
        int finalize_rc = sqlite3_finalize(st);
        if (finalize_rc != SQLITE_OK) {
            status_set_sqlite_err(err, err_size, db,
                                  "integer query finalize");
            return PKV_READ_ERROR;
        }
        return PKV_READ_ABSENT;
    }
    if (rc != SQLITE_ROW || sqlite3_column_type(st, 0) != SQLITE_INTEGER) {
        sqlite3_finalize(st);
        status_set_err(err, err_size,
                       "producer status: integer projection is malformed");
        return PKV_READ_ERROR;
    }
    int64_t value = sqlite3_column_int64(st, 0);
    rc = sqlite3_step(st); // raw-sql-ok:read-only-introspection
    int finalize_rc = sqlite3_finalize(st);
    if (rc != SQLITE_DONE || finalize_rc != SQLITE_OK) {
        status_set_sqlite_err(err, err_size, db, "integer query result");
        return PKV_READ_ERROR;
    }
    *out = value;
    return PKV_READ_PRESENT;
}

static void status_hex32(const uint8_t bytes[32], char out[65])
{
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < 32; i++) {
        out[i * 2] = hex[bytes[i] >> 4];
        out[i * 2 + 1] = hex[bytes[i] & 0x0f];
    }
    out[64] = '\0';
}

static bool pkv_rate_window_is_current(
    const struct producer_status_read *status,
    const struct cure_progress_sample *older,
    const struct cure_progress_sample *newer)
{
    if (!status || !older || !newer)
        return false;
    int64_t applied_height = status->receipt_finalized
        ? status->fold_cursor - 1
        : status->utxo_apply_cursor > 0
            ? status->utxo_apply_cursor - 1 : -1;
    if (newer->height != applied_height)
        return false;
    if (status->session_open) {
        /* Session start is microseconds while apply rows are whole seconds.
         * Flooring admits the first row written in the same wall-clock second
         * but rejects residual timing evidence from an earlier generation. */
        int64_t start_seconds = status->start_time_us / INT64_C(1000000);
        if (status->start_time_us <= 0 || older->time_unix < start_seconds ||
            newer->time_unix < start_seconds)
            return false;
    }
    return true;
}

#ifdef ZCL_TESTING
bool consensus_state_producer_status_rate_window_current_for_test(
    const struct producer_status_read *status,
    int64_t older_time_unix, int64_t newer_height,
    int64_t newer_time_unix);

bool consensus_state_producer_status_rate_window_current_for_test(
    const struct producer_status_read *status,
    int64_t older_time_unix, int64_t newer_height,
    int64_t newer_time_unix)
{
    const struct cure_progress_sample older = {
        .height = newer_height > 0 ? newer_height - 1 : 0,
        .time_unix = older_time_unix,
    };
    const struct cure_progress_sample newer = {
        .height = newer_height,
        .time_unix = newer_time_unix,
    };
    return pkv_rate_window_is_current(status, &older, &newer);
}
#endif

static bool status_schema_version(const char *schema, bool receipt,
                                  uint8_t *out_version)
{
    if (!schema || !out_version)
        return false;
    if (receipt)
        return consensus_state_source_receipt_schema_version(
            schema, strlen(schema), out_version);
    if (strcmp(schema, "zcl.consensus_state_producer_session.v1") == 0) {
        *out_version = CONSENSUS_STATE_SOURCE_RECEIPT_V1;
        return true;
    }
    if (strcmp(schema, "zcl.consensus_state_producer_session.v2") == 0) {
        *out_version = CONSENSUS_STATE_SOURCE_RECEIPT_V2;
        return true;
    }
    return false;
}

static bool status_copy_blob32(sqlite3_stmt *st, int column, uint8_t out[32])
{
    if (sqlite3_column_type(st, column) != SQLITE_BLOB ||
        sqlite3_column_bytes(st, column) != 32)
        return false;
    const void *blob = sqlite3_column_blob(st, column);
    if (!blob)
        return false;
    memcpy(out, blob, 32);
    return true;
}

/* Column is an INTEGER holding 0 or 1. */
static bool pkv_flag_col_ok(sqlite3_stmt *st, int rc, int column)
{
    return rc == SQLITE_ROW &&
           sqlite3_column_type(st, column) == SQLITE_INTEGER &&
           (sqlite3_column_int(st, column) == 0 ||
            sqlite3_column_int(st, column) == 1);
}

/* Column is an INTEGER naming a known validation profile. */
static bool pkv_profile_col_ok(sqlite3_stmt *st, int rc, int column)
{
    return rc == SQLITE_ROW &&
           sqlite3_column_type(st, column) == SQLITE_INTEGER &&
           (sqlite3_column_int(st, column) ==
                CONSENSUS_STATE_VALIDATION_FULL ||
            sqlite3_column_int(st, column) ==
                CONSENSUS_STATE_VALIDATION_CHECKPOINT_FOLD);
}

static const uint8_t *pkv_blob32_view(sqlite3_stmt *st, int rc, int column)
{
    return rc == SQLITE_ROW &&
           sqlite3_column_type(st, column) == SQLITE_BLOB &&
           sqlite3_column_bytes(st, column) == 32
        ? sqlite3_column_blob(st, column) : NULL;
}

static bool pkv_receipt_schema(sqlite3_stmt *st, int rc,
                               struct consensus_state_source_receipt *receipt,
                               char *schema_copy, size_t schema_cap,
                               int *schema_len)
{
    const unsigned char *schema = rc == SQLITE_ROW &&
        sqlite3_column_type(st, 0) == SQLITE_TEXT
        ? sqlite3_column_text(st, 0) : NULL;
    *schema_len = schema ? sqlite3_column_bytes(st, 0) : -1;
    bool schema_ok = schema && *schema_len > 0 &&
        (size_t)*schema_len < schema_cap &&
        memchr(schema, '\0', (size_t)*schema_len) == NULL &&
        consensus_state_source_receipt_schema_version(
            (const char *)schema, (size_t)*schema_len,
            &receipt->schema_version);
    if (schema_ok) {
        memcpy(schema_copy, schema, (size_t)*schema_len);
        schema_copy[*schema_len] = '\0';
    }
    return schema_ok;
}

static bool pkv_receipt_commit(
    sqlite3_stmt *st, int rc,
    const struct consensus_state_source_receipt *receipt,
    const unsigned char **commit, int *commit_len)
{
    *commit = rc == SQLITE_ROW && sqlite3_column_type(st, 9) == SQLITE_TEXT
        ? sqlite3_column_text(st, 9) : NULL;
    *commit_len = *commit ? sqlite3_column_bytes(st, 9) : -1;
    return *commit && *commit_len >= 0 &&
           (size_t)*commit_len < sizeof(receipt->producer_commit) &&
           memchr(*commit, '\0', (size_t)*commit_len) == NULL &&
           consensus_state_source_receipt_commit_valid(
               receipt->schema_version, (const char *)*commit,
               (size_t)*commit_len);
}

static bool pkv_receipt_scalars_ok(sqlite3_stmt *st, int rc)
{
    return pkv_flag_col_ok(st, rc, 7) && pkv_profile_col_ok(st, rc, 8) &&
           rc == SQLITE_ROW &&
           sqlite3_column_type(st, 10) == SQLITE_INTEGER &&
           sqlite3_column_int64(st, 10) > 0 &&
           sqlite3_column_int64(st, 10) <= INT32_MAX;
}

static bool pkv_receipt_blobs_copy(
    sqlite3_stmt *st, struct consensus_state_source_receipt *receipt)
{
    return status_copy_blob32(st, 1, receipt->source_epoch_digest) &&
           status_copy_blob32(st, 2, receipt->source_tree_root) &&
           status_copy_blob32(st, 3, receipt->running_binary_digest) &&
           status_copy_blob32(st, 4, receipt->toolchain_digest) &&
           status_copy_blob32(st, 5, receipt->build_inputs_digest) &&
           status_copy_blob32(st, 6, receipt->chain_corpus_digest) &&
           status_copy_blob32(st, 11, receipt->receipt_digest);
}

/* Every claim is nonzero, agrees with the session's profile when one is
 * known, and reproduces both the source epoch and the receipt digest. */
static bool pkv_receipt_claims_ok(
    const struct consensus_state_source_receipt *receipt, int session_profile)
{
    if (!(zcl_bytes_any_set(receipt->source_epoch_digest, 32) &&
          zcl_bytes_any_set(receipt->source_tree_root, 32) &&
          zcl_bytes_any_set(receipt->running_binary_digest, 32) &&
          zcl_bytes_any_set(receipt->toolchain_digest, 32) &&
          zcl_bytes_any_set(receipt->build_inputs_digest, 32) &&
          zcl_bytes_any_set(receipt->chain_corpus_digest, 32) &&
          zcl_bytes_any_set(receipt->receipt_digest, 32) &&
          (session_profile < 0 ||
           session_profile == receipt->validation_profile)))
        return false;
    uint8_t recomputed_epoch[32] = {0};
    uint8_t recomputed_receipt[32] = {0};
    consensus_state_source_epoch_digest(receipt, recomputed_epoch);
    consensus_state_source_receipt_digest(receipt, recomputed_receipt);
    return memcmp(recomputed_epoch, receipt->source_epoch_digest, 32) == 0 &&
           memcmp(recomputed_receipt, receipt->receipt_digest, 32) == 0;
}

/* A receipt row is not a finalized receipt merely because `fold_cursor`
 * exists. Parse every authority-bearing field, require the cryptographic
 * claims to be nonzero, and reproduce both the source epoch and complete
 * receipt digest before exposing `receipt_finalized=true`. */
static enum pkv_read_result pkv_read_final_receipt(
    sqlite3 *db, struct producer_status_read *out,
    char *err, size_t err_size)
{
    static const char table[] = "consensus_state_source_receipt";
    static const char sql[] =
        "SELECT schema,source_epoch_digest,source_tree_root,"
        "running_binary_digest,toolchain_digest,build_inputs_digest,"
        "chain_corpus_digest,source_clean,validation_profile,producer_commit,"
        "fold_cursor,receipt_digest FROM consensus_state_source_receipt "
        "WHERE singleton=1";
    bool table_present = false;
    if (!pkv_table_exists(db, table, &table_present, err, err_size))
        return PKV_READ_ERROR;
    if (!table_present)
        return PKV_READ_ABSENT;

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK) {
        status_set_sqlite_err(err, err_size, db,
                              "finalized receipt prepare");
        return PKV_READ_ERROR;
    }
    int rc = sqlite3_step(st); // raw-sql-ok:read-only-introspection
    if (rc == SQLITE_DONE) {
        int finalize_rc = sqlite3_finalize(st);
        if (finalize_rc != SQLITE_OK) {
            status_set_sqlite_err(err, err_size, db,
                                  "finalized receipt finalize");
            return PKV_READ_ERROR;
        }
        return PKV_READ_ABSENT;
    }

    struct consensus_state_source_receipt receipt;
    memset(&receipt, 0, sizeof(receipt));
    char schema_copy[sizeof(out->receipt_schema)] = {0};
    int schema_len = -1;
    bool schema_ok = pkv_receipt_schema(st, rc, &receipt, schema_copy,
                                        sizeof(schema_copy), &schema_len);
    const unsigned char *commit = NULL;
    int commit_len = -1;
    bool commit_ok = pkv_receipt_commit(st, rc, &receipt, &commit,
                                        &commit_len);
    bool fields_ok = schema_ok && commit_ok &&
        pkv_receipt_scalars_ok(st, rc) &&
        pkv_receipt_blobs_copy(st, &receipt);
    if (fields_ok) {
        receipt.source_clean = sqlite3_column_int(st, 7) == 1;
        receipt.validation_profile = (uint8_t)sqlite3_column_int(st, 8);
        memcpy(receipt.producer_commit, commit, (size_t)commit_len);
        receipt.producer_commit[commit_len] = '\0';
        receipt.fold_cursor = sqlite3_column_int64(st, 10);
        fields_ok = pkv_receipt_claims_ok(&receipt, out->validation_profile);
    }
    rc = sqlite3_step(st); // raw-sql-ok:read-only-introspection
    int finalize_rc = sqlite3_finalize(st);
    if (rc != SQLITE_DONE || finalize_rc != SQLITE_OK) {
        status_set_sqlite_err(err, err_size, db,
                              "finalized receipt result");
        return PKV_READ_ERROR;
    }
    if (!fields_ok) {
        status_set_err(err, err_size,
                       "producer status: finalized receipt is malformed or "
                       "fails digest verification");
        return PKV_READ_ERROR;
    }

    memcpy(out->receipt_schema, schema_copy, (size_t)schema_len + 1u);
    status_hex32(receipt.source_tree_root, out->source_tree_root);
    status_hex32(receipt.source_epoch_digest, out->source_epoch_digest);
    memcpy(out->producer_commit, receipt.producer_commit,
           (size_t)commit_len + 1u);
    out->validation_profile = receipt.validation_profile;
    out->fold_cursor = receipt.fold_cursor;
    out->receipt_finalized = true;
    return PKV_READ_PRESENT;
}

/* The open session row's source-claim columns, before any is validated. */
struct pkv_session_row {
    const unsigned char *schema;
    const unsigned char *commit;
    int schema_len;
    int commit_len;
    const uint8_t *root, *epoch, *toolchain, *build_inputs;
    bool clean_ok, profile_ok;
};

static void pkv_session_row_load(sqlite3_stmt *st, int rc,
                                 struct pkv_session_row *row)
{
    row->schema = rc == SQLITE_ROW &&
        sqlite3_column_type(st, 0) == SQLITE_TEXT
        ? sqlite3_column_text(st, 0) : NULL;
    row->schema_len = row->schema ? sqlite3_column_bytes(st, 0) : -1;
    row->root = pkv_blob32_view(st, rc, 1);
    row->epoch = pkv_blob32_view(st, rc, 2);
    row->commit = rc == SQLITE_ROW &&
        sqlite3_column_type(st, 3) == SQLITE_TEXT
        ? sqlite3_column_text(st, 3) : NULL;
    row->commit_len = row->commit ? sqlite3_column_bytes(st, 3) : -1;
    row->toolchain = pkv_blob32_view(st, rc, 4);
    row->build_inputs = pkv_blob32_view(st, rc, 5);
    row->clean_ok = pkv_flag_col_ok(st, rc, 6);
    row->profile_ok = pkv_profile_col_ok(st, rc, 7);
}

static bool pkv_session_blobs_present(const struct pkv_session_row *row)
{
    return row->root && row->epoch && row->toolchain && row->build_inputs &&
           zcl_bytes_any_set(row->root, 32) &&
           zcl_bytes_any_set(row->epoch, 32) &&
           zcl_bytes_any_set(row->toolchain, 32) &&
           zcl_bytes_any_set(row->build_inputs, 32);
}

/* Session schema text is bounded, NUL-free and names a known session schema;
 * returns the receipt-schema version it maps to. */
static bool pkv_session_schema_version(const struct pkv_session_row *row,
                                       const struct producer_status_read *out,
                                       uint8_t *version)
{
    char schema_copy[sizeof(out->receipt_schema)];
    if (!(row->schema && row->schema_len > 0 &&
          (size_t)row->schema_len < sizeof(out->receipt_schema) &&
          memchr(row->schema, '\0', (size_t)row->schema_len) == NULL))
        return false;
    memcpy(schema_copy, row->schema, (size_t)row->schema_len);
    schema_copy[row->schema_len] = '\0';
    return status_schema_version(schema_copy, false, version);
}

/* Builds the bounded source claim from the session row; true when it is
 * complete and its source epoch reproduces. */
static bool pkv_session_claim(sqlite3_stmt *st,
                              const struct pkv_session_row *row,
                              const struct producer_status_read *out,
                              struct consensus_state_source_receipt *claim)
{
    uint8_t version = CONSENSUS_STATE_SOURCE_RECEIPT_INVALID;
    bool schema_ok = pkv_session_schema_version(row, out, &version);
    bool commit_ok = row->commit && row->commit_len >= 0 &&
        (size_t)row->commit_len < sizeof(out->producer_commit) &&
        memchr(row->commit, '\0', (size_t)row->commit_len) == NULL &&
        consensus_state_source_receipt_commit_valid(
            version, (const char *)row->commit, (size_t)row->commit_len);
    memset(claim, 0, sizeof(*claim));
    if (!(schema_ok && row->clean_ok && row->profile_ok && commit_ok &&
          pkv_session_blobs_present(row)))
        return false;
    claim->schema_version = version;
    memcpy(claim->source_tree_root, row->root, 32);
    memcpy(claim->source_epoch_digest, row->epoch, 32);
    memcpy(claim->toolchain_digest, row->toolchain, 32);
    memcpy(claim->build_inputs_digest, row->build_inputs, 32);
    memcpy(claim->producer_commit, row->commit, (size_t)row->commit_len);
    claim->producer_commit[row->commit_len] = '\0';
    claim->source_clean = sqlite3_column_int(st, 6) == 1;
    claim->validation_profile = (uint8_t)sqlite3_column_int(st, 7);
    uint8_t recomputed_epoch[32];
    consensus_state_source_epoch_digest(claim, recomputed_epoch);
    return memcmp(recomputed_epoch, row->epoch, 32) == 0 &&
           (out->validation_profile < 0 ||
            out->validation_profile == claim->validation_profile);
}

static void pkv_session_export(
    struct producer_status_read *out, const struct pkv_session_row *row,
    const struct consensus_state_source_receipt *claim)
{
    memcpy(out->receipt_schema, row->schema, (size_t)row->schema_len);
    out->receipt_schema[row->schema_len] = '\0';
    status_hex32(row->root, out->source_tree_root);
    status_hex32(row->epoch, out->source_epoch_digest);
    memcpy(out->producer_commit, row->commit, (size_t)row->commit_len);
    out->producer_commit[row->commit_len] = '\0';
    out->validation_profile = claim->validation_profile;
}

/* When no finalized receipt exists, expose the open session's bounded source
 * claim. This is progress telemetry only and never sets receipt_finalized. */
static bool pkv_read_session_identity(sqlite3 *db,
                                      struct producer_status_read *out,
                                      char *err, size_t err_size)
{
    static const char table[] = "consensus_state_producer_session";
    static const char sql[] =
        "SELECT schema,source_tree_root,source_epoch_digest,producer_commit,"
        "toolchain_digest,build_inputs_digest,source_clean,validation_profile "
        "FROM consensus_state_producer_session WHERE singleton=1";
    bool table_present = false;
    if (!pkv_table_exists(db, table, &table_present, err, err_size))
        return false;
    if (!table_present)
        return true;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK)
        return status_set_sqlite_err(err, err_size, db,
                                     "source identity prepare");
    int rc = sqlite3_step(st); // raw-sql-ok:read-only-introspection
    if (rc == SQLITE_DONE) {
        int finalize_rc = sqlite3_finalize(st);
        if (finalize_rc != SQLITE_OK)
            return status_set_sqlite_err(err, err_size, db,
                                         "source identity finalize");
        return true;
    }
    struct pkv_session_row row;
    struct consensus_state_source_receipt claim;
    pkv_session_row_load(st, rc, &row);
    if (pkv_session_claim(st, &row, out, &claim)) {
        pkv_session_export(out, &row, &claim);
        rc = sqlite3_step(st); // raw-sql-ok:read-only-introspection
        int finalize_rc = sqlite3_finalize(st);
        if (rc != SQLITE_DONE || finalize_rc != SQLITE_OK)
            return status_set_sqlite_err(err, err_size, db,
                                         "source identity result");
        return true;
    }
    sqlite3_finalize(st);
    return status_set_err(err, err_size,
                          "producer status: source identity is malformed");
}

static void pkv_status_init(struct producer_status_read *out)
{
    memset(out, 0, sizeof(*out));
    out->utxo_apply_cursor = -1;
    out->tip_finalize_cursor = -1;
    out->fold_cursor = -1;
    out->rate_older_height = -1;
    out->rate_older_time_unix = -1;
    out->rate_newer_height = -1;
    out->rate_newer_time_unix = -1;
    out->validation_profile = -1;
}

enum pkv_open_result {
    PKV_OPEN_FAILED,
    PKV_OPEN_ABSENT,
    PKV_OPEN_READY,
};

/* Opens the kernel store read-only. A missing store is a successful absent
 * status; every other failure fills `err`. */
static enum pkv_open_result pkv_open_store(const char *datadir,
                                           struct producer_status_read *out,
                                           sqlite3 **db_out,
                                           char *err, size_t err_size)
{
    if (!datadir || !datadir[0]) {
        status_set_err(err, err_size, "producer status: empty datadir");
        return PKV_OPEN_FAILED;
    }
    if (strlen(datadir) >= CONSENSUS_STATE_PRODUCER_DATADIR_MAX) {
        status_set_err(err, err_size,
                       "producer status: datadir exceeds 1023 bytes");
        return PKV_OPEN_FAILED;
    }

    /* A4: read the kernel store — consensus.db post-flip, or the legacy
     * progress.kv on a pre-flip producer datadir. */
    char path[CONSENSUS_STATE_PRODUCER_DATADIR_MAX +
              sizeof("/consensus.db")];
    if (!consensus_db_kernel_store_path(datadir, path, sizeof(path))) {
        status_set_err(err, err_size,
                       "producer status: kernel store path overflow");
        return PKV_OPEN_FAILED;
    }
    struct stat stbuf;
    if (stat(path, &stbuf) != 0) {
        if (errno != ENOENT) {
            char why[1400];
            snprintf(why, sizeof(why), "producer status: stat %s: %s", path,
                     strerror(errno));
            status_set_err(err, err_size, why);
            return PKV_OPEN_FAILED;
        }
        out->progress_kv_present = false;
        return PKV_OPEN_ABSENT;
    }
    if (!S_ISREG(stbuf.st_mode)) {
        status_set_err(err, err_size,
                       "producer status: kernel store is not regular");
        return PKV_OPEN_FAILED;
    }

    sqlite3 *db = NULL;
    if (sqlite3_open_v2(path, &db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) {
        const char *message = db ? sqlite3_errmsg(db) : "open failed";
        char why[1400];
        snprintf(why, sizeof(why), "producer status: open %s: %s", path,
                 message);
        if (db)
            sqlite3_close(db);
        status_set_err(err, err_size, why);
        return PKV_OPEN_FAILED;
    }
    out->progress_kv_present = true;
    *db_out = db;
    return PKV_OPEN_READY;
}

/* One stage cursor: absent leaves *dest alone, present must be a
 * non-negative int32. */
static bool pkv_read_cursor(sqlite3 *db, const char *sql,
                            const char *malformed, int64_t *dest,
                            char *err, size_t err_size)
{
    int64_t value = 0;
    enum pkv_read_result read_result = pkv_query_i64(
        db, "stage_cursor", sql, &value, err, err_size);
    if (read_result == PKV_READ_ERROR)
        return false;
    if (read_result == PKV_READ_PRESENT) {
        if (value < 0 || value > INT32_MAX) {
            status_set_err(err, err_size, malformed);
            return false;
        }
        *dest = value;
    }
    return true;
}

static bool pkv_read_cursors(sqlite3 *db, struct producer_status_read *out,
                             char *err, size_t err_size)
{
    if (!pkv_read_cursor(
            db, "SELECT cursor FROM stage_cursor WHERE name='utxo_apply'",
            "producer status: utxo_apply cursor is malformed",
            &out->utxo_apply_cursor, err, err_size))
        return false;
#ifdef ZCL_TESTING
    if (g_status_after_first_cursor_hook)
        g_status_after_first_cursor_hook(g_status_after_first_cursor_ctx);
#endif
    return pkv_read_cursor(
        db, "SELECT cursor FROM stage_cursor WHERE name='tip_finalize'",
        "producer status: tip_finalize cursor is malformed",
        &out->tip_finalize_cursor, err, err_size);
}

static bool pkv_read_session(sqlite3 *db, struct producer_status_read *out,
                             char *err, size_t err_size)
{
    int64_t value = 0;
    enum pkv_read_result read_result = pkv_query_i64(
            db, "consensus_state_producer_session",
            "SELECT start_time_us FROM consensus_state_producer_session "
                "WHERE singleton=1", &value, err, err_size);
    if (read_result == PKV_READ_ERROR)
        return false;
    if (read_result == PKV_READ_PRESENT) {
        if (value <= 0) {
            status_set_err(err, err_size,
                           "producer status: session start time is malformed");
            return false;
        }
        out->session_open = true;
        out->start_time_us = value;
    }
    read_result = pkv_query_i64(
            db, "consensus_state_producer_session",
            "SELECT validation_profile "
                "FROM consensus_state_producer_session WHERE singleton=1",
            &value, err, err_size);
    if (read_result == PKV_READ_ERROR)
        return false;
    if (read_result == PKV_READ_PRESENT) {
        if (value != CONSENSUS_STATE_VALIDATION_FULL &&
            value != CONSENSUS_STATE_VALIDATION_CHECKPOINT_FOLD) {
            status_set_err(err, err_size,
                           "producer status: validation profile is malformed");
            return false;
        }
        out->validation_profile = (int)value;
    }
    return true;
}

static bool pkv_read_identity(sqlite3 *db, struct producer_status_read *out,
                              char *err, size_t err_size)
{
    enum pkv_read_result read_result =
        pkv_read_final_receipt(db, out, err, err_size);
    if (read_result == PKV_READ_ERROR)
        return false;
    return read_result != PKV_READ_ABSENT ||
           pkv_read_session_identity(db, out, err, err_size);
}

/* Publishes the durable rate window when the two samples describe the
 * current producer's frontier and span at least 60 seconds. */
static bool pkv_rate_publish(struct producer_status_read *out,
                             const struct cure_progress_sample *older,
                             const struct cure_progress_sample *newer,
                             char *err, size_t err_size)
{
    int64_t blocks = newer->height - older->height;
    int64_t seconds = newer->time_unix - older->time_unix;
    if (blocks <= 0 || seconds < 60 || blocks > INT64_MAX / 1000) {
        status_set_err(err, err_size,
                       "producer status: durable rate samples are malformed");
        return false;
    }
    /* Residual rows above/below the current durable frontier are not
     * evidence of the active producer's rate.  Rows predating the
     * open producer session are likewise from a prior generation.
     * Preserve status, but never expose an ETA from either. */
    if (!pkv_rate_window_is_current(out, older, newer))
        return true;
    out->durable_rate_available = true;
    out->rate_older_height = older->height;
    out->rate_older_time_unix = older->time_unix;
    out->rate_newer_height = newer->height;
    out->rate_newer_time_unix = newer->time_unix;
    out->rate_blocks_per_second_milli = blocks * 1000 / seconds;
    if (out->rate_blocks_per_second_milli <= 0) {
        status_set_err(err, err_size,
                       "producer status: durable rate rounds to zero");
        return false;
    }
    return true;
}

static bool pkv_read_rate(sqlite3 *db, struct producer_status_read *out,
                          char *err, size_t err_size)
{
    bool apply_log_present = false;
    if (!pkv_table_exists(db, "utxo_apply_log", &apply_log_present,
                          err, err_size))
        return false;
    if (!apply_log_present)
        return true;
    struct cure_progress_sample older, newer;
    int samples = cure_progress_read_eta_samples(db, 60, &older, &newer);
    if (samples < 0) {
        status_set_sqlite_err(err, err_size, db, "read durable rate samples");
        return false;
    }
    if (samples != 1)
        return true;
    return pkv_rate_publish(out, &older, &newer, err, err_size);
}

bool consensus_state_producer_status_read(const char *datadir,
                                          struct producer_status_read *out,
                                          char *err, size_t err_size)
{
    if (!out)
        return status_set_err(err, err_size, "producer status: null out");
    pkv_status_init(out);
    sqlite3 *db = NULL;
    enum pkv_open_result opened =
        pkv_open_store(datadir, out, &db, err, err_size);
    if (opened == PKV_OPEN_FAILED)
        return false;
    if (opened == PKV_OPEN_ABSENT)
        return true;
    bool read_tx_open = false;
    if (!pkv_read_transaction(db, "BEGIN DEFERRED",
                              "begin read snapshot", err, err_size))
        goto fail;
    read_tx_open = true;
    if (!pkv_read_cursors(db, out, err, err_size) ||
        !pkv_read_session(db, out, err, err_size) ||
        !pkv_read_identity(db, out, err, err_size) ||
        !pkv_read_rate(db, out, err, err_size))
        goto fail;
    if (!pkv_read_transaction(db, "COMMIT", "commit read snapshot",
                              err, err_size))
        goto fail;
    read_tx_open = false;
    if (sqlite3_close(db) != SQLITE_OK)
        return status_set_err(err, err_size,
                              "producer status: close progress.kv failed");
    return true;

fail:
    if (read_tx_open) {
        (void)sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL); // raw-sql-ok:read-only-introspection
    }
    sqlite3_close(db);
    return false;
}
