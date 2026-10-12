/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Reducer-stage + header-chain row-scan proofs for the
 * zcl.consensus_state_bundle.v1 export gate. Split out of
 * consensus_state_snapshot_export_proof.c along the file-size ceiling seam
 * (E1, docs/DEFENSIVE_CODING.md): these two functions are the O(H)-row scans
 * (up to ~3.1M rows on a full-history datadir) that consensus_export_
 * prove_source (still in _proof.c) orchestrates alongside its own fast,
 * non-scanning checks. Both emit "[export] ..." start/progress/done markers
 * via consensus_export_progress_emit (observability only — never touches gate
 * semantics) so the otherwise-silent 30-60+ minute -export-consensus-bundle
 * prove path is never quiet for more than ~500k rows at a time. */

#include "consensus_state_snapshot_export_internal.h"
#include "consensus_state_proof_prefix.h"

#include "crypto/sha3.h"
#include "util/log_macros.h"

#include <stdio.h>
#include <string.h>

#define EXPORT_PROOF_SUBSYS "consensus_bundle_export"

const struct export_stage_proof k_stages[CONSENSUS_EXPORT_STAGE_COUNT] = {
    {"validate_headers", "validate_headers_log", false, "hash", false, false},
    {"body_fetch", "body_fetch_log", false, "hash", false, false},
    {"body_persist", "body_persist_log", false, NULL, false, false},
    {"script_validate", "script_validate_log", false, "block_hash", true, true},
    {"proof_validate", "proof_validate_log", false, "block_hash", true, true},
    {"utxo_apply", "utxo_apply_log", false, "branch_hash", true, false},
    {"tip_finalize", "tip_finalize_log", true, NULL, false, false},
};

static void proof_u64(struct sha3_256_ctx *ctx, uint64_t value)
{
    uint8_t le[8];
    for (size_t i = 0; i < sizeof(le); i++)
        le[i] = (uint8_t)(value >> (8u * i));
    sha3_256_write(ctx, le, sizeof(le));
}

bool consensus_export_prove_header_chain(sqlite3 *db, int32_t height,
                                         const uint8_t expected_hash[32],
                                         uint8_t source_digest[32],
                                         struct consensus_state_bundle_proof_parent
                                             *parent)
{
    int64_t t0 = consensus_export_clock_ms();
    consensus_export_progress_emit(
        "prove_header_chain start height=%d rows=%lld", height,
        (long long)height + 1);
    bool ok = consensus_state_proof_header_digest(
        db, height, expected_hash, source_digest, parent);
    consensus_export_progress_emit(
        "prove_header_chain done height=%d ok=%d elapsed=%lldms", height,
        ok ? 1 : 0,
        (long long)(consensus_export_clock_ms() - t0));
    return ok;
}

/* The proof parent must sit strictly below this stage's tip, under the same
 * validation profile. */
static bool stage_parent_boundary_ok(
    const struct consensus_state_bundle_proof_parent *parent, size_t ordinal,
    int32_t height, uint8_t validation_profile,
    const struct export_stage_proof *stage)
{
    if (ordinal == 0 || ordinal >= CONSENSUS_STATE_BUNDLE_PROOF_COUNT ||
        height <= parent->base_height ||
        parent->validation_profile != validation_profile) {
        LOG_WARN(EXPORT_PROOF_SUBSYS,
                 "stage proof parent boundary/profile mismatch stage=%s",
                 stage->name);
        return false;
    }
    return true;
}

static bool stage_bind_range(sqlite3_stmt *st, int64_t first_height,
                             int32_t height)
{
    return sqlite3_bind_int64(st, 1, first_height) == SQLITE_OK &&
           sqlite3_bind_int(st, 2, height) == SQLITE_OK;
}

/* Prepares the ordered row scan over [first_height, height]. */
static bool stage_rows_open(sqlite3 *db, const struct export_stage_proof *stage,
                            int64_t first_height, int32_t height,
                            sqlite3_stmt **st)
{
    char sql[384];
    const char *columns = stage->source_epoch_bound
        ? "height,ok,status,source_epoch_digest"
        : stage->profile_bound ? "height,ok,status" : "height,ok";
    int n = snprintf(
        sql, sizeof(sql), "SELECT %s FROM %s "
        "WHERE height BETWEEN ? AND ? ORDER BY height", columns,
        stage->table);
    if (n <= 0 || (size_t)n >= sizeof(sql))
        LOG_FAIL(EXPORT_PROOF_SUBSYS, "stage proof SQL overflow");
    *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, st, NULL) != SQLITE_OK) {
        LOG_WARN(EXPORT_PROOF_SUBSYS, "stage proof missing table=%s: %s",
                 stage->table, sqlite3_errmsg(db));
        return false;
    }
    if (!stage_bind_range(*st, first_height, height)) {
        sqlite3_finalize(*st);
        LOG_WARN(EXPORT_PROOF_SUBSYS, "stage proof bind failed stage=%s",
                 stage->name);
        return false;
    }
    return true;
}

static void stage_summary_init(struct consensus_state_bundle_proof_summary *s,
                               const struct export_stage_proof *stage,
                               uint64_t cursor, int32_t height)
{
    memset(s, 0, sizeof(*s));
    snprintf(s->component, sizeof(s->component), "%s", stage->name);
    s->cursor = cursor;
    s->first_height = 0;
    s->last_height = height;
    s->row_count = (uint64_t)height + 1;
}

/* Starts the component digest: domain, optional parent boundary, stage name,
 * cursor and the source epoch when the stage rows are bound to it. */
static void stage_component_begin(
    struct sha3_256_ctx *component, const struct export_stage_proof *stage,
    const struct consensus_state_bundle_proof_parent *parent, bool composed,
    int32_t height, uint64_t cursor, const uint8_t source_epoch_digest[32])
{
    static const char full_domain[] =
        "zcl.consensus_state_bundle.v1/proof-component";
    static const char suffix_domain[] =
        "zcl.consensus_state_bundle.v1/proof-extension-suffix/component";
    sha3_256_init(component);
    const char *domain = composed ? suffix_domain : full_domain;
    size_t domain_len = composed ? sizeof(suffix_domain) : sizeof(full_domain);
    sha3_256_write(component, (const uint8_t *)domain, domain_len);
    if (composed) {
        proof_u64(component, (uint64_t)parent->base_height);
        proof_u64(component, (uint64_t)height);
        sha3_256_write(component, parent->base_block_hash, 32);
    }
    proof_u64(component, (uint64_t)strlen(stage->name));
    sha3_256_write(component, (const uint8_t *)stage->name,
                   strlen(stage->name));
    proof_u64(component, cursor);
    if (stage->source_epoch_bound)
        sha3_256_write(component, source_epoch_digest, 32);
}

static bool stage_status_ok(sqlite3_stmt *st,
                            const struct export_stage_proof *stage,
                            const char *required_status,
                            size_t required_status_len)
{
    if (!stage->profile_bound)
        return true;
    int status_type = sqlite3_column_type(st, 2);
    const unsigned char *status = status_type == SQLITE_TEXT
                                      ? sqlite3_column_text(st, 2) : NULL;
    return status_type == SQLITE_TEXT && status &&
           sqlite3_column_bytes(st, 2) == (int)required_status_len &&
           memcmp(status, required_status, required_status_len) == 0;
}

static bool stage_epoch_ok(sqlite3_stmt *st,
                           const struct export_stage_proof *stage,
                           const uint8_t source_epoch_digest[32])
{
    if (!stage->source_epoch_bound)
        return true;
    int epoch_type = sqlite3_column_type(st, 3);
    const void *row_epoch = epoch_type == SQLITE_BLOB
                                ? sqlite3_column_blob(st, 3) : NULL;
    return epoch_type == SQLITE_BLOB && row_epoch &&
           sqlite3_column_bytes(st, 3) == 32 &&
           memcmp(row_epoch, source_epoch_digest, 32) == 0;
}

/* One accepted stage row: consecutive height, ok=1, the profile's status and
 * the source epoch when bound. *row_height receives the stored height (-1 when
 * not an integer). */
static bool stage_row_ok(sqlite3_stmt *st,
                         const struct export_stage_proof *stage,
                         const char *required_status,
                         size_t required_status_len,
                         const uint8_t source_epoch_digest[32],
                         int64_t expected_height, int64_t *row_height)
{
    int height_type = sqlite3_column_type(st, 0);
    int verdict_type = sqlite3_column_type(st, 1);
    *row_height = height_type == SQLITE_INTEGER
        ? sqlite3_column_int64(st, 0) : -1;
    int verdict = verdict_type == SQLITE_INTEGER
        ? sqlite3_column_int(st, 1) : -1;
    return height_type == SQLITE_INTEGER && verdict_type == SQLITE_INTEGER &&
           *row_height == expected_height && verdict == 1 &&
           stage_status_ok(st, stage, required_status, required_status_len) &&
           stage_epoch_ok(st, stage, source_epoch_digest);
}

/* Folds every stage row into the component digest. True only when the rows
 * form a complete ok=1 prefix ending at `height`; *expected_height ends at the
 * next unread height and *fail_height names the first rejected row. */
static bool stage_scan_rows(sqlite3_stmt *st,
                            const struct export_stage_proof *stage,
                            uint8_t validation_profile,
                            const uint8_t source_epoch_digest[32],
                            int32_t height, int64_t t0,
                            struct sha3_256_ctx *component,
                            int64_t *expected_height, int64_t *fail_height)
{
    bool ok = true;
    int rc;
    const char *required_status =
        validation_profile == CONSENSUS_STATE_VALIDATION_FULL
            ? "verified" : "checkpoint_fold";
    size_t required_status_len = strlen(required_status);
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) { // raw-sql-ok:progress-kv-kernel-store
        int64_t row_height;
        if (!stage_row_ok(st, stage, required_status, required_status_len,
                          source_epoch_digest, *expected_height,
                          &row_height)) {
            ok = false;
            *fail_height = row_height;
            break;
        }
        proof_u64(component, (uint64_t)row_height);
        uint8_t accepted = 1;
        sha3_256_write(component, &accepted, 1);
        if (stage->profile_bound) {
            proof_u64(component, (uint64_t)required_status_len);
            sha3_256_write(component, (const uint8_t *)required_status,
                           required_status_len);
        }
        (*expected_height)++;
        if (*expected_height % 500000 == 0)
            consensus_export_progress_emit(
                "prove_stage_rows(%s): %lld/%lld rows, %llds elapsed",
                stage->name, (long long)*expected_height,
                (long long)height + 1,
                (long long)((consensus_export_clock_ms() - t0) / 1000));
    }
    if (rc != SQLITE_DONE || *expected_height != (int64_t)height + 1)
        ok = false;
    return ok;
}

/* Finishes the component digest; a composed proof commits the suffix and
 * derives the full digest from the parent lineage. */
static bool stage_digest_finalize(
    struct sha3_256_ctx *component,
    struct consensus_state_bundle_proof_parent *parent, bool composed,
    size_t ordinal, struct consensus_state_bundle_proof_summary *summary)
{
    if (!composed) {
        sha3_256_finalize(component, summary->component_digest);
        return true;
    }
    sha3_256_finalize(component, parent->suffix_digest[ordinal]);
    return consensus_state_bundle_proof_extension_digest(
        parent, ordinal, summary->component_digest);
}

enum stage_hash_check {
    STAGE_HASH_ABORT,
    STAGE_HASH_MISMATCH,
    STAGE_HASH_BOUND,
};

/* Counts the stage rows whose hash column joins to header_admit_log; every
 * row in the range must bind. */
static enum stage_hash_check stage_hash_bound(
    sqlite3 *db, const struct export_stage_proof *stage,
    int64_t first_height, int32_t height)
{
    char sql[384];
    int n;
    if (strcmp(stage->name, "utxo_apply") == 0) {
        n = snprintf(sql, sizeof(sql),
                     "SELECT COUNT(*) FROM utxo_apply_log s "
                     "JOIN utxo_apply_delta d ON d.height=s.height "
                     "JOIN header_admit_log h ON h.height=s.height "
                     "AND h.hash=d.branch_hash "
                     "WHERE s.height BETWEEN ? AND ? "
                     "AND typeof(s.ok)='integer' AND s.ok=1 "
                     "AND typeof(d.branch_hash)='blob' "
                     "AND length(d.branch_hash)=32");
    } else {
        n = snprintf(sql, sizeof(sql),
                     "SELECT COUNT(*) FROM %s s JOIN header_admit_log h "
                     "ON h.height=s.height AND h.hash=s.%s "
                     "WHERE s.height BETWEEN ? AND ? "
                     "AND typeof(s.ok)='integer' AND s.ok=1 "
                     "AND typeof(s.%s)='blob' AND length(s.%s)=32",
                     stage->table, stage->hash_column, stage->hash_column,
                     stage->hash_column);
    }
    if (n <= 0 || (size_t)n >= sizeof(sql)) {
        ZCL_LOG_ERROR_ORIGIN(EXPORT_PROOF_SUBSYS, "stage hash SQL overflow");
        return STAGE_HASH_ABORT;
    }
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK) {
        LOG_WARN(EXPORT_PROOF_SUBSYS, "stage hash proof prepare failed: %s",
                 sqlite3_errmsg(db));
        return STAGE_HASH_ABORT;
    }
    if (!stage_bind_range(st, first_height, height)) {
        sqlite3_finalize(st);
        LOG_WARN(EXPORT_PROOF_SUBSYS, "stage hash bind failed stage=%s",
                 stage->name);
        return STAGE_HASH_ABORT;
    }
    int rc = sqlite3_step(st); // raw-sql-ok:progress-kv-kernel-store
    int count_type = rc == SQLITE_ROW ? sqlite3_column_type(st, 0) : SQLITE_NULL;
    int64_t hash_bound_count = rc == SQLITE_ROW && count_type == SQLITE_INTEGER
        ? sqlite3_column_int64(st, 0) : -1;
    bool ok = rc == SQLITE_ROW && count_type == SQLITE_INTEGER &&
              hash_bound_count == (int64_t)height - first_height + 1;
    if (ok)
        ok = sqlite3_step(st) == SQLITE_DONE; // raw-sql-ok:progress-kv-kernel-store
    sqlite3_finalize(st);
    if (!ok)
        LOG_WARN(EXPORT_PROOF_SUBSYS,
                 "stage rows are not bound to header hashes table=%s "
                 "hash_bound_count=%lld required=%lld",
                 stage->table, (long long)hash_bound_count,
                 (long long)height - first_height + 1);
    return ok ? STAGE_HASH_BOUND : STAGE_HASH_MISMATCH;
}

bool consensus_export_prove_stage_rows(
    sqlite3 *db, const struct export_stage_proof *stage, int32_t height,
    uint64_t cursor, uint8_t validation_profile,
    const uint8_t source_epoch_digest[32],
    struct consensus_state_bundle_proof_summary *summary,
    struct consensus_state_bundle_proof_parent *parent, size_t ordinal)
{
    int64_t t0 = consensus_export_clock_ms();
    consensus_export_progress_emit(
        "prove_stage_rows(%s) start height=%d rows=%lld cursor=%llu",
        stage->name, height, (long long)height + 1,
        (unsigned long long)cursor);
    bool composed = parent && parent->present;
    int64_t first_height = composed ? (int64_t)parent->base_height + 1 : 0;
    if (composed && !stage_parent_boundary_ok(parent, ordinal, height,
                                              validation_profile, stage))
        return false;
    sqlite3_stmt *st = NULL;
    if (!stage_rows_open(db, stage, first_height, height, &st))
        return false;
    stage_summary_init(summary, stage, cursor, height);
    struct sha3_256_ctx component;
    stage_component_begin(&component, stage, parent, composed, height, cursor,
                          source_epoch_digest);
    int64_t expected_height = first_height;
    int64_t fail_height = -1;
    bool ok = stage_scan_rows(st, stage, validation_profile,
                              source_epoch_digest, height, t0, &component,
                              &expected_height, &fail_height);
    sqlite3_finalize(st);
    if (!ok) {
        LOG_WARN(EXPORT_PROOF_SUBSYS,
                 "stage proof is not a complete profile-bound ok=1 prefix "
                 "table=%s rows_read=%lld required=%lld fail_height=%lld "
                 "profile=%u",
                 stage->table, (long long)(expected_height - first_height),
                 (long long)height - first_height + 1,
                 (long long)fail_height,
                 (unsigned)validation_profile);
        consensus_export_progress_emit(
            "prove_stage_rows(%s) done rows=%lld ok=0 elapsed=%lldms",
            stage->name, (long long)(expected_height - first_height),
            (long long)(consensus_export_clock_ms() - t0));
        return false;
    }

    if (!stage->hash_column) {
        proof_u64(&component, 0);
        if (!stage_digest_finalize(&component, parent, composed, ordinal,
                                   summary))
            return false;
        consensus_export_progress_emit(
            "prove_stage_rows(%s) done rows=%lld ok=1 elapsed=%lldms",
            stage->name, (long long)expected_height,
            (long long)(consensus_export_clock_ms() - t0));
        return true;
    }
    enum stage_hash_check bound =
        stage_hash_bound(db, stage, first_height, height);
    if (bound == STAGE_HASH_ABORT)
        return false;
    ok = bound == STAGE_HASH_BOUND;
    if (ok) {
        summary->hash_bound_count = (uint64_t)height + 1;
        proof_u64(&component, summary->hash_bound_count);
        ok = stage_digest_finalize(&component, parent, composed, ordinal,
                                   summary);
    }
    consensus_export_progress_emit(
        "prove_stage_rows(%s) done rows=%lld ok=%d elapsed=%lldms",
        stage->name, (long long)expected_height, ok ? 1 : 0,
        (long long)(consensus_export_clock_ms() - t0));
    return ok;
}
