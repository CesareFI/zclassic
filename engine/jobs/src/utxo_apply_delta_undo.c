/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * utxo_apply_delta_undo — see jobs/utxo_apply_delta_undo.h.
 *
 * spent_blob layout (written by utxo_apply_delta.c serialize_spent, one entry
 * per transparent input in block order):
 *   32 txid | u32 vout | i64 value | u32 height | u8 coinbase |
 *   u32 script_len | script_len bytes  (all little-endian)
 */

// one-result-type-ok:typed-undo-load-status — the loader's one result is
// enum utxo_apply_delta_undo_status; every non-FOUND branch that is not a
// plain "no row" logs its context before returning.

#include "jobs/utxo_apply_delta_undo.h"

#include "base/serialize_le.h"
#include "coins/undo.h"
#include "core/amount.h"
#include "jobs/stage_helpers.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "script/script.h"
#include "util/log_macros.h"

#include <string.h>

#define UNDO_TAG "utxo_apply_undo"

const char *utxo_apply_delta_undo_status_name(
    enum utxo_apply_delta_undo_status status)
{
    switch (status) {
    case UTXO_DELTA_UNDO_FOUND:        return "found";
    case UTXO_DELTA_UNDO_ABSENT:       return "absent";
    case UTXO_DELTA_UNDO_OTHER_BRANCH: return "other_branch";
    case UTXO_DELTA_UNDO_MISMATCH:     return "mismatch";
    case UTXO_DELTA_UNDO_ERROR:        return "error";
    }
    return "unknown";
}

struct spent_cursor {
    const uint8_t *p;
    const uint8_t *end;
};

/* A one-byte, never-dereferenced sentinel: `c->p == c->end == NULL` (an
 * empty blob whose row gave back a NULL pointer) would otherwise subtract
 * two null pointers to measure the remaining length, which is undefined
 * pointer arithmetic even though both operands agree. Rebasing a null
 * cursor onto this sentinel keeps `end - p` a same-object subtraction. */
static const uint8_t g_empty_cursor_sentinel;

static bool take_bytes(struct spent_cursor *c, void *dst, size_t n)
{
    const uint8_t *p = c->p ? c->p : &g_empty_cursor_sentinel;
    const uint8_t *end = c->end ? c->end : &g_empty_cursor_sentinel;
    if ((size_t)(end - p) < n)
        return false; // raw-return-ok:truncation-reported-by-caller-as-mismatch
    if (dst)
        memcpy(dst, p, n);
    c->p = p + n;
    return true;
}

static bool take_u32(struct spent_cursor *c, uint32_t *out)
{
    uint8_t b[4];
    if (!take_bytes(c, b, sizeof(b)))
        return false; // raw-return-ok:truncation-reported-by-caller-as-mismatch
    *out = zcl_read_u32_le(b);
    return true;
}

static bool take_i64(struct spent_cursor *c, int64_t *out)
{
    uint8_t b[8];
    if (!take_bytes(c, b, sizeof(b)))
        return false; // raw-return-ok:truncation-reported-by-caller-as-mismatch
    *out = zcl_read_i64_le(b);
    return true;
}

/* A decoded value outside consensus range, or a coinbase byte that is
 * neither the encoder's 0 nor 1, is a corrupt local row, not a fact about
 * the chain — fail closed to MISMATCH (the caller reports it, the fold
 * re-derives it), never let it read as a valid-but-wrong undo entry. */
static bool spent_value_and_coinbase_ok(int64_t value, uint8_t coinbase)
{
    return MoneyRange(value) && (coinbase == 0 || coinbase == 1);
}

/* Does this entry name `prevout` and fit within the cursor's remaining
 * bytes? Split out of take_spent_for to stay under the complexity cap. */
static bool spent_entry_shape_ok(const struct spent_cursor *c,
                                 const struct outpoint *prevout,
                                 const uint8_t txid[32], uint32_t vout,
                                 uint32_t script_len)
{
    return memcmp(txid, prevout->hash.data, 32) == 0 &&
           vout == prevout->n && script_len <= MAX_SCRIPT_SIZE &&
           (size_t)(c->end - c->p) >= script_len;
}

/* Parse the next spent entry and require it to name `prevout`. */
static bool take_spent_for(struct spent_cursor *c,
                           const struct outpoint *prevout,
                           struct tx_in_undo *dst)
{
    uint8_t txid[32];
    uint32_t vout = 0, height = 0, script_len = 0;
    int64_t value = 0;
    uint8_t coinbase = 0;
    if (!take_bytes(c, txid, sizeof(txid)) || !take_u32(c, &vout) ||
        !take_i64(c, &value) || !take_u32(c, &height) ||
        !take_bytes(c, &coinbase, 1) || !take_u32(c, &script_len))
        return false; // raw-return-ok:truncation-reported-by-caller-as-mismatch
    if (!spent_entry_shape_ok(c, prevout, txid, vout, script_len) ||
        !spent_value_and_coinbase_ok(value, coinbase))
        return false; // raw-return-ok:shape-reported-by-caller-as-mismatch
    tx_in_undo_init(dst);
    dst->txout.value = value;
    dst->txout.script_pub_key.size = script_len;
    if (script_len)
        memcpy(dst->txout.script_pub_key.data, c->p, script_len);
    c->p += script_len;
    dst->height = height;
    dst->coinbase = coinbase != 0;
    return true;
}

/* Fill `out` from the row's spent blob. MISMATCH unless the blob names exactly
 * the block's transparent prevouts, in order, and nothing else. */
static enum utxo_apply_delta_undo_status build_undo(
    int height, const struct block *blk, const uint8_t *spent, size_t len,
    struct block_undo *out)
{
    /* spent may be NULL when the row's blob is empty (a block with no
     * transparent inputs to undo). Never form `NULL + len`: even `+0` on a
     * null base is undefined pointer arithmetic. Collapse to a null,
     * zero-width cursor instead — take_bytes/take_spent_for already treat
     * p == end as "nothing left", so an empty block still resolves FOUND. */
    struct spent_cursor c = spent
        ? (struct spent_cursor){ .p = spent, .end = spent + len }
        : (struct spent_cursor){ .p = NULL, .end = NULL };
    size_t first = (blk->num_vtx > 0 &&
                    transaction_is_coinbase(&blk->vtx[0])) ? 1 : 0;
    size_t ntx = blk->num_vtx - first;
    if (!block_undo_alloc(out, ntx)) {
        LOG_WARN(UNDO_TAG, "[utxo_apply_undo] h=%d alloc %zu tx undo failed",
                 height, ntx);
        return UTXO_DELTA_UNDO_ERROR;
    }
    for (size_t i = first; i < blk->num_vtx; i++) {
        const struct transaction *tx = &blk->vtx[i];
        struct tx_undo *tu = &out->vtxundo[i - first];
        if (transaction_is_coinbase(tx)) {
            LOG_WARN(UNDO_TAG, "[utxo_apply_undo] h=%d tx %zu is a second "
                     "coinbase; delta cannot describe it", height, i);
            block_undo_free(out);
            return UTXO_DELTA_UNDO_MISMATCH;
        }
        if (!tx_undo_alloc(tu, tx->num_vin)) {
            LOG_WARN(UNDO_TAG, "[utxo_apply_undo] h=%d tx %zu alloc %zu "
                     "prevouts failed", height, i, tx->num_vin);
            block_undo_free(out);
            return UTXO_DELTA_UNDO_ERROR;
        }
        for (size_t j = 0; j < tx->num_vin; j++) {
            if (!take_spent_for(&c, &tx->vin[j].prevout, &tu->vprevout[j])) {
                LOG_WARN(UNDO_TAG, "[utxo_apply_undo] h=%d tx %zu vin %zu: "
                         "delta entry missing, truncated or names another "
                         "outpoint", height, i, j);
                block_undo_free(out);
                return UTXO_DELTA_UNDO_MISMATCH;
            }
        }
    }
    if (c.p != c.end) {
        LOG_WARN(UNDO_TAG, "[utxo_apply_undo] h=%d delta carries %zu bytes "
                 "beyond the block's inputs", height,
                 (size_t)(c.end - c.p));
        block_undo_free(out);
        return UTXO_DELTA_UNDO_MISMATCH;
    }
    return UTXO_DELTA_UNDO_FOUND;
}

/* Classify the stepped row (rc from sqlite3_step) and, for this block's own
 * row, rebuild its undo. */
static enum utxo_apply_delta_undo_status classify_row(
    sqlite3 *db, sqlite3_stmt *st, int rc, int height,
    const struct uint256 *block_hash, const struct block *blk,
    struct block_undo *out)
{
    if (rc == SQLITE_DONE)
        return UTXO_DELTA_UNDO_ABSENT;
    if (rc != SQLITE_ROW) {
        LOG_WARN(UNDO_TAG, "[utxo_apply_undo] h=%d step rc=%d: %s",
                 height, rc, sqlite3_errmsg(db));
        return UTXO_DELTA_UNDO_ERROR;
    }
    if (sqlite3_column_type(st, 0) != SQLITE_BLOB ||
        sqlite3_column_bytes(st, 0) != 32 ||
        memcmp(sqlite3_column_blob(st, 0), block_hash->data, 32) != 0)
        return UTXO_DELTA_UNDO_OTHER_BRANCH;
    const uint8_t *spent = sqlite3_column_blob(st, 1);
    int spent_len = sqlite3_column_bytes(st, 1);
    return build_undo(height, blk, spent,
                      spent && spent_len > 0 ? (size_t)spent_len : 0, out);
}

enum utxo_apply_delta_undo_status utxo_apply_delta_block_undo_load(
    sqlite3 *db, int height, const struct uint256 *block_hash,
    const struct block *blk, struct block_undo *out)
{
    if (out)
        block_undo_init(out);
    if (!db || !block_hash || !blk || !out || height < 0) {
        LOG_WARN(UNDO_TAG, "[utxo_apply_undo] invalid arguments h=%d", height);
        return UTXO_DELTA_UNDO_ERROR;
    }

    sqlite3_stmt *st = NULL;
    int rc = sqlite3_prepare_v2(db,
        "SELECT branch_hash, spent_blob FROM utxo_apply_delta WHERE height = ?",
        -1, &st, NULL);
    if (rc != SQLITE_OK) {
        /* A store the reducer never folded into has no delta table: that is
         * "no undo here", not an unknown answer. */
        const char *msg = sqlite3_errmsg(db);
        if (msg && strstr(msg, "no such table"))
            return UTXO_DELTA_UNDO_ABSENT;
        LOG_WARN(UNDO_TAG, "[utxo_apply_undo] h=%d prepare rc=%d: %s",
                 height, rc, msg ? msg : "(null)");
        return UTXO_DELTA_UNDO_ERROR;
    }
    sqlite3_bind_int(st, 1, height);
    rc = sqlite3_step(st);  // raw-sql-ok:progress-kv-kernel-store
    enum utxo_apply_delta_undo_status status =
        classify_row(db, st, rc, height, block_hash, blk, out);
    sqlite3_finalize(st);
    return status;
}


bool utxo_apply_delta_undo_next_unapplied(sqlite3 *db, uint64_t *next_out,
                                          bool *found_out)
{
    if (!db || !next_out || !found_out)
        LOG_FAIL(UNDO_TAG, "[utxo_apply_undo] next_unapplied: invalid args");
    struct stage_cursor_read_result r =
        stage_cursor_read_persisted(db, "utxo_apply", UNDO_TAG);
    if (!r.ok)
        LOG_FAIL(UNDO_TAG, "[utxo_apply_undo] next_unapplied: cursor read "
                 "failed rc=%d", r.sqlite_rc);
    *next_out = r.cursor;
    *found_out = r.found;
    return true;
}

enum utxo_apply_delta_undo_status utxo_apply_delta_undo_row_branch(
    sqlite3 *db, int height, const struct uint256 *block_hash)
{
    if (!db || !block_hash || height < 0) {
        LOG_WARN(UNDO_TAG, "[utxo_apply_undo] row_branch: invalid args h=%d",
                 height);
        return UTXO_DELTA_UNDO_ERROR;
    }
    sqlite3_stmt *st = NULL;
    int rc = sqlite3_prepare_v2(db,
        "SELECT branch_hash FROM utxo_apply_delta WHERE height = ?",
        -1, &st, NULL);
    if (rc != SQLITE_OK) {
        const char *msg = sqlite3_errmsg(db);
        if (msg && strstr(msg, "no such table"))
            return UTXO_DELTA_UNDO_ABSENT;
        LOG_WARN(UNDO_TAG, "[utxo_apply_undo] row_branch h=%d prepare rc=%d: "
                 "%s", height, rc, msg ? msg : "(null)");
        return UTXO_DELTA_UNDO_ERROR;
    }
    sqlite3_bind_int(st, 1, height);
    rc = sqlite3_step(st);  // raw-sql-ok:progress-kv-kernel-store
    enum utxo_apply_delta_undo_status status;
    if (rc == SQLITE_DONE) {
        status = UTXO_DELTA_UNDO_ABSENT;
    } else if (rc != SQLITE_ROW) {
        LOG_WARN(UNDO_TAG, "[utxo_apply_undo] row_branch h=%d step rc=%d: %s",
                 height, rc, sqlite3_errmsg(db));
        status = UTXO_DELTA_UNDO_ERROR;
    } else {
        status = sqlite3_column_type(st, 0) == SQLITE_BLOB &&
                 sqlite3_column_bytes(st, 0) == 32 &&
                 memcmp(sqlite3_column_blob(st, 0), block_hash->data, 32) == 0
            ? UTXO_DELTA_UNDO_FOUND : UTXO_DELTA_UNDO_OTHER_BRANCH;
    }
    sqlite3_finalize(st);
    return status;
}
