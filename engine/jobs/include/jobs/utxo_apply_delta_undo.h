/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * utxo_apply_delta_undo — read a block's spent-coin undo from the reducer's
 * own inverse-delta record.
 *
 * The utxo_apply stage persists, for every height it applies, the full
 * pre-image of each transparent coin the block spends (txid, vout, value,
 * creation height, coinbase flag, scriptPubKey) in `utxo_apply_delta`, inside
 * the same SQLite transaction as the coins, the log row and the stage cursor
 * (jobs/utxo_apply_delta.h). That row is this node's undo record for the
 * block: it exists exactly when the block is applied, and a kill -9 can never
 * leave the cursor advanced without it.
 *
 * zclassicd-format rev files exist only when a legacy datadir was copied in;
 * blocks this node connected itself have none. Background full validation
 * needs the spent outputs to re-check every transparent script, so it reads
 * them from here when no rev record is present.
 *
 * The loader never trusts the row's shape. The row must be stamped with the
 * exact block hash being verified, and its spent entries must name, in order,
 * exactly the prevouts of the block's non-coinbase inputs, with nothing left
 * over. Anything else is reported as a mismatch and the caller treats the
 * block's scripts as unverified. */

#ifndef ZCL_JOBS_UTXO_APPLY_DELTA_UNDO_H
#define ZCL_JOBS_UTXO_APPLY_DELTA_UNDO_H

#include "core/uint256.h"

#include <sqlite3.h>
#include <stdbool.h>
#include <stdint.h>

struct block;
struct block_undo;

enum utxo_apply_delta_undo_status {
    /* `out` holds one tx_undo per non-coinbase transaction. */
    UTXO_DELTA_UNDO_FOUND = 0,
    /* No delta row at this height (never applied here, or no table). */
    UTXO_DELTA_UNDO_ABSENT,
    /* A row exists but was written for a different block at this height. */
    UTXO_DELTA_UNDO_OTHER_BRANCH,
    /* The row does not describe exactly this block's transparent inputs. */
    UTXO_DELTA_UNDO_MISMATCH,
    /* Store or allocation failure; the answer is unknown, not negative. */
    UTXO_DELTA_UNDO_ERROR,
};

/* Stable lowercase name for logs and test messages. */
const char *utxo_apply_delta_undo_status_name(
    enum utxo_apply_delta_undo_status status);

/* Reconstruct `blk`'s block undo from the delta row at `height`. `out` is
 * initialized on entry and owns its allocations only on FOUND (the caller
 * then block_undo_free()s it); on every other status it is left empty.
 * Entry i of out->vtxundo belongs to blk->vtx[i + 1], matching the rev-file
 * layout the background verifier already indexes. tx_in_undo.version is not
 * recorded by the delta and is left 0; value, scriptPubKey, creation height
 * and coinbase flag are exact. Read-only; takes no locks — the caller owns
 * the connection's serialization. */
enum utxo_apply_delta_undo_status utxo_apply_delta_block_undo_load(
    sqlite3 *db, int height, const struct uint256 *block_hash,
    const struct block *blk, struct block_undo *out);

/* Which block the delta row at `height` was written for, without decoding
 * it: FOUND when it is `block_hash`'s row, OTHER_BRANCH when the fold still
 * holds another block there (the active chain switched and the reducer has
 * not rewound yet), ABSENT when there is no row, ERROR on a store failure.
 * Takes no locks — the caller owns the connection's serialization. */
enum utxo_apply_delta_undo_status utxo_apply_delta_undo_row_branch(
    sqlite3 *db, int height, const struct uint256 *block_hash);

/* The utxo_apply stage's durable cursor: the next height it will apply, so
 * no height at or above it has a delta row yet. *found_out is false when the
 * stage has never committed on this store (nothing to wait for). Returns
 * false on a store error. Serializes on progress_store_tx_lock. */
bool utxo_apply_delta_undo_next_unapplied(sqlite3 *db, uint64_t *next_out,
                                          bool *found_out);

#endif /* ZCL_JOBS_UTXO_APPLY_DELTA_UNDO_H */
