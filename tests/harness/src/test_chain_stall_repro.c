/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Deterministic reproduction of a BIP30 chain stall.
 *
 * A tip that regresses to N-1 while the coins view still holds block N's
 * unspent coinbase makes connect_block(N) return `bad-txns-BIP30`.
 *
 * Failing shape: the coins view holds an unspent coinbase for txid X of block
 * N but the tip is N-1 (partial rollback or disconnect/reconnect). The BIP30
 * loop in core/modules/validation/src/connect_block.c then trips:
 *
 *     for (size_t i = 0; !skip_bip30 && i < block->num_vtx; i++) {
 *         if (coins_view_cache_have_coins(view, &block->vtx[i].hash)) {
 *             struct coins existing;
 *             coins_init(&existing);
 *             if (coins_view_cache_get_coins(view, &block->vtx[i].hash,
 *                                             &existing)) {
 *                 if (!coins_is_pruned(&existing)) {
 *                     coins_free(&existing);
 *                     return validation_state_dos(state, 100, false,
 *                         REJECT_INVALID, "bad-txns-BIP30", false, NULL);
 *                 }
 *             }
 *             coins_free(&existing);
 *         }
 *     }
 *
 * Scope: regression gate. connect_block must tolerate a block's own
 * same-height coinbase self-write after a local rewind, while still
 * rejecting real duplicate transactions.
 *
 * All state is in-process and in-memory. A chain_params copy with a
 * checkpoint at the test height skips check_block's POW and size checks;
 * g_deferred_proof_validation_below_height stays -1 so the BIP30 skip flag
 * stays false.
 */

#include "test/test_core.h"
#include "validation/connect_block.h"
#include "validation/process_block.h"
#include "validation/update_coins.h"
#include "validation/contextual_check_tx.h"  /* g_deferred_proof_validation_below_height */
#include "coins/coins_view.h"
#include "coins/coins.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "core/uint256.h"
#include "core/arith_uint256.h"
#include "script/script.h"
#include "bloom/merkle.h"
#include "chain/chainparams.h"
#include "chain/checkpoints.h"
#include "consensus/validation.h"
#include "storage/coins_view_sqlite.h"
#include "util/safe_alloc.h"

#include <errno.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* ── Helpers (mirrors test_reorg_safety.c so reviewers can compare) ── */

static struct transaction make_coinbase_seeded(int height, uint8_t seed)
{
    struct transaction tx;
    memset(&tx, 0, sizeof(tx));
    tx.version = 1;
    tx.num_vin = 1;
    tx.vin = zcl_calloc(1, sizeof(struct tx_in), "p10_cb_vin");

    uint8_t sig[6];
    sig[0] = 4;
    sig[1] = (uint8_t)(height & 0xFF);
    sig[2] = (uint8_t)((height >> 8) & 0xFF);
    sig[3] = (uint8_t)((height >> 16) & 0xFF);
    sig[4] = (uint8_t)((height >> 24) & 0xFF);
    sig[5] = seed;
    script_set(&tx.vin[0].script_sig, sig, 6);

    uint256_set_null(&tx.vin[0].prevout.hash);
    tx.vin[0].prevout.n = 0xFFFFFFFF;
    tx.vin[0].sequence = 0xFFFFFFFF;

    tx.num_vout = 1;
    tx.vout = zcl_calloc(1, sizeof(struct tx_out), "p10_cb_vout");
    tx.vout[0].value = 1000000000LL;
    uint8_t pk[] = {0x76, 0xa9, 0x14};
    script_set(&tx.vout[0].script_pub_key, pk, 3);

    transaction_compute_hash(&tx);
    return tx;
}

static void make_block_seeded(struct block *blk, int height,
                               const struct uint256 *prev_hash,
                               uint8_t seed)
{
    memset(blk, 0, sizeof(*blk));
    blk->num_vtx = 1;
    blk->vtx = zcl_calloc(1, sizeof(struct transaction), "p10_block_vtx");
    blk->vtx[0] = make_coinbase_seeded(height, seed);
    blk->header.nVersion = 4;
    if (prev_hash)
        blk->header.hashPrevBlock = *prev_hash;
    blk->header.nTime = 1000000 + (uint32_t)height * 150 + seed;
    blk->header.hashMerkleRoot =
        compute_merkle_root(&blk->vtx[0].hash, 1);
}

static void free_block(struct block *blk)
{
    for (size_t i = 0; i < blk->num_vtx; i++) {
        free(blk->vtx[i].vin);
        free(blk->vtx[i].vout);
    }
    free(blk->vtx);
}

/* chain_params copy with one checkpoint at `height` so check_block runs with
 * expensive_checks=false. Heap-owned; the caller frees. */
struct chain_params_fixture {
    struct chain_params params;
    struct checkpoint_entry entry;
};

static void build_checkpoint_params(struct chain_params_fixture *f,
                                     int checkpoint_height,
                                     const struct uint256 *hash)
{
    f->params = *chain_params_get();
    f->entry.height = checkpoint_height;
    f->entry.hash = *hash;
    f->params.checkpointData.entries = &f->entry;
    f->params.checkpointData.nEntries = 1;
}

/* ── Test 1 — live-node stall shape reproduces ──────────────────── */

static int t_connect_block_tolerates_own_coinbase_self_write(void)
{
    int failures = 0;

    TEST("chain_stall_repro: connect_block tolerates own coinbase self-write") {
        /* g_deferred_proof_validation_below_height guards the BIP30 skip flag — confirm
         * it is NOT set so the check runs. */
        atomic_store(&g_deferred_proof_validation_below_height, -1);

        /* Tip+1 after a partial-application rollback; small heights keep
         * the test fast. */
        const int parent_height = 199;
        const int stall_height = parent_height + 1;  /* = 200 */

        /* ── Parent block_index (height=199, the "tip" after rollback) ── */
        struct uint256 parent_hash;
        memset(parent_hash.data, 0xA0, sizeof(parent_hash.data));
        struct block_index parent_idx;
        block_index_init(&parent_idx);
        parent_idx.nHeight = parent_height;
        parent_idx.phashBlock = &parent_hash;
        parent_idx.nStatus = BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA;
        parent_idx.nTx = 1;
        parent_idx.nChainTx = 1;
        arith_uint256_set_u64(&parent_idx.nChainWork, (uint64_t)parent_height + 1);

        /* ── The block that is about to be reconnected at height=200 ── */
        struct block stall_blk;
        make_block_seeded(&stall_blk, stall_height, &parent_hash, 0x00);

        struct uint256 stall_hash;
        block_header_get_hash(&stall_blk.header, &stall_hash);

        struct block_index stall_idx;
        block_index_init(&stall_idx);
        stall_idx.nHeight = stall_height;
        stall_idx.phashBlock = &stall_hash;
        stall_idx.pprev = &parent_idx;
        stall_idx.nStatus = BLOCK_HAVE_DATA;
        stall_idx.nTx = 1;

        /* ── Chain params: add a checkpoint at stall_height so
         *    check_block treats the header as trusted (skip POW/size
         *    limits — we don't mine Equihash for the fixture). ── */
        struct chain_params_fixture fx;
        build_checkpoint_params(&fx, stall_height, &stall_hash);

        /* ── Coins view: seed the stall block's coinbase as UNSPENT,
         *    then set best_block to the PARENT hash — the exact
         *    post-rewind shape the live node was trapped in. ── */
        struct coins_view_cache cache;
        struct coins_view null_view;
        memset(&null_view, 0, sizeof(null_view));
        coins_view_cache_init(&cache, &null_view);

        /* Apply the coinbase to the cache: the output landed in the coins
         * view but the tip-update never committed. */
        update_coins(&stall_blk.vtx[0], &cache, stall_height);

        /* Pin best_block to the parent (tip regressed to N-1). */
        coins_view_cache_set_best_block(&cache, &parent_hash);

        /* Sanity: the stale coinbase really is present and unspent. */
        ASSERT(coins_view_cache_have_coins(&cache, &stall_blk.vtx[0].hash));
        {
            struct coins existing;
            coins_init(&existing);
            ASSERT(coins_view_cache_get_coins(&cache,
                                               &stall_blk.vtx[0].hash,
                                               &existing));
            ASSERT(!coins_is_pruned(&existing));
            coins_free(&existing);
        }

        /* ── Attempt to reconnect block N — the actual repro call. ── */
        struct validation_state vs;
        validation_state_init(&vs);
        connect_block_set_sapling_tree(NULL);  /* just_check path */

        bool ok = connect_block(&stall_blk, &vs, &stall_idx, &cache,
                                 &fx.params, /*just_check=*/true);

        /* A same-height self-write wedge:
         * block N's own coinbase is already present while durable tip
         * is N-1. Since contextual_check_block enforces BIP34 coinbase
         * height encoding for every height > 0, this cannot be a real
         * post-BIP34 duplicate-coinbase consensus violation. */
        printf("connect_block ok=%d reject=\"%s\" dos=%d at h=%d... ",
               (int)ok, vs.reject_reason, vs.dos, stall_height);

        ASSERT(ok);
        ASSERT(strcmp(vs.reject_reason, "bad-txns-BIP30") != 0);

        /* Cleanup */
        free_block(&stall_blk);
        coins_view_cache_free(&cache);

        PASS();
    } _test_next:;

    return failures;
}

/* ── Test 2 — clean view does NOT trip BIP30 (control) ──────────── */

static int t_clean_view_advances(void)
{
    int failures = 0;

    TEST("chain_stall_repro: clean view (no stale coinbase) does NOT trip BIP30") {
        atomic_store(&g_deferred_proof_validation_below_height, -1);

        const int parent_height = 199;
        const int stall_height = parent_height + 1;

        struct uint256 parent_hash;
        memset(parent_hash.data, 0xB0, sizeof(parent_hash.data));
        struct block_index parent_idx;
        block_index_init(&parent_idx);
        parent_idx.nHeight = parent_height;
        parent_idx.phashBlock = &parent_hash;
        parent_idx.nStatus = BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA;
        parent_idx.nTx = 1;
        parent_idx.nChainTx = 1;
        arith_uint256_set_u64(&parent_idx.nChainWork, (uint64_t)parent_height + 1);

        struct block blk;
        make_block_seeded(&blk, stall_height, &parent_hash, 0x11);

        struct uint256 blk_hash;
        block_header_get_hash(&blk.header, &blk_hash);

        struct block_index blk_idx;
        block_index_init(&blk_idx);
        blk_idx.nHeight = stall_height;
        blk_idx.phashBlock = &blk_hash;
        blk_idx.pprev = &parent_idx;
        blk_idx.nStatus = BLOCK_HAVE_DATA;
        blk_idx.nTx = 1;

        struct chain_params_fixture fx;
        build_checkpoint_params(&fx, stall_height, &blk_hash);

        struct coins_view_cache cache;
        struct coins_view null_view;
        memset(&null_view, 0, sizeof(null_view));
        coins_view_cache_init(&cache, &null_view);

        /* NO pre-seed of the coinbase — this is the "clean" state
         * that fix must restore. */
        coins_view_cache_set_best_block(&cache, &parent_hash);

        ASSERT(!coins_view_cache_have_coins(&cache, &blk.vtx[0].hash));

        struct validation_state vs;
        validation_state_init(&vs);
        connect_block_set_sapling_tree(NULL);

        bool ok = connect_block(&blk, &vs, &blk_idx, &cache,
                                 &fx.params, /*just_check=*/true);

        /* With a clean view BIP30 MUST NOT trip.  connect_block may
         * still fail further down (no sapling tree, etc.) but the
         * failure reason MUST NOT be "bad-txns-BIP30". */
        printf("clean: ok=%d reject=\"%s\"... ",
               (int)ok, vs.reject_reason);
        ASSERT(strcmp(vs.reject_reason, "bad-txns-BIP30") != 0);

        free_block(&blk);
        coins_view_cache_free(&cache);

        PASS();
    } _test_next:;

    return failures;
}

/* ── Test 3 — Regression test: disconnect_block purges coinbase ──
 *
 * Invariant: after `disconnect_block(B)` on a scratch view wrapping a parent
 * cache, and `coins_view_cache_flush_for_testing(scratch)`, the parent no
 * longer reports `coins_view_cache_have_coins` for any tx in B.
 *
 * Uses the production three-layer shape of `disconnect_tip`:
 *
 *     null_view  <-  parent   <-  scratch
 *      (stub)    (coins_tip)  (disconnect_tip's scratchpad)
 *
 * disconnect_block must emit a DIRTY+pruned tombstone (not a bare erase on
 * the empty scratch map) so the flush propagates to the parent. */

static int t_disconnect_block_purges_coinbase_from_backing(void)
{
    int failures = 0;

    TEST("chain_stall_repro RED: disconnect_block purges coinbase from the backing parent cache") {
        atomic_store(&g_deferred_proof_validation_below_height, -1);

        const int coinbase_height = 200;

        /* Stand-in for `coins_tip`; null backing view (no SQLite). */
        struct coins_view null_view;
        memset(&null_view, 0, sizeof(null_view));
        struct coins_view_cache parent;
        coins_view_cache_init(&parent, &null_view);

        /* Block whose coinbase lands in the parent, then gets
         * disconnected via the scratch. */
        struct uint256 parent_prev_hash;
        memset(parent_prev_hash.data, 0xC0, sizeof(parent_prev_hash.data));
        struct block blk;
        make_block_seeded(&blk, coinbase_height, &parent_prev_hash, 0x33);

        struct uint256 blk_hash;
        block_header_get_hash(&blk.header, &blk_hash);

        /* block_index for disconnect_block: nHeight + pprev + phashBlock. */
        struct block_index parent_idx;
        block_index_init(&parent_idx);
        parent_idx.nHeight = coinbase_height - 1;
        parent_idx.phashBlock = &parent_prev_hash;
        parent_idx.nStatus = BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA;
        parent_idx.nTx = 1;
        parent_idx.nChainTx = 1;
        arith_uint256_set_u64(&parent_idx.nChainWork,
                              (uint64_t)coinbase_height);

        struct block_index blk_idx;
        block_index_init(&blk_idx);
        blk_idx.nHeight = coinbase_height;
        blk_idx.phashBlock = &blk_hash;
        blk_idx.pprev = &parent_idx;
        blk_idx.nStatus = BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA;
        blk_idx.nTx = 1;

        /* Seed the parent with the coinbase (prior connect_block). */
        update_coins(&blk.vtx[0], &parent, coinbase_height);
        coins_view_cache_set_best_block(&parent, &blk_hash);

        /* Sanity: parent has the coinbase as unspent. */
        ASSERT(coins_view_cache_have_coins(&parent, &blk.vtx[0].hash));

        /* Scratch view wrapping the parent, as disconnect_tip builds it. */
        struct coins_view parent_as_view;
        coins_view_cache_as_view(&parent_as_view, &parent);
        struct coins_view_cache scratch;
        coins_view_cache_init(&scratch, &parent_as_view);

        /* disconnect_block on the scratch. empty undo data is fine
         * for a coinbase-only block (the coinbase has no restorable
         * inputs). */
        struct block_undo empty_undo;
        block_undo_init(&empty_undo);
        struct validation_state vs;
        validation_state_init(&vs);
        bool disc_ok = disconnect_block(&blk, &vs, &blk_idx,
                                         &scratch, &empty_undo);
        ASSERT(disc_ok);

        /* Flush the scratch into the parent; this must purge the coinbase. */
        ASSERT(coins_view_cache_flush_for_testing(&scratch));

        /* The parent must no longer report the coinbase: disconnect_block
         * emits a DIRTY+pruned tombstone that cvc_batch_write propagates. */
        if (coins_view_cache_have_coins(&parent, &blk.vtx[0].hash)) {
            printf("FAIL (RED — parent still has coinbase_%d after "
                   "disconnect+flush; invariant violated at "
                   "connect_block.c:639)\n",
                   coinbase_height);
            failures++;
            goto _p103_cleanup;
        }
        PASS();

    _p103_cleanup:
        block_undo_free(&empty_undo);
        coins_view_cache_free(&scratch);
        coins_view_cache_free(&parent);
        free_block(&blk);
    } _test_next:;

    return failures;
}

/* ── Test 4 — Regression test: disconnect-flush lands in SQLite under shared-handle writer contention ──
 *
 * The three-layer test above uses a null_view backing, so SQLite persistence
 * is not exercised. coins_view_sqlite's SAVEPOINT on a SHARED sqlite3 handle
 * fails with SQLITE_BUSY ("cannot open savepoint - SQL statements in
 * progress") while any writer statement on that connection is mid-execution
 * (`db->nVdbeWrite > 0`), so the tombstone DELETE would never reach disk.
 *
 * The test holds an `INSERT ... RETURNING` at SQLITE_ROW on the shared handle,
 * then drives the full three-layer flush. coins_view_sqlite uses a dedicated
 * connection, so the flush lands and the DELETE is observable. */

static int mkdir_p_p14(const char *p)
{
    if (mkdir(p, 0700) == 0) return 0;
    if (errno == EEXIST) return 0;
    return -1;
}

static void p14_tmp_path(char *buf, size_t n, const char *tag)
{
    snprintf(buf, n, "./test-tmp/p14_%d_%s", (int)getpid(), tag);
}

/* Build the minimal schema coins_view_sqlite_open's integrity check
 * and the flush path need. File-backed + WAL to match production. */
static bool p14_build_db(sqlite3 **out, const char *dbpath)
{
    if (sqlite3_open(dbpath, out) != SQLITE_OK) return false;
    sqlite3_exec(*out, "PRAGMA journal_mode=WAL",  NULL, NULL, NULL);
    sqlite3_exec(*out, "PRAGMA synchronous=NORMAL", NULL, NULL, NULL);
    sqlite3_busy_timeout(*out, 5000);
    char *err = NULL;
    int rc = sqlite3_exec(*out,
        "CREATE TABLE IF NOT EXISTS utxos("
        " txid BLOB, vout INTEGER, value INTEGER,"
        " script BLOB, script_type INTEGER, address_hash BLOB,"
        " height INTEGER, is_coinbase INTEGER,"
        " PRIMARY KEY(txid,vout));"
        "CREATE TABLE IF NOT EXISTS node_state("
        " key TEXT PRIMARY KEY, value BLOB);"
        "CREATE TABLE IF NOT EXISTS blocks("
        " hash BLOB PRIMARY KEY, height INTEGER, status INTEGER);",
        NULL, NULL, &err);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "p14_build_db exec err: %s\n", err ? err : "?");
        sqlite3_free(err);
        return false;
    }
    return true;
}

static int p14_count_utxos_by_txid(sqlite3 *db, const uint8_t txid[32])
{
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT COUNT(*) FROM utxos WHERE txid=?",
            -1, &s, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_blob(s, 1, txid, 32, SQLITE_STATIC);
    int count = -1;
    if (sqlite3_step(s) == SQLITE_ROW)
        count = sqlite3_column_int(s, 0);
    sqlite3_finalize(s);
    return count;
}

static int t_p14_flush_under_shared_cursor_lands_tombstone(void)
{
    int failures = 0;
    char dir[256];  p14_tmp_path(dir, sizeof(dir), "shared_cursor");
    mkdir_p_p14(dir);
    char dbpath[512]; snprintf(dbpath, sizeof(dbpath), "%s/node.db", dir);

    TEST("chain_stall_repro RED: file-backed coins_view_sqlite opens a dedicated connection AND three-layer disconnect+flush lands DELETE in SQLite") {
        atomic_store(&g_deferred_proof_validation_below_height, -1);

        sqlite3 *db = NULL;
        ASSERT(p14_build_db(&db, dbpath));

        struct coins_view_sqlite cvs;
        ASSERT(coins_view_sqlite_open(&cvs, db));

        /* Structural invariant: for a file-backed input handle,
         * `coins_view_sqlite_open` opens its own sqlite3 handle
         * (`cvs.db != db`, owns_db) so the flush has an independent
         * `nVdbeWrite` counter. */
        ASSERT(cvs.owns_db);
        ASSERT(cvs.db != db);

        /* Probe: a writer held at SQLITE_ROW on the shared `db` makes a
         * manual SAVEPOINT on that handle fail with SQLITE_BUSY; the flush
         * runs on `cvs.db`, so it is unaffected. */
        uint8_t decoy_txid[32]; memset(decoy_txid, 0xEE, 32);
        sqlite3_stmt *foreign = NULL;
        ASSERT(sqlite3_prepare_v2(db,
            "INSERT INTO utxos(txid, vout, value, script, script_type,"
            " address_hash, height, is_coinbase)"
            " VALUES(?,0,0,NULL,0,NULL,0,0) RETURNING txid",
            -1, &foreign, NULL) == SQLITE_OK);
        ASSERT_EQ(sqlite3_stmt_readonly(foreign), 0);
        sqlite3_bind_blob(foreign, 1, decoy_txid, 32, SQLITE_STATIC);
        ASSERT_EQ(sqlite3_step(foreign), SQLITE_ROW);
        {
            char *serr = NULL;
            int svrc = sqlite3_exec(db, "SAVEPOINT probe",
                                     NULL, NULL, &serr);
            /* Expected SQLite error signature. */
            ASSERT_EQ(svrc, SQLITE_BUSY);
            ASSERT(serr && strstr(serr,
                "SQL statements in progress") != NULL);
            sqlite3_free(serr);
            /* No RELEASE — the SAVEPOINT never began. */
        }
        /* Release the foreign writer before the flush. */
        sqlite3_reset(foreign);
        sqlite3_finalize(foreign);

        /* Three-layer end-to-end flush: cache + cache + coins_view_sqlite. */
        struct coins_view_cache parent;
        coins_view_cache_init(&parent, &cvs.view);

        const int coinbase_height = 200;
        struct uint256 parent_prev_hash;
        memset(parent_prev_hash.data, 0xD0, sizeof(parent_prev_hash.data));
        struct block blk;
        make_block_seeded(&blk, coinbase_height, &parent_prev_hash, 0x44);

        struct uint256 blk_hash;
        block_header_get_hash(&blk.header, &blk_hash);

        struct block_index parent_idx;
        block_index_init(&parent_idx);
        parent_idx.nHeight = coinbase_height - 1;
        parent_idx.phashBlock = &parent_prev_hash;
        parent_idx.nStatus = BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA;
        parent_idx.nTx = 1;
        parent_idx.nChainTx = 1;
        arith_uint256_set_u64(&parent_idx.nChainWork,
                              (uint64_t)coinbase_height);

        struct block_index blk_idx;
        block_index_init(&blk_idx);
        blk_idx.nHeight = coinbase_height;
        blk_idx.phashBlock = &blk_hash;
        blk_idx.pprev = &parent_idx;
        blk_idx.nStatus = BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA;
        blk_idx.nTx = 1;

        update_coins(&blk.vtx[0], &parent, coinbase_height);
        coins_view_cache_set_best_block(&parent, &blk_hash);
        ASSERT(coins_view_cache_flush_for_testing(&parent));

        const uint8_t *cb_txid = blk.vtx[0].hash.data;
        ASSERT_EQ(p14_count_utxos_by_txid(cvs.db, cb_txid), 1);

        /* Scratch view on top of parent, as disconnect_tip builds it. */
        struct coins_view parent_as_view;
        coins_view_cache_as_view(&parent_as_view, &parent);
        struct coins_view_cache scratch;
        coins_view_cache_init(&scratch, &parent_as_view);

        struct block_undo empty_undo;
        block_undo_init(&empty_undo);
        struct validation_state vs;
        validation_state_init(&vs);
        ASSERT(disconnect_block(&blk, &vs, &blk_idx,
                                 &scratch, &empty_undo));
        ASSERT(coins_view_cache_flush_for_testing(&scratch));

        /* The load-bearing flush, parent -> SQLite, on the dedicated
         * `cvs.db`. */
        ASSERT(coins_view_cache_flush_for_testing(&parent));

        /* The coinbase row is gone from SQLite, not just from the
         * in-memory tombstone map. */
        ASSERT_EQ(p14_count_utxos_by_txid(cvs.db, cb_txid), 0);

        block_undo_free(&empty_undo);
        coins_view_cache_free(&scratch);
        coins_view_cache_free(&parent);
        coins_view_sqlite_close(&cvs);
        sqlite3_close(db);
        free_block(&blk);

        PASS();
    } _test_next:;

    test_cleanup_tmpdir(dir);
    return failures;
}

int test_chain_stall_repro(void);

int test_chain_stall_repro(void)
{
    printf("\n=== chain stall repro ===\n");
    int failures = 0;
    failures += t_connect_block_tolerates_own_coinbase_self_write();
    failures += t_clean_view_advances();
    failures += t_disconnect_block_purges_coinbase_from_backing();
    failures += t_p14_flush_under_shared_cursor_lands_tombstone();
    return failures;
}
