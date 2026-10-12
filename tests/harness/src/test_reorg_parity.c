/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Reorg parity proof for the reducer-era UTXO invariants.
 *
 * A chain REORG must produce a byte-identical UTXO/coin state regardless of
 * path: unwinding a lighter branch A and applying a heavier branch B must
 * yield the EXACT SAME coin set as building B directly from the fork point.
 * A forward-only replay is not sufficient; this is the offline proof of the
 * disconnect/UTXO-unwind path.
 *
 * Strategy
 * --------
 *   Fork point at height H (genesis chain genesis..H built once, shared).
 *
 *   Branch A: H+1..H+3 coinbases, with H+2 spending H+1's coinbase output.
 *   Branch B: H+1..H+4 coinbases (heavier), with H+2 differently-spending
 *             — it spends the SHARED fork-point coinbase that A never
 *             touched, exercising a divergent spend pattern.
 *
 * Byte-exact comparison primitive
 * --------------------------------
 *   The `utxo_commitment` (XOR-hash accumulator of SHA256(txid||vout||
 *   value||height) over the whole UTXO set, plus a count) is the
 *   byte-level fingerprint of the coin set; equal commitments mean
 *   byte-identical UTXO sets.
 *
 *   The incremental accumulator (`cache->commitment`) is maintained only on
 *   the forward path; disconnect_block does NOT decrement it, so it is
 *   path-DEPENDENT after a reorg. The authoritative query is
 *   coins_view_cache_recompute_commitment(), an O(N) recompute over the
 *   coin set (the in-memory analogue of utxo_commitment_compute_db()); it
 *   leaves the forward-only value unchanged byte-for-byte. This test asserts
 *   the reorged and direct-build views converge to an identical fingerprint,
 *   plus per-outpoint presence/value/height equality so a commitment
 *   collision cannot mask a divergence.
 *
 * Uses the builders and helpers of test_reorg_safety.c, with the same real
 * consensus paths (disconnect_block / update_coins /
 * update_coins_with_undo), no stubs.
 */

#include "test/test_core.h"
#include "validation/connect_block.h"
#include "validation/update_coins.h"
#include "coins/coins_view.h"
#include "coins/coins.h"
#include "coins/utxo_commitment.h"
#include "coins/undo.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "core/uint256.h"
#include "core/arith_uint256.h"
#include "script/script.h"
#include "bloom/merkle.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "util/safe_alloc.h"

/* Pass/fail wrapper consistent with test_reorg_safety.c. */
#define RP_CHECK(name, expr) do {          \
    printf("%s... ", (name));              \
    if ((expr)) printf("OK\n");            \
    else { printf("FAIL\n"); failures++; } \
} while (0)

/* ── Builders (patterned on test_reorg_safety.c) ─────────────── */

static struct transaction make_coinbase_seeded(int height, uint8_t seed)
{
    struct transaction tx;
    memset(&tx, 0, sizeof(tx));
    tx.version = 1;
    tx.num_vin = 1;
    tx.vin = zcl_calloc(1, sizeof(struct tx_in), "rp_cb_vin");

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
    tx.vout = zcl_calloc(1, sizeof(struct tx_out), "rp_cb_vout");
    tx.vout[0].value = 1000000000LL;
    uint8_t pk[] = {0x76, 0xa9, 0x14};
    script_set(&tx.vout[0].script_pub_key, pk, 3);

    transaction_compute_hash(&tx);
    return tx;
}

/* A simple spend of one prior output. Produces one new output for
 * `value`. `seed` makes the txid distinct across branches. */
static struct transaction make_spend(const struct uint256 *prev_txid,
                                     uint32_t prev_n, int64_t value,
                                     uint8_t seed)
{
    struct transaction tx;
    memset(&tx, 0, sizeof(tx));
    tx.version = 1;
    tx.num_vin = 1;
    tx.vin = zcl_calloc(1, sizeof(struct tx_in), "rp_sp_vin");
    tx.vin[0].prevout.hash = *prev_txid;
    tx.vin[0].prevout.n = prev_n;
    uint8_t sig[2] = {0x48, seed};
    script_set(&tx.vin[0].script_sig, sig, 2);
    tx.vin[0].sequence = 0xFFFFFFFF;

    tx.num_vout = 1;
    tx.vout = zcl_calloc(1, sizeof(struct tx_out), "rp_sp_vout");
    tx.vout[0].value = value;
    uint8_t pk[4] = {0x76, 0xa9, 0x14, seed};
    script_set(&tx.vout[0].script_pub_key, pk, 4);

    transaction_compute_hash(&tx);
    return tx;
}

static void free_tx(struct transaction *tx)
{
    free(tx->vin);
    free(tx->vout);
}

static void free_block(struct block *blk)
{
    for (size_t i = 0; i < blk->num_vtx; i++) {
        free(blk->vtx[i].vin);
        free(blk->vtx[i].vout);
    }
    free(blk->vtx);
    blk->vtx = NULL;
    blk->num_vtx = 0;
}

/* Build a block holding the supplied transactions (caller owns the
 * tx array contents; block takes ownership by copy of the structs,
 * so the caller must NOT free the originals — free via free_block). */
static void make_block_txs(struct block *blk, int height,
                           const struct uint256 *prev_hash,
                           uint8_t seed,
                           struct transaction *txs, size_t ntx)
{
    memset(blk, 0, sizeof(*blk));
    blk->num_vtx = ntx;
    blk->vtx = zcl_calloc(ntx, sizeof(struct transaction), "rp_blk_vtx");
    struct uint256 *leaf_hashes =
        zcl_calloc(ntx, sizeof(struct uint256), "rp_blk_leaves");
    for (size_t i = 0; i < ntx; i++) {
        blk->vtx[i] = txs[i];
        leaf_hashes[i] = txs[i].hash;
    }
    blk->header.nVersion = 4;
    if (prev_hash)
        blk->header.hashPrevBlock = *prev_hash;
    blk->header.nTime = 1000000 + (uint32_t)height * 150 + seed;
    blk->header.hashMerkleRoot = compute_merkle_root(leaf_hashes, ntx);
    free(leaf_hashes);
}

/* Connect every tx in a block via update_coins_with_undo, accumulating
 * undo into the block_undo so disconnect_block can reverse it.
 * Coinbase (vtx[0]) is connected with plain update_coins (no inputs). */
static bool connect_block_with_undo(struct block *blk, int height,
                                    struct coins_view_cache *cache,
                                    struct block_undo *bu)
{
    block_undo_init(bu);
    if (blk->num_vtx > 1)
        block_undo_alloc(bu, blk->num_vtx - 1);

    /* coinbase */
    update_coins(&blk->vtx[0], cache, height);

    /* non-coinbase spends */
    for (size_t i = 1; i < blk->num_vtx; i++) {
        struct tx_undo txundo;
        memset(&txundo, 0, sizeof(txundo));
        if (!update_coins_with_undo(&blk->vtx[i], cache, &txundo, height)) {
            printf("[connect h=%d tx=%zu spend failed] ", height, i);
            return false;
        }
        bu->vtxundo[i - 1] = txundo;
    }
    return true;
}

/* ── Commitment / per-outpoint parity comparison ─────────────── */

/* Recompute a PATH-INDEPENDENT UTXO commitment for `view` by XOR-ing in
 * every still-available output across the supplied candidate txid set.
 * The explicit-universe twin of coins_view_cache_recompute_commitment():
 * both derive the fingerprint from the coin SET, so a leaked or missing
 * cache entry makes their counts disagree. */
static void recompute_commitment(struct coins_view_cache *view,
                                 const struct uint256 *txids, size_t ntx,
                                 struct utxo_commitment *out)
{
    utxo_commitment_init(out);
    for (size_t t = 0; t < ntx; t++) {
        struct coins c;
        coins_init(&c);
        if (coins_view_cache_get_coins(view, &txids[t], &c)) {
            for (size_t i = 0; i < c.num_vout; i++) {
                if (coins_is_available(&c, (unsigned)i))
                    utxo_commitment_add(out, txids[t].data, (uint32_t)i,
                                        c.vout[i].value, (int32_t)c.height);
            }
        }
        coins_free(&c);
    }
}

/* For a specific txid: both views agree on presence, and if present, on
 * the full coin contents (coinbase flag, height, each output's value
 * and spend-availability). This guards against an (astronomically
 * unlikely) commitment collision masking a real divergence. */
static bool coins_identical(struct coins_view_cache *x,
                            struct coins_view_cache *y,
                            const struct uint256 *txid)
{
    bool hx = coins_view_cache_have_coins(x, txid);
    bool hy = coins_view_cache_have_coins(y, txid);
    if (hx != hy) return false;
    if (!hx) return true;

    struct coins cx, cy;
    coins_init(&cx);
    coins_init(&cy);
    bool ok = coins_view_cache_get_coins(x, txid, &cx) &&
              coins_view_cache_get_coins(y, txid, &cy);
    if (ok) {
        ok = (cx.is_coinbase == cy.is_coinbase) &&
             (cx.height == cy.height) &&
             (cx.num_vout == cy.num_vout);
        for (size_t i = 0; ok && i < cx.num_vout; i++) {
            bool ax = coins_is_available(&cx, (unsigned)i);
            bool ay = coins_is_available(&cy, (unsigned)i);
            ok = (ax == ay);
            if (ok && ax)
                ok = (cx.vout[i].value == cy.vout[i].value);
        }
    }
    coins_free(&cx);
    coins_free(&cy);
    return ok;
}

/* ── Test implementation ─────────────────────────────────────── */

int test_reorg_parity(void)
{
    printf("\n=== reorg parity test (byte-exact unwind) ===\n");
    int failures = 0;

    /* ── Shared genesis fork point (height 0) ─────────────────── */

    struct transaction g_cb = make_coinbase_seeded(0, 0x00);
    struct block genesis;
    struct uint256 g_hash;
    struct transaction g_txs[1] = { g_cb };
    make_block_txs(&genesis, 0, NULL, 0x00, g_txs, 1);
    block_header_get_hash(&genesis.header, &g_hash);
    struct uint256 g_cb_hash = genesis.vtx[0].hash;

    /* ── Branch A: H+1..H+3 ───────────────────────────────────
     *   A1: coinbase (seed 0x10)
     *   A2: coinbase + spend of A1's coinbase output (n=0)
     *   A3: coinbase
     */
    struct block a_blk[4];   /* index by height: a_blk[1..3] */
    struct uint256 a_hash[4];
    a_hash[0] = g_hash;

    /* A1 */
    {
        struct transaction txs[1] = { make_coinbase_seeded(1, 0x10) };
        make_block_txs(&a_blk[1], 1, &a_hash[0], 0x10, txs, 1);
        block_header_get_hash(&a_blk[1].header, &a_hash[1]);
    }
    struct uint256 a1_cb_hash = a_blk[1].vtx[0].hash;

    /* A2: coinbase + spend A1 coinbase output 0 */
    {
        struct transaction cb = make_coinbase_seeded(2, 0x11);
        struct transaction sp = make_spend(&a1_cb_hash, 0, 900000000LL, 0x1A);
        struct transaction txs[2] = { cb, sp };
        make_block_txs(&a_blk[2], 2, &a_hash[1], 0x11, txs, 2);
        block_header_get_hash(&a_blk[2].header, &a_hash[2]);
    }

    /* A3 */
    {
        struct transaction txs[1] = { make_coinbase_seeded(3, 0x12) };
        make_block_txs(&a_blk[3], 3, &a_hash[2], 0x12, txs, 1);
        block_header_get_hash(&a_blk[3].header, &a_hash[3]);
    }

    /* ── Branch B: H+1..H+4 (heavier, divergent spends) ────────
     *   B1: coinbase (seed 0x20)
     *   B2: coinbase + spend of the SHARED genesis coinbase output
     *       (something branch A never spent — divergent pattern)
     *   B3: coinbase
     *   B4: coinbase
     */
    struct block b_blk[5];   /* index by height: b_blk[1..4] */
    struct uint256 b_hash[5];
    b_hash[0] = g_hash;

    /* B1 */
    {
        struct transaction txs[1] = { make_coinbase_seeded(1, 0x20) };
        make_block_txs(&b_blk[1], 1, &b_hash[0], 0x20, txs, 1);
        block_header_get_hash(&b_blk[1].header, &b_hash[1]);
    }

    /* B2: coinbase + spend genesis coinbase output 0 */
    {
        struct transaction cb = make_coinbase_seeded(2, 0x21);
        struct transaction sp = make_spend(&g_cb_hash, 0, 950000000LL, 0x2B);
        struct transaction txs[2] = { cb, sp };
        make_block_txs(&b_blk[2], 2, &b_hash[1], 0x21, txs, 2);
        block_header_get_hash(&b_blk[2].header, &b_hash[2]);
    }

    /* B3 */
    {
        struct transaction txs[1] = { make_coinbase_seeded(3, 0x22) };
        make_block_txs(&b_blk[3], 3, &b_hash[2], 0x22, txs, 1);
        block_header_get_hash(&b_blk[3].header, &b_hash[3]);
    }

    /* B4 */
    {
        struct transaction txs[1] = { make_coinbase_seeded(4, 0x23) };
        make_block_txs(&b_blk[4], 4, &b_hash[3], 0x23, txs, 1);
        block_header_get_hash(&b_blk[4].header, &b_hash[4]);
    }

    /* block_index records needed by disconnect_block (height + pprev). */
    struct block_index gi;
    block_index_init(&gi);
    gi.nHeight = 0;
    gi.phashBlock = &a_hash[0];

    struct block_index a_idx[4];
    for (int h = 1; h <= 3; h++) {
        block_index_init(&a_idx[h]);
        a_idx[h].nHeight = h;
        a_idx[h].phashBlock = &a_hash[h];
        a_idx[h].pprev = (h == 1) ? &gi : &a_idx[h - 1];
    }

    struct block_index b_idx[5];
    for (int h = 1; h <= 4; h++) {
        block_index_init(&b_idx[h]);
        b_idx[h].nHeight = h;
        b_idx[h].phashBlock = &b_hash[h];
        b_idx[h].pprev = (h == 1) ? &gi : &b_idx[h - 1];
    }

    /* ── VIEW 1: build A, then reorg to B ─────────────────────── */

    struct coins_view_cache v_reorg;
    struct coins_view nv1;
    memset(&nv1, 0, sizeof(nv1));
    coins_view_cache_init(&v_reorg, &nv1);
    update_coins(&genesis.vtx[0], &v_reorg, 0);

    struct block_undo a_undo[4];
    bool built_a = true;
    for (int h = 1; h <= 3 && built_a; h++)
        built_a = connect_block_with_undo(&a_blk[h], h, &v_reorg, &a_undo[h]);
    RP_CHECK("parity: branch A connects (with spend in A2)", built_a);

    /* Disconnect A3..A1 (reverse order), reversing each block's undo. */
    bool unwound = true;
    for (int h = 3; h >= 1 && unwound; h--) {
        struct validation_state vs;
        validation_state_init(&vs);
        unwound = disconnect_block(&a_blk[h], &vs, &a_idx[h],
                                   &v_reorg, &a_undo[h]);
    }
    RP_CHECK("parity: branch A fully disconnects back to fork point",
             unwound);

    for (int h = 1; h <= 3; h++)
        block_undo_free(&a_undo[h]);

    /* Connect heavier branch B onto the unwound view. */
    struct block_undo b_undo_r[5];
    bool reapplied = true;
    for (int h = 1; h <= 4 && reapplied; h++)
        reapplied = connect_block_with_undo(&b_blk[h], h, &v_reorg,
                                            &b_undo_r[h]);
    RP_CHECK("parity: branch B connects after reorg", reapplied);

    /* ── VIEW 2: build B directly from genesis, never seeing A ── */

    struct coins_view_cache v_direct;
    struct coins_view nv2;
    memset(&nv2, 0, sizeof(nv2));
    coins_view_cache_init(&v_direct, &nv2);
    update_coins(&genesis.vtx[0], &v_direct, 0);

    struct block_undo b_undo_d[5];
    bool direct = true;
    for (int h = 1; h <= 4 && direct; h++)
        direct = connect_block_with_undo(&b_blk[h], h, &v_direct,
                                         &b_undo_d[h]);
    RP_CHECK("parity: branch B builds directly from fork point", direct);

    /* Candidate txid universe: every coinbase + spend output either path
     * could have created. The recomputed (path-independent) commitment is
     * XOR'd over exactly the still-available outputs among these. */
    struct uint256 universe[16];
    size_t nu = 0;
    universe[nu++] = g_cb_hash;                  /* genesis coinbase */
    universe[nu++] = a1_cb_hash;                 /* A1 coinbase */
    universe[nu++] = a_blk[2].vtx[0].hash;       /* A2 coinbase */
    universe[nu++] = a_blk[2].vtx[1].hash;       /* A2 spend output */
    universe[nu++] = a_blk[3].vtx[0].hash;       /* A3 coinbase */
    for (int h = 1; h <= 4; h++)
        universe[nu++] = b_blk[h].vtx[0].hash;   /* B1..B4 coinbases */
    universe[nu++] = b_blk[2].vtx[1].hash;       /* B2 spend output */

    /* ── CORE PARITY PROOF (byte-exact UTXO set) ───────────────
     * The reorged view (A -> unwind -> B) must hold a byte-identical coin
     * SET to the direct-built B, via the path-independent recomputed
     * commitment. */

    struct utxo_commitment c_reorg, c_direct;
    recompute_commitment(&v_reorg, universe, nu, &c_reorg);
    recompute_commitment(&v_direct, universe, nu, &c_direct);

    RP_CHECK("parity: recomputed UTXO commitment matches (byte-exact set)",
             utxo_commitment_equal(&c_reorg, &c_direct));
    RP_CHECK("parity: recomputed UTXO count matches",
             c_reorg.count == c_direct.count);

    /* ── PATH-INDEPENDENCE ─────────────────────────────────────────
     * coins_view_cache_recompute_commitment() derives the fingerprint from
     * the live coin SET: the reorged view and the direct-built B must query
     * IDENTICAL commitment + count, each equal to the universe recompute
     * above; the stale incremental accumulator is never read. */
    struct utxo_commitment q_reorg, q_direct;
    coins_view_cache_recompute_commitment(&v_reorg, &q_reorg);
    coins_view_cache_recompute_commitment(&v_direct, &q_direct);

    RP_CHECK("parity: queried commitment is path-independent "
             "(reorg view == direct view)",
             utxo_commitment_equal(&q_reorg, &q_direct));
    RP_CHECK("parity: queried count is path-independent",
             q_reorg.count == q_direct.count);
    /* The production query and the independent universe-driven recompute
     * must agree — neither leaks nor drops a coin. */
    RP_CHECK("parity: production query == universe recompute (reorg view)",
             utxo_commitment_equal(&q_reorg, &c_reorg) &&
             q_reorg.count == c_reorg.count);
    RP_CHECK("parity: production query == universe recompute (direct view)",
             utxo_commitment_equal(&q_direct, &c_direct) &&
             q_direct.count == c_direct.count);

    /* Diagnostic, not a gate: the incremental accumulator on the reorged
     * view differs from the recompute (it keeps A's unwound entries), so
     * only the recompute is trusted across a reorg. */
    if (!utxo_commitment_equal(&v_reorg.commitment, &q_reorg)) {
        printf("[confirmed] stale incremental accumulator differs from "
               "authoritative recompute after reorg: incremental.count=%llu "
               "recompute.count=%llu (disconnect_block does not decrement the "
               "accumulator; the query recomputes from the coin set)\n",
               (unsigned long long)v_reorg.commitment.count,
               (unsigned long long)q_reorg.count);
    }

    /* ── FORWARD-ONLY VALUE UNCHANGED (snapshot compatibility) ─────
     * v_direct was built forward-only, so its incremental accumulator IS
     * the authoritative value; the recompute must return the same value
     * byte-for-byte (persisted snapshots are pinned to it). */
    RP_CHECK("parity: forward-only incremental == recompute (byte-exact)",
             utxo_commitment_equal(&v_direct.commitment, &q_direct) &&
             v_direct.commitment.count == q_direct.count);

    /* Per-outpoint: genesis coinbase (spent in B2 on both paths). */
    RP_CHECK("parity: genesis coinbase identical in both views",
             coins_identical(&v_reorg, &v_direct, &g_cb_hash));

    /* Each B coinbase identical in both views. */
    {
        bool ok = true;
        for (int h = 1; h <= 4; h++)
            ok = ok && coins_identical(&v_reorg, &v_direct,
                                       &b_blk[h].vtx[0].hash);
        RP_CHECK("parity: every branch-B coinbase identical in both views",
                 ok);
    }

    /* B2's spend output identical in both views. */
    RP_CHECK("parity: B2 spend output identical in both views",
             coins_identical(&v_reorg, &v_direct, &b_blk[2].vtx[1].hash));

    /* ── NO LEAK: branch A's outputs must be ABSENT after reorg ──
     * A1/A3 coinbases and A2's spend output must not exist in the reorged
     * view (B never re-created them). */
    {
        bool gone = !coins_view_cache_have_coins(&v_reorg, &a1_cb_hash) &&
                    !coins_view_cache_have_coins(&v_reorg,
                                                 &a_blk[2].vtx[0].hash) &&
                    !coins_view_cache_have_coins(&v_reorg,
                                                 &a_blk[2].vtx[1].hash) &&
                    !coins_view_cache_have_coins(&v_reorg,
                                                 &a_blk[3].vtx[0].hash);
        RP_CHECK("parity: no branch-A coin leaks into reorged view", gone);
        /* Same absence in the direct view (sanity: B never created them). */
        bool gone_d = !coins_view_cache_have_coins(&v_direct, &a1_cb_hash) &&
                      !coins_view_cache_have_coins(&v_direct,
                                                   &a_blk[2].vtx[1].hash);
        RP_CHECK("parity: direct-build view also free of branch-A coins",
                 gone_d);
    }

    /* ── IDEMPOTENT BACK-AND-FORTH: A→B→A→B == direct B ────────
     * Cycle twice on a fresh view, ending on B; state must equal the
     * direct-built B. */
    {
        struct coins_view_cache v_cyc;
        struct coins_view nvc;
        memset(&nvc, 0, sizeof(nvc));
        coins_view_cache_init(&v_cyc, &nvc);
        update_coins(&genesis.vtx[0], &v_cyc, 0);

        bool ok = true;
        for (int cycle = 0; cycle < 2 && ok; cycle++) {
            /* Connect A */
            struct block_undo au[4];
            for (int h = 1; h <= 3 && ok; h++)
                ok = connect_block_with_undo(&a_blk[h], h, &v_cyc, &au[h]);
            /* Disconnect A */
            for (int h = 3; h >= 1 && ok; h--) {
                struct validation_state vs;
                validation_state_init(&vs);
                ok = disconnect_block(&a_blk[h], &vs, &a_idx[h],
                                      &v_cyc, &au[h]);
            }
            for (int h = 1; h <= 3; h++)
                block_undo_free(&au[h]);

            /* Connect B */
            struct block_undo bu[5];
            for (int h = 1; h <= 4 && ok; h++)
                ok = connect_block_with_undo(&b_blk[h], h, &v_cyc, &bu[h]);
            /* Disconnect B (unless final cycle: leave B applied) */
            if (cycle < 1) {
                for (int h = 4; h >= 1 && ok; h--) {
                    struct validation_state vs;
                    validation_state_init(&vs);
                    ok = disconnect_block(&b_blk[h], &vs, &b_idx[h],
                                          &v_cyc, &bu[h]);
                }
            }
            for (int h = 1; h <= 4; h++)
                block_undo_free(&bu[h]);
        }
        RP_CHECK("parity: A->B->A->B cycle succeeds", ok);

        /* The recomputed commitment after two back-and-forth cycles equals
         * the direct-built B: no residue in the coin set. */
        struct utxo_commitment c_cyc, c_dir2;
        recompute_commitment(&v_cyc, universe, nu, &c_cyc);
        recompute_commitment(&v_direct, universe, nu, &c_dir2);
        RP_CHECK("parity: cycled recomputed commitment == direct-build",
                 ok && utxo_commitment_equal(&c_cyc, &c_dir2));
        RP_CHECK("parity: cycled recomputed count == direct-build count",
                 ok && c_cyc.count == c_dir2.count);

        /* Same invariant through the PRODUCTION query. */
        struct utxo_commitment q_cyc, q_dir2;
        coins_view_cache_recompute_commitment(&v_cyc, &q_cyc);
        coins_view_cache_recompute_commitment(&v_direct, &q_dir2);
        RP_CHECK("parity: cycled queried commitment == direct-build "
                 "(path-independent after 2 cycles)",
                 ok && utxo_commitment_equal(&q_cyc, &q_dir2) &&
                 q_cyc.count == q_dir2.count);

        /* And every outpoint in the universe is identical between the
         * cycled view and the direct build. */
        {
            bool same = true;
            for (size_t t = 0; t < nu && same; t++)
                same = coins_identical(&v_cyc, &v_direct, &universe[t]);
            RP_CHECK("parity: every outpoint identical after 2 cycles",
                     ok && same);
        }

        coins_view_cache_free(&v_cyc);
    }

    /* ── ADVERSARIAL #1: in-block create+spend rolled back ─────────
     * Block X creates a UTXO (tx1 spends genesis -> O1) and spends it (tx2
     * O1 -> O2). Disconnecting X must undo tx2 first, then tx1, yielding a
     * coin set BYTE-EXACT with the pre-block state (genesis unspent, O1 and
     * O2 absent). */
    {
        struct coins_view_cache v_pre, v_post;
        struct coins_view nvp1, nvp2;
        memset(&nvp1, 0, sizeof(nvp1));
        memset(&nvp2, 0, sizeof(nvp2));
        coins_view_cache_init(&v_pre, &nvp1);
        coins_view_cache_init(&v_post, &nvp2);

        /* Both views start at the same pre-block state: genesis only. */
        update_coins(&genesis.vtx[0], &v_pre, 0);
        update_coins(&genesis.vtx[0], &v_post, 0);

        /* Baseline fingerprint of the pre-block state (genesis present). */
        struct utxo_commitment c_pre_baseline;
        coins_view_cache_recompute_commitment(&v_pre, &c_pre_baseline);

        /* Block X at height 1: coinbase + tx1(genesis->O1) + tx2(O1->O2).
         * tx1 spends genesis output 0; tx2 spends tx1's output 0. */
        struct transaction xcb = make_coinbase_seeded(1, 0x31);
        struct transaction xt1 = make_spend(&g_cb_hash, 0, 800000000LL, 0x3A);
        struct uint256 o1_hash = xt1.hash;
        struct transaction xt2 = make_spend(&o1_hash, 0, 700000000LL, 0x3B);
        struct uint256 o2_hash = xt2.hash;
        struct uint256 xcb_hash = xcb.hash;

        struct transaction xtxs[3] = { xcb, xt1, xt2 };
        struct block x_blk;
        make_block_txs(&x_blk, 1, &g_hash, 0x31, xtxs, 3);
        struct uint256 x_hash;
        block_header_get_hash(&x_blk.header, &x_hash);

        struct block_index x_idx;
        block_index_init(&x_idx);
        x_idx.nHeight = 1;
        x_idx.phashBlock = &x_hash;
        x_idx.pprev = &gi;

        struct block_undo x_undo;
        bool x_built = connect_block_with_undo(&x_blk, 1, &v_post, &x_undo);
        RP_CHECK("adversarial1: in-block create+spend block connects", x_built);

        /* After connect: genesis spent, O1 spent, O2 present, coinbase present. */
        RP_CHECK("adversarial1: genesis consumed by in-block tx1",
                 !coins_view_cache_have_coins(&v_post, &g_cb_hash));
        RP_CHECK("adversarial1: O1 created-then-spent within the block (absent)",
                 !coins_view_cache_have_coins(&v_post, &o1_hash));
        RP_CHECK("adversarial1: O2 (final spend output) present after connect",
                 coins_view_cache_have_coins(&v_post, &o2_hash));

        /* Disconnect block X — single-block reorg of an intra-block chain. */
        struct validation_state xvs;
        validation_state_init(&xvs);
        bool x_undone = x_built &&
            disconnect_block(&x_blk, &xvs, &x_idx, &v_post, &x_undo);
        RP_CHECK("adversarial1: in-block create+spend block disconnects",
                 x_undone);

        /* Post-disconnect coin set must be BYTE-EXACT with the pre-block state. */
        struct utxo_commitment c_post_unwind;
        coins_view_cache_recompute_commitment(&v_post, &c_post_unwind);
        RP_CHECK("adversarial1: unwound set byte-exact vs pre-block "
                 "(commitment)",
                 x_undone &&
                 utxo_commitment_equal(&c_post_unwind, &c_pre_baseline) &&
                 c_post_unwind.count == c_pre_baseline.count);

        /* Genesis restored & unspent; O1/O2/coinbase gone (created on X only). */
        RP_CHECK("adversarial1: genesis restored after disconnect",
                 x_undone && coins_identical(&v_post, &v_pre, &g_cb_hash));
        RP_CHECK("adversarial1: O1 absent after disconnect",
                 x_undone && !coins_view_cache_have_coins(&v_post, &o1_hash));
        RP_CHECK("adversarial1: O2 absent after disconnect",
                 x_undone && !coins_view_cache_have_coins(&v_post, &o2_hash));
        RP_CHECK("adversarial1: block-X coinbase absent after disconnect",
                 x_undone && !coins_view_cache_have_coins(&v_post, &xcb_hash));

        block_undo_free(&x_undo);
        free_block(&x_blk);
        coins_view_cache_free(&v_pre);
        coins_view_cache_free(&v_post);
    }

    /* ── ADVERSARIAL #2: spend/unspend symmetry across a reorg ─────
     * The old tip (branch S) SPENDS a pre-fork output; the winning fork
     * (branch U) does not. After the reorg the pre-fork output must be
     * UNSPENT again and byte-exact with a direct build of U (the "restored
     * input -> ADD" disconnect path).
     *
     * Fork point: a 2-output funding coinbase F at height 0 (its output 1 is
     * the contested coin). Branch S (height 1) spends F:1. Branch U (heights
     * 1..2, heavier) leaves F:1 untouched. */
    {
        /* Funding coinbase with TWO outputs so F:1 is an ordinary (non-
         * coinbase-output-0) spendable target distinct from the chain genesis. */
        struct transaction fcb;
        memset(&fcb, 0, sizeof(fcb));
        fcb.version = 1;
        fcb.num_vin = 1;
        fcb.vin = zcl_calloc(1, sizeof(struct tx_in), "rp_fcb_vin");
        uint8_t fsig[6] = {4, 0, 0, 0, 0, 0x40};
        script_set(&fcb.vin[0].script_sig, fsig, 6);
        uint256_set_null(&fcb.vin[0].prevout.hash);
        fcb.vin[0].prevout.n = 0xFFFFFFFF;
        fcb.vin[0].sequence = 0xFFFFFFFF;
        fcb.num_vout = 2;
        fcb.vout = zcl_calloc(2, sizeof(struct tx_out), "rp_fcb_vout");
        fcb.vout[0].value = 500000000LL;
        fcb.vout[1].value = 400000000LL;
        uint8_t fpk[3] = {0x76, 0xa9, 0x14};
        script_set(&fcb.vout[0].script_pub_key, fpk, 3);
        script_set(&fcb.vout[1].script_pub_key, fpk, 3);
        transaction_compute_hash(&fcb);
        struct uint256 f_hash = fcb.hash;

        struct block fgen;
        struct transaction fgtx[1] = { fcb };
        make_block_txs(&fgen, 0, NULL, 0x40, fgtx, 1);
        struct uint256 fg_hash;
        block_header_get_hash(&fgen.header, &fg_hash);

        struct block_index fgi;
        block_index_init(&fgi);
        fgi.nHeight = 0;
        fgi.phashBlock = &fg_hash;

        /* Branch S (height 1): coinbase + spend of F:1 (the contested coin). */
        struct uint256 s_hash;
        struct transaction scb = make_coinbase_seeded(1, 0x41);
        struct transaction ssp = make_spend(&f_hash, 1, 350000000LL, 0x4A);
        struct uint256 ssp_out = ssp.hash;
        struct transaction stxs[2] = { scb, ssp };
        struct block s_blk;
        make_block_txs(&s_blk, 1, &fg_hash, 0x41, stxs, 2);
        block_header_get_hash(&s_blk.header, &s_hash);
        struct block_index s_idx;
        block_index_init(&s_idx);
        s_idx.nHeight = 1;
        s_idx.phashBlock = &s_hash;
        s_idx.pprev = &fgi;

        /* Branch U (heights 1..2, heavier): coinbases only — F:1 untouched. */
        struct block u_blk[3];
        struct uint256 u_hash[3];
        u_hash[0] = fg_hash;
        {
            struct transaction txs[1] = { make_coinbase_seeded(1, 0x51) };
            make_block_txs(&u_blk[1], 1, &u_hash[0], 0x51, txs, 1);
            block_header_get_hash(&u_blk[1].header, &u_hash[1]);
        }
        {
            struct transaction txs[1] = { make_coinbase_seeded(2, 0x52) };
            make_block_txs(&u_blk[2], 2, &u_hash[1], 0x52, txs, 1);
            block_header_get_hash(&u_blk[2].header, &u_hash[2]);
        }

        /* Reorg view: connect S (spends F:1), disconnect S, connect U. */
        struct coins_view_cache v_sym;
        struct coins_view nvs;
        memset(&nvs, 0, sizeof(nvs));
        coins_view_cache_init(&v_sym, &nvs);
        update_coins(&fcb, &v_sym, 0);

        /* F:1 spendable before S. */
        struct coins fc_before;
        coins_init(&fc_before);
        bool f1_avail_before =
            coins_view_cache_get_coins(&v_sym, &f_hash, &fc_before) &&
            fc_before.num_vout > 1 && coins_is_available(&fc_before, 1);
        coins_free(&fc_before);
        RP_CHECK("adversarial2: contested output F:1 available pre-reorg",
                 f1_avail_before);

        struct block_undo s_undo;
        bool s_ok = connect_block_with_undo(&s_blk, 1, &v_sym, &s_undo);
        RP_CHECK("adversarial2: branch S connects (spends F:1)", s_ok);
        /* F:1 now spent. */
        {
            struct coins fc;
            coins_init(&fc);
            bool spent = coins_view_cache_get_coins(&v_sym, &f_hash, &fc) &&
                         !coins_is_available(&fc, 1);
            coins_free(&fc);
            RP_CHECK("adversarial2: F:1 spent after branch S", s_ok && spent);
        }

        struct validation_state svs;
        validation_state_init(&svs);
        bool s_undone = s_ok &&
            disconnect_block(&s_blk, &svs, &s_idx, &v_sym, &s_undo);
        RP_CHECK("adversarial2: branch S disconnects (unspends F:1)", s_undone);

        struct block_undo u_undo_r[3];
        bool u_ok = s_undone;
        for (int h = 1; h <= 2 && u_ok; h++)
            u_ok = connect_block_with_undo(&u_blk[h], h, &v_sym, &u_undo_r[h]);
        RP_CHECK("adversarial2: heavier branch U connects after reorg", u_ok);

        /* Direct build of U from the same funding point — never saw S. */
        struct coins_view_cache v_symd;
        struct coins_view nvsd;
        memset(&nvsd, 0, sizeof(nvsd));
        coins_view_cache_init(&v_symd, &nvsd);
        update_coins(&fcb, &v_symd, 0);
        struct block_undo u_undo_d[3];
        bool ud_ok = true;
        for (int h = 1; h <= 2 && ud_ok; h++)
            ud_ok = connect_block_with_undo(&u_blk[h], h, &v_symd, &u_undo_d[h]);
        RP_CHECK("adversarial2: branch U builds directly", ud_ok);

        /* THE SYMMETRY PROOF: reorged view (spent then unspent) == direct
         * build (never spent), byte-exact over the whole coin set. */
        struct utxo_commitment q_sym, q_symd;
        coins_view_cache_recompute_commitment(&v_sym, &q_sym);
        coins_view_cache_recompute_commitment(&v_symd, &q_symd);
        RP_CHECK("adversarial2: reorged (unspend) == direct (never-spent) "
                 "byte-exact",
                 u_ok && ud_ok &&
                 utxo_commitment_equal(&q_sym, &q_symd) &&
                 q_sym.count == q_symd.count);

        /* F:1 restored to UNSPENT and identical to the direct build. */
        {
            struct coins fc;
            coins_init(&fc);
            bool restored =
                coins_view_cache_get_coins(&v_sym, &f_hash, &fc) &&
                fc.num_vout > 1 && coins_is_available(&fc, 1) &&
                fc.vout[1].value == 400000000LL;
            coins_free(&fc);
            RP_CHECK("adversarial2: F:1 restored UNSPENT after reorg",
                     u_ok && restored);
        }
        RP_CHECK("adversarial2: funding coin identical in both views",
                 u_ok && ud_ok && coins_identical(&v_sym, &v_symd, &f_hash));
        /* The abandoned S spend output must NOT leak into the reorged view. */
        RP_CHECK("adversarial2: branch-S spend output absent after reorg",
                 u_ok && !coins_view_cache_have_coins(&v_sym, &ssp_out));

        if (s_ok) block_undo_free(&s_undo);
        for (int h = 1; h <= 2; h++) {
            if (u_ok) block_undo_free(&u_undo_r[h]);
            if (ud_ok) block_undo_free(&u_undo_d[h]);
        }
        coins_view_cache_free(&v_sym);
        coins_view_cache_free(&v_symd);
        free_block(&s_blk);
        for (int h = 1; h <= 2; h++)
            free_block(&u_blk[h]);
        free_block(&fgen);
    }

    /* ── Cleanup ──────────────────────────────────────────────── */

    for (int h = 1; h <= 4; h++) {
        block_undo_free(&b_undo_r[h]);
        block_undo_free(&b_undo_d[h]);
    }

    coins_view_cache_free(&v_reorg);
    coins_view_cache_free(&v_direct);

    free_block(&genesis);
    for (int h = 1; h <= 3; h++)
        free_block(&a_blk[h]);
    for (int h = 1; h <= 4; h++)
        free_block(&b_blk[h]);
    (void)free_tx;

    printf("=== reorg parity: %d failures ===\n", failures);
    return failures;
}
