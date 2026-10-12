/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

/* Sapling tree rebuild support for the sync controller.
 *
 * This file owns the long-running replay that rebuilds the persisted
 * Sapling commitment tree from block files. */

#include "controllers/sync_controller.h"
#include "sync_controller_internal.h"

#include "chain/chain.h"
#include "core/serialize.h"
#include "core/uint256.h"
#include "core/utiltime.h"
#include "jobs/reducer_frontier.h"
#include "models/database.h"
#include "primitives/block.h"
#include "sapling/incremental_merkle_tree.h"
#include "services/block_index_loader.h"
#include "supervisors/domains.h"
#include "util/blocker.h"
#include "util/boot_progress.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"
#include "util/supervisor.h"
#include "util/thread_registry.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"
#include "validation/process_block.h"

#include <sqlite3.h>
#include <stdatomic.h>
#include <string.h>
#include <time.h>

/* The BEGIN-retry + atomic (tree-blob, height) persist machinery lives in
 * sync_controller_sapling_tree_persist.c (enum sapling_persist_status +
 * sapling_tree_persist_pair_status declared in sync_controller_internal.h). */

/* The FINAL persist bounded-retries a DEFERRED result, yielding between
 * attempts so the reducer can commit its batch and return to autocommit. The
 * per-100k checkpoint persists never wait — a deferred checkpoint is skipped
 * and re-attempted at the next checkpoint / the final persist. */
#define SAPLING_TREE_FINAL_PERSIST_ATTEMPTS  8
#define SAPLING_TREE_FINAL_PERSIST_BACKOFF_MS 125

/* Heartbeat cadence for the supervised rebuild: every 60s. */
#define SAPLING_TREE_REBUILD_HEARTBEAT_MS 60000

/* ── Supervision (platform/modules/util/include/util/supervisor.h contract) ───────────
 * The rebuild runs synchronously on WHATEVER thread invokes it (boot's own
 * thread, an RPC thread for `rebuildsaplingtree`, or a dedicated deferred
 * worker — see engine/composition/src/boot.c). Registering a liveness contract makes a
 * hung invocation a named stall (the supervisor thread notices
 * last_tick_us going stale). One contract is shared across
 * invocations (registered once, re-armed at the top of every call). */
static struct liveness_contract g_sapling_rebuild_contract;
static _Atomic supervisor_child_id g_sapling_rebuild_sup_id =
    SUPERVISOR_INVALID_ID;

static supervisor_child_id sapling_tree_rebuild_supervisor_ensure(void)
{
    supervisor_child_id id = atomic_load(&g_sapling_rebuild_sup_id);
    if (id != SUPERVISOR_INVALID_ID)
        return id;
    if (!supervisor_start())
        return SUPERVISOR_INVALID_ID;

    liveness_contract_init(&g_sapling_rebuild_contract,
                           "sync.sapling_tree_rebuild");
    /* Self-driven (period_secs=0): the replay loop ticks itself every
     * ~60s. deadline_secs is headroom over the worst-case persist-retry
     * stall (6 attempts * up to ~1.2s backoff, each behind a 10s sqlite
     * busy_timeout) so only a genuinely stuck loop fires the stall. */
    atomic_store(&g_sapling_rebuild_contract.deadline_secs, 180);
    atomic_store(&g_sapling_rebuild_contract.progress_max_quiet_us, 0);

    supervisor_domains_init();
    supervisor_child_id new_id = supervisor_register_in_domain(
        g_chain_sup, &g_sapling_rebuild_contract);
    if (new_id == SUPERVISOR_INVALID_ID)
        return SUPERVISOR_INVALID_ID;

    supervisor_child_id expected = SUPERVISOR_INVALID_ID;
    if (!atomic_compare_exchange_strong(&g_sapling_rebuild_sup_id, &expected,
                                        new_id)) {
        /* Lost a registration race against a concurrent invocation —
         * unregister the duplicate and use the winner's id. */
        supervisor_unregister(new_id);
        return atomic_load(&g_sapling_rebuild_sup_id);
    }
    return new_id;
}

/* Never silent: even a tolerated header-tip-tail skip is summarized so an
 * operator can see exactly how many blocks — and of which class — were not
 * folded, and over what height span. On the coins-applied endpoint a nonzero
 * tally never reaches here (any skip already fail-closed at its height). */
static void sapling_rebuild_log_skip_summary(
        int skipped_no_index, int skipped_no_data, int skipped_no_mmap,
        int skipped_datapos_oob, int skipped_deserialize,
        int first_skip_height, int last_skip_height,
        bool endpoint_is_coins_applied)
{
    int total_skipped = skipped_no_index + skipped_no_data + skipped_no_mmap +
                        skipped_datapos_oob + skipped_deserialize;
    if (total_skipped <= 0)
        return;
    LOG_WARN("sapling_tree_rebuild",
            "sapling_tree_rebuild: skip summary total=%d "
            "no_index=%d no_data=%d no_mmap=%d datapos_oob=%d "
            "deserialize=%d span=[%d..%d] endpoint=%s",
            total_skipped, skipped_no_index, skipped_no_data,
            skipped_no_mmap, skipped_datapos_oob, skipped_deserialize,
            first_skip_height, last_skip_height,
            endpoint_is_coins_applied ? "coins_applied" : "header_tip");
}

/* Shutdown responsiveness: the deferred rebuild can replay for HOURS on a
 * multi-million-block range; a rebuild that never polls the registry
 * shutdown flag keeps its thread alive past the orderly-shutdown join until
 * the external grace SIGKILLs the process — an unclean stop. The replay
 * loop polls this alongside its every-100 boot-progress tick (one cheap
 * atomic load, ≤100-block latency). */
static bool sapling_tree_rebuild_shutdown_requested(void)
{
    return thread_registry_shutdown_requested();
}

int sapling_tree_rebuild(struct node_db *ndb,
                         const struct active_chain *chain,
                         const char *datadir)
{
    if (!ndb || !chain || !datadir)
        LOG_ERR("sync", "sapling_tree_rebuild: invalid args (ndb=%p, chain=%p, datadir=%p)",
                (void *)ndb, (void *)chain, (void *)datadir);

    int header_tip = active_chain_height(chain);
    int sapling_height = 476969; /* ZClassic Sapling activation */

    /* Resolve the rebuild endpoint from coins-applied state, not the
     * header tip: the persisted hashFinalSaplingRoot above the applied
     * frontier may be absent, so verifying against the header tip would
     * FATAL on `tip_missing_sapling_root`. Cap the endpoint to coins-best
     * (coins_applied_height - 1) when present and lower than the header tip;
     * that block was applied, so its body is on disk and its root is known.
     * When the coins frontier is absent the header tip is kept; the
     * per-block replay skips header-only (non-HAVE_DATA) blocks. */
    int chain_tip = header_tip;
    /* When the endpoint is the coins-applied frontier, every block in
     * [sapling_height, chain_tip] has been APPLIED — its body is on disk and
     * its data position is valid — so a per-block skip (below) is a real local
     * defect worth failing-closed AT that height, not a legitimate header-only
     * tail. Stays false for the legacy/header-tip endpoint. */
    bool endpoint_is_coins_applied = false;
    {
        int32_t coins_best = -1;
        if (reducer_frontier_derive_coins_best_now(&coins_best, NULL, NULL)
            && coins_best >= 0 && coins_best < chain_tip) {
            LOG_INFO("sapling_tree_rebuild",
                     "sapling_tree_rebuild: capping endpoint to coins-applied "
                     "height %d (header tip %d)", coins_best, header_tip);
            chain_tip = coins_best;
            endpoint_is_coins_applied = true;
        }
    }

    if (chain_tip < sapling_height) return 0;

    supervisor_child_id sup_id = sapling_tree_rebuild_supervisor_ensure();
    if (sup_id != SUPERVISOR_INVALID_ID) {
        atomic_store(&g_sapling_rebuild_contract.completed, false);
        atomic_store(&g_sapling_rebuild_contract.deadline_secs, 180);
        supervisor_progress(sup_id, 0);
        supervisor_tick(sup_id);
    }
    int64_t last_heartbeat_ms = GetTimeMillis();

    struct incremental_merkle_tree tree;
    sapling_tree_init(&tree);
    int total_commitments = 0;
    int mismatches = 0;
    int start_height = sapling_height;
    const char *fail_reason = NULL;
    int fail_height = -1;

    /* Typed skip accounting — one counter per class so a dropped-block gap is
     * never silent (see sapling_rebuild_account_skip). */
    int skipped_no_index = 0;
    int skipped_no_data = 0;
    int skipped_no_mmap = 0;
    int skipped_datapos_oob = 0;
    int skipped_deserialize = 0;
    int first_skip_height = -1;
    int last_skip_height = -1;

    /* Try to resume from a persisted frontier to avoid a full replay
     * on crash recovery. Three candidates, most
     * authoritative first:
     *   (0) anchor_kv's sapling_anchors frontier — the CANONICAL ledger
     *       fold_sapling writes and root-verifies per block (see
     *       sapling_rebuild_anchor_seed in
     *       sync_controller_sapling_tree_resume.c).
     *   (1) Flat-file checkpoint at <datadir>/sapling_tree_ckpt.dat
     *       flushed every 10K blocks, SHA3-verified.
     *   (2) node_state["sapling_tree"] - flushed every 100K blocks,
     *       SQLite-backed, legacy path.
     * Each hit short-circuits the ones below it; every miss falls through.
     * All three bind fail-closed to the header chain before being trusted. */
    int64_t ckpt_h = 0;
    {
        struct incremental_merkle_tree akv_tree;
        int64_t akv_h = -1;
        if (sapling_rebuild_anchor_seed(chain, chain_tip, sapling_height,
                                        &akv_tree, &akv_h)) {
            tree = akv_tree;
            start_height = (int)akv_h + 1;
            total_commitments = (int)incremental_tree_size(&tree);
            ckpt_h = akv_h;
            LOG_INFO("sapling_tree_rebuild",
                     "sapling_tree_rebuild: resuming from the anchor_kv "
                     "Sapling frontier h=%lld (%d commitments) — the "
                     "canonical fold ledger, header-root-bound at that height",
                     (long long)akv_h, total_commitments);
        }
    }

    if (ckpt_h == 0) {
        char ckpt_path[512];
        int n = snprintf(ckpt_path, sizeof(ckpt_path),
                         "%s/sapling_tree_ckpt.dat", datadir);
        if (n > 0 && (size_t)n < sizeof(ckpt_path)) {
            int64_t flat_h = 0;
            uint8_t flat_hash[32] = {0};
            struct incremental_merkle_tree ff_tree;
            sapling_tree_init(&ff_tree);
            if (sapling_tree_load_checkpoint(&ff_tree, &flat_h, flat_hash,
                                             ckpt_path)
                && flat_h > sapling_height) {
                /* Fail-closed bind to the header chain at flat_h: height <=
                 * endpoint, same block hash, and root == hashFinalSaplingRoot.
                 * A stale/reorged/mismatched checkpoint is refused and the
                 * replay restarts from Sapling activation. */
                const struct block_index *ckpt_bi =
                    active_chain_at(chain, (int)flat_h);
                struct uint256 ffr;
                incremental_tree_root(&ff_tree, &ffr);
                bool exp_hash_known = ckpt_bi && ckpt_bi->phashBlock;
                enum sapling_ckpt_verdict v = sapling_ckpt_verify_binding(
                    flat_h, &ffr, flat_hash, chain_tip,
                    exp_hash_known ? ckpt_bi->phashBlock->data : NULL,
                    exp_hash_known,
                    sapling_rebuild_header_root_known(ckpt_bi)
                        ? &ckpt_bi->hashFinalSaplingRoot : NULL,
                    sapling_rebuild_header_root_known(ckpt_bi));
                if (v == SAPLING_CKPT_OK) {
                    tree = ff_tree;
                    start_height = (int)flat_h + 1;
                    total_commitments =
                        (int)incremental_tree_size(&tree);
                    ckpt_h = flat_h;
                    LOG_INFO("sapling_tree_rebuild", "sapling_tree_rebuild: resuming " "from flat-file checkpoint h=%lld " "(%d commitments,)", (long long)flat_h, total_commitments);
                    fflush(stderr);
                } else {
                    LOG_WARN("sapling_tree_rebuild",
                             "sapling_tree_rebuild: refusing flat-file "
                             "checkpoint h=%lld (%s)",
                             (long long)flat_h, sapling_ckpt_verdict_str(v));
                }
            }
        }
    }

    if (ckpt_h == 0
        && node_db_state_get_int(ndb, "sapling_tree_rebuild_height", &ckpt_h)
        && ckpt_h > sapling_height && ckpt_h <= chain_tip) {
        uint8_t tbuf[8192];
        size_t tlen = 0;
        if (node_db_state_get(ndb, "sapling_tree", tbuf, sizeof(tbuf), &tlen)
            && tlen > 0) {
            struct byte_stream ts;
            stream_init_from_data(&ts, tbuf, tlen);
            if (incremental_tree_deserialize(&tree, &ts)) {
                const struct block_index *ckpt_bi =
                    active_chain_at(chain, (int)ckpt_h);
                if (sapling_rebuild_header_root_known(ckpt_bi)) {
                    struct uint256 ckpt_root;
                    incremental_tree_root(&tree, &ckpt_root);
                    if (memcmp(ckpt_root.data,
                               ckpt_bi->hashFinalSaplingRoot.data,
                               32) == 0) {
                        start_height = (int)ckpt_h + 1;
                        total_commitments =
                            (int)incremental_tree_size(&tree);
                        LOG_INFO("sapling_tree_rebuild", "sapling_tree_rebuild: resuming " "from checkpoint h=%d (%d commitments)", (int)ckpt_h, total_commitments);
                        fflush(stderr);
                    } else {
                        LOG_WARN("sapling_tree_rebuild",
                                 "sapling_tree_rebuild: checkpoint h=%d "
                                 "root mismatch; replaying from activation",
                                 (int)ckpt_h);
                        sapling_tree_init(&tree);
                    }
                } else {
                    LOG_WARN("sapling_tree_rebuild",
                             "sapling_tree_rebuild: refusing unverified "
                             "node_state checkpoint h=%d (missing "
                             "hashFinalSaplingRoot)",
                             (int)ckpt_h);
                    sapling_tree_init(&tree);
                }
            }
        }
    }

    int64_t t_replay_start = GetTimeMillis();
    int cached_file = -1;
    struct sync_block_file_mapping cached_mapping;
    sync_block_file_mapping_init(&cached_mapping);

    /* Refuse a provably-impossible replay UP FRONT, from headers alone — see
     * sapling_rebuild_replay_is_impossible for the proof and why it can only
     * ever be conservative. Seeding the skip counters here is what makes the
     * shared fail path below report the absent run with the same tally and the
     * same body-availability DEPENDENCY class a post-hoc mismatch produces. */
    {
        struct sapling_rebuild_impossible pf = {0};
        if (sapling_rebuild_replay_is_impossible(chain, &tree, start_height,
                                                 chain_tip, &pf)) {
            skipped_no_index = pf.no_index;
            skipped_no_data = pf.no_data;
            first_skip_height = start_height;
            last_skip_height = pf.gap_last_h;
            fail_reason = SAPLING_REBUILD_REASON_REPLAY_IMPOSSIBLE;
            fail_height = (pf.first_body_h >= 0) ? pf.first_body_h
                                                 : pf.gap_last_h;
            goto fail;
        }
    }

    LOG_INFO("sapling_tree_rebuild", "sapling_tree_rebuild: replaying h=%d..%d", start_height, chain_tip);
    fflush(stderr);

    int abort_height = -1;
    for (int h = start_height; h <= chain_tip; h++) {
        if ((h % 100) == 0) {
            boot_progress_tick("sapling_tree_rebuild");
            if (sapling_tree_rebuild_shutdown_requested()) {
                abort_height = h;
                goto aborted;
            }
        }
        if (sup_id != SUPERVISOR_INVALID_ID && (h % 1000) == 0) {
            int64_t now_ms = GetTimeMillis();
            if (now_ms - last_heartbeat_ms >=
                SAPLING_TREE_REBUILD_HEARTBEAT_MS) {
                last_heartbeat_ms = now_ms;
                supervisor_tick(sup_id);
                supervisor_progress(sup_id, total_commitments);
                LOG_INFO("sapling_tree_rebuild",
                        "sapling_tree_rebuild: heartbeat h=%d/%d "
                        "commitments_folded=%d", h, chain_tip,
                        total_commitments);
            }
        }
        const struct block_index *bi = active_chain_at(chain, h);
        if (!bi) {
            if (sapling_rebuild_account_skip("no_index", h,
                    endpoint_is_coins_applied, &skipped_no_index,
                    &first_skip_height, &last_skip_height)) {
                fail_reason = "shielded_verify_skip_no_index";
                fail_height = h;
                goto fail;
            }
            continue;
        }
        if (!(bi->nStatus & BLOCK_HAVE_DATA)) {
            if (sapling_rebuild_account_skip("no_data", h,
                    endpoint_is_coins_applied, &skipped_no_data,
                    &first_skip_height, &last_skip_height)) {
                fail_reason = "shielded_verify_skip_no_data";
                fail_height = h;
                goto fail;
            }
            continue;
        }

        if (bi->nFile != cached_file) {
            if (!sync_block_file_mapping_open(&cached_mapping, datadir,
                                              bi->nFile)) {
                cached_file = -1;
                if (sapling_rebuild_account_skip("no_mmap", h,
                        endpoint_is_coins_applied, &skipped_no_mmap,
                        &first_skip_height, &last_skip_height)) {
                    fail_reason = "shielded_verify_skip_no_mmap";
                    fail_height = h;
                    goto fail;
                }
                continue;
            }
            cached_file = bi->nFile;
        }

        if ((uintmax_t)bi->nDataPos >=
            (uintmax_t)cached_mapping.view.size) {
            /* Data position past the mapped size: the block file grew after
             * it was mmap'd (stale cached_size), or the recorded position is
             * corrupt. */
            if (sapling_rebuild_account_skip("datapos_out_of_range", h,
                    endpoint_is_coins_applied, &skipped_datapos_oob,
                    &first_skip_height, &last_skip_height)) {
                fail_reason = "shielded_verify_skip_datapos_out_of_range";
                fail_height = h;
                goto fail;
            }
            continue;
        }

        struct block blk;
        block_init(&blk);
        size_t data_pos = (size_t)bi->nDataPos;
        size_t remaining = cached_mapping.view.size - data_pos;
        struct byte_stream s;
        stream_init_from_data(&s, cached_mapping.view.data + data_pos,
                              remaining);
        if (!block_deserialize(&blk, &s)) {
            block_free(&blk);
            if (sapling_rebuild_account_skip("deserialize_failed", h,
                    endpoint_is_coins_applied, &skipped_deserialize,
                    &first_skip_height, &last_skip_height)) {
                fail_reason = "shielded_verify_skip_deserialize_failed";
                fail_height = h;
                goto fail;
            }
            continue;
        }

        int appended_this_block = 0;
        for (size_t i = 0; i < blk.num_vtx; i++) {
            const struct transaction *tx = &blk.vtx[i];
            for (size_t j = 0; j < tx->num_shielded_output; j++) {
                incremental_tree_append(&tree,
                    &tx->v_shielded_output[j].cm);
                total_commitments++;
                appended_this_block++;
            }
        }

        bool is_checkpoint = ((h - sapling_height) % 100000 == 0 &&
                              h > sapling_height);

        /* Per-block root check, mirroring the live fold's cadence
         * (fold_sapling in utxo_apply_anchors.c): whenever a block changed
         * the tree, the post-append incremental root must equal that block's
         * committed hashFinalSaplingRoot, localizing a divergence to the
         * exact block. Compare against the block-index root
         * (bi->hashFinalSaplingRoot), the node-validated source the final tip
         * check also uses, not the re-read on-disk block header. Checkpoint
         * heights are skipped; the checkpoint verify below covers them.
         * Detection only. */
        if (!is_checkpoint && appended_this_block > 0 &&
            sapling_rebuild_header_root_known(bi)) {
            struct uint256 computed;
            incremental_tree_root(&tree, &computed);
            if (!uint256_eq(&computed, &bi->hashFinalSaplingRoot)) {
                mismatches++;
                fail_reason = "intermediate_sapling_root_mismatch";
                fail_height = h;
            }
        }

        if (is_checkpoint) {
            struct uint256 computed;
            incremental_tree_root(&tree, &computed);
            if (!sapling_rebuild_header_root_known(bi)) {
                fail_reason = "checkpoint_missing_sapling_root";
                fail_height = h;
            } else if (memcmp(computed.data,
                       blk.header.hashFinalSaplingRoot.data, 32) != 0) {
                mismatches++;
                fail_reason = "checkpoint_sapling_root_mismatch";
                fail_height = h;
            }
        }

        block_free(&blk);

        if (fail_reason)
            goto fail;

        if (is_checkpoint) {
            LOG_WARN("sapling_tree_rebuild", "  sapling_tree_rebuild: h=%d/%d " "commitments=%d mismatches=%d", h, chain_tip, total_commitments, mismatches);
            fflush(stderr);

            struct byte_stream ts;
            stream_init(&ts, 4096);
            if (!incremental_tree_serialize(&tree, &ts)) {
                stream_free(&ts);
                fail_reason = "serialize_checkpoint_tree_failed";
                fail_height = h;
                goto fail;
            }
            enum sapling_persist_status ps =
                sapling_tree_persist_pair_status(ndb, ts.data, ts.size,
                                                 (int64_t)h);
            stream_free(&ts);
            if (ps == SAPLING_PERSIST_FAILED) {
                fail_reason = "persist_checkpoint_pair_failed";
                fail_height = h;
                goto fail;
            }
            /* DEFERRED: a foreign tx transiently owned the connection. Skip
             * persisting THIS checkpoint — the tree stays in memory and the
             * next checkpoint (or the final persist) records it. Not a
             * failure; the fold keeps making progress. */
            if (ps == SAPLING_PERSIST_DEFERRED)
                LOG_INFO("sapling_tree_rebuild",
                        "checkpoint persist deferred at h=%d (busy)", h);
        }
    }

    sync_block_file_mapping_close(&cached_mapping);

    sapling_rebuild_log_skip_summary(skipped_no_index, skipped_no_data,
                                     skipped_no_mmap, skipped_datapos_oob,
                                     skipped_deserialize, first_skip_height,
                                     last_skip_height,
                                     endpoint_is_coins_applied);

    /* Verify against the resolved endpoint (the coins-applied frontier, or the
     * header tip when no coins frontier exists), not active_chain_tip(): a
     * block above the applied frontier may lack hashFinalSaplingRoot and
     * FATAL on `tip_missing_sapling_root`. */
    const struct block_index *tip = active_chain_at(chain, chain_tip);
    struct uint256 final_root;
    incremental_tree_root(&tree, &final_root);
    bool tip_root_known = sapling_rebuild_header_root_known(tip);
    bool match = tip_root_known && memcmp(final_root.data,
                               tip->hashFinalSaplingRoot.data, 32) == 0;

    char root_hex[65];
    uint256_get_hex(&final_root, root_hex);
    int64_t replay_ms = GetTimeMillis() - t_replay_start;
    int replayed_blocks = (chain_tip >= start_height)
                          ? (chain_tip - start_height + 1)
                          : 0;
    LOG_INFO("sapling_tree_rebuild", "sapling_tree_rebuild: replayed %d blocks in %lld ms", replayed_blocks, (long long)replay_ms);
    LOG_WARN("sapling_tree_rebuild", "sapling_tree_rebuild: DONE commitments=%d " "mismatches=%d root=%s match=%s", total_commitments, mismatches, root_hex, match ? "YES" : "NO");
    fflush(stderr);

    if (!match) {
        fail_reason = tip_root_known ? "tip_sapling_root_mismatch"
                                     : "tip_missing_sapling_root";
        fail_height = tip ? tip->nHeight : -1;
        goto fail;
    }

    {
        struct byte_stream ts;
        stream_init(&ts, 4096);
        if (!incremental_tree_serialize(&tree, &ts)) {
            stream_free(&ts);
            fail_reason = "serialize_final_tree_failed";
            fail_height = chain_tip;
            goto fail;
        }
        /* The final persist MUST durably land the rebuilt tree. A DEFERRED
         * result means the reducer's batch tx transiently owns the connection;
         * the reducer commits on a seconds timescale, so a bounded wait-then-
         * retry (yielding this background thread) lets the persist land without
         * ever nesting a BEGIN. Exhaustion is handled below. */
        enum sapling_persist_status ps = SAPLING_PERSIST_DEFERRED;
        for (int a = 1; a <= SAPLING_TREE_FINAL_PERSIST_ATTEMPTS &&
                        ps == SAPLING_PERSIST_DEFERRED; a++) {
            ps = sapling_tree_persist_pair_status(ndb, ts.data, ts.size,
                                                  (int64_t)chain_tip);
            if (ps == SAPLING_PERSIST_DEFERRED &&
                a < SAPLING_TREE_FINAL_PERSIST_ATTEMPTS) {
                int64_t backoff_ms =
                    (int64_t)SAPLING_TREE_FINAL_PERSIST_BACKOFF_MS * a;
                struct timespec bt = {
                    .tv_sec = backoff_ms / 1000,
                    .tv_nsec = (backoff_ms % 1000) * 1000000L,
                };
                nanosleep(&bt, NULL);
            }
        }
        stream_free(&ts);
        if (ps == SAPLING_PERSIST_DEFERRED) {
            /* Busy past the budget: a transient lock condition, not a
             * derived-state disagreement. Name the persist_busy TRANSIENT
             * blocker (self-clears on the next successful rebuild) and return
             * the soft-failure code (rc<0) meaning "leave the tree stale,
             * retry next pass", not the fail_closed path (reserved for real
             * root/state mismatches). Complete the child first so a clean
             * give-up is not a hung stall. */
            char reason[BLOCKER_REASON_MAX];
            snprintf(reason, sizeof(reason),
                    "final persist deferred height=%lld: connection stayed in "
                    "a foreign open transaction past %d attempts",
                    (long long)chain_tip,
                    SAPLING_TREE_FINAL_PERSIST_ATTEMPTS);
            struct blocker_record rec;
            if (blocker_init(&rec, "sapling_tree_rebuild.persist_busy",
                             "sync.sapling_tree_rebuild",
                             BLOCKER_TRANSIENT, reason))
                blocker_set(&rec);
            LOG_ERROR("sapling_tree_rebuild", "%s", reason);
            if (sup_id != SUPERVISOR_INVALID_ID)
                supervisor_child_complete(sup_id);
            return -1; // raw-return-ok:logged_above_and_persist_busy_blocker_set
        }
        if (ps == SAPLING_PERSIST_FAILED) {
            fail_reason = "persist_final_pair_failed";
            fail_height = chain_tip;
            goto fail;
        }
    }

    (void)tree;
    if (sup_id != SUPERVISOR_INVALID_ID) {
        supervisor_progress(sup_id, total_commitments);
        supervisor_tick(sup_id);
        supervisor_child_complete(sup_id);
    }
    blocker_clear("sapling_tree_rebuild.fail_closed");
    blocker_clear("sapling_tree_rebuild.persist_busy");
    return total_commitments;

aborted:
    /* Orderly shutdown was requested mid-replay. Deliberately NOT the fail
     * path: an abort is not a derived-state fault, so no fail-closed blocker
     * and no final persist — the per-100k checkpoint persists and the
     * anchor_kv frontier already durably record the partial fold, and the
     * next run resumes from them. Complete the supervisor child so a clean
     * give-up is not mistaken for a hung stall. */
    sync_block_file_mapping_close(&cached_mapping);
    if (sup_id != SUPERVISOR_INVALID_ID)
        supervisor_child_complete(sup_id);
    LOG_INFO("sapling_tree_rebuild",
             "sapling_tree_rebuild: shutdown requested at h=%d of %d — "
             "aborting replay; partial fold stays resumable from the "
             "persisted checkpoints", abort_height, chain_tip);
    return SAPLING_TREE_REBUILD_ABORTED;

fail:
    sync_block_file_mapping_close(&cached_mapping);
    if (sup_id != SUPERVISOR_INVALID_ID)
        supervisor_child_complete(sup_id);
    /* A tip/intermediate root mismatch is often the downstream shadow of an
     * earlier dropped block. Emit the skip tally next
     * to the fail-closed reason. The same tally decides the
     * blocker CLASS (see sapling_tree_rebuild_raise_fail_blocker): a mismatch
     * over a known-incomplete body set is a dependency, not corruption.
     * Every recorded skip is at a height strictly below `fail_height` — the
     * walk is ascending and a skipped height `continue`s before any root
     * check — so a non-zero tally always means "bodies missing BELOW the
     * mismatch". */
    struct sapling_rebuild_skip_tally fail_skips = {0};
    {
        fail_skips.total = skipped_no_index + skipped_no_data +
                           skipped_no_mmap + skipped_datapos_oob +
                           skipped_deserialize;
        fail_skips.first_height = first_skip_height;
        fail_skips.last_height = last_skip_height;
        size_t off = 0;
        static const char *k_names[5] = {"no_index", "no_data", "no_mmap",
                                         "datapos_oob", "deserialize"};
        const int counts[5] = {skipped_no_index, skipped_no_data,
                               skipped_no_mmap, skipped_datapos_oob,
                               skipped_deserialize};
        for (int i = 0; i < 5; i++) {
            if (counts[i] <= 0 || off + 1 >= sizeof(fail_skips.classes))
                continue;
            int w = snprintf(fail_skips.classes + off,
                             sizeof(fail_skips.classes) - off, "%s%s",
                             off ? "," : "", k_names[i]);
            if (w <= 0 || (size_t)w >= sizeof(fail_skips.classes) - off)
                break;
            off += (size_t)w;
        }
        if (fail_skips.total > 0)
            LOG_WARN("sapling_tree_rebuild",
                    "sapling_tree_rebuild: at fail — %d block(s) were skipped "
                    "(no_index=%d no_data=%d no_mmap=%d datapos_oob=%d "
                    "deserialize=%d span=[%d..%d]); a dropped shielded-output "
                    "block below the mismatch height is the leading cause",
                    fail_skips.total, skipped_no_index, skipped_no_data,
                    skipped_no_mmap, skipped_datapos_oob, skipped_deserialize,
                    first_skip_height, last_skip_height);
    }
    sapling_tree_rebuild_raise_fail_blocker(fail_reason, fail_height,
                                            total_commitments, mismatches,
                                            &fail_skips);
    LOG_ERR("sapling_tree_rebuild",
            "sapling_tree_rebuild: fail-closed reason=%s height=%d "
            "commitments=%d mismatches=%d",
            fail_reason ? fail_reason : "unknown", fail_height,
            total_commitments, mismatches);
}

/* ── Deferred/live background rebuild ─────────────────────────────────
 * engine/composition/src/boot.c's "Sapling tree root MISMATCH ... deferring live
 * rebuild until after boot" branch only sets g_sapling_tree_rebuilding=true;
 * this is what actually performs the rebuild. Runs the same
 * rebuild-then-reload sequence as the synchronous boot-time path, off
 * a background thread so the replay never blocks node startup. The
 * thread_registry_spawn call site below is covered by this file's
 * supervisor_register_in_domain() call above: sapling_tree_rebuild()
 * registers "sync.sapling_tree_rebuild" on entry, so a stuck deferred run
 * is a named supervisor stall. */
struct sapling_tree_deferred_args {
    struct node_db *ndb;
    struct active_chain *chain;
    const char *datadir;
    struct main_state *ms;
};

static void *sapling_tree_rebuild_deferred_thread(void *arg)
{
    struct sapling_tree_deferred_args *a = arg;
    struct node_db *reducer_ndb = a->ndb;
    struct active_chain *chain = a->chain;
    const char *datadir = a->datadir;
    struct main_state *ms = a->ms;
    free(a);

    size_t old_size = incremental_tree_size(&ms->sapling_tree);
    LOG_INFO("sapling_tree_rebuild",
            "deferred rebuild: starting background replay "
            "(pre-rebuild size=%zu)", old_size);
    atomic_store(&g_sapling_tree_rebuilding, true);

    /* The reducer can keep its own node_db transaction open across a batch,
     * which would DEFER every persist on a shared connection. The rebuild
     * uses a dedicated runtime connection; the bounded BUSY/LOCKED retry
     * lands after the reducer commits or names
     * sapling_tree_rebuild.persist_busy. */
    struct node_db persist_ndb;
    if (!sapling_tree_open_persist_lane(reducer_ndb, &persist_ndb,
                                        active_chain_height(chain))) {
        atomic_store(&g_sapling_tree_rebuilding, false);
        thread_registry_unregister_self();
        return NULL;
    }

    int n = sapling_tree_rebuild(&persist_ndb, chain, datadir);
    if (n >= 0) {
        uint8_t tbuf[8192];
        size_t tlen = 0;
        if (node_db_state_get(&persist_ndb, "sapling_tree", tbuf, sizeof(tbuf),
                              &tlen) && tlen > 0) {
            struct byte_stream ts2;
            stream_init_from_data(&ts2, tbuf, tlen);
            sapling_tree_init(&ms->sapling_tree);
            incremental_tree_deserialize(&ms->sapling_tree, &ts2);
            set_sapling_tree_for_flush(&ms->sapling_tree);
            LOG_WARN("sapling_tree_rebuild",
                    "deferred rebuild: DONE %d commitments (was %zu)",
                    n, old_size);
        }
    } else if (n == SAPLING_TREE_REBUILD_ABORTED) {
        /* Shutdown in progress: quiet clean exit, not a failure — the tree
         * stays at its pre-rebuild size and the next run resumes from the
         * persisted checkpoints. The wal-checkpoint/close/block-index save
         * below still run; they are part of an orderly stop. */
        LOG_INFO("sapling_tree_rebuild",
                "deferred rebuild: aborted for shutdown — tree left at "
                "pre-rebuild size=%zu; resumes from checkpoints next run",
                old_size);
    } else {
        LOG_WARN("sapling_tree_rebuild",
                "deferred rebuild: FAILED (rc=%d) — tree left at "
                "pre-rebuild size=%zu; sapling_tree_rebuild already "
                "raised a named blocker (see `z23 dumpstate "
                "blocker`)", n, old_size);
    }
    atomic_store(&g_sapling_tree_rebuilding, false);
    node_db_wal_checkpoint(&persist_ndb);
    node_db_close(&persist_ndb);
    if (datadir)
        save_block_index_flat(datadir, ms);
    thread_registry_unregister_self();
    return NULL;
}

/* Kick off the deferred/live rebuild as a background thread. Called from
 * boot when the synchronous inline rebuild would be too slow to run
 * before P2P/RPC starts. On spawn failure the tree simply stays stale
 * (as it already was) until an operator runs `rebuildsaplingtree`. */
void sapling_tree_rebuild_start_deferred(struct node_db *ndb,
                                         struct active_chain *chain,
                                         const char *datadir,
                                         struct main_state *ms)
{
    atomic_store(&g_sapling_tree_rebuilding, true);
    struct sapling_tree_deferred_args *args =
        zcl_malloc(sizeof(*args), "sapling_tree_deferred_args");
    if (!args) {
        LOG_WARN("sapling_tree_rebuild",
                "start_deferred: alloc failed — tree stays stale until "
                "an operator runs `rebuildsaplingtree`");
        atomic_store(&g_sapling_tree_rebuilding, false);
        return;
    }
    args->ndb = ndb;
    args->chain = chain;
    args->datadir = datadir;
    args->ms = ms;
    if (thread_registry_spawn("zcl_sapling_defer",
            sapling_tree_rebuild_deferred_thread, args, NULL) != 0) {
        LOG_WARN("sapling_tree_rebuild",
                "start_deferred: thread spawn failed — tree stays stale "
                "until an operator runs `rebuildsaplingtree`");
        free(args);
        atomic_store(&g_sapling_tree_rebuilding, false);
    }
}
