/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * One fail-closed block-swarm abandonment transaction shared by the
 * integrity-mismatch and completion-silent fallback paths. */

#include "msgprocessor_internal.h"
#include "msgprocessor_snapshot_internal.h"

#include "event/event.h"
#include "net/fast_sync.h"
#include "platform/time_compat.h"
#include "util/log_macros.h"
#include "validation/main_state.h"

#define BLOCK_PIECE_CONTIGUOUS_WINDOW PIECE_PIPELINE_DEPTH

struct block_swarm_pipeline_reconcile
mp_block_swarm_reconcile_peer_pipeline(struct block_swarm *swarm,
                                       struct p2p_node *node,
                                       int64_t now_monotonic)
{
    struct block_swarm_pipeline_reconcile result = {0};
    if (!swarm || !node || !swarm->piece_states || !swarm->piece_peer)
        return result;

    for (int pi = 0; pi < PIECE_PIPELINE_DEPTH; pi++) {
        int32_t piece = node->blk_pipeline[pi].piece_index;
        if (piece < 0)
            continue;

        bool owns_piece = (uint32_t)piece < swarm->manifest.num_pieces &&
            swarm->piece_states[piece] == CHUNK_INFLIGHT &&
            swarm->piece_peer[piece] == node->id;
        if (owns_piece &&
            (now_monotonic < node->blk_pipeline[pi].request_time ||
             now_monotonic - node->blk_pipeline[pi].request_time <=
                 BLOCK_PIECE_TIMEOUT_SECS))
            continue;

        if (owns_piece) {
            (void)block_swarm_requeue_piece_for_peer(
                swarm, (uint32_t)piece, node->id);
            result.timed_out = true;
            node->blk_timeout_yield_until = now_monotonic + 1;
            atomic_fetch_add(&node->blk_pieces_timed_out, 1);
        }
        node->blk_pipeline[pi].piece_index = -1;
        node->blk_pipeline[pi].request_time = 0;
        node->blk_pipeline[pi].request_time_us = 0;
        result.cleared++;
    }
    return result;
}

int32_t mp_block_swarm_peer_manifest_end(const struct p2p_node *node)
{
    return node->blk_manifest_received ? node->blk_peer_height : -1;
}

int32_t mp_block_swarm_local_header_cap(const struct msg_processor *mp)
{
    int32_t cap = 0;
    if (!mp || !mp->main_state)
        return cap;

    int active_h = active_chain_height(&mp->main_state->chain_active);
    if (active_h > cap)
        cap = active_h;

    struct block_index *best_header = mp->main_state->pindex_best_header;
    if (best_header && best_header->nHeight > cap)
        cap = best_header->nHeight;
    return cap;
}

int32_t mp_block_swarm_contiguous_window_cap(struct block_swarm *swarm,
                                             int32_t header_cap)
{
    if (!swarm || !swarm->piece_states || swarm->manifest.num_pieces == 0)
        return header_cap;

    uint32_t first_open = block_swarm_first_incomplete_piece(swarm);
    if (first_open >= swarm->manifest.num_pieces)
        return header_cap;

    uint32_t window_cap = first_open + BLOCK_PIECE_CONTIGUOUS_WINDOW - 1;
    if (window_cap >= swarm->manifest.num_pieces)
        window_cap = swarm->manifest.num_pieces - 1;

    int64_t piece_end = (int64_t)swarm->manifest.start_height +
        ((int64_t)window_cap + 1) * BLOCKS_PER_PIECE - 1;
    if (piece_end > swarm->manifest.end_height)
        piece_end = swarm->manifest.end_height;
    if (piece_end < header_cap)
        return (int32_t)piece_end;
    return header_cap;
}

void mp_block_swarm_mark_complete_through_height(
    struct block_swarm *swarm, int32_t have_height)
{
    if (!swarm || !swarm->piece_states ||
        have_height < swarm->manifest.start_height)
        return;

    int64_t complete_blocks =
        (int64_t)have_height - (int64_t)swarm->manifest.start_height + 1;
    if (complete_blocks <= 0)
        return;

    uint32_t full_pieces =
        (uint32_t)(complete_blocks / BLOCKS_PER_PIECE);
    if (full_pieces > swarm->manifest.num_pieces)
        full_pieces = swarm->manifest.num_pieces;

    for (uint32_t i = 0; i < full_pieces; i++) {
        if (swarm->piece_states[i] == CHUNK_COMPLETE)
            continue;
        swarm->piece_states[i] = CHUNK_COMPLETE;
        swarm->piece_peer[i] = -1;
        swarm->piece_request_time[i] = 0;
        swarm->pieces_complete++;
    }
    if (swarm->next_assign_hint < full_pieces)
        swarm->next_assign_hint = full_pieces;
    if (swarm->first_incomplete_hint < full_pieces)
        swarm->first_incomplete_hint = full_pieces;
    if (full_pieces > 0)
        swarm->last_complete_monotonic =
            platform_time_monotonic_us() / 1000000;
    if (full_pieces > 0 && swarm->last_complete_monotonic <= 0)
        swarm->last_complete_monotonic = 1;
}

bool mp_block_swarm_abandon_locked(
    struct block_swarm *swarm, _Atomic bool *active,
    _Atomic int64_t *reaped_monotonic, int64_t now_monotonic,
    struct block_swarm_abandonment *out)
{
    if (!swarm || !active || !reaped_monotonic || !atomic_load(active) ||
        !swarm->piece_states || swarm->manifest.num_pieces == 0)
        return false;

    if (out) {
        out->complete = swarm->pieces_complete;
        out->total = swarm->manifest.num_pieces;
        out->failed = swarm->pieces_failed;
        out->last_complete_monotonic = swarm->last_complete_monotonic;
    }
    block_swarm_free(swarm);
    atomic_store(active, false);
    atomic_store(reaped_monotonic, now_monotonic);
    return true;
}

void mp_block_swarm_finish_abandon(struct msg_processor *mp)
{
    if (!mp || !mp->net_mgr)
        return;

    zcl_mutex_lock(&mp->net_mgr->cs_nodes);
    for (size_t i = 0; i < mp->net_mgr->num_nodes; i++) {
        struct p2p_node *node = mp->net_mgr->nodes[i];
        if (!node)
            continue;
        for (int pi = 0; pi < PIECE_PIPELINE_DEPTH; pi++)
            node->blk_pipeline[pi].piece_index = -1;
    }
    zcl_mutex_unlock(&mp->net_mgr->cs_nodes);
}

void mp_block_swarm_report_integrity_abandon(
    struct msg_processor *mp, const struct p2p_node *node,
    uint32_t piece_index, const struct block_swarm_abandonment *abandoned)
{
    if (!abandoned)
        return;
    mp_block_swarm_finish_abandon(mp);
    LOG_WARN("net",
             "block swarm integrity failure at piece %u after %u/%u "
             "complete (%u failed) — abandoning swarm immediately; "
             "legacy getdata resumes body fetch",
             piece_index, abandoned->complete, abandoned->total,
             abandoned->failed);
    event_emitf(EV_BLOCK_REQUESTED, node ? (uint32_t)node->id : 0,
                "block_swarm_integrity_abandon piece=%u complete=%u "
                "total=%u failed=%u",
                piece_index, abandoned->complete, abandoned->total,
                abandoned->failed);
}
