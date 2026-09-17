/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Header-range ownership and continuation wiring, extracted from the legacy
 * msg_headers.c handler so that message parsing and range scheduling remain
 * independently reviewable. This module changes no header-validity rule. */

#include "net/msg_internal.h"

#include "chain/checkpoints.h"
#include "event/event.h"
#include "net/download.h"
#include "net/fast_sync.h"
#include "platform/time_compat.h"
#include "services/header_range_scheduler.h"
#include "sync/sync_planner.h"
#include "util/log_macros.h"

/* Resolve a span-boundary height to a locally-known block hash: a compiled
 * checkpoint hash, else a block held at or below our frontier. Never
 * fabricate an anchor for a height absent from both authorities. */
static bool hrs_resolve_anchor_hash(struct msg_processor *mp, int32_t height,
                                    int our_height, struct uint256 *out)
{
    if (!mp || !out)
        return false;
    if (checkpoints_hash_at_height(&mp->params->checkpointData, height, out))
        return true;
    if (height <= our_height) {
        struct block_index *bi =
            active_chain_at(&mp->main_state->chain_active, height);
        if (bi && bi->phashBlock) {
            *out = *bi->phashBlock;
            return true;
        }
    }
    return false;
}

void msg_header_range_note_response(struct p2p_node *node,
                                    const struct sync_header_batch *batch,
                                    size_t accepted,
                                    uint64_t count)
{
    struct header_range_scheduler *sched = header_range_scheduler_global();
    if (accepted > 0)
        (void)hrs_note_peer_progress(sched, node->id,
                                     platform_time_monotonic_us());
    if (batch->should_release_range && hrs_release_peer(sched, node->id) > 0)
        event_emitf(EV_HEADERS_REJECTED, (uint32_t)node->id,
                    "terminal header response released range span "
                    "accepted=%zu total=%llu", accepted,
                    (unsigned long long)count);
}

size_t mp_header_range_peer_disconnected(uint32_t peer_id)
{
    return hrs_release_peer(header_range_scheduler_global(), (int32_t)peer_id);
}

bool msg_range_continuation_stop(struct msg_processor *mp,
                                 struct p2p_node *node,
                                 int our_height,
                                 int64_t now_us,
                                 struct uint256 *stop_hash)
{
    int32_t hi = 0;
    if (!mp || !node || !stop_hash || now_us < 0)
        return false;
    if (!hrs_peer_span(header_range_scheduler_global(), node->id,
                       now_us, NULL, &hi))
        return false;
    return hrs_resolve_anchor_hash(mp, hi, our_height, stop_hash);
}

void msg_push_getheaders_followup(struct msg_processor *mp,
                                  struct p2p_node *node,
                                  struct block_index *from,
                                  int our_height)
{
    struct uint256 stop_hash;
    int64_t now_us = platform_time_monotonic_us();
    if (from && from->phashBlock &&
        msg_range_continuation_stop(mp, node, our_height, now_us,
                                    &stop_hash)) {
        push_getheaders_span(mp, node, from->phashBlock, &stop_hash);
        return;
    }
    push_getheaders_from(mp, node, from);
}

bool msg_try_range_parallel_getheaders(struct msg_processor *mp,
                                       struct p2p_node *node,
                                       int our_height, int64_t now_us)
{
    if (!mp || !node || !mp->main_state || !mp->net_mgr || !mp->params)
        return false;
    if (syncsvc_header_band_hole_open())
        return false;
    if (node->inbound || node->state < PEER_SYNCING_HEADERS ||
        !peer_supports_fast_sync(node->services))
        return false;

    struct main_state *ms = mp->main_state;
    int target = node->starting_height;
    if (ms->pindex_best_header && ms->pindex_best_header->nHeight > target)
        target = ms->pindex_best_header->nHeight;

    int fast_peers = 0;
    zcl_mutex_lock(&mp->net_mgr->cs_nodes);
    for (size_t pi = 0; pi < mp->net_mgr->num_nodes; pi++) {
        struct p2p_node *n = mp->net_mgr->nodes[pi];
        if (n && !n->inbound && !n->disconnect && n->state >= PEER_ACTIVE &&
            peer_supports_fast_sync(n->services)) {
            fast_peers++;
            target = hrs_include_peer_target(target, n->starting_height);
        }
    }
    zcl_mutex_unlock(&mp->net_mgr->cs_nodes);

    int32_t gap = (int32_t)(target - our_height);
    if (!hrs_should_parallelize(fast_peers, gap, 2000))
        return false;

    const struct checkpoint_data *cpd = &mp->params->checkpointData;
    int32_t anchors[HRS_MAX_SPANS];
    size_t n_anchors = 0;
    for (int i = 0; cpd && cpd->entries && i < cpd->nEntries &&
                    n_anchors < HRS_MAX_SPANS; i++) {
        int h = cpd->entries[i].height;
        if (h > our_height && h < target)
            anchors[n_anchors++] = (int32_t)h;
    }

    struct header_range_scheduler *sched = header_range_scheduler_global();
    hrs_plan(sched, (int32_t)our_height, target, anchors, n_anchors);
    if (ms->pindex_best_header)
        hrs_note_frontier(sched, ms->pindex_best_header->nHeight);

    /* Sweep globally: whichever peer ticks first releases every expired span.
     * Missing a performance deadline is reported and reassigned, never scored
     * as protocol misbehavior. */
    int32_t stalled_ids[HRS_MAX_SPANS];
    size_t n_stalled =
        hrs_sweep_expired(sched, now_us, stalled_ids, HRS_MAX_SPANS);
    for (size_t si = 0; si < n_stalled; si++) {
        int32_t sid = stalled_ids[si];
        bool duplicate = false;
        for (size_t sj = 0; sj < si; sj++) {
            if (stalled_ids[sj] == sid) {
                duplicate = true;
                break;
            }
        }
        if (!duplicate)
            event_emitf(EV_HEADERS_REJECTED, (uint32_t)sid,
                        "header span reclaimed from slow peer %d "
                        "(deadline missed; span reassigned, not scored)",
                        (int)sid);
    }

    int32_t lo, hi;
    if (!hrs_peer_span(sched, node->id, now_us, &lo, &hi)) {
        if (hrs_assign(sched, node->id, now_us) < 0 ||
            !hrs_peer_span(sched, node->id, now_us, &lo, &hi))
            return false;
    }

    struct uint256 start_hash, stop_hash;
    if (!hrs_resolve_anchor_hash(mp, lo, our_height, &start_hash))
        return false;
    bool have_stop = hrs_resolve_anchor_hash(mp, hi, our_height, &stop_hash);
    push_getheaders_span(mp, node, &start_hash, have_stop ? &stop_hash : NULL);
    LOG_INFO("headers",
             "range-parallel: peer=%d span=[%d,%d] fast_peers=%d gap=%d",
             node->id, lo, hi, fast_peers, gap);
    return true;
}
