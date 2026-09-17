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

static bool range_request_context_valid(const struct msg_processor *mp,
                                        const struct p2p_node *node)
{
    return mp && node && mp->main_state && mp->net_mgr && mp->params;
}

static bool range_peer_is_active(const struct p2p_node *node)
{
    return node && !node->inbound && !node->disconnect &&
           node->state >= PEER_ACTIVE &&
           peer_supports_fast_sync(node->services);
}

static int range_collect_target(struct msg_processor *mp,
                                int initial_target,
                                int *fast_peers)
{
    int target = initial_target;
    *fast_peers = 0;
    zcl_mutex_lock(&mp->net_mgr->cs_nodes);
    for (size_t i = 0; i < mp->net_mgr->num_nodes; i++) {
        struct p2p_node *candidate = mp->net_mgr->nodes[i];
        if (range_peer_is_active(candidate)) {
            (*fast_peers)++;
            target = hrs_include_peer_target(target,
                                             candidate->starting_height);
        }
    }
    zcl_mutex_unlock(&mp->net_mgr->cs_nodes);
    return target;
}

static size_t range_collect_anchors(const struct checkpoint_data *cpd,
                                    int our_height,
                                    int target,
                                    int32_t anchors[HRS_MAX_SPANS])
{
    size_t count = 0;
    if (!cpd || !cpd->entries)
        return 0;
    for (int i = 0; i < cpd->nEntries && count < HRS_MAX_SPANS; i++) {
        int height = cpd->entries[i].height;
        if (height > our_height && height < target)
            anchors[count++] = (int32_t)height;
    }
    return count;
}

static bool range_stall_was_reported(const int32_t *stalled_ids,
                                     size_t before,
                                     int32_t peer_id)
{
    for (size_t i = 0; i < before; i++) {
        if (stalled_ids[i] == peer_id)
            return true;
    }
    return false;
}

static void range_report_expired(struct header_range_scheduler *sched,
                                 int64_t now_us)
{
    int32_t stalled_ids[HRS_MAX_SPANS];
    size_t count = hrs_sweep_expired(sched, now_us, stalled_ids,
                                     HRS_MAX_SPANS);
    for (size_t i = 0; i < count; i++) {
        int32_t peer_id = stalled_ids[i];
        if (range_stall_was_reported(stalled_ids, i, peer_id))
            continue;
        event_emitf(EV_HEADERS_REJECTED, (uint32_t)peer_id,
                    "header span reclaimed from slow peer %d "
                    "(deadline missed; span reassigned, not scored)",
                    (int)peer_id);
    }
}

static bool range_claim_peer_span(struct header_range_scheduler *sched,
                                  int32_t peer_id,
                                  int64_t now_us,
                                  int32_t *lo,
                                  int32_t *hi)
{
    if (hrs_peer_span(sched, peer_id, now_us, lo, hi))
        return true;
    if (hrs_assign(sched, peer_id, now_us) < 0)
        return false;
    return hrs_peer_span(sched, peer_id, now_us, lo, hi);
}

bool msg_try_range_parallel_getheaders(struct msg_processor *mp,
                                       struct p2p_node *node,
                                       int our_height, int64_t now_us)
{
    if (!range_request_context_valid(mp, node))
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
    target = range_collect_target(mp, target, &fast_peers);
    int32_t gap = hrs_height_gap(target, our_height);
    if (!hrs_should_parallelize(fast_peers, gap, 2000))
        return false;

    int32_t anchors[HRS_MAX_SPANS];
    size_t n_anchors = range_collect_anchors(&mp->params->checkpointData,
                                             our_height, target, anchors);

    struct header_range_scheduler *sched = header_range_scheduler_global();
    hrs_plan(sched, (int32_t)our_height, target, anchors, n_anchors);
    if (ms->pindex_best_header)
        hrs_note_frontier(sched, ms->pindex_best_header->nHeight);

    /* Sweep globally: whichever peer ticks first releases every expired span.
     * Missing a performance deadline is reported and reassigned, never scored
     * as protocol misbehavior. */
    range_report_expired(sched, now_us);

    int32_t lo, hi;
    if (!range_claim_peer_span(sched, node->id, now_us, &lo, &hi))
        return false;

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
