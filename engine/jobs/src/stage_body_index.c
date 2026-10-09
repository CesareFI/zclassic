/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * PURPOSE: Resolve a hash-bound body owner for reducer stages. */

#include "jobs/stage_body_index.h"

#include "chain/chain.h"
#include "services/chain_state_service.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"

struct block_index *stage_body_index_at(struct main_state *ms, int height)
{
    if (!ms || height < 0)
        return NULL;

    /* Header admission publishes the best-header slot through the chain-state
     * repository.  Take the matching frontier snapshot rather than reading
     * that slot concurrently with a promotion.  The returned block-index
     * pointers have process lifetime, so they remain valid after the capture
     * releases its locks. */
    struct chain_state_frontier_view frontier;
    if (!csr_capture_frontiers(csr_instance(), &ms->chain_active,
                               &ms->pindex_best_header, height,
                               &frontier).ok)
        return NULL;

    struct block_index *canonical = frontier.window.requested;
    if (!canonical && frontier.header_tip &&
        height <= frontier.header_tip->nHeight)
        canonical = block_index_get_ancestor(frontier.header_tip, height);
    if (!canonical || !canonical->phashBlock)
        return NULL;
    if (block_index_status_load(canonical) & BLOCK_HAVE_DATA)
        return canonical;

    struct block_index *body =
        block_map_find(&ms->map_block_index, canonical->phashBlock);
    if (!body || body->nHeight != height ||
        !(block_index_status_load(body) & BLOCK_HAVE_DATA) ||
        (block_index_status_load(body) & BLOCK_FAILED_MASK))
        return canonical;
    return body;
}
