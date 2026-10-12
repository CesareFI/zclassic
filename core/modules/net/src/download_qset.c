/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Queued-hash membership set for the block download manager.
 * See download_qset.h for the contract. */

#include "download_qset.h"
#include "util/safe_alloc.h"
#include <stdlib.h>
#include <string.h>

size_t dl_hash_slot(const struct uint256 *h, size_t mask)
{
    uint64_t fnv = 14695981039346656037ULL;
    for (int i = 0; i < 32; i++) {
        fnv ^= h->data[i];
        fnv *= 1099511628211ULL;
    }
    return (size_t)(fnv & mask);
}

const struct dl_queued_key *dl_qset_find(const struct download_manager *dm,
                                         const struct uint256 *hash)
{
    if (!dm->qset || dm->qset_slots == 0) return NULL;
    size_t mask = dm->qset_slots - 1;
    size_t idx = dl_hash_slot(hash, mask);
    for (size_t i = 0; i < dm->qset_slots; i++) {
        const struct dl_queued_key *e = &dm->qset[(idx + i) & mask];
        if (e->state == 0) return NULL;             /* virgin: chain end */
        if (e->state == 1 && uint256_eq(&e->hash, hash)) return e;
    }
    return NULL;
}

bool dl_qset_contains(const struct download_manager *dm,
                      const struct uint256 *hash)
{
    return dl_qset_find(dm, hash) != NULL;
}

void dl_qset_insert_raw(struct download_manager *dm,
                        const struct uint256 *hash,
                        enum dl_work_class work_class)
{
    size_t mask = dm->qset_slots - 1;
    size_t idx = dl_hash_slot(hash, mask);
    for (size_t i = 0; i < dm->qset_slots; i++) {
        struct dl_queued_key *e = &dm->qset[(idx + i) & mask];
        if (e->state != 1) {
            if (e->state == 2) dm->qset_tombs--;
            e->hash = *hash;
            e->work_class = work_class;
            e->state = 1;
            dm->qset_live++;
            return;
        }
    }
}

/* Rebuild the set from the queue array (drops tombstones), growing to
 * `new_slots` (power of 2). Keeps the old table on alloc failure —
 * correctness is unaffected, only probe lengths suffer. */
static void qset_rebuild(struct download_manager *dm, size_t new_slots)
{
    struct dl_queued_key *ns =
        zcl_calloc(new_slots, sizeof(struct dl_queued_key), "dl_qset");
    if (!ns) return;
    free(dm->qset);
    dm->qset = ns;
    dm->qset_slots = new_slots;
    dm->qset_live = 0;
    dm->qset_tombs = 0;
    for (size_t i = 0; i < dm->queue_len; i++)
        dl_qset_insert_raw(dm, &dm->queue[i], dm->queue_classes[i]);
}

void dl_qset_reserve_one(struct download_manager *dm)
{
    if (!dm->qset || dm->qset_slots == 0) return;
    if ((dm->qset_live + dm->qset_tombs + 1) * 2 < dm->qset_slots) return;
    size_t want = dm->qset_slots;
    if ((dm->qset_live + 1) * 2 >= want)
        want *= 2;                  /* genuinely full: grow */
    /* else: tombstone-heavy — rebuild at same size */
    qset_rebuild(dm, want);
}

/* Bulk callers MUST reserve before staging inserts: qset_rebuild
 * repopulates from dm->queue only, so a rebuild fired mid-batch (by a
 * per-insert reserve) wipes every staged-but-not-yet-merged hash from
 * the set — dedup breaks, blocks download twice, and the duplicate
 * in-flight slots leak num_active. Same reason dl_queue_push reserves
 * BEFORE its queue insertion. */
void dl_qset_reserve_n(struct download_manager *dm, size_t n_more)
{
    if (!dm->qset || dm->qset_slots == 0) return;
    /* Live entries are bounded by queue cap + one staged batch; clamp a
     * pathological request so the doubling below cannot overflow. Past
     * the clamp the set degrades to silent dedup misses, never UB. */
    if (n_more > (size_t)DL_QUEUE_MAX_CAP * 2)
        n_more = (size_t)DL_QUEUE_MAX_CAP * 2;
    size_t want = dm->qset_slots;
    while ((dm->qset_live + n_more + 1) * 2 >= want)
        want *= 2;
    if (want == dm->qset_slots &&
        (dm->qset_live + dm->qset_tombs + n_more + 1) * 2 < dm->qset_slots)
        return;             /* enough live+tombstone headroom already */
    qset_rebuild(dm, want);
}

void dl_qset_remove(struct download_manager *dm, const struct uint256 *hash)
{
    if (!dm->qset || dm->qset_slots == 0) return;
    size_t mask = dm->qset_slots - 1;
    size_t idx = dl_hash_slot(hash, mask);
    for (size_t i = 0; i < dm->qset_slots; i++) {
        struct dl_queued_key *e = &dm->qset[(idx + i) & mask];
        if (e->state == 0) return;
        if (e->state == 1 && uint256_eq(&e->hash, hash)) {
            e->state = 2;
            dm->qset_live--;
            dm->qset_tombs++;
            return;
        }
    }
}

void dl_qset_clear(struct download_manager *dm)
{
    if (!dm->qset || dm->qset_slots == 0) return;
    memset(dm->qset, 0, dm->qset_slots * sizeof(struct dl_queued_key));
    dm->qset_live = 0;
    dm->qset_tombs = 0;
}
