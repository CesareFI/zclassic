/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Queued-hash membership set for the block download manager — internal
 * to core/modules/net. Open addressing, linear probe, tombstoned
 * deletes. The queue array is the source of truth; the set only answers
 * "is this hash queued, and with which work class?" in O(1) so bulk
 * enqueues stop scanning the whole queue per item.
 * All helpers require the caller to hold dm->cs. */

#ifndef DOWNLOAD_QSET_H
#define DOWNLOAD_QSET_H

#include "net/download.h"
#include <stdbool.h>
#include <stddef.h>

#define DL_QUEUE_MAX_CAP 65536

/* FNV-1a hash for uint256 → slot index */
size_t dl_hash_slot(const struct uint256 *h, size_t mask);

const struct dl_queued_key *dl_qset_find(const struct download_manager *dm,
                                         const struct uint256 *hash);
bool dl_qset_contains(const struct download_manager *dm,
                      const struct uint256 *hash);

/* Insert without duplicate check (callers check dl_qset_contains first).
 * Reuses tombstones. Never fails once capacity is ensured. */
void dl_qset_insert_raw(struct download_manager *dm,
                        const struct uint256 *hash,
                        enum dl_work_class work_class);

/* Ensure room for one more live entry at < 50% combined load. */
void dl_qset_reserve_one(struct download_manager *dm);

/* Ensure room for `n_more` additional live entries at < 50% combined
 * load, in at most ONE rebuild up-front. */
void dl_qset_reserve_n(struct download_manager *dm, size_t n_more);

void dl_qset_remove(struct download_manager *dm, const struct uint256 *hash);
void dl_qset_clear(struct download_manager *dm);

#endif
