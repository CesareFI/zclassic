/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0 */
#include "test/test_core.h"
#include "net/download.h"
#include "platform/time_compat.h"
#include "util/thread_registry.h"
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

enum { CONTENTION_QUEUE = 32768, CONTENTION_DUPLICATES = 2048,
       CONTENTION_ROUNDS = 20 };

struct contention_round {
    struct download_manager *dm;
    const struct uint256 *hashes;
    const int32_t *heights;
    pthread_mutex_t mu;
    pthread_cond_t cv;
    bool ready;
    bool go;
    size_t added;
    int64_t hold_us;
};

static void contention_hash(struct uint256 *hash, unsigned value)
{
    memset(hash, 0, sizeof(*hash));
    for (unsigned i = 0; i < 4; i++)
        hash->data[i] = (uint8_t)(value >> (i * 8));
    hash->data[31] = 0xB7;
}

static void *contention_duplicates(void *arg)
{
    struct contention_round *r = arg;
    /* The production mutex is recursive. The outer acquisition fixes the
     * interleaving: the fresh enqueue must contend with this duplicate call.
     * The barrier wait is excluded from the reported critical-section work. */
    zcl_mutex_lock(&r->dm->cs);
    pthread_mutex_lock(&r->mu);
    r->ready = true;
    pthread_cond_broadcast(&r->cv);
    while (!r->go)
        pthread_cond_wait(&r->cv, &r->mu);
    pthread_mutex_unlock(&r->mu);
    int64_t start_us = platform_time_monotonic_us();
    r->added = dl_queue_blocks(r->dm, r->hashes, r->heights,
                               CONTENTION_DUPLICATES);
    r->hold_us = platform_time_monotonic_us() - start_us;
    zcl_mutex_unlock(&r->dm->cs);
    return NULL;
}

static int contention_time_compare(const void *a, const void *b)
{
    int64_t x = *(const int64_t *)a, y = *(const int64_t *)b;
    return (x > y) - (x < y);
}

static bool contention_run_rounds(struct download_manager *dm,
                                  const struct uint256 *hashes,
                                  const int32_t *heights,
                                  int64_t holds[CONTENTION_ROUNDS],
                                  int64_t fresh[CONTENTION_ROUNDS],
                                  unsigned *completed,
                                  unsigned *over_100ms)
{
    struct contention_round r = {
        .dm = dm, .hashes = hashes, .heights = heights,
        .mu = PTHREAD_MUTEX_INITIALIZER, .cv = PTHREAD_COND_INITIALIZER
    };
    bool ok = true;
    for (unsigned i = 0; i < CONTENTION_ROUNDS; i++) {
        r.ready = false;
        r.go = false;
        pthread_t producer;
        if (thread_registry_spawn("test_dl_dupes", contention_duplicates,
                                  &r, &producer) != 0) {
            ok = false;
            break;
        }
        pthread_mutex_lock(&r.mu);
        while (!r.ready)
            pthread_cond_wait(&r.cv, &r.mu);
        struct uint256 first_seen;
        contention_hash(&first_seen, CONTENTION_QUEUE + i + 1);
        int32_t height = (int32_t)i + 1;
        int64_t start_us = platform_time_monotonic_us();
        r.go = true;
        pthread_cond_broadcast(&r.cv);
        pthread_mutex_unlock(&r.mu);
        size_t added = dl_queue_blocks_class(dm, &first_seen, &height,
                                             1, DL_WORK_HISTORY);
        fresh[i] = platform_time_monotonic_us() - start_us;
        pthread_join(producer, NULL);
        holds[i] = r.hold_us;
        if (holds[i] > 100000)
            (*over_100ms)++;
        struct dl_diagnostics d;
        dl_get_diagnostics(dm, &d);
        ok = added == 1 && r.added == 0 &&
             dm->queue_len == CONTENTION_QUEUE + i + 1 &&
             dm->qset_live == dm->queue_len && dm->queue_cap <= 65536 &&
             d.accounting_drift == 0;
        (*completed)++;
        if (!ok)
            break;
    }
    pthread_cond_destroy(&r.cv);
    pthread_mutex_destroy(&r.mu);
    return ok;
}

int test_download_contention(void);
int test_download_contention(void)
{
    int failures = 0;
    TEST("download duplicate-forward contention preserves fresh history and accounting") {
        struct uint256 *hashes = calloc(CONTENTION_QUEUE, sizeof(*hashes));
        int32_t *heights = calloc(CONTENTION_QUEUE, sizeof(*heights));
        if (!hashes || !heights) {
            free(hashes);
            free(heights);
            ASSERT(false);
        }
        for (unsigned i = 0; i < CONTENTION_QUEUE; i++) {
            contention_hash(&hashes[i], i + 1);
            heights[i] = (int32_t)i + 1000;
        }
        struct download_manager dm;
        dl_init(&dm);
        bool ok = dl_queue_blocks(&dm, hashes, heights, CONTENTION_QUEUE) ==
                  CONTENTION_QUEUE;
        int64_t holds[CONTENTION_ROUNDS] = {0};
        int64_t fresh[CONTENTION_ROUNDS] = {0};
        unsigned completed = 0, over_100ms = 0;
        ok = ok && contention_run_rounds(&dm, hashes, heights, holds, fresh,
                                         &completed, &over_100ms);
        /* Promotion must still work after repeated duplicate lookup and
         * queue growth; caching a class must not make history permanent. */
        struct uint256 promote;
        contention_hash(&promote, CONTENTION_QUEUE + 1);
        int32_t low = 1;
        ok = ok && dl_queue_blocks(&dm, &promote, &low, 1) == 0;
        struct uint256 assigned;
        ok = ok && dl_assign_to_peer(&dm, 7, &assigned, 1) == 1 &&
             uint256_eq(&assigned, &promote);
        ok = ok && dl_mark_received(&dm, &promote) == 7 &&
             dl_mark_received(&dm, &promote) == UINT32_MAX;
        qsort(holds, completed, sizeof(holds[0]), contention_time_compare);
        qsort(fresh, completed, sizeof(fresh[0]), contention_time_compare);
        if (completed == CONTENTION_ROUNDS)
            printf("[C3 download contention] rounds=20 queue=32768 duplicates=2048 "
                   "duplicate-lock-work-us p50=%lld p95=%lld "
                   "fresh-history-enqueue-us p50=%lld p95=%lld over100ms=%u\n",
                   (long long)holds[9], (long long)holds[18],
                   (long long)fresh[9], (long long)fresh[18], over_100ms);
        /* Receipt only: scheduler time cannot alter the correctness verdict.
         * This fixture proves queue mechanics, not public CLI or disk commit. */
        dl_free(&dm);
        free(heights);
        free(hashes);
        ASSERT(ok && completed == CONTENTION_ROUNDS);
        PASS();
    } _test_next:;
    return failures;
}
