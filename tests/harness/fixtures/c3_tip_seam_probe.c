/* Copyright 2026 Rhett Creighton - Apache License 2.0 */
/* purpose: Measure finalization seams in registered isolated test groups. */
#define _POSIX_C_SOURCE 200809L
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

struct sqlite3;
struct stage;
struct main_state;
struct block_index;
extern void __real_progress_store_tx_lock(void);
extern void __real_progress_store_tx_unlock(void);
extern bool __real_tip_finalize_reconcile_visible_cursor_body(
    struct sqlite3 *, struct stage *, struct main_state *);
extern void __real_tip_finalize_run_post_finalize(struct block_index *);
extern int __real_test_tip_finalize_stage(void);
extern int __real_test_tip_finalize_post_step(void);

enum seam { LOCK_WAIT, LOCK_HOLD, VISIBLE, VISIBLE_EXCLUSIVE,
            POST_VISIBLE, POST_STAGE, POST_UNLOCKED, SEAM_COUNT };
struct totals { _Atomic uint64_t calls, wall_ns, cpu_ns, max_ns; };
static struct totals stats[SEAM_COUNT];
static _Atomic bool active;
static _Atomic unsigned pending;
static _Thread_local unsigned lock_depth, visible_depth;
static _Thread_local uint64_t lock_start, nested_post_ns;

static uint64_t now(clockid_t id)
{
    struct timespec t;
    if (clock_gettime(id, &t)) { perror("tip seam clock"); abort(); }
    return (uint64_t)t.tv_sec * UINT64_C(1000000000) + (uint64_t)t.tv_nsec;
}

static void observe(enum seam kind, uint64_t wall, uint64_t cpu)
{
    struct totals *s = &stats[kind];
    atomic_fetch_add(&s->calls, 1);
    atomic_fetch_add(&s->wall_ns, wall);
    atomic_fetch_add(&s->cpu_ns, cpu);
    uint64_t maximum = atomic_load(&s->max_ns);
    while (maximum < wall && !atomic_compare_exchange_weak(&s->max_ns, &maximum, wall)) {}
}

void __wrap_progress_store_tx_lock(void)
{
    if (!atomic_load(&active)) { __real_progress_store_tx_lock(); return; }
    uint64_t begin = now(CLOCK_MONOTONIC);
    __real_progress_store_tx_lock();
    if (lock_depth++ == 0) {
        lock_start = now(CLOCK_MONOTONIC);
        atomic_fetch_add(&pending, 1);
        observe(LOCK_WAIT, lock_start-begin, 0);
    }
}

void __wrap_progress_store_tx_unlock(void)
{
    bool outer = lock_depth && --lock_depth == 0;
    if (outer) observe(LOCK_HOLD, now(CLOCK_MONOTONIC)-lock_start, 0);
    __real_progress_store_tx_unlock();
    if (outer) atomic_fetch_sub(&pending, 1);
}

bool __wrap_tip_finalize_reconcile_visible_cursor_body(
    struct sqlite3 *db, struct stage *stage, struct main_state *ms)
{
    if (!atomic_load(&active))
        return __real_tip_finalize_reconcile_visible_cursor_body(db, stage, ms);
    atomic_fetch_add(&pending, 1);
    uint64_t begin = now(CLOCK_MONOTONIC), cpu = now(CLOCK_THREAD_CPUTIME_ID);
    uint64_t nested = nested_post_ns;
    visible_depth++;
    bool result = __real_tip_finalize_reconcile_visible_cursor_body(db, stage, ms);
    visible_depth--;
    uint64_t wall = now(CLOCK_MONOTONIC)-begin;
    cpu = now(CLOCK_THREAD_CPUTIME_ID)-cpu;
    observe(VISIBLE, wall, cpu);
    nested = nested_post_ns-nested;
    observe(VISIBLE_EXCLUSIVE, wall >= nested ? wall-nested : 0, 0);
    atomic_fetch_sub(&pending, 1);
    return result;
}

void __wrap_tip_finalize_run_post_finalize(struct block_index *index)
{
    if (!atomic_load(&active)) { __real_tip_finalize_run_post_finalize(index); return; }
    atomic_fetch_add(&pending, 1);
    uint64_t begin = now(CLOCK_MONOTONIC), cpu = now(CLOCK_THREAD_CPUTIME_ID);
    __real_tip_finalize_run_post_finalize(index);
    uint64_t wall = now(CLOCK_MONOTONIC)-begin;
    cpu = now(CLOCK_THREAD_CPUTIME_ID)-cpu;
    observe(!lock_depth ? POST_UNLOCKED : visible_depth ? POST_VISIBLE : POST_STAGE, wall, cpu);
    if (visible_depth) nested_post_ns += wall;
    atomic_fetch_sub(&pending, 1);
}

static int finish(const char *group, int failures)
{
    atomic_store(&active, false);
    unsigned unfinished = atomic_load(&pending);
    const char *names[] = {"progress_lock_wait", "progress_lock_hold", "visible_inclusive",
        "visible_excluding_nested_post", "post_inside_visible", "post_inside_stage", "post_without_lock"};
    for (unsigned i = 0; i < SEAM_COUNT; i++) {
        char cpu[32] = "null";
        if (i == VISIBLE || i >= POST_VISIBLE)
            snprintf(cpu, sizeof(cpu), "%llu", (unsigned long long)atomic_load(&stats[i].cpu_ns));
        printf("{\"schema\":\"c3.tip_seam.v1\",\"group\":\"%s\",\"phase\":\"%s\","
               "\"calls\":%llu,\"wall_ns\":%llu,\"cpu_ns\":%s,\"max_ns\":%llu,"
               "\"unfinished_calls\":%u}\n", group, names[i],
               (unsigned long long)atomic_load(&stats[i].calls),
               (unsigned long long)atomic_load(&stats[i].wall_ns),
               cpu,
               (unsigned long long)atomic_load(&stats[i].max_ns), unfinished);
    }
    return failures + (unfinished ? 1 : 0);
}

int __wrap_test_tip_finalize_stage(void)
{
    atomic_store(&active, true);
    return finish("tip_finalize_stage", __real_test_tip_finalize_stage());
}

int __wrap_test_tip_finalize_post_step(void)
{
    atomic_store(&active, true);
    return finish("tip_finalize_post_step", __real_test_tip_finalize_post_step());
}
