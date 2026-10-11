/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

/* Focused sanitizer fixture. Compile this with tip_finalize_stage.c and
 * -DZCL_TESTING; it forces reader/shutdown overlap around the real public
 * cursor and EWMA readers without a node datadir or network. */

#include "jobs/tip_finalize_stage.h"
#include "util/stage.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>

struct stage {
    uint64_t cursor;
    int64_t ewma;
};

static _Atomic bool g_read;

static void probe_pause(void)
{
    const struct timespec pause = { .tv_sec = 0, .tv_nsec = 50000 };
    (void)nanosleep(&pause, NULL);
}

static stage_t *probe_stage_new(void)
{
    struct stage *s = malloc(sizeof(*s));
    if (s) {
        s->cursor = 7;
        s->ewma = 11;
    }
    return (stage_t *)s;
}

void stage_destroy(stage_t *stage) { free(stage); }
uint64_t stage_cursor(const stage_t *stage)
{
    probe_pause();
    return ((const struct stage *)stage)->cursor;
}
int64_t stage_step_us_ewma(const stage_t *stage)
{
    probe_pause();
    return ((const struct stage *)stage)->ewma;
}
void tip_finalize_evidence_clear(void) { }
void tip_finalize_visible_body_reset(void) { }
void tip_finalize_hooks_reset(void) { }
void tip_finalize_observe_shutdown(void) { }
void utxo_apply_sum_through_reset(void) { }
void reducer_frontier_provable_tip_reset(void) { }

static void *reader(void *unused)
{
    (void)unused;
    while (atomic_load(&g_read)) {
        (void)tip_finalize_stage_cursor();
        (void)tip_finalize_stage_step_us_ewma();
    }
    return NULL;
}

int main(void)
{
    pthread_t thread;
    stage_t *first = probe_stage_new();
    if (!first)
        return 2;
    tip_finalize_stage_test_install_stage(first);
    atomic_store(&g_read, true);
    if (pthread_create(&thread, NULL, reader, NULL) != 0)
        return 3;
    for (int i = 0; i < 5000; i++) {
        tip_finalize_stage_shutdown();
        stage_t *next = probe_stage_new();
        if (!next)
            return 4;
        tip_finalize_stage_test_install_stage(next);
    }
    atomic_store(&g_read, false);
    pthread_join(thread, NULL);
    tip_finalize_stage_shutdown();
    return 0;
}
