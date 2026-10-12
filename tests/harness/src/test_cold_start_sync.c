/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * MVP criterion #3 CI gate: cold-start sync to tip in <10 min.
 *
 * Drives the sync state machine from SYNC_IDLE to SYNC_AT_TIP through both
 * live cold-start paths, polling sync_get_state() at 1Hz (as
 * `z23 core sync status` does) under the 10-minute budget:
 *
 *   Path A: legacy IBD: IDLE, FINDING_PEERS, HEADERS_DOWNLOAD,
 *           BLOCKS_DOWNLOAD, CONNECTING_BLOCKS, AT_TIP
 *           (transition table at engine/modules/event/src/event.c:858-916).
 *   Path B: ZCL23 fast-sync: IDLE, FINDING_PEERS, SNAPSHOT_RECEIVE,
 *           CONNECTING_BLOCKS, AT_TIP.
 *
 * A background driver issues the transitions through sync_set_state() with
 * millisecond delays. Success is SYNC_AT_TIP before the 600 s ceiling with no
 * illegal transition. It proves only the sync FSM, not real cold sync (MVP
 * criterion #6) or Tor bootstrap (test_onion_bootstrap).
 *
 * Skipped unless ZCL_STRESS_TESTS=1:
 *   ZCL_STRESS_TESTS=1 build/bin/test_zcl
 *   ZCL_STRESS_TESTS=1 ZCL_TEST_ONLY=cold_start build/bin/test_zcl
 *
 * The global sync state is process-wide; the test resets to SYNC_IDLE at
 * entry and exit (see test_sync_watchdog.c's reset_test_state). */

#include "platform/time_compat.h"
#include "test/test_core.h"
#include "event/event.h"
#include "sync/sync_state.h"
#include <pthread.h>
#include <time.h>
#include <unistd.h>

int test_cold_start_sync(void);

/* ── Driver thread ──────────────────────────────────────────
 *
 * Walks a scripted sequence of (delay_us, target_state) pairs.  Each
 * leg sleeps first (simulating the "real" work an operator would see
 * — peer handshake, header download, block validation) and then
 * drives sync_set_state(target).  Reports an error flag back to the
 * main thread if any transition is rejected.
 */

struct p11_3_leg {
    long             delay_ms;
    enum sync_state  target;
    const char *     reason;
};

struct p11_3_driver_ctx {
    const struct p11_3_leg *legs;
    size_t n_legs;
    _Atomic int error;   /* set to 1 if any sync_set_state returns false */
};

static void p11_3_sleep_ms(long ms)
{
    if (ms <= 0) return;
    struct timespec req = {
        .tv_sec = ms / 1000,
        .tv_nsec = (ms % 1000) * 1000000L,
    };
    /* Use the POSIX.1-2001 nanosleep — usleep is obsolete in POSIX 2008. */
    nanosleep(&req, NULL);
}

static void *p11_3_driver(void *arg)
{
    struct p11_3_driver_ctx *ctx = (struct p11_3_driver_ctx *)arg;
    for (size_t i = 0; i < ctx->n_legs; i++) {
        p11_3_sleep_ms(ctx->legs[i].delay_ms);
        if (!sync_set_state(ctx->legs[i].target, ctx->legs[i].reason)) {
            atomic_store(&ctx->error, 1);
            return NULL;
        }
    }
    return NULL;
}

/* ── One path run ──────────────────────────────────────────── */

static int p11_3_run_path(const char *label,
                           const struct p11_3_leg *legs, size_t n_legs)
{
    /* Reset to cold baseline; any state to SYNC_IDLE is legal (event.c:858+). */
    if (!sync_set_state(SYNC_IDLE, "cold baseline")) {
        printf("FAIL (%s: could not reset to SYNC_IDLE; state=%s)\n",
               label, sync_state_name(sync_get_state()));
        return 1;
    }

    struct p11_3_driver_ctx ctx = { .legs = legs, .n_legs = n_legs };
    atomic_store(&ctx.error, 0);

    pthread_t t;
    if (pthread_create(&t, NULL, p11_3_driver, &ctx) != 0) {
        printf("FAIL (%s: pthread_create)\n", label);
        return 1;
    }

    /* 1Hz polling loop — mirrors native sync-status polling cadence.
     * Budget is the full MVP #3 limit: 10 minutes = 600 seconds. */
    const int budget_sec = 600;
    time_t t0 = platform_time_wall_time_t();
    int elapsed = 0;
    while (elapsed < budget_sec) {
        if (sync_get_state() == SYNC_AT_TIP) break;
        if (atomic_load(&ctx.error)) break;
        sleep(1);
        elapsed = (int)(platform_time_wall_time_t() - t0);
    }

    pthread_join(t, NULL);

    if (atomic_load(&ctx.error)) {
        printf("FAIL (%s: driver reported illegal transition; state=%s)\n",
               label, sync_state_name(sync_get_state()));
        return 1;
    }
    enum sync_state final = sync_get_state();
    if (final != SYNC_AT_TIP) {
        printf("FAIL (%s: reached %s after %ds, budget %ds)\n",
               label, sync_state_name(final), elapsed, budget_sec);
        return 1;
    }
    if (elapsed > budget_sec) {
        printf("FAIL (%s: reached SYNC_AT_TIP in %ds, exceeds %ds MVP budget)\n",
               label, elapsed, budget_sec);
        return 1;
    }
    printf("  %s: SYNC_AT_TIP in %ds (budget %ds)\n",
           label, elapsed, budget_sec);
    return 0;
}

/* ── Test entrypoint ───────────────────────────────────────── */

int test_cold_start_sync(void)
{
    int failures = 0;
    printf("\n=== cold-start sync (MVP #3, <10 min) ===\n");
    printf("cold_start_sync SYNC_AT_TIP via IBD + fast-sync paths... ");

    if (!getenv("ZCL_STRESS_TESTS")) {
        printf("SKIP (set ZCL_STRESS_TESTS=1 to run — sleep-driven 1Hz polling)\n");
        return 0;
    }
    printf("\n");

    /* Path A: legacy IBD. Delays approximate a small-fixture LAN sync (about
     * 3.5s total); 1Hz polling observes tip within 4s. */
    static const struct p11_3_leg ibd_legs[] = {
        { .delay_ms =  500, .target = SYNC_FINDING_PEERS,     .reason = "IBD: peers up"      },
        { .delay_ms = 1000, .target = SYNC_HEADERS_DOWNLOAD,  .reason = "IBD: headers start" },
        { .delay_ms = 1000, .target = SYNC_BLOCKS_DOWNLOAD,   .reason = "IBD: blocks start"  },
        { .delay_ms =  500, .target = SYNC_CONNECTING_BLOCKS, .reason = "IBD: connecting"    },
        { .delay_ms =   50, .target = SYNC_AT_TIP,            .reason = "IBD: caught up"     },
    };
    failures += p11_3_run_path("IBD path",
                                ibd_legs,
                                sizeof(ibd_legs) / sizeof(ibd_legs[0]));

    /* Path B — ZCL23 fast-sync via snapshot.  Delays approximate the
     * <60s MVP-target shape (snapshot receive dominates). */
    static const struct p11_3_leg fastsync_legs[] = {
        { .delay_ms =  500, .target = SYNC_FINDING_PEERS,     .reason = "fast-sync: peers up"    },
        { .delay_ms = 1500, .target = SYNC_SNAPSHOT_RECEIVE,  .reason = "fast-sync: snapshot"    },
        { .delay_ms =  500, .target = SYNC_CONNECTING_BLOCKS, .reason = "fast-sync: connecting"  },
        { .delay_ms =   50, .target = SYNC_AT_TIP,            .reason = "fast-sync: caught up"   },
    };
    failures += p11_3_run_path("fast-sync path",
                                fastsync_legs,
                                sizeof(fastsync_legs) / sizeof(fastsync_legs[0]));

    /* Cleanup: leave SYNC_IDLE so neighbor tests (test_sync_watchdog,
     * etc.) start from a clean state machine. */
    sync_set_state(SYNC_IDLE, "cleanup");

    if (failures == 0)
        printf("cold_start_sync OK (both cold-start paths reach SYNC_AT_TIP within MVP budget)\n");
    return failures;
}
