// one-result-type-ok:reducer-body-fsync-scoping-is-best-effort-void
/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * reducer_body_fsync — batched fdatasync scoping for the reducer drive's two
 * deferrable on-disk artifacts: the block bodies (blk*.dat) AND the append-only
 * event_log. See services/reducer_ingest_service.h for the enter/exit contract.
 *
 * The reducer fold defers two per-block fsync sources. (1) The body-persist
 * path (write_block_to_disk in reducer_persist_ingested_body_locked)
 * fdatasync()s each block on write. (2) event_log_append() fsync()s TWICE per
 * event, and the fold emits one EV_BLOCK_HEADER event/block ON the drive
 * thread — ~2 event fsyncs/block. Every one is an ext4
 * journal-commit barrier that dominates the fold / catch-up wait (the drive
 * thread parks in jbd2_log_wait_commit while the CPU is idle). This TU defers
 * both to the stage drain-batch boundary:
 *
 *   - enter() turns on disk_block_io deferred mode + event_log deferred mode,
 *     so block writes / event appends made inside the drive only buffer (page
 *     cache) instead of fdatasync()ing, and registers (once) the stage_batch_end
 *     pre-commit hook.
 *   - the pre-commit hook fdatasync()s every pending block file AND the
 *     event_log ONCE BEFORE the stage cursor / *_log rows that reference them
 *     commit — a false return from either VETOES the commit, so no durable
 *     marker ever outlives an unsynced body or event.
 *   - exit() does a final flush (for work written but not yet covered by a
 *     stage COMMIT) and leaves deferred mode, so unrelated write_block_to_disk
 *     / event_log callers (import, tests, at-tip) keep their immediate per-op
 *     fdatasync.
 *
 * Durability at tip is unchanged — only the fsync cadence drops from ~3/block
 * to ~1/batch. At tip the batch is a single block, so the artifacts are synced at
 * that block's own drain COMMIT: identical durability, one extra deferred hop.
 * During a LIVE CATCH-UP (peers connected, gap over threshold) the cadence
 * drops further — one flush per ZCL_CATCHUP_FSYNC_COMMIT_INTERVAL commits
 * (default 8, about one per drain round) — restoring the strict per-commit
 * regime the instant the gate closes. The mechanism, the bounded crash window
 * it accepts, and the recovery that covers the window are documented in the
 * "R1: catch-up ROUND cadence" block comment below.
 *
 * TIMING (drive+fsync telemetry gap 2): the flush above is bracketed with a
 * GetTimeMicros() pair so an IO stall INSIDE it (ext4 jbd2 journal-commit
 * wait, a slow/contended disk) becomes a visible number instead of an
 * indistinguishable-from-slow-fold mystery. last_flush_us is the most recent
 * sample; flush_us_ewma is an exponential moving average (alpha = 1/16,
 * integer arithmetic — identical shape to platform/modules/util/src/stage.c's
 * step_us_ewma) so a single slow outlier doesn't itself trip anything, only a
 * SUSTAINED regression does. Neither the veto-on-failed-flush contract nor
 * anything else about what gets fsynced or when changes — this is a clock
 * pair around an already-expensive fsync, negligible overhead. See
 * engine/conditions/src/batch_fsync_slow.c for the condition that watches the
 * EWMA against a budget. */

#include "services/reducer_ingest_service.h"

#include "core/utiltime.h"       /* GetTimeMicros */
#include "jobs/catchup_cadence.h" /* catchup_cadence_active_cached (R1 gate) */
#include "storage/disk_block_io.h"
#include "storage/event_log.h"
#include "storage/event_log_singleton.h"
#include "util/stage.h"

#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>              /* getenv, strtol */

static _Atomic bool g_body_fsync_hook_registered = false;
static _Atomic unsigned g_body_fsync_scope_depth = 0;

/* Single-writer: reducer_batched_durability_precommit fires only from
 * stage_batch_end(), which stage.c documents as serialized by the recursive
 * progress_store_tx_lock (at most one batch open/committing at a time) —
 * identical threading contract to stage.c's own step_us_ewma, so a plain
 * atomic_load/store read-modify-write here is race-free (matches
 * stage_record_step_timing exactly). Read from the reducer_drive dumpstate
 * thread and the batch_fsync_slow condition, hence atomics. */
static _Atomic int64_t g_fsync_last_flush_us;
static _Atomic int64_t g_fsync_flush_us_ewma;
/* Running totals beside the EWMA. The EWMA smooths ONE flush's duration and
 * counts nothing, so it cannot answer how many durability barriers a fold
 * actually pays — the question behind every "N fsyncs per block" claim. Each
 * flush here is exactly one barrier for one committing batch. */
static _Atomic uint64_t g_fsync_flush_count;
static _Atomic uint64_t g_fsync_flush_us_total;

/* ── R1: catch-up ROUND cadence ───────────────────────────────────────────
 * During a live catch-up (the same peers+gap gate the catch-up drain-batch /
 * tick overrides use — catchup_cadence_active_cached(), lock-free), the
 * pre-commit hook pays the body+event_log fdatasync once per
 * ZCL_CATCHUP_FSYNC_COMMIT_INTERVAL commits (default 8, clamp [1,64] — about
 * one per drain ROUND of eight stages) instead of once per batch COMMIT.
 * Measured against a 2026-09-14 cold-sync stopwatch: 5600 commits paid 5600
 * flushes for ~40-56 s of fsync_flush_us_total, ~3.5 flushes per drain round;
 * the interval demotes that to ~1 flush per round. Only the CADENCE changes:
 *
 *   - every flush that DOES run keeps the exact veto verdict (a false return
 *     still rolls the batch back), and the EWMA/total/count telemetry keeps
 *     counting real flushes only (batch_fsync_slow is untouched);
 *   - every batched-scope EXIT still does its final flush, so the tail of an
 *     un-flushed run is bounded by the scope (one kick / one supervisor tick);
 *   - the moment the gate closes (gap under threshold — converging / at tip,
 *     or no peers) the hook flushes EVERY commit again: the strict
 *     bodies-before-commit regime plus the exit flush is the whole at-tip
 *     behavior, byte-for-byte unchanged. The mint fold and the synchronous
 *     ingest path never see the gate open (offline / no gap), so they keep
 *     the strict regime too.
 *
 * Crash-ordering window (progress.kv is synchronous=OFF during IBD/catch-up,
 * so a batch COMMIT becomes durable only at the next WAL checkpoint): with
 * the demotion, up to INTERVAL-1 consecutive committed batches (bounded by
 * one round, and further bounded by every scope exit's final flush) can have
 * their cursor / *_log rows checkpointed durable while their blk*.dat bytes
 * sit only in page cache. A power loss inside that window leaves durable
 * HAVE_DATA / stage-cursor claims whose body bytes were never synced. The
 * window is BOUNDED (one round) and RECOVERABLE with existing machinery: any
 * later read of a lost body fails closed — body_persist's step requeues it
 * (requeue_body_for_refetch clears BLOCK_HAVE_DATA, emits the status event,
 * and the normal !HAVE_DATA sync path re-downloads the body), the boot-time
 * scan re-derives HAVE_DATA from physical blk content when the contiguous
 * frontier lags, and the drop-bodiless gate (fb3a6c4142 lineage) clears
 * borrowed/byte-less claims. Today the same demotion is already accepted for
 * the whole cursor side: synchronous=OFF means lost commits replay from the
 * last checkpoint — R1 only lets the body side lag by the same bounded
 * amount, never more.
 *
 * The two load-bearing assertions are pinned by deterministic kill -9 fault
 * injection (tests/harness/src/test_reducer_body_fsync_crash.c, group
 * reducer_body_fsync_crash), which SIGKILLs a child mid-scope, after
 * cadence-demoted commits and before the next round flush:
 *
 *   (a) the durable frontier never precedes its data — after the kill the
 *       reopened store's durable cursor never exceeds the count of intact
 *       body records on disk (bodies are written AND fflushed before their
 *       batch COMMIT, always, so no committed cursor can reference bytes
 *       that never reached the kernel). When the demoted tail is then
 *       truncated away (emulating the power loss a kill -9 cannot produce),
 *       the bounded lag is observed (cursor ahead by at most INTERVAL-1
 *       commits) and repaired by re-writing the missing bodies — the same
 *       fail-closed body read the real requeue/rescan machinery keys on;
 *
 *   (b) no acknowledged write is lost — every commit the round flush
 *       covered (the only commits ever acknowledged durable while the gate
 *       is open) is fully durable after the crash: cursor row and body
 *       bytes both present. In both cycles the resumed datadir reaches a
 *       final durable state byte-identical to an uninterrupted golden run. */
static _Atomic uint64_t g_cadence_commits;
static _Atomic uint64_t g_cadence_deferred_total;

#define CATCHUP_FSYNC_COMMIT_INTERVAL_DEFAULT 8

static int catchup_fsync_commit_interval(void)
{
    const char *v = getenv("ZCL_CATCHUP_FSYNC_COMMIT_INTERVAL");
    if (!v || !v[0])
        return CATCHUP_FSYNC_COMMIT_INTERVAL_DEFAULT;
    char *end = NULL;
    long n = strtol(v, &end, 10);
    if (end == v)
        return CATCHUP_FSYNC_COMMIT_INTERVAL_DEFAULT;
    if (n < 1) n = 1;
    if (n > 64) n = 64;
    return (int)n;
}

#ifdef ZCL_TESTING
#include <time.h>
/* Test-only artificial delay injected at the top of the precommit flush, so
 * a unit test can prove the timing + EWMA + the batch_fsync_slow condition
 * fire on a genuine slow-flush without needing a real contended disk. 0 (the
 * default) is a no-op — compiled out entirely in production builds. */
static _Atomic int64_t g_test_inject_delay_us;

void reducer_body_fsync_test_set_inject_delay_us(int64_t us)
{
    atomic_store(&g_test_inject_delay_us, us);
}

void reducer_body_fsync_test_reset(void)
{
    atomic_store(&g_test_inject_delay_us, 0);
    atomic_store(&g_fsync_last_flush_us, 0);
    atomic_store(&g_fsync_flush_us_ewma, 0);
    atomic_store(&g_fsync_flush_count, 0u);
    atomic_store(&g_fsync_flush_us_total, 0u);
    atomic_store(&g_cadence_commits, 0u);
    atomic_store(&g_cadence_deferred_total, 0u);
}
#endif

static bool reducer_batched_durability_precommit(void)
{
    /* R1 round cadence (see the block comment above): while the live catch-up
     * gate is open, skip the flush on all but every INTERVAL-th commit. The
     * skip is a verdict of TRUE (no flush ran, nothing to veto) — the commit
     * proceeds; the deferred bytes are covered by the interval flush, every
     * scope exit's final flush, and the strict regime the moment the gate
     * closes. Telemetry keeps counting only flushes that genuinely run. */
    if (catchup_cadence_active_cached()) {
        uint64_t n = atomic_fetch_add(&g_cadence_commits, 1u) + 1u;
        if (n % (uint64_t)catchup_fsync_commit_interval() != 0) {
            atomic_fetch_add(&g_cadence_deferred_total, 1u);
            return true;
        }
    }
    int64_t t0 = GetTimeMicros();
#ifdef ZCL_TESTING
    int64_t inj = atomic_load(&g_test_inject_delay_us);
    if (inj > 0) {
        struct timespec ts = { .tv_sec = inj / 1000000,
                               .tv_nsec = (inj % 1000000) * 1000 };
        nanosleep(&ts, NULL);
    }
#endif
    /* Fired by stage_batch_end() immediately before COMMIT. Flush BOTH
     * deferred on-disk artifacts the fold defers — the block bodies
     * (blk*.dat, disk_block_io) AND the append-only event_log — so no
     * committed stage marker (cursor, *_log row) references unsynced bytes.
     * A false return from EITHER flush VETOES the commit (stage_batch_end
     * rolls back). Both are attempted (no short-circuit) so a transient
     * failure in one still fdatasyncs the other. Neither this ordering nor
     * the veto decision below is touched by the timing wrap — only the two
     * GetTimeMicros() reads and the atomic stores after are new. */
    bool bodies = disk_block_io_sync_pending();
    event_log_t *log = event_log_singleton();
    bool events = log ? event_log_flush(log) : true;

    int64_t elapsed_us = GetTimeMicros() - t0;
    if (elapsed_us < 0)
        elapsed_us = 0;
    atomic_store(&g_fsync_last_flush_us, elapsed_us);
    int64_t prev = atomic_load(&g_fsync_flush_us_ewma);
    int64_t next = (prev == 0) ? elapsed_us : prev + (elapsed_us - prev) / 16;
    atomic_store(&g_fsync_flush_us_ewma, next);
    atomic_fetch_add(&g_fsync_flush_count, 1u);
    atomic_fetch_add(&g_fsync_flush_us_total, (uint64_t)elapsed_us);

    return bodies && events;
}

void reducer_body_fsync_timing_snapshot(int64_t *last_flush_us,
                                        int64_t *flush_us_ewma)
{
    if (last_flush_us)
        *last_flush_us = atomic_load(&g_fsync_last_flush_us);
    if (flush_us_ewma)
        *flush_us_ewma = atomic_load(&g_fsync_flush_us_ewma);
}

void reducer_body_fsync_totals_snapshot(uint64_t *flush_count,
                                        uint64_t *flush_us_total)
{
    if (flush_count)
        *flush_count = atomic_load(&g_fsync_flush_count);
    if (flush_us_total)
        *flush_us_total = atomic_load(&g_fsync_flush_us_total);
}

void reducer_body_fsync_cadence_snapshot(uint64_t *deferred_total)
{
    if (deferred_total)
        *deferred_total = atomic_load(&g_cadence_deferred_total);
}

void reducer_body_fsync_scope_snapshot(unsigned *depth,
                                       bool *event_log_deferred)
{
    if (depth)
        *depth = atomic_load_explicit(&g_body_fsync_scope_depth,
                                      memory_order_acquire);
    if (event_log_deferred) {
        event_log_t *log = event_log_singleton();
        *event_log_deferred = log && event_log_deferred_sync_enabled(log);
    }
}

#ifdef ZCL_TESTING
/* Direct test hook: invokes the exact static precommit function stage.c's
 * hook would call, WITHOUT needing a real open stage_batch/DB — safe because
 * disk_block_io_sync_pending() is a no-op fast-path with nothing pending and
 * event_log_singleton() returns NULL (events=true) when no event log module
 * is open in the test process. Returns the same veto verdict the real hook
 * would return. */
bool reducer_body_fsync_test_trigger_precommit(void)
{
    return reducer_batched_durability_precommit();
}
#endif

void reducer_enter_batched_body_sync(void)
{
    bool was = atomic_exchange_explicit(&g_body_fsync_hook_registered, true,
                                        memory_order_relaxed);
    if (!was)
        stage_batch_set_precommit_hook(reducer_batched_durability_precommit);
    (void)atomic_fetch_add_explicit(&g_body_fsync_scope_depth, 1,
                                    memory_order_acq_rel);
    /* Reassert on EVERY nested entry. The event-log singleton can be wired
     * after an outer scope began during boot; treating nested entry as a pure
     * counter increment then leaves that late handle in per-append two-fsync
     * mode for the entire catch-up. These setters are idempotent, and depth>0
     * prevents a concurrent final exit while this entry owns its increment. */
    disk_block_io_set_deferred_sync(true);
    /* event_log is a per-handle flag; NULL singleton (early boot, offline
     * mint with emission suppressed) simply means nothing to defer/flush. */
    event_log_t *log = event_log_singleton();
    if (log)
        event_log_set_deferred_sync(log, true);
}

void reducer_exit_batched_body_sync(void)
{
    unsigned prior = atomic_load_explicit(&g_body_fsync_scope_depth,
                                          memory_order_acquire);
    while (prior > 0 &&
           !atomic_compare_exchange_weak_explicit(
               &g_body_fsync_scope_depth, &prior, prior - 1,
               memory_order_acq_rel, memory_order_acquire)) {
        /* retry with the observed depth */
    }
    if (prior == 0)
        return;
    if (prior > 1)
        return;

    /* Final flush for any body / event written but not yet covered by a stage
     * COMMIT (e.g. a drive that persisted work then advanced nothing this
     * pass), then leave deferred mode. Best-effort: a sync failure keeps the
     * artifact pending/dirty, and the still-registered hook retries (and
     * vetoes) at the next stage COMMIT, so no marker commits ahead of bytes. */
    (void)disk_block_io_sync_pending();
    disk_block_io_set_deferred_sync(false);
    event_log_t *log = event_log_singleton();
    if (log) {
        (void)event_log_flush(log);
        event_log_set_deferred_sync(log, false);
    }
}
