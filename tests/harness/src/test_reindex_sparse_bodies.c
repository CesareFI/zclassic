/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_reindex_sparse_bodies — a datadir where coins are seeded near a tip
 * height H but block bodies are SPARSE (present only for a tail window
 * [H-k, H], not contiguously from genesis) must REFUSE the destructive
 * -reindex-chainstate remedy instead of consuming the armed
 * auto_reindex_request sentinel: a full reindex-chainstate replays bodies
 * from genesis through the target height, which a sparse datadir cannot
 * supply. Companion to the coins-best-vs-anchor-height axis.
 *
 * WEAK-SYMBOL SEAM (test_always_sync_selfheal.c pattern): the decision
 * predicate `boot_reindex_coverage_would_refuse` is declared here as a
 * `__attribute__((weak))` extern:
 *
 *     bool boot_reindex_coverage_would_refuse(int32_t scan_reindex_best,
 *                                             int32_t scan_max_have_data_h)
 *
 * `scan_reindex_best` is the height the replay must reach;
 * `scan_max_have_data_h` is the highest height with body coverage CONTIGUOUS
 * FROM GENESIS (-1 if genesis lacks a body marker). Until the symbol links,
 * this file compiles and SKIPs cleanly.
 *
 * FIXTURE (a synthetic mini-datadir; the test exercises the DECISION given
 * two integers, not the scan that produces them):
 *
 *     <dir>/blocks/h<N>.body   — an empty marker file per height N whose
 *                                body is present, for N in [H-k, H] only.
 *     <dir>/coins_best         — "<height> <hash_verified 0|1>\n", the
 *                                seeded coins-best marker at height H.
 *     <dir>/auto_reindex_request — the real on-disk sentinel (see
 *                                storage/boot_auto_reindex.h), armed via
 *                                boot_auto_reindex_request().
 *
 * tools/scripts/make-sparse-bodies-fixture.sh builds the identical layout
 * for manual repro.
 *
 * The test drives the weak decision hook directly and simulates the two
 * effects of a boot pass wiring it in: clearing the sentinel on a refusal
 * (boot_auto_reindex_clear) and re-detecting the same wedge on a second pass
 * (a second boot_auto_reindex_request call). */

#include "test/test_core.h"

#include "storage/boot_auto_reindex.h"

#include <stdint.h>
#include <stdio.h>
#include <sys/stat.h>

#define RSB_CHECK(name, expr) do {                                          \
    printf("reindex_sparse_bodies: %s... ", (name));                       \
    if (expr) { printf("OK\n"); }                                          \
    else { printf("FAIL\n"); failures++; }                                 \
} while (0)

/* See this file's header comment for the assumed signature. */
#if defined(__APPLE__)
static bool (*const boot_reindex_coverage_would_refuse)(int32_t, int32_t) =
    NULL;
#else
extern bool boot_reindex_coverage_would_refuse(int32_t scan_reindex_best,
                                               int32_t scan_max_have_data_h)
    __attribute__((weak));
#endif

static bool rsb_touch_body(const char *dir, int32_t height)
{
    char path[600];
    int n = snprintf(path, sizeof(path), "%s/blocks/h%d.body", dir,
                     (int)height);
    if (n < 0 || n >= (int)sizeof(path))
        return false;
    FILE *f = fopen(path, "wb");
    if (!f)
        return false;
    return fclose(f) == 0;
}

/* Highest N such that every height in [0, N] has a body marker present
 * (contiguous coverage FROM GENESIS); -1 means even genesis has none. Bounded
 * by `upper_bound`. Test-local stand-in for the real coverage scan: this test
 * exercises the DECISION given the two resulting integers. */
static int32_t rsb_scan_max_have_data_h(const char *dir, int32_t upper_bound)
{
    char path[600];
    int32_t h = 0;
    for (; h <= upper_bound; h++) {
        int n = snprintf(path, sizeof(path), "%s/blocks/h%d.body", dir,
                         (int)h);
        if (n < 0 || n >= (int)sizeof(path))
            break;
        struct stat st;
        if (stat(path, &st) != 0)
            break;
    }
    return h - 1;
}

static bool rsb_write_coins_best(const char *dir, int32_t height,
                                 bool hash_verified)
{
    char path[600];
    int n = snprintf(path, sizeof(path), "%s/coins_best", dir);
    if (n < 0 || n >= (int)sizeof(path))
        return false;
    FILE *f = fopen(path, "w");
    if (!f)
        return false;
    bool ok = fprintf(f, "%d %d\n", (int)height, hash_verified ? 1 : 0) > 0;
    return fclose(f) == 0 && ok;
}

static bool rsb_read_coins_best(const char *dir, int32_t *height,
                                bool *hash_verified)
{
    char path[600];
    int n = snprintf(path, sizeof(path), "%s/coins_best", dir);
    if (n < 0 || n >= (int)sizeof(path))
        return false;
    FILE *f = fopen(path, "r");
    if (!f)
        return false;
    int h = 0, v = 0;
    bool ok = fscanf(f, "%d %d", &h, &v) == 2;
    fclose(f);
    if (!ok)
        return false;
    *height = (int32_t)h;
    *hash_verified = (v != 0);
    return true;
}

int test_reindex_sparse_bodies(void);
int test_reindex_sparse_bodies(void)
{
    printf("\n=== reindex_sparse_bodies (Track B decision: sparse bodies "
          "refuse reindex) ===\n");
    int failures = 0;

    if (!boot_reindex_coverage_would_refuse) {
        printf("reindex_sparse_bodies: SKIP — "
              "boot_reindex_coverage_would_refuse not yet linked (lane 2B's "
              "body-coverage-aware reindex decision, a sibling worktree, "
              "not yet merged); this becomes the integration regression "
              "gate once that lane lands. ASSUMED SIGNATURE (see this "
              "file's header comment): bool "
              "boot_reindex_coverage_would_refuse(int32_t "
              "scan_reindex_best, int32_t scan_max_have_data_h)\n");
        return 0;
    }

    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "reindex_sparse_bodies", "main");
    char blocks_dir[300];
    int bn = snprintf(blocks_dir, sizeof(blocks_dir), "%s/blocks", dir);
    RSB_CHECK("fixture path formatted",
             bn > 0 && bn < (int)sizeof(blocks_dir));
    RSB_CHECK("blocks/ subdir created", mkdir(blocks_dir, 0755) == 0);

    const int32_t H = 5000;   /* coins seeded at this height (the wedge tip) */
    const int32_t K = 100;    /* bodies present only in [H-K, H] */

    bool bodies_ok = true;
    for (int32_t h = H - K; h <= H; h++)
        bodies_ok = rsb_touch_body(dir, h) && bodies_ok;
    RSB_CHECK("sparse bodies fixture written for [H-K, H]", bodies_ok);

    RSB_CHECK("coins-best marker seeded at H (hash-verified)",
             rsb_write_coins_best(dir, H, true));

    int n1 = boot_auto_reindex_request(dir, H, BOOT_AUTO_REINDEX_REASON_UNSPECIFIED);
    RSB_CHECK("auto_reindex_request sentinel armed on pass 1", n1 == 1);
    RSB_CHECK("sentinel PENDS after arming (pass 1)",
             boot_auto_reindex_pending(dir));

    int32_t scan_max_have_data_h = rsb_scan_max_have_data_h(dir, H);
    RSB_CHECK("body coverage has NO contiguous-from-genesis span (sparse: "
             "genesis itself lacks a body marker)",
             scan_max_have_data_h == -1);

    int32_t coins_h = -1;
    bool coins_verified = false;
    RSB_CHECK("coins-best marker reads back",
             rsb_read_coins_best(dir, &coins_h, &coins_verified) &&
             coins_h == H && coins_verified);
    int32_t scan_reindex_best = coins_h;

    bool refuses = boot_reindex_coverage_would_refuse(scan_reindex_best,
                                                       scan_max_have_data_h);
    RSB_CHECK("decision REFUSES reindex — bodies do not cover the target "
             "(a reindex-chainstate replay from genesis cannot complete, "
             "would only wipe the seeded coins)", refuses);

    /* Simulated boot wiring at the sentinel-consume chokepoint: a refusal
     * clears the stale request instead of consuming it. */
    if (refuses)
        boot_auto_reindex_clear(dir);
    RSB_CHECK("sentinel CLEARED after the refusal (pass 1) — never consumed "
             "into a destructive reindex", !boot_auto_reindex_pending(dir));

    /* Second pass: the node restarts, re-detects the identical wedge and arms
     * a fresh request. The decision must refuse AGAIN (deterministic on
     * unchanged inputs) and the sentinel must not be left pending: no re-arm,
     * no reindex-then-clear loop. */
    int n2 = boot_auto_reindex_request(dir, H, BOOT_AUTO_REINDEX_REASON_UNSPECIFIED);
    RSB_CHECK("sentinel re-arms via the boot pass's OWN detection (pass 2, "
             "not a leftover from pass 1)", n2 >= 1);
    bool refuses2 = boot_reindex_coverage_would_refuse(scan_reindex_best,
                                                        scan_max_have_data_h);
    RSB_CHECK("decision refuses again on pass 2 (deterministic on the same "
             "sparse-bodies input)", refuses2);
    if (refuses2)
        boot_auto_reindex_clear(dir);
    RSB_CHECK("sentinel does NOT re-arm — cleared again at the end of pass "
             "2 (no unbounded loop on a bodyless datadir)",
             !boot_auto_reindex_pending(dir));

    test_cleanup_tmpdir(blocks_dir);
    test_cleanup_tmpdir(dir);

    if (failures == 0)
        printf("=== reindex_sparse_bodies: ALL PASS ===\n\n");
    else
        printf("reindex_sparse_bodies: failures=%d\n", failures);
    return failures;
}
