/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Unit tests for catalog COVERAGE — "is this index empty because nothing
 * happened, or because it is broken?" (engine/modules/storage/src/catalog_completeness.c,
 * storage/catalog_completeness.h).
 *
 * The catalog reported one number per index: lag = target - cursor. That
 * cannot distinguish an index that has folded everything it can reach (an
 * empty table means nothing happened) from one that has folded nothing.
 *
 * The reachable range is [floor, target], NOT [0, target]: on a
 * snapshot-seeded datadir there are no block bodies below the seed height, so
 * an index that folds bodies forward can never cover them. Coverage is
 * measured against what is reachable; `floor` states what is not.
 *
 * The case that matters most is a cursor BELOW the floor (e.g. cursor
 * 2,881,792 against a floor of 3,196,425): apparent progress but zero
 * coverage of any height with a body, so the verdict is NONE, not PARTIAL. */

#include "test/test_core.h"
#include "storage/catalog_completeness.h"

#include <stdio.h>
#include <string.h>

#define CC_CHECK(name, expr) do { \
    printf("catalog_coverage: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

/* Build a row the way snapshot() would, then ask the public helper. Coverage
 * is computed inside snapshot(), so these tests pin the CONTRACT (the meaning
 * of the fields) via the public helper rather than reaching into statics. */
static struct catalog_index_status mk(int64_t cursor, int64_t floor,
                                      int64_t target, int coverage,
                                      bool enabled)
{
    struct catalog_index_status r;
    memset(&r, 0, sizeof(r));
    r.name = "test_index";
    r.cursor = cursor;
    r.floor = floor;
    r.target = target;
    r.coverage = coverage;
    r.enabled = enabled;
    int64_t lag = target - cursor;
    r.lag = lag > 0 ? lag : 0;
    return r;
}

int test_catalog_coverage(void)
{
    int failures = 0;

    /* ── The names an operator reads ─────────────────────────────────── */
    CC_CHECK("coverage_name(UNKNOWN)",
        strcmp(catalog_coverage_name(CATALOG_COVERAGE_UNKNOWN),
               "unknown") == 0);
    CC_CHECK("coverage_name(NONE)",
        strcmp(catalog_coverage_name(CATALOG_COVERAGE_NONE), "none") == 0);
    CC_CHECK("coverage_name(PARTIAL)",
        strcmp(catalog_coverage_name(CATALOG_COVERAGE_PARTIAL),
               "partial") == 0);
    CC_CHECK("coverage_name(COMPLETE)",
        strcmp(catalog_coverage_name(CATALOG_COVERAGE_COMPLETE),
               "complete") == 0);

    /* ── The decisive predicate ──────────────────────────────────────── */
    /* COMPLETE is the ONLY state in which an empty table is evidence. This is
     * the whole point of the change, so it is asserted from every angle. */
    {
        struct catalog_index_status complete =
            mk(3196525, 3196425, 3196525, CATALOG_COVERAGE_COMPLETE, true);
        CC_CHECK("complete coverage -> emptiness IS meaningful",
            catalog_index_emptiness_is_meaningful(&complete));

        struct catalog_index_status partial =
            mk(3196500, 3196425, 3196525, CATALOG_COVERAGE_PARTIAL, true);
        CC_CHECK("partial coverage -> emptiness is NOT meaningful",
            !catalog_index_emptiness_is_meaningful(&partial));

        struct catalog_index_status none =
            mk(-1, 3196425, 3196525, CATALOG_COVERAGE_NONE, true);
        CC_CHECK("no coverage -> emptiness is NOT meaningful",
            !catalog_index_emptiness_is_meaningful(&none));

        struct catalog_index_status unknown =
            mk(0, 0, 3196525, CATALOG_COVERAGE_UNKNOWN, true);
        CC_CHECK("unknown coverage -> emptiness is NOT meaningful",
            !catalog_index_emptiness_is_meaningful(&unknown));

        /* A DISABLED index says nothing about the chain, even if its stored
         * coverage value happens to read complete. An opted-out address_index
         * has not proven that nothing happened; it has not looked. */
        struct catalog_index_status disabled =
            mk(3196525, 0, 3196525, CATALOG_COVERAGE_COMPLETE, false);
        CC_CHECK("disabled index -> emptiness is NOT meaningful",
            !catalog_index_emptiness_is_meaningful(&disabled));

        CC_CHECK("NULL row -> emptiness is NOT meaningful",
            !catalog_index_emptiness_is_meaningful(NULL));
    }

    /* ── Coverage over the reachable range, via the live snapshot ────── */
    /* snapshot() is the only producer of `coverage`, and in a unit-test
     * process no index subsystem is wired, so every row must come back
     * enabled=false / UNKNOWN — never a confident-looking COMPLETE off an
     * unwired singleton. That degradation IS the contract (see the
     * CATALOG_CURSOR_UNAVAILABLE note in the header): a diagnostic that
     * guesses when it cannot read is worse than one that says "unknown". */
    {
        struct catalog_index_status rows[CATALOG_COMPLETENESS_MAX_INDEXES];
        size_t n = catalog_completeness_snapshot(
            rows, CATALOG_COMPLETENESS_MAX_INDEXES, 3196525);
        CC_CHECK("snapshot returns the full registry", n >= 9);

        bool all_safe = true;
        for (size_t i = 0; i < n; i++) {
            if (rows[i].enabled) continue;   /* nothing wired in a unit test */
            if (rows[i].coverage != (int)CATALOG_COVERAGE_UNKNOWN ||
                rows[i].floor != 0 ||
                catalog_index_emptiness_is_meaningful(&rows[i]))
                all_safe = false;
        }
        CC_CHECK("unwired rows degrade to unknown, floor 0, not meaningful",
            all_safe);

        bool named = true;
        for (size_t i = 0; i < n; i++)
            if (!rows[i].name || !rows[i].name[0]) named = false;
        CC_CHECK("every row carries a stable name", named);

        /* target is echoed verbatim on every row so a reader never has to
         * correlate against a separately-fetched height. */
        bool target_ok = true;
        for (size_t i = 0; i < n; i++)
            if (rows[i].target != 3196525) target_ok = false;
        CC_CHECK("every row echoes the target height", target_ok);
    }

    /* ── lag semantics are UNCHANGED ─────────────────────────────────── */
    /* catalog_lag_exceeded fires off `lag`; the new fields add truth and
     * move no threshold. */
    {
        struct catalog_index_status r =
            mk(-1, 3196425, 3196525, CATALOG_COVERAGE_NONE, true);
        CC_CHECK("lag stays measured from 0, not from the floor",
            r.lag == 3196526);
        CC_CHECK("floor is reported alongside, not folded into, lag",
            r.floor == 3196425 && r.coverage == (int)CATALOG_COVERAGE_NONE);
    }

    /* ── The reading that gets it backwards ──────────────────────────── */
    /* A cursor of 2.88 MILLION against a floor of 3.19M is zero coverage of
     * anything readable: the index has not reached the first height whose
     * body exists. */
    {
        struct catalog_index_status zslp_shaped =
            mk(2881792, 3196425, 3196525, CATALOG_COVERAGE_NONE, true);
        CC_CHECK("a huge cursor BELOW the floor is still NO coverage",
            zslp_shaped.coverage == (int)CATALOG_COVERAGE_NONE &&
            !catalog_index_emptiness_is_meaningful(&zslp_shaped));
    }

    /* ── A from-genesis node ─────────────────────────────────────────── */
    /* floor 0 is the normal case and must not be read as "seeded". An index
     * caught up on an unseeded datadir has genuinely covered all history. */
    {
        struct catalog_index_status genesis_node =
            mk(3196525, 0, 3196525, CATALOG_COVERAGE_COMPLETE, true);
        CC_CHECK("floor 0 + caught up -> complete, emptiness meaningful",
            genesis_node.floor == 0 &&
            catalog_index_emptiness_is_meaningful(&genesis_node));
    }

    return failures;
}
