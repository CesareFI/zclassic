/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: state-contract coverage for the metaverse property view pair —
 * metaverse_view_determined() / metaverse_view_undetermined(). A
 * determined view must always name the exact read primitive that
 * answered ("verified" is unclaimable by omission), and a refused
 * determination must leave the view untouched; an undetermined view
 * clears status, evidence, actions and work while the settlement class (a fact
 * about the mechanism) survives. metaverse_view_determined had zero test
 * references; the pair's interplay had none either. */

#include "test/test_core.h"

#include "metaverse/property_view.h"
#include "metaverse/property_work.h"

#include <string.h>

/* A view in a representative mid-life state: an adapter has begun it,
 * measured work, resolved a status, and recorded actions. */
static void mvs_prime(struct metaverse_property_view *v)
{
    memset(v, 0, sizeof(*v));
    v->settlement = METAVERSE_SETTLEMENT_PROOF_OF_WORK;
    v->status = METAVERSE_STATUS_PRESENT;
    v->actions = 3;
    v->work.settlement = METAVERSE_SETTLEMENT_PROOF_OF_WORK;
    v->work.applicable = true;
    v->work.gap = METAVERSE_WORK_GAP_NONE;
    v->work.has_anchor_height = true;
    v->work.anchor_height = 3045000;
    v->work.has_tip_height = true;
    v->work.tip_height = 3045042;
    v->work.has_depth = true;
    v->work.depth = 42;
    v->work.has_chainwork = true;
    memset(v->work.chainwork_hex, 'a', sizeof(v->work.chainwork_hex) - 1);
    memcpy(v->reason, "previous read", sizeof("previous read"));
}

static int test_mvs_determined_null_view_refuses(void)
{
    int failures = 0;
    TEST("metaverse view: null view refuses determination") {
        ASSERT(!metaverse_view_determined(
            NULL, METAVERSE_EVIDENCE_LOCAL_STORE_READ, "store.get"));
        PASS();
    } _test_next:;
    return failures;
}

static int test_mvs_unknown_evidence_leaves_view_untouched(void)
{
    int failures = 0;
    TEST("metaverse view: UNKNOWN evidence refuses and touches nothing") {
        struct metaverse_property_view v;
        mvs_prime(&v);
        unsigned char before[sizeof(v)];
        memcpy(before, &v, sizeof(v));
        ASSERT(!metaverse_view_determined(&v, METAVERSE_EVIDENCE_UNKNOWN,
                                          "store.get"));
        ASSERT(memcmp(&v, before, sizeof(v)) == 0);
        PASS();
    } _test_next:;
    return failures;
}

static int test_mvs_source_must_be_named(void)
{
    int failures = 0;
    TEST("metaverse view: null or empty evidence source refuses untouched") {
        struct metaverse_property_view v;
        mvs_prime(&v);
        unsigned char before[sizeof(v)];
        memcpy(before, &v, sizeof(v));
        ASSERT(!metaverse_view_determined(&v,
                                          METAVERSE_EVIDENCE_LOCAL_STORE_READ,
                                          NULL));
        ASSERT(memcmp(&v, before, sizeof(v)) == 0);
        ASSERT(!metaverse_view_determined(&v,
                                          METAVERSE_EVIDENCE_LOCAL_STORE_READ,
                                          ""));
        ASSERT(memcmp(&v, before, sizeof(v)) == 0);
        PASS();
    } _test_next:;
    return failures;
}

static int test_mvs_valid_determination_records_evidence(void)
{
    int failures = 0;
    TEST("metaverse view: a determination names its evidence source") {
        struct metaverse_property_view v;
        mvs_prime(&v);
        static const char source[] = "vcs_package_manifest_root";
        ASSERT(metaverse_view_determined(
            &v, METAVERSE_EVIDENCE_LOCAL_MANIFEST_HASH, source));
        ASSERT(v.determined && v.populated);
        ASSERT(v.evidence == METAVERSE_EVIDENCE_LOCAL_MANIFEST_HASH);
        ASSERT(v.evidence_source == source);
        /* determined() records evidence; it does not pick a status. */
        ASSERT(v.status == METAVERSE_STATUS_PRESENT);
        PASS();
    } _test_next:;
    return failures;
}

static int test_mvs_undetermined_clears_but_settlement_survives(void)
{
    int failures = 0;
    TEST("metaverse view: undetermined clears measurements, keeps class") {
        struct metaverse_property_view v;
        mvs_prime(&v);
        ASSERT(metaverse_view_determined(
            &v, METAVERSE_EVIDENCE_LOCAL_STORE_READ, "store.get"));
        metaverse_view_undetermined(&v, "backend timeout %d", 42);
        ASSERT(!v.determined && v.populated);
        ASSERT(v.status == METAVERSE_STATUS_UNKNOWN);
        ASSERT(v.evidence == METAVERSE_EVIDENCE_UNKNOWN);
        ASSERT(v.evidence_source == NULL);
        ASSERT(v.actions == 0);
        ASSERT(strcmp(v.reason, "backend timeout 42") == 0);
        /* The settlement class is a fact about the mechanism, not this
         * read — it survives, with fresh "no anchor" work. */
        ASSERT(v.work.settlement == METAVERSE_SETTLEMENT_PROOF_OF_WORK);
        ASSERT(v.work.applicable);
        ASSERT(v.work.gap == METAVERSE_WORK_GAP_NO_ANCHOR);
        ASSERT(!v.work.has_anchor_height);
        ASSERT(v.settlement == METAVERSE_SETTLEMENT_PROOF_OF_WORK);
        ASSERT(v.work.anchor_height == -1);
        ASSERT(!v.work.has_tip_height && v.work.tip_height == -1);
        ASSERT(!v.work.has_depth && v.work.depth == -1);
        ASSERT(!v.work.has_chainwork && v.work.chainwork_hex[0] == '\0');
        PASS();
    } _test_next:;
    return failures;
}

static int test_mvs_undetermined_null_view_and_null_fmt(void)
{
    int failures = 0;
    TEST("metaverse view: undetermined null view is a no-op; null fmt "
         "leaves an empty reason") {
        metaverse_view_undetermined(NULL, "ignored %d", 1);
        struct metaverse_property_view v;
        mvs_prime(&v);
        metaverse_view_undetermined(&v, NULL);
        ASSERT(!v.determined && v.populated);
        ASSERT(v.reason[0] == '\0');
        PASS();
    } _test_next:;
    return failures;
}

int test_metaverse_view_state(void)
{
    int failures = 0;
    failures += test_mvs_determined_null_view_refuses();
    failures += test_mvs_unknown_evidence_leaves_view_untouched();
    failures += test_mvs_source_must_be_named();
    failures += test_mvs_valid_determination_records_evidence();
    failures += test_mvs_undetermined_clears_but_settlement_survives();
    failures += test_mvs_undetermined_null_view_and_null_fmt();
    printf("=== metaverse_view_state: %d failures ===\n", failures);
    return failures;
}
