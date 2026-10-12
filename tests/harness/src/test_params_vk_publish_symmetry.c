/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The publish/release invariant in core/modules/sapling/src/params_init.c,
 * pinned for ALL FOUR shielded verifying keys.
 *
 * Four keys arm the four shielded verifiers:
 *
 *   sapling_spend_vk    sapling_check_spend        (sapling.c)
 *   sapling_output_vk   sapling_check_output       (sapling.c)
 *   sprout_vk           sprout_verify_groth16      (sprout.c)
 *   phgr_vk             sprout_verify_phgr13       (bn254.c)
 *
 * Each verifier is fail-closed on a NULL key, so the set of published
 * pointers is the process's answer to "is shielded validation armed?" and
 * the four must agree. sprout_phgr_vk_loaded() is a production accessor that
 * contextual_check_tx_proofs_unverifiable()
 * (core/modules/validation/src/contextual_check_tx.c) reads to decide whether
 * a pre-Sapling JoinSplit is checkable (PHGR13 is not covered by the
 * params_loaded latch), so this group asserts through that accessor as well
 * as the test-only pointer peek, and asserts they agree.
 *
 * ── Which release site may touch which key ──────────────────────────────
 *
 *   trio   spend_vk, output_vk, sprout_groth16_vk
 *          params_publish_groth16_vks() / params_release_groth16_vks()
 *   phgr   phgr_vk
 *          sprout_phgr_set_vk(&phgr_vk) / params_release_phgr_vk()
 *
 * PRE-PUBLICATION releases (params_release_groth16_vks() inside
 * params_load_first_locked() and params_install_embedded_locked()) run only
 * with nothing of ours published, so their unpublish half is defence in
 * depth.
 *
 * THE LATE PATH RELEASES NOTHING. params_load_late_proving_locked() runs with
 * all four keys published and verifiers reading them unlocked; each failure
 * frees only its own buffers, so a refused late upgrade costs the proving
 * capability and nothing else (section 6).
 *
 * POST-PUBLICATION release: sapling_free_params() only, the one place that
 * runs with keys live and releases all four.
 *
 * params_release_phgr_vk() must never be added to a failure path: a node on
 * the compiled-in keys that refused an arriving directory would lose its
 * PHGR13 verifier and with it blocks 0-581876.
 *
 * What this group pins:
 *
 *   1. Nothing is published before a load runs.
 *   2. A load arms all four together.
 *   3. sapling_free_params() disarms all four together, with no manual
 *      sprout_phgr_set_vk(NULL).
 *   4. The PHGR13 key has ONE storage instance: a reload republishes the same
 *      address.
 *   5. Reload cycles do not accumulate allocations (asserted structurally; a
 *      dropped ic[] is a finding for leak-checking runs).
 *   6. A refused LATE proving load leaves all four armed.
 *
 * Needs no parameter directory and touches no datadir: the compiled-in
 * verifying keys are the whole fixture.
 */

#include "test/test_core.h"

#include "sapling/bls12_381.h"
#include "sapling/bn254.h"
#include "sapling/params_init.h"
#include "sapling/params_vk_embedded.h"
#include "sapling/sapling.h"
#include "sapling/sprout.h"

#include <stdio.h>

#define SYM_CHECK(name, expr) do { \
    printf("params_vk_publish_symmetry: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

/* How many of the four verifiers are armed right now. The four must never
 * disagree, so assertions are on 0 and 4. The PHGR13 leg is read through the
 * production accessor sprout_phgr_vk_loaded() and the test-only pointer peek,
 * which must agree. */
static int armed_verifier_count(void)
{
    int n = 0;
    if (sapling_test_published_spend_vk() != NULL) n++;
    if (sapling_test_published_output_vk() != NULL) n++;
    if (sprout_test_published_vk() != NULL) n++;
    if (sprout_phgr_vk_loaded()) n++;
    return n;
}

/* The production accessor and the published pointer are the same fact seen two
 * ways; if they ever part company, one of the two is lying to consensus. */
static bool phgr_accessor_agrees_with_pointer(void)
{
    return sprout_phgr_vk_loaded() == (sprout_test_published_phgr_vk() != NULL);
}

int test_params_vk_publish_symmetry(void);
int test_params_vk_publish_symmetry(void)
{
    int failures = 0;
    printf("\n=== params VK publish/release symmetry ===\n");

    /* Deterministic baseline; the explicit sprout_phgr_set_vk(NULL) is setup,
     * not a stand-in for the teardown under test. */
    sapling_free_params();
    sprout_phgr_set_vk(NULL);

    /* ── 1. Nothing published before a load ───────────────────────────── */
    SYM_CHECK("baseline: no verifier is armed", armed_verifier_count() == 0);
    SYM_CHECK("baseline: params report NOT loaded", !sapling_params_loaded());

    /* ── 2. A load arms all four together ─────────────────────────────── */
    SYM_CHECK("installing the compiled-in keys succeeds",
              sapling_install_embedded_vks());
    SYM_CHECK("params report loaded", sapling_params_loaded());
    SYM_CHECK("install arms the spend verifier",
              sapling_test_published_spend_vk() != NULL);
    SYM_CHECK("install arms the output verifier",
              sapling_test_published_output_vk() != NULL);
    SYM_CHECK("install arms the sprout-groth16 verifier",
              sprout_test_published_vk() != NULL);
    SYM_CHECK("install arms the PHGR13 verifier",
              sprout_test_published_phgr_vk() != NULL);
    SYM_CHECK("install arms it as the production accessor reports it",
              sprout_phgr_vk_loaded() && phgr_accessor_agrees_with_pointer());
    SYM_CHECK("all four verifiers agree: armed", armed_verifier_count() == 4);

    const struct ppzksnark_vk *phgr_first = sprout_test_published_phgr_vk();
    size_t phgr_ic_len = phgr_first ? phgr_first->ic_len : 0;
    SYM_CHECK("the PHGR13 key carries IC points", phgr_ic_len > 1);

    /* ── 3. Teardown disarms all four together ────────────────────────── */
    /* No sprout_phgr_set_vk(NULL) here: sapling_free_params() must disarm the
     * PHGR13 key itself. */
    sapling_free_params();
    SYM_CHECK("free_params disarms the spend verifier",
              sapling_test_published_spend_vk() == NULL);
    SYM_CHECK("free_params disarms the output verifier",
              sapling_test_published_output_vk() == NULL);
    SYM_CHECK("free_params disarms the sprout-groth16 verifier",
              sprout_test_published_vk() == NULL);
    SYM_CHECK("free_params disarms the PHGR13 verifier "
              "(no manual sprout_phgr_set_vk(NULL))",
              sprout_test_published_phgr_vk() == NULL);
    SYM_CHECK("free_params makes the production accessor "
              "sprout_phgr_vk_loaded() report false too",
              !sprout_phgr_vk_loaded() && phgr_accessor_agrees_with_pointer());
    SYM_CHECK("all four verifiers agree: disarmed",
              armed_verifier_count() == 0);
    SYM_CHECK("free_params reports params NOT loaded",
              !sapling_params_loaded());

    /* ── 4. One PHGR13 storage instance, reachable from teardown ──────── */
    SYM_CHECK("reinstalling the compiled-in keys succeeds",
              sapling_install_embedded_vks());
    SYM_CHECK("all four verifiers re-arm together",
              armed_verifier_count() == 4);
    SYM_CHECK("the PHGR13 key is ONE file-scope struct, not a per-call static",
              sprout_test_published_phgr_vk() == phgr_first);
    SYM_CHECK("the reloaded PHGR13 key is the same key",
              sprout_test_published_phgr_vk() != NULL &&
              sprout_test_published_phgr_vk()->ic_len == phgr_ic_len);

    /* ── 5. Reload cycles do not accumulate ───────────────────────────── */
    /* ppzksnark_vk_read() memsets before parsing, so a teardown that does not
     * free ic[] drops one allocation per cycle. Drive enough cycles for a
     * leak-checking run to report it, and assert the key stays whole and
     * singular. */
    for (int i = 0; i < 8; i++) {
        sapling_free_params();
        if (armed_verifier_count() != 0) {
            printf("params_vk_publish_symmetry: cycle %d left a verifier "
                   "armed after free_params... FAIL\n", i);
            failures++;
            break;
        }
        if (!sapling_install_embedded_vks()) {
            printf("params_vk_publish_symmetry: cycle %d reinstall "
                   "failed... FAIL\n", i);
            failures++;
            break;
        }
    }
    SYM_CHECK("after 8 free/install cycles all four are armed",
              armed_verifier_count() == 4);
    SYM_CHECK("after 8 free/install cycles the PHGR13 storage has not moved",
              sprout_test_published_phgr_vk() == phgr_first);
    SYM_CHECK("after 8 free/install cycles the PHGR13 key is unchanged",
              sprout_test_published_phgr_vk() != NULL &&
              sprout_test_published_phgr_vk()->ic_len == phgr_ic_len);

    /* ── 6. A refused LATE load cannot disarm a live key set ──────────── */
    /* The keys are installed but no proving parameters are, so
     * params_init_locked() routes to params_load_late_proving_locked(). The
     * directory does not exist, so the late load must refuse, costing the
     * proving capability and nothing else: all four verifying keys stay
     * published. No datadir is involved. */
    SYM_CHECK("a refused late proving load returns false",
              !sapling_init_params("/nonexistent/params-vk-publish-symmetry"));
    SYM_CHECK("the refused late load left the spend verifier armed",
              sapling_test_published_spend_vk() != NULL);
    SYM_CHECK("the refused late load left the output verifier armed",
              sapling_test_published_output_vk() != NULL);
    SYM_CHECK("the refused late load left the sprout-groth16 verifier armed",
              sprout_test_published_vk() != NULL);
    SYM_CHECK("the refused late load left the PHGR13 verifier armed "
              "(blocks 0-581876 stay validatable)",
              sprout_test_published_phgr_vk() != NULL);
    SYM_CHECK("the refused late load left sprout_phgr_vk_loaded() true",
              sprout_phgr_vk_loaded());
    SYM_CHECK("params still report loaded after a refused late load",
              sapling_params_loaded());
    SYM_CHECK("all four verifiers still agree: armed",
              armed_verifier_count() == 4);

    /* Leave the process as this group found it. */
    sapling_free_params();
    SYM_CHECK("teardown leaves nothing armed", armed_verifier_count() == 0);

    return failures;
}
