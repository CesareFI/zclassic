/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Rebuild branch-work bounds for the proof_ticket_reuse group:
 *          keys anyone can mint cannot multiply the checkpoint branch
 *          search, broken-signature copies cannot enter it, and an
 *          untrusted issuer's forks are still detected under a policy. */

#include "test/test_core.h"

#include "test/proof_ticket_fixture.h"
#include "platform/time_compat.h"
#include "vcs/package_store.h"
#include "vcs/proof_signature.h"
#include "vcs/proof_ticket.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PBW_QUOTA (UINT64_C(64) * 1024 * 1024)
#define PBW_W VCS_PROOF_TICKET_WIRE_BYTES
#define PBW_FORKS 8u /* forked sequences: 2^8 = 256 branch states */
#define PBW_SIG_AT 296u /* first signature byte of a ticket wire */

static struct ptf g_w;

static bool pbw_fresh(void)
{
    ptf_free(&g_w);
    return ptf_init(&g_w);
}

static bool pbw_put(struct vcs_package_store *store, const uint8_t *wire,
                    size_t len)
{
    uint8_t root[32];
    return vcs_proof_ticket_store_put(store, wire, len, root);
}

/* One stranger key: PBW_FORKS forked sequences (two signed tickets each),
 * then `chain` single tickets, `junk` copies of its last ticket whose
 * signature is broken, and `cps` sibling checkpoints over the whole chain.
 * Each sibling re-walks all 256 branch states along the chain, so the key
 * asks for about 256 * chain * cps branch steps. */
struct pbw_shape {
    unsigned chain;
    unsigned junk;
    unsigned cps;
};

static bool pbw_body(uint32_t id, const char *side, unsigned seq,
                     struct vcs_proof_ticket_v1 *t)
{
    uint8_t scratch[PBW_W];
    struct vcs_component_proof_key_v1 k = g_w.base;
    char unit[64];
    snprintf(unit, sizeof(unit), "wide/%u/%s/%u", id, side, seq);
    ptf_root(VCS_CPK_UNIT_ID, unit, k.roots[VCS_CPK_UNIT_ID]);
    return ptf_emit(&g_w, PTF_STRANGER, &k, ptf_pass(), scratch, NULL) &&
           vcs_proof_ticket_decode(scratch, sizeof(scratch), t);
}

static bool pbw_chain(struct vcs_package_store *store, uint32_t id,
                      struct vcs_proof_ticket_v1 *a, unsigned total,
                      struct vcs_proof_issuer_log *la,
                      struct vcs_proof_issuer_log *lb)
{
    uint8_t wire[PBW_W];
    bool ok = la && lb;
    for (unsigned s = 0; ok && s < total; s++) {
        struct vcs_proof_ticket_v1 t;
        ok = pbw_body(id, "a", s, &a[s]);
        t = a[s];
        ok = ok && vcs_proof_issuer_log_append(la, &t, wire) &&
             pbw_put(store, wire, sizeof(wire));
        if (ok && s < PBW_FORKS)
            ok = pbw_body(id, "b", s, &t) &&
                 vcs_proof_issuer_log_append(lb, &t, wire) &&
                 pbw_put(store, wire, sizeof(wire));
    }
    return ok;
}

static bool pbw_junk(struct vcs_package_store *store, const uint8_t *last,
                     unsigned junk)
{
    bool ok = last != NULL;
    for (unsigned j = 0; ok && j < junk; j++) {
        uint8_t wire[PBW_W];
        memcpy(wire, last, sizeof(wire));
        wire[PBW_SIG_AT] ^= 0x5a;
        memcpy(wire + PBW_SIG_AT + 4u, &j, sizeof(j));
        ok = pbw_put(store, wire, sizeof(wire));
    }
    return ok;
}

static bool pbw_siblings(struct vcs_package_store *store,
                         const uint8_t seed[32],
                         const struct vcs_proof_ticket_v1 *a, unsigned total,
                         unsigned cps)
{
    bool ok = true;
    for (unsigned c = 0; ok && c < cps; c++) {
        struct vcs_proof_issuer_log *one = vcs_proof_issuer_log_new(seed);
        uint8_t wire[PBW_W];
        uint8_t cp[VCS_PROOF_CHECKPOINT_WIRE_BYTES];
        ok = one != NULL;
        for (unsigned s = 0; ok && s < total; s++) {
            struct vcs_proof_ticket_v1 t = a[s];
            ok = vcs_proof_issuer_log_append(one, &t, wire);
        }
        ok = ok && vcs_proof_issuer_log_checkpoint(one, 5000u + c, cp) &&
             pbw_put(store, cp, sizeof(cp));
        vcs_proof_issuer_log_free(one);
    }
    return ok;
}

static bool pbw_stranger(struct vcs_package_store *store, uint32_t id,
                         const struct pbw_shape *shape, uint8_t pub[32])
{
    uint8_t seed[32] = {0xc5};
    memcpy(seed + 1, &id, sizeof(id));
    unsigned total = PBW_FORKS + shape->chain;
    struct vcs_proof_ticket_v1 *a = calloc(total, sizeof(*a));
    struct vcs_proof_issuer_log *la = vcs_proof_issuer_log_new(seed);
    struct vcs_proof_issuer_log *lb = vcs_proof_issuer_log_new(seed);
    bool durable = !vcs_package_store_deferred_sync_enabled();
    vcs_package_store_set_deferred_sync(true); /* a fixture, discarded whole */
    bool ok = a && pbw_chain(store, id, a, total, la, lb) &&
              pbw_junk(store, vcs_proof_issuer_log_ticket(la, total - 1u),
                       shape->junk) &&
              pbw_siblings(store, seed, a, total, shape->cps);
    if (ok) vcs_proof_issuer_log_pubkey(la, pub);
    vcs_package_store_set_deferred_sync(!durable);
    vcs_proof_issuer_log_free(la);
    vcs_proof_issuer_log_free(lb);
    free(a);
    return ok;
}

struct pbw_run {
    bool rebuilt;
    size_t rows;
    int replayed;     /* keys whose branches replayed: kept, not isolated */
    int forked;       /* keys still known to have signed a fork */
    uint64_t checks;  /* full Ed25519 verifications during the rebuild */
    const char *why;  /* the typed reason a refused rebuild left */
    int64_t ms;
};

static uint64_t pbw_checks(void)
{
    struct vcs_proof_signature_stats s;
    vcs_proof_signature_stats(&s);
    return s.verified + s.refused;
}

/* A new process rebuilds the store of `keys` strangers, under `trust` or,
 * when it is NULL, with no trust policy at all. */
static bool pbw_rebuild(struct vcs_package_store *store,
                        const uint8_t (*pubs)[32], int keys,
                        const struct vcs_proof_reuse_policy *trust,
                        struct pbw_run *run)
{
    uint64_t generation = 0;
    size_t tickets = 0, cps = 0, skipped = 0;
    struct vcs_proof_receiver *rx = vcs_proof_receiver_new();
    if (!rx ||
        vcs_package_store_catalog_rows(store, &run->rows, &generation) !=
            VCS_PACKAGE_STORE_PAGE_OK) {
        vcs_proof_receiver_free(rx);
        return false;
    }
    vcs_proof_signature_forget();
    uint64_t checks = pbw_checks();
    int64_t t0 = platform_time_monotonic_us();
    run->rebuilt = trust
        ? vcs_proof_receiver_rebuild_with_policy(
              rx, store, trust, NULL, 0, run->rows + 8u, &tickets, &cps,
              &skipped, &generation)
        : vcs_proof_receiver_rebuild_bounded(rx, store, run->rows + 8u,
                                             &tickets, &cps, &skipped);
    run->ms = (platform_time_monotonic_us() - t0) / 1000;
    run->checks = pbw_checks() - checks;
    run->why = vcs_proof_receiver_rebuild_refusal(rx);
    for (int k = 0; k < keys; k++) {
        bool forked = vcs_proof_receiver_issuer_equivocating(rx, pubs[k]);
        run->forked += forked ? 1 : 0;
        run->replayed +=
            forked && !vcs_proof_receiver_issuer_history_incomplete(rx, pubs[k])
                ? 1 : 0;
    }
    vcs_proof_receiver_free(rx);
    return true;
}

static void pbw_print(const char *label, int keys,
                      const struct pbw_shape *shape, const struct pbw_run *run)
{
    printf("\nproof_branch_work case=%s keys=%d asked_per_key=%llu rows=%zu "
           "rebuilt=%d replayed_keys=%d forked_keys=%d signature_checks=%llu "
           "rebuild_ms=%lld\n",
           label, keys,
           (unsigned long long)256u * shape->chain * shape->cps, run->rows,
           run->rebuilt ? 1 : 0, run->replayed, run->forked,
           (unsigned long long)run->checks, (long long)run->ms);
}

static bool pbw_store(const char *tag, int keys, const struct pbw_shape *shape,
                      char *dir, size_t dir_len, uint8_t (*pubs)[32],
                      struct vcs_package_store **out)
{
    test_make_tmpdir(dir, dir_len, "proof_branch_work", tag);
    *out = vcs_package_store_open(dir, PBW_QUOTA);
    bool ok = *out != NULL;
    for (int k = 0; ok && k < keys; k++)
        ok = pbw_stranger(*out, (uint32_t)k, shape, pubs[k]);
    return ok;
}

enum { PBW_KEYS = 3 };

/* Each key asks for about 410k branch steps, under the 1M cap on its own.
 * Two keys fit the cap together; a third cannot buy a fresh budget. */
static const struct pbw_shape pbw_wide = {.chain = 200u, .junk = 0u,
                                          .cps = 8u};

static int pbw_case_keys_share_one_budget(void)
{
    int failures = 0;
    TEST_CASE("REVIEW: stranger keys cannot multiply total branch work") {
        ASSERT(pbw_fresh());
        char dir[256];
        uint8_t pubs[PBW_KEYS][32];
        struct vcs_package_store *store = NULL;
        ASSERT(pbw_store("shared", 2, &pbw_wide, dir, sizeof(dir), pubs,
                         &store));
        struct pbw_run two = {0};
        ASSERT(pbw_rebuild(store, (const uint8_t (*)[32])pubs, 2, NULL, &two));
        pbw_print("two_keys", 2, &pbw_wide, &two);
        ASSERT(two.rebuilt);
        ASSERT(two.why == NULL);
        ASSERT_EQ(two.replayed, 2);
        ASSERT(pbw_stranger(store, 2u, &pbw_wide, pubs[2]));
        struct pbw_run three = {0};
        ASSERT(pbw_rebuild(store, (const uint8_t (*)[32])pubs, PBW_KEYS, NULL,
                           &three));
        pbw_print("three_keys", PBW_KEYS, &pbw_wide, &three);
        ASSERT(!three.rebuilt);
        ASSERT(three.why != NULL);
        ASSERT_STR_EQ(three.why, VCS_PROOF_REBUILD_WHY_BRANCH_WORK);
        vcs_package_store_close(store);
        test_rm_rf(dir);
    } TEST_END
    return failures;
}

/* Under a trust policy no stranger's branch search runs at all, so the
 * same keys cannot refuse the rebuild; broken-signature copies are
 * refused once each at scan instead of once per branch state. */
static const struct pbw_shape pbw_junky = {.chain = 200u, .junk = 2u,
                                           .cps = 8u};

static int pbw_case_policy_skips_stranger_branches(void)
{
    int failures = 0;
    TEST_CASE("proof_branch_work: a policy rebuild replays no stranger branch") {
        ASSERT(pbw_fresh());
        char dir[256];
        uint8_t pubs[PBW_KEYS][32];
        struct vcs_package_store *store = NULL;
        ASSERT(pbw_store("policy", PBW_KEYS, &pbw_junky, dir, sizeof(dir),
                         pubs, &store));
        struct pbw_run run = {0};
        ASSERT(pbw_rebuild(store, (const uint8_t (*)[32])pubs, PBW_KEYS,
                           &g_w.policy, &run));
        pbw_print("policy", PBW_KEYS, &pbw_junky, &run);
        ASSERT(run.rebuilt);
        ASSERT_EQ(run.forked, PBW_KEYS);
        ASSERT_EQ(run.replayed, 0);
        ASSERT(run.checks <= run.rows);
        vcs_package_store_close(store);
        test_rm_rf(dir);
    } TEST_END
    return failures;
}

int ptf_branch_work_cases(void)
{
    int failures = 0;
    failures += pbw_case_keys_share_one_budget();
    failures += pbw_case_policy_skips_stranger_branches();
    ptf_free(&g_w);
    return failures;
}
