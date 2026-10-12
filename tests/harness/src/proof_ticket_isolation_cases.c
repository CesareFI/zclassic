/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Per-issuer isolation on receiver rebuild for the
 *          proof_ticket_reuse group: an evicted covered ticket, an orphan
 *          checkpoint or a pinned checkpoint pair without its parent
 *          distrusts only that issuer; every honest issuer still hits. */

#include "test/test_core.h"

#include "test/proof_ticket_fixture.h"
#include "vcs/blob_store.h"
#include "vcs/package_store.h"
#include "vcs/proof_ticket.h"

#include <stdio.h>
#include <string.h>

#define PIC_QUOTA (UINT64_C(64) * 1024 * 1024)
#define PIC_CAP 16u
#define PIC_FILLER (VCS_PACKAGE_STORE_PAGE_MAX + 4u)
#define PIC_W VCS_PROOF_TICKET_WIRE_BYTES
#define PIC_CPW VCS_PROOF_CHECKPOINT_WIRE_BYTES

static struct ptf g_i;

static bool pic_fresh(void)
{
    ptf_free(&g_i);
    return ptf_init(&g_i);
}

static void pic_key(const char *unit, struct vcs_component_proof_key_v1 *k)
{
    *k = g_i.base;
    ptf_root(VCS_CPK_UNIT_ID, unit, k->roots[VCS_CPK_UNIT_ID]);
}

static bool pic_put(struct vcs_package_store *store, const uint8_t *wire,
                    size_t len)
{
    uint8_t root[32];
    return vcs_proof_ticket_store_put(store, wire, len, root);
}

static bool pic_put_all(struct vcs_package_store *store,
                        const uint8_t (*wires)[PIC_W], size_t count)
{
    for (size_t i = 0; i < count; i++)
        if (!pic_put(store, wires[i], PIC_W)) return false;
    return true;
}

/* Fillers that all sort before `late`, so `late` is past the first page. */
static bool pic_fill(struct vcs_package_store *store, const uint8_t *late,
                     uint32_t count)
{
    uint32_t added = 0;
    for (uint32_t i = 0; added < count && i < 4000000u; i++) {
        uint8_t blob[8] = {'i', 's', 'o', 'l', (uint8_t)i, (uint8_t)(i >> 8),
                           (uint8_t)(i >> 16), (uint8_t)(i >> 24)};
        uint8_t root[32];
        if (!vcs_blob_root(blob, sizeof(blob), root)) return false;
        if (memcmp(root, late, 32) >= 0) continue;
        if (!pic_put(store, blob, sizeof(blob))) return false;
        added++;
    }
    return added == count;
}

static bool pic_later_page(struct vcs_package_store *store,
                           const uint8_t *late)
{
    static struct vcs_package_store_summary rows[VCS_PACKAGE_STORE_PAGE_MAX];
    struct vcs_package_store_page page;
    return vcs_package_store_page_summaries(
               store, NULL, VCS_PACKAGE_STORE_PAGE_MAX, 0, rows, &page) ==
               VCS_PACKAGE_STORE_PAGE_OK &&
           page.has_more && memcmp(late, page.next_root, 32) > 0;
}

/* Compaction: just over the RARE pool's usage (never below what is
 * pinned), `victim` is the first package the store may drop, so one
 * unrelated write of the same size evicts exactly it. */
static bool pic_compact(const char *dir, const uint8_t *victim, size_t len,
                        uint8_t salt)
{
    struct vcs_package_store *store = vcs_package_store_open(dir, PIC_QUOTA);
    if (!store) return false;
    uint64_t rare = vcs_package_store_pool_usage(store,
                                                 VCS_PACKAGE_STORE_POOL_RARE);
    uint64_t pins = vcs_package_store_pool_usage(store,
                                                 VCS_PACKAGE_STORE_POOL_PINS);
    vcs_package_store_close(store);
    uint64_t tight = (rare / 3u) * 10u + 10u;
    if (tight < pins * 5u + 10u) tight = pins * 5u + 10u;
    store = vcs_package_store_open(dir, tight);
    uint8_t root[32];
    uint8_t junk[PIC_W + 1u];
    size_t got = 0;
    bool ok = store && len <= PIC_W && vcs_blob_root(victim, len, root) &&
              vcs_package_store_set_class(store, root,
                                          VCS_PACKAGE_STORE_CLASS_RARE,
                                          1000u) == VCS_PACKAGE_STORE_OK;
    if (ok) {
        memset(junk, salt, len);
        ok = pic_put(store, junk, len) &&
             vcs_blob_get_from(store, root, junk, sizeof(junk), &got) ==
                 VCS_BLOB_ERR_ABSENT;
    }
    if (store) vcs_package_store_close(store);
    return ok;
}

/* A restarted receiver rebuilt under `trust` (NULL: the fixture policy). */
static struct vcs_proof_receiver *pic_rebuilt(
    struct vcs_package_store *store, size_t rows,
    const struct vcs_proof_reuse_policy *trust)
{
    struct vcs_proof_receiver *rx = vcs_proof_receiver_new();
    size_t tickets = 0, cps = 0, skipped = 0;
    uint64_t generation = 0;
    if (rx && vcs_proof_receiver_rebuild_with_policy(
                  rx, store, trust ? trust : &g_i.policy, NULL, 0, rows,
                  &tickets, &cps, &skipped, &generation))
        return rx;
    vcs_proof_receiver_free(rx);
    return NULL;
}

static bool pic_decide(const struct vcs_proof_receiver *rx,
                       const struct vcs_component_proof_key_v1 *key,
                       const struct vcs_proof_reuse_policy *policy,
                       struct vcs_proof_ticket_class cls[PIC_CAP],
                       struct vcs_proof_reuse_decision *d)
{
    struct vcs_proof_reuse_request req = {
        .local = key, .action_class = VCS_PROOF_ACTION_CHECK,
        .domain = &g_i.domain, .policy = policy ? policy : &g_i.policy,
        .artifacts = &g_i.source,
    };
    return vcs_proof_reuse_decide(rx, &req, cls, PIC_CAP, d);
}

static const char *pic_reason_of(const struct vcs_proof_ticket_class *cls,
                                 uint32_t seen, const uint8_t pub[32])
{
    for (uint32_t i = 0; i < seen; i++)
        if (memcmp(cls[i].producer_pubkey, pub, 32) == 0)
            return cls[i].reason;
    return "absent";
}

/* A second log under `seed` re-signs `wires` (same tickets, same sequences),
 * checkpointing once after the first at `created` and once after all of them
 * at `created_last`. The first checkpoint is returned in `first` (NULL:
 * dropped, so the second is an orphan whose parent nobody stored). */
static bool pic_resign(const uint8_t seed[32], const uint8_t (*wires)[PIC_W],
                       size_t count, uint64_t created, uint64_t created_last,
                       uint8_t first[PIC_CPW], uint8_t last[PIC_CPW])
{
    struct vcs_proof_issuer_log *log = vcs_proof_issuer_log_new(seed);
    uint8_t dropped[PIC_CPW];
    bool ok = log != NULL && count >= 2u;
    for (size_t i = 0; ok && i < count; i++) {
        struct vcs_proof_ticket_v1 t;
        uint8_t wire[PIC_W];
        ok = vcs_proof_ticket_decode(wires[i], PIC_W, &t) &&
             vcs_proof_issuer_log_append(log, &t, wire) &&
             memcmp(wire, wires[i], PIC_W) == 0;
        if (ok && i == 0)
            ok = vcs_proof_issuer_log_checkpoint(log, created,
                                                 first ? first : dropped);
    }
    ok = ok && vcs_proof_issuer_log_checkpoint(log, created_last, last);
    vcs_proof_issuer_log_free(log);
    return ok;
}

/* ── the shared honest history ──────────────────────────────────────── */

/* bc: A, B and C pass. a_only: only A signed. dissent: A failed, B and C
 * passed. pass_dissent: A passed, B and C failed. */
struct pic_keys {
    struct vcs_component_proof_key_v1 bc, a_only, dissent, pass_dissent;
};

struct pic_history {
    struct pic_keys k;
    uint8_t a[4][PIC_W];
    uint8_t b[3][PIC_W];
    uint8_t c[3][PIC_W];
    uint8_t cp_a[PIC_CPW], cp_b[PIC_CPW], cp_c[PIC_CPW];
};

static bool pic_emit_history(struct pic_history *h)
{
    pic_key("unit/iso/bc", &h->k.bc);
    pic_key("unit/iso/a_only", &h->k.a_only);
    pic_key("unit/iso/dissent", &h->k.dissent);
    pic_key("unit/iso/pass_dissent", &h->k.pass_dissent);
    return ptf_emit(&g_i, PTF_A, &h->k.bc, ptf_pass(), h->a[0], NULL) &&
           ptf_emit(&g_i, PTF_A, &h->k.a_only, ptf_pass(), h->a[1], NULL) &&
           ptf_emit(&g_i, PTF_A, &h->k.dissent, ptf_fail(), h->a[2], NULL) &&
           ptf_emit(&g_i, PTF_A, &h->k.pass_dissent, ptf_pass(), h->a[3],
                    NULL) &&
           ptf_emit(&g_i, PTF_B, &h->k.bc, ptf_pass(), h->b[0], NULL) &&
           ptf_emit(&g_i, PTF_B, &h->k.dissent, ptf_pass(), h->b[1], NULL) &&
           ptf_emit(&g_i, PTF_B, &h->k.pass_dissent, ptf_fail(), h->b[2],
                    NULL) &&
           ptf_emit(&g_i, PTF_C, &h->k.bc, ptf_pass(), h->c[0], NULL) &&
           ptf_emit(&g_i, PTF_C, &h->k.dissent, ptf_pass(), h->c[1], NULL) &&
           ptf_emit(&g_i, PTF_C, &h->k.pass_dissent, ptf_fail(), h->c[2],
                    NULL) &&
           vcs_proof_issuer_log_checkpoint(g_i.logs[PTF_A], 81, h->cp_a) &&
           vcs_proof_issuer_log_checkpoint(g_i.logs[PTF_B], 82, h->cp_b) &&
           vcs_proof_issuer_log_checkpoint(g_i.logs[PTF_C], 83, h->cp_c);
}

static bool pic_store_history(struct vcs_package_store *store,
                              const struct pic_history *h)
{
    return pic_put_all(store, (const uint8_t (*)[PIC_W])h->a, 4) &&
           pic_put_all(store, (const uint8_t (*)[PIC_W])h->b, 3) &&
           pic_put_all(store, (const uint8_t (*)[PIC_W])h->c, 3) &&
           pic_put(store, h->cp_a, PIC_CPW) &&
           pic_put(store, h->cp_b, PIC_CPW) &&
           pic_put(store, h->cp_c, PIC_CPW);
}

/* Every key's verdict with A's history complete. */
static int pic_expect_complete(const struct vcs_proof_receiver *rx,
                               const struct pic_keys *k)
{
    int failures = 0;
    TEST_CASE("proof_isolation: complete history keeps its verdicts") {
        ASSERT(rx != NULL);
        struct vcs_proof_ticket_class cls[PIC_CAP];
        struct vcs_proof_reuse_decision d;
        ASSERT(pic_decide(rx, &k->bc, NULL, cls, &d));
        ASSERT_EQ(d.outcome, VCS_PROOF_REUSE_HIT_PASS);
        ASSERT_EQ(d.distinct_pass_signers, (uint32_t)3);
        ASSERT(pic_decide(rx, &k->a_only, NULL, cls, &d));
        ASSERT_EQ(d.outcome, VCS_PROOF_REUSE_MISS);
        ASSERT_STR_EQ(d.reason, VCS_PROOF_REUSE_WHY_QUORUM);
        ASSERT(pic_decide(rx, &k->dissent, NULL, cls, &d));
        ASSERT_EQ(d.outcome, VCS_PROOF_REUSE_REFUSE);
        ASSERT_STR_EQ(d.reason, VCS_PROOF_OBSERVATION_CONFLICT);
        ASSERT(pic_decide(rx, &k->pass_dissent, NULL, cls, &d));
        ASSERT_EQ(d.outcome, VCS_PROOF_REUSE_REFUSE);
        ASSERT_STR_EQ(d.reason, VCS_PROOF_OBSERVATION_CONFLICT);
        ASSERT(!vcs_proof_receiver_issuer_history_incomplete(rx,
                                                             g_i.pub[PTF_A]));
    } TEST_END
    return failures;
}

/* A isolated, not equivocating: B and C still hit; A's own observations
 * are named, never counted, and its dissent is not forgotten. */
static int pic_expect_a_isolated(const struct vcs_proof_receiver *rx,
                                 const struct pic_keys *k)
{
    int failures = 0;
    TEST_CASE("proof_isolation: only the broken issuer is isolated") {
        ASSERT(rx != NULL);
        ASSERT(vcs_proof_receiver_issuer_history_incomplete(rx,
                                                            g_i.pub[PTF_A]));
        ASSERT(!vcs_proof_receiver_issuer_equivocating(rx, g_i.pub[PTF_A]));
        ASSERT_EQ(vcs_proof_receiver_issuer_leaves(rx, g_i.pub[PTF_A]),
                  (uint64_t)0);
        for (int s = PTF_B; s <= PTF_C; s++) {
            ASSERT(!vcs_proof_receiver_issuer_history_incomplete(rx,
                                                                 g_i.pub[s]));
            ASSERT_EQ(vcs_proof_receiver_issuer_leaves(rx, g_i.pub[s]),
                      (uint64_t)3);
        }
        struct vcs_proof_ticket_class cls[PIC_CAP];
        struct vcs_proof_reuse_decision d;
        ASSERT(pic_decide(rx, &k->bc, NULL, cls, &d));
        ASSERT_EQ(d.outcome, VCS_PROOF_REUSE_HIT_PASS);
        ASSERT_EQ(d.distinct_pass_signers, (uint32_t)2);
        ASSERT_STR_EQ(pic_reason_of(cls, d.tickets_seen, g_i.pub[PTF_B]),
                      VCS_PROOF_TICKET_ELIGIBLE);
        ASSERT(pic_decide(rx, &k->a_only, NULL, cls, &d));
        ASSERT_EQ(d.outcome, VCS_PROOF_REUSE_MISS);
        ASSERT_STR_EQ(d.reason, VCS_PROOF_REUSE_WHY_HISTORY_INCOMPLETE);
        ASSERT_STR_EQ(pic_reason_of(cls, d.tickets_seen, g_i.pub[PTF_A]),
                      VCS_PROOF_TICKET_HISTORY_INCOMPLETE);
        ASSERT_EQ(d.eligible_pass, (uint32_t)0);
        ASSERT(pic_decide(rx, &k->dissent, NULL, cls, &d));
        ASSERT_EQ(d.outcome, VCS_PROOF_REUSE_REFUSE);
        ASSERT_STR_EQ(d.reason, VCS_PROOF_REUSE_WHY_UNVERIFIED_DISSENT);
        ASSERT_EQ(d.eligible_pass, (uint32_t)2);
        ASSERT(pic_decide(rx, &k->pass_dissent, NULL, cls, &d));
        ASSERT_EQ(d.outcome, VCS_PROOF_REUSE_REFUSE);
        ASSERT_STR_EQ(d.reason, VCS_PROOF_REUSE_WHY_UNVERIFIED_DISSENT);
        ASSERT_EQ(d.eligible_fail, (uint32_t)2);
    } TEST_END
    return failures;
}

/* ── (a) a covered ticket evicted ───────────────────────────────────── */

static int pic_case_evicted_ticket(void)
{
    int failures = 0;
    TEST_CASE("proof_isolation: an evicted covered ticket isolates only its issuer") {
        ASSERT(pic_fresh());
        static struct pic_history h;
        ASSERT(pic_emit_history(&h));
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "proof_isolation", "ticket");
        struct vcs_package_store *store = vcs_package_store_open(dir, PIC_QUOTA);
        ASSERT(store != NULL);
        ASSERT(pic_store_history(store, &h));
        struct vcs_proof_receiver *rx = pic_rebuilt(store, 64u, NULL);
        failures += pic_expect_complete(rx, &h.k);
        vcs_proof_receiver_free(rx);
        vcs_package_store_close(store);
        /* A's covered PASS on bc is compacted away. */
        ASSERT(pic_compact(dir, h.a[0], PIC_W, 0x41));
        store = vcs_package_store_open(dir, PIC_QUOTA);
        ASSERT(store != NULL);
        rx = pic_rebuilt(store, 64u, NULL);
        failures += pic_expect_a_isolated(rx, &h.k);
        ASSERT(rx != NULL);
        ASSERT_EQ(vcs_proof_receiver_ticket_count(rx), (size_t)9);
        vcs_proof_receiver_free(rx);
        vcs_package_store_close(store);
        test_rm_rf(dir);
    } TEST_END
    return failures;
}

/* ── (b) one signed orphan checkpoint ───────────────────────────────── */

static int pic_case_orphan_checkpoint(void)
{
    int failures = 0;
    TEST_CASE("proof_isolation: a stranger's orphan changes nothing; A's isolates A") {
        ASSERT(pic_fresh());
        static struct pic_history h;
        ASSERT(pic_emit_history(&h));
        /* A stranger signs two tickets, but stores only its second
         * checkpoint: an orphan whose parent nobody has. */
        uint8_t s[2][PIC_W], s_cp1[PIC_CPW], s_cp2[PIC_CPW];
        ASSERT(ptf_emit(&g_i, PTF_STRANGER, &h.k.bc, ptf_pass(), s[0], NULL));
        ASSERT(vcs_proof_issuer_log_checkpoint(g_i.logs[PTF_STRANGER], 84,
                                               s_cp1));
        ASSERT(ptf_emit(&g_i, PTF_STRANGER, &h.k.a_only, ptf_pass(), s[1],
                        NULL));
        ASSERT(vcs_proof_issuer_log_checkpoint(g_i.logs[PTF_STRANGER], 85,
                                               s_cp2));
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "proof_isolation", "orphan");
        struct vcs_package_store *store = vcs_package_store_open(dir, PIC_QUOTA);
        ASSERT(store != NULL);
        ASSERT(pic_store_history(store, &h));
        ASSERT(pic_put_all(store, (const uint8_t (*)[PIC_W])s, 2));
        ASSERT(pic_put(store, s_cp2, PIC_CPW));
        struct vcs_proof_receiver *rx = pic_rebuilt(store, 64u, NULL);
        failures += pic_expect_complete(rx, &h.k);
        ASSERT(rx != NULL);
        ASSERT(vcs_proof_receiver_issuer_history_incomplete(
            rx, g_i.pub[PTF_STRANGER]));
        for (int signer = PTF_A; signer <= PTF_C; signer++)
            ASSERT_EQ(vcs_proof_receiver_issuer_leaves(rx, g_i.pub[signer]),
                      (uint64_t)(signer == PTF_A ? 4 : 3));
        vcs_proof_receiver_free(rx);

        /* A's own key signs an orphan: its checkpoint over A's first two
         * tickets names a parent that was never stored. */
        uint8_t orphan[PIC_CPW];
        ASSERT(pic_resign(g_i.seed[PTF_A], (const uint8_t (*)[PIC_W])h.a, 2,
                          900, 901, NULL, orphan));
        ASSERT(pic_put(store, orphan, PIC_CPW));
        rx = pic_rebuilt(store, 64u, NULL);
        ASSERT(rx != NULL);
        ASSERT_EQ(vcs_proof_receiver_ticket_count(rx), (size_t)12);
        vcs_package_store_close(store);
        failures += pic_expect_a_isolated(rx, &h.k);
        vcs_proof_receiver_free(rx);
        test_rm_rf(dir);
    } TEST_END
    return failures;
}

/* ── (c) a pinned checkpoint pair whose parent is evicted ───────────── */

static int pic_case_pair_parent_evicted(void)
{
    int failures = 0;
    TEST_CASE("proof_isolation: a pinned pair without its parent stays a fork; B and C hit") {
        ASSERT(pic_fresh());
        struct vcs_component_proof_key_v1 bc, second;
        pic_key("unit/iso/pair/bc", &bc);
        pic_key("unit/iso/pair/second", &second);
        uint8_t a[2][PIC_W], b[1][PIC_W], c[1][PIC_W];
        uint8_t cp1[PIC_CPW], cp2a[PIC_CPW], cp2b[PIC_CPW], again[PIC_CPW];
        uint8_t cp_b[PIC_CPW], cp_c[PIC_CPW];
        ASSERT(ptf_emit(&g_i, PTF_A, &bc, ptf_pass(), a[0], NULL));
        ASSERT(vcs_proof_issuer_log_checkpoint(g_i.logs[PTF_A], 70, cp1));
        ASSERT(ptf_emit(&g_i, PTF_A, &second, ptf_pass(), a[1], NULL));
        ASSERT(vcs_proof_issuer_log_checkpoint(g_i.logs[PTF_A], 71, cp2a));
        /* The same key re-signs the same two tickets: the same first
         * checkpoint, then a second child of it. */
        ASSERT(pic_resign(g_i.seed[PTF_A], (const uint8_t (*)[PIC_W])a, 2,
                          70, 72, again, cp2b));
        ASSERT(memcmp(again, cp1, PIC_CPW) == 0);
        ASSERT(memcmp(cp2a, cp2b, PIC_CPW) != 0);
        ASSERT(ptf_emit(&g_i, PTF_B, &bc, ptf_pass(), b[0], NULL));
        ASSERT(vcs_proof_issuer_log_checkpoint(g_i.logs[PTF_B], 73, cp_b));
        ASSERT(ptf_emit(&g_i, PTF_C, &bc, ptf_pass(), c[0], NULL));
        ASSERT(vcs_proof_issuer_log_checkpoint(g_i.logs[PTF_C], 74, cp_c));
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "proof_isolation", "pair");
        struct vcs_package_store *store = vcs_package_store_open(dir, PIC_QUOTA);
        ASSERT(store != NULL);
        ASSERT(pic_put_all(store, (const uint8_t (*)[PIC_W])a, 2));
        ASSERT(pic_put_all(store, (const uint8_t (*)[PIC_W])b, 1));
        ASSERT(pic_put_all(store, (const uint8_t (*)[PIC_W])c, 1));
        ASSERT(pic_put(store, cp1, PIC_CPW));
        ASSERT(pic_put(store, cp2a, PIC_CPW));
        ASSERT(pic_put(store, cp2b, PIC_CPW));
        ASSERT(pic_put(store, cp_b, PIC_CPW));
        ASSERT(pic_put(store, cp_c, PIC_CPW));
        struct vcs_proof_receiver *rx = pic_rebuilt(store, 64u, NULL);
        ASSERT(rx != NULL);
        ASSERT(vcs_proof_receiver_issuer_equivocating(rx, g_i.pub[PTF_A]));
        vcs_proof_receiver_free(rx);
        vcs_package_store_close(store);
        ASSERT(pic_compact(dir, cp1, PIC_CPW, 0x43));
        store = vcs_package_store_open(dir, PIC_QUOTA);
        ASSERT(store != NULL);
        rx = pic_rebuilt(store, 64u, NULL);
        ASSERT(rx != NULL);
        ASSERT(vcs_proof_receiver_issuer_equivocating(rx, g_i.pub[PTF_A]));
        ASSERT(vcs_proof_receiver_issuer_history_incomplete(rx,
                                                            g_i.pub[PTF_A]));
        ASSERT_EQ(vcs_proof_receiver_issuer_checkpoints(rx, g_i.pub[PTF_A]),
                  (size_t)2);
        ASSERT(!vcs_proof_receiver_issuer_history_incomplete(rx,
                                                             g_i.pub[PTF_B]));
        struct vcs_proof_ticket_class cls[PIC_CAP];
        struct vcs_proof_reuse_decision d;
        ASSERT(pic_decide(rx, &bc, NULL, cls, &d));
        ASSERT_EQ(d.outcome, VCS_PROOF_REUSE_HIT_PASS);
        ASSERT_EQ(d.distinct_pass_signers, (uint32_t)2);
        ASSERT_STR_EQ(pic_reason_of(cls, d.tickets_seen, g_i.pub[PTF_A]),
                      VCS_PROOF_TICKET_EQUIVOCATION);
        ASSERT(pic_decide(rx, &second, NULL, cls, &d));
        ASSERT_EQ(d.outcome, VCS_PROOF_REUSE_MISS);
        ASSERT_STR_EQ(d.reason, VCS_PROOF_REUSE_WHY_INELIGIBLE);
        vcs_proof_receiver_free(rx);
        vcs_package_store_close(store);
        test_rm_rf(dir);
    } TEST_END
    return failures;
}

/* ── all three past the first catalog page ──────────────────────────── */

enum { PIC_X = 3 };

struct pic_paged {
    uint8_t seed[PIC_X][32];
    uint8_t pub[PIC_X][32];
    struct vcs_proof_issuer_log *log[PIC_X];
    struct vcs_component_proof_key_v1 bc, own[PIC_X];
    uint8_t x[PIC_X][2][PIC_W];
    uint8_t b[1][PIC_W], c[1][PIC_W], cp_b[PIC_CPW], cp_c[PIC_CPW];
    uint8_t x1_cp[PIC_CPW];               /* X1: its covered ticket evicted */
    uint8_t x2_orphan[PIC_CPW];           /* X2: parent never stored */
    uint8_t x3_cp1[PIC_CPW], x3_cp2a[PIC_CPW], x3_cp2b[PIC_CPW];
    uint8_t trusted[2 + PIC_X][32];
    struct vcs_proof_reuse_policy policy;
};

/* A ticket signed by a throwaway key's own log. */
static bool pic_emit_as(struct vcs_proof_issuer_log *log,
                        const struct vcs_component_proof_key_v1 *key,
                        uint8_t wire[PIC_W])
{
    uint8_t scratch[PIC_W];
    struct vcs_proof_ticket_v1 t;
    return ptf_emit(&g_i, PTF_STRANGER, key, ptf_pass(), scratch, NULL) &&
           vcs_proof_ticket_decode(scratch, sizeof(scratch), &t) &&
           vcs_proof_issuer_log_append(log, &t, wire);
}

/* Throwaway trusted issuer `i`: a ticket on bc, then its own unit. X1
 * checkpoints once over both; X2 and X3 checkpoint after the first too
 * (X2 drops that one, so its second is an orphan). */
static bool pic_paged_issuer(struct pic_paged *p, int i)
{
    char unit[48];
    snprintf(unit, sizeof(unit), "unit/iso/paged/own/%d", i);
    pic_key(unit, &p->own[i]);
    memset(p->seed[i], 0, 32);
    p->seed[i][0] = 0xc1;
    p->seed[i][1] = (uint8_t)i;
    p->log[i] = vcs_proof_issuer_log_new(p->seed[i]);
    if (!p->log[i] || !pic_emit_as(p->log[i], &p->bc, p->x[i][0]))
        return false;
    vcs_proof_issuer_log_pubkey(p->log[i], p->pub[i]);
    uint8_t dropped[PIC_CPW];
    uint8_t *first = i == 1 ? dropped : p->x3_cp1;
    uint8_t *last = i == 0 ? p->x1_cp : i == 1 ? p->x2_orphan : p->x3_cp2a;
    return (i == 0 || vcs_proof_issuer_log_checkpoint(p->log[i], 93, first)) &&
           pic_emit_as(p->log[i], &p->own[i], p->x[i][1]) &&
           vcs_proof_issuer_log_checkpoint(p->log[i], 94, last);
}

static bool pic_paged_emit(struct pic_paged *p)
{
    pic_key("unit/iso/paged/bc", &p->bc);
    bool ok = ptf_emit(&g_i, PTF_B, &p->bc, ptf_pass(), p->b[0], NULL) &&
              ptf_emit(&g_i, PTF_C, &p->bc, ptf_pass(), p->c[0], NULL) &&
              vcs_proof_issuer_log_checkpoint(g_i.logs[PTF_B], 91, p->cp_b) &&
              vcs_proof_issuer_log_checkpoint(g_i.logs[PTF_C], 92, p->cp_c);
    for (int i = 0; ok && i < PIC_X; i++) ok = pic_paged_issuer(p, i);
    uint8_t again[PIC_CPW];
    ok = ok && pic_resign(p->seed[2], (const uint8_t (*)[PIC_W])p->x[2], 2,
                          93, 95, again, p->x3_cp2b) &&
         memcmp(again, p->x3_cp1, PIC_CPW) == 0 &&
         memcmp(p->x3_cp2a, p->x3_cp2b, PIC_CPW) != 0;
    memcpy(p->trusted[0], g_i.pub[PTF_B], 32);
    memcpy(p->trusted[1], g_i.pub[PTF_C], 32);
    for (int i = 0; i < PIC_X; i++) memcpy(p->trusted[2 + i], p->pub[i], 32);
    p->policy = g_i.policy;
    p->policy.verifiers = (const uint8_t (*)[32])p->trusted;
    p->policy.verifier_count = 2 + PIC_X;
    return ok;
}

/* The lowest root among the broken records: fillers sort below it. */
static void pic_paged_late(const struct pic_paged *p, uint8_t late[32])
{
    const uint8_t *broken[] = {p->x1_cp, p->x2_orphan, p->x3_cp2a,
                               p->x3_cp2b};
    memset(late, 0xff, 32);
    for (size_t i = 0; i < sizeof(broken) / sizeof(broken[0]); i++) {
        uint8_t root[32];
        if (vcs_blob_root(broken[i], PIC_CPW, root) &&
            memcmp(root, late, 32) < 0)
            memcpy(late, root, 32);
    }
}

static bool pic_paged_store(struct vcs_package_store *store,
                            const struct pic_paged *p)
{
    bool ok = pic_put(store, p->b[0], PIC_W) && pic_put(store, p->c[0], PIC_W) &&
              pic_put(store, p->cp_b, PIC_CPW) &&
              pic_put(store, p->cp_c, PIC_CPW) &&
              pic_put(store, p->x1_cp, PIC_CPW) &&
              pic_put(store, p->x2_orphan, PIC_CPW) &&
              pic_put(store, p->x3_cp1, PIC_CPW) &&
              pic_put(store, p->x3_cp2a, PIC_CPW) &&
              pic_put(store, p->x3_cp2b, PIC_CPW);
    for (int i = 0; ok && i < PIC_X; i++)
        ok = pic_put_all(store, (const uint8_t (*)[PIC_W])p->x[i], 2);
    return ok;
}

static int pic_expect_paged(const struct vcs_proof_receiver *rx,
                            const struct pic_paged *p)
{
    int failures = 0;
    TEST_CASE("proof_isolation: past page one, each broken issuer alone is isolated") {
        ASSERT(rx != NULL);
        for (int i = 0; i < PIC_X; i++)
            ASSERT(vcs_proof_receiver_issuer_history_incomplete(rx, p->pub[i]));
        ASSERT(!vcs_proof_receiver_issuer_equivocating(rx, p->pub[0]));
        ASSERT(!vcs_proof_receiver_issuer_equivocating(rx, p->pub[1]));
        ASSERT(vcs_proof_receiver_issuer_equivocating(rx, p->pub[2]));
        ASSERT(!vcs_proof_receiver_issuer_history_incomplete(rx,
                                                             g_i.pub[PTF_B]));
        ASSERT(!vcs_proof_receiver_issuer_history_incomplete(rx,
                                                             g_i.pub[PTF_C]));
        struct vcs_proof_ticket_class cls[PIC_CAP];
        struct vcs_proof_reuse_decision d;
        ASSERT(pic_decide(rx, &p->bc, &p->policy, cls, &d));
        ASSERT_EQ(d.outcome, VCS_PROOF_REUSE_HIT_PASS);
        ASSERT_EQ(d.distinct_pass_signers, (uint32_t)2);
        ASSERT_STR_EQ(pic_reason_of(cls, d.tickets_seen, p->pub[1]),
                      VCS_PROOF_TICKET_HISTORY_INCOMPLETE);
        ASSERT_STR_EQ(pic_reason_of(cls, d.tickets_seen, p->pub[2]),
                      VCS_PROOF_TICKET_EQUIVOCATION);
        for (int i = 0; i < 2; i++) {
            ASSERT(pic_decide(rx, &p->own[i], &p->policy, cls, &d));
            ASSERT_EQ(d.outcome, VCS_PROOF_REUSE_MISS);
            ASSERT_STR_EQ(d.reason, VCS_PROOF_REUSE_WHY_HISTORY_INCOMPLETE);
        }
        ASSERT(pic_decide(rx, &p->own[2], &p->policy, cls, &d));
        ASSERT_EQ(d.outcome, VCS_PROOF_REUSE_MISS);
        ASSERT_STR_EQ(d.reason, VCS_PROOF_REUSE_WHY_INELIGIBLE);
    } TEST_END
    return failures;
}

static int pic_case_paged(void)
{
    int failures = 0;
    TEST_CASE("proof_isolation: >256 objects, every broken record on a later page") {
        ASSERT(pic_fresh());
        static struct pic_paged p;
        memset(&p, 0, sizeof(p));
        bool emitted = pic_paged_emit(&p);
        for (int i = 0; i < PIC_X; i++) vcs_proof_issuer_log_free(p.log[i]);
        ASSERT(emitted);
        uint8_t late[32];
        pic_paged_late(&p, late);
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "proof_isolation", "paged");
        struct vcs_package_store *store = vcs_package_store_open(dir, PIC_QUOTA);
        ASSERT(store != NULL);
        ASSERT(pic_fill(store, late, PIC_FILLER));
        ASSERT(pic_paged_store(store, &p));
        ASSERT(pic_later_page(store, late));
        const size_t rows = PIC_FILLER + 32u;
        /* The first restart pins X3's signed checkpoint pair. */
        struct vcs_proof_receiver *rx = pic_rebuilt(store, rows, &p.policy);
        ASSERT(rx != NULL);
        ASSERT(vcs_proof_receiver_issuer_equivocating(rx, p.pub[2]));
        vcs_proof_receiver_free(rx);
        vcs_package_store_close(store);
        ASSERT(pic_compact(dir, p.x[0][0], PIC_W, 0x44));
        ASSERT(pic_compact(dir, p.x3_cp1, PIC_CPW, 0x45));
        store = vcs_package_store_open(dir, PIC_QUOTA);
        ASSERT(store != NULL);
        ASSERT(pic_later_page(store, late));
        rx = pic_rebuilt(store, rows, &p.policy);
        failures += pic_expect_paged(rx, &p);
        vcs_proof_receiver_free(rx);
        vcs_package_store_close(store);
        test_rm_rf(dir);
    } TEST_END
    return failures;
}

/* ── a live receiver keeps what it already verified ─────────────────── */

static int pic_case_live_prior(void)
{
    int failures = 0;
    TEST_CASE("proof_isolation: a live receiver keeps its verified issuer, learns the rest") {
        ASSERT(pic_fresh());
        struct vcs_component_proof_key_v1 bc, later;
        pic_key("unit/iso/live/bc", &bc);
        pic_key("unit/iso/live/later", &later);
        uint8_t a[1][PIC_W], b[2][PIC_W], c[2][PIC_W];
        uint8_t cp_a[PIC_CPW], cp_b1[PIC_CPW], cp_c1[PIC_CPW];
        uint8_t cp_b2[PIC_CPW], cp_c2[PIC_CPW];
        ASSERT(ptf_emit(&g_i, PTF_A, &bc, ptf_pass(), a[0], NULL));
        ASSERT(ptf_emit(&g_i, PTF_B, &bc, ptf_pass(), b[0], NULL));
        ASSERT(ptf_emit(&g_i, PTF_C, &bc, ptf_pass(), c[0], NULL));
        ASSERT(vcs_proof_issuer_log_checkpoint(g_i.logs[PTF_A], 101, cp_a));
        ASSERT(vcs_proof_issuer_log_checkpoint(g_i.logs[PTF_B], 102, cp_b1));
        ASSERT(vcs_proof_issuer_log_checkpoint(g_i.logs[PTF_C], 103, cp_c1));
        struct vcs_proof_sync_report rep;
        const size_t lens[] = {PIC_W};
        const uint8_t *da[] = {a[0]}, *db[] = {b[0]}, *dc[] = {c[0]};
        ASSERT(vcs_proof_receiver_sync(g_i.rx, cp_a, PIC_CPW, da, lens, 1, &rep));
        ASSERT(vcs_proof_receiver_sync(g_i.rx, cp_b1, PIC_CPW, db, lens, 1, &rep));
        ASSERT(vcs_proof_receiver_sync(g_i.rx, cp_c1, PIC_CPW, dc, lens, 1, &rep));
        ASSERT_EQ(rep.outcome, VCS_PROOF_SYNC_ADVANCED);
        /* B and C sign more, which only the store holds. */
        ASSERT(ptf_emit(&g_i, PTF_B, &later, ptf_pass(), b[1], NULL));
        ASSERT(ptf_emit(&g_i, PTF_C, &later, ptf_pass(), c[1], NULL));
        ASSERT(vcs_proof_issuer_log_checkpoint(g_i.logs[PTF_B], 104, cp_b2));
        ASSERT(vcs_proof_issuer_log_checkpoint(g_i.logs[PTF_C], 105, cp_c2));
        /* X = A: its checkpoint is stored, its covered ticket is not. */
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "proof_isolation", "live");
        struct vcs_package_store *store = vcs_package_store_open(dir, PIC_QUOTA);
        ASSERT(store != NULL);
        ASSERT(pic_put(store, cp_a, PIC_CPW));
        ASSERT(pic_put_all(store, (const uint8_t (*)[PIC_W])b, 2));
        ASSERT(pic_put_all(store, (const uint8_t (*)[PIC_W])c, 2));
        ASSERT(pic_put(store, cp_b1, PIC_CPW));
        ASSERT(pic_put(store, cp_b2, PIC_CPW));
        ASSERT(pic_put(store, cp_c1, PIC_CPW));
        ASSERT(pic_put(store, cp_c2, PIC_CPW));
        size_t tickets = 0, cps = 0, skipped = 0;
        ASSERT(vcs_proof_receiver_rebuild_bounded(g_i.rx, store, 64u, &tickets,
                                                  &cps, &skipped));
        ASSERT_EQ(tickets, (size_t)4);
        ASSERT_EQ(cps, (size_t)4);
        /* Policy: the live view keeps A exactly as it verified it. */
        ASSERT(!vcs_proof_receiver_issuer_history_incomplete(g_i.rx,
                                                             g_i.pub[PTF_A]));
        ASSERT_EQ(vcs_proof_receiver_issuer_leaves(g_i.rx, g_i.pub[PTF_A]),
                  (uint64_t)1);
        ASSERT_EQ(vcs_proof_receiver_ticket_count(g_i.rx), (size_t)5);
        struct vcs_proof_ticket_class cls[PIC_CAP];
        struct vcs_proof_reuse_decision d;
        ASSERT(pic_decide(g_i.rx, &bc, NULL, cls, &d));
        ASSERT_EQ(d.outcome, VCS_PROOF_REUSE_HIT_PASS);
        ASSERT_EQ(d.distinct_pass_signers, (uint32_t)3);
        ASSERT(pic_decide(g_i.rx, &later, NULL, cls, &d));
        ASSERT_EQ(d.outcome, VCS_PROOF_REUSE_HIT_PASS);
        /* A restart has no prior: the same store isolates A. */
        struct vcs_proof_receiver *rx = pic_rebuilt(store, 64u, NULL);
        ASSERT(rx != NULL);
        ASSERT(vcs_proof_receiver_issuer_history_incomplete(rx,
                                                            g_i.pub[PTF_A]));
        ASSERT(pic_decide(rx, &bc, NULL, cls, &d));
        ASSERT_EQ(d.outcome, VCS_PROOF_REUSE_HIT_PASS);
        ASSERT_EQ(d.distinct_pass_signers, (uint32_t)2);
        vcs_proof_receiver_free(rx);
        vcs_package_store_close(store);
        test_rm_rf(dir);
    } TEST_END
    return failures;
}

/* ── the local issuer's own restore ─────────────────────────────────── */

static int pic_case_own_restore(void)
{
    int failures = 0;
    TEST_CASE("proof_isolation: a stranger orphan cannot block restore; an own orphan refuses") {
        ASSERT(pic_fresh());
        uint8_t a[1][PIC_W], cp_a[PIC_CPW], head[32];
        ASSERT(ptf_emit(&g_i, PTF_A, &g_i.base, ptf_pass(), a[0], NULL));
        ASSERT(vcs_proof_issuer_log_checkpoint(g_i.logs[PTF_A], 111, cp_a));
        uint8_t s[2][PIC_W], s_cp1[PIC_CPW], s_cp2[PIC_CPW];
        ASSERT(ptf_emit(&g_i, PTF_STRANGER, &g_i.base, ptf_pass(), s[0], NULL));
        ASSERT(vcs_proof_issuer_log_checkpoint(g_i.logs[PTF_STRANGER], 112,
                                               s_cp1));
        ASSERT(ptf_emit(&g_i, PTF_STRANGER, &g_i.base, ptf_fail(), s[1], NULL));
        ASSERT(vcs_proof_issuer_log_checkpoint(g_i.logs[PTF_STRANGER], 113,
                                               s_cp2));
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "proof_isolation", "restore");
        struct vcs_package_store *store = vcs_package_store_open(dir, PIC_QUOTA);
        ASSERT(store != NULL);
        ASSERT(pic_put(store, a[0], PIC_W));
        ASSERT(vcs_proof_ticket_store_put(store, cp_a, PIC_CPW, head));
        ASSERT(pic_put_all(store, (const uint8_t (*)[PIC_W])s, 2));
        ASSERT(pic_put(store, s_cp2, PIC_CPW));
        struct vcs_proof_issuer_log *log = vcs_proof_issuer_log_restore_from_store(
            g_i.seed[PTF_A], store, head, 64u, 64u);
        ASSERT(log != NULL);
        ASSERT_EQ(vcs_proof_issuer_log_count(log), (uint64_t)1);
        vcs_proof_issuer_log_free(log);
        /* C's key has only an orphan checkpoint here: its history is
         * incomplete, so it never restores as an empty log. */
        uint8_t c[2][PIC_W], orphan[PIC_CPW];
        ASSERT(ptf_emit(&g_i, PTF_C, &g_i.base, ptf_pass(), c[0], NULL));
        ASSERT(ptf_emit(&g_i, PTF_C, &g_i.base, ptf_pass(), c[1], NULL));
        ASSERT(pic_resign(g_i.seed[PTF_C], (const uint8_t (*)[PIC_W])c, 2, 114,
                          115, NULL, orphan));
        ASSERT(pic_put(store, orphan, PIC_CPW));
        log = vcs_proof_issuer_log_restore_from_store(g_i.seed[PTF_C], store,
                                                      NULL, 64u, 64u);
        ASSERT(log == NULL);
        vcs_package_store_close(store);
        test_rm_rf(dir);
    } TEST_END
    return failures;
}

int ptf_isolation_cases(void)
{
    int failures = 0;
    failures += pic_case_evicted_ticket();
    failures += pic_case_orphan_checkpoint();
    failures += pic_case_pair_parent_evicted();
    failures += pic_case_live_prior();
    failures += pic_case_own_restore();
    failures += pic_case_paged();
    ptf_free(&g_i);
    return failures;
}
