/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Restart-anywhere receiver history for the proof_ticket_reuse
 *          group: revocation after a reopened rebuild, a fork visible only
 *          past the first catalog page, and a process that dies inside a
 *          rebuild. Every case keeps HIT, MISS and REFUSE distinct. */

#include "test/test_core.h"

#include "test/proof_ticket_fixture.h"
#include "vcs/blob_store.h"
#include "vcs/package_store.h"
#include "vcs/proof_ticket.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#if !defined(_WIN32)
#include <sys/wait.h>
#endif

#define PHC_QUOTA (UINT64_C(64) * 1024 * 1024)
#define PHC_CAP 16u
#define PHC_CRASHED 42
#define PHC_FILLER (VCS_PACKAGE_STORE_PAGE_MAX + 4u)

static struct ptf g_h;

static bool phc_fresh(void)
{
    ptf_free(&g_h);
    return ptf_init(&g_h);
}

static void phc_key(const char *unit, struct vcs_component_proof_key_v1 *k)
{
    *k = g_h.base;
    ptf_root(VCS_CPK_UNIT_ID, unit, k->roots[VCS_CPK_UNIT_ID]);
}

static bool phc_put(struct vcs_package_store *store, const uint8_t *wire,
                    size_t len, uint8_t root[32])
{
    uint8_t local[32];
    return vcs_proof_ticket_store_put(store, wire, len, root ? root : local);
}

/* Checkpoint one signer's whole log and store its tickets and checkpoint.
 * The exact checkpoint wire is returned for a live sync of the same view. */
static bool phc_store_log(struct vcs_package_store *store, int signer,
                          const uint8_t (*wires)[VCS_PROOF_TICKET_WIRE_BYTES],
                          size_t count, uint64_t created,
                          uint8_t cp[VCS_PROOF_CHECKPOINT_WIRE_BYTES])
{
    uint8_t local[VCS_PROOF_CHECKPOINT_WIRE_BYTES];
    uint8_t *out = cp ? cp : local;
    for (size_t i = 0; i < count; i++)
        if (!phc_put(store, wires[i], VCS_PROOF_TICKET_WIRE_BYTES, NULL))
            return false;
    return vcs_proof_issuer_log_checkpoint(g_h.logs[signer], created, out) &&
           phc_put(store, out, VCS_PROOF_CHECKPOINT_WIRE_BYTES, NULL);
}

/* Sync a receiver with exactly one stored ticket and checkpoint. */
static bool phc_sync_one_into(struct vcs_proof_receiver *rx, const uint8_t *cp,
                              const uint8_t *ticket)
{
    const uint8_t *delta[] = {ticket};
    const size_t lens[] = {VCS_PROOF_TICKET_WIRE_BYTES};
    struct vcs_proof_sync_report rep;
    return vcs_proof_receiver_sync(rx, cp, VCS_PROOF_CHECKPOINT_WIRE_BYTES,
                                   delta, lens, 1, &rep) &&
           rep.outcome == VCS_PROOF_SYNC_ADVANCED;
}

static bool phc_sync_one(const uint8_t *cp, const uint8_t *ticket)
{
    return phc_sync_one_into(g_h.rx, cp, ticket);
}

/* Filler packages: `count` of them, all sorting before `late` when `late`
 * is non-NULL, so `late` cannot appear on the first catalog page. */
static bool phc_fill(struct vcs_package_store *store, const uint8_t *late,
                     uint32_t count)
{
    uint32_t added = 0;
    for (uint32_t i = 0; added < count && i < 1000000u; i++) {
        uint8_t blob[8] = {'h', 'i', 's', 't', (uint8_t)i, (uint8_t)(i >> 8),
                           (uint8_t)(i >> 16), (uint8_t)(i >> 24)};
        uint8_t root[32];
        if (!vcs_blob_root(blob, sizeof(blob), root)) return false;
        if (late && memcmp(root, late, 32) >= 0) continue;
        if (!phc_put(store, blob, sizeof(blob), NULL)) return false;
        added++;
    }
    return added == count;
}

/* A restarted receiver rebuilt under `trust` (NULL: the fixture policy),
 * which also pins its trusted verifiers' fork evidence. */
static struct vcs_proof_receiver *phc_rebuilt_under(
    struct vcs_package_store *store, size_t rows,
    const struct vcs_proof_reuse_policy *trust)
{
    struct vcs_proof_receiver *rx = vcs_proof_receiver_new();
    size_t tickets = 0, cps = 0, skipped = 0;
    uint64_t generation = 0;
    if (rx && vcs_proof_receiver_rebuild_with_policy(
                  rx, store, trust ? trust : &g_h.policy, NULL, 0, rows,
                  &tickets, &cps, &skipped, &generation))
        return rx;
    vcs_proof_receiver_free(rx);
    return NULL;
}

static struct vcs_proof_receiver *phc_rebuilt(struct vcs_package_store *store,
                                              size_t rows)
{
    return phc_rebuilt_under(store, rows, NULL);
}

static bool phc_decide(const struct vcs_proof_receiver *rx,
                       const struct vcs_component_proof_key_v1 *key,
                       const struct vcs_proof_reuse_policy *policy,
                       struct vcs_proof_ticket_class cls[PHC_CAP],
                       struct vcs_proof_reuse_decision *d)
{
    struct vcs_proof_reuse_request req = {
        .local = key, .action_class = VCS_PROOF_ACTION_CHECK,
        .domain = &g_h.domain, .policy = policy ? policy : &g_h.policy,
        .artifacts = &g_h.source,
    };
    return vcs_proof_reuse_decide(rx, &req, cls, PHC_CAP, d);
}

static const char *phc_reason_of(const struct vcs_proof_ticket_class *cls,
                                 uint32_t seen, int signer)
{
    for (uint32_t i = 0; i < seen; i++)
        if (memcmp(cls[i].producer_pubkey, g_h.pub[signer], 32) == 0)
            return cls[i].reason;
    return "absent";
}

static bool phc_pinned(struct vcs_package_store *store, const uint8_t *wire,
                       size_t len)
{
    uint8_t root[32];
    struct vcs_package_store_status st;
    return vcs_blob_root(wire, len, root) &&
           vcs_package_store_package_status(store, root, &st) &&
           st.tracked && st.pinned;
}

static uint64_t phc_pins(struct vcs_package_store *store)
{
    return vcs_package_store_pool_usage(store, VCS_PACKAGE_STORE_POOL_PINS);
}

/* A's own key signs a second history whose sequence 0 is `unit`. */
static bool phc_fork_ticket(const char *unit,
                            uint8_t wire[VCS_PROOF_TICKET_WIRE_BYTES])
{
    struct vcs_proof_issuer_log *fork =
        vcs_proof_issuer_log_new(g_h.seed[PTF_A]);
    uint8_t scratch[VCS_PROOF_TICKET_WIRE_BYTES];
    struct vcs_proof_ticket_v1 t;
    struct vcs_component_proof_key_v1 k;
    phc_key(unit, &k);
    bool made = fork &&
        ptf_emit(&g_h, PTF_STRANGER, &k, ptf_pass(), scratch, NULL) &&
        vcs_proof_ticket_decode(scratch, sizeof(scratch), &t) &&
        vcs_proof_issuer_log_append(fork, &t, wire);
    vcs_proof_issuer_log_free(fork);
    return made;
}

/* Compaction: at a quota a few bytes over the RARE pool's usage, `victim`
 * is the best-replicated RARE package (the first the store may drop), so
 * one unrelated write of the same size evicts exactly it. */
static bool phc_compact(const char *dir, const uint8_t *victim, size_t len,
                        uint8_t salt)
{
    struct vcs_package_store *store = vcs_package_store_open(dir, PHC_QUOTA);
    if (!store) return false;
    uint64_t rare = vcs_package_store_pool_usage(store,
                                                 VCS_PACKAGE_STORE_POOL_RARE);
    vcs_package_store_close(store);
    store = vcs_package_store_open(dir, (rare / 3u) * 10u + 10u);
    uint8_t root[32];
    uint8_t junk[VCS_PROOF_TICKET_WIRE_BYTES + 1u];
    size_t got = 0;
    bool ok = store && len <= VCS_PROOF_TICKET_WIRE_BYTES &&
              vcs_blob_root(victim, len, root) &&
              vcs_package_store_set_class(store, root,
                                          VCS_PACKAGE_STORE_CLASS_RARE,
                                          1000u) == VCS_PACKAGE_STORE_OK;
    if (ok) {
        memset(junk, salt, len);
        ok = phc_put(store, junk, len, NULL) &&
             vcs_blob_get_from(store, root, junk, sizeof(junk), &got) ==
                 VCS_BLOB_ERR_ABSENT;
    }
    if (store) vcs_package_store_close(store);
    return ok;
}

/* ── a process that dies inside a multi-page rebuild ────────────────── */

#if !defined(_WIN32)
void vcs_proof_receiver_test_before_recheck(void (*hook)(void *),
                                            void *context);

static void phc_die(void *context)
{
    (void)context;
    _exit(PHC_CRASHED);
}

/* A child process scans every page, then dies before it can publish. */
static bool phc_crash_rebuild(const char *dir, size_t rows)
{
    fflush(stdout);
    fflush(stderr);
    pid_t pid = fork();
    if (pid < 0) return false;
    if (pid == 0) {
        struct vcs_package_store *store = vcs_package_store_open(dir, PHC_QUOTA);
        if (!store) _exit(2);
        struct vcs_proof_receiver *rx = vcs_proof_receiver_new();
        if (!rx) _exit(3);
        vcs_proof_receiver_test_before_recheck(phc_die, NULL);
        size_t tickets = 0, cps = 0, skipped = 0;
        bool rebuilt = vcs_proof_receiver_rebuild_bounded(
            rx, store, rows, &tickets, &cps, &skipped);
        _exit(rebuilt ? 4 : 5);
    }
    int status = 0;
    return waitpid(pid, &status, 0) == pid && WIFEXITED(status) &&
           WEXITSTATUS(status) == PHC_CRASHED;
}
#endif

/* ── revocation, conflict and a crash after a reopened rebuild ──────── */

struct phc_keys {
    struct vcs_component_proof_key_v1 both, two, disputed, never;
};

/* After any restart, without revocation: HIT, REFUSE and MISS stay apart. */
static int phc_expect_unrevoked(const struct vcs_proof_receiver *rx,
                                const struct phc_keys *k)
{
    int failures = 0;
    TEST_CASE("proof_history: restarted receiver keeps HIT/MISS/REFUSE distinct") {
        struct vcs_proof_ticket_class cls[PHC_CAP];
        struct vcs_proof_reuse_decision d;
        ASSERT(phc_decide(rx, &k->both, NULL, cls, &d));
        ASSERT_EQ(d.outcome, VCS_PROOF_REUSE_HIT_PASS);
        ASSERT_EQ(d.distinct_pass_signers, (uint32_t)3);
        ASSERT(phc_decide(rx, &k->two, NULL, cls, &d));
        ASSERT_EQ(d.outcome, VCS_PROOF_REUSE_HIT_PASS);
        ASSERT(phc_decide(rx, &k->disputed, NULL, cls, &d));
        ASSERT_EQ(d.outcome, VCS_PROOF_REUSE_REFUSE);
        ASSERT_STR_EQ(d.reason, VCS_PROOF_OBSERVATION_CONFLICT);
        ASSERT(phc_decide(rx, &k->never, NULL, cls, &d));
        ASSERT_EQ(d.outcome, VCS_PROOF_REUSE_MISS);
        ASSERT_STR_EQ(d.reason, VCS_PROOF_REUSE_WHY_NONE);
    } TEST_END
    return failures;
}

static int phc_case_revoked_after_reopen(void)
{
    int failures = 0;
    TEST_CASE("proof_history: revocation after reopen neither hits nor forgets") {
        ASSERT(phc_fresh());
        struct phc_keys k;
        phc_key("unit/both", &k.both);
        phc_key("unit/two", &k.two);
        phc_key("unit/disputed", &k.disputed);
        phc_key("unit/never", &k.never);
        uint8_t a[3][VCS_PROOF_TICKET_WIRE_BYTES];
        uint8_t b[2][VCS_PROOF_TICKET_WIRE_BYTES];
        uint8_t c[2][VCS_PROOF_TICKET_WIRE_BYTES];
        ASSERT(ptf_emit(&g_h, PTF_A, &k.both, ptf_pass(), a[0], NULL));
        ASSERT(ptf_emit(&g_h, PTF_A, &k.two, ptf_pass(), a[1], NULL));
        ASSERT(ptf_emit(&g_h, PTF_A, &k.disputed, ptf_pass(), a[2], NULL));
        ASSERT(ptf_emit(&g_h, PTF_B, &k.both, ptf_pass(), b[0], NULL));
        ASSERT(ptf_emit(&g_h, PTF_B, &k.two, ptf_pass(), b[1], NULL));
        ASSERT(ptf_emit(&g_h, PTF_C, &k.both, ptf_pass(), c[0], NULL));
        ASSERT(ptf_emit(&g_h, PTF_C, &k.disputed, ptf_fail(), c[1], NULL));
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "proof_history", "revoked");
        struct vcs_package_store *store = vcs_package_store_open(dir, PHC_QUOTA);
        ASSERT(store != NULL);
        ASSERT(phc_fill(store, NULL, PHC_FILLER));
        ASSERT(phc_store_log(store, PTF_A, a, 3, 41, NULL));
        ASSERT(phc_store_log(store, PTF_B, b, 2, 42, NULL));
        ASSERT(phc_store_log(store, PTF_C, c, 2, 43, NULL));
        const size_t rows = PHC_FILLER + 10u;
        vcs_package_store_close(store);
        store = vcs_package_store_open(dir, PHC_QUOTA);
        ASSERT(store != NULL);
        struct vcs_proof_receiver *rx = phc_rebuilt(store, rows);
        ASSERT(rx != NULL);
        failures += phc_expect_unrevoked(rx, &k);

        /* A revoked: its rebuilt history cannot authorize, B and C still do. */
        struct vcs_proof_ticket_class cls[PHC_CAP];
        struct vcs_proof_reuse_decision d;
        struct vcs_proof_reuse_policy revoked = g_h.policy;
        revoked.revoked = (const uint8_t (*)[32])&g_h.pub[PTF_A];
        revoked.revoked_count = 1;
        ASSERT(phc_decide(rx, &k.both, &revoked, cls, &d));
        ASSERT_EQ(d.outcome, VCS_PROOF_REUSE_HIT_PASS);
        ASSERT_EQ(d.eligible_pass, (uint32_t)2);
        ASSERT_STR_EQ(phc_reason_of(cls, d.tickets_seen, PTF_A),
                      VCS_PROOF_TICKET_SIGNER_REVOKED);
        ASSERT(phc_decide(rx, &k.two, &revoked, cls, &d));
        ASSERT_EQ(d.outcome, VCS_PROOF_REUSE_MISS);
        ASSERT_STR_EQ(d.reason, VCS_PROOF_REUSE_WHY_QUORUM);
        ASSERT_EQ(d.eligible_pass, (uint32_t)1);

        /* A and B revoked: nothing authorizes, still a MISS, not a REFUSE. */
        uint8_t ab[2][32];
        memcpy(ab[0], g_h.pub[PTF_A], 32);
        memcpy(ab[1], g_h.pub[PTF_B], 32);
        struct vcs_proof_reuse_policy both_revoked = g_h.policy;
        both_revoked.revoked = (const uint8_t (*)[32])ab;
        both_revoked.revoked_count = 2;
        ASSERT(phc_decide(rx, &k.both, &both_revoked, cls, &d));
        ASSERT_EQ(d.outcome, VCS_PROOF_REUSE_MISS);
        ASSERT_EQ(d.eligible_pass, (uint32_t)1);
        ASSERT(phc_decide(rx, &k.two, &both_revoked, cls, &d));
        ASSERT_EQ(d.outcome, VCS_PROOF_REUSE_MISS);
        ASSERT_STR_EQ(d.reason, VCS_PROOF_REUSE_WHY_INELIGIBLE);
        ASSERT_EQ(d.tickets_seen, (uint32_t)2);

        /* Revoking C, who never signed `two`, leaves `two` a HIT. */
        struct vcs_proof_reuse_policy c_revoked = g_h.policy;
        c_revoked.revoked = (const uint8_t (*)[32])&g_h.pub[PTF_C];
        c_revoked.revoked_count = 1;
        ASSERT(phc_decide(rx, &k.two, &c_revoked, cls, &d));
        ASSERT_EQ(d.outcome, VCS_PROOF_REUSE_HIT_PASS);

        /* Policy is read per decision: the receiver forgot nothing. */
        ASSERT_EQ(vcs_proof_receiver_ticket_count(rx), (size_t)7);
        failures += phc_expect_unrevoked(rx, &k);

        /* A second restart rebuilds over the live receiver as its anchor and
         * reaches the same verdicts under the same revoked policy. */
        vcs_package_store_close(store);
        store = vcs_package_store_open(dir, PHC_QUOTA);
        ASSERT(store != NULL);
        size_t tickets = 0, cps = 0, skipped = 0;
        ASSERT(vcs_proof_receiver_rebuild_bounded(rx, store, rows, &tickets,
                                                  &cps, &skipped));
        ASSERT_EQ(tickets, (size_t)7);
        ASSERT_EQ(cps, (size_t)3);
        ASSERT_EQ(skipped, (size_t)PHC_FILLER);
        ASSERT(phc_decide(rx, &k.both, &revoked, cls, &d));
        ASSERT_EQ(d.outcome, VCS_PROOF_REUSE_HIT_PASS);
        ASSERT(phc_decide(rx, &k.two, &revoked, cls, &d));
        ASSERT_EQ(d.outcome, VCS_PROOF_REUSE_MISS);
        vcs_proof_receiver_free(rx);
        vcs_package_store_close(store);
#if !defined(_WIN32)
        /* A process dies after scanning every page, before publishing. The
         * next process rebuilds the same truth from the untouched CAS. */
        ASSERT(phc_crash_rebuild(dir, rows));
        store = vcs_package_store_open(dir, PHC_QUOTA);
        ASSERT(store != NULL);
        rx = phc_rebuilt(store, rows);
        ASSERT(rx != NULL);
        failures += phc_expect_unrevoked(rx, &k);
        vcs_proof_receiver_free(rx);
        vcs_package_store_close(store);
#endif
        test_rm_rf(dir);
    } TEST_END
    return failures;
}

/* ── a fork visible only past the first catalog page ────────────── */

static int phc_case_late_page_fork(void)
{
    int failures = 0;
    TEST_CASE("proof_history: a fork found only on a later page never hits") {
        ASSERT(phc_fresh());
        struct vcs_component_proof_key_v1 forked_key;
        phc_key("unit/forked", &forked_key);
        uint8_t a[1][VCS_PROOF_TICKET_WIRE_BYTES];
        uint8_t b[1][VCS_PROOF_TICKET_WIRE_BYTES];
        ASSERT(ptf_emit(&g_h, PTF_A, &g_h.base, ptf_pass(), a[0], NULL));
        ASSERT(ptf_emit(&g_h, PTF_B, &g_h.base, ptf_pass(), b[0], NULL));

        /* A's own key signs a second history at the same sequence. */
        struct vcs_proof_issuer_log *fork =
            vcs_proof_issuer_log_new(g_h.seed[PTF_A]);
        ASSERT(fork != NULL);
        uint8_t forked[VCS_PROOF_TICKET_WIRE_BYTES];
        uint8_t fork_cp[VCS_PROOF_CHECKPOINT_WIRE_BYTES];
        uint8_t scratch[VCS_PROOF_TICKET_WIRE_BYTES];
        struct vcs_proof_ticket_v1 t;
        bool made = ptf_emit(&g_h, PTF_STRANGER, &forked_key, ptf_pass(),
                             scratch, NULL) &&
                    vcs_proof_ticket_decode(scratch, sizeof(scratch), &t) &&
                    vcs_proof_issuer_log_append(fork, &t, forked) &&
                    vcs_proof_issuer_log_checkpoint(fork, 51, fork_cp);
        vcs_proof_issuer_log_free(fork);
        ASSERT(made);
        uint8_t forked_root[32], fork_cp_root[32];
        ASSERT(vcs_blob_root(forked, sizeof(forked), forked_root));
        ASSERT(vcs_blob_root(fork_cp, sizeof(fork_cp), fork_cp_root));
        const uint8_t *late = memcmp(forked_root, fork_cp_root, 32) > 0
                            ? forked_root : fork_cp_root;

        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "proof_history", "latefork");
        struct vcs_package_store *store = vcs_package_store_open(dir, PHC_QUOTA);
        ASSERT(store != NULL);
        ASSERT(phc_fill(store, late, VCS_PACKAGE_STORE_PAGE_MAX));
        uint8_t cp_a[VCS_PROOF_CHECKPOINT_WIRE_BYTES];
        uint8_t cp_b[VCS_PROOF_CHECKPOINT_WIRE_BYTES];
        ASSERT(phc_store_log(store, PTF_A, a, 1, 52, cp_a));
        ASSERT(phc_store_log(store, PTF_B, b, 1, 53, cp_b));
        /* A live receiver already serves a HIT from the honest history. */
        ASSERT(phc_sync_one(cp_a, a[0]));
        ASSERT(phc_sync_one(cp_b, b[0]));
        struct vcs_proof_ticket_class cls[PHC_CAP];
        struct vcs_proof_reuse_decision d;
        ASSERT(phc_decide(g_h.rx, &g_h.base, NULL, cls, &d));
        ASSERT_EQ(d.outcome, VCS_PROOF_REUSE_HIT_PASS);
        ASSERT(phc_put(store, forked, sizeof(forked), NULL));
        ASSERT(phc_put(store, fork_cp, sizeof(fork_cp), NULL));
        const size_t rows = VCS_PACKAGE_STORE_PAGE_MAX + 6u;
        struct vcs_package_store_summary page_rows[VCS_PACKAGE_STORE_PAGE_MAX];
        struct vcs_package_store_page page;
        ASSERT_EQ(vcs_package_store_page_summaries(
                      store, NULL, VCS_PACKAGE_STORE_PAGE_MAX, 0, page_rows,
                      &page), VCS_PACKAGE_STORE_PAGE_OK);
        ASSERT(page.has_more);
        ASSERT(memcmp(late, page.next_root, 32) > 0);

        /* One page is not the history: refuse, publish nothing. */
        struct vcs_proof_receiver *partial = vcs_proof_receiver_new();
        ASSERT(partial != NULL);
        size_t tickets = 9, cps = 9, skipped = 9;
        ASSERT(!vcs_proof_receiver_rebuild_bounded(
            partial, store, VCS_PACKAGE_STORE_PAGE_MAX, &tickets, &cps,
            &skipped));
        ASSERT_EQ(tickets, (size_t)0);
        ASSERT_EQ(vcs_proof_receiver_ticket_count(partial), (size_t)0);
        vcs_proof_receiver_free(partial);

        /* Restart: the complete catalog shows A equivocating. */
        vcs_package_store_close(store);
        store = vcs_package_store_open(dir, PHC_QUOTA);
        ASSERT(store != NULL);
        struct vcs_proof_receiver *rx = phc_rebuilt(store, rows);
        ASSERT(rx != NULL);
        ASSERT(vcs_proof_receiver_issuer_equivocating(rx, g_h.pub[PTF_A]));
        ASSERT(phc_decide(rx, &g_h.base, NULL, cls, &d));
        ASSERT_EQ(d.outcome, VCS_PROOF_REUSE_MISS);
        ASSERT_STR_EQ(d.reason, VCS_PROOF_REUSE_WHY_QUORUM);
        ASSERT_STR_EQ(phc_reason_of(cls, d.tickets_seen, PTF_A),
                      VCS_PROOF_TICKET_EQUIVOCATION);
        ASSERT(phc_decide(rx, &forked_key, NULL, cls, &d));
        ASSERT_EQ(d.outcome, VCS_PROOF_REUSE_MISS);
        ASSERT_STR_EQ(d.reason, VCS_PROOF_REUSE_WHY_INELIGIBLE);
        ASSERT_STR_EQ(phc_reason_of(cls, d.tickets_seen, PTF_A),
                      VCS_PROOF_TICKET_EQUIVOCATION);
        vcs_proof_receiver_free(rx);

        /* The receiver that already served a HIT cannot publish a view that
         * unverifies its own checkpoint, so its rebuild refuses. The signed
         * fork from the later page still reaches it: A stops hitting, B's
         * history and the rest of the old view are untouched. */
        ASSERT(!vcs_proof_receiver_rebuild_bounded(g_h.rx, store, rows,
                                                   &tickets, &cps, &skipped));
        ASSERT_EQ(tickets, (size_t)0);
        ASSERT_EQ(vcs_proof_receiver_ticket_count(g_h.rx), (size_t)2);
        ASSERT(vcs_proof_receiver_issuer_equivocating(g_h.rx, g_h.pub[PTF_A]));
        ASSERT(!vcs_proof_receiver_issuer_equivocating(g_h.rx, g_h.pub[PTF_B]));
        ASSERT(phc_decide(g_h.rx, &g_h.base, NULL, cls, &d));
        ASSERT_EQ(d.outcome, VCS_PROOF_REUSE_MISS);
        ASSERT_STR_EQ(d.reason, VCS_PROOF_REUSE_WHY_QUORUM);
        ASSERT_STR_EQ(phc_reason_of(cls, d.tickets_seen, PTF_A),
                      VCS_PROOF_TICKET_EQUIVOCATION);
        ASSERT_STR_EQ(phc_reason_of(cls, d.tickets_seen, PTF_B),
                      VCS_PROOF_TICKET_ELIGIBLE);
        /* A budget that cannot reach the later page records nothing. */
        struct vcs_proof_receiver *early = vcs_proof_receiver_new();
        ASSERT(early != NULL);
        ASSERT(phc_sync_one_into(early, cp_a, a[0]));
        ASSERT(!vcs_proof_receiver_rebuild_bounded(
            early, store, VCS_PACKAGE_STORE_PAGE_MAX, &tickets, &cps,
            &skipped));
        ASSERT(!vcs_proof_receiver_issuer_equivocating(early, g_h.pub[PTF_A]));
        vcs_proof_receiver_free(early);
        vcs_package_store_close(store);
        test_rm_rf(dir);
    } TEST_END
    return failures;
}

/* ── compaction never erases signed fork evidence ───────────────────── */

/* A's second ticket at sequence 0 sorts below every
 * honest root, so root-order eviction would take it first. */
static bool phc_lowest_fork(const uint8_t (*honest)[32], size_t count,
                            uint8_t forked[VCS_PROOF_TICKET_WIRE_BYTES],
                            uint8_t forked_root[32])
{
    for (uint64_t i = 0; i < 4096u; i++) {
        char unit[48];
        snprintf(unit, sizeof(unit), "unit/fork/%llu", (unsigned long long)i);
        if (!phc_fork_ticket(unit, forked) ||
            !vcs_blob_root(forked, VCS_PROOF_TICKET_WIRE_BYTES, forked_root))
            return false;
        bool lowest = true;
        for (size_t h = 0; h < count; h++)
            if (memcmp(forked_root, honest[h], 32) >= 0) lowest = false;
        if (lowest) return true;
    }
    return false;
}

static int phc_case_evicted_fork_kept(void)
{
    int failures = 0;
    TEST_CASE("proof_history: an evicted-first signed fork survives restart") {
        ASSERT(phc_fresh());
        uint8_t a[1][VCS_PROOF_TICKET_WIRE_BYTES];
        uint8_t b[1][VCS_PROOF_TICKET_WIRE_BYTES];
        ASSERT(ptf_emit(&g_h, PTF_A, &g_h.base, ptf_pass(), a[0], NULL));
        ASSERT(ptf_emit(&g_h, PTF_B, &g_h.base, ptf_pass(), b[0], NULL));
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "proof_history", "evictfork");
        struct vcs_package_store *store = vcs_package_store_open(dir, PHC_QUOTA);
        ASSERT(store != NULL);
        uint8_t cp_a[VCS_PROOF_CHECKPOINT_WIRE_BYTES];
        uint8_t cp_b[VCS_PROOF_CHECKPOINT_WIRE_BYTES];
        ASSERT(phc_store_log(store, PTF_A, a, 1, 52, cp_a));
        ASSERT(phc_store_log(store, PTF_B, b, 1, 53, cp_b));
        uint8_t honest[4][32];
        ASSERT(vcs_blob_root(a[0], sizeof(a[0]), honest[0]));
        ASSERT(vcs_blob_root(b[0], sizeof(b[0]), honest[1]));
        ASSERT(vcs_blob_root(cp_a, sizeof(cp_a), honest[2]));
        ASSERT(vcs_blob_root(cp_b, sizeof(cp_b), honest[3]));
        uint8_t forked[VCS_PROOF_TICKET_WIRE_BYTES], forked_root[32];
        ASSERT(phc_lowest_fork((const uint8_t (*)[32])honest, 4, forked,
                               forked_root));
        ASSERT(phc_put(store, forked, sizeof(forked), NULL));
        const size_t rows = 64u;
        struct vcs_proof_receiver *rx = phc_rebuilt(store, rows);
        ASSERT(rx != NULL);
        ASSERT(vcs_proof_receiver_issuer_equivocating(rx, g_h.pub[PTF_A]));
        struct vcs_proof_ticket_class cls[PHC_CAP];
        struct vcs_proof_reuse_decision d;
        ASSERT(phc_decide(rx, &g_h.base, NULL, cls, &d));
        ASSERT(d.outcome != VCS_PROOF_REUSE_HIT_PASS);
        vcs_proof_receiver_free(rx);
        vcs_package_store_close(store);
        /* Compaction: the node runs near its quota and an unrelated blob of
         * the same size (anyone may write one) makes the store evict. */
        store = vcs_package_store_open(dir, PHC_QUOTA);
        ASSERT(store != NULL);
        uint64_t rare = vcs_package_store_pool_usage(
            store, VCS_PACKAGE_STORE_POOL_RARE);
        /* A quota that still holds what is pinned: pins never make room. */
        uint64_t tight = (rare / 3u) * 10u + 10u;
        if (tight < phc_pins(store) * 5u + 10u)
            tight = phc_pins(store) * 5u + 10u;
        vcs_package_store_close(store);
        store = vcs_package_store_open(dir, tight);
        ASSERT(store != NULL);
        uint8_t junk[VCS_PROOF_TICKET_WIRE_BYTES];
        memset(junk, 0x5a, sizeof(junk));
        ASSERT(phc_put(store, junk, sizeof(junk), NULL));
        uint8_t got[VCS_PROOF_TICKET_WIRE_BYTES + 1u];
        size_t got_len = 0;
        int evicted = 0;
        for (int h = 0; h < 4; h++)
            if (vcs_blob_get_from(store, honest[h], got, sizeof(got),
                                  &got_len) == VCS_BLOB_ERR_ABSENT)
                evicted++;
        ASSERT(evicted > 0);
        vcs_package_store_close(store);
        /* Restart: the fork is still known, or the rebuild refuses. */
        store = vcs_package_store_open(dir, PHC_QUOTA);
        ASSERT(store != NULL);
        rx = phc_rebuilt(store, rows);
        ASSERT(rx == NULL ||
               vcs_proof_receiver_issuer_equivocating(rx, g_h.pub[PTF_A]));
        ASSERT(rx == NULL || !phc_decide(rx, &g_h.base, NULL, cls, &d) ||
               d.outcome != VCS_PROOF_REUSE_HIT_PASS);
        vcs_proof_receiver_free(rx);
        /* The evidence itself is what survived: both signed tickets at A's
         * sequence 0 are pinned, nothing else is. */
        ASSERT_EQ(vcs_blob_get_from(store, forked_root, got, sizeof(got),
                                    &got_len), VCS_BLOB_OK);
        ASSERT(phc_pinned(store, forked, sizeof(forked)));
        ASSERT(phc_pinned(store, a[0], sizeof(a[0])));
        ASSERT_EQ(phc_pins(store), (uint64_t)(2u * VCS_PROOF_TICKET_WIRE_BYTES));
        vcs_package_store_close(store);
        test_rm_rf(dir);
    } TEST_END
    return failures;
}

static int phc_count_pinned(struct vcs_package_store *store,
                            const uint8_t (*wires)[VCS_PROOF_TICKET_WIRE_BYTES],
                            size_t count)
{
    int pinned = 0;
    for (size_t i = 0; i < count; i++)
        if (phc_pinned(store, wires[i], VCS_PROOF_TICKET_WIRE_BYTES)) pinned++;
    return pinned;
}

static int phc_case_fork_evidence_bounded(void)
{
    int failures = 0;
    TEST_CASE("proof_history: one signed evidence pair per issuer is pinned") {
        ASSERT(phc_fresh());
        uint8_t a[3][VCS_PROOF_TICKET_WIRE_BYTES];
        uint8_t b[1][VCS_PROOF_TICKET_WIRE_BYTES];
        ASSERT(ptf_emit(&g_h, PTF_A, &g_h.base, ptf_pass(), a[0], NULL));
        ASSERT(ptf_emit(&g_h, PTF_B, &g_h.base, ptf_pass(), b[0], NULL));
        /* Two more histories from A's key: three tickets at sequence 0. */
        ASSERT(phc_fork_ticket("unit/fork/one", a[1]));
        ASSERT(phc_fork_ticket("unit/fork/two", a[2]));
        /* A forged third: A's name and sequence, not A's signature. */
        uint8_t forged[VCS_PROOF_TICKET_WIRE_BYTES];
        ASSERT(phc_fork_ticket("unit/fork/forged", forged));
        forged[sizeof(forged) - 1u] ^= 0x01u;
        struct vcs_proof_ticket_v1 t;
        ASSERT(vcs_proof_ticket_decode(forged, sizeof(forged), &t));
        ASSERT(!vcs_proof_ticket_signature_valid(&t));

        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "proof_history", "pinbound");
        struct vcs_package_store *store = vcs_package_store_open(dir, PHC_QUOTA);
        ASSERT(store != NULL);
        uint8_t cp_a[VCS_PROOF_CHECKPOINT_WIRE_BYTES];
        uint8_t cp_b[VCS_PROOF_CHECKPOINT_WIRE_BYTES];
        ASSERT(phc_store_log(store, PTF_A, a, 1, 54, cp_a));
        ASSERT(phc_store_log(store, PTF_B, b, 1, 55, cp_b));
        ASSERT(phc_put(store, a[1], sizeof(a[1]), NULL));
        ASSERT(phc_put(store, a[2], sizeof(a[2]), NULL));
        ASSERT(phc_put(store, forged, sizeof(forged), NULL));
        const size_t rows = 64u;
        const uint64_t pair = 2u * VCS_PROOF_TICKET_WIRE_BYTES;
        for (int round = 0; round < 2; round++) {
            struct vcs_proof_receiver *rx = phc_rebuilt(store, rows);
            ASSERT(rx != NULL);
            ASSERT(vcs_proof_receiver_issuer_equivocating(rx, g_h.pub[PTF_A]));
            ASSERT(!vcs_proof_receiver_issuer_equivocating(rx, g_h.pub[PTF_B]));
            vcs_proof_receiver_free(rx);
            /* Exactly two of A's three signed tickets, on every rebuild. */
            ASSERT_EQ(phc_count_pinned(store, (const uint8_t (*)
                          [VCS_PROOF_TICKET_WIRE_BYTES])a, 3), 2);
            ASSERT_EQ(phc_pins(store), pair);
            ASSERT(!phc_pinned(store, forged, sizeof(forged)));
            ASSERT(!phc_pinned(store, b[0], sizeof(b[0])));
            ASSERT(!phc_pinned(store, cp_a, sizeof(cp_a)));
            ASSERT(!phc_pinned(store, cp_b, sizeof(cp_b)));
        }
        vcs_package_store_close(store);

        /* Compaction drops A's honest checkpoint. The restarted rebuild
         * re-derives the fork from the pinned pair alone. */
        ASSERT(phc_compact(dir, cp_a, sizeof(cp_a), 0x3c));
        store = vcs_package_store_open(dir, PHC_QUOTA);
        ASSERT(store != NULL);
        struct vcs_proof_receiver *rx = phc_rebuilt(store, rows);
        ASSERT(rx != NULL);
        ASSERT(vcs_proof_receiver_issuer_equivocating(rx, g_h.pub[PTF_A]));
        struct vcs_proof_ticket_class cls[PHC_CAP];
        struct vcs_proof_reuse_decision d;
        ASSERT(phc_decide(rx, &g_h.base, NULL, cls, &d));
        ASSERT_EQ(d.outcome, VCS_PROOF_REUSE_MISS);
        ASSERT_STR_EQ(d.reason, VCS_PROOF_REUSE_WHY_QUORUM);
        ASSERT_STR_EQ(phc_reason_of(cls, d.tickets_seen, PTF_B),
                      VCS_PROOF_TICKET_ELIGIBLE);
        vcs_proof_receiver_free(rx);
        ASSERT_EQ(phc_pins(store), pair);
        vcs_package_store_close(store);
        test_rm_rf(dir);
    } TEST_END
    return failures;
}

/* Two checkpoints under A's key both claim to be A's first: no two tickets
 * conflict, so the evidence is the pair of signed checkpoints. */
static int phc_case_checkpoint_fork_pinned(void)
{
    int failures = 0;
    TEST_CASE("proof_history: a signed checkpoint fork pins both checkpoints") {
        ASSERT(phc_fresh());
        struct vcs_component_proof_key_v1 second;
        phc_key("unit/second", &second);
        uint8_t a[2][VCS_PROOF_TICKET_WIRE_BYTES];
        uint8_t cp_one[VCS_PROOF_CHECKPOINT_WIRE_BYTES];
        uint8_t cp_two[VCS_PROOF_CHECKPOINT_WIRE_BYTES];
        ASSERT(ptf_emit(&g_h, PTF_A, &g_h.base, ptf_pass(), a[0], NULL));
        ASSERT(vcs_proof_issuer_log_checkpoint(g_h.logs[PTF_A], 56, cp_one));
        ASSERT(ptf_emit(&g_h, PTF_A, &second, ptf_pass(), a[1], NULL));
        struct vcs_proof_issuer_log *again =
            vcs_proof_issuer_log_new(g_h.seed[PTF_A]);
        ASSERT(again != NULL);
        bool same = true;
        for (int i = 0; i < 2 && same; i++) {
            struct vcs_proof_ticket_v1 t;
            uint8_t wire[VCS_PROOF_TICKET_WIRE_BYTES];
            same = vcs_proof_ticket_decode(a[i], sizeof(a[i]), &t) &&
                   vcs_proof_issuer_log_append(again, &t, wire) &&
                   memcmp(wire, a[i], sizeof(wire)) == 0;
        }
        same = same && vcs_proof_issuer_log_checkpoint(again, 57, cp_two);
        vcs_proof_issuer_log_free(again);
        ASSERT(same);

        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "proof_history", "cpfork");
        struct vcs_package_store *store = vcs_package_store_open(dir, PHC_QUOTA);
        ASSERT(store != NULL);
        ASSERT(phc_put(store, a[0], sizeof(a[0]), NULL));
        ASSERT(phc_put(store, a[1], sizeof(a[1]), NULL));
        ASSERT(phc_put(store, cp_one, sizeof(cp_one), NULL));
        ASSERT(phc_put(store, cp_two, sizeof(cp_two), NULL));
        struct vcs_proof_receiver *rx = phc_rebuilt(store, 64u);
        ASSERT(rx != NULL);
        ASSERT(vcs_proof_receiver_issuer_equivocating(rx, g_h.pub[PTF_A]));
        vcs_proof_receiver_free(rx);
        ASSERT(phc_pinned(store, cp_one, sizeof(cp_one)));
        ASSERT(phc_pinned(store, cp_two, sizeof(cp_two)));
        ASSERT(!phc_pinned(store, a[0], sizeof(a[0])));
        ASSERT(!phc_pinned(store, a[1], sizeof(a[1])));
        ASSERT_EQ(phc_pins(store),
                  (uint64_t)(2u * VCS_PROOF_CHECKPOINT_WIRE_BYTES));
        vcs_package_store_close(store);
        store = vcs_package_store_open(dir, PHC_QUOTA);
        ASSERT(store != NULL);
        rx = phc_rebuilt(store, 64u);
        ASSERT(rx != NULL);
        ASSERT(vcs_proof_receiver_issuer_equivocating(rx, g_h.pub[PTF_A]));
        vcs_proof_receiver_free(rx);
        vcs_package_store_close(store);
        test_rm_rf(dir);
    } TEST_END
    return failures;
}

/* ── compaction of eligible history loses reuse, never truth ────────── */

static int phc_hits(const struct vcs_proof_receiver *rx,
                    const struct vcs_component_proof_key_v1 *keys, int count)
{
    int hits = 0;
    for (int i = 0; rx && i < count; i++) {
        struct vcs_proof_ticket_class cls[PHC_CAP];
        struct vcs_proof_reuse_decision d;
        if (phc_decide(rx, &keys[i], NULL, cls, &d) &&
            d.outcome == VCS_PROOF_REUSE_HIT_PASS)
            hits++;
    }
    return hits;
}

static int phc_case_evicted_history(void)
{
    int failures = 0;
    TEST_CASE("proof_history: compacted eligible history is a MISS or refusal") {
        ASSERT(phc_fresh());
        struct vcs_component_proof_key_v1 keys[2];
        keys[0] = g_h.base;
        phc_key("unit/second", &keys[1]);
        uint8_t a[2][VCS_PROOF_TICKET_WIRE_BYTES];
        uint8_t b[2][VCS_PROOF_TICKET_WIRE_BYTES];
        for (int i = 0; i < 2; i++) {
            ASSERT(ptf_emit(&g_h, PTF_A, &keys[i], ptf_pass(), a[i], NULL));
            ASSERT(ptf_emit(&g_h, PTF_B, &keys[i], ptf_pass(), b[i], NULL));
        }
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "proof_history", "evicthist");
        struct vcs_package_store *store = vcs_package_store_open(dir, PHC_QUOTA);
        ASSERT(store != NULL);
        uint8_t cp_a[VCS_PROOF_CHECKPOINT_WIRE_BYTES];
        uint8_t cp_b[VCS_PROOF_CHECKPOINT_WIRE_BYTES];
        ASSERT(phc_store_log(store, PTF_A, a, 2, 61, cp_a));
        ASSERT(phc_store_log(store, PTF_B, b, 2, 62, cp_b));
        struct vcs_proof_receiver *rx = phc_rebuilt(store, 64u);
        int before = phc_hits(rx, keys, 2);
        vcs_proof_receiver_free(rx);
        /* Remote PASS history is ordinary RARE content: nothing pins it. */
        ASSERT_EQ(phc_pins(store), (uint64_t)0);
        vcs_package_store_close(store);
        ASSERT_EQ(before, 2);

        /* B's only checkpoint is compacted: B's tickets are uncovered, the
         * rebuild still succeeds, and both keys fall to a MISS. */
        ASSERT(phc_compact(dir, cp_b, sizeof(cp_b), 0x11));
        store = vcs_package_store_open(dir, PHC_QUOTA);
        ASSERT(store != NULL);
        rx = phc_rebuilt(store, 64u);
        ASSERT(rx != NULL);
        int after_checkpoint = phc_hits(rx, keys, 2);
        struct vcs_proof_ticket_class cls[PHC_CAP];
        struct vcs_proof_reuse_decision d;
        ASSERT(phc_decide(rx, &keys[0], NULL, cls, &d));
        ASSERT_EQ(d.outcome, VCS_PROOF_REUSE_MISS);
        ASSERT_STR_EQ(d.reason, VCS_PROOF_REUSE_WHY_QUORUM);
        vcs_proof_receiver_free(rx);
        vcs_package_store_close(store);
        ASSERT_EQ(after_checkpoint, 0);

        /* A covered ticket of A is compacted: A's checkpoint no longer has a
         * complete ticket branch, so A alone is isolated. Its surviving
         * ticket is named, never counted, and B stays uncovered. */
        ASSERT(phc_compact(dir, a[1], sizeof(a[1]), 0x22));
        store = vcs_package_store_open(dir, PHC_QUOTA);
        ASSERT(store != NULL);
        rx = phc_rebuilt(store, 64u);
        ASSERT(rx != NULL);
        int after_ticket = phc_hits(rx, keys, 2);
        ASSERT(vcs_proof_receiver_issuer_history_incomplete(rx,
                                                            g_h.pub[PTF_A]));
        ASSERT(!vcs_proof_receiver_issuer_history_incomplete(rx,
                                                             g_h.pub[PTF_B]));
        ASSERT(phc_decide(rx, &keys[0], NULL, cls, &d));
        ASSERT_EQ(d.outcome, VCS_PROOF_REUSE_MISS);
        ASSERT_STR_EQ(d.reason, VCS_PROOF_REUSE_WHY_HISTORY_INCOMPLETE);
        ASSERT_STR_EQ(phc_reason_of(cls, d.tickets_seen, PTF_A),
                      VCS_PROOF_TICKET_HISTORY_INCOMPLETE);
        ASSERT_STR_EQ(phc_reason_of(cls, d.tickets_seen, PTF_B),
                      VCS_PROOF_TICKET_NOT_CHECKPOINTED);
        vcs_proof_receiver_free(rx);
        vcs_package_store_close(store);
        ASSERT_EQ(after_ticket, 0);
        printf("\n  measured: HIT keys before=%d, after checkpoint evicted=%d, "
               "after covered ticket evicted=%d (A isolated, B uncovered)\n",
               before, after_checkpoint, after_ticket);
        test_rm_rf(dir);
    } TEST_END
    return failures;
}

/* ── only trusted issuers' evidence reaches the pins pool ───────────── */

/* A throwaway key signs two tickets at its sequence 0. */
static bool phc_throwaway_fork(uint32_t key, uint8_t pub[32],
                               uint8_t wires[2][VCS_PROOF_TICKET_WIRE_BYTES])
{
    uint8_t seed[32];
    memset(seed, 0, sizeof(seed));
    seed[0] = 0xa7;
    memcpy(seed + 1, &key, sizeof(key));
    bool ok = true;
    for (int side = 0; ok && side < 2; side++) {
        struct vcs_proof_issuer_log *log = vcs_proof_issuer_log_new(seed);
        uint8_t scratch[VCS_PROOF_TICKET_WIRE_BYTES];
        struct vcs_proof_ticket_v1 t;
        struct vcs_component_proof_key_v1 k;
        char unit[64];
        snprintf(unit, sizeof(unit), "unit/throwaway/%u/%d", key, side);
        phc_key(unit, &k);
        ok = log &&
             ptf_emit(&g_h, PTF_STRANGER, &k, ptf_pass(), scratch, NULL) &&
             vcs_proof_ticket_decode(scratch, sizeof(scratch), &t) &&
             vcs_proof_issuer_log_append(log, &t, wires[side]);
        if (ok) vcs_proof_issuer_log_pubkey(log, pub);
        vcs_proof_issuer_log_free(log);
    }
    return ok;
}

/* Throwaway keys with self-signed forks must not fill
 * the pins pool the store's own history needs. */
static int phc_case_stranger_forks_unpinned(void)
{
    int failures = 0;
    TEST_CASE("proof_history: stranger forks cannot starve the store's own pins") {
        ASSERT(phc_fresh());
        enum { PHC_STRANGERS = 4 };
        const uint64_t b = VCS_PROOF_TICKET_WIRE_BYTES;
        const uint64_t pins_budget = 2u * PHC_STRANGERS * b + b / 2u;
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "proof_history", "pinsdos");
        struct vcs_package_store *store =
            vcs_package_store_open(dir, pins_budget * 5u);
        ASSERT(store != NULL);
        uint8_t own[VCS_PROOF_TICKET_WIRE_BYTES], own_root[32];
        ASSERT(ptf_emit(&g_h, PTF_A, &g_h.base, ptf_pass(), own, NULL));
        ASSERT(phc_put(store, own, sizeof(own), own_root));
        uint8_t pubs[PHC_STRANGERS][32];
        for (uint32_t key = 0; key < PHC_STRANGERS; key++) {
            uint8_t wires[2][VCS_PROOF_TICKET_WIRE_BYTES];
            ASSERT(phc_throwaway_fork(key, pubs[key], wires));
            ASSERT(phc_put(store, wires[0], sizeof(wires[0]), NULL));
            ASSERT(phc_put(store, wires[1], sizeof(wires[1]), NULL));
        }
        struct vcs_proof_receiver *rx = phc_rebuilt(store, 64u);
        ASSERT(rx != NULL);
        /* Every fork is still known to this view; none of it is pinned. */
        for (uint32_t key = 0; key < PHC_STRANGERS; key++)
            ASSERT(vcs_proof_receiver_issuer_equivocating(rx, pubs[key]));
        vcs_proof_receiver_free(rx);
        ASSERT_EQ(phc_pins(store), (uint64_t)0);
        ASSERT_EQ(vcs_package_store_pin(store, own_root, true),
                  VCS_PACKAGE_STORE_OK);
        vcs_package_store_close(store);
        test_rm_rf(dir);
    } TEST_END
    return failures;
}

/* A trusted verifier's fork in a store rebuilt with no trusted set, or with
 * that verifier revoked, pins nothing; the view still knows the fork. */
static int phc_case_untrusted_fork_unpinned(void)
{
    int failures = 0;
    TEST_CASE("proof_history: no trusted set, or a revoked signer, pins nothing") {
        ASSERT(phc_fresh());
        uint8_t a[2][VCS_PROOF_TICKET_WIRE_BYTES];
        ASSERT(ptf_emit(&g_h, PTF_A, &g_h.base, ptf_pass(), a[0], NULL));
        ASSERT(phc_fork_ticket("unit/fork/untrusted", a[1]));
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "proof_history", "untrusted");
        struct vcs_package_store *store = vcs_package_store_open(dir, PHC_QUOTA);
        ASSERT(store != NULL);
        ASSERT(phc_put(store, a[0], sizeof(a[0]), NULL));
        ASSERT(phc_put(store, a[1], sizeof(a[1]), NULL));
        struct vcs_proof_receiver *rx = vcs_proof_receiver_new();
        ASSERT(rx != NULL);
        size_t tickets = 0, cps = 0, skipped = 0;
        ASSERT(vcs_proof_receiver_rebuild_bounded(rx, store, 64u, &tickets,
                                                  &cps, &skipped));
        ASSERT(vcs_proof_receiver_issuer_equivocating(rx, g_h.pub[PTF_A]));
        vcs_proof_receiver_free(rx);
        ASSERT_EQ(phc_pins(store), (uint64_t)0);
        /* A revoked verifier is no longer trusted: nothing is pinned. */
        struct vcs_proof_reuse_policy revoked = g_h.policy;
        revoked.revoked = (const uint8_t (*)[32])&g_h.pub[PTF_A];
        revoked.revoked_count = 1;
        rx = phc_rebuilt_under(store, 64u, &revoked);
        ASSERT(rx != NULL);
        ASSERT(vcs_proof_receiver_issuer_equivocating(rx, g_h.pub[PTF_A]));
        vcs_proof_receiver_free(rx);
        ASSERT_EQ(phc_pins(store), (uint64_t)0);
        /* The same fork under a policy that trusts A is pinned. */
        rx = phc_rebuilt(store, 64u);
        ASSERT(rx != NULL);
        vcs_proof_receiver_free(rx);
        ASSERT(phc_pinned(store, a[0], sizeof(a[0])));
        ASSERT(phc_pinned(store, a[1], sizeof(a[1])));
        ASSERT_EQ(phc_pins(store), (uint64_t)(2u * VCS_PROOF_TICKET_WIRE_BYTES));
        vcs_package_store_close(store);
        test_rm_rf(dir);
    } TEST_END
    return failures;
}

/* A pinned checkpoint pair whose parent checkpoint is later
 * compacted is still a known fork, or the rebuild refuses. */
static int phc_case_cp_pair_parent_evicted(void)
{
    int failures = 0;
    TEST_CASE("proof_history: a pinned checkpoint pair without its parent never trusts") {
        ASSERT(phc_fresh());
        struct vcs_component_proof_key_v1 second;
        phc_key("unit/second", &second);
        uint8_t a[2][VCS_PROOF_TICKET_WIRE_BYTES];
        uint8_t cp1[VCS_PROOF_CHECKPOINT_WIRE_BYTES];
        uint8_t cp2a[VCS_PROOF_CHECKPOINT_WIRE_BYTES];
        uint8_t cp2b[VCS_PROOF_CHECKPOINT_WIRE_BYTES];
        uint8_t again_cp1[VCS_PROOF_CHECKPOINT_WIRE_BYTES];
        ASSERT(ptf_emit(&g_h, PTF_A, &g_h.base, ptf_pass(), a[0], NULL));
        ASSERT(vcs_proof_issuer_log_checkpoint(g_h.logs[PTF_A], 70, cp1));
        ASSERT(ptf_emit(&g_h, PTF_A, &second, ptf_pass(), a[1], NULL));
        ASSERT(vcs_proof_issuer_log_checkpoint(g_h.logs[PTF_A], 71, cp2a));
        struct vcs_proof_issuer_log *again =
            vcs_proof_issuer_log_new(g_h.seed[PTF_A]);
        ASSERT(again != NULL);
        struct vcs_proof_ticket_v1 t;
        uint8_t wire[VCS_PROOF_TICKET_WIRE_BYTES];
        bool same = vcs_proof_ticket_decode(a[0], sizeof(a[0]), &t) &&
                    vcs_proof_issuer_log_append(again, &t, wire) &&
                    vcs_proof_issuer_log_checkpoint(again, 70, again_cp1) &&
                    memcmp(again_cp1, cp1, sizeof(cp1)) == 0 &&
                    vcs_proof_ticket_decode(a[1], sizeof(a[1]), &t) &&
                    vcs_proof_issuer_log_append(again, &t, wire) &&
                    vcs_proof_issuer_log_checkpoint(again, 72, cp2b);
        vcs_proof_issuer_log_free(again);
        ASSERT(same);
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "proof_history", "cpparent");
        struct vcs_package_store *store = vcs_package_store_open(dir, PHC_QUOTA);
        ASSERT(store != NULL);
        ASSERT(phc_put(store, a[0], sizeof(a[0]), NULL));
        ASSERT(phc_put(store, a[1], sizeof(a[1]), NULL));
        ASSERT(phc_put(store, cp1, sizeof(cp1), NULL));
        ASSERT(phc_put(store, cp2a, sizeof(cp2a), NULL));
        ASSERT(phc_put(store, cp2b, sizeof(cp2b), NULL));
        struct vcs_proof_receiver *rx = phc_rebuilt(store, 64u);
        ASSERT(rx != NULL);
        ASSERT(vcs_proof_receiver_issuer_equivocating(rx, g_h.pub[PTF_A]));
        vcs_proof_receiver_free(rx);
        ASSERT(phc_pinned(store, cp2a, sizeof(cp2a)));
        ASSERT(phc_pinned(store, cp2b, sizeof(cp2b)));
        ASSERT(!phc_pinned(store, cp1, sizeof(cp1)));
        vcs_package_store_close(store);
        ASSERT(phc_compact(dir, cp1, sizeof(cp1), 0x33));
        store = vcs_package_store_open(dir, PHC_QUOTA);
        ASSERT(store != NULL);
        rx = phc_rebuilt(store, 64u);
        ASSERT(rx != NULL);
        ASSERT(vcs_proof_receiver_issuer_equivocating(rx, g_h.pub[PTF_A]));
        vcs_proof_receiver_free(rx);
        vcs_package_store_close(store);
        test_rm_rf(dir);
    } TEST_END
    return failures;
}

/* A revoked verifier's checkpoint-only fork (two first checkpoints under
 * A's key) is still detected when its branches are not replayed, and pins
 * nothing; neither does a verifier entry one bit away from A's key. */
static int phc_case_untrusted_cp_fork_seen(void)
{
    int failures = 0;
    TEST_CASE("proof_history: an untrusted checkpoint-only fork is still seen") {
        ASSERT(phc_fresh());
        struct vcs_component_proof_key_v1 second;
        phc_key("unit/second", &second);
        uint8_t a[2][VCS_PROOF_TICKET_WIRE_BYTES];
        uint8_t cp_one[VCS_PROOF_CHECKPOINT_WIRE_BYTES];
        uint8_t cp_two[VCS_PROOF_CHECKPOINT_WIRE_BYTES];
        ASSERT(ptf_emit(&g_h, PTF_A, &g_h.base, ptf_pass(), a[0], NULL));
        ASSERT(vcs_proof_issuer_log_checkpoint(g_h.logs[PTF_A], 56, cp_one));
        ASSERT(ptf_emit(&g_h, PTF_A, &second, ptf_pass(), a[1], NULL));
        struct vcs_proof_issuer_log *again =
            vcs_proof_issuer_log_new(g_h.seed[PTF_A]);
        ASSERT(again != NULL);
        bool same = true;
        for (int i = 0; i < 2 && same; i++) {
            struct vcs_proof_ticket_v1 t;
            uint8_t wire[VCS_PROOF_TICKET_WIRE_BYTES];
            same = vcs_proof_ticket_decode(a[i], sizeof(a[i]), &t) &&
                   vcs_proof_issuer_log_append(again, &t, wire) &&
                   memcmp(wire, a[i], sizeof(wire)) == 0;
        }
        same = same && vcs_proof_issuer_log_checkpoint(again, 57, cp_two);
        vcs_proof_issuer_log_free(again);
        ASSERT(same);
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "proof_history", "cpforkseen");
        struct vcs_package_store *store = vcs_package_store_open(dir, PHC_QUOTA);
        ASSERT(store != NULL);
        ASSERT(phc_put(store, a[0], sizeof(a[0]), NULL));
        ASSERT(phc_put(store, a[1], sizeof(a[1]), NULL));
        ASSERT(phc_put(store, cp_one, sizeof(cp_one), NULL));
        ASSERT(phc_put(store, cp_two, sizeof(cp_two), NULL));
        struct vcs_proof_reuse_policy revoked = g_h.policy;
        revoked.revoked = (const uint8_t (*)[32])&g_h.pub[PTF_A];
        revoked.revoked_count = 1;
        struct vcs_proof_receiver *rx = phc_rebuilt_under(store, 64u, &revoked);
        ASSERT(rx != NULL);
        ASSERT(vcs_proof_receiver_issuer_equivocating(rx, g_h.pub[PTF_A]));
        vcs_proof_receiver_free(rx);
        ASSERT_EQ(phc_pins(store), (uint64_t)0);
        uint8_t near[1][32];
        memcpy(near[0], g_h.pub[PTF_A], 32);
        near[0][31] ^= 0x01;
        struct vcs_proof_reuse_policy near_policy = g_h.policy;
        near_policy.verifiers = (const uint8_t (*)[32])near;
        near_policy.verifier_count = 1;
        rx = phc_rebuilt_under(store, 64u, &near_policy);
        ASSERT(rx != NULL);
        ASSERT(vcs_proof_receiver_issuer_equivocating(rx, g_h.pub[PTF_A]));
        vcs_proof_receiver_free(rx);
        ASSERT_EQ(phc_pins(store), (uint64_t)0);
        rx = phc_rebuilt(store, 64u);
        ASSERT(rx != NULL);
        ASSERT(vcs_proof_receiver_issuer_equivocating(rx, g_h.pub[PTF_A]));
        vcs_proof_receiver_free(rx);
        ASSERT_EQ(phc_pins(store),
                  (uint64_t)(2u * VCS_PROOF_CHECKPOINT_WIRE_BYTES));
        vcs_package_store_close(store);
        test_rm_rf(dir);
    } TEST_END
    return failures;
}

int ptf_history_cases(void)
{
    int failures = 0;
    failures += phc_case_stranger_forks_unpinned();
    failures += phc_case_untrusted_fork_unpinned();
    failures += phc_case_untrusted_cp_fork_seen();
    failures += phc_case_evicted_fork_kept();
    failures += phc_case_fork_evidence_bounded();
    failures += phc_case_checkpoint_fork_pinned();
    failures += phc_case_cp_pair_parent_evicted();
    failures += phc_case_evicted_history();
    failures += phc_case_revoked_after_reopen();
    failures += phc_case_late_page_fork();
    ptf_free(&g_h);
    return failures;
}
