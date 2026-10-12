/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Issuer-log, equivocation, artifact-verification and CAS rebuild
 *          cases for the proof_ticket_reuse group. */

#include "test/test_core.h"

#include "test/proof_ticket_fixture.h"
#include "base/hex.h"
#include "base/safe_alloc.h"
#include "platform/time_compat.h"
#include "vcs/blob_store.h"
#include "vcs/package_manifest.h"
#include "vcs/package_store.h"
#include "../../../contexts/commons/modules/vcs/src/proof_reuse_priv.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#if !defined(_WIN32)
#include <sys/resource.h>
#endif

static struct ptf g_l;

#define PTL_CAP 16u
static bool ptl_rebuild(struct vcs_proof_receiver *r,
                        struct vcs_package_store *store, size_t max_rows,
                        size_t *tickets, size_t *checkpoints, size_t *skipped)
{
    return vcs_proof_receiver_rebuild_bounded(
        r, store, max_rows, tickets, checkpoints, skipped);
}

struct ptl_cost_sample {
    int64_t wall_before;
    clock_t cpu_before;
#if !defined(_WIN32)
    struct rusage usage_before;
    bool usage_started;
#endif
};

static struct ptl_cost_sample ptl_cost_begin(void)
{
    struct ptl_cost_sample sample = {
        .wall_before = platform_time_monotonic_us(), .cpu_before = clock(),
    };
#if !defined(_WIN32)
    sample.usage_started = getrusage(RUSAGE_SELF, &sample.usage_before) == 0;
#endif
    return sample;
}

static void ptl_cost_print(const char *phase, size_t listed, bool success,
                           const struct ptl_cost_sample *sample)
{
    uint64_t wall_us = (uint64_t)(platform_time_monotonic_us() -
                                  sample->wall_before);
    clock_t cpu_after = clock();
    uint64_t cpu_us = 0, rss_kib = 0, read_ops = 0, write_ops = 0;
    if (sample->cpu_before != (clock_t)-1 && cpu_after != (clock_t)-1 &&
        cpu_after >= sample->cpu_before)
        cpu_us = (uint64_t)((double)(cpu_after - sample->cpu_before) *
                            1000000.0 / (double)CLOCKS_PER_SEC);
#if !defined(_WIN32)
    struct rusage usage_after;
    if (sample->usage_started &&
        getrusage(RUSAGE_SELF, &usage_after) == 0) {
#if defined(__APPLE__)
        rss_kib = (uint64_t)usage_after.ru_maxrss / 1024u;
#else
        rss_kib = (uint64_t)usage_after.ru_maxrss;
#endif
        read_ops = (uint64_t)(usage_after.ru_inblock -
                              sample->usage_before.ru_inblock);
        write_ops = (uint64_t)(usage_after.ru_oublock -
                               sample->usage_before.ru_oublock);
    }
#endif
    printf("\nproof_store_boundary phase=%s listed=%zu success=%u "
           "wall_us=%llu cpu_us=%llu process_peak_rss_kib=%llu "
           "io_read_ops=%llu io_write_ops=%llu\n", phase, listed,
           success ? 1u : 0u, (unsigned long long)wall_us,
           (unsigned long long)cpu_us, (unsigned long long)rss_kib,
           (unsigned long long)read_ops, (unsigned long long)write_ops);
}

static bool ptl_fresh(void)
{
    ptf_free(&g_l);
    return ptf_init(&g_l);
}

static bool ptl_sync_wires(const uint8_t *cp, const uint8_t *const *delta,
                           size_t n, struct vcs_proof_sync_report *rep)
{
    size_t lens[8];
    for (size_t i = 0; i < n && i < 8; i++)
        lens[i] = VCS_PROOF_TICKET_WIRE_BYTES;
    return vcs_proof_receiver_sync(g_l.rx, cp, VCS_PROOF_CHECKPOINT_WIRE_BYTES,
                                   delta, lens, n, rep);
}

/* A forked log with A's own key: the same issuer signing a second history. */
static struct vcs_proof_issuer_log *ptl_fork(void)
{
    return vcs_proof_issuer_log_new(g_l.seed[PTF_A]);
}

static bool ptl_append(struct vcs_proof_issuer_log *log, struct ptf_spec s,
                       uint8_t wire[VCS_PROOF_TICKET_WIRE_BYTES])
{
    struct vcs_proof_ticket_v1 t;
    uint8_t tmp[VCS_PROOF_TICKET_WIRE_BYTES];
    /* Borrow the fixture's canonical fill through a throwaway emit. */
    if (!ptf_emit(&g_l, PTF_STRANGER, &g_l.base, s, tmp, NULL) ||
        !vcs_proof_ticket_decode(tmp, sizeof(tmp), &t))
        return false;
    return vcs_proof_issuer_log_append(log, &t, wire);
}

static int ptl_case_issuer_restore(void)
{
    int failures = 0;
    TEST_CASE("proof_ticket: issuer resumes only from complete exact head") {
        ASSERT(ptl_fresh());
        uint8_t first[VCS_PROOF_TICKET_WIRE_BYTES];
        uint8_t second[VCS_PROOF_TICKET_WIRE_BYTES];
        uint8_t next[VCS_PROOF_TICKET_WIRE_BYTES];
        uint8_t cp[VCS_PROOF_CHECKPOINT_WIRE_BYTES];
        uint8_t next_cp[VCS_PROOF_CHECKPOINT_WIRE_BYTES];
        uint8_t head_root[VCS_PROOF_ROOT_BYTES];
        ASSERT(ptf_emit(&g_l, PTF_A, &g_l.base, ptf_pass(), first, NULL));
        ASSERT(ptf_emit(&g_l, PTF_A, &g_l.base, ptf_fail(), second, NULL));
        ASSERT(vcs_proof_issuer_log_checkpoint(g_l.logs[PTF_A], 11, cp));
        ASSERT(vcs_proof_checkpoint_root(cp, sizeof(cp), head_root));
        const uint8_t *wires[] = {first, second};
        size_t lens[] = {sizeof(first), sizeof(second)};
        struct vcs_proof_issuer_log *restored =
            vcs_proof_issuer_log_restore(g_l.seed[PTF_A], wires, lens, 2, 2,
                                         cp, sizeof(cp), head_root);
        ASSERT(restored != NULL);
        ASSERT_EQ(vcs_proof_issuer_log_count(restored), (uint64_t)2);
        ASSERT(ptl_append(restored, ptf_pass(), next));
        struct vcs_proof_ticket_v1 decoded;
        ASSERT(vcs_proof_ticket_decode(next, sizeof(next), &decoded));
        ASSERT_EQ(decoded.issuer_seq, (uint64_t)2);
        ASSERT(vcs_proof_issuer_log_checkpoint(restored, 12, next_cp));
        struct vcs_proof_checkpoint_v1 next_head;
        ASSERT(vcs_proof_checkpoint_decode(next_cp, sizeof(next_cp),
                                           &next_head));
        ASSERT_EQ(memcmp(next_head.prev_checkpoint_root, head_root,
                         sizeof(head_root)), 0);
        vcs_proof_issuer_log_free(restored);

        uint8_t wrong_root[VCS_PROOF_ROOT_BYTES];
        memcpy(wrong_root, head_root, sizeof(wrong_root));
        wrong_root[0] ^= 1u;
        ASSERT(vcs_proof_issuer_log_restore(g_l.seed[PTF_A], wires, lens, 2,
                    2, cp, sizeof(cp), wrong_root) == NULL);
        ASSERT(vcs_proof_issuer_log_restore(g_l.seed[PTF_A], wires, lens, 1,
                    2, cp, sizeof(cp), head_root) == NULL);
        ASSERT(vcs_proof_issuer_log_restore(g_l.seed[PTF_A], wires, lens, 2,
                    1, cp, sizeof(cp), head_root) == NULL);
        const uint8_t *missing[] = {first, NULL};
        ASSERT(vcs_proof_issuer_log_restore(g_l.seed[PTF_A], missing, lens, 2,
                    2, cp, sizeof(cp), head_root) == NULL);
        const uint8_t *reordered[] = {second, first};
        ASSERT(vcs_proof_issuer_log_restore(g_l.seed[PTF_A], reordered, lens, 2,
                    2, cp, sizeof(cp), head_root) == NULL);
        size_t short_lens[] = {sizeof(first) - 1u, sizeof(second)};
        ASSERT(vcs_proof_issuer_log_restore(g_l.seed[PTF_A], wires,
                    short_lens, 2, 2, cp, sizeof(cp), head_root) == NULL);
        uint8_t tampered[VCS_PROOF_TICKET_WIRE_BYTES];
        memcpy(tampered, second, sizeof(tampered));
        tampered[sizeof(tampered) - 1u] ^= 1u;
        const uint8_t *bad_sig[] = {first, tampered};
        ASSERT(vcs_proof_issuer_log_restore(g_l.seed[PTF_A], bad_sig, lens, 2,
                    2, cp, sizeof(cp), head_root) == NULL);
        ASSERT(vcs_proof_issuer_log_restore(g_l.seed[PTF_B], wires, lens, 2,
                    2, cp, sizeof(cp), head_root) == NULL);
        ASSERT(vcs_proof_issuer_log_restore(g_l.seed[PTF_A], wires, lens, 2,
                    2, cp, sizeof(cp) - 1u, head_root) == NULL);
    } TEST_END
    return failures;
}

static int ptl_case_checkpoint_blob_head(void)
{
    int failures = 0;
    TEST_CASE("proof_ticket: checkpoint blob head resolves after restart") {
        ASSERT(ptl_fresh());
        ASSERT(ptf_emit(&g_l, PTF_A, &g_l.base, ptf_pass(), NULL, NULL));
        uint8_t cp[VCS_PROOF_CHECKPOINT_WIRE_BYTES];
        ASSERT(vcs_proof_issuer_log_checkpoint(g_l.logs[PTF_A], 17, cp));
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "proof_ticket", "headblob");
        struct vcs_package_store *store =
            vcs_package_store_open(dir, UINT64_C(8) * 1024 * 1024);
        ASSERT(store != NULL);
        uint8_t blob_root[32], expected[32];
        ASSERT(vcs_proof_ticket_store_put(store, cp, sizeof(cp), blob_root));
        ASSERT(vcs_proof_checkpoint_root(cp, sizeof(cp), expected));
        vcs_package_store_close(store);
        store = vcs_package_store_open(dir, UINT64_C(8) * 1024 * 1024);
        ASSERT(store != NULL);
        uint8_t wire[VCS_PROOF_CHECKPOINT_WIRE_BYTES], root[32];
        ASSERT(vcs_proof_checkpoint_store_load(store, blob_root,
                    g_l.pub[PTF_A], wire, root));
        ASSERT_EQ(memcmp(wire, cp, sizeof(cp)), 0);
        ASSERT_EQ(memcmp(root, expected, sizeof(root)), 0);
        uint8_t missing[32];
        memcpy(missing, blob_root, sizeof(missing));
        missing[0] ^= 1u;
        ASSERT(!vcs_proof_checkpoint_store_load(store, missing,
                    g_l.pub[PTF_A], wire, root));
        ASSERT(!vcs_proof_checkpoint_store_load(store, blob_root,
                    g_l.pub[PTF_B], wire, root));
        uint8_t invalid[VCS_PROOF_CHECKPOINT_WIRE_BYTES], bad_root[32];
        memcpy(invalid, cp, sizeof(invalid));
        invalid[sizeof(invalid) - 1u] ^= 1u;
        ASSERT(vcs_proof_ticket_store_put(store, invalid, sizeof(invalid),
                                          bad_root));
        ASSERT(!vcs_proof_checkpoint_store_load(store, bad_root,
                    g_l.pub[PTF_A], wire, root));
        vcs_package_store_close(store);
        test_rm_rf(dir);
    } TEST_END
    return failures;
}

static int ptl_case_store_issuer_restore(void)
{
    int failures = 0;
    TEST_CASE("proof_ticket: issuer store restart requires complete anchored catalog") {
        ASSERT(ptl_fresh());
        uint8_t first[VCS_PROOF_TICKET_WIRE_BYTES];
        uint8_t second[VCS_PROOF_TICKET_WIRE_BYTES];
        uint8_t cp[VCS_PROOF_CHECKPOINT_WIRE_BYTES];
        uint8_t next[VCS_PROOF_TICKET_WIRE_BYTES];
        uint8_t head[32], unused[32], absent[32];
        ASSERT(ptf_emit(&g_l, PTF_A, &g_l.base, ptf_pass(), first, NULL));
        ASSERT(ptf_emit(&g_l, PTF_A, &g_l.base, ptf_fail(), second, NULL));
        ASSERT(vcs_proof_issuer_log_checkpoint(g_l.logs[PTF_A], 29, cp));
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "proof_ticket", "issuerstore");
        struct vcs_package_store *store =
            vcs_package_store_open(dir, UINT64_C(8) * 1024 * 1024);
        ASSERT(store != NULL);
        ASSERT(vcs_proof_ticket_store_put(store, first, sizeof(first), unused));
        ASSERT(vcs_proof_ticket_store_put(store, cp, sizeof(cp), head));
        ASSERT(vcs_proof_issuer_log_restore_from_store(g_l.seed[PTF_A],
                    store, head, 3, 2) == NULL); /* referenced leaf absent */
        ASSERT(vcs_proof_ticket_store_put(store, second, sizeof(second), unused));
        vcs_package_store_close(store);
        store = vcs_package_store_open(dir, UINT64_C(8) * 1024 * 1024);
        ASSERT(store != NULL);
        ASSERT(vcs_proof_issuer_log_restore_from_store(g_l.seed[PTF_A],
                    store, head, 0, 2) == NULL);
        ASSERT(vcs_proof_issuer_log_restore_from_store(g_l.seed[PTF_A],
                    store, head, 2, 2) == NULL);
        ASSERT(vcs_proof_issuer_log_restore_from_store(g_l.seed[PTF_A],
                    store, head, 3, 1) == NULL);
        ASSERT(vcs_proof_issuer_log_restore_from_store(g_l.seed[PTF_A],
                    store, NULL, 3, 2) == NULL);
        memcpy(absent, head, sizeof(absent));
        absent[0] ^= 1u;
        ASSERT(vcs_proof_issuer_log_restore_from_store(g_l.seed[PTF_A],
                    store, absent, 3, 2) == NULL);
        struct vcs_proof_issuer_log *restored =
            vcs_proof_issuer_log_restore_from_store(g_l.seed[PTF_A],
                                                    store, head, 3, 2);
        ASSERT(restored != NULL);
        ASSERT_EQ(vcs_proof_issuer_log_count(restored), (uint64_t)2);
        ASSERT(ptl_append(restored, ptf_pass(), next));
        struct vcs_proof_ticket_v1 decoded;
        ASSERT(vcs_proof_ticket_decode(next, sizeof(next), &decoded));
        ASSERT_EQ(decoded.issuer_seq, (uint64_t)2);
        vcs_proof_issuer_log_free(restored);
        /* A signed ticket that escaped before the crash owns sequence 2.
         * Reissuing it would create an issuer fork even without a checkpoint. */
        ASSERT(ptl_append(g_l.logs[PTF_A], ptf_pass(), next));
        ASSERT(vcs_proof_ticket_store_put(store, next, sizeof(next), unused));
        ASSERT(vcs_proof_issuer_log_restore_from_store(g_l.seed[PTF_A],
                    store, head, 4, 3) == NULL);
        uint8_t later[VCS_PROOF_CHECKPOINT_WIRE_BYTES], later_head[32];
        ASSERT(vcs_proof_issuer_log_checkpoint(g_l.logs[PTF_A], 30, later));
        ASSERT(vcs_proof_ticket_store_put(store, later, sizeof(later),
                                          later_head));
        ASSERT(vcs_proof_issuer_log_restore_from_store(g_l.seed[PTF_A],
                    store, head, 5, 3) == NULL); /* stale durable head */
        restored = vcs_proof_issuer_log_restore_from_store(g_l.seed[PTF_A],
                                                            store, later_head,
                                                            5, 3);
        ASSERT(restored != NULL);
        ASSERT_EQ(vcs_proof_issuer_log_count(restored), (uint64_t)3);
        vcs_proof_issuer_log_free(restored);
        struct vcs_proof_issuer_log *fork = ptl_fork();
        ASSERT(fork != NULL);
        uint8_t forked[VCS_PROOF_TICKET_WIRE_BYTES];
        ASSERT(ptl_append(fork, ptf_fail(), forked)); /* signed seq 0 fork */
        vcs_proof_issuer_log_free(fork);
        ASSERT(vcs_proof_ticket_store_put(store, forked, sizeof(forked),
                                          unused));
        ASSERT(vcs_proof_issuer_log_restore_from_store(g_l.seed[PTF_A],
                    store, later_head, 6, 3) == NULL);
        vcs_package_store_close(store);
        test_rm_rf(dir);
    } TEST_END
    return failures;
}

static int ptl_case_store_issuer_missing_cas(void)
{
    int failures = 0;
    TEST_CASE("proof_ticket: issuer restart refuses missing ticket CAS bytes") {
        ASSERT(ptl_fresh());
        uint8_t ticket[VCS_PROOF_TICKET_WIRE_BYTES];
        uint8_t cp[VCS_PROOF_CHECKPOINT_WIRE_BYTES], head[32], root[32];
        ASSERT(ptf_emit(&g_l, PTF_A, &g_l.base, ptf_pass(), ticket, NULL));
        ASSERT(vcs_proof_issuer_log_checkpoint(g_l.logs[PTF_A], 31, cp));
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "proof_ticket", "issuercas");
        struct vcs_package_store *store =
            vcs_package_store_open(dir, UINT64_C(8) * 1024 * 1024);
        ASSERT(store != NULL);
        ASSERT(vcs_proof_ticket_store_put(store, ticket, sizeof(ticket), root));
        ASSERT(vcs_proof_ticket_store_put(store, cp, sizeof(cp), head));
        uint8_t chunk[32];
        char hex[65], path[640];
        ASSERT(vcs_package_chunk_hash(ticket, sizeof(ticket), chunk));
        zcl_hex_encode(chunk, sizeof(chunk), hex);
        ASSERT(snprintf(path, sizeof(path), "%s/zcode/cas/sha3/%.2s/%s",
                        dir, hex, hex) < (int)sizeof(path));
        ASSERT(unlink(path) == 0);
        ASSERT(vcs_proof_issuer_log_restore_from_store(g_l.seed[PTF_A],
                    store, head, 2, 1) == NULL);
        vcs_package_store_close(store);
        test_rm_rf(dir);
    } TEST_END
    return failures;
}

static int ptl_case_catalog_budget(void)
{
    int failures = 0;
    TEST_CASE("proof_ticket: exhausted catalog budget retains old receiver") {
        ASSERT(ptl_fresh());
        uint8_t ticket[VCS_PROOF_TICKET_WIRE_BYTES];
        uint8_t cp[VCS_PROOF_CHECKPOINT_WIRE_BYTES], root[32];
        ASSERT(ptf_emit(&g_l, PTF_A, &g_l.base, ptf_pass(), ticket, NULL));
        ASSERT(vcs_proof_issuer_log_checkpoint(g_l.logs[PTF_A], 19, cp));
        struct vcs_proof_sync_report rep;
        const uint8_t *delta[] = {ticket};
        ASSERT(ptl_sync_wires(cp, delta, 1, &rep));
        ASSERT_EQ(vcs_proof_receiver_issuer_leaves(g_l.rx, g_l.pub[PTF_A]),
                  (uint64_t)1);
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "proof_ticket", "catalogcap");
        struct vcs_package_store *store =
            vcs_package_store_open(dir, UINT64_C(8) * 1024 * 1024);
        ASSERT(store != NULL);
        ASSERT(vcs_proof_ticket_store_put(store, ticket, sizeof(ticket), root));
        ASSERT(vcs_proof_ticket_store_put(store, cp, sizeof(cp), root));
        size_t tickets = 9, cps = 9, skipped = 9;
        ASSERT(!vcs_proof_receiver_rebuild_bounded(g_l.rx, store, 0,
                    &tickets, &cps, &skipped));
        ASSERT_EQ(tickets, (size_t)0);
        ASSERT_EQ(cps, (size_t)0);
        ASSERT_EQ(skipped, (size_t)0);
        ASSERT(!vcs_proof_receiver_rebuild_bounded(g_l.rx, store, 1,
                    &tickets, &cps, &skipped));
        ASSERT_EQ(tickets, (size_t)0);
        ASSERT_EQ(cps, (size_t)0);
        ASSERT_EQ(vcs_proof_receiver_issuer_leaves(g_l.rx, g_l.pub[PTF_A]),
                  (uint64_t)1);
        ASSERT(vcs_proof_receiver_rebuild_bounded(g_l.rx, store, 2,
                    &tickets, &cps, &skipped));
        ASSERT_EQ(tickets, (size_t)1);
        ASSERT_EQ(cps, (size_t)1);
        vcs_package_store_close(store);
        test_rm_rf(dir);
    } TEST_END
    return failures;
}

static int ptl_case_page_budget_conflict(void)
{
    int failures = 0;
    TEST_CASE("proof_ticket: conflict past page one cannot become a miss") {
        ASSERT(ptl_fresh());
        uint8_t pass[VCS_PROOF_TICKET_WIRE_BYTES];
        uint8_t fail[VCS_PROOF_TICKET_WIRE_BYTES];
        uint8_t cp_a[VCS_PROOF_CHECKPOINT_WIRE_BYTES];
        uint8_t cp_b[VCS_PROOF_CHECKPOINT_WIRE_BYTES];
        uint8_t pass_root[32], fail_root[32], root[32];
        ASSERT(ptf_emit(&g_l, PTF_A, &g_l.base, ptf_pass(), pass, NULL));
        ASSERT(ptf_emit(&g_l, PTF_B, &g_l.base, ptf_fail(), fail, NULL));
        ASSERT(vcs_proof_issuer_log_checkpoint(g_l.logs[PTF_A], 11, cp_a));
        ASSERT(vcs_proof_issuer_log_checkpoint(g_l.logs[PTF_B], 11, cp_b));
        struct vcs_proof_sync_report rep;
        const uint8_t *delta[] = {pass};
        ASSERT(ptl_sync_wires(cp_a, delta, 1, &rep));
        ASSERT_EQ(vcs_proof_receiver_ticket_count(g_l.rx), (size_t)1);
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "proof_ticket", "pageconflict");
        struct vcs_package_store *store =
            vcs_package_store_open(dir, UINT64_C(64) * 1024 * 1024);
        ASSERT(store != NULL);
        ASSERT(vcs_proof_ticket_store_put(store, pass, sizeof(pass),
                                          pass_root));
        ASSERT(vcs_proof_ticket_store_put(store, fail, sizeof(fail),
                                          fail_root));
        ASSERT(vcs_proof_ticket_store_put(store, cp_a, sizeof(cp_a), root));
        ASSERT(vcs_proof_ticket_store_put(store, cp_b, sizeof(cp_b), root));
        struct vcs_package_store_summary rows[VCS_PACKAGE_STORE_PAGE_MAX];
        struct vcs_package_store_page page;
        const uint8_t *late_root = memcmp(pass_root, fail_root, 32) > 0
                                 ? pass_root : fail_root;
        uint32_t filler = 0;
        struct ptl_cost_sample cost = ptl_cost_begin();
        for (uint32_t candidate = 0;
             candidate < 65536u && filler < VCS_PACKAGE_STORE_PAGE_MAX;
             candidate++) {
            uint8_t blob[4] = {(uint8_t)candidate,
                               (uint8_t)(candidate >> 8),
                               (uint8_t)(candidate >> 16),
                               (uint8_t)(candidate >> 24)};
            uint8_t candidate_root[32];
            ASSERT(vcs_blob_root(blob, sizeof(blob), candidate_root));
            if (memcmp(candidate_root, late_root, 32) >= 0) continue;
            ASSERT(vcs_proof_ticket_store_put(store, blob,
                                               sizeof(blob), root));
            ASSERT_EQ(memcmp(root, candidate_root, 32), 0);
            filler++;
        }
        ASSERT_EQ(filler, (uint32_t)VCS_PACKAGE_STORE_PAGE_MAX);
        ptl_cost_print("page_conflict_populate", (size_t)filler + 4u,
                       true, &cost);
        ASSERT_EQ(vcs_package_store_page_summaries(
                      store, NULL, VCS_PACKAGE_STORE_PAGE_MAX, 0,
                      rows, &page), VCS_PACKAGE_STORE_PAGE_OK);
        ASSERT_EQ(page.count, (size_t)VCS_PACKAGE_STORE_PAGE_MAX);
        ASSERT(page.has_more);
        ASSERT(memcmp(late_root, page.next_root, 32) > 0);
        size_t tickets = 9, cps = 9, skipped = 9;
        ASSERT(!vcs_proof_receiver_rebuild_bounded(g_l.rx, store,
                    VCS_PACKAGE_STORE_PAGE_MAX, &tickets, &cps, &skipped));
        ASSERT_EQ(tickets, (size_t)0);
        ASSERT_EQ(cps, (size_t)0);
        ASSERT_EQ(skipped, (size_t)0);
        ASSERT_EQ(vcs_proof_receiver_ticket_count(g_l.rx), (size_t)1);
        vcs_package_store_close(store);
        store = vcs_package_store_open(dir, UINT64_C(64) * 1024 * 1024);
        ASSERT(store != NULL);
        vcs_proof_receiver_free(g_l.rx);
        g_l.rx = vcs_proof_receiver_new();
        ASSERT(g_l.rx != NULL);
        cost = ptl_cost_begin();
        bool rebuilt = vcs_proof_receiver_rebuild_bounded(g_l.rx, store,
                    (size_t)filler + 4u, &tickets, &cps, &skipped);
        ptl_cost_print("page_conflict_rebuild", (size_t)filler + 4u,
                       rebuilt, &cost);
        ASSERT(rebuilt);
        ASSERT_EQ(tickets, (size_t)2);
        ASSERT_EQ(cps, (size_t)2);
        ASSERT_EQ(skipped, (size_t)filler);
        struct vcs_proof_ticket_class cls[PTL_CAP];
        struct vcs_proof_reuse_decision decision;
        ASSERT(ptf_decide(&g_l, &g_l.base, VCS_PROOF_ACTION_CHECK, NULL,
                          cls, PTL_CAP, &decision));
        ASSERT_EQ(decision.outcome, VCS_PROOF_REUSE_REFUSE);
        ASSERT_STR_EQ(decision.reason, VCS_PROOF_OBSERVATION_CONFLICT);
        ASSERT_EQ(decision.eligible_pass, (uint32_t)1);
        ASSERT_EQ(decision.eligible_fail, (uint32_t)1);
        vcs_package_store_close(store);
        test_rm_rf(dir);
    } TEST_END
    return failures;
}

static int ptl_case_same_count(void)
{
    int failures = 0;
    TEST_CASE("proof_ticket: two signed roots at one size -> equivocation") {
        ASSERT(ptl_fresh());
        struct vcs_proof_sync_report rep;
        ASSERT(ptf_emit(&g_l, PTF_A, &g_l.base, ptf_pass(), NULL, NULL));
        ASSERT(ptf_emit(&g_l, PTF_B, &g_l.base, ptf_pass(), NULL, NULL));
        ASSERT(ptf_sync(&g_l, PTF_A, 0, &rep));
        ASSERT(ptf_sync(&g_l, PTF_B, 0, &rep));
        struct vcs_proof_issuer_log *fork = ptl_fork();
        ASSERT(fork != NULL);
        uint8_t w[VCS_PROOF_TICKET_WIRE_BYTES], cp[VCS_PROOF_CHECKPOINT_WIRE_BYTES];
        bool ok = ptl_append(fork, ptf_fail(), w) &&
                  vcs_proof_issuer_log_checkpoint(fork, 5, cp);
        vcs_proof_issuer_log_free(fork);
        ASSERT(ok);
        ASSERT(ptl_sync_wires(cp, NULL, 0, &rep));
        ASSERT_EQ(rep.outcome, VCS_PROOF_SYNC_EQUIVOCATION);
        ASSERT(vcs_proof_receiver_issuer_equivocating(g_l.rx, g_l.pub[PTF_A]));
        ASSERT_EQ(vcs_proof_receiver_issuer_checkpoints(g_l.rx, g_l.pub[PTF_A]),
                  (size_t)2); /* both sides kept */
        struct vcs_proof_ticket_class cls[PTL_CAP];
        struct vcs_proof_reuse_decision d;
        ASSERT(ptf_decide(&g_l, &g_l.base, VCS_PROOF_ACTION_CHECK, NULL, cls,
                          PTL_CAP, &d));
        ASSERT_EQ(d.outcome, VCS_PROOF_REUSE_MISS);
        ASSERT_STR_EQ(cls[0].reason, VCS_PROOF_TICKET_EQUIVOCATION);
    } TEST_END
    return failures;
}

static int ptl_case_same_size_ancestry(void)
{
    int failures = 0;
    TEST_CASE("proof_ticket: same-size checkpoint ancestry survives rebuild") {
        ASSERT(ptl_fresh());
        uint8_t first[VCS_PROOF_TICKET_WIRE_BYTES];
        uint8_t second[VCS_PROOF_TICKET_WIRE_BYTES];
        uint8_t cp1[VCS_PROOF_CHECKPOINT_WIRE_BYTES];
        uint8_t cp2[VCS_PROOF_CHECKPOINT_WIRE_BYTES];
        uint8_t cp3[VCS_PROOF_CHECKPOINT_WIRE_BYTES], root[32];
        ASSERT(ptf_emit(&g_l, PTF_A, &g_l.base, ptf_pass(), first, NULL));
        ASSERT(vcs_proof_issuer_log_checkpoint(g_l.logs[PTF_A], 11, cp1));
        ASSERT(vcs_proof_issuer_log_checkpoint(g_l.logs[PTF_A], 12, cp2));
        ASSERT(ptf_emit(&g_l, PTF_A, &g_l.base, ptf_pass(), second, NULL));
        ASSERT(vcs_proof_issuer_log_checkpoint(g_l.logs[PTF_A], 13, cp3));
        struct vcs_proof_sync_report rep;
        const uint8_t *one[] = {first};
        const uint8_t *two[] = {second};
        ASSERT(ptl_sync_wires(cp1, one, 1, &rep));
        ASSERT_EQ(rep.outcome, VCS_PROOF_SYNC_ADVANCED);
        ASSERT(ptl_sync_wires(cp2, NULL, 0, &rep));
        ASSERT(rep.outcome == VCS_PROOF_SYNC_CURRENT ||
               rep.outcome == VCS_PROOF_SYNC_ADVANCED);
        ASSERT(ptl_sync_wires(cp3, two, 1, &rep));
        ASSERT_EQ(rep.outcome, VCS_PROOF_SYNC_ADVANCED);
        ASSERT_EQ(vcs_proof_receiver_issuer_checkpoints(g_l.rx, g_l.pub[PTF_A]),
                  (size_t)3);
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "proof_ticket", "sameleaf");
        struct vcs_package_store *store =
            vcs_package_store_open(dir, UINT64_C(8) * 1024 * 1024);
        ASSERT(store != NULL);
        ASSERT(vcs_proof_ticket_store_put(store, cp3, sizeof(cp3), root));
        ASSERT(vcs_proof_ticket_store_put(store, cp2, sizeof(cp2), root));
        ASSERT(vcs_proof_ticket_store_put(store, cp1, sizeof(cp1), root));
        ASSERT(vcs_proof_ticket_store_put(store, second, sizeof(second), root));
        ASSERT(vcs_proof_ticket_store_put(store, first, sizeof(first), root));
        size_t tickets = 0, cps = 0, skipped = 0;
        ASSERT(ptl_rebuild(g_l.rx, store, 5, &tickets, &cps,
                                          &skipped));
        ASSERT_EQ(cps, (size_t)3);
        ASSERT_EQ(vcs_proof_receiver_issuer_leaves(g_l.rx, g_l.pub[PTF_A]),
                  (uint64_t)2);
        uint8_t expected[32];
        ASSERT(vcs_proof_checkpoint_root(cp3, sizeof(cp3), expected));
        const struct pr_issuer *recovered =
            pr_issuer_find(g_l.rx, g_l.pub[PTF_A]);
        ASSERT(recovered != NULL);
        ASSERT(memcmp(recovered->last_root, expected, sizeof(expected)) == 0);
        vcs_package_store_close(store);
        test_rm_rf(dir);
    } TEST_END
    return failures;
}

static int ptl_case_late_same_size_fork(void)
{
    int failures = 0;
    TEST_CASE("proof_ticket: late same-size fork remains equivocation") {
        ASSERT(ptl_fresh());
        uint8_t first[VCS_PROOF_TICKET_WIRE_BYTES];
        uint8_t second[VCS_PROOF_TICKET_WIRE_BYTES];
        uint8_t cp1[VCS_PROOF_CHECKPOINT_WIRE_BYTES];
        uint8_t cp2[VCS_PROOF_CHECKPOINT_WIRE_BYTES];
        uint8_t cp3[VCS_PROOF_CHECKPOINT_WIRE_BYTES];
        uint8_t fork1[VCS_PROOF_CHECKPOINT_WIRE_BYTES];
        uint8_t fork2[VCS_PROOF_CHECKPOINT_WIRE_BYTES];
        ASSERT(ptf_emit(&g_l, PTF_A, &g_l.base, ptf_pass(), first, NULL));
        ASSERT(vcs_proof_issuer_log_checkpoint(g_l.logs[PTF_A], 11, cp1));
        ASSERT(vcs_proof_issuer_log_checkpoint(g_l.logs[PTF_A], 12, cp2));
        struct vcs_proof_issuer_log *fork = ptl_fork();
        ASSERT(fork != NULL);
        struct vcs_proof_ticket_v1 ticket;
        uint8_t replay[VCS_PROOF_TICKET_WIRE_BYTES];
        ASSERT(vcs_proof_ticket_decode(first, sizeof(first), &ticket));
        ASSERT(vcs_proof_issuer_log_append(fork, &ticket, replay));
        ASSERT(vcs_proof_issuer_log_checkpoint(fork, 11, fork1));
        ASSERT(memcmp(cp1, fork1, sizeof(cp1)) == 0);
        ASSERT(vcs_proof_issuer_log_checkpoint(fork, 14, fork2));
        vcs_proof_issuer_log_free(fork);
        ASSERT(ptf_emit(&g_l, PTF_A, &g_l.base, ptf_pass(), second, NULL));
        ASSERT(vcs_proof_issuer_log_checkpoint(g_l.logs[PTF_A], 13, cp3));
        struct vcs_proof_sync_report rep;
        const uint8_t *one[] = {first}, *two[] = {second};
        ASSERT(ptl_sync_wires(cp1, one, 1, &rep));
        ASSERT(ptl_sync_wires(cp2, NULL, 0, &rep));
        ASSERT(ptl_sync_wires(cp3, two, 1, &rep));
        ASSERT(ptl_sync_wires(fork2, NULL, 0, &rep));
        ASSERT_EQ(rep.outcome, VCS_PROOF_SYNC_EQUIVOCATION);
        ASSERT(vcs_proof_receiver_issuer_equivocating(g_l.rx, g_l.pub[PTF_A]));
    } TEST_END
    return failures;
}

static int ptl_case_fork(void)
{
    int failures = 0;
    TEST_CASE("proof_ticket: second child of one checkpoint -> equivocation") {
        ASSERT(ptl_fresh());
        struct vcs_proof_sync_report rep;
        ASSERT(ptf_emit(&g_l, PTF_A, &g_l.base, ptf_pass(), NULL, NULL));
        ASSERT(ptf_sync(&g_l, PTF_A, 0, &rep));
        ASSERT(ptf_emit(&g_l, PTF_A, &g_l.base, ptf_pass(), NULL, NULL));
        ASSERT(ptf_sync(&g_l, PTF_A, 0, &rep));
        ASSERT_EQ(rep.outcome, VCS_PROOF_SYNC_ADVANCED);
        /* A fork whose first checkpoint names no predecessor, at 3 leaves:
         * it claims the same parent as the receiver's first checkpoint. */
        struct vcs_proof_issuer_log *fork = ptl_fork();
        ASSERT(fork != NULL);
        uint8_t w[3][VCS_PROOF_TICKET_WIRE_BYTES];
        uint8_t cp[VCS_PROOF_CHECKPOINT_WIRE_BYTES];
        bool ok = true;
        for (int i = 0; i < 3 && ok; i++) ok = ptl_append(fork, ptf_pass(), w[i]);
        ok = ok && vcs_proof_issuer_log_checkpoint(fork, 5, cp);
        vcs_proof_issuer_log_free(fork);
        ASSERT(ok);
        const uint8_t *delta[1] = {w[2]};
        ASSERT(ptl_sync_wires(cp, delta, 1, &rep));
        ASSERT_EQ(rep.outcome, VCS_PROOF_SYNC_EQUIVOCATION);
    } TEST_END
    return failures;
}

static int ptl_case_not_extension(void)
{
    int failures = 0;
    TEST_CASE("proof_ticket: signed delta that misses the root -> equivocation") {
        ASSERT(ptl_fresh());
        struct vcs_proof_issuer_log *fork = ptl_fork();
        ASSERT(fork != NULL);
        uint8_t w0[VCS_PROOF_TICKET_WIRE_BYTES], w1[sizeof(w0)], f1[sizeof(w0)];
        uint8_t cp1[VCS_PROOF_CHECKPOINT_WIRE_BYTES], cpf[sizeof(cp1)];
        uint8_t fcp1[sizeof(cp1)];
        struct vcs_proof_ticket_v1 t;
        struct ptf_spec later = ptf_pass();
        later.created = 1790000500u;
        bool ok = ptf_emit(&g_l, PTF_A, &g_l.base, ptf_pass(), w0, NULL) &&
                  vcs_proof_ticket_decode(w0, sizeof(w0), &t) &&
                  vcs_proof_issuer_log_append(fork, &t, w0) &&
                  vcs_proof_issuer_log_checkpoint(g_l.logs[PTF_A], 5, cp1) &&
                  vcs_proof_issuer_log_checkpoint(fork, 5, fcp1) &&
                  ptf_emit(&g_l, PTF_A, &g_l.base, ptf_pass(), w1, NULL) &&
                  ptl_append(fork, later, f1) &&
                  vcs_proof_issuer_log_checkpoint(fork, 6, cpf);
        vcs_proof_issuer_log_free(fork);
        ASSERT(ok);
        ASSERT(memcmp(cp1, fcp1, sizeof(cp1)) == 0); /* one shared prefix */
        struct vcs_proof_sync_report rep;
        const uint8_t *d0[1] = {w0}, *d1[1] = {w1};
        ASSERT(ptl_sync_wires(cp1, d0, 1, &rep));
        ASSERT_EQ(rep.outcome, VCS_PROOF_SYNC_ADVANCED);
        /* The fork's checkpoint plus A's genuinely signed seq-1 ticket. */
        ASSERT(ptl_sync_wires(cpf, d1, 1, &rep));
        ASSERT_EQ(rep.outcome, VCS_PROOF_SYNC_EQUIVOCATION);
    } TEST_END
    return failures;
}

static int ptl_case_delta_bytes(void)
{
    int failures = 0;
    TEST_CASE("proof_ticket: a resync moves only the new tickets") {
        ASSERT(ptl_fresh());
        struct vcs_proof_sync_report rep;
        for (int i = 0; i < 5; i++)
            ASSERT(ptf_emit(&g_l, PTF_A, &g_l.base, ptf_pass(), NULL, NULL));
        ASSERT(ptf_sync(&g_l, PTF_A, 0, &rep));
        ASSERT_EQ(rep.bytes, (uint64_t)(VCS_PROOF_CHECKPOINT_WIRE_BYTES +
                                        5u * VCS_PROOF_TICKET_WIRE_BYTES));
        ASSERT(ptf_emit(&g_l, PTF_A, &g_l.base, ptf_pass(), NULL, NULL));
        ASSERT(ptf_sync(&g_l, PTF_A, 0, &rep));
        ASSERT_EQ(rep.outcome, VCS_PROOF_SYNC_ADVANCED);
        ASSERT_EQ(rep.leaves_before, (uint64_t)5);
        ASSERT_EQ(rep.bytes, (uint64_t)(VCS_PROOF_CHECKPOINT_WIRE_BYTES +
                                        VCS_PROOF_TICKET_WIRE_BYTES));
    } TEST_END
    return failures;
}

static struct ptf_spec ptl_build(uint8_t salt)
{
    struct ptf_spec s = ptf_pass();
    s.action_class = VCS_PROOF_ACTION_BUILD;
    s.artifact_salt = salt;
    return s;
}

static bool ptl_build_quorum(uint8_t salt_b)
{
    struct vcs_proof_sync_report rep;
    return ptf_emit(&g_l, PTF_A, &g_l.base, ptl_build(0), NULL, NULL) &&
           ptf_emit(&g_l, PTF_B, &g_l.base, ptl_build(salt_b), NULL, NULL) &&
           ptf_sync(&g_l, PTF_A, 0, &rep) && ptf_sync(&g_l, PTF_B, 0, &rep);
}

static int ptl_case_artifact(void)
{
    int failures = 0;
    TEST_CASE("proof_ticket: build reuse re-hashes the artifact bytes") {
        ASSERT(ptl_fresh());
        ASSERT(ptl_build_quorum(0));
        struct vcs_proof_ticket_class cls[PTL_CAP];
        struct vcs_proof_reuse_decision d;
        ASSERT(ptf_decide(&g_l, &g_l.base, VCS_PROOF_ACTION_BUILD, NULL, cls,
                          PTL_CAP, &d));
        ASSERT_EQ(d.outcome, VCS_PROOF_REUSE_HIT_PASS);
        ASSERT(memcmp(d.artifact_root, cls[0].artifact_root, 32) == 0);
        g_l.tamper = true;
        memcpy(g_l.tamper_root, d.artifact_root, 32);
        ASSERT(ptf_decide(&g_l, &g_l.base, VCS_PROOF_ACTION_BUILD, NULL, cls,
                          PTL_CAP, &d));
        ASSERT_EQ(d.outcome, VCS_PROOF_REUSE_MISS);
        ASSERT_STR_EQ(d.reason, VCS_PROOF_REUSE_WHY_ARTIFACT_MISMATCH);
        ASSERT(d.false_hit_refused);
        g_l.tamper = false;
        size_t held = g_l.art_count;
        g_l.art_count = 0; /* the bytes are absent from the CAS */
        bool decided = ptf_decide(&g_l, &g_l.base, VCS_PROOF_ACTION_BUILD,
                                  NULL, cls, PTL_CAP, &d);
        g_l.art_count = held;
        ASSERT(decided);
        ASSERT_STR_EQ(d.reason, VCS_PROOF_REUSE_WHY_ARTIFACT_MISSING);
        /* The same obligation asked as a CHECK is another action class. */
        ASSERT(ptf_decide(&g_l, &g_l.base, VCS_PROOF_ACTION_CHECK, NULL, cls,
                          PTL_CAP, &d));
        ASSERT_STR_EQ(cls[0].reason, VCS_PROOF_TICKET_CLASS_MISMATCH);
    } TEST_END
    return failures;
}

static int ptl_case_output_conflict(void)
{
    int failures = 0;
    TEST_CASE("proof_ticket: two outputs for one build action -> conflict") {
        ASSERT(ptl_fresh());
        ASSERT(ptl_build_quorum(0x55));
        struct vcs_proof_ticket_class cls[PTL_CAP];
        struct vcs_proof_reuse_decision d;
        ASSERT(ptf_decide(&g_l, &g_l.base, VCS_PROOF_ACTION_BUILD, NULL, cls,
                          PTL_CAP, &d));
        ASSERT_EQ(d.outcome, VCS_PROOF_REUSE_REFUSE);
        ASSERT_STR_EQ(d.reason, VCS_PROOF_OBSERVATION_CONFLICT);
    } TEST_END
    return failures;
}

static bool ptl_store_logs(struct vcs_package_store *store)
{
    uint8_t root[32], pre[VCS_CPK_WIRE_BYTES];
    uint8_t cp[VCS_PROOF_CHECKPOINT_WIRE_BYTES];
    if (!vcs_component_proof_key_encode(&g_l.base, pre) ||
        !vcs_proof_ticket_store_put(store, pre, sizeof(pre), root))
        return false;
    for (int s = PTF_A; s <= PTF_B; s++) {
        struct vcs_proof_issuer_log *log = g_l.logs[s];
        for (uint64_t i = 0; i < vcs_proof_issuer_log_count(log); i++)
            if (!vcs_proof_ticket_store_put(store,
                                            vcs_proof_issuer_log_ticket(log, i),
                                            VCS_PROOF_TICKET_WIRE_BYTES, root))
                return false;
        if (!vcs_proof_issuer_log_checkpoint(log, 9, cp) ||
            !vcs_proof_ticket_store_put(store, cp, sizeof(cp), root))
            return false;
    }
    return true;
}

static int ptl_case_rebuild(void)
{
    int failures = 0;
    TEST_CASE("proof_ticket: receiver rebuilt from CAS blobs reaches HIT") {
        ASSERT(ptl_fresh());
        for (int s = PTF_A; s <= PTF_B; s++)
            ASSERT(ptf_emit(&g_l, s, &g_l.base, ptf_pass(), NULL, NULL));
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "proof_ticket", "cas");
        struct vcs_package_store *store =
            vcs_package_store_open(dir, UINT64_C(8) * 1024 * 1024);
        ASSERT(store != NULL);
        size_t tickets = 0, cps = 0, skipped = 0;
        bool ok = ptl_store_logs(store) &&
                  ptl_rebuild(g_l.rx, store, 5, &tickets, &cps,
                                             &skipped);
        vcs_package_store_close(store);
        test_rm_rf(dir);
        ASSERT(ok);
        ASSERT_EQ(tickets, (size_t)2);
        ASSERT_EQ(cps, (size_t)2);
        ASSERT_EQ(skipped, (size_t)1); /* the key preimage */
        struct vcs_proof_ticket_class cls[PTL_CAP];
        struct vcs_proof_reuse_decision d;
        ASSERT(ptf_decide(&g_l, &g_l.base, VCS_PROOF_ACTION_CHECK, NULL, cls,
                          PTL_CAP, &d));
        ASSERT_EQ(d.outcome, VCS_PROOF_REUSE_HIT_PASS);
    } TEST_END
    return failures;
}

static int ptl_case_empty_issuer_rebuild(void)
{
    int failures = 0;
    TEST_CASE("proof_ticket: refused sync adds no recovery obligation") {
        ASSERT(ptl_fresh());
        ASSERT(ptf_emit(&g_l, PTF_A, &g_l.base, ptf_pass(), NULL, NULL));
        uint8_t cp[VCS_PROOF_CHECKPOINT_WIRE_BYTES];
        ASSERT(vcs_proof_issuer_log_checkpoint(g_l.logs[PTF_A], 11, cp));
        struct vcs_proof_sync_report rep;
        ASSERT(ptl_sync_wires(cp, NULL, 0, &rep));
        ASSERT_EQ(rep.outcome, VCS_PROOF_SYNC_REFUSED);
        ASSERT_EQ(vcs_proof_receiver_issuer_checkpoints(g_l.rx,
                                                        g_l.pub[PTF_A]),
                  (size_t)0);
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "proof_ticket", "emptyissuer");
        struct vcs_package_store *store =
            vcs_package_store_open(dir, UINT64_C(8) * 1024 * 1024);
        ASSERT(store != NULL);
        size_t tickets = 0, cps = 0, skipped = 0;
        ASSERT(ptl_rebuild(g_l.rx, store, 1, &tickets, &cps,
                                          &skipped));
        ASSERT_EQ(tickets, (size_t)0);
        ASSERT_EQ(cps, (size_t)0);
        vcs_package_store_close(store);
        test_rm_rf(dir);
    } TEST_END
    return failures;
}

static int ptl_case_rebuild_missing_ticket(void)
{
    int failures = 0;
    TEST_CASE("proof_ticket: checkpoint missing its ticket keeps live state, isolates on restart") {
        ASSERT(ptl_fresh());
        uint8_t ticket[VCS_PROOF_TICKET_WIRE_BYTES];
        ASSERT(ptf_emit(&g_l, PTF_A, &g_l.base, ptf_pass(), ticket, NULL));
        uint8_t cp[VCS_PROOF_CHECKPOINT_WIRE_BYTES], root[32];
        ASSERT(vcs_proof_issuer_log_checkpoint(g_l.logs[PTF_A], 11, cp));
        struct vcs_proof_sync_report rep;
        const uint8_t *one[] = {ticket};
        ASSERT(ptl_sync_wires(cp, one, 1, &rep));
        ASSERT_EQ(vcs_proof_receiver_ticket_count(g_l.rx), (size_t)1);
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "proof_ticket", "missing");
        struct vcs_package_store *store =
            vcs_package_store_open(dir, UINT64_C(8) * 1024 * 1024);
        ASSERT(store != NULL);
        ASSERT(vcs_proof_ticket_store_put(store, cp, sizeof(cp), root));
        size_t tickets = 0, cps = 0, skipped = 0;
        /* The live receiver verified A itself: the store losing A's ticket
         * neither drops that ticket nor its coverage. */
        ASSERT(ptl_rebuild(g_l.rx, store, 1, &tickets, &cps, &skipped));
        ASSERT_EQ(tickets, (size_t)0);
        ASSERT_EQ(cps, (size_t)0);
        ASSERT_EQ(vcs_proof_receiver_issuer_leaves(g_l.rx, g_l.pub[PTF_A]),
                  (uint64_t)1);
        ASSERT_EQ(vcs_proof_receiver_ticket_count(g_l.rx), (size_t)1);
        ASSERT(!vcs_proof_receiver_issuer_history_incomplete(g_l.rx,
                                                             g_l.pub[PTF_A]));
        /* A restart has nothing verified to keep: A is isolated. */
        struct vcs_proof_receiver *fresh = vcs_proof_receiver_new();
        ASSERT(fresh != NULL);
        bool rebuilt = ptl_rebuild(fresh, store, 1, &tickets, &cps, &skipped);
        bool isolated = vcs_proof_receiver_issuer_history_incomplete(
            fresh, g_l.pub[PTF_A]);
        uint64_t leaves = vcs_proof_receiver_issuer_leaves(fresh,
                                                           g_l.pub[PTF_A]);
        vcs_proof_receiver_free(fresh);
        ASSERT(rebuilt);
        ASSERT(isolated);
        ASSERT_EQ(leaves, (uint64_t)0);
        vcs_package_store_close(store);
        test_rm_rf(dir);
    } TEST_END
    return failures;
}

static int ptl_case_rebuild_missing_chunk(void)
{
    int failures = 0;
    TEST_CASE("proof_ticket: listed proof blob with missing chunk refuses") {
        ASSERT(ptl_fresh());
        uint8_t ticket[VCS_PROOF_TICKET_WIRE_BYTES];
        uint8_t cp[VCS_PROOF_CHECKPOINT_WIRE_BYTES], root[32];
        ASSERT(ptf_emit(&g_l, PTF_A, &g_l.base, ptf_pass(), ticket, NULL));
        ASSERT(vcs_proof_issuer_log_checkpoint(g_l.logs[PTF_A], 11, cp));
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "proof_ticket", "lostchunk");
        struct vcs_package_store *store =
            vcs_package_store_open(dir, UINT64_C(8) * 1024 * 1024);
        ASSERT(store != NULL);
        ASSERT(vcs_proof_ticket_store_put(store, ticket, sizeof(ticket), root));
        ASSERT(vcs_proof_ticket_store_put(store, cp, sizeof(cp), root));
        uint8_t chunk[32];
        char hex[65], path[640];
        ASSERT(vcs_package_chunk_hash(ticket, sizeof(ticket), chunk));
        zcl_hex_encode(chunk, sizeof(chunk), hex);
        ASSERT(snprintf(path, sizeof(path), "%s/zcode/cas/sha3/%.2s/%s",
                        dir, hex, hex) < (int)sizeof(path));
        ASSERT(unlink(path) == 0);
        size_t tickets = 0, cps = 0, skipped = 0;
        ASSERT(!ptl_rebuild(g_l.rx, store, 2, &tickets, &cps,
                                           &skipped));
        ASSERT_EQ(vcs_proof_receiver_ticket_count(g_l.rx), (size_t)0);
        vcs_package_store_close(store);
        test_rm_rf(dir);
    } TEST_END
    return failures;
}

static int ptl_case_rebuild_mid_scan_resume(void)
{
    int failures = 0;
    TEST_CASE("proof_ticket: late unreadable blob refuses; restart and replay") {
        ASSERT(ptl_fresh());
        uint8_t wires[3][VCS_PROOF_TICKET_WIRE_BYTES];
        for (size_t i = 0; i < 3; i++)
            ASSERT(ptf_emit(&g_l, PTF_A, &g_l.base, ptf_pass(), wires[i], NULL));
        uint8_t cp[VCS_PROOF_CHECKPOINT_WIRE_BYTES], root[32];
        ASSERT(vcs_proof_issuer_log_checkpoint(g_l.logs[PTF_A], 11, cp));
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "proof_ticket", "midscan");
        struct vcs_package_store *store =
            vcs_package_store_open(dir, UINT64_C(8) * 1024 * 1024);
        ASSERT(store != NULL);
        ASSERT(vcs_proof_ticket_store_put(store, wires[0], sizeof(wires[0]),
                                          root));
        ASSERT(vcs_proof_ticket_store_put(store, wires[1], sizeof(wires[1]),
                                          root));
        ASSERT(vcs_proof_ticket_store_put(store, cp, sizeof(cp), root));
        uint8_t late_root[32];
        ASSERT(vcs_proof_ticket_store_put(store, wires[2], sizeof(wires[2]),
                                          late_root));
        uint8_t chunk[32];
        char hex[65], path[640];
        ASSERT(vcs_package_chunk_hash(wires[2], sizeof(wires[2]), chunk));
        zcl_hex_encode(chunk, sizeof(chunk), hex);
        ASSERT(snprintf(path, sizeof(path), "%s/zcode/cas/sha3/%.2s/%s",
                        dir, hex, hex) < (int)sizeof(path));
        ASSERT(unlink(path) == 0);
        size_t tickets = 0, cps = 0, skipped = 0;
        ASSERT(!ptl_rebuild(g_l.rx, store, 4, &tickets, &cps,
                                           &skipped));
        ASSERT_EQ(tickets, (size_t)0);
        ASSERT_EQ(cps, (size_t)0);
        ASSERT_EQ(vcs_proof_receiver_ticket_count(g_l.rx), (size_t)0);
        vcs_package_store_close(store);
        store = vcs_package_store_open(dir, UINT64_C(8) * 1024 * 1024);
        ASSERT(store != NULL);
        ASSERT(vcs_package_store_put_chunk(store, late_root, VCS_BLOB_PATH,
                                           0u, wires[2], sizeof(wires[2])) ==
               VCS_PACKAGE_STORE_OK);
        ASSERT(ptl_rebuild(g_l.rx, store, 4, &tickets, &cps,
                                          &skipped));
        ASSERT_EQ(tickets, (size_t)3);
        ASSERT_EQ(cps, (size_t)1);
        ASSERT_EQ(vcs_proof_receiver_issuer_leaves(g_l.rx, g_l.pub[PTF_A]),
                  (uint64_t)3);
        uint8_t expected[32];
        ASSERT(vcs_proof_checkpoint_root(cp, sizeof(cp), expected));
        const struct pr_issuer *recovered =
            pr_issuer_find(g_l.rx, g_l.pub[PTF_A]);
        ASSERT(recovered != NULL);
        ASSERT(memcmp(recovered->last_root, expected, sizeof(expected)) == 0);
        vcs_package_store_close(store);
        test_rm_rf(dir);
    } TEST_END
    return failures;
}

static int ptl_case_staged_ticket(void)
{
    int failures = 0;
    TEST_CASE("proof_ticket: staged ticket blob refuses partial rebuild") {
        ASSERT(ptl_fresh());
        uint8_t ticket[VCS_PROOF_TICKET_WIRE_BYTES];
        uint8_t cp[VCS_PROOF_CHECKPOINT_WIRE_BYTES], root[32];
        ASSERT(ptf_emit(&g_l, PTF_A, &g_l.base, ptf_pass(), ticket, NULL));
        ASSERT(vcs_proof_issuer_log_checkpoint(g_l.logs[PTF_A], 11, cp));
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "proof_ticket", "staged");
        struct vcs_package_store *store =
            vcs_package_store_open(dir, UINT64_C(8) * 1024 * 1024);
        ASSERT(store != NULL);
        uint8_t chunk[32];
        ASSERT(vcs_package_chunk_hash(ticket, sizeof(ticket), chunk));
        struct vcs_package_manifest manifest;
        vcs_package_manifest_init(&manifest);
        ASSERT(vcs_package_manifest_add(&manifest, VCS_BLOB_PATH,
                                        VCS_PACKAGE_MODE_FILE, sizeof(ticket),
                                        chunk, 1u));
        uint8_t *wire = NULL;
        size_t wire_len = 0;
        ASSERT(vcs_package_manifest_serialize(&manifest, &wire, &wire_len));
        vcs_package_manifest_free(&manifest);
        ASSERT(vcs_package_store_put_manifest(store, wire, wire_len, root) ==
               VCS_PACKAGE_STORE_OK);
        uint8_t ticket_root[32];
        memcpy(ticket_root, root, sizeof(ticket_root));
        free(wire);
        ASSERT(vcs_proof_ticket_store_put(store, cp, sizeof(cp), root));
        size_t tickets = 0, cps = 0, skipped = 0;
        ASSERT(!ptl_rebuild(g_l.rx, store, 2, &tickets, &cps,
                                           &skipped));
        ASSERT_EQ(vcs_proof_receiver_ticket_count(g_l.rx), (size_t)0);
        vcs_package_store_close(store);
        store = vcs_package_store_open(dir, UINT64_C(8) * 1024 * 1024);
        ASSERT(store != NULL);
        ASSERT(vcs_package_store_put_chunk(store, ticket_root, VCS_BLOB_PATH,
                                           0u, ticket, sizeof(ticket)) ==
               VCS_PACKAGE_STORE_OK);
        ASSERT(ptl_rebuild(g_l.rx, store, 2, &tickets, &cps,
                                          &skipped));
        ASSERT_EQ(tickets, (size_t)1);
        ASSERT_EQ(cps, (size_t)1);
        vcs_package_store_close(store);
        test_rm_rf(dir);
    } TEST_END
    return failures;
}

static int ptl_case_deleted_history_resume(void)
{
    int failures = 0;
    TEST_CASE("proof_ticket: deleted checkpoint isolates its issuer; restore replays it") {
        ASSERT(ptl_fresh());
        uint8_t first[VCS_PROOF_TICKET_WIRE_BYTES];
        uint8_t second[VCS_PROOF_TICKET_WIRE_BYTES];
        uint8_t cp1[VCS_PROOF_CHECKPOINT_WIRE_BYTES];
        uint8_t cp2[VCS_PROOF_CHECKPOINT_WIRE_BYTES], root[32];
        ASSERT(ptf_emit(&g_l, PTF_A, &g_l.base, ptf_pass(), first, NULL));
        ASSERT(vcs_proof_issuer_log_checkpoint(g_l.logs[PTF_A], 11, cp1));
        ASSERT(ptf_emit(&g_l, PTF_A, &g_l.base, ptf_pass(), second, NULL));
        ASSERT(vcs_proof_issuer_log_checkpoint(g_l.logs[PTF_A], 12, cp2));
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "proof_ticket", "restore");
        struct vcs_package_store *store =
            vcs_package_store_open(dir, UINT64_C(8) * 1024 * 1024);
        ASSERT(store != NULL);
        ASSERT(vcs_proof_ticket_store_put(store, first, sizeof(first), root));
        ASSERT(vcs_proof_ticket_store_put(store, second, sizeof(second), root));
        ASSERT(vcs_proof_ticket_store_put(store, cp2, sizeof(cp2), root));
        size_t tickets = 0, cps = 0, skipped = 0;
        ASSERT(ptl_rebuild(g_l.rx, store, 3, &tickets, &cps, &skipped));
        ASSERT_EQ(tickets, (size_t)2);
        ASSERT_EQ(cps, (size_t)0);
        ASSERT_EQ(vcs_proof_receiver_ticket_count(g_l.rx), (size_t)2);
        ASSERT(vcs_proof_receiver_issuer_history_incomplete(g_l.rx,
                                                            g_l.pub[PTF_A]));
        ASSERT_EQ(vcs_proof_receiver_issuer_leaves(g_l.rx, g_l.pub[PTF_A]),
                  (uint64_t)0);
        ASSERT_EQ(vcs_proof_receiver_issuer_checkpoints(g_l.rx,
                                                        g_l.pub[PTF_A]),
                  (size_t)0);
        vcs_package_store_close(store);
        store = vcs_package_store_open(dir, UINT64_C(8) * 1024 * 1024);
        ASSERT(store != NULL);
        ASSERT(vcs_proof_ticket_store_put(store, cp1, sizeof(cp1), root));
        ASSERT(ptl_rebuild(g_l.rx, store, 4, &tickets, &cps,
                                          &skipped));
        ASSERT_EQ(tickets, (size_t)2);
        ASSERT_EQ(cps, (size_t)2);
        ASSERT_EQ(vcs_proof_receiver_issuer_leaves(g_l.rx, g_l.pub[PTF_A]),
                  (uint64_t)2);
        uint8_t expected[32];
        ASSERT(vcs_proof_checkpoint_root(cp2, sizeof(cp2), expected));
        const struct pr_issuer *recovered =
            pr_issuer_find(g_l.rx, g_l.pub[PTF_A]);
        ASSERT(recovered != NULL);
        ASSERT(memcmp(recovered->last_root, expected, sizeof(expected)) == 0);
        vcs_package_store_close(store);
        test_rm_rf(dir);
    } TEST_END
    return failures;
}

static int ptl_case_late_replay_failure(void)
{
    int failures = 0;
    TEST_CASE("proof_ticket: late replay gap publishes no partial checkpoint") {
        ASSERT(ptl_fresh());
        uint8_t first[VCS_PROOF_TICKET_WIRE_BYTES];
        uint8_t second[VCS_PROOF_TICKET_WIRE_BYTES];
        uint8_t cp1[VCS_PROOF_CHECKPOINT_WIRE_BYTES];
        uint8_t cp2[VCS_PROOF_CHECKPOINT_WIRE_BYTES], root[32];
        ASSERT(ptf_emit(&g_l, PTF_A, &g_l.base, ptf_pass(), first, NULL));
        ASSERT(vcs_proof_issuer_log_checkpoint(g_l.logs[PTF_A], 11, cp1));
        ASSERT(ptf_emit(&g_l, PTF_A, &g_l.base, ptf_pass(), second, NULL));
        ASSERT(vcs_proof_issuer_log_checkpoint(g_l.logs[PTF_A], 12, cp2));
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "proof_ticket", "latereplay");
        struct vcs_package_store *store =
            vcs_package_store_open(dir, UINT64_C(8) * 1024 * 1024);
        ASSERT(store != NULL);
        ASSERT(vcs_proof_ticket_store_put(store, first, sizeof(first), root));
        ASSERT(vcs_proof_ticket_store_put(store, cp1, sizeof(cp1), root));
        ASSERT(vcs_proof_ticket_store_put(store, cp2, sizeof(cp2), root));
        size_t tickets = 0, cps = 0, skipped = 0;
        /* cp1 replays, cp2 cannot: A is isolated whole, keeping neither. */
        ASSERT(ptl_rebuild(g_l.rx, store, 3, &tickets, &cps, &skipped));
        ASSERT_EQ(tickets, (size_t)1);
        ASSERT_EQ(cps, (size_t)0);
        ASSERT_EQ(vcs_proof_receiver_ticket_count(g_l.rx), (size_t)1);
        ASSERT_EQ(vcs_proof_receiver_issuer_leaves(g_l.rx, g_l.pub[PTF_A]),
                  (uint64_t)0);
        ASSERT_EQ(vcs_proof_receiver_issuer_checkpoints(g_l.rx,
                                                        g_l.pub[PTF_A]),
                  (size_t)0);
        ASSERT(vcs_proof_receiver_issuer_history_incomplete(g_l.rx,
                                                            g_l.pub[PTF_A]));
        uint8_t first_root[32];
        ASSERT(vcs_proof_ticket_observation_root(first, sizeof(first),
                                                 first_root));
        const struct pr_entry *partial = pr_entry_find(g_l.rx, first_root);
        ASSERT(partial != NULL);
        ASSERT(!partial->covered);
        vcs_package_store_close(store);
        store = vcs_package_store_open(dir, UINT64_C(8) * 1024 * 1024);
        ASSERT(store != NULL);
        ASSERT(vcs_proof_ticket_store_put(store, second, sizeof(second), root));
        ASSERT(ptl_rebuild(g_l.rx, store, 4, &tickets, &cps,
                                          &skipped));
        ASSERT_EQ(tickets, (size_t)2);
        ASSERT_EQ(cps, (size_t)2);
        ASSERT_EQ(vcs_proof_receiver_issuer_leaves(g_l.rx, g_l.pub[PTF_A]),
                  (uint64_t)2);
        uint8_t expected[32];
        ASSERT(vcs_proof_checkpoint_root(cp2, sizeof(cp2), expected));
        const struct pr_issuer *recovered =
            pr_issuer_find(g_l.rx, g_l.pub[PTF_A]);
        ASSERT(recovered != NULL);
        ASSERT(memcmp(recovered->last_root, expected, sizeof(expected)) == 0);
        char head_hex[65];
        zcl_hex_encode(expected, sizeof(expected), head_hex);
        printf("\nproof_recovery_root case=late_replay head=%s\n", head_hex);
        vcs_package_store_close(store);
        test_rm_rf(dir);
    } TEST_END
    return failures;
}

static int ptl_case_deleted_head(void)
{
    int failures = 0;
    TEST_CASE("proof_ticket: live head prevents silent history rollback") {
        ASSERT(ptl_fresh());
        uint8_t first[VCS_PROOF_TICKET_WIRE_BYTES];
        uint8_t second[VCS_PROOF_TICKET_WIRE_BYTES];
        uint8_t cp1[VCS_PROOF_CHECKPOINT_WIRE_BYTES];
        uint8_t cp2[VCS_PROOF_CHECKPOINT_WIRE_BYTES], root[32];
        ASSERT(ptf_emit(&g_l, PTF_A, &g_l.base, ptf_pass(), first, NULL));
        ASSERT(vcs_proof_issuer_log_checkpoint(g_l.logs[PTF_A], 11, cp1));
        ASSERT(ptf_emit(&g_l, PTF_A, &g_l.base, ptf_pass(), second, NULL));
        ASSERT(vcs_proof_issuer_log_checkpoint(g_l.logs[PTF_A], 12, cp2));
        struct vcs_proof_sync_report rep;
        const uint8_t *one[] = {first}, *two[] = {second};
        ASSERT(ptl_sync_wires(cp1, one, 1, &rep));
        ASSERT(ptl_sync_wires(cp2, two, 1, &rep));
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "proof_ticket", "missinghead");
        struct vcs_package_store *store =
            vcs_package_store_open(dir, UINT64_C(8) * 1024 * 1024);
        ASSERT(store != NULL);
        ASSERT(vcs_proof_ticket_store_put(store, first, sizeof(first), root));
        ASSERT(vcs_proof_ticket_store_put(store, second, sizeof(second), root));
        ASSERT(vcs_proof_ticket_store_put(store, cp1, sizeof(cp1), root));
        size_t tickets = 0, cps = 0, skipped = 0;
        ASSERT(!ptl_rebuild(g_l.rx, store, 3, &tickets, &cps,
                                           &skipped));
        ASSERT_EQ(vcs_proof_receiver_issuer_checkpoints(g_l.rx, g_l.pub[PTF_A]),
                  (size_t)2);
        ASSERT(vcs_proof_ticket_store_put(store, cp2, sizeof(cp2), root));
        ASSERT(ptl_rebuild(g_l.rx, store, 4, &tickets, &cps,
                                          &skipped));
        ASSERT_EQ(cps, (size_t)2);
        vcs_package_store_close(store);
        test_rm_rf(dir);
    } TEST_END
    return failures;
}

static int ptl_case_rebuild_conflict(void)
{
    int failures = 0;
    TEST_CASE("proof_ticket: reordered and duplicate CAS blobs retain conflict") {
        ASSERT(ptl_fresh());
        uint8_t pass[VCS_PROOF_TICKET_WIRE_BYTES];
        uint8_t fail[VCS_PROOF_TICKET_WIRE_BYTES];
        uint8_t a[VCS_PROOF_CHECKPOINT_WIRE_BYTES];
        uint8_t b[VCS_PROOF_CHECKPOINT_WIRE_BYTES], root[32];
        ASSERT(ptf_emit(&g_l, PTF_A, &g_l.base, ptf_pass(), pass, NULL));
        ASSERT(ptf_emit(&g_l, PTF_B, &g_l.base, ptf_fail(), fail, NULL));
        ASSERT(vcs_proof_issuer_log_checkpoint(g_l.logs[PTF_A], 11, a));
        ASSERT(vcs_proof_issuer_log_checkpoint(g_l.logs[PTF_B], 11, b));
        struct vcs_proof_sync_report rep;
        const uint8_t *pass_delta[] = {pass}, *fail_delta[] = {fail};
        ASSERT(ptl_sync_wires(a, pass_delta, 1, &rep));
        ASSERT_EQ(rep.outcome, VCS_PROOF_SYNC_ADVANCED);
        ASSERT(ptl_sync_wires(b, fail_delta, 1, &rep));
        ASSERT_EQ(rep.outcome, VCS_PROOF_SYNC_ADVANCED);
        struct vcs_proof_ticket_class before_cls[PTL_CAP];
        struct vcs_proof_reuse_decision before;
        ASSERT(ptf_decide(&g_l, &g_l.base, VCS_PROOF_ACTION_CHECK, NULL,
                          before_cls, PTL_CAP, &before));
        ASSERT_EQ(before.outcome, VCS_PROOF_REUSE_REFUSE);
        ASSERT_EQ(before.eligible_pass, (uint32_t)1);
        ASSERT_EQ(before.eligible_fail, (uint32_t)1);
        ASSERT_EQ(before.used_count, (uint32_t)2);
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "proof_ticket", "conflict");
        struct vcs_package_store *store =
            vcs_package_store_open(dir, UINT64_C(8) * 1024 * 1024);
        ASSERT(store != NULL);
        ASSERT(vcs_proof_ticket_store_put(store, b, sizeof(b), root));
        ASSERT(vcs_proof_ticket_store_put(store, fail, sizeof(fail), root));
        ASSERT(vcs_proof_ticket_store_put(store, a, sizeof(a), root));
        ASSERT(vcs_proof_ticket_store_put(store, pass, sizeof(pass), root));
        ASSERT(vcs_proof_ticket_store_put(store, pass, sizeof(pass), root));
        struct vcs_proof_receiver *recovered = vcs_proof_receiver_new();
        ASSERT(recovered != NULL);
        size_t tickets = 0, cps = 0, skipped = 0;
        ASSERT(ptl_rebuild(recovered, store, 4, &tickets, &cps,
                                          &skipped));
        ASSERT_EQ(tickets, (size_t)2);
        ASSERT_EQ(cps, (size_t)2);
        struct vcs_proof_ticket_class cls[PTL_CAP];
        struct vcs_proof_reuse_decision d;
        struct vcs_proof_reuse_request req = {
            .local = &g_l.base, .action_class = VCS_PROOF_ACTION_CHECK,
            .domain = &g_l.domain, .policy = &g_l.policy,
            .artifacts = &g_l.source,
        };
        ASSERT(vcs_proof_reuse_decide(recovered, &req, cls, PTL_CAP, &d));
        ASSERT_EQ(d.outcome, VCS_PROOF_REUSE_REFUSE);
        ASSERT_STR_EQ(d.reason, VCS_PROOF_OBSERVATION_CONFLICT);
        ASSERT_EQ(d.eligible_pass, before.eligible_pass);
        ASSERT_EQ(d.eligible_fail, before.eligible_fail);
        ASSERT_EQ(d.used_count, before.used_count);
        ASSERT((memcmp(d.used[0], before.used[0], 32) == 0 &&
                memcmp(d.used[1], before.used[1], 32) == 0) ||
               (memcmp(d.used[0], before.used[1], 32) == 0 &&
                memcmp(d.used[1], before.used[0], 32) == 0));
        uint8_t pass_root[32], fail_root[32];
        ASSERT(vcs_proof_ticket_observation_root(pass, sizeof(pass),
                                                  pass_root));
        ASSERT(vcs_proof_ticket_observation_root(fail, sizeof(fail),
                                                  fail_root));
        ASSERT((memcmp(d.used[0], pass_root, 32) == 0 &&
                memcmp(d.used[1], fail_root, 32) == 0) ||
               (memcmp(d.used[0], fail_root, 32) == 0 &&
                memcmp(d.used[1], pass_root, 32) == 0));
        char pass_hex[65], fail_hex[65];
        zcl_hex_encode(pass_root, sizeof(pass_root), pass_hex);
        zcl_hex_encode(fail_root, sizeof(fail_root), fail_hex);
        printf("\nproof_recovery_roots case=eligible_conflict pass=%s "
               "fail=%s\n", pass_hex, fail_hex);
        struct vcs_proof_admission_context admission = ptf_context(&g_l);
        admission.receiver = recovered;
        struct vcs_proof_change change = {
            .component_id = "fixture", .scope_known = true,
        };
        struct vcs_proof_obligation obligation = {
            .name = "fixture/check", .component_id = "fixture",
            .action_class = VCS_PROOF_ACTION_CHECK, .preimage = &g_l.base,
            .in_reach = true,
        };
        struct vcs_proof_admission_result admitted;
        struct vcs_proof_admission_report report;
        ASSERT(vcs_proof_admission_run(&admission, &change, &obligation, 1u,
                                       &admitted, &report));
        ASSERT_EQ(admitted.status, VCS_PROOF_ADMIT_REFUSED);
        ASSERT_STR_EQ(admitted.reason, VCS_PROOF_OBSERVATION_CONFLICT);
        ASSERT_STR_EQ(report.fallback_reason, VCS_PROOF_FALLBACK_CONFLICT);
        ASSERT_EQ(report.proofs_fresh, (uint32_t)0);
        ASSERT_EQ(report.proofs_refused, (uint32_t)1);
        ASSERT_EQ(report.proof_invalidated, (uint32_t)1);
        struct vcs_proof_reuse_policy inconsistent = g_l.policy;
        inconsistent.policy_root[0] ^= 1u;
        admission.policy = &inconsistent;
        ASSERT(vcs_proof_admission_run(&admission, &change, &obligation, 1u,
                                       &admitted, &report));
        ASSERT_EQ(admitted.status, VCS_PROOF_ADMIT_REFUSED);
        ASSERT_STR_EQ(admitted.reason, VCS_PROOF_REUSE_WHY_POLICY_ROOT);
        ASSERT_STR_EQ(report.fallback_reason, VCS_PROOF_FALLBACK_POLICY);
        ASSERT_EQ(report.proofs_fresh, (uint32_t)0);
        ASSERT_EQ(report.proofs_refused, (uint32_t)1);
        ASSERT_EQ(report.proof_invalidated, (uint32_t)1);
        vcs_proof_receiver_free(recovered);
        vcs_package_store_close(store);
        test_rm_rf(dir);
    } TEST_END
    return failures;
}

static int ptl_case_seq_reorder(void)
{
    int failures = 0;
    TEST_CASE("proof_ticket: forged seq predecessor cannot hide valid ticket") {
        ASSERT(ptl_fresh());
        uint8_t valid[VCS_PROOF_TICKET_WIRE_BYTES];
        uint8_t forged[VCS_PROOF_TICKET_WIRE_BYTES];
        uint8_t cp[VCS_PROOF_CHECKPOINT_WIRE_BYTES], root[32];
        ASSERT(ptf_emit(&g_l, PTF_A, &g_l.base, ptf_pass(), valid, NULL));
        ASSERT(vcs_proof_issuer_log_checkpoint(g_l.logs[PTF_A], 11, cp));
        memcpy(forged, valid, sizeof(forged));
        forged[sizeof(forged) - 1u] ^= 1u;
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "proof_ticket", "forgedfirst");
        struct vcs_package_store *store =
            vcs_package_store_open(dir, UINT64_C(8) * 1024 * 1024);
        ASSERT(store != NULL);
        ASSERT(vcs_proof_ticket_store_put(store, forged, sizeof(forged), root));
        ASSERT(vcs_proof_ticket_store_put(store, valid, sizeof(valid), root));
        ASSERT(vcs_proof_ticket_store_put(store, cp, sizeof(cp), root));
        size_t tickets = 0, cps = 0, skipped = 0;
        ASSERT(ptl_rebuild(g_l.rx, store, 3, &tickets, &cps,
                                          &skipped));
        /* The forged copy is refused once at scan and never retained. */
        ASSERT_EQ(tickets, (size_t)1);
        ASSERT_EQ(skipped, (size_t)1);
        uint8_t forged_root[32];
        ASSERT(vcs_proof_ticket_observation_root(forged, sizeof(forged),
                                                  forged_root));
        ASSERT(pr_entry_find(g_l.rx, forged_root) == NULL);
        uint8_t valid_root[32];
        ASSERT(vcs_proof_ticket_observation_root(valid, sizeof(valid),
                                                  valid_root));
        struct pr_entry *e = pr_entry_find(g_l.rx, valid_root);
        ASSERT(e != NULL && e->covered);
        ASSERT(!vcs_proof_receiver_issuer_equivocating(g_l.rx,
                                                       g_l.pub[PTF_A]));
        vcs_package_store_close(store);
        test_rm_rf(dir);
    } TEST_END
    return failures;
}

static int ptl_case_signed_seq_fork(void)
{
    int failures = 0;
    TEST_CASE("proof_ticket: two signed seq roots remain equivocation") {
        ASSERT(ptl_fresh());
        uint8_t original[VCS_PROOF_TICKET_WIRE_BYTES];
        uint8_t forked[VCS_PROOF_TICKET_WIRE_BYTES];
        uint8_t cp[VCS_PROOF_CHECKPOINT_WIRE_BYTES], root[32];
        ASSERT(ptf_emit(&g_l, PTF_A, &g_l.base, ptf_pass(), original, NULL));
        ASSERT(vcs_proof_issuer_log_checkpoint(g_l.logs[PTF_A], 11, cp));
        struct vcs_proof_issuer_log *fork = ptl_fork();
        ASSERT(fork != NULL);
        ASSERT(ptl_append(fork, ptf_fail(), forked));
        vcs_proof_issuer_log_free(fork);
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "proof_ticket", "seqfork");
        struct vcs_package_store *store =
            vcs_package_store_open(dir, UINT64_C(8) * 1024 * 1024);
        ASSERT(store != NULL);
        ASSERT(vcs_proof_ticket_store_put(store, original, sizeof(original), root));
        ASSERT(vcs_proof_ticket_store_put(store, forked, sizeof(forked), root));
        ASSERT(vcs_proof_ticket_store_put(store, cp, sizeof(cp), root));
        size_t tickets = 0, cps = 0, skipped = 0;
        ASSERT(ptl_rebuild(g_l.rx, store, 3, &tickets, &cps,
                                          &skipped));
        ASSERT_EQ(tickets, (size_t)2);
        ASSERT(vcs_proof_receiver_issuer_equivocating(g_l.rx, g_l.pub[PTF_A]));
        vcs_package_store_close(store);
        test_rm_rf(dir);
    } TEST_END
    return failures;
}

static int ptl_case_live_signed_seq_fork(void)
{
    int failures = 0;
    TEST_CASE("proof_ticket: live signed sequence fork marks issuer") {
        ASSERT(ptl_fresh());
        uint8_t original[VCS_PROOF_TICKET_WIRE_BYTES];
        uint8_t forked[VCS_PROOF_TICKET_WIRE_BYTES];
        ASSERT(ptf_emit(&g_l, PTF_A, &g_l.base, ptf_pass(), original, NULL));
        struct vcs_proof_issuer_log *fork = ptl_fork();
        ASSERT(fork != NULL);
        ASSERT(ptl_append(fork, ptf_fail(), forked));
        vcs_proof_issuer_log_free(fork);
        bool added = false;
        ASSERT(vcs_proof_receiver_add_ticket(g_l.rx, original,
                                             sizeof(original), &added));
        ASSERT(added);
        ASSERT(vcs_proof_receiver_add_ticket(g_l.rx, forked,
                                             sizeof(forked), &added));
        ASSERT(added);
        ASSERT(vcs_proof_receiver_issuer_equivocating(g_l.rx,
                                                       g_l.pub[PTF_A]));
        ASSERT_EQ(vcs_proof_receiver_ticket_count(g_l.rx), (size_t)2);
    } TEST_END
    return failures;
}

static int ptl_case_rebuild_after_live_seq_fork(void)
{
    int failures = 0;
    TEST_CASE("proof_ticket: complete CAS preserves pre-fork verified head") {
        ASSERT(ptl_fresh());
        uint8_t original[VCS_PROOF_TICKET_WIRE_BYTES];
        uint8_t forked[VCS_PROOF_TICKET_WIRE_BYTES];
        uint8_t cp[VCS_PROOF_CHECKPOINT_WIRE_BYTES], root[32];
        ASSERT(ptf_emit(&g_l, PTF_A, &g_l.base, ptf_pass(), original, NULL));
        ASSERT(vcs_proof_issuer_log_checkpoint(g_l.logs[PTF_A], 11, cp));
        const uint8_t *delta[] = {original};
        struct vcs_proof_sync_report rep;
        ASSERT(ptl_sync_wires(cp, delta, 1u, &rep));
        ASSERT_EQ(rep.outcome, VCS_PROOF_SYNC_ADVANCED);
        struct vcs_proof_issuer_log *fork = ptl_fork();
        ASSERT(fork != NULL);
        ASSERT(ptl_append(fork, ptf_fail(), forked));
        vcs_proof_issuer_log_free(fork);
        bool added = false;
        ASSERT(vcs_proof_receiver_add_ticket(g_l.rx, forked,
                                             sizeof(forked), &added));
        ASSERT(added);
        ASSERT(vcs_proof_receiver_issuer_equivocating(g_l.rx,
                                                       g_l.pub[PTF_A]));
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "proof_ticket", "livefork");
        struct vcs_package_store *store =
            vcs_package_store_open(dir, UINT64_C(8) * 1024 * 1024);
        ASSERT(store != NULL);
        ASSERT(vcs_proof_ticket_store_put(store, forked, sizeof(forked), root));
        ASSERT(vcs_proof_ticket_store_put(store, cp, sizeof(cp), root));
        ASSERT(vcs_proof_ticket_store_put(store, original,
                                          sizeof(original), root));
        size_t tickets = 0, cps = 0, skipped = 0;
        ASSERT(ptl_rebuild(g_l.rx, store, 3, &tickets, &cps,
                                          &skipped));
        ASSERT_EQ(tickets, (size_t)2);
        ASSERT_EQ(cps, (size_t)1);
        ASSERT_EQ(vcs_proof_receiver_issuer_leaves(g_l.rx, g_l.pub[PTF_A]),
                  (uint64_t)1);
        ASSERT(vcs_proof_receiver_issuer_equivocating(g_l.rx,
                                                       g_l.pub[PTF_A]));
        const struct pr_issuer *is = pr_issuer_find(g_l.rx, g_l.pub[PTF_A]);
        ASSERT(is != NULL && is->cp_count == 1u && is->cps[0].verified);
        uint8_t observed[32];
        ASSERT(vcs_proof_ticket_observation_root(original, sizeof(original),
                                                  observed));
        const struct pr_entry *entry = pr_entry_find(g_l.rx, observed);
        ASSERT(entry != NULL && entry->covered);
        struct vcs_proof_ticket_class classes[PTL_CAP];
        struct vcs_proof_reuse_decision decision;
        ASSERT(ptf_decide(&g_l, &g_l.base, VCS_PROOF_ACTION_CHECK, NULL,
                          classes, PTL_CAP, &decision));
        ASSERT(decision.outcome != VCS_PROOF_REUSE_HIT_PASS &&
               decision.outcome != VCS_PROOF_REUSE_HIT_FAIL);
        vcs_package_store_close(store);
        test_rm_rf(dir);
    } TEST_END
    return failures;
}

static int ptl_case_rebuild_fork_checkpoint_alloc(void)
{
    int failures = 0;
    TEST_CASE("proof_ticket: fork checkpoint allocation cannot drop history") {
        ASSERT(ptl_fresh());
        uint8_t original[VCS_PROOF_TICKET_WIRE_BYTES];
        uint8_t forked[VCS_PROOF_TICKET_WIRE_BYTES];
        uint8_t cps_wire[9][VCS_PROOF_CHECKPOINT_WIRE_BYTES], root[32];
        ASSERT(ptf_emit(&g_l, PTF_A, &g_l.base, ptf_pass(), original, NULL));
        struct vcs_proof_sync_report rep;
        const uint8_t *one[] = {original};
        for (size_t i = 0; i < 8u; i++) {
            ASSERT(vcs_proof_issuer_log_checkpoint(g_l.logs[PTF_A],
                                                     11u + i, cps_wire[i]));
            ASSERT(ptl_sync_wires(cps_wire[i], i ? NULL : one,
                                  i ? 0u : 1u, &rep));
            ASSERT_EQ(rep.outcome, VCS_PROOF_SYNC_ADVANCED);
        }
        ASSERT(vcs_proof_issuer_log_checkpoint(g_l.logs[PTF_A], 19,
                                                cps_wire[8]));
        struct vcs_proof_issuer_log *fork = ptl_fork();
        ASSERT(fork != NULL);
        ASSERT(ptl_append(fork, ptf_fail(), forked));
        vcs_proof_issuer_log_free(fork);
        bool added = false;
        ASSERT(vcs_proof_receiver_add_ticket(g_l.rx, forked,
                                             sizeof(forked), &added));
        ASSERT(added);
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "proof_ticket", "forkalloc");
        struct vcs_package_store *store =
            vcs_package_store_open(dir, UINT64_C(8) * 1024 * 1024);
        ASSERT(store != NULL);
        ASSERT(vcs_proof_ticket_store_put(store, original,
                                          sizeof(original), root));
        ASSERT(vcs_proof_ticket_store_put(store, forked, sizeof(forked), root));
        for (size_t i = 0; i < 9u; i++)
            ASSERT(vcs_proof_ticket_store_put(store, cps_wire[i],
                                               sizeof(cps_wire[i]), root));
        size_t tickets = 7, cps = 8, skipped = 9;
        zcl_alloc_fault_fail_nth("proof_checkpoints", 2u);
        bool rebuilt = ptl_rebuild(g_l.rx, store, 11, &tickets,
                                                   &cps, &skipped);
        bool consumed = zcl_alloc_fault_armed_label() == NULL;
        zcl_alloc_fault_clear();
        ASSERT(consumed);
        ASSERT(!rebuilt);
        ASSERT_EQ(tickets, (size_t)0);
        ASSERT_EQ(cps, (size_t)0);
        ASSERT_EQ(skipped, (size_t)0);
        ASSERT_EQ(vcs_proof_receiver_issuer_leaves(g_l.rx, g_l.pub[PTF_A]),
                  (uint64_t)1);
        const struct pr_issuer *is = pr_issuer_find(g_l.rx, g_l.pub[PTF_A]);
        ASSERT(is != NULL && is->cp_count == 8u);
        vcs_package_store_close(store);
        test_rm_rf(dir);
    } TEST_END
    return failures;
}

static int ptl_case_rebuild_invalid_outputs(void)
{
    int failures = 0;
    TEST_CASE("proof_ticket: early rebuild refusal clears output counts") {
        size_t tickets = 7, cps = 8, skipped = 9;
        ASSERT(!ptl_rebuild(NULL, NULL, 0, &tickets, &cps,
                                           &skipped));
        ASSERT_EQ(tickets, (size_t)0);
        ASSERT_EQ(cps, (size_t)0);
        ASSERT_EQ(skipped, (size_t)0);
    } TEST_END
    return failures;
}

static int ptl_case_rebuild_equivocation(void)
{
    int failures = 0;
    TEST_CASE("proof_ticket: rebuild retains both signed checkpoint forks") {
        ASSERT(ptl_fresh());
        uint8_t original[VCS_PROOF_TICKET_WIRE_BYTES];
        uint8_t forked[VCS_PROOF_TICKET_WIRE_BYTES];
        uint8_t a[VCS_PROOF_CHECKPOINT_WIRE_BYTES];
        uint8_t b[VCS_PROOF_CHECKPOINT_WIRE_BYTES], root[32];
        ASSERT(ptf_emit(&g_l, PTF_A, &g_l.base, ptf_pass(), original, NULL));
        ASSERT(vcs_proof_issuer_log_checkpoint(g_l.logs[PTF_A], 11, a));
        struct vcs_proof_issuer_log *fork = ptl_fork();
        ASSERT(fork != NULL);
        bool made = ptl_append(fork, ptf_fail(), forked) &&
                    vcs_proof_issuer_log_checkpoint(fork, 12, b);
        vcs_proof_issuer_log_free(fork);
        ASSERT(made);
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "proof_ticket", "forkrebuild");
        struct vcs_package_store *store =
            vcs_package_store_open(dir, UINT64_C(8) * 1024 * 1024);
        ASSERT(store != NULL);
        ASSERT(vcs_proof_ticket_store_put(store, b, sizeof(b), root));
        ASSERT(vcs_proof_ticket_store_put(store, forked, sizeof(forked), root));
        ASSERT(vcs_proof_ticket_store_put(store, a, sizeof(a), root));
        ASSERT(vcs_proof_ticket_store_put(store, original, sizeof(original), root));
        size_t tickets = 0, cps = 0, skipped = 0;
        ASSERT(ptl_rebuild(g_l.rx, store, 4, &tickets, &cps,
                                          &skipped));
        ASSERT_EQ(tickets, (size_t)2);
        ASSERT_EQ(cps, (size_t)2);
        ASSERT(vcs_proof_receiver_issuer_equivocating(g_l.rx, g_l.pub[PTF_A]));
        ASSERT_EQ(vcs_proof_receiver_issuer_checkpoints(g_l.rx, g_l.pub[PTF_A]),
                  (size_t)2);
        vcs_package_store_close(store);
        test_rm_rf(dir);
    } TEST_END
    return failures;
}

static int ptl_case_rebuild_preserves_covered_branch(void)
{
    int failures = 0;
    TEST_CASE("proof_ticket: rebuild cannot erase a verified fork branch") {
        ASSERT(ptl_fresh());
        uint8_t first[VCS_PROOF_TICKET_WIRE_BYTES];
        uint8_t a[VCS_PROOF_TICKET_WIRE_BYTES];
        uint8_t b[VCS_PROOF_TICKET_WIRE_BYTES];
        uint8_t cp1[VCS_PROOF_CHECKPOINT_WIRE_BYTES];
        uint8_t cpa[VCS_PROOF_CHECKPOINT_WIRE_BYTES];
        uint8_t cpb[VCS_PROOF_CHECKPOINT_WIRE_BYTES], root[32];
        ASSERT(ptf_emit(&g_l, PTF_A, &g_l.base, ptf_pass(), first, NULL));
        ASSERT(vcs_proof_issuer_log_checkpoint(g_l.logs[PTF_A], 11, cp1));
        struct vcs_proof_issuer_log *fork = ptl_fork();
        ASSERT(fork != NULL);
        struct vcs_proof_ticket_v1 decoded;
        uint8_t copy[VCS_PROOF_TICKET_WIRE_BYTES];
        ASSERT(vcs_proof_ticket_decode(first, sizeof(first), &decoded));
        ASSERT(vcs_proof_issuer_log_append(fork, &decoded, copy));
        uint8_t fork_cp1[VCS_PROOF_CHECKPOINT_WIRE_BYTES];
        ASSERT(vcs_proof_issuer_log_checkpoint(fork, 11, fork_cp1));
        ASSERT(memcmp(cp1, fork_cp1, sizeof(cp1)) == 0);
        ASSERT(ptf_emit(&g_l, PTF_A, &g_l.base, ptf_pass(), a, NULL));
        ASSERT(vcs_proof_issuer_log_checkpoint(g_l.logs[PTF_A], 12, cpa));
        ASSERT(ptl_append(fork, ptf_fail(), b));
        ASSERT(vcs_proof_issuer_log_checkpoint(fork, 12, cpb));
        vcs_proof_issuer_log_free(fork);
        bool a_later = memcmp(cpa, cpb, sizeof(cpa)) > 0;
        const uint8_t *later_cp = a_later ? cpa : cpb;
        const uint8_t *earlier_cp = a_later ? cpb : cpa;
        const uint8_t *later_ticket = a_later ? a : b;
        struct vcs_proof_sync_report rep;
        const uint8_t *one[] = {first}, *second[] = {later_ticket};
        ASSERT(ptl_sync_wires(cp1, one, 1, &rep));
        ASSERT(ptl_sync_wires(later_cp, second, 1, &rep));
        ASSERT_EQ(rep.outcome, VCS_PROOF_SYNC_ADVANCED);
        ASSERT(ptl_sync_wires(earlier_cp, NULL, 0, &rep));
        ASSERT_EQ(rep.outcome, VCS_PROOF_SYNC_EQUIVOCATION);
        uint8_t later_root[32];
        ASSERT(vcs_proof_ticket_observation_root(later_ticket,
                                                  VCS_PROOF_TICKET_WIRE_BYTES,
                                                  later_root));
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "proof_ticket", "coveredfork");
        struct vcs_package_store *store =
            vcs_package_store_open(dir, UINT64_C(8) * 1024 * 1024);
        ASSERT(store != NULL);
        ASSERT(vcs_proof_ticket_store_put(store, first, sizeof(first), root));
        ASSERT(vcs_proof_ticket_store_put(store, a, sizeof(a), root));
        ASSERT(vcs_proof_ticket_store_put(store, b, sizeof(b), root));
        ASSERT(vcs_proof_ticket_store_put(store, cp1, sizeof(cp1), root));
        ASSERT(vcs_proof_ticket_store_put(store, cpa, sizeof(cpa), root));
        ASSERT(vcs_proof_ticket_store_put(store, cpb, sizeof(cpb), root));
        size_t tickets = 0, cps = 0, skipped = 0;
        ASSERT(!ptl_rebuild(g_l.rx, store, 6, &tickets, &cps,
                                           &skipped));
        struct pr_entry *retained = pr_entry_find(g_l.rx, later_root);
        ASSERT(retained != NULL && retained->covered);
        ASSERT_EQ(vcs_proof_receiver_issuer_leaves(g_l.rx, g_l.pub[PTF_A]),
                  (uint64_t)2);
        vcs_package_store_close(store);
        test_rm_rf(dir);
    } TEST_END
    return failures;
}

static int ptl_case_rebuild_preserves_checkpoint_head(void)
{
    int failures = 0;
    TEST_CASE("proof_ticket: rebuild cannot switch verified checkpoint head") {
        ASSERT(ptl_fresh());
        uint8_t ticket[VCS_PROOF_TICKET_WIRE_BYTES];
        uint8_t cp1[VCS_PROOF_CHECKPOINT_WIRE_BYTES];
        uint8_t cpa[VCS_PROOF_CHECKPOINT_WIRE_BYTES];
        uint8_t cpb[VCS_PROOF_CHECKPOINT_WIRE_BYTES], root[32];
        ASSERT(ptf_emit(&g_l, PTF_A, &g_l.base, ptf_pass(), ticket, NULL));
        ASSERT(vcs_proof_issuer_log_checkpoint(g_l.logs[PTF_A], 11, cp1));
        ASSERT(vcs_proof_issuer_log_checkpoint(g_l.logs[PTF_A], 12, cpa));
        struct vcs_proof_issuer_log *fork = ptl_fork();
        ASSERT(fork != NULL);
        struct vcs_proof_ticket_v1 decoded;
        uint8_t copy[VCS_PROOF_TICKET_WIRE_BYTES];
        uint8_t fork_cp1[VCS_PROOF_CHECKPOINT_WIRE_BYTES];
        ASSERT(vcs_proof_ticket_decode(ticket, sizeof(ticket), &decoded));
        ASSERT(vcs_proof_issuer_log_append(fork, &decoded, copy));
        ASSERT(vcs_proof_issuer_log_checkpoint(fork, 11, fork_cp1));
        ASSERT(memcmp(cp1, fork_cp1, sizeof(cp1)) == 0);
        ASSERT(vcs_proof_issuer_log_checkpoint(fork, 13, cpb));
        vcs_proof_issuer_log_free(fork);
        const uint8_t *later = memcmp(cpa, cpb, sizeof(cpa)) > 0 ? cpa : cpb;
        const uint8_t *earlier = later == cpa ? cpb : cpa;
        struct vcs_proof_sync_report rep;
        const uint8_t *one[] = {ticket};
        ASSERT(ptl_sync_wires(cp1, one, 1, &rep));
        ASSERT(ptl_sync_wires(later, NULL, 0, &rep));
        ASSERT_EQ(rep.outcome, VCS_PROOF_SYNC_ADVANCED);
        ASSERT(ptl_sync_wires(earlier, NULL, 0, &rep));
        ASSERT_EQ(rep.outcome, VCS_PROOF_SYNC_EQUIVOCATION);
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "proof_ticket", "headfork");
        struct vcs_package_store *store =
            vcs_package_store_open(dir, UINT64_C(8) * 1024 * 1024);
        ASSERT(store != NULL);
        ASSERT(vcs_proof_ticket_store_put(store, ticket, sizeof(ticket), root));
        ASSERT(vcs_proof_ticket_store_put(store, cp1, sizeof(cp1), root));
        ASSERT(vcs_proof_ticket_store_put(store, cpa, sizeof(cpa), root));
        ASSERT(vcs_proof_ticket_store_put(store, cpb, sizeof(cpb), root));
        size_t tickets = 0, cps = 0, skipped = 0;
        ASSERT(!ptl_rebuild(g_l.rx, store, 4, &tickets, &cps,
                                           &skipped));
        uint8_t expected[32];
        ASSERT(vcs_proof_checkpoint_root(later, sizeof(cpa), expected));
        const struct pr_issuer *is = pr_issuer_find(g_l.rx, g_l.pub[PTF_A]);
        ASSERT(is != NULL);
        ASSERT(memcmp(is->last_root, expected, sizeof(expected)) == 0);
        vcs_package_store_close(store);
        test_rm_rf(dir);
    } TEST_END
    return failures;
}

static int ptl_case_rebuild_corrupt_index(void)
{
    int failures = 0;
    TEST_CASE("proof_ticket: corrupt local index rebuilt from signed CAS") {
        ASSERT(ptl_fresh());
        ASSERT(ptf_emit(&g_l, PTF_A, &g_l.base, ptf_pass(), NULL, NULL));
        ASSERT(ptf_emit(&g_l, PTF_B, &g_l.base, ptf_fail(), NULL, NULL));
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "proof_ticket", "badindex");
        struct vcs_package_store *store =
            vcs_package_store_open(dir, UINT64_C(8) * 1024 * 1024);
        ASSERT(store != NULL);
        ASSERT(ptl_store_logs(store));
        size_t tickets = 0, cps = 0, skipped = 0;
        ASSERT(ptl_rebuild(g_l.rx, store, 5, &tickets, &cps,
                                          &skipped));
        ASSERT(g_l.rx->index_cap > 0);
        memset(g_l.rx->keys, 0,
               g_l.rx->index_cap * sizeof(*g_l.rx->keys));
        memset(g_l.rx->seqs, 0,
               g_l.rx->index_cap * sizeof(*g_l.rx->seqs));
        ASSERT(ptl_rebuild(g_l.rx, store, 5, &tickets, &cps,
                                          &skipped));
        struct vcs_proof_ticket_class cls[PTL_CAP];
        struct vcs_proof_reuse_decision d;
        ASSERT(ptf_decide(&g_l, &g_l.base, VCS_PROOF_ACTION_CHECK, NULL, cls,
                          PTL_CAP, &d));
        ASSERT_EQ(d.outcome, VCS_PROOF_REUSE_REFUSE);
        ASSERT_STR_EQ(d.reason, VCS_PROOF_OBSERVATION_CONFLICT);
        vcs_package_store_close(store);
        test_rm_rf(dir);
    } TEST_END
    return failures;
}

static void ptl_publish_marker(void *context)
{
    *(bool *)context = true;
}

static int ptl_case_checked_issuer_publish(void)
{
    int failures = 0;
    TEST_CASE("proof_ticket: in-memory issuer view swaps only after complete replay") {
        ASSERT(ptl_fresh());
        uint8_t ticket[VCS_PROOF_TICKET_WIRE_BYTES];
        uint8_t cp[VCS_PROOF_CHECKPOINT_WIRE_BYTES];
        uint8_t ticket_root[32], cp_root[32];
        ASSERT(ptf_emit(&g_l, PTF_A, &g_l.base, ptf_pass(), ticket, NULL));
        ASSERT(vcs_proof_issuer_log_checkpoint(g_l.logs[PTF_A], 11, cp));
        ASSERT(vcs_blob_root(cp, sizeof(cp), cp_root));
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "proof_ticket", "checkedpublish");
        struct vcs_package_store *store =
            vcs_package_store_open(dir, UINT64_C(8) * 1024 * 1024);
        ASSERT(store != NULL);
        ASSERT(vcs_proof_ticket_store_put(store, ticket, sizeof(ticket),
                                          ticket_root));
        struct vcs_proof_issuer_log *live =
            vcs_proof_issuer_log_new(g_l.seed[PTF_A]);
        ASSERT(live != NULL);
        struct vcs_proof_issuer_log *old = live;
        ASSERT(!vcs_proof_issuer_log_restore_publish_from_store(
            g_l.seed[PTF_A], store, cp_root, 2, 1, &live));
        ASSERT(live == old);
        ASSERT(vcs_proof_ticket_store_put(store, cp, sizeof(cp), cp_root));
        ASSERT(!vcs_proof_issuer_log_restore_publish_from_store(
            g_l.seed[PTF_A], store, cp_root, 1, 1, &live));
        ASSERT(live == old);
        ASSERT(vcs_proof_issuer_log_restore_publish_from_store(
            g_l.seed[PTF_A], store, cp_root, 2, 1, &live));
        ASSERT(live != old);
        ASSERT_EQ(vcs_proof_issuer_log_count(live), UINT64_C(1));
        struct vcs_proof_issuer_log *published = live;
        uint8_t chunk[32];
        ASSERT(vcs_package_chunk_hash(ticket, sizeof(ticket), chunk));
        char hex[65], path[640];
        zcl_hex_encode(chunk, sizeof(chunk), hex);
        ASSERT(snprintf(path, sizeof(path), "%s/zcode/cas/sha3/%.2s/%s",
                        dir, hex, hex) < (int)sizeof(path));
        ASSERT(unlink(path) == 0);
        ASSERT(!vcs_proof_issuer_log_restore_publish_from_store(
            g_l.seed[PTF_A], store, cp_root, 2, 1, &live));
        ASSERT(live == published);
        ASSERT_EQ(vcs_proof_issuer_log_count(live), UINT64_C(1));
        vcs_proof_issuer_log_free(live);
        vcs_package_store_close(store);
        test_rm_rf(dir);
    } TEST_END
    return failures;
}

/* Test-only seam: change the CAS leaf after scan/replay and before the
 * receiver's final verified read, without relying on scheduler timing. */
void vcs_proof_receiver_test_before_recheck(void (*hook)(void *), void *context);
void vcs_proof_receiver_test_after_recheck(void (*hook)(void *), void *context);

struct ptl_cas_change {
    char path[640];
    bool changed;
};

static void ptl_change_cas(void *context)
{
    struct ptl_cas_change *change = context;
    uint8_t corrupt[VCS_PROOF_TICKET_WIRE_BYTES];
    memset(corrupt, 0x5a, sizeof(corrupt));
    FILE *f = fopen(change->path, "wb");
    if (!f) return;
    size_t wrote = fwrite(corrupt, 1, sizeof(corrupt), f);
    int closed = fclose(f);
    change->changed = wrote == sizeof(corrupt) && closed == 0;
}

static int ptl_case_changed_cas_during_rebuild(void)
{
    int failures = 0;
    TEST_CASE("proof_ticket: changed CAS after replay retains old receiver") {
        ASSERT(ptl_fresh());
        uint8_t ticket[VCS_PROOF_TICKET_WIRE_BYTES];
        uint8_t root[32], chunk[32];
        ASSERT(ptf_emit(&g_l, PTF_A, &g_l.base, ptf_pass(), ticket, NULL));
        ASSERT(vcs_package_chunk_hash(ticket, sizeof(ticket), chunk));
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "proof_ticket", "midcas");
        struct vcs_package_store *store =
            vcs_package_store_open(dir, UINT64_C(8) * 1024 * 1024);
        ASSERT(store != NULL);
        ASSERT(vcs_proof_ticket_store_put(store, ticket, sizeof(ticket), root));
        size_t tickets = 0, cps = 0, skipped = 0;
        ASSERT(ptl_rebuild(g_l.rx, store, 1, &tickets, &cps,
                                          &skipped));
        ASSERT_EQ(vcs_proof_receiver_ticket_count(g_l.rx), (size_t)1);
        char hex[65];
        zcl_hex_encode(chunk, sizeof(chunk), hex);
        struct ptl_cas_change change = {0};
        ASSERT(snprintf(change.path, sizeof(change.path),
                        "%s/zcode/cas/sha3/%.2s/%s", dir, hex, hex) <
               (int)sizeof(change.path));
        vcs_proof_receiver_test_before_recheck(ptl_change_cas, &change);
        bool rebuilt = ptl_rebuild(g_l.rx, store, 1, &tickets,
                                                   &cps, &skipped);
        vcs_proof_receiver_test_before_recheck(NULL, NULL);
        ASSERT(change.changed);
        ASSERT(!rebuilt);
        ASSERT_EQ(tickets, (size_t)0);
        ASSERT_EQ(vcs_proof_receiver_ticket_count(g_l.rx), (size_t)1);
        vcs_package_store_close(store);
        test_rm_rf(dir);
    } TEST_END
    return failures;
}

static int ptl_case_changed_cas_after_recheck(void)
{
    int failures = 0;
    TEST_CASE("proof_ticket: changed CAS after final read blocks publication") {
        ASSERT(ptl_fresh());
        uint8_t ticket[VCS_PROOF_TICKET_WIRE_BYTES];
        uint8_t root[32], chunk[32];
        ASSERT(ptf_emit(&g_l, PTF_A, &g_l.base, ptf_pass(), ticket, NULL));
        ASSERT(vcs_package_chunk_hash(ticket, sizeof(ticket), chunk));
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "proof_ticket", "postcheckcas");
        struct vcs_package_store *store =
            vcs_package_store_open(dir, UINT64_C(8) * 1024 * 1024);
        ASSERT(store != NULL);
        ASSERT(vcs_proof_ticket_store_put(store, ticket, sizeof(ticket), root));
        size_t tickets = 0, cps = 0, skipped = 0;
        ASSERT(ptl_rebuild(g_l.rx, store, 1, &tickets, &cps,
                                          &skipped));
        ASSERT_EQ(vcs_proof_receiver_ticket_count(g_l.rx), (size_t)1);
        char hex[65];
        zcl_hex_encode(chunk, sizeof(chunk), hex);
        struct ptl_cas_change change = {0};
        ASSERT(snprintf(change.path, sizeof(change.path),
                        "%s/zcode/cas/sha3/%.2s/%s", dir, hex, hex) <
               (int)sizeof(change.path));
        vcs_proof_receiver_test_after_recheck(ptl_change_cas, &change);
        bool rebuilt = ptl_rebuild(g_l.rx, store, 1, &tickets,
                                                   &cps, &skipped);
        vcs_proof_receiver_test_after_recheck(NULL, NULL);
        ASSERT(change.changed);
        ASSERT(!rebuilt);
        ASSERT_EQ(tickets, (size_t)0);
        ASSERT_EQ(vcs_proof_receiver_ticket_count(g_l.rx), (size_t)1);
        vcs_package_store_close(store);
        test_rm_rf(dir);
    } TEST_END
    return failures;
}

static int ptl_case_deleted_catalog_manifest(void)
{
    int failures = 0;
    TEST_CASE("proof_ticket: deleted committed manifest blocks publication") {
        ASSERT(ptl_fresh());
        uint8_t ticket[VCS_PROOF_TICKET_WIRE_BYTES];
        uint8_t cp[VCS_PROOF_CHECKPOINT_WIRE_BYTES];
        uint8_t ticket_root[32], cp_root[32];
        ASSERT(ptf_emit(&g_l, PTF_A, &g_l.base, ptf_pass(), ticket, NULL));
        ASSERT(vcs_proof_issuer_log_checkpoint(g_l.logs[PTF_A], 11, cp));
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "proof_ticket", "lostmanifest");
        struct vcs_package_store *store =
            vcs_package_store_open(dir, UINT64_C(8) * 1024 * 1024);
        ASSERT(store != NULL);
        ASSERT(vcs_proof_ticket_store_put(store, ticket, sizeof(ticket),
                                          ticket_root));
        ASSERT(vcs_proof_ticket_store_put(store, cp, sizeof(cp), cp_root));
        size_t tickets = 0, cps = 0, skipped = 0;
        ASSERT(ptl_rebuild(g_l.rx, store, 2, &tickets, &cps,
                                          &skipped));
        ASSERT_EQ(tickets, (size_t)1);
        ASSERT_EQ(cps, (size_t)1);
        struct vcs_package_store_summary rows[2];
        struct vcs_package_store_page page;
        ASSERT_EQ(vcs_package_store_page_summaries(store, NULL, 2, 0,
                                                    rows, &page),
                  VCS_PACKAGE_STORE_PAGE_OK);
        char hex[65], path[640];
        zcl_hex_encode(cp_root, sizeof(cp_root), hex);
        ASSERT(snprintf(path, sizeof(path), "%s/zcode/manifests/%s",
                        dir, hex) < (int)sizeof(path));
        ASSERT(unlink(path) == 0);
        bool published = false;
        ASSERT_EQ(vcs_package_store_publish_if_generation(
                      store, page.generation, ptl_publish_marker,
                      &published), VCS_PACKAGE_STORE_PAGE_INCOMPLETE);
        ASSERT(!published);
        ASSERT(!ptl_rebuild(g_l.rx, store, 2, &tickets, &cps,
                                           &skipped));
        ASSERT_EQ(vcs_proof_receiver_ticket_count(g_l.rx), (size_t)1);
        ASSERT_EQ(vcs_proof_receiver_issuer_checkpoints(g_l.rx,
                                                        g_l.pub[PTF_A]),
                  (size_t)1);
        vcs_package_store_close(store);
        test_rm_rf(dir);
    } TEST_END
    return failures;
}

static int ptl_case_fresh_anchored_head(void)
{
    int failures = 0;
    TEST_CASE("proof_ticket: fresh receiver refuses a lost durable head") {
        ASSERT(ptl_fresh());
        uint8_t ticket[VCS_PROOF_TICKET_WIRE_BYTES];
        uint8_t cp[VCS_PROOF_CHECKPOINT_WIRE_BYTES];
        uint8_t ticket_root[32], cp_root[32];
        ASSERT(ptf_emit(&g_l, PTF_A, &g_l.base, ptf_pass(), ticket, NULL));
        ASSERT(vcs_proof_issuer_log_checkpoint(g_l.logs[PTF_A], 11, cp));
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "proof_ticket", "freshhead");
        struct vcs_package_store *store =
            vcs_package_store_open(dir, UINT64_C(8) * 1024 * 1024);
        ASSERT(store != NULL);
        ASSERT(vcs_proof_ticket_store_put(store, ticket, sizeof(ticket),
                                          ticket_root));
        ASSERT(vcs_proof_ticket_store_put(store, cp, sizeof(cp), cp_root));
        struct vcs_proof_receiver_anchor anchor = {0};
        memcpy(anchor.issuer_pubkey, g_l.pub[PTF_A], 32);
        memcpy(anchor.checkpoint_blob_root, cp_root, 32);
        struct vcs_proof_receiver *fresh = vcs_proof_receiver_new();
        ASSERT(fresh != NULL);
        size_t tickets = 0, cps = 0, skipped = 0;
        uint64_t generation = 0;
        ASSERT(vcs_proof_receiver_rebuild_anchored_bounded(
            fresh, store, &anchor, 1, 2, &tickets, &cps, &skipped,
            &generation));
        ASSERT_EQ(tickets, (size_t)1);
        ASSERT_EQ(cps, (size_t)1);
        ASSERT(generation != 0);
        ASSERT_EQ(vcs_proof_receiver_ticket_count(fresh), (size_t)1);
        generation = UINT64_C(99);
        ASSERT(!vcs_proof_receiver_rebuild_anchored_bounded(
            fresh, store, NULL, 0, 2, &tickets, &cps, &skipped,
            &generation));
        ASSERT_EQ(generation, (uint64_t)0);
        ASSERT_EQ(vcs_proof_receiver_ticket_count(fresh), (size_t)1);
        generation = UINT64_C(99);
        ASSERT(!vcs_proof_receiver_rebuild_anchored_bounded(
            fresh, store, &anchor, 1, 0, &tickets, &cps, &skipped,
            &generation));
        ASSERT_EQ(generation, (uint64_t)0);
        ASSERT_EQ(vcs_proof_receiver_ticket_count(fresh), (size_t)1);
        vcs_package_store_close(store);

        char hex[65], path[640];
        zcl_hex_encode(ticket_root, sizeof(ticket_root), hex);
        ASSERT(snprintf(path, sizeof(path), "%s/zcode/manifests/%s",
                        dir, hex) < (int)sizeof(path));
        ASSERT(unlink(path) == 0);
        zcl_hex_encode(cp_root, sizeof(cp_root), hex);
        ASSERT(snprintf(path, sizeof(path), "%s/zcode/manifests/%s",
                        dir, hex) < (int)sizeof(path));
        ASSERT(unlink(path) == 0);

        store = vcs_package_store_open(dir, UINT64_C(8) * 1024 * 1024);
        ASSERT(store != NULL);
        generation = UINT64_C(99);
        ASSERT(!vcs_proof_receiver_rebuild_anchored_bounded(
            fresh, store, &anchor, 1, 2, &tickets, &cps, &skipped,
            &generation));
        ASSERT_EQ(tickets, (size_t)0);
        ASSERT_EQ(cps, (size_t)0);
        ASSERT_EQ(generation, (uint64_t)0);
        ASSERT_EQ(vcs_proof_receiver_ticket_count(fresh), (size_t)1);
        vcs_proof_receiver_free(fresh);

        fresh = vcs_proof_receiver_new();
        ASSERT(fresh != NULL);
        generation = UINT64_C(99);
        /* The old, unanchored API sees an empty catalog after restart. */
        ASSERT(ptl_rebuild(fresh, store, 2, &tickets, &cps, &skipped));
        ASSERT_EQ(tickets, (size_t)0);
        ASSERT_EQ(cps, (size_t)0);
        ASSERT(!vcs_proof_receiver_rebuild_anchored_bounded(
            fresh, store, &anchor, 1, 2, &tickets, &cps, &skipped,
            &generation));
        ASSERT_EQ(tickets, (size_t)0);
        ASSERT_EQ(cps, (size_t)0);
        ASSERT_EQ(generation, (uint64_t)0);
        ASSERT_EQ(vcs_proof_receiver_ticket_count(fresh), (size_t)0);
        vcs_proof_receiver_free(fresh);
        vcs_package_store_close(store);
        test_rm_rf(dir);
    } TEST_END
    return failures;
}

static int ptl_case_stale_anchored_head(void)
{
    int failures = 0;
    TEST_CASE("proof_ticket: a verified ancestor is not the durable head") {
        ASSERT(ptl_fresh());
        uint8_t ticket_a[VCS_PROOF_TICKET_WIRE_BYTES];
        uint8_t ticket_b[VCS_PROOF_TICKET_WIRE_BYTES];
        uint8_t cp_a[VCS_PROOF_CHECKPOINT_WIRE_BYTES];
        uint8_t cp_b[VCS_PROOF_CHECKPOINT_WIRE_BYTES];
        uint8_t root[32], cp_a_root[32], cp_b_root[32];
        ASSERT(ptf_emit(&g_l, PTF_A, &g_l.base, ptf_pass(),
                        ticket_a, NULL));
        ASSERT(vcs_proof_issuer_log_checkpoint(g_l.logs[PTF_A], 11, cp_a));
        ASSERT(ptf_emit(&g_l, PTF_A, &g_l.base, ptf_pass(),
                        ticket_b, NULL));
        ASSERT(vcs_proof_issuer_log_checkpoint(g_l.logs[PTF_A], 12, cp_b));
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "proof_ticket", "stalehead");
        struct vcs_package_store *store =
            vcs_package_store_open(dir, UINT64_C(8) * 1024 * 1024);
        ASSERT(store != NULL);
        ASSERT(vcs_proof_ticket_store_put(store, ticket_a,
                                          sizeof(ticket_a), root));
        ASSERT(vcs_proof_ticket_store_put(store, cp_a,
                                          sizeof(cp_a), cp_a_root));
        ASSERT(vcs_proof_ticket_store_put(store, ticket_b,
                                          sizeof(ticket_b), root));
        ASSERT(vcs_proof_ticket_store_put(store, cp_b,
                                          sizeof(cp_b), cp_b_root));
        struct vcs_proof_receiver_anchor anchor = {0};
        memcpy(anchor.issuer_pubkey, g_l.pub[PTF_A], 32);
        memcpy(anchor.checkpoint_blob_root, cp_a_root, 32);
        struct vcs_proof_receiver *fresh = vcs_proof_receiver_new();
        ASSERT(fresh != NULL);
        size_t tickets = 0, cps = 0, skipped = 0;
        uint64_t generation = UINT64_C(99);
        ASSERT(!vcs_proof_receiver_rebuild_anchored_bounded(
            fresh, store, &anchor, 1, 4, &tickets, &cps, &skipped,
            &generation));
        ASSERT_EQ(generation, (uint64_t)0);
        ASSERT_EQ(vcs_proof_receiver_ticket_count(fresh), (size_t)0);
        memcpy(anchor.checkpoint_blob_root, cp_b_root, 32);
        ASSERT(vcs_proof_receiver_rebuild_anchored_bounded(
            fresh, store, &anchor, 1, 4, &tickets, &cps, &skipped,
            &generation));
        ASSERT_EQ(tickets, (size_t)2);
        ASSERT_EQ(cps, (size_t)2);
        ASSERT(generation != 0);
        vcs_proof_receiver_free(fresh);
        vcs_package_store_close(store);
        test_rm_rf(dir);
    } TEST_END
    return failures;
}

static int ptl_case_rebuild_boundary(void)
{
    int failures = 0;
    TEST_CASE("proof_ticket: actual store crosses the 4096 object boundary") {
        ASSERT(ptl_fresh());
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "proof_ticket", "boundary");
        struct vcs_package_store *store =
            vcs_package_store_open(dir, UINT64_C(128) * 1024 * 1024);
        ASSERT(store != NULL);
        uint8_t root[32];
        bool ok = true;
        struct ptl_cost_sample cost = ptl_cost_begin();
        for (uint32_t i = 0; i < 4095 && ok; i++) {
            uint8_t blob[4] = {(uint8_t)i, (uint8_t)(i >> 8),
                               (uint8_t)(i >> 16), (uint8_t)(i >> 24)};
            ok = vcs_proof_ticket_store_put(store, blob, sizeof(blob), root);
        }
        ptl_cost_print("populate", 4095u, ok, &cost);
        ASSERT(ok);
        size_t tickets = 0, cps = 0, skipped = 0;
        cost = ptl_cost_begin();
        bool rebuilt = ptl_rebuild(g_l.rx, store, 4095, &tickets,
                                                   &cps, &skipped);
        ptl_cost_print("rebuild", 4095u, rebuilt, &cost);
        ASSERT(rebuilt);
        ASSERT_EQ(skipped, (size_t)4095);
        const uint8_t last[4] = {0xff, 0x0f, 0, 0};
        ASSERT(vcs_proof_ticket_store_put(store, last, sizeof(last), root));
        cost = ptl_cost_begin();
        rebuilt = ptl_rebuild(g_l.rx, store, 4096, &tickets, &cps,
                                             &skipped);
        ptl_cost_print("rebuild", 4096u, rebuilt, &cost);
        ASSERT(rebuilt);
        ASSERT_EQ(skipped, (size_t)4096);
        struct vcs_package_store_summary rows[VCS_PACKAGE_STORE_PAGE_MAX];
        struct vcs_package_store_page page;
        ASSERT_EQ(vcs_package_store_page_summaries(
                      store, NULL, VCS_PACKAGE_STORE_PAGE_MAX, 0, rows,
                      &page), VCS_PACKAGE_STORE_PAGE_OK);
        ASSERT_EQ(page.count, (size_t)VCS_PACKAGE_STORE_PAGE_MAX);
        ASSERT(page.has_more);
        uint8_t stale_cursor[32];
        memcpy(stale_cursor, page.next_root, sizeof(stale_cursor));
        uint64_t stale_generation = page.generation;
        const uint8_t next[4] = {0, 0x10, 0, 0};
        ASSERT(vcs_proof_ticket_store_put(store, next, sizeof(next), root));
        ASSERT_EQ(vcs_package_store_page_summaries(
                      store, stale_cursor, VCS_PACKAGE_STORE_PAGE_MAX,
                      stale_generation, rows, &page),
                  VCS_PACKAGE_STORE_PAGE_STALE);
        bool published = false;
        ASSERT_EQ(vcs_package_store_publish_if_generation(
                      store, stale_generation, ptl_publish_marker,
                      &published), VCS_PACKAGE_STORE_PAGE_STALE);
        ASSERT(!published);
        cost = ptl_cost_begin();
        rebuilt = ptl_rebuild(g_l.rx, store, 4097, &tickets, &cps,
                                             &skipped);
        ptl_cost_print("rebuild", 4097u, rebuilt, &cost);
        ASSERT(rebuilt);
        ASSERT_EQ(skipped, (size_t)4097);
        size_t enumerated = 0;
        bool resume = false;
        uint8_t cursor[32] = {0};
        uint64_t generation = 0;
        do {
            ASSERT_EQ(vcs_package_store_page_summaries(
                          store, resume ? cursor : NULL,
                          VCS_PACKAGE_STORE_PAGE_MAX,
                          resume ? generation : 0, rows, &page),
                      VCS_PACKAGE_STORE_PAGE_OK);
            ASSERT(page.count > 0);
            generation = page.generation;
            memcpy(cursor, page.next_root, sizeof(cursor));
            enumerated += page.count;
            resume = true;
        } while (page.has_more);
        ASSERT_EQ(enumerated, (size_t)4097);
        vcs_package_store_close(store);
        cost = ptl_cost_begin();
        store = vcs_package_store_open(dir, UINT64_C(128) * 1024 * 1024);
        ptl_cost_print("reopen", 4097u, store != NULL, &cost);
        ASSERT(store != NULL);
        cost = ptl_cost_begin();
        rebuilt = ptl_rebuild(g_l.rx, store, 4097, &tickets, &cps,
                                             &skipped);
        ptl_cost_print("rebuild_after_reopen", 4097u, rebuilt, &cost);
        ASSERT(rebuilt);
        ASSERT_EQ(skipped, (size_t)4097);
        struct vcs_package_store *observer =
            vcs_package_store_open(dir, UINT64_C(128) * 1024 * 1024);
        ASSERT(observer != NULL);
        ASSERT_EQ(vcs_package_store_set_class(
                      store, root, VCS_PACKAGE_STORE_CLASS_HOT, 0),
                  VCS_PACKAGE_STORE_OK);
        ASSERT_EQ(vcs_package_store_page_summaries(
                      observer, NULL, VCS_PACKAGE_STORE_PAGE_MAX, 0, rows,
                      &page), VCS_PACKAGE_STORE_PAGE_STALE);
        const uint8_t stale_write[4] = {0xfd, 0xfe, 0xff, 0x7f};
        uint8_t stale_root[32];
        ASSERT(!vcs_proof_ticket_store_put(observer, stale_write,
                                            sizeof(stale_write), stale_root));
        vcs_package_store_close(observer);
        /* The rejected stale writer may have staged an orphan CAS chunk before
         * manifest admission refused. Reopen after that generation change. */
        vcs_package_store_close(store);
        store = vcs_package_store_open(dir, UINT64_C(128) * 1024 * 1024);
        ASSERT(store != NULL);
        const char *large = getenv("Z23_PROOF_STORE_LARGE_CORPUS");
        size_t corpus_rows = large && large[0] == '1' ? 8193u : 4097u;
        if (large && large[0] == '1') {
            cost = ptl_cost_begin();
            for (uint32_t i = 4097; i < 8193 && ok; i++) {
                uint8_t blob[4] = {(uint8_t)i, (uint8_t)(i >> 8),
                                   (uint8_t)(i >> 16), (uint8_t)(i >> 24)};
                ok = vcs_proof_ticket_store_put(store, blob, sizeof(blob),
                                                root);
            }
            ptl_cost_print("populate", 8193u, ok, &cost);
            ASSERT(ok);
            cost = ptl_cost_begin();
            rebuilt = ptl_rebuild(g_l.rx, store, 8193, &tickets,
                                                 &cps, &skipped);
            ptl_cost_print("rebuild", 8193u, rebuilt, &cost);
            ASSERT(rebuilt);
            ASSERT_EQ(skipped, (size_t)8193);
        }
        uint8_t pass[VCS_PROOF_TICKET_WIRE_BYTES];
        uint8_t fail[VCS_PROOF_TICKET_WIRE_BYTES];
        uint8_t cp_a[VCS_PROOF_CHECKPOINT_WIRE_BYTES];
        uint8_t cp_b[VCS_PROOF_CHECKPOINT_WIRE_BYTES];
        uint8_t pass_blob[32], fail_blob[32];
        ASSERT(ptf_emit(&g_l, PTF_A, &g_l.base, ptf_pass(), pass, NULL));
        ASSERT(ptf_emit(&g_l, PTF_B, &g_l.base, ptf_fail(), fail, NULL));
        ASSERT(vcs_proof_issuer_log_checkpoint(g_l.logs[PTF_A], 11, cp_a));
        ASSERT(vcs_proof_issuer_log_checkpoint(g_l.logs[PTF_B], 11, cp_b));
        ASSERT(vcs_proof_ticket_store_put(store, pass, sizeof(pass),
                                          pass_blob));
        ASSERT(vcs_proof_ticket_store_put(store, fail, sizeof(fail),
                                          fail_blob));
        ASSERT(vcs_proof_ticket_store_put(store, cp_a, sizeof(cp_a), root));
        ASSERT(vcs_proof_ticket_store_put(store, cp_b, sizeof(cp_b), root));
        ASSERT_EQ(vcs_package_store_page_summaries(
                      store, NULL, VCS_PACKAGE_STORE_PAGE_MAX, 0, rows,
                      &page), VCS_PACKAGE_STORE_PAGE_OK);
        ASSERT_EQ(page.count, (size_t)VCS_PACKAGE_STORE_PAGE_MAX);
        ASSERT(memcmp(pass_blob, page.next_root, 32) > 0 ||
               memcmp(fail_blob, page.next_root, 32) > 0);
        ASSERT(ptl_rebuild(g_l.rx, store, corpus_rows + 4u, &tickets, &cps,
                                          &skipped));
        ASSERT_EQ(tickets, (size_t)2);
        ASSERT_EQ(cps, (size_t)2);
        struct vcs_proof_ticket_class cls[PTL_CAP];
        struct vcs_proof_reuse_decision decision;
        struct vcs_proof_reuse_request req = {
            .local = &g_l.base, .action_class = VCS_PROOF_ACTION_CHECK,
            .domain = &g_l.domain, .policy = &g_l.policy,
            .artifacts = &g_l.source,
        };
        ASSERT(vcs_proof_reuse_decide(g_l.rx, &req, cls, PTL_CAP,
                                      &decision));
        ASSERT_EQ(decision.outcome, VCS_PROOF_REUSE_REFUSE);
        ASSERT_STR_EQ(decision.reason, VCS_PROOF_OBSERVATION_CONFLICT);
        ASSERT_EQ(decision.eligible_pass, (uint32_t)1);
        ASSERT_EQ(decision.eligible_fail, (uint32_t)1);
        struct vcs_proof_reuse_policy revoked = g_l.policy;
        revoked.revoked = (const uint8_t (*)[32])&g_l.pub[PTF_A];
        revoked.revoked_count = 1;
        req.policy = &revoked;
        ASSERT(vcs_proof_reuse_decide(g_l.rx, &req, cls, PTL_CAP,
                                      &decision));
        ASSERT(decision.outcome != VCS_PROOF_REUSE_HIT_PASS);
        ASSERT_EQ(decision.eligible_pass, (uint32_t)0);
        vcs_package_store_close(store);
        test_rm_rf(dir);
    } TEST_END
    return failures;
}

static int ptl_case_missing_third_fork_checkpoint(void)
{
    int failures = 0;
    TEST_CASE("proof_ticket: absent third signed branch isolates a forked issuer") {
        ASSERT(ptl_fresh());
        uint8_t original[VCS_PROOF_TICKET_WIRE_BYTES];
        uint8_t forked[VCS_PROOF_TICKET_WIRE_BYTES];
        uint8_t absent[VCS_PROOF_TICKET_WIRE_BYTES];
        uint8_t cp[VCS_PROOF_CHECKPOINT_WIRE_BYTES], root[32];
        ASSERT(ptf_emit(&g_l, PTF_A, &g_l.base, ptf_pass(), original, NULL));
        struct vcs_proof_issuer_log *fork = ptl_fork();
        ASSERT(fork != NULL);
        ASSERT(ptl_append(fork, ptf_fail(), forked));
        vcs_proof_issuer_log_free(fork);
        struct vcs_proof_issuer_log *third = ptl_fork();
        ASSERT(third != NULL);
        struct ptf_spec third_spec = ptf_pass();
        third_spec.created = 1790000001u;
        ASSERT(ptl_append(third, third_spec, absent));
        ASSERT(vcs_proof_issuer_log_checkpoint(third, 12, cp));
        vcs_proof_issuer_log_free(third);
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "proof_ticket", "missingfork");
        struct vcs_package_store *store =
            vcs_package_store_open(dir, UINT64_C(8) * 1024 * 1024);
        ASSERT(store != NULL);
        ASSERT(vcs_proof_ticket_store_put(store, original, sizeof(original), root));
        ASSERT(vcs_proof_ticket_store_put(store, forked, sizeof(forked), root));
        ASSERT(vcs_proof_ticket_store_put(store, cp, sizeof(cp), root));
        size_t tickets = 0, cps = 0, skipped = 0;
        ASSERT(ptl_rebuild(g_l.rx, store, 3, &tickets, &cps, &skipped));
        ASSERT_EQ(cps, (size_t)0);
        ASSERT_EQ(vcs_proof_receiver_ticket_count(g_l.rx), (size_t)2);
        ASSERT(vcs_proof_receiver_issuer_equivocating(g_l.rx, g_l.pub[PTF_A]));
        ASSERT(vcs_proof_receiver_issuer_history_incomplete(g_l.rx,
                                                            g_l.pub[PTF_A]));
        ASSERT_EQ(vcs_proof_receiver_issuer_leaves(g_l.rx, g_l.pub[PTF_A]),
                  (uint64_t)0);
        vcs_package_store_close(store);
        test_rm_rf(dir);
    } TEST_END
    return failures;
}

int ptf_log_cases(void)
{
    int failures = 0;
    failures += ptl_case_issuer_restore();
    failures += ptl_case_checkpoint_blob_head();
    failures += ptl_case_store_issuer_restore();
    failures += ptl_case_store_issuer_missing_cas();
    failures += ptl_case_catalog_budget();
    failures += ptl_case_page_budget_conflict();
    failures += ptl_case_same_count();
    failures += ptl_case_same_size_ancestry();
    failures += ptl_case_late_same_size_fork();
    failures += ptl_case_fork();
    failures += ptl_case_not_extension();
    failures += ptl_case_delta_bytes();
    failures += ptl_case_artifact();
    failures += ptl_case_output_conflict();
    failures += ptl_case_rebuild();
    failures += ptl_case_empty_issuer_rebuild();
    failures += ptl_case_rebuild_missing_ticket();
    failures += ptl_case_rebuild_missing_chunk();
    failures += ptl_case_rebuild_mid_scan_resume();
    failures += ptl_case_staged_ticket();
    failures += ptl_case_deleted_history_resume();
    failures += ptl_case_late_replay_failure();
    failures += ptl_case_deleted_head();
    failures += ptl_case_rebuild_conflict();
    failures += ptl_case_seq_reorder();
    failures += ptl_case_signed_seq_fork();
    failures += ptl_case_missing_third_fork_checkpoint();
    failures += ptl_case_live_signed_seq_fork();
    failures += ptl_case_rebuild_after_live_seq_fork();
    failures += ptl_case_rebuild_fork_checkpoint_alloc();
    failures += ptl_case_rebuild_invalid_outputs();
    failures += ptl_case_rebuild_equivocation();
    failures += ptl_case_rebuild_preserves_covered_branch();
    failures += ptl_case_rebuild_preserves_checkpoint_head();
    failures += ptl_case_rebuild_corrupt_index();
    failures += ptl_case_deleted_catalog_manifest();
    failures += ptl_case_fresh_anchored_head();
    failures += ptl_case_stale_anchored_head();
    failures += ptl_case_changed_cas_during_rebuild();
    failures += ptl_case_changed_cas_after_recheck();
    failures += ptl_case_checked_issuer_publish();
    if (getenv("Z23_PROOF_STORE_BOUNDARY_RED"))
        failures += ptl_case_rebuild_boundary();
    ptf_free(&g_l);
    return failures;
}
