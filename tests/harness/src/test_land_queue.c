/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_land_queue - the gate on the landing queue.
 *
 * The queue makes N agents cost one gate run. Two properties must hold
 * absolutely:
 *
 *  1. A landing cannot be fabricated. Five attempts land work through the
 *     five ways "the gate did not run" could be confused with "passed" (no
 *     gate run, a run that never contained this submission, a red run, a
 *     run that skipped its groups, a run that cannot say which tree it
 *     proved); each must be refused by name.
 *
 *  2. A bad batch refuses only the culprit. case_bisect drives the lander's
 *     recursion (gate three, red; gate the halves; land the innocent, refuse
 *     the guilty) and checks every resulting state.
 *
 * The rest guards the properties the receipts stand on:
 *
 *  3. The queue is the log: no sidecar state, so a restart is invisible.
 *
 *  4. Identical content, identical bytes: equal submissions encode
 *     byte-equal and changing any field changes the bytes.
 *
 *  5. Four submitters do not corrupt or convoy: four processes append
 *     concurrently to one queue file; the chain verifies and every
 *     submission is present exactly once, with no gap.
 *
 *  6. Submitting never waits for a gate: one submit writes exactly one frame
 *     and its cost does not grow with queue depth. Not a stopwatch
 *     (tools/lint/check_no_wallclock_assertion.sh forbids it); latency is
 *     reported by tools/dev/land_bench.sh.
 *
 *  7. A verdict is checkable by whoever receives it: its content address is
 *     computed from four public facts (submitted commit, integration commit,
 *     gating tree identity, verdict), so a second machine recomputes it
 *     without this queue.
 */

#include "test/test_core.h"

#include "land/land_queue.h"
#include "util/spawn.h"

#include <stdlib.h>
#include <string.h>
#if !defined(_WIN32)
#include <sys/wait.h>
#endif
#include <unistd.h>

#if !defined(_WIN32)
#define LAND_CLI_TEST
#define main land_cli_main
#include "../../../tools/land/land_main.c"
#undef main
#undef LAND_CLI_TEST
#endif

#define LQ_CHECK(name, expr)                                            \
    do {                                                                \
        const bool lq_ok_ = (expr);                                     \
        if (!lq_ok_) failures++;                                        \
        printf("land_queue: %s %s\n", lq_ok_ ? "OK  " : "FAIL", (name)); \
    } while (0)

/* Two distinct 20-byte shas, spelled as hex. */
static const char *const k_head_a =
    "1111111111111111111111111111111111111111";
static const char *const k_head_b =
    "2222222222222222222222222222222222222222";
static const char *const k_integ =
    "abcdef0123456789abcdef0123456789abcdef01";

static void fill_submit(struct land_submit *s, const char *branch,
                        const char *head, const char *who, const char *note)
{
    memset(s, 0, sizeof *s);
    snprintf(s->branch, sizeof s->branch, "%s", branch);
    snprintf(s->submitter, sizeof s->submitter, "%s", who);
    snprintf(s->note, sizeof s->note, "%s", note ? note : "");
    (void)land_sha_parse(head, s->head);
}

/* Submit one branch and hand back its seq. */
static uint64_t submit_one(struct land_queue *q, const char *branch,
                           const char *head)
{
    struct land_submit s;
    fill_submit(&s, branch, head, "test-agent", "");
    uint64_t seq = 0;
    if (land_queue_submit(q, &s, &seq) != LAND_OK)
        return 0;
    return seq;
}

/* A gating tree's identity, as source-identity.sh would report one. */
static const char *const k_gate_id =
    "3333333333333333333333333333333333333333333333333333333333333333";

/* Record one gate run over `n` submissions and hand back its seq. */
static uint64_t gate_over(struct land_queue *q, enum land_gate_outcome outcome,
                          bool stress, const uint64_t *seqs, uint32_t n)
{
    struct land_gate_run g;
    memset(&g, 0, sizeof g);
    g.outcome = outcome;
    g.stress = stress;
    (void)land_sha_parse(k_integ, g.integration);
    (void)land_id32_parse(k_gate_id, g.gate_id);
    g.member_count = n;
    for (uint32_t i = 0; i < n; i++)
        g.member_seq[i] = seqs[i];
    uint64_t seq = 0;
    if (land_queue_gate_run(q, &g, &seq) != LAND_OK)
        return 0;
    return seq;
}

static enum land_status settle(struct land_queue *q, uint64_t submit_seq,
                               enum land_state state, uint64_t gate_run_seq)
{
    struct land_verdict v;
    memset(&v, 0, sizeof v);
    v.state = state;
    v.submit_seq = submit_seq;
    v.gate_run_seq = gate_run_seq;
    const struct land_entry *e = land_queue_find_seq(q, submit_seq);
    if (e) {
        memcpy(v.branch, e->submit.branch, sizeof v.branch);
        memcpy(v.head, e->submit.head, sizeof v.head);
    } else {
        snprintf(v.branch, sizeof v.branch, "unknown");
    }
    snprintf(v.reason, sizeof v.reason, "test");
    if (state == LAND_STATE_LANDED)
        (void)land_sha_parse(k_integ, v.integration);
    return land_queue_verdict(q, &v, NULL);
}

static enum land_state state_of(struct land_queue *q, uint64_t seq)
{
    const struct land_entry *e = land_queue_find_seq(q, seq);
    return e ? e->state : LAND_STATE_QUEUED;
}

/* ── 1. submit costs nothing and the queue is the log ──────────────────── */

static int case_gate_member_bounds(void)
{
    int failures = 0;
    char dir[512], path[640];
    test_make_tmpdir(dir, sizeof dir, "land", "member-bounds");
    snprintf(path, sizeof path, "%s/queue.chainlog", dir);
    struct zcl_chainlog_report rep;
    struct land_queue *q = land_queue_open(path, &rep);
    LQ_CHECK("member bounds: fixture opens", q != NULL);
    if (!q) {
        test_cleanup_tmpdir(dir);
        return failures;
    }
    uint64_t a = submit_one(q, "lane/bounds", k_head_a);
    LQ_CHECK("member bounds: submission is seq 1", a == 1);
    const struct land_entry *e = land_queue_find_seq(q, a);
    if (!e) {
        land_queue_close(q);
        test_cleanup_tmpdir(dir);
        return failures + 1;
    }
    struct land_entry before;
    memcpy(&before, e, sizeof before);
    struct { struct land_gate_run gate; uint64_t sentinel; } fixture = {0};
    fixture.gate.outcome = LAND_GATE_GREEN;
    fixture.gate.stress = true;
    (void)land_sha_parse(k_integ, fixture.gate.integration);
    (void)land_id32_parse(k_gate_id, fixture.gate.gate_id);
    for (uint32_t i = 0; i < LAND_MEMBERS_MAX; i++)
        fixture.gate.member_seq[i] = a;
    /* Invalid counts must win over an unknown member. This also makes
     * the parent and mutation fail by status before an invalid read. */
    fixture.gate.member_seq[0] = 0;
    const uint32_t counts[] = {LAND_MEMBERS_MAX + 1u, 0, UINT32_MAX};
    const char *const names[] = {
        "member bounds: 257 refuses encode without changing state or output",
        "member bounds: zero refuses encode without changing state or output",
        "member bounds: UINT32_MAX refuses encode without changing state or output"
    };
    for (size_t i = 0; i < sizeof counts / sizeof counts[0]; i++) {
        fixture.gate.member_count = counts[i];
        uint64_t out = UINT64_MAX;
        enum land_status status = land_queue_gate_run(q, &fixture.gate, &out);
        LQ_CHECK(names[i], status == LAND_ERR_ENCODE && out == UINT64_MAX &&
                 land_queue_count(q) == 1 && memcmp(e, &before, sizeof before) == 0);
    }
    land_queue_close(q);
    q = land_queue_open(path, &rep);
    LQ_CHECK("member bounds: refusals append no frame", q && rep.records == 1);
    if (q) {
        const struct land_entry *replayed = land_queue_find_seq(q, a);
        LQ_CHECK("member bounds: refused queue replays unchanged",
                 land_queue_count(q) == 1 && replayed &&
                     memcmp(replayed, &before, sizeof before) == 0);
        fixture.gate.member_count = LAND_MEMBERS_MAX;
        fixture.gate.member_seq[0] = a;
        uint64_t out = 0;
        LQ_CHECK("member bounds: 256 remains valid at next log sequence",
                 land_queue_gate_run(q, &fixture.gate, &out) == LAND_OK && out == 2);
        land_queue_close(q);
    }
    test_cleanup_tmpdir(dir);
    return failures;
}

static int case_submit_and_pending(void)
{
    int failures = 0;
    char dir[512];
    test_make_tmpdir(dir, sizeof dir, "land", "submit");
    char path[640];
    snprintf(path, sizeof path, "%s/queue.chainlog", dir);

    struct zcl_chainlog_report rep;
    struct land_queue *q = land_queue_open(path, &rep);
    LQ_CHECK("a fresh queue opens", q != NULL);
    LQ_CHECK("and is empty", q && land_queue_count(q) == 0);
    if (!q) {
        test_cleanup_tmpdir(dir);
        return failures;
    }

    uint64_t a = submit_one(q, "lane/alpha", k_head_a);
    uint64_t b = submit_one(q, "lane/beta", k_head_b);
    LQ_CHECK("two submissions get dense sequence numbers", a == 1 && b == 2);
    LQ_CHECK("both are QUEUED immediately",
             state_of(q, a) == LAND_STATE_QUEUED &&
                 state_of(q, b) == LAND_STATE_QUEUED);

    const struct land_entry *e = land_queue_find_branch(q, "lane/alpha");
    LQ_CHECK("a branch can be looked up by name", e && e->seq == a);
    uint8_t want_a[LAND_SHA_BYTES];
    (void)land_sha_parse(k_head_a, want_a);
    LQ_CHECK("and carries the exact head that was submitted",
             e && memcmp(e->submit.head, want_a, LAND_SHA_BYTES) == 0);

    /* A resubmitted branch is a new entry; status answers about the live
     * one, and the first entry's receipt is kept. */
    uint64_t again = submit_one(q, "lane/alpha", k_head_b);
    const struct land_entry *live = land_queue_find_branch(q, "lane/alpha");
    LQ_CHECK("a resubmitted branch is a second entry, not an overwrite",
             again == 3 && land_queue_count(q) == 3 && live && live->seq == again);

    land_queue_close(q);
    test_cleanup_tmpdir(dir);
    return failures;
}

/* ── 2. THE SEAM: a landing cannot be fabricated ───────────────────────── */

static int case_landing_needs_a_real_gate(void)
{
    int failures = 0;
    char dir[512];
    test_make_tmpdir(dir, sizeof dir, "land", "seam");
    char path[640];
    snprintf(path, sizeof path, "%s/queue.chainlog", dir);

    struct zcl_chainlog_report rep;
    struct land_queue *q = land_queue_open(path, &rep);
    if (!q) {
        LQ_CHECK("the queue opens", false);
        test_cleanup_tmpdir(dir);
        return failures;
    }

    uint64_t a = submit_one(q, "lane/alpha", k_head_a);
    uint64_t b = submit_one(q, "lane/beta", k_head_b);

    /* (i) No gate run at all: a crashed agent or a lander that lost its log
     * must never settle work as landed. */
    LQ_CHECK("LANDED with no gate run is refused",
             settle(q, a, LAND_STATE_LANDED, 0) == LAND_ERR_NO_GATE_RUN);
    LQ_CHECK("and the submission is still QUEUED, not landed",
             state_of(q, a) == LAND_STATE_QUEUED);

    /* (ii) A gate run that exists but never contained this submission. */
    uint64_t only_b[] = { b };
    uint64_t gr_b = gate_over(q, LAND_GATE_GREEN, true, only_b, 1);
    LQ_CHECK("a green gate run records", gr_b != 0);
    LQ_CHECK("LANDED against a gate run that did not contain it is refused",
             settle(q, a, LAND_STATE_LANDED, gr_b) == LAND_ERR_NO_GATE_RUN);

    /* (iii) A gate run that DID contain it, and was red. */
    uint64_t both[] = { a, b };
    uint64_t gr_red = gate_over(q, LAND_GATE_RED, true, both, 2);
    LQ_CHECK("LANDED against a red gate run is refused",
             settle(q, a, LAND_STATE_LANDED, gr_red) == LAND_ERR_GATE_NOT_GREEN);

    /* (iv) Green, containing it, but the run skipped its groups (without
     * ZCL_STRESS_TESTS=1 four groups self-skip and `make pre-push-ci` refuses the receipt). */
    uint64_t gr_soft = gate_over(q, LAND_GATE_GREEN, false, both, 2);
    LQ_CHECK("LANDED against a gate run that skipped its groups is refused",
             settle(q, a, LAND_STATE_LANDED, gr_soft) ==
                 LAND_ERR_GATE_NOT_STRESSED);

    /* (v) Green, stressed, containing it, but the runner could not say
     * which tree it gated: a receipt no second machine can check. */
    struct land_gate_run anon;
    memset(&anon, 0, sizeof anon);
    anon.outcome = LAND_GATE_GREEN;
    anon.stress = true;
    (void)land_sha_parse(k_integ, anon.integration);
    /* gate_id deliberately left all zero */
    anon.member_count = 2;
    anon.member_seq[0] = a;
    anon.member_seq[1] = b;
    uint64_t gr_anon = 0;
    LQ_CHECK("an unidentified gate run still records honestly",
             land_queue_gate_run(q, &anon, &gr_anon) == LAND_OK);
    LQ_CHECK("but LANDED behind an unidentifiable tree is refused",
             settle(q, a, LAND_STATE_LANDED, gr_anon) ==
                 LAND_ERR_GATE_UNIDENTIFIED);

    LQ_CHECK("after five attempts nothing has landed",
             state_of(q, a) != LAND_STATE_LANDED);

    /* Refusing ungated work is always sound and needs no backing. */
    LQ_CHECK("REFUSED needs no gate run behind it",
             settle(q, a, LAND_STATE_REFUSED, 0) == LAND_OK);
    LQ_CHECK("and the submission is REFUSED, never LANDED",
             state_of(q, a) == LAND_STATE_REFUSED);
    LQ_CHECK("a second verdict for a settled submission is refused",
             settle(q, a, LAND_STATE_LANDED, 0) == LAND_ERR_ALREADY_FINAL);

    /* The real thing succeeds, so the refusals above are not refuse-everything. */
    uint64_t gr_ok = gate_over(q, LAND_GATE_GREEN, true, both, 2);
    LQ_CHECK("a green, stress-enabled run containing it does land",
             settle(q, b, LAND_STATE_LANDED, gr_ok) == LAND_OK);
    LQ_CHECK("and the state is LANDED", state_of(q, b) == LAND_STATE_LANDED);

    struct land_metrics m;
    land_queue_metrics(q, &m);
    LQ_CHECK("every landing in the log is backed", m.unbacked_landings == 0);

    land_queue_close(q);
    test_cleanup_tmpdir(dir);
    return failures;
}

/* ── 3. a red batch bisects: innocent lands, culprit is refused ─────────
 * Drives the lander's recursion: gate all three (red), split, gate the
 * halves, settle from each smaller run. */

static int case_bisect(void)
{
    int failures = 0;
    char dir[512];
    test_make_tmpdir(dir, sizeof dir, "land", "bisect");
    char path[640];
    snprintf(path, sizeof path, "%s/queue.chainlog", dir);

    struct zcl_chainlog_report rep;
    struct land_queue *q = land_queue_open(path, &rep);
    if (!q) {
        LQ_CHECK("the queue opens", false);
        test_cleanup_tmpdir(dir);
        return failures;
    }

    uint64_t a = submit_one(q, "lane/good-a", k_head_a);
    uint64_t b = submit_one(q, "lane/good-b", k_head_b);
    uint64_t c = submit_one(q, "lane/bad-c", k_head_a);

    /* Batch of three: RED. Nothing settles; a red batch is no verdict about anyone. */
    uint64_t all[] = { a, b, c };
    uint64_t gr_all = gate_over(q, LAND_GATE_RED, true, all, 3);
    LQ_CHECK("the red batch is recorded", gr_all != 0);
    LQ_CHECK("a red batch settles nobody",
             state_of(q, a) == LAND_STATE_GATING &&
                 state_of(q, b) == LAND_STATE_GATING &&
                 state_of(q, c) == LAND_STATE_GATING);

    /* First half: green. Both land off ONE further gate run. */
    uint64_t half_a[] = { a };
    uint64_t gr_a = gate_over(q, LAND_GATE_GREEN, true, half_a, 1);
    LQ_CHECK("the innocent half lands",
             settle(q, a, LAND_STATE_LANDED, gr_a) == LAND_OK);

    uint64_t half_b[] = { b, c };
    uint64_t gr_bc = gate_over(q, LAND_GATE_RED, true, half_b, 2);
    LQ_CHECK("the half holding the culprit is red", gr_bc != 0);

    uint64_t only_b[] = { b };
    uint64_t gr_b = gate_over(q, LAND_GATE_GREEN, true, only_b, 1);
    LQ_CHECK("the second innocent lands once gated alone",
             settle(q, b, LAND_STATE_LANDED, gr_b) == LAND_OK);

    uint64_t only_c[] = { c };
    uint64_t gr_c = gate_over(q, LAND_GATE_RED, true, only_c, 1);
    LQ_CHECK("the culprit, gated alone, is red", gr_c != 0);
    LQ_CHECK("and is REFUSED, not landed",
             settle(q, c, LAND_STATE_REFUSED, gr_c) == LAND_OK);

    LQ_CHECK("innocent work landed",
             state_of(q, a) == LAND_STATE_LANDED &&
                 state_of(q, b) == LAND_STATE_LANDED);
    LQ_CHECK("guilty work did not",
             state_of(q, c) == LAND_STATE_REFUSED);
    /* The culprit could not have landed by mistake: its only green gate runs never contained it. */
    LQ_CHECK("and could not be landed against the innocents' runs",
             land_queue_check_landable(q, c, gr_a) == LAND_ERR_NO_GATE_RUN &&
                 land_queue_check_landable(q, c, gr_b) == LAND_ERR_NO_GATE_RUN);

    struct land_metrics m;
    land_queue_metrics(q, &m);
    LQ_CHECK("two landed, one refused", m.landed == 2 && m.refused == 1);
    LQ_CHECK("five gate runs were spent", m.gate_runs == 5);
    LQ_CHECK("nothing in the log is an unbacked landing",
             m.unbacked_landings == 0);

    land_queue_close(q);
    test_cleanup_tmpdir(dir);
    return failures;
}

/* ── 4. a timeout is a refusal, never a landing ────────────────────────── */

static int case_timeout(void)
{
    int failures = 0;
    char dir[512];
    test_make_tmpdir(dir, sizeof dir, "land", "timeout");
    char path[640];
    snprintf(path, sizeof path, "%s/queue.chainlog", dir);

    struct zcl_chainlog_report rep;
    struct land_queue *q = land_queue_open(path, &rep);
    if (!q) {
        LQ_CHECK("the queue opens", false);
        test_cleanup_tmpdir(dir);
        return failures;
    }

    uint64_t a = submit_one(q, "lane/slow", k_head_a);
    uint64_t only_a[] = { a };
    uint64_t gr = gate_over(q, LAND_GATE_TIMEOUT, true, only_a, 1);
    LQ_CHECK("a timed-out gate run is recorded as what it was", gr != 0);
    LQ_CHECK("a timed-out run cannot back a landing",
             land_queue_check_landable(q, a, gr) == LAND_ERR_GATE_NOT_GREEN);
    LQ_CHECK("the submission settles as TIMEOUT",
             settle(q, a, LAND_STATE_TIMEOUT, gr) == LAND_OK);
    LQ_CHECK("and is not landed", state_of(q, a) == LAND_STATE_TIMEOUT);

    land_queue_close(q);
    test_cleanup_tmpdir(dir);
    return failures;
}

/* ── 5. a restart is invisible ─────────────────────────────────────────── */

static int case_restart(void)
{
    int failures = 0;
    char dir[512];
    test_make_tmpdir(dir, sizeof dir, "land", "restart");
    char path[640];
    snprintf(path, sizeof path, "%s/queue.chainlog", dir);

    struct zcl_chainlog_report rep;
    struct land_queue *q = land_queue_open(path, &rep);
    if (!q) {
        LQ_CHECK("the queue opens", false);
        test_cleanup_tmpdir(dir);
        return failures;
    }
    uint64_t a = submit_one(q, "lane/alpha", k_head_a);
    uint64_t b = submit_one(q, "lane/beta", k_head_b);
    uint64_t both[] = { a, b };
    uint64_t gr = gate_over(q, LAND_GATE_GREEN, true, both, 2);
    (void)settle(q, a, LAND_STATE_LANDED, gr);
    struct land_metrics before;
    land_queue_metrics(q, &before);
    land_queue_close(q);

    /* Nothing was kept in RAM. */
    struct zcl_chainlog_report rep2;
    struct land_queue *again = land_queue_open(path, &rep2);
    LQ_CHECK("the queue reopens", again != NULL);
    if (!again) {
        test_cleanup_tmpdir(dir);
        return failures;
    }
    struct land_metrics after;
    land_queue_metrics(again, &after);
    LQ_CHECK("with nothing torn", rep2.torn_bytes == 0);
    LQ_CHECK("the same submissions", after.submissions == before.submissions);
    LQ_CHECK("the same states",
             after.landed == before.landed && after.queued == before.queued &&
                 after.gating == before.gating);
    LQ_CHECK("the same gate runs", after.gate_runs == before.gate_runs);
    LQ_CHECK("the unsettled submission is still pending after a restart",
             state_of(again, b) == LAND_STATE_GATING);
    LQ_CHECK("the settled one is still landed",
             state_of(again, a) == LAND_STATE_LANDED);
    /* The seam still holds after a restart: the backing check is recomputed from the log. */
    LQ_CHECK("the backing check survives the restart",
             land_queue_check_landable(again, b, gr) == LAND_OK);

    /* Appending after a restart continues the sequence (receipts stay totally ordered). */
    uint64_t c = submit_one(again, "lane/gamma", k_head_a);
    LQ_CHECK("a submission after a restart continues the ordering",
             c > b && c > gr);

    land_queue_close(again);
    test_cleanup_tmpdir(dir);
    return failures;
}

/* ── 6. receipts are ordered and the chain verifies ────────────────────── */

static int case_chain_verifies(void)
{
    int failures = 0;
    char dir[512];
    test_make_tmpdir(dir, sizeof dir, "land", "chain");
    char path[640];
    snprintf(path, sizeof path, "%s/queue.chainlog", dir);

    struct zcl_chainlog_report rep;
    struct land_queue *q = land_queue_open(path, &rep);
    if (!q) {
        LQ_CHECK("the queue opens", false);
        test_cleanup_tmpdir(dir);
        return failures;
    }
    uint64_t a = submit_one(q, "lane/alpha", k_head_a);
    uint64_t b = submit_one(q, "lane/beta", k_head_b);
    uint64_t both[] = { a, b };
    uint64_t gr = gate_over(q, LAND_GATE_GREEN, true, both, 2);
    (void)settle(q, a, LAND_STATE_LANDED, gr);
    (void)settle(q, b, LAND_STATE_LANDED, gr);
    land_queue_close(q);

    uint8_t stream[32];
    land_stream_id(stream);
    struct zcl_chainlog_report vrep;
    LQ_CHECK("the receipt chain verifies from the outside",
             zcl_chainlog_verify(path, stream, &vrep) == ZCL_CHAINLOG_OK);
    LQ_CHECK("with every frame accounted for (2 submits, 1 run, 2 verdicts)",
             vrep.records == 5);
    LQ_CHECK("and receipts are ordered by the log's own dense seq",
             a == 1 && b == 2 && gr == 3);

    /* A queue log is bound to its stream; its frames cannot be replayed into another chainlog. */
    uint8_t other[32];
    memset(other, 0x5A, sizeof other);
    struct zcl_chainlog_report orep;
    LQ_CHECK("and cannot be read as a log of something else",
             zcl_chainlog_verify(path, other, &orep) ==
                 ZCL_CHAINLOG_STREAM_MISMATCH);

    /* An edit is named: flip one payload bit and the chain must refuse at that frame. */
    FILE *f = fopen(path, "r+b");
    LQ_CHECK("the log file opens for a tamper test", f != NULL);
    if (f) {
        /* Byte 80 is inside the first frame's payload (past the 64-byte header and 16-byte frame prefix). */
        (void)fseek(f, 80, SEEK_SET);
        int ch = fgetc(f);
        (void)fseek(f, 80, SEEK_SET);
        (void)fputc(ch ^ 0x01, f);
        (void)fclose(f);
        struct zcl_chainlog_report trep;
        LQ_CHECK("an edited receipt refuses as a broken chain",
                 zcl_chainlog_verify(path, stream, &trep) ==
                     ZCL_CHAINLOG_BROKEN_CHAIN);
        LQ_CHECK("and names the first frame that does not verify",
                 trep.first_bad_seq == 1);
    }

    test_cleanup_tmpdir(dir);
    return failures;
}

/* ── 7. identical content, identical bytes ─────────────────────────────── */

static int case_canonical_bytes(void)
{
    int failures = 0;
    uint8_t one[1024], two[1024];
    struct land_submit s1, s2;

    fill_submit(&s1, "lane/alpha", k_head_a, "agent-a", "a note");
    fill_submit(&s2, "lane/alpha", k_head_a, "agent-a", "a note");
    /* Poison the buffers differently so an unwritten reserved byte shows as a difference. */
    memset(one, 0xAA, sizeof one);
    memset(two, 0x55, sizeof two);
    size_t n1 = land_submit_encode(&s1, one, sizeof one);
    size_t n2 = land_submit_encode(&s2, two, sizeof two);
    LQ_CHECK("a submission encodes", n1 > 0 && n1 == n2);
    LQ_CHECK("identical content gives identical bytes",
             n1 > 0 && memcmp(one, two, n1) == 0);

    /* Every field is load-bearing: changing any one must change the bytes. */
    struct land_submit v;
    size_t nv;

    fill_submit(&v, "lane/beta", k_head_a, "agent-a", "a note");
    nv = land_submit_encode(&v, two, sizeof two);
    LQ_CHECK("a different branch gives different bytes",
             nv == 0 || nv != n1 || memcmp(one, two, n1) != 0);

    fill_submit(&v, "lane/alpha", k_head_b, "agent-a", "a note");
    nv = land_submit_encode(&v, two, sizeof two);
    LQ_CHECK("a different head gives different bytes",
             nv == n1 && memcmp(one, two, n1) != 0);

    fill_submit(&v, "lane/alpha", k_head_a, "agent-b", "a note");
    nv = land_submit_encode(&v, two, sizeof two);
    LQ_CHECK("a different submitter gives different bytes",
             nv == n1 && memcmp(one, two, n1) != 0);

    fill_submit(&v, "lane/alpha", k_head_a, "agent-a", "b note");
    nv = land_submit_encode(&v, two, sizeof two);
    LQ_CHECK("a different note gives different bytes",
             nv == n1 && memcmp(one, two, n1) != 0);

    /* Round trip. */
    struct land_submit back;
    LQ_CHECK("a submission decodes back to itself",
             land_submit_decode(one, n1, &back) &&
                 strcmp(back.branch, s1.branch) == 0 &&
                 strcmp(back.submitter, s1.submitter) == 0 &&
                 strcmp(back.note, s1.note) == 0 &&
                 memcmp(back.head, s1.head, LAND_SHA_BYTES) == 0);

    /* Trailing bytes are refused, not ignored. */
    LQ_CHECK("a trailing byte is refused, not ignored",
             !land_submit_decode(one, n1 + 1, &back));
    LQ_CHECK("a truncated record is refused",
             !land_submit_decode(one, n1 - 1, &back));

    /* A control character or an over-long branch is refused at the encoder. */
    fill_submit(&v, "lane/a\nb", k_head_a, "agent-a", "");
    LQ_CHECK("a newline in a branch name has no encoding",
             land_submit_encode(&v, two, sizeof two) == 0);
    memset(&v, 0, sizeof v);
    memset(v.branch, 'x', LAND_BRANCH_MAX + 1);
    snprintf(v.submitter, sizeof v.submitter, "agent-a");
    LQ_CHECK("an over-long branch has no encoding",
             land_submit_encode(&v, two, sizeof two) == 0);

    /* The same discipline over the other two kinds. */
    struct land_gate_run g1, g2;
    memset(&g1, 0, sizeof g1);
    g1.outcome = LAND_GATE_GREEN;
    g1.stress = true;
    (void)land_sha_parse(k_integ, g1.integration);
    g1.member_count = 2;
    g1.member_seq[0] = 7;
    g1.member_seq[1] = 9;
    g2 = g1;
    memset(one, 0xAA, sizeof one);
    memset(two, 0x55, sizeof two);
    n1 = land_gate_run_encode(&g1, one, sizeof one);
    n2 = land_gate_run_encode(&g2, two, sizeof two);
    LQ_CHECK("a gate run encodes identically for identical content",
             n1 > 0 && n1 == n2 && memcmp(one, two, n1) == 0);
    g2.stress = false;
    n2 = land_gate_run_encode(&g2, two, sizeof two);
    LQ_CHECK("dropping the stress flag changes the bytes",
             n2 == n1 && memcmp(one, two, n1) != 0);
    g2 = g1;
    g2.member_seq[1] = 10;
    n2 = land_gate_run_encode(&g2, two, sizeof two);
    LQ_CHECK("a different member set changes the bytes",
             n2 == n1 && memcmp(one, two, n1) != 0);
    struct land_gate_run gback;
    LQ_CHECK("a gate run decodes back to itself",
             land_gate_run_decode(one, n1, &gback) &&
                 gback.outcome == g1.outcome && gback.stress == g1.stress &&
                 gback.member_count == 2 && gback.member_seq[0] == 7 &&
                 gback.member_seq[1] == 9);

    struct land_verdict d1, d2;
    memset(&d1, 0, sizeof d1);
    d1.state = LAND_STATE_LANDED;
    d1.submit_seq = 4;
    d1.gate_run_seq = 6;
    snprintf(d1.branch, sizeof d1.branch, "lane/alpha");
    snprintf(d1.reason, sizeof d1.reason, "green in a batch of 3");
    (void)land_sha_parse(k_head_a, d1.head);
    (void)land_sha_parse(k_integ, d1.integration);
    d2 = d1;
    memset(one, 0xAA, sizeof one);
    memset(two, 0x55, sizeof two);
    n1 = land_verdict_encode(&d1, one, sizeof one);
    n2 = land_verdict_encode(&d2, two, sizeof two);
    LQ_CHECK("a verdict encodes identically for identical content",
             n1 > 0 && n1 == n2 && memcmp(one, two, n1) == 0);
    d2.gate_run_seq = 7;
    n2 = land_verdict_encode(&d2, two, sizeof two);
    LQ_CHECK("naming a different gate run changes the bytes",
             n2 == n1 && memcmp(one, two, n1) != 0);
    struct land_verdict dback;
    LQ_CHECK("a verdict decodes back to itself",
             land_verdict_decode(one, n1, &dback) &&
                 dback.state == LAND_STATE_LANDED && dback.submit_seq == 4 &&
                 dback.gate_run_seq == 6 &&
                 strcmp(dback.branch, "lane/alpha") == 0);
    /* QUEUED and GATING are derived by replay; asserting one as a verdict is refused. */
    d2 = d1;
    d2.state = LAND_STATE_QUEUED;
    LQ_CHECK("a derived state has no verdict encoding",
             land_verdict_encode(&d2, two, sizeof two) == 0);

    /* A sha is one spelling or a refusal. */
    uint8_t sha[LAND_SHA_BYTES];
    char hex[LAND_SHA_HEX + 1];
    LQ_CHECK("a full lowercase sha parses", land_sha_parse(k_head_a, sha));
    land_sha_format(sha, hex);
    LQ_CHECK("and formats back identically", strcmp(hex, k_head_a) == 0);
    LQ_CHECK("an uppercase sha is refused",
             !land_sha_parse("ABCDEF0123456789ABCDEF0123456789ABCDEF01", sha));
    LQ_CHECK("a short sha is refused", !land_sha_parse("abcdef01", sha));
    LQ_CHECK("a non-hex sha is refused",
             !land_sha_parse("zzcdef0123456789abcdef0123456789abcdef01", sha));

    return failures;
}

/* ── 8. four submitters racing, which is the real fleet ────────────────
 * Four real processes, not threads (the lock is a whole-file lock in
 * platform/modules/platform). Each appends to one queue file; afterwards
 * the chain must verify and every submission be present exactly once with
 * dense sequence numbers. */

#define RACE_EACH 12
#define RACE_WRITERS 4

static int race_child_run(const char *path, const char *prefix)
{
    struct zcl_chainlog_report rep;
    for (int i = 0; i < RACE_EACH; i++) {
        /* Open/append/close per submission, as the CLI does, so processes interleave at the file lock. */
        struct land_queue *q = land_queue_open(path, &rep);
        if (!q)
            return 2;
        char branch[64];
        snprintf(branch, sizeof branch, "%s/%d", prefix, i);
        if (submit_one(q, branch, k_head_a) == 0) {
            land_queue_close(q);
            return 3;
        }
        land_queue_close(q);
    }
    return 0;
}

#if !defined(_WIN32)
static void race_child(const char *path, const char *prefix)
{
    _exit(race_child_run(path, prefix));
}
#endif

static int case_two_submitters_race(void)
{
    int failures = 0;
    char dir[512];
    test_make_tmpdir(dir, sizeof dir, "land", "race");
    char path[640];
    snprintf(path, sizeof path, "%s/queue.chainlog", dir);

    /* Create the log first so neither child races the header write. */
    struct zcl_chainlog_report rep;
    struct land_queue *seed = land_queue_open(path, &rep);
    LQ_CHECK("the queue is created before the race", seed != NULL);
    if (!seed) {
        test_cleanup_tmpdir(dir);
        return failures;
    }
    land_queue_close(seed);

    const char *prefixes[RACE_WRITERS] = { "lane/one", "lane/two",
                                           "lane/three", "lane/four" };
#if defined(_WIN32)
    void *kids[RACE_WRITERS] = {0};
    char logs[RACE_WRITERS][704];
    bool forked = setenv("ZCL_LAND_RACE_PATH", path, 1) == 0;
    for (int k = 0; k < RACE_WRITERS; k++) {
        snprintf(logs[k], sizeof logs[k], "%s/worker-%d.log", dir, k);
        if (setenv("ZCL_LAND_RACE_PREFIX", prefixes[k], 1) != 0) {
            forked = false;
            continue;
        }
        kids[k] = test_spawn_self_with_role("test_land_queue", "race-writer",
                                            logs[k]);
        if (!kids[k])
            forked = false;
    }
    (void)unsetenv("ZCL_LAND_RACE_PATH");
    (void)unsetenv("ZCL_LAND_RACE_PREFIX");
#else
    pid_t kids[RACE_WRITERS];
    bool forked = true;
    for (int k = 0; k < RACE_WRITERS; k++) {
        kids[k] = fork();
        if (kids[k] == 0)
            race_child(path, prefixes[k]);
        if (kids[k] < 0)
            forked = false;
    }
#endif
    LQ_CHECK("four submitter processes start at once", forked);

    int bad = 0;
    for (int k = 0; k < RACE_WRITERS; k++) {
#if defined(_WIN32)
        if (!kids[k])
            continue;
        int child_status = test_self_child_wait(kids[k]);
        if (child_status != 0) {
            printf("land_queue: worker %d exited %d", k, child_status);
            FILE *worker_log = fopen(logs[k], "rb");
            if (worker_log) {
                char diagnostic[512];
                size_t got = fread(diagnostic, 1, sizeof(diagnostic) - 1,
                                   worker_log);
                diagnostic[got] = '\0';
                fclose(worker_log);
                printf(": %s", diagnostic);
            }
            printf("\n");
            bad++;
        }
#else
        if (kids[k] <= 0)
            continue;
        int status = 0;
        (void)waitpid(kids[k], &status, 0);
        if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
            bad++;
#endif
    }
    LQ_CHECK("all four submitters finish cleanly", bad == 0);

    uint8_t stream[32];
    land_stream_id(stream);
    struct zcl_chainlog_report vrep;
    LQ_CHECK("the chain verifies after the race",
             zcl_chainlog_verify(path, stream, &vrep) == ZCL_CHAINLOG_OK);

    struct zcl_chainlog_report rrep;
    struct land_queue *q = land_queue_open(path, &rrep);
    LQ_CHECK("the queue replays after the race", q != NULL);
    if (q) {
        LQ_CHECK("with nothing torn", rrep.torn_bytes == 0);
        LQ_CHECK("every submission is present exactly once",
                 land_queue_count(q) == (size_t)(RACE_WRITERS * RACE_EACH));
        int found = 0;
        for (int k = 0; k < RACE_WRITERS; k++) {
            for (int i = 0; i < RACE_EACH; i++) {
                char branch[64];
                snprintf(branch, sizeof branch, "%s/%d", prefixes[k], i);
                if (land_queue_find_branch(q, branch))
                    found++;
            }
        }
        LQ_CHECK("and each is findable by name", found == RACE_WRITERS * RACE_EACH);

        /* Dense, gap-free sequence numbers across both writers. */
        bool dense = true;
        for (size_t i = 0; i < land_queue_count(q); i++)
            if (land_queue_at(q, i)->seq != (uint64_t)(i + 1))
                dense = false;
        LQ_CHECK("sequence numbers are dense across both writers", dense);
        land_queue_close(q);
    }

    test_cleanup_tmpdir(dir);
    return failures;
}

/* ── 9. submit costs the same whether the queue is empty or deep ───────
 * A stopwatch bound is forbidden by tools/lint/check_no_wallclock_assertion.sh
 * (it grades the machine, and the fleet includes 7200rpm boxes). The
 * load-independent property is asserted instead: one submit writes exactly
 * one frame, does no gate, and its cost does not grow with queue depth.
 * Latency is reported by tools/dev/land_bench.sh. */

static int case_submit_cost_is_flat(void)
{
    int failures = 0;
    char dir[512];
    test_make_tmpdir(dir, sizeof dir, "land", "flat");
    char path[640];
    snprintf(path, sizeof path, "%s/queue.chainlog", dir);

    struct zcl_chainlog_report rep;
    struct land_queue *q = land_queue_open(path, &rep);
    if (!q) {
        LQ_CHECK("the queue opens", false);
        test_cleanup_tmpdir(dir);
        return failures;
    }

    /* A submit into an empty queue: exactly one frame. */
    uint64_t first = submit_one(q, "lane/first", k_head_a);
    LQ_CHECK("the first submission is frame 1", first == 1);

    /* Fill the queue, with some inside an outstanding gate run, so the
     * deep case is realistic. */
    enum { DEEP = 200 };
    bool all_ok = true;
    uint64_t members[64];
    for (int i = 0; i < DEEP; i++) {
        char branch[64];
        snprintf(branch, sizeof branch, "lane/bulk-%d", i);
        uint64_t s = submit_one(q, branch, k_head_b);
        all_ok = all_ok && s == (uint64_t)(i + 2);
        if (i < 64)
            members[i] = s;
    }
    LQ_CHECK("a deep queue fills with dense sequence numbers", all_ok);
    uint64_t gr = gate_over(q, LAND_GATE_GREEN, true, members, 64);
    LQ_CHECK("a gate run over 64 of them is outstanding", gr != 0);

    /* A submit while all of that is in flight still writes exactly one
     * frame at the very next sequence number. */
    size_t entries_before = land_queue_count(q);
    uint64_t deep = submit_one(q, "lane/deep", k_head_a);
    LQ_CHECK("a submit into a deep queue with a gate run outstanding "
             "succeeds", deep != 0);
    LQ_CHECK("and adds exactly one entry",
             land_queue_count(q) == entries_before + 1);
    LQ_CHECK("and exactly one frame — no fan-out with queue depth",
             deep == (uint64_t)(DEEP + 2 /* submissions */ + 1 /* gate run */));
    LQ_CHECK("and it is QUEUED, not blocked behind the running gate",
             state_of(q, deep) == LAND_STATE_QUEUED);

    land_queue_close(q);
    test_cleanup_tmpdir(dir);
    return failures;
}

/* ── 10. status says what it is waiting on ────────────────────────────
 * Every live state names the one thing that will end the wait. */

static int case_status_says_what_it_waits_on(void)
{
    int failures = 0;
    char dir[512];
    test_make_tmpdir(dir, sizeof dir, "land", "waiting");
    char path[640];
    snprintf(path, sizeof path, "%s/queue.chainlog", dir);

    struct zcl_chainlog_report rep;
    struct land_queue *q = land_queue_open(path, &rep);
    if (!q) {
        LQ_CHECK("the queue opens", false);
        test_cleanup_tmpdir(dir);
        return failures;
    }

    uint64_t a = submit_one(q, "lane/a", k_head_a);
    uint64_t b = submit_one(q, "lane/b", k_head_b);
    uint64_t c = submit_one(q, "lane/c", k_head_a);

    LQ_CHECK("the head of the queue has nothing ahead of it",
             land_queue_find_seq(q, a)->ahead == 0);
    LQ_CHECK("and the ones behind it say how many",
             land_queue_find_seq(q, b)->ahead == 1 &&
                 land_queue_find_seq(q, c)->ahead == 2);

    uint64_t two[] = { a, b };
    uint64_t gr = gate_over(q, LAND_GATE_GREEN, true, two, 2);
    LQ_CHECK("a submission inside a batch names the run it is in",
             land_queue_find_seq(q, a)->gate_run_seq == gr &&
                 land_queue_find_seq(q, a)->state == LAND_STATE_GATING);
    LQ_CHECK("and how many submissions that run is proving at once",
             land_queue_find_seq(q, a)->batch_size == 2 &&
                 land_queue_find_seq(q, b)->batch_size == 2);
    LQ_CHECK("the one still queued moved up as the others left the queue",
             land_queue_find_seq(q, c)->ahead == 0 &&
                 land_queue_find_seq(q, c)->state == LAND_STATE_QUEUED);

    (void)settle(q, a, LAND_STATE_LANDED, gr);
    LQ_CHECK("a settled submission is waiting on nothing",
             land_queue_find_seq(q, a)->ahead == 0 &&
                 land_queue_find_seq(q, a)->state == LAND_STATE_LANDED);

    land_queue_close(q);
    test_cleanup_tmpdir(dir);
    return failures;
}

/* ── 11. a verdict is checkable by whoever receives it ─────────────────
 * The digest is computed from four public facts, so a second machine
 * recomputes it without the queue or the network. */

static int case_verdict_digest(void)
{
    int failures = 0;
    uint8_t head[LAND_SHA_BYTES], integ[LAND_SHA_BYTES];
    uint8_t gate_id[LAND_GATE_ID_BYTES], other_id[LAND_GATE_ID_BYTES];
    (void)land_sha_parse(k_head_a, head);
    (void)land_sha_parse(k_integ, integ);
    (void)land_id32_parse(k_gate_id, gate_id);
    memset(other_id, 0x7E, sizeof other_id);

    uint8_t d1[LAND_DIGEST_BYTES], d2[LAND_DIGEST_BYTES];
    land_verdict_digest(head, integ, gate_id, LAND_STATE_LANDED, true, d1);
    land_verdict_digest(head, integ, gate_id, LAND_STATE_LANDED, true, d2);
    LQ_CHECK("the same four facts give the same digest",
             memcmp(d1, d2, LAND_DIGEST_BYTES) == 0);

    /* Every input is load-bearing: each must change the digest. */
    uint8_t other_head[LAND_SHA_BYTES];
    (void)land_sha_parse(k_head_b, other_head);
    land_verdict_digest(other_head, integ, gate_id, LAND_STATE_LANDED, true, d2);
    LQ_CHECK("a different submitted commit gives a different digest",
             memcmp(d1, d2, LAND_DIGEST_BYTES) != 0);

    uint8_t other_integ[LAND_SHA_BYTES];
    memset(other_integ, 0x11, sizeof other_integ);
    land_verdict_digest(head, other_integ, gate_id, LAND_STATE_LANDED, true, d2);
    LQ_CHECK("a different integration commit gives a different digest",
             memcmp(d1, d2, LAND_DIGEST_BYTES) != 0);

    land_verdict_digest(head, integ, other_id, LAND_STATE_LANDED, true, d2);
    LQ_CHECK("a different gating tree gives a different digest",
             memcmp(d1, d2, LAND_DIGEST_BYTES) != 0);

    land_verdict_digest(head, integ, gate_id, LAND_STATE_REFUSED, true, d2);
    LQ_CHECK("a different verdict gives a different digest",
             memcmp(d1, d2, LAND_DIGEST_BYTES) != 0);

    land_verdict_digest(head, integ, gate_id, LAND_STATE_LANDED, false, d2);
    LQ_CHECK("a run that skipped its groups gives a different digest",
             memcmp(d1, d2, LAND_DIGEST_BYTES) != 0);

    /* The published digest must equal the one an outsider recomputes. */
    char dir[512];
    test_make_tmpdir(dir, sizeof dir, "land", "digest");
    char path[640];
    snprintf(path, sizeof path, "%s/queue.chainlog", dir);
    struct zcl_chainlog_report rep;
    struct land_queue *q = land_queue_open(path, &rep);
    if (!q) {
        LQ_CHECK("the queue opens", false);
        test_cleanup_tmpdir(dir);
        return failures;
    }
    uint64_t a = submit_one(q, "lane/checkable", k_head_a);
    uint64_t only_a[] = { a };
    uint64_t gr = gate_over(q, LAND_GATE_GREEN, true, only_a, 1);
    LQ_CHECK("the submission lands", settle(q, a, LAND_STATE_LANDED, gr) ==
                                         LAND_OK);
    const struct land_entry *e = land_queue_find_seq(q, a);
    LQ_CHECK("a settled submission publishes a digest", e && e->has_digest);
    if (e) {
        LQ_CHECK("and carries the gating tree's identity beside it",
                 memcmp(e->gate_id, gate_id, LAND_GATE_ID_BYTES) == 0 &&
                     e->gate_stress);
        /* Recompute it the way a stranger would: from the four facts only. */
        uint8_t outside[LAND_DIGEST_BYTES];
        land_verdict_digest(e->submit.head, e->verdict.integration,
                            e->gate_id, e->state, e->gate_stress, outside);
        LQ_CHECK("and a receiver recomputes exactly it from the public facts",
                 memcmp(outside, e->digest, LAND_DIGEST_BYTES) == 0);
        /* A receiver told the wrong tree does not reproduce it. */
        land_verdict_digest(e->submit.head, e->verdict.integration, other_id,
                            e->state, e->gate_stress, outside);
        LQ_CHECK("a verdict cannot be replayed onto another tree",
                 memcmp(outside, e->digest, LAND_DIGEST_BYTES) != 0);
    }

    /* An ungated verdict digests over an all-zero gate identity, distinct from a gated one. */
    uint64_t b = submit_one(q, "lane/ungated", k_head_b);
    LQ_CHECK("an ungated refusal records", settle(q, b, LAND_STATE_REFUSED, 0) ==
                                               LAND_OK);
    const struct land_entry *eb = land_queue_find_seq(q, b);
    if (eb) {
        uint8_t zero_id[LAND_GATE_ID_BYTES];
        memset(zero_id, 0, sizeof zero_id);
        uint8_t expect[LAND_DIGEST_BYTES];
        land_verdict_digest(eb->submit.head, eb->verdict.integration, zero_id,
                            LAND_STATE_REFUSED, false, expect);
        LQ_CHECK("and its digest names 'nothing gated this'",
                 eb->has_digest &&
                     memcmp(eb->digest, expect, LAND_DIGEST_BYTES) == 0);
    }

    land_queue_close(q);
    test_cleanup_tmpdir(dir);
    return failures;
}

/* ── 12. an unreachable queue refuses; it never looks empty ────────────
 * The agent falls back to gating locally: degraded, never blocked, and
 * never told "nothing queued" when it could not look. */

static int case_unreachable_queue(void)
{
    int failures = 0;
    struct zcl_chainlog_report rep;
    memset(&rep, 0, sizeof rep);

    /* A path whose parent does not exist must fail loudly. */
    struct land_queue *q =
        land_queue_open("/nonexistent-directory-for-land/queue.chainlog", &rep);
    LQ_CHECK("an unreachable queue refuses to open", q == NULL);
    LQ_CHECK("and says why, rather than reporting an empty queue",
             rep.status != ZCL_CHAINLOG_OK);
    if (q)
        land_queue_close(q);

    /* The refusal is distinguishable from a real, empty queue. */
    char dir[512];
    test_make_tmpdir(dir, sizeof dir, "land", "empty");
    char path[640];
    snprintf(path, sizeof path, "%s/queue.chainlog", dir);
    struct zcl_chainlog_report erep;
    struct land_queue *empty = land_queue_open(path, &erep);
    LQ_CHECK("a real but empty queue opens", empty != NULL);
    LQ_CHECK("with an OK status and no entries",
             empty && erep.status == ZCL_CHAINLOG_OK &&
                 land_queue_count(empty) == 0);
    if (empty)
        land_queue_close(empty);
    test_cleanup_tmpdir(dir);
    return failures;
}

/* ── 13. surface: refusals are named, and nothing crashes on NULL ─────── */

static int case_surface(void)
{
    int failures = 0;

    LQ_CHECK("every status has a label",
             strcmp(land_status_label(LAND_OK), "ok") == 0 &&
                 strcmp(land_status_label(LAND_ERR_NO_GATE_RUN),
                        "no-gate-run") == 0 &&
                 strcmp(land_status_label(LAND_ERR_GATE_NOT_STRESSED),
                        "gate-skipped-groups") == 0);
    LQ_CHECK("every state has a label",
             strcmp(land_state_label(LAND_STATE_QUEUED), "QUEUED") == 0 &&
                 strcmp(land_state_label(LAND_STATE_LANDED), "LANDED") == 0 &&
                 strcmp(land_state_label(LAND_STATE_REFUSED), "REFUSED") == 0);

    enum land_state st;
    LQ_CHECK("a state parses from its command-line spelling",
             land_state_parse("landed", &st) && st == LAND_STATE_LANDED);
    LQ_CHECK("and an unknown spelling is refused",
             !land_state_parse("probably-fine", &st));
    enum land_gate_outcome out;
    LQ_CHECK("an outcome parses",
             land_gate_outcome_parse("red", &out) && out == LAND_GATE_RED);
    LQ_CHECK("and an unknown outcome is refused",
             !land_gate_outcome_parse("amber", &out));

    LQ_CHECK("a NULL queue answers rather than crashes",
             land_queue_count(NULL) == 0 && land_queue_at(NULL, 0) == NULL &&
                 land_queue_find_branch(NULL, "x") == NULL &&
                 land_queue_submit(NULL, NULL, NULL) == LAND_ERR_ARGUMENT);
    LQ_CHECK("and a NULL queue cannot be talked into a landing",
             land_queue_check_landable(NULL, 1, 1) == LAND_ERR_ARGUMENT);

    /* The stream id is a fixed derivation so boxes can read each other's queue. */
    uint8_t s1[32], s2[32];
    land_stream_id(s1);
    land_stream_id(s2);
    LQ_CHECK("the stream id is stable", memcmp(s1, s2, 32) == 0);

    return failures;
}

/* Exercise the real entry point; no queue command reaches a live queue. */
static int case_git_selectors(void)
{
#if defined(_WIN32)
    return 0; /* This bash lander is a POSIX-only surface. */
#else
    int failures = 0;
    char dir[512], root[4096], path_env[4096], out[4096];
    const char *path = getenv("PATH");
    int n = snprintf(path_env, sizeof path_env, "PATH=%s", path ? path : "");
    LQ_CHECK("selector fixture has a bounded trusted PATH and root",
             path && n > 0 && (size_t)n < sizeof path_env &&
                 getcwd(root, sizeof root) != NULL);
    if (failures) return failures;
    test_make_tmpdir(dir, sizeof dir, "land", "selectors");
    static const char fixture[] =
        "set -euo pipefail\n"
        "t=$(mktemp -d \"$2/fixture.XXXXXX\")\n"
        "trap 'rm -rf -- \"$t\"' EXIT\n"
        "export HOME=$t LC_ALL=C\n"
        "git_tool=$(command -v git); bash_tool=$(command -v bash)\n"
        "for repo in a b; do\n"
        " git init -q -b fixture-base \"$t/$repo\"\n"
        " printf 'original\\n' > \"$t/$repo/tracked\"\n"
        " git -C \"$t/$repo\" add tracked\n"
        " env GIT_AUTHOR_DATE='2000-01-01T00:00:00Z' GIT_COMMITTER_DATE='2000-01-01T00:00:00Z'"
        " git -C \"$t/$repo\" -c user.name=Fixture -c user.email=fixture@example.invalid"
        " -c core.hooksPath=/dev/null commit -qm base\n"
        " git -C \"$t/$repo\" branch -f main HEAD\n"
        " git -C \"$t/$repo\" branch land/ready HEAD\n"
        " printf 'UNCOMMITTED\\n' > \"$t/$repo/tracked\"\n"
        " cp \"$t/$repo/.git/index\" \"$t/$repo.index\"\n"
        " cp \"$t/$repo/.git/HEAD\" \"$t/$repo.head\"\n"
        " cp \"$t/$repo/tracked\" \"$t/$repo.bytes\"\n"
        " git -C \"$t/$repo\" show-ref > \"$t/$repo.refs\"\n"
        "done\n"
        "mkdir \"$t/bin\"\n"
        "printf '#!/bin/sh\\nprintf called >> \"$CALLS\"\\nexec \"$REAL_GIT\" \"$@\"\\n' > \"$t/bin/git\"\n"
        "printf '#!/bin/sh\\n[ \"$LC_ALL\" = C ] && [ \"${BASH_ENV+x}\" != x ]\\n' > \"$t/queue\"\n"
        "chmod +x \"$t/bin/git\" \"$t/queue\"\n"
        "export REAL_GIT=$git_tool CALLS=$t/calls\n"
        "export ZCL_LAND_BIN=$t/queue ZCL_LAND_WORKTREE=$t/a ZCL_LAND_STATE_DIR=$t/state\n"
        "selectors=\"GIT_DIR GIT_WORK_TREE $(\"$git_tool\" rev-parse --local-env-vars)\"\n"
        "selectors+=\" GIT_NAMESPACE GIT_EXEC_PATH GIT_CONFIG_KEY_17 GIT_CONFIG_VALUE_17"
        " GIT_CONFIG_GLOBAL GIT_CONFIG_SYSTEM GIT_CONFIG_NOSYSTEM GIT_CEILING_DIRECTORIES"
        " GIT_DISCOVERY_ACROSS_FILESYSTEM GIT_LITERAL_PATHSPECS GIT_GLOB_PATHSPECS"
        " GIT_NOGLOB_PATHSPECS GIT_ICASE_PATHSPECS\"\n"
        "for selector in $selectors; do\n"
        " for value in \"$t/b/.git\" ''; do\n"
        "  rc=0\n"
        "  env PATH=\"$t/bin:$PATH\" \"$selector=$value\" \"$bash_tool\" --noprofile --norc"
        " \"$1/tools/dev/land_lander.sh\" --once > \"$t/output\" 2>&1 || rc=$?\n"
        "  [ \"$rc\" = 2 ]\n"
        "  grep -Fx \"lander: inherited Git selector refused: $selector\" \"$t/output\"\n"
        "  [ ! -e \"$t/calls\" ] && [ ! -e \"$t/state\" ]\n"
        " done\n"
        "done\n"
        "rc=0\n"
        "env PATH=\"$t/bin:$PATH\" GIT_DIR=\"$t/b/.git\" GIT_WORK_TREE=\"$t/b\""
        " \"$bash_tool\" --noprofile --norc \"$1/tools/dev/land_lander.sh\" --once"
        " > \"$t/output\" 2>&1 || rc=$?\n"
        "[ \"$rc\" = 2 ] && grep -F 'inherited Git selector refused:' \"$t/output\"\n"
        "[ ! -e \"$t/calls\" ] && [ ! -e \"$t/state\" ]\n"
        "for repo in a b; do\n"
        " cmp \"$t/$repo/.git/index\" \"$t/$repo.index\"\n"
        " cmp \"$t/$repo/.git/HEAD\" \"$t/$repo.head\"\n"
        " cmp \"$t/$repo/tracked\" \"$t/$repo.bytes\"\n"
        " \"$git_tool\" -C \"$t/$repo\" show-ref > \"$t/$repo.after\"\n"
        " cmp \"$t/$repo.after\" \"$t/$repo.refs\"\n"
        "done\n"
        "printf 'echo unexpected > \"$HOME/startup\"\\n' > \"$t/startup.sh\"\n"
        "env BASH_ENV=\"$t/startup.sh\" LC_ALL=invalid env -i PATH=\"$PATH\" HOME=\"$t\" LC_ALL=C"
        " ZCL_LAND_BIN=\"$t/queue\" ZCL_LAND_WORKTREE=\"$t/a\" ZCL_LAND_STATE_DIR=\"$t/state\""
        " \"$bash_tool\" --noprofile --norc \"$1/tools/dev/land_lander.sh\" --once\n"
        "[ ! -e \"$t/startup\" ]\n"
        "printf 'PASS: land-selector-fixture complete\\n'\n";
    const char *const argv[] = {"env", "-i", path_env, "LC_ALL=C", "bash",
        "--noprofile", "--norc", "-c", fixture, "selector-fixture", root, dir, NULL};
    static const char complete[] = "PASS: land-selector-fixture complete\n";
    struct zcl_spawn_binary_observation observation = {0};
    memset(out, 0, sizeof out);
    struct zcl_result capture = zcl_spawn_capture_binary(
        argv, out, sizeof out - 1, 60000, &observation);
    LQ_CHECK("real lander refuses selectors before Git and preserves both repositories",
             capture.ok && observation.output_len >= sizeof complete - 1 &&
                 memcmp(out + observation.output_len - (sizeof complete - 1),
                        complete, sizeof complete - 1) == 0);
    if (failures) printf("land_queue: selector fixture output: %s\n", out);
    LQ_CHECK("selector fixture cleanup succeeds", test_rm_rf_recursive(dir) == 0);
    return failures;
#endif
}

#if !defined(_WIN32)
/* Exercise the real dispatcher with actual writable/read-only descriptors. */
static int cli_output_run(int argc, char **argv, FILE *sink, FILE *errors)
{
    int saved[2] = { -1, -1 }, rc = -1;
    FILE *streams[2] = { stdout, stderr }, *targets[2] = { sink, errors };
    for (int i = 0; i < 2; i++) {
        if (fflush(streams[i]) != 0 || (saved[i] = dup(fileno(streams[i]))) < 0)
            goto restore;
        if (dup2(fileno(targets[i]), fileno(streams[i])) < 0)
            goto restore;
    }
    rc = land_cli_main(argc, argv);
restore:
    for (int i = 0; i < 2; i++) {
        if (saved[i] < 0) continue;
        if (fflush(streams[i]) != 0 && i == 1) rc = -1;
        clearerr(streams[i]);
        if (dup2(saved[i], fileno(streams[i])) < 0) rc = -1;
        if (close(saved[i]) != 0) rc = -1;
    }
    return rc;
}

static int cli_descriptor_rows(char *path, FILE *healthy, FILE *readonly,
                               FILE *errors)
{
    int failures = 0;
    char diagnostic[512] = {0};
    char *digest[] = { "land", "digest", "--head", (char *)k_head_a,
                       "--state", "landed", "--stress", "1" };
    LQ_CHECK("healthy digest output succeeds",
             cli_output_run(8, digest, healthy, errors) == 0);
    LQ_CHECK("digest output failure refuses success",
             cli_output_run(8, digest, readonly, errors) == 1);
    char *submit[] = { "land", "submit", "--queue", path, "--branch", "lane/a",
                       "--head", (char *)k_head_a, "--submitter", "test" };
    LQ_CHECK("committed submit output failure refuses success",
             cli_output_run(10, submit, readonly, errors) == 1);
    LQ_CHECK("diagnostics rewind", fseek(errors, 0, SEEK_SET) == 0);
    size_t n = fread(diagnostic, 1, sizeof diagnostic - 1, errors);
    diagnostic[n] = '\0';
    LQ_CHECK("committed-effect warning discourages blind retry",
             !ferror(errors) && strstr(diagnostic, "after action committed; inspect queue before retrying"));
    struct zcl_chainlog_report report;
    struct land_queue *q = land_queue_open(path, &report);
    LQ_CHECK("failed output leaves exactly one durable submission",
             q && land_queue_count(q) == 1);
    land_queue_close(q);
    const char *commands[] = { "pending", "status", "metrics", "verify" };
    for (size_t i = 0; i < sizeof commands / sizeof commands[0]; i++) {
        char *args[] = { "land", (char *)commands[i], "--queue", path };
        LQ_CHECK(commands[i], cli_output_run(4, args, healthy, errors) == 0);
        LQ_CHECK(commands[i], cli_output_run(4, args, readonly, errors) == 1);
    }
    return failures;
}

static int case_cli_output_failure(void)
{
    int failures = 0;
    char dir[512], path[640], outpath[640], errpath[640];
    if (!test_mkdtemp(dir, sizeof dir, "land-output")) {
        LQ_CHECK("output fixture directory opens", false);
        return failures;
    }
    snprintf(path, sizeof path, "%s/queue.chainlog", dir);
    snprintf(outpath, sizeof outpath, "%s/stdout", dir);
    snprintf(errpath, sizeof errpath, "%s/stderr", dir);
    FILE *healthy = fopen(outpath, "w+"), *errors = fopen(errpath, "w+");
    FILE *readonly = NULL;
    struct zcl_chainlog_report report;
    struct land_queue *q = land_queue_open(path, &report);
    bool opened = healthy && errors && q;
    LQ_CHECK("output fixture opens", opened);
    land_queue_close(q);
    if (!opened) goto cleanup;
    readonly = fopen(path, "r");
    LQ_CHECK("read-only output opens", readonly != NULL);
    if (!readonly) goto cleanup;
    failures += cli_descriptor_rows(path, healthy, readonly, errors);
cleanup:
    if (readonly) LQ_CHECK("read-only output closes", fclose(readonly) == 0);
    if (healthy) LQ_CHECK("healthy output closes", fclose(healthy) == 0);
    if (errors) LQ_CHECK("diagnostic output closes", fclose(errors) == 0);
    LQ_CHECK("output fixture cleanup succeeds", test_rm_rf_recursive(dir) == 0);
    return failures;
}

static bool cli_warning(FILE *errors)
{
    char diagnostic[512] = {0};
    if (fseek(errors, 0, SEEK_SET) != 0) return false;
    size_t n = fread(diagnostic, 1, sizeof diagnostic - 1, errors);
    diagnostic[n] = '\0';
    return !ferror(errors) && strcmp(diagnostic,
        "z23-land: stdout output failed after action committed; inspect queue before retrying\n") == 0;
}

static int cli_pipe_setup(const char *path, FILE *errors)
{
    struct sigaction normal = {0};
    normal.sa_handler = SIG_DFL;
    if (sigemptyset(&normal.sa_mask) != 0 ||
        sigaction(SIGALRM, &normal, NULL) != 0 ||
        sigaction(SIGPIPE, &normal, NULL) != 0) return 120;
    sigset_t unblocked;
    if (sigemptyset(&unblocked) != 0 ||
        sigaddset(&unblocked, SIGALRM) != 0 ||
        sigaddset(&unblocked, SIGPIPE) != 0 ||
        sigprocmask(SIG_UNBLOCK, &unblocked, NULL) != 0) return 129;
    alarm(10); /* A watchdog, never a timing assertion or clock reading. */
    char output_path[768];
    snprintf(output_path, sizeof output_path, "%s.stdout", path);
    if (!freopen(output_path, "w", stdout)) return 130;
    int ends[2];
    if (pipe(ends) != 0) return 121;
    if (close(ends[0]) != 0) return 122;
    if (dup2(ends[1], STDOUT_FILENO) < 0) return 123;
    if (close(ends[1]) != 0) return 124;
    if (dup2(fileno(errors), STDERR_FILENO) < 0) return 125;
    return 0;
}

/* All readers are closed before the actual CLI entry. */
static int cli_pipe_child(const char *path, FILE *errors, bool buffered)
{
    int setup = cli_pipe_setup(path, errors);
    if (setup != 0) return setup;
    clearerr(stdout);
    clearerr(stderr);
    char buffer[4096];
    if (setvbuf(stdout, buffered ? buffer : NULL,
                buffered ? _IOFBF : _IONBF, buffered ? sizeof buffer : 0) != 0)
        return 126;
    char *submit[] = { "land", "submit", "--queue", (char *)path,
        "--branch", "lane/pipe", "--head", (char *)k_head_a,
        "--submitter", "test" };
    int rc = land_cli_main(10, submit);
    struct sigaction restored;
    if (sigaction(SIGPIPE, NULL, &restored) != 0 ||
        restored.sa_handler != SIG_DFL) return 127;
    if (fflush(stderr) != 0 || ferror(stderr)) return 128;
    return rc;
}

static bool cli_wait(pid_t child, int *status)
{
    pid_t got;
    do { got = waitpid(child, status, 0); } while (got < 0 && errno == EINTR);
    return got == child;
}

static int case_cli_pipe(bool buffered)
{
    int failures = 0;
    char dir[512], path[640], error_path[640];
    if (!test_mkdtemp(dir, sizeof dir, "land-pipe")) {
        LQ_CHECK("pipe fixture directory opens", false);
        return failures;
    }
    snprintf(path, sizeof path, "%s/queue.chainlog", dir);
    snprintf(error_path, sizeof error_path, "%s/stderr", dir);
    FILE *errors = fopen(error_path, "w+");
    LQ_CHECK("pipe diagnostics open", errors != NULL);
    if (!errors) goto cleanup;
    LQ_CHECK("parent streams flush before fork", fflush(NULL) == 0);
    if (failures) goto cleanup;
    pid_t child = fork();
    if (child == 0) _exit(cli_pipe_child(path, errors, buffered));
    LQ_CHECK("pipe child starts", child > 0);
    if (child < 0) goto cleanup;
    int status = 0;
    bool waited = cli_wait(child, &status);
    LQ_CHECK("pipe child wait succeeds", waited);
    LQ_CHECK(buffered ? "buffered pipe exits normally with failure" :
                       "unbuffered pipe exits normally with failure",
             waited && WIFEXITED(status) && WEXITSTATUS(status) == 1);
    LQ_CHECK("pipe committed warning is exact", cli_warning(errors));
    struct zcl_chainlog_report report;
    struct land_queue *q = land_queue_open(path, &report);
    LQ_CHECK("pipe leaves exactly one durable record",
             q && report.records == 1 && land_queue_count(q) == 1);
    land_queue_close(q);
cleanup:
    if (errors) LQ_CHECK("pipe diagnostics close", fclose(errors) == 0);
    LQ_CHECK("pipe fixture cleanup succeeds", test_rm_rf_recursive(dir) == 0);
    return failures;
}

#endif

int test_land_queue(void);
int test_land_queue(void)
{
#if defined(_WIN32)
    const char *role = getenv("ZCL_TEST_FORK_ROLE");
    if (role && strcmp(role, "race-writer") == 0) {
        const char *path = getenv("ZCL_LAND_RACE_PATH");
        const char *prefix = getenv("ZCL_LAND_RACE_PREFIX");
        if (!path || !path[0] || !prefix || !prefix[0])
            return 2;
        return race_child_run(path, prefix);
    }
#endif
    int failures = 0;
    failures += case_submit_and_pending();
    failures += case_gate_member_bounds();
    failures += case_landing_needs_a_real_gate();
    failures += case_bisect();
    failures += case_timeout();
    failures += case_restart();
    failures += case_chain_verifies();
    failures += case_canonical_bytes();
    failures += case_two_submitters_race();
    failures += case_submit_cost_is_flat();
    failures += case_status_says_what_it_waits_on();
    failures += case_verdict_digest();
    failures += case_unreachable_queue();
    failures += case_surface();
    failures += case_git_selectors();
#if !defined(_WIN32)
    failures += case_cli_output_failure();
    failures += case_cli_pipe(true);
    failures += case_cli_pipe(false);
#endif
    printf("land_queue: %d failure(s)\n", failures);
    return failures;
}
