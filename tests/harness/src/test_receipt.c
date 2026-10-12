/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_receipt — the engine/modules/receipt gate.
 *
 * A receipt lets a node rely on what another node established without
 * re-running it, so this file proves the properties that stop a receipt from
 * lying:
 *
 *  1. THE CANONICAL BYTES ARE CANONICAL. Encode is fixed width (size asserted
 *     at compile time); a round trip returns the same receipt, a buffer one
 *     byte short is refused, a decode of any other length is refused, and a
 *     one-bit difference in one field yields a different id.
 *
 *  2. A REFUSAL LEAVES NOTHING BEHIND. Every rejected decode zeroes its
 *     output (proven by poisoning the struct first).
 *
 *  3. ONLY A PASS WITH A VECTOR PUBLISHES AS A PASS. HOLLOW looks like
 *     success and is not.
 *
 *  4. AN INELIGIBLE GROUP GETS NO RECEIPT. With no ledger wired every group
 *     is UNKNOWN and every build refuses, naming the group.
 *
 *  5. BELIEF IS NEVER READ OFF THE WIRE. A node with no run of its own
 *     believes UNVERIFIED; a differing vector is REFUTED, and so is a
 *     differing CHECK COUNT even when the digests match.
 *
 *  6. A RED-DELTA MUST BE A DELTA. One whose base tree is absent, or
 *     identical to the tree it claims to have fixed, is refused.
 */

#include "test/test_core.h"

#include "receipt/receipt.h"

#include <stdio.h>
#include <string.h>

/* One line per check, outcome first, name after, in ONE printf so a
 * transcript parser never sees a split line as a check that asserted nothing. */
#define RC_CHECK(name, expr) do {                                   \
    const bool rc_ok_ = (expr);                                     \
    if (!rc_ok_) failures++;                                        \
    printf("receipt: %s %s\n", rc_ok_ ? "OK  " : "FAIL", (name));   \
} while (0)

static void fill(uint8_t *p, size_t n, uint8_t v)
{
    for (size_t i = 0; i < n; i++)
        p[i] = (uint8_t)(v + i);
}

static bool is_all_zero(const void *p, size_t n)
{
    const uint8_t *b = (const uint8_t *)p;
    uint8_t acc = 0;
    for (size_t i = 0; i < n; i++)
        acc |= b[i];
    return acc == 0;
}

/* A ledger that says yes to everything, for cases not ABOUT eligibility. No
 * such ledger exists in the tree, and one must never. */
static enum zcl_receipt_eligibility yes_to_everything(const char *group,
                                                      void *user)
{
    (void)group; (void)user;
    return ZCL_RECEIPT_ELIGIBLE;
}

/* Answers off the enum, to prove that an answer this code does not
 * understand is not read as "yes". */
static enum zcl_receipt_eligibility nonsense(const char *group, void *user)
{
    (void)group; (void)user;
    return (enum zcl_receipt_eligibility)99;
}

static enum zcl_receipt_eligibility timing_sensitive(const char *group,
                                                     void *user)
{
    (void)group; (void)user;
    return ZCL_RECEIPT_INELIGIBLE_TIMING_SENSITIVE;
}

static const struct zcl_receipt_ledger open_ledger = {
    .lookup = yes_to_everything, .user = NULL, .source = "test fixture"
};
static const struct zcl_receipt_ledger no_ledger = {
    .lookup = NULL, .user = NULL, .source = "determinism ledger not landed"
};
static const struct zcl_receipt_ledger bad_ledger = {
    .lookup = nonsense, .user = NULL, .source = "test fixture"
};
static const struct zcl_receipt_ledger timing_ledger = {
    .lookup = timing_sensitive, .user = NULL, .source = "test fixture"
};

static uint8_t g_root[32], g_base[32], g_vec[32], g_other_vec[32], g_producer[32];
static char g_why[256];

static void fixtures_init(void)
{
    fill(g_root, 32, 0x10);
    fill(g_base, 32, 0x40);
    fill(g_vec, 32, 0x70);
    fill(g_other_vec, 32, 0x71);
    fill(g_producer, 32, 0xa0);
}

static bool build_pass(struct zcl_proof_receipt *r)
{
    return zcl_receipt_build(r, &open_ledger, ZCL_RECEIPT_KIND_PASS,
        ZCL_RECEIPT_VERDICT_PASS, g_root, NULL, "test_receipt", g_vec, 131,
        "gcc-13.2 -std=c23 -O2", "linux-glibc-x86_64-O2", g_producer,
        g_why, sizeof(g_why));
}

/* ── 1. the canonical bytes are canonical ────────────────────────────── */

static int case_canonical(void)
{
    int failures = 0;
    struct zcl_proof_receipt r;
    RC_CHECK("a receipt over an eligible group is built", build_pass(&r));
    RC_CHECK("it is structurally valid", zcl_receipt_is_valid(&r));
    RC_CHECK("it publishes as a pass", zcl_receipt_is_publishable_pass(&r));
    RC_CHECK("the group survived the round of copies",
             strcmp(r.group, "test_receipt") == 0);
    RC_CHECK("the check count survived", r.checks_total == 131);

    uint8_t wire[ZCL_RECEIPT_WIRE_BYTES + 1];
    RC_CHECK("encode writes exactly the wire size",
             zcl_receipt_encode(wire, ZCL_RECEIPT_WIRE_BYTES, &r) ==
                 (size_t)ZCL_RECEIPT_WIRE_BYTES);

    struct zcl_proof_receipt back;
    RC_CHECK("a round trip decodes",
             zcl_receipt_decode(&back, wire, ZCL_RECEIPT_WIRE_BYTES));
    RC_CHECK("a round trip returns exactly what went in",
             memcmp(&back, &r, sizeof(back)) == 0);

    RC_CHECK("a buffer one byte short is refused, not truncated",
             zcl_receipt_encode(wire, ZCL_RECEIPT_WIRE_BYTES - 1, &r) == 0);
    RC_CHECK("a decode one byte short is refused",
             !zcl_receipt_decode(&back, wire, ZCL_RECEIPT_WIRE_BYTES - 1));
    RC_CHECK("a decode one byte long is refused",
             !zcl_receipt_decode(&back, wire, ZCL_RECEIPT_WIRE_BYTES + 1));
    RC_CHECK("a zero-length decode is refused",
             !zcl_receipt_decode(&back, wire, 0));
    return failures;
}

/* ── 2. a refusal leaves nothing behind ──────────────────────────────── */

static int case_refusal_is_clean(void)
{
    int failures = 0;
    struct zcl_proof_receipt r;
    if (!build_pass(&r)) {
        printf("receipt: FAIL could not build the fixture receipt\n");
        return 1;
    }
    uint8_t wire[ZCL_RECEIPT_WIRE_BYTES];
    (void)zcl_receipt_encode(wire, sizeof(wire), &r);

    struct zcl_proof_receipt poisoned;
    memset(&poisoned, 0xa5, sizeof(poisoned));
    uint8_t saved = wire[0];
    wire[0] = 0xff;                      /* a version this build never wrote */
    RC_CHECK("a wrong version is refused",
             !zcl_receipt_decode(&poisoned, wire, sizeof(wire)));
    RC_CHECK("and the refusal zeroed the output",
             is_all_zero(&poisoned, sizeof(poisoned)));
    wire[0] = saved;

    saved = wire[1];
    wire[1] = 0;
    RC_CHECK("kind 0 is refused", !zcl_receipt_decode(&poisoned, wire,
                                                      sizeof(wire)));
    wire[1] = 3;
    RC_CHECK("kind just past the range is refused",
             !zcl_receipt_decode(&poisoned, wire, sizeof(wire)));
    wire[1] = 255;
    RC_CHECK("kind 255 is refused", !zcl_receipt_decode(&poisoned, wire,
                                                        sizeof(wire)));
    wire[1] = saved;

    saved = wire[2];
    wire[2] = 0;
    RC_CHECK("verdict 0 is refused", !zcl_receipt_decode(&poisoned, wire,
                                                         sizeof(wire)));
    wire[2] = 8;
    RC_CHECK("verdict just past the range is refused",
             !zcl_receipt_decode(&poisoned, wire, sizeof(wire)));
    wire[2] = saved;

    const size_t group_at = 3 + 32 + 32;
    saved = wire[group_at + 2];
    wire[group_at + 2] = 0x1b;
    RC_CHECK("a control byte in a name is refused, not sanitised",
             !zcl_receipt_decode(&poisoned, wire, sizeof(wire)));
    wire[group_at + 2] = saved;

    /* Padding differences must not give one claim two ids. */
    saved = wire[group_at + ZCL_RECEIPT_GROUP_MAX - 1];
    wire[group_at + ZCL_RECEIPT_GROUP_MAX - 1] = 'x';
    RC_CHECK("a non-zero tail after the NUL is refused",
             !zcl_receipt_decode(&poisoned, wire, sizeof(wire)));
    wire[group_at + ZCL_RECEIPT_GROUP_MAX - 1] = saved;

    RC_CHECK("and the untampered frame still decodes",
             zcl_receipt_decode(&poisoned, wire, sizeof(wire)));
    return failures;
}

/* ── the id ──────────────────────────────────────────────────────────── */

static int case_structural_refusals(void)
{
    int failures = 0;
    struct zcl_proof_receipt valid;
    if (!build_pass(&valid)) {
        printf("receipt: FAIL could not build the fixture receipt\n");
        return 1;
    }
    RC_CHECK("the structural refusal fixture is valid",
             zcl_receipt_is_valid(&valid));
    struct zcl_proof_receipt changed = valid;
    memcpy(changed.base_root, g_base, sizeof(changed.base_root));
    RC_CHECK("a plain receipt with a nonzero base is invalid",
             !zcl_receipt_is_valid(&changed));
    changed = valid;
    memset(changed.group, 0, sizeof(changed.group));
    RC_CHECK("an assembled receipt with an empty group is invalid",
             !zcl_receipt_is_valid(&changed));

    const char *names[] = { "group", "toolchain", "env_class" };
    const char *defects[] = {
        "unterminated", "control byte", "non-ASCII byte", "nonzero tail"
    };
    for (size_t field = 0; field < 3; field++) {
        for (size_t defect = 0; defect < 4; defect++) {
            changed = valid;
            char *fields[] = {
                changed.group, changed.toolchain, changed.env_class
            };
            const size_t widths[] = {
                sizeof(changed.group), sizeof(changed.toolchain),
                sizeof(changed.env_class)
            };
            char *value = fields[field];
            size_t width = widths[field];
            switch (defect) {
            case 0: memset(value, 'g', width); break;
            case 1: value[0] = 0x1b; break;
            case 2: value[0] = (char)0x80; break;
            case 3: value[width - 1] = 'x'; break;
            }
            char label[128];
            (void)snprintf(label, sizeof(label), "%s with %s is invalid",
                           names[field], defects[defect]);
            RC_CHECK(label, !zcl_receipt_is_valid(&changed));
        }
    }
    RC_CHECK("the unchanged structural fixture remains valid",
             zcl_receipt_is_valid(&valid));
    return failures;
}

static int case_id(void)
{
    int failures = 0;
    struct zcl_proof_receipt r;
    if (!build_pass(&r)) {
        printf("receipt: FAIL could not build the fixture receipt\n");
        return 1;
    }
    uint8_t id_a[32], id_b[32], id_c[32];
    RC_CHECK("a valid receipt has an id", zcl_receipt_id(id_a, &r));
    RC_CHECK("the id is not all zero", !is_all_zero(id_a, 32));
    RC_CHECK("the id is stable across calls",
             zcl_receipt_id(id_c, &r) && memcmp(id_a, id_c, 32) == 0);

    struct zcl_proof_receipt tweaked = r;
    tweaked.verdict_vector[31] ^= 0x01;
    RC_CHECK("one changed bit in the vector is a different id",
             zcl_receipt_id(id_b, &tweaked) && memcmp(id_a, id_b, 32) != 0);

    tweaked = r;
    tweaked.checks_total ^= 1u;
    RC_CHECK("one changed bit in the check count is a different id",
             zcl_receipt_id(id_b, &tweaked) && memcmp(id_a, id_b, 32) != 0);

    tweaked = r;
    tweaked.source_root[0] ^= 0x80;
    RC_CHECK("one changed bit in the source root is a different id",
             zcl_receipt_id(id_b, &tweaked) && memcmp(id_a, id_b, 32) != 0);
    return failures;
}

/* ── 3. only a pass with a vector publishes as a pass ─────────────────── */

static int case_publishable(void)
{
    int failures = 0;
    struct zcl_proof_receipt r;

    const enum zcl_receipt_verdict not_pass[] = {
        ZCL_RECEIPT_VERDICT_FAIL, ZCL_RECEIPT_VERDICT_HOLLOW,
        ZCL_RECEIPT_VERDICT_NO_CHANGE, ZCL_RECEIPT_VERDICT_TIMEOUT,
        ZCL_RECEIPT_VERDICT_REFUSED, ZCL_RECEIPT_VERDICT_UNVERIFIED,
    };
    for (size_t i = 0; i < sizeof(not_pass) / sizeof(not_pass[0]); i++) {
        bool built = zcl_receipt_build(&r, &open_ledger,
            ZCL_RECEIPT_KIND_PASS, not_pass[i], g_root, NULL, "test_receipt",
            g_vec, 131, "tc", "env", g_producer, g_why, sizeof(g_why));
        char label[128];
        (void)snprintf(label, sizeof(label),
                       "%s is a valid receipt that does NOT publish as a pass",
                       zcl_receipt_verdict_label(not_pass[i]));
        RC_CHECK(label, built && zcl_receipt_is_valid(&r) &&
                        !zcl_receipt_is_publishable_pass(&r));
    }

    uint8_t zero_vec[32] = { 0 };
    RC_CHECK("a PASS with no measured vector does not publish as a pass",
             zcl_receipt_build(&r, &open_ledger, ZCL_RECEIPT_KIND_PASS,
                 ZCL_RECEIPT_VERDICT_PASS, g_root, NULL, "test_receipt",
                 zero_vec, 131, "tc", "env", g_producer, g_why,
                 sizeof(g_why)) &&
             !zcl_receipt_is_publishable_pass(&r));

    RC_CHECK("a PASS covering zero checks does not publish as a pass",
             zcl_receipt_build(&r, &open_ledger, ZCL_RECEIPT_KIND_PASS,
                 ZCL_RECEIPT_VERDICT_PASS, g_root, NULL, "test_receipt",
                 g_vec, 0, "tc", "env", g_producer, g_why, sizeof(g_why)) &&
             !zcl_receipt_is_publishable_pass(&r));
    return failures;
}

/* ── 4. an ineligible group gets no receipt at all ────────────────────── */

static int case_eligibility(void)
{
    int failures = 0;
    struct zcl_proof_receipt r;

    g_why[0] = '\0';
    RC_CHECK("with no ledger wired, a group produces no receipt",
             !zcl_receipt_build(&r, &no_ledger, ZCL_RECEIPT_KIND_PASS,
                 ZCL_RECEIPT_VERDICT_PASS, g_root, NULL, "test_receipt",
                 g_vec, 131, "tc", "env", g_producer, g_why, sizeof(g_why)));
    RC_CHECK("and the refusal names the group",
             strstr(g_why, "test_receipt") != NULL);
    RC_CHECK("an unwired ledger answers UNKNOWN, never ELIGIBLE",
             zcl_receipt_group_eligibility(&no_ledger, "anything") ==
                 ZCL_RECEIPT_ELIGIBILITY_UNKNOWN);
    RC_CHECK("and the refusal is zeroed, not half-filled",
             is_all_zero(&r, sizeof(r)));

    g_why[0] = '\0';
    RC_CHECK("a timing-sensitive group produces no receipt",
             !zcl_receipt_build(&r, &timing_ledger, ZCL_RECEIPT_KIND_PASS,
                 ZCL_RECEIPT_VERDICT_PASS, g_root, NULL,
                 "test_block_status_event_restart_proof", g_vec, 131, "tc",
                 "env", g_producer, g_why, sizeof(g_why)));
    RC_CHECK("and says why, by name",
             strstr(g_why, "TIMING_SENSITIVE") != NULL);

    RC_CHECK("a ledger answering off the enum is not read as yes",
             zcl_receipt_group_eligibility(&bad_ledger, "g") ==
                 ZCL_RECEIPT_ELIGIBILITY_UNKNOWN);
    RC_CHECK("and it produces no receipt either",
             !zcl_receipt_build(&r, &bad_ledger, ZCL_RECEIPT_KIND_PASS,
                 ZCL_RECEIPT_VERDICT_PASS, g_root, NULL, "g", g_vec, 1, "tc",
                 "env", g_producer, g_why, sizeof(g_why)));

    RC_CHECK("a receipt with no group name is refused",
             !zcl_receipt_build(&r, &open_ledger, ZCL_RECEIPT_KIND_PASS,
                 ZCL_RECEIPT_VERDICT_PASS, g_root, NULL, "", g_vec, 131,
                 "tc", "env", g_producer, g_why, sizeof(g_why)));

    char long_group[ZCL_RECEIPT_GROUP_MAX + 8];
    memset(long_group, 'g', sizeof(long_group) - 1);
    long_group[sizeof(long_group) - 1] = '\0';
    RC_CHECK("a name that does not fit is refused, not truncated",
             !zcl_receipt_build(&r, &open_ledger, ZCL_RECEIPT_KIND_PASS,
                 ZCL_RECEIPT_VERDICT_PASS, g_root, NULL, long_group, g_vec,
                 131, "tc", "env", g_producer, g_why, sizeof(g_why)));
    return failures;
}

/* ── 5. belief is never read off the wire ─────────────────────────────── */

static int case_belief(void)
{
    int failures = 0;
    struct zcl_proof_receipt r;
    if (!build_pass(&r)) {
        printf("receipt: FAIL could not build the fixture receipt\n");
        return 1;
    }
    uint8_t none[32] = { 0 };

    RC_CHECK("a nonzero vector covering zero checks stays UNVERIFIED",
             zcl_receipt_corroborate(&r, g_vec, 0) ==
                 ZCL_RECEIPT_UNVERIFIED);
    RC_CHECK("a valid claim with no observed vector stays UNVERIFIED",
             zcl_receipt_corroborate(&r, NULL, 131) ==
                 ZCL_RECEIPT_UNVERIFIED);
    RC_CHECK("a node with no run of its own believes UNVERIFIED",
             zcl_receipt_corroborate(&r, none, 0) == ZCL_RECEIPT_UNVERIFIED);
    RC_CHECK("a claimed check count cannot substitute for a run",
             zcl_receipt_corroborate(&r, none, 131) ==
                 ZCL_RECEIPT_UNVERIFIED);
    RC_CHECK("the same vector over the same checks is CORROBORATED",
             zcl_receipt_corroborate(&r, g_vec, 131) ==
                 ZCL_RECEIPT_CORROBORATED);
    RC_CHECK("a different vector is REFUTED",
             zcl_receipt_corroborate(&r, g_other_vec, 131) ==
                 ZCL_RECEIPT_REFUTED);
    /* Same digest, different check count: the nodes did not run the same set. */
    RC_CHECK("a different check COUNT is REFUTED, not corroborated",
             zcl_receipt_corroborate(&r, g_vec, 130) == ZCL_RECEIPT_REFUTED);

    struct zcl_proof_receipt hollow;
    RC_CHECK("a claim that never published as a pass stays UNVERIFIED",
             zcl_receipt_build(&hollow, &open_ledger, ZCL_RECEIPT_KIND_PASS,
                 ZCL_RECEIPT_VERDICT_HOLLOW, g_root, NULL, "test_receipt",
                 g_vec, 131, "tc", "env", g_producer, g_why, sizeof(g_why)) &&
             zcl_receipt_corroborate(&hollow, g_vec, 131) ==
                 ZCL_RECEIPT_UNVERIFIED);

    RC_CHECK("a refutation under identical conditions is material",
             zcl_receipt_refutation_is_material(&r, g_root,
                 "gcc-13.2 -std=c23 -O2", "linux-glibc-x86_64-O2"));
    RC_CHECK("a different toolchain explains the disagreement by itself",
             !zcl_receipt_refutation_is_material(&r, g_root,
                 "clang-18 -std=c23 -O2", "linux-glibc-x86_64-O2"));
    RC_CHECK("so does a different environment class",
             !zcl_receipt_refutation_is_material(&r, g_root,
                 "gcc-13.2 -std=c23 -O2", "linux-musl-aarch64-O0"));
    RC_CHECK("and so does a different tree",
             !zcl_receipt_refutation_is_material(&r, g_base,
                 "gcc-13.2 -std=c23 -O2", "linux-glibc-x86_64-O2"));
    return failures;
}

/* ── 6. a red-delta must actually be a delta ──────────────────────────── */

static int case_red_delta(void)
{
    int failures = 0;
    struct zcl_proof_receipt rd;

    RC_CHECK("a red-delta over two different trees is built",
             zcl_receipt_build(&rd, &open_ledger, ZCL_RECEIPT_KIND_RED_DELTA,
                 ZCL_RECEIPT_VERDICT_PASS, g_root, g_base, "test_receipt",
                 g_vec, 131, "tc", "env", g_producer, g_why, sizeof(g_why)));
    RC_CHECK("and it publishes as a pass",
             zcl_receipt_is_publishable_pass(&rd));
    RC_CHECK("and it carries the tree that was red",
             !is_all_zero(rd.base_root, 32));

    RC_CHECK("a red-delta with no base tree is refused",
             !zcl_receipt_build(&rd, &open_ledger,
                 ZCL_RECEIPT_KIND_RED_DELTA, ZCL_RECEIPT_VERDICT_PASS,
                 g_root, NULL, "test_receipt", g_vec, 131, "tc", "env",
                 g_producer, g_why, sizeof(g_why)));
    RC_CHECK("a red-delta whose base IS the tree it fixed is refused",
             !zcl_receipt_build(&rd, &open_ledger,
                 ZCL_RECEIPT_KIND_RED_DELTA, ZCL_RECEIPT_VERDICT_PASS,
                 g_root, g_root, "test_receipt", g_vec, 131, "tc", "env",
                 g_producer, g_why, sizeof(g_why)));

    /* A plain pass carries no such tree: a stale one would sit inside the id. */
    struct zcl_proof_receipt plain;
    RC_CHECK("a plain pass does not carry a base tree",
             zcl_receipt_build(&plain, &open_ledger, ZCL_RECEIPT_KIND_PASS,
                 ZCL_RECEIPT_VERDICT_PASS, g_root, g_base, "test_receipt",
                 g_vec, 131, "tc", "env", g_producer, g_why,
                 sizeof(g_why)) &&
             is_all_zero(plain.base_root, 32));
    return failures;
}

/* ── labels and NULLs ─────────────────────────────────────────────────── */

static int case_labels(void)
{
    int failures = 0;
    static const struct { int value; const char *label; } kinds[] = {
        {ZCL_RECEIPT_KIND_PASS, "PASS_RECEIPT"},
        {ZCL_RECEIPT_KIND_RED_DELTA, "RED_DELTA_RECEIPT"},
        {-1, "UNKNOWN_KIND"}, {77, "UNKNOWN_KIND"},
    }, verdicts[] = {
        {ZCL_RECEIPT_VERDICT_PASS, "PASS"},
        {ZCL_RECEIPT_VERDICT_FAIL, "FAIL"},
        {ZCL_RECEIPT_VERDICT_HOLLOW, "HOLLOW"},
        {ZCL_RECEIPT_VERDICT_NO_CHANGE, "NO_CHANGE"},
        {ZCL_RECEIPT_VERDICT_TIMEOUT, "TIMEOUT"},
        {ZCL_RECEIPT_VERDICT_REFUSED, "REFUSED"},
        {ZCL_RECEIPT_VERDICT_UNVERIFIED, "UNVERIFIED"},
        {-1, "UNKNOWN_VERDICT"}, {77, "UNKNOWN_VERDICT"},
    }, beliefs[] = {
        {ZCL_RECEIPT_UNVERIFIED, "UNVERIFIED"},
        {ZCL_RECEIPT_CORROBORATED, "CORROBORATED"},
        {ZCL_RECEIPT_REFUTED, "REFUTED"},
        {-1, "UNKNOWN_BELIEF"}, {77, "UNKNOWN_BELIEF"},
    }, eligibilities[] = {
        {ZCL_RECEIPT_ELIGIBILITY_UNKNOWN, "UNKNOWN"},
        {ZCL_RECEIPT_ELIGIBLE, "ELIGIBLE"},
        {ZCL_RECEIPT_INELIGIBLE_NONDETERMINISTIC, "INELIGIBLE_NONDETERMINISTIC"},
        {ZCL_RECEIPT_INELIGIBLE_TIMING_SENSITIVE, "INELIGIBLE_TIMING_SENSITIVE"},
        {ZCL_RECEIPT_INELIGIBLE_NO_VECTOR, "INELIGIBLE_NO_VECTOR"},
        {-1, "UNKNOWN"}, {77, "UNKNOWN"},
    };
#define CHECK_LABELS(rows, type, label_fn)                            \
    for (size_t i = 0; i < sizeof(rows) / sizeof((rows)[0]); i++) {    \
        printf("receipt: label %s value=%d\n", #rows, (rows)[i].value); \
        RC_CHECK((rows)[i].label,                                    \
                 strcmp(label_fn((enum type)(rows)[i].value),        \
                        (rows)[i].label) == 0);                      \
    }
    CHECK_LABELS(kinds, zcl_receipt_kind, zcl_receipt_kind_label);
    CHECK_LABELS(verdicts, zcl_receipt_verdict, zcl_receipt_verdict_label);
    CHECK_LABELS(beliefs, zcl_receipt_belief, zcl_receipt_belief_label);
    CHECK_LABELS(eligibilities, zcl_receipt_eligibility, zcl_receipt_eligibility_label);
#undef CHECK_LABELS
    return failures;
}

static int case_surface(void)
{
    int failures = 0;
    struct zcl_proof_receipt r;
    bool have = build_pass(&r);

    uint8_t id[32];
    RC_CHECK("a NULL receipt is not valid", !zcl_receipt_is_valid(NULL));
    RC_CHECK("a NULL receipt does not publish",
             !zcl_receipt_is_publishable_pass(NULL));
    RC_CHECK("encoding to NULL writes nothing",
             have && zcl_receipt_encode(NULL, 999, &r) == 0);
    RC_CHECK("decoding from NULL refuses",
             !zcl_receipt_decode(NULL, NULL, 0));
    RC_CHECK("an id into NULL refuses", have && !zcl_receipt_id(NULL, &r));
    RC_CHECK("an id of NULL refuses", !zcl_receipt_id(id, NULL));
    RC_CHECK("corroborating nothing is UNVERIFIED",
             zcl_receipt_corroborate(NULL, g_vec, 1) ==
                 ZCL_RECEIPT_UNVERIFIED);
    RC_CHECK("a NULL claim is never a material refutation",
             !zcl_receipt_refutation_is_material(NULL, g_root, "a", "b"));
    return failures;
}

static int case_null_output(void)
{
    int failures = 0;
    memset(g_why, 0xa5, sizeof(g_why));
    RC_CHECK("building into NULL refuses",
        !zcl_receipt_build(NULL, &open_ledger, ZCL_RECEIPT_KIND_PASS,
            ZCL_RECEIPT_VERDICT_PASS, g_root, NULL, "test_receipt",
            g_vec, 131, "tc", "env", g_producer, g_why, sizeof(g_why)));
    RC_CHECK("NULL output identifies out and requests storage",
        memchr(g_why, '\0', sizeof(g_why)) != NULL &&
        strstr(g_why, "out is NULL") != NULL &&
        strstr(g_why, "provide output storage") != NULL);
    return failures;
}

static int case_null_output_unavailable_diagnostics(void)
{
    int failures = 0;
    char untouched[sizeof(g_why)];
    memset(untouched, 0xa5, sizeof(untouched));
    for (int mode = 0; mode < 2; mode++) {
        memcpy(g_why, untouched, sizeof(g_why));
        char *why = mode == 0 ? NULL : g_why;
        size_t why_cap = mode == 0 ? sizeof(g_why) : 0;
        RC_CHECK("NULL output refuses without diagnostic capacity",
            !zcl_receipt_build(NULL, &open_ledger, ZCL_RECEIPT_KIND_PASS,
                ZCL_RECEIPT_VERDICT_PASS, g_root, NULL, "test_receipt",
                g_vec, 131, "tc", "env", g_producer, why, why_cap));
        RC_CHECK("unavailable diagnostics leave the buffer unchanged",
            memcmp(g_why, untouched, sizeof(g_why)) == 0);
    }
    return failures;
}

static int case_enum_narrowing(void)
{
    int failures = 0;
    struct zcl_proof_receipt r;
    const int invalid[] = {257, 0, -1, 256};
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
        for (int operand = 0; operand < 2; operand++) {
            enum zcl_receipt_kind kind = operand == 0
                ? (enum zcl_receipt_kind)invalid[i] : ZCL_RECEIPT_KIND_PASS;
            enum zcl_receipt_verdict verdict = operand == 1
                ? (enum zcl_receipt_verdict)invalid[i] : ZCL_RECEIPT_VERDICT_PASS;
            memset(&r, 0xa5, sizeof(r));
            memset(g_why, 0, sizeof(g_why));
            RC_CHECK(operand == 0 ? "invalid full-width kind refuses"
                                  : "invalid full-width verdict refuses",
                !zcl_receipt_build(&r, &open_ledger, kind, verdict,
                    g_root, NULL, "test_receipt", g_vec, 131,
                    "gcc-13.2 -std=c23 -O2", "linux-glibc-x86_64-O2",
                    g_producer, g_why, sizeof(g_why)));
            RC_CHECK("invalid enum leaves no receipt", is_all_zero(&r, sizeof(r)));
            RC_CHECK("invalid enum explains the group and reason",
                strstr(g_why, "test_receipt") != NULL &&
                strstr(g_why, "not structurally valid") != NULL);
        }
    }
    return failures;
}

int test_receipt(void);
int test_receipt(void)
{
    int failures = 0;
    fixtures_init();
    failures += case_canonical();
    failures += case_refusal_is_clean();
    failures += case_structural_refusals();
    failures += case_id();
    failures += case_publishable();
    failures += case_eligibility();
    failures += case_belief();
    failures += case_red_delta();
    failures += case_labels();
    failures += case_surface();
    failures += case_null_output();
    failures += case_null_output_unavailable_diagnostics();
    failures += case_enum_narrowing();
    printf("receipt: %d failure(s)\n", failures);
    return failures;
}
