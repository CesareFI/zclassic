/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Property grant engine tests: the rules (contexts/commons/modules/metaverse) and the
 * PLAN -> COMMIT -> RECEIPT state machine (services/property_grant_service.h).
 *
 * Only the property catalog and the clock are faked; the rules, store, receipt
 * codec, hash chain and Ed25519 signer are shipped code. Tamper cases corrupt
 * the real store through the service's test-only hook.
 * Proves: codec round-trips; PLAN refuses each violation with its own named
 * reason; COMMIT re-checks stale revision, owner, revocation and catalog;
 * revocation covers a delegation subtree (revoked flag and generation each
 * proven alone on the pure evaluator); idempotent replay; tamper-evident
 * receipt chain; delegation only narrows; budget and rate window bind; a
 * commit that mints no receipt leaves the store bit-identical.
 *
 * One TEST block per function: ASSERT jumps to `_test_next`. */

#include "test/test_core.h"

#include "crypto/ed25519.h"
#include "metaverse/property_grant.h"
#include "metaverse/property_id.h"
#include "metaverse/property_receipt.h"
#include "services/property_grant_service.h"

#include <stdio.h>
#include <string.h>

static const char *const k_holder = "t1MetaverseGrantHolderAccount0000000";
static const char *const k_other = "t1MetaverseSomeoneElseAccount0000000";
static const char *const k_buyer = "t1MetaverseBuyerCounterparty00000000";
static const char *const k_stranger = "t1MetaverseStrangerCounterparty00000";

/* ── Fakes for the two declared seams ───────────────────────────────────── */

static int64_t g_now = 1700000000;
static int64_t g_height = 900000;

static void fake_clock(int64_t *now_unix, int64_t *height, void *ctx)
{
    (void)ctx;
    if (now_unix) *now_unix = g_now;
    if (height) *height = g_height;
}

struct fake_catalog {
    struct metaverse_property_id id;
    char controller[METAVERSE_PRINCIPAL_MAX + 1];
    int64_t revision;
    bool present;
};

static struct fake_catalog g_cat;

static bool fake_lookup(const struct metaverse_property_id *id,
                        struct metaverse_catalog_view *out, void *ctx)
{
    (void)ctx;
    if (!g_cat.present) return false;
    if (!metaverse_property_id_equal(&g_cat.id, id)) return false;
    out->id = *id;
    snprintf(out->controller, sizeof(out->controller), "%s", g_cat.controller);
    out->revision = g_cat.revision;
    out->freshness_height = g_height;
    return true;
}

/* ── Fixture helpers ────────────────────────────────────────────────────── */

static struct metaverse_property_id make_id(enum metaverse_kind kind,
                                            uint8_t tag)
{
    struct metaverse_property_id id;
    memset(&id, 0, sizeof(id));
    id.kind = kind;
    for (size_t i = 0; i < METAVERSE_ROOT_BYTES; i++)
        id.root[i] = (uint8_t)(tag + i);
    return id;
}

/* Install the fakes and clear every store so no case inherits leftovers. */
static void fixture_reset(const struct metaverse_property_id *prop)
{
    property_grant_service_reset();
    g_now = 1700000000;
    g_height = 900000;

    memset(&g_cat, 0, sizeof(g_cat));
    if (prop) {
        g_cat.id = *prop;
        g_cat.present = true;
        g_cat.revision = 7;
        snprintf(g_cat.controller, sizeof(g_cat.controller), "%s", k_holder);
    }

    struct property_grant_env env;
    memset(&env, 0, sizeof(env));
    env.catalog_lookup = fake_lookup;
    env.clock = fake_clock;
    property_grant_service_configure(&env);

    uint8_t seed[32];
    memset(seed, 0xA5, sizeof(seed));
    property_grant_service_set_signing_seed(seed);
}

/* A root grant over exactly one property id. */
static struct metaverse_grant grant_over_id(
    const struct metaverse_property_id *id, metaverse_action_set actions,
    int64_t budget_zat)
{
    struct metaverse_grant g;
    memset(&g, 0, sizeof(g));
    snprintf(g.holder, sizeof(g.holder), "%s", k_holder);
    snprintf(g.issuer, sizeof(g.issuer), "%s", k_holder);
    g.scope_form = METAVERSE_SCOPE_IDS;
    g.ids[0] = *id;
    g.id_count = 1;
    g.actions = actions;
    g.max_value_zat = budget_zat;
    return g;
}

static struct metaverse_action_request request_for(
    const struct metaverse_property_id *id, enum metaverse_action a,
    const char *counterparty, int64_t value_zat)
{
    struct metaverse_action_request r;
    memset(&r, 0, sizeof(r));
    snprintf(r.actor, sizeof(r.actor), "%s", k_holder);
    r.property = *id;
    r.action = a;
    if (counterparty)
        snprintf(r.counterparty, sizeof(r.counterparty), "%s", counterparty);
    r.value_zat = value_zat;
    return r;
}

/* Commit `n` 1000-zatoshi BUYs, each under its own key. 0 on success, -1 on first refusal. */
static int commit_n(const struct metaverse_grant *g,
                    const struct metaverse_property_id *prop, int n)
{
    for (int i = 0; i < n; i++) {
        struct metaverse_action_request r =
            request_for(prop, METAVERSE_ACTION_BUY, NULL, 1000);
        struct property_grant_plan plan;
        if (property_grant_service_plan(g->grant_id, &r, &plan) !=
            PROPERTY_GRANT_OK)
            return -1;
        char key[32];
        snprintf(key, sizeof(key), "seq-%d", i);
        struct property_grant_commit_result res;
        if (property_grant_service_commit(plan.plan_id, key, &res) !=
            PROPERTY_GRANT_OK)
            return -1;
    }
    return 0;
}

#define ACT(a) metaverse_action_bit(METAVERSE_ACTION_##a)

/* ── 1. Codecs ──────────────────────────────────────────────────────────── */

static int t_id_roundtrip(void)
{
    int failures = 0;
    TEST("property id renders and re-parses to the same value") {
        struct metaverse_property_id id =
            make_id(METAVERSE_KIND_ZCODE_PACKAGE, 3);
        char text[METAVERSE_ID_TEXT_MAX + 1];
        ASSERT(metaverse_property_id_format(&id, text, sizeof(text)));
        ASSERT(strncmp(text, "zcode_package:", 14) == 0);
        struct metaverse_property_id back;
        ASSERT(metaverse_property_id_parse(text, &back));
        ASSERT(metaverse_property_id_equal(&id, &back));
        PASS();
    } _test_next:;
    return failures;
}

static int t_id_rejects(void)
{
    int failures = 0;
    TEST("malformed property ids are rejected, not guessed") {
        struct metaverse_property_id out;
        ASSERT(!metaverse_property_id_parse("content", &out));
        ASSERT(!metaverse_property_id_parse("no-such-kind:00", &out));
        ASSERT(!metaverse_property_id_parse("content:beef", &out));
        ASSERT_EQ((int)metaverse_kind_from_name("unknown"),
                  (int)METAVERSE_KIND_UNKNOWN);
        ASSERT_EQ((int)metaverse_kind_from_name(NULL),
                  (int)METAVERSE_KIND_UNKNOWN);
        ASSERT_STR_EQ(metaverse_kind_name(METAVERSE_KIND_CONTRACT_SWAP),
                      "contract_swap");
        PASS();
    } _test_next:;
    return failures;
}

static int t_action_set_codec(void)
{
    int failures = 0;
    TEST("action sets round-trip and reject a typo whole") {
        metaverse_action_set set = 0;
        ASSERT(metaverse_action_set_parse("host,publish_revision", &set));
        ASSERT(set == (ACT(HOST) | ACT(PUBLISH_REVISION)));
        char rendered[256];
        ASSERT(metaverse_action_mask_format(set, rendered, sizeof(rendered)));
        ASSERT_STR_EQ(rendered, "host,publish_revision");

        /* Both separators are accepted on input; output is canonical underscore. */
        metaverse_action_set hyphenated = 0;
        ASSERT(metaverse_action_set_parse("host,publish-revision",
                                          &hyphenated));
        ASSERT(hyphenated == set);

        /* One bad element fails the whole parse; the good element must be a real action. */
        metaverse_action_set bad = 0xFFFF;
        ASSERT(!metaverse_action_set_parse("host,hosst", &bad));

        metaverse_action_set empty = 0xFFFF;
        ASSERT(metaverse_action_set_parse("", &empty));
        ASSERT_EQ((int)empty, 0);
        PASS();
    } _test_next:;
    return failures;
}

static int t_value_actions(void)
{
    int failures = 0;
    TEST("value-moving actions are exactly the five that move value") {
        ASSERT(metaverse_action_moves_value(METAVERSE_ACTION_BUY));
        ASSERT(metaverse_action_moves_value(METAVERSE_ACTION_SELL));
        ASSERT(metaverse_action_moves_value(METAVERSE_ACTION_LEASE));
        ASSERT(metaverse_action_moves_value(METAVERSE_ACTION_TRANSFER));
        ASSERT(metaverse_action_moves_value(METAVERSE_ACTION_ACCEPT_PAYMENT));
        ASSERT(!metaverse_action_moves_value(METAVERSE_ACTION_HOST));
        ASSERT(!metaverse_action_moves_value(METAVERSE_ACTION_DELEGATE));

        /* "May carry a value" and "is charged" differ: LIST_FOR_SALE carries a price but moves nothing. */
        ASSERT(metaverse_action_accepts_value(METAVERSE_ACTION_LIST_FOR_SALE));
        ASSERT(!metaverse_action_moves_value(METAVERSE_ACTION_LIST_FOR_SALE));
        ASSERT(!metaverse_action_accepts_value(METAVERSE_ACTION_HOST));
        PASS();
    } _test_next:;
    return failures;
}

/* ── 1b. the reserved bit ───────────────────────────────────────────────
 * "inspect" is not an action; asserted here directly. */

static int t_reserved_inspect_names_no_action(void)
{
    int failures = 0;
    TEST("the reserved inspect bit is legible but names no action") {
        /* Renders legibly but is invalid, so a stale mask never confers a right. */
        ASSERT(metaverse_action_name(METAVERSE_ACTION_RESERVED_INSPECT) != NULL);
        ASSERT_EQ(strcmp(metaverse_action_name(METAVERSE_ACTION_RESERVED_INSPECT),
                         "inspect"), 0);
        ASSERT(!metaverse_action_valid(
            (enum metaverse_action)METAVERSE_ACTION_RESERVED_INSPECT));
        ASSERT_EQ((int)metaverse_action_bit(
                      (enum metaverse_action)METAVERSE_ACTION_RESERVED_INSPECT),
                  0);

        ASSERT_EQ((int)metaverse_action_from_name("inspect"), 0);
        enum metaverse_action parsed = METAVERSE_ACTION_HOST;
        ASSERT(!metaverse_action_parse("inspect", &parsed));
        metaverse_action_set set = 0xffffffffu;
        ASSERT(!metaverse_action_set_parse("inspect", &set));
        ASSERT(!metaverse_action_set_parse("host,inspect", &set));
        ASSERT(!metaverse_action_mask_valid(METAVERSE_ACTION_RESERVED_INSPECT));
        ASSERT_EQ((int)(METAVERSE_ACTION_ALL & METAVERSE_ACTION_RESERVED), 0);

        /* An unnameable operation gets no permissions: every fact column is false. */
        enum metaverse_action rb =
            (enum metaverse_action)METAVERSE_ACTION_RESERVED_INSPECT;
        ASSERT(!metaverse_action_changes_local_state(rb));
        ASSERT(!metaverse_action_changes_external_state(rb));
        ASSERT(!metaverse_action_changes_state(rb));
        ASSERT(!metaverse_action_changes_title(rb));
        ASSERT(!metaverse_action_accepts_value(rb));
        ASSERT(!metaverse_action_moves_value(rb));
        ASSERT(!metaverse_action_uses_counterparty(rb));
        ASSERT(!metaverse_action_requires_receipt(rb));
        ASSERT(!metaverse_action_requires_plan_commit(rb));
        ASSERT(!metaverse_action_is_mutation(rb));
        PASS();
    } _test_next:;
    return failures;
}

static int t_reserved_inspect_authorizes_nothing(void)
{
    int failures = 0;
    TEST("a grant carrying the reserved bit authorizes nothing at PLAN") {
        struct metaverse_property_id prop = make_id(METAVERSE_KIND_CONTENT, 61);
        fixture_reset(&prop);
        /* Written raw, not through ACT(): the shape a legacy mask deserializes into. */
        struct metaverse_grant g = grant_over_id(&prop, 0, 0);
        g.actions = METAVERSE_ACTION_RESERVED_INSPECT;

        /* An unnameable bit makes the record malformed, refused at the boundary. */
        ASSERT(!metaverse_grant_well_formed(&g));
        ASSERT_EQ((int)property_grant_service_mint(&g),
                  (int)PROPERTY_GRANT_GRANT_MALFORMED);

        /* Control: the same record with a real action mints. */
        struct metaverse_grant ok = g;
        ok.actions = ACT(HOST);
        ASSERT(metaverse_grant_well_formed(&ok));
        ASSERT_EQ((int)property_grant_service_mint(&ok), (int)PROPERTY_GRANT_OK);

        /* A record that reached memory another way still authorizes nothing; evaluated directly. */
        snprintf(g.grant_id, sizeof(g.grant_id),
                 "11111111111111111111111111111111");
        struct metaverse_action_request req =
            request_for(&prop, METAVERSE_ACTION_HOST, NULL, 0);
        req.now_unix = 1700000000;
        req.height = 900000;
        ASSERT_EQ((int)metaverse_grant_check(&g, NULL, 0, &req),
                  (int)METAVERSE_GRANT_MALFORMED);

        /* Asking for the reserved bit is a malformed request, not ACTION_NOT_GRANTED. */
        struct metaverse_action_request bad =
            request_for(&prop, METAVERSE_ACTION_HOST, NULL, 0);
        bad.now_unix = 1700000000;
        bad.height = 900000;
        ASSERT_EQ((int)metaverse_grant_check(&ok, NULL, 0, &bad),
                  (int)METAVERSE_GRANT_OK);
        bad.action = (enum metaverse_action)METAVERSE_ACTION_RESERVED_INSPECT;
        ASSERT_EQ((int)metaverse_grant_check(&ok, NULL, 0, &bad),
                  (int)METAVERSE_GRANT_BAD_ARGS);

        /* Nothing was recorded against the one grant that did mint. */
        struct metaverse_receipt rc[4];
        ASSERT_EQ((int)property_grant_service_receipts(ok.grant_id, rc, 4), 0);
        PASS();
    } _test_next:;
    return failures;
}

/* ── 1c. reads are a separate vocabulary ────────────────────────────────
 * Reads go through the grant's query field. */

static const char k_query_grant_id[] = "cccccccccccccccccccccccccccccccc";

/* A grant that may INSPECT one property and HOST it, and nothing else. */
static struct metaverse_grant query_grant(
    const struct metaverse_property_id *prop)
{
    struct metaverse_grant g = grant_over_id(prop, ACT(HOST), 0);
    snprintf(g.grant_id, sizeof(g.grant_id), "%s", k_query_grant_id);
    g.queries = METAVERSE_QUERY_INSPECT_PROPERTY;
    return g;
}

static struct metaverse_query_request query_for(
    const struct metaverse_property_id *prop, enum metaverse_query q)
{
    struct metaverse_query_request r;
    memset(&r, 0, sizeof(r));
    snprintf(r.actor, sizeof(r.actor), "%s", k_holder);
    if (prop)
        r.property = *prop;
    r.query = q;
    r.now_unix = 1700000000;
    r.height = 900000;
    return r;
}

static int t_query_allowed(void)
{
    int failures = 0;
    TEST("a held query over an in-scope property is allowed") {
        struct metaverse_property_id prop = make_id(METAVERSE_KIND_CONTENT, 62);
        struct metaverse_grant g = query_grant(&prop);
        struct metaverse_query_request q =
            query_for(&prop, METAVERSE_QUERY_INSPECT_PROPERTY);
        ASSERT_EQ((int)metaverse_grant_query_check(&g, NULL, 0, &q),
                  (int)METAVERSE_GRANT_OK);
        PASS();
    } _test_next:;
    return failures;
}

static int t_query_not_granted(void)
{
    int failures = 0;
    TEST("a query the grant does not hold is ACTION_NOT_GRANTED") {
        struct metaverse_property_id prop = make_id(METAVERSE_KIND_CONTENT, 62);
        struct metaverse_grant g = query_grant(&prop);
        /* A missing READ right reports the same verdict as a missing action right. */
        struct metaverse_query_request q =
            query_for(&prop, METAVERSE_QUERY_ENUMERATE_PROPERTIES);
        ASSERT_EQ((int)metaverse_grant_query_check(&g, NULL, 0, &q),
                  (int)METAVERSE_GRANT_ACTION_NOT_GRANTED);
        PASS();
    } _test_next:;
    return failures;
}

static int t_query_property_out_of_scope(void)
{
    int failures = 0;
    TEST("a query outside the grant's scope is PROPERTY_OUT_OF_SCOPE") {
        struct metaverse_property_id prop = make_id(METAVERSE_KIND_CONTENT, 62);
        struct metaverse_property_id other =
            make_id(METAVERSE_KIND_CONTENT, 63);
        struct metaverse_grant g = query_grant(&prop);
        struct metaverse_query_request q =
            query_for(&other, METAVERSE_QUERY_INSPECT_PROPERTY);
        ASSERT_EQ((int)metaverse_grant_query_check(&g, NULL, 0, &q),
                  (int)METAVERSE_GRANT_PROPERTY_OUT_OF_SCOPE);
        PASS();
    } _test_next:;
    return failures;
}

static int t_query_wrong_holder(void)
{
    int failures = 0;
    TEST("a query by an actor other than the holder is WRONG_HOLDER") {
        struct metaverse_property_id prop = make_id(METAVERSE_KIND_CONTENT, 62);
        struct metaverse_grant g = query_grant(&prop);
        struct metaverse_query_request q =
            query_for(&prop, METAVERSE_QUERY_INSPECT_PROPERTY);
        snprintf(q.actor, sizeof(q.actor), "%s", "somebody-else");
        ASSERT_EQ((int)metaverse_grant_query_check(&g, NULL, 0, &q),
                  (int)METAVERSE_GRANT_WRONG_HOLDER);
        PASS();
    } _test_next:;
    return failures;
}

static int t_query_expiry_and_revocation(void)
{
    int failures = 0;
    TEST("an expired or revoked grant refuses READS too") {
        struct metaverse_property_id prop = make_id(METAVERSE_KIND_CONTENT, 62);
        struct metaverse_grant g = query_grant(&prop);
        struct metaverse_query_request q =
            query_for(&prop, METAVERSE_QUERY_INSPECT_PROPERTY);

        /* Control: nothing expired, so OK. */
        ASSERT_EQ((int)metaverse_grant_query_check(&g, NULL, 0, &q),
                  (int)METAVERSE_GRANT_OK);

        g.expires_height = q.height - 1;
        ASSERT_EQ((int)metaverse_grant_query_check(&g, NULL, 0, &q),
                  (int)METAVERSE_GRANT_EXPIRED_HEIGHT);
        g.expires_height = 0;

        g.expires_unix = q.now_unix - 1;
        ASSERT_EQ((int)metaverse_grant_query_check(&g, NULL, 0, &q),
                  (int)METAVERSE_GRANT_EXPIRED_TIME);
        g.expires_unix = 0;

        g.revoked = true;
        ASSERT_EQ((int)metaverse_grant_query_check(&g, NULL, 0, &q),
                  (int)METAVERSE_GRANT_REVOKED);
        PASS();
    } _test_next:;
    return failures;
}

static int t_query_and_action_sets_do_not_leak(void)
{
    int failures = 0;
    TEST("holding every ACTION confers no read right, and the reverse") {
        struct metaverse_property_id prop = make_id(METAVERSE_KIND_CONTENT, 62);

        /* The two sets do not leak into each other. */
        struct metaverse_grant all_actions =
            grant_over_id(&prop, METAVERSE_ACTION_ALL, 0);
        snprintf(all_actions.grant_id, sizeof(all_actions.grant_id),
                 "dddddddddddddddddddddddddddddddd");
        all_actions.queries = 0;
        struct metaverse_query_request q =
            query_for(&prop, METAVERSE_QUERY_INSPECT_PROPERTY);
        ASSERT_EQ((int)metaverse_grant_query_check(&all_actions, NULL, 0, &q),
                  (int)METAVERSE_GRANT_ACTION_NOT_GRANTED);

        struct metaverse_grant reads_only = grant_over_id(&prop, 0, 0);
        snprintf(reads_only.grant_id, sizeof(reads_only.grant_id),
                 "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee");
        reads_only.queries = METAVERSE_QUERY_ALL;
        struct metaverse_action_request act =
            request_for(&prop, METAVERSE_ACTION_HOST, NULL, 0);
        act.now_unix = 1700000000;
        act.height = 900000;
        ASSERT_EQ((int)metaverse_grant_check(&reads_only, NULL, 0, &act),
                  (int)METAVERSE_GRANT_ACTION_NOT_GRANTED);
        PASS();
    } _test_next:;
    return failures;
}

static int t_query_enumerate_names_no_property(void)
{
    int failures = 0;
    TEST("enumerate may arrive with a zeroed id and still does not widen "
         "scope") {
        struct metaverse_property_id prop = make_id(METAVERSE_KIND_CONTENT, 62);
        struct metaverse_property_id other =
            make_id(METAVERSE_KIND_CONTENT, 63);
        ASSERT(metaverse_query_allows_zero_property_id(
            METAVERSE_QUERY_ENUMERATE_PROPERTIES));
        ASSERT(!metaverse_query_allows_zero_property_id(
            METAVERSE_QUERY_INSPECT_PROPERTY));

        struct metaverse_grant e = grant_over_id(&prop, 0, 0);
        snprintf(e.grant_id, sizeof(e.grant_id),
                 "ffffffffffffffffffffffffffffffff");
        e.queries = METAVERSE_QUERY_ENUMERATE_PROPERTIES;

        struct metaverse_query_request eq =
            query_for(NULL, METAVERSE_QUERY_ENUMERATE_PROPERTIES);
        ASSERT_EQ((int)metaverse_grant_query_check(&e, NULL, 0, &eq),
                  (int)METAVERSE_GRANT_OK);

        /* Enumerate right is not see-everything: the id scope still filters rows. */
        ASSERT(metaverse_grant_in_scope(&e, &prop));
        ASSERT(!metaverse_grant_in_scope(&e, &other));
        PASS();
    } _test_next:;
    return failures;
}


/* ── 2. PLAN fails fast ─────────────────────────────────────────────────── */

static int t_plan_action_not_granted(void)
{
    int failures = 0;
    TEST("an action outside the grant's set is refused at PLAN") {
        struct metaverse_property_id prop = make_id(METAVERSE_KIND_CONTENT, 11);
        fixture_reset(&prop);
        struct metaverse_grant g =
            grant_over_id(&prop, ACT(HOST) | ACT(PUBLISH_REVISION), 0);
        ASSERT_EQ((int)property_grant_service_mint(&g), (int)PROPERTY_GRANT_OK);

        struct metaverse_action_request r =
            request_for(&prop, METAVERSE_ACTION_TRANSFER, NULL, 0);
        struct property_grant_plan plan;
        ASSERT_EQ((int)property_grant_service_plan(g.grant_id, &r, &plan),
                  (int)PROPERTY_GRANT_ACTION_NOT_GRANTED);
        /* Fails fast means NOTHING was recorded. */
        struct metaverse_receipt rc[4];
        ASSERT_EQ((int)property_grant_service_receipts(g.grant_id, rc, 4), 0);
        PASS();
    } _test_next:;
    return failures;
}

static int t_plan_property_out_of_scope(void)
{
    int failures = 0;
    TEST("a property outside an id-scoped grant is refused at PLAN") {
        struct metaverse_property_id prop = make_id(METAVERSE_KIND_CONTENT, 11);
        fixture_reset(&prop);
        struct metaverse_grant g = grant_over_id(&prop, ACT(HOST), 0);
        ASSERT_EQ((int)property_grant_service_mint(&g), (int)PROPERTY_GRANT_OK);
        struct metaverse_property_id other = make_id(METAVERSE_KIND_CONTENT, 99);
        struct metaverse_action_request r =
            request_for(&other, METAVERSE_ACTION_HOST, NULL, 0);
        struct property_grant_plan plan;
        ASSERT_EQ((int)property_grant_service_plan(g.grant_id, &r, &plan),
                  (int)PROPERTY_GRANT_PROPERTY_OUT_OF_SCOPE);
        PASS();
    } _test_next:;
    return failures;
}

static int t_plan_kind_out_of_scope(void)
{
    int failures = 0;
    TEST("a kind-scoped grant refuses another kind at PLAN") {
        struct metaverse_property_id zc =
            make_id(METAVERSE_KIND_ZCODE_PACKAGE, 21);
        fixture_reset(&zc);
        struct metaverse_grant g;
        memset(&g, 0, sizeof(g));
        snprintf(g.holder, sizeof(g.holder), "%s", k_holder);
        g.scope_form = METAVERSE_SCOPE_KINDS;
        g.kinds = metaverse_kind_bit(METAVERSE_KIND_CONTENT);
        g.actions = ACT(HOST);
        ASSERT_EQ((int)property_grant_service_mint(&g), (int)PROPERTY_GRANT_OK);
        struct metaverse_action_request r =
            request_for(&zc, METAVERSE_ACTION_HOST, NULL, 0);
        struct property_grant_plan plan;
        ASSERT_EQ((int)property_grant_service_plan(g.grant_id, &r, &plan),
                  (int)PROPERTY_GRANT_KIND_OUT_OF_SCOPE);
        PASS();
    } _test_next:;
    return failures;
}

static int t_plan_counterparty(void)
{
    int failures = 0;
    TEST("a counterparty outside the allowlist is refused at PLAN") {
        struct metaverse_property_id prop = make_id(METAVERSE_KIND_CONTENT, 11);
        fixture_reset(&prop);
        struct metaverse_grant g = grant_over_id(&prop, ACT(SELL), 500000);
        snprintf(g.counterparties[0], sizeof(g.counterparties[0]), "%s",
                 k_buyer);
        g.counterparty_count = 1;
        ASSERT_EQ((int)property_grant_service_mint(&g), (int)PROPERTY_GRANT_OK);

        struct property_grant_plan plan;
        struct metaverse_action_request bad =
            request_for(&prop, METAVERSE_ACTION_SELL, k_stranger, 1000);
        ASSERT_EQ((int)property_grant_service_plan(g.grant_id, &bad, &plan),
                  (int)PROPERTY_GRANT_COUNTERPARTY_NOT_ALLOWED);
        /* The allowlisted counterparty passes, so the refusal was the allowlist. */
        struct metaverse_action_request ok =
            request_for(&prop, METAVERSE_ACTION_SELL, k_buyer, 1000);
        ASSERT_EQ((int)property_grant_service_plan(g.grant_id, &ok, &plan),
                  (int)PROPERTY_GRANT_OK);
        PASS();
    } _test_next:;
    return failures;
}

static int t_plan_budget(void)
{
    int failures = 0;
    TEST("a budget-exceeding action is refused at PLAN") {
        struct metaverse_property_id prop = make_id(METAVERSE_KIND_CONTENT, 11);
        fixture_reset(&prop);
        struct metaverse_grant g = grant_over_id(&prop, ACT(BUY), 100000);
        ASSERT_EQ((int)property_grant_service_mint(&g), (int)PROPERTY_GRANT_OK);
        struct property_grant_plan plan;
        struct metaverse_action_request over =
            request_for(&prop, METAVERSE_ACTION_BUY, NULL, 100001);
        ASSERT_EQ((int)property_grant_service_plan(g.grant_id, &over, &plan),
                  (int)PROPERTY_GRANT_BUDGET_EXCEEDED);
        struct metaverse_action_request at_cap =
            request_for(&prop, METAVERSE_ACTION_BUY, NULL, 100000);
        ASSERT_EQ((int)property_grant_service_plan(g.grant_id, &at_cap, &plan),
                  (int)PROPERTY_GRANT_OK);
        PASS();
    } _test_next:;
    return failures;
}

static int t_plan_value_shape(void)
{
    int failures = 0;
    TEST("value on a free action and a negative value each name themselves") {
        struct metaverse_property_id prop = make_id(METAVERSE_KIND_CONTENT, 11);
        fixture_reset(&prop);
        struct metaverse_grant g =
            grant_over_id(&prop, ACT(HOST) | ACT(BUY), 100000);
        ASSERT_EQ((int)property_grant_service_mint(&g), (int)PROPERTY_GRANT_OK);

        /* HOST is granted, in scope and takes no value, so only the value can be refused. */
        ASSERT(!metaverse_action_accepts_value(METAVERSE_ACTION_HOST));
        struct property_grant_plan plan;
        struct metaverse_action_request free_with_value =
            request_for(&prop, METAVERSE_ACTION_HOST, NULL, 5);
        ASSERT_EQ((int)property_grant_service_plan(g.grant_id, &free_with_value,
                                                   &plan),
                  (int)PROPERTY_GRANT_VALUE_ON_FREE_ACTION);

        struct metaverse_action_request negative =
            request_for(&prop, METAVERSE_ACTION_BUY, NULL, -1);
        ASSERT_EQ((int)property_grant_service_plan(g.grant_id, &negative,
                                                   &plan),
                  (int)PROPERTY_GRANT_VALUE_NEGATIVE);
        PASS();
    } _test_next:;
    return failures;
}

static int t_plan_wrong_holder(void)
{
    int failures = 0;
    TEST("an actor who is not the grant's holder is refused at PLAN") {
        struct metaverse_property_id prop = make_id(METAVERSE_KIND_CONTENT, 11);
        fixture_reset(&prop);
        struct metaverse_grant g = grant_over_id(&prop, ACT(HOST), 0);
        ASSERT_EQ((int)property_grant_service_mint(&g), (int)PROPERTY_GRANT_OK);
        struct metaverse_action_request imposter =
            request_for(&prop, METAVERSE_ACTION_HOST, NULL, 0);
        snprintf(imposter.actor, sizeof(imposter.actor), "%s", k_other);
        struct property_grant_plan plan;
        ASSERT_EQ((int)property_grant_service_plan(g.grant_id, &imposter,
                                                   &plan),
                  (int)PROPERTY_GRANT_WRONG_HOLDER);
        PASS();
    } _test_next:;
    return failures;
}

static int t_plan_expiry(void)
{
    int failures = 0;
    TEST("both expiry forms are enforced at PLAN") {
        struct metaverse_property_id prop = make_id(METAVERSE_KIND_CONTENT, 11);
        fixture_reset(&prop);
        struct metaverse_action_request r =
            request_for(&prop, METAVERSE_ACTION_HOST, NULL, 0);
        struct property_grant_plan plan;

        struct metaverse_grant byh = grant_over_id(&prop, ACT(HOST), 0);
        byh.expires_height = g_height;   /* already reached */
        ASSERT_EQ((int)property_grant_service_mint(&byh),
                  (int)PROPERTY_GRANT_OK);
        ASSERT_EQ((int)property_grant_service_plan(byh.grant_id, &r, &plan),
                  (int)PROPERTY_GRANT_GRANT_EXPIRED_HEIGHT);

        struct metaverse_grant byt = grant_over_id(&prop, ACT(HOST), 0);
        byt.expires_unix = g_now - 1;
        ASSERT_EQ((int)property_grant_service_mint(&byt),
                  (int)PROPERTY_GRANT_OK);
        ASSERT_EQ((int)property_grant_service_plan(byt.grant_id, &r, &plan),
                  (int)PROPERTY_GRANT_GRANT_EXPIRED_TIME);
        PASS();
    } _test_next:;
    return failures;
}

/* ── 3. COMMIT re-checks ────────────────────────────────────────────────── */

static int t_commit_stale_revision(void)
{
    int failures = 0;
    TEST("a property revised between PLAN and COMMIT is STALE_REVISION") {
        struct metaverse_property_id prop = make_id(METAVERSE_KIND_CONTENT, 31);
        fixture_reset(&prop);
        struct metaverse_grant g =
            grant_over_id(&prop, ACT(PUBLISH_REVISION), 0);
        ASSERT_EQ((int)property_grant_service_mint(&g), (int)PROPERTY_GRANT_OK);

        struct metaverse_action_request r =
            request_for(&prop, METAVERSE_ACTION_PUBLISH_REVISION, NULL, 0);
        struct property_grant_plan plan;
        ASSERT_EQ((int)property_grant_service_plan(g.grant_id, &r, &plan),
                  (int)PROPERTY_GRANT_OK);
        ASSERT_EQ((int)plan.property_revision, 7);

        /* Somebody else publishes a revision in between. */
        g_cat.revision = 8;

        struct property_grant_commit_result res;
        ASSERT_EQ((int)property_grant_service_commit(plan.plan_id, "k", &res),
                  (int)PROPERTY_GRANT_STALE_REVISION);
        struct metaverse_receipt rc[4];
        ASSERT_EQ((int)property_grant_service_receipts(g.grant_id, rc, 4), 0);

        /* Re-planning against the current revision commits cleanly. */
        ASSERT_EQ((int)property_grant_service_plan(g.grant_id, &r, &plan),
                  (int)PROPERTY_GRANT_OK);
        ASSERT_EQ((int)plan.property_revision, 8);
        ASSERT_EQ((int)property_grant_service_commit(plan.plan_id, "k2", &res),
                  (int)PROPERTY_GRANT_OK);
        ASSERT_EQ((int)res.receipt.property_revision, 8);
        PASS();
    } _test_next:;
    return failures;
}

static int t_commit_owner_mismatch(void)
{
    int failures = 0;
    TEST("a property that changed controller is OWNER_MISMATCH") {
        struct metaverse_property_id prop = make_id(METAVERSE_KIND_CONTENT, 31);
        fixture_reset(&prop);
        struct metaverse_grant g = grant_over_id(&prop, ACT(HOST), 0);
        ASSERT_EQ((int)property_grant_service_mint(&g), (int)PROPERTY_GRANT_OK);
        struct metaverse_action_request r =
            request_for(&prop, METAVERSE_ACTION_HOST, NULL, 0);
        struct property_grant_plan plan;
        ASSERT_EQ((int)property_grant_service_plan(g.grant_id, &r, &plan),
                  (int)PROPERTY_GRANT_OK);

        snprintf(g_cat.controller, sizeof(g_cat.controller), "%s", k_other);

        struct property_grant_commit_result res;
        ASSERT_EQ((int)property_grant_service_commit(plan.plan_id, "k", &res),
                  (int)PROPERTY_GRANT_OWNER_MISMATCH);
        PASS();
    } _test_next:;
    return failures;
}

static int t_commit_property_unknown(void)
{
    int failures = 0;
    TEST("a property that left the catalog is PROPERTY_UNKNOWN") {
        struct metaverse_property_id prop = make_id(METAVERSE_KIND_CONTENT, 31);
        fixture_reset(&prop);
        struct metaverse_grant g = grant_over_id(&prop, ACT(HOST), 0);
        ASSERT_EQ((int)property_grant_service_mint(&g), (int)PROPERTY_GRANT_OK);
        struct metaverse_action_request r =
            request_for(&prop, METAVERSE_ACTION_HOST, NULL, 0);
        struct property_grant_plan plan;
        ASSERT_EQ((int)property_grant_service_plan(g.grant_id, &r, &plan),
                  (int)PROPERTY_GRANT_OK);
        g_cat.present = false;
        struct property_grant_commit_result res;
        ASSERT_EQ((int)property_grant_service_commit(plan.plan_id, "k", &res),
                  (int)PROPERTY_GRANT_PROPERTY_UNKNOWN);
        PASS();
    } _test_next:;
    return failures;
}

static int t_commit_no_catalog(void)
{
    int failures = 0;
    TEST("with no catalog installed COMMIT fails closed, PLAN still diagnoses") {
        struct metaverse_property_id prop = make_id(METAVERSE_KIND_CONTENT, 31);
        fixture_reset(&prop);
        struct property_grant_env env;
        memset(&env, 0, sizeof(env));
        env.clock = fake_clock;           /* no catalog_lookup at all */
        property_grant_service_configure(&env);

        struct metaverse_grant g = grant_over_id(&prop, ACT(HOST), 0);
        ASSERT_EQ((int)property_grant_service_mint(&g), (int)PROPERTY_GRANT_OK);
        struct metaverse_action_request r =
            request_for(&prop, METAVERSE_ACTION_HOST, NULL, 0);
        struct property_grant_plan plan;
        ASSERT_EQ((int)property_grant_service_plan(g.grant_id, &r, &plan),
                  (int)PROPERTY_GRANT_OK);
        ASSERT(!plan.catalog_seen);
        struct property_grant_commit_result res;
        ASSERT_EQ((int)property_grant_service_commit(plan.plan_id, "k", &res),
                  (int)PROPERTY_GRANT_CATALOG_UNAVAILABLE);
        PASS();
    } _test_next:;
    return failures;
}

static int t_commit_plan_expired(void)
{
    int failures = 0;
    TEST("a plan that outlived its TTL is PLAN_EXPIRED") {
        struct metaverse_property_id prop = make_id(METAVERSE_KIND_CONTENT, 31);
        fixture_reset(&prop);
        struct metaverse_grant g = grant_over_id(&prop, ACT(HOST), 0);
        ASSERT_EQ((int)property_grant_service_mint(&g), (int)PROPERTY_GRANT_OK);
        struct metaverse_action_request r =
            request_for(&prop, METAVERSE_ACTION_HOST, NULL, 0);
        struct property_grant_plan plan;
        ASSERT_EQ((int)property_grant_service_plan(g.grant_id, &r, &plan),
                  (int)PROPERTY_GRANT_OK);
        g_now += PROPERTY_GRANT_PLAN_TTL_SECONDS + 1;
        struct property_grant_commit_result res;
        ASSERT_EQ((int)property_grant_service_commit(plan.plan_id, "k", &res),
                  (int)PROPERTY_GRANT_PLAN_EXPIRED);
        PASS();
    } _test_next:;
    return failures;
}

static int t_commit_unknown_plan(void)
{
    int failures = 0;
    TEST("an unknown plan id is PLAN_UNKNOWN") {
        struct metaverse_property_id prop = make_id(METAVERSE_KIND_CONTENT, 31);
        fixture_reset(&prop);
        struct property_grant_commit_result res;
        ASSERT_EQ((int)property_grant_service_commit(
                      "ffffffffffffffffffffffffffffffff", "k", &res),
                  (int)PROPERTY_GRANT_PLAN_UNKNOWN);
        PASS();
    } _test_next:;
    return failures;
}

/* ── 4. Revocation ──────────────────────────────────────────────────────── */

static int t_revoke_kills_grant(void)
{
    int failures = 0;
    TEST("commit succeeds, revoke, then the next attempt is GRANT_REVOKED") {
        struct metaverse_property_id prop = make_id(METAVERSE_KIND_CONTENT, 41);
        fixture_reset(&prop);
        struct metaverse_grant g = grant_over_id(&prop, ACT(HOST), 0);
        ASSERT_EQ((int)property_grant_service_mint(&g), (int)PROPERTY_GRANT_OK);
        struct metaverse_action_request r =
            request_for(&prop, METAVERSE_ACTION_HOST, NULL, 0);

        struct property_grant_plan plan;
        struct property_grant_commit_result res;
        ASSERT_EQ((int)property_grant_service_plan(g.grant_id, &r, &plan),
                  (int)PROPERTY_GRANT_OK);
        ASSERT_EQ((int)property_grant_service_commit(plan.plan_id, "one", &res),
                  (int)PROPERTY_GRANT_OK);
        ASSERT_EQ((int)res.receipt.seq, 1);

        /* A plan taken before the revoke also dies at commit. */
        struct property_grant_plan pre;
        ASSERT_EQ((int)property_grant_service_plan(g.grant_id, &r, &pre),
                  (int)PROPERTY_GRANT_OK);

        ASSERT_EQ((int)property_grant_service_revoke(g.grant_id),
                  (int)PROPERTY_GRANT_OK);

        ASSERT_EQ((int)property_grant_service_commit(pre.plan_id, "two", &res),
                  (int)PROPERTY_GRANT_GRANT_REVOKED);
        ASSERT_EQ((int)property_grant_service_plan(g.grant_id, &r, &plan),
                  (int)PROPERTY_GRANT_GRANT_REVOKED);

        /* Exactly one receipt: the revoked attempts wrote nothing. */
        struct metaverse_receipt rc[4];
        ASSERT_EQ((int)property_grant_service_receipts(g.grant_id, rc, 4), 1);
        PASS();
    } _test_next:;
    return failures;
}

static int t_revoke_kills_subtree(void)
{
    int failures = 0;
    TEST("revoking a parent kills the delegated child at every stage") {
        struct metaverse_property_id prop = make_id(METAVERSE_KIND_CONTENT, 41);
        fixture_reset(&prop);
        struct metaverse_grant parent =
            grant_over_id(&prop, ACT(HOST) | ACT(DELEGATE), 100000);
        parent.delegation_allowed = true;
        parent.max_delegation_depth = 2;
        ASSERT_EQ((int)property_grant_service_mint(&parent),
                  (int)PROPERTY_GRANT_OK);

        struct metaverse_grant child = grant_over_id(&prop, ACT(HOST), 1000);
        ASSERT_EQ((int)property_grant_service_delegate(parent.grant_id, &child),
                  (int)PROPERTY_GRANT_OK);
        ASSERT_EQ((int)child.depth, 1);
        ASSERT_EQ((int)child.lineage_count, 1);

        struct metaverse_action_request r =
            request_for(&prop, METAVERSE_ACTION_HOST, NULL, 0);
        struct property_grant_plan child_plan;
        ASSERT_EQ((int)property_grant_service_plan(child.grant_id, &r,
                                                   &child_plan),
                  (int)PROPERTY_GRANT_OK);

        /* Revoke the PARENT; the child record is never touched. */
        ASSERT_EQ((int)property_grant_service_revoke(parent.grant_id),
                  (int)PROPERTY_GRANT_OK);
        struct metaverse_grant child_now;
        ASSERT_EQ((int)property_grant_service_get(child.grant_id, &child_now),
                  (int)PROPERTY_GRANT_OK);
        ASSERT(!child_now.revoked);

        struct property_grant_commit_result res;
        ASSERT_EQ((int)property_grant_service_commit(child_plan.plan_id, "x",
                                                     &res),
                  (int)PROPERTY_GRANT_ANCESTOR_REVOKED);
        struct property_grant_plan plan;
        ASSERT_EQ((int)property_grant_service_plan(child.grant_id, &r, &plan),
                  (int)PROPERTY_GRANT_ANCESTOR_REVOKED);
        PASS();
    } _test_next:;
    return failures;
}

/* The ancestor check has two independent halves, the ancestor's `revoked` flag
 * and its revocation generation. Through the service they move together, so
 * these cases vary each alone on the pure evaluator with a live control. */
static void ancestor_pair(struct metaverse_grant *parent,
                          struct metaverse_grant *child,
                          const struct metaverse_property_id *prop)
{
    *parent = grant_over_id(prop, ACT(HOST) | ACT(DELEGATE), 100000);
    snprintf(parent->grant_id, sizeof(parent->grant_id),
             "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    parent->delegation_allowed = true;
    parent->max_delegation_depth = 2;

    *child = grant_over_id(prop, ACT(HOST), 1000);
    snprintf(child->grant_id, sizeof(child->grant_id),
             "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
    child->depth = 1;
    child->lineage_count = 1;
    snprintf(child->lineage[0].grant_id, sizeof(child->lineage[0].grant_id),
             "%s", parent->grant_id);
    child->lineage[0].revocation_generation = 0;
}

static int t_ancestor_generation_alone_kills(void)
{
    int failures = 0;
    TEST("a bumped ancestor GENERATION alone kills the child") {
        struct metaverse_property_id prop = make_id(METAVERSE_KIND_CONTENT, 43);
        struct metaverse_grant parent, child;
        ancestor_pair(&parent, &child, &prop);
        struct metaverse_action_request r =
            request_for(&prop, METAVERSE_ACTION_HOST, NULL, 0);
        r.now_unix = 1700000000;
        r.height = 900000;
        const struct metaverse_grant *anc[1] = { &parent };

        /* Control: generations agree and the child is live. */
        ASSERT_EQ((int)metaverse_grant_check(&child, anc, 1, &r),
                  (int)METAVERSE_GRANT_OK);

        /* Only the ancestor's counter moved; the flag is clear. */
        parent.revocation_generation = 1;
        ASSERT(!parent.revoked);
        ASSERT_EQ((int)metaverse_grant_check(&child, anc, 1, &r),
                  (int)METAVERSE_GRANT_ANCESTOR_REVOKED);
        PASS();
    } _test_next:;
    return failures;
}

static int t_ancestor_revoked_flag_alone_kills(void)
{
    int failures = 0;
    TEST("an ancestor's revoked FLAG alone kills the child") {
        struct metaverse_property_id prop = make_id(METAVERSE_KIND_CONTENT, 43);
        struct metaverse_grant parent, child;
        ancestor_pair(&parent, &child, &prop);
        struct metaverse_action_request r =
            request_for(&prop, METAVERSE_ACTION_HOST, NULL, 0);
        r.now_unix = 1700000000;
        r.height = 900000;
        const struct metaverse_grant *anc[1] = { &parent };

        ASSERT_EQ((int)metaverse_grant_check(&child, anc, 1, &r),
                  (int)METAVERSE_GRANT_OK);

        /* The flag is set and the generation matches; only the flag can refuse. */
        parent.revoked = true;
        ASSERT_EQ((int)parent.revocation_generation,
                  (int)child.lineage[0].revocation_generation);
        ASSERT_EQ((int)metaverse_grant_check(&child, anc, 1, &r),
                  (int)METAVERSE_GRANT_ANCESTOR_REVOKED);
        PASS();
    } _test_next:;
    return failures;
}

/* ── 5. Idempotency ─────────────────────────────────────────────────────── */

static int t_idempotent_commit(void)
{
    int failures = 0;
    TEST("the same idempotency key returns the SAME receipt and charges once") {
        struct metaverse_property_id prop = make_id(METAVERSE_KIND_CONTENT, 51);
        fixture_reset(&prop);
        struct metaverse_grant g = grant_over_id(&prop, ACT(BUY), 100000);
        ASSERT_EQ((int)property_grant_service_mint(&g), (int)PROPERTY_GRANT_OK);

        struct metaverse_action_request r =
            request_for(&prop, METAVERSE_ACTION_BUY, NULL, 25000);
        struct property_grant_plan plan;
        ASSERT_EQ((int)property_grant_service_plan(g.grant_id, &r, &plan),
                  (int)PROPERTY_GRANT_OK);

        struct property_grant_commit_result first;
        ASSERT_EQ((int)property_grant_service_commit(plan.plan_id, "order-7",
                                                     &first),
                  (int)PROPERTY_GRANT_OK);
        ASSERT(!first.replayed);
        ASSERT_EQ((int)first.receipt.seq, 1);
        ASSERT_EQ((int)first.budget_remaining_zat, 75000);

        struct property_grant_commit_result second;
        ASSERT_EQ((int)property_grant_service_commit(plan.plan_id, "order-7",
                                                     &second),
                  (int)PROPERTY_GRANT_OK);
        ASSERT(second.replayed);
        ASSERT_EQ((int)second.receipt.seq, (int)first.receipt.seq);
        ASSERT(memcmp(second.receipt.chain_hash, first.receipt.chain_hash,
                      METAVERSE_HASH_LEN) == 0);
        /* No double charge and no second chain link. */
        ASSERT_EQ((int)second.budget_remaining_zat, 75000);
        struct metaverse_grant after;
        ASSERT_EQ((int)property_grant_service_get(g.grant_id, &after),
                  (int)PROPERTY_GRANT_OK);
        ASSERT_EQ((int)after.spent_zat, 25000);
        struct metaverse_receipt rc[8];
        ASSERT_EQ((int)property_grant_service_receipts(g.grant_id, rc, 8), 1);
        PASS();
    } _test_next:;
    return failures;
}

static int t_unkeyed_commit_not_replayable(void)
{
    int failures = 0;
    TEST("an un-keyed commit is not replay-protected and says so") {
        struct metaverse_property_id prop = make_id(METAVERSE_KIND_CONTENT, 51);
        fixture_reset(&prop);
        struct metaverse_grant g = grant_over_id(&prop, ACT(HOST), 0);
        ASSERT_EQ((int)property_grant_service_mint(&g), (int)PROPERTY_GRANT_OK);
        struct metaverse_action_request r =
            request_for(&prop, METAVERSE_ACTION_HOST, NULL, 0);
        struct property_grant_plan plan;
        ASSERT_EQ((int)property_grant_service_plan(g.grant_id, &r, &plan),
                  (int)PROPERTY_GRANT_OK);
        struct property_grant_commit_result res;
        ASSERT_EQ((int)property_grant_service_commit(plan.plan_id, "", &res),
                  (int)PROPERTY_GRANT_OK);
        ASSERT_EQ((int)property_grant_service_commit(plan.plan_id, "", &res),
                  (int)PROPERTY_GRANT_PLAN_ALREADY_COMMITTED);
        PASS();
    } _test_next:;
    return failures;
}

static int t_distinct_key_is_not_replay(void)
{
    int failures = 0;
    TEST("a different key on a committed plan is not a replay") {
        struct metaverse_property_id prop = make_id(METAVERSE_KIND_CONTENT, 51);
        fixture_reset(&prop);
        struct metaverse_grant g = grant_over_id(&prop, ACT(BUY), 100000);
        ASSERT_EQ((int)property_grant_service_mint(&g), (int)PROPERTY_GRANT_OK);
        struct metaverse_action_request r =
            request_for(&prop, METAVERSE_ACTION_BUY, NULL, 1000);
        struct property_grant_plan plan;
        ASSERT_EQ((int)property_grant_service_plan(g.grant_id, &r, &plan),
                  (int)PROPERTY_GRANT_OK);
        struct property_grant_commit_result res;
        ASSERT_EQ((int)property_grant_service_commit(plan.plan_id, "a", &res),
                  (int)PROPERTY_GRANT_OK);
        ASSERT_EQ((int)property_grant_service_commit(plan.plan_id, "b", &res),
                  (int)PROPERTY_GRANT_PLAN_ALREADY_COMMITTED);
        PASS();
    } _test_next:;
    return failures;
}

/* A replay must match the request, not just the key: a reused key with a
 * different action, property, value or counterparty is refused by name. */
static int t_replay_must_match_the_request(void)
{
    int failures = 0;
    TEST("a reused key with a different request is refused, not replayed") {
        struct metaverse_property_id prop = make_id(METAVERSE_KIND_CONTENT, 52);
        struct metaverse_property_id other =
            make_id(METAVERSE_KIND_CONTENT, 53);
        fixture_reset(&prop);
        struct metaverse_grant g;
        memset(&g, 0, sizeof(g));
        snprintf(g.holder, sizeof(g.holder), "%s", k_holder);
        snprintf(g.issuer, sizeof(g.issuer), "%s", k_holder);
        g.scope_form = METAVERSE_SCOPE_IDS;
        g.ids[0] = prop;
        g.ids[1] = other;
        g.id_count = 2;
        g.actions = ACT(BUY) | ACT(HOST);
        g.max_value_zat = 100000;
        ASSERT_EQ((int)property_grant_service_mint(&g), (int)PROPERTY_GRANT_OK);

        struct metaverse_action_request r =
            request_for(&prop, METAVERSE_ACTION_BUY, NULL, 25000);
        struct property_grant_plan plan;
        ASSERT_EQ((int)property_grant_service_plan(g.grant_id, &r, &plan),
                  (int)PROPERTY_GRANT_OK);
        struct property_grant_commit_result first;
        ASSERT_EQ((int)property_grant_service_commit(plan.plan_id, "order-7",
                                                     &first),
                  (int)PROPERTY_GRANT_OK);
        ASSERT_EQ((int)first.receipt.seq, 1);

        /* Four requests each differing in one field; planned fine, refused at COMMIT. */
        struct metaverse_action_request diff[4] = {
            request_for(&prop, METAVERSE_ACTION_BUY, NULL, 30000),
            request_for(&prop, METAVERSE_ACTION_HOST, NULL, 0),
            request_for(&prop, METAVERSE_ACTION_BUY, k_buyer, 25000),
            request_for(&other, METAVERSE_ACTION_BUY, NULL, 25000),
        };
        for (size_t i = 0; i < 4; i++) {
            /* The catalog answers for whichever property this case names. */
            g_cat.id = diff[i].property;
            struct property_grant_plan p2;
            ASSERT_EQ((int)property_grant_service_plan(g.grant_id, &diff[i],
                                                       &p2),
                      (int)PROPERTY_GRANT_OK);
            struct property_grant_commit_result res;
            ASSERT_EQ((int)property_grant_service_commit(p2.plan_id, "order-7",
                                                         &res),
                      (int)PROPERTY_GRANT_IDEMPOTENCY_KEY_REUSED);
            /* Refused, so it is not a replay and carries no receipt. */
            ASSERT(!res.replayed);
            ASSERT_EQ((int)res.receipt.seq, 0);
        }
        g_cat.id = prop;

        /* The stored receipt is unchanged and nothing was charged. */
        struct metaverse_receipt rc[8];
        ASSERT_EQ((int)property_grant_service_receipts(g.grant_id, rc, 8), 1);
        ASSERT_EQ((int)rc[0].seq, 1);
        ASSERT_EQ((int)rc[0].value_zat, 25000);
        ASSERT_EQ((int)rc[0].action, (int)METAVERSE_ACTION_BUY);
        ASSERT(memcmp(rc[0].chain_hash, first.receipt.chain_hash,
                      METAVERSE_HASH_LEN) == 0);
        struct metaverse_grant after;
        ASSERT_EQ((int)property_grant_service_get(g.grant_id, &after),
                  (int)PROPERTY_GRANT_OK);
        ASSERT_EQ((int)after.spent_zat, 25000);

        /* And the genuine retry — same key, same request — still replays. */
        struct property_grant_commit_result again;
        ASSERT_EQ((int)property_grant_service_commit(plan.plan_id, "order-7",
                                                     &again),
                  (int)PROPERTY_GRANT_OK);
        ASSERT(again.replayed);
        ASSERT_EQ((int)again.receipt.seq, 1);

        ASSERT_STR_EQ(
            property_grant_reason_token(PROPERTY_GRANT_IDEMPOTENCY_KEY_REUSED),
            "IDEMPOTENCY_KEY_REUSED");
        PASS();
    } _test_next:;
    return failures;
}

/* ── 6. Tamper evidence ─────────────────────────────────────────────────── */

static int t_tamper_edit_detected(void)
{
    int failures = 0;
    TEST("editing a stored receipt breaks the chain and is located") {
        struct metaverse_property_id prop = make_id(METAVERSE_KIND_CONTENT, 61);
        fixture_reset(&prop);
        struct metaverse_grant g = grant_over_id(&prop, ACT(BUY), 100000);
        ASSERT_EQ((int)property_grant_service_mint(&g), (int)PROPERTY_GRANT_OK);
        ASSERT_EQ(commit_n(&g, &prop, 3), 0);

        uint64_t bad = 0;
        ASSERT_EQ((int)property_grant_service_verify_chain(g.grant_id, &bad),
                  (int)METAVERSE_RECEIPT_OK);

        struct metaverse_receipt rc[8];
        ASSERT_EQ((int)property_grant_service_receipts(g.grant_id, rc, 8), 3);

        /* An auditor's-eye edit: change the amount and put it back. */
        struct metaverse_receipt edited = rc[1];
        edited.value_zat = 999999;
        ASSERT(property_grant_service_test_overwrite_receipt(g.grant_id, 2,
                                                             &edited));
        ASSERT_EQ((int)property_grant_service_verify_chain(g.grant_id, &bad),
                  (int)METAVERSE_RECEIPT_BODY_HASH_MISMATCH);
        ASSERT_EQ((int)bad, 2);
        PASS();
    } _test_next:;
    return failures;
}

static int t_tamper_foreign_signature(void)
{
    int failures = 0;
    TEST("re-signing a rewritten receipt with a foreign key is still caught") {
        struct metaverse_property_id prop = make_id(METAVERSE_KIND_CONTENT, 61);
        fixture_reset(&prop);
        struct metaverse_grant g = grant_over_id(&prop, ACT(BUY), 100000);
        ASSERT_EQ((int)property_grant_service_mint(&g), (int)PROPERTY_GRANT_OK);
        ASSERT_EQ(commit_n(&g, &prop, 2), 0);

        struct metaverse_receipt rc[8];
        ASSERT_EQ((int)property_grant_service_receipts(g.grant_id, rc, 8), 2);

        /* Forger rewrites the amount and re-seals with their own key; only pinning the signer catches it. */
        uint8_t fseed[32], fpk[32], fsk[32];
        memset(fseed, 0x11, sizeof(fseed));
        ed25519_keypair(fpk, fsk, fseed);
        struct metaverse_receipt forged = rc[1];
        forged.value_zat = 42;
        ASSERT(metaverse_receipt_seal(&forged, rc[0].chain_hash, fsk, fpk));
        ASSERT(property_grant_service_test_overwrite_receipt(g.grant_id, 2,
                                                             &forged));

        uint64_t bad = 0;
        ASSERT_EQ((int)property_grant_service_verify_chain(g.grant_id, &bad),
                  (int)METAVERSE_RECEIPT_SIGNER_UNEXPECTED);
        ASSERT_EQ((int)bad, 2);
        PASS();
    } _test_next:;
    return failures;
}

static int t_tamper_cut_link(void)
{
    int failures = 0;
    TEST("cutting a link out of the chain is reported as CHAIN_BROKEN") {
        struct metaverse_property_id prop = make_id(METAVERSE_KIND_CONTENT, 61);
        fixture_reset(&prop);
        struct metaverse_grant g = grant_over_id(&prop, ACT(BUY), 100000);
        ASSERT_EQ((int)property_grant_service_mint(&g), (int)PROPERTY_GRANT_OK);
        ASSERT_EQ(commit_n(&g, &prop, 3), 0);

        struct metaverse_receipt rc[8];
        ASSERT_EQ((int)property_grant_service_receipts(g.grant_id, rc, 8), 3);

        /* Receipt 3 re-pointed at the first and sealed correctly; only the link is wrong. */
        uint8_t signer[METAVERSE_PUBKEY_LEN];
        ASSERT(property_grant_service_signer_pubkey(signer));
        uint8_t seed[32], pk[32], sk[32];
        memset(seed, 0xA5, sizeof(seed));
        ed25519_keypair(pk, sk, seed);
        ASSERT(memcmp(pk, signer, METAVERSE_PUBKEY_LEN) == 0);

        struct metaverse_receipt relinked = rc[2];
        ASSERT(metaverse_receipt_seal(&relinked, rc[0].chain_hash, sk, pk));
        ASSERT_EQ((int)metaverse_receipt_verify(&relinked, signer),
                  (int)METAVERSE_RECEIPT_OK);
        ASSERT(property_grant_service_test_overwrite_receipt(g.grant_id, 3,
                                                             &relinked));

        uint64_t bad = 0;
        ASSERT_EQ((int)property_grant_service_verify_chain(g.grant_id, &bad),
                  (int)METAVERSE_RECEIPT_CHAIN_BROKEN);
        ASSERT_EQ((int)bad, 3);
        PASS();
    } _test_next:;
    return failures;
}

static int t_chain_verifier_agrees(void)
{
    int failures = 0;
    TEST("the standalone chain verifier agrees, and catches a reorder") {
        struct metaverse_property_id prop = make_id(METAVERSE_KIND_CONTENT, 61);
        fixture_reset(&prop);
        struct metaverse_grant g = grant_over_id(&prop, ACT(BUY), 100000);
        ASSERT_EQ((int)property_grant_service_mint(&g), (int)PROPERTY_GRANT_OK);
        ASSERT_EQ(commit_n(&g, &prop, 2), 0);

        struct metaverse_receipt rc[8];
        size_t n = property_grant_service_receipts(g.grant_id, rc, 8);
        ASSERT_EQ((int)n, 2);
        uint8_t signer[METAVERSE_PUBKEY_LEN];
        ASSERT(property_grant_service_signer_pubkey(signer));
        size_t bad_index = 99;
        ASSERT_EQ((int)metaverse_receipt_chain_verify(rc, n, signer,
                                                      &bad_index),
                  (int)METAVERSE_RECEIPT_OK);

        /* Reordering alone is caught, without touching a single byte. */
        struct metaverse_receipt swapped[2] = { rc[1], rc[0] };
        ASSERT_EQ((int)metaverse_receipt_chain_verify(swapped, 2, signer,
                                                      &bad_index),
                  (int)METAVERSE_RECEIPT_SEQ_OUT_OF_ORDER);
        ASSERT_EQ((int)bad_index, 0);
        PASS();
    } _test_next:;
    return failures;
}

/* ── 7. Delegation attenuation ──────────────────────────────────────────── */

static int t_delegation_depth(void)
{
    int failures = 0;
    TEST("delegation beyond the declared max depth is refused") {
        struct metaverse_property_id prop = make_id(METAVERSE_KIND_CONTENT, 71);
        fixture_reset(&prop);
        struct metaverse_grant parent =
            grant_over_id(&prop, ACT(HOST) | ACT(DELEGATE), 100000);
        parent.delegation_allowed = true;
        parent.max_delegation_depth = 1;  /* children yes, grandchildren no */
        ASSERT_EQ((int)property_grant_service_mint(&parent),
                  (int)PROPERTY_GRANT_OK);

        struct metaverse_grant child =
            grant_over_id(&prop, ACT(HOST) | ACT(DELEGATE), 1000);
        child.delegation_allowed = true;
        child.max_delegation_depth = 1;
        ASSERT_EQ((int)property_grant_service_delegate(parent.grant_id, &child),
                  (int)PROPERTY_GRANT_OK);

        struct metaverse_grant grandchild = grant_over_id(&prop, ACT(HOST), 100);
        ASSERT_EQ((int)property_grant_service_delegate(child.grant_id,
                                                       &grandchild),
                  (int)PROPERTY_GRANT_DELEGATION_DEPTH_EXCEEDED);
        PASS();
    } _test_next:;
    return failures;
}

static int t_delegation_requires_right(void)
{
    int failures = 0;
    TEST("a grant without the DELEGATE action cannot mint a child") {
        struct metaverse_property_id prop = make_id(METAVERSE_KIND_CONTENT, 71);
        fixture_reset(&prop);
        struct metaverse_grant parent = grant_over_id(&prop, ACT(HOST), 100000);
        parent.delegation_allowed = true;  /* the flag alone is not enough */
        parent.max_delegation_depth = 2;
        ASSERT_EQ((int)property_grant_service_mint(&parent),
                  (int)PROPERTY_GRANT_OK);
        struct metaverse_grant child = grant_over_id(&prop, ACT(HOST), 10);
        ASSERT_EQ((int)property_grant_service_delegate(parent.grant_id, &child),
                  (int)PROPERTY_GRANT_DELEGATION_NOT_PERMITTED);
        PASS();
    } _test_next:;
    return failures;
}

static int t_delegation_attenuates(void)
{
    int failures = 0;
    TEST("a child may not hold an action, budget, or scope the parent lacks") {
        struct metaverse_property_id prop = make_id(METAVERSE_KIND_CONTENT, 71);
        fixture_reset(&prop);
        struct metaverse_grant parent =
            grant_over_id(&prop, ACT(HOST) | ACT(DELEGATE), 5000);
        parent.delegation_allowed = true;
        parent.max_delegation_depth = 2;
        ASSERT_EQ((int)property_grant_service_mint(&parent),
                  (int)PROPERTY_GRANT_OK);

        struct metaverse_grant wider_action =
            grant_over_id(&prop, ACT(HOST) | ACT(TRANSFER), 10);
        ASSERT_EQ((int)property_grant_service_delegate(parent.grant_id,
                                                       &wider_action),
                  (int)PROPERTY_GRANT_ACTION_NOT_GRANTED);

        struct metaverse_grant richer = grant_over_id(&prop, ACT(HOST), 5001);
        ASSERT_EQ((int)property_grant_service_delegate(parent.grant_id,
                                                       &richer),
                  (int)PROPERTY_GRANT_BUDGET_EXCEEDED);

        struct metaverse_property_id other = make_id(METAVERSE_KIND_CONTENT, 72);
        struct metaverse_grant elsewhere = grant_over_id(&other, ACT(HOST), 10);
        ASSERT_EQ((int)property_grant_service_delegate(parent.grant_id,
                                                       &elsewhere),
                  (int)PROPERTY_GRANT_PROPERTY_OUT_OF_SCOPE);

        /* A kind-wildcard child under an id-scoped parent is a WIDENING. */
        struct metaverse_grant kindwide;
        memset(&kindwide, 0, sizeof(kindwide));
        snprintf(kindwide.holder, sizeof(kindwide.holder), "%s", k_holder);
        kindwide.scope_form = METAVERSE_SCOPE_KINDS;
        kindwide.kinds = metaverse_kind_bit(METAVERSE_KIND_CONTENT);
        kindwide.actions = ACT(HOST);
        ASSERT_EQ((int)property_grant_service_delegate(parent.grant_id,
                                                       &kindwide),
                  (int)PROPERTY_GRANT_KIND_OUT_OF_SCOPE);
        PASS();
    } _test_next:;
    return failures;
}

/* An empty child counterparty list would be the widest grant. */
static int t_delegation_attenuates_counterparties(void)
{
    int failures = 0;
    TEST("a child may not drop or widen its parent's counterparty list") {
        struct metaverse_property_id prop = make_id(METAVERSE_KIND_CONTENT, 73);
        fixture_reset(&prop);
        struct metaverse_grant parent =
            grant_over_id(&prop, ACT(HOST) | ACT(DELEGATE), 5000);
        parent.delegation_allowed = true;
        parent.max_delegation_depth = 2;
        parent.counterparty_count = 1;
        snprintf(parent.counterparties[0], sizeof(parent.counterparties[0]),
                 "%s", "alice");
        ASSERT_EQ((int)property_grant_service_mint(&parent),
                  (int)PROPERTY_GRANT_OK);

        /* An empty list means ANY counterparty: the widest child. */
        struct metaverse_grant anyone = grant_over_id(&prop, ACT(HOST), 10);
        ASSERT_EQ((int)property_grant_service_delegate(parent.grant_id,
                                                       &anyone),
                  (int)PROPERTY_GRANT_COUNTERPARTY_NOT_ALLOWED);

        struct metaverse_grant other = grant_over_id(&prop, ACT(HOST), 10);
        other.counterparty_count = 2;
        snprintf(other.counterparties[0], sizeof(other.counterparties[0]),
                 "%s", "alice");
        snprintf(other.counterparties[1], sizeof(other.counterparties[1]),
                 "%s", "mallory");
        ASSERT_EQ((int)property_grant_service_delegate(parent.grant_id,
                                                       &other),
                  (int)PROPERTY_GRANT_COUNTERPARTY_NOT_ALLOWED);

        /* The same list, or a narrower one, still delegates. */
        struct metaverse_grant same = grant_over_id(&prop, ACT(HOST), 10);
        same.counterparty_count = 1;
        snprintf(same.counterparties[0], sizeof(same.counterparties[0]),
                 "%s", "alice");
        ASSERT_EQ((int)property_grant_service_delegate(parent.grant_id,
                                                       &same),
                  (int)PROPERTY_GRANT_OK);
        PASS();
    } _test_next:;
    return failures;
}

/* ── 8. Budget and rate window ──────────────────────────────────────────── */

static int t_budget_is_cumulative(void)
{
    int failures = 0;
    TEST("the budget is CUMULATIVE: repeated under-cap actions exhaust it") {
        struct metaverse_property_id prop = make_id(METAVERSE_KIND_CONTENT, 81);
        fixture_reset(&prop);
        struct metaverse_grant g = grant_over_id(&prop, ACT(BUY), 2500);
        ASSERT_EQ((int)property_grant_service_mint(&g), (int)PROPERTY_GRANT_OK);
        ASSERT_EQ(commit_n(&g, &prop, 2), 0);   /* 1000 + 1000 spent */

        struct metaverse_grant after;
        ASSERT_EQ((int)property_grant_service_get(g.grant_id, &after),
                  (int)PROPERTY_GRANT_OK);
        ASSERT_EQ((int)after.spent_zat, 2000);
        ASSERT_EQ((int)metaverse_grant_budget_remaining(&after), 500);

        /* A third 1000 is under no per-action cap but over the ceiling. */
        struct metaverse_action_request r =
            request_for(&prop, METAVERSE_ACTION_BUY, NULL, 1000);
        struct property_grant_plan plan;
        ASSERT_EQ((int)property_grant_service_plan(g.grant_id, &r, &plan),
                  (int)PROPERTY_GRANT_BUDGET_EXCEEDED);
        PASS();
    } _test_next:;
    return failures;
}

/* ── 8b. The cumulative ceiling bounds the whole delegation subtree ──────
 * A commit charges its grant and every ancestor and is refused unless all can pay. */

static int t_parent_budget_bounds_its_children(void)
{
    int failures = 0;
    TEST("a parent's cumulative ceiling bounds what its children may move") {
        struct metaverse_property_id prop = make_id(METAVERSE_KIND_CONTENT, 82);
        fixture_reset(&prop);
        struct metaverse_grant parent =
            grant_over_id(&prop, ACT(BUY) | ACT(DELEGATE), 5000);
        parent.delegation_allowed = true;
        parent.max_delegation_depth = 2;
        ASSERT_EQ((int)property_grant_service_mint(&parent),
                  (int)PROPERTY_GRANT_OK);

        /* Two siblings each minted with the parent's full remaining budget; each is a legal attenuation alone. */
        struct metaverse_grant a = grant_over_id(&prop, ACT(BUY), 5000);
        struct metaverse_grant b = grant_over_id(&prop, ACT(BUY), 5000);
        ASSERT_EQ((int)property_grant_service_delegate(parent.grant_id, &a),
                  (int)PROPERTY_GRANT_OK);
        ASSERT_EQ((int)property_grant_service_delegate(parent.grant_id, &b),
                  (int)PROPERTY_GRANT_OK);

        /* Both quotes are taken before either commits, so the refusal comes from the commit's lineage charge. */
        struct metaverse_action_request r =
            request_for(&prop, METAVERSE_ACTION_BUY, NULL, 5000);
        struct property_grant_plan pa, pb;
        ASSERT_EQ((int)property_grant_service_plan(a.grant_id, &r, &pa),
                  (int)PROPERTY_GRANT_OK);
        ASSERT_EQ((int)property_grant_service_plan(b.grant_id, &r, &pb),
                  (int)PROPERTY_GRANT_OK);

        struct property_grant_commit_result ra, rb;
        ASSERT_EQ((int)property_grant_service_commit(pa.plan_id, "sib-a", &ra),
                  (int)PROPERTY_GRANT_OK);
        ASSERT_EQ((int)property_grant_service_commit(pb.plan_id, "sib-b", &rb),
                  (int)PROPERTY_GRANT_BUDGET_EXCEEDED);

        /* 5000 authorized, 5000 at risk. */
        struct metaverse_grant pnow, anow, bnow;
        ASSERT_EQ((int)property_grant_service_get(parent.grant_id, &pnow),
                  (int)PROPERTY_GRANT_OK);
        ASSERT_EQ((int)property_grant_service_get(a.grant_id, &anow),
                  (int)PROPERTY_GRANT_OK);
        ASSERT_EQ((int)property_grant_service_get(b.grant_id, &bnow),
                  (int)PROPERTY_GRANT_OK);
        ASSERT_EQ((int)pnow.spent_zat, 5000);
        ASSERT_EQ((int)anow.spent_zat, 5000);
        ASSERT_EQ((int)bnow.spent_zat, 0);
        ASSERT_EQ((int)metaverse_grant_budget_remaining(&pnow), 0);

        /* The refused sibling wrote no evidence. */
        struct metaverse_receipt rc[4];
        ASSERT_EQ((int)property_grant_service_receipts(b.grant_id, rc, 4), 0);
        PASS();
    } _test_next:;
    return failures;
}

static int t_lineage_charge_reaches_a_grandparent(void)
{
    int failures = 0;
    TEST("a grandchild's spend is charged to every ancestor, all or none") {
        struct metaverse_property_id prop = make_id(METAVERSE_KIND_CONTENT, 83);
        fixture_reset(&prop);

        struct metaverse_grant root =
            grant_over_id(&prop, ACT(BUY) | ACT(DELEGATE), 10000);
        root.delegation_allowed = true;
        root.max_delegation_depth = 3;
        ASSERT_EQ((int)property_grant_service_mint(&root),
                  (int)PROPERTY_GRANT_OK);

        struct metaverse_grant mid =
            grant_over_id(&prop, ACT(BUY) | ACT(DELEGATE), 9000);
        mid.delegation_allowed = true;
        mid.max_delegation_depth = 3;
        ASSERT_EQ((int)property_grant_service_delegate(root.grant_id, &mid),
                  (int)PROPERTY_GRANT_OK);

        struct metaverse_grant leaf = grant_over_id(&prop, ACT(BUY), 9000);
        ASSERT_EQ((int)property_grant_service_delegate(mid.grant_id, &leaf),
                  (int)PROPERTY_GRANT_OK);
        ASSERT_EQ((int)leaf.depth, 2);
        ASSERT_EQ((int)leaf.lineage_count, 2);

        /* The middle grant spends most of its budget; the leaf's record is unchanged. */
        struct metaverse_action_request big =
            request_for(&prop, METAVERSE_ACTION_BUY, NULL, 8000);
        struct property_grant_plan pm;
        ASSERT_EQ((int)property_grant_service_plan(mid.grant_id, &big, &pm),
                  (int)PROPERTY_GRANT_OK);
        struct property_grant_commit_result rm;
        ASSERT_EQ((int)property_grant_service_commit(pm.plan_id, "mid-1", &rm),
                  (int)PROPERTY_GRANT_OK);

        struct metaverse_grant now;
        ASSERT_EQ((int)property_grant_service_get(root.grant_id, &now),
                  (int)PROPERTY_GRANT_OK);
        ASSERT_EQ((int)now.spent_zat, 8000);   /* the root paid for it too */

        /* A leaf spend two levels down lands on BOTH ancestors. */
        struct metaverse_action_request small =
            request_for(&prop, METAVERSE_ACTION_BUY, NULL, 800);
        struct property_grant_plan pl;
        ASSERT_EQ((int)property_grant_service_plan(leaf.grant_id, &small, &pl),
                  (int)PROPERTY_GRANT_OK);
        struct property_grant_commit_result rl;
        ASSERT_EQ((int)property_grant_service_commit(pl.plan_id, "leaf-1", &rl),
                  (int)PROPERTY_GRANT_OK);
        ASSERT_EQ((int)property_grant_service_get(root.grant_id, &now),
                  (int)PROPERTY_GRANT_OK);
        ASSERT_EQ((int)now.spent_zat, 8800);
        ASSERT_EQ((int)property_grant_service_get(mid.grant_id, &now),
                  (int)PROPERTY_GRANT_OK);
        ASSERT_EQ((int)now.spent_zat, 8800);
        ASSERT_EQ((int)property_grant_service_get(leaf.grant_id, &now),
                  (int)PROPERTY_GRANT_OK);
        ASSERT_EQ((int)now.spent_zat, 800);

        /* Atomicity: the root is charged first, so a partial charge would leave it debited. */
        struct metaverse_action_request over =
            request_for(&prop, METAVERSE_ACTION_BUY, NULL, 1000);
        struct property_grant_plan po;
        ASSERT_EQ((int)property_grant_service_plan(leaf.grant_id, &over, &po),
                  (int)PROPERTY_GRANT_OK);
        struct property_grant_commit_result ro;
        ASSERT_EQ((int)property_grant_service_commit(po.plan_id, "leaf-2", &ro),
                  (int)PROPERTY_GRANT_BUDGET_EXCEEDED);

        ASSERT_EQ((int)property_grant_service_get(root.grant_id, &now),
                  (int)PROPERTY_GRANT_OK);
        ASSERT_EQ((int)now.spent_zat, 8800);   /* not left holding the charge */
        ASSERT_EQ((int)property_grant_service_get(mid.grant_id, &now),
                  (int)PROPERTY_GRANT_OK);
        ASSERT_EQ((int)now.spent_zat, 8800);
        ASSERT_EQ((int)property_grant_service_get(leaf.grant_id, &now),
                  (int)PROPERTY_GRANT_OK);
        ASSERT_EQ((int)now.spent_zat, 800);
        struct metaverse_receipt rc[8];
        ASSERT_EQ((int)property_grant_service_receipts(leaf.grant_id, rc, 8), 1);
        PASS();
    } _test_next:;
    return failures;
}

static int t_rate_window(void)
{
    int failures = 0;
    TEST("the rate window bounds action COUNT and rolls over") {
        struct metaverse_property_id prop = make_id(METAVERSE_KIND_CONTENT, 81);
        fixture_reset(&prop);
        struct metaverse_grant g = grant_over_id(&prop, ACT(BUY), 1000000);
        g.rate_limit = 2;
        g.rate_window_seconds = 60;
        ASSERT_EQ((int)property_grant_service_mint(&g), (int)PROPERTY_GRANT_OK);

        ASSERT_EQ(commit_n(&g, &prop, 2), 0);
        struct metaverse_action_request r =
            request_for(&prop, METAVERSE_ACTION_BUY, NULL, 1000);
        struct property_grant_plan plan;
        ASSERT_EQ((int)property_grant_service_plan(g.grant_id, &r, &plan),
                  (int)PROPERTY_GRANT_RATE_LIMITED);

        g_now += 61;
        ASSERT_EQ((int)property_grant_service_plan(g.grant_id, &r, &plan),
                  (int)PROPERTY_GRANT_OK);
        struct property_grant_commit_result res;
        ASSERT_EQ((int)property_grant_service_commit(plan.plan_id, "after",
                                                     &res),
                  (int)PROPERTY_GRANT_OK);
        PASS();
    } _test_next:;
    return failures;
}

/* ── 9. THE FAILED-COMMIT INVERSE ────────────────────────────────────────
 * A commit that produces no receipt must restore the grant record exactly.
 * The ZCL_TESTING-only seal hook makes the failure path reachable. */

struct seal_probe {
    int calls;
    int fail_next;        /* fail the seal on this many further calls */
    int lock_held_calls;  /* how often the store mutex was held while it ran */
};

static bool seal_probe_hook(void *ctx)
{
    struct seal_probe *p = ctx;
    p->calls++;
    /* The mutate-and-restore window straddles this call; releasing the store mutex
     * inside it makes the trylock succeed and the count stay zero. */
    if (property_grant_service_test_store_lock_busy()) p->lock_held_calls++;
    if (p->fail_next > 0) {
        p->fail_next--;
        return false;
    }
    return true;
}

/* The whole stored record, zeroed first so unchanged reads compare byte-equal. */
static bool grant_record(const char *grant_id, struct metaverse_grant *out)
{
    memset(out, 0, sizeof(*out));
    return property_grant_service_get(grant_id, out) == PROPERTY_GRANT_OK;
}

/* P1 */
static int t_quoted_value_is_never_charged(void)
{
    int failures = 0;
    TEST("a quoted asking price cannot move spent_zat on ANY path") {
        struct metaverse_property_id prop = make_id(METAVERSE_KIND_CONTENT, 91);
        fixture_reset(&prop);
        struct metaverse_grant g =
            grant_over_id(&prop, ACT(LIST_FOR_SALE), 2500);
        ASSERT_EQ((int)property_grant_service_mint(&g), (int)PROPERTY_GRANT_OK);

        /* LIST_FOR_SALE names 5000, above the ceiling, and is allowed: it moves nothing. */
        struct metaverse_action_request r =
            request_for(&prop, METAVERSE_ACTION_LIST_FOR_SALE, NULL, 5000);
        struct property_grant_plan plan;
        ASSERT_EQ((int)property_grant_service_plan(g.grant_id, &r, &plan),
                  (int)PROPERTY_GRANT_OK);
        struct property_grant_commit_result res;
        ASSERT_EQ((int)property_grant_service_commit(plan.plan_id, "quote-ok",
                                                     &res),
                  (int)PROPERTY_GRANT_OK);
        struct metaverse_grant after;
        ASSERT(grant_record(g.grant_id, &after));
        ASSERT_EQ((int)after.spent_zat, 0);

        /* Same quote, sealed unsuccessfully: crediting it would drive spent_zat negative. */
        struct seal_probe probe;
        memset(&probe, 0, sizeof(probe));
        probe.fail_next = 1;
        ASSERT(property_grant_service_test_set_seal_hook(seal_probe_hook,
                                                         &probe));
        struct property_grant_plan plan2;
        ASSERT_EQ((int)property_grant_service_plan(g.grant_id, &r, &plan2),
                  (int)PROPERTY_GRANT_OK);
        struct property_grant_commit_result res2;
        ASSERT_EQ((int)property_grant_service_commit(plan2.plan_id, "quote-bad",
                                                     &res2),
                  (int)PROPERTY_GRANT_RECEIPT_SEAL_FAILED);
        ASSERT_EQ(probe.calls, 1);
        ASSERT(property_grant_service_test_set_seal_hook(NULL, NULL));

        struct metaverse_grant after2;
        ASSERT(grant_record(g.grant_id, &after2));
        ASSERT_EQ((int)after2.spent_zat, 0);
        ASSERT_EQ((int)metaverse_grant_budget_remaining(&after2), 2500);
        /* And the grant is still usable. */
        ASSERT(metaverse_grant_well_formed(&after2));
        ASSERT_EQ((int)property_grant_service_plan(g.grant_id, &r, &plan2),
                  (int)PROPERTY_GRANT_OK);
        PASS();
    } _test_next:;
    return failures;
}

/* P2 */
static int t_failed_commit_restores_the_rate_window(void)
{
    int failures = 0;
    TEST("a failed commit restores the whole rate window, start included") {
        struct metaverse_property_id prop = make_id(METAVERSE_KIND_CONTENT, 92);
        fixture_reset(&prop);
        struct metaverse_grant g = grant_over_id(&prop, ACT(BUY), 1000000);
        g.rate_limit = 2;
        g.rate_window_seconds = 60;
        ASSERT_EQ((int)property_grant_service_mint(&g), (int)PROPERTY_GRANT_OK);
        ASSERT_EQ(commit_n(&g, &prop, 2), 0);      /* the window is now FULL */

        struct metaverse_grant before;
        ASSERT(grant_record(g.grant_id, &before));
        ASSERT_EQ((int)before.window_used, 2);

        /* Past the window the next commit rolls it; the rollback restores start and counter. */
        g_now += 61;
        struct seal_probe probe;
        memset(&probe, 0, sizeof(probe));
        probe.fail_next = 1;
        ASSERT(property_grant_service_test_set_seal_hook(seal_probe_hook,
                                                         &probe));
        struct metaverse_action_request r =
            request_for(&prop, METAVERSE_ACTION_BUY, NULL, 1000);
        struct property_grant_plan plan;
        ASSERT_EQ((int)property_grant_service_plan(g.grant_id, &r, &plan),
                  (int)PROPERTY_GRANT_OK);
        struct property_grant_commit_result res;
        ASSERT_EQ((int)property_grant_service_commit(plan.plan_id, "rolled",
                                                     &res),
                  (int)PROPERTY_GRANT_RECEIPT_SEAL_FAILED);
        ASSERT_EQ(probe.calls, 1);
        ASSERT(property_grant_service_test_set_seal_hook(NULL, NULL));

        /* BIT-IDENTICAL, not "the two fields we thought of". */
        struct metaverse_grant after;
        ASSERT(grant_record(g.grant_id, &after));
        ASSERT_EQ(memcmp(&before, &after, sizeof(before)), 0);
        PASS();
    } _test_next:;
    return failures;
}

/* P3 */
static int t_evidence_and_generation_move_together(void)
{
    int failures = 0;
    TEST("evidence and the authority generation move together, or neither") {
        struct metaverse_property_id prop = make_id(METAVERSE_KIND_CONTENT, 93);
        fixture_reset(&prop);
        struct metaverse_grant g =
            grant_over_id(&prop, ACT(LIST_FOR_SALE), 2500);
        ASSERT_EQ((int)property_grant_service_mint(&g), (int)PROPERTY_GRANT_OK);
        struct metaverse_action_request r =
            request_for(&prop, METAVERSE_ACTION_LIST_FOR_SALE, NULL, 5000);
        struct metaverse_receipt seen[4];

        /* (a) A commit that produces nothing moves nothing, including the generation. */
        struct metaverse_grant before;
        ASSERT(grant_record(g.grant_id, &before));
        uint64_t gen_before = property_grant_service_authority_generation();

        struct seal_probe probe;
        memset(&probe, 0, sizeof(probe));
        probe.fail_next = 1;
        ASSERT(property_grant_service_test_set_seal_hook(seal_probe_hook,
                                                         &probe));
        struct property_grant_plan plan;
        ASSERT_EQ((int)property_grant_service_plan(g.grant_id, &r, &plan),
                  (int)PROPERTY_GRANT_OK);
        struct property_grant_commit_result res;
        ASSERT_EQ((int)property_grant_service_commit(plan.plan_id, "none",
                                                     &res),
                  (int)PROPERTY_GRANT_RECEIPT_SEAL_FAILED);
        ASSERT(property_grant_service_test_set_seal_hook(NULL, NULL));

        struct metaverse_grant after;
        ASSERT(grant_record(g.grant_id, &after));
        ASSERT_EQ(memcmp(&before, &after, sizeof(before)), 0);
        ASSERT_EQ((int)property_grant_service_receipts(g.grant_id, seen, 4), 0);
        struct property_grant_plan replanned;
        ASSERT_EQ((int)property_grant_service_plan_get(plan.plan_id,
                                                       &replanned),
                  (int)PROPERTY_GRANT_OK);
        ASSERT(!replanned.committed);
        ASSERT_EQ((int)(property_grant_service_authority_generation() -
                        gen_before),
                  0);

        /* (b) A commit that produces evidence moves the generation, which tracks the store. */
        uint64_t gen_mid = property_grant_service_authority_generation();
        struct property_grant_plan plan2;
        ASSERT_EQ((int)property_grant_service_plan(g.grant_id, &r, &plan2),
                  (int)PROPERTY_GRANT_OK);
        struct property_grant_commit_result res2;
        ASSERT_EQ((int)property_grant_service_commit(plan2.plan_id, "some",
                                                     &res2),
                  (int)PROPERTY_GRANT_OK);
        ASSERT_EQ((int)property_grant_service_receipts(g.grant_id, seen, 4), 1);
        ASSERT(property_grant_service_authority_generation() > gen_mid);
        struct metaverse_grant after2;
        ASSERT(grant_record(g.grant_id, &after2));
        ASSERT_EQ(memcmp(&before, &after2, sizeof(before)), 0);
        PASS();
    } _test_next:;
    return failures;
}

/* Read a source file whole (suite runs from the repository root); 0 if unreadable.
 * Lock-scope invariants are asserted on source shape, not sampled instants. */
static size_t slurp_source(const char *rel, char *out, size_t cap)
{
    FILE *f = fopen(rel, "rb");
    if (!f) return 0;
    size_t n = fread(out, 1, cap - 1, f);
    fclose(f);
    out[n] = '\0';
    return n;
}

/* P4 */
static int t_failed_commit_window_stays_locked(void)
{
    int failures = 0;
    TEST("the mutate-and-restore window never releases the store mutex") {
        struct metaverse_property_id prop = make_id(METAVERSE_KIND_CONTENT, 94);
        fixture_reset(&prop);
        struct metaverse_grant g = grant_over_id(&prop, ACT(BUY), 100000);
        g.rate_limit = 4;
        g.rate_window_seconds = 60;
        ASSERT_EQ((int)property_grant_service_mint(&g), (int)PROPERTY_GRANT_OK);

        struct seal_probe probe;
        memset(&probe, 0, sizeof(probe));
        probe.fail_next = 1;
        ASSERT(property_grant_service_test_set_seal_hook(seal_probe_hook,
                                                         &probe));
        struct metaverse_action_request r =
            request_for(&prop, METAVERSE_ACTION_BUY, NULL, 1000);
        struct property_grant_plan plan;
        ASSERT_EQ((int)property_grant_service_plan(g.grant_id, &r, &plan),
                  (int)PROPERTY_GRANT_OK);
        struct property_grant_commit_result res;
        ASSERT_EQ((int)property_grant_service_commit(plan.plan_id, "locked-bad",
                                                     &res),
                  (int)PROPERTY_GRANT_RECEIPT_SEAL_FAILED);
        ASSERT_EQ(probe.calls, 1);
        ASSERT_EQ(probe.lock_held_calls, 1);

        /* Also holds when the seal succeeds: receipt append and generation bump share the critical section. */
        struct property_grant_plan plan2;
        ASSERT_EQ((int)property_grant_service_plan(g.grant_id, &r, &plan2),
                  (int)PROPERTY_GRANT_OK);
        struct property_grant_commit_result res2;
        ASSERT_EQ((int)property_grant_service_commit(plan2.plan_id, "locked-ok",
                                                     &res2),
                  (int)PROPERTY_GRANT_OK);
        ASSERT_EQ(probe.calls, 2);
        ASSERT_EQ(probe.lock_held_calls, 2);
        ASSERT(property_grant_service_test_set_seal_hook(NULL, NULL));

        /* A re-acquire inside the window is the tell-tale of any release; asserted on the source region. */
        static char src[131072];
        size_t n = slurp_source("engine/services/src/property_grant_commit.c", src,
                                sizeof(src));
        ASSERT(n > 0);          /* the suite runs from the repository root */
        const char *win = strstr(src,
                                 "const struct metaverse_grant "
                                 "grant_before_effect = *g;");
        ASSERT(win != NULL);
        const char *win_end = strstr(win,
                                     "g_pg_store.receipts"
                                     "[g_pg_store.receipt_count++] = r;");
        ASSERT(win_end != NULL);

        /* Nothing re-takes the lock inside the window. */
        const char *relock = strstr(win, "pthread_mutex_lock(");
        ASSERT(relock == NULL || relock > win_end);

        /* Every exit restores the record before it unlocks. */
        const char *cur = win;
        int unlocks = 0;
        for (;;) {
            const char *u = strstr(cur, "pthread_mutex_unlock(");
            if (!u || u > win_end) break;
            const char *restore = strstr(cur, "*g = grant_before_effect;");
            ASSERT(restore != NULL && restore < u);
            unlocks++;
            cur = u + 1;
        }
        ASSERT(unlocks >= 2);   /* the debit refusal and the seal refusal */

        /* From the lineage charge onward, every exit restores charged ancestors before unlocking. */
        const char *charge = strstr(win,
                                    "metaverse_grant_record_descendant_charge(");
        ASSERT(charge != NULL && charge < win_end);
        cur = charge;
        int lineage_unlocks = 0;
        for (;;) {
            const char *u = strstr(cur, "pthread_mutex_unlock(");
            if (!u || u > win_end) break;
            const char *restore = strstr(cur, "] = lineage_before[");
            ASSERT(restore != NULL && restore < u);
            lineage_unlocks++;
            cur = u + 1;
        }
        /* The ancestor refusal and the seal refusal. */
        ASSERT(lineage_unlocks >= 2);
        PASS();
    } _test_next:;
    return failures;
}

/* The environment is a decision input too */
static int t_env_swap_invalidates_a_decision(void)
{
    int failures = 0;
    TEST("replacing the clock or the catalog invalidates a decision in flight") {
        struct metaverse_property_id prop = make_id(METAVERSE_KIND_CONTENT, 95);
        fixture_reset(&prop);
        struct metaverse_grant g = grant_over_id(&prop, ACT(BUY), 100000);
        ASSERT_EQ((int)property_grant_service_mint(&g), (int)PROPERTY_GRANT_OK);

        struct property_grant_authority_snapshot snap;
        ASSERT_EQ((int)property_grant_service_snapshot(g.grant_id, &snap),
                  (int)PROPERTY_GRANT_OK);
        ASSERT_EQ((int)property_grant_service_recheck(&snap),
                  (int)PROPERTY_GRANT_OK);
        uint64_t before = property_grant_service_authority_generation();

        /* A changed clock changes expiry verdicts; an in-flight decision must not recheck clean. */
        struct property_grant_env env;
        memset(&env, 0, sizeof(env));
        env.catalog_lookup = fake_lookup;
        env.clock = fake_clock;
        property_grant_service_configure(&env);

        ASSERT(property_grant_service_authority_generation() > before);
        ASSERT_EQ((int)property_grant_service_recheck(&snap),
                  (int)PROPERTY_GRANT_AUTHORITY_CHANGED);
        PASS();
    } _test_next:;
    return failures;
}

static int t_unknown_and_malformed(void)
{
    int failures = 0;
    TEST("an unknown grant and a malformed grant each name themselves") {
        struct metaverse_property_id prop = make_id(METAVERSE_KIND_CONTENT, 81);
        fixture_reset(&prop);
        struct metaverse_action_request r =
            request_for(&prop, METAVERSE_ACTION_HOST, NULL, 0);
        struct property_grant_plan plan;
        ASSERT_EQ((int)property_grant_service_plan(
                      "00000000000000000000000000000000", &r, &plan),
                  (int)PROPERTY_GRANT_GRANT_UNKNOWN);

        struct metaverse_grant empty_scope;
        memset(&empty_scope, 0, sizeof(empty_scope));
        snprintf(empty_scope.holder, sizeof(empty_scope.holder), "%s",
                 k_holder);
        empty_scope.scope_form = METAVERSE_SCOPE_IDS;
        empty_scope.id_count = 0;   /* no ids under an id-scoped grant */
        ASSERT_EQ((int)property_grant_service_mint(&empty_scope),
                  (int)PROPERTY_GRANT_GRANT_MALFORMED);
        PASS();
    } _test_next:;
    return failures;
}

static int t_list_and_get(void)
{
    int failures = 0;
    TEST("list and get report what the store holds") {
        struct metaverse_property_id prop = make_id(METAVERSE_KIND_CONTENT, 81);
        fixture_reset(&prop);
        struct metaverse_grant a = grant_over_id(&prop, ACT(HOST), 0);
        struct metaverse_grant b = grant_over_id(&prop, ACT(HOST), 0);
        snprintf(b.holder, sizeof(b.holder), "%s", k_other);
        ASSERT_EQ((int)property_grant_service_mint(&a), (int)PROPERTY_GRANT_OK);
        ASSERT_EQ((int)property_grant_service_mint(&b), (int)PROPERTY_GRANT_OK);

        struct metaverse_grant rows[8];
        ASSERT_EQ((int)property_grant_service_list(NULL, rows, 8), 2);
        ASSERT_EQ((int)property_grant_service_list(k_holder, rows, 8), 1);
        ASSERT_STR_EQ(rows[0].grant_id, a.grant_id);
        struct metaverse_grant one;
        ASSERT_EQ((int)property_grant_service_get("deadbeef", &one),
                  (int)PROPERTY_GRANT_GRANT_UNKNOWN);
        PASS();
    } _test_next:;
    return failures;
}

static int t_reason_tokens_are_contract(void)
{
    int failures = 0;
    TEST("every reason has a distinct, stable token") {
        ASSERT_STR_EQ(property_grant_reason_token(PROPERTY_GRANT_OK), "OK");
        ASSERT_STR_EQ(property_grant_reason_token(PROPERTY_GRANT_STALE_REVISION),
                      "STALE_REVISION");
        ASSERT_STR_EQ(property_grant_reason_token(PROPERTY_GRANT_GRANT_REVOKED),
                      "GRANT_REVOKED");
        ASSERT_STR_EQ(
            property_grant_reason_token(PROPERTY_GRANT_ANCESTOR_REVOKED),
            "ANCESTOR_REVOKED");
        ASSERT_STR_EQ(property_grant_reason_token(PROPERTY_GRANT_REASON_COUNT),
                      "UNKNOWN_REASON");
        /* No two reasons share a token. */
        for (int i = 0; i < PROPERTY_GRANT_REASON_COUNT; i++) {
            for (int j = i + 1; j < PROPERTY_GRANT_REASON_COUNT; j++) {
                ASSERT(strcmp(property_grant_reason_token(
                                  (enum property_grant_reason)i),
                              property_grant_reason_token(
                                  (enum property_grant_reason)j)) != 0);
            }
        }
        /* And the verdict→reason map is total. */
        for (int v = 1; v < METAVERSE_GRANT_VERDICT_COUNT; v++) {
            ASSERT(property_grant_reason_from_verdict(
                       (enum metaverse_grant_verdict)v) != PROPERTY_GRANT_OK);
        }
        PASS();
    } _test_next:;
    return failures;
}

int test_metaverse_grant(void);
int test_metaverse_grant(void)
{
    printf("\n=== metaverse property grant tests ===\n");
    int failures = 0;

    failures += t_id_roundtrip();
    failures += t_id_rejects();
    failures += t_action_set_codec();
    failures += t_value_actions();
    failures += t_reserved_inspect_names_no_action();
    failures += t_reserved_inspect_authorizes_nothing();

    failures += t_query_allowed();
    failures += t_query_not_granted();
    failures += t_query_property_out_of_scope();
    failures += t_query_wrong_holder();
    failures += t_query_expiry_and_revocation();
    failures += t_query_and_action_sets_do_not_leak();
    failures += t_query_enumerate_names_no_property();

    failures += t_plan_action_not_granted();
    failures += t_plan_property_out_of_scope();
    failures += t_plan_kind_out_of_scope();
    failures += t_plan_counterparty();
    failures += t_plan_budget();
    failures += t_plan_value_shape();
    failures += t_plan_wrong_holder();
    failures += t_plan_expiry();

    failures += t_commit_stale_revision();
    failures += t_commit_owner_mismatch();
    failures += t_commit_property_unknown();
    failures += t_commit_no_catalog();
    failures += t_commit_plan_expired();
    failures += t_commit_unknown_plan();

    failures += t_revoke_kills_grant();
    failures += t_revoke_kills_subtree();
    failures += t_ancestor_generation_alone_kills();
    failures += t_ancestor_revoked_flag_alone_kills();

    failures += t_idempotent_commit();
    failures += t_unkeyed_commit_not_replayable();
    failures += t_distinct_key_is_not_replay();
    failures += t_replay_must_match_the_request();

    failures += t_tamper_edit_detected();
    failures += t_tamper_foreign_signature();
    failures += t_tamper_cut_link();
    failures += t_chain_verifier_agrees();

    failures += t_delegation_depth();
    failures += t_delegation_requires_right();
    failures += t_delegation_attenuates();
    failures += t_delegation_attenuates_counterparties();

    failures += t_budget_is_cumulative();
    failures += t_parent_budget_bounds_its_children();
    failures += t_lineage_charge_reaches_a_grandparent();
    failures += t_rate_window();

    failures += t_quoted_value_is_never_charged();
    failures += t_failed_commit_restores_the_rate_window();
    failures += t_evidence_and_generation_move_together();
    failures += t_failed_commit_window_stays_locked();
    failures += t_env_swap_invalidates_a_decision();

    failures += t_unknown_and_malformed();
    failures += t_list_and_get();
    failures += t_reason_tokens_are_contract();

    property_grant_service_reset();
    printf("metaverse_grant: %s (%d failures)\n",
           failures == 0 ? "OK" : "FAIL", failures);
    return failures;
}
