/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * directlink policy: the decision table over every scope, pairing state,
 * join state and setting. The default configuration refuses everything. */

#include "test/test_core.h"

#include "gamelink/directlink_policy.h"

#include <string.h>

static enum directlink_refusal expected(bool paired, bool joining,
                                        enum directlink_setting setting)
{
    if (joining)
        return DIRECTLINK_REFUSE_JOIN_IN_PROGRESS;
    if (!paired)
        return DIRECTLINK_REFUSE_NOT_PAIRED;
    if (setting == DIRECTLINK_SETTING_OFF)
        return DIRECTLINK_REFUSE_SCOPE_OFF;
    return DIRECTLINK_ALLOW;
}

static int dlp_case_table(void)
{
    int failures = 0;
    TEST_CASE("directlink policy: every scope/paired/join/setting combination") {
        size_t rows = 0;
        for (unsigned scope = 0; scope < DIRECTLINK_SCOPE_COUNT; scope++)
            for (int paired = 0; paired < 2; paired++)
                for (int joining = 0; joining < 2; joining++)
                    for (int setting = 0; setting < 2; setting++) {
                        enum directlink_refusal got = directlink_may_offer_direct(
                            (enum directlink_scope)scope, paired != 0,
                            joining != 0, (enum directlink_setting)setting);
                        enum directlink_refusal want = expected(
                            paired != 0, joining != 0,
                            (enum directlink_setting)setting);
                        ASSERT_EQ((int)got, (int)want);
                        rows++;
                    }
        ASSERT_EQ(rows, (size_t)16);
    } TEST_END;
    return failures;
}

static int dlp_case_default_refuses(void)
{
    int failures = 0;
    TEST_CASE("directlink policy: the default configuration refuses everything") {
        struct directlink_policy zeroed;
        memset(&zeroed, 0, sizeof zeroed);
        struct directlink_policy def;
        memset(&def, 0xAB, sizeof def);
        directlink_policy_default(&def);
        ASSERT(memcmp(&zeroed, &def, sizeof def) == 0);
        for (unsigned scope = 0; scope < DIRECTLINK_SCOPE_COUNT; scope++)
            for (int paired = 0; paired < 2; paired++) {
                struct directlink_peer peer;
                memset(&peer, 0, sizeof peer);
                peer.identity[0] = 1;
                peer.scope = (enum directlink_scope)scope;
                peer.paired = paired != 0;
                ASSERT(directlink_policy_decide(&def, &peer) != DIRECTLINK_ALLOW);
            }
        /* A paired peer is refused for the setting, not for the pairing. */
        struct directlink_peer paired_peer = {.scope = DIRECTLINK_SCOPE_INTRA_FLEET,
                                              .paired = true};
        ASSERT_EQ((int)directlink_policy_decide(&def, &paired_peer),
                  (int)DIRECTLINK_REFUSE_SCOPE_OFF);
    } TEST_END;
    return failures;
}

static int dlp_case_scopes_independent(void)
{
    int failures = 0;
    TEST_CASE("directlink policy: the two scope settings are independent") {
        struct directlink_policy policy;
        directlink_policy_default(&policy);
        policy.scope_setting[DIRECTLINK_SCOPE_INTRA_FLEET] =
            DIRECTLINK_SETTING_DIRECT_ALLOWED;
        struct directlink_peer intra = {.scope = DIRECTLINK_SCOPE_INTRA_FLEET,
                                        .paired = true};
        struct directlink_peer inter = {.scope = DIRECTLINK_SCOPE_INTER_FLEET,
                                        .paired = true};
        ASSERT_EQ((int)directlink_policy_decide(&policy, &intra),
                  (int)DIRECTLINK_ALLOW);
        ASSERT_EQ((int)directlink_policy_decide(&policy, &inter),
                  (int)DIRECTLINK_REFUSE_SCOPE_OFF);
        policy.scope_setting[DIRECTLINK_SCOPE_INTER_FLEET] =
            DIRECTLINK_SETTING_DIRECT_ALLOWED;
        policy.scope_setting[DIRECTLINK_SCOPE_INTRA_FLEET] =
            DIRECTLINK_SETTING_OFF;
        ASSERT_EQ((int)directlink_policy_decide(&policy, &intra),
                  (int)DIRECTLINK_REFUSE_SCOPE_OFF);
        ASSERT_EQ((int)directlink_policy_decide(&policy, &inter),
                  (int)DIRECTLINK_ALLOW);
        /* A join in progress overrides an allowed setting. */
        inter.join_in_progress = true;
        ASSERT_EQ((int)directlink_policy_decide(&policy, &inter),
                  (int)DIRECTLINK_REFUSE_JOIN_IN_PROGRESS);
    } TEST_END;
    return failures;
}

static int dlp_case_invalid_fails_closed(void)
{
    int failures = 0;
    TEST_CASE("directlink policy: invalid input refuses") {
        struct directlink_policy policy;
        directlink_policy_default(&policy);
        struct directlink_peer peer = {.paired = true};
        ASSERT_EQ((int)directlink_policy_decide(NULL, &peer),
                  (int)DIRECTLINK_REFUSE_INVALID);
        ASSERT_EQ((int)directlink_policy_decide(&policy, NULL),
                  (int)DIRECTLINK_REFUSE_INVALID);
        peer.scope = (enum directlink_scope)7;
        ASSERT_EQ((int)directlink_policy_decide(&policy, &peer),
                  (int)DIRECTLINK_REFUSE_INVALID);
        ASSERT_EQ((int)directlink_may_offer_direct(DIRECTLINK_SCOPE_INTRA_FLEET,
                                                   true, false,
                                                   (enum directlink_setting)2),
                  (int)DIRECTLINK_REFUSE_INVALID);
        ASSERT_STR_EQ(directlink_refusal_label(DIRECTLINK_REFUSE_NOT_PAIRED),
                      "not_paired");
        ASSERT_STR_EQ(directlink_refusal_label(DIRECTLINK_REFUSE_SCOPE_OFF),
                      "scope_off");
        ASSERT_STR_EQ(
            directlink_refusal_label(DIRECTLINK_REFUSE_JOIN_IN_PROGRESS),
            "join_in_progress");
    } TEST_END;
    return failures;
}

int test_directlink_policy(void)
{
    int failures = 0;
    failures += dlp_case_table();
    failures += dlp_case_default_refuses();
    failures += dlp_case_scopes_independent();
    failures += dlp_case_invalid_fails_closed();
    return failures;
}
