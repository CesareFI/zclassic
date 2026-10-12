/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 *
 * test_dev_proof_observation_env — fixture-only regressions for explicit
 * observation store lifecycle: isolated verdict scratch, durable signed CAS,
 * cleanup and interrupted-run retry. Automatic worker collection is deferred
 * until all required input closures qualify. These ZCL_TESTING helpers do not
 * add stores or filesystem prerequisites to the default whole-cycle proof. */

#include "test/test_core.h"

#include "dev_proof.h"
#include "dev_proof_observation.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#define DPOE_KEY "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef01-cafe01"

static void dpoe_clear_env(void)
{
    (void)unsetenv("ZCL_TESTCACHE_STORE_ROOT");
    (void)unsetenv(ZCL_DEV_OBSERVATION_STORE_ENV);
}

static int test_dpoe_absent_becomes_private_pair(void)
{
    int failures = 0;
    char root[4096];
    test_make_tmpdir(root, sizeof(root), "proof_obs_env", "absent");
    TEST_CASE("dev_proof_obs_env: absent before, per-pair private stores after") {
        dpoe_clear_env();
        ASSERT(getenv("ZCL_TESTCACHE_STORE_ROOT") == NULL);
        ASSERT(getenv(ZCL_DEV_OBSERVATION_STORE_ENV) == NULL);

        char why[160] = {0};
        ASSERT(zcl_dev_proof_test_observation_env_prepare(
                   root, DPOE_KEY, why, sizeof(why)));
        ASSERT(why[0] == '\0');

        char expect[4096];
        ASSERT(snprintf(expect, sizeof(expect), "%s/testcache.%s",
                        root, DPOE_KEY) > 0);
        const char *verdict_store = getenv("ZCL_TESTCACHE_STORE_ROOT");
        ASSERT(verdict_store != NULL);
        ASSERT_STR_EQ(verdict_store, expect);
        ASSERT(snprintf(expect, sizeof(expect), "%s/observations.%s",
                        root, DPOE_KEY) > 0);
        const char *observation_store =
            getenv(ZCL_DEV_OBSERVATION_STORE_ENV);
        ASSERT(observation_store != NULL);
        ASSERT_STR_EQ(observation_store, expect);

        /* The two stores are distinct trees: durable signed observations
         * never share content-addressed space with unsigned verdict
         * records. */
        ASSERT(strcmp(verdict_store, observation_store) != 0);
    }
    TEST_END
    dpoe_clear_env();
    (void)test_rm_rf_recursive(root);
    return failures;
}

static int test_dpoe_restore_removes_both(void)
{
    int failures = 0;
    char root[4096];
    test_make_tmpdir(root, sizeof(root), "proof_obs_env", "restore");
    TEST_CASE("dev_proof_obs_env: restore removes both knobs again") {
        dpoe_clear_env();
        ASSERT(zcl_dev_proof_test_observation_env_prepare(
                   root, DPOE_KEY, NULL, 0));
        ASSERT(getenv("ZCL_TESTCACHE_STORE_ROOT") != NULL);
        ASSERT(getenv(ZCL_DEV_OBSERVATION_STORE_ENV) != NULL);

        ASSERT(zcl_dev_proof_test_observation_env_restore(root, DPOE_KEY));
        ASSERT(getenv("ZCL_TESTCACHE_STORE_ROOT") == NULL);
        ASSERT(getenv(ZCL_DEV_OBSERVATION_STORE_ENV) == NULL);
    }
    TEST_END
    dpoe_clear_env();
    (void)test_rm_rf_recursive(root);
    return failures;
}

static int test_dpoe_unconditional_overwrite(void)
{
    int failures = 0;
    char root[4096];
    test_make_tmpdir(root, sizeof(root), "proof_obs_env", "overwrite");
    TEST_CASE("dev_proof_obs_env: stale inherited values are overwritten") {
        /* A prior tool, or a resident daemon's very first environment, could
         * have exported a shared store here. The proof must not defer to it:
         * the whole point is that the test dimension no longer depends on
         * what invoked this binary. */
        ASSERT(setenv("ZCL_TESTCACHE_STORE_ROOT", "/shared/verdict-store",
                      1) == 0);
        ASSERT(setenv(ZCL_DEV_OBSERVATION_STORE_ENV, "/shared/observations",
                      1) == 0);

        char why[160] = {0};
        ASSERT(zcl_dev_proof_test_observation_env_prepare(
                   root, DPOE_KEY, why, sizeof(why)));
        char expect[4096];
        ASSERT(snprintf(expect, sizeof(expect), "%s/testcache.%s",
                        root, DPOE_KEY) > 0);
        ASSERT_STR_EQ(getenv("ZCL_TESTCACHE_STORE_ROOT"), expect);
        ASSERT(snprintf(expect, sizeof(expect), "%s/observations.%s",
                        root, DPOE_KEY) > 0);
        ASSERT_STR_EQ(getenv(ZCL_DEV_OBSERVATION_STORE_ENV), expect);
    }
    TEST_END
    dpoe_clear_env();
    (void)test_rm_rf_recursive(root);
    return failures;
}

static int test_dpoe_refusal_leaves_env_untouched(void)
{
    int failures = 0;
    char root[4096];
    test_make_tmpdir(root, sizeof(root), "proof_obs_env", "refuse");
    TEST_CASE("dev_proof_obs_env: invalid pair refuses by name, env untouched") {
        ASSERT(setenv("ZCL_TESTCACHE_STORE_ROOT", "/sentinel/verdict",
                      1) == 0);
        ASSERT(setenv(ZCL_DEV_OBSERVATION_STORE_ENV, "/sentinel/observations",
                      1) == 0);

        char why[160] = {0};
        /* A key containing '/' would escape the per-pair directory. */
        ASSERT(!zcl_dev_proof_test_observation_env_prepare(
                   root, "bad/key", why, sizeof(why)));
        ASSERT(why[0] != '\0');
        ASSERT(!zcl_dev_proof_test_observation_env_prepare(
                   "", DPOE_KEY, why, sizeof(why)));
        ASSERT(!zcl_dev_proof_test_observation_env_prepare(
                   root, "", why, sizeof(why)));
        ASSERT(!zcl_dev_proof_test_observation_env_prepare(
                   NULL, DPOE_KEY, why, sizeof(why)));

        /* A refused prepare must not have partial-set the environment. */
        ASSERT_STR_EQ(getenv("ZCL_TESTCACHE_STORE_ROOT"), "/sentinel/verdict");
        ASSERT_STR_EQ(getenv(ZCL_DEV_OBSERVATION_STORE_ENV),
                      "/sentinel/observations");
    }
    TEST_END
    dpoe_clear_env();
    (void)test_rm_rf_recursive(root);
    return failures;
}

static int test_dpoe_prepare_is_idempotent_across_runs(void)
{
    int failures = 0;
    char root[4096];
    test_make_tmpdir(root, sizeof(root), "proof_obs_env", "retry");
    TEST_CASE("dev_proof_obs_env: re-prepare tolerates the durable CAS") {
        /* A retried proof re-arms the same pair. The verdict store is
         * scratch and starts empty again; the observation CAS is durable
         * and already exists -- the second prepare must not refuse it. */
        dpoe_clear_env();
        ASSERT(zcl_dev_proof_test_observation_env_prepare(
                   root, DPOE_KEY, NULL, 0));
        char obs[4096];
        ASSERT(snprintf(obs, sizeof(obs), "%s/observations.%s",
                        root, DPOE_KEY) > 0);
        ASSERT(access(obs, F_OK) == 0);
        ASSERT(zcl_dev_proof_test_observation_env_restore(root, DPOE_KEY));
        ASSERT(!zcl_dev_proof_test_observation_env_prepare(
                    root, "bad/key", NULL, 0));

        ASSERT(zcl_dev_proof_test_observation_env_prepare(
                   root, DPOE_KEY, NULL, 0));
        ASSERT_STR_EQ(getenv(ZCL_DEV_OBSERVATION_STORE_ENV), obs);
        ASSERT(access(obs, F_OK) == 0);
    }
    TEST_END
    dpoe_clear_env();
    (void)test_rm_rf_recursive(root);
    return failures;
}

static bool dpoe_sentinel_matches(const char *path)
{
    static const char expected[] = "durable observation fixture";
    char bytes[sizeof(expected)] = {0};
    FILE *file = fopen(path, "rb");
    if (!file) return false;
    size_t got = fread(bytes, 1, sizeof(bytes), file);
    bool ok = got == sizeof(expected) - 1 &&
              memcmp(bytes, expected, sizeof(expected) - 1) == 0 &&
              !ferror(file);
    return fclose(file) == 0 && ok;
}

static int test_dpoe_scratch_cleanup_and_partial_open(void)
{
    int failures = 0;
    char root[4096], scratch[4096], observations[4096], sentinel[4096];
    test_make_tmpdir(root, sizeof(root), "proof_obs_env", "cleanup");
    TEST_CASE("dev_proof_obs_env: scratch removed, durable bytes retained, partial open cleaned") {
        ASSERT(snprintf(scratch, sizeof(scratch), "%s/testcache.%s", root, DPOE_KEY) > 0);
        ASSERT(snprintf(observations, sizeof(observations), "%s/observations.%s", root, DPOE_KEY) > 0);
        ASSERT(snprintf(sentinel, sizeof(sentinel), "%s/keep", observations) > 0);
        ASSERT(zcl_dev_proof_test_observation_env_prepare(root, DPOE_KEY, NULL, 0));
        FILE *file = fopen(sentinel, "wb");
        ASSERT(file != NULL);
        ASSERT(fputs("durable observation fixture", file) >= 0);
        ASSERT(fclose(file) == 0);
        char stale[4096];
        ASSERT(snprintf(stale, sizeof(stale), "%s/stale", scratch) > 0);
        file = fopen(stale, "wb");
        ASSERT(file != NULL);
        ASSERT(fclose(file) == 0);
        ASSERT(zcl_dev_proof_test_observation_env_prepare(root, DPOE_KEY, NULL, 0));
        ASSERT(access(stale, F_OK) != 0);
        ASSERT(dpoe_sentinel_matches(sentinel));
        ASSERT(zcl_dev_proof_test_observation_env_restore(root, DPOE_KEY));
        ASSERT(access(scratch, F_OK) != 0);
        ASSERT(dpoe_sentinel_matches(sentinel));
        ASSERT(zcl_dev_proof_test_observation_env_prepare(root, DPOE_KEY, NULL, 0));
        ASSERT(access(sentinel, F_OK) == 0);
        ASSERT(zcl_dev_proof_test_observation_env_restore(root, DPOE_KEY));
        ASSERT_EQ(test_rm_rf_recursive(observations), 0);
        file = fopen(observations, "wb");
        ASSERT(file != NULL);
        ASSERT(fclose(file) == 0);
        ASSERT(!zcl_dev_proof_test_observation_env_prepare(root, DPOE_KEY, NULL, 0));
        ASSERT(getenv("ZCL_TESTCACHE_STORE_ROOT") == NULL);
        ASSERT(getenv(ZCL_DEV_OBSERVATION_STORE_ENV) == NULL);
        ASSERT(access(scratch, F_OK) != 0);
        ASSERT(access(observations, F_OK) == 0);
    }
    TEST_END
    dpoe_clear_env();
    (void)test_rm_rf_recursive(root);
    return failures;
}



int test_dev_proof_observation_env(void)
{
    int failures = 0;
    failures += test_dpoe_absent_becomes_private_pair();
    failures += test_dpoe_restore_removes_both();
    failures += test_dpoe_unconditional_overwrite();
    failures += test_dpoe_refusal_leaves_env_untouched();
    failures += test_dpoe_prepare_is_idempotent_across_runs();
    failures += test_dpoe_scratch_cleanup_and_partial_open();
    return failures;
}
