/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: verdict-vocabulary coverage for
 * zcl_service_binding_result_name_v1(), the stable lowercase_snake name
 * table for the service-binding gate's named refusals. Callers log and
 * compare these strings, so every value must map to its documented name
 * and out-of-range values must degrade to "unknown" rather than a
 * fabricated or NULL name. Zero test references existed. */

#include "test/test_core.h"

#include "kernel/service_binding.h"

#include <string.h>

static int test_sbn_vocabulary_identity(void)
{
    int failures = 0;
    TEST("service binding names: identity verdicts map to their stable names") {
        ASSERT(strcmp(zcl_service_binding_result_name_v1(
                          ZCL_SERVICE_BINDING_OK), "ok") == 0);
        ASSERT(strcmp(zcl_service_binding_result_name_v1(
                          ZCL_SERVICE_BINDING_NULL), "null") == 0);
        ASSERT(strcmp(zcl_service_binding_result_name_v1(
                          ZCL_SERVICE_BINDING_SCHEMA), "schema") == 0);
        ASSERT(strcmp(zcl_service_binding_result_name_v1(
                          ZCL_SERVICE_BINDING_IDENTITY), "identity") == 0);
        ASSERT(strcmp(zcl_service_binding_result_name_v1(
                          ZCL_SERVICE_BINDING_HOST), "host") == 0);
        ASSERT(strcmp(zcl_service_binding_result_name_v1(
                          ZCL_SERVICE_BINDING_COMMAND_PREFIX),
                      "command_prefix") == 0);
        ASSERT(strcmp(zcl_service_binding_result_name_v1(
                          ZCL_SERVICE_BINDING_STATE_PREFIX),
                      "state_prefix") == 0);
        ASSERT(strcmp(zcl_service_binding_result_name_v1(
                          ZCL_SERVICE_BINDING_STATE_SCHEMA),
                      "state_schema") == 0);
        PASS();
    } _test_next:;
    return failures;
}

static int test_sbn_vocabulary_policy(void)
{
    int failures = 0;
    TEST("service binding names: policy verdicts map to their stable names") {
        ASSERT(strcmp(zcl_service_binding_result_name_v1(
                          ZCL_SERVICE_BINDING_TOKEN_GATE),
                      "token_gate") == 0);
        ASSERT(strcmp(zcl_service_binding_result_name_v1(
                          ZCL_SERVICE_BINDING_ISOLATION),
                      "isolation") == 0);
        ASSERT(strcmp(zcl_service_binding_result_name_v1(
                          ZCL_SERVICE_BINDING_RESTART), "restart") == 0);
        ASSERT(strcmp(zcl_service_binding_result_name_v1(
                          ZCL_SERVICE_BINDING_HEALTH), "health") == 0);
        ASSERT(strcmp(zcl_service_binding_result_name_v1(
                          ZCL_SERVICE_BINDING_CATALOG_ORDER),
                      "catalog_order") == 0);
        ASSERT(strcmp(zcl_service_binding_result_name_v1(
                          ZCL_SERVICE_BINDING_CATALOG_COLLISION),
                      "catalog_collision") == 0);
        PASS();
    } _test_next:;
    return failures;
}

static int test_sbn_out_of_range_degrades(void)
{
    int failures = 0;
    TEST("service binding names: out-of-range degrades to unknown") {
        ASSERT(strcmp(zcl_service_binding_result_name_v1(
                          (enum zcl_service_binding_result)9999),
                      "unknown") == 0);
        ASSERT(strcmp(zcl_service_binding_result_name_v1(
                          (enum zcl_service_binding_result)-1),
                      "unknown") == 0);
        PASS();
    } _test_next:;
    return failures;
}

int test_service_binding_names(void)
{
    int failures = 0;
    failures += test_sbn_vocabulary_identity();
    failures += test_sbn_vocabulary_policy();
    failures += test_sbn_out_of_range_degrades();
    printf("=== service_binding_names: %d failures ===\n", failures);
    return failures;
}
