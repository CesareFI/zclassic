/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "test/test_core.h"
#include "base/safe_alloc.h"
#include "config/command_catalog.h"
#include "kernel/command_registry.h"
#include "json/json.h"
#include "controllers/rpc_client.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

static unsigned outcome_fault_index;
static const char *outcome_fault_label;
static bool outcome_effect_observed;
static bool outcome_bounded;
static bool outcome_debit;
static unsigned outcome_authorize_calls;

static char *outcome_policy_rpc(const char *method, const char *params)
{
    /* Only the policy decision transport is mocked; no custody or debit claim. */
    if (strcmp(method, "agentsession") || !strstr(params, "authorize")) return NULL;
    outcome_authorize_calls++;
    const char answer[] = "{\"ok\":true,\"charged_zat\":7,\"window_remaining_zat\":93}";
    char *result = malloc(sizeof(answer));
    if (result) memcpy(result, answer, sizeof(answer));
    return result;
}

static void outcome_handler(const struct zcl_command_request *request,
                            struct zcl_command_reply *reply)
{
    (void)request;
    /* A trusted test handler's observable effect. */
    outcome_effect_observed = true;
    reply->status = ZCL_COMMAND_STATUS_PASSED;
    reply->exit_code = ZCL_COMMAND_EXIT_OK;
    reply->error.mutated = true;
    if (outcome_fault_index)
        zcl_alloc_fault_fail_nth(outcome_fault_label, outcome_fault_index);
}

static size_t outcome_execute(char *out, size_t capacity,
                              enum zcl_command_exit *code)
{
    const struct zcl_command_registry *catalog = zcl_command_catalog();
    const struct zcl_command_spec *original =
        zcl_command_registry_find(catalog, "discover.help", NULL);
    if (!original)
        return 0;
    struct zcl_command_spec spec = *original;
    if (outcome_debit) {
        spec.path = "core.wallet.transaction.send";
        spec.input_keys = "amount,address,wallet_scope";
    }
    spec.handler = outcome_handler;
    struct zcl_command_registry registry = { .commands = &spec, .count = 1 };
    struct zcl_command_context context = {
        .registry = catalog, .granted_capabilities = UINT64_MAX,
        .authority_ceiling = ZCL_COMMAND_AUTH_OWNER,
        .agent_session = outcome_bounded ? "0123456789abcdef0123456789abcdef" : NULL,
    };
    struct json_value input;
    json_init(&input);
    json_set_object(&input);
    if (outcome_debit) {
        (void)json_push_kv_real(&input, "amount", 0.00000007);
        (void)json_push_kv_str(&input, "address", "fixture-recipient");
        (void)json_push_kv_str(&input, "wallet_scope", "dev");
    }
    size_t used = zcl_command_registry_execute_json(
        &registry, &spec, &context, &input, false, spec.path, "normal",
        0, 0, NULL, out, capacity, code);
    json_free(&input);
    return used;
}

static int authority_copy_refusal(const char *label, unsigned index)
{
    int failures = 0;
    char out[8192] = "";
    enum zcl_command_exit code = ZCL_COMMAND_EXIT_OK;
    bool consumed = false;
    outcome_effect_observed = false;
    outcome_fault_index = index;
    outcome_fault_label = label;
    TEST("actual execute refuses incomplete authority after an observed effect") {
        size_t used = outcome_execute(out, sizeof(out), &code);
        consumed = zcl_alloc_fault_armed_label() == NULL;
        zcl_alloc_fault_clear();
        ASSERT(used > 0);
        ASSERT(outcome_effect_observed);
        ASSERT(consumed);
        ASSERT_EQ(code, ZCL_COMMAND_EXIT_INTERNAL);
        ASSERT(strstr(out, "\"ok\":false") != NULL);
        ASSERT(strstr(out, "\"mutated\":true") != NULL);
        ASSERT(strstr(out, "inspect preserved publication artifacts") != NULL);
        PASS();
    } _test_next:;
    zcl_alloc_fault_clear();
    outcome_fault_index = 0;
    return failures;
}

static int authority_success(void)
{
    int failures = 0;
    char out[8192] = "";
    enum zcl_command_exit code = ZCL_COMMAND_EXIT_INTERNAL;
    outcome_fault_index = 0;
    TEST("actual execute emits the complete exempt authority without a fault") {
        ASSERT(outcome_execute(out, sizeof(out), &code) > 0);
        ASSERT_EQ(code, ZCL_COMMAND_EXIT_OK);
        ASSERT(strstr(out, "\"policy\":\"exempt\"") != NULL);
        ASSERT(strstr(out, "\"agent_session\":\"none (local operator)\"") != NULL);
        PASS();
    } _test_next:;
    return failures;
}

static int authority_bounded_debit(void)
{
    int failures = 0;
    char out[8192]; enum zcl_command_exit code;
    outcome_bounded = true; outcome_debit = true; outcome_authorize_calls = 0;
    node_rpc_client_set_test_hook(outcome_policy_rpc);
    TEST("rendered bounded authority keeps the observed debit and remaining window") {
        ASSERT(outcome_execute(out, sizeof(out), &code) > 0);
        ASSERT_EQ(code, ZCL_COMMAND_EXIT_OK); ASSERT_EQ(outcome_authorize_calls, 1);
        ASSERT(strstr(out, "\"policy\":\"bounded\"") != NULL);
        ASSERT(strstr(out, "\"debited_zat\":7") != NULL);
        ASSERT(strstr(out, "\"window_remaining_zat\":93") != NULL);
        PASS();
    } _test_next:;
    failures += authority_copy_refusal("json_copy_children", 1);
    node_rpc_client_set_test_hook(NULL); outcome_bounded = false; outcome_debit = false;
    return failures;
}

int test_command_outcome(void)
{
    int failures = authority_success();
    /* The nine-field root allocates and grows before the authority object.
     * Copying authority is the first child-object clone. These labels use
     * checked malloc/realloc hooks; strdup labels are not injectable here. */
    failures += authority_copy_refusal("json_children", 3);
    failures += authority_copy_refusal("json_copy_children", 1);
    failures += authority_bounded_debit();
    return failures;
}
