/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: Deterministic observation decoder witnesses, no transport/effects. */
#include "test/test_core.h"
#include "command/native_devagent_codex_observation_decode.h"
#include <string.h>
#include "json/json.h"

static enum cga_result cgot_read(const char *raw, struct cgo_snapshot *out)
{
    char why[160];
    return cgo_decode_goal_get(raw, strlen(raw), "request", 7, "thread", 6,
        out, why, sizeof(why));
}

static int cgot_missing_null_zero(void)
{
    int failures = 0;
    struct cgo_snapshot s;
    TEST("native observer: missing, explicit null and reported zero differ") {
        ASSERT_EQ(cgot_read("{\"id\":\"request\",\"result\":{}}", &s), CGA_OK);
        ASSERT_EQ(s.goal_present, CGO_TRUTH_UNKNOWN);
        ASSERT_EQ(s.tokens_used.state, CGO_UNKNOWN);
        ASSERT_EQ(s.thread_id.state, CGO_UNKNOWN);
        ASSERT_EQ(cgot_read("{\"id\":\"request\",\"result\":{\"goal\":null}}", &s), CGA_OK);
        ASSERT_EQ(s.goal_present, CGO_FALSE);
        ASSERT_EQ(s.token_budget.state, CGO_UNKNOWN);
        ASSERT_EQ(cgot_read("{\"id\":\"request\",\"result\":{\"goal\":{\"threadId\":\"thread\",\"tokenBudget\":null,\"tokensUsed\":0,\"timeUsedSeconds\":0}}}", &s), CGA_OK);
        ASSERT_EQ(s.token_budget.state, CGO_ABSENT);
        ASSERT_EQ(s.tokens_used.state, CGO_KNOWN);
        ASSERT_EQ(s.tokens_used.value, 0);
    }
_test_next:;
    return failures;
}

static int cgot_refusals(void)
{
    int failures = 0;
    struct cgo_snapshot s;
    const char *bad[] = {
        "{\"id\":\"wrong\",\"result\":{}}",
        "{\"id\":\"request\",\"result\":{\"goal\":{\"threadId\":\"wrong\"}}}",
        "{\"id\":\"request\",\"error\":null,\"result\":{}}",
        "{\"id\":\"request\",\"id\":\"request\",\"result\":{}}",
        "{\"id\":\"request\",\"result\":{\"goal\":{\"threadId\":\"thread\",\"tokensUsed\":-1}}}",
        "{\"id\":\"request\",\"result\":{\"goal\":{\"threadId\":\"thread\",\"tokensUsed\":null}}}",
        "{\"id\":\"request\",\"result\":{\"goal\":{\"threadId\":\"thread\",\"tokensUsed\":1.0}}}",
        "{\"id\":\"request\",\"result\":{\"goal\":{\"threadId\":\"thread\",\"tokensUsed\":01}}}",
        "{\"id\":\"request\",\"result\":{\"goal\":{\"threadId\":\"thread\",\"createdAt\":2,\"updatedAt\":1}}}",
        "{\"id\":\"request\",\"result\":{\"goal\":{\"threadId\":\"thread\",\"invented\":true}}}",
        "{\"id\":\"request\",\"result\":{\"goal\":{\"threadId\":\"thread\",\"objective\":\"\\u0000\"}}}",
        "{\"id\":\"request\",\"result\":{\"goal\":{\"threadId\":\"thread\",\"status\":\"newStatus\"}}}",
        "{\"id\":\"request\",\"result\":{\"goal\":{\"threadId\":\"thread\",\"objective\":\"\xc0\xaf\"}}}",
        /* Each refusal below asserts parser heap balance in the registered group. */
        "{\"id\":\"request\",\"result\":{\"goal\":{\"threadId\":\"thread\",\"objective\":\"ok\",\"tokensUsed\":}}}",
        "{\"id\":\"request\",\"result\":{\"goal\":{\"threadId\":\"thread\",\"objective\":\"ok\",\"tokensUsed\":",
        "{\"id\":\"request\",\"result\":{\"goal\":[{\"objective\":\"ok\",\"tokensUsed\":}]}}",
        "{\"id\":\"request\",\"result\":{\"goal\":[{\"objective\":\"ok\",\"tokensUsed\":"
    };
    TEST("native observer: malformed correlation and fields refuse without partial facts") {
        for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
            size_t live = json_test_live_blocks();
            memset(&s, 0xa5, sizeof(s));
            ASSERT_EQ(cgot_read(bad[i], &s), CGA_INVALID);
            ASSERT_EQ(s.readback, CGO_TRUTH_UNKNOWN);
            ASSERT_EQ(s.tokens_used.state, CGO_UNKNOWN);
            ASSERT_EQ(json_test_live_blocks(), live);
        }
    }
_test_next:;
    return failures;
}

static int cgot_overflow(void)
{
    int failures = 0;
    struct cgo_snapshot s;
    TEST("native observer: int64 overflow never saturates into native accounting") {
        ASSERT_EQ(cgot_read("{\"id\":\"request\",\"result\":{\"goal\":{\"threadId\":\"thread\",\"tokensUsed\":9223372036854775808}}}", &s), CGA_INVALID);
        ASSERT_EQ(s.tokens_used.state, CGO_UNKNOWN);
        ASSERT_EQ(cgot_read("{\"id\":\"request\",\"result\":{\"goal\":{\"threadId\":\"thread\",\"tokensUsed\":9223372036854775807}}}", &s), CGA_OK);
        ASSERT_EQ(s.tokens_used.value, INT64_MAX);
    }
_test_next:;
    return failures;
}

static int cgot_reported_only(void)
{
    int failures = 0;
    struct cgo_snapshot s;
    TEST("native observer: native accounting is reported without effective or lifecycle inventions") {
        ASSERT_EQ(cgot_read("{\"id\":\"request\",\"result\":{\"goal\":{\"threadId\":\"thread\",\"status\":\"complete\",\"tokenBudget\":800000,\"tokensUsed\":713772,\"timeUsedSeconds\":6300,\"createdAt\":100,\"updatedAt\":200}}}", &s), CGA_OK);
        ASSERT_EQ(s.created_at_unix_seconds.value, 100);
        ASSERT_EQ(s.updated_at_unix_seconds.value, 200);
        ASSERT_EQ(s.time_used_seconds.value, 6300);
        ASSERT_EQ(s.tokens_used.value, 713772);
        ASSERT_EQ(s.observed_at_unix_ms.state, CGO_UNKNOWN);
        ASSERT_EQ(s.freshness, CGO_FRESHNESS_UNKNOWN);
        ASSERT_EQ(s.readback, CGO_TRUE);
        ASSERT_EQ(s.accepted, CGO_TRUTH_UNKNOWN);
        ASSERT_EQ(s.submitted, CGO_TRUTH_UNKNOWN);
        ASSERT_EQ(s.applied, CGO_TRUTH_UNKNOWN);
        ASSERT_EQ(s.terminal, CGO_TRUTH_UNKNOWN);
        ASSERT_EQ(s.quiescent, CGO_TRUTH_UNKNOWN);
        ASSERT_EQ(s.effective_model.state, CGO_UNKNOWN);
        ASSERT_EQ(s.requested_model.state, CGO_UNKNOWN);
        ASSERT_EQ(s.runtime.state, CGO_UNQUALIFIED);
        ASSERT_EQ(s.storage.state, CGO_UNQUALIFIED);
        ASSERT_EQ(s.transport.state, CGO_UNQUALIFIED);
        ASSERT_EQ(s.exclusive_authority.state, CGO_UNQUALIFIED);
        ASSERT_EQ(s.job_id.state, CGO_UNKNOWN);
        ASSERT_EQ(s.attempt.state, CGO_UNKNOWN);
        ASSERT_EQ(s.source_sha256.state, CGO_UNKNOWN);
    }
_test_next:;
    return failures;
}

static int cgot_exact_objective(void)
{
    int failures = 0;
    struct cgo_snapshot s, again;
    const char *raw = "{\"id\":\"request\",\"result\":{\"goal\":{\"threadId\":\"thread\",\"objective\":\" \\u0001\\\"\\\\\\n\\b\\f\\u00e9 \"}}}";
    TEST("native observer: escaped controls and Unicode hash exact decoded bytes, replay stays unfresh") {
        ASSERT_EQ(cgot_read(raw, &s), CGA_OK);
        ASSERT_EQ(s.objective_length.value, 10);
        ASSERT_EQ(s.objective_sha256.state, CGO_KNOWN);
        ASSERT(strcmp(s.objective_sha256.value,
            "cda1504e998f9c38254d8cac0d827b8845c45ad132014ee1776e4d2800783914") == 0);
        ASSERT_EQ(cgot_read(raw, &again), CGA_OK);
        ASSERT(strcmp(s.objective_sha256.value, again.objective_sha256.value) == 0);
        ASSERT_EQ(again.freshness, CGO_FRESHNESS_UNKNOWN);
        ASSERT_EQ(again.observed_at_unix_ms.state, CGO_UNKNOWN);
    }
_test_next:;
    return failures;
}

static int cgot_bounds(void)
{
    int failures = 0;
    struct cgo_snapshot s;
    char why[160];
    const char *raw = "{\"id\":\"request\",\"result\":{\"goal\":null}}";
    const char invalid[] = { (char)0xc0, (char)0xaf };
    const char invalid_response[] = "{\"id\":\"request\",\"result\":{\"goal\":{\"threadId\":\"\xc0\xaf\"}}}";
    TEST("native observer: explicit input bounds and invalid expected UTF8 refuse") {
        ASSERT_EQ(cgo_decode_goal_get(raw, CGO_RESPONSE_CAP + 1u, "request", 7,
            "thread", 6, &s, why, sizeof(why)), CGA_INVALID);
        ASSERT_EQ(cgo_decode_goal_get(raw, strlen(raw), "request", 7,
            invalid, sizeof(invalid), &s, why, sizeof(why)), CGA_INVALID);
        ASSERT_EQ(cgo_decode_goal_get(raw, strlen(raw), "request", 0,
            "thread", 6, &s, why, sizeof(why)), CGA_INVALID);
        ASSERT_EQ(cgo_decode_goal_get(invalid_response, sizeof(invalid_response) - 1,
            "request", 7, invalid, sizeof(invalid), &s, why, sizeof(why)), CGA_INVALID);
        ASSERT_EQ(s.readback, CGO_TRUTH_UNKNOWN);
    }
_test_next:;
    return failures;
}

static int cgot_domain(void)
{
    int failures = 0;
    struct cgo_snapshot s;
    char why[160];
    struct cgo_decode_context context = { "0.160.0", "request", 7, "thread", 6 };
    const char *raw = "{\"id\":\"request\",\"result\":{}}";
    TEST("native observer: input domain and installed version are explicit gates") {
        ASSERT_EQ(cgo_decode_input_v2(CGO_NATIVE_GOAL_GET, &context, raw,
            strlen(raw), &s, why, sizeof(why)), CGA_OK);
        ASSERT_EQ(cgo_decode_input_v2(CGO_OBSERVATION_WIRE, &context, raw,
            strlen(raw), &s, why, sizeof(why)), CGA_UNSUPPORTED);
        ASSERT_EQ(s.readback, CGO_TRUTH_UNKNOWN);
        memcpy(context.protocol_version, "0.161.0", sizeof(context.protocol_version));
        ASSERT_EQ(cgo_decode_input_v2(CGO_NATIVE_GOAL_GET, &context, raw,
            strlen(raw), &s, why, sizeof(why)), CGA_UNSUPPORTED);
    }
_test_next:;
    return failures;
}

static int cgot_version_storage(void)
{
    int failures = 0;
    struct cgo_decode_context original = { "0.160.0", "request", 7, "thread", 6 };
    struct cgo_decode_context context = original;
    struct cgo_snapshot s, zero = {0};
    struct cgo_journal_pair pair, pair_zero = {0};
    const char *raw = "{\"id\":\"request\",\"result\":{}}";
    const char *request = "{\"id\":\"request\",\"method\":\"thread/goal/get\",\"params\":{\"threadId\":\"thread\"}}";
    char why[160];
    TEST("review decoder B1: version is owned bounded storage including its terminator") {
        /* A copied selection owns its version, including the final byte. */
        context.protocol_version[sizeof(context.protocol_version) - 1] = 'X';
        ASSERT_STR_EQ(original.protocol_version, "0.160.0");
        memset(&s, 0xa5, sizeof(s));
        ASSERT_EQ(cgo_decode_input_v2(CGO_NATIVE_GOAL_GET, &context, raw,
            strlen(raw), &s, why, sizeof(why)), CGA_UNSUPPORTED);
        ASSERT(!memcmp(&s, &zero, sizeof(s)));
        memset(&s, 0xa5, sizeof(s));
        ASSERT_EQ(cgo_decode_input_v3(CGO_NATIVE_GOAL_GET, &context, raw,
            strlen(raw), &s, why, sizeof(why)), CGA_UNSUPPORTED);
        ASSERT(!memcmp(&s, &zero, sizeof(s)));
        memset(&pair, 0xa5, sizeof(pair));
        ASSERT_EQ(cgo_decode_journal_pair_v1(&context, request, strlen(request),
            raw, strlen(raw), &pair, why, sizeof(why)), CGA_UNSUPPORTED);
        ASSERT(!memcmp(&pair, &pair_zero, sizeof(pair)));
    }
_test_next:;
    return failures;
}

static int cgot_strict_required(void)
{
    int failures = 0;
    struct cgo_snapshot s;
    char why[160];
    struct cgo_decode_context context = { "0.160.0", "request", 7, "thread", 6 };
    const char *partial = "{\"id\":\"request\",\"result\":{\"goal\":{\"threadId\":\"thread\"}}}";
    const char *complete = "{\"id\":\"request\",\"result\":{\"goal\":{\"threadId\":\"thread\",\"objective\":\"\",\"status\":\"active\",\"tokensUsed\":0,\"timeUsedSeconds\":0,\"createdAt\":0,\"updatedAt\":0}}}";
    TEST("native observer revision3: required installed properties refuse partial goal") {
        ASSERT_EQ(cgo_decode_input_v3(CGO_NATIVE_GOAL_GET, &context, partial,
            strlen(partial), &s, why, sizeof(why)), CGA_INVALID);
        ASSERT_EQ(s.readback, CGO_TRUTH_UNKNOWN);
        ASSERT_EQ(cgo_decode_input_v3(CGO_NATIVE_GOAL_GET, &context, complete,
            strlen(complete), &s, why, sizeof(why)), CGA_OK);
        ASSERT_EQ(s.token_budget.state, CGO_UNKNOWN);
        ASSERT_EQ(s.tokens_used.state, CGO_KNOWN);
        ASSERT_EQ(s.tokens_used.value, 0);
        ASSERT_EQ(s.objective_length.value, 0);
    }
_test_next:;
    return failures;
}

static int cgot_strict_absent(void)
{
    int failures = 0;
    struct cgo_snapshot s;
    char why[160];
    struct cgo_decode_context context = { "0.160.0", "request", 7, "thread", 6 };
    const char *raw = "{\"id\":\"request\",\"result\":{\"goal\":null}}";
    TEST("native observer revision3: explicit absent goal has no accounting or quiescence") {
        ASSERT_EQ(cgo_decode_input_v3(CGO_NATIVE_GOAL_GET, &context, raw,
            strlen(raw), &s, why, sizeof(why)), CGA_OK);
        ASSERT_EQ(s.goal_present, CGO_FALSE);
        ASSERT_EQ(s.goal_status_state, CGO_ABSENT);
        ASSERT_EQ(s.tokens_used.state, CGO_ABSENT);
        ASSERT_EQ(s.token_budget.state, CGO_ABSENT);
        ASSERT_EQ(s.objective_sha256.state, CGO_ABSENT);
        ASSERT_EQ(s.thread_id.state, CGO_UNKNOWN);
        ASSERT_EQ(s.freshness, CGO_FRESHNESS_UNKNOWN);
        ASSERT_EQ(s.terminal, CGO_TRUTH_UNKNOWN);
        ASSERT_EQ(s.quiescent, CGO_TRUTH_UNKNOWN);
    }
_test_next:;
    return failures;
}

static int cgot_entry_metadata(void)
{
    int failures = 0;
    bool explicit_entries = false;
#if defined(CGO_INPUT_CONTRACT_V2) && defined(CGO_INPUT_CONTRACT_V3) && defined(CGO_BOUND_HELPER_CONTRACT)
    explicit_entries = strcmp(CGO_INPUT_CONTRACT_V2,
        "zcl.codex_native_goal_observation.input.v2") == 0 &&
        strcmp(CGO_INPUT_CONTRACT_V3,
        "zcl.codex_native_goal_observation.input.v3") == 0 &&
        strcmp(CGO_INPUT_CONTRACT, CGO_INPUT_CONTRACT_V2) == 0 &&
        strcmp(CGO_INPUT_CONTRACT_V2, CGO_INPUT_CONTRACT_V3) != 0 &&
        strcmp(CGO_BOUND_HELPER_CONTRACT,
        "zcl.codex_native_goal_get.bound_helper.v1") == 0;
#endif
    TEST("native observer entry metadata: strict and legacy discriminators cannot be conflated") {
        ASSERT(explicit_entries);
    }
_test_next:;
    return failures;
}

static int cgot_entry_compatibility(void)
{
    int failures = 0;
    struct cgo_snapshot s;
    char why[160];
    struct cgo_decode_context context = { "0.160.0", "request", 7, "thread", 6 };
    const char *partial = "{\"id\":\"request\",\"result\":{\"goal\":{\"threadId\":\"thread\"}}}";
    TEST("native observer entry compatibility: V2 partial remains diagnostic and V3 strict never inherits it") {
        ASSERT_EQ(cgo_decode_input_v2(CGO_NATIVE_GOAL_GET, &context, partial,
            strlen(partial), &s, why, sizeof(why)), CGA_OK);
        ASSERT_EQ(s.runtime.state, CGO_UNQUALIFIED);
        ASSERT_EQ(s.tokens_used.state, CGO_UNKNOWN);
        ASSERT_EQ(cgo_decode_input_v3(CGO_NATIVE_GOAL_GET, &context, partial,
            strlen(partial), &s, why, sizeof(why)), CGA_INVALID);
        ASSERT_EQ(s.readback, CGO_TRUTH_UNKNOWN);
        ASSERT_EQ(cgo_decode_input_v3(CGO_OBSERVATION_WIRE, &context, partial,
            strlen(partial), &s, why, sizeof(why)), CGA_UNSUPPORTED);
        memcpy(context.protocol_version, "0.161.0", sizeof(context.protocol_version));
        ASSERT_EQ(cgo_decode_input_v2(CGO_NATIVE_GOAL_GET, &context, partial,
            strlen(partial), &s, why, sizeof(why)), CGA_UNSUPPORTED);
        ASSERT_EQ(cgo_decode_input_v3(CGO_NATIVE_GOAL_GET, &context, partial,
            strlen(partial), &s, why, sizeof(why)), CGA_UNSUPPORTED);
        ASSERT_EQ(s.readback, CGO_TRUTH_UNKNOWN);
        ASSERT_EQ(s.runtime.state, CGO_UNQUALIFIED);
    }
_test_next:;
    return failures;
}
static const unsigned char cgot_recorded_request[] = {
  0x7b, 0x22, 0x6a, 0x73, 0x6f, 0x6e, 0x72, 0x70, 0x63, 0x22, 0x3a, 0x22,
  0x32, 0x2e, 0x30, 0x22, 0x2c, 0x22, 0x69, 0x64, 0x22, 0x3a, 0x22, 0x67,
  0x6f, 0x61, 0x6c, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x2d, 0x31, 0x37,
  0x39, 0x31, 0x30, 0x36, 0x38, 0x36, 0x33, 0x36, 0x2d, 0x33, 0x34, 0x32,
  0x33, 0x31, 0x36, 0x37, 0x22, 0x2c, 0x22, 0x6d, 0x65, 0x74, 0x68, 0x6f,
  0x64, 0x22, 0x3a, 0x22, 0x74, 0x68, 0x72, 0x65, 0x61, 0x64, 0x2f, 0x67,
  0x6f, 0x61, 0x6c, 0x2f, 0x67, 0x65, 0x74, 0x22, 0x2c, 0x22, 0x70, 0x61,
  0x72, 0x61, 0x6d, 0x73, 0x22, 0x3a, 0x7b, 0x22, 0x74, 0x68, 0x72, 0x65,
  0x61, 0x64, 0x49, 0x64, 0x22, 0x3a, 0x22, 0x30, 0x31, 0x61, 0x30, 0x66,
  0x66, 0x36, 0x36, 0x2d, 0x33, 0x62, 0x64, 0x34, 0x2d, 0x37, 0x63, 0x66,
  0x30, 0x2d, 0x38, 0x32, 0x36, 0x63, 0x2d, 0x64, 0x36, 0x62, 0x32, 0x31,
  0x38, 0x65, 0x37, 0x65, 0x64, 0x37, 0x32, 0x22, 0x7d, 0x0a, 0x7d
};
static const unsigned int cgot_recorded_request_len = 143;
static const unsigned char cgot_recorded_response[] = {
  0x7b, 0x22, 0x69, 0x64, 0x22, 0x3a, 0x22, 0x67, 0x6f, 0x61, 0x6c, 0x73,
  0x74, 0x61, 0x74, 0x75, 0x73, 0x2d, 0x31, 0x37, 0x39, 0x31, 0x30, 0x36,
  0x38, 0x36, 0x33, 0x36, 0x2d, 0x33, 0x34, 0x32, 0x33, 0x31, 0x36, 0x37,
  0x22, 0x2c, 0x22, 0x72, 0x65, 0x73, 0x75, 0x6c, 0x74, 0x22, 0x3a, 0x7b,
  0x22, 0x67, 0x6f, 0x61, 0x6c, 0x22, 0x3a, 0x7b, 0x22, 0x74, 0x68, 0x72,
  0x65, 0x61, 0x64, 0x49, 0x64, 0x22, 0x3a, 0x22, 0x30, 0x31, 0x61, 0x30,
  0x66, 0x66, 0x36, 0x36, 0x2d, 0x33, 0x62, 0x64, 0x34, 0x2d, 0x37, 0x63,
  0x66, 0x30, 0x2d, 0x38, 0x32, 0x36, 0x63, 0x2d, 0x64, 0x36, 0x62, 0x32,
  0x31, 0x38, 0x65, 0x37, 0x65, 0x64, 0x37, 0x32, 0x22, 0x2c, 0x22, 0x6f,
  0x62, 0x6a, 0x65, 0x63, 0x74, 0x69, 0x76, 0x65, 0x22, 0x3a, 0x22, 0x49,
  0x6d, 0x70, 0x6c, 0x65, 0x6d, 0x65, 0x6e, 0x74, 0x20, 0x61, 0x20, 0x76,
  0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x2d, 0x67, 0x61, 0x74, 0x65, 0x64,
  0x20, 0x43, 0x32, 0x33, 0x20, 0x43, 0x6f, 0x64, 0x65, 0x78, 0x20, 0x6e,
  0x61, 0x74, 0x69, 0x76, 0x65, 0x2d, 0x67, 0x6f, 0x61, 0x6c, 0x20, 0x61,
  0x64, 0x61, 0x70, 0x74, 0x65, 0x72, 0x20, 0x61, 0x74, 0x20, 0x74, 0x68,
  0x65, 0x20, 0x65, 0x78, 0x69, 0x73, 0x74, 0x69, 0x6e, 0x67, 0x20, 0x77,
  0x6b, 0x72, 0x5f, 0x65, 0x78, 0x65, 0x63, 0x75, 0x74, 0x6f, 0x72, 0x5f,
  0x66, 0x6e, 0x2f, 0x4d, 0x75, 0x73, 0x65, 0x20, 0x65, 0x78, 0x65, 0x63,
  0x75, 0x74, 0x6f, 0x72, 0x20, 0x73, 0x65, 0x61, 0x6d, 0x2c, 0x20, 0x6b,
  0x65, 0x65, 0x70, 0x69, 0x6e, 0x67, 0x20, 0x65, 0x78, 0x69, 0x73, 0x74,
  0x69, 0x6e, 0x67, 0x20, 0x71, 0x75, 0x65, 0x75, 0x65, 0x2c, 0x20, 0x63,
  0x6c, 0x61, 0x69, 0x6d, 0x2c, 0x20, 0x6c, 0x65, 0x64, 0x67, 0x65, 0x72,
  0x2c, 0x20, 0x61, 0x64, 0x6d, 0x69, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x20,
  0x61, 0x6e, 0x64, 0x20, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x61, 0x74,
  0x69, 0x6f, 0x6e, 0x20, 0x6f, 0x77, 0x6e, 0x65, 0x72, 0x73, 0x2e, 0x20,
  0x55, 0x73, 0x65, 0x20, 0x74, 0x68, 0x69, 0x73, 0x20, 0x65, 0x78, 0x69,
  0x73, 0x74, 0x69, 0x6e, 0x67, 0x20, 0x67, 0x70, 0x74, 0x2d, 0x36, 0x2e,
  0x31, 0x2d, 0x73, 0x6f, 0x6c, 0x20, 0x6c, 0x6f, 0x77, 0x20, 0x73, 0x65,
  0x73, 0x73, 0x69, 0x6f, 0x6e, 0x2e, 0x20, 0x52, 0x65, 0x63, 0x6f, 0x6e,
  0x63, 0x69, 0x6c, 0x65, 0x20, 0x63, 0x68, 0x65, 0x63, 0x6b, 0x6f, 0x75,
  0x74, 0x20, 0x69, 0x6e, 0x73, 0x74, 0x72, 0x75, 0x63, 0x74, 0x69, 0x6f,
  0x6e, 0x73, 0x2c, 0x20, 0x63, 0x6c, 0x61, 0x69, 0x6d, 0x73, 0x2c, 0x20,
  0x63, 0x75, 0x72, 0x72, 0x65, 0x6e, 0x74, 0x20, 0x48, 0x45, 0x41, 0x44,
  0x20, 0x61, 0x6e, 0x64, 0x20, 0x61, 0x63, 0x74, 0x69, 0x76, 0x65, 0x20,
  0x6a, 0x6f, 0x62, 0x73, 0x3b, 0x20, 0x75, 0x73, 0x65, 0x20, 0x61, 0x6e,
  0x20, 0x69, 0x73, 0x6f, 0x6c, 0x61, 0x74, 0x65, 0x64, 0x20, 0x62, 0x72,
  0x61, 0x6e, 0x63, 0x68, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x70, 0x72, 0x65,
  0x73, 0x65, 0x72, 0x76, 0x65, 0x20, 0x51, 0x45, 0x44, 0x43, 0x2f, 0x73,
  0x68, 0x61, 0x72, 0x65, 0x64, 0x20, 0x63, 0x61, 0x70, 0x61, 0x63, 0x69,
  0x74, 0x79, 0x2e, 0x20, 0x4f, 0x77, 0x6e, 0x20, 0x6e, 0x65, 0x77, 0x20,
  0x61, 0x64, 0x61, 0x70, 0x74, 0x65, 0x72, 0x20, 0x63, 0x6f, 0x64, 0x65,
  0x2c, 0x20, 0x6d, 0x69, 0x6e, 0x69, 0x6d, 0x61, 0x6c, 0x20, 0x77, 0x6f,
  0x72, 0x6b, 0x65, 0x72, 0x20, 0x68, 0x6f, 0x6f, 0x6b, 0x73, 0x20, 0x61,
  0x6e, 0x64, 0x20, 0x65, 0x78, 0x70, 0x6c, 0x69, 0x63, 0x69, 0x74, 0x6c,
  0x79, 0x20, 0x61, 0x67, 0x72, 0x65, 0x65, 0x64, 0x20, 0x68, 0x65, 0x61,
  0x64, 0x65, 0x72, 0x73, 0x2f, 0x62, 0x75, 0x69, 0x6c, 0x64, 0x20, 0x67,
  0x6c, 0x75, 0x65, 0x2c, 0x20, 0x6e, 0x6f, 0x74, 0x20, 0x67, 0x61, 0x74,
  0x65, 0x77, 0x61, 0x79, 0x2f, 0x70, 0x72, 0x6f, 0x6a, 0x65, 0x63, 0x74,
  0x69, 0x6f, 0x6e, 0x20, 0x6f, 0x72, 0x20, 0x70, 0x65, 0x65, 0x72, 0x20,
  0x71, 0x75, 0x65, 0x75, 0x65, 0x2f, 0x66, 0x72, 0x65, 0x73, 0x68, 0x2d,
  0x63, 0x68, 0x69, 0x6c, 0x64, 0x2f, 0x6f, 0x70, 0x65, 0x72, 0x61, 0x74,
  0x69, 0x6f, 0x6e, 0x73, 0x20, 0x66, 0x69, 0x6c, 0x65, 0x73, 0x2e, 0x20,
  0x44, 0x69, 0x73, 0x63, 0x6f, 0x76, 0x65, 0x72, 0x20, 0x69, 0x6e, 0x73,
  0x74, 0x61, 0x6c, 0x6c, 0x65, 0x64, 0x20, 0x43, 0x6f, 0x64, 0x65, 0x78,
  0x20, 0x73, 0x63, 0x68, 0x65, 0x6d, 0x61, 0x73, 0x2f, 0x63, 0x61, 0x70,
  0x61, 0x62, 0x69, 0x6c, 0x69, 0x74, 0x69, 0x65, 0x73, 0x20, 0x77, 0x69,
  0x74, 0x68, 0x6f, 0x75, 0x74, 0x20, 0x63, 0x68, 0x61, 0x6e, 0x67, 0x69,
  0x6e, 0x67, 0x20, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x75, 0x72, 0x61,
  0x74, 0x69, 0x6f, 0x6e, 0x2e, 0x20, 0x50, 0x72, 0x65, 0x73, 0x65, 0x72,
  0x76, 0x65, 0x20, 0x65, 0x78, 0x61, 0x63, 0x74, 0x20, 0x67, 0x6f, 0x61,
  0x6c, 0x20, 0x62, 0x79, 0x74, 0x65, 0x73, 0x2c, 0x20, 0x65, 0x78, 0x65,
  0x63, 0x75, 0x74, 0x61, 0x62, 0x6c, 0x65, 0x2f, 0x65, 0x6e, 0x76, 0x69,
  0x72, 0x6f, 0x6e, 0x6d, 0x65, 0x6e, 0x74, 0x2f, 0x6d, 0x6f, 0x64, 0x65,
  0x6c, 0x2f, 0x65, 0x66, 0x66, 0x6f, 0x72, 0x74, 0x20, 0x61, 0x6e, 0x64,
  0x20, 0x6e, 0x61, 0x74, 0x69, 0x76, 0x65, 0x20, 0x74, 0x68, 0x72, 0x65,
  0x61, 0x64, 0x2f, 0x74, 0x75, 0x72, 0x6e, 0x20, 0x69, 0x64, 0x65, 0x6e,
  0x74, 0x69, 0x74, 0x79, 0x2e, 0x20, 0x4a, 0x6f, 0x75, 0x72, 0x6e, 0x61,
  0x6c, 0x20, 0x69, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x20, 0x62, 0x65, 0x66,
  0x6f, 0x72, 0x65, 0x20, 0x65, 0x66, 0x66, 0x65, 0x63, 0x74, 0x66, 0x75,
  0x6c, 0x20, 0x73, 0x75, 0x62, 0x6d, 0x69, 0x73, 0x73, 0x69, 0x6f, 0x6e,
  0x2c, 0x20, 0x67, 0x69, 0x76, 0x65, 0x20, 0x63, 0x6f, 0x6d, 0x6d, 0x61,
  0x6e, 0x64, 0x73, 0x20, 0x73, 0x74, 0x61, 0x62, 0x6c, 0x65, 0x20, 0x49,
  0x44, 0x73, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x65, 0x78, 0x70, 0x65, 0x63,
  0x74, 0x65, 0x64, 0x20, 0x74, 0x61, 0x72, 0x67, 0x65, 0x74, 0x2f, 0x72,
  0x65, 0x76, 0x69, 0x73, 0x69, 0x6f, 0x6e, 0x2c, 0x20, 0x64, 0x69, 0x73,
  0x74, 0x69, 0x6e, 0x67, 0x75, 0x69, 0x73, 0x68, 0x20, 0x61, 0x63, 0x63,
  0x65, 0x70, 0x74, 0x65, 0x64, 0x2f, 0x61, 0x70, 0x70, 0x6c, 0x69, 0x65,
  0x64, 0x2f, 0x72, 0x65, 0x61, 0x64, 0x62, 0x61, 0x63, 0x6b, 0x2f, 0x74,
  0x65, 0x72, 0x6d, 0x69, 0x6e, 0x61, 0x6c, 0x20, 0x73, 0x74, 0x61, 0x74,
  0x65, 0x73, 0x2c, 0x20, 0x72, 0x65, 0x66, 0x75, 0x73, 0x65, 0x20, 0x63,
  0x6f, 0x6e, 0x66, 0x6c, 0x69, 0x63, 0x74, 0x69, 0x6e, 0x67, 0x20, 0x64,
  0x75, 0x70, 0x6c, 0x69, 0x63, 0x61, 0x74, 0x65, 0x73, 0x20, 0x61, 0x6e,
  0x64, 0x20, 0x72, 0x65, 0x63, 0x6f, 0x6e, 0x63, 0x69, 0x6c, 0x65, 0x20,
  0x75, 0x6e, 0x63, 0x65, 0x72, 0x74, 0x61, 0x69, 0x6e, 0x20, 0x73, 0x65,
  0x6e, 0x64, 0x73, 0x20, 0x62, 0x65, 0x66, 0x6f, 0x72, 0x65, 0x20, 0x72,
  0x65, 0x74, 0x72, 0x79, 0x2e, 0x20, 0x55, 0x73, 0x65, 0x20, 0x6e, 0x61,
  0x74, 0x69, 0x76, 0x65, 0x20, 0x47, 0x6f, 0x61, 0x6c, 0x73, 0x20, 0x6f,
  0x6e, 0x6c, 0x79, 0x20, 0x77, 0x68, 0x65, 0x6e, 0x20, 0x73, 0x75, 0x70,
  0x70, 0x6f, 0x72, 0x74, 0x65, 0x64, 0x3b, 0x20, 0x6e, 0x65, 0x76, 0x65,
  0x72, 0x20, 0x65, 0x6d, 0x75, 0x6c, 0x61, 0x74, 0x65, 0x20, 0x74, 0x68,
  0x65, 0x6d, 0x20, 0x77, 0x69, 0x74, 0x68, 0x20, 0x72, 0x65, 0x70, 0x65,
  0x61, 0x74, 0x65, 0x64, 0x20, 0x63, 0x6f, 0x6e, 0x74, 0x69, 0x6e, 0x75,
  0x65, 0x20, 0x70, 0x72, 0x6f, 0x6d, 0x70, 0x74, 0x73, 0x2e, 0x20, 0x43,
  0x6c, 0x65, 0x61, 0x72, 0x69, 0x6e, 0x67, 0x20, 0x61, 0x20, 0x67, 0x6f,
  0x61, 0x6c, 0x2c, 0x20, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x72, 0x75, 0x70,
  0x74, 0x69, 0x6e, 0x67, 0x20, 0x61, 0x20, 0x74, 0x75, 0x72, 0x6e, 0x20,
  0x61, 0x6e, 0x64, 0x20, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x72, 0x6d, 0x65,
  0x64, 0x20, 0x70, 0x72, 0x6f, 0x63, 0x65, 0x73, 0x73, 0x20, 0x71, 0x75,
  0x69, 0x65, 0x73, 0x63, 0x65, 0x6e, 0x63, 0x65, 0x20, 0x61, 0x72, 0x65,
  0x20, 0x64, 0x69, 0x73, 0x74, 0x69, 0x6e, 0x63, 0x74, 0x2e, 0x20, 0x42,
  0x65, 0x67, 0x69, 0x6e, 0x20, 0x77, 0x69, 0x74, 0x68, 0x20, 0x64, 0x65,
  0x74, 0x65, 0x72, 0x6d, 0x69, 0x6e, 0x69, 0x73, 0x74, 0x69, 0x63, 0x20,
  0x66, 0x61, 0x6b, 0x65, 0x2d, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x63, 0x6f,
  0x6c, 0x20, 0x74, 0x65, 0x73, 0x74, 0x73, 0x20, 0x61, 0x6e, 0x64, 0x20,
  0x61, 0x64, 0x61, 0x70, 0x74, 0x65, 0x72, 0x20, 0x63, 0x6f, 0x6e, 0x74,
  0x72, 0x61, 0x63, 0x74, 0x3b, 0x20, 0x64, 0x6f, 0x20, 0x6e, 0x6f, 0x74,
  0x20, 0x73, 0x74, 0x61, 0x72, 0x74, 0x20, 0x6e, 0x65, 0x73, 0x74, 0x65,
  0x64, 0x20, 0x70, 0x61, 0x69, 0x64, 0x20, 0x6d, 0x6f, 0x64, 0x65, 0x6c,
  0x20, 0x77, 0x6f, 0x72, 0x6b, 0x65, 0x72, 0x73, 0x20, 0x77, 0x69, 0x74,
  0x68, 0x6f, 0x75, 0x74, 0x20, 0x61, 0x70, 0x70, 0x72, 0x6f, 0x76, 0x61,
  0x6c, 0x2e, 0x20, 0x4e, 0x6f, 0x20, 0x6e, 0x65, 0x77, 0x20, 0x73, 0x63,
  0x68, 0x65, 0x64, 0x75, 0x6c, 0x65, 0x72, 0x2c, 0x20, 0x63, 0x72, 0x65,
  0x64, 0x65, 0x6e, 0x74, 0x69, 0x61, 0x6c, 0x73, 0x2c, 0x20, 0x69, 0x6e,
  0x73, 0x74, 0x61, 0x6c, 0x6c, 0x73, 0x2c, 0x20, 0x6c, 0x69, 0x73, 0x74,
  0x65, 0x6e, 0x65, 0x72, 0x73, 0x2c, 0x20, 0x73, 0x65, 0x63, 0x75, 0x72,
  0x69, 0x74, 0x79, 0x20, 0x63, 0x68, 0x61, 0x6e, 0x67, 0x65, 0x73, 0x2c,
  0x20, 0x75, 0x6e, 0x61, 0x70, 0x70, 0x72, 0x6f, 0x76, 0x65, 0x64, 0x20,
  0x63, 0x6f, 0x72, 0x65, 0x20, 0x75, 0x6e, 0x73, 0x65, 0x61, 0x6c, 0x2c,
  0x20, 0x67, 0x61, 0x74, 0x65, 0x20, 0x62, 0x79, 0x70, 0x61, 0x73, 0x73,
  0x2c, 0x20, 0x6d, 0x65, 0x72, 0x67, 0x65, 0x20, 0x6f, 0x72, 0x20, 0x64,
  0x65, 0x70, 0x6c, 0x6f, 0x79, 0x6d, 0x65, 0x6e, 0x74, 0x2e, 0x20, 0x52,
  0x65, 0x74, 0x75, 0x72, 0x6e, 0x20, 0x61, 0x20, 0x72, 0x65, 0x76, 0x69,
  0x65, 0x77, 0x61, 0x62, 0x6c, 0x65, 0x20, 0x70, 0x61, 0x74, 0x63, 0x68,
  0x20, 0x61, 0x6e, 0x64, 0x20, 0x68, 0x6f, 0x6e, 0x65, 0x73, 0x74, 0x20,
  0x63, 0x61, 0x70, 0x61, 0x62, 0x69, 0x6c, 0x69, 0x74, 0x79, 0x2f, 0x72,
  0x65, 0x63, 0x6f, 0x76, 0x65, 0x72, 0x79, 0x2f, 0x74, 0x65, 0x73, 0x74,
  0x20, 0x65, 0x76, 0x69, 0x64, 0x65, 0x6e, 0x63, 0x65, 0x2e, 0x22, 0x2c,
  0x22, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x22, 0x3a, 0x22, 0x62, 0x6c,
  0x6f, 0x63, 0x6b, 0x65, 0x64, 0x22, 0x2c, 0x22, 0x74, 0x6f, 0x6b, 0x65,
  0x6e, 0x42, 0x75, 0x64, 0x67, 0x65, 0x74, 0x22, 0x3a, 0x31, 0x32, 0x30,
  0x30, 0x30, 0x30, 0x30, 0x2c, 0x22, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x73,
  0x55, 0x73, 0x65, 0x64, 0x22, 0x3a, 0x31, 0x30, 0x34, 0x37, 0x33, 0x38,
  0x36, 0x2c, 0x22, 0x74, 0x69, 0x6d, 0x65, 0x55, 0x73, 0x65, 0x64, 0x53,
  0x65, 0x63, 0x6f, 0x6e, 0x64, 0x73, 0x22, 0x3a, 0x39, 0x37, 0x31, 0x30,
  0x2c, 0x22, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x64, 0x41, 0x74, 0x22,
  0x3a, 0x31, 0x37, 0x39, 0x31, 0x30, 0x35, 0x31, 0x33, 0x30, 0x31, 0x2c,
  0x22, 0x75, 0x70, 0x64, 0x61, 0x74, 0x65, 0x64, 0x41, 0x74, 0x22, 0x3a,
  0x31, 0x37, 0x39, 0x31, 0x30, 0x36, 0x37, 0x38, 0x30, 0x31, 0x7d, 0x7d,
  0x7d
};
static const unsigned int cgot_recorded_response_len = 1657;

static int cgot_recorded_pair(void)
{
    int failures = 0;
    struct cgo_decode_context c = { "0.160.0", "goalstatus-1791068636-3423167", 29,
        "01a0ff66-3bd4-7cf0-826c-d6b218e7ed72", 36 };
    c.request_length = strlen(c.request_id);
    struct cgo_journal_pair p;
    char why[160];
    TEST("journal pair: actual retained native report is historical correlation only") {
        ASSERT_EQ(cgo_decode_journal_pair_v1(&c, (const char *)cgot_recorded_request,
            cgot_recorded_request_len, (const char *)cgot_recorded_response,
            cgot_recorded_response_len, &p, why, sizeof(why)), CGA_OK);
        ASSERT(!strcmp(p.request_sha256.value,
            "692832c9b0d2ce02f826b745df87ff3c7b1e7729d29cdc94489b4deac06d0061"));
        ASSERT(!strcmp(p.response_sha256.value,
            "6d36eef6d63d4f80b00d3b67ba5214d83375f44dd520f7cc28afadbddefda4bc"));
        ASSERT_EQ(p.observation.goal_status, CGA_BLOCKED);
        ASSERT_EQ(p.observation.tokens_used.value, 1047386);
        ASSERT_EQ(p.observation.token_budget.value, 1200000);
        ASSERT_EQ(p.observation.runtime.state, CGO_UNQUALIFIED);
        ASSERT_EQ(p.observation.freshness, CGO_FRESHNESS_UNKNOWN);
        ASSERT_EQ(p.observation.accepted, CGO_TRUTH_UNKNOWN);
        ASSERT_EQ(p.observation.source_sha256.state, CGO_UNKNOWN);
        c.request_id = "wrong-key"; c.request_length = 9;
        ASSERT_EQ(cgo_decode_journal_pair_v1(&c, (const char *)cgot_recorded_request,
            cgot_recorded_request_len, (const char *)cgot_recorded_response,
            cgot_recorded_response_len, &p, why, sizeof(why)), CGA_INVALID);
        ASSERT_EQ(p.request_sha256.state, CGO_UNKNOWN);
        ASSERT_EQ(p.response_sha256.value[0], 0);
        ASSERT_EQ(p.observation.tokens_used.state, CGO_UNKNOWN);
    }
_test_next:;
    return failures;
}

static int cgot_pair_requests(void)
{
    int failures = 0;
    struct cgo_decode_context c = { "0.160.0", "request", 7, "thread", 6 };
    const char *bad[] = {
        "{\"id\":\"request\",\"method\":\"thread/goal/set\",\"params\":{\"threadId\":\"thread\"}}",
        "{\"id\":\"request\",\"method\":\"turn/interrupt\",\"params\":{\"threadId\":\"thread\"}}",
        "{\"id\":\"wrong\",\"method\":\"thread/goal/get\",\"params\":{\"threadId\":\"thread\"}}",
        "{\"id\":\"request\",\"method\":\"thread/goal/get\",\"params\":{\"threadId\":\"wrong\"}}",
        "{\"id\":\"request\",\"method\":\"thread/goal/get\",\"params\":{\"threadId\":\"thread\",\"x\":0}}",
        "{\"id\":\"request\",\"method\":\"thread/goal/get\",\"params\":{\"threadId\":\"thread\",\"threadId\":\"thread\"}}",
        "{\"id\":\"request\",\"id\":\"request\",\"method\":\"thread/goal/get\",\"params\":{\"threadId\":\"thread\"}}",
        "{\"id\":\"request\",\"method\":\"thread/goal/get\",\"params\":{\"threadId\":\"thread\"},\"extra\":0}",
        "{\"jsonrpc\":\"1.0\",\"id\":\"request\",\"method\":\"thread/goal/get\",\"params\":{\"threadId\":\"thread\"}}",
        "{\"id\":7,\"method\":\"thread/goal/get\",\"params\":{\"threadId\":\"thread\"}}",
        "{\"id\":\"request\",\"method\":\"thread/goal/get\",\"params\":{\"threadId\":null}}",
        "{\"id\":\"request\",\"method\":\"thread/goal/get\",\"params\":{\"threadId\":\"\\u0000\"}}",
        "{\"id\":\"request\",\"method\":\"thread/goal/get\",\"params\":{\"threadId\":\"\\ud800\"}}",
        "{\"id\":\"request\",\"method\":\"thread/goal/get\",\"params\":{\"threadId\":\"\xc0\xaf\"}}",
        "{\"id\":\"request\",\"method\":\"thread/goal/get\",\"params\":{\"threadId\":9223372036854775808}}"
    };
    struct cgo_journal_pair p, zero = {0};
    char why[160];
    const char *response = "{\"id\":\"request\",\"result\":{}}";
    TEST("journal pair: derived control methods, correlation, keys and Unicode refuse") {
        for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
            memset(&p, 0xa5, sizeof(p));
            ASSERT_EQ(cgo_decode_journal_pair_v1(&c, bad[i], strlen(bad[i]),
                response, strlen(response), &p, why, sizeof(why)), CGA_INVALID);
            ASSERT(!memcmp(&p, &zero, sizeof(p)));
        }
    }
_test_next:;
    return failures;
}

static int cgot_pair_boundaries(void)
{
    int failures = 0;
    struct cgo_decode_context c = { "0.160.0", "request", 7, "thread", 6 };
    const char *request = "{\"id\":\"request\",\"method\":\"thread/goal/get\",\"params\":{\"threadId\":\"thread\"}}";
    const char *bad[] = {
        "{\"id\":\"wrong\",\"result\":{}}",
        "{\"id\":\"request\",\"error\":{\"code\":1}}",
        "{\"id\":\"request\",\"result\":{},\"error\":null}",
        "{\"id\":\"request\",\"result\":{\"goal\":{\"threadId\":\"thread\"}}}",
        "{\"id\":\"request\",\"result\":{}} trailing"
        , "{\"id\":\"request\",\"id\":\"request\",\"result\":{}}"
        , "{\"id\":\"request\",\"result\":{\"unknown\":true}}"
        , "{\"id\":\"request\",\"result\":{\"goal\":{\"threadId\":\"wrong\",\"objective\":\"x\",\"status\":\"active\",\"tokensUsed\":0,\"timeUsedSeconds\":0,\"createdAt\":1,\"updatedAt\":1}}}"
        , "{\"id\":\"request\",\"result\":{\"goal\":{\"threadId\":\"thread\",\"objective\":\"\\ud800\",\"status\":\"active\",\"tokensUsed\":0,\"timeUsedSeconds\":0,\"createdAt\":1,\"updatedAt\":1}}}"
    };
    struct cgo_journal_pair p, zero = {0};
    char why[160];
    TEST("journal pair: derived response and length failures clear entire result") {
        for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
            memset(&p, 0xa5, sizeof(p));
            ASSERT_EQ(cgo_decode_journal_pair_v1(&c, request, strlen(request),
                bad[i], strlen(bad[i]), &p, why, sizeof(why)), CGA_INVALID);
            ASSERT(!memcmp(&p, &zero, sizeof(p)));
        }
        ASSERT_EQ(cgo_decode_journal_pair_v1(&c, request, strlen(request) + 1,
            bad[0], strlen(bad[0]), &p, why, sizeof(why)), CGA_INVALID);
        ASSERT_EQ(cgo_decode_journal_pair_v1(&c, request, strlen(request) - 1,
            bad[0], strlen(bad[0]), &p, why, sizeof(why)), CGA_INVALID);
        ASSERT_EQ(cgo_decode_journal_pair_v1(&c, request, CGO_RESPONSE_CAP + 1,
            bad[0], strlen(bad[0]), &p, why, sizeof(why)), CGA_INVALID);
        const char *valid = "{\"id\":\"request\",\"result\":{}}";
        ASSERT_EQ(cgo_decode_journal_pair_v1(&c, request, strlen(request),
            valid, strlen(valid) + 1, &p, why, sizeof(why)), CGA_INVALID);
        ASSERT_EQ(cgo_decode_journal_pair_v1(&c, request, strlen(request),
            valid, strlen(valid) - 1, &p, why, sizeof(why)), CGA_INVALID);
        memcpy(c.protocol_version, "0.161.0", sizeof(c.protocol_version));
        ASSERT_EQ(cgo_decode_journal_pair_v1(&c, request, strlen(request),
            bad[0], strlen(bad[0]), &p, why, sizeof(why)), CGA_UNSUPPORTED);
        ASSERT(!memcmp(&p, &zero, sizeof(p)));
    }
_test_next:;
    return failures;
}

static int cgot_pair_semantics(void)
{
    int failures = 0;
    struct cgo_decode_context c = { "0.160.0", "request", 7, "t\xc3\xa9", 3 };
    const char *request = "{\"id\":\"request\",\"method\":\"thread/goal/get\",\"params\":{\"threadId\":\"t\\u00e9\"}}";
    const char *responses[] = {
        "{\"id\":\"request\",\"result\":{}}",
        "{\"id\":\"request\",\"result\":{\"goal\":null}}",
        "{\"id\":\"request\",\"result\":{\"goal\":{\"threadId\":\"t\\u00e9\",\"objective\":\"\\u0001\\u00e9\",\"status\":\"active\",\"tokensUsed\":0,\"timeUsedSeconds\":0,\"createdAt\":0,\"updatedAt\":0}}}",
        "{\"id\":\"request\",\"result\":{\"goal\":{\"threadId\":\"t\\u00e9\",\"objective\":\"\\u0001\\u00e9\",\"status\":\"active\",\"tokenBudget\":null,\"tokensUsed\":0,\"timeUsedSeconds\":0,\"createdAt\":0,\"updatedAt\":0}}}",
        "{\"id\":\"request\",\"result\":{\"goal\":{\"threadId\":\"t\\u00e9\",\"objective\":\"\\u0001\\u00e9\",\"status\":\"active\",\"tokenBudget\":0,\"tokensUsed\":0,\"timeUsedSeconds\":0,\"createdAt\":0,\"updatedAt\":0}}}"
    };
    const enum cgo_state budgets[] = { CGO_UNKNOWN, CGO_ABSENT, CGO_UNKNOWN,
        CGO_ABSENT, CGO_KNOWN };
    struct cgo_journal_pair p;
    char why[160];
    TEST("journal pair: derived Unicode and missing/null/zero states stay lossless") {
        for (size_t i = 0; i < sizeof(responses) / sizeof(responses[0]); i++) {
            ASSERT_EQ(cgo_decode_journal_pair_v1(&c, request, strlen(request),
                responses[i], strlen(responses[i]), &p, why, sizeof(why)), CGA_OK);
            ASSERT_EQ(p.observation.token_budget.state, budgets[i]);
            ASSERT_EQ(p.observation.readback, CGO_TRUE);
            ASSERT_EQ(p.observation.runtime.state, CGO_UNQUALIFIED);
        }
        ASSERT_EQ(p.observation.objective_length.value, 3);
        ASSERT_STR_EQ(p.observation.thread_id.value, "t\xc3\xa9");
        ASSERT_EQ(p.observation.tokens_used.value, 0);
        c.thread_length = 2; /* split UTF-8 codepoint is not a selection */
        ASSERT_EQ(cgo_decode_journal_pair_v1(&c, request, strlen(request),
            responses[0], strlen(responses[0]), &p, why, sizeof(why)), CGA_INVALID);
    }
_test_next:;
    return failures;
}

/* End-to-end refusals: wire and decoded-objective UTF-8 guards overlap.
 * These cases do not independently witness deletion of either guard. */
static int cgot_review_invalid_utf8(const char *objective)
{
    int failures = 0; struct cgo_snapshot snapshot, zero = {0}; char raw[256];
    int length = snprintf(raw, sizeof(raw), "{\"id\":\"request\",\"result\":{\"goal\":{\"threadId\":\"thread\",\"objective\":\"%s\"}}}", objective);
    TEST("D3: invalid objective UTF-8 refuses and clears the entire snapshot") {
        ASSERT(length > 0 && (size_t)length < sizeof(raw));
        memset(&snapshot, 0xa5, sizeof(snapshot));
        ASSERT_EQ(cgot_read(raw, &snapshot), CGA_INVALID);
        ASSERT(!memcmp(&snapshot, &zero, sizeof(snapshot)));
        PASS();
    }
_test_next:;
    return failures;
}
static int cgot_review_utf8(void)
{
    const char *invalid[] = {"\x80", "\xc0\xaf", "\xed\xa0\x80", "\xe2\x82", "\xf4\x90\x80\x80"};
    int failures = 0;
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i)
        failures += cgot_review_invalid_utf8(invalid[i]);
    return failures;
}
/* Parser escape/surrogate/NUL refusals and observer duplicate-key refusals;
 * parser refusals are not deletion witnesses for an observer escape guard. */
static int cgot_review_escape_refusal(const char *raw)
{
    int failures = 0; struct cgo_snapshot snapshot, zero = {0};
    TEST("D4: Unicode escape aliases and malformed escapes refuse with no partial facts") {
        memset(&snapshot, 0xa5, sizeof(snapshot));
        ASSERT_EQ(cgot_read(raw, &snapshot), CGA_INVALID);
        ASSERT(!memcmp(&snapshot, &zero, sizeof(snapshot)));
        PASS();
    }
_test_next:;
    return failures;
}
static int cgot_review_escapes(void)
{
    const char *invalid[] = {
        "{\"id\":\"request\",\"\\u0069d\":\"request\",\"result\":{}}",
        "{\"id\":\"request\",\"result\":{\"goal\":{\"threadId\":\"thread\",\"objective\":\"x\",\"obj\\u0065ctive\":\"x\"}}}",
        "{\"id\":\"request\",\"result\":{\"goal\":{\"threadId\":\"thread\",\"objective\":\"\\u12",
        "{\"id\":\"request\",\"result\":{\"goal\":{\"threadId\":\"thread\",\"objective\":\"\\u12xz\"}}}",
        "{\"id\":\"request\",\"result\":{\"goal\":{\"threadId\":\"thread\",\"objective\":\"\\ud800\"}}}",
        "{\"id\":\"request\",\"result\":{\"goal\":{\"threadId\":\"thread\",\"objective\":\"\\udc00\"}}}",
        "{\"id\":\"request\",\"result\":{\"goal\":{\"threadId\":\"thread\",\"objective\":\"\\u0000\"}}}"
    };
    int failures = 0;
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i)
        failures += cgot_review_escape_refusal(invalid[i]);
    struct cgo_snapshot literal, escaped;
    const char *raw = "{\"id\":\"request\",\"result\":{\"goal\":{\"threadId\":\"thread\",\"objective\":\"\xc3\xa9\xf0\x9f\x98\x80\"}}}";
    const char *encoded = "{\"id\":\"request\",\"result\":{\"goal\":{\"threadId\":\"thread\",\"objective\":\"\\u00e9\\ud83d\\ude00\"}}}";
    TEST("D3/D4: raw Unicode and escaped scalars have identical known byte lengths and hashes") {
        ASSERT_EQ(cgot_read(raw, &literal), CGA_OK);
        ASSERT_EQ(cgot_read(encoded, &escaped), CGA_OK);
        ASSERT_EQ(literal.objective_length.state, CGO_KNOWN);
        ASSERT_EQ(literal.objective_sha256.state, CGO_KNOWN);
        ASSERT_EQ(literal.objective_length.value, 6);
        ASSERT_EQ(escaped.objective_length.state, CGO_KNOWN);
        ASSERT_EQ(escaped.objective_sha256.state, CGO_KNOWN);
        ASSERT_EQ(escaped.objective_length.value, literal.objective_length.value);
        ASSERT_STR_EQ(escaped.objective_sha256.value, literal.objective_sha256.value);
        PASS();
    }
_test_next:;
    return failures;
}

int cgo_decoder_tests(void);
int cgo_decoder_tests(void)
{
    return cgot_missing_null_zero() + cgot_refusals() + cgot_overflow() +
        cgot_reported_only() + cgot_exact_objective() + cgot_bounds() +
        cgot_domain() + cgot_version_storage() + cgot_strict_required() + cgot_strict_absent() +
        cgot_entry_metadata() + cgot_entry_compatibility() +
        cgot_recorded_pair() + cgot_pair_requests() + cgot_pair_boundaries() +
        cgot_pair_semantics() + cgot_review_utf8() + cgot_review_escapes();
}
