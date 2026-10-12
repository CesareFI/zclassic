/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: relevance-free, source-bound retrieval heuristic projection. */
#include "command/native_command.h"
#include "command/native_dev_retrieval_stream.h"

#include "base/hex.h"
#include "base/log_macros.h"
#include "json/json.h"
#include "retrieval/retrieval_experiment.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define RXC_TAG "native.dev.retrieval.experiment"

#if defined(ZCL_DEV_BUILD) || defined(ZCL_TESTING)

static void rxc_fail(struct zcl_command_reply *reply, const char *code,
                     const char *phase, const char *message,
                     const char *evidence)
{
    LOG_ERROR(RXC_TAG, "%s: %s (%s)", code, message,
              evidence ? evidence : "");
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                           ZCL_COMMAND_EXIT_INVALID, code, phase, false, false,
                           message, evidence ? evidence : "");
}

static bool rxc_root(const struct json_value *input, const char *key,
                     uint8_t out[32])
{
    const struct json_value *value = json_get(input, key);
    const char *hex = value && value->type == JSON_STR
        ? json_get_str(value) : NULL;
    if (!hex || !zcl_hex_decode_lower(hex, out, 32u)) return false;
    uint8_t aggregate = 0;
    for (size_t i = 0; i < 32u; i++) aggregate |= out[i];
    return aggregate != 0;
}

static bool rxc_profile(const struct json_value *input,
                        struct zcl_retrieval_profile_v1 *out)
{
    const struct json_value *value = json_get(input, "profile_hex");
    const char *hex = value && value->type == JSON_STR
        ? json_get_str(value) : NULL;
    uint8_t wire[ZCL_RETRIEVAL_PROFILE_WIRE_BYTES];
    return hex && zcl_hex_decode_lower(hex, wire, sizeof(wire)) &&
        zcl_retrieval_profile_parse(wire, sizeof(wire), out) ==
            ZCL_RETRIEVAL_EXPERIMENT_OK;
}

static bool rxc_push_rows(
    struct json_value *object,
    const struct zcl_retrieval_ranked_file *rows, size_t count)
{
    struct json_value ranked;
    json_init(&ranked);
    json_set_array(&ranked);
    size_t displayed = count < ZCL_RETRIEVAL_EXPERIMENT_WINDOW
        ? count : ZCL_RETRIEVAL_EXPERIMENT_WINDOW;
    bool ok = true;
    for (size_t i = 0; i < displayed && ok; i++) {
        struct json_value row;
        json_init(&row);
        json_set_object(&row);
        ok = json_push_kv_int(&row, "rank", (int64_t)i + 1) &&
            json_push_kv_str(&row, "path", rows[i].path) &&
            rows[i].context_bytes <= INT64_MAX &&
            json_push_kv_int(&row, "context_bytes",
                             (int64_t)rows[i].context_bytes) &&
            json_push_back(&ranked, &row);
        json_free(&row);
    }
    if (ok) ok = json_push_kv_int(object, "displayed_files",
                                  (int64_t)displayed) &&
                 json_push_kv(object, "ranking", &ranked);
    json_free(&ranked);
    return ok;
}

struct rxc_run {
    uint8_t study_root[32], preregistration_root[32], evaluator_root[32];
    struct zcl_retrieval_profile_v1 profile;
    struct zcl_native_dev_retrieval_snapshot snapshot;
    uint8_t recomputed_bm25[32];
    struct zcl_retrieval_feature_snapshot_v1 feature_snapshot;
    struct zcl_retrieval_feature_row_v1
        feature_rows[ZCL_RETRIEVAL_EVAL_RANK_MAX];
    struct zcl_retrieval_ranked_file
        candidate[ZCL_RETRIEVAL_EVAL_RANK_MAX];
    struct zcl_retrieval_profile_report report;
    uint8_t candidate_root[32], feature_snapshot_root[32], profile_root[32];
    uint8_t proposal_root[32];
};

static bool rxc_parse_input(const struct zcl_command_request *request,
                            struct zcl_command_reply *reply,
                            struct rxc_run *run)
{
    if (!request || !request->input || request->input->type != JSON_OBJ) {
        rxc_fail(reply, "INVALID_INPUT", "input",
                 "experiment input must be one JSON object", "input");
        return false;
    }
    if (!rxc_root(request->input, "study_root", run->study_root) ||
        !rxc_root(request->input, "preregistration_root",
                  run->preregistration_root) ||
        !rxc_root(request->input, "evaluator_root", run->evaluator_root)) {
        rxc_fail(reply, "INVALID_SCIENCE_ROOT", "bind",
                 "study, preregistration, and evaluator roots must be "
                 "nonzero lowercase roots", "science_roots");
        return false;
    }
    if (!rxc_profile(request->input, &run->profile)) {
        rxc_fail(reply, "INVALID_PROFILE", "input",
                 "profile_hex must be one canonical 56-byte retrieval "
                 "profile encoded as 112 lowercase hex characters",
                 "profile_hex");
        return false;
    }
    if (run->profile.feature_mask != ZCL_RETRIEVAL_FEATURE_BIT(
            ZCL_RETRIEVAL_FEATURE_CONTEXT_BYTES)) {
        rxc_fail(reply, "PROJECTION_REFUSED", "project",
                 zcl_retrieval_experiment_error_string(
                     ZCL_RETRIEVAL_EXPERIMENT_INCOMPLETE),
                 "context_bytes_only");
        return false;
    }
    return true;
}

/* Recomputes the source-bound BM25 baseline and checks it against the
 * frozen ranking root. */
static bool rxc_load_baseline(const struct zcl_command_request *request,
                              struct zcl_command_reply *reply,
                              struct rxc_run *run)
{
    struct zcl_native_dev_retrieval_snapshot *snapshot = &run->snapshot;
    char error_code[64], error_message[256];
    int rc = zcl_native_dev_retrieval_snapshot_compute(
        request->input, snapshot, error_code, sizeof(error_code),
        error_message, sizeof(error_message));
    if (rc != ZCL_COMMAND_EXIT_OK) {
        rxc_fail(reply, error_code[0] ? error_code : "RANKING_FAILED",
                 "rank", error_message[0] ? error_message
                                            : "source-bound baseline recomputation failed",
                 "generation_joined_baseline");
        return false;
    }
    bool rooted = zcl_retrieval_ranked_files_root(
            snapshot->bm25.rows, snapshot->bm25.count,
            snapshot->bm25.complete, run->recomputed_bm25);
    if (!rooted || memcmp(run->recomputed_bm25, snapshot->bm25_ranking_root,
                           32u) != 0) {
        rxc_fail(reply, "RANKING_ROOT_RECOMPUTE_FAILED", "bind",
                 "snapshot rows do not reproduce the frozen BM25 root",
                 "ranked_files_root_v1");
        return false;
    }
    return true;
}

/* Extracts the feature snapshot and projects the candidate ranking. */
static bool rxc_project(struct zcl_command_reply *reply, struct rxc_run *run)
{
    const struct zcl_native_dev_retrieval_snapshot *snapshot = &run->snapshot;
    enum zcl_retrieval_experiment_error extracted =
        zcl_retrieval_context_feature_snapshot(
            snapshot->codeindex_source_root,
            snapshot->retrieval_projection_root, snapshot->query,
            snapshot->bm25.rows, snapshot->bm25.count, snapshot->bm25.complete,
            &run->feature_snapshot, run->feature_rows,
            ZCL_RETRIEVAL_EVAL_RANK_MAX);
    if (extracted != ZCL_RETRIEVAL_EXPERIMENT_OK) {
        rxc_fail(reply, "FEATURE_SNAPSHOT_REFUSED", "extract",
                 zcl_retrieval_experiment_error_string(extracted),
                 "context_bytes_only");
        return false;
    }
    size_t indices[ZCL_RETRIEVAL_EVAL_RANK_MAX];
    enum zcl_retrieval_experiment_error projected =
        zcl_retrieval_profile_project(
            &run->profile, &run->feature_snapshot, run->feature_rows, indices,
            ZCL_RETRIEVAL_EVAL_RANK_MAX, &run->report);
    if (projected != ZCL_RETRIEVAL_EXPERIMENT_OK) {
        rxc_fail(reply, "PROJECTION_REFUSED", "project",
                 zcl_retrieval_experiment_error_string(projected),
                 projected == ZCL_RETRIEVAL_EXPERIMENT_INCOMPLETE
                    ? "context_bytes_only"
                    : ZCL_RETRIEVAL_PROFILE_ALGORITHM);
        return false;
    }
    for (size_t i = 0; i < run->report.ranked_count; i++)
        run->candidate[i] = snapshot->bm25.rows[indices[i]];
    return true;
}

/* Recomputes the candidate, profile, and feature roots and seals the
 * proposal input root over them. */
static bool rxc_roots_reproduce(struct rxc_run *run)
{
    const struct zcl_retrieval_profile_report *report = &run->report;
    return zcl_retrieval_ranked_files_root(
            run->candidate, report->ranked_count,
            run->snapshot.bm25.complete, run->candidate_root) &&
        memcmp(run->candidate_root, report->candidate_ranking_root, 32u) == 0 &&
        zcl_retrieval_profile_root(&run->profile, run->profile_root) ==
            ZCL_RETRIEVAL_EXPERIMENT_OK &&
        zcl_retrieval_feature_snapshot_root(
            &run->feature_snapshot, run->feature_rows,
            run->feature_snapshot_root) == ZCL_RETRIEVAL_EXPERIMENT_OK &&
        memcmp(run->profile_root, report->profile_root, 32u) == 0 &&
        memcmp(run->feature_snapshot_root, report->feature_snapshot_root,
               32u) == 0;
}

static bool rxc_seal(struct zcl_command_reply *reply, struct rxc_run *run)
{
    const struct zcl_native_dev_retrieval_snapshot *snapshot = &run->snapshot;
    if (!rxc_roots_reproduce(run) ||
        !zcl_retrieval_profile_proposal_input_root(
            snapshot->source_root, snapshot->codeindex_source_root,
            snapshot->retrieval_projection_root, snapshot->task_id,
            snapshot->query, run->recomputed_bm25, run->profile_root,
            run->feature_snapshot_root, run->candidate_root,
            run->study_root, run->preregistration_root, run->evaluator_root,
            run->proposal_root)) {
        rxc_fail(reply, "PROPOSAL_ROOT_FAILED", "seal",
                 "profile evidence, candidate, or proposal root could not "
                 "be reproduced and sealed", ZCL_RETRIEVAL_PROFILE_ALGORITHM);
        return false;
    }
    return true;
}

static bool rxc_push_root_hex(struct json_value *object, const char *key,
                              const uint8_t root[32])
{
    char hex[65];
    zcl_hex_encode(root, 32u, hex);
    return json_push_kv_str(object, key, hex);
}

static bool rxc_push_roots(struct json_value *out, const struct rxc_run *run)
{
    const struct zcl_native_dev_retrieval_snapshot *snapshot = &run->snapshot;
    return json_push_kv_str(out, "schema",
                            "zcl.dev_retrieval_experiment.v3") &&
        json_push_kv_str(out, "algorithm", ZCL_RETRIEVAL_PROFILE_ALGORITHM) &&
        json_push_kv_str(out, "task_id", snapshot->task_id) &&
        json_push_kv_str(out, "query", snapshot->query) &&
        rxc_push_root_hex(out, "source_root", snapshot->source_root) &&
        rxc_push_root_hex(out, "codeindex_source_root",
                          snapshot->codeindex_source_root) &&
        rxc_push_root_hex(out, "retrieval_projection_root",
                          snapshot->retrieval_projection_root) &&
        rxc_push_root_hex(out, "baseline_ranking_root",
                          run->recomputed_bm25) &&
        rxc_push_root_hex(out, "profile_root", run->profile_root) &&
        rxc_push_root_hex(out, "feature_snapshot_root",
                          run->feature_snapshot_root) &&
        rxc_push_root_hex(out, "candidate_ranking_root", run->candidate_root) &&
        rxc_push_root_hex(out, "proposal_input_root", run->proposal_root) &&
        rxc_push_root_hex(out, "study_root", run->study_root) &&
        rxc_push_root_hex(out, "preregistration_root",
                          run->preregistration_root) &&
        rxc_push_root_hex(out, "evaluator_root", run->evaluator_root);
}

static bool rxc_push_metrics(struct json_value *out, const struct rxc_run *run)
{
    const struct zcl_retrieval_profile_report *report = &run->report;
    const struct zcl_retrieval_profile_v1 *profile = &run->profile;
    return json_push_kv_int(out, "ranked_files",
                            (int64_t)report->ranked_count) &&
        json_push_kv_bool(out, "ranking_complete",
                          run->snapshot.bm25.complete) &&
        json_push_kv_int(out, "requested_rerank_window",
                         profile->rerank_window) &&
        json_push_kv_int(out, "effective_rerank_window",
                         profile->rerank_window < report->ranked_count
                            ? profile->rerank_window
                            : (int64_t)report->ranked_count) &&
        json_push_kv_int(out, "requested_top_k", profile->top_k) &&
        json_push_kv_int(out, "effective_top_k",
                         profile->top_k < report->ranked_count
                            ? profile->top_k
                            : (int64_t)report->ranked_count) &&
        report->baseline_context_bytes_at_top <= INT64_MAX &&
        report->candidate_context_bytes_at_top <= INT64_MAX &&
        json_push_kv_int(out, "baseline_context_bytes_at_top",
                         (int64_t)report->baseline_context_bytes_at_top) &&
        json_push_kv_int(out, "candidate_context_bytes_at_top",
                         (int64_t)report->candidate_context_bytes_at_top) &&
        json_push_kv_int(out, "changed_positions_at_top",
                         (int64_t)report->changed_positions_at_top);
}

static bool rxc_push_verdict(struct json_value *out, const struct rxc_run *run)
{
    const struct zcl_retrieval_profile_report *report = &run->report;
    return json_push_kv_bool(out, "used_baseline_fallback",
                             report->used_baseline_fallback) &&
        json_push_kv_bool(out, "baseline_recomputed", true) &&
        json_push_kv_bool(out, "observed_retained_set_preserved",
                          report->retained_set_preserved) &&
        json_push_kv_bool(out, "context_ceiling_preserved",
                          report->candidate_context_bytes_at_top <=
                          report->baseline_context_bytes_at_top) &&
        json_push_kv_str(out, "feature_evidence", "context_bytes_only") &&
        json_push_kv_str(out, "gold_basis", "not_supplied") &&
        json_push_kv_str(out, "scope_basis", "unavailable") &&
        json_push_kv_str(out, "evaluation_status", "not_run") &&
        json_push_kv_str(out, "science_binding_status",
                         "opaque_roots_unverified") &&
        json_push_kv_bool(out, "quality_claim_available", false) &&
        json_push_kv_bool(out, "promotion_authorized", false) &&
        rxc_push_rows(out, run->candidate, report->ranked_count);
}

static void rxc_run(const struct zcl_command_request *request,
                    struct zcl_command_reply *reply)
{
    struct rxc_run run;
    if (!rxc_parse_input(request, reply, &run) ||
        !rxc_load_baseline(request, reply, &run) ||
        !rxc_project(reply, &run) || !rxc_seal(reply, &run))
        return;
    if (!rxc_push_roots(&reply->data, &run) ||
        !rxc_push_metrics(&reply->data, &run) ||
        !rxc_push_verdict(&reply->data, &run))
        rxc_fail(reply, "OUTPUT_ALLOCATION_FAILED", "render",
                 "experiment result could not be rendered completely",
                 run.snapshot.task_id);
}

#endif /* ZCL_DEV_BUILD || ZCL_TESTING */

void zcl_native_handle_dev_retrieval_experiment(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
#if defined(ZCL_DEV_BUILD) || defined(ZCL_TESTING)
    rxc_run(request, reply);
#else
    (void)request;
    zcl_command_reply_fail(
        reply, ZCL_COMMAND_STATUS_BLOCKED, ZCL_COMMAND_EXIT_BLOCKED,
        "DEV_BUILD_REQUIRED", "dispatch", false, false,
        "retrieval experiments require the dev binary", "make dev-bin");
#endif
}
