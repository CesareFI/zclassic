/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: explicitly execute one exact installed resident app invocation. */
#include "command/native_command.h"
#include "base/hex.h"
#include "base/safe_alloc.h"
#include "json/json.h"
#include "services/package_resident.h"
#include "models/package_resident.h"
#include "platform/time_compat.h"
#include "platform/os_proc.h"
#include "util/log_macros.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#if !defined(_WIN32)
#include <fcntl.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

static uint64_t npr_now(void)
{
    int64_t now = platform_time_monotonic_us();
    return now > 0 ? (uint64_t)now : 0;
}

static const char *npr_str(const struct json_value *input, const char *key)
{
    const struct json_value *value = input ? json_get(input, key) : NULL;
    return value && value->type == JSON_STR ? json_get_str(value) : NULL;
}

static void npr_fail(struct zcl_command_reply *reply, const char *message)
{
    LOG_ERROR("app.invoke.package", "%s", message);
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
        ZCL_COMMAND_EXIT_INVALID, "RESIDENT_APP_REFUSED", "execute",
        false, false, message, "app.invoke.package");
}


enum npr_action { NPR_INVOKE, NPR_ACCEPT, NPR_ACTIVATE, NPR_ROLLBACK };
struct npr_plan {
    struct package_resident_store store;
    struct package_resident_record before;
    struct package_resident_identity target;
    const char *datadir, *text, *app;
    enum npr_action action;
    bool named, explicit_identity, candidate, mutated;
    int64_t ticket;
    char superseded_sha3[65];
};
struct npr_observation {
    struct resident_receipt receipt;
    struct resident_startup startup;
    char output[4097];
    uint64_t began, verified, observed, activated;
};

static bool npr_granted(const struct zcl_command_request *request)
{
    const struct json_value *input = request ? request->input : NULL;
    const struct json_value *grant = input ? json_get(input, "accept_execution") : NULL;
    return grant && grant->type == JSON_BOOL && json_get_bool(grant);
}

static struct zcl_result npr_string_types(const struct json_value *input)
{
    static const char *const keys[] = {
        "datadir", "app", "action", "operation", "input_text", "package_root",
        "receipt_id", "artifact_sha3", "program", "nonce"
    };
    for (size_t i = 0; i < sizeof(keys)/sizeof(keys[0]); ++i) {
        const struct json_value *v = json_get(input, keys[i]);
        if (v && v->type != JSON_STR)
            return ZCL_ERR(-1, "resident-input: %s must be a string", keys[i]);
    }
    return ZCL_OK;
}

static struct zcl_result npr_action_read(const struct json_value *input, struct npr_plan *plan)
{
    const char *action = npr_str(input, plan->named ? "action" : "operation");
    if (json_get(input, plan->named ? "operation" : "action"))
        return ZCL_ERR(-1, "resident-input: named apps use action; legacy invocations use operation");
    if (!action) action = "invoke";
    if (strcmp(action, "invoke") == 0) plan->action = NPR_INVOKE;
    else if (strcmp(action, "rollback") == 0) plan->action = NPR_ROLLBACK;
    else if (plan->named && strcmp(action, "accept") == 0) plan->action = NPR_ACCEPT;
    else if (plan->named && strcmp(action, "activate") == 0) plan->action = NPR_ACTIVATE;
    else return ZCL_ERR(-1, "resident-input: invalid action or operation");
    plan->text = npr_str(input, "input_text");
    if (!plan->text) plan->text = "list";
    if (strlen(plan->text) > 1024)
        return ZCL_ERR(-1, "resident-input: input_text exceeds 1024 bytes");
    return ZCL_OK;
}

/* Bind optional historical observation fields together. They are comparison
 * inputs, never a claim that the probe's old PID remains alive. */
static struct zcl_result npr_binding_shape(const struct json_value *nonce,
    const struct json_value *token, const struct json_value *generation)
{
    if (nonce->type != JSON_STR || token->type != JSON_INT || generation->type != JSON_INT)
        return ZCL_ERR(-1, "resident-binding: string nonce and integer token/generation required");
    uint8_t parsed[32];
    if (!zcl_hex_decode_lower(json_get_str(nonce), parsed, 32) || json_get_int(token) <= 0)
        return ZCL_ERR(-1, "resident-binding: exact nonce and positive start_token required");
    return ZCL_OK;
}

static struct zcl_result npr_binding_check(const struct json_value *input,
                                          const struct npr_plan *plan)
{
    const struct json_value *nonce = json_get(input, "nonce");
    const struct json_value *token = json_get(input, "start_token");
    const struct json_value *generation = json_get(input, "generation");
    if (!nonce && !token && !generation) return ZCL_OK;
    if (!nonce || !token || !generation)
        return ZCL_ERR(-1, "resident-binding: nonce, start_token and generation are required together");
    ZCL_CHECK(npr_binding_shape(nonce, token, generation));
    const char *bound_nonce = plan->before.current_nonce;
    uint64_t bound_token = plan->before.current_start_token;
    if (plan->named && plan->action == NPR_ACTIVATE) {
        bound_nonce = plan->before.pending_nonce;
        bound_token = plan->before.pending_start_token;
    }
    if (json_get_int(generation) != plan->before.generation)
        return ZCL_ERR(-1, "resident-generation-stale: supplied generation is not current");
    if (strcmp(json_get_str(nonce), bound_nonce) != 0)
        return ZCL_ERR(-1, "resident-nonce-stale: supplied nonce is not the stored observation");
    if ((uint64_t)json_get_int(token) != bound_token)
        return ZCL_ERR(-1, "resident-token-stale: supplied start_token is not the stored observation");
    return ZCL_OK;
}

static struct zcl_result npr_expected_check(const struct json_value *input,
                                           const struct npr_plan *plan)
{
    const struct json_value *v = json_get(input, "expected_generation");
    if (v && (v->type != JSON_INT || json_get_int(v) != plan->before.generation))
        return ZCL_ERR(-1, "resident-generation-precondition: expected serving generation differs");
    return ZCL_OK;
}

static bool npr_has_identity(const struct json_value *input)
{
    return json_get(input, "package_root") || json_get(input, "receipt_id") ||
        json_get(input, "artifact_sha3") || json_get(input, "program");
}

static struct zcl_result npr_identity_read(const struct json_value *input,
                                           struct package_resident_identity *target)
{
    const char *root = npr_str(input, "package_root");
    const char *receipt = npr_str(input, "receipt_id");
    const char *digest = npr_str(input, "artifact_sha3");
    const char *program = npr_str(input, "program");
    if (!root || !receipt || !digest || !program)
        return ZCL_ERR(-1, "resident-acceptance: complete exact root, receipt, artifact and program required");
    uint8_t parsed[32];
    if (!zcl_hex_decode_lower(root, parsed, 32) ||
        !zcl_hex_decode_lower(receipt, parsed, 32) ||
        !zcl_hex_decode_lower(digest, parsed, 32))
        return ZCL_ERR(-1, "resident-acceptance: exact lowercase hashes required");
    if (strlen(program) >= sizeof(target->program) || strncmp(program, "bin/", 4) != 0 || !program[4])
        return ZCL_ERR(-1, "resident-acceptance: bounded installed bin/ program required");
    memcpy(target->package_root, root, sizeof(target->package_root));
    memcpy(target->receipt_id, receipt, sizeof(target->receipt_id));
    memcpy(target->artifact_sha3, digest, sizeof(target->artifact_sha3));
    (void)snprintf(target->program, sizeof(target->program), "%s", program);
    return ZCL_OK;
}

static struct zcl_result npr_select(const struct json_value *input, struct npr_plan *plan)
{
    plan->explicit_identity = npr_has_identity(input);
    if (plan->action == NPR_ROLLBACK) plan->target = plan->before.previous;
    else if (plan->action == NPR_ACTIVATE) plan->target = plan->before.pending;
    else plan->target = plan->before.current;
    if (plan->action == NPR_ROLLBACK || plan->action == NPR_ACTIVATE) {
        if (plan->explicit_identity)
            return ZCL_ERR(-1, "resident-selection: activate and rollback use stored exact identities only");
    } else if (plan->explicit_identity) {
        if (!plan->named || plan->action == NPR_ACCEPT)
            plan->target.configuration_generation = 1;
        ZCL_CHECK(npr_identity_read(input, &plan->target));
    } else if (plan->action == NPR_ACCEPT) {
        return ZCL_ERR(-1, "resident-acceptance: accept requires a complete explicit identity");
    }
    if (!plan->target.package_root[0])
        return ZCL_ERR(-1, "resident-selection: no accepted identity for requested action");
    return ZCL_OK;
}

static struct zcl_result npr_config(const struct json_value *input, struct npr_plan *plan)
{
    const struct json_value *config = json_get(input, "configuration_generation");
    bool editable = plan->explicit_identity && (!plan->named || plan->action == NPR_ACCEPT);
    if (config) {
        if (config->type != JSON_INT || json_get_int(config) <= 0)
            return ZCL_ERR(-1, "resident-config: positive integer generation required");
        if (!editable && json_get_int(config) != plan->target.configuration_generation)
            return ZCL_ERR(-1, "resident-config: stored accepted configuration differs");
        plan->target.configuration_generation = json_get_int(config);
    }
    if (plan->named && plan->action == NPR_INVOKE &&
        !package_resident_identity_equal(&plan->target, &plan->before.current))
        return ZCL_ERR(-1, "resident-identity-stale: named invoke cannot replace the serving identity");
    return ZCL_OK;
}

static struct zcl_result npr_reserve(struct npr_plan *plan)
{
    if (plan->named && plan->action == NPR_ACTIVATE) {
        plan->ticket = plan->before.pending_ticket;
        if (plan->ticket <= 0 || plan->before.pending_generation != plan->before.generation ||
            plan->ticket != plan->before.revision)
            return ZCL_ERR(-1, "resident-pending-superseded: no current accepted candidate");
        return ZCL_OK;
    }
    plan->candidate = plan->action == NPR_ACCEPT || plan->action == NPR_ROLLBACK ||
        (!plan->named && plan->explicit_identity);
    if (plan->candidate) {
        struct package_resident_record reserved;
        ZCL_CHECK(package_resident_record_begin(&plan->store, plan->before.generation, &reserved));
        plan->ticket = reserved.revision;
        memcpy(plan->superseded_sha3, reserved.displaced_pending.artifact_sha3,
               sizeof(plan->superseded_sha3));
        plan->mutated = true;
    }
    return ZCL_OK;
}

static struct zcl_result npr_plan_open(const struct json_value *input, struct npr_plan *plan)
{
    plan->datadir = npr_str(input, "datadir");
    plan->app = npr_str(input, "app");
    plan->named = json_get(input, "app") != NULL;
    /* Resolve the row before other input checks so refusals can report the
     * current exact selection. Invalid app/datadir never chooses a fallback. */
    if (plan->named)
        ZCL_CHECK(package_resident_store_open_app(&plan->store, plan->datadir, plan->app));
    else
        ZCL_CHECK(package_resident_store_open(&plan->store, plan->datadir));
    ZCL_CHECK(package_resident_record_read(&plan->store, &plan->before));
    ZCL_CHECK(npr_string_types(input));
    ZCL_CHECK(npr_action_read(input, plan));
    ZCL_CHECK(npr_expected_check(input, plan));
    ZCL_CHECK(npr_binding_check(input, plan));
    ZCL_CHECK(npr_select(input, plan));
    ZCL_CHECK(npr_config(input, plan));
    return npr_reserve(plan);
}

static struct zcl_result npr_named_publish(struct npr_plan *plan,
    const struct resident_receipt *proof, struct package_resident_record *row)
{
    struct zcl_result result;
    if (plan->action == NPR_ACCEPT)
        result = package_resident_record_accept(&plan->store, plan->ticket,
            plan->before.generation, &plan->target, proof->nonce, proof->start_token, row);
    else if (plan->action == NPR_ACTIVATE)
        result = package_resident_record_activate(&plan->store, plan->ticket,
            plan->before.generation, proof->nonce, proof->start_token, row);
    else
        result = package_resident_record_rollback(&plan->store, plan->ticket,
            plan->before.generation, proof->nonce, proof->start_token, row);
    if (result.ok) plan->mutated = true;
    return result;
}

static struct zcl_result npr_publish(struct npr_plan *plan,
    const struct resident_receipt *proof, struct package_resident_record *row)
{
    if (plan->named && plan->action != NPR_INVOKE)
        return npr_named_publish(plan, proof, row);
    if (plan->candidate)
        return package_resident_record_commit(&plan->store, plan->ticket,
            plan->before.generation, &plan->target, row);
    ZCL_CHECK(package_resident_record_read(&plan->store, row));
    if (row->generation != plan->before.generation ||
        !package_resident_identity_equal(&row->current, &plan->target))
        return ZCL_ERR(-1, "resident-result-stale: serving generation changed while the child worked");
    return ZCL_OK;
}
static struct zcl_result npr_exchange(struct package_resident *app,
    const char *input, char output[4097])
{
#if defined(_WIN32)
    (void)app; (void)input; (void)output;
    return ZCL_ERR(-1, "resident app execution is unavailable on Windows");
#else
    struct resident_result_header header;
    char error[RESIDENT_LAUNCH_ERROR_MAX] = {0};
    int fd = (int)app->launch.ipc_native;
    int flags = fcntl(fd, F_GETFL);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0)
        return ZCL_ERR(-1, "resident IPC nonblocking setup failed");
    if (!resident_startup_read(&app->launch, &app->startup, error, sizeof(error)))
        return ZCL_ERR(-1, "resident READY refused: %s", error);
    struct { struct resident_result_header header; char text[1024]; } frame = {0};
    memcpy(frame.header.magic, "z23-res-run-v1", sizeof("z23-res-run-v1"));
    memcpy(frame.header.nonce, app->launch.nonce, sizeof(frame.header.nonce));
    frame.header.payload_len = (uint32_t)strlen(input);
    memcpy(frame.text, input, frame.header.payload_len);
    size_t bytes = sizeof(frame.header) + frame.header.payload_len;
    ssize_t sent = send(fd, &frame, bytes, MSG_NOSIGNAL);
    if (sent < 0 || (size_t)sent != bytes)
        return ZCL_ERR(-1, "resident input incomplete: candidate cancelled");
    if (!resident_result_read(&app->launch, &header, output, 4096, 2000, error, sizeof(error)))
        return ZCL_ERR(-1, "resident result refused: %s", error);
    for (uint32_t i = 0; i < header.payload_len; ++i) {
        unsigned char c = (unsigned char)output[i];
        if ((c < 32 && c != '\n' && c != '\t') || c > 126)
            return ZCL_ERR(-1, "resident result is not bounded display text");
    }
    output[header.payload_len] = 0;
    return ZCL_OK;
#endif
}


static struct zcl_result npr_artifact(struct npr_plan *plan, struct package_resident *app)
{
    uint8_t root[32], receipt[32];
    if (!zcl_hex_decode_lower(plan->target.package_root, root, 32) ||
        !zcl_hex_decode_lower(plan->target.receipt_id, receipt, 32))
        return ZCL_ERR(-1, "resident-acceptance: stored identity is malformed");
    ZCL_CHECK(package_resident_artifact_read(plan->datadir, root, receipt,
        plan->target.program, &app->artifact));
    if (strcmp(app->artifact.accepted.image_sha3_hex, plan->target.artifact_sha3) != 0)
        return ZCL_ERR(-1, "explicitly accepted artifact digest differs from installed receipt");
    return ZCL_OK;
}

static struct zcl_result npr_run(struct npr_plan *plan, struct npr_observation *seen)
{
    struct package_resident *app = zcl_calloc(1, sizeof(*app), "package.resident");
    if (!app) return ZCL_ERR(-1, "resident app allocation failed");
    package_resident_init(app);
    char error[RESIDENT_LAUNCH_ERROR_MAX] = {0};
    struct zcl_result result = resident_startup_begin(&app->startup,
        RESIDENT_STARTUP_PLATFORM_MS, RESIDENT_STARTUP_PROTOCOL_MS, error, sizeof(error))
        ? npr_artifact(plan, app) : ZCL_ERR(-1, "resident-startup-budget: %s", error);
    seen->verified = npr_now();
    if (result.ok) result = package_resident_prepare(app, &app->artifact);
    if (result.ok) result = package_resident_start(app);
    if (result.ok) result = npr_exchange(app, plan->text, seen->output);
    seen->observed = npr_now();
    seen->receipt = app->receipt;
    seen->startup = app->startup;
    struct zcl_result closed = package_resident_close(app);
    if (!closed.ok) result = closed;
    free(app);
    return result;
}

static bool npr_render_proof(struct json_value *data, const struct npr_plan *plan,
                             const struct npr_observation *seen)
{
    return json_push_kv_str(data, "artifact_sha3", plan->target.artifact_sha3) &&
        json_push_kv_str(data, "package_root", plan->target.package_root) &&
        json_push_kv_str(data, "receipt_id", plan->target.receipt_id) &&
        json_push_kv_int(data, "configuration_generation", plan->target.configuration_generation) &&
        json_push_kv_str(data, "program", plan->target.program) &&
        json_push_kv_str(data, "result", seen->output) &&
        json_push_kv_str(data, "mapped_proof", seen->receipt.mapped_proof) &&
        json_push_kv_str(data, "nonce", seen->receipt.nonce) &&
        json_push_kv_int(data, "pid", (int64_t)seen->receipt.pid) &&
        json_push_kv_int(data, "start_token", (int64_t)seen->receipt.start_token) &&
        json_push_kv_bool(data, "child_reaped", true);
}

static bool npr_render_record(struct json_value *data, const struct package_resident_record *row)
{
    return json_push_kv_int(data, "generation", row->generation) &&
        json_push_kv_str(data, "previous_artifact_sha3", row->previous.artifact_sha3) &&
        json_push_kv_str(data, "serving_sha3", row->current.artifact_sha3) &&
        json_push_kv_str(data, "serving_receipt_id", row->current.receipt_id) &&
        json_push_kv_str(data, "serving_nonce", row->current_nonce) &&
        json_push_kv_int(data, "serving_start_token", (int64_t)row->current_start_token);
}

static bool npr_render_named(struct json_value *data, const struct npr_plan *plan,
                             const struct package_resident_record *row)
{
    if (!plan->named) return true;
    if (!json_push_kv_str(data, "app", plan->app)) return false;
    if (plan->action == NPR_ACCEPT)
        return json_push_kv_str(data, "pending_sha3", row->pending.artifact_sha3) &&
            json_push_kv_str(data, "pending_receipt_id", row->pending.receipt_id) &&
            json_push_kv_str(data, "candidate_nonce", row->pending_nonce) &&
            json_push_kv_int(data, "candidate_start_token", (int64_t)row->pending_start_token) &&
            json_push_kv_str(data, "superseded_sha3", plan->superseded_sha3);
    if (plan->action == NPR_ACTIVATE || plan->action == NPR_ROLLBACK)
        return json_push_kv_str(data, "switched_from_sha3", plan->before.current.artifact_sha3);
    return true;
}

static bool npr_render_times(struct json_value *data, const struct npr_observation *seen)
{
    return json_push_kv_int(data, "startup_began_ns", (int64_t)seen->startup.began_ns) &&
        json_push_kv_int(data, "startup_total_deadline_ns", (int64_t)seen->startup.total_end_ns) &&
        json_push_kv_int(data, "entry_observed_ns", (int64_t)seen->startup.entry_observed_ns) &&
        json_push_kv_int(data, "child_entry_ns", (int64_t)seen->startup.child_entry_ns) &&
        json_push_kv_int(data, "ready_ns", (int64_t)seen->startup.ready_ns) &&
        json_push_kv_int(data, "platform_launch_budget_ms", seen->startup.platform_ms) &&
        json_push_kv_int(data, "ready_protocol_budget_ms", seen->startup.protocol_ms) &&
        json_push_kv_int(data, "verification_us", (int64_t)(seen->verified - seen->began)) &&
        json_push_kv_int(data, "first_result_us", (int64_t)(seen->observed - seen->began)) &&
        json_push_kv_int(data, "activation_us", (int64_t)(seen->activated - seen->began)) &&
        json_push_kv_int(data, "completed_us", (int64_t)(npr_now() - seen->began)) &&
        json_push_kv_str(data, "next_action", "explicitly activate an accepted candidate, invoke the current version, or request rollback");
}

static void npr_error(struct npr_plan *plan, struct zcl_command_reply *reply, const char *message)
{
    npr_fail(reply, message);
    reply->error.mutated = plan->mutated;
    if (!plan->store.db) return;
    struct package_resident_record row;
    struct zcl_result read = package_resident_record_read(&plan->store, &row);
    if (read.ok && row.generation > 0)
        (void)snprintf(reply->error.evidence, sizeof(reply->error.evidence),
            "serving_generation=%lld artifact_sha3=%s",
            (long long)row.generation, row.current.artifact_sha3);
}

static struct zcl_result npr_complete(struct npr_plan *plan, struct npr_observation *seen,
                                      struct zcl_command_reply *reply)
{
    ZCL_CHECK(npr_run(plan, seen));
    struct package_resident_record row;
    ZCL_CHECK(npr_publish(plan, &seen->receipt, &row));
    seen->activated = npr_now();
    json_set_object(&reply->data);
    if (!npr_render_proof(&reply->data, plan, seen) ||
        !npr_render_record(&reply->data, &row) ||
        !npr_render_named(&reply->data, plan, &row) ||
        !npr_render_times(&reply->data, seen))
        return ZCL_ERR(-1, "resident result allocation failed after completed invocation");
    return ZCL_OK;
}

/* Observe the real controller after its store, snapshot and IPC owners have
 * closed. Unavailable census is explicitly absent, never reported as zero. */
static void npr_descriptor_evidence(struct npr_plan *plan,
    struct zcl_command_reply *reply, bool before_known, size_t before, bool passed)
{
    size_t after = 0;
    bool known = before_known && os_proc_open_fd_count(&after);
    if (!passed) {
        size_t used = strlen(reply->error.evidence);
        if (!known) {
            (void)snprintf(reply->error.evidence + used,
                sizeof(reply->error.evidence) - used, " fd_census=unavailable");
            return;
        }
        (void)snprintf(reply->error.evidence + used,
            sizeof(reply->error.evidence) - used, " fd_census=%s before=%zu after=%zu",
            "observed", before, after);
        return;
    }
    bool rendered = json_push_kv_bool(&reply->data, "fd_census_available", known);
    if (known) rendered = rendered &&
        json_push_kv_int(&reply->data, "fd_count_before", (int64_t)before) &&
        json_push_kv_int(&reply->data, "fd_count_after", (int64_t)after);
    if (!rendered) npr_error(plan, reply, "resident descriptor evidence allocation failed");
}

void zcl_native_handle_package_resident(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    struct npr_observation seen = {.began = npr_now()};
    if (!npr_granted(request)) {
        npr_fail(reply, "accept_execution must be JSON boolean true; no execution acceptance was granted");
        return;
    }
    size_t descriptors_before = 0;
    bool census_known = os_proc_open_fd_count(&descriptors_before);
    struct npr_plan plan = {0};
    struct zcl_result result = npr_plan_open(request->input, &plan);
    if (result.ok) result = npr_complete(&plan, &seen, reply);
    if (!result.ok) npr_error(&plan, reply, result.message);
    struct zcl_result closed = package_resident_store_close(&plan.store);
    if (!closed.ok) npr_error(&plan, reply, closed.message);
    npr_descriptor_evidence(&plan, reply, census_known, descriptors_before,
        result.ok && closed.ok);
}
