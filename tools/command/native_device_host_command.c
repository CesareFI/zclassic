/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * Purpose: complete explicit offline HOST proposal approval, no transport. */
#include "command/native_command.h"
#include "services/device_identity.h"
#include "services/device_host_key.h"
#include "base/hex.h"
#include "platform/clock.h"
#include "platform/private_directory.h"
#include "platform/positioned_file.h"
#include "support/cleanse.h"
#include "platform/rng.h"
#include "base/bytes.h"
#include "base/safe_alloc.h"
#include "util/log_macros.h"
#include <string.h>

struct host_proposal {
    struct device_pairing_store store;
    struct db_device_pairing row;
    uint8_t proposed[32], prior[32];
    bool upgrade;
    const char *local_blob, *peer_blob;
};
static bool host_fail(struct zcl_command_reply *reply, const char *message, bool mutated)
{
    LOG_ERROR("native.device.host", "%s", message);
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_FAILED,
        "HOST_APPROVAL_REFUSED", "approve_host", false, mutated, message,
        "complete owner-confirmed HOST proposal and exact prior root");
    return false;
}
static uint64_t host_now(void)
{
    int64_t ms = clock_now_wall_ms();
    return ms > 0 ? (uint64_t)ms / 1000 : 0;
}
static bool host_hex_input(const struct json_value *input, const char *field, uint8_t out[32])
{
    const struct json_value *value = json_get(input, field);
    return value && value->type == JSON_STR && zcl_hex_decode(json_get_str(value), out, 32);
}
static bool host_uint(const struct json_value *input, const char *field, uint64_t max, uint64_t *out)
{
    const struct json_value *value = json_get(input, field);
    if (!value || value->type != JSON_INT || json_get_int(value) < 0) return false;
    uint64_t number = (uint64_t)json_get_int(value);
    if (number > max) return false;
    *out = number;
    return true;
}
static bool host_put_hex(struct json_value *data, const char *field, const uint8_t bytes[32])
{
    char text[65]; zcl_hex_encode(bytes, 32, text);
    return json_push_kv_str(data, field, text);
}
bool zcl_native_device_host_requested(const struct json_value *input)
{
    const char *cap = json_get_str(json_get(input, "capability"));
    if (cap && !strcmp(cap, "host-forward")) return true;
    static const char *const fields[] = {"backend", "local_pq_blob", "peer_pq_blob",
        "inbound_port", "outbound_port", "paired_at", "confirmed_proposal_root",
        "credential_id", "key_epoch", "secret_file"};
    for (size_t i = 0; i < sizeof(fields) / sizeof(fields[0]); ++i)
        if (json_get(input, fields[i])) return true;
    return false;
}
static bool host_pq_binding_read(const struct json_value *input, struct host_proposal *proposal)
{
    if (json_get(input, "credential_id") || json_get(input, "key_epoch") ||
        json_get(input, "secret_file")) return false;
    proposal->local_blob = json_get_str(json_get(input, "local_pq_blob"));
    proposal->peer_blob = json_get_str(json_get(input, "peer_pq_blob"));
    uint8_t blob[DEVICE_HOST_KEY_BLOB_SIZE];
    if (!proposal->local_blob || !proposal->peer_blob ||
        !zcl_hex_decode(proposal->local_blob, blob, sizeof(blob)) ||
        !device_host_key_root(1, blob, sizeof(blob), proposal->row.host_scope.binding.local_pq_key_root).ok) return false;
    return zcl_hex_decode(proposal->peer_blob, blob, sizeof(blob)) &&
        device_host_key_root(1, blob, sizeof(blob), proposal->row.host_scope.binding.peer_pq_key_root).ok;
}
static bool host_psk_binding_read(const struct json_value *input, struct host_proposal *proposal)
{
    if (json_get(input, "local_pq_blob") || json_get(input, "peer_pq_blob")) return false;
    struct device_pairing_psk_binding *psk = &proposal->row.host_scope.binding.psk;
    if (!host_hex_input(input, "credential_id", psk->credential_id) ||
        !host_uint(input, "key_epoch", INT64_MAX, &psk->key_epoch) || !psk->key_epoch) return false;
    const uint8_t *local = proposal->row.local_key, *peer = proposal->row.peer_key;
    int order = memcmp(local, peer, 32);
    if (!order) return false;
    memcpy(psk->endpoint_a, order < 0 ? local : peer, 32);
    memcpy(psk->endpoint_b, order < 0 ? peer : local, 32);
    return true;
}
static bool host_binding_read(const struct json_value *input, struct host_proposal *proposal)
{
    uint64_t backend, inbound, outbound;
    if (!host_uint(input, "backend", 2, &backend) || !backend ||
        !host_uint(input, "inbound_port", UINT16_MAX, &inbound) ||
        !host_uint(input, "outbound_port", UINT16_MAX, &outbound)) return false;
    proposal->row.host_scope.inbound_port = (uint16_t)inbound;
    proposal->row.host_scope.outbound_port = (uint16_t)outbound;
    proposal->row.host_scope.binding.backend_profile = (uint32_t)backend;
    return backend == 1 ? host_pq_binding_read(input, proposal) : host_psk_binding_read(input, proposal);
}
static bool host_backend_compatible(uint32_t current, uint32_t proposed)
{
    return current == proposed || (current != 2 && proposed != 2);
}
static bool host_prior_read(const struct json_value *input, bool commit,
    struct host_proposal *proposal, uint64_t now)
{
    const struct json_value *value = json_get(input, "expected_root");
    const char *expected = value ? json_get_str(value) : "absent";
    if (!expected || (commit && !value)) return false;
    if (!strcmp(expected, "absent")) return true;
    if (!host_hex_input(input, "expected_root", proposal->prior)) return false;
    struct db_device_pairing current;
    uint8_t root[32];
    if (!db_device_pairing_inspect(&proposal->store, proposal->row.peer_key, &current, root) ||
        memcmp(root, proposal->prior, 32) || current.revoked_at || current.generation ||
        now < current.paired_at || now >= current.expires_at) return false;
    if (!host_backend_compatible(current.host_scope.binding.backend_profile,
        proposal->row.host_scope.binding.backend_profile)) return false;
    proposal->upgrade = true;
    proposal->row.paired_at = current.paired_at;
    return true;
}
static bool host_interval_read(const struct json_value *input, bool commit,
    struct host_proposal *proposal, uint64_t now)
{
    uint64_t paired = proposal->upgrade ? proposal->row.paired_at : now;
    const struct json_value *value = json_get(input, "paired_at");
    if (value) {
        if (!host_uint(input, "paired_at", INT64_MAX, &paired)) return false;
        if (proposal->upgrade && paired != proposal->row.paired_at) return false;
    } else if (commit) return false;
    proposal->row.paired_at = paired;
    if (!host_uint(input, "expires_at", INT64_MAX, &proposal->row.expires_at)) return false;
    return now && paired && paired <= now && proposal->row.expires_at > now;
}
static bool host_read(const struct json_value *input, const struct device_identity *identity,
    bool commit, struct host_proposal *proposal)
{
    memset(proposal, 0, sizeof(*proposal));
    const char *cap = json_get_str(json_get(input, "capability"));
    if (!cap || strcmp(cap, "host-forward") || json_get(input, "fingerprint") ||
        !host_hex_input(input, "peer_key", proposal->row.peer_key)) return false;
    if (!commit && json_get(input, "secret_file")) return false;
    if (!device_identity_pair_store(identity, proposal->row.peer_key, &proposal->store).ok) return false;
    memcpy(proposal->row.profile, proposal->store.profile, 32);
    memcpy(proposal->row.local_key, identity->public_key, 32);
    proposal->row.capabilities = DEVICE_PAIRING_CAP_HOST_FORWARD;
    uint64_t now = host_now();
    if (!host_binding_read(input, proposal) || !host_prior_read(input, commit, proposal, now) ||
        !host_interval_read(input, commit, proposal, now)) return false;
    return device_pairing_host_proposal_root(&proposal->row, proposal->proposed);
}
static bool host_emit_keys(struct json_value *data, const struct host_proposal *proposal)
{
    if (!(host_put_hex(data, "local_key", proposal->row.local_key) &&
        host_put_hex(data, "peer_key", proposal->row.peer_key) &&
        host_put_hex(data, "profile", proposal->row.profile) &&
        json_push_kv_int(data, "backend", proposal->row.host_scope.binding.backend_profile))) return false;
    if (proposal->row.host_scope.binding.backend_profile == 2) {
        const struct device_pairing_psk_binding *psk = &proposal->row.host_scope.binding.psk;
        return host_put_hex(data, "credential_id", psk->credential_id) &&
            json_push_kv_int(data, "key_epoch", (int64_t)psk->key_epoch) &&
            host_put_hex(data, "endpoint_a", psk->endpoint_a) &&
            host_put_hex(data, "endpoint_b", psk->endpoint_b);
    }
    return
        json_push_kv_str(data, "local_pq_blob", proposal->local_blob) &&
        json_push_kv_str(data, "peer_pq_blob", proposal->peer_blob) &&
        host_put_hex(data, "local_pq_key_root", proposal->row.host_scope.binding.local_pq_key_root) &&
        host_put_hex(data, "peer_pq_key_root", proposal->row.host_scope.binding.peer_pq_key_root);
}
static bool host_emit(struct json_value *data, const struct host_proposal *proposal)
{
    if (!host_emit_keys(data, proposal)) return false;
    if (proposal->upgrade) {
        if (!host_put_hex(data, "inspected_prior_root", proposal->prior)) return false;
    } else if (!json_push_kv_str(data, "required_prior_state", "absent") ||
        !json_push_kv_bool(data, "absence_observed", false)) return false;
    return json_push_kv_int(data, "inbound_port", proposal->row.host_scope.inbound_port) &&
        json_push_kv_int(data, "outbound_port", proposal->row.host_scope.outbound_port) &&
        json_push_kv_int(data, "paired_at", (int64_t)proposal->row.paired_at) &&
        json_push_kv_int(data, "expires_at", (int64_t)proposal->row.expires_at) &&
        json_push_kv_int(data, "capabilities", (int64_t)proposal->row.capabilities) &&
        json_push_kv_int(data, "revoked_at", 0) && json_push_kv_int(data, "generation", 0) &&
        host_put_hex(data, "proposal_root", proposal->proposed) &&
        json_push_kv_str(data, "possession", "not_established_by_this_command") &&
        json_push_kv_str(data, "backend_qualification", "not_established_by_this_command");
}
static bool host_publication(struct json_value *data, enum device_pairing_publication state)
{
    const char *name = state == DEVICE_PAIRING_DURABLE ? "durable" :
        state == DEVICE_PAIRING_DURABILITY_UNKNOWN ? "durability_unknown" : "not_published";
    return json_push_kv_str(data, "publication", name);
}
/* Trusted ancestors/private parent are caller requirements, not hostile-path
 * confinement. Never expose the source path or a secret-derived identifier. */
#if !defined(_WIN32)
static bool host_secret_read(const struct json_value *input, uint8_t secret[32])
{
    const char *source = json_get_str(json_get(input, "secret_file"));
    char resolved[1200], parent[1200];
    if (!source || !platform_private_destination_resolve(source, resolved, sizeof(resolved),
        parent, sizeof(parent))) return false;
    const char *leaf = strrchr(resolved, '/');
    if (!leaf || !leaf[1]) return false;
    uintptr_t directory;
    if (!platform_private_directory_open_validated(parent, &directory)) return false;
    platform_private_directory_close(directory);
    struct platform_positioned_file file;
    struct platform_positioned_file_snapshot before, after;
    platform_positioned_file_init(&file);
    bool ok = platform_positioned_file_open_beneath(&file, parent, leaf + 1) &&
        platform_positioned_file_is_private(&file) &&
        platform_positioned_file_is_current_user_only(&file) &&
        platform_positioned_file_snapshot(&file, &before) && before.size == 32 &&
        platform_positioned_file_read(&file, secret, 32, 0) == 32 &&
        platform_positioned_file_snapshot(&file, &after) &&
        platform_positioned_file_snapshot_equal(&before, &after);
    platform_positioned_file_close(&file);
    return ok;
}
#endif
static const char *host_publication_name(enum device_pairing_publication state)
{
    return state == DEVICE_PAIRING_DURABLE ? "durable" :
        state == DEVICE_PAIRING_DURABILITY_UNKNOWN ? "durability_unknown" : "not_published";
}
static bool host_psk_publication(struct json_value *data,
    const struct device_pairing_psk_publication *report)
{
    return json_push_kv_str(data, "secret_publication", host_publication_name(report->secret)) &&
        json_push_kv_str(data, "grant_publication", host_publication_name(report->grant)) &&
        json_push_kv_bool(data, "mutation_attempted", report->mutation_attempted) &&
        json_push_kv_bool(data, "intent_retired", report->intent_retired);
}
static bool host_psk_failure(struct zcl_command_reply *reply, const char *message,
    const struct device_pairing_psk_publication *report)
{
    struct json_value facts = {0};
    json_set_object(&facts);
    bool emitted = host_psk_publication(&facts, report) &&
        json_push_kv(&reply->data, "failure_facts", &facts);
    json_free(&facts);
    return host_fail(reply, emitted ? message :
        "PSK outcome facts could not be serialized; preserve artifacts and inspect before retry",
        report->mutation_attempted);
}
static bool host_psk_commit(const struct json_value *input, struct host_proposal *proposal,
    const uint8_t confirmed[32], struct zcl_command_reply *reply)
{
    struct device_pairing_psk_publication report = {0};
#if defined(_WIN32)
    (void)input; (void)proposal; (void)confirmed;
    (void)host_psk_publication(&reply->data, &report);
    return host_psk_failure(reply, "Windows durable PSK import is unsupported; no mutation attempted", &report);
#else
    uint8_t secret[32] = {0};
    bool read = host_secret_read(input, secret);
    /* Source filesystem IO may block. Recheck the proposed interval after
     * reading and pass this same fresh sample to the current-grant check. */
    uint64_t now = read ? host_now() : 0;
    bool active = now && now >= proposal->row.paired_at && now < proposal->row.expires_at;
    bool ok = false;
    if (active) ok = proposal->upgrade ? db_device_pairing_rotate_host_psk(&proposal->store,
        &proposal->row, secret, confirmed, proposal->prior, now, &report) :
        db_device_pairing_insert_host_psk(&proposal->store, &proposal->row, secret, confirmed, &report);
    memory_cleanse(secret, sizeof(secret));
    reply->error.mutated = report.mutation_attempted;
    bool emitted = host_psk_publication(&reply->data, &report);
    if (!read) return host_psk_failure(reply, "private owner-bound exact32 stable regular source required", &report);
    if (!active) return host_psk_failure(reply, "approved interval expired during private source acquisition", &report);
    if (!ok) return host_psk_failure(reply,
        "PSK import refused or interrupted; preserve artifacts; reconciliation is unsupported, do not retry automatically",
        &report);
    if (!emitted || !json_push_kv_bool(&reply->data, "committed", true))
        return host_psk_failure(reply, "PSK saved but reply serialization failed; inspect before retry", &report);
    return true;
#endif
}
static bool host_commit(const struct json_value *input, struct host_proposal *proposal,
    struct zcl_command_reply *reply)
{
    uint8_t confirmed[32];
    if (!host_hex_input(input, "confirmed_proposal_root", confirmed) || memcmp(confirmed, proposal->proposed, 32))
        return host_fail(reply, "independently confirmed complete proposal root required", false);
    uint64_t now = host_now();
    if (!now || now < proposal->row.paired_at || now >= proposal->row.expires_at)
        return host_fail(reply, "approved interval is not currently active", false);
    if (proposal->row.host_scope.binding.backend_profile == 2)
        return host_psk_commit(input, proposal, confirmed, reply);
#if defined(_WIN32)
    if (!host_publication(&reply->data, DEVICE_PAIRING_NOT_PUBLISHED))
        return host_fail(reply, "cannot serialize unsupported Windows HOST publication", false);
    return host_fail(reply, "Windows durable HOST publication is unsupported; no mutation attempted", false);
#else
    enum device_pairing_publication publication = DEVICE_PAIRING_NOT_PUBLISHED;
    bool ok = proposal->upgrade ? db_device_pairing_upgrade_host(&proposal->store, &proposal->row,
        confirmed, proposal->prior, now, &publication) :
        db_device_pairing_insert_host(&proposal->store, &proposal->row, confirmed, &publication);
    reply->error.mutated = true; /* Publication attempt may have created intent. */
    bool emitted = host_publication(&reply->data, publication);
    if (!ok) return host_fail(reply, "host publication refused or interrupted; inspect before retry", true);
    if (!emitted || !json_push_kv_bool(&reply->data, "committed", true))
        return host_fail(reply, "host saved but reply serialization failed; inspect before retry", true);
    return true;
#endif
}
bool zcl_native_device_host_pairing(const struct json_value *input,
    const struct device_identity *identity, bool commit, struct zcl_command_reply *reply)
{
    struct host_proposal proposal;
    if (!host_read(input, identity, commit, &proposal))
        return host_fail(reply, "HOST requires explicit recognized backend binding, both ports, active exact interval and prior root", false);
    if (!host_emit(&reply->data, &proposal)) return false;
    if (commit) return host_commit(input, &proposal, reply);
    return json_push_kv_bool(&reply->data, "committed", false) &&
        json_push_kv_bool(&reply->data, "defaults_are_proposals", true);
}

struct secret_preparation {
    char destination[1200], parent[1200];
    uintptr_t directory;
    uint8_t id[32];
    bool id_known, attempted;
    enum device_pairing_publication publication;
};
#ifdef ZCL_TESTING
static _Thread_local unsigned prepare_fault;
void zcl_native_device_prepare_test_interrupt(unsigned stage) { prepare_fault = stage; }
#endif
#if !defined(_WIN32)
static bool prepare_checkpoint(unsigned stage)
{
#ifdef ZCL_TESTING
    if (prepare_fault == stage) { prepare_fault = 0; return false; }
#else
    (void)stage;
#endif
    return true;
}
#endif
static bool prepare_report(struct json_value *data, const struct secret_preparation *prepared)
{
    return json_push_kv_str(data, "source_publication", host_publication_name(prepared->publication)) &&
        json_push_kv_bool(data, "mutation_attempted", prepared->attempted);
}
static bool prepare_fail(struct zcl_command_reply *reply, const char *message,
    const struct secret_preparation *prepared)
{
    struct json_value facts = {0}; json_set_object(&facts);
    bool ok = prepare_report(&facts, prepared);
    if (ok && prepared->id_known) ok = host_put_hex(&facts, "credential_id", prepared->id);
    if (ok) ok = json_push_kv(&reply->data, "failure_facts", &facts);
    json_free(&facts);
    return host_fail(reply, ok ? message :
        "preparation outcome could not be serialized; preserve artifacts and inspect before further action",
        prepared->attempted);
}
#if !defined(_WIN32)
static bool prepare_pair_input(const struct json_value *input, uint8_t peer[32])
{
    uint64_t backend;
    const struct json_value *confirm = json_get(input, "confirm");
    const char *cap = json_get_str(json_get(input, "capability"));
    if (!confirm || confirm->type != JSON_BOOL || !json_get_bool(confirm) ||
        !cap || strcmp(cap, "host-forward") || !host_uint(input, "backend", 2, &backend) || backend != 2 ||
        !host_hex_input(input, "peer_key", peer) || !zcl_bytes_any_set(peer, 32)) return false;
    return true;
}
static bool prepare_public_metadata(const struct json_value *input,
    const struct device_identity *identity, struct json_value *data)
{
    uint8_t peer[32];
    if (!prepare_pair_input(input, peer)) return false;
    int order = memcmp(identity->public_key, peer, 32);
    if (!order) return false;
    struct device_pairing_store store;
    if (!device_identity_pair_store(identity, peer, &store).ok) return false;
    return host_put_hex(data, "local_key", identity->public_key) && host_put_hex(data, "peer_key", peer) &&
        host_put_hex(data, "profile", store.profile) &&
        host_put_hex(data, "endpoint_a", order < 0 ? identity->public_key : peer) &&
        host_put_hex(data, "endpoint_b", order < 0 ? peer : identity->public_key) &&
        json_push_kv_int(data, "backend", 2) && json_push_kv_str(data, "purpose", "host-forward") &&
        json_push_kv_str(data, "possession", "not_established_by_this_command");
}
static bool prepare_destination(const struct json_value *input, struct secret_preparation *prepared)
{
    const char *path = json_get_str(json_get(input, "destination"));
    if (!path || !platform_private_destination_resolve(path, prepared->destination,
        sizeof(prepared->destination), prepared->parent, sizeof(prepared->parent)) ||
        !platform_private_path_absent(prepared->destination)) return false;
    return platform_private_directory_open_validated(prepared->parent, &prepared->directory);
}
static bool prepare_entropy(uint8_t secret[32], struct secret_preparation *prepared)
{
    if (!prepare_checkpoint(1) || !rng_host_fill(secret, 32) ||
        !prepare_checkpoint(2) || !rng_host_fill(prepared->id, 32)) return false;
    if (!prepare_checkpoint(3)) memset(prepared->id, 0, 32);
    prepared->id_known = zcl_bytes_any_set(prepared->id, 32);
    return prepared->id_known;
}
static bool prepare_usable(const char *path, const struct platform_private_file_identity *identity)
{
    struct platform_positioned_file file;
    struct platform_positioned_file_snapshot snapshot;
    platform_positioned_file_init(&file);
    bool ok = platform_positioned_file_open(&file, path) &&
        platform_positioned_file_is_private(&file) && platform_positioned_file_is_current_user_only(&file) &&
        platform_positioned_file_snapshot(&file, &snapshot) && snapshot.size == 32 &&
        snapshot.volume == identity->volume && snapshot.file_low == identity->file && snapshot.file_high == 0;
    platform_positioned_file_close(&file);
    return ok;
}
static bool prepare_write(const uint8_t secret[32], const char *path,
    struct platform_private_file *file, struct platform_private_file_identity *before)
{
    uint64_t size = 0;
    return prepare_checkpoint(4) && platform_private_file_create_locked(path, file) &&
        platform_private_file_identity(file, before) && prepare_checkpoint(5) &&
        platform_private_file_write_at(file, secret, 32, 0) && platform_private_file_size(file, &size) &&
        size == 32 && prepare_usable(path, before) &&
        prepare_checkpoint(6) && platform_private_file_authority_flush(file);
}
static bool prepare_publish(const uint8_t secret[32], struct secret_preparation *prepared)
{
    struct platform_private_file file; platform_private_file_init(&file);
    prepared->attempted = true;
    prepared->publication = DEVICE_PAIRING_DURABILITY_UNKNOWN;
    struct platform_private_file_identity before, after;
    bool ok = prepare_write(secret, prepared->destination, &file, &before);
    if (ok) ok = platform_private_file_identity(&file, &after) &&
        before.volume == after.volume && before.file == after.file && prepare_checkpoint(7) &&
        platform_private_parent_flush(prepared->parent);
    platform_private_file_close(&file);
    if (ok) prepared->publication = DEVICE_PAIRING_DURABLE;
    return ok;
}
static void prepare_reply_checkpoint(struct json_value *data)
{
#ifdef ZCL_TESTING
    if (!prepare_checkpoint(8)) {
        /* White-box allocation geometry: preserve initialized fields but
         * force the next public report append to grow its owned allocation. */
        data->children_cap = data->num_children;
        zcl_alloc_fault_fail_next("json_children");
    }
#else
    (void)data;
#endif
}
#endif
bool zcl_native_device_prepare_secret(const struct json_value *input,
    const struct device_identity *identity, struct zcl_command_reply *reply)
{
    struct secret_preparation prepared = {0};
#if defined(_WIN32)
    (void)input; (void)identity;
    return prepare_fail(reply, "Windows durable private preparation is unsupported; no mutation attempted", &prepared);
#else
    if (!prepare_public_metadata(input, identity, &reply->data) || !prepare_destination(input, &prepared))
        return prepare_fail(reply, "explicit owner confirmation, backend2 pair and absent source in trusted private parent required", &prepared);
    uint8_t secret[32] = {0};
    bool ok = prepare_entropy(secret, &prepared);
    if (ok) ok = host_put_hex(&reply->data, "credential_id", prepared.id);
    if (ok) ok = prepare_publish(secret, &prepared);
    memory_cleanse(secret, sizeof(secret));
    platform_private_directory_close(prepared.directory);
    reply->error.mutated = prepared.attempted;
    if (!ok) return prepare_fail(reply,
        "private source preparation refused or interrupted; preserve artifacts, do not retry automatically", &prepared);
    prepare_reply_checkpoint(&reply->data);
    if (!prepare_report(&reply->data, &prepared))
        return prepare_fail(reply, "private source is durable but reply allocation failed; inspect before further action", &prepared);
    return true;
#endif
}
