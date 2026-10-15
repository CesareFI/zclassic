/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: explicit offline identity and grant approval; no network/runtime. */
#include "command/native_command.h"
#include "services/device_identity.h"
#include "base/hex.h"
#include "net/v2_identity.h"
#include "platform/clock.h"
#include "util/log_macros.h"
#include <string.h>

static bool device_fail(struct zcl_command_reply *reply, const char *message, bool mutated)
{
    LOG_ERROR("native.device", "%s", message);
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_FAILED,
        "DEVICE_PROFILE_REFUSED", "approve_local", false, mutated, message,
        "owner-device profile and exact grant");
    return false;
}
static bool put_hex(struct json_value *data, const char *name, const uint8_t bytes[32])
{
    char hex[65];
    zcl_hex_encode(bytes, 32, hex);
    return json_push_kv_str(data, name, hex);
}
static bool hex_input(const struct json_value *input, const char *key, uint8_t bytes[32])
{
    const struct json_value *value = json_get(input, key);
    if (!value || value->type != JSON_STR) return false;
    const char *text = json_get_str(value);
    return strlen(text) == 64 && zcl_hex_decode(text, bytes, 32);
}
static uint64_t device_now(void)
{
    int64_t wall = clock_now_wall_ms();
    return wall > 0 ? (uint64_t)wall / 1000 : 0;
}
static bool publication(struct json_value *data, enum device_pairing_publication state)
{
    const char *name = state == DEVICE_PAIRING_DURABLE ? "durable" :
        state == DEVICE_PAIRING_DURABILITY_UNKNOWN ? "durability_unknown" : "not_published";
    return json_push_kv_str(data, "publication", name);
}
static bool identity_report(struct json_value *data, const struct device_identity *identity,
    const struct device_identity_publication_report *report, bool create)
{
    const char *state = report->state == DEVICE_IDENTITY_DURABLE ? "durable" :
        report->state == DEVICE_IDENTITY_DURABILITY_UNKNOWN ? "durability_unknown" : "not_published";
    if (!json_push_kv_str(data, "identity_publication", state) ||
        !json_push_kv_bool(data, "public_key_known", report->public_key_known) ||
        !json_push_kv_bool(data, "observation_only", !create)) return false;
    if (!report->public_key_known) return true;
    uint8_t fingerprint[32];
    const uint8_t *key = report->public_key;
    (void)identity;
    return v2_identity_public_fingerprint(key, fingerprint) &&
        put_hex(data, "public_key", key) && put_hex(data, "fingerprint", fingerprint);
}
static bool capability(const struct json_value *input, bool required, uint64_t *mask)
{
    const struct json_value *value = json_get(input, "capability");
    if (!value) { *mask = DEVICE_PAIRING_CAP_STATUS_READ; return !required; }
    if (value->type != JSON_STR) return false;
    const char *text = json_get_str(value);
    if (!strcmp(text, "status-read")) *mask = DEVICE_PAIRING_CAP_STATUS_READ;
    else if (!strcmp(text, "guest-stream")) *mask = DEVICE_PAIRING_CAP_GUEST_STREAM;
    else if (!strcmp(text, "status-read+guest-stream"))
        *mask = DEVICE_PAIRING_CAP_STATUS_READ | DEVICE_PAIRING_CAP_GUEST_STREAM;
    else return false;
    return true;
}
static bool expiry(const struct json_value *input, bool required, uint64_t now, uint64_t *out)
{
    const struct json_value *value = json_get(input, "expires_at");
    if (!now) return false;
    if (!value) { *out = now + 604800; return !required; }
    if (value->type != JSON_INT || json_get_int(value) <= 0) return false;
    *out = (uint64_t)json_get_int(value);
    return *out > now && *out - now <= UINT64_C(2592000);
}
struct device_proposal {
    struct device_pairing_store store;
    struct db_device_pairing row;
    uint8_t fingerprint[32];
};
static bool proposal_read(const struct json_value *input, const struct device_identity *identity,
    bool commit, struct device_proposal *proposal)
{
    memset(proposal, 0, sizeof(*proposal));
    proposal->row.paired_at = device_now();
    if (!hex_input(input, "peer_key", proposal->row.peer_key) ||
        !capability(input, commit, &proposal->row.capabilities) ||
        !expiry(input, commit, proposal->row.paired_at, &proposal->row.expires_at)) return false;
    if (!device_identity_pair_store(identity, proposal->row.peer_key, &proposal->store).ok)
        return false;
    memcpy(proposal->row.profile, proposal->store.profile, 32);
    memcpy(proposal->row.local_key, identity->public_key, 32);
    struct ar_errors errors;
    return db_device_pairing_validate(&proposal->row, &errors) &&
        v2_identity_public_fingerprint(proposal->row.peer_key, proposal->fingerprint);
}
static bool proposal_emit(struct json_value *data, const struct device_proposal *proposal)
{
    return put_hex(data, "peer_key", proposal->row.peer_key) &&
        put_hex(data, "peer_fingerprint", proposal->fingerprint) &&
        put_hex(data, "profile", proposal->row.profile) &&
        json_push_kv_int(data, "capabilities", (int64_t)proposal->row.capabilities) &&
        json_push_kv_int(data, "expires_at", (int64_t)proposal->row.expires_at) &&
        json_push_kv_str(data, "required_prior_state", "absent") &&
        json_push_kv_bool(data, "absence_observed", false);
}
static bool commit_proposal(const struct json_value *input, struct device_proposal *proposal,
    struct zcl_command_reply *reply)
{
    uint8_t confirmed[32];
    const char *expected = json_get_str(json_get(input, "expected_root"));
    if (!expected || strcmp(expected, "absent") ||
        !hex_input(input, "fingerprint", confirmed) || memcmp(confirmed, proposal->fingerprint, 32))
        return device_fail(reply, "commit requires independently confirmed fingerprint and expected_root=absent", false);
    enum device_pairing_publication state = DEVICE_PAIRING_NOT_PUBLISHED;
    bool ok = db_device_pairing_insert(&proposal->store, &proposal->row, confirmed, &state);
    reply->error.mutated = true; /* Completed save or conservatively unknown effects. */
    bool emitted = publication(&reply->data, state);
    if (!ok) return device_fail(reply, "insert refused or interrupted; existing grants never change, reconcile publication", true);
    if (!emitted || !json_push_kv_bool(&reply->data, "committed", true))
        return device_fail(reply, "grant inserted but result serialization failed; inspect before retry", true);
    return true;
}
static bool pairing_action(const char *action, const struct json_value *input,
    const struct device_identity *identity, struct zcl_command_reply *reply)
{
    bool commit = !strcmp(action, "commit");
    if (zcl_native_device_host_requested(input))
        return zcl_native_device_host_pairing(input, identity, commit, reply);
    struct device_proposal proposal;
    if (!proposal_read(input, identity, commit, &proposal))
        return device_fail(reply, "peer_key, explicit supported capability and future expires_at within 30 days required", false);
    if (!proposal_emit(&reply->data, &proposal)) return false;
    if (commit) return commit_proposal(input, &proposal, reply);
    return json_push_kv_bool(&reply->data, "committed", false) &&
        json_push_kv_bool(&reply->data, "defaults_are_proposals", true);
}
static bool revoke_emit(struct json_value *data, const struct db_device_pairing *row,
    const uint8_t root[32], bool approval)
{
    if (row->revoked_at > INT64_MAX || row->expires_at > INT64_MAX) return false;
    return put_hex(data, approval ? "inspected_prior_root" : "expected_root", root) &&
        put_hex(data, "peer_key", row->peer_key) &&
        json_push_kv_int(data, "capabilities", (int64_t)row->capabilities) &&
        json_push_kv_int(data, "expires_at", (int64_t)row->expires_at) &&
        json_push_kv_int(data, "inspected_revoked_at", (int64_t)row->revoked_at);
}
static bool revoke_publish(const struct json_value *input, struct device_pairing_store *store,
    const uint8_t peer[32], struct zcl_command_reply *reply)
{
    uint8_t expected[32], confirmed[32], fingerprint[32];
    if (!hex_input(input, "expected_root", expected) || !hex_input(input, "fingerprint", confirmed) ||
        !v2_identity_public_fingerprint(peer, fingerprint) || memcmp(confirmed, fingerprint, 32))
        return device_fail(reply, "revoke requires independently confirmed fingerprint and exact inspected expected_root", false);
    enum device_pairing_publication state = DEVICE_PAIRING_NOT_PUBLISHED;
    bool ok = db_device_pairing_revoke_expected(store, peer, device_now(), expected, &state);
    reply->error.mutated = true;
    bool emitted = publication(&reply->data, state);
    if (!ok) return device_fail(reply, "exact-root revocation refused or interrupted; inspect before retry", true);
    if (!emitted || !json_push_kv_bool(&reply->data, "committed", true))
        return device_fail(reply, "grant revoked but result serialization failed; inspect before retry", true);
    return true;
}
static bool revoke_action(const struct json_value *input, const struct device_identity *identity,
    struct zcl_command_reply *reply)
{
    uint8_t peer[32], root[32];
    struct device_pairing_store store;
    struct db_device_pairing row;
    bool approval = json_get(input, "fingerprint") != NULL;
    bool expected = json_get(input, "expected_root") != NULL;
    if (approval != expected)
        return device_fail(reply, "fingerprint and expected_root must be supplied together", false);
    if (!hex_input(input, "peer_key", peer) || !device_identity_pair_store(identity, peer, &store).ok ||
        !db_device_pairing_inspect(&store, peer, &row, root))
        return device_fail(reply, "existing exact grant required for revoke inspection", false);
    if (!revoke_emit(&reply->data, &row, root, approval)) return false;
    if (approval) return revoke_publish(input, &store, peer, reply);
    return json_push_kv_bool(&reply->data, "committed", false);
}
static bool device_action(const char *action)
{
    return !strcmp(action, "init") || !strcmp(action, "identity") ||
        !strcmp(action, "plan") || !strcmp(action, "commit") || !strcmp(action, "revoke") ||
        !strcmp(action, "prepare-secret");
}
static bool dispatch_action(const char *action, const struct json_value *input,
    const struct device_identity *identity, struct zcl_command_reply *reply)
{
    if (!strcmp(action, "plan") || !strcmp(action, "commit"))
        return pairing_action(action, input, identity, reply);
    if (!strcmp(action, "revoke")) return revoke_action(input, identity, reply);
    if (!strcmp(action, "prepare-secret")) return zcl_native_device_prepare_secret(input, identity, reply);
    return true;
}
void zcl_native_handle_ops_mesh_device(const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    if (!reply) { LOG_ERROR("native.device", "missing reply"); return; }
    if (!request || !request->spec || !request->input) {
        (void)device_fail(reply, "explicit native device request required", false); return;
    }
    const char *action = strrchr(request->spec->path, '.');
    action = action ? action + 1 : "";
    const char *directory = json_get_str(json_get(request->input, "directory"));
    if (!device_action(action) || !directory || !directory[0]) {
        (void)device_fail(reply, "supported action and explicit trusted private profile required", false); return;
    }
    bool create = !strcmp(action, "init");
    struct device_identity identity = {0};
    struct device_identity_publication_report report;
    struct zcl_result opened = device_identity_open(&identity, directory, create, &report);
    json_set_object(&reply->data);
    bool emitted = identity_report(&reply->data, &identity, &report, create);
    bool mutated = create && report.state != DEVICE_IDENTITY_NOT_PUBLISHED;
    if (!opened.ok) { (void)device_fail(reply, opened.message, mutated); return; }
    bool ok = emitted && dispatch_action(action, request->input, &identity, reply);
    device_identity_close(&identity);
    if (!ok && reply->status != ZCL_COMMAND_STATUS_FAILED)
        (void)device_fail(reply, "cannot serialize bounded device result", mutated || reply->error.mutated);
}
