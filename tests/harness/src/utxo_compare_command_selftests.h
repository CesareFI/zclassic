/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * Purpose: exercise offline command refusal and public admitted inputs. */
#ifndef ZCL_UTXO_COMPARE_COMMAND_SELFTESTS_H
#define ZCL_UTXO_COMPARE_COMMAND_SELFTESTS_H
#include "command/native_command.h"
#include "utxo_compare_runtime_selftests.h"
#include "utxo_compare_dispatch_selftests.h"
struct ucot_runtime {
    struct zcl_command_cleanup_slot slots[2];
    unsigned reservations;
    bool cancelled;
};
static bool ucot_cancelled(void *context)
{
    return ((struct ucot_runtime *)context)->cancelled;
}
static bool ucot_reserve(void *context, unsigned count, struct zcl_command_cleanup_slot **out)
{
    struct ucot_runtime *r = context;
    if (count != 2 || r->reservations) return false;
    r->reservations++; *out = r->slots; return true;
}
static bool ucot_cleanup(struct ucot_runtime *r)
{
    bool ok = true;
    for (unsigned i = 0; i < 2; i++) {
        struct zcl_command_cleanup_slot *slot = &r->slots[i];
        if (slot->owner && (!slot->release || !slot->release(&slot->owner))) slot->release_failed = true;
        if (slot->owner || slot->release_failed) ok = false;
    }
    return ok;
}
static bool ucot_input(struct json_value *input, const struct csi_fixture *bundle,
                        const char *projection, const char *manifest, const uint8_t digest[32],
                        const uint8_t accepted[32], const char *order)
{
    json_set_object(input);
    return json_push_kv_str(input, "artifact_file", bundle->path) &&
        json_push_kv_str(input, "projection_file", projection) &&
        ucf_push_hash(input, "projection_sha3_256", digest) &&
        json_push_kv_str(input, "producer_byte_order", order) &&
        json_push_kv_str(input, "capture_manifest_file", manifest) &&
        ucf_push_hash(input, "accepted_manifest_sha3_256", accepted) &&
        json_push_kv_int(input, "example_limit", 1);
}
static bool ucot_manifest_file(const char *path, const struct ucf_manifest *manifest)
{
    FILE *file = fopen(path, "wb");
    if (!file) return false;
    bool ok = fwrite(manifest->raw, 1, manifest->length, file) == manifest->length;
    int closed = fclose(file);
    return ok && closed == 0 && chmod(path, 0400) == 0;
}
static bool ucot_expected_failure(const struct zcl_command_reply *reply,
    const struct ucot_runtime *state, bool token, bool unknown)
{
    const char *code = unknown ? "INVALID_INPUT" :
        !token ? "CANCELLATION_UNAVAILABLE" : "COMPARISON_INCOMPLETE";
    unsigned reservations = !unknown && token ? 1 : 0;
    return reply->status == ZCL_COMMAND_STATUS_FAILED &&
        strcmp(reply->error.code, code) == 0 && state->reservations == reservations &&
        json_get(&reply->data, "authority_count") == NULL &&
        json_get(&reply->data, "complete") == NULL;
}
static bool ucot_invoke(struct json_value *input, bool cancellation, bool token, bool unknown)
{
    struct ucot_runtime state = {.cancelled = cancellation};
    struct zcl_command_invocation_runtime runtime = {
        ucot_cancelled, &state, ucot_reserve, &state
    };
    struct zcl_command_context context = {.invocation = token ? &runtime : NULL};
    struct zcl_command_request request = {.context = &context, .input = input};
    struct zcl_command_reply reply;
    zcl_command_reply_init(&reply, "zcl.utxo_compare_offline.v1");
    if (unknown) (void)json_push_kv_bool(input, "manifest_validated", true);
    zcl_native_handle_core_consensus_utxo_compare_offline(&request, &reply);
    const char *comparison = json_get_str(json_get(&reply.data, "comparison"));
    const char *count = json_get_str(json_get(&reply.data, "authority_count"));
    bool failure = cancellation || !token || unknown;
    bool ok = failure ? ucot_expected_failure(&reply, &state, token, unknown) :
        reply.status == ZCL_COMMAND_STATUS_PASSED &&
        comparison && count && strcmp(comparison, "equal") == 0 && strcmp(count, "2") == 0;
    if (!token || unknown) ok = ok && state.reservations == 0;
    ok = ucot_cleanup(&state) && ok;
    if (!ok) fprintf(stderr,
        "offline command fixture: code=%.80s reservations=%u cancelled=%d token=%d unknown=%d\n",
        reply.error.code, state.reservations, cancellation, token, unknown);
    zcl_command_reply_free(&reply); return ok;
}
/* Existing sqlite_pinned_reader test convention: scope one auto-extension,
 * retain a real statement, cancel only our extension, finalize before retry.
 * Do not reset unrelated extensions or corrupt a borrowed descriptor. */
static sqlite3_stmt *ucot_busy_statement;
static unsigned ucot_busy_opens;
static int ucot_hold_artifact_statement(sqlite3 *db, char **error,
                                       const sqlite3_api_routines *api)
{
    (void)error; (void)api;
    ucot_busy_opens++;
    if (ucot_busy_opens != 1) return SQLITE_OK;
    return sqlite3_prepare_v2(db, "SELECT 1", -1, &ucot_busy_statement, NULL);
}
static bool ucot_no_completed_data(const struct zcl_command_reply *reply)
{
    return reply->status == ZCL_COMMAND_STATUS_FAILED &&
        json_get(&reply->data, "complete") == NULL &&
        json_get(&reply->data, "authority_count") == NULL &&
        json_get(&reply->data, "projection_count") == NULL &&
        json_get(&reply->data, "authority_root") == NULL &&
        json_get(&reply->data, "projection_root") == NULL &&
        json_get(&reply->data, "examples") == NULL;
}
static bool ucot_busy_result(bool observed, int finalized, bool released, bool sticky,
    const struct zcl_command_reply *reply, const struct ucot_runtime *state)
{
    bool ok = observed && finalized == SQLITE_OK && released && sticky;
    if (!ok) fprintf(stderr,
        "offline BUSY fixture: code=%.80s reservations=%u opens=%u "
        "observed=%d finalized=%d released=%d sticky=%d\n", reply->error.code,
        state->reservations, ucot_busy_opens, observed, finalized, released, sticky);
    return ok;
}
static bool ucot_busy_invoke(struct json_value *input)
{
    struct ucot_runtime state = {0};
    struct zcl_command_invocation_runtime runtime = {
        ucot_cancelled, &state, ucot_reserve, &state
    };
    struct zcl_command_context context = {.invocation = &runtime};
    struct zcl_command_request request = {.context = &context, .input = input};
    struct zcl_command_reply reply;
    zcl_command_reply_init(&reply, "zcl.utxo_compare_offline.v1");
    ucot_busy_statement = NULL; ucot_busy_opens = 0;
    int registered = sqlite3_auto_extension((void (*)(void))ucot_hold_artifact_statement);
    if (registered == SQLITE_OK)
        zcl_native_handle_core_consensus_utxo_compare_offline(&request, &reply);
    int removed = sqlite3_cancel_auto_extension((void (*)(void))ucot_hold_artifact_statement);
    /* Both readers opened. The first checked artifact close refused while
     * the independent mirror slot was still consumed/released. In the bad
     * manifest case comparator never runs, so mirror NULL witnesses handler
     * cleanup continuing past the first BUSY slot rather than short circuit. */
    void *retained = state.slots[0].owner;
    bool observed = registered == SQLITE_OK && removed == 1 && ucot_busy_opens == 2 &&
        state.reservations == 1 && ucot_busy_statement && retained &&
        state.slots[0].release_failed && state.slots[1].owner == NULL &&
        !state.slots[1].release_failed && ucot_no_completed_data(&reply) &&
        strcmp(reply.error.code, "COMPARISON_CLEANUP_FAILED") == 0;
    if (ucot_busy_statement)
        observed = sqlite3_step(ucot_busy_statement) == SQLITE_ROW && observed;
    int finalized = sqlite3_finalize(ucot_busy_statement); ucot_busy_statement = NULL;
    /* Caller owns slot storage after handler return. Retry once now that
     * the real external statement has been finalized. Sticky failure keeps
     * this invocation invalid even though all physical owners can release. */
    bool cleanup_ok = ucot_cleanup(&state);
    bool released = state.slots[0].owner == NULL && state.slots[1].owner == NULL;
    bool sticky = !cleanup_ok && state.slots[0].release_failed && ucot_no_completed_data(&reply);
    bool ok = ucot_busy_result(observed, finalized, released, sticky, &reply, &state);
    zcl_command_reply_free(&reply);
    return ok;
}
static bool ucot_write_refused_manifest(const char *path, uint8_t accepted[32])
{
    static const char raw[] = "{}";
    if (chmod(path, 0600) != 0) return false;
    FILE *file = fopen(path, "wb");
    if (!file) return false;
    bool wrote = fwrite(raw, 1, sizeof(raw) - 1, file) == sizeof(raw) - 1;
    int closed = fclose(file);
    /* Explicit synthetic test acceptance of malformed bytes is not real
     * capture trust. The public factory must still reject its shape. */
    return wrote && closed == 0 && chmod(path, 0400) == 0 && ucf_file_digest(path, accepted);
}
static bool ucot_both_owner_cleanup(struct json_value *input, const struct csi_fixture *bundle,
    const struct ucf_owners *owners, const char *path, const struct ucf_manifest *manifest)
{
    uint8_t refused_digest[32];
    bool prepared = ucot_write_refused_manifest(path, refused_digest) &&
        ucot_input(input, bundle, owners->path, path, owners->digest, refused_digest, "little");
    bool observed = prepared && ucot_busy_invoke(input);
    /* Restore the exact accepted valid manifest before later command cases,
     * including when the expected refusal observation itself failed. */
    bool writable = chmod(path, 0600) == 0;
    bool restored = writable && ucot_manifest_file(path, manifest) &&
        ucot_input(input, bundle, owners->path, path, owners->digest, manifest->accepted_sha3, "little");
    return observed && restored;
}

static int csi_compare_command_cases(const char *dir, const struct csi_fixture *bundle)
{
    int failures = csi_compare_runtime_cases();
    struct ucf_owners owners = {0}; struct ucf_manifest manifest = {0};
    struct json_value input = {0}; char path[1024] = {0};
    enum utxo_mirror_byte_order order = UTXO_MIRROR_LITTLE_ENDIAN;
    bool ok = ucf_owners_open(&owners, dir, bundle, UCF_EQUAL, order) &&
        ucf_manifest_build(&manifest, owners.authority, owners.projection, UCF_EQUAL) &&
        ucf_manifest_serialize(&manifest, UCF_EQUAL) && ucf_fixture_path(dir, path);
    /* Both construction readers close before creating another parent entry.
     * Keep projection fixture file for the actual command's fresh admission. */
    utxo_copy_capture_free(owners.capture); owners.capture = NULL;
    bool projection_closed = !owners.projection || utxo_mirror_read_snapshot_abort(&owners.projection);
    bool artifact_closed = consensus_state_artifact_evidence_close(&owners.authority);
    ok = ok && projection_closed && artifact_closed;
    if (ok) ok = ucot_manifest_file(path, &manifest) &&
        ucot_input(&input, bundle, owners.path, path, owners.digest, manifest.accepted_sha3, "little");
    CSI_CHECK("offline command public copy fixture prepared", ok);
    if (ok) {
        failures += csi_compare_dispatch_cases(&input, dir);
        CSI_CHECK("offline command retains real BUSY evidence and withholds completed result",
            ucot_busy_invoke(&input));
        CSI_CHECK("offline command releases second reader after first close BUSY on factory refusal",
            ucot_both_owner_cleanup(&input, bundle, &owners, path, &manifest));
        CSI_CHECK("offline command checked cleanup precedes complete equality", ucot_invoke(&input, false, true, false));
        CSI_CHECK("offline command actual token cancellation clears totals", ucot_invoke(&input, true, true, false));
        CSI_CHECK("offline command missing token refuses before reservation", ucot_invoke(&input, false, false, false));
        CSI_CHECK("offline command direct schema rejects trust flag before reservation", ucot_invoke(&input, false, true, true));
    }
    json_free(&input); json_free(&manifest.json);
    if (!owners.projection && !owners.authority) {
        if (path[0]) TEST_DISCARD(unlink(path));
        if (owners.path[0]) TEST_DISCARD(unlink(owners.path));
    }
    return failures;
}
#endif
