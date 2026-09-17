/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: The `fleet` leaves' handlers — the owner's private fleet ledger.
 * Each answers from local files under the datadir and contacts no peer. */

#ifndef ZCL_NATIVE_FLEET_H
#define ZCL_NATIVE_FLEET_H

struct zcl_command_request;
struct zcl_command_reply;

void zcl_native_handle_fleet_ledger_add(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_fleet_ledger_status(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_fleet_usage(const struct zcl_command_request *request,
                                   struct zcl_command_reply *reply);
void zcl_native_handle_fleet_vitals_sample(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_fleet_experiment_predict(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_fleet_experiment_result(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_fleet_experiment_stats(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_fleet_experiment_export(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_fleet_roles_list(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_fleet_roles_grant(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_fleet_roles_revoke(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_fleet_link_probe(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_fleet_roles_check(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);

/* fleet.steer.* — the thin remote-STEER adapter over mail, queue, board and
 * receipts (tools/command/native_fleet_steer.c). Brief/send/evidence compose
 * sibling leaves in-process; the grant leaf mints and revokes the
 * adapter's own scoped bearer grants. */
void zcl_native_handle_fleet_steer_brief(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_fleet_steer_send(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_fleet_steer_evidence(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_fleet_steer_grant(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);

/* The one shared reader of <state>/steer/grants.jsonl by LABEL. Returns NULL
 * when a live (not revoked, not expired) grant carries `label` and `scope`,
 * otherwise the fail-closed STEER_GRANT_* reason for the closest matching
 * row ("STEER_GRANT_UNKNOWN" when no row carries the label at all, including
 * when there is no store yet). The store is re-read on every call, so a
 * revoke takes effect immediately. A label is a name the owner minted a
 * grant under, never a credential: this answers only "has the owner named
 * this sender", and grants no fleet.steer verb to the caller. Callers that
 * must not write anything are safe — this never creates the steer directory.
 * Implemented in tools/command/native_fleet_steer.c beside the store it
 * reads, so no second permission system can drift away from it. */
const char *zcl_fleet_steer_grant_label_live(const char *label,
                                             const char *scope);

#endif /* ZCL_NATIVE_FLEET_H */
