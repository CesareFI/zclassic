/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Select an independent ZCODE work peer for async proof. */

#ifndef ZCL_CONFIG_BOOT_ZCODE_ASYNC_SELECT_H
#define ZCL_CONFIG_BOOT_ZCODE_ASYNC_SELECT_H

#include <stdbool.h>
#include <stdint.h>

struct db_build_job;
struct db_build_proof_event;
struct vcs_zcode_work_capability_v1;
struct vcs_zcode_work_node;

/* True when the event names a work session that is no longer live. Session
 * ids never return, so nothing can answer the request there any more. */
bool boot_zcode_async_session_lost(
    struct vcs_zcode_work_node *work,
    const struct db_build_proof_event *event);
/* True when the request can no longer be answered where it was sent: its
 * lease is over or its session is gone. */
bool boot_zcode_async_needs_retry(
    struct vcs_zcode_work_node *work,
    const struct db_build_proof_event *event, int64_t now);
bool boot_zcode_async_select_peer(
    struct vcs_zcode_work_node *work,
    const struct db_build_proof_event *event,
    const struct db_build_job *job, uint8_t work_kind, int64_t now,
    uint64_t *peer_out, struct vcs_zcode_work_capability_v1 *capability_out);
/* Returns the next_action it logged: `z23 join` when no capable worker
 * exists, otherwise the toolchain compare. Never a flag recitation. */
const char *boot_zcode_async_log_no_peer(
    struct vcs_zcode_work_node *work, const struct db_build_job *job,
    const char *action_id, int64_t now);

#endif /* ZCL_CONFIG_BOOT_ZCODE_ASYNC_SELECT_H */
