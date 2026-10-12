/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: Single-owner governed guest execution and measured-work accounting APIs. */
#ifndef ZCL_PLATFORM_GUEST_SERVICE_RUNNER_H
#define ZCL_PLATFORM_GUEST_SERVICE_RUNNER_H
#include "platform/guest_service.h"
#include "rvmachine/rvmachine.h"
/* Single owning drive. No concurrent calls, including stop and destruction.
 * This synchronous boundary creates no thread and grants no activation. */
struct guest_service_runner;
/* The factory consumes config->disk only once machine creation succeeds,
 * including a later kernel-load failure; disk_consumed reports that boundary. */
struct guest_service_runner_snapshot {
    bool stopping, in_slice, returned, accounting_pending;
    uint64_t slices;
    enum rvmachine_status status;
    struct rvmachine_result result;
};
enum rvmachine_status guest_service_runner_create(struct guest_service_runner **,
    const struct rvmachine_config *, const uint8_t *, size_t,
    const struct guest_limits *, bool *disk_consumed);
bool guest_service_runner_destroy(struct guest_service_runner *);
void guest_service_runner_request_stop(struct guest_service_runner *);
enum rvmachine_status guest_service_runner_slice(struct guest_service_runner *,
    uint64_t now_ms, uint64_t previous_slice_us, bool startup,
    struct guest_gov_decision *, struct rvmachine_result *);
/* now_ms never decreases. previous_slice_us accounts the preceding returned
 * invocation once, including a failed invocation that performed work. A
 * pending charge requires nonzero measured time (round clock resolution up);
 * validation refusals preserve the obligation. No-run polls require zero.
 * After stop, this same entry accepts the final charge once and returns
 * ERR_STATE with SLEEP/NOT_READY, zero result and accounting_pending=false;
 * it advances no machine time and starts no run. Duplicate positive charges
 * refuse. Destruction refuses while a charge remains pending.
 * SLEEP and ERR_WAITING are
 * not returned guest runs: snapshot.returned is false and result is zero. */
bool guest_service_runner_snapshot(const struct guest_service_runner *,
    struct guest_service_runner_snapshot *);
/* Borrowed machine for the owning device shim. No call during a run or
 * machine callback; ownership and destruction remain with the runner. */
struct rvmachine *guest_service_runner_device(struct guest_service_runner *);
#endif
