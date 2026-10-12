/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: Executes bounded guest slices and settles measured invocation charges. */
#include "platform/guest_service_runner.h"
#include "base/safe_alloc.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
struct guest_service_runner {
    struct rvmachine *machine;
    struct guest_governor governor;
    struct guest_service_runner_snapshot observation;
    bool waiting;
    uint64_t wait_since_ms, wait_guest_time;
    bool clock_started;
    uint64_t last_now_ms;
};
static enum rvmachine_status runner_fail(enum rvmachine_status status,
    const char *message)
{
    fprintf(stderr, "guest runner: %s\n", message);
    return status;
}
static bool runner_factory_input_ok(struct guest_service_runner **out,
    const struct rvmachine_config *config, const uint8_t *kernel, size_t length,
    const struct guest_limits *limits, const bool *disk_consumed)
{
    return out && config && kernel && length && limits && config->wait_stops &&
        (!config->disk || disk_consumed);
}
enum rvmachine_status guest_service_runner_create(struct guest_service_runner **out,
    const struct rvmachine_config *config, const uint8_t *kernel, size_t length,
    const struct guest_limits *limits, bool *disk_consumed)
{
    if (out) *out = NULL;
    if (disk_consumed) *disk_consumed = false;
    if (!runner_factory_input_ok(out,
        config, kernel, length, limits, disk_consumed))
        return runner_fail(RVMACHINE_ERR_ARG, "invalid bounded factory input");
    struct guest_service_runner *r = zcl_calloc(1, sizeof(*r), "guest service runner");
    if (!r) return runner_fail(RVMACHINE_ERR_NOMEM, "allocation failed");
    if (!guest_governor_init(&r->governor, limits)) {
        free(r);
        return runner_fail(RVMACHINE_ERR_ARG, "governor limits refused");
    }
    enum rvmachine_status status = rvmachine_create(&r->machine, config);
    if (status == RVMACHINE_OK && disk_consumed) *disk_consumed = config->disk != NULL;
    if (status == RVMACHINE_OK)
        status = rvmachine_load_kernel(r->machine, kernel, length);
    if (status != RVMACHINE_OK) {
        if (r->machine) rvmachine_destroy(r->machine);
        free(r);
        return runner_fail(status, "machine factory or kernel refused");
    }
    *out = r;
    return RVMACHINE_OK;
}
bool guest_service_runner_destroy(struct guest_service_runner *r)
{
    if (!r) return true;
    if (r->observation.in_slice || r->observation.accounting_pending) {
        (void)runner_fail(RVMACHINE_ERR_STATE, "destruction before run return or final charge");
        return false;
    }
    rvmachine_destroy(r->machine);
    free(r);
    return true;
}
void guest_service_runner_request_stop(struct guest_service_runner *r)
{
    if (r) r->observation.stopping = true;
}
static uint64_t runner_deadline(const struct rvmachine *m)
{
    uint64_t deadline = rvmachine_timer_deadline(m), now = rvmachine_time(m);
    if (deadline == RVMACHINE_NO_DEADLINE) return GUEST_GOV_NO_DEADLINE;
    if (deadline <= now) return 0;
    uint64_t ticks = deadline - now;
    return ticks / (RVMACHINE_TIMEBASE_HZ / 1000u) +
        (ticks % (RVMACHINE_TIMEBASE_HZ / 1000u) != 0);
}
static enum rvmachine_status runner_advance_wait(struct guest_service_runner *r, uint64_t now)
{
    if (!r->observation.stopping && r->waiting && now >= r->wait_since_ms) {
        uint64_t deadline = rvmachine_timer_deadline(r->machine);
        uint64_t elapsed = now - r->wait_since_ms;
        uint64_t tick_ms = RVMACHINE_TIMEBASE_HZ / 1000u;
        if (deadline != RVMACHINE_NO_DEADLINE && deadline >= r->wait_guest_time &&
            elapsed >= (deadline - r->wait_guest_time) / tick_ms +
                ((deadline - r->wait_guest_time) % tick_ms != 0)) {
            enum rvmachine_status advanced = rvmachine_advance_time(r->machine, deadline);
            if (advanced != RVMACHINE_OK)
                return runner_fail(advanced, "wait time advance refused");
            r->waiting = false;
        }
    }
    return RVMACHINE_OK;
}
static enum rvmachine_status runner_run_slice(struct guest_service_runner *r,
    uint64_t now, const struct guest_gov_decision *decision, struct rvmachine_result *result)
{
    r->observation.in_slice = true;
    r->observation.returned = false;
    enum rvmachine_status status = rvmachine_run(r->machine, decision->work, result);
    r->observation.accounting_pending = status != RVMACHINE_ERR_WAITING;
    r->observation.in_slice = false;
    r->observation.returned = status == RVMACHINE_OK;
    r->observation.status = status;
    r->observation.slices++;
    memset(&r->observation.result, 0, sizeof(r->observation.result));
    if (status == RVMACHINE_OK) r->observation.result = *result;
    if (status == RVMACHINE_OK &&
        (result->stop == RVMACHINE_STOP_WAIT || result->stop == RVMACHINE_STOP_IDLE)) {
        r->waiting = true;
        r->wait_since_ms = now;
        r->wait_guest_time = rvmachine_time(r->machine);
    } else if (status == RVMACHINE_OK) r->waiting = false;
    if (status != RVMACHINE_OK && status != RVMACHINE_ERR_WAITING)
        return runner_fail(status, "machine slice failed");
    return status;
}
static enum rvmachine_status runner_slice_clock(struct guest_service_runner *r,
    uint64_t now, uint64_t previous_us)
{
    if ((r->clock_started && now < r->last_now_ms) ||
        (r->observation.accounting_pending != (previous_us != 0)))
        return runner_fail(RVMACHINE_ERR_ARG, "reversed clock or repeated slice accounting");
    r->clock_started = true;
    r->last_now_ms = now;
    return RVMACHINE_OK;
}
enum rvmachine_status guest_service_runner_slice(struct guest_service_runner *r,
    uint64_t now, uint64_t previous_us, bool startup,
    struct guest_gov_decision *decision, struct rvmachine_result *result)
{
    if (decision) memset(decision, 0, sizeof(*decision));
    if (result) memset(result, 0, sizeof(*result));
    if (!r || r->observation.in_slice)
        return runner_fail(RVMACHINE_ERR_ARG, "invalid or reentrant slice");
    r->observation.returned = false;
    memset(&r->observation.result, 0, sizeof(r->observation.result));
    if (!decision || !result)
        return runner_fail(RVMACHINE_ERR_ARG, "missing slice output");
    enum rvmachine_status checked = runner_slice_clock(r, now, previous_us);
    if (checked != RVMACHINE_OK) return checked;
    enum rvmachine_status advanced = runner_advance_wait(r, now);
    if (advanced != RVMACHINE_OK) return advanced;
    bool pending = !r->observation.stopping &&
        (rvmachine_pending(r->machine) & RVMACHINE_PENDING_RUNNABLE) != 0;
    uint64_t deadline = r->observation.stopping ? GUEST_GOV_NO_DEADLINE :
        (r->waiting ? runner_deadline(r->machine) : 0);
    if (!guest_governor_next(&r->governor, now, previous_us,
        deadline, pending, startup, decision))
        return runner_fail(RVMACHINE_ERR_STATE, "governor refused slice");
    r->observation.accounting_pending = false;
    if (r->observation.stopping) {
        *decision = (struct guest_gov_decision){ .kind = GUEST_GOV_SLEEP,
            .reason = GUEST_SLEEP_NOT_READY };
        return runner_fail(RVMACHINE_ERR_STATE, "runner stopped; final charge settled, no run");
    }
    if (decision->kind == GUEST_GOV_SLEEP) return RVMACHINE_OK;
    return runner_run_slice(r, now, decision, result);
}
bool guest_service_runner_snapshot(const struct guest_service_runner *r,
    struct guest_service_runner_snapshot *out)
{
    if (!r || !out) {
        (void)runner_fail(RVMACHINE_ERR_ARG, "invalid snapshot");
        return false;
    }
    *out = r->observation;
    return true;
}
struct rvmachine *guest_service_runner_device(struct guest_service_runner *r)
{
    return r && !r->observation.in_slice ? r->machine : NULL;
}
