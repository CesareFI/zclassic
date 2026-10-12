/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: the run loop and the firmware-call glue. The hart runs in the
 * engine's supervisor profile: a supervisor ecall stops the engine, the host
 * answers it through the SBI handler and acts on what it returns. Time is the
 * retired-instruction count, so a wfi with a timer armed jumps the count to
 * the deadline instead of waiting. */
#include "rvmachine_priv.h"

/* Policy points. The test group recompiles this file as a mutation twin with
 * these replaced, to show that each one is what makes its proof pass. */
#if !defined(RVMACHINE_TWIN_BUILD) && \
    (defined(RVMACHINE_POLICY_SCOUNTEREN) || defined(RVMACHINE_POLICY_RFENCE) || \
     defined(RVMACHINE_POLICY_SERVICE) || defined(RVMACHINE_POLICY_DRAIN) || \
     defined(RVMACHINE_POLICY_DEVICE_CHARGE) || defined(RVMACHINE_POLICY_WAIT_LATCH))
#error "machine policy points may be replaced only by the test twin"
#endif
#ifndef RVMACHINE_POLICY_SCOUNTEREN
#define RVMACHINE_POLICY_SCOUNTEREN RVMACHINE_SCOUNTEREN
#endif
#ifndef RVMACHINE_POLICY_RFENCE
#define RVMACHINE_POLICY_RFENCE true /* a firmware remote fence flushes this hart */
#endif
#ifndef RVMACHINE_POLICY_SERVICE
#define RVMACHINE_POLICY_SERVICE true /* finish capped block work every step */
#endif
#ifndef RVMACHINE_POLICY_DRAIN
#define RVMACHINE_POLICY_DRAIN true /* finish block work before a wfi waits */
#endif

#ifndef RVMACHINE_POLICY_DEVICE_CHARGE
#define RVMACHINE_POLICY_DEVICE_CHARGE true /* device data movement is work */
#endif
#ifndef RVMACHINE_POLICY_WAIT_LATCH
#define RVMACHINE_POLICY_WAIT_LATCH true /* no run while nothing can wake the hart */
#endif

/* Work done: retired instructions, answered firmware calls and device work. */
static uint64_t machine_work(const struct rvmachine *m)
{
    uint64_t work = machine_retired(m) + m->fw_calls;
    return RVMACHINE_POLICY_DEVICE_CHARGE ? work + m->device_work : work;
}

/* Guest time advances with the retired count, one unit per
 * RVMACHINE_TICKS_PER_TIME instructions. */
static void sync_time(struct rvmachine *m)
{
    uint64_t now = machine_now(m);
    uint64_t unit = machine_retired(m) / RVMACHINE_TICKS_PER_TIME + 1u;
    m->hart.time = now;
    if (!m->timer_raised && rvplat_timer_pending(&m->timer, now)) {
        rvemu_set_irq(&m->hart, RVEMU_IRQ_STIP, 1);
        m->timer_raised = true;
    }
    m->sched.sync_at = unit > UINT64_MAX / RVMACHINE_TICKS_PER_TIME
                           ? UINT64_MAX : unit * RVMACHINE_TICKS_PER_TIME;
}

/* Only a retired instruction crossing a time unit, or a change of the skip or
 * of the timer (both made by a stop, which resets sync_at), can change what
 * sync_time computes. */
static bool time_due(const struct rvmachine *m)
{
    return machine_retired(m) >= m->sched.sync_at;
}

/* The deadline a caller may wait for and advance to: the armed timer's,
 * unless it has passed and cannot wake the hart because the timer interrupt
 * is masked in mie. Then nothing is left to wait for and no time is barred. */
static uint64_t wake_deadline(const struct rvmachine *m)
{
    const uint64_t timer_line = UINT64_C(1) << RVEMU_IRQ_STIP;
    if (m->timer.deadline > machine_now(m)) return m->timer.deadline;
    return (m->hart.csr.mie & timer_line) != 0 ? m->timer.deadline : RVMACHINE_NO_DEADLINE;
}

/* Arming (or disarming, with all ones) clears the pending timer interrupt. */
static void timer_set(struct rvmachine *m, uint64_t deadline)
{
    rvplat_timer_set_timer(&m->timer, deadline);
    rvemu_set_irq(&m->hart, RVEMU_IRQ_STIP, 0);
    m->timer_raised = false;
}

static void halt(struct rvmachine *m, enum rvmachine_stop why,
                 const struct rvplat_sbi_ret *r)
{
    m->halted = true;
    m->halt_stop = why;
    m->reset_type = (uint32_t)r->action_args[0];
    m->reset_reason = (uint32_t)r->action_args[1];
}

/* With one hart a remote fence has nothing to flush elsewhere, and an IPI can
 * only name the caller: it raises the supervisor software interrupt. */
static void sbi_act(struct rvmachine *m, const struct rvplat_sbi_ret *r)
{
    switch (r->action) {
    case RVPLAT_SBI_ACTION_TIMER_SET: timer_set(m, r->action_args[0]); break;
    case RVPLAT_SBI_ACTION_CONSOLE_PUT:
        rvmachine_console_put(m, (uint8_t)r->action_args[0]);
        break;
    case RVPLAT_SBI_ACTION_SHUTDOWN: halt(m, RVMACHINE_STOP_SHUTDOWN, r); break;
    case RVPLAT_SBI_ACTION_REBOOT: halt(m, RVMACHINE_STOP_REBOOT, r); break;
    case RVPLAT_SBI_ACTION_IPI: rvemu_set_irq(&m->hart, RVEMU_IRQ_SSIP, 1); break;
    case RVPLAT_SBI_ACTION_RFENCE:
        /* The call selected this hart, which must now behave as if it had
         * executed the fence itself. The engine's translation cache keeps no
         * address ranges or address-space ids, so every form (fence.i,
         * sfence.vma, sfence.vma with an id) is one whole flush: more than
         * fence.i needs, never less than any of them requires. */
        if (RVMACHINE_POLICY_RFENCE) rvemu_tlb_flush(&m->hart);
        break;
    case RVPLAT_SBI_ACTION_CLEAR_IPI:
        rvemu_set_irq(&m->hart, RVEMU_IRQ_SSIP, 0);
        break;
    default: break;
    }
}

static void on_ecall(struct rvmachine *m)
{
    uint64_t *x = m->hart.x;
    struct rvplat_sbi_ret r = rvplat_sbi_call(&m->sbi, x[17], x[16], &x[10]);
    m->fw_calls++;
    sbi_act(m, &r);
    rvemu_ecall_return(&m->hart, (uint64_t)r.error, r.value);
    rvmachine_input_pump(m, false);
    rvmachine_irq_sync(m);
}

/* Finishes left-over device requests before the hart waits, one capped round
 * at a time and never past the work budget. Each round completes at least one
 * request and a waiting hart adds none, so one round per ring entry is
 * enough; a device still pending after that cannot make progress (its driver
 * stopped the queue) and is treated as quiet. True when the hart must not
 * wait yet: work was done and nothing is left, or the budget ran out first. */
static bool drain(struct rvmachine *m)
{
    bool worked = false;
    for (unsigned i = 0; i < RVVIRTIO_QUEUE_MAX && rvmachine_devices_pending(m); i++) {
        if (machine_work(m) >= m->work_limit) return true;
        rvmachine_devices_service(m);
        worked = true;
    }
    return worked && !rvmachine_devices_pending(m);
}

/* The hart waits for a timer that lies `wait` time units ahead and nothing
 * else can wake it. By default guest time jumps there. With wait_stops the
 * run ends instead and the caller moves time; the latch makes the next run
 * wait for the caller to have done something. False when the run ends. */
static bool on_timed_wait(struct rvmachine *m, uint64_t wait, enum rvmachine_stop *why)
{
    m->wfi_stalled = false;
    if (m->wait_stops) {
        m->wait_latched = true;
        *why = RVMACHINE_STOP_WAIT;
        return false;
    }
    m->time_skip = machine_time_add(m->time_skip, wait);
    return true;
}

/* wfi with nothing pending. A timer that lies ahead is waited for (see
 * on_timed_wait), unless bringing the interrupt lines up to date shows the
 * hart can wake now. Otherwise give the engine one more look at the lines; a
 * second stop without a retired instruction means nothing can wake the hart. */
static bool on_wfi(struct rvmachine *m, enum rvmachine_stop *why)
{
    uint64_t wait;
    /* Unfinished device work completes first: its interrupt may be what the
     * hart is waiting for, and time must not jump past it. */
    if (RVMACHINE_POLICY_DRAIN && drain(m)) return true;
    wait = rvplat_timer_next_event(&m->timer, machine_now(m));
    rvmachine_input_pump(m, false);
    rvmachine_irq_sync(m);
    if (wait != UINT64_MAX && wait != 0 && !rvmachine_hart_wakes(m, UINT64_MAX))
        return on_timed_wait(m, wait, why);
    *why = RVMACHINE_STOP_IDLE;
    if (m->wfi_stalled && m->wfi_instret == machine_retired(m)) {
        m->wait_latched = m->wait_stops; /* held to it like a wait stop */
        return false;
    }
    m->wfi_stalled = true;
    m->wfi_instret = machine_retired(m);
    return true;
}

/* True once RVMACHINE_TRAP_STORM steps in a row have retired nothing. */
static bool trap_storm(struct rvmachine *m)
{
    if (machine_retired(m) != m->storm_instret) {
        m->storm_instret = machine_retired(m);
        m->storm_steps = 0;
        return false;
    }
    return ++m->storm_steps >= RVMACHINE_TRAP_STORM;
}

/* Returns false when the run must end, with *why and *engine_stop set. */
static bool on_stop(struct rvmachine *m, enum rvemu_stop s,
                    enum rvmachine_stop *why, unsigned *engine_stop)
{
    if (s == RVEMU_STOP_ECALL) {
        on_ecall(m);
        *why = m->halt_stop;
        return !m->halted;
    }
    if (s == RVEMU_STOP_WFI) return on_wfi(m, why);
    *why = RVMACHINE_STOP_FAULT;
    *engine_stop = (unsigned)s;
    return false;
}

static void fill_result(const struct rvmachine *m, enum rvmachine_stop why,
                        unsigned engine_stop, struct rvmachine_result *r)
{
    r->stop = why;
    r->retired = machine_retired(m);
    r->skip = m->time_skip;
    r->fw_calls = m->fw_calls;
    r->device_work = m->device_work;
    r->guest_time = machine_now(m);
    r->pc = m->hart.pc;
    r->cause = m->hart.csr.scause;
    r->tval = m->hart.csr.stval;
    r->engine_stop = engine_stop;
    r->reset_type = m->reset_type;
    r->reset_reason = m->reset_reason;
    r->timer_deadline = wake_deadline(m);
    r->fetch_hits = m->hart.icache_hit;
    r->fetch_misses = m->hart.icache_miss;
}

void rvmachine_enter(struct rvmachine *m)
{
    rvemu_hart_init_sbi(&m->hart, m->entry_pc);
    m->hart.x[10] = m->entry_a0;
    m->hart.x[11] = m->entry_a1;
    /* Firmware leaves the cycle, time and instret counters readable from user
     * mode; a kernel that never writes scounteren relies on that for its
     * user-level clock. */
    m->hart.csr.scounteren = RVMACHINE_POLICY_SCOUNTEREN;
    m->mem.io_ctx = m;
    m->mem.io_load = rvmachine_io_load;
    m->mem.io_store = rvmachine_io_store;
    rvplat_timer_init(&m->timer, RVMACHINE_TICKS_PER_TIME);
    rvplat_sbi_init(&m->sbi);
    m->sbi.getchar = rvmachine_sbi_getchar;
    m->sbi.ctx = m;
    m->time_skip = 0;
    m->fw_calls = 0;
    m->device_work = 0;
    m->device_moved = 0;
    m->work_limit = 0;
    m->timer_raised = false;
    m->wfi_stalled = false;
    m->storm_steps = 0;
    m->wait_latched = false;
    m->halted = false;
    m->loaded = true;
}

/* Whether a device service round can find work ahead of the next
 * instruction: after a bus access outside RAM (which may notify a device or
 * change its state), or while a device was left with work. Nothing else
 * changes what rvmachine_devices_pending reports. */
static bool service_due(const struct rvmachine *m)
{
    return m->sched.service_owed || m->sched.io_events != m->sched.io_seen;
}

/* One capped round of left-over device work ahead of the next instruction.
 * False when that round used up the budget, so the instruction is not run. */
static bool service_in_budget(struct rvmachine *m)
{
    m->sched.io_seen = m->sched.io_events;
    if (RVMACHINE_POLICY_SERVICE) rvmachine_devices_service(m);
    m->sched.service_owed = rvmachine_devices_pending(m);
    return machine_work(m) < m->work_limit;
}

/* Why a run cannot start, or RVMACHINE_OK. After a wait stop, and with
 * wait_stops after an idle stop, the hart is where it was until something can
 * wake it (rvmachine_wake_check): a run before that would only hand out the
 * same stop again for no work. */
static enum rvmachine_status run_refusal(const struct rvmachine *m,
                                         const struct rvmachine_result *result)
{
    if (m == NULL || result == NULL) return RVMACHINE_ERR_ARG;
    if (!m->loaded || m->halted) return RVMACHINE_ERR_STATE;
    if (m->conport_fault) return RVMACHINE_ERR_PORT;
    if (m->entropy_fault) return RVMACHINE_ERR_ENTROPY;
    if (RVMACHINE_POLICY_WAIT_LATCH && m->wait_latched) return RVMACHINE_ERR_WAITING;
    return RVMACHINE_OK;
}

static enum rvmachine_status callback_fault_status(const struct rvmachine *m)
{
    if (m->entropy_fault) return RVMACHINE_ERR_ENTROPY;
    return m->conport_fault ? RVMACHINE_ERR_PORT : RVMACHINE_OK;
}

/* The work owed ahead of the next instruction: the device round, guest time
 * and the trace. False when the run ends here, with *why set for a failed
 * entropy source; an exhausted budget leaves *why as it was. */
static bool before_step(struct rvmachine *m, enum rvmachine_stop *why)
{
    if (service_due(m)) {
        bool in_budget = service_in_budget(m);
        if (m->entropy_fault) {
            *why = RVMACHINE_STOP_REQUESTED;
            return false;
        }
        if (!in_budget) return false;
    }
    if (time_due(m)) sync_time(m);
    if (m->trace != NULL) m->trace[m->trace_count++ % m->trace_cap] = m->hart.pc;
    return true;
}

/* What follows a step that returned s: stops, the trap storm, a requested
 * stop. False when the run ends, with *why and *engine_stop set. */
static bool after_step(struct rvmachine *m, enum rvemu_stop s,
                       enum rvmachine_stop *why, unsigned *engine_stop)
{
    if (m->entropy_fault) {
        *why = RVMACHINE_STOP_REQUESTED;
        return false;
    }
    if (s != RVEMU_STOP_NONE) {
        /* A stop may move time, arm the timer or change a device. */
        machine_sched_reset(m);
        if (!on_stop(m, s, why, engine_stop)) return false;
    }
    if (s == RVEMU_STOP_NONE && trap_storm(m)) {
        *why = RVMACHINE_STOP_FAULT;
        return false;
    }
    *why = RVMACHINE_STOP_BUDGET;
    if (m->stop_requested) {
        *why = RVMACHINE_STOP_REQUESTED;
        return false;
    }
    return true;
}

enum rvmachine_status rvmachine_run(struct rvmachine *m, uint64_t max_work,
                                    struct rvmachine_result *result)
{
    enum rvmachine_stop why = RVMACHINE_STOP_BUDGET;
    enum rvmachine_status refusal = run_refusal(m, result);
    unsigned engine_stop = 0;
    uint64_t start;
    if (refusal != RVMACHINE_OK) return refusal;
    m->wait_latched = false;
    m->stop_requested = false;
    machine_sched_reset(m);
    start = machine_work(m);
    m->work_limit = max_work > UINT64_MAX - start ? UINT64_MAX : start + max_work;
    while (machine_work(m) < m->work_limit) {
        enum rvemu_stop s;
        if (m->entropy_fault) {
            why = RVMACHINE_STOP_REQUESTED;
            break;
        }
        if (m->conport_fault) return RVMACHINE_ERR_PORT;
        if (!before_step(m, &why)) break;
        s = rvemu_step(&m->hart, &m->mem);
        if (!after_step(m, s, &why, &engine_stop)) break;
    }
    fill_result(m, why, engine_stop, result);
    /* A callback may fail on the final service, instruction or stop. */
    return callback_fault_status(m);
}

_Static_assert(RVMACHINE_NO_DEADLINE == RVPLAT_TIMER_DISARMED,
               "a disarmed timer reads as no deadline");

uint64_t rvmachine_timer_deadline(const struct rvmachine *m)
{
    return m != NULL && m->loaded ? wake_deadline(m) : RVMACHINE_NO_DEADLINE;
}

enum rvmachine_status rvmachine_advance_time(struct rvmachine *m, uint64_t guest_time)
{
    uint64_t now;
    if (m == NULL) return RVMACHINE_ERR_ARG;
    if (!m->loaded || m->halted) return RVMACHINE_ERR_STATE;
    now = machine_now(m);
    if (guest_time < now) return RVMACHINE_ERR_TIME_BACKWARDS;
    if (guest_time == now) return RVMACHINE_OK; /* the present, even with a timer overdue */
    if (guest_time > wake_deadline(m)) return RVMACHINE_ERR_TIME_PAST_DEADLINE;
    m->time_skip = machine_time_add(m->time_skip, guest_time - now);
    sync_time(m); /* a timer now due raises its line */
    rvmachine_wake_check(m);
    return RVMACHINE_OK;
}
