/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: pure guest service decisions - the lifecycle state machine and the
 * CPU governor. No guest, machine, thread, clock, I/O, logging or allocation. */
#include "platform/guest_service.h"

#define COUNT_OF(a) (sizeof(a) / sizeof((a)[0]))

/* ---- names ------------------------------------------------------------ */

static const char *const k_state_names[GUEST_STATE_COUNT] = {
    [GUEST_STATE_ABSENT] = "absent",
    [GUEST_STATE_STARTING] = "starting",
    [GUEST_STATE_READY] = "ready",
    [GUEST_STATE_SERVING] = "serving",
    [GUEST_STATE_IDLE] = "idle",
    [GUEST_STATE_STOPPING] = "stopping",
    [GUEST_STATE_FAILED] = "failed",
    [GUEST_STATE_ABANDONED] = "abandoned",
};

static const char *const k_event_names[GUEST_EV_COUNT] = {
    [GUEST_EV_ENABLE] = "enable",
    [GUEST_EV_PEER_OPEN] = "peer_open",
    [GUEST_EV_OPERATOR_START] = "operator_start",
    [GUEST_EV_OPERATOR_RESET] = "operator_reset",
    [GUEST_EV_BOOT_READY] = "boot_ready",
    [GUEST_EV_BOOT_FAILED] = "boot_failed",
    [GUEST_EV_START_REFUSED] = "start_refused",
    [GUEST_EV_PORT_OPENED] = "port_opened",
    [GUEST_EV_PORT_CLOSED] = "port_closed",
    [GUEST_EV_REVOKED_ALL] = "revoked_all",
    [GUEST_EV_REVOKED_PEER] = "revoked_peer",
    [GUEST_EV_SLOT_BOUND] = "slot_bound",
    [GUEST_EV_GUEST_STOPPED] = "guest_stopped",
    [GUEST_EV_CALLBACK_OVERRUN] = "callback_overrun",
    [GUEST_EV_TICK] = "tick",
};

static const char *const k_reason_names[GUEST_REASON_COUNT] = {
    [GUEST_REASON_NONE] = "none",
    [GUEST_REASON_DISABLED] = "disabled",
    [GUEST_REASON_STARTING] = "starting",
    [GUEST_REASON_BACKOFF] = "backoff",
    [GUEST_REASON_FAILED] = "failed_until_operator_reset",
    [GUEST_REASON_STOPPING] = "stopping",
    [GUEST_REASON_ABANDONED] = "abandoned_until_operator_reset",
    [GUEST_REASON_PORT_LIMIT] = "port_limit",
    [GUEST_REASON_SESSIONS_FULL] = "sessions_full",
    [GUEST_REASON_PEER_ALREADY_BOUND] = "peer_already_bound",
    [GUEST_REASON_PEER_NOT_BOUND] = "peer_not_bound",
    [GUEST_REASON_SLOT_NOT_UNBOUND] = "slot_not_unbound",
    [GUEST_REASON_GUEST_NOT_JOINED] = "guest_not_joined",
    [GUEST_REASON_BOOT_FAILED] = "boot_failed",
    [GUEST_REASON_STARTUP_DEADLINE] = "startup_deadline",
    [GUEST_REASON_GUEST_EXITED_EARLY] = "guest_exited_during_boot",
    [GUEST_REASON_NOT_SEEDED] = "not_seeded",
    [GUEST_REASON_INJECT_FAILED] = "inject_failed",
    [GUEST_REASON_CALLBACK_OVERRUN] = "callback_overrun",
    [GUEST_REASON_GUEST_CRASHED] = "guest_stopped_unexpectedly",
    [GUEST_REASON_IDLE_TIMEOUT] = "idle_timeout",
    [GUEST_REASON_REVOKED] = "revoked",
    [GUEST_REASON_DISABLED_WHILE_RUNNING] = "disabled_while_running",
    [GUEST_REASON_STOP_JOIN_TIMEOUT] = "stop_join_timeout",
    [GUEST_REASON_TIME_JUMP_CLAMPED] = "time_jump_clamped",
    [GUEST_REASON_IGNORED_STATE] = "ignored_wrong_state",
    [GUEST_REASON_IGNORED_RUNNING] = "ignored_already_running",
    [GUEST_REASON_IGNORED_NO_CHANGE] = "ignored_no_change",
    [GUEST_REASON_IGNORED_NO_PORT] = "ignored_no_port_open",
    [GUEST_REASON_IGNORED_UNKNOWN_PEER] = "ignored_unknown_peer",
    [GUEST_REASON_IGNORED_BAD_EVENT] = "ignored_bad_event",
    [GUEST_REASON_IGNORED_TICK] = "ignored_tick_nothing_due",
};

static const char *const k_action_names[] = {
    [GUEST_ACTION_NONE] = "none",
    [GUEST_ACTION_START_GUEST] = "start_guest",
    [GUEST_ACTION_STOP_GUEST] = "stop_guest",
    [GUEST_ACTION_ANSWER_UNAVAILABLE] = "answer_unavailable",
};

static const char *const k_sleep_names[GUEST_SLEEP_REASON_COUNT] = {
    [GUEST_SLEEP_NONE] = "none",
    [GUEST_SLEEP_DUTY_CEILING] = "duty_ceiling",
    [GUEST_SLEEP_SLICE_RATE] = "slice_rate",
    [GUEST_SLEEP_IDLE_UNTIL_DEADLINE] = "idle_until_deadline",
    [GUEST_SLEEP_IDLE_UNTIL_INPUT] = "idle_until_input",
    [GUEST_SLEEP_NOT_READY] = "governor_not_ready",
};

static const char *name_of(const char *const *table, size_t n, unsigned v)
{
    return v < n && table[v] ? table[v] : "unknown";
}

const char *guest_state_name(enum guest_state state)
{
    return name_of(k_state_names, GUEST_STATE_COUNT, (unsigned)state);
}

const char *guest_event_name(enum guest_event_kind kind)
{
    return name_of(k_event_names, GUEST_EV_COUNT, (unsigned)kind);
}

const char *guest_reason_name(enum guest_reason reason)
{
    return name_of(k_reason_names, GUEST_REASON_COUNT, (unsigned)reason);
}

const char *guest_action_name(enum guest_action_kind kind)
{
    return name_of(k_action_names, COUNT_OF(k_action_names), (unsigned)kind);
}

const char *guest_sleep_reason_name(enum guest_sleep_reason reason)
{
    return name_of(k_sleep_names, GUEST_SLEEP_REASON_COUNT, (unsigned)reason);
}

/* ---- lifecycle -------------------------------------------------------- */

typedef void (*event_fn)(struct guest_service *s, const struct guest_event *ev,
                         uint64_t now, struct guest_action *out);

/* Subtraction form; a `since` ahead of `now` is no time elapsed. */
static uint64_t elapsed_ms(uint64_t now, uint64_t since)
{
    return now >= since ? now - since : 0;
}

static bool guest_alive(const struct guest_service *s)
{
    return s->state >= GUEST_STATE_STARTING && s->state <= GUEST_STATE_IDLE;
}

static bool guest_up(const struct guest_service *s)
{
    return s->state >= GUEST_STATE_READY && s->state <= GUEST_STATE_IDLE;
}

static void act_ignore(struct guest_action *out, enum guest_reason why)
{
    out->kind = GUEST_ACTION_NONE;
    out->reason = why;
}

static void act_refuse(struct guest_action *out, enum guest_reason why,
                       uint64_t retry_ms)
{
    out->kind = GUEST_ACTION_ANSWER_UNAVAILABLE;
    out->reason = why;
    out->retry_after_ms = retry_ms;
    out->answer_unavailable = true;
}

/* Slots: UNBOUND, BOUND(peer) or RETIRED, fixed for the guest instance. */
static int slot_of(const struct guest_service *s, uint32_t peer,
                   enum guest_slot_state want)
{
    for (uint32_t i = 0; i < GUEST_SERVICE_MAX_SESSIONS; i++)
        if (s->slot_state[i] == want && s->slot_peer[i] == peer) return (int)i;
    return -1;
}

/* A slot of this peer that is BOUND or RETIRED: the peer already has its one. */
static bool peer_has_slot(const struct guest_service *s, uint32_t peer)
{
    return slot_of(s, peer, GUEST_SLOT_BOUND) >= 0 ||
           slot_of(s, peer, GUEST_SLOT_RETIRED) >= 0;
}

static uint32_t slots_in(const struct guest_service *s, enum guest_slot_state st)
{
    uint32_t n = 0;

    for (uint32_t i = 0; i < GUEST_SERVICE_MAX_SESSIONS; i++)
        if (s->slot_state[i] == st) n++;
    return n;
}

static void clear_ports(struct guest_service *s)
{
    s->ports = 0;
    for (uint32_t i = 0; i < GUEST_SERVICE_MAX_SESSIONS; i++) s->slot_ports[i] = 0;
}

/* A new guest instance: every slot is UNBOUND again. */
static void reset_slots(struct guest_service *s)
{
    clear_ports(s);
    for (uint32_t i = 0; i < GUEST_SERVICE_MAX_SESSIONS; i++) {
        s->slot_state[i] = GUEST_SLOT_UNBOUND;
        s->slot_peer[i] = 0;
    }
}

static void begin_stop(struct guest_service *s, struct guest_action *out,
                       enum guest_reason why, uint64_t now)
{
    s->state = GUEST_STATE_STOPPING;
    s->stop_since_ms = now;
    s->stop_counted = false;
    s->overrun_count = 0;
    clear_ports(s);
    out->kind = GUEST_ACTION_STOP_GUEST;
    out->reason = why;
}

void guest_service_init(struct guest_service *s)
{
    if (!s) return;
    *s = (struct guest_service){ .state = GUEST_STATE_ABSENT };
}

uint64_t guest_service_backoff_ms(uint32_t failures)
{
    uint64_t ms = GUEST_SERVICE_BACKOFF_BASE_MS;

    if (failures == 0) return 0;
    for (uint32_t i = 1; i < failures; i++) {
        if (ms >= GUEST_SERVICE_BACKOFF_CAP_MS / 2) return GUEST_SERVICE_BACKOFF_CAP_MS;
        ms *= 2;
    }
    return ms < GUEST_SERVICE_BACKOFF_CAP_MS ? ms : GUEST_SERVICE_BACKOFF_CAP_MS;
}

static uint64_t backoff_left(const struct guest_service *s, uint64_t now)
{
    uint64_t el;

    if (s->backoff_len_ms == 0) return 0;
    el = elapsed_ms(now, s->backoff_from_ms);
    return el < s->backoff_len_ms ? s->backoff_len_ms - el : 0;
}

static void prune_recent(struct guest_service *s, uint64_t now)
{
    uint32_t keep = 0;

    for (uint32_t i = 0; i < s->recent_count; i++)
        if (elapsed_ms(now, s->recent_ms[i]) < GUEST_SERVICE_FAIL_WINDOW_MS)
            s->recent_ms[keep++] = s->recent_ms[i];
    s->recent_count = keep;
}

/* Count one failure. The 4th inside the rolling hour ends in FAILED, the
 * others in the backoff. A guest that is still running is stopped first: the
 * outcome waits in STOPPING (join deadline applies) for GUEST_STOPPED. A
 * guest that is already gone settles at once. */
static bool count_failure(struct guest_service *s, uint64_t now,
                          enum guest_reason why)
{
    bool fatal;

    prune_recent(s, now);
    s->last_failure = why;
    if (s->generation < UINT32_MAX) s->generation++;
    fatal = s->recent_count >= GUEST_SERVICE_FAIL_LIMIT;
    if (!fatal) {
        s->recent_ms[s->recent_count++] = now;
        s->backoff_from_ms = now;
        s->backoff_len_ms = guest_service_backoff_ms(s->recent_count);
    }
    return fatal;
}

static void note_failure(struct guest_service *s, uint64_t now,
                         enum guest_reason why, struct guest_action *out,
                         bool guest_gone)
{
    bool fatal = count_failure(s, now, why);

    s->pending_failed = fatal;
    if (!guest_gone) {
        begin_stop(s, out, why, now);
        s->stop_counted = true;
        return;
    }
    clear_ports(s);
    s->overrun_count = 0;
    s->pending_failed = false;
    s->state = fatal ? GUEST_STATE_FAILED : GUEST_STATE_ABSENT;
    out->reason = why;
}

static void ev_enable(struct guest_service *s, const struct guest_event *ev,
                      uint64_t now, struct guest_action *out)
{
    if (ev->enable == s->enabled) {
        act_ignore(out, GUEST_REASON_IGNORED_NO_CHANGE);
        return;
    }
    s->enabled = ev->enable;
    if (!s->enabled && guest_alive(s))
        begin_stop(s, out, GUEST_REASON_DISABLED_WHILE_RUNNING, now);
}

static void open_absent(struct guest_service *s, uint64_t now, bool from_peer,
                        struct guest_action *out)
{
    uint64_t left = backoff_left(s, now);

    if (left > 0) {
        act_refuse(out, GUEST_REASON_BACKOFF, left);
        return;
    }
    s->state = GUEST_STATE_STARTING;
    s->state_since_ms = now;
    s->joined = false;
    reset_slots(s);
    out->kind = GUEST_ACTION_START_GUEST;
    if (from_peer) {
        out->reason = GUEST_REASON_STARTING;
        out->answer_unavailable = true;
    }
}

static void open_running(const struct guest_service *s, const struct guest_event *ev,
                         bool from_peer, struct guest_action *out)
{
    if (!from_peer)
        act_ignore(out, GUEST_REASON_IGNORED_RUNNING);
    else if (s->state == GUEST_STATE_STARTING)
        act_refuse(out, GUEST_REASON_STARTING, 0);
    else if (slot_of(s, ev->peer, GUEST_SLOT_RETIRED) >= 0)
        act_refuse(out, GUEST_REASON_PEER_ALREADY_BOUND, 0);
    else if (slot_of(s, ev->peer, GUEST_SLOT_BOUND) < 0 &&
             slots_in(s, GUEST_SLOT_UNBOUND) == 0)
        act_refuse(out, GUEST_REASON_SESSIONS_FULL, 0);
    else if (s->ports >= GUEST_SERVICE_MAX_PORTS)
        act_refuse(out, GUEST_REASON_PORT_LIMIT, 0);
}

static void open_request(struct guest_service *s, const struct guest_event *ev,
                         uint64_t now, bool from_peer, struct guest_action *out)
{
    if (!s->enabled) {
        act_refuse(out, GUEST_REASON_DISABLED, 0);
        return;
    }
    switch (s->state) {
    case GUEST_STATE_ABSENT:
        open_absent(s, now, from_peer, out);
        break;
    case GUEST_STATE_STOPPING:
        act_refuse(out, GUEST_REASON_STOPPING, 0);
        break;
    case GUEST_STATE_FAILED:
        act_refuse(out, GUEST_REASON_FAILED, 0);
        break;
    case GUEST_STATE_ABANDONED:
        act_refuse(out, GUEST_REASON_ABANDONED, 0);
        break;
    default:
        open_running(s, ev, from_peer, out);
        break;
    }
}

static void ev_peer_open(struct guest_service *s, const struct guest_event *ev,
                         uint64_t now, struct guest_action *out)
{
    open_request(s, ev, now, true, out);
}

static void ev_operator_start(struct guest_service *s, const struct guest_event *ev,
                              uint64_t now, struct guest_action *out)
{
    open_request(s, ev, now, false, out);
}

/* FAILED and ABANDONED are left only here. */
static void ev_operator_reset(struct guest_service *s, const struct guest_event *ev,
                              uint64_t now, struct guest_action *out)
{
    (void)ev;
    (void)now;
    if (s->state != GUEST_STATE_FAILED && s->state != GUEST_STATE_ABANDONED) {
        act_ignore(out, GUEST_REASON_IGNORED_STATE);
        return;
    }
    if (s->state == GUEST_STATE_ABANDONED && !s->joined) {
        /* The old run loop may still be running: a new guest would be a second. */
        act_refuse(out, GUEST_REASON_GUEST_NOT_JOINED, 0);
        return;
    }
    if (s->state == GUEST_STATE_FAILED) {
        s->recent_count = 0;      /* a reset out of ABANDONED keeps the hour history */
        s->backoff_len_ms = 0;
    }
    s->state = GUEST_STATE_ABSENT;
    s->pending_failed = false;
    s->joined = false;
    s->overrun_count = 0;
    clear_ports(s);
}

/* The failure history is not cleared at READY: only the hour window forgets. */
static void ev_boot_ready(struct guest_service *s, const struct guest_event *ev,
                          uint64_t now, struct guest_action *out)
{
    (void)ev;
    if (s->state != GUEST_STATE_STARTING) {
        act_ignore(out, GUEST_REASON_IGNORED_STATE);
        return;
    }
    /* Readiness can arrive before the next timer event. It has the same
     * deadline as TICK and cannot erase an already expired startup. */
    if (elapsed_ms(now, s->state_since_ms) >= GUEST_SERVICE_START_DEADLINE_MS) {
        note_failure(s, now, GUEST_REASON_STARTUP_DEADLINE, out, false);
        return;
    }
    s->state = GUEST_STATE_READY;
    s->state_since_ms = now;
}

static bool boot_reason_ok(enum guest_reason r)
{
    return r == GUEST_REASON_BOOT_FAILED || r == GUEST_REASON_NOT_SEEDED ||
           r == GUEST_REASON_INJECT_FAILED;
}

static void ev_boot_failed(struct guest_service *s, const struct guest_event *ev,
                           uint64_t now, struct guest_action *out)
{
    if (s->state != GUEST_STATE_STARTING) {
        act_ignore(out, GUEST_REASON_IGNORED_STATE);
        return;
    }
    note_failure(s, now, boot_reason_ok(ev->reason) ? ev->reason : GUEST_REASON_BOOT_FAILED,
                 out, false);
}

/* Start refusal retained no allocated instance and invoked no run. */
static void ev_start_refused(struct guest_service *s, const struct guest_event *ev,
                            uint64_t now, struct guest_action *out)
{
    if (s->state != GUEST_STATE_STARTING) {
        act_ignore(out, GUEST_REASON_IGNORED_STATE);
        return;
    }
    note_failure(s, now, boot_reason_ok(ev->reason) ? ev->reason : GUEST_REASON_BOOT_FAILED,
                 out, true);
}

static void ev_port_opened(struct guest_service *s, const struct guest_event *ev,
                           uint64_t now, struct guest_action *out)
{
    int slot;

    (void)now;
    if (s->state == GUEST_STATE_STARTING || s->state == GUEST_STATE_STOPPING) {
        act_refuse(out, s->state == GUEST_STATE_STARTING ? GUEST_REASON_STARTING
                                                         : GUEST_REASON_STOPPING, 0);
        return;
    }
    if (!guest_up(s)) {
        act_ignore(out, GUEST_REASON_IGNORED_STATE);
        return;
    }
    /* Only on the peer's own bound slot. */
    slot = slot_of(s, ev->peer, GUEST_SLOT_BOUND);
    if (slot < 0) {
        act_refuse(out, GUEST_REASON_PEER_NOT_BOUND, 0);
    } else if (s->ports >= GUEST_SERVICE_MAX_PORTS) {
        act_refuse(out, GUEST_REASON_PORT_LIMIT, 0);
    } else {
        s->slot_ports[slot]++;
        s->ports++;
        s->state = GUEST_STATE_SERVING;
    }
}

/* Bind an UNBOUND slot to a peer, once, after the authenticated binding was
 * acknowledged. A bound or retired slot is never rebound. */
static void ev_slot_bound(struct guest_service *s, const struct guest_event *ev,
                          uint64_t now, struct guest_action *out)
{
    (void)now;
    if (!guest_up(s)) {
        act_ignore(out, GUEST_REASON_IGNORED_STATE);
    } else if (ev->slot >= GUEST_SERVICE_MAX_SESSIONS) {
        act_ignore(out, GUEST_REASON_IGNORED_BAD_EVENT);
    } else if (peer_has_slot(s, ev->peer)) {
        act_refuse(out, GUEST_REASON_PEER_ALREADY_BOUND, 0);
    } else if (slots_in(s, GUEST_SLOT_UNBOUND) == 0) {
        act_refuse(out, GUEST_REASON_SESSIONS_FULL, 0);
    } else if (s->slot_state[ev->slot] != GUEST_SLOT_UNBOUND) {
        act_refuse(out, GUEST_REASON_SLOT_NOT_UNBOUND, 0);
    } else {
        s->slot_state[ev->slot] = GUEST_SLOT_BOUND;
        s->slot_peer[ev->slot] = ev->peer;
    }
}

static void ev_port_closed(struct guest_service *s, const struct guest_event *ev,
                           uint64_t now, struct guest_action *out)
{
    int slot = guest_up(s) ? slot_of(s, ev->peer, GUEST_SLOT_BOUND) : -1;

    if (!guest_up(s)) {
        act_ignore(out, GUEST_REASON_IGNORED_STATE);
    } else if (slot < 0 || s->slot_ports[slot] == 0) {
        act_ignore(out, GUEST_REASON_IGNORED_NO_PORT);   /* no underflow */
    } else {
        /* The slot stays bound: closing its ports does not free it. */
        s->slot_ports[slot]--;
        if (--s->ports == 0) {
            s->state = GUEST_STATE_IDLE;
            s->state_since_ms = now;
        }
    }
}

/* Retire exactly one peer's slot and ports; the other peer is untouched. The
 * guest stops only when no bound peer remains. */
static void ev_revoked_peer(struct guest_service *s, const struct guest_event *ev,
                            uint64_t now, struct guest_action *out)
{
    int slot = guest_alive(s) ? slot_of(s, ev->peer, GUEST_SLOT_BOUND) : -1;

    if (!guest_alive(s)) {
        act_ignore(out, GUEST_REASON_IGNORED_STATE);
        return;
    }
    if (slot < 0) {
        act_ignore(out, GUEST_REASON_IGNORED_UNKNOWN_PEER);
        return;
    }
    s->ports -= s->slot_ports[slot];
    s->slot_ports[slot] = 0;
    s->slot_state[slot] = GUEST_SLOT_RETIRED;
    if (slots_in(s, GUEST_SLOT_BOUND) == 0) {
        begin_stop(s, out, GUEST_REASON_REVOKED, now);
    } else if (s->ports == 0 && s->state == GUEST_STATE_SERVING) {
        s->state = GUEST_STATE_IDLE;
        s->state_since_ms = now;
    }
}

/* Only for the case where no peer remains: retire every slot and stop. */
static void ev_revoked_all(struct guest_service *s, const struct guest_event *ev,
                           uint64_t now, struct guest_action *out)
{
    (void)ev;
    if (!guest_alive(s)) {
        act_ignore(out, GUEST_REASON_IGNORED_STATE);
        return;
    }
    for (uint32_t i = 0; i < GUEST_SERVICE_MAX_SESSIONS; i++)
        if (s->slot_state[i] == GUEST_SLOT_BOUND) s->slot_state[i] = GUEST_SLOT_RETIRED;
    begin_stop(s, out, GUEST_REASON_REVOKED, now);
}

/* The run loop returned. A requested stop settles here; anything else is a
 * failure with the guest already gone. FAILED and ABANDONED ignore it. */
static void ev_guest_stopped(struct guest_service *s, const struct guest_event *ev,
                             uint64_t now, struct guest_action *out)
{
    (void)ev;
    switch (s->state) {
    case GUEST_STATE_STOPPING:
        s->state = s->pending_failed ? GUEST_STATE_FAILED : GUEST_STATE_ABSENT;
        s->pending_failed = false;
        clear_ports(s);
        break;
    case GUEST_STATE_STARTING:
        note_failure(s, now, GUEST_REASON_GUEST_EXITED_EARLY, out, true);
        break;
    case GUEST_STATE_READY:
    case GUEST_STATE_SERVING:
    case GUEST_STATE_IDLE:
        note_failure(s, now, GUEST_REASON_GUEST_CRASHED, out, true);
        break;
    case GUEST_STATE_ABANDONED:
        /* The late join: now, and only now, an operator reset may leave. */
        if (s->joined) act_ignore(out, GUEST_REASON_IGNORED_STATE);
        s->joined = true;
        break;
    default:
        act_ignore(out, GUEST_REASON_IGNORED_STATE);
        break;
    }
}

/* Three inside 60 s fail the guest. */
static void ev_callback_overrun(struct guest_service *s, const struct guest_event *ev,
                                uint64_t now, struct guest_action *out)
{
    uint32_t keep = 0;

    (void)ev;
    if (!guest_alive(s)) {
        act_ignore(out, GUEST_REASON_IGNORED_STATE);
        return;
    }
    for (uint32_t i = 0; i < s->overrun_count; i++)
        if (elapsed_ms(now, s->overrun_ms[i]) < GUEST_SERVICE_OVERRUN_WINDOW_MS)
            s->overrun_ms[keep++] = s->overrun_ms[i];
    s->overrun_count = keep;
    if (s->overrun_count + 1u >= GUEST_SERVICE_OVERRUN_LIMIT)
        note_failure(s, now, GUEST_REASON_CALLBACK_OVERRUN, out, false);
    else
        s->overrun_ms[s->overrun_count++] = now;
}

static void ev_tick(struct guest_service *s, const struct guest_event *ev,
                    uint64_t now, struct guest_action *out)
{
    uint64_t el = elapsed_ms(now, s->state_since_ms);

    (void)ev;
    if (s->state == GUEST_STATE_STARTING && el >= GUEST_SERVICE_START_DEADLINE_MS) {
        note_failure(s, now, GUEST_REASON_STARTUP_DEADLINE, out, false);
    } else if ((s->state == GUEST_STATE_IDLE || s->state == GUEST_STATE_READY) &&
               el >= GUEST_SERVICE_IDLE_STOP_MS) {
        begin_stop(s, out, GUEST_REASON_IDLE_TIMEOUT, now);
    } else if (s->state == GUEST_STATE_STOPPING &&
               elapsed_ms(now, s->stop_since_ms) >= GUEST_SERVICE_STOP_JOIN_MS) {
        /* A stop that never joined is a failure too, unless this stop was
         * already caused by (and counted as) one. */
        if (!s->stop_counted) (void)count_failure(s, now, GUEST_REASON_STOP_JOIN_TIMEOUT);
        s->state = GUEST_STATE_ABANDONED;
        s->pending_failed = false;
        s->joined = false;
        act_ignore(out, GUEST_REASON_STOP_JOIN_TIMEOUT);
    } else {
        act_ignore(out, GUEST_REASON_IGNORED_TICK);
    }
}

static const event_fn k_handlers[GUEST_EV_COUNT] = {
    [GUEST_EV_ENABLE] = ev_enable,
    [GUEST_EV_PEER_OPEN] = ev_peer_open,
    [GUEST_EV_OPERATOR_START] = ev_operator_start,
    [GUEST_EV_OPERATOR_RESET] = ev_operator_reset,
    [GUEST_EV_BOOT_READY] = ev_boot_ready,
    [GUEST_EV_BOOT_FAILED] = ev_boot_failed,
    [GUEST_EV_START_REFUSED] = ev_start_refused,
    [GUEST_EV_PORT_OPENED] = ev_port_opened,
    [GUEST_EV_PORT_CLOSED] = ev_port_closed,
    [GUEST_EV_REVOKED_ALL] = ev_revoked_all,
    [GUEST_EV_REVOKED_PEER] = ev_revoked_peer,
    [GUEST_EV_SLOT_BOUND] = ev_slot_bound,
    [GUEST_EV_GUEST_STOPPED] = ev_guest_stopped,
    [GUEST_EV_CALLBACK_OVERRUN] = ev_callback_overrun,
    [GUEST_EV_TICK] = ev_tick,
};

bool guest_service_step(struct guest_service *s, const struct guest_event *ev,
                        uint64_t now_ms, struct guest_action *out)
{
    if (!s || !ev || !out) return false;
    *out = (struct guest_action){ .kind = GUEST_ACTION_NONE };
    if (!s->clock_started) {
        s->clock_started = true;                  /* the first event adopts its now */
    } else if (now_ms < s->last_now_ms) {
        now_ms = s->last_now_ms;                  /* backwards: no time elapsed */
    } else if (now_ms - s->last_now_ms > GUEST_SERVICE_MAX_TIME_STEP_MS) {
        now_ms = s->last_now_ms + GUEST_SERVICE_MAX_TIME_STEP_MS;
        out->time_jump_clamped = true;
    }
    s->last_now_ms = now_ms;
    if ((unsigned)ev->kind >= GUEST_EV_COUNT)
        act_ignore(out, GUEST_REASON_IGNORED_BAD_EVENT);
    else
        k_handlers[ev->kind](s, ev, now_ms, out);
    if (out->time_jump_clamped && out->reason == GUEST_REASON_NONE)
        out->reason = GUEST_REASON_TIME_JUMP_CLAMPED;
    return true;
}

bool guest_service_snapshot(const struct guest_service *s, uint64_t now_ms,
                            struct guest_service_snapshot *out)
{
    struct guest_service copy;

    if (!s || !out) return false;
    copy = *s;
    prune_recent(&copy, now_ms > s->last_now_ms ? now_ms : s->last_now_ms);
    *out = (struct guest_service_snapshot){
        .state = s->state,
        .enabled = s->enabled,
        .ports = s->ports,
        .sessions = slots_in(s, GUEST_SLOT_BOUND),
        .generation = s->generation,
        .failures_in_hour = copy.recent_count,
        .last_failure = s->last_failure,
        .backoff_left_ms = backoff_left(s, now_ms > s->last_now_ms ? now_ms : s->last_now_ms),
    };
    return true;
}

/* ---- CPU governor ----------------------------------------------------- */

struct guest_limits guest_limits_default(void)
{
    return (struct guest_limits){
        .slice_work = GUEST_GOV_SLICE_WORK_DEFAULT,
        .max_slices_per_second = GUEST_GOV_SLICES_PER_SECOND_DEFAULT,
        .duty_percent = GUEST_GOV_DUTY_PERCENT_MAX,
        .window_ms = GUEST_GOV_WINDOW_MS_DEFAULT,
        .short_budget_ms = GUEST_GOV_SHORT_BUDGET_MS_MAX,
    };
}

static bool limits_work_ok(const struct guest_limits *l)
{
    return l->slice_work >= GUEST_GOV_SLICE_WORK_MIN &&
           l->slice_work <= UINT64_C(1000000000) &&
           l->max_slices_per_second >= 1 &&
           l->max_slices_per_second <= GUEST_GOV_SLICES_PER_SECOND_MAX;
}

static bool limits_time_ok(const struct guest_limits *l)
{
    return l->duty_percent >= 1 && l->duty_percent <= GUEST_GOV_DUTY_PERCENT_MAX &&
           l->short_budget_ms >= 1 && l->short_budget_ms <= GUEST_GOV_SHORT_BUDGET_MS_MAX &&
           l->window_ms >= 1000 && l->window_ms <= GUEST_GOV_WINDOW_MS_MAX &&
           l->window_ms % 1000 == 0;
}

bool guest_limits_ok(const struct guest_limits *lim)
{
    return lim && limits_work_ok(lim) && limits_time_ok(lim);
}

bool guest_governor_init(struct guest_governor *g, const struct guest_limits *lim)
{
    if (!g) return false;
    *g = (struct guest_governor){ .ready = false };
    if (!guest_limits_ok(lim)) return false;
    g->lim = *lim;
    g->work = lim->slice_work;
    g->ready = true;
    return true;
}

static uint64_t sat_add(uint64_t a, uint64_t b)
{
    return b > UINT64_MAX - a ? UINT64_MAX : a + b;
}

static void account_us(struct guest_governor *g, uint64_t now_ms, uint64_t us)
{
    uint64_t sec = now_ms / 1000;
    size_t i = (size_t)(sec % GUEST_GOV_RING);

    if (us == 0) return;
    if (g->ring_tag[i] != sec + 1) {
        g->ring_tag[i] = sec + 1;
        g->ring_us[i] = 0;
    }
    g->ring_us[i] = sat_add(g->ring_us[i], us);
}

/* Host microseconds over `span_s` seconds plus the partial current second,
 * so the sum always covers the last span_s seconds of real time: a ceiling
 * built on it is conservative, never loose. */
static uint64_t window_used_us(const struct guest_governor *g, uint64_t now_ms,
                               uint64_t span_s)
{
    uint64_t cur = now_ms / 1000;
    uint64_t used = 0;

    for (uint64_t k = 0; k <= span_s && k <= cur; k++) {
        uint64_t sec = cur - k;
        size_t i = (size_t)(sec % GUEST_GOV_RING);

        if (g->ring_tag[i] == sec + 1) used = sat_add(used, g->ring_us[i]);
    }
    return used;
}

/* Resize the next slice from the one just reported: over SLOW halves (floor
 * SLICE_WORK_MIN); FAST_RUN consecutive under FAST double back up to the
 * configured slice. */
static void resize_slice(struct guest_governor *g, uint64_t reported_us)
{
    if (reported_us == 0) return;
    if (reported_us > GUEST_GOV_SLOW_SLICE_US) {
        g->work /= 2;
        if (g->work < GUEST_GOV_SLICE_WORK_MIN) g->work = GUEST_GOV_SLICE_WORK_MIN;
        g->fast_run = 0;
    } else if (reported_us < GUEST_GOV_FAST_SLICE_US) {
        if (++g->fast_run >= GUEST_GOV_FAST_RUN) {
            g->work = g->work > g->lim.slice_work / 2 ? g->lim.slice_work : g->work * 2;
            g->fast_run = 0;
        }
    } else {
        g->fast_run = 0;
    }
}

static void gov_sleep(struct guest_gov_decision *out, uint64_t ms,
                      enum guest_sleep_reason why)
{
    if (ms < 1) ms = 1;
    if (ms > GUEST_GOV_MAX_SLEEP_MS) ms = GUEST_GOV_MAX_SLEEP_MS;
    out->kind = GUEST_GOV_SLEEP;
    out->work = 0;
    out->sleep_ms = ms;
    out->reason = why;
}

/* Is the long window or the short window full? */
static bool duty_full(const struct guest_governor *g, uint64_t now_ms, bool startup)
{
    uint64_t pct = startup ? GUEST_GOV_STARTUP_DUTY_PERCENT : g->lim.duty_percent;
    uint64_t short_ms = startup ? GUEST_GOV_STARTUP_SHORT_BUDGET_MS : g->lim.short_budget_ms;
    uint64_t long_budget = (uint64_t)g->lim.window_ms * 1000u / 100u * pct;

    return window_used_us(g, now_ms, g->lim.window_ms / 1000) >= long_budget ||
           window_used_us(g, now_ms, GUEST_GOV_SHORT_WINDOW_MS / 1000) >= short_ms * 1000u;
}

/* At most max_slices_per_second run starts in any rolling second: the run
 * that would be one too many must start more than 1000 ms after the
 * (max)th most recent start. Returns the wait in ms, 0 when allowed. */
static uint64_t rate_wait_ms(const struct guest_governor *g, uint64_t now_ms)
{
    uint32_t n = g->lim.max_slices_per_second;
    uint64_t age;

    if (g->rate_count < n) return 0;
    age = elapsed_ms(now_ms, g->rate_ms[(g->rate_head + GUEST_GOV_SLICES_PER_SECOND_MAX - n) %
                                       GUEST_GOV_SLICES_PER_SECOND_MAX]);
    return age > 1000 ? 0 : 1001 - age;
}

static void rate_note(struct guest_governor *g, uint64_t now_ms)
{
    g->rate_ms[g->rate_head] = now_ms;
    g->rate_head = (g->rate_head + 1) % GUEST_GOV_SLICES_PER_SECOND_MAX;
    if (g->rate_count < GUEST_GOV_SLICES_PER_SECOND_MAX) g->rate_count++;
}

/* A ceiling or rate sleep is cut to the guest's real deadline when it has one
 * (neither 0, runnable now, nor NO_DEADLINE), never below 1 ms. */
static uint64_t cut_to_deadline(uint64_t ms, uint64_t deadline_in_ms)
{
    if (deadline_in_ms != 0 && deadline_in_ms != GUEST_GOV_NO_DEADLINE &&
        deadline_in_ms < ms)
        ms = deadline_in_ms;
    return ms < 1 ? 1 : ms;
}

static bool gov_throttled(const struct guest_governor *g, uint64_t now_ms,
                          bool startup, uint64_t deadline_in_ms,
                          struct guest_gov_decision *out)
{
    uint64_t wait;

    if (duty_full(g, now_ms, startup)) {
        gov_sleep(out, cut_to_deadline(1000 - now_ms % 1000, deadline_in_ms),
                  GUEST_SLEEP_DUTY_CEILING);
        return true;
    }
    wait = rate_wait_ms(g, now_ms);
    if (wait > 0) {
        gov_sleep(out, cut_to_deadline(wait, deadline_in_ms), GUEST_SLEEP_SLICE_RATE);
        return true;
    }
    return false;
}

bool guest_governor_next(struct guest_governor *g, uint64_t now_ms,
                         uint64_t last_slice_host_us,
                         uint64_t next_guest_deadline_in_ms, bool input_pending,
                         bool startup, struct guest_gov_decision *out)
{
    if (!g || !out) return false;
    *out = (struct guest_gov_decision){ .kind = GUEST_GOV_SLEEP };
    if (!g->ready) {
        gov_sleep(out, GUEST_GOV_MAX_SLEEP_MS, GUEST_SLEEP_NOT_READY);
        return true;
    }
    if (now_ms < g->last_now_ms) now_ms = g->last_now_ms;
    g->last_now_ms = now_ms;
    account_us(g, now_ms, last_slice_host_us);
    resize_slice(g, last_slice_host_us);
    if (gov_throttled(g, now_ms, startup, next_guest_deadline_in_ms, out)) return true;
    if (!input_pending && next_guest_deadline_in_ms != 0) {
        if (next_guest_deadline_in_ms == GUEST_GOV_NO_DEADLINE)
            gov_sleep(out, GUEST_GOV_MAX_SLEEP_MS, GUEST_SLEEP_IDLE_UNTIL_INPUT);
        else
            gov_sleep(out, next_guest_deadline_in_ms, GUEST_SLEEP_IDLE_UNTIL_DEADLINE);
        return true;
    }
    rate_note(g, now_ms);
    out->kind = GUEST_GOV_RUN_SLICE;
    out->work = g->work;
    return true;
}
