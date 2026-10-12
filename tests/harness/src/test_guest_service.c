/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Proves the pure guest service decisions: the lifecycle state machine and
 * the CPU governor. No guest, no machine, no thread, no clock: time is a
 * number the test supplies. Each case names the rule it guards and fails if
 * that rule is removed from platform/guest_service.c.
 */

#include "test/test_core.h"

#include "platform/guest_service.h"

#include <string.h>

/* ---- lifecycle helpers ------------------------------------------------ */

static struct guest_action step_ev(struct guest_service *s, struct guest_event ev,
                                   uint64_t now)
{
    struct guest_action a;

    memset(&a, 0xAA, sizeof(a));
    if (!guest_service_step(s, &ev, now, &a)) a.kind = (enum guest_action_kind)99;
    return a;
}

static struct guest_action step(struct guest_service *s, enum guest_event_kind k,
                                uint64_t now)
{
    return step_ev(s, (struct guest_event){ .kind = k }, now);
}

static struct guest_action stepp(struct guest_service *s, enum guest_event_kind k,
                                 uint64_t now, uint32_t peer)
{
    return step_ev(s, (struct guest_event){ .kind = k, .peer = peer }, now);
}

static struct guest_action bind_slot(struct guest_service *s, uint32_t slot,
                                     uint32_t peer, uint64_t now)
{
    return step_ev(s, (struct guest_event){ .kind = GUEST_EV_SLOT_BOUND, .slot = slot,
                                            .peer = peer }, now);
}

static struct guest_action set_enable(struct guest_service *s, bool on, uint64_t now)
{
    return step_ev(s, (struct guest_event){ .kind = GUEST_EV_ENABLE, .enable = on }, now);
}

static void fresh_enabled(struct guest_service *s)
{
    guest_service_init(s);
    (void)set_enable(s, true, 0);
}

/* A guest that is up and has no port: STARTING at `at`, READY a second later. */
static void make_ready(struct guest_service *s, uint64_t at)
{
    (void)step(s, GUEST_EV_OPERATOR_START, at);
    (void)step(s, GUEST_EV_BOOT_READY, at + 1000);
}

/* One boot attempt that fails: started at `at`, BOOT_FAILED a second later,
 * the guest joined ten ms after. Returns the BOOT_FAILED action, or the
 * refusal when the start itself was refused. */
static struct guest_action boot_fail(struct guest_service *s, uint64_t at)
{
    struct guest_action a = step(s, GUEST_EV_OPERATOR_START, at);
    struct guest_action f;

    if (a.kind != GUEST_ACTION_START_GUEST) return a;
    f = step(s, GUEST_EV_BOOT_FAILED, at + 1000);
    (void)step(s, GUEST_EV_GUEST_STOPPED, at + 1010);
    return f;
}

/* Start, ready a second later, crash another second later. Returns the
 * GUEST_STOPPED action, or the refusal when the start was refused. */
static struct guest_action crash_cycle(struct guest_service *s, uint64_t at)
{
    struct guest_action a = step(s, GUEST_EV_OPERATOR_START, at);

    if (a.kind != GUEST_ACTION_START_GUEST) return a;
    (void)step(s, GUEST_EV_BOOT_READY, at + 1000);
    return step(s, GUEST_EV_GUEST_STOPPED, at + 2000);
}

/* ---- lifecycle cases -------------------------------------------------- */

static int case_disabled_starts_nothing(void)
{
    int failures = 0;
    struct guest_service s;
    struct guest_action a;

    TEST("guest_service: disabled (the default) refuses every start and starts nothing") {
        guest_service_init(&s);
        ASSERT(!s.enabled);
        a = step(&s, GUEST_EV_PEER_OPEN, 100);
        ASSERT_EQ(a.kind, GUEST_ACTION_ANSWER_UNAVAILABLE);
        ASSERT_EQ(a.reason, GUEST_REASON_DISABLED);
        ASSERT(a.answer_unavailable);
        ASSERT_EQ(s.state, GUEST_STATE_ABSENT);
        a = step(&s, GUEST_EV_OPERATOR_START, 200);
        ASSERT_EQ(a.kind, GUEST_ACTION_ANSWER_UNAVAILABLE);
        ASSERT_EQ(a.reason, GUEST_REASON_DISABLED);
        ASSERT_EQ(s.state, GUEST_STATE_ABSENT);
        a = set_enable(&s, true, 300);
        ASSERT_EQ(a.kind, GUEST_ACTION_NONE);
        a = step(&s, GUEST_EV_PEER_OPEN, 400);
        ASSERT_EQ(a.kind, GUEST_ACTION_START_GUEST);
        PASS();
    }
_test_next:
    return failures;
}

static int case_open_starts_exactly_one(void)
{
    int failures = 0;
    struct guest_service s;
    struct guest_action a;
    int starts = 0;

    TEST("guest_service: an open while absent starts one guest, answers unavailable, and a second open adds none") {
        fresh_enabled(&s);
        a = step(&s, GUEST_EV_PEER_OPEN, 1000);
        ASSERT_EQ(a.kind, GUEST_ACTION_START_GUEST);
        ASSERT_EQ(a.reason, GUEST_REASON_STARTING);
        ASSERT(a.answer_unavailable);
        ASSERT_EQ(s.state, GUEST_STATE_STARTING);
        starts++;
        a = step(&s, GUEST_EV_PEER_OPEN, 1500);
        ASSERT_EQ(a.kind, GUEST_ACTION_ANSWER_UNAVAILABLE);
        ASSERT_EQ(a.reason, GUEST_REASON_STARTING);
        a = step(&s, GUEST_EV_OPERATOR_START, 1600);
        ASSERT(a.kind != GUEST_ACTION_START_GUEST);
        (void)step(&s, GUEST_EV_BOOT_READY, 5000);
        for (int i = 0; i < 4; i++) {
            a = step(&s, i % 2 ? GUEST_EV_PEER_OPEN : GUEST_EV_OPERATOR_START, 6000 + (uint64_t)i);
            if (a.kind == GUEST_ACTION_START_GUEST) starts++;
        }
        ASSERT_EQ(starts, 1);
        ASSERT_EQ(s.state, GUEST_STATE_READY);
        PASS();
    }
_test_next:
    return failures;
}

static int case_fourth_failure_is_failed(void)
{
    int failures = 0;
    struct guest_service s;
    struct guest_action a;

    TEST("guest_service: the third failure in an hour is not FAILED, the fourth is until reset") {
        fresh_enabled(&s);
        a = boot_fail(&s, 0);
        ASSERT_EQ(a.kind, GUEST_ACTION_STOP_GUEST);
        a = boot_fail(&s, 31000);
        ASSERT_EQ(a.kind, GUEST_ACTION_STOP_GUEST);
        a = boot_fail(&s, 92000);
        ASSERT_EQ(a.kind, GUEST_ACTION_STOP_GUEST);
        ASSERT_EQ(s.state, GUEST_STATE_ABSENT);
        ASSERT_EQ(s.last_failure, GUEST_REASON_BOOT_FAILED);
        ASSERT_EQ(s.generation, (uint32_t)3);
        a = step(&s, GUEST_EV_OPERATOR_START, 213000);
        ASSERT_EQ(a.kind, GUEST_ACTION_START_GUEST);
        /* The fourth stops the guest first; FAILED waits for the join. */
        a = step(&s, GUEST_EV_BOOT_FAILED, 214000);
        ASSERT_EQ(a.kind, GUEST_ACTION_STOP_GUEST);
        ASSERT_EQ(s.state, GUEST_STATE_STOPPING);
        (void)step(&s, GUEST_EV_GUEST_STOPPED, 214010);
        ASSERT_EQ(s.state, GUEST_STATE_FAILED);
        ASSERT_EQ(s.generation, (uint32_t)4);
        /* Hours later it is still FAILED, for a peer and for an operator. */
        a = step(&s, GUEST_EV_PEER_OPEN, 40000000);
        ASSERT_EQ(a.kind, GUEST_ACTION_ANSWER_UNAVAILABLE);
        ASSERT_EQ(a.reason, GUEST_REASON_FAILED);
        a = step(&s, GUEST_EV_OPERATOR_START, 40000001);
        ASSERT_EQ(a.reason, GUEST_REASON_FAILED);
        (void)step(&s, GUEST_EV_TICK, 80000000);
        ASSERT_EQ(s.state, GUEST_STATE_FAILED);
        a = step(&s, GUEST_EV_OPERATOR_RESET, 80000001);
        ASSERT_EQ(a.kind, GUEST_ACTION_NONE);
        ASSERT_EQ(s.state, GUEST_STATE_ABSENT);
        a = step(&s, GUEST_EV_OPERATOR_START, 80000002);
        ASSERT_EQ(a.kind, GUEST_ACTION_START_GUEST);
        PASS();
    }
_test_next:
    return failures;
}

static int case_failures_age_out_of_the_hour(void)
{
    int failures = 0;
    struct guest_service s;
    struct guest_action a;
    struct guest_service_snapshot snap;

    TEST("guest_service: failures older than an hour no longer count toward FAILED") {
        fresh_enabled(&s);
        (void)boot_fail(&s, 0);
        (void)boot_fail(&s, 31000);
        (void)boot_fail(&s, 92000);
        ASSERT(guest_service_snapshot(&s, 93010, &snap));
        ASSERT_EQ(snap.failures_in_hour, (uint32_t)3);
        /* The third failure is at 93000; the fourth lands exactly an hour on. */
        a = boot_fail(&s, 93000 + GUEST_SERVICE_FAIL_WINDOW_MS - 1000);
        ASSERT_EQ(a.kind, GUEST_ACTION_STOP_GUEST);
        ASSERT_EQ(s.state, GUEST_STATE_ABSENT);
        ASSERT_EQ(s.generation, (uint32_t)4);   /* generation never forgets */
        PASS();
    }
_test_next:
    return failures;
}

static int case_backoff_doubles_and_caps(void)
{
    int failures = 0;
    struct guest_service s;
    struct guest_action a;

    TEST("guest_service: backoff doubles from 30 s and caps at 15 minutes") {
        ASSERT_EQ(guest_service_backoff_ms(0), (uint64_t)0);
        ASSERT_EQ(guest_service_backoff_ms(1), (uint64_t)30000);
        ASSERT_EQ(guest_service_backoff_ms(2), (uint64_t)60000);
        ASSERT_EQ(guest_service_backoff_ms(3), (uint64_t)120000);
        ASSERT_EQ(guest_service_backoff_ms(4), (uint64_t)240000);
        ASSERT_EQ(guest_service_backoff_ms(5), (uint64_t)480000);
        ASSERT_EQ(guest_service_backoff_ms(6), (uint64_t)900000);
        ASSERT_EQ(guest_service_backoff_ms(7), (uint64_t)900000);
        ASSERT_EQ(guest_service_backoff_ms(UINT32_MAX), (uint64_t)900000);
        PASS();
    }
    TEST("guest_service: a start during backoff is refused with BACKOFF and the milliseconds left") {
        fresh_enabled(&s);
        (void)boot_fail(&s, 0);              /* failed at 1000, backoff 30000 */
        a = step(&s, GUEST_EV_PEER_OPEN, 11000);
        ASSERT_EQ(a.kind, GUEST_ACTION_ANSWER_UNAVAILABLE);
        ASSERT_EQ(a.reason, GUEST_REASON_BACKOFF);
        ASSERT_EQ(a.retry_after_ms, (uint64_t)20000);
        a = step(&s, GUEST_EV_OPERATOR_START, 30999);
        ASSERT_EQ(a.reason, GUEST_REASON_BACKOFF);
        ASSERT_EQ(a.retry_after_ms, (uint64_t)1);
        a = step(&s, GUEST_EV_OPERATOR_START, 31000);
        ASSERT_EQ(a.kind, GUEST_ACTION_START_GUEST);
        PASS();
    }
    TEST("guest_service: the second failure doubles the wait") {
        (void)step(&s, GUEST_EV_BOOT_FAILED, 32000);
        (void)step(&s, GUEST_EV_GUEST_STOPPED, 32010);
        a = step(&s, GUEST_EV_OPERATOR_START, 32100);
        ASSERT_EQ(a.reason, GUEST_REASON_BACKOFF);
        ASSERT_EQ(a.retry_after_ms, (uint64_t)(60000 - 100));
        PASS();
    }
    TEST("guest_service: refused opens during backoff leave the backoff unchanged") {
        struct guest_service_snapshot snap;

        fresh_enabled(&s);
        (void)boot_fail(&s, 0);
        for (uint64_t t = 2000; t < 30000; t += 4000) {
            a = step(&s, GUEST_EV_PEER_OPEN, t);
            ASSERT_EQ(a.reason, GUEST_REASON_BACKOFF);
            a = step(&s, GUEST_EV_OPERATOR_START, t + 1);
            ASSERT_EQ(a.reason, GUEST_REASON_BACKOFF);
        }
        ASSERT_EQ(s.backoff_from_ms, (uint64_t)1000);
        ASSERT_EQ(s.backoff_len_ms, (uint64_t)30000);
        ASSERT(guest_service_snapshot(&s, 30000, &snap));
        ASSERT_EQ(snap.backoff_left_ms, (uint64_t)1000);
        ASSERT_EQ(s.generation, (uint32_t)1);
        a = step(&s, GUEST_EV_OPERATOR_START, 31000);
        ASSERT_EQ(a.kind, GUEST_ACTION_START_GUEST);
        PASS();
    }
_test_next:
    return failures;
}

static int case_startup_deadline(void)
{
    int failures = 0;
    struct guest_service s;
    struct guest_action a;

    TEST("guest_service: no ready marker inside 120 s fails startup_deadline, one ms earlier does not") {
        ASSERT_EQ(GUEST_SERVICE_START_DEADLINE_MS, UINT64_C(120000));
        fresh_enabled(&s);
        (void)step(&s, GUEST_EV_OPERATOR_START, 1000);
        a = step(&s, GUEST_EV_TICK, 1000 + GUEST_SERVICE_START_DEADLINE_MS - 1);
        ASSERT_EQ(a.kind, GUEST_ACTION_NONE);
        ASSERT_EQ(a.reason, GUEST_REASON_IGNORED_TICK);
        ASSERT_EQ(s.state, GUEST_STATE_STARTING);
        a = step(&s, GUEST_EV_TICK, 1000 + GUEST_SERVICE_START_DEADLINE_MS);
        ASSERT_EQ(a.kind, GUEST_ACTION_STOP_GUEST);
        ASSERT_EQ(a.reason, GUEST_REASON_STARTUP_DEADLINE);
        ASSERT_STR_EQ(guest_reason_name(a.reason), "startup_deadline");
        ASSERT_EQ(s.last_failure, GUEST_REASON_STARTUP_DEADLINE);
        ASSERT_EQ(s.state, GUEST_STATE_STOPPING);
        PASS();
    }
_test_next:
    return failures;
}

static int case_ready_obeys_startup_deadline(void)
{
    int failures = 0;
    TEST("guest_service: ready cannot outrun the startup deadline without an intervening tick") {
        for (unsigned offset = 0; offset < 3; offset++) {
            struct guest_service s;
            fresh_enabled(&s);
            (void)step(&s, GUEST_EV_OPERATOR_START, 1000);
            uint64_t observed = 1000 + GUEST_SERVICE_START_DEADLINE_MS - 1 + offset;
            struct guest_action a = step(&s, GUEST_EV_BOOT_READY, observed);
            if (offset == 0) {
                ASSERT_EQ(s.state, GUEST_STATE_READY);
                ASSERT_EQ(a.kind, GUEST_ACTION_NONE);
            } else {
                ASSERT_EQ(s.state, GUEST_STATE_STOPPING);
                ASSERT_EQ(a.kind, GUEST_ACTION_STOP_GUEST);
                ASSERT_EQ(a.reason, GUEST_REASON_STARTUP_DEADLINE);
                ASSERT_EQ(s.last_failure, GUEST_REASON_STARTUP_DEADLINE);
                ASSERT_EQ(s.generation, 1);
                (void)step(&s, GUEST_EV_BOOT_READY, observed + 1);
                ASSERT_EQ(s.state, GUEST_STATE_STOPPING);
                ASSERT_EQ(s.generation, 1);
            }
        }
        PASS();
    }
_test_next:
    return failures;
}

static int case_boot_failure_reasons(void)
{
    int failures = 0;
    struct guest_service s;
    struct guest_action a;

    TEST("guest_service: not_seeded and inject_failed are kept by name, an unknown reason becomes boot_failed") {
        fresh_enabled(&s);
        (void)step(&s, GUEST_EV_OPERATOR_START, 0);
        a = step_ev(&s, (struct guest_event){ .kind = GUEST_EV_BOOT_FAILED,
                                              .reason = GUEST_REASON_NOT_SEEDED }, 100);
        ASSERT_EQ(a.reason, GUEST_REASON_NOT_SEEDED);
        ASSERT_EQ(s.last_failure, GUEST_REASON_NOT_SEEDED);
        (void)step(&s, GUEST_EV_GUEST_STOPPED, 110);
        (void)step(&s, GUEST_EV_OPERATOR_START, 31000);
        a = step_ev(&s, (struct guest_event){ .kind = GUEST_EV_BOOT_FAILED,
                                              .reason = GUEST_REASON_INJECT_FAILED }, 31100);
        ASSERT_EQ(a.reason, GUEST_REASON_INJECT_FAILED);
        ASSERT_EQ(s.last_failure, GUEST_REASON_INJECT_FAILED);
        (void)step(&s, GUEST_EV_GUEST_STOPPED, 31110);
        (void)step(&s, GUEST_EV_OPERATOR_START, 100000);
        a = step_ev(&s, (struct guest_event){ .kind = GUEST_EV_BOOT_FAILED,
                                              .reason = GUEST_REASON_IDLE_TIMEOUT }, 100100);
        ASSERT_EQ(a.reason, GUEST_REASON_BOOT_FAILED);
        PASS();
    }
_test_next:
    return failures;
}

static int case_idle_stop_at_the_deadline(void)
{
    int failures = 0;
    struct guest_service s;
    struct guest_action a;
    uint64_t closed_at;

    TEST("guest_service: idle stop at exactly 300 s after the last port, not a millisecond before") {
        fresh_enabled(&s);
        make_ready(&s, 0);
        (void)bind_slot(&s, 0, 5, 1500);
        a = stepp(&s, GUEST_EV_PORT_OPENED, 2000, 5);
        ASSERT_EQ(a.kind, GUEST_ACTION_NONE);
        ASSERT_EQ(s.state, GUEST_STATE_SERVING);
        closed_at = 2000 + 10 * GUEST_SERVICE_IDLE_STOP_MS;
        a = step(&s, GUEST_EV_TICK, closed_at);
        ASSERT_EQ(a.kind, GUEST_ACTION_NONE);   /* a served guest never idles out */
        a = stepp(&s, GUEST_EV_PORT_CLOSED, closed_at, 5);
        ASSERT_EQ(s.state, GUEST_STATE_IDLE);
        a = step(&s, GUEST_EV_TICK, closed_at + GUEST_SERVICE_IDLE_STOP_MS - 1);
        ASSERT_EQ(a.kind, GUEST_ACTION_NONE);
        ASSERT_EQ(s.state, GUEST_STATE_IDLE);
        a = step(&s, GUEST_EV_TICK, closed_at + GUEST_SERVICE_IDLE_STOP_MS);
        ASSERT_EQ(a.kind, GUEST_ACTION_STOP_GUEST);
        ASSERT_EQ(a.reason, GUEST_REASON_IDLE_TIMEOUT);
        ASSERT_EQ(s.state, GUEST_STATE_STOPPING);
        a = step(&s, GUEST_EV_GUEST_STOPPED, closed_at + GUEST_SERVICE_IDLE_STOP_MS + 5);
        ASSERT_EQ(s.state, GUEST_STATE_ABSENT);
        PASS();
    }
    TEST("guest_service: a guest that never served idles out too") {
        fresh_enabled(&s);
        make_ready(&s, 0);   /* ready at 1000 */
        a = step(&s, GUEST_EV_TICK, 1000 + GUEST_SERVICE_IDLE_STOP_MS - 1);
        ASSERT_EQ(a.kind, GUEST_ACTION_NONE);
        a = step(&s, GUEST_EV_TICK, 1000 + GUEST_SERVICE_IDLE_STOP_MS);
        ASSERT_EQ(a.kind, GUEST_ACTION_STOP_GUEST);
        PASS();
    }
_test_next:
    return failures;
}

static int case_stop_join_abandons(void)
{
    int failures = 0;
    struct guest_service s;
    struct guest_service_snapshot snap;
    struct guest_action a;

    TEST("guest_service: a stop not joined in 5 s is ABANDONED, counts a failure, and refuses by name") {
        ASSERT_EQ(GUEST_SERVICE_STOP_JOIN_MS, UINT64_C(5000));
        fresh_enabled(&s);
        make_ready(&s, 0);
        a = set_enable(&s, false, 10000);
        ASSERT_EQ(a.kind, GUEST_ACTION_STOP_GUEST);
        ASSERT_EQ(s.generation, (uint32_t)0);           /* a requested stop is no failure */
        a = step(&s, GUEST_EV_TICK, 10000 + GUEST_SERVICE_STOP_JOIN_MS - 1);
        ASSERT_EQ(a.reason, GUEST_REASON_IGNORED_TICK);
        ASSERT_EQ(s.state, GUEST_STATE_STOPPING);
        a = step(&s, GUEST_EV_TICK, 10000 + GUEST_SERVICE_STOP_JOIN_MS);
        ASSERT_EQ(a.kind, GUEST_ACTION_NONE);
        ASSERT_EQ(a.reason, GUEST_REASON_STOP_JOIN_TIMEOUT);
        ASSERT_EQ(s.state, GUEST_STATE_ABANDONED);
        ASSERT_EQ(s.generation, (uint32_t)1);           /* the timeout is a failure */
        ASSERT_EQ(s.last_failure, GUEST_REASON_STOP_JOIN_TIMEOUT);
        (void)set_enable(&s, true, 16000);
        a = step(&s, GUEST_EV_PEER_OPEN, 17000);
        ASSERT_EQ(a.kind, GUEST_ACTION_ANSWER_UNAVAILABLE);
        ASSERT_EQ(a.reason, GUEST_REASON_ABANDONED);
        a = step(&s, GUEST_EV_OPERATOR_START, 18000);
        ASSERT_EQ(a.reason, GUEST_REASON_ABANDONED);
        (void)step(&s, GUEST_EV_TICK, 99000000);
        ASSERT_EQ(s.state, GUEST_STATE_ABANDONED);
        PASS();
    }
    TEST("guest_service: a reset before the old guest returned is refused, so no second guest can start") {
        fresh_enabled(&s);
        make_ready(&s, 0);
        (void)set_enable(&s, false, 10000);
        (void)step(&s, GUEST_EV_TICK, 15000);
        ASSERT_EQ(s.state, GUEST_STATE_ABANDONED);
        (void)set_enable(&s, true, 15500);
        a = step(&s, GUEST_EV_OPERATOR_RESET, 16000);
        ASSERT_EQ(a.kind, GUEST_ACTION_ANSWER_UNAVAILABLE);
        ASSERT_EQ(a.reason, GUEST_REASON_GUEST_NOT_JOINED);
        ASSERT_EQ(s.state, GUEST_STATE_ABANDONED);
        a = step(&s, GUEST_EV_OPERATOR_START, 16001);
        ASSERT(a.kind != GUEST_ACTION_START_GUEST);
        PASS();
    }
    TEST("guest_service: a late join lets the reset leave, which keeps the hour history") {
        a = step(&s, GUEST_EV_GUEST_STOPPED, 17000);
        ASSERT_EQ(a.kind, GUEST_ACTION_NONE);
        ASSERT_EQ(s.state, GUEST_STATE_ABANDONED);      /* joined, not yet reset */
        a = step(&s, GUEST_EV_GUEST_STOPPED, 17001);
        ASSERT_EQ(a.reason, GUEST_REASON_IGNORED_STATE);
        a = step(&s, GUEST_EV_PEER_OPEN, 17002);
        ASSERT_EQ(a.reason, GUEST_REASON_ABANDONED);
        a = step(&s, GUEST_EV_OPERATOR_RESET, 18000);
        ASSERT_EQ(a.kind, GUEST_ACTION_NONE);
        ASSERT_EQ(s.state, GUEST_STATE_ABSENT);
        ASSERT(guest_service_snapshot(&s, 18000, &snap));
        ASSERT_EQ(snap.failures_in_hour, (uint32_t)1);  /* not cleared */
        a = step(&s, GUEST_EV_OPERATOR_START, 18001);
        ASSERT_EQ(a.reason, GUEST_REASON_BACKOFF);
        a = step(&s, GUEST_EV_OPERATOR_START, 15000 + 30000);
        ASSERT_EQ(a.kind, GUEST_ACTION_START_GUEST);
        PASS();
    }
    TEST("guest_service: a failure with a running guest goes through STOPPING, never straight to FAILED") {
        fresh_enabled(&s);
        (void)boot_fail(&s, 0);
        (void)boot_fail(&s, 31000);
        (void)boot_fail(&s, 92000);
        (void)step(&s, GUEST_EV_OPERATOR_START, 213000);
        a = step(&s, GUEST_EV_BOOT_FAILED, 214000);       /* the fourth */
        ASSERT_EQ(a.kind, GUEST_ACTION_STOP_GUEST);
        ASSERT_EQ(s.state, GUEST_STATE_STOPPING);
        a = step(&s, GUEST_EV_PEER_OPEN, 214500);
        ASSERT_EQ(a.reason, GUEST_REASON_STOPPING);
        a = step(&s, GUEST_EV_TICK, 214000 + GUEST_SERVICE_STOP_JOIN_MS);
        ASSERT_EQ(a.reason, GUEST_REASON_STOP_JOIN_TIMEOUT);
        ASSERT_EQ(s.state, GUEST_STATE_ABANDONED);
        ASSERT_EQ(s.generation, (uint32_t)4);   /* the failure already counted this stop */
        PASS();
    }
_test_next:
    return failures;
}

static int case_failure_during_stopping_not_double_counted(void)
{
    int failures = 0;
    struct guest_service s;
    struct guest_action a;

    TEST("guest_service: more failure events while STOPPING are ignored and not counted again") {
        fresh_enabled(&s);
        (void)step(&s, GUEST_EV_OPERATOR_START, 0);
        a = step(&s, GUEST_EV_BOOT_FAILED, 1000);
        ASSERT_EQ(a.kind, GUEST_ACTION_STOP_GUEST);
        ASSERT_EQ(s.generation, (uint32_t)1);
        a = step(&s, GUEST_EV_BOOT_FAILED, 1100);
        ASSERT_EQ(a.reason, GUEST_REASON_IGNORED_STATE);
        for (int i = 0; i < 4; i++) {
            a = step(&s, GUEST_EV_CALLBACK_OVERRUN, 1200 + (uint64_t)i);
            ASSERT_EQ(a.reason, GUEST_REASON_IGNORED_STATE);
        }
        ASSERT_EQ(s.generation, (uint32_t)1);
        ASSERT_EQ(s.recent_count, (uint32_t)1);
        /* The join timeout of a stop that a failure caused is not a second one. */
        a = step(&s, GUEST_EV_TICK, 1000 + GUEST_SERVICE_STOP_JOIN_MS);
        ASSERT_EQ(a.reason, GUEST_REASON_STOP_JOIN_TIMEOUT);
        ASSERT_EQ(s.generation, (uint32_t)1);
        ASSERT_EQ(s.recent_count, (uint32_t)1);
        PASS();
    }
_test_next:
    return failures;
}

static int case_fifth_port_refused(void)
{
    int failures = 0;
    struct guest_service s;
    struct guest_action a;

    TEST("guest_service: the fifth port is refused by name and the count stays at four") {
        fresh_enabled(&s);
        make_ready(&s, 0);
        (void)bind_slot(&s, 0, 5, 1500);
        for (uint32_t i = 0; i < GUEST_SERVICE_MAX_PORTS; i++) {
            a = stepp(&s, GUEST_EV_PORT_OPENED, 2000 + i, 5);
            ASSERT_EQ(a.kind, GUEST_ACTION_NONE);
        }
        ASSERT_EQ(s.ports, GUEST_SERVICE_MAX_PORTS);
        a = stepp(&s, GUEST_EV_PORT_OPENED, 3000, 5);
        ASSERT_EQ(a.kind, GUEST_ACTION_ANSWER_UNAVAILABLE);
        ASSERT_EQ(a.reason, GUEST_REASON_PORT_LIMIT);
        ASSERT_EQ(s.ports, GUEST_SERVICE_MAX_PORTS);
        a = stepp(&s, GUEST_EV_PEER_OPEN, 3001, 5);
        ASSERT_EQ(a.kind, GUEST_ACTION_ANSWER_UNAVAILABLE);
        ASSERT_EQ(a.reason, GUEST_REASON_PORT_LIMIT);
        (void)stepp(&s, GUEST_EV_PORT_CLOSED, 3002, 5);
        a = stepp(&s, GUEST_EV_PORT_OPENED, 3003, 5);
        ASSERT_EQ(a.kind, GUEST_ACTION_NONE);
        PASS();
    }
    TEST("guest_service: a port opened while STARTING or STOPPING is refused by name") {
        fresh_enabled(&s);
        (void)step(&s, GUEST_EV_OPERATOR_START, 0);
        a = stepp(&s, GUEST_EV_PORT_OPENED, 10, 5);
        ASSERT_EQ(a.kind, GUEST_ACTION_ANSWER_UNAVAILABLE);
        ASSERT_EQ(a.reason, GUEST_REASON_STARTING);
        (void)step(&s, GUEST_EV_BOOT_READY, 1000);
        (void)bind_slot(&s, 0, 5, 1100);
        (void)step(&s, GUEST_EV_REVOKED_ALL, 1200);
        ASSERT_EQ(s.state, GUEST_STATE_STOPPING);
        a = stepp(&s, GUEST_EV_PORT_OPENED, 1300, 5);
        ASSERT_EQ(a.kind, GUEST_ACTION_ANSWER_UNAVAILABLE);
        ASSERT_EQ(a.reason, GUEST_REASON_STOPPING);
        ASSERT_EQ(s.ports, (uint32_t)0);
        PASS();
    }
    TEST("guest_service: closing a port that is not open cannot underflow the count") {
        fresh_enabled(&s);
        make_ready(&s, 0);
        (void)bind_slot(&s, 0, 5, 1500);
        a = stepp(&s, GUEST_EV_PORT_CLOSED, 2000, 5);        /* bound, none open */
        ASSERT_EQ(a.reason, GUEST_REASON_IGNORED_NO_PORT);
        a = stepp(&s, GUEST_EV_PORT_CLOSED, 2001, 99);       /* unknown peer */
        ASSERT_EQ(a.reason, GUEST_REASON_IGNORED_NO_PORT);
        ASSERT_EQ(s.ports, (uint32_t)0);
        (void)stepp(&s, GUEST_EV_PORT_OPENED, 2002, 5);
        (void)stepp(&s, GUEST_EV_PORT_CLOSED, 2003, 5);
        a = stepp(&s, GUEST_EV_PORT_CLOSED, 2004, 5);        /* a second close */
        ASSERT_EQ(a.reason, GUEST_REASON_IGNORED_NO_PORT);
        ASSERT_EQ(s.ports, (uint32_t)0);
        ASSERT_EQ(s.slot_ports[0], (uint32_t)0);
        ASSERT_EQ(s.state, GUEST_STATE_IDLE);
        PASS();
    }
_test_next:
    return failures;
}

static int case_two_slots(void)
{
    int failures = 0;
    struct guest_service s;
    struct guest_action a;

    TEST("guest_service: two immutable slots; a third peer is refused with sessions_full, even after ports close") {
        fresh_enabled(&s);
        make_ready(&s, 0);
        /* A peer may open before it is bound while a slot is free, but
         * opens ports only on its bound slot. */
        ASSERT_EQ(stepp(&s, GUEST_EV_PEER_OPEN, 2000, 1).kind, GUEST_ACTION_NONE);
        a = stepp(&s, GUEST_EV_PORT_OPENED, 2001, 1);
        ASSERT_EQ(a.reason, GUEST_REASON_PEER_NOT_BOUND);
        ASSERT_EQ(bind_slot(&s, 0, 1, 2002).kind, GUEST_ACTION_NONE);
        ASSERT_EQ(s.slot_state[0], GUEST_SLOT_BOUND);
        ASSERT_EQ(stepp(&s, GUEST_EV_PORT_OPENED, 2003, 1).kind, GUEST_ACTION_NONE);
        ASSERT_EQ(stepp(&s, GUEST_EV_PORT_OPENED, 2004, 1).kind, GUEST_ACTION_NONE);
        ASSERT_EQ(bind_slot(&s, 1, 2, 2005).kind, GUEST_ACTION_NONE);
        ASSERT_EQ(stepp(&s, GUEST_EV_PORT_OPENED, 2006, 2).kind, GUEST_ACTION_NONE);
        a = stepp(&s, GUEST_EV_PEER_OPEN, 2007, 3);
        ASSERT_EQ(a.kind, GUEST_ACTION_ANSWER_UNAVAILABLE);
        ASSERT_EQ(a.reason, GUEST_REASON_SESSIONS_FULL);
        a = bind_slot(&s, 0, 3, 2008);
        ASSERT_EQ(a.reason, GUEST_REASON_SESSIONS_FULL);
        a = stepp(&s, GUEST_EV_PORT_OPENED, 2009, 3);
        ASSERT_EQ(a.reason, GUEST_REASON_PEER_NOT_BOUND);
        /* Closing every port of peer 1 does not free its slot. */
        (void)stepp(&s, GUEST_EV_PORT_CLOSED, 2010, 1);
        (void)stepp(&s, GUEST_EV_PORT_CLOSED, 2011, 1);
        ASSERT_EQ(s.slot_state[0], GUEST_SLOT_BOUND);
        ASSERT_EQ(s.slot_peer[0], (uint32_t)1);
        a = stepp(&s, GUEST_EV_PEER_OPEN, 2012, 3);
        ASSERT_EQ(a.reason, GUEST_REASON_SESSIONS_FULL);
        a = bind_slot(&s, 0, 3, 2013);
        ASSERT_EQ(a.reason, GUEST_REASON_SESSIONS_FULL);
        /* Peer 1 still has its slot and can come back to it. */
        ASSERT_EQ(stepp(&s, GUEST_EV_PORT_OPENED, 2014, 1).kind, GUEST_ACTION_NONE);
        PASS();
    }
    TEST("guest_service: one slot per peer, a bound slot is not rebound, and a bad slot is named") {
        fresh_enabled(&s);
        make_ready(&s, 0);
        ASSERT_EQ(bind_slot(&s, 0, 1, 1500).kind, GUEST_ACTION_NONE);
        a = bind_slot(&s, 1, 1, 1600);
        ASSERT_EQ(a.kind, GUEST_ACTION_ANSWER_UNAVAILABLE);
        ASSERT_EQ(a.reason, GUEST_REASON_PEER_ALREADY_BOUND);
        a = bind_slot(&s, 0, 2, 1700);
        ASSERT_EQ(a.reason, GUEST_REASON_SLOT_NOT_UNBOUND);
        ASSERT_EQ(s.slot_peer[0], (uint32_t)1);
        a = bind_slot(&s, 7, 2, 1800);
        ASSERT_EQ(a.reason, GUEST_REASON_IGNORED_BAD_EVENT);
        ASSERT_EQ(bind_slot(&s, 1, 2, 1900).kind, GUEST_ACTION_NONE);
        PASS();
    }
    TEST("guest_service: a revoke retires the slot for the instance and a new instance starts all unbound") {
        a = stepp(&s, GUEST_EV_REVOKED_PEER, 2000, 1);
        ASSERT_EQ(a.kind, GUEST_ACTION_NONE);             /* peer 2 remains */
        ASSERT_EQ(s.slot_state[0], GUEST_SLOT_RETIRED);
        a = stepp(&s, GUEST_EV_PEER_OPEN, 2001, 1);
        ASSERT_EQ(a.reason, GUEST_REASON_PEER_ALREADY_BOUND);
        a = stepp(&s, GUEST_EV_PORT_OPENED, 2002, 1);
        ASSERT_EQ(a.reason, GUEST_REASON_PEER_NOT_BOUND);
        a = bind_slot(&s, 0, 9, 2003);
        ASSERT_EQ(a.reason, GUEST_REASON_SESSIONS_FULL);  /* retired is not reusable */
        a = stepp(&s, GUEST_EV_REVOKED_PEER, 2004, 2);    /* the last bound peer */
        ASSERT_EQ(a.kind, GUEST_ACTION_STOP_GUEST);
        ASSERT_EQ(a.reason, GUEST_REASON_REVOKED);
        (void)step(&s, GUEST_EV_GUEST_STOPPED, 2005);
        a = step(&s, GUEST_EV_OPERATOR_START, 2006);
        ASSERT_EQ(a.kind, GUEST_ACTION_START_GUEST);
        ASSERT_EQ(s.slot_state[0], GUEST_SLOT_UNBOUND);
        ASSERT_EQ(s.slot_state[1], GUEST_SLOT_UNBOUND);
        (void)step(&s, GUEST_EV_BOOT_READY, 3000);
        ASSERT_EQ(bind_slot(&s, 0, 1, 3100).kind, GUEST_ACTION_NONE);
        PASS();
    }
_test_next:
    return failures;
}

static int case_revocation_is_per_peer(void)
{
    int failures = 0;
    struct guest_service s;
    struct guest_action a;

    TEST("guest_service: revoking peer B while A is serving leaves A's ports and state, and A's closes still match") {
        fresh_enabled(&s);
        make_ready(&s, 0);
        (void)bind_slot(&s, 0, 1, 1500);
        (void)bind_slot(&s, 1, 2, 1600);
        (void)stepp(&s, GUEST_EV_PORT_OPENED, 2000, 1);
        (void)stepp(&s, GUEST_EV_PORT_OPENED, 2001, 1);
        (void)stepp(&s, GUEST_EV_PORT_OPENED, 2002, 2);
        ASSERT_EQ(s.ports, (uint32_t)3);
        a = stepp(&s, GUEST_EV_REVOKED_PEER, 3000, 2);
        ASSERT_EQ(a.kind, GUEST_ACTION_NONE);
        ASSERT_EQ(s.ports, (uint32_t)2);
        ASSERT_EQ(s.slot_ports[0], (uint32_t)2);
        ASSERT_EQ(s.slot_ports[1], (uint32_t)0);
        ASSERT_EQ(s.state, GUEST_STATE_SERVING);
        ASSERT_EQ(s.slot_state[0], GUEST_SLOT_BOUND);
        ASSERT_EQ(s.slot_state[1], GUEST_SLOT_RETIRED);
        a = stepp(&s, GUEST_EV_PORT_CLOSED, 3100, 1);
        ASSERT_EQ(a.kind, GUEST_ACTION_NONE);
        ASSERT_EQ(s.ports, (uint32_t)1);
        ASSERT_EQ(s.state, GUEST_STATE_SERVING);
        (void)stepp(&s, GUEST_EV_PORT_CLOSED, 3101, 1);
        ASSERT_EQ(s.ports, (uint32_t)0);
        ASSERT_EQ(s.state, GUEST_STATE_IDLE);
        a = stepp(&s, GUEST_EV_REVOKED_PEER, 3200, 2);
        ASSERT_EQ(a.reason, GUEST_REASON_IGNORED_UNKNOWN_PEER);
        a = stepp(&s, GUEST_EV_REVOKED_PEER, 3300, 1);
        ASSERT_EQ(a.kind, GUEST_ACTION_STOP_GUEST);
        ASSERT_EQ(a.reason, GUEST_REASON_REVOKED);
        ASSERT_EQ(s.state, GUEST_STATE_STOPPING);
        PASS();
    }
    TEST("guest_service: revoking the only serving peer leaves the guest up and idle while another peer is bound") {
        fresh_enabled(&s);
        make_ready(&s, 0);
        (void)bind_slot(&s, 0, 1, 1500);
        (void)bind_slot(&s, 1, 2, 1600);
        (void)stepp(&s, GUEST_EV_PORT_OPENED, 2000, 2);
        a = stepp(&s, GUEST_EV_REVOKED_PEER, 3000, 2);
        ASSERT_EQ(a.kind, GUEST_ACTION_NONE);
        ASSERT_EQ(s.ports, (uint32_t)0);
        ASSERT_EQ(s.state, GUEST_STATE_IDLE);
        PASS();
    }
    TEST("guest_service: REVOKED_ALL retires every slot, closes every port and stops the guest") {
        fresh_enabled(&s);
        make_ready(&s, 0);
        (void)bind_slot(&s, 0, 1, 1500);
        (void)stepp(&s, GUEST_EV_PORT_OPENED, 2000, 1);
        a = step(&s, GUEST_EV_REVOKED_ALL, 3000);
        ASSERT_EQ(a.kind, GUEST_ACTION_STOP_GUEST);
        ASSERT_EQ(a.reason, GUEST_REASON_REVOKED);
        ASSERT_EQ(s.ports, (uint32_t)0);
        ASSERT_EQ(s.slot_state[0], GUEST_SLOT_RETIRED);
        ASSERT_EQ(s.state, GUEST_STATE_STOPPING);
        PASS();
    }
_test_next:
    return failures;
}

static int case_time_going_backwards(void)
{
    int failures = 0;
    struct guest_service s;
    struct guest_action a;

    TEST("guest_service: a now that goes backwards is no time elapsed, for backoff and for the idle clock") {
        fresh_enabled(&s);
        (void)boot_fail(&s, 99000);          /* failed at 100000, backoff 30000 */
        (void)step(&s, GUEST_EV_TICK, 120000);
        a = step(&s, GUEST_EV_OPERATOR_START, 50000);   /* clock stepped back */
        ASSERT_EQ(a.reason, GUEST_REASON_BACKOFF);
        ASSERT_EQ(a.retry_after_ms, (uint64_t)10000);   /* 120000 stands */
        ASSERT_EQ(s.last_now_ms, (uint64_t)120000);

        guest_service_init(&s);
        (void)set_enable(&s, true, 0);
        make_ready(&s, 19000);                          /* ready at 20000 */
        (void)bind_slot(&s, 0, 5, 20000);
        (void)stepp(&s, GUEST_EV_PORT_OPENED, 20000, 5);
        (void)stepp(&s, GUEST_EV_PORT_CLOSED, 1000, 5); /* clock stepped back */
        ASSERT_EQ(s.state, GUEST_STATE_IDLE);
        a = step(&s, GUEST_EV_TICK, 20000 + GUEST_SERVICE_IDLE_STOP_MS - 1);
        ASSERT_EQ(a.kind, GUEST_ACTION_NONE);
        a = step(&s, GUEST_EV_TICK, 20000 + GUEST_SERVICE_IDLE_STOP_MS);
        ASSERT_EQ(a.kind, GUEST_ACTION_STOP_GUEST);
        PASS();
    }
    TEST("guest_service: a near-maximum clock does not overflow a deadline") {
        guest_service_init(&s);
        s.enabled = true;
        s.clock_started = true;
        s.last_now_ms = UINT64_MAX - 10000;
        make_ready(&s, UINT64_MAX - 9000);
        (void)bind_slot(&s, 0, 5, UINT64_MAX - 7500);
        (void)stepp(&s, GUEST_EV_PORT_OPENED, UINT64_MAX - 7000, 5);
        (void)stepp(&s, GUEST_EV_PORT_CLOSED, UINT64_MAX - 6000, 5);
        a = step(&s, GUEST_EV_TICK, UINT64_MAX - 2000);
        ASSERT_EQ(a.kind, GUEST_ACTION_NONE);
        a = step(&s, GUEST_EV_TICK, UINT64_MAX);
        ASSERT_EQ(a.kind, GUEST_ACTION_NONE);
        ASSERT_EQ(s.state, GUEST_STATE_IDLE);
        PASS();
    }
_test_next:
    return failures;
}

static int case_time_jump_clamped(void)
{
    int failures = 0;
    struct guest_service s;
    struct guest_action a;

    TEST("guest_service: the first event adopts its now, however large") {
        guest_service_init(&s);
        a = set_enable(&s, true, UINT64_C(1000000000000));
        ASSERT(!a.time_jump_clamped);
        ASSERT_EQ(a.reason, GUEST_REASON_NONE);
        ASSERT_EQ(s.last_now_ms, UINT64_C(1000000000000));
        PASS();
    }
    TEST("guest_service: a step larger than an hour is used as one hour and reported") {
        fresh_enabled(&s);
        make_ready(&s, 0);                                /* ready at 1000 */
        a = step(&s, GUEST_EV_TICK, UINT64_C(1000000000000));
        ASSERT(a.time_jump_clamped);
        ASSERT_EQ(a.kind, GUEST_ACTION_STOP_GUEST);       /* an hour idle is past 300 s */
        ASSERT_EQ(a.reason, GUEST_REASON_IDLE_TIMEOUT);
        ASSERT_EQ(s.last_now_ms, 1000 + GUEST_SERVICE_MAX_TIME_STEP_MS);
        a = set_enable(&s, true, UINT64_C(2000000000000));    /* no change: nothing to report */
        ASSERT(a.time_jump_clamped);
        ASSERT_EQ(s.last_now_ms, 1000 + 2 * GUEST_SERVICE_MAX_TIME_STEP_MS);
        PASS();
    }
    TEST("guest_service: an event with no other reason reports time_jump_clamped") {
        fresh_enabled(&s);
        a = set_enable(&s, false, 100);                   /* a plain change: reason none */
        ASSERT_EQ(a.reason, GUEST_REASON_NONE);
        a = set_enable(&s, true, 100 + GUEST_SERVICE_MAX_TIME_STEP_MS + 1);
        ASSERT(a.time_jump_clamped);
        ASSERT_EQ(a.reason, GUEST_REASON_TIME_JUMP_CLAMPED);
        a = set_enable(&s, false, s.last_now_ms + GUEST_SERVICE_MAX_TIME_STEP_MS);
        ASSERT(!a.time_jump_clamped);                     /* exactly an hour is not a jump */
        PASS();
    }
_test_next:
    return failures;
}

static int case_revoke_disable(void)
{
    int failures = 0;
    struct guest_service s;
    struct guest_action a;

    TEST("guest_service: disabling while running stops the guest, and a stopping guest refuses opens by name") {
        fresh_enabled(&s);
        make_ready(&s, 0);
        a = set_enable(&s, false, 2000);
        ASSERT_EQ(a.kind, GUEST_ACTION_STOP_GUEST);
        ASSERT_EQ(a.reason, GUEST_REASON_DISABLED_WHILE_RUNNING);
        a = step(&s, GUEST_EV_PEER_OPEN, 2001);
        ASSERT_EQ(a.reason, GUEST_REASON_DISABLED);
        (void)set_enable(&s, true, 2002);
        a = step(&s, GUEST_EV_PEER_OPEN, 2003);
        ASSERT_EQ(a.reason, GUEST_REASON_STOPPING);
        (void)step(&s, GUEST_EV_GUEST_STOPPED, 2004);
        ASSERT_EQ(s.state, GUEST_STATE_ABSENT);
        ASSERT_EQ(s.generation, (uint32_t)0);   /* a requested stop is no failure */
        PASS();
    }
_test_next:
    return failures;
}

static int case_crash_after_ready(void)
{
    int failures = 0;
    struct guest_service s;
    struct guest_action a;
    static const uint64_t starts[] = { 0, 32000, 94000 };

    TEST("guest_service: a ready-then-crash loop reaches FAILED on the fourth crash, and ready forgets nothing") {
        fresh_enabled(&s);
        for (size_t i = 0; i < 3; i++) {
            a = crash_cycle(&s, starts[i]);
            ASSERT_EQ(a.kind, GUEST_ACTION_NONE);
            ASSERT_EQ(a.reason, GUEST_REASON_GUEST_CRASHED);
            ASSERT_EQ(s.state, GUEST_STATE_ABSENT);
            ASSERT_EQ(s.generation, (uint32_t)(i + 1));
        }
        ASSERT_EQ(s.last_failure, GUEST_REASON_GUEST_CRASHED);
        a = step(&s, GUEST_EV_OPERATOR_START, 95000);
        ASSERT_EQ(a.reason, GUEST_REASON_BACKOFF);     /* the third doubled to 120 s */
        (void)crash_cycle(&s, 216000);
        ASSERT_EQ(s.state, GUEST_STATE_FAILED);
        ASSERT_EQ(s.generation, (uint32_t)4);
        a = step(&s, GUEST_EV_PEER_OPEN, 300000);
        ASSERT_EQ(a.reason, GUEST_REASON_FAILED);
        PASS();
    }
    TEST("guest_service: a crash while serving drops the ports and counts as a failure") {
        fresh_enabled(&s);
        make_ready(&s, 0);
        (void)bind_slot(&s, 0, 7, 1500);
        (void)stepp(&s, GUEST_EV_PORT_OPENED, 2000, 7);
        a = step(&s, GUEST_EV_GUEST_STOPPED, 3000);
        ASSERT_EQ(a.reason, GUEST_REASON_GUEST_CRASHED);
        ASSERT_EQ(s.ports, (uint32_t)0);
        ASSERT_EQ(s.state, GUEST_STATE_ABSENT);
        PASS();
    }
_test_next:
    return failures;
}

static int case_callback_overrun(void)
{
    int failures = 0;
    struct guest_service s;
    struct guest_action a;

    TEST("guest_service: three callback overruns inside 60 s fail the guest, the third one later does not") {
        fresh_enabled(&s);
        make_ready(&s, 0);
        a = step(&s, GUEST_EV_CALLBACK_OVERRUN, 10000);
        ASSERT_EQ(a.kind, GUEST_ACTION_NONE);
        a = step(&s, GUEST_EV_CALLBACK_OVERRUN, 20000);
        ASSERT_EQ(a.kind, GUEST_ACTION_NONE);
        ASSERT_EQ(s.state, GUEST_STATE_READY);
        a = step(&s, GUEST_EV_CALLBACK_OVERRUN, 10000 + GUEST_SERVICE_OVERRUN_WINDOW_MS - 1);
        ASSERT_EQ(a.kind, GUEST_ACTION_STOP_GUEST);
        ASSERT_EQ(a.reason, GUEST_REASON_CALLBACK_OVERRUN);
        ASSERT_EQ(s.state, GUEST_STATE_STOPPING);
        ASSERT_EQ(s.last_failure, GUEST_REASON_CALLBACK_OVERRUN);
        (void)step(&s, GUEST_EV_GUEST_STOPPED, 71000);

        fresh_enabled(&s);
        make_ready(&s, 0);
        (void)step(&s, GUEST_EV_CALLBACK_OVERRUN, 10000);
        (void)step(&s, GUEST_EV_CALLBACK_OVERRUN, 20000);
        a = step(&s, GUEST_EV_CALLBACK_OVERRUN, 10000 + GUEST_SERVICE_OVERRUN_WINDOW_MS);
        ASSERT_EQ(a.kind, GUEST_ACTION_NONE);
        ASSERT_EQ(s.state, GUEST_STATE_READY);
        a = step(&s, GUEST_EV_CALLBACK_OVERRUN, 10000 + GUEST_SERVICE_OVERRUN_WINDOW_MS + 1);
        ASSERT_EQ(a.reason, GUEST_REASON_CALLBACK_OVERRUN);   /* 20000, 70000, 70001 */
        PASS();
    }
_test_next:
    return failures;
}

/* One guest instance that fails in the way `kind` says, an hour after the
 * last one so the history never reaches FAILED. Returns the generation
 * change caused by the failure event and then by settling the stop. */
static uint32_t gen_after(struct guest_service *s, int kind, uint32_t *settle_delta)
{
    uint64_t t = s->last_now_ms + GUEST_SERVICE_MAX_TIME_STEP_MS;
    uint32_t before = s->generation, mid;
    enum guest_reason why[] = { GUEST_REASON_BOOT_FAILED, GUEST_REASON_NOT_SEEDED,
                                GUEST_REASON_INJECT_FAILED };

    (void)step(s, GUEST_EV_OPERATOR_START, t);
    if (kind < 3) {
        (void)step_ev(s, (struct guest_event){ .kind = GUEST_EV_BOOT_FAILED,
                                               .reason = why[kind] }, t + 100);
    } else if (kind == 3) {
        (void)step(s, GUEST_EV_TICK, t + GUEST_SERVICE_START_DEADLINE_MS);
    } else if (kind == 4) {
        (void)step(s, GUEST_EV_GUEST_STOPPED, t + 100);
    } else {
        (void)step(s, GUEST_EV_BOOT_READY, t + 100);
        if (kind == 5) {
            (void)step(s, GUEST_EV_GUEST_STOPPED, t + 200);
        } else if (kind == 6) {
            for (uint64_t i = 0; i < 3; i++) (void)step(s, GUEST_EV_CALLBACK_OVERRUN, t + 200 + i);
        } else {
            (void)set_enable(s, false, t + 200);
            (void)step(s, GUEST_EV_TICK, t + 200 + GUEST_SERVICE_STOP_JOIN_MS);
        }
    }
    mid = s->generation;
    (void)step(s, GUEST_EV_GUEST_STOPPED, s->last_now_ms + 10);
    *settle_delta = s->generation - mid;
    return mid - before;
}

static int case_generation_once_per_failure(void)
{
    int failures = 0;
    struct guest_service s;
    uint32_t settle = 99;

    TEST("guest_service: the generation rises exactly once per failure, for every kind of failure") {
        fresh_enabled(&s);
        for (int kind = 0; kind < 8; kind++) {
            ASSERT_EQ(gen_after(&s, kind, &settle), (uint32_t)1);
            ASSERT_EQ(settle, (uint32_t)0);
            if (s.state == GUEST_STATE_ABANDONED) {
                (void)step(&s, GUEST_EV_OPERATOR_RESET, s.last_now_ms + 10);
                (void)set_enable(&s, true, s.last_now_ms + 10);
            }
            ASSERT(s.state == GUEST_STATE_ABSENT);
        }
        ASSERT_EQ(s.generation, (uint32_t)8);
        PASS();
    }
_test_next:
    return failures;
}

static int case_unlisted_events_are_ignored(void)
{
    int failures = 0;
    struct guest_service s;
    struct guest_action a;

    TEST("guest_service: an event the table does not list is a named no-op that changes nothing") {
        fresh_enabled(&s);
        a = step(&s, GUEST_EV_BOOT_READY, 10);
        ASSERT_EQ(a.kind, GUEST_ACTION_NONE);
        ASSERT_EQ(a.reason, GUEST_REASON_IGNORED_STATE);
        a = step(&s, GUEST_EV_GUEST_STOPPED, 11);
        ASSERT_EQ(a.reason, GUEST_REASON_IGNORED_STATE);
        a = stepp(&s, GUEST_EV_PORT_OPENED, 12, 1);
        ASSERT_EQ(a.reason, GUEST_REASON_IGNORED_STATE);
        a = step(&s, GUEST_EV_OPERATOR_RESET, 13);
        ASSERT_EQ(a.reason, GUEST_REASON_IGNORED_STATE);
        a = step(&s, GUEST_EV_REVOKED_ALL, 14);
        ASSERT_EQ(a.reason, GUEST_REASON_IGNORED_STATE);
        a = stepp(&s, GUEST_EV_REVOKED_PEER, 14, 1);
        ASSERT_EQ(a.reason, GUEST_REASON_IGNORED_STATE);
        a = bind_slot(&s, 0, 1, 14);
        ASSERT_EQ(a.reason, GUEST_REASON_IGNORED_STATE);
        a = step(&s, GUEST_EV_CALLBACK_OVERRUN, 15);
        ASSERT_EQ(a.reason, GUEST_REASON_IGNORED_STATE);
        a = step(&s, GUEST_EV_TICK, 16);
        ASSERT_EQ(a.kind, GUEST_ACTION_NONE);
        ASSERT_EQ(a.reason, GUEST_REASON_IGNORED_TICK);
        a = set_enable(&s, true, 17);
        ASSERT_EQ(a.reason, GUEST_REASON_IGNORED_NO_CHANGE);
        ASSERT_EQ(s.state, GUEST_STATE_ABSENT);
        make_ready(&s, 100);
        a = stepp(&s, GUEST_EV_PORT_CLOSED, 2000, 1);
        ASSERT_EQ(a.reason, GUEST_REASON_IGNORED_NO_PORT);
        a = stepp(&s, GUEST_EV_REVOKED_PEER, 2000, 1);
        ASSERT_EQ(a.reason, GUEST_REASON_IGNORED_UNKNOWN_PEER);
        a = step(&s, GUEST_EV_OPERATOR_START, 2001);
        ASSERT_EQ(a.reason, GUEST_REASON_IGNORED_RUNNING);
        a = step(&s, GUEST_EV_BOOT_READY, 2002);
        ASSERT_EQ(a.reason, GUEST_REASON_IGNORED_STATE);
        a = step(&s, GUEST_EV_BOOT_FAILED, 2003);
        ASSERT_EQ(a.reason, GUEST_REASON_IGNORED_STATE);
        ASSERT_EQ(s.state, GUEST_STATE_READY);
        a = step(&s, (enum guest_event_kind)99, 2004);
        ASSERT_EQ(a.kind, GUEST_ACTION_NONE);
        ASSERT_EQ(a.reason, GUEST_REASON_IGNORED_BAD_EVENT);
        ASSERT(!guest_service_step(NULL, &(struct guest_event){ 0 }, 0, &a));
        ASSERT(!guest_service_step(&s, NULL, 0, &a));
        ASSERT(!guest_service_step(&s, &(struct guest_event){ 0 }, 0, NULL));
        PASS();
    }
_test_next:
    return failures;
}

static int case_snapshot(void)
{
    int failures = 0;
    struct guest_service s;
    struct guest_service_snapshot snap;

    TEST("guest_service: the snapshot shows state, sessions, generation, last failure and backoff") {
        fresh_enabled(&s);
        (void)boot_fail(&s, 0);
        ASSERT(guest_service_snapshot(&s, 11000, &snap));
        ASSERT_EQ(snap.state, GUEST_STATE_ABSENT);
        ASSERT(snap.enabled);
        ASSERT_EQ(snap.generation, (uint32_t)1);
        ASSERT_EQ(snap.last_failure, GUEST_REASON_BOOT_FAILED);
        ASSERT_EQ(snap.backoff_left_ms, (uint64_t)20000);
        make_ready(&s, 31000);
        (void)bind_slot(&s, 0, 4, 32500);
        (void)stepp(&s, GUEST_EV_PORT_OPENED, 33000, 4);
        ASSERT(guest_service_snapshot(&s, 33000, &snap));
        ASSERT_EQ(snap.state, GUEST_STATE_SERVING);
        ASSERT_EQ(snap.ports, (uint32_t)1);
        ASSERT_EQ(snap.sessions, (uint32_t)1);
        ASSERT(!guest_service_snapshot(NULL, 0, &snap));
        ASSERT(!guest_service_snapshot(&s, 0, NULL));
        PASS();
    }
_test_next:
    return failures;
}

/* ---- governor helpers ------------------------------------------------- */

#define SIM_MAX_SLICES 20000u

struct sim_slice { uint64_t end_us; uint64_t cost_us; };
static struct sim_slice g_slices[SIM_MAX_SLICES];
static size_t g_nslices;

static struct guest_governor g_gov;

static uint64_t g_rng = 12345;
static uint32_t sim_rand(void)
{
    g_rng = g_rng * UINT64_C(6364136223846793005) + UINT64_C(1442695040888963407);
    return (uint32_t)(g_rng >> 33);
}

/* Is every window of `window_us` within budget by at most the one slice that
 * was admitted last? For each slice j: what the window held before j is
 * under the budget, because j was only admitted under it. */
static bool windows_hold(uint64_t window_us, uint64_t budget_us, uint64_t *worst_out)
{
    size_t lo = 0;
    uint64_t sum = 0, worst = 0;

    for (size_t hi = 0; hi < g_nslices; hi++) {
        sum += g_slices[hi].cost_us;
        while (g_slices[hi].end_us - g_slices[lo].end_us >= window_us) {
            sum -= g_slices[lo].cost_us;
            lo++;
        }
        if (sum > worst) worst = sum;
        if (sum - g_slices[hi].cost_us >= budget_us) {
            *worst_out = worst;
            return false;
        }
    }
    *worst_out = worst;
    return true;
}

/* An always-wanting-to-run guest. cost_of() picks the host cost of each
 * slice. With `chaos` a call may carry a stale (backwards) clock, including
 * the call that reports a slice's cost, and a sleep may be followed by a time
 * jump. A slice is recorded at the time the governor was given when the cost
 * was reported (the later of that and every earlier one): the bound is on the
 * clock the governor was told. */
static uint64_t cost_fixed(size_t n) { (void)n; return 20000; }

static uint64_t g_big_at = 777;

static uint64_t cost_varied(size_t n)
{
    static const uint64_t table[] = { 2000, 5000, 20000, 50000, 60000, 120000 };

    if (n == g_big_at) return 2000000;            /* the one 2 s slice */
    return table[sim_rand() % (sizeof(table) / sizeof(table[0]))];
}

static void sim_spin(uint64_t until_ms, bool startup, bool chaos,
                     uint64_t (*cost_of)(size_t))
{
    uint64_t t_us = 0, pending = 0, gov_ms = 0;
    struct guest_gov_decision d;

    g_nslices = 0;
    while (t_us / 1000 < until_ms && g_nslices < SIM_MAX_SLICES) {
        uint64_t pass_ms = t_us / 1000;
        uint64_t reported = pending;

        if (chaos && sim_rand() % 16 == 0)
            pass_ms = pass_ms > 5000 ? pass_ms - sim_rand() % 5000 : 0;
        if (pass_ms > gov_ms) gov_ms = pass_ms;
        if (reported > 0) {
            g_slices[g_nslices].end_us = gov_ms * 1000;
            g_slices[g_nslices++].cost_us = reported;
        }
        pending = 0;
        if (!guest_governor_next(&g_gov, pass_ms, reported, 0, false, startup, &d)) return;
        if (d.kind == GUEST_GOV_RUN_SLICE) {
            pending = cost_of(g_nslices);
            t_us += pending;
        } else {
            t_us += d.sleep_ms * 1000;
            if (chaos && sim_rand() % 40 == 0) t_us += (3 + sim_rand() % 27) * UINT64_C(1000000);
        }
    }
}

static bool adversarial_ok(const struct guest_limits *l, uint64_t big_at, size_t min_slices)
{
    uint64_t worst = 0;
    bool big = false;

    g_rng = 12345;
    g_big_at = big_at;
    if (!guest_governor_init(&g_gov, l)) return false;
    sim_spin(1200u * 1000u, false, true, cost_varied);
    for (size_t i = 0; i < g_nslices; i++)
        if (g_slices[i].cost_us == 2000000) big = true;
    return g_nslices >= min_slices && big &&
           windows_hold(UINT64_C(10000) * 1000, (uint64_t)l->short_budget_ms * 1000, &worst) &&
           windows_hold((uint64_t)l->window_ms * 1000,
                        (uint64_t)l->window_ms * 1000 / 100 * l->duty_percent, &worst);
}

/* Calls every millisecond for 6 s; no two runs more than n apart inside a
 * closed second. With `stale`, every third call carries an older clock. */
static bool rate_sweep_ok(uint32_t n, bool stale)
{
    static struct guest_governor g;
    static uint64_t runs[2000];
    struct guest_limits l = guest_limits_default();
    struct guest_gov_decision d;
    uint64_t gov_ms = 0;
    size_t count = 0;

    l.max_slices_per_second = n;
    if (!guest_governor_init(&g, &l)) return false;
    for (uint64_t ms = 0; ms <= 6000 && count < 2000; ms++) {
        uint64_t pass = stale && ms % 3 == 0 && ms > 500 ? ms - 400 : ms;

        if (pass > gov_ms) gov_ms = pass;
        if (!guest_governor_next(&g, pass, 1, 0, false, false, &d)) return false;
        if (d.kind == GUEST_GOV_RUN_SLICE) runs[count++] = gov_ms;
    }
    if (count < (size_t)n * 5) return false;
    for (size_t i = 0; i + n < count; i++)
        if (runs[i + n] - runs[i] <= 1000) return false;
    return true;
}

/* ---- governor cases --------------------------------------------------- */

static int case_limits_validated(void)
{
    int failures = 0;
    struct guest_limits l = guest_limits_default();
    struct guest_governor g;
    struct guest_gov_decision d;

    TEST("guest_governor: the default limits are the brief's and are accepted") {
        ASSERT(guest_limits_ok(&l));
        ASSERT_EQ(l.slice_work, (uint64_t)1000000);
        ASSERT_EQ(l.max_slices_per_second, (uint32_t)100);
        ASSERT_EQ(l.duty_percent, (uint32_t)10);
        ASSERT_EQ(l.window_ms, (uint32_t)60000);
        ASSERT_EQ(l.short_budget_ms, (uint32_t)1000);
        ASSERT(!guest_limits_ok(NULL));
        PASS();
    }
    TEST("guest_governor: zero and absurd limits are refused") {
        l = guest_limits_default(); l.slice_work = 0;
        ASSERT(!guest_limits_ok(&l));
        l = guest_limits_default(); l.slice_work = GUEST_GOV_SLICE_WORK_MIN - 1;
        ASSERT(!guest_limits_ok(&l));
        l = guest_limits_default(); l.slice_work = UINT64_MAX;
        ASSERT(!guest_limits_ok(&l));
        l = guest_limits_default(); l.max_slices_per_second = 0;
        ASSERT(!guest_limits_ok(&l));
        l = guest_limits_default(); l.max_slices_per_second = 1000000;
        ASSERT(!guest_limits_ok(&l));
        l = guest_limits_default(); l.duty_percent = 0;
        ASSERT(!guest_limits_ok(&l));
        l = guest_limits_default(); l.short_budget_ms = 0;
        ASSERT(!guest_limits_ok(&l));
        l = guest_limits_default(); l.window_ms = 0;
        ASSERT(!guest_limits_ok(&l));
        l = guest_limits_default(); l.window_ms = GUEST_GOV_WINDOW_MS_MAX + 1000;
        ASSERT(!guest_limits_ok(&l));
        l = guest_limits_default(); l.window_ms = 60500;
        ASSERT(!guest_limits_ok(&l));
        PASS();
    }
    TEST("guest_governor: an operator may lower the duty and the burst but never raise them") {
        l = guest_limits_default(); l.duty_percent = 5;
        ASSERT(guest_limits_ok(&l));
        l.duty_percent = 1;
        ASSERT(guest_limits_ok(&l));
        l.duty_percent = GUEST_GOV_DUTY_PERCENT_MAX + 1;
        ASSERT(!guest_limits_ok(&l));
        ASSERT(!guest_governor_init(&g, &l));
        l = guest_limits_default(); l.short_budget_ms = 500;
        ASSERT(guest_limits_ok(&l));
        l.short_budget_ms = GUEST_GOV_SHORT_BUDGET_MS_MAX + 1;
        ASSERT(!guest_limits_ok(&l));
        PASS();
    }
    TEST("guest_governor: a governor whose limits were refused never runs the guest") {
        ASSERT(!guest_governor_init(&g, &l));
        ASSERT(guest_governor_next(&g, 1000, 0, 0, true, false, &d));
        ASSERT_EQ(d.kind, GUEST_GOV_SLEEP);
        ASSERT_EQ(d.reason, GUEST_SLEEP_NOT_READY);
        ASSERT(d.sleep_ms >= 1 && d.sleep_ms <= GUEST_GOV_MAX_SLEEP_MS);
        ASSERT(!guest_governor_next(NULL, 0, 0, 0, false, false, &d));
        ASSERT(!guest_governor_next(&g, 0, 0, 0, false, false, NULL));
        PASS();
    }
_test_next:
    return failures;
}

static int case_spinning_guest_stays_under_ceilings(void)
{
    int failures = 0;
    struct guest_limits l = guest_limits_default();
    uint64_t worst = 0;

    TEST("guest_governor: a spinning guest never exceeds 1050 ms in any 10 s nor 10 percent plus one slice over 60 s") {
        ASSERT(guest_governor_init(&g_gov, &l));
        sim_spin(600u * 1000u, false, false, cost_fixed);
        ASSERT(g_nslices > 2000);
        ASSERT(windows_hold(10u * UINT64_C(1000000), UINT64_C(1000000), &worst));
        printf("(%zu slices, worst 10 s %llu us) ", g_nslices, (unsigned long long)worst);
        ASSERT(worst <= 1050000);
        ASSERT(worst >= 500000);
        ASSERT(windows_hold(60u * UINT64_C(1000000), UINT64_C(6000000), &worst));
        ASSERT(worst <= 6050000);
        PASS();
    }
_test_next:
    return failures;
}

static int case_windows_hold_adversarially(void)
{
    int failures = 0;
    struct guest_limits l = guest_limits_default();
    struct guest_limits other = { .slice_work = 50000, .max_slices_per_second = 30,
                                  .duty_percent = 4, .window_ms = 30000,
                                  .short_budget_ms = 400 };

    TEST("guest_governor: varying cost, a 2 s slice, time jumps and a stale clock stay within budget plus one slice") {
        ASSERT(adversarial_ok(&l, 777, 1000));
        PASS();
    }
    TEST("guest_governor: the same holds under non-default limits") {
        ASSERT(guest_limits_ok(&other));
        ASSERT(adversarial_ok(&other, 100, 250));
        PASS();
    }
_test_next:
    return failures;
}

static int case_other_window(void)
{
    int failures = 0;
    struct guest_limits l = guest_limits_default();
    uint64_t worst = 0;

    TEST("guest_governor: a long window other than 60 s is the one enforced") {
        l.window_ms = 20000;
        l.duty_percent = 1;                       /* 200 ms in 20 s: tighter than the 10 s rule */
        ASSERT(guest_governor_init(&g_gov, &l));
        sim_spin(200u * 1000u, false, false, cost_fixed);
        ASSERT(g_nslices > 50);
        ASSERT(windows_hold(20u * UINT64_C(1000000), UINT64_C(200000), &worst));
        printf("(%zu slices, worst 20 s %llu us) ", g_nslices, (unsigned long long)worst);
        ASSERT(worst <= 220000);
        PASS();
    }
_test_next:
    return failures;
}

static int case_startup_ceilings(void)
{
    int failures = 0;
    struct guest_limits l = guest_limits_default();
    uint64_t worst = 0;

    TEST("guest_governor: while STARTING the ceilings are 50 percent and 5000 ms in any 10 s") {
        ASSERT(guest_governor_init(&g_gov, &l));
        sim_spin(120u * 1000u, true, false, cost_fixed);
        ASSERT(windows_hold(10u * UINT64_C(1000000), UINT64_C(5000000), &worst));
        printf("(worst 10 s %llu us) ", (unsigned long long)worst);
        ASSERT(worst > 4000000);                  /* well past the normal 1000 ms */
        ASSERT(worst <= 5020000);
        ASSERT(windows_hold(60u * UINT64_C(1000000), UINT64_C(30000000), &worst));
        ASSERT(worst > 20000000);
        PASS();
    }
    TEST("guest_governor: the normal ceilings hold again once startup is over") {
        ASSERT(guest_governor_init(&g_gov, &l));
        sim_spin(120u * 1000u, false, false, cost_fixed);
        ASSERT(windows_hold(10u * UINT64_C(1000000), UINT64_C(1000000), &worst));
        ASSERT(worst <= 1020000);
        PASS();
    }
_test_next:
    return failures;
}

static int case_time_jumps_and_ring(void)
{
    int failures = 0;
    struct guest_governor g;
    struct guest_limits l = guest_limits_default();
    struct guest_gov_decision d;

    TEST("guest_governor: usage older than the window is forgotten after a jump, even onto the same ring slot") {
        ASSERT(guest_governor_init(&g, &l));
        ASSERT(guest_governor_next(&g, 1000, 6000000, 0, false, false, &d));
        ASSERT_EQ(d.reason, GUEST_SLEEP_DUTY_CEILING);
        /* The ring has 602 one-second slots: second 603 shares second 1's. */
        ASSERT(guest_governor_next(&g, 603000, 0, 0, false, false, &d));
        ASSERT_EQ(d.kind, GUEST_GOV_RUN_SLICE);
        ASSERT(guest_governor_init(&g, &l));
        ASSERT(guest_governor_next(&g, 1000, 6000000, 0, false, false, &d));
        ASSERT(guest_governor_next(&g, 1000 + UINT64_C(5000000000), 0, 0, false, false, &d));
        ASSERT_EQ(d.kind, GUEST_GOV_RUN_SLICE);
        PASS();
    }
_test_next:
    return failures;
}

static int case_slice_rate_rolling(void)
{
    int failures = 0;
    struct guest_governor g;
    struct guest_limits l = guest_limits_default();
    struct guest_gov_decision d;
    int run = 0, rate_sleeps = 0;
    static uint64_t runs[2000];
    size_t n = 0;

    TEST("guest_governor: at most 100 slices a second, then SLICE_RATE") {
        ASSERT(guest_governor_init(&g, &l));
        for (int i = 0; i < 150; i++) {
            ASSERT(guest_governor_next(&g, 5250, 1, 0, false, false, &d));
            if (d.kind == GUEST_GOV_RUN_SLICE) {
                ASSERT_EQ(d.work, (uint64_t)1000000);
                run++;
            } else if (d.reason == GUEST_SLEEP_SLICE_RATE) {
                ASSERT(d.sleep_ms >= 1 && d.sleep_ms <= GUEST_GOV_MAX_SLEEP_MS);
                rate_sleeps++;
            }
        }
        ASSERT_EQ(run, 100);
        ASSERT_EQ(rate_sleeps, 50);
        PASS();
    }
    TEST("guest_governor: the limit holds in any rolling second, not only calendar seconds") {
        /* A burst at the end of one calendar second must not be followed by
         * another at the start of the next: 200 inside one second. */
        ASSERT(guest_governor_init(&g, &l));
        for (uint64_t ms = 0; ms < 8000 && n < 2000; ms++) {
            uint64_t now = 100 + ms;

            /* calls cluster at x.900 .. x.999 and x.000 .. x.099 */
            if (now % 1000 > 100 && now % 1000 < 900) continue;
            ASSERT(guest_governor_next(&g, now, 1, 0, false, false, &d));
            if (d.kind == GUEST_GOV_RUN_SLICE) runs[n++] = now;
        }
        ASSERT(n > 300);
        for (size_t i = 0; i + 100 < n; i++)
            ASSERT(runs[i + 100] - runs[i] > 1000);   /* the 101st is over a second on */
        PASS();
    }
    TEST("guest_governor: a rate other than 100 holds, with and without a stale clock") {
        ASSERT(rate_sweep_ok(100, false));
        ASSERT(rate_sweep_ok(7, false));
        ASSERT(rate_sweep_ok(7, true));
        ASSERT(rate_sweep_ok(100, true));
        PASS();
    }
    TEST("guest_governor: a start at exactly 1000 ms after the Nth earlier one is refused, 1001 is allowed") {
        l.max_slices_per_second = 7;
        ASSERT(guest_governor_init(&g, &l));
        for (int i = 0; i < 7; i++) {
            ASSERT(guest_governor_next(&g, 3000, 1, 0, false, false, &d));
            ASSERT_EQ(d.kind, GUEST_GOV_RUN_SLICE);
        }
        ASSERT(guest_governor_next(&g, 3000, 1, 0, false, false, &d));
        ASSERT_EQ(d.reason, GUEST_SLEEP_SLICE_RATE);
        ASSERT(guest_governor_next(&g, 4000, 1, 0, false, false, &d));
        ASSERT_EQ(d.reason, GUEST_SLEEP_SLICE_RATE);
        ASSERT_EQ(d.sleep_ms, (uint64_t)1);
        ASSERT(guest_governor_next(&g, 4001, 1, 0, false, false, &d));
        ASSERT_EQ(d.kind, GUEST_GOV_RUN_SLICE);
        PASS();
    }
    TEST("guest_governor: a clock stepping back does not reopen the rate window") {
        ASSERT(guest_governor_init(&g, &l));
        for (int i = 0; i < 7; i++)
            ASSERT(guest_governor_next(&g, 9000, 1, 0, false, false, &d));
        ASSERT(guest_governor_next(&g, 100, 1, 0, false, false, &d));
        ASSERT_EQ(d.reason, GUEST_SLEEP_SLICE_RATE);
        PASS();
    }
_test_next:
    return failures;
}

static int case_slice_sizing(void)
{
    int failures = 0;
    struct guest_governor g;
    struct guest_limits l = guest_limits_default();
    struct guest_gov_decision d;
    uint64_t now;

    TEST("guest_governor: a 200 ms slice halves the next call's work") {
        now = 1000;
        ASSERT(guest_governor_init(&g, &l));
        ASSERT(guest_governor_next(&g, now, 0, 0, false, false, &d));
        ASSERT_EQ(d.work, (uint64_t)1000000);
        ASSERT(guest_governor_next(&g, now + 200, 200000, 0, false, false, &d));
        ASSERT_EQ(d.kind, GUEST_GOV_RUN_SLICE);
        ASSERT_EQ(d.work, (uint64_t)500000);
        PASS();
    }
    TEST("guest_governor: the work never goes below 10,000") {
        now = 1000;
        ASSERT(guest_governor_init(&g, &l));
        for (int i = 0; i < 12; i++) {
            now += 1000;
            ASSERT(guest_governor_next(&g, now, 60000, 0, false, false, &d));
            ASSERT_EQ(d.kind, GUEST_GOV_RUN_SLICE);
            ASSERT(d.work >= GUEST_GOV_SLICE_WORK_MIN);
        }
        ASSERT_EQ(d.work, GUEST_GOV_SLICE_WORK_MIN);
        PASS();
    }
    TEST("guest_governor: 10001 halves to the 10,000 floor, not to 5000") {
        now = 1000;
        l.slice_work = 10001;
        ASSERT(guest_governor_init(&g, &l));
        ASSERT(guest_governor_next(&g, now, 60000, 0, false, false, &d));
        ASSERT_EQ(d.work, GUEST_GOV_SLICE_WORK_MIN);
        l = guest_limits_default();
        PASS();
    }
    TEST("guest_governor: 8 consecutive slices under 25 ms double the work back, no sooner") {
        now = 1000;
        ASSERT(guest_governor_init(&g, &l));
        for (int i = 0; i < 12; i++) {                       /* down to the floor */
            now += 1000;
            ASSERT(guest_governor_next(&g, now, 60000, 0, false, false, &d));
        }
        for (int i = 0; i < 7; i++) {
            now += 1000;
            ASSERT(guest_governor_next(&g, now, 10000, 0, false, false, &d));
            ASSERT_EQ(d.work, GUEST_GOV_SLICE_WORK_MIN);
        }
        now += 1000;
        ASSERT(guest_governor_next(&g, now, 10000, 0, false, false, &d));
        ASSERT_EQ(d.work, GUEST_GOV_SLICE_WORK_MIN * 2);
        PASS();
    }
    TEST("guest_governor: a slice between 25 and 50 ms breaks the run of fast slices") {
        now = 1000;
        ASSERT(guest_governor_init(&g, &l));
        now += 1000;
        ASSERT(guest_governor_next(&g, now, 60000, 0, false, false, &d));
        ASSERT_EQ(d.work, (uint64_t)500000);
        for (int i = 0; i < 7; i++) {
            now += 1000;
            ASSERT(guest_governor_next(&g, now, 10000, 0, false, false, &d));
        }
        now += 1000;
        ASSERT(guest_governor_next(&g, now, 30000, 0, false, false, &d));
        now += 1000;
        ASSERT(guest_governor_next(&g, now, 10000, 0, false, false, &d));
        ASSERT_EQ(d.work, (uint64_t)500000);
        PASS();
    }
    TEST("guest_governor: doubling stops at the configured slice") {
        now = 1000;
        ASSERT(guest_governor_init(&g, &l));
        now += 1000;
        ASSERT(guest_governor_next(&g, now, 60000, 0, false, false, &d));
        ASSERT_EQ(d.work, (uint64_t)500000);
        for (int i = 0; i < 40; i++) {
            now += 1000;
            ASSERT(guest_governor_next(&g, now, 1000, 0, false, false, &d));
            ASSERT(d.work <= (uint64_t)1000000);
        }
        ASSERT_EQ(d.work, (uint64_t)1000000);
        PASS();
    }
_test_next:
    return failures;
}

static int case_idle_guest_sleeps(void)
{
    int failures = 0;
    struct guest_governor g;
    struct guest_limits l = guest_limits_default();
    struct guest_gov_decision d;
    int runs = 0;

    TEST("guest_governor: an idle guest with a deadline 500 ms away yields no slice and sleeps at most 500") {
        ASSERT(guest_governor_init(&g, &l));
        ASSERT(guest_governor_next(&g, 7000, 0, 500, false, false, &d));
        ASSERT_EQ(d.kind, GUEST_GOV_SLEEP);
        ASSERT_EQ(d.reason, GUEST_SLEEP_IDLE_UNTIL_DEADLINE);
        ASSERT(d.sleep_ms >= 1 && d.sleep_ms <= 500);
        for (uint64_t t = 7000; t < 67000; t += d.sleep_ms) {
            ASSERT(guest_governor_next(&g, t, 0, 500, false, false, &d));
            if (d.kind == GUEST_GOV_RUN_SLICE) runs++;
        }
        ASSERT_EQ(runs, 0);
        PASS();
    }
    TEST("guest_governor: no deadline and no input sleeps for input with a bounded sleep") {
        ASSERT(guest_governor_next(&g, 8000, 0, GUEST_GOV_NO_DEADLINE, false, false, &d));
        ASSERT_EQ(d.kind, GUEST_GOV_SLEEP);
        ASSERT_EQ(d.reason, GUEST_SLEEP_IDLE_UNTIL_INPUT);
        ASSERT(d.sleep_ms >= 1 && d.sleep_ms <= GUEST_GOV_MAX_SLEEP_MS);
        ASSERT(guest_governor_next(&g, 8001, 0, 3600000, false, false, &d));
        ASSERT_EQ(d.reason, GUEST_SLEEP_IDLE_UNTIL_DEADLINE);
        ASSERT_EQ(d.sleep_ms, (uint64_t)GUEST_GOV_MAX_SLEEP_MS);
        PASS();
    }
    TEST("guest_governor: pending input runs an idle guest") {
        ASSERT(guest_governor_next(&g, 9000, 0, GUEST_GOV_NO_DEADLINE, true, false, &d));
        ASSERT_EQ(d.kind, GUEST_GOV_RUN_SLICE);
        PASS();
    }
_test_next:
    return failures;
}

static int case_input_and_clock(void)
{
    int failures = 0;
    struct guest_governor g;
    struct guest_limits l = guest_limits_default();
    struct guest_gov_decision d;

    TEST("guest_governor: pending input does not override the duty ceiling") {
        ASSERT(guest_governor_init(&g, &l));
        /* 6 s of host time in one report fills the 10 percent of 60 s. */
        ASSERT(guest_governor_next(&g, 20000, 6000000, 0, true, false, &d));
        ASSERT_EQ(d.kind, GUEST_GOV_SLEEP);
        ASSERT_EQ(d.reason, GUEST_SLEEP_DUTY_CEILING);
        ASSERT_EQ(d.sleep_ms, (uint64_t)1000);
        PASS();
    }
    TEST("guest_governor: the short window alone stops a burst the long window would allow") {
        ASSERT(guest_governor_init(&g, &l));
        ASSERT(guest_governor_next(&g, 30000, 1000000, 0, false, false, &d));
        ASSERT_EQ(d.reason, GUEST_SLEEP_DUTY_CEILING);
        ASSERT(guest_governor_next(&g, 39999, 0, 0, false, false, &d));
        ASSERT_EQ(d.reason, GUEST_SLEEP_DUTY_CEILING);
        ASSERT(guest_governor_next(&g, 41000, 0, 0, false, false, &d));
        ASSERT_EQ(d.kind, GUEST_GOV_RUN_SLICE);
        PASS();
    }
    TEST("guest_governor: a now that goes backwards is no time elapsed") {
        ASSERT(guest_governor_init(&g, &l));
        ASSERT(guest_governor_next(&g, 20000, 6000000, 0, true, false, &d));
        ASSERT(guest_governor_next(&g, 20500, 0, 0, true, false, &d));
        ASSERT_EQ(d.reason, GUEST_SLEEP_DUTY_CEILING);
        ASSERT_EQ(d.sleep_ms, (uint64_t)500);
        ASSERT(guest_governor_next(&g, 100, 0, 0, true, false, &d));
        ASSERT_EQ(d.reason, GUEST_SLEEP_DUTY_CEILING);
        ASSERT_EQ(d.sleep_ms, (uint64_t)500);
        PASS();
    }
    TEST("guest_governor: a ceiling or rate sleep is cut to the guest's real deadline, never below 1 ms") {
        ASSERT(guest_governor_init(&g, &l));
        ASSERT(guest_governor_next(&g, 20000, 6000000, 300, false, false, &d));
        ASSERT_EQ(d.reason, GUEST_SLEEP_DUTY_CEILING);
        ASSERT_EQ(d.sleep_ms, (uint64_t)300);
        ASSERT(guest_governor_next(&g, 20000, 0, 1, false, false, &d));
        ASSERT_EQ(d.sleep_ms, (uint64_t)1);
        ASSERT(guest_governor_next(&g, 20000, 0, 5000, false, false, &d));
        ASSERT_EQ(d.sleep_ms, (uint64_t)1000);            /* a later deadline cuts nothing */
        ASSERT(guest_governor_next(&g, 20000, 0, 0, false, false, &d));
        ASSERT_EQ(d.sleep_ms, (uint64_t)1000);            /* runnable now: no cut */
        ASSERT(guest_governor_next(&g, 20000, 0, GUEST_GOV_NO_DEADLINE, false, false, &d));
        ASSERT_EQ(d.sleep_ms, (uint64_t)1000);
        l.max_slices_per_second = 7;
        ASSERT(guest_governor_init(&g, &l));
        for (int i = 0; i < 7; i++)
            ASSERT(guest_governor_next(&g, 3000, 1, 0, false, false, &d));
        ASSERT(guest_governor_next(&g, 3000, 1, 40, false, false, &d));
        ASSERT_EQ(d.reason, GUEST_SLEEP_SLICE_RATE);
        ASSERT_EQ(d.sleep_ms, (uint64_t)40);
        PASS();
    }
_test_next:
    return failures;
}

/* ---- names ------------------------------------------------------------ */

static bool names_ok(const char *(*name)(unsigned), unsigned count)
{
    for (unsigned i = 0; i < count; i++) {
        const char *a = name(i);

        if (!a || !a[0] || strcmp(a, "unknown") == 0) return false;
        for (unsigned j = i + 1; j < count; j++)
            if (strcmp(a, name(j)) == 0) return false;
    }
    return strcmp(name(count), "unknown") == 0 && strcmp(name(99), "unknown") == 0;
}

static int case_start_refused_settlement(void)
{
    int failures = 0;
    struct guest_service s;
    struct guest_action a;
    uint64_t now = 100;

    TEST("guest_service: start refusal settles once without a stop or join and the fourth fails") {
        fresh_enabled(&s);
        for (uint32_t attempt = 1; attempt <= 4; attempt++) {
            a = step(&s, GUEST_EV_OPERATOR_START, now);
            ASSERT_EQ(a.kind, GUEST_ACTION_START_GUEST);
            a = step_ev(&s, (struct guest_event){ .kind = GUEST_EV_START_REFUSED,
                         .reason = GUEST_REASON_NOT_SEEDED }, ++now);
            ASSERT_EQ(a.kind, GUEST_ACTION_NONE);
            ASSERT_EQ(a.reason, GUEST_REASON_NOT_SEEDED);
            ASSERT_EQ(s.generation, attempt);
            ASSERT_EQ(s.recent_count, attempt < 4 ? attempt : (uint32_t)3);
            ASSERT_EQ(s.state, attempt < 4 ? GUEST_STATE_ABSENT : GUEST_STATE_FAILED);
            ASSERT(!s.pending_failed);
            ASSERT(!s.stop_counted);
            a = step(&s, GUEST_EV_START_REFUSED, now);
            ASSERT_EQ(a.reason, GUEST_REASON_IGNORED_STATE);
            ASSERT_EQ(s.generation, attempt);
            if (attempt < 4) {
                uint64_t deadline = now + guest_service_backoff_ms(attempt);
                a = step(&s, GUEST_EV_OPERATOR_START, deadline - 1);
                ASSERT_EQ(a.kind, GUEST_ACTION_ANSWER_UNAVAILABLE);
                ASSERT_EQ(a.reason, GUEST_REASON_BACKOFF);
                ASSERT_EQ(a.retry_after_ms, (uint64_t)1);
                now = deadline;
            }
        }
        PASS();
    }
_test_next:
    return failures;
}

static int case_start_refused_wrong_state(void)
{
    int failures = 0;
    struct guest_service s;

    TEST("guest_service: start refusal changes no failure state outside STARTING") {
        for (unsigned state = 0; state < GUEST_STATE_COUNT; state++) {
            if (state == GUEST_STATE_STARTING) continue;
            fresh_enabled(&s);
            s.state = (enum guest_state)state;
            s.generation = 7;
            s.recent_count = 1;
            s.recent_ms[0] = 10;
            s.last_failure = GUEST_REASON_INJECT_FAILED;
            struct guest_action a = step(&s, GUEST_EV_START_REFUSED, 100);
            ASSERT_EQ(a.kind, GUEST_ACTION_NONE);
            ASSERT_EQ(a.reason, GUEST_REASON_IGNORED_STATE);
            ASSERT_EQ(s.state, (enum guest_state)state);
            ASSERT_EQ(s.generation, (uint32_t)7);
            ASSERT_EQ(s.recent_count, (uint32_t)1);
            ASSERT_EQ(s.last_failure, GUEST_REASON_INJECT_FAILED);
        }
        PASS();
    }
_test_next:
    return failures;
}

static int case_start_refused_reasons_and_boot_failed(void)
{
    int failures = 0;
    struct guest_service s;
    const enum guest_reason reasons[] = { GUEST_REASON_BOOT_FAILED,
        GUEST_REASON_NOT_SEEDED, GUEST_REASON_INJECT_FAILED, GUEST_REASON_COUNT };

    TEST("guest_service: start refusal validates boot reasons and BOOT_FAILED still requires stop and join") {
        for (unsigned i = 0; i < sizeof(reasons) / sizeof(reasons[0]); i++) {
            fresh_enabled(&s);
            (void)step(&s, GUEST_EV_OPERATOR_START, 100);
            struct guest_action a = step_ev(&s, (struct guest_event){
                .kind = GUEST_EV_START_REFUSED, .reason = reasons[i] }, 101);
            ASSERT_EQ(a.reason, i < 3 ? reasons[i] : GUEST_REASON_BOOT_FAILED);
            ASSERT_EQ(s.state, GUEST_STATE_ABSENT);
            ASSERT_EQ(s.generation, (uint32_t)1);
        }
        fresh_enabled(&s);
        (void)step(&s, GUEST_EV_OPERATOR_START, 100);
        struct guest_action a = step(&s, GUEST_EV_BOOT_FAILED, 101);
        ASSERT_EQ(a.kind, GUEST_ACTION_STOP_GUEST);
        ASSERT_EQ(s.state, GUEST_STATE_STOPPING);
        ASSERT(s.stop_counted);
        (void)step(&s, GUEST_EV_TICK, 102);
        ASSERT_EQ(s.state, GUEST_STATE_STOPPING);
        ASSERT_EQ(s.generation, (uint32_t)1);
        (void)step(&s, GUEST_EV_GUEST_STOPPED, 103);
        ASSERT_EQ(s.state, GUEST_STATE_ABSENT);
        ASSERT_EQ(s.generation, (uint32_t)1);
        PASS();
    }
_test_next:
    return failures;
}

static const char *n_state(unsigned v) { return guest_state_name((enum guest_state)v); }
static const char *n_event(unsigned v) { return guest_event_name((enum guest_event_kind)v); }
static const char *n_reason(unsigned v) { return guest_reason_name((enum guest_reason)v); }
static const char *n_action(unsigned v) { return guest_action_name((enum guest_action_kind)v); }
static const char *n_sleep(unsigned v) { return guest_sleep_reason_name((enum guest_sleep_reason)v); }

static int case_names(void)
{
    int failures = 0;

    TEST("guest_service: every state, event, reason, action and sleep reason has a non-empty unique name") {
        ASSERT(names_ok(n_state, GUEST_STATE_COUNT));
        ASSERT(names_ok(n_event, GUEST_EV_COUNT));
        ASSERT(names_ok(n_reason, GUEST_REASON_COUNT));
        ASSERT(names_ok(n_action, GUEST_ACTION_ANSWER_UNAVAILABLE + 1));
        ASSERT(names_ok(n_sleep, GUEST_SLEEP_REASON_COUNT));
        PASS();
    }
_test_next:
    return failures;
}

int test_guest_service(void);
int test_guest_service(void)
{
    int failures = 0;

    printf("\n=== guest_service tests ===\n");
    failures += case_disabled_starts_nothing();
    failures += case_open_starts_exactly_one();
    failures += case_fourth_failure_is_failed();
    failures += case_failures_age_out_of_the_hour();
    failures += case_backoff_doubles_and_caps();
    failures += case_startup_deadline();
    failures += case_ready_obeys_startup_deadline();
    failures += case_boot_failure_reasons();
    failures += case_idle_stop_at_the_deadline();
    failures += case_stop_join_abandons();
    failures += case_failure_during_stopping_not_double_counted();
    failures += case_fifth_port_refused();
    failures += case_two_slots();
    failures += case_revocation_is_per_peer();
    failures += case_time_going_backwards();
    failures += case_time_jump_clamped();
    failures += case_revoke_disable();
    failures += case_crash_after_ready();
    failures += case_callback_overrun();
    failures += case_generation_once_per_failure();
    failures += case_unlisted_events_are_ignored();
    failures += case_snapshot();
    failures += case_limits_validated();
    failures += case_spinning_guest_stays_under_ceilings();
    failures += case_windows_hold_adversarially();
    failures += case_other_window();
    failures += case_startup_ceilings();
    failures += case_time_jumps_and_ring();
    failures += case_slice_rate_rolling();
    failures += case_slice_sizing();
    failures += case_idle_guest_sleeps();
    failures += case_input_and_clock();
    failures += case_start_refused_settlement();
    failures += case_start_refused_wrong_state();
    failures += case_start_refused_reasons_and_boot_failed();
    failures += case_names();
    printf("=== guest_service tests done: %d failure(s) ===\n", failures);
    return failures;
}
