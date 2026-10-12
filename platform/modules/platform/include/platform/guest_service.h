/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * guest_service - the PURE decisions for a guest service launcher.
 *
 * Part A is the lifecycle: guest_service_step() reads one event and the
 * caller-owned state and says what the host must do (start the guest, stop
 * it, answer a peer "unavailable" with a named reason, or nothing). Part B is
 * the CPU governor: guest_governor_next() says whether the host may run one
 * more slice of the guest or must sleep, and for how long, and why.
 *
 * Everything here is pure. There is no guest, no machine, no thread, no
 * clock read, no I/O (not even logging) and no allocation. Time is an input
 * in monotonic milliseconds supplied by the caller. A `now` that goes
 * backwards is treated as no time elapsed. All time arithmetic uses the
 * subtraction form (now - since), so a counter near UINT64_MAX cannot
 * overflow a deadline. Every event the table does not list is a no-op
 * carrying a named IGNORED reason; nothing asserts. A bad argument returns
 * false; every other outcome is a named reason.
 *
 * A decision is NOT execution authority: the launcher that applies it, and
 * the report of what happened (GUEST_STOPPED, BOOT_READY, ...), are the
 * caller's job. This module never starts anything itself.
 */
#ifndef ZCL_PLATFORM_GUEST_SERVICE_H
#define ZCL_PLATFORM_GUEST_SERVICE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* ---- Part A: lifecycle ------------------------------------------------ */

#define GUEST_SERVICE_MAX_PORTS 4u
/* A link is a traffic plus a control port, so four ports carry two peers. */
#define GUEST_SERVICE_MAX_SESSIONS 2u
#define GUEST_SERVICE_IDLE_STOP_MS UINT64_C(300000)
/* Monotonic time from start to the ready marker; the host also keeps the
 * 600 million work bound and whichever trips first fails the start. */
#define GUEST_SERVICE_START_DEADLINE_MS UINT64_C(120000)
/* From a stop request to the run loop returned; past it the guest is
 * ABANDONED and nothing starts until an operator reset. */
#define GUEST_SERVICE_STOP_JOIN_MS UINT64_C(5000)
/* Failures tolerated per rolling hour; the next one moves to FAILED. */
#define GUEST_SERVICE_FAIL_LIMIT 3u
#define GUEST_SERVICE_FAIL_WINDOW_MS UINT64_C(3600000)
/* Callback overruns: this many inside the window fail the guest. */
#define GUEST_SERVICE_OVERRUN_LIMIT 3u
#define GUEST_SERVICE_OVERRUN_WINDOW_MS UINT64_C(60000)
/* One event moves the clock at most this far. A larger forward step is used
 * as exactly this much and the action reports time_jump_clamped; the next
 * event continues from there. The first event ever adopts its `now`. */
#define GUEST_SERVICE_MAX_TIME_STEP_MS UINT64_C(3600000)
#define GUEST_SERVICE_BACKOFF_BASE_MS UINT64_C(30000)
#define GUEST_SERVICE_BACKOFF_CAP_MS UINT64_C(900000)

enum guest_state {
    GUEST_STATE_ABSENT = 0,
    GUEST_STATE_STARTING,
    GUEST_STATE_READY,
    GUEST_STATE_SERVING,
    GUEST_STATE_IDLE,
    GUEST_STATE_STOPPING,
    GUEST_STATE_FAILED,
    GUEST_STATE_ABANDONED,
    GUEST_STATE_COUNT
};

enum guest_event_kind {
    GUEST_EV_ENABLE = 0,     /* .enable: true on, false off               */
    GUEST_EV_PEER_OPEN,      /* .peer: a paired peer opened the channel   */
    GUEST_EV_OPERATOR_START,
    GUEST_EV_OPERATOR_RESET,
    GUEST_EV_BOOT_READY,
    GUEST_EV_BOOT_FAILED,    /* .reason: boot_failed, not_seeded or inject_failed */
    GUEST_EV_PORT_OPENED,    /* .peer: whose port                         */
    GUEST_EV_PORT_CLOSED,    /* .peer: whose port                         */
    GUEST_EV_REVOKED_ALL,    /* no peer remains: retire every slot, stop  */
    GUEST_EV_REVOKED_PEER,   /* .peer: retire exactly that peer's slot    */
    GUEST_EV_SLOT_BOUND,     /* .slot, .peer: the authenticated binding was acknowledged */
    GUEST_EV_GUEST_STOPPED,  /* the run loop really returned (not merely asked to stop) */
    GUEST_EV_CALLBACK_OVERRUN, /* a device callback took over its bound   */
    GUEST_EV_TICK,
    /* Start refused before any run, with all factory allocations released. */
    GUEST_EV_START_REFUSED,
    GUEST_EV_COUNT
};

/* One stable value per refusal, failure, stop cause and ignored event. */
enum guest_reason {
    GUEST_REASON_NONE = 0,
    /* refusals: the peer or operator is answered unavailable */
    GUEST_REASON_DISABLED,
    GUEST_REASON_STARTING,
    GUEST_REASON_BACKOFF,
    GUEST_REASON_FAILED,
    GUEST_REASON_STOPPING,
    GUEST_REASON_ABANDONED,
    GUEST_REASON_PORT_LIMIT,
    GUEST_REASON_SESSIONS_FULL,
    GUEST_REASON_PEER_ALREADY_BOUND,
    GUEST_REASON_PEER_NOT_BOUND,
    GUEST_REASON_SLOT_NOT_UNBOUND,
    GUEST_REASON_GUEST_NOT_JOINED,    /* reset asked before the old guest returned */
    /* failures, counted against the hourly budget (contiguous) */
    GUEST_REASON_BOOT_FAILED,
    GUEST_REASON_STARTUP_DEADLINE,
    GUEST_REASON_GUEST_EXITED_EARLY,
    GUEST_REASON_NOT_SEEDED,
    GUEST_REASON_INJECT_FAILED,
    GUEST_REASON_CALLBACK_OVERRUN,
    GUEST_REASON_GUEST_CRASHED,       /* stopped after ready, unrequested */
    /* stop causes */
    GUEST_REASON_IDLE_TIMEOUT,
    GUEST_REASON_REVOKED,
    GUEST_REASON_DISABLED_WHILE_RUNNING,
    GUEST_REASON_STOP_JOIN_TIMEOUT,   /* also a counted failure (see below) */
    GUEST_REASON_TIME_JUMP_CLAMPED,   /* reported when nothing else is */
    /* no-ops */
    GUEST_REASON_IGNORED_STATE,       /* event not valid in this state    */
    GUEST_REASON_IGNORED_RUNNING,     /* start asked while one is up      */
    GUEST_REASON_IGNORED_NO_CHANGE,   /* enable/disable repeated          */
    GUEST_REASON_IGNORED_NO_PORT,     /* port closed that is not open     */
    GUEST_REASON_IGNORED_UNKNOWN_PEER,/* revoke of a peer with no bound slot */
    GUEST_REASON_IGNORED_BAD_EVENT,   /* event kind out of range          */
    GUEST_REASON_IGNORED_TICK,        /* tick with nothing due            */
    GUEST_REASON_COUNT
};

enum guest_action_kind {
    GUEST_ACTION_NONE = 0,
    GUEST_ACTION_START_GUEST,
    GUEST_ACTION_STOP_GUEST,
    GUEST_ACTION_ANSWER_UNAVAILABLE
};

struct guest_event {
    enum guest_event_kind kind;
    bool enable;                 /* ENABLE only                         */
    enum guest_reason reason;    /* BOOT_FAILED only                    */
    uint32_t peer;               /* PEER_OPEN, PORT_*, REVOKED_PEER, SLOT_BOUND */
    uint32_t slot;               /* SLOT_BOUND only                     */
};

struct guest_action {
    enum guest_action_kind kind;
    enum guest_reason reason;    /* why: refusal, failure, stop cause, ignore */
    uint64_t retry_after_ms;     /* BACKOFF: milliseconds left, else 0  */
    bool answer_unavailable;     /* the peer's open is answered UNAVAILABLE */
    bool time_jump_clamped;      /* the step was cut to MAX_TIME_STEP_MS */
};

/* Two immutable session slots per guest instance. A slot is bound once, to
 * one peer, after the authenticated binding is acknowledged; closing its
 * ports does not free it; a revoke retires it for the life of the instance.
 * All slots return to UNBOUND only when a new guest instance starts. */
enum guest_slot_state { GUEST_SLOT_UNBOUND = 0, GUEST_SLOT_BOUND, GUEST_SLOT_RETIRED };

/* Caller-owned. guest_service_init() sets the defaults: disabled, ABSENT. */
struct guest_service {
    enum guest_state state;
    bool enabled;
    bool pending_failed;         /* the stop in progress ends in FAILED */
    bool stop_counted;           /* the stop in progress already counted a failure */
    bool joined;                 /* ABANDONED: the old guest really returned */
    bool clock_started;          /* last_now_ms is meaningful          */
    uint32_t ports;              /* all open ports                     */
    enum guest_slot_state slot_state[GUEST_SERVICE_MAX_SESSIONS];
    uint32_t slot_peer[GUEST_SERVICE_MAX_SESSIONS];  /* BOUND/RETIRED  */
    uint32_t slot_ports[GUEST_SERVICE_MAX_SESSIONS];
    uint64_t last_now_ms;        /* highest `now` seen                 */
    uint64_t state_since_ms;     /* STARTING / READY / IDLE entry      */
    uint64_t stop_since_ms;      /* stop request                       */
    uint64_t backoff_from_ms;
    uint64_t backoff_len_ms;     /* 0: no backoff running              */
    uint32_t recent_count;       /* entries of recent_ms in use        */
    uint64_t recent_ms[GUEST_SERVICE_FAIL_LIMIT]; /* failure times, oldest first */
    uint32_t overrun_count;      /* entries of overrun_ms in use       */
    uint64_t overrun_ms[GUEST_SERVICE_OVERRUN_LIMIT - 1u];
    uint32_t generation;         /* bumped on every failure            */
    enum guest_reason last_failure;
};

/* What a status command shows. */
struct guest_service_snapshot {
    enum guest_state state;
    bool enabled;
    uint32_t ports;
    uint32_t sessions;
    uint32_t generation;
    uint32_t failures_in_hour;
    enum guest_reason last_failure;
    uint64_t backoff_left_ms;
};

void guest_service_init(struct guest_service *s);

/* Backoff after the nth failure in the hour (n >= 1): 30 s doubling to the
 * 15 minute cap. n == 0 gives 0. Overflow-safe for any n. */
uint64_t guest_service_backoff_ms(uint32_t failures);

/* Apply one event. Returns false only for a NULL argument; every other
 * input, including a bad event kind, returns true with a named action.
 * A failure while a guest runs goes through STOPPING (the stop-and-join
 * deadline applies) before FAILED or the backoff takes effect. A stop-join
 * timeout is itself a counted failure (generation bumped, last_failure
 * stop_join_timeout) unless the stop was already caused by a counted
 * failure. ABANDONED is left only by OPERATOR_RESET after GUEST_STOPPED
 * reported the old guest really returned (else guest_not_joined); that reset
 * does not clear the hour history. A reset out of FAILED does. */
/* START_REFUSED is STARTING-only: the owner confirmed no run was invoked and
 * all factory allocations were released. Its reason has BOOT_FAILED's
 * whitelist; it counts once and settles to backoff/FAILED without a join.
 * It is not the event for a failed invocation or a retained instance. */
bool guest_service_step(struct guest_service *s, const struct guest_event *ev,
                        uint64_t now_ms, struct guest_action *out);

bool guest_service_snapshot(const struct guest_service *s, uint64_t now_ms,
                            struct guest_service_snapshot *out);

const char *guest_state_name(enum guest_state state);
const char *guest_event_name(enum guest_event_kind kind);
const char *guest_reason_name(enum guest_reason reason);
const char *guest_action_name(enum guest_action_kind kind);

/* ---- Part B: CPU governor --------------------------------------------- */

#define GUEST_GOV_SLICE_WORK_DEFAULT UINT64_C(1000000)
#define GUEST_GOV_SLICE_WORK_MIN UINT64_C(10000)
#define GUEST_GOV_SLICES_PER_SECOND_DEFAULT 100u
#define GUEST_GOV_SLICES_PER_SECOND_MAX 1000u
/* Compiled maxima: an operator may lower these, never raise them. */
#define GUEST_GOV_DUTY_PERCENT_MAX 10u
#define GUEST_GOV_SHORT_BUDGET_MS_MAX 1000u
#define GUEST_GOV_WINDOW_MS_DEFAULT 60000u
#define GUEST_GOV_WINDOW_MS_MAX 600000u
#define GUEST_GOV_SHORT_WINDOW_MS 10000u
/* Startup ceilings (cold boot needs 19 to 46 s of host time). */
#define GUEST_GOV_STARTUP_DUTY_PERCENT 50u
#define GUEST_GOV_STARTUP_SHORT_BUDGET_MS 5000u
/* Slice sizing: a reported slice over SLOW halves the work; this many in a
 * row under FAST double it back up to the configured slice. */
#define GUEST_GOV_SLOW_SLICE_US UINT64_C(50000)
#define GUEST_GOV_FAST_SLICE_US UINT64_C(25000)
#define GUEST_GOV_FAST_RUN 8u
#define GUEST_GOV_MAX_SLEEP_MS 1000u
/* One bucket per second: the longest window plus the partial current one. */
#define GUEST_GOV_RING (GUEST_GOV_WINDOW_MS_MAX / 1000u + 2u)
#define GUEST_GOV_NO_DEADLINE UINT64_MAX

struct guest_limits {
    uint64_t slice_work;         /* work units per call                */
    uint32_t max_slices_per_second;
    uint32_t duty_percent;       /* of one core, 1..GUEST_GOV_DUTY_PERCENT_MAX */
    uint32_t window_ms;          /* multiple of 1000 */
    uint32_t short_budget_ms;    /* slice host ms in any 10 s, 1..GUEST_GOV_SHORT_BUDGET_MS_MAX */
};

enum guest_sleep_reason {
    GUEST_SLEEP_NONE = 0,
    GUEST_SLEEP_DUTY_CEILING,    /* the long or the short window is full */
    GUEST_SLEEP_SLICE_RATE,
    GUEST_SLEEP_IDLE_UNTIL_DEADLINE,
    GUEST_SLEEP_IDLE_UNTIL_INPUT,
    GUEST_SLEEP_NOT_READY,       /* governor unset or limits refused */
    GUEST_SLEEP_REASON_COUNT
};

enum guest_gov_kind { GUEST_GOV_RUN_SLICE = 0, GUEST_GOV_SLEEP };

struct guest_gov_decision {
    enum guest_gov_kind kind;
    uint64_t work;               /* RUN_SLICE: work units for this call */
    uint64_t sleep_ms;           /* SLEEP: at most GUEST_GOV_MAX_SLEEP_MS */
    enum guest_sleep_reason reason;
};

/* Caller-owned; fixed size, no allocation. */
struct guest_governor {
    struct guest_limits lim;
    bool ready;
    uint64_t last_now_ms;
    uint64_t work;               /* work for the next call, <= lim.slice_work */
    uint32_t fast_run;           /* consecutive reported slices under FAST */
    uint64_t rate_ms[GUEST_GOV_SLICES_PER_SECOND_MAX]; /* start times, ring */
    uint32_t rate_head;
    uint32_t rate_count;
    uint64_t ring_tag[GUEST_GOV_RING];  /* second + 1; 0 means empty   */
    uint64_t ring_us[GUEST_GOV_RING];   /* host microseconds per second */
};

struct guest_limits guest_limits_default(void);

/* true when every value is non-zero, in range, the duty and the short
 * budget are at most the compiled maxima and the window is a whole number
 * of seconds. */
bool guest_limits_ok(const struct guest_limits *lim);

/* Validates and installs the limits; false leaves the governor not ready,
 * so every guest_governor_next() sleeps with NOT_READY. */
bool guest_governor_init(struct guest_governor *g, const struct guest_limits *lim);

/* Decide the next step. Inputs:
 *   last_slice_host_us    host time the previous slice took (0 if none)
 *   next_guest_deadline_in_ms
 *                         milliseconds, relative to now, until the machine's
 *                         returned deadline: 0 means runnable now (a spinning
 *                         guest); GUEST_GOV_NO_DEADLINE means it waits for input
 *   input_pending         input is waiting AND the guest can run on it, taken
 *                         from the machine's runnable mask; a masked past
 *                         deadline arrives as GUEST_GOV_NO_DEADLINE
 *   startup               the guest is STARTING: the startup ceilings apply
 * Guarantees: the slice host time accounted in any window (60 s and 10 s,
 * or the startup pair) never exceeds its budget by more than one reported
 * slice; at most max_slices_per_second runs start in any rolling second; a
 * sleep is never longer than GUEST_GOV_MAX_SLEEP_MS so the caller
 * re-checks, and when the guest has a real deadline (neither 0 nor
 * NO_DEADLINE) a ceiling or rate sleep is cut to that deadline, never below
 * 1 ms. The work to run is in the decision. Returns false only for a
 * NULL argument. */
bool guest_governor_next(struct guest_governor *g, uint64_t now_ms,
                         uint64_t last_slice_host_us,
                         uint64_t next_guest_deadline_in_ms, bool input_pending,
                         bool startup, struct guest_gov_decision *out);

const char *guest_sleep_reason_name(enum guest_sleep_reason reason);

#endif /* ZCL_PLATFORM_GUEST_SERVICE_H */
