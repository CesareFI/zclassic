/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Property tests for engine/modules/health/heartbeat — the unified watchdog
 * surface. The architectural invariant this protects: edge-triggered
 * stall firing. A subsystem that misses one deadline must get exactly
 * one on_stall call, not a flood of them every sweep cycle. A
 * subsequent fresh heartbeat must re-arm the edge so the next stall
 * fires again.
 */

#include "test/test_core.h"
#include "health/heartbeat.h"
#include "json/json.h"
#include "zutf8/zutf8.h"
#include "core/utiltime.h"
#include "platform/clock.h"

#include <stdatomic.h>
#include <string.h>
#include <time.h>
#include <errno.h>

/* ASSERT jumps out of the subcase. Release its isolated ring and worker
 * before recording an assertion failure, including partially filled rings. */
#define HEALTH_ASSERT(cond) do { \
    if (!(cond)) { \
        health_reset_for_test(); \
        printf("FAIL at %s:%d (%s)\n", __FILE__, __LINE__, #cond); \
        failures++; goto _test_next; \
    } \
} while (0)

static _Atomic int g_stall_count;
static _Atomic int g_last_ctx_value;
static bool g_cleanup_inject_context;
static bool g_cleanup_inject_prefix;
static bool g_cleanup_injected;

static void stall_cb(void *ctx)
{
    atomic_fetch_add(&g_stall_count, 1);
    atomic_store(&g_last_ctx_value, (int)(intptr_t)ctx);
}

static int (*sleep_call)(const struct timespec *, struct timespec *) = nanosleep;

static bool sleep_ms(int ms)
{
    struct timespec ts = {
        .tv_sec  = ms / 1000,
        .tv_nsec = (long)(ms % 1000) * 1000000L,
    };
    while (sleep_call(&ts, &ts) != 0) {
        if (errno == EINTR) continue;
        fprintf(stderr, "heartbeat sleep_ms(%d): nanosleep: %s\n", ms, strerror(errno));
        return false;
    }
    return true;
}

/* Monotonic elapsed microseconds since an arbitrary fixed point. */
static int64_t monotonic_us(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);  // platform-ok:test-monotonic-jitter-realtime
    return (int64_t)ts.tv_sec * 1000000 + ts.tv_nsec / 1000;
}

static int sleep_script_left, sleep_script_calls;
static bool sleep_script_bad, sleep_script_error;
static long sleep_script_expected;

static int sleep_script(const struct timespec *request, struct timespec *remaining)
{
    sleep_script_calls++;
    if (!remaining || request->tv_sec != 0 ||
        request->tv_nsec != sleep_script_expected) sleep_script_bad = true;
    if (sleep_script_error) { errno = EINVAL; return -1; }
    if (!sleep_script_left) return 0;
    sleep_script_left--;
    sleep_script_expected -= 100000000L;
    *remaining = (struct timespec){ .tv_nsec = sleep_script_expected };
    errno = EINTR;
    return -1;
}

static int test_heartbeat_interrupted_sleep(void)
{
    int failures = 0;
    sleep_call = sleep_script;
    for (int count = 0; count <= 2; count++) {
        sleep_script_left = count;
        sleep_script_calls = 0;
        sleep_script_bad = sleep_script_error = false;
        sleep_script_expected = 300000000L;
        bool slept = sleep_ms(300);
        if (!slept || sleep_script_bad || sleep_script_left != 0 ||
            sleep_script_calls != count + 1) failures++;
    }
    sleep_script_error = true;
    sleep_script_calls = 0;
    sleep_script_bad = false;
    sleep_script_expected = 300000000L;
    if (sleep_ms(300) || sleep_script_bad || sleep_script_calls != 1) failures++;
    sleep_call = nanosleep;
    if (failures) fprintf(stderr, "heartbeat interrupted sleep: %d failures\n", failures);
    return failures;
}

static int test_heartbeat_register_and_snapshot(void)
{
    int failures = 0;
    TEST("heartbeat: register + snapshot reports the entry") {
        health_reset_for_test();
        atomic_store(&g_stall_count, 0);

        health_subsystem_id id = health_register("test.foo", 10,
                                                  stall_cb, (void *)0xAA);
        HEALTH_ASSERT(id >= 0);

        struct health_snapshot snap[4];
        int n = health_snapshot_all(snap, 4);
        HEALTH_ASSERT(n == 1);
        HEALTH_ASSERT(strcmp(snap[0].name, "test.foo") == 0);
        HEALTH_ASSERT(snap[0].deadline_secs == 10);
        HEALTH_ASSERT(snap[0].on_stall_fired == 0);
        HEALTH_ASSERT(!snap[0].currently_stalled);

        health_unregister(id);
        n = health_snapshot_all(snap, 4);
        HEALTH_ASSERT(n == 0);
        PASS();
    } _test_next:;
    return failures;
}

static int test_heartbeat_edge_triggered_stall(void)
{
    int failures = 0;
    TEST("heartbeat: stall fires exactly once per missed-deadline edge") {
        health_reset_for_test();
        atomic_store(&g_stall_count, 0);
        atomic_store(&g_last_ctx_value, 0);

        health_set_check_interval_ms(20);
        HEALTH_ASSERT(health_start());

        /* Deadline = 1s; wait > 1.1s without heartbeating. The sweeper runs
         * every 20ms; the edge trigger must clamp to exactly one call. */
        health_subsystem_id id = health_register("test.bar", 1,
                                                  stall_cb, (void *)0xBB);
        HEALTH_ASSERT(id >= 0);

        sleep_ms(1300);

        int n = atomic_load(&g_stall_count);
        if (n != 1) {
            printf("FAIL (expected 1 stall fire, got %d)\n", n);
            failures++; goto _cleanup;
        }
        if (g_cleanup_inject_context) {
            atomic_store(&g_last_ctx_value, 0);
            g_cleanup_injected = true;
        }
        HEALTH_ASSERT(atomic_load(&g_last_ctx_value) == 0xBB);

        /* A fresh heartbeat re-arms the edge. Subsequent stall should
         * fire one more time. */
        health_heartbeat(id);
        sleep_ms(1300);

        n = atomic_load(&g_stall_count);
        if (n != 2) {
            printf("FAIL (expected 2 stall fires after re-arm, got %d)\n", n);
            failures++; goto _cleanup;
        }

        PASS();
_cleanup:
        health_unregister(id);
        health_stop();
    } _test_next:;
    return failures;
}

static int test_heartbeat_resets_freshness(void)
{
    int failures = 0;
    TEST("heartbeat: keeping the beat fresh prevents stall firing") {
        health_reset_for_test();
        atomic_store(&g_stall_count, 0);
        health_set_check_interval_ms(20);
        HEALTH_ASSERT(health_start());

        health_subsystem_id id = health_register("test.baz", 1,
                                                  stall_cb, NULL);
        HEALTH_ASSERT(id >= 0);

        /* Beat every 100ms for 1.5s. Deadline is 1s, so freshness is
         * always within budget; stall must not fire. */
        for (int i = 0; i < 15; i++) {
            health_heartbeat(id);
            sleep_ms(100);
        }
        int n = atomic_load(&g_stall_count);
        if (n != 0) {
            printf("FAIL (kept beating but stall fired %d times)\n", n);
            failures++; goto _cleanup;
        }
        PASS();
_cleanup:
        health_unregister(id);
        health_stop();
    } _test_next:;
    return failures;
}

static int test_heartbeat_registry_full(void)
{
    int failures = 0;
    TEST("heartbeat: registry-full returns HEALTH_INVALID_ID") {
        health_reset_for_test();
        health_subsystem_id ids[HEALTH_REGISTRY_CAP];
        char name[32];
        for (int i = 0; i < HEALTH_REGISTRY_CAP; i++) {
            snprintf(name, sizeof(name), "test.fill.%d", i);
            ids[i] = health_register(name, 10, stall_cb, NULL);
            if (g_cleanup_inject_prefix && i == 3 && ids[i] >= 0) {
                /* Four real slots exist; fail the real assertion below. */
                ids[i] = HEALTH_INVALID_ID;
                g_cleanup_injected = true;
            }
            HEALTH_ASSERT(ids[i] >= 0);
        }
        health_subsystem_id overflow = health_register("test.overflow", 10,
                                                        stall_cb, NULL);
        HEALTH_ASSERT(overflow == HEALTH_INVALID_ID);

        for (int i = 0; i < HEALTH_REGISTRY_CAP; i++)
            health_unregister(ids[i]);
        PASS();
    } _test_next:;
    return failures;
}

static int64_t heartbeat_fixed_time(void *self)
{
    (void)self;
    return INT64_C(1000000);
}

static const clock_iface_t heartbeat_fixed_clock = {
    .now_monotonic_ns = heartbeat_fixed_time,
    .now_wall_ms = heartbeat_fixed_time,
};

/* Each refused call must leave the occupied slot and remaining capacity intact. */
static int heartbeat_refused_interval(bool periodic, int64_t seconds)
{
    int failures = 0;
    TEST("heartbeat: overflowing interval preserves registry") {
        health_reset_for_test();
        health_subsystem_id kept = health_register("test.kept", 10, stall_cb, NULL);
        ASSERT(kept == 0);
        health_subsystem_id refused = periodic
            ? health_register_periodic("test.overflow", seconds, stall_cb, NULL)
            : health_register("test.overflow", seconds, stall_cb, NULL);
        ASSERT(refused == HEALTH_INVALID_ID);
        struct health_snapshot snap[2];
        ASSERT(health_snapshot_all(snap, 2) == 1);
        ASSERT(strcmp(snap[0].name, "test.kept") == 0);
        ASSERT(snap[0].deadline_secs == 10);
        ASSERT(snap[0].on_stall_fired == 0);
        ASSERT(snap[0].last_beat_age_secs == 0);
        ASSERT(!snap[0].periodic);
        ASSERT(health_register("test.next", 1, stall_cb, NULL) == 1);
        PASS();
    } _test_next:;
    health_reset_for_test();
    return failures;
}

static int heartbeat_valid_interval(bool periodic, int64_t seconds)
{
    int failures = 0;
    TEST("heartbeat: representable positive interval remains valid") {
        health_reset_for_test();
        health_subsystem_id id = periodic
            ? health_register_periodic("test.bound", seconds, stall_cb, NULL)
            : health_register("test.bound", seconds, stall_cb, NULL);
        ASSERT(id == 0);
        struct health_snapshot snap[1];
        ASSERT(health_snapshot_all(snap, 1) == 1);
        ASSERT(snap[0].deadline_secs == seconds);
        ASSERT(snap[0].periodic == periodic);
        ASSERT(snap[0].last_beat_age_secs == 0);
        ASSERT(snap[0].on_stall_fired == 0);
        health_unregister(id);
        ASSERT(health_snapshot_all(snap, 1) == 0);
        PASS();
    } _test_next:;
    health_reset_for_test();
    return failures;
}

static int heartbeat_periodic_invalid_inputs(void)
{
    int failures = 0;
    TEST("heartbeat: invalid periodic inputs preserve empty registry") {
        health_reset_for_test();
        ASSERT(health_register_periodic(NULL, 10, stall_cb, NULL) == HEALTH_INVALID_ID);
        ASSERT(health_register_periodic("test.null", 10, NULL, NULL) == HEALTH_INVALID_ID);
        ASSERT(health_register_periodic("test.bad", 0, stall_cb, NULL) == HEALTH_INVALID_ID);
        ASSERT(health_register_periodic("test.bad", -1, stall_cb, NULL) == HEALTH_INVALID_ID);
        struct health_snapshot snap[1];
        ASSERT(health_snapshot_all(snap, 1) == 0);
        PASS();
    } _test_next:;
    health_reset_for_test();
    return failures;
}

static int test_heartbeat_interval_bounds(void)
{
    int failures = 0;
    const clock_iface_t *saved_clock = clock_default();
    health_reset_for_test();
    clock_set_default(&heartbeat_fixed_clock);
    failures += heartbeat_periodic_invalid_inputs();
    const int64_t limit = INT64_MAX / INT64_C(1000000);
    for (int periodic = 0; periodic < 2; periodic++) {
        failures += heartbeat_refused_interval(periodic, limit + 1);
        failures += heartbeat_refused_interval(periodic, INT64_MAX);
        failures += heartbeat_valid_interval(periodic, 1);
        failures += heartbeat_valid_interval(periodic, limit);
    }
    health_reset_for_test();
    clock_set_default(saved_clock);
    return failures;
}

static int test_heartbeat_invalid_inputs(void)
{
    int failures = 0;
    TEST("heartbeat: invalid inputs return HEALTH_INVALID_ID without crashing") {
        health_reset_for_test();
        ASSERT(health_register(NULL, 10, stall_cb, NULL) == HEALTH_INVALID_ID);
        ASSERT(health_register("test.null", 10, NULL, NULL) == HEALTH_INVALID_ID);
        ASSERT(health_register("test.bad", 0,  stall_cb, NULL) == HEALTH_INVALID_ID);
        ASSERT(health_register("test.bad", -1, stall_cb, NULL) == HEALTH_INVALID_ID);

        /* Heartbeats on invalid ids are silent no-ops. */
        health_heartbeat(-1);
        health_heartbeat(HEALTH_REGISTRY_CAP);
        health_heartbeat(HEALTH_REGISTRY_CAP + 1000);
        health_unregister(-1);
        health_unregister(HEALTH_REGISTRY_CAP);
        PASS();
    } _test_next:;
    return failures;
}

static int test_heartbeat_periodic_tick(void)
{
    int failures = 0;
    TEST("heartbeat: periodic tick fires repeatedly on cadence (NOT edge-triggered)") {
        health_reset_for_test();
        atomic_store(&g_stall_count, 0);
        health_set_check_interval_ms(20);
        HEALTH_ASSERT(health_start());

        /* period = 1s. Over 3.3s we expect ~3 fires; the 2..5 band tolerates
         * sweeper jitter. Poll a monotonic clock so the count is judged at the
         * real 3300ms boundary rather than after a fixed sleep. */
        health_subsystem_id id = health_register_periodic("test.tick", 1,
                                                           stall_cb, NULL);
        HEALTH_ASSERT(id >= 0);

        const int64_t start_us  = monotonic_us();
        const int64_t window_us = 3300 * 1000;  /* observe over 3.3s real time */
        int n = atomic_load(&g_stall_count);
        for (;;) {
            int64_t elapsed_us = monotonic_us() - start_us;
            /* Record the count observed at this checkpoint. The final
             * recorded value is the one at/after the 3300ms boundary. */
            n = atomic_load(&g_stall_count);
            if (elapsed_us >= window_us)
                break;
            sleep_ms(100);
        }

        if (n < 2 || n > 5) {
            printf("FAIL (expected 2..5 periodic fires, got %d)\n", n);
            failures++; goto _cleanup;
        }

        /* Snapshot should mark it periodic. */
        struct health_snapshot snap[4];
        int got = health_snapshot_all(snap, 4);
        if (got != 1 || !snap[0].periodic || snap[0].currently_stalled) {
            printf("FAIL (snapshot wrong: got=%d periodic=%d stalled=%d)\n",
                   got, snap[0].periodic, snap[0].currently_stalled);
            failures++; goto _cleanup;
        }

        /* Heartbeat is a no-op for periodic entries — the fire count
         * should keep climbing on cadence regardless. */
        for (int i = 0; i < 5; i++) health_heartbeat(id);
        PASS();
_cleanup:
        health_unregister(id);
        health_stop();
    } _test_next:;
    return failures;
}

/* Expected inner failures use the same assertion exit as the real subcases.
 * The marker separates an injected verdict from an acquisition failure. */
static int heartbeat_failing_subcase(bool context_case, bool *injected)
{
    g_cleanup_injected = false;
    g_cleanup_inject_context = context_case;
    g_cleanup_inject_prefix = !context_case;
    int failures = context_case
        ? test_heartbeat_edge_triggered_stall()
        : test_heartbeat_registry_full();
    g_cleanup_inject_context = false;
    g_cleanup_inject_prefix = false;
    *injected = g_cleanup_injected;
    return failures;
}

static int test_heartbeat_assertion_cleanup(void)
{
    int failures = 0;
    TEST("heartbeat: expected inner failures release worker and prefix slots") {
        for (int kind = 0; kind < 2; kind++) {
            bool injected = false;
            int inner = heartbeat_failing_subcase(kind == 0, &injected);
            struct health_snapshot snap[HEALTH_REGISTRY_CAP];
            int retained = health_snapshot_all(snap, HEALTH_REGISTRY_CAP);
            struct json_value out;
            json_init(&out);
            json_set_object(&out);
            bool dumped = health_dump_state_json(&out, NULL);
            const struct json_value *running = json_get(&out, "sweeper_running");
            bool stopped = running && running->type == JSON_BOOL &&
                           !json_get_bool(running);
            json_free(&out);
            /* Observe before cleanup; contain a restored defect afterward. */
            health_reset_for_test();
            ASSERT(injected);
            ASSERT(inner == 1);
            ASSERT(retained == 0);
            ASSERT(dumped && stopped);
        }
        PASS();
    } _test_next:;
    return failures;
}

static bool heartbeat_json_fields_match(const struct json_value *a,
                                       const struct json_value *b)
{
    const char *fields[] = {"deadline_secs", "last_beat_age_secs", "fires_total",
                           "periodic", "currently_stalled"};
    for (size_t i = 0; i < sizeof(fields) / sizeof(fields[0]); i++) {
        const struct json_value *x = json_get(a, fields[i]);
        const struct json_value *y = json_get(b, fields[i]);
        if (!x || !y || x->type != y->type || json_get_int(x) != json_get_int(y) ||
            json_get_bool(x) != json_get_bool(y)) return false;
    }
    return true;
}

static int heartbeat_name_case(const char *name, const char *expected, bool periodic)
{
    int failures = 0;
    TEST("heartbeat: normalized names survive snapshot and JSON serialization") {
        health_reset_for_test();
        health_subsystem_id id = periodic
            ? health_register_periodic(name, 10, stall_cb, NULL)
            : health_register(name, 10, stall_cb, NULL);
        HEALTH_ASSERT(id >= 0);
        struct health_snapshot snap;
        HEALTH_ASSERT(health_snapshot_all(&snap, 1) == 1);
        bool same_snapshot = strcmp(snap.name, expected) == 0;
        HEALTH_ASSERT(snap.last_beat_age_secs == 0);
        HEALTH_ASSERT(snap.deadline_secs == 10);
        HEALTH_ASSERT(snap.periodic == periodic);
        HEALTH_ASSERT(snap.on_stall_fired == 0);
        HEALTH_ASSERT(!snap.currently_stalled);
        struct json_value out, parsed;
        json_init(&out);
        json_init(&parsed);
        json_set_object(&out);
        bool dumped = health_dump_state_json(&out, NULL);
        char wire[2048];
        size_t len = json_write(&out, wire, sizeof(wire));
        bool valid = len < sizeof(wire) && zutf8_validate_n(wire, len);
        bool read = valid && json_read(&parsed, wire, len);
        const struct json_value *entry = json_at(json_get(&parsed, "entries"), 0);
        bool same_name = strcmp(json_get_str(json_get(entry, "name")), expected) == 0;
        const struct json_value *original = json_at(json_get(&out, "entries"), 0);
        bool same_fields = heartbeat_json_fields_match(original, entry);
        bool escaped = strcmp(name, "x\"\\\n") != 0 ||
                       strstr(wire, "x\\\"\\\\\\n") != NULL;
        json_free(&parsed);
        json_free(&out);
        HEALTH_ASSERT(valid);
        HEALTH_ASSERT(dumped && read && same_snapshot && same_name && same_fields && escaped);
        health_unregister(id);
        PASS();
    } _test_next:;
    return failures;
}

static bool heartbeat_snapshots_match(const struct health_snapshot *a,
                                      const struct health_snapshot *b)
{
    return strcmp(a->name, b->name) == 0 &&
           a->deadline_secs == b->deadline_secs &&
           a->last_beat_age_secs == b->last_beat_age_secs &&
           a->on_stall_fired == b->on_stall_fired &&
           a->periodic == b->periodic &&
           a->currently_stalled == b->currently_stalled;
}

static int heartbeat_full_bounded_name(bool periodic)
{
    int failures = 0;
    TEST("heartbeat: full registry refuses bounded names without changing entries") {
        health_reset_for_test();
        for (int i = 0; i < HEALTH_REGISTRY_CAP; i++) {
            health_subsystem_id id = i % 2
                ? health_register_periodic("test.kept.periodic", 10, stall_cb, NULL)
                : health_register("test.kept", 10, stall_cb, NULL);
            HEALTH_ASSERT(id == i);
        }
        struct health_snapshot before[HEALTH_REGISTRY_CAP];
        struct health_snapshot after[HEALTH_REGISTRY_CAP];
        HEALTH_ASSERT(health_snapshot_all(before, HEALTH_REGISTRY_CAP) == HEALTH_REGISTRY_CAP);
        char name[HEALTH_NAME_MAX - 1];
        memset(name, 'a', sizeof(name));
        health_subsystem_id refused = periodic
            ? health_register_periodic(name, 10, stall_cb, NULL)
            : health_register(name, 10, stall_cb, NULL);
        HEALTH_ASSERT(refused == HEALTH_INVALID_ID);
        HEALTH_ASSERT(health_snapshot_all(after, HEALTH_REGISTRY_CAP) == HEALTH_REGISTRY_CAP);
        for (int i = 0; i < HEALTH_REGISTRY_CAP; i++)
            HEALTH_ASSERT(heartbeat_snapshots_match(&before[i], &after[i]));
        PASS();
    } _test_next:;
    health_reset_for_test();
    return failures;
}

static int heartbeat_bounded_malformed_name(bool periodic)
{
    int failures = 0;
    TEST("heartbeat: bounded malformed suffix retains replacement and following byte") {
        char name[HEALTH_NAME_MAX - 1], expected[HEALTH_NAME_MAX - 1];
        memset(name, 'a', sizeof(name));
        name[37] = (char)0xe2;
        name[38] = '(';
        memcpy(expected, name, sizeof(expected));
        expected[37] = '?';
        health_reset_for_test();
        health_subsystem_id id = periodic
            ? health_register_periodic(name, 10, stall_cb, NULL)
            : health_register(name, 10, stall_cb, NULL);
        HEALTH_ASSERT(id >= 0);
        struct health_snapshot snap;
        HEALTH_ASSERT(health_snapshot_all(&snap, 1) == 1);
        HEALTH_ASSERT(memcmp(snap.name, expected, sizeof(expected)) == 0);
        HEALTH_ASSERT(snap.name[HEALTH_NAME_MAX - 1] == '\0');
        health_unregister(id);
        PASS();
    } _test_next:;
    health_reset_for_test();
    return failures;
}

static int test_heartbeat_bounded_names(void)
{
    int failures = 0;
    for (int periodic = 0; periodic < 2; periodic++) {
        failures += heartbeat_full_bounded_name(periodic);
        failures += heartbeat_bounded_malformed_name(periodic);
        TEST("heartbeat: bounded unterminated names retain all bytes") {
            char name[HEALTH_NAME_MAX - 1];
            memset(name, 'a', sizeof(name));
            health_reset_for_test();
            health_subsystem_id id = periodic
                ? health_register_periodic(name, 10, stall_cb, NULL)
                : health_register(name, 10, stall_cb, NULL);
            HEALTH_ASSERT(id >= 0);
            struct health_snapshot snap;
            HEALTH_ASSERT(health_snapshot_all(&snap, 1) == 1);
            HEALTH_ASSERT(memcmp(snap.name, name, sizeof(name)) == 0);
            HEALTH_ASSERT(snap.name[HEALTH_NAME_MAX - 1] == '\0');
            health_unregister(id);
            PASS();
        } _test_next:;
    }
    health_reset_for_test();
    return failures;
}

static int test_heartbeat_utf8_names(void)
{
    int failures = 0;
    const struct { const char *input, *expected; } cases[] = {
        {"\xff", "?"}, {"\x80", "?"}, {"\xc0\xaf", "??"},
        {"\xed\xa0\x80", "???"}, {"\xe2\x82", "??"},
        {"ok\xe2\x82\xac", "ok\xe2\x82\xac"}, {"x\"\\\n", "x\"\\\n"}
    };
    const char *sequences[] = {"\xc2\xa2", "\xe2\x82\xac", "\xf0\x9f\x98\x80"};
    for (int periodic = 0; periodic < 2; periodic++) {
        for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
            failures += heartbeat_name_case(cases[i].input, cases[i].expected, periodic);
        char malformed[HEALTH_NAME_MAX], replaced[HEALTH_NAME_MAX];
        memset(malformed, 'a', 37);
        memcpy(replaced, malformed, 37);
        malformed[37] = (char)0xe2;
        malformed[38] = '\0';
        replaced[37] = '?';
        replaced[38] = '\0';
        failures += heartbeat_name_case(malformed, replaced, periodic);
        malformed[38] = '(';
        malformed[39] = '\0';
        replaced[38] = '(';
        replaced[39] = '\0';
        failures += heartbeat_name_case(malformed, replaced, periodic);
        for (size_t i = 0; i < sizeof(sequences) / sizeof(sequences[0]); i++) {
            size_t width = strlen(sequences[i]);
            for (size_t room = 1; room <= width; room++) {
                char input[44], expected[HEALTH_NAME_MAX];
                size_t prefix = HEALTH_NAME_MAX - 1 - room;
                memset(input, 'a', prefix);
                strcpy(input + prefix, sequences[i]);
                memcpy(expected, input, prefix);
                expected[prefix] = '\0';
                if (room == width) strcpy(expected + prefix, sequences[i]);
                failures += heartbeat_name_case(input, expected, periodic);
            }
        }
    }
    health_reset_for_test();
    return failures;
}

static int heartbeat_normalized_names(void)
{
    health_reset_for_test();
    const clock_iface_t *saved = clock_default();
    clock_set_default(&heartbeat_fixed_clock);
    int failures = test_heartbeat_utf8_names();
    failures += test_heartbeat_bounded_names();
    health_reset_for_test();
    clock_set_default(saved);
    return failures;
}

int test_heartbeat(void)
{
    int failures = 0;
    failures += heartbeat_normalized_names();
    failures += test_heartbeat_interrupted_sleep();
    failures += test_heartbeat_assertion_cleanup();
    failures += test_heartbeat_register_and_snapshot();
    failures += test_heartbeat_invalid_inputs();
    failures += test_heartbeat_interval_bounds();
    failures += test_heartbeat_registry_full();
    failures += test_heartbeat_resets_freshness();
    failures += test_heartbeat_edge_triggered_stall();
    failures += test_heartbeat_periodic_tick();
    return failures;
}
