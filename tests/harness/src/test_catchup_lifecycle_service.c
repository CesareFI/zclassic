/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * catchup_lifecycle_service — start/join/reap policy lifted out of
 * engine/composition/src/boot_services.c (boot_start_catchup_service /
 * boot_join_catchup_service / boot_reap_catchup_service). Exercises the
 * double-start guard, the NULL-safety of every entry point, the bounded
 * join ownership contract, and the poll-only reap contract (no-op while
 * running, joins + clears once finished). */

#include "platform/time_compat.h"
#include "test/test_core.h"
#include "services/catchup_lifecycle_service.h"
#include "controllers/sync_controller.h"
#include "models/database.h"
#include "util/thread_registry.h"
#include "validation/chainstate.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

struct catchup_join_fixture {
    pthread_mutex_t mutex;
    pthread_cond_t changed;
    bool worker_started;
    bool release_worker;
    bool join_returned;
    bool forced_release;
};

static void *catchup_join_fixture_worker(void *arg)
{
    struct catchup_join_fixture *fixture = arg;
    pthread_mutex_lock(&fixture->mutex);
    fixture->worker_started = true;
    pthread_cond_broadcast(&fixture->changed);
    while (!fixture->release_worker)
        pthread_cond_wait(&fixture->changed, &fixture->mutex);
    pthread_mutex_unlock(&fixture->mutex);
    return NULL;
}

static void *catchup_join_fixture_watchdog(void *arg)
{
    struct catchup_join_fixture *fixture = arg;
    struct timespec deadline;
    bool have_deadline = platform_time_realtime_timespec(&deadline) == 0;
    if (have_deadline)
        deadline.tv_sec += 1;

    pthread_mutex_lock(&fixture->mutex);
    int rc = 0;
    while (!fixture->join_returned && have_deadline && rc == 0)
        rc = pthread_cond_timedwait(&fixture->changed, &fixture->mutex,
                                    &deadline);
    if (!fixture->join_returned) {
        fixture->forced_release = true;
        fixture->release_worker = true;
        pthread_cond_broadcast(&fixture->changed);
    }
    pthread_mutex_unlock(&fixture->mutex);
    return NULL;
}

static bool catchup_join_fixture_wait_started(
    struct catchup_join_fixture *fixture)
{
    struct timespec deadline;
    if (platform_time_realtime_timespec(&deadline) != 0)
        return false;
    deadline.tv_sec += 2;
    pthread_mutex_lock(&fixture->mutex);
    int rc = 0;
    while (!fixture->worker_started && rc == 0)
        rc = pthread_cond_timedwait(&fixture->changed, &fixture->mutex,
                                    &deadline);
    bool started = fixture->worker_started;
    pthread_mutex_unlock(&fixture->mutex);
    return started;
}

static bool catchup_join_fixture_join_thread(pthread_t thread,
                                              int timeout_sec)
{
    struct timespec deadline;
    if (platform_time_realtime_timespec(&deadline) != 0)
        return false;
    deadline.tv_sec += timeout_sec;
    return thread_registry_join_until(thread, NULL, &deadline) == 0;
}

static int catchup_lifecycle_test_safe_noops(void)
{
    int failures = 0;
    printf("catchup_lifecycle_service: every entry point is NULL-safe... ");
    bool null_ok = !catchup_lifecycle_start(NULL, NULL, NULL, NULL, NULL);
    null_ok = null_ok && catchup_lifecycle_join(NULL, 0);
    null_ok = null_ok && catchup_lifecycle_reap(NULL);
    if (null_ok) printf("OK\n");
    else { printf("FAIL\n"); failures++; }

    printf("catchup_lifecycle_service: reap/join no-op on a job never started... ");
    struct node_db_sync_catchup_job job;
    node_db_sync_catchup_job_init(&job);
    bool idle_ok = catchup_lifecycle_reap(&job);
    idle_ok = idle_ok && catchup_lifecycle_join(&job, 0);
    idle_ok = idle_ok && !job.started;
    if (idle_ok) printf("OK\n");
    else { printf("FAIL\n"); failures++; }
    return failures;
}

static bool catchup_join_fixture_result_ok(
    bool worker_spawned, bool worker_started, bool watchdog_spawned,
    bool bounded, bool retained, bool watchdog_joined, bool retry_joined,
    const struct node_db_sync_catchup_job *job,
    const struct catchup_join_fixture *fixture)
{
    return worker_spawned && worker_started && watchdog_spawned && bounded &&
           retained && watchdog_joined && retry_joined && !job->started &&
           !fixture->forced_release;
}

static int catchup_lifecycle_test_bounded_retry(void)
{
    printf("catchup_lifecycle_service: bounded join retains ownership "
           "and can be retried... ");
    struct catchup_join_fixture fixture = {
        .mutex = PTHREAD_MUTEX_INITIALIZER,
        .changed = PTHREAD_COND_INITIALIZER,
    };
    struct node_db_sync_catchup_job job;
    node_db_sync_catchup_job_init(&job);
    pthread_t watchdog = {0};
    bool worker_spawned = thread_registry_spawn(
        "catchup-join-fixture", catchup_join_fixture_worker, &fixture,
        &job.thread) == 0;
    job.started = worker_spawned;
    bool worker_started = worker_spawned &&
        catchup_join_fixture_wait_started(&fixture);
    bool watchdog_spawned = worker_started && thread_registry_spawn(
        "catchup-join-watchdog", catchup_join_fixture_watchdog, &fixture,
        &watchdog) == 0;

    bool bounded = watchdog_spawned && !catchup_lifecycle_join(&job, 0);
    bool retained = bounded && job.started;
    pthread_mutex_lock(&fixture.mutex);
    fixture.join_returned = true;
    fixture.release_worker = true;
    pthread_cond_broadcast(&fixture.changed);
    pthread_mutex_unlock(&fixture.mutex);

    bool watchdog_joined = !watchdog_spawned ||
        catchup_join_fixture_join_thread(watchdog, 2);
    bool retry_joined = !worker_spawned || catchup_lifecycle_join(&job, 2);
    bool ok = catchup_join_fixture_result_ok(
        worker_spawned, worker_started, watchdog_spawned, bounded, retained,
        watchdog_joined, retry_joined, &job, &fixture);
    pthread_cond_destroy(&fixture.changed);
    pthread_mutex_destroy(&fixture.mutex);
    if (ok) printf("OK\n");
    else printf("FAIL\n");
    return ok ? 0 : 1;
}

static int catchup_lifecycle_test_start_join(void)
{
    printf("catchup_lifecycle_service: start + double-start guard + join... ");
    struct node_db ndb;
    struct active_chain ac;
    struct node_db_sync_catchup_job job;
    bool db_ok = node_db_open(&ndb, ":memory:");

    active_chain_init(&ac);
    node_db_sync_catchup_job_init(&job);
    bool started = db_ok &&
        catchup_lifecycle_start(&job, &ndb, &ac, NULL, NULL);
    /* A second start must fail closed without disturbing the live job. */
    bool double_start_rejected = started &&
        !catchup_lifecycle_start(&job, &ndb, &ac, NULL, NULL);
    bool joined = catchup_lifecycle_join(&job, 5);
    bool joined_clears_started = joined && !job.started;
    bool ok = db_ok && started && double_start_rejected &&
              joined_clears_started;

    if (ndb.open)
        node_db_close(&ndb);
    active_chain_free(&ac);
    if (ok) printf("OK\n");
    else printf("FAIL\n");
    return ok ? 0 : 1;
}

static int catchup_lifecycle_test_reap(void)
{
    printf("catchup_lifecycle_service: reap is a no-op until the job finishes... ");
    struct node_db ndb;
    struct active_chain ac;
    struct node_db_sync_catchup_job job;
    bool db_ok = node_db_open(&ndb, ":memory:");

    active_chain_init(&ac);
    node_db_sync_catchup_job_init(&job);
    bool started = db_ok &&
        catchup_lifecycle_start(&job, &ndb, &ac, NULL, NULL);
    bool reaped = false;
    for (int i = 0; i < 200 && !reaped; i++) {
        if (atomic_load(&job.finished))
            reaped = catchup_lifecycle_reap(&job);
        else
            platform_sleep_ms(5); /* real-clock: bounded poll, pre-existing */
    }
    bool ok = started && reaped && !job.started;

    if (job.started)
        (void)catchup_lifecycle_join(&job, 5);
    if (ndb.open)
        node_db_close(&ndb);
    active_chain_free(&ac);
    if (ok) printf("OK\n");
    else printf("FAIL\n");
    return ok ? 0 : 1;
}

static int catchup_lifecycle_test_owned_datadir(void)
{
    /* catchup_lifecycle_start() resolves a function-local path before the
     * worker runs. The job must retain the bytes, not that stack pointer. */
    printf("catchup_lifecycle_service: the job owns the starter's "
           "datadir bytes... ");
    static const char kDatadir[] = "/nonexistent/catchup-datadir-owner";
    struct node_db ndb;
    struct active_chain ac;
    struct node_db_sync_catchup_job job;
    memset(&ndb, 0, sizeof(ndb));
    active_chain_init(&ac);
    node_db_sync_catchup_job_init(&job);

    char caller_path[512];
    snprintf(caller_path, sizeof(caller_path), "%s", kDatadir);
    bool started =
        node_db_sync_catchup_job_start(&job, &ndb, &ac, NULL, caller_path);
    memset(caller_path, 0xA5, sizeof(caller_path));
    int result = 0;
    bool joined = started && node_db_sync_catchup_job_join(&job, &result);
    bool ok = started && joined &&
        job.args.datadir == job.args.datadir_storage &&
        strcmp(job.args.datadir, kDatadir) == 0;

    char oversized[sizeof(job.args.datadir_storage) + 1u];
    memset(oversized, 'x', sizeof(oversized) - 1u);
    oversized[sizeof(oversized) - 1u] = '\0';
    node_db_sync_catchup_job_init(&job);
    ok = ok &&
        !node_db_sync_catchup_job_start(&job, &ndb, &ac, NULL, oversized) &&
        job.args.datadir_storage[0] == '\0';

    active_chain_free(&ac);
    if (ok) printf("OK\n");
    else printf("FAIL\n");
    return ok ? 0 : 1;
}

int test_catchup_lifecycle_service(void)
{
    int failures = 0;
    printf("\n=== catchup_lifecycle_service tests ===\n");

    failures += catchup_lifecycle_test_safe_noops();

    failures += catchup_lifecycle_test_start_join();
    failures += catchup_lifecycle_test_reap();

    failures += catchup_lifecycle_test_bounded_retry();

    failures += catchup_lifecycle_test_owned_datadir();

    printf("catchup_lifecycle_service: %d failures\n", failures);
    return failures;
}
