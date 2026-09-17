/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Host-executed Android preprocessor acceptance for cooperative registered
 * worker completion. This is not an NDK/arm64 proof: it proves that the same
 * registry source compiled with __ANDROID__ needs neither glibc timed join nor
 * pthread cancellation, and that a timed-out owner can retry safely. */

#include "platform/time_compat.h"
#include "util/thread_registry.h"

#include <errno.h>
#include <stdatomic.h>
#include <stdio.h>

struct acceptance_worker {
    _Atomic bool release;
};

static void *acceptance_worker_main(void *opaque)
{
    struct acceptance_worker *worker = opaque;
    while (!atomic_load_explicit(&worker->release, memory_order_acquire)) {
        struct timespec pause = {
            .tv_sec = 0,
            .tv_nsec = 1000 * 1000,
        };
        nanosleep(&pause, NULL);
    }
    return worker;
}

int main(void)
{
    struct acceptance_worker worker;
    atomic_init(&worker.release, false);

    pthread_t tid;
    // thread-supervision-ok:standalone-acceptance-worker-bounded-and-joined
    if (thread_registry_spawn("android-coop", acceptance_worker_main,
                              &worker, &tid) != 0)
        return 1;

    struct timespec deadline;
    if (platform_time_realtime_timespec(&deadline) != 0)
        return 2;
    if (thread_registry_join_until(tid, NULL, &deadline) != ETIMEDOUT)
        return 3;
    if (thread_registry_live_count() != 1 ||
        thread_registry_unreaped_count() != 1)
        return 4;

    atomic_store_explicit(&worker.release, true, memory_order_release);
    if (platform_time_realtime_timespec(&deadline) != 0)
        return 5;
    deadline.tv_sec += 2;
    void *result = NULL;
    if (thread_registry_join_until(tid, &result, &deadline) != 0)
        return 6;
    if (result != &worker || thread_registry_live_count() != 0 ||
        thread_registry_unreaped_count() != 0)
        return 7;

    puts("thread_registry_android_acceptance: PASS");
    return 0;
}
