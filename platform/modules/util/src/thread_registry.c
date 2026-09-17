/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * thread_registry: spawn, track, and drain zclassic23's
 * pthread population. See `util/thread_registry.h` for the API
 * contract and rationale. */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE  /* pthread_setname_np */
#endif

#include "platform/time_compat.h"
#include "util/thread_registry.h"
#include "util/safe_alloc.h"

#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* Bounded fixed-size table.  Heap would be simpler but registering
 * from inside pthread creation paths is easier to reason about without
 * allocator round-trips, and the cap catches runaway thread growth. */
struct entry {
    pthread_t tid;
    char      name[48];
    bool      occupied;
    bool      running;
    bool      registry_owns_join;
    bool      registry_joining;
};

static struct entry         g_entries[ZCL_THREAD_REGISTRY_CAP];
static pthread_mutex_t      g_mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t       g_changed = PTHREAD_COND_INITIALIZER;
static _Atomic bool         g_shutdown = false;

/* The trampoline records normal exit. Registry-owned pthreads (spawned with
 * out_tid == NULL) remain occupied until join_all or a later spawn reaps them;
 * a returned joinable pthread still consumes resources and must not disappear
 * from the ownership table first. Caller-owned pthreads unregister on exit
 * because their subsystem retained the tid and is contractually responsible
 * for joining it. Allocated per-spawn and freed in the trampoline. */
struct trampoline_args {
    void *(*entry)(void *);
    void  *arg;
};

static void thread_registry_publish_exit(void)
{
    pthread_t self = pthread_self();
    pthread_mutex_lock(&g_mu);
    for (int i = 0; i < ZCL_THREAD_REGISTRY_CAP; i++) {
        if (g_entries[i].occupied &&
            pthread_equal(g_entries[i].tid, self)) {
            g_entries[i].running = false;
            if (!g_entries[i].registry_owns_join &&
                !g_entries[i].registry_joining)
                memset(&g_entries[i], 0, sizeof(g_entries[i]));
            break;
        }
    }
    pthread_cond_broadcast(&g_changed);
    pthread_mutex_unlock(&g_mu);
}

static void *thread_registry_trampoline(void *raw)
{
    struct trampoline_args *ta = raw;
    void *(*entry)(void *) = ta->entry;
    void *arg = ta->arg;
    free(ta);
    void *ret = entry(arg);
    /* This trampoline is the sole completion publication point. Worker entry
     * functions must not claim completion while their stack can still touch
     * owner state. */
    thread_registry_publish_exit();
    return ret;
}

/* Registry-owned workers have no subsystem retaining their pthread_t. Reap
 * completed rows before admitting more work so a long-lived node does not
 * exhaust the fixed registry merely because many bounded jobs completed
 * between shutdown sweeps. `running == false` is published only by the
 * trampoline immediately before return, so pthread_join performs at most the
 * final reap and never waits on worker logic. */
static void thread_registry_reap_finished_owned(void)
{
    for (;;) {
        pthread_mutex_lock(&g_mu);
        int slot = -1;
        for (int i = 0; i < ZCL_THREAD_REGISTRY_CAP; i++) {
            if (g_entries[i].occupied && !g_entries[i].running &&
                g_entries[i].registry_owns_join &&
                !g_entries[i].registry_joining) {
                slot = i;
                g_entries[i].registry_joining = true;
                break;
            }
        }
        if (slot < 0) {
            pthread_mutex_unlock(&g_mu);
            return;
        }
        pthread_t tid = g_entries[slot].tid;
        pthread_mutex_unlock(&g_mu);

        int join_rc;
        do {
            join_rc = pthread_join(tid, NULL);
        } while (join_rc == EINTR);

        pthread_mutex_lock(&g_mu);
        if (g_entries[slot].occupied &&
            pthread_equal(g_entries[slot].tid, tid)) {
            if (join_rc == 0)
                memset(&g_entries[slot], 0, sizeof(g_entries[slot]));
            else
                g_entries[slot].registry_joining = false;
        }
        pthread_mutex_unlock(&g_mu);
        if (join_rc != 0)
            return;
    }
}

int thread_registry_spawn(const char *name,
                          void *(*entry)(void *), void *arg,
                          pthread_t *out_tid)
{
    if (!entry) return EINVAL;

    thread_registry_reap_finished_owned();

#if defined(__APPLE__)
    pthread_attr_t attr;
    int attr_rc = pthread_attr_init(&attr);
    if (attr_rc != 0) return attr_rc;
    attr_rc = pthread_attr_setstacksize(
        &attr, (size_t)ZCL_DARWIN_THREAD_STACK_BYTES);
    if (attr_rc != 0) {
        int destroy_rc = pthread_attr_destroy(&attr);
        if (destroy_rc != 0)
            fprintf(stderr, "[thread_registry] pthread_attr_destroy: %s\n",
                    strerror(destroy_rc));
        return attr_rc;
    }
#endif

    struct trampoline_args *ta = zcl_malloc(sizeof(*ta),
                                             "thread_registry_trampoline");
    if (!ta) {
#if defined(__APPLE__)
        int destroy_rc = pthread_attr_destroy(&attr);
        if (destroy_rc != 0)
            fprintf(stderr, "[thread_registry] pthread_attr_destroy: %s\n",
                    strerror(destroy_rc));
#endif
        return ENOMEM;
    }
    ta->entry = entry;
    ta->arg   = arg;

    /* Reserve a slot BEFORE pthread_create so we can't race with an
     * immediate exit + lifecycle publication. */
    pthread_mutex_lock(&g_mu);
    int slot = -1;
    for (int i = 0; i < ZCL_THREAD_REGISTRY_CAP; i++) {
        if (!g_entries[i].occupied) { slot = i; break; }
    }
    if (slot < 0) {
        pthread_mutex_unlock(&g_mu);
        free(ta);
#if defined(__APPLE__)
        int destroy_rc = pthread_attr_destroy(&attr);
        if (destroy_rc != 0)
            fprintf(stderr, "[thread_registry] pthread_attr_destroy: %s\n",
                    strerror(destroy_rc));
#endif
        fprintf(stderr, "[thread_registry] capacity %d exceeded — "
                "cannot spawn '%s'\n",
                ZCL_THREAD_REGISTRY_CAP, name ? name : "?");
        return -1;
    }
    g_entries[slot].occupied = true;
    g_entries[slot].running = true;
    g_entries[slot].registry_owns_join = (out_tid == NULL);
    /* tid filled in after pthread_create succeeds. */
    strncpy(g_entries[slot].name, name ? name : "?",
            sizeof(g_entries[slot].name) - 1);
    g_entries[slot].name[sizeof(g_entries[slot].name) - 1] = '\0';
    /* Keep g_mu held across create + tid publication. A very short-lived
     * child can reach trampoline unregister immediately; without this barrier
     * it observes an uninitialised tid, misses its slot, and strands an active
     * registry entry forever. The child merely blocks on g_mu until its tid is
     * fully published. */
    pthread_t tid;
    int rc = pthread_create(&tid,
#if defined(__APPLE__)
                            &attr,
#else
                            NULL,
#endif
                            thread_registry_trampoline, ta);
#if defined(__APPLE__)
    int destroy_rc = pthread_attr_destroy(&attr);
    if (destroy_rc != 0)
        fprintf(stderr, "[thread_registry] pthread_attr_destroy: %s\n",
                strerror(destroy_rc));
#endif
    if (rc != 0) {
        memset(&g_entries[slot], 0, sizeof(g_entries[slot]));
        pthread_mutex_unlock(&g_mu);
        free(ta);
        return rc;
    }

    g_entries[slot].tid = tid;
    pthread_mutex_unlock(&g_mu);

    if (out_tid) *out_tid = tid;

#if defined(__linux__) || defined(_WIN32)
    /* pthread_setname_np accepts up to 15 chars + NUL; silently
     * truncate without propagating failure — diagnostics only. */
    char short_name[16];
    strncpy(short_name, name ? name : "zcl-thread", sizeof(short_name) - 1);
    short_name[sizeof(short_name) - 1] = '\0';
    (void)pthread_setname_np(tid, short_name);
#endif

    return 0;
}

bool thread_registry_shutdown_requested(void)
{
    return atomic_load_explicit(&g_shutdown, memory_order_acquire);
}

void thread_registry_request_shutdown(void)
{
    atomic_store_explicit(&g_shutdown, true, memory_order_release);
}

static int thread_registry_find_locked(pthread_t tid)
{
    for (int i = 0; i < ZCL_THREAD_REGISTRY_CAP; i++) {
        if (g_entries[i].occupied &&
            pthread_equal(g_entries[i].tid, tid))
            return i;
    }
    return -1;
}

/* Claim the registry row and wait for the trampoline's completion
 * publication. g_mu is held on entry and return. */
static int thread_registry_wait_for_exit_locked(
    pthread_t tid, const struct timespec *deadline, int *out_slot)
{
    int slot = thread_registry_find_locked(tid);
    *out_slot = slot;
    if (slot < 0)
        return 0;
    if (g_entries[slot].registry_joining)
        return EBUSY;

    g_entries[slot].registry_joining = true;
    int wait_rc = 0;
    while (g_entries[slot].occupied &&
           pthread_equal(g_entries[slot].tid, tid) &&
           g_entries[slot].running && wait_rc == 0) {
        wait_rc = pthread_cond_timedwait(&g_changed, &g_mu, deadline);
    }
    bool still_running =
        g_entries[slot].occupied &&
        pthread_equal(g_entries[slot].tid, tid) &&
        g_entries[slot].running;
    if (wait_rc != 0 && still_running)
        g_entries[slot].registry_joining = false;
    return still_running ? wait_rc : 0;
}

static void thread_registry_finish_join(int slot, pthread_t tid, int join_rc)
{
    if (slot < 0)
        return;
    pthread_mutex_lock(&g_mu);
    if (g_entries[slot].occupied &&
        pthread_equal(g_entries[slot].tid, tid)) {
        if (join_rc == 0)
            memset(&g_entries[slot], 0, sizeof(g_entries[slot]));
        else
            g_entries[slot].registry_joining = false;
    }
    pthread_mutex_unlock(&g_mu);
}

int thread_registry_join_until(pthread_t tid,
                               void **result,
                               const struct timespec *deadline)
{
    if (!deadline)
        return EINVAL;

    int slot;
    pthread_mutex_lock(&g_mu);
    int wait_rc =
        thread_registry_wait_for_exit_locked(tid, deadline, &slot);
    pthread_mutex_unlock(&g_mu);
    if (wait_rc != 0)
        return wait_rc;

    /* Completion was published by the trampoline (or the caller-owned row
     * was already retired after publication), so this join cannot wait on
     * worker execution. It only reaps the retained pthread resources. */
    int join_rc;
    do {
        join_rc = pthread_join(tid, result);
    } while (join_rc == EINTR);

    thread_registry_finish_join(slot, tid, join_rc);
    return join_rc;
}

static bool thread_registry_tid_is_excluded(
    pthread_t tid, const pthread_t *excluded, size_t excluded_count)
{
    if (!excluded)
        return false;
    for (size_t i = 0; i < excluded_count; i++) {
        if (pthread_equal(tid, excluded[i]))
            return true;
    }
    return false;
}

int thread_registry_join_all_except(int timeout_sec,
                                    const pthread_t *excluded,
                                    size_t excluded_count)
{
    if (timeout_sec < 0) timeout_sec = 0;
    int failed = 0;
    struct timespec deadline = {0};
    if (platform_time_realtime_timespec(&deadline) == 0)
        deadline.tv_sec += timeout_sec;

    for (int i = 0; i < ZCL_THREAD_REGISTRY_CAP; i++) {
        pthread_mutex_lock(&g_mu);
        bool occupied = g_entries[i].occupied;
        pthread_t tid = g_entries[i].tid;
        char name[sizeof(g_entries[i].name)];
        if (occupied)
            memcpy(name, g_entries[i].name, sizeof(name));
        pthread_mutex_unlock(&g_mu);
        if (!occupied) continue;
        if (thread_registry_tid_is_excluded(tid, excluded, excluded_count))
            continue;

        int rc = thread_registry_join_until(tid, NULL, &deadline);
        if (rc != 0) {
            fprintf(stderr, "[thread_registry] straggler after %ds: "  // obs-ok:helper-context-logged
                    "'%s' (rc=%d: %s)\n",
                    timeout_sec, name, rc, strerror(rc));
            failed++;
        }
    }
    return failed;
}

int thread_registry_join_all(int timeout_sec)
{
    return thread_registry_join_all_except(timeout_sec, NULL, 0);
}

void thread_registry_join_all_owned_except(const pthread_t *excluded,
                                           size_t excluded_count)
{
    for (int i = 0; i < ZCL_THREAD_REGISTRY_CAP; i++) {
        pthread_mutex_lock(&g_mu);
        bool occupied = g_entries[i].occupied;
        pthread_t tid = g_entries[i].tid;
        char name[sizeof(g_entries[i].name)];
        if (occupied) {
            memcpy(name, g_entries[i].name, sizeof(name));
            if (!thread_registry_tid_is_excluded(
                    tid, excluded, excluded_count))
                g_entries[i].registry_joining = true;
        }
        pthread_mutex_unlock(&g_mu);
        if (!occupied)
            continue;
        if (thread_registry_tid_is_excluded(tid, excluded, excluded_count))
            continue;

        fprintf(stderr,  // obs-ok:shutdown-owner-join-progress
                "[thread_registry] retaining ownership while joining '%s'\n",
                name);
        int rc;
        do {
            rc = pthread_join(tid, NULL);
        } while (rc == EINTR);

        if (rc != 0) {
            fprintf(stderr,  // obs-ok:shutdown-watchdog-propagates-join-failure
                    "[thread_registry] blocking join of '%s' failed: "
                    "rc=%d: %s\n",
                    name, rc, strerror(rc));
            /* Keep the registry entry active. The caller's shutdown watchdog
             * remains responsible for a truthful unclean process exit; we
             * must not manufacture a successful ownership handoff. */
            pthread_mutex_lock(&g_mu);
            g_entries[i].registry_joining = false;
            pthread_mutex_unlock(&g_mu);
            continue;
        }

        pthread_mutex_lock(&g_mu);
        memset(&g_entries[i], 0, sizeof(g_entries[i]));
        pthread_mutex_unlock(&g_mu);
    }
}

void thread_registry_join_all_owned(void)
{
    thread_registry_join_all_owned_except(NULL, 0);
}

int thread_registry_live_count(void)
{
    int n = 0;
    pthread_mutex_lock(&g_mu);
    for (int i = 0; i < ZCL_THREAD_REGISTRY_CAP; i++)
        if (g_entries[i].running) n++;
    pthread_mutex_unlock(&g_mu);
    return n;
}

int thread_registry_unreaped_count(void)
{
    int n = 0;
    pthread_mutex_lock(&g_mu);
    for (int i = 0; i < ZCL_THREAD_REGISTRY_CAP; i++)
        if (g_entries[i].occupied) n++;
    pthread_mutex_unlock(&g_mu);
    return n;
}

int thread_registry_snapshot(struct thread_registry_view *out, int cap)
{
    if (!out || cap <= 0) return 0;
    int n = 0;
    pthread_mutex_lock(&g_mu);
    for (int i = 0; i < ZCL_THREAD_REGISTRY_CAP && n < cap; i++) {
        if (!g_entries[i].running) continue;
        out[n].tid = g_entries[i].tid;
        memcpy(out[n].name, g_entries[i].name, sizeof(out[n].name));
        n++;
    }
    pthread_mutex_unlock(&g_mu);
    return n;
}

void thread_registry_reset_for_test(void)
{
    pthread_mutex_lock(&g_mu);
    memset(g_entries, 0, sizeof(g_entries));
    atomic_store_explicit(&g_shutdown, false, memory_order_release);
    pthread_mutex_unlock(&g_mu);
}
