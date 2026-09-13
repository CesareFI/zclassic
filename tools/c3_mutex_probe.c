/* Copyright 2026 Rhett Creighton - Apache License 2.0 */
#define _GNU_SOURCE
#include "dev/c3_mutex_probe.h"
#include <dlfcn.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static pthread_once_t once = PTHREAD_ONCE_INIT;
static int (*real_lock)(pthread_mutex_t *);
static int (*real_unlock)(pthread_mutex_t *);
static _Atomic(pthread_mutex_t *) selected;
static _Atomic size_t used;
static struct c3_mutex_sample samples[64];
static _Thread_local unsigned role, depth;
static _Thread_local uint64_t acquired, waited;

static uint64_t now_ns(void)
{
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t)) {
        perror("c3 mutex probe clock");
        _Exit(125);
    }
    return (uint64_t)t.tv_sec * UINT64_C(1000000000) + (uint64_t)t.tv_nsec;
}

static void resolve(void)
{
    void *lock = dlsym(RTLD_NEXT, "pthread_mutex_lock");
    void *unlock = dlsym(RTLD_NEXT, "pthread_mutex_unlock");
    static_assert(sizeof(lock) == sizeof(real_lock), "POSIX function pointer size");
    if (!lock || !unlock) {
        fputs("c3 mutex probe cannot resolve pthread functions\n", stderr);
        _Exit(125);
    }
    memcpy(&real_lock, &lock, sizeof(real_lock));
    memcpy(&real_unlock, &unlock, sizeof(real_unlock));
}

int pthread_mutex_lock(pthread_mutex_t *mutex)
{
    int ready = pthread_once(&once, resolve);
    if (ready) return ready;
    bool measure = mutex == atomic_load_explicit(&selected, memory_order_relaxed);
    uint64_t before = measure && !depth ? now_ns() : 0;
    int result = real_lock(mutex);
    if (measure && !result && depth++ == 0) {
        acquired = now_ns();
        waited = acquired - before;
    }
    return result;
}

int pthread_mutex_unlock(pthread_mutex_t *mutex)
{
    int ready = pthread_once(&once, resolve);
    if (ready) return ready;
    bool measure = mutex == atomic_load_explicit(&selected, memory_order_relaxed);
    bool outer = measure && depth && --depth == 0;
    uint64_t before = outer ? now_ns() : 0;
    int result = real_unlock(mutex);
    if (outer) {
        uint64_t after = now_ns();
        size_t index = atomic_fetch_add_explicit(&used, 1, memory_order_relaxed);
        if (result || index >= sizeof(samples) / sizeof(samples[0])) {
            fputs("c3 mutex probe unlock failure or sample capacity exceeded\n", stderr);
            _Exit(125);
        }
        samples[index] = (struct c3_mutex_sample){waited, before-acquired,
                                                after-before, role};
    }
    return result;
}

static void begin(pthread_mutex_t *target)
{
    atomic_store(&selected, NULL);
    atomic_store(&used, 0);
    depth = 0;
    atomic_store(&selected, target);
}

static void set_role(unsigned value) { role = value; }

static size_t read_samples(struct c3_mutex_sample *out, size_t capacity)
{
    size_t count = atomic_load(&used);
    if (count > capacity) return count;
    memcpy(out, samples, count * sizeof(*out));
    return count;
}

const struct c3_mutex_probe_api c3_mutex_probe_v1 = {begin, set_role, read_samples};
