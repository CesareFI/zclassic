/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Define the isolated benchmark mutex-sample interface.
 */
#ifndef ZCL_C3_MUTEX_PROBE_H
#define ZCL_C3_MUTEX_PROBE_H
#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
struct c3_mutex_sample {
    uint64_t wait_ns, hold_ns, unlock_ns;
    unsigned role;
};
struct c3_mutex_probe_api {
    void (*begin)(pthread_mutex_t *target);
    void (*set_role)(unsigned role);
    size_t (*read)(struct c3_mutex_sample *out, size_t capacity);
};
#endif
