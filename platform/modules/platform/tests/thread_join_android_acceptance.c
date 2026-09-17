/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Host-side acceptance for Android's bounded-join capability branch.
 * This is not an Android NDK link proof. */

#include "platform/thread_compat.h"

#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <time.h>

int main(void)
{
#if !defined(__ANDROID__)
#error "compile this acceptance fixture with __ANDROID__ defined"
#endif
    pthread_t thread = (pthread_t)0;
    struct timespec deadline = {0};
    int rc = platform_thread_join_until(thread, NULL, &deadline);
    if (rc != ENOTSUP) {
        fprintf(stderr, /* obs-ok:acceptance-failure-exits-synchronously */
                "Android timed join capability returned %d, expected %d\n",
                rc, ENOTSUP);
        return 1;
    }
    puts("thread_join_android_acceptance: unsupported capability is explicit");
    return 0;
}
