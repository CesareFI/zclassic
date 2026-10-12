/* Copyright 2026 Rhett Creighton - Apache-2.0
 * Purpose: private seam between resident_launch.c and the per-platform spawn arms */
/* Private seam between resident_launch.c and the per-platform spawn arms. */
#ifndef ZCL_PLATFORM_RESIDENT_LAUNCH_INTERNAL_H
#define ZCL_PLATFORM_RESIDENT_LAUNCH_INTERNAL_H

#include "platform/resident_launch.h"

#if defined(__APPLE__)
bool resident_launch_revalidate(struct resident_launch *launch,
                                char *error, size_t error_size);

/* Suspended posix_spawn of the pinned image's locator path, CodeDirectory
 * proof that the MAPPED process equals the PINNED descriptor, kill-before-
 * first-instruction on mismatch, SIGCONT resume on match. The path is a
 * locator only: a swap between F_GETPATH and spawn surfaces as a cdhash
 * mismatch and the child dies unexecuted (errno ESTALE). */
bool resident_spawn_darwin(struct resident_launch *launch,
                           char *const argv[], char *const envp[],
                           struct resident_receipt *receipt,
                           char *error, size_t error_size);
#endif

#endif
