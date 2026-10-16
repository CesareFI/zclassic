/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * Purpose: shared Linux descriptor closure for freshly forked children (the
 * terminal worker and the confined resident launcher). */
#ifndef ZCL_OS_PROC_FDCLOSE_INTERNAL_H
#define ZCL_OS_PROC_FDCLOSE_INTERNAL_H
#include <stdbool.h>
#include <stddef.h>
#if defined(__linux__)
/* Freshly forked child only. Sorted keep set (negative entries ignored), at
 * most 48 entries. False forbids exec; no allocation, streams or callbacks.
 * Caller must exclude inherited handlers that can open descriptors from the
 * sweep through exec; this operation does not establish a signal policy.
 * try_range=false exercises the same complete proc fallback on older kernels. */
bool os_proc_linux_close_fds_kept(const int *keep, size_t n, bool try_range);
#endif
#endif
