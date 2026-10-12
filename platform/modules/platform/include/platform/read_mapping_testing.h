/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Observe successful descriptor mappings in focused tests. */
#ifndef ZCL_PLATFORM_READ_MAPPING_TESTING_H
#define ZCL_PLATFORM_READ_MAPPING_TESTING_H

#ifdef ZCL_TESTING
#include "platform/read_mapping.h"

/* Observe a successful descriptor mapping on this thread, after the native
 * mapping exists and before returning to its caller. The observer does not
 * select or replace the opener, descriptor flags, or mapped bytes. Passing
 * NULL clears it; context must remain live until it is cleared. */
void platform_read_mapping_observe_for_testing(
    void (*observer)(int fd, const struct platform_read_mapping *mapping,
                     void *context),
    void *context);
#endif

#endif
