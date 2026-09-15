/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Resolve owner-private development and application state roots. */
#ifndef ZCL_PLATFORM_STATE_ROOT_H
#define ZCL_PLATFORM_STATE_ROOT_H
#include <stdbool.h>
#include <stddef.h>
bool platform_state_root(char *out, size_t out_size);
/* Resolve the development state root only when its z23 and dev directories
 * already exist and are owner-private/no-link.  Never creates or repairs. */
bool platform_state_root_existing(char *out, size_t out_size);
/* Persistent app state, separate from the development root. Creates only
 * owner-private directories beneath an absolute platform-selected base. */
bool platform_application_state_root(char *out, size_t out_size);
#endif
