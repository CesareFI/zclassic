/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Windows-only internal helpers shared by process_lifecycle.c and
 * confined_process.c — the one UTF-8 to UTF-16 conversion, the one
 * CommandLineToArgvW-exact command-line encoder, the one sorted explicit
 * environment block, and the one absolute-path test, so the hidden launch
 * and the confined launch can never quote an argument or pass an
 * environment differently. Every returned buffer is heap-owned by the
 * caller (free). Declares nothing on POSIX. */
#ifndef ZCL_PLATFORM_PROCESS_LIFECYCLE_INTERNAL_H
#define ZCL_PLATFORM_PROCESS_LIFECYCLE_INTERNAL_H

#if defined(_WIN32)
#include <stdbool.h>
#include <wchar.h>

wchar_t *platform_process_windows_utf16(const char *text);
wchar_t *platform_process_windows_command_line(const char *const *argv);
wchar_t *platform_process_windows_environment(const char *const *env);
bool platform_process_windows_absolute(const wchar_t *path);
#endif

#endif
