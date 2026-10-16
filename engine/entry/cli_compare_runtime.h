/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * Purpose: own standalone CLI cancellation and retained cleanup slots. */
#ifndef ZCL_ENTRY_CLI_COMPARE_RUNTIME_H
#define ZCL_ENTRY_CLI_COMPARE_RUNTIME_H
#include "kernel/command_registry.h"
#if !defined(_WIN32)
#include <signal.h>
#endif
/* Entry-private invocation storage. Outlives synchronous dispatch, buffered
 * output and all cleanup handling until this standalone process exits.
 * Shared registry callers provide their own longer-lived runtime/capsule.
 * Supply fresh zero-initialized storage for ONE invocation; do not reuse it
 * while any retained cleanup owner exists. This is not a reusable runtime.
 * begin refuses NULL or an active process scope before changing storage.
 * Same-context active refusal preserves the original owner's state; do not
 * call end for that refused nested acquisition (end would close the original).
 * A distinct fresh context remains safe for end after refused acquisition. */
struct cli_compare_signals {
#if !defined(_WIN32)
    struct sigaction previous[2];
    sigset_t original, owned;
    unsigned installed;
    bool mask_saved, acquired;
#endif
    bool reserved;
    struct zcl_command_cleanup_slot slots[ZCL_COMMAND_CLEANUP_SLOTS_MAX];
};
bool cli_compare_scope_begin(void *context);
bool cli_compare_scope_end(void *context);
bool cli_compare_reserve(void *context, unsigned count,
                                struct zcl_command_cleanup_slot **slots);
bool cli_compare_cleanup(void *context);
bool cli_compare_scope_cancelled(void *context);
#endif
