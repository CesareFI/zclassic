/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Identity of the checkout the local MCP adapter serves. */

#ifndef ZCL_TOOLS_MCP_IDENTITY_H
#define ZCL_TOOLS_MCP_IDENTITY_H

#include "mcp_rpc.h"

#include <limits.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

struct mcp_identity {
    char root[PATH_MAX];     /* realpath of the --checkout argument */
    char toplevel[PATH_MAX]; /* git toplevel, equal to root once verified */
    char head[65];           /* full commit id */
    bool dirty;              /* tracked changes or untracked files */
    bool fingerprint_present;
    bool fingerprint_stale;  /* the code index is older than the tree */
    char fingerprint[65];    /* hex code-index source_root_sha3 */
};

/* Verify checkout is a git toplevel and read its identity. Never uses the
 * ambient working directory or GIT_DIR: git runs with -C on the realpath.
 * Codes: CHECKOUT_NOT_FOUND, CHECKOUT_NOT_GIT, CHECKOUT_NOT_TOPLEVEL,
 * HEAD_UNREADABLE. The fingerprint is optional and never fails the call. */
bool mcp_identity_resolve(const char *checkout, struct mcp_identity *id,
                          struct mcp_refusal *why);

/* One-line JSON object describing id, NUL-terminated. Returns its length or
 * 0 when it does not fit. */
size_t mcp_identity_json(const struct mcp_identity *id, char *out, size_t cap);

#ifdef __cplusplus
}
#endif

#endif
