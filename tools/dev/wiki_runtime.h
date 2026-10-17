/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: finite wiki propagation qualification; lifecycle remains a separate gate. */
#ifndef ZCL_WIKI_RUNTIME_H
#define ZCL_WIKI_RUNTIME_H
#include "json/json.h"
#include "session/fleet_board_proto.h"
#include <stdbool.h>
#include <stdint.h>
enum { WR_MAX = 8, WR_ARGS = 12, WR_ARG_CAP = 512, WR_REPLY_CAP = 16384 };
enum wr_role { WR_WRITER = 1, WR_READER = 2, WR_BOTH = 3 };
enum wr_call_state { WR_CALL_OK, WR_TIMEOUT, WR_TRUNCATED, WR_UNKNOWN_EXIT,
    WR_CANCELLED, WR_LAUNCH_FAILED, WR_EXIT_FAILED, WR_INVALID_JSON };
struct wr_participant {
    char name[25], platform[25], source[41], artifact[65];
    uint8_t host[32], scope;
    char room[33];
    enum wr_role role;
    char argv[WR_ARGS][WR_ARG_CAP];
    size_t argc;
};
struct wr_plan {
    char run[25];
    uint32_t ttl_seconds;
    size_t count;
    struct wr_participant participants[WR_MAX];
};
struct wr_backend {
    void *ctx;
    int64_t (*now_ms)(void *ctx);
    /* Always returns an initialized caller-owned reply, including failures.
     * wr_invoke alone disposes refused/cancelled replies and reinitializes.
     * Valid nonzero-exit JSON may be retained solely for typed NOT_FOUND. */
    enum wr_call_state (*call)(void *ctx, const struct wr_participant *peer,
        const char *operation, const char *run, const struct json_value *input,
        int64_t deadline_ms, struct json_value *reply);
};
/* Success binds the EXACT required set/roles, with at least two participants.
 * Git provenance is owner-qualified; a version source digest is not a git ID. */
bool wr_plan_read(const struct json_value *in, struct wr_plan *out,
    const char **why);
/* Reconstruct every signed field and all short-body bytes, then use the
 * production canonical ID/signature verifier. Output is zero on refusal. */
bool wr_post_read(const struct json_value *reply,
    struct fleet_board_post *out, const char **why);
/* Returns propagation evidence only. full_qualification is ALWAYS false until
 * separately reviewed owner lifecycle/cleanup qualification exists. No launch
 * or restart authority is implied by an endpoint or valid signature. */
bool wr_run(const struct wr_plan *plan, const struct wr_backend *backend,
    struct json_value *receipt, const char **why);
enum wr_call_state wr_capture(const char *const argv[], int remaining_ms,
    struct json_value *reply);
int64_t wr_monotonic_ms(void);
/* Opened-object nofollow, nonblocking regular-file observation; bounded bytes. */
bool wr_read_regular(const char *path, void *bytes, size_t cap, size_t *length);
#endif
