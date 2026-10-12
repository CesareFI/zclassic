/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: private seam between dev.agent.outcomes and its usage_log reader
 *          (native_devagent_usage.c).
 */
#ifndef ZCL_NATIVE_DEVAGENT_USAGE_INTERNAL_H
#define ZCL_NATIVE_DEVAGENT_USAGE_INTERNAL_H

#include "command/native_command.h"
#include "json/json.h"

/* When `input` carries usage_log, read it and push a "usage" object onto
 * reply->data; on a bad or unreadable usage_log, fail the reply instead.
 * The path must be nonempty UTF-8. Malformed physical records (NUL or
 * invalid UTF-8) are counted before parsing or aggregation; a complete final
 * record needs no newline. JSON construction failure or invalid derived
 * UTF-8 fails the reply and leaves reply->data an empty object. Counter
 * totals above INT64_MAX fail with USAGE_OVERFLOW and the same empty object.
 * Codex total_token_usage is a cumulative rollout-generation snapshot, keyed
 * by explicit account and generation and ordered by ordinal. Resets, changed
 * coverage or conflicting checkpoints fail with USAGE_CONFLICT.
 * Only explicit root lineage (session_id == id, no parent_thread_id) qualifies;
 * inherited or missing lineage and malformed active-namespace records refuse.
 * It supplies no task attribution or model attribution; by_hour is the
 * snapshot hour, not interval usage. Missing namespace or ordinal is unkeyed.
 * `model` and `since` are the outcomes filters (NULL when absent). A call
 * without usage_log does nothing. */
void dvu_push_usage(const struct json_value *input, const char *model,
                    const char *since, struct zcl_command_reply *reply);

#ifdef ZCL_TESTING
/* Thread-local observation of the linked reader only. NULL restores normal
 * calls; fixtures and the outcomes handler retain their normal JSON calls. */
struct dvu_test_ops {
    void (*sort)(void *, size_t, size_t, int (*)(const void *, const void *));
    bool (*kv)(struct json_value *, const char *, const struct json_value *);
    bool (*back)(struct json_value *, const struct json_value *);
    bool (*str)(struct json_value *, const char *, const char *);
    bool (*integer)(struct json_value *, const char *, int64_t);
    bool (*boolean)(struct json_value *, const char *, bool);
};
void dvu_test_set_ops(const struct dvu_test_ops *ops);
#endif

#endif
