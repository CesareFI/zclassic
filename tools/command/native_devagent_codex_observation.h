/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: Read-only native observation v1. No effects or transport authority. */
#ifndef ZCL_NATIVE_DEVAGENT_CODEX_OBSERVATION_H
#define ZCL_NATIVE_DEVAGENT_CODEX_OBSERVATION_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define CGA_GOAL_CAP 8192u
#define CGA_ID_CAP 128u
enum cga_goal_status {
    CGA_ABSENT, CGA_ACTIVE, CGA_PAUSED, CGA_BLOCKED, CGA_USAGE_LIMITED,
    CGA_BUDGET_LIMITED, CGA_COMPLETE
};
enum cga_result {
    CGA_OK, CGA_INVALID, CGA_UNSUPPORTED, CGA_AUTHORITY,
    CGA_STORAGE, CGA_STALE, CGA_CONFLICT, CGA_UNCERTAIN, CGA_LIMIT
};

#define CGO_SCHEMA "zcl.codex_native_goal_observation.v1"

/* Zero initialization reports UNKNOWN, never false, zero usage or absence. */
enum cgo_state { CGO_UNKNOWN, CGO_KNOWN, CGO_ABSENT, CGO_REFUSED };
enum cgo_truth { CGO_TRUTH_UNKNOWN, CGO_FALSE, CGO_TRUE };
enum cgo_freshness { CGO_FRESHNESS_UNKNOWN, CGO_FRESH, CGO_STALE };
enum cgo_qualification { CGO_UNQUALIFIED, CGO_REJECTED, CGO_QUALIFIED };

struct cgo_text { enum cgo_state state; char value[4096]; };
struct cgo_id { enum cgo_state state; char value[CGA_ID_CAP]; };
struct cgo_digest { enum cgo_state state; char value[65]; };
struct cgo_integer { enum cgo_state state; int64_t value; };
struct cgo_qualified {
    enum cgo_qualification state;
    struct cgo_digest evidence_sha256;
};

/* Value fields are inert unless state is KNOWN. Digests bind exact bytes,
 * not semantic equivalence. No struct padding is serialized. All strings
 * are bounded, terminated, lossless UTF-8 without embedded NUL. */
struct cgo_snapshot {
    struct cgo_digest source_sha256;
    struct cgo_digest executable_sha256;
    struct cgo_digest controller_sha256;
    struct cgo_digest response_sha256;
    struct cgo_text workspace;
    struct cgo_id job_id;
    struct cgo_integer queue_seq;
    struct cgo_integer attempt;
    struct cgo_id thread_id;
    struct cgo_id turn_id;
    struct cgo_id request_id;
    struct cgo_text requested_model;
    struct cgo_text requested_effort;
    struct cgo_text effective_model;
    struct cgo_text effective_effort;
    struct cgo_digest environment_sha256;
    struct cgo_integer observed_at_unix_ms;
    struct cgo_integer age_ms;
    struct cgo_integer max_age_ms;
    enum cgo_freshness freshness;
    enum cgo_truth goal_present;
    enum cgo_state goal_status_state;
    enum cga_goal_status goal_status;
    struct cgo_digest objective_sha256;
    struct cgo_integer objective_length;
    struct cgo_integer token_budget;
    struct cgo_integer tokens_used;
    struct cgo_integer time_used_seconds;
    struct cgo_integer created_at_unix_seconds;
    struct cgo_integer updated_at_unix_seconds;
    enum cgo_truth accepted;
    enum cgo_truth submitted;
    enum cgo_truth applied;
    enum cgo_truth readback;
    enum cgo_truth terminal;
    enum cgo_truth quiescent;
    struct cgo_qualified transport;
    struct cgo_qualified storage;
    struct cgo_qualified runtime;
    struct cgo_qualified exclusive_authority;
};

#endif
