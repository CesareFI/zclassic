/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: Pure bounded decoder beneath the frozen observation v1 contract. */
#ifndef ZCL_NATIVE_DEVAGENT_CODEX_OBSERVATION_DECODE_H
#define ZCL_NATIVE_DEVAGENT_CODEX_OBSERVATION_DECODE_H
#include "command/native_devagent_codex_observation.h"
#define CGO_RESPONSE_CAP (64u * 1024u)
#define CGO_BOUND_HELPER_CONTRACT "zcl.codex_native_goal_get.bound_helper.v1"
#define CGO_INPUT_CONTRACT_V2 "zcl.codex_native_goal_observation.input.v2"
#define CGO_INPUT_CONTRACT_V3 "zcl.codex_native_goal_observation.input.v3"
/* Compatibility-only legacy alias. It labels cgo_decode_input_v2, NEVER V3.
 * New consumers explicitly bind their entry point and its matching constant;
 * a discriminator or CGA_OK grants no effect/runtime admission. */
#define CGO_INPUT_CONTRACT CGO_INPUT_CONTRACT_V2
enum cgo_input_domain { CGO_NATIVE_GOAL_GET, CGO_OBSERVATION_WIRE };
struct cgo_decode_context {
    /* Receiver-owned complete version, including its bounded terminator. */
    char protocol_version[sizeof("0.160.0")];
    const char *request_id;
    size_t request_length;
    const char *thread_id;
    size_t thread_length;
};
/* Explicit expected lengths exclude NUL. No transport or clock side effects.
 * Output is entirely UNKNOWN/unqualified on refusal. A correlated result
 * reports readback only; all receiver identity/freshness/settings remain unknown.
 * Caller must initialize/free no JSON state. No response padding is hashed.
 * Entry identity CGO_BOUND_HELPER_CONTRACT: already-version-bound helper,
 * partial diagnostic facts allowed, not strict consumer admission. */
enum cga_result cgo_decode_goal_get(const char *raw, size_t raw_len,
    const char *request_id, size_t request_len,
    const char *thread_id, size_t thread_len,
    struct cgo_snapshot *out, char *why, size_t why_cap);
/* Entry identity CGO_INPUT_CONTRACT_V2; preserves partial diagnostic semantics.
 * Explicit domain/version boundary. Observation wire remains unsupported
 * until an independently bound owning verifier exists; never a stand-in. */
enum cga_result cgo_decode_input_v2(enum cgo_input_domain domain,
    const struct cgo_decode_context *context, const char *raw, size_t raw_length,
    struct cgo_snapshot *out, char *why, size_t why_cap);
/* Entry identity CGO_INPUT_CONTRACT_V3; new consumer must select this explicitly.
 * Strict revision3 coupling entry: installed required goal fields; explicit
 * goal:null gives ABSENT goal-related states. Frozen v2 remains diagnostic. */
enum cga_result cgo_decode_input_v3(enum cgo_input_domain domain,
    const struct cgo_decode_context *context, const char *raw, size_t raw_length,
    struct cgo_snapshot *out, char *why, size_t why_cap);
/* Pure recorded-pair correlation, not transport/admission or live freshness.
 * Both byte lengths exclude terminators. On any refusal the entire result is
 * zero/UNKNOWN, including digests. Context selects external operation/thread;
 * no authority is inferred from it. Successful digests cover exact raw bytes. */
#define CGO_JOURNAL_PAIR_CONTRACT_V1 "zcl.codex_native_goal_observation.journal_pair.v1"
struct cgo_journal_pair {
    struct cgo_digest request_sha256;
    struct cgo_digest response_sha256;
    struct cgo_snapshot observation;
};
enum cga_result cgo_decode_journal_pair_v1(
    const struct cgo_decode_context *context,
    const char *request, size_t request_length,
    const char *response, size_t response_length,
    struct cgo_journal_pair *out, char *why, size_t why_cap);
/* Additive passive capture. Frozen observation v1 and V13 are unchanged.
 * Receiver owns clock/assignment/replay authority; timestamps describe a
 * non-atomic interval only. Byte spans remain caller-owned and immutable
 * through the call. No I/O, invocation, policy or admission is performed. */
#define CGO_PASSIVE_CAPTURE_V1 "z23.codex.passive.capture.v1"
enum cgo_passive_method { CGO_PASSIVE_READ, CGO_PASSIVE_GOAL, CGO_PASSIVE_TURNS };
struct cgo_passive_leg {
    struct cgo_decode_context selection;
    const char *request;
    size_t request_length;
    const char *response; /* NULL/zero means unavailable, never successful */
    size_t response_length;
};
struct cgo_passive_trace {
    struct cgo_digest request_sha256;
    struct cgo_digest response_sha256;
    size_t request_length, response_length;
    enum cgo_truth readback;
};
struct cgo_passive_capture {
    struct cgo_passive_trace trace[3];
    struct cgo_snapshot goal;
    struct cgo_id thread_status, turn_id, turn_status;
    int64_t capture_started_at_ms, capture_completed_at_ms, maximum_age_ms;
    /* Transport/storage/runtime/exclusive authority remain unqualified.
     * Raw thread/turn replies are evidence only; no effective policy copy. */
};
enum cga_result cgo_passive_request_v1(enum cgo_passive_method method,
    const struct cgo_decode_context *selection, char *raw, size_t capacity,
    size_t *length, char *why, size_t why_capacity);
enum cga_result cgo_passive_capture_v1(const struct cgo_passive_leg legs[3],
    int64_t started_ms, int64_t completed_ms, int64_t maximum_age_ms,
    struct cgo_passive_capture *out, char *why, size_t why_capacity);
/* Additive compiled caller identity; existing wire/decoder APIs unchanged.
 * Only the authenticated receiver may select this compiled capability. This
 * enum authorizes no control effect and proves no source/runtime authority. */
#define CGO_PASSIVE_CALLER_V1 "z23.codex.passive.caller.v1"
/* Selection label revision2: opaque, not a measured host or authority fact.
 * The historical frozen v1 header remains immutable. Consumers of this source
 * successor must bind this discriminator and label explicitly; the old label
 * is refused, with the fixed thread and read-only methods unchanged. */
#define CGO_PASSIVE_M1_SELECTION_V2 "z23.codex.passive.pilot.selection.v2"
#define CGO_PASSIVE_M1_HOST "pilot-v1"
#define CGO_PASSIVE_M1_THREAD "01a0ff66-3abb-73b0-9c63-be51d80217bb"
#define CGO_PASSIVE_DIAGNOSTIC_MAX_AGE_MS INT64_C(5000)
enum cgo_passive_capability { CGO_PASSIVE_DISABLED, CGO_PASSIVE_LOCAL_M1 };
struct cgo_passive_caller_request {
    enum cgo_passive_capability capability;
    const char *host;
    size_t host_length;
    const char *thread;
    size_t thread_length;
    const char *request_ids[3];
    size_t request_id_lengths[3];
};
/* Read-only compiled port, never remote executable/path/shell. Reply bytes
 * are borrowed until release, called once for every non-NULL reply (including
 * failures). begin/end bracket one connection; end runs even on begin failure.
 * begin sends only supplied initialize/initialized; exchange only the supplied
 * closed read request. clock uses one process-local monotonic domain plus wall
 * milliseconds. Callback context need not outlive caller return. */
struct cgo_passive_caller_io {
    void *context;
    enum cga_result (*begin)(void *, const char *, size_t, const char *, size_t,
        char **, size_t *, char *, size_t);
    enum cga_result (*exchange)(void *, enum cgo_passive_method,
        const char *, size_t, char **, size_t *, char *, size_t);
    void (*release)(void *, char *, size_t);
    void (*end)(void *);
    bool (*clock)(void *, int64_t *, int64_t *);
};
struct cgo_passive_owned;
struct cgo_passive_caller_view {
    struct cgo_passive_leg legs[3];
    const char *initialize_request, *initialized_request, *initialize_response;
    size_t initialize_request_length, initialized_request_length, initialize_response_length;
    struct cgo_passive_capture observation;
    const char *objective; /* exact decoded native bytes, or NULL/length0 */
    size_t objective_length;
    int64_t started_monotonic_ms, completed_monotonic_ms;
    enum cga_result result;
};
/* Wrong/disabled capability, host/thread or IDs refuse before port entry and
 * return *out=NULL. After port entry failures may return an owned raw trace,
 * but its observation/objective remain wholly UNKNOWN. No callback retry.
 * All inputs/replies are deep copied: immutable view survives callback/input
 * lifetime and another capture; free with the owning release entry only. */
enum cga_result cgo_passive_caller_v1(const struct cgo_passive_caller_request *,
    const struct cgo_passive_caller_io *, struct cgo_passive_owned **,
    char *, size_t);
const struct cgo_passive_caller_view *cgo_passive_caller_view_v1(
    const struct cgo_passive_owned *);
void cgo_passive_caller_free_v1(struct cgo_passive_owned *);
/* Diagnostic same-monotonic-domain policy only: age measured from START of
 * non-atomic capture. age>=5000ms returns CGA_STALE and whole UNKNOWN; future/
 * reversed time refuses. CGO freshness/continuity/effective policy stay UNKNOWN
 * even within age. Raw evidence remains available, never relabeled fresh. */
enum cga_result cgo_passive_caller_project_v1(const struct cgo_passive_owned *,
    int64_t receiver_now_monotonic_ms, struct cgo_passive_capture *, char *, size_t);
/* Implemented by source-built existing-controller candidate, not installed
 * 6bba. No socket/executable/path parameter: fixed existing local route only.
 * Link only behind service-owner explicit candidate capability binding. */
enum cga_result cgo_passive_local_m1_v1(const struct cgo_passive_caller_request *,
    struct cgo_passive_owned **, char *, size_t);
/* Additive fixed local rhett2 binding; PROPOSED, not existing v1 authority. */
#define CGO_PASSIVE_RHETT2_CALLER_V1 "z23.codex.passive.rhett2.caller.v1"
#define CGO_PASSIVE_RHETT2_HOST "rhett2"
#define CGO_PASSIVE_RHETT2_THREAD "01a103b3-421d-7fd1-a08d-006e62d7367d"
struct cgo_passive_rhett2_request_v1 {
    bool enabled;
    const char *request_ids[3];
    size_t request_id_lengths[3];
};
/* enabled selects only this compiled local passive capability, not authority.
 * No host/thread/socket/path input; disabled/invalid IDs refuse zero I/O.
 * Existing view/free/project/lifetime/uncertainty contracts apply unchanged. */
enum cga_result cgo_passive_rhett2_caller_v1(
    const struct cgo_passive_rhett2_request_v1 *,
    const struct cgo_passive_caller_io *, struct cgo_passive_owned **,
    char *, size_t);
enum cga_result cgo_passive_local_rhett2_v1(
    const struct cgo_passive_rhett2_request_v1 *,
    struct cgo_passive_owned **, char *, size_t);
#endif
