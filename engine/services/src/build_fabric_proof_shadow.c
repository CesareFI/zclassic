/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Feedback-only proof-ticket decision beside every attach decision:
 *          the same key, the worker table's current trust, the requester's
 *          own trust domain, and a count of where the two agree. */

#include "build_fabric_proof_context_internal.h"

#include "base/hex.h"
#include "base/log_macros.h"
#include "base/safe_alloc.h"
#include "json/json.h"
#include "platform/time_compat.h"
#include "services/build_fabric_attach.h"
#include "vcs/build_execution_observation.h"
#include "vcs/proof_reuse.h"
#include "vcs/vcs_object.h"

#ifndef _WIN32
#include "build_fabric_attach_identity_internal.h"
#endif

#include <stdlib.h>
#include <string.h>

#define BFPS_LOG "build_fabric"
#define BFPS_CLASS_CAP 64u
#define BFPS_MAX_FUTURE_SECONDS 300u

/* Artifact bytes for a ticket's root: the evidence observation the ticket
 * names, checked against its root and the artifact root, then the chunked
 * output it binds. The decision re-hashes whatever this returns. */
struct bfps_fetch {
    const char *workspace;
    const struct vcs_proof_receiver *receiver;
    const uint8_t *input_key;
    uint8_t *bytes;
    size_t len;
};

static bool bfps_evidence_bytes(struct bfps_fetch *f,
                                const struct vcs_proof_ticket_v1 *t)
{
#ifndef _WIN32
    uint8_t *wire = NULL, checked[32];
    size_t len = 0;
    struct vcs_build_execution_observation_v1 obs;
    if (vcs_object_load_raw(f->workspace, t->evidence_root, &wire, &len) != 0)
        return false;
    bool ok = vcs_build_execution_observation_v1_parse(wire, len, &obs) &&
              vcs_build_execution_observation_v1_root(&obs, checked) &&
              memcmp(checked, t->evidence_root, 32) == 0 &&
              memcmp(obs.output_bytes_root, t->artifact_root, 32) == 0;
    free(wire);
    return ok && bfat_artifact_read(f->workspace, obs.artifact_root,
                                    obs.action_root, &f->bytes,
                                    &f->len).ok;
#else
    (void)f;
    (void)t;
    return false;
#endif
}

static bool bfps_fetch_artifact(void *vctx, const uint8_t artifact_root[32],
                                const uint8_t **bytes, size_t *len)
{
    struct bfps_fetch *f = vctx;
    free(f->bytes);
    f->bytes = NULL;
    f->len = 0;
    const uint8_t *wires[BFPS_CLASS_CAP];
    size_t n = vcs_proof_receiver_lookup(f->receiver, f->input_key, wires,
                                         BFPS_CLASS_CAP);
    for (size_t i = 0; i < n && i < BFPS_CLASS_CAP; i++) {
        struct vcs_proof_ticket_v1 t;
        if (!vcs_proof_ticket_decode(wires[i], VCS_PROOF_TICKET_WIRE_BYTES,
                                     &t) ||
            memcmp(t.artifact_root, artifact_root, 32) != 0)
            continue;
        if (bfps_evidence_bytes(f, &t)) {
            *bytes = f->bytes;
            *len = f->len;
            return true;
        }
    }
    return false;
}

/* D2: the requester is the candidate's author and this worker is the local
 * signer, so no ticket either of them issued can count toward reuse. */
static const char *bfps_decide(struct build_fabric_proof_context *ctx,
                               struct node_db *ndb, const char *workspace,
                               const uint8_t requester_pubkey[32],
                               const struct vcs_component_proof_key_v1 *key,
                               struct vcs_proof_reuse_decision *decision)
{
    if (!ctx->receiver) return "receiver_unavailable";
    int64_t now = (int64_t)platform_time_wall_unix();
    struct bfpc_trust trust;
    if (BFPC_FAULT(BUILD_FABRIC_PROOF_FAULT_SHADOW_DECIDE) ||
        !bfpc_trust_load(ndb, now, &trust).ok)
        return "trust_unreadable";
    struct vcs_proof_reuse_policy policy = {
        .verifiers = (const uint8_t (*)[32])trust.verifiers,
        .verifier_count = trust.verifier_count,
        .revoked = (const uint8_t (*)[32])trust.revoked,
        .revoked_count = trust.revoked_count,
        .quorum = ctx->quorum,
        .now_unix = (uint64_t)now,
        .max_future_seconds = BFPS_MAX_FUTURE_SECONDS,
    };
    memcpy(policy.policy_root, key->roots[VCS_CPK_POLICY], 32);
    struct vcs_proof_candidate_domain domain = { .has_local_signer = true };
    memcpy(domain.author_pubkey, requester_pubkey, 32);
    memcpy(domain.local_signer_pubkey, ctx->pubkey, 32);
    uint8_t input_key[32];
    struct bfps_fetch fetch = { .workspace = workspace,
                                .receiver = ctx->receiver,
                                .input_key = input_key };
    struct vcs_proof_artifact_source artifacts = {
        .fetch = bfps_fetch_artifact, .ctx = &fetch };
    struct vcs_proof_reuse_request request = {
        .local = key, .action_class = VCS_PROOF_ACTION_BUILD,
        .domain = &domain, .policy = &policy, .artifacts = &artifacts };
    struct vcs_proof_ticket_class *classes =
        zcl_calloc(BFPS_CLASS_CAP, sizeof(*classes), "proof shadow classes");
    const char *unavailable = classes &&
        vcs_component_proof_key_derive(key, input_key) ? NULL
        : "shadow_allocation";
    if (!unavailable)
        (void)vcs_proof_reuse_decide(ctx->receiver, &request, classes,
                                     BFPS_CLASS_CAP, decision);
    free(classes);
    free(fetch.bytes);
    bfpc_trust_free(&trust);
    return unavailable;
}

static void bfps_count_attach(struct bfpc_live *l,
                              enum build_fabric_attach_disposition d)
{
    atomic_store(&l->last_attach, build_fabric_attach_disposition_string(d));
    if (d == BUILD_FABRIC_ATTACH_HIT) atomic_fetch_add(&l->attach_hit, 1);
    else if (d == BUILD_FABRIC_ATTACH_MISS)
        atomic_fetch_add(&l->attach_miss, 1);
    else atomic_fetch_add(&l->attach_refused, 1);
}

static void bfps_count_ticket(struct bfpc_live *l,
                              enum vcs_proof_reuse_outcome o)
{
    if (o == VCS_PROOF_REUSE_HIT_PASS) atomic_fetch_add(&l->ticket_hit, 1);
    else if (o == VCS_PROOF_REUSE_HIT_FAIL)
        atomic_fetch_add(&l->ticket_hit_fail, 1);
    else if (o == VCS_PROOF_REUSE_MISS) atomic_fetch_add(&l->ticket_miss, 1);
    else atomic_fetch_add(&l->ticket_refuse, 1);
}

/* Agreement is on the one question both answer: may this request skip its
 * compile? Attach HIT against ticket HIT_PASS. */
static bool bfps_count_pair(struct bfpc_live *l,
                            enum build_fabric_attach_disposition d,
                            const struct vcs_proof_reuse_decision *decision)
{
    bool attach_hit = d == BUILD_FABRIC_ATTACH_HIT;
    bool ticket_hit = decision->outcome == VCS_PROOF_REUSE_HIT_PASS;
    atomic_fetch_add(&l->shadow_decisions, 1);
    bfps_count_ticket(l, decision->outcome);
    atomic_store(&l->last_ticket_outcome,
                 vcs_proof_reuse_outcome_name(decision->outcome));
    atomic_store(&l->last_ticket_reason,
                 decision->reason ? decision->reason : "none");
    if (attach_hit == ticket_hit) {
        atomic_fetch_add(&l->agree, 1);
        return true;
    }
    atomic_fetch_add(&l->disagree, 1);
    atomic_fetch_add(attach_hit ? &l->disagree_attach_only
                                : &l->disagree_ticket_only, 1);
    return false;
}

struct zcl_result build_fabric_proof_shadow_attach(
    struct build_fabric_proof_context *ctx, struct node_db *ndb,
    const char *workspace, const uint8_t requester_pubkey[32],
    const struct build_fabric_attach_report *report)
{
    if (!ctx || !report)
        return ZCL_ERR(-1, "proof shadow requires a context and a report");
    struct bfpc_live *l = &ctx->live;
    bfps_count_attach(l, report->disposition);
    struct vcs_proof_reuse_decision decision;
    memset(&decision, 0, sizeof(decision));
    const char *unavailable = !ndb || !workspace || !requester_pubkey
        ? "shadow_arguments"
        : !report->proof_key_known ? "proof_key_unknown"
        : bfps_decide(ctx, ndb, workspace, requester_pubkey,
                      &report->proof_key, &decision);
    if (unavailable) {
        atomic_fetch_add(&l->shadow_unavailable, 1);
        atomic_store(&l->last_ticket_outcome, "unavailable");
        atomic_store(&l->last_ticket_reason, unavailable);
        LOG_INFO(BFPS_LOG,
                 "schema=zcl.proof_shadow.v1 executor_key=%s attach=%s "
                 "ticket=unavailable reason=%s",
                 report->executor_key[0] ? report->executor_key : "none",
                 build_fabric_attach_disposition_string(report->disposition),
                 unavailable);
        return ZCL_ERR(-1, "proof-shadow-unavailable: %s", unavailable);
    }
    bool agree = bfps_count_pair(l, report->disposition, &decision);
    LOG_INFO(BFPS_LOG,
             "schema=zcl.proof_shadow.v1 executor_key=%s attach=%s "
             "ticket=%s reason=%s tickets_seen=%u eligible_pass=%u "
             "distinct_pass_signers=%u agree=%d",
             report->executor_key,
             build_fabric_attach_disposition_string(report->disposition),
             vcs_proof_reuse_outcome_name(decision.outcome),
             decision.reason ? decision.reason : "none",
             decision.tickets_seen, decision.eligible_pass,
             decision.distinct_pass_signers, agree ? 1 : 0);
    return ZCL_OK;
}

static void bfps_json_int(struct json_value *o, const char *k, uint64_t v)
{
    (void)json_push_kv_int(o, k, (int64_t)v);
}

void build_fabric_proof_stats_json(const struct build_fabric_proof_stats *s,
                                   struct json_value *out)
{
    if (!s || !out) return;
    json_set_object(out);
    (void)json_push_kv_str(out, "schema", "zcl.build_fabric_proof.v1");
    (void)json_push_kv_str(out, "tickets_role", "feedback_only");
    (void)json_push_kv_str(out, "issuer_state", s->issuer_state);
    (void)json_push_kv_str(out, "receiver_state", s->receiver_state);
    bfps_json_int(out, "issuer_leaves", s->issuer_leaves);
    bfps_json_int(out, "receiver_tickets", s->receiver_tickets);
    bfps_json_int(out, "receiver_checkpoints", s->receiver_checkpoints);
    bfps_json_int(out, "receiver_skipped", s->receiver_skipped);
    bfps_json_int(out, "receiver_catalog_rows", s->receiver_catalog_rows);
    bfps_json_int(out, "issued", s->issued);
    bfps_json_int(out, "issue_refused", s->issue_refused);
    (void)json_push_kv_str(out, "last_issue_refusal", s->last_issue_refusal);
    bfps_json_int(out, "shadow_decisions", s->shadow_decisions);
    bfps_json_int(out, "shadow_unavailable", s->shadow_unavailable);
    bfps_json_int(out, "ticket_hit", s->ticket_hit);
    bfps_json_int(out, "ticket_hit_fail", s->ticket_hit_fail);
    bfps_json_int(out, "ticket_miss", s->ticket_miss);
    bfps_json_int(out, "ticket_refuse", s->ticket_refuse);
    bfps_json_int(out, "attach_hit", s->attach_hit);
    bfps_json_int(out, "attach_miss", s->attach_miss);
    bfps_json_int(out, "attach_refused", s->attach_refused);
    bfps_json_int(out, "agree", s->agree);
    bfps_json_int(out, "disagree", s->disagree);
    bfps_json_int(out, "disagree_attach_only", s->disagree_attach_only);
    bfps_json_int(out, "disagree_ticket_only", s->disagree_ticket_only);
    (void)json_push_kv_str(out, "last_attach", s->last_attach);
    (void)json_push_kv_str(out, "last_ticket_outcome",
                          s->last_ticket_outcome);
    (void)json_push_kv_str(out, "last_ticket_reason", s->last_ticket_reason);
}
