/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Sign one proof ticket for each executed plain compile and publish
 *          it at the durable head: stage, CAS, conditional head. */

#include "build_fabric_proof_context_internal.h"

#include "base/hex.h"
#include "base/log_macros.h"
#include "models/build_fabric.h"
#include "platform/time_compat.h"
#include "services/build_fabric_attach.h"
#include "services/build_fabric_worker.h"
#include "vcs/blob_store.h"
#include "vcs/build_action.h"
#include "vcs/build_execution_observation.h"
#include "vcs/proof_reuse.h"
#include "vcs/vcs_object.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if !defined(_WIN32)
#include "build_fabric_attach_identity_internal.h"
#endif

#define BFPI_LOG "build_fabric"

#ifdef ZCL_TESTING
static void (*g_bfpi_hook)(enum build_fabric_proof_issue_point, void *);
static void *g_bfpi_hook_context;

void build_fabric_proof_test_issue_hook(
    void (*hook)(enum build_fabric_proof_issue_point point, void *context),
    void *context)
{
    g_bfpi_hook = hook;
    g_bfpi_hook_context = context;
}

#define BFPI_POINT(point) \
    do { if (g_bfpi_hook) g_bfpi_hook((point), g_bfpi_hook_context); } while (0)
#else
#define BFPI_POINT(point) do { } while (0)
#endif

struct zcl_result build_fabric_proof_compile_key(
    const char *workspace, const struct db_build_action *action,
    const uint8_t input_bytes_root[32],
    struct vcs_component_proof_key_v1 *out)
{
    if (!workspace || !action || !input_bytes_root || !out)
        return ZCL_ERR(-1, "proof compile key requires action and input");
#if defined(_WIN32)
    return ZCL_ERR(-1, "proof-key-unavailable: no qualified Windows executor");
#else
    /* The cached capsule and descriptor, as attach composes its key: no
     * toolchain re-capture launches, only the runtime closure probes. */
    struct vcs_toolchain_capsule_v1 capsule;
    struct platform_toolchain_descriptor descriptor;
    uint8_t driver[32], backend[32], assembler[32];
    uint8_t runtime[32], verifier[32], policy[32] = {0};
    if (!vcs_toolchain_capsule_v1_cached(&capsule, &descriptor))
        return ZCL_ERR(-1, "proof-key-toolchain-capsule-unavailable");
    ZCL_CHECK(bfat_cached_tool_hashes(&descriptor, driver, backend,
                                      assembler));
    ZCL_CHECK(bfat_runtime_roots(workspace, &descriptor, runtime, verifier));
    if (action->proof_policy_root_sha3[0] &&
        !zcl_hex_decode_lower(action->proof_policy_root_sha3, policy, 32))
        return ZCL_ERR(-1, "proof-key-policy-root-malformed");
    struct vcs_fixed_compile_proof_inputs inputs = {
        .capsule = &capsule,
        .driver_bytes_sha3 = driver,
        .backend_bytes_sha3 = backend,
        .assembler_bytes_sha3 = assembler,
        .runtime_bytes_sha3 = runtime,
        .verifier_bytes_sha3 = verifier,
        .input_bytes_sha3 = input_bytes_root,
        .proof_policy_root = policy,
        .target = action->target,
        .resource_policy = action->resource_policy,
    };
    if (!vcs_build_action_v1_compile_proof_key(&inputs, out))
        return ZCL_ERR(-1, "proof-key-incomplete");
    return ZCL_OK;
#endif
}

/* What one executed compile proves, each fact re-derived from CAS. */
struct bfpi_facts {
    struct vcs_component_proof_key_v1 key;
    uint8_t input_key[32];
    uint8_t preimage_root[32];
    uint8_t evidence_root[32];
    uint8_t artifact_root[32];
};

static const char *bfpi_observation(
    const char *workspace, const struct db_build_action *action,
    const struct db_build_receipt *receipt,
    struct vcs_build_execution_observation_v1 *obs, uint8_t evidence[32])
{
    uint8_t *wire = NULL, checked[32], action_root[32];
    size_t len = 0;
    if (!zcl_hex_decode_lower(receipt->observation_sha3, evidence, 32) ||
        vcs_object_load_raw(workspace, evidence, &wire, &len) != 0)
        return "observation_absent";
    bool ok = vcs_build_execution_observation_v1_parse(wire, len, obs) &&
              vcs_build_execution_observation_v1_root(obs, checked) &&
              memcmp(checked, evidence, 32) == 0;
    free(wire);
    if (!ok) return "observation_malformed";
    if (!zcl_hex_decode_lower(action->action_id, action_root, 32) ||
        memcmp(obs->action_root, action_root, 32) != 0)
        return "observation_action_mismatch";
    return NULL;
}

/* The key must be the one the worker's checked publish just placed in the
 * workspace: its preimage present at its own root proves both derivations
 * saw the same tool, runtime, and input bytes. */
static const char *bfpi_facts_load(
    struct node_db *ndb, const char *workspace,
    const struct db_build_action *action,
    const struct db_build_receipt *receipt, struct bfpi_facts *facts)
{
    struct db_build_action admitted;
    if (strcmp(action->kind, VCS_BUILD_ACTION_KIND_V1) != 0 ||
        action->task_root_sha3[0] || receipt->exit_status != 0)
        return "not_executed_plain_compile";
    if (strcmp(receipt->action_id, action->action_id) != 0 ||
        !db_build_action_find(ndb, action->action_id, &admitted) ||
        strcmp(admitted.state, "ACCEPTED") != 0)
        return "receipt_not_admitted";
    struct vcs_build_execution_observation_v1 obs;
    const char *refused = bfpi_observation(workspace, action, receipt, &obs,
                                           facts->evidence_root);
    if (refused) return refused;
    if (!build_fabric_proof_compile_key(workspace, action,
                                        obs.observed_input_bytes_root,
                                        &facts->key).ok)
        return "proof_key_unavailable";
    if (!vcs_component_proof_key_derive(&facts->key, facts->input_key) ||
        !vcs_component_proof_key_preimage_root(&facts->key,
                                               facts->preimage_root))
        return "proof_key_incomplete";
    if (!vcs_object_has(workspace, facts->preimage_root))
        return "proof_key_not_published";
    memcpy(facts->artifact_root, obs.output_bytes_root, 32);
    return NULL;
}

static void bfpi_ticket(const struct bfpi_facts *facts,
                        const struct build_fabric_host_accounting *acct,
                        uint64_t now, struct vcs_proof_ticket_v1 *t)
{
    memset(t, 0, sizeof(*t));
    t->verdict = VCS_PROOF_VERDICT_PASS;
    t->basis = VCS_PROOF_BASIS_EXECUTED;
    t->action_class = VCS_PROOF_ACTION_BUILD;
    memcpy(t->input_key, facts->input_key, 32);
    memcpy(t->key_preimage_root, facts->preimage_root, 32);
    memcpy(t->source_root, facts->key.roots[VCS_CPK_SOURCE_CLOSURE], 32);
    memcpy(t->artifact_root, facts->artifact_root, 32);
    memcpy(t->evidence_root, facts->evidence_root, 32);
    t->checks_run = 1;
    t->checks_passed = 1;
    if (acct && acct->measured) {
        int64_t cpu = acct->host_cpu_user_us + acct->host_cpu_system_us;
        t->cpu_us = cpu > 0 ? (uint64_t)cpu : 0;
        t->wall_us = acct->host_wall_us > 0 ? (uint64_t)acct->host_wall_us : 0;
    }
    t->created_unix = now;
}

/* The receiver learns the new ticket through the same verified sync a peer
 * would use: one checkpoint and its one-ticket delta. A refusal leaves it
 * unchanged and names why. */
static void bfpi_receiver_sync(struct build_fabric_proof_context *ctx,
                               const struct db_build_worker_proof_pending *p)
{
    if (!ctx->receiver) return;
    const uint8_t *delta[1] = { p->ticket_wire };
    size_t lens[1] = { sizeof(p->ticket_wire) };
    struct vcs_proof_sync_report report;
    bool synced = vcs_proof_receiver_sync(ctx->receiver, p->checkpoint_wire,
                                          sizeof(p->checkpoint_wire), delta,
                                          lens, 1, &report) &&
                  (report.outcome == VCS_PROOF_SYNC_ADVANCED ||
                   report.outcome == VCS_PROOF_SYNC_CURRENT);
    if (!synced) {
        atomic_store(&ctx->live.receiver_state,
                     BUILD_FABRIC_PROOF_STATE_SYNC_REFUSED);
        LOG_ERROR(BFPI_LOG, "proof receiver refused own ticket: %s",
                  report.reason ? report.reason : "unknown");
    }
    atomic_store(&ctx->live.receiver_tickets,
                 vcs_proof_receiver_ticket_count(ctx->receiver));
}

static bool bfpi_blob_is(struct vcs_package_store *store,
                         const uint8_t *wire, size_t len)
{
    uint8_t root[32], present[VCS_BLOB_MAX_BYTES];
    size_t got = 0;
    return vcs_blob_root(wire, len, root) &&
           vcs_blob_get_from(store, root, present, sizeof(present), &got) ==
               VCS_BLOB_OK &&
           got == len && memcmp(present, wire, len) == 0;
}

/* Make the staged wires durable in the order worker-start recovery can
 * complete from any prefix, then advance the head with the row's own
 * conditional finalize, which moves only from the expected head and only
 * with these exact staged wires. Two CAS writes, two reads and one row
 * update, whatever the history holds. */
static const char *bfpi_publish(struct build_fabric_proof_context *ctx,
                                struct node_db *ndb)
{
    const struct db_build_worker_proof_pending *p = &ctx->staged_row;
    uint8_t root[32], head[32];
    if (BFPC_FAULT(BUILD_FABRIC_PROOF_FAULT_ISSUE_TICKET_PUT) ||
        !vcs_proof_ticket_store_put_no_evict(ctx->store, p->ticket_wire,
                                             sizeof(p->ticket_wire), root))
        return "ticket_put_refused";
    BFPI_POINT(BUILD_FABRIC_PROOF_ISSUE_AFTER_TICKET_PUT);
    if (!vcs_proof_ticket_store_put_no_evict(ctx->store, p->checkpoint_wire,
                                             sizeof(p->checkpoint_wire),
                                             head))
        return "checkpoint_put_refused";
    BFPI_POINT(BUILD_FABRIC_PROOF_ISSUE_AFTER_CHECKPOINT_PUT);
    if (!bfpi_blob_is(ctx->store, p->ticket_wire, sizeof(p->ticket_wire)) ||
        !bfpi_blob_is(ctx->store, p->checkpoint_wire,
                      sizeof(p->checkpoint_wire)))
        return "staged_wires_absent";
    BFPI_POINT(BUILD_FABRIC_PROOF_ISSUE_BEFORE_FINALIZE);
    char next_head[65];
    zcl_hex_encode(head, sizeof(head), next_head);
    if (BFPC_FAULT(BUILD_FABRIC_PROOF_FAULT_ISSUE_FINALIZE) ||
        !db_build_worker_proof_pending_finalize(ndb, p, next_head))
        return "head_finalize_refused";
    ctx->staged = false;
    bfpi_receiver_sync(ctx, p);
    return NULL;
}

static bool bfpi_row(struct build_fabric_proof_context *ctx,
                     struct node_db *ndb, struct db_build_worker *row)
{
    return db_build_worker_find_checked(ndb, ctx->worker_id, row) == 1 &&
           strcmp(row->signer_pubkey, ctx->signer_hex) == 0;
}

static bool bfpi_same_row(const struct db_build_worker_proof_pending *a,
                          const struct db_build_worker_proof_pending *b)
{
    return strcmp(a->worker_id, b->worker_id) == 0 &&
           strcmp(a->signer_pubkey, b->signer_pubkey) == 0 &&
           strcmp(a->expected_head, b->expected_head) == 0 &&
           memcmp(a->ticket_wire, b->ticket_wire,
                  sizeof(a->ticket_wire)) == 0 &&
           memcmp(a->checkpoint_wire, b->checkpoint_wire,
                  sizeof(a->checkpoint_wire)) == 0;
}

/* This issuer's own row already finalized: the durable head is exactly its
 * staged checkpoint. */
static bool bfpi_staged_is_head(struct build_fabric_proof_context *ctx,
                                struct node_db *ndb)
{
    struct db_build_worker row;
    uint8_t head[32];
    char head_hex[65];
    if (!bfpi_row(ctx, ndb, &row) ||
        !vcs_blob_root(ctx->staged_row.checkpoint_wire,
                       sizeof(ctx->staged_row.checkpoint_wire), head))
        return false;
    zcl_hex_encode(head, sizeof(head), head_hex);
    return strcmp(row.proof_checkpoint_head_sha3, head_hex) == 0;
}

/* A row this issuer staged but could not publish is completed before
 * anything else is appended, with the same bounded steps; until then the
 * issuer is exactly one leaf ahead of the durable head. Any other staged
 * row is one only worker start may recover, so *paused asks the caller to
 * stop issuing. */
static const char *bfpi_complete_staged(struct build_fabric_proof_context *ctx,
                                        struct node_db *ndb, bool *paused)
{
    struct db_build_worker_proof_pending found_row;
    int found = db_build_worker_proof_pending_find_checked(
        ndb, ctx->worker_id, &found_row);
    if (found < 0) return "pending_unreadable";
    if (found == 0) {
        if (!ctx->staged) return NULL;
        *paused = !bfpi_staged_is_head(ctx, ndb);
        if (*paused) return "staged_row_lost";
        ctx->staged = false;
        bfpi_receiver_sync(ctx, &ctx->staged_row);
        return NULL;
    }
    *paused = !ctx->staged || !bfpi_same_row(&found_row, &ctx->staged_row);
    if (*paused) return "pending_not_this_issuer";
    return bfpi_publish(ctx, ndb);
}

/* The durable head the next leaf must extend, read from its one checkpoint
 * blob: its leaf count and protocol root. */
static const char *bfpi_durable_head(struct build_fabric_proof_context *ctx,
                                     const struct db_build_worker *row,
                                     uint64_t *leaves, uint8_t root[32])
{
    *leaves = 0;
    memset(root, 0, 32);
    if (!row->proof_checkpoint_head_sha3[0]) return NULL;
    uint8_t blob[32], wire[VCS_PROOF_CHECKPOINT_WIRE_BYTES];
    struct vcs_proof_checkpoint_v1 head;
    if (!zcl_hex_decode_lower(row->proof_checkpoint_head_sha3, blob, 32) ||
        !vcs_proof_checkpoint_store_load(ctx->store, blob, ctx->pubkey, wire,
                                         root) ||
        !vcs_proof_checkpoint_decode(wire, sizeof(wire), &head))
        return "durable_head_unreadable";
    *leaves = head.leaf_count;
    return NULL;
}

/* Sign the next leaf and its checkpoint in memory and stage both exact
 * wires in the worker row. The issuer must sit exactly at the durable head
 * and the new checkpoint must chain to it. Once appended, a refusal leaves
 * the issuer ahead of every durable record, so *paused is set. */
static const char *bfpi_append(struct build_fabric_proof_context *ctx,
                               struct node_db *ndb,
                               struct vcs_proof_ticket_v1 *ticket,
                               bool *paused)
{
    struct db_build_worker row;
    uint64_t leaves = 0;
    uint8_t parent[32];
    if (!bfpi_row(ctx, ndb, &row)) return "worker_row_unreadable";
    const char *refused = bfpi_durable_head(ctx, &row, &leaves, parent);
    if (refused) return refused;
    *paused = true;
    if (vcs_proof_issuer_log_count(ctx->issuer) != leaves)
        return "issuer_not_at_durable_head";
    struct db_build_worker_proof_pending *p = &ctx->staged_row;
    memset(p, 0, sizeof(*p));
    struct vcs_proof_checkpoint_v1 cp;
    if (!vcs_proof_issuer_log_append(ctx->issuer, ticket, p->ticket_wire) ||
        !vcs_proof_issuer_log_checkpoint(ctx->issuer, ticket->created_unix,
                                         p->checkpoint_wire))
        return "issuer_append_refused";
    if (!vcs_proof_checkpoint_decode(p->checkpoint_wire,
                                     sizeof(p->checkpoint_wire), &cp) ||
        cp.leaf_count != leaves + 1u ||
        memcmp(cp.prev_checkpoint_root, parent, sizeof(parent)) != 0)
        return "checkpoint_parent_mismatch";
    memcpy(p->worker_id, ctx->worker_id, sizeof(p->worker_id));
    memcpy(p->signer_pubkey, ctx->signer_hex, sizeof(p->signer_pubkey));
    memcpy(p->expected_head, row.proof_checkpoint_head_sha3,
           sizeof(p->expected_head));
    if (BFPC_FAULT(BUILD_FABRIC_PROOF_FAULT_ISSUE_STAGE) ||
        !db_build_worker_proof_pending_stage(ndb, p))
        return "pending_stage_refused";
    ctx->staged = true;
    *paused = false;
    BFPI_POINT(BUILD_FABRIC_PROOF_ISSUE_AFTER_STAGE);
    return NULL;
}

/* Every step is bounded by one leaf: the history behind the durable head
 * is never read here. Replay belongs to worker start alone. */
static const char *bfpi_issue(struct build_fabric_proof_context *ctx,
                              struct node_db *ndb, const char *workspace,
                              const struct db_build_action *action,
                              const struct db_build_receipt *receipt,
                              const struct build_fabric_host_accounting *acct,
                              bool *paused)
{
    if (!ctx->store) return "store_unavailable";
    if (!ctx->issuer) return "issuer_unavailable";
    struct bfpi_facts facts;
    const char *refused = bfpi_facts_load(ndb, workspace, action, receipt,
                                          &facts);
    if (refused) return refused;
    refused = bfpi_complete_staged(ctx, ndb, paused);
    if (refused) return refused;
    uint8_t preimage[VCS_CPK_WIRE_BYTES], root[32];
    if (!vcs_component_proof_key_encode(&facts.key, preimage) ||
        !vcs_proof_ticket_store_put_no_evict(ctx->store, preimage,
                                             sizeof(preimage), root) ||
        memcmp(root, facts.preimage_root, 32) != 0)
        return "key_preimage_put_refused";
    struct vcs_proof_ticket_v1 ticket;
    bfpi_ticket(&facts, acct, (uint64_t)platform_time_wall_unix(), &ticket);
    refused = bfpi_append(ctx, ndb, &ticket, paused);
    return refused ? refused : bfpi_publish(ctx, ndb);
}

struct zcl_result build_fabric_proof_issue_executed(
    struct build_fabric_proof_context *ctx, struct node_db *ndb,
    const char *workspace, const struct db_build_action *action,
    const struct db_build_receipt *receipt,
    const struct build_fabric_host_accounting *accounting)
{
    if (!ctx || !ndb || !workspace || !action || !receipt)
        return ZCL_ERR(-1, "proof issue requires context, action, receipt");
    bool paused = false;
    const char *refused = bfpi_issue(ctx, ndb, workspace, action, receipt,
                                     accounting, &paused);
    if (refused && strcmp(refused, "not_executed_plain_compile") == 0)
        return ZCL_OK;
    if (refused) {
        atomic_fetch_add(&ctx->live.issue_refused, 1);
        atomic_store(&ctx->live.last_issue_refusal, refused);
        if (paused)
            bfpc_issuer_pause(ctx, BUILD_FABRIC_PROOF_STATE_ISSUE_PAUSED);
        LOG_WARN(BFPI_LOG,
                 "schema=zcl.proof_issue.v1 action=%s issued=false "
                 "refusal=%s staged=%d paused=%d", action->action_id,
                 refused, ctx->staged ? 1 : 0, paused ? 1 : 0);
        return ZCL_ERR(-1, "proof ticket not issued: %s", refused);
    }
    atomic_fetch_add(&ctx->live.issued, 1);
    atomic_store(&ctx->live.issuer_leaves,
                 vcs_proof_issuer_log_count(ctx->issuer));
    LOG_INFO(BFPI_LOG,
             "schema=zcl.proof_issue.v1 action=%s issued=true leaves=%llu",
             action->action_id,
             (unsigned long long)vcs_proof_issuer_log_count(ctx->issuer));
    return ZCL_OK;
}
