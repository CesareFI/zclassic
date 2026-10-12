/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Replay exact staged proof wires after an interrupted CAS transfer. */

#include "services/build_fabric_proof_recovery.h"

#include "base/hex.h"
#include "base/log_macros.h"
#include "base/safe_alloc.h"
#include "models/build_fabric.h"
#include "vcs/blob_store.h"
#include "vcs/package_manifest.h"
#include "vcs/package_store.h"
#include "vcs/proof_reuse.h"

#include <stdlib.h>
#include <string.h>

/* Worker-start recovery re-derives its catalog budget at most this many
 * times when the catalog moves underneath one attempt. */
#define BFPR_RECOVER_ATTEMPTS 4u
/* The staged ticket and checkpoint replay may itself add to the catalog. */
#define BFPR_RECOVER_TRANSFER_ROWS 2u

#ifdef ZCL_TESTING
static void (*bfpr_before_finalize_hook)(void *);
static void *bfpr_before_finalize_context;
void build_fabric_proof_test_before_finalize(void (*hook)(void *),
                                              void *context)
{
    bfpr_before_finalize_hook = hook;
    bfpr_before_finalize_context = context;
}
static void (*bfpr_before_history_pin_hook)(void *);
static void *bfpr_before_history_pin_context;
void build_fabric_proof_test_before_history_pin(void (*hook)(void *),
                                                void *context)
{
    bfpr_before_history_pin_hook = hook;
    bfpr_before_history_pin_context = context;
}

/* One-shot: fire once, after the history walk and before its first pin. */
static void bfpr_fire_before_history_pin(void)
{
    void (*hook)(void *) = bfpr_before_history_pin_hook;
    void *context = bfpr_before_history_pin_context;
    bfpr_before_history_pin_hook = NULL;
    bfpr_before_history_pin_context = NULL;
    if (hook) hook(context);
}
#endif

static bool bfpr_unsettled(enum vcs_package_store_page_result result)
{
    return result == VCS_PACKAGE_STORE_PAGE_STALE ||
           result == VCS_PACKAGE_STORE_PAGE_INCOMPLETE;
}

/* This handle no longer sees the catalog it walked: another writer moved
 * it. The store reports a pin refused for that reason as an I/O refusal. */
static bool bfpr_catalog_unsettled(struct vcs_package_store *store)
{
    size_t rows = 0;
    uint64_t generation = 0;
    return bfpr_unsettled(
        vcs_package_store_catalog_rows(store, &rows, &generation));
}

/* *moved reports a walk the catalog changed under (stale or incomplete). */
static bool bfpr_catalog_roots(struct vcs_package_store *store,
                               size_t max_rows, uint8_t (**roots)[32],
                               size_t *count, bool *moved)
{
    *roots = NULL;
    *count = 0;
    *moved = false;
    if (!max_rows || max_rows > SIZE_MAX / sizeof(**roots))
        LOG_RETURN(false, "build_fabric", "invalid proof catalog row budget");
    uint8_t (*all)[32] = zcl_malloc(max_rows * sizeof(*all),
                                   "proof catalog roots");
    if (!all)
        LOG_RETURN(false, "build_fabric", "allocate proof catalog roots");
    struct vcs_package_store_summary page_rows[VCS_PACKAGE_STORE_PAGE_MAX];
    struct vcs_package_store_page page;
    uint8_t cursor[32];
    uint64_t generation = 0;
    bool resume = false;
    bool complete = false;
    while (!complete) {
        size_t remaining = max_rows - *count;
        if (!remaining) break;
        size_t limit = remaining < VCS_PACKAGE_STORE_PAGE_MAX
                         ? remaining : VCS_PACKAGE_STORE_PAGE_MAX;
        enum vcs_package_store_page_result result =
            vcs_package_store_page_summaries(
                store, resume ? cursor : NULL, limit,
                resume ? generation : 0, page_rows, &page);
        *moved = bfpr_unsettled(result);
        if (result != VCS_PACKAGE_STORE_PAGE_OK || page.count > remaining ||
            (page.has_more && page.count == 0)) break;
        generation = page.generation;
        for (size_t i = 0; i < page.count; i++)
            memcpy(all[*count + i], page_rows[i].root, 32);
        *count += page.count;
        memcpy(cursor, page.next_root, sizeof(cursor));
        resume = true;
        complete = !page.has_more;
    }
    if (!complete) {
        free(all);
        *count = 0;
        LOG_RETURN(false, "build_fabric", "proof catalog scan incomplete");
    }
    *roots = all;
    return true;
}

static bool bfpr_issuer_wire(const uint8_t *wire, size_t len,
                             const uint8_t issuer[32])
{
    if (len == VCS_PROOF_TICKET_WIRE_BYTES) {
        struct vcs_proof_ticket_v1 ticket;
        return vcs_proof_ticket_decode(wire, len, &ticket) &&
               vcs_proof_ticket_signature_valid(&ticket) &&
               memcmp(ticket.producer_pubkey, issuer, 32) == 0;
    }
    if (len == VCS_PROOF_CHECKPOINT_WIRE_BYTES) {
        struct vcs_proof_checkpoint_v1 checkpoint;
        return vcs_proof_checkpoint_decode(wire, len, &checkpoint) &&
               vcs_proof_checkpoint_signature_valid(&checkpoint) &&
               memcmp(checkpoint.issuer_pubkey, issuer, 32) == 0;
    }
    return false;
}

/* *moved: the catalog changed under the walk, or a listed package vanished
 * before it could be read or pinned. A retry may then succeed. */
static bool bfpr_pin_issuer_history(struct vcs_package_store *store,
                                    const uint8_t issuer[32],
                                    size_t max_catalog_rows,
                                    uint8_t (**hashes_out)[32],
                                    size_t *hash_count_out, bool *moved)
{
    *hashes_out = NULL;
    *hash_count_out = 0;
    uint8_t (*roots)[32] = NULL;
    size_t count = 0;
    if (!bfpr_catalog_roots(store, max_catalog_rows, &roots, &count, moved))
        LOG_RETURN(false, "build_fabric", "pin issuer catalog unavailable");
    bool ok = true;
    for (size_t i = 0; ok && i < count; i++) {
        uint8_t wire[VCS_BLOB_MAX_BYTES + 1u];
        size_t len = 0;
        enum vcs_blob_result got = vcs_blob_get_from(
            store, roots[i], wire, sizeof(wire), &len);
        if (got == VCS_BLOB_ERR_SHAPE || got == VCS_BLOB_ERR_CAPACITY)
            continue;
        if (got != VCS_BLOB_OK) {
            *moved = got == VCS_BLOB_ERR_ABSENT;
            ok = false;
            break;
        }
        if (!bfpr_issuer_wire(wire, len, issuer)) continue;
#ifdef ZCL_TESTING
        bfpr_fire_before_history_pin();
#endif
        enum vcs_package_store_result pinned =
            vcs_package_store_pin(store, roots[i], true);
        *moved = pinned == VCS_PACKAGE_STORE_ERR_UNKNOWN_PACKAGE ||
                 (pinned == VCS_PACKAGE_STORE_ERR_IO &&
                  bfpr_catalog_unsettled(store));
        if (pinned != VCS_PACKAGE_STORE_OK ||
            !vcs_package_chunk_hash(wire, len, roots[*hash_count_out]))
            ok = false;
        else
            (*hash_count_out)++;
    }
    if (ok) *hashes_out = roots;
    else {
        free(roots);
        *hash_count_out = 0;
    }
    return ok;
}

static struct zcl_result bfpr_pin_history(struct vcs_package_store *store,
                                          const uint8_t issuer[32],
                                          size_t max_catalog_rows,
                                          uint8_t (**hashes_out)[32],
                                          size_t *hash_count_out)
{
    bool moved = false;
    if (bfpr_pin_issuer_history(store, issuer, max_catalog_rows, hashes_out,
                                hash_count_out, &moved))
        return ZCL_OK;
    if (moved)
        return ZCL_ERR(BUILD_FABRIC_PROOF_ERR_CATALOG_CHANGED,
                       "proof-pending-publish-history-catalog-changed");
    return ZCL_ERR(-1, "proof-pending-publish-history-pin-refused");
}

static bool bfpr_signed_pair(
    const struct db_build_worker_proof_pending *pending,
    const uint8_t pubkey[32], struct vcs_proof_ticket_v1 *ticket,
    struct vcs_proof_checkpoint_v1 *checkpoint)
{
    if (!vcs_proof_ticket_decode(pending->ticket_wire,
                                 sizeof(pending->ticket_wire), ticket) ||
        !vcs_proof_ticket_signature_valid(ticket) ||
        !vcs_proof_checkpoint_decode(pending->checkpoint_wire,
                                     sizeof(pending->checkpoint_wire),
                                     checkpoint) ||
        !vcs_proof_checkpoint_signature_valid(checkpoint) ||
        memcmp(ticket->producer_pubkey, pubkey, 32) != 0 ||
        memcmp(checkpoint->issuer_pubkey, pubkey, 32) != 0 ||
        ticket->issuer_seq == UINT64_MAX ||
        checkpoint->leaf_count != ticket->issuer_seq + 1u)
        return false;
    return true;
}

static bool bfpr_parent_matches(struct vcs_package_store *store,
                                const char *expected_head,
                                const uint8_t pubkey[32],
                                const struct vcs_proof_ticket_v1 *ticket,
                                const struct vcs_proof_checkpoint_v1 *cp)
{
    uint8_t parent[32] = {0};
    if (expected_head[0]) {
        uint8_t base_blob[32], base_wire[VCS_PROOF_CHECKPOINT_WIRE_BYTES];
        struct vcs_proof_checkpoint_v1 base;
        if (!zcl_hex_decode_lower(expected_head, base_blob, 32) ||
            !vcs_proof_checkpoint_store_load(store, base_blob, pubkey,
                                              base_wire, parent) ||
            !vcs_proof_checkpoint_decode(base_wire, sizeof(base_wire),
                                          &base) ||
            ticket->issuer_seq != base.leaf_count)
            return false;
    } else if (ticket->issuer_seq != 0) {
        return false;
    }
    return memcmp(cp->prev_checkpoint_root, parent, sizeof(parent)) == 0;
}

enum bfpr_issuer_state {
    BFPR_ISSUER_UNAVAILABLE,
    BFPR_ISSUER_CHANGED,
    BFPR_ISSUER_MATCH,
};

static enum bfpr_issuer_state bfpr_issuer_matches(
    const uint8_t signer_seed[32],
    const struct db_build_worker_proof_pending *pending,
    uint8_t pubkey[32])
{
    struct vcs_proof_issuer_log *identity =
        vcs_proof_issuer_log_new(signer_seed);
    if (!identity) return BFPR_ISSUER_UNAVAILABLE;
    vcs_proof_issuer_log_pubkey(identity, pubkey);
    vcs_proof_issuer_log_free(identity);
    char signer_hex[65];
    zcl_hex_encode(pubkey, 32, signer_hex);
    return strcmp(signer_hex, pending->signer_pubkey) == 0
               ? BFPR_ISSUER_MATCH : BFPR_ISSUER_CHANGED;
}

enum bfpr_transfer_state {
    BFPR_TRANSFER_ROOT_INVALID,
    BFPR_TRANSFER_INCOMPLETE,
    BFPR_TRANSFER_COMPLETE,
};

static enum bfpr_transfer_state bfpr_transfer_complete(
    struct vcs_package_store *store,
    const struct db_build_worker_proof_pending *pending,
    uint8_t expected_head[32])
{
    uint8_t expected_ticket[32];
    if (!vcs_blob_root(pending->ticket_wire, sizeof(pending->ticket_wire),
                       expected_ticket) ||
        !vcs_blob_root(pending->checkpoint_wire,
                       sizeof(pending->checkpoint_wire), expected_head))
        return BFPR_TRANSFER_ROOT_INVALID;
    uint8_t present[VCS_PROOF_TICKET_WIRE_BYTES];
    size_t present_len = 0;
    if (vcs_blob_get_from(store, expected_ticket, present,
                          sizeof(present), &present_len) != VCS_BLOB_OK ||
        present_len != sizeof(pending->ticket_wire) ||
        memcmp(present, pending->ticket_wire, present_len) != 0 ||
        vcs_blob_get_from(store, expected_head, present,
                          sizeof(present), &present_len) != VCS_BLOB_OK ||
        present_len != sizeof(pending->checkpoint_wire) ||
        memcmp(present, pending->checkpoint_wire, present_len) != 0)
        return BFPR_TRANSFER_INCOMPLETE;
    return BFPR_TRANSFER_COMPLETE;
}

/* The pending row carries signed, exact wires. Resume only their immutable
 * CAS transfer; quota refusal leaves the published DB head unchanged. */
static bool bfpr_resume_transfer(
    struct vcs_package_store *store,
    const struct db_build_worker_proof_pending *pending,
    const uint8_t expected_head[32])
{
    uint8_t expected_ticket[32], stored_ticket[32], stored_head[32];
    if (!vcs_blob_root(pending->ticket_wire, sizeof(pending->ticket_wire),
                       expected_ticket) ||
        !vcs_proof_ticket_store_put_no_evict(
            store, pending->ticket_wire, sizeof(pending->ticket_wire),
            stored_ticket) ||
        memcmp(stored_ticket, expected_ticket, 32) != 0 ||
        !vcs_proof_ticket_store_put_no_evict(
            store, pending->checkpoint_wire, sizeof(pending->checkpoint_wire),
            stored_head) ||
        memcmp(stored_head, expected_head, 32) != 0)
        return false;
    return true;
}

static enum bfpr_transfer_state bfpr_transfer_ready(
    struct vcs_package_store *store,
    const struct db_build_worker_proof_pending *pending,
    uint8_t expected_head[32])
{
    enum bfpr_transfer_state state =
        bfpr_transfer_complete(store, pending, expected_head);
    if (state != BFPR_TRANSFER_INCOMPLETE) return state;
    if (!bfpr_resume_transfer(store, pending, expected_head))
        return BFPR_TRANSFER_INCOMPLETE;
    return bfpr_transfer_complete(store, pending, expected_head);
}

static bool bfpr_replay_selects_staged(
    const struct vcs_proof_issuer_log *restored,
    const struct db_build_worker_proof_pending *pending,
    const struct vcs_proof_ticket_v1 *ticket,
    const struct vcs_proof_checkpoint_v1 *checkpoint)
{
    const uint8_t *selected = vcs_proof_issuer_log_ticket(
        restored, ticket->issuer_seq);
    return vcs_proof_issuer_log_count(restored) == checkpoint->leaf_count &&
           selected && memcmp(selected, pending->ticket_wire,
                              sizeof(pending->ticket_wire)) == 0;
}

static void bfpr_clear_outputs(bool *had_pending, char next_head_hex[65])
{
    if (had_pending) *had_pending = false;
    if (next_head_hex) next_head_hex[0] = '\0';
}

static bool bfpr_inputs_valid(struct node_db *ndb, const char *worker_id,
                              const uint8_t signer_seed[32],
                              bool *had_pending, char next_head_hex[65])
{
    return ndb && worker_id && signer_seed && had_pending && next_head_hex;
}

static struct zcl_result bfpr_load_pending(
    struct node_db *ndb, const char *worker_id,
    struct db_build_worker_proof_pending *pending, bool *found_out)
{
    int found = db_build_worker_proof_pending_find_checked(
        ndb, worker_id, pending);
    if (found < 0)
        return ZCL_ERR(-1, "proof-pending-replay-missing-or-corrupt-row");
    *found_out = found > 0;
    return ZCL_OK;
}

static struct zcl_result bfpr_validate_pending(
    struct vcs_package_store *store, const uint8_t signer_seed[32],
    const struct db_build_worker_proof_pending *pending,
    uint8_t expected_head[32], struct vcs_proof_ticket_v1 *ticket,
    struct vcs_proof_checkpoint_v1 *checkpoint)
{
    uint8_t pubkey[32];
    enum bfpr_issuer_state issuer =
        bfpr_issuer_matches(signer_seed, pending, pubkey);
    if (issuer == BFPR_ISSUER_UNAVAILABLE)
        return ZCL_ERR(-1, "proof-pending-replay-issuer-key-unavailable");
    if (issuer != BFPR_ISSUER_MATCH)
        return ZCL_ERR(-1, "proof-pending-replay-signer-changed");
    if (!bfpr_signed_pair(pending, pubkey, ticket, checkpoint) ||
        !bfpr_parent_matches(store, pending->expected_head, pubkey,
                             ticket, checkpoint))
        return ZCL_ERR(-1, "proof-pending-replay-signed-chain-invalid");
    enum bfpr_transfer_state transfer =
        bfpr_transfer_ready(store, pending, expected_head);
    if (transfer == BFPR_TRANSFER_ROOT_INVALID)
        return ZCL_ERR(-1, "proof-pending-replay-root-invalid");
    if (transfer != BFPR_TRANSFER_COMPLETE)
        return ZCL_ERR(-1, "proof-pending-replay-transfer-incomplete");
    return ZCL_OK;
}

struct bfpr_epoch {
    enum vcs_package_store_page_result result;
    uint64_t generation;
};

static struct bfpr_epoch bfpr_epoch_now(struct vcs_package_store *store)
{
    struct bfpr_epoch epoch = {VCS_PACKAGE_STORE_PAGE_INPUT, 0};
    size_t rows = 0;
    epoch.result = vcs_package_store_catalog_rows(store, &rows,
                                                  &epoch.generation);
    return epoch;
}

/* Replay publishes nothing, so any generation change across it came from
 * another writer: a pin, or an add and an evict that leave the row count
 * unchanged. Such a refusal is the typed, retryable one. */
static struct zcl_result bfpr_restore_history(
    struct vcs_package_store *store, const uint8_t signer_seed[32],
    const uint8_t expected_head[32], size_t max_catalog_rows,
    size_t max_tickets, struct vcs_proof_issuer_log **restored,
    uint64_t *generation, uint8_t (**chunk_hashes)[32], size_t *chunk_count)
{
    struct bfpr_epoch before = bfpr_epoch_now(store);
    *restored = vcs_proof_issuer_log_restore_from_store_at_generation(
        signer_seed, store, expected_head, max_catalog_rows, max_tickets,
        generation, chunk_hashes, chunk_count);
    if (*restored) return ZCL_OK;
    struct bfpr_epoch after = bfpr_epoch_now(store);
    if (bfpr_unsettled(before.result) || bfpr_unsettled(after.result) ||
        (before.result == VCS_PACKAGE_STORE_PAGE_OK &&
         after.result == VCS_PACKAGE_STORE_PAGE_OK &&
         before.generation != after.generation))
        return ZCL_ERR(BUILD_FABRIC_PROOF_ERR_CATALOG_CHANGED,
                       "proof-pending-replay-catalog-changed");
    return ZCL_ERR(-1, "proof-pending-replay-incomplete-history");
}

static struct zcl_result bfpr_pending_replay_impl(
    struct node_db *ndb, struct vcs_package_store *store,
    const char *worker_id, const uint8_t signer_seed[32],
    size_t max_catalog_rows, size_t max_tickets,
    bool *had_pending, char next_head_hex[65], uint64_t *generation_out,
    uint8_t (**chunk_hashes_out)[32], size_t *chunk_count_out)
{
    bfpr_clear_outputs(had_pending, next_head_hex);
    if (generation_out) *generation_out = 0;
    if (chunk_hashes_out) *chunk_hashes_out = NULL;
    if (chunk_count_out) *chunk_count_out = 0;
    if (!bfpr_inputs_valid(ndb, worker_id, signer_seed,
                           had_pending, next_head_hex))
        return ZCL_ERR(-1, "proof-pending-replay-invalid-input");
    struct db_build_worker_proof_pending pending;
    bool found = false;
    ZCL_CHECK(bfpr_load_pending(ndb, worker_id, &pending, &found));
    if (!found) return ZCL_OK;
    if (!store || !max_catalog_rows || !max_tickets)
        return ZCL_ERR(-1, "proof-pending-replay-store-or-budget-missing");

    struct vcs_proof_ticket_v1 ticket;
    struct vcs_proof_checkpoint_v1 cp;
    uint8_t expected_head[32];
    ZCL_CHECK(bfpr_validate_pending(store, signer_seed, &pending,
                                    expected_head, &ticket, &cp));

    uint64_t generation = 0;
    uint8_t (*chunk_hashes)[32] = NULL;
    size_t chunk_count = 0;
    struct vcs_proof_issuer_log *restored = NULL;
    ZCL_CHECK(bfpr_restore_history(store, signer_seed, expected_head,
                                   max_catalog_rows, max_tickets, &restored,
                                   &generation, &chunk_hashes, &chunk_count));
    bool exact = bfpr_replay_selects_staged(restored, &pending, &ticket, &cp);
    vcs_proof_issuer_log_free(restored);
    if (!exact) {
        free(chunk_hashes);
        return ZCL_ERR(-1, "proof-pending-replay-ticket-not-selected");
    }
    zcl_hex_encode(expected_head, sizeof(expected_head), next_head_hex);
    *had_pending = true;
    if (generation_out) *generation_out = generation;
    if (chunk_hashes_out && chunk_count_out) {
        *chunk_hashes_out = chunk_hashes;
        *chunk_count_out = chunk_count;
    } else {
        free(chunk_hashes);
    }
    return ZCL_OK;
}

struct zcl_result build_fabric_proof_pending_replay(
    struct node_db *ndb, struct vcs_package_store *store,
    const char *worker_id, const uint8_t signer_seed[32],
    size_t max_catalog_rows, size_t max_tickets,
    bool *had_pending, char next_head_hex[65])
{
    return bfpr_pending_replay_impl(
        ndb, store, worker_id, signer_seed, max_catalog_rows,
        max_tickets, had_pending, next_head_hex, NULL, NULL, NULL);
}

struct bfpr_commit_context {
    struct node_db *ndb;
    const struct db_build_worker_proof_pending *pending;
    const char *next_head;
};

static bool bfpr_finalize_under_store_lock(void *context)
{
    struct bfpr_commit_context *commit = context;
    return db_build_worker_proof_pending_finalize(
        commit->ndb, commit->pending, commit->next_head);
}

static struct zcl_result bfpr_guarded_finalize(
    struct node_db *ndb, struct vcs_package_store *store,
    const struct db_build_worker_proof_pending *pending,
    const char *next_head, size_t max_catalog_rows, uint64_t generation,
    uint8_t (*history_hashes)[32], size_t history_count,
    uint8_t (*chunk_hashes)[32], size_t chunk_count)
{
    if (chunk_count > SIZE_MAX / sizeof(*history_hashes) ||
        history_count > SIZE_MAX / sizeof(*history_hashes) - chunk_count) {
        free(history_hashes);
        free(chunk_hashes);
        return ZCL_ERR(-1, "proof-pending-publish-chunk-budget-overflow");
    }
    uint8_t (*all_hashes)[32] = zcl_realloc(
        history_hashes, (history_count + chunk_count) *
                        sizeof(*history_hashes), "proof chunk guard hashes");
    if (!all_hashes) {
        free(history_hashes);
        free(chunk_hashes);
        return ZCL_ERR(-1, "proof-pending-publish-chunk-guard-allocation");
    }
    memcpy(all_hashes + history_count, chunk_hashes,
           chunk_count * sizeof(*chunk_hashes));
    free(chunk_hashes);
#ifdef ZCL_TESTING
    if (bfpr_before_finalize_hook) {
        void (*hook)(void *) = bfpr_before_finalize_hook;
        void *context = bfpr_before_finalize_context;
        bfpr_before_finalize_hook = NULL;
        bfpr_before_finalize_context = NULL;
        hook(context);
    }
#endif
    struct bfpr_commit_context commit = {ndb, pending, next_head};
    bool committed = false;
    enum vcs_package_store_page_result guard =
        vcs_package_store_commit_if_generation(
            store, generation, max_catalog_rows,
            (const uint8_t (*)[32])all_hashes,
            history_count + chunk_count, bfpr_finalize_under_store_lock,
            &commit, &committed);
    free(all_hashes);
    if (guard == VCS_PACKAGE_STORE_PAGE_STALE)
        return ZCL_ERR(BUILD_FABRIC_PROOF_ERR_CATALOG_CHANGED,
                       "proof-pending-publish-stale-generation");
    if (guard == VCS_PACKAGE_STORE_PAGE_INCOMPLETE)
        return ZCL_ERR(BUILD_FABRIC_PROOF_ERR_CATALOG_CHANGED,
                       "proof-pending-publish-incomplete-catalog");
    if (guard != VCS_PACKAGE_STORE_PAGE_OK)
        return ZCL_ERR(-1, "proof-pending-publish-store-guard-refused");
    if (!committed)
        return ZCL_ERR(-1, "proof-pending-publish-conditional-head-refused");
    return ZCL_OK;
}

struct zcl_result build_fabric_proof_pending_publish(
    struct node_db *ndb, struct vcs_package_store *store,
    const char *worker_id, const uint8_t signer_seed[32],
    size_t max_catalog_rows, size_t max_tickets)
{
    if (!ndb || !store || !worker_id || !signer_seed)
        return ZCL_ERR(-1, "proof-pending-publish-invalid-input");
    struct db_build_worker_proof_pending pending;
    int found = db_build_worker_proof_pending_find_checked(
        ndb, worker_id, &pending);
    if (found < 0)
        return ZCL_ERR(-1, "proof-pending-publish-missing-or-corrupt-row");
    if (found == 0) return ZCL_OK;

    bool had_pending = false;
    char next_head[65];
    ZCL_CHECK(build_fabric_proof_pending_replay(
        ndb, store, worker_id, signer_seed, max_catalog_rows,
        max_tickets, &had_pending, next_head));
    if (!had_pending)
        return ZCL_ERR(-1, "proof-pending-publish-staged-row-changed");

    uint8_t checkpoint_root[32], issuer[32];
    if (!zcl_hex_decode_lower(pending.signer_pubkey, issuer,
                              sizeof(issuer)) ||
        !vcs_blob_root(pending.checkpoint_wire,
                       sizeof(pending.checkpoint_wire), checkpoint_root))
        return ZCL_ERR(-1, "proof-pending-publish-root-invalid");
    char checkpoint_hex[65];
    zcl_hex_encode(checkpoint_root, sizeof(checkpoint_root), checkpoint_hex);
    if (strcmp(checkpoint_hex, next_head) != 0)
        return ZCL_ERR(-1, "proof-pending-publish-head-changed");
    uint8_t (*history_hashes)[32] = NULL;
    size_t history_count = 0;
    ZCL_CHECK(bfpr_pin_history(store, issuer, max_catalog_rows,
                               &history_hashes, &history_count));

    /* Pinning changes store generation. Replay again against the fully
     * pinned issuer closure before the conditional DB publication. */
    had_pending = false;
    uint64_t generation = 0;
    uint8_t (*chunk_hashes)[32] = NULL;
    size_t chunk_count = 0;
    struct zcl_result replay = bfpr_pending_replay_impl(
        ndb, store, worker_id, signer_seed, max_catalog_rows,
        max_tickets, &had_pending, next_head, &generation,
        &chunk_hashes, &chunk_count);
    if (!replay.ok) {
        free(history_hashes);
        return replay;
    }
    if (!had_pending || strcmp(checkpoint_hex, next_head) != 0) {
        free(history_hashes);
        free(chunk_hashes);
        return ZCL_ERR(-1, "proof-pending-publish-replay-changed");
    }
    return bfpr_guarded_finalize(
        ndb, store, &pending, next_head, max_catalog_rows, generation,
        history_hashes, history_count, chunk_hashes, chunk_count);
}

/* Size the catalog this handle will scan, first catching a stale handle up
 * with writes made through other handles. */
static struct zcl_result bfpr_catalog_size(struct vcs_package_store *store,
                                           size_t *rows)
{
    uint64_t generation = 0;
    enum vcs_package_store_page_result sized =
        vcs_package_store_catalog_rows(store, rows, &generation);
    if (sized == VCS_PACKAGE_STORE_PAGE_STALE) {
        if (!vcs_package_store_refresh(store))
            return ZCL_ERR(-1, "proof-pending-recover-store-refresh-refused");
        sized = vcs_package_store_catalog_rows(store, rows, &generation);
    }
    if (sized == VCS_PACKAGE_STORE_PAGE_STALE)
        return ZCL_ERR(BUILD_FABRIC_PROOF_ERR_CATALOG_CHANGED,
                       "proof-pending-recover-catalog-changed-while-sizing");
    if (sized != VCS_PACKAGE_STORE_PAGE_OK)
        return ZCL_ERR(-1, "proof-pending-recover-catalog-size-refused");
    if (*rows > SIZE_MAX - BFPR_RECOVER_TRANSFER_ROWS)
        return ZCL_ERR(-1, "proof-pending-recover-catalog-size-overflow");
    return ZCL_OK;
}

/* One publication at a budget covering the catalog as sized now plus the
 * two staged wires replay may itself transfer into it. */
static struct zcl_result bfpr_recover_once(
    struct node_db *ndb, struct vcs_package_store *store,
    const char *worker_id, const uint8_t signer_seed[32],
    uint64_t leaf_count, bool *catalog_moved)
{
    *catalog_moved = false;
    size_t rows = 0;
    struct zcl_result before = bfpr_catalog_size(store, &rows);
    if (!before.ok) {
        *catalog_moved = before.code == BUILD_FABRIC_PROOF_ERR_CATALOG_CHANGED;
        return before;
    }
    size_t budget = rows + BFPR_RECOVER_TRANSFER_ROWS;
    size_t tickets = leaf_count < budget ? (size_t)leaf_count : budget;
    struct zcl_result published = build_fabric_proof_pending_publish(
        ndb, store, worker_id, signer_seed, budget, tickets);
    if (published.ok) return published;
    size_t after = 0;
    struct zcl_result sized = bfpr_catalog_size(store, &after);
    *catalog_moved =
        published.code == BUILD_FABRIC_PROOF_ERR_CATALOG_CHANGED ||
        sized.code == BUILD_FABRIC_PROOF_ERR_CATALOG_CHANGED ||
        (sized.ok && after > budget);
    if (*catalog_moved)
        LOG_WARN("build_fabric", "proof recovery at %zu catalog rows saw the "
                 "catalog move (now %zu): %s", budget, after,
                 published.message);
    return published;
}

struct zcl_result build_fabric_proof_pending_recover(
    struct node_db *ndb, struct vcs_package_store *store,
    const char *worker_id, const uint8_t signer_seed[32])
{
    if (!ndb || !store || !worker_id || !signer_seed)
        return ZCL_ERR(-1, "proof-pending-recover-invalid-input");
    struct db_build_worker_proof_pending pending;
    int found = db_build_worker_proof_pending_find_checked(
        ndb, worker_id, &pending);
    if (found < 0)
        return ZCL_ERR(-1, "proof-pending-recover-missing-or-corrupt-row");
    if (found == 0) return ZCL_OK;
    struct vcs_proof_checkpoint_v1 staged;
    if (!vcs_proof_checkpoint_decode(pending.checkpoint_wire,
                                     sizeof(pending.checkpoint_wire),
                                     &staged) || staged.leaf_count == 0)
        return ZCL_ERR(-1, "proof-pending-recover-staged-checkpoint-invalid");
    for (unsigned attempt = 0; attempt < BFPR_RECOVER_ATTEMPTS; attempt++) {
        bool moved = false;
        struct zcl_result recovered = bfpr_recover_once(
            ndb, store, worker_id, signer_seed, staged.leaf_count, &moved);
        if (recovered.ok || !moved) return recovered;
    }
    return ZCL_ERR(BUILD_FABRIC_PROOF_ERR_CATALOG_CHANGED,
                   "proof-pending-recover-catalog-changed attempts=%u",
                   BFPR_RECOVER_ATTEMPTS);
}
