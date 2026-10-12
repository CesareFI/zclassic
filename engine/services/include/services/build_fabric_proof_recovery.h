/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Validate and replay an interrupted local proof-head publication. */

#ifndef ZCL_SERVICES_BUILD_FABRIC_PROOF_RECOVERY_H
#define ZCL_SERVICES_BUILD_FABRIC_PROOF_RECOVERY_H

#include "base/result.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct node_db;
struct vcs_package_store;

/* Re-read the exact staged ticket/checkpoint wires, verify the local signer,
 * sequence and checkpoint parent against the still-current worker head, then
 * resume missing exact wires into CAS without evicting another package, and
 * reconstruct the complete issuer log at the proposed next head. A transfer
 * that cannot fit or replay stays pending. On refusal,
 * outputs clear and the worker's durable head/pending bytes are untouched.
 * This does NOT finalize the database head, authorize reuse, or pin objects.
 * The caller must fence the local issuer writer and store mutation across
 * this call and any later conditional head publication. */
struct zcl_result build_fabric_proof_pending_replay(
    struct node_db *ndb, struct vcs_package_store *store,
    const char *worker_id, const uint8_t signer_seed[32],
    size_t max_catalog_rows, size_t max_tickets,
    bool *had_pending, char next_head_hex[65]);

/* Startup-only publication: replay the complete staged history, pin its
 * exact CAS objects, then conditionally advance the durable worker head.
 * Refusal leaves the old head and pending wires in place. */
struct zcl_result build_fabric_proof_pending_publish(
    struct node_db *ndb, struct vcs_package_store *store,
    const char *worker_id, const uint8_t signer_seed[32],
    size_t max_catalog_rows, size_t max_tickets);

/* A publication refused because the package catalog moved underneath it
 * (stale generation, more rows than the derived budget, or a generation
 * change with no new rows, such as a pin or an add and an evict). Nothing
 * was published; the staged row stays pending and a later retry is safe. */
#define BUILD_FABRIC_PROOF_ERR_CATALOG_CHANGED 1101

/* Worker-start recovery of a staged proof publication. Each attempt derives
 * its finite budgets from the store itself: the catalog's current row count
 * (plus the two staged wires replay may transfer) and the staged
 * checkpoint's leaf count, so no catalog size is ever out of reach. When the
 * catalog moves underneath an attempt it re-derives and retries a bounded
 * number of times, then returns BUILD_FABRIC_PROOF_ERR_CATALOG_CHANGED.
 * Any other refusal is returned as is. Refusal publishes nothing. */
struct zcl_result build_fabric_proof_pending_recover(
    struct node_db *ndb, struct vcs_package_store *store,
    const char *worker_id, const uint8_t signer_seed[32]);

#ifdef ZCL_TESTING
/* Inject a second store writer at the final publication boundary. */
void build_fabric_proof_test_before_finalize(void (*hook)(void *),
                                              void *context);
/* Inject a second store writer between the history walk and its first pin
 * (one-shot). */
void build_fabric_proof_test_before_history_pin(void (*hook)(void *),
                                                void *context);
#endif

#endif /* ZCL_SERVICES_BUILD_FABRIC_PROOF_RECOVERY_H */
