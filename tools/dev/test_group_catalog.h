/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Public API for the canonical native test group catalog. */

#ifndef ZCL_TEST_GROUP_CATALOG_H
#define ZCL_TEST_GROUP_CATALOG_H

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ZCL_TEST_GROUP_FULL_MAX 96

enum zcl_test_proof_contract {
    ZCL_TEST_PROOF_NONE = 0,
    ZCL_TEST_PROOF_STRESS,
    ZCL_TEST_PROOF_EVENT_LOG_KILL9,
    ZCL_TEST_PROOF_EVENT_LOG_BENCH,
    ZCL_TEST_PROOF_GOLDEN_TIMING,
};

/* Canonical registry order, shared with test_parallel's dispatch table. */
size_t zcl_test_group_catalog_count(void);
const char *zcl_test_group_catalog_at(size_t index);
bool zcl_test_group_catalog_contains(const char *full_id);

/* True only for exact catalog groups whose wall-clock assertions must run
 * before the worker pool starts. Repository-exclusive lint groups remain a
 * separate runner policy. */
bool zcl_test_group_requires_exclusive_run(const char *full_id);

/* The line the runner prints, whole and at once, when its run-alone pass has
 * ended and before its worker pool starts. It is printed on every run, even
 * one that selects no exclusive group. The proof worker waits for it before
 * it starts lint, so lint never competes with a run-alone group. */
#define ZCL_TEST_EXCLUSIVE_PASS_DONE "test_parallel: exclusive pass done"

/* Return the one bounded opt-in contract associated with an exact group.
 * NONE is the normal case.  The catalog validates that every declared row is
 * registered and unique before a runner may activate these contracts. */
enum zcl_test_proof_contract
zcl_test_group_proof_contract(const char *full_id);
/* Resolve the exact environment assignment used to activate a proof
 * contract. NONE is valid and returns NULL name/value; unknown values fail. */
bool zcl_test_proof_contract_environment(
    enum zcl_test_proof_contract contract,
    const char **env_name, const char **env_value);
bool zcl_test_group_proof_contracts_valid(void);

/* True only for a mechanically audited test translation-unit proof leaf. */
bool zcl_test_group_source_is_semantic_leaf(const char *path);

/* Resolve a full or legacy prefixless ID to exactly one canonical full ID.
 * Substrings are never accepted. */
bool zcl_test_group_resolve_exact(
    const char *id, char out[ZCL_TEST_GROUP_FULL_MAX]);

/* True when `full_id` belongs to the validated plan ID. A canonical full
 * test or spec plan ID selects only itself; a legacy prefixless ID preserves
 * its substring union plus declared semantic families. The exact primary must
 * exist or this returns false. */
bool zcl_test_group_plan_selects(const char *plan_id, const char *full_id);

/* Visitor for one expanded execution-set member. Return false to abort the
 * walk; the expansion then reports failure so a caller that ran out of room
 * refuses instead of silently running a narrower set. */
typedef bool (*zcl_test_group_visit_fn)(const char *full_id, void *ctx);

/* Umbrella groups (tools/dev/test_group_umbrellas.def). An umbrella is a
 * registered group whose sub-suites are split across registered shard
 * groups. Named exactly it runs whole; inside an expanded set that already
 * carries every one of its shards it is subsumed, and only the shards run. */
typedef bool (*zcl_test_group_selected_fn)(const char *full_id, void *ctx);

bool zcl_test_group_is_umbrella(const char *full_id);
/* True when `full_id` is a registered shard of the registered `umbrella`. */
bool zcl_test_group_is_umbrella_shard(const char *umbrella,
                                      const char *full_id);
/* Registered shards of `umbrella`; 0 when it is not an umbrella. */
size_t zcl_test_group_umbrella_shard_count(const char *umbrella);
/* True only when `full_id` is an umbrella with at least one registered shard
 * and `selected` answers true for every one of them: the set already runs
 * the umbrella's whole body, so the umbrella itself need not run. */
bool zcl_test_group_umbrella_subsumed(const char *full_id,
                                      zcl_test_group_selected_fn selected,
                                      void *ctx);
/* Every umbrella is registered, unique, not its own shard, has two or more
 * registered shards, and no shard is itself an umbrella. */
bool zcl_test_group_umbrellas_valid(void);

/* Expand ONE plan token to the execution set it stands for, in canonical
 * registry order: the exact primary first, then every catalog group the
 * token's DECLARED proof family selects. An umbrella primary whose shards the
 * family carries is subsumed and not visited: the shards are its body. Declared families only — a bare
 * substring would let a short token such as "net" drag in every group whose
 * name merely contains it, a selection nobody wrote down. A token with no
 * exact primary refuses exactly as zcl_test_group_resolve_exact() refuses,
 * so an unknown token still fails closed. `visit` may be NULL to ask only
 * whether the token expands at all, which is what an admission check needs.
 *
 * This is the ONE expansion both the proof selector (tools/dev/dev_proof.c)
 * and the plan builder (tools/dev/devloop_plan.c) call, so the set a plan
 * admits and the set the proof runs cannot drift apart. */
bool zcl_test_group_family_expand(const char *plan_id,
                                  zcl_test_group_visit_fn visit, void *ctx);

/* Expand plan IDs to a deterministic, deduplicated exact execution set in
 * canonical registry order, leaving out any umbrella the set subsumes.
 * Returns the total selected count. When total is
 * greater than cap, the first cap rows are retained and *truncated is true. A
 * missing/ambiguous primary fails closed and returns SIZE_MAX. */
size_t zcl_test_group_expand_plan(
    const char *const *plan_ids, size_t plan_count,
    char (*out)[ZCL_TEST_GROUP_FULL_MAX], size_t cap, bool *truncated);

/* Integration-only groups remain in the complete expansion above but are
 * excluded from the bounded save-cycle expansion below. The predicate accepts
 * exact canonical IDs only. */
bool zcl_test_group_is_integration_only(const char *full_id);
bool zcl_test_group_integration_policy_valid(void);
size_t zcl_test_group_expand_plan_immediate(
    const char *const *plan_ids, size_t plan_count,
    char (*out)[ZCL_TEST_GROUP_FULL_MAX], size_t cap, bool *truncated);

#ifdef __cplusplus
}
#endif

#endif /* ZCL_TEST_GROUP_CATALOG_H */
