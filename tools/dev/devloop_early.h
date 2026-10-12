/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Early feedback stage of the resident restart proof: the facts-narrowed groups run on the new candidate bytes before the full plan, reported as feedback and never as proof. */
#ifndef ZCL_TOOLS_DEV_DEVLOOP_EARLY_H
#define ZCL_TOOLS_DEV_DEVLOOP_EARLY_H

#include "devloop.h"
#include "devloop_early_skip.h"

struct json_value;

/* The early stage answers one question quickly: do the tests the semantic
 * facts name pass on the bytes just compiled? It is FEEDBACK ONLY.
 *
 *   - It runs only after the full plan was admitted and selected, on the
 *     same candidate the full plan then runs, and it changes nothing the
 *     full plan selects, runs, caches or reports: its runner gets
 *     --no-cache, its counts never enter the proof receipt, and its
 *     failures never enter the failure-first priority store.
 *   - Its receipt always says feedback_only and proof_admissible false.
 *   - A red early stage is reported at once on stderr; the full plan still
 *     runs exactly as it would have without the stage.
 *   - Without usable facts it is skipped and says why. It never guesses a
 *     narrower set: missing, stale or non-narrowing evidence skips it.
 *   - Within the selection, a group whose input closure is unchanged since
 *     its last early PASS is not re-executed (devloop_early_skip.h); every
 *     group it cannot vouch for runs. When every selected group is
 *     skipped that way the stage is skipped as closure_unchanged. */

#define ZCL_DEVLOOP_EARLY_SCHEMA "zcl.dev_early_feedback.v1"
/* Repo-relative facts directory the resident restart path reads
 * (<file>.before.zsm, <file>.after.zsm and <file>.before per changed .c,
 * as dev.change.plan "facts" reads them). Unset: the stage is skipped. */
#define ZCL_DEVLOOP_EARLY_FACTS_ENV "ZCL_DEVLOOP_FACTS_DIR"
#define ZCL_DEVLOOP_EARLY_GROUP_MAX 32

/* A facts plan the early stage may run. `ready` only when the facts
 * evidence narrowed the plan for exactly these sources. */
struct zcl_devloop_early_plan {
    bool ready;
    const char *skip_reason; /* literal; "" when ready */
    char detail[192];
    char facts_dir[ZCL_DEVLOOP_PATH_MAX];
    /* Monotonic time of the edit the stage answers (0: unknown; the stage
     * then measures from the start of the restart proof). */
    int64_t origin_us;
    int64_t plan_us;
    struct zcl_devloop_plan plan;
};

struct zcl_devloop_early_receipt {
    const char *status; /* "skipped", "green", "red" or "cancelled" */
    const char *reason; /* literal; "" when green */
    char detail[256];
    char facts_dir[ZCL_DEVLOOP_PATH_MAX];
    char groups[4096];
    char groups_sha256[65];
    char artifact_sha256[65];
    uint32_t group_count; /* selected */
    uint32_t run_count;   /* selected and handed to the runner */
    uint32_t groups_ran;
    uint32_t groups_cached;
    uint32_t groups_failed;
    uint32_t self_skips;
    int exit_code;
    bool origin_is_edit;
    int64_t origin_us;
    int64_t facts_plan_us;
    /* origin -> the early runner's start, and the runner's wall time. */
    int64_t first_exec_us;
    int64_t wall_us;
    /* The same measures for the full plan that followed (0: it never ran). */
    int64_t full_first_exec_us;
    int64_t full_wall_us;
    /* Which selected groups ran, which were skipped as closure-unchanged,
     * and why. */
    struct zcl_devloop_early_skip skip;
};

/* Resolve `facts_dir` (repo-relative, confined) into a narrowed plan for
 * `sources` through the facts consumer. Always fills `out`; false only for
 * invalid arguments. A plan that did not narrow is not ready and names why
 * (facts_dir_unset, facts_dir_invalid, facts_dir_missing,
 * facts_evidence_missing, facts_stale, facts_not_narrowed,
 * facts_consume_failed, out_of_memory). */
bool zcl_devloop_early_plan_facts(const char *root,
                                  const char *const *sources, size_t n,
                                  const char *facts_dir, int64_t origin_us,
                                  struct zcl_devloop_early_plan *out);

/* The facts plan of the resident restart path: the directory named by
 * ZCL_DEVLOOP_EARLY_FACTS_ENV, measured from the watcher's edit time when
 * one is known. zcl_malloc'd; NULL only when out of memory. */
struct zcl_devloop_early_plan *zcl_devloop_early_plan_resident(
    const char *root, const char *const *sources, size_t n);

/* The watcher records the monotonic time it first saw the edit of the
 * epoch it is about to restart (0 clears it). */
void zcl_devloop_early_note_edit(int64_t seen_us);
int64_t zcl_devloop_early_edit_seen_us(void);

/* A skipped receipt naming `reason`. */
void zcl_devloop_early_skip(struct zcl_devloop_early_receipt *r,
                            const char *reason, const char *detail);

/* Run the stage on `artifact`: the plan's non-integration groups, unless
 * they are empty, unbounded, universal or exactly `full_groups`. Fills `r`;
 * never touches the proof receipt. */
void zcl_devloop_early_run(const char *root, const char *artifact,
                           const char *artifact_sha256,
                           const struct zcl_devloop_early_plan *plan,
                           const char *full_groups, int64_t fallback_origin_us,
                           struct zcl_devloop_early_receipt *r);

/* The same stage with closure-unchanged skipping keyed to `tc`, what the
 * candidate was built from. zcl_devloop_early_run() is this with a NULL
 * `tc`: an unknown identity, so every selected group runs and nothing is
 * recorded. */
void zcl_devloop_early_run_keyed(const char *root, const char *artifact,
                                 const char *artifact_sha256,
                                 const struct zcl_devloop_early_plan *plan,
                                 const char *full_groups,
                                 int64_t fallback_origin_us,
                                 const struct zcl_devloop_early_toolchain *tc,
                                 struct zcl_devloop_early_receipt *r);

/* Push the "early_feedback" object onto `doc`. */
void zcl_devloop_early_json(const struct zcl_devloop_early_receipt *r,
                            struct json_value *doc);

/* zcl_devloop_restart_prove() with the early stage: `early_plan` (NULL: the
 * stage is skipped as facts_dir_unset) runs on the test candidate before
 * the full plan, into `early`. Every proof output is what
 * zcl_devloop_restart_prove() gives for the same inputs. */
bool zcl_devloop_restart_prove_early(
    const char *repo_root, const char *const *source_tus, size_t source_count,
    const struct zcl_devloop_plan *proof_plan,
    const struct zcl_devloop_early_plan *early_plan,
    struct zcl_devloop_restart_proof_receipt *receipt,
    struct zcl_devloop_early_receipt *early,
    struct zcl_devloop_process_result *process, char *why, size_t why_len);

#endif /* ZCL_TOOLS_DEV_DEVLOOP_EARLY_H */
