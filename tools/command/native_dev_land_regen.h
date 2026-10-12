/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: dev.land regen phase — regenerate the generated-doc artifacts
 *          (capability inventory, executor routing, doc-counts block) in
 *          the landing worktree right after a successful rebase, so a
 *          submission never fails at push time for staleness a train
 *          assembler would otherwise have to fix by hand.
 *
 * Split out of tools/command/native_dev_land.c (which was already at its
 * file-size ceiling) rather than grown inside it. native_dev_land.c owns
 * the queue and rows; this file owns generated-document refresh and the
 * final Make restart-plan and proof-tool preparation before proof
 * admission.
 */
#ifndef ZCL_NATIVE_DEV_LAND_REGEN_H
#define ZCL_NATIVE_DEV_LAND_REGEN_H

#include <stddef.h>
#include <stdbool.h>

/* Prepare the native Make restart plan after all landing inputs are ready.
 * Re-run its FORCE target even when a plan exists: earlier preparation may
 * have changed source metadata. Uses the bounded real Make adapter; false
 * leaves a diagnostic and never accepts a stale file after Make failure. */
bool zcl_dev_land_restart_plan_prepare(const char *wt, char *why,
                                       size_t why_cap);

/* Ensure the sealed proof's generated-docs checker binaries
 * (build/bin/z23-lint, z23-fleet-observe, gen_capability_inventory) exist
 * in the landing worktree: the proof copies them out of this checkout
 * before any dimension builds inside its generation and refuses the proof
 * when one is absent. Runs make only when a member is missing; false
 * leaves a diagnostic naming the exact absent binary or the make
 * failure. */
bool zcl_dev_land_proof_tools_prepare(const char *wt, char *why,
                                      size_t why_cap);

/* Run the regen phase in the already-rebased landing worktree `wt` (HEAD is
 * the row's rebased tip). `base_sha` is the exact main the tip was rebased
 * onto (row->base). When a regenerated artifact changed, the changed
 * closed-table paths -- and nothing else -- are AMENDED into HEAD, keeping
 * its message, author and parents, signed by the same ambient
 * commit.gpgsign configuration as any other landing commit. Only a HEAD
 * that is already reachable from `base_sha` (the rebase dropped every
 * candidate commit) cannot be amended without rewriting published history;
 * that case alone still gets a separate "Regenerate generated docs after
 * <tip subject>" commit, where `tip_sha` (the original submitted commit id,
 * never checked out or moved) supplies the subject.
 *
 * If any regenerated artifact's on-disk identity (inode/size/mtime/ctime)
 * changed -- whether or not the bytes it wrote differ from what git already
 * had, and whether or not a commit followed -- this re-seals
 * build/dev-loop/restart.env (make's DEV_RESTART_PLAN target, which carries
 * a FORCE prerequisite) before returning, so the plan the proof later reads
 * describes the tree as this phase left it rather than as it stood before
 * this phase ran. See native_dev_land_regen.c's dlrg_plan_refresh() for why.
 *
 * Returns 1 on success (whether or not a commit was made — see below), or
 * -1 on a hard failure with a human-actionable `why` (min 128 bytes
 * recommended; longer is truncated, never overflowed).
 *
 * On return, regardless of success/failure sign:
 *   `transcript` (transcript_cap bytes) always holds whatever make/git
 *   output was captured, NUL-terminated, empty string if nothing ran yet
 *   (e.g. the worktree has no Makefile at all — a hermetic test rig, never
 *   a real landing worktree). The caller appends it to the attempt log
 *   exactly like every other phase's output.
 *
 * On success only:
 *   `new_head` (>= 41 bytes) receives HEAD's full commit id AFTER this
 *   call: identical to HEAD on entry when nothing changed, otherwise the
 *   amended tip's id. The caller MUST replace row->local with it: the
 *   pre-amend id no longer names the tree the proof must prove and the
 *   push must publish. */
int zcl_dev_land_regen_phase(const char *wt, const char *base_sha,
                             const char *tip_sha,
                             char *new_head, size_t new_head_cap,
                             char *transcript, size_t transcript_cap,
                             char *why, size_t why_cap);

#endif /* ZCL_NATIVE_DEV_LAND_REGEN_H */
