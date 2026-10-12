/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Late-body reconciliation helpers for tip_finalize_stage.c. */

#ifndef ZCL_JOBS_TIP_FINALIZE_VISIBLE_BODY_H
#define ZCL_JOBS_TIP_FINALIZE_VISIBLE_BODY_H

#include <stdbool.h>
#include <stdint.h>

struct block_index;
struct main_state;
struct sqlite3;
struct stage;
struct uint256;

const char *tip_finalize_precondition_block_reason(
    const struct block_index *bi);
bool tip_finalize_reconcile_visible_cursor_body(
    struct sqlite3 *db, struct stage *stage, struct main_state *ms);
void tip_finalize_visible_body_reset(void);

/* Stamp the one-shot reconcile dedup pair from OUTSIDE the visible-body
 * pass. A successful tip_finalize_run_post_finalize already ran every
 * effect the late-visible reconcile would replay for this exact
 * (height, hash); stamping here keeps the next visible-body check a no-op
 * instead of a second identical reconcile. The body-unreadable skip path
 * must NOT call this, so a late-arriving body stays eligible for retry. */
void tip_finalize_visible_body_note_reconciled(int32_t height,
                                               const struct uint256 *hash);

#endif /* ZCL_JOBS_TIP_FINALIZE_VISIBLE_BODY_H */
