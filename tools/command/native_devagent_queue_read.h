/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: a read-only view of the dev agent queue rows for projections that
 * hold no state of their own (fleet.mission.board). The reader resolves the
 * existing state root only: it creates no directory, takes no lock and
 * writes nothing. A missing root or queue file is an empty queue. */

#ifndef ZCL_NATIVE_DEVAGENT_QUEUE_READ_H
#define ZCL_NATIVE_DEVAGENT_QUEUE_READ_H

#include <stdbool.h>
#include <stddef.h>

struct zcl_dvq_row_view {
    long long seq;
    long long attempt;
    long long started; /* unix seconds the row went running, 0 unknown */
    char ts[64];
    char name[80];
    char kind[16];
    char engine[40];
    char state[24];
};

/* Fills *rows (caller frees; NULL when empty) in file order. A line that
 * does not parse is skipped and counted in *skipped (may be NULL). Returns
 * false only when the queue file exists but cannot be read within budget. */
bool zcl_devagent_queue_rows_read(struct zcl_dvq_row_view **rows, size_t *n,
                                  size_t *skipped);

#endif
