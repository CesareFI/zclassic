/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: shared declarations of the check-accel-oracle-pinned family (the
 * gate body and its selftest).
 */
#ifndef GATE_ACCEL_ORACLE_PINNED_PRIV_H
#define GATE_ACCEL_ORACLE_PINNED_PRIV_H

/* Registry and catalog locations and the anti-hollow scan floors. The
 * shipped gate uses the tree-sized floors; the selftest uses a tiny
 * synthetic tree and so smaller ones. */
struct aop_cfg {
    const char *registry;
    const char *catalog;
    int hdr_floor;
    int work_floor;
    int closure_floor;
    int isa_floor;
    int rows_floor;
};

/* Runs the gate against the working directory; returns 0, 1 or 2. */
int aop_run_cfg(const struct aop_cfg *cfg);

#endif
