/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: the one entry point that drops the state a machine derives from
 * its serialisable state. */
#include "rvmachine_priv.h"

void rvmachine_invalidate_derived(struct rvmachine *m)
{
    if (m == NULL) return;
    machine_sched_reset(m);
    rvemu_invalidate_derived(&m->hart);
}
