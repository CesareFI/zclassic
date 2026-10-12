/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * z23-sem-replay: one replayed commit (step), the reproducibility check
 * (repro) and the aggregate report. */
#ifndef ZCL_SEM_REPLAY_STEP_H
#define ZCL_SEM_REPLAY_STEP_H

#include "sem_replay.h"

struct sr_cfg {
    char repo[SR_PATH];    /* absolute replay worktree */
    char state[SR_PATH];   /* absolute state directory */
    char sensor[SR_PATH];  /* z23-clang-manifest */
    char planner[SR_PATH]; /* z23-dev */
    char devbuild[SR_PATH];
    char self[SR_PATH];
    int jobs;
    int index;
    char commit[64];
};

/* Exit codes of a step. */
enum {
    SR_STEP_OK = 0,
    SR_STEP_FAILED = 2,
    SR_STEP_FALSE_NEGATIVE = 3,
};

int sr_step(const struct sr_cfg *cfg);
int sr_repro(const struct sr_cfg *cfg, const char *label);
/* Compile every TU of the current tree cold with make's argv, time it, and
 * compare its bytes with the incremental object: catalog_cost.tsv. */
int sr_catalog(const struct sr_cfg *cfg);
int sr_report(const struct sr_cfg *cfg);

/* The make build of the test-fast binary at the checked-out tree, with the
 * compiler cache disabled so every recipe compiles. Its link runs the
 * aggregate epoch verification; building the objects alone would leave the
 * epoch marked unverified, and the next make would discard every object. */
bool sr_make_objects(const struct sr_cfg *cfg, const char *log,
                     const struct sr_strv *what_if, struct sr_cost *cost);

#endif /* ZCL_SEM_REPLAY_STEP_H */
