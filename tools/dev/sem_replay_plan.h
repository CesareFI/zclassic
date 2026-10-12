/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * z23-sem-replay plan side: run dev.change.plan without and with the facts
 * directory, page the facts universe, and read the fields the replay
 * compares. */
#ifndef ZCL_SEM_REPLAY_PLAN_H
#define ZCL_SEM_REPLAY_PLAN_H

#include "sem_replay.h"

struct sr_plan {
    bool ok;
    long groups_total;      /* execution_groups_total */
    char selector[32];      /* execution_selector */
    bool closure_universal; /* the whole catalog is in scope */
    struct sr_strv groups;  /* execution_groups (may be abridged) */
    /* the facts object */
    bool has_facts, narrowed;
    char reason[128], detail[512];
    long seeds_total;
    char obl_reason[128];
    long obl_plain, obl_facts;
    bool obl_plain_universal;
    struct sr_strv obl_groups;
    bool uni_applied, uni_complete;
    char uni_reason[128], uni_detail[512];
    long uni_total, uni_affected;
    long next_offset; /* -1 when null */
    struct sr_strv tus_affected; /* sorted after sr_plan_run */
    struct sr_strv tu_rows;      /* "path\taffected\tbroadened\treason" */
    char error[512];
};

/* Plan files in repo. facts is NULL for the plain plan, or the facts
 * directory relative to repo; every universe page is read and merged.
 * raw_prefix names where each page's JSON is saved (NULL: not saved).
 * out is initialized on entry. On refusal return false, set out->ok false
 * and out->error, and retain completed TU rows only. */
bool sr_plan_run(const char *planner, const char *repo,
                 const struct sr_strv *files, const char *facts,
                 const char *raw_prefix, struct sr_plan *out);
void sr_plan_free(struct sr_plan *p);

#endif /* ZCL_SEM_REPLAY_PLAN_H */
