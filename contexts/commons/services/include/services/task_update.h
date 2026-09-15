/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: permissioned task program previews over host-owned durable data. */
#ifndef ZCL_SERVICES_TASK_UPDATE_H
#define ZCL_SERVICES_TASK_UPDATE_H
#include "models/task_document.h"
struct task_update_job;
enum task_update_phase { TASK_UPDATE_IDLE, TASK_UPDATE_RUNNING, TASK_UPDATE_READY,
    TASK_UPDATE_KEEPING, TASK_UPDATE_KEPT, TASK_UPDATE_CANCELLED, TASK_UPDATE_FAILED };
struct task_update {
    char directory[4096], app[256], verifier[4096];
    struct package_resident_identity candidate;
    struct task_update_job *pending, *ready;
    enum task_update_phase phase;
    char preview[4096], active[4096], message[256];
    uint64_t active_revision;
    bool active_valid;
    int64_t elapsed_us;
};
struct zcl_result task_update_open(struct task_update *update, const char *directory,
    const char *app, const char *verifier, const struct package_resident_identity *candidate);
/* Permission belongs to this exact user action. No execution when false. */
struct zcl_result task_update_try(struct task_update *update, bool permission, bool go_back);
struct zcl_result task_update_keep(struct task_update *update);
void task_update_cancel(struct task_update *update);
struct zcl_result task_update_poll(struct task_update *update, bool *changed);
struct zcl_result task_update_finish(struct task_update *update);
/* Previously kept program: refresh its view from current host-owned data. */
struct zcl_result task_update_refresh(struct task_update *update);
#endif
