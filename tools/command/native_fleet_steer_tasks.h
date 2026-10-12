/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: bounded, read-only task projection of existing local authorities. */
#ifndef ZCL_NATIVE_FLEET_STEER_TASKS_H
#define ZCL_NATIVE_FLEET_STEER_TASKS_H
#include "json/json.h"
#define ZCL_FMC_TASK_CAP 32u
#define ZCL_FMC_TASK_FRESH_S 900
struct zcl_fmc_tasks {
    struct json_value rows;
    size_t observed, dropped, malformed;
    bool queue_ok, land_ok;
};
void zcl_fmc_tasks_init(struct zcl_fmc_tasks *view);
void zcl_fmc_tasks_free(struct zcl_fmc_tasks *view);
bool zcl_fmc_tasks_queue(struct zcl_fmc_tasks *view,
    const struct json_value *queue, long long observed, long long now);
bool zcl_fmc_tasks_land(struct zcl_fmc_tasks *view,
    const struct json_value *land, const struct json_value *proof,
    long long observed, long long now);
void zcl_fmc_tasks_emit(const struct zcl_fmc_tasks *view, struct json_value *data);
/* Render only already-classified, already-trimmed rows. Never re-read a source. */
void zcl_fmc_tasks_screen(const struct json_value *data, char *out, size_t cap);
#endif
