/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: local task contents with durable confirmation and revision checks. */
#include "command/native_command.h"
#include "models/task_document.h"
#include "services/task_editor.h"
#include "services/task_list.h"
#include "platform/private_directory.h"
#include "platform/time_compat.h"
#include "util/log_macros.h"
#include <stdio.h>
#include <string.h>

static const char *ntd_string(const struct json_value *input, const char *key)
{
    const struct json_value *value = json_get(input, key);
    return value && value->type == JSON_STR ? json_get_str(value) : NULL;
}

static bool ntd_integer(const struct json_value *input, const char *key, uint64_t *out)
{
    const struct json_value *value = json_get(input, key);
    if (!value || value->type != JSON_INT || json_get_int(value) < 0) return false;
    *out = (uint64_t)json_get_int(value);
    return true;
}

static struct zcl_result ntd_open(const struct json_value *input,
    struct package_resident_store *store)
{
    static const char *const keys[] = { "datadir", "app", "action", "title" };
    for (size_t i = 0; i < sizeof(keys)/sizeof(keys[0]); ++i) {
        const struct json_value *value = json_get(input, keys[i]);
        if (value && value->type != JSON_STR)
            return ZCL_ERR(-1, "tasks: %s must be text", keys[i]);
    }
    const char *directory = ntd_string(input, "datadir");
    const char *app = ntd_string(input, "app");
    if (!app) app = "local/tasks";
    if (!directory || directory[0] != '/')
        return ZCL_ERR(-1, "tasks: choose an absolute private data directory");
    char package_directory[4096];
    int n = snprintf(package_directory, sizeof(package_directory), "%s/zcode", directory);
    if (n < 0 || (size_t)n >= sizeof(package_directory))
        return ZCL_ERR(-1, "tasks: data directory is too long");
    if (!platform_private_directory_ensure(directory) ||
        !platform_private_directory_ensure(package_directory))
        return ZCL_ERR(-1, "tasks: private data directory could not be opened");
    return package_resident_store_open_app(store, directory, app);
}

static struct zcl_result ntd_editor(const struct json_value *input,
    struct package_resident_store *store, bool new_task, struct task_document *row)
{
    struct task_editor editor = {0};
    ZCL_CHECK(task_editor_open(&editor, ntd_string(input, "datadir"), store->app));
    if (!new_task && !json_get(input, "task_id")) {
        ZCL_CHECK(task_list_window_run(&editor));
        *row = editor.saved;
        return ZCL_OK;
    }
    uint64_t id = 0;
    if (!new_task) {
        if (json_get(input, "task_id")) {
            if (!ntd_integer(input, "task_id", &id))
                return ZCL_ERR(-1, "tasks: choose a task ID");
        } else if (editor.saved.state.count) id = editor.saved.state.tasks[0].id;
    }
    ZCL_CHECK(task_editor_select(&editor, id));
    struct zcl_result result = task_editor_window_run(&editor);
    if (result.ok) *row = editor.saved;
    return result;
}

static struct zcl_result ntd_change(const struct json_value *input,
    struct package_resident_store *store, struct task_document *row)
{
    const char *action = ntd_string(input, "action");
    if (!action || strcmp(action, "list") == 0) return task_document_read(store, row);
    if (strcmp(action, "open") == 0 || strcmp(action, "new") == 0)
        return ntd_editor(input, store, strcmp(action, "new") == 0, row);
    static const char *const actions[] = { "add", "edit", "complete", "reopen", "delete", "undo" };
    size_t selected = 0;
    while (selected < sizeof(actions)/sizeof(actions[0]) && strcmp(action, actions[selected]) != 0)
        ++selected;
    if (selected == sizeof(actions)/sizeof(actions[0]))
        return ZCL_ERR(-1, "tasks: unknown action");
    uint64_t revision, id = 0;
    if (!ntd_integer(input, "expected_revision", &revision))
        return ZCL_ERR(-1, "tasks: saving requires the revision you edited");
    if (selected != TASK_DOCUMENT_ADD && selected != TASK_DOCUMENT_UNDO &&
        !ntd_integer(input, "task_id", &id))
        return ZCL_ERR(-1, "tasks: choose a task ID");
    return task_document_apply(store, revision, (enum task_document_action)selected,
        id, ntd_string(input, "title"), row);
}

static bool ntd_render(struct json_value *data, const struct task_document *row,
                        int64_t elapsed)
{
    json_set_object(data);
    if (!json_push_kv_str(data, "save_state", "Saved") ||
        !json_push_kv_int(data, "revision", (int64_t)row->state.revision) ||
        !json_push_kv_bool(data, "can_undo", row->can_undo) ||
        !json_push_kv_int(data, "storage_us", elapsed)) return false;
    struct json_value tasks = {0};
    json_set_array(&tasks);
    bool ok = true;
    for (uint32_t i = 0; ok && i < row->state.count; ++i) {
        const struct ta_task *task = &row->state.tasks[i];
        struct json_value item = {0};
        json_set_object(&item);
        ok = json_push_kv_int(&item, "id", (int64_t)task->id) &&
            json_push_kv_str(&item, "title", task->title) &&
            json_push_kv_bool(&item, "done", task->done != 0) && json_push_back(&tasks, &item);
        json_free(&item);
    }
    if (ok) ok = json_push_kv(data, "tasks", &tasks);
    json_free(&tasks);
    return ok;
}

void zcl_native_handle_task_document(const struct zcl_command_request *request,
                                     struct zcl_command_reply *reply)
{
    int64_t began = platform_time_monotonic_us();
    struct package_resident_store store = {0};
    struct task_document row;
    struct zcl_result result = ntd_open(request->input, &store);
    if (result.ok) result = ntd_change(request->input, &store, &row);
    struct zcl_result closed = package_resident_store_close(&store);
    if (result.ok && !closed.ok) result = closed;
    if (result.ok && !ntd_render(&reply->data, &row, platform_time_monotonic_us() - began))
        result = ZCL_ERR(-1, "tasks: contents committed but confirmation allocation failed; reopen to inspect");
    if (!result.ok) {
        LOG_ERROR("app.tasks", "%s", result.message);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
            "TASK_SAVE_FAILED", "save", false, false, result.message, "app.tasks");
    }
}
