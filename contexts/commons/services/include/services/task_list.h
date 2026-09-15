/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: task-list selection and actions over the durable editor owner. */
#ifndef ZCL_SERVICES_TASK_LIST_H
#define ZCL_SERVICES_TASK_LIST_H
#include "services/task_editor.h"
enum { TASK_LIST_ROWS = 8, TASK_LIST_TOP = 184, TASK_LIST_ROW_HEIGHT = 45 };
struct task_list {
    struct task_editor *editor;
    uint32_t selected, first, focus;
    uint64_t selected_id;
    bool menu, repaint, closing, open_editor, new_task;
    char notice[128];
};
void task_list_init(struct task_list *list, struct task_editor *editor);
void task_list_refresh(struct task_list *list);
struct zcl_result task_list_action(struct task_list *list, uint32_t action);
struct zcl_result task_list_poll(struct task_list *list);
bool task_list_input(void *context, const struct zcl_present_input_v1 *input,
                     uint32_t *focus, uint32_t *action);
struct zcl_result task_list_model(const struct task_list *list,
                                 struct zcl_present_model_v1 *model);
struct zcl_result task_list_window_run(struct task_editor *editor);
#endif
