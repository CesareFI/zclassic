/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: prove task contents survive restart, undo and failed commits. */
#include "test/test_core.h"
#include "models/task_document.h"
#include "services/task_editor.h"
#include "services/task_list.h"
#include "platform/time_compat.h"
#include "platform/os_proc.h"
#include "util/thread_registry.h"
#include "presentation/model_render.h"
#include "../../../contexts/explorer/modules/presentation/src/presentation_form_internal.h"
#include "../../../contexts/explorer/modules/presentation/src/presentation_focus_internal.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if !defined(_WIN32)
#include <sys/stat.h>
#include <unistd.h>

#define TD_CHECK(label, expression) do { \
    bool ok = (expression); \
    printf("task_document: %s... %s\n", label, ok ? "OK" : "FAIL"); \
    if (!ok) ++failures; \
} while (0)

static int td_refuse_commit(void *context) { (void)context; return 1; }

static int td_actions(struct package_resident_store *store, struct task_document *row)
{
    int failures = 0;
    TD_CHECK("empty document", task_document_read(store, row).ok && row->state.count == 0);
    TD_CHECK("add durable task", task_document_apply(store, 0, TASK_DOCUMENT_ADD, 0,
        "Buy milk", row).ok && row->state.count == 1);
    uint64_t id = row->state.tasks[0].id;
    TD_CHECK("edit exact contents", task_document_apply(store, 1, TASK_DOCUMENT_EDIT, id,
        "Buy oat milk", row).ok && strcmp(row->state.tasks[0].title, "Buy oat milk") == 0);
    TD_CHECK("stale writer cannot overwrite", !task_document_apply(store, 1,
        TASK_DOCUMENT_EDIT, id, "stale", row).ok && row->state.revision == 2);
    TD_CHECK("complete", task_document_apply(store, 2, TASK_DOCUMENT_COMPLETE, id,
        NULL, row).ok && row->state.tasks[0].done == 1);
    TD_CHECK("undo completion", task_document_apply(store, 3, TASK_DOCUMENT_UNDO, 0,
        NULL, row).ok && row->state.tasks[0].done == 0);
    TD_CHECK("delete", task_document_apply(store, 4, TASK_DOCUMENT_DELETE, id,
        NULL, row).ok && row->state.count == 0);
    return failures;
}

static int td_restart(struct package_resident_store *store,
    const char *directory, struct task_document *row)
{
    int failures = 0;
    TD_CHECK("close database", package_resident_store_close(store).ok);
    TD_CHECK("reopen same app", package_resident_store_open_app(store, directory, "local/tasks").ok);
    TD_CHECK("deletion and undo survive restart", task_document_read(store, row).ok &&
        row->state.count == 0 && row->can_undo);
    TD_CHECK("undo restores exact edited contents", task_document_apply(store, 5,
        TASK_DOCUMENT_UNDO, 0, NULL, row).ok && row->state.count == 1 &&
        strcmp(row->state.tasks[0].title, "Buy oat milk") == 0 && row->state.revision == 6);
    TD_CHECK("consumed undo refuses", !task_document_apply(store, 6,
        TASK_DOCUMENT_UNDO, 0, NULL, row).ok);
    return failures;
}

static int td_failures(struct package_resident_store *store, struct task_document *row)
{
    int failures = 0;
    uint64_t id = row->state.tasks[0].id;
    int changed_before = sqlite3_total_changes(store->db);
    sqlite3_commit_hook(store->db, td_refuse_commit, NULL);
    TD_CHECK("failed durable commit is not success", !task_document_apply(store, 6,
        TASK_DOCUMENT_EDIT, id, "must not be Saved", row).ok);
    TD_CHECK("failure was injected after the actual write", sqlite3_total_changes(store->db) > changed_before);
    sqlite3_commit_hook(store->db, NULL, NULL);
    TD_CHECK("failure retains caller contents", row->state.revision == 6 &&
        strcmp(row->state.tasks[0].title, "Buy oat milk") == 0);
    TD_CHECK("failure retains database contents", task_document_read(store, row).ok &&
        row->state.revision == 6 && strcmp(row->state.tasks[0].title, "Buy oat milk") == 0);
    TD_CHECK("invalid title refuses without edits", !task_document_apply(store, 6,
        TASK_DOCUMENT_EDIT, id, "   ", row).ok && row->state.revision == 6);
    TD_CHECK("new edit after undo remains possible", task_document_apply(store, 6,
        TASK_DOCUMENT_ADD, 0, "Second task", row).ok && row->state.tasks[1].id == 7);
    return failures;
}

static int td_isolation(struct package_resident_store *store, const char *directory)
{
    int failures = 0;
    struct package_resident_store other = {0};
    struct task_document row = {0};
    TD_CHECK("another app opens", package_resident_store_open_app(&other, directory, "local/other").ok);
    TD_CHECK("app contents are isolated", task_document_read(&other, &row).ok && row.state.count == 0);
    TD_CHECK("other app closes", package_resident_store_close(&other).ok);
    TD_CHECK("unknown schema fixture", sqlite3_exec(store->db,
        "UPDATE task_documents SET payload=x'020000000000000000000000000000000000000000000000' WHERE app='local/tasks'",
        NULL, NULL, NULL) == SQLITE_OK);
    memset(&row, 0x55, sizeof(row));
    struct task_document before = row;
    TD_CHECK("incompatible data refuses and preserves output", !task_document_read(store, &row).ok &&
        memcmp(&row, &before, sizeof(row)) == 0);
    return failures;
}
#define TE_CHECK(label, expression) do { \
    bool passed = (expression); \
    printf("task_editor: %s... %s\n", label, passed ? "OK" : "FAIL"); \
    if (!passed) ++failures; \
} while (0)

static bool te_summary(const struct task_editor *editor, const char *prefix)
{
    struct zcl_present_model_v1 model;
    return task_editor_model(editor, &model).ok &&
        strncmp(model.summary, prefix, strlen(prefix)) == 0;
}

static int te_visual(const struct task_editor *editor)
{
    int failures = 0;
    struct zcl_present_model_v1 model;
    struct zcl_present_model_bitmap_v1 title = {0}, action = {0}, ordinary = {0};
    char error[256] = {0};
    TE_CHECK("build native form model", task_editor_model(editor, &model).ok);
    int64_t began = platform_time_monotonic_us();
    bool first = zcl_present_model_render_editor_v1(&model, &title, error, sizeof(error));
    printf("task_editor: native_editor_frame_us=%lld\n",
        (long long)(platform_time_monotonic_us() - began));
    bool rendered = first && zcl_present_model_render_editor_v1(&model, &action, error, sizeof(error));
    TE_CHECK("render actual native form pixels headlessly", rendered);
    if (rendered) {
        bool ordinary_ok = zcl_present_model_render_v1(&model, &ordinary, error, sizeof(error));
        TE_CHECK("local editor omits technical header; ordinary form retains it", ordinary_ok &&
            memcmp(title.pixels, ordinary.pixels, 164u * 720u * 3u) != 0 &&
            strlen(model.exact_root) == 64);
        zcl_present_form_draw_state_internal(title.pixels, ZCL_PRESENT_MODEL_BITMAP_BYTES,
            &editor->form, 0, false);
        zcl_present_form_draw_state_internal(action.pixels, ZCL_PRESENT_MODEL_BITMAP_BYTES,
            &editor->form, 1, false);
        const struct zcl_present_window_v1 page = {
            .width = action.width, .height = action.height, .pixel_format = ZCL_PRESENT_RGB8 };
        zcl_present_draw_action_focus_internal(&page, action.pixels,
            action.width, action.height, 2, 0);
        TE_CHECK("moving focus changes the native pixel overlay",
            memcmp(title.pixels, action.pixels, ZCL_PRESENT_MODEL_BITMAP_BYTES) != 0);
    } else fprintf(stderr, "task_editor: render: %s\n", error);
    zcl_present_model_bitmap_free_v1(&title);
    zcl_present_model_bitmap_free_v1(&action);
    zcl_present_model_bitmap_free_v1(&ordinary);
    return failures;
}

static struct zcl_result te_wait(struct task_editor *editor)
{
    int64_t deadline = platform_time_monotonic_us() + INT64_C(2000000);
    while (platform_time_monotonic_us() < deadline) {
        bool changed = false;
        struct zcl_result result = task_editor_poll(editor, &changed);
        if (!result.ok || changed) return result;
    }
    return ZCL_ERR(-1, "task editor test: save completion not observed");
}

static int te_focus(struct task_editor *editor)
{
    int failures = 0;
    uint32_t focus = UINT32_MAX;
    TE_CHECK("Tab focuses first action", zcl_present_window_form_focus_step_v1(
        &editor->form, 2, 0, 1, &focus) && focus == 1);
    TE_CHECK("Shift-Tab returns to title", zcl_present_window_form_focus_step_v1(
        &editor->form, 2, focus, -1, &focus) && focus == 0);
    return failures;
}

static int te_drafts(struct task_editor *editor)
{
    int failures = 0;
    const char *title = "First";
    for (size_t i = 0; title[i]; ++i)
        TE_CHECK("shared native typing", task_editor_type(editor, (uint8_t)title[i], false).ok);
    TE_CHECK("new draft model does not say Saved", te_summary(editor, "Unsaved changes"));
    failures += te_focus(editor);
    TE_CHECK("start save without claiming Saved", task_editor_submit(editor,
        TASK_DOCUMENT_ADD).ok && editor->status == TASK_EDITOR_SAVING &&
        te_summary(editor, "Saving..."));
    TE_CHECK("typing continues after submission", task_editor_type(editor, '!', false).ok &&
        strcmp(editor->form.fields[0].value, "First!") == 0);
    TE_CHECK("older success leaves newer draft unsaved", te_wait(editor).ok &&
        editor->status == TASK_EDITOR_UNSAVED && editor->dirty &&
        te_summary(editor, "Unsaved changes") &&
        strcmp(editor->saved.state.tasks[0].title, "First") == 0 &&
        strcmp(editor->form.fields[0].value, "First!") == 0);
    TE_CHECK("closing saves latest draft", task_editor_finish(editor).ok &&
        editor->status == TASK_EDITOR_SAVED && !editor->dirty && te_summary(editor, "Saved") &&
        strcmp(editor->saved.state.tasks[0].title, "First!") == 0);
    return failures;
}

static int te_busy(struct task_editor *editor, const char *directory)
{
    int failures = 0;
    struct package_resident_store blocker = {0};
    struct zcl_result opened = package_resident_store_open_app(&blocker, directory, "local/editor");
    if (!opened.ok) { fprintf(stderr, "task_editor: blocker: %s\n", opened.message); return 1; }
    TE_CHECK("hold competing database writer", sqlite3_exec(blocker.db,
        "BEGIN IMMEDIATE", NULL, NULL, NULL) == SQLITE_OK);
    TE_CHECK("edit while storage is busy", task_editor_type(editor, '?', false).ok);
    TE_CHECK("queue save while storage is busy", task_editor_submit(editor, TASK_DOCUMENT_EDIT).ok);
    int64_t began = platform_time_monotonic_us();
    bool keyboard_ok = true;
    for (unsigned i = 0; i < 1000; ++i) {
        keyboard_ok &= task_editor_type(editor, 'x', false).ok;
        keyboard_ok &= task_editor_type(editor, 0, true).ok;
    }
    printf("task_editor: keyboard_2000_events_us=%lld\n",
        (long long)(platform_time_monotonic_us() - began));
    TE_CHECK("keyboard preserves exact draft during busy save", keyboard_ok &&
        strcmp(editor->form.fields[0].value, "First!?") == 0);
    TE_CHECK("busy save reports failure and retains draft", !te_wait(editor).ok &&
        editor->status == TASK_EDITOR_FAILED && editor->failure[0] && editor->dirty &&
        te_summary(editor, "Save failed") &&
        strcmp(editor->form.fields[0].value, "First!?") == 0 &&
        strcmp(editor->saved.state.tasks[0].title, "First!") == 0);
    TE_CHECK("release competing writer", sqlite3_exec(blocker.db,
        "ROLLBACK", NULL, NULL, NULL) == SQLITE_OK);
    TE_CHECK("close competing connection", package_resident_store_close(&blocker).ok);
    TE_CHECK("explicit save after cause clears", task_editor_submit(editor,
        TASK_DOCUMENT_EDIT).ok && task_editor_finish(editor).ok &&
        editor->status == TASK_EDITOR_SAVED);
    return failures;
}
static struct zcl_result tl_wait_test(struct task_list *list)
{
    int64_t end = platform_time_monotonic_us() + INT64_C(2000000);
    while (list->editor->pending && platform_time_monotonic_us() < end) {
        struct zcl_result result = task_list_poll(list);
        if (!result.ok) return result;
    }
    if (list->editor->pending) return ZCL_ERR(-1, "list test: save not observed");
    return ZCL_OK;
}

static bool tl_key_test(struct task_list *list, enum zcl_present_input_key key, bool shift)
{
    const struct zcl_present_input_v1 input = { .key = key, .shift = shift };
    uint32_t action = UINT32_MAX;
    return task_list_input(list, &input, &list->focus, &action);
}

static int tl_visual_test(struct task_list *list)
{
    int failures = 0;
    struct zcl_present_model_v1 model;
    struct zcl_present_model_bitmap_v1 selected = {0}, button = {0};
    char error[256];
    int64_t began = platform_time_monotonic_us();
    TE_CHECK("list input moves selection", tl_key_test(list, ZCL_PRESENT_INPUT_DOWN, false));
    bool rendered = task_list_model(list, &model).ok &&
        zcl_present_model_render_list_v1(&model, &selected, error, sizeof(error));
    printf("task_list: input_to_frame_us=%lld bitmap_bytes=%u\n",
        (long long)(platform_time_monotonic_us() - began), ZCL_PRESENT_MODEL_BITMAP_BYTES);
    TE_CHECK("list selected row has real rendered pixels", rendered);
    TE_CHECK("Tab moves from content to New", tl_key_test(list, ZCL_PRESENT_INPUT_TAB, false) && list->focus == 0);
    bool second = task_list_model(list, &model).ok &&
        zcl_present_model_render_list_v1(&model, &button, error, sizeof(error));
    TE_CHECK("list keyboard focus changes visible pixels", rendered && second &&
        memcmp(selected.pixels, button.pixels, ZCL_PRESENT_MODEL_BITMAP_BYTES) != 0);
    TE_CHECK("Shift-Tab returns focus to selected row", tl_key_test(list, ZCL_PRESENT_INPUT_TAB, true) && list->focus == UINT32_MAX);
    zcl_present_model_bitmap_free_v1(&selected);
    zcl_present_model_bitmap_free_v1(&button);
    return failures;
}

static int tl_actions_test(struct task_list *list)
{
    int failures = 0;
    struct task_editor *editor = list->editor;
    uint64_t completed_id = list->selected_id;
    TE_CHECK("complete starts asynchronous Saving", task_list_action(list, 2).ok && editor->pending && editor->status == TASK_EDITOR_SAVING);
    TE_CHECK("navigation stays responsive during save", tl_key_test(list, ZCL_PRESENT_INPUT_DOWN, false));
    uint64_t navigated_id = list->selected_id;
    TE_CHECK("save retains newer navigation selection", tl_wait_test(list).ok && list->selected_id == navigated_id);
    bool completed = false;
    for (uint32_t i = 0; i < editor->saved.state.count; ++i)
        if (editor->saved.state.tasks[i].id == completed_id) completed = editor->saved.state.tasks[i].done != 0;
    TE_CHECK("completion changed only requested task", completed);
    struct ta_state before = editor->saved.state;
    TE_CHECK("Delete key enqueues selected task removal", tl_key_test(list, ZCL_PRESENT_INPUT_DELETE, false) && editor->pending);
    TE_CHECK("deleted task is durable and undo available", tl_wait_test(list).ok && editor->saved.state.count == before.count - 1 && editor->saved.can_undo);
    const struct zcl_present_input_v1 undo = { .key = ZCL_PRESENT_INPUT_TEXT, .character = 'z', .command = true };
    uint32_t action = UINT32_MAX;
    TE_CHECK("Cmd/Ctrl+Z enqueues durable undo", task_list_input(list, &undo, &list->focus, &action) && editor->pending);
    TE_CHECK("undo restores exact contents with fresh revision", tl_wait_test(list).ok &&
        editor->saved.state.count == before.count && editor->saved.state.revision > before.revision &&
        memcmp(editor->saved.state.tasks, before.tasks, sizeof(before.tasks)) == 0);
    TE_CHECK("More exposes deletion and durable undo", task_list_action(list, 3).ok && list->menu);
    TE_CHECK("Back returns to main actions", task_list_action(list, 0).ok && !list->menu);
    return failures;
}

static bool tl_populate(struct task_editor *editor)
{
    for (unsigned i = 0; i < 12; ++i) {
        char title[32];
        (void)snprintf(title, sizeof(title), "Task %02u", i + 1);
        if (!task_editor_select(editor, 0).ok) return false;
        for (size_t j = 0; title[j]; ++j)
            if (!task_editor_type(editor, (uint8_t)title[j], false).ok) return false;
        if (!task_editor_submit(editor, TASK_DOCUMENT_ADD).ok || !task_editor_finish(editor).ok) return false;
    }
    return true;
}

static int tl_failure_test(struct task_list *list, const char *directory)
{
    int failures = 0;
    struct package_resident_store other = {0};
    struct task_document row;
    TE_CHECK("open independent task writer", package_resident_store_open_app(&other, directory, "local/list").ok);
    TE_CHECK("read independent current revision", task_document_read(&other, &row).ok);
    TE_CHECK("another window durably edits selected task", task_document_apply(&other,
        row.state.revision, TASK_DOCUMENT_EDIT, list->selected_id, "Other window edit", &row).ok);
    TE_CHECK("stale list can enqueue but cannot overwrite", task_list_action(list, 2).ok && !tl_wait_test(list).ok &&
        list->editor->status == TASK_EDITOR_FAILED);
    struct zcl_present_model_v1 model;
    TE_CHECK("failed list action never displays Saved", task_list_model(list, &model).ok &&
        strncmp(model.summary, "Save failed", 11) == 0);
    struct task_document after;
    TE_CHECK("failed list action preserves exact other-window data", task_document_read(&other, &after).ok &&
        after.state.revision == row.state.revision &&
        memcmp(after.state.tasks, row.state.tasks, sizeof(row.state.tasks)) == 0);
    TE_CHECK("independent task writer closes", package_resident_store_close(&other).ok);
    return failures;
}

static int tl_acceptance(const char *directory)
{
    int failures = 0;
    struct task_editor editor = {0};
    TE_CHECK("open empty task-list store", task_editor_open(&editor, directory, "local/list").ok);
    struct task_list list;
    task_list_init(&list, &editor);
    struct zcl_present_model_v1 model;
    char error[256];
    TE_CHECK("empty list validates with obvious New action", task_list_model(&list, &model).ok &&
        zcl_present_model_validate_v1(&model, error, sizeof(error)) && strcmp(model.actions[0].label, "New task") == 0);
    TE_CHECK("create twelve durable tasks", tl_populate(&editor) && editor.saved.state.count == 12);
    task_list_refresh(&list);
    TE_CHECK("End scrolls selected row into viewport", tl_key_test(&list, ZCL_PRESENT_INPUT_END, false) && list.selected == 11 && list.first == 4);
    TE_CHECK("Home restores first row and viewport", tl_key_test(&list, ZCL_PRESENT_INPUT_HOME, false) && list.selected == 0 && list.first == 0);
    failures += tl_visual_test(&list);
    failures += tl_actions_test(&list);
    struct task_editor reopened = {0};
    TE_CHECK("reopen retains exact list contents", task_editor_open(&reopened, directory, "local/list").ok &&
        reopened.saved.state.count == editor.saved.state.count &&
        memcmp(reopened.saved.state.tasks, editor.saved.state.tasks, sizeof(editor.saved.state.tasks)) == 0);
    failures += tl_failure_test(&list, directory);
    TE_CHECK("list releases its save worker", task_editor_finish(&editor).ok && !editor.pending);
    return failures;
}

static int td_editor_acceptance(const char *directory)
{
    int failures = 0;
    size_t fd_before = 0, fd_after = 0;
    int threads_before = thread_registry_live_count();
    int rows_before = thread_registry_unreaped_count();
    TE_CHECK("observe initial descriptor count", os_proc_open_fd_count(&fd_before));
    struct task_editor editor = {0};
    struct zcl_result opened = task_editor_open(&editor, directory, "local/editor");
    if (!opened.ok) { fprintf(stderr, "task_editor: open: %s\n", opened.message); return 1; }
    failures += tl_acceptance(directory);
    failures += te_drafts(&editor);
    failures += te_busy(&editor, directory);
    struct task_editor reopened = {0};
    TE_CHECK("restart keeps exact latest editor contents", task_editor_open(&reopened,
        directory, "local/editor").ok && reopened.saved.state.count == 1 &&
        strcmp(reopened.saved.state.tasks[0].title, "First!?") == 0);
    TE_CHECK("select the reopened task", task_editor_select(&reopened,
        reopened.saved.state.tasks[0].id).ok);
    failures += te_visual(&reopened);
    TE_CHECK("request close without blocking or early Saved",
        task_editor_type(&reopened, '+', false).ok && task_editor_request_close(&reopened).ok &&
        reopened.closing && reopened.pending && te_summary(&reopened, "Saving..."));
    TE_CHECK("native close becomes ready only after durable completion", te_wait(&reopened).ok &&
        reopened.closing && !reopened.pending && !reopened.dirty &&
        te_summary(&reopened, "Saved") && strcmp(reopened.saved.state.tasks[0].title, "First!?+") == 0);
    TE_CHECK("finish prior editor", task_editor_finish(&editor).ok);
    TE_CHECK("finish reopened editor", task_editor_finish(&reopened).ok);
    TE_CHECK("save workers leave descriptor count unchanged",
        os_proc_open_fd_count(&fd_after) && fd_before == fd_after);
    TE_CHECK("save workers retain no thread or join ownership",
        thread_registry_live_count() == threads_before &&
        thread_registry_unreaped_count() == rows_before);
    return failures;
}

#endif

int test_task_document(void)
{
#if defined(_WIN32)
    struct package_resident_store store = {0};
    struct task_document row = {0};
    return task_document_read(&store, &row).ok ? 1 : 0;
#else
    int failures = 0;
    /* The resident store rejects writable ancestors. Shared checkout parents
     * can be group-writable, so this security fixture uses the same private
     * system-temp boundary as test_package_resident_record and removes it. */
    char directory[] = "/tmp/z23-task-document-XXXXXX", path[256];
    if (!mkdtemp(directory)) { perror("task_document: mkdtemp"); return 1; }
    (void)snprintf(path, sizeof(path), "%s/zcode", directory);
    if (mkdir(path, 0700) != 0) { perror("task_document: mkdir"); return 1; }
    struct package_resident_store store = {0};
    struct task_document row = {0};
    struct zcl_result opened = package_resident_store_open_app(&store, directory, "local/tasks");
    if (!opened.ok) { fprintf(stderr, "task_document: open: %s\n", opened.message); return 1; }
    failures += td_actions(&store, &row);
    failures += td_restart(&store, directory, &row);
    failures += td_failures(&store, &row);
    failures += td_editor_acceptance(directory);
    failures += td_isolation(&store, directory);
    TD_CHECK("final close", package_resident_store_close(&store).ok);
    (void)snprintf(path, sizeof(path), "%s/zcode/resident.db", directory);
    TD_CHECK("fixture database removed", unlink(path) == 0);
    (void)snprintf(path, sizeof(path), "%s/zcode", directory);
    TD_CHECK("fixture directories removed", rmdir(path) == 0 && rmdir(directory) == 0);
    return failures;
#endif
}
