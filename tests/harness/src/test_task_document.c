/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: prove task contents survive restart, undo and failed commits. */
#include "test/test_core.h"
#include "models/task_document.h"
#include "services/task_editor.h"
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
