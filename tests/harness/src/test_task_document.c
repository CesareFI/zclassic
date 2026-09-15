/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: prove task contents survive restart, undo and failed commits. */
#include "test/test_core.h"
#include "models/task_document.h"
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
    failures += td_isolation(&store, directory);
    TD_CHECK("final close", package_resident_store_close(&store).ok);
    (void)snprintf(path, sizeof(path), "%s/zcode/resident.db", directory);
    TD_CHECK("fixture database removed", unlink(path) == 0);
    (void)snprintf(path, sizeof(path), "%s/zcode", directory);
    TD_CHECK("fixture directories removed", rmdir(path) == 0 && rmdir(directory) == 0);
    return failures;
#endif
}
