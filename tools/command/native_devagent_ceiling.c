/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: dev.agent.ceiling — refuse a working tree whose diff outgrew the
 *          scope it was given, before it is committed rather than after it is
 *          reviewed.
 *
 * ── CONTRACT (this file is the whole implementation) ──────────────────────
 *
 * WHY. A unit asked to edit one file that quietly edits six, or rewrites the
 * one it was given, is the most expensive failure in a parallel lane: it
 * collides with every sibling and cannot be reviewed as one change. The
 * scope is stated up front, so it can be MEASURED up front.
 *
 * INPUT (zcl.agent_ceiling_input.v1)
 *   cwd            optional string. Directory to run Git in. Default: the
 *                  process working directory.
 *   base           REQUIRED string, a ref.
 *   requested      REQUIRED array of path strings, the files the change was
 *                  allowed to touch. Paths are compared exactly as Git prints
 *                  them, relative to the worktree top level.
 *   ceiling_lines  optional int. Default 80.
 *
 * SCAN. `git diff --numstat <base>` gives added/deleted per changed file
 * against the WORKING TREE (not the index, not HEAD). Every untracked file
 * (`git ls-files --others --exclude-standard`) is additionally counted as a
 * changed file whose added is its line count and whose deleted is 0.
 *
 * PER FILE
 *   path
 *   added          lines added
 *   deleted        lines deleted
 *   requested      bool: the path is in the `requested` array
 *   new_file       bool: the path does not exist at `base`
 *   rewrite        bool: deleted * 2 > the file's line count AT BASE
 *                  (`git show <base>:<path>`). Always false for a new file.
 *   over_ceiling   bool: added + deleted > ceiling_lines
 *
 * VERDICT. The verdict word is reported as the data field `status` on BOTH
 * outcomes, so one reader gets it the same way either way.
 *   ok=true and status "WITHIN_CEILING" only when EVERY changed file is
 *   requested, no file is a rewrite, and no file is over_ceiling.
 *   Otherwise ok=false with the error code "CEILING_EXCEEDED", the same word
 *   in the data field `status`, and
 *   violations:[{path, reason}] where reason is exactly one of
 *   "unrequested", "rewrite", "over_ceiling". A file that breaks more than
 *   one rule contributes one violation per broken rule, in that order.
 *
 * OUTPUT (zcl.agent_ceiling.v1), on success AND on CEILING_EXCEEDED
 *   leaf     "dev.agent.ceiling"
 *   status   "WITHIN_CEILING" or "CEILING_EXCEEDED"
 *   files    array of the per-file objects above
 *   summary  {changed, unrequested, rewrites, over_ceiling} — counts of files
 *   base     the base ref used
 *
 * FAILURE. A missing `base` or a missing/empty `requested` is ok=false,
 * status "BAD_INPUT". Any Git invocation that does not exit 0 is ok=false,
 * status "GIT_FAILED", with a message naming the failing argv — EXCEPT
 * `git show <base>:<path>` for a path absent at base, which is the
 * new_file=true answer.
 *
 * PROCESS RULE. Run Git only through zcl_spawn_capture() from util/spawn.h.
 * popen(), system() and a shell command string are forbidden and gated.
 *
 * Implement this file only; the test
 * tests/harness/src/test_devagent_ceiling.c is the acceptance bar and must
 * not be edited.
 */

#include "command/native_command.h"

#include "json/json.h"
#include "util/spawn.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DVL_LEAF "dev.agent.ceiling"

#define DVL_OUT_CAP 262144
#define DVL_LINE_CAP (DVL_OUT_CAP + 128)
#define DVL_TIMEOUT_MS 30000
#define DVL_MAX_FILES 4096

static void dvl_join_argv(const char *const argv[], char *line, size_t cap)
{
    size_t used = 0;
    if (cap == 0)
        return;
    line[0] = '\0';
    for (size_t i = 0; argv[i]; i++) {
        int w = snprintf(line + used, cap - used, "%s%s",
                         used == 0 ? "" : " ", argv[i]);
        if (w < 0 || (size_t)w >= cap - used)
            return;
        used += (size_t)w;
    }
}

/* Run one git command through the only allowed process rail. `line` always
 * receives the joined argv, so a failure names exactly what to rerun.
 * Returns the spawn result: 0 on success, else non-zero (never treated as a
 * hard failure by the callers that expect a non-zero exit as data). */
static int dvl_git(const char *dir, const char *const args[], char *out,
                   size_t cap, char *line, size_t linecap)
{
    const char *argv[16];
    size_t n = 0;

    argv[n++] = "git";
    if (dir && dir[0]) {
        argv[n++] = "-C";
        argv[n++] = dir;
    }
    for (size_t i = 0; args[i]; i++) {
        if (n + 1 >= sizeof(argv) / sizeof(argv[0])) {
            (void)snprintf(line, linecap, "git <internal argv overflow>");
            out[0] = '\0';
            return -1;
        }
        argv[n++] = args[i];
    }
    argv[n] = NULL;

    dvl_join_argv(argv, line, linecap);
    out[0] = '\0';
    return zcl_spawn_capture(argv, out, cap, DVL_TIMEOUT_MS);
}

static void dvl_git_failed(struct zcl_command_reply *reply, const char *line,
                           int rc)
{
    char msg[DVL_LINE_CAP + 64];
    (void)snprintf(msg, sizeof(msg),
                   "git invocation failed (exit status %d): %s", rc, line);
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                           ZCL_COMMAND_EXIT_FAILED, "GIT_FAILED", "spawn",
                           false, false, msg,
                           "tools/command/native_devagent_ceiling.c");
    (void)snprintf(reply->error.next_action, sizeof(reply->error.next_action),
                   "rerun: %s", line);
}

struct dvl_file {
    char path[PATH_MAX];
    long long added;
    long long deleted;
    bool requested;
    bool new_file;
    bool rewrite;
    bool over_ceiling;
};

static struct dvl_file *dvl_find_or_add(struct dvl_file *files, size_t *n,
                                        const char *path)
{
    for (size_t i = 0; i < *n; i++) {
        if (strcmp(files[i].path, path) == 0)
            return &files[i];
    }
    if (*n >= DVL_MAX_FILES)
        return NULL;
    struct dvl_file *f = &files[*n];
    memset(f, 0, sizeof(*f));
    (void)snprintf(f->path, sizeof(f->path), "%s", path);
    (*n)++;
    return f;
}

static bool dvl_path_in_requested(const struct json_value *requested,
                                  const char *path)
{
    if (!requested)
        return false;
    for (size_t i = 0; i < requested->num_children; i++) {
        const struct json_value *v = &requested->children[i];
        if (v->type == JSON_STR && json_get_str(v) &&
            strcmp(json_get_str(v), path) == 0)
            return true;
    }
    return false;
}

/* Count lines in `text` (git show output). A file ending without a final
 * newline still counts its last line. Empty text is 0 lines. */
static long long dvl_count_lines(const char *text, size_t len)
{
    if (len == 0)
        return 0;
    long long lines = 0;
    for (size_t i = 0; i < len; i++) {
        if (text[i] == '\n')
            lines++;
    }
    if (text[len - 1] != '\n')
        lines++;
    return lines;
}

struct dvl_input {
    const char *cwd;
    const char *base;
    const struct json_value *requested;
    long long ceiling_lines;
};

static const char *dvl_input_string(const struct json_value *input,
                                    const char *key)
{
    const struct json_value *v = json_get(input, key);
    if (v && v->type == JSON_STR && json_get_str(v) && json_get_str(v)[0])
        return json_get_str(v);
    return NULL;
}

static void dvl_read_input(const struct zcl_command_request *request,
                           struct dvl_input *in)
{
    in->cwd = NULL;
    in->base = NULL;
    in->requested = NULL;
    in->ceiling_lines = 80;
    if (!request || !request->input)
        return;
    const struct json_value *v;
    in->cwd = dvl_input_string(request->input, "cwd");
    in->base = dvl_input_string(request->input, "base");
    v = json_get(request->input, "requested");
    if (v && v->type == JSON_ARR)
        in->requested = v;
    v = json_get(request->input, "ceiling_lines");
    if (v && v->type == JSON_INT)
        in->ceiling_lines = json_get_int(v);
}

static bool dvl_input_valid(struct zcl_command_reply *reply,
                            const struct dvl_input *in)
{
    if (!in->base || !in->base[0]) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_FAILED, "BAD_INPUT",
                               "validate", false, false,
                               "base is required and must be a non-empty ref",
                               "input.base missing or empty");
        return false;
    }
    if (!in->requested || in->requested->num_children == 0) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_FAILED, "BAD_INPUT",
                               "validate", false, false,
                               "requested is required and must be a non-empty "
                               "array of path strings",
                               "input.requested missing or empty");
        return false;
    }
    return true;
}

/* Records one `git diff --numstat` row ("<added>\t<deleted>\t<path>"). */
static void dvl_record_numstat_row(char *rowbuf, struct dvl_file *files,
                                   size_t *nfiles)
{
    char *tab1 = strchr(rowbuf, '\t');
    if (!tab1)
        return;
    *tab1 = '\0';
    char *added_s = rowbuf;
    char *rest = tab1 + 1;
    char *tab2 = strchr(rest, '\t');
    if (!tab2)
        return;
    *tab2 = '\0';
    char *deleted_s = rest;
    char *path = tab2 + 1;

    long long added = strcmp(added_s, "-") == 0 ? 0
                                                : strtoll(added_s, NULL, 10);
    long long deleted = strcmp(deleted_s, "-") == 0
                            ? 0 : strtoll(deleted_s, NULL, 10);
    struct dvl_file *f = dvl_find_or_add(files, nfiles, path);
    if (f) {
        f->added = added;
        f->deleted = deleted;
    }
}

/* `git diff --numstat <base>` against the working tree. */
static bool dvl_load_tracked(struct zcl_command_reply *reply,
                             const struct dvl_input *in, char *out,
                             size_t out_sz, struct dvl_file *files,
                             size_t *nfiles)
{
    char line[DVL_LINE_CAP];
    const char *argv[] = {"diff", "--numstat", in->base, NULL};
    int rc = dvl_git(in->cwd, argv, out, out_sz, line, sizeof(line));
    if (rc != 0) {
        dvl_git_failed(reply, line, rc);
        return false;
    }
    const char *p = out;
    while (*p) {
        const char *nl = strchr(p, '\n');
        size_t len = nl ? (size_t)(nl - p) : strlen(p);
        if (len > 0) {
            char rowbuf[PATH_MAX + 64];
            size_t rowlen = len < sizeof(rowbuf) - 1 ? len : sizeof(rowbuf) - 1;
            memcpy(rowbuf, p, rowlen);
            rowbuf[rowlen] = '\0';
            dvl_record_numstat_row(rowbuf, files, nfiles);
        }
        if (!nl)
            break;
        p = nl + 1;
    }
    return true;
}

/* Line count of one untracked file (0 when unreadable). */
static long long dvl_untracked_lines(const char *cwd, const char *path)
{
    char full[PATH_MAX + 8];
    if (cwd && cwd[0])
        (void)snprintf(full, sizeof(full), "%s/%s", cwd, path);
    else
        (void)snprintf(full, sizeof(full), "%s", path);
    FILE *f = fopen(full, "rb");
    if (!f)
        return 0;
    static char buf[1 << 20];
    size_t got = fread(buf, 1, sizeof(buf), f);
    long long added = dvl_count_lines(buf, got);
    (void)fclose(f);
    return added;
}

/* Untracked files, each counted as a new file whose added is its line count
 * and deleted is 0. */
static bool dvl_load_untracked(struct zcl_command_reply *reply,
                               const struct dvl_input *in, char *out,
                               size_t out_sz, struct dvl_file *files,
                               size_t *nfiles)
{
    char line[DVL_LINE_CAP];
    const char *argv[] = {"ls-files", "--others", "--exclude-standard", NULL};
    int rc = dvl_git(in->cwd, argv, out, out_sz, line, sizeof(line));
    if (rc != 0) {
        dvl_git_failed(reply, line, rc);
        return false;
    }
    const char *p = out;
    while (*p) {
        const char *nl = strchr(p, '\n');
        size_t len = nl ? (size_t)(nl - p) : strlen(p);
        if (len > 0 && len < PATH_MAX) {
            char path[PATH_MAX];
            memcpy(path, p, len);
            path[len] = '\0';
            long long added = dvl_untracked_lines(in->cwd, path);
            struct dvl_file *df = dvl_find_or_add(files, nfiles, path);
            if (df) {
                df->added = added;
                df->deleted = 0;
            }
        }
        if (!nl)
            break;
        p = nl + 1;
    }
    return true;
}

/* Per file: requested, new_file, rewrite, over_ceiling. */
static void dvl_classify_files(const struct dvl_input *in, char *out,
                               size_t out_sz, struct dvl_file *files,
                               size_t nfiles)
{
    for (size_t i = 0; i < nfiles; i++) {
        struct dvl_file *f = &files[i];
        f->requested = dvl_path_in_requested(in->requested, f->path);
        f->over_ceiling = (f->added + f->deleted) > in->ceiling_lines;

        /* new_file: does `git show <base>:<path>` fail? A failure here is
         * the new_file=true answer, per contract, never a hard GIT_FAILED. */
        char spec[PATH_MAX + 256];
        (void)snprintf(spec, sizeof(spec), "%s:%s", in->base, f->path);
        const char *argv[] = {"show", spec, NULL};
        char show_line[DVL_LINE_CAP];
        int show_rc = dvl_git(in->cwd, argv, out, out_sz, show_line,
                              sizeof(show_line));
        if (show_rc != 0) {
            f->new_file = true;
            f->rewrite = false;
        } else {
            f->new_file = false;
            long long base_lines = dvl_count_lines(out, strlen(out));
            f->rewrite = f->deleted * 2 > base_lines;
        }
    }
}

struct dvl_counts {
    long long unrequested, rewrites, over_ceiling;
};

static void dvl_push_violation(struct json_value *violations,
                               const char *path, const char *reason)
{
    struct json_value entry;
    json_init(&entry);
    json_set_object(&entry);
    (void)json_push_kv_str(&entry, "path", path);
    (void)json_push_kv_str(&entry, "reason", reason);
    (void)json_push_back(violations, &entry);
    json_free(&entry);
}

static void dvl_collect_violations(const struct dvl_file *files, size_t nfiles,
                                   struct json_value *violations,
                                   struct dvl_counts *counts)
{
    for (size_t i = 0; i < nfiles; i++) {
        const struct dvl_file *f = &files[i];
        if (!f->requested) {
            counts->unrequested++;
            dvl_push_violation(violations, f->path, "unrequested");
        }
        if (f->rewrite) {
            counts->rewrites++;
            dvl_push_violation(violations, f->path, "rewrite");
        }
        if (f->over_ceiling) {
            counts->over_ceiling++;
            dvl_push_violation(violations, f->path, "over_ceiling");
        }
    }
}

static void dvl_push_files(struct json_value *files_arr,
                           const struct dvl_file *files, size_t nfiles)
{
    struct json_value row;
    json_init(&row);
    for (size_t i = 0; i < nfiles; i++) {
        const struct dvl_file *f = &files[i];
        json_set_object(&row);
        (void)json_push_kv_str(&row, "path", f->path);
        (void)json_push_kv_int(&row, "added", f->added);
        (void)json_push_kv_int(&row, "deleted", f->deleted);
        (void)json_push_kv_bool(&row, "requested", f->requested);
        (void)json_push_kv_bool(&row, "new_file", f->new_file);
        (void)json_push_kv_bool(&row, "rewrite", f->rewrite);
        (void)json_push_kv_bool(&row, "over_ceiling", f->over_ceiling);
        (void)json_push_back(files_arr, &row);
    }
    json_free(&row);
}

void zcl_native_handle_dev_agent_ceiling(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    struct dvl_input in;
    char out[DVL_OUT_CAP];

    if (!reply)
        return;

    (void)json_push_kv_str(&reply->data, "leaf", DVL_LEAF);

    dvl_read_input(request, &in);
    if (!dvl_input_valid(reply, &in))
        return;
    if (in.ceiling_lines <= 0)
        in.ceiling_lines = 80;

    static struct dvl_file files[DVL_MAX_FILES];
    size_t nfiles = 0;
    if (!dvl_load_tracked(reply, &in, out, sizeof(out), files, &nfiles) ||
        !dvl_load_untracked(reply, &in, out, sizeof(out), files, &nfiles))
        return;
    dvl_classify_files(&in, out, sizeof(out), files, nfiles);

    /* Verdict + violations. */
    struct json_value violations;
    json_init(&violations);
    json_set_array(&violations);
    struct dvl_counts counts = {0, 0, 0};
    dvl_collect_violations(files, nfiles, &violations, &counts);

    struct json_value files_arr;
    json_init(&files_arr);
    json_set_array(&files_arr);
    dvl_push_files(&files_arr, files, nfiles);

    struct json_value summary;
    json_init(&summary);
    json_set_object(&summary);
    (void)json_push_kv_int(&summary, "changed", (long long)nfiles);
    (void)json_push_kv_int(&summary, "unrequested", counts.unrequested);
    (void)json_push_kv_int(&summary, "rewrites", counts.rewrites);
    (void)json_push_kv_int(&summary, "over_ceiling", counts.over_ceiling);

    bool within_ceiling = counts.unrequested == 0 && counts.rewrites == 0 &&
                          counts.over_ceiling == 0;
    const char *status = within_ceiling ? "WITHIN_CEILING" : "CEILING_EXCEEDED";

    (void)json_push_kv_str(&reply->data, "status", status);
    (void)json_push_kv(&reply->data, "files", &files_arr);
    (void)json_push_kv(&reply->data, "summary", &summary);
    (void)json_push_kv_str(&reply->data, "base", in.base);

    json_free(&files_arr);
    json_free(&summary);

    if (!within_ceiling) {
        (void)json_push_kv(&reply->data, "violations", &violations);
        json_free(&violations);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_FAILED, "CEILING_EXCEEDED",
                               "resolve", false, false,
                               "the diff outgrew the requested scope",
                               "see violations in the reply data");
        return;
    }
    json_free(&violations);

    reply->status = ZCL_COMMAND_STATUS_PASSED;
}
