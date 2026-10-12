/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: z23-toolgen - expands the Z23_TOOL_V1 manifest comment of each
 *          tools/command source into the generator-owned blocks of the
 *          command registry files.
 *
 *   z23-toolgen [--root DIR] --check   exit 1 and name the reason when any
 *                                      block differs from what the manifests
 *                                      imply, or a manifest is invalid
 *   z23-toolgen [--root DIR] --write   rewrite only the generator-owned
 *                                      blocks; a file that is already correct
 *                                      is not touched
 *
 * No shell, no compiler, no dynamic loading, no preprocessor evaluation. */

#define _POSIX_C_SOURCE 200809L

#include "toolgen.h"

#include "base/safe_alloc.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define FILE_LIMIT (4u * 1024u * 1024u)

struct plan {
    struct tg_target target;
    struct tg_sb text;
    struct tg_sb cur;
    struct tg_sb want;
    struct tg_sb next;
    struct tg_block blk;
    bool changed;
};

static void plan_free(struct plan *p)
{
    tg_sb_free(&p->text);
    tg_sb_free(&p->cur);
    tg_sb_free(&p->want);
    tg_sb_free(&p->next);
}

static bool read_target(const char *root, struct plan *p, struct tg_err *e)
{
    char path[1024];
    if (!tg_join(path, sizeof path, root, p->target.path))
        return tg_fail(e, "IO_ERROR", "path too long: %s", p->target.path);
    switch (tg_read_file(path, FILE_LIMIT, &p->text)) {
    case TG_READ_OK:
        return true;
    case TG_READ_NOT_REGULAR:
        return tg_fail(e, "SOURCE_NOT_REGULAR", "%s is not a regular file", p->target.path);
    default:
        return tg_fail(e, "IO_ERROR", "cannot read %s", p->target.path);
    }
}

static size_t select_for(const struct tg_target *t, const struct tg_set *set,
                         const struct tg_manifest **out)
{
    size_t n = 0;
    for (size_t i = 0; i < set->n; i++)
        if (tg_applies(t, &set->m[i]))
            out[n++] = &set->m[i];
    return n;
}

static bool build_plan(const char *root, const struct tg_set *set, struct plan *p,
                       struct tg_err *e)
{
    if (!read_target(root, p, e))
        return false;
    if (!tg_block_locate(p->text.p, p->text.n, p->target.id, p->target.path, &p->blk, e))
        return false;
    tg_sb_putn(&p->cur, p->text.p + p->blk.body_start, p->blk.body_end - p->blk.body_start);
    const struct tg_manifest *sel[TG_MAX_MANIFESTS];
    size_t n = select_for(&p->target, set, sel);
    tg_render_body(&p->target, sel, n, p->cur.p ? p->cur.p : "", p->cur.n, &p->want);
    if (p->want.oom || p->cur.oom)
        return tg_fail(e, "IO_ERROR", "out of memory rendering %s", p->target.path);
    p->changed = p->want.n != p->cur.n ||
                 (p->want.n && memcmp(p->want.p, p->cur.p, p->want.n) != 0);
    if (!p->changed)
        return true;
    return tg_block_splice(p->text.p, p->text.n, &p->blk, p->want.p ? p->want.p : "", p->want.n,
                           &p->next) ||
           tg_fail(e, "IO_ERROR", "out of memory rendering %s", p->target.path);
}

static bool in_body(const struct plan *p, const struct tg_manifest *m)
{
    struct tg_sb unit = {0};
    tg_render_unit(&p->target, m, &unit);
    bool hit = p->cur.p && unit.p && strstr(p->cur.p, unit.p) != NULL;
    tg_sb_free(&unit);
    return hit;
}

/* A command whose rows exist in some generated blocks but not in others. */
static size_t report_mixed(const struct tg_set *set, const struct plan *plans, size_t np)
{
    size_t problems = 0;
    for (size_t i = 0; i < set->n; i++) {
        size_t present = 0;
        size_t total = 0;
        for (size_t k = 0; k < np; k++) {
            if (!tg_applies(&plans[k].target, &set->m[i]))
                continue;
            total++;
            present += in_body(&plans[k], &set->m[i]) ? 1u : 0u;
        }
        if (present > 0 && present < total) {
            fprintf(stderr, "z23-toolgen: ERROR MIXED_GENERATION: %s has its rows in %zu of %zu generated blocks\n",
                    set->m[i].path, present, total);
            problems++;
        }
    }
    return problems;
}

static size_t report_drift(const struct plan *plans, size_t np)
{
    size_t problems = 0;
    for (size_t k = 0; k < np; k++)
        if (plans[k].changed) {
            fprintf(stderr, "z23-toolgen: ERROR BLOCK_DRIFT: %s block \"%s\" differs from its manifests\n",
                    plans[k].target.path, plans[k].target.id);
            problems++;
        }
    return problems;
}

/* A uniquely named temp file next to the target; never follows a link. */
static int open_temp(const char *path, char *tmp, size_t cap)
{
    for (unsigned n = 0; n < 8u; n++) {
        int w = snprintf(tmp, cap, "%s.toolgen.%ld.%u", path, (long)getpid(), n);
        if (w <= 0 || (size_t)w >= cap)
            return -1;
        int fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
        if (fd >= 0 || errno != EEXIST)
            return fd;
    }
    return -1;
}

static bool write_all(int fd, const char *p, size_t n)
{
    while (n > 0) {
        ssize_t w = write(fd, p, n);
        if (w <= 0)
            return false;
        p += w;
        n -= (size_t)w;
    }
    return true;
}

/* Temp file, fsync, then rename: readers see the old or the new bytes. A temp
 * left by a dead writer ends in .toolgen.<pid>.<n>, matches no scanned suffix
 * and is never read. */
static bool write_atomic(const char *path, const struct tg_sb *text, struct tg_err *e)
{
    char tmp[1100];
    struct stat st;
    int fd = open_temp(path, tmp, sizeof tmp);
    if (fd < 0)
        return tg_fail(e, "WRITE_FAILED", "cannot create a temp file beside %s", path);
    bool ok = write_all(fd, text->p, text->n) && fsync(fd) == 0;
    if (ok && stat(path, &st) == 0)
        ok = fchmod(fd, st.st_mode & 07777) == 0;
    ok = close(fd) == 0 && ok;
    if (!ok || rename(tmp, path) != 0) {
        remove(tmp);
        return tg_fail(e, "WRITE_FAILED", "cannot replace %s", path);
    }
    return true;
}

static bool apply_plan(const char *root, const struct plan *p, struct tg_err *e)
{
    char path[1024];
    struct tg_sb now = {0};
    tg_join(path, sizeof path, root, p->target.path);
    bool same = tg_read_file(path, FILE_LIMIT, &now) == TG_READ_OK && now.n == p->text.n &&
                (now.n == 0 || memcmp(now.p, p->text.p, now.n) == 0);
    tg_sb_free(&now);
    if (!same)
        return tg_fail(e, "PREIMAGE_CHANGED", "%s changed while the generator ran", p->target.path);
    if (!write_atomic(path, &p->next, e))
        return false;
    printf("z23-toolgen: wrote %s\n", p->target.path);
    return true;
}

/* The lock file holds the writer pid; one whose pid no longer exists is taken over. */
static bool lock_stale(const char *lock)
{
    long pid = 0;
    FILE *f = fopen(lock, "r");
    if (!f)
        return false;
    bool parsed = fscanf(f, "%ld", &pid) == 1;
    fclose(f);
    return parsed && pid > 0 && kill((pid_t)pid, 0) != 0 && errno == ESRCH;
}

static bool lock_take(const char *root, char *lock, size_t cap, struct tg_err *e)
{
    char dir[1024];
    if (!tg_join(dir, sizeof dir, root, "build") || !tg_join(lock, cap, dir, "z23-toolgen.lock"))
        return tg_fail(e, "IO_ERROR", "path too long");
    if (mkdir(dir, 0777) != 0 && access(dir, W_OK) != 0)
        return tg_fail(e, "IO_ERROR", "cannot use %s", dir);
    for (int attempt = 0; attempt < 2; attempt++) {
        int fd = open(lock, O_CREAT | O_EXCL | O_WRONLY | O_NOFOLLOW | O_CLOEXEC, 0600);
        if (fd >= 0) {
            dprintf(fd, "%ld\n", (long)getpid());
            close(fd);
            return true;
        }
        if (errno != EEXIST || !lock_stale(lock) || unlink(lock) != 0)
            break;
    }
    return tg_fail(e, "WRITER_BUSY",
                   "another writer holds %s; if no z23-toolgen is running, remove that file", lock);
}

static bool run_plans(const char *root, const struct tg_set *set, struct plan *plans,
                      size_t *np, struct tg_err *e)
{
    struct tg_target t[TG_MAX_TARGETS];
    size_t n = tg_targets(t, TG_MAX_TARGETS);
    for (size_t i = 0; i < n; i++) {
        plans[i] = (struct plan){.target = t[i]};
        (*np)++;
        if (!build_plan(root, set, &plans[i], e))
            return false;
    }
    return true;
}

static int finish_check(const struct tg_set *set, struct plan *plans, size_t np)
{
    size_t problems = report_drift(plans, np) + report_mixed(set, plans, np);
    if (problems) {
        fprintf(stderr, "z23-toolgen: check FAILED (%zu problem%s); run build/bin/z23-toolgen --write\n",
                problems, problems == 1 ? "" : "s");
        return 1;
    }
    printf("z23-toolgen: check ok (%zu manifest%s, %zu blocks)\n", set->n, set->n == 1 ? "" : "s", np);
    return 0;
}

static int finish_write(const char *root, struct plan *plans, size_t np, struct tg_err *e)
{
    char lock[1100];
    if (!lock_take(root, lock, sizeof lock, e))
        return 1;
    bool ok = true;
    size_t wrote = 0;
    for (size_t k = 0; ok && k < np; k++)
        if (plans[k].changed) {
            ok = apply_plan(root, &plans[k], e);
            wrote++;
        }
    remove(lock);
    if (ok && wrote == 0)
        printf("z23-toolgen: write: nothing to change\n");
    return ok ? 0 : 1;
}

static int execute(const char *root, bool write)
{
    static struct tg_set set;
    struct plan plans[TG_MAX_TARGETS];
    size_t np = 0;
    struct tg_err e = {0};
    int rc = 1;
    if (tg_gather(root, &set, &e) && run_plans(root, &set, plans, &np, &e))
        rc = write ? finish_write(root, plans, np, &e) : finish_check(&set, plans, np);
    if (e.code[0])
        fprintf(stderr, "z23-toolgen: ERROR %s: %s\n", e.code, e.detail);
    for (size_t k = 0; k < np; k++)
        plan_free(&plans[k]);
    return rc;
}

int main(int argc, char **argv)
{
    const char *root = ".";
    int mode = 0;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--check") == 0 && mode == 0)
            mode = 1;
        else if (strcmp(argv[i], "--write") == 0 && mode == 0)
            mode = 2;
        else if (strcmp(argv[i], "--root") == 0 && i + 1 < argc)
            root = argv[++i];
        else
            mode = -1;
    }
    if (mode <= 0) {
        fputs("usage: z23-toolgen [--root DIR] --check|--write\n", stderr);
        return 2;
    }
    return execute(root, mode == 2);
}
