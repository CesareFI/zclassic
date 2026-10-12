/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Collect the Z23_TOOL_V1 manifests from the tools/command sources, validate
 *          each against its authored source and test, and reject any name
 *          that collides with an authored or other generated command. */

#define _POSIX_C_SOURCE 200809L

#include "toolgen.h"

#include "base/safe_alloc.h"

#include <ctype.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SOURCE_DIR "tools/command"
#define TEST_DIR "tests/harness/src"
#define TEXT_LIMIT (4u * 1024u * 1024u)

static bool read_source(const char *root, const char *rel, size_t limit, struct tg_sb *sb,
                        struct tg_err *e)
{
    char path[1024];
    if (!tg_join(path, sizeof path, root, rel))
        return tg_fail(e, "IO_ERROR", "path too long: %s", rel);
    switch (tg_read_file(path, limit, sb)) {
    case TG_READ_OK:
        return true;
    case TG_READ_NOT_REGULAR:
        return tg_fail(e, "SOURCE_NOT_REGULAR", "%s is not a regular file", rel);
    case TG_READ_TOO_LARGE:
        return tg_fail(e, "SOURCE_TOO_LARGE", "%s exceeds the %u byte read ceiling", rel, (unsigned)limit);
    case TG_READ_MISSING:
        return tg_fail(e, "TEST_SOURCE_MISSING", "%s does not exist", rel);
    default:
        return tg_fail(e, "IO_ERROR", "cannot read %s", rel);
    }
}

static bool check_test(const char *root, const struct tg_manifest *m, struct tg_err *e)
{
    char rel[256], entry[96], quoted[140];
    snprintf(rel, sizeof rel, TEST_DIR "/test_%s.c", m->test_group);
    snprintf(entry, sizeof entry, "test_%s", m->test_group);
    snprintf(quoted, sizeof quoted, "\"%s\"", m->path);
    struct tg_sb sb = {0};
    struct tg_lex lx;
    if (!read_source(root, rel, TEXT_LIMIT, &sb, e)) {
        tg_sb_free(&sb);
        return false;
    }
    if (!tg_lex_run(sb.p ? sb.p : "", sb.n, &lx)) {
        tg_sb_free(&sb);
        return tg_fail(e, "IO_ERROR", "out of memory scanning %s", rel);
    }
    bool ok = true;
    if (!tg_has_definition(&lx, "int", entry))
        ok = tg_fail(e, "TEST_ENTRY_MISSING", "%s does not define int %s(void)", rel, entry);
    else if (!strstr(lx.code, quoted))
        ok = tg_fail(e, "TEST_NAMES_NOT_COMMAND", "%s names the command %s only in a comment or not at all", rel, quoted);
    tg_lex_free(&lx);
    tg_sb_free(&sb);
    return ok;
}

static bool take_manifest(const char *root, const char *rel, const struct tg_sb *src,
                          const struct tg_lex *lx, const struct tg_marker *mk,
                          struct tg_set *set, struct tg_err *e)
{
    if (set->n >= TG_MAX_MANIFESTS)
        return tg_fail(e, "TOO_MANY_MANIFESTS", "more than %u manifests", TG_MAX_MANIFESTS);
    struct tg_manifest *m = &set->m[set->n];
    *m = (struct tg_manifest){0};
    if (!tg_manifest_parse(src->p + mk->body_off, mk->body_len, m, e))
        return tg_err_context(e, rel);
    size_t rel_len = strlen(rel);
    if (rel_len >= sizeof m->source)
        return tg_fail(e, "SOURCE_NAME_BAD", "%s is longer than %zu bytes", rel,
                       sizeof m->source - 1);
    memcpy(m->source, rel, rel_len + 1);
    if (!tg_has_definition(lx, "void", m->handler))
        return tg_fail(e, "HANDLER_UNDEFINED", "%s does not define void %s(...)", rel, m->handler);
    if (!check_test(root, m, e))
        return false;
    set->n++;
    return true;
}

static bool scan_source(const char *root, const char *name, struct tg_set *set, struct tg_err *e)
{
    char rel[256];
    snprintf(rel, sizeof rel, SOURCE_DIR "/%s", name);
    struct tg_sb src = {0};
    struct tg_lex lx;
    struct tg_marker mk;
    if (!read_source(root, rel, TG_READ_CEILING, &src, e)) {
        tg_sb_free(&src);
        return false;
    }
    if (src.n > TG_SOURCE_MAX) {
        bool has = src.p && strstr(src.p, TG_MARKER) != NULL;
        tg_sb_free(&src);
        return !has || tg_fail(e, "SOURCE_TOO_LARGE", "%s exceeds %u bytes and names %s", rel,
                               TG_SOURCE_MAX, TG_MARKER);
    }
    if (!tg_lex_run(src.p ? src.p : "", src.n, &lx)) {
        tg_sb_free(&src);
        return tg_fail(e, "IO_ERROR", "out of memory scanning %s", rel);
    }
    bool ok = tg_find_marker(src.p ? src.p : "", &lx, &mk, e) || tg_err_context(e, rel);
    if (ok && mk.found)
        ok = take_manifest(root, rel, &src, &lx, &mk, set, e);
    tg_lex_free(&lx);
    tg_sb_free(&src);
    return ok;
}

static int by_path(const void *a, const void *b)
{
    const struct tg_manifest *x = a;
    const struct tg_manifest *y = b;
    return strcmp(x->path, y->path);
}

static bool generated_branch(const struct tg_set *set, const char *name)
{
    for (size_t i = 0; i < set->n; i++)
        if (set->m[i].has_branch && strcmp(set->m[i].parent, name) == 0)
            return true;
    return false;
}

static bool pair_clash(const struct tg_manifest *a, const struct tg_manifest *b, struct tg_err *e)
{
    if (strcmp(a->path, b->path) == 0)
        return tg_fail(e, "COLLISION_PATH", "%s and %s both declare %s", a->source, b->source, a->path);
    if (strcmp(a->handler, b->handler) == 0)
        return tg_fail(e, "COLLISION_HANDLER", "%s and %s both declare %s", a->source, b->source, a->handler);
    if (strcmp(a->test_group, b->test_group) == 0)
        return tg_fail(e, "COLLISION_TEST_GROUP", "%s and %s both declare group %s", a->source,
                       b->source, a->test_group);
    if (a->has_branch && b->has_branch && strcmp(a->parent, b->parent) == 0)
        return tg_fail(e, "COLLISION_BRANCH", "%s and %s both declare branch %s", a->source,
                       b->source, a->parent);
    return true;
}

static bool parent_known(const struct tg_world *w, const struct tg_set *set, const char *name)
{
    return tg_names_has(&w->branches, name) || generated_branch(set, name);
}

static bool world_clash(const struct tg_world *w, const struct tg_set *set,
                        const struct tg_manifest *m, struct tg_err *e)
{
    if (tg_names_has(&w->paths, m->path) || tg_names_has(&w->remote, m->path))
        return tg_fail(e, "COLLISION_PATH", "%s: %s is already registered by hand", m->source, m->path);
    if (tg_names_has(&w->handlers, m->handler))
        return tg_fail(e, "COLLISION_HANDLER", "%s: %s is already named by hand", m->source, m->handler);
    if (tg_names_has(&w->groups, m->test_group))
        return tg_fail(e, "COLLISION_TEST_GROUP", "%s: group %s is already registered by hand",
                       m->source, m->test_group);
    if (m->has_branch && tg_names_has(&w->paths, m->parent))
        return tg_fail(e, "COLLISION_BRANCH", "%s: %s is already registered by hand", m->source, m->parent);
    char up[100];
    const char *want = m->has_branch ? m->parent : m->path;
    const char *dot = strrchr(want, '.');
    if (!dot)
        return tg_fail(e, "PARENT_UNKNOWN", "%s: a root branch cannot be generated", m->source);
    snprintf(up, sizeof up, "%.*s", (int)(dot - want), want);
    if (m->has_branch ? !parent_known(w, set, up) : !parent_known(w, set, m->parent))
        return tg_fail(e, "PARENT_UNKNOWN", "%s: branch %s does not exist", m->source,
                       m->has_branch ? up : m->parent);
    return true;
}

static bool graph_clash(const struct tg_manifest *a, const struct tg_manifest *b, struct tg_err *e)
{
    if (strcmp(b->path, a->parent) != 0)
        return true;
    if (a->has_branch)
        return tg_fail(e, "COLLISION_BRANCH", "%s declares branch %s, which is the command path of %s",
                       a->source, a->parent, b->source);
    return tg_fail(e, "PARENT_IS_LEAF", "%s has parent %s, which is the command path of %s",
                   a->source, a->parent, b->source);
}

static bool check_pairs(const struct tg_set *set, struct tg_err *e)
{
    for (size_t i = 0; i < set->n; i++)
        for (size_t j = 0; j < i; j++)
            if (!pair_clash(&set->m[j], &set->m[i], e) ||
                !graph_clash(&set->m[j], &set->m[i], e) ||
                !graph_clash(&set->m[i], &set->m[j], e))
                return false;
    return true;
}

static bool check_names(const char *root, struct tg_set *set, struct tg_err *e)
{
    struct tg_world w;
    if (!check_pairs(set, e) || !tg_world_load(root, &w, e))
        return false;
    bool ok = true;
    for (size_t i = 0; ok && i < set->n; i++)
        ok = world_clash(&w, set, &set->m[i], e);
    tg_world_free(&w);
    return ok;
}

/* Dot files are skipped, as in the authored-world scan. Other names must be
 * plain: a name is copied into generated comments. */
static bool add_source_name(struct tg_names *names, const char *name, struct tg_err *e)
{
    size_t n = strlen(name);
    if (name[0] == '.' || n <= 2u || strcmp(name + n - 2u, ".c") != 0)
        return true;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)name[i];
        if (!(isalnum(c) || c == '_' || c == '-' || c == '.'))
            return tg_fail(e, "SOURCE_NAME_BAD", "source name \"%s\" has a character outside [A-Za-z0-9_.-]", name);
    }
    if (n > 120u)
        return tg_fail(e, "SOURCE_NAME_BAD", "source name \"%s\" is longer than 120 bytes", name);
    return tg_names_add(names, name, n) || tg_fail(e, "IO_ERROR", "out of memory listing sources");
}

bool tg_gather(const char *root, struct tg_set *set, struct tg_err *e)
{
    set->n = 0;
    char dir[1024];
    if (!tg_join(dir, sizeof dir, root, SOURCE_DIR))
        return tg_fail(e, "IO_ERROR", "path too long");
    struct tg_names names = {0};
    DIR *d = opendir(dir);
    if (!d)
        return tg_fail(e, "IO_ERROR", "cannot list %s", SOURCE_DIR);
    struct dirent *de;
    bool ok = true;
    while (ok && (de = readdir(d)) != NULL)
        ok = add_source_name(&names, de->d_name, e);
    closedir(d);
    if (!ok) {
        tg_names_free(&names);
        return false;
    }
    tg_names_sort(&names);
    for (size_t i = 0; ok && i < names.n; i++)
        ok = scan_source(root, names.v[i], set, e);
    tg_names_free(&names);
    if (ok)
        qsort(set->m, set->n, sizeof set->m[0], by_path);
    return ok && check_names(root, set, e);
}
