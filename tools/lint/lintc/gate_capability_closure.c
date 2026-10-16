/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: evidence stage of the capability-closure gate in C23. Loads the symbol and
 * module tables, freezes the object list of the newest build epoch, runs nm over it
 * once and enforces the object and coverage floors, so a hollow or partial epoch is
 * UNPROVEN (exit 2). The grading passes follow in the next steps. Output strings are
 * those of the shell gate this replaces.
 */
#define _POSIX_C_SOURCE 200809L
#include <dirent.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include "base/safe_alloc.h"
#include "gate_capability_closure_priv.h"
#include "lintc.h"

#define CCG_DASH "\xe2\x80\x94"

/* Anti-hollow floor: a tree below it is refused, never reported clean. */
enum { CCG_MIN_OBJECTS = 500, CCG_FOREIGN_SHOWN = 5, CCG_UNOBS_SHOWN = 20 };

/* Declared rows with no compiled object anywhere in a complete epoch: the
 * standalone tools tests/harness/src/test_thread_qos.c and
 * tools/rebuild_recent.c, which neither z23-dev nor the package verifier
 * links. Shrink-only: a lower measurement must lower this in the same commit. */
enum { CCG_HOST_BASELINE = 2 };

static const char k_ccg_nm_long[] = " Likely a concurrent build rewriting\n"
                                    "  an object underneath this scan. Refusing to trust a partial read:\n";
static const char k_ccg_nm_short[] = " Refusing to trust a partial read:\n";

struct ccg_list { char **s; size_t n, cap; };

struct ccg_counts { int unobserved, excluded; };

struct ccg_scan {
    const struct ccg_cfg *cfg;
    const char *root;
    char epoch[CCD_PATH];
    struct ccd_map sym, compiled, defined, undef, foreign;
    size_t n_sym;
    struct ccd_mods mods;
    struct ccg_list objs, unobs;
    struct ccd_nm nm;
    struct ccg_counts c;
};

static void ccg_say(const struct ccg_scan *s, const char *fmt, ...) __attribute__((format(printf, 2, 3)));

static void ccg_say(const struct ccg_scan *s, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vfprintf(s->cfg->out, fmt, ap);
    va_end(ap);
}

static int ccg_list_add(struct ccg_list *l, const char *str)
{
    if (l->n == l->cap) {
        size_t cap = l->cap ? l->cap * 2 : 64;
        char **p = zcl_realloc(l->s, cap * sizeof *p, "ccg_list");
        if (!p)
            return -1;
        l->s = p;
        l->cap = cap;
    }
    l->s[l->n] = zcl_strdup(str, "ccg_list item");
    return l->s[l->n++] ? 0 : -1;
}

static void ccg_list_free(struct ccg_list *l)
{
    for (size_t i = 0; i < l->n; i++)
        free(l->s[i]);
    free(l->s);
    *l = (struct ccg_list){ 0 };
}

static void ccg_free(struct ccg_scan *s)
{
    ccd_map_free(&s->sym);
    ccd_map_free(&s->compiled);
    ccd_map_free(&s->defined);
    ccd_map_free(&s->undef);
    ccd_map_free(&s->foreign);
    ccd_mods_free(&s->mods);
    ccd_nm_free(&s->nm);
    ccg_list_free(&s->objs);
    ccg_list_free(&s->unobs);
}

static int ccg_is_file(const char *root, const char *rel)
{
    char path[CCD_PATH];
    struct stat st;
    return snprintf(path, sizeof path, "%s/%s", root, rel) < (int)sizeof path && stat(path, &st) == 0
           && S_ISREG(st.st_mode);
}

static int ccg_has_suffix(const char *name, const char *suffix)
{
    size_t n = strlen(name), k = strlen(suffix);
    return n >= k && strcmp(name + n - k, suffix) == 0;
}

/* "dir/x.o" becomes "dir/x.c"; any other name is kept. */
static void ccg_c_of(const char *obj, char *out, size_t cap)
{
    if (ccg_has_suffix(obj, ".o"))
        snprintf(out, cap, "%.*s.c", (int)(strlen(obj) - 2), obj);
    else
        snprintf(out, cap, "%s", obj);
}

static int ccg_walk(const char *base, const char *rel, const char *suffix, struct ccd_map *out);

/* One directory entry: recurse into a directory, take a name with the suffix.
 * Symbolic links are not followed. */
static int ccg_walk_entry(const char *base, const char *rel, const char *name, const char *suffix,
                          struct ccd_map *out)
{
    char r[CCD_PATH], p[CCD_PATH];
    struct stat st;
    if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0)
        return 0;
    if (snprintf(r, sizeof r, "%s%s%s", rel, rel[0] ? "/" : "", name) >= (int)sizeof r
        || snprintf(p, sizeof p, "%s/%s", base, r) >= (int)sizeof p || lstat(p, &st) != 0)
        return 0;
    if (S_ISDIR(st.st_mode))
        return ccg_walk(base, r, suffix, out);
    return ccg_has_suffix(name, suffix) ? ccd_map_put(out, r, "") : 0;
}

/* Collects the base-relative names under base/rel that end in suffix. */
static int ccg_walk(const char *base, const char *rel, const char *suffix, struct ccd_map *out)
{
    char dir[CCD_PATH];
    DIR *d;
    int rc = 0;
    if (snprintf(dir, sizeof dir, "%s/%s", base, rel) >= (int)sizeof dir || !(d = opendir(dir)))
        return 0;
    for (struct dirent *e; rc == 0 && (e = readdir(d));)
        rc = ccg_walk_entry(base, rel, e->d_name, suffix, out);
    closedir(d);
    return rc;
}

static int ccg_fatal(const struct ccg_scan *s, const char *what, const char *path)
{
    ccg_say(s, "check_capability_closure: FATAL " CCG_DASH " %s %s\n", what, path);
    return 2;
}

static int ccg_tables(struct ccg_scan *s)
{
    char sym[CCD_PATH], mod[CCD_PATH], plat[CCD_PATH];
    const char *pn = s->cfg->os == CCD_LINUX ? "linux" : s->cfg->os == CCD_WINDOWS ? "windows" : NULL;
    if (snprintf(sym, sizeof sym, "%s/engine/composition/capability_symbols.def", s->root) >= (int)sizeof sym
        || snprintf(mod, sizeof mod, "%s/engine/composition/module_capabilities.def", s->root) >= (int)sizeof mod
        || snprintf(plat, sizeof plat, "%s/engine/composition/module_capabilities_%s.def", s->root,
                    pn ? pn : "") >= (int)sizeof plat)
        return ccg_fatal(s, "cannot read", s->root);
    if (ccd_symbols_load(sym, s->cfg->os == CCD_WINDOWS, &s->sym, &s->n_sym) != 0) {
        ccg_fatal(s, "cannot read", sym);
        ccg_say(s, "  This file is the symbol->class table; without it, closure and\n"
                   "  declaration cannot be checked at all. Refusing to report clean\n"
                   "  off input this script cannot see.\n");
        return 2;
    }
    if (s->n_sym < 1) {
        ccg_fatal(s, "parsed 0 rows from", sym);
        ccg_say(s, "  Either the file is empty or this script's parser no longer\n"
                   "  matches its ZCL_CAPABILITY_SYMBOL(...) shape. Refusing to\n"
                   "  report clean off a scan that saw nothing.\n");
        return 2;
    }
    if (ccd_modules_load(mod, pn ? plat : NULL, s->root, &s->mods) != 0) {
        if (s->mods.error[0])
            fprintf(s->cfg->err, "%s\n", s->mods.error);
        return ccg_fatal(s, "cannot read", mod);
    }
    return 0;
}

/* Keeps an object whose translation unit exists here (or is generated under
 * build/); a leftover of a failed candidate is foreign and never graded. */
static int ccg_grade_object(struct ccg_scan *s, const char *rel)
{
    char src[CCD_PATH], abs[CCD_PATH];
    const char *slash = strrchr(rel, '/');
    if (strcmp(slash ? slash + 1 : rel, "restart-base.o") == 0)
        return 0;
    ccg_c_of(rel, src, sizeof src);
    if (!ccg_is_file(s->root, src) && strncmp(rel, "build/", 6) != 0)
        return ccd_map_put(&s->foreign, rel, "");
    if (snprintf(abs, sizeof abs, "%s/%s", s->epoch, rel) >= (int)sizeof abs)
        return -1;
    return ccd_map_put(&s->compiled, src, "") || ccg_list_add(&s->objs, abs) ? -1 : 0;
}

static void ccg_foreign_report(const struct ccg_scan *s)
{
    if (s->foreign.n == 0)
        return;
    ccg_say(s, "check_capability_closure: %zu foreign object(s) under %s\n"
               "  have no source in this tree (a failed candidate's leftovers);\n"
               "  not graded. First %d:\n", s->foreign.n, s->epoch, CCG_FOREIGN_SHOWN);
    for (size_t i = 0; i < s->foreign.n && i < CCG_FOREIGN_SHOWN; i++)
        ccg_say(s, "    %s\n", s->foreign.ent[i].key);
}

/* Freezes the object list once, so a build running underneath cannot change
 * the evidence set. */
static int ccg_objects(struct ccg_scan *s)
{
    struct ccd_map rel = { 0 };
    int rc = ccd_find_epoch(s->root, s->epoch, sizeof s->epoch);
    if (rc <= 0) {
        ccg_say(s, "check_capability_closure: UNPROVEN " CCG_DASH " no build/dev-obj/epochs/* found.\n"
                   "  Populate it with the normal dev build (e.g. 'make z23-dev') and\n"
                   "  re-run. Never treat an absent object tree as zero violations.\n");
        return 2;
    }
    rc = ccg_walk(s->epoch, "", ".o", &rel);
    for (size_t i = 0; rc == 0 && i < rel.n; i++)
        rc = ccg_grade_object(s, rel.ent[i].key);
    ccd_map_free(&rel);
    if (rc != 0)
        return ccg_fatal(s, "out of memory scanning", s->epoch);
    ccg_foreign_report(s);
    if (s->objs.n < CCG_MIN_OBJECTS) {
        ccg_say(s, "check_capability_closure: UNPROVEN " CCG_DASH " %s holds only %zu\n"
                   "  production objects (floor %d).\n"
                   "  A stale or partial build epoch, not a clean scan.\n", s->epoch, s->objs.n, CCG_MIN_OBJECTS);
        return 2;
    }
    return 0;
}

static void ccg_indent(const struct ccg_scan *s, const char *text)
{
    for (const char *p = text ? text : ""; *p;) {
        const char *nl = strchr(p, '\n');
        size_t n = nl ? (size_t)(nl - p) : strlen(p);
        ccg_say(s, "    %.*s\n", (int)n, p);
        p += n + (nl != NULL);
    }
}

/* The status xargs reports for the nm it would have run. */
static int ccg_xargs_rc(int rc)
{
    if (rc == 126 || rc == 127)
        return rc;
    return rc == 255 ? 124 : rc > 127 ? 125 : rc ? 123 : 0;
}

/* A concurrent rewrite of an object makes nm fail or complain while it still
 * lists the objects that read cleanly: trust no row of such a scan. */
static int ccg_nm_unproven(const struct ccg_scan *s, const struct ccd_nm *nm, const char *pass, const char *tail)
{
    ccg_say(s, "check_capability_closure: UNPROVEN " CCG_DASH " nm reported an error scanning\n"
               "  %s (%src=%d).%s", s->epoch, pass, ccg_xargs_rc(nm->rc), tail);
    ccg_indent(s, nm->err);
    return 2;
}

static int ccg_is_undef(const char *type)
{
    return strcmp(type, "U") == 0 || strcmp(type, "w") == 0 || strcmp(type, "v") == 0;
}

/* Names defined in this tree and names referenced undefined (U, w and v alike:
 * a weak reference is still a reach). Without a defined-only listing the full
 * one already holds both sides. */
static int ccg_name_sets(struct ccg_scan *s, const struct ccd_nm *def)
{
    for (size_t i = 0; i < s->nm.n; i++) {
        const struct ccd_nmrow *r = &s->nm.row[i];
        struct ccd_map *to = ccg_is_undef(r->type) ? &s->undef : def ? NULL : &s->defined;
        if (to && ccd_map_put(to, r->name, "") != 0)
            return -1;
    }
    for (size_t i = 0; def && i < def->n; i++)
        if (ccd_map_put(&s->defined, def->row[i].name, "") != 0)
            return -1;
    return 0;
}

static int ccg_nm_defined(struct ccg_scan *s, struct ccd_nm *def)
{
    int rc = ccd_run_nm(s->objs.s, s->objs.n, 1, 0, s->cfg->strip, def);
    return rc == 0 && ccd_nm_failed(def) ? ccg_nm_unproven(s, def, "defined-only ", k_ccg_nm_short) : rc;
}

/* Never `nm -u`: Apple nm drops the type column there, so strong and weak
 * references cannot be told apart. */
static int ccg_nm(struct ccg_scan *s)
{
    struct ccd_nm def = { 0 };
    int one = s->cfg->os == CCD_LINUX;
    int rc = ccd_run_nm(s->objs.s, s->objs.n, 0, 0, s->cfg->strip, &s->nm);
    if (rc == 0 && ccd_nm_failed(&s->nm))
        rc = ccg_nm_unproven(s, &s->nm, "", k_ccg_nm_long);
    else if (rc == 0 && !one)
        rc = ccg_nm_defined(s, &def);
    if (rc == 0 && ccg_name_sets(s, one ? NULL : &def) != 0)
        rc = -1;
    if (rc < 0)
        ccg_fatal(s, "cannot run nm over", s->epoch);
    ccd_nm_free(&def);
    return rc ? 2 : 0;
}

static void ccg_coverage_scan(struct ccg_scan *s)
{
    for (size_t i = 0; i < s->mods.raw.n; i++) {
        const char *path = s->mods.raw.ent[i].key;
        if (!ccg_is_file(s->root, path))
            continue;
        if (!ccd_coverage_applicable(s->cfg->os, path))
            s->c.excluded++;
        else if (!ccd_map_get(&s->compiled, path) && ccg_list_add(&s->unobs, path) == 0)
            s->c.unobserved++;
    }
}

/* A partial epoch (a z23-dev-only rebuild) holds thousands of objects yet
 * silently misses declared files; more of those than the baseline allows is
 * a scan that did not happen. */
static int ccg_coverage_floor(struct ccg_scan *s)
{
    ccg_coverage_scan(s);
    if (s->c.unobserved <= s->cfg->baseline)
        return 0;
    ccg_say(s, "check_capability_closure: UNPROVEN " CCG_DASH " %d module_capabilities.def\n"
               "  row(s) have no compiled object anywhere in %s " CCG_DASH " above the\n"
               "  shrink-only coverage baseline of %ld.\n"
               "  This looks like a PARTIAL epoch (e.g. a 'make z23-dev'-only\n"
               "  rebuild), not a scan complete enough to grade. 'I scanned an\n"
               "  incomplete epoch' is not a pass and it is not a violation; it is\n"
               "  a scan that did not happen. Missing (first %d of %d):\n",
            s->c.unobserved, s->epoch, s->cfg->baseline, CCG_UNOBS_SHOWN, s->c.unobserved);
    for (size_t i = 0; i < s->unobs.n && i < CCG_UNOBS_SHOWN; i++)
        ccg_say(s, "    %s\n", s->unobs.s[i]);
    if (s->c.unobserved > CCG_UNOBS_SHOWN)
        ccg_say(s, "    ... and %d more\n", s->c.unobserved - CCG_UNOBS_SHOWN);
    ccg_say(s, "  Build a COMPLETE epoch and re-run:\n"
               "    tools/dev/checkout-lock.sh foreground build/.checkout.lock -- \\\n"
               "      %s\n", s->cfg->os == CCD_WINDOWS ? "make -j16 z23-dev"
                                                      : "make -j16 build/bin/z23-dev build/bin/z23-package-verify-dev");
    return 2;
}

/* Collects the evidence of one tree; 0 when the floors hold, 2 when the scan is unproven. */
int ccg_check_root(const struct ccg_cfg *cfg, const char *root)
{
    struct ccg_scan s = { .cfg = cfg, .root = root };
    int rc = ccg_tables(&s);
    rc = rc ? rc : ccg_objects(&s);
    rc = rc ? rc : ccg_nm(&s);
    rc = rc ? rc : ccg_coverage_floor(&s);
    ccg_free(&s);
    return rc;
}

static const char *ccg_env(const char *name, const char *fallback)
{
    const char *v = getenv(name);
    return v && v[0] ? v : fallback;
}

static enum ccd_os ccg_host_os(void)
{
    struct utsname u;
    if (uname(&u) != 0)
        return CCD_OTHER;
    if (strcmp(u.sysname, "Linux") == 0)
        return CCD_LINUX;
    if (strcmp(u.sysname, "Darwin") == 0)
        return CCD_DARWIN;
    if (strncmp(u.sysname, "MINGW", 5) == 0 || strncmp(u.sysname, "MSYS", 4) == 0
        || strncmp(u.sysname, "CYGWIN", 6) == 0)
        return CCD_WINDOWS;
    return CCD_OTHER;
}

/* Linux produced the declaration snapshot and stays the symmetry authority;
 * Darwin still enforces closure and every undeclared reach. */
void ccg_host_cfg(struct ccg_cfg *cfg)
{
    char base[16];
    snprintf(base, sizeof base, "%d", CCG_HOST_BASELINE);
    cfg->os = ccg_host_os();
    cfg->strip = cfg->os == CCD_DARWIN;
    cfg->baseline = strtol(ccg_env("ZCL_CAP_CLOSURE_COVERAGE_BASELINE", base), NULL, 10);
    cfg->out = stdout;
    cfg->err = stderr;
}

int check_capability_closure_run(int argc, char **argv)
{
    return die("z23-lint: check-capability-closure has a selftest only until its grading passes land: %s\n",
               argc > 0 ? argv[0] : "use --selftest");
}
