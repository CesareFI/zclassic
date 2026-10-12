/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Facts extension records (symbols, references, unknown effects, namespace probes) shared by both semantic manifest producers. */
#include "clang_manifest_core.h"

#include "base/hex.h"
#include "base/safe_alloc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char *cm_id(char prefix, const char *path, const char *name, uint8_t linkage)
{
    size_t n = (path != NULL ? strlen(path) : 0) + strlen(name) + 8;
    char *out = zcl_malloc(n, "clang_manifest.id");
    if (out != NULL &&
        !vcs_semantic_id_v1(prefix, path, name, linkage == 3 || linkage == 4,
                            out, n)) {
        free(out);
        out = NULL;
    }
    return out;
}

bool cm_symbol(struct cm_core *c, const char *id, const char *path,
               const char *kind, uint8_t linkage, bool defined)
{
    struct vcs_semantic_record_v1 rec = {0};
    bool ok;
    if (!c->facts || id == NULL)
        return true;
    vcs_semantic_record_v1_cstr(&rec, id);
    vcs_semantic_record_v1_cstr(&rec, path);
    vcs_semantic_record_v1_cstr(&rec, kind);
    vcs_semantic_record_v1_u8(&rec, linkage);
    vcs_semantic_record_v1_u8(&rec, defined ? 1 : 0);
    ok = cm_add(c, VCS_SEMANTIC_SECTION_V1_SYMBOLS, &rec);
    vcs_semantic_record_v1_free(&rec);
    return ok;
}

bool cm_ref(struct cm_core *c, const char *from, uint8_t kind, const char *to)
{
    struct vcs_semantic_record_v1 rec = {0};
    bool ok;
    if (!c->facts || from == NULL || to == NULL)
        return true;
    vcs_semantic_record_v1_cstr(&rec, from);
    vcs_semantic_record_v1_u8(&rec, kind);
    vcs_semantic_record_v1_cstr(&rec, to);
    ok = cm_add(c, VCS_SEMANTIC_SECTION_V1_REFS, &rec);
    vcs_semantic_record_v1_free(&rec);
    return ok;
}

bool cm_unknown(struct cm_core *c, const char *site, uint8_t kind,
                const char *detail)
{
    struct cm_occurrence *o;
    if (!c->facts || site == NULL)
        return true;
    if (!cm_grow((void **)&c->occ, &c->capocc, c->nocc, sizeof(*c->occ)))
        return cm_fail(c, "out of memory");
    o = &c->occ[c->nocc];
    o->site = cm_strdup(site);
    o->detail = cm_strdup(detail != NULL ? detail : "");
    o->kind = kind;
    if (o->site == NULL || o->detail == NULL) {
        free(o->site);
        free(o->detail);
        return cm_fail(c, "out of memory");
    }
    c->nocc++;
    return true;
}

static int cm_occ_cmp(const void *x, const void *y)
{
    const struct cm_occurrence *a = x, *b = y;
    int r = strcmp(a->site, b->site);
    if (r != 0)
        return r;
    if (a->kind != b->kind)
        return a->kind < b->kind ? -1 : 1;
    return strcmp(a->detail, b->detail);
}

/* One UNKNOWNS record per (site, kind, detail), with its occurrence count. */
static bool cm_emit_unknowns(struct cm_core *c)
{
    struct vcs_semantic_record_v1 rec = {0};
    bool ok = true;
    if (c->nocc > 1)
        qsort(c->occ, c->nocc, sizeof(*c->occ), cm_occ_cmp);
    for (size_t k = 0; ok && k < c->nocc;) {
        size_t j = k + 1;
        while (j < c->nocc && cm_occ_cmp(&c->occ[k], &c->occ[j]) == 0)
            j++;
        vcs_semantic_record_v1_reset(&rec);
        vcs_semantic_record_v1_cstr(&rec, c->occ[k].site);
        vcs_semantic_record_v1_u8(&rec, c->occ[k].kind);
        vcs_semantic_record_v1_cstr(&rec, c->occ[k].detail);
        vcs_semantic_record_v1_u32(&rec, (uint32_t)(j - k));
        ok = cm_add(c, VCS_SEMANTIC_SECTION_V1_UNKNOWNS, &rec);
        k = j;
    }
    vcs_semantic_record_v1_free(&rec);
    return ok;
}

static bool cm_hex_decode(const char *hex, uint8_t out[32])
{
    return hex != NULL && strlen(hex) == 64 && zcl_hex_decode(hex, out, 32);
}

/* A missing snapshot is not a refusal: every negative claim then carries the
 * NO_SNAPSHOT reason instead. A named snapshot that cannot be loaded or does
 * not hash to its name IS a refusal. */
bool cm_facts_begin(struct cm_core *c, const char *tree_hex)
{
    uint8_t tree[32];
    char why[256];
    c->facts = true;
    c->ns_bound = false;
    if (tree_hex == NULL || tree_hex[0] == '\0')
        return true;
    if (!cm_hex_decode(tree_hex, tree))
        return cm_fail(c, "snapshot tree is not 64 hex characters");
    if (!vcs_semantic_namespace_v1_load(c->root, tree, &c->ns, why, sizeof(why)))
        return cm_fail(c, "snapshot %s: %s", tree_hex, why);
    c->ns_bound = true;
    for (size_t k = 0; k < c->nfiles; k++) {
        const struct cm_file *f = &c->files[k];
        if (f->origin == VCS_SEMANTIC_ORIGIN_V1_SYSTEM)
            continue;
        if (!vcs_semantic_namespace_v1_binds(c->ns, f->path,
                                             (const uint8_t *)f->contents,
                                             f->size)) {
            c->ns_bound = false;
            break;
        }
    }
    return true;
}

/* Canonical directory of a manifest path: "." for a top-level file. */
static void cm_dirname(const char *path, char out[PATH_MAX])
{
    const char *slash = strrchr(path, '/');
    if (slash == NULL)
        (void)snprintf(out, PATH_MAX, ".");
    else
        (void)snprintf(out, PATH_MAX, "%.*s", (int)(slash - path), path);
}

static const char *cm_slot_path(const struct cm_core *c, uint8_t form,
                                const char *slot0, uint32_t slot)
{
    if (form == VCS_SEMANTIC_FORM_V1_QUOTED) {
        if (slot == 0)
            return slot0;
        slot -= 1;
        if (slot < c->quote.n)
            return c->quote.items[slot].path;
        slot -= (uint32_t)c->quote.n;
    }
    return slot < c->angled.n ? c->angled.items[slot].path : NULL;
}

static uint8_t cm_slot_reason(const struct cm_core *c, const char *dir,
                              const char *name)
{
    if (dir == NULL)
        return VCS_SEMANTIC_PROBE_V1_UNRESOLVED;
    if (c->ns == NULL)
        return VCS_SEMANTIC_PROBE_V1_NO_SNAPSHOT;
    if (!c->ns_bound)
        return strncmp(dir, "@sys", 4) == 0 ? VCS_SEMANTIC_PROBE_V1_OUTSIDE
                                            : VCS_SEMANTIC_PROBE_V1_STALE;
    return vcs_semantic_namespace_v1_absent(c->ns, dir, name);
}

static bool cm_is_present(const uint32_t *present, size_t n, uint32_t slot)
{
    for (size_t k = 0; k < n; k++) {
        if (present[k] == slot)
            return true;
    }
    return false;
}

bool cm_emit_probe(struct cm_core *c, const struct cm_file *includer,
                   const char *spelled, uint8_t form, uint8_t kind, bool claim,
                   uint32_t hit_slot, const uint32_t *present, size_t npresent)
{
    struct vcs_semantic_record_v1 rec = {0}, slots = {0};
    char slot0[PATH_MAX];
    uint32_t nunknown = 0;
    bool ok;
    cm_dirname(includer->path, slot0);
    for (uint32_t s = 0; claim && s < hit_slot; s++) {
        uint8_t reason;
        if (cm_is_present(present, npresent, s))
            continue;
        reason = cm_slot_reason(c, cm_slot_path(c, form, slot0, s), spelled);
        if (reason == 0)
            continue;
        vcs_semantic_record_v1_u32(&slots, s);
        vcs_semantic_record_v1_u8(&slots, reason);
        nunknown++;
    }
    vcs_semantic_record_v1_cstr(&rec, includer->path);
    vcs_semantic_record_v1_cstr(&rec, spelled);
    vcs_semantic_record_v1_u8(&rec, form);
    vcs_semantic_record_v1_u8(&rec, kind);
    vcs_semantic_record_v1_u8(&rec, claim ? 1 : 0);
    vcs_semantic_record_v1_u32(&rec, nunknown);
    for (size_t k = 0; k < slots.len; k++)
        vcs_semantic_record_v1_u8(&rec, slots.bytes[k]);
    ok = !slots.failed && cm_add(c, VCS_SEMANTIC_SECTION_V1_PROBES, &rec);
    vcs_semantic_record_v1_free(&rec);
    vcs_semantic_record_v1_free(&slots);
    return ok;
}

bool cm_emit_facts(struct cm_core *c, uint32_t max_records,
                   uint64_t max_section_bytes)
{
    struct vcs_semantic_facts_v1 f = {
        .max_records = max_records ? max_records
                                   : VCS_SEMANTIC_FACTS_V1_DEFAULT_MAX_RECORDS,
        .max_section_bytes = max_section_bytes
                                 ? max_section_bytes
                                 : VCS_SEMANTIC_FACTS_V1_DEFAULT_MAX_SECTION_BYTES,
        /* This producer writes the @scope, @cond and @assert sites
         * (records.c, cond.c, ast.c) and names anonymous members' records
         * (ast.c). */
        .revision = 4,
    };
    if (!c->facts)
        return true;
    if (c->ns != NULL && c->ns_bound)
        memcpy(f.namespace_root, vcs_semantic_namespace_v1_root(c->ns), 32);
    /* Darwin requires byte-bound image and type-grammar identity before
     * emitting facts. Other platforms retain the unknown-producer signal. */
#if defined(__APPLE__)
    if (!c->producer_before_valid)
        return cm_fail(c, "darwin producer image identity unavailable");
    memcpy(f.producer, c->producer_before, sizeof(f.producer));
#else
    (void)cm_producer_digest(c->type_grammar, f.producer);
#endif
    if (!vcs_semantic_builder_v1_enable_facts(c->b, &f))
        return cm_fail(c, "facts caps out of range");
    return cm_emit_unknowns(c);
}
