/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Declaration, layout, enum, macro and function records shared by both semantic manifest producers. */
#include "clang_manifest_core.h"

#include "base/safe_alloc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

bool cm_emit_decl(struct cm_core *c, const struct cm_file *f, const char *kind,
                  const char *name, const char *type, uint8_t linkage)
{
    struct vcs_semantic_record_v1 rec = {0};
    bool ok;
    vcs_semantic_record_v1_cstr(&rec, f->path);
    vcs_semantic_record_v1_cstr(&rec, kind);
    vcs_semantic_record_v1_cstr(&rec, name);
    vcs_semantic_record_v1_cstr(&rec, type);
    vcs_semantic_record_v1_u8(&rec, linkage);
    ok = cm_add(c, VCS_SEMANTIC_SECTION_V1_DECLS, &rec);
    vcs_semantic_record_v1_free(&rec);
    return ok;
}

bool cm_emit_layout(struct cm_core *c, const struct cm_file *f,
                    const char *name, uint8_t kind, uint64_t size,
                    uint64_t align, const struct cm_field *fields,
                    size_t nfields)
{
    struct vcs_semantic_record_v1 rec = {0};
    bool ok;
    vcs_semantic_record_v1_cstr(&rec, f->path);
    vcs_semantic_record_v1_cstr(&rec, name);
    vcs_semantic_record_v1_u8(&rec, kind);
    vcs_semantic_record_v1_u64(&rec, size);
    vcs_semantic_record_v1_u64(&rec, align);
    vcs_semantic_record_v1_u32(&rec, (uint32_t)nfields);
    for (size_t k = 0; k < nfields; k++) {
        vcs_semantic_record_v1_cstr(&rec, fields[k].name);
        vcs_semantic_record_v1_u64(&rec, fields[k].offset_bits);
        vcs_semantic_record_v1_u32(&rec, fields[k].bit_width);
        vcs_semantic_record_v1_cstr(&rec, fields[k].type);
    }
    ok = cm_add(c, VCS_SEMANTIC_SECTION_V1_LAYOUTS, &rec);
    vcs_semantic_record_v1_free(&rec);
    return ok;
}

bool cm_emit_enum(struct cm_core *c, const struct cm_file *f,
                  const char *enum_name, const char *constant, int64_t value)
{
    struct vcs_semantic_record_v1 rec = {0};
    bool ok;
    vcs_semantic_record_v1_cstr(&rec, f->path);
    vcs_semantic_record_v1_cstr(&rec, enum_name);
    vcs_semantic_record_v1_cstr(&rec, constant);
    vcs_semantic_record_v1_i64(&rec, value);
    ok = cm_add(c, VCS_SEMANTIC_SECTION_V1_ENUMS, &rec);
    vcs_semantic_record_v1_free(&rec);
    return ok;
}

/* A definition is function-like exactly when '(' follows its name with no
 * space between (C23 6.10.4). Read from the definition's own bytes: the
 * front end's end-of-TU macro table would answer for the LAST definition
 * of the name, or not at all after an #undef. */
static bool cm_function_like(const struct cm_file *f, unsigned offset,
                             size_t name_len)
{
    size_t at = (size_t)offset + name_len;
    return f->contents != NULL && at < f->size && f->contents[at] == '(';
}

bool cm_macro_def(struct cm_core *c, const struct cm_file *f, unsigned offset,
                  char *name, char *body)
{
    struct cm_macro *m;
    if (name == NULL || body == NULL ||
        !cm_grow((void **)&c->macros, &c->capmacros, c->nmacros,
                 sizeof(*c->macros))) {
        free(name);
        free(body);
        return cm_fail(c, "out of memory");
    }
    m = &c->macros[c->nmacros++];
    *m = (struct cm_macro){
        .name = name, .path = f->path, .body = body,
        .function_like = cm_function_like(f, offset, strlen(name)) ? 1 : 0};
    return true;
}

bool cm_macro_exp(struct cm_core *c, const struct cm_file *f, unsigned offset,
                  unsigned end, char *name, char *def_id)
{
    struct cm_expansion *e;
    if (name == NULL ||
        !cm_grow((void **)&c->exps, &c->capexps, c->nexps, sizeof(*c->exps))) {
        free(name);
        free(def_id);
        return cm_fail(c, "out of memory");
    }
    e = &c->exps[c->nexps++];
    *e = (struct cm_expansion){.file = f, .offset = offset,
                               .end = end < offset ? offset : end,
                               .name = name, .def_id = def_id};
    return true;
}

const char *cm_assert_add(struct cm_core *c, const struct cm_file *f,
                          unsigned begin, unsigned end)
{
    size_t n = strlen(VCS_SEMANTIC_FACTS_ASSERT_SITE) + strlen(f->path) + 1;
    char *site = zcl_malloc(n, "clang_manifest.assert_site");
    if (site == NULL ||
        !cm_grow((void **)&c->asserts, &c->capasserts, c->nasserts,
                 sizeof(*c->asserts))) {
        free(site);
        (void)cm_fail(c, "out of memory");
        return NULL;
    }
    (void)snprintf(site, n, "%s%s", VCS_SEMANTIC_FACTS_ASSERT_SITE, f->path);
    c->asserts[c->nasserts++] = (struct cm_assert){
        .file = f, .site = site, .begin = begin,
        .end = end < begin ? begin : end};
    return site;
}

struct cm_function *cm_function_add(struct cm_core *c,
                                    const struct cm_function *fn)
{
    if (!cm_grow((void **)&c->fns, &c->capfns, c->nfns, sizeof(*c->fns))) {
        (void)cm_fail(c, "out of memory");
        return NULL;
    }
    c->fns[c->nfns] = *fn;
    return &c->fns[c->nfns++];
}

bool cm_function_callee(struct cm_core *c, struct cm_function *fn,
                        const char *name)
{
    char *s = cm_strdup(name);
    if (s == NULL || !cm_grow((void **)&fn->callees, &fn->capcallees,
                              fn->ncallees, sizeof(*fn->callees))) {
        free(s);
        return cm_fail(c, "out of memory");
    }
    fn->callees[fn->ncallees++] = s;
    return true;
}

/* ---- deferred emission (needs every expansion) ------------------------------------ */

static int cm_exp_cmp(const void *x, const void *y)
{
    const struct cm_expansion *a = x, *b = y;
    if (a->file != b->file)
        return a->file < b->file ? -1 : 1;
    return a->offset < b->offset ? -1 : a->offset > b->offset;
}

static int cm_str_cmp(const void *x, const void *y)
{
    return strcmp(*(const char *const *)x, *(const char *const *)y);
}

static bool cm_emit_macros(struct cm_core *c, char **used, size_t nused)
{
    struct vcs_semantic_record_v1 rec = {0};
    bool ok = true;
    for (size_t k = 0; ok && k < c->nmacros; k++) {
        const struct cm_macro *m = &c->macros[k];
        const char *key = m->name;
        bool is_used = bsearch(&key, used, nused, sizeof(*used), cm_str_cmp) != NULL;
        vcs_semantic_record_v1_reset(&rec);
        vcs_semantic_record_v1_cstr(&rec, m->path);
        vcs_semantic_record_v1_cstr(&rec, m->name);
        vcs_semantic_record_v1_u8(&rec, m->function_like);
        vcs_semantic_record_v1_cstr(&rec, m->body);
        vcs_semantic_record_v1_u8(&rec, is_used ? 1 : 0);
        ok = cm_add(c, VCS_SEMANTIC_SECTION_V1_MACROS, &rec);
    }
    vcs_semantic_record_v1_free(&rec);
    return ok;
}

/* First expansion at or after (file, offset) in the sorted expansion list. */
static size_t cm_exp_lower(const struct cm_core *c, const struct cm_file *f,
                           unsigned offset)
{
    size_t lo = 0, hi = c->nexps;
    struct cm_expansion key = {.file = f, .offset = offset};
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (cm_exp_cmp(&c->exps[mid], &key) < 0)
            lo = mid + 1;
        else
            hi = mid;
    }
    return lo;
}

static bool cm_emit_span(struct cm_core *c, const struct cm_function *fn)
{
    struct vcs_semantic_record_v1 rec = {0};
    bool ok;
    vcs_semantic_record_v1_cstr(&rec, fn->file->path);
    vcs_semantic_record_v1_cstr(&rec, fn->name);
    vcs_semantic_record_v1_u32(&rec, fn->begin_line);
    vcs_semantic_record_v1_u32(&rec, fn->end_line);
    vcs_semantic_record_v1_u64(&rec, fn->begin_off);
    vcs_semantic_record_v1_u64(&rec, fn->end_off);
    ok = cm_add(c, VCS_SEMANTIC_SECTION_V1_SPANS, &rec);
    vcs_semantic_record_v1_free(&rec);
    return ok;
}

static bool cm_emit_function(struct cm_core *c, const struct cm_function *fn)
{
    struct vcs_semantic_record_v1 rec = {0};
    size_t lo = cm_exp_lower(c, fn->file, fn->begin_off), hi = lo;
    const char **macros;
    bool ok;
    while (hi < c->nexps && c->exps[hi].file == fn->file &&
           c->exps[hi].offset <= fn->end_off)
        hi++;
    macros = zcl_calloc(hi - lo + 1, sizeof(*macros), "clang_manifest.fn_macros");
    if (macros == NULL)
        return cm_fail(c, "out of memory");
    for (size_t k = lo; k < hi; k++) {
        macros[k - lo] = c->exps[k].name;
        c->exps[k].in_fn = true;
    }
    vcs_semantic_record_v1_cstr(&rec, fn->file->path);
    vcs_semantic_record_v1_cstr(&rec, fn->name);
    vcs_semantic_record_v1_u8(&rec, fn->linkage);
    vcs_semantic_record_v1_cstr(&rec, fn->type);
    vcs_semantic_record_v1_digest(&rec, fn->token_sha3);
    vcs_semantic_record_v1_sorted_texts(&rec, (const char *const *)fn->callees,
                                        fn->ncallees);
    vcs_semantic_record_v1_sorted_texts(&rec, macros, hi - lo);
    ok = cm_add(c, VCS_SEMANTIC_SECTION_V1_FUNCTIONS, &rec) &&
         cm_emit_span(c, fn);
    for (size_t k = lo; ok && c->facts && k < hi; k++) {
        if (c->exps[k].def_id != NULL)
            ok = cm_ref(c, fn->id, VCS_SEMANTIC_REF_V1_MACRO, c->exps[k].def_id);
    }
    vcs_semantic_record_v1_free(&rec);
    free(macros);
    return ok;
}

/* Facts revision 2: every expansion no function definition's span holds
 * is a file-scope use of its macro, attributed to the file it is in. */
static bool cm_emit_scope_refs(struct cm_core *c)
{
    bool ok = true;
    for (size_t k = 0; ok && c->facts && k < c->nexps; k++) {
        const struct cm_expansion *e = &c->exps[k];
        size_t n;
        char *site;
        if (e->in_fn || e->def_id == NULL)
            continue;
        n = strlen(VCS_SEMANTIC_FACTS_SCOPE_SITE) + strlen(e->file->path) + 1;
        site = zcl_malloc(n, "clang_manifest.scope_site");
        if (site == NULL)
            return cm_fail(c, "out of memory");
        (void)snprintf(site, n, "%s%s", VCS_SEMANTIC_FACTS_SCOPE_SITE,
                       e->file->path);
        ok = cm_ref(c, site, VCS_SEMANTIC_REF_V1_MACRO, e->def_id);
        free(site);
    }
    return ok;
}

/* Facts revision 3: every expansion inside a static_assert outside every
 * function definition is a MACRO ref of its "@assert:<path>" site. The
 * assertion's extent in expansion offsets ends at its closing parenthesis;
 * when a macro writes the assertion (`CHECK(x)`), it ends where that
 * invocation begins instead, so an expansion that begins inside the span
 * stretches it over the invocation's arguments. */
static bool cm_emit_assert_refs(struct cm_core *c)
{
    bool ok = true;
    for (size_t a = 0; ok && c->facts && a < c->nasserts; a++) {
        const struct cm_assert *s = &c->asserts[a];
        unsigned end = s->end;
        for (size_t k = cm_exp_lower(c, s->file, s->begin);
             ok && k < c->nexps && c->exps[k].file == s->file &&
             c->exps[k].offset <= end;
             k++) {
            if (c->exps[k].end > end)
                end = c->exps[k].end;
            if (c->exps[k].def_id != NULL)
                ok = cm_ref(c, s->site, VCS_SEMANTIC_REF_V1_MACRO,
                            c->exps[k].def_id);
        }
    }
    return ok;
}

bool cm_emit_deferred(struct cm_core *c)
{
    char **used = NULL;
    size_t nused = 0, capused = 0;
    bool ok = true;
    if (c->nexps > 1)
        qsort(c->exps, c->nexps, sizeof(*c->exps), cm_exp_cmp);
    for (size_t k = 0; ok && k < c->nexps; k++) {
        if (c->exps[k].file->origin == VCS_SEMANTIC_ORIGIN_V1_MAIN)
            ok = cm_grow((void **)&used, &capused, nused, sizeof(*used)) &&
                 (used[nused++] = c->exps[k].name) != NULL;
    }
    if (!ok) {
        free(used);
        return cm_fail(c, "out of memory");
    }
    if (nused > 1)
        qsort(used, nused, sizeof(*used), cm_str_cmp);
    ok = cm_emit_macros(c, used, nused);
    free(used);
    for (size_t k = 0; ok && k < c->nfns; k++)
        ok = cm_emit_function(c, &c->fns[k]);
    return ok && cm_emit_scope_refs(c) && cm_emit_assert_refs(c) &&
           cm_emit_conditionals(c);
}
