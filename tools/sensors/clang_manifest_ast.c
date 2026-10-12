/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: libclang walk of declarations, layouts, enums, macros, functions and their facts for the semantic sensor. */
#include "clang_manifest.h"

#include "base/safe_alloc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---- small helpers ---------------------------------------------------------- */

#if !CM_TYPE_PRETTY_PRINTED
/* clang_getTypeSpelling names an anonymous tag with its location,
 * "(unnamed at path:line:col)" or "(anonymous at ...)". The location is a
 * position (and can be a host path), so it is cut to "(unnamed)" /
 * "(anonymous)", as the pretty printer does with anonymous-tag locations
 * off. Edits s in place. */
static void cm_strip_anon_locations(char *s)
{
    static const char *const k[] = {"(unnamed at ", "(anonymous at "};
    for (size_t i = 0; s != NULL && i < sizeof(k) / sizeof(k[0]); i++) {
        char *at;
        while ((at = strstr(s, k[i])) != NULL) {
            size_t word = strlen(k[i]) - 4; /* "(unnamed" */
            char *close = strchr(at + word, ')');
            if (close == NULL)
                break;
            memmove(at + word, close, strlen(close) + 1);
        }
    }
}
#endif

/* Canonical type spelling. clang_getTypePrettyPrinted (with anonymous-tag
 * locations off) is used where the libclang image exports it; the Makefile
 * decides that by a link probe, never by the header's CINDEX_VERSION,
 * because Apple's libclang.dylib declares the call and does not export it.
 * Without it the spelling is clang_getTypeSpelling of the canonical type
 * with anonymous-tag locations cut, a different grammar: CM_TYPE_GRAMMAR
 * names the one in use and enters the producer digest, so manifests from
 * the two never compare. */
static char *cm_type_str(struct cm_state *st, CXType t)
{
#if CM_TYPE_PRETTY_PRINTED
    return cm_take_string(
        clang_getTypePrettyPrinted(clang_getCanonicalType(t), st->policy));
#else
    char *s = cm_take_string(clang_getTypeSpelling(clang_getCanonicalType(t)));
    if (s == NULL || s[0] == '\0') {
        (void)cm_fail(&st->core,
                      "type printer: unsupported or missing type spelling");
        free(s);
        return cm_strdup("");
    }
    cm_strip_anon_locations(s);
    return s;
#endif
}

static bool cm_is_repo(const struct cm_file *f)
{
    return f != NULL && f->origin != VCS_SEMANTIC_ORIGIN_V1_SYSTEM;
}

/* Name for an unnamed tag: the first repo typedef that names it, else "". */
static const char *cm_tag_name(struct cm_state *st, CXCursor decl)
{
    for (size_t k = 0; k < st->ntagnames; k++) {
        if (clang_equalCursors(st->tagnames[k].decl, decl))
            return st->tagnames[k].name;
    }
    return "";
}

static char *cm_decl_name(struct cm_state *st, CXCursor c)
{
    if (clang_Cursor_isAnonymous(c))
        return cm_strdup(cm_tag_name(st, c));
    return cm_take_string(clang_getCursorSpelling(c));
}

/* ---- canonical identities ------------------------------------------------------ */

static char cm_id_prefix(enum CXCursorKind k)
{
    switch (k) {
    case CXCursor_FunctionDecl: return 'f';
    case CXCursor_VarDecl: return 'v';
    case CXCursor_TypedefDecl: return 't';
    case CXCursor_StructDecl: return 's';
    case CXCursor_UnionDecl: return 'u';
    case CXCursor_EnumDecl: return 'e';
    case CXCursor_EnumConstantDecl: return 'k';
    default: return 0;
    }
}

/* The path that names an entity: the file of its definition when this TU
 * has one, else of its first declaration; "@builtin" when neither is in a
 * file the front end read. */
static const char *cm_entity_path(struct cm_state *st, CXCursor d)
{
    CXCursor def = clang_getCursorDefinition(d);
    const struct cm_file *f = NULL;
    if (!clang_Cursor_isNull(def))
        f = cm_cursor_file(st, def, NULL, NULL);
    if (f == NULL)
        f = cm_cursor_file(st, clang_getCanonicalCursor(d), NULL, NULL);
    return f != NULL ? f->path : "@builtin";
}

/* Canonical identity of a declaration cursor; NULL for an unnamed tag or a
 * kind that has none. */
static char *cm_entity_id(struct cm_state *st, CXCursor d)
{
    char prefix = cm_id_prefix(clang_getCursorKind(d));
    char *name, *id;
    if (prefix == 0)
        return NULL;
    name = cm_decl_name(st, d);
    if (name == NULL || name[0] == '\0') {
        free(name);
        return NULL;
    }
    id = cm_id(prefix, cm_entity_path(st, d), name,
               (uint8_t)clang_getCursorLinkage(d));
    free(name);
    return id;
}

static bool cm_emit_decl_symbol(struct cm_state *st, const struct cm_file *f,
                                const char *kind, const char *name,
                                const char *type, CXCursor c)
{
    uint8_t linkage = (uint8_t)clang_getCursorLinkage(c);
    char *id;
    bool ok;
    if (!cm_emit_decl(&st->core, f, kind, name, type, linkage))
        return false;
    if (!st->core.facts || name[0] == '\0')
        return true;
    id = cm_entity_id(st, c);
    ok = cm_symbol(&st->core, id, f->path, kind, linkage,
                   clang_isCursorDefinition(c) != 0);
    free(id);
    return ok;
}

/* ---- layouts ------------------------------------------------------------------ */

struct cm_fields {
    struct cm_state *st;
    struct cm_field *items;
    size_t n, cap;
    uint64_t base;
};

static enum CXVisitorResult cm_field_visit(CXCursor c, CXClientData data);

static bool cm_anon_member(CXCursor field)
{
    CXCursor decl = clang_getTypeDeclaration(clang_getCursorType(field));
    return !clang_Cursor_isNull(decl) && clang_Cursor_isAnonymousRecordDecl(decl);
}

static enum CXVisitorResult cm_field_visit(CXCursor c, CXClientData data)
{
    struct cm_fields *fs = data;
    long long off = clang_Cursor_getOffsetOfField(c);
    struct cm_field *e;
    if (off < 0)
        return CXVisit_Continue;
    if (cm_anon_member(c)) {
        uint64_t saved = fs->base;
        fs->base = saved + (uint64_t)off;
        clang_Type_visitFields(clang_getCursorType(c), cm_field_visit, fs);
        fs->base = saved;
        return CXVisit_Continue;
    }
    if (!cm_grow((void **)&fs->items, &fs->cap, fs->n, sizeof(*fs->items))) {
        (void)cm_fail(&fs->st->core, "out of memory");
        return CXVisit_Break;
    }
    e = &fs->items[fs->n++];
    e->name = cm_take_string(clang_getCursorSpelling(c));
    e->type = cm_type_str(fs->st, clang_getCursorType(c));
    e->offset_bits = fs->base + (uint64_t)off;
    e->bit_width = clang_Cursor_isBitField(c)
                       ? (uint32_t)clang_getFieldDeclBitWidth(c)
                       : UINT32_MAX;
    return CXVisit_Continue;
}

static void cm_fields_free(struct cm_fields *fs)
{
    for (size_t k = 0; k < fs->n; k++) {
        free(fs->items[k].name);
        free(fs->items[k].type);
    }
    free(fs->items);
}

static bool cm_layout(struct cm_state *st, const struct cm_file *f, CXCursor c,
                      const char *name)
{
    CXType t = clang_getCursorType(c);
    long long size = clang_Type_getSizeOf(t), align = clang_Type_getAlignOf(t);
    struct cm_fields fs = {.st = st};
    bool ok;
    if (size < 0 || align < 0)
        return true;
    clang_Type_visitFields(t, cm_field_visit, &fs);
    ok = !st->core.failed &&
         cm_emit_layout(&st->core, f, name,
                        clang_getCursorKind(c) == CXCursor_UnionDecl ? 2 : 1,
                        (uint64_t)size, (uint64_t)align, fs.items, fs.n);
    cm_fields_free(&fs);
    return ok;
}

/* ---- enums --------------------------------------------------------------------- */

struct cm_enum_ctx {
    struct cm_state *st;
    const struct cm_file *f;
    const char *name;
};

static enum CXChildVisitResult cm_enum_visit(CXCursor c, CXCursor parent,
                                             CXClientData data)
{
    struct cm_enum_ctx *ec = data;
    char *constant;
    (void)parent;
    if (clang_getCursorKind(c) != CXCursor_EnumConstantDecl)
        return CXChildVisit_Continue;
    constant = cm_take_string(clang_getCursorSpelling(c));
    if (constant == NULL)
        (void)cm_fail(&ec->st->core, "out of memory");
    else
        (void)cm_emit_enum(&ec->st->core, ec->f, ec->name, constant,
                           clang_getEnumConstantDeclValue(c));
    free(constant);
    return ec->st->core.failed ? CXChildVisit_Break : CXChildVisit_Continue;
}

/* ---- tags (struct/union/enum), including named tags nested in records ----- */

static bool cm_tag(struct cm_state *st, const struct cm_file *f, CXCursor c);
static bool cm_assert_site(struct cm_state *st, CXCursor c);

static enum CXChildVisitResult cm_nested_visit(CXCursor c, CXCursor parent,
                                               CXClientData data)
{
    struct cm_state *st = data;
    enum CXCursorKind k = clang_getCursorKind(c);
    const struct cm_file *f;
    (void)parent;
    if (k != CXCursor_StructDecl && k != CXCursor_UnionDecl &&
        k != CXCursor_EnumDecl)
        return CXChildVisit_Continue;
    if (clang_Cursor_isAnonymous(c))
        return CXChildVisit_Continue;
    f = cm_cursor_file(st, c, NULL, NULL);
    if (cm_is_repo(f))
        (void)cm_tag(st, f, c);
    return st->core.failed ? CXChildVisit_Break : CXChildVisit_Continue;
}

/* A static_assert in a record's member list, or in an unnamed record nested
 * in it, is the record's file's; a named nested record walks its own. */
static enum CXChildVisitResult cm_record_assert_visit(CXCursor c, CXCursor parent,
                                                     CXClientData data)
{
    struct cm_state *st = data;
    enum CXCursorKind k = clang_getCursorKind(c);
    (void)parent;
    if (k == CXCursor_StaticAssert)
        return cm_assert_site(st, c) ? CXChildVisit_Continue
                                     : CXChildVisit_Break;
    if ((k == CXCursor_StructDecl || k == CXCursor_UnionDecl) &&
        clang_Cursor_isAnonymous(c))
        return CXChildVisit_Recurse;
    return CXChildVisit_Continue;
}

static const char *cm_tag_kind(enum CXCursorKind k)
{
    return k == CXCursor_UnionDecl ? "union"
           : k == CXCursor_EnumDecl ? "enum"
                                    : "struct";
}

static bool cm_tag(struct cm_state *st, const struct cm_file *f, CXCursor c)
{
    enum CXCursorKind k = clang_getCursorKind(c);
    char *name = cm_decl_name(st, c);
    bool ok;
    if (name == NULL)
        return cm_fail(&st->core, "out of memory");
    ok = cm_emit_decl_symbol(st, f, cm_tag_kind(k), name, "", c);
    if (ok && clang_isCursorDefinition(c)) {
        if (k == CXCursor_EnumDecl) {
            struct cm_enum_ctx ec = {.st = st, .f = f, .name = name};
            clang_visitChildren(c, cm_enum_visit, &ec);
            ok = !st->core.failed;
        } else {
            ok = cm_layout(st, f, c, name);
            if (ok)
                clang_visitChildren(c, cm_nested_visit, st);
            if (ok && st->core.facts && !st->core.failed)
                clang_visitChildren(c, cm_record_assert_visit, st);
            ok = ok && !st->core.failed;
        }
    }
    free(name);
    return ok;
}

/* ---- macros ------------------------------------------------------------------- */

/* clang_tokenize retains comments as CXToken_Comment; they are never part of
 * a macro body or a function's token identity. */
static bool cm_code_token(CXToken t)
{
    return clang_getTokenKind(t) != CXToken_Comment;
}

/* Non-comment tokens joined by one space, after dropping the first `skip`
 * non-comment tokens (the macro name). */
static char *cm_join_tokens(struct cm_state *st, CXToken *toks, unsigned n,
                            unsigned skip)
{
    size_t len = 0, w = 0;
    unsigned seen = 0;
    char *out;
    for (unsigned k = 0; k < n; k++) {
        CXString s = clang_getTokenSpelling(st->tu, toks[k]);
        len += strlen(clang_getCString(s)) + 1;
        clang_disposeString(s);
    }
    out = zcl_malloc(len + 1, "clang_manifest.macro_body");
    if (out == NULL)
        return NULL;
    for (unsigned k = 0; k < n; k++) {
        CXString s;
        size_t sl;
        if (!cm_code_token(toks[k]) || seen++ < skip)
            continue;
        s = clang_getTokenSpelling(st->tu, toks[k]);
        sl = strlen(clang_getCString(s));
        if (w > 0)
            out[w++] = ' ';
        memcpy(out + w, clang_getCString(s), sl);
        w += sl;
        clang_disposeString(s);
    }
    out[w] = '\0';
    return out;
}

static bool cm_macro_definition(struct cm_state *st, const struct cm_file *f,
                                unsigned offset,
                                CXCursor c)
{
    CXToken *toks = NULL;
    unsigned n = 0;
    char *name, *body;
    clang_tokenize(st->tu, clang_getCursorExtent(c), &toks, &n);
    name = cm_take_string(clang_getCursorSpelling(c));
    body = cm_join_tokens(st, toks, n, 1);
    clang_disposeTokens(st->tu, toks, n);
    return cm_macro_def(&st->core, f, offset, name, body);
}

/* m:<definition path>:<name>; "@builtin" for a builtin macro and
 * "@predefined" for one defined outside any file (predefines, -D). */
static char *cm_macro_id(struct cm_state *st, CXCursor exp, const char *name)
{
    CXCursor def = clang_getCursorReferenced(exp);
    const struct cm_file *f;
    if (clang_Cursor_isNull(def) || clang_getCursorKind(def) != CXCursor_MacroDefinition)
        return cm_id('m', "@builtin", name, 0);
    f = cm_cursor_file(st, def, NULL, NULL);
    return cm_id('m', f != NULL ? f->path : "@predefined", name, 0);
}

static bool cm_macro_expansion(struct cm_state *st, const struct cm_file *f,
                               CXCursor c, unsigned offset)
{
    char *name = cm_take_string(clang_getCursorSpelling(c));
    char *def_id = NULL;
    CXFile file;
    unsigned line, col, end = offset;
    clang_getExpansionLocation(clang_getRangeEnd(clang_getCursorExtent(c)),
                               &file, &line, &col, &end);
    if (name != NULL && st->core.facts)
        def_id = cm_macro_id(st, c, name);
    return cm_macro_exp(&st->core, f, offset, end, name, def_id);
}

/* ---- the facts of one definition -------------------------------------------- */

static bool cm_site_call(struct cm_site *s, CXSourceLocation loc)
{
    if (!cm_grow((void **)&s->calls, &s->capcalls, s->ncalls, sizeof(*s->calls)))
        return false;
    s->calls[s->ncalls++] = loc;
    return true;
}

static bool cm_site_is_call(const struct cm_site *s, CXSourceLocation loc)
{
    for (size_t k = 0; k < s->ncalls; k++) {
        if (clang_equalLocations(s->calls[k], loc))
            return true;
    }
    return false;
}

/* A callee is external when neither its first declaration nor a
 * definition in this TU lies in a repo file. */
static bool cm_external(struct cm_state *st, CXCursor fn)
{
    CXCursor def = clang_getCursorDefinition(fn);
    if (!clang_Cursor_isNull(def) && cm_is_repo(cm_cursor_file(st, def, NULL, NULL)))
        return false;
    return !cm_is_repo(cm_cursor_file(st, clang_getCanonicalCursor(fn), NULL, NULL));
}

static bool cm_ref_to(struct cm_state *st, uint8_t kind, CXCursor d)
{
    char *id = cm_entity_id(st, d);
    bool ok = cm_ref(&st->core, st->site->id, kind, id);
    free(id);
    return ok;
}

static bool cm_facts_call(struct cm_state *st, CXCursor c)
{
    struct cm_site *s = st->site;
    CXCursor ref = clang_getCursorReferenced(c);
    char *name;
    bool ok;
    if (clang_Cursor_isNull(ref) || clang_getCursorKind(ref) != CXCursor_FunctionDecl) {
        ok = s->fn == NULL || cm_function_callee(&st->core, s->fn, "(indirect)");
        return ok && cm_unknown(&st->core, s->id,
                                VCS_SEMANTIC_UNKNOWN_V1_INDIRECT_CALL, "");
    }
    name = cm_take_string(clang_getCursorSpelling(ref));
    if (name == NULL)
        return cm_fail(&st->core, "out of memory");
    ok = (s->fn == NULL || cm_function_callee(&st->core, s->fn, name)) &&
         (!st->core.facts ||
          (cm_site_call(s, clang_getCursorLocation(c)) &&
           cm_ref_to(st, VCS_SEMANTIC_REF_V1_CALL, ref) &&
           (!cm_external(st, ref) ||
            cm_unknown(&st->core, s->id, VCS_SEMANTIC_UNKNOWN_V1_EXTERNAL_CALL,
                       name))));
    free(name);
    return ok;
}

/* volatile or _Atomic accesses, on the canonical type of the expression */
static bool cm_facts_access(struct cm_state *st, CXCursor c, CXCursor ref)
{
    CXType t = clang_getCanonicalType(clang_getCursorType(c));
    char *name;
    bool ok = true;
    bool vol = clang_isVolatileQualifiedType(t) != 0;
    bool atomic = t.kind == CXType_Atomic;
    if (!vol && !atomic)
        return true;
    name = cm_take_string(clang_getCursorSpelling(ref));
    if (name == NULL)
        return cm_fail(&st->core, "out of memory");
    if (vol)
        ok = cm_unknown(&st->core, st->site->id, VCS_SEMANTIC_UNKNOWN_V1_VOLATILE, name);
    if (ok && atomic)
        ok = cm_unknown(&st->core, st->site->id, VCS_SEMANTIC_UNKNOWN_V1_ATOMIC, name);
    free(name);
    return ok;
}

static bool cm_facts_declref(struct cm_state *st, CXCursor c)
{
    CXCursor ref = clang_getCursorReferenced(c);
    enum CXCursorKind k = clang_Cursor_isNull(ref) ? CXCursor_InvalidFile
                                                   : clang_getCursorKind(ref);
    uint8_t linkage;
    switch (k) {
    case CXCursor_FunctionDecl:
        if (cm_site_is_call(st->site, clang_getCursorLocation(c)))
            return true;
        return cm_ref_to(st, VCS_SEMANTIC_REF_V1_ADDRESS, ref);
    case CXCursor_EnumConstantDecl:
        return cm_ref_to(st, VCS_SEMANTIC_REF_V1_ENUMERATOR, ref);
    case CXCursor_VarDecl:
    case CXCursor_ParmDecl:
        linkage = (uint8_t)clang_getCursorLinkage(ref);
        if (k == CXCursor_VarDecl && linkage >= 2 &&
            !cm_ref_to(st, VCS_SEMANTIC_REF_V1_VARIABLE, ref))
            return false;
        return cm_facts_access(st, c, ref);
    default:
        return true;
    }
}

/* The record a member access names: the field's parent, or, through an
 * anonymous struct or union member, the nearest named enclosing record, so
 * `s.a` into `struct S { union { int a; }; }` names S (facts revision 2). */
static CXCursor cm_member_owner(struct cm_state *st, CXCursor field)
{
    CXCursor parent = clang_getCursorSemanticParent(field);
    for (int depth = 0; depth < 64; depth++) {
        enum CXCursorKind pk = clang_getCursorKind(parent);
        char *id;
        bool named;
        if (pk != CXCursor_StructDecl && pk != CXCursor_UnionDecl)
            return parent;
        id = cm_entity_id(st, parent);
        named = id != NULL;
        free(id);
        if (named)
            return parent;
        parent = clang_getCursorSemanticParent(parent);
    }
    return parent;
}

static bool cm_facts_member(struct cm_state *st, CXCursor c)
{
    CXCursor field = clang_getCursorReferenced(c), parent;
    enum CXCursorKind pk;
    if (clang_Cursor_isNull(field) || clang_getCursorKind(field) != CXCursor_FieldDecl)
        return true;
    parent = cm_member_owner(st, field);
    pk = clang_getCursorKind(parent);
    if ((pk == CXCursor_StructDecl || pk == CXCursor_UnionDecl) &&
        !cm_ref_to(st, VCS_SEMANTIC_REF_V1_TYPE, parent))
        return false;
    return cm_facts_access(st, c, field);
}

/* ---- attributes that name a function -------------------------------------------- */

/* cleanup(f), malloc(f) and any other attribute whose argument names a
 * function make the compile call or pair that function from the
 * declaration's owner, though no expression names it. Each such argument is
 * a call ref from the owner. An identifier argument that names nothing
 * visible is an UNKNOWN, never an omission, unless the attribute is one
 * whose arguments are known never to name a function. */
static const char *const k_cm_nofn_attrs[] = {
    "access",     "aligned",     "alloc_align", "alloc_size", "assume_aligned",
    "availability", "constructor", "counted_by", "counted_by_or_null",
    "deprecated", "destructor",  "format",      "format_arg", "mode",
    "no_sanitize", "nonnull",    "optimize",    "section",    "sentinel",
    "sized_by",   "sized_by_or_null", "target", "target_clones", "tls_model",
    "unavailable", "vector_size", "visibility", "warning",    "error",
};

static bool cm_nofn_attr(const char *name)
{
    char bare[64];
    size_t n = strlen(name);
    if (n > 4 && strncmp(name, "__", 2) == 0 && strcmp(name + n - 2, "__") == 0 &&
        n - 4 < sizeof(bare)) {
        memcpy(bare, name + 2, n - 4);
        bare[n - 4] = '\0';
        name = bare;
    }
    for (size_t k = 0; k < sizeof(k_cm_nofn_attrs) / sizeof(*k_cm_nofn_attrs); k++)
        if (strcmp(name, k_cm_nofn_attrs[k]) == 0)
            return true;
    return false;
}

struct cm_name_find {
    const char *name;
    CXCursor fn;
    bool function, other;
};

/* A file-scope function of that name (its definition when there is one),
 * or any other file-scope declaration of it. */
static enum CXChildVisitResult cm_name_find_visit(CXCursor c, CXCursor parent,
                                                  CXClientData data)
{
    struct cm_name_find *q = data;
    enum CXCursorKind k = clang_getCursorKind(c);
    char *name = cm_take_string(clang_getCursorSpelling(c));
    bool same = name != NULL && strcmp(name, q->name) == 0;
    (void)parent;
    free(name);
    if (same && k == CXCursor_FunctionDecl &&
        (!q->function || clang_isCursorDefinition(c))) {
        q->fn = c;
        q->function = true;
    } else if (same) {
        q->other = true;
    }
    return q->function && clang_isCursorDefinition(q->fn) ? CXChildVisit_Break
                                                         : CXChildVisit_Continue;
}

static bool cm_attr_ident(struct cm_state *st, const char *from,
                          const char *attr, const char *ident)
{
    struct cm_name_find q = {.name = ident};
    char *id;
    bool ok;
    clang_visitChildren(clang_getTranslationUnitCursor(st->tu),
                        cm_name_find_visit, &q);
    if (!q.function) {
        char detail[256];
        if (q.other || cm_nofn_attr(attr))
            return true;
        (void)snprintf(detail, sizeof(detail), "attribute %s(%s)", attr, ident);
        return cm_unknown(&st->core, from, VCS_SEMANTIC_UNKNOWN_V1_UNRESOLVED,
                          detail);
    }
    if ((id = cm_entity_id(st, q.fn)) == NULL)
        return cm_fail(&st->core, "out of memory");
    ok = cm_ref(&st->core, from, VCS_SEMANTIC_REF_V1_CALL, id) &&
         (!cm_external(st, q.fn) ||
          cm_unknown(&st->core, from, VCS_SEMANTIC_UNKNOWN_V1_EXTERNAL_CALL,
                     ident));
    free(id);
    return ok;
}

/* The attribute's name (after any `gnu ::` scope) and every identifier
 * among its arguments. */
static bool cm_attr_args(struct cm_state *st, CXCursor a, const char *from)
{
    CXToken *toks = NULL;
    unsigned n = 0, k = 0;
    char *name = NULL;
    bool ok = true;
    clang_tokenize(st->tu, clang_getCursorExtent(a), &toks, &n);
    for (; k < n; k++) {
        char *s = cm_take_string(clang_getTokenSpelling(st->tu, toks[k]));
        bool punct = clang_getTokenKind(toks[k]) == CXToken_Punctuation;
        bool stop;
        if (s == NULL) {
            ok = cm_fail(&st->core, "out of memory");
            break;
        }
        stop = punct && strcmp(s, "::") != 0;
        if (!punct) {
            free(name);
            name = s;
        } else {
            free(s);
        }
        if (stop)
            break;
    }
    for (k++; ok && name != NULL && k < n; k++) {
        char *s;
        if (clang_getTokenKind(toks[k]) != CXToken_Identifier)
            continue;
        s = cm_take_string(clang_getTokenSpelling(st->tu, toks[k]));
        ok = s != NULL ? cm_attr_ident(st, from, name, s)
                       : cm_fail(&st->core, "out of memory");
        free(s);
    }
    free(name);
    clang_disposeTokens(st->tu, toks, n);
    return ok;
}

struct cm_attr_decl {
    struct cm_state *st;
    const char *from;
    bool ok;
};

static enum CXChildVisitResult cm_attr_decl_visit(CXCursor c, CXCursor parent,
                                                  CXClientData data)
{
    struct cm_attr_decl *q = data;
    (void)parent;
    if (clang_getCursorKind(c) == CXCursor_UnexposedAttr)
        q->ok = cm_attr_args(q->st, c, q->from);
    return q->ok ? CXChildVisit_Continue : CXChildVisit_Break;
}

static bool cm_facts_cursor(struct cm_state *st, CXCursor c)
{
    CXCursor ref;
    switch (clang_getCursorKind(c)) {
    case CXCursor_CallExpr:
        return cm_facts_call(st, c);
    case CXCursor_DeclRefExpr:
        return !st->core.facts || cm_facts_declref(st, c);
    case CXCursor_MemberRefExpr:
        return !st->core.facts || cm_facts_member(st, c);
    case CXCursor_TypeRef:
        if (!st->core.facts)
            return true;
        ref = clang_getCursorReferenced(c);
        return clang_Cursor_isNull(ref) ||
               cm_ref_to(st, VCS_SEMANTIC_REF_V1_TYPE, ref);
    case CXCursor_AsmStmt:
        return cm_unknown(&st->core, st->site->id,
                          VCS_SEMANTIC_UNKNOWN_V1_INLINE_ASM, "");
    case CXCursor_UnexposedAttr: /* cleanup(f) on a local, and the like */
        return !st->core.facts || cm_attr_args(st, c, st->site->id);
    default:
        return true;
    }
}

static enum CXChildVisitResult cm_site_visit(CXCursor c, CXCursor parent,
                                             CXClientData data)
{
    struct cm_state *st = data;
    (void)parent;
    if (!cm_facts_cursor(st, c))
        return CXChildVisit_Break;
    return CXChildVisit_Recurse;
}

static bool cm_walk_site(struct cm_state *st, CXCursor c, const char *id,
                         struct cm_function *fn)
{
    struct cm_site site = {.id = id, .fn = fn};
    st->site = &site;
    clang_visitChildren(c, cm_site_visit, st);
    st->site = NULL;
    free(site.calls);
    return !st->core.failed;
}

/* A static_assert outside every function definition (facts revision 3):
 * each entity its condition names is a ref of "@assert:<path>", and each
 * expansion inside its span a MACRO ref (cm_emit_assert_refs). One inside a
 * function body is that function's, walked with its site. */
static bool cm_assert_site(struct cm_state *st, CXCursor c)
{
    const struct cm_file *f = cm_cursor_file(st, c, NULL, NULL);
    CXSourceRange ext = clang_getCursorExtent(c);
    CXFile file;
    unsigned line, col, begin, end;
    const char *site;
    if (!st->core.facts || !cm_is_repo(f))
        return true;
    clang_getExpansionLocation(clang_getRangeStart(ext), &file, &line, &col,
                               &begin);
    clang_getExpansionLocation(clang_getRangeEnd(ext), &file, &line, &col,
                               &end);
    site = cm_assert_add(&st->core, f, begin, end);
    return site != NULL && cm_walk_site(st, c, site, NULL);
}

/* ---- functions ---------------------------------------------------------------- */

static void cm_fn_tokens(struct cm_state *st, CXSourceRange ext,
                         uint8_t out[32])
{
    CXToken *toks = NULL;
    unsigned n = 0;
    struct vcs_semantic_token_hash_v1 h;
    vcs_semantic_token_hash_v1_init(&h);
    clang_tokenize(st->tu, ext, &toks, &n);
    for (unsigned k = 0; k < n; k++) {
        CXString s;
        const char *cs;
        if (!cm_code_token(toks[k]))
            continue;
        s = clang_getTokenSpelling(st->tu, toks[k]);
        cs = clang_getCString(s);
        vcs_semantic_token_hash_v1_add(&h, cs, strlen(cs));
        clang_disposeString(s);
    }
    clang_disposeTokens(st->tu, toks, n);
    vcs_semantic_token_hash_v1_final(&h, out);
}

static void cm_fn_span(CXSourceRange ext, struct cm_function *fn)
{
    CXFile f;
    unsigned col;
    clang_getExpansionLocation(clang_getRangeStart(ext), &f, &fn->begin_line,
                               &col, &fn->begin_off);
    clang_getExpansionLocation(clang_getRangeEnd(ext), &f, &fn->end_line, &col,
                               &fn->end_off);
    if (fn->end_line < fn->begin_line)
        fn->end_line = fn->begin_line;
    if (fn->end_off < fn->begin_off)
        fn->end_off = fn->begin_off;
}

static bool cm_function_def(struct cm_state *st, const struct cm_file *f,
                            CXCursor c, const char *name, const char *type)
{
    struct cm_function fn = {.file = f,
                             .linkage = (uint8_t)clang_getCursorLinkage(c)};
    struct cm_function *stored;
    CXSourceRange ext = clang_getCursorExtent(c);
    fn.name = cm_strdup(name);
    fn.type = cm_strdup(type);
    fn.id = cm_entity_id(st, c);
    cm_fn_tokens(st, ext, fn.token_sha3);
    cm_fn_span(ext, &fn);
    stored = fn.name != NULL && fn.type != NULL ? cm_function_add(&st->core, &fn)
                                                : NULL;
    if (stored == NULL) {
        free(fn.name);
        free(fn.type);
        free(fn.id);
        return cm_fail(&st->core, "out of memory");
    }
    return cm_walk_site(st, c, stored->id, stored);
}

/* ---- symbol aliases ------------------------------------------------------------ */

/* alias("x"), weakref("x"), ifunc("r") and an asm label give code or data a
 * second entry, named by a string no expression refers to. Each is written
 * as the address of every id the string may name and of the declaration
 * itself, so a change to either side refuses a narrowing (address-taken). */
static const char *const k_cm_alias_attrs[] = {
    "alias", "__alias__", "weakref", "__weakref__", "ifunc", "__ifunc__",
};

struct cm_alias_find {
    const char *name;
    CXCursor hit;
    bool found;
};

static enum CXChildVisitResult cm_alias_find_visit(CXCursor c, CXCursor parent,
                                                   CXClientData data)
{
    struct cm_alias_find *q = data;
    enum CXCursorKind k = clang_getCursorKind(c);
    char *name;
    (void)parent;
    if ((k != CXCursor_FunctionDecl && k != CXCursor_VarDecl) ||
        !clang_isCursorDefinition(c))
        return CXChildVisit_Continue;
    name = cm_take_string(clang_getCursorSpelling(c));
    if (name != NULL && strcmp(name, q->name) == 0) {
        q->hit = c;
        q->found = true;
    }
    free(name);
    return q->found ? CXChildVisit_Break : CXChildVisit_Continue;
}

/* The target's id when this TU defines it; else both external spellings. */
static bool cm_alias_ref(struct cm_state *st, const char *from,
                         const char *target)
{
    struct cm_alias_find q = {.name = target};
    char ext[512];
    char *id;
    bool ok;
    clang_visitChildren(clang_getTranslationUnitCursor(st->tu),
                        cm_alias_find_visit, &q);
    if (q.found) {
        /* a named file-scope definition always has an id: NULL is memory */
        if ((id = cm_entity_id(st, q.hit)) == NULL)
            return cm_fail(&st->core, "out of memory");
        ok = cm_ref(&st->core, from, VCS_SEMANTIC_REF_V1_ADDRESS, id);
        free(id);
        return ok;
    }
    /* A cut name would address some other id: no manifest instead. */
    if (strlen(target) + 3 > sizeof(ext))
        return cm_fail(&st->core, "alias target longer than %zu bytes",
                       sizeof(ext) - 3);
    (void)snprintf(ext, sizeof(ext), "f:%s", target);
    ok = cm_ref(&st->core, from, VCS_SEMANTIC_REF_V1_ADDRESS, ext);
    (void)snprintf(ext, sizeof(ext), "v:%s", target);
    return ok && cm_ref(&st->core, from, VCS_SEMANTIC_REF_V1_ADDRESS, ext);
}

static bool cm_alias_attr_name(const char *s)
{
    for (size_t k = 0; k < sizeof(k_cm_alias_attrs) / sizeof(*k_cm_alias_attrs); k++)
        if (strcmp(s, k_cm_alias_attrs[k]) == 0)
            return true;
    return false;
}

/* Every `alias ( "x" )` token run in the declaration's extent. */
static bool cm_alias_tokens(struct cm_state *st, CXCursor d, const char *from)
{
    CXToken *toks = NULL;
    unsigned n = 0;
    bool ok = true;
    clang_tokenize(st->tu, clang_getCursorExtent(d), &toks, &n);
    for (unsigned k = 0; ok && k + 2 < n; k++) {
        char *a = cm_take_string(clang_getTokenSpelling(st->tu, toks[k]));
        char *p = cm_take_string(clang_getTokenSpelling(st->tu, toks[k + 1]));
        char *s = cm_take_string(clang_getTokenSpelling(st->tu, toks[k + 2]));
        size_t sl = s != NULL ? strlen(s) : 0;
        if (a == NULL || p == NULL || s == NULL)
            ok = cm_fail(&st->core, "out of memory");
        else if (cm_alias_attr_name(a) && strcmp(p, "(") == 0 && sl >= 2 &&
                 s[0] == '"' && s[sl - 1] == '"') {
            s[sl - 1] = '\0';
            ok = cm_alias_ref(st, from, s + 1);
        }
        free(a);
        free(p);
        free(s);
    }
    clang_disposeTokens(st->tu, toks, n);
    return ok;
}

struct cm_alias_scan {
    bool unexposed;
    char *label; /* an asm label, owned */
};

static enum CXChildVisitResult cm_alias_attr_visit(CXCursor c, CXCursor parent,
                                                   CXClientData data)
{
    struct cm_alias_scan *q = data;
    enum CXCursorKind k = clang_getCursorKind(c);
    (void)parent;
    if (k == CXCursor_UnexposedAttr)
        q->unexposed = true;
    else if (k == CXCursor_AsmLabelAttr && q->label == NULL)
        q->label = cm_take_string(clang_getCursorSpelling(c));
    return CXChildVisit_Continue;
}

static bool cm_aliases(struct cm_state *st, CXCursor d)
{
    struct cm_alias_scan q = {0};
    char *from;
    bool ok = true;
    clang_visitChildren(d, cm_alias_attr_visit, &q);
    if (!q.unexposed && q.label == NULL)
        return true;
    from = cm_entity_id(st, d);
    if (from != NULL && q.label != NULL)
        ok = cm_ref(&st->core, from, VCS_SEMANTIC_REF_V1_ADDRESS, from) &&
             cm_alias_ref(st, from, q.label);
    if (ok && from != NULL && q.unexposed)
        ok = cm_alias_tokens(st, d, from);
    /* A definition's attributes are walked with its site. */
    if (ok && from != NULL && q.unexposed && !clang_isCursorDefinition(d)) {
        struct cm_attr_decl a = {.st = st, .from = from, .ok = true};
        clang_visitChildren(d, cm_attr_decl_visit, &a);
        ok = a.ok;
    }
    free(from);
    free(q.label);
    return ok;
}

/* The facts a file-scope function or variable adds beyond its decl record:
 * its second entries (alias, weakref, ifunc, asm label) and, for a variable
 * definition, the sites its initializer and attributes name. A function
 * definition's own sites come from cm_function_def. */
static bool cm_value_facts(struct cm_state *st, CXCursor c,
                           enum CXCursorKind k)
{
    bool ok;
    if (!st->core.facts ||
        (k != CXCursor_FunctionDecl && k != CXCursor_VarDecl))
        return true;
    ok = cm_aliases(st, c);
    if (ok && k == CXCursor_VarDecl && clang_isCursorDefinition(c)) {
        char *id = cm_entity_id(st, c);
        ok = id == NULL || cm_walk_site(st, c, id, NULL);
        free(id);
    }
    return ok;
}

static bool cm_value_decl(struct cm_state *st, const struct cm_file *f,
                          CXCursor c, const char *kind)
{
    char *name = cm_take_string(clang_getCursorSpelling(c));
    char *type = cm_type_str(st, clang_getCursorType(c));
    enum CXCursorKind k = clang_getCursorKind(c);
    bool ok = name != NULL && type != NULL &&
              cm_emit_decl_symbol(st, f, kind, name, type, c) &&
              cm_value_facts(st, c, k);
    if (ok && k == CXCursor_FunctionDecl && clang_isCursorDefinition(c))
        ok = cm_function_def(st, f, c, name, type);
    free(name);
    free(type);
    return ok || cm_fail(&st->core, "declaration capture failed");
}

/* ---- include directives -------------------------------------------------------- */

/* The directive's spelling: '#' then include/include_next/import, then a
 * string literal (quoted) or '<' (angled). A computed include (a macro) is
 * recorded as angled with no negative claim. */
static void cm_directive_shape(struct cm_state *st, CXCursor c, uint8_t *form,
                               uint8_t *kind, bool *computed)
{
    CXToken *toks = NULL;
    unsigned n = 0;
    *form = VCS_SEMANTIC_FORM_V1_ANGLED;
    *kind = VCS_SEMANTIC_LOOKUP_V1_INCLUDE;
    *computed = true;
    clang_tokenize(st->tu, clang_getCursorExtent(c), &toks, &n);
    if (n >= 3) {
        CXString k = clang_getTokenSpelling(st->tu, toks[1]);
        CXString v = clang_getTokenSpelling(st->tu, toks[2]);
        const char *vs = clang_getCString(v);
        if (strcmp(clang_getCString(k), "include_next") == 0)
            *kind = VCS_SEMANTIC_LOOKUP_V1_INCLUDE_NEXT;
        if (vs[0] == '"' || vs[0] == '<') {
            *computed = false;
            *form = vs[0] == '"' ? VCS_SEMANTIC_FORM_V1_QUOTED
                                 : VCS_SEMANTIC_FORM_V1_ANGLED;
        }
        clang_disposeString(k);
        clang_disposeString(v);
    }
    clang_disposeTokens(st->tu, toks, n);
}

static bool cm_inclusion_directive(struct cm_state *st, CXCursor c,
                                   const struct cm_file *includer)
{
    uint8_t form, kind;
    bool computed, ok;
    char *name = cm_take_string(clang_getCursorSpelling(c));
    if (name == NULL)
        return cm_fail(&st->core, "out of memory");
    cm_directive_shape(st, c, &form, &kind, &computed);
    ok = cm_lookup_directive(&st->core, includer, name, form, kind, computed,
                             cm_file_of(st, clang_getIncludedFile(c)));
    free(name);
    return ok;
}

/* ---- the walk -------------------------------------------------------------------- */

static enum CXChildVisitResult cm_typedef_pass(CXCursor c, CXCursor parent,
                                               CXClientData data)
{
    struct cm_state *st = data;
    CXCursor decl;
    struct cm_tagname *t;
    (void)parent;
    if (clang_getCursorKind(c) != CXCursor_TypedefDecl ||
        !cm_is_repo(cm_cursor_file(st, c, NULL, NULL)))
        return CXChildVisit_Continue;
    decl = clang_getTypeDeclaration(
        clang_getCanonicalType(clang_getTypedefDeclUnderlyingType(c)));
    if (clang_Cursor_isNull(decl) || !clang_Cursor_isAnonymous(decl) ||
        cm_tag_name(st, decl)[0] != '\0')
        return CXChildVisit_Continue;
    if (!cm_grow((void **)&st->tagnames, &st->captagnames, st->ntagnames,
                 sizeof(*st->tagnames))) {
        (void)cm_fail(&st->core, "out of memory");
        return CXChildVisit_Break;
    }
    t = &st->tagnames[st->ntagnames++];
    t->decl = decl;
    t->name = cm_take_string(clang_getCursorSpelling(c));
    return CXChildVisit_Continue;
}

static bool cm_dispatch(struct cm_state *st, CXCursor c,
                        const struct cm_file *f, unsigned offset)
{
    switch (clang_getCursorKind(c)) {
    case CXCursor_MacroDefinition:
        return cm_macro_definition(st, f, offset, c);
    case CXCursor_MacroExpansion:
        return cm_macro_expansion(st, f, c, offset);
    case CXCursor_InclusionDirective:
        return cm_inclusion_directive(st, c, f);
    case CXCursor_FunctionDecl:
        return cm_value_decl(st, f, c, "function");
    case CXCursor_VarDecl:
        return cm_value_decl(st, f, c, "variable");
    case CXCursor_TypedefDecl:
        return cm_value_decl(st, f, c, "typedef");
    case CXCursor_StructDecl:
    case CXCursor_UnionDecl:
    case CXCursor_EnumDecl:
        return cm_tag(st, f, c);
    case CXCursor_StaticAssert:
        return cm_assert_site(st, c);
    default:
        return true;
    }
}

static enum CXChildVisitResult cm_top_visit(CXCursor c, CXCursor parent,
                                            CXClientData data)
{
    struct cm_state *st = data;
    unsigned offset = 0;
    const struct cm_file *f = cm_cursor_file(st, c, NULL, &offset);
    (void)parent;
    if (!cm_is_repo(f))
        return CXChildVisit_Continue;
    /* This walk models C declarations. A different language can have
     * top-level declarations we do not emit, such as C++ templates.
     * libclang tags every static_assert cursor as C++, but a file-scope
     * static_assert is C11/C23 and emits nothing; the argv check already
     * refused a C++ translation unit. */
    enum CXLanguageKind language = clang_getCursorLanguage(c);
    if (clang_getCursorKind(c) != CXCursor_StaticAssert &&
        language != CXLanguage_Invalid && language != CXLanguage_C) {
        (void)cm_fail(&st->core, "unsupported translation-unit language");
        return CXChildVisit_Break;
    }
    if (!cm_dispatch(st, c, f, offset))
        return CXChildVisit_Break;
    return CXChildVisit_Continue;
}

bool cm_walk(struct cm_state *st)
{
    CXCursor tu = clang_getTranslationUnitCursor(st->tu);
    clang_visitChildren(tu, cm_typedef_pass, st);
    if (st->core.failed)
        return false;
    clang_visitChildren(tu, cm_top_visit, st);
    return !st->core.failed;
}
