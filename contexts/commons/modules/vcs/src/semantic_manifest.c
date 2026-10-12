/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Strict decoder, roots and section/function diff for semantic manifest v1. */
#include "vcs/semantic_manifest.h"

#include "semantic_manifest_priv.h"

#include "base/serialize_le.h"

#include <stdio.h>
#include <string.h>

/* Field codes of a record schema (docs/work/SEMANTIC_MANIFEST.md):
 *   T text   P path   Q path or empty   D directory (path or ".")
 *   A argv text (no absolute host path)  b u8  u u32  q u64  i i64
 *   h 32-byte digest   [X u32le count then X elements
 *   S text element of a strictly increasing list
 *   U u32 element of a strictly increasing list
 *   e env entry (text name, u8 set, argv text value)
 *   f layout field (text name, u64 offset_bits, u32 bit_width, text type)
 *   s probe slot (u32 slot, strictly increasing, then u8 reason) */
static const char *const k_sm_schema[VCS_SEMANTIC_SECTION_V1_COUNT] = {
    [VCS_SEMANTIC_SECTION_V1_IDENTITY] = "TQTP[A[D[D[D[e",
    [VCS_SEMANTIC_SECTION_V1_FILES] = "Phb",
    [VCS_SEMANTIC_SECTION_V1_LOOKUPS] = "PTbbQub[U",
    [VCS_SEMANTIC_SECTION_V1_MACROS] = "PTbTb",
    [VCS_SEMANTIC_SECTION_V1_DECLS] = "PTTTb",
    [VCS_SEMANTIC_SECTION_V1_LAYOUTS] = "PTbqq[f",
    [VCS_SEMANTIC_SECTION_V1_ENUMS] = "PTTi",
    [VCS_SEMANTIC_SECTION_V1_FUNCTIONS] = "PTbTh[S[S",
    [VCS_SEMANTIC_SECTION_V1_SPANS] = "PTuuqq",
    [VCS_SEMANTIC_SECTION_V1_FACTS] = "Thhuqb",
    [VCS_SEMANTIC_SECTION_V1_SYMBOLS] = "TPTbb",
    [VCS_SEMANTIC_SECTION_V1_REFS] = "TbT",
    [VCS_SEMANTIC_SECTION_V1_UNKNOWNS] = "TbTu",
    [VCS_SEMANTIC_SECTION_V1_PROBES] = "PTbbb[s",
    [VCS_SEMANTIC_SECTION_V1_TRUNCATED] = "Tuu",
};

static const char *const k_sm_names[VCS_SEMANTIC_SECTION_V1_COUNT] = {
    [VCS_SEMANTIC_SECTION_V1_IDENTITY] = "identity",
    [VCS_SEMANTIC_SECTION_V1_FILES] = "files",
    [VCS_SEMANTIC_SECTION_V1_LOOKUPS] = "lookups",
    [VCS_SEMANTIC_SECTION_V1_MACROS] = "macros",
    [VCS_SEMANTIC_SECTION_V1_DECLS] = "decls",
    [VCS_SEMANTIC_SECTION_V1_LAYOUTS] = "layouts",
    [VCS_SEMANTIC_SECTION_V1_ENUMS] = "enums",
    [VCS_SEMANTIC_SECTION_V1_FUNCTIONS] = "functions",
    [VCS_SEMANTIC_SECTION_V1_SPANS] = "spans",
    [VCS_SEMANTIC_SECTION_V1_FACTS] = "facts",
    [VCS_SEMANTIC_SECTION_V1_SYMBOLS] = "symbols",
    [VCS_SEMANTIC_SECTION_V1_REFS] = "refs",
    [VCS_SEMANTIC_SECTION_V1_UNKNOWNS] = "unknowns",
    [VCS_SEMANTIC_SECTION_V1_PROBES] = "probes",
    [VCS_SEMANTIC_SECTION_V1_TRUNCATED] = "truncated",
};

static const char *const k_sm_env[] = {VCS_SEMANTIC_ENV_V1_ALLOWLIST};
#define SM_ENV_COUNT (sizeof(k_sm_env) / sizeof(k_sm_env[0]))

/* Options whose value may be glued to them ("-Ifoo"). A '/' right after one
 * of these starts a path, so it must be a canonical token. */
static const char *const k_sm_glued[] = {
    "-I", "-iquote", "-isystem", "-idirafter", "-include", "-imacros",
    "-o", "-L", "-F", "-B", "-MF", "-MT", "-MQ", "--sysroot", "-isysroot",
    "-iprefix", "-iwithprefix", "-resource-dir",
};

/* Absolute spellings that name the same virtual location on every host. */
static const char *const k_sm_virtual[] = {"/zclassic23", "/zbuild"};

const char *vcs_semantic_section_v1_name(enum vcs_semantic_section_v1 s)
{
    if (s <= VCS_SEMANTIC_SECTION_V1_NONE || s >= VCS_SEMANTIC_SECTION_V1_COUNT)
        return NULL;
    return k_sm_names[s];
}

/* ---- cursor ------------------------------------------------------------ */

bool sm_take(struct sm_cur *c, size_t n, const uint8_t **out)
{
    if (c->len - c->off < n)
        return false;
    *out = c->p + c->off;
    c->off += n;
    return true;
}

bool sm_u32(struct sm_cur *c, uint32_t *v)
{
    const uint8_t *p;
    if (!sm_take(c, 4, &p))
        return false;
    *v = zcl_read_u32_le(p);
    return true;
}

bool sm_text(struct sm_cur *c, const uint8_t **s, size_t *n)
{
    uint32_t len;
    if (!sm_u32(c, &len) || len > VCS_SEMANTIC_MANIFEST_V1_MAX_TEXT)
        return false;
    *n = len;
    return sm_take(c, len, s) && memchr(*s, 0, len) == NULL;
}

/* ---- canonical token checks ------------------------------------------- */

static bool sm_component_ok(const uint8_t *s, size_t n)
{
    if (n == 0)
        return false;
    if (n == 1 && s[0] == '.')
        return false;
    return !(n == 2 && s[0] == '.' && s[1] == '.');
}

static bool sm_rel_ok(const uint8_t *s, size_t n)
{
    size_t start = 0;
    if (n == 0 || s[0] == '/' || s[0] == '@')
        return false;
    for (size_t i = 0; i <= n; i++) {
        if (i < n && s[i] != '/')
            continue;
        if (!sm_component_ok(s + start, i - start))
            return false;
        start = i + 1;
    }
    return true;
}

bool sm_path_ok(const uint8_t *s, size_t n, bool allow_dir_root)
{
    if (allow_dir_root && n == 1 && s[0] == '.')
        return true;
    if (n >= 4 && memcmp(s, "@sys", 4) == 0) {
        if (n == 4)
            return allow_dir_root;
        return s[4] == '/' && sm_rel_ok(s + 5, n - 5);
    }
    return sm_rel_ok(s, n);
}

static bool sm_glued_at(const uint8_t *s, size_t i)
{
    if (s[0] != '-')
        return false;
    for (size_t k = 0; k < sizeof(k_sm_glued) / sizeof(k_sm_glued[0]); k++) {
        if (strlen(k_sm_glued[k]) == i && memcmp(s, k_sm_glued[k], i) == 0)
            return true;
    }
    return false;
}

static bool sm_boundary(const uint8_t *s, size_t i)
{
    return vcs_semantic_argv_path_boundary_v1((const char *)s, i);
}

bool vcs_semantic_argv_path_boundary_v1(const char *text, size_t i)
{
    const uint8_t *s = (const uint8_t *)text;
    if (i == 0)
        return true;
    if (memchr("=,:;\"' ", s[i - 1], 7) != NULL)
        return true;
    return sm_glued_at(s, i);
}

static bool sm_virtual_at(const uint8_t *s, size_t n, size_t i)
{
    for (size_t k = 0; k < sizeof(k_sm_virtual) / sizeof(k_sm_virtual[0]);
         k++) {
        size_t vl = strlen(k_sm_virtual[k]);
        if (n - i < vl || memcmp(s + i, k_sm_virtual[k], vl) != 0)
            continue;
        if (n - i == vl || s[i + vl] == '/' || s[i + vl] == '=' ||
            s[i + vl] == ':')
            return true;
    }
    return false;
}

bool sm_argv_ok(const uint8_t *s, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        if (s[i] != '/' || !sm_boundary(s, i))
            continue;
        if (!sm_virtual_at(s, n, i))
            return false;
    }
    return true;
}

/* ---- schema-driven record parse ---------------------------------------- */

static bool sm_sorted_after(struct sm_elem *prev, const uint8_t *p, size_t n)
{
    bool ok = true;
    if (prev->have) {
        size_t m = prev->len < n ? prev->len : n;
        int c = memcmp(prev->p, p, m);
        ok = c < 0 || (c == 0 && prev->len < n);
    }
    prev->have = true;
    prev->p = p;
    prev->len = n;
    return ok;
}

static bool sm_capture_text(struct sm_rec *r, const uint8_t *s, size_t n)
{
    if (r->ntext >= SM_REC_MAX)
        return true;
    r->text[r->ntext].p = s;
    r->text[r->ntext].len = n;
    r->ntext++;
    return true;
}

static void sm_capture_num(struct sm_rec *r, uint64_t v)
{
    if (r->nnum < SM_REC_MAX)
        r->num[r->nnum++] = v;
}

static bool sm_field_text(struct sm_cur *c, char code, struct sm_rec *r)
{
    const uint8_t *s;
    size_t n;
    if (!sm_text(c, &s, &n))
        return false;
    switch (code) {
    case 'P':
        if (!sm_path_ok(s, n, false))
            return false;
        break;
    case 'Q':
        if (n != 0 && !sm_path_ok(s, n, false))
            return false;
        break;
    case 'D':
        if (!sm_path_ok(s, n, true))
            return false;
        break;
    case 'A':
        if (!sm_argv_ok(s, n))
            return false;
        break;
    default:
        break;
    }
    return sm_capture_text(r, s, n);
}

static bool sm_field_num(struct sm_cur *c, char code, struct sm_rec *r)
{
    const uint8_t *p;
    size_t w = code == 'b' ? 1 : code == 'u' ? 4 : 8;
    if (!sm_take(c, w, &p))
        return false;
    sm_capture_num(r, w == 1   ? p[0]
                      : w == 4 ? zcl_read_u32_le(p)
                               : zcl_read_u64_le(p));
    return true;
}

static bool sm_field_env(struct sm_cur *c, size_t index)
{
    const uint8_t *name, *value, *set;
    size_t name_len, value_len;
    if (index >= SM_ENV_COUNT || !sm_text(c, &name, &name_len))
        return false;
    if (name_len != strlen(k_sm_env[index]) ||
        memcmp(name, k_sm_env[index], name_len) != 0)
        return false;
    if (!sm_take(c, 1, &set) || *set > 1 || !sm_text(c, &value, &value_len))
        return false;
    if (*set == 0 && value_len != 0)
        return false;
    return sm_argv_ok(value, value_len);
}

static bool sm_field_layout(struct sm_cur *c)
{
    const uint8_t *s, *p;
    size_t n;
    if (!sm_text(c, &s, &n) || !sm_take(c, 8 + 4, &p))
        return false;
    return sm_text(c, &s, &n);
}

/* A strictly increasing u32 list element. */
static bool sm_elem_u32(struct sm_cur *c, struct sm_elem *prev)
{
    uint32_t v;
    bool ok;
    if (!sm_u32(c, &v))
        return false;
    ok = !prev->have || v > prev->num;
    prev->have = true;
    prev->num = v;
    return ok;
}

/* A probe slot: a strictly increasing u32 slot and its UNKNOWN reason. */
static bool sm_elem_slot(struct sm_cur *c, struct sm_elem *prev)
{
    const uint8_t *reason;
    if (!sm_elem_u32(c, prev) || !sm_take(c, 1, &reason))
        return false;
    return *reason >= VCS_SEMANTIC_PROBE_V1_NO_SNAPSHOT &&
           *reason <= VCS_SEMANTIC_PROBE_V1_UNRESOLVED;
}

static bool sm_list_elem(struct sm_cur *c, char code, size_t index,
                         struct sm_elem *prev)
{
    const uint8_t *s;
    size_t n;
    size_t start = c->off;
    switch (code) {
    case 'S':
        return sm_text(c, &s, &n) &&
               sm_sorted_after(prev, c->p + start, c->off - start);
    case 'U':
        return sm_elem_u32(c, prev);
    case 's':
        return sm_elem_slot(c, prev);
    case 'e':
        return sm_field_env(c, index);
    case 'f':
        return sm_field_layout(c);
    default: {
        struct sm_rec scratch = {0};
        if (code == 'b' || code == 'u' || code == 'q' || code == 'i')
            return sm_field_num(c, code, &scratch);
        return sm_field_text(c, code, &scratch);
    }
    }
}

static bool sm_field_list(struct sm_cur *c, char code, struct sm_rec *r)
{
    uint32_t count;
    struct sm_elem prev = {0};
    if (!sm_u32(c, &count) || count > VCS_SEMANTIC_MANIFEST_V1_MAX_RECORDS)
        return false;
    if (code == 'e' && count != SM_ENV_COUNT)
        return false;
    sm_capture_num(r, count);
    for (uint32_t k = 0; k < count; k++) {
        if (!sm_list_elem(c, code, k, &prev))
            return false;
    }
    return true;
}

bool sm_parse_record(const uint8_t *p, size_t n,
                     enum vcs_semantic_section_v1 section, struct sm_rec *r)
{
    struct sm_cur c = {.p = p, .len = n, .off = 0};
    const char *schema = k_sm_schema[section];
    memset(r, 0, sizeof(*r));
    for (size_t i = 0; schema[i] != '\0'; i++) {
        char code = schema[i];
        bool ok;
        if (code == '[')
            ok = sm_field_list(&c, schema[++i], r);
        else if (code == 'b' || code == 'u' || code == 'q' || code == 'i')
            ok = sm_field_num(&c, code, r);
        else if (code == 'h') {
            const uint8_t *d;
            ok = sm_take(&c, 32, &d);
            if (ok && r->ndigest < 2)
                r->digest[r->ndigest++] = d;
        } else
            ok = sm_field_text(&c, code, r);
        if (!ok)
            return false;
        if (i == 1)
            r->key_len = c.off;
    }
    return c.off == n;
}

/* ---- per-section record rules ------------------------------------------ */

static bool sm_lookup_rules(const struct sm_rec *r)
{
    /* num: form, kind, hit_slot, evidence, present_count */
    uint64_t form = r->num[0], kind = r->num[1];
    uint64_t evidence = r->num[3];
    bool miss = r->text[2].len == 0;
    if (form < VCS_SEMANTIC_FORM_V1_QUOTED || form > VCS_SEMANTIC_FORM_V1_ANGLED)
        return false;
    if (kind < VCS_SEMANTIC_LOOKUP_V1_INCLUDE ||
        kind > VCS_SEMANTIC_LOOKUP_V1_INCLUDE_NEXT)
        return false;
    if (evidence > VCS_SEMANTIC_MISS_V1_REPLAYED_STAT)
        return false;
    if (miss && kind != VCS_SEMANTIC_LOOKUP_V1_HAS_INCLUDE)
        return false;
    if (kind == VCS_SEMANTIC_LOOKUP_V1_INCLUDE_NEXT)
        return evidence == VCS_SEMANTIC_MISS_V1_NONE;
    return true;
}

static bool sm_span_is(const struct sm_span *s, const char *lit)
{
    return s->len == strlen(lit) && memcmp(s->p, lit, s->len) == 0;
}

static bool sm_symbol_kind_ok(const struct sm_span *s)
{
    static const char *const kinds[] = {"function", "variable", "typedef",
                                        "struct", "union", "enum"};
    for (size_t k = 0; k < sizeof(kinds) / sizeof(kinds[0]); k++) {
        if (sm_span_is(s, kinds[k]))
            return true;
    }
    return false;
}

/* A TRUNCATED record names a cappable section: files through probes. */
static int sm_truncated_section(const struct sm_span *s)
{
    for (int t = VCS_SEMANTIC_SECTION_V1_FILES;
         t < VCS_SEMANTIC_SECTION_V1_TRUNCATED; t++) {
        if (t != VCS_SEMANTIC_SECTION_V1_FACTS && sm_span_is(s, k_sm_names[t]))
            return t;
    }
    return 0;
}

static bool sm_probe_rules(const struct sm_rec *r)
{
    /* num: form, kind, claim, unknown_count */
    uint64_t form = r->num[0], kind = r->num[1];
    if (form < VCS_SEMANTIC_FORM_V1_QUOTED || form > VCS_SEMANTIC_FORM_V1_ANGLED)
        return false;
    if (kind < VCS_SEMANTIC_LOOKUP_V1_INCLUDE ||
        kind > VCS_SEMANTIC_LOOKUP_V1_INCLUDE_NEXT)
        return false;
    return r->num[2] <= 1 && (r->num[2] == 1 || r->num[3] == 0);
}

static bool sm_header_rules(const struct sm_rec *r)
{
    /* num: max_records, max_section_bytes, complete */
    return (sm_span_is(&r->text[0], VCS_SEMANTIC_FACTS_V1_NAME) ||
            sm_span_is(&r->text[0], VCS_SEMANTIC_FACTS_V2_NAME) ||
            sm_span_is(&r->text[0], VCS_SEMANTIC_FACTS_V3_NAME) ||
            sm_span_is(&r->text[0], VCS_SEMANTIC_FACTS_V4_NAME)) &&
           r->num[0] >= 1 && r->num[0] <= VCS_SEMANTIC_MANIFEST_V1_MAX_RECORDS &&
           r->num[1] >= 4 && r->num[1] <= VCS_SEMANTIC_MANIFEST_V1_MAX_BYTES &&
           r->num[2] <= 1;
}

static bool sm_edge_rules(enum vcs_semantic_section_v1 section,
                          const struct sm_rec *r)
{
    /* REFS num: kind; UNKNOWNS num: kind, occurrences */
    if (r->text[0].len == 0)
        return false;
    if (section == VCS_SEMANTIC_SECTION_V1_REFS)
        return r->text[1].len > 0 && r->num[0] >= VCS_SEMANTIC_REF_V1_CALL &&
               r->num[0] <= VCS_SEMANTIC_REF_V1_MACRO;
    return r->num[0] >= VCS_SEMANTIC_UNKNOWN_V1_INDIRECT_CALL &&
           r->num[0] <= VCS_SEMANTIC_UNKNOWN_V1_UNRESOLVED && r->num[1] >= 1;
}

static bool sm_facts_rules(enum vcs_semantic_section_v1 section,
                           const struct sm_rec *r)
{
    switch (section) {
    case VCS_SEMANTIC_SECTION_V1_FACTS:
        return sm_header_rules(r);
    case VCS_SEMANTIC_SECTION_V1_SYMBOLS:
        return r->text[0].len > 0 && sm_symbol_kind_ok(&r->text[2]) &&
               r->num[0] <= 4 && r->num[1] <= 1;
    case VCS_SEMANTIC_SECTION_V1_REFS:
    case VCS_SEMANTIC_SECTION_V1_UNKNOWNS:
        return sm_edge_rules(section, r);
    case VCS_SEMANTIC_SECTION_V1_PROBES:
        return sm_probe_rules(r);
    case VCS_SEMANTIC_SECTION_V1_TRUNCATED:
        return sm_truncated_section(&r->text[0]) != 0 && r->num[1] >= 1;
    default:
        return false;
    }
}

static bool sm_record_rules(enum vcs_semantic_section_v1 section,
                            const struct sm_rec *r)
{
    if (section > VCS_SEMANTIC_SECTION_V1_BASE_LAST)
        return sm_facts_rules(section, r);
    switch (section) {
    case VCS_SEMANTIC_SECTION_V1_FILES:
        return r->num[0] >= VCS_SEMANTIC_ORIGIN_V1_MAIN &&
               r->num[0] <= VCS_SEMANTIC_ORIGIN_V1_SYSTEM;
    case VCS_SEMANTIC_SECTION_V1_LOOKUPS:
        return sm_lookup_rules(r);
    case VCS_SEMANTIC_SECTION_V1_DECLS:
        return r->num[0] <= 4;
    case VCS_SEMANTIC_SECTION_V1_MACROS:
        return r->num[0] <= 1 && r->num[1] <= 1;
    case VCS_SEMANTIC_SECTION_V1_LAYOUTS:
        return r->num[0] == 1 || r->num[0] == 2;
    case VCS_SEMANTIC_SECTION_V1_FUNCTIONS:
        return r->num[0] <= 4;
    case VCS_SEMANTIC_SECTION_V1_SPANS:
        return r->num[0] <= r->num[1] && r->num[2] <= r->num[3];
    default:
        return true;
    }
}

/* ---- whole-manifest walk ------------------------------------------------ */

static int sm_fail(char *why, size_t why_len, const char *msg,
                   enum vcs_semantic_section_v1 s, uint32_t index)
{
    if (why != NULL && why_len > 0) {
        const char *name = vcs_semantic_section_v1_name(s);
        (void)snprintf(why, why_len, "%s (section %s, record %u)", msg,
                       name != NULL ? name : "-", index);
    }
    return 0;
}

static bool sm_key_equal(const struct sm_elem *prev, const uint8_t *p,
                         size_t key_len)
{
    return prev->have && prev->len == key_len &&
           memcmp(prev->p, p, key_len) == 0;
}

struct sm_walk {
    const uint8_t *main_path;
    size_t main_path_len;
    uint32_t main_files;
    bool main_matched;
    /* facts extension */
    uint32_t count[VCS_SEMANTIC_SECTION_V1_COUNT];
    uint64_t max_records;
    uint64_t max_section_bytes;
    bool complete;
    uint32_t truncated_mask;
    uint32_t truncated_kept[VCS_SEMANTIC_SECTION_V1_COUNT];
    bool truncated_dup;
};

static void sm_note_facts(struct sm_walk *w, enum vcs_semantic_section_v1 s,
                          const struct sm_rec *r)
{
    int t;
    if (s == VCS_SEMANTIC_SECTION_V1_FACTS) {
        w->max_records = r->num[0];
        w->max_section_bytes = r->num[1];
        w->complete = r->num[2] == 1;
        return;
    }
    if (s != VCS_SEMANTIC_SECTION_V1_TRUNCATED)
        return;
    t = sm_truncated_section(&r->text[0]);
    if (w->truncated_mask & (1u << t))
        w->truncated_dup = true;
    w->truncated_mask |= 1u << t;
    w->truncated_kept[t] = (uint32_t)r->num[0];
}

static void sm_note_main(struct sm_walk *w, enum vcs_semantic_section_v1 s,
                         const struct sm_rec *r)
{
    sm_note_facts(w, s, r);
    if (s == VCS_SEMANTIC_SECTION_V1_IDENTITY) {
        w->main_path = r->text[3].p;
        w->main_path_len = r->text[3].len;
        return;
    }
    if (s != VCS_SEMANTIC_SECTION_V1_FILES ||
        r->num[0] != VCS_SEMANTIC_ORIGIN_V1_MAIN)
        return;
    w->main_files++;
    w->main_matched = w->main_path_len == r->text[0].len &&
                      memcmp(w->main_path, r->text[0].p, r->text[0].len) == 0;
}

static bool sm_check_payload(const uint8_t *p, size_t n,
                             enum vcs_semantic_section_v1 s,
                             struct sm_walk *w, char *why, size_t why_len)
{
    struct sm_cur c = {.p = p, .len = n, .off = 0};
    struct sm_elem prev = {0}, prev_key = {0};
    uint32_t count;
    if (!sm_u32(&c, &count) || count > VCS_SEMANTIC_MANIFEST_V1_MAX_RECORDS)
        return sm_fail(why, why_len, "bad record count", s, 0);
    if ((s == VCS_SEMANTIC_SECTION_V1_IDENTITY ||
         s == VCS_SEMANTIC_SECTION_V1_FACTS) && count != 1)
        return sm_fail(why, why_len, "section needs exactly one record", s, 0);
    w->count[s] = count;
    for (uint32_t k = 0; k < count; k++) {
        uint32_t rl;
        const uint8_t *rp;
        struct sm_rec r;
        if (!sm_u32(&c, &rl) || !sm_take(&c, rl, &rp))
            return sm_fail(why, why_len, "truncated record", s, k);
        if (!sm_parse_record(rp, rl, s, &r) || !sm_record_rules(s, &r))
            return sm_fail(why, why_len, "record violates schema", s, k);
        if (!sm_sorted_after(&prev, rp, rl))
            return sm_fail(why, why_len, "records not strictly sorted", s, k);
        if (s == VCS_SEMANTIC_SECTION_V1_FUNCTIONS &&
            sm_key_equal(&prev_key, rp, r.key_len))
            return sm_fail(why, why_len, "duplicate function key", s, k);
        prev_key = (struct sm_elem){.have = true, .p = rp, .len = r.key_len};
        sm_note_main(w, s, &r);
    }
    if (c.off != n)
        return sm_fail(why, why_len, "trailing bytes in section", s, count);
    return true;
}

bool sm_sections(const uint8_t *bytes, size_t len,
                 struct sm_span out[VCS_SEMANTIC_SECTION_V1_COUNT])
{
    size_t ml = strlen(VCS_SEMANTIC_MANIFEST_V1_MAGIC);
    struct sm_cur c = {.p = bytes, .len = len, .off = 0};
    const uint8_t *magic;
    if (bytes == NULL || len > VCS_SEMANTIC_MANIFEST_V1_MAX_BYTES)
        return false;
    if (!sm_take(&c, ml, &magic) ||
        memcmp(magic, VCS_SEMANTIC_MANIFEST_V1_MAGIC, ml) != 0)
        return false;
    for (int t = 1; t < VCS_SEMANTIC_SECTION_V1_COUNT; t++) {
        const uint8_t *tag;
        uint32_t pl;
        out[t] = (struct sm_span){0};
        /* The facts extension is one optional block after the base. */
        if (t == VCS_SEMANTIC_SECTION_V1_FACTS && c.off == len)
            return true;
        if (!sm_take(&c, 1, &tag) || *tag != t || !sm_u32(&c, &pl))
            return false;
        out[t].len = pl;
        if (!sm_take(&c, pl, &out[t].p))
            return false;
    }
    return c.off == len;
}

bool sm_has_facts(const struct sm_span sec[VCS_SEMANTIC_SECTION_V1_COUNT])
{
    return sec[VCS_SEMANTIC_SECTION_V1_FACTS].p != NULL;
}

/* The facts header binds the caps and completeness to the other sections:
 * every cappable section fits the caps, and a section is named in TRUNCATED
 * exactly when it was cut, with its kept count. */
static bool sm_check_facts(const struct sm_span *sec, const struct sm_walk *w,
                           char *why, size_t why_len)
{
    if (w->truncated_dup)
        return sm_fail(why, why_len, "section truncated twice",
                       VCS_SEMANTIC_SECTION_V1_TRUNCATED, 0);
    if (w->complete != (w->count[VCS_SEMANTIC_SECTION_V1_TRUNCATED] == 0))
        return sm_fail(why, why_len, "complete byte disagrees with truncated",
                       VCS_SEMANTIC_SECTION_V1_FACTS, 0);
    for (int t = VCS_SEMANTIC_SECTION_V1_FILES;
         t < VCS_SEMANTIC_SECTION_V1_TRUNCATED; t++) {
        if (t == VCS_SEMANTIC_SECTION_V1_FACTS)
            continue;
        if (w->count[t] > w->max_records || sec[t].len > w->max_section_bytes)
            return sm_fail(why, why_len, "section exceeds its declared cap",
                           (enum vcs_semantic_section_v1)t, w->count[t]);
        if ((w->truncated_mask & (1u << t)) &&
            w->truncated_kept[t] != w->count[t])
            return sm_fail(why, why_len, "truncated kept count disagrees",
                           (enum vcs_semantic_section_v1)t, w->count[t]);
    }
    return true;
}

bool vcs_semantic_manifest_v1_validate(const uint8_t *bytes, size_t len,
                                       char *why, size_t why_len)
{
    struct sm_span sec[VCS_SEMANTIC_SECTION_V1_COUNT] = {0};
    struct sm_walk w = {0};
    int last;
    bool files_cut;
    if (why != NULL && why_len > 0)
        why[0] = '\0';
    if (!sm_sections(bytes, len, sec))
        return sm_fail(why, why_len, "bad magic, section framing or order",
                       VCS_SEMANTIC_SECTION_V1_NONE, 0);
    last = sm_has_facts(sec) ? VCS_SEMANTIC_SECTION_V1_COUNT - 1
                             : VCS_SEMANTIC_SECTION_V1_BASE_LAST;
    for (int t = 1; t <= last; t++) {
        if (!sm_check_payload(sec[t].p, sec[t].len,
                              (enum vcs_semantic_section_v1)t, &w, why,
                              why_len))
            return false;
    }
    if (sm_has_facts(sec) && !sm_check_facts(sec, &w, why, why_len))
        return false;
    /* A FILES section cut by its cap may have lost the main file; it is
     * then named in TRUNCATED and the manifest is not authoritative. */
    files_cut = (w.truncated_mask & (1u << VCS_SEMANTIC_SECTION_V1_FILES)) != 0;
    if (w.main_files > 1 || (w.main_files == 1 && !w.main_matched) ||
        (w.main_files == 0 && !files_cut))
        return sm_fail(why, why_len, "identity main file is not the one main file",
                       VCS_SEMANTIC_SECTION_V1_FILES, 0);
    return true;
}

bool vcs_semantic_root_v1(const uint8_t *bytes, size_t len, uint8_t out[32],
                          char *why, size_t why_len)
{
    struct sha3_256_ctx ctx;
    if (!vcs_semantic_manifest_v1_validate(bytes, len, why, why_len))
        return false;
    sha3_256_init(&ctx);
    sha3_256_write(&ctx, (const unsigned char *)VCS_SEMANTIC_ROOT_V1_DOMAIN,
                   strlen(VCS_SEMANTIC_ROOT_V1_DOMAIN));
    sha3_256_write(&ctx, bytes, len);
    sha3_256_finalize(&ctx, out);
    return true;
}

static void sm_section_root(enum vcs_semantic_section_v1 s,
                            const struct sm_span *span, uint8_t out[32])
{
    struct sha3_256_ctx ctx;
    unsigned char tag = (unsigned char)s;
    sha3_256_init(&ctx);
    sha3_256_write(&ctx,
                   (const unsigned char *)VCS_SEMANTIC_SECTION_ROOT_V1_DOMAIN,
                   strlen(VCS_SEMANTIC_SECTION_ROOT_V1_DOMAIN));
    sha3_256_write(&ctx, &tag, 1);
    sha3_256_write(&ctx, span->p, span->len);
    sha3_256_finalize(&ctx, out);
}

bool vcs_semantic_section_root_v1(const uint8_t *bytes, size_t len,
                                  enum vcs_semantic_section_v1 section,
                                  uint8_t out[32])
{
    struct sm_span sec[VCS_SEMANTIC_SECTION_V1_COUNT] = {0};
    if (vcs_semantic_section_v1_name(section) == NULL ||
        !vcs_semantic_manifest_v1_validate(bytes, len, NULL, 0) ||
        !sm_sections(bytes, len, sec))
        return false;
    if (sec[section].p == NULL)
        return false;
    sm_section_root(section, &sec[section], out);
    return true;
}

bool vcs_semantic_section_count_v1(const uint8_t *bytes, size_t len,
                                   enum vcs_semantic_section_v1 section,
                                   uint32_t *out)
{
    struct sm_span sec[VCS_SEMANTIC_SECTION_V1_COUNT] = {0};
    struct sm_cur c;
    if (vcs_semantic_section_v1_name(section) == NULL ||
        !vcs_semantic_manifest_v1_validate(bytes, len, NULL, 0) ||
        !sm_sections(bytes, len, sec))
        return false;
    if (sec[section].p == NULL)
        return false;
    c = (struct sm_cur){.p = sec[section].p, .len = sec[section].len};
    return sm_u32(&c, out);
}

const char *sm_schema(enum vcs_semantic_section_v1 section)
{
    if (vcs_semantic_section_v1_name(section) == NULL)
        return NULL;
    return k_sm_schema[section];
}

bool vcs_semantic_hint_root_v1(const uint8_t *bytes, size_t len,
                               uint8_t out[32], char *why, size_t why_len)
{
    struct sm_span sec[VCS_SEMANTIC_SECTION_V1_COUNT] = {0};
    struct sha3_256_ctx ctx;
    if (!vcs_semantic_manifest_v1_validate(bytes, len, why, why_len) ||
        !sm_sections(bytes, len, sec))
        return false;
    sha3_256_init(&ctx);
    sha3_256_write(&ctx, (const unsigned char *)VCS_SEMANTIC_HINT_ROOT_V1_DOMAIN,
                   strlen(VCS_SEMANTIC_HINT_ROOT_V1_DOMAIN));
    for (int t = 1; t < VCS_SEMANTIC_SECTION_V1_COUNT; t++) {
        unsigned char tag = (unsigned char)t;
        uint8_t section_root[32];
        if ((VCS_SEMANTIC_HINT_SECTIONS_V1 & (1u << t)) == 0)
            continue;
        sm_section_root((enum vcs_semantic_section_v1)t, &sec[t], section_root);
        sha3_256_write(&ctx, &tag, 1);
        sha3_256_write(&ctx, section_root, 32);
    }
    sha3_256_finalize(&ctx, out);
    return true;
}
