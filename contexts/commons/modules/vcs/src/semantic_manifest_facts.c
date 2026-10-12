/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Facts extension reader for semantic manifests: header info, per-record field iteration, canonical identities and negative lookups. */
#include "vcs/semantic_manifest.h"

#include "semantic_manifest_priv.h"

#include "base/serialize_le.h"

#include <stdio.h>
#include <string.h>

bool vcs_semantic_id_v1(char prefix, const char *path, const char *name,
                        bool external, char *out, size_t out_len)
{
    int w;
    if (out == NULL || out_len == 0 || name == NULL)
        return false;
    if (external || path == NULL)
        w = snprintf(out, out_len, "%c:%s", prefix, name);
    else
        w = snprintf(out, out_len, "%c:%s:%s", prefix, path, name);
    return w > 0 && (size_t)w < out_len;
}

static void sf_fields(const struct sm_rec *r, struct vcs_semantic_fields_v1 *f)
{
    memset(f, 0, sizeof(*f));
    for (size_t k = 0; k < r->ntext && k < VCS_SEMANTIC_FIELDS_V1_MAX; k++) {
        f->text[k] = (const char *)r->text[k].p;
        f->text_len[k] = r->text[k].len;
    }
    f->ntext = r->ntext;
    for (size_t k = 0; k < r->nnum && k < VCS_SEMANTIC_FIELDS_V1_MAX; k++)
        f->num[k] = r->num[k];
    f->nnum = r->nnum;
    for (size_t k = 0; k < r->ndigest; k++)
        f->digest[k] = r->digest[k];
    f->ndigest = r->ndigest;
}

bool vcs_semantic_section_v1_each(const uint8_t *bytes, size_t len,
                                  enum vcs_semantic_section_v1 section,
                                  vcs_semantic_record_cb_v1 cb, void *ctx)
{
    struct sm_span sec[VCS_SEMANTIC_SECTION_V1_COUNT] = {0};
    struct sm_cur c;
    uint32_t count;
    if (vcs_semantic_section_v1_name(section) == NULL || cb == NULL ||
        !vcs_semantic_manifest_v1_validate(bytes, len, NULL, 0) ||
        !sm_sections(bytes, len, sec))
        return false;
    if (sec[section].p == NULL)
        return true;
    c = (struct sm_cur){.p = sec[section].p, .len = sec[section].len};
    if (!sm_u32(&c, &count))
        return false;
    for (uint32_t k = 0; k < count; k++) {
        uint32_t rl;
        const uint8_t *rp;
        struct sm_rec r;
        struct vcs_semantic_fields_v1 f;
        if (!sm_u32(&c, &rl) || !sm_take(&c, rl, &rp) ||
            !sm_parse_record(rp, rl, section, &r))
            return false;
        sf_fields(&r, &f);
        if (!cb(ctx, &f))
            return false;
    }
    return true;
}

bool vcs_semantic_manifest_v1_each(const uint8_t *bytes, size_t len,
                                   vcs_semantic_raw_cb_v1 cb, void *ctx)
{
    struct sm_span sec[VCS_SEMANTIC_SECTION_V1_COUNT] = {0};
    if (cb == NULL || !vcs_semantic_manifest_v1_validate(bytes, len, NULL, 0) ||
        !sm_sections(bytes, len, sec))
        return false;
    for (int t = 1; t < VCS_SEMANTIC_SECTION_V1_COUNT; t++) {
        struct sm_cur c = {.p = sec[t].p, .len = sec[t].len};
        uint32_t count;
        if (sec[t].p == NULL)
            continue;
        if (!sm_u32(&c, &count))
            return false;
        for (uint32_t k = 0; k < count; k++) {
            uint32_t rl;
            const uint8_t *rp;
            struct sm_rec r;
            struct vcs_semantic_fields_v1 f;
            if (!sm_u32(&c, &rl) || !sm_take(&c, rl, &rp) ||
                !sm_parse_record(rp, rl, (enum vcs_semantic_section_v1)t, &r))
                return false;
            sf_fields(&r, &f);
            if (!cb(ctx, (enum vcs_semantic_section_v1)t, &f, rp, rl))
                return false;
        }
    }
    return true;
}

static bool sf_name_is(const uint8_t *text, size_t len, const char *name)
{
    return len == strlen(name) && memcmp(text, name, len) == 0;
}

static bool sf_header(void *ctx, const struct vcs_semantic_fields_v1 *f)
{
    struct vcs_semantic_facts_info_v1 *out = ctx;
    out->max_records = (uint32_t)f->num[0];
    out->max_section_bytes = f->num[1];
    out->complete = f->num[2] == 1;
    if (f->ndigest == 2)
        memcpy(out->producer, f->digest[1], 32);
    return true;
}

bool vcs_semantic_facts_v1_info(const uint8_t *bytes, size_t len,
                                struct vcs_semantic_facts_info_v1 *out)
{
    struct sm_span sec[VCS_SEMANTIC_SECTION_V1_COUNT] = {0};
    struct sm_cur c;
    uint32_t count, rl;
    const uint8_t *rp, *text, *digest;
    size_t text_len;
    if (out == NULL)
        return false;
    memset(out, 0, sizeof(*out));
    if (!vcs_semantic_manifest_v1_validate(bytes, len, NULL, 0) ||
        !sm_sections(bytes, len, sec))
        return false;
    if (!sm_has_facts(sec))
        return true;
    /* The one FACTS record: text name, then the 32-byte namespace root and
     * the 32-byte producer digest. */
    c = (struct sm_cur){.p = sec[VCS_SEMANTIC_SECTION_V1_FACTS].p,
                        .len = sec[VCS_SEMANTIC_SECTION_V1_FACTS].len};
    if (!sm_u32(&c, &count) || count != 1 || !sm_u32(&c, &rl) ||
        !sm_take(&c, rl, &rp))
        return false;
    c = (struct sm_cur){.p = rp, .len = rl};
    if (!sm_text(&c, &text, &text_len) || !sm_take(&c, 32, &digest))
        return false;
    memcpy(out->namespace_root, digest, 32);
    out->present = true;
    out->revision = sf_name_is(text, text_len, VCS_SEMANTIC_FACTS_V4_NAME)   ? 4
                    : sf_name_is(text, text_len, VCS_SEMANTIC_FACTS_V3_NAME) ? 3
                    : sf_name_is(text, text_len, VCS_SEMANTIC_FACTS_V2_NAME) ? 2
                                                                             : 1;
    return vcs_semantic_section_v1_each(bytes, len, VCS_SEMANTIC_SECTION_V1_FACTS,
                                        sf_header, out);
}

/* ---- negative lookups ------------------------------------------------------ */

enum { SA_QUOTE = 0, SA_ANGLED = 1, SA_IGNORED = 2 };

/* Skip one text list: u32 count || text*. */
static bool sa_skip_texts(struct sm_cur *c)
{
    uint32_t count;
    const uint8_t *s;
    size_t n;
    if (!sm_u32(c, &count))
        return false;
    for (uint32_t k = 0; k < count; k++)
        if (!sm_text(c, &s, &n))
            return false;
    return true;
}

/* Position c at the start of one IDENTITY dir list ("TQTP[A[D[D[D[e"). */
static bool sa_dir_list(const struct sm_span *ident, int which,
                        struct sm_cur *c)
{
    uint32_t count, rl;
    const uint8_t *rp, *s;
    size_t n;
    *c = (struct sm_cur){.p = ident->p, .len = ident->len};
    if (!sm_u32(c, &count) || count != 1 || !sm_u32(c, &rl) ||
        !sm_take(c, rl, &rp))
        return false;
    *c = (struct sm_cur){.p = rp, .len = rl};
    for (int k = 0; k < 4; k++)
        if (!sm_text(c, &s, &n))
            return false;
    if (!sa_skip_texts(c))
        return false;
    for (int k = 0; k < which; k++)
        if (!sa_skip_texts(c))
            return false;
    return true;
}

/* The index-th dir of one IDENTITY list; false past its end. */
static bool sa_dir_at(const struct sm_span *ident, int which, uint32_t index,
                      struct sm_span *out, uint32_t *count)
{
    struct sm_cur c;
    const uint8_t *s;
    size_t n;
    if (!sa_dir_list(ident, which, &c) || !sm_u32(&c, count))
        return false;
    for (uint32_t k = 0; k < *count; k++) {
        if (!sm_text(&c, &s, &n))
            return false;
        if (k == index) {
            *out = (struct sm_span){.p = s, .len = n};
            return true;
        }
    }
    return false;
}

/* The directory of slot `slot` of one lookup (see the header). */
static bool sa_slot_dir(const struct sm_span *ident, uint64_t form,
                        const struct sm_span *includer, uint32_t slot,
                        struct sm_span *out)
{
    uint32_t count = 0;
    if (form == VCS_SEMANTIC_FORM_V1_QUOTED) {
        if (slot == 0) {
            const uint8_t *slash = NULL;
            for (size_t k = 0; k < includer->len; k++)
                if (includer->p[k] == '/')
                    slash = includer->p + k;
            *out = slash != NULL
                       ? (struct sm_span){.p = includer->p,
                                          .len = (size_t)(slash - includer->p)}
                       : (struct sm_span){.p = (const uint8_t *)".", .len = 1};
            return true;
        }
        /* Past the quote list, sa_dir_at still reports its length. */
        if (sa_dir_at(ident, SA_QUOTE, slot - 1, out, &count))
            return true;
        slot -= 1 + count;
    }
    return sa_dir_at(ident, SA_ANGLED, slot, out, &count);
}

struct sa_lookup {
    struct sm_span includer, spelled;
    uint64_t form, hit_slot, evidence;
    const uint8_t *present;
    uint32_t npresent;
};

/* LOOKUPS "PTbbQub[U". */
static bool sa_parse_lookup(const uint8_t *rp, size_t rl, struct sa_lookup *l)
{
    struct sm_cur c = {.p = rp, .len = rl};
    const uint8_t *b, *s;
    size_t n;
    uint32_t v;
    if (!sm_text(&c, &l->includer.p, &l->includer.len) ||
        !sm_text(&c, &l->spelled.p, &l->spelled.len) || !sm_take(&c, 1, &b))
        return false;
    l->form = b[0];
    if (!sm_take(&c, 1, &b) || !sm_text(&c, &s, &n) || !sm_u32(&c, &v))
        return false;
    l->hit_slot = v;
    if (!sm_take(&c, 1, &b) || !sm_u32(&c, &l->npresent) ||
        !sm_take(&c, (size_t)l->npresent * 4, &l->present))
        return false;
    l->evidence = b[0];
    return true;
}

static bool sa_present(const struct sa_lookup *l, uint32_t slot)
{
    for (uint32_t k = 0; k < l->npresent; k++)
        if (zcl_read_u32_le(l->present + 4 * k) == slot)
            return true;
    return false;
}

static bool sa_lookup(const struct sm_span *ident, const struct sa_lookup *l,
                      vcs_semantic_absent_cb_v1 cb, void *ctx)
{
    if (l->evidence == VCS_SEMANTIC_MISS_V1_NONE)
        return cb(ctx, NULL, 0, (const char *)l->spelled.p, l->spelled.len);
    for (uint32_t s = 0; s < l->hit_slot; s++) {
        struct sm_span dir;
        if (sa_present(l, s))
            continue;
        if (!sa_slot_dir(ident, l->form, &l->includer, s, &dir) ||
            !cb(ctx, (const char *)dir.p, dir.len, (const char *)l->spelled.p,
                l->spelled.len))
            return false;
    }
    return true;
}

static bool sa_ignored(const struct sm_span *ident,
                       vcs_semantic_absent_cb_v1 cb, void *ctx)
{
    struct sm_cur c;
    uint32_t count;
    const uint8_t *s;
    size_t n;
    if (!sa_dir_list(ident, SA_IGNORED, &c) || !sm_u32(&c, &count))
        return false;
    for (uint32_t k = 0; k < count; k++)
        if (!sm_text(&c, &s, &n) || !cb(ctx, (const char *)s, n, NULL, 0))
            return false;
    return true;
}

bool vcs_semantic_absent_v1_each(const uint8_t *bytes, size_t len,
                                 vcs_semantic_absent_cb_v1 cb, void *ctx)
{
    struct sm_span sec[VCS_SEMANTIC_SECTION_V1_COUNT] = {0};
    struct sm_cur c;
    uint32_t count;
    if (cb == NULL || !vcs_semantic_manifest_v1_validate(bytes, len, NULL, 0) ||
        !sm_sections(bytes, len, sec) ||
        !sa_ignored(&sec[VCS_SEMANTIC_SECTION_V1_IDENTITY], cb, ctx))
        return false;
    c = (struct sm_cur){.p = sec[VCS_SEMANTIC_SECTION_V1_LOOKUPS].p,
                        .len = sec[VCS_SEMANTIC_SECTION_V1_LOOKUPS].len};
    if (!sm_u32(&c, &count))
        return false;
    for (uint32_t k = 0; k < count; k++) {
        uint32_t rl;
        const uint8_t *rp;
        struct sa_lookup l;
        if (!sm_u32(&c, &rl) || !sm_take(&c, rl, &rp) ||
            !sa_parse_lookup(rp, rl, &l) ||
            !sa_lookup(&sec[VCS_SEMANTIC_SECTION_V1_IDENTITY], &l, cb, ctx))
            return false;
    }
    return true;
}
