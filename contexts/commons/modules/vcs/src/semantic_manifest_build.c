/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Canonical builder, function token hash and section/function diff for semantic manifest v1. */
#include "vcs/semantic_manifest.h"

#include "semantic_manifest_priv.h"

#include "base/safe_alloc.h"
#include "base/serialize_le.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---- record builder ----------------------------------------------------- */

static void rec_put(struct vcs_semantic_record_v1 *rec, const void *p, size_t n)
{
    if (rec->failed)
        return;
    if (rec->cap - rec->len < n) {
        size_t cap = rec->cap ? rec->cap : 256;
        uint8_t *grown;
        while (cap - rec->len < n) {
            if (cap > SIZE_MAX / 2) {
                rec->failed = true;
                return;
            }
            cap *= 2;
        }
        grown = zcl_realloc(rec->bytes, cap, "semantic_manifest.record");
        if (grown == NULL) {
            rec->failed = true;
            return;
        }
        rec->bytes = grown;
        rec->cap = cap;
    }
    if (n > 0)
        memcpy(rec->bytes + rec->len, p, n);
    rec->len += n;
}

static void le_put(struct vcs_semantic_record_v1 *rec, uint64_t v, size_t w)
{
    uint8_t b[8];
    zcl_write_u64_le(b, v); /* w is 4 or 8: the low bytes come first */
    rec_put(rec, b, w);
}

void vcs_semantic_record_v1_reset(struct vcs_semantic_record_v1 *rec)
{
    rec->len = 0;
    rec->failed = false;
}

void vcs_semantic_record_v1_free(struct vcs_semantic_record_v1 *rec)
{
    free(rec->bytes);
    *rec = (struct vcs_semantic_record_v1){0};
}

void vcs_semantic_record_v1_text(struct vcs_semantic_record_v1 *rec,
                                 const char *s, size_t len)
{
    if (len > VCS_SEMANTIC_MANIFEST_V1_MAX_TEXT) {
        rec->failed = true;
        return;
    }
    le_put(rec, len, 4);
    rec_put(rec, s, len);
}

void vcs_semantic_record_v1_cstr(struct vcs_semantic_record_v1 *rec,
                                 const char *s)
{
    vcs_semantic_record_v1_text(rec, s != NULL ? s : "",
                                s != NULL ? strlen(s) : 0);
}

void vcs_semantic_record_v1_u8(struct vcs_semantic_record_v1 *rec, uint8_t v)
{
    rec_put(rec, &v, 1);
}

void vcs_semantic_record_v1_u32(struct vcs_semantic_record_v1 *rec,
                                uint32_t v)
{
    le_put(rec, v, 4);
}

void vcs_semantic_record_v1_u64(struct vcs_semantic_record_v1 *rec,
                                uint64_t v)
{
    le_put(rec, v, 8);
}

void vcs_semantic_record_v1_i64(struct vcs_semantic_record_v1 *rec,
                                int64_t v)
{
    le_put(rec, (uint64_t)v, 8);
}

void vcs_semantic_record_v1_digest(struct vcs_semantic_record_v1 *rec,
                                   const uint8_t digest[32])
{
    rec_put(rec, digest, 32);
}

/* memcmp order with a proper prefix first: the one ordering every section
 * and every sorted list of the format uses. */
static int sm_bytes_cmp(const uint8_t *a, size_t an, const uint8_t *b,
                        size_t bn)
{
    size_t m = an < bn ? an : bn;
    int c = m ? memcmp(a, b, m) : 0;
    if (c != 0)
        return c;
    return an < bn ? -1 : an > bn ? 1 : 0;
}

static int sm_span_cmp(const void *x, const void *y)
{
    const struct sm_span *a = x, *b = y;
    return sm_bytes_cmp(a->p, a->len, b->p, b->len);
}

/* Encoded text elements share one buffer; spans point into it. */
void vcs_semantic_record_v1_sorted_texts(struct vcs_semantic_record_v1 *rec,
                                         const char *const *items,
                                         size_t count)
{
    struct vcs_semantic_record_v1 tmp = {0};
    struct sm_span *spans;
    size_t off = 0, kept = 0;
    if (count == 0) {
        le_put(rec, 0, 4);
        return;
    }
    spans = zcl_calloc(count, sizeof(*spans), "semantic_manifest.texts");
    for (size_t k = 0; k < count; k++)
        vcs_semantic_record_v1_cstr(&tmp, items[k]);
    if (spans == NULL || tmp.failed) {
        rec->failed = true;
        free(spans);
        vcs_semantic_record_v1_free(&tmp);
        return;
    }
    for (size_t k = 0; k < count; k++) {
        size_t n = 4 + strlen(items[k]);
        spans[k] = (struct sm_span){.p = tmp.bytes + off, .len = n};
        off += n;
    }
    qsort(spans, count, sizeof(*spans), sm_span_cmp);
    for (size_t k = 0; k < count; k++)
        kept += k == 0 || sm_span_cmp(&spans[k - 1], &spans[k]) != 0;
    le_put(rec, kept, 4);
    for (size_t k = 0; k < count; k++) {
        if (k == 0 || sm_span_cmp(&spans[k - 1], &spans[k]) != 0)
            rec_put(rec, spans[k].p, spans[k].len);
    }
    free(spans);
    vcs_semantic_record_v1_free(&tmp);
}

/* ---- manifest builder ---------------------------------------------------- */

struct sm_list {
    struct sm_span *items;
    size_t n;
    size_t cap;
};

struct vcs_semantic_builder_v1 {
    struct sm_list sec[VCS_SEMANTIC_SECTION_V1_COUNT];
    bool facts;
    struct vcs_semantic_facts_v1 caps;
};

bool vcs_semantic_builder_v1_enable_facts(struct vcs_semantic_builder_v1 *b,
                                          const struct vcs_semantic_facts_v1 *f)
{
    if (b == NULL || f == NULL || f->max_records < 1 ||
        f->max_records > VCS_SEMANTIC_MANIFEST_V1_MAX_RECORDS ||
        f->max_section_bytes < 4 ||
        f->max_section_bytes > VCS_SEMANTIC_MANIFEST_V1_MAX_BYTES ||
        f->revision > 4)
        return false;
    b->facts = true;
    b->caps = *f;
    return true;
}

struct vcs_semantic_builder_v1 *vcs_semantic_builder_v1_new(void)
{
    return zcl_calloc(1, sizeof(struct vcs_semantic_builder_v1),
                      "semantic_manifest.builder");
}

void vcs_semantic_builder_v1_free(struct vcs_semantic_builder_v1 *b)
{
    if (b == NULL)
        return;
    for (int t = 0; t < VCS_SEMANTIC_SECTION_V1_COUNT; t++) {
        for (size_t k = 0; k < b->sec[t].n; k++)
            free((void *)b->sec[t].items[k].p);
        free(b->sec[t].items);
    }
    free(b);
}

static bool sm_add_raw(struct vcs_semantic_builder_v1 *b,
                       enum vcs_semantic_section_v1 s,
                       const struct vcs_semantic_record_v1 *rec);

bool vcs_semantic_builder_v1_add(struct vcs_semantic_builder_v1 *b,
                                 enum vcs_semantic_section_v1 section,
                                 const struct vcs_semantic_record_v1 *rec)
{
    if (b == NULL || rec == NULL || rec->failed ||
        vcs_semantic_section_v1_name(section) == NULL ||
        section == VCS_SEMANTIC_SECTION_V1_FACTS ||
        section == VCS_SEMANTIC_SECTION_V1_TRUNCATED)
        return false;
    return sm_add_raw(b, section, rec);
}

static void sm_clear(struct sm_list *l)
{
    for (size_t k = 0; k < l->n; k++)
        free((void *)l->items[k].p);
    l->n = 0;
}

/* Sort, then drop duplicates in place: the canonical record order. */
static void sm_dedupe(struct sm_list *l)
{
    size_t w = 0;
    if (l->n == 0)
        return; /* qsort's base is a nonnull param; an untouched section's
                  * items array is still NULL, so an empty list must return
                  * before the call rather than pass NULL with n==0. */
    qsort(l->items, l->n, sizeof(*l->items), sm_span_cmp);
    for (size_t k = 0; k < l->n; k++) {
        if (w > 0 && sm_span_cmp(&l->items[w - 1], &l->items[k]) == 0) {
            free((void *)l->items[k].p);
            continue;
        }
        l->items[w++] = l->items[k];
    }
    l->n = w;
}

/* The longest canonical prefix within both caps. */
static size_t sm_capped(const struct sm_list *l, uint64_t max_records,
                        uint64_t max_bytes)
{
    uint64_t payload = 4;
    size_t kept = 0;
    while (kept < l->n && kept < max_records &&
           payload + 4 + l->items[kept].len <= max_bytes) {
        payload += 4 + l->items[kept].len;
        kept++;
    }
    return kept;
}

static void sm_emit_section(struct vcs_semantic_record_v1 *out, uint8_t tag,
                            const struct sm_list *l, size_t kept)
{
    size_t payload = 4;
    for (size_t k = 0; k < kept; k++)
        payload += 4 + l->items[k].len;
    vcs_semantic_record_v1_u8(out, tag);
    if (payload > UINT32_MAX) {
        out->failed = true;
        return;
    }
    le_put(out, payload, 4);
    le_put(out, kept, 4);
    for (size_t k = 0; k < kept; k++) {
        le_put(out, l->items[k].len, 4);
        rec_put(out, l->items[k].p, l->items[k].len);
    }
}

static bool sm_add_raw(struct vcs_semantic_builder_v1 *b,
                       enum vcs_semantic_section_v1 s,
                       const struct vcs_semantic_record_v1 *rec)
{
    struct sm_list *l = &b->sec[s];
    uint8_t *copy;
    if (rec->failed)
        return false;
    if (l->n == l->cap) {
        size_t cap = l->cap ? l->cap * 2 : 16;
        struct sm_span *grown =
            zcl_realloc(l->items, cap * sizeof(*grown), "semantic_manifest.list");
        if (grown == NULL)
            return false;
        l->items = grown;
        l->cap = cap;
    }
    copy = zcl_malloc(rec->len ? rec->len : 1, "semantic_manifest.copy");
    if (copy == NULL)
        return false;
    if (rec->len > 0)
        memcpy(copy, rec->bytes, rec->len);
    l->items[l->n++] = (struct sm_span){.p = copy, .len = rec->len};
    return true;
}

/* Apply the caps, then write the TRUNCATED records and the FACTS header. */
static bool sm_apply_caps(struct vcs_semantic_builder_v1 *b,
                          size_t kept[VCS_SEMANTIC_SECTION_V1_COUNT])
{
    struct vcs_semantic_record_v1 rec = {0};
    bool ok = true, complete = true;
    for (int t = VCS_SEMANTIC_SECTION_V1_FILES;
         ok && t < VCS_SEMANTIC_SECTION_V1_TRUNCATED; t++) {
        if (t == VCS_SEMANTIC_SECTION_V1_FACTS)
            continue;
        kept[t] = sm_capped(&b->sec[t], b->caps.max_records,
                            b->caps.max_section_bytes);
        if (kept[t] == b->sec[t].n)
            continue;
        complete = false;
        vcs_semantic_record_v1_reset(&rec);
        vcs_semantic_record_v1_cstr(&rec, vcs_semantic_section_v1_name(
                                              (enum vcs_semantic_section_v1)t));
        vcs_semantic_record_v1_u32(&rec, (uint32_t)kept[t]);
        vcs_semantic_record_v1_u32(&rec, (uint32_t)(b->sec[t].n - kept[t]));
        ok = sm_add_raw(b, VCS_SEMANTIC_SECTION_V1_TRUNCATED, &rec);
    }
    vcs_semantic_record_v1_reset(&rec);
    vcs_semantic_record_v1_cstr(&rec, b->caps.revision == 4
                                          ? VCS_SEMANTIC_FACTS_V4_NAME
                                      : b->caps.revision == 3
                                          ? VCS_SEMANTIC_FACTS_V3_NAME
                                      : b->caps.revision == 2
                                          ? VCS_SEMANTIC_FACTS_V2_NAME
                                          : VCS_SEMANTIC_FACTS_V1_NAME);
    vcs_semantic_record_v1_digest(&rec, b->caps.namespace_root);
    vcs_semantic_record_v1_digest(&rec, b->caps.producer);
    vcs_semantic_record_v1_u32(&rec, b->caps.max_records);
    vcs_semantic_record_v1_u64(&rec, b->caps.max_section_bytes);
    vcs_semantic_record_v1_u8(&rec, complete ? 1 : 0);
    ok = ok && sm_add_raw(b, VCS_SEMANTIC_SECTION_V1_FACTS, &rec);
    vcs_semantic_record_v1_free(&rec);
    sm_dedupe(&b->sec[VCS_SEMANTIC_SECTION_V1_TRUNCATED]);
    kept[VCS_SEMANTIC_SECTION_V1_FACTS] = b->sec[VCS_SEMANTIC_SECTION_V1_FACTS].n;
    kept[VCS_SEMANTIC_SECTION_V1_TRUNCATED] =
        b->sec[VCS_SEMANTIC_SECTION_V1_TRUNCATED].n;
    return ok;
}

static bool sm_finish_fail(char *why, size_t why_len, const char *msg)
{
    if (why != NULL && why_len > 0)
        (void)snprintf(why, why_len, "%s", msg);
    return false;
}

bool vcs_semantic_builder_v1_finish(struct vcs_semantic_builder_v1 *b,
                                    uint8_t **out, size_t *out_len,
                                    char *why, size_t why_len)
{
    struct vcs_semantic_record_v1 m = {0};
    size_t kept[VCS_SEMANTIC_SECTION_V1_COUNT] = {0};
    int last = VCS_SEMANTIC_SECTION_V1_BASE_LAST;
    *out = NULL;
    *out_len = 0;
    if (b == NULL)
        return sm_finish_fail(why, why_len, "no builder");
    for (int t = 1; t < VCS_SEMANTIC_SECTION_V1_COUNT; t++) {
        sm_dedupe(&b->sec[t]);
        kept[t] = b->sec[t].n;
        if (t > last && !b->facts && b->sec[t].n > 0)
            return sm_finish_fail(why, why_len,
                                  "facts records without the facts extension");
    }
    if (b->facts) {
        last = VCS_SEMANTIC_SECTION_V1_COUNT - 1;
        /* finish() owns FACTS and TRUNCATED; a repeated finish rebuilds them. */
        sm_clear(&b->sec[VCS_SEMANTIC_SECTION_V1_FACTS]);
        sm_clear(&b->sec[VCS_SEMANTIC_SECTION_V1_TRUNCATED]);
        if (!sm_apply_caps(b, kept))
            return sm_finish_fail(why, why_len, "facts caps: out of memory");
    }
    rec_put(&m, VCS_SEMANTIC_MANIFEST_V1_MAGIC,
            strlen(VCS_SEMANTIC_MANIFEST_V1_MAGIC));
    for (int t = 1; t <= last; t++)
        sm_emit_section(&m, (uint8_t)t, &b->sec[t], kept[t]);
    if (m.failed) {
        vcs_semantic_record_v1_free(&m);
        return sm_finish_fail(why, why_len, "manifest encoding overflow or OOM");
    }
    if (!vcs_semantic_manifest_v1_validate(m.bytes, m.len, why, why_len)) {
        vcs_semantic_record_v1_free(&m);
        return false;
    }
    *out = m.bytes;
    *out_len = m.len;
    return true;
}

/* ---- function token hash ------------------------------------------------- */

void vcs_semantic_token_hash_v1_init(struct vcs_semantic_token_hash_v1 *h)
{
    sha3_256_init(&h->ctx);
    sha3_256_write(&h->ctx,
                   (const unsigned char *)VCS_SEMANTIC_FN_TOKENS_V1_DOMAIN,
                   strlen(VCS_SEMANTIC_FN_TOKENS_V1_DOMAIN));
}

void vcs_semantic_token_hash_v1_add(struct vcs_semantic_token_hash_v1 *h,
                                    const char *token, size_t len)
{
    uint8_t b[4];
    zcl_write_u32_le(b, (uint32_t)len);
    sha3_256_write(&h->ctx, b, 4);
    sha3_256_write(&h->ctx, (const unsigned char *)token, len);
}

void vcs_semantic_token_hash_v1_final(struct vcs_semantic_token_hash_v1 *h,
                                      uint8_t out[32])
{
    sha3_256_finalize(&h->ctx, out);
}

/* ---- diff ------------------------------------------------------------------ */

struct sm_fn_iter {
    struct sm_cur c;
    uint32_t left;
    struct sm_span rec;
    size_t key_len;
    bool have;
};

static void sm_fn_next(struct sm_fn_iter *it)
{
    uint32_t rl;
    struct sm_rec r;
    it->have = false;
    if (it->left == 0 || !sm_u32(&it->c, &rl) ||
        !sm_take(&it->c, rl, &it->rec.p))
        return;
    it->left--;
    it->rec.len = rl;
    if (!sm_parse_record(it->rec.p, rl, VCS_SEMANTIC_SECTION_V1_FUNCTIONS, &r))
        return;
    it->key_len = r.key_len;
    it->have = true;
}

static bool sm_fn_open(struct sm_fn_iter *it, const struct sm_span *payload)
{
    *it = (struct sm_fn_iter){.c = {.p = payload->p, .len = payload->len}};
    if (!sm_u32(&it->c, &it->left))
        return false;
    sm_fn_next(it);
    return true;
}

static void sm_fn_report(vcs_semantic_fn_change_cb_v1 cb, void *ctx,
                         enum vcs_semantic_fn_change_v1 change,
                         const struct sm_fn_iter *it)
{
    struct sm_cur c = {.p = it->rec.p, .len = it->key_len};
    const uint8_t *path, *name;
    size_t path_len, name_len;
    if (cb == NULL || !sm_text(&c, &path, &path_len) ||
        !sm_text(&c, &name, &name_len))
        return;
    cb(ctx, change, (const char *)path, path_len, (const char *)name,
       name_len);
}

static int sm_fn_order(const struct sm_fn_iter *a, const struct sm_fn_iter *b)
{
    if (!a->have)
        return 1;
    if (!b->have)
        return -1;
    return sm_bytes_cmp(a->rec.p, a->key_len, b->rec.p, b->key_len);
}

static void sm_fn_step(struct sm_fn_iter *a, struct sm_fn_iter *b,
                       struct vcs_semantic_diff_v1 *out,
                       vcs_semantic_fn_change_cb_v1 cb, void *ctx)
{
    int order = sm_fn_order(a, b);
    if (order < 0) {
        out->functions_removed++;
        sm_fn_report(cb, ctx, VCS_SEMANTIC_FN_V1_REMOVED, a);
        sm_fn_next(a);
        return;
    }
    if (order > 0) {
        out->functions_added++;
        sm_fn_report(cb, ctx, VCS_SEMANTIC_FN_V1_ADDED, b);
        sm_fn_next(b);
        return;
    }
    if (sm_span_cmp(&a->rec, &b->rec) != 0) {
        out->functions_changed++;
        sm_fn_report(cb, ctx, VCS_SEMANTIC_FN_V1_CHANGED, b);
    } else {
        out->functions_same++;
    }
    sm_fn_next(a);
    sm_fn_next(b);
}

bool vcs_semantic_manifest_v1_diff(const uint8_t *a, size_t a_len,
                                   const uint8_t *b, size_t b_len,
                                   struct vcs_semantic_diff_v1 *out,
                                   vcs_semantic_fn_change_cb_v1 cb, void *ctx)
{
    struct sm_span sa[VCS_SEMANTIC_SECTION_V1_COUNT] = {0};
    struct sm_span sb[VCS_SEMANTIC_SECTION_V1_COUNT] = {0};
    struct sm_fn_iter ia, ib;
    *out = (struct vcs_semantic_diff_v1){0};
    if (!vcs_semantic_manifest_v1_validate(a, a_len, NULL, 0) ||
        !vcs_semantic_manifest_v1_validate(b, b_len, NULL, 0) ||
        !sm_sections(a, a_len, sa) || !sm_sections(b, b_len, sb))
        return false;
    for (int t = 1; t < VCS_SEMANTIC_SECTION_V1_COUNT; t++) {
        if (sm_span_cmp(&sa[t], &sb[t]) != 0)
            out->changed_sections |= 1u << t;
    }
    out->exact_equal = out->changed_sections == 0;
    out->hint_equal =
        (out->changed_sections & VCS_SEMANTIC_HINT_SECTIONS_V1) == 0;
    if (!sm_fn_open(&ia, &sa[VCS_SEMANTIC_SECTION_V1_FUNCTIONS]) ||
        !sm_fn_open(&ib, &sb[VCS_SEMANTIC_SECTION_V1_FUNCTIONS]))
        return false;
    while (ia.have || ib.have)
        sm_fn_step(&ia, &ib, out, cb, ctx);
    return true;
}
