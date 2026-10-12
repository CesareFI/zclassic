/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: Flattened Device Tree (DTB) writer and reader over caller-owned buffers. */
#include "fdt/fdt.h"

#include "base/serialize_le.h"

#include <string.h>

#define FDT_NOT_FOUND_POS ((size_t)-1)

/* ---- checked arithmetic and big-endian access ---- */

static int sum_ok(size_t *out, size_t a, size_t b)
{
    if (b > SIZE_MAX - a) return 0;
    *out = a + b;
    return 1;
}

static int align4_ok(size_t *out, size_t n)
{
    size_t padded = 0;
    if (!sum_ok(&padded, n, 3u)) return 0;
    *out = padded & ~(size_t)3u;
    return 1;
}

/* ---- writer ---- */

/* Offset of the structure block: header, reservation entries, and the one
 * terminating reservation entry. */
static size_t writer_header_end(const struct fdt_writer *w)
{
    return FDT_HEADER_SIZE + w->rsv_bytes + FDT_RSV_ENTRY_SIZE;
}

static uint8_t *writer_tail(struct fdt_writer *w)
{
    return w->buf + writer_header_end(w) + w->struct_len;
}

/* Succeeds only when the finished blob, with the given extra bytes, fits in
 * cap and in the 32-bit header fields. Every writer call checks this before it
 * writes a byte, so a refused call leaves the buffer and writer unchanged. */
static enum fdt_status writer_fits(const struct fdt_writer *w, size_t rsv_add,
                                   size_t struct_add, size_t str_add)
{
    size_t rsv = 0, need = 0;
    if (!sum_ok(&rsv, w->rsv_bytes, rsv_add) ||
        !sum_ok(&need, FDT_HEADER_SIZE, rsv) ||
        !sum_ok(&need, need, FDT_RSV_ENTRY_SIZE) ||
        !sum_ok(&need, need, w->struct_len) ||
        !sum_ok(&need, need, struct_add) ||
        !sum_ok(&need, need, w->str_len) ||
        !sum_ok(&need, need, str_add) ||
        need > w->cap || need > UINT32_MAX)
        return FDT_ERR_NO_SPACE;
    return FDT_OK;
}

static void writer_put_be32(struct fdt_writer *w, uint32_t v)
{
    zcl_write_u32_be(writer_tail(w), v);
    w->struct_len += 4u;
}

static void writer_put_raw(struct fdt_writer *w, const void *p, size_t n)
{
    if (n != 0) memcpy(writer_tail(w), p, n);
    w->struct_len += n;
}

static void writer_pad4(struct fdt_writer *w)
{
    size_t pad = (4u - (w->struct_len & 3u)) & 3u;
    memset(writer_tail(w), 0, pad);
    w->struct_len += pad;
}

/* Name rules: no '/', length at most max_len. The root name is the empty
 * string; every other node name and every property name is non-empty. */
static enum fdt_status name_check(const char *name, size_t max_len, int allow_empty,
                                  size_t *len)
{
    size_t n = 0;
    while (n <= max_len && name[n] != '\0') {
        if (name[n] == '/') return FDT_ERR_BAD_NAME;
        n++;
    }
    if (n > max_len || (n == 0 && !allow_empty)) return FDT_ERR_BAD_NAME;
    *len = n;
    return FDT_OK;
}

static size_t strings_find(const struct fdt_writer *w, const char *name)
{
    size_t p = 0;
    while (p < w->str_len) {
        const char *s = (const char *)w->strings + p;
        if (strcmp(s, name) == 0) return p;
        p += strlen(s) + 1u;
    }
    return FDT_NOT_FOUND_POS;
}

/* Checks everything, then interns the name and writes the PROP header. The
 * caller then writes exactly data_len bytes and pads to 4. */
static enum fdt_status writer_prop_begin(struct fdt_writer *w, const char *name,
                                         size_t data_len)
{
    size_t nlen = 0, padded = 0, struct_add = 0, add = 0, nameoff = 0;
    size_t found;
    enum fdt_status st;
    if (w->finished) return FDT_ERR_STATE;
    if (w->depth == 0) return FDT_ERR_NESTING;
    st = name_check(name, FDT_MAX_NAME, 0, &nlen);
    if (st != FDT_OK) return st;
    if (data_len > UINT32_MAX || !align4_ok(&padded, data_len) ||
        !sum_ok(&struct_add, 12u, padded))
        return FDT_ERR_NO_SPACE;
    found = strings_find(w, name);
    if (found == FDT_NOT_FOUND_POS) add = nlen + 1u;
    if (add > FDT_STRINGS_MAX - w->str_len) return FDT_ERR_NO_SPACE;
    if (writer_fits(w, 0, struct_add, add) != FDT_OK) return FDT_ERR_NO_SPACE;
    if (found == FDT_NOT_FOUND_POS) {
        nameoff = w->str_len;
        memcpy(w->strings + nameoff, name, nlen + 1u);
        w->str_len += add;
    } else {
        nameoff = found;
    }
    writer_put_be32(w, FDT_TOKEN_PROP);
    writer_put_be32(w, (uint32_t)data_len);
    writer_put_be32(w, (uint32_t)nameoff);
    return FDT_OK;
}

enum fdt_status fdt_writer_init(struct fdt_writer *w, uint8_t *buf, size_t cap)
{
    if (!w || !buf) return FDT_ERR_ARG;
    w->buf = buf;
    w->cap = cap;
    w->rsv_bytes = 0;
    w->struct_len = 0;
    w->depth = 0;
    w->str_len = 0;
    w->root_closed = 0;
    w->finished = 0;
    return FDT_OK;
}

enum fdt_status fdt_add_reservation(struct fdt_writer *w, uint64_t addr, uint64_t size)
{
    uint8_t *entry;
    if (!w) return FDT_ERR_ARG;
    if (w->finished || w->struct_len != 0) return FDT_ERR_STATE;
    if (size == 0) return FDT_ERR_ARG;
    if (writer_fits(w, FDT_RSV_ENTRY_SIZE, 0, 0) != FDT_OK) return FDT_ERR_NO_SPACE;
    entry = w->buf + FDT_HEADER_SIZE + w->rsv_bytes;
    zcl_write_u64_be(entry, addr);
    zcl_write_u64_be(entry + 8, size);
    w->rsv_bytes += FDT_RSV_ENTRY_SIZE;
    return FDT_OK;
}

enum fdt_status fdt_begin_node(struct fdt_writer *w, const char *name)
{
    size_t nlen = 0, struct_add = 0;
    enum fdt_status st;
    if (!w || !name) return FDT_ERR_ARG;
    if (w->finished) return FDT_ERR_STATE;
    if (w->root_closed || w->depth >= FDT_MAX_DEPTH) return FDT_ERR_NESTING;
    st = name_check(name, w->depth == 0 ? 0 : FDT_MAX_NAME, w->depth == 0, &nlen);
    if (st != FDT_OK) return st;
    struct_add = 4u + ((nlen + 1u + 3u) & ~(size_t)3u);
    if (writer_fits(w, 0, struct_add, 0) != FDT_OK) return FDT_ERR_NO_SPACE;
    writer_put_be32(w, FDT_TOKEN_BEGIN_NODE);
    writer_put_raw(w, name, nlen + 1u);
    writer_pad4(w);
    w->depth++;
    return FDT_OK;
}

enum fdt_status fdt_end_node(struct fdt_writer *w)
{
    if (!w) return FDT_ERR_ARG;
    if (w->finished) return FDT_ERR_STATE;
    if (w->depth == 0) return FDT_ERR_NESTING;
    if (writer_fits(w, 0, 4u, 0) != FDT_OK) return FDT_ERR_NO_SPACE;
    writer_put_be32(w, FDT_TOKEN_END_NODE);
    w->depth--;
    if (w->depth == 0) w->root_closed = 1;
    return FDT_OK;
}

enum fdt_status fdt_prop(struct fdt_writer *w, const char *name, const void *data, size_t len)
{
    enum fdt_status st;
    if (!w || !name || (!data && len != 0)) return FDT_ERR_ARG;
    st = writer_prop_begin(w, name, len);
    if (st != FDT_OK) return st;
    writer_put_raw(w, data, len);
    writer_pad4(w);
    return FDT_OK;
}

enum fdt_status fdt_prop_u32(struct fdt_writer *w, const char *name, uint32_t value)
{
    uint8_t be[4];
    zcl_write_u32_be(be, value);
    return fdt_prop(w, name, be, sizeof be);
}

enum fdt_status fdt_prop_u64(struct fdt_writer *w, const char *name, uint64_t value)
{
    uint8_t be[8];
    zcl_write_u64_be(be, value);
    return fdt_prop(w, name, be, sizeof be);
}

enum fdt_status fdt_prop_string(struct fdt_writer *w, const char *name, const char *value)
{
    if (!value) return FDT_ERR_ARG;
    return fdt_prop(w, name, value, strlen(value) + 1u);
}

enum fdt_status fdt_prop_strings(struct fdt_writer *w, const char *name,
                                 const char *const *values, size_t count)
{
    size_t total = 0, i;
    enum fdt_status st;
    if (!w || !name || (!values && count != 0)) return FDT_ERR_ARG;
    for (i = 0; i < count; i++) {
        if (!values[i]) return FDT_ERR_ARG;
        if (!sum_ok(&total, total, strlen(values[i]) + 1u)) return FDT_ERR_NO_SPACE;
    }
    st = writer_prop_begin(w, name, total);
    if (st != FDT_OK) return st;
    for (i = 0; i < count; i++) writer_put_raw(w, values[i], strlen(values[i]) + 1u);
    writer_pad4(w);
    return FDT_OK;
}

enum fdt_status fdt_finish(struct fdt_writer *w, size_t *len)
{
    size_t strings_at, total;
    uint8_t *b;
    if (!w || !len) return FDT_ERR_ARG;
    if (w->finished) return FDT_ERR_STATE;
    if (w->depth != 0 || !w->root_closed) return FDT_ERR_NOT_FINISHED;
    if (writer_fits(w, 0, 4u, 0) != FDT_OK) return FDT_ERR_NO_SPACE;
    writer_put_be32(w, FDT_TOKEN_END);
    strings_at = writer_header_end(w) + w->struct_len;
    total = strings_at + w->str_len;
    b = w->buf;
    memset(b + FDT_HEADER_SIZE + w->rsv_bytes, 0, FDT_RSV_ENTRY_SIZE);
    if (w->str_len != 0) memcpy(b + strings_at, w->strings, w->str_len);
    zcl_write_u32_be(b, FDT_MAGIC);
    zcl_write_u32_be(b + 4, (uint32_t)total);
    zcl_write_u32_be(b + 8, (uint32_t)writer_header_end(w));
    zcl_write_u32_be(b + 12, (uint32_t)strings_at);
    zcl_write_u32_be(b + 16, FDT_HEADER_SIZE);
    zcl_write_u32_be(b + 20, FDT_VERSION);
    zcl_write_u32_be(b + 24, FDT_LAST_COMP_VERSION);
    zcl_write_u32_be(b + 28, 0);
    zcl_write_u32_be(b + 32, (uint32_t)w->str_len);
    zcl_write_u32_be(b + 36, (uint32_t)w->struct_len);
    w->finished = 1;
    *len = total;
    return FDT_OK;
}

/* ---- reader ---- */

struct fdt_view {
    const uint8_t *b;
    size_t total;
    size_t rsv;
    size_t sbase;
    size_t send;
    size_t strbase;
    size_t strend;
};

static enum fdt_status check_identity(const uint8_t *b, size_t len, size_t *total)
{
    if (len < FDT_HEADER_SIZE) return FDT_ERR_TRUNCATED;
    if (zcl_read_u32_be(b) != FDT_MAGIC) return FDT_ERR_BAD_MAGIC;
    *total = zcl_read_u32_be(b + 4);
    if (*total < FDT_HEADER_SIZE || *total > len) return FDT_ERR_TOTALSIZE;
    if (zcl_read_u32_be(b + 24) > FDT_VERSION || zcl_read_u32_be(b + 20) < zcl_read_u32_be(b + 24))
        return FDT_ERR_BAD_VERSION;
    return FDT_OK;
}

static enum fdt_status check_layout(const uint8_t *b, struct fdt_view *v)
{
    size_t rsv_off = zcl_read_u32_be(b + 16), sbase = zcl_read_u32_be(b + 8);
    size_t stroff = zcl_read_u32_be(b + 12), size_str = zcl_read_u32_be(b + 32);
    size_t size_struct = zcl_read_u32_be(b + 36);
    if ((rsv_off & 7u) != 0 || (sbase & 3u) != 0 || (size_struct & 3u) != 0)
        return FDT_ERR_ALIGN;
    if (rsv_off < FDT_HEADER_SIZE || sbase < FDT_HEADER_SIZE || stroff < FDT_HEADER_SIZE)
        return FDT_ERR_OFFSET;
    if (!sum_ok(&v->send, sbase, size_struct) || v->send > v->total)
        return FDT_ERR_TOTALSIZE;
    if (!sum_ok(&v->strend, stroff, size_str) || v->strend > v->total)
        return FDT_ERR_TOTALSIZE;
    v->rsv = rsv_off;
    v->sbase = sbase;
    v->strbase = stroff;
    return FDT_OK;
}

/* The reservation block must end in an all-zero entry inside the blob. */
static enum fdt_status check_reservations(const uint8_t *b, const struct fdt_view *v)
{
    size_t pos = v->rsv;
    for (;;) {
        if (pos > v->total || v->total - pos < FDT_RSV_ENTRY_SIZE)
            return FDT_ERR_TOTALSIZE;
        if (zcl_read_u64_be(b + pos) == 0 && zcl_read_u64_be(b + pos + 8) == 0) return FDT_OK;
        pos += FDT_RSV_ENTRY_SIZE;
    }
}

/* Finds the NUL that ends a string starting at start and lying before limit. */
static int find_nul(const uint8_t *b, size_t limit, size_t start, size_t *nul)
{
    size_t i;
    for (i = start; i < limit; i++) {
        if (b[i] == 0) {
            *nul = i;
            return 1;
        }
    }
    return 0;
}

static int prop_name_ok(const uint8_t *b, const struct fdt_view *v, size_t nameoff)
{
    size_t nul = 0;
    if (nameoff >= v->strend - v->strbase) return 0;
    return find_nul(b, v->strend, v->strbase + nameoff, &nul);
}

/* Returns the offset just past a PROP token's padded data, if it fits. */
static int prop_end(size_t pos, size_t len, size_t send, size_t *out)
{
    size_t data = 0, padded = 0, end = 0;
    if (!sum_ok(&data, pos, 12u) || !align4_ok(&padded, len) ||
        !sum_ok(&end, data, padded) || end > send)
        return 0;
    *out = end;
    return 1;
}

static enum fdt_status walk_prop(const uint8_t *b, const struct fdt_view *v, size_t *pos)
{
    size_t end = 0;
    if (v->send - *pos < 12u) return FDT_ERR_TRUNCATED;
    if (!prop_name_ok(b, v, zcl_read_u32_be(b + *pos + 8))) return FDT_ERR_STRING_OFFSET;
    if (!prop_end(*pos, zcl_read_u32_be(b + *pos + 4), v->send, &end)) return FDT_ERR_TRUNCATED;
    *pos = end;
    return FDT_OK;
}

static enum fdt_status walk_begin(const uint8_t *b, const struct fdt_view *v,
                                  size_t *pos, size_t *depth)
{
    size_t nul = 0, next = 0;
    if (*depth == 0 && *pos != v->sbase) return FDT_ERR_BAD_TOKEN;
    if (*depth >= FDT_MAX_DEPTH) return FDT_ERR_NESTING;
    if (!find_nul(b, v->send, *pos + 4u, &nul)) return FDT_ERR_TRUNCATED;
    if (!align4_ok(&next, nul + 1u) || next > v->send) return FDT_ERR_TRUNCATED;
    *pos = next;
    (*depth)++;
    return FDT_OK;
}

static enum fdt_status step_token(const uint8_t *b, const struct fdt_view *v,
                                  size_t *pos, size_t *depth, uint32_t tok)
{
    switch (tok) {
    case FDT_TOKEN_BEGIN_NODE:
        return walk_begin(b, v, pos, depth);
    case FDT_TOKEN_END_NODE:
        if (*depth == 0) return FDT_ERR_NESTING;
        (*depth)--;
        *pos += 4u;
        return FDT_OK;
    case FDT_TOKEN_PROP:
        if (*depth == 0) return FDT_ERR_BAD_TOKEN;
        return walk_prop(b, v, pos);
    case FDT_TOKEN_NOP:
        *pos += 4u;
        return FDT_OK;
    default:
        return FDT_ERR_BAD_TOKEN;
    }
}

static enum fdt_status check_end(const struct fdt_view *v, size_t pos, size_t depth)
{
    if (depth != 0) return FDT_ERR_NESTING;
    if (pos + 4u != v->send) return FDT_ERR_BAD_TOKEN;
    return FDT_OK;
}

/* Walks the whole structure block. The root must open it, nesting stays within
 * FDT_MAX_DEPTH, and the block must close with FDT_END as its last token. */
static enum fdt_status check_tokens(const uint8_t *b, const struct fdt_view *v)
{
    size_t pos = v->sbase, depth = 0;
    enum fdt_status st;
    if (v->send - pos < 4u) return FDT_ERR_NO_END;
    if (zcl_read_u32_be(b + pos) != FDT_TOKEN_BEGIN_NODE) return FDT_ERR_BAD_TOKEN;
    for (;;) {
        uint32_t tok;
        if (v->send - pos < 4u) return FDT_ERR_NO_END;
        tok = zcl_read_u32_be(b + pos);
        if (tok == FDT_TOKEN_END) return check_end(v, pos, depth);
        st = step_token(b, v, &pos, &depth, tok);
        if (st != FDT_OK) return st;
    }
}

static enum fdt_status view_open(const void *buf, size_t len, struct fdt_view *v)
{
    const uint8_t *b = buf;
    enum fdt_status st;
    if (!buf) return FDT_ERR_ARG;
    v->b = b;
    st = check_identity(b, len, &v->total);
    if (st != FDT_OK) return st;
    st = check_layout(b, v);
    if (st != FDT_OK) return st;
    st = check_reservations(b, v);
    if (st != FDT_OK) return st;
    return check_tokens(b, v);
}

enum fdt_status fdt_check(const void *buf, size_t len)
{
    struct fdt_view v;
    return view_open(buf, len, &v);
}

/* ---- node navigation over a validated blob ---- */

/* Reads the name of the BEGIN_NODE token at pos and the offset just past its
 * padded name. */
static int node_name(const uint8_t *b, const struct fdt_view *v, size_t pos,
                     const char **name, size_t *len, size_t *after)
{
    size_t nul = 0;
    if (!find_nul(b, v->send, pos + 4u, &nul)) return 0;
    if (!align4_ok(after, nul + 1u)) return 0;
    *name = (const char *)(b + pos + 4u);
    *len = nul - (pos + 4u);
    return 1;
}

/* A path segment matches a node name exactly, or, when the segment has no
 * unit address, when it equals the part of the node name before '@'. */
static int name_matches(const char *nm, size_t nlen, const char *seg, size_t slen)
{
    const char *at;
    size_t base = nlen;
    if (nlen == slen && memcmp(nm, seg, slen) == 0) return 1;
    if (memchr(seg, '@', slen) != NULL) return 0;
    at = memchr(nm, '@', nlen);
    if (at != NULL) base = (size_t)(at - nm);
    return base == slen && memcmp(nm, seg, slen) == 0;
}

/* Returns the offset just past the subtree whose BEGIN_NODE token is at pos. */
static int skip_node(const uint8_t *b, const struct fdt_view *v, size_t pos, size_t *out)
{
    size_t depth = 0;
    for (;;) {
        uint32_t tok;
        if (v->send - pos < 4u) return 0;
        tok = zcl_read_u32_be(b + pos);
        if (tok == FDT_TOKEN_BEGIN_NODE) {
            const char *n;
            size_t nl = 0, after = 0;
            if (!node_name(b, v, pos, &n, &nl, &after)) return 0;
            depth++;
            pos = after;
        } else if (tok == FDT_TOKEN_END_NODE) {
            if (depth == 0) return 0;
            depth--;
            pos += 4u;
            if (depth == 0) {
                *out = pos;
                return 1;
            }
        } else if (tok == FDT_TOKEN_PROP) {
            size_t end = 0;
            if (v->send - pos < 12u || !prop_end(pos, zcl_read_u32_be(b + pos + 4), v->send, &end))
                return 0;
            pos = end;
        } else if (tok == FDT_TOKEN_NOP) {
            pos += 4u;
        } else {
            return 0;
        }
    }
}

/* Moves *cur to the child named by seg, scanning the direct children of *cur. */
static enum fdt_status find_child(const uint8_t *b, const struct fdt_view *v,
                                  size_t *cur, const char *seg, size_t seg_len)
{
    const char *n = NULL;
    size_t nl = 0, pos = 0;
    if (!node_name(b, v, *cur, &n, &nl, &pos)) return FDT_ERR_BAD_TOKEN;
    for (;;) {
        uint32_t tok;
        if (v->send - pos < 4u) return FDT_ERR_NO_END;
        tok = zcl_read_u32_be(b + pos);
        if (tok == FDT_TOKEN_NOP) {
            pos += 4u;
        } else if (tok == FDT_TOKEN_PROP) {
            size_t end = 0;
            if (!prop_end(pos, zcl_read_u32_be(b + pos + 4), v->send, &end)) return FDT_ERR_TRUNCATED;
            pos = end;
        } else if (tok == FDT_TOKEN_BEGIN_NODE) {
            size_t after = 0;
            if (!node_name(b, v, pos, &n, &nl, &after)) return FDT_ERR_BAD_TOKEN;
            if (name_matches(n, nl, seg, seg_len)) {
                *cur = pos;
                return FDT_OK;
            }
            if (!skip_node(b, v, pos, &pos)) return FDT_ERR_BAD_TOKEN;
        } else {
            return FDT_ERR_NOT_FOUND;
        }
    }
}

/* Resolves the remaining path segments p starting from node cur. */
static enum fdt_status walk_path(const uint8_t *b, const struct fdt_view *v,
                                 const char *p, size_t cur, fdt_node_t *out)
{
    while (*p != '\0') {
        const char *end = strchr(p, '/');
        size_t seg_len = end != NULL ? (size_t)(end - p) : strlen(p);
        enum fdt_status st;
        if (seg_len == 0) return FDT_ERR_NOT_FOUND;
        st = find_child(b, v, &cur, p, seg_len);
        if (st != FDT_OK) return st;
        p += seg_len;
        if (*p == '/') p++;
    }
    *out = cur;
    return FDT_OK;
}

enum fdt_status fdt_find_node(const void *buf, size_t len, const char *path,
                              fdt_node_t *node)
{
    struct fdt_view v;
    enum fdt_status st;
    if (!path || !node || path[0] != '/') return FDT_ERR_ARG;
    st = view_open(buf, len, &v);
    if (st != FDT_OK) return st;
    return walk_path(v.b, &v, path + 1, v.sbase, node);
}

/* Searches the direct properties of the node whose body starts at pos. Each
 * PROP header and its padded payload are validated against the structure block
 * before the name is compared or anything is returned. */
static enum fdt_status find_prop(const uint8_t *b, const struct fdt_view *v, size_t pos,
                                 const char *name, const uint8_t **data, size_t *data_len)
{
    for (;;) {
        uint32_t tok;
        if (v->send - pos < 4u) return FDT_ERR_NO_END;
        tok = zcl_read_u32_be(b + pos);
        if (tok == FDT_TOKEN_NOP) {
            pos += 4u;
        } else if (tok == FDT_TOKEN_PROP) {
            size_t len, end = 0, nameoff;
            if (v->send - pos < 12u) return FDT_ERR_TRUNCATED;
            len = zcl_read_u32_be(b + pos + 4);
            nameoff = zcl_read_u32_be(b + pos + 8);
            if (!prop_end(pos, len, v->send, &end)) return FDT_ERR_TRUNCATED;
            if (!prop_name_ok(b, v, nameoff)) return FDT_ERR_STRING_OFFSET;
            if (strcmp((const char *)b + v->strbase + nameoff, name) == 0) {
                *data = b + pos + 12u;
                *data_len = len;
                return FDT_OK;
            }
            pos = end;
        } else if (tok == FDT_TOKEN_BEGIN_NODE) {
            if (!skip_node(b, v, pos, &pos)) return FDT_ERR_BAD_TOKEN;
        } else {
            return FDT_ERR_NOT_FOUND;
        }
    }
}

/* A node offset is valid only when a token walk from the start of the
 * structure block, following real tokens and skipping property payload without
 * reading it, lands exactly on it at a BEGIN_NODE token. */
static int valid_node(const uint8_t *b, const struct fdt_view *v, fdt_node_t node)
{
    size_t pos = v->sbase, depth = 0;
    if (node < v->sbase || node >= v->send || ((node - v->sbase) & 3u) != 0) return 0;
    while (pos < node && v->send - pos >= 4u) {
        uint32_t tok = zcl_read_u32_be(b + pos);
        if (tok == FDT_TOKEN_END) return 0;
        if (step_token(b, v, &pos, &depth, tok) != FDT_OK) return 0;
    }
    return pos == node && v->send - pos >= 4u &&
           zcl_read_u32_be(b + pos) == FDT_TOKEN_BEGIN_NODE;
}

enum fdt_status fdt_get_prop(const void *buf, size_t len, fdt_node_t node,
                             const char *name, const uint8_t **data, size_t *data_len)
{
    struct fdt_view v;
    const char *n = NULL;
    size_t nl = 0, pos = 0;
    enum fdt_status st;
    if (!name || !data || !data_len) return FDT_ERR_ARG;
    st = view_open(buf, len, &v);
    if (st != FDT_OK) return st;
    if (!valid_node(v.b, &v, node)) return FDT_ERR_BAD_NODE;
    if (!node_name(v.b, &v, node, &n, &nl, &pos)) return FDT_ERR_BAD_TOKEN;
    return find_prop(v.b, &v, pos, name, data, data_len);
}
