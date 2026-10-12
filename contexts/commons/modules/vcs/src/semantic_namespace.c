/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Load one ZVCS snapshot manifest by tree hash and answer include-probe absence against its immutable namespace. */
#include "vcs/semantic_namespace.h"

#include "vcs/semantic_manifest.h"
#include "vcs/vcs_manifest.h"

#include "base/hex.h"
#include "base/safe_alloc.h"
#include "base/serialize_le.h"
#include "sha3/sha3.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ZVCS object tags (vcs/vcs_object.h): content, entry and manifest. */
#define NS_TAG_BLOB 0x20
#define NS_TAG_ENTRY 0x21
#define NS_TAG_MANIFEST 0x22
#define NS_MODE_TYPE 0170000u
#define NS_MODE_REG 0100000u

struct ns_entry {
    const char *path; /* points into wire copy, NUL-terminated by us */
    uint32_t mode;
    uint8_t blob[32];
};

struct vcs_semantic_namespace_v1 {
    uint8_t root[32];
    char *paths;          /* all paths, each NUL-terminated */
    struct ns_entry *entries;
    size_t count;
};

static bool ns_fail(char *why, size_t why_len, const char *msg)
{
    if (why != NULL && why_len > 0)
        (void)snprintf(why, why_len, "%s", msg);
    return false;
}

/* SHA3(0x21 || path || 0x00 || mode_le32 || size_le64 || blob), the ZVCS
 * entry hash (vcs_manifest_entry_hash). */
static void ns_entry_hash(const uint8_t *path, size_t n, const uint8_t *mode4,
                          const uint8_t *size8, const uint8_t blob[32],
                          uint8_t out[32])
{
    struct sha3_256_ctx ctx;
    uint8_t tag = NS_TAG_ENTRY, nul = 0;
    sha3_256_init(&ctx);
    sha3_256_write(&ctx, &tag, 1);
    sha3_256_write(&ctx, path, n);
    sha3_256_write(&ctx, &nul, 1);
    sha3_256_write(&ctx, mode4, 4);
    sha3_256_write(&ctx, size8, 8);
    sha3_256_write(&ctx, blob, 32);
    sha3_256_finalize(&ctx, out);
}

struct ns_parse {
    const uint8_t *p;
    size_t len, off;
    struct sha3_256_ctx tree;
    size_t path_bytes;
};

static bool ns_take(struct ns_parse *ps, size_t n, const uint8_t **out)
{
    if (ps->len - ps->off < n)
        return false;
    *out = ps->p + ps->off;
    ps->off += n;
    return true;
}

/* One entry: [2 path_len][path][4 mode][8 size][32 blob], strictly after
 * the previous path in byte order (the canonical manifest order). */
static bool ns_parse_entry(struct ns_parse *ps, struct vcs_semantic_namespace_v1 *ns,
                           size_t k, char *cursor)
{
    const uint8_t *lenp, *path, *mode, *size, *blob;
    uint8_t eh[32];
    size_t n;
    if (!ns_take(ps, 2, &lenp))
        return false;
    n = (size_t)zcl_read_u16_le(lenp);
    if (n == 0 || n > VCS_PATH_MAX || !ns_take(ps, n, &path) ||
        memchr(path, 0, n) != NULL || !ns_take(ps, 4, &mode) ||
        !ns_take(ps, 8, &size) || !ns_take(ps, 32, &blob))
        return false;
    memcpy(cursor, path, n);
    cursor[n] = '\0';
    if (k > 0 && strcmp(ns->entries[k - 1].path, cursor) >= 0)
        return false;
    ns->entries[k].path = cursor;
    ns->entries[k].mode = (uint32_t)zcl_read_u32_le(mode);
    memcpy(ns->entries[k].blob, blob, 32);
    ns_entry_hash(path, n, mode, size, blob, eh);
    sha3_256_write(&ps->tree, eh, 32);
    return true;
}

bool vcs_semantic_namespace_v1_from_wire(const uint8_t *wire, size_t len,
                                         const uint8_t tree[32],
                                         struct vcs_semantic_namespace_v1 **out,
                                         char *why, size_t why_len)
{
    struct ns_parse ps = {.p = wire, .len = len};
    struct vcs_semantic_namespace_v1 *ns;
    const uint8_t *head;
    uint8_t tag = NS_TAG_MANIFEST, check[32];
    uint64_t count;
    char *cursor;
    *out = NULL;
    if (wire == NULL || tree == NULL || len < 9 || wire[0] != VCS_MANIFEST_VERSION)
        return ns_fail(why, why_len, "not a ZVCS manifest");
    (void)ns_take(&ps, 9, &head);
    count = zcl_read_u64_le(head + 1);
    /* Every entry takes at least 47 bytes, which bounds the allocation. */
    if (count > (len - 9) / 47)
        return ns_fail(why, why_len, "manifest entry count exceeds its bytes");
    ns = zcl_calloc(1, sizeof(*ns), "semantic_namespace");
    if (ns == NULL)
        return ns_fail(why, why_len, "out of memory");
    ns->entries = zcl_calloc(count ? count : 1, sizeof(*ns->entries),
                             "semantic_namespace.entries");
    ns->paths = zcl_malloc(len, "semantic_namespace.paths");
    if (ns->entries == NULL || ns->paths == NULL) {
        vcs_semantic_namespace_v1_free(ns);
        return ns_fail(why, why_len, "out of memory");
    }
    sha3_256_init(&ps.tree);
    sha3_256_write(&ps.tree, &tag, 1);
    cursor = ns->paths;
    for (uint64_t k = 0; k < count; k++) {
        if (!ns_parse_entry(&ps, ns, (size_t)k, cursor)) {
            vcs_semantic_namespace_v1_free(ns);
            return ns_fail(why, why_len, "malformed or unsorted manifest entry");
        }
        cursor += strlen(cursor) + 1;
    }
    ns->count = (size_t)count;
    sha3_256_finalize(&ps.tree, check);
    if (ps.off != len || memcmp(check, tree, 32) != 0) {
        vcs_semantic_namespace_v1_free(ns);
        return ns_fail(why, why_len, "manifest does not hash to the named tree");
    }
    memcpy(ns->root, tree, 32);
    *out = ns;
    return true;
}

static bool ns_read(const char *path, uint8_t **out, size_t *len)
{
    FILE *fp = fopen(path, "rb");
    long size;
    bool ok = false;
    *out = NULL;
    *len = 0;
    if (fp == NULL)
        return false;
    if (fseek(fp, 0, SEEK_END) == 0 && (size = ftell(fp)) > 0 &&
        (unsigned long)size <= VCS_SEMANTIC_NAMESPACE_V1_MAX_BYTES &&
        fseek(fp, 0, SEEK_SET) == 0) {
        *out = zcl_malloc((size_t)size, "semantic_namespace.wire");
        ok = *out != NULL && fread(*out, 1, (size_t)size, fp) == (size_t)size;
        *len = (size_t)size;
    }
    (void)fclose(fp);
    if (!ok) {
        free(*out);
        *out = NULL;
    }
    return ok;
}

bool vcs_semantic_namespace_v1_load(const char *repo_root,
                                    const uint8_t tree[32],
                                    struct vcs_semantic_namespace_v1 **out,
                                    char *why, size_t why_len)
{
    char hex[65], path[4096 + 128];
    uint8_t *wire = NULL;
    size_t len = 0;
    bool ok;
    int w;
    *out = NULL;
    if (repo_root == NULL || tree == NULL)
        return ns_fail(why, why_len, "no repo root or tree");
    zcl_hex_encode(tree, 32, hex);
    w = snprintf(path, sizeof(path), "%s/.zvcs/objects/%.2s/%s", repo_root,
                 hex, hex + 2);
    if (w < 0 || (size_t)w >= sizeof(path))
        return ns_fail(why, why_len, "snapshot object path too long");
    if (!ns_read(path, &wire, &len))
        return ns_fail(why, why_len, "snapshot tree object is not in the ZVCS store");
    ok = vcs_semantic_namespace_v1_from_wire(wire, len, tree, out, why, why_len);
    free(wire);
    return ok;
}

void vcs_semantic_namespace_v1_free(struct vcs_semantic_namespace_v1 *ns)
{
    if (ns == NULL)
        return;
    free(ns->entries);
    free(ns->paths);
    free(ns);
}

const uint8_t *vcs_semantic_namespace_v1_root(
    const struct vcs_semantic_namespace_v1 *ns)
{
    return ns != NULL ? ns->root : NULL;
}

size_t vcs_semantic_namespace_v1_count(const struct vcs_semantic_namespace_v1 *ns)
{
    return ns != NULL ? ns->count : 0;
}

static const struct ns_entry *ns_find(const struct vcs_semantic_namespace_v1 *ns,
                                      const char *path)
{
    size_t lo = 0, hi = ns->count;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        int c = strcmp(ns->entries[mid].path, path);
        if (c == 0)
            return &ns->entries[mid];
        if (c < 0)
            lo = mid + 1;
        else
            hi = mid;
    }
    return NULL;
}

bool vcs_semantic_namespace_v1_binds(const struct vcs_semantic_namespace_v1 *ns,
                                     const char *relpath, const uint8_t *content,
                                     size_t size)
{
    const struct ns_entry *e;
    struct sha3_256_ctx ctx;
    uint8_t tag = NS_TAG_BLOB, blob[32];
    if (ns == NULL || relpath == NULL || (content == NULL && size > 0))
        return false;
    e = ns_find(ns, relpath);
    if (e == NULL || (e->mode & NS_MODE_TYPE) != NS_MODE_REG)
        return false;
    sha3_256_init(&ctx);
    sha3_256_write(&ctx, &tag, 1);
    if (size > 0)
        sha3_256_write(&ctx, content, size);
    sha3_256_finalize(&ctx, blob);
    return memcmp(blob, e->blob, 32) == 0;
}

/* Join dir and name lexically, resolving "." and ".." components. False
 * when the result escapes the checkout, is empty or is too long. */
/* Apply one path component to out[0..*w): ".." pops (false above the
 * root), "." and "" are skipped, anything else is appended. */
static bool ns_component(const char *p, size_t len, char out[VCS_PATH_MAX + 1],
                         size_t *w)
{
    if (len == 2 && p[0] == '.' && p[1] == '.') {
        if (*w == 0)
            return false;
        while (*w > 0 && out[*w - 1] != '/')
            (*w)--;
        if (*w > 0)
            (*w)--;
        return true;
    }
    if (len == 0 || (len == 1 && p[0] == '.'))
        return true;
    if (*w + (*w > 0) + len > VCS_PATH_MAX)
        return false;
    if (*w > 0)
        out[(*w)++] = '/';
    memcpy(out + *w, p, len);
    *w += len;
    return true;
}

static bool ns_join(const char *dir, const char *name, char out[VCS_PATH_MAX + 1])
{
    char buf[2 * VCS_PATH_MAX + 2];
    size_t w = 0;
    int n = strcmp(dir, ".") == 0 ? snprintf(buf, sizeof(buf), "%s", name)
                                  : snprintf(buf, sizeof(buf), "%s/%s", dir, name);
    if (n <= 0 || (size_t)n >= sizeof(buf) || name[0] == '/')
        return false;
    for (char *p = buf; *p != '\0';) {
        char *slash = strchr(p, '/');
        size_t len = slash != NULL ? (size_t)(slash - p) : strlen(p);
        if (!ns_component(p, len, out, &w))
            return false;
        p += len + (slash != NULL);
    }
    out[w] = '\0';
    return w > 0;
}

uint8_t vcs_semantic_namespace_v1_absent(
    const struct vcs_semantic_namespace_v1 *ns, const char *dir,
    const char *name)
{
    char path[VCS_PATH_MAX + 1];
    if (ns == NULL)
        return VCS_SEMANTIC_PROBE_V1_NO_SNAPSHOT;
    if (dir == NULL || name == NULL)
        return VCS_SEMANTIC_PROBE_V1_UNRESOLVED;
    if (strncmp(dir, "@sys", 4) == 0)
        return VCS_SEMANTIC_PROBE_V1_OUTSIDE;
    if (!ns_join(dir, name, path))
        return VCS_SEMANTIC_PROBE_V1_UNRESOLVED;
    if (vcs_path_ignored(path))
        return VCS_SEMANTIC_PROBE_V1_EXCLUDED;
    if (ns_find(ns, path) != NULL)
        return VCS_SEMANTIC_PROBE_V1_STALE;
    /* Every proper prefix must be a directory: an entry there is a file or
     * link the lookup would pass through, so absence is not listed. */
    for (char *p = strchr(path, '/'); p != NULL; p = strchr(p + 1, '/')) {
        bool hit;
        *p = '\0';
        hit = ns_find(ns, path) != NULL;
        *p = '/';
        if (hit)
            return VCS_SEMANTIC_PROBE_V1_NOT_DIRECTORY;
    }
    return 0;
}
