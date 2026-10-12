/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Bind an after manifest to the namespace a plan runs against: every file it read still has its bytes and every lookup it saw miss still misses. */
#include "devloop_facts.h"

#include "sha3/sha3.h"
#include "vcs/semantic_manifest.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

/* A narrowing compares two manifests; it says nothing about the tree the
 * plan runs against unless the "after" manifest is that tree's compile.
 * The main file is bound by the caller's after source. Everything else the
 * compile depended on is checked here, against the files under root:
 *   - every other file it read (repo and system) has the same SHA3-256;
 *   - every include slot it saw absent is still absent, and every ignored
 *     search dir still does not exist, so no header now shadows one it used
 *     (a negative lookup the positive FILES digests cannot see);
 *   - it made no lookup without a negative claim (include_next, computed or
 *     absolute includes), because such a lookup cannot be re-checked.
 * The first failure names the fallback: "after-stale" or "lookup-unbound". */

struct fb_ctx {
    const char *root;
    const char *reason;
    char *detail;
    size_t detail_len;
};

static bool fb_fail(struct fb_ctx *c, const char *reason, const char *fmt, ...)
{
    va_list ap;
    c->reason = reason;
    va_start(ap, fmt);
    (void)vsnprintf(c->detail, c->detail_len, fmt, ap);
    va_end(ap);
    return false;
}

/* Host path of a manifest path: "." is root, "@sys/x" is "/x", anything
 * else is root-relative. name (when not NULL) is appended after a '/'. */
static bool fb_host_path(const struct fb_ctx *c, const char *p, size_t n,
                         const char *name, size_t name_len, char *out,
                         size_t cap)
{
    int w;
    if (n >= 4 && memcmp(p, "@sys", 4) == 0)
        w = snprintf(out, cap, "/%.*s", (int)(n > 5 ? n - 5 : 0), p + 5);
    else if (n == 1 && p[0] == '.')
        w = snprintf(out, cap, "%s", c->root);
    else
        w = snprintf(out, cap, "%s/%.*s", c->root, (int)n, p);
    if (w < 0 || (size_t)w >= cap)
        return false;
    if (name == NULL)
        return true;
    w += snprintf(out + w, cap - (size_t)w, "%s%.*s",
                  out[w - 1] == '/' ? "" : "/", (int)name_len, name);
    return (size_t)w < cap;
}

static bool fb_file_sha3(const char *path, uint8_t out[32])
{
    FILE *fp = fopen(path, "rb");
    struct sha3_256_ctx h;
    unsigned char buf[16384];
    size_t n;
    bool ok;
    if (fp == NULL)
        return false;
    sha3_256_init(&h);
    while ((n = fread(buf, 1, sizeof(buf), fp)) > 0)
        sha3_256_write(&h, buf, n);
    ok = ferror(fp) == 0;
    (void)fclose(fp);
    sha3_256_finalize(&h, out);
    return ok;
}

static bool fb_files_cb(void *ctx, const struct vcs_semantic_fields_v1 *f)
{
    struct fb_ctx *c = ctx;
    char path[4096];
    uint8_t now[32];
    if (f->ntext < 1 || f->nnum < 1 || f->ndigest < 1)
        return fb_fail(c, "after-stale", "a FILES record is malformed");
    if (f->num[0] == VCS_SEMANTIC_ORIGIN_V1_MAIN)
        return true;
    if (!fb_host_path(c, f->text[0], f->text_len[0], NULL, 0, path,
                      sizeof(path)) ||
        !fb_file_sha3(path, now) || memcmp(now, f->digest[0], 32) != 0)
        return fb_fail(c, "after-stale", "%.*s changed since the compile",
                       (int)f->text_len[0], f->text[0]);
    return true;
}

static bool fb_absent_cb(void *ctx, const char *dir, size_t dir_len,
                         const char *name, size_t name_len)
{
    struct fb_ctx *c = ctx;
    char path[4096];
    struct stat st;
    if (dir == NULL)
        return fb_fail(c, "lookup-unbound",
                       "the lookup of %.*s makes no negative claim",
                       (int)name_len, name);
    if (!fb_host_path(c, dir, dir_len, name, name_len, path, sizeof(path)))
        return fb_fail(c, "after-stale", "a probe path is too long");
    if (stat(path, &st) == 0)
        return fb_fail(c, "after-stale", "%.*s%s%.*s now exists",
                       (int)dir_len, dir, name ? "/" : "",
                       (int)(name ? name_len : 0), name ? name : "");
    return true;
}

bool zcl_devloop_facts_bind_after(const char *root,
                                  const struct zcl_devloop_facts_tu *tu,
                                  const char **reason, char *detail,
                                  size_t detail_len)
{
    struct fb_ctx c = {.root = root, .detail = detail,
                       .detail_len = detail_len};
    bool ok = vcs_semantic_section_v1_each(tu->after, tu->after_len,
                                           VCS_SEMANTIC_SECTION_V1_FILES,
                                           fb_files_cb, &c) &&
              vcs_semantic_absent_v1_each(tu->after, tu->after_len,
                                          fb_absent_cb, &c);
    if (!ok && c.reason == NULL)
        (void)fb_fail(&c, "after-stale", "cannot read the after manifest of %s",
                      tu->source);
    *reason = c.reason;
    return ok;
}
