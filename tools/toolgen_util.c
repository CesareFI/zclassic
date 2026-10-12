/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Diagnostics, text buffer and bounded file reads for z23-toolgen. */

#define _POSIX_C_SOURCE 200809L

#include "toolgen.h"

#include "base/safe_alloc.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

/* Rewrites bytes outside printable ASCII as \xNN so a diagnostic never carries
 * raw manifest or file-name bytes. */
static void sanitize(struct tg_err *e)
{
    char tmp[sizeof e->detail];
    size_t o = 0;
    for (const unsigned char *p = (const unsigned char *)e->detail; *p; p++) {
        if (*p >= 0x20u && *p <= 0x7eu) {
            if (o + 1u >= sizeof tmp)
                break;
            tmp[o++] = (char)*p;
        } else {
            if (o + 4u >= sizeof tmp)
                break;
            o += (size_t)snprintf(tmp + o, 5, "\\x%02X", *p);
        }
    }
    tmp[o] = '\0';
    memcpy(e->detail, tmp, o + 1u);
}

bool tg_fail(struct tg_err *e, const char *code, const char *fmt, ...)
{
    if (e && e->code[0] == '\0') {
        size_t n = strlen(code);
        if (n >= sizeof e->code)
            n = sizeof e->code - 1u;
        memcpy(e->code, code, n);
        e->code[n] = '\0';
        va_list ap;
        va_start(ap, fmt);
        vsnprintf(e->detail, sizeof e->detail, fmt, ap);
        va_end(ap);
        sanitize(e);
    }
    return false;
}

static bool sb_reserve(struct tg_sb *s, size_t extra)
{
    if (s->oom)
        return false;
    if (s->n + extra + 1u <= s->cap)
        return true;
    size_t cap = s->cap ? s->cap : 256u;
    while (cap < s->n + extra + 1u)
        cap *= 2u;
    char *p = zcl_realloc(s->p, cap, "toolgen.sb");
    if (!p) {
        s->oom = true;
        return false;
    }
    s->p = p;
    s->cap = cap;
    return true;
}

void tg_sb_putn(struct tg_sb *s, const char *text, size_t n)
{
    if (!sb_reserve(s, n))
        return;
    if (n)
        memcpy(s->p + s->n, text, n);
    s->n += n;
    s->p[s->n] = '\0';
}

void tg_sb_put(struct tg_sb *s, const char *text)
{
    tg_sb_putn(s, text, strlen(text));
}

void tg_sb_printf(struct tg_sb *s, const char *fmt, ...)
{
    char line[1024];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(line, sizeof line, fmt, ap);
    va_end(ap);
    if (n < 0 || (size_t)n >= sizeof line) {
        s->oom = true;
        return;
    }
    tg_sb_putn(s, line, (size_t)n);
}

void tg_sb_free(struct tg_sb *s)
{
    free(s->p);
    *s = (struct tg_sb){0};
}

bool tg_join(char *out, size_t cap, const char *a, const char *b)
{
    int n = snprintf(out, cap, "%s/%s", a, b);
    return n > 0 && (size_t)n < cap;
}

static enum tg_read read_body(const char *path, size_t size, struct tg_sb *out)
{
    FILE *f = fopen(path, "rb");
    if (!f)
        return TG_READ_IO;
    char chunk[8192];
    size_t total = 0;
    size_t got;
    while ((got = fread(chunk, 1, sizeof chunk, f)) > 0) {
        total += got;
        if (total > size) {
            fclose(f);
            return TG_READ_IO;
        }
        tg_sb_putn(out, chunk, got);
    }
    bool bad = ferror(f) != 0 || total != size || out->oom;
    fclose(f);
    return bad ? TG_READ_IO : TG_READ_OK;
}

enum tg_read tg_read_file(const char *path, size_t limit, struct tg_sb *out)
{
    struct stat st;
    if (lstat(path, &st) != 0)
        return TG_READ_MISSING;
    if (!S_ISREG(st.st_mode))
        return TG_READ_NOT_REGULAR;
    if (st.st_size < 0 || (unsigned long long)st.st_size > limit)
        return TG_READ_TOO_LARGE;
    tg_sb_putn(out, "", 0);
    return read_body(path, (size_t)st.st_size, out);
}

bool tg_err_context(struct tg_err *e, const char *context)
{
    if (!e || e->code[0] == '\0')
        return false;
    char old[sizeof e->detail];
    memcpy(old, e->detail, sizeof old);
    size_t room = sizeof e->detail - 1u;
    size_t cl = strnlen(context, room / 2u);
    size_t ol = strnlen(old, room - cl - 2u);
    memcpy(e->detail, context, cl);
    memcpy(e->detail + cl, ": ", 2u);
    memcpy(e->detail + cl + 2u, old, ol);
    e->detail[cl + 2u + ol] = '\0';
    sanitize(e);
    return false;
}
