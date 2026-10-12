/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Locate and replace generator-owned blocks. A block is the text
 *          between one exact begin line and one exact end line; every other
 *          byte of the file is preserved. */

#include "toolgen.h"

#include <stdio.h>
#include <string.h>

#define MARK_PREFIX "/* z23-toolgen:"

static size_t begin_line(char *buf, size_t cap, const char *id)
{
    int n = snprintf(buf, cap, MARK_PREFIX "begin %s - generated, do not edit */", id);
    return n > 0 && (size_t)n < cap ? (size_t)n : 0;
}

static size_t end_line(char *buf, size_t cap, const char *id)
{
    int n = snprintf(buf, cap, MARK_PREFIX "end %s */", id);
    return n > 0 && (size_t)n < cap ? (size_t)n : 0;
}

struct marks {
    size_t count;
    size_t line_start[3];
    size_t line_len[3];
};

static void collect_marks(const char *text, size_t len, struct marks *mk)
{
    size_t pre = sizeof MARK_PREFIX - 1u;
    for (size_t pos = 0; pos < len;) {
        const char *nl = memchr(text + pos, '\n', len - pos);
        size_t end = nl ? (size_t)(nl - text) : len;
        if (end - pos >= pre && memcmp(text + pos, MARK_PREFIX, pre) == 0) {
            if (mk->count < 3u) {
                mk->line_start[mk->count] = pos;
                mk->line_len[mk->count] = end - pos;
            }
            mk->count++;
        }
        pos = end + 1u;
    }
}

static bool line_is(const char *text, const struct marks *mk, size_t i, const char *want,
                    size_t want_len)
{
    return mk->line_len[i] == want_len && memcmp(text + mk->line_start[i], want, want_len) == 0;
}

bool tg_block_locate(const char *text, size_t len, const char *id, const char *file,
                     struct tg_block *b, struct tg_err *e)
{
    struct marks mk = {0};
    collect_marks(text, len, &mk);
    if (mk.count == 0)
        return tg_fail(e, "BLOCK_MISSING", "%s has no \"%s\" generated block", file, id);
    char want_b[200], want_e[100];
    size_t lb = begin_line(want_b, sizeof want_b, id);
    size_t le = end_line(want_e, sizeof want_e, id);
    if (mk.count != 2u || !lb || !le || !line_is(text, &mk, 0, want_b, lb) ||
        !line_is(text, &mk, 1, want_e, le))
        return tg_fail(e, "BLOCK_MALFORMED",
                       "%s must hold exactly one \"%s\" begin line followed by its end line", file,
                       id);
    b->body_start = mk.line_start[0] + lb + 1u;
    b->body_end = mk.line_start[1];
    if (b->body_start > b->body_end || b->body_start > len)
        return tg_fail(e, "BLOCK_MALFORMED", "%s: the \"%s\" begin line has no line break", file, id);
    return true;
}

bool tg_block_splice(const char *text, size_t len, const struct tg_block *b,
                     const char *body, size_t body_len, struct tg_sb *out)
{
    tg_sb_putn(out, text, b->body_start);
    tg_sb_putn(out, body, body_len);
    tg_sb_putn(out, text + b->body_end, len - b->body_end);
    return !out->oom;
}
