/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Schema-driven text rendering of a valid semantic manifest v1, one line per record. */
#include "vcs/semantic_manifest.h"

#include "semantic_manifest_priv.h"

#include "base/serialize_le.h"

#include <string.h>

static void sd_text(FILE *out, const uint8_t *s, size_t n)
{
    fputc('"', out);
    for (size_t k = 0; k < n; k++) {
        uint8_t ch = s[k];
        if (ch == '"' || ch == '\\')
            fprintf(out, "\\%c", ch);
        else if (ch < 0x20 || ch > 0x7e)
            fprintf(out, "\\x%02x", ch);
        else
            fputc(ch, out);
    }
    fputc('"', out);
}

static uint64_t sd_le(const uint8_t *p, size_t w)
{
    return w == 1   ? p[0]
           : w == 4 ? zcl_read_u32_le(p)
                    : zcl_read_u64_le(p);
}

static bool sd_num(struct sm_cur *c, char code, FILE *out)
{
    const uint8_t *p;
    size_t w = code == 'b' ? 1 : (code == 'u' || code == 'U') ? 4 : 8;
    if (!sm_take(c, w, &p))
        return false;
    if (code == 'i')
        fprintf(out, "%lld", (long long)(int64_t)sd_le(p, w));
    else
        fprintf(out, "%llu", (unsigned long long)sd_le(p, w));
    return true;
}

static bool sd_one(struct sm_cur *c, char code, FILE *out);

/* A composite list element, spelled as field codes at even positions and
 * the separators printed between them at odd positions. A shape has an odd
 * length (it ends on a field code), so the walk stops at the last code and
 * never steps past the terminator. */
static bool sd_composite(struct sm_cur *c, const char *shape, FILE *out)
{
    for (size_t k = 0; shape[k] != '\0'; k += 2) {
        if (k > 0 && fputc(shape[k - 1], out) == EOF)
            return false;
        if (!sd_one(c, shape[k], out))
            return false;
        if (shape[k + 1] == '\0')
            break;
    }
    return true;
}

static bool sd_one(struct sm_cur *c, char code, FILE *out)
{
    const uint8_t *s;
    size_t n;
    switch (code) {
    case 'b': case 'u': case 'U': case 'q': case 'i':
        return sd_num(c, code, out);
    case 'h':
        if (!sm_take(c, 32, &s))
            return false;
        for (int k = 0; k < 32; k++)
            fprintf(out, "%02x", s[k]);
        return true;
    case 'e':
        return sd_composite(c, "T=b:T", out);
    case 's':
        return sd_composite(c, "u:b", out);
    case 'f':
        return sd_composite(c, "T@q:u:T", out);
    default:
        if (!sm_text(c, &s, &n))
            return false;
        sd_text(out, s, n);
        return true;
    }
}

static bool sd_list(struct sm_cur *c, char code, FILE *out)
{
    uint32_t count;
    if (!sm_u32(c, &count))
        return false;
    fputc('[', out);
    for (uint32_t k = 0; k < count; k++) {
        if (k > 0)
            fputc(',', out);
        if (!sd_one(c, code, out))
            return false;
    }
    fputc(']', out);
    return true;
}

static bool sd_record(const uint8_t *p, size_t n, enum vcs_semantic_section_v1 s,
                      FILE *out)
{
    struct sm_cur c = {.p = p, .len = n};
    const char *schema = sm_schema(s);
    fputs(vcs_semantic_section_v1_name(s), out);
    for (size_t i = 0; schema[i] != '\0'; i++) {
        bool ok;
        fputc(' ', out);
        if (schema[i] == '[')
            ok = sd_list(&c, schema[++i], out);
        else
            ok = sd_one(&c, schema[i], out);
        if (!ok)
            return false;
    }
    fputc('\n', out);
    return c.off == n;
}

bool vcs_semantic_manifest_v1_dump(const uint8_t *bytes, size_t len, FILE *out)
{
    struct sm_span sec[VCS_SEMANTIC_SECTION_V1_COUNT] = {0};
    if (!vcs_semantic_manifest_v1_validate(bytes, len, NULL, 0) ||
        !sm_sections(bytes, len, sec))
        return false;
    for (int t = 1; t < VCS_SEMANTIC_SECTION_V1_COUNT; t++) {
        struct sm_cur c = {.p = sec[t].p, .len = sec[t].len};
        if (sec[t].p == NULL)
            continue;
        uint32_t count;
        if (!sm_u32(&c, &count))
            return false;
        for (uint32_t k = 0; k < count; k++) {
            uint32_t rl;
            const uint8_t *rp;
            if (!sm_u32(&c, &rl) || !sm_take(&c, rl, &rp) ||
                !sd_record(rp, rl, (enum vcs_semantic_section_v1)t, out))
                return false;
        }
    }
    return true;
}
