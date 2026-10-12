/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * HTML template engine: {{var}}, {{{raw}}}, {{> partial}}. */

#include "util/template.h"
#include <string.h>
#include <stdbool.h>

/* ── HTML escaping ─────────────────────────────────────────── */

size_t html_escape(char *dst, size_t max, const char *src)
{
    if (!dst || max == 0) return 0;
    if (!src) { dst[0] = '\0'; return 0; }
    size_t w = 0;
    for (size_t i = 0; src[i]; i++) {
        const char *esc = NULL;
        size_t elen = 0;
        switch (src[i]) {
        case '<':  esc = "&lt;";   elen = 4; break;
        case '>':  esc = "&gt;";   elen = 4; break;
        case '&':  esc = "&amp;";  elen = 5; break;
        case '"':  esc = "&quot;"; elen = 6; break;
        case '\'': esc = "&#39;";  elen = 5; break;
        default: break;
        }
        if (esc) {
            if (w + elen >= max) break;
            memcpy(dst + w, esc, elen);
            w += elen;
        } else {
            if (w + 1 >= max) break;
            dst[w++] = src[i];
        }
    }
    if (max > 0) dst[w] = '\0';
    return w;
}

/* ── Key validation ────────────────────────────────────────── */

#define TMPL_MAX_KEY_LEN 64

static bool tmpl_valid_key(const char *key, size_t len)
{
    if (len == 0 || len > TMPL_MAX_KEY_LEN) return false;
    for (size_t i = 0; i < len; i++) {
        char c = key[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '_'))
            return false;
    }
    return true;
}

/* Validate partial name: alphanumeric + hyphens, max 64 chars. */
static bool tmpl_valid_partial_name(const char *name, size_t len)
{
    if (len == 0 || len > TMPL_MAX_KEY_LEN) return false;
    for (size_t i = 0; i < len; i++) {
        char c = name[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '-'))
            return false;
    }
    return true;
}

/* ── Variable lookup ───────────────────────────────────────── */

static const char *tmpl_lookup(const struct template_var *vars, size_t n,
                               const char *key, size_t key_len)
{
    if (!tmpl_valid_key(key, key_len))
        return NULL;
    for (size_t i = 0; i < n; i++) {
        if (vars[i].key && strlen(vars[i].key) == key_len &&
            memcmp(vars[i].key, key, key_len) == 0)
            return vars[i].value ? vars[i].value : "";
    }
    return NULL;
}

/* ── Partial registry ──────────────────────────────────────── */

static const struct template_partial *g_partials = NULL;
static size_t g_num_partials = 0;

void template_register_partials(const struct template_partial *partials,
                                size_t count)
{
    g_partials = partials;
    g_num_partials = count;
}

static const char *tmpl_lookup_partial(const char *name, size_t name_len)
{
    if (!g_partials || !tmpl_valid_partial_name(name, name_len))
        return NULL;
    for (size_t i = 0; i < g_num_partials; i++) {
        if (g_partials[i].name &&
            strlen(g_partials[i].name) == name_len &&
            memcmp(g_partials[i].name, name, name_len) == 0)
            return g_partials[i].tmpl;
    }
    return NULL;
}

/* ── Render (with recursion depth limit) ───────────────────── */

#define TMPL_MAX_DEPTH 4

static size_t render_impl(const char *tmpl,
                          const struct template_var *vars, size_t num_vars,
                          char *out, size_t out_max, int depth);

/* Appends up to `len` bytes of `text`, leaving room for the terminator. */
static void render_copy(char *out, size_t out_max, size_t *w, const char *text,
                        size_t len)
{
    size_t avail = out_max - *w - 1;
    size_t copy = len < avail ? len : avail;
    memcpy(out + *w, text, copy);
    *w += copy;
}

/* Triple-brace {{{key}}} — raw output. Returns the tag end, or NULL when the
 * tag at `p` is not a complete triple-brace tag. */
static const char *render_raw_tag(const char *p, const struct template_var *vars,
                                  size_t num_vars, char *out, size_t out_max,
                                  size_t *w)
{
    const char *key_start = p + 3;
    const char *end = strstr(key_start, "}}}");
    if (!end)
        return NULL;
    const char *val = tmpl_lookup(vars, num_vars, key_start,
                                  (size_t)(end - key_start));
    if (val)
        render_copy(out, out_max, w, val, strlen(val));
    else
        render_copy(out, out_max, w, p, (size_t)(end + 3 - p));
    return end + 3;
}

/* Partial {{> name}} — inline include. A missing partial is skipped without
 * a placeholder. */
static const char *render_partial_tag(const char *p,
                                      const struct template_var *vars,
                                      size_t num_vars, char *out,
                                      size_t out_max, size_t *w, int depth)
{
    const char *name_start = p + 3;
    while (*name_start == ' ') name_start++;
    const char *end = strstr(name_start, "}}");
    if (!end)
        return NULL;
    const char *name_end = end;
    while (name_end > name_start && name_end[-1] == ' ')
        name_end--;
    const char *partial = tmpl_lookup_partial(
        name_start, (size_t)(name_end - name_start));
    if (partial)
        *w += render_impl(partial, vars, num_vars, out + *w, out_max - *w,
                          depth + 1);
    return end + 2;
}

/* Double-brace {{key}} — escaped output. */
static const char *render_escaped_tag(const char *p,
                                      const struct template_var *vars,
                                      size_t num_vars, char *out,
                                      size_t out_max, size_t *w)
{
    const char *key_start = p + 2;
    const char *end = strstr(key_start, "}}");
    if (!end)
        return NULL;
    const char *val = tmpl_lookup(vars, num_vars, key_start,
                                  (size_t)(end - key_start));
    if (val)
        *w += html_escape(out + *w, out_max - *w, val);
    else
        render_copy(out, out_max, w, p, (size_t)(end + 2 - p));
    return end + 2;
}

/* Renders the tag at `p` when it is a complete one; returns the position
 * after it, or NULL when `p` is plain text. */
static const char *render_tag(const char *p, const struct template_var *vars,
                              size_t num_vars, char *out, size_t out_max,
                              size_t *w, int depth)
{
    const char *next = NULL;
    if (p[0] != '{' || p[1] != '{')
        return NULL;
    if (p[2] == '{')
        next = render_raw_tag(p, vars, num_vars, out, out_max, w);
    if (!next && p[2] == '>')
        next = render_partial_tag(p, vars, num_vars, out, out_max, w, depth);
    if (!next)
        next = render_escaped_tag(p, vars, num_vars, out, out_max, w);
    return next;
}

static size_t render_impl(const char *tmpl,
                          const struct template_var *vars, size_t num_vars,
                          char *out, size_t out_max, int depth)
{
    if (!out || out_max == 0) return 0;
    if (!tmpl) { out[0] = '\0'; return 0; }
    if (!vars) num_vars = 0;
    if (depth > TMPL_MAX_DEPTH) { out[0] = '\0'; return 0; }

    size_t w = 0;
    const char *p = tmpl;

    while (*p && w + 1 < out_max) {
        const char *next = render_tag(p, vars, num_vars, out, out_max, &w,
                                      depth);
        if (next)
            p = next;
        else
            out[w++] = *p++;
    }

    out[w] = '\0';
    return w;
}

size_t template_render(const char *tmpl,
                       const struct template_var *vars, size_t num_vars,
                       char *out, size_t out_max)
{
    return render_impl(tmpl, vars, num_vars, out, out_max, 0);
}
