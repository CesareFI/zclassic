/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Closure-unchanged skipping for the early feedback stage: key each early group over its working-tree input closure, skip a group whose key and toolchain identity match its last recorded PASS, and keep those records in a local dev-only store written by temporary file and rename. */
#include "devloop_early_skip.h"

#include "test_group_host_need.h"

#include "base/hex.h"
#include "base/safe_alloc.h"
#include "json/json.h"
#include "platform/directory_compat.h"
#include "platform/file_sync.h"
#include "platform/path_replace.h"
#include "sha3/sha3.h"
#include "util/spawn.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define ES_PATH_MAX 1024
#define ES_FILE_MAX (16u * 1024u * 1024u)
#define ES_NODE_MAX 16384u
#define ES_DIRS_MAX 1024u
#define ES_ARGV_MAX 4096u
#define ES_NONE UINT32_MAX
#define ES_STORE_HEADER "zcl.dev_early_skip_store.v1"
#define ES_STORE_MAX_BYTES (1u << 20)
#define ES_STORE_MAX_RECS 4096u

/* ── a string -> index map (open addressing, owned keys) ──────────────── */

struct es_map {
    char **keys;
    uint32_t *vals;
    size_t cap; /* a power of two, or 0 */
    size_t n;
};

static uint64_t es_fnv(const char *s)
{
    uint64_t h = 1469598103934665603ull;
    while (*s)
        h = (h ^ (unsigned char)*s++) * 1099511628211ull;
    return h;
}

static size_t es_map_slot(char *const *keys, size_t cap, const char *key)
{
    size_t i = (size_t)es_fnv(key) & (cap - 1);
    while (keys[i] && strcmp(keys[i], key) != 0)
        i = (i + 1) & (cap - 1);
    return i;
}

static bool es_map_grow(struct es_map *m)
{
    size_t cap = m->cap ? m->cap * 2 : 256;
    char **keys = zcl_calloc(cap, sizeof(*keys), "early_skip.map");
    uint32_t *vals = zcl_calloc(cap, sizeof(*vals), "early_skip.map");
    if (!keys || !vals) {
        free(keys);
        free(vals);
        return false;
    }
    for (size_t i = 0; i < m->cap; i++) {
        if (!m->keys[i])
            continue;
        size_t at = es_map_slot(keys, cap, m->keys[i]);
        keys[at] = m->keys[i];
        vals[at] = m->vals[i];
    }
    free(m->keys);
    free(m->vals);
    m->keys = keys;
    m->vals = vals;
    m->cap = cap;
    return true;
}

static bool es_map_get(const struct es_map *m, const char *key, uint32_t *out)
{
    if (!m->cap)
        return false;
    size_t i = es_map_slot(m->keys, m->cap, key);
    if (!m->keys[i])
        return false;
    *out = m->vals[i];
    return true;
}

static bool es_map_put(struct es_map *m, const char *key, uint32_t val)
{
    if ((m->n + 1) * 2 > m->cap && !es_map_grow(m))
        return false;
    size_t i = es_map_slot(m->keys, m->cap, key);
    if (!m->keys[i]) {
        m->keys[i] = zcl_strdup(key, "early_skip.map");
        if (!m->keys[i])
            return false;
        m->n++;
    }
    m->vals[i] = val;
    return true;
}

static void es_map_free(struct es_map *m)
{
    for (size_t i = 0; i < m->cap; i++)
        free(m->keys[i]);
    free(m->keys);
    free(m->vals);
    memset(m, 0, sizeof(*m));
}

/* ── files ─────────────────────────────────────────────────────────────── */

static bool es_read(const char *path, size_t cap, char **out, size_t *len)
{
    *out = NULL;
    *len = 0;
    FILE *f = fopen(path, "rb");
    if (!f)
        return false;
    size_t size = 0, alloc = 0;
    char *buf = NULL;
    bool ok = true;
    for (;;) {
        if (size + 4096 + 1 > alloc) {
            size_t next = alloc ? alloc * 2 : 16384;
            char *grown = next <= cap + 4096 + 1
                ? zcl_realloc(buf, next, "early_skip.read") : NULL;
            if (!grown) {
                ok = false;
                break;
            }
            buf = grown;
            alloc = next;
        }
        size_t got = fread(buf + size, 1, 4096, f);
        size += got;
        if (got < 4096)
            break;
    }
    ok = ok && !ferror(f) && size <= cap;
    (void)fclose(f);
    if (!ok) {
        free(buf);
        return false;
    }
    buf[size] = '\0';
    *out = buf;
    *len = size;
    return true;
}

static void es_sha3_hex(const void *data, size_t len, char out[65])
{
    struct sha3_256_ctx ctx;
    unsigned char digest[32];
    sha3_256_init(&ctx);
    sha3_256_write(&ctx, (const unsigned char *)data, len);
    sha3_256_finalize(&ctx, digest);
    zcl_hex_encode(digest, sizeof(digest), out);
}

static void es_sha3_line(struct sha3_256_ctx *ctx, const char *label,
                         const char *value)
{
    sha3_256_write(ctx, (const unsigned char *)label, strlen(label));
    sha3_256_write(ctx, (const unsigned char *)":", 1);
    if (value)
        sha3_256_write(ctx, (const unsigned char *)value, strlen(value));
    sha3_256_write(ctx, (const unsigned char *)"\n", 1);
}

/* Drop the last segment of out[base, *o). False when there is none. */
static bool es_path_up(char out[ES_PATH_MAX], size_t base, size_t *o)
{
    if (*o <= base)
        return false;
    while (*o > base && out[*o - 1] != '/')
        (*o)--;
    if (*o > base)
        (*o)--;
    return true;
}

/* Append one `len`-byte segment. False when it does not fit. */
static bool es_path_push(char out[ES_PATH_MAX], size_t base, size_t *o,
                         const char *seg, size_t len)
{
    if (*o + len + 2 >= ES_PATH_MAX)
        return false;
    if (*o > base)
        out[(*o)++] = '/';
    memcpy(out + *o, seg, len);
    *o += len;
    return true;
}

/* `dir`/`name` with "." and ".." folded. False when it would climb above
 * its start, is empty, or does not fit. */
static bool es_path_fold(const char *in, char out[ES_PATH_MAX])
{
    size_t base = in[0] == '/' ? 1 : 0, o = base;
    out[0] = '/';
    for (const char *p = in; *p;) {
        p += strspn(p, "/");
        size_t len = strcspn(p, "/");
        bool dot = len == 1 && p[0] == '.';
        bool up = len == 2 && p[0] == '.' && p[1] == '.';
        bool ok = up ? es_path_up(out, base, &o)
                : len && !dot ? es_path_push(out, base, &o, p, len) : true;
        if (!ok)
            return false;
        p += len;
    }
    out[o] = '\0';
    return o > base;
}

static bool es_path_join(const char *dir, const char *name,
                         char out[ES_PATH_MAX])
{
    char joined[ES_PATH_MAX * 2];
    bool bare = name[0] == '/' || !dir || !dir[0];
    int n = bare ? snprintf(joined, sizeof(joined), "%s", name)
                 : snprintf(joined, sizeof(joined), "%s/%s", dir, name);
    return n > 0 && (size_t)n < sizeof(joined) && es_path_fold(joined, out);
}

/* Lexical folding across a symlink can name a different file than the
 * compiler opens. Refuse any parent segment until resolution is filesystem
 * faithful. */
static bool es_parent_segment(const char *path)
{
    for (const char *p = path; *p;) {
        p += strspn(p, "/");
        size_t len = strcspn(p, "/");
        if (len == 2 && p[0] == '.' && p[1] == '.')
            return true;
        p += len;
    }
    return false;
}

/* ── the include graph, shared by every group of one decision ─────────── */

struct es_node {
    char *path; /* root-relative, or absolute outside the checkout */
    char digest[65];
    uint32_t *deps;
    size_t ndeps, capdeps;
    const char *bad; /* literal; NULL while the node is vouched */
    char bad_detail[96];
    bool loaded;
    uint32_t stamp;
};

/* Why a loaded file's text leaves every group it reaches unvouched, with
 * what it saw in `detail`; NULL when nothing does. */
typedef const char *(*es_vet_fn)(void *arg, const char *text, char *detail,
                                 size_t cap);

struct es_graph {
    const char *root;
    char *flags;
    const char **dirs; /* [0, nquote) -iquote, then -I, in flag order */
    size_t ndirs, nquote;
    const char *unmodeled; /* the first flag es_resolve does not model */
    es_vet_fn vet;
    void *vet_arg;
    struct es_node *nodes;
    size_t n, cap;
    struct es_map paths;    /* path -> node */
    struct es_map searched; /* "q:name" or "a:name" -> node or ES_NONE */
};

static bool es_full(const struct es_graph *g, const char *path,
                    char out[ES_PATH_MAX * 2])
{
    int n = path[0] == '/'
        ? snprintf(out, ES_PATH_MAX * 2, "%s", path)
        : snprintf(out, ES_PATH_MAX * 2, "%s/%s", g->root, path);
    return n > 0 && n < ES_PATH_MAX * 2;
}

static bool es_regular(const struct es_graph *g, const char *path)
{
    char full[ES_PATH_MAX * 2];
    struct stat st;
    return es_full(g, path, full) && stat(full, &st) == 0 &&
           S_ISREG(st.st_mode);
}

/* One flag's directory: "-Xdir" or "-X dir". */
static const char *es_flag_dir(const char *const *argv, size_t argc,
                               size_t *i, const char *flag)
{
    size_t len = strlen(flag);
    if (strncmp(argv[*i], flag, len) != 0)
        return NULL;
    if (argv[*i][len])
        return argv[*i] + len;
    return *i + 1 < argc ? argv[++*i] : NULL;
}

static void es_graph_dirs_pass(struct es_graph *g, const char *const *argv,
                               size_t argc, const char *flag)
{
    for (size_t i = 0; i < argc && !g->unmodeled; i++) {
        const char *dir = es_flag_dir(argv, argc, &i, flag);
        if (!dir || !dir[0])
            continue;
        char probe[ES_PATH_MAX];
        if (es_parent_segment(dir) ||
            !es_path_join(dir, "early_skip_probe.h", probe)) {
            g->unmodeled = dir;
            return;
        }
        if (g->ndirs == ES_DIRS_MAX) {
            g->unmodeled = "(include dirs past their bound)";
            return;
        }
        g->dirs[g->ndirs++] = dir;
    }
}

/* A flag that moves include resolution or supplies a volatile macro which
 * this source-text key cannot model. */
static bool es_flag_unmodeled(const char *arg)
{
    if (strncmp(arg, "-Wp,", 4) == 0 ||
        strcmp(arg, "-Xpreprocessor") == 0)
        return true;
    if (strstr(arg, "_Pragma") ||
        strstr(arg, "__has_include") || strstr(arg, "__has_embed") ||
        strstr(arg, "__DATE__") || strstr(arg, "__TIME__") ||
        strstr(arg, "__TIMESTAMP__") || strstr(arg, "##") ||
        strstr(arg, "%:%:"))
        return true;
    if (strncmp(arg, "-iquote", 7) == 0)
        return false;
    return strncmp(arg, "-i", 2) == 0 || strcmp(arg, "-I-") == 0 ||
           strncmp(arg, "--sysroot", 9) == 0 || arg[0] == '@';
}

static bool es_graph_init(struct es_graph *g, const char *root,
                          const char *cflags)
{
    memset(g, 0, sizeof(*g));
    g->root = root;
    g->flags = zcl_strdup(cflags ? cflags : "", "early_skip.flags");
    const char **argv = zcl_calloc(ES_ARGV_MAX, sizeof(*argv),
                                   "early_skip.argv");
    g->dirs = zcl_calloc(ES_DIRS_MAX, sizeof(*g->dirs), "early_skip.dirs");
    if (!g->flags || !argv || !g->dirs) {
        free(argv);
        return false;
    }
    size_t argc = zcl_argv_split(g->flags, argv, ES_ARGV_MAX);
    /* A split that filled argv may have dropped flags it never saw. */
    if (argc >= ES_ARGV_MAX - 1)
        g->unmodeled = "(flags past their bound)";
    for (size_t i = 0; i < argc && !g->unmodeled; i++)
        if (es_flag_unmodeled(argv[i]))
            g->unmodeled = argv[i];
    es_graph_dirs_pass(g, argv, argc, "-iquote");
    g->nquote = g->ndirs;
    es_graph_dirs_pass(g, argv, argc, "-I");
    free(argv);
    return true;
}

static void es_graph_free(struct es_graph *g)
{
    for (size_t i = 0; i < g->n; i++) {
        free(g->nodes[i].path);
        free(g->nodes[i].deps);
    }
    free(g->nodes);
    free(g->dirs);
    free(g->flags);
    es_map_free(&g->paths);
    es_map_free(&g->searched);
    memset(g, 0, sizeof(*g));
}

static bool es_node_of(struct es_graph *g, const char *path, uint32_t *out)
{
    if (es_map_get(&g->paths, path, out))
        return true;
    if (g->n >= ES_NODE_MAX)
        return false;
    if (g->n == g->cap) {
        size_t cap = g->cap ? g->cap * 2 : 256;
        struct es_node *grown = zcl_realloc(g->nodes, cap * sizeof(*grown),
                                            "early_skip.nodes");
        if (!grown)
            return false;
        g->nodes = grown;
        g->cap = cap;
    }
    struct es_node *node = &g->nodes[g->n];
    memset(node, 0, sizeof(*node));
    node->path = zcl_strdup(path, "early_skip.node");
    if (!node->path || !es_map_put(&g->paths, path, (uint32_t)g->n)) {
        free(node->path);
        return false;
    }
    *out = (uint32_t)g->n++;
    return true;
}

static void es_node_bad(struct es_graph *g, uint32_t idx, const char *why,
                        const char *what)
{
    if (g->nodes[idx].bad)
        return;
    g->nodes[idx].bad = why;
    (void)snprintf(g->nodes[idx].bad_detail,
                   sizeof(g->nodes[idx].bad_detail), "%s", what ? what : "");
}

static bool es_node_dep(struct es_graph *g, uint32_t idx, uint32_t dep)
{
    struct es_node *node = &g->nodes[idx];
    if (node->ndeps == node->capdeps) {
        size_t cap = node->capdeps ? node->capdeps * 2 : 8;
        uint32_t *grown = zcl_realloc(node->deps, cap * sizeof(*grown),
                                      "early_skip.deps");
        if (!grown)
            return false;
        node->deps = grown;
        node->capdeps = cap;
    }
    node->deps[node->ndeps++] = dep;
    return true;
}

/* #include_next continues the search after the directory that found the
 * includer, which es_resolve does not track: it is never resolved. */
enum es_inc {
    ES_INC_NONE, ES_INC_QUOTE, ES_INC_ANGLE, ES_INC_COMPUTED, ES_INC_NEXT
};

static const char *es_skip_blank(const char *p, const char *end)
{
    while (p < end && (*p == ' ' || *p == '\t' || *p == '\v' ||
                       *p == '\f' || *p == '\r'))
        p++;
    return p;
}

/* C's %: digraph is the same directive marker as #. */
static const char *es_after_marker(const char *p, const char *end)
{
    if (p >= end)
        return NULL;
    if (*p == '#')
        return p + 1;
    if (end - p >= 2 && p[0] == '%' && p[1] == ':')
        return p + 2;
    return NULL;
}

/* Length of the include-like directive keyword at `p`, or 0. */
static size_t es_keyword(const char *p, const char *end)
{
    static const char *const words[] = { "include_next", "include",
                                         "import", "embed" };
    for (size_t i = 0; i < sizeof(words) / sizeof(words[0]); i++) {
        size_t len = strlen(words[i]);
        if ((size_t)(end - p) > len && strncmp(p, words[i], len) == 0 &&
            p[len] &&
            strchr(" \t\v\f\r\"<", p[len]))
            return len;
    }
    return 0;
}

/* The directive on one line: none, a quoted or angle name, or a computed
 * operand (a macro) that no text scan can resolve. */
static enum es_inc es_directive(const char *p, const char *end, char *name,
                                size_t cap)
{
    p = es_after_marker(es_skip_blank(p, end), end);
    if (!p)
        return ES_INC_NONE;
    p = es_skip_blank(p, end);
    size_t kw = es_keyword(p, end);
    if (!kw)
        return ES_INC_NONE;
    if (kw == strlen("include_next"))
        return ES_INC_NEXT;
    p = es_skip_blank(p + kw, end);
    char close = p < end && *p == '"' ? '"' : p < end && *p == '<' ? '>' : 0;
    const char *q = close ? memchr(p + 1, close, (size_t)(end - p - 1)) : NULL;
    if (!q || q == p + 1 || (size_t)(q - p - 1) >= cap)
        return ES_INC_COMPUTED;
    memcpy(name, p + 1, (size_t)(q - p - 1));
    name[q - p - 1] = '\0';
    return close == '"' ? ES_INC_QUOTE : ES_INC_ANGLE;
}

/* The -iquote/-I search for `name`, cached per spelling. */
static bool es_search(struct es_graph *g, enum es_inc kind, const char *name,
                      uint32_t *out)
{
    char cache_key[ES_PATH_MAX + 3];
    (void)snprintf(cache_key, sizeof(cache_key), "%c:%s",
                   kind == ES_INC_QUOTE ? 'q' : 'a', name);
    if (es_map_get(&g->searched, cache_key, out))
        return true;
    *out = ES_NONE;
    char path[ES_PATH_MAX];
    for (size_t i = kind == ES_INC_QUOTE ? 0 : g->nquote; i < g->ndirs; i++) {
        if (!es_path_join(g->dirs[i], name, path))
            return false;
        if (es_regular(g, path))
            return es_node_of(g, path, out) &&
                   es_map_put(&g->searched, cache_key, *out);
    }
    return es_map_put(&g->searched, cache_key, ES_NONE);
}

/* Resolve one include of node `idx` as the compiler would. *out is ES_NONE
 * when nothing matched. False only when a bound or memory ran out. */
static bool es_resolve(struct es_graph *g, uint32_t idx, enum es_inc kind,
                       const char *name, uint32_t *out)
{
    *out = ES_NONE;
    if (kind == ES_INC_QUOTE) {
        char dir[ES_PATH_MAX], path[ES_PATH_MAX];
        (void)snprintf(dir, sizeof(dir), "%s", g->nodes[idx].path);
        char *slash = strrchr(dir, '/');
        if (slash)
            *slash = '\0';
        else
            dir[0] = '\0';
        if (!es_path_join(dir, name, path))
            return false;
        if (es_regular(g, path))
            return es_node_of(g, path, out);
    }
    return es_search(g, kind, name, out);
}

/* One directive of node `idx`: join its resolved file, or mark the node
 * unvouched. False only when a bound or memory ran out. */
static bool es_scan_directive(struct es_graph *g, uint32_t idx,
                              enum es_inc kind, const char *name)
{
    uint32_t dep = ES_NONE;
    if (kind == ES_INC_COMPUTED || kind == ES_INC_NEXT) {
        es_node_bad(g, idx, kind == ES_INC_NEXT ? "include-next"
                                                : "include-computed",
                    g->nodes[idx].path);
        return true;
    }
    if (es_parent_segment(name)) {
        es_node_bad(g, idx, "include-parent", name);
        return true;
    }
    if (!es_resolve(g, idx, kind, name, &dep))
        return false;
    if (dep != ES_NONE)
        return es_node_dep(g, idx, dep);
    if (kind == ES_INC_QUOTE)
        es_node_bad(g, idx, "include-unresolved", name);
    return true;
}

/* Join every include of node `idx`, then blank its directive lines: their
 * operand is keyed through the file it resolves to (or the node is already
 * unvouched), so it names no input the text vet must still see. */
static bool es_scan(struct es_graph *g, uint32_t idx, char *text, size_t len)
{
    char *end = text + len;
    char name[ES_PATH_MAX];
    for (char *p = text; p < end;) {
        char *nl = memchr(p, '\n', (size_t)(end - p));
        char *line_end = nl ? nl : end;
        enum es_inc kind = es_directive(p, line_end, name, sizeof(name));
        if (kind != ES_INC_NONE && !es_scan_directive(g, idx, kind, name))
            return false;
        if (kind != ES_INC_NONE)
            memset(p, ' ', (size_t)(line_end - p));
        p = nl ? nl + 1 : end;
    }
    return true;
}

static bool es_ident_char(char ch)
{
    return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
           (ch >= '0' && ch <= '9') || ch == '_';
}

/* A ' inside a number (1'000'000, C23) separates digits and opens no
 * literal; a token that starts with a letter (u8'x', L'x') is a prefix. */
static bool es_digit_separator(const char *text, size_t i)
{
    size_t j = i;
    while (j > 0 && es_ident_char(text[j - 1]))
        j--;
    return j < i && text[j] >= '0' && text[j] <= '9';
}

/* The index of the quote closing the literal opened at `i`, or of the line
 * end, which no literal crosses. */
static size_t es_literal_end(const char *text, size_t len, size_t i)
{
    size_t j = i + 1;
    while (j < len && text[j] != text[i] && text[j] != '\n')
        j += text[j] == '\\' && j + 1 < len ? 2 : 1;
    return j < len ? j : len - 1;
}

enum es_marker_bits {
    ES_MARK_INCLUDE = 1u, ES_MARK_EMBED = 2u,
    ES_MARK_VOLATILE = 4u, ES_MARK_PASTE = 8u,
    ES_MARK_PRAGMA = 16u,
};

static bool es_marker_at(const char *text, size_t len, size_t i,
                         const char *marker)
{
    size_t n = strlen(marker);
    return n <= len - i && memcmp(text + i, marker, n) == 0;
}

static unsigned es_marker_bits_at(const char *text, size_t len, size_t i)
{
    unsigned bits = 0;
    if (text[i] == '_') {
        if (es_marker_at(text, len, i, "__has_include"))
            bits |= ES_MARK_INCLUDE;
        if (es_marker_at(text, len, i, "__has_embed"))
            bits |= ES_MARK_EMBED;
        if (es_marker_at(text, len, i, "__DATE__") ||
            es_marker_at(text, len, i, "__TIME__") ||
            es_marker_at(text, len, i, "__TIMESTAMP__"))
            bits |= ES_MARK_VOLATILE;
        if (es_marker_at(text, len, i, "_Pragma"))
            bits |= ES_MARK_PRAGMA;
    }
    if (es_marker_at(text, len, i, "##") ||
        es_marker_at(text, len, i, "%:%:"))
        bits |= ES_MARK_PASTE;
    return bits;
}

/* These compiler operators are tokens; bytes in an ordinary literal cannot
 * expand to them. Keep the original text intact for include resolution and
 * the test-input vet. A malformed literal is never a vouched closure. */
static unsigned es_live_markers(const char *text, size_t len, bool *uncertain)
{
    unsigned bits = 0;
    *uncertain = false;
    for (size_t i = 0; i < len; i++) {
        if (text[i] == '"' ||
            (text[i] == '\'' && !es_digit_separator(text, i))) {
            size_t end = es_literal_end(text, len, i);
            if (end <= i || text[end] != text[i]) {
                *uncertain = true;
                return bits;
            }
            i = end;
        } else {
            bits |= es_marker_bits_at(text, len, i);
        }
    }
    return bits;
}

/* Blank a // comment from `i` up to its line end; a backslash-newline that
 * would continue it only leaves more text to scan. */
static size_t es_blank_line_comment(char *text, size_t len, size_t i)
{
    size_t j = i;
    while (j < len && text[j] != '\n')
        text[j++] = ' ';
    return j - 1;
}

static size_t es_blank_block_comment(char *text, size_t len, size_t i)
{
    size_t j = i + 2;
    text[i] = text[i + 1] = ' ';
    while (j + 1 < len && !(text[j] == '*' && text[j + 1] == '/')) {
        if (text[j] != '\n')
            text[j] = ' ';
        j++;
    }
    if (j + 1 >= len)
        return len - 1;
    text[j] = text[j + 1] = ' ';
    return j + 1;
}

/* Blank every comment in place (newlines kept), string and character
 * literals intact: a comment calls nothing and names no input. The file's
 * digest is taken before. */
static void es_strip_comments(char *text, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        char ch = text[i];
        char next = i + 1 < len ? text[i + 1] : '\0';
        if (ch == '"' || (ch == '\'' && !es_digit_separator(text, i)))
            i = es_literal_end(text, len, i);
        else if (ch == '/' && next == '/')
            i = es_blank_line_comment(text, len, i);
        else if (ch == '/' && next == '*')
            i = es_blank_block_comment(text, len, i);
    }
}

/* C joins backslash-newline pairs before recognizing directives and comments.
 * Work on the copy: the node digest above still identifies the exact bytes. */
static size_t es_splice_lines(char *text, size_t len)
{
    size_t out = 0;
    for (size_t i = 0; i < len; i++) {
        if (text[i] == '\\' && i + 1 < len) {
            if (text[i + 1] == '\n') {
                i++;
                continue;
            }
            if (text[i + 1] == '\r' && i + 2 < len &&
                text[i + 2] == '\n') {
                i += 2;
                continue;
            }
        }
        text[out++] = text[i];
    }
    text[out] = '\0';
    return out;
}

/* Trigraph conversion precedes comment removal and line splicing on
 * toolchains that enable it. Even a candidate in a comment can change the
 * directive stream, so inspect the original bytes before either pass. */
static bool es_trigraph_candidate(const char *text, size_t len)
{
    for (size_t i = 0; i + 1 < len; i++)
        if (text[i] == '?' && text[i + 1] == '?')
            return true;
    return false;
}

/* A bare CR can end a preprocessing directive on supported compilers.
 * The line scanner splits on LF, so refuse this spelling until it models
 * that extra line boundary. CRLF remains covered by the ordinary scan. */
static bool es_lone_cr(const char *text, size_t len)
{
    for (size_t i = 0; i < len; i++)
        if (text[i] == '\r' && (i + 1 == len || text[i + 1] != '\n'))
            return true;
    return false;
}

/* A compiler can discard a UTF-8 BOM before recognizing a directive.
 * A byte-oriented directive scan would otherwise miss its first include. */
static bool es_utf8_bom(const char *text, size_t len)
{
    for (size_t i = 0; i + 2 < len; i++)
        if ((unsigned char)text[i] == 0xef &&
            (unsigned char)text[i + 1] == 0xbb &&
            (unsigned char)text[i + 2] == 0xbf)
            return true;
    return false;
}

static void es_node_load(struct es_graph *g, uint32_t idx)
{
    char full[ES_PATH_MAX * 2];
    char *text = NULL;
    size_t len = 0;
    g->nodes[idx].loaded = true;
    if (!es_full(g, g->nodes[idx].path, full) ||
        !es_read(full, ES_FILE_MAX, &text, &len)) {
        es_node_bad(g, idx, "unreadable", g->nodes[idx].path);
        return;
    }
    es_sha3_hex(text, len, g->nodes[idx].digest);
    if (es_trigraph_candidate(text, len))
        es_node_bad(g, idx, "trigraph", g->nodes[idx].path);
    if (es_lone_cr(text, len))
        es_node_bad(g, idx, "lone-cr", g->nodes[idx].path);
    if (es_utf8_bom(text, len))
        es_node_bad(g, idx, "utf8-bom", g->nodes[idx].path);
    len = es_splice_lines(text, len);
    es_strip_comments(text, len);
    bool uncertain = false;
    unsigned markers = es_live_markers(text, len, &uncertain);
    if (uncertain)
        es_node_bad(g, idx, "literal-unclosed", g->nodes[idx].path);
    /* A file's appearance can flip these predicates without any include or
     * embed edge. The closure key cannot vouch for those search results. */
    if (markers & ES_MARK_INCLUDE)
        es_node_bad(g, idx, "has-include", g->nodes[idx].path);
    if (markers & ES_MARK_EMBED)
        es_node_bad(g, idx, "has-embed", g->nodes[idx].path);
    /* Wall-clock expansion and file mtime can change while source bytes do
     * not. A prior early PASS therefore cannot cover these inputs. */
    if (markers & ES_MARK_VOLATILE)
        es_node_bad(g, idx, "volatile-macro", g->nodes[idx].path);
    /* Token pasting can synthesize those spellings (and include probes)
     * without any full token appearing in the bytes scanned above. */
    if (markers & ES_MARK_PASTE)
        es_node_bad(g, idx, "macro-paste", g->nodes[idx].path);
    /* Pragmas can depend on external file metadata and destringize text. */
    if (markers & ES_MARK_PRAGMA)
        es_node_bad(g, idx, "pragma", g->nodes[idx].path);
    if (!es_scan(g, idx, text, len))
        es_node_bad(g, idx, "closure-bound", g->nodes[idx].path);
    char seen[64] = "";
    const char *why = g->vet ? g->vet(g->vet_arg, text, seen, sizeof(seen))
                             : NULL;
    if (why) {
        char what[sizeof(g->nodes[idx].bad_detail)];
        (void)snprintf(what, sizeof(what), "%s in %s", seen,
                       g->nodes[idx].path);
        es_node_bad(g, idx, why, what);
    }
    free(text);
}

/* ── one group's closure ───────────────────────────────────────────────── */

struct es_walk {
    uint32_t *list; /* visit order; doubles as the queue */
    size_t n, cap;
    uint32_t stamp;
    const char *bad;
    char detail[128];
};

static bool es_walk_visit(struct es_graph *g, struct es_walk *w,
                          uint32_t idx)
{
    if (g->nodes[idx].stamp == w->stamp)
        return true;
    if (w->n == w->cap) {
        size_t cap = w->cap ? w->cap * 2 : 64;
        uint32_t *grown = zcl_realloc(w->list, cap * sizeof(*grown),
                                      "early_skip.walk");
        if (!grown)
            return false;
        w->list = grown;
        w->cap = cap;
    }
    g->nodes[idx].stamp = w->stamp;
    w->list[w->n++] = idx;
    return true;
}

static bool es_walk_root(struct es_graph *g, struct es_walk *w,
                         const char *path)
{
    char folded[ES_PATH_MAX];
    uint32_t idx = ES_NONE;
    return es_path_fold(path, folded) && es_node_of(g, folded, &idx) &&
           es_walk_visit(g, w, idx);
}

static void es_walk_run(struct es_graph *g, struct es_walk *w)
{
    for (size_t i = 0; i < w->n && !w->bad; i++) {
        uint32_t idx = w->list[i];
        if (!g->nodes[idx].loaded)
            es_node_load(g, idx);
        if (g->nodes[idx].bad) {
            w->bad = g->nodes[idx].bad;
            (void)snprintf(w->detail, sizeof(w->detail), "%s",
                           g->nodes[idx].bad_detail);
            return;
        }
        for (size_t d = 0; d < g->nodes[idx].ndeps; d++) {
            if (!es_walk_visit(g, w, g->nodes[idx].deps[d])) {
                w->bad = "closure-bound";
                return;
            }
        }
    }
}

struct es_line {
    const char *path;
    const char *digest;
};

static int es_line_cmp(const void *a, const void *b)
{
    return strcmp(((const struct es_line *)a)->path,
                  ((const struct es_line *)b)->path);
}

static bool es_walk_key(const struct es_graph *g, const struct es_walk *w,
                        const char *identity, const char *group,
                        char out[65])
{
    struct es_line *lines = zcl_calloc(w->n ? w->n : 1, sizeof(*lines),
                                       "early_skip.lines");
    if (!lines)
        return false;
    for (size_t i = 0; i < w->n; i++) {
        lines[i].path = g->nodes[w->list[i]].path;
        lines[i].digest = g->nodes[w->list[i]].digest;
    }
    qsort(lines, w->n, sizeof(*lines), es_line_cmp);
    struct sha3_256_ctx ctx;
    unsigned char digest[32];
    sha3_256_init(&ctx);
    sha3_256_write(&ctx, (const unsigned char *)"zcl.dev_early_skip.key.v1\n",
                   strlen("zcl.dev_early_skip.key.v1\n"));
    es_sha3_line(&ctx, "identity", identity);
    es_sha3_line(&ctx, "group", group);
    for (size_t i = 0; i < w->n; i++)
        es_sha3_line(&ctx, lines[i].path, lines[i].digest);
    sha3_256_finalize(&ctx, digest);
    zcl_hex_encode(digest, sizeof(digest), out);
    free(lines);
    return true;
}

/* ── the record store ─────────────────────────────────────────────────── */

struct es_rec {
    char group[ZCL_TEST_GROUP_FULL_MAX];
    char key[65];
    char identity[65];
    char candidate[65];
    long long run_us;
};

struct es_store {
    struct es_rec *recs;
    size_t n;
    const char *state;
};

static bool es_hex64(const char *s)
{
    return strlen(s) == 64 && strspn(s, "0123456789abcdef") == 64;
}

static bool es_store_line(const char *line, struct es_rec *rec)
{
    char extra;
    int got = sscanf(line, "%95[^\t]\t%64[^\t]\t%64[^\t]\t%64[^\t]\t%lld%c",
                     rec->group, rec->key, rec->identity, rec->candidate,
                     &rec->run_us, &extra);
    return got == 5 && es_hex64(rec->key) && es_hex64(rec->identity) &&
           (es_hex64(rec->candidate) || strcmp(rec->candidate, "-") == 0) &&
           rec->run_us >= 0;
}

static bool es_store_parse(char *text, struct es_store *st)
{
    char *save = NULL;
    char *line = strtok_r(text, "\n", &save);
    if (!line || strcmp(line, ES_STORE_HEADER) != 0)
        return false;
    while ((line = strtok_r(NULL, "\n", &save)) != NULL) {
        if (st->n >= ES_STORE_MAX_RECS || strlen(line) >= 512 ||
            !es_store_line(line, &st->recs[st->n]))
            return false;
        st->n++;
    }
    return true;
}

static bool es_store_path(const char *root, char out[ES_PATH_MAX * 2])
{
    int n = snprintf(out, ES_PATH_MAX * 2, "%s/%s", root,
                     ZCL_DEVLOOP_EARLY_SKIP_STORE);
    return n > 0 && n < ES_PATH_MAX * 2;
}

static bool es_store_load(const char *root, struct es_store *st)
{
    char path[ES_PATH_MAX * 2];
    char *text = NULL;
    size_t len = 0;
    memset(st, 0, sizeof(*st));
    st->state = "absent";
    st->recs = zcl_calloc(ES_STORE_MAX_RECS, sizeof(*st->recs),
                          "early_skip.store");
    if (!st->recs)
        return false;
    if (!es_store_path(root, path) ||
        !es_read(path, ES_STORE_MAX_BYTES, &text, &len))
        return true;
    st->state = "loaded";
    if (!es_store_parse(text, st)) {
        st->state = "malformed";
        st->n = 0;
    }
    free(text);
    return true;
}

static struct es_rec *es_store_find(struct es_store *st, const char *group)
{
    for (size_t i = 0; i < st->n; i++)
        if (strcmp(st->recs[i].group, group) == 0)
            return &st->recs[i];
    return NULL;
}

static bool es_store_write(FILE *f, const struct es_store *st)
{
    bool ok = fprintf(f, "%s\n", ES_STORE_HEADER) > 0;
    for (size_t i = 0; ok && i < st->n; i++) {
        const struct es_rec *r = &st->recs[i];
        ok = fprintf(f, "%s\t%s\t%s\t%s\t%lld\n", r->group, r->key,
                     r->identity, r->candidate, r->run_us) > 0;
    }
    return ok && fflush(f) == 0 && platform_file_sync(fileno(f)) == 0;
}

static bool es_store_dir(const char *root)
{
    char dir[ES_PATH_MAX * 2];
    int n = snprintf(dir, sizeof(dir), "%s/build", root);
    if (n <= 0 || (size_t)n >= sizeof(dir) ||
        !platform_directory_ensure(dir, 0755))
        return false;
    n = snprintf(dir, sizeof(dir), "%s/build/dev-loop", root);
    return n > 0 && (size_t)n < sizeof(dir) &&
           platform_directory_ensure(dir, 0755);
}

/* The whole store replaced at once: a temporary file beside it, then a
 * rename, so a reader sees the old image or the new one. */
static bool es_store_save(const char *root, const struct es_store *st)
{
    char path[ES_PATH_MAX * 2], temp[ES_PATH_MAX * 2 + 32];
    if (!es_store_dir(root) || !es_store_path(root, path))
        return false;
    int n = snprintf(temp, sizeof(temp), "%s.%ld.tmp", path, (long)getpid());
    if (n <= 0 || (size_t)n >= sizeof(temp))
        return false;
    FILE *f = fopen(temp, "wb");
    if (!f)
        return false;
    bool ok = es_store_write(f, st);
    ok = fclose(f) == 0 && ok;
    ok = ok && platform_path_replace(temp, path) == 0;
    if (!ok)
        (void)unlink(temp);
    return ok;
}

/* ── vouching ─────────────────────────────────────────────────────────── */

struct es_tops {
    struct platform_directory_list dirs;
    struct platform_directory_list files;
    bool listed;
};

struct es_ctx {
    const char *root;
    const struct zcl_devloop_early_toolchain *tc;
    struct zcl_devloop_early_skip *s;
    struct es_graph g;
    struct es_tops tops;
    struct es_store store;
    struct es_walk walk;
    const char *blocked_detail; /* what blocked every row, when any */
};

static bool es_test_file(const char *group, char *out, size_t cap)
{
    const char *dir = strncmp(group, "test_", 5) == 0 ? "tests/harness/src"
                    : strncmp(group, "spec_", 5) == 0 ? "tests/harness/spec"
                    : NULL;
    if (!dir)
        return false;
    int n = snprintf(out, cap, "%s/%s.c", dir, group);
    return n > 0 && (size_t)n < cap;
}

static const char *es_host_need(const char *group, char *detail, size_t cap)
{
    struct zcl_test_group_host_need need = {0};
    if (!zcl_test_group_host_need(group, &need))
        return "group-unregistered";
    if (need.kind == ZCL_HOST_NEED_NONE)
        return NULL;
    const char *kind = zcl_test_group_host_need_kind_name(need.kind);
    (void)snprintf(detail, cap, "%s %s", kind ? kind : "unknown",
                   need.value ? need.value : "");
    return "host-need";
}

static const char *es_marker(const char *text, const char *const *markers)
{
    for (size_t i = 0; markers[i]; i++)
        if (strstr(text, markers[i]))
            return markers[i];
    return NULL;
}

/* A string literal naming a top-level entry of the checkout: `name` then
 * '/' or the closing quote. test-tmp is a test's own scratch. */
static const char *es_top_literal(const char *text,
                                  const struct platform_directory_list *l)
{
    for (const char *q = strchr(text, '"'); q; q = strchr(q + 1, '"')) {
        for (size_t i = 0; i < l->count; i++) {
            const char *name = l->entries[i].name;
            size_t len = strlen(name);
            if (strcmp(name, "test-tmp") != 0 &&
                strncmp(q + 1, name, len) == 0 &&
                (q[1 + len] == '/' || q[1 + len] == '"'))
                return name;
        }
    }
    return NULL;
}

/* A function that opens a file by the path its first argument names: the
 * C and POSIX openers, and every platform_ helper with "open" in its
 * name. */
static bool es_opener(const char *name, size_t len)
{
    static const char *const exact[] = {
        "fopen", "fopen64", "freopen", "open", "open64", "openat",
        "openat64", "openat2", "creat", "creat64", "dlopen", NULL,
    };
    for (size_t i = 0; exact[i]; i++)
        if (strlen(exact[i]) == len && strncmp(name, exact[i], len) == 0)
            return true;
    if (len <= 9 || strncmp(name, "platform_", 9) != 0)
        return false;
    for (size_t i = 9; i + 4 <= len; i++)
        if (strncmp(name + i, "open", 4) == 0)
            return true;
    return false;
}

/* A first argument that starts with a type keyword: a prototype, which no
 * call can spell. */
static bool es_type_word(const char *p)
{
    static const char *const words[] = {
        "const", "volatile", "restrict", "char", "int", "unsigned",
        "signed", "short", "long", "void", "struct", "union", "enum",
        "bool", "_Bool", "float", "double", NULL,
    };
    for (size_t i = 0; words[i]; i++) {
        size_t len = strlen(words[i]);
        if (strncmp(p, words[i], len) == 0 && !es_ident_char(p[len]))
            return true;
    }
    return false;
}

static const char *es_skip_space(const char *p)
{
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')
        p++;
    return p;
}

/* The opener named by the identifier holding `at`, when it is called with
 * a first argument that is not a string literal; its length, or 0. */
static size_t es_open_call_at(const char *text, const char *at,
                              const char **name)
{
    const char *start = at, *end = at;
    while (start > text && es_ident_char(start[-1]))
        start--;
    while (es_ident_char(*end))
        end++;
    if (!es_opener(start, (size_t)(end - start)))
        return 0;
    const char *arg = es_skip_space(end);
    if (*arg != '(')
        return 0;
    arg = es_skip_space(arg + 1);
    if (*arg == '"' || es_type_word(arg))
        return 0;
    *name = start;
    return (size_t)(end - start);
}

/* A file opened by a computed path: an input no key names. A literal path
 * is left to es_top_literal. */
static const char *es_open_call(const char *text, char *detail, size_t cap)
{
    for (const char *p = strstr(text, "open"); p; p = strstr(p + 4, "open")) {
        const char *name = NULL;
        size_t len = es_open_call_at(text, p, &name);
        if (len) {
            (void)snprintf(detail, cap, "%.*s(", (int)len, name);
            return "opens-file";
        }
    }
    return NULL;
}

/* Runtime inputs a closure file can reach that no key names: the
 * environment, another process, a file opened by a computed path, and
 * checkout data it names by path. */
static const char *es_text_unvouched(struct es_ctx *c, const char *text,
                                     char *detail, size_t cap)
{
    static const char *const env[] = { "getenv(", "environment_get", NULL };
    static const char *const proc[] = { "execv", "execl", "posix_spawn",
                                        "zcl_spawn", "popen(", "system(",
                                        "process_run", NULL };
    const char *hit = es_marker(text, env);
    const char *why = hit ? "reads-environment" : NULL;
    if (!why && (hit = es_marker(text, proc)) != NULL)
        why = "starts-process";
    if (!why && (hit = es_top_literal(text, &c->tops.dirs)) != NULL)
        why = "names-checkout-path";
    if (!why && (hit = es_top_literal(text, &c->tops.files)) != NULL)
        why = "names-checkout-path";
    if (why) {
        (void)snprintf(detail, cap, "%s", hit);
        return why;
    }
    return es_open_call(text, detail, cap);
}

/* The graph's vet: every file of every closure is read through it, the
 * test file, the restart sources and every header they reach alike. */
static const char *es_vet(void *arg, const char *text, char *detail,
                          size_t cap)
{
    return es_text_unvouched(arg, text, detail, cap);
}

static void es_row_unvouched(struct zcl_devloop_early_skip_row *row,
                             const char *why, const char *what)
{
    row->vouched = false;
    row->key[0] = '\0';
    row->reason = "unvouched";
    (void)snprintf(row->detail, sizeof(row->detail), "%s%s%s", why,
                   what && what[0] ? ": " : "", what ? what : "");
}

/* Walk the test file and every restart source linked into the candidate;
 * key the closure. */
static bool es_row_key(struct es_ctx *c, struct zcl_devloop_early_skip_row *row,
                       const char *test_file)
{
    struct es_walk *w = &c->walk;
    w->n = 0;
    w->stamp++;
    w->bad = NULL;
    w->detail[0] = '\0';
    bool ok = es_walk_root(&c->g, w, test_file);
    for (size_t j = 0; ok && j < c->tc->source_count; j++)
        ok = es_walk_root(&c->g, w, c->tc->sources[j]);
    if (!ok)
        w->bad = "closure-bound";
    if (!w->bad)
        es_walk_run(&c->g, w);
    if (!w->bad && !es_walk_key(&c->g, w, c->s->identity, row->group,
                                row->key))
        w->bad = "closure-bound";
    if (w->bad) {
        es_row_unvouched(row, w->bad, w->detail);
        return false;
    }
    row->vouched = true;
    return true;
}

static bool es_row_vouch(struct es_ctx *c,
                         struct zcl_devloop_early_skip_row *row)
{
    char test_file[256], detail[128] = "";
    if (!es_test_file(row->group, test_file, sizeof(test_file))) {
        es_row_unvouched(row, "no-test-file", row->group);
        return false;
    }
    const char *why = es_host_need(row->group, detail, sizeof(detail));
    if (!why && !es_regular(&c->g, test_file)) {
        why = "no-test-file";
        (void)snprintf(detail, sizeof(detail), "%s", test_file);
    }
    if (!why && c->tc->source_count == 0)
        why = "no-restart-source";
    if (why) {
        es_row_unvouched(row, why, detail);
        return false;
    }
    return es_row_key(c, row, test_file);
}

static void es_row_compare(struct es_ctx *c,
                           struct zcl_devloop_early_skip_row *row)
{
    const struct es_rec *rec = es_store_find(&c->store, row->group);
    if (!rec)
        row->reason = "no-record";
    else if (strcmp(rec->identity, c->s->identity) != 0)
        row->reason = "identity-changed";
    else if (strcmp(rec->key, row->key) != 0)
        row->reason = "key-changed";
    else {
        row->last_run_us = rec->run_us;
        row->skip = c->s->mode != ZCL_DEVLOOP_EARLY_SKIP_OFF;
        row->reason = row->skip ? "closure-unchanged" : "skip-off";
    }
}

/* ── the decision ─────────────────────────────────────────────────────── */

enum zcl_devloop_early_skip_mode zcl_devloop_early_skip_mode_env(void)
{
    const char *v = getenv(ZCL_DEVLOOP_EARLY_SKIP_ENV);
    if (!v || !v[0] || strcmp(v, "on") == 0 || strcmp(v, "1") == 0)
        return ZCL_DEVLOOP_EARLY_SKIP_ON;
    if (strcmp(v, "verify") == 0)
        return ZCL_DEVLOOP_EARLY_SKIP_VERIFY;
    return ZCL_DEVLOOP_EARLY_SKIP_OFF;
}

const char *zcl_devloop_early_skip_mode_name(
    enum zcl_devloop_early_skip_mode mode)
{
    return mode == ZCL_DEVLOOP_EARLY_SKIP_ON ? "on"
         : mode == ZCL_DEVLOOP_EARLY_SKIP_VERIFY ? "verify" : "off";
}

static bool es_identity(const struct zcl_devloop_early_toolchain *tc,
                        char out[65])
{
    out[0] = '\0';
    if (!tc || !tc->compiler_id || !tc->compiler_id[0] ||
        !tc->base_generation || !tc->base_generation[0])
        return false;
    struct sha3_256_ctx ctx;
    unsigned char digest[32];
    sha3_256_init(&ctx);
    es_sha3_line(&ctx, "harness", ZCL_DEVLOOP_EARLY_SKIP_HARNESS);
    es_sha3_line(&ctx, "compiler", tc->compiler_id);
    es_sha3_line(&ctx, "base", tc->base_generation);
    es_sha3_line(&ctx, "cflags", tc->cflags);
    es_sha3_line(&ctx, "ldflags", tc->ldflags);
    es_sha3_line(&ctx, "libs", tc->libs);
    sha3_256_finalize(&ctx, digest);
    zcl_hex_encode(digest, sizeof(digest), out);
    return true;
}

/* Why no row can be vouched at all, or NULL. */
static const char *es_ctx_open(struct es_ctx *c, const char *root,
                               const struct zcl_devloop_early_toolchain *tc)
{
    c->root = root;
    c->tc = tc;
    if (!root || !es_identity(tc, c->s->identity))
        return "identity-unknown";
    if (tc->source_count > ZCL_DEVLOOP_EARLY_SKIP_SOURCE_MAX ||
        (tc->source_count && !tc->sources))
        return "source-set-exceeds-bound";
    /* A cached restart.env can retain its compiler ID while a long-lived
     * watcher's external include root changes. This closure only resolves
     * explicit -I/-iquote paths, so it cannot vouch for ambient roots. */
    const char *ambient = getenv("CPATH") ? "CPATH"
                        : getenv("C_INCLUDE_PATH") ? "C_INCLUDE_PATH" : NULL;
    if (ambient) {
        c->blocked_detail = ambient;
        return "ambient-include-path";
    }
    if (!es_graph_init(&c->g, root, tc->cflags) ||
        !es_store_load(root, &c->store))
        return "out-of-memory";
    c->g.vet = es_vet;
    c->g.vet_arg = c;
    if (c->g.unmodeled) {
        c->blocked_detail = c->g.unmodeled;
        return "cflags-unmodeled";
    }
    c->tops.listed = platform_directory_list_children_sorted(
        root, &c->tops.dirs, &c->tops.files);
    return c->tops.listed ? NULL : "checkout-unlisted";
}

static void es_ctx_close(struct es_ctx *c)
{
    if (c->tops.listed) {
        platform_directory_list_free(&c->tops.dirs);
        platform_directory_list_free(&c->tops.files);
    }
    es_graph_free(&c->g);
    free(c->store.recs);
    free(c->walk.list);
}

static void es_count(struct zcl_devloop_early_skip *s)
{
    for (size_t i = 0; i < s->n; i++) {
        const struct zcl_devloop_early_skip_row *row = &s->rows[i];
        s->groups_run += !row->skip;
        s->groups_skipped += row->skip;
        s->groups_unvouched += strcmp(row->reason, "unvouched") == 0;
        s->groups_skip_disabled += strcmp(row->reason, "skip-off") == 0;
        s->saved_us += row->skip ? row->last_run_us : 0;
    }
}

static void es_decide_rows(struct es_ctx *c, const char *blocked)
{
    struct zcl_devloop_early_skip *s = c->s;
    for (size_t i = 0; i < s->n; i++) {
        struct zcl_devloop_early_skip_row *row = &s->rows[i];
        row->key[0] = '\0';
        row->detail[0] = '\0';
        row->skip = false;
        row->vouched = false;
        row->last_run_us = 0;
        if (strcmp(blocked, "identity-unknown") == 0)
            row->reason = blocked;
        else if (blocked[0])
            es_row_unvouched(row, blocked, c->blocked_detail);
        else if (es_row_vouch(c, row))
            es_row_compare(c, row);
    }
}

/* Every output of a decision cleared; rows keep their group and sources. */
static void es_reset(struct zcl_devloop_early_skip *s)
{
    if (s->n > ZCL_DEVLOOP_EARLY_SKIP_GROUP_MAX)
        s->n = ZCL_DEVLOOP_EARLY_SKIP_GROUP_MAX;
    s->mode = zcl_devloop_early_skip_mode_env();
    s->mode_name = zcl_devloop_early_skip_mode_name(s->mode);
    s->store_state = "absent";
    s->identity[0] = '\0';
    s->groups_selected = (uint32_t)s->n;
    s->groups_run = s->groups_skipped = s->groups_unvouched = 0;
    s->groups_skip_disabled = 0;
    s->saved_us = 0;
    s->record_state = "none";
    s->records_written = s->records_forgotten = 0;
    s->verify_ran = false;
    s->verify_status = "";
    s->verify_groups = s->false_narrows = 0;
    s->verify_wall_us = 0;
}

void zcl_devloop_early_skip_decide(const char *root,
                                   const struct zcl_devloop_early_toolchain *tc,
                                   struct zcl_devloop_early_skip *s)
{
    if (!s)
        return;
    es_reset(s);
    struct es_ctx *c = zcl_calloc(1, sizeof(*c), "early_skip.ctx");
    if (!c) {
        for (size_t i = 0; i < s->n; i++)
            es_row_unvouched(&s->rows[i], "out-of-memory", "");
        es_count(s);
        return;
    }
    c->s = s;
    const char *blocked = es_ctx_open(c, root, tc);
    s->store_state = c->store.state ? c->store.state : "absent";
    es_decide_rows(c, blocked ? blocked : "");
    es_count(s);
    es_ctx_close(c);
    free(c);
}

/* ── recording ────────────────────────────────────────────────────────── */

static bool es_store_upsert(struct es_store *st,
                            const struct zcl_devloop_early_skip_row *row,
                            const char *identity, const char *candidate,
                            int64_t run_us)
{
    struct es_rec *rec = es_store_find(st, row->group);
    if (!rec && st->n >= ES_STORE_MAX_RECS)
        return false;
    if (!rec)
        rec = &st->recs[st->n++];
    memset(rec, 0, sizeof(*rec));
    (void)snprintf(rec->group, sizeof(rec->group), "%s", row->group);
    (void)snprintf(rec->key, sizeof(rec->key), "%s", row->key);
    (void)snprintf(rec->identity, sizeof(rec->identity), "%s", identity);
    (void)snprintf(rec->candidate, sizeof(rec->candidate), "%s",
                   es_hex64(candidate) ? candidate : "-");
    rec->run_us = run_us;
    return true;
}

static bool es_record_finish(const char *root, struct zcl_devloop_early_skip *s,
                             const struct es_store *st, uint32_t changed)
{
    bool ok = changed == 0 || es_store_save(root, st);
    s->record_state = changed == 0 ? "none" : ok ? "written" : "failed";
    return ok;
}

bool zcl_devloop_early_skip_record(const char *root,
                                   struct zcl_devloop_early_skip *s,
                                   const char *candidate_sha256,
                                   int64_t run_wall_us)
{
    if (!root || !s || !s->identity[0] || s->groups_run == 0)
        return true;
    struct es_store st;
    if (!es_store_load(root, &st)) {
        s->record_state = "failed";
        return false;
    }
    int64_t share = run_wall_us > 0 ? run_wall_us / s->groups_run : 0;
    uint32_t written = 0;
    bool ok = true;
    for (size_t i = 0; ok && i < s->n; i++) {
        const struct zcl_devloop_early_skip_row *row = &s->rows[i];
        if (row->skip || !row->vouched || !es_hex64(row->key))
            continue;
        ok = es_store_upsert(&st, row, s->identity,
                             candidate_sha256 ? candidate_sha256 : "", share);
        written += ok;
    }
    ok = ok && es_record_finish(root, s, &st, written);
    s->records_written = ok ? written : 0;
    free(st.recs);
    return ok;
}

bool zcl_devloop_early_skip_forget(const char *root,
                                   struct zcl_devloop_early_skip *s)
{
    if (!root || !s)
        return false;
    struct es_store st;
    if (!es_store_load(root, &st))
        return false;
    uint32_t dropped = 0;
    for (size_t i = 0; i < s->n; i++) {
        struct es_rec *rec = s->rows[i].skip
            ? es_store_find(&st, s->rows[i].group) : NULL;
        if (!rec)
            continue;
        *rec = st.recs[--st.n];
        dropped++;
    }
    bool ok = dropped == 0 || es_store_save(root, &st);
    s->records_forgotten = ok ? dropped : 0;
    free(st.recs);
    return ok;
}

/* ── the receipt ──────────────────────────────────────────────────────── */

static void es_json_rows(const struct zcl_devloop_early_skip *s,
                         struct json_value *o)
{
    struct json_value arr;
    json_init(&arr);
    json_set_array(&arr);
    for (size_t i = 0; i < s->n; i++) {
        const struct zcl_devloop_early_skip_row *row = &s->rows[i];
        struct json_value item;
        json_init(&item);
        json_set_object(&item);
        (void)json_push_kv_str(&item, "group", row->group);
        (void)json_push_kv_str(&item, "decision",
                               row->skip ? "skipped" : "run");
        (void)json_push_kv_str(&item, "reason", row->reason ? row->reason : "");
        (void)json_push_kv_str(&item, "key", row->key);
        (void)json_push_kv_bool(&item, "vouched", row->vouched);
        (void)json_push_kv_str(&item, "detail", row->detail);
        (void)json_push_kv_int(&item, "last_run_us", row->last_run_us);
        (void)json_push_back(&arr, &item);
        json_free(&item);
    }
    (void)json_push_kv(o, "groups", &arr);
    json_free(&arr);
}

static void es_json_verify(const struct zcl_devloop_early_skip *s,
                           struct json_value *o)
{
    struct json_value v;
    json_init(&v);
    json_set_object(&v);
    (void)json_push_kv_bool(&v, "ran", s->verify_ran);
    (void)json_push_kv_str(&v, "status",
                           s->verify_status ? s->verify_status : "");
    (void)json_push_kv_int(&v, "groups", s->verify_groups);
    (void)json_push_kv_int(&v, "false_narrows", s->false_narrows);
    (void)json_push_kv_int(&v, "wall_us", s->verify_wall_us);
    (void)json_push_kv(o, "verify", &v);
    json_free(&v);
}

void zcl_devloop_early_skip_json(const struct zcl_devloop_early_skip *s,
                                 struct json_value *doc)
{
    if (!s || !doc || !s->mode_name)
        return;
    struct json_value o;
    json_init(&o);
    json_set_object(&o);
    (void)json_push_kv_str(&o, "mode", s->mode_name);
    (void)json_push_kv_str(&o, "store", ZCL_DEVLOOP_EARLY_SKIP_STORE);
    (void)json_push_kv_str(&o, "store_state",
                           s->store_state ? s->store_state : "");
    (void)json_push_kv_str(&o, "identity", s->identity);
    (void)json_push_kv_int(&o, "groups_selected", s->groups_selected);
    (void)json_push_kv_int(&o, "groups_run", s->groups_run);
    (void)json_push_kv_int(&o, "groups_skipped_closure_unchanged",
                           s->groups_skipped);
    (void)json_push_kv_int(&o, "groups_unvouched", s->groups_unvouched);
    (void)json_push_kv_int(&o, "groups_skip_disabled",
                           s->groups_skip_disabled);
    (void)json_push_kv_int(&o, "estimated_wall_saved_us", s->saved_us);
    (void)json_push_kv_str(&o, "record_state",
                           s->record_state ? s->record_state : "");
    (void)json_push_kv_int(&o, "records_written", s->records_written);
    (void)json_push_kv_int(&o, "records_forgotten", s->records_forgotten);
    es_json_verify(s, &o);
    es_json_rows(s, &o);
    (void)json_push_kv(doc, "closure_skip", &o);
    json_free(&o);
}
