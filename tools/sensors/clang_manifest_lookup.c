/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Include lookups, stat-confirmed negative probes and __has_include replay shared by both semantic manifest producers. */
/* realpath() is declared only under _DEFAULT_SOURCE on glibc without the
 * fortify inline; set it before the first header pulls in <features.h>. */
#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif

#include "clang_manifest_core.h"

#include "base/safe_alloc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define CM_PRESENT_MAX 256

/* Probe slots of one lookup, in the order the front end searches them:
 * quoted: the includer's directory, then the quote dirs, then the angled
 * dirs; angled: the angled dirs only. */
struct cm_probe {
    uint8_t form;
    char includer_dir[PATH_MAX];
    const char *name;
    uint32_t hit_slot;
    uint32_t present[CM_PRESENT_MAX];
    size_t npresent;
    char found_real[PATH_MAX];
    bool found;
};

static uint32_t cm_slot_count(const struct cm_core *c, uint8_t form)
{
    size_t n = c->angled.n;
    if (form == VCS_SEMANTIC_FORM_V1_QUOTED)
        n += 1 + c->quote.n;
    return (uint32_t)n;
}

static const char *cm_slot_dir(const struct cm_core *c,
                               const struct cm_probe *p, uint32_t slot)
{
    if (p->form == VCS_SEMANTIC_FORM_V1_QUOTED) {
        if (slot == 0)
            return p->includer_dir;
        slot -= 1;
        if (slot < c->quote.n)
            return c->quote.items[slot].raw;
        slot -= (uint32_t)c->quote.n;
    }
    return slot < c->angled.n ? c->angled.items[slot].raw : NULL;
}

static void cm_dir_of(const char *opened, char out[PATH_MAX])
{
    const char *slash = strrchr(opened, '/');
    if (slash == NULL) {
        (void)snprintf(out, PATH_MAX, ".");
        return;
    }
    if (slash == opened) {
        (void)snprintf(out, PATH_MAX, "/");
        return;
    }
    (void)snprintf(out, PATH_MAX, "%.*s", (int)(slash - opened), opened);
}

/* Walk the slots from `first` on; every slot before it is one the search
 * never looks at (an include_next start), recorded present: unclaimed.
 * With want_real set, stop at the slot whose regular file is that exact
 * file (the compiler's reported hit) and record any earlier regular file
 * that the compiler skipped; without it, stop at the first regular file (a
 * replay of the search). Misses are stat-confirmed. False when the slots
 * before `first` do not fit the present list. */
static bool cm_probe_run(const struct cm_core *c, struct cm_probe *p,
                         const char *want_real, uint32_t first)
{
    uint32_t count = cm_slot_count(c, p->form);
    p->hit_slot = count;
    p->npresent = 0;
    p->found = false;
    if (first > CM_PRESENT_MAX)
        return false;
    for (uint32_t s = 0; s < first && s < count; s++)
        p->present[p->npresent++] = s;
    for (uint32_t s = first; s < count; s++) {
        char cand[PATH_MAX * 2];
        struct stat sb;
        (void)snprintf(cand, sizeof(cand), "%s/%s", cm_slot_dir(c, p, s),
                       p->name);
        if (stat(cand, &sb) != 0 || !S_ISREG(sb.st_mode))
            continue;
        if (realpath(cand, p->found_real) == NULL)
            continue;
        if (want_real == NULL || strcmp(p->found_real, want_real) == 0) {
            p->hit_slot = s;
            p->found = true;
            return true;
        }
        if (p->npresent < CM_PRESENT_MAX)
            p->present[p->npresent++] = s;
    }
    return true;
}

static bool cm_emit_lookup(struct cm_core *c, const struct cm_file *includer,
                           const struct cm_probe *p, uint8_t kind,
                           const char *hit_path, uint8_t evidence)
{
    struct vcs_semantic_record_v1 rec = {0};
    bool ok;
    vcs_semantic_record_v1_cstr(&rec, includer->path);
    vcs_semantic_record_v1_cstr(&rec, p->name);
    vcs_semantic_record_v1_u8(&rec, p->form);
    vcs_semantic_record_v1_u8(&rec, kind);
    vcs_semantic_record_v1_cstr(&rec, hit_path);
    vcs_semantic_record_v1_u32(&rec, p->hit_slot);
    vcs_semantic_record_v1_u8(&rec, evidence);
    vcs_semantic_record_v1_u32(&rec, (uint32_t)p->npresent);
    for (size_t k = 0; k < p->npresent; k++)
        vcs_semantic_record_v1_u32(&rec, p->present[k]);
    ok = cm_add(c, VCS_SEMANTIC_SECTION_V1_LOOKUPS, &rec);
    vcs_semantic_record_v1_free(&rec);
    if (ok && c->facts)
        ok = cm_emit_probe(c, includer, p->name, p->form, kind,
                           evidence != VCS_SEMANTIC_MISS_V1_NONE, p->hit_slot,
                           p->present, p->npresent);
    return ok;
}

/* How a directive entered its hit, for a __has_include_next the hit makes
 * (cm_cond_next): the combined search index (quote dirs, then angled dirs)
 * of the slot the replay found it in; CM_ENTRY_NORMAL when found in its
 * includer's own dir (the front end then records no search slot, and
 * include_next searches as include does); CM_ENTRY_UNKNOWN when the
 * directive makes no claim (include_next, computed, absolute, or a replay
 * that did not find the compiler's file). */
static uint32_t cm_entry_of(const struct cm_core *c, const struct cm_probe *p,
                            uint8_t evidence)
{
    if (evidence == VCS_SEMANTIC_MISS_V1_NONE || !p->found)
        return CM_ENTRY_UNKNOWN;
    if (p->form != VCS_SEMANTIC_FORM_V1_QUOTED)
        return (uint32_t)c->quote.n + p->hit_slot;
    return p->hit_slot == 0 ? CM_ENTRY_NORMAL : p->hit_slot - 1;
}

static bool cm_entry_add(struct cm_core *c, const struct cm_file *f,
                         uint32_t slot)
{
    for (size_t k = 0; k < c->nentries; k++)
        if (c->entries[k].file == f && c->entries[k].slot == slot)
            return true;
    if (!cm_grow((void **)&c->entries, &c->capentries, c->nentries,
                 sizeof(*c->entries)))
        return cm_fail(c, "out of memory");
    c->entries[c->nentries++] = (struct cm_entry){.file = f, .slot = slot};
    return true;
}

bool cm_lookup_directive(struct cm_core *c, const struct cm_file *includer,
                         const char *spelled, uint8_t form, uint8_t kind,
                         bool computed, const struct cm_file *hit)
{
    struct cm_probe p = {.form = form, .name = spelled};
    uint8_t evidence = VCS_SEMANTIC_MISS_V1_DERIVED_STAT;
    if (hit == NULL)
        return cm_fail(c, "include of \"%s\" in %s resolved to no read file",
                       spelled, includer->path);
    cm_dir_of(includer->opened, p.includer_dir);
    if (kind == VCS_SEMANTIC_LOOKUP_V1_INCLUDE_NEXT || computed ||
        spelled[0] == '/') {
        p.hit_slot = cm_slot_count(c, p.form);
        evidence = VCS_SEMANTIC_MISS_V1_NONE;
        kind = kind == VCS_SEMANTIC_LOOKUP_V1_INCLUDE_NEXT
                   ? kind : VCS_SEMANTIC_LOOKUP_V1_INCLUDE;
    } else if (!cm_probe_run(c, &p, hit->real, 0) || !p.found) {
        p.npresent = 0;
        p.found = false;
        evidence = VCS_SEMANTIC_MISS_V1_NONE;
    }
    return cm_entry_add(c, hit, cm_entry_of(c, &p, evidence)) &&
           cm_emit_lookup(c, includer, &p, kind, hit->path, evidence);
}

/* ---- conditional lookups: text scan + search replay --------------------------- */

/* __has_include and its relatives ask whether a name resolves, and #embed
 * reads a resource, without an include directive the front end reports.
 * The scan's invariant: every occurrence of a lookup word in the text of
 * any file the TU reads (a system header's too: its angled searches start
 * at the repo's -I dirs) ends with a record, unless it lies in a group
 * clang skipped (less the #elif lines it may evaluate) or clang's own tokens,
 * outside a skipped group, show it is none (cm_floor_file). A word clang
 * lexes as a lookup token (clang_manifest_tokens.c) is replayed where the
 * scan can: a __has_include whose operand is a literal "x" or <x>, or an
 * object-like repo macro every definition of which is one plain string
 * literal (the front end's recorded expansion at that offset names the
 * definition; facts manifests only, since only they keep expansions), and
 * a __has_include_next from the slot after each one its file was entered
 * through (cm_entry_add), or, in a system header, from the start and after
 * each search dir that could hold it (cm_cond_next_system); the producer
 * runs the search itself and stat-confirms every probe (REPLAYED_STAT),
 * and the slots before the start are recorded present, with no claim.
 * Every other occurrence - another operand, __has_embed, the GNU
 * __has_include__ words, #embed, an include_next start no slot names, one
 * a line continuation or trigraph runs through, a word in any #define body
 * or -D value, a word not followed by its '(' (an alias's body), one in a
 * header name or #warning or #error text, and, once for
 * the TU, words some ## could paste into a lookup word
 * (cm_core.paste_piece) - is recorded with no negative claim
 * (MISS_V1_NONE), spelled from "#embed" or "__has_embed" on, so the facts
 * consumer treats it as reachable by every changed path. Precision
 * failures only ever widen. The sensor refuses every -X pass-through,
 * -Wp,, front-end plugins and MSVC compatibility,
 * whose -D, -std or trigraph rules the scan cannot read, and a TU where a
 * lookup token clang lexes is not the word the scan reads at its offset.
 * The scan reads each word's operand in the text as translation phases 1
 * and 2 leave it (cm_splice, with the trigraph rule cm_measure_lang
 * measured for the TU).
 * Contract: docs/work/SEMANTIC_MANIFEST.md, "Warm session". */

/* The longest spelled name an unbound record keeps. */
#define CM_COND_NAME_MAX 200

static bool cm_ident_char(char ch)
{
    return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
           (ch >= '0' && ch <= '9') || ch == '_';
}

static size_t cm_skip_space(const char *s, size_t i, size_t n)
{
    while (i < n && (s[i] == ' ' || s[i] == '\t'))
        i++;
    return i;
}

/* A file's text as translation phases 1 and 2 leave it: each trigraph
 * replaced (when the TU's mode has them) and every backslash-newline (clang
 * also takes spaces between the two) removed. splices holds, strictly
 * increasing, each offset of the spliced text that one was removed before,
 * or that holds a trigraph's replacement: an offset the front end reports
 * past one no longer names the same byte here. */
struct cm_spliced {
    const char *s;
    size_t n;
    char *owned;
    size_t *splices;
    size_t *map; /* when owned: map[r] is the spliced offset of raw byte r */
    size_t nsplices, cap;
};

/* The end of a line splice whose backslash is at s[i], as clang's
 * getEscapedNewLineSize reads one (blanks, form feeds and vertical tabs,
 * then a newline or carriage return, then the other of the two), or 0. */
static size_t cm_continuation_end(const char *s, size_t i, size_t n)
{
    size_t j = i + 1;
    while (j < n && (s[j] == ' ' || s[j] == '\t' || s[j] == '\f' ||
                     s[j] == '\v'))
        j++;
    if (j >= n || (s[j] != '\n' && s[j] != '\r'))
        return 0;
    if (j + 1 < n && (s[j + 1] == '\n' || s[j + 1] == '\r') &&
        s[j + 1] != s[j])
        return j + 2;
    return j + 1;
}

/* The character the trigraph at s[i] stands for, else 0. */
static char cm_trigraph(const char *s, size_t i, size_t n)
{
    static const char from[] = "=/'()!<>-", to[] = "#\\^[]|{}~";
    const char *p;
    if (n - i < 3 || s[i] != '?' || s[i + 1] != '?' || s[i + 2] == '\0')
        return 0;
    p = strchr(from, s[i + 2]);
    return p == NULL ? 0 : to[p - from];
}

static bool cm_any_trigraph(const char *s, size_t n)
{
    for (size_t i = 0; i + 2 < n; i++)
        if (cm_trigraph(s, i, n) != 0)
            return true;
    return false;
}

static bool cm_splice_mark(struct cm_spliced *t, size_t w)
{
    if (!cm_grow((void **)&t->splices, &t->cap, t->nsplices,
                 sizeof(*t->splices)))
        return false;
    if (t->nsplices == 0 || t->splices[t->nsplices - 1] != w)
        t->splices[t->nsplices++] = w;
    return true;
}

/* One step of cm_splice at raw offset *i: a trigraph, a continuation or a
 * plain character, written at spliced offset *w; map records where each
 * raw byte it covers lands. */
static bool cm_splice_step(const char *s, size_t n, bool trigraphs,
                           struct cm_spliced *t, size_t *i, size_t *w)
{
    char tri = trigraphs ? cm_trigraph(s, *i, n) : 0;
    char ch = tri != 0 ? tri : s[*i];
    size_t width = tri != 0 ? 3 : 1;
    size_t end = ch == '\\' ? cm_continuation_end(s, *i + width - 1, n) : 0;
    size_t next = end != 0 ? end : *i + width;
    if ((end != 0 || tri != 0) && !cm_splice_mark(t, *w))
        return false;
    for (size_t k = *i; k < next; k++)
        t->map[k] = *w;
    if (end == 0)
        t->owned[(*w)++] = ch;
    *i = next;
    return true;
}

static bool cm_splice(const char *s, size_t n, bool trigraphs,
                      struct cm_spliced *t)
{
    size_t w = 0;
    memset(t, 0, sizeof(*t));
    t->s = s;
    t->n = n;
    trigraphs = trigraphs && cm_any_trigraph(s, n);
    if (!trigraphs && memchr(s, '\\', n) == NULL)
        return true;
    t->owned = zcl_malloc(n + 1, "clang_manifest.spliced");
    t->map = zcl_calloc(n + 1, sizeof(*t->map), "clang_manifest.splice_map");
    if (t->owned == NULL || t->map == NULL)
        return false;
    for (size_t i = 0; i < n;)
        if (!cm_splice_step(s, n, trigraphs, t, &i, &w))
            return false;
    t->owned[w] = '\0';
    t->map[n] = w;
    t->s = t->owned;
    t->n = w;
    return true;
}

static void cm_spliced_free(struct cm_spliced *t)
{
    free(t->owned);
    free(t->splices);
    free(t->map);
}

/* Did a continuation run through the occurrence [start, end)? */
static bool cm_spliced_inside(const struct cm_spliced *t, size_t start,
                              size_t end)
{
    for (size_t k = 0; k < t->nsplices; k++) {
        if (t->splices[k] > start && t->splices[k] < end)
            return true;
    }
    return false;
}

/* The quoted or angled operand starting at s[j]; copied to name. *close is
 * the offset of its closing character. */
static bool cm_include_operand(const char *s, size_t j, size_t n,
                               uint8_t *form, char name[PATH_MAX],
                               size_t *close)
{
    size_t end;
    char want;
    if (j >= n || (s[j] != '"' && s[j] != '<'))
        return false;
    want = s[j] == '"' ? '"' : '>';
    *form = s[j] == '"' ? VCS_SEMANTIC_FORM_V1_QUOTED : VCS_SEMANTIC_FORM_V1_ANGLED;
    for (end = j + 1; end < n && s[end] != want && s[end] != '\n'; end++)
        ;
    if (end >= n || s[end] != want || end - j - 1 == 0 || end - j - 1 >= PATH_MAX)
        return false;
    memcpy(name, s + j + 1, end - j - 1);
    name[end - j - 1] = '\0';
    *close = end;
    return true;
}

/* What the scan can replay of a conditional-lookup word. */
enum cm_cond_kind {
    CM_COND_OTHER, /* recorded unbound */
    CM_COND_PLAIN, /* __has_include */
    CM_COND_NEXT,  /* __has_include_next */
};

/* The length of the conditional-lookup word at s[i], else 0; *kind: what
 * the scan can replay of it. */
static size_t cm_cond_word(const char *s, size_t i, size_t n,
                           enum cm_cond_kind *kind)
{
    static const char *const words[] = {
        "__has_include_next__", "__has_include_next", "__has_include__",
        "__has_include", "__has_embed",
    };
    if (s[i] != '_' || (i > 0 && cm_ident_char(s[i - 1])))
        return 0;
    for (size_t w = 0; w < sizeof(words) / sizeof(words[0]); w++) {
        size_t len = strlen(words[w]);
        if (n - i >= len && memcmp(s + i, words[w], len) == 0 &&
            (i + len == n || !cm_ident_char(s[i + len]))) {
            *kind = strcmp(words[w], "__has_include") == 0 ? CM_COND_PLAIN
                    : strcmp(words[w], "__has_include_next") == 0
                        ? CM_COND_NEXT
                        : CM_COND_OTHER;
            return len;
        }
    }
    return 0;
}

/* A __has_include(...) with a literal operand, closed on its own spelling:
 * form and name; *end is just past the ')'. An operand holding a comment
 * opener is none: which name the front end reads there is left unbound. */
static bool cm_literal_at(const char *s, size_t i, size_t n, uint8_t *form,
                          char name[PATH_MAX], size_t *end)
{
    size_t j = cm_skip_space(s, i, n), close;
    if (j >= n || s[j] != '(')
        return false;
    if (!cm_include_operand(s, cm_skip_space(s, j + 1, n), n, form, name,
                            &close) ||
        strstr(name, "/*") != NULL || strstr(name, "//") != NULL)
        return false;
    j = cm_skip_space(s, close + 1, n);
    if (j >= n || s[j] != ')')
        return false;
    *end = j + 1;
    return true;
}

/* The form of an unbound occurrence s[i, end): angled when its operand's
 * first quote or angle is '<', else quoted. */
static uint8_t cm_cond_form(const char *s, size_t i, size_t end)
{
    size_t open = i;
    while (open < end && s[open] != '"' && s[open] != '<')
        open++;
    return open < end && s[open] == '<' ? VCS_SEMANTIC_FORM_V1_ANGLED
                                        : VCS_SEMANTIC_FORM_V1_QUOTED;
}

/* An unbound occurrence's spelled name: from s[i] through the first ')' of
 * its line, else to the line's end, trailing blanks dropped, with prefix in
 * front; and its form. */
static void cm_cond_name(const char *prefix, const char *s, size_t i,
                         size_t n, char name[PATH_MAX], uint8_t *form)
{
    size_t end = i;
    while (end < n && s[end] != '\n' && s[end] != ')')
        end++;
    if (end < n && s[end] == ')')
        end++;
    while (end > i && (s[end - 1] == ' ' || s[end - 1] == '\t' ||
                       s[end - 1] == '\r'))
        end--;
    if (end - i > CM_COND_NAME_MAX)
        end = i + CM_COND_NAME_MAX;
    (void)snprintf(name, PATH_MAX, "%s%.*s", prefix, (int)(end - i), s + i);
    *form = cm_cond_form(s, i, end);
}

/* A lookup the scan found and cannot replay: no hit, no negative claim.
 * Its name is spelled from "#embed" or "__has_embed" on ("#embed? " put in
 * front of any other), so the facts consumer treats it as reachable by
 * every changed path, a content edit too: what it reads is not known. */
static bool cm_cond_unbound(struct cm_core *c, const struct cm_file *f,
                            const char *name, uint8_t form)
{
    char spelled[PATH_MAX];
    struct cm_probe p = {.form = form, .name = spelled};
    bool embed = strncmp(name, "#embed", 6) == 0 ||
                 strncmp(name, "__has_embed", 11) == 0;
    int w = snprintf(spelled, sizeof(spelled), "%s%s", embed ? "" : "#embed? ",
                     name);
    if (w < 0)
        return cm_fail(c, "cannot spell an unbound lookup");
    cm_dir_of(f->opened, p.includer_dir);
    p.hit_slot = cm_slot_count(c, form);
    return cm_emit_lookup(c, f, &p, VCS_SEMANTIC_LOOKUP_V1_HAS_INCLUDE, "",
                          VCS_SEMANTIC_MISS_V1_NONE);
}

/* Replay the search for `name` from slot `first` of form's numbering;
 * *fits false (nothing emitted) when the slots before it do not fit. */
static bool cm_has_include_from(struct cm_core *c, const struct cm_file *f,
                                uint8_t form, const char *name,
                                uint32_t first, bool *fits)
{
    struct cm_probe p = {.form = form, .name = name};
    char *hit_path = NULL;
    bool ok;
    cm_dir_of(f->opened, p.includer_dir);
    *fits = cm_probe_run(c, &p, NULL, first);
    if (!*fits)
        return true;
    if (p.found && !cm_norm_path(c, p.found_real, &hit_path))
        return false;
    ok = cm_emit_lookup(c, f, &p, VCS_SEMANTIC_LOOKUP_V1_HAS_INCLUDE,
                        p.found ? hit_path : "",
                        VCS_SEMANTIC_MISS_V1_REPLAYED_STAT);
    free(hit_path);
    return ok;
}

static bool cm_has_include_one(struct cm_core *c, const struct cm_file *f,
                               uint8_t form, const char *name)
{
    bool fits;
    return cm_has_include_from(c, f, form, name, 0, &fits);
}

/* One entry of f for __has_include_next(name): the main file, or a file
 * found in its includer's own dir, searches as __has_include does (the
 * front end warns and starts over); a file found in combined slot e
 * searches from e + 1, which is quoted slot e + 2 (slot 0 is the
 * includer's dir, which include_next never searches). */
static bool cm_next_entry(struct cm_core *c, const struct cm_file *f,
                          uint8_t form, const char *name, const char *raw,
                          uint8_t raw_form, uint32_t entry)
{
    bool fits = false, ok;
    if (entry == CM_ENTRY_NORMAL)
        return cm_has_include_one(c, f, form, name);
    ok = entry == CM_ENTRY_UNKNOWN ||
         cm_has_include_from(c, f, VCS_SEMANTIC_FORM_V1_QUOTED, name,
                             entry + 2, &fits);
    return ok && (fits || cm_cond_unbound(c, f, raw, raw_form));
}

/* Could f have been found in the search dir `raw`: its raw spelling opens
 * f's opened name, or its realpath holds f's realpath? */
static bool cm_dir_holds(const char *raw, const struct cm_file *f)
{
    char real[PATH_MAX];
    size_t n = strlen(raw);
    while (n > 1 && raw[n - 1] == '/')
        n--;
    if (strncmp(f->opened, raw, n) == 0 && f->opened[n] == '/')
        return true;
    if (realpath(raw, real) == NULL)
        return false;
    n = strlen(real);
    return n > 1 && strncmp(f->real, real, n) == 0 && f->real[n] == '/';
}

/* __has_include_next(name) in a system file. Its entries come from other
 * system files too, which record no lookups, so every way it could have
 * been entered is replayed: found relative or by absolute path (searches
 * as __has_include does), and found in each search dir that could hold it
 * (searches the dirs after it). Unbound when no search dir holds it. */
static bool cm_cond_next_system(struct cm_core *c, const struct cm_file *f,
                                uint8_t form, const char *name,
                                const char *raw, uint8_t raw_form)
{
    size_t nq = c->quote.n, all = nq + c->angled.n;
    bool any = false, ok = cm_has_include_one(c, f, form, name);
    for (size_t e = 0; ok && e < all; e++) {
        const char *dir = e < nq ? c->quote.items[e].raw
                                 : c->angled.items[e - nq].raw;
        bool fits = false;
        if (!cm_dir_holds(dir, f))
            continue;
        any = true;
        ok = cm_has_include_from(c, f, VCS_SEMANTIC_FORM_V1_QUOTED, name,
                                 (uint32_t)e + 2, &fits) &&
             (fits || cm_cond_unbound(c, f, raw, raw_form));
    }
    return ok && (any || cm_cond_unbound(c, f, raw, raw_form));
}

/* __has_include_next(name) in f, once per way f was entered; unbound when
 * f was entered in a way that names no search slot. */
static bool cm_cond_next(struct cm_core *c, const struct cm_file *f,
                         uint8_t form, const char *name, const char *raw,
                         uint8_t raw_form)
{
    bool any = false, ok = true;
    if (f->origin == VCS_SEMANTIC_ORIGIN_V1_MAIN)
        return cm_has_include_one(c, f, form, name);
    if (f->origin == VCS_SEMANTIC_ORIGIN_V1_SYSTEM)
        return cm_cond_next_system(c, f, form, name, raw, raw_form);
    for (size_t k = 0; ok && k < c->nentries; k++) {
        if (c->entries[k].file != f)
            continue;
        any = true;
        ok = cm_next_entry(c, f, form, name, raw, raw_form,
                           c->entries[k].slot);
    }
    return ok && (any || cm_cond_unbound(c, f, raw, raw_form));
}

/* ---- a macro operand: the literals its expansion there can give ------------- */

#define CM_MACRO_NAMES_MAX 8

struct cm_names {
    char v[CM_MACRO_NAMES_MAX][PATH_MAX];
    size_t n;
};

/* The identifier operand of "( IDENT )" at s[j]: [*a, *b). */
static bool cm_ident_operand(const char *s, size_t j, size_t n, size_t *a,
                             size_t *b)
{
    j = cm_skip_space(s, j, n);
    if (j >= n || s[j] != '(')
        return false;
    *a = cm_skip_space(s, j + 1, n);
    if (*a >= n || !cm_ident_char(s[*a]) || (s[*a] >= '0' && s[*a] <= '9'))
        return false;
    for (*b = *a; *b < n && cm_ident_char(s[*b]); (*b)++)
        ;
    j = cm_skip_space(s, *b, n);
    return j < n && s[j] == ')';
}

/* A macro body that is one plain string literal: its contents. */
static bool cm_string_body(const char *body, char name[PATH_MAX])
{
    size_t n = strlen(body);
    if (n < 3 || n - 2 >= PATH_MAX || body[0] != '"' || body[n - 1] != '"' ||
        memchr(body + 1, '"', n - 2) != NULL ||
        memchr(body + 1, '\\', n - 2) != NULL)
        return false;
    memcpy(name, body + 1, n - 2);
    name[n - 2] = '\0';
    return true;
}

static bool cm_names_add(struct cm_names *out, const char *name)
{
    for (size_t k = 0; k < out->n; k++)
        if (strcmp(out->v[k], name) == 0)
            return true;
    if (out->n == CM_MACRO_NAMES_MAX)
        return false;
    (void)snprintf(out->v[out->n++], PATH_MAX, "%s", name);
    return true;
}

/* Every repo definition of `ident` whose id is def_id is an object-like
 * macro whose body is one plain string literal; add each. */
static bool cm_def_literals(const struct cm_core *c, const char *ident,
                            const char *def_id, struct cm_names *out)
{
    bool matched = false;
    for (size_t k = 0; k < c->nmacros; k++) {
        const struct cm_macro *m = &c->macros[k];
        char name[PATH_MAX], *id;
        bool same;
        if (strcmp(m->name, ident) != 0)
            continue;
        id = cm_id('m', m->path, m->name, 0);
        same = id != NULL && strcmp(id, def_id) == 0;
        free(id);
        if (!same)
            continue;
        matched = true;
        if (m->function_like || !cm_string_body(m->body, name) ||
            !cm_names_add(out, name))
            return false;
    }
    return matched;
}

/* The literals the macro operand spelled at f's offset [a, b) expands to:
 * every expansion the front end recorded there names a repo definition,
 * and every such definition is a plain string literal. False (unbound)
 * otherwise: no expansion there (a skipped group, or offsets a line
 * continuation moved), a predefined or builtin macro, or another body. */
static bool cm_macro_names(const struct cm_core *c, const struct cm_file *f,
                           const struct cm_spliced *t, size_t a, size_t b,
                           struct cm_names *out)
{
    char ident[CM_COND_NAME_MAX + 1];
    bool any = false;
    if (t->nsplices != 0 || b - a > CM_COND_NAME_MAX)
        return false;
    memcpy(ident, t->s + a, b - a);
    ident[b - a] = '\0';
    for (size_t k = 0; k < c->nexps; k++) {
        const struct cm_expansion *e = &c->exps[k];
        if (e->file != f || e->offset != a || strcmp(e->name, ident) != 0)
            continue;
        any = true;
        if (e->def_id == NULL || !cm_def_literals(c, ident, e->def_id, out))
            return false;
    }
    return any;
}

/* A __has_include or __has_include_next whose operand is a literal, or a
 * macro that expands to literals: replay each; false in *done otherwise. */
static bool cm_cond_resolve(struct cm_core *c, const struct cm_file *f,
                            const struct cm_spliced *t, size_t i, size_t len,
                            enum cm_cond_kind kind, bool *done)
{
    struct cm_names names = {0};
    char raw[PATH_MAX];
    uint8_t form = VCS_SEMANTIC_FORM_V1_QUOTED, raw_form;
    size_t end, a, b;
    bool ok = true;
    *done = true;
    if (cm_literal_at(t->s, i + len, t->n, &form, names.v[0], &end) &&
        !cm_spliced_inside(t, i, end))
        names.n = 1;
    else if (!cm_ident_operand(t->s, i + len, t->n, &a, &b) ||
             !cm_macro_names(c, f, t, a, b, &names))
        return *done = false, true;
    cm_cond_name("", t->s, i, t->n, raw, &raw_form);
    for (size_t k = 0; ok && k < names.n; k++)
        ok = kind == CM_COND_NEXT
                 ? cm_cond_next(c, f, form, names.v[k], raw, raw_form)
                 : cm_has_include_one(c, f, form, names.v[k]);
    return ok;
}

/* The lookup word clang lexed at t[i]: replayed, or recorded unbound. */
static bool cm_cond_at(struct cm_core *c, const struct cm_file *f,
                       const struct cm_spliced *t, size_t i)
{
    char name[PATH_MAX];
    uint8_t form;
    enum cm_cond_kind kind = CM_COND_OTHER;
    bool done = false;
    size_t len = cm_cond_word(t->s, i, t->n, &kind);
    if (kind != CM_COND_OTHER &&
        !cm_cond_resolve(c, f, t, i, len, kind, &done))
        return false;
    if (done)
        return true;
    cm_cond_name("", t->s, i, t->n, name, &form);
    return cm_cond_unbound(c, f, name, form);
}

/* ---- what the scan reads: the TU's language, its files, its -D values ------ */

/* A conditional-lookup word at s[i] in a macro's body (a #define's, or a
 * -D value's): evaluated wherever the macro expands, and quoted names then
 * search that file's directory, so the scan cannot replay it: recorded
 * unbound, on f. */
static bool cm_body_at(struct cm_core *c, const struct cm_file *f,
                       const char *s, size_t i, size_t n)
{
    enum cm_cond_kind kind = CM_COND_OTHER;
    char name[PATH_MAX];
    uint8_t form;
    if (cm_cond_word(s, i, n, &kind) == 0)
        return true;
    cm_cond_name("", s, i, n, name, &form);
    return cm_cond_unbound(c, f, name, form);
}

/* The value of the -D (or --define-macro) option at argv[*k], or NULL;
 * *k moves past a separate value. */
static const char *cm_define_value(const char *const *argv, size_t argc,
                                   size_t *k)
{
    const char *a = argv[*k];
    if (strcmp(a, "-D") == 0 || strcmp(a, "--define-macro") == 0)
        return *k + 1 < argc ? argv[++*k] : NULL;
    if (strncmp(a, "-D", 2) == 0)
        return a + 2;
    if (strncmp(a, "--define-macro=", 15) == 0)
        return a + 15;
    return NULL;
}

/* The main file, or NULL. */
static const struct cm_file *cm_main_file(const struct cm_core *c)
{
    for (size_t k = 0; k < c->nfiles; k++)
        if (c->files[k].origin == VCS_SEMANTIC_ORIGIN_V1_MAIN)
            return &c->files[k];
    return NULL;
}

/* Every conditional-lookup word in a -D value, recorded unbound on the
 * main file: the macro it defines is text no file holds. */
static bool cm_scan_argv(struct cm_core *c, const struct cm_file *main,
                         const char *const *argv, size_t argc)
{
    for (size_t k = 0; k < argc; k++) {
        const char *v = cm_define_value(argv, argc, &k);
        size_t n = v == NULL ? 0 : strlen(v);
        for (size_t i = 0; i < n; i++)
            if (!cm_body_at(c, main, v, i, n))
                return false;
    }
    return true;
}

/* ---- the floor: every occurrence of a lookup word has a record ------------ */

/* f's text with every line splice clang could accept removed, a ??/ one
 * too whether or not the TU replaces trigraphs (removing more only finds
 * more words); map[k] is the raw offset of out[k]. */
struct cm_floor {
    char *s;
    size_t *map;
    size_t n;
};

static bool cm_floor_text(const char *s, size_t n, struct cm_floor *t)
{
    t->s = zcl_malloc(n + 1, "clang_manifest.floor");
    t->map = zcl_calloc(n + 1, sizeof(*t->map), "clang_manifest.floor_map");
    t->n = 0;
    if (t->s == NULL || t->map == NULL)
        return false;
    for (size_t i = 0; i < n;) {
        bool tri = n - i >= 3 && s[i] == '?' && s[i + 1] == '?' &&
                   s[i + 2] == '/';
        size_t end = s[i] == '\\' || tri
                         ? cm_continuation_end(s, tri ? i + 2 : i, n) : 0;
        if (end != 0) {
            i = end;
            continue;
        }
        t->map[t->n] = i;
        t->s[t->n++] = s[i++];
    }
    t->s[t->n] = '\0';
    t->map[t->n] = n;
    return true;
}

/* Skip blanks and block comments: what may sit between a directive's '#'
 * and its name. */
static size_t cm_floor_space(const char *s, size_t i, size_t n)
{
    for (;;) {
        while (i < n && (s[i] == ' ' || s[i] == '\t' || s[i] == '\f' ||
                         s[i] == '\v'))
            i++;
        if (n - i < 2 || s[i] != '/' || s[i + 1] != '*')
            return i;
        for (i += 2; n - i >= 2 && (s[i] != '*' || s[i + 1] != '/'); i++)
            ;
        if (n - i < 2)
            return n;
        i += 2;
    }
}

/* The offset of "embed" in an #embed directive (#, %: or ??=, whether or
 * not the TU has trigraphs) that starts at s[i], else SIZE_MAX. */
static size_t cm_floor_embed(const char *s, size_t i, size_t n)
{
    size_t j;
    if (s[i] == '#')
        j = i + 1;
    else if (s[i] == '%' && n - i >= 2 && s[i + 1] == ':')
        j = i + 2;
    else if (s[i] == '?' && n - i >= 3 && s[i + 1] == '?' && s[i + 2] == '=')
        j = i + 3;
    else
        return SIZE_MAX;
    j = cm_floor_space(s, j, n);
    if (n - j < 5 || memcmp(s + j, "embed", 5) != 0 ||
        (j + 5 < n && cm_ident_char(s[j + 5])))
        return SIZE_MAX;
    return j;
}

static bool cm_floor_is(const struct cm_floor *t, size_t i, const char *w)
{
    size_t len = strlen(w);
    return t->n - i >= len && memcmp(t->s + i, w, len) == 0;
}

/* The occurrence at t[i], if any: recorded unbound unless clang's tokens
 * already gave it a record (a lookup token the scan read) or show it is
 * none (exempt, or hidden, outside a skipped group) or it lies in a
 * skipped group. */
static bool cm_floor_at(struct cm_core *c, const struct cm_file *f,
                        const struct cm_floor *t, size_t i)
{
    char name[PATH_MAX];
    uint8_t form, v;
    size_t e = SIZE_MAX;
    if (!cm_floor_is(t, i, "__has_include") &&
        !cm_floor_is(t, i, "__has_embed") &&
        (e = cm_floor_embed(t->s, i, t->n)) == SIZE_MAX)
        return true;
    v = f->live[t->map[e != SIZE_MAX ? e : i]];
    if (v == CM_LIVE_HIDDEN || v == CM_LIVE_SKIPPED ||
        (e == SIZE_MAX && v != CM_LIVE_NONE))
        return true;
    if (e != SIZE_MAX)
        cm_cond_name("#embed ", t->s, cm_skip_space(t->s, e + 5, t->n), t->n,
                     name, &form);
    else
        cm_cond_name("", t->s, i, t->n, name, &form);
    return cm_cond_unbound(c, f, name, form);
}

/* Every occurrence of a lookup word in f's text (any spelling of
 * __has_include or __has_embed, as a word or inside one, and every #embed
 * directive, in comments and literals too) ends with a
 * record, unless clang's tokens show it is none or it lies in a skipped
 * group. */
static bool cm_floor_file(struct cm_core *c, const struct cm_file *f)
{
    struct cm_floor t = {0};
    bool ok = cm_floor_text(f->contents, f->size, &t);
    if (!ok)
        (void)cm_fail(c, "out of memory");
    for (size_t i = 0; ok && i < t.n; i++)
        if (t.s[i] == '_' || t.s[i] == '#' || t.s[i] == '%' || t.s[i] == '?')
            ok = cm_floor_at(c, f, &t, i);
    free(t.s);
    free(t.map);
    return ok;
}

/* ---- the files: clang's lookup tokens, then the floor ---------------------- */

/* code[i]: f->live (clang's tokens, by raw offset) carried through the
 * splice to t's offsets, for the lookup tokens. */
static uint8_t *cm_code_of(const struct cm_file *f, const struct cm_spliced *t)
{
    uint8_t *code = zcl_calloc(t->n + 1, 1, "clang_manifest.code_mask");
    if (code == NULL)
        return NULL;
    for (size_t r = 0; r < f->size; r++)
        if (f->live[r] != CM_LIVE_NONE && f->live[r] != CM_LIVE_HIDDEN &&
            f->live[r] != CM_LIVE_SKIPPED)
            code[t->map != NULL ? t->map[r] : r] = f->live[r];
    return code;
}

/* The lookup token clang lexed at t[i]: the scan must read the same word
 * there, or the TU is refused (a splice or trigraph rule the scan does
 * not share with clang would otherwise drop it). */
static bool cm_token_at(struct cm_core *c, const struct cm_file *f,
                        const struct cm_spliced *t, size_t i, uint8_t v)
{
    enum cm_cond_kind kind;
    if (cm_cond_word(t->s, i, t->n, &kind) == 0)
        return cm_fail(c, "unsupported translation-unit language: a lookup "
                          "word the scan cannot read in %s", f->path);
    if (v == CM_LIVE_BODY)
        return cm_body_at(c, f, t->s, i, t->n);
    return v == CM_LIVE_EXEMPT || cm_cond_at(c, f, t, i);
}

/* One file, repo or system: a system header's own conditionals search the
 * -I dirs too (an angled search starts there), so a repo dir gaining a
 * name can flip them. */
static bool cm_scan_file(struct cm_core *c, const struct cm_file *f,
                         struct cm_lang lang)
{
    bool ok;
    struct cm_spliced t;
    uint8_t *code = NULL;
    if (f->size == 0)
        return true;
    if (f->live == NULL)
        return cm_fail(c, "%s was not tokenized", f->path);
    ok = cm_splice(f->contents, f->size, lang.trigraphs, &t);
    if (!ok)
        (void)cm_fail(c, "cannot splice %s", f->path);
    else if ((code = cm_code_of(f, &t)) == NULL)
        ok = cm_fail(c, "out of memory");
    for (size_t i = 0; ok && i < t.n; i++)
        if (code[i] != CM_LIVE_NONE)
            ok = cm_token_at(c, f, &t, i, code[i]);
    free(code);
    cm_spliced_free(&t);
    return ok && cm_floor_file(c, f);
}

bool cm_scan_has_include(struct cm_core *c, const char *const *argv,
                         size_t argc, struct cm_lang lang)
{
    const struct cm_file *main = cm_main_file(c);
    char name[PATH_MAX];
    if (main == NULL)
        return cm_fail(c, "no main file");
    if (!cm_scan_argv(c, main, argv, argc))
        return false;
    for (size_t k = 0; k < c->nfiles; k++)
        if (!cm_scan_file(c, &c->files[k], lang))
            return false;
    if (c->paste_piece == NULL)
        return true;
    (void)snprintf(name, sizeof(name), "#embed? pasted from %.*s",
                   CM_COND_NAME_MAX, c->paste_piece);
    return cm_cond_unbound(c, main, name, VCS_SEMANTIC_FORM_V1_QUOTED);
}
