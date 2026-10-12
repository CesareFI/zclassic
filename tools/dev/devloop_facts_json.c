/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: dev.change.plan facts input: load before/after manifest evidence from a facts directory and render the narrowed plan with its verdict. */
#include "devloop_facts.h"

#include "base/hex.h"
#include "sha3/sha3.h"
#include "util/safe_alloc.h"
#include "vcs/semantic_manifest.h"
#include "zutf8/zutf8.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Evidence files are bounded: a manifest by the format's own ceiling, a
 * source by the same 16 MiB the facts section cap uses. */
#define FX_SOURCE_MAX (16u * 1024u * 1024u)

/* The facts object of one reply: the verdict, obligations and universe
 * summary, then as many TU entries as fit, so the whole reply stays inside
 * the dev.change.plan contract budget. A reader pages the rest with
 * "facts_offset". */
#define FX_TUS_PAGE 3584u
#define FX_GROUPS_PAGE 1536u
#define FX_GUARDS_PAGE 6144u
#define FX_ENTRY_MAX (ZCL_DEVLOOP_PATH_MAX * 2u + 1024u)
#define FX_CONSUMER_SCHEMA "zcl.semantic_consumer.v1"

bool zcl_devloop_facts_read(const char *root, const char *dir, const char *file,
                            const char *suffix, size_t max, uint8_t **out,
                            size_t *len)
{
    char path[ZCL_DEVLOOP_PATH_MAX * 2 + 64];
    FILE *fp;
    long size;
    bool ok = false;
    *out = NULL;
    *len = 0;
    if (snprintf(path, sizeof(path), "%s/%s%s%s%s", root, dir ? dir : "",
                 dir ? "/" : "", file, suffix) >= (int)sizeof(path))
        return false;
    fp = fopen(path, "rb");
    if (fp == NULL)
        return false;
    if (fseek(fp, 0, SEEK_END) == 0 && (size = ftell(fp)) >= 0 &&
        (size_t)size <= max && fseek(fp, 0, SEEK_SET) == 0) {
        *out = zcl_malloc((size_t)size + 1, "facts.evidence");
        ok = *out != NULL &&
             fread(*out, 1, (size_t)size, fp) == (size_t)size;
        *len = (size_t)size;
        if (ok)
            (*out)[size] = 0;
    }
    (void)fclose(fp);
    if (!ok) {
        free(*out);
        *out = NULL;
    }
    return ok;
}

/* A file whose evidence is incomplete gets no entry; the decision then
 * names it ("no-manifest"). */
static void fx_load(const char *root, const char *dir, const char *file,
                    struct zcl_devloop_facts_tu *tu)
{
    uint8_t *b = NULL, *a = NULL, *bs = NULL, *as = NULL;
    bool ok = zcl_devloop_facts_read(root, dir, file, ".before.zsm",
                      VCS_SEMANTIC_MANIFEST_V1_MAX_BYTES, &b,
                      &tu->before_len) &&
              zcl_devloop_facts_read(root, dir, file, ".after.zsm",
                      VCS_SEMANTIC_MANIFEST_V1_MAX_BYTES, &a,
                      &tu->after_len) &&
              zcl_devloop_facts_read(root, dir, file, ".before", FX_SOURCE_MAX, &bs,
                      &tu->before_src_len) &&
              zcl_devloop_facts_read(root, NULL, file, "", FX_SOURCE_MAX, &as,
                      &tu->after_src_len);
    if (!ok) {
        free(b);
        free(a);
        free(bs);
        free(as);
        memset(tu, 0, sizeof(*tu));
        return;
    }
    tu->source = file;
    tu->before = b;
    tu->after = a;
    tu->before_src = bs;
    tu->after_src = as;
}

static void fx_unload(struct zcl_devloop_facts_tu *tu)
{
    free((void *)tu->before);
    free((void *)tu->after);
    free((void *)tu->before_src);
    free((void *)tu->after_src);
}

/* A bounded JSON writer: the first write that does not fit stops it, and
 * every later write is a no-op, so a render checks `ok` once at the end. */
struct fxw {
    char *out;
    size_t cap, at;
    bool ok;
};

static void fw_raw(struct fxw *w, const char *s)
{
    size_t n = strlen(s);
    if (!w->ok || w->at + n >= w->cap) {
        w->ok = false;
        return;
    }
    memcpy(w->out + w->at, s, n);
    w->at += n;
    w->out[w->at] = '\0';
}

static void fw_str(struct fxw *w, const char *s)
{
    char esc[8];
    fw_raw(w, "\"");
    for (const unsigned char *p = (const unsigned char *)s; w->ok && *p; p++) {
        if (*p == '"' || *p == '\\')
            (void)snprintf(esc, sizeof(esc), "\\%c", *p);
        else if (*p < 0x20)
            (void)snprintf(esc, sizeof(esc), "\\u%04x", *p);
        else
            (void)snprintf(esc, sizeof(esc), "%c", *p);
        fw_raw(w, esc);
    }
    fw_raw(w, "\"");
}

/* ,"key": the comma is left out right after an opening brace or bracket
 * (an empty writer takes one: it renders a fragment spliced after others). */
static void fw_key(struct fxw *w, const char *key)
{
    size_t at = w->at;
    bool first = at > 0 && (w->out[at - 1] == '{' || w->out[at - 1] == '[');
    if (!first)
        fw_raw(w, ",");
    fw_str(w, key);
    fw_raw(w, ":");
}

static void fw_kstr(struct fxw *w, const char *key, const char *v)
{
    fw_key(w, key);
    fw_str(w, v ? v : "");
}

static void fw_kbool(struct fxw *w, const char *key, bool v)
{
    fw_key(w, key);
    fw_raw(w, v ? "true" : "false");
}

static void fw_knum(struct fxw *w, const char *key, size_t v)
{
    char num[32];
    (void)snprintf(num, sizeof(num), "%zu", v);
    fw_key(w, key);
    fw_raw(w, num);
}

static void fw_khex(struct fxw *w, const char *key, bool has,
                    const uint8_t d[32])
{
    char hex[65];
    fw_key(w, key);
    if (!has) {
        fw_raw(w, "null");
        return;
    }
    zcl_hex_encode(d, 32, hex);
    fw_str(w, hex);
}

/* "narrowed":B,"reason":S,"detail":S,"seeds":[S...],"seeds_total":N,
 * "reached_files":N */
static void fx_verdict_json(const struct zcl_devloop_facts_verdict *v,
                            struct fxw *w)
{
    fw_kbool(w, "narrowed", v->narrowed);
    fw_kstr(w, "reason", v->reason);
    fw_kstr(w, "detail", v->detail);
    fw_key(w, "seeds");
    fw_raw(w, "[");
    for (size_t k = 0; k < v->seeds_len; k++) {
        if (k > 0)
            fw_raw(w, ",");
        fw_str(w, v->seeds[k]);
    }
    fw_raw(w, "]");
    fw_knum(w, "seeds_total", v->seeds_total);
    fw_knum(w, "reached_files", v->reached_files);
}

/* The digest of the whole universe listing, so a paged reader can tell the
 * pages it joined describe one computation. */
static void fx_universe_digest(const struct zcl_devloop_facts_report *r,
                               uint8_t out[32])
{
    struct sha3_256_ctx h;
    static const char domain[] = "zcl.semantic_consumer.universe.v1";
    sha3_256_init(&h);
    sha3_256_write(&h, (const unsigned char *)domain, sizeof(domain));
    for (size_t k = 0; k < r->ntus; k++) {
        const struct zcl_devloop_facts_tu_verdict *t = &r->tus[k];
        uint8_t flags[3] = {t->affected, t->broadened, t->has_roots};
        sha3_256_write(&h, (const unsigned char *)t->path, strlen(t->path) + 1);
        sha3_256_write(&h, (const unsigned char *)t->reason,
                       strlen(t->reason) + 1);
        sha3_256_write(&h, flags, sizeof(flags));
        sha3_256_write(&h, t->interface, 32);
        sha3_256_write(&h, t->implementation, 32);
    }
    sha3_256_finalize(&h, out);
}

static void fx_tu_json(const struct zcl_devloop_facts_tu_verdict *t,
                       struct fxw *w)
{
    fw_raw(w, "{");
    fw_kstr(w, "path", t->path);
    fw_khex(w, "source", t->has_roots, t->source);
    fw_khex(w, "fact", t->has_roots, t->fact);
    fw_khex(w, "interface", t->has_roots, t->interface);
    fw_khex(w, "implementation", t->has_roots, t->implementation);
    fw_khex(w, "action", t->has_action, t->action);
    fw_kstr(w, "action_reason", t->action_reason);
    fw_khex(w, "artifact", t->has_artifact, t->artifact);
    fw_kstr(w, "artifact_reason",
            t->has_artifact ? "" : "artifact-evidence-absent");
    fw_kbool(w, "affected", t->affected);
    fw_kbool(w, "broadened", t->broadened);
    fw_kbool(w, "compile_only", t->compile_only);
    fw_kstr(w, "reason", t->reason);
    fw_kstr(w, "detail", t->detail);
    fw_raw(w, "}");
}

/* "tus":[...]: entries from `offset` while w stays under `limit` bytes,
 * and always the first, so each page advances; *listed counts them. */
static void fx_tus_json(const struct zcl_devloop_facts_report *r,
                        size_t offset, size_t limit, struct fxw *w,
                        size_t *listed)
{
    char *entry = zcl_malloc(FX_ENTRY_MAX, "facts.entry");
    *listed = 0;
    fw_key(w, "tus");
    fw_raw(w, "[");
    w->ok = w->ok && entry != NULL;
    for (size_t k = offset; w->ok && k < r->ntus; k++) {
        struct fxw e = {.out = entry, .cap = FX_ENTRY_MAX, .ok = true};
        fx_tu_json(&r->tus[k], &e);
        if (!e.ok) {
            w->ok = false; /* an entry that cannot render fails the reply */
            break;
        }
        if (*listed > 0 && w->at + e.at + 2 > limit)
            break; /* the first entry always lists, so paging advances */
        if (*listed > 0)
            fw_raw(w, ",");
        fw_raw(w, entry);
        *listed += w->ok;
    }
    free(entry);
    fw_raw(w, "]");
}

static void fx_universe_json(const struct zcl_devloop_facts_report *r,
                             size_t offset, size_t listed, struct fxw *w)
{
    uint8_t digest[32];
    fx_universe_digest(r, digest);
    fw_key(w, "universe");
    fw_raw(w, "{");
    fw_kbool(w, "applied", r->applied);
    fw_kbool(w, "complete", r->complete);
    fw_kstr(w, "reason", r->reason);
    fw_kstr(w, "detail", r->detail);
    fw_knum(w, "total", r->ntus);
    fw_knum(w, "affected", r->naffected);
    fw_knum(w, "offset", offset);
    fw_knum(w, "listed", listed);
    if (offset + listed < r->ntus)
        fw_knum(w, "next_offset", offset + listed);
    else {
        fw_key(w, "next_offset");
        fw_raw(w, "null");
    }
    fw_khex(w, "sha3", true, digest);
    fw_raw(w, "}");
}

/* One {"group","reason"} while the list stays under FX_GROUPS_PAGE bytes
 * from `start`; *listed counts those written. The first that does not fit
 * ends the list, so the listed groups are a prefix. */
static void fx_group_json(struct fxw *w, size_t start, size_t *listed,
                          bool *full, const char *group, const char *reason)
{
    *full = *full ||
            w->at - start + strlen(group) + strlen(reason ? reason : "") + 32 >
                FX_GROUPS_PAGE;
    if (*full)
        return;
    if (*listed > 0)
        fw_raw(w, ",");
    (*listed)++;
    fw_raw(w, "{");
    fw_kstr(w, "group", group);
    fw_kstr(w, "reason", reason);
    fw_raw(w, "}");
}

/* "obligations":{"reason":S,"plain":N,"plain_universal":B,"facts":N,
 *  "groups":[{"group":S,"reason":S}...],"groups_listed":N}: every path
 * group, then every closure group with the rule that reached it, as many
 * as fit FX_GROUPS_PAGE ("facts" is the total). */
static void fx_obligations_json(const struct zcl_devloop_facts_report *r,
                                const struct zcl_devloop_plan *p,
                                struct fxw *w)
{
    size_t start, listed = 0;
    bool full = false;
    fw_key(w, "obligations");
    fw_raw(w, "{");
    fw_kstr(w, "reason", r->obligations_reason);
    fw_knum(w, "plain", r->plain_groups);
    fw_kbool(w, "plain_universal", r->plain_universal);
    fw_knum(w, "facts", p->path_groups_len + p->closure_groups_len);
    fw_key(w, "groups");
    fw_raw(w, "[");
    start = w->at;
    for (size_t k = 0; k < p->path_groups_len; k++)
        fx_group_json(w, start, &listed, &full, p->path_groups[k], r->path_reason);
    for (size_t k = 0; k < p->closure_groups_len; k++)
        fx_group_json(w, start, &listed, &full, p->closure_groups[k],
                      r->group_reason[k]);
    fw_raw(w, "]");
    fw_knum(w, "groups_listed", listed);
    fw_raw(w, "}");
}

static const struct {
    unsigned bit;
    const char *name, *reads;
} fx_premises[] = {
    {ZCL_DEVLOOP_PREMISE_NO_REPAIR_GOAL, "no-repair-goal",
     "no goal on the make command line is vendor-ready, deploy or install"},
    {ZCL_DEVLOOP_PREMISE_EPOCH_ONE_COMPONENT, "epoch-one-component",
     "the compile epoch $(call zcl_compile_epoch,...) computes with $(shell) "
     "is one path component, or none"},
    {ZCL_DEVLOOP_PREMISE_BUILD_READS_PLANNED_TREE, "build-reads-planned-tree",
     "the build reads the tree the plan globbed, and an include that exists "
     "under build/ is current"},
    {ZCL_DEVLOOP_PREMISE_NO_COMMAND_LINE_OVERRIDE, "no-command-line-override",
     "no command-line or make -e environment value overrides a variable the "
     "makefile sets with = or :="},
    {ZCL_DEVLOOP_PREMISE_PARSE_COMMANDS_NO_INCLUDE_WRITES,
     "parse-commands-no-include-writes",
     "a command make runs as it reads the makefiles that is not provably "
     "read-only (a script, a program, any shell text) creates or rewrites no "
     "include make reads and no path a skip globbed"},
    {ZCL_DEVLOOP_PREMISE_COMPUTED_TARGETS_NOT_INCLUDES,
     "computed-targets-not-includes",
     "a rule whose targets a function or a value no text spells computes, "
     "and whose text names no missing optional include, makes none"},
    {ZCL_DEVLOOP_PREMISE_HOST_TARGET_DEFAULT_TOR, "host-target-default-tor",
     "ZCL_TARGET and ZCL_TOR hold their makefile defaults (host, full): no "
     "command-line, environment or make -e value sets them"},
};

static void fx_premise_names(unsigned bits, struct fxw *w)
{
    bool first = true;
    fw_raw(w, "[");
    for (size_t k = 0; k < sizeof(fx_premises) / sizeof(fx_premises[0]); k++)
        if (bits & fx_premises[k].bit) {
            fw_raw(w, first ? "" : ",");
            fw_str(w, fx_premises[k].name);
            first = false;
        }
    fw_raw(w, "]");
}

/* A space-separated list as a JSON array of its words. */
static void fx_words_json(const char *s, struct fxw *w)
{
    char word[ZCL_DEVLOOP_GUARD_TEXT];
    bool first = true;
    fw_raw(w, "[");
    while (*s != '\0') {
        size_t n = strcspn(s, " ");
        if (n > 0 && n < sizeof(word)) {
            memcpy(word, s, n);
            word[n] = '\0';
            fw_raw(w, first ? "" : ",");
            fw_str(w, word);
            first = false;
        }
        s += n + (s[n] == ' ');
    }
    fw_raw(w, "]");
}

/* A bound on one guard's rendering. */
static size_t fx_guard_size(const struct zcl_devloop_facts_guard *g)
{
    size_t n = strlen(g->include) + strlen(g->include_at) +
               2 * strlen(g->guard) + strlen(g->guard_at) + 256;
    for (size_t k = 0; k < g->nglobs; k++)
        n += strlen(g->glob[k]) + strlen(g->found[k]) + 48;
    return n;
}

static void fx_guard_json(const struct zcl_devloop_facts_guard *g,
                          struct fxw *w)
{
    fw_raw(w, "{");
    fw_kstr(w, "include", g->include);
    fw_kstr(w, "include_at", g->include_at);
    fw_kstr(w, "guard", g->guard);
    fw_kstr(w, "guard_at", g->guard_at);
    fw_key(w, "premises");
    fx_premise_names(g->premises, w);
    fw_key(w, "globbed");
    fw_raw(w, "[");
    for (size_t k = 0; k < g->nglobs; k++) {
        fw_raw(w, k > 0 ? ",{" : "{");
        fw_kstr(w, "path", g->glob[k]);
        fw_key(w, "found");
        fx_words_json(g->found[k], w);
        fw_raw(w, "}");
    }
    fw_raw(w, "]}");
}

/* "plan":{premises,include,includes,skips,existing,command,command_at,
 * commands,target,target_at,targets}: what the whole make reading rests
 * on, beyond each skip. */
static void fx_plan_premise_json(const struct zcl_devloop_facts_plan_premise *p,
                                 struct fxw *w)
{
    fw_key(w, "plan");
    fw_raw(w, "{");
    fw_key(w, "premises");
    fx_premise_names(p->premises, w);
    fw_kstr(w, "include", p->include);
    fw_knum(w, "includes", p->nincludes);
    fw_knum(w, "skips", p->nskips);
    fw_knum(w, "existing", p->nexisting);
    fw_kstr(w, "command", p->command);
    fw_kstr(w, "command_at", p->command_at);
    fw_knum(w, "commands", p->ncommands);
    fw_kstr(w, "target", p->target);
    fw_kstr(w, "target_at", p->target_at);
    fw_knum(w, "targets", p->ntargets);
    fw_raw(w, "}");
}

/* "make_guards":{"premises":[{"name","reads"}...],"skipped":[...],
 * "skipped_total":N,"skipped_listed":N,"plan":{...}}: the named premises a
 * guard reading may rest on, each missing include the root makefile
 * provably skips with the directive read not taken, the premises it used
 * and every path it globbed, as many as fit FX_GUARDS_PAGE, and the
 * premises the whole reading rests on. */
static void fx_guards_json(const struct zcl_devloop_facts_report *r,
                           struct fxw *w)
{
    size_t start, listed = 0;
    fw_key(w, "make_guards");
    fw_raw(w, "{");
    fw_key(w, "premises");
    fw_raw(w, "[");
    for (size_t k = 0; k < sizeof(fx_premises) / sizeof(fx_premises[0]); k++) {
        fw_raw(w, k > 0 ? ",{" : "{");
        fw_kstr(w, "name", fx_premises[k].name);
        fw_kstr(w, "reads", fx_premises[k].reads);
        fw_raw(w, "}");
    }
    fw_raw(w, "]");
    fw_key(w, "skipped");
    fw_raw(w, "[");
    start = w->at;
    for (; listed < r->nguards &&
           w->at - start + fx_guard_size(&r->guards[listed]) <= FX_GUARDS_PAGE;
         listed++) {
        fw_raw(w, listed > 0 ? "," : "");
        fx_guard_json(&r->guards[listed], w);
    }
    fw_raw(w, "]");
    fw_knum(w, "skipped_total", r->nguards);
    fw_knum(w, "skipped_listed", listed);
    fx_plan_premise_json(&r->make_premise, w);
    fw_raw(w, "}");
}

/* ,"facts":{verdict,"consumer":S,obligations,universe,make_guards,tus}}
 * closing the plan document. The universe summary names how many entries
 * follow, so the entries render aside first against what remains of the
 * page. */
static bool fx_facts_json(const struct zcl_devloop_facts_verdict *v,
                          const struct zcl_devloop_facts_report *r,
                          const struct zcl_devloop_plan *p, size_t offset,
                          struct fxw *w)
{
    size_t listed = 0;
    struct fxw t = {.out = zcl_malloc(w->cap, "facts.tus_json"),
                    .cap = w->cap, .ok = true};
    t.ok = t.out != NULL;
    fw_raw(w, ",\"facts\":{");
    fx_verdict_json(v, w);
    fw_kstr(w, "consumer", FX_CONSUMER_SCHEMA);
    fx_obligations_json(r, p, w);
    if (offset < r->ntus)
        fx_tus_json(r, offset, FX_TUS_PAGE, &t, &listed);
    else
        fw_raw(&t, ",\"tus\":[]");
    fx_universe_json(r, offset, listed, w);
    fx_guards_json(r, w);
    fw_raw(w, t.ok ? t.out : "");
    w->ok = w->ok && t.ok;
    fw_raw(w, "}}");
    free(t.out);
    /* Include the plan prefix, not only strings emitted by this writer. */
    if (w->ok && !zutf8_validate_n(w->out, w->at))
        w->ok = false;
    if (!w->ok) w->out[0] = '\0';
    return w->ok;
}

#ifdef ZCL_TESTING
bool zcl_devloop_test_facts_json(const struct zcl_devloop_facts_report *r,
                                const struct zcl_devloop_plan *p,
                                char *out, size_t out_sz)
{
    if (out != NULL && out_sz > 0) out[0] = '\0';
    if (r == NULL || p == NULL || out == NULL || out_sz == 0) return false;
    struct fxw w = {.out = out, .cap = out_sz, .ok = true};
    struct zcl_devloop_facts_verdict v = {.reason = ""};
    fw_raw(&w, "{\"fixture\":true");
    return fx_facts_json(&v, r, p, 0, &w);
}
#endif

/* Plan with the facts evidence and render the plan document with the
 * facts object spliced in before its closing brace; 0 on any failure. */
static size_t fx_render(const char *root, const char *const *files,
                        size_t file_count, const char *facts_dir,
                        size_t offset, struct zcl_devloop_plan *plan,
                        struct zcl_devloop_facts_tu *tus,
                        struct zcl_devloop_facts_verdict *v, char *out,
                        size_t out_sz)
{
    struct zcl_devloop_facts_report report = {0};
    bool all_c = file_count > 0, ok;
    size_t n;
    if (!zcl_devloop_plan_files(files, file_count, plan))
        return 0;
    for (size_t k = 0; k < file_count; k++) {
        size_t len = strlen(files[k]);
        all_c = all_c && len > 2 && strcmp(files[k] + len - 2, ".c") == 0;
    }
    for (size_t k = 0; all_c && k < file_count; k++)
        fx_load(root, facts_dir, files[k], &tus[k]);
    ok = zcl_devloop_facts_consume(root, files, file_count, facts_dir,
                                   all_c ? tus : NULL, plan, v, &report);
    n = ok ? zcl_devloop_plan_json_render(plan, files, file_count, out, out_sz)
           : 0;
    if (n == 0 || out[n - 1] != '}') {
        zcl_devloop_facts_report_free(&report);
        return 0;
    }
    n--;
    out[n] = '\0';
    {
        struct fxw w = {.out = out, .cap = out_sz, .at = n, .ok = true};
        ok = fx_facts_json(v, &report, plan, offset, &w);
        n = w.at;
    }
    zcl_devloop_facts_report_free(&report);
    return ok ? n : 0;
}

size_t zcl_devloop_plan_json_facts(const char *repo_root,
                                   const char *const *files, size_t file_count,
                                   const char *facts_dir, size_t tu_offset,
                                   char *out, size_t out_sz)
{
    const char *root = repo_root && repo_root[0] ? repo_root : ".";
    struct zcl_devloop_plan *plan = zcl_malloc(sizeof(*plan), "facts.plan");
    struct zcl_devloop_facts_tu *tus =
        zcl_calloc(file_count ? file_count : 1, sizeof(*tus), "facts.tus");
    struct zcl_devloop_facts_verdict *v = zcl_malloc(sizeof(*v), "facts.v");
    bool ok = plan && tus && v && out && out_sz > 0 && facts_dir;
    size_t n = ok ? fx_render(root, files, file_count, facts_dir, tu_offset,
                              plan, tus, v, out, out_sz)
                  : 0;
    for (size_t k = 0; tus && k < file_count; k++)
        fx_unload(&tus[k]);
    free(tus);
    free(plan);
    free(v);
    return n;
}
