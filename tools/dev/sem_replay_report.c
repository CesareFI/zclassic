/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * z23-sem-replay report: the per-commit table, totals, totals by change
 * kind, the fallback reasons ranked by what precision would save, and the
 * sensor's cost against the compile CPU of each plan's set. Reads
 * <state>/run/<NN>_<commit>/result.tsv, sets.tsv and tasks.tsv, and prices
 * each TU from catalog_cost.tsv, then compile_cost.tsv; writes Markdown to
 * stdout. */
#include "base/safe_alloc.h"
#include "sem_replay_record.h"

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sem_replay.h"
#include "sem_replay_step.h"


/* ── pricing: every compile set in CPU seconds ────────────────────────── */

/* The sets a commit's sets.tsv names that the report prices. */
enum { P_MAKE, P_CHANGED, P_PLAIN, P_FACTS, P_CFACTS, P_N };
static const char *const price_set[P_N] = {"make", "changed", "plain", "facts", "c_facts"};

struct price_row {
    char *tu;
    double cpu;
    size_t n;
};

struct prices {
    struct price_row *v;
    size_t n, cap;
    double mean; /* over the catalog, else over the timed compiles */
};

static int cmp_price(const void *a, const void *b)
{
    return strcmp(((const struct price_row *)a)->tu, ((const struct price_row *)b)->tu);
}

static bool price_push(struct prices *p, const char *tu, double cpu)
{
    if (p->n == p->cap) {
        if (p->cap > SIZE_MAX / 2 ||
            (p->cap ? p->cap * 2 : 4096) > SIZE_MAX / sizeof(*p->v)) {
            fprintf(stderr, "sem-replay: price table capacity overflow\n");
            return false;
        }
        size_t cap = p->cap ? p->cap * 2 : 4096;
        struct price_row *v = zcl_realloc(p->v, cap * sizeof(*v), "sem_replay_price_row");
        if (v == NULL) {
            fprintf(stderr, "sem-replay: out of memory in the price table\n");
            return false;
        }
        p->v = v;
        p->cap = cap;
    }
    char *dup = zcl_strdup(tu, "sem_replay_price_tu");
    if (dup == NULL) {
        fprintf(stderr, "sem-replay: out of memory in the price table\n");
        return false;
    }
    p->v[p->n] = (struct price_row){.tu = dup, .cpu = cpu, .n = 1};
    p->n++;
    return true;
}

static void prices_average(struct prices *p)
{
    double sum = 0;
    if (p->n > 1)
        qsort(p->v, p->n, sizeof(*p->v), cmp_price);
    size_t w = 0;
    for (size_t i = 0; i < p->n; i++) {
        sum += p->v[i].cpu;
        if (w > 0 && strcmp(p->v[w - 1].tu, p->v[i].tu) == 0) {
            p->v[w - 1].cpu += p->v[i].cpu;
            p->v[w - 1].n++;
            free(p->v[i].tu);
            continue;
        }
        p->v[w++] = p->v[i];
    }
    p->mean = p->n ? sum / (double)p->n : 0;
    p->n = w;
    for (size_t i = 0; i < p->n; i++)
        p->v[i].cpu /= (double)p->v[i].n;
}

/* Rows "TU<TAB>cpu..." averaged per TU, sorted for lookup. */
static bool prices_load(struct prices *p, const char *path)
{
    FILE *fp = fopen(path, "r");
    char line[SR_PATH + 128], *tu;
    double cpu = 0;
    bool ok = true;
    int record = 0;
    while (fp != NULL && ok && (record = sr_record(fp, line, sizeof line)) > 0)
        ok = sr_record_cost(line, &tu, &cpu) && price_push(p, tu, cpu);
    if (record < 0)
        ok = false;
    if (fp != NULL && fclose(fp) != 0)
        ok = false;
    if (!ok)
        fprintf(stderr, "sem-replay: malformed cost record %s\n", path);
    prices_average(p);
    return ok;
}

static const struct price_row *price_find(const struct prices *p, const char *tu)
{
    struct price_row key = {.tu = (char *)tu};
    return p->n ? bsearch(&key, p->v, p->n, sizeof(*p->v), cmp_price) : NULL;
}

static void prices_free(struct prices *p)
{
    for (size_t i = 0; i < p->n; i++)
        free(p->v[i].tu);
    free(p->v);
    memset(p, 0, sizeof(*p));
}

/* The catalog's cold compile of the TU, else its timed compiles in the
 * replay, else the mean. */
struct pricing {
    struct prices catalog, timed;
    double mean;
    size_t guessed; /* lookups that fell back to the mean */
};

static double price_of(struct pricing *pr, const char *tu)
{
    const struct price_row *r = price_find(&pr->catalog, tu);
    if (r == NULL)
        r = price_find(&pr->timed, tu);
    pr->guessed += r == NULL;
    return r ? r->cpu : pr->mean;
}

static bool pricing_load(struct pricing *pr, const char *state)
{
    char path[SR_PATH];
    snprintf(path, sizeof(path), "%s/catalog_cost.tsv", state);
    bool ok = prices_load(&pr->catalog, path);
    snprintf(path, sizeof(path), "%s/compile_cost.tsv", state);
    ok = ok && prices_load(&pr->timed, path);
    pr->mean = pr->catalog.n ? pr->catalog.mean : pr->timed.mean;
    return ok;
}

static void price_sets(struct pricing *pr, const char *file, double out[P_N])
{
    FILE *fp = fopen(file, "r");
    char line[SR_PATH + 64], set[32], tu[SR_PATH];
    memset(out, 0, P_N * sizeof(double));
    while (fp && fgets(line, sizeof(line), fp) != NULL) {
        if (sscanf(line, "%31s\t%4095s", set, tu) != 2)
            continue;
        for (int k = 0; k < P_N; k++)
            if (strcmp(set, price_set[k]) == 0)
                out[k] += price_of(pr, tu);
    }
    if (fp)
        fclose(fp);
}

#define SR_COLS 128

struct row {
    char *line;
    char *f[SR_COLS];
    size_t n;
    double p[P_N]; /* priced compile sets, CPU s */
};

struct table {
    char *head_line;
    char *h[SR_COLS];
    size_t nh;
    struct row *rows;
    size_t n, cap;
};

static size_t split_tabs(char *line, char **f)
{
    size_t n = 0;
    line[strcspn(line, "\n")] = '\0';
    for (char *p = line; p; n++) {
        if (n == SR_COLS)
            return 0;
        f[n] = p;
        p = strchr(p, '\t');
        if (p)
            *p++ = '\0';
    }
    return n;
}

static const char *col(const struct table *t, const struct row *r, const char *name)
{
    for (size_t i = 0; i < t->nh && i < r->n; i++)
        if (strcmp(t->h[i], name) == 0)
            return r->f[i];
    return "";
}

static double num(const struct table *t, const struct row *r, const char *name)
{
    return strtod(col(t, r, name), NULL);
}

/* Exactly a header and one complete data record, with optional final LF. */
static bool table_frame(char *text, size_t len)
{
    if (memchr(text, '\0', len) != NULL)
        return false;
    char *nl = strchr(text, '\n');
    if (nl == NULL)
        return false;
    char *end = memchr(nl + 1, '\n', len - (size_t)(nl + 1 - text));
    if (nl + 1 == text + len || (end && end != text + len - 1))
        return false;
    return true;
}

static size_t table_header_width(const char *text)
{
    size_t n = 1;
    for (const char *p = text; *p; p++) {
        if (*p == '\t' && ++n > SR_COLS)
            return 0;
    }
    return n;
}

static bool table_add(struct table *t, char *text, size_t len)
{
    if (!table_frame(text, len))
        return false;
    char *nl = strchr(text, '\n');
    *nl = '\0';
    size_t local_nh = table_header_width(text);
    if (local_nh == 0 || (t->head_line != NULL && local_nh != t->nh))
        return false;
    if (t->head_line == NULL) {
        t->head_line = zcl_strdup(text, "sem_replay_table_head");
        if (t->head_line == NULL)
            return false;
        t->nh = split_tabs(t->head_line, t->h);
        if (t->nh == 0)
            return false;
    }
    if (t->n == t->cap) {
        size_t cap = t->cap ? t->cap * 2 : 64;
        struct row *v = zcl_realloc(t->rows, cap * sizeof(*v), "sem_replay_report_row");
        if (v == NULL)
            return false;
        t->rows = v;
        t->cap = cap;
    }
    struct row *r = &t->rows[t->n];
    r->line = zcl_strdup(nl + 1, "sem_replay_table_row");
    if (r->line == NULL)
        return false;
    r->n = split_tabs(r->line, r->f);
    t->n++;
    if (r->n == 0 || r->n != t->nh)
        return false;
    return true;
}

static int cmp_name(const void *a, const void *b)
{
    return strcmp(*(char *const *)a, *(char *const *)b);
}

static bool load_runs(const char *state, struct pricing *pr, struct table *t,
                      struct sr_strv *dirs)
{
    char path[SR_PATH];
    snprintf(path, sizeof(path), "%s/run", state);
    DIR *d = opendir(path);
    if (d == NULL) {
        fprintf(stderr, "sem-replay: no runs under %s\n", path);
        return false;
    }
    struct dirent *e;
    while ((e = readdir(d)) != NULL)
        if (e->d_name[0] != '.')
            (void)sr_strv_push(dirs, e->d_name);
    closedir(d);
    if (dirs->n > 1)
        qsort(dirs->v, dirs->n, sizeof(char *), cmp_name);
    for (size_t i = 0; i < dirs->n; i++) {
        char file[SR_PATH], *text = NULL;
        size_t len = 0;
        snprintf(file, sizeof(file), "%s/%s/result.tsv", path, dirs->v[i]);
        size_t before = t->n;
        bool read_ok = sr_read_file(file, &text, &len);
        if (!read_ok && errno == ENOENT)
            continue; /* A run without a published result is not yet complete. */
        bool malformed = !read_ok || !table_add(t, text, len);
        if (malformed)
            fprintf(stderr, "sem-replay: malformed %s\n", file);
        free(text);
        if (malformed)
            return false;
        if (t->n == before)
            continue;
        snprintf(file, sizeof(file), "%s/%s/sets.tsv", path, dirs->v[i]);
        price_sets(pr, file, t->rows[t->n - 1].p);
    }
    return true;
}

static bool is_one(const struct table *t, const struct row *r, const char *name)
{
    return strcmp(col(t, r, name), "1") == 0;
}

/* A step whose build failed: its misses are reported but did not stop the run. */
static const char *failed_note(const struct table *t, const struct row *r)
{
    static const char *const note[] = {"", " (after build failed)", " (parent build failed)",
                                       " (both builds failed)"};
    int f = atoi(col(t, r, "build_failed"));
    return note[f >= 0 && f <= 3 ? f : 3];
}

static void print_commits(const struct table *t)
{
    printf("## Per commit\n\n");
    printf("Compile counts are TUs; CPU is priced per TU (see Pricing). changed splits into "
           "code (objects differ after objcopy --strip-debug) and debug (only debug sections "
           "differ). Misses are changed objects the facts compile set left out: code, "
           "debug-only, and argv (the identity-stamped TU, whose compile argv changes every "
           "commit).\n\n");
    printf("Groups are catalog test groups, the execution set each plan runs "
           "(execution_groups_total). Tokens are the plan's own group entries (path and "
           "closure groups; the facts plan's are its obligations): one token may expand to "
           "several catalog groups, so tokens and groups are different units and only "
           "compare within a column.\n\n");
    printf("| # | commit | kind | files c/h/other | make | changed (code/debug) | plain | "
           "facts (mode) | misses code/debug/argv | groups plain / facts | tokens plain / facts | "
           "verdict | sensor CPU s | compile CPU make / plain / facts / changed s |\n");
    printf("|---|---|---|---|---|---|---|---|---|---|---|---|---|---|\n");
    for (size_t i = 0; i < t->n; i++) {
        const struct row *r = &t->rows[i];
        printf("| %s | %s | %s%s | %s/%s/%s | %s | %s (%s/%s) | %s | %s (%s) | %s/%s/%s | "
               "%s / %s | %s / %s | %s | %.1f | %.1f / %.1f / %.1f / %.1f |\n",
               col(t, r, "idx"), col(t, r, "commit"), col(t, r, "kind"), failed_note(t, r), col(t, r, "c"),
               col(t, r, "h"), col(t, r, "other"), col(t, r, "make"), col(t, r, "changed"),
               col(t, r, "code_changed"), col(t, r, "debug_changed"), col(t, r, "plain"),
               col(t, r, "facts"), col(t, r, "facts_mode"), col(t, r, "fn_code"),
               col(t, r, "fn_debug"), col(t, r, "fn_flags"), col(t, r, "groups_plain"),
               col(t, r, "groups_facts"), col(t, r, "obl_plain"), col(t, r, "obl_facts"),
               is_one(t, r, "narrowed") ? "narrowed" : col(t, r, "reason"),
               num(t, r, "sense_cpu"), r->p[P_MAKE], r->p[P_PLAIN], r->p[P_FACTS],
               r->p[P_CHANGED]);
    }
    printf("\n");
}

struct agg {
    char name[128];
    size_t commits, narrowed, precise;
    double make, changed, code, debug, plain, facts, fn_code, fn_debug, fn_flags;
    double gplain, gfacts, oplain, obl, sense, fw_facts, fw_plain;
    double p[P_N];
};

static void agg_add(struct agg *a, const struct table *t, const struct row *r)
{
    static const char *const cols[] = {"make", "changed", "code_changed", "debug_changed",
                                       "plain", "facts", "fn_code", "fn_debug", "fn_flags",
                                       "groups_plain", "groups_facts", "obl_plain",
                                       "obl_facts", "sense_cpu", "fw_facts", "fw_plain"};
    double *dst[] = {&a->make, &a->changed, &a->code, &a->debug, &a->plain, &a->facts,
                     &a->fn_code, &a->fn_debug, &a->fn_flags, &a->gplain, &a->gfacts,
                     &a->oplain, &a->obl, &a->sense, &a->fw_facts, &a->fw_plain};
    a->commits++;
    a->narrowed += is_one(t, r, "narrowed");
    a->precise += strcmp(col(t, r, "facts_mode"), "precise") == 0;
    for (size_t k = 0; k < sizeof(cols) / sizeof(cols[0]); k++)
        *dst[k] += num(t, r, cols[k]);
    for (int k = 0; k < P_N; k++)
        a->p[k] += r->p[k];
}

static struct agg *agg_find(struct agg *v, size_t *n, size_t cap, const char *name)
{
    for (size_t i = 0; i < *n; i++)
        if (strcmp(v[i].name, name) == 0)
            return &v[i];
    if (*n == cap)
        return NULL;
    memset(&v[*n], 0, sizeof(v[*n]));
    snprintf(v[*n].name, sizeof(v[*n].name), "%s", name);
    return &v[(*n)++];
}

static void print_agg_row(const struct agg *a)
{
    printf("| %s | %zu | %zu / %zu | %.0f | %.0f (%.0f/%.0f) | %.0f | %.0f | %.0f/%.0f/%.0f | "
           "%.0f / %.0f | %.0f / %.0f | %.1f | %.1f / %.1f / %.1f / %.1f |\n",
           a->name, a->commits, a->narrowed, a->precise, a->make, a->changed, a->code, a->debug,
           a->plain, a->facts, a->fn_code, a->fn_debug, a->fn_flags, a->gplain, a->gfacts,
           a->oplain, a->obl, a->sense, a->p[P_MAKE], a->p[P_PLAIN], a->p[P_FACTS], a->p[P_CHANGED]);
}

/* The headline: what the facts plan avoided running, in total, against the
 * two baselines that matter — make's actual compile set and dev.change.plan
 * without the facts. Per-commit counts are in print_commits; this is the
 * one total worth reading first. */
static void print_headline(const struct table *t)
{
    struct agg total = {0};
    snprintf(total.name, sizeof(total.name), "**total**");
    for (size_t i = 0; i < t->n; i++)
        agg_add(&total, t, &t->rows[i]);
    printf("## Headline\n\n");
    printf("Compiler executions avoided vs make: %.0f (make compiled %.0f TUs, the facts plan "
           "%.0f).\n\n", total.make - total.facts, total.make, total.facts);
    printf("Test-group executions avoided vs plain: %.0f (plain selected %.0f groups, the facts "
           "plan %.0f).\n\n", total.gplain - total.gfacts, total.gplain, total.gfacts);
    printf("False-narrow (a changed object the facts plan left out; must be 0, fails the "
           "run): %.0f.\n\n", total.fn_code);
    printf("False-wide vs facts (a TU the facts plan compiled whose object bytes did not "
           "change): %.0f.\n\n", total.fw_facts);
    printf("False-wide vs plain (a TU the plain plan compiled whose object bytes did not "
           "change): %.0f.\n\n", total.fw_plain);
}

static void print_groups(const struct table *t, const char *key, const char *title)
{
    struct agg v[64];
    size_t n = 0;
    struct agg total = {0};
    snprintf(total.name, sizeof(total.name), "**total**");
    for (size_t i = 0; i < t->n; i++) {
        struct agg *a = agg_find(v, &n, 64, col(t, &t->rows[i], key));
        if (a)
            agg_add(a, t, &t->rows[i]);
        agg_add(&total, t, &t->rows[i]);
    }
    printf("## %s\n\n", title);
    printf("| %s | commits | narrowed / precise | make | changed (code/debug) | plain | facts | "
           "misses code/debug/argv | groups plain / facts | tokens plain / facts | sensor CPU s | "
           "compile CPU make / plain / facts / changed s |\n", key);
    printf("|---|---|---|---|---|---|---|---|---|---|---|---|\n");
    for (size_t i = 0; i < n; i++)
        print_agg_row(&v[i]);
    print_agg_row(&total);
    printf("\n");
}

/* What a precise plan could still remove: compile CPU (the facts set's
 * minus the changed objects'), and the catalog test groups the facts plan
 * runs beyond the plain plan's (both execution sets, one unit). */
static double waste_cpu(const struct agg *a)
{
    return a->p[P_FACTS] - a->p[P_CHANGED];
}

static double waste_groups(const struct agg *a)
{
    return a->gfacts - a->gplain;
}

static int cmp_waste_cpu(const void *a, const void *b)
{
    double x = waste_cpu(a), y = waste_cpu(b);
    return (x < y) - (x > y);
}

static int cmp_waste_groups(const void *a, const void *b)
{
    double x = waste_groups(a), y = waste_groups(b);
    return (x < y) - (x > y);
}

static void print_fallback_rows(struct agg *v, size_t n, int (*cmp)(const void *, const void *),
                                const char *title)
{
    qsort(v, n, sizeof(v[0]), cmp);
    printf("### %s\n\n", title);
    printf("| rank | reason | commits | facts TUs | changed TUs | compile CPU s precision could "
           "drop | groups facts / plain | tokens facts / plain | groups facts runs beyond plain |\n");
    printf("|---|---|---|---|---|---|---|---|---|\n");
    for (size_t i = 0; i < n; i++)
        printf("| %zu | %s | %zu | %.0f | %.0f | %.1f | %.0f / %.0f | %.0f / %.0f | %.0f |\n",
               i + 1, v[i].name, v[i].commits, v[i].facts, v[i].changed, waste_cpu(&v[i]),
               v[i].gfacts, v[i].gplain, v[i].obl, v[i].oplain, waste_groups(&v[i]));
    printf("\n");
}

static void print_fallbacks(const struct table *t, const char *reason_col, const char *title)
{
    struct agg v[64];
    size_t n = 0;
    for (size_t i = 0; i < t->n; i++) {
        const struct row *r = &t->rows[i];
        if (strcmp(col(t, r, "facts_mode"), "precise") == 0)
            continue;
        struct agg *a = agg_find(v, &n, 64, col(t, r, reason_col));
        if (a)
            agg_add(a, t, r);
    }
    printf("## %s\n\n", title);
    print_fallback_rows(v, n, cmp_waste_cpu, "Ranked by compile CPU");
    print_fallback_rows(v, n, cmp_waste_groups, "Ranked by test groups");
}

/* The same commits planned with only the inputs a compile reads. */
static void print_c_variant(const struct table *t)
{
    double facts = 0, fnc = 0, fnd = 0, fna = 0, gp = 0, gf = 0, obl = 0, cpu = 0;
    size_t precise = 0;
    printf("## Compiled-inputs variant (.c, .h and any changed path a depfile names)\n\n");
    printf("| # | commit | separate plan | files | facts (mode) | changed | misses code/debug/argv "
           "| groups plain / facts | tokens facts | verdict | compile CPU facts s |\n");
    printf("|---|---|---|---|---|---|---|---|---|---|---|\n");
    for (size_t i = 0; i < t->n; i++) {
        const struct row *r = &t->rows[i];
        double fn_argv = num(t, r, "c_fn") - num(t, r, "c_fn_source");
        printf("| %s | %s | %s | %s | %s (%s) | %s | %s/%s/%.0f | %s / %s | %s | %s | %.1f |\n",
               col(t, r, "idx"), col(t, r, "commit"), col(t, r, "c_run"), col(t, r, "c_files"),
               col(t, r, "c_facts"), col(t, r, "c_mode"), col(t, r, "changed"),
               col(t, r, "c_fn_code"), col(t, r, "c_fn_debug"), fn_argv,
               col(t, r, "c_groups_plain"), col(t, r, "c_groups_facts"), col(t, r, "c_obl_facts"),
               is_one(t, r, "c_narrowed") ? "narrowed" : col(t, r, "c_reason"), r->p[P_CFACTS]);
        precise += strcmp(col(t, r, "c_mode"), "precise") == 0;
        facts += num(t, r, "c_facts");
        fnc += num(t, r, "c_fn_code");
        fnd += num(t, r, "c_fn_debug");
        fna += fn_argv;
        gp += num(t, r, "c_groups_plain");
        gf += num(t, r, "c_groups_facts");
        obl += num(t, r, "c_obl_facts");
        cpu += r->p[P_CFACTS];
    }
    printf("| **total** | | %zu precise | | %.0f | | %.0f/%.0f/%.0f | %.0f / %.0f | %.0f | | %.1f |\n\n",
           precise, facts, fnc, fnd, fna, gp, gf, obl, cpu);
}

/* The sensor's cost for a full re-extraction (both sides of every TU that
 * reads a changed file) against incremental extraction (after side only,
 * over the TUs make rebuilt, the facts plan found affected, or whose
 * manifest bytes changed), and the compile CPU the facts plan saved. */
static void print_sensor(const struct table *t)
{
    static const char *const cols[] = {"sense_n", "sense_cpu", "sense_after_n",
                                       "sense_after_cpu", "sense_make_n", "sense_make_cpu",
                                       "sense_aff_n", "sense_aff_cpu", "sense_zsm_n",
                                       "sense_zsm_cpu"};
    double s[10] = {0}, saved = 0;
    for (size_t i = 0; i < t->n; i++) {
        const struct row *r = &t->rows[i];
        for (size_t k = 0; k < 10; k++)
            s[k] += num(t, r, cols[k]);
        saved += r->p[P_MAKE] - r->p[P_FACTS] > 0 ? r->p[P_MAKE] - r->p[P_FACTS] : 0;
    }
    printf("## Sensor cost against compile CPU saved\n\n");
    printf("| extraction | TUs sensed | sensor CPU s |\n|---|---|---|\n");
    printf("| full (before and after, every TU reading a changed file) | %.0f | %.1f |\n", s[0], s[1]);
    printf("| after side only, same TUs | %.0f | %.1f |\n", s[2], s[3]);
    printf("| after side, TUs make rebuilt | %.0f | %.1f |\n", s[4], s[5]);
    printf("| after side, TUs the facts plan found affected | %.0f | %.1f |\n", s[6], s[7]);
    printf("| after side, TUs whose manifest bytes changed | %.0f | %.1f |\n\n", s[8], s[9]);
    printf("Compile CPU the facts set saved against make, summed over commits where it was "
           "smaller: %.1f s.\n\n", saved);
}

static void print_pricing(const struct pricing *pr)
{
    printf("## Pricing\n\n");
    printf("A TU's compile CPU is its cold compile in the catalog (%zu TUs, mean %.3f s), "
           "else the mean of its timed compiles during the replay (%zu TUs, mean %.3f s), "
           "else the mean (%.3f s; %zu lookups).\n\n",
           pr->catalog.n, pr->catalog.mean, pr->timed.n, pr->timed.mean, pr->mean, pr->guessed);
}

static int cmp_double(const void *a, const void *b)
{
    double x = *(const double *)a, y = *(const double *)b;
    return (x > y) - (x < y);
}

struct samples {
    double *v;
    size_t n, cap;
};

static void sample_push(struct samples *s, double x)
{
    if (s->n == s->cap) {
        size_t cap = s->cap ? s->cap * 2 : 1024;
        double *v = zcl_realloc(s->v, cap * sizeof(*v), "sem_replay_report_series");
        if (v == NULL)
            return;
        s->v = v;
        s->cap = cap;
    }
    s->v[s->n++] = x;
}

static void sample_line(const char *name, struct samples *s)
{
    if (s->n == 0) {
        printf("| %s | 0 | - | - | - | - |\n", name);
        return;
    }
    qsort(s->v, s->n, sizeof(double), cmp_double);
    double sum = 0;
    for (size_t i = 0; i < s->n; i++)
        sum += s->v[i];
    printf("| %s | %zu | %.3f | %.3f | %.3f | %.1f |\n", name, s->n, sum / (double)s->n,
           s->v[s->n / 2], s->v[(s->n * 9) / 10], sum);
}

static void read_tasks(const char *path, struct samples *cpu, struct samples *wall,
                       const char *side)
{
    FILE *fp = fopen(path, "r");
    char line[SR_PATH + 128], s[32], tu[SR_PATH];
    double w = 0, c = 0;
    int rc = 0;
    while (fp && fgets(line, sizeof(line), fp) != NULL) {
        if (sscanf(line, "%31s\t%4095s\t%lf\t%lf\t%d", s, tu, &w, &c, &rc) != 5)
            continue;
        if ((strcmp(side, "compile") == 0) != (strcmp(s, "compile") == 0) || rc != 0)
            continue;
        sample_push(cpu, c);
        sample_push(wall, w);
    }
    if (fp)
        fclose(fp);
}

static void print_costs(const char *state, const struct sr_strv *dirs)
{
    struct samples scpu = {0}, swall = {0}, ccpu = {0}, cwall = {0};
    for (size_t i = 0; i < dirs->n; i++) {
        char path[SR_PATH];
        snprintf(path, sizeof(path), "%s/run/%s/tasks.tsv", state, dirs->v[i]);
        read_tasks(path, &scpu, &swall, "sense");
        read_tasks(path, &ccpu, &cwall, "compile");
    }
    printf("## Per-TU cost (seconds)\n\n");
    printf("| measure | samples | mean | p50 | p90 | sum |\n|---|---|---|---|---|---|\n");
    sample_line("sensor CPU per TU", &scpu);
    sample_line("sensor wall per TU", &swall);
    sample_line("compile CPU per TU (timed, same argv)", &ccpu);
    sample_line("compile wall per TU (timed, same argv)", &cwall);
    printf("\n");
    free(scpu.v);
    free(swall.v);
    free(ccpu.v);
    free(cwall.v);
}

/* ── changed inputs and line shifts ───────────────────────────────────── */

static void row_dir(const struct table *t, const struct row *r, char *out, size_t cap)
{
    snprintf(out, cap, "%03d_%s", atoi(col(t, r, "idx")), col(t, r, "commit"));
}

struct input_class {
    char name[32];
    size_t files, read, named, commits_named;
};

static struct input_class *class_find(struct input_class *v, size_t *n, const char *name)
{
    for (size_t i = 0; i < *n; i++)
        if (strcmp(v[i].name, name) == 0)
            return &v[i];
    if (*n == 16)
        return NULL;
    memset(&v[*n], 0, sizeof(v[*n]));
    snprintf(v[*n].name, sizeof(v[*n].name), "%s", name);
    return &v[(*n)++];
}

/* One inputs.tsv row: file, class, readers, named, named_variant. */
static bool input_row(char *line, char **f)
{
    return split_tabs(line, f) >= 5 && strcmp(f[0], "file") != 0;
}

static void print_commit_inputs(const char *state, const struct table *t, const struct row *r,
                                struct input_class *cls, size_t *ncls)
{
    char dir[64], path[SR_PATH], line[SR_PATH + 128], *f[SR_COLS];
    row_dir(t, r, dir, sizeof(dir));
    snprintf(path, sizeof(path), "%s/run/%s/inputs.tsv", state, dir);
    FILE *fp = fopen(path, "r");
    bool fallback = strcmp(col(t, r, "reason"), "build-input-changed") == 0;
    bool any = false;
    while (fp && fgets(line, sizeof(line), fp) != NULL) {
        if (!input_row(line, f))
            continue;
        struct input_class *c = class_find(cls, ncls, f[1]);
        if (c) {
            c->files++;
            c->read += atoi(f[2]) > 0;
            c->named += atoi(f[3]) == 1;
        }
        if (!fallback)
            continue;
        printf("%s%s (%s, %s readers%s)", any ? "; " : "| ", f[0], f[1], f[2],
               atoi(f[3]) == 1 ? ", named" : "");
        any = true;
    }
    if (fp)
        fclose(fp);
    if (any)
        printf(" | %s | %s |\n", col(t, r, "commit"),
               is_one(t, r, "c_narrowed") ? "narrowed" : col(t, r, "c_reason"));
}

static void print_inputs(const char *state, const struct table *t)
{
    struct input_class cls[16];
    size_t ncls = 0;
    printf("## Changed non-C inputs\n\n");
    printf("### Commits whose facts plan fell back on build-input-changed\n\n");
    printf("Each changed path other than .c and .h: its class, how many compiles' depfiles name "
           "it, and whether the plan named it as the cause (the plan names the first). The last "
           "column is the compiled-inputs variant's verdict for the same commit.\n\n");
    printf("| inputs (class, readers) | commit | variant verdict |\n|---|---|---|\n");
    for (size_t i = 0; i < t->n; i++)
        print_commit_inputs(state, t, &t->rows[i], cls, &ncls);
    printf("\n### By class, over all commits\n\n");
    printf("| class | changed paths | read by a compile | named as a fallback cause |\n");
    printf("|---|---|---|---|\n");
    for (size_t i = 0; i < ncls; i++)
        printf("| %s | %zu | %zu | %zu |\n", cls[i].name, cls[i].files, cls[i].read,
               cls[i].named);
    printf("\n");
}

static void print_shifts(const char *state, const struct table *t)
{
    size_t rows = 0;
    printf("## Debug-only misses and the line shifts behind them\n\n");
    printf("Each left-out object whose bytes agree with the before object after objcopy "
           "--strip-debug; the changed files it reads and the hunks that shift the lines below "
           "them (L<old line><delta>).\n\n");
    printf("| # | commit | TU | changed file read | shifting hunks |\n|---|---|---|---|---|\n");
    for (size_t i = 0; i < t->n; i++) {
        char dir[64], path[SR_PATH], line[2 * SR_PATH], *f[SR_COLS];
        row_dir(t, &t->rows[i], dir, sizeof(dir));
        snprintf(path, sizeof(path), "%s/run/%s/shifts.tsv", state, dir);
        FILE *fp = fopen(path, "r");
        while (fp && fgets(line, sizeof(line), fp) != NULL) {
            if (split_tabs(line, f) < 3)
                continue;
            printf("| %s | %s | %s | %s | %s |\n", col(t, &t->rows[i], "idx"),
                   col(t, &t->rows[i], "commit"), f[0], f[1], f[2]);
            rows++;
        }
        if (fp)
            fclose(fp);
    }
    if (rows == 0)
        printf("| | | none | | |\n");
    printf("\n");
}

int sr_report(const struct sr_cfg *cfg)
{
    struct table t = {0};
    struct sr_strv dirs = {0};
    struct pricing pr = {0};
    if (!pricing_load(&pr, cfg->state) || !load_runs(cfg->state, &pr, &t, &dirs))
        return 1;
    printf("# Semantic facts replay\n\n%zu commits replayed.\n\n", t.n);
    print_headline(&t);
    print_commits(&t);
    print_groups(&t, "kind", "By change kind");
    print_groups(&t, "facts_mode", "By facts compile-set mode");
    print_fallbacks(&t, "reason", "Fallback reasons (facts compile set not precise)");
    print_inputs(cfg->state, &t);
    print_shifts(cfg->state, &t);
    print_c_variant(&t);
    print_sensor(&t);
    print_costs(cfg->state, &dirs);
    print_pricing(&pr);
    prices_free(&pr.catalog);
    prices_free(&pr.timed);
    for (size_t i = 0; i < t.n; i++)
        free(t.rows[i].line);
    free(t.rows);
    free(t.head_line);
    sr_strv_free(&dirs);
    return 0;
}
