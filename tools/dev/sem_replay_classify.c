/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * z23-sem-replay: object change kinds, changed-input readers, header line
 * shifts, and the sensor's incremental cost. See sem_replay_classify.h. */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "sem_replay_classify.h"

/* ── kept objects ─────────────────────────────────────────────────────── */

static void obj_path(const char *repo, const char *epoch, const char *tu, char out[SR_PATH])
{
    size_t tl = strlen(tu);
    snprintf(out, SR_PATH, "%s/%s/%.*s.o", repo, epoch, (int)(tl > 2 ? tl - 2 : tl), tu);
}

static bool keep_one(const char *src, const char *dst)
{
    char *text = NULL;
    size_t len = 0;
    if (!sr_mkparent(dst))
        return false;
    if (link(src, dst) == 0)
        return true;
    bool ok = sr_read_file(src, &text, &len) && sr_write_file(dst, text, len);
    free(text);
    return ok;
}

bool sr_keep_objects(const char *repo, const struct sr_snap *snap, const char *dir)
{
    bool ok = sr_rmtree(dir) && sr_mkdirs(dir);
    for (size_t i = 0; ok && i < snap->n; i++) {
        char src[SR_PATH], dst[SR_PATH];
        obj_path(repo, snap->epoch, snap->v[i].tu, src);
        snprintf(dst, sizeof(dst), "%s/%s.o", dir, snap->v[i].tu);
        ok = keep_one(src, dst);
        if (!ok)
            fprintf(stderr, "sem-replay: cannot keep %s: %s\n", src, strerror(errno));
    }
    return ok;
}

/* ── code or debug information ────────────────────────────────────────── */

static bool stripped_hash(const char *obj, const char *out, const char *log, uint8_t h[32])
{
    char *argv[] = {"objcopy", "--strip-debug", (char *)obj, (char *)out, NULL};
    bool ok = sr_run(argv, NULL, log, NULL, NULL) == 0 && sr_hash_file(out, h);
    (void)unlink(out);
    return ok;
}

/* 0 code, 1 debug, 2 unknown. */
static int classify_pair(const char *repo, const char *epoch, const struct sr_obj *b,
                         const struct sr_obj *a, const char *keep, const char *tmp,
                         const char *log)
{
    char kept[SR_PATH], now[SR_PATH], sb[SR_PATH], sa[SR_PATH];
    uint8_t hk[32], hb[32], ha[32];
    if (b == NULL)
        return 0; /* a new object is new code */
    snprintf(kept, sizeof(kept), "%s/%s.o", keep, a->tu);
    snprintf(sb, sizeof(sb), "%s/strip-before.o", tmp);
    snprintf(sa, sizeof(sa), "%s/strip-after.o", tmp);
    obj_path(repo, epoch, a->tu, now);
    if (!sr_hash_file(kept, hk) || memcmp(hk, b->hash, 32) != 0)
        return 2;
    if (!stripped_hash(kept, sb, log, hb) || !stripped_hash(now, sa, log, ha))
        return 2;
    return memcmp(hb, ha, 32) == 0 ? 1 : 0;
}

bool sr_classify_objects(const char *repo, const struct sr_snap *before,
                         const struct sr_snap *after, const char *keep,
                         const char *tmp, const struct sr_strv *tus,
                         const char *log, struct sr_obj_kinds *out)
{
    bool ok = sr_mkdirs(tmp);
    for (size_t i = 0; ok && i < tus->n; i++) {
        const struct sr_obj *a = sr_snap_find(after, tus->v[i]);
        if (a == NULL)
            continue;
        int k = classify_pair(repo, after->epoch, sr_snap_find(before, tus->v[i]), a, keep,
                              tmp, log);
        struct sr_strv *dst = k == 0 ? &out->code : k == 1 ? &out->debug : &out->unknown;
        ok = sr_strv_push(dst, tus->v[i]);
    }
    sr_strv_sort_unique(&out->code);
    sr_strv_sort_unique(&out->debug);
    sr_strv_sort_unique(&out->unknown);
    return ok;
}

void sr_obj_kinds_free(struct sr_obj_kinds *k)
{
    sr_strv_free(&k->code);
    sr_strv_free(&k->debug);
    sr_strv_free(&k->unknown);
}

/* ── changed inputs ───────────────────────────────────────────────────── */

static bool ends_with(const char *s, const char *suffix)
{
    size_t n = strlen(s), m = strlen(suffix);
    return n >= m && strcmp(s + n - m, suffix) == 0;
}

/* Suffix classes, in order; the first match wins. */
static const struct {
    const char *suffix, *cls;
} k_suffix_class[] = {
    {"/Makefile", "makefile"}, {".mk", "makefile"}, {".def", "def"},   {".inc", "def"},
    {".md", "doc"},            {".sh", "script"},   {".txt", "data"},  {".json", "data"},
    {".jsonl", "data"},        {".tsv", "data"},    {".csv", "data"},
};

static bool generated_name(const char *path)
{
    const char *base = strrchr(path, '/');
    base = base ? base + 1 : path;
    return strstr(base, "_gen.") != NULL || strstr(path, "INVENTORY") != NULL ||
           strstr(path, "generated") != NULL;
}

const char *sr_input_class(const char *path)
{
    size_t n = sizeof(k_suffix_class) / sizeof(k_suffix_class[0]);
    if (strcmp(path, "Makefile") == 0)
        return "makefile";
    for (size_t i = 0; i < 4; i++)
        if (ends_with(path, k_suffix_class[i].suffix))
            return k_suffix_class[i].cls;
    if (generated_name(path))
        return "generated";
    if (strncmp(path, "docs/", 5) == 0)
        return "doc";
    for (size_t i = 4; i < n; i++)
        if (ends_with(path, k_suffix_class[i].suffix))
            return k_suffix_class[i].cls;
    return "other";
}

/* The index of the first pair not below "path\t". */
static size_t pairs_first(const struct sr_strv *pairs, const char *path)
{
    char key[SR_PATH + 2];
    size_t lo = 0, hi = pairs->n;
    snprintf(key, sizeof(key), "%s\t", path);
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (strcmp(pairs->v[mid], key) < 0)
            lo = mid + 1;
        else
            hi = mid;
    }
    return lo;
}

size_t sr_pairs_readers(const struct sr_strv *pairs, const char *path)
{
    size_t pl = strlen(path), n = 0;
    for (size_t i = pairs_first(pairs, path); i < pairs->n; i++) {
        if (strncmp(pairs->v[i], path, pl) != 0 || pairs->v[i][pl] != '\t')
            break;
        n++;
    }
    return n;
}

bool sr_pairs_reads(const struct sr_strv *pairs, const char *tu, struct sr_strv *out)
{
    bool ok = true;
    for (size_t i = 0; ok && i < pairs->n; i++) {
        const char *tab = strchr(pairs->v[i], '\t');
        if (tab != NULL && strcmp(tab + 1, tu) == 0)
            ok = sr_strv_pushn(out, pairs->v[i], (size_t)(tab - pairs->v[i]));
    }
    return ok;
}

/* ── header line shifts ───────────────────────────────────────────────── */

/* "@@ -a[,b] +c[,d] @@": the old start and the line-count delta. */
static bool hunk_shift(const char *line, long *at, long *delta)
{
    long a = 0, b = 1, c = 0, d = 1;
    const char *p = line + 4;
    char *end;
    a = strtol(p, &end, 10);
    if (*end == ',')
        b = strtol(end + 1, &end, 10);
    p = strchr(end, '+');
    if (p == NULL)
        return false;
    c = strtol(p + 1, &end, 10);
    if (*end == ',')
        d = strtol(end + 1, &end, 10);
    (void)c;
    *at = b == 0 ? a + 1 : a;
    *delta = d - b;
    return true;
}

bool sr_line_shifts(const char *repo, const char *parent, const char *commit,
                    const char *path, char *out, size_t cap)
{
    char *argv[] = {"git", "diff", "-U0", "--no-color", "--no-ext-diff", (char *)parent,
                    (char *)commit, "--", (char *)path, NULL};
    char *text = NULL;
    size_t len = 0, used = 0, n = 0;
    out[0] = '\0';
    if (sr_capture(argv, repo, NULL, &text, &len) != 0) {
        free(text);
        return false;
    }
    for (char *line = text; line && *line && n < 8; line = strchr(line, '\n')) {
        line += *line == '\n';
        long at = 0, delta = 0;
        if (strncmp(line, "@@ -", 4) != 0 || !hunk_shift(line, &at, &delta) || delta == 0)
            continue;
        int w = snprintf(out + used, cap - used, "%sL%ld%+ld", n ? " " : "", at, delta);
        if (w < 0 || (size_t)w >= cap - used)
            break;
        used += (size_t)w;
        n++;
    }
    free(text);
    return true;
}

/* ── the sensor's incremental cost ────────────────────────────────────── */

static bool manifest_changed(const char *facts_dir, const char *tu)
{
    char b[SR_PATH], a[SR_PATH];
    uint8_t hb[32], ha[32];
    snprintf(b, sizeof(b), "%s/%s.before.zsm", facts_dir, tu);
    snprintf(a, sizeof(a), "%s/%s.after.zsm", facts_dir, tu);
    if (!sr_hash_file(a, ha))
        return false;
    return !sr_hash_file(b, hb) || memcmp(ha, hb, 32) != 0;
}

bool sr_sense_split(const char *tasks, const char *facts_dir,
                    const struct sr_strv *make, const struct sr_strv *affected,
                    struct sr_sense_split *out)
{
    FILE *fp = fopen(tasks, "r");
    char line[SR_PATH + 128], side[32], tu[SR_PATH];
    double wall = 0, cpu = 0;
    int rc = 0;
    memset(out, 0, sizeof(*out));
    if (fp == NULL)
        return true; /* no sensing this step */
    while (fgets(line, sizeof(line), fp) != NULL) {
        if (sscanf(line, "%31s\t%4095s\t%lf\t%lf\t%d", side, tu, &wall, &cpu, &rc) != 5 ||
            strcmp(side, "after") != 0)
            continue;
        bool m = sr_strv_has(make, tu), f = sr_strv_has(affected, tu);
        bool z = manifest_changed(facts_dir, tu);
        out->after_cpu += cpu;
        out->after_n++;
        out->make_cpu += m ? cpu : 0;
        out->make_n += m;
        out->affected_cpu += f ? cpu : 0;
        out->affected_n += f;
        out->manifest_cpu += z ? cpu : 0;
        out->manifest_n += z;
    }
    fclose(fp);
    return true;
}
