/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * z23-sem-replay build side; see sem_replay_build.h. */
#define _GNU_SOURCE /* wait4 */

#include "sem_replay_build.h"

#include "base/hex.h"
#include "base/safe_alloc.h"
#include "sem_replay_record.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#define SR_TEST_OBJ_ROOT "build/test-obj"

#ifdef __APPLE__
#define SR_MTIME(st) ((st)->st_mtimespec)
#else
#define SR_MTIME(st) ((st)->st_mtim)
#endif

/* ── the live epoch ───────────────────────────────────────────────────── */

bool sr_epoch_dir(const char *repo, char out[SR_PATH])
{
    char path[SR_PATH], *text = NULL;
    size_t n = 0;
    snprintf(path, sizeof(path), "%s/%s/.current-epoch", repo, SR_TEST_OBJ_ROOT);
    if (!sr_read_file(path, &text, &n)) {
        fprintf(stderr, "sem-replay: no live test-fast epoch at %s\n", path);
        return false;
    }
    while (n > 0 && (text[n - 1] == '\n' || text[n - 1] == '\r'))
        text[--n] = '\0';
    bool ok = n == 64 && strspn(text, "0123456789abcdef") == 64;
    if (ok)
        snprintf(out, SR_PATH, "%s/epochs/%s", SR_TEST_OBJ_ROOT, text);
    else
        fprintf(stderr, "sem-replay: %s does not name an epoch\n", path);
    free(text);
    return ok;
}

/* ── snapshots ────────────────────────────────────────────────────────── */

static int cmp_obj(const void *a, const void *b)
{
    return strcmp(((const struct sr_obj *)a)->tu, ((const struct sr_obj *)b)->tu);
}

const struct sr_obj *sr_snap_find(const struct sr_snap *s, const char *tu)
{
    struct sr_obj key = {.tu = (char *)tu};
    if (s->n == 0)
        return NULL;
    return bsearch(&key, s->v, s->n, sizeof(*s->v), cmp_obj);
}

static bool snap_push(struct sr_snap *s, const struct sr_obj *o)
{
    if (s->n == s->cap) {
        size_t cap = s->cap ? s->cap * 2 : 1024;
        struct sr_obj *v = zcl_realloc(s->v, cap * sizeof(*v), "sem_replay_snap");
        if (v == NULL) {
            fprintf(stderr, "sem-replay: out of memory in a snapshot\n");
            return false;
        }
        s->v = v;
        s->cap = cap;
    }
    s->v[s->n++] = *o;
    return true;
}

static bool obj_hash(const char *abs, const struct stat *st,
                     const struct sr_snap *prev, bool same_epoch,
                     struct sr_obj *o)
{
    o->ino = (uint64_t)st->st_ino;
    o->mtime_ns = (int64_t)SR_MTIME(st).tv_sec * 1000000000LL + SR_MTIME(st).tv_nsec;
    o->size = (int64_t)st->st_size;
    const struct sr_obj *p = same_epoch && prev ? sr_snap_find(prev, o->tu) : NULL;
    if (p && p->ino == o->ino && p->mtime_ns == o->mtime_ns && p->size == o->size) {
        memcpy(o->hash, p->hash, 32);
        return true;
    }
    if (!sr_hash_file(abs, o->hash)) {
        fprintf(stderr, "sem-replay: cannot hash %s\n", abs);
        return false;
    }
    return true;
}

struct walk {
    const char *repo;
    const struct sr_snap *prev;
    bool same_epoch;
    size_t foreign; /* objects whose source this tree lacks, left out */
    struct sr_snap *out;
};

static bool walk_dir(struct walk *w, const char *rel);

/* The TU of an epoch object, "<dir>/<name>.c" for "<dir>/<name>.o"; *tu is
 * NULL when that source is absent from the checked-out tree (an epoch
 * reused across commits keeps the objects of TUs another commit had, and
 * no rule of this tree builds them). False only when out of memory. */
static bool object_tu(const struct walk *w, const char *child, char **tu)
{
    char src[SR_PATH];
    size_t cl = strlen(child);
    *tu = zcl_malloc(cl + 1, "sem_replay_tu");
    if (*tu == NULL) {
        fprintf(stderr, "sem-replay: out of memory naming %s\n", child);
        return false;
    }
    memcpy(*tu, child, cl + 1);
    (*tu)[cl - 1] = 'c';
    snprintf(src, sizeof(src), "%s/%s", w->repo, *tu);
    if (!sr_exists(src)) {
        free(*tu);
        *tu = NULL;
    }
    return true;
}

static bool walk_entry(struct walk *w, const char *rel, const char *name)
{
    char child[SR_PATH], abs[SR_PATH];
    struct stat st;
    size_t nl = strlen(name);
    snprintf(child, sizeof(child), "%s%s%s", rel, rel[0] ? "/" : "", name);
    snprintf(abs, sizeof(abs), "%s/%s/%s", w->repo, w->out->epoch, child);
    if (lstat(abs, &st) != 0)
        return true; /* raced with a publish; the next snapshot sees it */
    if (S_ISDIR(st.st_mode))
        return walk_dir(w, child);
    if (!S_ISREG(st.st_mode) || nl < 3 || strcmp(name + nl - 2, ".o") != 0 ||
        rel[0] == '\0')
        return true; /* the epoch root holds link products, not TUs */
    struct sr_obj o = {0};
    if (!object_tu(w, child, &o.tu))
        return false;
    if (o.tu == NULL) {
        w->foreign++;
        return true;
    }
    if (!obj_hash(abs, &st, w->prev, w->same_epoch, &o) || !snap_push(w->out, &o)) {
        free(o.tu);
        return false;
    }
    return true;
}

static bool walk_dir(struct walk *w, const char *rel)
{
    char abs[SR_PATH];
    snprintf(abs, sizeof(abs), "%s/%s%s%s", w->repo, w->out->epoch,
             rel[0] ? "/" : "", rel);
    DIR *d = opendir(abs);
    if (d == NULL) {
        fprintf(stderr, "sem-replay: opendir %s: %s\n", abs, strerror(errno));
        return false;
    }
    bool ok = true;
    struct dirent *e;
    while (ok && (e = readdir(d)) != NULL) {
        if (e->d_name[0] == '.')
            continue; /* ., .., .leases, .build-session */
        ok = walk_entry(w, rel, e->d_name);
    }
    closedir(d);
    return ok;
}

bool sr_snap_take(const char *repo, const struct sr_snap *prev,
                  struct sr_snap *out)
{
    memset(out, 0, sizeof(*out));
    if (!sr_epoch_dir(repo, out->epoch))
        return false;
    struct walk w = {
        .repo = repo, .prev = prev, .out = out,
        .same_epoch = prev != NULL && strcmp(prev->epoch, out->epoch) == 0,
    };
    if (!walk_dir(&w, ""))
        return false;
    if (w.foreign > 0)
        fprintf(stderr, "sem-replay: %zu objects in %s have no source in this tree; left out\n",
                w.foreign, out->epoch);
    if (out->n == 0) {
        fprintf(stderr, "sem-replay: %s holds no objects; the build did not run\n",
                out->epoch);
        return false;
    }
    qsort(out->v, out->n, sizeof(*out->v), cmp_obj);
    return true;
}

bool sr_snap_save(const struct sr_snap *s, const char *path)
{
    FILE *fp = fopen(path, "w");
    if (fp == NULL) {
        fprintf(stderr, "sem-replay: write %s: %s\n", path, strerror(errno));
        return false;
    }
    fprintf(fp, "epoch\t%s\n", s->epoch);
    for (size_t i = 0; i < s->n; i++) {
        char hex[65];
        sr_hex(s->v[i].hash, hex);
        fprintf(fp, "%s\t%llu\t%lld\t%lld\t%s\n", s->v[i].tu,
                (unsigned long long)s->v[i].ino, (long long)s->v[i].mtime_ns,
                (long long)s->v[i].size, hex);
    }
    return fclose(fp) == 0;
}

static bool unhex(const char *h, uint8_t out[32])
{
    return zcl_hex_decode(h, out, 32);
}

static bool snap_numbers(char **f, struct sr_obj *o)
{
    char *end;
    errno = 0;
    if (f[1][0] == '-')
        return false;
    o->ino = strtoull(f[1], &end, 10);
    if (end == f[1] || *end || errno == ERANGE)
        return false;
    errno = 0;
    o->mtime_ns = strtoll(f[2], &end, 10);
    if (end == f[2] || *end || errno == ERANGE)
        return false;
    errno = 0;
    o->size = strtoll(f[3], &end, 10);
    return end != f[3] && *end == '\0' && errno != ERANGE;
}

static bool snap_line(struct sr_snap *s, char *line)
{
    char *f[5];
    size_t n = sr_record_fields(line, f, 5);
    if (n == 2 && strcmp(f[0], "epoch") == 0) {
        if (strlen(f[1]) >= sizeof(s->epoch))
            return false;
        memcpy(s->epoch, f[1], strlen(f[1]) + 1);
        return true;
    }
    struct sr_obj o = {0};
    if (n != 5 || strlen(f[0]) >= SR_PATH ||
        !snap_numbers(f, &o) || !unhex(f[4], o.hash))
        return false;
    o.tu = zcl_strdup(f[0], "sem_replay_snap_tu");
    if (o.tu == NULL || !snap_push(s, &o)) {
        free(o.tu);
        return false;
    }
    return true;
}

bool sr_snap_load(struct sr_snap *s, const char *path)
{
    memset(s, 0, sizeof(*s));
    FILE *fp = fopen(path, "r");
    if (fp == NULL)
        return false;
    char line[SR_PATH + 256];
    bool ok = true;
    int record = 0;
    while (ok && (record = sr_record(fp, line, sizeof line)) > 0)
        ok = snap_line(s, line);
    if (record < 0)
        ok = false;
    if (fclose(fp) != 0)
        ok = false;
    if (!ok)
        fprintf(stderr, "sem-replay: malformed snapshot %s\n", path);
    /* Empty snapshots have no allocation to pass as qsort's base. */
    if (s->n > 1)
        qsort(s->v, s->n, sizeof(*s->v), cmp_obj);
    return ok;
}

void sr_snap_free(struct sr_snap *s)
{
    for (size_t i = 0; i < s->n; i++)
        free(s->v[i].tu);
    free(s->v);
    memset(s, 0, sizeof(*s));
}

/* ── depfiles ─────────────────────────────────────────────────────────── */

/* End of the depfile's first rule: the first newline no backslash
 * continues. */
static char *dep_rule_end(char *p)
{
    for (; *p; p++)
        if (*p == '\n' && p[-1] != '\\')
            return p;
    return p;
}

/* Does out[0..n) end in a ".." component (which a later ".." must keep)? */
static bool ends_in_up(const char *out, size_t n)
{
    return n >= 2 && out[n - 1] == '.' && out[n - 2] == '.';
}

/* Apply one path component of length len to out[0..*n): "." is dropped,
 * ".." removes the previous component unless out is empty or ends in "..",
 * anything else is appended. */
static void path_component(const char *c, size_t len, char *out, size_t *n, size_t cap)
{
    bool up = len == 2 && c[0] == '.' && c[1] == '.';
    if (len == 0 || (len == 1 && c[0] == '.'))
        return;
    if (up && *n > 0 && !ends_in_up(out, *n)) {
        while (*n > 0 && out[*n - 1] != '/')
            (*n)--;
        *n = *n > 0 ? *n - 1 : 0;
        return;
    }
    if (*n + len + 2 >= cap)
        return;
    if (*n > 0)
        out[(*n)++] = '/';
    memcpy(out + *n, c, len);
    *n += len;
}

/* Lexically resolve "." and ".." components: a depfile spells a prerequisite
 * the way the include named it ("tools/dev/../../engine/x.def"). */
static void normalize_path(const char *in, char *out, size_t cap)
{
    size_t n = 0;
    while (*in && n + 1 < cap) {
        size_t len = strcspn(in, "/");
        path_component(in, len, out, &n, cap);
        in += len;
        in += *in == '/';
    }
    out[n] = '\0';
}

/* Does the first rule of depfile text name a path in files? The target is
 * skipped; continuation backslashes are separators. */
static bool dep_names(char *text, const struct sr_strv *files)
{
    char *p = strstr(text, ": ");
    if (p == NULL)
        return false;
    char *end = dep_rule_end(p);
    *end = '\0';
    for (p += 2; *p;) {
        p += strspn(p, " \t\n\\");
        size_t len = strcspn(p, " \t\n");
        if (len == 0)
            break;
        char save = p[len];
        p[len] = '\0';
        char name[SR_PATH];
        normalize_path(p, name, sizeof(name));
        bool hit = sr_strv_has(files, name);
        p[len] = save;
        if (hit)
            return true;
        p += len;
    }
    return false;
}

bool sr_deps_hits(const char *repo, const struct sr_snap *snap,
                  const struct sr_strv *files, struct sr_strv *out,
                  size_t *missing)
{
    *missing = 0;
    for (size_t i = 0; i < snap->n; i++) {
        char path[SR_PATH], *text = NULL;
        size_t n = 0, tl = strlen(snap->v[i].tu);
        snprintf(path, sizeof(path), "%s/%s/%.*s.d", repo, snap->epoch,
                 (int)(tl - 2), snap->v[i].tu);
        if (!sr_read_file(path, &text, &n)) {
            (*missing)++;
            continue;
        }
        bool hit = dep_names(text, files);
        free(text);
        if (hit && !sr_strv_push(out, snap->v[i].tu))
            return false;
    }
    sr_strv_sort_unique(out);
    return true;
}

/* Every path of files that the first rule of depfile text names. */
static bool dep_named(char *text, const struct sr_strv *files, const char *tu,
                      struct sr_strv *out)
{
    char *p = strstr(text, ": ");
    if (p == NULL)
        return true;
    *dep_rule_end(p) = '\0';
    bool ok = true;
    for (p += 2; ok && *p;) {
        p += strspn(p, " \t\n\\");
        size_t len = strcspn(p, " \t\n");
        if (len == 0)
            break;
        char name[SR_PATH], pair[2 * SR_PATH + 2];
        char save = p[len];
        p[len] = '\0';
        normalize_path(p, name, sizeof(name));
        p[len] = save;
        p += len;
        if (!sr_strv_has(files, name))
            continue;
        snprintf(pair, sizeof(pair), "%s\t%s", name, tu);
        ok = sr_strv_push(out, pair);
    }
    return ok;
}

bool sr_deps_pairs(const char *repo, const struct sr_snap *snap,
                   const struct sr_strv *files, struct sr_strv *out)
{
    bool ok = true;
    for (size_t i = 0; ok && i < snap->n; i++) {
        char path[SR_PATH], *text = NULL;
        size_t n = 0, tl = strlen(snap->v[i].tu);
        snprintf(path, sizeof(path), "%s/%s/%.*s.d", repo, snap->epoch,
                 (int)(tl - 2), snap->v[i].tu);
        if (sr_read_file(path, &text, &n))
            ok = dep_named(text, files, snap->v[i].tu, out);
        free(text);
    }
    sr_strv_sort_unique(out);
    return ok;
}


/* ── compile argv from make -n ────────────────────────────────────────── */

static int find_word(const struct sr_strv *w, const char *s, size_t from)
{
    for (size_t i = from; i < w->n; i++)
        if (strcmp(w->v[i], s) == 0)
            return (int)i;
    return -1;
}

/* One recipe line "<tool> [--epoch-object] dep OBJ SRC ... -- CC FLAGS". */
static bool argv_line(const char *line, size_t len, struct sr_strv *tus,
                      struct sr_strv **flags_out)
{
    struct sr_strv w = {0};
    bool ok = sr_split_words(line, len, &w);
    int dep = ok ? find_word(&w, "dep", 0) : -1;
    int sep = dep >= 0 ? find_word(&w, "--", (size_t)dep) : -1;
    if (sep < 0 || (size_t)dep + 2 >= w.n) {
        sr_strv_free(&w);
        return ok;
    }
    struct sr_strv *f = zcl_calloc(1, sizeof(*f), "sem_replay_argv_flags");
    ok = f != NULL && sr_strv_push(tus, w.v[dep + 2]);
    for (size_t i = (size_t)sep + 1; ok && i < w.n; i++)
        ok = sr_strv_push(f, w.v[i]);
    if (ok) {
        *flags_out = f;
    } else {
        fprintf(stderr, "sem-replay: out of memory reading a recipe\n");
        if (f)
            sr_strv_free(f);
        free(f);
    }
    sr_strv_free(&w);
    return ok;
}

static bool make_argv_cmd(const char *epoch, const struct sr_strv *tus,
                          struct sr_strv *cmd)
{
    bool ok = sr_strv_push(cmd, "make") && sr_strv_push(cmd, "-n") &&
              sr_strv_push(cmd, "--no-print-directory");
    for (size_t i = 0; ok && i < tus->n; i++)
        ok = sr_strv_push(cmd, "-W") && sr_strv_push(cmd, tus->v[i]);
    for (size_t i = 0; ok && i < tus->n; i++) {
        char obj[SR_PATH];
        size_t tl = strlen(tus->v[i]);
        snprintf(obj, sizeof(obj), "%s/%.*s.o", epoch, (int)(tl - 2), tus->v[i]);
        ok = sr_strv_push(cmd, obj);
    }
    ok = ok && sr_strv_pushn(cmd, "", 0);
    if (ok) {
        free(cmd->v[cmd->n - 1]);
        cmd->v[cmd->n - 1] = NULL; /* argv terminator */
    }
    return ok;
}

/* Pairs (tu, flags) sorted by tu. */
struct argv_pair {
    char *tu;
    struct sr_strv *flags;
};

static int cmp_pair(const void *a, const void *b)
{
    return strcmp(((const struct argv_pair *)a)->tu, ((const struct argv_pair *)b)->tu);
}

/* The line holds the word "dep" of an epoch-object recipe. */
static bool has_dep_word(const char *p, size_t len)
{
    for (size_t i = 0; i + 5 <= len; i++)
        if (memcmp(p + i, " dep ", 5) == 0)
            return true;
    return false;
}

/* make -n prints a recipe as written: sh removes backslash-newline pairs,
 * so one logical command spans several printed lines. */
static void join_continuations(char *out, size_t len)
{
    for (size_t i = 0; i + 1 < len; i++)
        if (out[i] == '\\' && out[i + 1] == '\n')
            out[i] = out[i + 1] = ' ';
}

/* Store f as the flags of the TU argv_line just pushed (tus->n - 1). */
static bool store_flags(struct sr_strv ***fl, size_t *cap, size_t n, struct sr_strv *f)
{
    if (n > *cap) {
        size_t want = n * 2;
        struct sr_strv **nf = zcl_realloc(*fl, want * sizeof(*nf), "sem_replay_argv_flags_tbl");
        if (nf == NULL)
            return false;
        *fl = nf;
        *cap = want;
    }
    (*fl)[n - 1] = f;
    return true;
}

/* Every epoch-object recipe line: its TU in tus, its flags in fl[i]. */
static bool collect_lines(const char *out, size_t len, struct sr_strv *tus,
                          struct sr_strv ***fl)
{
    size_t cap = 0;
    bool ok = true;
    for (const char *p = out; ok && p < out + len;) {
        const char *nl = memchr(p, '\n', (size_t)(out + len - p));
        size_t ll = nl ? (size_t)(nl - p) : (size_t)(out + len - p);
        struct sr_strv *f = NULL;
        if (has_dep_word(p, ll))
            ok = argv_line(p, ll, tus, &f);
        if (ok && f != NULL)
            ok = store_flags(fl, &cap, tus->n, f);
        p += ll + 1;
    }
    return ok;
}

/* Move (tus, fl) into m sorted by TU; fl's rows are consumed. */
static bool sort_into(const struct sr_strv *tus, struct sr_strv **fl, struct sr_argv_map *m)
{
    size_t n = tus->n;
    if (n == 0)
        return true;
    struct argv_pair *pairs = zcl_calloc(n, sizeof(*pairs), "sem_replay_argv_pairs");
    m->flags = zcl_calloc(n, sizeof(*m->flags), "sem_replay_argv_map_flags");
    bool ok = pairs != NULL && m->flags != NULL;
    for (size_t i = 0; ok && i < n; i++)
        pairs[i] = (struct argv_pair){tus->v[i], fl[i]};
    if (ok)
        qsort(pairs, n, sizeof(*pairs), cmp_pair);
    for (size_t i = 0; ok && i < n; i++) {
        ok = sr_strv_push(&m->tus, pairs[i].tu);
        m->flags[i] = *pairs[i].flags;
        free(pairs[i].flags);
    }
    free(pairs);
    return ok;
}

static bool argv_collect(char *out, size_t len, struct sr_argv_map *m)
{
    struct sr_strv tus = {0};
    struct sr_strv **fl = NULL;
    join_continuations(out, len);
    bool ok = collect_lines(out, len, &tus, &fl) && sort_into(&tus, fl, m);
    free(fl);
    sr_strv_free(&tus);
    return ok;
}

bool sr_make_argv(const char *repo, const char *epoch,
                  const struct sr_strv *tus, const char *log,
                  struct sr_argv_map *out)
{
    memset(out, 0, sizeof(*out));
    if (tus->n == 0)
        return true;
    struct sr_strv cmd = {0};
    char *text = NULL;
    size_t len = 0;
    bool ok = make_argv_cmd(epoch, tus, &cmd);
    int rc = ok ? sr_capture(cmd.v, repo, log, &text, &len) : -1;
    ok = rc == 0 && argv_collect(text, len, out);
    if (rc != 0)
        fprintf(stderr, "sem-replay: make -n for %zu TUs exited %d\n", tus->n, rc);
    free(text);
    sr_strv_free(&cmd);
    return ok;
}

const struct sr_strv *sr_argv_find(const struct sr_argv_map *m, const char *tu)
{
    if (m->tus.n == 0)
        return NULL;
    size_t lo = 0, hi = m->tus.n;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        int c = strcmp(m->tus.v[mid], tu);
        if (c == 0)
            return &m->flags[mid];
        if (c < 0)
            lo = mid + 1;
        else
            hi = mid;
    }
    return NULL;
}

void sr_argv_free(struct sr_argv_map *m)
{
    for (size_t i = 0; i < m->tus.n; i++)
        sr_strv_free(&m->flags[i]);
    free(m->flags);
    sr_strv_free(&m->tus);
    memset(m, 0, sizeof(*m));
}

/* ── the pool ─────────────────────────────────────────────────────────── */

static pid_t pool_start(struct sr_task *t, const char *cwd)
{
    int fd = open(t->log, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0644);
    if (fd < 0) {
        fprintf(stderr, "sem-replay: open %s: %s\n", t->log, strerror(errno));
        return -1;
    }
    pid_t pid = fork();
    if (pid == 0) {
        if (chdir(cwd) != 0)
            _exit(126);
        (void)dup2(fd, STDOUT_FILENO);
        (void)dup2(fd, STDERR_FILENO);
        execvp(t->argv[0], t->argv);
        _exit(127);
    }
    close(fd);
    if (pid < 0)
        fprintf(stderr, "sem-replay: fork: %s\n", strerror(errno));
    return pid;
}

static void pool_reap(struct sr_task *t, size_t n, pid_t *pids, double *t0,
                      size_t *running)
{
    int status = 0;
    struct rusage ru;
    pid_t pid = wait4(-1, &status, 0, &ru);
    if (pid < 0)
        return;
    for (size_t i = 0; i < n; i++) {
        if (pids[i] != pid)
            continue;
        t[i].wall_s = sr_now() - t0[i];
        t[i].cpu_s = (double)ru.ru_utime.tv_sec + ru.ru_utime.tv_usec / 1e6 +
                     (double)ru.ru_stime.tv_sec + ru.ru_stime.tv_usec / 1e6;
        t[i].rc = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
        pids[i] = 0;
        (*running)--;
        return;
    }
}

bool sr_pool_run(struct sr_task *t, size_t n, int jobs, const char *cwd)
{
    pid_t *pids = zcl_calloc(n ? n : 1, sizeof(*pids), "sem_replay_pool_pids");
    double *t0 = zcl_calloc(n ? n : 1, sizeof(*t0), "sem_replay_pool_t0");
    bool ok = pids != NULL && t0 != NULL;
    size_t next = 0, running = 0;
    while (ok && (next < n || running > 0)) {
        if (next < n && running < (size_t)jobs) {
            t0[next] = sr_now();
            pids[next] = pool_start(&t[next], cwd);
            ok = pids[next] > 0;
            t[next].rc = -1;
            running += ok ? 1 : 0;
            next++;
            continue;
        }
        pool_reap(t, n, pids, t0, &running);
    }
    while (running > 0)
        pool_reap(t, n, pids, t0, &running);
    if (pids == NULL || t0 == NULL)
        fprintf(stderr, "sem-replay: out of memory starting a pool\n");
    free(pids);
    free(t0);
    return ok;
}

void sr_task_free(struct sr_task *t)
{
    for (size_t i = 0; t->argv != NULL && t->argv[i] != NULL; i++)
        free(t->argv[i]);
    free(t->argv);
    t->argv = NULL;
}
