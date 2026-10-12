/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * z23-sem-replay helpers: string lists, child processes with their
 * resource use, files, hashing, sh word splitting and JSON flattening. */
#if defined(__APPLE__) && !defined(_DARWIN_C_SOURCE)
#define _DARWIN_C_SOURCE 1 /* wait4 even with caller-defined _POSIX_C_SOURCE */
#endif
#define _GNU_SOURCE /* wait4, putenv */

#include "sem_replay.h"

#include "base/hex.h"
#include "base/safe_alloc.h"
#include "platform/clock.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "sha3/sha3.h"
#include "zjsonp/zjsonp.h"

extern char **environ;

/* ── string lists ─────────────────────────────────────────────────────── */

bool sr_strv_pushn(struct sr_strv *s, const char *str, size_t len)
{
    if (s->n == s->cap) {
        size_t cap = s->cap ? s->cap * 2 : 16;
        char **v = zcl_realloc(s->v, cap * sizeof(*v), "sem_replay_strv");
        if (v == NULL) {
            fprintf(stderr, "sem-replay: out of memory growing a list\n");
            return false;
        }
        s->v = v;
        s->cap = cap;
    }
    char *copy = zcl_malloc(len + 1, "sem_replay_strv_item");
    if (copy == NULL) {
        fprintf(stderr, "sem-replay: out of memory copying a string\n");
        return false;
    }
    memcpy(copy, str, len);
    copy[len] = '\0';
    s->v[s->n++] = copy;
    return true;
}

bool sr_strv_push(struct sr_strv *s, const char *str)
{
    return sr_strv_pushn(s, str, strlen(str));
}

static int cmp_str(const void *a, const void *b)
{
    return strcmp(*(char *const *)a, *(char *const *)b);
}

void sr_strv_sort_unique(struct sr_strv *s)
{
    if (s->n < 2)
        return;
    qsort(s->v, s->n, sizeof(*s->v), cmp_str);
    size_t w = 1;
    for (size_t r = 1; r < s->n; r++) {
        if (strcmp(s->v[r], s->v[w - 1]) == 0)
            free(s->v[r]);
        else
            s->v[w++] = s->v[r];
    }
    s->n = w;
}

bool sr_strv_has(const struct sr_strv *s, const char *str)
{
    if (s->n == 0)
        return false;
    return bsearch(&str, s->v, s->n, sizeof(*s->v), cmp_str) != NULL;
}

void sr_strv_clear(struct sr_strv *s)
{
    for (size_t i = 0; i < s->n; i++)
        free(s->v[i]);
    s->n = 0;
}

void sr_strv_free(struct sr_strv *s)
{
    sr_strv_clear(s);
    free(s->v);
    s->v = NULL;
    s->cap = 0;
}

/* ── processes ────────────────────────────────────────────────────────── */

double sr_now(void)
{
    return (double)clock_now_monotonic_ns() / 1e9;
}

static void child_setup(const char *cwd, int out_fd, int err_fd,
                        char *const env[])
{
    if (cwd != NULL && chdir(cwd) != 0) {
        fprintf(stderr, "sem-replay: chdir %s: %s\n", cwd, strerror(errno));
        _exit(126);
    }
    if (out_fd >= 0)
        (void)dup2(out_fd, STDOUT_FILENO);
    if (err_fd >= 0)
        (void)dup2(err_fd, STDERR_FILENO);
    for (size_t i = 0; env != NULL && env[i] != NULL; i++)
        (void)putenv(env[i]);
}

static int wait_child(pid_t pid, double t0, struct sr_cost *cost)
{
    int status = 0;
    struct rusage ru;
    memset(&ru, 0, sizeof(ru));
    while (wait4(pid, &status, 0, &ru) < 0) {
        if (errno != EINTR) {
            fprintf(stderr, "sem-replay: wait4: %s\n", strerror(errno));
            return -1;
        }
    }
    if (cost != NULL) {
        cost->wall_s = sr_now() - t0;
        cost->cpu_s = (double)ru.ru_utime.tv_sec + ru.ru_utime.tv_usec / 1e6 +
                      (double)ru.ru_stime.tv_sec + ru.ru_stime.tv_usec / 1e6;
    }
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

static int open_log(const char *log)
{
    if (log == NULL)
        return -1;
    int fd = open(log, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0644);
    if (fd < 0)
        fprintf(stderr, "sem-replay: open %s: %s\n", log, strerror(errno));
    return fd;
}

int sr_run(char *const argv[], const char *cwd, const char *log,
           char *const env[], struct sr_cost *cost)
{
    int fd = open_log(log);
    double t0 = sr_now();
    pid_t pid = fork();
    if (pid < 0) {
        fprintf(stderr, "sem-replay: fork %s: %s\n", argv[0], strerror(errno));
        if (fd >= 0)
            close(fd);
        return -1;
    }
    if (pid == 0) {
        child_setup(cwd, fd, fd, env);
        execvp(argv[0], argv);
        fprintf(stderr, "sem-replay: exec %s: %s\n", argv[0], strerror(errno));
        _exit(127);
    }
    if (fd >= 0)
        close(fd);
    return wait_child(pid, t0, cost);
}

static bool drain(int fd, char **out, size_t *len)
{
    *out = NULL;
    *len = 0;
    size_t cap = 65536, n = 0;
    char *buf = zcl_malloc(cap, "sem_replay_drain");
    if (buf == NULL) {
        fprintf(stderr, "sem-replay: out of memory reading a pipe\n");
        return false;
    }
    for (;;) {
        if (cap - n < 4096) {
            if (cap > SIZE_MAX / 2) {
                fprintf(stderr, "sem-replay: input too large\n");
                goto failed;
            }
            char *nb = zcl_realloc(buf, cap * 2, "sem_replay_drain");
            if (nb == NULL) {
                fprintf(stderr, "sem-replay: out of memory reading a pipe\n");
                goto failed;
            }
            buf = nb;
            cap *= 2;
        }
        ssize_t r = read(fd, buf + n, cap - n - 1);
        if (r < 0 && errno == EINTR)
            continue;
        if (r < 0) {
            fprintf(stderr, "sem-replay: read: %s\n", strerror(errno));
            goto failed;
        }
        if (r == 0)
            break;
        n += (size_t)r;
    }
    buf[n] = '\0';
    *out = buf;
    *len = n;
    return true;
failed:
    free(buf);
    return false;
}

int sr_capture(char *const argv[], const char *cwd, const char *log,
               char **out, size_t *len)
{
    int p[2];
    *out = NULL;
    *len = 0;
    if (pipe(p) != 0) {
        fprintf(stderr, "sem-replay: pipe: %s\n", strerror(errno));
        return -1;
    }
    int fd = open_log(log);
    pid_t pid = fork();
    if (pid == 0) {
        close(p[0]);
        child_setup(cwd, p[1], fd, NULL);
        execvp(argv[0], argv);
        fprintf(stderr, "sem-replay: exec %s: %s\n", argv[0], strerror(errno));
        _exit(127);
    }
    close(p[1]);
    if (fd >= 0)
        close(fd);
    bool ok = pid > 0 && drain(p[0], out, len);
    close(p[0]);
    if (pid < 0) {
        fprintf(stderr, "sem-replay: fork %s: %s\n", argv[0], strerror(errno));
        return -1;
    }
    int rc = wait_child(pid, sr_now(), NULL);
    return ok ? rc : -1;
}

/* ── files ────────────────────────────────────────────────────────────── */

bool sr_read_file(const char *path, char **out, size_t *len)
{
    *out = NULL;
    *len = 0;
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return false;
    errno = 0;
    bool ok = drain(fd, out, len);
    int read_errno = errno;
    close(fd);
    if (!ok)
        errno = read_errno ? read_errno : EIO;
    return ok;
}

bool sr_write_file(const char *path, const char *data, size_t len)
{
    FILE *fp = fopen(path, "wb");
    if (fp == NULL) {
        fprintf(stderr, "sem-replay: write %s: %s\n", path, strerror(errno));
        return false;
    }
    bool ok = fwrite(data, 1, len, fp) == len;
    ok = (fclose(fp) == 0) && ok;
    if (!ok)
        fprintf(stderr, "sem-replay: short write %s\n", path);
    return ok;
}

bool sr_mkdirs(const char *path)
{
    char buf[SR_PATH];
    size_t n = strlen(path);
    if (n == 0 || n >= sizeof(buf))
        return false;
    memcpy(buf, path, n + 1);
    for (size_t i = 1; i <= n; i++) {
        if (buf[i] != '/' && buf[i] != '\0')
            continue;
        char c = buf[i];
        buf[i] = '\0';
        if (mkdir(buf, 0755) != 0 && errno != EEXIST) {
            fprintf(stderr, "sem-replay: mkdir %s: %s\n", buf, strerror(errno));
            return false;
        }
        buf[i] = c;
    }
    return true;
}

bool sr_mkparent(const char *path)
{
    char buf[SR_PATH];
    const char *slash = strrchr(path, '/');
    if (slash == NULL)
        return true;
    size_t n = (size_t)(slash - path);
    if (n == 0 || n >= sizeof(buf))
        return n == 0;
    memcpy(buf, path, n);
    buf[n] = '\0';
    return sr_mkdirs(buf);
}

bool sr_rmtree(const char *path)
{
    struct stat st;
    if (lstat(path, &st) != 0)
        return errno == ENOENT;
    if (!S_ISDIR(st.st_mode))
        return unlink(path) == 0;
    DIR *d = opendir(path);
    if (d == NULL) {
        fprintf(stderr, "sem-replay: opendir %s: %s\n", path, strerror(errno));
        return false;
    }
    bool ok = true;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
            continue;
        char child[SR_PATH];
        int w = snprintf(child, sizeof(child), "%s/%s", path, e->d_name);
        ok = w > 0 && (size_t)w < sizeof(child) && sr_rmtree(child) && ok;
    }
    closedir(d);
    return rmdir(path) == 0 && ok;
}

bool sr_exists(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0;
}

bool sr_hash_file(const char *path, uint8_t out[32])
{
    char *buf = NULL;
    size_t n = 0;
    if (!sr_read_file(path, &buf, &n))
        return false;
    zcl_sha3_256((const unsigned char *)buf, n, out);
    free(buf);
    return true;
}

void sr_hex(const uint8_t in[32], char out[65])
{
    zcl_hex_encode(in, 32, out);
}

/* ── sh word splitting ────────────────────────────────────────────────── */

struct wordbuf {
    char *b;
    size_t n, cap;
};

static bool wb_put(struct wordbuf *w, char c)
{
    if (w->n + 1 >= w->cap) {
        size_t cap = w->cap ? w->cap * 2 : 256;
        char *nb = zcl_realloc(w->b, cap, "sem_replay_wordbuf");
        if (nb == NULL) {
            fprintf(stderr, "sem-replay: out of memory splitting words\n");
            return false;
        }
        w->b = nb;
        w->cap = cap;
    }
    w->b[w->n++] = c;
    return true;
}

/* One character inside double quotes, starting at line[*i]. */
static bool split_dq(const char *line, size_t len, size_t *i,
                     struct wordbuf *w)
{
    char c = line[*i];
    if (c == '\\' && *i + 1 < len && strchr("\"\\$`", line[*i + 1])) {
        (*i)++;
        c = line[*i];
    }
    return wb_put(w, c);
}

/* Returns the index after the word, or len + 1 on failure. */
static size_t split_one(const char *line, size_t len, size_t i,
                        struct wordbuf *w)
{
    char quote = 0;
    for (; i < len; i++) {
        char c = line[i];
        bool ok = true;
        if (quote == '\'')
            ok = c == '\'' ? (quote = 0, true) : wb_put(w, c);
        else if (quote == '"')
            ok = c == '"' ? (quote = 0, true) : split_dq(line, len, &i, w);
        else if (c == ' ' || c == '\t' || c == '\n')
            break;
        else if (c == '\'' || c == '"')
            quote = c;
        else if (c == '\\' && i + 1 < len)
            ok = wb_put(w, line[++i]);
        else
            ok = wb_put(w, c);
        if (!ok)
            return len + 1;
    }
    return quote ? len + 1 : i;
}

bool sr_split_words(const char *line, size_t len, struct sr_strv *out)
{
    struct wordbuf w = {0};
    size_t i = 0;
    bool ok = true;
    while (ok && i < len) {
        if (line[i] == ' ' || line[i] == '\t' || line[i] == '\n') {
            i++;
            continue;
        }
        w.n = 0;
        i = split_one(line, len, i, &w);
        ok = i <= len && sr_strv_pushn(out, w.b ? w.b : "", w.n);
    }
    free(w.b);
    if (!ok)
        fprintf(stderr, "sem-replay: cannot split a recipe line\n");
    return ok;
}

/* ── JSON flattening ──────────────────────────────────────────────────── */

struct flat {
    bool failed;
    char path[1024];
    size_t mark[ZJRP_MAX_DEPTH + 1]; /* path length at each level */
    bool array[ZJRP_MAX_DEPTH + 1];
    uint32_t depth;
    size_t key_len; /* path length before the pending key's value */
    char *scratch;
    size_t scratch_cap;
};

static void flat_append(struct flat *f, const char *s, size_t n)
{
    size_t at = strlen(f->path);
    if (at + n + 2 >= sizeof(f->path))
        return;
    if (at > 0 && s[0] != '[')
        f->path[at++] = '.';
    memcpy(f->path + at, s, n);
    f->path[at + n] = '\0';
}

static void flat_open(struct flat *f, bool array)
{
    if (f->depth >= ZJRP_MAX_DEPTH)
        return;
    if (f->depth > 0 && f->array[f->depth])
        flat_append(f, "[]", 2);
    f->depth++;
    f->array[f->depth] = array;
    f->mark[f->depth] = strlen(f->path);
}

static void flat_close(struct flat *f, sr_json_close_cb cb, void *ctx)
{
    if (f->depth == 0)
        return;
    if (cb != NULL)
        cb(ctx, f->path);
    f->depth--;
    f->path[f->mark[f->depth + 1]] = '\0';
    /* Back to the enclosing container's own path. */
    if (f->depth > 0)
        f->path[f->mark[f->depth]] = '\0';
}

static const char *flat_decode(struct flat *f, const char *text,
                               const zjsonp_event *ev)
{
    size_t need = zjsonp_str_decode(text, ev, NULL, 0);
    if (need == SIZE_MAX) {
        f->failed = true;
        return "";
    }
    if (need + 1 > f->scratch_cap) {
        char *nb = zcl_realloc(f->scratch, need + 1, "sem_replay_json_scratch");
        if (nb == NULL) {
            f->failed = true;
            return "";
        }
        f->scratch = nb;
        f->scratch_cap = need + 1;
    }
    if (zjsonp_str_decode(text, ev, f->scratch, need + 1) != need ||
        memchr(f->scratch, 0, need) != NULL) {
        f->failed = true;
        return "";
    }
    f->scratch[need] = '\0';
    return f->scratch;
}

static void flat_scalar(struct flat *f, const char *text,
                        const zjsonp_event *ev, sr_json_cb cb, void *ctx)
{
    char raw[64];
    const char *value = raw;
    if (ev->kind == ZJRP_STR) {
        value = flat_decode(f, text, ev);
    } else {
        size_t n = ev->len < sizeof(raw) - 1 ? ev->len : sizeof(raw) - 1;
        memcpy(raw, text + ev->off, n);
        raw[n] = '\0';
    }
    if (f->depth > 0 && f->array[f->depth])
        flat_append(f, "[]", 2);
    if (!f->failed)
        cb(ctx, f->path, value);
    f->path[f->mark[f->depth]] = '\0';
}

static void flat_key(struct flat *f, const char *text, const zjsonp_event *ev)
{
    const char *key = flat_decode(f, text, ev);
    size_t n = strlen(key);
    if (f->failed || n >= 256) {
        f->failed = true;
        return;
    }
    f->path[f->mark[f->depth]] = '\0';
    flat_append(f, key, n);
}

bool sr_json_flatten_with_close(const char *text, size_t len, sr_json_cb cb,
                               sr_json_close_cb close_cb, void *ctx)
{
    zjsonp p;
    zjsonp_event ev;
    struct flat f = {0};
    zjsonp_status st;
    zjsonp_init(&p, text, len);
    while ((st = zjsonp_next(&p, &ev)) == ZJRP_OK) {
        if (ev.kind == ZJRP_OBJ_OPEN || ev.kind == ZJRP_ARR_OPEN)
            flat_open(&f, ev.kind == ZJRP_ARR_OPEN);
        else if (ev.kind == ZJRP_OBJ_CLOSE || ev.kind == ZJRP_ARR_CLOSE)
            flat_close(&f, close_cb, ctx);
        else if (ev.kind == ZJRP_KEY)
            flat_key(&f, text, &ev);
        else
            flat_scalar(&f, text, &ev, cb, ctx);
        if (f.failed)
            break;
    }
    free(f.scratch);
    if (f.failed) {
        fprintf(stderr, "sem-replay: JSON string decode refused at byte %zu\n",
                zjsonp_pos(&p));
        return false;
    }
    if (st != ZJRP_DONE)
        fprintf(stderr, "sem-replay: JSON %s at byte %zu\n",
                zjsonp_status_name(st), zjsonp_pos(&p));
    return st == ZJRP_DONE;
}

bool sr_json_flatten(const char *text, size_t len, sr_json_cb cb, void *ctx)
{
    return sr_json_flatten_with_close(text, len, cb, NULL, ctx);
}
