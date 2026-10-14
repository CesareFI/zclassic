/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * install_selftest - file, text and environment helpers.
 *
 * Every string returned by isf_fmt and isf_slurp is owned by a process-wide
 * list released by isf_heap_release, so callers never free.
 */
#define _POSIX_C_SOURCE 200809L

#include "install_selftest.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "base/safe_alloc.h"
#include "crypto/sha256.h"

extern char **environ;

constexpr size_t ISF_SLURP_CAP = 256u * 1024u * 1024u;

static void **isf_heap;
static size_t isf_heap_len;
static size_t isf_heap_cap;

static void *isf_own(void *p)
{
    if (isf_heap_len == isf_heap_cap) {
        size_t cap = isf_heap_cap == 0 ? 64 : isf_heap_cap * 2;
        void **grown = zcl_realloc(isf_heap, cap * sizeof *grown, "isf_heap");

        if (grown == nullptr)
            isf_die("out of memory");
        isf_heap = grown;
        isf_heap_cap = cap;
    }
    isf_heap[isf_heap_len++] = p;
    return p;
}

void isf_heap_release(void)
{
    for (size_t i = 0; i < isf_heap_len; i++)
        free(isf_heap[i]);
    free(isf_heap);
    isf_heap = nullptr;
    isf_heap_len = isf_heap_cap = 0;
}

char *isf_vfmt(const char *fmt, va_list ap)
{
    va_list cp;
    int n;
    char *out;

    va_copy(cp, ap);
    n = vsnprintf(nullptr, 0, fmt, cp);
    va_end(cp);
    if (n < 0)
        isf_die("formatting failed");
    out = zcl_malloc((size_t)n + 1, "isf_fmt");
    if (out == nullptr)
        isf_die("out of memory");
    vsnprintf(out, (size_t)n + 1, fmt, ap);
    return isf_own(out);
}

char *isf_fmt(const char *fmt, ...)
{
    va_list ap;
    char *out;

    va_start(ap, fmt);
    out = isf_vfmt(fmt, ap);
    va_end(ap);
    return out;
}

/* ---- environment -------------------------------------------------------- */

static void isf_env_reserve(struct isf_env *env)
{
    char **grown;
    size_t cap;

    if (env->n + 2 <= env->cap)
        return;
    cap = env->cap == 0 ? 64 : env->cap * 2;
    grown = zcl_realloc(env->kv, cap * sizeof *grown, "isf_env");
    if (grown == nullptr)
        isf_die("out of memory");
    for (size_t i = 0; i < isf_heap_len; i++)
        if (isf_heap[i] == env->kv)
            isf_heap[i] = grown;
    if (env->kv == nullptr)
        isf_own(grown);
    env->kv = grown;
    env->cap = cap;
}

static size_t isf_env_find(const struct isf_env *env, const char *key, size_t klen)
{
    for (size_t i = 0; i < env->n; i++)
        if (strncmp(env->kv[i], key, klen) == 0 && env->kv[i][klen] == '=')
            return i;
    return env->n;
}

static void isf_env_put(struct isf_env *env, char *kv, size_t klen)
{
    size_t at = isf_env_find(env, kv, klen);

    isf_env_reserve(env);
    env->kv[at] = kv;
    if (at == env->n)
        env->n++;
    env->kv[env->n] = nullptr;
}

void isf_env_set(struct isf_env *env, const char *key, const char *value)
{
    isf_env_put(env, isf_fmt("%s=%s", key, value), strlen(key));
}

void isf_env_add(struct isf_env *env, const char *key_value)
{
    const char *eq = strchr(key_value, '=');

    if (eq == nullptr)
        isf_die("malformed environment entry: %s", key_value);
    isf_env_put(env, isf_fmt("%s", key_value), (size_t)(eq - key_value));
}

void isf_env_from_environ(struct isf_env *env)
{
    for (char **e = environ; *e != nullptr; e++) {
        const char *eq = strchr(*e, '=');

        if (eq != nullptr)
            isf_env_put(env, isf_fmt("%s", *e), (size_t)(eq - *e));
    }
}

/* ---- reading ------------------------------------------------------------ */

bool isf_is_file(const char *path)
{
    struct stat st;

    return stat(path, &st) == 0 && S_ISREG(st.st_mode);
}

bool isf_file_nonempty(const char *path)
{
    struct stat st;

    return stat(path, &st) == 0 && st.st_size > 0;
}

bool isf_dir_empty(const char *path)
{
    DIR *d = opendir(path);
    bool empty = d != nullptr;

    for (struct dirent *e = d != nullptr ? readdir(d) : nullptr; e != nullptr; e = readdir(d))
        if (strcmp(e->d_name, ".") != 0 && strcmp(e->d_name, "..") != 0)
            empty = false;
    if (d != nullptr)
        closedir(d);
    return empty;
}

char *isf_slurp(const char *path, size_t *len)
{
    FILE *f = fopen(path, "rb");
    size_t cap = 4096, n = 0;
    char *buf = nullptr;

    if (f == nullptr)
        return nullptr;
    for (;;) {
        char *grown = zcl_realloc(buf, cap + 1, "isf_slurp");

        if (grown == nullptr)
            isf_die("out of memory reading %s", path);
        buf = grown;
        n += fread(buf + n, 1, cap - n, f);
        if (n < cap)
            break;
        if (cap >= ISF_SLURP_CAP)
            isf_die("%s is larger than %zu bytes", path, ISF_SLURP_CAP);
        cap *= 2;
    }
    fclose(f);
    buf[n] = '\0';
    *len = n;
    return isf_own(buf);
}

/* The text of a file without trailing newlines, as `$(cat FILE)` yields it;
 * empty when the file cannot be read. */
char *isf_slurp_trim(const char *path)
{
    size_t len = 0;
    char *text = isf_slurp(path, &len);

    if (text == nullptr)
        return "";
    while (len > 0 && text[len - 1] == '\n')
        text[--len] = '\0';
    return text;
}

static const char *isf_memfind(const char *hay, size_t hlen, const char *needle)
{
    size_t nlen = strlen(needle);

    for (size_t i = 0; i + nlen <= hlen; i++)
        if (memcmp(hay + i, needle, nlen) == 0)
            return hay + i;
    return nullptr;
}

/* grep -q NEEDLE FILE for a needle without newlines or metacharacters. */
bool isf_file_has(const char *path, const char *needle)
{
    size_t len = 0;
    const char *text = isf_slurp(path, &len);

    return text != nullptr && isf_memfind(text, len, needle) != nullptr;
}

static bool isf_line_matches(const char *line, size_t len, const char *want)
{
    return strlen(want) == len && memcmp(line, want, len) == 0;
}

/* grep -qx LINE FILE: some whole line equals LINE. */
bool isf_file_has_line(const char *path, const char *line)
{
    size_t len = 0;
    const char *text = isf_slurp(path, &len);
    size_t at = 0;

    while (text != nullptr && at < len) {
        const char *nl = memchr(text + at, '\n', len - at);
        size_t end = nl != nullptr ? (size_t)(nl - text) : len;

        if (isf_line_matches(text + at, end - at, line))
            return true;
        at = end + 1;
    }
    return false;
}

static bool isf_is_lower_hex(const char *s, size_t n)
{
    for (size_t i = 0; i < n; i++)
        if (!((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f')))
            return false;
    return true;
}

static bool isf_is_pin(const char *line, size_t len)
{
    static const char tag[] = "z23-pin-v1:";
    constexpr size_t tag_len = sizeof tag - 1;

    return len == tag_len + 2 * ISF_HEX_LEN + 1 && memcmp(line, tag, tag_len) == 0 &&
           isf_is_lower_hex(line + tag_len, ISF_HEX_LEN) && line[tag_len + ISF_HEX_LEN] == ':' &&
           isf_is_lower_hex(line + tag_len + ISF_HEX_LEN + 1, ISF_HEX_LEN);
}

/* grep -qxE 'z23-pin-v1:[0-9a-f]{64}:[0-9a-f]{64}' FILE. */
bool isf_file_has_pin_line(const char *path)
{
    size_t len = 0;
    const char *text = isf_slurp(path, &len);
    size_t at = 0;

    while (text != nullptr && at < len) {
        const char *nl = memchr(text + at, '\n', len - at);
        size_t end = nl != nullptr ? (size_t)(nl - text) : len;

        if (isf_is_pin(text + at, end - at))
            return true;
        at = end + 1;
    }
    return false;
}

/* The ELF identification: magic, a valid class and data encoding, and the
 * current version, which is what `file -b` needs to report "ELF". */
bool isf_starts_with_elf_magic(const char *path)
{
    static const unsigned char magic[4] = {0x7f, 'E', 'L', 'F'};
    unsigned char head[7];
    FILE *f = fopen(path, "rb");
    bool elf = f != nullptr && fread(head, 1, sizeof head, f) == sizeof head &&
               memcmp(head, magic, sizeof magic) == 0 && (head[4] == 1 || head[4] == 2) &&
               (head[5] == 1 || head[5] == 2) && head[6] == 1;

    if (f != nullptr)
        fclose(f);
    return elf;
}

/* ---- writing ------------------------------------------------------------ */

static bool isf_write_all(int fd, const char *p, size_t n)
{
    while (n > 0) {
        ssize_t w = write(fd, p, n);

        if (w < 0 && errno == EINTR)
            continue;
        if (w <= 0)
            return false;
        p += w;
        n -= (size_t)w;
    }
    return true;
}

bool isf_write_file(const char *path, const char *text, unsigned mode)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, (mode_t)mode);
    bool ok = fd >= 0 && isf_write_all(fd, text, strlen(text)) && fchmod(fd, (mode_t)mode) == 0;

    if (fd >= 0 && close(fd) != 0)
        ok = false;
    return ok;
}

bool isf_copy_file(const char *src, const char *dst)
{
    struct stat st;
    int in = open(src, O_RDONLY);
    int out = -1;
    char buf[65536];
    bool ok = in >= 0 && fstat(in, &st) == 0;

    if (ok)
        out = open(dst, O_WRONLY | O_CREAT | O_TRUNC, st.st_mode & 0777);
    ok = ok && out >= 0;
    for (ssize_t n; ok && (n = read(in, buf, sizeof buf)) != 0;)
        ok = (n > 0 || errno == EINTR) && (n < 0 || isf_write_all(out, buf, (size_t)n));
    if (in >= 0)
        close(in);
    if (out >= 0 && close(out) != 0)
        ok = false;
    return ok;
}

bool isf_mkdir_p(const char *path)
{
    char *copy = isf_fmt("%s", path);

    for (char *p = copy + 1; *p != '\0'; p++) {
        if (*p != '/')
            continue;
        *p = '\0';
        if (mkdir(copy, 0777) != 0 && errno != EEXIST)
            return false;
        *p = '/';
    }
    return mkdir(copy, 0777) == 0 || errno == EEXIST;
}

static bool isf_rm_dir_at(int parent, const char *name)
{
    int fd = openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
    DIR *d = fd >= 0 ? fdopendir(fd) : nullptr;
    bool ok = true;

    if (d == nullptr) {
        if (fd >= 0)
            close(fd);
        return false;
    }
    for (struct dirent *e = readdir(d); e != nullptr; e = readdir(d)) {
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
            continue;
        if (unlinkat(fd, e->d_name, 0) != 0 && errno != ENOENT && !isf_rm_dir_at(fd, e->d_name))
            ok = false;
    }
    closedir(d);
    return unlinkat(parent, name, AT_REMOVEDIR) == 0 && ok;
}

/* rm -rf: a missing path is success, a symbolic link is removed unfollowed. */
bool isf_rm_rf(const char *path)
{
    struct stat st;

    if (lstat(path, &st) != 0)
        return errno == ENOENT;
    if (S_ISDIR(st.st_mode))
        return isf_rm_dir_at(AT_FDCWD, path);
    return unlink(path) == 0;
}

/* ---- digest and lookup -------------------------------------------------- */

bool isf_sha256_hex(const char *path, char out[ISF_HEX_LEN + 1])
{
    struct sha256_ctx ctx;
    unsigned char hash[SHA256_OUTPUT_SIZE], buf[65536];
    FILE *f = fopen(path, "rb");
    size_t n;

    if (f == nullptr)
        return false;
    sha256_init(&ctx);
    while ((n = fread(buf, 1, sizeof buf, f)) > 0)
        sha256_write(&ctx, buf, n);
    fclose(f);
    sha256_finalize(&ctx, hash);
    for (size_t i = 0; i < SHA256_OUTPUT_SIZE; i++)
        snprintf(out + 2 * i, 3, "%02x", hash[i]);
    return true;
}

/* The first executable regular file NAME in the colon-separated PATH_LIST;
 * an empty entry means the current directory. Returns nullptr when absent. */
char *isf_find_in_path(const char *name, const char *path_list)
{
    const char *p = path_list;

    while (p != nullptr) {
        const char *colon = strchr(p, ':');
        size_t dlen = colon != nullptr ? (size_t)(colon - p) : strlen(p);
        char *cand = isf_fmt("%.*s/%s", dlen == 0 ? 1 : (int)dlen, dlen == 0 ? "." : p, name);
        struct stat st;

        if (stat(cand, &st) == 0 && S_ISREG(st.st_mode) && access(cand, X_OK) == 0)
            return cand;
        p = colon != nullptr ? colon + 1 : nullptr;
    }
    return nullptr;
}
