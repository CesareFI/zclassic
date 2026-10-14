/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: file helpers for the plugin store: bounded reads, hashing copies,
 * directory creation and generation link parsing. */

#include "plugin_internal.h"

#include "base/hex.h"
#include "base/safe_alloc.h"
#include "platform/private_directory.h"
#include "sha3/sha3.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* Hosts without these open flags (Windows) have no symbolic-link or
 * close-on-exec semantics to request; the store is a POSIX feature. */
#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif
#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif
#ifndef O_DIRECTORY
#define O_DIRECTORY 0
#endif

bool plugin_join(char *out, size_t cap, const char *a, const char *b,
                 const char *c, const char *d)
{
    int n = snprintf(out, cap, "%s%s%s%s%s%s%s", a, b ? "/" : "", b ? b : "",
                     c ? "/" : "", c ? c : "", d ? "/" : "", d ? d : "");
    return n > 0 && (size_t)n < cap;
}

int plugin_open_read(const char *path, unsigned flags)
{
    int oflags = O_RDONLY | O_CLOEXEC;
    struct stat st;
    if (flags & PLUGIN_OPEN_NOFOLLOW)
        oflags |= O_NOFOLLOW;
    int fd = open(path, oflags);
    if (fd < 0)
        return -1;
    bool ok = fstat(fd, &st) == 0 && S_ISREG(st.st_mode);
    if (ok && (flags & PLUGIN_OPEN_OWNER_ONLY))
        ok = st.st_uid == geteuid() && (st.st_mode & 022) == 0;
    if (!ok) {
        close(fd);
        errno = EPERM;
        return -1;
    }
    return fd;
}

enum plugin_status plugin_check_dir(const char *path)
{
    struct stat st;
    if (lstat(path, &st) != 0)
        return errno == ENOENT ? PLUGIN_ERR_NOT_INSTALLED : PLUGIN_ERR_IO;
    if (!S_ISDIR(st.st_mode) || st.st_uid != geteuid() ||
        (st.st_mode & 022) != 0)
        return PLUGIN_ERR_TRUST_INSECURE;
    return PLUGIN_OK;
}

bool plugin_fsync_dir(const char *path)
{
    int fd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0)
        return false;
    bool ok = fsync(fd) == 0 || errno == EINVAL;
    close(fd);
    return ok;
}

bool plugin_read_file(const char *path, size_t max, unsigned flags,
                      char **out, size_t *len)
{
    int fd = plugin_open_read(path, flags);
    FILE *f = fd >= 0 ? fdopen(fd, "rb") : NULL;
    if (!f) {
        if (fd >= 0)
            close(fd);
        return false;
    }
    char *buf = zcl_malloc(max + 1, "plugin_read_file");
    if (!buf) {
        fclose(f);
        errno = ENOMEM;
        return false;
    }
    size_t n = fread(buf, 1, max + 1, f);
    bool bad = ferror(f) || n > max;
    fclose(f);
    if (bad) {
        free(buf);
        errno = n > max ? EFBIG : EIO;
        return false;
    }
    buf[n] = '\0';
    *out = buf;
    *len = n;
    return true;
}

static enum plugin_status plugin_hash_stream(FILE *in, FILE *copy,
                                             char hex[PLUGIN_HEX_SHA3_512 + 1])
{
    unsigned char buf[16384], digest[PLUGIN_DIGEST_BYTES];
    struct sha3_512_ctx ctx;
    sha3_512_init(&ctx);
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), in)) > 0) {
        sha3_512_write(&ctx, buf, n);
        if (copy && fwrite(buf, 1, n, copy) != n)
            return PLUGIN_ERR_IO;
    }
    if (ferror(in))
        return PLUGIN_ERR_IO;
    sha3_512_finalize(&ctx, digest);
    zcl_hex_encode(digest, sizeof(digest), hex);
    return PLUGIN_OK;
}

static enum plugin_status plugin_open_failure(void)
{
    if (errno == ENOENT)
        return PLUGIN_ERR_EXE_MISSING;
    return errno == EPERM || errno == ELOOP ? PLUGIN_ERR_TRUST_INSECURE
                                            : PLUGIN_ERR_IO;
}

enum plugin_status plugin_hash_path(const char *path, unsigned flags,
                                    char hex[PLUGIN_HEX_SHA3_512 + 1])
{
    int fd = path ? plugin_open_read(path, flags) : -1;
    if (fd < 0)
        return path ? plugin_open_failure() : PLUGIN_ERR_ARGUMENT;
    FILE *f = fdopen(fd, "rb");
    if (!f) {
        close(fd);
        return PLUGIN_ERR_IO;
    }
    enum plugin_status st = plugin_hash_stream(f, NULL, hex);
    fclose(f);
    return st;
}

enum plugin_status plugin_hash_file(const char *path,
                                    char hex[PLUGIN_HEX_SHA3_512 + 1])
{
    return plugin_hash_path(path, 0, hex);
}

static enum plugin_status plugin_copy_finish(FILE *out)
{
    bool ok = fflush(out) == 0 && fsync(fileno(out)) == 0;
    ok = (fclose(out) == 0) && ok;
    return ok ? PLUGIN_OK : PLUGIN_ERR_IO;
}

enum plugin_status plugin_copy_file(const char *src, const char *dst,
                                    unsigned mode,
                                    char hex[PLUGIN_HEX_SHA3_512 + 1])
{
    int in_fd = plugin_open_read(src, 0);
    if (in_fd < 0)
        return plugin_open_failure();
    FILE *in = fdopen(in_fd, "rb");
    int out_fd = open(dst, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                      (mode_t)mode);
    FILE *out = out_fd >= 0 ? fdopen(out_fd, "wb") : NULL;
    if (!in || !out) {
        if (in)
            fclose(in);
        else
            close(in_fd);
        if (out)
            fclose(out);
        else if (out_fd >= 0)
            close(out_fd);
        return PLUGIN_ERR_IO;
    }
    enum plugin_status st = plugin_hash_stream(in, out, hex);
    fclose(in);
    if (st != PLUGIN_OK) {
        fclose(out);
        return st;
    }
    return plugin_copy_finish(out);
}

bool plugin_mkdirs(const char *path)
{
    char tmp[PLUGIN_PATH_MAX];
    size_t len = strlen(path);
    struct stat st;
    if (len == 0 || len >= sizeof(tmp))
        return false;
    memcpy(tmp, path, len + 1);
    for (size_t i = 1; i <= len; i++) {
        if (tmp[i] != '/' && tmp[i] != '\0')
            continue;
        char saved = tmp[i];
        tmp[i] = '\0';
        bool present = stat(tmp, &st) == 0 && S_ISDIR(st.st_mode);
        if (!present && !platform_private_directory_create(tmp))
            return false;
        tmp[i] = saved;
    }
    return true;
}

bool plugin_mkdir_new(const char *path)
{
    return platform_private_directory_create(path);
}

bool plugin_remove_tree(const char *path)
{
    struct stat st;
    if (lstat(path, &st) != 0)
        return errno == ENOENT;
    if (!S_ISDIR(st.st_mode))
        return unlink(path) == 0;
    DIR *d = opendir(path);
    if (!d)
        return false;
    bool ok = true;
    struct dirent *e;
    while (ok && (e = readdir(d)) != NULL) {
        char child[PLUGIN_PATH_MAX];
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
            continue;
        ok = plugin_join(child, sizeof(child), path, e->d_name, NULL, NULL) &&
             plugin_remove_tree(child);
    }
    closedir(d);
    return ok && rmdir(path) == 0;
}

bool plugin_link_generation(const char *dir, const char *link,
                            char hex[PLUGIN_HEX_SHA3_512 + 1])
{
    static const char prefix[] = "generations/";
    char path[PLUGIN_PATH_MAX], target[PLUGIN_PATH_MAX];
    if (!plugin_join(path, sizeof(path), dir, link, NULL, NULL))
        return false;
    ssize_t n = readlink(path, target, sizeof(target) - 1);
    if (n < 0)
        return false;
    target[n] = '\0';
    if (strncmp(target, prefix, sizeof(prefix) - 1) != 0 ||
        !plugin_hex_valid(target + sizeof(prefix) - 1, PLUGIN_HEX_SHA3_512))
        return false;
    memcpy(hex, target + sizeof(prefix) - 1, PLUGIN_HEX_SHA3_512 + 1);
    return true;
}
