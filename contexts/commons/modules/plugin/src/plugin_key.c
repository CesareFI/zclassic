/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: plugin signing key files: a 32-byte Ed25519 seed that only its
 * owner can read. */

#include "plugin_internal.h"

#include "base/cleanse.h"
#include "base/hex.h"
#include "crypto/ed25519.h"
#include "platform/rng.h"
#include "plugin/plugin_pack.h"

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif
#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif

static enum plugin_status pk_open_failure(void)
{
    if (errno == ENOENT)
        return PLUGIN_ERR_KEY_MISSING;
    return errno == ELOOP ? PLUGIN_ERR_KEY_INSECURE : PLUGIN_ERR_IO;
}

enum plugin_status plugin_key_load(const char *path,
                                   uint8_t seed[PLUGIN_KEY_FILE_BYTES])
{
    struct stat st;
    int fd = path ? open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC) : -1;
    if (fd < 0)
        return path ? pk_open_failure() : PLUGIN_ERR_ARGUMENT;
    enum plugin_status result = PLUGIN_OK;
    if (fstat(fd, &st) != 0)
        result = PLUGIN_ERR_IO;
    else if (!S_ISREG(st.st_mode) || st.st_uid != geteuid() ||
             (st.st_mode & 077) != 0)
        result = PLUGIN_ERR_KEY_INSECURE;
    else if (st.st_size != PLUGIN_KEY_FILE_BYTES)
        result = PLUGIN_ERR_KEY_MALFORMED;
    else if (read(fd, seed, PLUGIN_KEY_FILE_BYTES) != PLUGIN_KEY_FILE_BYTES)
        result = PLUGIN_ERR_IO;
    close(fd);
    if (result != PLUGIN_OK)
        memory_cleanse(seed, PLUGIN_KEY_FILE_BYTES);
    return result;
}

void plugin_key_public(const uint8_t seed[PLUGIN_KEY_FILE_BYTES],
                       uint8_t pk[32])
{
    uint8_t secret[PLUGIN_KEY_FILE_BYTES];
    ed25519_keypair(pk, secret, seed);
    memory_cleanse(secret, sizeof(secret));
}

static enum plugin_status pk_write_new(const char *path,
                                       const uint8_t seed[PLUGIN_KEY_FILE_BYTES])
{
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                  0600);
    if (fd < 0)
        return errno == EEXIST ? PLUGIN_ERR_KEY_EXISTS : PLUGIN_ERR_IO;
    bool ok = write(fd, seed, PLUGIN_KEY_FILE_BYTES) == PLUGIN_KEY_FILE_BYTES &&
              fchmod(fd, 0600) == 0 && fsync(fd) == 0;
    ok = close(fd) == 0 && ok;
    if (!ok)
        (void)unlink(path);
    return ok ? PLUGIN_OK : PLUGIN_ERR_IO;
}

/* Makes the new directory entry durable. */
static bool pk_sync_parent(const char *path)
{
    char dir[PLUGIN_PATH_MAX];
    size_t len = strlen(path);
    if (len >= sizeof(dir))
        return false;
    memcpy(dir, path, len + 1);
    char *slash = strrchr(dir, '/');
    if (!slash)
        return plugin_fsync_dir(".");
    if (slash == dir)
        slash++;
    *slash = '\0';
    return plugin_fsync_dir(dir);
}

enum plugin_status plugin_keygen(const char *key_path,
                                 char public_key[PLUGIN_HEX_PUBLIC_KEY + 1])
{
    uint8_t seed[PLUGIN_KEY_FILE_BYTES], pk[32];
    if (!key_path || !*key_path || !public_key)
        return PLUGIN_ERR_ARGUMENT;
    if (!rng_host_fill(seed, sizeof(seed)))
        return PLUGIN_ERR_IO;
    enum plugin_status st = pk_write_new(key_path, seed);
    if (st == PLUGIN_OK && !pk_sync_parent(key_path)) {
        (void)unlink(key_path);
        st = PLUGIN_ERR_IO;
    }
    if (st == PLUGIN_OK) {
        plugin_key_public(seed, pk);
        zcl_hex_encode(pk, sizeof(pk), public_key);
    }
    memory_cleanse(seed, sizeof(seed));
    return st;
}
