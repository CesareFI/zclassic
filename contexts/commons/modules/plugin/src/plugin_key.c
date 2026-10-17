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

void plugin_key_public(const uint8_t seed[PLUGIN_KEY_FILE_BYTES],
                       uint8_t pk[32])
{
    uint8_t secret[PLUGIN_KEY_FILE_BYTES];
    ed25519_keypair(pk, secret, seed);
    memory_cleanse(secret, sizeof(secret));
}

#if defined(_WIN32)
#include "platform/directory_transaction.h"
#include "platform/private_file.h"

static enum plugin_status pk_windows_parent(
    const char *path, struct platform_directory_transaction *parent,
    char leaf[PLATFORM_DIRECTORY_CHILD_LEAF_MAX + 1u])
{
    char resolved[PLUGIN_PATH_MAX], directory[PLUGIN_PATH_MAX];
    if (!path || !*path || !platform_private_destination_resolve(
            path, resolved, sizeof(resolved), directory, sizeof(directory)))
        return PLUGIN_ERR_ARGUMENT;
    const char *base = strrchr(resolved, '/');
    const char *back = strrchr(resolved, '\\');
    if (!base || (back && back > base)) base = back;
    base = base ? base + 1 : resolved;
    size_t len = strlen(base);
    if (!len || len > PLATFORM_DIRECTORY_CHILD_LEAF_MAX)
        return PLUGIN_ERR_ARGUMENT;
    memcpy(leaf, base, len + 1u);
    if (!platform_directory_transaction_open(parent, directory))
        return PLUGIN_ERR_KEY_INSECURE;
    return PLUGIN_OK;
}

static enum plugin_status pk_windows_result(enum platform_directory_result r)
{
    if (r == PLATFORM_DIRECTORY_MISSING) return PLUGIN_ERR_KEY_MISSING;
    if (r == PLATFORM_DIRECTORY_EXISTS) return PLUGIN_ERR_KEY_EXISTS;
    if (r == PLATFORM_DIRECTORY_REFUSED) return PLUGIN_ERR_KEY_INSECURE;
    return r == PLATFORM_DIRECTORY_OK ? PLUGIN_OK : PLUGIN_ERR_IO;
}

enum plugin_status plugin_key_load(const char *path,
                                   uint8_t seed[PLUGIN_KEY_FILE_BYTES])
{
    if (!seed) return PLUGIN_ERR_ARGUMENT;
    struct platform_directory_transaction parent;
    struct platform_directory_child file;
    struct platform_directory_child_info info;
    char leaf[PLATFORM_DIRECTORY_CHILD_LEAF_MAX + 1u];
    platform_directory_transaction_init(&parent);
    platform_directory_child_init(&file);
    enum plugin_status st = pk_windows_parent(path, &parent, leaf);
    if (st == PLUGIN_OK)
        st = pk_windows_result(platform_directory_child_open_result(
            &parent, leaf, false, false, &file, NULL));
    if (st == PLUGIN_OK && !platform_directory_child_info(&file, &info))
        st = PLUGIN_ERR_IO;
    if (st == PLUGIN_OK && !info.current_user_only)
        st = PLUGIN_ERR_KEY_INSECURE;
    if (st == PLUGIN_OK && info.size != PLUGIN_KEY_FILE_BYTES)
        st = PLUGIN_ERR_KEY_MALFORMED;
    if (st == PLUGIN_OK && !platform_directory_child_read_exact(
            &file, seed, PLUGIN_KEY_FILE_BYTES, 0))
        st = PLUGIN_ERR_IO;
    platform_directory_child_close(&file);
    platform_directory_transaction_close(&parent);
    if (st != PLUGIN_OK) memory_cleanse(seed, PLUGIN_KEY_FILE_BYTES);
    return st;
}

enum plugin_status plugin_keygen(const char *path,
                                 char public_key[PLUGIN_HEX_PUBLIC_KEY + 1])
{
    if (!path || !*path || !public_key) return PLUGIN_ERR_ARGUMENT;
    uint8_t seed[PLUGIN_KEY_FILE_BYTES] = {0}, pk[32];
    struct platform_directory_transaction parent;
    struct platform_directory_child file;
    char leaf[PLATFORM_DIRECTORY_CHILD_LEAF_MAX + 1u];
    platform_directory_transaction_init(&parent);
    platform_directory_child_init(&file);
    enum plugin_status st = pk_windows_parent(path, &parent, leaf);
    if (st == PLUGIN_OK && !rng_host_fill(seed, sizeof(seed))) st = PLUGIN_ERR_IO;
    if (st == PLUGIN_OK)
        st = pk_windows_result(platform_directory_child_open_result(
            &parent, leaf, true, false, &file, NULL));
    if (st == PLUGIN_OK &&
        (!platform_directory_child_write_exact(&file, seed, sizeof(seed), 0) ||
         !platform_directory_child_flush(&file) ||
         !platform_directory_transaction_flush(&parent)))
        st = PLUGIN_ERR_IO;
    /* A failed durability observation leaves the exclusive private file for
     * reconciliation. Never delete a pathname after authority became unknown. */
    if (st == PLUGIN_OK) {
        plugin_key_public(seed, pk);
        zcl_hex_encode(pk, sizeof(pk), public_key);
    }
    memory_cleanse(seed, sizeof(seed));
    platform_directory_child_close(&file);
    platform_directory_transaction_close(&parent);
    return st;
}
#else
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

#endif
