/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: file and encoding helpers shared by the plugin store sources. */
#ifndef ZCL_PLUGIN_INTERNAL_H
#define ZCL_PLUGIN_INTERNAL_H

#include "plugin/plugin_store.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

enum {
    PLUGIN_PATH_MAX = 4096,
    PLUGIN_FILE_MAX = 65536,
    PLUGIN_DIGEST_BYTES = 64
};

bool plugin_name_valid(const char *name);
/* True for exactly len lowercase hex characters (len even, at most 128). */
bool plugin_hex_valid(const char *hex, size_t len);

enum { PLUGIN_OPEN_NOFOLLOW = 1, PLUGIN_OPEN_OWNER_ONLY = 2 };

/* Open a regular file read-only. NOFOLLOW refuses a symbolic link; OWNER_ONLY
 * requires the file to belong to the effective user and not be group or world
 * writable. A refusal returns -1 with errno EPERM or ELOOP. */
int plugin_open_read(const char *path, unsigned flags);

/* Read a whole file of at most max bytes into a NUL-terminated heap buffer.
 * Returns false on error (errno set); too large sets errno to EFBIG. */
bool plugin_read_file(const char *path, size_t max, unsigned flags,
                      char **out, size_t *len);

/* SHA3-512 of a file opened with plugin_open_read flags. */
enum plugin_status plugin_hash_path(const char *path, unsigned flags,
                                    char hex[PLUGIN_HEX_SHA3_512 + 1]);

/* Copy src to dst created exclusively with mode, hashing the bytes written. */
enum plugin_status plugin_copy_file(const char *src, const char *dst,
                                    unsigned mode,
                                    char hex[PLUGIN_HEX_SHA3_512 + 1]);

/* lstat a directory: it must be a real directory owned by the effective user
 * and not group or world writable. Missing is PLUGIN_ERR_NOT_INSTALLED,
 * anything else wrong is PLUGIN_ERR_TRUST_INSECURE. */
enum plugin_status plugin_check_dir(const char *path);

/* fsync a directory so a rename inside it is durable. */
bool plugin_fsync_dir(const char *path);

bool plugin_mkdirs(const char *path);
/* Create one new owner-private directory; false if it exists. */
bool plugin_mkdir_new(const char *path);
bool plugin_join(char *out, size_t cap, const char *a, const char *b,
                 const char *c, const char *d);
bool plugin_remove_tree(const char *path);

/* Parse a "generations/<hex>" link at dir/link into hex. */
bool plugin_link_generation(const char *dir, const char *link,
                            char hex[PLUGIN_HEX_SHA3_512 + 1]);

/* Verify a stored generation directory against the trust file. */
enum plugin_status plugin_verify_generation(const char *root, const char *name,
                                            const char *generation);

#endif
