/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: signed plugin store under ~/.z23/plugins. A plugin executable is
 * installed only when its manifest is strictly formed, its detached Ed25519
 * signature verifies against a locally trusted key, and the executable
 * matches the manifest SHA3-512. Generations are content addressed;
 * "current" and "last-good" are symbolic links replaced atomically.
 * docs/PLUGINS.md is the operator-facing description. */
#ifndef ZCL_PLUGIN_STORE_H
#define ZCL_PLUGIN_STORE_H

#include <stddef.h>
#include <stdint.h>

enum {
    PLUGIN_NAME_MAX = 32,
    PLUGIN_VERSION_MAX = 64,
    PLUGIN_HEX_SHA3_512 = 128
};

enum plugin_status {
    PLUGIN_OK = 0,
    PLUGIN_ERR_ARGUMENT,
    PLUGIN_ERR_NO_TRUST,
    PLUGIN_ERR_TRUST_MALFORMED,
    PLUGIN_ERR_MANIFEST_MISSING,
    PLUGIN_ERR_MANIFEST_INVALID,
    PLUGIN_ERR_MANIFEST_DUPLICATE_KEY,
    PLUGIN_ERR_MANIFEST_UNKNOWN_KEY,
    PLUGIN_ERR_SIG_MISSING,
    PLUGIN_ERR_SIG_INVALID,
    PLUGIN_ERR_SIG_ALG,
    PLUGIN_ERR_KEY_UNTRUSTED,
    PLUGIN_ERR_SIG_BAD,
    PLUGIN_ERR_EXE_MISSING,
    PLUGIN_ERR_EXE_HASH,
    PLUGIN_ERR_NOT_INSTALLED,
    PLUGIN_ERR_NO_GENERATION,
    PLUGIN_ERR_NO_LAST_GOOD,
    PLUGIN_ERR_IO,
    PLUGIN_ERR_TRUST_INSECURE,
    PLUGIN_ERR_KEY_MISSING,
    PLUGIN_ERR_KEY_INSECURE,
    PLUGIN_ERR_KEY_MALFORMED,
    PLUGIN_ERR_KEY_EXISTS
};

/* Stable refusal code, for example "PLUGIN_KEY_UNTRUSTED". */
const char *plugin_status_code(enum plugin_status status);

/* The operator action that resolves the refusal. */
const char *plugin_status_next_action(enum plugin_status status);

struct plugin_manifest {
    char name[PLUGIN_NAME_MAX + 1];
    char version[PLUGIN_VERSION_MAX + 1];
    int64_t interface_version;
    char exe_sha3[PLUGIN_HEX_SHA3_512 + 1];
    unsigned capabilities; /* bit i is the i-th entry of plugin_capability_name */
};

/* Fixed capability vocabulary; index is the bit position. NULL past the end. */
const char *plugin_capability_name(unsigned index);

/* Strict parse of NAME.plugin.json bytes. Unknown keys, duplicate keys,
 * malformed values and capabilities outside the vocabulary are refused. */
enum plugin_status plugin_manifest_parse(const char *bytes, size_t len,
                                         struct plugin_manifest *out);

/* Verify manifest bytes against the detached signature bytes and the trust
 * file at trust_path. Succeeds only for a well-formed manifest signed by a
 * trusted key. On success fills out. */
enum plugin_status plugin_verify_manifest(const char *manifest, size_t manifest_len,
                                          const char *sig, size_t sig_len,
                                          const char *trust_path,
                                          struct plugin_manifest *out);

/* SHA3-512 of a file as 128 lowercase hex characters plus terminator. */
enum plugin_status plugin_hash_file(const char *path,
                                    char hex[PLUGIN_HEX_SHA3_512 + 1]);

/* Install the plugin described by manifest_path (NAME.plugin.json). The
 * signature is NAME.plugin.sig and the executable is NAME, both in the same
 * directory. root is the plugin store, normally ~/.z23/plugins. Installing
 * does not change the current link. already_present is set when the
 * generation was stored earlier. */
enum plugin_status plugin_store_install(const char *root,
                                        const char *manifest_path,
                                        struct plugin_manifest *out,
                                        int *already_present);

/* Make generation (128 hex characters) the current one, recording the
 * previous current generation as last-good. The generation is verified again
 * first. */
enum plugin_status plugin_store_switch(const char *root, const char *name,
                                       const char *generation);

/* Make the last-good generation current. restored receives its id. */
enum plugin_status plugin_store_rollback(const char *root, const char *name,
                                         char restored[PLUGIN_HEX_SHA3_512 + 1]);

struct plugin_info {
    char name[PLUGIN_NAME_MAX + 1];
    char current[PLUGIN_HEX_SHA3_512 + 1];   /* empty when unset */
    char last_good[PLUGIN_HEX_SHA3_512 + 1]; /* empty when unset */
    char (*generations)[PLUGIN_HEX_SHA3_512 + 1];
    size_t generation_count;
};

/* List installed plugins, sorted by name, generations sorted by id. */
enum plugin_status plugin_store_list(const char *root,
                                     struct plugin_info **out, size_t *count);
void plugin_store_list_free(struct plugin_info *infos, size_t count);

#endif
