/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: install, switch, rollback and list for the signed plugin store. */

#include "plugin_internal.h"

#include "base/safe_alloc.h"
#include "platform/atomic_link.h"

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define PS_TRUST_FILE "trusted_keys"
#define PS_MANIFEST_SUFFIX ".plugin.json"

struct ps_paths {
    char manifest[PLUGIN_PATH_MAX];
    char sig[PLUGIN_PATH_MAX];
    char exe[PLUGIN_PATH_MAX];
};

static bool ps_is_dir(const char *path)
{
    struct stat st;
    return lstat(path, &st) == 0 && S_ISDIR(st.st_mode);
}

static enum plugin_status ps_read_error(enum plugin_status missing,
                                        enum plugin_status oversize)
{
    if (errno == ENOENT)
        return missing;
    if (errno == EFBIG)
        return oversize;
    return errno == EPERM || errno == ELOOP ? PLUGIN_ERR_TRUST_INSECURE
                                            : PLUGIN_ERR_IO;
}

/* Verify one manifest, signature and executable set end to end. */
static enum plugin_status ps_verify_set(const struct ps_paths *p,
                                        const char *trust, const char *trust_bytes,
                                        size_t trust_len, unsigned flags,
                                        struct plugin_manifest *out)
{
    char *mf = NULL, *sg = NULL;
    size_t mf_len = 0, sg_len = 0;
    char hex[PLUGIN_HEX_SHA3_512 + 1];
    if (!plugin_read_file(p->manifest, PLUGIN_FILE_MAX, flags, &mf, &mf_len))
        return ps_read_error(PLUGIN_ERR_MANIFEST_MISSING,
                             PLUGIN_ERR_MANIFEST_INVALID);
    enum plugin_status st = PLUGIN_OK;
    if (!plugin_read_file(p->sig, PLUGIN_FILE_MAX, flags, &sg, &sg_len))
        st = ps_read_error(PLUGIN_ERR_SIG_MISSING, PLUGIN_ERR_SIG_INVALID);
    if (st == PLUGIN_OK)
        st = trust_bytes
                 ? plugin_verify_manifest_trust(mf, mf_len, sg, sg_len, trust_bytes,
                                                trust_len, out)
                 : plugin_verify_manifest(mf, mf_len, sg, sg_len, trust, out);
    if (st == PLUGIN_OK)
        st = plugin_hash_path(p->exe, flags, hex);
    if (st == PLUGIN_OK && strcmp(hex, out->exe_sha3) != 0)
        st = PLUGIN_ERR_EXE_HASH;
    free(mf);
    free(sg);
    return st;
}

static bool ps_trust_path(const char *root, char *out, size_t cap)
{
    return plugin_join(out, cap, root, PS_TRUST_FILE, NULL, NULL);
}

static bool ps_generation_paths(const char *root, const char *name,
                                const char *generation, struct ps_paths *p)
{
    char dir[PLUGIN_PATH_MAX], leaf[PLUGIN_NAME_MAX + 16];
    if (!plugin_join(dir, sizeof(dir), root, name, "generations", generation))
        return false;
    snprintf(leaf, sizeof(leaf), "%s.plugin.json", name);
    if (!plugin_join(p->manifest, sizeof(p->manifest), dir, leaf, NULL, NULL))
        return false;
    snprintf(leaf, sizeof(leaf), "%s.plugin.sig", name);
    return plugin_join(p->sig, sizeof(p->sig), dir, leaf, NULL, NULL) &&
           plugin_join(p->exe, sizeof(p->exe), dir, name, NULL, NULL);
}

/* The store root, the plugin directory and its generations directory must
 * each be a real directory owned by the user and closed to group and others. */
static enum plugin_status ps_check_chain(const char *root, const char *plugdir)
{
    char gens[PLUGIN_PATH_MAX];
    enum plugin_status st = plugin_check_dir(root);
    if (st == PLUGIN_OK)
        st = plugin_check_dir(plugdir);
    if (st == PLUGIN_OK &&
        !plugin_join(gens, sizeof(gens), plugdir, "generations", NULL, NULL))
        st = PLUGIN_ERR_ARGUMENT;
    if (st == PLUGIN_OK) {
        st = plugin_check_dir(gens);
        if (st == PLUGIN_ERR_NOT_INSTALLED)
            st = PLUGIN_ERR_NO_GENERATION;
    }
    return st;
}

enum plugin_status plugin_check_generation_dirs(const char *root, const char *name,
                                                const char *generation)
{
    char dir[PLUGIN_PATH_MAX], gen_dir[PLUGIN_PATH_MAX];
    if (!plugin_name_valid(name) ||
        !plugin_hex_valid(generation, PLUGIN_HEX_SHA3_512) ||
        !plugin_join(dir, sizeof(dir), root, name, NULL, NULL) ||
        !plugin_join(gen_dir, sizeof(gen_dir), dir, "generations", generation, NULL))
        return PLUGIN_ERR_ARGUMENT;
    enum plugin_status st = ps_check_chain(root, dir);
    if (st != PLUGIN_OK)
        return st;
    st = plugin_check_dir(gen_dir);
    return st == PLUGIN_ERR_NOT_INSTALLED ? PLUGIN_ERR_NO_GENERATION : st;
}

/* Trust comes from the file at trust, or from trust_bytes when given. */
static enum plugin_status ps_verify_generation(const char *root, const char *name,
                                               const char *generation, const char *trust,
                                               const char *trust_bytes, size_t trust_len,
                                               struct plugin_manifest *out)
{
    struct ps_paths p;
    if (!ps_generation_paths(root, name, generation, &p))
        return PLUGIN_ERR_ARGUMENT;
    enum plugin_status st = plugin_check_generation_dirs(root, name, generation);
    if (st != PLUGIN_OK)
        return st;
    st = ps_verify_set(&p, trust, trust_bytes, trust_len, PLUGIN_OPEN_NOFOLLOW, out);
    if (st == PLUGIN_OK &&
        (strcmp(out->name, name) != 0 ||
         (strcmp(out->generation, generation) != 0 &&
          /* generations stored before the id covered the manifest */
          strcmp(out->exe_sha3, generation) != 0)))
        st = PLUGIN_ERR_MANIFEST_INVALID;
    return st;
}

enum plugin_status plugin_verify_generation_manifest(const char *root,
                                                     const char *name,
                                                     const char *generation,
                                                     struct plugin_manifest *out)
{
    char trust[PLUGIN_PATH_MAX];
    if (!ps_trust_path(root, trust, sizeof(trust)))
        return PLUGIN_ERR_ARGUMENT;
    return ps_verify_generation(root, name, generation, trust, NULL, 0, out);
}

enum plugin_status plugin_verify_generation_manifest_trust(const char *root,
                                                           const char *name,
                                                           const char *generation,
                                                           const char *trust,
                                                           size_t trust_len,
                                                           struct plugin_manifest *out)
{
    return ps_verify_generation(root, name, generation, NULL, trust, trust_len, out);
}

enum plugin_status plugin_verify_generation(const char *root, const char *name,
                                            const char *generation)
{
    struct plugin_manifest m;
    return plugin_verify_generation_manifest(root, name, generation, &m);
}

/* Derive sibling signature and executable paths from NAME.plugin.json. */
static enum plugin_status ps_source_paths(const char *manifest_path,
                                          char stem[PLUGIN_NAME_MAX + 1],
                                          struct ps_paths *p)
{
    size_t len = manifest_path ? strlen(manifest_path) : 0;
    size_t suffix = sizeof(PS_MANIFEST_SUFFIX) - 1;
    if (len <= suffix || len >= PLUGIN_PATH_MAX ||
        strcmp(manifest_path + len - suffix, PS_MANIFEST_SUFFIX) != 0)
        return PLUGIN_ERR_ARGUMENT;
    const char *slash = strrchr(manifest_path, '/');
    const char *base = slash ? slash + 1 : manifest_path;
    size_t stem_len = (size_t)(manifest_path + len - suffix - base);
    if (stem_len < 1 || stem_len > PLUGIN_NAME_MAX)
        return PLUGIN_ERR_ARGUMENT;
    memcpy(stem, base, stem_len);
    stem[stem_len] = '\0';
    if (!plugin_name_valid(stem))
        return PLUGIN_ERR_ARGUMENT;
    size_t dir_len = (size_t)(base - manifest_path);
    int a = snprintf(p->manifest, sizeof(p->manifest), "%s", manifest_path);
    int b = snprintf(p->sig, sizeof(p->sig), "%.*s%s.plugin.sig",
                     (int)dir_len, manifest_path, stem);
    int c = snprintf(p->exe, sizeof(p->exe), "%.*s%s", (int)dir_len,
                     manifest_path, stem);
    return a > 0 && b > 0 && c > 0 && (size_t)b < sizeof(p->sig) &&
                   (size_t)c < sizeof(p->exe)
               ? PLUGIN_OK : PLUGIN_ERR_ARGUMENT;
}

/* Copy the verified set into a staging directory and verify the copy. */
static enum plugin_status ps_stage(const struct ps_paths *src, const char *name,
                                   const char *staging, const char *trust,
                                   struct plugin_manifest *m)
{
    struct ps_paths dst;
    char leaf[PLUGIN_NAME_MAX + 16], hex[PLUGIN_HEX_SHA3_512 + 1];
    snprintf(leaf, sizeof(leaf), "%s.plugin.json", name);
    bool ok = plugin_join(dst.manifest, sizeof(dst.manifest), staging, leaf, NULL, NULL);
    snprintf(leaf, sizeof(leaf), "%s.plugin.sig", name);
    ok = ok && plugin_join(dst.sig, sizeof(dst.sig), staging, leaf, NULL, NULL) &&
         plugin_join(dst.exe, sizeof(dst.exe), staging, name, NULL, NULL);
    if (!ok)
        return PLUGIN_ERR_ARGUMENT;
    enum plugin_status st = plugin_copy_file(src->exe, dst.exe, 0555, hex);
    if (st == PLUGIN_OK)
        st = plugin_copy_file(src->manifest, dst.manifest, 0444, hex);
    if (st == PLUGIN_OK)
        st = plugin_copy_file(src->sig, dst.sig, 0444, hex);
    return st == PLUGIN_OK ? ps_verify_set(&dst, trust, NULL, 0, PLUGIN_OPEN_NOFOLLOW, m)
                           : st;
}

/* Move a generation that failed verification aside and put the verified
 * staging copy at its name; on failure the old directory is restored. */
static enum plugin_status ps_replace(const char *gens, const char *staging,
                                     const char *final_dir)
{
    char aside[PLUGIN_PATH_MAX];
    struct stat st;
    bool had = lstat(final_dir, &st) == 0;
    if (had) {
        int n = snprintf(aside, sizeof(aside), "%s.old.%ld", final_dir,
                         (long)getpid());
        if (n <= 0 || (size_t)n >= sizeof(aside) || !plugin_remove_tree(aside) ||
            rename(final_dir, aside) != 0)
            return PLUGIN_ERR_IO;
    }
    if (rename(staging, final_dir) != 0) {
        if (had)
            (void)rename(aside, final_dir);
        return PLUGIN_ERR_IO;
    }
    if (had)
        (void)plugin_remove_tree(aside);
    return plugin_fsync_dir(gens) ? PLUGIN_OK : PLUGIN_ERR_IO;
}

static enum plugin_status ps_publish(const char *plugdir, const char *name,
                                     const struct ps_paths *src,
                                     const char *trust,
                                     struct plugin_manifest *m)
{
    char gens[PLUGIN_PATH_MAX], staging[PLUGIN_PATH_MAX], final_dir[PLUGIN_PATH_MAX];
    char tag[32];
    snprintf(tag, sizeof(tag), "staging.%ld", (long)getpid());
    if (!plugin_join(gens, sizeof(gens), plugdir, "generations", NULL, NULL) ||
        !plugin_join(staging, sizeof(staging), plugdir, tag, NULL, NULL) ||
        !plugin_join(final_dir, sizeof(final_dir), gens, m->generation, NULL, NULL))
        return PLUGIN_ERR_ARGUMENT;
    if (!plugin_mkdirs(gens))
        return PLUGIN_ERR_IO;
    enum plugin_status st = plugin_check_dir(gens);
    if (st == PLUGIN_OK && (!plugin_remove_tree(staging) || !plugin_mkdir_new(staging)))
        st = PLUGIN_ERR_IO;
    if (st == PLUGIN_OK)
        st = ps_stage(src, name, staging, trust, m);
    if (st == PLUGIN_OK)
        st = ps_replace(gens, staging, final_dir);
    if (st != PLUGIN_OK)
        (void)plugin_remove_tree(staging);
    return st;
}

enum plugin_status plugin_store_install(const char *root,
                                        const char *manifest_path,
                                        struct plugin_manifest *out,
                                        int *already_present)
{
    struct ps_paths src;
    char stem[PLUGIN_NAME_MAX + 1], trust[PLUGIN_PATH_MAX], plugdir[PLUGIN_PATH_MAX];
    if (already_present)
        *already_present = 0;
    if (!root || !out)
        return PLUGIN_ERR_ARGUMENT;
    enum plugin_status st = ps_source_paths(manifest_path, stem, &src);
    if (st != PLUGIN_OK)
        return st;
    if (!ps_trust_path(root, trust, sizeof(trust)))
        return PLUGIN_ERR_ARGUMENT;
    if (plugin_check_dir(root) == PLUGIN_ERR_TRUST_INSECURE)
        return PLUGIN_ERR_TRUST_INSECURE;
    st = ps_verify_set(&src, trust, NULL, 0, 0, out);
    if (st == PLUGIN_OK && strcmp(out->name, stem) != 0)
        st = PLUGIN_ERR_MANIFEST_INVALID;
    if (st != PLUGIN_OK)
        return st;
    if (!plugin_join(plugdir, sizeof(plugdir), root, stem, NULL, NULL) ||
        !plugin_mkdirs(plugdir))
        return PLUGIN_ERR_IO;
    st = plugin_check_dir(plugdir);
    if (st != PLUGIN_OK)
        return st;
    if (plugin_verify_generation(root, stem, out->generation) == PLUGIN_OK) {
        if (already_present)
            *already_present = 1;
        return PLUGIN_OK;
    }
    return ps_publish(plugdir, stem, &src, trust, out);
}

static enum plugin_status ps_plugin_dir(const char *root, const char *name,
                                        char *plugdir, size_t cap)
{
    if (!root || !plugin_name_valid(name) ||
        !plugin_join(plugdir, cap, root, name, NULL, NULL))
        return PLUGIN_ERR_ARGUMENT;
    enum plugin_status st = plugin_check_dir(root);
    return st == PLUGIN_OK ? plugin_check_dir(plugdir) : st;
}

static enum plugin_status ps_point(const char *plugdir, const char *link,
                                   const char *generation)
{
    char target[PLUGIN_PATH_MAX], path[PLUGIN_PATH_MAX];
    snprintf(target, sizeof(target), "generations/%s", generation);
    if (!plugin_join(path, sizeof(path), plugdir, link, NULL, NULL))
        return PLUGIN_ERR_ARGUMENT;
    return platform_atomic_symlink(target, path) == 0 ? PLUGIN_OK : PLUGIN_ERR_IO;
}

enum plugin_status plugin_store_switch(const char *root, const char *name,
                                       const char *generation)
{
    char plugdir[PLUGIN_PATH_MAX], previous[PLUGIN_HEX_SHA3_512 + 1];
    enum plugin_status st = ps_plugin_dir(root, name, plugdir, sizeof(plugdir));
    if (st == PLUGIN_OK)
        st = plugin_verify_generation(root, name, generation);
    if (st != PLUGIN_OK)
        return st;
    if (plugin_link_generation(plugdir, "current", previous)) {
        if (strcmp(previous, generation) == 0)
            return PLUGIN_OK;
        st = ps_point(plugdir, "last-good", previous);
    }
    return st == PLUGIN_OK ? ps_point(plugdir, "current", generation) : st;
}

enum plugin_status plugin_store_rollback(const char *root, const char *name,
                                         char restored[PLUGIN_HEX_SHA3_512 + 1])
{
    char plugdir[PLUGIN_PATH_MAX];
    enum plugin_status st = ps_plugin_dir(root, name, plugdir, sizeof(plugdir));
    if (st != PLUGIN_OK)
        return st;
    if (!restored || !plugin_link_generation(plugdir, "last-good", restored))
        return PLUGIN_ERR_NO_LAST_GOOD;
    st = plugin_verify_generation(root, name, restored);
    return st == PLUGIN_OK ? ps_point(plugdir, "current", restored) : st;
}

static int ps_cmp_info(const void *a, const void *b)
{
    const struct plugin_info *x = a, *y = b;
    return strcmp(x->name, y->name);
}

static int ps_cmp_generation(const void *a, const void *b)
{
    return strcmp(a, b);
}

static enum plugin_status ps_load_generations(const char *plugdir,
                                              struct plugin_info *info)
{
    char gens[PLUGIN_PATH_MAX];
    if (!plugin_join(gens, sizeof(gens), plugdir, "generations", NULL, NULL))
        return PLUGIN_ERR_IO;
    DIR *d = opendir(gens);
    if (!d)
        return PLUGIN_OK;
    struct dirent *e;
    size_t cap = 0;
    while ((e = readdir(d)) != NULL) {
        if (!plugin_hex_valid(e->d_name, PLUGIN_HEX_SHA3_512))
            continue;
        if (info->generation_count == cap) {
            cap = cap ? cap * 2 : 4;
            void *grown = zcl_realloc(info->generations,
                                      cap * (PLUGIN_HEX_SHA3_512 + 1),
                                      "plugin_generations");
            if (!grown) {
                closedir(d);
                return PLUGIN_ERR_IO;
            }
            info->generations = grown;
        }
        memcpy(info->generations[info->generation_count++], e->d_name,
               PLUGIN_HEX_SHA3_512 + 1);
    }
    closedir(d);
    qsort(info->generations, info->generation_count, PLUGIN_HEX_SHA3_512 + 1,
          ps_cmp_generation);
    return PLUGIN_OK;
}

static enum plugin_status ps_load_info(const char *root, const char *name,
                                       struct plugin_info *info)
{
    char plugdir[PLUGIN_PATH_MAX];
    memset(info, 0, sizeof(*info));
    snprintf(info->name, sizeof(info->name), "%s", name);
    if (!plugin_join(plugdir, sizeof(plugdir), root, name, NULL, NULL))
        return PLUGIN_ERR_IO;
    if (!plugin_link_generation(plugdir, "current", info->current))
        info->current[0] = '\0';
    if (!plugin_link_generation(plugdir, "last-good", info->last_good))
        info->last_good[0] = '\0';
    return ps_load_generations(plugdir, info);
}

static enum plugin_status ps_collect(DIR *d, const char *root,
                                     struct plugin_info **out, size_t *count)
{
    struct dirent *e;
    size_t cap = 0;
    while ((e = readdir(d)) != NULL) {
        char path[PLUGIN_PATH_MAX];
        if (!plugin_name_valid(e->d_name) ||
            !plugin_join(path, sizeof(path), root, e->d_name, NULL, NULL) ||
            !ps_is_dir(path))
            continue;
        if (*count == cap) {
            cap = cap ? cap * 2 : 8;
            struct plugin_info *grown =
                zcl_realloc(*out, cap * sizeof(**out), "plugin_infos");
            if (!grown)
                return PLUGIN_ERR_IO;
            *out = grown;
        }
        if (ps_load_info(root, e->d_name, &(*out)[*count]) != PLUGIN_OK) {
            free((*out)[*count].generations);
            return PLUGIN_ERR_IO;
        }
        (*count)++;
    }
    return PLUGIN_OK;
}

enum plugin_status plugin_store_list(const char *root,
                                     struct plugin_info **out, size_t *count)
{
    if (!root || !out || !count)
        return PLUGIN_ERR_ARGUMENT;
    *out = NULL;
    *count = 0;
    DIR *d = opendir(root);
    if (!d)
        return errno == ENOENT ? PLUGIN_OK : PLUGIN_ERR_IO;
    enum plugin_status st = ps_collect(d, root, out, count);
    closedir(d);
    if (st != PLUGIN_OK) {
        plugin_store_list_free(*out, *count);
        *out = NULL;
        *count = 0;
        return st;
    }
    qsort(*out, *count, sizeof(**out), ps_cmp_info);
    return PLUGIN_OK;
}

void plugin_store_list_free(struct plugin_info *infos, size_t count)
{
    for (size_t i = 0; infos && i < count; i++)
        free(infos[i].generations);
    free(infos);
}
