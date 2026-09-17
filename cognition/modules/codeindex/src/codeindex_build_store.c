/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Assemble one deterministic codeindex generation in memory for a
 * platform publisher to commit through its retained directory capability. */

#include "codeindex_priv.h"

#include "base/checked.h"
#include "platform/time_compat.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void ci_source_root_init(struct sha3_256_ctx *sha)
{
    /* v4 admits *.def registries into the exact indexed source universe. */
    static const char domain[] = "zcl.codeindex.source_root.v4";
    sha3_256_init(sha);
    sha3_256_write(sha, (const unsigned char *)domain, sizeof(domain));
}

void ci_source_root_add(struct sha3_256_ctx *sha, const char *relpath,
                        const uint8_t content_sha3[32])
{
    sha3_256_write(sha, (const unsigned char *)relpath, strlen(relpath) + 1);
    sha3_256_write(sha, content_sha3, 32);
}

enum { CI_SOURCE_CACHE_MAX = 96u * 1024u * 1024u };

struct ci_source_cache_span {
    size_t path_offset;
    size_t data_offset;
    size_t data_length;
    uint8_t content_digest[32];
};

struct ci_source_cache {
    char *paths;
    size_t paths_len, paths_cap;
    unsigned char *data;
    size_t data_len, data_cap;
    struct ci_source_cache_span *spans;
    size_t span_count, span_cap, cursor;
    bool complete;
};

static bool source_cache_capacity(size_t paths, size_t data, size_t spans)
{
    size_t span_bytes = 0, total = 0;
    return zcl_size_mul(spans, sizeof(struct ci_source_cache_span),
                        &span_bytes) &&
           zcl_size_add(paths, data, &total) &&
           zcl_size_add(total, span_bytes, &total) &&
           total <= CI_SOURCE_CACHE_MAX;
}

static void source_cache_grown(size_t current, size_t need, size_t initial,
                               size_t *out)
{
    size_t capacity = current ? current : initial;
    while (capacity < need) {
        size_t next = 0;
        if (!zcl_size_mul(capacity, 2u, &next)) {
            capacity = need;
            break;
        }
        capacity = next;
    }
    *out = capacity;
}

static void source_cache_disable(struct ci_source_cache *cache)
{
    if (!cache) return;
    free(cache->paths);
    free(cache->data);
    free(cache->spans);
    cache->paths = NULL;
    cache->data = NULL;
    cache->spans = NULL;
    cache->paths_len = cache->paths_cap = 0;
    cache->data_len = cache->data_cap = 0;
    cache->span_count = cache->span_cap = cache->cursor = 0;
    cache->complete = false;
}

static bool source_cache_reserve_data(struct ci_source_cache *cache,
                                      size_t need)
{
    if (need <= cache->data_cap) return true;
    size_t capacity = 0;
    source_cache_grown(cache->data_cap, need, 16384u, &capacity);
    if (!source_cache_capacity(cache->paths_cap, capacity, cache->span_cap))
        return false;
    void *next = zcl_realloc(cache->data, capacity, "ci_source_cache_data");
    if (!next) return false;
    cache->data = next;
    cache->data_cap = capacity;
    return true;
}

static bool source_cache_reserve_path(struct ci_source_cache *cache,
                                      size_t need)
{
    if (need <= cache->paths_cap) return true;
    size_t capacity = 0;
    source_cache_grown(cache->paths_cap, need, 16384u, &capacity);
    if (!source_cache_capacity(capacity, cache->data_cap, cache->span_cap))
        return false;
    void *next = zcl_realloc(cache->paths, capacity, "ci_source_cache_paths");
    if (!next) return false;
    cache->paths = next;
    cache->paths_cap = capacity;
    return true;
}

static bool source_cache_reserve_span(struct ci_source_cache *cache)
{
    if (cache->span_count < cache->span_cap) return true;
    size_t capacity = 0, bytes = 0;
    source_cache_grown(cache->span_cap, cache->span_count + 1u, 1024u,
                       &capacity);
    if (!source_cache_capacity(cache->paths_cap, cache->data_cap, capacity) ||
        !zcl_size_mul(capacity, sizeof(*cache->spans), &bytes))
        return false;
    void *next = zcl_realloc(cache->spans, bytes, "ci_source_cache_spans");
    if (!next) return false;
    cache->spans = next;
    cache->span_cap = capacity;
    return true;
}

struct ci_source_cache *ci_source_cache_new(void)
{
    struct ci_source_cache *cache =
        zcl_calloc(1, sizeof(*cache), "ci_source_cache");
    if (cache) cache->complete = true;
    return cache;
}

void ci_source_cache_mark_incomplete(struct ci_source_cache *cache)
{
    source_cache_disable(cache);
}

size_t ci_source_cache_mark(const struct ci_source_cache *cache)
{
    return cache && cache->complete ? cache->data_len : 0;
}

void ci_source_cache_append(struct ci_source_cache *cache,
                            const unsigned char *data, size_t length)
{
    if (!cache || !cache->complete || length == 0) return;
    size_t need = 0;
    if (!zcl_size_add(cache->data_len, length, &need) ||
        !source_cache_reserve_data(cache, need)) {
        source_cache_disable(cache);
        return;
    }
    memcpy(cache->data + cache->data_len, data, length);
    cache->data_len = need;
}

void ci_source_cache_rollback(struct ci_source_cache *cache, size_t mark)
{
    if (cache && cache->complete && mark <= cache->data_len)
        cache->data_len = mark;
}

void ci_source_cache_commit(struct ci_source_cache *cache, size_t mark,
                            const char *path, const uint8_t content_digest[32])
{
    if (!cache || !cache->complete) return;
    size_t path_length = 0, path_need = 0;
    if (mark > cache->data_len ||
        !zcl_size_add(strlen(path), 1u, &path_length) ||
        !zcl_size_add(cache->paths_len, path_length, &path_need) ||
        !source_cache_reserve_path(cache, path_need) ||
        !source_cache_reserve_span(cache)) {
        source_cache_disable(cache);
        return;
    }
    struct ci_source_cache_span *span =
        &cache->spans[cache->span_count++];
    span->path_offset = cache->paths_len;
    span->data_offset = mark;
    span->data_length = cache->data_len - mark;
    memcpy(span->content_digest, content_digest,
           sizeof(span->content_digest));
    memcpy(cache->paths + cache->paths_len, path, path_length);
    cache->paths_len = path_need;
}

bool ci_source_cache_is_complete(const struct ci_source_cache *cache,
                                 size_t source_count)
{
    return cache && cache->complete && cache->span_count == source_count;
}

bool ci_source_cache_next(struct ci_source_cache *cache, const char *path,
                          const unsigned char **data, size_t *length,
                          const uint8_t **content_digest)
{
    if (!cache || !path || !data || !length || !content_digest ||
        cache->cursor >= cache->span_count)
        return false;
    const struct ci_source_cache_span *span = &cache->spans[cache->cursor];
    if (span->path_offset >= cache->paths_len ||
        span->data_offset > cache->data_len ||
        span->data_length > cache->data_len - span->data_offset ||
        strcmp(cache->paths + span->path_offset, path) != 0)
        return false;
    *data = span->data_length
        ? cache->data + span->data_offset
        : (const unsigned char *)"";
    *length = span->data_length;
    *content_digest = span->content_digest;
    cache->cursor++;
    return true;
}

bool ci_source_cache_consumed(const struct ci_source_cache *cache)
{
    return !cache || cache->cursor == cache->span_count;
}

void ci_source_cache_free(struct ci_source_cache *cache)
{
    if (!cache) return;
    free(cache->paths);
    free(cache->data);
    free(cache->spans);
    free(cache);
}

struct idmap_ent { size_t path_offset; int64_t id; };
struct build_ctx {
    struct ci_store   *store;
    bool               err;
    struct idmap_ent  *ids;
    size_t             nids, cap_ids;
    char              *id_paths;
    size_t             id_paths_len, id_paths_cap;
    struct sha3_256_ctx source_root;
};

static void on_sym_cb(const struct ci_symbol *sym, void *user)
{
    struct build_ctx *b = user;
    if (!b->err && !ci_store_put_symbol(b->store, sym)) b->err = true;
}

static void ignore_sym_cb(const struct ci_symbol *sym, void *user)
{
    (void)sym;
    (void)user;
}

static void ignore_ref_cb(const char *callee, const char *ref_file,
                          int ref_line, const char *enclosing, void *user)
{
    (void)callee;
    (void)ref_file;
    (void)ref_line;
    (void)enclosing;
    (void)user;
}

static void on_ref_cb(const char *callee, const char *ref_file, int ref_line,
                      const char *enclosing, void *user)
{
    struct build_ctx *b = user;
    if (!b->err && !ci_store_put_ref(b->store, callee, ref_file, ref_line,
                                     enclosing))
        b->err = true;
}

static const char *idmap_path(const struct build_ctx *b, size_t index)
{
    return b->id_paths + b->ids[index].path_offset;
}

static bool idmap_reserve_entry(struct build_ctx *b)
{
    if (b->nids < b->cap_ids) return true;
    size_t ncap = 512, bytes = 0;
    if (b->cap_ids > 0 &&
        !zcl_size_mul(b->cap_ids, 2u, &ncap))
        return false;
    if (!zcl_size_mul(ncap, sizeof(*b->ids), &bytes)) return false;
    void *next = zcl_realloc(b->ids, bytes, "ci_idmap");
    if (!next) return false;
    b->ids = next;
    b->cap_ids = ncap;
    return true;
}

static bool idmap_reserve_path(struct build_ctx *b, size_t length)
{
    size_t need = 0;
    if (!zcl_size_add(b->id_paths_len, length, &need)) return false;
    if (need <= b->id_paths_cap) return true;
    size_t ncap = b->id_paths_cap ? b->id_paths_cap : 16384u;
    while (ncap < need) {
        size_t grown = 0;
        if (!zcl_size_mul(ncap, 2u, &grown)) {
            ncap = need;
            break;
        }
        ncap = grown;
    }
    void *next = zcl_realloc(b->id_paths, ncap, "ci_idmap_paths");
    if (!next) return false;
    b->id_paths = next;
    b->id_paths_cap = ncap;
    return true;
}

static bool idmap_push(struct build_ctx *b, const char *path, int64_t id)
{
    /* ci_enumerate_sources() is the canonical sorted, de-duplicated source
     * stream.  Keep that order instead of sorting hundreds of thousands of
     * fixed-size path records again after the scan.  The explicit check makes
     * an enumeration-contract regression fail closed before binary search can
     * return a wrong dependency owner. */
    if (b->nids > 0 && strcmp(idmap_path(b, b->nids - 1), path) >= 0)
        return false;
    size_t path_len = 0;
    if (!zcl_size_add(strlen(path), 1u, &path_len) ||
        !idmap_reserve_entry(b) || !idmap_reserve_path(b, path_len))
        return false;
    b->ids[b->nids].path_offset = b->id_paths_len;
    b->ids[b->nids].id = id;
    memcpy(b->id_paths + b->id_paths_len, path, path_len);
    b->id_paths_len += path_len;
    b->nids++;
    return true;
}

static int64_t idmap_find(const struct build_ctx *b, const char *path)
{
    size_t lo = 0, hi = b->nids;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        int cmp = strcmp(idmap_path(b, mid), path);
        if (cmp == 0) return b->ids[mid].id;
        if (cmp < 0) lo = mid + 1;
        else hi = mid;
    }
    return -1;
}

struct build_file_env {
    struct build_ctx *build;
    const char *root;
    struct ci_source_cache *source_cache;
};

static bool build_scan_source(struct build_file_env *env, const char *relpath,
                              bool registry, uint8_t sha[32],
                              char purpose[CI_FILE_PURPOSE_MAX])
{
    struct build_ctx *b = env->build;
    ci_sym_cb sym_cb = registry ? ignore_sym_cb : on_sym_cb;
    ci_ref_cb ref_cb = registry ? ignore_ref_cb : on_ref_cb;
    if (!env->source_cache)
        return ci_scan_file(env->root, relpath, sym_cb, ref_cb, b, sha,
                            purpose);
    const unsigned char *data = NULL;
    size_t length = 0;
    const uint8_t *expected = NULL;
    if (!ci_source_cache_next(env->source_cache, relpath, &data, &length,
                              &expected))
        return false;
    ci_test_note_exact_bytes((uint64_t)length);
    return ci_scan_source_bytes(relpath, data, length, sym_cb, ref_cb, b, sha,
                                purpose) &&
           memcmp(sha, expected, 32) == 0;
}

static bool build_file_cb(const char *relpath, const struct stat *file_st,
                          void *user)
{
    struct build_file_env *env = user;
    struct build_ctx *b = env->build;
    if (b->err) return false;

    uint8_t sha[32];
    char purpose[CI_FILE_PURPOSE_MAX] = "";
    bool registry = ci_path_is_registry(relpath);
    if (!build_scan_source(env, relpath, registry, sha, purpose)) {
        b->err = true;
        return false;
    }
    ci_source_root_add(&b->source_root, relpath, sha);

    struct ci_file file;
    memset(&file, 0, sizeof(file));
    (void)snprintf(file.path, sizeof(file.path), "%s", relpath);
    ci_group_for_path(relpath, file.group);
    (void)snprintf(file.purpose, sizeof(file.purpose), "%s", purpose);
#if defined(_WIN32)
    int64_t mtime_ns = (int64_t)file_st->st_mtime * INT64_C(1000000000);
#else
    int64_t mtime_ns = (int64_t)file_st->st_mtim.tv_sec * INT64_C(1000000000) +
                       (int64_t)file_st->st_mtim.tv_nsec;
#endif
    int64_t id = -1;
    if (!ci_store_put_file(b->store, &file, sha, mtime_ns, &id) ||
        !idmap_push(b, relpath, id) ||
        !ci_store_scan_shard_refresh(b->store, relpath)) {
        b->err = true;
        return false;
    }
    return true;
}

static bool build_sources(const char *root, struct build_ctx *build,
                          struct ci_source_cache *source_cache)
{
    struct build_file_env env = {
        .build = build, .root = root, .source_cache = source_cache,
    };
    return ci_enumerate_sources(root, build_file_cb, &env) &&
           !build->err && ci_source_cache_consumed(source_cache);
}

static void on_dep_cb(const char *source, const char *dependency, void *user)
{
    struct build_ctx *b = user;
    if (b->err) return;
    int64_t id = idmap_find(b, source);
    if (id >= 0 && !ci_store_put_include(b->store, id, dependency))
        b->err = true;
}

static bool build_roots_match(const char *root,
                              const uint8_t built_source_root[32],
                              const uint8_t built_dep_root[32],
                              const uint8_t expected_source_root[32],
                              const uint8_t expected_source_stat_root[32],
                              uint8_t source_stat_out[32],
                              uint8_t dep_stat_out[32])
{
    uint8_t current_source_root[32], current_dep_root[32];
    if (expected_source_root && expected_source_stat_root) {
        memcpy(current_source_root, expected_source_root,
               sizeof(current_source_root));
        memcpy(source_stat_out, expected_source_stat_root, 32);
    } else if (!ci_source_roots_sha3(root, current_source_root,
                                     source_stat_out)) {
        LOG_FAIL("codeindex", "source freshness scan failed under %s", root);
    }
    if (memcmp(built_source_root, current_source_root, 32) != 0)
        LOG_FAIL("codeindex", "source root changed during memory build under %s",
                 root);
    if (!ci_deps_scan_roots(root, NULL, NULL, current_dep_root, dep_stat_out))
        LOG_FAIL("codeindex", "dependency freshness scan failed under %s", root);
    if (memcmp(built_dep_root, current_dep_root, 32) != 0)
        LOG_FAIL("codeindex",
                 "dependency root changed during memory build under %s", root);
    return true;
}

static bool write_cold_receipt_and_counts(struct ci_store *store,
                                          int64_t build_start_ms,
                                          size_t nids)
{
    char cold_ms_text[24], cold_files_text[24];
    int64_t cold_ms = platform_time_monotonic_ms() - build_start_ms;
    if (cold_ms < 0) cold_ms = 0;
    int ms_n = snprintf(cold_ms_text, sizeof(cold_ms_text), "%lld",
                        (long long)cold_ms);
    int files_n = snprintf(cold_files_text, sizeof(cold_files_text),
                           "%llu", (unsigned long long)nids);
    return ms_n > 0 && (size_t)ms_n < sizeof(cold_ms_text) &&
           files_n > 0 && (size_t)files_n < sizeof(cold_files_text) &&
           ci_store_meta_set(store, "build_cold_ms", cold_ms_text,
                             (size_t)ms_n) &&
           ci_store_meta_set(store, "build_cold_files", cold_files_text,
                             (size_t)files_n) &&
           ci_store_write_table_count_meta(store);
}

bool ci_build_store_memory(const char *root, int64_t build_start_ms,
                           const uint8_t expected_source_root[32],
                           const uint8_t expected_source_stat_root[32],
                           struct ci_source_cache *source_cache,
                           struct ci_store **out_store,
                           uint8_t source_stat_out[32],
                           uint8_t dep_stat_out[32])
{
    if (!root || !out_store || !source_stat_out || !dep_stat_out)
        LOG_FAIL("codeindex", "null argument to memory store build");
    *out_store = NULL;
    /* The caller stamps the rebuild start when it takes the lock so the
     * self-receipt covers the whole cold build (freshness passes included),
     * not only this assembly phase. A nonpositive stamp means "unknown". */
    if (build_start_ms <= 0)
        build_start_ms = platform_time_monotonic_ms();

    struct ci_store *store = ci_store_open_path(":memory:");
    if (!store) LOG_FAIL("codeindex", "open in-memory staging store failed");
    struct build_ctx build;
    memset(&build, 0, sizeof(build));
    build.store = store;
    ci_source_root_init(&build.source_root);

    bool tx_open = ci_store_begin(store);
    bool ok = tx_open && ci_store_clear(store) && ci_group_emit_all(store);
    if (ok) ok = build_sources(root, &build, source_cache);

    uint8_t built_source_root[32], built_dep_root[32];
    if (ok) {
        sha3_256_finalize(&build.source_root, built_source_root);
        ok = ci_store_meta_set(store, "source_root_sha3", built_source_root,
                               sizeof(built_source_root));
    }
    if (ok)
        ok = ci_deps_scan(root, on_dep_cb, &build, built_dep_root) &&
             !build.err &&
             ci_store_meta_set(store, "dep_root_sha3", built_dep_root,
                               sizeof(built_dep_root));

    if (ok)
        ok = build_roots_match(root, built_source_root, built_dep_root,
                               expected_source_root,
                               expected_source_stat_root, source_stat_out,
                               dep_stat_out);
    if (ok)
        ok = ci_store_meta_set(store, "source_stat_root_sha3",
                               source_stat_out, 32) &&
             ci_store_meta_set(store, "dep_stat_root_sha3", dep_stat_out, 32) &&
             ci_store_meta_set(store, "store_format", CI_STORE_FORMAT,
                               sizeof(CI_STORE_FORMAT) - 1) &&
             ci_store_meta_set(store, "ci_schema_version", CI_SCHEMA_VERSION,
                               sizeof(CI_SCHEMA_VERSION) - 1);

    uint8_t retrieval_projection_root[32];
    if (ok)
        ok = ci_store_retrieval_projection_root(
                 store, retrieval_projection_root) &&
             ci_store_meta_set(store, CI_RETRIEVAL_PROJECTION_META,
                               retrieval_projection_root,
                               sizeof(retrieval_projection_root));

    /* The cold build's self-receipt: the whole-rebuild wall time (from the
     * rebuild-lock stamp the caller passed in) and how many files the exact
     * generation holds. Recorded only on this full-build path — the
     * incremental path clones a prior generation and never rewrites these
     * keys, so they always describe the last cold build. Additive meta keys
     * with a presence check: no store-format change. */
    if (ok)
        ok = write_cold_receipt_and_counts(store, build_start_ms, build.nids);

    if (!ok) {
        if (tx_open) (void)ci_store_rollback(store);
        ci_store_close(store);
        free(build.ids);
        free(build.id_paths);
        LOG_FAIL("codeindex", "source scan or staging write failed");
    }
    if (!ci_store_commit(store)) {
        ci_store_close(store);
        free(build.ids);
        free(build.id_paths);
        LOG_FAIL("codeindex", "commit staging store failed");
    }
    free(build.ids);
    free(build.id_paths);
    *out_store = store;
    return true;
}
