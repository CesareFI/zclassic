/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: Derive, sign, and verify the per-pair mandatory coverage
 *          manifest that binds executed test groups to eligible signed
 *          observations. */
#include "dev_proof_coverage.h"

#include "dev_proof_signer.h"

#include "base/hex.h"
#include "base/safe_alloc.h"
#include "base/serialize_le.h"
#include "platform/directory_compat.h"
#include "sha3/sha3.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Envelope wire layout, little-endian integers (see header):
 *   0   magic[8] = "Z23COV1\0"
 *   8   version u32 = 1
 *   12  policy_version u32
 *   16  row_count u32
 *   20  blob_len u32
 *   24  coverage_root[32]
 *   56  child_set_root[32]
 *   88  impact_policy_root[32]
 *   120 local_commit[32]
 *   152 local_commit_len u8
 *   153 remote_base_len u8
 *   154 reserved[2] = zero
 *   156 remote_base[32]
 *   188 reserved[44] = zero
 *   232 signer_pubkey[32]
 *   264 signature[64]
 * The Ed25519 message is domain "zcl.dev_proof_coverage_sig.v1" followed by
 * bytes [0,232). The coverage root is SHA3-256 over domain
 * "zcl.dev_proof_coverage.v1" followed by the canonical blob bytes. */
#define COV_OFF_VERSION 8u
#define COV_OFF_POLICY_VERSION 12u
#define COV_OFF_ROW_COUNT 16u
#define COV_OFF_BLOB_LEN 20u
#define COV_OFF_COVERAGE_ROOT 24u
#define COV_OFF_CHILD_SET_ROOT 56u
#define COV_OFF_IMPACT_ROOT 88u
#define COV_OFF_LOCAL 120u
#define COV_OFF_LOCAL_LEN 152u
#define COV_OFF_BASE_LEN 153u
#define COV_OFF_BASE 156u
#define COV_OFF_PUBKEY 232u

static const uint8_t COVERAGE_DOMAIN[] = "zcl.dev_proof_coverage.v1";
static const uint8_t COVERAGE_SIGN_DOMAIN[] = "zcl.dev_proof_coverage_sig.v1";

/* The observation CAS layout owned by vcs_object.c. This module only READS
 * it; the layout knowledge stays in one place (vcs_object.c is the write
 * authority) and one reader here. */
#define COV_OBJECTS_SUBDIR ".zvcs/objects"
#define COV_LEAF_HEX (ZCL_DEV_PROOF_ROOT_BYTES * 2u)
#define COV_SHARD_HEX 2u
#define COV_NAME_HEX (COV_LEAF_HEX - COV_SHARD_HEX)

static bool cov_fail(char *why, size_t cap, const char *token)
{
    if (why && cap) (void)snprintf(why, cap, "%s", token);
    return false;
}

static bool cov_fail_group(char *why, size_t cap, const char *token,
                           const char *group)
{
    if (why && cap) (void)snprintf(why, cap, "%s:%s", token, group);
    return false;
}

static bool cov_root_is_zero(const uint8_t root[ZCL_DEV_PROOF_ROOT_BYTES])
{
    static const uint8_t zero[ZCL_DEV_PROOF_ROOT_BYTES] = {0};
    return memcmp(root, zero, sizeof(zero)) == 0;
}

/* ── Runner-log parsing ────────────────────────────────────────────────
 * The runner prints one canonical line per executed group (see
 * emit_group_observations in tests/harness/src/test_parallel.c). The line
 * IS the worker's record of what had to run; the durable CAS is the
 * evidence that what it recorded actually persisted. */

static bool cov_line_has_prefix(const char *line, const char *prefix)
{
    return strncmp(line, prefix, strlen(prefix)) == 0;
}

static bool cov_row_set_group(struct zcl_dev_coverage_log_row *row,
                              const char *group)
{
    size_t group_len = strlen(group);
    if (group_len == 0 || group_len > ZCL_DEV_VERDICT_LEAF_GROUP_MAX)
        return false;
    (void)memcpy(row->group, group, group_len + 1);
    row->group_len = (uint8_t)group_len;
    return true;
}

/* An executed group the runner minted no reusable observation for, exactly
 * as --collect-observations prints it (emit_group_observations in
 * tests/harness/src/test_parallel.c):
 *   OBSERVATION UNQUALIFIED group=<name> reason=<token> coverage=missing
 * It still counts toward the executed set; it carries no key and no root. */
static bool cov_parse_unqualified(const char *line,
    struct zcl_dev_coverage_log_row *row, char *why, size_t why_len)
{
    char group[ZCL_DEV_VERDICT_LEAF_GROUP_BYTES] = {0};
    char reason[64] = {0};
    char coverage[16] = {0};
    int fields = sscanf(line,
                        "OBSERVATION UNQUALIFIED group=%127[A-Za-z0-9_] "
                        "reason=%63[a-z_] coverage=%15[a-z]",
                        group, reason, coverage);
    if (fields != 3 || strcmp(coverage, "missing") != 0)
        return cov_fail(why, why_len, ZCL_DEV_COVERAGE_WHY_LOG_INVALID);
    if (!cov_row_set_group(row, group))
        return cov_fail(why, why_len, ZCL_DEV_COVERAGE_WHY_LOG_INVALID);
    row->unqualified = true;
    return true;
}

static bool cov_parse_observation(const char *line,
    struct zcl_dev_coverage_log_row *row, bool *refused,
    char *why, size_t why_len)
{
    char group[ZCL_DEV_VERDICT_LEAF_GROUP_BYTES] = {0};
    char verdict[8] = {0};
    char key_hex[ZCL_DEV_VERDICT_LEAF_KEY_BYTES * 2 + 1] = {0};
    char root_hex[ZCL_DEV_PROOF_ROOT_BYTES * 2 + 1] = {0};
    char source[40] = {0};
    *refused = false;
    if (cov_line_has_prefix(line, "OBSERVATION REFUSE ")) {
        *refused = true;
        return true;
    }
    if (cov_line_has_prefix(line, "OBSERVATION UNQUALIFIED "))
        return cov_parse_unqualified(line, row, why, why_len);
    int fields = sscanf(line,
                        "OBSERVATION group=%127[A-Za-z0-9_] verdict=%7[A-Z] "
                        "key=%64[0-9a-f] root=%64[0-9a-f] source=%39s",
                        group, verdict, key_hex, root_hex, source);
    if (fields != 5 || strcmp(source, "independent_execution") != 0)
        return cov_fail(why, why_len, ZCL_DEV_COVERAGE_WHY_LOG_INVALID);
    if (strcmp(verdict, "PASS") != 0)
        return cov_fail(why, why_len, ZCL_DEV_COVERAGE_WHY_OBSERVATION_FAIL);
    if (!cov_row_set_group(row, group) ||
        !zcl_hex_decode(key_hex, row->key, ZCL_DEV_VERDICT_LEAF_KEY_BYTES) ||
        !zcl_hex_decode(root_hex, row->root, ZCL_DEV_PROOF_ROOT_BYTES) ||
        cov_root_is_zero(row->key))
        return cov_fail(why, why_len, ZCL_DEV_COVERAGE_WHY_LOG_INVALID);
    return true;
}

/* Account one runner-log line: parse, refuse, dedupe, append. Every refusal
 * is named in `why`; a false return means the log is not usable. */
static bool cov_log_account_line(const char *at,
    struct zcl_dev_coverage_log_row *rows, uint32_t *count, uint32_t rows_cap,
    char *why, size_t why_len)
{
    struct zcl_dev_coverage_log_row row = {0};
    bool refused = false;
    if (!cov_parse_observation(at, &row, &refused, why, why_len))
        return false;
    if (refused)
        return cov_fail(why, why_len, ZCL_DEV_COVERAGE_WHY_OBSERVATION_REFUSED);
    for (uint32_t i = 0; i < *count; i++) {
        if (rows[i].group_len == row.group_len &&
            memcmp(rows[i].group, row.group, row.group_len) == 0)
            return cov_fail(why, why_len, ZCL_DEV_COVERAGE_WHY_LOG_DUPLICATE);
    }
    if (*count >= rows_cap || *count >= ZCL_DEV_COVERAGE_MAX_ROWS)
        return cov_fail(why, why_len, ZCL_DEV_COVERAGE_WHY_COUNT_MISMATCH);
    rows[*count] = row;
    (*count)++;
    return true;
}

/* Scan one open runner log: every canonical observation line is accounted;
 * anything else in the log is ignored. The test-dimension log also carries
 * every group's own output, so two things are load-bearing here. A line is
 * canonical only when "OBSERVATION " is the first thing on it: the same
 * rule dp_test_verdict_read applies to SUITE VERDICT, and a group that
 * merely mentions the word mid-line cannot add or refuse a row. And a
 * foreign line may be arbitrarily long (make echoes multi-kilobyte source
 * lists), so the tail of an over-long line is skipped as a continuation,
 * never mistaken for a line start and never a reason to refuse the log.
 * Embedded NUL invalidates any record. A bounded final canonical record
 * without LF is parsed at clean EOF; incomplete fields still refuse. */
#define COV_LOG_LINE_BYTES 1024u
static size_t cov_log_chunk(FILE *f, char line[COV_LOG_LINE_BYTES])
{
    size_t len = 0;
    int byte;
    while (len < COV_LOG_LINE_BYTES - 1u && (byte = fgetc(f)) != EOF) {
        line[len++] = (char)byte;
        if (byte == '\n') break;
    }
    line[len] = 0;
    return len;
}

static bool cov_log_scan(FILE *f, struct zcl_dev_coverage_log_row *rows,
    uint32_t rows_cap, uint32_t *count, char *why, size_t why_len)
{
    char line[COV_LOG_LINE_BYTES];
    bool continuation = false;
    size_t len;
    while ((len = cov_log_chunk(f, line)) != 0) {
        if (memchr(line, 0, len))
            return cov_fail(why, why_len, ZCL_DEV_COVERAGE_WHY_LOG_INVALID);
        bool terminated = len > 0 && line[len - 1] == '\n';
        bool line_start = !continuation;
        continuation = !terminated;
        if (!line_start || !cov_line_has_prefix(line, "OBSERVATION ") ||
            cov_line_has_prefix(line, "OBSERVATION COVERAGE "))
            continue; /* group output, suite verdicts, the runner's own
                       * coverage summary */
        if (!terminated && !(feof(f) && !ferror(f) && len < sizeof(line) - 1u))
            return cov_fail(why, why_len, ZCL_DEV_COVERAGE_WHY_LOG_INVALID);
        if (!cov_log_account_line(line, rows, count, rows_cap,
                                  why, why_len))
            return false;
    }
    if (ferror(f))
        return cov_fail(why, why_len, ZCL_DEV_COVERAGE_WHY_LOG_UNAVAILABLE);
    return true;
}

bool zcl_dev_coverage_log_rows(const char *log_path, uint32_t expected,
    struct zcl_dev_coverage_log_row *rows, uint32_t rows_cap,
    uint32_t *out_count, char *why, size_t why_len)
{
    if (!out_count || (expected && (!log_path || !log_path[0])) ||
        (rows_cap && !rows) || expected > ZCL_DEV_COVERAGE_MAX_ROWS)
        return cov_fail(why, why_len, ZCL_DEV_COVERAGE_WHY_ARGUMENTS);
    *out_count = 0;
    if (expected == 0) return true;
    FILE *f = fopen(log_path, "r");
    if (!f) return cov_fail(why, why_len, ZCL_DEV_COVERAGE_WHY_LOG_UNAVAILABLE);
    bool ok = cov_log_scan(f, rows, rows_cap, out_count, why, why_len);
    (void)fclose(f);
    if (!ok) return false;
    if (*out_count != expected)
        return cov_fail(why, why_len, ZCL_DEV_COVERAGE_WHY_COUNT_MISMATCH);
    return true;
}

/* ── Observation CAS enumeration ─────────────────────────────────────── */

struct cov_leaf {
    uint8_t root[ZCL_DEV_PROOF_ROOT_BYTES];
    struct zcl_dev_verdict_leaf_v1 leaf;
    bool eligible;
};

struct cov_store {
    struct cov_leaf *leaves;
    size_t count;
    bool present;
};

static void cov_store_release(struct cov_store *store)
{
    if (!store) return;
    free(store->leaves);
    memset(store, 0, sizeof(*store));
}

static bool cov_leaf_group_matches(const struct zcl_dev_verdict_leaf_v1 *leaf,
                                   uint8_t group_len, const char *group)
{
    return leaf->group_len == group_len &&
           memcmp(leaf->group, group, group_len) == 0;
}

static bool cov_store_load_leaf(const char *path,
    const uint8_t root[ZCL_DEV_PROOF_ROOT_BYTES],
    struct zcl_dev_verdict_leaf_v1 *leaf, bool *eligible)
{
    *eligible = false;
    FILE *f = fopen(path, "rb");
    if (!f) return false;
    uint8_t wire[ZCL_DEV_VERDICT_LEAF_WIRE_BYTES];
    size_t got = fread(wire, 1, sizeof(wire), f);
    int extra = fgetc(f);
    (void)fclose(f);
    if (got != sizeof(wire) || extra != EOF) return false;
    char why[80];
    uint8_t derived[ZCL_DEV_PROOF_ROOT_BYTES];
    if (!zcl_dev_verdict_leaf_parse(wire, sizeof(wire), leaf,
                                    why, sizeof(why)) ||
        !zcl_dev_verdict_leaf_root(leaf, derived, why, sizeof(why)) ||
        memcmp(derived, root, sizeof(derived)) != 0)
        return false;
    char group[ZCL_DEV_VERDICT_LEAF_GROUP_BYTES];
    (void)memcpy(group, leaf->group, leaf->group_len);
    group[leaf->group_len] = 0;
    *eligible = zcl_dev_verdict_leaf_verify(leaf, leaf->key, group,
                                            why, sizeof(why));
    return true;
}

/* One shard of the store: every listed file must be a well-formed addressed
 * leaf; one corrupt object makes the whole projection incomplete. */
static bool cov_enumerate_shard(struct cov_store *store, size_t *cap,
    const char *shard_path, const char *shard_name,
    char *why, size_t why_len)
{
    struct platform_directory_list files = {0};
    if (!platform_directory_list_regular_sorted(shard_path, &files))
        return cov_fail(why, why_len, ZCL_DEV_COVERAGE_WHY_STORE_INCOMPLETE);
    bool ok = true;
    for (size_t i = 0; i < files.count && ok; i++) {
        if (strlen(shard_name) != COV_SHARD_HEX ||
            strlen(files.entries[i].name) != COV_NAME_HEX) {
            ok = cov_fail(why, why_len, ZCL_DEV_COVERAGE_WHY_STORE_INCOMPLETE);
            break;
        }
        if (store->count >= ZCL_DEV_COVERAGE_MAX_ROWS) {
            ok = cov_fail(why, why_len, ZCL_DEV_COVERAGE_WHY_STORE_TOO_MANY);
            break;
        }
        if (store->count == *cap) {
            *cap *= 2;
            struct cov_leaf *grown =
                zcl_realloc(store->leaves, *cap * sizeof(*store->leaves),
                            "dev-coverage-leaves-grow");
            if (!grown) {
                ok = cov_fail(why, why_len,
                              ZCL_DEV_COVERAGE_WHY_STORE_INCOMPLETE);
                break;
            }
            store->leaves = grown;
        }
        struct cov_leaf *slot = &store->leaves[store->count];
        char hex[COV_LEAF_HEX + 1];
        (void)memcpy(hex, shard_name, COV_SHARD_HEX);
        (void)memcpy(hex + COV_SHARD_HEX, files.entries[i].name,
                     COV_NAME_HEX);
        hex[COV_LEAF_HEX] = 0;
        char leaf_path[4096];
        int n = snprintf(leaf_path, sizeof(leaf_path), "%s/%s", shard_path,
                         files.entries[i].name);
        if (n < 0 || n >= (int)sizeof(leaf_path) ||
            !zcl_hex_decode(hex, slot->root, ZCL_DEV_PROOF_ROOT_BYTES) ||
            !cov_store_load_leaf(leaf_path, slot->root, &slot->leaf,
                                 &slot->eligible))
            ok = cov_fail(why, why_len, ZCL_DEV_COVERAGE_WHY_STORE_INCOMPLETE);
        else
            store->count++;
    }
    platform_directory_list_free(&files);
    return ok;
}

static bool cov_store_enumerate_objects(const char *objects_path,
    struct cov_store *store, char *why, size_t why_len);

/* A complete local projection of the per-pair observation CAS. Every
 * listed object must load, re-derive to its address, and parse as a leaf;
 * one corrupt object makes the whole projection incomplete, exactly like a
 * missing chunk in a receiver index. Signature eligibility is decided per
 * leaf but does not affect completeness. */
static bool cov_store_enumerate(const char *store_root, struct cov_store *store,
                                char *why, size_t why_len)
{
    memset(store, 0, sizeof(*store));
    if (!store_root || !store_root[0])
        return cov_fail(why, why_len, ZCL_DEV_COVERAGE_WHY_ARGUMENTS);
    enum platform_directory_probe_result probe =
        platform_directory_probe_real(store_root);
    if (probe == PLATFORM_DIRECTORY_PROBE_REFUSED)
        return cov_fail(why, why_len, ZCL_DEV_COVERAGE_WHY_STORE_INCOMPLETE);
    if (probe == PLATFORM_DIRECTORY_PROBE_MISSING) return true; /* absent */
    store->present = true;

    char objects_path[4096];
    if (snprintf(objects_path, sizeof(objects_path), "%s/%s", store_root,
                 COV_OBJECTS_SUBDIR) >= (int)sizeof(objects_path))
        return cov_fail(why, why_len, ZCL_DEV_COVERAGE_WHY_ARGUMENTS);
    /* A store root that never received a leaf has no object tree yet (a
     * proof whose every executed group was unqualified): complete and empty,
     * not incomplete. */
    enum platform_directory_probe_result objects =
        platform_directory_probe_real(objects_path);
    if (objects == PLATFORM_DIRECTORY_PROBE_MISSING) return true;
    if (objects == PLATFORM_DIRECTORY_PROBE_REFUSED)
        return cov_fail(why, why_len, ZCL_DEV_COVERAGE_WHY_STORE_INCOMPLETE);
    return cov_store_enumerate_objects(objects_path, store, why, why_len);
}

static bool cov_store_enumerate_objects(const char *objects_path,
    struct cov_store *store, char *why, size_t why_len)
{
    struct platform_directory_list shards = {0};
    if (!platform_directory_list_real_sorted(objects_path, &shards))
        return cov_fail(why, why_len, ZCL_DEV_COVERAGE_WHY_STORE_INCOMPLETE);
    size_t cap = 256;
    store->leaves = zcl_malloc(cap * sizeof(*store->leaves),
                               "dev-coverage-leaves");
    if (!store->leaves) {
        platform_directory_list_free(&shards);
        return cov_fail(why, why_len, ZCL_DEV_COVERAGE_WHY_STORE_INCOMPLETE);
    }
    bool ok = true;
    for (size_t s = 0; s < shards.count && ok; s++) {
        /* The store's own tmp/ staging pool lives beside the shards; it is
         * part of the layout, never an observation object. */
        if (strcmp(shards.entries[s].name, "tmp") == 0) continue;
        char shard_path[4096];
        int n = snprintf(shard_path, sizeof(shard_path), "%s/%s",
                         objects_path, shards.entries[s].name);
        if (n < 0 || n >= (int)sizeof(shard_path)) {
            ok = cov_fail(why, why_len, ZCL_DEV_COVERAGE_WHY_STORE_INCOMPLETE);
            break;
        }
        ok = cov_enumerate_shard(store, &cap, shard_path,
                                 shards.entries[s].name, why, why_len);
    }
    platform_directory_list_free(&shards);
    if (!ok) cov_store_release(store);
    return ok;
}

/* ── Classification ──────────────────────────────────────────────────── */

/* Per (key, group): an eligible PASS/FAIL contradiction refuses; zero
 * eligible PASS refuses as missing; otherwise the eligible PASS roots are
 * the coverage basis. `listed` restricts verification to the manifest's
 * roots (receiver side); derive passes the whole store match instead. */
static bool cov_classify(const struct cov_store *store,
    const uint8_t key[ZCL_DEV_VERDICT_LEAF_KEY_BYTES], uint8_t group_len,
    const char *group, const uint8_t (*listed)[ZCL_DEV_PROOF_ROOT_BYTES],
    size_t n_listed,
    uint8_t (*pass_roots)[ZCL_DEV_PROOF_ROOT_BYTES], size_t *n_pass,
    char *why, size_t why_len)
{
    bool pass = false, fail = false;
    *n_pass = 0;
    for (size_t i = 0; i < store->count; i++) {
        const struct cov_leaf *leaf = &store->leaves[i];
        if (!leaf->eligible || memcmp(leaf->leaf.key, key, 32) != 0 ||
            !cov_leaf_group_matches(&leaf->leaf, group_len, group))
            continue;
        if (leaf->leaf.verdict == ZCL_DEV_VERDICT_LEAF_FAIL) {
            fail = true;
            continue;
        }
        pass = true;
        if (*n_pass >= ZCL_DEV_COVERAGE_MAX_ROW_ROOTS)
            return cov_fail(why, why_len, ZCL_DEV_COVERAGE_WHY_STORE_TOO_MANY);
        (void)memcpy(pass_roots[*n_pass], leaf->root, 32);
        (*n_pass)++;
    }
    if (pass && fail)
        return cov_fail_group(why, why_len, ZCL_DEV_COVERAGE_WHY_CONFLICT,
                              group);
    if (!pass)
        return cov_fail_group(why, why_len, ZCL_DEV_COVERAGE_WHY_MISSING,
                              group);
    if (listed) {
        for (size_t i = 0; i < n_listed; i++) {
            bool found = false;
            for (size_t j = 0; j < *n_pass; j++) {
                if (memcmp(listed[i], pass_roots[j], 32) == 0) {
                    found = true;
                    break;
                }
            }
            if (!found)
                return cov_fail_group(why, why_len,
                                      ZCL_DEV_COVERAGE_WHY_MISSING, group);
        }
    }
    return true;
}

/* An unqualified row claims the group executed and passed without a reusable
 * observation. It lists no root, so there is nothing to look up -- but the
 * pair's CAS may still hold this group's leaves from an earlier attempt of
 * the same pair, and a retained eligible FAIL contradicts the claim. A
 * producer therefore cannot retire a known contradiction by reporting the
 * group as unqualified: any eligible FAIL for the group, at any key, refuses. */
static bool cov_classify_unqualified(const struct cov_store *store,
    uint8_t group_len, const char *group, char *why, size_t why_len)
{
    for (size_t i = 0; i < store->count; i++) {
        const struct cov_leaf *leaf = &store->leaves[i];
        if (leaf->eligible &&
            leaf->leaf.verdict == ZCL_DEV_VERDICT_LEAF_FAIL &&
            cov_leaf_group_matches(&leaf->leaf, group_len, group))
            return cov_fail_group(why, why_len, ZCL_DEV_COVERAGE_WHY_CONFLICT,
                                  group);
    }
    return true;
}

static int cov_group_cmp(const struct zcl_dev_coverage_log_row *ra,
                         const struct zcl_dev_coverage_log_row *rb)
{
    size_t la = ra->group_len, lb = rb->group_len;
    size_t common = la < lb ? la : lb;
    int by_group = memcmp(ra->group, rb->group, common);
    if (by_group != 0) return by_group;
    return la == lb ? 0 : (la < lb ? -1 : 1);
}

static int cov_row_cmp(const void *a, const void *b)
{
    const struct zcl_dev_coverage_log_row *ra = a, *rb = b;
    int by_group = cov_group_cmp(ra, rb);
    if (by_group != 0) return by_group;
    return memcmp(ra->key, rb->key, ZCL_DEV_VERDICT_LEAF_KEY_BYTES);
}

static int cov_root_cmp(const void *a, const void *b)
{
    return memcmp(a, b, ZCL_DEV_PROOF_ROOT_BYTES);
}

/* Canonical blob row: u8 group_len || group[128] (zero padded) || key[32] ||
 * u16le n_roots || roots[32*n] sorted bytewise. Rows sorted by
 * (group, key). An unqualified row is the same shape with an all-zero key and
 * n_roots == 0; a keyed row always lists at least one root. */
static bool cov_blob_write_row(uint8_t *blob, size_t cap, size_t *at,
    const struct zcl_dev_coverage_log_row *row,
    uint8_t (*roots)[ZCL_DEV_PROOF_ROOT_BYTES], size_t n_roots)
{
    size_t need = 1 + ZCL_DEV_VERDICT_LEAF_GROUP_BYTES +
                  ZCL_DEV_VERDICT_LEAF_KEY_BYTES + 2 +
                  n_roots * ZCL_DEV_PROOF_ROOT_BYTES;
    if (*at > cap || need > cap - *at || n_roots > UINT16_MAX)
        return false;
    blob[(*at)++] = row->group_len;
    (void)memcpy(blob + *at, row->group, ZCL_DEV_VERDICT_LEAF_GROUP_BYTES);
    *at += ZCL_DEV_VERDICT_LEAF_GROUP_BYTES;
    (void)memcpy(blob + *at, row->key, ZCL_DEV_VERDICT_LEAF_KEY_BYTES);
    *at += ZCL_DEV_VERDICT_LEAF_KEY_BYTES;
    zcl_write_u16_le(blob + *at, (uint16_t)n_roots);
    *at += 2;
    if (n_roots)
        qsort(roots, n_roots, ZCL_DEV_PROOF_ROOT_BYTES, cov_root_cmp);
    for (size_t i = 0; i < n_roots; i++) {
        (void)memcpy(blob + *at, roots[i], ZCL_DEV_PROOF_ROOT_BYTES);
        *at += ZCL_DEV_PROOF_ROOT_BYTES;
    }
    return true;
}

/* The group field is a registry identifier, zero padded to its fixed width,
 * so the same group has exactly one encoding and a reader may treat the
 * field as a C string. */
static bool cov_blob_group_canonical(const uint8_t *field, uint8_t group_len)
{
    if (group_len == 0 || group_len > ZCL_DEV_VERDICT_LEAF_GROUP_MAX)
        return false;
    for (size_t i = 0; i < ZCL_DEV_VERDICT_LEAF_GROUP_BYTES; i++) {
        uint8_t c = field[i];
        bool word = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                    (c >= '0' && c <= '9') || c == '_';
        if (i < group_len ? !word : c != 0) return false;
    }
    return true;
}

static bool cov_blob_rows(const uint8_t *blob, size_t blob_len,
    uint32_t row_count, size_t *consumed)
{
    size_t at = 0;
    for (uint32_t r = 0; r < row_count; r++) {
        if (at + 1 + ZCL_DEV_VERDICT_LEAF_GROUP_BYTES +
                ZCL_DEV_VERDICT_LEAF_KEY_BYTES + 2 > blob_len)
            return false;
        if (!cov_blob_group_canonical(blob + at + 1, blob[at]))
            return false;
        at += 1 + ZCL_DEV_VERDICT_LEAF_GROUP_BYTES;
        bool keyed = !cov_root_is_zero(blob + at);
        at += ZCL_DEV_VERDICT_LEAF_KEY_BYTES;
        uint16_t n_roots = zcl_read_u16_le(blob + at);
        at += 2;
        if (keyed != (n_roots != 0) ||
            n_roots > ZCL_DEV_COVERAGE_MAX_ROW_ROOTS ||
            (size_t)n_roots * ZCL_DEV_PROOF_ROOT_BYTES > blob_len - at)
            return false;
        at += (size_t)n_roots * ZCL_DEV_PROOF_ROOT_BYTES;
    }
    *consumed = at;
    return true;
}

static bool cov_coverage_root(const uint8_t *blob, size_t blob_len,
    uint8_t out[ZCL_DEV_PROOF_ROOT_BYTES])
{
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    sha3_256_write(&sha, COVERAGE_DOMAIN, sizeof(COVERAGE_DOMAIN));
    if (blob_len) sha3_256_write(&sha, blob, blob_len);
    sha3_256_finalize(&sha, out);
    return true;
}

/* ── Envelope ────────────────────────────────────────────────────────── */

static bool cov_envelope_fill(uint8_t envelope[ZCL_DEV_COVERAGE_WIRE_BYTES],
    const struct zcl_dev_coverage_binding *binding, uint32_t row_count,
    uint32_t blob_len,
    const uint8_t coverage_root[ZCL_DEV_PROOF_ROOT_BYTES])
{
    memset(envelope, 0, ZCL_DEV_COVERAGE_WIRE_BYTES);
    (void)memcpy(envelope, ZCL_DEV_COVERAGE_MAGIC,
                 ZCL_DEV_COVERAGE_MAGIC_BYTES - 1);
    envelope[ZCL_DEV_COVERAGE_MAGIC_BYTES - 1] = 0;
    zcl_write_u32_le(envelope + COV_OFF_VERSION, ZCL_DEV_COVERAGE_VERSION);
    zcl_write_u32_le(envelope + COV_OFF_POLICY_VERSION,
                     binding->policy_version);
    zcl_write_u32_le(envelope + COV_OFF_ROW_COUNT, row_count);
    zcl_write_u32_le(envelope + COV_OFF_BLOB_LEN, blob_len);
    (void)memcpy(envelope + COV_OFF_COVERAGE_ROOT, coverage_root, 32);
    (void)memcpy(envelope + COV_OFF_CHILD_SET_ROOT, binding->child_set_root,
                 32);
    (void)memcpy(envelope + COV_OFF_IMPACT_ROOT, binding->impact_policy_root,
                 32);
    (void)memcpy(envelope + COV_OFF_LOCAL, binding->local_commit,
                 ZCL_DEV_PROOF_OID_MAX);
    envelope[COV_OFF_LOCAL_LEN] = binding->local_commit_len;
    envelope[COV_OFF_BASE_LEN] = binding->remote_base_len;
    (void)memcpy(envelope + COV_OFF_BASE, binding->remote_base,
                 ZCL_DEV_PROOF_OID_MAX);
    return true;
}

/* Wire framing: magic, version, reserved zero regions, row/blob bounds, and
 * the coverage-root consistency. Binding-agnostic. */
static bool cov_envelope_framing(const uint8_t *wire,
    uint32_t *row_count, uint32_t *blob_len,
    uint8_t coverage_root[ZCL_DEV_PROOF_ROOT_BYTES],
    char *why, size_t why_len)
{
    if (memcmp(wire, ZCL_DEV_COVERAGE_MAGIC,
               ZCL_DEV_COVERAGE_MAGIC_BYTES - 1) != 0 ||
        wire[ZCL_DEV_COVERAGE_MAGIC_BYTES - 1] != 0 ||
        zcl_read_u32_le(wire + COV_OFF_VERSION) != ZCL_DEV_COVERAGE_VERSION)
        return cov_fail(why, why_len, ZCL_DEV_COVERAGE_WHY_MANIFEST_INVALID);
    for (size_t i = 154; i < 156; i++)
        if (wire[i] != 0)
            return cov_fail(why, why_len, ZCL_DEV_COVERAGE_WHY_MANIFEST_INVALID);
    for (size_t i = 188; i < COV_OFF_PUBKEY; i++)
        if (wire[i] != 0)
            return cov_fail(why, why_len, ZCL_DEV_COVERAGE_WHY_MANIFEST_INVALID);
    uint32_t rows = zcl_read_u32_le(wire + COV_OFF_ROW_COUNT);
    uint32_t blen = zcl_read_u32_le(wire + COV_OFF_BLOB_LEN);
    if (rows > ZCL_DEV_COVERAGE_MAX_ROWS ||
        blen > ZCL_DEV_COVERAGE_BLOB_MAX_BYTES)
        return cov_fail(why, why_len, ZCL_DEV_COVERAGE_WHY_MANIFEST_TOO_LARGE);
    (void)memcpy(coverage_root, wire + COV_OFF_COVERAGE_ROOT, 32);
    if (cov_root_is_zero(coverage_root) && (rows != 0 || blen != 0))
        return cov_fail(why, why_len, ZCL_DEV_COVERAGE_WHY_MANIFEST_INVALID);
    *row_count = rows;
    *blob_len = blen;
    return true;
}

/* Receipt binding: the manifest is valid for exactly one pair receipt. */
static bool cov_envelope_binding(const uint8_t *wire,
    const struct zcl_dev_coverage_binding *binding, char *why, size_t why_len)
{
    if (zcl_read_u32_le(wire + COV_OFF_POLICY_VERSION) !=
            binding->policy_version ||
        wire[COV_OFF_LOCAL_LEN] != binding->local_commit_len ||
        wire[COV_OFF_BASE_LEN] != binding->remote_base_len ||
        (binding->local_commit_len &&
         memcmp(wire + COV_OFF_LOCAL, binding->local_commit,
                binding->local_commit_len) != 0) ||
        (binding->remote_base_len &&
         memcmp(wire + COV_OFF_BASE, binding->remote_base,
                binding->remote_base_len) != 0) ||
        memcmp(wire + COV_OFF_CHILD_SET_ROOT, binding->child_set_root, 32) != 0 ||
        memcmp(wire + COV_OFF_IMPACT_ROOT, binding->impact_policy_root,
               32) != 0)
        return cov_fail(why, why_len, ZCL_DEV_COVERAGE_WHY_BINDING);
    return true;
}

static bool cov_envelope_parse(const uint8_t *wire, size_t wire_len,
    const struct zcl_dev_coverage_binding *binding,
    uint32_t *row_count, uint32_t *blob_len,
    uint8_t coverage_root[ZCL_DEV_PROOF_ROOT_BYTES],
    char *why, size_t why_len)
{
    if (!wire || wire_len != ZCL_DEV_COVERAGE_WIRE_BYTES)
        return cov_fail(why, why_len, ZCL_DEV_COVERAGE_WHY_MANIFEST_INVALID);
    if (!cov_envelope_framing(wire, row_count, blob_len, coverage_root,
                              why, why_len))
        return false;
    return cov_envelope_binding(wire, binding, why, why_len);
}

static bool cov_envelope_sign(uint8_t envelope[ZCL_DEV_COVERAGE_WIRE_BYTES],
    char *why, size_t why_len)
{
    uint8_t message[sizeof(COVERAGE_SIGN_DOMAIN) - 1 +
                    ZCL_DEV_COVERAGE_UNSIGNED_WIRE_BYTES];
    (void)memcpy(message, COVERAGE_SIGN_DOMAIN,
                 sizeof(COVERAGE_SIGN_DOMAIN) - 1);
    (void)memcpy(message + sizeof(COVERAGE_SIGN_DOMAIN) - 1, envelope,
                 ZCL_DEV_COVERAGE_UNSIGNED_WIRE_BYTES);
    const char *signer_why = NULL;
    if (!zcl_dev_proof_signer_sign(message, sizeof(message),
                                   envelope + COV_OFF_PUBKEY,
                                   envelope + COV_OFF_PUBKEY +
                                       ZCL_DEV_PROOF_PUBKEY_BYTES,
                                   &signer_why))
        return cov_fail(why, why_len,
                        signer_why ? signer_why
                                   : ZCL_DEV_COVERAGE_WHY_MANIFEST_UNSIGNED);
    return true;
}

static bool cov_envelope_verify_signature(
    const uint8_t envelope[ZCL_DEV_COVERAGE_WIRE_BYTES],
    char *why, size_t why_len)
{
    if (cov_root_is_zero(envelope + COV_OFF_PUBKEY))
        return cov_fail(why, why_len, ZCL_DEV_COVERAGE_WHY_MANIFEST_UNSIGNED);
    uint8_t message[sizeof(COVERAGE_SIGN_DOMAIN) - 1 +
                    ZCL_DEV_COVERAGE_UNSIGNED_WIRE_BYTES];
    (void)memcpy(message, COVERAGE_SIGN_DOMAIN,
                 sizeof(COVERAGE_SIGN_DOMAIN) - 1);
    (void)memcpy(message + sizeof(COVERAGE_SIGN_DOMAIN) - 1, envelope,
                 ZCL_DEV_COVERAGE_UNSIGNED_WIRE_BYTES);
    const char *signer_why = NULL;
    if (!zcl_dev_proof_signer_verify(message, sizeof(message),
                                     envelope + COV_OFF_PUBKEY,
                                     envelope + COV_OFF_PUBKEY +
                                         ZCL_DEV_PROOF_PUBKEY_BYTES,
                                     &signer_why))
        return cov_fail(why, why_len,
                        signer_why ? signer_why
                                   : ZCL_DEV_COVERAGE_WHY_MANIFEST_INVALID);
    return true;
}

/* ── Shared derivation/verification body ─────────────────────────────── */

struct cov_row_roots {
    uint8_t (*roots)[ZCL_DEV_PROOF_ROOT_BYTES];
    size_t n_roots;
};

static bool cov_rows_resolve(const struct cov_store *store,
    const struct zcl_dev_coverage_log_row *rows, uint32_t n_rows,
    const uint8_t (*const *listed)[ZCL_DEV_PROOF_ROOT_BYTES],
    const size_t *n_listed, struct cov_row_roots *resolved,
    char *why, size_t why_len)
{
    for (uint32_t r = 0; r < n_rows; r++) {
        if (rows[r].unqualified) {
            if (!cov_classify_unqualified(store, rows[r].group_len,
                                       rows[r].group, why, why_len))
                return false;
            continue;
        }
        resolved[r].roots = zcl_malloc(ZCL_DEV_COVERAGE_MAX_ROW_ROOTS * 32u,
                                       "dev-coverage-row-roots");
        if (!resolved[r].roots)
            return cov_fail(why, why_len, ZCL_DEV_COVERAGE_WHY_STORE_INCOMPLETE);
        if (!cov_classify(store, rows[r].key, rows[r].group_len, rows[r].group,
                          listed ? listed[r] : NULL,
                          listed ? n_listed[r] : 0,
                          resolved[r].roots, &resolved[r].n_roots,
                          why, why_len))
            return false;
    }
    return true;
}

static void cov_rows_roots_release(struct cov_row_roots *resolved,
    uint32_t n_rows)
{
    if (!resolved) return;
    for (uint32_t r = 0; r < n_rows; r++) free(resolved[r].roots);
    free(resolved);
}

/* Producer classification phase: enumerate the CAS, resolve every row's
 * eligible PASS roots, and require each row's emitted root to be among
 * them. */
static bool cov_derive_resolve(const char *store_root,
    struct zcl_dev_coverage_log_row *rows, uint32_t n_rows,
    struct cov_store *store, struct cov_row_roots **resolved_out,
    char *why, size_t why_len)
{
    *resolved_out = NULL;
    if (!cov_store_enumerate(store_root, store, why, why_len))
        return false;
    if (!store->present)
        return cov_fail(why, why_len, ZCL_DEV_COVERAGE_WHY_STORE_INCOMPLETE);
    struct cov_row_roots *resolved =
        zcl_malloc(n_rows * sizeof(*resolved), "dev-coverage-resolved");
    if (!resolved)
        return cov_fail(why, why_len, ZCL_DEV_COVERAGE_WHY_STORE_INCOMPLETE);
    memset(resolved, 0, n_rows * sizeof(*resolved));
    if (!cov_rows_resolve(store, rows, n_rows, NULL, NULL, resolved,
                          why, why_len)) {
        cov_rows_roots_release(resolved, n_rows);
        return false;
    }
    /* The emitted root the runner logged must be among the eligible PASS
     * roots: the log row claims this exact observation persisted. */
    for (uint32_t r = 0; r < n_rows; r++) {
        bool found = rows[r].unqualified;
        for (size_t i = 0; i < resolved[r].n_roots; i++) {
            if (memcmp(resolved[r].roots[i], rows[r].root, 32) == 0) {
                found = true;
                break;
            }
        }
        if (!found) {
            cov_rows_roots_release(resolved, n_rows);
            return cov_fail(why, why_len, ZCL_DEV_COVERAGE_WHY_EMITTED_MISSING);
        }
    }
    *resolved_out = resolved;
    return true;
}

/* Producer serialization phase: canonical blob, coverage root, envelope,
 * signature. On success the blob ownership moves to the caller. */
static bool cov_derive_emit(const struct zcl_dev_coverage_binding *binding,
    const struct zcl_dev_coverage_log_row *rows, uint32_t n_rows,
    const struct cov_row_roots *resolved,
    uint8_t envelope[ZCL_DEV_COVERAGE_WIRE_BYTES],
    uint8_t **blob_out, size_t *blob_len_out,
    char *why, size_t why_len)
{
    uint8_t *blob =
        zcl_malloc(ZCL_DEV_COVERAGE_BLOB_MAX_BYTES, "dev-coverage-blob");
    if (!blob)
        return cov_fail(why, why_len, ZCL_DEV_COVERAGE_WHY_STORE_INCOMPLETE);
    size_t blob_len = 0;
    for (uint32_t r = 0; r < n_rows; r++) {
        if (!cov_blob_write_row(blob, ZCL_DEV_COVERAGE_BLOB_MAX_BYTES,
                                &blob_len, &rows[r], resolved[r].roots,
                                resolved[r].n_roots)) {
            free(blob);
            return cov_fail(why, why_len,
                            ZCL_DEV_COVERAGE_WHY_MANIFEST_TOO_LARGE);
        }
    }
    uint8_t coverage_root[ZCL_DEV_PROOF_ROOT_BYTES] = {0};
    cov_coverage_root(blob, blob_len, coverage_root);
    cov_envelope_fill(envelope, binding, n_rows, (uint32_t)blob_len,
                      coverage_root);
    if (!cov_envelope_sign(envelope, why, why_len)) {
        free(blob);
        return false;
    }
    *blob_out = blob;
    *blob_len_out = blob_len;
    return true;
}

bool zcl_dev_coverage_manifest_derive(const char *store_root,
    const char *test_log_path,
    const struct zcl_dev_coverage_binding *binding, uint32_t expected_rows,
    uint8_t envelope[ZCL_DEV_COVERAGE_WIRE_BYTES],
    uint8_t **blob_out, size_t *blob_len_out,
    char *why, size_t why_len)
{
    if (!binding || !envelope || !blob_out || !blob_len_out ||
        expected_rows > ZCL_DEV_COVERAGE_MAX_ROWS)
        return cov_fail(why, why_len, ZCL_DEV_COVERAGE_WHY_ARGUMENTS);
    *blob_out = NULL;
    *blob_len_out = 0;

    struct zcl_dev_coverage_log_row *rows = NULL;
    uint32_t n_rows = 0;
    if (expected_rows) {
        rows = zcl_malloc(expected_rows * sizeof(*rows), "dev-coverage-rows");
        if (!rows)
            return cov_fail(why, why_len, ZCL_DEV_COVERAGE_WHY_STORE_INCOMPLETE);
        if (!zcl_dev_coverage_log_rows(test_log_path, expected_rows, rows,
                                       expected_rows, &n_rows,
                                       why, why_len)) {
            free(rows);
            return false;
        }
        /* Canonical order BEFORE resolution so row data and its resolved
         * roots stay paired through the emitted check and the blob write. */
        qsort(rows, n_rows, sizeof(*rows), cov_row_cmp);
    }

    struct cov_store store = {0};
    struct cov_row_roots *resolved = NULL;
    bool ok = n_rows == 0 ||
              cov_derive_resolve(store_root, rows, n_rows, &store, &resolved,
                                 why, why_len);
    if (ok)
        ok = cov_derive_emit(binding, rows, n_rows, resolved, envelope,
                             blob_out, blob_len_out, why, why_len);
    cov_rows_roots_release(resolved, n_rows);
    free(rows);
    cov_store_release(&store);
    if (ok && why && why_len) why[0] = 0;
    return ok;
}

bool zcl_dev_coverage_envelope_blob_len(const uint8_t *envelope_wire,
                                        size_t envelope_len,
                                        uint32_t *blob_len_out)
{
    if (!envelope_wire || envelope_len != ZCL_DEV_COVERAGE_WIRE_BYTES ||
        !blob_len_out)
        return cov_fail(NULL, 0, ZCL_DEV_COVERAGE_WHY_MANIFEST_INVALID);
    if (memcmp(envelope_wire, ZCL_DEV_COVERAGE_MAGIC,
               ZCL_DEV_COVERAGE_MAGIC_BYTES - 1) != 0 ||
        envelope_wire[ZCL_DEV_COVERAGE_MAGIC_BYTES - 1] != 0 ||
        zcl_read_u32_le(envelope_wire + COV_OFF_VERSION) !=
            ZCL_DEV_COVERAGE_VERSION)
        return cov_fail(NULL, 0, ZCL_DEV_COVERAGE_WHY_MANIFEST_INVALID);
    uint32_t blob_len = zcl_read_u32_le(envelope_wire + COV_OFF_BLOB_LEN);
    if (blob_len > ZCL_DEV_COVERAGE_BLOB_MAX_BYTES)
        return cov_fail(NULL, 0, ZCL_DEV_COVERAGE_WHY_MANIFEST_TOO_LARGE);
    *blob_len_out = blob_len;
    return true;
}

/* Receiver row phase: re-derive the coverage root over the blob bytes and
 * extract (group, key, listed roots) per row. `listed` points into `blob`
 * and dies with it; the row arrays are caller-freed. */
static bool cov_verify_rows_extract(const uint8_t *blob, size_t blob_len,
    uint32_t row_count,
    const uint8_t coverage_root[ZCL_DEV_PROOF_ROOT_BYTES],
    struct zcl_dev_coverage_log_row **rows_out,
    const uint8_t (***listed_out)[ZCL_DEV_PROOF_ROOT_BYTES],
    size_t **n_listed_out, char *why, size_t why_len)
{
    *rows_out = NULL;
    *listed_out = NULL;
    *n_listed_out = NULL;
    uint8_t derived[ZCL_DEV_PROOF_ROOT_BYTES];
    cov_coverage_root(blob, blob_len, derived);
    if (memcmp(derived, coverage_root, 32) != 0)
        return cov_fail(why, why_len, ZCL_DEV_COVERAGE_WHY_BLOB_INVALID);
    size_t consumed = 0;
    if (!cov_blob_rows(blob, blob_len, row_count, &consumed) ||
        consumed != blob_len)
        return cov_fail(why, why_len, ZCL_DEV_COVERAGE_WHY_BLOB_INVALID);
    struct zcl_dev_coverage_log_row *rows =
        zcl_malloc(row_count * sizeof(*rows), "dev-coverage-vrows");
    const uint8_t (**listed)[ZCL_DEV_PROOF_ROOT_BYTES] =
        zcl_malloc(row_count * sizeof(*listed), "dev-coverage-listed");
    size_t *n_listed =
        zcl_malloc(row_count * sizeof(*n_listed), "dev-coverage-listed-n");
    if (!rows || !listed || !n_listed) {
        free(rows);
        free(listed);
        free(n_listed);
        return cov_fail(why, why_len, ZCL_DEV_COVERAGE_WHY_STORE_INCOMPLETE);
    }
    size_t at = 0;
    for (uint32_t r = 0; r < row_count; r++) {
        rows[r].group_len = blob[at];
        (void)memcpy(rows[r].group, blob + at + 1,
                     ZCL_DEV_VERDICT_LEAF_GROUP_BYTES);
        at += 1 + ZCL_DEV_VERDICT_LEAF_GROUP_BYTES;
        (void)memcpy(rows[r].key, blob + at, ZCL_DEV_VERDICT_LEAF_KEY_BYTES);
        at += ZCL_DEV_VERDICT_LEAF_KEY_BYTES;
        n_listed[r] = zcl_read_u16_le(blob + at);
        at += 2;
        listed[r] = (const uint8_t (*)[32])(blob + at);
        at += n_listed[r] * ZCL_DEV_PROOF_ROOT_BYTES;
        memset(rows[r].root, 0, sizeof(rows[r].root));
        rows[r].unqualified = n_listed[r] == 0;
        /* One row per group, in canonical order: a second encoding of the
         * same executed set, or a group counted twice, is not this blob. */
        if (r > 0 && cov_group_cmp(&rows[r - 1], &rows[r]) >= 0) {
            free(rows);
            free(listed);
            free(n_listed);
            return cov_fail(why, why_len, ZCL_DEV_COVERAGE_WHY_BLOB_INVALID);
        }
    }
    *rows_out = rows;
    *listed_out = listed;
    *n_listed_out = n_listed;
    return true;
}

/* Receiver classification phase: a complete local enumeration of the same
 * CAS, then resolve every manifest row against it. */
static bool cov_verify_resolve(const char *store_root, uint32_t row_count,
    const struct zcl_dev_coverage_log_row *rows,
    const uint8_t (*const *listed)[ZCL_DEV_PROOF_ROOT_BYTES],
    const size_t *n_listed, char *why, size_t why_len)
{
    struct cov_store store = {0};
    if (!cov_store_enumerate(store_root, &store, why, why_len))
        return false;
    bool ok = store.present;
    if (!ok)
        ok = cov_fail(why, why_len, ZCL_DEV_COVERAGE_WHY_STORE_INCOMPLETE);
    struct cov_row_roots *resolved = NULL;
    if (ok) {
        resolved = zcl_malloc(row_count * sizeof(*resolved),
                              "dev-coverage-vresolved");
        if (!resolved)
            ok = cov_fail(why, why_len, ZCL_DEV_COVERAGE_WHY_STORE_INCOMPLETE);
    }
    if (ok) {
        memset(resolved, 0, row_count * sizeof(*resolved));
        ok = cov_rows_resolve(&store, rows, row_count, listed, n_listed,
                              resolved, why, why_len);
    }
    cov_rows_roots_release(resolved, row_count);
    cov_store_release(&store);
    return ok;
}

bool zcl_dev_coverage_manifest_verify(const char *store_root,
    const uint8_t *envelope_wire, size_t envelope_len,
    const uint8_t *blob, size_t blob_len,
    const struct zcl_dev_coverage_binding *binding, uint32_t expected_rows,
    char *why, size_t why_len)
{
    if (!binding)
        return cov_fail(why, why_len, ZCL_DEV_COVERAGE_WHY_ARGUMENTS);
    uint32_t row_count = 0, want_blob_len = 0;
    uint8_t coverage_root[ZCL_DEV_PROOF_ROOT_BYTES] = {0};
    if (!cov_envelope_parse(envelope_wire, envelope_len, binding, &row_count,
                            &want_blob_len, coverage_root, why, why_len))
        return false;
    if (want_blob_len != blob_len || (blob_len && !blob))
        return cov_fail(why, why_len, ZCL_DEV_COVERAGE_WHY_BLOB_INVALID);
    if (!cov_envelope_verify_signature(envelope_wire, why, why_len))
        return false;
    /* The signed row count is the receipt's executed-group count, or the
     * manifest belongs to some other test dimension: an empty manifest must
     * not stand in for a receipt that ran groups. */
    if (row_count != expected_rows)
        return cov_fail(why, why_len, ZCL_DEV_COVERAGE_WHY_COUNT_MISMATCH);
    if (row_count == 0) {
        /* The empty mandatory set has exactly one encoding. */
        uint8_t derived[ZCL_DEV_PROOF_ROOT_BYTES];
        cov_coverage_root(blob, 0, derived);
        return (blob_len == 0 && memcmp(derived, coverage_root, 32) == 0) ||
               cov_fail(why, why_len, ZCL_DEV_COVERAGE_WHY_BLOB_INVALID);
    }

    /* Parse the blob rows back into (group, key) pairs and resolve each
     * against the store. The byte-bound root check already pins the blob;
     * this proves the pinned rows carry coverage. */
    struct zcl_dev_coverage_log_row *rows = NULL;
    const uint8_t (**listed)[ZCL_DEV_PROOF_ROOT_BYTES] = NULL;
    size_t *n_listed = NULL;
    if (!cov_verify_rows_extract(blob, blob_len, row_count, coverage_root,
                                 &rows, &listed, &n_listed, why, why_len))
        return false;
    bool ok = cov_verify_resolve(store_root, row_count, rows, listed, n_listed,
                                 why, why_len);
    free(n_listed);
    free(listed);
    free(rows);
    if (ok && why && why_len) why[0] = 0;
    return ok;
}

/* ── Query mode ───────────────────────────────────────────────────────── */

/* Observation projection stats: totals, eligibility and the observed age
 * range. An empty projection reports zeros, not a refusal. */
static void cov_inspect_stats(const struct cov_store *store,
    struct zcl_dev_coverage_inspect *out)
{
    out->observed_total = store->count;
    for (size_t i = 0; i < store->count; i++) {
        if (!store->leaves[i].eligible) continue;
        out->observed_eligible++;
        uint64_t seen = store->leaves[i].leaf.observed_unix;
        if (out->oldest_observed_unix == 0 || seen < out->oldest_observed_unix)
            out->oldest_observed_unix = seen;
        if (seen > out->newest_observed_unix)
            out->newest_observed_unix = seen;
    }
}

/* Classify every manifest row against the projection. Keyed rows resolve
 * to covered, missing (named, capped) or conflict; unqualified rows are
 * counted as their own state — executed with no reusable observation —
 * unless the store retains an eligible FAIL for the group, which is the
 * same preserved contradiction verify() refuses. */
static bool cov_inspect_rows(const struct cov_store *store,
    const uint8_t *blob, size_t blob_len, uint32_t row_count,
    const uint8_t coverage_root[ZCL_DEV_PROOF_ROOT_BYTES],
    struct zcl_dev_coverage_inspect *out, char *why, size_t why_len)
{
    struct zcl_dev_coverage_log_row *rows = NULL;
    const uint8_t (**listed)[ZCL_DEV_PROOF_ROOT_BYTES] = NULL;
    size_t *n_listed = NULL;
    if (!cov_verify_rows_extract(blob, blob_len, row_count, coverage_root,
                                 &rows, &listed, &n_listed, why, why_len))
        return false;
    uint8_t (*pass_roots)[ZCL_DEV_PROOF_ROOT_BYTES] =
        zcl_malloc(ZCL_DEV_COVERAGE_MAX_ROW_ROOTS * 32u,
                   "dev-coverage-inspect-roots");
    if (!pass_roots) {
        free(n_listed);
        free(listed);
        free(rows);
        return cov_fail(why, why_len, ZCL_DEV_COVERAGE_WHY_STORE_INCOMPLETE);
    }
    for (uint32_t r = 0; r < row_count; r++) {
        if (rows[r].unqualified) {
            char row_why[160] = {0};
            if (cov_classify_unqualified(store, rows[r].group_len,
                                         rows[r].group,
                                         row_why, sizeof(row_why)))
                out->unqualified++;
            else if (strncmp(row_why, ZCL_DEV_COVERAGE_WHY_CONFLICT,
                             strlen(ZCL_DEV_COVERAGE_WHY_CONFLICT)) == 0)
                out->conflicts++;
            else
                out->unqualified++;
            continue;
        }
        size_t n_pass = 0;
        char row_why[160] = {0};
        bool covered = cov_classify(store, rows[r].key, rows[r].group_len,
                                    rows[r].group, listed[r], n_listed[r],
                                    pass_roots, &n_pass,
                                    row_why, sizeof(row_why));
        if (covered) {
            out->covered++;
            continue;
        }
        if (strncmp(row_why, ZCL_DEV_COVERAGE_WHY_CONFLICT,
                    strlen(ZCL_DEV_COVERAGE_WHY_CONFLICT)) == 0) {
            out->conflicts++;
            continue;
        }
        out->missing++;
        if (out->missing_named < ZCL_DEV_COVERAGE_INSPECT_MAX_MISSING) {
            size_t gl = rows[r].group_len;
            (void)memcpy(out->missing_groups[out->missing_named], rows[r].group,
                         gl);
            out->missing_groups[out->missing_named][gl] = 0;
            out->missing_named++;
        }
    }
    free(pass_roots);
    free(n_listed);
    free(listed);
    free(rows);
    return true;
}

bool zcl_dev_coverage_inspect(const char *store_root,
    const uint8_t *envelope_wire, size_t envelope_len,
    const uint8_t *blob, size_t blob_len,
    const struct zcl_dev_coverage_binding *binding,
    struct zcl_dev_coverage_inspect *out, char *why, size_t why_len)
{
    if (!binding || !out)
        return cov_fail(why, why_len, ZCL_DEV_COVERAGE_WHY_ARGUMENTS);
    memset(out, 0, sizeof(*out));
    if (envelope_len != ZCL_DEV_COVERAGE_WIRE_BYTES)
        return cov_fail(why, why_len, ZCL_DEV_COVERAGE_WHY_MANIFEST_INVALID);

    uint32_t row_count = 0, want_blob_len = 0;
    uint8_t coverage_root[ZCL_DEV_PROOF_ROOT_BYTES] = {0};
    if (!cov_envelope_framing(envelope_wire, &row_count, &want_blob_len,
                              coverage_root, why, why_len))
        return false;
    if (want_blob_len != blob_len || (blob_len && !blob))
        return cov_fail(why, why_len, ZCL_DEV_COVERAGE_WHY_BLOB_INVALID);
    out->binding_mismatch =
        !cov_envelope_binding(envelope_wire, binding, NULL, 0);
    if (!cov_envelope_verify_signature(envelope_wire, out->signer_why,
                                       sizeof(out->signer_why)) &&
        !out->signer_why[0])
        (void)snprintf(out->signer_why, sizeof(out->signer_why), "%s",
                       ZCL_DEV_COVERAGE_WHY_MANIFEST_INVALID);

    /* The observation projection and its age range are reported whether
     * or not the manifest rows resolve: the query answers both "does this
     * pair carry coverage" and "what has this box seen". */
    struct cov_store store = {0};
    if (!cov_store_enumerate(store_root, &store, why, why_len))
        return false;
    cov_inspect_stats(&store, out);

    out->row_count = row_count;
    bool ok = row_count == 0 ||
              cov_inspect_rows(&store, blob, blob_len, row_count,
                               coverage_root, out, why, why_len);
    cov_store_release(&store);
    if (ok && why && why_len) why[0] = 0;
    return ok;
}
