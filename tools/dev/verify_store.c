/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0.
 * Receiver-side, bounded read of one fixed-result verifier observation key.
 * The signer publishes under an exclusive fixed_result.lock; this reader
 * holds its shared lock until the caller has materialized verified bytes. */
#define _POSIX_C_SOURCE 200809L
#include "verify_store.h"

#include "verify/fixed_result_contract.h"

#include "base/hex.h"
#include "base/safe_alloc.h"
#include "sha3/sha3.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define VS_MAX_OBSERVATIONS 64u
#define VS_MAX_DIR_ENTRIES 96u
#define VS_MAX_RECORD (128u * 1024u)
#define VS_MAX_OBJECT (8u * 1024u * 1024u)
#define VS_MAX_DEP (4u * 1024u * 1024u)
#define VS_MAX_STDERR (4u * 1024u * 1024u)
#define VS_MAX_RECEIPT (64u * 1024u)
#define VS_CHILDREN 5u
#define VS_MAX_TOTAL (64u * 1024u * 1024u)
#define VS_KEY_HEX 64u
#define VS_POLICY "z23verify.store.v1\nsigner_uid="
#define VS_PUBLISHER "publisher_uid="
#define VS_PINS_FILE "fixed_result.pins"
#define VS_MAX_PINS 2048u

struct vs_bytes {
    uint8_t *p;
    size_t n;
};

struct vs_member {
    struct zcl_verify_attest_observation view;
    struct vs_bytes record, object, dep, stderr_bytes, receipt;
    struct zcl_fr_binding binding; /* view.binding points here once bound */
};

/* What one lookup expects of every observation under its key. */
struct vs_request {
    const struct zcl_verify_attest_expected *expected;
    const struct zcl_fixed_result_v2_roots *pins;
    uid_t publisher;
};

#ifdef ZCL_TESTING
static void (*vs_before_refresh_hook)(void *);
static void *vs_before_refresh_context;

void zcl_verify_store_test_before_refresh(void (*hook)(void *), void *context)
{
    vs_before_refresh_hook = hook;
    vs_before_refresh_context = context;
}
#endif

static void vs_result_init(struct zcl_verify_store_result *out)
{
    memset(out, 0, sizeof(*out));
    out->verdict = ZCL_VERIFY_STORE_COLD;
    out->reason = "store_unavailable";
    out->lock_fd = -1;
}

void zcl_verify_store_result_release(struct zcl_verify_store_result *result)
{
    if (!result) return;
    free(result->object);
    free(result->depfile);
    free(result->stderr_bytes);
    if (result->lock_fd >= 0) (void)close(result->lock_fd);
    vs_result_init(result);
}

static void vs_set(struct zcl_verify_store_result *out,
                   enum zcl_verify_store_verdict verdict, const char *reason)
{
    out->verdict = verdict;
    out->reason = reason;
}

static bool vs_mode(const struct stat *st, uid_t owner, mode_t type)
{
    return st->st_uid == owner && (st->st_mode & S_IFMT) == type &&
           (st->st_mode & 0022) == 0;
}

static int vs_child_dir(int parent, const char *name, uid_t owner)
{
    int fd = openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW |
                                     O_CLOEXEC);
    struct stat st;
    if (fd < 0) return -1;
    if (fstat(fd, &st) != 0 || !vs_mode(&st, owner, S_IFDIR)) {
        (void)close(fd);
        return -1;
    }
    return fd;
}

static bool vs_same_file(const struct stat *a, const struct stat *b)
{
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino &&
           a->st_uid == b->st_uid && a->st_mode == b->st_mode &&
           a->st_nlink == b->st_nlink && a->st_size == b->st_size &&
           a->st_mtime == b->st_mtime && a->st_ctime == b->st_ctime;
}

static const char *vs_read_exact(int fd, const struct stat *before,
                                 size_t *total, struct vs_bytes *out)
{
    size_t len = (size_t)before->st_size;
    uint8_t *p = zcl_malloc(len ? len : 1u, "verify store artifact");
    if (!p) return "store_out_of_memory";
    const char *why = NULL;
    size_t at = 0;
    while (at < len) {
        ssize_t n = read(fd, p + at, len - at);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) { why = "store_file_changed"; break; }
        at += (size_t)n;
    }
    struct stat after;
    if (!why && (fstat(fd, &after) != 0 ||
                 !vs_same_file(before, &after)))
        why = "store_file_changed";
    if (why) free(p);
    else {
        out->p = p;
        out->n = len;
        *total += len;
    }
    return why;
}

/* A missing artifact is distinct from an empty present artifact. The caller
 * keeps the record in the set either way, so an exact signed FAIL still wins. */
static const char *vs_read_file(int parent, const char *name, uid_t owner,
                                size_t limit, size_t *total,
                                struct vs_bytes *out)
{
    int fd = openat(parent, name, O_RDONLY | O_NONBLOCK | O_NOFOLLOW |
                                     O_CLOEXEC);
    if (fd < 0) return errno == ENOENT ? "store_artifact_missing"
                                      : "store_file_unreadable";
    struct stat before;
    const char *why = NULL;
    if (fstat(fd, &before) != 0 || !vs_mode(&before, owner, S_IFREG) ||
        before.st_nlink != 1)
        why = "store_file_unsafe";
    else if (before.st_size < 0 || (uint64_t)before.st_size > limit ||
             (size_t)before.st_size > VS_MAX_TOTAL - *total)
        why = "store_bytes_limit";
    else
        why = vs_read_exact(fd, &before, total, out);
    if (close(fd) != 0 && !why) why = "store_file_changed";
    return why;
}

static void vs_member_free(struct vs_member *m)
{
    free(m->record.p);
    free(m->object.p);
    free(m->dep.p);
    free(m->stderr_bytes.p);
    free(m->receipt.p);
}

static bool vs_hex_name(const char *name)
{
    if (strlen(name) != VS_KEY_HEX) return false;
    for (size_t i = 0; i < VS_KEY_HEX; ++i)
        if (!((name[i] >= '0' && name[i] <= '9') ||
              (name[i] >= 'a' && name[i] <= 'f')))
            return false;
    return true;
}

static const char *vs_record_name_check(const struct vs_member *m,
                                        const char *name)
{
    uint8_t hash[SHA3_256_OUTPUT_SIZE];
    char hex[VS_KEY_HEX + 1u];
    if (!m->record.p) return "store_record_missing";
    zcl_sha3_256(m->record.p, m->record.n, hash);
    zcl_hex_encode(hash, sizeof(hash), hex);
    return strcmp(hex, name) == 0 ? NULL : "store_record_name_mismatch";
}

static bool vs_dot_name(const char *name)
{
    return strcmp(name, ".") == 0 || strcmp(name, "..") == 0;
}

/* Store layout v2: the signed record, the three reused artifacts and the
 * root launch receipt they were copied from. */
static const char *const k_vs_children[VS_CHILDREN] = {
    "attest.bin", "object.o", "deps.d", "stderr.bin", "launch.bin"
};

static bool vs_known_child(const char *name)
{
    for (size_t i = 0; i < VS_CHILDREN; ++i)
        if (strcmp(name, k_vs_children[i]) == 0) return true;
    return false;
}

static const char *vs_member_children(int fd)
{
    const char *unknown = NULL;
    int scan_fd = dup(fd);
    DIR *entries = scan_fd >= 0 ? fdopendir(scan_fd) : NULL;
    if (!entries) {
        if (scan_fd >= 0) (void)close(scan_fd);
        return "store_observation_unreadable";
    }
    size_t seen = 0;
    for (;;) {
        errno = 0;
        struct dirent *e = readdir(entries);
        if (!e) {
            if (errno != 0) unknown = "store_observation_unreadable";
            break;
        }
        if (vs_dot_name(e->d_name))
            continue;
        if (++seen > VS_CHILDREN) {
            unknown = "store_observation_children_limit";
            break;
        }
        if (!vs_known_child(e->d_name))
            unknown = "store_observation_child_unknown";
    }
    if (closedir(entries) != 0) unknown = "store_observation_unreadable";
    return unknown;
}

static bool vs_limit_failure(const char *why)
{
    return why && (strcmp(why, "store_bytes_limit") == 0 ||
                   strcmp(why, "store_out_of_memory") == 0);
}

/* The receiver's own receipt expectation for this observation. A missing or
 * refused receipt leaves view.binding NULL, so a PASS cannot admit. */
static const char *vs_member_bind(struct vs_member *m,
                                  const struct vs_request *req)
{
    if (!m->receipt.p || !m->record.p) return NULL;
    const struct zcl_fr_artifact_bytes bytes = {
        m->object.p, m->object.n, m->dep.p, m->dep.n,
        m->stderr_bytes.p, m->stderr_bytes.n};
    const char *why = NULL;
    if (!zcl_fr_receipt_bind(m->receipt.p, m->receipt.n, req->pins,
                             req->expected, &bytes, &m->binding, &why))
        return why;
    m->view.binding = &m->binding.binding;
    return NULL;
}

static const char *vs_member_artifacts(int fd, const char *name,
                                       const struct vs_request *req,
                                       size_t *total,
                                       struct vs_member *m, bool *complete)
{
    uid_t owner = req->publisher;
    const char *first = vs_read_file(fd, "attest.bin", owner,
                                     VS_MAX_RECORD, total, &m->record);
    bool record_read = first == NULL;
    const char *why = vs_read_file(fd, "object.o", owner,
                                   VS_MAX_OBJECT, total, &m->object);
    bool bounded = vs_limit_failure(why);
    if (!first) first = why;
    why = vs_read_file(fd, "deps.d", owner, VS_MAX_DEP, total, &m->dep);
    bounded |= vs_limit_failure(why);
    if (!first) first = why;
    why = vs_read_file(fd, "stderr.bin", owner,
                       VS_MAX_STDERR, total, &m->stderr_bytes);
    bounded |= vs_limit_failure(why);
    if (!first) first = why;
    why = vs_read_file(fd, "launch.bin", owner,
                       VS_MAX_RECEIPT, total, &m->receipt);
    bounded |= vs_limit_failure(why);
    if (!first) first = why;
    if (!first) first = vs_record_name_check(m, name);
    m->view = (struct zcl_verify_attest_observation){
        .record_bytes = m->record.p, .record_len = m->record.n,
        .obj_bytes = m->object.p, .obj_len = m->object.n,
        .dep_bytes = m->dep.p, .dep_len = m->dep.n,
        .stderr_bytes = m->stderr_bytes.p, .stderr_len = m->stderr_bytes.n,
        .binding = NULL,
    };
    why = vs_member_bind(m, req);
    if (!first) first = why;
    *complete = record_read && !bounded;
    return first;
}

static const char *vs_member_read(int key_fd, const char *name,
                                  const struct vs_request *req,
                                  size_t *total, struct vs_member *m,
                                  bool *complete)
{
    *complete = false;
    int fd = vs_child_dir(key_fd, name, req->publisher);
    if (fd < 0) return "store_observation_unsafe";
    const char *children_why = vs_member_children(fd);
    const char *why = vs_member_artifacts(fd, name, req, total, m, complete);
    if (close(fd) != 0) *complete = false;
    return why ? why : children_why;
}

static bool vs_scan_entries(DIR *dir, int key_fd, const struct vs_request *req,
                             struct vs_member *members, size_t *count,
                             const char **scan_why)
{
    size_t total = 0, entries_seen = 0;
    bool incomplete = false;
    for (;;) {
        errno = 0;
        struct dirent *e = readdir(dir);
        if (!e) { if (errno != 0) incomplete = true; break; }
        if (vs_dot_name(e->d_name))
            continue;
        if (++entries_seen > VS_MAX_DIR_ENTRIES) { incomplete = true; break; }
        if (!vs_hex_name(e->d_name)) {
            if (!*scan_why) *scan_why = "store_child_unknown";
            continue;
        }
        if (*count == VS_MAX_OBSERVATIONS) { incomplete = true; break; }
        bool member_complete = false;
        const char *why = vs_member_read(key_fd, e->d_name, req,
                                         &total, &members[*count],
                                         &member_complete);
        if (why && !*scan_why) *scan_why = why;
        (*count)++;
        if (!member_complete) incomplete = true;
    }
    return !incomplete;
}

static void vs_take_hit(struct vs_member *m, const char *store_key,
                        const struct zcl_verify_attest_trust_root *root,
                        struct zcl_verify_store_result *out)
{
    out->object = m->object.p; out->object_len = m->object.n;
    out->depfile = m->dep.p; out->depfile_len = m->dep.n;
    out->stderr_bytes = m->stderr_bytes.p;
    out->stderr_len = m->stderr_bytes.n;
    memcpy(out->store_key, store_key, ZCL_VERIFY_ATTEST_STORE_KEY_HEX);
    uint8_t record_hash[SHA3_256_OUTPUT_SIZE];
    zcl_sha3_256(m->record.p, m->record.n, record_hash);
    zcl_hex_encode(record_hash, sizeof(record_hash), out->record_sha3);
    memcpy(out->verifier_pubkey, root->verifier_pubkey,
           sizeof(out->verifier_pubkey));
    m->object.p = m->dep.p = m->stderr_bytes.p = NULL;
    vs_set(out, ZCL_VERIFY_STORE_HIT, NULL);
}

static void vs_scan_decide(struct vs_member *members, size_t count,
                           const char *scan_why, const char *store_key,
                           const struct zcl_verify_attest_expected *expected,
                           const struct zcl_verify_attest_trust_root *root,
                           struct zcl_verify_store_result *out)
{
    struct zcl_verify_attest_observation views[VS_MAX_OBSERVATIONS];
    for (size_t i = 0; i < count; ++i) views[i] = members[i].view;
    size_t selected = SIZE_MAX;
    struct zcl_verify_attest_decision d = zcl_verify_attest_admit_set(
        views, count, expected, root, &selected);
    if (d.verdict == ZCL_VERIFY_ATTEST_FAIL)
        vs_set(out, ZCL_VERIFY_STORE_BLOCK, d.reason);
    else if (scan_why || d.verdict != ZCL_VERIFY_ATTEST_ADMIT ||
             selected >= count)
        vs_set(out, ZCL_VERIFY_STORE_COLD, scan_why ? scan_why : d.reason);
    else
        vs_take_hit(&members[selected], store_key, root, out);
}

/* Full enumeration under LOCK_SH. A bounded overflow blocks rather than
 * compiling past an unseen signed failure. Other malformed children are
 * cold, but all readable records still reach admit_set first. */
static void vs_scan(int key_fd, const struct vs_request *req,
                    const char *store_key,
                    const struct zcl_verify_attest_trust_root *root,
                    struct zcl_verify_store_result *out)
{
    struct vs_member *members = zcl_calloc(VS_MAX_OBSERVATIONS,
                                            sizeof(*members),
                                            "verify store observations");
    if (!members) { vs_set(out, ZCL_VERIFY_STORE_BLOCK, "store_out_of_memory"); return; }
    int iter_fd = dup(key_fd);
    DIR *dir = iter_fd >= 0 ? fdopendir(iter_fd) : NULL;
    if (!dir) {
        if (iter_fd >= 0) (void)close(iter_fd);
        free(members);
        vs_set(out, ZCL_VERIFY_STORE_BLOCK, "store_scan_incomplete");
        return;
    }
    size_t count = 0;
    const char *scan_why = NULL;
    bool complete = vs_scan_entries(dir, key_fd, req, members, &count,
                                     &scan_why);
    if (closedir(dir) != 0) complete = false;
    if (!complete)
        vs_set(out, ZCL_VERIFY_STORE_BLOCK, "store_scan_incomplete");
    else
        vs_scan_decide(members, count, scan_why, store_key, req->expected,
                       root, out);
    for (size_t i = 0; i < count; ++i) vs_member_free(&members[i]);
    free(members);
}

static bool vs_expected_ready(const struct zcl_verify_attest_expected *e)
{
    static const uint8_t zero[ZCL_VERIFY_ATTEST_HASH_BYTES] = {0};
    return e && e->toolchain_id.bytes && e->toolchain_id.len > 0 &&
           e->toolchain_id.len <= ZCL_VERIFY_ATTEST_TOOLCHAIN_MAX &&
           e->argv_norm.bytes && e->argv_norm.len > 0 &&
           e->argv_norm.len <= ZCL_VERIFY_ATTEST_ARGV_MAX &&
           e->recorded_cwd.bytes && e->recorded_cwd.len > 0 &&
           e->recorded_cwd.len <= ZCL_VERIFY_ATTEST_CWD_MAX &&
           memcmp(e->closure_sha3, zero, sizeof(zero)) != 0;
}

static int vs_open_store_lock(int base_fd, uid_t anchor_owner,
                              uid_t publisher, int *store_fd,
                              struct zcl_verify_store_result *out)
{
    int locks_fd = vs_child_dir(base_fd, "locks", anchor_owner);
    *store_fd = vs_child_dir(base_fd, "store", publisher);
    if (locks_fd < 0 || *store_fd < 0) {
        vs_set(out, ZCL_VERIFY_STORE_COLD, "store_path_unsafe");
        if (locks_fd >= 0) (void)close(locks_fd);
        return -1;
    }
    int fd = openat(locks_fd, "fixed_result.lock",
                    O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
    (void)close(locks_fd);
    struct stat st;
    if (fd < 0 || fstat(fd, &st) != 0 || !vs_mode(&st, publisher, S_IFREG) ||
        (st.st_mode & 0777) != 0644 || st.st_nlink != 1) {
        if (fd >= 0) (void)close(fd);
        vs_set(out, ZCL_VERIFY_STORE_COLD, "store_lock_unsafe");
        return -1;
    }
    if (flock(fd, LOCK_SH | LOCK_NB) != 0) {
        (void)close(fd);
        vs_set(out, ZCL_VERIFY_STORE_BLOCK, "store_lock_unavailable");
        return -1;
    }
    return fd;
}

/* Where the policy, the pins and the store live. Production is the one
 * const site below: anchor "/", every directory and policy file root-owned.
 * Only a ZCL_TESTING entry point names another anchor, owned by the test
 * uid, so tests drive this exact policy, custody and lookup code. */
struct vs_site {
    const char *anchor;
    uid_t owner;
};

static const struct vs_site vs_production_site = {"/", 0};
static const char *const vs_etc_path[] = {"etc", "z23verify", NULL};
static const char *const vs_base_path[] = {"var", "lib", "z23verify", NULL};

/* anchor/names... by descriptor, each directory owned by the site owner
 * and not group or world writable. */
static int vs_site_dir(const struct vs_site *site, const char *const *names)
{
    int fd = open(site->anchor, O_RDONLY | O_DIRECTORY | O_NOFOLLOW |
                                    O_CLOEXEC);
    struct stat st;
    if (fd < 0) return -1;
    if (fstat(fd, &st) != 0 || !vs_mode(&st, site->owner, S_IFDIR)) {
        (void)close(fd);
        return -1;
    }
    for (size_t i = 0; names[i]; ++i) {
        int next = vs_child_dir(fd, names[i], site->owner);
        (void)close(fd);
        if (next < 0) return -1;
        fd = next;
    }
    return fd;
}

/* "z23verify.store.v1\nsigner_uid=<N>\npublisher_uid=<site owner>\n".
 * The publisher is the site owner: root in production. The same-uid rule
 * is not here; vs_custody() applies it to every lookup. */
static bool vs_parse_policy_uids(const char *text, size_t len, uid_t owner,
                                 uid_t *signer, uid_t *publisher,
                                 const char **why)
{
    size_t prefix = sizeof(VS_POLICY) - 1u;
    char suffix[40];
    int made = snprintf(suffix, sizeof(suffix), "\n" VS_PUBLISHER "%u\n",
                        (unsigned)owner);
    size_t suffix_len = made > 0 ? (size_t)made : 0u;
    *why = "store_policy_malformed";
    if (suffix_len == 0 || suffix_len >= sizeof(suffix) ||
        len <= prefix + suffix_len ||
        memcmp(text, VS_POLICY, prefix) != 0 ||
        memcmp(text + len - suffix_len, suffix, suffix_len) != 0)
        return false;
    unsigned long value = 0;
    for (size_t i = prefix; i < len - suffix_len; ++i) {
        unsigned digit = (unsigned)(text[i] - '0');
        if (!isdigit((unsigned char)text[i]) ||
            value > (UINT_MAX - digit) / 10ul)
            return false;
        value = value * 10ul + digit;
    }
    if (value == 0 || value > UINT_MAX) return false;
    *why = NULL;
    *signer = (uid_t)value;
    *publisher = owner;
    return true;
}

static bool vs_read_policy_file(int fd, uid_t owner, uid_t *signer,
                                uid_t *publisher, const char **why)
{
    struct stat before, after;
    if (fstat(fd, &before) != 0 || !vs_mode(&before, owner, S_IFREG) ||
        (before.st_mode & 0777) != 0444 || before.st_nlink != 1 ||
        before.st_size < 0 || before.st_size > 96) {
        *why = "store_policy_unsafe";
        return false;
    }
    char text[97];
    size_t at = 0;
    while (at < (size_t)before.st_size) {
        ssize_t n = read(fd, text + at, (size_t)before.st_size - at);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) { *why = "store_policy_changed"; return false; }
        at += (size_t)n;
    }
    if (fstat(fd, &after) != 0 || !vs_same_file(&before, &after)) {
        *why = "store_policy_changed";
        return false;
    }
    text[at] = '\0';
    return vs_parse_policy_uids(text, at, owner, signer, publisher, why);
}

/* The site's store.policy, walked by descriptor from the anchor on every
 * call. No environment override is compiled into this loader. */
static bool vs_site_policy(const struct vs_site *site, uid_t *signer,
                           uid_t *publisher, const char **why)
{
    int dir = vs_site_dir(site, vs_etc_path);
    if (dir < 0) { *why = "store_policy_path_unsafe"; return false; }
    int fd = openat(dir, "store.policy", O_RDONLY | O_NONBLOCK | O_NOFOLLOW |
                                           O_CLOEXEC);
    bool ok = false;
    *why = "store_policy_missing";
    if (fd >= 0) ok = vs_read_policy_file(fd, site->owner, signer, publisher,
                                          why);
    if (fd >= 0) (void)close(fd);
    (void)close(dir);
    return ok;
}

static const char *vs_site_pins(const struct vs_site *site,
                                struct zcl_fixed_result_v2_roots *out);

static bool vs_pins_equal(const struct zcl_fixed_result_v2_roots *a,
                          const struct zcl_fixed_result_v2_roots *b)
{
    for (size_t i = 0; i < ZCL_FR_ROOT_COUNT; ++i) {
        if (memcmp(zcl_fr_root_at(a, i), zcl_fr_root_at(b, i), 32u) != 0)
            return false;
    }
    return true;
}

static void vs_refresh_hit(const struct vs_site *site, uid_t signer,
                           uid_t publisher,
                           const struct zcl_fixed_result_v2_roots *pins,
                           const struct zcl_verify_attest_box_key *box,
                           const struct zcl_verify_attest_trust_root *root,
                           struct zcl_verify_store_result *out)
{
    struct zcl_verify_attest_trust_root current;
    struct zcl_fixed_result_v2_roots current_pins;
    uid_t fresh_signer = 0, fresh_publisher = 0;
    const char *why = NULL, *policy_why = NULL, *pins_why = NULL;
    bool policy_current = !site ||
        (vs_site_policy(site, &fresh_signer, &fresh_publisher, &policy_why) &&
         fresh_signer == signer && fresh_publisher == publisher);
    bool pins_current = !site ||
        (vs_site_pins(site, &current_pins) == NULL &&
         vs_pins_equal(pins, &current_pins));
    if (site && !pins_current) pins_why = "store_pins_changed";
    bool key_current = zcl_verify_attest_trust_root_load(NULL, box, &current,
                                                          &why) &&
        memcmp(root->verifier_pubkey, current.verifier_pubkey,
               ZCL_VERIFY_ATTEST_PUBKEY_BYTES) == 0;
    if (policy_current && pins_current && key_current)
        return;
    free(out->object); free(out->depfile); free(out->stderr_bytes);
    out->object = out->depfile = out->stderr_bytes = NULL;
    out->object_len = out->depfile_len = out->stderr_len = 0;
    memset(out->store_key, 0, sizeof(out->store_key));
    memset(out->record_sha3, 0, sizeof(out->record_sha3));
    memset(out->verifier_pubkey, 0, sizeof(out->verifier_pubkey));
    vs_set(out, ZCL_VERIFY_STORE_COLD,
           !policy_current ? "store_policy_changed" :
           !pins_current ? pins_why :
           (why ? why : "verifier_key_changed"));
}

static const char *vs_request_ready(const struct vs_request *req)
{
    if (!vs_expected_ready(req->expected)) return "store_expected_unqualified";
    if (!req->pins) return "store_pins_unqualified";
    return zcl_fr_roots_check(req->pins);
}

static void vs_lookup_at(int base_fd, uid_t anchor_owner, uid_t signer,
                         const struct vs_site *site,
                         const struct vs_request *req,
                         const struct zcl_verify_attest_box_key *box,
                         struct zcl_verify_store_result *out)
{
    int store_fd = -1, lock_fd = -1, key_fd = -1;
    const struct zcl_verify_attest_expected *expected = req->expected;
    const char *why = vs_request_ready(req);
    if (why) {
        vs_set(out, ZCL_VERIFY_STORE_COLD, why);
        return;
    }
    if (!box || !box->known) {
        vs_set(out, ZCL_VERIFY_STORE_COLD, "box_signer_key_unknown");
        return;
    }
    struct zcl_verify_attest_trust_root root;
    if (!zcl_verify_attest_trust_root_load(NULL, box, &root, &why)) {
        vs_set(out, ZCL_VERIFY_STORE_COLD, why);
        return;
    }
    lock_fd = vs_open_store_lock(base_fd, anchor_owner, req->publisher,
                                 &store_fd,
                                 out);
    if (lock_fd < 0) goto done;
    char key[ZCL_VERIFY_ATTEST_STORE_KEY_HEX];
    zcl_verify_attest_store_key_hex(&expected->toolchain_id,
                                    &expected->argv_norm,
                                    &expected->recorded_cwd,
                                    expected->pp_sha3,
                                    expected->closure_sha3, key);
    key_fd = vs_child_dir(store_fd, key, req->publisher);
    if (key_fd < 0) {
        vs_set(out, ZCL_VERIFY_STORE_COLD,
               errno == ENOENT ? "attest_no_observation" : "store_key_unsafe");
        goto done;
    }
    vs_scan(key_fd, req, key, &root, out);
    if (out->verdict == ZCL_VERIFY_STORE_HIT) {
#ifdef ZCL_TESTING
        if (vs_before_refresh_hook)
            vs_before_refresh_hook(vs_before_refresh_context);
#endif
        vs_refresh_hit(site, signer, req->publisher, req->pins, box, &root,
                       out);
        if (out->verdict == ZCL_VERIFY_STORE_HIT) {
            out->lock_fd = lock_fd;
            lock_fd = -1;
        }
    }
done:
    if (key_fd >= 0) (void)close(key_fd);
    if (lock_fd >= 0) (void)close(lock_fd);
    if (store_fd >= 0) (void)close(store_fd);
}

/* Pins v2 under an already-verified directory: one nlink-1 regular file,
 * mode exactly 0444, owned by `owner`, opened without following a link and
 * read by descriptor. Every framing or value fault keeps its contract token. */
static bool vs_pins_qualified(const struct stat *st, uid_t owner)
{
    return vs_mode(st, owner, S_IFREG) && (st->st_mode & 0777) == 0444 &&
           st->st_nlink == 1 && st->st_size > 0 &&
           st->st_size <= (off_t)VS_MAX_PINS;
}

static bool vs_pins_bytes(int fd, uint8_t *bytes, size_t len)
{
    size_t at = 0;
    while (at < len) {
        ssize_t n = read(fd, bytes + at, len - at);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return false;
        at += (size_t)n;
    }
    return true;
}

static const char *vs_pins_read(int dir, uid_t owner,
                                struct zcl_fixed_result_v2_roots *out)
{
    int fd = openat(dir, VS_PINS_FILE, O_RDONLY | O_NONBLOCK | O_NOFOLLOW |
                                         O_CLOEXEC);
    if (fd < 0) return errno == ENOENT ? "store_pins_missing"
                                      : "store_pins_unsafe";
    struct stat before, after;
    uint8_t bytes[VS_MAX_PINS];
    const char *why = NULL;
    if (fstat(fd, &before) != 0 || !vs_pins_qualified(&before, owner))
        why = "store_pins_unsafe";
    else if (!vs_pins_bytes(fd, bytes, (size_t)before.st_size) ||
             fstat(fd, &after) != 0 || !vs_same_file(&before, &after))
        why = "store_pins_changed";
    if (close(fd) != 0 && !why) why = "store_pins_changed";
    if (!why && !zcl_fr_pins_parse(bytes, (size_t)before.st_size, out, &why) &&
        !why)
        why = "store_pins_unqualified";
    return why;
}


static const char *vs_site_pins(const struct vs_site *site,
                                struct zcl_fixed_result_v2_roots *out)
{
    int dir = vs_site_dir(site, vs_etc_path);
    const char *why = dir >= 0 ? vs_pins_read(dir, site->owner, out)
                               : "store_pins_path_unsafe";
    if (dir >= 0) (void)close(dir);
    if (why) memset(out, 0, sizeof(*out));
    return why;
}

bool zcl_verify_store_pins_load(struct zcl_fixed_result_v2_roots *out,
                                const char **why)
{
    const char *reason = out ? vs_site_pins(&vs_production_site, out)
                             : "store_pins_unqualified";
    if (why) *why = reason;
    return reason == NULL;
}

/* The one same-uid rule; every lookup passes it before reading a store
 * file. A receiver running as the signer or the publisher could have
 * written what it is about to trust. Only a ZCL_TESTING entry point can
 * pass allow_same_uid; production passes false. */
static const char *vs_custody(uid_t signer, uid_t publisher,
                              bool allow_same_uid)
{
    if (signer == 0) return "store_owner_same_uid";
    if (allow_same_uid) return NULL;
    if (signer == geteuid()) return "store_owner_same_uid";
    if (publisher == geteuid()) return "store_owner_same_uid";
    return NULL;
}

/* Uids, pins and store base named directly: the uid fixture only. */
struct vs_given {
    const char *root;
    uid_t signer, publisher;
    const struct zcl_fixed_result_v2_roots *pins;
};

/* One lookup's resolved inputs, from the site or from vs_given. */
struct vs_plan {
    uid_t signer, publisher, anchor_owner;
    const struct zcl_fixed_result_v2_roots *pins;
    struct zcl_fixed_result_v2_roots loaded;
};

/* Policy (site) or given uids, then custody, then pins. */
static const char *vs_plan_make(const struct vs_site *site,
                                const struct vs_given *given,
                                bool allow_same_uid, struct vs_plan *plan)
{
    const char *why = NULL;
    memset(plan, 0, sizeof(*plan));
    if (given) {
        plan->signer = given->signer;
        plan->publisher = given->publisher;
        plan->anchor_owner = given->signer;
        plan->pins = given->pins;
    } else if (!vs_site_policy(site, &plan->signer, &plan->publisher, &why)) {
        return why;
    }
    why = vs_custody(plan->signer, plan->publisher, allow_same_uid);
    if (why || given) return why;
    plan->anchor_owner = site->owner;
    plan->pins = &plan->loaded;
    return vs_site_pins(site, &plan->loaded);
}

/* The store base: the given root, owned by the signer, or the site's
 * var/lib/z23verify. */
static int vs_plan_base(const struct vs_site *site,
                        const struct vs_given *given)
{
    if (!given) return vs_site_dir(site, vs_base_path);
    if (!given->root || given->root[0] != '/') return -1;
    int fd = open(given->root, O_RDONLY | O_DIRECTORY | O_NOFOLLOW |
                                   O_CLOEXEC);
    struct stat st;
    if (fd >= 0 && (fstat(fd, &st) != 0 ||
                    !vs_mode(&st, given->signer, S_IFDIR))) {
        (void)close(fd);
        return -1;
    }
    return fd;
}

/* Production and both ZCL_TESTING entry points run this. `given` is NULL
 * except for the uid fixture; the site is production's except for the
 * site fixture. */
static void vs_lookup_shared(const struct vs_site *site,
                             const struct vs_given *given, bool allow_same_uid,
                             const struct zcl_verify_attest_expected *expected,
                             const struct zcl_verify_attest_box_key *box,
                             struct zcl_verify_store_result *out)
{
    if (!out) return;
    vs_result_init(out);
    struct vs_plan plan;
    const char *why = vs_plan_make(site, given, allow_same_uid, &plan);
    if (why) {
        vs_set(out, ZCL_VERIFY_STORE_COLD, why);
        return;
    }
    int base = vs_plan_base(site, given);
    if (base < 0) {
        vs_set(out, ZCL_VERIFY_STORE_COLD, "store_path_unsafe");
        return;
    }
    const struct vs_request req = {expected, plan.pins, plan.publisher};
    vs_lookup_at(base, plan.anchor_owner, plan.signer, given ? NULL : site,
                 &req, box, out);
    (void)close(base);
}

void zcl_verify_store_lookup(const struct zcl_verify_attest_expected *expected,
                             const struct zcl_verify_attest_box_key *box,
                             struct zcl_verify_store_result *out)
{
    vs_lookup_shared(&vs_production_site, NULL, false, expected, box, out);
}

#ifdef ZCL_TESTING
void zcl_verify_store_lookup_fixture(
    const char *root_path, unsigned signer_uid, unsigned publisher_uid,
    bool allow_same_uid,
    const struct zcl_verify_attest_expected *expected,
    const struct zcl_fixed_result_v2_roots *pins,
    const struct zcl_verify_attest_box_key *box,
    struct zcl_verify_store_result *out)
{
    const struct vs_given given = {root_path, (uid_t)signer_uid,
                                   (uid_t)publisher_uid, pins};
    vs_lookup_shared(&vs_production_site, &given, allow_same_uid, expected,
                     box, out);
}

void zcl_verify_store_lookup_site_fixture(
    const char *anchor, bool allow_same_uid,
    const struct zcl_verify_attest_expected *expected,
    const struct zcl_verify_attest_box_key *box,
    struct zcl_verify_store_result *out)
{
    if (!anchor || anchor[0] != '/') {
        if (out) {
            vs_result_init(out);
            vs_set(out, ZCL_VERIFY_STORE_COLD, "store_path_unsafe");
        }
        return;
    }
    const struct vs_site site = {anchor, geteuid()};
    vs_lookup_shared(&site, NULL, allow_same_uid, expected, box, out);
}

const char *zcl_verify_store_pins_load_fixture(
    const char *dir_path, unsigned dir_owner, unsigned file_owner,
    struct zcl_fixed_result_v2_roots *out)
{
    if (!out) return "store_pins_unqualified";
    memset(out, 0, sizeof(*out));
    int dir = dir_path ? open(dir_path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW |
                                            O_CLOEXEC) : -1;
    struct stat st;
    const char *why = "store_pins_path_unsafe";
    if (dir >= 0 && fstat(dir, &st) == 0 &&
        vs_mode(&st, (uid_t)dir_owner, S_IFDIR))
        why = vs_pins_read(dir, (uid_t)file_owner, out);
    if (dir >= 0) (void)close(dir);
    if (why) memset(out, 0, sizeof(*out));
    return why;
}
#endif
