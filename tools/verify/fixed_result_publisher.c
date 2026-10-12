/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0.
 * purpose: The fixed-result publisher core: re-verify signed staging,
 *          then add it no-clobber to the root-owned observation store
 *          under the exclusive publication lock. See
 *          fixed_result_publisher.h. */
#if defined(__linux__)
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "verify/fixed_result_publisher.h"

#include "base/hex.h"
#include "base/safe_alloc.h"
#include "sha3/sha3.h"
#include "verify/fixed_result_contract.h"
#include "verify/fixed_result_signer.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define FRP_RECORD_MAX (128u * 1024u)
#define FRP_RECEIPT_MAX (64u * 1024u)
#define FRP_OBJECT_MAX (8u * 1024u * 1024u)
#define FRP_OUTPUT_MAX (4u * 1024u * 1024u)
#define FRP_LOCK_STEP_MS 10u
/* The publisher scans at most 96 record directories per key; once a key
 * holds more, the scan overflows and the key refuses every
 * further publish with publisher_store_unsafe; receivers already BLOCK
 * past their own 64-observation scan bound (store_scan_incomplete). */
#define FRP_SCAN_MAX 96u

enum {
    FRP_ATTEST = 0, FRP_LAUNCH, FRP_STDERR, FRP_OBJECT, FRP_DEPS, FRP_FILES
};

static const char *const k_frp_names[FRP_FILES] = {
    "attest.bin", "launch.bin", "stderr.bin", "object.o", "deps.d"
};

static const size_t k_frp_max[FRP_FILES] = {
    FRP_RECORD_MAX, FRP_RECEIPT_MAX, FRP_OUTPUT_MAX, FRP_OBJECT_MAX,
    FRP_OUTPUT_MAX
};

struct frp_bytes {
    uint8_t *p;
    size_t n;
};

struct frp_work {
    struct frp_bytes file[FRP_FILES];
    struct zcl_frs_launch launch;
    struct zcl_fixed_result_v2_expected expected;
    struct zcl_verify_attest_trust_root root;
    char record_hex[ZCL_VERIFY_ATTEST_STORE_KEY_HEX];
    char store_key[ZCL_VERIFY_ATTEST_STORE_KEY_HEX];
};

static void frp_work_free(struct frp_work *w)
{
    for (size_t i = 0; i < FRP_FILES; i++) free(w->file[i].p);
}

static bool frp_hex64(const char *s)
{
    if (!s || strlen(s) != 64u) return false;
    for (size_t i = 0; i < 64u; i++)
        if (!((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f')))
            return false;
    return true;
}

/* ── staging ──────────────────────────────────────────────────────────── */

static const char *frp_owned_dir(int fd, uint32_t owner)
{
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISDIR(st.st_mode) ||
        (st.st_mode & 0022u) != 0)
        return ZCL_FRP_WHY_STAGING_UNSAFE;
    return st.st_uid == owner ? NULL : ZCL_FRP_WHY_STAGING_OWNER;
}

static int frp_open_staging(int parent, const char *name, uint32_t owner,
                            const char **why)
{
    int fd = openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW |
                                      O_CLOEXEC);
    if (fd < 0) {
        *why = errno == ENOENT ? ZCL_FRP_WHY_STAGING_MISSING
                               : ZCL_FRP_WHY_STAGING_UNSAFE;
        return -1;
    }
    *why = frp_owned_dir(fd, owner);
    if (!*why) return fd;
    (void)close(fd);
    return -1;
}

static int frp_name_index(const char *name)
{
    for (int i = 0; i < FRP_FILES; i++)
        if (strcmp(name, k_frp_names[i]) == 0) return i;
    return -1;
}

/* Only the store layout's names, each at most once (a directory cannot
 * repeat a name, so the count bound is the whole check). */
static const char *frp_staging_names(int dir)
{
    int scan = dup(dir);
    DIR *d = scan >= 0 ? fdopendir(scan) : NULL;
    if (!d) {
        if (scan >= 0) (void)close(scan);
        return ZCL_FRP_WHY_STAGING_UNSAFE;
    }
    const char *why = NULL;
    for (struct dirent *e; !why && (errno = 0, e = readdir(d)) != NULL;) {
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
            continue;
        if (frp_name_index(e->d_name) < 0) why = ZCL_FRP_WHY_STAGING_CHILD;
    }
    if (!why && errno != 0) why = ZCL_FRP_WHY_STAGING_UNSAFE;
    (void)closedir(d);
    return why;
}

static const char *frp_read_entry(int dir, int index, uint32_t owner,
                                  struct frp_bytes *out)
{
    int fd = openat(dir, k_frp_names[index], O_RDONLY | O_NOFOLLOW |
                                                 O_NONBLOCK | O_CLOEXEC);
    if (fd < 0)
        return errno == ENOENT ? NULL : ZCL_FRP_WHY_STAGING_ENTRY;
    const struct zcl_frt_custody custody = {owner, 0u, k_frp_max[index]};
    const char *why = NULL;
    bool ok = zcl_frt_read_fd(fd, &custody, &out->p, &out->n, &why);
    (void)close(fd);
    return ok ? NULL : ZCL_FRP_WHY_STAGING_ENTRY;
}

static const char *frp_read_staging(const struct zcl_frt_trust *t,
                                    int staging, struct frp_work *w)
{
    const char *why = NULL;
    int dir = frp_open_staging(staging, w->record_hex, t->signer_uid, &why);
    if (dir < 0) return why;
    why = frp_staging_names(dir);
    for (int i = 0; i < FRP_FILES && !why; i++)
        why = frp_read_entry(dir, i, t->signer_uid, &w->file[i]);
    (void)close(dir);
    if (!why && (!w->file[FRP_ATTEST].p || !w->file[FRP_LAUNCH].p ||
                 !w->file[FRP_STDERR].p))
        why = ZCL_FRP_WHY_STAGING_INCOMPLETE;
    return why;
}

/* ── verification ─────────────────────────────────────────────────────── */

static const char *frp_record_name(struct frp_work *w)
{
    uint8_t hash[32];
    char hex[ZCL_VERIFY_ATTEST_STORE_KEY_HEX];
    zcl_sha3_256(w->file[FRP_ATTEST].p, w->file[FRP_ATTEST].n, hash);
    zcl_hex_encode(hash, sizeof(hash), hex);
    return strcmp(hex, w->record_hex) == 0 ? NULL : ZCL_FRP_WHY_RECORD_NAME;
}

/* The staged launch.bin must be the root launcher's own record, byte for
 * byte: the signer cannot write a root-owned file, so this is what makes
 * the receipt root-written rather than signer-claimed. */
static const char *frp_root_launch(const struct zcl_frt_trust *t, int state,
                                   const struct frp_work *w)
{
    const char *why = NULL;
    int launches = zcl_frt_open_dir(state, "launches", t->launcher_uid,
                                    false, &why);
    int dir = launches >= 0
                  ? zcl_frt_open_dir(launches, w->launch.f.launch.launch_id,
                                     t->launcher_uid, false, &why)
                  : -1;
    const struct zcl_frt_custody custody = {t->launcher_uid, 0444u,
                                            FRP_RECEIPT_MAX};
    uint8_t *bytes = NULL;
    size_t len = 0;
    bool same = dir >= 0 &&
                zcl_frt_read_file(dir, "launch.bin", &custody, &bytes, &len,
                                  &why) &&
                len == w->file[FRP_LAUNCH].n &&
                memcmp(bytes, w->file[FRP_LAUNCH].p, len) == 0;
    free(bytes);
    if (dir >= 0) (void)close(dir);
    if (launches >= 0) (void)close(launches);
    return same ? NULL : ZCL_FRP_WHY_ROOT_LAUNCH;
}

static const char *frp_admit_pass(const struct zcl_frt_trust *t,
                                  const struct frp_work *w)
{
    const struct frp_bytes *f = w->file;
    if (!f[FRP_OBJECT].p || !f[FRP_DEPS].p) return ZCL_FRP_WHY_STAGING_INCOMPLETE;
    const struct zcl_fr_artifact_bytes artifacts = {
        f[FRP_OBJECT].p, f[FRP_OBJECT].n, f[FRP_DEPS].p, f[FRP_DEPS].n,
        f[FRP_STDERR].p, f[FRP_STDERR].n};
    struct zcl_fr_binding binding;
    const char *why = NULL;
    if (!zcl_fr_receipt_bind(f[FRP_LAUNCH].p, f[FRP_LAUNCH].n, &t->pins,
                             &w->expected.expected, &artifacts, &binding,
                             &why))
        return why;
    struct zcl_verify_attest_decision d = zcl_verify_attest_admit(
        f[FRP_ATTEST].p, f[FRP_ATTEST].n, f[FRP_OBJECT].p, f[FRP_OBJECT].n,
        f[FRP_DEPS].p, f[FRP_DEPS].n, f[FRP_STDERR].p, f[FRP_STDERR].n,
        &binding.binding, &w->expected.expected, &w->root);
    return d.verdict == ZCL_VERIFY_ATTEST_ADMIT ? NULL : d.reason;
}

static bool frp_text_eq(const struct zcl_verify_attest_text *a,
                        const struct zcl_verify_attest_text *b)
{
    return a->len == b->len && (a->len == 0u ||
                                memcmp(a->bytes, b->bytes, a->len) == 0);
}

/* The signed failure must repeat exactly the record the publisher derives
 * from the root failure receipt. */
static const char *frp_failure_binding(const struct zcl_verify_attest_record *have,
                                       const struct zcl_verify_attest_record *want)
{
    if (!frp_text_eq(&have->binding.contract, &want->binding.contract))
        return ZCL_VERIFY_ATTEST_WHY_CONTRACT_MISMATCH;
    if (memcmp(have->binding.profile_sha3, want->binding.profile_sha3, 32u))
        return ZCL_VERIFY_ATTEST_WHY_PROFILE_MISMATCH;
    if (!frp_text_eq(&have->binding.target, &want->binding.target))
        return ZCL_VERIFY_ATTEST_WHY_TARGET_MISMATCH;
    if (memcmp(have->binding.receipt_sha3, want->binding.receipt_sha3, 32u))
        return ZCL_VERIFY_ATTEST_WHY_RECEIPT_MISMATCH;
    if (memcmp(have->obj_sha3, want->obj_sha3, 32u))
        return ZCL_VERIFY_ATTEST_WHY_OBJ_MISMATCH;
    if (memcmp(have->dep_sha3, want->dep_sha3, 32u))
        return ZCL_VERIFY_ATTEST_WHY_DEP_MISMATCH;
    if (memcmp(have->stderr_sha3, want->stderr_sha3, 32u))
        return ZCL_VERIFY_ATTEST_WHY_STDERR_MISMATCH;
    return have->exit_code == want->exit_code ? NULL : ZCL_FRP_WHY_FAILURE_EXIT;
}

static const char *frp_admit_failure(const struct zcl_frt_trust *t,
                                     const struct frp_work *w)
{
    const struct frp_bytes *f = w->file;
    if (f[FRP_OBJECT].p || f[FRP_DEPS].p) return ZCL_FRP_WHY_STAGING_CHILD;
    uint8_t hash[32];
    zcl_sha3_256(f[FRP_STDERR].p, f[FRP_STDERR].n, hash);
    if (memcmp(hash, w->launch.f.launch.artifacts[2].sha3, 32u) != 0 ||
        f[FRP_STDERR].n != w->launch.f.launch.artifacts[2].size)
        return ZCL_FR_WHY_RECEIPT_ARTIFACT;
    struct zcl_verify_attest_decision d = zcl_verify_attest_admit(
        f[FRP_ATTEST].p, f[FRP_ATTEST].n, NULL, 0u, NULL, 0u,
        f[FRP_STDERR].p, f[FRP_STDERR].n, NULL, &w->expected.expected,
        &w->root);
    if (d.verdict != ZCL_VERIFY_ATTEST_FAIL ||
        strcmp(d.reason, ZCL_VERIFY_ATTEST_WHY_EXIT_NONZERO) != 0)
        return d.reason ? d.reason : ZCL_VERIFY_ATTEST_WHY_MALFORMED;
    struct zcl_verify_attest_signed parsed;
    struct zcl_verify_attest_record want;
    const char *why = NULL;
    if (!zcl_verify_attest_parse(f[FRP_ATTEST].p, f[FRP_ATTEST].n, &parsed,
                                 &why))
        return why;
    zcl_frs_record(t, &w->launch, &w->expected, &want);
    return frp_failure_binding(&parsed.record, &want);
}

static const char *frp_verify(const struct zcl_frt_trust *t, int state,
                              struct frp_work *w)
{
    const char *why = frp_record_name(w);
    if (!why)
        why = zcl_frs_launch_parse(w->file[FRP_LAUNCH].p, w->file[FRP_LAUNCH].n,
                                   &w->launch);
    if (!why) why = frp_root_launch(t, state, w);
    if (!why)
        why = zcl_frs_expected_rebuild(t, &w->launch,
                                       w->launch.f.launch.artifacts[3].sha3,
                                       &w->expected);
    if (why) return why;
    w->root.loaded = true;
    memcpy(w->root.verifier_pubkey, t->verifier_pubkey, 32u);
    w->root.box = t->box;
    why = w->launch.failure ? frp_admit_failure(t, w) : frp_admit_pass(t, w);
    if (!why) {
        const struct zcl_verify_attest_expected *e = &w->expected.expected;
        zcl_verify_attest_store_key_hex(&e->toolchain_id, &e->argv_norm,
                                        &e->recorded_cwd, e->pp_sha3,
                                        e->closure_sha3, w->store_key);
    }
    return why;
}

/* ── the publication lock ─────────────────────────────────────────────── */

static int frp_lock_open(const struct zcl_frt_trust *t, int state,
                         const char **why)
{
    int locks = zcl_frt_open_dir(state, "locks", t->publisher_uid, false, why);
    int fd = locks >= 0 ? openat(locks, "fixed_result.lock",
                                 O_RDONLY | O_NOFOLLOW | O_NONBLOCK |
                                     O_CLOEXEC)
                        : -1;
    if (locks >= 0) (void)close(locks);
    struct stat st;
    if (fd >= 0 && fstat(fd, &st) == 0 && S_ISREG(st.st_mode) &&
        st.st_uid == t->publisher_uid && (st.st_mode & 07777u) == 0644u &&
        st.st_nlink == 1)
        return fd;
    if (fd >= 0) (void)close(fd);
    *why = ZCL_FRP_WHY_LOCK_UNSAFE;
    return -1;
}

/* LOCK_EX within the deadline. A reader (or anyone who can open the
 * public lock) may hold LOCK_SH; waiting forever would hand them a
 * denial of the whole publisher. */
static bool frp_lock_take(int fd, unsigned deadline_ms)
{
    const struct timespec step = {0, (long)FRP_LOCK_STEP_MS * 1000000L};
    for (unsigned waited = 0;; waited += FRP_LOCK_STEP_MS) {
        if (flock(fd, LOCK_EX | LOCK_NB) == 0) return true;
        if (errno != EWOULDBLOCK && errno != EINTR) return false;
        if (waited >= deadline_ms) return false;
        (void)nanosleep(&step, NULL);
    }
}

/* ── the store ────────────────────────────────────────────────────────── */

static int frp_key_dir(const struct zcl_frt_trust *t, int store,
                       const char *key, const char **why)
{
    if (mkdirat(store, key, 0755) != 0 && errno != EEXIST) {
        *why = ZCL_FRP_WHY_STORE_UNSAFE;
        return -1;
    }
    int fd = zcl_frt_open_dir(store, key, t->publisher_uid, false, why);
    if (fd >= 0 && fchmod(fd, 0755) == 0) return fd;
    if (fd >= 0) (void)close(fd);
    *why = ZCL_FRP_WHY_STORE_UNSAFE;
    return -1;
}

struct frp_existing {
    bool record_exists;
    bool signed_pass;
    bool signed_fail;
};

/* Classify one existing observation by its record alone. A signed FAIL is
 * a verified failure (admit says so); a signed PASS verifies up to the
 * missing binding. Anything unverified can neither conflict nor admit. */
static void frp_classify(int key_fd, const char *name, const struct frp_work *w,
                         const struct zcl_frt_trust *t,
                         struct frp_existing *seen)
{
    int dir = zcl_frt_open_dir(key_fd, name, t->publisher_uid, false, NULL);
    const struct zcl_frt_custody custody = {t->publisher_uid, 0u,
                                            FRP_RECORD_MAX};
    uint8_t *bytes = NULL;
    size_t len = 0;
    const char *why = NULL;
    if (dir >= 0 &&
        zcl_frt_read_file(dir, "attest.bin", &custody, &bytes, &len, &why)) {
        struct zcl_verify_attest_decision d = zcl_verify_attest_admit(
            bytes, len, NULL, 0u, NULL, 0u, NULL, 0u, NULL,
            &w->expected.expected, &w->root);
        if (d.verdict == ZCL_VERIFY_ATTEST_FAIL)
            seen->signed_fail = true;
        else if (d.reason &&
                 strcmp(d.reason, ZCL_VERIFY_ATTEST_WHY_BINDING_MISSING) == 0)
            seen->signed_pass = true;
    }
    free(bytes);
    if (dir >= 0) (void)close(dir);
}

static const char *frp_scan(int key_fd, const struct frp_work *w,
                            const struct zcl_frt_trust *t,
                            struct frp_existing *seen)
{
    int scan = dup(key_fd);
    DIR *d = scan >= 0 ? fdopendir(scan) : NULL;
    if (!d) {
        if (scan >= 0) (void)close(scan);
        return ZCL_FRP_WHY_STORE_UNSAFE;
    }
    size_t count = 0;
    const char *why = NULL;
    for (struct dirent *e; !why && (errno = 0, e = readdir(d)) != NULL;) {
        if (!frp_hex64(e->d_name)) continue;
        if (++count > FRP_SCAN_MAX) why = ZCL_FRP_WHY_STORE_UNSAFE;
        else if (strcmp(e->d_name, w->record_hex) == 0)
            seen->record_exists = true;
        else
            frp_classify(key_fd, e->d_name, w, t, seen);
    }
    if (!why && errno != 0) why = ZCL_FRP_WHY_STORE_UNSAFE;
    (void)closedir(d);
    return why;
}

/* `exists`, when given, is set only from openat's own errno, before any
 * later call can overwrite it. */
static bool frp_write_file(int dir, const char *name, int mode,
                           const struct frp_bytes *b, bool *exists)
{
    int fd = openat(dir, name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW |
                                   O_CLOEXEC, mode);
    int open_errno = fd < 0 ? errno : 0;
    if (exists) *exists = open_errno == EEXIST;
    if (fd < 0) return false;
    size_t at = 0;
    while (at < b->n) {
        ssize_t k = write(fd, b->p + at, b->n - at);
        if (k < 0 && errno == EINTR) continue;
        if (k <= 0) break;
        at += (size_t)k;
    }
    bool ok = at == b->n && fchmod(fd, (mode_t)mode) == 0 && fsync(fd) == 0;
    return close(fd) == 0 && ok;
}

/* An audit note for the operator in conflicts/, beside (never instead of)
 * the conflicting record the store now holds for the receiver. */
static bool frp_record_conflict(const struct zcl_frt_trust *t, int state,
                                const struct frp_work *w)
{
    int dir = zcl_frt_open_dir(state, "conflicts", t->publisher_uid, true,
                               NULL);
    char name[160];
    int n = snprintf(name, sizeof(name), "%s.%s.attest", w->store_key,
                     w->record_hex);
    bool ok = dir >= 0 && n > 0 && (size_t)n < sizeof(name);
    bool exists = false;
    if (ok && !frp_write_file(dir, name, 0600, &w->file[FRP_ATTEST], &exists))
        ok = exists;
    if (ok) ok = fsync(dir) == 0;
    if (dir >= 0) (void)close(dir);
    return ok;
}

static size_t frp_publish_set(const struct frp_work *w, int set[FRP_FILES])
{
    size_t n = 0;
    set[n++] = FRP_ATTEST;
    set[n++] = FRP_LAUNCH;
    set[n++] = FRP_STDERR;
    if (!w->launch.failure) {
        set[n++] = FRP_OBJECT;
        set[n++] = FRP_DEPS;
    }
    return n;
}

static void frp_discard(int tmp_parent, const char *name, int dir,
                        const int set[FRP_FILES], size_t n)
{
    for (size_t i = 0; dir >= 0 && i < n; i++)
        (void)unlinkat(dir, k_frp_names[set[i]], 0);
    (void)unlinkat(tmp_parent, name, AT_REMOVEDIR);
}

/* Fill a root-owned temporary directory, make it world-readable, fsync
 * every file and the directory. */
static bool frp_fill(int dir, const struct frp_work *w,
                     const int set[FRP_FILES], size_t n)
{
    bool ok = true;
    for (size_t i = 0; ok && i < n; i++)
        ok = frp_write_file(dir, k_frp_names[set[i]], 0644, &w->file[set[i]],
                            NULL);
    return ok && fchmod(dir, 0755) == 0 && fsync(dir) == 0;
}

static const char *frp_same_device(int a, int b)
{
    struct stat sa, sb;
    if (fstat(a, &sa) != 0 || fstat(b, &sb) != 0) return ZCL_FRP_WHY_STORE_UNSAFE;
    return sa.st_dev == sb.st_dev ? NULL : ZCL_FRP_WHY_CROSS_DEVICE;
}

/* publish-tmp/<record>.<pid>/, root-private, on the store's device. */
static int frp_temp_dir(const struct zcl_frt_trust *t, int tmp, int store,
                        const struct frp_work *w, char name[96],
                        const char **why)
{
    *why = frp_same_device(tmp, store);
    if (*why) return -1;
    int k = snprintf(name, 96, "%s.%ld", w->record_hex, (long)getpid());
    if (k <= 0 || k >= 96 || mkdirat(tmp, name, 0700) != 0) {
        *why = ZCL_FRP_WHY_WRITE;
        return -1;
    }
    int dir = zcl_frt_open_dir(tmp, name, t->publisher_uid, true, why);
    if (dir < 0) {
        (void)unlinkat(tmp, name, AT_REMOVEDIR);
        *why = ZCL_FRP_WHY_WRITE;
    }
    return dir;
}

static const char *frp_place(const struct zcl_frt_trust *t, int state,
                             int store, int key_fd, const struct frp_work *w)
{
    const char *why = NULL;
    int tmp = zcl_frt_open_dir(state, "publish-tmp", t->publisher_uid, true,
                               &why);
    if (tmp < 0) return ZCL_FRP_WHY_STORE_UNSAFE;
    char name[96];
    int set[FRP_FILES];
    size_t n = frp_publish_set(w, set);
    int dir = frp_temp_dir(t, tmp, store, w, name, &why);
    if (!why && !frp_fill(dir, w, set, n)) why = ZCL_FRP_WHY_WRITE;
    if (!why && renameat2(tmp, name, key_fd, w->record_hex,
                          RENAME_NOREPLACE) != 0)
        why = errno == EEXIST ? ZCL_FRP_WHY_RECORD_EXISTS : ZCL_FRP_WHY_WRITE;
    if (why && dir >= 0) frp_discard(tmp, name, dir, set, n);
    if (!why && (fsync(key_fd) != 0 || fsync(store) != 0))
        why = ZCL_FRP_WHY_WRITE;
    if (dir >= 0) (void)close(dir);
    (void)close(tmp);
    return why;
}

/* A second signed observation of the opposite verdict for this exact key.
 * It is still published beside the first: the receiver's admit_set then
 * sees both and blocks with attest_eligible_conflict. */
static const char *frp_conflict(const struct frp_existing *seen,
                                const struct frp_work *w)
{
    if (!w->launch.failure && seen->signed_fail) return ZCL_FRP_WHY_CONFLICT_FAIL;
    if (w->launch.failure && seen->signed_pass) return ZCL_FRP_WHY_CONFLICT_PASS;
    return NULL;
}

/* Everything under LOCK_EX: the key directory, the scan of its history,
 * the no-clobber rule, the conflict audit note, and the publish. */
static const char *frp_locked(const struct zcl_frt_trust *t, int state,
                              const struct frp_work *w,
                              struct zcl_frp_result *out)
{
    const char *why = NULL;
    int store = zcl_frt_open_dir(state, "store", t->publisher_uid, false, &why);
    int key_fd = store >= 0 ? frp_key_dir(t, store, w->store_key, &why) : -1;
    struct frp_existing seen = {0};
    if (store < 0) why = ZCL_FRP_WHY_STORE_UNSAFE;
    if (key_fd >= 0) why = frp_scan(key_fd, w, t, &seen);
    if (key_fd >= 0 && !why && seen.record_exists)
        why = ZCL_FRP_WHY_RECORD_EXISTS;
    if (key_fd >= 0 && !why) out->conflict = frp_conflict(&seen, w);
    if (out->conflict) out->conflict_recorded = frp_record_conflict(t, state, w);
    if (key_fd >= 0 && !why) why = frp_place(t, state, store, key_fd, w);
    if (key_fd >= 0) (void)close(key_fd);
    if (store >= 0) (void)close(store);
    return why;
}

static const char *frp_identity(const struct zcl_frt_trust *t,
                                bool allow_same_uid)
{
    if ((uint32_t)geteuid() != t->publisher_uid) return ZCL_FRP_WHY_UID_MISMATCH;
    if (!allow_same_uid && t->publisher_uid == t->signer_uid)
        return ZCL_FRP_WHY_SAME_UID;
    return NULL;
}

void zcl_frp_publish(const struct zcl_frt_trust *trust, int staging,
                     const char *record_hex, int state,
                     unsigned lock_deadline_ms, bool allow_same_uid,
                     struct zcl_frp_result *out)
{
    if (!out) return;
    memset(out, 0, sizeof(*out));
    if (!trust || staging < 0 || state < 0 || !frp_hex64(record_hex)) {
        out->reason = ZCL_FRP_WHY_ARGUMENTS;
        return;
    }
    struct frp_work *w = zcl_calloc(1u, sizeof(*w), "frp work");
    if (!w) { out->reason = ZCL_FRP_WHY_NO_MEMORY; return; }
    memcpy(w->record_hex, record_hex, 65u);
    const char *why = frp_identity(trust, allow_same_uid);
    if (!why) why = frp_read_staging(trust, staging, w);
    if (!why) why = frp_verify(trust, state, w);
    int lock = why ? -1 : frp_lock_open(trust, state, &why);
    if (lock >= 0 && !frp_lock_take(lock, lock_deadline_ms))
        why = ZCL_FRP_WHY_LOCK_DEADLINE;
    if (lock >= 0 && !why) why = frp_locked(trust, state, w, out);
    if (lock >= 0) (void)close(lock);
    out->reason = why;
    out->failure = w->launch.failure;
    memcpy(out->store_key, w->store_key, sizeof(out->store_key));
    memcpy(out->record_sha3, w->record_hex, sizeof(out->record_sha3));
    frp_work_free(w);
    free(w);
}

void zcl_frp_publish_production(const char *record_hex,
                                struct zcl_frp_result *out)
{
    struct zcl_frt_trust trust;
    const char *why = NULL;
    if (!out) return;
    memset(out, 0, sizeof(*out));
    if (geteuid() != 0) { out->reason = ZCL_FRP_WHY_ROOT_REQUIRED; return; }
    if (!zcl_frt_load_production(&trust, &why)) { out->reason = why; return; }
    int root = zcl_frt_open_root(&why);
    int state = root >= 0 ? zcl_frt_open_path(root, ZCL_FRT_STATE_DIR, 0u,
                                              &why) : -1;
    int staging = state >= 0 ? zcl_frt_open_dir(state, ZCL_FRS_STAGING_DIR,
                                                trust.signer_uid, true, &why)
                             : -1;
    if (staging >= 0)
        zcl_frp_publish(&trust, staging, record_hex, state,
                        ZCL_FRP_LOCK_DEADLINE_MS, false, out);
    else
        out->reason = why;
    if (staging >= 0) (void)close(staging);
    if (state >= 0) (void)close(state);
    if (root >= 0) (void)close(root);
    zcl_frt_release(&trust);
}

#ifdef ZCL_TESTING
void zcl_frp_publish_fixture(const struct zcl_frp_fixture *fixture,
                             const char *record_hex,
                             struct zcl_frp_result *out)
{
    struct zcl_frt_trust trust;
    const char *why = NULL;
    if (!out) return;
    memset(out, 0, sizeof(*out));
    if (!fixture || !fixture->staging_dir || !fixture->state_dir) {
        out->reason = ZCL_FRP_WHY_ARGUMENTS;
        return;
    }
    if (!zcl_frt_load_fixture(&fixture->trust, &trust, &why)) {
        out->reason = why;
        return;
    }
    int staging = open(fixture->staging_dir, O_RDONLY | O_DIRECTORY |
                                                 O_NOFOLLOW | O_CLOEXEC);
    int state = open(fixture->state_dir, O_RDONLY | O_DIRECTORY | O_NOFOLLOW |
                                             O_CLOEXEC);
    why = staging < 0 ? ZCL_FRP_WHY_STAGING_UNSAFE
                      : frp_owned_dir(staging, trust.signer_uid);
    if (!why && state < 0) why = ZCL_FRP_WHY_STORE_UNSAFE;
    if (!why)
        zcl_frp_publish(&trust, staging, record_hex, state,
                        fixture->lock_deadline_ms, fixture->allow_same_uid,
                        out);
    else
        out->reason = why;
    if (staging >= 0) (void)close(staging);
    if (state >= 0) (void)close(state);
    zcl_frt_release(&trust);
}
#endif

#else
/* The verifier scope is one Linux x86-64 translation unit. */
typedef int zcl_fixed_result_publisher_linux_only;
#endif
