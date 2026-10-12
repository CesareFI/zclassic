/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: quarantine inbox store for fleet.steer.deliver; see
 * native_fleet_steer_inbox.h for the layout and the safety contract. */
#include "command/native_fleet_steer_inbox.h"

#if !defined(_WIN32)

#include "sha3/sha3.h"
#include "platform/file_sync.h"
#include "platform/private_directory.h"
#include "platform/state_root.h"
#include "platform/time_compat.h"
#include "services/disk_monitor.h"
#include "util/log_macros.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

#define FSI_LOG "fleet.steer.inbox"
#define FSI_NAMES_MAX 128u
#define FSI_MANIFEST_MAX 512u

#ifdef ZCL_TESTING
static enum fsi_fault g_fsi_fault;

void fsi_test_fault(enum fsi_fault point) { g_fsi_fault = point; }

/* True once for an armed fault point: the call returns as if the process
 * died there, leaving every durable object exactly as it stood. */
static bool fsi_crash(enum fsi_fault point)
{
    if (g_fsi_fault != point)
        return false;
    g_fsi_fault = FSI_FAULT_NONE;
    return true;
}
#else
#define fsi_crash(point) false
#endif

static const char *fsi_errno(int e)
{
    if (e == ELOOP || e == ENOTDIR || e == ENXIO || e == EISDIR ||
        e == EMLINK)
        return "UNSAFE_PATH";
    return e == ENOENT ? "NOT_FOUND" : "STORE";
}

static void fsi_close_fd(int *fd)
{
    if (*fd >= 0)
        (void)close(*fd);
    *fd = -1;
}

static bool fsi_sync(int fd)
{
    int rc;
    do {
        rc = platform_authority_sync(fd);
    } while (rc != 0 && errno == EINTR);
    return rc == 0;
}

/* ── root ───────────────────────────────────────────────────────────────── */

bool fsi_root_path(char *out, size_t cap)
{
    char base[4096];
    int n;
    if (!platform_state_root_existing(base, sizeof(base)))
        return false;
    n = snprintf(out, cap, "%s/steer/inbox", base);
    return n > 0 && (size_t)n < cap;
}

static const char *fsi_root_create(char *path, size_t cap)
{
    char base[4096], steer[4200];
    int n;
    if (!platform_state_root(base, sizeof(base)))
        return "STORE";
    n = snprintf(steer, sizeof(steer), "%s/steer", base);
    if (n <= 0 || (size_t)n >= sizeof(steer) ||
        !platform_private_directory_ensure(steer))
        return "STORE";
    n = snprintf(path, cap, "%s/inbox", steer);
    if (n <= 0 || (size_t)n >= cap || !platform_private_directory_ensure(path))
        return "STORE";
    return NULL;
}

const char *fsi_root_open(bool create, int *root)
{
    char path[4400];
    uintptr_t h = 0;
    const char *err = NULL;
    if (create)
        err = fsi_root_create(path, sizeof(path));
    else if (!fsi_root_path(path, sizeof(path)))
        err = "NOT_FOUND";
    if (err)
        return err;
    if (!platform_private_directory_open_validated(path, &h))
        return create ? "STORE" : "NOT_FOUND";
    if (create) {
        int64_t free_bytes = disk_monitor_free_bytes(path);
        if (free_bytes >= 0 && free_bytes < DISK_MONITOR_DEFAULT_REFUSE_BYTES) {
            platform_private_directory_close(h);
            return "STORE";
        }
    }
    *root = (int)h;
    return NULL;
}

void fsi_root_close(int root)
{
    platform_private_directory_close((uintptr_t)root);
}

/* ── descriptor-relative objects ─────────────────────────────────────────── */

static const char *fsi_open_dir(int parent, const char *name, bool create,
                                int *out)
{
    struct stat st;
    int fd;
    if (create && mkdirat(parent, name, 0700) != 0 && errno != EEXIST)
        return fsi_errno(errno);
    fd = openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0)
        return fsi_errno(errno);
    if (fstat(fd, &st) != 0 || !S_ISDIR(st.st_mode) ||
        st.st_uid != geteuid() || (st.st_mode & 07077) != 0) {
        (void)close(fd);
        return "UNSAFE_PATH";
    }
    *out = fd;
    return NULL;
}

/* Regular, owned, private, non-executable, single-link: anything else is
 * refused UNSAFE_PATH. O_NONBLOCK keeps a planted FIFO from blocking. */
static const char *fsi_open_file(int dir, const char *name, int flags,
                                 int *out)
{
    struct stat st;
    int fd = openat(dir, name,
                    flags | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK, 0600);
    if (fd < 0)
        return fsi_errno(errno);
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) ||
        st.st_uid != geteuid() || (st.st_mode & 07177) != 0 ||
        st.st_nlink != 1) {
        (void)close(fd);
        return "UNSAFE_PATH";
    }
    *out = fd;
    return NULL;
}

/* Nonblocking exclusive lock on a lock file: BUSY, never a wait. */
static const char *fsi_lock(int dir, const char *name, int *fd)
{
    const char *err = fsi_open_file(dir, name, O_RDWR | O_CREAT, fd);
    if (err)
        return err;
    if (flock(*fd, LOCK_EX | LOCK_NB) != 0) {
        err = errno == EWOULDBLOCK ? "BUSY" : "STORE";
        fsi_close_fd(fd);
    }
    return err;
}

static bool fsi_pwrite_all(int fd, const unsigned char *p, size_t n,
                           long long off)
{
    while (n > 0) {
        ssize_t w = pwrite(fd, p, n, (off_t)off);
        if (w < 0 && errno == EINTR)
            continue;
        if (w <= 0)
            return false;
        p += (size_t)w;
        n -= (size_t)w;
        off += w;
    }
    return true;
}

static bool fsi_pread_all(int fd, unsigned char *p, size_t n, long long off)
{
    while (n > 0) {
        ssize_t r = pread(fd, p, n, (off_t)off);
        if (r < 0 && errno == EINTR)
            continue;
        if (r <= 0)
            return false;
        p += (size_t)r;
        n -= (size_t)r;
        off += r;
    }
    return true;
}

/* ── manifest: the durable cursor ────────────────────────────────────────── */

static bool fsi_lower_hex(const char *s, size_t n)
{
    size_t i;
    if (strlen(s) != n)
        return false;
    for (i = 0; i < n; i++)
        if (!((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f')))
            return false;
    return true;
}

/* Take "key=value\n" at *p; value copied into out (cap bytes). */
static bool fsi_line(const char **p, const char *key, char *out, size_t cap)
{
    size_t kn = strlen(key), n = 0;
    const char *v;
    if (strncmp(*p, key, kn) != 0 || (*p)[kn] != '=')
        return false;
    v = *p + kn + 1;
    while (v[n] != '\n' && v[n] != '\0')
        n++;
    if (v[n] != '\n' || n + 1 > cap)
        return false;
    memcpy(out, v, n);
    out[n] = '\0';
    *p = v + n + 1;
    return true;
}

static bool fsi_num(const char **p, const char *key, long long *out)
{
    char t[24], *end = NULL;
    if (!fsi_line(p, key, t, sizeof(t)) || t[0] == '\0')
        return false;
    *out = strtoll(t, &end, 10);
    return *end == '\0' && *out >= 0;
}

static bool fsi_meta_valid(const struct fsi_meta *m)
{
    bool state = strcmp(m->state, "receiving") == 0 ||
                 strcmp(m->state, "quarantined") == 0 ||
                 strcmp(m->state, "failed") == 0;
    return state && m->ref[0] && m->name[0] &&
           fsi_lower_hex(m->digest, FSI_SHA_HEX) && m->size >= 1 &&
           m->size <= (long long)FSI_SIZE_MAX && m->offset <= m->size &&
           (m->offset % (long long)FSI_CHUNK == 0 || m->offset == m->size);
}

static bool fsi_meta_parse(const char *text, struct fsi_meta *m)
{
    const char *p = text;
    char v[4];
    memset(m, 0, sizeof(*m));
    if (!fsi_line(&p, "v", v, sizeof(v)) || strcmp(v, "1") != 0)
        return false;
    if (!fsi_line(&p, "ref", m->ref, sizeof(m->ref)) ||
        !fsi_line(&p, "name", m->name, sizeof(m->name)) ||
        !fsi_num(&p, "size", &m->size) ||
        !fsi_line(&p, "sha3_512", m->digest, sizeof(m->digest)) ||
        !fsi_num(&p, "offset", &m->offset) ||
        !fsi_line(&p, "state", m->state, sizeof(m->state)) ||
        !fsi_num(&p, "created", &m->created) ||
        !fsi_num(&p, "updated", &m->updated))
        return false;
    return *p == '\0' && fsi_meta_valid(m);
}

static const char *fsi_manifest_read(int dir, struct fsi_meta *m)
{
    char text[FSI_MANIFEST_MAX + 1];
    ssize_t n;
    int fd = -1;
    const char *err = fsi_open_file(dir, "manifest", O_RDONLY, &fd);
    if (err)
        return err;
    n = pread(fd, text, FSI_MANIFEST_MAX, 0);
    fsi_close_fd(&fd);
    if (n <= 0 || n >= (ssize_t)FSI_MANIFEST_MAX)
        return "STORE";
    text[n] = '\0';
    return fsi_meta_parse(text, m) ? NULL : "STORE";
}

/* Write the staged manifest, replace atomically, then sync the directory.
 * The reply is only ever sent after this returns NULL. */
static const char *fsi_manifest_commit(struct fsi_upload *u)
{
    const struct fsi_meta *m = &u->meta;
    char text[FSI_MANIFEST_MAX];
    const char *err;
    int fd = -1, n;
    n = snprintf(text, sizeof(text),
                 "v=1\nref=%s\nname=%s\nsize=%lld\nsha3_512=%s\noffset=%lld\n"
                 "state=%s\ncreated=%lld\nupdated=%lld\n",
                 m->ref, m->name, m->size, m->digest, m->offset, m->state,
                 m->created, m->updated);
    if (n <= 0 || (size_t)n >= sizeof(text))
        return "STORE";
    if (unlinkat(u->dir_fd, "manifest.tmp", 0) != 0 && errno != ENOENT)
        return "STORE";
    err = fsi_open_file(u->dir_fd, "manifest.tmp", O_WRONLY | O_CREAT | O_EXCL,
                        &fd);
    if (err)
        return err;
    if (fsi_crash(FSI_FAULT_SHORT_MANIFEST))
        n /= 2;
    if (!fsi_pwrite_all(fd, (const unsigned char *)text, (size_t)n, 0) ||
        !fsi_sync(fd) || (size_t)n < strlen(text)) {
        fsi_close_fd(&fd);
        return "STORE";
    }
    fsi_close_fd(&fd);
    if (fsi_crash(FSI_FAULT_RENAME_FAIL) ||
        renameat(u->dir_fd, "manifest.tmp", u->dir_fd, "manifest") != 0)
        return "STORE";
    if (fsi_crash(FSI_FAULT_AFTER_MANIFEST_RENAME))
        return "STORE";
    return fsi_sync(u->dir_fd) ? NULL : "STORE";
}

/* ── walking, sweeping and quota ─────────────────────────────────────────── */

#define FSI_WALK_MAX 4096u
#define FSI_BINDINGS_MAX 128u

typedef const char *(*fsi_walk_fn)(const char *name, bool well_formed,
                                   void *ctx);

/* Visit the entries of dir that are not bookkeeping, at most FSI_WALK_MAX.
 * well_formed says the name is lowercase hex of want_len. The visitor's first
 * non-NULL return stops the walk and is returned. */
static const char *fsi_walk(int dir, size_t want_len, fsi_walk_fn fn,
                            void *ctx)
{
    struct dirent *e;
    const char *err = NULL;
    size_t seen = 0;
    int dup = fcntl(dir, F_DUPFD_CLOEXEC, 3);
    DIR *d = NULL;
    if (dup >= 0 && lseek(dup, 0, SEEK_SET) >= 0)
        d = fdopendir(dup);
    if (!d) {
        if (dup >= 0)
            (void)close(dup);
        return "STORE";
    }
    while (!err && seen < FSI_WALK_MAX && (e = readdir(d)) != NULL) {
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0 ||
            strcmp(e->d_name, ".lock") == 0 || strcmp(e->d_name, "rate") == 0)
            continue;
        seen++;
        err = fn(e->d_name, fsi_lower_hex(e->d_name, want_len), ctx);
    }
    (void)closedir(d);
    return err;
}

static const char *fsi_reclaim(int bind_fd, const char *id)
{
    static const char *const files[] = {"payload", "manifest", "manifest.tmp",
                                        "lock"};
    int dir = -1;
    size_t i;
    const char *err = fsi_open_dir(bind_fd, id, false, &dir);
    if (err)
        return err;
    for (i = 0; i < sizeof(files) / sizeof(files[0]); i++) {
        if (unlinkat(dir, files[i], 0) != 0 && errno != ENOENT) {
            fsi_close_fd(&dir);
            return "STORE";
        }
    }
    fsi_close_fd(&dir);
    return unlinkat(bind_fd, id, AT_REMOVEDIR) == 0 ? NULL : "STORE";
}

/* Reclaim an upload nobody is writing: the upload lock is taken first, and a
 * held lock leaves it alone (BUSY). */
static const char *fsi_reclaim_free(int bind_fd, const char *id)
{
    int dir = -1, lk = -1;
    const char *err = fsi_open_dir(bind_fd, id, false, &dir);
    if (!err)
        err = fsi_lock(dir, "lock", &lk);
    fsi_close_fd(&dir);
    if (!err)
        err = fsi_reclaim(bind_fd, id);
    fsi_close_fd(&lk);
    return err;
}

/* Partials expire after a day, failed uploads after an hour; a verified
 * (quarantined) upload stays until the owner drops it. A clock that moved
 * backwards never expires anything. */
static bool fsi_expired(const struct fsi_meta *m, long long now)
{
    long long ttl = 0;
    if (strcmp(m->state, "receiving") == 0)
        ttl = FSI_PARTIAL_TTL_S;
    else if (strcmp(m->state, "failed") == 0)
        ttl = FSI_FAILED_TTL_S;
    return ttl > 0 && now > m->updated && now - m->updated > ttl;
}

/* Per-grant request and byte ledger, one small file per binding so a restart
 * recomputes nothing: fixed minute and hour windows that only move forward.
 * Every call after authorization is charged, refused or not. */
struct fsi_rate {
    long long minute, count, hour, bytes;
};

/* False for an empty or garbled file, which then reads as an empty window. */
static bool fsi_rate_load(int fd, struct fsi_rate *r)
{
    char text[160];
    ssize_t n = pread(fd, text, sizeof(text) - 1, 0);
    memset(r, 0, sizeof(*r));
    if (n <= 0)
        return false;
    text[n] = '\0';
    if (sscanf(text, "m=%lld n=%lld h=%lld b=%lld", &r->minute, &r->count,
               &r->hour, &r->bytes) == 4 && r->minute >= 0 && r->count >= 0 &&
        r->hour >= 0 && r->bytes >= 0)
        return true;
    memset(r, 0, sizeof(*r));
    return false;
}

static const char *fsi_rate_take(int bind_fd, long long now, size_t bytes)
{
    struct fsi_rate r;
    char text[160];
    const char *err;
    int fd = -1, n;
    err = fsi_open_file(bind_fd, "rate", O_RDWR | O_CREAT, &fd);
    if (err)
        return err;
    if (flock(fd, LOCK_EX) != 0) {
        fsi_close_fd(&fd);
        return "STORE";
    }
    (void)fsi_rate_load(fd, &r);
    if (now / 60 > r.minute)
        r.minute = now / 60, r.count = 0;
    if (now / 3600 > r.hour)
        r.hour = now / 3600, r.bytes = 0;
    err = r.count >= (long long)FSI_REQ_PER_MIN ? "RATE"
          : r.bytes + (long long)bytes > FSI_BYTES_PER_HOUR ? "BYTE_RATE"
                                                            : NULL;
    r.count++;
    r.bytes += err ? 0 : (long long)bytes;
    n = snprintf(text, sizeof(text), "m=%lld n=%lld h=%lld b=%lld\n", r.minute,
                 r.count, r.hour, r.bytes);
    if (n <= 0 || !fsi_pwrite_all(fd, (const unsigned char *)text, (size_t)n, 0) ||
        ftruncate(fd, n) != 0)
        err = err ? err : "STORE";
    fsi_close_fd(&fd);
    return err;
}

static const char *fsi_count_cb(const char *name, bool well, void *ctx)
{
    (void)name;
    (void)well;
    ++*(unsigned *)ctx;
    return NULL;
}

/* Remove an empty binding directory with its ledger. Unless forced, only
 * when the ledger is from an earlier hour (nothing left to remember) and no
 * request holds it. A directory that still holds uploads keeps its ledger
 * and is never removed, forced or not. */
static void fsi_prune(int root, int bind_fd, const char *name, long long now,
                      bool force)
{
    struct fsi_rate r;
    unsigned held = 0;
    int fd = -1;
    const char *err = fsi_open_file(bind_fd, "rate", O_RDWR, &fd);
    bool stale = err ? strcmp(err, "NOT_FOUND") == 0 : false;
    if (force && (fsi_walk(bind_fd, FSI_ID_HEX, fsi_count_cb, &held) != NULL ||
                  held > 0))
        goto out;
    if (!err && flock(fd, LOCK_EX | LOCK_NB) == 0)
        stale = !fsi_rate_load(fd, &r) || r.hour < now / 3600;
    if (!force && !stale)
        goto out;
    if (unlinkat(bind_fd, "rate", 0) == 0 || errno == ENOENT)
        (void)unlinkat(root, name, AT_REMOVEDIR);
out:
    fsi_close_fd(&fd);
}

struct fsi_tally {
    unsigned all, mine, recv, recv_all, damaged, live;
    long long b_all, b_mine, now;
    int root, bind_fd;
    const char *binding;
    bool mine_now;
};

/* A damaged upload keeps its slot and is charged the largest size. */
static void fsi_count(struct fsi_tally *t, const struct fsi_meta *m)
{
    long long size = m ? m->size : (long long)FSI_SIZE_MAX;
    unsigned recv = m && strcmp(m->state, "receiving") == 0;
    t->all++;
    t->live++;
    t->b_all += size;
    t->recv_all += recv;
    t->damaged += m == NULL;
    if (t->mine_now) {
        t->mine++;
        t->b_mine += size;
        t->recv += recv;
    }
}

/* Count one retained upload, reclaiming an expired one or a creation that
 * never committed. A bad entry is counted and skipped, never fatal. */
static const char *fsi_tally_id(const char *name, bool well, void *ctx)
{
    struct fsi_tally *t = ctx;
    struct fsi_meta m;
    int dir = -1;
    const char *err = well ? fsi_open_dir(t->bind_fd, name, false, &dir)
                           : "STORE";
    if (!err) {
        err = fsi_manifest_read(dir, &m);
        fsi_close_fd(&dir);
    }
    if (well && err && strcmp(err, "NOT_FOUND") == 0) {
        if (fsi_reclaim_free(t->bind_fd, name) != NULL)
            fsi_count(t, NULL);
        return NULL;
    }
    if (err) {
        fsi_count(t, NULL);
        return NULL;
    }
    if (fsi_expired(&m, t->now) &&
        fsi_reclaim_free(t->bind_fd, name) == NULL)
        return NULL;
    fsi_count(t, &m);
    return NULL;
}

static const char *fsi_tally_binding(const char *name, bool well, void *ctx)
{
    struct fsi_tally *t = ctx;
    if (!well || fsi_open_dir(t->root, name, false, &t->bind_fd) != NULL) {
        fsi_count(t, NULL);
        return NULL;
    }
    t->mine_now = strcmp(name, t->binding) == 0;
    t->live = 0;
    (void)fsi_walk(t->bind_fd, FSI_ID_HEX, fsi_tally_id, t);
    if (t->live == 0)
        fsi_prune(t->root, t->bind_fd, name, t->now, false);
    fsi_close_fd(&t->bind_fd);
    return NULL;
}

static const char *fsi_tally(int root, const char *binding,
                             struct fsi_tally *t, long long now)
{
    memset(t, 0, sizeof(*t));
    t->root = root;
    t->bind_fd = -1;
    t->binding = binding;
    t->now = now;
    return fsi_walk(root, 32, fsi_tally_binding, t);
}

static const char *fsi_quota(const struct fsi_tally *t, long long size)
{
    if (t->recv_all >= FSI_OUTSTANDING)
        return "OUTSTANDING";
    if (t->all >= FSI_TOTAL || t->mine >= FSI_PER_GRANT || t->recv >= 1u ||
        t->b_mine + size > (long long)FSI_BYTES_GRANT ||
        t->b_all + size > (long long)FSI_BYTES_TOTAL)
        return "QUOTA";
    return NULL;
}

/* ── open, create, recover ───────────────────────────────────────────────── */

static const char *fsi_create(struct fsi_upload *u, int root, long long now)
{
    struct fsi_tally t = {0};
    const char *err = u->recheck ? u->recheck(u->recheck_ctx) : NULL;
    if (!err)
        err = fsi_tally(root, u->binding, &t, now);
    if (!err)
        err = fsi_quota(&t, u->meta.size);
    if (!err)
        err = fsi_open_dir(u->bind_fd, u->id, true, &u->dir_fd);
    if (!err)
        err = fsi_lock(u->dir_fd, "lock", &u->lock_fd);
    if (!err)
        err = fsi_open_file(u->dir_fd, "payload",
                            O_RDWR | O_CREAT | O_EXCL, &u->payload_fd);
    if (err)
        return err;
    snprintf(u->meta.state, sizeof(u->meta.state), "receiving");
    u->meta.offset = 0;
    u->meta.created = u->meta.updated = now;
    err = fsi_manifest_commit(u);
    if (!err && !fsi_sync(u->bind_fd))
        err = "STORE";
    return err;
}

/* Only this owned partial's uncommitted tail may be cut; a payload shorter
 * than the cursor is corruption and refuses. */
static const char *fsi_recover(struct fsi_upload *u)
{
    struct stat st;
    if (fstat(u->payload_fd, &st) != 0)
        return "STORE";
    if (st.st_size < (off_t)u->meta.offset)
        return "STORE";
    if (st.st_size > (off_t)u->meta.offset) {
        if (ftruncate(u->payload_fd, (off_t)u->meta.offset) != 0 ||
            !fsi_sync(u->payload_fd))
            return "STORE";
    }
    return NULL;
}

static const char *fsi_adopt(struct fsi_upload *u, long long now)
{
    struct fsi_meta m;
    const char *err = fsi_lock(u->dir_fd, "lock", &u->lock_fd);
    if (!err)
        err = fsi_manifest_read(u->dir_fd, &m);
    if (err)
        return strcmp(err, "NOT_FOUND") == 0 ? "NOMANIFEST" : err;
    if (strcmp(m.ref, u->meta.ref) != 0 || strcmp(m.name, u->meta.name) != 0 ||
        m.size != u->meta.size || strcmp(m.digest, u->meta.digest) != 0)
        return "CONFLICT";
    u->meta = m;
    if (fsi_expired(&m, now)) {
        err = fsi_reclaim(u->bind_fd, u->id);
        return err ? err : "EXPIRED_UPLOAD";
    }
    err = fsi_open_file(u->dir_fd, "payload", O_RDWR, &u->payload_fd);
    return err ? err : fsi_recover(u);
}

/* A directory with no manifest is a creation that never committed. */
static const char *fsi_discard_stub(struct fsi_upload *u)
{
    fsi_close_fd(&u->lock_fd);
    fsi_close_fd(&u->payload_fd);
    fsi_close_fd(&u->dir_fd);
    return fsi_reclaim(u->bind_fd, u->id);
}

static const char *fsi_attach(struct fsi_upload *u, int root, bool first,
                              long long now)
{
    const char *err = fsi_open_dir(u->bind_fd, u->id, false, &u->dir_fd);
    if (!err) {
        err = fsi_adopt(u, now);
        if (!err || strcmp(err, "NOMANIFEST") != 0)
            return err;
        err = fsi_discard_stub(u);
        if (err)
            return err;
    } else if (strcmp(err, "NOT_FOUND") != 0) {
        return err;
    }
    return first ? fsi_create(u, root, now) : "NOT_FOUND";
}

/* A call that finds no binding has no ledger file to charge, so refusals on
 * that path are bounded per process instead: after FSI_REFUSALS_PER_MIN
 * BINDINGS or BUSY refusals in one minute, further creation attempts are
 * refused RATE before any lock or walk. A new minute opens a new window. */
#define FSI_REFUSALS_PER_MIN 16u
static _Atomic long long g_fsi_refused_minute;
static _Atomic unsigned g_fsi_refused;

static bool fsi_gate_open(long long now)
{
    long long minute = atomic_load(&g_fsi_refused_minute);
    if (now / 60 != minute) {
        atomic_store(&g_fsi_refused, 0u);
        atomic_store(&g_fsi_refused_minute, now / 60);
    }
    return atomic_load(&g_fsi_refused) < FSI_REFUSALS_PER_MIN;
}

static void fsi_gate_note(const char *err)
{
    if (err && (strcmp(err, "BINDINGS") == 0 || strcmp(err, "BUSY") == 0))
        atomic_fetch_add(&g_fsi_refused, 1u);
}

/* Create the grant's binding below FSI_BINDINGS_MAX after a sweep of empty
 * stale ones. The grant is re-checked last, so a revoked grant leaves no
 * directory behind. */
static const char *fsi_binding_create(struct fsi_upload *u, int root,
                                      long long now)
{
    struct fsi_tally t;
    unsigned n = 0;
    const char *err = fsi_gate_open(now) ? NULL : "RATE";
    if (!err)
        err = fsi_lock(root, ".lock", &u->global_fd);
    if (!err)
        err = fsi_tally(root, u->binding, &t, now);
    if (!err)
        err = fsi_walk(root, 32, fsi_count_cb, &n);
    if (!err && n >= FSI_BINDINGS_MAX)
        err = "BINDINGS";
    if (!err && u->recheck)
        err = u->recheck(u->recheck_ctx);
    if (!err)
        err = fsi_open_dir(root, u->binding, true, &u->bind_fd);
    fsi_close_fd(&u->global_fd);
    fsi_gate_note(err);
    return err;
}

/* Open the grant's binding directory; existing bindings are never refused
 * here. */
static const char *fsi_binding_open(struct fsi_upload *u, int root, bool first,
                                    long long now)
{
    const char *err = fsi_open_dir(root, u->binding, false, &u->bind_fd);
    if (!err || strcmp(err, "NOT_FOUND") != 0 || !first)
        return err;
    return fsi_binding_create(u, root, now);
}

/* Open the binding and charge the call. A binding pruned between the two
 * steps is opened once more; if it vanishes again the refusal is BUSY, which
 * the caller may retry. */
static const char *fsi_open_charged(struct fsi_upload *u, int root, bool first,
                                    long long now)
{
    const char *err = NULL;
    int attempt;
    for (attempt = 0; attempt < 2; attempt++) {
        err = fsi_binding_open(u, root, first, now);
        if (err)
            return err;
        if (fsi_crash(FSI_FAULT_BINDING_VANISH))
            (void)unlinkat(root, u->binding, AT_REMOVEDIR);
        err = fsi_rate_take(u->bind_fd, now, u->charge);
        if (!err || strcmp(err, "NOT_FOUND") != 0)
            return err;
        fsi_close_fd(&u->bind_fd);
    }
    return "BUSY";
}

void fsi_end(struct fsi_upload *u)
{
    fsi_close_fd(&u->payload_fd);
    fsi_close_fd(&u->lock_fd);
    fsi_close_fd(&u->dir_fd);
    fsi_close_fd(&u->bind_fd);
    fsi_close_fd(&u->global_fd);
}

/* Order: binding, per-grant charge (before the global lock, so a call that
 * loses it is still counted), global lock, upload. */
const char *fsi_begin(struct fsi_upload *u, int root, const char *binding,
                      const char *id, const struct fsi_meta *want, bool first,
                      size_t charge)
{
    long long now = (long long)platform_time_wall_time_t();
    const char *err;
    u->bind_fd = u->dir_fd = u->lock_fd = u->payload_fd = u->global_fd = -1;
    snprintf(u->binding, sizeof(u->binding), "%s", binding);
    snprintf(u->id, sizeof(u->id), "%s", id);
    u->meta = *want;
    u->charge = charge;
    err = fsi_open_charged(u, root, first, now);
    if (!err)
        err = fsi_lock(root, ".lock", &u->global_fd);
    if (!err)
        err = fsi_attach(u, root, first, now);
    fsi_close_fd(&u->global_fd);
    if (err)
        fsi_end(u);
    return err;
}

const char *fsi_drop(int root, const char *binding, const char *id)
{
    int global = -1, bfd = -1;
    const char *err = fsi_lock(root, ".lock", &global);
    if (!err)
        err = fsi_open_dir(root, binding, false, &bfd);
    if (!err)
        err = fsi_reclaim_free(bfd, id);
    if (!err)
        fsi_prune(root, bfd, binding, (long long)platform_time_wall_time_t(),
                  true);
    fsi_close_fd(&bfd);
    fsi_close_fd(&global);
    return err;
}

/* ── chunks and completion ───────────────────────────────────────────────── */

static const char *fsi_sha(int fd, long long size, char *hex)
{
    struct sha3_512_ctx ctx;
    unsigned char buf[FSI_CHUNK], sum[SHA3_512_OUTPUT_SIZE];
    long long off = 0;
    size_t i;
    sha3_512_init(&ctx);
    while (off < size) {
        size_t n = size - off > (long long)sizeof(buf) ? sizeof(buf)
                                                       : (size_t)(size - off);
        if (!fsi_pread_all(fd, buf, n, off))
            return "STORE";
        sha3_512_write(&ctx, buf, n);
        off += (long long)n;
    }
    sha3_512_finalize(&ctx, sum);
    for (i = 0; i < sizeof(sum); i++)
        (void)snprintf(hex + i * 2u, 3u, "%02x", sum[i]);
    return NULL;
}

const char *fsi_finish(struct fsi_upload *u)
{
    char got[FSI_SHA_HEX + 1];
    struct stat st;
    bool match;
    const char *err;
    if (strcmp(u->meta.state, "receiving") != 0)
        return NULL;
    if (u->recheck && (err = u->recheck(u->recheck_ctx)) != NULL)
        return err;
    if (fstat(u->payload_fd, &st) != 0 || st.st_size != (off_t)u->meta.size)
        return "STORE";
    err = fsi_sha(u->payload_fd, u->meta.size, got);
    if (err)
        return err;
    if (fsi_crash(FSI_FAULT_BEFORE_FINAL_COMMIT))
        return "STORE";
    match = strcmp(got, u->meta.digest) == 0;
    snprintf(u->meta.state, sizeof(u->meta.state),
             match ? "quarantined" : "failed");
    u->meta.updated = (long long)platform_time_wall_time_t();
    err = fsi_manifest_commit(u);
    if (err)
        return err;
    return match ? NULL : "HASH_MISMATCH";
}

/* A byte-identical retry of an accepted chunk. */
static const char *fsi_retry(struct fsi_upload *u, long long offset,
                             const unsigned char *data, size_t n, bool *dup)
{
    unsigned char have[FSI_CHUNK];
    if (offset + (long long)n > u->meta.offset || n > sizeof(have) ||
        !fsi_pread_all(u->payload_fd, have, n, offset) ||
        memcmp(have, data, n) != 0)
        return "CONFLICT";
    *dup = true;
    return NULL;
}

/* The cursor advances in memory only for the commit; a failed commit puts
 * the durable cursor back so the refusal reports where the upload stands. */
static const char *fsi_advance(struct fsi_upload *u, long long offset,
                               size_t n)
{
    long long was = u->meta.offset, stamp = u->meta.updated;
    const char *err;
    u->meta.offset = offset + (long long)n;
    u->meta.updated = (long long)platform_time_wall_time_t();
    err = fsi_manifest_commit(u);
    if (err) {
        u->meta.offset = was;
        u->meta.updated = stamp;
    }
    return err;
}

static const char *fsi_store_chunk(struct fsi_upload *u, long long offset,
                                   const unsigned char *data, size_t n)
{
    if (fsi_crash(FSI_FAULT_SHORT_PAYLOAD)) {
        (void)fsi_pwrite_all(u->payload_fd, data, n / 2, offset);
        return "STORE";
    }
    if (!fsi_pwrite_all(u->payload_fd, data, n, offset) ||
        !fsi_sync(u->payload_fd))
        return "STORE";
    if (fsi_crash(FSI_FAULT_AFTER_PAYLOAD))
        return "STORE";
    return fsi_advance(u, offset, n);
}

const char *fsi_append(struct fsi_upload *u, long long offset,
                       const unsigned char *data, size_t n, bool *dup)
{
    const char *err = NULL;
    *dup = false;
    if (strcmp(u->meta.state, "failed") == 0)
        return "HASH_MISMATCH";
    if (u->recheck && (err = u->recheck(u->recheck_ctx)) != NULL)
        return err;
    if (offset < u->meta.offset)
        err = fsi_retry(u, offset, data, n, dup);
    else if (strcmp(u->meta.state, "receiving") != 0)
        err = "CONFLICT";
    else if (offset > u->meta.offset)
        err = "OFFSET";
    else
        err = fsi_store_chunk(u, offset, data, n);
    if (err)
        return err;
    return u->meta.offset == u->meta.size ? fsi_finish(u) : NULL;
}

/* ── read-only listing ───────────────────────────────────────────────────── */

struct fsi_list {
    fsi_row_fn fn;
    void *ctx;
    unsigned *skipped;
    int root, bind_fd;
    char binding[33];
};

/* A manifest that cannot be read is reported as state "damaged" so the owner
 * can drop it; a name that is not an upload id is only counted. */
static const char *fsi_list_id(const char *name, bool well, void *ctx)
{
    struct fsi_list *l = ctx;
    struct fsi_row row;
    int dir = -1;
    memset(&row, 0, sizeof(row));
    if (!well) {
        ++*l->skipped;
        return NULL;
    }
    snprintf(row.binding, sizeof(row.binding), "%s", l->binding);
    snprintf(row.id, sizeof(row.id), "%s", name);
    if (fsi_open_dir(l->bind_fd, name, false, &dir) != NULL ||
        fsi_manifest_read(dir, &row.meta) != NULL) {
        memset(&row.meta, 0, sizeof(row.meta));
        snprintf(row.meta.state, sizeof(row.meta.state), "damaged");
    }
    fsi_close_fd(&dir);
    return l->fn(&row, l->ctx) ? NULL : "STOP";
}

static const char *fsi_list_binding(const char *name, bool well, void *ctx)
{
    struct fsi_list *l = ctx;
    const char *err;
    if (!well || fsi_open_dir(l->root, name, false, &l->bind_fd) != NULL) {
        ++*l->skipped;
        return NULL;
    }
    snprintf(l->binding, sizeof(l->binding), "%s", name);
    err = fsi_walk(l->bind_fd, FSI_ID_HEX, fsi_list_id, l);
    fsi_close_fd(&l->bind_fd);
    return err;
}

const char *fsi_each(int root, fsi_row_fn fn, void *ctx, unsigned *skipped)
{
    struct fsi_list l = {fn, ctx, skipped, root, -1, ""};
    const char *err;
    *skipped = 0;
    err = fsi_walk(root, 32, fsi_list_binding, &l);
    return err && strcmp(err, "STOP") == 0 ? NULL : err;
}

#endif /* !_WIN32 */
