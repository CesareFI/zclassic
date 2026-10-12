/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: granted-file system calls for rvuser. Mechanism only: a bounded
 * guest fd table (fds 3..18) with per-fd offset and mode, bounded guest path
 * copy, FreeBSD flag decoding. Which paths exist or are allowed is decided by
 * the caller's struct rvuser_io callbacks; a null open means EACCES.
 * Constants: sys/sys/fcntl.h (O_*, AT_FDCWD), sys/sys/unistd.h (SEEK_*),
 * sys/sys/errno.h, sys/sys/stat.h (struct stat, S_IF*) and sys/sys/_types.h.
 * Syscall numbers (sys/kern/syscalls.master) are bound in rvuser_sys.c. */
#include "rvuser_internal.h"
#include "base/serialize_le.h"
#include <string.h>

enum {
    E_IO = 5, E_BADF = 9, E_ACCES = 13, E_FAULT = 14, E_INVAL = 22, E_MFILE = 24, E_SPIPE = 29,
    E_NAMETOOLONG = 63, E_NOSYS = 78
};
/* sys/sys/fcntl.h */
enum {
    O_ACCMODE = 3, O_WRONLY = 1, O_APPEND = 0x8, O_CREAT = 0x200, O_TRUNC = 0x400,
    O_EXCL = 0x800, O_CLOEXEC = 0x100000
};
enum { SEEK_SET_ = 0, SEEK_CUR_ = 1, SEEK_END_ = 2 }; /* sys/sys/unistd.h */
#define AT_FDCWD_ (-100)                                 /* sys/sys/fcntl.h */

/* struct stat on riscv64 (LP64, no __STAT_TIME_T_EXT), sys/sys/stat.h: st_dev 0, st_ino 8,
 * st_nlink 16, st_mode 24 (u16), st_bsdflags 26, st_uid 28, st_gid 32, st_rdev 40, four
 * timespecs 48..111, st_size 112, st_blocks 120, st_blksize 128 (u32), st_flags 132, st_gen
 * 136, st_filerev 144, st_spare[9] to 224. */
enum {
    ST_NLINK = 16, ST_MODE = 24, ST_SIZE = 112, ST_BLOCKS = 120, ST_BLKSIZE = 128, ST_BYTES = 224,
    S_IFREG_0600 = 0100600, S_IFCHR_0620 = 0020620, ST_BLOCK_UNIT = 512, ST_IO_BLOCK = 4096
};

/* A callback errno must be a small positive FreeBSD errno; anything else is EIO. */
static int ru_errno(int64_t e)
{
    return (e > 0 && e < 256) ? (int)e : E_IO;
}

static int ru_neg_errno(int64_t r)
{
    return (r < 0 && r > -256) ? (int)-r : E_IO;
}

static struct ru_fd *ru_fd_get(struct ru_proc *p, uint64_t fd)
{
    if (fd < RU_FD_FIRST || fd - RU_FD_FIRST >= RU_FD_COUNT) return NULL;
    struct ru_fd *f = &p->fds[fd - RU_FD_FIRST];
    return f->used ? f : NULL;
}

static int ru_size(const struct ru_proc *p, const struct ru_fd *f, uint64_t *size)
{
    if (!p->io->fsize) return E_INVAL;
    int64_t s = p->io->fsize(p->io->ctx, f->handle);
    if (s < 0) return ru_neg_errno(s);
    *size = (uint64_t)s;
    return 0;
}

static int ru_xfer(const struct ru_proc *p, const struct ru_fd *f, const uint64_t a[6], bool wr,
                   uint64_t off, uint64_t *got)
{
    const struct rvuser_io *io = p->io;
    *got = 0;
    /* Offset range guard (before any callback or guest buffer access): the stored offset and
     * offset + the REQUESTED length must stay inside the signed range, as FreeBSD refuses a
     * negative offset. Checked before the chunk clamp so a huge request is refused, not
     * served short. */
    if (off > (uint64_t)INT64_MAX || a[2] > (uint64_t)INT64_MAX - off) return E_INVAL;
    uint64_t n = a[2] > RU_IO_CHUNK ? RU_IO_CHUNK : a[2];
    if (n == 0) return 0; /* zero length: buffer untouched, no pointer formed (as FreeBSD) */
    uint8_t *buf = ru_guest_ptr(p, a[1], n);
    if (!buf) return E_FAULT;
    if (wr ? !io->pwrite : !io->pread) return E_BADF;
    int64_t r = wr ? io->pwrite(io->ctx, f->handle, buf, (size_t)n, off)
                   : io->pread(io->ctx, f->handle, buf, (size_t)n, off);
    if (r < 0) return ru_neg_errno(r);
    *got = (uint64_t)r > n ? n : (uint64_t)r;
    return 0;
}

/* read/write use and advance the fd offset; pread/pwrite take a[3] and leave it. */
static int ru_rw(struct ru_proc *p, const uint64_t a[6], bool wr, bool pos, uint64_t *ret)
{
    if (pos && a[0] <= 2u) return E_SPIPE;
    struct ru_fd *f = ru_fd_get(p, a[0]);
    if (!f || (wr ? !f->can_write : !f->can_read)) return E_BADF;
    uint64_t off = f->off, got = 0;
    int e = 0;
    if (pos) off = a[3];
    else if (wr && f->append) e = ru_size(p, f, &off);
    if (e) return e;
    if (off > (uint64_t)INT64_MAX) return E_INVAL;
    e = ru_xfer(p, f, a, wr, off, &got);
    if (e) return e;
    if (!pos) f->off = off + got;
    *ret = got;
    return 0;
}

int ru_sys_read_fd(struct ru_proc *p, const uint64_t a[6], uint64_t *ret)
{
    return ru_rw(p, a, false, false, ret);
}

int ru_sys_write_fd(struct ru_proc *p, const uint64_t a[6], uint64_t *ret)
{
    return ru_rw(p, a, true, false, ret);
}

int ru_sys_pread(struct ru_proc *p, const uint64_t a[6], uint64_t *ret)
{
    return ru_rw(p, a, false, true, ret);
}

int ru_sys_pwrite(struct ru_proc *p, const uint64_t a[6], uint64_t *ret)
{
    return ru_rw(p, a, true, true, ret);
}

static void ru_fd_release(struct ru_proc *p, struct ru_fd *f)
{
    if (p->io->close) p->io->close(p->io->ctx, f->handle);
    memset(f, 0, sizeof(*f));
}

int ru_sys_close_fd(struct ru_proc *p, const uint64_t a[6], uint64_t *ret)
{
    (void)ret;
    struct ru_fd *f = ru_fd_get(p, a[0]);
    if (!f) return E_BADF;
    ru_fd_release(p, f);
    return 0;
}

void ru_files_close_all(struct ru_proc *p)
{
    for (unsigned i = 0; i < RU_FD_COUNT; i++)
        if (p->fds[i].used) ru_fd_release(p, &p->fds[i]);
}

/* Copy a NUL-terminated guest string. A pointer that leaves guest memory
 * before the NUL is EFAULT; no NUL within RU_PATH_MAX bytes is ENAMETOOLONG. */
static int ru_copy_path(const struct ru_proc *p, uint64_t addr, char out[RU_PATH_MAX])
{
    for (uint64_t i = 0; i < RU_PATH_MAX; i++) {
        if (addr > UINT64_MAX - i) return E_FAULT;
        const uint8_t *c = ru_guest_ptr(p, addr + i, 1);
        if (!c) return E_FAULT;
        out[i] = (char)*c;
        if (*c == 0) return 0;
    }
    return E_NAMETOOLONG;
}

/* FreeBSD open flags to a caller request and fd mode. O_CLOEXEC is accepted and ignored (no
 * exec); every other unknown bit is EINVAL. Create or truncate always asks for write. */
static int ru_decode_flags(uint64_t raw, struct rvuser_open_req *req, struct ru_fd *mode)
{
    uint32_t fl = (uint32_t)raw, acc = fl & O_ACCMODE;
    if ((fl & ~(uint32_t)(O_ACCMODE | O_APPEND | O_CREAT | O_TRUNC | O_EXCL | O_CLOEXEC)) ||
        acc == O_ACCMODE)
        return E_INVAL;
    mode->can_read = acc != O_WRONLY;
    mode->can_write = acc != 0;
    mode->append = (fl & O_APPEND) != 0;
    req->read = mode->can_read;
    req->create = (fl & O_CREAT) != 0;
    req->trunc = (fl & O_TRUNC) != 0;
    req->excl = (fl & O_EXCL) != 0;
    req->write = mode->can_write || req->create || req->trunc;
    return 0;
}

static int ru_open_at(struct ru_proc *p, uint64_t path_addr, uint64_t flags, uint64_t *ret)
{
    char path[RU_PATH_MAX];
    struct rvuser_open_req req = {0};
    struct ru_fd mode = {0};
    if (!p->io->open) return E_ACCES;
    int e = ru_decode_flags(flags, &req, &mode);
    if (!e) e = ru_copy_path(p, path_addr, path);
    if (e) return e;
    if (mode.append && !p->io->fsize) return E_INVAL;
    unsigned slot = 0;
    while (slot < RU_FD_COUNT && p->fds[slot].used) slot++;
    if (slot == RU_FD_COUNT) return E_MFILE;
    e = p->io->open(p->io->ctx, path, &req, &mode.handle);
    if (e) return ru_errno(e);
    mode.used = true;
    p->fds[slot] = mode;
    *ret = RU_FD_FIRST + slot;
    return 0;
}

int ru_sys_open(struct ru_proc *p, const uint64_t a[6], uint64_t *ret)
{
    return ru_open_at(p, a[0], a[1], ret);
}

/* Only AT_FDCWD: there are no directory fds, so any other dirfd is EBADF. */
int ru_sys_openat(struct ru_proc *p, const uint64_t a[6], uint64_t *ret)
{
    if ((int32_t)a[0] != AT_FDCWD_) return E_BADF;
    return ru_open_at(p, a[1], a[2], ret);
}

int ru_sys_lseek(struct ru_proc *p, const uint64_t a[6], uint64_t *ret)
{
    if (a[0] <= 2u) return E_SPIPE;
    struct ru_fd *f = ru_fd_get(p, a[0]);
    if (!f) return E_BADF;
    int64_t delta = (int64_t)a[1], base = 0;
    uint64_t size = 0;
    if (a[2] == SEEK_CUR_) {
        base = (int64_t)f->off;
    } else if (a[2] == SEEK_END_) {
        int e = ru_size(p, f, &size);
        if (e) return e;
        if (size > (uint64_t)INT64_MAX) return E_INVAL;
        base = (int64_t)size;
    } else if (a[2] != SEEK_SET_) {
        return E_INVAL;
    }
    if ((delta > 0 && base > INT64_MAX - delta) || (delta < 0 && base + delta < 0)) return E_INVAL;
    f->off = (uint64_t)(base + delta);
    *ret = f->off;
    return 0;
}

/* Minimal fstat: mode, link count, size, block counts. Everything else is zero. */
int ru_sys_fstat(struct ru_proc *p, const uint64_t a[6], uint64_t *ret)
{
    (void)ret;
    uint8_t *sb = ru_guest_ptr(p, a[1], ST_BYTES);
    uint64_t size = 0;
    if (!sb) return E_FAULT;
    memset(sb, 0, ST_BYTES);
    zcl_write_u64_le(sb + ST_NLINK, 1);
    if (a[0] <= 2u) {
        if (p->closed_fds & (1u << a[0])) return E_BADF;
        zcl_write_u16_le(sb + ST_MODE, S_IFCHR_0620);
        return 0;
    }
    const struct ru_fd *f = ru_fd_get(p, a[0]);
    if (!f) return E_BADF;
    if (!p->io->fsize) return E_NOSYS;
    int e = ru_size(p, f, &size);
    if (e) return e;
    zcl_write_u16_le(sb + ST_MODE, S_IFREG_0600);
    zcl_write_u64_le(sb + ST_SIZE, size);
    zcl_write_u64_le(sb + ST_BLOCKS, (size + ST_BLOCK_UNIT - 1u) / ST_BLOCK_UNIT);
    zcl_write_u32_le(sb + ST_BLKSIZE, ST_IO_BLOCK);
    return 0;
}
