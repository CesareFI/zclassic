/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: caller-owned block backends. The default read-only image keeps
 * guest writes in a bounded private overlay. The explicitly retained backend
 * delegates reads, writes and flushes to the caller without an overlay.
 * Failed callbacks and exhausted overlay space become guest I/O errors. */
#include "rvmachine_priv.h"

#include "base/safe_alloc.h"
#include "base/cleanse.h"

#include <string.h>

/* Policy point: the test group recompiles this file with a small cap. */
#if !defined(RVMACHINE_TWIN_BUILD) && defined(RVMACHINE_POLICY_OVERLAY_BLOCKS)
#error "machine policy points may be replaced only by the test twin"
#endif
#ifndef RVMACHINE_POLICY_OVERLAY_BLOCKS
#define RVMACHINE_POLICY_OVERLAY_BLOCKS RVMACHINE_DISK_OVERLAY_BLOCKS
#endif

/* Reads exactly n bytes at off from the image, or fails. */
static bool file_read(const struct rvmachine_disk *d, uint64_t off, uint8_t *buf,
                      size_t n)
{
    return n == 0 || d->read(d->ctx, off, buf, n);
}

static bool range_ok(const struct rvmachine_disk *d, uint64_t off, size_t n)
{
    return off <= d->size && n <= d->size - off;
}

/* The image bytes of one block; the tail past the end of the file is zero. */
static bool block_from_file(const struct rvmachine_disk *d, uint64_t block,
                            uint8_t *buf)
{
    uint64_t off = block * RVMACHINE_DISK_BLOCK;
    uint64_t left = d->size - off;
    size_t n = left < RVMACHINE_DISK_BLOCK ? (size_t)left : RVMACHINE_DISK_BLOCK;
    memset(buf + n, 0, RVMACHINE_DISK_BLOCK - n);
    return file_read(d, off, buf, n);
}

/* The overlay copy of a block, made on first write. NULL when the overlay is
 * full, an allocation fails or the image cannot be read. */
static uint8_t *block_for_write(struct rvmachine_disk *d, uint64_t block)
{
    uint8_t *copy;
    if (d->slot[block] != 0) return d->overlay[d->slot[block] - 1u];
    if (d->used >= RVMACHINE_POLICY_OVERLAY_BLOCKS) return NULL;
    copy = zcl_malloc(RVMACHINE_DISK_BLOCK, "rvmachine_disk_block");
    if (copy == NULL) return NULL;
    if (!block_from_file(d, block, copy)) {
        memory_cleanse(copy, RVMACHINE_DISK_BLOCK);
        free(copy);
        return NULL;
    }
    d->overlay[d->used] = copy;
    d->slot[block] = ++d->used;
    return copy;
}

bool rvmachine_disk_read(struct rvmachine_disk *d, uint64_t off, void *buf, size_t n)
{
    uint8_t *out = buf;
    if (d == NULL || buf == NULL || !range_ok(d, off, n)) return false;
    if (d->write != NULL) return file_read(d, off, out, n);
    while (n != 0) {
        uint64_t block = off / RVMACHINE_DISK_BLOCK;
        size_t in = (size_t)(off % RVMACHINE_DISK_BLOCK);
        size_t take = RVMACHINE_DISK_BLOCK - in;
        if (take > n) take = n;
        if (d->slot[block] != 0)
            memcpy(out, d->overlay[d->slot[block] - 1u] + in, take);
        else if (!file_read(d, off, out, take))
            return false;
        out += take;
        off += take;
        n -= take;
    }
    return true;
}

bool rvmachine_disk_write(struct rvmachine_disk *d, uint64_t off, const void *buf,
                          size_t n)
{
    const uint8_t *in_buf = buf;
    if (d == NULL || buf == NULL || !range_ok(d, off, n)) return false;
    if (d->write != NULL) return n == 0 || d->write(d->ctx, off, buf, n);
    while (n != 0) {
        uint64_t block = off / RVMACHINE_DISK_BLOCK;
        size_t in = (size_t)(off % RVMACHINE_DISK_BLOCK);
        size_t take = RVMACHINE_DISK_BLOCK - in;
        uint8_t *copy = block_for_write(d, block);
        if (copy == NULL) return false;
        if (take > n) take = n;
        memcpy(copy + in, in_buf, take);
        in_buf += take;
        off += take;
        n -= take;
    }
    return true;
}

uint64_t rvmachine_disk_size(const struct rvmachine_disk *d)
{
    return d != NULL ? d->size : 0;
}

bool rvmachine_disk_flush(struct rvmachine_disk *d)
{
    return d != NULL && (d->flush == NULL || d->flush(d->ctx));
}

uint32_t rvmachine_disk_overlay_blocks(const struct rvmachine_disk *d)
{
    return d != NULL ? d->used : 0;
}

void rvmachine_disk_cleanse(struct rvmachine_disk *d)
{
    if (d == NULL) return;
    for (uint32_t i = 0; i < d->used; i++)
        memory_cleanse(d->overlay[i], RVMACHINE_DISK_BLOCK);
}

void rvmachine_disk_close(struct rvmachine_disk *d)
{
    if (d == NULL) return;
    for (uint32_t i = 0; i < d->used; i++) free(d->overlay[i]);
    free(d->overlay);
    free(d->slot);
    free(d);
}

static bool disk_alloc_tables(struct rvmachine_disk *d)
{
    d->nblocks = d->size / RVMACHINE_DISK_BLOCK +
                 (d->size % RVMACHINE_DISK_BLOCK != 0 ? 1u : 0u);
    if (d->nblocks > SIZE_MAX / sizeof *d->slot) return false;
    d->slot = zcl_calloc((size_t)d->nblocks, sizeof *d->slot, "rvmachine_disk_slots");
    d->overlay = zcl_calloc(RVMACHINE_POLICY_OVERLAY_BLOCKS, sizeof *d->overlay,
                            "rvmachine_disk_overlay");
    return d->slot != NULL && d->overlay != NULL;
}

enum rvmachine_status rvmachine_disk_open(struct rvmachine_disk **out, uint64_t size,
                                          rvmachine_disk_read_fn read, void *ctx)
{
    struct rvmachine_disk *d;
    if (out == NULL) return RVMACHINE_ERR_ARG;
    *out = NULL;
    if (read == NULL) return RVMACHINE_ERR_ARG;
    if (size == 0 || size > RVMACHINE_DISK_BYTES_MAX) return RVMACHINE_ERR_DISK;
    d = zcl_calloc(1, sizeof *d, "rvmachine_disk");
    if (d == NULL) return RVMACHINE_ERR_NOMEM;
    d->read = read;
    d->ctx = ctx;
    d->size = size;
    if (!disk_alloc_tables(d)) {
        rvmachine_disk_close(d);
        return RVMACHINE_ERR_NOMEM;
    }
    *out = d;
    return RVMACHINE_OK;
}

enum rvmachine_status rvmachine_disk_open_backend(struct rvmachine_disk **out,
    uint64_t size, rvmachine_disk_read_fn read, rvmachine_disk_write_fn write,
    rvmachine_disk_flush_fn flush, void *ctx)
{
    if (out == NULL) return RVMACHINE_ERR_ARG;
    *out = NULL;
    if (read == NULL || write == NULL || flush == NULL) return RVMACHINE_ERR_ARG;
    if (size == 0 || size > RVMACHINE_DISK_BYTES_MAX) return RVMACHINE_ERR_DISK;
    struct rvmachine_disk *d = zcl_calloc(1, sizeof *d, "rvmachine_disk_backend");
    if (d == NULL) return RVMACHINE_ERR_NOMEM;
    d->read = read;
    d->write = write;
    d->flush = flush;
    d->ctx = ctx;
    d->size = size;
    *out = d;
    return RVMACHINE_OK;
}
