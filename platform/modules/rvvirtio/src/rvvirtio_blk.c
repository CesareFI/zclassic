/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: virtio-blk (VIRTIO 1.2, section 5.2) over a caller-supplied
 * storage backend. Requests IN, OUT, FLUSH and GET_ID; no file I/O here. */

#include "rvvirtio_priv.h"

#include <string.h>

/* 5.2.3: feature bits. */
#define BLK_F_SEG_MAX (UINT64_C(1) << 2)
#define BLK_F_RO (UINT64_C(1) << 5)
#define BLK_F_BLK_SIZE (UINT64_C(1) << 6)
#define BLK_F_FLUSH (UINT64_C(1) << 9)

#define BLK_SEG_MAX RVVIRTIO_BLK_DATA_SEGS_MAX
#define BLK_HDR_LEN 16u /* 5.2.6: type, reserved, sector */

/* 5.2.4: config space: capacity u64 @0, seg_max u32 @12, blk_size u32 @20. */
static void blk_fill_config(struct rvvirtio_blk *b)
{
    struct rvvirtio_dev *d = &b->dev;
    uint64_t cap = b->capacity_sectors;
    rvvirtio_put_le32(d->config, (uint32_t)cap);
    rvvirtio_put_le32(d->config + 4, (uint32_t)(cap >> 32));
    rvvirtio_put_le32(d->config + 12, BLK_SEG_MAX);
    rvvirtio_put_le32(d->config + 20, RVVIRTIO_BLK_SECTOR);
    d->config_len = 24;
}

struct blk_result {
    uint8_t status;
    uint64_t written; /* device-writable bytes produced, excluding status */
    uint64_t moved;   /* data bytes read or written on the backend, for the notify cap */
};

/* Bound-by-construction facts the admission guard relies on. */
static_assert(RVVIRTIO_BLK_REQ_BYTES_MAX < UINT32_MAX,
              "used length (data + status) must fit uint32_t");
static_assert(RVVIRTIO_BLK_REQ_BYTES_MAX % RVVIRTIO_BLK_SECTOR == 0,
              "request bound is whole sectors");
static_assert((uint64_t)RVVIRTIO_BLK_DATA_SEGS_MAX * 4096u <= RVVIRTIO_BLK_REQ_BYTES_MAX,
              "a driver sizing requests by seg_max pages stays under the bound");
static_assert((uint64_t)RVVIRTIO_BLK_NOTIFY_REQS_MAX * RVVIRTIO_BLK_DATA_SEGS_MAX * 4096u <=
                  RVVIRTIO_BLK_NOTIFY_BYTES_MAX,
              "a full legitimate queue never reaches the per-notify byte cap");
static_assert(RVVIRTIO_BLK_NOTIFY_REQS_MAX >= RVVIRTIO_QUEUE_MAX,
              "a full queue is serviced by one notify");

static bool blk_range_ok(const struct rvvirtio_blk *b, uint64_t sector,
                         uint64_t bytes)
{
    uint64_t nsect = bytes / RVVIRTIO_BLK_SECTOR;
    uint64_t cap = b->capacity_sectors;
    return bytes % RVVIRTIO_BLK_SECTOR == 0 &&
           RVVIRTIO_SECTOR_RANGE_OK(sector, nsect, cap);
}

/* 5.2.6: IN reads from the disk into the device-writable data bytes. */
static struct blk_result blk_do_in(struct rvvirtio_blk *b, uint64_t sector)
{
    struct blk_result r = {RVVIRTIO_BLK_S_IOERR, 0, 0};
    uint64_t bytes = b->dev.chain.out_len - 1u; /* 64-bit sum of the writable segments */
    /* Admission: refuse before the first backend callback. */
    if (!RVVIRTIO_BLK_BYTES_OK(bytes) || !blk_range_ok(b, sector, bytes))
        return r;
    uint64_t off = sector * RVVIRTIO_BLK_SECTOR; /* <= capacity, no wrap */
    while (r.written < bytes) {
        uint64_t left = bytes - r.written;
        size_t n = left < RVVIRTIO_BLK_CHUNK ? (size_t)left : RVVIRTIO_BLK_CHUNK;
        if (!b->be.pread(b->be.ctx, off + r.written, b->chunk, n) ||
            !rvvirtio_chain_write(&b->dev, r.written, b->chunk, n))
            return r;
        r.written += n;
        r.moved += n;
    }
    r.status = RVVIRTIO_BLK_S_OK;
    return r;
}

/* 5.2.6: OUT writes the device-readable data bytes to the disk. */
static struct blk_result blk_do_out(struct rvvirtio_blk *b, uint64_t sector)
{
    struct blk_result r = {RVVIRTIO_BLK_S_IOERR, 0, 0};
    uint64_t bytes = b->dev.chain.in_len - BLK_HDR_LEN;
    if (b->read_only || !RVVIRTIO_BLK_BYTES_OK(bytes) || !blk_range_ok(b, sector, bytes))
        return r;
    uint64_t off = sector * RVVIRTIO_BLK_SECTOR;
    for (uint64_t done = 0; done < bytes;) {
        uint64_t left = bytes - done;
        size_t n = left < RVVIRTIO_BLK_CHUNK ? (size_t)left : RVVIRTIO_BLK_CHUNK;
        if (!rvvirtio_chain_read(&b->dev, BLK_HDR_LEN + done, b->chunk, n) ||
            !b->be.pwrite(b->be.ctx, off + done, b->chunk, n))
            return r;
        done += n;
        r.moved = done;
    }
    r.status = RVVIRTIO_BLK_S_OK;
    return r;
}

/* 5.2.6: GET_ID returns a 20-byte, NUL-padded identifier. */
static struct blk_result blk_do_get_id(struct rvvirtio_blk *b)
{
    struct blk_result r = {RVVIRTIO_BLK_S_IOERR, 0, 0};
    uint8_t id[RVVIRTIO_BLK_ID_LEN];
    const char *s = b->be.serial != NULL ? b->be.serial : "z23-virtio-blk";
    memset(id, 0, sizeof(id));
    for (size_t i = 0; i < sizeof(id) && s[i] != '\0'; i++)
        id[i] = (uint8_t)s[i];
    if (b->dev.chain.out_len - 1u < sizeof(id) ||
        !rvvirtio_chain_write(&b->dev, 0, id, sizeof(id)))
        return r;
    r.status = RVVIRTIO_BLK_S_OK;
    r.written = sizeof(id);
    return r;
}

static struct blk_result blk_do_flush(struct rvvirtio_blk *b)
{
    struct blk_result r = {RVVIRTIO_BLK_S_UNSUPP, 0, 0};
    if (b->be.flush == NULL)
        return r;
    r.status = b->be.flush(b->be.ctx) ? RVVIRTIO_BLK_S_OK : RVVIRTIO_BLK_S_IOERR;
    return r;
}

static struct blk_result blk_dispatch(struct rvvirtio_blk *b, uint32_t type,
                                      uint64_t sector)
{
    switch (type) {
    case RVVIRTIO_BLK_T_IN: return blk_do_in(b, sector);
    case RVVIRTIO_BLK_T_OUT: return blk_do_out(b, sector);
    case RVVIRTIO_BLK_T_FLUSH: return blk_do_flush(b);
    case RVVIRTIO_BLK_T_GET_ID: return blk_do_get_id(b);
    default: return (struct blk_result){RVVIRTIO_BLK_S_UNSUPP, 0, 0};
    }
}

/* One popped chain. A request whose header or status byte is missing cannot
 * be answered at all: that is a driver error, so NEEDS_RESET and nothing is
 * completed. Anything else gets a status byte. */
static uint64_t blk_request(struct rvvirtio_blk *b)
{
    struct rvvirtio_dev *d = &b->dev;
    uint8_t hdr[BLK_HDR_LEN];
    if (d->chain.out_len < 1u || d->chain.in_len < BLK_HDR_LEN) {
        rvvirtio_dev_fail(d);
        return 0;
    }
    if (!rvvirtio_chain_read(d, 0, hdr, sizeof(hdr)))
        return 0;
    struct blk_result r = blk_dispatch(b, rvvirtio_le32(hdr), rvvirtio_le64(hdr + 8));
    if ((d->status & RVVIRTIO_STATUS_NEEDS_RESET) != 0)
        return r.moved;
    if (!rvvirtio_chain_write(d, d->chain.out_len - 1u, &r.status, 1))
        return r.moved;
    /* r.written <= REQ_BYTES_MAX by the admission guard, so the used length
     * fits; the clamp only documents that no narrowing can wrap. */
    uint64_t used = r.written + 1u;
    (void)rvvirtio_queue_push(d, 0, used > UINT32_MAX ? UINT32_MAX : (uint32_t)used);
    return r.moved;
}

/* One notify's worth of work: at least the first available request, then stop
 * at the request or byte cap (rvvirtio.h) and leave the rest pending. */
static void blk_run(struct rvvirtio_blk *b)
{
    struct rvvirtio_dev *dev = &b->dev;
    uint64_t moved = 0;
    b->pending = false;
    for (uint32_t served = 0; served < RVVIRTIO_BLK_NOTIFY_REQS_MAX; served++) {
        if (moved >= RVVIRTIO_BLK_NOTIFY_BYTES_MAX)
            break;
        if (rvvirtio_queue_pop(dev, 0) != RVVIRTIO_POP_OK)
            return; /* empty, or the device is now NEEDS_RESET */
        moved += blk_request(b);
        if (!rvvirtio_dev_running(dev))
            return;
    }
    b->pending = rvvirtio_queue_has_avail(dev, 0);
}

static void blk_notify(struct rvvirtio_dev *dev, uint32_t queue)
{
    if (queue != 0)
        return;
    blk_run((struct rvvirtio_blk *)dev);
}

static void blk_on_reset(struct rvvirtio_dev *dev)
{
    ((struct rvvirtio_blk *)dev)->pending = false;
}

void rvvirtio_blk_service(struct rvvirtio_blk *blk)
{
    if (rvvirtio_dev_running(&blk->dev) && blk->dev.queues[0].ready)
        blk_run(blk);
}

bool rvvirtio_blk_pending(const struct rvvirtio_blk *blk)
{
    return blk->pending;
}

bool rvvirtio_blk_init(struct rvvirtio_blk *blk, const struct rvvirtio_mem *mem,
                       const struct rvvirtio_blk_backend *backend,
                       bool read_only)
{
    if (mem == NULL || backend == NULL || mem->read == NULL ||
        mem->write == NULL || backend->size == NULL || backend->pread == NULL)
        return false;
    uint64_t features = BLK_F_SEG_MAX | BLK_F_BLK_SIZE;
    memset(blk, 0, sizeof(*blk));
    blk->be = *backend;
    blk->read_only = read_only || backend->pwrite == NULL;
    blk->capacity_sectors = backend->size(backend->ctx) / RVVIRTIO_BLK_SECTOR;
    if (blk->read_only)
        features |= BLK_F_RO;
    if (backend->flush != NULL)
        features |= BLK_F_FLUSH;
    rvvirtio_dev_setup(&blk->dev, mem, RVVIRTIO_DEVICE_ID_BLOCK, features, 1);
    blk->dev.notify = blk_notify;
    blk->dev.on_reset = blk_on_reset;
    blk_fill_config(blk);
    return true;
}
