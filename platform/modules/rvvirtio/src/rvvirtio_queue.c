/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: split virtqueue (VIRTIO 1.2, 2.7) descriptor-chain walking, avail
 * and used rings, with a bounded walk and callback-validated guest memory. */

#include "rvvirtio_priv.h"

#include <string.h>

bool rvvirtio_dev_running(const struct rvvirtio_dev *dev)
{
    return (dev->status & RVVIRTIO_STATUS_DRIVER_OK) != 0 &&
           (dev->status & RVVIRTIO_STATUS_NEEDS_RESET) == 0;
}

bool rvvirtio_queue_live(const struct rvvirtio_dev *dev, uint32_t qi)
{
    if (rvvirtio_dev_running(dev))
        return true;
    return qi < 32u && ((dev->early_queues >> qi) & 1u) != 0 &&
           (dev->status & RVVIRTIO_STATUS_FEATURES_OK) != 0 &&
           (dev->status & RVVIRTIO_STATUS_NEEDS_RESET) == 0;
}

static bool gm_span_ok(uint64_t gpa, size_t n)
{
    return n == 0 || (uint64_t)n - 1u <= UINT64_MAX - gpa;
}

bool rvvirtio_gm_read(struct rvvirtio_dev *dev, uint64_t gpa, void *buf,
                      size_t n)
{
    if (n == 0)
        return true;
    if (!gm_span_ok(gpa, n) || dev->mem.read == NULL ||
        !dev->mem.read(dev->mem.ctx, gpa, buf, n)) {
        rvvirtio_dev_fail(dev);
        return false;
    }
    return true;
}

bool rvvirtio_gm_write(struct rvvirtio_dev *dev, uint64_t gpa, const void *buf,
                       size_t n)
{
    if (n == 0)
        return true;
    if (!gm_span_ok(gpa, n) || dev->mem.write == NULL ||
        !dev->mem.write(dev->mem.ctx, gpa, buf, n)) {
        rvvirtio_dev_fail(dev);
        return false;
    }
    return true;
}

/* 2.7: ring regions must not wrap the address space. */
bool rvvirtio_queue_valid(const struct rvvirtio_queue *q)
{
    uint64_t n = q->num;
    if (n == 0 || n > RVVIRTIO_QUEUE_MAX || (n & (n - 1u)) != 0)
        return false;
    /* 2.7: alignment 16 (descriptors), 2 (avail), 4 (used). */
    if ((q->desc & 15u) != 0 || (q->driver & 1u) != 0 || (q->device & 3u) != 0)
        return false;
    return gm_span_ok(q->desc, (size_t)(16u * n)) &&
           gm_span_ok(q->driver, (size_t)(6u + 2u * n)) &&
           gm_span_ok(q->device, (size_t)(6u + 8u * n));
}

/* ---- descriptor chains (2.7.5) ---- */

struct rvvirtio_desc {
    uint64_t addr;
    uint32_t len;
    uint16_t flags;
    uint16_t next;
};

static bool desc_load(struct rvvirtio_dev *dev, uint64_t table, uint32_t idx,
                      struct rvvirtio_desc *d)
{
    uint8_t raw[RVVIRTIO_DESC_SIZE];
    if (!rvvirtio_gm_read(dev, table + (uint64_t)idx * RVVIRTIO_DESC_SIZE, raw,
                          sizeof(raw)))
        return false;
    d->addr = rvvirtio_le64(raw);
    d->len = rvvirtio_le32(raw + 8);
    d->flags = rvvirtio_le16(raw + 12);
    d->next = rvvirtio_le16(raw + 14);
    return true;
}

static bool chain_add(struct rvvirtio_dev *dev, const struct rvvirtio_desc *d)
{
    struct rvvirtio_chain *c = &dev->chain;
    if (c->nsegs >= RVVIRTIO_SEG_MAX || !gm_span_ok(d->addr, d->len))
        return false;
    bool w = (d->flags & RVVIRTIO_DESC_F_WRITE) != 0;
    c->segs[c->nsegs] = (struct rvvirtio_seg){d->addr, d->len, w};
    c->nsegs++;
    if (w)
        c->out_len += d->len;
    else
        c->in_len += d->len;
    return true;
}

static bool chain_walk(struct rvvirtio_dev *dev, uint64_t table, uint32_t entries,
                       uint32_t head, bool indirect_allowed);

/* 2.7.5.3: an indirect descriptor names a table of 16-byte descriptors. */
static bool chain_indirect(struct rvvirtio_dev *dev, const struct rvvirtio_desc *d)
{
    bool negotiated = (dev->driver_features & RVVIRTIO_F_INDIRECT_DESC) != 0;
    if (!negotiated || (d->flags & RVVIRTIO_DESC_F_NEXT) != 0 || d->len == 0 ||
        d->len % RVVIRTIO_DESC_SIZE != 0)
        return false;
    uint32_t entries = d->len / RVVIRTIO_DESC_SIZE;
    if (entries > RVVIRTIO_QUEUE_MAX || !gm_span_ok(d->addr, d->len))
        return false;
    return chain_walk(dev, d->addr, entries, 0, false);
}

/* Follow NEXT links from head. The walk is bounded by the table size: a loop
 * or an over-long chain is a device error (NEEDS_RESET), never a hang. */
static bool chain_walk(struct rvvirtio_dev *dev, uint64_t table, uint32_t entries,
                       uint32_t head, bool indirect_allowed)
{
    uint32_t idx = head;
    for (uint32_t steps = 0; RVVIRTIO_CHAIN_BOUND_OK(steps, entries); steps++) {
        struct rvvirtio_desc d;
        if (idx >= entries || !desc_load(dev, table, idx, &d))
            return false;
        if ((d.flags & RVVIRTIO_DESC_F_INDIRECT) != 0)
            return indirect_allowed && chain_indirect(dev, &d);
        if (!chain_add(dev, &d))
            return false;
        if ((d.flags & RVVIRTIO_DESC_F_NEXT) == 0)
            return true;
        idx = d.next;
    }
    return false;
}

static enum rvvirtio_pop pop_fail(struct rvvirtio_dev *dev)
{
    rvvirtio_dev_fail(dev);
    return RVVIRTIO_POP_ERROR;
}

/* 2.7.13: take the next available head, if any, and load its chain. */
enum rvvirtio_pop rvvirtio_queue_pop(struct rvvirtio_dev *dev, uint32_t qi)
{
    struct rvvirtio_queue *q = &dev->queues[qi];
    uint8_t b[2];
    if (!rvvirtio_queue_live(dev, qi) || !q->ready)
        return RVVIRTIO_POP_EMPTY;
    if (!rvvirtio_gm_read(dev, q->driver + 2u, b, 2)) /* avail.idx */
        return RVVIRTIO_POP_ERROR;
    uint16_t avail = rvvirtio_le16(b);
    if (avail == q->last_avail)
        return RVVIRTIO_POP_EMPTY;
    if ((uint16_t)(avail - q->last_avail) > q->num) /* 2.7.13.3 */
        return pop_fail(dev);
    uint64_t slot = q->last_avail % q->num;
    if (!rvvirtio_gm_read(dev, q->driver + 4u + 2u * slot, b, 2))
        return RVVIRTIO_POP_ERROR;
    uint32_t head = rvvirtio_le16(b);
    memset(&dev->chain, 0, sizeof(dev->chain));
    dev->chain.head = head;
    if (head >= q->num || !chain_walk(dev, q->desc, q->num, head, true))
        return pop_fail(dev);
    return RVVIRTIO_POP_OK;
}

bool rvvirtio_queue_has_avail(struct rvvirtio_dev *dev, uint32_t qi)
{
    const struct rvvirtio_queue *q = &dev->queues[qi];
    uint8_t b[2];
    if (!rvvirtio_queue_live(dev, qi) || !q->ready)
        return false;
    if (!rvvirtio_gm_read(dev, q->driver + 2u, b, 2))
        return false;
    return rvvirtio_le16(b) != q->last_avail;
}

/* 2.7.14: publish the used element, then notify unless suppressed. */
bool rvvirtio_queue_push(struct rvvirtio_dev *dev, uint32_t qi, uint32_t len)
{
    struct rvvirtio_queue *q = &dev->queues[qi];
    uint8_t elem[8], idx[2], flags[2];
    uint64_t slot = q->used_idx % q->num;
    rvvirtio_put_le32(elem, dev->chain.head);
    rvvirtio_put_le32(elem + 4, len);
    if (!rvvirtio_gm_write(dev, q->device + 4u + 8u * slot, elem, sizeof(elem)))
        return false;
    rvvirtio_put_le16(idx, (uint16_t)(q->used_idx + 1u));
    if (!rvvirtio_gm_write(dev, q->device + 2u, idx, sizeof(idx)))
        return false;
    q->used_idx++;
    q->last_avail++;
    if (!rvvirtio_gm_read(dev, q->driver, flags, sizeof(flags)))
        return false;
    if ((rvvirtio_le16(flags) & RVVIRTIO_AVAIL_F_NO_INTERRUPT) == 0) {
        dev->interrupt_status |= RVVIRTIO_INT_USED_BUFFER;
        rvvirtio_irq_update(dev);
    }
    return true;
}

/* ---- chain byte streams ---- */

static bool chain_xfer(struct rvvirtio_dev *dev, bool want_write, uint64_t off,
                       uint8_t *rd, const uint8_t *wr, size_t n)
{
    const struct rvvirtio_chain *c = &dev->chain;
    uint64_t total = want_write ? c->out_len : c->in_len;
    if (off > total || (uint64_t)n > total - off) {
        rvvirtio_dev_fail(dev);
        return false;
    }
    for (uint32_t i = 0; i < c->nsegs && n > 0; i++) {
        const struct rvvirtio_seg *s = &c->segs[i];
        if (s->write != want_write)
            continue;
        if (off >= s->len) {
            off -= s->len;
            continue;
        }
        size_t take = (size_t)(s->len - off) < n ? (size_t)(s->len - off) : n;
        bool ok = want_write ? rvvirtio_gm_write(dev, s->gpa + off, wr, take)
                              : rvvirtio_gm_read(dev, s->gpa + off, rd, take);
        if (!ok)
            return false;
        if (rd != NULL)
            rd += take;
        if (wr != NULL)
            wr += take;
        n -= take;
        off = 0;
    }
    return true;
}

bool rvvirtio_chain_read(struct rvvirtio_dev *dev, uint64_t off, void *buf,
                         size_t n)
{
    return chain_xfer(dev, false, off, buf, NULL, n);
}

bool rvvirtio_chain_write(struct rvvirtio_dev *dev, uint64_t off,
                          const void *buf, size_t n)
{
    return chain_xfer(dev, true, off, NULL, buf, n);
}
