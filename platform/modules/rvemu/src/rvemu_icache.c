/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0.
 * Purpose: direct-mapped cache of decoded instruction bits. A hit whose store
 * epoch matches the hart returns the cached bits and does not read guest
 * memory. Any other hit re-reads the parcel and drops the line when the bits
 * differ. A store advances the epoch; a store over the parcel, fence.i, or a
 * translation flush also drops the line. */
#include "rvemu_internal.h"
#include "base/serialize_le.h"
#include <stdint.h>
#include <string.h>

/* 1 when the cached parcel is still the bytes at its physical address.
 * A host or a guest that edits those bytes must not execute the old decode. */
static int line_holds(const struct rvemu_mem *mem, const struct rvemu_icache_entry *e)
{
    const uint8_t *p = rvemu_ram_ptr(mem, e->pa, e->len);
    uint32_t now;
    if (p == NULL || (e->len != 2u && e->len != 4u)) return 0;
    now = e->len == 2u ? zcl_read_u16_le(p) : zcl_read_u32_le(p);
    return now == e->raw;
}

/* 0 means the next hit must re-read. Wrap flushes, so a recycled epoch cannot
 * match a line filled before the wrap. */
static void epoch_bump(struct rvemu_hart *h)
{
    if (h->mem_epoch == UINT64_MAX) {
        rvemu_icache_flush(h);
        h->mem_epoch = 1;
        return;
    }
    h->mem_epoch++;
}

int rvemu_icache_lookup(struct rvemu_hart *h, const struct rvemu_mem *mem, uint64_t pc,
                        uint32_t *raw)
{
    struct rvemu_icache_entry *e;
    if (h == NULL || mem == NULL || raw == NULL) return 0;
    e = &h->icache[(pc >> 1) & (RVEMU_ICACHE_ENTRIES - 1u)];
    if (e->valid == 0 || e->tag_pc != pc || e->tag_satp != h->csr.satp ||
        e->priv != (uint8_t)h->priv)
        return 0;
    if (e->epoch != 0 && e->epoch == h->mem_epoch) {
        *raw = e->raw;
        h->icache_hit++;
        h->icache_fast++;
        return 1;
    }
    if (!line_holds(mem, e)) {
        e->valid = 0;
        return 0;
    }
    e->epoch = h->mem_epoch;
    *raw = e->raw;
    h->icache_hit++;
    return 1;
}

void rvemu_icache_fill(struct rvemu_hart *h, uint64_t pc, uint64_t pa, uint32_t raw,
                       unsigned len)
{
    struct rvemu_icache_entry *e;
    if (h == NULL) return;
    h->icache_miss++;
    if (len != 2u && len != 4u) return;
    e = &h->icache[(pc >> 1) & (RVEMU_ICACHE_ENTRIES - 1u)];
    e->tag_pc = pc;
    e->tag_satp = h->csr.satp;
    e->pa = pa;
    e->epoch = h->mem_epoch;
    e->raw = raw;
    e->len = (uint8_t)len;
    e->priv = (uint8_t)h->priv;
    e->valid = 1u;
}

void rvemu_icache_note_store(struct rvemu_hart *h, uint64_t pa, unsigned n)
{
    unsigned i;
    if (h == NULL || n == 0) return;
    epoch_bump(h);
    if (n > 8u || pa > UINT64_MAX - n) {
        rvemu_icache_flush(h);
        return;
    }
    for (i = 0; i < RVEMU_ICACHE_ENTRIES; i++) {
        struct rvemu_icache_entry *e = &h->icache[i];
        if (e->valid == 0) continue;
        if (e->len > UINT64_MAX - e->pa || (pa < e->pa + e->len && e->pa < pa + n))
            e->valid = 0;
    }
}

void rvemu_icache_flush(struct rvemu_hart *h)
{
    if (h == NULL) return;
    memset(h->icache, 0, sizeof h->icache);
}
