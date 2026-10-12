/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: RISC-V PLIC model for hart 0, written from the RISC-V PLIC
 * specification 1.0 (memory map, gateway, claim/complete). */
#include "rvplat/plic.h"

static bool bit_get(const uint32_t *map, uint32_t id)
{
    return ((map[id / 32u] >> (id % 32u)) & 1u) != 0u;
}

static void bit_set(uint32_t *map, uint32_t id, bool value)
{
    uint32_t mask = 1u << (id % 32u);
    if (value)
        map[id / 32u] |= mask;
    else
        map[id / 32u] &= ~mask;
}

static bool id_valid(const struct rvplat_plic *plic, uint32_t id)
{
    return id >= 1u && id <= plic->nsources;
}

void rvplat_plic_init(struct rvplat_plic *plic, uint32_t nsources)
{
    *plic = (struct rvplat_plic){0};
    if (nsources < 1u)
        nsources = 1u;
    if (nsources > RVPLAT_PLIC_MAX_SOURCES)
        nsources = RVPLAT_PLIC_MAX_SOURCES;
    plic->nsources = nsources;
}

void rvplat_plic_set_source(struct rvplat_plic *plic, uint32_t irq, bool level)
{
    if (!id_valid(plic, irq))
        return;
    bit_set(plic->level, irq, level);
    if (level && !bit_get(plic->inflight, irq))
        bit_set(plic->pending, irq, true);
}

/* Selection (PLIC 1.0 "Interrupt Claim Process"): the pending and enabled
 * source with the highest NONZERO priority, lowest id on ties because ids are
 * scanned in ascending order. The context threshold plays no part here; it
 * only gates the notification (context_pending). */
static uint32_t best_candidate(const struct rvplat_plic *plic, uint32_t ctx)
{
    uint32_t best = 0u;
    uint32_t best_prio = 0u;
    for (uint32_t id = 1u; id <= plic->nsources; id++) {
        if (!bit_get(plic->pending, id) || !bit_get(plic->enable[ctx], id))
            continue;
        if (plic->priority[id] > best_prio) {
            best_prio = plic->priority[id];
            best = id;
        }
    }
    return best;
}

bool rvplat_plic_context_pending(const struct rvplat_plic *plic, uint32_t ctx)
{
    if (ctx >= RVPLAT_PLIC_CONTEXTS)
        return false;
    uint32_t best = best_candidate(plic, ctx);
    return best != 0u && plic->priority[best] > plic->threshold[ctx];
}

uint32_t rvplat_plic_claim(struct rvplat_plic *plic, uint32_t ctx)
{
    if (ctx >= RVPLAT_PLIC_CONTEXTS)
        return 0u;
    uint32_t id = best_candidate(plic, ctx);
    if (id != 0u) {
        bit_set(plic->pending, id, false);
        bit_set(plic->inflight, id, true);
    }
    return id;
}

void rvplat_plic_complete(struct rvplat_plic *plic, uint32_t ctx, uint32_t id)
{
    if (ctx >= RVPLAT_PLIC_CONTEXTS || !id_valid(plic, id))
        return;
    if (!bit_get(plic->enable[ctx], id) || !bit_get(plic->inflight, id))
        return;
    bit_set(plic->inflight, id, false);
    if (bit_get(plic->level, id))
        bit_set(plic->pending, id, true);
}

/* Mask of the register bits that name implemented sources in word w. */
static uint32_t word_mask(const struct rvplat_plic *plic, uint32_t w)
{
    uint32_t mask = 0u;
    for (uint32_t b = 0u; b < 32u; b++) {
        uint32_t id = w * 32u + b;
        if (id_valid(plic, id))
            mask |= 1u << b;
    }
    return mask;
}

struct plic_reg {
    enum { REG_NONE, REG_PRIORITY, REG_PENDING, REG_ENABLE, REG_THRESHOLD,
           REG_CLAIM } kind;
    uint32_t a; /* source id, word index or context */
    uint32_t b; /* word index for enables */
};

static struct plic_reg decode_context(uint64_t offset)
{
    struct plic_reg reg = {REG_NONE, 0u, 0u};
    uint64_t rel = offset - RVPLAT_PLIC_CONTEXT_BASE;
    uint64_t ctx = rel / RVPLAT_PLIC_CONTEXT_STRIDE;
    uint64_t off = rel % RVPLAT_PLIC_CONTEXT_STRIDE;
    if (ctx >= RVPLAT_PLIC_CONTEXTS)
        return reg;
    reg.a = (uint32_t)ctx;
    if (off == RVPLAT_PLIC_THRESHOLD_OFF)
        reg.kind = REG_THRESHOLD;
    else if (off == RVPLAT_PLIC_CLAIM_OFF)
        reg.kind = REG_CLAIM;
    return reg;
}

static struct plic_reg decode_enable(uint64_t offset)
{
    struct plic_reg reg = {REG_NONE, 0u, 0u};
    uint64_t rel = offset - RVPLAT_PLIC_ENABLE_BASE;
    uint64_t ctx = rel / RVPLAT_PLIC_ENABLE_STRIDE;
    uint64_t word = (rel % RVPLAT_PLIC_ENABLE_STRIDE) / 4u;
    if (ctx < RVPLAT_PLIC_CONTEXTS && word < RVPLAT_PLIC_WORDS) {
        reg.kind = REG_ENABLE;
        reg.a = (uint32_t)ctx;
        reg.b = (uint32_t)word;
    }
    return reg;
}

static struct plic_reg decode(const struct rvplat_plic *plic, uint64_t offset)
{
    struct plic_reg reg = {REG_NONE, 0u, 0u};
    if (offset >= RVPLAT_PLIC_SIZE || (offset & 3u) != 0u)
        return reg;
    if (offset < RVPLAT_PLIC_PENDING_BASE) {
        reg.a = (uint32_t)(offset / 4u);
        if (id_valid(plic, reg.a))
            reg.kind = REG_PRIORITY;
    } else if (offset < RVPLAT_PLIC_PENDING_BASE + 4u * RVPLAT_PLIC_WORDS) {
        reg.kind = REG_PENDING;
        reg.a = (uint32_t)((offset - RVPLAT_PLIC_PENDING_BASE) / 4u);
    } else if (offset >= RVPLAT_PLIC_ENABLE_BASE &&
               offset < RVPLAT_PLIC_ENABLE_BASE +
                            RVPLAT_PLIC_ENABLE_STRIDE * RVPLAT_PLIC_CONTEXTS) {
        reg = decode_enable(offset);
    } else if (offset >= RVPLAT_PLIC_CONTEXT_BASE) {
        reg = decode_context(offset);
    }
    return reg;
}

uint32_t rvplat_plic_read(struct rvplat_plic *plic, uint64_t offset)
{
    struct plic_reg reg = decode(plic, offset);
    switch (reg.kind) {
    case REG_PRIORITY: return plic->priority[reg.a];
    case REG_PENDING: return plic->pending[reg.a];
    case REG_ENABLE: return plic->enable[reg.a][reg.b];
    case REG_THRESHOLD: return plic->threshold[reg.a];
    case REG_CLAIM: return rvplat_plic_claim(plic, reg.a);
    case REG_NONE: break;
    }
    return 0u;
}

void rvplat_plic_write(struct rvplat_plic *plic, uint64_t offset,
                       uint32_t value)
{
    struct plic_reg reg = decode(plic, offset);
    switch (reg.kind) {
    case REG_PRIORITY:
        plic->priority[reg.a] = value & RVPLAT_PLIC_MAX_PRIORITY;
        break;
    case REG_ENABLE:
        plic->enable[reg.a][reg.b] = value & word_mask(plic, reg.b);
        break;
    case REG_THRESHOLD:
        plic->threshold[reg.a] = value & RVPLAT_PLIC_MAX_PRIORITY;
        break;
    case REG_CLAIM:
        rvplat_plic_complete(plic, reg.a, value);
        break;
    case REG_PENDING: /* read-only */
    case REG_NONE:
        break;
    }
}
