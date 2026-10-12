/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0.
 * Base Sv39 translation: RISC-V Privileged ISA supervisor chapter,
 * Virtual Address Translation Process and Sv39. */
#include "rvemu/translate.h"
#include <stdbool.h>
#define PTE_V UINT64_C(1)
#define PTE_R UINT64_C(2)
#define PTE_W UINT64_C(4)
#define PTE_X UINT64_C(8)
#define PTE_U UINT64_C(16)
#define PTE_A UINT64_C(64)
#define PTE_D UINT64_C(128)
#define PPN_MASK ((UINT64_C(1) << 44) - 1)
#define STATUS_SUM (UINT64_C(1) << 18)
#define STATUS_MXR (UINT64_C(1) << 19)

static struct rvemu_translation result(const struct rvemu_translation_request *r,
                                      enum rvemu_translation_status status)
{
    struct rvemu_translation out = {.status = status, .tval = r ? r->va : 0};
    if (status == RVEMU_TRANSLATION_PAGE_FAULT)
        out.cause = r->access == RVEMU_ACCESS_FETCH ? 12u :
                    r->access == RVEMU_ACCESS_LOAD ? 13u : 15u;
    if (status == RVEMU_TRANSLATION_ACCESS_FAULT)
        out.cause = r->access == RVEMU_ACCESS_FETCH ? 1u :
                    r->access == RVEMU_ACCESS_LOAD ? 5u : 7u;
    return out;
}

static bool permitted(const struct rvemu_translation_request *r, uint64_t pte)
{
    if (r->effective_priv == RVEMU_PRIV_U && !(pte & PTE_U)) return false;
    if (r->effective_priv == RVEMU_PRIV_S && (pte & PTE_U) &&
        (r->access == RVEMU_ACCESS_FETCH || !(r->mstatus & STATUS_SUM))) return false;
    if (r->access == RVEMU_ACCESS_FETCH) return (pte & PTE_X) != 0;
    if (r->access == RVEMU_ACCESS_STORE) return (pte & PTE_W) != 0;
    return (pte & PTE_R) != 0 || ((r->mstatus & STATUS_MXR) && (pte & PTE_X));
}

static struct rvemu_translation leaf(const struct rvemu_translation_request *r,
    const struct rvemu_page_table_io *io, uint64_t pte, uint64_t pte_pa, unsigned level)
{
    unsigned low_bits = level * 9u;
    uint64_t ppn = (pte >> 10) & PPN_MASK;
    uint64_t low_mask = (UINT64_C(1) << low_bits) - 1;
    if (!permitted(r, pte) || (ppn & low_mask))
        return result(r, RVEMU_TRANSLATION_PAGE_FAULT);
    uint64_t needed = PTE_A | (r->access == RVEMU_ACCESS_STORE ? PTE_D : 0);
    if ((pte & needed) != needed) {
        if (r->ad_policy == RVEMU_AD_FAULT)
            return result(r, RVEMU_TRANSLATION_PAGE_FAULT);
        if (!io->compare_exchange64) return result(r, RVEMU_TRANSLATION_INVALID);
        int changed = io->compare_exchange64(io->ctx, pte_pa, pte, pte | needed);
        if (changed == 1) return result(r, RVEMU_TRANSLATION_RETRY);
        if (changed != 0) return result(r, RVEMU_TRANSLATION_ACCESS_FAULT);
    }
    struct rvemu_translation out = result(r, RVEMU_TRANSLATED);
    out.page_shift = 12u + low_bits;
    uint64_t offset_mask = (UINT64_C(1) << out.page_shift) - 1;
    out.pa = (ppn << 12) | (r->va & offset_mask);
    return out;
}

static bool valid(const struct rvemu_translation_request *r)
{
    return r && (r->effective_priv == RVEMU_PRIV_U ||
        r->effective_priv == RVEMU_PRIV_S || r->effective_priv == RVEMU_PRIV_M) &&
        (unsigned)r->access <= RVEMU_ACCESS_STORE &&
        (unsigned)r->ad_policy <= RVEMU_AD_UPDATE;
}

static struct rvemu_translation walk(const struct rvemu_translation_request *r,
                                     const struct rvemu_page_table_io *io)
{
    uint64_t table = (r->satp & PPN_MASK) << 12;
    for (unsigned depth = 0; depth < 3; depth++) {
        unsigned level = 2u - depth;
        uint64_t index = (r->va >> (12u + 9u * level)) & UINT64_C(511);
        uint64_t pte_pa = table + index * 8u, pte = 0;
        if (io->read64(io->ctx, pte_pa, &pte) != 0)
            return result(r, RVEMU_TRANSLATION_ACCESS_FAULT);
        if (!(pte & PTE_V) || ((pte & PTE_W) && !(pte & PTE_R)) || (pte >> 54))
            return result(r, RVEMU_TRANSLATION_PAGE_FAULT);
        if (pte & (PTE_R | PTE_X)) return leaf(r, io, pte, pte_pa, level);
        if ((pte & (PTE_U | PTE_A | PTE_D)) || level == 0)
            return result(r, RVEMU_TRANSLATION_PAGE_FAULT);
        table = ((pte >> 10) & PPN_MASK) << 12;
    }
    return result(r, RVEMU_TRANSLATION_PAGE_FAULT);
}

struct rvemu_translation rvemu_translate_sv39(
    const struct rvemu_translation_request *r, const struct rvemu_page_table_io *io)
{
    if (!valid(r)) return result(r, RVEMU_TRANSLATION_INVALID);
    unsigned mode = (unsigned)(r->satp >> 60);
    if (r->effective_priv == RVEMU_PRIV_M || mode == 0) {
        struct rvemu_translation out = result(r, RVEMU_TRANSLATED);
        out.pa = r->va;
        return out;
    }
    if (mode != 8) return result(r, RVEMU_TRANSLATION_UNSUPPORTED);
    uint64_t upper = r->va >> 39;
    if (upper != ((r->va & (UINT64_C(1) << 38)) ? (UINT64_MAX >> 39) : 0))
        return result(r, RVEMU_TRANSLATION_PAGE_FAULT);
    if (!io || !io->read64) return result(r, RVEMU_TRANSLATION_INVALID);
    return walk(r, io);
}
