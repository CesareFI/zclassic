/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: every guest-virtual memory access of the executing hart: instruction
 * fetch, load, store and the atomics. It picks the effective privilege (MPRV
 * and MPP for data), runs the bounded Sv39 walker of rvemu/translate.h when
 * satp selects Sv39 below M, splits an access that crosses a page, and sends
 * the physical access to RAM or the device callbacks. A failed access records
 * its architectural cause and the faulting virtual address in the hart and
 * returns RVEMU_STOP_OUT_OF_RANGE; nothing was written in that case.
 *
 * Choices:
 *  - A and D bits are updated in the page table (hardware update), through the
 *    walker's compare-exchange on RAM. A page table outside RAM is an access
 *    fault. A page-crossing access translates both pages before it touches
 *    memory, so the first page may gain A or D although the access then faults
 *    on the second.
 *  - With translation on, a page-crossing access must lie in RAM on both sides:
 *    a device access is never split. Instructions and atomics use RAM only.
 *  - PMP is not enforced.
 *
 * The translation cache sits above the walker: one direct-mapped table per
 * access kind, keyed by the virtual page, the effective privilege, SUM and
 * MXR, valid for one satp value. An entry is made only by a successful walk of
 * the same access kind (so A is set, and D before any store entry exists) and
 * only for a page that lies wholly in RAM; a device page is walked every time.
 * A hit yields a physical address and nothing more: the access still goes
 * through the same bounds-checked bus as a miss. sfence.vma and every satp
 * write empty it (rvemu_tlb_flush). */
#include "rvemu_internal.h"
#include "rvemu/translate.h"
#include "base/serialize_le.h"
#include <string.h>

#define VM_PAGE 4096u
#define VM_PAGE_MASK 0xfffu
#define VM_SATP_SV39 8u
#define VM_RETRY_MAX 4u
#define VM_TAG_VALID 1ull
#define VM_TAG_SUPERVISOR 2ull
#define VM_TAG_STATUS_SHIFT 16u /* SUM (bit 18) and MXR (bit 19) land on tag bits 2 and 3 */
#define VM_CAUSE_FETCH_ACCESS 1u
#define VM_CAUSE_LOAD_ACCESS 5u
#define VM_CAUSE_STORE_ACCESS 7u

struct vm_pt {
    struct rvemu_hart *h;
    struct rvemu_mem *m;
};

static enum rvemu_stop vm_fault(struct rvemu_hart *h, unsigned cause, uint64_t tval)
{
    h->fault_cause = cause;
    h->fault_tval = tval;
    h->fault_set = 1;
    return RVEMU_STOP_OUT_OF_RANGE;
}

static unsigned access_fault(enum rvemu_access acc)
{
    if (acc == RVEMU_ACCESS_FETCH) return VM_CAUSE_FETCH_ACCESS;
    return acc == RVEMU_ACCESS_LOAD ? VM_CAUSE_LOAD_ACCESS : VM_CAUSE_STORE_ACCESS;
}

/* Loads and stores run at MPP while MPRV is set; fetches never do. */
static unsigned data_priv(const struct rvemu_hart *h)
{
    uint64_t ms = h->csr.mstatus;
    if (ms & MSTATUS_MPRV) return (unsigned)((ms & MSTATUS_MPP) >> MSTATUS_MPP_SHIFT);
    return h->priv;
}

static int paging_on(const struct rvemu_hart *h, unsigned priv)
{
    return priv != RVEMU_PRIV_M && (h->csr.satp >> 60) == VM_SATP_SV39;
}

/* Page-table access for the walker: RAM only, a whole aligned PTE at a time. */
static int pt_read64(void *ctx, uint64_t pa, uint64_t *pte)
{
    const struct vm_pt *pt = ctx;
    const uint8_t *p = rvemu_ram_ptr(pt->m, pa, 8u);
    if (!p) return -1;
    *pte = zcl_read_u64_le(p);
    return 0;
}

static int pt_exchange64(void *ctx, uint64_t pa, uint64_t expected, uint64_t desired)
{
    const struct vm_pt *pt = ctx;
    uint8_t *p = rvemu_ram_ptr(pt->m, pa, 8u);
    if (!p) return -1;
    if (zcl_read_u64_le(p) != expected) return 1;
    zcl_write_u64_le(p, desired);
    rvemu_resv_note_store(pt->h, pa, 8u);
    rvemu_icache_note_store(pt->h, pa, 8u);
    return 0;
}

/* Walks the page table for one access that stays inside one page. */
static enum rvemu_stop vm_walk(struct rvemu_hart *h, struct rvemu_mem *m, uint64_t va,
                               enum rvemu_access acc, unsigned priv, uint64_t *pa)
{
    struct vm_pt pt = {h, m};
    const struct rvemu_page_table_io io = {&pt, pt_read64, pt_exchange64};
    const struct rvemu_translation_request req = {
        .va = va, .satp = h->csr.satp, .mstatus = h->csr.mstatus,
        .effective_priv = (enum rvemu_priv)priv, .access = acc, .ad_policy = RVEMU_AD_UPDATE};
    for (unsigned tries = 0; tries < VM_RETRY_MAX; tries++) {
        struct rvemu_translation t = rvemu_translate_sv39(&req, &io);
        if (t.status == RVEMU_TRANSLATED) {
            *pa = t.pa;
            return RVEMU_STOP_NONE;
        }
        if (t.status == RVEMU_TRANSLATION_PAGE_FAULT || t.status == RVEMU_TRANSLATION_ACCESS_FAULT)
            return vm_fault(h, t.cause, t.tval);
        if (t.status != RVEMU_TRANSLATION_RETRY) break;
    }
    return vm_fault(h, access_fault(acc), va);
}

void rvemu_tlb_flush(struct rvemu_hart *hart)
{
    if (!hart) return;
    memset(hart->tlb, 0, sizeof(hart->tlb));
    hart->tlb_satp = hart->csr.satp;
    rvemu_icache_flush(hart);
}

void rvemu_invalidate_derived(struct rvemu_hart *hart)
{
    rvemu_tlb_flush(hart);
}

/* The cache tag of va: the page, a non-zero mark, and everything besides the
 * page table that decides the outcome of a walk (S or U, SUM, MXR). */
static uint64_t tlb_tag(const struct rvemu_hart *h, uint64_t va, unsigned priv)
{
    uint64_t ctx = (h->csr.mstatus & (MSTATUS_SUM | MSTATUS_MXR)) >> VM_TAG_STATUS_SHIFT;
    if (priv == RVEMU_PRIV_S) ctx |= VM_TAG_SUPERVISOR;
    return (va & ~(uint64_t)VM_PAGE_MASK) | ctx | VM_TAG_VALID;
}

/* The physical address of va for one access that stays inside one page, on a
 * cache miss: a walk whose result is cached when its page is RAM. */
static enum rvemu_stop vm_translate_miss(struct rvemu_hart *h, struct rvemu_mem *m, uint64_t va,
                                         enum rvemu_access acc, unsigned priv, uint64_t *pa)
{
    if (h->tlb_satp != h->csr.satp) rvemu_tlb_flush(h); /* satp changed behind the CSR file */
    struct rvemu_tlb_entry *e = &h->tlb[acc][(va >> 12) & (RVEMU_TLB_ENTRIES - 1u)];
    enum rvemu_stop s = vm_walk(h, m, va, acc, priv, pa);
    if (s != RVEMU_STOP_NONE) return s;
    uint64_t page = *pa & ~(uint64_t)VM_PAGE_MASK;
    if (rvemu_mem_contains(m, page, VM_PAGE)) {
        e->tag = tlb_tag(h, va, priv);
        e->page = page;
    }
    return RVEMU_STOP_NONE;
}

/* The physical address of va for one access that stays inside one page: from
 * the cache, else from vm_translate_miss. */
static inline enum rvemu_stop vm_translate(struct rvemu_hart *h, struct rvemu_mem *m, uint64_t va,
                                           enum rvemu_access acc, unsigned priv, uint64_t *pa)
{
    if (!paging_on(h, priv)) {
        *pa = va;
        return RVEMU_STOP_NONE;
    }
    if (h->tlb_satp == h->csr.satp) {
        const struct rvemu_tlb_entry *e = &h->tlb[acc][(va >> 12) & (RVEMU_TLB_ENTRIES - 1u)];
        if (e->tag == tlb_tag(h, va, priv)) {
            *pa = e->page | (va & VM_PAGE_MASK);
            return RVEMU_STOP_NONE;
        }
    }
    return vm_translate_miss(h, m, va, acc, priv, pa);
}

/* 1 when [va, va + n) leaves the page of va while translation is on. */
static int crosses_page(const struct rvemu_hart *h, unsigned priv, uint64_t va, unsigned n)
{
    return (va & VM_PAGE_MASK) + n > VM_PAGE && paging_on(h, priv);
}

/* Both halves of a page-crossing access as RAM pointers; head is the byte
 * count on the first page. Each page is translated from its own first byte,
 * which is the tval when that page faults. */
static enum rvemu_stop vm_span(struct rvemu_hart *h, struct rvemu_mem *m, uint64_t va, unsigned n,
                               enum rvemu_access acc, uint8_t *part[2], unsigned *head)
{
    unsigned priv = data_priv(h);
    uint64_t pa[2] = {0, 0};
    *head = VM_PAGE - (unsigned)(va & VM_PAGE_MASK);
    enum rvemu_stop s = vm_translate(h, m, va, acc, priv, &pa[0]);
    if (s == RVEMU_STOP_NONE) s = vm_translate(h, m, va + *head, acc, priv, &pa[1]);
    if (s != RVEMU_STOP_NONE) return s;
    part[0] = rvemu_ram_ptr(m, pa[0], *head);
    part[1] = rvemu_ram_ptr(m, pa[1], n - *head);
    if (!part[0]) return vm_fault(h, access_fault(acc), va);
    if (!part[1]) return vm_fault(h, access_fault(acc), va + *head);
    return RVEMU_STOP_NONE;
}

static enum rvemu_stop load_span(struct rvemu_hart *h, struct rvemu_mem *m, uint64_t va,
                                 unsigned n, uint64_t *out)
{
    uint8_t *part[2] = {NULL, NULL}, wide[8] = {0, 0, 0, 0, 0, 0, 0, 0};
    unsigned head = 0;
    enum rvemu_stop s = vm_span(h, m, va, n, RVEMU_ACCESS_LOAD, part, &head);
    if (s != RVEMU_STOP_NONE) return s;
    memcpy(wide, part[0], head);
    memcpy(wide + head, part[1], n - head);
    *out = zcl_read_u64_le(wide);
    return RVEMU_STOP_NONE;
}

static enum rvemu_stop store_span(struct rvemu_hart *h, struct rvemu_mem *m, uint64_t va,
                                  unsigned n, uint64_t val)
{
    uint8_t *part[2] = {NULL, NULL}, wide[8];
    unsigned head = 0;
    enum rvemu_stop s = vm_span(h, m, va, n, RVEMU_ACCESS_STORE, part, &head);
    if (s != RVEMU_STOP_NONE) return s;
    zcl_write_u64_le(wide, val);
    memcpy(part[0], wide, head);
    memcpy(part[1], wide + head, n - head);
    rvemu_resv_note_store(h, (uint64_t)(part[0] - m->bytes) + m->base, head);
    rvemu_resv_note_store(h, (uint64_t)(part[1] - m->bytes) + m->base, n - head);
    rvemu_icache_note_store(h, (uint64_t)(part[0] - m->bytes) + m->base, head);
    rvemu_icache_note_store(h, (uint64_t)(part[1] - m->bytes) + m->base, n - head);
    return RVEMU_STOP_NONE;
}

enum rvemu_stop rvemu_vm_load(struct rvemu_hart *h, struct rvemu_mem *m, uint64_t va, unsigned n,
                              uint64_t *out)
{
    unsigned priv = data_priv(h);
    uint64_t pa = 0;
    if (crosses_page(h, priv, va, n)) return load_span(h, m, va, n, out);
    enum rvemu_stop s = vm_translate(h, m, va, RVEMU_ACCESS_LOAD, priv, &pa);
    if (s != RVEMU_STOP_NONE) return s;
    if (rvemu_ram_load(m, pa, n, out) == 0) return RVEMU_STOP_NONE;
    if (rvemu_mem_load(m, pa, n, out) != 0) return vm_fault(h, VM_CAUSE_LOAD_ACCESS, va);
    return RVEMU_STOP_NONE;
}

enum rvemu_stop rvemu_vm_store(struct rvemu_hart *h, struct rvemu_mem *m, uint64_t va, unsigned n,
                               uint64_t val)
{
    unsigned priv = data_priv(h);
    uint64_t pa = 0;
    if (crosses_page(h, priv, va, n)) return store_span(h, m, va, n, val);
    enum rvemu_stop s = vm_translate(h, m, va, RVEMU_ACCESS_STORE, priv, &pa);
    if (s != RVEMU_STOP_NONE) return s;
    int in_ram = rvemu_ram_store(m, pa, n, val) == 0;
    if (!in_ram && rvemu_mem_store(m, pa, n, val) != 0)
        return vm_fault(h, VM_CAUSE_STORE_ACCESS, va);
    if (h->resv_bytes != 0) rvemu_resv_note_store(h, pa, n);
    if (in_ram) rvemu_icache_note_store(h, pa, n);
    return RVEMU_STOP_NONE;
}

enum rvemu_stop rvemu_vm_atomic(struct rvemu_hart *h, struct rvemu_mem *m, uint64_t va, unsigned n,
                                int store, uint64_t *pa)
{
    enum rvemu_access acc = store ? RVEMU_ACCESS_STORE : RVEMU_ACCESS_LOAD;
    enum rvemu_stop s = vm_translate(h, m, va, acc, data_priv(h), pa);
    if (s != RVEMU_STOP_NONE) return s;
    if (!rvemu_mem_contains(m, *pa, n)) return vm_fault(h, access_fault(acc), va);
    return RVEMU_STOP_NONE;
}

/* One 16-bit instruction parcel at the even address va, from RAM. */
static enum rvemu_stop fetch_parcel(struct rvemu_hart *h, struct rvemu_mem *m, uint64_t va,
                                    uint64_t pa, uint32_t *out)
{
    const uint8_t *p = rvemu_ram_ptr(m, pa, 2u);
    if (!p) return vm_fault(h, VM_CAUSE_FETCH_ACCESS, va);
    *out = zcl_read_u16_le(p);
    return RVEMU_STOP_NONE;
}

enum rvemu_stop rvemu_vm_fetch(struct rvemu_hart *h, struct rvemu_mem *m, uint64_t pc,
                               uint32_t *raw)
{
    uint64_t pa = 0, first = 0;
    uint32_t lo = 0, hi = 0;
    int same_page;
    enum rvemu_stop s;
    if (rvemu_icache_lookup(h, m, pc, raw) != 0) return RVEMU_STOP_NONE;
    s = vm_translate(h, m, pc, RVEMU_ACCESS_FETCH, h->priv, &pa);
    if (s == RVEMU_STOP_NONE) s = fetch_parcel(h, m, pc, pa, &lo);
    if (s != RVEMU_STOP_NONE) return s;
    *raw = lo;
    if ((lo & 3u) != 3u) {
        rvemu_icache_fill(h, pc, pa, lo, 2u);
        return RVEMU_STOP_NONE;
    }
    first = pa;
    same_page = (pc & VM_PAGE_MASK) != VM_PAGE - 2u;
    pa += 2u;
    if (!same_page)
        s = vm_translate(h, m, pc + 2u, RVEMU_ACCESS_FETCH, h->priv, &pa);
    if (s == RVEMU_STOP_NONE) s = fetch_parcel(h, m, pc + 2u, pa, &hi);
    if (s != RVEMU_STOP_NONE) return s;
    *raw = lo | (hi << 16);
    rvemu_icache_fill(h, pc, first, *raw, same_page ? 4u : 0u);
    return RVEMU_STOP_NONE;
}
