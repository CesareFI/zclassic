/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: RISC-V PLIC model (spec 1.0) for hart 0: priorities, pending,
 * per-context enables, threshold, claim/complete, level-triggered gateways. */
#ifndef RVPLAT_PLIC_H
#define RVPLAT_PLIC_H

#include <stdbool.h>
#include <stdint.h>

/* Memory map, RISC-V PLIC spec 1.0 section "Memory Map". */
#define RVPLAT_PLIC_PRIORITY_BASE 0x000000u
#define RVPLAT_PLIC_PENDING_BASE  0x001000u
#define RVPLAT_PLIC_ENABLE_BASE   0x002000u
#define RVPLAT_PLIC_ENABLE_STRIDE 0x80u
#define RVPLAT_PLIC_CONTEXT_BASE  0x200000u
#define RVPLAT_PLIC_CONTEXT_STRIDE 0x1000u
#define RVPLAT_PLIC_THRESHOLD_OFF 0x0u
#define RVPLAT_PLIC_CLAIM_OFF     0x4u
#define RVPLAT_PLIC_SIZE          0x4000000u

#define RVPLAT_PLIC_MAX_SOURCES 64u
#define RVPLAT_PLIC_WORDS 3u /* ids 0..64 -> 65 bits */
#define RVPLAT_PLIC_MAX_PRIORITY 7u /* three implemented priority bits */

/* Context numbering follows the SiFive/QEMU virt layout for one hart:
 * context 0 is the M-mode external line, context 1 the S-mode one. A device
 * tree that lists only the S entry in interrupts-extended makes the kernel
 * index it as context 0, so such a tree must list both entries. */
enum rvplat_plic_context {
    RVPLAT_PLIC_CTX_M = 0,
    RVPLAT_PLIC_CTX_S = 1,
    RVPLAT_PLIC_CONTEXTS = 2,
};

struct rvplat_plic {
    uint32_t nsources;
    uint32_t priority[RVPLAT_PLIC_MAX_SOURCES + 1u];
    uint32_t level[RVPLAT_PLIC_WORDS];
    uint32_t pending[RVPLAT_PLIC_WORDS];
    uint32_t inflight[RVPLAT_PLIC_WORDS];
    uint32_t enable[RVPLAT_PLIC_CONTEXTS][RVPLAT_PLIC_WORDS];
    uint32_t threshold[RVPLAT_PLIC_CONTEXTS];
};

/* nsources is clamped to 1..RVPLAT_PLIC_MAX_SOURCES. */
void rvplat_plic_init(struct rvplat_plic *plic, uint32_t nsources);

/* Drive source irq (1..nsources) to level. Out-of-range ids are ignored.
 * The gateway raises one request per assertion and holds the next until the
 * source is completed (PLIC spec 1.0 "Interrupt Gateways"). */
void rvplat_plic_set_source(struct rvplat_plic *plic, uint32_t irq,
                            bool level);

/* True when the external-interrupt line of the context (meip for M, seip for
 * S) is asserted: the highest-priority enabled pending source has priority
 * above the context threshold. The threshold gates only this notification. */
bool rvplat_plic_context_pending(const struct rvplat_plic *plic,
                                 uint32_t ctx);

/* Claim returns the enabled pending id with the highest nonzero priority
 * (lowest id on ties) and clears its pending bit, or 0 when none. It is
 * independent of the context threshold (PLIC 1.0, Interrupt Claim Process).
 * Complete ignores ids that are not
 * enabled for the context, then re-arms a still-high level source. */
uint32_t rvplat_plic_claim(struct rvplat_plic *plic, uint32_t ctx);
void rvplat_plic_complete(struct rvplat_plic *plic, uint32_t ctx, uint32_t id);

/* 32-bit register access by offset from the PLIC base. Unmapped, unaligned
 * and out-of-range reads return 0; such writes are ignored. Reading a claim
 * register claims, writing it completes. */
uint32_t rvplat_plic_read(struct rvplat_plic *plic, uint64_t offset);
void rvplat_plic_write(struct rvplat_plic *plic, uint64_t offset,
                       uint32_t value);

#endif
