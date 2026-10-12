/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0.
 * Purpose: bounded Sv39 page-table walk for the RISC-V hart. */
#ifndef ZCL_RVEMU_TRANSLATE_H
#define ZCL_RVEMU_TRANSLATE_H
#include <stdint.h>
#include "rvemu/rvemu.h"

/* Base Sv39, little-endian page tables, no Svnapot or Svpbmt. No cache,
 * allocation or host pointers. Caller supplies effective privilege (including
 * MPRV for data accesses) and performs final physical access/PMP/PMA checks.
 * Callbacks must check physical PTE access bounds and PMP/PMA as S-mode.
 * One call performs at most three read64 calls and one compare_exchange64.
 * A competing PTE change returns RETRY; caller retries under its own budget.
 * Callbacks must not reenter this operation or mutate the request. */
enum rvemu_access { RVEMU_ACCESS_FETCH, RVEMU_ACCESS_LOAD, RVEMU_ACCESS_STORE };
enum rvemu_ad_policy { RVEMU_AD_FAULT, RVEMU_AD_UPDATE };
enum rvemu_translation_status {
    RVEMU_TRANSLATED, RVEMU_TRANSLATION_PAGE_FAULT,
    RVEMU_TRANSLATION_ACCESS_FAULT, RVEMU_TRANSLATION_RETRY,
    RVEMU_TRANSLATION_UNSUPPORTED, RVEMU_TRANSLATION_INVALID
};
struct rvemu_translation_request {
    uint64_t va, satp, mstatus;
    enum rvemu_priv effective_priv;
    enum rvemu_access access;
    enum rvemu_ad_policy ad_policy;
};
struct rvemu_page_table_io {
    void *ctx;
    /* 0 success, nonzero denied/inaccessible; returns one atomic full LE PTE. */
    int (*read64)(void *ctx, uint64_t pa, uint64_t *pte);
    /* Atomic entire-PTE comparison and update, ordered before guest access.
     * 0 exchanged, 1 comparison mismatch, other value access failure. */
    int (*compare_exchange64)(void *ctx, uint64_t pa, uint64_t expected,
                             uint64_t desired);
};
struct rvemu_translation {
    enum rvemu_translation_status status;
    uint64_t pa, tval;
    unsigned cause; /* architectural fault cause, otherwise zero */
    unsigned page_shift; /* 12,21,30 for Sv39; zero for identity mapping */
};
struct rvemu_translation rvemu_translate_sv39(
    const struct rvemu_translation_request *request,
    const struct rvemu_page_table_io *io);
#endif
