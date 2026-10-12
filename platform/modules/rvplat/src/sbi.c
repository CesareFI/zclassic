/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: pure SBI call handler written from the RISC-V SBI specification
 * 2.0. The legacy console and probe behaviour is what FreeBSD's
 * sys/riscv/riscv/sbi.c requires: sbi_init() asserts that probing legacy
 * putchar (1) and getchar (2) reports present, and sbi.h reads a legacy
 * result from the error register (a0). */
#include "rvplat/sbi.h"

#include <stdbool.h>
#include <stddef.h>

typedef struct rvplat_sbi_ret (*sbi_handler)(struct rvplat_sbi *sbi,
                                             uint64_t eid, uint64_t fid,
                                             const uint64_t *args);

static struct rvplat_sbi_ret ret_err(int64_t error)
{
    struct rvplat_sbi_ret r = {0};
    r.error = error;
    return r;
}

static struct rvplat_sbi_ret ret_val(uint64_t value)
{
    struct rvplat_sbi_ret r = {0};
    r.value = value;
    return r;
}

static struct rvplat_sbi_ret ret_action(enum rvplat_sbi_action action,
                                        uint64_t arg0, uint64_t arg1)
{
    struct rvplat_sbi_ret r = {0};
    r.action = action;
    r.action_args[0] = arg0;
    r.action_args[1] = arg1;
    return r;
}

/* Hart masks (spec 3.x): hart_mask_base == all-ones selects every hart and
 * ignores the mask; otherwise bit i names hart base+i. Only hart 0 exists.
 * An empty selected set succeeds with no action. */
enum hart_sel { HART_SEL_EMPTY, HART_SEL_HART0, HART_SEL_INVALID };

static enum hart_sel hart_select(uint64_t mask, uint64_t base)
{
    if (base == UINT64_MAX)
        return HART_SEL_HART0;
    if (mask == 0u)
        return HART_SEL_EMPTY;
    return (base == 0u && mask == 1u) ? HART_SEL_HART0 : HART_SEL_INVALID;
}

static struct rvplat_sbi_ret h_base(struct rvplat_sbi *sbi, uint64_t eid,
                                    uint64_t fid, const uint64_t *args);

/* Every extension answered with a handler; probe reads the same table. */
struct sbi_ext {
    uint64_t eid;
    sbi_handler handler;
};

static struct rvplat_sbi_ret h_time(struct rvplat_sbi *sbi, uint64_t eid,
                                    uint64_t fid, const uint64_t *args)
{
    (void)sbi; (void)eid;
    if (fid != 0u)
        return ret_err(RVPLAT_SBI_ERR_NOT_SUPPORTED);
    return ret_action(RVPLAT_SBI_ACTION_TIMER_SET, args[0], 0u);
}

static struct rvplat_sbi_ret h_ipi(struct rvplat_sbi *sbi, uint64_t eid,
                                   uint64_t fid, const uint64_t *args)
{
    (void)sbi; (void)eid;
    if (fid != 0u)
        return ret_err(RVPLAT_SBI_ERR_NOT_SUPPORTED);
    switch (hart_select(args[0], args[1])) {
    case HART_SEL_EMPTY: return ret_err(RVPLAT_SBI_SUCCESS);
    case HART_SEL_HART0: return ret_action(RVPLAT_SBI_ACTION_IPI, 0u, 0u);
    default: return ret_err(RVPLAT_SBI_ERR_INVALID_PARAM);
    }
}

/* RFENCE fids 0..2 (fence.i, sfence.vma, sfence.vma with ASID) are the ones
 * FreeBSD issues; the hfence family needs the H extension. */
static struct rvplat_sbi_ret h_rfence(struct rvplat_sbi *sbi, uint64_t eid,
                                      uint64_t fid, const uint64_t *args)
{
    (void)sbi; (void)eid;
    if (fid > 2u)
        return ret_err(RVPLAT_SBI_ERR_NOT_SUPPORTED);
    switch (hart_select(args[0], args[1])) {
    case HART_SEL_EMPTY: return ret_err(RVPLAT_SBI_SUCCESS);
    case HART_SEL_HART0: return ret_action(RVPLAT_SBI_ACTION_RFENCE, fid, 0u);
    default: return ret_err(RVPLAT_SBI_ERR_INVALID_PARAM);
    }
}

static struct rvplat_sbi_ret hsm_start(struct rvplat_sbi *sbi, uint64_t hart)
{
    if (hart != 0u)
        return ret_err(RVPLAT_SBI_ERR_INVALID_PARAM);
    if (sbi->hart0 == RVPLAT_SBI_HART_STARTED)
        return ret_err(RVPLAT_SBI_ERR_ALREADY_AVAILABLE);
    sbi->hart0 = RVPLAT_SBI_HART_STARTED;
    return ret_err(RVPLAT_SBI_SUCCESS);
}

/* Stopping the only hart leaves nothing to run, so the machine halts. */
static struct rvplat_sbi_ret hsm_stop(struct rvplat_sbi *sbi)
{
    if (sbi->hart0 == RVPLAT_SBI_HART_STOPPED)
        return ret_err(RVPLAT_SBI_ERR_ALREADY_STOPPED);
    sbi->hart0 = RVPLAT_SBI_HART_STOPPED;
    return ret_action(RVPLAT_SBI_ACTION_SHUTDOWN, RVPLAT_SBI_RESET_SHUTDOWN, 0u);
}

static struct rvplat_sbi_ret h_hsm(struct rvplat_sbi *sbi, uint64_t eid,
                                   uint64_t fid, const uint64_t *args)
{
    (void)eid;
    switch (fid) {
    case 0: return hsm_start(sbi, args[0]);
    case 1: return hsm_stop(sbi);
    case 2:
        if (args[0] != 0u)
            return ret_err(RVPLAT_SBI_ERR_INVALID_PARAM);
        return ret_val((uint64_t)sbi->hart0);
    default: return ret_err(RVPLAT_SBI_ERR_NOT_SUPPORTED);
    }
}

/* system_reset(type, reason): both arguments are 32-bit in the spec. */
static struct rvplat_sbi_ret h_srst(struct rvplat_sbi *sbi, uint64_t eid,
                                    uint64_t fid, const uint64_t *args)
{
    (void)sbi; (void)eid;
    if (fid != 0u)
        return ret_err(RVPLAT_SBI_ERR_NOT_SUPPORTED);
    uint32_t type = (uint32_t)args[0];
    uint32_t reason = (uint32_t)args[1];
    if (type == RVPLAT_SBI_RESET_SHUTDOWN)
        return ret_action(RVPLAT_SBI_ACTION_SHUTDOWN, type, reason);
    if (type == RVPLAT_SBI_RESET_COLD_REBOOT ||
        type == RVPLAT_SBI_RESET_WARM_REBOOT)
        return ret_action(RVPLAT_SBI_ACTION_REBOOT, type, reason);
    return ret_err(RVPLAT_SBI_ERR_INVALID_PARAM);
}

/* Output is reported only as an action (see sbi.h); no callback is invoked,
 * so a machine that acts on actions emits the byte exactly once. */
static struct rvplat_sbi_ret legacy_putchar(uint64_t ch)
{
    return ret_action(RVPLAT_SBI_ACTION_CONSOLE_PUT, ch & 0xFFu, 0u);
}

/* Legacy getchar returns the byte, or -1 when none is waiting, in a0. */
static struct rvplat_sbi_ret legacy_getchar(struct rvplat_sbi *sbi)
{
    int c = sbi->getchar != NULL ? sbi->getchar(sbi->ctx) : -1;
    return ret_err(c < 0 ? -1 : (int64_t)(c & 0xFF));
}

/* Legacy calls ignore fid and return their result in the error slot. */
static struct rvplat_sbi_ret h_legacy(struct rvplat_sbi *sbi, uint64_t eid,
                                      uint64_t fid, const uint64_t *args)
{
    (void)fid;
    switch (eid) {
    case RVPLAT_SBI_LEGACY_SET_TIMER:
        return ret_action(RVPLAT_SBI_ACTION_TIMER_SET, args[0], 0u);
    case RVPLAT_SBI_LEGACY_PUTCHAR: return legacy_putchar(args[0]);
    case RVPLAT_SBI_LEGACY_GETCHAR: return legacy_getchar(sbi);
    case RVPLAT_SBI_LEGACY_CLEAR_IPI:
        return ret_action(RVPLAT_SBI_ACTION_CLEAR_IPI, 0u, 0u);
    case RVPLAT_SBI_LEGACY_SEND_IPI:
        return ret_action(RVPLAT_SBI_ACTION_IPI, 0u, 0u);
    case RVPLAT_SBI_LEGACY_FENCE_I:
        return ret_action(RVPLAT_SBI_ACTION_RFENCE, 0u, 0u);
    case RVPLAT_SBI_LEGACY_SFENCE_VMA:
        return ret_action(RVPLAT_SBI_ACTION_RFENCE, 1u, 0u);
    case RVPLAT_SBI_LEGACY_SFENCE_ASID:
        return ret_action(RVPLAT_SBI_ACTION_RFENCE, 2u, 0u);
    case RVPLAT_SBI_LEGACY_SHUTDOWN:
        return ret_action(RVPLAT_SBI_ACTION_SHUTDOWN, RVPLAT_SBI_RESET_SHUTDOWN, 0u);
    default: return ret_err(RVPLAT_SBI_ERR_NOT_SUPPORTED);
    }
}

static const struct sbi_ext k_exts[] = {
    {RVPLAT_SBI_EXT_BASE, h_base},
    {RVPLAT_SBI_EXT_TIME, h_time},
    {RVPLAT_SBI_EXT_IPI, h_ipi},
    {RVPLAT_SBI_EXT_RFNC, h_rfence},
    {RVPLAT_SBI_EXT_HSM, h_hsm},
    {RVPLAT_SBI_EXT_SRST, h_srst},
    {RVPLAT_SBI_LEGACY_SET_TIMER, h_legacy},
    {RVPLAT_SBI_LEGACY_PUTCHAR, h_legacy},
    {RVPLAT_SBI_LEGACY_GETCHAR, h_legacy},
    {RVPLAT_SBI_LEGACY_CLEAR_IPI, h_legacy},
    {RVPLAT_SBI_LEGACY_SEND_IPI, h_legacy},
    {RVPLAT_SBI_LEGACY_FENCE_I, h_legacy},
    {RVPLAT_SBI_LEGACY_SFENCE_VMA, h_legacy},
    {RVPLAT_SBI_LEGACY_SFENCE_ASID, h_legacy},
    {RVPLAT_SBI_LEGACY_SHUTDOWN, h_legacy},
};

static const struct sbi_ext *find_ext(uint64_t eid)
{
    for (size_t i = 0; i < sizeof(k_exts) / sizeof(k_exts[0]); i++)
        if (k_exts[i].eid == eid)
            return &k_exts[i];
    return NULL;
}

/* Base extension, spec chapter 4. probe_extension returns 1 when present. */
static struct rvplat_sbi_ret h_base(struct rvplat_sbi *sbi, uint64_t eid,
                                    uint64_t fid, const uint64_t *args)
{
    (void)eid;
    switch (fid) {
    case 0: return ret_val(RVPLAT_SBI_SPEC_VERSION);
    case 1: return ret_val(RVPLAT_SBI_IMPL_ID);
    case 2: return ret_val(RVPLAT_SBI_IMPL_VERSION);
    case 3: return ret_val(find_ext(args[0]) != NULL ? 1u : 0u);
    case 4: return ret_val(sbi->mvendorid);
    case 5: return ret_val(sbi->marchid);
    case 6: return ret_val(sbi->mimpid);
    default: return ret_err(RVPLAT_SBI_ERR_NOT_SUPPORTED);
    }
}

void rvplat_sbi_init(struct rvplat_sbi *sbi)
{
    *sbi = (struct rvplat_sbi){0};
    sbi->hart0 = RVPLAT_SBI_HART_STARTED;
}

struct rvplat_sbi_ret rvplat_sbi_call(struct rvplat_sbi *sbi, uint64_t eid,
                                      uint64_t fid, const uint64_t args[6])
{
    const struct sbi_ext *ext = find_ext(eid);
    if (ext == NULL)
        return ret_err(RVPLAT_SBI_ERR_NOT_SUPPORTED);
    return ext->handler(sbi, eid, fid, args);
}
