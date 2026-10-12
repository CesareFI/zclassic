/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: pure RISC-V SBI 2.0 call handler for a single-hart machine, with
 * the legacy console calls FreeBSD's sbi.c requires. */
#ifndef RVPLAT_SBI_H
#define RVPLAT_SBI_H

#include <stdint.h>

/* Extension ids, RISC-V SBI spec 2.0 chapters 4-12 (ASCII names). */
#define RVPLAT_SBI_EXT_BASE  0x10ull
#define RVPLAT_SBI_EXT_TIME  0x54494D45ull
#define RVPLAT_SBI_EXT_IPI   0x735049ull
#define RVPLAT_SBI_EXT_RFNC  0x52464E43ull
#define RVPLAT_SBI_EXT_HSM   0x48534Dull
#define RVPLAT_SBI_EXT_SRST  0x53525354ull
/* Legacy extensions 0x00..0x08 (spec chapter 5). */
#define RVPLAT_SBI_LEGACY_SET_TIMER   0x00ull
#define RVPLAT_SBI_LEGACY_PUTCHAR     0x01ull
#define RVPLAT_SBI_LEGACY_GETCHAR     0x02ull
#define RVPLAT_SBI_LEGACY_CLEAR_IPI   0x03ull
#define RVPLAT_SBI_LEGACY_SEND_IPI    0x04ull
#define RVPLAT_SBI_LEGACY_FENCE_I     0x05ull
#define RVPLAT_SBI_LEGACY_SFENCE_VMA  0x06ull
#define RVPLAT_SBI_LEGACY_SFENCE_ASID 0x07ull
#define RVPLAT_SBI_LEGACY_SHUTDOWN    0x08ull

/* Error codes, spec table "Standard SBI Errors". */
enum rvplat_sbi_error {
    RVPLAT_SBI_SUCCESS = 0,
    RVPLAT_SBI_ERR_FAILED = -1,
    RVPLAT_SBI_ERR_NOT_SUPPORTED = -2,
    RVPLAT_SBI_ERR_INVALID_PARAM = -3,
    RVPLAT_SBI_ERR_DENIED = -4,
    RVPLAT_SBI_ERR_INVALID_ADDRESS = -5,
    RVPLAT_SBI_ERR_ALREADY_AVAILABLE = -6,
    RVPLAT_SBI_ERR_ALREADY_STARTED = -7,
    RVPLAT_SBI_ERR_ALREADY_STOPPED = -8,
};

/* HSM hart states (spec chapter 9). */
enum rvplat_sbi_hart_state {
    RVPLAT_SBI_HART_STARTED = 0,
    RVPLAT_SBI_HART_STOPPED = 1,
};

/* SRST reset types (spec chapter 10). */
enum rvplat_sbi_reset_type {
    RVPLAT_SBI_RESET_SHUTDOWN = 0,
    RVPLAT_SBI_RESET_COLD_REBOOT = 1,
    RVPLAT_SBI_RESET_WARM_REBOOT = 2,
};

#define RVPLAT_SBI_SPEC_VERSION 0x01000000ull /* major 1, minor 0 */
#define RVPLAT_SBI_IMPL_ID 0x5A323300ull
#define RVPLAT_SBI_IMPL_VERSION 1ull

/* What the machine must do after the call returns. */
enum rvplat_sbi_action {
    RVPLAT_SBI_ACTION_NONE = 0,
    RVPLAT_SBI_ACTION_SHUTDOWN,
    RVPLAT_SBI_ACTION_REBOOT,
    RVPLAT_SBI_ACTION_TIMER_SET,  /* action_args[0] = new compare value */
    RVPLAT_SBI_ACTION_CONSOLE_PUT, /* action_args[0] = byte written */
    RVPLAT_SBI_ACTION_IPI,
    RVPLAT_SBI_ACTION_RFENCE,     /* action_args[0] = fid */
    RVPLAT_SBI_ACTION_CLEAR_IPI,  /* legacy clear_ipi: clear pending sip.SSIP */
};

/* Rule: every effect on the machine (timer, shutdown, reboot, console output,
 * IPI, fence, clear-IPI) is reported only as a returned action, which the
 * machine performs once. The call handler invokes no output callback. The one
 * callback is getchar, because its result is the call's return value. An IPI
 * or fence whose selected hart set is empty succeeds with RVPLAT_SBI_ACTION_NONE. */

/* a0 = error, a1 = value. Legacy calls (eid 0x00..0x08) return their single
 * result in `error` (a0) and leave `value` 0, as FreeBSD's sbi.h reads it.
 * SHUTDOWN/REBOOT carry the reset type and reason in action_args[0..1]. */
struct rvplat_sbi_ret {
    int64_t error;
    uint64_t value;
    enum rvplat_sbi_action action;
    uint64_t action_args[2];
};

struct rvplat_sbi {
    uint64_t mvendorid;
    uint64_t marchid;
    uint64_t mimpid;
    enum rvplat_sbi_hart_state hart0;
    /* Caller input callback; may be NULL. getchar returns the next
     * input byte (0..255) or a negative value when none is waiting. */
    int (*getchar)(void *ctx);
    void *ctx;
};

void rvplat_sbi_init(struct rvplat_sbi *sbi);

/* Handle one ecall: eid = a7, fid = a6, args = a0..a5. */
struct rvplat_sbi_ret rvplat_sbi_call(struct rvplat_sbi *sbi, uint64_t eid,
                                      uint64_t fid, const uint64_t args[6]);

#endif
