/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: standalone proofs for the RISC-V platform device models (PLIC,
 * timer, SBI call handler, ns16550 UART) with no CPU core. */
#include "test/test_core.h"

#include "rvplat/plic.h"
#include "rvplat/sbi.h"
#include "rvplat/timer.h"
#include "rvplat/uart.h"

#include <stdint.h>
#include <string.h>

#define CTX_M RVPLAT_PLIC_CTX_M
#define CTX_S RVPLAT_PLIC_CTX_S

static void plic_enable(struct rvplat_plic *p, uint32_t ctx, uint32_t id)
{
    uint64_t off = RVPLAT_PLIC_ENABLE_BASE +
                   (uint64_t)ctx * RVPLAT_PLIC_ENABLE_STRIDE + (id / 32u) * 4u;
    rvplat_plic_write(p, off, rvplat_plic_read(p, off) | (1u << (id % 32u)));
}

static void plic_prio(struct rvplat_plic *p, uint32_t id, uint32_t prio)
{
    rvplat_plic_write(p, RVPLAT_PLIC_PRIORITY_BASE + id * 4u, prio);
}

static uint64_t ctx_reg(uint32_t ctx, uint64_t off)
{
    return RVPLAT_PLIC_CONTEXT_BASE + (uint64_t)ctx * RVPLAT_PLIC_CONTEXT_STRIDE + off;
}

static int t_plic_order(void)
{
    int failures = 0;
    TEST("rvplat plic: priority ordering, lowest id wins ties") {
        struct rvplat_plic p;
        rvplat_plic_init(&p, 8);
        for (uint32_t id = 1; id <= 4; id++) plic_enable(&p, CTX_S, id);
        plic_prio(&p, 1, 2);
        plic_prio(&p, 2, 5);
        plic_prio(&p, 3, 5);
        plic_prio(&p, 4, 1);
        for (uint32_t id = 1; id <= 4; id++) rvplat_plic_set_source(&p, id, true);
        ASSERT(rvplat_plic_context_pending(&p, CTX_S));
        ASSERT_EQ(rvplat_plic_claim(&p, CTX_S), 2u); /* tie 2 vs 3 -> 2 */
        ASSERT_EQ(rvplat_plic_claim(&p, CTX_S), 3u);
        ASSERT_EQ(rvplat_plic_claim(&p, CTX_S), 1u);
        ASSERT_EQ(rvplat_plic_claim(&p, CTX_S), 4u);
        ASSERT_EQ(rvplat_plic_claim(&p, CTX_S), 0u);
        ASSERT(!rvplat_plic_context_pending(&p, CTX_S));
        PASS();
    } _test_next:;
    return failures;
}

static int t_plic_threshold(void)
{
    int failures = 0;
    TEST("rvplat plic: threshold masks priority at or below it") {
        struct rvplat_plic p;
        rvplat_plic_init(&p, 8);
        plic_enable(&p, CTX_S, 1);
        plic_prio(&p, 1, 3);
        rvplat_plic_set_source(&p, 1, true);
        rvplat_plic_write(&p, ctx_reg(CTX_S, RVPLAT_PLIC_THRESHOLD_OFF), 2);
        ASSERT(rvplat_plic_context_pending(&p, CTX_S));
        rvplat_plic_write(&p, ctx_reg(CTX_S, RVPLAT_PLIC_THRESHOLD_OFF), 3);
        ASSERT(!rvplat_plic_context_pending(&p, CTX_S)); /* equal masks */
        rvplat_plic_write(&p, ctx_reg(CTX_S, RVPLAT_PLIC_THRESHOLD_OFF), 4);
        ASSERT(!rvplat_plic_context_pending(&p, CTX_S));
        rvplat_plic_write(&p, ctx_reg(CTX_S, RVPLAT_PLIC_THRESHOLD_OFF), 0);
        ASSERT(rvplat_plic_context_pending(&p, CTX_S));
        /* priority 0 never interrupts, even over threshold 0 */
        plic_prio(&p, 1, 0);
        ASSERT(!rvplat_plic_context_pending(&p, CTX_S));
        PASS();
    } _test_next:;
    return failures;
}

static int t_plic_claim_complete(void)
{
    int failures = 0;
    TEST("rvplat plic: claim clears pending, complete re-arms a high level") {
        struct rvplat_plic p;
        rvplat_plic_init(&p, 8);
        plic_enable(&p, CTX_S, 3);
        plic_prio(&p, 3, 1);
        rvplat_plic_set_source(&p, 3, true);
        ASSERT_EQ(rvplat_plic_read(&p, RVPLAT_PLIC_PENDING_BASE), 1u << 3);
        ASSERT_EQ(rvplat_plic_read(&p, ctx_reg(CTX_S, RVPLAT_PLIC_CLAIM_OFF)), 3u);
        ASSERT_EQ(rvplat_plic_read(&p, RVPLAT_PLIC_PENDING_BASE), 0u);
        ASSERT(!rvplat_plic_context_pending(&p, CTX_S));
        /* still high: no new request until complete */
        rvplat_plic_set_source(&p, 3, true);
        ASSERT(!rvplat_plic_context_pending(&p, CTX_S));
        rvplat_plic_write(&p, ctx_reg(CTX_S, RVPLAT_PLIC_CLAIM_OFF), 3);
        ASSERT(rvplat_plic_context_pending(&p, CTX_S));
        ASSERT_EQ(rvplat_plic_claim(&p, CTX_S), 3u);
        /* line drops before complete: nothing re-arms */
        rvplat_plic_set_source(&p, 3, false);
        rvplat_plic_complete(&p, CTX_S, 3);
        ASSERT(!rvplat_plic_context_pending(&p, CTX_S));
        /* completing an id that is not in flight changes nothing */
        rvplat_plic_set_source(&p, 3, true);
        rvplat_plic_complete(&p, CTX_S, 3);
        ASSERT_EQ(rvplat_plic_claim(&p, CTX_S), 3u);
        PASS();
    } _test_next:;
    return failures;
}

static int t_plic_enables(void)
{
    int failures = 0;
    TEST("rvplat plic: enables are per context") {
        struct rvplat_plic p;
        rvplat_plic_init(&p, 8);
        plic_enable(&p, CTX_S, 2);
        plic_prio(&p, 2, 1);
        rvplat_plic_set_source(&p, 2, true);
        ASSERT(rvplat_plic_context_pending(&p, CTX_S));
        ASSERT(!rvplat_plic_context_pending(&p, CTX_M));
        ASSERT_EQ(rvplat_plic_claim(&p, CTX_M), 0u);
        ASSERT_EQ(rvplat_plic_read(&p, RVPLAT_PLIC_ENABLE_BASE), 0u);
        ASSERT_EQ(rvplat_plic_read(&p, RVPLAT_PLIC_ENABLE_BASE +
                                           RVPLAT_PLIC_ENABLE_STRIDE), 1u << 2);
        plic_enable(&p, CTX_M, 2);
        ASSERT(rvplat_plic_context_pending(&p, CTX_M));
        /* the out-of-range context reports nothing */
        ASSERT(!rvplat_plic_context_pending(&p, 2));
        PASS();
    } _test_next:;
    return failures;
}

static int t_plic_mmio(void)
{
    int failures = 0;
    TEST("rvplat plic: registers, source 0, top id and out-of-range reads") {
        struct rvplat_plic p;
        rvplat_plic_init(&p, 64);
        plic_prio(&p, 0, 5); /* source 0 does not exist */
        ASSERT_EQ(rvplat_plic_read(&p, RVPLAT_PLIC_PRIORITY_BASE), 0u);
        plic_prio(&p, 64, 6);
        ASSERT_EQ(rvplat_plic_read(&p, 64u * 4u), 6u);
        plic_prio(&p, 64, 15); /* only three bits implemented */
        ASSERT_EQ(rvplat_plic_read(&p, 64u * 4u), 7u);
        plic_enable(&p, CTX_S, 64);
        plic_enable(&p, CTX_S, 1);
        rvplat_plic_set_source(&p, 64, true);
        ASSERT_EQ(rvplat_plic_read(&p, RVPLAT_PLIC_PENDING_BASE + 8u), 1u);
        ASSERT(rvplat_plic_context_pending(&p, CTX_S));
        ASSERT_EQ(rvplat_plic_claim(&p, CTX_S), 64u);
        /* ids past the source count are ignored */
        rvplat_plic_set_source(&p, 65, true);
        rvplat_plic_set_source(&p, 0, true);
        ASSERT_EQ(rvplat_plic_read(&p, RVPLAT_PLIC_PENDING_BASE + 8u), 0u);
        struct rvplat_plic q;
        rvplat_plic_init(&q, 4);
        rvplat_plic_write(&q, RVPLAT_PLIC_ENABLE_BASE, 0xFFFFFFFFu);
        ASSERT_EQ(rvplat_plic_read(&q, RVPLAT_PLIC_ENABLE_BASE), 0x1Eu);
        /* out of range, unaligned, unmapped: zero, writes ignored */
        ASSERT_EQ(rvplat_plic_read(&p, RVPLAT_PLIC_SIZE), 0u);
        ASSERT_EQ(rvplat_plic_read(&p, UINT64_MAX), 0u);
        ASSERT_EQ(rvplat_plic_read(&p, 0x1002u), 0u);
        ASSERT_EQ(rvplat_plic_read(&p, RVPLAT_PLIC_PENDING_BASE + 12u), 0u);
        ASSERT_EQ(rvplat_plic_read(&p, 0x1800u), 0u);
        ASSERT_EQ(rvplat_plic_read(&p, ctx_reg(2, 0)), 0u);
        ASSERT_EQ(rvplat_plic_read(&p, ctx_reg(CTX_S, 8)), 0u);
        ASSERT_EQ(rvplat_plic_read(&p, 65u * 4u), 0u);
        rvplat_plic_write(&p, RVPLAT_PLIC_SIZE, 7);
        rvplat_plic_write(&p, ctx_reg(2, 0), 7);
        ASSERT_EQ(rvplat_plic_read(&p, ctx_reg(CTX_M, RVPLAT_PLIC_THRESHOLD_OFF)), 0u);
        PASS();
    } _test_next:;
    return failures;
}

static int t_timer_deadline(void)
{
    int failures = 0;
    TEST("rvplat timer: ticks derive time, pending exactly at the deadline") {
        struct rvplat_timer t;
        rvplat_timer_init(&t, 10);
        ASSERT_EQ(rvplat_timer_time(&t, 99), 9u);
        ASSERT_EQ(rvplat_timer_time(&t, 100), 10u);
        ASSERT(!rvplat_timer_pending(&t, UINT64_MAX)); /* disarmed */
        rvplat_timer_set_timer(&t, 50);
        ASSERT(!rvplat_timer_pending(&t, 49));
        ASSERT(rvplat_timer_pending(&t, 50));
        ASSERT(rvplat_timer_pending(&t, 51));
        ASSERT_EQ(rvplat_timer_next_event(&t, 20), 30u);
        ASSERT_EQ(rvplat_timer_next_event(&t, 50), 0u);
        ASSERT_EQ(rvplat_timer_next_event(&t, 70), 0u);
        ASSERT_EQ(rvplat_timer_next_event_ticks(&t, 205), 500u);
        ASSERT_EQ(rvplat_timer_next_event_ticks(&t, 777), 777u);
        rvplat_timer_set_timer(&t, RVPLAT_TIMER_DISARMED);
        ASSERT_EQ(rvplat_timer_next_event(&t, 0), UINT64_MAX);
        ASSERT_EQ(rvplat_timer_next_event_ticks(&t, 0), UINT64_MAX);
        struct rvplat_timer z;
        rvplat_timer_init(&z, 0);
        ASSERT_EQ(rvplat_timer_time(&z, 42), 42u);
        PASS();
    } _test_next:;
    return failures;
}

static int t_timer_overflow(void)
{
    int failures = 0;
    TEST("rvplat timer: next_event arithmetic never overflows at UINT64_MAX") {
        struct rvplat_timer t;
        rvplat_timer_init(&t, 10);
        rvplat_timer_set_timer(&t, UINT64_MAX - 1u);
        ASSERT_EQ(rvplat_timer_next_event(&t, 0), UINT64_MAX - 1u);
        ASSERT_EQ(rvplat_timer_next_event(&t, UINT64_MAX - 2u), 1u);
        ASSERT_EQ(rvplat_timer_next_event(&t, UINT64_MAX), 0u);
        ASSERT(rvplat_timer_pending(&t, UINT64_MAX));
        ASSERT_EQ(rvplat_timer_ticks_for_time(&t, UINT64_MAX), UINT64_MAX);
        ASSERT_EQ(rvplat_timer_ticks_for_time(&t, UINT64_MAX / 10u),
                  (UINT64_MAX / 10u) * 10u);
        ASSERT_EQ(rvplat_timer_next_event_ticks(&t, 0), UINT64_MAX);
        ASSERT_EQ(rvplat_timer_time(&t, UINT64_MAX), UINT64_MAX / 10u);
        PASS();
    } _test_next:;
    return failures;
}

struct sbi_log {
    uint8_t out[16];
    size_t n;
    int in[4];
    size_t in_n, in_pos;
};

static int log_get(void *ctx)
{
    struct sbi_log *l = ctx;
    return l->in_pos < l->in_n ? l->in[l->in_pos++] : -1;
}

static int t_sbi_probe(void)
{
    int failures = 0;
    TEST("rvplat sbi: probe table for every extension") {
        struct rvplat_sbi s;
        rvplat_sbi_init(&s);
        static const uint64_t present[] = {
            RVPLAT_SBI_EXT_BASE, RVPLAT_SBI_EXT_TIME, RVPLAT_SBI_EXT_IPI,
            RVPLAT_SBI_EXT_RFNC, RVPLAT_SBI_EXT_HSM, RVPLAT_SBI_EXT_SRST,
            0, 1, 2, 3, 4, 5, 6, 7, 8,
        };
        static const uint64_t absent[] = {
            9, 0x0A, 0x0F, 0x11, 0x4442434Eull /* DBCN */, 0x09000000ull,
            0x735049ull + 1u, UINT64_MAX,
        };
        for (size_t i = 0; i < sizeof(present) / sizeof(present[0]); i++) {
            uint64_t a[6] = {present[i], 0, 0, 0, 0, 0};
            struct rvplat_sbi_ret r =
                rvplat_sbi_call(&s, RVPLAT_SBI_EXT_BASE, 3, a);
            ASSERT_EQ(r.error, 0);
            ASSERT(r.value != 0u);
        }
        for (size_t i = 0; i < sizeof(absent) / sizeof(absent[0]); i++) {
            uint64_t a[6] = {absent[i], 0, 0, 0, 0, 0};
            struct rvplat_sbi_ret r =
                rvplat_sbi_call(&s, RVPLAT_SBI_EXT_BASE, 3, a);
            ASSERT_EQ(r.error, 0);
            ASSERT_EQ(r.value, 0u);
        }
        PASS();
    } _test_next:;
    return failures;
}

static int t_sbi_legacy_probe(void)
{
    int failures = 0;
    TEST("rvplat sbi: FreeBSD requires legacy putchar and getchar present") {
        struct rvplat_sbi s;
        rvplat_sbi_init(&s);
        for (uint64_t legacy = 1; legacy <= 2; legacy++) {
            uint64_t a[6] = {legacy, 0, 0, 0, 0, 0};
            struct rvplat_sbi_ret r =
                rvplat_sbi_call(&s, RVPLAT_SBI_EXT_BASE, 3, a);
            ASSERT_EQ(r.error, 0);
            ASSERT_EQ(r.value, 1u);
        }
        PASS();
    } _test_next:;
    return failures;
}

static int t_sbi_base(void)
{
    int failures = 0;
    TEST("rvplat sbi: base extension identity and unknown calls") {
        struct rvplat_sbi s;
        rvplat_sbi_init(&s);
        s.mvendorid = 0; s.marchid = 7; s.mimpid = 9;
        uint64_t a[6] = {0};
        struct rvplat_sbi_ret r = rvplat_sbi_call(&s, RVPLAT_SBI_EXT_BASE, 0, a);
        ASSERT_EQ(r.error, 0);
        ASSERT_EQ(r.value, 0x01000000u); /* spec 1.0 */
        r = rvplat_sbi_call(&s, RVPLAT_SBI_EXT_BASE, 1, a);
        ASSERT_EQ(r.value, RVPLAT_SBI_IMPL_ID);
        r = rvplat_sbi_call(&s, RVPLAT_SBI_EXT_BASE, 2, a);
        ASSERT_EQ(r.value, RVPLAT_SBI_IMPL_VERSION);
        r = rvplat_sbi_call(&s, RVPLAT_SBI_EXT_BASE, 4, a);
        ASSERT_EQ(r.value, 0u);
        r = rvplat_sbi_call(&s, RVPLAT_SBI_EXT_BASE, 5, a);
        ASSERT_EQ(r.value, 7u);
        r = rvplat_sbi_call(&s, RVPLAT_SBI_EXT_BASE, 6, a);
        ASSERT_EQ(r.value, 9u);
        r = rvplat_sbi_call(&s, RVPLAT_SBI_EXT_BASE, 7, a);
        ASSERT_EQ(r.error, RVPLAT_SBI_ERR_NOT_SUPPORTED);
        r = rvplat_sbi_call(&s, 0x12345678u, 0, a);
        ASSERT_EQ(r.error, RVPLAT_SBI_ERR_NOT_SUPPORTED);
        ASSERT_EQ(r.value, 0u);
        ASSERT_EQ(r.action, RVPLAT_SBI_ACTION_NONE);
        r = rvplat_sbi_call(&s, 0x4442434Eull, 0, a);
        ASSERT_EQ(r.error, RVPLAT_SBI_ERR_NOT_SUPPORTED);
        PASS();
    } _test_next:;
    return failures;
}

static int t_sbi_timer_ipi_rfence_hsm(void)
{
    int failures = 0;
    TEST("rvplat sbi: set_timer, IPI, RFENCE and HSM") {
        struct rvplat_sbi s;
        rvplat_sbi_init(&s);
        uint64_t a[6] = {0x1122334455667788ull, 0, 0, 0, 0, 0};
        struct rvplat_sbi_ret r = rvplat_sbi_call(&s, RVPLAT_SBI_EXT_TIME, 0, a);
        ASSERT_EQ(r.error, 0);
        ASSERT_EQ(r.action, RVPLAT_SBI_ACTION_TIMER_SET);
        ASSERT_EQ(r.action_args[0], 0x1122334455667788ull);
        r = rvplat_sbi_call(&s, RVPLAT_SBI_EXT_TIME, 1, a);
        ASSERT_EQ(r.error, RVPLAT_SBI_ERR_NOT_SUPPORTED);
        uint64_t one[6] = {1, 0, 0, 0, 0, 0};
        r = rvplat_sbi_call(&s, RVPLAT_SBI_EXT_IPI, 0, one);
        ASSERT_EQ(r.error, 0);
        ASSERT_EQ(r.action, RVPLAT_SBI_ACTION_IPI);
        uint64_t two[6] = {2, 0, 0, 0, 0, 0};
        r = rvplat_sbi_call(&s, RVPLAT_SBI_EXT_IPI, 0, two);
        ASSERT_EQ(r.error, RVPLAT_SBI_ERR_INVALID_PARAM);
        uint64_t all[6] = {0xFF, UINT64_MAX, 0, 0, 0, 0};
        r = rvplat_sbi_call(&s, RVPLAT_SBI_EXT_RFNC, 1, all);
        ASSERT_EQ(r.error, 0);
        ASSERT_EQ(r.action, RVPLAT_SBI_ACTION_RFENCE);
        ASSERT_EQ(r.action_args[0], 1u);
        r = rvplat_sbi_call(&s, RVPLAT_SBI_EXT_RFNC, 0, one);
        ASSERT_EQ(r.action_args[0], 0u);
        r = rvplat_sbi_call(&s, RVPLAT_SBI_EXT_RFNC, 3, one);
        ASSERT_EQ(r.error, RVPLAT_SBI_ERR_NOT_SUPPORTED);
        uint64_t hart0[6] = {0};
        uint64_t hart1[6] = {1, 0, 0, 0, 0, 0};
        r = rvplat_sbi_call(&s, RVPLAT_SBI_EXT_HSM, 2, hart0);
        ASSERT_EQ(r.error, 0);
        ASSERT_EQ(r.value, 0u); /* STARTED */
        r = rvplat_sbi_call(&s, RVPLAT_SBI_EXT_HSM, 2, hart1);
        ASSERT_EQ(r.error, RVPLAT_SBI_ERR_INVALID_PARAM);
        r = rvplat_sbi_call(&s, RVPLAT_SBI_EXT_HSM, 0, hart0);
        ASSERT_EQ(r.error, RVPLAT_SBI_ERR_ALREADY_AVAILABLE);
        r = rvplat_sbi_call(&s, RVPLAT_SBI_EXT_HSM, 0, hart1);
        ASSERT_EQ(r.error, RVPLAT_SBI_ERR_INVALID_PARAM);
        r = rvplat_sbi_call(&s, RVPLAT_SBI_EXT_HSM, 1, hart0);
        ASSERT_EQ(r.action, RVPLAT_SBI_ACTION_SHUTDOWN);
        r = rvplat_sbi_call(&s, RVPLAT_SBI_EXT_HSM, 2, hart0);
        ASSERT_EQ(r.value, 1u); /* STOPPED */
        r = rvplat_sbi_call(&s, RVPLAT_SBI_EXT_HSM, 1, hart0);
        ASSERT_EQ(r.error, RVPLAT_SBI_ERR_ALREADY_STOPPED);
        r = rvplat_sbi_call(&s, RVPLAT_SBI_EXT_HSM, 9, hart0);
        ASSERT_EQ(r.error, RVPLAT_SBI_ERR_NOT_SUPPORTED);
        PASS();
    } _test_next:;
    return failures;
}

static int t_sbi_srst(void)
{
    int failures = 0;
    TEST("rvplat sbi: system_reset actions") {
        struct rvplat_sbi s;
        rvplat_sbi_init(&s);
        uint64_t a[6] = {RVPLAT_SBI_RESET_SHUTDOWN, 0, 0, 0, 0, 0};
        struct rvplat_sbi_ret r = rvplat_sbi_call(&s, RVPLAT_SBI_EXT_SRST, 0, a);
        ASSERT_EQ(r.error, 0);
        ASSERT_EQ(r.action, RVPLAT_SBI_ACTION_SHUTDOWN);
        a[0] = RVPLAT_SBI_RESET_COLD_REBOOT;
        a[1] = 5;
        r = rvplat_sbi_call(&s, RVPLAT_SBI_EXT_SRST, 0, a);
        ASSERT_EQ(r.action, RVPLAT_SBI_ACTION_REBOOT);
        ASSERT_EQ(r.action_args[0], 1u);
        ASSERT_EQ(r.action_args[1], 5u);
        a[0] = RVPLAT_SBI_RESET_WARM_REBOOT;
        r = rvplat_sbi_call(&s, RVPLAT_SBI_EXT_SRST, 0, a);
        ASSERT_EQ(r.action, RVPLAT_SBI_ACTION_REBOOT);
        a[0] = 3;
        r = rvplat_sbi_call(&s, RVPLAT_SBI_EXT_SRST, 0, a);
        ASSERT_EQ(r.error, RVPLAT_SBI_ERR_INVALID_PARAM);
        ASSERT_EQ(r.action, RVPLAT_SBI_ACTION_NONE);
        a[0] = 0x100000000ull; /* low 32 bits are the type */
        r = rvplat_sbi_call(&s, RVPLAT_SBI_EXT_SRST, 0, a);
        ASSERT_EQ(r.action, RVPLAT_SBI_ACTION_SHUTDOWN);
        r = rvplat_sbi_call(&s, RVPLAT_SBI_EXT_SRST, 1, a);
        ASSERT_EQ(r.error, RVPLAT_SBI_ERR_NOT_SUPPORTED);
        uint64_t none[6] = {0};
        r = rvplat_sbi_call(&s, RVPLAT_SBI_LEGACY_SHUTDOWN, 0, none);
        ASSERT_EQ(r.action, RVPLAT_SBI_ACTION_SHUTDOWN);
        PASS();
    } _test_next:;
    return failures;
}

static int t_sbi_console(void)
{
    int failures = 0;
    TEST("rvplat sbi: legacy putchar emits exactly once, getchar and -1 when empty") {
        struct sbi_log log = {.in = {'x', 0xFF}, .in_n = 2};
        struct rvplat_sbi s;
        rvplat_sbi_init(&s);
        s.getchar = log_get;
        s.ctx = &log;
        /* The machine acts on actions: it is the only emitter. */
        const char *msg = "ok\n";
        for (size_t i = 0; msg[i] != '\0'; i++) {
            uint64_t a[6] = {(uint64_t)(uint8_t)msg[i] | 0x100u, 0, 0, 0, 0, 0};
            struct rvplat_sbi_ret r =
                rvplat_sbi_call(&s, RVPLAT_SBI_LEGACY_PUTCHAR, 0, a);
            ASSERT_EQ(r.error, 0);
            ASSERT_EQ(r.action, RVPLAT_SBI_ACTION_CONSOLE_PUT);
            ASSERT_EQ(r.action_args[0], (uint64_t)(uint8_t)msg[i]);
            if (r.action == RVPLAT_SBI_ACTION_CONSOLE_PUT && log.n < sizeof(log.out))
                log.out[log.n++] = (uint8_t)r.action_args[0];
        }
        ASSERT_EQ(log.n, 3u); /* one emission per putchar, not two */
        ASSERT(memcmp(log.out, "ok\n", 3) == 0);
        uint64_t none[6] = {0};
        struct rvplat_sbi_ret r = rvplat_sbi_call(&s, RVPLAT_SBI_LEGACY_GETCHAR, 0, none);
        ASSERT_EQ(r.error, (int64_t)'x'); /* result is in a0 */
        r = rvplat_sbi_call(&s, RVPLAT_SBI_LEGACY_GETCHAR, 0, none);
        ASSERT_EQ(r.error, 0xFF);
        r = rvplat_sbi_call(&s, RVPLAT_SBI_LEGACY_GETCHAR, 0, none);
        ASSERT_EQ(r.error, -1);
        ASSERT_EQ(r.value, 0u);
        s.getchar = nullptr;
        r = rvplat_sbi_call(&s, RVPLAT_SBI_LEGACY_GETCHAR, 0, none);
        ASSERT_EQ(r.error, -1);
        r = rvplat_sbi_call(&s, RVPLAT_SBI_LEGACY_PUTCHAR, 0, none);
        ASSERT_EQ(r.error, 0);
        r = rvplat_sbi_call(&s, RVPLAT_SBI_LEGACY_SET_TIMER, 0, none);
        ASSERT_EQ(r.action, RVPLAT_SBI_ACTION_TIMER_SET);
        PASS();
    } _test_next:;
    return failures;
}

struct uart_log { uint8_t out[8]; size_t n; };

static void uart_tx(void *ctx, uint8_t b)
{
    struct uart_log *l = ctx;
    if (l->n < sizeof(l->out)) l->out[l->n++] = b;
}

static int t_uart_rx_irq(void)
{
    int failures = 0;
    TEST("rvplat uart: rx interrupt, LSR data ready and IIR") {
        struct uart_log log = {0};
        struct rvplat_uart u;
        rvplat_uart_init(&u, uart_tx, &log);
        ASSERT_EQ(rvplat_uart_read(&u, RVPLAT_UART_IIR), RVPLAT_UART_IIR_NONE);
        ASSERT_EQ(rvplat_uart_read(&u, RVPLAT_UART_LSR) & RVPLAT_UART_LSR_DR, 0u);
        rvplat_uart_rx(&u, 'A');
        ASSERT(!rvplat_uart_irq(&u)); /* IER still masks it */
        ASSERT_EQ(rvplat_uart_read(&u, RVPLAT_UART_LSR) & RVPLAT_UART_LSR_DR, 1u);
        rvplat_uart_write(&u, RVPLAT_UART_IER, RVPLAT_UART_IER_RDA);
        ASSERT(rvplat_uart_irq(&u));
        ASSERT_EQ(rvplat_uart_read(&u, RVPLAT_UART_IIR), RVPLAT_UART_IIR_RDA);
        rvplat_uart_rx(&u, 'B');
        ASSERT_EQ(rvplat_uart_read(&u, RVPLAT_UART_RBR), (uint8_t)'A');
        ASSERT(rvplat_uart_irq(&u));
        ASSERT_EQ(rvplat_uart_read(&u, RVPLAT_UART_RBR), (uint8_t)'B');
        ASSERT(!rvplat_uart_irq(&u));
        ASSERT_EQ(rvplat_uart_read(&u, RVPLAT_UART_LSR) & RVPLAT_UART_LSR_DR, 0u);
        ASSERT_EQ(rvplat_uart_read(&u, RVPLAT_UART_RBR), 0u); /* empty */
        /* transmit goes to the callback and raises THRE when enabled */
        rvplat_uart_write(&u, RVPLAT_UART_RBR, 'h');
        rvplat_uart_write(&u, RVPLAT_UART_RBR, 'i');
        ASSERT_EQ(log.n, 2u);
        ASSERT(memcmp(log.out, "hi", 2) == 0);
        ASSERT(!rvplat_uart_irq(&u));
        rvplat_uart_write(&u, RVPLAT_UART_IER, RVPLAT_UART_IER_THRE);
        ASSERT(rvplat_uart_irq(&u));
        ASSERT_EQ(rvplat_uart_read(&u, RVPLAT_UART_IIR), RVPLAT_UART_IIR_THRE);
        ASSERT(!rvplat_uart_irq(&u)); /* IIR read acknowledged it */
        ASSERT_EQ(rvplat_uart_read(&u, RVPLAT_UART_LSR) &
                      (RVPLAT_UART_LSR_THRE | RVPLAT_UART_LSR_TEMT), 0x60u);
        PASS();
    } _test_next:;
    return failures;
}

static int t_uart_overrun(void)
{
    int failures = 0;
    TEST("rvplat uart: 16-byte FIFO overflow drops the byte and sets OE") {
        struct rvplat_uart u;
        rvplat_uart_init(&u, nullptr, nullptr);
        for (uint32_t i = 0; i < RVPLAT_UART_FIFO_SIZE; i++)
            rvplat_uart_rx(&u, (uint8_t)(0x40u + i));
        ASSERT_EQ(rvplat_uart_read(&u, RVPLAT_UART_LSR) & RVPLAT_UART_LSR_OE, 0u);
        rvplat_uart_rx(&u, 0xEE); /* the 17th byte */
        rvplat_uart_write(&u, RVPLAT_UART_IER, RVPLAT_UART_IER_RLS);
        ASSERT(rvplat_uart_irq(&u));
        ASSERT_EQ(rvplat_uart_read(&u, RVPLAT_UART_IIR), RVPLAT_UART_IIR_RLS);
        uint8_t lsr = rvplat_uart_read(&u, RVPLAT_UART_LSR);
        ASSERT_EQ(lsr & RVPLAT_UART_LSR_OE, RVPLAT_UART_LSR_OE);
        ASSERT_EQ(rvplat_uart_read(&u, RVPLAT_UART_LSR) & RVPLAT_UART_LSR_OE, 0u);
        ASSERT(!rvplat_uart_irq(&u));
        for (uint32_t i = 0; i < RVPLAT_UART_FIFO_SIZE; i++)
            ASSERT_EQ(rvplat_uart_read(&u, RVPLAT_UART_RBR), (uint8_t)(0x40u + i));
        ASSERT_EQ(rvplat_uart_read(&u, RVPLAT_UART_LSR) & RVPLAT_UART_LSR_DR, 0u);
        /* wrap-around after draining works */
        rvplat_uart_rx(&u, 0x11);
        ASSERT_EQ(rvplat_uart_read(&u, RVPLAT_UART_RBR), 0x11u);
        /* FCR clears the receive FIFO */
        rvplat_uart_rx(&u, 0x22);
        rvplat_uart_write(&u, RVPLAT_UART_IIR, 0x07);
        ASSERT_EQ(rvplat_uart_read(&u, RVPLAT_UART_LSR) & RVPLAT_UART_LSR_DR, 0u);
        ASSERT_EQ(rvplat_uart_read(&u, RVPLAT_UART_IIR) & RVPLAT_UART_IIR_FIFO,
                  RVPLAT_UART_IIR_FIFO);
        PASS();
    } _test_next:;
    return failures;
}

static int t_uart_dlab(void)
{
    int failures = 0;
    TEST("rvplat uart: DLAB divisor latch, scratch, MCR and LCR") {
        struct uart_log log = {0};
        struct rvplat_uart u;
        rvplat_uart_init(&u, uart_tx, &log);
        rvplat_uart_write(&u, RVPLAT_UART_IER, 0x05);
        rvplat_uart_write(&u, RVPLAT_UART_LCR, 0x80 | 0x03);
        rvplat_uart_write(&u, RVPLAT_UART_RBR, 0x34); /* DLL, not THR */
        rvplat_uart_write(&u, RVPLAT_UART_IER, 0x12); /* DLM, not IER */
        ASSERT_EQ(log.n, 0u);
        ASSERT_EQ(rvplat_uart_read(&u, RVPLAT_UART_RBR), 0x34u);
        ASSERT_EQ(rvplat_uart_read(&u, RVPLAT_UART_IER), 0x12u);
        ASSERT_EQ(rvplat_uart_divisor(&u), 0x1234u);
        rvplat_uart_write(&u, RVPLAT_UART_LCR, 0x03);
        ASSERT_EQ(rvplat_uart_read(&u, RVPLAT_UART_LCR), 0x03u);
        ASSERT_EQ(rvplat_uart_read(&u, RVPLAT_UART_IER), 0x05u); /* intact */
        ASSERT_EQ(rvplat_uart_divisor(&u), 0x1234u);
        rvplat_uart_write(&u, RVPLAT_UART_SCR, 0xA5);
        ASSERT_EQ(rvplat_uart_read(&u, RVPLAT_UART_SCR), 0xA5u);
        rvplat_uart_write(&u, RVPLAT_UART_MCR, 0xFF);
        ASSERT_EQ(rvplat_uart_read(&u, RVPLAT_UART_MCR), 0x1Fu);
        rvplat_uart_write(&u, RVPLAT_UART_LSR, 0xFF); /* read-only */
        ASSERT_EQ(rvplat_uart_read(&u, RVPLAT_UART_MSR), 0xF0u); /* MCR 0x1F is loopback */
        rvplat_uart_write(&u, RVPLAT_UART_MCR, 0x00);
        ASSERT_EQ(rvplat_uart_read(&u, RVPLAT_UART_MSR), 0u);
        ASSERT_EQ(rvplat_uart_read(&u, 8 + RVPLAT_UART_SCR), 0xA5u); /* masked */
        PASS();
    } _test_next:;
    return failures;
}

static int t_plic_claim_ignores_threshold(void)
{
    int failures = 0;
    TEST("rvplat plic: claim is independent of threshold (PLIC 1.0 claim process)") {
        static const uint32_t thresholds[] = {1u, 7u};
        for (size_t i = 0; i < 2u; i++) {
            struct rvplat_plic p;
            rvplat_plic_init(&p, 31);
            rvplat_plic_write(&p, RVPLAT_PLIC_PRIORITY_BASE + 10u * 4u, 1);
            rvplat_plic_write(&p, RVPLAT_PLIC_ENABLE_BASE +
                                      RVPLAT_PLIC_ENABLE_STRIDE, 1u << 10);
            rvplat_plic_write(&p, ctx_reg(CTX_S, RVPLAT_PLIC_THRESHOLD_OFF),
                              thresholds[i]);
            rvplat_plic_set_source(&p, 10, true);
            ASSERT(!rvplat_plic_context_pending(&p, CTX_S));
            ASSERT_EQ(rvplat_plic_read(&p, RVPLAT_PLIC_PENDING_BASE), 1u << 10);
            ASSERT_EQ(rvplat_plic_read(&p, ctx_reg(CTX_S, RVPLAT_PLIC_CLAIM_OFF)), 10u);
            ASSERT_EQ(rvplat_plic_read(&p, RVPLAT_PLIC_PENDING_BASE), 0u);
            ASSERT_EQ(rvplat_plic_read(&p, ctx_reg(CTX_S, RVPLAT_PLIC_CLAIM_OFF)), 0u);
        }
        /* control: threshold 0 notifies */
        struct rvplat_plic p;
        rvplat_plic_init(&p, 31);
        rvplat_plic_write(&p, RVPLAT_PLIC_PRIORITY_BASE + 10u * 4u, 1);
        rvplat_plic_write(&p, RVPLAT_PLIC_ENABLE_BASE + RVPLAT_PLIC_ENABLE_STRIDE,
                          1u << 10);
        rvplat_plic_set_source(&p, 10, true);
        ASSERT(rvplat_plic_context_pending(&p, CTX_S));
        PASS();
    } _test_next:;
    return failures;
}

static struct rvplat_sbi_ret sbi_hartset(struct rvplat_sbi *s, uint64_t eid,
                                         uint64_t fid, uint64_t mask,
                                         uint64_t base)
{
    uint64_t a[6] = {mask, base, 0, 0, 0, 0};
    return rvplat_sbi_call(s, eid, fid, a);
}

static int t_sbi_empty_hart_set(void)
{
    int failures = 0;
    TEST("rvplat sbi: IPI and RFENCE with an empty hart set succeed without action") {
        struct rvplat_sbi s;
        rvplat_sbi_init(&s);
        struct rvplat_sbi_ret r = sbi_hartset(&s, RVPLAT_SBI_EXT_IPI, 0, 0, 0);
        ASSERT_EQ(r.error, 0);
        ASSERT_EQ(r.action, RVPLAT_SBI_ACTION_NONE);
        r = sbi_hartset(&s, RVPLAT_SBI_EXT_IPI, 0, 1, 0);
        ASSERT_EQ(r.error, 0);
        ASSERT_EQ(r.action, RVPLAT_SBI_ACTION_IPI);
        r = sbi_hartset(&s, RVPLAT_SBI_EXT_IPI, 0, 0, UINT64_MAX);
        ASSERT_EQ(r.action, RVPLAT_SBI_ACTION_IPI); /* all harts */
        r = sbi_hartset(&s, RVPLAT_SBI_EXT_IPI, 0, 0, 5);
        ASSERT_EQ(r.error, 0);
        ASSERT_EQ(r.action, RVPLAT_SBI_ACTION_NONE);
        for (uint64_t fid = 0; fid <= 2; fid++) {
            r = sbi_hartset(&s, RVPLAT_SBI_EXT_RFNC, fid, 0, 0);
            ASSERT_EQ(r.error, 0);
            ASSERT_EQ(r.action, RVPLAT_SBI_ACTION_NONE);
            r = sbi_hartset(&s, RVPLAT_SBI_EXT_RFNC, fid, 1, 0);
            ASSERT_EQ(r.action, RVPLAT_SBI_ACTION_RFENCE);
            r = sbi_hartset(&s, RVPLAT_SBI_EXT_RFNC, fid, 0, UINT64_MAX);
            ASSERT_EQ(r.action, RVPLAT_SBI_ACTION_RFENCE);
        }
        PASS();
    } _test_next:;
    return failures;
}

static int t_sbi_legacy_clear_ipi(void)
{
    int failures = 0;
    TEST("rvplat sbi: legacy clear_ipi reports a CLEAR_IPI action") {
        struct rvplat_sbi s;
        rvplat_sbi_init(&s);
        uint64_t a[6] = {0};
        struct rvplat_sbi_ret r = rvplat_sbi_call(&s, RVPLAT_SBI_LEGACY_CLEAR_IPI, 0, a);
        ASSERT_EQ(r.error, 0);
        ASSERT_EQ(r.action, RVPLAT_SBI_ACTION_CLEAR_IPI);
        PASS();
    } _test_next:;
    return failures;
}

/* Replays riscv/riscv/sbi.c sbi_init() and the boot-time calls. */
static int t_sbi_freebsd_sbi_init(void)
{
    int failures = 0;
    TEST("rvplat sbi: FreeBSD sbi_init sequence (sbi.c:288-347) and runtime calls") {
        struct rvplat_sbi s;
        rvplat_sbi_init(&s);
        uint64_t z[6] = {0};
        struct rvplat_sbi_ret r = rvplat_sbi_call(&s, RVPLAT_SBI_EXT_BASE, 0, z);
        ASSERT_EQ(r.error, 0); /* nonzero error would select legacy mode */
        ASSERT_EQ((r.value >> 24) & 0x7F, 1u); /* major */
        ASSERT_EQ(r.value & 0xFFFFFF, 0u);     /* minor */
        for (uint64_t fid = 1; fid <= 6; fid++) {
            r = rvplat_sbi_call(&s, RVPLAT_SBI_EXT_BASE, fid, z);
            ASSERT_EQ(r.error, 0);
        }
        static const uint64_t need[] = {
            RVPLAT_SBI_EXT_TIME, RVPLAT_SBI_EXT_IPI, RVPLAT_SBI_EXT_RFNC,
            RVPLAT_SBI_EXT_SRST, RVPLAT_SBI_EXT_HSM, 0, 1, 2, 3, 4, 5, 6, 7, 8};
        for (size_t i = 0; i < sizeof(need) / sizeof(need[0]); i++) {
            uint64_t a[6] = {need[i], 0, 0, 0, 0, 0};
            r = rvplat_sbi_call(&s, RVPLAT_SBI_EXT_BASE, 3, a);
            ASSERT_EQ(r.error, 0);
            ASSERT(r.value != 0u);
        }
        /* sbi_set_timer MPASS(error == SBI_SUCCESS); disarm with -1UL */
        uint64_t t[6] = {UINT64_MAX, 0, 0, 0, 0, 0};
        r = rvplat_sbi_call(&s, RVPLAT_SBI_EXT_TIME, 0, t);
        ASSERT_EQ(r.error, 0);
        ASSERT_EQ(r.action, RVPLAT_SBI_ACTION_TIMER_SET);
        ASSERT_EQ(r.action_args[0], UINT64_MAX);
        /* sbi_send_ipi / sbi_remote_*: hart mask value in a0, base 0 in a1 */
        r = sbi_hartset(&s, RVPLAT_SBI_EXT_IPI, 0, 1, 0);
        ASSERT_EQ(r.error, 0);
        r = sbi_hartset(&s, RVPLAT_SBI_EXT_RFNC, 0, 1, 0);
        ASSERT_EQ(r.error, 0);
        uint64_t sv[6] = {1, 0, 0x1000, 0x2000, 0, 0}; /* sfence.vma */
        r = rvplat_sbi_call(&s, RVPLAT_SBI_EXT_RFNC, 1, sv);
        ASSERT_EQ(r.error, 0);
        uint64_t sa[6] = {1, 0, 0x1000, 0x2000, 3, 0}; /* with asid */
        r = rvplat_sbi_call(&s, RVPLAT_SBI_EXT_RFNC, 2, sa);
        ASSERT_EQ(r.error, 0);
        /* sbi_system_reset(SHUTDOWN, NONE), then legacy fallthrough */
        uint64_t sd[6] = {RVPLAT_SBI_RESET_SHUTDOWN, 0, 0, 0, 0, 0};
        r = rvplat_sbi_call(&s, RVPLAT_SBI_EXT_SRST, 0, sd);
        ASSERT_EQ(r.action, RVPLAT_SBI_ACTION_SHUTDOWN);
        r = rvplat_sbi_call(&s, RVPLAT_SBI_LEGACY_SHUTDOWN, 0, z);
        ASSERT_EQ(r.action, RVPLAT_SBI_ACTION_SHUTDOWN);
        uint64_t rb[6] = {RVPLAT_SBI_RESET_COLD_REBOOT, 0, 0, 0, 0, 0};
        r = rvplat_sbi_call(&s, RVPLAT_SBI_EXT_SRST, 0, rb);
        ASSERT_EQ(r.action, RVPLAT_SBI_ACTION_REBOOT);
        PASS();
    } _test_next:;
    return failures;
}

/* riscv/riscv/timer.c: et_start arms now+counts (:119-122), the interrupt
 * handler disarms with -1UL (:146-149), stop only clears SIE.STIE. */
static int t_timer_freebsd_arm_ack_rearm(void)
{
    int failures = 0;
    TEST("rvplat timer: FreeBSD arm, interrupt ack by disarm, re-arm") {
        struct rvplat_timer t;
        rvplat_timer_init(&t, 4);
        uint64_t ticks = 400; /* time 100 */
        rvplat_timer_set_timer(&t, rvplat_timer_time(&t, ticks) + 25);
        ASSERT(!rvplat_timer_pending(&t, rvplat_timer_time(&t, ticks)));
        ASSERT_EQ(rvplat_timer_next_event(&t, rvplat_timer_time(&t, ticks)), 25u);
        ASSERT_EQ(rvplat_timer_next_event_ticks(&t, ticks), 500u);
        ticks = 500;
        ASSERT(rvplat_timer_pending(&t, rvplat_timer_time(&t, ticks)));
        rvplat_timer_set_timer(&t, UINT64_MAX); /* handler ack */
        ASSERT(!rvplat_timer_pending(&t, rvplat_timer_time(&t, ticks)));
        ASSERT_EQ(rvplat_timer_next_event_ticks(&t, ticks), UINT64_MAX);
        rvplat_timer_set_timer(&t, 130); /* re-arm */
        ASSERT_EQ(rvplat_timer_next_event_ticks(&t, ticks), 520u);
        rvplat_timer_set_timer(&t, 90); /* re-arm into the past: fires now */
        ASSERT(rvplat_timer_pending(&t, rvplat_timer_time(&t, ticks)));
        ASSERT_EQ(rvplat_timer_next_event_ticks(&t, ticks), ticks);
        PASS();
    } _test_next:;
    return failures;
}

static uint8_t u_rd(struct rvplat_uart *u, uint32_t r)
{
    return rvplat_uart_read(u, r);
}

static int t_uart_probe_ns8250_probe(void)
{
    int failures = 0;
    TEST("rvplat uart: ns8250_probe known-zero bits (uart_dev_ns8250.c:344-356)") {
        struct uart_log log = {0};
        struct rvplat_uart u;
        rvplat_uart_init(&u, uart_tx, &log);
        ASSERT_EQ(u_rd(&u, RVPLAT_UART_IIR) & 0x30u, 0u);
        ASSERT_EQ(u_rd(&u, RVPLAT_UART_MCR) & 0xA0u, 0u);
        /* ns8250_init: MCR = IE|RTS|DTR, FCR 0, IER upper bits preserved */
        rvplat_uart_write(&u, RVPLAT_UART_MCR, 0x0B);
        ASSERT_EQ(u_rd(&u, RVPLAT_UART_MCR) & 0xA0u, 0u);
        rvplat_uart_write(&u, RVPLAT_UART_IER, 0xE0);
        ASSERT_EQ(u_rd(&u, RVPLAT_UART_IER) & 0xE0u, 0u); /* not writable */
        rvplat_uart_write(&u, RVPLAT_UART_SCR, 0x5A);
        ASSERT_EQ(u_rd(&u, RVPLAT_UART_SCR), 0x5Au);
        ASSERT_EQ(u_rd(&u, RVPLAT_UART_LSR) & (RVPLAT_UART_LSR_THRE | RVPLAT_UART_LSR_TEMT),
                  RVPLAT_UART_LSR_THRE | RVPLAT_UART_LSR_TEMT);
        PASS();
    } _test_next:;
    return failures;
}

/* Replays ns8250_bus_probe (uart_dev_ns8250.c:872-998) register by register. */
static int t_uart_bus_probe_fifo_sizing(void)
{
    int failures = 0;
    TEST("rvplat uart: ns8250_bus_probe loopback FIFO sizing computes 16, no console output") {
        struct uart_log log = {0};
        struct rvplat_uart u;
        rvplat_uart_init(&u, uart_tx, &log);
        rvplat_uart_write(&u, RVPLAT_UART_MCR, 0x0B);          /* init: IE|RTS|DTR */
        rvplat_uart_write(&u, RVPLAT_UART_IIR, 0);              /* FCR = 0 */
        /* :902 loopback, :910 FCR enable, :912 IIR must show FIFO */
        rvplat_uart_write(&u, RVPLAT_UART_MCR, 0x10 | 0x08 | 0x01 | 0x02);
        ASSERT_EQ(u_rd(&u, RVPLAT_UART_MSR), 0xB0u); /* CTS|DSR|DCD follow MCR */
        rvplat_uart_write(&u, RVPLAT_UART_IIR, 0x01);
        ASSERT((u_rd(&u, RVPLAT_UART_IIR) & 0xC0u) != 0u);
        rvplat_uart_write(&u, RVPLAT_UART_IIR, 0x01 | 0x04 | 0x02); /* :924 reset */
        /* :931 drain: LSR.RXRDY clear */
        ASSERT_EQ(u_rd(&u, RVPLAT_UART_LSR) & RVPLAT_UART_LSR_DR, 0u);
        int count = 0;
        uint8_t lsr;
        do {
            rvplat_uart_write(&u, RVPLAT_UART_RBR, 0); /* :947 */
            count++;
            int limit = 30;
            lsr = 0;
            while (((lsr |= u_rd(&u, RVPLAT_UART_LSR)) & RVPLAT_UART_LSR_TEMT) == 0 &&
                   --limit) {}
            ASSERT(limit != 0);
        } while ((lsr & RVPLAT_UART_LSR_OE) == 0 && count < 260);
        count--;
        ASSERT_EQ(count, 16); /* 14..16 -> "16550 or compatible", rxfifosz 16 */
        ASSERT_EQ(log.n, 0u); /* nothing reached the console */
        rvplat_uart_write(&u, RVPLAT_UART_MCR, 0x0B);          /* :973 restore */
        ASSERT_EQ(u_rd(&u, RVPLAT_UART_MSR), 0u);
        /* :976 ns8250_flush: FCR enable|XMT_RST|RCV_RST, then LSR.RXRDY clear */
        rvplat_uart_write(&u, RVPLAT_UART_IIR, 0x01 | 0x04 | 0x02);
        ASSERT_EQ(u_rd(&u, RVPLAT_UART_LSR) & RVPLAT_UART_LSR_DR, 0u);
        /* and the line is usable again: THR reaches the console */
        rvplat_uart_write(&u, RVPLAT_UART_RBR, 'k');
        ASSERT_EQ(log.n, 1u);
        PASS();
    } _test_next:;
    return failures;
}

static int t_uart_loopback_msr(void)
{
    int failures = 0;
    TEST("rvplat uart: loopback MSR mirrors MCR outputs, FIFO holds looped bytes in order") {
        struct uart_log log = {0};
        struct rvplat_uart u;
        rvplat_uart_init(&u, uart_tx, &log);
        rvplat_uart_write(&u, RVPLAT_UART_MCR, 0x1F);
        ASSERT_EQ(u_rd(&u, RVPLAT_UART_MSR), 0xF0u);
        rvplat_uart_write(&u, RVPLAT_UART_MCR, 0x14); /* loop|OUT1 */
        ASSERT_EQ(u_rd(&u, RVPLAT_UART_MSR), RVPLAT_UART_MSR_RI);
        rvplat_uart_write(&u, RVPLAT_UART_RBR, 'a');
        rvplat_uart_write(&u, RVPLAT_UART_RBR, 'b');
        ASSERT_EQ(log.n, 0u);
        ASSERT(u_rd(&u, RVPLAT_UART_LSR) & RVPLAT_UART_LSR_DR);
        ASSERT_EQ(u_rd(&u, RVPLAT_UART_RBR), 'a');
        ASSERT_EQ(u_rd(&u, RVPLAT_UART_RBR), 'b');
        ASSERT_EQ(u_rd(&u, RVPLAT_UART_LSR) & RVPLAT_UART_LSR_DR, 0u);
        rvplat_uart_write(&u, RVPLAT_UART_MCR, 0x0F); /* loopback off */
        ASSERT_EQ(u_rd(&u, RVPLAT_UART_MSR), 0u);
        rvplat_uart_write(&u, RVPLAT_UART_RBR, 'c');
        ASSERT_EQ(log.n, 1u);
        PASS();
    } _test_next:;
    return failures;
}

/* ns8250_clrint (:113-132) must terminate with every cause pending. */
static int t_uart_clrint_terminates(void)
{
    int failures = 0;
    TEST("rvplat uart: ns8250_clrint drains RLS, RXRDY and THRE causes") {
        struct uart_log log = {0};
        struct rvplat_uart u;
        rvplat_uart_init(&u, uart_tx, &log);
        rvplat_uart_write(&u, RVPLAT_UART_IER, 0x0F);
        for (int i = 0; i < 20; i++) rvplat_uart_rx(&u, (uint8_t)i); /* overrun */
        rvplat_uart_write(&u, RVPLAT_UART_RBR, 'x'); /* THRE latch */
        int guard = 0;
        uint8_t iir = u_rd(&u, RVPLAT_UART_IIR);
        while ((iir & RVPLAT_UART_IIR_NONE) == 0 && guard++ < 64) {
            uint8_t cause = iir & 0x0F;
            if (cause == RVPLAT_UART_IIR_RLS)
                (void)u_rd(&u, RVPLAT_UART_LSR);
            else if (cause == RVPLAT_UART_IIR_RDA)
                (void)u_rd(&u, RVPLAT_UART_RBR);
            iir = u_rd(&u, RVPLAT_UART_IIR);
        }
        ASSERT(guard < 64);
        ASSERT(!rvplat_uart_irq(&u));
        PASS();
    } _test_next:;
    return failures;
}

int test_rvplat(void)
{
    return t_plic_order() + t_plic_threshold() + t_plic_claim_complete() +
           t_plic_enables() + t_plic_mmio() + t_timer_deadline() +
           t_timer_overflow() + t_sbi_probe() + t_sbi_legacy_probe() +
           t_sbi_base() + t_sbi_timer_ipi_rfence_hsm() + t_sbi_srst() +
           t_sbi_console() + t_uart_rx_irq() + t_uart_overrun() +
           t_uart_dlab() + t_plic_claim_ignores_threshold() +
           t_sbi_empty_hart_set() + t_sbi_legacy_clear_ipi() +
           t_sbi_freebsd_sbi_init() + t_timer_freebsd_arm_ack_rearm() +
           t_uart_probe_ns8250_probe() + t_uart_bus_probe_fifo_sizing() +
           t_uart_loopback_msr() + t_uart_clrint_terminates();
}
