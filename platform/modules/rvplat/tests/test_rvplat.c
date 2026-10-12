/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: standalone package smoke test for the rvplat device models; the
 * full behavioural proofs live in tests/harness/src/test_rvplat.c. */
#include "rvplat/plic.h"
#include "rvplat/sbi.h"
#include "rvplat/timer.h"
#include "rvplat/uart.h"

#include <stdio.h>

#define CHECK(expr) do { if (!(expr)) { \
    fprintf(stderr, "rvplat test failed: %s:%d: %s\n", __FILE__, __LINE__, #expr); \
    return 1; \
} } while (0)

static uint8_t sent;

static void tx(void *ctx, uint8_t byte)
{
    (void)ctx;
    sent = byte;
}

int main(void)
{
    struct rvplat_plic plic;
    rvplat_plic_init(&plic, 8);
    rvplat_plic_write(&plic, RVPLAT_PLIC_PRIORITY_BASE + 4u * 3u, 2);
    rvplat_plic_write(&plic, RVPLAT_PLIC_ENABLE_BASE + RVPLAT_PLIC_ENABLE_STRIDE, 1u << 3);
    rvplat_plic_set_source(&plic, 3, true);
    CHECK(rvplat_plic_context_pending(&plic, RVPLAT_PLIC_CTX_S));
    CHECK(!rvplat_plic_context_pending(&plic, RVPLAT_PLIC_CTX_M));
    CHECK(rvplat_plic_claim(&plic, RVPLAT_PLIC_CTX_S) == 3u);
    CHECK(!rvplat_plic_context_pending(&plic, RVPLAT_PLIC_CTX_S));
    rvplat_plic_complete(&plic, RVPLAT_PLIC_CTX_S, 3);
    CHECK(rvplat_plic_context_pending(&plic, RVPLAT_PLIC_CTX_S));

    struct rvplat_timer timer;
    rvplat_timer_init(&timer, 10);
    CHECK(rvplat_timer_next_event(&timer, 0) == UINT64_MAX);
    rvplat_timer_set_timer(&timer, 5);
    CHECK(!rvplat_timer_pending(&timer, 4));
    CHECK(rvplat_timer_pending(&timer, 5));
    CHECK(rvplat_timer_next_event_ticks(&timer, 0) == 50u);

    struct rvplat_sbi sbi;
    rvplat_sbi_init(&sbi);
    uint64_t args[6] = {1, 0, 0, 0, 0, 0};
    struct rvplat_sbi_ret ret = rvplat_sbi_call(&sbi, RVPLAT_SBI_EXT_BASE, 3, args);
    CHECK(ret.error == 0 && ret.value == 1u);
    ret = rvplat_sbi_call(&sbi, 0xDEADu, 0, args);
    CHECK(ret.error == RVPLAT_SBI_ERR_NOT_SUPPORTED);

    struct rvplat_uart uart;
    rvplat_uart_init(&uart, tx, NULL);
    rvplat_uart_write(&uart, RVPLAT_UART_IER, RVPLAT_UART_IER_RDA);
    rvplat_uart_rx(&uart, 'z');
    CHECK(rvplat_uart_irq(&uart));
    CHECK(rvplat_uart_read(&uart, RVPLAT_UART_RBR) == 'z');
    rvplat_uart_write(&uart, RVPLAT_UART_RBR, 'q');
    CHECK(sent == 'q');
    return 0;
}
