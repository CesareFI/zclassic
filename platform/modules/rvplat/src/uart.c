/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: ns16550 UART written from the 16550 register set (RBR/THR/DLL,
 * IER/DLM, IIR/FCR, LCR, MCR, LSR, MSR, SCR). Transmit is instantaneous, so
 * the transmitter is always empty; loopback mirrors MCR outputs into MSR; there is no other modem model. */
#include "rvplat/uart.h"

#include <stddef.h>

void rvplat_uart_init(struct rvplat_uart *uart,
                      void (*tx)(void *ctx, uint8_t byte), void *ctx)
{
    *uart = (struct rvplat_uart){0};
    uart->tx = tx;
    uart->ctx = ctx;
}

void rvplat_uart_rx(struct rvplat_uart *uart, uint8_t byte)
{
    if (uart->rx_count >= RVPLAT_UART_FIFO_SIZE) {
        uart->overrun = true;
        return;
    }
    uint32_t tail = ((uint32_t)uart->rx_head + uart->rx_count) %
                    RVPLAT_UART_FIFO_SIZE;
    uart->rx[tail] = byte;
    uart->rx_count++;
}

static bool dlab(const struct rvplat_uart *uart)
{
    return (uart->lcr & RVPLAT_UART_LCR_DLAB) != 0u;
}

static uint8_t rx_pop(struct rvplat_uart *uart)
{
    if (uart->rx_count == 0u)
        return 0u;
    uint8_t byte = uart->rx[uart->rx_head];
    uart->rx_head = (uint8_t)((uart->rx_head + 1u) % RVPLAT_UART_FIFO_SIZE);
    uart->rx_count--;
    return byte;
}

/* Highest-priority pending cause, or RVPLAT_UART_IIR_NONE. Priorities:
 * receiver line status, received data, transmitter empty. */
static uint8_t iir_cause(const struct rvplat_uart *uart)
{
    if ((uart->ier & RVPLAT_UART_IER_RLS) != 0u && uart->overrun)
        return RVPLAT_UART_IIR_RLS;
    if ((uart->ier & RVPLAT_UART_IER_RDA) != 0u && uart->rx_count != 0u)
        return RVPLAT_UART_IIR_RDA;
    if ((uart->ier & RVPLAT_UART_IER_THRE) != 0u && uart->thre_irq)
        return RVPLAT_UART_IIR_THRE;
    return RVPLAT_UART_IIR_NONE;
}

bool rvplat_uart_irq(const struct rvplat_uart *uart)
{
    return iir_cause(uart) != RVPLAT_UART_IIR_NONE;
}

uint16_t rvplat_uart_divisor(const struct rvplat_uart *uart)
{
    return (uint16_t)(((uint32_t)uart->dlm << 8) | uart->dll);
}

static uint8_t read_iir(struct rvplat_uart *uart)
{
    uint8_t cause = iir_cause(uart);
    if (cause == RVPLAT_UART_IIR_THRE)
        uart->thre_irq = false; /* reading IIR acknowledges it */
    if ((uart->fcr & 1u) != 0u)
        cause |= RVPLAT_UART_IIR_FIFO;
    return cause;
}

static uint8_t read_lsr(struct rvplat_uart *uart)
{
    uint8_t lsr = RVPLAT_UART_LSR_THRE | RVPLAT_UART_LSR_TEMT;
    if (uart->rx_count != 0u)
        lsr |= RVPLAT_UART_LSR_DR;
    if (uart->overrun)
        lsr |= RVPLAT_UART_LSR_OE;
    uart->overrun = false;
    return lsr;
}

static bool loopback(const struct rvplat_uart *uart)
{
    return (uart->mcr & RVPLAT_UART_MCR_LOOP) != 0u;
}

/* 16550 loopback: the modem inputs read back the MCR outputs. */
static uint8_t read_msr(const struct rvplat_uart *uart)
{
    uint8_t msr = 0u;
    if (!loopback(uart))
        return 0u;
    if ((uart->mcr & RVPLAT_UART_MCR_RTS) != 0u)
        msr |= RVPLAT_UART_MSR_CTS;
    if ((uart->mcr & RVPLAT_UART_MCR_DTR) != 0u)
        msr |= RVPLAT_UART_MSR_DSR;
    if ((uart->mcr & RVPLAT_UART_MCR_OUT1) != 0u)
        msr |= RVPLAT_UART_MSR_RI;
    if ((uart->mcr & RVPLAT_UART_MCR_OUT2) != 0u)
        msr |= RVPLAT_UART_MSR_DCD;
    return msr;
}

uint8_t rvplat_uart_read(struct rvplat_uart *uart, uint32_t offset)
{
    switch (offset & 7u) {
    case RVPLAT_UART_RBR: return dlab(uart) ? uart->dll : rx_pop(uart);
    case RVPLAT_UART_IER: return dlab(uart) ? uart->dlm : uart->ier;
    case RVPLAT_UART_IIR: return read_iir(uart);
    case RVPLAT_UART_LCR: return uart->lcr;
    case RVPLAT_UART_MCR: return uart->mcr;
    case RVPLAT_UART_LSR: return read_lsr(uart);
    case RVPLAT_UART_MSR: return read_msr(uart);
    default: return uart->scr;
    }
}

static void write_thr(struct rvplat_uart *uart, uint8_t value)
{
    if (loopback(uart))
        rvplat_uart_rx(uart, value);
    else if (uart->tx != NULL)
        uart->tx(uart->ctx, value);
    uart->thre_irq = true; /* holding register is immediately empty again */
}

static void write_ier(struct rvplat_uart *uart, uint8_t value)
{
    value &= RVPLAT_UART_IER_MASK;
    /* Enabling the transmit-empty interrupt with an empty THR raises it. */
    if ((value & RVPLAT_UART_IER_THRE) != 0u &&
        (uart->ier & RVPLAT_UART_IER_THRE) == 0u)
        uart->thre_irq = true;
    uart->ier = value;
}

static void write_fcr(struct rvplat_uart *uart, uint8_t value)
{
    uart->fcr = value & 1u;
    if ((value & 2u) != 0u) { /* clear receive FIFO */
        uart->rx_head = 0u;
        uart->rx_count = 0u;
    }
}

void rvplat_uart_write(struct rvplat_uart *uart, uint32_t offset, uint8_t value)
{
    switch (offset & 7u) {
    case RVPLAT_UART_RBR:
        if (dlab(uart))
            uart->dll = value;
        else
            write_thr(uart, value);
        break;
    case RVPLAT_UART_IER:
        if (dlab(uart))
            uart->dlm = value;
        else
            write_ier(uart, value);
        break;
    case RVPLAT_UART_IIR: write_fcr(uart, value); break;
    case RVPLAT_UART_LCR: uart->lcr = value; break;
    case RVPLAT_UART_MCR: uart->mcr = value & 0x1Fu; break;
    case RVPLAT_UART_SCR: uart->scr = value; break;
    default: break; /* LSR and MSR are read-only */
    }
}
