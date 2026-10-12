/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: ns16550 UART model: register file, 16-byte receive FIFO, transmit
 * to a caller callback, and an interrupt line. */
#ifndef RVPLAT_UART_H
#define RVPLAT_UART_H

#include <stdbool.h>
#include <stdint.h>

#define RVPLAT_UART_FIFO_SIZE 16u

/* Register offsets (reg-shift 0); DLAB selects the aliased registers. */
enum rvplat_uart_reg {
    RVPLAT_UART_RBR = 0, /* read; THR on write; DLL when DLAB */
    RVPLAT_UART_IER = 1, /* DLM when DLAB */
    RVPLAT_UART_IIR = 2, /* read; FCR on write */
    RVPLAT_UART_LCR = 3,
    RVPLAT_UART_MCR = 4,
    RVPLAT_UART_LSR = 5,
    RVPLAT_UART_MSR = 6,
    RVPLAT_UART_SCR = 7,
};

#define RVPLAT_UART_IER_RDA  0x01u
#define RVPLAT_UART_IER_THRE 0x02u
#define RVPLAT_UART_IER_RLS  0x04u
#define RVPLAT_UART_IER_MASK 0x0Fu
#define RVPLAT_UART_LCR_DLAB 0x80u
#define RVPLAT_UART_MCR_DTR  0x01u
#define RVPLAT_UART_MCR_RTS  0x02u
#define RVPLAT_UART_MCR_OUT1 0x04u
#define RVPLAT_UART_MCR_OUT2 0x08u
#define RVPLAT_UART_MCR_LOOP 0x10u
#define RVPLAT_UART_MSR_CTS  0x10u
#define RVPLAT_UART_MSR_DSR  0x20u
#define RVPLAT_UART_MSR_RI   0x40u
#define RVPLAT_UART_MSR_DCD  0x80u
#define RVPLAT_UART_LSR_DR   0x01u
#define RVPLAT_UART_LSR_OE   0x02u
#define RVPLAT_UART_LSR_THRE 0x20u
#define RVPLAT_UART_LSR_TEMT 0x40u
#define RVPLAT_UART_IIR_NONE 0x01u
#define RVPLAT_UART_IIR_RLS  0x06u
#define RVPLAT_UART_IIR_RDA  0x04u
#define RVPLAT_UART_IIR_THRE 0x02u
#define RVPLAT_UART_IIR_FIFO 0xC0u

struct rvplat_uart {
    uint8_t rx[RVPLAT_UART_FIFO_SIZE];
    uint8_t rx_head;
    uint8_t rx_count;
    uint8_t ier, lcr, mcr, scr, fcr, dll, dlm;
    bool overrun;   /* LSR.OE, cleared by an LSR read */
    bool thre_irq;  /* transmit-empty interrupt latch */
    void (*tx)(void *ctx, uint8_t byte);
    void *ctx;
};

void rvplat_uart_init(struct rvplat_uart *uart,
                      void (*tx)(void *ctx, uint8_t byte), void *ctx);

/* Deliver one received byte. A full FIFO drops it and latches LSR.OE. */
void rvplat_uart_rx(struct rvplat_uart *uart, uint8_t byte);

/* While MCR.LOOP is set a byte written to THR goes to the model's own receive
 * FIFO (overrun sets LSR.OE when full) and never reaches the tx callback; MSR
 * then mirrors the MCR outputs (RTS->CTS, DTR->DSR, OUT1->RI, OUT2->DCD). Out
 * of loopback MSR reads 0.
 *
 * Registers are read with side effects (RBR pops, LSR clears OE, IIR clears
 * a transmit-empty indication). Offsets are masked to 0..7. */
uint8_t rvplat_uart_read(struct rvplat_uart *uart, uint32_t offset);
void rvplat_uart_write(struct rvplat_uart *uart, uint32_t offset,
                       uint8_t value);

/* Level of the interrupt output (to be fed to rvplat_plic_set_source). */
bool rvplat_uart_irq(const struct rvplat_uart *uart);

/* Baud divisor latch (DLM:DLL). */
uint16_t rvplat_uart_divisor(const struct rvplat_uart *uart);

#endif
