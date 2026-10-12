/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: the machine's device tree (contract v1): one cpu with its local
 * interrupt controller, RAM, a simple-bus with the PLIC, the serial port and
 * the eight virtio mmio slots, and the chosen node. */
#include "rvmachine/rvmachine.h"

#include "base/serialize_le.h"
#include "fdt/fdt.h"

#include <stdio.h>
#include <string.h>

#define PHANDLE_CPU_INTC 1u
#define PHANDLE_PLIC 2u
#define IRQ_M_EXTERNAL 11u
#define IRQ_S_EXTERNAL 9u

/* The first failure sticks; later calls are skipped. */
struct dtb {
    struct fdt_writer w;
    enum fdt_status st;
};

static void begin(struct dtb *d, const char *name)
{
    if (d->st == FDT_OK) d->st = fdt_begin_node(&d->w, name);
}

static void end(struct dtb *d)
{
    if (d->st == FDT_OK) d->st = fdt_end_node(&d->w);
}

static void p_u32(struct dtb *d, const char *name, uint32_t v)
{
    if (d->st == FDT_OK) d->st = fdt_prop_u32(&d->w, name, v);
}

static void p_str(struct dtb *d, const char *name, const char *v)
{
    if (d->st == FDT_OK) d->st = fdt_prop_string(&d->w, name, v);
}

static void p_empty(struct dtb *d, const char *name)
{
    if (d->st == FDT_OK) d->st = fdt_prop(&d->w, name, NULL, 0);
}

static void p_cells(struct dtb *d, const char *name, const uint32_t *cells, size_t n)
{
    uint8_t be[32];
    if (d->st != FDT_OK) return;
    if (n > sizeof be / 4u) {
        d->st = FDT_ERR_ARG;
        return;
    }
    for (size_t i = 0; i < n; i++) zcl_write_u32_be(be + 4u * i, cells[i]);
    d->st = fdt_prop(&d->w, name, be, 4u * n);
}

/* reg with two address cells and two size cells. */
static void p_reg(struct dtb *d, uint64_t addr, uint64_t size)
{
    const uint32_t cells[4] = {(uint32_t)(addr >> 32), (uint32_t)addr,
                               (uint32_t)(size >> 32), (uint32_t)size};
    p_cells(d, "reg", cells, 4);
}

static void begin_at(struct dtb *d, const char *base, uint64_t addr)
{
    char name[FDT_MAX_NAME + 1u];
    snprintf(name, sizeof name, "%s@%llx", base, (unsigned long long)addr);
    begin(d, name);
}

static void node_cpus(struct dtb *d)
{
    begin(d, "cpus");
    p_u32(d, "#address-cells", 1);
    p_u32(d, "#size-cells", 0);
    p_u32(d, "timebase-frequency", RVMACHINE_TIMEBASE_HZ);
    begin(d, "cpu@0");
    p_str(d, "device_type", "cpu");
    p_u32(d, "reg", 0);
    p_str(d, "status", "okay");
    p_str(d, "compatible", "riscv");
    p_str(d, "riscv,isa", "rv64imafdc");
    p_str(d, "mmu-type", "riscv,sv39");
    begin(d, "interrupt-controller");
    p_u32(d, "#interrupt-cells", 1);
    p_empty(d, "interrupt-controller");
    p_str(d, "compatible", "riscv,cpu-intc");
    p_u32(d, "phandle", PHANDLE_CPU_INTC);
    end(d);
    end(d);
    end(d);
}

static void node_memory(struct dtb *d, uint64_t ram_bytes)
{
    begin_at(d, "memory", RVMACHINE_RAM_BASE);
    p_str(d, "device_type", "memory");
    p_reg(d, RVMACHINE_RAM_BASE, ram_bytes);
    end(d);
}

/* Context 0 is the machine external line (unused), context 1 the supervisor
 * one; a kernel indexes contexts by position in interrupts-extended. */
static void node_plic(struct dtb *d)
{
    static const char *const compat[2] = {"sifive,plic-1.0.0", "riscv,plic0"};
    const uint32_t ext[4] = {PHANDLE_CPU_INTC, IRQ_M_EXTERNAL, PHANDLE_CPU_INTC,
                             IRQ_S_EXTERNAL};
    begin_at(d, "plic", RVMACHINE_PLIC_BASE);
    if (d->st == FDT_OK) d->st = fdt_prop_strings(&d->w, "compatible", compat, 2);
    p_reg(d, RVMACHINE_PLIC_BASE, RVMACHINE_PLIC_SIZE);
    p_u32(d, "#address-cells", 0);
    p_u32(d, "#interrupt-cells", 1);
    p_empty(d, "interrupt-controller");
    p_cells(d, "interrupts-extended", ext, 4);
    p_u32(d, "riscv,ndev", RVMACHINE_PLIC_NDEV);
    p_u32(d, "phandle", PHANDLE_PLIC);
    end(d);
}

static void node_serial(struct dtb *d)
{
    begin_at(d, "serial", RVMACHINE_UART_BASE);
    p_str(d, "compatible", "ns16550a");
    p_reg(d, RVMACHINE_UART_BASE, RVMACHINE_UART_SIZE);
    p_u32(d, "interrupts", RVMACHINE_UART_IRQ);
    p_u32(d, "interrupt-parent", PHANDLE_PLIC);
    p_u32(d, "clock-frequency", RVMACHINE_UART_CLOCK);
    p_u32(d, "reg-shift", 0);
    p_u32(d, "reg-io-width", 1);
    p_u32(d, "current-speed", RVMACHINE_UART_SPEED);
    end(d);
}

static void node_virtio(struct dtb *d, unsigned slot)
{
    uint64_t base = RVMACHINE_VIRTIO_BASE + slot * RVMACHINE_VIRTIO_STRIDE;
    begin_at(d, "virtio_mmio", base);
    p_str(d, "compatible", "virtio,mmio");
    p_reg(d, base, RVMACHINE_VIRTIO_STRIDE);
    p_u32(d, "interrupts", RVMACHINE_VIRTIO_IRQ0 + slot);
    p_u32(d, "interrupt-parent", PHANDLE_PLIC);
    end(d);
}

static void node_soc(struct dtb *d)
{
    begin(d, "soc");
    p_u32(d, "#address-cells", 2);
    p_u32(d, "#size-cells", 2);
    p_str(d, "compatible", "simple-bus");
    p_empty(d, "ranges");
    node_plic(d);
    node_serial(d);
    for (unsigned slot = 0; slot < RVMACHINE_VIRTIO_SLOTS; slot++)
        node_virtio(d, slot);
    end(d);
}

static void node_chosen(struct dtb *d, const char *bootargs)
{
    char path[64];
    snprintf(path, sizeof path, "/soc/serial@%llx",
             (unsigned long long)RVMACHINE_UART_BASE);
    begin(d, "chosen");
    p_str(d, "stdout-path", path);
    p_str(d, "bootargs", bootargs != NULL ? bootargs : "");
    end(d);
}

enum rvmachine_status rvmachine_build_dtb(uint64_t ram_bytes, const char *bootargs,
                                          uint8_t *buf, size_t cap, size_t *len)
{
    struct dtb d;
    if (buf == NULL || len == NULL) return RVMACHINE_ERR_ARG;
    if (bootargs != NULL && strlen(bootargs) >= RVMACHINE_BOOTARGS_MAX)
        return RVMACHINE_ERR_ARG;
    d.st = fdt_writer_init(&d.w, buf, cap);
    begin(&d, "");
    p_u32(&d, "#address-cells", 2);
    p_u32(&d, "#size-cells", 2);
    p_str(&d, "compatible", "zclassic23,rvmachine-v1");
    p_str(&d, "model", "zclassic23,rvmachine-v1");
    node_chosen(&d, bootargs);
    node_cpus(&d);
    node_memory(&d, ram_bytes);
    node_soc(&d);
    end(&d);
    if (d.st == FDT_OK) d.st = fdt_finish(&d.w, len);
    if (d.st == FDT_OK) d.st = fdt_check(buf, *len);
    return d.st == FDT_OK ? RVMACHINE_OK : RVMACHINE_ERR_FDT;
}
