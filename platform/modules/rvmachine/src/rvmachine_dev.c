/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: the machine's devices and their bus decode. Every physical access
 * outside RAM arrives here from the engine: the PLIC, the ns16550 and the
 * eight virtio mmio slots. An address nothing answers is an access fault. */
#include "rvmachine_priv.h"
#include "base/log_macros.h"
#include "base/cleanse.h"

#include <limits.h>
#include <string.h>

#define UART_REGS 8u
static bool virtio_mem_read(void *ctx, uint64_t gpa, void *buf, size_t n);
static bool virtio_mem_write(void *ctx, uint64_t gpa, const void *buf, size_t n);

/* ---- bounded named byte ports ---- */

static bool conport_valid(const struct rvmachine *m, unsigned port)
{
    if (m != NULL && port < m->conport_count && !m->con.busy &&
        !m->conports[port].retired && !m->conport_fault) return true;
    LOG_WARN("rvmachine", "byte port refused: invalid, retired or reentrant port %u", port);
    return false;
}

static void conport_discard_queue(struct rvmachine_conport *p)
{
    p->discarded = machine_time_add(p->discarded, p->count);
    if (p->private_keyfile) memory_cleanse(p->bytes, sizeof p->bytes);
    else memset(p->bytes, 0, sizeof p->bytes);
    p->head = 0;
    p->count = 0;
    p->stalled = false;
    p->writable = false;
}

static void conport_new_epoch(struct rvmachine *m, unsigned port)
{
    struct rvmachine_conport *p = &m->conports[port];
    conport_discard_queue(p);
    p->blocked = false;
    p->tx_more = false;
    p->tx_left = RVMACHINE_CONPORT_ROUND_BYTES;
    if (p->generation == UINT32_MAX) {
        p->retired = true;
        rvvirtio_console_port_close(&m->con, port);
        LOG_WARN("rvmachine", "byte port %u retired: generation exhausted", port);
    } else {
        p->generation++;
    }
    p->seen_generation = rvvirtio_console_port_generation(&m->con, port);
}

static void conport_sync_epochs(struct rvmachine *m)
{
    for (unsigned port = 0; port < m->conport_count; port++) {
        if (m->conports[port].seen_generation !=
            rvvirtio_console_port_generation(&m->con, port))
            conport_new_epoch(m, port);
    }
}

bool rvmachine_conport_configure(struct rvmachine *m,
                                const struct rvmachine_config *c)
{
    if (c->private_keyfile_port_plus_one > c->conport_count ||
        (c->private_keyfile_port_plus_one != 0u && !c->cleanse_on_destroy)) {
        LOG_WARN("rvmachine", "private keyfile port refused: index or cleanse policy");
        return false;
    }
    if (c->conport_count > RVMACHINE_CONPORT_MAX ||
        (c->conport_count != 0u && c->conport_sink == NULL)) {
        LOG_WARN("rvmachine", "byte ports refused: count or sink invalid");
        return false;
    }
    for (unsigned port = 0; port < c->conport_count; port++) {
        const char *name = c->conport_names[port];
        if (name == NULL || name[0] == '\0' ||
            strlen(name) >= RVVIRTIO_CONSOLE_NAME_MAX) {
            LOG_WARN("rvmachine", "byte port %u refused: name empty or too long", port);
            return false;
        }
        for (unsigned prior = 0; prior < port; prior++) {
            if (strcmp(name, m->conport_names[prior]) == 0) {
                LOG_WARN("rvmachine", "byte port %u refused: duplicate name", port);
                return false;
            }
        }
        memcpy(m->conport_names[port], name, strlen(name) + 1u);
        m->conports[port].tx_left = RVMACHINE_CONPORT_ROUND_BYTES;
        m->conports[port].generation = 1u;
        m->conports[port].private_keyfile = c->private_keyfile_port_plus_one == port + 1u;
    }
    m->conport_count = c->conport_count;
    m->conport_sink = c->conport_sink;
    m->conport_ctx = c->conport_ctx;
    return true;
}

static bool conport_irq_enabled(const struct rvmachine *m)
{
    const unsigned source = RVMACHINE_VIRTIO_IRQ0 + RVMACHINE_VIRTIO_SLOT_CONSOLE;
    return (m->hart.csr.mie & (UINT64_C(1) << RVEMU_IRQ_SEIP)) != 0u &&
        (m->plic.enable[RVPLAT_PLIC_CTX_S][source / 32u] &
         (UINT32_C(1) << (source % 32u))) != 0u &&
        m->plic.priority[source] > m->plic.threshold[RVPLAT_PLIC_CTX_S];
}

static bool conport_running(const struct rvmachine *m)
{
    return (m->con.dev.status & RVVIRTIO_STATUS_DRIVER_OK) != 0u &&
        (m->con.dev.status & RVVIRTIO_STATUS_NEEDS_RESET) == 0u;
}

static bool conport_rx_ready(const struct rvmachine *m, unsigned port)
{
    const struct rvmachine_conport *p = &m->conports[port];
    return p->count != 0u && m->con.ports[port].host_open &&
        m->con.ports[port].guest_open && (!p->stalled || p->writable) &&
        conport_running(m);
}

/* Service does not require interrupt delivery: a running guest may poll. */
static bool conport_service_ready(const struct rvmachine *m, unsigned port)
{
    const struct rvmachine_conport *p = &m->conports[port];
    if (p->retired || m->conport_fault) return false;
    return conport_rx_ready(m, port) ||
        (p->tx_more && !p->blocked && m->con.ports[port].host_open &&
         conport_running(m));
}

static unsigned conport_pending_flags(const struct rvmachine *m, unsigned port)
{
    const struct rvmachine_conport *p = &m->conports[port];
    if (p->retired || m->conport_fault) return 0;
    unsigned flags = p->blocked ? RVMACHINE_PENDING_PORT_BLOCKED : 0u;
    if (conport_service_ready(m, port)) {
        flags |= conport_irq_enabled(m) ? RVMACHINE_PENDING_PORT :
                                         RVMACHINE_PENDING_PORT_HELD;
    } else if (p->count != 0u) {
        flags |= RVMACHINE_PENDING_PORT_HELD;
    }
    return flags;
}

unsigned rvmachine_conport_pending(const struct rvmachine *m, unsigned port)
{
    return conport_valid(m, port) ? conport_pending_flags(m, port) : 0u;
}

size_t rvmachine_conport_input(struct rvmachine *m, unsigned port,
                              const uint8_t *bytes, size_t n)
{
    if (!conport_valid(m, port)) return 0;
    if (m->conports[port].private_keyfile) {
        LOG_WARN("rvmachine", "public byte injection refused: private keyfile port");
        return 0;
    }
    if (bytes == NULL && n != 0u) {
        LOG_WARN("rvmachine", "byte port %u input refused: missing bytes", port);
        return 0;
    }
    conport_sync_epochs(m);
    if (!conport_valid(m, port)) return 0;
    struct rvmachine_conport *p = &m->conports[port];
    size_t accepted = RVMACHINE_CONPORT_QUEUE - p->count;
    if (accepted > n) accepted = n;
    for (size_t i = 0; i < accepted; i++)
        p->bytes[(p->head + p->count + i) % RVMACHINE_CONPORT_QUEUE] = bytes[i];
    p->count += accepted;
    if ((rvmachine_conport_pending(m, port) & RVMACHINE_PENDING_PORT) != 0u)
        m->wait_latched = false;
    return accepted;
}

void rvmachine_conport_resume(struct rvmachine *m, unsigned port)
{
    if (!conport_valid(m, port)) return;
    m->conports[port].blocked = false;
    m->conports[port].tx_more = true;
    if ((rvmachine_conport_pending(m, port) & RVMACHINE_PENDING_PORT) != 0u)
        m->wait_latched = false;
}

size_t rvmachine_conport_discard(struct rvmachine *m, unsigned port)
{
    if (!conport_valid(m, port)) return 0;
    size_t discarded = m->conports[port].count;
    conport_discard_queue(&m->conports[port]);
    return discarded;
}

bool rvmachine_public_export_allowed(const struct rvmachine *m)
{
    if (m == NULL) {
        LOG_WARN("rvmachine", "public export refused: absent machine");
        return false;
    }
    for (unsigned port = 0; port < m->conport_count; port++) {
        if (m->conports[port].private_keyfile) {
            LOG_WARN("rvmachine", "public export refused: private keyfile machine");
            return false;
        }
    }
    return true;
}

static bool keyfile_refuse(struct rvmachine *m, unsigned port)
{
    struct rvmachine_conport *p = &m->conports[port];
    p->private_failed = true;
    p->private_sealed = true;
    conport_discard_queue(p);
    m->conport_fault = true;
    LOG_WARN("rvmachine", "keyfile delivery refused: repeated attempt, epoch, size or receiver state");
    return false;
}

bool rvmachine_keyfile_deliver(struct rvmachine *m, unsigned port,
    uint32_t generation, const uint8_t *bytes, size_t n)
{
    if (!conport_valid(m, port)) return false;
    if (!m->conports[port].private_keyfile) {
        LOG_WARN("rvmachine", "keyfile delivery refused: ordinary public port");
        return false;
    }
    conport_sync_epochs(m);
    if (!conport_valid(m, port)) return false;
    struct rvmachine_conport *p = &m->conports[port];
    if (p->private_sealed) return keyfile_refuse(m, port);
    p->private_sealed = true;
    if (generation != p->generation || !bytes || n != 32u || p->count != 0u ||
        !m->con.ports[port].host_open || !m->con.ports[port].guest_open)
        return keyfile_refuse(m, port);
    /* Head may wrap; accept all 32 bytes atomically into the empty queue. */
    for (size_t i = 0; i < n; i++)
        p->bytes[(p->head + i) % RVMACHINE_CONPORT_QUEUE] = bytes[i];
    p->count = n;
    if ((rvmachine_conport_pending(m, port) & RVMACHINE_PENDING_PORT) != 0u)
        m->wait_latched = false;
    return true;
}

bool rvmachine_conport_close(struct rvmachine *m, unsigned port)
{
    if (!conport_valid(m, port)) return false;
    rvvirtio_console_port_close(&m->con, port);
    conport_new_epoch(m, port);
    return true;
}

bool rvmachine_conport_open(struct rvmachine *m, unsigned port)
{
    if (!conport_valid(m, port)) return false;
    if (!rvvirtio_console_port_open(&m->con, port, m->conport_names[port])) {
        LOG_WARN("rvmachine", "byte port %u open refused by device", port);
        return false;
    }
    conport_new_epoch(m, port);
    return !m->conports[port].retired;
}

bool rvmachine_conport_guest_open(const struct rvmachine *m, unsigned port)
{
    return conport_valid(m, port) && m->con.ports[port].guest_open;
}

size_t rvmachine_conport_queued(const struct rvmachine *m, unsigned port)
{
    return conport_valid(m, port) ? m->conports[port].count : 0u;
}

uint32_t rvmachine_conport_generation(const struct rvmachine *m, unsigned port)
{
    return conport_valid(m, port) ? m->conports[port].generation : 0u;
}

size_t rvmachine_conport_consumed(struct rvmachine *m, unsigned port)
{
    return conport_valid(m, port) ? rvvirtio_console_port_consumed(&m->con, port) : 0u;
}

static size_t conport_from_guest(void *ctx, uint32_t port,
                                 const uint8_t *bytes, size_t n)
{
    struct rvmachine *m = ctx;
    struct rvmachine_conport *p = &m->conports[port];
    if (p->private_keyfile) {
        p->private_failed = true;
        p->private_sealed = true;
        conport_discard_queue(p);
        m->conport_fault = true;
        LOG_WARN("rvmachine", "private keyfile port refused: guest TX is prohibited");
        return 0;
    }
    size_t take = n < p->tx_left ? n : p->tx_left;
    if (take == 0u) {
        p->tx_more = true;
        return 0;
    }
    size_t accepted = m->conport_sink(m->conport_ctx, port, bytes, take);
    if (accepted > take) {
        m->conport_fault = true;
        LOG_WARN("rvmachine", "byte port %u sink refused: accepted beyond offered bytes", port);
        return 0;
    }
    p->tx_left -= accepted;
    m->device_moved += accepted;
    if (accepted < take) p->blocked = true;
    else if (accepted < n || p->tx_left == 0u) p->tx_more = true;
    return accepted;
}

static void conport_writable(void *ctx, uint32_t port)
{
    struct rvmachine *m = ctx;
    m->conports[port].writable = true;
}

static void conport_irq(void *ctx, bool level)
{
    struct rvmachine *m = ctx;
    rvplat_plic_set_source(&m->plic,
        RVMACHINE_VIRTIO_IRQ0 + RVMACHINE_VIRTIO_SLOT_CONSOLE, level);
    rvmachine_irq_sync(m);
}

static bool conport_init(struct rvmachine *m)
{
    if (m->conport_count == 0u) return true;
    const struct rvvirtio_mem mem = {m, virtio_mem_read, virtio_mem_write, conport_irq};
    const struct rvvirtio_console_ops ops = {m, conport_from_guest, conport_writable};
    if (!rvvirtio_console_init(&m->con, &mem, &ops, m->conport_count)) {
        LOG_WARN("rvmachine", "byte console initialization refused");
        return false;
    }
    for (unsigned port = 0; port < m->conport_count; port++) {
        if (!rvvirtio_console_port_open(&m->con, port, m->conport_names[port])) {
            LOG_WARN("rvmachine", "byte port %u initialization refused", port);
            return false;
        }
        m->conports[port].seen_generation =
            rvvirtio_console_port_generation(&m->con, port);
    }
    return true;
}

static void conport_rx_round(struct rvmachine *m, unsigned port)
{
    struct rvmachine_conport *p = &m->conports[port];
    size_t left = RVMACHINE_CONPORT_ROUND_BYTES;
    while (left != 0u && conport_rx_ready(m, port)) {
        size_t take = RVMACHINE_CONPORT_QUEUE - p->head;
        if (take > p->count) take = p->count;
        if (take > left) take = left;
        size_t accepted = rvvirtio_console_port_write(&m->con, port,
                                                      p->bytes + p->head, take);
        if (p->private_keyfile) memory_cleanse(p->bytes + p->head, accepted);
        p->head = (p->head + accepted) % RVMACHINE_CONPORT_QUEUE;
        p->count -= accepted;
        left -= accepted;
        m->device_moved += accepted;
        p->writable = false;
        p->stalled = accepted < take;
    }
}

static void conport_service(struct rvmachine *m)
{
    conport_sync_epochs(m);
    for (unsigned port = 0; port < m->conport_count; port++) {
        if (!conport_service_ready(m, port)) continue;
        struct rvmachine_conport *p = &m->conports[port];
        p->tx_left = RVMACHINE_CONPORT_ROUND_BYTES;
        if (p->tx_more && !p->blocked) {
            p->tx_more = false;
            rvvirtio_console_port_resume(&m->con, port);
        }
        conport_rx_round(m, port);
    }
}

/* ---- interrupt wiring ---- */

void rvmachine_irq_sync(struct rvmachine *m)
{
    rvplat_plic_set_source(&m->plic, RVMACHINE_UART_IRQ, rvplat_uart_irq(&m->uart));
    rvemu_set_irq(&m->hart, RVEMU_IRQ_SEIP,
                  rvplat_plic_context_pending(&m->plic, RVPLAT_PLIC_CTX_S));
}

#define IRQ_LINE(cause) (UINT64_C(1) << (cause))
#define IRQ_S_LINES \
    (IRQ_LINE(RVEMU_IRQ_SSIP) | IRQ_LINE(RVEMU_IRQ_STIP) | IRQ_LINE(RVEMU_IRQ_SEIP))
#define IRQ_M_LINES \
    (IRQ_LINE(RVEMU_IRQ_MSIP) | IRQ_LINE(RVEMU_IRQ_MTIP) | IRQ_LINE(RVEMU_IRQ_MEIP))

/* The rule a waiting hart follows: "The operation of WFI must be unaffected
 * by the global interrupt bits in mstatus (MIE and SIE) and the delegation
 * register mideleg (i.e., the hart must resume if a locally enabled interrupt
 * becomes pending, even if it has been delegated to a less-privileged mode),
 * but should honor the individual interrupt enables (e.g, MTIE) (i.e.,
 * implementations should avoid resuming the hart if the interrupt is pending
 * but not locally enabled)." (The RISC-V Instruction Set Manual, Volume II,
 * Machine-Level ISA 1.13, "Wait for Interrupt"; CC BY 4.0.) The engine
 * implements exactly that, so an interrupt that is pending with its mie bit
 * clear leaves the hart asleep, and the global enable plays no part. */
bool rvmachine_hart_wakes(const struct rvmachine *m, uint64_t lines)
{
    uint64_t pending = (m->hart.csr.mip & IRQ_S_LINES) | (m->hart.irq_in & IRQ_M_LINES);
    return (pending & m->hart.csr.mie & lines) != 0;
}

/* ---- serial port ---- */

static void uart_tx(void *ctx, uint8_t byte)
{
    rvmachine_console_put(ctx, byte);
}

static uint64_t uart_load(struct rvmachine *m, uint64_t off)
{
    uint64_t v = 0;
    if (off < UART_REGS) {
        rvmachine_input_pump(m, true);
        v = rvplat_uart_read(&m->uart, (uint32_t)off);
    }
    return v;
}

static void uart_store(struct rvmachine *m, uint64_t off, uint64_t val)
{
    if (off >= UART_REGS) return;
    rvplat_uart_write(&m->uart, (uint32_t)off, (uint8_t)val);
    rvmachine_input_pump(m, false);
}

/* ---- virtio slots ---- */

static bool ram_span(const struct rvmachine *m, uint64_t gpa, size_t n)
{
    if (gpa < m->mem.base) return false;
    uint64_t off = gpa - m->mem.base;
    return off <= m->mem.size && n <= m->mem.size - off;
}

static bool virtio_mem_read(void *ctx, uint64_t gpa, void *buf, size_t n)
{
    struct rvmachine *m = ctx;
    if (!ram_span(m, gpa, n)) return false;
    memcpy(buf, m->mem.bytes + (gpa - m->mem.base), n);
    return true;
}

/* A device write is guest RAM the hart did not store. Wider than one
 * guest store, so the decode cache drops every line and re-reads later. */
static void virtio_note_ram(struct rvmachine *m, uint64_t gpa, size_t n)
{
    unsigned span = 9u;
    if (n == 0) return;
    if (n <= 8u) span = (unsigned)n;
    rvemu_icache_note_store(&m->hart, gpa, span);
}

static bool virtio_mem_write(void *ctx, uint64_t gpa, const void *buf, size_t n)
{
    struct rvmachine *m = ctx;
    if (!ram_span(m, gpa, n)) return false;
    memcpy(m->mem.bytes + (gpa - m->mem.base), buf, n);
    virtio_note_ram(m, gpa, n);
    return true;
}

static void blk_irq_slot(struct rvmachine *m, unsigned slot, bool level)
{
    rvplat_plic_set_source(&m->plic, RVMACHINE_VIRTIO_IRQ0 + slot, level);
    rvmachine_irq_sync(m);
}

static void blk_irq(void *ctx, bool level)
{
    blk_irq_slot(ctx, RVMACHINE_VIRTIO_SLOT_DISK, level);
}

static void blk1_irq(void *ctx, bool level)
{
    blk_irq_slot(ctx, RVMACHINE_VIRTIO_SLOT_DISK1, level);
}

static void rng_irq(void *ctx, bool level)
{
    struct rvmachine *m = ctx;
    rvplat_plic_set_source(&m->plic,
                           RVMACHINE_VIRTIO_IRQ0 + RVMACHINE_VIRTIO_SLOT_ENTROPY, level);
    rvmachine_irq_sync(m);
}

/* The entropy device's source. ctx is the machine: the caller's callback is
 * the only origin of the bytes, each delivered byte is counted as device
 * data, and a source that has nothing is remembered so it is not asked on
 * every instruction. */
static size_t entropy_fill_cb(void *ctx, uint8_t *buf, size_t n)
{
    struct rvmachine *m = ctx;
    if (m->entropy_fault) return 0;
    size_t got = m->entropy(m->entropy_ctx, buf, n);
    if (m->entropy_fail_closed && n != 0 && got != n) {
        LOG_WARN("rvmachine", "fatal entropy request refused: requested=%zu returned=%zu", n, got);
        memory_cleanse(buf, n);
        m->entropy_fault = true;
        got = 0;
    }
    if (got > n) got = n;
    m->entropy_dry = got == 0;
    m->device_moved += got;
    return got;
}

/* The block backends. ctx is the device's rvmachine_blkctx: every byte a
 * request moves is counted, read or written, whether or not the disk could
 * serve it. */
static struct rvmachine_disk *blk_disk(const struct rvmachine_blkctx *b)
{
    return b->data ? b->m->data_disk : b->m->disk;
}

static uint64_t disk_size_cb(void *ctx)
{
    return rvmachine_disk_size(blk_disk(ctx));
}

static bool disk_pread_cb(void *ctx, uint64_t off, void *buf, size_t n)
{
    struct rvmachine_blkctx *b = ctx;
    b->m->device_moved += n;
    return rvmachine_disk_read(blk_disk(b), off, buf, n);
}

static bool disk_pwrite_cb(void *ctx, uint64_t off, const void *buf, size_t n)
{
    struct rvmachine_blkctx *b = ctx;
    b->m->device_moved += n;
    return rvmachine_disk_write(blk_disk(b), off, buf, n);
}

static bool disk_flush_cb(void *ctx)
{
    return rvmachine_disk_flush(blk_disk(ctx));
}

/* Charges what the backend moved since the last call to the work budget: one
 * unit per started RVMACHINE_DEVICE_WORK_BYTES. Called once after each place
 * a block request can be serviced (a queue notify, a service round). */
static void device_settle(struct rvmachine *m)
{
    m->device_work += m->device_moved / RVMACHINE_DEVICE_WORK_BYTES +
                      (m->device_moved % RVMACHINE_DEVICE_WORK_BYTES != 0 ? 1u : 0u);
    m->device_moved = 0;
}

/* The device behind a slot, or NULL for an empty one. */
static struct rvvirtio_dev *virtio_slot(struct rvmachine *m, uint64_t slot)
{
    if (slot == RVMACHINE_VIRTIO_SLOT_DISK && m->disk != NULL) return &m->blk.dev;
    if (slot == RVMACHINE_VIRTIO_SLOT_DISK1 && m->data_disk != NULL) return &m->blk1.dev;
    if (slot == RVMACHINE_VIRTIO_SLOT_ENTROPY && m->entropy != NULL) return &m->rng.dev;
    if (slot == RVMACHINE_VIRTIO_SLOT_CONSOLE && m->conport_count != 0u) return &m->con.dev;
    return NULL;
}

/* An empty slot still answers the identification registers (device id 0). */
static uint32_t virtio_empty_read(uint64_t off)
{
    switch (off) {
    case RVVIRTIO_REG_MAGIC: return RVVIRTIO_MAGIC;
    case RVVIRTIO_REG_VERSION: return RVVIRTIO_MMIO_VERSION;
    case RVVIRTIO_REG_VENDOR_ID: return RVVIRTIO_VENDOR_ID;
    default: return 0;
    }
}

/* The low bytes of a register value for an access of 1, 2, 4 or 8 bytes. */
static uint64_t narrow(uint64_t v, unsigned nbytes)
{
    switch (nbytes) {
    case 1u: return (uint8_t)v;
    case 2u: return (uint16_t)v;
    case 4u: return (uint32_t)v;
    default: return v;
    }
}

/* Registers are 32-bit; the configuration space is byte addressed. */
static int virtio_load(struct rvmachine *m, uint64_t rel, unsigned nbytes,
                       uint64_t *out)
{
    struct rvvirtio_dev *dev = virtio_slot(m, rel / RVMACHINE_VIRTIO_STRIDE);
    uint64_t off = rel % RVMACHINE_VIRTIO_STRIDE;
    uint64_t v;
    if (off < RVVIRTIO_REG_CONFIG && (nbytes != 4u || (off & 3u) != 0u)) return -1;
    if (dev == NULL) {
        *out = off < RVVIRTIO_REG_CONFIG ? virtio_empty_read(off) : 0;
        return 0;
    }
    v = rvvirtio_mmio_read(dev, off);
    if (nbytes == 8u) v |= (uint64_t)rvvirtio_mmio_read(dev, off + 4u) << 32;
    *out = narrow(v, nbytes);
    return 0;
}

static int virtio_store(struct rvmachine *m, uint64_t rel, unsigned nbytes,
                        uint64_t val)
{
    struct rvvirtio_dev *dev = virtio_slot(m, rel / RVMACHINE_VIRTIO_STRIDE);
    uint64_t off = rel % RVMACHINE_VIRTIO_STRIDE;
    if (off < RVVIRTIO_REG_CONFIG && (nbytes != 4u || (off & 3u) != 0u)) return -1;
    if (dev != NULL && nbytes == 4u) {
        bool port_reset = dev == &m->con.dev && off == RVVIRTIO_REG_STATUS && val == 0u;
        if (port_reset) {
            /* A reset ends the epoch even before the guest first opened a
             * tty; the model's guest-open generation alone cannot detect it. */
            for (unsigned port = 0; port < m->conport_count; port++)
                conport_new_epoch(m, port);
        }
        rvvirtio_mmio_write(dev, off, (uint32_t)val);
        if (port_reset) {
            for (unsigned port = 0; port < m->conport_count; port++)
                m->conports[port].seen_generation =
                    rvvirtio_console_port_generation(&m->con, port);
        }
        if (m->conport_fault) rvvirtio_dev_fail(&m->con.dev);
        device_settle(m); /* a notify or a first DRIVER_OK serves requests */
    }
    return 0;
}

/* ---- bus decode ---- */

static bool in_region(uint64_t paddr, unsigned nbytes, uint64_t base, uint64_t size)
{
    return paddr >= base && paddr - base < size && nbytes <= size - (paddr - base);
}

static int plic_load(struct rvmachine *m, uint64_t off, unsigned nbytes, uint64_t *out)
{
    if (nbytes != 4u || (off & 3u) != 0u) return -1;
    *out = rvplat_plic_read(&m->plic, off);
    return 0;
}

static int plic_store(struct rvmachine *m, uint64_t off, unsigned nbytes, uint64_t val)
{
    if (nbytes != 4u || (off & 3u) != 0u) return -1;
    rvplat_plic_write(&m->plic, off, (uint32_t)val);
    return 0;
}

#define VIRTIO_SPAN (RVMACHINE_VIRTIO_SLOTS * RVMACHINE_VIRTIO_STRIDE)

int rvmachine_io_load(void *ctx, uint64_t paddr, unsigned nbytes, uint64_t *out)
{
    struct rvmachine *m = ctx;
    int rc = -1;
    m->sched.io_events++;
    if (nbytes == 0 || nbytes > 8u) return -1;
    if (in_region(paddr, nbytes, RVMACHINE_UART_BASE, RVMACHINE_UART_SIZE)) {
        *out = uart_load(m, paddr - RVMACHINE_UART_BASE);
        rc = 0;
    } else if (in_region(paddr, nbytes, RVMACHINE_PLIC_BASE, RVMACHINE_PLIC_SIZE)) {
        rc = plic_load(m, paddr - RVMACHINE_PLIC_BASE, nbytes, out);
    } else if (in_region(paddr, nbytes, RVMACHINE_VIRTIO_BASE, VIRTIO_SPAN)) {
        rc = virtio_load(m, paddr - RVMACHINE_VIRTIO_BASE, nbytes, out);
    }
    if (rc == 0) rvmachine_irq_sync(m);
    return rc;
}

int rvmachine_io_store(void *ctx, uint64_t paddr, unsigned nbytes, uint64_t val)
{
    struct rvmachine *m = ctx;
    int rc = -1;
    m->sched.io_events++;
    if (nbytes == 0 || nbytes > 8u) return -1;
    if (in_region(paddr, nbytes, RVMACHINE_UART_BASE, RVMACHINE_UART_SIZE)) {
        uart_store(m, paddr - RVMACHINE_UART_BASE, val);
        rc = 0;
    } else if (in_region(paddr, nbytes, RVMACHINE_PLIC_BASE, RVMACHINE_PLIC_SIZE)) {
        rc = plic_store(m, paddr - RVMACHINE_PLIC_BASE, nbytes, val);
    } else if (in_region(paddr, nbytes, RVMACHINE_VIRTIO_BASE, VIRTIO_SPAN)) {
        rc = virtio_store(m, paddr - RVMACHINE_VIRTIO_BASE, nbytes, val);
    }
    if (rc == 0) rvmachine_irq_sync(m);
    return rc;
}

static bool blk_attach(struct rvmachine *m, bool data)
{
    struct rvmachine_blkctx *ctx = &m->blkctx[data ? 1 : 0];
    struct rvvirtio_blk *blk = data ? &m->blk1 : &m->blk;
    const struct rvvirtio_mem mem = {m, virtio_mem_read, virtio_mem_write,
                                     data ? blk1_irq : blk_irq};
    const struct rvvirtio_blk_backend be = {
        ctx, disk_size_cb, disk_pread_cb, disk_pwrite_cb, disk_flush_cb,
        data ? "z23-rvmachine-disk1" : "z23-rvmachine-disk0"};
    ctx->m = m;
    ctx->data = data;
    return rvvirtio_blk_init(blk, &mem, &be, false);
}

bool rvmachine_devices_init(struct rvmachine *m)
{
    const struct rvvirtio_mem rng_mem = {m, virtio_mem_read, virtio_mem_write, rng_irq};
    const struct rvvirtio_rng_ops source = {m, entropy_fill_cb};
    rvplat_plic_init(&m->plic, RVMACHINE_PLIC_NDEV);
    rvplat_uart_init(&m->uart, uart_tx, m);
    if (m->disk != NULL && !blk_attach(m, false)) return false;
    if (m->data_disk != NULL && !blk_attach(m, true)) return false;
    if (m->entropy != NULL && !rvvirtio_rng_init(&m->rng, &rng_mem, &source)) return false;
    return conport_init(m);
}

/* A device serves its queue only while its driver runs it; the service call
 * does nothing otherwise. Requests left behind a queue the driver stopped, or
 * in a device that asked for a reset, are not work a run could do. */
static bool queue_served(const struct rvvirtio_dev *d)
{
    return (d->status & RVVIRTIO_STATUS_DRIVER_OK) != 0u &&
           (d->status & RVVIRTIO_STATUS_NEEDS_RESET) == 0u && d->queues[0].ready;
}

static bool blk_pending(const struct rvmachine *m)
{
    return (m->disk != NULL && rvvirtio_blk_pending(&m->blk) && queue_served(&m->blk.dev)) ||
           (m->data_disk != NULL && rvvirtio_blk_pending(&m->blk1) &&
            queue_served(&m->blk1.dev));
}

/* Entropy requests wait while the source has nothing; they are not pending
 * work until the guest notifies again or rvmachine_entropy_ready is called. */
static bool rng_pending(const struct rvmachine *m)
{
    return m->entropy != NULL && !m->entropy_dry && rvvirtio_rng_pending(&m->rng) &&
           queue_served(&m->rng.dev);
}

bool rvmachine_devices_pending(const struct rvmachine *m)
{
    if (blk_pending(m) || rng_pending(m)) return true;
    for (unsigned port = 0; port < m->conport_count; port++) {
        if (conport_service_ready(m, port)) return true;
    }
    return false;
}

void rvmachine_wake_check(struct rvmachine *m)
{
    if (rvmachine_hart_wakes(m, UINT64_MAX) || blk_pending(m) || rng_pending(m))
        m->wait_latched = false;
    for (unsigned port = 0; port < m->conport_count; port++) {
        if ((conport_pending_flags(m, port) & RVMACHINE_PENDING_PORT) != 0u)
            m->wait_latched = false;
    }
}

/* One capped round of the requests a capped notify left in each device. */
void rvmachine_devices_service(struct rvmachine *m)
{
    if (!rvmachine_devices_pending(m)) return;
    if (m->disk != NULL && rvvirtio_blk_pending(&m->blk) && queue_served(&m->blk.dev))
        rvvirtio_blk_service(&m->blk);
    if (m->data_disk != NULL && rvvirtio_blk_pending(&m->blk1) && queue_served(&m->blk1.dev))
        rvvirtio_blk_service(&m->blk1);
    if (rng_pending(m)) rvvirtio_rng_service(&m->rng);
    conport_service(m);
    if (m->conport_fault) rvvirtio_dev_fail(&m->con.dev);
    device_settle(m);
    rvmachine_irq_sync(m);
}

static bool serial_queued(const struct rvmachine *m)
{
    return m->serial_in.count != 0 || m->uart.rx_count != 0;
}

/* Serial input ends a wfi when the port raises its receive interrupt and the
 * hart has the external interrupt pending and enabled. */
static bool serial_wakes(const struct rvmachine *m)
{
    return (m->uart.ier & RVPLAT_UART_IER_RDA) != 0u &&
           rvmachine_hart_wakes(m, IRQ_LINE(RVEMU_IRQ_SEIP));
}

unsigned rvmachine_pending(const struct rvmachine *m)
{
    unsigned set = 0;
    if (m == NULL) return 0;
    if (serial_queued(m))
        set |= serial_wakes(m) ? RVMACHINE_PENDING_CONSOLE : RVMACHINE_PENDING_CONSOLE_HELD;
    if (rng_pending(m)) set |= RVMACHINE_PENDING_ENTROPY;
    if (blk_pending(m)) set |= RVMACHINE_PENDING_BLOCK;
    for (unsigned port = 0; port < m->conport_count; port++)
        set |= conport_pending_flags(m, port);
    return set;
}
