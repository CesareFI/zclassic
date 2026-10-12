/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: virtio-console with VIRTIO_CONSOLE_F_MULTIPORT (VIRTIO 1.2,
 * section 5.3): control-message handshake and per-port byte channels with
 * partial acceptance in both directions and no internal buffering. */

#include "rvvirtio_priv.h"

#include <string.h>

/* 5.3.6.1: control message events. */
#define EV_DEVICE_READY 0u
#define EV_DEVICE_ADD 1u
#define EV_PORT_READY 3u
#define EV_CONSOLE_PORT 4u
#define EV_PORT_OPEN 6u
#define EV_PORT_NAME 7u
#define CTL_LEN 8u /* struct virtio_console_control: id u32, event u16, value u16 */

/* Pending control messages owed to the guest, in send order per port. */
#define P_ADD 1u
#define P_CONSOLE 2u
#define P_NAME 4u
#define P_OPEN 8u

#define Q_CTL_RX 2u
#define Q_CTL_TX 3u

static uint32_t rx_queue(uint32_t port) { return port == 0 ? 0u : 2u * (port + 1u); }

static struct rvvirtio_console *as_console(struct rvvirtio_dev *dev)
{
    return (struct rvvirtio_console *)dev;
}

static bool port_ok(const struct rvvirtio_console *c, uint32_t port)
{
    return port < c->nports;
}

/* ---- control receive queue: messages to the guest ---- */

static bool ctl_find(struct rvvirtio_console *c, uint32_t *port, uint8_t *bit)
{
    for (uint32_t p = 0; p < c->nports; p++) {
        for (uint8_t b = P_ADD; b <= P_OPEN; b = (uint8_t)(b << 1)) {
            if ((c->ports[p].pending & b) != 0) {
                *port = p;
                *bit = b;
                return true;
            }
        }
    }
    return false;
}

static size_t ctl_build(const struct rvvirtio_console *c, uint32_t port,
                        uint8_t bit, uint8_t *msg)
{
    const struct rvvirtio_console_port *ps = &c->ports[port];
    uint16_t event = EV_DEVICE_ADD, value = 1;
    size_t len = CTL_LEN;
    if (bit == P_CONSOLE)
        event = EV_CONSOLE_PORT;
    if (bit == P_NAME) {
        event = EV_PORT_NAME;
        memcpy(msg + CTL_LEN, ps->name, ps->name_len);
        len += ps->name_len;
    }
    if (bit == P_OPEN) {
        event = EV_PORT_OPEN;
        value = ps->open_value ? 1u : 0u;
    }
    rvvirtio_put_le32(msg, port);
    rvvirtio_put_le16(msg + 4, event);
    rvvirtio_put_le16(msg + 6, value);
    return len;
}

/* Send as many owed control messages as the guest has buffers for. */
static void ctl_pump(struct rvvirtio_console *c)
{
    struct rvvirtio_dev *d = &c->dev;
    uint8_t msg[CTL_LEN + RVVIRTIO_CONSOLE_NAME_MAX];
    uint32_t port;
    uint8_t bit;
    for (uint32_t i = 0; i < 4u * c->nports; i++) {
        if (!ctl_find(c, &port, &bit) ||
            rvvirtio_queue_pop(d, Q_CTL_RX) != RVVIRTIO_POP_OK)
            return;
        size_t len = ctl_build(c, port, bit, msg);
        if (d->chain.in_len != 0 || d->chain.out_len < len) {
            rvvirtio_dev_fail(d);
            return;
        }
        if (!rvvirtio_chain_write(d, 0, msg, len) ||
            !rvvirtio_queue_push(d, Q_CTL_RX, (uint32_t)len))
            return;
        c->ports[port].pending &= (uint8_t)~bit;
    }
}

/* ---- control transmit queue: messages from the guest ---- */

static void ctl_port_ready(struct rvvirtio_console_port *ps)
{
    ps->guest_ready = true;
    if (ps->host_open) {
        ps->pending |= ps->is_console ? P_CONSOLE : P_NAME;
        ps->pending |= P_OPEN;
        ps->open_value = true;
    }
}

/* Unknown ports and unknown events are ignored (defined, no state change). */
static void ctl_handle(struct rvvirtio_console *c, uint32_t id, uint16_t event,
                       uint16_t value)
{
    if (event == EV_DEVICE_READY) {
        c->device_ready = value == 1u;
        for (uint32_t p = 0; c->device_ready && p < c->nports; p++)
            c->ports[p].pending |= P_ADD;
        return;
    }
    if (!port_ok(c, id) || !c->device_ready)
        return;
    if (event == EV_PORT_READY && value == 1u)
        ctl_port_ready(&c->ports[id]);
    else if (event == EV_PORT_OPEN)
        c->ports[id].guest_open = value != 0;
}

static void ctl_tx(struct rvvirtio_console *c)
{
    struct rvvirtio_dev *d = &c->dev;
    uint8_t msg[CTL_LEN];
    for (uint32_t i = 0; i < d->queues[Q_CTL_TX].num; i++) {
        if (rvvirtio_queue_pop(d, Q_CTL_TX) != RVVIRTIO_POP_OK)
            break;
        if (d->chain.out_len != 0) {
            rvvirtio_dev_fail(d);
            return;
        }
        if (d->chain.in_len >= CTL_LEN) {
            if (!rvvirtio_chain_read(d, 0, msg, CTL_LEN))
                return;
            ctl_handle(c, rvvirtio_le32(msg), rvvirtio_le16(msg + 4),
                       rvvirtio_le16(msg + 6));
        }
        if (!rvvirtio_queue_push(d, Q_CTL_TX, 0))
            return;
    }
    ctl_pump(c);
}

/* ---- guest to host ---- */

/* Hand one transmit chain to from_guest, resuming at tx_off. Returns false
 * when the chain was left in place (stopped, budget spent or device error). */
static bool tx_chain(struct rvvirtio_console *c, uint32_t port, uint32_t *budget)
{
    struct rvvirtio_console_port *ps = &c->ports[port];
    struct rvvirtio_dev *d = &c->dev;
    if (d->chain.out_len != 0) {
        rvvirtio_dev_fail(d);
        return false;
    }
    while (ps->host_open && ps->tx_off < d->chain.in_len) {
        uint64_t left = d->chain.in_len - ps->tx_off;
        size_t n = left < sizeof(c->chunk) ? (size_t)left : sizeof(c->chunk);
        if (n > *budget)
            n = *budget;
        if (n == 0 || !rvvirtio_chain_read(d, ps->tx_off, c->chunk, n))
            return false;
        c->busy = true;
        size_t a = c->ops.from_guest(c->ops.ctx, port, c->chunk, n);
        c->busy = false;
        a = RVVIRTIO_ACCEPTED(a, n) < n ? RVVIRTIO_ACCEPTED(a, n) : n;
        ps->tx_off += (uint32_t)a;
        *budget -= (uint32_t)a;
        if (a < n) {
            ps->tx_stopped = true;
            return false;
        }
    }
    return true;
}

static void tx_pump(struct rvvirtio_console *c, uint32_t port)
{
    struct rvvirtio_console_port *ps = &c->ports[port];
    struct rvvirtio_dev *d = &c->dev;
    uint32_t q = rx_queue(port) + 1u, budget = RVVIRTIO_CONSOLE_PUMP_BYTES;
    for (uint32_t i = 0; i < d->queues[q].num && !ps->tx_stopped; i++) {
        if (rvvirtio_queue_pop(d, q) != RVVIRTIO_POP_OK ||
            !tx_chain(c, port, &budget))
            return;
        ps->tx_off = 0;
        if (!rvvirtio_queue_push(d, q, 0))
            return;
    }
}

/* ---- host to guest ---- */

static void account(struct rvvirtio_console_port *ps, uint32_t head)
{
    if (head < RVVIRTIO_QUEUE_MAX && ps->delivered[head] != 0) {
        ps->consumed += ps->delivered[head];
        ps->delivered[head] = 0;
    }
}

/* Fill one guest receive buffer; returns bytes placed, 0 when none/failed. */
static size_t rx_deliver(struct rvvirtio_console *c, uint32_t port,
                         const uint8_t *buf, size_t n)
{
    struct rvvirtio_console_port *ps = &c->ports[port];
    struct rvvirtio_dev *d = &c->dev;
    uint32_t q = rx_queue(port);
    if (rvvirtio_queue_pop(d, q) != RVVIRTIO_POP_OK)
        return 0;
    if (d->chain.in_len != 0 || d->chain.out_len == 0) {
        rvvirtio_dev_fail(d);
        return 0;
    }
    account(ps, d->chain.head);
    size_t take = n < d->chain.out_len ? n : (size_t)d->chain.out_len;
    if (take > UINT32_MAX)
        take = UINT32_MAX;
    if (!rvvirtio_chain_write(d, 0, buf, take) ||
        !rvvirtio_queue_push(d, q, (uint32_t)take))
        return 0;
    ps->delivered[d->chain.head] = (uint32_t)take;
    return take;
}

size_t rvvirtio_console_port_write(struct rvvirtio_console *c, uint32_t port,
                                   const uint8_t *buf, size_t n)
{
    if (c->busy || !port_ok(c, port) || buf == NULL || n == 0 ||
        !rvvirtio_dev_running(&c->dev))
        return 0;
    struct rvvirtio_console_port *ps = &c->ports[port];
    size_t acc = 0;
    if (!ps->host_open || !ps->guest_open)
        return 0;
    for (uint32_t i = 0; i < c->dev.queues[rx_queue(port)].num && acc < n; i++) {
        size_t took = rx_deliver(c, port, buf + acc, n - acc);
        if (took == 0)
            break;
        acc += took;
    }
    ps->rx_stalled = acc < n;
    return acc;
}

/* The guest kicked a receive queue: report writability once per stall. */
static void rx_kick(struct rvvirtio_console *c, uint32_t port)
{
    struct rvvirtio_console_port *ps = &c->ports[port];
    if (!ps->rx_stalled || !ps->host_open ||
        rvvirtio_queue_pop(&c->dev, rx_queue(port)) != RVVIRTIO_POP_OK)
        return;
    ps->rx_stalled = false;
    if (c->ops.writable != NULL) {
        c->busy = true;
        c->ops.writable(c->ops.ctx, port);
        c->busy = false;
    }
}

size_t rvvirtio_console_port_consumed(struct rvvirtio_console *c, uint32_t port)
{
    if (c->busy || !port_ok(c, port))
        return 0;
    struct rvvirtio_console_port *ps = &c->ports[port];
    struct rvvirtio_dev *d = &c->dev;
    const struct rvvirtio_queue *q = &d->queues[rx_queue(port)];
    uint8_t b[2];
    if (rvvirtio_dev_running(d) && q->ready &&
        rvvirtio_gm_read(d, q->driver + 2u, b, 2)) {
        uint16_t pending = (uint16_t)(rvvirtio_le16(b) - q->last_avail);
        for (uint16_t i = 0; i < pending && i < q->num; i++) {
            uint64_t slot = (uint16_t)(q->last_avail + i) % q->num;
            if (!rvvirtio_gm_read(d, q->driver + 4u + 2u * slot, b, 2))
                break;
            account(ps, rvvirtio_le16(b));
        }
    }
    return (size_t)ps->consumed;
}

/* ---- host API and device plumbing ---- */

bool rvvirtio_console_port_open(struct rvvirtio_console *c, uint32_t port,
                                const char *name)
{
    size_t len = name != NULL ? strlen(name) : 0;
    if (c->busy || !port_ok(c, port) || c->ports[port].host_open ||
        len >= RVVIRTIO_CONSOLE_NAME_MAX)
        return false;
    struct rvvirtio_console_port *ps = &c->ports[port];
    memset(ps->name, 0, sizeof(ps->name));
    if (len != 0)
        memcpy(ps->name, name, len);
    ps->name_len = (uint8_t)len;
    ps->is_console = len == 0;
    ps->host_open = true;
    ps->generation++;
    ps->consumed = 0;
    ps->tx_off = 0;
    ps->tx_stopped = false;
    ps->rx_stalled = false;
    memset(ps->delivered, 0, sizeof(ps->delivered));
    if (ps->guest_ready)
        ctl_port_ready(ps);
    ctl_pump(c);
    return true;
}

void rvvirtio_console_port_resume(struct rvvirtio_console *c, uint32_t port)
{
    if (c->busy || !port_ok(c, port) || !rvvirtio_dev_running(&c->dev))
        return;
    c->ports[port].tx_stopped = false;
    tx_pump(c, port);
}

void rvvirtio_console_port_close(struct rvvirtio_console *c, uint32_t port)
{
    if (c->busy || !port_ok(c, port) || !c->ports[port].host_open)
        return;
    struct rvvirtio_console_port *ps = &c->ports[port];
    ps->host_open = false;
    ps->generation++;
    ps->rx_stalled = false;
    ps->tx_stopped = false;
    ps->pending &= (uint8_t)~(P_CONSOLE | P_NAME);
    ps->pending |= P_OPEN;
    ps->open_value = false;
    if (rvvirtio_dev_running(&c->dev))
        tx_pump(c, port); /* discards the chain that was waiting on us */
    ps->tx_off = 0;
    ctl_pump(c);
}

uint32_t rvvirtio_console_port_generation(const struct rvvirtio_console *c,
                                          uint32_t port)
{
    return port_ok(c, port) ? c->ports[port].generation : 0;
}

static void console_notify(struct rvvirtio_dev *dev, uint32_t q)
{
    struct rvvirtio_console *c = as_console(dev);
    if (c->busy)
        return;
    if (q == Q_CTL_RX)
        ctl_pump(c);
    else if (q == Q_CTL_TX)
        ctl_tx(c);
    else if ((q & 1u) != 0)
        tx_pump(c, q < 2u ? 0u : (q - 2u) / 2u);
    else
        rx_kick(c, q < 2u ? 0u : (q - 2u) / 2u);
}

/* The FreeBSD driver sends DEVICE_READY and polls for its completion inside
 * attach (virtio_console.c vtcon_ctrl_poll), before the transport sets
 * DRIVER_OK (virtio_mmio.c). The control transmit queue is therefore served
 * from FEATURES_OK; the PORT_ADD messages owed after DEVICE_READY wait for the
 * control receive queue and are sent the moment DRIVER_OK is set. */
static void console_on_driver_ok(struct rvvirtio_dev *dev)
{
    ctl_pump(as_console(dev));
}

/* A guest reset ends every guest-side session: ports stay host-open and are
 * re-announced when the guest repeats the handshake. */
static void console_reset(struct rvvirtio_dev *dev)
{
    struct rvvirtio_console *c = as_console(dev);
    c->device_ready = false;
    for (uint32_t p = 0; p < c->nports; p++) {
        struct rvvirtio_console_port *ps = &c->ports[p];
        if (ps->guest_open)
            ps->generation++;
        ps->guest_open = false;
        ps->guest_ready = false;
        ps->tx_stopped = false;
        ps->rx_stalled = false;
        ps->tx_off = 0;
        ps->pending = 0;
        memset(ps->delivered, 0, sizeof(ps->delivered));
    }
}

bool rvvirtio_console_init(struct rvvirtio_console *c,
                           const struct rvvirtio_mem *mem,
                           const struct rvvirtio_console_ops *ops,
                           uint32_t nports)
{
    if (mem == NULL || ops == NULL || ops->from_guest == NULL ||
        mem->read == NULL || mem->write == NULL || nports == 0 ||
        nports > RVVIRTIO_CONSOLE_PORTS_MAX)
        return false;
    memset(c, 0, sizeof(*c));
    c->ops = *ops;
    c->nports = nports;
    rvvirtio_dev_setup(&c->dev, mem, RVVIRTIO_DEVICE_ID_CONSOLE,
                       RVVIRTIO_CONSOLE_F_MULTIPORT, 2u * (nports + 1u));
    c->dev.notify = console_notify;
    c->dev.on_reset = console_reset;
    c->dev.on_driver_ok = console_on_driver_ok;
    c->dev.early_queues = 1u << Q_CTL_TX;
    /* 5.3.4: cols u16, rows u16, max_nr_ports u32, emerg_wr u32. */
    rvvirtio_put_le32(c->dev.config + 4, nports);
    c->dev.config_len = 12;
    return true;
}
