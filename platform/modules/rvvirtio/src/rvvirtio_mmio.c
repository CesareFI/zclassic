/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: VIRTIO 1.2 MMIO transport, version 2 (section 4.2): identification,
 * feature negotiation, status state machine, queue registers, interrupts. */

#include "rvvirtio_priv.h"

#include <string.h>

void rvvirtio_irq_update(struct rvvirtio_dev *dev)
{
    bool level = dev->interrupt_status != 0;
    if (level != dev->irq_level) {
        dev->irq_level = level;
        if (dev->mem.irq != NULL)
            dev->mem.irq(dev->mem.ctx, level);
    }
}

/* 2.1: the device sets DEVICE_NEEDS_RESET and notifies a config change. */
void rvvirtio_dev_fail(struct rvvirtio_dev *dev)
{
    dev->status |= RVVIRTIO_STATUS_NEEDS_RESET;
    dev->interrupt_status |= RVVIRTIO_INT_CONFIG_CHANGE;
    rvvirtio_irq_update(dev);
}

void rvvirtio_dev_config_changed(struct rvvirtio_dev *dev)
{
    dev->config_generation++;
    dev->interrupt_status |= RVVIRTIO_INT_CONFIG_CHANGE;
    rvvirtio_irq_update(dev);
}

/* 2.1.1/4.2.3.1: writing 0 to Status resets the device. */
void rvvirtio_dev_reset(struct rvvirtio_dev *dev)
{
    dev->status = 0;
    dev->driver_features = 0;
    dev->device_features_sel = 0;
    dev->driver_features_sel = 0;
    dev->queue_sel = 0;
    dev->interrupt_status = 0;
    memset(dev->queues, 0, sizeof(dev->queues));
    memset(&dev->chain, 0, sizeof(dev->chain));
    if (dev->on_reset != NULL)
        dev->on_reset(dev);
    rvvirtio_irq_update(dev);
}

void rvvirtio_dev_setup(struct rvvirtio_dev *dev, const struct rvvirtio_mem *mem,
                        uint32_t device_id, uint64_t features, uint32_t nqueues)
{
    memset(dev, 0, sizeof(*dev));
    dev->mem = *mem;
    dev->device_id = device_id;
    dev->device_features = features | RVVIRTIO_F_INDIRECT_DESC;
    dev->nqueues = nqueues;
}

/* ---- reads (4.2.2) ---- */

static uint32_t read_features(const struct rvvirtio_dev *dev)
{
    uint64_t all = dev->device_features | RVVIRTIO_F_VERSION_1;
    if (dev->device_features_sel > 1u)
        return 0;
    return (uint32_t)(all >> (32u * dev->device_features_sel));
}

static const struct rvvirtio_queue *sel_queue(const struct rvvirtio_dev *dev)
{
    return dev->queue_sel < dev->nqueues ? &dev->queues[dev->queue_sel] : NULL;
}

static uint32_t read_queue_reg(const struct rvvirtio_dev *dev, uint64_t off)
{
    const struct rvvirtio_queue *q = sel_queue(dev);
    if (q == NULL)
        return 0; /* 4.2.2: invalid queue reads zero */
    switch (off) {
    case RVVIRTIO_REG_QUEUE_NUM_MAX: return RVVIRTIO_QUEUE_MAX;
    case RVVIRTIO_REG_QUEUE_READY: return q->ready ? 1u : 0u;
    default: return 0; /* QueueNum etc. are write-only */
    }
}

static uint32_t read_config(const struct rvvirtio_dev *dev, uint64_t off)
{
    uint8_t raw[4] = {0, 0, 0, 0};
    uint64_t base = off - RVVIRTIO_REG_CONFIG;
    for (uint32_t i = 0; i < 4u; i++)
        if (base + i < dev->config_len)
            raw[i] = dev->config[base + i];
    return rvvirtio_le32(raw);
}

uint32_t rvvirtio_mmio_read(struct rvvirtio_dev *dev, uint64_t off)
{
    if (off >= RVVIRTIO_REG_CONFIG)
        return read_config(dev, off);
    switch (off) {
    case RVVIRTIO_REG_MAGIC: return RVVIRTIO_MAGIC;
    case RVVIRTIO_REG_VERSION: return RVVIRTIO_MMIO_VERSION;
    case RVVIRTIO_REG_DEVICE_ID: return dev->device_id;
    case RVVIRTIO_REG_VENDOR_ID: return RVVIRTIO_VENDOR_ID;
    case RVVIRTIO_REG_DEVICE_FEATURES: return read_features(dev);
    case RVVIRTIO_REG_QUEUE_NUM_MAX:
    case RVVIRTIO_REG_QUEUE_READY: return read_queue_reg(dev, off);
    case RVVIRTIO_REG_INTERRUPT_STATUS: return dev->interrupt_status;
    case RVVIRTIO_REG_STATUS: return dev->status;
    case RVVIRTIO_REG_CONFIG_GENERATION: return dev->config_generation;
    default: return 0;
    }
}

/* ---- writes ---- */

static bool features_valid(const struct rvvirtio_dev *dev)
{
    uint64_t offered = dev->device_features | RVVIRTIO_F_VERSION_1;
    return (dev->driver_features & RVVIRTIO_F_VERSION_1) != 0 &&
           (dev->driver_features & ~offered) == 0;
}

/* 2.1, 3.1.1: statuses only accumulate until a reset. FEATURES_OK is refused
 * (read back clear) unless VERSION_1 and a subset of the offered bits were
 * negotiated; DRIVER_OK is meaningless without FEATURES_OK. */
static void write_status(struct rvvirtio_dev *dev, uint32_t val)
{
    const uint32_t settable = RVVIRTIO_STATUS_ACKNOWLEDGE | RVVIRTIO_STATUS_DRIVER |
                              RVVIRTIO_STATUS_DRIVER_OK |
                              RVVIRTIO_STATUS_FEATURES_OK | RVVIRTIO_STATUS_FAILED;
    if (val == 0) {
        rvvirtio_dev_reset(dev);
        return;
    }
    if ((dev->status & RVVIRTIO_STATUS_NEEDS_RESET) != 0)
        return;
    uint32_t next = dev->status | (val & settable);
    bool fresh_ok = (next & RVVIRTIO_STATUS_FEATURES_OK) != 0 &&
                    (dev->status & RVVIRTIO_STATUS_FEATURES_OK) == 0;
    if (fresh_ok && !features_valid(dev))
        next &= ~RVVIRTIO_STATUS_FEATURES_OK;
    if ((next & RVVIRTIO_STATUS_FEATURES_OK) == 0)
        next &= ~RVVIRTIO_STATUS_DRIVER_OK;
    bool fresh_driver_ok = (next & RVVIRTIO_STATUS_DRIVER_OK) != 0 &&
                           (dev->status & RVVIRTIO_STATUS_DRIVER_OK) == 0;
    dev->status = next;
    if (fresh_driver_ok && dev->on_driver_ok != NULL)
        dev->on_driver_ok(dev);
}

static void write_driver_features(struct rvvirtio_dev *dev, uint32_t val)
{
    if ((dev->status & RVVIRTIO_STATUS_FEATURES_OK) != 0 ||
        dev->driver_features_sel > 1u)
        return;
    unsigned shift = 32u * dev->driver_features_sel;
    dev->driver_features &= ~(UINT64_C(0xffffffff) << shift);
    dev->driver_features |= (uint64_t)val << shift;
}

static void write_addr(uint64_t *addr, bool high, uint32_t val)
{
    if (high)
        *addr = (*addr & UINT64_C(0xffffffff)) | ((uint64_t)val << 32);
    else
        *addr = (*addr & ~UINT64_C(0xffffffff)) | val;
}

/* 4.2.3.2: QueueReady=1 enables a fully configured queue. */
static void write_queue_ready(struct rvvirtio_dev *dev,
                              struct rvvirtio_queue *q, uint32_t val)
{
    if (val == 0) {
        q->ready = false;
        q->last_avail = 0;
        q->used_idx = 0;
    } else if (!q->ready) {
        if (!rvvirtio_queue_valid(q)) {
            rvvirtio_dev_fail(dev);
            return;
        }
        q->ready = true;
        q->last_avail = 0;
        q->used_idx = 0;
    }
}

static void write_queue_reg(struct rvvirtio_dev *dev, uint64_t off, uint32_t val)
{
    if (dev->queue_sel >= dev->nqueues)
        return;
    struct rvvirtio_queue *q = &dev->queues[dev->queue_sel];
    if (off == RVVIRTIO_REG_QUEUE_READY) {
        write_queue_ready(dev, q, val);
        return;
    }
    if (q->ready)
        return; /* 4.2.2: configuration is frozen while ready */
    switch (off) {
    case RVVIRTIO_REG_QUEUE_NUM:
        q->num = val <= RVVIRTIO_QUEUE_MAX ? val : 0u;
        break;
    case RVVIRTIO_REG_QUEUE_DESC_LOW: write_addr(&q->desc, false, val); break;
    case RVVIRTIO_REG_QUEUE_DESC_HIGH: write_addr(&q->desc, true, val); break;
    case RVVIRTIO_REG_QUEUE_DRIVER_LOW: write_addr(&q->driver, false, val); break;
    case RVVIRTIO_REG_QUEUE_DRIVER_HIGH: write_addr(&q->driver, true, val); break;
    case RVVIRTIO_REG_QUEUE_DEVICE_LOW: write_addr(&q->device, false, val); break;
    case RVVIRTIO_REG_QUEUE_DEVICE_HIGH: write_addr(&q->device, true, val); break;
    default: break;
    }
}

/* 4.2.2.2: QueueNotify is ignored until DRIVER_OK (2.1.2: no buffer may be
 * consumed earlier). The one deviation is a queue the device model lists in
 * early_queues, served from FEATURES_OK because its driver polls for a reply
 * during attach, before the transport can set DRIVER_OK. */
static void write_notify(struct rvvirtio_dev *dev, uint32_t val)
{
    if (val >= dev->nqueues || !rvvirtio_queue_live(dev, val) ||
        !dev->queues[val].ready || dev->notify == NULL)
        return;
    dev->notify(dev, val);
}

static bool is_queue_reg(uint64_t off)
{
    return off == RVVIRTIO_REG_QUEUE_NUM || off == RVVIRTIO_REG_QUEUE_READY ||
           (off >= RVVIRTIO_REG_QUEUE_DESC_LOW &&
            off <= RVVIRTIO_REG_QUEUE_DEVICE_HIGH);
}

void rvvirtio_mmio_write(struct rvvirtio_dev *dev, uint64_t off, uint32_t val)
{
    switch (off) {
    case RVVIRTIO_REG_DEVICE_FEATURES_SEL: dev->device_features_sel = val; break;
    case RVVIRTIO_REG_DRIVER_FEATURES: write_driver_features(dev, val); break;
    case RVVIRTIO_REG_DRIVER_FEATURES_SEL: dev->driver_features_sel = val; break;
    case RVVIRTIO_REG_QUEUE_SEL: dev->queue_sel = val; break;
    case RVVIRTIO_REG_QUEUE_NOTIFY: write_notify(dev, val); break;
    case RVVIRTIO_REG_INTERRUPT_ACK:
        dev->interrupt_status &= ~val;
        rvvirtio_irq_update(dev);
        break;
    case RVVIRTIO_REG_STATUS: write_status(dev, val); break;
    default:
        /* read-only and unknown registers ignore writes */
        if (is_queue_reg(off))
            write_queue_reg(dev, off, val);
        break;
    }
}
