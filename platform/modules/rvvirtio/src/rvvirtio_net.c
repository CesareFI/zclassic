/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: virtio-net (VIRTIO 1.2, section 5.1): one receiveq (0) and one
 * transmitq (1), 12-byte virtio_net_hdr, no offloads negotiated. */

#include "rvvirtio_priv.h"

#include <string.h>

/* 5.1.3: feature bits. */
#define NET_F_MAC (UINT64_C(1) << 5)
#define NET_F_STATUS (UINT64_C(1) << 16)
#define NET_S_LINK_UP 1u /* 5.1.4: status field */

/* 5.1.4: config: mac[6] @0, status u16 @6. */
static void net_fill_config(struct rvvirtio_net *n, const uint8_t mac[6])
{
    memcpy(n->dev.config, mac, 6);
    rvvirtio_put_le16(n->dev.config + 6, NET_S_LINK_UP);
    n->dev.config_len = 8;
}

/* 5.1.6.2: the transmit buffer is device-readable only: virtio_net_hdr then
 * the frame. An out-of-bounds frame is dropped but still completed. */
static void net_tx_one(struct rvvirtio_net *n)
{
    struct rvvirtio_dev *d = &n->dev;
    uint64_t total = d->chain.in_len;
    if (d->chain.out_len != 0) {
        rvvirtio_dev_fail(d);
        return;
    }
    bool sane = total >= RVVIRTIO_NET_HDR_LEN + RVVIRTIO_NET_FRAME_MIN &&
                total <= RVVIRTIO_NET_HDR_LEN + RVVIRTIO_NET_FRAME_MAX;
    if (sane) {
        if (!rvvirtio_chain_read(d, 0, n->buf, (size_t)total))
            return;
        n->tx(n->tx_ctx, n->buf + RVVIRTIO_NET_HDR_LEN,
              (size_t)total - RVVIRTIO_NET_HDR_LEN);
    }
    (void)rvvirtio_queue_push(d, RVVIRTIO_NET_TXQ, 0);
}

static void net_notify(struct rvvirtio_dev *dev, uint32_t queue)
{
    struct rvvirtio_net *n = (struct rvvirtio_net *)dev;
    if (queue != RVVIRTIO_NET_TXQ)
        return; /* rx buffers are only consumed when a frame arrives */
    for (uint32_t i = 0; i < dev->queues[RVVIRTIO_NET_TXQ].num; i++) {
        if (rvvirtio_queue_pop(dev, RVVIRTIO_NET_TXQ) != RVVIRTIO_POP_OK)
            return;
        net_tx_one(n);
        if (!rvvirtio_dev_running(dev))
            return;
    }
}

bool rvvirtio_net_receive(struct rvvirtio_net *net, const uint8_t *frame,
                          size_t len)
{
    struct rvvirtio_dev *d = &net->dev;
    if (frame == NULL || len < RVVIRTIO_NET_FRAME_MIN ||
        len > RVVIRTIO_NET_FRAME_MAX || !rvvirtio_dev_running(d))
        return false;
    if (rvvirtio_queue_pop(d, RVVIRTIO_NET_RXQ) != RVVIRTIO_POP_OK)
        return false;
    /* 5.1.6.3: receive buffers are device-writable and hold hdr + frame. */
    if (d->chain.in_len != 0 || d->chain.out_len < RVVIRTIO_NET_HDR_LEN + len) {
        rvvirtio_dev_fail(d);
        return false;
    }
    memset(net->buf, 0, RVVIRTIO_NET_HDR_LEN);
    net->buf[10] = 1; /* num_buffers = 1 without MRG_RXBUF (5.1.6.4) */
    memcpy(net->buf + RVVIRTIO_NET_HDR_LEN, frame, len);
    if (!rvvirtio_chain_write(d, 0, net->buf, RVVIRTIO_NET_HDR_LEN + len))
        return false;
    return rvvirtio_queue_push(d, RVVIRTIO_NET_RXQ,
                               (uint32_t)(RVVIRTIO_NET_HDR_LEN + len));
}

bool rvvirtio_net_init(struct rvvirtio_net *net, const struct rvvirtio_mem *mem,
                       const uint8_t mac[6], rvvirtio_net_tx_fn tx, void *tx_ctx)
{
    if (mem == NULL || mac == NULL || tx == NULL || mem->read == NULL ||
        mem->write == NULL)
        return false;
    memset(net, 0, sizeof(*net));
    net->tx = tx;
    net->tx_ctx = tx_ctx;
    rvvirtio_dev_setup(&net->dev, mem, RVVIRTIO_DEVICE_ID_NET,
                       NET_F_MAC | NET_F_STATUS, 2);
    net->dev.notify = net_notify;
    net_fill_config(net, mac);
    return true;
}
