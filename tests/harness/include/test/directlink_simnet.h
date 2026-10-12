/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Adapters that let gamelink sessions and the direct-link channel run over
 * the deterministic network in directlink_netsim.h: a datagram seam bound to
 * one simulated node and a monotonic clock that reads the simulated time.
 * No sockets and no wall clock. */
#ifndef ZCL_TEST_DIRECTLINK_SIMNET_H
#define ZCL_TEST_DIRECTLINK_SIMNET_H

#include "gamelink/gamelink.h"
#include "test/directlink_netsim.h"

struct simnet_end {
    struct ns *net;
    int node;
    uint32_t sent;
    uint32_t received;
    uint32_t refused;
};

static inline int simnet_send(void *ctx, const uint8_t addr[4], uint16_t port,
                              const void *data, size_t len)
{
    struct simnet_end *end = ctx;
    struct directlink_addr to = ns_ip4(addr[0], addr[1], addr[2], addr[3], port);
    if (!ns_send(end->net, end->node, &to, data, len)) {
        end->refused++;
        return -1;
    }
    end->sent++;
    return (int)len;
}

static inline int simnet_recv(void *ctx, void *data, size_t cap,
                              uint8_t addr[4], uint16_t *port)
{
    struct simnet_end *end = ctx;
    struct ns_dgram d;
    if (!ns_recv(end->net, end->node, &d))
        return 0;
    if (d.len > cap)
        return 0;
    memcpy(data, d.bytes, d.len);
    memcpy(addr, d.from.ip, 4);
    *port = d.from.port;
    end->received++;
    return (int)d.len;
}

static inline struct gamelink_ops simnet_ops(struct simnet_end *end)
{
    return (struct gamelink_ops){.send = simnet_send, .recv = simnet_recv,
                                 .ctx = end};
}

static inline int64_t simnet_now_ns(void *self)
{
    return ((const struct ns *)self)->now_ms * INT64_C(1000000);
}

static inline int64_t simnet_wall_ms(void *self)
{
    return ((const struct ns *)self)->now_ms;
}

static inline clock_iface_t simnet_clock(const struct ns *net)
{
    return (clock_iface_t){.now_monotonic_ns = simnet_now_ns,
                           .now_wall_ms = simnet_wall_ms,
                           .self = (void *)net};
}

#endif /* ZCL_TEST_DIRECTLINK_SIMNET_H */
