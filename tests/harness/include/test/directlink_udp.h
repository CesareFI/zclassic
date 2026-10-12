/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * A gamelink datagram seam over one real, non-blocking IPv4 UDP socket on
 * 127.0.0.1, for tests and measurements that run below the NAT layer. */
#ifndef ZCL_TEST_DIRECTLINK_UDP_H
#define ZCL_TEST_DIRECTLINK_UDP_H

#include "gamelink/gamelink.h"
#include "platform/socket_compat.h"

#include <stdbool.h>
#include <string.h>

struct udp_end {
    platform_socket_t sock;
    uint16_t port;
};

static inline bool udp_end_open(struct udp_end *end)
{
    memset(end, 0, sizeof *end);
    end->sock = platform_socket_open(AF_INET, SOCK_DGRAM, 0, true, true);
    if (end->sock == PLATFORM_SOCKET_INVALID)
        return false;
    struct sockaddr_in local;
    memset(&local, 0, sizeof local);
    local.sin_family = AF_INET;
    if (platform_socket_parse_address(AF_INET, "127.0.0.1", &local.sin_addr) != 1 ||
        platform_socket_bind(end->sock, (const struct sockaddr *)&local,
                             sizeof local) != 0)
        return false;
    struct sockaddr_in bound;
    size_t bound_size = sizeof bound;
    memset(&bound, 0, sizeof bound);
    if (platform_socket_local_address(end->sock, (struct sockaddr *)&bound,
                                      &bound_size) != 0)
        return false;
    end->port = ntohs(bound.sin_port);
    return true;
}

static inline void udp_end_close(struct udp_end *end)
{
    if (end->sock != PLATFORM_SOCKET_INVALID)
        (void)platform_socket_close(end->sock);
    end->sock = PLATFORM_SOCKET_INVALID;
}

static inline int udp_send(void *ctx, const uint8_t addr[4], uint16_t port,
                           const void *data, size_t len)
{
    const struct udp_end *end = ctx;
    struct sockaddr_in to;
    memset(&to, 0, sizeof to);
    to.sin_family = AF_INET;
    to.sin_port = htons(port);
    memcpy(&to.sin_addr.s_addr, addr, 4);
    return (int)sendto(end->sock, data, len, 0, (const struct sockaddr *)&to,
                       (socklen_t)sizeof to);
}

static inline int udp_recv(void *ctx, void *data, size_t cap, uint8_t addr[4],
                           uint16_t *port)
{
    const struct udp_end *end = ctx;
    struct sockaddr_in from;
    socklen_t from_size = (socklen_t)sizeof from;
    memset(&from, 0, sizeof from);
    int n = (int)recvfrom(end->sock, data, cap, 0, (struct sockaddr *)&from,
                          &from_size);
    if (n <= 0)
        return 0;
    memcpy(addr, &from.sin_addr.s_addr, 4);
    *port = ntohs(from.sin_port);
    return n;
}

static inline struct gamelink_ops udp_ops(struct udp_end *end)
{
    return (struct gamelink_ops){.send = udp_send, .recv = udp_recv, .ctx = end};
}

#endif /* ZCL_TEST_DIRECTLINK_UDP_H */
