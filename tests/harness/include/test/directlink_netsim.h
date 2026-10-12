/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Deterministic in-process datagram network for tests: nodes, fixed-latency
 * links, seeded loss, and NAT boxes with the three behaviours that matter for
 * hole punching. No sockets, no wall clock: time moves only when the test
 * calls ns_advance().
 *
 * NAT behaviours (RFC 4787 terms):
 *   NS_NAT_FULL_CONE         endpoint-independent mapping, endpoint-independent
 *                            filtering: any remote may use an existing mapping.
 *   NS_NAT_PORT_RESTRICTED   endpoint-independent mapping, address-and-port
 *                            dependent filtering: a remote may reach the node
 *                            only after the node sent to that exact address.
 *   NS_NAT_SYMMETRIC         address-and-port dependent mapping and filtering:
 *                            a fresh external port per destination.
 * A mapping or permission not refreshed by an outbound datagram for
 * `timeout_ms` expires. Each NAT serves one node. A destination that is
 * neither a NAT external address nor a public node address is unroutable and
 * the datagram is dropped.
 *
 * Not modelled: hairpinning (a node reaching its own mapped address), port
 * preservation and allocation patterns beyond sequential assignment (so no
 * symmetric-port prediction), several nodes behind one NAT, mapping refresh
 * by inbound traffic, per-state timeouts, reordering, duplication, MTU and
 * fragmentation, bandwidth and queueing, ICMP errors, IPv6 and NAT64, and
 * application-layer gateways. A result here shows the state machine copes
 * with the three behaviours above, not that it works on every real NAT.
 *
 * Every send and every delivery decision updates an FNV-1a digest, so two runs
 * with the same seed and the same calls can be compared byte for byte.
 */

#ifndef ZCL_TEST_DIRECTLINK_NETSIM_H
#define ZCL_TEST_DIRECTLINK_NETSIM_H

#include "gamelink/directlink_addr.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define NS_NODES 8
#define NS_MAPS 16
#define NS_PERMS 16
#define NS_QUEUE 1024
#define NS_INBOX 64
#define NS_PKT 64
#define NS_FIRST_EXT_PORT 40000u

enum ns_nat_kind {
    NS_NAT_NONE = 0,
    NS_NAT_FULL_CONE,
    NS_NAT_PORT_RESTRICTED,
    NS_NAT_SYMMETRIC
};

struct ns_dgram {
    struct directlink_addr from;
    uint8_t bytes[NS_PKT];
    size_t len;
};

struct ns_flight {
    bool used;
    int64_t at_ms;
    uint64_t order;
    struct directlink_addr to;
    struct ns_dgram dgram;
};

struct ns_map {
    bool used;
    uint16_t ext_port;
    struct directlink_addr dest; /* symmetric mappings only */
    int64_t last_ms;
};

struct ns_perm {
    bool used;
    struct directlink_addr remote;
    int64_t last_ms;
};

struct ns_node {
    bool used;
    struct directlink_addr addr; /* own address (private when natted) */
    int64_t access_ms;
    enum ns_nat_kind nat;
    uint8_t ext_ip[4];
    int64_t timeout_ms;
    uint16_t next_port;
    struct ns_map map[NS_MAPS];
    struct ns_perm perm[NS_PERMS];
    struct ns_dgram inbox[NS_INBOX];
    size_t inbox_head;
    size_t inbox_count;
};

struct ns {
    int64_t now_ms;
    uint64_t rng;
    uint32_t loss_ppm;
    uint64_t order;
    uint64_t digest;
    uint32_t events;
    uint32_t dropped_loss;
    uint32_t dropped_nat;
    uint32_t dropped_route;
    uint32_t delivered;
    struct ns_node node[NS_NODES];
    struct ns_flight flight[NS_QUEUE];
};

static inline struct directlink_addr ns_ip4(uint8_t a, uint8_t b, uint8_t c,
                                            uint8_t d, uint16_t port)
{
    struct directlink_addr addr;
    memset(&addr, 0, sizeof addr);
    addr.family = DIRECTLINK_V4;
    addr.ip[0] = a;
    addr.ip[1] = b;
    addr.ip[2] = c;
    addr.ip[3] = d;
    addr.port = port;
    return addr;
}

static inline void ns_mix(struct ns *s, uint64_t value)
{
    for (int i = 0; i < 8; i++) {
        s->digest ^= (value >> (8 * i)) & 0xFFu;
        s->digest *= UINT64_C(0x100000001B3);
    }
}

static inline void ns_trace(struct ns *s, uint64_t kind,
                            const struct directlink_addr *a,
                            const struct directlink_addr *b, size_t len)
{
    s->events++;
    ns_mix(s, (uint64_t)s->now_ms);
    ns_mix(s, kind);
    ns_mix(s, ((uint64_t)a->ip[0] << 24) | ((uint64_t)a->ip[3] << 16) | a->port);
    ns_mix(s, ((uint64_t)b->ip[0] << 24) | ((uint64_t)b->ip[3] << 16) | b->port);
    ns_mix(s, len);
}

static inline uint64_t ns_random(struct ns *s)
{
    s->rng += UINT64_C(0x9E3779B97F4A7C15);
    uint64_t z = s->rng;
    z = (z ^ (z >> 30)) * UINT64_C(0xBF58476D1CE4E5B9);
    z = (z ^ (z >> 27)) * UINT64_C(0x94D049BB133111EB);
    return z ^ (z >> 31);
}

static inline void ns_init(struct ns *s, uint64_t seed, uint32_t loss_ppm)
{
    memset(s, 0, sizeof *s);
    s->rng = seed;
    s->loss_ppm = loss_ppm;
    s->digest = UINT64_C(0xCBF29CE484222325);
}

/* A node with its own public address. */
static inline int ns_add_public(struct ns *s, struct directlink_addr addr,
                                int64_t access_ms)
{
    for (int i = 0; i < NS_NODES; i++) {
        if (s->node[i].used)
            continue;
        memset(&s->node[i], 0, sizeof s->node[i]);
        s->node[i].used = true;
        s->node[i].addr = addr;
        s->node[i].access_ms = access_ms;
        return i;
    }
    return -1;
}

/* A node with a private address behind one NAT box. */
static inline int ns_add_natted(struct ns *s, struct directlink_addr priv,
                                int64_t access_ms, enum ns_nat_kind kind,
                                const uint8_t ext_ip[4], int64_t timeout_ms)
{
    int i = ns_add_public(s, priv, access_ms);
    if (i < 0)
        return -1;
    s->node[i].nat = kind;
    memcpy(s->node[i].ext_ip, ext_ip, 4);
    s->node[i].timeout_ms = timeout_ms;
    s->node[i].next_port = NS_FIRST_EXT_PORT;
    return i;
}

static inline bool ns_fresh(const struct ns *s, const struct ns_node *n,
                            int64_t last_ms)
{
    return s->now_ms - last_ms <= n->timeout_ms;
}

static inline struct ns_map *ns_find_map(struct ns *s, struct ns_node *n,
                                         const struct directlink_addr *dest)
{
    for (int i = 0; i < NS_MAPS; i++) {
        struct ns_map *m = &n->map[i];
        if (!m->used)
            continue;
        if (!ns_fresh(s, n, m->last_ms)) {
            m->used = false;
            continue;
        }
        if (n->nat != NS_NAT_SYMMETRIC || directlink_addr_equal(&m->dest, dest))
            return m;
    }
    return NULL;
}

static inline struct ns_map *ns_new_map(struct ns *s, struct ns_node *n,
                                        const struct directlink_addr *dest)
{
    for (int i = 0; i < NS_MAPS; i++) {
        if (n->map[i].used)
            continue;
        n->map[i].used = true;
        n->map[i].ext_port = n->next_port++;
        n->map[i].dest = *dest;
        n->map[i].last_ms = s->now_ms;
        return &n->map[i];
    }
    return NULL;
}

static inline void ns_touch_perm(struct ns *s, struct ns_node *n,
                                 const struct directlink_addr *remote)
{
    struct ns_perm *slot = NULL;
    for (int i = 0; i < NS_PERMS; i++) {
        struct ns_perm *p = &n->perm[i];
        if (p->used && directlink_addr_equal(&p->remote, remote)) {
            p->last_ms = s->now_ms;
            return;
        }
        if (!slot && (!p->used || !ns_fresh(s, n, p->last_ms)))
            slot = p;
    }
    if (slot) {
        slot->used = true;
        slot->remote = *remote;
        slot->last_ms = s->now_ms;
    }
}

/* The source address the network sees for a datagram a node sends to `dest`. */
static inline bool ns_translate_out(struct ns *s, struct ns_node *n,
                                    const struct directlink_addr *dest,
                                    struct directlink_addr *src)
{
    *src = n->addr;
    if (n->nat == NS_NAT_NONE)
        return true;
    struct ns_map *m = ns_find_map(s, n, dest);
    if (!m)
        m = ns_new_map(s, n, dest);
    if (!m)
        return false;
    m->last_ms = s->now_ms;
    if (n->nat == NS_NAT_PORT_RESTRICTED)
        ns_touch_perm(s, n, dest);
    memset(src, 0, sizeof *src);
    src->family = DIRECTLINK_V4;
    memcpy(src->ip, n->ext_ip, 4);
    src->port = m->ext_port;
    return true;
}

/* The node that owns `addr` (public node address or NAT external address). */
static inline int ns_route(const struct ns *s, const struct directlink_addr *addr)
{
    for (int i = 0; i < NS_NODES; i++) {
        const struct ns_node *n = &s->node[i];
        if (!n->used)
            continue;
        if (n->nat == NS_NAT_NONE ? directlink_addr_equal(&n->addr, addr)
                                  : memcmp(n->ext_ip, addr->ip, 4) == 0)
            return i;
    }
    return -1;
}

static inline bool ns_send(struct ns *s, int node, const struct directlink_addr *to,
                           const uint8_t *bytes, size_t len)
{
    if (node < 0 || node >= NS_NODES || !s->node[node].used || len > NS_PKT)
        return false;
    struct ns_node *n = &s->node[node];
    struct directlink_addr src;
    if (!ns_translate_out(s, n, to, &src))
        return false;
    ns_trace(s, 1, &src, to, len);
    int dst = ns_route(s, to);
    if (dst < 0) {
        s->dropped_route++;
        ns_trace(s, 2, &src, to, len);
        return true;
    }
    if (ns_random(s) % 1000000u < s->loss_ppm) {
        s->dropped_loss++;
        ns_trace(s, 3, &src, to, len);
        return true;
    }
    for (int i = 0; i < NS_QUEUE; i++) {
        struct ns_flight *f = &s->flight[i];
        if (f->used)
            continue;
        f->used = true;
        f->at_ms = s->now_ms + n->access_ms + s->node[dst].access_ms;
        f->order = s->order++;
        f->to = *to;
        f->dgram.from = src;
        f->dgram.len = len;
        memcpy(f->dgram.bytes, bytes, len);
        return true;
    }
    return false;
}

static inline bool ns_admit_inbound(struct ns *s, struct ns_node *n,
                                    const struct directlink_addr *to,
                                    const struct directlink_addr *from)
{
    if (n->nat == NS_NAT_NONE)
        return true;
    for (int i = 0; i < NS_MAPS; i++) {
        struct ns_map *m = &n->map[i];
        if (!m->used || m->ext_port != to->port || !ns_fresh(s, n, m->last_ms))
            continue;
        if (n->nat == NS_NAT_FULL_CONE)
            return true;
        if (n->nat == NS_NAT_SYMMETRIC)
            return directlink_addr_equal(&m->dest, from);
        for (int j = 0; j < NS_PERMS; j++)
            if (n->perm[j].used && directlink_addr_equal(&n->perm[j].remote, from) &&
                ns_fresh(s, n, n->perm[j].last_ms))
                return true;
        return false;
    }
    return false;
}

static inline void ns_deliver(struct ns *s, const struct ns_flight *f)
{
    int dst = ns_route(s, &f->to);
    struct ns_node *n = dst >= 0 ? &s->node[dst] : NULL;
    if (!n || !ns_admit_inbound(s, n, &f->to, &f->dgram.from)) {
        s->dropped_nat++;
        ns_trace(s, 4, &f->dgram.from, &f->to, f->dgram.len);
        return;
    }
    if (n->inbox_count >= NS_INBOX) {
        s->dropped_route++;
        return;
    }
    n->inbox[(n->inbox_head + n->inbox_count++) % NS_INBOX] = f->dgram;
    s->delivered++;
    ns_trace(s, 5, &f->dgram.from, &f->to, f->dgram.len);
}

/* Deliver everything due at or before `to_ms`, in (time, send order). */
static inline void ns_advance(struct ns *s, int64_t to_ms)
{
    for (;;) {
        struct ns_flight *best = NULL;
        for (int i = 0; i < NS_QUEUE; i++) {
            struct ns_flight *f = &s->flight[i];
            if (f->used && f->at_ms <= to_ms &&
                (!best || f->at_ms < best->at_ms ||
                 (f->at_ms == best->at_ms && f->order < best->order)))
                best = f;
        }
        if (!best)
            break;
        if (best->at_ms > s->now_ms)
            s->now_ms = best->at_ms;
        ns_deliver(s, best);
        best->used = false;
    }
    if (to_ms > s->now_ms)
        s->now_ms = to_ms;
}

static inline bool ns_recv(struct ns *s, int node, struct ns_dgram *out)
{
    if (node < 0 || node >= NS_NODES)
        return false;
    struct ns_node *n = &s->node[node];
    if (n->inbox_count == 0)
        return false;
    *out = n->inbox[n->inbox_head];
    n->inbox_head = (n->inbox_head + 1) % NS_INBOX;
    n->inbox_count--;
    return true;
}

#endif /* ZCL_TEST_DIRECTLINK_NETSIM_H */
