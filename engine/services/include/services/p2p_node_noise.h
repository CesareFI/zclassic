/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: read a live peer's Noise transport without racing the socket
 * thread that frees it.
 *
 * WHY. node->transport is owned by the socket thread (connman.c). It holds
 * node->cs_recv while it feeds the transport, and while it frees the
 * transport and sets it NULL when an inbound responder falls back to
 * plaintext (NOISE_PLAINTEXT_FALLBACK). An engine thread that dereferences
 * node->transport without cs_recv can read the pointer, lose the race to that
 * free, and then lock or read freed memory. Every engine read of
 * node->transport therefore goes through the helpers below, which take
 * node->cs_recv, read, and release it before returning.
 *
 * LOCK ORDER. cs_nodes -> cs_recv, as the socket thread takes them. A caller
 * may hold cs_nodes. A caller must NOT already hold node->cs_recv (it is not
 * recursive), and must not hold node->cs_send (the socket thread takes cs_send
 * under cs_recv). Message handlers run after msgprocessor released cs_recv,
 * so they may call these. The noise_transport's own lock is taken inside
 * (cs_recv -> transport lock), the same nesting the socket thread uses.
 *
 * A node reference (p2p_node_add_ref) keeps the node alive, not its
 * transport; this is why a held reference is not enough. */
#ifndef SERVICES_P2P_NODE_NOISE_H
#define SERVICES_P2P_NODE_NOISE_H

#include <stdbool.h>
#include <string.h>

#include "net/net.h"
#include "net/noise_transport.h"
#include "util/sync.h"

enum p2p_node_noise_phase {
    P2P_NODE_NOISE_NONE,        /* no transport attached: plaintext, or fallen back */
    P2P_NODE_NOISE_HANDSHAKING, /* transport attached, not yet established */
    P2P_NODE_NOISE_ESTABLISHED  /* transport attached and established */
};

/* Phase of `node`'s transport, read under cs_recv. When `snap` is non-NULL it
 * is zeroed and then filled by noise_transport_snapshot (snap->established is
 * true only for an established session). `node` must be non-NULL. */
static inline enum p2p_node_noise_phase p2p_node_noise_read(
    const struct p2p_node *node, struct noise_transport_snapshot *snap)
{
    struct p2p_node *n = (struct p2p_node *)node;
    if (snap)
        memset(snap, 0, sizeof(*snap));
    zcl_mutex_lock(&n->cs_recv);
    const struct noise_transport *t = n->transport;
    enum p2p_node_noise_phase phase = P2P_NODE_NOISE_NONE;
    if (t) {
        phase = t->state == NOISE_ESTABLISHED ? P2P_NODE_NOISE_ESTABLISHED
                                              : P2P_NODE_NOISE_HANDSHAKING;
        if (snap)
            (void)noise_transport_snapshot(t, snap);
    }
    zcl_mutex_unlock(&n->cs_recv);
    return phase;
}

/* True, with *snap filled, when the node holds an established Noise session.
 * False for a NULL node, no transport, or a session still handshaking. */
static inline bool p2p_node_noise_snapshot(
    const struct p2p_node *node, struct noise_transport_snapshot *snap)
{
    if (snap)
        memset(snap, 0, sizeof(*snap));
    if (!node || !snap)
        return false;
    (void)p2p_node_noise_read(node, snap);
    return snap->established;
}

/* True when a transport (established or not) is attached right now. */
static inline bool p2p_node_noise_attached(const struct p2p_node *node)
{
    if (!node)
        return false;
    struct p2p_node *n = (struct p2p_node *)node;
    zcl_mutex_lock(&n->cs_recv);
    bool attached = n->transport != NULL; /* pointer test only, no deref */
    zcl_mutex_unlock(&n->cs_recv);
    return attached;
}

#endif /* SERVICES_P2P_NODE_NOISE_H */
