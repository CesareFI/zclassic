/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * noise_upgrade.c — one-shot legacy-to-Noise reconnect policy. */

#include <stdatomic.h>
#include "net/connman.h"
#include "core/utiltime.h"
#include "net/noise_transport.h"
#include "util/log_macros.h"

bool connman_request_noise_upgrade(struct connman *cm, struct p2p_node *node)
{
    if (!cm || !node || node->inbound || node->transport ||
        !cm->manager.noise_enabled ||
        (node->services & NODE_NOISE_HYBRID) == 0)
        return false;

    /* node->addr is the dial-time capability snapshot.  If it already knew
     * the Noise bit, net.c would have armed Noise before sending any version
     * bytes; do not create a reconnect loop if a caller reaches this path
     * anyway. */
    if ((node->addr.nServices & NODE_NOISE_HYBRID) != 0)
        return false;

    node->addr.nServices |= NODE_NOISE_HYBRID;

    /* Pinned addnodes bypass addrman selection, so update their durable
     * in-process dial entry as well. */
    bool matched_addnode = false;
    for (int i = 0; i < cm->num_addnodes; i++) {
        if (net_addr_eq(&cm->addnodes[i].svc.addr, &node->addr.svc.addr) &&
            cm->addnodes[i].svc.port == node->addr.svc.port) {
            matched_addnode = true;
            cm->addnodes[i].nServices |= NODE_NOISE_HYBRID;
            /* This disconnect is the successful capability-upgrade path,
             * not a failed dial. Make the specifically matched addnode
             * immediately eligible for its one Noise reconnect instead of
             * stranding it behind the ordinary 30-second retry cooldown. */
            cm->addnode_last_attempt[i] = 0;
            cm->addnode_backoff_sec[i] = 0;
        }
    }

    /* A learned ZENDP hop is deliberately a one-shot hint, not an addnode.
     * Its first connection may still be legacy because the Noise capability
     * was not known until VERSION arrived. Preserve exactly that same signed
     * endpoint for the one controlled Noise reconnect. This is also required
     * in -connect mode, where addrman is intentionally not a dial source. */
    if (!matched_addnode && !connman_queue_dht_hint(cm, &node->addr))
        LOG_FAIL("net", "cannot retain learned peer %s for Noise reconnect",
                 node->addr_name);

    /* addrman_add merges service bits for an existing entry even if it does
     * not add another bucket reference.  Loopback addnodes are covered above. */
    if (net_addr_is_routable(&node->addr.svc.addr)) {
        struct net_addr source = node->addr.svc.addr;
        (void)addrman_add(&cm->manager.addrman, &node->addr, &source, 0);
    }

    (void)p2p_node_request_disconnect(
        node, P2P_DISCONNECT_NOISE_UPGRADE,
        P2P_DISCONNECT_SOURCE_DIAL_SCHEDULER,
        node->endpoint_generation);
    LOG_INFO("net", "peer %s advertised Noise transport; capability persisted "
             "and controlled Noise reconnect requested", node->addr_name);
    return true;
}

/* True when a peer short of PEER_HANDSHAKE_COMPLETE exceeded the 90 s version
 * handshake budget, the Noise handshake budget, or its Noise quarantine. */
bool connman_handshake_overdue(const struct p2p_node *n, int64_t now_check)
{
    const int64_t quarantined_since = atomic_load_explicit(
        &n->noise_quarantine_since, memory_order_acquire);
    return n->state < PEER_HANDSHAKE_COMPLETE &&
           ((n->time_connected > 0 && now_check - n->time_connected > 90) ||
            noise_transport_handshake_expired(n->transport, GetTimeMicros()) ||
            (quarantined_since > 0 &&
             now_check - quarantined_since > P2P_NOISE_QUARANTINE_SECS));
}

/* A node stops processing messages once it is disconnecting or while its
 * plaintext link is quarantined (queued messages are neither parsed nor
 * relayed; the quarantine deadline closes the link). */
bool p2p_node_processing_halted(const struct p2p_node *node)
{
    return node->disconnect ||
           atomic_load_explicit(&node->noise_quarantine_since,
                                memory_order_acquire) != 0;
}
