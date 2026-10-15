/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Noise requirement checks: a node with Noise enabled drops plaintext links to
 * peers advertising NODE_NOISE_HYBRID, and a Noise initiator drops a plaintext
 * answer. Links without the bit, or with Noise disabled, are unaffected. */

#include <stdatomic.h>
#include <sys/socket.h>
#include <unistd.h>
#include "test/test_core.h"
#include "net/connman.h"
#include "net/msg_internal.h"
#include "core/hash.h"
#include "net/msgprocessor.h"
#include "net/noise_transport.h"
#include "net/protocol.h"
#include "net/version.h"
#include "util/safe_alloc.h"
#include "test/test_connman_addnode_fallback_priv.h"

static bool noise_required_disconnected_for_upgrade(const struct p2p_node *node)
{
    return atomic_load(&node->disconnect_reason) ==
           (int)P2P_DISCONNECT_NOISE_UPGRADE;
}

static bool noise_required_feed_version(struct connman *cm,
                                        struct p2p_node *node,
                                        uint64_t services)
{
    struct msg_processor mp;
    memset(&mp, 0, sizeof(mp));
    mp.net_mgr = &cm->manager;
    mp.params = chain_params_get();
    cm->manager.owner = cm;

    struct version_message ver;
    msg_version_build(&ver, &mp, node, 7);
    ver.services = services;
    ver.nonce = cm->manager.local_host_nonce + 1;

    struct byte_stream s, r;
    stream_init(&s, 256);
    version_message_serialize(&ver, &s);
    stream_init_from_data(&r, s.data, s.size);
    bool ok = process_version(&mp, node, &r);
    stream_free(&s);
    return ok;
}

/* Feeds one empty-payload message to the node and runs the dispatch loop. */
static bool noise_required_dispatch_empty(struct connman *cm,
                                          struct p2p_node *node,
                                          const char *command)
{
    struct msg_processor mp;
    memset(&mp, 0, sizeof(mp));
    mp.net_mgr = &cm->manager;
    mp.params = chain_params_get();
    struct msg_header hdr;
    msg_header_init_full(&hdr, cm->manager.message_start, command, 0);
    unsigned char h[32];
    hash256((const unsigned char *)"", 0, h);
    memcpy(&hdr.nChecksum, h, 4);
    return p2p_node_receive_bytes(node, (const char *)&hdr, MSG_HEADER_SIZE,
                                  cm->manager.message_start) &&
           msg_process_messages(&mp, node);
}

static bool noise_required_queue_pending_relay(struct p2p_node *node)
{
    node->inventory_to_send = zcl_calloc(1, sizeof(*node->inventory_to_send),
                                         "noise_required_inv");
    node->addr_to_send = zcl_calloc(1, sizeof(*node->addr_to_send),
                                    "noise_required_addr");
    if (!node->inventory_to_send || !node->addr_to_send)
        return false;
    node->inventory_to_send_count = node->inventory_to_send_cap = 1;
    node->addr_to_send_count = node->addr_to_send_cap = 1;
    return true;
}

static bool noise_required_queue_commands(struct connman *cm,
                                          struct p2p_node *node)
{
    /* inv, addr, ping, getdata and verack must stay unprocessed. */
    static const char *const cmds[] = { "inv", "addr", "ping", "getdata",
                                        "verack" };
    unsigned char h[32];
    hash256((const unsigned char *)"", 0, h);
    for (size_t i = 0; i < sizeof(cmds) / sizeof(cmds[0]); i++) {
        struct msg_header hdr;
        msg_header_init_full(&hdr, cm->manager.message_start, cmds[i], 0);
        memcpy(&hdr.nChecksum, h, 4);
        if (!p2p_node_receive_bytes(node, (const char *)&hdr, MSG_HEADER_SIZE,
                                    cm->manager.message_start))
            return false;
    }
    return node->recv_msg_count == 5;
}

/* Nothing is dequeued, scored, answered, or allowed to complete the
 * handshake. */
static bool noise_required_dispatch_halted(struct connman *cm,
                                           struct msg_processor *mp,
                                           struct p2p_node *node)
{
    const size_t sent_before = node->send_size;
    return noise_required_queue_commands(cm, node) &&
           msg_process_messages(mp, node) && node->recv_msg_count == 5 &&
           node->misbehavior == 0 && !node->disconnect &&
           node->send_size == sent_before &&
           node->state < PEER_HANDSHAKE_COMPLETE;
}

/* The trickle sends nothing while quarantined, even with relay pending. */
static bool noise_required_trickle_silent(struct msg_processor *mp,
                                          struct p2p_node *node)
{
    const size_t sent_before = node->send_size;
    return noise_required_queue_pending_relay(node) &&
           msg_send_messages(mp, node, true) &&
           node->send_size == sent_before &&
           node->inventory_to_send_count == 1 &&
           node->addr_to_send_count == 1;
}

/* The real sweep step flags the peer after the deadline and not before. */
static bool noise_required_sweep_deadline(struct connman *cm,
                                          struct p2p_node *node, int64_t since)
{
    const int64_t deadline = since + P2P_NOISE_QUARANTINE_SECS;
    return !connman_sweep_handshake_deadline(cm, node, deadline, false, 0) &&
           !node->disconnect &&
           connman_sweep_handshake_deadline(cm, node, deadline + 1, false, 0) &&
           node->disconnect;
}

static bool noise_required_quarantined_ok(struct connman *cm,
                                          struct p2p_node *node)
{
    struct msg_processor mp;
    memset(&mp, 0, sizeof(mp));
    mp.net_mgr = &cm->manager;
    mp.params = chain_params_get();
    const int64_t since = atomic_load(&node->noise_quarantine_since);
    return since != 0 && !node->disconnect &&
           p2p_node_processing_halted(node) &&
           noise_required_dispatch_halted(cm, &mp, node) &&
           noise_required_trickle_silent(&mp, node) &&
           noise_required_sweep_deadline(cm, node, since);
}

/* Outbound: the upgrade disconnect is set, and because the target already
 * advertised Noise (no upgrade requested) the refused fallback backs off as a
 * protocol failure instead of redialing in a loop. */
static bool noise_required_outbound_ok(const struct connman *cm,
                                       const struct p2p_node *node)
{
    return noise_required_disconnected_for_upgrade(node) &&
           cm->addnode_protocol_failures[0] == 1 &&
           cm->addnode_backoff_sec[0] == 60 &&
           cm->addnode_last_attempt[0] > 0;
}

/* Inbound: our version reached the dialer before the quarantine began. */
static bool noise_required_inbound_ok(struct connman *cm,
                                      struct p2p_node *node, int dialer_fd)
{
    char wire[512];
    ssize_t got = recv(dialer_fd, wire, sizeof(wire), MSG_DONTWAIT);
    return got >= 16 && memcmp(wire + 4, "version", 7) == 0 &&
           noise_required_quarantined_ok(cm, node);
}

static int noise_required_check_plaintext_refused(bool inbound)
{
    int failures = 0;
    printf("connman_noise_required: plaintext %s link to a bit-26 peer is "
           "refused (outbound: upgrade disconnect, inbound: quarantine)... ", inbound ? "inbound" : "outbound");
    {
        chain_params_select(CHAIN_MAIN);
        struct connman cm;
        struct node_signals sigs;
        memset(&sigs, 0, sizeof(sigs));
        bool ok = connman_init(&cm, chain_params_get(), &sigs);
        cm.manager.noise_enabled = true;
        int sv[2] = { -1, -1 };
        ok = ok && socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0;
        struct p2p_node *node = add_test_peer(
            &cm, 51, 178, 179, 75, PEER_CONNECTED, inbound, false);
        ok = ok && node != NULL;
        if (node && sv[0] >= 0) {
            /* A live socket keeps queued sends from failing and racing the
             * disconnect reason under test. */
            node->socket = sv[0];
            node->version = 0;
            node->addr.nServices |= NODE_NOISE_HYBRID;
            if (!inbound)
                cm.addnodes[cm.num_addnodes++] = node->addr;
            ok = ok && noise_required_feed_version(
                &cm, node, NODE_NETWORK | NODE_NOISE_HYBRID);
            ok = ok && node->state < PEER_HANDSHAKE_COMPLETE;
            ok = ok && (inbound ? noise_required_inbound_ok(&cm, node, sv[1])
                                : noise_required_outbound_ok(&cm, node));
        }
        connman_free(&cm);
        if (sv[1] >= 0)
            close(sv[1]);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

static int noise_required_check_dialer_upgrades(void)
{
    int failures = 0;
    printf("connman_noise_required: a dialer that learns bit 26 redials over "
           "Noise... ");
    {
        chain_params_select(CHAIN_MAIN);
        struct connman cm;
        struct node_signals sigs;
        memset(&sigs, 0, sizeof(sigs));
        bool ok = connman_init(&cm, chain_params_get(), &sigs);
        cm.manager.noise_enabled = true;
        int sv[2] = { -1, -1 };
        ok = ok && socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0;
        struct p2p_node *node = add_test_peer(
            &cm, 51, 178, 179, 77, PEER_CONNECTED, false, false);
        ok = ok && node != NULL;
        if (node && sv[0] >= 0) {
            node->socket = sv[0];
            node->version = 0;
            ok = ok && !noise_hybrid_dial_allowed(true, node->addr.nServices);
            ok = ok && noise_required_feed_version(
                &cm, node, NODE_NETWORK | NODE_NOISE_HYBRID);
            ok = ok && noise_required_disconnected_for_upgrade(node);
            ok = ok && noise_hybrid_dial_allowed(true, node->addr.nServices);
        }
        connman_free(&cm);
        if (sv[1] >= 0)
            close(sv[1]);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

static int noise_required_check_unaffected(void)
{
    int failures = 0;
    printf("connman_noise_required: Noise-off, non-bit-26 and Noise links "
           "are unaffected... ");
    {
        chain_params_select(CHAIN_MAIN);
        struct connman cm;
        struct node_signals sigs;
        memset(&sigs, 0, sizeof(sigs));
        bool ok = connman_init(&cm, chain_params_get(), &sigs);
        struct p2p_node *node = add_test_peer(
            &cm, 51, 178, 179, 76, PEER_CONNECTED, false, false);
        ok = ok && node != NULL;
        if (node) {
            node->version = PROTOCOL_VERSION;
            node->services = NODE_NETWORK | NODE_NOISE_HYBRID;
            ok = ok && !msg_version_plaintext_link_refused(&cm.manager, node);
            /* Noise off: messages from a bit-26 peer dispatch normally. */
            ok = ok && noise_required_dispatch_empty(&cm, node, "ping") &&
                 node->recv_msg_count == 0 &&
                 !p2p_node_processing_halted(node);
            cm.manager.noise_enabled = true;
            ok = ok && msg_version_plaintext_link_refused(&cm.manager, node);
            node->services = NODE_NETWORK;
            ok = ok && !msg_version_plaintext_link_refused(&cm.manager, node);
            /* Noise on, no bit 26: dispatches normally. */
            ok = ok && noise_required_dispatch_empty(&cm, node, "ping") &&
                 node->recv_msg_count == 0 &&
                 !p2p_node_processing_halted(node);
            node->services = NODE_NETWORK | NODE_NOISE_HYBRID;
            uint8_t priv[32] = { 1 };
            node->transport = noise_transport_begin(
                false, priv, cm.manager.message_start, NULL, NULL);
            ok = ok && node->transport != NULL;
            ok = ok && !msg_version_plaintext_link_refused(&cm.manager, node);
        }
        connman_free(&cm);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

static int noise_required_check_initiator_drops_plaintext(void)
{
    int failures = 0;
    printf("connman_noise_required: Noise initiator drops a plaintext "
           "answer... ");
    {
        const unsigned char magic[4] = { 0x24, 0xe9, 0x27, 0x64 };
        uint8_t priv[32] = { 7 };
        uint8_t *msg1 = NULL, *wire = NULL, *plain = NULL;
        size_t msg1_len = 0, wire_len = 0, plain_len = 0;
        struct noise_transport *t =
            noise_transport_begin(true, priv, magic, &msg1, &msg1_len);
        bool ok = t != NULL && t->state == NOISE_KEY_SENT;
        const uint8_t answer[24] = { 0x24, 0xe9, 0x27, 0x64, 'v', 'e', 'r' };
        if (ok)
            ok = noise_transport_feed(t, answer, 2, &wire, &wire_len,
                                      &plain, &plain_len) &&
                 t->state == NOISE_KEY_SENT;
        free(wire);
        free(plain);
        wire = plain = NULL;
        if (ok)
            ok = !noise_transport_feed(t, answer + 2, sizeof(answer) - 2,
                                       &wire, &wire_len, &plain, &plain_len);
        ok = ok && t->state == NOISE_FAILED;
        free(wire);
        free(plain);
        free(msg1);
        noise_transport_free(t);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

int check_connman_noise_required(void)
{
    int failures = 0;
    failures += noise_required_check_plaintext_refused(false);
    failures += noise_required_check_plaintext_refused(true);
    failures += noise_required_check_dialer_upgrades();
    failures += noise_required_check_unaffected();
    failures += noise_required_check_initiator_drops_plaintext();
    return failures;
}
