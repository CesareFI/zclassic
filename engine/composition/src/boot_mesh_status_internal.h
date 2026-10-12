/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Purpose: the mesh-status lane's private cross-TU contract. The combined
 * file passed the 800-line shape ceiling, so the requester lane (begin:
 * pairing preflight, session lookup, pending admission, request send) lives
 * in boot_mesh_status_requester.c while boot_mesh_status.c keeps the shared
 * state, the pure helpers, the responder lane, receipt ingress, poll, and
 * lifecycle. Production code outside those two translation units must not
 * include this header; the focused wire test includes it to exercise the
 * exact bounded-table contract.
 */

#ifndef ZCL_CONFIG_BOOT_MESH_STATUS_INTERNAL_H
#define ZCL_CONFIG_BOOT_MESH_STATUS_INTERNAL_H

#include "models/mesh_pairing.h"
#include "vcs/zcode_dht_delegation.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct boot_svc_ctx;
struct mesh_status_request_v1;
struct msg_processor;
struct net_manager;
struct noise_transport_snapshot;
struct p2p_node;

/* Locked snapshot of the wired composition context and its generation.
 * Defined in boot_mesh_status.c. */
struct boot_svc_ctx *mesh_status_service(uint64_t *generation_out);

/* Pending-table primitives for the requester lane; each takes the lane lock
 * internally. admit evicts expired entries and refuses a still-full table;
 * it never destroys a live request. retract clears the entry only when it
 * still names this exact request and has not completed. */
bool mesh_status_request_id_free(const uint8_t request_id[32]);
bool mesh_status_pending_admit(const struct mesh_status_request_v1 *request,
                               const uint8_t expected_responder_master[32],
                               const uint8_t expected_responder_online[32],
                               uint64_t generation);
void mesh_status_pending_retract(const uint8_t request_id[32]);

/* Prefix+kind frame send on zpkgswm. Defined in boot_mesh_status.c. */
bool mesh_status_send(struct msg_processor *mp, struct p2p_node *node,
                      uint8_t kind, const uint8_t *wire, size_t wire_len);

/* Mesh-lane shared helpers, defined in boot_mesh_status.c. The responder's
 * own receipt identity (filed local delegation + ACTIVE ZID master + online
 * key, fail-closed on every mismatch), and the connected-peer lookup: a
 * referenced p2p_node whose established Noise session names `peer_noise`,
 * with its session snapshot out; caller releases the reference. Both are
 * used by the mesh terminal lane too — one implementation, so fail-closed
 * identity and session lookup can never drift between the two lanes. */
bool boot_mesh_local_identity(struct node_db *ndb, const char *datadir,
                              uint8_t master_out[32],
                              uint8_t online_pub_out[32],
                              uint8_t online_seed_out[32]);
struct p2p_node *boot_mesh_find_session_peer(
    struct net_manager *nm, const uint8_t peer_noise[32],
    struct noise_transport_snapshot *session_out);

/* Most ready nodes one observation captures. The net manager's default is
 * 125 connections and a configured maximum is clamped near 1000, so this
 * covers any real table; the array is 8 KiB of stack. */
#define BOOT_MESH_OBSERVE_MAX_READY 1024u

/* "Does this node hold an established session with `peer_noise`". Membership
 * is fixed once, when the node table lock is held to capture every ready
 * node. Each captured node's session is read afterwards, one at a time, under
 * that node's own transport lock while its reference is held. This is not an
 * atomic view of all sessions: each read reports its node at its own later
 * moment, so a session that ends or changes between the capture and that read
 * is reported as read. A node that joins the table or becomes ready after the
 * capture is not seen until the next call. LIVE: a captured node's locked read
 * is established and names this peer. ABSENT: every ready node in the captured
 * membership was read under its transport lock, and none held an established
 * session naming this peer when read. INCOMPLETE (the zero value): more ready
 * nodes than the capture bound, a captured node had lost its transport when
 * read, or an argument was NULL. No reference is held on return. */
enum boot_mesh_session_observation {
    BOOT_MESH_SESSION_INCOMPLETE = 0,
    BOOT_MESH_SESSION_LIVE,
    BOOT_MESH_SESSION_ABSENT,
};
enum boot_mesh_session_observation boot_mesh_observe_session_peer(
    struct net_manager *nm, const uint8_t peer_noise[32]);

/* The paired peer's greatest-seq held delegation for the exact identity the
 * pairing row binds; two different online keys at that sequence are
 * ambiguous and fail closed. Used by both requester lanes — an open or a
 * status request must pre-flight the same authority the responder will
 * re-verify. Defined in boot_mesh_status.c. */
bool boot_mesh_peer_delegation(const struct db_mesh_pairing *row,
                               struct vcs_zcode_dht_delegation *out);

#endif /* ZCL_CONFIG_BOOT_MESH_STATUS_INTERNAL_H */
