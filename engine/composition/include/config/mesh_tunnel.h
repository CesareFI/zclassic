/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: The TCP tunnel service on the mesh stream primitive — the
 * loopback-only acceptor, the explicit per-peer allow table that admits a
 * target port, and the local listeners the operator opens.
 *
 * A tunnel is not a wire. It is the second service registered on
 * config/mesh_stream.h, exactly as the confined terminal is the first: no
 * new frame, no new pump for streams, no second session table. One local
 * TCP connection is one stream named "tcp"; the stream owns the framing,
 * the credit window, the idle mark, the per-peer cap and the lifetime.
 *
 * The two halves:
 *
 *   INITIATOR  binds a listener on 127.0.0.1:<local_port> and, for every
 *              connection it accepts there, opens one stream carrying a
 *              fixed 8-byte header that names the target port and nothing
 *              else.
 *   ACCEPTOR   dials 127.0.0.1:<port> — ALWAYS loopback, never an address
 *              the peer chose, never a name to resolve — and only when a
 *              local allow row admits this exact (peer, port) pair.
 *
 * Nothing is allowed by default. The allow table is a file in the datadir
 * with one row per line, `<pairing_id> <port> <why>`; no file means no row,
 * and no row means every OPEN is refused by name. There is no wildcard
 * port, no default row, and no non-loopback target: the acceptor's dial
 * address is a compile-time constant, so a widened allow row still cannot
 * reach anything but this machine's own loopback. Forwarding ssh is one
 * row for port 22, written by the operator, on the machine being reached.
 *
 * Flow control is the stream's credit, spent by bytes and nothing else.
 * A side never reads more from its socket than the credit it holds, and
 * grants credit back only as bytes actually leave for the socket, so one
 * stream's buffer is one chunk — a slow reader stalls its own tunnel and
 * never grows the node's memory. Socket EOF becomes CLOSE; CLOSE shuts
 * the socket down.
 *
 * Every refusal is named (mesh_tunnel_refusal_string) and fails closed.
 */

#ifndef ZCL_CONFIG_MESH_TUNNEL_H
#define ZCL_CONFIG_MESH_TUNNEL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct boot_svc_ctx;
struct rpc_table;

/* The stream service name. Short, fixed, and the same on both ends. */
#define MESH_TUNNEL_SERVICE_NAME "tcp"

/* The allow table's file name inside the datadir. */
#define MESH_TUNNEL_ALLOW_FILE "mesh_tunnel_allow"

/* One chunk is one frame and one whole credit window, so a side that has
 * not drained holds exactly one chunk and the peer's next DATA cannot
 * arrive until it has. Well under MESH_STREAM_PAYLOAD_MAX. */
#define MESH_TUNNEL_CHUNK (uint32_t)(16u * 1024u)

/* Bounded tables: local listeners the operator may hold open at once, and
 * allow rows this node will read. Both fail closed when full. */
#define MESH_TUNNEL_LISTENERS_MAX 8u
#define MESH_TUNNEL_ALLOW_MAX 64u
/* How often a live acceptor stream re-reads the pairing that admitted it. */
#define MESH_TUNNEL_PAIRING_RECHECK_SECONDS 5

/* Accepts drained per listener tick, so one busy listener can never hold
 * the net domain's tick. */
#define MESH_TUNNEL_ACCEPTS_PER_TICK 4

/* The prose an allow row carries, and the allow file's read ceiling. */
#define MESH_TUNNEL_WHY_MAX 96u
#define MESH_TUNNEL_ALLOW_FILE_MAX (size_t)(64u * 1024u)

/* The OPEN payload: "ZTUN", version, reserved, target port big-endian. */
#define MESH_TUNNEL_OPEN_BYTES 8u

/* Every named end of a tunnel. The stream primitive's own verdicts stay
 * its own; these are what the tunnel service decides, and they ride the
 * CLOSE payload under MESH_STREAM_CLOSED_BY_SERVICE. */
enum mesh_tunnel_refusal {
    MESH_TUNNEL_OK = 0,
    /* The OPEN header was not this service's header. */
    MESH_TUNNEL_REFUSED_MALFORMED = 1,
    /* No allow row on this node admits this (peer, port). */
    MESH_TUNNEL_REFUSED_TARGET_NOT_ALLOWED = 2,
    /* An allow row admitted it and nothing was listening there. */
    MESH_TUNNEL_REFUSED_DIAL_FAILED = 3,
    /* This node already holds its share of tunnels or listeners. */
    MESH_TUNNEL_REFUSED_CAP = 4,
    /* No composition context, no datadir, or no pairing row to name the
     * peer by — the node cannot make an honest decision. */
    MESH_TUNNEL_REFUSED_UNAVAILABLE = 5,
    /* The local listener could not be bound. */
    MESH_TUNNEL_REFUSED_LOCAL_BIND_FAILED = 6,
    /* The peer holds no live pairing row on this node. */
    MESH_TUNNEL_REFUSED_PEER_UNPAIRED = 7,
    /* No entrance with that id is open on this node. */
    MESH_TUNNEL_REFUSED_NO_SUCH_TUNNEL = 8,
    /* The socket on this side ended the connection. */
    MESH_TUNNEL_ENDED_LOCAL_CLOSE = 9,
    /* An allow row that admitted this stream was removed while it was open. */
    MESH_TUNNEL_ENDED_TARGET_DENIED = 10,
};

/* "tunnel_target_not_allowed", "tunnel_peer_unpaired",
 * "tunnel_local_bind_failed", "tunnel_cap", ... — one stable token per
 * value, the same token the operator surfaces and the logs print. */
const char *mesh_tunnel_refusal_string(enum mesh_tunnel_refusal reason);

/* Longest stream-end token a row carries, including the terminator. */
#define MESH_TUNNEL_END_NAME_MAX 40u

/* Whether the entrance's peer had an established Noise session on this node
 * when the list was built. Membership of the node table is fixed once, when
 * its lock is held to capture every ready node; each captured node's session
 * is read afterwards under its own transport lock. This is not an atomic view
 * of all sessions: each read reports its node at its own later moment, and a
 * peer that connects after the capture is not seen until the next list.
 * LIVE: a captured node's locked read is established and names the peer.
 * ABSENT: every ready node in the captured membership was read under its
 * transport lock, and none held an established session naming the peer when
 * read. UNKNOWN: more ready nodes than the capture bound, a node had lost its
 * transport when read, or there was no context. The zero value is UNKNOWN,
 * so a row nobody filled in, or a lookup that could not run, can never read
 * as healthy. */
enum mesh_tunnel_peer_session {
    MESH_TUNNEL_PEER_SESSION_UNKNOWN = 0,
    MESH_TUNNEL_PEER_SESSION_LIVE = 1,
    MESH_TUNNEL_PEER_SESSION_ABSENT = 2,
};

/* "unknown" (also any other value), "live", "absent". */
const char *mesh_tunnel_peer_session_string(enum mesh_tunnel_peer_session s);

/* One local listener the operator opened: the row `list` renders.
 *
 * Health reading for a monitor. Healthy-idle: peer_session "live" and the
 * last end reason is "" or "tunnel_local_closed". Peer-gone: peer_session
 * "absent", or a recent "stream_session_lost" or "stream_peer_not_connected"
 * end. Unknown: peer_session "unknown". streams_failed_total is history,
 * not current state. last_activity_unix counts bytes moved either way on
 * any stream of the entrance; keepalives and window frames do not move it.
 * A stream end is clean only when it carries "tunnel_local_closed"; every
 * other token, including a remote refusal, counts as failed. The reason is
 * always one of a closed set of static tokens, never peer-supplied bytes. */
struct mesh_tunnel_row {
    uint64_t tunnel_id;
    char peer[65]; /* the peer's pairing id, lowercase hex */
    uint16_t remote_port;
    uint16_t local_port;
    uint64_t streams_open;   /* live connections on this listener now */
    uint64_t streams_total;  /* connections accepted since it opened */
    uint64_t bytes_to_peer;
    uint64_t bytes_from_peer;
    int64_t opened_unix;
    int64_t last_activity_unix; /* last byte either way; 0 = none ever */
    char last_stream_end_reason[MESH_TUNNEL_END_NAME_MAX]; /* "" = none */
    int64_t last_stream_end_unix;                          /* 0 = none */
    uint64_t streams_failed_total;
    enum mesh_tunnel_peer_session peer_session;
};

/* One allow row: what this node will let one peer reach on its loopback. */
struct mesh_tunnel_allow_row {
    char peer[65]; /* the peer's pairing id, lowercase hex */
    uint16_t port;
    char why[MESH_TUNNEL_WHY_MAX];
};

/* Open one local listener on 127.0.0.1. `local_port` of zero asks the OS
 * for a free port and `*bound_port_out` reports it. The peer must hold a
 * live pairing row on this node; the peer's own allow table is what
 * decides whether the far side will dial anything. */
enum mesh_tunnel_refusal mesh_tunnel_listen(const char *peer_pairing_id,
                                            uint16_t remote_port,
                                            uint16_t local_port,
                                            uint64_t *tunnel_id_out,
                                            uint16_t *bound_port_out);

/* Close one local listener and every stream it opened. */
bool mesh_tunnel_close(uint64_t tunnel_id);

/* Both directions in one bounded read: `out` receives up to `cap` local
 * listeners, `*total` the number that exist. */
size_t mesh_tunnel_list(struct mesh_tunnel_row *out, size_t cap,
                        size_t *total);

/* Write one allow row, or remove it. Both rewrite the datadir file and
 * reload the table, so the answer is what the next OPEN will read. */
enum mesh_tunnel_refusal mesh_tunnel_allow(const char *peer_pairing_id,
                                           uint16_t port, const char *why);
bool mesh_tunnel_deny(const char *peer_pairing_id, uint16_t port);
size_t mesh_tunnel_allow_list(struct mesh_tunnel_allow_row *out, size_t cap,
                              size_t *total);

/* Records the composition context, loads the allow table, registers the
 * stream service, and starts the listener tick. Shutdown closes every
 * listener and unregisters the service, which ends every live stream. */
void mesh_tunnel_wire(struct boot_svc_ctx *svc);
void mesh_tunnel_shutdown(void);

/* The node-side verbs behind `z23 dev fleet tunnel`. */
void mesh_tunnel_register_rpc(struct rpc_table *table);

#ifdef ZCL_TESTING
/* Test seams: drive the exact production accept path and per-stream copy
 * without a supervisor. bind records the composition context and registers
 * the service WITHOUT a supervised tick, so a loopback test drives the
 * beats itself; pass NULL to unbind. reset closes every listener and
 * clears the allow table; tick runs one listener beat and then the service
 * tick over every live tunnel stream, which is exactly what the supervised
 * ticks do in production. set_now pins the time every health stamp reads
 * (last byte, last stream end) to a fixed value; zero, and reset, restore
 * the real wall clock. */
void mesh_tunnel_test_bind(struct boot_svc_ctx *svc);
void mesh_tunnel_test_reset(void);
void mesh_tunnel_test_set_now(int64_t now_unix);
void mesh_tunnel_test_tick(int64_t now_unix);
#endif

#endif /* ZCL_CONFIG_MESH_TUNNEL_H */
