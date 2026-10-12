/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: The guest byte-channel adapter: carries the ports of a guest
 * device (platform/guest_chan.h) over mesh streams named "guest.chan".
 *
 * A port is one byte stream. The adapter never opens a socket, a file or a
 * process: its only outward path is config/mesh_stream.h, so a guest can
 * reach exactly the paired peers whose local pairing row grants
 * MESH_PAIRING_CAP_GUEST_CHAN, over the established Noise session.
 *
 * STAGE 1 (this unit): nothing in production calls
 * mesh_guest_chan_set_enabled(true), so the service is NEVER registered in
 * a real node; an inbound OPEN for "guest.chan" is refused by the stream
 * primitive as an unknown service. Only a test attaches a fake device and
 * enables it.
 *
 * Authorisation is one function evaluated before every action, not on a
 * tick: the service is enabled AND a fresh read of the pairing rows finds a
 * live (unrevoked, unexpired) row for the peer granting the capability. It
 * runs on outbound open, on_open, every on_data before delivery to the
 * device, every from_guest, every drained, and in the pump after each device
 * callback and immediately before the grant, the send and any resume. These
 * reads are admission points taken before each action: a revocation that
 * commits concurrently with an action already admitted may see that one
 * action complete, and nothing further is started.
 *
 * Known stage-1 limit, failing closed: the read covers only the first 64
 * pairing rows, listed in paired_at order, and the 64 COUNT revoked and
 * expired rows too (the same ceiling the stream primitive uses). 64 stale
 * rows ahead of it therefore deny every newer peer, even one with a valid
 * granting row. It never admits a peer by mistake. Stage 1 keeps that
 * behaviour.
 *
 * End reason, first arrival wins: a port ends exactly once and the device
 * hears exactly one end(). When a local closed(), a revocation, a protocol
 * fault or a remote CLOSE all reach the same port, the reason of the first
 * to arrive is the one reported; a later one changes nothing (its token is
 * already stale, or the stream is already released).
 *
 * An outbound port is judged in one place: the pump's open check ends a
 * port that is not authorised UNAVAILABLE. Host ops on a port whose open is
 * still undecided only buffer within the bound.
 *
 * Threading. Lock order is mesh lane, then the adapter mutex, then the
 * device; never the reverse. Stream callbacks run under the lane lock and
 * may call device write/end/accept/resume. The host ops (opened,
 * from_guest, drained, writable, closed) are called by the device pump with
 * no lane lock, so they only validate the token, copy into bounded
 * per-port buffers and queue work; the stream verbs (open, send, grant,
 * close, release) and every device callback they trigger run from
 * mesh_guest_chan_pump() or from a stream callback.
 */

#ifndef ZCL_CONFIG_MESH_GUEST_CHAN_H
#define ZCL_CONFIG_MESH_GUEST_CHAN_H

#include "platform/guest_chan.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define MESH_GUEST_CHAN_SERVICE_NAME "guest.chan"

/* A zero field takes its default. total_max may not exceed
 * GUEST_CHAN_PORTS_MAX. */
struct mesh_guest_chan_limits {
    uint32_t per_peer_max;    /* default 2 */
    uint32_t total_max;       /* default 4 */
    uint32_t window;          /* default 65536: credit asked on outbound OPEN
                               * and the largest credit an inbound OPEN may
                               * name */
    uint32_t idle_seconds;    /* default 120 */
    uint32_t pump_bytes_max;  /* default 262144: no credit is granted while
                               * more than this is buffered across ports */
};

struct mesh_guest_chan_stats {
    uint64_t opened;
    uint64_t refused_disabled;
    uint64_t refused_bound;
    uint64_t refused_unpaired;
    uint64_t ended_revoked;
    uint64_t ended_protocol;
    uint64_t ended_idle;
    uint64_t stale_token_dropped;
    uint64_t bytes_to_guest;
    uint64_t bytes_from_guest;
};

/* Bind a device. Both pumps must be stopped and nothing queued. Returns the
 * host table and context the device must call. Fails when already attached,
 * when an op is missing or when a limit is out of range. */
bool mesh_guest_chan_attach(const struct guest_chan_device_ops *ops, void *dev,
                            const struct mesh_guest_chan_limits *limits_or_null,
                            const struct guest_chan_host_ops **host_ops_out,
                            void **host_out);

/* Required peer-aware admission mode. Legacy attach behavior is unchanged.
 * A missing handler refuses attachment; no default control-envelope handler
 * or public-key binding is supplied by the adapter. Both pumps are stopped. */
bool mesh_guest_chan_attach_peer_v2(const struct guest_chan_device_ops *ops,
    guest_chan_peer_accept_v2_fn accept_peer, void *dev,
    const struct mesh_guest_chan_limits *limits_or_null,
    const struct guest_chan_host_ops **host_ops_out, void **host_out);

/* Unbind. Disables first, which ends every port. */
void mesh_guest_chan_detach(void);

/* Default OFF. on=true registers the service (needs an attached device);
 * on=false ends every port with GUEST_CHAN_END_SHUTDOWN, closes and
 * releases its streams and unregisters the service. Not callable from a
 * stream callback or a device callback. */
bool mesh_guest_chan_set_enabled(bool on);
bool mesh_guest_chan_enabled(void);

/* The adapter's own pump: performs queued outbound opens, queued device
 * work, re-offers, credit and idle checks. `now_unix` is the adapter's
 * clock for idle accounting. */
void mesh_guest_chan_pump(int64_t now_unix);

void mesh_guest_chan_stats(struct mesh_guest_chan_stats *out);

#ifdef ZCL_TESTING
/* Bytes buffered across all ports right now (both directions). */
size_t mesh_guest_chan_test_buffered(void);
#endif

#endif /* ZCL_CONFIG_MESH_GUEST_CHAN_H */
