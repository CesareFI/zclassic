/* guest_chan.h -- contract between a guest byte-channel device and the
 * host adapter that carries its ports over mesh streams.
 *
 * Standard headers only: no emulator types, no mesh types. The device shim
 * implements struct guest_chan_device_ops; the adapter implements struct
 * guest_chan_host_ops. Each side receives the other's table at attach.
 *
 * Binding rules:
 *  1. A port is one byte stream. No packets, addresses or framing cross.
 *  2. Every call names a token (index, generation). Tokens never repeat
 *     across attachments. A generation never wraps into a live or stale
 *     token: when an index runs out of generations it is retired. A call
 *     with a token that is not live is dropped and counted.
 *  3. Every call is bounded and non-blocking. Neither side calls into the
 *     other from inside a call it is serving; triggered work runs from the
 *     callee's own pump.
 *  4. Buffers are borrowed for the call only. Bytes counted as taken are
 *     copied before return.
 *  5. A count returned greater than the n offered, an accept output with
 *     index >= GUEST_CHAN_PORTS_MAX, generation 0 or a live token, n above
 *     GUEST_CHAN_RUN_MAX, or a drained report above the bytes delivered and
 *     not yet reported, each end the port with GUEST_CHAN_END_PROTOCOL
 *     before any accounting changes. Nothing is clamped silently.
 *  6. Close is terminal for both directions.
 *  7. Lock order: mesh lane, then adapter, then device; never the reverse.
 *     The device calls the adapter only from the device pump with no device
 *     lock held. Attach and detach happen only with both pumps stopped and
 *     no queued callback or context left.
 *  8. Outbound peer naming: the device shim gathers exactly the first
 *     GUEST_CHAN_PEER_ID_BYTES the guest writes on a guest-opened port,
 *     across partial writes, under a finite pre-open deadline, then calls
 *     opened(). Any bytes that arrived with them are held bounded by the
 *     shim and passed to from_guest only after opened() returned true.
 *  9. drained() means bytes the guest DRIVER consumed, not bytes the guest
 *     application read. It is not end-to-end application backpressure.
 * 10. The guest is assumed hostile. Nothing crossing is a host address,
 *     path, descriptor or guest-chosen pointer.
 */
#ifndef ZCL_PLATFORM_GUEST_CHAN_H
#define ZCL_PLATFORM_GUEST_CHAN_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define GUEST_CHAN_PORTS_MAX 4u
#define GUEST_CHAN_RUN_MAX   65536u
#define GUEST_CHAN_PEER_ID_BYTES 32u

struct guest_chan_port {
    uint32_t index;                      /* < GUEST_CHAN_PORTS_MAX */
    uint32_t generation;                 /* never 0 for a live port */
};

/* Versioned inbound admission. Peer is the authenticated mesh remote static,
 * never a guest-supplied locator. The handler validates its complete control
 * envelope and binding before accepting. Outputs are borrowed for this call;
 * reply_length must not exceed reply_capacity. False reserves no live token.
 * The handler follows the same nonblocking, nonreentrant device lock rules. */
typedef bool (*guest_chan_peer_accept_v2_fn)(void *dev,
    const uint8_t peer[GUEST_CHAN_PEER_ID_BYTES],
    const uint8_t *payload, size_t length, uint8_t *reply, size_t reply_capacity,
    size_t *reply_length, struct guest_chan_port *out);

enum guest_chan_end {
    GUEST_CHAN_END_NORMAL = 0,
    GUEST_CHAN_END_UNAVAILABLE = 1,
    GUEST_CHAN_END_REVOKED = 2,
    GUEST_CHAN_END_SESSION_LOST = 3,
    GUEST_CHAN_END_IDLE = 4,
    GUEST_CHAN_END_BOUND = 5,
    GUEST_CHAN_END_PROTOCOL = 6,
    GUEST_CHAN_END_SHUTDOWN = 7,
};

/* Implemented by the DEVICE shim, called by the adapter. */
struct guest_chan_device_ops {
    bool (*accept)(void *dev, struct guest_chan_port *out);
    /* Returns bytes taken, 0..n. After a short return the adapter offers
     * nothing more on the port until host->writable or host->drained. */
    size_t (*write)(void *dev, struct guest_chan_port port,
                    const uint8_t *bytes, size_t n);
    void (*resume)(void *dev, struct guest_chan_port port);
    void (*end)(void *dev, struct guest_chan_port port,
                enum guest_chan_end why);
};

/* Implemented by the ADAPTER, called by the device shim from its pump. */
struct guest_chan_host_ops {
    bool (*opened)(void *host, struct guest_chan_port port,
                   const uint8_t peer[GUEST_CHAN_PEER_ID_BYTES]);
    /* Returns bytes taken, 0..n. After a short return wait for resume. */
    size_t (*from_guest)(void *host, struct guest_chan_port port,
                         const uint8_t *bytes, size_t n);
    void (*drained)(void *host, struct guest_chan_port port, size_t n);
    /* The guest can take bytes again on a port whose write() returned
     * short. Fired once per stall. Grants no credit by itself. */
    void (*writable)(void *host, struct guest_chan_port port);
    void (*closed)(void *host, struct guest_chan_port port);
};

#endif /* ZCL_PLATFORM_GUEST_CHAN_H */
