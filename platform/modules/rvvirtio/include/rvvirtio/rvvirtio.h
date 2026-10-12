/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: standalone VIRTIO 1.2 MMIO (version 2) device models: split
 * virtqueues, virtio-blk, virtio-net, a multiport console and entropy, with
 * no CPU core and no host I/O.
 *
 * Specification: OASIS "Virtual I/O Device (VIRTIO) Version 1.2" (2022).
 * Section numbers cited in the sources refer to that document.
 *
 * Contract: all guest memory is reached through the caller callbacks in
 * struct rvvirtio_mem. Every guest-supplied address and length is validated
 * (wrap-around first, then the callback); a failing callback sets
 * DEVICE_NEEDS_RESET (2.1) and the device performs no further work until the
 * guest resets it by writing status 0. The module never allocates, never
 * touches host memory named by the guest, and keeps no globals. */
#ifndef RVVIRTIO_RVVIRTIO_H
#define RVVIRTIO_RVVIRTIO_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* 4.2.2: MMIO register offsets (32-bit registers). */
enum rvvirtio_reg {
    RVVIRTIO_REG_MAGIC = 0x000,
    RVVIRTIO_REG_VERSION = 0x004,
    RVVIRTIO_REG_DEVICE_ID = 0x008,
    RVVIRTIO_REG_VENDOR_ID = 0x00c,
    RVVIRTIO_REG_DEVICE_FEATURES = 0x010,
    RVVIRTIO_REG_DEVICE_FEATURES_SEL = 0x014,
    RVVIRTIO_REG_DRIVER_FEATURES = 0x020,
    RVVIRTIO_REG_DRIVER_FEATURES_SEL = 0x024,
    RVVIRTIO_REG_QUEUE_SEL = 0x030,
    RVVIRTIO_REG_QUEUE_NUM_MAX = 0x034,
    RVVIRTIO_REG_QUEUE_NUM = 0x038,
    RVVIRTIO_REG_QUEUE_READY = 0x044,
    RVVIRTIO_REG_QUEUE_NOTIFY = 0x050,
    RVVIRTIO_REG_INTERRUPT_STATUS = 0x060,
    RVVIRTIO_REG_INTERRUPT_ACK = 0x064,
    RVVIRTIO_REG_STATUS = 0x070,
    RVVIRTIO_REG_QUEUE_DESC_LOW = 0x080,
    RVVIRTIO_REG_QUEUE_DESC_HIGH = 0x084,
    RVVIRTIO_REG_QUEUE_DRIVER_LOW = 0x090,
    RVVIRTIO_REG_QUEUE_DRIVER_HIGH = 0x094,
    RVVIRTIO_REG_QUEUE_DEVICE_LOW = 0x0a0,
    RVVIRTIO_REG_QUEUE_DEVICE_HIGH = 0x0a4,
    RVVIRTIO_REG_CONFIG_GENERATION = 0x0fc,
    RVVIRTIO_REG_CONFIG = 0x100,
};

#define RVVIRTIO_MAGIC 0x74726976u /* "virt", 4.2.2 */
#define RVVIRTIO_MMIO_VERSION 2u
#define RVVIRTIO_VENDOR_ID 0x5a323300u /* "Z23" */

/* 2.1: device status bits. */
#define RVVIRTIO_STATUS_ACKNOWLEDGE 0x01u
#define RVVIRTIO_STATUS_DRIVER 0x02u
#define RVVIRTIO_STATUS_DRIVER_OK 0x04u
#define RVVIRTIO_STATUS_FEATURES_OK 0x08u
#define RVVIRTIO_STATUS_NEEDS_RESET 0x40u
#define RVVIRTIO_STATUS_FAILED 0x80u

/* 6: reserved feature bits. */
#define RVVIRTIO_F_INDIRECT_DESC (UINT64_C(1) << 28)
#define RVVIRTIO_F_VERSION_1 (UINT64_C(1) << 32)

/* 4.2.2: InterruptStatus bits. */
#define RVVIRTIO_INT_USED_BUFFER 0x1u
#define RVVIRTIO_INT_CONFIG_CHANGE 0x2u

#define RVVIRTIO_DEVICE_ID_NET 1u /* 5 */
#define RVVIRTIO_DEVICE_ID_BLOCK 2u
#define RVVIRTIO_DEVICE_ID_CONSOLE 3u
#define RVVIRTIO_DEVICE_ID_ENTROPY 4u

#define RVVIRTIO_QUEUE_MAX 256u /* QueueNumMax, a power of two */
#define RVVIRTIO_QUEUES_MAX 18u /* console: 2 + 2 * 8 ports */
#define RVVIRTIO_CONFIG_MAX 32u
#define RVVIRTIO_SEG_MAX RVVIRTIO_QUEUE_MAX

/* Guest memory access. read/write return false when [gpa, gpa+n) is not
 * backed; irq receives the new level of the interrupt line. */
struct rvvirtio_mem {
    void *ctx;
    bool (*read)(void *ctx, uint64_t gpa, void *buf, size_t n);
    bool (*write)(void *ctx, uint64_t gpa, const void *buf, size_t n);
    void (*irq)(void *ctx, bool level);
};

/* 2.7.5: one device-visible buffer segment of a descriptor chain. */
struct rvvirtio_seg {
    uint64_t gpa;
    uint32_t len;
    bool write; /* device-writable */
};

/* The chain most recently popped from a queue. */
struct rvvirtio_chain {
    struct rvvirtio_seg segs[RVVIRTIO_SEG_MAX];
    uint32_t nsegs;
    uint32_t head;
    uint64_t in_len;  /* total device-readable bytes */
    uint64_t out_len; /* total device-writable bytes */
};

/* 2.7: split virtqueue state, owned by the device model. */
struct rvvirtio_queue {
    uint64_t desc, driver, device; /* guest addresses (4.2.2 Queue*Low/High) */
    uint32_t num;
    bool ready;
    uint16_t last_avail;
    uint16_t used_idx;
};

/* Common transport and queue state. Device models embed it as their FIRST
 * member; notify is installed by the device model. */
struct rvvirtio_dev {
    struct rvvirtio_mem mem;
    uint32_t device_id;
    uint64_t device_features; /* device bits; VERSION_1 is added by transport */
    uint32_t nqueues;
    uint8_t config[RVVIRTIO_CONFIG_MAX];
    uint32_t config_len;
    void (*notify)(struct rvvirtio_dev *dev, uint32_t queue);
    void (*on_reset)(struct rvvirtio_dev *dev); /* optional; runs on status-0 reset */
    /* optional; runs when a status write first sets DRIVER_OK, so a device can
     * serve a buffer the driver notified before it (the FreeBSD entropy driver
     * does: virtio_random.c:184,284 precede virtio_mmio.c:858) */
    void (*on_driver_ok)(struct rvvirtio_dev *dev);
    /* queues served from FEATURES_OK instead of DRIVER_OK (bit n = queue n); a
     * device sets it for a queue whose driver waits on a completion before the
     * transport can set DRIVER_OK (the FreeBSD console driver polls the
     * control transmit queue inside attach) */
    uint32_t early_queues;

    uint32_t status;
    uint64_t driver_features;
    uint32_t device_features_sel, driver_features_sel, queue_sel;
    uint32_t interrupt_status;
    uint32_t config_generation;
    bool irq_level;
    struct rvvirtio_queue queues[RVVIRTIO_QUEUES_MAX];
    struct rvvirtio_chain chain;
};

/* 2.7: whether a ready queue's size is a power of two within the limit and its
 * rings are aligned and do not wrap the address space. */
bool rvvirtio_queue_valid(const struct rvvirtio_queue *q);

/* 4.2.2: 32-bit register access. Configuration space (offset >= 0x100) is
 * byte addressed: a read returns the four bytes at off little-endian, zero
 * beyond the config length; the embedding emulator masks narrower accesses. */
uint32_t rvvirtio_mmio_read(struct rvvirtio_dev *dev, uint64_t off);
void rvvirtio_mmio_write(struct rvvirtio_dev *dev, uint64_t off, uint32_t val);

/* Mark the device broken (2.1: DEVICE_NEEDS_RESET) and signal a config change. */
void rvvirtio_dev_fail(struct rvvirtio_dev *dev);
/* Config content changed: bump ConfigGeneration and raise the config interrupt. */
void rvvirtio_dev_config_changed(struct rvvirtio_dev *dev);

/* ---- virtio-blk (5.2) ---- */
#define RVVIRTIO_BLK_SECTOR 512u
#define RVVIRTIO_BLK_ID_LEN 20u
#define RVVIRTIO_BLK_CHUNK 4096u

/* Work bounds. The rule, in one place:
 *  - Admission: an IN or OUT request whose data exceeds
 *    RVVIRTIO_BLK_REQ_BYTES_MAX is refused BEFORE any backend callback: the
 *    status byte is IOERR, the used length is the bytes actually written to
 *    the guest (the status byte alone, 1), and the device stays usable. The
 *    data total is summed in 64 bits, so no wrap can hide it. A used length
 *    (data plus the status byte) therefore always fits uint32_t.
 *  - Work per notify: one QueueNotify (or rvvirtio_blk_service) services at
 *    least the first available request and then stops once
 *    RVVIRTIO_BLK_NOTIFY_REQS_MAX requests have been serviced or
 *    RVVIRTIO_BLK_NOTIFY_BYTES_MAX data bytes have been moved, so one notify
 *    moves fewer than NOTIFY_BYTES_MAX + REQ_BYTES_MAX bytes. Requests left in
 *    the avail ring stay there; rvvirtio_blk_pending() reports them and the
 *    next notify or rvvirtio_blk_service() call continues. The caps sit above
 *    a full legitimate queue (RVVIRTIO_QUEUE_MAX requests of the advertised
 *    seg_max pages), so only a hostile or oversized-request mix reaches them;
 *    a driver that never notifies again relies on the caller servicing a
 *    pending device. */
#define RVVIRTIO_BLK_REQ_BYTES_MAX (UINT64_C(1) << 20)
#define RVVIRTIO_BLK_NOTIFY_REQS_MAX 256u
#define RVVIRTIO_BLK_NOTIFY_BYTES_MAX (UINT64_C(128) << 20)
/* Advertised seg_max: data segments (excluding header and status) of one
 * request. A driver that sizes requests as seg_max pages sends at most
 * RVVIRTIO_BLK_DATA_SEGS_MAX * 4096 bytes, under the request bound. */
#define RVVIRTIO_BLK_DATA_SEGS_MAX 126u

#define RVVIRTIO_BLK_T_IN 0u
#define RVVIRTIO_BLK_T_OUT 1u
#define RVVIRTIO_BLK_T_FLUSH 4u
#define RVVIRTIO_BLK_T_GET_ID 8u
#define RVVIRTIO_BLK_S_OK 0u
#define RVVIRTIO_BLK_S_IOERR 1u
#define RVVIRTIO_BLK_S_UNSUPP 2u

/* The caller's storage. Nothing here opens files. size() is in bytes. */
struct rvvirtio_blk_backend {
    void *ctx;
    uint64_t (*size)(void *ctx);
    bool (*pread)(void *ctx, uint64_t off, void *buf, size_t n);
    bool (*pwrite)(void *ctx, uint64_t off, const void *buf, size_t n);
    bool (*flush)(void *ctx); /* NULL: no FLUSH feature, FLUSH is UNSUPP */
    const char *serial;       /* GET_ID text, up to 20 bytes; may be NULL */
};

struct rvvirtio_blk {
    struct rvvirtio_dev dev; /* must stay first */
    struct rvvirtio_blk_backend be;
    bool read_only;
    bool pending; /* requests left in the avail ring by a capped notify */
    uint64_t capacity_sectors;
    uint8_t chunk[RVVIRTIO_BLK_CHUNK];
};

/* False when mem/backend lack the mandatory callbacks. A backend without
 * pwrite forces read-only. */
bool rvvirtio_blk_init(struct rvvirtio_blk *blk, const struct rvvirtio_mem *mem,
                       const struct rvvirtio_blk_backend *backend,
                       bool read_only);

/* Service the request queue now, under the same per-notify caps as a
 * QueueNotify. A no-op unless the device is running. Call it while
 * rvvirtio_blk_pending() is true. */
void rvvirtio_blk_service(struct rvvirtio_blk *blk);
/* True when a capped notify left available requests unserviced. */
bool rvvirtio_blk_pending(const struct rvvirtio_blk *blk);

/* ---- virtio-net (5.1) ---- */
#define RVVIRTIO_NET_HDR_LEN 12u /* struct virtio_net_hdr, VERSION_1 layout */
#define RVVIRTIO_NET_FRAME_MIN 14u
#define RVVIRTIO_NET_FRAME_MAX 1514u
#define RVVIRTIO_NET_RXQ 0u
#define RVVIRTIO_NET_TXQ 1u

typedef void (*rvvirtio_net_tx_fn)(void *ctx, const uint8_t *frame, size_t len);

struct rvvirtio_net {
    struct rvvirtio_dev dev; /* must stay first */
    rvvirtio_net_tx_fn tx;
    void *tx_ctx;
    uint8_t buf[RVVIRTIO_NET_HDR_LEN + RVVIRTIO_NET_FRAME_MAX];
};

/* False when mem or tx is missing. */
bool rvvirtio_net_init(struct rvvirtio_net *net, const struct rvvirtio_mem *mem,
                       const uint8_t mac[6], rvvirtio_net_tx_fn tx, void *tx_ctx);

/* Place one frame (14..1514 bytes) into the next available rx chain and raise
 * the interrupt. False, with guest memory untouched, when the device is not
 * running, the length is out of bounds or no buffer is available. */
bool rvvirtio_net_receive(struct rvvirtio_net *net, const uint8_t *frame,
                          size_t len);

/* ---- virtio-console, multiport byte channels (5.3) ----
 *
 * Queue layout (5.3.2): receiveq(port0)=0, transmitq(port0)=1, control
 * receiveq=2, control transmitq=3, then receiveq(N)=2*(N+1), transmitq(N)=
 * 2*(N+1)+1 for each extra port N >= 1. Only VIRTIO_CONSOLE_F_MULTIPORT is
 * offered, so ports are announced through control messages (5.3.6.2).
 *
 * Contract for the caller:
 *  - Callbacks (from_guest, writable) run synchronously inside a device entry
 *    point and MUST NOT call back into the device (no rvvirtio_console_*, no
 *    MMIO access). Re-entrant calls are refused (0 / false / no effect).
 *  - Every call is bounded and non-blocking; nothing is queued inside the
 *    device. Host-to-guest data is accepted only into buffers the guest has
 *    already made available, and the caller keeps the unaccepted suffix.
 *  - Guest-to-host: from_guest returns how many of the n bytes it accepted.
 *    A short return stops that port's transmit queue (the unaccepted bytes
 *    stay in the guest's buffer) until rvvirtio_console_port_resume.
 *  - Each port has a generation counter, incremented on open, on close and
 *    when a guest reset ends an open session. */
#define RVVIRTIO_CONSOLE_PORTS_MAX 8u
#define RVVIRTIO_CONSOLE_NAME_MAX 32u
#define RVVIRTIO_CONSOLE_CHUNK 512u
#define RVVIRTIO_CONSOLE_PUMP_BYTES 65536u /* guest-to-host bytes per pump */
#define RVVIRTIO_CONSOLE_F_MULTIPORT (UINT64_C(1) << 1)

struct rvvirtio_console_ops {
    void *ctx;
    /* Returns the number of bytes accepted (0..n). */
    size_t (*from_guest)(void *ctx, uint32_t port, const uint8_t *buf, size_t n);
    /* The guest posted receive buffers on a port whose last write was short;
     * fires at most once per stall, never from inside port_write. May be NULL. */
    void (*writable)(void *ctx, uint32_t port);
};

struct rvvirtio_console_port {
    char name[RVVIRTIO_CONSOLE_NAME_MAX];
    uint8_t name_len;
    uint8_t pending; /* control messages owed to the guest */
    bool host_open, guest_open, guest_ready, is_console;
    bool open_value, tx_stopped, rx_stalled;
    uint32_t generation;
    uint64_t tx_off; /* bytes of the head transmit chain already accepted */
    uint64_t consumed;
    uint32_t delivered[RVVIRTIO_QUEUE_MAX]; /* bytes per rx head, awaiting re-post */
};

struct rvvirtio_console {
    struct rvvirtio_dev dev; /* must stay first */
    struct rvvirtio_console_ops ops;
    uint32_t nports;
    bool device_ready, busy;
    struct rvvirtio_console_port ports[RVVIRTIO_CONSOLE_PORTS_MAX];
    uint8_t chunk[RVVIRTIO_CONSOLE_CHUNK];
};

/* nports is max_nr_ports (1..8). False when mem or ops.from_guest is missing. */
bool rvvirtio_console_init(struct rvvirtio_console *c,
                           const struct rvvirtio_mem *mem,
                           const struct rvvirtio_console_ops *ops,
                           uint32_t nports);
/* Open the host end. name NULL makes a console-type port (CONSOLE_PORT),
 * otherwise the port is announced with PORT_NAME. False if out of range,
 * already open, or the name is too long. */
bool rvvirtio_console_port_open(struct rvvirtio_console *c, uint32_t port,
                                const char *name);
/* Host to guest: bytes accepted into available guest buffers (0 when the
 * port is not open on both ends or no buffer is available). */
size_t rvvirtio_console_port_write(struct rvvirtio_console *c, uint32_t port,
                                   const uint8_t *buf, size_t n);
/* Continue a transmit queue stopped by a short from_guest return. */
void rvvirtio_console_port_resume(struct rvvirtio_console *c, uint32_t port);
/* Close the host end: sends PORT_OPEN 0, discards unaccepted guest data. */
void rvvirtio_console_port_close(struct rvvirtio_console *c, uint32_t port);
uint32_t rvvirtio_console_port_generation(const struct rvvirtio_console *c,
                                          uint32_t port);
/* Delivered bytes whose receive buffers the guest driver has re-posted.
 * Driver-consumed, NOT application-level read; tracked per buffer head, so
 * it is exact for drivers that re-post the same descriptor heads. */
size_t rvvirtio_console_port_consumed(struct rvvirtio_console *c, uint32_t port);

/* ---- virtio-entropy (5.4) ----
 *
 * One queue (requestq, index 0), no device feature bits (the transport adds
 * VERSION_1 and INDIRECT_DESC), no configuration space: config reads return 0
 * and writes are ignored. The FreeBSD driver reads no configuration either
 * (sys/dev/virtio/random/virtio_random.c has no config accessor call).
 *
 * The bytes come only from the embedder: fill() is the sole source. The module
 * never calls getrandom, never opens a device file and never reads a clock, so
 * a run fed from a recorded input replays exactly.
 *
 * Request rule (5.4.6): only device-writable descriptors are filled, in chain
 * order. A chain with any device-readable descriptor, or with no writable
 * bytes, is malformed: it completes with used length 0, is counted, and the
 * device stays usable. At most RVVIRTIO_RNG_REQ_BYTES_MAX bytes are written
 * per request; the used length is exactly the bytes written. The FreeBSD
 * driver's request is sizeof(uint32_t) * HARVESTSIZE = 8 bytes in one
 * writable descriptor (virtio_random.c:150, random_harvestq.h:33), so the cap
 * is 512 times what it needs.
 *
 * Work per notify: one QueueNotify (or rvvirtio_rng_service) serves at least
 * the first available request, then stops after RVVIRTIO_RNG_NOTIFY_REQS_MAX
 * requests or RVVIRTIO_RNG_NOTIFY_BYTES_MAX delivered bytes. A request that
 * would pass the byte cap is cut to what the notify has left (its used length
 * says so), so one notify never delivers more than the cap. Requests left in
 * the avail ring stay there; rvvirtio_rng_pending() reports them. The same
 * work also runs once when the driver sets DRIVER_OK, because the FreeBSD
 * driver notifies its only request during attach, before DRIVER_OK
 * (virtio_random.c:184,284; virtio_mmio.c:851,858), when the transport drops
 * the notify, and it never notifies that request again.
 *
 * Empty source: if fill returns 0 for the first byte of a request, the
 * request is NOT completed, nothing is written, the request stays available,
 * empty_fills is incremented and the device reports pending; servicing stops
 * for this call. If fill returns 0 or fewer bytes than asked after some bytes
 * were delivered, the request completes with those bytes. The caller services
 * a pending device (rvvirtio_rng_service) once its source has bytes again.
 * Beware: the FreeBSD driver notifies once per request and then polls for the
 * used entry (virtqueue_poll, virtqueue.c:605-614, reached from detach,
 * virtio_random.c:212); its harvest path only dequeues without waiting
 * (virtio_random.c:299-301). An embedder whose source can run dry therefore
 * leaves that request outstanding, and a guest that detaches the device spins
 * until the embedder services it.
 *
 * Counters are cumulative since init and are NOT cleared by a guest reset
 * (they describe the embedder's source, not the guest's session). A guest
 * reset (status 0) clears the queues and pending; a request left in the avail
 * ring is forgotten with the queue. fill is called synchronously inside a
 * device entry point, must not call back into the device, and must return at
 * most n (a larger value is treated as n). */
#define RVVIRTIO_RNG_REQ_BYTES_MAX 4096u
#define RVVIRTIO_RNG_NOTIFY_REQS_MAX 64u
#define RVVIRTIO_RNG_NOTIFY_BYTES_MAX (UINT64_C(64) << 10)
#define RVVIRTIO_RNG_CHUNK 512u /* bytes per fill call */

struct rvvirtio_rng_ops {
    void *ctx;
    /* Write up to n bytes into buf and return how many (0..n); 0 means the
     * source has nothing now. */
    size_t (*fill)(void *ctx, uint8_t *buf, size_t n);
};

struct rvvirtio_rng_counters {
    uint64_t requests;    /* requests completed (malformed ones included) */
    uint64_t bytes;       /* bytes delivered to the guest */
    uint64_t empty_fills; /* fill calls that returned 0 */
    uint64_t malformed;   /* requests completed with 0 for a readable
                             descriptor or no writable bytes */
};

struct rvvirtio_rng {
    struct rvvirtio_dev dev; /* must stay first */
    struct rvvirtio_rng_ops ops;
    bool pending; /* requests left available (capped notify or empty source) */
    struct rvvirtio_rng_counters counters;
    uint8_t chunk[RVVIRTIO_RNG_CHUNK];
};

/* False when mem lacks read/write or ops.fill is missing. */
bool rvvirtio_rng_init(struct rvvirtio_rng *rng, const struct rvvirtio_mem *mem,
                       const struct rvvirtio_rng_ops *ops);
/* Serve the request queue now, under the same per-notify caps as a
 * QueueNotify. A no-op unless the device is running. Call it while
 * rvvirtio_rng_pending() is true. */
void rvvirtio_rng_service(struct rvvirtio_rng *rng);
/* True when available requests remain unserved. */
bool rvvirtio_rng_pending(const struct rvvirtio_rng *rng);
struct rvvirtio_rng_counters rvvirtio_rng_counters_get(const struct rvvirtio_rng *rng);

#endif /* RVVIRTIO_RVVIRTIO_H */
