/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: drive the rvvirtio device models as a guest driver over a fake RAM
 * array: init handshake, split-virtqueue chains, virtio-blk and virtio-net
 * traffic, hostile guests (every one must end in a defined status or
 * DEVICE_NEEDS_RESET with the canaries untouched), and two mutation twins
 * proving the chain-walk bound and the sector range check are load-bearing.
 *
 * The twins recompile the module sources in this translation unit under the
 * rvvmut_ prefix with the bound / the range check replaced by "always true". */
#include "test/test_core.h"
#include "rvvirtio/rvvirtio.h"

#include <stdint.h>
#include <string.h>

/* ---- mutation twin: same sources, the policy macros defeated ---- */
#define RVVIRTIO_CHAIN_BOUND_OK(steps, limit) \
    ((void)(steps), (void)(limit), true)
#define RVVIRTIO_SECTOR_RANGE_OK(sector, nsect, capacity) \
    ((void)(sector), (void)(nsect), (void)(capacity), true)
#define RVVIRTIO_BLK_BYTES_OK(bytes) ((void)(bytes), true)
#define RVVIRTIO_RNG_CLAMP(bytes) (bytes)
#define RVVIRTIO_RNG_READABLE_OK(in_len) ((void)(in_len), true)
#define RVVIRTIO_RNG_NOTIFY_LEFT(moved) ((void)(moved), UINT64_MAX)
#define rvvirtio_mmio_read rvvmut_mmio_read
#define rvvirtio_mmio_write rvvmut_mmio_write
#define rvvirtio_dev_fail rvvmut_dev_fail
#define rvvirtio_dev_config_changed rvvmut_dev_config_changed
#define rvvirtio_dev_running rvvmut_dev_running
#define rvvirtio_queue_live rvvmut_queue_live
#define rvvirtio_dev_setup rvvmut_dev_setup
#define rvvirtio_dev_reset rvvmut_dev_reset
#define rvvirtio_irq_update rvvmut_irq_update
#define rvvirtio_gm_read rvvmut_gm_read
#define rvvirtio_gm_write rvvmut_gm_write
#define rvvirtio_queue_valid rvvmut_queue_valid
#define rvvirtio_queue_pop rvvmut_queue_pop
#define rvvirtio_queue_push rvvmut_queue_push
#define rvvirtio_chain_read rvvmut_chain_read
#define rvvirtio_chain_write rvvmut_chain_write
#define rvvirtio_blk_init rvvmut_blk_init
#define rvvirtio_blk_service rvvmut_blk_service
#define rvvirtio_blk_pending rvvmut_blk_pending
#define rvvirtio_queue_has_avail rvvmut_queue_has_avail
#define rvvirtio_net_init rvvmut_net_init
#define rvvirtio_net_receive rvvmut_net_receive
#define RVVIRTIO_ACCEPTED(accepted, offered) ((void)(accepted), (offered))
#define rvvirtio_console_init rvvmut_console_init
#define rvvirtio_console_port_open rvvmut_console_port_open
#define rvvirtio_console_port_write rvvmut_console_port_write
#define rvvirtio_console_port_resume rvvmut_console_port_resume
#define rvvirtio_console_port_close rvvmut_console_port_close
#define rvvirtio_console_port_generation rvvmut_console_port_generation
#define rvvirtio_console_port_consumed rvvmut_console_port_consumed
#define rvvirtio_rng_init rvvmut_rng_init
#define rvvirtio_rng_service rvvmut_rng_service
#define rvvirtio_rng_pending rvvmut_rng_pending
#define rvvirtio_rng_counters_get rvvmut_rng_counters_get
/* public prototypes, now under the twin names */
uint32_t rvvirtio_mmio_read(struct rvvirtio_dev *dev, uint64_t off);
void rvvirtio_mmio_write(struct rvvirtio_dev *dev, uint64_t off, uint32_t val);
void rvvirtio_dev_fail(struct rvvirtio_dev *dev);
void rvvirtio_dev_config_changed(struct rvvirtio_dev *dev);
bool rvvirtio_blk_init(struct rvvirtio_blk *blk, const struct rvvirtio_mem *mem,
                       const struct rvvirtio_blk_backend *backend, bool ro);
bool rvvirtio_rng_init(struct rvvirtio_rng *rng, const struct rvvirtio_mem *mem,
                       const struct rvvirtio_rng_ops *ops);
void rvvirtio_rng_service(struct rvvirtio_rng *rng);
bool rvvirtio_rng_pending(const struct rvvirtio_rng *rng);
struct rvvirtio_rng_counters rvvirtio_rng_counters_get(const struct rvvirtio_rng *rng);
#include "../../../platform/modules/rvvirtio/src/rvvirtio_queue.c"
#include "../../../platform/modules/rvvirtio/src/rvvirtio_mmio.c"
#include "../../../platform/modules/rvvirtio/src/rvvirtio_blk.c"
#include "../../../platform/modules/rvvirtio/src/rvvirtio_console.c"
#include "../../../platform/modules/rvvirtio/src/rvvirtio_rng.c"
#undef rvvirtio_mmio_read
#undef rvvirtio_mmio_write
#undef rvvirtio_dev_fail
#undef rvvirtio_dev_config_changed
#undef rvvirtio_dev_running
#undef rvvirtio_queue_live
#undef rvvirtio_dev_setup
#undef rvvirtio_dev_reset
#undef rvvirtio_irq_update
#undef rvvirtio_gm_read
#undef rvvirtio_gm_write
#undef rvvirtio_queue_valid
#undef rvvirtio_queue_pop
#undef rvvirtio_queue_push
#undef rvvirtio_chain_read
#undef rvvirtio_chain_write
#undef rvvirtio_blk_init
#undef rvvirtio_blk_service
#undef rvvirtio_blk_pending
#undef rvvirtio_queue_has_avail
#undef RVVIRTIO_BLK_BYTES_OK
#undef rvvirtio_net_init
#undef rvvirtio_net_receive
#undef RVVIRTIO_ACCEPTED
#undef rvvirtio_console_init
#undef rvvirtio_console_port_open
#undef rvvirtio_console_port_write
#undef rvvirtio_console_port_resume
#undef rvvirtio_console_port_close
#undef rvvirtio_console_port_generation
#undef rvvirtio_console_port_consumed
#undef RVVIRTIO_RNG_CLAMP
#undef RVVIRTIO_RNG_READABLE_OK
#undef RVVIRTIO_RNG_NOTIFY_LEFT
#undef rvvirtio_rng_init
#undef rvvirtio_rng_service
#undef rvvirtio_rng_pending
#undef rvvirtio_rng_counters_get

struct rv_api {
    uint32_t (*rd)(struct rvvirtio_dev *, uint64_t);
    void (*wr)(struct rvvirtio_dev *, uint64_t, uint32_t);
    bool (*blk_init)(struct rvvirtio_blk *, const struct rvvirtio_mem *,
                     const struct rvvirtio_blk_backend *, bool);
};

static const struct rv_api k_real = {rvvirtio_mmio_read, rvvirtio_mmio_write,
                                     rvvirtio_blk_init};
static const struct rv_api k_mut = {rvvmut_mmio_read, rvvmut_mmio_write,
                                    rvvmut_blk_init};
static const struct rv_api *g_api = &k_real;
static unsigned g_checks;

#define CHK(cond) do { g_checks++; ASSERT(cond); } while (0)
#define CHK_EQ(a, b) do { g_checks++; ASSERT_EQ(a, b); } while (0)

/* ---- fake guest RAM with canaries on both sides ---- */
#define RAM_BASE UINT64_C(0x40000000)
#define RAM_SIZE 0x40000u
#define GUARD 4096u
#define CANARY 0xa5u
#define QN 16u
#define DISK_BYTES 65536u /* 128 sectors */

#define OFF_HDR 0x4000u
#define OFF_STATUS 0x4100u
#define OFF_DATA 0x8000u
#define OFF_DATA2 0x10000u
#define OFF_VICTIM 0x30000u
#define VICTIM_LEN 0x1000u

struct disk {
    uint8_t data[DISK_BYTES];
    unsigned calls;
    unsigned flushes;
};

struct txcap {
    uint8_t frame[2048];
    size_t len;
    unsigned calls;
};

struct fx {
    uint8_t pre[GUARD];
    uint8_t ram[RAM_SIZE];
    uint8_t post[GUARD];
    unsigned reads, writes, read_limit;
    bool aperture; /* a sink window: reads give 0x5a, writes are dropped */
    uint64_t aperture_bytes;
    bool irq;
    unsigned irq_edges;
    struct disk disk;
    struct txcap tx;
};

static bool fx_span(uint64_t gpa, size_t n)
{
    return gpa >= RAM_BASE && gpa - RAM_BASE <= RAM_SIZE &&
           n <= RAM_SIZE - (gpa - RAM_BASE);
}

/* A 512 MiB window far above RAM that models aliased guest buffers: descriptors
 * can name gigabytes without the test owning them. */
#define APERTURE_OFF UINT64_C(0x10000000)
#define APERTURE_LEN UINT64_C(0x20000000)
static bool fx_aperture(const struct fx *f, uint64_t gpa, size_t n)
{
    if (!f->aperture || gpa < RAM_BASE + APERTURE_OFF)
        return false;
    uint64_t o = gpa - (RAM_BASE + APERTURE_OFF);
    return o <= APERTURE_LEN && n <= APERTURE_LEN - o;
}

static bool fx_read(void *ctx, uint64_t gpa, void *buf, size_t n)
{
    struct fx *f = ctx;
    f->reads++;
    if (f->read_limit != 0 && f->reads > f->read_limit)
        return false;
    if (fx_aperture(f, gpa, n)) {
        memset(buf, 0x5a, n);
        f->aperture_bytes += n;
        return true;
    }
    if (!fx_span(gpa, n))
        return false;
    memcpy(buf, f->ram + (gpa - RAM_BASE), n);
    return true;
}

static bool fx_write(void *ctx, uint64_t gpa, const void *buf, size_t n)
{
    struct fx *f = ctx;
    f->writes++;
    if (fx_aperture(f, gpa, n)) {
        f->aperture_bytes += n;
        return true;
    }
    if (!fx_span(gpa, n))
        return false;
    memcpy(f->ram + (gpa - RAM_BASE), buf, n);
    return true;
}

static void fx_irq(void *ctx, bool level)
{
    struct fx *f = ctx;
    f->irq = level;
    f->irq_edges++;
}

static struct rvvirtio_mem fx_mem(struct fx *f)
{
    return (struct rvvirtio_mem){f, fx_read, fx_write, fx_irq};
}

static void fx_reset(struct fx *f)
{
    memset(f, 0, sizeof(*f));
    memset(f->pre, CANARY, sizeof(f->pre));
    memset(f->post, CANARY, sizeof(f->post));
    memset(f->ram + OFF_VICTIM, 0x77, VICTIM_LEN);
    for (unsigned i = 0; i < DISK_BYTES; i++)
        f->disk.data[i] = (uint8_t)(i * 7u + 3u);
}

static bool guards_ok(const struct fx *f)
{
    for (unsigned i = 0; i < GUARD; i++)
        if (f->pre[i] != CANARY || f->post[i] != CANARY)
            return false;
    for (unsigned i = 0; i < VICTIM_LEN; i++)
        if (f->ram[OFF_VICTIM + i] != 0x77)
            return false;
    return true;
}

/* ---- in-memory disk backend ---- */
static uint64_t disk_size(void *ctx)
{
    (void)ctx;
    return DISK_BYTES;
}

static bool disk_pread(void *ctx, uint64_t off, void *buf, size_t n)
{
    struct disk *d = ctx;
    d->calls++;
    if (off > DISK_BYTES || n > DISK_BYTES - off)
        return false;
    memcpy(buf, d->data + off, n);
    return true;
}

static bool disk_pwrite(void *ctx, uint64_t off, const void *buf, size_t n)
{
    struct disk *d = ctx;
    d->calls++;
    if (off > DISK_BYTES || n > DISK_BYTES - off)
        return false;
    memcpy(d->data + off, buf, n);
    return true;
}

static bool disk_flush(void *ctx)
{
    struct disk *d = ctx;
    d->flushes++;
    return true;
}

static struct rvvirtio_blk_backend disk_backend(struct fx *f)
{
    return (struct rvvirtio_blk_backend){&f->disk, disk_size, disk_pread,
                                         disk_pwrite, disk_flush, "z23-test-disk"};
}

static void tx_cb(void *ctx, const uint8_t *frame, size_t len)
{
    struct txcap *t = ctx;
    t->calls++;
    t->len = len;
    memcpy(t->frame, frame, len);
}

/* ---- guest-driver helpers ---- */
static uint32_t RD(struct rvvirtio_dev *d, uint64_t off) { return g_api->rd(d, off); }
static void WR(struct rvvirtio_dev *d, uint64_t off, uint32_t v) { g_api->wr(d, off, v); }

static uint64_t qdesc(unsigned qi) { return (uint64_t)qi * 0x1000u; }
static uint64_t qavail(unsigned qi) { return qdesc(qi) + 0x200u; }
static uint64_t qused(unsigned qi) { return qdesc(qi) + 0x400u; }

static void put16(struct fx *f, uint64_t off, uint16_t v)
{
    f->ram[off] = (uint8_t)v;
    f->ram[off + 1] = (uint8_t)(v >> 8);
}

static void put32(struct fx *f, uint64_t off, uint32_t v)
{
    put16(f, off, (uint16_t)v);
    put16(f, off + 2, (uint16_t)(v >> 16));
}

static void put64(struct fx *f, uint64_t off, uint64_t v)
{
    put32(f, off, (uint32_t)v);
    put32(f, off + 4, (uint32_t)(v >> 32));
}

static uint16_t get16(const struct fx *f, uint64_t off)
{
    return (uint16_t)(f->ram[off] | (f->ram[off + 1] << 8));
}

static uint32_t get32(const struct fx *f, uint64_t off)
{
    return (uint32_t)get16(f, off) | ((uint32_t)get16(f, off + 2) << 16);
}

struct dsc {
    uint64_t addr;
    uint32_t len;
    uint16_t flags;
};

static void desc_put(struct fx *f, uint64_t table, unsigned idx,
                     const struct dsc *s, unsigned next)
{
    uint64_t o = table + 16u * idx;
    put64(f, o, s->addr);
    put32(f, o + 8, s->len);
    put16(f, o + 12, s->flags);
    put16(f, o + 14, (uint16_t)next);
}

/* Lay descriptors out at idx0.. linked by NEXT; returns the head index. */
static unsigned chain_put(struct fx *f, unsigned qi, unsigned idx0,
                          const struct dsc *ds, unsigned n)
{
    for (unsigned i = 0; i < n; i++) {
        struct dsc s = ds[i];
        if (i + 1u < n)
            s.flags |= 1u;
        desc_put(f, qdesc(qi), idx0 + i, &s, idx0 + i + 1u);
    }
    return idx0;
}

static void avail_post(struct fx *f, unsigned qi, unsigned head)
{
    uint16_t idx = get16(f, qavail(qi) + 2);
    put16(f, qavail(qi) + 4 + 2u * (idx % QN), (uint16_t)head);
    put16(f, qavail(qi) + 2, (uint16_t)(idx + 1u));
}

static uint16_t used_idx(const struct fx *f, unsigned qi) { return get16(f, qused(qi) + 2); }
static uint32_t used_len(const struct fx *f, unsigned qi, unsigned i)
{
    return get32(f, qused(qi) + 4 + 8u * i + 4u);
}
static uint32_t used_id(const struct fx *f, unsigned qi, unsigned i)
{
    return get32(f, qused(qi) + 4 + 8u * i);
}

static void put_hdr(struct fx *f, uint32_t type, uint64_t sector)
{
    put32(f, OFF_HDR, type);
    put32(f, OFF_HDR + 4, 0);
    put64(f, OFF_HDR + 8, sector);
}

/* 3.1.1 steps 1-6: reset, ACKNOWLEDGE, DRIVER, features, FEATURES_OK. */
static uint32_t drv_negotiate(struct rvvirtio_dev *d, uint64_t want_mask)
{
    WR(d, RVVIRTIO_REG_STATUS, 0);
    WR(d, RVVIRTIO_REG_STATUS, RVVIRTIO_STATUS_ACKNOWLEDGE);
    WR(d, RVVIRTIO_REG_STATUS, RVVIRTIO_STATUS_ACKNOWLEDGE | RVVIRTIO_STATUS_DRIVER);
    WR(d, RVVIRTIO_REG_DEVICE_FEATURES_SEL, 0);
    uint64_t feat = RD(d, RVVIRTIO_REG_DEVICE_FEATURES);
    WR(d, RVVIRTIO_REG_DEVICE_FEATURES_SEL, 1);
    feat |= (uint64_t)RD(d, RVVIRTIO_REG_DEVICE_FEATURES) << 32;
    feat &= want_mask | RVVIRTIO_F_VERSION_1;
    WR(d, RVVIRTIO_REG_DRIVER_FEATURES_SEL, 0);
    WR(d, RVVIRTIO_REG_DRIVER_FEATURES, (uint32_t)feat);
    WR(d, RVVIRTIO_REG_DRIVER_FEATURES_SEL, 1);
    WR(d, RVVIRTIO_REG_DRIVER_FEATURES, (uint32_t)(feat >> 32));
    WR(d, RVVIRTIO_REG_STATUS, RVVIRTIO_STATUS_ACKNOWLEDGE | RVVIRTIO_STATUS_DRIVER |
                                   RVVIRTIO_STATUS_FEATURES_OK);
    return RD(d, RVVIRTIO_REG_STATUS);
}

static void drv_queue(struct rvvirtio_dev *d, unsigned qi, uint32_t num)
{
    uint64_t desc = RAM_BASE + qdesc(qi), avail = RAM_BASE + qavail(qi),
             used = RAM_BASE + qused(qi);
    WR(d, RVVIRTIO_REG_QUEUE_SEL, qi);
    WR(d, RVVIRTIO_REG_QUEUE_NUM, num);
    WR(d, RVVIRTIO_REG_QUEUE_DESC_LOW, (uint32_t)desc);
    WR(d, RVVIRTIO_REG_QUEUE_DESC_HIGH, (uint32_t)(desc >> 32));
    WR(d, RVVIRTIO_REG_QUEUE_DRIVER_LOW, (uint32_t)avail);
    WR(d, RVVIRTIO_REG_QUEUE_DRIVER_HIGH, (uint32_t)(avail >> 32));
    WR(d, RVVIRTIO_REG_QUEUE_DEVICE_LOW, (uint32_t)used);
    WR(d, RVVIRTIO_REG_QUEUE_DEVICE_HIGH, (uint32_t)(used >> 32));
    WR(d, RVVIRTIO_REG_QUEUE_READY, 1);
}

static void drv_ok(struct rvvirtio_dev *d)
{
    WR(d, RVVIRTIO_REG_STATUS, RD(d, RVVIRTIO_REG_STATUS) | RVVIRTIO_STATUS_DRIVER_OK);
}

/* Full bring-up of a one-queue block device; returns final status. */
static uint32_t drv_blk_up(struct fx *f, struct rvvirtio_blk *b, bool ro)
{
    struct rvvirtio_mem mem = fx_mem(f);
    struct rvvirtio_blk_backend be = disk_backend(f);
    if (!g_api->blk_init(b, &mem, &be, ro))
        return 0xffffffffu;
    drv_negotiate(&b->dev, ~UINT64_C(0));
    drv_queue(&b->dev, 0, QN);
    drv_ok(&b->dev);
    return RD(&b->dev, RVVIRTIO_REG_STATUS);
}

static bool is_reset(struct rvvirtio_dev *d)
{
    return (RD(d, RVVIRTIO_REG_STATUS) & RVVIRTIO_STATUS_NEEDS_RESET) != 0;
}

/* One standard request: header, data segment(s), status. data_flags selects
 * IN (WRITE) vs OUT (readable). */
static void blk_post(struct fx *f, struct rvvirtio_dev *d, uint32_t type,
                     uint64_t sector, uint32_t data_len, uint16_t data_flags)
{
    struct dsc ds[3] = {
        {RAM_BASE + OFF_HDR, 16, 0},
        {RAM_BASE + OFF_DATA, data_len, data_flags},
        {RAM_BASE + OFF_STATUS, 1, 2},
    };
    if (data_len == 0)
        ds[1] = ds[2];
    put_hdr(f, type, sector);
    f->ram[OFF_STATUS] = 0xee;
    unsigned head = chain_put(f, 0, 0, ds, data_len != 0 ? 3u : 2u);
    avail_post(f, 0, head);
    WR(d, RVVIRTIO_REG_QUEUE_NOTIFY, 0);
}

/* ---- 1. transport identity, negotiation, status machine ---- */
static int t_handshake(void)
{
    int failures = 0;
    TEST("rvvirtio: mmio v2 identity, feature negotiation, status machine") {
        static struct fx f;
        static struct rvvirtio_blk b;
        fx_reset(&f);
        CHK(drv_blk_up(&f, &b, false) ==
            (RVVIRTIO_STATUS_ACKNOWLEDGE | RVVIRTIO_STATUS_DRIVER |
             RVVIRTIO_STATUS_FEATURES_OK | RVVIRTIO_STATUS_DRIVER_OK));
        struct rvvirtio_dev *d = &b.dev;
        CHK_EQ(RD(d, RVVIRTIO_REG_MAGIC), 0x74726976u);
        CHK_EQ(RD(d, RVVIRTIO_REG_VERSION), 2u);
        CHK_EQ(RD(d, RVVIRTIO_REG_DEVICE_ID), 2u);
        CHK_EQ(RD(d, RVVIRTIO_REG_VENDOR_ID), RVVIRTIO_VENDOR_ID);
        WR(d, RVVIRTIO_REG_DEVICE_FEATURES_SEL, 1);
        CHK_EQ(RD(d, RVVIRTIO_REG_DEVICE_FEATURES), 1u); /* VERSION_1 */
        WR(d, RVVIRTIO_REG_DEVICE_FEATURES_SEL, 7);
        CHK_EQ(RD(d, RVVIRTIO_REG_DEVICE_FEATURES), 0u);
        /* queue registers */
        WR(d, RVVIRTIO_REG_QUEUE_SEL, 0);
        CHK_EQ(RD(d, RVVIRTIO_REG_QUEUE_NUM_MAX), RVVIRTIO_QUEUE_MAX);
        CHK_EQ(RD(d, RVVIRTIO_REG_QUEUE_READY), 1u);
        WR(d, RVVIRTIO_REG_QUEUE_SEL, 5);
        CHK_EQ(RD(d, RVVIRTIO_REG_QUEUE_NUM_MAX), 0u);
        CHK_EQ(RD(d, RVVIRTIO_REG_QUEUE_READY), 0u);
        /* config: capacity 128 sectors, generation stable */
        CHK_EQ(RD(d, RVVIRTIO_REG_CONFIG), 128u);
        CHK_EQ(RD(d, RVVIRTIO_REG_CONFIG + 4), 0u);
        CHK_EQ(RD(d, RVVIRTIO_REG_CONFIG_GENERATION), 0u);
        CHK_EQ(RD(d, RVVIRTIO_REG_CONFIG + 0x200), 0u);
        rvvirtio_dev_config_changed(d);
        CHK_EQ(RD(d, RVVIRTIO_REG_CONFIG_GENERATION), 1u);
        CHK_EQ(RD(d, RVVIRTIO_REG_INTERRUPT_STATUS), 2u);
        CHK(f.irq);
        /* a status 0 write resets everything */
        WR(d, RVVIRTIO_REG_STATUS, 0);
        CHK_EQ(RD(d, RVVIRTIO_REG_STATUS), 0u);
        WR(d, RVVIRTIO_REG_QUEUE_SEL, 0);
        CHK_EQ(RD(d, RVVIRTIO_REG_QUEUE_READY), 0u);
        CHK(!f.irq);
        CHK(guards_ok(&f));
        PASS();
    } _test_next:;
    return failures;
}

static int t_features_ok_rejection(void)
{
    int failures = 0;
    TEST("rvvirtio: FEATURES_OK is refused without VERSION_1 or with unknown bits") {
        static struct fx f;
        static struct rvvirtio_blk b;
        struct rvvirtio_mem mem = fx_mem(&f);
        fx_reset(&f);
        struct rvvirtio_blk_backend be = disk_backend(&f);
        CHK(g_api->blk_init(&b, &mem, &be, false));
        struct rvvirtio_dev *d = &b.dev;
        WR(d, RVVIRTIO_REG_STATUS, 1);
        WR(d, RVVIRTIO_REG_STATUS, 3);
        /* no VERSION_1 */
        WR(d, RVVIRTIO_REG_DRIVER_FEATURES_SEL, 0);
        WR(d, RVVIRTIO_REG_DRIVER_FEATURES, 0);
        WR(d, RVVIRTIO_REG_STATUS, 3 | RVVIRTIO_STATUS_FEATURES_OK);
        CHK((RD(d, RVVIRTIO_REG_STATUS) & RVVIRTIO_STATUS_FEATURES_OK) == 0);
        WR(d, RVVIRTIO_REG_STATUS, 3 | RVVIRTIO_STATUS_FEATURES_OK | RVVIRTIO_STATUS_DRIVER_OK);
        CHK((RD(d, RVVIRTIO_REG_STATUS) & RVVIRTIO_STATUS_DRIVER_OK) == 0);
        /* VERSION_1 plus a bit the device never offered */
        WR(d, RVVIRTIO_REG_STATUS, 0);
        WR(d, RVVIRTIO_REG_STATUS, 3);
        WR(d, RVVIRTIO_REG_DRIVER_FEATURES_SEL, 0);
        WR(d, RVVIRTIO_REG_DRIVER_FEATURES, 1u << 3);
        WR(d, RVVIRTIO_REG_DRIVER_FEATURES_SEL, 1);
        WR(d, RVVIRTIO_REG_DRIVER_FEATURES, 1u);
        WR(d, RVVIRTIO_REG_STATUS, 3 | RVVIRTIO_STATUS_FEATURES_OK);
        CHK((RD(d, RVVIRTIO_REG_STATUS) & RVVIRTIO_STATUS_FEATURES_OK) == 0);
        /* features are frozen after a successful FEATURES_OK */
        CHK((drv_negotiate(d, 0) & RVVIRTIO_STATUS_FEATURES_OK) != 0);
        WR(d, RVVIRTIO_REG_DRIVER_FEATURES_SEL, 0);
        WR(d, RVVIRTIO_REG_DRIVER_FEATURES, 0xffffffffu);
        CHK(d->driver_features != (UINT64_C(0xffffffff)));
        /* queue setup with a bad size is NEEDS_RESET, never accepted */
        drv_queue(d, 0, 3);
        CHK(is_reset(d));
        WR(d, RVVIRTIO_REG_STATUS, 0);
        CHK(!is_reset(d));
        CHK(guards_ok(&f));
        PASS();
    } _test_next:;
    return failures;
}

/* ---- 2. blk traffic ---- */
static int t_blk_roundtrip(void)
{
    int failures = 0;
    TEST("rvvirtio: blk IN/OUT/FLUSH/GET_ID round trips incl. multi-descriptor") {
        static struct fx f;
        static struct rvvirtio_blk b;
        fx_reset(&f);
        CHK(drv_blk_up(&f, &b, false) != 0xffffffffu);
        struct rvvirtio_dev *d = &b.dev;
        /* OUT, 3 descriptors of data: 512 + 1024 + 512 bytes at sector 10 */
        uint8_t pat[2048];
        for (unsigned i = 0; i < sizeof(pat); i++)
            pat[i] = (uint8_t)(i ^ 0x5a);
        memcpy(f.ram + OFF_DATA, pat, 512);
        memcpy(f.ram + OFF_DATA2, pat + 512, 1024);
        memcpy(f.ram + OFF_DATA2 + 0x1000, pat + 1536, 512);
        struct dsc ds[5] = {
            {RAM_BASE + OFF_HDR, 16, 0},
            {RAM_BASE + OFF_DATA, 512, 0},
            {RAM_BASE + OFF_DATA2, 1024, 0},
            {RAM_BASE + OFF_DATA2 + 0x1000, 512, 0},
            {RAM_BASE + OFF_STATUS, 1, 2},
        };
        put_hdr(&f, RVVIRTIO_BLK_T_OUT, 10);
        avail_post(&f, 0, chain_put(&f, 0, 0, ds, 5));
        WR(d, RVVIRTIO_REG_QUEUE_NOTIFY, 0);
        CHK_EQ(f.ram[OFF_STATUS], RVVIRTIO_BLK_S_OK);
        CHK_EQ(used_idx(&f, 0), 1u);
        CHK_EQ(used_id(&f, 0, 0), 0u);
        CHK_EQ(used_len(&f, 0, 0), 1u);
        CHK(memcmp(f.disk.data + 10 * 512, pat, sizeof(pat)) == 0);
        CHK(f.irq);
        CHK_EQ(RD(d, RVVIRTIO_REG_INTERRUPT_STATUS), 1u);
        WR(d, RVVIRTIO_REG_INTERRUPT_ACK, 1);
        CHK(!f.irq);
        /* IN of 16 sectors (two bounce chunks) split over two data segments */
        struct dsc in[4] = {
            {RAM_BASE + OFF_HDR, 16, 0},
            {RAM_BASE + OFF_DATA, 3000, 2},
            {RAM_BASE + OFF_DATA2, 5192, 2},
            {RAM_BASE + OFF_STATUS, 1, 2},
        };
        put_hdr(&f, RVVIRTIO_BLK_T_IN, 20);
        avail_post(&f, 0, chain_put(&f, 0, 4, in, 4));
        WR(d, RVVIRTIO_REG_QUEUE_NOTIFY, 0);
        CHK_EQ(f.ram[OFF_STATUS], RVVIRTIO_BLK_S_OK);
        CHK_EQ(used_len(&f, 0, 1), 8192u + 1u);
        CHK(memcmp(f.ram + OFF_DATA, f.disk.data + 20 * 512, 3000) == 0);
        CHK(memcmp(f.ram + OFF_DATA2, f.disk.data + 20 * 512 + 3000, 5192) == 0);
        WR(d, RVVIRTIO_REG_INTERRUPT_ACK, 1);
        /* FLUSH */
        blk_post(&f, d, RVVIRTIO_BLK_T_FLUSH, 0, 0, 0);
        CHK_EQ(f.ram[OFF_STATUS], RVVIRTIO_BLK_S_OK);
        CHK_EQ(f.disk.flushes, 1u);
        /* GET_ID: 20 bytes, NUL padded */
        blk_post(&f, d, RVVIRTIO_BLK_T_GET_ID, 0, 20, 2);
        CHK_EQ(f.ram[OFF_STATUS], RVVIRTIO_BLK_S_OK);
        CHK(memcmp(f.ram + OFF_DATA, "z23-test-disk\0\0\0\0\0\0\0", 20) == 0);
        /* unknown request type */
        blk_post(&f, d, 99, 0, 0, 0);
        CHK_EQ(f.ram[OFF_STATUS], RVVIRTIO_BLK_S_UNSUPP);
        /* IN with a data length that is not a sector multiple */
        blk_post(&f, d, RVVIRTIO_BLK_T_IN, 0, 100, 2);
        CHK_EQ(f.ram[OFF_STATUS], RVVIRTIO_BLK_S_IOERR);
        CHK_EQ(used_idx(&f, 0), 6u);
        CHK(!is_reset(d));
        CHK(guards_ok(&f));
        PASS();
    } _test_next:;
    return failures;
}

static int t_blk_indirect_and_suppress(void)
{
    int failures = 0;
    TEST("rvvirtio: blk indirect descriptors and interrupt suppression") {
        static struct fx f;
        static struct rvvirtio_blk b;
        fx_reset(&f);
        CHK(drv_blk_up(&f, &b, false) != 0xffffffffu);
        struct rvvirtio_dev *d = &b.dev;
        /* indirect table at OFF_DATA2: hdr, data(write), status */
        struct dsc tab[3] = {
            {RAM_BASE + OFF_HDR, 16, 0},
            {RAM_BASE + OFF_DATA, 512, 2},
            {RAM_BASE + OFF_STATUS, 1, 2},
        };
        for (unsigned i = 0; i < 3; i++) {
            struct dsc s = tab[i];
            s.flags |= (i < 2) ? 1u : 0u;
            desc_put(&f, OFF_DATA2, i, &s, i + 1u);
        }
        struct dsc ind = {RAM_BASE + OFF_DATA2, 48, 4};
        desc_put(&f, qdesc(0), 0, &ind, 0);
        put_hdr(&f, RVVIRTIO_BLK_T_IN, 3);
        put16(&f, qavail(0), 1); /* VRING_AVAIL_F_NO_INTERRUPT */
        avail_post(&f, 0, 0);
        WR(d, RVVIRTIO_REG_QUEUE_NOTIFY, 0);
        CHK_EQ(f.ram[OFF_STATUS], RVVIRTIO_BLK_S_OK);
        CHK(memcmp(f.ram + OFF_DATA, f.disk.data + 3 * 512, 512) == 0);
        CHK_EQ(used_idx(&f, 0), 1u);
        CHK_EQ(RD(d, RVVIRTIO_REG_INTERRUPT_STATUS), 0u);
        CHK(!f.irq);
        /* a nested indirect descriptor inside the table is a device error */
        desc_put(&f, OFF_DATA2, 1, &ind, 0);
        put16(&f, qavail(0), 0);
        avail_post(&f, 0, 0);
        WR(d, RVVIRTIO_REG_QUEUE_NOTIFY, 0);
        CHK(is_reset(d));
        CHK(guards_ok(&f));
        PASS();
    } _test_next:;
    return failures;
}

/* ---- 3. read-only disk ---- */
static int t_blk_read_only(void)
{
    int failures = 0;
    TEST("rvvirtio: write to a read-only disk is IOERR and the disk is untouched") {
        static struct fx f;
        static struct rvvirtio_blk b;
        static uint8_t before[DISK_BYTES];
        fx_reset(&f);
        CHK(drv_blk_up(&f, &b, true) != 0xffffffffu);
        struct rvvirtio_dev *d = &b.dev;
        WR(d, RVVIRTIO_REG_DEVICE_FEATURES_SEL, 0);
        CHK((RD(d, RVVIRTIO_REG_DEVICE_FEATURES) & (1u << 5)) != 0); /* F_RO */
        memcpy(before, f.disk.data, sizeof(before));
        memset(f.ram + OFF_DATA, 0xab, 512);
        blk_post(&f, d, RVVIRTIO_BLK_T_OUT, 1, 512, 0);
        CHK_EQ(f.ram[OFF_STATUS], RVVIRTIO_BLK_S_IOERR);
        CHK(memcmp(before, f.disk.data, sizeof(before)) == 0);
        CHK_EQ(f.disk.calls, 0u);
        blk_post(&f, d, RVVIRTIO_BLK_T_IN, 1, 512, 2);
        CHK_EQ(f.ram[OFF_STATUS], RVVIRTIO_BLK_S_OK);
        CHK(memcmp(f.ram + OFF_DATA, before + 512, 512) == 0);
        CHK(!is_reset(d));
        CHK(guards_ok(&f));
        PASS();
    } _test_next:;
    return failures;
}

/* ---- 4. hostile range requests (also run against the sector twin) ---- */
struct range_probe {
    unsigned backend_calls;
    unsigned ioerr;
    unsigned cases;
};

static void probe_one(struct fx *f, struct rvvirtio_dev *d, uint32_t type,
                      uint64_t sector, uint32_t len, struct range_probe *p)
{
    blk_post(f, d, type, sector, len, type == RVVIRTIO_BLK_T_IN ? 2 : 0);
    p->cases++;
    if (f->ram[OFF_STATUS] == RVVIRTIO_BLK_S_IOERR)
        p->ioerr++;
    p->backend_calls = f->disk.calls;
}

static struct range_probe run_range_cases(struct fx *f)
{
    static struct rvvirtio_blk b;
    struct range_probe p = {0, 0, 0};
    fx_reset(f);
    (void)drv_blk_up(f, &b, false);
    struct rvvirtio_dev *d = &b.dev;
    const uint64_t cap = DISK_BYTES / 512u;
    probe_one(f, d, RVVIRTIO_BLK_T_IN, cap, 512, &p);            /* first past end */
    probe_one(f, d, RVVIRTIO_BLK_T_OUT, cap + 1u, 512, &p);
    probe_one(f, d, RVVIRTIO_BLK_T_IN, cap - 1u, 1024, &p);      /* straddles end */
    probe_one(f, d, RVVIRTIO_BLK_T_IN, UINT64_MAX, 512, &p);
    probe_one(f, d, RVVIRTIO_BLK_T_OUT, (UINT64_C(1) << 55) + 1u, 512, &p); /* *512 wraps to 512 */
    probe_one(f, d, RVVIRTIO_BLK_T_IN, (UINT64_C(1) << 55) + 1u, 512, &p);
    probe_one(f, d, RVVIRTIO_BLK_T_OUT, (UINT64_C(1) << 63) + 2u, 512, &p);
    return p;
}

static int t_blk_range(void)
{
    int failures = 0;
    TEST("rvvirtio: sector past capacity and sector*512 overflow never reach the backend") {
        static struct fx f;
        static uint8_t before[DISK_BYTES];
        fx_reset(&f);
        memcpy(before, f.disk.data, sizeof(before));
        struct range_probe p = run_range_cases(&f);
        CHK_EQ(p.cases, 7u);
        CHK_EQ(p.ioerr, 7u);
        CHK_EQ(p.backend_calls, 0u);
        CHK(memcmp(before, f.disk.data, sizeof(before)) == 0);
        CHK_EQ(used_idx(&f, 0), 7u);
        CHK(guards_ok(&f));
        PASS();
    } _test_next:;
    return failures;
}

/* ---- 5. hostile descriptors ---- */
static int t_hostile_descriptors(void)
{
    int failures = 0;
    TEST("rvvirtio: out-of-RAM, wrapping, bad-head and short chains end in NEEDS_RESET") {
        static struct fx f;
        static struct rvvirtio_blk b;
        const uint64_t bad[3] = {RAM_BASE + RAM_SIZE - 100u, UINT64_MAX - 10u, 0x10u};
        for (unsigned i = 0; i < 3; i++) {
            fx_reset(&f);
            CHK(drv_blk_up(&f, &b, false) != 0xffffffffu);
            struct dsc ds[3] = {
                {RAM_BASE + OFF_HDR, 16, 0},
                {bad[i], 512, 2},
                {RAM_BASE + OFF_STATUS, 1, 2},
            };
            put_hdr(&f, RVVIRTIO_BLK_T_IN, 0);
            avail_post(&f, 0, chain_put(&f, 0, 0, ds, 3));
            WR(&b.dev, RVVIRTIO_REG_QUEUE_NOTIFY, 0);
            CHK(is_reset(&b.dev));
            CHK_EQ(used_idx(&f, 0), 0u);
            CHK(guards_ok(&f));
            CHK(f.ram[OFF_DATA] == 0); /* nothing delivered into RAM */
            /* a reset notify is ignored; status 0 recovers the device */
            WR(&b.dev, RVVIRTIO_REG_QUEUE_NOTIFY, 0);
            WR(&b.dev, RVVIRTIO_REG_STATUS, 0);
            CHK(!is_reset(&b.dev));
        }
        /* head index outside the queue */
        fx_reset(&f);
        CHK(drv_blk_up(&f, &b, false) != 0xffffffffu);
        avail_post(&f, 0, QN + 3u);
        WR(&b.dev, RVVIRTIO_REG_QUEUE_NOTIFY, 0);
        CHK(is_reset(&b.dev));
        /* avail.idx runs further ahead than the queue can hold */
        fx_reset(&f);
        CHK(drv_blk_up(&f, &b, false) != 0xffffffffu);
        put16(&f, qavail(0) + 2, QN + 5u);
        WR(&b.dev, RVVIRTIO_REG_QUEUE_NOTIFY, 0);
        CHK(is_reset(&b.dev));
        CHK(guards_ok(&f));
        PASS();
    } _test_next:;
    return failures;
}

static int t_undersized_status_and_ordering(void)
{
    int failures = 0;
    TEST("rvvirtio: undersized status descriptor and missing header are device errors") {
        static struct fx f;
        static struct rvvirtio_blk b;
        for (unsigned variant = 0; variant < 3; variant++) {
            fx_reset(&f);
            CHK(drv_blk_up(&f, &b, false) != 0xffffffffu);
            struct dsc ds[3] = {
                {RAM_BASE + OFF_HDR, variant == 2 ? 8u : 16u, 0},
                {RAM_BASE + OFF_DATA, 512, 0},
                {RAM_BASE + OFF_STATUS, 0, 2}, /* zero-length status */
            };
            put_hdr(&f, RVVIRTIO_BLK_T_OUT, 0);
            unsigned n = variant == 1 ? 2u : 3u; /* variant 1: no status at all */
            avail_post(&f, 0, chain_put(&f, 0, 0, ds, n));
            WR(&b.dev, RVVIRTIO_REG_QUEUE_NOTIFY, 0);
            CHK(is_reset(&b.dev));
            CHK_EQ(used_idx(&f, 0), 0u);
            CHK_EQ(f.ram[OFF_STATUS], 0u);
            CHK_EQ(f.disk.calls, 0u);
            CHK(guards_ok(&f));
        }
        /* a zero-length status after a writable data segment is still
         * defined: the last writable byte is the status, the 511-byte data
         * area is not a sector multiple, so the answer is IOERR. */
        fx_reset(&f);
        CHK(drv_blk_up(&f, &b, false) != 0xffffffffu);
        struct dsc in[3] = {{RAM_BASE + OFF_HDR, 16, 0},
                            {RAM_BASE + OFF_DATA, 512, 2},
                            {RAM_BASE + OFF_STATUS, 0, 2}};
        put_hdr(&f, RVVIRTIO_BLK_T_IN, 0);
        avail_post(&f, 0, chain_put(&f, 0, 0, in, 3));
        WR(&b.dev, RVVIRTIO_REG_QUEUE_NOTIFY, 0);
        CHK(!is_reset(&b.dev));
        CHK_EQ(f.ram[OFF_DATA + 511], RVVIRTIO_BLK_S_IOERR);
        CHK_EQ(used_idx(&f, 0), 1u);
        CHK_EQ(f.disk.calls, 0u);
        CHK(guards_ok(&f));
        PASS();
    } _test_next:;
    return failures;
}

static int t_notify_before_driver_ok(void)
{
    int failures = 0;
    TEST("rvvirtio: notify before DRIVER_OK consumes nothing and reads no guest memory") {
        static struct fx f;
        static struct rvvirtio_blk b;
        struct rvvirtio_mem mem = fx_mem(&f);
        struct rvvirtio_blk_backend be = disk_backend(&f);
        fx_reset(&f);
        CHK(g_api->blk_init(&b, &mem, &be, false));
        drv_negotiate(&b.dev, ~UINT64_C(0));
        drv_queue(&b.dev, 0, QN);
        put_hdr(&f, RVVIRTIO_BLK_T_FLUSH, 0);
        struct dsc ds[2] = {{RAM_BASE + OFF_HDR, 16, 0}, {RAM_BASE + OFF_STATUS, 1, 2}};
        avail_post(&f, 0, chain_put(&f, 0, 0, ds, 2));
        f.reads = 0;
        WR(&b.dev, RVVIRTIO_REG_QUEUE_NOTIFY, 0);
        CHK_EQ(f.reads, 0u);
        CHK_EQ(f.writes, 0u);
        CHK_EQ(used_idx(&f, 0), 0u);
        CHK(!is_reset(&b.dev));
        drv_ok(&b.dev);
        WR(&b.dev, RVVIRTIO_REG_QUEUE_NOTIFY, 0);
        CHK_EQ(used_idx(&f, 0), 1u);
        CHK_EQ(f.disk.flushes, 1u);
        /* notify on an unconfigured queue index is ignored too */
        WR(&b.dev, RVVIRTIO_REG_QUEUE_NOTIFY, 9);
        CHK(!is_reset(&b.dev));
        CHK(guards_ok(&f));
        PASS();
    } _test_next:;
    return failures;
}

static int t_callback_failure(void)
{
    int failures = 0;
    TEST("rvvirtio: a failing guest-memory callback sets NEEDS_RESET") {
        static struct fx f;
        static struct rvvirtio_blk b;
        fx_reset(&f);
        CHK(drv_blk_up(&f, &b, false) != 0xffffffffu);
        struct dsc ds[2] = {{RAM_BASE + OFF_HDR, 16, 0}, {RAM_BASE + OFF_STATUS, 1, 2}};
        put_hdr(&f, RVVIRTIO_BLK_T_FLUSH, 0);
        avail_post(&f, 0, chain_put(&f, 0, 0, ds, 2));
        f.reads = 0;
        f.read_limit = 1; /* avail.idx ok, the head read fails */
        WR(&b.dev, RVVIRTIO_REG_QUEUE_NOTIFY, 0);
        CHK(is_reset(&b.dev));
        CHK_EQ(used_idx(&f, 0), 0u);
        CHK(f.irq); /* config-change interrupt announces the failure */
        CHK_EQ(RD(&b.dev, RVVIRTIO_REG_INTERRUPT_STATUS) & 2u, 2u);
        CHK(guards_ok(&f));
        PASS();
    } _test_next:;
    return failures;
}

/* ---- 6. chain loops: step counter, never a real hang (also the twin) ---- */
static unsigned run_loop_case(struct fx *f, bool self_loop, bool *reset_out)
{
    static struct rvvirtio_blk b;
    fx_reset(f);
    (void)drv_blk_up(f, &b, false);
    struct dsc a = {RAM_BASE + OFF_HDR, 16, 1};
    struct dsc c = {RAM_BASE + OFF_DATA, 16, 1};
    desc_put(f, qdesc(0), 0, &a, self_loop ? 0u : 1u);
    desc_put(f, qdesc(0), 1, &c, 0);
    avail_post(f, 0, 0);
    f->read_limit = 100000; /* abort guard: the callback ends any runaway walk */
    f->reads = 0;
    WR(&b.dev, RVVIRTIO_REG_QUEUE_NOTIFY, 0);
    *reset_out = is_reset(&b.dev);
    return f->reads;
}

#define LOOP_READ_BUDGET (QN + 2u) /* avail.idx + head + one read per descriptor */

static int t_chain_loops(void)
{
    int failures = 0;
    TEST("rvvirtio: looped chains stop within the queue size and reset the device") {
        static struct fx f;
        for (unsigned self = 0; self < 2; self++) {
            bool reset = false;
            unsigned reads = run_loop_case(&f, self != 0, &reset);
            CHK(reset);
            CHK(reads <= LOOP_READ_BUDGET);
            CHK_EQ(used_idx(&f, 0), 0u);
            CHK(guards_ok(&f));
        }
        PASS();
    } _test_next:;
    return failures;
}

/* ---- 7. net ---- */
static const uint8_t k_mac[6] = {0x02, 0x5a, 0x32, 0x33, 0x00, 0x01};

static bool drv_net_up(struct fx *f, struct rvvirtio_net *n)
{
    struct rvvirtio_mem mem = fx_mem(f);
    if (!rvvirtio_net_init(n, &mem, k_mac, tx_cb, &f->tx))
        return false;
    drv_negotiate(&n->dev, ~UINT64_C(0));
    drv_queue(&n->dev, 0, QN);
    drv_queue(&n->dev, 1, QN);
    drv_ok(&n->dev);
    return (RD(&n->dev, RVVIRTIO_REG_STATUS) & RVVIRTIO_STATUS_DRIVER_OK) != 0;
}

static void frame_fill(uint8_t *p, size_t len)
{
    for (size_t i = 0; i < len; i++)
        p[i] = (uint8_t)(i * 13u + 1u);
}

static void tx_post(struct fx *f, struct rvvirtio_dev *d, size_t frame_len,
                    unsigned idx0, uint16_t seg2_flags)
{
    uint8_t *hdr = f->ram + OFF_DATA;
    memset(hdr, 0, 12);
    frame_fill(f->ram + OFF_DATA2, frame_len);
    struct dsc ds[2] = {{RAM_BASE + OFF_DATA, 12, 0},
                        {RAM_BASE + OFF_DATA2, (uint32_t)frame_len, seg2_flags}};
    avail_post(f, 1, chain_put(f, 1, idx0, ds, 2));
    WR(d, RVVIRTIO_REG_QUEUE_NOTIFY, 1);
}

static int t_net_config_and_tx(void)
{
    int failures = 0;
    TEST("rvvirtio: net identity, MAC config and transmit") {
        static struct fx f;
        static struct rvvirtio_net n;
        fx_reset(&f);
        CHK(drv_net_up(&f, &n));
        struct rvvirtio_dev *d = &n.dev;
        CHK_EQ(RD(d, RVVIRTIO_REG_DEVICE_ID), 1u);
        CHK_EQ(RD(d, RVVIRTIO_REG_CONFIG), 0x33325a02u);
        CHK_EQ(RD(d, RVVIRTIO_REG_CONFIG + 4) & 0xffffu, 0x0100u);
        CHK_EQ(RD(d, RVVIRTIO_REG_CONFIG + 4) >> 16, 1u); /* link up */
        tx_post(&f, d, 60, 0, 0);
        CHK_EQ(f.tx.calls, 1u);
        CHK_EQ(f.tx.len, 60u);
        uint8_t want[1514];
        frame_fill(want, 60);
        CHK(memcmp(f.tx.frame, want, 60) == 0);
        CHK_EQ(used_idx(&f, 1), 1u);
        CHK_EQ(used_len(&f, 1, 0), 0u);
        /* bounds: 14 and 1514 pass, 13 and 1515 are dropped but completed */
        tx_post(&f, d, 14, 2, 0);
        tx_post(&f, d, 1514, 4, 0);
        CHK_EQ(f.tx.calls, 3u);
        CHK_EQ(f.tx.len, 1514u);
        tx_post(&f, d, 13, 6, 0);
        tx_post(&f, d, 1515, 8, 0);
        CHK_EQ(f.tx.calls, 3u);
        CHK_EQ(used_idx(&f, 1), 5u);
        CHK(!is_reset(d));
        /* a transmit chain with a device-writable data segment is an error */
        tx_post(&f, d, 60, 10, 2);
        CHK(is_reset(d));
        CHK_EQ(f.tx.calls, 3u);
        CHK(guards_ok(&f));
        PASS();
    } _test_next:;
    return failures;
}

static void rx_buffers(struct fx *f, unsigned count, uint32_t len)
{
    for (unsigned i = 0; i < count; i++) {
        struct dsc ds[1] = {{RAM_BASE + OFF_DATA + 0x2000u * i, len, 2}};
        avail_post(f, 0, chain_put(f, 0, i, ds, 1));
    }
}

static int t_net_rx(void)
{
    int failures = 0;
    TEST("rvvirtio: net receive places hdr+frame, raises irq, refuses when no buffer") {
        static struct fx f;
        static struct rvvirtio_net n;
        uint8_t fr[1514];
        fx_reset(&f);
        CHK(drv_net_up(&f, &n));
        frame_fill(fr, sizeof(fr));
        /* no buffer yet: false, nothing written, no interrupt */
        f.writes = 0;
        CHK(!rvvirtio_net_receive(&n, fr, 60));
        CHK_EQ(f.writes, 0u);
        CHK(!f.irq);
        rx_buffers(&f, 2, 2048);
        CHK(rvvirtio_net_receive(&n, fr, 60));
        CHK(f.irq);
        CHK_EQ(used_idx(&f, 0), 1u);
        CHK_EQ(used_len(&f, 0, 0), 72u);
        static const uint8_t hdr[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0};
        CHK(memcmp(f.ram + OFF_DATA, hdr, 12) == 0);
        CHK(memcmp(f.ram + OFF_DATA + 12, fr, 60) == 0);
        WR(&n.dev, RVVIRTIO_REG_INTERRUPT_ACK, 1);
        CHK(!f.irq);
        /* maximum frame fits the 2048-byte buffer */
        CHK(rvvirtio_net_receive(&n, fr, 1514));
        CHK_EQ(used_len(&f, 0, 1), 1526u);
        CHK(memcmp(f.ram + OFF_DATA + 0x2000u + 12, fr, 1514) == 0);
        /* out of buffers again */
        CHK(!rvvirtio_net_receive(&n, fr, 60));
        /* length bounds never touch guest memory */
        f.writes = 0;
        f.reads = 0;
        CHK(!rvvirtio_net_receive(&n, fr, 13));
        CHK(!rvvirtio_net_receive(&n, fr, 1515));
        CHK(!rvvirtio_net_receive(&n, NULL, 60));
        CHK_EQ(f.writes + f.reads, 0u);
        CHK(guards_ok(&f));
        PASS();
    } _test_next:;
    return failures;
}

static int t_net_rx_hostile(void)
{
    int failures = 0;
    TEST("rvvirtio: net rx with a short or readable buffer, or before DRIVER_OK") {
        static struct fx f;
        static struct rvvirtio_net n;
        uint8_t fr[100];
        frame_fill(fr, sizeof(fr));
        /* rx before DRIVER_OK */
        fx_reset(&f);
        struct rvvirtio_mem mem = fx_mem(&f);
        CHK(rvvirtio_net_init(&n, &mem, k_mac, tx_cb, &f.tx));
        drv_negotiate(&n.dev, ~UINT64_C(0));
        drv_queue(&n.dev, 0, QN);
        rx_buffers(&f, 1, 2048);
        f.reads = 0;
        CHK(!rvvirtio_net_receive(&n, fr, 60));
        CHK_EQ(f.reads, 0u);
        CHK_EQ(used_idx(&f, 0), 0u);
        /* buffer too small for hdr + frame */
        fx_reset(&f);
        CHK(drv_net_up(&f, &n));
        rx_buffers(&f, 1, 40);
        CHK(!rvvirtio_net_receive(&n, fr, 60));
        CHK(is_reset(&n.dev));
        CHK_EQ(used_idx(&f, 0), 0u);
        CHK_EQ(f.ram[OFF_DATA], 0u);
        /* device-readable rx buffer */
        fx_reset(&f);
        CHK(drv_net_up(&f, &n));
        struct dsc ds[1] = {{RAM_BASE + OFF_DATA, 2048, 0}};
        avail_post(&f, 0, chain_put(&f, 0, 0, ds, 1));
        CHK(!rvvirtio_net_receive(&n, fr, 60));
        CHK(is_reset(&n.dev));
        /* rx buffer pointing outside RAM */
        fx_reset(&f);
        CHK(drv_net_up(&f, &n));
        struct dsc bad[1] = {{RAM_BASE + RAM_SIZE - 20u, 2048, 2}};
        avail_post(&f, 0, chain_put(&f, 0, 0, bad, 1));
        CHK(!rvvirtio_net_receive(&n, fr, 60));
        CHK(is_reset(&n.dev));
        CHK_EQ(used_idx(&f, 0), 0u);
        CHK(guards_ok(&f));
        PASS();
    } _test_next:;
    return failures;
}

/* ---- 8. mutation twins: each removed guard must be detectable ---- */
static int t_mutation_twins(void)
{
    int failures = 0;
    TEST("rvvirtio: mutation twins (chain bound removed, sector check removed) are caught") {
        static struct fx f;
        bool reset = false;
        /* (a) chain-loop bound removed: the walk reads far past the queue
         * size. The step counter (guest-memory reads) catches it; the abort
         * limit in the callback means the twin can never really hang. */
        g_api = &k_real;
        unsigned good = run_loop_case(&f, false, &reset);
        g_api = &k_mut;
        unsigned bad = run_loop_case(&f, false, &reset);
        g_api = &k_real;
        printf("\n    rvvirtio twin chain-bound: real reads=%u bound=%u, twin reads=%u -> %s\n",
               good, LOOP_READ_BUDGET, bad, bad > LOOP_READ_BUDGET ? "DETECTED" : "MISSED");
        CHK(good <= LOOP_READ_BUDGET);
        CHK(bad > LOOP_READ_BUDGET);
        CHK(bad < 100000u); /* the twin was stopped by the array limit, not a hang */
        /* (b) sector range check removed: hostile sectors reach the backend. */
        g_api = &k_real;
        struct range_probe rp = run_range_cases(&f);
        g_api = &k_mut;
        struct range_probe mp = run_range_cases(&f);
        g_api = &k_real;
        printf("    rvvirtio twin sector-range: real backend calls=%u, twin backend calls=%u -> %s\n",
               rp.backend_calls, mp.backend_calls, mp.backend_calls > 0 ? "DETECTED" : "MISSED");
        CHK_EQ(rp.backend_calls, 0u);
        CHK(mp.backend_calls > 0);
        PASS();
    } _test_next:;
    return failures;
}

/* ---- 9. virtio-console, multiport (5.3) ---- */
struct con_api {
    bool (*init)(struct rvvirtio_console *, const struct rvvirtio_mem *,
                 const struct rvvirtio_console_ops *, uint32_t);
    bool (*open)(struct rvvirtio_console *, uint32_t, const char *);
    size_t (*write)(struct rvvirtio_console *, uint32_t, const uint8_t *, size_t);
    void (*resume)(struct rvvirtio_console *, uint32_t);
    void (*close)(struct rvvirtio_console *, uint32_t);
    uint32_t (*gen)(const struct rvvirtio_console *, uint32_t);
    size_t (*consumed)(struct rvvirtio_console *, uint32_t);
};

static const struct con_api k_creal = {
    rvvirtio_console_init, rvvirtio_console_port_open,
    rvvirtio_console_port_write, rvvirtio_console_port_resume,
    rvvirtio_console_port_close, rvvirtio_console_port_generation,
    rvvirtio_console_port_consumed};
static const struct con_api k_cmut = {
    rvvmut_console_init, rvvmut_console_port_open, rvvmut_console_port_write,
    rvvmut_console_port_resume, rvvmut_console_port_close,
    rvvmut_console_port_generation, rvvmut_console_port_consumed};
static const struct con_api *g_capi = &k_creal;

#define CTL_RX_OFF 0x20000u
#define CTL_TX_OFF 0x24000u
#define RXBUF_OFF 0x28000u
#define TXBUF_OFF 0x2c000u

struct sink {
    uint8_t got[512];
    size_t n;
    size_t quota;
    unsigned calls, writable_calls, reentry_bad;
    uint32_t writable_port;
    struct rvvirtio_console *c;
};

static struct sink g_sink;

static void sink_probe(void)
{
    uint8_t z = 'z';
    if (g_sink.c == NULL)
        return;
    if (g_capi->write(g_sink.c, 1, &z, 1) != 0 || g_capi->open(g_sink.c, 2, "x"))
        g_sink.reentry_bad++;
    g_capi->resume(g_sink.c, 1);
    g_capi->close(g_sink.c, 1); /* all refused: callbacks must not re-enter */
}

static size_t sink_from_guest(void *ctx, uint32_t port, const uint8_t *buf, size_t n)
{
    (void)ctx;
    (void)port;
    g_sink.calls++;
    sink_probe();
    size_t k = n < g_sink.quota ? n : g_sink.quota;
    if (g_sink.n + k <= sizeof(g_sink.got))
        memcpy(g_sink.got + g_sink.n, buf, k);
    g_sink.n += k;
    g_sink.quota -= k;
    return k;
}

static void sink_writable(void *ctx, uint32_t port)
{
    (void)ctx;
    g_sink.writable_calls++;
    g_sink.writable_port = port;
    sink_probe();
}

static void ctl_send(struct fx *f, struct rvvirtio_dev *d, uint32_t id,
                     uint16_t ev, uint16_t val)
{
    unsigned slot = get16(f, qavail(3) + 2) % QN;
    put32(f, CTL_TX_OFF + slot * 0x20u, id);
    put16(f, CTL_TX_OFF + slot * 0x20u + 4, ev);
    put16(f, CTL_TX_OFF + slot * 0x20u + 6, val);
    struct dsc s = {RAM_BASE + CTL_TX_OFF + slot * 0x20u, 8, 0};
    desc_put(f, qdesc(3), slot, &s, 0);
    avail_post(f, 3, slot);
    WR(d, RVVIRTIO_REG_QUEUE_NOTIFY, 3);
}

/* Control message k delivered on the control receiveq. */
static bool ctl_msg(const struct fx *f, unsigned k, uint32_t *id, uint16_t *ev,
                    uint16_t *val, char *name, uint32_t *len)
{
    if (k >= used_idx(f, 2))
        return false;
    uint32_t head = used_id(f, 2, k % QN);
    uint64_t o = CTL_RX_OFF + head * 0x100u;
    *id = get32(f, o);
    *ev = get16(f, o + 4);
    *val = get16(f, o + 6);
    *len = used_len(f, 2, k % QN);
    memset(name, 0, 33);
    if (*len > 8)
        memcpy(name, f->ram + o + 8, *len - 8);
    return true;
}

static void rx_post(struct fx *f, unsigned qi, unsigned slot, uint32_t len)
{
    struct dsc s = {RAM_BASE + RXBUF_OFF + qi * 0x800u + slot * 0x80u, len, 2};
    desc_put(f, qdesc(qi), slot, &s, 0);
    avail_post(f, qi, slot);
}

static uint8_t *rx_ptr(struct fx *f, unsigned qi, unsigned slot)
{
    return f->ram + RXBUF_OFF + qi * 0x800u + slot * 0x80u;
}

static void tx_data(struct fx *f, unsigned qi, const void *data, uint32_t len)
{
    unsigned slot = get16(f, qavail(qi) + 2) % QN;
    memcpy(f->ram + TXBUF_OFF + slot * 0x40u, data, len);
    struct dsc s = {RAM_BASE + TXBUF_OFF + slot * 0x40u, len, 0};
    desc_put(f, qdesc(qi), slot, &s, 0);
    avail_post(f, qi, slot);
}

static void sink_reset(size_t quota)
{
    memset(&g_sink, 0, sizeof(g_sink));
    g_sink.quota = quota;
}

/* Negotiate and configure every queue, stopping short of DRIVER_OK. */
static bool con_setup(struct fx *f, struct rvvirtio_console *c, uint32_t nports)
{
    struct rvvirtio_mem mem = fx_mem(f);
    struct rvvirtio_console_ops ops = {NULL, sink_from_guest, sink_writable};
    fx_reset(f);
    sink_reset(SIZE_MAX);
    if (!g_capi->init(c, &mem, &ops, nports))
        return false;
    g_sink.c = c;
    drv_negotiate(&c->dev, ~UINT64_C(0));
    for (unsigned q = 0; q < 2u * (nports + 1u); q++)
        drv_queue(&c->dev, q, QN);
    return true;
}

static void con_post_ctl_rx(struct fx *f)
{
    for (unsigned s = 0; s < 8; s++) {
        struct dsc d = {RAM_BASE + CTL_RX_OFF + s * 0x100u, 64, 2};
        desc_put(f, qdesc(2), s, &d, 0);
        avail_post(f, 2, s);
    }
}

/* Bring a console up through the DEVICE_READY handshake. */
static bool con_up(struct fx *f, struct rvvirtio_console *c, uint32_t nports)
{
    if (!con_setup(f, c, nports))
        return false;
    drv_ok(&c->dev);
    con_post_ctl_rx(f);
    return (RD(&c->dev, RVVIRTIO_REG_STATUS) & RVVIRTIO_STATUS_DRIVER_OK) != 0;
}

/* Handshake + guest opens `port` (named "ssh"); returns once both ends are open. */
static bool con_open_port1(struct fx *f, struct rvvirtio_console *c)
{
    if (!con_up(f, c, 3) || !g_capi->open(c, 1, "ssh"))
        return false;
    ctl_send(f, &c->dev, 0, 0, 1);      /* DEVICE_READY */
    ctl_send(f, &c->dev, 1, 3, 1);      /* PORT_READY */
    ctl_send(f, &c->dev, 1, 6, 1);      /* PORT_OPEN */
    return !is_reset(&c->dev);
}

static int t_console_handshake(void)
{
    int failures = 0;
    TEST("rvvirtio: console multiport handshake, named port, unknown ports") {
        static struct fx f;
        static struct rvvirtio_console c;
        uint32_t id, len;
        uint16_t ev, val;
        char name[33];
        g_capi = &k_creal;
        CHK(con_up(&f, &c, 3));
        CHK_EQ(RD(&c.dev, RVVIRTIO_REG_DEVICE_ID), 3u);
        CHK_EQ(RD(&c.dev, RVVIRTIO_REG_CONFIG + 4), 3u); /* max_nr_ports */
        WR(&c.dev, RVVIRTIO_REG_DEVICE_FEATURES_SEL, 0);
        CHK((RD(&c.dev, RVVIRTIO_REG_DEVICE_FEATURES) & 2u) != 0); /* MULTIPORT */
        CHK(!g_capi->open(&c, 3, "x"));   /* out of range */
        CHK(!g_capi->open(&c, 99, NULL));
        CHK(g_capi->open(&c, 1, "ssh"));
        CHK(!g_capi->open(&c, 1, "ssh")); /* already open */
        CHK_EQ(g_capi->gen(&c, 1), 1u);
        CHK_EQ(g_capi->gen(&c, 7), 0u);
        CHK_EQ(used_idx(&f, 2), 0u); /* nothing before DEVICE_READY */
        ctl_send(&f, &c.dev, 0, 0, 1);
        CHK_EQ(used_idx(&f, 3), 1u);
        CHK_EQ(used_idx(&f, 2), 3u); /* DEVICE_ADD x3 */
        for (unsigned p = 0; p < 3; p++) {
            CHK(ctl_msg(&f, p, &id, &ev, &val, name, &len));
            CHK_EQ(id, p);
            CHK_EQ(ev, 1u);
            CHK_EQ(len, 8u);
        }
        ctl_send(&f, &c.dev, 1, 3, 1); /* PORT_READY(1) -> PORT_NAME, PORT_OPEN */
        CHK_EQ(used_idx(&f, 2), 5u);
        CHK(ctl_msg(&f, 3, &id, &ev, &val, name, &len));
        CHK(id == 1u && ev == 7u && len == 11u && strcmp(name, "ssh") == 0);
        CHK(ctl_msg(&f, 4, &id, &ev, &val, name, &len));
        CHK(id == 1u && ev == 6u && val == 1u);
        /* unknown port, unknown event, short message: ignored, defined */
        unsigned before = used_idx(&f, 2);
        ctl_send(&f, &c.dev, 9, 3, 1);
        ctl_send(&f, &c.dev, 1, 99, 1);
        ctl_send(&f, &c.dev, 0xffffffffu, 6, 1);
        CHK_EQ(used_idx(&f, 2), before);
        CHK_EQ(used_idx(&f, 3), 5u);
        CHK(!is_reset(&c.dev));
        /* console-type port 0 announces CONSOLE_PORT */
        CHK(g_capi->open(&c, 0, NULL));
        ctl_send(&f, &c.dev, 0, 3, 1);
        CHK(ctl_msg(&f, 5, &id, &ev, &val, name, &len));
        CHK(id == 0u && ev == 4u);
        CHK(guards_ok(&f));
        PASS();
    } _test_next:;
    return failures;
}

/* The FreeBSD driver posts its control receive buffers, notifies, sends
 * DEVICE_READY and polls for its completion, all inside attach and before the
 * transport sets DRIVER_OK. */
static int t_console_ready_before_driver_ok(void)
{
    int failures = 0;
    TEST("rvvirtio: console DEVICE_READY completes before DRIVER_OK, PORT_ADD follows it") {
        static struct fx f;
        static struct rvvirtio_console c;
        uint32_t id, len;
        uint16_t ev, val;
        char name[33];
        g_capi = &k_creal;
        CHK(con_setup(&f, &c, 2));
        CHK(g_capi->open(&c, 1, "ssh"));
        con_post_ctl_rx(&f);
        WR(&c.dev, RVVIRTIO_REG_QUEUE_NOTIFY, 2);
        CHK_EQ(used_idx(&f, 2), 0u);
        ctl_send(&f, &c.dev, 0xffffffffu, 0, 1); /* DEVICE_READY */
        CHK_EQ(used_idx(&f, 3), 1u);
        CHK_EQ(used_idx(&f, 2), 0u); /* the receive side waits for DRIVER_OK */
        CHK(!is_reset(&c.dev));
        drv_ok(&c.dev);
        CHK_EQ(used_idx(&f, 2), 2u);
        for (unsigned p = 0; p < 2; p++) {
            CHK(ctl_msg(&f, p, &id, &ev, &val, name, &len));
            CHK(id == p && ev == 1u && len == 8u);
        }
        CHK(guards_ok(&f));
        PASS();
    } _test_next:;
    return failures;
}

static int t_console_early_other_queue(void)
{
    int failures = 0;
    TEST("rvvirtio: console serves no queue but the control transmit queue before DRIVER_OK") {
        static struct fx f;
        static struct rvvirtio_console c;
        g_capi = &k_creal;
        CHK(con_setup(&f, &c, 2));
        tx_data(&f, 1, "x", 1);
        WR(&c.dev, RVVIRTIO_REG_QUEUE_NOTIFY, 1);
        CHK_EQ(used_idx(&f, 1), 0u);
        CHK(!is_reset(&c.dev));
        CHK(guards_ok(&f));
        PASS();
    } _test_next:;
    return failures;
}

static int t_console_early_queue_not_ready(void)
{
    int failures = 0;
    TEST("rvvirtio: console control transmit notify with QueueReady clear is ignored") {
        static struct fx f;
        static struct rvvirtio_console c;
        g_capi = &k_creal;
        CHK(con_setup(&f, &c, 2));
        WR(&c.dev, RVVIRTIO_REG_QUEUE_SEL, 3);
        WR(&c.dev, RVVIRTIO_REG_QUEUE_READY, 0);
        ctl_send(&f, &c.dev, 0xffffffffu, 0, 1);
        CHK_EQ(used_idx(&f, 3), 0u);
        CHK(!is_reset(&c.dev));
        CHK(guards_ok(&f));
        PASS();
    } _test_next:;
    return failures;
}

static int t_console_early_without_features_ok(void)
{
    int failures = 0;
    TEST("rvvirtio: console control transmit notify before FEATURES_OK is ignored") {
        static struct fx f;
        static struct rvvirtio_console c;
        g_capi = &k_creal;
        CHK(con_setup(&f, &c, 2));
        WR(&c.dev, RVVIRTIO_REG_STATUS, 0);
        WR(&c.dev, RVVIRTIO_REG_STATUS, RVVIRTIO_STATUS_ACKNOWLEDGE);
        WR(&c.dev, RVVIRTIO_REG_STATUS,
           RVVIRTIO_STATUS_ACKNOWLEDGE | RVVIRTIO_STATUS_DRIVER);
        for (unsigned q = 0; q < 6u; q++)
            drv_queue(&c.dev, q, QN);
        CHK_EQ(RD(&c.dev, RVVIRTIO_REG_STATUS) & RVVIRTIO_STATUS_FEATURES_OK, 0u);
        ctl_send(&f, &c.dev, 0xffffffffu, 0, 1);
        CHK_EQ(used_idx(&f, 3), 0u);
        CHK(!is_reset(&c.dev));
        CHK(guards_ok(&f));
        PASS();
    } _test_next:;
    return failures;
}

static int t_console_early_after_reset(void)
{
    int failures = 0;
    TEST("rvvirtio: console reset after an early DEVICE_READY forgets it; PORT_ADD is sent once") {
        static struct fx f;
        static struct rvvirtio_console c;
        g_capi = &k_creal;
        CHK(con_setup(&f, &c, 2));
        CHK(g_capi->open(&c, 1, "ssh"));
        con_post_ctl_rx(&f);
        ctl_send(&f, &c.dev, 0xffffffffu, 0, 1);
        CHK_EQ(used_idx(&f, 3), 1u);
        WR(&c.dev, RVVIRTIO_REG_STATUS, 0);
        ctl_send(&f, &c.dev, 0xffffffffu, 0, 1); /* queue no longer ready */
        CHK_EQ(used_idx(&f, 3), 1u);
        CHK(!is_reset(&c.dev));
        fx_reset(&f);
        drv_negotiate(&c.dev, ~UINT64_C(0));
        for (unsigned q = 0; q < 6u; q++)
            drv_queue(&c.dev, q, QN);
        con_post_ctl_rx(&f);
        drv_ok(&c.dev);
        CHK_EQ(used_idx(&f, 2), 0u); /* nothing owed until DEVICE_READY */
        ctl_send(&f, &c.dev, 0xffffffffu, 0, 1);
        CHK_EQ(used_idx(&f, 2), 2u);
        CHK(!is_reset(&c.dev));
        CHK(guards_ok(&f));
        PASS();
    } _test_next:;
    return failures;
}

static int t_console_early_after_needs_reset(void)
{
    int failures = 0;
    TEST("rvvirtio: console control transmit notify after NEEDS_RESET is ignored") {
        static struct fx f;
        static struct rvvirtio_console c;
        g_capi = &k_creal;
        CHK(con_setup(&f, &c, 2));
        rvvirtio_dev_fail(&c.dev);
        CHK(is_reset(&c.dev));
        ctl_send(&f, &c.dev, 0xffffffffu, 0, 1);
        CHK_EQ(used_idx(&f, 3), 0u);
        CHK(is_reset(&c.dev));
        CHK(guards_ok(&f));
        PASS();
    } _test_next:;
    return failures;
}

static int t_console_data(void)
{
    int failures = 0;
    TEST("rvvirtio: console bytes both ways, partial acceptance, stop and resume") {
        static struct fx f;
        static struct rvvirtio_console c;
        uint8_t src[40], got[40];
        g_capi = &k_creal;
        for (unsigned i = 0; i < sizeof(src); i++)
            src[i] = (uint8_t)('A' + i);
        CHK(con_open_port1(&f, &c));
        /* host to guest, small write across two 8-byte buffers */
        rx_post(&f, 4, 0, 8);
        rx_post(&f, 4, 1, 8);
        CHK_EQ(g_capi->write(&c, 1, src, 10), 10u);
        CHK_EQ(used_len(&f, 4, 0), 8u);
        CHK_EQ(used_len(&f, 4, 1), 2u);
        memcpy(got, rx_ptr(&f, 4, 0), 8);
        memcpy(got + 8, rx_ptr(&f, 4, 1), 2);
        /* partial: 6 bytes of room, 12 offered; the caller keeps the suffix */
        rx_post(&f, 4, 2, 6);
        size_t acc = g_capi->write(&c, 1, src + 10, 12);
        CHK_EQ(acc, 6u);
        memcpy(got + 10, rx_ptr(&f, 4, 2), 6);
        /* retry the suffix once more room is posted: no loss, no duplication */
        rx_post(&f, 4, 3, 64);
        CHK_EQ(g_capi->write(&c, 1, src + 10 + acc, 12 - acc), 12 - acc);
        memcpy(got + 16, rx_ptr(&f, 4, 3), 6);
        CHK(memcmp(got, src, 22) == 0);
        /* guest to host, fully accepted */
        tx_data(&f, 5, "hello", 5);
        WR(&c.dev, RVVIRTIO_REG_QUEUE_NOTIFY, 5);
        CHK(g_sink.n == 5u && memcmp(g_sink.got, "hello", 5) == 0);
        CHK_EQ(used_idx(&f, 5), 1u);
        /* guest to host, partial: sink takes 5 of 12, port stops */
        g_sink.quota = 5;
        tx_data(&f, 5, "0123456789AB", 12);
        tx_data(&f, 5, "next", 4);
        WR(&c.dev, RVVIRTIO_REG_QUEUE_NOTIFY, 5);
        CHK_EQ(g_sink.n, 10u);
        CHK_EQ(used_idx(&f, 5), 1u); /* chain left in the guest's hands */
        unsigned calls = g_sink.calls;
        WR(&c.dev, RVVIRTIO_REG_QUEUE_NOTIFY, 5); /* stopped: nothing consumed */
        CHK_EQ(g_sink.calls, calls);
        g_sink.quota = SIZE_MAX;
        g_capi->resume(&c, 1);
        CHK_EQ(used_idx(&f, 5), 3u);
        CHK(g_sink.n == 21u);
        CHK(memcmp(g_sink.got, "hello0123456789ABnext", 21) == 0);
        CHK_EQ(g_sink.reentry_bad, 0u);
        CHK(!is_reset(&c.dev));
        CHK(guards_ok(&f));
        PASS();
    } _test_next:;
    return failures;
}

static int t_console_writable_consumed(void)
{
    int failures = 0;
    TEST("rvvirtio: console writable fires once per stall; consumed is exact") {
        static struct fx f;
        static struct rvvirtio_console c;
        uint8_t src[64];
        g_capi = &k_creal;
        memset(src, 0x31, sizeof(src));
        CHK(con_open_port1(&f, &c));
        /* guest never supplied buffers: 0 accepted, guest memory flat */
        f.writes = 0;
        CHK_EQ(g_capi->write(&c, 1, src, 10), 0u);
        CHK_EQ(f.writes, 0u);
        CHK_EQ(g_sink.writable_calls, 0u); /* never from inside port_write */
        WR(&c.dev, RVVIRTIO_REG_QUEUE_NOTIFY, 4); /* kick with no buffer */
        CHK_EQ(g_sink.writable_calls, 0u);      /* no invented capacity */
        rx_post(&f, 4, 0, 32);
        WR(&c.dev, RVVIRTIO_REG_QUEUE_NOTIFY, 4);
        CHK_EQ(g_sink.writable_calls, 1u);
        CHK_EQ(g_sink.writable_port, 1u);
        WR(&c.dev, RVVIRTIO_REG_QUEUE_NOTIFY, 4);
        CHK_EQ(g_sink.writable_calls, 1u); /* once per stall */
        CHK_EQ(g_capi->write(&c, 1, src, 10), 10u);
        CHK_EQ(g_sink.writable_calls, 1u);
        /* a fully accepted write leaves no stall behind */
        rx_post(&f, 4, 1, 32);
        WR(&c.dev, RVVIRTIO_REG_QUEUE_NOTIFY, 4);
        CHK_EQ(g_sink.writable_calls, 1u);
        /* consumed: delivered bytes count only after the buffer is re-posted */
        CHK_EQ(g_capi->consumed(&c, 1), 0u);
        avail_post(&f, 4, 0); /* guest re-posts buffer 0 (held 10 bytes) */
        CHK_EQ(g_capi->consumed(&c, 1), 10u);
        CHK_EQ(g_capi->consumed(&c, 1), 10u); /* idempotent */
        /* 32 + 8 across two buffers; consumed follows each re-post exactly */
        CHK_EQ(g_capi->write(&c, 1, src, 40), 40u);
        CHK_EQ(g_capi->consumed(&c, 1), 10u);
        avail_post(&f, 4, 1);
        CHK_EQ(g_capi->consumed(&c, 1), 10u + 32u);
        avail_post(&f, 4, 0);
        CHK_EQ(g_capi->consumed(&c, 1), 10u + 40u);
        CHK(g_capi->consumed(&c, 1) <= 10u + 40u);
        CHK_EQ(g_capi->consumed(&c, 9), 0u);
        CHK_EQ(g_sink.reentry_bad, 0u);
        CHK(guards_ok(&f));
        PASS();
    } _test_next:;
    return failures;
}

static int t_console_close_reset(void)
{
    int failures = 0;
    TEST("rvvirtio: console close with data pending, generations, guest reset") {
        static struct fx f;
        static struct rvvirtio_console c;
        uint32_t id, len;
        uint16_t ev, val;
        char name[33];
        g_capi = &k_creal;
        CHK(con_open_port1(&f, &c));
        uint32_t g1 = g_capi->gen(&c, 1);
        g_sink.quota = 3;
        tx_data(&f, 5, "abcdefgh", 8);
        tx_data(&f, 5, "ijkl", 4);
        WR(&c.dev, RVVIRTIO_REG_QUEUE_NOTIFY, 5);
        CHK_EQ(g_sink.n, 3u);
        CHK_EQ(used_idx(&f, 5), 0u);
        unsigned msgs = used_idx(&f, 2);
        g_capi->close(&c, 1);
        CHK(g_capi->gen(&c, 1) != g1);
        CHK_EQ(used_idx(&f, 5), 2u); /* pending chains released, not wedged */
        CHK_EQ(g_sink.n, 3u);        /* and never delivered after close */
        CHK(ctl_msg(&f, msgs, &id, &ev, &val, name, &len));
        CHK(id == 1u && ev == 6u && val == 0u); /* PORT_OPEN 0 */
        uint8_t z = 'q';
        rx_post(&f, 4, 0, 16);
        CHK_EQ(g_capi->write(&c, 1, &z, 1), 0u);
        g_capi->close(&c, 1); /* second close: no effect */
        uint32_t g2 = g_capi->gen(&c, 1);
        CHK(g2 != g1);
        CHK(g_capi->open(&c, 1, "ssh"));
        uint32_t g3 = g_capi->gen(&c, 1);
        CHK(g3 != g2 && g3 != g1);
        /* a guest reset ends the session: generation moves, state re-arms */
        ctl_send(&f, &c.dev, 1, 6, 1);
        uint32_t g4 = g_capi->gen(&c, 1);
        WR(&c.dev, RVVIRTIO_REG_STATUS, 0);
        CHK(g_capi->gen(&c, 1) != g4);
        CHK(!is_reset(&c.dev));
        CHK_EQ(g_capi->write(&c, 1, &z, 1), 0u); /* not running */
        CHK(guards_ok(&f));
        PASS();
    } _test_next:;
    return failures;
}

/* Partial acceptance end to end; also the red twin's probe. Returns the bytes
 * the sink holds after a stop and a resume (12 expected, nothing lost). */
static size_t run_partial_case(struct fx *f)
{
    static struct rvvirtio_console c;
    if (!con_open_port1(f, &c))
        return 0;
    g_sink.quota = 5;
    tx_data(f, 5, "0123456789AB", 12);
    WR(&c.dev, RVVIRTIO_REG_QUEUE_NOTIFY, 5);
    g_sink.quota = SIZE_MAX;
    g_capi->resume(&c, 1);
    return g_sink.n;
}

static int t_console_twin(void)
{
    int failures = 0;
    TEST("rvvirtio: console twin (partial-acceptance suffix dropped) is caught") {
        static struct fx f;
        g_capi = &k_creal;
        size_t good = run_partial_case(&f);
        bool exact = g_sink.n == 12u && memcmp(g_sink.got, "0123456789AB", 12) == 0;
        CHK(exact);
        g_capi = &k_cmut;
        size_t bad = run_partial_case(&f);
        bool lost = bad != 12u;
        g_capi = &k_creal;
        printf("\n    rvvirtio twin console-suffix: real bytes=%zu, twin bytes=%zu of 12 -> %s\n",
               good, bad, lost ? "DETECTED" : "MISSED");
        CHK_EQ(good, 12u);
        CHK(lost);
        PASS();
    } _test_next:;
    return failures;
}

/* ---- 10. FreeBSD 15.1 vtbd driver shape, bounded requests, notify cap ----
 *
 * The bring-up below repeats the order of the FreeBSD virtio_mmio and
 * virtio_blk drivers (sys/dev/virtio/mmio/virtio_mmio.c vtmmio_attach,
 * vtmmio_negotiate_features, vtmmio_finalize_features, vtmmio_set_virtqueue,
 * vtmmio_probe_and_attach_child; sys/dev/virtio/block/virtio_blk.c
 * vtblk_attach), with a 256-entry queue laid out as vring_size() does. */
#define F_QN 256u
#define F_AVAIL 0x1000u
#define F_USED 0x2000u
#define BLK_F_SIZE_MAX (UINT64_C(1) << 1)
#define BLK_F_SEG_MAX (UINT64_C(1) << 2)
#define BLK_F_GEOMETRY (UINT64_C(1) << 4)
#define BLK_F_RO (UINT64_C(1) << 5)
#define BLK_F_BLK_SIZE (UINT64_C(1) << 6)
#define BLK_F_FLUSH (UINT64_C(1) << 9)
#define BLK_F_TOPOLOGY (UINT64_C(1) << 10)
#define BLK_F_CONFIG_WCE (UINT64_C(1) << 11)
#define BLK_F_DISCARD (UINT64_C(1) << 13)
#define RING_F_EVENT_IDX (UINT64_C(1) << 29)
#define FBSD_PAGE 4096u
#define FBSD_MAXSIZE ((128u - 2u - 1u) * FBSD_PAGE) /* virtio_blk.c:795-798 */
#define SYNTH_STOP 5000u /* the backend fails after this many callbacks */

/* A backend with no storage that counts callbacks and cuts a runaway short. */
struct synth {
    uint64_t size;
    unsigned calls, preads, pwrites, flushes, stop_after;
};

static uint64_t synth_size(void *ctx) { return ((struct synth *)ctx)->size; }

static bool synth_pread(void *ctx, uint64_t off, void *buf, size_t n)
{
    struct synth *s = ctx;
    (void)off;
    s->calls++;
    s->preads++;
    if (s->stop_after != 0 && s->calls > s->stop_after)
        return false;
    memset(buf, 0xc3, n);
    return true;
}

static bool synth_pwrite(void *ctx, uint64_t off, const void *buf, size_t n)
{
    struct synth *s = ctx;
    (void)off;
    (void)buf;
    (void)n;
    s->calls++;
    s->pwrites++;
    return s->stop_after == 0 || s->calls <= s->stop_after;
}

static bool synth_flush(void *ctx)
{
    struct synth *s = ctx;
    s->flushes++;
    return true;
}

static void synth_init(struct synth *s, uint64_t size)
{
    memset(s, 0, sizeof(*s));
    s->size = size;
    s->stop_after = SYNTH_STOP;
}

static uint16_t f_used_idx(const struct fx *f) { return get16(f, F_USED + 2); }
static uint32_t f_used_len(const struct fx *f, unsigned i)
{
    return get32(f, F_USED + 4 + 8u * (i % F_QN) + 4u);
}

static void f_avail_post(struct fx *f, unsigned head)
{
    uint16_t idx = get16(f, F_AVAIL + 2);
    put16(f, F_AVAIL + 4 + 2u * (idx % F_QN), (uint16_t)head);
    put16(f, F_AVAIL + 2, (uint16_t)(idx + 1u));
}

/* vtmmio_set_status: read the status, OR the bit in, write it back. */
static void fb_set_status(struct rvvirtio_dev *d, uint32_t bit)
{
    WR(d, RVVIRTIO_REG_STATUS, RD(d, RVVIRTIO_REG_STATUS) | bit);
}

/* vtmmio_read_dev_config_8 (virtio_mmio.c:739-755): generation-guarded. */
static uint64_t fb_config8(struct rvvirtio_dev *d, uint64_t off)
{
    uint32_t gen, lo, hi;
    do {
        gen = RD(d, RVVIRTIO_REG_CONFIG_GENERATION);
        lo = RD(d, RVVIRTIO_REG_CONFIG + off);
        hi = RD(d, RVVIRTIO_REG_CONFIG + off + 4);
    } while (gen != RD(d, RVVIRTIO_REG_CONFIG_GENERATION));
    return ((uint64_t)hi << 32) | lo;
}

struct fb_seen {
    uint64_t host, negotiated, capacity;
    uint32_t seg_max, blk_size;
};

#define FB(cond) do { g_checks++; if (!(cond)) return false; } while (0)

/* Probe, attach and DRIVER_OK exactly as the FreeBSD drivers do. */
static bool fb_bringup(struct fx *f, struct rvvirtio_blk *b, struct synth *s,
                       bool read_only, struct fb_seen *seen)
{
    struct rvvirtio_mem mem = fx_mem(f);
    struct rvvirtio_blk_backend be = {s, synth_size, synth_pread, synth_pwrite,
                                      synth_flush, "z23-synth-disk"};
    if (!g_api->blk_init(b, &mem, &be, read_only))
        return false;
    struct rvvirtio_dev *d = &b->dev;
    /* vtmmio_probe (virtio_mmio.c:172-189) */
    FB((RD(d, RVVIRTIO_REG_MAGIC)) == (0x74726976u));
    uint32_t version = RD(d, RVVIRTIO_REG_VERSION);
    FB(version >= 1u && version <= 2u);
    FB((version) == (2u));
    FB((RD(d, RVVIRTIO_REG_DEVICE_ID)) == (RVVIRTIO_DEVICE_ID_BLOCK));
    /* vtmmio_attach (223-258): reset, ACK; probe_and_attach_child: DRIVER */
    WR(d, RVVIRTIO_REG_STATUS, 0);
    FB((RD(d, RVVIRTIO_REG_STATUS)) == (0u));
    fb_set_status(d, RVVIRTIO_STATUS_ACKNOWLEDGE);
    fb_set_status(d, RVVIRTIO_STATUS_DRIVER);
    /* vtmmio_negotiate_features (392-429): select 1 then 0, in that order */
    WR(d, RVVIRTIO_REG_DEVICE_FEATURES_SEL, 1);
    uint64_t host = (uint64_t)RD(d, RVVIRTIO_REG_DEVICE_FEATURES) << 32;
    WR(d, RVVIRTIO_REG_DEVICE_FEATURES_SEL, 0);
    host |= RD(d, RVVIRTIO_REG_DEVICE_FEATURES);
    const uint64_t child = BLK_F_SIZE_MAX | BLK_F_SEG_MAX | BLK_F_GEOMETRY |
                           BLK_F_RO | BLK_F_BLK_SIZE | BLK_F_FLUSH |
                           BLK_F_TOPOLOGY | BLK_F_CONFIG_WCE | BLK_F_DISCARD |
                           RVVIRTIO_F_INDIRECT_DESC | RING_F_EVENT_IDX |
                           RVVIRTIO_F_VERSION_1;
    uint64_t feat = host & child; /* virtio_filter_transport_features keeps these */
    WR(d, RVVIRTIO_REG_DRIVER_FEATURES_SEL, 1);
    WR(d, RVVIRTIO_REG_DRIVER_FEATURES, (uint32_t)(feat >> 32));
    WR(d, RVVIRTIO_REG_DRIVER_FEATURES_SEL, 0);
    WR(d, RVVIRTIO_REG_DRIVER_FEATURES, (uint32_t)feat);
    /* vtmmio_finalize_features (432-454): FEATURES_OK must read back set */
    fb_set_status(d, RVVIRTIO_STATUS_FEATURES_OK);
    FB((RD(d, RVVIRTIO_REG_STATUS) & RVVIRTIO_STATUS_FEATURES_OK) != 0);
    /* vtblk_read_config (1354-1390): capacity, then only negotiated fields */
    struct fb_seen sv = {host, feat, fb_config8(d, 0), 0, 0};
    if ((feat & BLK_F_SEG_MAX) != 0)
        sv.seg_max = RD(d, RVVIRTIO_REG_CONFIG + 12);
    if ((feat & BLK_F_BLK_SIZE) != 0)
        sv.blk_size = RD(d, RVVIRTIO_REG_CONFIG + 20);
    /* vtmmio_alloc_virtqueues / vtmmio_set_virtqueue (504-501): size is the
     * NUM_MAX value; DESC, AVAIL, USED, then READY last. */
    WR(d, RVVIRTIO_REG_QUEUE_SEL, 0);
    uint32_t size = RD(d, RVVIRTIO_REG_QUEUE_NUM_MAX);
    FB((size) == (F_QN));
    FB((size & (size - 1u)) == 0u); /* virtqueue.c:167 powerof2 */
    WR(d, RVVIRTIO_REG_QUEUE_NUM, size);
    uint64_t desc = RAM_BASE, avail = RAM_BASE + F_AVAIL, used = RAM_BASE + F_USED;
    WR(d, RVVIRTIO_REG_QUEUE_DESC_LOW, (uint32_t)desc);
    WR(d, RVVIRTIO_REG_QUEUE_DESC_HIGH, (uint32_t)(desc >> 32));
    WR(d, RVVIRTIO_REG_QUEUE_DRIVER_LOW, (uint32_t)avail);
    WR(d, RVVIRTIO_REG_QUEUE_DRIVER_HIGH, (uint32_t)(avail >> 32));
    WR(d, RVVIRTIO_REG_QUEUE_DEVICE_LOW, (uint32_t)used);
    WR(d, RVVIRTIO_REG_QUEUE_DEVICE_HIGH, (uint32_t)(used >> 32));
    WR(d, RVVIRTIO_REG_QUEUE_READY, 1);
    FB((RD(d, RVVIRTIO_REG_QUEUE_READY)) == (1u));
    FB(!is_reset(d));
    /* vtmmio_probe_and_attach_child (859): DRIVER_OK last */
    fb_set_status(d, RVVIRTIO_STATUS_DRIVER_OK);
    FB(RD(d, RVVIRTIO_REG_STATUS) ==
       (RVVIRTIO_STATUS_ACKNOWLEDGE | RVVIRTIO_STATUS_DRIVER |
        RVVIRTIO_STATUS_FEATURES_OK | RVVIRTIO_STATUS_DRIVER_OK));
    if (seen != NULL)
        *seen = sv;
    return true;
}

struct seg {
    uint64_t addr;
    uint32_t len;
    bool write;
};

/* One request as the FreeBSD driver enqueues it with indirect descriptors
 * (virtqueue.c:751-785): the ring head is a single INDIRECT descriptor naming
 * a table of segs[0..n). The table sits at table_off; segs may be shared by
 * many heads. */
static void f_table(struct fx *f, uint64_t table_off, const struct seg *segs,
                    unsigned n)
{
    for (unsigned i = 0; i < n; i++) {
        uint64_t o = table_off + 16u * i;
        put64(f, o, segs[i].addr);
        put32(f, o + 8, segs[i].len);
        put16(f, o + 12, (uint16_t)((segs[i].write ? 2u : 0u) | (i + 1u < n ? 1u : 0u)));
        put16(f, o + 14, (uint16_t)(i + 1u));
    }
}

static void f_head(struct fx *f, unsigned head, uint64_t table_off, unsigned n)
{
    struct dsc ind = {RAM_BASE + table_off, 16u * n, 4};
    desc_put(f, 0, head, &ind, 0);
}

/* hdr + `ndata` data segments + status, all but the data in real RAM. */
#define F_TABLE_MAX 260u
static unsigned f_build(struct seg *s, const uint32_t *lens, unsigned ndata,
                        uint64_t data_gpa, bool dev_writes)
{
    unsigned n = 0;
    s[n++] = (struct seg){RAM_BASE + OFF_HDR, 16, false};
    for (unsigned i = 0; i < ndata; i++)
        s[n++] = (struct seg){data_gpa, lens[i], dev_writes};
    s[n++] = (struct seg){RAM_BASE + OFF_STATUS, 1, true};
    return n;
}

static void f_request(struct fx *f, struct rvvirtio_dev *d, unsigned head,
                      uint32_t type, uint64_t sector, const uint32_t *lens,
                      unsigned ndata, uint64_t data_gpa, bool dev_writes)
{
    struct seg s[F_TABLE_MAX];
    unsigned n = f_build(s, lens, ndata, data_gpa, dev_writes);
    put_hdr(f, type, sector);
    f->ram[OFF_STATUS] = 0xee;
    f_table(f, OFF_DATA2, s, n);
    f_head(f, head, OFF_DATA2, n);
    f_avail_post(f, head);
    WR(d, RVVIRTIO_REG_QUEUE_NOTIFY, 0);
}

#define AP_GPA (RAM_BASE + APERTURE_OFF)

/* The reviewer's request: 254 data segments of 32-bit length summing to
 * `total`, every one aliased to the aperture. */
static unsigned huge_lens(uint32_t *lens, uint64_t total)
{
    unsigned n = 0;
    uint64_t left = total;
    while (left != 0 && n < 254u) {
        uint64_t cap = n < 253u ? UINT64_C(0x01000000) : (uint64_t)UINT32_MAX;
        uint64_t take = left < cap ? left : cap;
        lens[n++] = (uint32_t)take;
        left -= take;
    }
    return n;
}

struct bound_probe {
    unsigned in_calls, out_calls, callbacks_after_legit;
    uint8_t in_status, out_status;
    uint32_t in_used, out_used;
    bool reset_seen, device_usable;
    uint64_t aperture_bytes;
};

/* Runs the oversized IN and OUT through the real queue and registers. */
static struct bound_probe run_bound_case(struct fx *f, uint64_t total)
{
    static struct rvvirtio_blk b;
    static struct synth s;
    struct bound_probe p;
    memset(&p, 0, sizeof(p));
    fx_reset(f);
    f->aperture = true;
    synth_init(&s, UINT64_C(16) << 30);
    if (!fb_bringup(f, &b, &s, false, NULL))
        return p;
    struct rvvirtio_dev *d = &b.dev;
    uint32_t lens[256];
    unsigned n = huge_lens(lens, total);
    f_request(f, d, 0, RVVIRTIO_BLK_T_IN, 0, lens, n, AP_GPA, true);
    p.in_calls = s.calls;
    p.in_status = f->ram[OFF_STATUS];
    p.in_used = f_used_len(f, 0);
    s.calls = 0;
    f_request(f, d, 1, RVVIRTIO_BLK_T_OUT, 0, lens, n, AP_GPA, false);
    p.out_calls = s.calls;
    p.out_status = f->ram[OFF_STATUS];
    p.out_used = f_used_len(f, 1);
    p.reset_seen = is_reset(d);
    p.aperture_bytes = f->aperture_bytes;
    /* the device must still serve a legitimate request afterwards */
    s.calls = 0;
    uint32_t one = 4096;
    f_request(f, d, 2, RVVIRTIO_BLK_T_IN, 8, &one, 1, RAM_BASE + OFF_DATA, true);
    p.device_usable = !is_reset(d) && f->ram[OFF_STATUS] == RVVIRTIO_BLK_S_OK &&
                      s.calls == 1u && f_used_idx(f) == 3u &&
                      f_used_len(f, 2) == 4097u;
    p.callbacks_after_legit = s.calls;
    return p;
}

static int t_freebsd_attach_sequence(void)
{
    int failures = 0;
    TEST("rvvirtio: FreeBSD vtbd attach sequence (probe, features, config, queue, DRIVER_OK, GET_ID)") {
        static struct fx f;
        static struct rvvirtio_blk b;
        static struct synth s;
        struct fb_seen seen;
        fx_reset(&f);
        f.aperture = true;
        synth_init(&s, UINT64_C(1) << 30);
        CHK(fb_bringup(&f, &b, &s, false, &seen));
        struct rvvirtio_dev *d = &b.dev;
        /* vtblk_setup_features: what the driver ends up with */
        CHK((seen.negotiated & RVVIRTIO_F_VERSION_1) != 0);
        CHK((seen.negotiated & RVVIRTIO_F_INDIRECT_DESC) != 0);
        CHK((seen.negotiated & BLK_F_SEG_MAX) != 0);
        CHK((seen.negotiated & BLK_F_BLK_SIZE) != 0);
        CHK((seen.negotiated & BLK_F_FLUSH) != 0);
        CHK((seen.negotiated & BLK_F_RO) == 0);
        /* size_max < maxphys makes attach fail (virtio_blk.c:346-352); the
         * others would make the driver read config fields the model lacks. */
        CHK((seen.host & (BLK_F_SIZE_MAX | BLK_F_GEOMETRY | BLK_F_TOPOLOGY |
                          BLK_F_CONFIG_WCE | BLK_F_DISCARD | RING_F_EVENT_IDX)) == 0);
        CHK_EQ(seen.capacity, (UINT64_C(1) << 30) / 512u);
        CHK_EQ(seen.blk_size, 512u);
        CHK_EQ(seen.seg_max, RVVIRTIO_BLK_DATA_SEGS_MAX);
        /* vtmmio_read_dev_config (699-713): 1- and 2-byte config loads are the
         * low bytes of the byte-addressed word the model returns */
        CHK_EQ(RD(d, RVVIRTIO_REG_CONFIG + 12) & 0xffu, RVVIRTIO_BLK_DATA_SEGS_MAX);
        CHK_EQ(RD(d, RVVIRTIO_REG_CONFIG + 13) & 0xffu, 0u);
        CHK_EQ(RD(d, RVVIRTIO_REG_CONFIG + 20) & 0xffffu, 512u);
        /* vtblk_maximum_segments (677-695) and d_maxsize (795-798) */
        unsigned nsegs = 2u + (seen.seg_max < 257u ? seen.seg_max : 257u);
        CHK(nsegs > 2u);
        unsigned maxsize = (nsegs - 2u) * FBSD_PAGE - FBSD_PAGE;
        CHK_EQ(maxsize, FBSD_MAXSIZE);
        CHK(maxsize <= RVVIRTIO_BLK_REQ_BYTES_MAX);
        CHK((uint64_t)seen.seg_max * FBSD_PAGE <= RVVIRTIO_BLK_REQ_BYTES_MAX);
        /* vtblk_ident (1394-1426): GET_ID, 20 writable bytes, polled */
        memset(f.ram + OFF_DATA, 0xee, 32);
        uint32_t id_len = 20;
        f_request(&f, d, 0, RVVIRTIO_BLK_T_GET_ID, 0, &id_len, 1, RAM_BASE + OFF_DATA, true);
        CHK_EQ(f_used_idx(&f), 1u); /* virtqueue_poll sees it with no interrupt wait */
        CHK_EQ(f.ram[OFF_STATUS], RVVIRTIO_BLK_S_OK);
        CHK_EQ(f_used_len(&f, 0), 21u);
        CHK(memcmp(f.ram + OFF_DATA, "z23-synth-disk\0\0\0\0\0\0", 20) == 0);
        CHK_EQ(f.ram[OFF_DATA + 20], 0xee);
        /* vtmmio_vq_intr (962-963): read InterruptStatus, ack the same value */
        CHK(f.irq);
        uint32_t st = RD(d, RVVIRTIO_REG_INTERRUPT_STATUS);
        CHK_EQ(st, RVVIRTIO_INT_USED_BUFFER);
        WR(d, RVVIRTIO_REG_INTERRUPT_ACK, st);
        CHK(!f.irq);
        CHK_EQ(RD(d, RVVIRTIO_REG_INTERRUPT_STATUS), 0u);
        /* largest request the driver sends: d_maxsize bytes in 126 segments
         * (first and last partial pages), IN then OUT */
        uint32_t lens[126];
        lens[0] = FBSD_PAGE - 512u;
        for (unsigned i = 1; i < 125u; i++)
            lens[i] = FBSD_PAGE;
        lens[125] = 512u;
        uint64_t sum = 0;
        for (unsigned i = 0; i < 126u; i++)
            sum += lens[i];
        CHK_EQ(sum, FBSD_MAXSIZE);
        s.calls = s.preads = s.pwrites = 0;
        f_request(&f, d, 1, RVVIRTIO_BLK_T_IN, 100, lens, 126, AP_GPA, true);
        CHK_EQ(f.ram[OFF_STATUS], RVVIRTIO_BLK_S_OK);
        CHK_EQ(f_used_len(&f, 1), FBSD_MAXSIZE + 1u);
        CHK_EQ(s.preads, (FBSD_MAXSIZE + 4095u) / 4096u);
        f_request(&f, d, 2, RVVIRTIO_BLK_T_OUT, 100, lens, 126, AP_GPA, false);
        CHK_EQ(f.ram[OFF_STATUS], RVVIRTIO_BLK_S_OK);
        CHK_EQ(f_used_len(&f, 2), 1u);
        CHK_EQ(s.pwrites, (FBSD_MAXSIZE + 4095u) / 4096u);
        /* BIO_FLUSH: header and status only (virtio_blk.c:1080-1129) */
        f_request(&f, d, 3, RVVIRTIO_BLK_T_FLUSH, 0, NULL, 0, 0, false);
        CHK_EQ(f.ram[OFF_STATUS], RVVIRTIO_BLK_S_OK);
        CHK_EQ(s.flushes, 1u);
        /* a type the model does not implement is UNSUPP, not a hang */
        unsigned before = s.calls;
        f_request(&f, d, 4, 11u /* DISCARD */, 0, NULL, 0, 0, false);
        CHK_EQ(f.ram[OFF_STATUS], RVVIRTIO_BLK_S_UNSUPP);
        CHK_EQ(s.calls, before);
        CHK(!is_reset(d));
        CHK(guards_ok(&f));
        PASS();
    } _test_next:;
    return failures;
}

static int t_blk_request_bound(void)
{
    int failures = 0;
    TEST("rvvirtio: an oversized block request is refused with zero backend callbacks") {
        static struct fx f;
        /* exactly 4 GiB of data: a uint32 progress counter wraps to 0 here */
        struct bound_probe p = run_bound_case(&f, UINT64_C(1) << 32);
        CHK_EQ(p.in_calls, 0u);
        CHK_EQ(p.in_status, RVVIRTIO_BLK_S_IOERR);
        CHK_EQ(p.in_used, 1u); /* nothing written but the status byte */
        CHK_EQ(p.out_calls, 0u);
        CHK_EQ(p.out_status, RVVIRTIO_BLK_S_IOERR);
        CHK_EQ(p.out_used, 1u);
        CHK(!p.reset_seen);
        CHK_EQ(p.aperture_bytes, 0u); /* no data byte was touched */
        CHK(p.device_usable);
        /* 4 GiB + 512: a 32-bit total is 512, a valid-looking small request */
        p = run_bound_case(&f, (UINT64_C(1) << 32) + 512u);
        CHK_EQ(p.in_calls, 0u);
        CHK_EQ(p.in_status, RVVIRTIO_BLK_S_IOERR);
        CHK_EQ(p.out_calls, 0u);
        CHK(!p.reset_seen);
        CHK(p.device_usable);
        /* the boundary: the bound itself passes, one sector more is refused */
        static struct rvvirtio_blk b;
        static struct synth s;
        fx_reset(&f);
        f.aperture = true;
        synth_init(&s, UINT64_C(16) << 30);
        CHK(fb_bringup(&f, &b, &s, false, NULL));
        uint32_t lens[130];
        for (unsigned i = 0; i < 128u; i++)
            lens[i] = 8192u;
        f_request(&f, &b.dev, 0, RVVIRTIO_BLK_T_IN, 0, lens, 128, AP_GPA, true);
        CHK_EQ(f.ram[OFF_STATUS], RVVIRTIO_BLK_S_OK);
        CHK_EQ(s.calls, RVVIRTIO_BLK_REQ_BYTES_MAX / RVVIRTIO_BLK_CHUNK);
        CHK_EQ(f_used_len(&f, 0), RVVIRTIO_BLK_REQ_BYTES_MAX + 1u);
        s.calls = 0;
        lens[128] = 512;
        f_request(&f, &b.dev, 1, RVVIRTIO_BLK_T_IN, 0, lens, 129, AP_GPA, true);
        CHK_EQ(f.ram[OFF_STATUS], RVVIRTIO_BLK_S_IOERR);
        CHK_EQ(s.calls, 0u);
        f_request(&f, &b.dev, 2, RVVIRTIO_BLK_T_OUT, 0, lens, 129, AP_GPA, false);
        CHK_EQ(f.ram[OFF_STATUS], RVVIRTIO_BLK_S_IOERR);
        CHK_EQ(s.calls, 0u);
        CHK(!is_reset(&b.dev));
        CHK(guards_ok(&f));
        PASS();
    } _test_next:;
    return failures;
}

/* Red twin: the same cases with the admission guard compiled out. The
 * synthetic backend stops the run after SYNTH_STOP callbacks, so the twin ends. */
static int t_blk_request_bound_twin(void)
{
    int failures = 0;
    TEST("rvvirtio: twin without the admission guard reaches the backend (caught)") {
        static struct fx f;
        g_api = &k_real;
        struct bound_probe good = run_bound_case(&f, UINT64_C(1) << 32);
        g_api = &k_mut;
        struct bound_probe bad = run_bound_case(&f, UINT64_C(1) << 32);
        g_api = &k_real;
        printf("\n    rvvirtio twin request-bound: real in/out backend calls=%u/%u, "
               "twin in/out backend calls=%u/%u (stop at %u) -> %s\n",
               good.in_calls, good.out_calls, bad.in_calls, bad.out_calls, SYNTH_STOP,
               bad.in_calls > 0 && bad.out_calls > 0 ? "DETECTED" : "MISSED");
        CHK_EQ(good.in_calls, 0u);
        CHK_EQ(good.out_calls, 0u);
        CHK(bad.in_calls > 0u);
        CHK(bad.out_calls > 0u);
        CHK(bad.in_calls <= SYNTH_STOP + 1u); /* stopped by the backend limit */
        PASS();
    } _test_next:;
    return failures;
}

/* Post `n` 1 MiB reads sharing one indirect table, then notify once. */
static void cap_post(struct fx *f, unsigned n, uint64_t table_off)
{
    uint32_t lens[128];
    for (unsigned i = 0; i < 128u; i++)
        lens[i] = 8192u;
    struct seg s[F_TABLE_MAX];
    unsigned ns = f_build(s, lens, 128, AP_GPA, true);
    put_hdr(f, RVVIRTIO_BLK_T_IN, 0);
    f_table(f, table_off, s, ns);
    for (unsigned i = 0; i < n; i++) {
        f_head(f, i, table_off, ns);
        f_avail_post(f, i);
    }
}

static int t_blk_notify_cap(void)
{
    int failures = 0;
    TEST("rvvirtio: one notify services a bounded amount and leaves the rest pending") {
        static struct fx f;
        static struct rvvirtio_blk b;
        static struct synth s;
        fx_reset(&f);
        f.aperture = true;
        synth_init(&s, UINT64_C(16) << 30);
        s.stop_after = 0;
        CHK(fb_bringup(&f, &b, &s, false, NULL));
        struct rvvirtio_dev *d = &b.dev;
        const unsigned per_notify =
            (unsigned)(RVVIRTIO_BLK_NOTIFY_BYTES_MAX / RVVIRTIO_BLK_REQ_BYTES_MAX);
        const unsigned posted = per_notify + 12u;
        /* a full queue of seg_max-page requests is under both caps */
        uint32_t page = FBSD_PAGE;
        for (unsigned i = 0; i < F_QN; i++) {
            struct seg sg[3] = {{RAM_BASE + OFF_HDR, 16, false},
                                {RAM_BASE + OFF_DATA, page, true},
                                {RAM_BASE + OFF_STATUS, 1, true}};
            f_table(&f, 0x20000u + 48u * i, sg, 3);
            f_head(&f, i, 0x20000u + 48u * i, 3);
            f_avail_post(&f, i);
        }
        put_hdr(&f, RVVIRTIO_BLK_T_IN, 0);
        WR(d, RVVIRTIO_REG_QUEUE_NOTIFY, 0);
        CHK_EQ(f_used_idx(&f), (uint16_t)F_QN);
        CHK(!rvvirtio_blk_pending(&b));
        /* hostile mix: posted 1 MiB requests, notified once */
        s.calls = 0;
        cap_post(&f, posted, OFF_DATA2);
        WR(d, RVVIRTIO_REG_QUEUE_NOTIFY, 0);
        CHK_EQ((uint16_t)(f_used_idx(&f) - (uint16_t)F_QN), (uint16_t)per_notify);
        CHK_EQ(s.calls, per_notify * (RVVIRTIO_BLK_REQ_BYTES_MAX / RVVIRTIO_BLK_CHUNK));
        CHK(rvvirtio_blk_pending(&b));
        /* the next notify continues where the cap stopped */
        WR(d, RVVIRTIO_REG_QUEUE_NOTIFY, 0);
        CHK_EQ((uint16_t)(f_used_idx(&f) - (uint16_t)F_QN), (uint16_t)posted);
        CHK(!rvvirtio_blk_pending(&b));
        /* the explicit service call does the same without a notify */
        cap_post(&f, posted, OFF_DATA2);
        WR(d, RVVIRTIO_REG_QUEUE_NOTIFY, 0);
        CHK(rvvirtio_blk_pending(&b));
        rvvirtio_blk_service(&b);
        CHK_EQ((uint16_t)(f_used_idx(&f) - (uint16_t)F_QN), (uint16_t)(2u * posted));
        CHK(!rvvirtio_blk_pending(&b));
        /* a reset forgets pending work */
        cap_post(&f, posted, OFF_DATA2);
        WR(d, RVVIRTIO_REG_QUEUE_NOTIFY, 0);
        CHK(rvvirtio_blk_pending(&b));
        WR(d, RVVIRTIO_REG_STATUS, 0);
        CHK(!rvvirtio_blk_pending(&b));
        CHK(!is_reset(d));
        CHK(guards_ok(&f));
        PASS();
    } _test_next:;
    return failures;
}


/* ---- 11. virtio-entropy (5.4) ----
 *
 * FreeBSD facts used below (sys/dev/virtio/random/virtio_random.c, FreeBSD
 * 15.1): the request is one device-writable segment of
 * sizeof(*vtrnd_value) * HARVESTSIZE = 4 * 2 = 8 bytes (150, random_harvestq.h:33),
 * enqueued with 0 readable and 1 writable segment (280) and notified at once
 * (284), from attach (184), before the transport sets DRIVER_OK
 * (virtio_mmio.c:851,858). The queue has no interrupt handler (vqai_intr NULL,
 * virtio_mmio.c:551). A harvest dequeues without waiting, copies the used
 * length bytes (299-305) and enqueues the next request (307). Only detach
 * polls (212). No feature bit is requested (74, 238) and no config is read. */
struct rng_api {
    bool (*init)(struct rvvirtio_rng *, const struct rvvirtio_mem *,
                 const struct rvvirtio_rng_ops *);
    void (*service)(struct rvvirtio_rng *);
    bool (*pending)(const struct rvvirtio_rng *);
    struct rvvirtio_rng_counters (*counters)(const struct rvvirtio_rng *);
};
static const struct rng_api k_rreal = {rvvirtio_rng_init, rvvirtio_rng_service,
                                       rvvirtio_rng_pending, rvvirtio_rng_counters_get};
static const struct rng_api k_rmut = {rvvmut_rng_init, rvvmut_rng_service,
                                      rvvmut_rng_pending, rvvmut_rng_counters_get};
static const struct rng_api *g_rapi = &k_rreal;

#define RBUF 0x14000u   /* poisoned scratch area for request buffers */
#define RPOISON_FROM (RBUF - 256u)
#define RPOISON_LEN 0x4000u
#define RPOISON 0xccu

/* Deterministic source: byte number p of the stream is (uint8_t)p. */
struct ent {
    uint64_t pos, left;
    unsigned calls;
    size_t maxn;
};
static uint8_t ent_byte(uint64_t pos) { return (uint8_t)pos; }

static size_t ent_fill(void *ctx, uint8_t *buf, size_t n)
{
    struct ent *e = ctx;
    e->calls++;
    if (n > e->maxn)
        e->maxn = n;
    size_t k = (uint64_t)n < e->left ? n : (size_t)e->left;
    for (size_t i = 0; i < k; i++)
        buf[i] = ent_byte(e->pos++);
    e->left -= k;
    return k;
}

static void ent_init(struct ent *e, uint64_t left)
{
    memset(e, 0, sizeof(*e));
    e->left = left;
}

static void r_poison(struct fx *f)
{
    memset(f->ram + RPOISON_FROM, RPOISON, RPOISON_LEN);
}

/* True when [from, to) of RAM still holds the poison. */
static bool r_untouched(const struct fx *f, uint64_t from, uint64_t to)
{
    for (uint64_t i = from; i < to; i++)
        if (f->ram[i] != RPOISON)
            return false;
    return true;
}

/* A direct (non-indirect) chain at descriptor idx0.., published to the avail ring. */
static void r_post(struct fx *f, unsigned idx0, const struct seg *s, unsigned n)
{
    for (unsigned i = 0; i < n; i++) {
        uint64_t o = 16u * (idx0 + i);
        put64(f, o, s[i].addr);
        put32(f, o + 8, s[i].len);
        put16(f, o + 12, (uint16_t)((s[i].write ? 2u : 0u) | (i + 1u < n ? 1u : 0u)));
        put16(f, o + 14, (uint16_t)(idx0 + i + 1u));
    }
    f_avail_post(f, idx0);
}

static void r_post1(struct fx *f, unsigned idx, uint64_t off, uint32_t len)
{
    struct seg s = {RAM_BASE + off, len, true};
    r_post(f, idx, &s, 1);
}

static uint32_t f_used_id(const struct fx *f, unsigned i)
{
    return get32(f, F_USED + 4 + 8u * (i % F_QN));
}

struct fr_seen {
    uint64_t host, negotiated;
};

/* vtmmio_attach (240-246): reset, ACK; probe_and_attach_child (850): DRIVER;
 * then the part of vtrnd_attach that precedes the first enqueue. Everything
 * up to, but not including, DRIVER_OK. */
static bool fr_session(struct rvvirtio_dev *d, struct fr_seen *seen)
{
    WR(d, RVVIRTIO_REG_STATUS, 0);
    FB(RD(d, RVVIRTIO_REG_STATUS) == 0u);
    fb_set_status(d, RVVIRTIO_STATUS_ACKNOWLEDGE);
    fb_set_status(d, RVVIRTIO_STATUS_DRIVER);
    /* vtrnd_negotiate_features (virtio_random.c:232-242): child features 0;
     * vtmmio_negotiate_features (392-429) adds only VERSION_1 (397-399) */
    WR(d, RVVIRTIO_REG_DEVICE_FEATURES_SEL, 1);
    uint64_t host = (uint64_t)RD(d, RVVIRTIO_REG_DEVICE_FEATURES) << 32;
    WR(d, RVVIRTIO_REG_DEVICE_FEATURES_SEL, 0);
    host |= RD(d, RVVIRTIO_REG_DEVICE_FEATURES);
    uint64_t feat = host & RVVIRTIO_F_VERSION_1;
    WR(d, RVVIRTIO_REG_DRIVER_FEATURES_SEL, 1);
    WR(d, RVVIRTIO_REG_DRIVER_FEATURES, (uint32_t)(feat >> 32));
    WR(d, RVVIRTIO_REG_DRIVER_FEATURES_SEL, 0);
    WR(d, RVVIRTIO_REG_DRIVER_FEATURES, (uint32_t)feat);
    fb_set_status(d, RVVIRTIO_STATUS_FEATURES_OK);
    FB((RD(d, RVVIRTIO_REG_STATUS) & RVVIRTIO_STATUS_FEATURES_OK) != 0);
    /* vtrnd_alloc_virtqueue (257-268): one queue, size = QueueNumMax (536) */
    WR(d, RVVIRTIO_REG_QUEUE_SEL, 0);
    uint32_t size = RD(d, RVVIRTIO_REG_QUEUE_NUM_MAX);
    FB(size == F_QN);
    WR(d, RVVIRTIO_REG_QUEUE_NUM, size);
    uint64_t desc = RAM_BASE, avail = RAM_BASE + F_AVAIL, used = RAM_BASE + F_USED;
    WR(d, RVVIRTIO_REG_QUEUE_DESC_LOW, (uint32_t)desc);
    WR(d, RVVIRTIO_REG_QUEUE_DESC_HIGH, (uint32_t)(desc >> 32));
    WR(d, RVVIRTIO_REG_QUEUE_DRIVER_LOW, (uint32_t)avail);
    WR(d, RVVIRTIO_REG_QUEUE_DRIVER_HIGH, (uint32_t)(avail >> 32));
    WR(d, RVVIRTIO_REG_QUEUE_DEVICE_LOW, (uint32_t)used);
    WR(d, RVVIRTIO_REG_QUEUE_DEVICE_HIGH, (uint32_t)(used >> 32));
    WR(d, RVVIRTIO_REG_QUEUE_READY, 1);
    FB(RD(d, RVVIRTIO_REG_QUEUE_READY) == 1u);
    /* a second queue does not exist: QueueNumMax of queue 1 reads 0 */
    WR(d, RVVIRTIO_REG_QUEUE_SEL, 1);
    FB(RD(d, RVVIRTIO_REG_QUEUE_NUM_MAX) == 0u);
    WR(d, RVVIRTIO_REG_QUEUE_SEL, 0);
    if (seen != NULL)
        *seen = (struct fr_seen){host, feat};
    return true;
}

/* vtmmio_probe (virtio_mmio.c:172-189), then the session above. */
static bool fr_attach(struct fx *f, struct rvvirtio_rng *r, struct ent *e,
                      struct fr_seen *seen)
{
    struct rvvirtio_mem mem = fx_mem(f);
    struct rvvirtio_rng_ops ops = {e, ent_fill};
    if (!g_rapi->init(r, &mem, &ops))
        return false;
    struct rvvirtio_dev *d = &r->dev;
    FB(RD(d, RVVIRTIO_REG_MAGIC) == 0x74726976u);
    FB(RD(d, RVVIRTIO_REG_VERSION) == 2u);
    FB(RD(d, RVVIRTIO_REG_DEVICE_ID) == RVVIRTIO_DEVICE_ID_ENTROPY); /* VIRTIO_ID_ENTROPY 4 */
    return fr_session(d, seen);
}
static bool fr_up(struct fx *f, struct rvvirtio_rng *r, struct ent *e)
{
    if (!fr_attach(f, r, e, NULL))
        return false;
    fb_set_status(&r->dev, RVVIRTIO_STATUS_DRIVER_OK);
    FB(!is_reset(&r->dev));
    return true;
}

static int t_rng_freebsd_attach_harvest(void)
{
    int failures = 0;
    TEST("rvvirtio: FreeBSD vtrnd attach and first harvest, register by register") {
        static struct fx f;
        static struct rvvirtio_rng r;
        static struct ent e;
        struct fr_seen seen;
        fx_reset(&f);
        r_poison(&f);
        ent_init(&e, UINT64_MAX);
        CHK(fr_attach(&f, &r, &e, &seen));
        struct rvvirtio_dev *d = &r.dev;
        /* VTRND_FEATURES is 0 (74): the host offers no device bit, only
         * VERSION_1 and INDIRECT_DESC from the transport */
        CHK_EQ(seen.host, RVVIRTIO_F_VERSION_1 | RVVIRTIO_F_INDIRECT_DESC);
        CHK_EQ(seen.negotiated, RVVIRTIO_F_VERSION_1);
        /* no configuration space: reads give 0, writes are ignored */
        CHK_EQ(RD(d, RVVIRTIO_REG_CONFIG), 0u);
        CHK_EQ(RD(d, RVVIRTIO_REG_CONFIG + 8), 0u);
        WR(d, RVVIRTIO_REG_CONFIG, 0xffffffffu);
        CHK_EQ(RD(d, RVVIRTIO_REG_CONFIG), 0u);
        CHK_EQ(RD(d, RVVIRTIO_REG_CONFIG_GENERATION), 0u);
        /* vtrnd_enqueue (270-285): one 8-byte writable segment, then notify,
         * all before DRIVER_OK (virtio_mmio.c:858) */
        r_post1(&f, 0, RBUF, 8);
        WR(d, RVVIRTIO_REG_QUEUE_NOTIFY, 0);
        CHK_EQ(f_used_idx(&f), 0u); /* the transport dropped the early notify */
        CHK(!g_rapi->pending(&r));
        CHK_EQ(RD(d, RVVIRTIO_REG_INTERRUPT_STATUS), 0u);
        fb_set_status(d, RVVIRTIO_STATUS_DRIVER_OK); /* virtio_mmio.c:858 */
        CHK_EQ(RD(d, RVVIRTIO_REG_STATUS),
               RVVIRTIO_STATUS_ACKNOWLEDGE | RVVIRTIO_STATUS_DRIVER |
                   RVVIRTIO_STATUS_FEATURES_OK | RVVIRTIO_STATUS_DRIVER_OK);
        /* virtqueue_dequeue (virtqueue.c:570-600): used.idx moved, id and len set */
        CHK_EQ(f_used_idx(&f), 1u);
        CHK_EQ(f_used_id(&f, 0), 0u);
        CHK_EQ(f_used_len(&f, 0), 8u);
        for (unsigned i = 0; i < 8u; i++)
            CHK_EQ(f.ram[RBUF + i], ent_byte(i));
        CHK(r_untouched(&f, RPOISON_FROM, RBUF));
        CHK(r_untouched(&f, RBUF + 8u, RPOISON_FROM + RPOISON_LEN));
        /* the status bit is right even though the driver registers no handler */
        CHK(f.irq);
        CHK_EQ(RD(d, RVVIRTIO_REG_INTERRUPT_STATUS), RVVIRTIO_INT_USED_BUFFER);
        WR(d, RVVIRTIO_REG_INTERRUPT_ACK, RVVIRTIO_INT_USED_BUFFER);
        CHK(!f.irq);
        CHK_EQ(RD(d, RVVIRTIO_REG_INTERRUPT_STATUS), 0u);
        /* vtrnd_harvest (299-307) then vtrnd_enqueue: the same head is reused,
         * the new notify arrives after DRIVER_OK and is served at once */
        r_post1(&f, 0, RBUF, 8);
        WR(d, RVVIRTIO_REG_QUEUE_NOTIFY, 0);
        CHK_EQ(f_used_idx(&f), 2u);
        CHK_EQ(f_used_len(&f, 1), 8u);
        for (unsigned i = 0; i < 8u; i++)
            CHK_EQ(f.ram[RBUF + i], ent_byte(8u + i));
        struct rvvirtio_rng_counters c = g_rapi->counters(&r);
        CHK_EQ(c.requests, 2u);
        CHK_EQ(c.bytes, 16u);
        CHK_EQ(c.empty_fills, 0u);
        CHK_EQ(c.malformed, 0u);
        CHK(!g_rapi->pending(&r));
        CHK(!is_reset(d));
        CHK(guards_ok(&f));
        PASS();
    } _test_next:;
    return failures;
}

static int t_rng_order_and_guards(void)
{
    int failures = 0;
    TEST("rvvirtio: entropy bytes land in chain order and only in writable segments") {
        static struct fx f;
        static struct rvvirtio_rng r;
        static struct ent e;
        fx_reset(&f);
        r_poison(&f);
        ent_init(&e, UINT64_MAX);
        CHK(fr_up(&f, &r, &e));
        struct rvvirtio_dev *d = &r.dev;
        const struct seg s3[3] = {{RAM_BASE + RBUF + 0x100u, 5, true},
                                  {RAM_BASE + RBUF + 0x400u, 3, true},
                                  {RAM_BASE + RBUF + 0x800u, 100, true}};
        r_post(&f, 0, s3, 3);
        WR(d, RVVIRTIO_REG_QUEUE_NOTIFY, 0);
        CHK_EQ(f_used_idx(&f), 1u);
        CHK_EQ(f_used_len(&f, 0), 108u);
        for (unsigned i = 0; i < 5u; i++)
            CHK_EQ(f.ram[RBUF + 0x100u + i], ent_byte(i));
        for (unsigned i = 0; i < 3u; i++)
            CHK_EQ(f.ram[RBUF + 0x400u + i], ent_byte(5u + i));
        for (unsigned i = 0; i < 100u; i++)
            CHK_EQ(f.ram[RBUF + 0x800u + i], ent_byte(8u + i));
        /* everything around the three segments is untouched, byte for byte */
        CHK(r_untouched(&f, RPOISON_FROM, RBUF + 0x100u));
        CHK(r_untouched(&f, RBUF + 0x105u, RBUF + 0x400u));
        CHK(r_untouched(&f, RBUF + 0x403u, RBUF + 0x800u));
        CHK(r_untouched(&f, RBUF + 0x864u, RPOISON_FROM + RPOISON_LEN));
        /* a request longer than one fill chunk crosses it without a gap */
        const struct seg s2[2] = {{RAM_BASE + RBUF + 0x1000u, 700, true},
                                  {RAM_BASE + RBUF + 0x2000u, 600, true}};
        unsigned calls = e.calls;
        r_post(&f, 4, s2, 2);
        WR(d, RVVIRTIO_REG_QUEUE_NOTIFY, 0);
        CHK_EQ(f_used_len(&f, 1), 1300u);
        CHK_EQ(e.calls - calls, 3u); /* 512 + 512 + 276 */
        CHK(e.maxn <= RVVIRTIO_RNG_CHUNK);
        for (unsigned i = 0; i < 700u; i++)
            CHK_EQ(f.ram[RBUF + 0x1000u + i], ent_byte(108u + i));
        for (unsigned i = 0; i < 600u; i++)
            CHK_EQ(f.ram[RBUF + 0x2000u + i], ent_byte(808u + i));
        CHK(r_untouched(&f, RBUF + 0x864u, RBUF + 0x1000u));
        CHK(r_untouched(&f, RBUF + 0x12bcu, RBUF + 0x2000u));
        CHK(r_untouched(&f, RBUF + 0x2258u, RPOISON_FROM + RPOISON_LEN));
        CHK_EQ(e.pos, 1408u); /* the source was asked for exactly what was delivered */
        CHK(guards_ok(&f));
        PASS();
    } _test_next:;
    return failures;
}

struct clamp_probe {
    uint32_t used;
    uint64_t given;
    bool past_cap_untouched;
    bool at_cap_written;
};

/* One writable descriptor of cap + 904 bytes. */
static struct clamp_probe run_clamp_case(struct fx *f)
{
    static struct rvvirtio_rng r;
    static struct ent e;
    struct clamp_probe p = {0, 0, false, false};
    fx_reset(f);
    r_poison(f);
    ent_init(&e, UINT64_MAX);
    if (!fr_up(f, &r, &e))
        return p;
    const uint32_t len = RVVIRTIO_RNG_REQ_BYTES_MAX + 904u;
    r_post1(f, 0, RBUF, len);
    WR(&r.dev, RVVIRTIO_REG_QUEUE_NOTIFY, 0);
    p.used = f_used_len(f, 0);
    p.given = e.pos;
    p.past_cap_untouched = r_untouched(f, RBUF + RVVIRTIO_RNG_REQ_BYTES_MAX, RBUF + len);
    p.at_cap_written = f->ram[RBUF + RVVIRTIO_RNG_REQ_BYTES_MAX - 1u] ==
                       ent_byte(RVVIRTIO_RNG_REQ_BYTES_MAX - 1u);
    return p;
}

struct readable_probe {
    uint32_t used;
    uint64_t malformed;
    unsigned fills;
    bool readable_intact;
};

/* A chain of a readable 16-byte descriptor and a writable 64-byte one. */
static struct readable_probe run_readable_case(struct fx *f)
{
    static struct rvvirtio_rng r;
    static struct ent e;
    struct readable_probe p = {0, 0, 0, false};
    fx_reset(f);
    r_poison(f);
    memset(f->ram + RBUF, 0x11, 16);
    ent_init(&e, UINT64_MAX);
    if (!fr_up(f, &r, &e))
        return p;
    const struct seg s[2] = {{RAM_BASE + RBUF, 16, false},
                             {RAM_BASE + RBUF + 0x100u, 64, true}};
    r_post(f, 0, s, 2);
    WR(&r.dev, RVVIRTIO_REG_QUEUE_NOTIFY, 0);
    p.used = f_used_len(f, 0);
    p.malformed = g_rapi->counters(&r).malformed;
    p.fills = e.calls;
    p.readable_intact = true;
    for (unsigned i = 0; i < 16u; i++)
        p.readable_intact = p.readable_intact && f->ram[RBUF + i] == 0x11;
    return p;
}

static int t_rng_bounds(void)
{
    int failures = 0;
    TEST("rvvirtio: entropy request cap, readable chains, empty source and per-notify caps") {
        static struct fx f;
        static struct rvvirtio_rng r;
        static struct ent e;
        /* (a) clamp: used = cap, the source is asked for exactly the cap */
        g_rapi = &k_rreal;
        g_api = &k_real;
        struct clamp_probe cp = run_clamp_case(&f);
        CHK_EQ(cp.used, RVVIRTIO_RNG_REQ_BYTES_MAX);
        CHK_EQ(cp.given, RVVIRTIO_RNG_REQ_BYTES_MAX);
        CHK(cp.at_cap_written);
        CHK(cp.past_cap_untouched);
        /* (b) readable descriptor: completes with 0, nothing written, fill unused */
        struct readable_probe rp = run_readable_case(&f);
        CHK_EQ(rp.used, 0u);
        CHK_EQ(rp.malformed, 1u);
        CHK_EQ(rp.fills, 0u);
        CHK(rp.readable_intact);
        CHK(r_untouched(&f, RBUF + 0x100u, RBUF + 0x140u));
        /* (c) zero-length and writable-then-readable chains */
        fx_reset(&f);
        r_poison(&f);
        ent_init(&e, UINT64_MAX);
        CHK(fr_up(&f, &r, &e));
        struct rvvirtio_dev *d = &r.dev;
        r_post1(&f, 0, RBUF, 0);
        WR(d, RVVIRTIO_REG_QUEUE_NOTIFY, 0);
        CHK_EQ(f_used_idx(&f), 1u);
        CHK_EQ(f_used_len(&f, 0), 0u);
        const struct seg wr[2] = {{RAM_BASE + RBUF, 32, true}, {RAM_BASE + RBUF + 0x100u, 16, false}};
        r_post(&f, 2, wr, 2);
        const struct seg ro[1] = {{RAM_BASE + RBUF + 0x200u, 16, false}};
        r_post(&f, 5, ro, 1);
        WR(d, RVVIRTIO_REG_QUEUE_NOTIFY, 0);
        CHK_EQ(f_used_idx(&f), 3u);
        CHK_EQ(f_used_len(&f, 1), 0u);
        CHK_EQ(f_used_len(&f, 2), 0u);
        CHK_EQ(g_rapi->counters(&r).malformed, 3u);
        CHK_EQ(g_rapi->counters(&r).requests, 3u);
        CHK_EQ(g_rapi->counters(&r).bytes, 0u);
        CHK_EQ(e.calls, 0u);
        CHK(r_untouched(&f, RPOISON_FROM, RPOISON_FROM + RPOISON_LEN));
        CHK(!is_reset(d));
        /* (d) empty source: the request stays available and pending */
        fx_reset(&f);
        r_poison(&f);
        ent_init(&e, 0);
        CHK(fr_up(&f, &r, &e));
        d = &r.dev;
        r_post1(&f, 0, RBUF, 8);
        WR(d, RVVIRTIO_REG_QUEUE_NOTIFY, 0);
        CHK_EQ(f_used_idx(&f), 0u);
        CHK(g_rapi->pending(&r));
        CHK_EQ(g_rapi->counters(&r).empty_fills, 1u);
        CHK_EQ(g_rapi->counters(&r).requests, 0u);
        CHK(!f.irq);
        CHK(r_untouched(&f, RPOISON_FROM, RPOISON_FROM + RPOISON_LEN));
        g_rapi->service(&r); /* still dry: still pending, one more empty fill */
        CHK(g_rapi->pending(&r));
        CHK_EQ(g_rapi->counters(&r).empty_fills, 2u);
        e.left = 100; /* the source recovers */
        g_rapi->service(&r);
        CHK(!g_rapi->pending(&r));
        CHK_EQ(f_used_idx(&f), 1u);
        CHK_EQ(f_used_len(&f, 0), 8u);
        CHK_EQ(f.ram[RBUF + 7], ent_byte(7));
        CHK(f.irq);
        CHK_EQ(g_rapi->counters(&r).bytes, 8u);
        /* a source with only 3 bytes left completes the request with 3 and
         * counts the empty fill that ended it; the next request waits */
        e.left = 3;
        r_post1(&f, 0, RBUF + 0x100u, 8);
        r_post1(&f, 1, RBUF + 0x200u, 8);
        WR(d, RVVIRTIO_REG_QUEUE_NOTIFY, 0);
        CHK_EQ(f_used_idx(&f), 2u);
        CHK_EQ(f_used_len(&f, 1), 3u);
        CHK(r_untouched(&f, RBUF + 0x103u, RBUF + 0x108u));
        CHK(g_rapi->pending(&r));
        CHK_EQ(g_rapi->counters(&r).empty_fills, 3u);
        e.left = UINT64_MAX;
        g_rapi->service(&r);
        CHK_EQ(f_used_idx(&f), 3u);
        CHK_EQ(f_used_len(&f, 2), 8u);
        CHK(!g_rapi->pending(&r));
        /* (e) per-notify byte cap: 40 maximal requests, one notify serves 16 */
        fx_reset(&f);
        r_poison(&f);
        ent_init(&e, UINT64_MAX);
        CHK(fr_up(&f, &r, &e));
        d = &r.dev;
        const unsigned per_notify = (unsigned)(RVVIRTIO_RNG_NOTIFY_BYTES_MAX / RVVIRTIO_RNG_REQ_BYTES_MAX);
        CHK_EQ(per_notify, 16u);
        for (unsigned i = 0; i < 40u; i++)
            r_post1(&f, i, RBUF, RVVIRTIO_RNG_REQ_BYTES_MAX);
        WR(d, RVVIRTIO_REG_QUEUE_NOTIFY, 0);
        CHK_EQ(f_used_idx(&f), per_notify);
        CHK(g_rapi->pending(&r));
        CHK_EQ(e.pos, RVVIRTIO_RNG_NOTIFY_BYTES_MAX);
        WR(d, RVVIRTIO_REG_QUEUE_NOTIFY, 0); /* the next notify continues */
        CHK_EQ(f_used_idx(&f), 2u * per_notify);
        g_rapi->service(&r);
        CHK_EQ(f_used_idx(&f), 40u);
        CHK(!g_rapi->pending(&r));
        CHK_EQ(g_rapi->counters(&r).bytes, 40u * RVVIRTIO_RNG_REQ_BYTES_MAX);
        /* per-notify request cap: 100 small requests, one notify serves 64 */
        for (unsigned i = 0; i < 100u; i++)
            r_post1(&f, i, RBUF, 8);
        WR(d, RVVIRTIO_REG_QUEUE_NOTIFY, 0);
        CHK_EQ((uint16_t)(f_used_idx(&f) - 40u), RVVIRTIO_RNG_NOTIFY_REQS_MAX);
        CHK(g_rapi->pending(&r));
        g_rapi->service(&r);
        CHK_EQ((uint16_t)(f_used_idx(&f) - 40u), 100u);
        CHK(!g_rapi->pending(&r));
        CHK(!is_reset(d));
        CHK(guards_ok(&f));
        PASS();
    } _test_next:;
    return failures;
}

struct budget_probe {
    bool ok;            /* the device came up and stayed up */
    unsigned used;      /* requests completed by the one notify */
    uint32_t short_len; /* used length of the 4095-byte request */
    uint32_t last_len;  /* used length of the request that reaches the cap */
    uint64_t pulled;    /* bytes the notify took from the source */
    uint64_t counted;   /* the device's own byte counter */
    bool first_byte_ok, rest_untouched, pending;
};

/* Fifteen maximal requests, one a byte short, then a maximal one: 65535 bytes
 * are delivered when the last request starts, so it may take one. */
static struct budget_probe run_budget_case(struct fx *f)
{
    static struct rvvirtio_rng r;
    static struct ent e;
    struct budget_probe p = {0};
    const uint64_t last = RBUF + 0x2000u;
    fx_reset(f);
    r_poison(f);
    ent_init(&e, UINT64_MAX);
    if (!fr_up(f, &r, &e))
        return p;
    for (unsigned i = 0; i < 15u; i++)
        r_post1(f, i, RBUF, RVVIRTIO_RNG_REQ_BYTES_MAX);
    r_post1(f, 15, RBUF, RVVIRTIO_RNG_REQ_BYTES_MAX - 1u);
    r_post1(f, 16, last, RVVIRTIO_RNG_REQ_BYTES_MAX);
    r_post1(f, 17, RBUF, 8);
    g_api->wr(&r.dev, RVVIRTIO_REG_QUEUE_NOTIFY, 0);
    p.used = f_used_idx(f);
    p.short_len = f_used_len(f, 15);
    p.last_len = f_used_len(f, 16);
    p.pulled = e.pos;
    p.counted = g_rapi->counters(&r).bytes;
    p.first_byte_ok = f->ram[last] == ent_byte(RVVIRTIO_RNG_NOTIFY_BYTES_MAX - 1u);
    p.rest_untouched = r_untouched(f, last + 1u, last + RVVIRTIO_RNG_REQ_BYTES_MAX);
    p.pending = g_rapi->pending(&r);
    g_rapi->service(&r); /* the eight-byte request, and for the twin nothing new */
    p.ok = !is_reset(&r.dev) && guards_ok(f) && f_used_idx(f) == 18u &&
           f_used_len(f, 17) == 8u && !g_rapi->pending(&r);
    return p;
}

static int t_rng_notify_budget(void)
{
    int failures = 0;
    TEST("rvvirtio: an entropy notify delivers exactly its byte cap over mixed request sizes (twin)") {
        static struct fx f;
        g_rapi = &k_rreal;
        g_api = &k_real;
        struct budget_probe good = run_budget_case(&f);
        g_rapi = &k_rmut;
        g_api = &k_mut;
        struct budget_probe bad = run_budget_case(&f);
        g_rapi = &k_rreal;
        g_api = &k_real;
        printf("\n    rvvirtio twin rng-notify-left: real last=%u delivered=%llu, "
               "twin last=%u delivered=%llu -> %s\n",
               good.last_len, (unsigned long long)good.pulled, bad.last_len,
               (unsigned long long)bad.pulled,
               bad.pulled > RVVIRTIO_RNG_NOTIFY_BYTES_MAX ? "DETECTED" : "MISSED");
        CHK(good.ok);
        CHK_EQ(good.used, 17u);
        CHK_EQ(good.short_len, RVVIRTIO_RNG_REQ_BYTES_MAX - 1u);
        CHK_EQ(good.last_len, 1u); /* cut to what the notify had left */
        CHK_EQ(good.pulled, RVVIRTIO_RNG_NOTIFY_BYTES_MAX);
        CHK_EQ(good.counted, RVVIRTIO_RNG_NOTIFY_BYTES_MAX);
        CHK(good.first_byte_ok);
        CHK(good.rest_untouched);
        CHK(good.pending); /* the eight-byte request waits for the next notify */
        /* twin without the cut: the last request is served whole */
        CHK(bad.ok);
        CHK_EQ(bad.last_len, RVVIRTIO_RNG_REQ_BYTES_MAX);
        CHK_EQ(bad.pulled, RVVIRTIO_RNG_NOTIFY_BYTES_MAX + RVVIRTIO_RNG_REQ_BYTES_MAX - 1u);
        CHK(!bad.rest_untouched);
        PASS();
    } _test_next:;
    return failures;
}

static int t_rng_reset_pending(void)
{
    int failures = 0;
    TEST("rvvirtio: a guest reset clears a pending entropy request and the device works again") {
        static struct fx f;
        static struct rvvirtio_rng r;
        static struct ent e;
        fx_reset(&f);
        r_poison(&f);
        ent_init(&e, 0);
        CHK(fr_up(&f, &r, &e));
        struct rvvirtio_dev *d = &r.dev;
        r_post1(&f, 0, RBUF, 8);
        WR(d, RVVIRTIO_REG_QUEUE_NOTIFY, 0);
        CHK(g_rapi->pending(&r));
        CHK_EQ(g_rapi->counters(&r).empty_fills, 1u);
        WR(d, RVVIRTIO_REG_STATUS, 0);
        CHK(!g_rapi->pending(&r));
        CHK_EQ(RD(d, RVVIRTIO_REG_STATUS), 0u);
        g_rapi->service(&r); /* not running: nothing happens */
        CHK_EQ(g_rapi->counters(&r).empty_fills, 1u);
        /* counters survive the reset */
        CHK_EQ(g_rapi->counters(&r).requests, 0u);
        /* a fresh guest session on the same device, with a source that works */
        memset(f.ram, 0, F_USED + 0x900u);
        e.left = UINT64_MAX;
        struct rvvirtio_rng_counters before = g_rapi->counters(&r);
        CHK(fr_session(d, NULL));
        fb_set_status(d, RVVIRTIO_STATUS_DRIVER_OK);
        r_post1(&f, 0, RBUF + 0x100u, 8);
        WR(d, RVVIRTIO_REG_QUEUE_NOTIFY, 0);
        CHK_EQ(f_used_idx(&f), 1u);
        CHK_EQ(f_used_len(&f, 0), 8u);
        CHK_EQ(f.ram[RBUF + 0x100u + 3u], ent_byte(3));
        CHK(!g_rapi->pending(&r));
        CHK_EQ(g_rapi->counters(&r).requests, before.requests + 1u);
        CHK(!is_reset(d));
        CHK(guards_ok(&f));
        PASS();
    } _test_next:;
    return failures;
}

static int t_rng_twins(void)
{
    int failures = 0;
    TEST("rvvirtio: entropy twins (request cap removed, readable refusal removed) are caught") {
        static struct fx f;
        g_rapi = &k_rreal;
        g_api = &k_real;
        struct clamp_probe good = run_clamp_case(&f);
        struct readable_probe rgood = run_readable_case(&f);
        g_rapi = &k_rmut;
        g_api = &k_mut;
        struct clamp_probe bad = run_clamp_case(&f);
        struct readable_probe rbad = run_readable_case(&f);
        g_rapi = &k_rreal;
        g_api = &k_real;
        printf("\n    rvvirtio twin rng-clamp: real used=%u past-cap-untouched=%d, "
               "twin used=%u past-cap-untouched=%d -> %s\n",
               good.used, good.past_cap_untouched, bad.used, bad.past_cap_untouched,
               bad.past_cap_untouched ? "MISSED" : "DETECTED");
        printf("    rvvirtio twin rng-readable: real used=%u malformed=%u, "
               "twin used=%u malformed=%u -> %s\n",
               rgood.used, (unsigned)rgood.malformed, rbad.used, (unsigned)rbad.malformed,
               rbad.used != 0 ? "DETECTED" : "MISSED");
        CHK(good.past_cap_untouched);
        CHK(!bad.past_cap_untouched);
        CHK_EQ(bad.used, RVVIRTIO_RNG_REQ_BYTES_MAX + 904u);
        CHK_EQ(rgood.used, 0u);
        CHK(rbad.used != 0u);
        CHK_EQ(rbad.malformed, 0u);
        PASS();
    } _test_next:;
    return failures;
}

int test_rvvirtio(void)
{
    int failures = 0;
    g_api = &k_real;
    g_checks = 0;
    failures += t_handshake();
    failures += t_features_ok_rejection();
    failures += t_blk_roundtrip();
    failures += t_blk_indirect_and_suppress();
    failures += t_blk_read_only();
    failures += t_blk_range();
    failures += t_hostile_descriptors();
    failures += t_undersized_status_and_ordering();
    failures += t_notify_before_driver_ok();
    failures += t_callback_failure();
    failures += t_chain_loops();
    failures += t_net_config_and_tx();
    failures += t_net_rx();
    failures += t_net_rx_hostile();
    failures += t_mutation_twins();
    failures += t_console_handshake();
    failures += t_console_ready_before_driver_ok();
    failures += t_console_early_other_queue();
    failures += t_console_early_queue_not_ready();
    failures += t_console_early_without_features_ok();
    failures += t_console_early_after_reset();
    failures += t_console_early_after_needs_reset();
    failures += t_console_data();
    failures += t_console_writable_consumed();
    failures += t_console_close_reset();
    failures += t_console_twin();
    failures += t_freebsd_attach_sequence();
    failures += t_blk_request_bound();
    failures += t_blk_request_bound_twin();
    failures += t_blk_notify_cap();
    failures += t_rng_freebsd_attach_harvest();
    failures += t_rng_order_and_guards();
    failures += t_rng_bounds();
    failures += t_rng_notify_budget();
    failures += t_rng_reset_pending();
    failures += t_rng_twins();
    printf("=== rvvirtio: %u checks, %d failures ===\n", g_checks, failures);
    return failures;
}
