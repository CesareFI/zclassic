/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: package-local smoke test: a guest driver over a byte array drives
 * virtio-blk, virtio-net and the multiport console through the MMIO surface.
 * The exhaustive hostile-guest suite lives in tests/harness/src/test_rvvirtio.c. */
#include "rvvirtio/rvvirtio.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define BASE UINT64_C(0x1000)
#define RAM_SIZE 0x8000u
#define CHECK(expr) do { if (!(expr)) { \
    fprintf(stderr, "rvvirtio test failed: %s:%d: %s\n", __FILE__, __LINE__, #expr); \
    return 1; } } while (0)

static uint8_t g_ram[RAM_SIZE];
static uint8_t g_disk[4096];
static unsigned g_tx_calls;
static size_t g_guest_bytes;

static bool mem_read(void *ctx, uint64_t gpa, void *buf, size_t n)
{
    (void)ctx;
    if (gpa < BASE || gpa - BASE > RAM_SIZE || n > RAM_SIZE - (gpa - BASE))
        return false;
    memcpy(buf, g_ram + (gpa - BASE), n);
    return true;
}

static bool mem_write(void *ctx, uint64_t gpa, const void *buf, size_t n)
{
    (void)ctx;
    if (gpa < BASE || gpa - BASE > RAM_SIZE || n > RAM_SIZE - (gpa - BASE))
        return false;
    memcpy(g_ram + (gpa - BASE), buf, n);
    return true;
}

static uint64_t disk_size(void *ctx) { (void)ctx; return sizeof(g_disk); }
static bool disk_pread(void *ctx, uint64_t off, void *buf, size_t n)
{
    (void)ctx;
    if (off > sizeof(g_disk) || n > sizeof(g_disk) - off)
        return false;
    memcpy(buf, g_disk + off, n);
    return true;
}
static void net_tx(void *ctx, const uint8_t *frame, size_t len)
{
    (void)ctx; (void)frame;
    g_tx_calls += len == 60u ? 1u : 0u;
}
static size_t con_from_guest(void *ctx, uint32_t port, const uint8_t *buf, size_t n)
{
    (void)ctx; (void)port; (void)buf;
    g_guest_bytes += n;
    return n;
}

static void w16(uint64_t o, uint16_t v) { g_ram[o] = (uint8_t)v; g_ram[o + 1] = (uint8_t)(v >> 8); }
static void w32(uint64_t o, uint32_t v) { w16(o, (uint16_t)v); w16(o + 2, (uint16_t)(v >> 16)); }
static void w64(uint64_t o, uint64_t v) { w32(o, (uint32_t)v); w32(o + 4, (uint32_t)(v >> 32)); }

/* Queue q lives at 0x1000 * q: desc +0, avail +0x200, used +0x400 (size 16). */
static void desc(unsigned q, unsigned i, uint64_t off, uint32_t len, uint16_t fl, unsigned next)
{
    uint64_t o = 0x1000u * q + 16u * i;
    w64(o, BASE + off);
    w32(o + 8, len);
    w16(o + 12, fl);
    w16(o + 14, (uint16_t)next);
}

static void post(unsigned q, unsigned head)
{
    uint64_t a = 0x1000u * q + 0x200u;
    uint16_t idx = (uint16_t)(g_ram[a + 2] | (g_ram[a + 3] << 8));
    w16(a + 4 + 2u * (idx % 16u), (uint16_t)head);
    w16(a + 2, (uint16_t)(idx + 1u));
}

static uint16_t used(unsigned q)
{
    uint64_t a = 0x1000u * q + 0x400u + 2u;
    return (uint16_t)(g_ram[a] | (g_ram[a + 1] << 8));
}

static void bring_up(struct rvvirtio_dev *d, unsigned nq)
{
    rvvirtio_mmio_write(d, RVVIRTIO_REG_STATUS, 0);
    rvvirtio_mmio_write(d, RVVIRTIO_REG_STATUS, 3);
    rvvirtio_mmio_write(d, RVVIRTIO_REG_DRIVER_FEATURES_SEL, 0);
    rvvirtio_mmio_write(d, RVVIRTIO_REG_DEVICE_FEATURES_SEL, 0);
    rvvirtio_mmio_write(d, RVVIRTIO_REG_DRIVER_FEATURES,
                        rvvirtio_mmio_read(d, RVVIRTIO_REG_DEVICE_FEATURES));
    rvvirtio_mmio_write(d, RVVIRTIO_REG_DRIVER_FEATURES_SEL, 1);
    rvvirtio_mmio_write(d, RVVIRTIO_REG_DRIVER_FEATURES, 1);
    rvvirtio_mmio_write(d, RVVIRTIO_REG_STATUS, 11);
    for (unsigned q = 0; q < nq; q++) {
        uint64_t a = BASE + 0x1000u * q;
        rvvirtio_mmio_write(d, RVVIRTIO_REG_QUEUE_SEL, q);
        rvvirtio_mmio_write(d, RVVIRTIO_REG_QUEUE_NUM, 16);
        rvvirtio_mmio_write(d, RVVIRTIO_REG_QUEUE_DESC_LOW, (uint32_t)a);
        rvvirtio_mmio_write(d, RVVIRTIO_REG_QUEUE_DRIVER_LOW, (uint32_t)(a + 0x200u));
        rvvirtio_mmio_write(d, RVVIRTIO_REG_QUEUE_DEVICE_LOW, (uint32_t)(a + 0x400u));
        rvvirtio_mmio_write(d, RVVIRTIO_REG_QUEUE_READY, 1);
    }
    rvvirtio_mmio_write(d, RVVIRTIO_REG_STATUS, 15);
}

static int test_blk(const struct rvvirtio_mem *mem)
{
    static struct rvvirtio_blk b;
    struct rvvirtio_blk_backend be = {NULL, disk_size, disk_pread, NULL, NULL, NULL};
    for (unsigned i = 0; i < sizeof(g_disk); i++)
        g_disk[i] = (uint8_t)(i * 5u);
    CHECK(rvvirtio_blk_init(&b, mem, &be, false));
    CHECK(b.read_only); /* no pwrite: forced read-only */
    bring_up(&b.dev, 1);
    CHECK(rvvirtio_mmio_read(&b.dev, RVVIRTIO_REG_MAGIC) == RVVIRTIO_MAGIC);
    CHECK(rvvirtio_mmio_read(&b.dev, RVVIRTIO_REG_CONFIG) == 8u);
    w32(0x4000, RVVIRTIO_BLK_T_IN);
    w64(0x4008, 2);
    desc(0, 0, 0x4000, 16, 1, 1);
    desc(0, 1, 0x4100, 512, 3, 2);
    desc(0, 2, 0x4400, 1, 2, 0);
    post(0, 0);
    rvvirtio_mmio_write(&b.dev, RVVIRTIO_REG_QUEUE_NOTIFY, 0);
    CHECK(g_ram[0x4400] == RVVIRTIO_BLK_S_OK);
    CHECK(memcmp(g_ram + 0x4100, g_disk + 1024, 512) == 0);
    CHECK(used(0) == 1u);
    return 0;
}

static int test_net(const struct rvvirtio_mem *mem)
{
    static struct rvvirtio_net n;
    static const uint8_t mac[6] = {2, 0, 0, 0, 0, 1};
    uint8_t frame[60];
    memset(frame, 0x42, sizeof(frame));
    CHECK(rvvirtio_net_init(&n, mem, mac, net_tx, NULL));
    bring_up(&n.dev, 2);
    desc(1, 0, 0x4000, 12, 1, 1);
    desc(1, 1, 0x4100, 60, 0, 0);
    post(1, 0);
    rvvirtio_mmio_write(&n.dev, RVVIRTIO_REG_QUEUE_NOTIFY, 1);
    CHECK(g_tx_calls == 1u && used(1) == 1u);
    CHECK(!rvvirtio_net_receive(&n, frame, sizeof(frame))); /* no buffer */
    desc(0, 0, 0x4800, 2048, 2, 0);
    post(0, 0);
    CHECK(rvvirtio_net_receive(&n, frame, sizeof(frame)));
    CHECK(memcmp(g_ram + 0x4800 + 12, frame, sizeof(frame)) == 0);
    return 0;
}

static int test_console(const struct rvvirtio_mem *mem)
{
    static struct rvvirtio_console c;
    struct rvvirtio_console_ops ops = {NULL, con_from_guest, NULL};
    CHECK(rvvirtio_console_init(&c, mem, &ops, 2));
    bring_up(&c.dev, 6);
    CHECK(rvvirtio_mmio_read(&c.dev, RVVIRTIO_REG_CONFIG + 4) == 2u);
    CHECK(rvvirtio_console_port_open(&c, 1, "ssh"));
    CHECK(rvvirtio_console_port_generation(&c, 1) == 1u);
    /* guest: DEVICE_READY on control tx (queue 3), control rx buffers on 2 */
    for (unsigned i = 0; i < 4; i++) {
        desc(2, i, 0x5000u + 0x100u * i, 64, 2, 0);
        post(2, i);
    }
    w32(0x4000, 0);
    w16(0x4004, 0);
    w16(0x4006, 1);
    desc(3, 0, 0x4000, 8, 0, 0);
    post(3, 0);
    rvvirtio_mmio_write(&c.dev, RVVIRTIO_REG_QUEUE_NOTIFY, 3);
    CHECK(used(2) == 2u); /* DEVICE_ADD for both ports */
    CHECK(rvvirtio_console_port_write(&c, 1, (const uint8_t *)"x", 1) == 0);
    return 0;
}

int main(void)
{
    struct rvvirtio_mem mem = {NULL, mem_read, mem_write, NULL};
    if (test_blk(&mem) != 0)
        return 1;
    memset(g_ram, 0, sizeof(g_ram));
    if (test_net(&mem) != 0)
        return 1;
    memset(g_ram, 0, sizeof(g_ram));
    if (test_console(&mem) != 0)
        return 1;
    puts("rvvirtio standalone: ok");
    return 0;
}
