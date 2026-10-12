/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Device tree writer and reader (platform/modules/fdt): a realistic riscv64
 * machine tree round trip, hand-computed header layout and de-duplicated
 * strings, fail-closed reader errors, and writer errors. Every expected number
 * below is derived by hand in the comments, not read back from the code. */

#include "test/test_core.h"

#include "fdt/fdt.h"

#include "base/serialize_le.h"

#include <string.h>

#define SV(s) ((const uint8_t *)(s)), (sizeof(s))

static const uint8_t k_u32_2[4] = {0, 0, 0, 2};
static const uint8_t k_u32_timebase[4] = {0x00, 0x98, 0x96, 0x80};
static const uint8_t k_u32_0[4] = {0, 0, 0, 0};
static const uint8_t k_u32_1[4] = {0, 0, 0, 1};
static const uint8_t k_u32_10[4] = {0, 0, 0, 10};
static const uint8_t k_u32_uartclk[4] = {0x00, 0x38, 0x40, 0x00};
static const uint8_t k_reg_mem[16] = {0, 0, 0, 0, 0x80, 0, 0, 0, 0, 0, 0, 0, 0x40, 0, 0, 0};
static const uint8_t k_reg_uart[16] = {0, 0, 0, 0, 0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0x00};
static const uint8_t k_reg_virtio[16] = {0, 0, 0, 0, 0x10, 0x00, 0x10, 0x00,
                                         0, 0, 0, 0, 0, 0, 0x10, 0x00};

/* Every property of the riscv tree below, with the exact bytes written. */
static const struct {
    const char *path;
    const char *name;
    const uint8_t *data;
    size_t len;
} k_props[] = {
    {"/", "#address-cells", k_u32_2, sizeof k_u32_2},
    {"/", "#size-cells", k_u32_2, sizeof k_u32_2},
    {"/", "compatible", SV("riscv-virtio")},
    {"/chosen", "bootargs", SV("console=ttyS0")},
    {"/chosen", "stdout-path", SV("/soc/uart@10000000")},
    {"/cpus", "timebase-frequency", k_u32_timebase, sizeof k_u32_timebase},
    {"/cpus/cpu@0", "device_type", SV("cpu")},
    {"/cpus/cpu@0", "reg", k_u32_0, sizeof k_u32_0},
    {"/cpus/cpu@0", "status", SV("okay")},
    {"/cpus/cpu@0", "riscv,isa", SV("rv64imafdc")},
    {"/cpus/cpu@0", "mmu-type", SV("riscv,sv39")},
    {"/cpus/cpu@0", "compatible", SV("riscv")},
    {"/cpus/cpu@0/interrupt-controller", "#interrupt-cells", k_u32_1, sizeof k_u32_1},
    {"/cpus/cpu@0/interrupt-controller", "interrupt-controller", NULL, 0},
    {"/cpus/cpu@0/interrupt-controller", "compatible", SV("riscv,cpu-intc")},
    {"/memory@80000000", "device_type", SV("memory")},
    {"/memory@80000000", "reg", k_reg_mem, sizeof k_reg_mem},
    {"/soc", "compatible", SV("simple-bus")},
    {"/soc", "ranges", NULL, 0},
    {"/soc/uart@10000000", "compatible", SV("ns16550a")},
    {"/soc/uart@10000000", "reg", k_reg_uart, sizeof k_reg_uart},
    {"/soc/uart@10000000", "interrupts", k_u32_10, sizeof k_u32_10},
    {"/soc/uart@10000000", "clock-frequency", k_u32_uartclk, sizeof k_u32_uartclk},
    {"/soc/virtio_mmio@10001000", "compatible", SV("virtio,mmio")},
    {"/soc/virtio_mmio@10001000", "reg", k_reg_virtio, sizeof k_reg_virtio},
    {"/soc/virtio_mmio@10001000", "interrupts", k_u32_1, sizeof k_u32_1},
};

/* The sixteen distinct property names of the riscv tree. */
static const char *const k_unique_names[] = {
    "#address-cells", "#size-cells", "compatible", "bootargs", "stdout-path",
    "timebase-frequency", "device_type", "reg", "status", "riscv,isa",
    "mmu-type", "#interrupt-cells", "interrupt-controller", "ranges",
    "interrupts", "clock-frequency",
};

#define TRY(expr) do { enum fdt_status try_st_ = (expr); if (try_st_ != FDT_OK) return try_st_; } while (0)

static uint32_t be32_at(const uint8_t *p) { return zcl_read_u32_be(p); }
static void put32(uint8_t *p, uint32_t v) { zcl_write_u32_be(p, v); }

/* The riscv64 machine tree: / with 2/2 cells, /chosen, /cpus with cpu@0 and its
 * interrupt controller, /memory@80000000, and /soc with a uart and virtio-mmio. */
static enum fdt_status build_riscv(uint8_t *buf, size_t cap, size_t *len)
{
    struct fdt_writer w;
    TRY(fdt_writer_init(&w, buf, cap));
    TRY(fdt_begin_node(&w, ""));
    TRY(fdt_prop_u32(&w, "#address-cells", 2));
    TRY(fdt_prop_u32(&w, "#size-cells", 2));
    TRY(fdt_prop_string(&w, "compatible", "riscv-virtio"));
    TRY(fdt_begin_node(&w, "chosen"));
    TRY(fdt_prop_string(&w, "bootargs", "console=ttyS0"));
    TRY(fdt_prop_string(&w, "stdout-path", "/soc/uart@10000000"));
    TRY(fdt_end_node(&w));
    TRY(fdt_begin_node(&w, "cpus"));
    TRY(fdt_prop_u32(&w, "timebase-frequency", 10000000));
    TRY(fdt_begin_node(&w, "cpu@0"));
    TRY(fdt_prop_string(&w, "device_type", "cpu"));
    TRY(fdt_prop_u32(&w, "reg", 0));
    TRY(fdt_prop_string(&w, "status", "okay"));
    TRY(fdt_prop_string(&w, "riscv,isa", "rv64imafdc"));
    TRY(fdt_prop_string(&w, "mmu-type", "riscv,sv39"));
    TRY(fdt_prop_string(&w, "compatible", "riscv"));
    TRY(fdt_begin_node(&w, "interrupt-controller"));
    TRY(fdt_prop_u32(&w, "#interrupt-cells", 1));
    TRY(fdt_prop(&w, "interrupt-controller", NULL, 0));
    TRY(fdt_prop_string(&w, "compatible", "riscv,cpu-intc"));
    TRY(fdt_end_node(&w));
    TRY(fdt_end_node(&w));
    TRY(fdt_end_node(&w));
    TRY(fdt_begin_node(&w, "memory@80000000"));
    TRY(fdt_prop_string(&w, "device_type", "memory"));
    TRY(fdt_prop(&w, "reg", k_reg_mem, sizeof k_reg_mem));
    TRY(fdt_end_node(&w));
    TRY(fdt_begin_node(&w, "soc"));
    TRY(fdt_prop_string(&w, "compatible", "simple-bus"));
    TRY(fdt_prop(&w, "ranges", NULL, 0));
    TRY(fdt_begin_node(&w, "uart@10000000"));
    TRY(fdt_prop_string(&w, "compatible", "ns16550a"));
    TRY(fdt_prop(&w, "reg", k_reg_uart, sizeof k_reg_uart));
    TRY(fdt_prop_u32(&w, "interrupts", 10));
    TRY(fdt_prop_u32(&w, "clock-frequency", 3686400));
    TRY(fdt_end_node(&w));
    TRY(fdt_begin_node(&w, "virtio_mmio@10001000"));
    TRY(fdt_prop_string(&w, "compatible", "virtio,mmio"));
    TRY(fdt_prop(&w, "reg", k_reg_virtio, sizeof k_reg_virtio));
    TRY(fdt_prop_u32(&w, "interrupts", 1));
    TRY(fdt_end_node(&w));
    TRY(fdt_end_node(&w));
    TRY(fdt_end_node(&w));
    return fdt_finish(&w, len);
}

/* Small tree for the header known-answer: one reservation (0x80000000, 0x1000),
 * root { #address-cells = 2; cpus { compatible = "x"; } }. */
static enum fdt_status build_small(uint8_t *buf, size_t cap, size_t *len)
{
    struct fdt_writer w;
    TRY(fdt_writer_init(&w, buf, cap));
    TRY(fdt_add_reservation(&w, UINT64_C(0x80000000), UINT64_C(0x1000)));
    TRY(fdt_begin_node(&w, ""));
    TRY(fdt_prop_u32(&w, "#address-cells", 2));
    TRY(fdt_begin_node(&w, "cpus"));
    TRY(fdt_prop_string(&w, "compatible", "x"));
    TRY(fdt_end_node(&w));
    TRY(fdt_end_node(&w));
    return fdt_finish(&w, len);
}

/* Hand-built blob: depth nested nodes, each named "", then their closing ends
 * and FDT_END. The writer refuses past FDT_MAX_DEPTH, so the reader's own
 * limit is exercised with raw bytes. */
static size_t build_nest(uint8_t *b, size_t depth)
{
    size_t s = 56, i;
    memset(b, 0, 56);
    for (i = 0; i < depth; i++) { put32(b + s, 1); put32(b + s + 4, 0); s += 8; }
    for (i = 0; i < depth; i++) { put32(b + s, 2); s += 4; }
    put32(b + s, 9);
    s += 4;
    put32(b, 0xd00dfeedu); put32(b + 4, (uint32_t)s); put32(b + 8, 56);
    put32(b + 12, (uint32_t)s); put32(b + 16, 40); put32(b + 20, 17);
    put32(b + 24, 16); put32(b + 32, 0); put32(b + 36, (uint32_t)(s - 56));
    return s;
}

int test_test_fdt(void);
int test_test_fdt(void)
{
    int failures = 0;

    TEST("riscv tree: writes, checks, and every property reads back exactly") {
        static uint8_t blob[4096];
        size_t len = 0;
        ASSERT_EQ(build_riscv(blob, sizeof blob, &len), FDT_OK);
        ASSERT_EQ(fdt_check(blob, len), FDT_OK);
        for (size_t i = 0; i < sizeof k_props / sizeof k_props[0]; i++) {
            fdt_node_t node = 0;
            const uint8_t *d = NULL;
            size_t dl = 0;
            ASSERT_EQ(fdt_find_node(blob, len, k_props[i].path, &node), FDT_OK);
            ASSERT_EQ(fdt_get_prop(blob, len, node, k_props[i].name, &d, &dl), FDT_OK);
            ASSERT_EQ(dl, k_props[i].len);
            ASSERT(dl == 0 || memcmp(d, k_props[i].data, dl) == 0);
        }
        PASS();
    }

    TEST("riscv tree: path lookup, unit-address-free segments, and misses") {
        static uint8_t blob[4096];
        size_t len = 0;
        fdt_node_t exact = 0, bare = 0, root = 0;
        ASSERT_EQ(build_riscv(blob, sizeof blob, &len), FDT_OK);
        ASSERT_EQ(fdt_find_node(blob, len, "/cpus/cpu@0", &exact), FDT_OK);
        ASSERT_EQ(fdt_find_node(blob, len, "/cpus/cpu", &bare), FDT_OK);
        ASSERT_EQ(bare, exact);
        ASSERT_EQ(fdt_find_node(blob, len, "/", &root), FDT_OK);
        ASSERT_EQ(fdt_find_node(blob, len, "/cpus/cpu@1", &exact), FDT_ERR_NOT_FOUND);
        ASSERT_EQ(fdt_find_node(blob, len, "cpus", &exact), FDT_ERR_ARG);
        {
            const uint8_t *d = NULL;
            size_t dl = 0;
            ASSERT_EQ(fdt_get_prop(blob, len, root, "no-such-prop", &d, &dl), FDT_ERR_NOT_FOUND);
        }
        PASS();
    }

    TEST("known answer: header, reservation and strings of the small tree") {
        static uint8_t blob[256];
        size_t len = 0;
        ASSERT_EQ(build_small(blob, sizeof blob, &len), FDT_OK);
        /* 40 header + 16 reservation + 16 terminator = 72 structure base.
         * Structure: 8 root + 16 #address-cells + 12 cpus + 16 compatible
         * + 4 + 4 + 4 (END) = 64. Strings: "#address-cells\0" 15 + "compatible\0" 11 = 26.
         * Total 72 + 64 + 26 = 162. */
        ASSERT_EQ(len, 162u);
        ASSERT_EQ(be32_at(blob + 0), 0xd00dfeedu);
        ASSERT_EQ(be32_at(blob + 4), 162u);
        ASSERT_EQ(be32_at(blob + 8), 72u);
        ASSERT_EQ(be32_at(blob + 12), 136u);
        ASSERT_EQ(be32_at(blob + 16), 40u);
        ASSERT_EQ(be32_at(blob + 20), 17u);
        ASSERT_EQ(be32_at(blob + 24), 16u);
        ASSERT_EQ(be32_at(blob + 32), 26u);
        ASSERT_EQ(be32_at(blob + 36), 64u);
        ASSERT_EQ(be32_at(blob + 40), 0u);
        ASSERT_EQ(be32_at(blob + 44), 0x80000000u);
        ASSERT_EQ(be32_at(blob + 48), 0u);
        ASSERT_EQ(be32_at(blob + 52), 0x1000u);
        ASSERT_EQ(be32_at(blob + 56), 0u);
        ASSERT_EQ(be32_at(blob + 60), 0u);
        ASSERT_EQ(be32_at(blob + 64), 0u);
        ASSERT_EQ(be32_at(blob + 68), 0u);
        ASSERT_EQ(be32_at(blob + 72), 1u);
        ASSERT_EQ(be32_at(blob + 132), 9u);
        ASSERT(memcmp(blob + 136, "#address-cells\0compatible\0", 26) == 0);
        ASSERT_EQ(fdt_check(blob, len), FDT_OK);
        PASS();
    }

    TEST("de-duplicated strings: riscv tree has 16 names, 192 bytes") {
        static uint8_t blob[4096];
        size_t len = 0, expect = 0, n = sizeof k_unique_names / sizeof k_unique_names[0];
        ASSERT_EQ(build_riscv(blob, sizeof blob, &len), FDT_OK);
        /* Hand sums of (strlen + 1): 15 12 11 9 12 19 12 4 7 10 9 17 17 7 11 16 = 192. */
        for (size_t i = 0; i < n; i++) expect += strlen(k_unique_names[i]) + 1u;
        ASSERT_EQ(n, 16u);
        ASSERT_EQ(expect, 192u);
        ASSERT_EQ(be32_at(blob + 32), 192u);
        ASSERT_EQ(be32_at(blob + 4), (uint32_t)len);
        PASS();
    }

    TEST("fail closed: corrupted magic is BAD_MAGIC") {
        static uint8_t blob[256], mut[256];
        size_t len = 0;
        ASSERT_EQ(build_small(blob, sizeof blob, &len), FDT_OK);
        memcpy(mut, blob, len);
        mut[0] ^= 0xffu;
        ASSERT_EQ(fdt_check(mut, len), FDT_ERR_BAD_MAGIC);
        PASS();
    }

    TEST("fail closed: truncated totalsize is TOTALSIZE") {
        static uint8_t blob[256], mut[256];
        size_t len = 0;
        ASSERT_EQ(build_small(blob, sizeof blob, &len), FDT_OK);
        memcpy(mut, blob, len);
        put32(mut + 4, 158u);
        ASSERT_EQ(fdt_check(mut, len), FDT_ERR_TOTALSIZE);
        ASSERT_EQ(fdt_check(blob, len - 1u), FDT_ERR_TOTALSIZE);
        PASS();
    }

    TEST("fail closed: misaligned structure offset is ALIGN") {
        static uint8_t blob[256], mut[256];
        size_t len = 0;
        ASSERT_EQ(build_small(blob, sizeof blob, &len), FDT_OK);
        memcpy(mut, blob, len);
        put32(mut + 8, 73u);
        ASSERT_EQ(fdt_check(mut, len), FDT_ERR_ALIGN);
        PASS();
    }

    TEST("fail closed: FDT_END missing is NO_END") {
        static uint8_t blob[256], mut[256];
        size_t len = 0;
        ASSERT_EQ(build_small(blob, sizeof blob, &len), FDT_OK);
        memcpy(mut, blob, len);
        put32(mut + 72u + 60u, 4u);
        ASSERT_EQ(fdt_check(mut, len), FDT_ERR_NO_END);
        PASS();
    }

    TEST("fail closed: string offset out of range is STRING_OFFSET") {
        static uint8_t blob[256], mut[256];
        size_t len = 0;
        ASSERT_EQ(build_small(blob, sizeof blob, &len), FDT_OK);
        memcpy(mut, blob, len);
        put32(mut + 72u + 8u + 8u, 0x1000u);
        ASSERT_EQ(fdt_check(mut, len), FDT_ERR_STRING_OFFSET);
        PASS();
    }

    TEST("fail closed: nesting past FDT_MAX_DEPTH is NESTING, at the limit it passes") {
        static uint8_t blob[512];
        size_t len = build_nest(blob, FDT_MAX_DEPTH);
        ASSERT_EQ(fdt_check(blob, len), FDT_OK);
        len = build_nest(blob, FDT_MAX_DEPTH + 1u);
        ASSERT_EQ(fdt_check(blob, len), FDT_ERR_NESTING);
        PASS();
    }

    TEST("writer: a tiny buffer is NO_SPACE") {
        uint8_t buf[64];
        struct fdt_writer w;
        ASSERT_EQ(fdt_writer_init(&w, buf, 60), FDT_OK);
        /* Header 40 + terminator 16 + root begin 8 = 64 bytes needed. */
        ASSERT_EQ(fdt_begin_node(&w, ""), FDT_ERR_NO_SPACE);
        ASSERT_EQ(fdt_writer_init(&w, buf, 10), FDT_OK);
        ASSERT_EQ(fdt_begin_node(&w, ""), FDT_ERR_NO_SPACE);
        PASS();
    }

    TEST("writer: finishing before the root closes is NOT_FINISHED") {
        static uint8_t buf[256];
        struct fdt_writer w;
        size_t len = 0;
        ASSERT_EQ(fdt_writer_init(&w, buf, sizeof buf), FDT_OK);
        ASSERT_EQ(fdt_finish(&w, &len), FDT_ERR_NOT_FINISHED);
        ASSERT_EQ(fdt_begin_node(&w, ""), FDT_OK);
        ASSERT_EQ(fdt_finish(&w, &len), FDT_ERR_NOT_FINISHED);
        ASSERT_EQ(fdt_end_node(&w), FDT_OK);
        ASSERT_EQ(fdt_finish(&w, &len), FDT_OK);
        PASS();
    }

    TEST("writer: bad names and misplaced tokens are typed errors") {
        static uint8_t buf[512];
        struct fdt_writer w;
        ASSERT_EQ(fdt_writer_init(&w, buf, sizeof buf), FDT_OK);
        ASSERT_EQ(fdt_prop_u32(&w, "x", 1), FDT_ERR_NESTING);
        ASSERT_EQ(fdt_begin_node(&w, "named-root"), FDT_ERR_BAD_NAME);
        ASSERT_EQ(fdt_begin_node(&w, ""), FDT_OK);
        ASSERT_EQ(fdt_begin_node(&w, "a/b"), FDT_ERR_BAD_NAME);
        ASSERT_EQ(fdt_begin_node(&w, ""), FDT_ERR_BAD_NAME);
        ASSERT_EQ(fdt_prop_u32(&w, "x/y", 1), FDT_ERR_BAD_NAME);
        ASSERT_EQ(fdt_add_reservation(&w, 0, 1), FDT_ERR_STATE);
        PASS();
    }

    TEST("reader: a counterfeit node inside a property payload is BAD_NODE") {
        static uint8_t blob[512];
        struct fdt_writer w;
        fdt_node_t root = 0, fake;
        const uint8_t *pay = NULL, *out = blob;
        size_t len = 0, plen = 0, olen = 77;
        uint8_t body[20];
        /* BEGIN_NODE, empty name, PROP, huge length, string offset 0. */
        put32(body, 1);
        put32(body + 4, 0);
        put32(body + 8, 3);
        put32(body + 12, 0x7fffff00u);
        put32(body + 16, 0);
        ASSERT_EQ(fdt_writer_init(&w, blob, sizeof blob), FDT_OK);
        ASSERT_EQ(fdt_begin_node(&w, ""), FDT_OK);
        ASSERT_EQ(fdt_prop(&w, "blob", body, sizeof body), FDT_OK);
        ASSERT_EQ(fdt_end_node(&w), FDT_OK);
        ASSERT_EQ(fdt_finish(&w, &len), FDT_OK);
        ASSERT_EQ(fdt_check(blob, len), FDT_OK);
        ASSERT_EQ(fdt_find_node(blob, len, "/", &root), FDT_OK);
        /* Healthy control: the real root returns the exact length. */
        ASSERT_EQ(fdt_get_prop(blob, len, root, "blob", &pay, &plen), FDT_OK);
        ASSERT_EQ(plen, sizeof body);
        fake = (size_t)(pay - blob);
        ASSERT_EQ(be32_at(blob + fake), 1u);
        ASSERT_EQ(fdt_get_prop(blob, len, fake, "blob", &out, &olen), FDT_ERR_BAD_NODE);
        ASSERT(out == blob);
        ASSERT_EQ(olen, 77u);
        PASS();
    }

    TEST("reader: a stale node offset that is now inside a payload is BAD_NODE") {
        static uint8_t blob[512], other[512];
        struct fdt_writer w;
        fdt_node_t n = 0;
        const uint8_t *out = blob, *pay = NULL;
        size_t la = 0, lb = 0, olen = 77, plen = 0;
        uint8_t body[24];
        ASSERT_EQ(fdt_writer_init(&w, other, sizeof other), FDT_OK);
        ASSERT_EQ(fdt_begin_node(&w, ""), FDT_OK);
        ASSERT_EQ(fdt_prop_u32(&w, "blob", 0), FDT_OK);
        ASSERT_EQ(fdt_begin_node(&w, "n"), FDT_OK);
        ASSERT_EQ(fdt_prop_u32(&w, "blob", 5), FDT_OK);
        ASSERT_EQ(fdt_end_node(&w), FDT_OK);
        ASSERT_EQ(fdt_end_node(&w), FDT_OK);
        ASSERT_EQ(fdt_finish(&w, &la), FDT_OK);
        ASSERT_EQ(fdt_find_node(other, la, "/n", &n), FDT_OK);
        ASSERT_EQ(fdt_get_prop(other, la, n, "blob", &pay, &plen), FDT_OK);
        ASSERT_EQ(plen, 4u);
        /* Blob B: root { blob = <filler, BEGIN_NODE, "", PROP, huge, 0>; }
         * puts the counterfeit BEGIN_NODE exactly at the old offset of /n. */
        put32(body, 0);
        put32(body + 4, 1);
        put32(body + 8, 0);
        put32(body + 12, 3);
        put32(body + 16, 0x7fffff00u);
        put32(body + 20, 0);
        ASSERT_EQ(fdt_writer_init(&w, blob, sizeof blob), FDT_OK);
        ASSERT_EQ(fdt_begin_node(&w, ""), FDT_OK);
        ASSERT_EQ(fdt_prop(&w, "blob", body, sizeof body), FDT_OK);
        ASSERT_EQ(fdt_end_node(&w), FDT_OK);
        ASSERT_EQ(fdt_finish(&w, &lb), FDT_OK);
        ASSERT_EQ(fdt_check(blob, lb), FDT_OK);
        ASSERT_EQ(be32_at(blob + n), 1u);
        ASSERT_EQ(fdt_get_prop(blob, lb, n, "blob", &out, &olen), FDT_ERR_BAD_NODE);
        ASSERT(out == blob);
        ASSERT_EQ(olen, 77u);
        PASS();
    }

    TEST("reader: a PROP whose length runs past the structure block is typed, never OK") {
        static uint8_t blob[512];
        struct fdt_writer w;
        fdt_node_t root = 0;
        const uint8_t *pay = NULL, *out = blob;
        size_t len = 0, plen = 0, olen = 77;
        ASSERT_EQ(fdt_writer_init(&w, blob, sizeof blob), FDT_OK);
        ASSERT_EQ(fdt_begin_node(&w, ""), FDT_OK);
        ASSERT_EQ(fdt_prop_u32(&w, "blob", 9), FDT_OK);
        ASSERT_EQ(fdt_end_node(&w), FDT_OK);
        ASSERT_EQ(fdt_finish(&w, &len), FDT_OK);
        ASSERT_EQ(fdt_find_node(blob, len, "/", &root), FDT_OK);
        ASSERT_EQ(fdt_get_prop(blob, len, root, "blob", &pay, &plen), FDT_OK);
        ASSERT_EQ(plen, 4u);
        put32((uint8_t *)blob + (size_t)(pay - blob) - 8, 0x7fffff00u);
        ASSERT_EQ(fdt_get_prop(blob, len, root, "blob", &out, &olen), FDT_ERR_TRUNCATED);
        ASSERT(out == blob);
        ASSERT_EQ(olen, 77u);
        PASS();
    }

_test_next:;
    if (failures == 0)
        printf("test_test_fdt: all passed\n");
    else
        printf("test_test_fdt: %d FAILED\n", failures);
    return failures;
}
