/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: proofs for the built-in RISC-V machine. Small supervisor guests
 * from tests/fixtures/rvmachine (MANIFEST holds each image's sha256, checked
 * before it runs) go through the real machine: console text, stop reason and
 * the retired, skip and firmware-call counts are known answers and repeat
 * exactly. Also the device tree, the loader's refusals, the disk overlay, the
 * console input cursors, the console script and the run-loop stops.
 *
 * Mutation twins recompile the run loop and the disk in this translation unit
 * with one policy changed each, and must make the matching proof fail: the
 * user-mode counter enable at entry, the remote-fence flush, finishing block
 * requests before a wfi waits, charging device data movement to the work
 * budget, and the overlay cap. */
#include "test/test_core.h"

#include "base/serialize_le.h"
#include "crypto/sha256.h"
#include "fdt/fdt.h"
#include "rvmachine/rvmachine.h"

#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* ---- mutation twins: same sources, policy points under test control ---- */
static uint64_t twin_scounteren = RVMACHINE_SCOUNTEREN;
static bool twin_service = true;
static bool twin_drain = true;
static bool twin_rfence = true;
static bool twin_charge = true;
static bool twin_wait_latch = true;

#define RVMACHINE_TWIN_BUILD 1
#define RVMACHINE_POLICY_SCOUNTEREN twin_scounteren
#define RVMACHINE_POLICY_SERVICE twin_service
#define RVMACHINE_POLICY_DRAIN twin_drain
#define RVMACHINE_POLICY_RFENCE twin_rfence
#define RVMACHINE_POLICY_DEVICE_CHARGE twin_charge
#define RVMACHINE_POLICY_WAIT_LATCH twin_wait_latch
#define RVMACHINE_POLICY_OVERLAY_BLOCKS 4u
#define rvmachine_enter rvmtwin_enter
#define rvmachine_run rvmtwin_run
#define rvmachine_advance_time rvmtwin_advance_time
#define rvmachine_timer_deadline rvmtwin_timer_deadline
#define rvmachine_disk_open rvmtwin_disk_open
#define rvmachine_disk_open_backend rvmtwin_disk_open_backend
#define rvmachine_disk_flush rvmtwin_disk_flush
#define rvmachine_disk_close rvmtwin_disk_close
#define rvmachine_disk_size rvmtwin_disk_size
#define rvmachine_disk_read rvmtwin_disk_read
#define rvmachine_disk_write rvmtwin_disk_write
#define rvmachine_disk_overlay_blocks rvmtwin_disk_overlay_blocks
#define rvmachine_disk_cleanse rvmtwin_disk_cleanse

/* public prototypes, now under the twin names */
enum rvmachine_status rvmtwin_run(struct rvmachine *m, uint64_t max_work,
                                  struct rvmachine_result *result);
enum rvmachine_status rvmtwin_advance_time(struct rvmachine *m, uint64_t guest_time);
uint64_t rvmtwin_timer_deadline(const struct rvmachine *m);
enum rvmachine_status rvmtwin_disk_open(struct rvmachine_disk **out, uint64_t size,
                                        rvmachine_disk_read_fn read, void *ctx);
enum rvmachine_status rvmtwin_disk_open_backend(struct rvmachine_disk **out,
    uint64_t size, rvmachine_disk_read_fn read, rvmachine_disk_write_fn write,
    rvmachine_disk_flush_fn flush, void *ctx);
bool rvmtwin_disk_flush(struct rvmachine_disk *disk);
void rvmtwin_disk_close(struct rvmachine_disk *disk);
uint64_t rvmtwin_disk_size(const struct rvmachine_disk *disk);
bool rvmtwin_disk_read(struct rvmachine_disk *disk, uint64_t off, void *buf, size_t n);
bool rvmtwin_disk_write(struct rvmachine_disk *disk, uint64_t off, const void *buf,
                        size_t n);
uint32_t rvmtwin_disk_overlay_blocks(const struct rvmachine_disk *disk);
void rvmtwin_disk_cleanse(struct rvmachine_disk *disk);

#include "../../../platform/modules/rvmachine/src/rvmachine_run.c"
#include "../../../platform/modules/rvmachine/src/rvmachine_disk.c"

#undef rvmachine_enter
#undef rvmachine_run
#undef rvmachine_advance_time
#undef rvmachine_timer_deadline
#undef rvmachine_disk_open
#undef rvmachine_disk_open_backend
#undef rvmachine_disk_flush
#undef rvmachine_disk_close
#undef rvmachine_disk_size
#undef rvmachine_disk_read
#undef rvmachine_disk_write
#undef rvmachine_disk_overlay_blocks
#undef rvmachine_disk_cleanse

static void twin_reset(void)
{
    twin_scounteren = RVMACHINE_SCOUNTEREN;
    twin_service = true;
    twin_drain = true;
    twin_rfence = true;
    twin_charge = true;
    twin_wait_latch = true;
}

/* ---- fixtures ---- */
#define RMT_DIR "tests/fixtures/rvmachine"
#define RMT_IMAGE_MAX ((size_t)1 << 16)
#define RMT_OUT_MAX 1024u
#define RMT_RAM (UINT64_C(64) << 20)
#define RMT_WORK UINT64_C(1000000)
#define MIB (UINT64_C(1) << 20)

static bool rmt_read_file(const char *path, uint8_t *buf, size_t cap, size_t *len)
{
    FILE *f = fopen(path, "rb");
    if (f == NULL) return false;
    *len = fread(buf, 1, cap, f);
    bool whole = feof(f) != 0 && ferror(f) == 0;
    fclose(f);
    return whole;
}

/* True when MANIFEST has the line "<name> <hex>". */
static bool rmt_manifest_has(const char *name, const char *hex)
{
    static uint8_t text[8192];
    char want[160];
    size_t n = 0;
    if (!rmt_read_file(RMT_DIR "/MANIFEST", text, sizeof text - 1u, &n)) return false;
    text[n] = '\0';
    snprintf(want, sizeof want, "\n%s %s\n", name, hex);
    return strstr((const char *)text, want) != NULL;
}

/* Loads tests/fixtures/rvmachine/<name>.bin after checking its sha256 against
 * the manifest; an image that does not match never runs. */
static bool rmt_fixture(const char *name, uint8_t *buf, size_t *len)
{
    static const char digits[] = "0123456789abcdef";
    char path[128], hex[2 * SHA256_OUTPUT_SIZE + 1];
    unsigned char hash[SHA256_OUTPUT_SIZE];
    struct sha256_ctx sha;
    snprintf(path, sizeof path, RMT_DIR "/%s.bin", name);
    if (!rmt_read_file(path, buf, RMT_IMAGE_MAX, len) || *len == 0) return false;
    sha256_init(&sha);
    sha256_write(&sha, buf, *len);
    sha256_finalize(&sha, hash);
    for (size_t i = 0; i < SHA256_OUTPUT_SIZE; i++) {
        hex[2 * i] = digits[hash[i] >> 4];
        hex[2 * i + 1] = digits[hash[i] & 15u];
    }
    hex[2 * SHA256_OUTPUT_SIZE] = '\0';
    return rmt_manifest_has(name, hex);
}

struct rmt_run {
    struct rvmachine *m;
    struct rvmachine_script *script;
    char out[RMT_OUT_MAX];
    size_t n;
    enum rvmachine_status st;
    struct rvmachine_result res;
};

static void rmt_console(void *ctx, uint8_t byte)
{
    struct rmt_run *r = ctx;
    if (r->n + 1u < sizeof r->out) r->out[r->n++] = (char)byte;
    r->out[r->n] = '\0';
    if (r->script != NULL) rvmachine_script_console(r->script, r->m, byte);
}

enum rmt_engine { RMT_REAL, RMT_TWIN };

/* The machine of a config with the image loaded, or NULL. The run's console
 * sink is put in. The twin engine re-enters the kernel under the twin's
 * policy and later runs the twin's loop. */
static struct rvmachine *rmt_machine_cfg(struct rmt_run *r, enum rmt_engine engine,
                                         const uint8_t *image, size_t len,
                                         struct rvmachine_config c)
{
    memset(r, 0, sizeof *r);
    c.console = rmt_console;
    c.console_ctx = r;
    r->st = rvmachine_create(&r->m, &c);
    if (r->st != RVMACHINE_OK) return NULL;
    r->st = rvmachine_load_kernel(r->m, image, len);
    if (r->st != RVMACHINE_OK) {
        rvmachine_destroy(r->m);
        r->m = NULL;
        return NULL;
    }
    if (engine == RMT_TWIN) rvmtwin_enter(r->m);
    return r->m;
}

/* A 64 MiB machine with the image loaded, or NULL. */
static struct rvmachine *rmt_machine_on(struct rmt_run *r, enum rmt_engine engine,
                                        const uint8_t *image, size_t len,
                                        struct rvmachine_disk *disk)
{
    return rmt_machine_cfg(r, engine, image, len,
                           (struct rvmachine_config){.ram_bytes = RMT_RAM, .disk = disk});
}

static struct rvmachine *rmt_machine(struct rmt_run *r, const uint8_t *image,
                                     size_t len, struct rvmachine_disk *disk)
{
    return rmt_machine_on(r, RMT_REAL, image, len, disk);
}

static void rmt_go(struct rmt_run *r, enum rmt_engine engine, uint64_t work)
{
    r->st = engine == RMT_TWIN ? rvmtwin_run(r->m, work, &r->res)
                               : rvmachine_run(r->m, work, &r->res);
}

/* Boots a fixture to its stop and destroys the machine. */
static bool rmt_boot(const char *name, enum rmt_engine engine, const char *input,
                     struct rmt_run *r)
{
    static uint8_t image[RMT_IMAGE_MAX];
    size_t len = 0;
    memset(r, 0, sizeof *r);
    if (!rmt_fixture(name, image, &len)) return false;
    if (rmt_machine_on(r, engine, image, len, NULL) == NULL) return false;
    if (input != NULL)
        (void)rvmachine_console_input(r->m, (const uint8_t *)input, strlen(input));
    rmt_go(r, engine, RMT_WORK);
    rvmachine_destroy(r->m);
    r->m = NULL;
    return r->st == RVMACHINE_OK;
}

static bool rmt_same(const struct rmt_run *a, const struct rmt_run *b)
{
    return a->n == b->n && memcmp(a->out, b->out, a->n) == 0 &&
           a->res.stop == b->res.stop && a->res.retired == b->res.retired &&
           a->res.skip == b->res.skip && a->res.fw_calls == b->res.fw_calls &&
           a->res.guest_time == b->res.guest_time && a->res.pc == b->res.pc;
}

/* ---- 1. the tiny supervisor guest: known answers, twice ---- */
#define TINY_TEXT "tiny: hello from S-mode\nprobe putchar=1\ntiny: timer fired\nU\n"

static int tiny_fetch_reused(const struct rmt_run *a, const struct rmt_run *b)
{
    uint64_t hits = a->res.fetch_hits;
    uint64_t misses = a->res.fetch_misses;
    if (hits < misses || misses == 0) return 0;
    if (hits != b->res.fetch_hits || misses != b->res.fetch_misses) return 0;
    printf("    rvmachine tiny fetch_hits=%llu fetch_misses=%llu\n",
           (unsigned long long)hits, (unsigned long long)misses);
    return misses < hits + misses ? 1 : 0;
}

static int t_tiny(void)
{
    int failures = 0;
    TEST("rvmachine: tiny guest prints, sleeps to its timer and powers off, identically twice") {
        static struct rmt_run a, b;
        ASSERT(rmt_boot("tiny", RMT_REAL, NULL, &a));
        ASSERT_STR_EQ(a.out, TINY_TEXT);
        ASSERT_EQ(a.res.stop, RVMACHINE_STOP_SHUTDOWN);
        ASSERT_EQ(a.res.retired, 279u);
        ASSERT_EQ(a.res.skip, 999u);
        ASSERT_EQ(a.res.fw_calls, 62u);
        ASSERT_EQ(a.res.guest_time, 279u / RVMACHINE_TICKS_PER_TIME + 999u);
        ASSERT_EQ(a.res.reset_type, 0u);
        ASSERT(rmt_boot("tiny", RMT_REAL, NULL, &b));
        ASSERT(rmt_same(&a, &b));
        PASS();
    } _test_next:;
    return failures;
}

static int t_tiny_fetch(void)
{
    int failures = 0;
    TEST("rvmachine: tiny guest reuses decoded instructions") {
        static struct rmt_run a, b;
        ASSERT(rmt_boot("tiny", RMT_REAL, NULL, &a));
        ASSERT(rmt_boot("tiny", RMT_REAL, NULL, &b));
        ASSERT(tiny_fetch_reused(&a, &b));
        ASSERT_EQ(a.res.retired, 279u);
        ASSERT_EQ(a.res.fw_calls, 62u);
        PASS();
    } _test_next:;
    return failures;
}

/* ---- 2. paging turned on through stvec, as a kernel does ---- */
static int t_paging(void)
{
    int failures = 0;
    TEST("rvmachine: a guest enters Sv39 through the stvec fault and runs in the high half") {
        static struct rmt_run a, b;
        ASSERT(rmt_boot("paging", RMT_REAL, NULL, &a));
        ASSERT_STR_EQ(a.out, "paging: running after the satp write\n"
                             "paging: entered through an instruction page fault\n"
                             "paging: pc is in the high half\n"
                             "paging: data reads through the mapping\n");
        ASSERT_EQ(a.res.stop, RVMACHINE_STOP_SHUTDOWN);
        ASSERT_EQ(a.res.retired, 860u);
        ASSERT_EQ(a.res.fw_calls, 158u);
        ASSERT_EQ(a.res.skip, 0u);
        ASSERT(rmt_boot("paging", RMT_REAL, NULL, &b));
        ASSERT(rmt_same(&a, &b));
        PASS();
    } _test_next:;
    return failures;
}

/* ---- 3. run-loop stops ---- */
static int t_budget(void)
{
    int failures = 0;
    TEST("rvmachine: a budget stop counts retired plus firmware calls and resumes exactly") {
        static uint8_t image[RMT_IMAGE_MAX];
        static struct rmt_run whole, r;
        size_t len = 0;
        ASSERT(rmt_boot("tiny", RMT_REAL, NULL, &whole));
        ASSERT(rmt_fixture("tiny", image, &len));
        ASSERT(rmt_machine(&r, image, len, NULL) != NULL);
        rmt_go(&r, RMT_REAL, 100);
        ASSERT_EQ(r.st, RVMACHINE_OK);
        ASSERT_EQ(r.res.stop, RVMACHINE_STOP_BUDGET);
        ASSERT_EQ(r.res.retired + r.res.fw_calls, 100u);
        ASSERT(r.res.fw_calls > 0u); /* the firmware calls were charged */
        for (unsigned i = 0; i < 100u && r.res.stop == RVMACHINE_STOP_BUDGET; i++)
            rmt_go(&r, RMT_REAL, 7);
        rvmachine_destroy(r.m);
        ASSERT(rmt_same(&whole, &r)); /* slicing the run changes nothing */
        PASS();
    } _test_next:;
    return failures;
}

static int t_idle_and_fault(void)
{
    int failures = 0;
    TEST("rvmachine: idle, fault and after-shutdown stops are typed") {
        /* wfi; j .-4 : nothing armed, nothing queued */
        static const uint8_t idle[8] = {0x73, 0x00, 0x50, 0x10, 0x6f, 0xf0, 0xdf, 0xff};
        /* jalr x0, 0(x0): jumps to address 0, where nothing answers; the trap
         * vector is 0 as well, so no handler can ever be fetched */
        static const uint8_t wild[4] = {0x67, 0x00, 0x00, 0x00};
        static uint8_t image[RMT_IMAGE_MAX];
        static struct rmt_run r;
        struct rvmachine_config c = {.ram_bytes = RMT_RAM};
        struct rvmachine *m = NULL;
        size_t len = 0;
        ASSERT(rmt_machine(&r, idle, sizeof idle, NULL) != NULL);
        rmt_go(&r, RMT_REAL, RMT_WORK);
        rvmachine_destroy(r.m);
        ASSERT_EQ(r.res.stop, RVMACHINE_STOP_IDLE);
        ASSERT_EQ(r.res.retired, 1u);
        ASSERT_EQ(r.res.skip, 0u);
        ASSERT(rmt_machine(&r, wild, sizeof wild, NULL) != NULL);
        rmt_go(&r, RMT_REAL, RMT_WORK);
        rvmachine_destroy(r.m);
        ASSERT_EQ(r.res.stop, RVMACHINE_STOP_FAULT);
        ASSERT_EQ(r.res.engine_stop, 0u); /* a trap storm, not an engine stop */
        ASSERT_EQ(r.res.pc, 0u);
        ASSERT_EQ(r.res.cause, 1u); /* instruction access fault */
        ASSERT_EQ(r.res.tval, 0u);
        ASSERT_EQ(r.res.retired, 1u);
        /* not runnable before a load or after a power-off */
        ASSERT_EQ(rvmachine_create(&m, &c), RVMACHINE_OK);
        ASSERT_EQ(rvmachine_run(m, 10, &r.res), RVMACHINE_ERR_STATE);
        rvmachine_destroy(m);
        ASSERT(rmt_fixture("tiny", image, &len));
        ASSERT(rmt_machine(&r, image, len, NULL) != NULL);
        rmt_go(&r, RMT_REAL, RMT_WORK);
        ASSERT_EQ(r.res.stop, RVMACHINE_STOP_SHUTDOWN);
        ASSERT_EQ(rvmachine_run(r.m, 10, &r.res), RVMACHINE_ERR_STATE);
        rvmachine_destroy(r.m);
        ASSERT_EQ(rvmachine_run(NULL, 10, &r.res), RVMACHINE_ERR_ARG);
        PASS();
    } _test_next:;
    return failures;
}

/* ---- 4. device tree known answers and placement ---- */
static bool dt_u32(const uint8_t *blob, size_t len, const char *path, const char *name,
                   size_t index, uint32_t want)
{
    fdt_node_t node;
    const uint8_t *data = NULL;
    size_t n = 0;
    if (fdt_find_node(blob, len, path, &node) != FDT_OK) return false;
    if (fdt_get_prop(blob, len, node, name, &data, &n) != FDT_OK) return false;
    return n >= 4u * (index + 1u) && zcl_read_u32_be(data + 4u * index) == want;
}

static bool dt_str(const uint8_t *blob, size_t len, const char *path, const char *name,
                   const char *want)
{
    fdt_node_t node;
    const uint8_t *data = NULL;
    size_t n = 0;
    if (fdt_find_node(blob, len, path, &node) != FDT_OK) return false;
    if (fdt_get_prop(blob, len, node, name, &data, &n) != FDT_OK) return false;
    return n >= strlen(want) + 1u && memcmp(data, want, strlen(want) + 1u) == 0;
}

static int t_dtb(void)
{
    int failures = 0;
    TEST("rvmachine: the device tree carries the contract's nodes and values") {
        static uint8_t blob[RVMACHINE_DTB_MAX];
        static char longargs[RVMACHINE_BOOTARGS_MAX + 1u];
        size_t len = 0;
        ASSERT_EQ(rvmachine_build_dtb(UINT64_C(1) << 30, "-s", blob, sizeof blob, &len),
                  RVMACHINE_OK);
        ASSERT_EQ(fdt_check(blob, len), FDT_OK);
        ASSERT(dt_u32(blob, len, "/", "#address-cells", 0, 2));
        ASSERT(dt_u32(blob, len, "/", "#size-cells", 0, 2));
        ASSERT(dt_str(blob, len, "/chosen", "bootargs", "-s"));
        ASSERT(dt_str(blob, len, "/chosen", "stdout-path", "/soc/serial@10000000"));
        ASSERT(dt_u32(blob, len, "/cpus", "timebase-frequency", 0, 10000000u));
        ASSERT(dt_str(blob, len, "/cpus/cpu@0", "riscv,isa", "rv64imafdc"));
        ASSERT(dt_str(blob, len, "/cpus/cpu@0", "mmu-type", "riscv,sv39"));
        ASSERT(dt_str(blob, len, "/cpus/cpu@0/interrupt-controller", "compatible",
                      "riscv,cpu-intc"));
        ASSERT(dt_u32(blob, len, "/cpus/cpu@0/interrupt-controller", "phandle", 0, 1));
        /* memory: base 0x80000000, size 1 GiB, two cells each */
        ASSERT(dt_u32(blob, len, "/memory@80000000", "reg", 1, 0x80000000u));
        ASSERT(dt_u32(blob, len, "/memory@80000000", "reg", 3, 0x40000000u));
        /* interrupt controller: 31 sources, contexts (machine 11, supervisor 9) */
        ASSERT(dt_str(blob, len, "/soc/plic@c000000", "compatible", "sifive,plic-1.0.0"));
        ASSERT(dt_u32(blob, len, "/soc/plic@c000000", "riscv,ndev", 0, 31));
        ASSERT(dt_u32(blob, len, "/soc/plic@c000000", "interrupts-extended", 1, 11));
        ASSERT(dt_u32(blob, len, "/soc/plic@c000000", "interrupts-extended", 3, 9));
        ASSERT(dt_u32(blob, len, "/soc/plic@c000000", "reg", 3, 0x600000u));
        ASSERT(dt_str(blob, len, "/soc/serial@10000000", "compatible", "ns16550a"));
        ASSERT(dt_u32(blob, len, "/soc/serial@10000000", "interrupts", 0, 10));
        ASSERT(dt_u32(blob, len, "/soc/serial@10000000", "clock-frequency", 0, 3686400u));
        ASSERT(dt_u32(blob, len, "/soc/serial@10000000", "reg-shift", 0, 0));
        ASSERT(dt_u32(blob, len, "/soc/serial@10000000", "current-speed", 0, 115200u));
        /* eight virtio slots on sources 1..8, described with or without a disk */
        ASSERT(dt_str(blob, len, "/soc/virtio_mmio@10001000", "compatible", "virtio,mmio"));
        ASSERT(dt_u32(blob, len, "/soc/virtio_mmio@10001000", "interrupts", 0, 1));
        ASSERT(dt_u32(blob, len, "/soc/virtio_mmio@10008000", "interrupts", 0, 8));
        ASSERT(dt_u32(blob, len, "/soc/virtio_mmio@10008000", "interrupt-parent", 0, 2));
        /* refusals */
        memset(longargs, 'a', RVMACHINE_BOOTARGS_MAX);
        ASSERT_EQ(rvmachine_build_dtb(UINT64_C(1) << 30, longargs, blob, sizeof blob, &len),
                  RVMACHINE_ERR_ARG);
        ASSERT_EQ(rvmachine_build_dtb(UINT64_C(1) << 30, "", blob, 64, &len),
                  RVMACHINE_ERR_FDT);
        PASS();
    } _test_next:;
    return failures;
}

static int t_entry_and_placement(void)
{
    int failures = 0;
    TEST("rvmachine: entry state, and the tree stays inside the first gigabyte of RAM") {
        static const uint8_t nop[4] = {0x13, 0x00, 0x00, 0x00};
        static struct rmt_run r;
        struct rvmachine_config c = {0};
        struct rvmachine *m = NULL;
        size_t len = 0;
        ASSERT(rmt_machine(&r, nop, sizeof nop, NULL) != NULL);
        ASSERT_EQ(r.m->dtb_addr, RVMACHINE_RAM_BASE + RMT_RAM - 2u * MIB);
        ASSERT_EQ(r.m->hart.pc, RVMACHINE_KERNEL_BASE);
        ASSERT_EQ(r.m->hart.x[10], 0u);
        ASSERT_EQ(r.m->hart.x[11], r.m->dtb_addr);
        ASSERT_EQ(r.m->hart.csr.satp, 0u);
        ASSERT_EQ(r.m->hart.csr.scounteren, 7u);
        ASSERT_EQ(r.m->hart.csr.mstatus & 2u, 0u); /* supervisor interrupts off */
        const uint8_t *blob = rvmachine_dtb(r.m, &len);
        ASSERT_EQ(fdt_check(blob, len), FDT_OK);
        rvmachine_destroy(r.m);
        /* 2 GiB of RAM: the tree stays at RAM base + 1 GiB - 2 MiB, where the
         * boot page tables of a kernel can still reach it */
        c.ram_bytes = UINT64_C(2) << 30;
        ASSERT_EQ(rvmachine_create(&m, &c), RVMACHINE_OK);
        ASSERT_EQ(m->dtb_addr, RVMACHINE_RAM_BASE + (UINT64_C(1) << 30) - 2u * MIB);
        blob = rvmachine_dtb(m, &len);
        ASSERT(dt_u32(blob, len, "/memory@80000000", "reg", 3,
                      0x80000000u));
        rvmachine_destroy(m);
        /* sizes the machine refuses */
        c.ram_bytes = 32u * MIB;
        ASSERT_EQ(rvmachine_create(&m, &c), RVMACHINE_ERR_ARG);
        ASSERT(m == NULL);
        c.ram_bytes = 64u * MIB + 4096u;
        ASSERT_EQ(rvmachine_create(&m, &c), RVMACHINE_ERR_ARG);
        c.ram_bytes = RMT_RAM;
        PASS();
    } _test_next:;
    return failures;
}

/* ---- 5. loader ---- */
#define ELF_HDR 64u
#define ELF_PH 56u

struct elf_seg {
    uint64_t off, vaddr, paddr, filesz, memsz;
};

/* A little-endian ELF64 RISC-V header and nseg PT_LOAD program headers. */
static void elf_build(uint8_t *img, const struct elf_seg *segs, unsigned nseg)
{
    static const uint8_t ident[8] = {0x7f, 'E', 'L', 'F', 2, 1, 1, 0};
    memset(img, 0, ELF_HDR + (size_t)nseg * ELF_PH);
    memcpy(img, ident, sizeof ident);
    zcl_write_u16_le(img + 16, 2);   /* ET_EXEC */
    zcl_write_u16_le(img + 18, 243); /* EM_RISCV */
    zcl_write_u32_le(img + 20, 1);
    zcl_write_u64_le(img + 32, ELF_HDR); /* e_phoff */
    zcl_write_u16_le(img + 52, ELF_HDR);
    zcl_write_u16_le(img + 54, ELF_PH);
    zcl_write_u16_le(img + 56, (uint16_t)nseg);
    for (unsigned i = 0; i < nseg; i++) {
        uint8_t *ph = img + ELF_HDR + (size_t)i * ELF_PH;
        zcl_write_u32_le(ph, 1); /* PT_LOAD */
        zcl_write_u32_le(ph + 4, 7);
        zcl_write_u64_le(ph + 8, segs[i].off);
        zcl_write_u64_le(ph + 16, segs[i].vaddr);
        zcl_write_u64_le(ph + 24, segs[i].paddr);
        zcl_write_u64_le(ph + 32, segs[i].filesz);
        zcl_write_u64_le(ph + 40, segs[i].memsz);
    }
}

static enum rvmachine_status load_into(const uint8_t *img, size_t len,
                                       struct rvmachine **keep)
{
    struct rvmachine_config c = {.ram_bytes = RMT_RAM};
    struct rvmachine *m = NULL;
    enum rvmachine_status st = rvmachine_create(&m, &c);
    if (st != RVMACHINE_OK) return st;
    memset(m->mem.bytes + 2u * MIB, 0xee, 0x4000); /* so zeroed bss is visible */
    st = rvmachine_load_kernel(m, img, len);
    if (keep != NULL && st == RVMACHINE_OK)
        *keep = m;
    else
        rvmachine_destroy(m);
    return st;
}

static int t_loader_places(void)
{
    int failures = 0;
    TEST("rvmachine: the loader places segments by physical or relative address and zeroes bss") {
        static uint8_t img[0x3000];
        struct rvmachine *m = NULL;
        /* physical addresses usable: lowest is the kernel base */
        struct elf_seg phys[2] = {
            {0x1000, 0xffffffc000000000u, 0x80200000u, 0x10, 0x10},
            {0x2000, 0xffffffc000002000u, 0x80202000u, 0x08, 0x100}};
        elf_build(img, phys, 2);
        memset(img + 0x1000, 0x11, 0x10);
        memset(img + 0x2000, 0x22, 0x08);
        ASSERT_EQ(load_into(img, sizeof img, &m), RVMACHINE_OK);
        ASSERT_EQ(m->mem.bytes[2u * MIB], 0x11);
        ASSERT_EQ(m->mem.bytes[2u * MIB + 0x2000], 0x22);
        ASSERT_EQ(m->mem.bytes[2u * MIB + 0x2008], 0x00); /* bss */
        ASSERT_EQ(m->mem.bytes[2u * MIB + 0x20ff], 0x00);
        ASSERT_EQ(m->mem.bytes[2u * MIB + 0x2100], 0xee); /* past memsz: untouched */
        ASSERT_EQ(m->image_end, 0x80202100u);
        ASSERT_EQ(m->hart.pc, RVMACHINE_KERNEL_BASE);
        rvmachine_destroy(m);
        m = NULL;
        /* physical addresses unusable (a link address of 0): placed relative
         * to the lowest virtual address */
        struct elf_seg rel[2] = {{0x1000, 0x10000, 0x10000, 0x10, 0x10},
                                 {0x2000, 0x13000, 0x13000, 0x08, 0x08}};
        elf_build(img, rel, 2);
        ASSERT_EQ(load_into(img, sizeof img, &m), RVMACHINE_OK);
        ASSERT_EQ(m->mem.bytes[2u * MIB], 0x11);
        ASSERT_EQ(m->mem.bytes[2u * MIB + 0x3000], 0x22);
        ASSERT_EQ(m->image_end, 0x80203008u);
        rvmachine_destroy(m);
        PASS();
    } _test_next:;
    return failures;
}

static int t_loader_refuses(void)
{
    int failures = 0;
    TEST("rvmachine: the loader refuses truncated, foreign, oversized and overlapping images") {
        static uint8_t img[0x3000];
        static uint8_t big[60u * 1024u * 1024u + 1u];
        struct elf_seg seg = {0x1000, 0xffffffc000000000u, 0x80200000u, 0x10, 0x10};
        const uint64_t tree = RVMACHINE_RAM_BASE + RMT_RAM - 2u * MIB;
        elf_build(img, &seg, 1);
        ASSERT_EQ(load_into(img, sizeof img, NULL), RVMACHINE_OK);
        /* truncated: the file ends inside the program headers, then inside
         * the segment data */
        ASSERT_EQ(load_into(img, ELF_HDR + ELF_PH - 1u, NULL), RVMACHINE_ERR_IMAGE);
        ASSERT_EQ(load_into(img, 0x1008, NULL), RVMACHINE_ERR_IMAGE);
        ASSERT_EQ(load_into(img, 63, NULL), RVMACHINE_ERR_IMAGE); /* ELF magic, no header */
        /* bad magic: an ELF for another machine or word size is not a flat image */
        zcl_write_u16_le(img + 18, 62); /* x86-64 */
        ASSERT_EQ(load_into(img, sizeof img, NULL), RVMACHINE_ERR_IMAGE);
        elf_build(img, &seg, 1);
        img[4] = 1; /* 32-bit */
        ASSERT_EQ(load_into(img, sizeof img, NULL), RVMACHINE_ERR_IMAGE);
        /* malformed tables */
        elf_build(img, &seg, 1);
        zcl_write_u16_le(img + 54, 32); /* program header entry size */
        ASSERT_EQ(load_into(img, sizeof img, NULL), RVMACHINE_ERR_IMAGE);
        elf_build(img, &seg, 0);
        ASSERT_EQ(load_into(img, sizeof img, NULL), RVMACHINE_ERR_IMAGE);
        seg.filesz = 0x20; /* file size above memory size */
        elf_build(img, &seg, 1);
        ASSERT_EQ(load_into(img, sizeof img, NULL), RVMACHINE_ERR_IMAGE);
        /* a segment outside RAM: neither its physical address nor its
         * distance from the lowest virtual address can be placed */
        struct elf_seg far[2] = {{0x1000, 0x10000, 0x80200000u, 0x10, 0x10},
                                 {0x2000, UINT64_C(0x4000010000), UINT64_C(0x4000000000),
                                  0x10, 0x10}};
        elf_build(img, far, 2);
        ASSERT_EQ(load_into(img, sizeof img, NULL), RVMACHINE_ERR_IMAGE_RANGE);
        /* an image that reaches the device tree: one byte short fits */
        seg = (struct elf_seg){0x1000, 0xffffffc000000000u, 0x80200000u, 0x10,
                               tree - 0x80200000u};
        elf_build(img, &seg, 1);
        ASSERT_EQ(load_into(img, sizeof img, NULL), RVMACHINE_OK);
        seg.memsz += 1u;
        elf_build(img, &seg, 1);
        ASSERT_EQ(load_into(img, sizeof img, NULL), RVMACHINE_ERR_IMAGE_RANGE);
        seg.memsz = UINT64_MAX - 0x1000u; /* wraps the address space */
        elf_build(img, &seg, 1);
        ASSERT_EQ(load_into(img, sizeof img, NULL), RVMACHINE_ERR_IMAGE_RANGE);
        /* flat images */
        ASSERT_EQ(load_into(big, 3, NULL), RVMACHINE_ERR_IMAGE);
        ASSERT_EQ(load_into(big, sizeof big - 1u, NULL), RVMACHINE_OK);
        ASSERT_EQ(load_into(big, sizeof big, NULL), RVMACHINE_ERR_IMAGE_RANGE);
        ASSERT_EQ(rvmachine_load_kernel(NULL, img, sizeof img), RVMACHINE_ERR_ARG);
        PASS();
    } _test_next:;
    return failures;
}

/* ---- 6. disk: read-through, copy-on-write, cap, image untouched ---- */
#define DISK_BYTES 10000u /* two whole blocks and a partial one */

static uint8_t disk_pattern(size_t i)
{
    return (uint8_t)(i * 7u + (i >> 8));
}

/* An image in memory behind the disk's read function. */
struct mem_image {
    uint8_t *bytes;
    size_t size;
    unsigned reads;
    uint64_t asked; /* bytes asked for, over every read */
    bool fail;    /* reads fail from now on */
    bool escaped; /* a read asked for bytes outside the image */
};

static bool mem_image_read(void *ctx, uint64_t off, void *buf, size_t n)
{
    struct mem_image *im = ctx;
    im->reads++;
    im->asked += n;
    if (off > im->size || n > im->size - off) {
        im->escaped = true;
        return false;
    }
    if (im->fail) return false;
    memcpy(buf, im->bytes + off, n);
    return true;
}

static void mem_image_fill(struct mem_image *im, uint8_t *bytes, size_t size)
{
    for (size_t i = 0; i < size; i++) bytes[i] = disk_pattern(i);
    *im = (struct mem_image){.bytes = bytes, .size = size};
}

/* The image still holds the pattern and no read ever left it. */
static bool mem_image_intact(const struct mem_image *im)
{
    for (size_t i = 0; i < im->size; i++)
        if (im->bytes[i] != disk_pattern(i)) return false;
    return !im->escaped;
}

static int t_disk(void)
{
    int failures = 0;
    TEST("rvmachine: disk reads through, writes stay in the overlay, the image never changes") {
        static uint8_t image[DISK_BYTES], buf[DISK_BYTES];
        struct mem_image im;
        struct rvmachine_disk *d = NULL;
        struct rvmachine *m = NULL;
        struct rvmachine_config c = {.ram_bytes = 32u * MIB}; /* a refused size */
        mem_image_fill(&im, image, DISK_BYTES);
        ASSERT_EQ(rvmachine_disk_open(&d, DISK_BYTES, mem_image_read, &im), RVMACHINE_OK);
        ASSERT_EQ(rvmachine_disk_size(d), (uint64_t)DISK_BYTES);
        ASSERT(rvmachine_disk_read(d, 0, buf, DISK_BYTES));
        for (size_t i = 0; i < DISK_BYTES; i++) ASSERT_EQ(buf[i], disk_pattern(i));
        ASSERT_EQ(rvmachine_disk_overlay_blocks(d), 0u);
        /* an image that cannot be read fails the read and the first write */
        im.fail = true;
        ASSERT(!rvmachine_disk_read(d, 0, buf, 16));
        ASSERT(!rvmachine_disk_write(d, 0, "x", 1));
        ASSERT_EQ(rvmachine_disk_overlay_blocks(d), 0u);
        im.fail = false;
        /* a write across the first block boundary copies two blocks */
        ASSERT(rvmachine_disk_write(d, 4090, "0123456789AB", 12));
        ASSERT_EQ(rvmachine_disk_overlay_blocks(d), 2u);
        ASSERT(rvmachine_disk_read(d, 4080, buf, 32));
        ASSERT(memcmp(buf + 10, "0123456789AB", 12) == 0);
        ASSERT_EQ(buf[9], disk_pattern(4089));  /* around the write: the image */
        ASSERT_EQ(buf[22], disk_pattern(4102));
        /* the partial last block: writable, and bounded by the image size */
        ASSERT(rvmachine_disk_write(d, DISK_BYTES - 4u, "tail", 4));
        ASSERT(rvmachine_disk_read(d, DISK_BYTES - 4u, buf, 4));
        ASSERT(memcmp(buf, "tail", 4) == 0);
        ASSERT(!rvmachine_disk_write(d, DISK_BYTES - 3u, "tail", 4));
        ASSERT(!rvmachine_disk_read(d, DISK_BYTES, buf, 1));
        ASSERT(!rvmachine_disk_read(d, UINT64_MAX, buf, 2));
        ASSERT(rvmachine_disk_read(d, DISK_BYTES, buf, 0));
        /* overlay blocks no longer need the image */
        im.fail = true;
        ASSERT(rvmachine_disk_read(d, 4090, buf, 12));
        ASSERT(memcmp(buf, "0123456789AB", 12) == 0);
        im.fail = false;
        /* a machine that refuses its configuration leaves the disk with us */
        c.disk = d;
        ASSERT_EQ(rvmachine_create(&m, &c), RVMACHINE_ERR_ARG);
        ASSERT(m == NULL);
        ASSERT(rvmachine_disk_read(d, DISK_BYTES - 4u, buf, 4));
        ASSERT(memcmp(buf, "tail", 4) == 0);
        rvmachine_disk_close(d);
        ASSERT(mem_image_intact(&im)); /* nothing reached the image */
        /* refusals */
        d = (struct rvmachine_disk *)&im;
        ASSERT_EQ(rvmachine_disk_open(&d, 0, mem_image_read, &im), RVMACHINE_ERR_DISK);
        ASSERT(d == NULL);
        ASSERT_EQ(rvmachine_disk_open(&d, RVMACHINE_DISK_BYTES_MAX + 1u, mem_image_read, &im),
                  RVMACHINE_ERR_DISK);
        ASSERT_EQ(rvmachine_disk_open(&d, DISK_BYTES, NULL, &im), RVMACHINE_ERR_ARG);
        ASSERT_EQ(rvmachine_disk_open(NULL, DISK_BYTES, mem_image_read, &im),
                  RVMACHINE_ERR_ARG);
        PASS();
    } _test_next:;
    return failures;
}

struct retained_disk {
    uint8_t live[1024], durable[1024];
    char order[32];
    unsigned calls;
    bool read_fail, write_fail, flush_fail;
};
static void retained_call(struct retained_disk *b, char kind)
{
    if (b->calls < sizeof b->order) b->order[b->calls] = kind;
    b->calls++;
}
static bool retained_read(void *ctx, uint64_t off, void *buf, size_t n)
{
    struct retained_disk *b = ctx;
    retained_call(b, 'R');
    if (b->read_fail || off > sizeof b->live || n > sizeof b->live - off) return false;
    memcpy(buf, b->live + off, n);
    return true;
}
static bool retained_write(void *ctx, uint64_t off, const void *buf, size_t n)
{
    struct retained_disk *b = ctx;
    retained_call(b, 'W');
    if (b->write_fail || off > sizeof b->live || n > sizeof b->live - off) return false;
    memcpy(b->live + off, buf, n);
    return true;
}
static bool retained_flush(void *ctx)
{
    struct retained_disk *b = ctx;
    retained_call(b, 'F');
    if (b->flush_fail) return false;
    memcpy(b->durable, b->live, sizeof b->live);
    return true;
}

static int t_retained_disk(void)
{
    int failures = 0;
    struct rvmachine_disk *d = NULL;
    TEST("rvmachine: retained storage requires callbacks and preserves its caller backing across reopen") {
        struct retained_disk b = {0};
        uint8_t got[4], bytes[4] = {0, 0x7f, 0x80, 0xff};
        ASSERT_EQ(rvmachine_disk_open_backend(&d, sizeof b.live, retained_read, NULL,
                                              retained_flush, &b), RVMACHINE_ERR_ARG);
        ASSERT(d == NULL);
        ASSERT_EQ(rvmachine_disk_open_backend(&d, sizeof b.live, retained_read,
                                              retained_write, NULL, &b), RVMACHINE_ERR_ARG);
        ASSERT_EQ(rvmachine_disk_open_backend(&d, sizeof b.live, retained_read,
                                              retained_write, retained_flush, &b), RVMACHINE_OK);
        ASSERT(!rvmachine_disk_write(d, sizeof b.live - 1u, bytes, sizeof bytes));
        ASSERT(!rvmachine_disk_read(d, UINT64_MAX, got, sizeof got));
        ASSERT_EQ(b.calls, 0u);
        ASSERT(rvmachine_disk_write(d, 512, bytes, sizeof bytes));
        ASSERT_EQ(rvmachine_disk_overlay_blocks(d), 0u);
        b.flush_fail = true;
        ASSERT(!rvmachine_disk_flush(d));
        ASSERT_EQ(b.durable[513], 0u);
        b.flush_fail = false;
        ASSERT(rvmachine_disk_flush(d));
        ASSERT(memcmp(b.order, "WFF", 3) == 0);
        rvmachine_disk_close(d); d = NULL;
        ASSERT_EQ(b.calls, 3u); /* close does not fabricate a flush */
        memcpy(b.live, b.durable, sizeof b.live);
        ASSERT_EQ(rvmachine_disk_open_backend(&d, sizeof b.live, retained_read,
                                              retained_write, retained_flush, &b), RVMACHINE_OK);
        ASSERT(rvmachine_disk_read(d, 512, got, sizeof got));
        ASSERT(memcmp(got, bytes, sizeof got) == 0);
        b.read_fail = true;
        ASSERT(!rvmachine_disk_read(d, 512, got, sizeof got));
        b.write_fail = true;
        ASSERT(!rvmachine_disk_write(d, 0, bytes, sizeof bytes));
        ASSERT_EQ(b.live[0], 0u);
        PASS();
    } _test_next:;
    rvmachine_disk_close(d);
    return failures;
}

static int t_disk_cap(void)
{
    int failures = 0;
    TEST("rvmachine: a full overlay refuses a new block and keeps serving the old ones") {
        static uint8_t image[8u * 4096u];
        struct mem_image im;
        uint8_t byte = 0x5a, got = 0;
        struct rvmachine_disk *d = NULL;
        static_assert(RVMACHINE_DISK_OVERLAY_BLOCKS == 65536u, "256 MiB of 4 KiB blocks");
        mem_image_fill(&im, image, sizeof image);
        /* the twin is the same source with a cap of four blocks */
        ASSERT_EQ(rvmtwin_disk_open(&d, sizeof image, mem_image_read, &im), RVMACHINE_OK);
        for (uint64_t b = 0; b < 4u; b++)
            ASSERT(rvmtwin_disk_write(d, b * 4096u, &byte, 1));
        ASSERT_EQ(rvmtwin_disk_overlay_blocks(d), 4u);
        ASSERT(!rvmtwin_disk_write(d, 4u * 4096u, &byte, 1)); /* a fifth block */
        ASSERT(rvmtwin_disk_write(d, 3u * 4096u + 9u, &byte, 1)); /* an old one */
        ASSERT(rvmtwin_disk_read(d, 4u * 4096u, &got, 1));
        ASSERT_EQ(got, disk_pattern(4u * 4096u)); /* the refused block reads the image */
        ASSERT(rvmtwin_disk_read(d, 3u * 4096u + 9u, &got, 1));
        ASSERT_EQ(got, 0x5a);
        rvmtwin_disk_close(d);
        ASSERT(mem_image_intact(&im));
        PASS();
    } _test_next:;
    return failures;
}

/* ---- 7. console input: one cursor per reader ---- */
static int t_input(void)
{
    int failures = 0;
    TEST("rvmachine: every input byte reaches both the firmware console and the serial port") {
        static struct rmt_run r;
        static const uint8_t nop[4] = {0x13, 0x00, 0x00, 0x00};
        static uint8_t flood[RVMACHINE_INPUT_MAX + 904u];
        ASSERT(rmt_boot("echo", RMT_REAL, "xyz", &r));
        ASSERT_STR_EQ(r.out, "xyzxyz");
        ASSERT_EQ(r.res.stop, RVMACHINE_STOP_SHUTDOWN);
        /* a reader that never reads keeps only the newest bytes */
        ASSERT(rmt_machine(&r, nop, sizeof nop, NULL) != NULL);
        for (size_t i = 0; i < sizeof flood; i++) flood[i] = (uint8_t)i;
        ASSERT_EQ(rvmachine_console_input(r.m, flood, sizeof flood), sizeof flood);
        ASSERT_EQ(r.m->firmware_in.count, (size_t)RVMACHINE_INPUT_MAX);
        ASSERT_EQ(r.m->serial_in.count, (size_t)RVMACHINE_INPUT_MAX);
        ASSERT_EQ(r.m->firmware_in.bytes[r.m->firmware_in.head], (uint8_t)904u);
        ASSERT_EQ(rvmachine_console_input(r.m, NULL, 4), 0u);
        rvmachine_destroy(r.m);
        PASS();
    } _test_next:;
    return failures;
}

/* ---- 8. console script ---- */
static int t_script(void)
{
    int failures = 0;
    TEST("rvmachine: script steps type on their markers in order and the stop marker ends the run") {
        static uint8_t image[RMT_IMAGE_MAX];
        static struct rvmachine_script s;
        static struct rmt_run r;
        static char longtext[RVMACHINE_SCRIPT_TEXT_MAX + 2u];
        size_t len = 0;
        ASSERT(rmt_fixture("echo", image, &len));
        /* the guest waits for input: the script types it when asked */
        rvmachine_script_init(&s);
        ASSERT(rvmachine_script_add(&s, "x", 1, "yz", 2));
        ASSERT(rvmachine_script_until(&s, "zxy", 3));
        ASSERT(rmt_machine(&r, image, len, NULL) != NULL);
        r.script = &s;
        (void)rvmachine_console_input(r.m, (const uint8_t *)"x", 1);
        rmt_go(&r, RMT_REAL, RMT_WORK);
        rvmachine_destroy(r.m);
        ASSERT_EQ(r.res.stop, RVMACHINE_STOP_REQUESTED);
        ASSERT_STR_EQ(r.out, "xyzxy"); /* stopped at the marker, before the last z */
        ASSERT_EQ(s.fired, 1u);
        ASSERT(s.until_seen);
        ASSERT(rvmachine_script_met(&s));
        ASSERT_EQ(s.console_bytes, 5u);
        /* a marker that never appears: the run ends some other way, unmet */
        rvmachine_script_init(&s);
        ASSERT(rvmachine_script_add(&s, "x", 1, "yz", 2));
        ASSERT(rvmachine_script_add(&s, "never", 5, "", 0));
        ASSERT(rvmachine_script_until(&s, "z", 1));
        ASSERT(rmt_machine(&r, image, len, NULL) != NULL);
        r.script = &s;
        (void)rvmachine_console_input(r.m, (const uint8_t *)"x", 1);
        rmt_go(&r, RMT_REAL, RMT_WORK);
        rvmachine_destroy(r.m);
        ASSERT_EQ(r.res.stop, RVMACHINE_STOP_SHUTDOWN);
        ASSERT_STR_EQ(r.out, "xyzxyz"); /* the stop marker was not armed */
        ASSERT_EQ(s.fired, 1u);
        ASSERT(!s.until_seen);
        ASSERT(!rvmachine_script_met(&s));
        /* what the table refuses */
        rvmachine_script_init(&s);
        ASSERT(rvmachine_script_met(&s)); /* nothing asked, nothing missed */
        ASSERT(!rvmachine_script_add(&s, "", 0, "a", 1));
        ASSERT(!rvmachine_script_add(&s, longtext, RVMACHINE_SCRIPT_MARKER_MAX + 1u, "a", 1));
        ASSERT(!rvmachine_script_add(&s, "m", 1, longtext, RVMACHINE_SCRIPT_TEXT_MAX + 1u));
        ASSERT(!rvmachine_script_until(&s, "", 0));
        for (unsigned i = 0; i < RVMACHINE_SCRIPT_STEPS; i++)
            ASSERT(rvmachine_script_add(&s, "m", 1, "", 0));
        ASSERT(!rvmachine_script_add(&s, "m", 1, "", 0));
        PASS();
    } _test_next:;
    return failures;
}

/* ---- 9. user-mode clock read: the entry counter enable, and its twin ---- */
static int t_user_clock(void)
{
    int failures = 0;
    TEST("rvmachine: user mode reads the time; without the entry counter enable it traps (twin)") {
        static struct rmt_run real, same, bad;
        ASSERT(rmt_boot("uclock", RMT_REAL, NULL, &real));
        ASSERT_STR_EQ(real.out, "uclock: user mode read the time\n");
        ASSERT_EQ(real.res.stop, RVMACHINE_STOP_SHUTDOWN);
        twin_reset();
        ASSERT(rmt_boot("uclock", RMT_TWIN, NULL, &same));
        ASSERT(rmt_same(&real, &same)); /* the twin with nothing changed is the machine */
        twin_scounteren = 0;
        ASSERT(rmt_boot("uclock", RMT_TWIN, NULL, &bad));
        twin_reset();
        ASSERT_STR_EQ(bad.out, "uclock: the user clock read trapped, cause 2\n");
        printf("\n    rvmachine twin scounteren=0: real reads the time, twin traps with cause 2 -> caught\n    ");
        PASS();
    } _test_next:;
    twin_reset();
    return failures;
}

/* ---- 10. firmware remote fence reaches the hart's translation cache ---- */
static int t_remote_fence(void)
{
    int failures = 0;
    TEST("rvmachine: a firmware remote fence for this hart makes a remapped page visible (twin)") {
        static struct rmt_run real, bad;
        struct rvplat_sbi sbi;
        struct rvplat_sbi_ret ret;
        uint64_t empty[6] = {0, 0, 0, UINT64_MAX, 0, 0};
        uint64_t self[6] = {1, 0, 0, UINT64_MAX, 0, 0};
        /* the firmware handler: an empty hart set succeeds and asks for nothing */
        rvplat_sbi_init(&sbi);
        for (uint64_t fid = 0; fid <= 2u; fid++) {
            ret = rvplat_sbi_call(&sbi, RVPLAT_SBI_EXT_RFNC, fid, empty);
            ASSERT_EQ(ret.error, RVPLAT_SBI_SUCCESS);
            ASSERT_EQ(ret.action, RVPLAT_SBI_ACTION_NONE);
            ret = rvplat_sbi_call(&sbi, RVPLAT_SBI_EXT_RFNC, fid, self);
            ASSERT_EQ(ret.error, RVPLAT_SBI_SUCCESS);
            ASSERT_EQ(ret.action, RVPLAT_SBI_ACTION_RFENCE);
        }
        /* the guest remaps one page A -> B -> C with no sfence.vma of its
         * own. Reads: first; after the empty-set call (the old translation
         * may stay: A); after sfence.vma for this hart (B); after
         * sfence.vma with an address-space id for this hart (C). */
        ASSERT(rmt_boot("rfence", RMT_REAL, NULL, &real));
        ASSERT_STR_EQ(real.out, "rfence: A A B C\n");
        ASSERT_EQ(real.res.stop, RVMACHINE_STOP_SHUTDOWN);
        ASSERT_EQ(real.res.retired, 157u);
        ASSERT_EQ(real.res.fw_calls, 20u);
        /* twin: the machine ignores the fence action, the stale page stays */
        twin_reset();
        twin_rfence = false;
        ASSERT(rmt_boot("rfence", RMT_TWIN, NULL, &bad));
        twin_reset();
        ASSERT_STR_EQ(bad.out, "rfence: A A A A\n");
        ASSERT_EQ(bad.res.retired, real.res.retired); /* same path, different bytes */
        printf("\n    rvmachine twin fence ignored: real reads A A B C, twin reads A A A A -> caught\n    ");
        PASS();
    } _test_next:;
    twin_reset();
    return failures;
}

/* ---- 11. unfinished block requests and wfi ---- */
#define VQ_DESC UINT64_C(0x82000000)
#define VQ_AVAIL UINT64_C(0x82001000)
#define VQ_USED UINT64_C(0x82002000)
#define VQ_HDR UINT64_C(0x82004000)
#define VQ_STATUS UINT64_C(0x82004100)
#define VQ_DATA UINT64_C(0x82100000)
#define VQ_NUM 256u
#define VQ_DISK_BYTES (2u * 1024u * 1024u)

static uint8_t *vq_at(struct rvmachine *m, uint64_t gpa)
{
    return m->mem.bytes + (gpa - RVMACHINE_RAM_BASE);
}

static void vq_reg(struct rvmachine *m, uint32_t reg, uint32_t val)
{
    rvvirtio_mmio_write(&m->blk.dev, reg, val);
}

static void vq_desc(struct rvmachine *m, unsigned i, uint64_t addr, uint32_t len,
                    uint16_t flags, uint16_t next)
{
    uint8_t *d = vq_at(m, VQ_DESC) + 16u * i;
    zcl_write_u64_le(d, addr);
    zcl_write_u32_le(d + 8, len);
    zcl_write_u16_le(d + 12, flags);
    zcl_write_u16_le(d + 14, next);
}

/* Brings a virtio device up as a driver would, with one queue at VQ_DESC,
 * VQ_AVAIL and VQ_USED. */
static void vq_up(struct rvvirtio_dev *d)
{
    rvvirtio_mmio_write(d, RVVIRTIO_REG_STATUS, 0);
    rvvirtio_mmio_write(d, RVVIRTIO_REG_STATUS,
                        RVVIRTIO_STATUS_ACKNOWLEDGE | RVVIRTIO_STATUS_DRIVER);
    rvvirtio_mmio_write(d, RVVIRTIO_REG_DRIVER_FEATURES_SEL, 1);
    rvvirtio_mmio_write(d, RVVIRTIO_REG_DRIVER_FEATURES, 1); /* VERSION_1 */
    rvvirtio_mmio_write(d, RVVIRTIO_REG_DRIVER_FEATURES_SEL, 0);
    rvvirtio_mmio_write(d, RVVIRTIO_REG_DRIVER_FEATURES, 0);
    rvvirtio_mmio_write(d, RVVIRTIO_REG_STATUS,
                        RVVIRTIO_STATUS_ACKNOWLEDGE | RVVIRTIO_STATUS_DRIVER |
                            RVVIRTIO_STATUS_FEATURES_OK);
    rvvirtio_mmio_write(d, RVVIRTIO_REG_QUEUE_SEL, 0);
    rvvirtio_mmio_write(d, RVVIRTIO_REG_QUEUE_NUM, VQ_NUM);
    rvvirtio_mmio_write(d, RVVIRTIO_REG_QUEUE_DESC_LOW, (uint32_t)VQ_DESC);
    rvvirtio_mmio_write(d, RVVIRTIO_REG_QUEUE_DESC_HIGH, 0);
    rvvirtio_mmio_write(d, RVVIRTIO_REG_QUEUE_DRIVER_LOW, (uint32_t)VQ_AVAIL);
    rvvirtio_mmio_write(d, RVVIRTIO_REG_QUEUE_DRIVER_HIGH, 0);
    rvvirtio_mmio_write(d, RVVIRTIO_REG_QUEUE_DEVICE_LOW, (uint32_t)VQ_USED);
    rvvirtio_mmio_write(d, RVVIRTIO_REG_QUEUE_DEVICE_HIGH, 0);
    rvvirtio_mmio_write(d, RVVIRTIO_REG_QUEUE_READY, 1);
    rvvirtio_mmio_write(d, RVVIRTIO_REG_STATUS,
                        RVVIRTIO_STATUS_ACKNOWLEDGE | RVVIRTIO_STATUS_DRIVER |
                            RVVIRTIO_STATUS_FEATURES_OK | RVVIRTIO_STATUS_DRIVER_OK);
}

/* Brings the block device up and posts `count` reads of the largest admitted
 * request, all naming the one descriptor chain. */
static void retained_request(struct rvmachine *m, uint32_t type, uint16_t index)
{
    memset(vq_at(m, VQ_HDR), 0, 16);
    zcl_write_u32_le(vq_at(m, VQ_HDR), type);
    zcl_write_u64_le(vq_at(m, VQ_HDR) + 8, 1); /* sector 1 */
    vq_desc(m, 0, VQ_HDR, 16, 1, type == RVVIRTIO_BLK_T_FLUSH ? 2 : 1);
    if (type != RVVIRTIO_BLK_T_FLUSH)
        vq_desc(m, 1, VQ_DATA, 512, 1 | (type == RVVIRTIO_BLK_T_IN ? 2 : 0), 2);
    vq_desc(m, 2, VQ_STATUS, 1, 2, 0);
    *vq_at(m, VQ_STATUS) = 0xa5;
    zcl_write_u16_le(vq_at(m, VQ_AVAIL) + 4u + 2u * (index - 1u), 0);
    zcl_write_u16_le(vq_at(m, VQ_AVAIL) + 2, index);
    vq_reg(m, RVVIRTIO_REG_QUEUE_NOTIFY, 0);
}

static int t_retained_virtio(void)
{
    int failures = 0;
    static struct rmt_run r;
    struct rvmachine_disk *disk = NULL;
    TEST("rvmachine: actual virtio retained writes precede flush and backend faults reach guest status") {
        struct retained_disk b = {0};
        uint8_t kernel[4];
        zcl_write_u32_le(kernel, 0x0000006f); /* bounded guest loop */
        ASSERT_EQ(rvmachine_disk_open_backend(&disk, sizeof b.live, retained_read,
                                              retained_write, retained_flush, &b), RVMACHINE_OK);
        ASSERT(rmt_machine(&r, kernel, sizeof kernel, disk) != NULL);
        disk = NULL; /* successful create transfers only the disk handle */
        vq_up(&r.m->blk.dev);
        memset(vq_at(r.m, VQ_DATA), 0x6d, 512);
        retained_request(r.m, RVVIRTIO_BLK_T_OUT, 1);
        ASSERT_EQ(*vq_at(r.m, VQ_STATUS), RVVIRTIO_BLK_S_OK);
        ASSERT_EQ(zcl_read_u16_le(vq_at(r.m, VQ_USED) + 2), 1u);
        ASSERT_EQ(b.live[512], 0x6d);
        ASSERT_EQ(b.durable[512], 0u);
        b.flush_fail = true;
        retained_request(r.m, RVVIRTIO_BLK_T_FLUSH, 2);
        ASSERT_EQ(*vq_at(r.m, VQ_STATUS), RVVIRTIO_BLK_S_IOERR);
        ASSERT_EQ(zcl_read_u16_le(vq_at(r.m, VQ_USED) + 2), 2u);
        b.flush_fail = false;
        retained_request(r.m, RVVIRTIO_BLK_T_FLUSH, 3);
        ASSERT_EQ(*vq_at(r.m, VQ_STATUS), RVVIRTIO_BLK_S_OK);
        ASSERT_EQ(b.durable[512], 0x6d);
        b.write_fail = true;
        memset(vq_at(r.m, VQ_DATA), 0x7e, 512);
        retained_request(r.m, RVVIRTIO_BLK_T_OUT, 4);
        ASSERT_EQ(*vq_at(r.m, VQ_STATUS), RVVIRTIO_BLK_S_IOERR);
        ASSERT_EQ(b.live[512], 0x6d);
        b.read_fail = true;
        retained_request(r.m, RVVIRTIO_BLK_T_IN, 5);
        ASSERT_EQ(*vq_at(r.m, VQ_STATUS), RVVIRTIO_BLK_S_IOERR);
        ASSERT_EQ(zcl_read_u16_le(vq_at(r.m, VQ_USED) + 2), 5u);
        ASSERT_EQ(b.calls, 5u);
        ASSERT(memcmp(b.order, "WFFWR", 5) == 0);
        PASS();
    } _test_next:;
    rvmachine_destroy(r.m); r.m = NULL;
    rvmachine_disk_close(disk);
    return failures;
}

/* Brings the block device up and posts `count` reads of the largest admitted
 * request without notifying the device. */
static void vq_stage_reads(struct rvmachine *m, unsigned count)
{
    vq_up(&m->blk.dev);
    memset(vq_at(m, VQ_HDR), 0, 16); /* type 0 = read */
    zcl_write_u64_le(vq_at(m, VQ_HDR) + 8, 1); /* sector 1 */
    vq_desc(m, 0, VQ_HDR, 16, 1, 1);
    vq_desc(m, 1, VQ_DATA, (uint32_t)RVVIRTIO_BLK_REQ_BYTES_MAX, 1 | 2, 2);
    vq_desc(m, 2, VQ_STATUS, 1, 2, 0);
    memset(vq_at(m, VQ_AVAIL), 0, 4u + 2u * VQ_NUM); /* every ring slot: head 0 */
    zcl_write_u16_le(vq_at(m, VQ_AVAIL) + 2, (uint16_t)count);
}

static void vq_post_reads(struct rvmachine *m, unsigned count)
{
    vq_stage_reads(m, count);
    vq_reg(m, RVVIRTIO_REG_QUEUE_NOTIFY, 0);
}

static unsigned vq_used(struct rvmachine *m)
{
    return zcl_read_u16_le(vq_at(m, VQ_USED) + 2);
}

/* Takes the interrupt of the first capped round the way a driver would, so
 * only the left-over requests can raise it again. */
static bool vq_take_interrupt(struct rvmachine *m)
{
    rvplat_plic_write(&m->plic, RVPLAT_PLIC_PRIORITY_BASE + 4u * RVMACHINE_VIRTIO_IRQ0, 1);
    rvplat_plic_write(&m->plic, RVPLAT_PLIC_ENABLE_BASE + RVPLAT_PLIC_ENABLE_STRIDE,
                      1u << RVMACHINE_VIRTIO_IRQ0);
    if (rvplat_plic_claim(&m->plic, RVPLAT_PLIC_CTX_S) != RVMACHINE_VIRTIO_IRQ0)
        return false;
    vq_reg(m, RVVIRTIO_REG_INTERRUPT_ACK, RVVIRTIO_INT_USED_BUFFER);
    rvplat_plic_complete(&m->plic, RVPLAT_PLIC_CTX_S, RVMACHINE_VIRTIO_IRQ0);
    return !rvplat_plic_context_pending(&m->plic, RVPLAT_PLIC_CTX_S);
}

struct wait_probe {
    bool ok;            /* the fixture ran as set up */
    unsigned used_before, used_after;
    bool pending_before, pending_after;
    uint64_t skip;
    char out[64];
};

/* One capped notify leaves two requests in the ring; then the guest waits in
 * wfi for the disk interrupt or a far timer. */
static struct wait_probe wait_case(struct mem_image *im, enum rmt_engine engine)
{
    static uint8_t image[RMT_IMAGE_MAX];
    static struct rmt_run r;
    struct wait_probe p = {0};
    struct rvmachine_disk *d = NULL;
    size_t len = 0;
    const unsigned per_notify =
        (unsigned)(RVVIRTIO_BLK_NOTIFY_BYTES_MAX / RVVIRTIO_BLK_REQ_BYTES_MAX);
    if (!rmt_fixture("diskwait", image, &len)) return p;
    if (rvmachine_disk_open(&d, im->size, mem_image_read, im) != RVMACHINE_OK) return p;
    if (rmt_machine_on(&r, engine, image, len, d) == NULL) {
        rvmachine_disk_close(d);
        return p;
    }
    vq_post_reads(r.m, per_notify + 2u);
    p.used_before = vq_used(r.m);
    p.pending_before = rvvirtio_blk_pending(&r.m->blk);
    p.ok = p.used_before == per_notify && vq_take_interrupt(r.m);
    rmt_go(&r, engine, RMT_WORK);
    p.ok = p.ok && r.st == RVMACHINE_OK && r.res.stop == RVMACHINE_STOP_SHUTDOWN &&
           *vq_at(r.m, VQ_DATA) == disk_pattern(512);
    p.used_after = vq_used(r.m);
    p.pending_after = rvvirtio_blk_pending(&r.m->blk);
    p.skip = r.res.skip;
    memcpy(p.out, r.out, sizeof p.out - 1u);
    rvmachine_destroy(r.m);
    return p;
}

static int t_block_before_wait(void)
{
    int failures = 0;
    TEST("rvmachine: unfinished block requests complete before a wfi skips time (twins)") {
        static uint8_t disk[VQ_DISK_BYTES];
        struct mem_image im;
        struct wait_probe real, drain_only, service_only, neither;
        const unsigned posted =
            (unsigned)(RVVIRTIO_BLK_NOTIFY_BYTES_MAX / RVVIRTIO_BLK_REQ_BYTES_MAX) + 2u;
        mem_image_fill(&im, disk, VQ_DISK_BYTES);
        real = wait_case(&im, RMT_REAL);
        ASSERT(real.ok);
        ASSERT(real.pending_before);
        ASSERT_EQ(real.used_after, posted);
        ASSERT(!real.pending_after);
        ASSERT_STR_EQ(real.out, "diskwait: woke on the disk interrupt\n");
        ASSERT_EQ(real.skip, 0u); /* the wait ended on the disk, not the timer */
        /* each mechanism alone is enough */
        twin_reset();
        twin_service = false;
        drain_only = wait_case(&im, RMT_TWIN);
        twin_reset();
        twin_drain = false;
        service_only = wait_case(&im, RMT_TWIN);
        ASSERT(drain_only.ok && service_only.ok);
        ASSERT_EQ(drain_only.used_after, posted);
        ASSERT_EQ(drain_only.skip, 0u);
        ASSERT_STR_EQ(drain_only.out, real.out);
        ASSERT_EQ(service_only.used_after, posted);
        ASSERT_EQ(service_only.skip, 0u);
        /* twin with neither: time jumps to the timer over unfinished requests */
        twin_service = false;
        neither = wait_case(&im, RMT_TWIN);
        twin_reset();
        ASSERT(neither.ok);
        ASSERT_EQ(neither.used_after, posted - 2u);
        ASSERT(neither.pending_after);
        ASSERT_STR_EQ(neither.out, "diskwait: woke on the timer\n");
        ASSERT(neither.skip > 900000u);
        printf("\n    rvmachine twin no service before wfi: real used=%u skip=%llu, "
               "twin used=%u skip=%llu -> caught\n    ",
               real.used_after, (unsigned long long)real.skip, neither.used_after,
               (unsigned long long)neither.skip);
        ASSERT(mem_image_intact(&im));
        PASS();
    } _test_next:;
    twin_reset();
    return failures;
}

/* ---- 11b. scheduled work lands on the instruction boundary it always did ---- */
enum { RV_T0 = 5, RV_T1 = 6, RV_T2 = 7, RV_A0 = 10, RV_A7 = 17, RV_T3 = 28 };
#define RV_OP_IMM 0x13u
#define RV_OP_LOAD 0x03u
#define RV_OP_SYSTEM 0x73u
#define RV_CSR_SSTATUS 0x100u
#define RV_CSR_SIE 0x104u
#define RV_CSR_STVEC 0x105u
#define RV_ECALL 0x00000073u
#define RV_JAL_SELF 0x0000006fu
#define RV_SBI_SET_TIMER 0
#define RV_SBI_SHUTDOWN 8
#define RV_SCAUSE_IRQ (UINT64_C(1) << 63)

static uint32_t rv_i(uint32_t op, uint32_t f3, uint32_t rd, uint32_t rs1, int32_t imm)
{
    return (((uint32_t)imm & 0xfffu) << 20) | (rs1 << 15) | (f3 << 12) | (rd << 7) | op;
}

static uint32_t rv_u(uint32_t op, uint32_t rd, uint32_t imm20)
{
    return (imm20 << 12) | (rd << 7) | op;
}

static uint32_t rv_s(uint32_t f3, uint32_t rs1, uint32_t rs2, int32_t imm)
{
    uint32_t i = (uint32_t)imm & 0xfffu;
    return ((i >> 5) << 25) | (rs2 << 20) | (rs1 << 15) | (f3 << 12) | ((i & 31u) << 7) | 0x23u;
}

/* bne rs1, rs2 back by `back` bytes (a multiple of 2, at most 4094). */
static uint32_t rv_bne_back(uint32_t rs1, uint32_t rs2, uint32_t back)
{
    uint32_t o = (0u - back) & 0x1fffu;
    return ((o >> 12) << 31) | (((o >> 5) & 63u) << 25) | (rs2 << 20) | (rs1 << 15) |
           (1u << 12) | (((o >> 1) & 15u) << 8) | (((o >> 11) & 1u) << 7) | 0x63u;
}

struct rv_prog {
    uint32_t w[32];
    unsigned n;
};

static void rv_emit(struct rv_prog *p, uint32_t insn)
{
    p->w[p->n++] = insn;
}

static size_t rv_image(const struct rv_prog *p, uint8_t *out)
{
    for (unsigned i = 0; i < p->n; i++) zcl_write_u32_le(out + 4u * i, p->w[i]);
    return 4u * p->n;
}

/* Points stvec at the instruction `handler_index` words in and enables the
 * supervisor interrupt in `sie_bit`, with sstatus.SIE set: 7 instructions. */
static void rv_prologue(struct rv_prog *p, unsigned handler_index, uint32_t sie_bit)
{
    rv_emit(p, rv_u(0x17u, RV_T0, 0)); /* auipc t0, 0 */
    rv_emit(p, rv_i(RV_OP_IMM, 0, RV_T0, RV_T0, (int32_t)(4u * handler_index)));
    rv_emit(p, rv_i(RV_OP_SYSTEM, 1, 0, RV_T0, RV_CSR_STVEC)); /* csrw stvec, t0 */
    rv_emit(p, rv_i(RV_OP_IMM, 0, RV_T1, 0, (int32_t)sie_bit));
    rv_emit(p, rv_i(RV_OP_SYSTEM, 1, 0, RV_T1, RV_CSR_SIE)); /* csrw sie, t1 */
    rv_emit(p, rv_i(RV_OP_IMM, 0, RV_T1, 0, 2)); /* sstatus.SIE */
    rv_emit(p, rv_i(RV_OP_SYSTEM, 2, 0, RV_T1, RV_CSR_SSTATUS)); /* csrs sstatus, t1 */
}

static void rv_shutdown(struct rv_prog *p)
{
    rv_emit(p, rv_i(RV_OP_IMM, 0, RV_A7, 0, RV_SBI_SHUTDOWN));
    rv_emit(p, RV_ECALL);
}

static int t_sched_timer(void)
{
    int failures = 0;
    static struct rmt_run r;
    TEST("rvmachine: a timer armed for time D interrupts at retired instruction 10 D, not one later") {
        enum { DEADLINE = 200 };
        static uint8_t image[256];
        struct rv_prog p = {.n = 0};
        rv_prologue(&p, 11, 0x20u);                                   /* STIE */
        rv_emit(&p, rv_i(RV_OP_IMM, 0, RV_A0, 0, DEADLINE));
        rv_emit(&p, rv_i(RV_OP_IMM, 0, RV_A7, 0, RV_SBI_SET_TIMER));
        rv_emit(&p, RV_ECALL);                                        /* index 9 */
        rv_emit(&p, RV_JAL_SELF);                                     /* index 10 */
        rv_shutdown(&p);                                              /* handler: 11, 12 */
        ASSERT(rmt_machine(&r, image, rv_image(&p, image), NULL) != NULL);
        rmt_go(&r, RMT_REAL, RMT_WORK);
        ASSERT_EQ(r.st, RVMACHINE_OK);
        ASSERT_EQ(r.res.stop, RVMACHINE_STOP_SHUTDOWN);
        ASSERT_EQ(r.res.cause, RV_SCAUSE_IRQ | RVEMU_IRQ_STIP);
        /* the interrupt is taken before instruction 10 D, which never runs; the
         * handler's first instruction is the one more that retired */
        ASSERT_EQ(r.res.retired, (uint64_t)RVMACHINE_TICKS_PER_TIME * DEADLINE + 1u);
        ASSERT_EQ(r.res.fw_calls, 2u);
        PASS();
    } _test_next:;
    rvmachine_destroy(r.m); r.m = NULL;
    return failures;
}

static int t_sched_console(void)
{
    int failures = 0;
    static struct rmt_run r;
    TEST("rvmachine: a queued console byte interrupts the instruction after the store that enables it") {
        static uint8_t image[256];
        struct rv_prog p = {.n = 0};
        rv_prologue(&p, 17, 0x200u);                                  /* SEIE */
        rv_emit(&p, rv_u(0x37u, RV_T0, (uint32_t)(RVMACHINE_PLIC_BASE >> 12)));
        rv_emit(&p, rv_i(RV_OP_IMM, 0, RV_T1, 0, 1));
        rv_emit(&p, rv_s(2, RV_T0, RV_T1, (int32_t)(4u * RVMACHINE_UART_IRQ)));
        rv_emit(&p, rv_u(0x37u, RV_T0, (uint32_t)((RVMACHINE_PLIC_BASE +
                                                  RVPLAT_PLIC_ENABLE_BASE) >> 12)));
        rv_emit(&p, rv_i(RV_OP_IMM, 0, RV_T1, 0, 1 << RVMACHINE_UART_IRQ));
        rv_emit(&p, rv_s(2, RV_T0, RV_T1, (int32_t)RVPLAT_PLIC_ENABLE_STRIDE));
        rv_emit(&p, rv_u(0x37u, RV_T0, (uint32_t)(RVMACHINE_UART_BASE >> 12)));
        rv_emit(&p, rv_i(RV_OP_IMM, 0, RV_T1, 0, RVPLAT_UART_IER_RDA));
        rv_emit(&p, rv_s(0, RV_T0, RV_T1, RVPLAT_UART_IER));          /* index 15 */
        rv_emit(&p, RV_JAL_SELF);                                     /* index 16 */
        rv_shutdown(&p);                                              /* handler: 17, 18 */
        ASSERT(rmt_machine(&r, image, rv_image(&p, image), NULL) != NULL);
        ASSERT_EQ(rvmachine_console_input(r.m, (const uint8_t *)"k", 1), 1u);
        rmt_go(&r, RMT_REAL, RMT_WORK);
        ASSERT_EQ(r.st, RVMACHINE_OK);
        ASSERT_EQ(r.res.stop, RVMACHINE_STOP_SHUTDOWN);
        ASSERT_EQ(r.res.cause, RV_SCAUSE_IRQ | RVEMU_IRQ_SEIP);
        /* 16 instructions retire through the enabling store, the handler's first
         * is the 17th */
        ASSERT_EQ(r.res.retired, 17u);
        PASS();
    } _test_next:;
    rvmachine_destroy(r.m); r.m = NULL;
    return failures;
}

static int t_sched_block(void)
{
    int failures = 0;
    static struct rmt_run r;
    struct rvmachine_disk *d = NULL;
    TEST("rvmachine: block requests left by a guest notify finish before the next instruction") {
        enum { POSTED = RVVIRTIO_BLK_NOTIFY_BYTES_MAX / RVVIRTIO_BLK_REQ_BYTES_MAX + 2 };
        static uint8_t image[256], disk[VQ_DISK_BYTES];
        struct rv_prog p = {.n = 0};
        struct mem_image im;
        mem_image_fill(&im, disk, VQ_DISK_BYTES);
        /* t1 = VQ_USED, built from the pc: lui would sign-extend bit 31 */
        rv_emit(&p, rv_u(0x17u, RV_T1, (uint32_t)((VQ_USED - RVMACHINE_KERNEL_BASE) >> 12)));
        rv_emit(&p, rv_u(0x37u, RV_T0, (uint32_t)(RVMACHINE_VIRTIO_BASE >> 12)));
        rv_emit(&p, rv_i(RV_OP_IMM, 0, RV_T3, 0, POSTED));
        rv_emit(&p, rv_s(2, RV_T0, 0, RVVIRTIO_REG_QUEUE_NOTIFY));    /* index 3 */
        rv_emit(&p, rv_i(RV_OP_LOAD, 5, RV_T2, RV_T1, 2));            /* index 4: used idx */
        rv_emit(&p, rv_bne_back(RV_T2, RV_T3, 4));
        rv_shutdown(&p);
        ASSERT_EQ(rvmachine_disk_open(&d, im.size, mem_image_read, &im), RVMACHINE_OK);
        ASSERT(rmt_machine(&r, image, rv_image(&p, image), d) != NULL);
        d = NULL;
        vq_stage_reads(r.m, POSTED);
        ASSERT_EQ(vq_used(r.m), 0u);
        rmt_go(&r, RMT_REAL, RMT_WORK);
        ASSERT_EQ(r.st, RVMACHINE_OK);
        ASSERT_EQ(r.res.stop, RVMACHINE_STOP_SHUTDOWN);
        ASSERT_EQ(vq_used(r.m), (unsigned)POSTED);
        /* The notify is the 4th instruction. It serves a capped part and the
         * round before the 5th, the first load, serves the rest, so that load
         * already sees every request done. Then the branch and the shutdown's
         * first instruction retire. */
        ASSERT_EQ(r.res.retired, 7u);
        ASSERT(mem_image_intact(&im));
        PASS();
    } _test_next:;
    rvmachine_destroy(r.m); r.m = NULL;
    rvmachine_disk_close(d);
    return failures;
}

/* ---- 12. one kernel per machine ---- */
static int t_one_kernel(void)
{
    int failures = 0;
    TEST("rvmachine: a second kernel load is refused and leaves the machine as it was") {
        static uint8_t tiny[RMT_IMAGE_MAX], other[RMT_IMAGE_MAX];
        size_t tiny_len = 0, other_len = 0;
        struct rmt_run once, twice;
        ASSERT(rmt_boot("tiny", RMT_REAL, NULL, &once));
        ASSERT(rmt_fixture("tiny", tiny, &tiny_len));
        ASSERT(rmt_fixture("paging", other, &other_len));
        ASSERT(rmt_machine(&twice, tiny, tiny_len, NULL) != NULL);
        /* before the first instruction */
        ASSERT_EQ(rvmachine_load_kernel(twice.m, other, other_len), RVMACHINE_ERR_STATE);
        ASSERT(memcmp(twice.m->mem.bytes + 2u * MIB, tiny, tiny_len) == 0);
        ASSERT_EQ(twice.m->hart.pc, RVMACHINE_KERNEL_BASE);
        /* and in the middle of a run: the guest carries on as if never asked */
        rmt_go(&twice, RMT_REAL, 100);
        ASSERT_EQ(twice.res.stop, RVMACHINE_STOP_BUDGET);
        ASSERT_EQ(rvmachine_load_kernel(twice.m, other, other_len), RVMACHINE_ERR_STATE);
        ASSERT_EQ(rvmachine_load_kernel(twice.m, tiny, tiny_len), RVMACHINE_ERR_STATE);
        rmt_go(&twice, RMT_REAL, RMT_WORK);
        rvmachine_destroy(twice.m);
        twice.m = NULL;
        ASSERT_EQ(twice.st, RVMACHINE_OK);
        ASSERT(rmt_same(&once, &twice));
        PASS();
    } _test_next:;
    return failures;
}

/* ---- 13. the clock saturates ---- */
static int t_clock_saturates(void)
{
    int failures = 0;
    TEST("rvmachine: sleeping to a deadline at the top of the range leaves the clock there") {
        /* li t0,32; csrw sie,t0 (timer wakes a wfi); li a0,-2; li a7,0; ecall
         * (legacy set_timer to 2^64 - 2); wfi; j . */
        static const uint8_t guest[] = {
            0x93, 0x02, 0x00, 0x02, 0x73, 0x90, 0x42, 0x10, 0x13, 0x05, 0xe0, 0xff,
            0x93, 0x08, 0x00, 0x00, 0x73, 0x00, 0x00, 0x00, 0x73, 0x00, 0x50, 0x10,
            0x6f, 0x00, 0x00, 0x00};
        struct rmt_run r;
        ASSERT(rmt_machine(&r, guest, sizeof guest, NULL) != NULL);
        rmt_go(&r, RMT_REAL, 1000);
        ASSERT_EQ(r.st, RVMACHINE_OK);
        ASSERT_EQ(r.res.stop, RVMACHINE_STOP_BUDGET);
        ASSERT_EQ(r.res.skip, UINT64_MAX - 1u); /* slept from time 0 to the deadline */
        ASSERT(r.res.retired >= 900u);          /* then ran on: 90 more time units */
        ASSERT_EQ(r.res.guest_time, UINT64_MAX);
        ASSERT_EQ(r.m->hart.time, UINT64_MAX); /* what the guest reads */
        rvmachine_destroy(r.m);
        PASS();
    } _test_next:;
    return failures;
}

/* ---- 14. device data movement is charged to the work budget ---- */
#define FLOOD_WORK 64u
#define FLOOD_PER_NOTIFY \
    ((unsigned)(RVVIRTIO_BLK_NOTIFY_BYTES_MAX / RVVIRTIO_BLK_REQ_BYTES_MAX))

struct flood_probe {
    bool ok; /* the machine was set up and ran */
    enum rvmachine_stop stop;
    uint64_t retired, device_work, asked;
    unsigned used;
};

/* A guest that does nothing but post the largest admitted reads, a full
 * notify's worth at a time: five instructions make the host copy 128 MiB. */
static struct flood_probe flood_case(struct mem_image *im, enum rmt_engine engine)
{
    /* loop: lhu t0,2(s1); addi t0,t0,128; sh t0,2(s1) (avail.idx += 128);
     * sw zero,0x50(s2) (QueueNotify); j loop */
    static const uint8_t guest[] = {
        0x83, 0xd2, 0x24, 0x00, 0x93, 0x82, 0x02, 0x08, 0x23, 0x91, 0x54, 0x00,
        0x23, 0x28, 0x09, 0x04, 0x6f, 0xf0, 0x1f, 0xff};
    static struct rmt_run r;
    struct flood_probe p = {0};
    struct rvmachine_disk *d = NULL;
    if (FLOOD_PER_NOTIFY != 128u) return p; /* the addi above */
    if (rvmachine_disk_open(&d, im->size, mem_image_read, im) != RVMACHINE_OK) return p;
    if (rmt_machine_on(&r, engine, guest, sizeof guest, d) == NULL) {
        rvmachine_disk_close(d);
        return p;
    }
    vq_post_reads(r.m, 0); /* the driver setup; every ring slot names the read */
    r.m->hart.x[9] = VQ_AVAIL;              /* s1 */
    r.m->hart.x[18] = RVMACHINE_VIRTIO_BASE; /* s2: the block device's slot */
    im->asked = 0;
    rmt_go(&r, engine, FLOOD_WORK);
    p.ok = r.st == RVMACHINE_OK;
    p.stop = r.res.stop;
    p.retired = r.res.retired;
    p.device_work = r.res.device_work;
    p.asked = im->asked;
    p.used = vq_used(r.m);
    rvmachine_destroy(r.m);
    return p;
}

static int t_device_work(void)
{
    int failures = 0;
    TEST("rvmachine: a guest flooding block reads runs out of budget, not the host (twin)") {
        static uint8_t disk[VQ_DISK_BYTES];
        struct mem_image im;
        struct flood_probe real, again, twin;
        /* the budget in bytes, plus the one capped notify that may cross it */
        const uint64_t bound = (uint64_t)FLOOD_WORK * RVMACHINE_DEVICE_WORK_BYTES +
                               RVVIRTIO_BLK_NOTIFY_BYTES_MAX + RVVIRTIO_BLK_REQ_BYTES_MAX;
        mem_image_fill(&im, disk, VQ_DISK_BYTES);
        real = flood_case(&im, RMT_REAL);
        ASSERT(real.ok);
        ASSERT_EQ(real.stop, RVMACHINE_STOP_BUDGET);
        ASSERT(real.used >= FLOOD_PER_NOTIFY); /* the flood did reach the disk */
        ASSERT(real.asked >= RVVIRTIO_BLK_NOTIFY_BYTES_MAX);
        ASSERT(real.asked <= bound);
        ASSERT(real.retired < FLOOD_WORK); /* the data ended the run, not the count */
        /* the three terms: one unit per started 4096 bytes, settled per notify */
        ASSERT_EQ(real.device_work,
                  real.asked / RVMACHINE_DEVICE_WORK_BYTES);
        ASSERT(real.retired + real.device_work >= FLOOD_WORK);
        again = flood_case(&im, RMT_REAL);
        ASSERT(again.ok && again.retired == real.retired &&
               again.device_work == real.device_work && again.asked == real.asked);
        /* twin without the charge: the instruction count alone ends the run */
        twin_reset();
        twin_charge = false;
        twin = flood_case(&im, RMT_TWIN);
        twin_reset();
        ASSERT(twin.ok);
        ASSERT_EQ(twin.stop, RVMACHINE_STOP_BUDGET);
        ASSERT_EQ(twin.retired, (uint64_t)FLOOD_WORK);
        ASSERT(twin.asked > bound);
        printf("\n    rvmachine twin no device charge: real retired=%llu moved=%llu MiB, "
               "twin retired=%llu moved=%llu MiB -> caught\n    ",
               (unsigned long long)real.retired, (unsigned long long)(real.asked / MIB),
               (unsigned long long)twin.retired, (unsigned long long)(twin.asked / MIB));
        ASSERT(mem_image_intact(&im));
        PASS();
    } _test_next:;
    twin_reset();
    return failures;
}

/* ---- 15. the entropy device ---- */
#define ENT_ASKED 40u /* bytes the entropy fixture asks for */
struct ent_src {
    uint64_t pos;  /* bytes given so far; the next one is ent_pattern(pos) */
    uint64_t left; /* bytes the source will still give */
    unsigned calls;
};

static uint8_t ent_pattern(uint64_t i)
{
    return (uint8_t)(0xa0u + 7u * i);
}

static size_t ent_fill(void *ctx, uint8_t *buf, size_t n)
{
    struct ent_src *s = ctx;
    size_t k = (uint64_t)n < s->left ? n : (size_t)s->left;
    s->calls++;
    for (size_t i = 0; i < k; i++) buf[i] = ent_pattern(s->pos++);
    s->left -= k;
    return k;
}

/* A 64 MiB machine with the image loaded and the source attached; src NULL
 * gives the machine no entropy device. */
static struct rvmachine *ent_machine(struct rmt_run *r, enum rmt_engine engine,
                                     const uint8_t *image, size_t len,
                                     struct ent_src *src)
{
    return rmt_machine_cfg(r, engine, image, len,
                           (struct rvmachine_config){
                               .ram_bytes = RMT_RAM,
                               .entropy = src != NULL ? ent_fill : NULL,
                               .entropy_ctx = src});
}

/* What the entropy fixture prints for the first ENT_ASKED bytes of the source. */
static void ent_expected(char *out, size_t cap)
{
    size_t n = (size_t)snprintf(out, cap, "entropy: ");
    for (uint64_t i = 0; i < ENT_ASKED; i++)
        n += (size_t)snprintf(out + n, cap - n, "%02x", ent_pattern(i));
    snprintf(out + n, cap - n, " len=%02x irq=1\n", (unsigned)ENT_ASKED);
}

static int t_entropy(void)
{
    int failures = 0;
    TEST("rvmachine: a guest reads exactly its entropy source's bytes through slot 1; no source, no device") {
        static uint8_t image[RMT_IMAGE_MAX], tiny[RMT_IMAGE_MAX];
        static struct rmt_run with, again, without, plain, fed;
        static uint8_t tree_with[RVMACHINE_DTB_MAX];
        struct ent_src src = {.left = UINT64_MAX}, src2 = {.left = UINT64_MAX};
        struct ent_src unused = {.left = UINT64_MAX};
        char want[160];
        size_t len = 0, tiny_len = 0, tree_len = 0, tree_len2 = 0;
        uint64_t id = 0;
        const uint64_t slot1 = RVMACHINE_VIRTIO_BASE +
                               RVMACHINE_VIRTIO_SLOT_ENTROPY * RVMACHINE_VIRTIO_STRIDE;
        ASSERT(rmt_fixture("entropy", image, &len));
        ent_expected(want, sizeof want);
        /* with a source: the device is there and hands over the source's bytes */
        ASSERT(ent_machine(&with, RMT_REAL, image, len, &src) != NULL);
        ASSERT_EQ(with.m->mem.io_load(with.m->mem.io_ctx, slot1 + RVVIRTIO_REG_DEVICE_ID, 4, &id), 0);
        ASSERT_EQ(id, (uint64_t)RVVIRTIO_DEVICE_ID_ENTROPY);
        memcpy(tree_with, rvmachine_dtb(with.m, &tree_len), with.m->dtb_len);
        rmt_go(&with, RMT_REAL, RMT_WORK);
        ASSERT_EQ(with.st, RVMACHINE_OK);
        ASSERT_EQ(with.res.stop, RVMACHINE_STOP_SHUTDOWN);
        ASSERT_STR_EQ(with.out, want);
        ASSERT_EQ(src.pos, ENT_ASKED); /* asked for what the guest asked, no more */
        ASSERT_EQ(rvvirtio_rng_counters_get(&with.m->rng).bytes, ENT_ASKED);
        ASSERT_EQ(rvvirtio_rng_counters_get(&with.m->rng).requests, 1u);
        ASSERT_EQ(with.res.device_work, 1u); /* forty bytes: one started unit */
        rvmachine_destroy(with.m);
        /* the same source again: the same run */
        ASSERT(ent_machine(&again, RMT_REAL, image, len, &src2) != NULL);
        rmt_go(&again, RMT_REAL, RMT_WORK);
        rvmachine_destroy(again.m);
        ASSERT(rmt_same(&with, &again));
        ASSERT_EQ(again.res.device_work, with.res.device_work);
        /* without a source: slot 1 is an empty slot, in the same device tree */
        ASSERT(ent_machine(&without, RMT_REAL, image, len, NULL) != NULL);
        ASSERT_EQ(without.m->mem.io_load(without.m->mem.io_ctx, slot1 + RVVIRTIO_REG_DEVICE_ID, 4, &id), 0);
        ASSERT_EQ(id, 0u);
        ASSERT_EQ(without.m->mem.io_load(without.m->mem.io_ctx, slot1 + RVVIRTIO_REG_MAGIC, 4, &id), 0);
        ASSERT_EQ(id, (uint64_t)RVVIRTIO_MAGIC);
        ASSERT(rvmachine_dtb(without.m, &tree_len2) != NULL);
        ASSERT(tree_len2 == tree_len &&
               memcmp(rvmachine_dtb(without.m, &tree_len2), tree_with, tree_len) == 0);
        rmt_go(&without, RMT_REAL, RMT_WORK);
        ASSERT_EQ(without.res.stop, RVMACHINE_STOP_SHUTDOWN);
        ASSERT_STR_EQ(without.out, "entropy: no device\n");
        ASSERT_EQ(without.res.device_work, 0u);
        rvmachine_destroy(without.m);
        /* a guest that never touches the device runs the same with it attached */
        ASSERT(rmt_boot("tiny", RMT_REAL, NULL, &plain));
        ASSERT(rmt_fixture("tiny", tiny, &tiny_len));
        ASSERT(ent_machine(&fed, RMT_REAL, tiny, tiny_len, &unused) != NULL);
        rmt_go(&fed, RMT_REAL, RMT_WORK);
        rvmachine_destroy(fed.m);
        ASSERT(rmt_same(&plain, &fed));
        ASSERT_EQ(unused.calls, 0u);
        ASSERT_EQ(fed.res.device_work, 0u);
        PASS();
    } _test_next:;
    return failures;
}

static int t_entropy_dry(void)
{
    int failures = 0;
    TEST("rvmachine: an empty entropy source is asked once, then again only when it is ready") {
        static uint8_t image[RMT_IMAGE_MAX];
        static struct rmt_run r;
        struct ent_src src = {.left = 0};
        char want[160];
        size_t len = 0;
        ASSERT(rmt_fixture("entropy", image, &len));
        ent_expected(want, sizeof want);
        ASSERT(ent_machine(&r, RMT_REAL, image, len, &src) != NULL);
        rmt_go(&r, RMT_REAL, 300); /* device set up, request posted, now polling */
        ASSERT_EQ(r.res.stop, RVMACHINE_STOP_BUDGET);
        ASSERT_EQ(src.calls, 1u);
        ASSERT_STR_EQ(r.out, "");
        ASSERT(rvvirtio_rng_pending(&r.m->rng));
        /* bytes arrive, but nobody said so: the request keeps waiting and the
         * source is not asked on every instruction */
        src.left = UINT64_MAX;
        rmt_go(&r, RMT_REAL, 300);
        ASSERT_EQ(r.res.stop, RVMACHINE_STOP_BUDGET);
        ASSERT_EQ(src.calls, 1u);
        ASSERT_EQ(r.res.device_work, 0u);
        rvmachine_entropy_ready(r.m);
        rmt_go(&r, RMT_REAL, RMT_WORK);
        ASSERT_EQ(r.res.stop, RVMACHINE_STOP_SHUTDOWN);
        ASSERT_STR_EQ(r.out, want);
        ASSERT_EQ(src.pos, ENT_ASKED);
        ASSERT_EQ(r.res.device_work, 1u);
        rvmachine_destroy(r.m);
        /* a source that stays empty: the guest gives up by itself */
        src = (struct ent_src){.left = 0};
        ASSERT(ent_machine(&r, RMT_REAL, image, len, &src) != NULL);
        rmt_go(&r, RMT_REAL, RMT_WORK);
        ASSERT_EQ(r.res.stop, RVMACHINE_STOP_SHUTDOWN);
        ASSERT_STR_EQ(r.out, "entropy: nothing yet\n");
        ASSERT_EQ(src.calls, 1u);
        ASSERT_EQ(r.res.device_work, 0u);
        rvmachine_destroy(r.m);
        PASS();
    } _test_next:;
    return failures;
}

struct both_probe {
    bool ok; /* the machine was built and the block requests were left over */
    uint64_t id0, id1;      /* device ids of slot 0 and slot 1 */
    uint64_t plic_pending;  /* the PLIC pending word after the run */
    unsigned blk_used;      /* block requests completed */
    uint64_t device_work;
    uint64_t asked;
    char out[160];
};

/* A machine with a disk and, when src is given, an entropy source runs the
 * entropy fixture while two block requests are left over from a capped
 * notify: both devices have work in the same service rounds. */
static struct both_probe both_case(struct mem_image *im, struct ent_src *src)
{
    static uint8_t image[RMT_IMAGE_MAX];
    static struct rmt_run r;
    struct both_probe p = {0};
    struct rvmachine_disk *d = NULL;
    size_t len = 0;
    const unsigned per_notify =
        (unsigned)(RVVIRTIO_BLK_NOTIFY_BYTES_MAX / RVVIRTIO_BLK_REQ_BYTES_MAX);
    if (!rmt_fixture("entropy", image, &len)) return p;
    if (rvmachine_disk_open(&d, im->size, mem_image_read, im) != RVMACHINE_OK) return p;
    if (rmt_machine_cfg(&r, RMT_REAL, image, len,
                        (struct rvmachine_config){
                            .ram_bytes = RMT_RAM, .disk = d,
                            .entropy = src != NULL ? ent_fill : NULL,
                            .entropy_ctx = src}) == NULL) {
        rvmachine_disk_close(d);
        return p;
    }
    (void)r.m->mem.io_load(r.m->mem.io_ctx, RVMACHINE_VIRTIO_BASE + RVVIRTIO_REG_DEVICE_ID,
                           4, &p.id0);
    (void)r.m->mem.io_load(r.m->mem.io_ctx,
                           RVMACHINE_VIRTIO_BASE + RVMACHINE_VIRTIO_STRIDE +
                               RVVIRTIO_REG_DEVICE_ID, 4, &p.id1);
    vq_post_reads(r.m, per_notify + 2u);
    p.ok = vq_used(r.m) == per_notify && rvvirtio_blk_pending(&r.m->blk);
    rmt_go(&r, RMT_REAL, RMT_WORK);
    p.ok = p.ok && r.st == RVMACHINE_OK && r.res.stop == RVMACHINE_STOP_SHUTDOWN;
    (void)r.m->mem.io_load(r.m->mem.io_ctx, RVMACHINE_PLIC_BASE + RVPLAT_PLIC_PENDING_BASE,
                           4, &p.plic_pending);
    p.blk_used = vq_used(r.m);
    p.device_work = r.res.device_work;
    p.asked = src != NULL ? src->pos : 0;
    memcpy(p.out, r.out, sizeof p.out - 1u);
    rvmachine_destroy(r.m);
    return p;
}

static int t_entropy_with_disk(void)
{
    int failures = 0;
    TEST("rvmachine: the entropy device works alongside the block device, each on its own line") {
        static uint8_t disk[VQ_DISK_BYTES];
        struct mem_image im;
        struct ent_src src = {.left = UINT64_MAX};
        struct both_probe disk_only, both;
        char want[160];
        const unsigned per_notify =
            (unsigned)(RVVIRTIO_BLK_NOTIFY_BYTES_MAX / RVVIRTIO_BLK_REQ_BYTES_MAX);
        ent_expected(want, sizeof want);
        mem_image_fill(&im, disk, VQ_DISK_BYTES);
        disk_only = both_case(&im, NULL);
        ASSERT(disk_only.ok);
        ASSERT_EQ(disk_only.id0, (uint64_t)RVVIRTIO_DEVICE_ID_BLOCK);
        ASSERT_EQ(disk_only.id1, 0u);
        ASSERT_STR_EQ(disk_only.out, "entropy: no device\n");
        ASSERT_EQ(disk_only.blk_used, per_notify + 2u);
        ASSERT_EQ(disk_only.plic_pending, UINT64_C(1) << RVMACHINE_VIRTIO_IRQ0);
        both = both_case(&im, &src);
        ASSERT(both.ok);
        ASSERT_EQ(both.id0, (uint64_t)RVVIRTIO_DEVICE_ID_BLOCK);
        ASSERT_EQ(both.id1, (uint64_t)RVVIRTIO_DEVICE_ID_ENTROPY);
        ASSERT_STR_EQ(both.out, want);            /* the source's bytes */
        ASSERT_EQ(both.asked, ENT_ASKED);
        ASSERT_EQ(both.blk_used, per_notify + 2u); /* the left-over reads finished too */
        /* each device raised its own source: 1 for the disk, 2 for entropy */
        ASSERT_EQ(both.plic_pending,
                  (UINT64_C(1) << RVMACHINE_VIRTIO_IRQ0) |
                      (UINT64_C(1) << (RVMACHINE_VIRTIO_IRQ0 + RVMACHINE_VIRTIO_SLOT_ENTROPY)));
        /* the same disk work, plus one unit for the forty bytes */
        ASSERT_EQ(both.device_work, disk_only.device_work + 1u);
        ASSERT(disk_only.device_work >= per_notify + 2u);
        ASSERT(mem_image_intact(&im));
        PASS();
    } _test_next:;
    return failures;
}

/* A guest that does nothing but ask for entropy, a full notify's worth of
 * maximal requests at a time: five instructions make the host deliver 64 KiB. */
static struct flood_probe ent_flood_case(enum rmt_engine engine)
{
    /* loop: lhu t0,2(s1); addi t0,t0,16; sh t0,2(s1) (avail.idx += 16);
     * sw zero,0x50(s2) (QueueNotify); j loop */
    static const uint8_t guest[] = {
        0x83, 0xd2, 0x24, 0x00, 0x93, 0x82, 0x02, 0x01, 0x23, 0x91, 0x54, 0x00,
        0x23, 0x28, 0x09, 0x04, 0x6f, 0xf0, 0x1f, 0xff};
    static struct rmt_run r;
    struct ent_src src = {.left = UINT64_MAX};
    struct flood_probe p = {0};
    if (RVVIRTIO_RNG_NOTIFY_BYTES_MAX / RVVIRTIO_RNG_REQ_BYTES_MAX != 16u) return p;
    if (ent_machine(&r, engine, guest, sizeof guest, &src) == NULL) return p;
    vq_up(&r.m->rng.dev);
    vq_desc(r.m, 0, VQ_DATA, RVVIRTIO_RNG_REQ_BYTES_MAX, 2, 0);
    memset(vq_at(r.m, VQ_AVAIL), 0, 4u + 2u * VQ_NUM); /* every ring slot: head 0 */
    r.m->hart.x[9] = VQ_AVAIL; /* s1 */
    r.m->hart.x[18] = RVMACHINE_VIRTIO_BASE +
                      RVMACHINE_VIRTIO_SLOT_ENTROPY * RVMACHINE_VIRTIO_STRIDE; /* s2 */
    rmt_go(&r, engine, FLOOD_WORK);
    p.ok = r.st == RVMACHINE_OK;
    p.stop = r.res.stop;
    p.retired = r.res.retired;
    p.device_work = r.res.device_work;
    p.asked = src.pos;
    p.used = vq_used(r.m);
    rvmachine_destroy(r.m);
    return p;
}

static int t_entropy_work(void)
{
    int failures = 0;
    TEST("rvmachine: a guest flooding entropy requests runs out of budget, not the host (twin)") {
        struct flood_probe real, twin;
        /* the budget in bytes, plus the one capped notify that may cross it */
        const uint64_t bound = (uint64_t)FLOOD_WORK * RVMACHINE_DEVICE_WORK_BYTES +
                               RVVIRTIO_RNG_NOTIFY_BYTES_MAX;
        real = ent_flood_case(RMT_REAL);
        ASSERT(real.ok);
        ASSERT_EQ(real.stop, RVMACHINE_STOP_BUDGET);
        ASSERT(real.asked >= RVVIRTIO_RNG_NOTIFY_BYTES_MAX); /* the flood did flow */
        ASSERT(real.asked <= bound);
        ASSERT(real.retired < FLOOD_WORK);
        ASSERT_EQ(real.device_work, real.asked / RVMACHINE_DEVICE_WORK_BYTES);
        ASSERT_EQ(real.retired + real.device_work, (uint64_t)FLOOD_WORK);
        /* twin without the charge: the instruction count alone ends the run */
        twin_reset();
        twin_charge = false;
        twin = ent_flood_case(RMT_TWIN);
        twin_reset();
        ASSERT(twin.ok);
        ASSERT_EQ(twin.stop, RVMACHINE_STOP_BUDGET);
        ASSERT_EQ(twin.retired, (uint64_t)FLOOD_WORK);
        ASSERT(twin.asked > bound);
        printf("\n    rvmachine twin no device charge (entropy): real retired=%llu "
               "delivered=%llu KiB, twin retired=%llu delivered=%llu KiB -> caught\n    ",
               (unsigned long long)real.retired, (unsigned long long)(real.asked / 1024u),
               (unsigned long long)twin.retired, (unsigned long long)(twin.asked / 1024u));
        PASS();
    } _test_next:;
    twin_reset();
    return failures;
}

/* ---- 16. wait stops: the host moves guest time ---- */
static struct rvmachine *wait_machine(struct rmt_run *r, enum rmt_engine engine,
                                      const char *fixture, bool wait_stops)
{
    static uint8_t image[RMT_IMAGE_MAX];
    size_t len = 0;
    if (!rmt_fixture(fixture, image, &len)) return NULL;
    return rmt_machine_cfg(r, engine, image, len,
                           (struct rvmachine_config){.ram_bytes = RMT_RAM,
                                                     .wait_stops = wait_stops});
}

#define WAIT_REFUSED UINT_MAX
/* The re-arm guest stops this far in with its last deadline behind it. */
#define REARM_OVERDUE_WORK 50u

/* Drives a machine the way a host loop does: every wait stop is answered by
 * advancing guest time exactly to the returned deadline. Returns the number
 * of wait stops seen (at most max_waits + 1), or WAIT_REFUSED when a deadline
 * did not lie ahead, an advance was refused or a wait stop left runnable work. */
static unsigned wait_drive(struct rmt_run *r, enum rmt_engine engine, uint64_t work,
                           unsigned max_waits)
{
    unsigned waits = 0;
    for (;;) {
        rmt_go(r, engine, work);
        if (r->st != RVMACHINE_OK || r->res.stop != RVMACHINE_STOP_WAIT) return waits;
        /* at a wait stop nothing is left that a run could act on */
        if ((rvmachine_pending(r->m) & RVMACHINE_PENDING_RUNNABLE) != 0) return WAIT_REFUSED;
        if (++waits > max_waits) return waits;
        if (r->res.timer_deadline <= r->res.guest_time) return WAIT_REFUSED;
        if (rvmachine_advance_time(r->m, r->res.timer_deadline) != RVMACHINE_OK)
            return WAIT_REFUSED;
    }
}

static int t_wait_stop(void)
{
    int failures = 0;
    TEST("rvmachine: with wait stops a timed wfi returns its deadline and only the host moves time") {
        static struct rmt_run plain, w;
        struct rvmachine_result kept;
        uint64_t deadline, at;
        ASSERT(rmt_boot("tiny", RMT_REAL, NULL, &plain)); /* default: the machine jumps */
        ASSERT_EQ(plain.res.stop, RVMACHINE_STOP_SHUTDOWN);
        ASSERT_EQ(plain.res.skip, 999u);
        ASSERT_EQ(plain.res.timer_deadline, RVMACHINE_NO_DEADLINE); /* disarmed by the guest */
        ASSERT(wait_machine(&w, RMT_REAL, "tiny", true) != NULL);
        ASSERT_EQ(rvmachine_timer_deadline(w.m), RVMACHINE_NO_DEADLINE);
        ASSERT_EQ(rvmachine_pending(w.m), 0u);
        rmt_go(&w, RMT_REAL, RMT_WORK);
        ASSERT_EQ(w.st, RVMACHINE_OK);
        ASSERT_EQ(w.res.stop, RVMACHINE_STOP_WAIT);
        ASSERT_STR_EQ(rvmachine_stop_name(w.res.stop), "wait");
        ASSERT_STR_EQ(w.out, "tiny: hello from S-mode\nprobe putchar=1\n");
        ASSERT_EQ(w.res.skip, 0u); /* nothing jumped */
        deadline = w.res.timer_deadline;
        at = w.res.guest_time;
        ASSERT_EQ(deadline, at + plain.res.skip); /* where the default mode jumps to */
        ASSERT_EQ(rvmachine_timer_deadline(w.m), deadline);
        ASSERT_EQ(rvmachine_time(w.m), at);
        kept = w.res;
        /* nothing done since the stop: no second one, and nothing moves */
        ASSERT_EQ(rvmachine_run(w.m, RMT_WORK, &w.res), RVMACHINE_ERR_WAITING);
        ASSERT_STR_EQ(rvmachine_status_name(RVMACHINE_ERR_WAITING),
                      "the hart waits and nothing can wake it yet");
        ASSERT(memcmp(&kept, &w.res, sizeof kept) == 0);
        ASSERT_EQ(rvmachine_retired(w.m), kept.retired);
        /* time goes neither backwards nor past the deadline, by name */
        ASSERT_EQ(rvmachine_advance_time(w.m, at - 1u), RVMACHINE_ERR_TIME_BACKWARDS);
        ASSERT_EQ(rvmachine_advance_time(w.m, 0), RVMACHINE_ERR_TIME_BACKWARDS);
        ASSERT_EQ(rvmachine_advance_time(w.m, deadline + 1u), RVMACHINE_ERR_TIME_PAST_DEADLINE);
        ASSERT_EQ(rvmachine_advance_time(w.m, UINT64_MAX), RVMACHINE_ERR_TIME_PAST_DEADLINE);
        ASSERT_EQ(rvmachine_advance_time(NULL, deadline), RVMACHINE_ERR_ARG);
        ASSERT_EQ(rvmachine_time(w.m), at);
        /* the present is accepted and is not an advance */
        ASSERT_EQ(rvmachine_advance_time(w.m, at), RVMACHINE_OK);
        ASSERT_EQ(rvmachine_time(w.m), at);
        ASSERT_EQ(rvmachine_run(w.m, RMT_WORK, &w.res), RVMACHINE_ERR_WAITING);
        /* part of the way: the timer is not due, nothing can wake the hart, a
         * run is still refused */
        ASSERT_EQ(rvmachine_advance_time(w.m, deadline - 10u), RVMACHINE_OK);
        ASSERT_EQ(rvmachine_time(w.m), deadline - 10u);
        ASSERT_EQ(rvmachine_timer_deadline(w.m), deadline);
        ASSERT_EQ(rvmachine_run(w.m, RMT_WORK, &w.res), RVMACHINE_ERR_WAITING);
        ASSERT_EQ(rvmachine_retired(w.m), kept.retired); /* waiting does no work */
        ASSERT_EQ(w.m->fw_calls, kept.fw_calls);
        /* to the deadline: the timer interrupt is delivered and the guest finishes
         * exactly as it does when the machine jumps by itself */
        ASSERT_EQ(rvmachine_advance_time(w.m, deadline), RVMACHINE_OK);
        rmt_go(&w, RMT_REAL, RMT_WORK);
        ASSERT_EQ(w.res.stop, RVMACHINE_STOP_SHUTDOWN);
        ASSERT(rmt_same(&plain, &w));
        ASSERT_EQ(w.res.skip, 999u);
        ASSERT_EQ(rvmachine_advance_time(w.m, UINT64_MAX), RVMACHINE_ERR_STATE); /* powered off */
        rvmachine_destroy(w.m);
        /* a timer already overdue allows no advance, and the present is still
         * the present */
        ASSERT(wait_machine(&w, RMT_REAL, "rearm", true) != NULL);
        rmt_go(&w, RMT_REAL, REARM_OVERDUE_WORK);
        ASSERT_EQ(w.res.stop, RVMACHINE_STOP_BUDGET);
        ASSERT(w.res.timer_deadline < w.res.guest_time);
        ASSERT_EQ(rvmachine_advance_time(w.m, w.res.guest_time), RVMACHINE_OK);
        ASSERT_EQ(rvmachine_advance_time(w.m, w.res.guest_time + 1u),
                  RVMACHINE_ERR_TIME_PAST_DEADLINE);
        ASSERT_EQ(rvmachine_time(w.m), w.res.guest_time);
        rvmachine_destroy(w.m);
        /* the advance works without wait stops too; with no timer armed any
         * later time is accepted */
        ASSERT(wait_machine(&w, RMT_REAL, "tiny", false) != NULL);
        ASSERT_EQ(rvmachine_advance_time(w.m, 7), RVMACHINE_OK);
        ASSERT_EQ(rvmachine_time(w.m), 7u);
        ASSERT_EQ(rvmachine_advance_time(w.m, 3), RVMACHINE_ERR_TIME_BACKWARDS);
        ASSERT_EQ(rvmachine_time(w.m), 7u);
        rvmachine_destroy(w.m);
        PASS();
    } _test_next:;
    return failures;
}

#define TICKER_TEXT "tick 1\ntick 2\nabtick 3\ntick 4\nticker: done\n"

static int t_wait_equal(void)
{
    int failures = 0;
    TEST("rvmachine: a host that advances exactly to each deadline gets the run the machine makes alone") {
        static struct rvmachine_script script;
        static struct rmt_run alone, hosted;
        unsigned waits;
        /* default mode, input typed by a script on a marker */
        rvmachine_script_init(&script);
        ASSERT(rvmachine_script_add(&script, "tick 2\n", 7, "ab", 2));
        ASSERT(wait_machine(&alone, RMT_REAL, "ticker", false) != NULL);
        alone.script = &script;
        rmt_go(&alone, RMT_REAL, RMT_WORK);
        rvmachine_destroy(alone.m);
        ASSERT_EQ(alone.st, RVMACHINE_OK);
        ASSERT_EQ(alone.res.stop, RVMACHINE_STOP_SHUTDOWN);
        ASSERT_STR_EQ(alone.out, TICKER_TEXT);
        ASSERT(alone.res.skip > 9000u); /* four sleeps of about 1000, 2000, 3000, 4000 */
        ASSERT(alone.res.skip <= 10000u);
        /* the same guest and script, time moved by the host */
        rvmachine_script_init(&script);
        ASSERT(rvmachine_script_add(&script, "tick 2\n", 7, "ab", 2));
        ASSERT(wait_machine(&hosted, RMT_REAL, "ticker", true) != NULL);
        hosted.script = &script;
        waits = wait_drive(&hosted, RMT_REAL, RMT_WORK, 16);
        rvmachine_destroy(hosted.m);
        ASSERT_EQ(waits, 4u);
        ASSERT_EQ(hosted.st, RVMACHINE_OK);
        ASSERT_STR_EQ(hosted.out, TICKER_TEXT);
        ASSERT(rmt_same(&alone, &hosted)); /* console, stop, retired, skip, fw_calls, time, pc */
        ASSERT_EQ(hosted.res.skip, alone.res.skip);
        ASSERT_EQ(hosted.res.guest_time, alone.res.guest_time);
        printf("\n    rvmachine wait mode: 4 wait stops, retired=%llu skip=%llu, equal to the "
               "default mode\n    ",
               (unsigned long long)hosted.res.retired, (unsigned long long)hosted.res.skip);
        PASS();
    } _test_next:;
    return failures;
}

static int t_wait_input(void)
{
    int failures = 0;
    TEST("rvmachine: input ends a wait early and the guest waits again for the same deadline") {
        static struct rmt_run r, fw;
        uint64_t deadline, retired;
        ASSERT(wait_machine(&r, RMT_REAL, "ticker", true) != NULL);
        rmt_go(&r, RMT_REAL, RMT_WORK);
        ASSERT_EQ(r.res.stop, RVMACHINE_STOP_WAIT);
        ASSERT_STR_EQ(r.out, "tick 1\n");
        deadline = r.res.timer_deadline;
        retired = r.res.retired;
        ASSERT_EQ(rvmachine_pending(r.m), 0u); /* quiet: the host may sleep */
        /* a key is pressed while the guest sleeps; no time is advanced */
        ASSERT_EQ(rvmachine_console_input(r.m, (const uint8_t *)"x", 1), 1u);
        ASSERT_EQ(rvmachine_pending(r.m), RVMACHINE_PENDING_CONSOLE);
        rmt_go(&r, RMT_REAL, RMT_WORK);
        ASSERT_EQ(r.st, RVMACHINE_OK);
        ASSERT_EQ(r.res.stop, RVMACHINE_STOP_WAIT); /* handled, asleep again */
        ASSERT_STR_EQ(r.out, "tick 1\nx");
        ASSERT_EQ(r.res.timer_deadline, deadline);
        ASSERT(r.res.retired > retired); /* the second stop was paid for */
        ASSERT_EQ(r.res.skip, 0u);
        ASSERT_EQ(rvmachine_pending(r.m), 0u); /* the one reader took it */
        /* an entropy signal that changes nothing (no device here) is not a
         * reason to run again */
        rvmachine_entropy_ready(r.m);
        ASSERT_EQ(rvmachine_run(r.m, RMT_WORK, &r.res), RVMACHINE_ERR_WAITING);
        /* then the deadline: the first sleep ends and the second begins */
        ASSERT_EQ(rvmachine_advance_time(r.m, deadline), RVMACHINE_OK);
        rmt_go(&r, RMT_REAL, RMT_WORK);
        ASSERT_EQ(r.res.stop, RVMACHINE_STOP_WAIT);
        ASSERT_STR_EQ(r.out, "tick 1\nxtick 2\n");
        ASSERT(r.res.timer_deadline > deadline);
        rvmachine_destroy(r.m);
        /* a guest that reads only through firmware calls never turns the serial
         * receive interrupt on: input queued for it cannot wake the hart, so it
         * is held and does not keep a host awake */
        ASSERT(wait_machine(&fw, RMT_REAL, "tiny", true) != NULL);
        ASSERT_EQ(rvmachine_console_input(fw.m, (const uint8_t *)"abc", 3), 3u);
        ASSERT_EQ(rvmachine_pending(fw.m), RVMACHINE_PENDING_CONSOLE_HELD);
        rvmachine_destroy(fw.m);
        PASS();
    } _test_next:;
    return failures;
}

static int t_wait_entropy(void)
{
    int failures = 0;
    TEST("rvmachine: a dry entropy source lets the guest sleep, and its return is a reason to run again") {
        static uint8_t image[RMT_IMAGE_MAX];
        static struct rmt_run r;
        struct ent_src src = {.left = 0};
        size_t len = 0;
        uint64_t deadline, retired;
        ASSERT(rmt_fixture("ticker", image, &len));
        ASSERT(rmt_machine_cfg(&r, RMT_REAL, image, len,
                               (struct rvmachine_config){.ram_bytes = RMT_RAM,
                                                         .entropy = ent_fill,
                                                         .entropy_ctx = &src,
                                                         .wait_stops = true}) != NULL);
        /* a driver's request finds the source empty */
        vq_up(&r.m->rng.dev);
        vq_desc(r.m, 0, VQ_DATA, 64, 2, 0);
        memset(vq_at(r.m, VQ_AVAIL), 0, 4u + 2u * VQ_NUM);
        zcl_write_u16_le(vq_at(r.m, VQ_AVAIL) + 2, 1);
        rvvirtio_mmio_write(&r.m->rng.dev, RVVIRTIO_REG_QUEUE_NOTIFY, 0);
        ASSERT_EQ(src.calls, 1u);
        ASSERT(rvvirtio_rng_pending(&r.m->rng));
        ASSERT_EQ(rvmachine_pending(r.m), 0u); /* a dry source is nothing to run for */
        rmt_go(&r, RMT_REAL, RMT_WORK);
        ASSERT_EQ(r.res.stop, RVMACHINE_STOP_WAIT);
        ASSERT_EQ(src.calls, 1u); /* not asked again while dry */
        deadline = r.res.timer_deadline;
        retired = r.res.retired;
        /* the source has bytes again, but nobody said so */
        src.left = UINT64_MAX;
        ASSERT_EQ(rvmachine_run(r.m, RMT_WORK, &r.res), RVMACHINE_ERR_WAITING);
        ASSERT_EQ(src.calls, 1u);
        /* told so, the machine serves the request in the next run, charges
         * it, and the guest (which does not listen to that device) sleeps on */
        rvmachine_entropy_ready(r.m);
        ASSERT_EQ(rvmachine_pending(r.m), RVMACHINE_PENDING_ENTROPY);
        rmt_go(&r, RMT_REAL, RMT_WORK);
        ASSERT_EQ(r.st, RVMACHINE_OK);
        ASSERT_EQ(r.res.stop, RVMACHINE_STOP_WAIT);
        ASSERT_EQ(r.res.timer_deadline, deadline);
        ASSERT_EQ(src.pos, 64u);
        ASSERT_EQ(vq_used(r.m), 1u);
        ASSERT_EQ(r.res.device_work, 1u); /* the second stop was paid for */
        ASSERT_EQ(r.res.retired, retired);
        ASSERT_EQ(rvmachine_pending(r.m), 0u);
        /* a signal with nothing dry behind it changes nothing */
        rvmachine_entropy_ready(r.m);
        ASSERT_EQ(rvmachine_run(r.m, RMT_WORK, &r.res), RVMACHINE_ERR_WAITING);
        rvmachine_destroy(r.m);
        PASS();
    } _test_next:;
    return failures;
}

/* ---- 17. serial input against each gate between the port and the hart ---- */
#define SIE_STIE UINT64_C(0x20)
#define SIE_SEIE UINT64_C(0x200)
#define IRQ_STIP_BIT 5u
#define IRQ_SEIP_BIT 9u
#define PLIC_UART UINT64_C(0x400)
#define MASKED_LEAD UINT64_C(1000)
#define MASKED_RETRIES 16u
#define MASKED_FLOOD 8u
#define MASKED_TEXT "masked: asleep\nmasked: awake\nkjjjjjjjj"

/* What the embedder sets before the masked fixture runs. */
struct masked_cfg {
    uint64_t lead; /* timer this far ahead; 0: not armed */
    uint64_t sie;  /* the hart's interrupt enables */
    uint64_t ier;  /* the serial port's interrupt enables */
    uint64_t plic; /* the interrupt controller's enables for the context */
};

/* One gate shut in each, the other two open; the timer interrupt is on. */
static const struct masked_cfg MASK_HART = {MASKED_LEAD, SIE_STIE, 1, PLIC_UART};
static const struct masked_cfg MASK_PORT = {MASKED_LEAD, SIE_STIE | SIE_SEIE, 0, PLIC_UART};
static const struct masked_cfg MASK_PLIC = {MASKED_LEAD, SIE_STIE | SIE_SEIE, 1, 0};
static const struct masked_cfg MASK_NONE = {MASKED_LEAD, SIE_STIE | SIE_SEIE, 1, PLIC_UART};

static struct rvmachine *masked_machine(struct rmt_run *r, bool wait_stops,
                                        const struct masked_cfg *c)
{
    if (wait_machine(r, RMT_REAL, "masked", wait_stops) == NULL) return NULL;
    r->m->hart.x[18] = c->lead; /* s2 */
    r->m->hart.x[19] = c->sie;  /* s3 */
    r->m->hart.x[20] = c->ier;  /* s4 */
    r->m->hart.x[21] = c->plic; /* s5 */
    return r->m;
}

/* Runs again `times` times with nothing changed; returns how many of the
 * runs were refused as waiting. */
static unsigned masked_retries(struct rmt_run *r, unsigned times)
{
    unsigned refused = 0;
    for (unsigned i = 0; i < times; i++)
        if (rvmachine_run(r->m, RMT_WORK, &r->res) == RVMACHINE_ERR_WAITING) refused++;
    return refused;
}

/* A host loop that runs for as long as the machine says it has something to
 * act on; returns its turns, at most `cap`. */
static unsigned masked_host_turns(struct rmt_run *r, unsigned cap)
{
    const unsigned runnable =
        RVMACHINE_PENDING_CONSOLE | RVMACHINE_PENDING_ENTROPY | RVMACHINE_PENDING_BLOCK;
    unsigned turns = 0;
    while (turns < cap && (rvmachine_pending(r->m) & runnable) != 0) {
        (void)rvmachine_run(r->m, RMT_WORK, &r->res);
        turns++;
    }
    return turns;
}

struct masked_probe {
    bool ok;                   /* machines built, advance accepted */
    enum rvmachine_stop first; /* how the first run ended */
    unsigned pending;          /* rvmachine_pending at that stop */
    bool port_irq, seip, seie; /* the three gates as the machine holds them there */
    unsigned in_port;          /* bytes in the port's receive buffer */
    size_t queued;             /* bytes still queued behind the port */
    unsigned refused;          /* of MASKED_RETRIES unchanged retries */
    unsigned flood_refused;    /* of MASKED_FLOOD runs, each after one more byte */
    unsigned flood_runnable;   /* times the machine then reported work to run for */
    uint64_t wasted;           /* work done between the wait stop and the deadline */
    unsigned turns;            /* turns of a host loop that follows rvmachine_pending */
    bool same;                 /* ended as the default-mode run on the same input */
};

/* One byte per round is thrown at a waiting hart that cannot be woken by it. */
static void masked_flood(struct rmt_run *r, struct masked_probe *p)
{
    for (unsigned i = 0; i < MASKED_FLOOD; i++) {
        (void)rvmachine_console_input(r->m, (const uint8_t *)"j", 1);
        if ((rvmachine_pending(r->m) & RVMACHINE_PENDING_RUNNABLE) != 0) p->flood_runnable++;
        if (rvmachine_run(r->m, RMT_WORK, &r->res) == RVMACHINE_ERR_WAITING) p->flood_refused++;
    }
}

/* The guest waits for its timer with input queued behind one shut gate. */
static struct masked_probe masked_case(const struct masked_cfg *c)
{
    static struct rmt_run alone, r;
    struct masked_probe p = {0};
    uint64_t deadline, work;
    /* the reference: default mode, every byte typed before the run */
    if (masked_machine(&alone, false, c) == NULL) return p;
    (void)rvmachine_console_input(alone.m, (const uint8_t *)"kjjjjjjjj", 1u + MASKED_FLOOD);
    rmt_go(&alone, RMT_REAL, RMT_WORK);
    rvmachine_destroy(alone.m);
    if (masked_machine(&r, true, c) == NULL) return p;
    (void)rvmachine_console_input(r.m, (const uint8_t *)"k", 1);
    rmt_go(&r, RMT_REAL, RMT_WORK);
    p.first = r.res.stop;
    p.pending = rvmachine_pending(r.m);
    p.port_irq = rvplat_uart_irq(&r.m->uart);
    p.seip = ((r.m->hart.csr.mip >> IRQ_SEIP_BIT) & 1u) != 0;
    p.seie = ((r.m->hart.csr.mie >> IRQ_SEIP_BIT) & 1u) != 0;
    p.in_port = r.m->uart.rx_count;
    p.queued = r.m->serial_in.count;
    deadline = r.res.timer_deadline;
    work = rvmachine_retired(r.m) + r.m->fw_calls;
    p.refused = masked_retries(&r, MASKED_RETRIES);
    masked_flood(&r, &p);
    p.turns = masked_host_turns(&r, MASKED_RETRIES);
    p.wasted = rvmachine_retired(r.m) + r.m->fw_calls - work;
    p.ok = rvmachine_advance_time(r.m, deadline) == RVMACHINE_OK;
    rmt_go(&r, RMT_REAL, RMT_WORK);
    rvmachine_destroy(r.m);
    p.same = alone.res.stop == RVMACHINE_STOP_SHUTDOWN && alone.res.skip > 900u &&
             strcmp(alone.out, MASKED_TEXT) == 0 && rmt_same(&alone, &r);
    return p;
}

/* The hart stayed asleep, an unchanged retry and a retry after each further
 * byte were refused by name, no work was done, a host loop that follows the
 * pending flags never turned, and at the deadline the guest got every byte. */
#define ASSERT_MASKED_ASLEEP(p) \
    do { \
        ASSERT((p).ok); \
        ASSERT_EQ((p).first, RVMACHINE_STOP_WAIT); \
        ASSERT_EQ((p).pending & RVMACHINE_PENDING_CONSOLE, 0u); \
        ASSERT_EQ((p).refused, MASKED_RETRIES); \
        ASSERT_EQ((p).flood_refused, MASKED_FLOOD); \
        ASSERT_EQ((p).flood_runnable, 0u); \
        ASSERT_EQ((p).wasted, 0u); \
        ASSERT_EQ((p).turns, 0u); \
        ASSERT((p).same); \
    } while (0)

static int t_wait_masked(void)
{
    int failures = 0;
    TEST("rvmachine: input behind a shut gate neither wakes the hart nor keeps a host loop turning") {
        struct masked_probe hart, port, plic;
        /* the port and the controller raise the line and the hart sees it
         * pending: only its own enable (mie) is off */
        hart = masked_case(&MASK_HART);
        ASSERT(hart.port_irq);
        ASSERT(hart.seip);
        ASSERT(!hart.seie);
        ASSERT_EQ(hart.in_port, 1u);
        ASSERT_MASKED_ASLEEP(hart);
        /* the port's receive interrupt is off: the byte waits behind the port */
        port = masked_case(&MASK_PORT);
        ASSERT(!port.port_irq);
        ASSERT(!port.seip);
        ASSERT(port.seie);
        ASSERT_EQ(port.in_port, 0u);
        ASSERT_EQ(port.queued, 1u);
        ASSERT_MASKED_ASLEEP(port);
        /* the interrupt controller has the port's source disabled */
        plic = masked_case(&MASK_PLIC);
        ASSERT(plic.port_irq);
        ASSERT(!plic.seip);
        ASSERT(plic.seie);
        ASSERT_EQ(plic.in_port, 1u);
        ASSERT_MASKED_ASLEEP(plic);
        printf("\n    rvmachine masked input: hart, port and controller gate each %u unchanged "
               "and %u flooded retries refused, 0 work\n    ",
               MASKED_RETRIES, MASKED_FLOOD);
        PASS();
    } _test_next:;
    return failures;
}

static int t_wait_held(void)
{
    int failures = 0;
    TEST("rvmachine: input that wakes the hart and input held behind a gate are told apart") {
        static const struct masked_cfg idle_masked = {0, SIE_STIE, 1, PLIC_UART};
        static struct rmt_run r;
        struct masked_probe p;
        uint64_t retired;
        /* behind each gate the input is reported as held */
        p = masked_case(&MASK_HART);
        ASSERT_EQ(p.pending, RVMACHINE_PENDING_CONSOLE_HELD);
        p = masked_case(&MASK_PORT);
        ASSERT_EQ(p.pending, RVMACHINE_PENDING_CONSOLE_HELD);
        p = masked_case(&MASK_PLIC);
        ASSERT_EQ(p.pending, RVMACHINE_PENDING_CONSOLE_HELD);
        /* every gate open, interrupts globally off: input that arrives while
         * the guest waits for its timer ends the wfi without a trap, the run
         * does work and no guest time passes */
        ASSERT(masked_machine(&r, true, &MASK_NONE) != NULL);
        rmt_go(&r, RMT_REAL, RMT_WORK);
        ASSERT_EQ(r.res.stop, RVMACHINE_STOP_WAIT);
        ASSERT_EQ(rvmachine_pending(r.m), 0u);
        ASSERT_EQ(r.m->hart.csr.mstatus & 2u, 0u); /* sstatus.SIE */
        retired = r.res.retired;
        ASSERT_EQ(rvmachine_console_input(r.m, (const uint8_t *)"kjjjjjjjj", 9), 9u);
        ASSERT_EQ(rvmachine_pending(r.m), RVMACHINE_PENDING_CONSOLE);
        rmt_go(&r, RMT_REAL, RMT_WORK);
        rvmachine_destroy(r.m);
        ASSERT_EQ(r.st, RVMACHINE_OK);
        ASSERT_EQ(r.res.stop, RVMACHINE_STOP_SHUTDOWN);
        ASSERT_STR_EQ(r.out, MASKED_TEXT);
        ASSERT(r.res.retired > retired);
        ASSERT_EQ(r.res.skip, 0u);
        /* masked in the hart and no timer armed: nothing can wake it. That is
         * the idle stop; a rerun is refused and nothing is reported to run for */
        ASSERT(masked_machine(&r, true, &idle_masked) != NULL);
        ASSERT_EQ(rvmachine_console_input(r.m, (const uint8_t *)"k", 1), 1u);
        rmt_go(&r, RMT_REAL, RMT_WORK);
        ASSERT_EQ(r.res.stop, RVMACHINE_STOP_IDLE);
        ASSERT_EQ(r.res.timer_deadline, RVMACHINE_NO_DEADLINE);
        ASSERT_EQ(rvmachine_pending(r.m), RVMACHINE_PENDING_CONSOLE_HELD);
        retired = rvmachine_retired(r.m);
        ASSERT_EQ(masked_retries(&r, MASKED_RETRIES), MASKED_RETRIES);
        ASSERT_EQ(masked_host_turns(&r, MASKED_RETRIES), 0u);
        ASSERT_EQ(rvmachine_retired(r.m), retired);
        rvmachine_destroy(r.m);
        /* without wait stops the idle stop is simply given again, for no work */
        ASSERT(masked_machine(&r, false, &idle_masked) != NULL);
        rmt_go(&r, RMT_REAL, RMT_WORK);
        ASSERT_EQ(r.res.stop, RVMACHINE_STOP_IDLE);
        retired = r.res.retired;
        rmt_go(&r, RMT_REAL, RMT_WORK);
        ASSERT_EQ(r.st, RVMACHINE_OK);
        ASSERT_EQ(r.res.stop, RVMACHINE_STOP_IDLE);
        ASSERT_EQ(r.res.retired, retired);
        rvmachine_destroy(r.m);
        PASS();
    } _test_next:;
    return failures;
}

static int t_wait_past_deadline(void)
{
    int failures = 0;
    TEST("rvmachine: a timer that has passed with its interrupt masked is not a deadline to wait for") {
        /* the timer interrupt is masked in the hart; the deadline is one time
         * unit before the arming call, or a thousand after it */
        static const struct masked_cfg past = {UINT64_MAX, 0, 1, PLIC_UART};
        static const struct masked_cfg ahead = {MASKED_LEAD, 0, 1, PLIC_UART};
        static struct rmt_run r;
        uint64_t work, deadline;
        ASSERT(masked_machine(&r, true, &past) != NULL);
        rmt_go(&r, RMT_REAL, RMT_WORK);
        ASSERT_EQ(r.st, RVMACHINE_OK);
        ASSERT_EQ(r.res.stop, RVMACHINE_STOP_IDLE); /* not a wait with a past deadline */
        ASSERT_STR_EQ(r.out, "masked: asleep\n");
        ASSERT(r.m->timer.deadline < r.res.guest_time); /* armed, and behind */
        ASSERT_EQ((r.m->hart.csr.mip >> IRQ_STIP_BIT) & 1u, 1u); /* raised */
        ASSERT_EQ((r.m->hart.csr.mie >> IRQ_STIP_BIT) & 1u, 0u); /* masked */
        ASSERT_EQ(r.res.timer_deadline, RVMACHINE_NO_DEADLINE);
        ASSERT_EQ(rvmachine_timer_deadline(r.m), RVMACHINE_NO_DEADLINE);
        ASSERT_EQ(rvmachine_pending(r.m), 0u);
        /* an unchanged retry is refused by name, for no work */
        work = rvmachine_retired(r.m) + r.m->fw_calls;
        ASSERT_EQ(masked_retries(&r, MASKED_RETRIES), MASKED_RETRIES);
        /* no deadline bars time, and time passing wakes nothing */
        ASSERT_EQ(rvmachine_advance_time(r.m, r.res.guest_time + 5000u), RVMACHINE_OK);
        ASSERT_EQ(rvmachine_time(r.m), r.res.guest_time + 5000u);
        ASSERT_EQ(rvmachine_timer_deadline(r.m), RVMACHINE_NO_DEADLINE);
        ASSERT_EQ(masked_retries(&r, MASKED_RETRIES), MASKED_RETRIES);
        ASSERT_EQ(rvmachine_retired(r.m) + r.m->fw_calls, work);
        rvmachine_destroy(r.m);
        /* without wait stops: the idle stop, with no deadline, given again */
        ASSERT(masked_machine(&r, false, &past) != NULL);
        rmt_go(&r, RMT_REAL, RMT_WORK);
        ASSERT_EQ(r.res.stop, RVMACHINE_STOP_IDLE);
        ASSERT_EQ(r.res.timer_deadline, RVMACHINE_NO_DEADLINE);
        ASSERT_EQ(r.res.skip, 0u);
        work = r.res.retired + r.res.fw_calls;
        rmt_go(&r, RMT_REAL, RMT_WORK);
        ASSERT_EQ(r.res.stop, RVMACHINE_STOP_IDLE);
        ASSERT_EQ(r.res.retired + r.res.fw_calls, work);
        rvmachine_destroy(r.m);
        /* a masked timer that still lies ahead is waited for once; when it has
         * passed, nothing woke and nothing is left to wait for */
        ASSERT(masked_machine(&r, true, &ahead) != NULL);
        rmt_go(&r, RMT_REAL, RMT_WORK);
        ASSERT_EQ(r.res.stop, RVMACHINE_STOP_WAIT);
        deadline = r.res.timer_deadline;
        ASSERT(deadline > r.res.guest_time);
        ASSERT(deadline != RVMACHINE_NO_DEADLINE);
        ASSERT_EQ(rvmachine_advance_time(r.m, deadline), RVMACHINE_OK);
        ASSERT_EQ(rvmachine_timer_deadline(r.m), RVMACHINE_NO_DEADLINE);
        ASSERT_EQ(masked_retries(&r, MASKED_RETRIES), MASKED_RETRIES);
        ASSERT_EQ(rvmachine_advance_time(r.m, deadline + 1u), RVMACHINE_OK);
        rvmachine_destroy(r.m);
        PASS();
    } _test_next:;
    return failures;
}

static int t_wait_lines(void)
{
    int failures = 0;
    TEST("rvmachine: a hart that the up-to-date interrupt lines wake is not declared waiting") {
        static struct rmt_run r;
        struct rvmachine_input *q;
        uint64_t deadline;
        ASSERT(wait_machine(&r, RMT_REAL, "ticker", true) != NULL);
        rmt_go(&r, RMT_REAL, RMT_WORK);
        ASSERT_EQ(r.res.stop, RVMACHINE_STOP_WAIT);
        deadline = r.res.timer_deadline;
        /* A byte put on the serial queue behind the machine's back: no caller
         * can do this, it stands for any path that leaves the lines stale when
         * the hart stops in wfi. The port takes the byte at that stop. */
        q = &r.m->serial_in;
        q->bytes[(q->head + q->count) % RVMACHINE_INPUT_MAX] = 'z';
        q->count++;
        r.m->wait_latched = false; /* and the run is let through by hand */
        rmt_go(&r, RMT_REAL, RMT_WORK);
        /* the guest ran its handler before the machine called it waiting again */
        ASSERT_EQ(r.res.stop, RVMACHINE_STOP_WAIT);
        ASSERT_STR_EQ(r.out, "tick 1\nz");
        ASSERT_EQ(r.res.timer_deadline, deadline);
        ASSERT_EQ(rvmachine_pending(r.m), 0u);
        rvmachine_destroy(r.m);
        PASS();
    } _test_next:;
    return failures;
}

static int t_wait_stopped_queue(void)
{
    int failures = 0;
    TEST("rvmachine: requests behind a queue its driver stopped are not work a run could do") {
        static uint8_t image[RMT_IMAGE_MAX];
        static struct rmt_run r;
        struct ent_src src = {.left = UINT64_MAX};
        size_t len = 0;
        uint64_t given;
        ASSERT(RVVIRTIO_RNG_NOTIFY_BYTES_MAX / RVVIRTIO_RNG_REQ_BYTES_MAX == 16u);
        ASSERT(rmt_fixture("ticker", image, &len));
        ASSERT(rmt_machine_cfg(&r, RMT_REAL, image, len,
                               (struct rvmachine_config){.ram_bytes = RMT_RAM,
                                                         .entropy = ent_fill,
                                                         .entropy_ctx = &src,
                                                         .wait_stops = true}) != NULL);
        /* two notifies' worth of requests: one capped notify leaves half */
        vq_up(&r.m->rng.dev);
        vq_desc(r.m, 0, VQ_DATA, RVVIRTIO_RNG_REQ_BYTES_MAX, 2, 0);
        memset(vq_at(r.m, VQ_AVAIL), 0, 4u + 2u * VQ_NUM);
        zcl_write_u16_le(vq_at(r.m, VQ_AVAIL) + 2, 32);
        rvvirtio_mmio_write(&r.m->rng.dev, RVVIRTIO_REG_QUEUE_NOTIFY, 0);
        ASSERT(rvvirtio_rng_pending(&r.m->rng));
        ASSERT_EQ(rvmachine_pending(r.m), RVMACHINE_PENDING_ENTROPY);
        /* the driver stops its queue with the rest still in the ring */
        rvvirtio_mmio_write(&r.m->rng.dev, RVVIRTIO_REG_QUEUE_READY, 0);
        ASSERT(rvvirtio_rng_pending(&r.m->rng));
        given = src.pos;
        ASSERT_EQ(rvmachine_pending(r.m) & RVMACHINE_PENDING_ENTROPY, 0u);
        /* the guest sleeps on its timer; nothing is served, nothing is owed */
        rmt_go(&r, RMT_REAL, RMT_WORK);
        ASSERT_EQ(r.res.stop, RVMACHINE_STOP_WAIT);
        ASSERT_EQ(src.pos, given);
        ASSERT_EQ(rvmachine_pending(r.m), 0u);
        ASSERT_EQ(masked_retries(&r, MASKED_RETRIES), MASKED_RETRIES);
        ASSERT_EQ(masked_host_turns(&r, MASKED_RETRIES), 0u);
        rvmachine_destroy(r.m);
        PASS();
    } _test_next:;
    return failures;
}

#define REARM_WORK 1000u
#define REARM_RERUNS 16u

struct rearm_probe {
    bool ok;
    enum rvmachine_stop stop;
    unsigned waits;         /* wait stops over the whole budget */
    uint64_t retired, fw_calls;
    unsigned free_waits;    /* wait stops got by rerunning without doing anything */
    enum rvmachine_status rerun;
};

/* The re-arm guest with its timer `lead` time units ahead, on a budget of
 * REARM_WORK. First the host reruns after a wait stop without acting, then it
 * drives the guest to the end of the budget. */
static struct rearm_probe rearm_case(enum rmt_engine engine, uint64_t lead)
{
    static struct rmt_run r;
    struct rearm_probe p = {0};
    uint64_t left = REARM_WORK;
    if (wait_machine(&r, engine, "rearm", true) == NULL) return p;
    r.m->hart.x[9] = lead; /* s1 */
    p.ok = true;
    rmt_go(&r, engine, left);
    if (r.st == RVMACHINE_OK && r.res.stop == RVMACHINE_STOP_WAIT) {
        uint64_t work = r.res.retired + r.res.fw_calls;
        p.waits = 1;
        for (unsigned i = 0; i < REARM_RERUNS; i++) {
            rmt_go(&r, engine, left);
            p.rerun = r.st;
            if (r.st != RVMACHINE_OK || r.res.stop != RVMACHINE_STOP_WAIT) break;
            if (r.res.retired + r.res.fw_calls == work) p.free_waits++;
        }
        p.ok = rvmachine_advance_time(r.m, rvmachine_timer_deadline(r.m)) == RVMACHINE_OK;
        left -= work;
        while (p.ok && left != 0) {
            unsigned more = wait_drive(&r, engine, left, 0);
            if (more == WAIT_REFUSED || r.st != RVMACHINE_OK) p.ok = false;
            if (r.res.stop != RVMACHINE_STOP_WAIT) break;
            p.waits++;
            left = REARM_WORK - (r.res.retired + r.res.fw_calls);
            p.ok = p.ok &&
                   rvmachine_advance_time(r.m, r.res.timer_deadline) == RVMACHINE_OK;
        }
    }
    p.stop = r.res.stop;
    p.retired = r.res.retired;
    p.fw_calls = r.res.fw_calls;
    rvmachine_destroy(r.m);
    return p;
}

static int t_wait_hostile(void)
{
    int failures = 0;
    TEST("rvmachine: a guest that keeps re-arming its timer cannot spin a host loop for free (twin)") {
        struct rearm_probe due, ahead, twin;
        /* every deadline already due: no wait stop at all, the budget ends it */
        due = rearm_case(RMT_REAL, 0);
        ASSERT(due.ok);
        ASSERT_EQ(due.stop, RVMACHINE_STOP_BUDGET);
        ASSERT_EQ(due.waits, 0u);
        ASSERT_EQ(due.retired + due.fw_calls, (uint64_t)REARM_WORK);
        ASSERT(due.fw_calls >= 100u); /* it did re-arm, over and over */
        /* every deadline a little ahead: each wait stop is paid for by the
         * firmware call that armed it, and a rerun for nothing is refused */
        ahead = rearm_case(RMT_REAL, 100);
        ASSERT(ahead.ok);
        ASSERT_EQ(ahead.rerun, RVMACHINE_ERR_WAITING);
        ASSERT_EQ(ahead.free_waits, 0u);
        ASSERT_EQ(ahead.stop, RVMACHINE_STOP_BUDGET);
        ASSERT_EQ(ahead.retired + ahead.fw_calls, (uint64_t)REARM_WORK);
        ASSERT(ahead.waits >= 100u);
        ASSERT(ahead.waits <= ahead.fw_calls); /* one arming call per wait stop at least */
        /* twin without the latch: the same stop again and again, for no work */
        twin_reset();
        twin_wait_latch = false;
        twin = rearm_case(RMT_TWIN, 100);
        twin_reset();
        ASSERT(twin.ok);
        ASSERT_EQ(twin.rerun, RVMACHINE_OK);
        ASSERT_EQ(twin.free_waits, REARM_RERUNS);
        printf("\n    rvmachine twin no wait latch: real rerun refused, %u wait stops for %u "
               "work; twin %u free wait stops -> caught\n    ",
               ahead.waits, (unsigned)REARM_WORK, twin.free_waits);
        PASS();
    } _test_next:;
    twin_reset();
    return failures;
}

/* ---- 18. the loader entry and its boot seed ---- */
#define SEED_N RVMACHINE_BOOT_SEED_BYTES
#define SEED_VA UINT64_C(0xffffffc000000000) /* where the wrapped image is linked */
#define SEED_ENTRY 0x30u                     /* the preload fixture's loader entry */
#define SEED_PAGE 4096u
#define SEED_WATCH 0x8000u /* RAM from the kernel base that the tests fill and check */
#define SEED_TEXT_LEN 591u /* the preload fixture */

/* A boot seed source that does what the test tells it. */
struct seed_src {
    bool fails;  /* it reports failure */
    size_t give; /* bytes it claims */
    size_t fill; /* bytes it really writes */
    unsigned calls;
    size_t asked;
};

static uint8_t seed_byte(size_t i)
{
    return (uint8_t)(i * 7u + 3u);
}

static bool seed_source(void *ctx, uint8_t *buf, size_t n, size_t *got)
{
    struct seed_src *s = ctx;
    s->calls++;
    s->asked = n;
    for (size_t i = 0; i < s->fill && i < n; i++) buf[i] = seed_byte(i);
    *got = s->give;
    return !s->fails;
}

static bool seed_all(const uint8_t *bytes, size_t n, uint8_t value)
{
    for (size_t i = 0; i < n; i++)
        if (bytes[i] != value) return false;
    return true;
}

/* The text as one readable and executable segment linked at vaddr, loaded at
 * the kernel base and entered SEED_ENTRY into it. Returns the file length. */
static size_t seed_elf(uint8_t *img, const uint8_t *text, size_t text_len, uint64_t vaddr)
{
    struct elf_seg seg = {0x1000, vaddr, RVMACHINE_KERNEL_BASE, text_len, text_len};
    elf_build(img, &seg, 1);
    zcl_write_u32_le(img + ELF_HDR + 4, 5); /* p_flags: read, execute */
    zcl_write_u64_le(img + 24, vaddr + SEED_ENTRY); /* e_entry */
    memcpy(img + 0x1000, text, text_len);
    return 0x1000 + text_len;
}

/* A 64 MiB machine whose RAM from the kernel base is 0xee, and the image
 * loaded or refused. The machine is the caller's either way. */
static enum rvmachine_status seed_load(struct rmt_run *r, struct seed_src *src,
                                       const uint8_t *img, size_t len)
{
    struct rvmachine_config c = {.ram_bytes = RMT_RAM,
                                 .console = rmt_console, .console_ctx = r,
                                 .boot_seed = src != NULL ? seed_source : NULL,
                                 .boot_seed_ctx = src};
    memset(r, 0, sizeof *r);
    r->st = rvmachine_create(&r->m, &c);
    if (r->st != RVMACHINE_OK) return r->st;
    memset(r->m->mem.bytes + 2u * MIB, 0xee, SEED_WATCH);
    r->st = rvmachine_load_kernel(r->m, img, len);
    return r->st;
}

/* The list the machine writes for the preload fixture wrapped at SEED_VA in
 * a 64 MiB machine: the image ends at 0x24f, the tree copy, the seed and the
 * list take the next three pages. Written out by hand from the FreeBSD
 * loader's format. */
static const uint8_t seed_list[224] = {
    /* name "kernel" */
    1, 0, 0, 0, 7, 0, 0, 0, 'k', 'e', 'r', 'n', 'e', 'l', 0, 0,
    /* type "elf kernel" */
    2, 0, 0, 0, 11, 0, 0, 0, 'e', 'l', 'f', ' ', 'k', 'e', 'r', 'n', 'e', 'l', 0, 0, 0, 0, 0, 0,
    /* address 0xffffffc000000000 */
    3, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0xc0, 0xff, 0xff, 0xff,
    /* size 0x24f */
    4, 0, 0, 0, 8, 0, 0, 0, 0x4f, 0x02, 0, 0, 0, 0, 0, 0,
    /* 0x9001 device tree at 0xffffffc000001000 */
    0x01, 0x90, 0, 0, 8, 0, 0, 0, 0, 0x10, 0, 0, 0xc0, 0xff, 0xff, 0xff,
    /* 0x8008 end of everything at 0xffffffc000004000 */
    0x08, 0x80, 0, 0, 8, 0, 0, 0, 0, 0x40, 0, 0, 0xc0, 0xff, 0xff, 0xff,
    /* 0x8007 boot flags: verbose (0x800) */
    0x07, 0x80, 0, 0, 4, 0, 0, 0, 0, 0x08, 0, 0, 0, 0, 0, 0,
    /* 0x9004 boot hart 0 */
    0x04, 0x90, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    /* name "entropy" */
    1, 0, 0, 0, 8, 0, 0, 0, 'e', 'n', 't', 'r', 'o', 'p', 'y', 0,
    /* type "boot_entropy_platform" */
    2, 0, 0, 0, 22, 0, 0, 0, 'b', 'o', 'o', 't', '_', 'e', 'n', 't', 'r', 'o', 'p', 'y',
    '_', 'p', 'l', 'a', 't', 'f', 'o', 'r', 'm', 0, 0, 0,
    /* address 0xffffffc000002000 */
    3, 0, 0, 0, 8, 0, 0, 0, 0, 0x20, 0, 0, 0xc0, 0xff, 0xff, 0xff,
    /* size 2048 */
    4, 0, 0, 0, 8, 0, 0, 0, 0, 0x08, 0, 0, 0, 0, 0, 0,
    /* end of list */
    0, 0, 0, 0, 0, 0, 0, 0};

/* True when the page at `page` starts with n bytes of `want` and is zero after. */
static bool seed_page_is(const uint8_t *page, const uint8_t *want, size_t n)
{
    return memcmp(page, want, n) == 0 && seed_all(page + n, SEED_PAGE - n, 0);
}

static int t_seed_layout(void)
{
    int failures = 0;
    TEST("rvmachine: a boot seed source puts the seed, the tree and the loader's list above the image") {
        static uint8_t text[RMT_IMAGE_MAX], img[RMT_IMAGE_MAX + 0x1000], seed[SEED_N];
        static struct rmt_run r, plain;
        struct seed_src src = {.give = SEED_N, .fill = SEED_N};
        const uint8_t *ram, *tree;
        size_t text_len = 0, tree_len = 0, len;
        ASSERT(rmt_fixture("preload", text, &text_len));
        ASSERT_EQ(text_len, SEED_TEXT_LEN);
        len = seed_elf(img, text, text_len, SEED_VA);
        for (size_t i = 0; i < SEED_N; i++) seed[i] = seed_byte(i);
        ASSERT_EQ(seed_load(&r, &src, img, len), RVMACHINE_OK);
        ram = r.m->mem.bytes + 2u * MIB;
        tree = rvmachine_dtb(r.m, &tree_len);
        ASSERT(tree_len != 0 && tree_len <= SEED_PAGE);
        /* asked once, for exactly the seed, and no host copy is left */
        ASSERT_EQ(src.calls, 1u);
        ASSERT_EQ(src.asked, SEED_N);
        ASSERT(seed_all(r.m->seed_scratch, sizeof r.m->seed_scratch, 0));
        /* the entry: e_entry's physical address, the list's virtual address
         * in a0, nothing in a1 */
        ASSERT_EQ(r.m->hart.pc, RVMACHINE_KERNEL_BASE + SEED_ENTRY);
        ASSERT_EQ(r.m->hart.x[10], SEED_VA + 0x3000u);
        ASSERT_EQ(r.m->hart.x[11], 0u);
        /* the image, then zeros up to the page boundary */
        ASSERT_EQ(r.m->image_end, RVMACHINE_KERNEL_BASE + text_len);
        ASSERT(memcmp(ram, text, text_len) == 0);
        ASSERT(seed_all(ram + text_len, 0x1000 - text_len, 0));
        /* tree copy, seed and list: one page each, zero padded */
        ASSERT(seed_page_is(ram + 0x1000, tree, tree_len));
        ASSERT_EQ(r.m->seed_addr, RVMACHINE_KERNEL_BASE + 0x2000u);
        ASSERT(seed_page_is(ram + 0x2000, seed, SEED_N));
        ASSERT(seed_page_is(ram + 0x3000, seed_list, sizeof seed_list));
        /* nothing above the end the list names */
        ASSERT(seed_all(ram + 0x4000, SEED_WATCH - 0x4000, 0xee));
        /* the tree at its usual place is still there */
        ASSERT_EQ(r.m->dtb_addr, RVMACHINE_RAM_BASE + RMT_RAM - 2u * MIB);
        ASSERT_EQ(zcl_read_u32_le(tree), 0xedfe0dd0u);
        /* cleared only once the guest has zeroed every byte of the seed */
        ASSERT(!rvmachine_boot_seed_cleared(r.m));
        memset(r.m->mem.bytes + 2u * MIB + 0x2000, 0, SEED_N - 1u);
        ASSERT(!rvmachine_boot_seed_cleared(r.m));
        r.m->mem.bytes[2u * MIB + 0x2000 + SEED_N - 1u] = 0;
        ASSERT(rvmachine_boot_seed_cleared(r.m));
        ASSERT(!rvmachine_boot_seed_cleared(NULL));
        rvmachine_destroy(r.m);
        /* the same image linked elsewhere: every listed address follows */
        src = (struct seed_src){.give = SEED_N, .fill = SEED_N};
        len = seed_elf(img, text, text_len, 0x40000000u);
        ASSERT_EQ(seed_load(&r, &src, img, len), RVMACHINE_OK);
        ASSERT_EQ(r.m->hart.pc, RVMACHINE_KERNEL_BASE + SEED_ENTRY);
        ASSERT_EQ(r.m->hart.x[10], 0x40003000u);
        ram = r.m->mem.bytes + 2u * MIB + 0x3000;
        ASSERT_EQ(zcl_read_u64_le(ram + 48), 0x40000000u);  /* kernel address */
        ASSERT_EQ(zcl_read_u64_le(ram + 80), 0x40001000u);  /* device tree */
        ASSERT_EQ(zcl_read_u64_le(ram + 96), 0x40004000u);  /* end of everything */
        ASSERT_EQ(zcl_read_u64_le(ram + 192), 0x40002000u); /* seed */
        rvmachine_destroy(r.m);
        /* no source: the firmware entry and not one byte above the image */
        len = seed_elf(img, text, text_len, SEED_VA);
        ASSERT_EQ(seed_load(&plain, NULL, img, len), RVMACHINE_OK);
        ASSERT_EQ(plain.m->hart.pc, RVMACHINE_KERNEL_BASE);
        ASSERT_EQ(plain.m->hart.x[10], 0u);
        ASSERT_EQ(plain.m->hart.x[11], plain.m->dtb_addr);
        ASSERT_EQ(plain.m->seed_addr, 0u);
        ASSERT(!rvmachine_boot_seed_cleared(plain.m));
        ASSERT(seed_all(plain.m->mem.bytes + 2u * MIB + text_len, SEED_WATCH - text_len, 0xee));
        rvmachine_destroy(plain.m);
        PASS();
    } _test_next:;
    return failures;
}

/* What the preload fixture prints at its loader entry for seed_list and the
 * seed of seed_byte: each record, the tree's first word, the seed's checksum. */
static void seed_guest_text(char *out, size_t cap)
{
    uint64_t sum = 0;
    for (size_t i = 0; i < SEED_N; i++) sum = sum * 31u + seed_byte(i);
    snprintf(out, cap,
             "0001 07 kernel\n"
             "0002 0b elf kernel\n"
             "0003 08 ffffffc000000000\n"
             "0004 08 000000000000024f\n"
             "9001 08 ffffffc000001000\n"
             "8008 08 ffffffc000004000\n"
             "8007 04 0000000000000800\n"
             "9004 08 0000000000000000\n"
             "0001 08 entropy\n"
             "0002 16 boot_entropy_platform\n"
             "0003 08 ffffffc000002000\n"
             "0004 08 0000000000000800\n"
             "tree 00000000edfe0dd0\n"
             "seed %016llx\n",
             (unsigned long long)sum);
}

static int t_seed_guest(void)
{
    int failures = 0;
    TEST("rvmachine: a guest entered at its loader entry walks the list, reads the tree and takes the seed") {
        static uint8_t text[RMT_IMAGE_MAX], img[RMT_IMAGE_MAX + 0x1000];
        static struct rmt_run a, b, fw;
        static char want[RMT_OUT_MAX];
        struct seed_src src = {.give = SEED_N, .fill = SEED_N};
        size_t text_len = 0, len;
        ASSERT(rmt_fixture("preload", text, &text_len));
        len = seed_elf(img, text, text_len, SEED_VA);
        seed_guest_text(want, sizeof want);
        ASSERT_EQ(seed_load(&a, &src, img, len), RVMACHINE_OK);
        ASSERT_EQ(rvmachine_run(a.m, RMT_WORK, &a.res), RVMACHINE_OK);
        ASSERT_EQ(a.res.stop, RVMACHINE_STOP_SHUTDOWN);
        ASSERT_STR_EQ(a.out, want);
        ASSERT(rvmachine_boot_seed_cleared(a.m)); /* the guest zeroed it */
        rvmachine_destroy(a.m);
        /* the same bytes give the same run */
        src = (struct seed_src){.give = SEED_N, .fill = SEED_N};
        ASSERT_EQ(seed_load(&b, &src, img, len), RVMACHINE_OK);
        ASSERT_EQ(rvmachine_run(b.m, RMT_WORK, &b.res), RVMACHINE_OK);
        rvmachine_destroy(b.m);
        ASSERT(rmt_same(&a, &b));
        /* without a source the same file is entered at its first instruction */
        ASSERT_EQ(seed_load(&fw, NULL, img, len), RVMACHINE_OK);
        ASSERT_EQ(rvmachine_run(fw.m, RMT_WORK, &fw.res), RVMACHINE_OK);
        ASSERT_STR_EQ(fw.out, "preload: firmware entry\n");
        ASSERT(!rvmachine_boot_seed_cleared(fw.m));
        rvmachine_destroy(fw.m);
        PASS();
    } _test_next:;
    return failures;
}

/* How a load with a boot seed source ended. */
struct seed_verdict {
    enum rvmachine_status st;
    bool untouched; /* guest RAM, the hart, the machine and the host copy as before */
    unsigned calls; /* times the source was asked */
};

static struct seed_verdict seed_try(const uint8_t *img, size_t len, struct seed_src src)
{
    static struct rmt_run r;
    struct seed_verdict v = {.st = seed_load(&r, &src, img, len)};
    const struct rvmachine *m = r.m;
    if (m == NULL) return v;
    v.untouched = seed_all(m->mem.bytes + 2u * MIB, SEED_WATCH, 0xee) &&
                  seed_all(m->seed_scratch, sizeof m->seed_scratch, 0) && !m->loaded &&
                  m->hart.pc == 0 && m->seed_addr == 0 && m->image_end == 0;
    v.calls = src.calls;
    rvmachine_destroy(r.m);
    return v;
}

#define ASSERT_SEED_REFUSED(verdict, status, asked)                              \
    do {                                                                         \
        struct seed_verdict seen_ = (verdict);                                   \
        ASSERT_EQ(seen_.st, (status));                                           \
        ASSERT(seen_.untouched);                                                 \
        ASSERT_EQ(seen_.calls, (asked));                                         \
    } while (0)

static int t_seed_source_refused(void)
{
    int failures = 0;
    TEST("rvmachine: a boot seed that is absent, short, failed or all zero refuses the load by name and writes nothing") {
        static uint8_t text[RMT_IMAGE_MAX], img[RMT_IMAGE_MAX + 0x1000];
        size_t text_len = 0, len;
        ASSERT(rmt_fixture("preload", text, &text_len));
        len = seed_elf(img, text, text_len, SEED_VA);
        ASSERT_SEED_REFUSED(seed_try(img, len, (struct seed_src){.give = 0}),
                            RVMACHINE_ERR_SEED_ABSENT, 1u);
        ASSERT_SEED_REFUSED(seed_try(img, len, (struct seed_src){.give = 1, .fill = 1}),
                            RVMACHINE_ERR_SEED_SHORT, 1u);
        ASSERT_SEED_REFUSED(seed_try(img, len, (struct seed_src){.give = SEED_N - 1u,
                                                                 .fill = SEED_N - 1u}),
                            RVMACHINE_ERR_SEED_SHORT, 1u);
        /* a source that wrote every byte and then reported failure */
        ASSERT_SEED_REFUSED(seed_try(img, len, (struct seed_src){.fails = true,
                                                                 .give = SEED_N,
                                                                 .fill = SEED_N}),
                            RVMACHINE_ERR_SEED_SOURCE, 1u);
        /* more than asked; and bytes claimed but never written (all zero) */
        ASSERT_SEED_REFUSED(seed_try(img, len, (struct seed_src){.give = SEED_N + 1u,
                                                                 .fill = SEED_N}),
                            RVMACHINE_ERR_SEED_SOURCE, 1u);
        ASSERT_SEED_REFUSED(seed_try(img, len, (struct seed_src){.give = SEED_N}),
                            RVMACHINE_ERR_SEED_SOURCE, 1u);
        ASSERT_STR_EQ(rvmachine_status_name(RVMACHINE_ERR_SEED_ABSENT),
                      "the boot seed source gave no bytes");
        ASSERT_STR_EQ(rvmachine_status_name(RVMACHINE_ERR_SEED_SHORT),
                      "the boot seed source gave too few bytes");
        ASSERT_STR_EQ(rvmachine_status_name(RVMACHINE_ERR_SEED_SOURCE),
                      "the boot seed source failed");
        ASSERT_STR_EQ(rvmachine_status_name(RVMACHINE_ERR_ENTRY),
                      "the kernel image has no loader entry to take a boot seed");
        /* every status has its own name; anything else has none */
        ASSERT_STR_EQ(rvmachine_status_name(RVMACHINE_ERR_PORT),
                      "byte port configuration or sink refused");
        ASSERT_STR_EQ(rvmachine_status_name(RVMACHINE_ERR_ENTROPY),
                      "fail-closed entropy source refused");
        for (int s = RVMACHINE_OK; s <= RVMACHINE_ERR_ENTROPY; s++)
            ASSERT(strcmp(rvmachine_status_name((enum rvmachine_status)s), "unknown") != 0);
        ASSERT_STR_EQ(rvmachine_status_name((enum rvmachine_status)(RVMACHINE_ERR_ENTROPY + 1)),
                      "unknown");
        ASSERT_STR_EQ(rvmachine_status_name((enum rvmachine_status)-1), "unknown");
        PASS();
    } _test_next:;
    return failures;
}

static int t_seed_image_refused(void)
{
    int failures = 0;
    TEST("rvmachine: an image without a usable loader entry or without room is refused before the seed source is asked") {
        static uint8_t text[RMT_IMAGE_MAX], img[RMT_IMAGE_MAX + 0x1000];
        static struct rmt_run r;
        const struct seed_src good = {.give = SEED_N, .fill = SEED_N};
        const uint64_t tree = RVMACHINE_RAM_BASE + RMT_RAM - 2u * MIB;
        struct seed_src src = good;
        size_t text_len = 0, len;
        ASSERT(rmt_fixture("preload", text, &text_len));
        /* a flat image has no entry but its first byte */
        ASSERT_SEED_REFUSED(seed_try(text, text_len, good), RVMACHINE_ERR_ENTRY, 0u);
        /* e_entry: below the segment, one past its file bytes, odd */
        len = seed_elf(img, text, text_len, SEED_VA);
        zcl_write_u64_le(img + 24, SEED_VA - 2u);
        ASSERT_SEED_REFUSED(seed_try(img, len, good), RVMACHINE_ERR_ENTRY, 0u);
        zcl_write_u64_le(img + 24, SEED_VA + text_len + 1u);
        ASSERT_SEED_REFUSED(seed_try(img, len, good), RVMACHINE_ERR_ENTRY, 0u);
        zcl_write_u64_le(img + 24, SEED_VA + SEED_ENTRY + 1u);
        ASSERT_SEED_REFUSED(seed_try(img, len, good), RVMACHINE_ERR_ENTRY, 0u);
        /* an even e_entry in an image linked at an odd address: the entry
         * would be loaded at an odd address, where no instruction starts */
        len = seed_elf(img, text, text_len, SEED_VA + 1u);
        zcl_write_u64_le(img + 24, SEED_VA + 1u + SEED_ENTRY + 1u);
        ASSERT_SEED_REFUSED(seed_try(img, len, good), RVMACHINE_ERR_ENTRY, 0u);
        ASSERT_EQ(seed_load(&r, NULL, img, len), RVMACHINE_OK); /* loads without a seed */
        rvmachine_destroy(r.m);
        len = seed_elf(img, text, text_len, SEED_VA);
        /* the last even address of the file bytes is an entry */
        zcl_write_u64_le(img + 24, SEED_VA + text_len - 1u);
        ASSERT_EQ(seed_load(&r, &src, img, len), RVMACHINE_OK);
        ASSERT_EQ(r.m->hart.pc, RVMACHINE_KERNEL_BASE + text_len - 1u);
        rvmachine_destroy(r.m);
        /* inside the segment but past its file bytes (bss) */
        len = seed_elf(img, text, text_len, SEED_VA);
        zcl_write_u64_le(img + ELF_HDR + 40, text_len + 0x100u); /* p_memsz */
        zcl_write_u64_le(img + 24, SEED_VA + text_len + 0x11u);
        ASSERT_SEED_REFUSED(seed_try(img, len, good), RVMACHINE_ERR_ENTRY, 0u);
        /* a segment that may not be executed */
        len = seed_elf(img, text, text_len, SEED_VA);
        zcl_write_u32_le(img + ELF_HDR + 4, 6); /* read, write */
        ASSERT_SEED_REFUSED(seed_try(img, len, good), RVMACHINE_ERR_ENTRY, 0u);
        /* two segments with different distances between virtual and physical */
        struct elf_seg split[2] = {
            {0x1000, SEED_VA, RVMACHINE_KERNEL_BASE, 0x100, 0x100},
            {0x1100, SEED_VA + 0x2000u, RVMACHINE_KERNEL_BASE + 0x3000u, 0x100, 0x100}};
        elf_build(img, split, 2);
        zcl_write_u64_le(img + 24, SEED_VA + SEED_ENTRY);
        ASSERT_SEED_REFUSED(seed_try(img, 0x1200, good), RVMACHINE_ERR_ENTRY, 0u);
        split[1].paddr = RVMACHINE_KERNEL_BASE + 0x2000u; /* one offset: accepted */
        elf_build(img, split, 2);
        zcl_write_u64_le(img + 24, SEED_VA + SEED_ENTRY);
        src = good;
        ASSERT_EQ(seed_load(&r, &src, img, 0x1200), RVMACHINE_OK);
        ASSERT_EQ(r.m->hart.x[10], SEED_VA + 0x5000u);
        rvmachine_destroy(r.m);
        /* a link address so high that the listed addresses would wrap */
        len = seed_elf(img, text, text_len, UINT64_MAX - 0xfffu);
        ASSERT_SEED_REFUSED(seed_try(img, len, good), RVMACHINE_ERR_ENTRY, 0u);
        /* no room under the device tree for the three pages: exactly three fit */
        len = seed_elf(img, text, text_len, SEED_VA);
        zcl_write_u64_le(img + ELF_HDR + 40, tree - RVMACHINE_KERNEL_BASE - 0x3000u);
        src = good;
        ASSERT_EQ(seed_load(&r, &src, img, len), RVMACHINE_OK);
        ASSERT_EQ(r.m->seed_addr, tree - 0x2000u);
        rvmachine_destroy(r.m);
        zcl_write_u64_le(img + ELF_HDR + 40, tree - RVMACHINE_KERNEL_BASE - 0x3000u + 1u);
        ASSERT_SEED_REFUSED(seed_try(img, len, good), RVMACHINE_ERR_IMAGE_RANGE, 0u);
        ASSERT_EQ(seed_load(&r, NULL, img, len), RVMACHINE_OK); /* fits without a seed */
        rvmachine_destroy(r.m);
        PASS();
    } _test_next:;
    return failures;
}

static int t_seed_metadata_alignment(void)
{
    int failures = 0;
    TEST("rvmachine: boot metadata must be word aligned before the seed source or guest memory is touched") {
        static uint8_t text[RMT_IMAGE_MAX], img[RMT_IMAGE_MAX + 0x1000];
        static struct rmt_run r;
        const struct seed_src good = {.give = SEED_N, .fill = SEED_N};
        struct seed_src src = good;
        size_t text_len = 0, len;
        ASSERT(rmt_fixture("preload", text, &text_len));
        /* The loaded instruction remains even for every offset; only the
         * virtual addresses handed to the metadata parser are misaligned. */
        for (uint64_t offset = 2u; offset < 8u; offset += 2u) {
            len = seed_elf(img, text, text_len, SEED_VA + offset);
            ASSERT_SEED_REFUSED(seed_try(img, len, good), RVMACHINE_ERR_ENTRY, 0u);
        }
        /* Word alignment is sufficient; a page-alignment restriction would
         * reject this otherwise usable loader entry. */
        len = seed_elf(img, text, text_len, SEED_VA + 8u);
        ASSERT_EQ(seed_load(&r, &src, img, len), RVMACHINE_OK);
        ASSERT_EQ(src.calls, 1u);
        ASSERT_EQ(r.m->hart.pc, RVMACHINE_KERNEL_BASE + SEED_ENTRY);
        ASSERT_EQ(r.m->hart.x[10], SEED_VA + 0x3008u);
        rvmachine_destroy(r.m);
        PASS();
    } _test_next:;
    return failures;
}

/* Each console queue has its own descriptor/available/used/payload region. */
static uint64_t cp_base(unsigned q) { return VQ_DESC + (uint64_t)q * 0x10000u; }
static void cp_queue(struct rvmachine *m, unsigned q)
{
    struct rvvirtio_dev *d = &m->con.dev;
    uint64_t base = cp_base(q);
    memset(vq_at(m, base), 0, 0x10000u);
    rvvirtio_mmio_write(d, RVVIRTIO_REG_QUEUE_SEL, q);
    rvvirtio_mmio_write(d, RVVIRTIO_REG_QUEUE_NUM, 16);
    rvvirtio_mmio_write(d, RVVIRTIO_REG_QUEUE_DESC_LOW, (uint32_t)base);
    rvvirtio_mmio_write(d, RVVIRTIO_REG_QUEUE_DESC_HIGH, 0);
    rvvirtio_mmio_write(d, RVVIRTIO_REG_QUEUE_DRIVER_LOW, (uint32_t)(base + 0x1000u));
    rvvirtio_mmio_write(d, RVVIRTIO_REG_QUEUE_DRIVER_HIGH, 0);
    rvvirtio_mmio_write(d, RVVIRTIO_REG_QUEUE_DEVICE_LOW, (uint32_t)(base + 0x2000u));
    rvvirtio_mmio_write(d, RVVIRTIO_REG_QUEUE_DEVICE_HIGH, 0);
    rvvirtio_mmio_write(d, RVVIRTIO_REG_QUEUE_READY, 1);
}
static void cp_post(struct rvmachine *m, unsigned q, unsigned i, unsigned n, bool write)
{
    uint64_t base = cp_base(q);
    uint8_t *d = vq_at(m, base) + 16u * i;
    zcl_write_u64_le(d, base + 0x3000u);
    zcl_write_u32_le(d + 8, n);
    zcl_write_u16_le(d + 12, write ? 2u : 0u);
    zcl_write_u16_le(d + 14, 0);
    uint8_t *a = vq_at(m, base + 0x1000u);
    unsigned pos = zcl_read_u16_le(a + 2);
    zcl_write_u16_le(a + 4u + 2u * (pos % 16u), (uint16_t)i);
    zcl_write_u16_le(a + 2, (uint16_t)(pos + 1u));
    uint64_t addr = RVMACHINE_VIRTIO_BASE +
        RVMACHINE_VIRTIO_SLOT_CONSOLE * RVMACHINE_VIRTIO_STRIDE + RVVIRTIO_REG_QUEUE_NOTIFY;
    (void)m->mem.io_store(m->mem.io_ctx, addr, 4, q);
}
static void cp_control(struct rvmachine *m, unsigned port, unsigned event)
{
    uint8_t *b = vq_at(m, cp_base(3) + 0x3000u);
    zcl_write_u32_le(b, port);
    zcl_write_u16_le(b + 4, (uint16_t)event);
    zcl_write_u16_le(b + 6, 1);
    cp_post(m, 3, 0, 8, false);
}
static void cp_driver(struct rvmachine *m)
{
    vq_up(&m->con.dev);
    for (unsigned q = 0; q < 2u * (m->conport_count + 1u); q++) cp_queue(m, q);
    cp_control(m, 0, 0); /* DEVICE_READY */
    for (unsigned p = 0; p < m->conport_count; p++) {
        cp_control(m, p, 3); /* PORT_READY */
        cp_control(m, p, 6); /* PORT_OPEN */
    }
}
struct cp_sink_state { uint8_t bytes[8][16384]; size_t n[8]; size_t limit; bool over; };
static size_t cp_sink(void *ctx, unsigned port, const uint8_t *bytes, size_t n)
{
    struct cp_sink_state *s = ctx;
    if (s->over && port == 1u) return n + 1u;
    size_t take = n < s->limit ? n : s->limit;
    if (port >= 8u || take > sizeof s->bytes[port] - s->n[port]) return 0;
    memcpy(s->bytes[port] + s->n[port], bytes, take);
    s->n[port] += take;
    return take;
}
static struct rvmachine *cp_machine(struct rmt_run *r, struct cp_sink_state *s,
                                   bool wait)
{
    static const uint8_t loop[4] = {0x6f, 0, 0, 0}; /* jal x0,0 */
    static const uint8_t idle[8] = {0x73, 0, 0x50, 0x10, 0x6f, 0xf0, 0xdf, 0xff};
    return rmt_machine_cfg(r, RMT_REAL, wait ? idle : loop, wait ? 8u : 4u,
        (struct rvmachine_config){.ram_bytes = RMT_RAM, .wait_stops = wait,
            .conport_count = 2, .conport_names = {"test.0", "test.1"},
            .conport_sink = cp_sink, .conport_ctx = s});
}
static struct rvmachine *cp_private_machine(struct rmt_run *r, struct cp_sink_state *s)
{
    static const uint8_t loop[4] = {0x6f, 0, 0, 0};
    return rmt_machine_cfg(r, RMT_REAL, loop, sizeof loop,
        (struct rvmachine_config){.ram_bytes = RMT_RAM, .cleanse_on_destroy = true,
            .conport_count = 2, .conport_names = {"test.0", "private.keyfile"},
            .private_keyfile_port_plus_one = 2, .conport_sink = cp_sink, .conport_ctx = s});
}

static bool cp_private_zero(const struct rvmachine_conport *p, size_t off, size_t n)
{
    for (size_t i = 0; i < n; i++)
        if (p->bytes[(off + i) % RVMACHINE_CONPORT_QUEUE] != 0) return false;
    return true;
}

static int t_private_keyfile_config(void)
{
    int failures = 0;
    struct rvmachine *m = NULL;
    static struct cp_sink_state s;
    struct rvmachine_config config = {.ram_bytes = RMT_RAM,
        .conport_count = 2, .conport_names = {"test.0", "private.keyfile"},
        .conport_sink = cp_sink, .conport_ctx = &s};
    TEST("rvmachine: keyfile mode defaults off and refuses index or missing cleanse") {
        ASSERT_EQ(rvmachine_create(&m, &config), RVMACHINE_OK);
        ASSERT(rvmachine_public_export_allowed(m));
        ASSERT(!m->conports[0].private_keyfile && !m->conports[1].private_keyfile);
        rvmachine_destroy(m); m = NULL;
        config.private_keyfile_port_plus_one = 3;
        config.cleanse_on_destroy = true;
        ASSERT_EQ(rvmachine_create(&m, &config), RVMACHINE_ERR_PORT);
        ASSERT(m == NULL);
        config.private_keyfile_port_plus_one = 2;
        config.cleanse_on_destroy = false;
        ASSERT_EQ(rvmachine_create(&m, &config), RVMACHINE_ERR_PORT);
        ASSERT(m == NULL);
        PASS();
    } _test_next:;
    rvmachine_destroy(m);
    return failures;
}

static int t_private_keyfile_public_target(void)
{
    int failures = 0;
    static struct rmt_run r;
    static struct cp_sink_state s;
    uint8_t material[32] = {1};
    TEST("rvmachine: wrong private API target preserves an ordinary queue with a pending epoch") {
        memset(&s, 0, sizeof s); s.limit = SIZE_MAX;
        ASSERT(cp_machine(&r, &s, false) != NULL);
        cp_driver(r.m);
        ASSERT_EQ(rvmachine_conport_input(r.m, 0, (const uint8_t *)"public", 6), 6u);
        rvvirtio_console_port_close(&r.m->con, 0); /* pending model epoch, not host reconciliation */
        ASSERT(r.m->conports[0].seen_generation !=
            rvvirtio_console_port_generation(&r.m->con, 0));
        struct rvmachine_conport before = r.m->conports[0];
        ASSERT(!rvmachine_keyfile_deliver(r.m, 0, before.generation, material, sizeof material));
        ASSERT(memcmp(&before, &r.m->conports[0], sizeof before) == 0);
        ASSERT(!r.m->conport_fault);
        PASS();
    } _test_next:;
    rvmachine_destroy(r.m); r.m = NULL;
    return failures;
}

static int t_private_keyfile_consume(void)
{
    int failures = 0;
    static struct rmt_run r;
    static struct cp_sink_state s;
    uint8_t material[32], received[32];
    for (size_t i = 0; i < sizeof material; i++) material[i] = (uint8_t)(i + 1u);
    TEST("rvmachine: private keyfile consumes and clears wrapped host spans exactly once") {
        memset(&s, 0, sizeof s); s.limit = SIZE_MAX;
        ASSERT(cp_private_machine(&r, &s) != NULL);
        cp_driver(r.m);
        ASSERT_EQ(rvmachine_conport_input(r.m, 0, NULL, 0), 0u); /* reconcile epochs */
        ASSERT(!rvmachine_public_export_allowed(r.m));
        ASSERT_EQ(rvmachine_conport_input(r.m, 1, material, sizeof material), 0u);
        ASSERT(!r.m->conports[1].private_sealed);
        r.m->conports[1].head = RVMACHINE_CONPORT_QUEUE - 16u;
        uint32_t generation = rvmachine_conport_generation(r.m, 1);
        ASSERT(rvmachine_keyfile_deliver(r.m, 1, generation, material, sizeof material));
        cp_post(r.m, 4, 0, 16, true);
        ASSERT_EQ(rvmachine_run(r.m, 64, &r.res), RVMACHINE_OK);
        memcpy(received, vq_at(r.m, cp_base(4) + 0x3000u), 16);
        ASSERT_EQ(rvmachine_conport_queued(r.m, 1), 16u);
        ASSERT(cp_private_zero(&r.m->conports[1], RVMACHINE_CONPORT_QUEUE - 16u, 16));
        ASSERT_EQ(r.m->conports[1].bytes[0], material[16]);
        cp_post(r.m, 4, 1, 16, true);
        ASSERT_EQ(rvmachine_run(r.m, 64, &r.res), RVMACHINE_OK);
        memcpy(received + 16, vq_at(r.m, cp_base(4) + 0x3000u), 16);
        ASSERT(memcmp(received, material, sizeof material) == 0);
        ASSERT_EQ(rvmachine_conport_queued(r.m, 1), 0u);
        ASSERT(cp_private_zero(&r.m->conports[1], 0, RVMACHINE_CONPORT_QUEUE));
        ASSERT(!rvmachine_keyfile_deliver(r.m, 1, generation, material, sizeof material));
        PASS();
    } _test_next:;
    rvmachine_destroy(r.m); r.m = NULL;
    return failures;
}

static int t_private_keyfile_duplicate(void)
{
    int failures = 0;
    static struct rmt_run r;
    static struct cp_sink_state s;
    uint8_t material[32];
    for (size_t i = 0; i < sizeof material; i++) material[i] = (uint8_t)(i + 1u);
    TEST("rvmachine: duplicate private attempt clears pending tail and faults after partial delivery") {
        memset(&s, 0, sizeof s); s.limit = SIZE_MAX;
        ASSERT(cp_private_machine(&r, &s) != NULL);
        cp_driver(r.m);
        (void)rvmachine_conport_input(r.m, 0, NULL, 0);
        uint32_t generation = rvmachine_conport_generation(r.m, 1);
        ASSERT(rvmachine_keyfile_deliver(r.m, 1, generation, material, sizeof material));
        cp_post(r.m, 4, 0, 16, true);
        ASSERT_EQ(rvmachine_run(r.m, 64, &r.res), RVMACHINE_OK);
        ASSERT_EQ(rvmachine_conport_queued(r.m, 1), 16u);
        ASSERT(memcmp(vq_at(r.m, cp_base(4) + 0x3000u), material, 16) == 0);
        ASSERT(!rvmachine_keyfile_deliver(r.m, 1, generation, material, sizeof material));
        ASSERT(r.m->conports[1].private_failed && r.m->conports[1].private_sealed);
        ASSERT_EQ(r.m->conports[1].count, 0u);
        ASSERT(cp_private_zero(&r.m->conports[1], 0, RVMACHINE_CONPORT_QUEUE));
        uint64_t retired = r.m->hart.retired;
        ASSERT_EQ(rvmachine_run(r.m, 64, &r.res), RVMACHINE_ERR_PORT);
        ASSERT_EQ(r.m->hart.retired, retired);
        /* Already delivered guest bytes are not retracted by host queue cleanup. */
        ASSERT(memcmp(vq_at(r.m, cp_base(4) + 0x3000u), material, 16) == 0);
        PASS();
    } _test_next:;
    rvmachine_destroy(r.m); r.m = NULL;
    return failures;
}

static int t_private_keyfile_retire(void)
{
    int failures = 0;
    static struct rmt_run r;
    static struct cp_sink_state s;
    uint8_t material[32]; memset(material, 0x6b, sizeof material);
    TEST("rvmachine: private discard close and reset clear residuals and never rearm") {
        for (unsigned mode = 0; mode < 3; mode++) {
            memset(&s, 0, sizeof s); s.limit = SIZE_MAX;
            ASSERT(cp_private_machine(&r, &s) != NULL);
            cp_driver(r.m);
            (void)rvmachine_conport_input(r.m, 0, NULL, 0);
            uint32_t generation = rvmachine_conport_generation(r.m, 1);
            ASSERT(rvmachine_keyfile_deliver(r.m, 1, generation, material, sizeof material));
            if (mode == 0) ASSERT_EQ(rvmachine_conport_discard(r.m, 1), sizeof material);
            if (mode == 1) {
                ASSERT(rvmachine_conport_close(r.m, 1));
                ASSERT(rvmachine_conport_open(r.m, 1));
            }
            if (mode == 2) {
                uint64_t base = RVMACHINE_VIRTIO_BASE +
                    RVMACHINE_VIRTIO_SLOT_CONSOLE * RVMACHINE_VIRTIO_STRIDE;
                ASSERT_EQ(r.m->mem.io_store(r.m->mem.io_ctx, base + RVVIRTIO_REG_STATUS, 4, 0), 0);
                cp_driver(r.m);
            }
            ASSERT_EQ(rvmachine_conport_queued(r.m, 1), 0u);
            ASSERT(cp_private_zero(&r.m->conports[1], 0, RVMACHINE_CONPORT_QUEUE));
            ASSERT(r.m->conports[1].private_sealed);
            ASSERT(!rvmachine_keyfile_deliver(r.m, 1,
                rvmachine_conport_generation(r.m, 1), material, sizeof material));
            rvmachine_destroy(r.m); r.m = NULL;
        }
        PASS();
    } _test_next:;
    rvmachine_destroy(r.m); r.m = NULL;
    return failures;
}

static int t_private_keyfile_refusal(void)
{
    int failures = 0;
    static struct rmt_run r;
    static struct cp_sink_state s;
    uint8_t material[32]; memset(material, 0x7c, sizeof material);
    TEST("rvmachine: private wrong length epoch and closed receiver refuse once") {
        for (unsigned mode = 0; mode < 4; mode++) {
            memset(&s, 0, sizeof s); s.limit = SIZE_MAX;
            ASSERT(cp_private_machine(&r, &s) != NULL);
            if (mode != 2) cp_driver(r.m);
            (void)rvmachine_conport_input(r.m, 0, NULL, 0);
            if (mode == 3) {
                ASSERT(rvmachine_conport_close(r.m, 1));
                ASSERT(!r.m->con.ports[1].host_open);
                ASSERT(r.m->con.ports[1].guest_open); /* before guest close acknowledgement */
            }
            uint32_t generation = rvmachine_conport_generation(r.m, 1);
            ASSERT(!rvmachine_keyfile_deliver(r.m, 1,
                mode == 1 ? generation + 1u : generation, material, mode == 0 ? 31u : 32u));
            ASSERT(r.m->conports[1].private_failed && r.m->conports[1].private_sealed);
            ASSERT_EQ(rvmachine_run(r.m, 1, &r.res), RVMACHINE_ERR_PORT);
            ASSERT(cp_private_zero(&r.m->conports[1], 0, RVMACHINE_CONPORT_QUEUE));
            cp_driver(r.m);
            ASSERT(!rvmachine_keyfile_deliver(r.m, 1,
                rvmachine_conport_generation(r.m, 1), material, sizeof material));
            rvmachine_destroy(r.m); r.m = NULL;
        }
        PASS();
    } _test_next:;
    rvmachine_destroy(r.m); r.m = NULL;
    return failures;
}

static int t_private_keyfile_tx(void)
{
    int failures = 0;
    static struct rmt_run r;
    static struct cp_sink_state s;
    TEST("rvmachine: private guest TX never reaches the public sink") {
        memset(&s, 0, sizeof s); s.limit = SIZE_MAX;
        ASSERT(cp_private_machine(&r, &s) != NULL);
        cp_driver(r.m);
        memset(vq_at(r.m, cp_base(5) + 0x3000u), 0x7c, 32);
        cp_post(r.m, 5, 0, 32, false);
        ASSERT_EQ(s.n[1], 0u);
        ASSERT_EQ(rvmachine_run(r.m, 1, &r.res), RVMACHINE_ERR_PORT);
        ASSERT(r.m->conports[1].private_failed && r.m->conports[1].private_sealed);
        PASS();
    } _test_next:;
    rvmachine_destroy(r.m); r.m = NULL;
    return failures;
}

static int t_conport_polling(void)
{
    int failures = 0;
    static struct rmt_run r;
    static struct cp_sink_state s;
    TEST("rvmachine: masked polling progresses both byte ports with exact TX suffixes") {
        memset(&s, 0, sizeof s); s.limit = SIZE_MAX;
        ASSERT(cp_machine(&r, &s, false) != NULL);
        cp_driver(r.m);
        ASSERT_EQ(r.m->hart.csr.mie, 0u);
        for (unsigned p = 0; p < 2; p++) {
            unsigned tx = p == 0u ? 1u : 5u;
            memset(vq_at(r.m, cp_base(tx) + 0x3000u), (int)('A' + p), 12288);
            cp_post(r.m, tx, 0, 12288, false);
            ASSERT_EQ(s.n[p], 4096u);
            ASSERT_EQ(rvmachine_conport_input(r.m, p, (const uint8_t *)"rx", 2), 2u);
            cp_post(r.m, p == 0u ? 0u : 4u, 0, 2, true);
        }
        ASSERT_EQ(rvmachine_run(r.m, 3, &r.res), RVMACHINE_OK);
        for (unsigned p = 0; p < 2; p++) {
            ASSERT_EQ(s.n[p], 8192u);
            ASSERT_EQ(rvmachine_conport_queued(r.m, p), 0u);
            ASSERT(memcmp(vq_at(r.m, cp_base(p == 0u ? 0u : 4u) + 0x3000u), "rx", 2) == 0);
        }
        ASSERT_EQ(rvmachine_run(r.m, 3, &r.res), RVMACHINE_OK);
        for (unsigned p = 0; p < 2; p++) {
            ASSERT_EQ(s.n[p], 12288u);
            for (size_t i = 0; i < s.n[p]; i++) ASSERT_EQ(s.bytes[p][i], 'A' + p);
        }
        PASS();
    } _test_next:;
    rvmachine_destroy(r.m); r.m = NULL;
    return failures;
}
static int t_conport_refusal(void)
{
    int failures = 0;
    static struct rmt_run r;
    static struct cp_sink_state s;
    TEST("rvmachine: a port sink overaccept at the last service fails closed") {
        memset(&s, 0, sizeof s); s.limit = 0;
        ASSERT(cp_machine(&r, &s, false) != NULL);
        cp_driver(r.m);
        for (unsigned p = 0; p < 2; p++) {
            unsigned tx = p == 0u ? 1u : 5u;
            memset(vq_at(r.m, cp_base(tx) + 0x3000u), 'x', 4096);
            cp_post(r.m, tx, 0, 4096, false);
        }
        ASSERT_EQ(s.n[0], 0u);
        s.over = true; s.limit = SIZE_MAX;
        rvmachine_conport_resume(r.m, 0);
        rvmachine_conport_resume(r.m, 1);
        /* Port0 consumes the final work unit; port1 fails in that same round. */
        ASSERT_EQ(rvmachine_run(r.m, 1, &r.res), RVMACHINE_ERR_PORT);
        ASSERT_EQ(s.n[0], 4096u);
        ASSERT_EQ(s.n[1], 0u);
        ASSERT_EQ(r.res.device_work, 1u);
        PASS();
    } _test_next:;
    rvmachine_destroy(r.m); r.m = NULL;
    return failures;
}
static int t_conport_wait_reset(void)
{
    int failures = 0;
    static struct rmt_run r;
    static struct cp_sink_state s;
    TEST("rvmachine: masked wait holds input and reset drops it before guest open") {
        memset(&s, 0, sizeof s); s.limit = SIZE_MAX;
        ASSERT(cp_machine(&r, &s, true) != NULL);
        ASSERT_EQ(rvmachine_conport_input(r.m, 0, (const uint8_t *)"old", 3), 3u);
        uint32_t generation = rvmachine_conport_generation(r.m, 0);
        ASSERT_EQ(rvmachine_run(r.m, 100, &r.res), RVMACHINE_OK);
        ASSERT_EQ(r.res.stop, RVMACHINE_STOP_IDLE);
        uint64_t retired = r.res.retired, work = r.res.device_work, time = r.res.guest_time;
        for (unsigned i = 0; i < 16; i++) {
            ASSERT_EQ(rvmachine_run(r.m, 100, &r.res), RVMACHINE_ERR_WAITING);
            ASSERT_EQ(r.res.retired, retired);
            ASSERT_EQ(r.res.device_work, work);
            ASSERT_EQ(r.res.guest_time, time);
        }
        /* Use machine MMIO so its host-queue epoch reset runs as well. */
        uint64_t addr = RVMACHINE_VIRTIO_BASE +
            RVMACHINE_VIRTIO_SLOT_CONSOLE * RVMACHINE_VIRTIO_STRIDE + RVVIRTIO_REG_STATUS;
        ASSERT_EQ(r.m->mem.io_store(r.m->mem.io_ctx, addr, 4, 0), 0);
        ASSERT(rvmachine_conport_generation(r.m, 0) > generation);
        ASSERT_EQ(rvmachine_conport_queued(r.m, 0), 0u);
        ASSERT_EQ(r.m->conports[0].discarded, 3u);
        PASS();
    } _test_next:;
    rvmachine_destroy(r.m); r.m = NULL;
    return failures;
}
static int t_conport_masked_wait(void)
{
    int failures = 0;
    static struct rmt_run r;
    static struct cp_sink_state s;
    TEST("rvmachine: functioning masked byte ports cannot spin a waiting hart") {
        memset(&s, 0, sizeof s); s.limit = SIZE_MAX;
        ASSERT(cp_machine(&r, &s, true) != NULL);
        cp_driver(r.m);
        memset(vq_at(r.m, cp_base(0) + 0x3000u), 0xa5, 3);
        cp_post(r.m, 0, 0, 3, true);
        ASSERT_EQ(rvmachine_run(r.m, 100, &r.res), RVMACHINE_OK);
        ASSERT_EQ(r.res.stop, RVMACHINE_STOP_IDLE);
        ASSERT_EQ(rvmachine_conport_input(r.m, 0, (const uint8_t *)"held", 4), 4u);
        uint64_t retired = r.res.retired, work = r.res.device_work, time = r.res.guest_time;
        for (unsigned i = 0; i < 16; i++) {
            ASSERT_EQ(rvmachine_run(r.m, 100, &r.res), RVMACHINE_ERR_WAITING);
            ASSERT_EQ(r.res.retired, retired);
            ASSERT_EQ(r.res.device_work, work);
            ASSERT_EQ(r.res.guest_time, time);
            ASSERT_EQ(rvmachine_conport_queued(r.m, 0), 4u);
            ASSERT_EQ(zcl_read_u16_le(vq_at(r.m, cp_base(0) + 0x2000u) + 2), 0u);
        }
        PASS();
    } _test_next:;
    rvmachine_destroy(r.m); r.m = NULL;
    return failures;
}
static int t_conport_close_suffix(void)
{
    int failures = 0;
    static struct rmt_run r;
    static struct cp_sink_state s;
    TEST("rvmachine: closing a partial byte stream revokes its suffix only") {
        memset(&s, 0, sizeof s); s.limit = 3;
        ASSERT(cp_machine(&r, &s, false) != NULL);
        cp_driver(r.m);
        memcpy(vq_at(r.m, cp_base(1) + 0x3000u), "oldOLD", 6);
        cp_post(r.m, 1, 0, 6, false);
        ASSERT_EQ(s.n[0], 3u);
        ASSERT_EQ(r.m->con.ports[0].tx_off, 3u);
        ASSERT(r.m->conports[0].blocked);
        ASSERT_EQ(rvmachine_conport_input(r.m, 0, (const uint8_t *)"old", 3), 3u);
        uint32_t generation = rvmachine_conport_generation(r.m, 0);
        ASSERT(rvmachine_conport_close(r.m, 0));
        ASSERT(rvmachine_conport_generation(r.m, 0) > generation);
        ASSERT_EQ(rvmachine_conport_queued(r.m, 0), 0u);
        ASSERT_EQ(r.m->conports[0].discarded, 3u);
        ASSERT(!r.m->conports[0].blocked);
        ASSERT_EQ(r.m->con.ports[0].tx_off, 0u);
        ASSERT(rvmachine_conport_open(r.m, 0));
        s.limit = SIZE_MAX;
        rvmachine_conport_resume(r.m, 0);
        ASSERT_EQ(rvmachine_run(r.m, 10, &r.res), RVMACHINE_OK);
        ASSERT_EQ(s.n[0], 3u);
        memcpy(vq_at(r.m, cp_base(5) + 0x3000u), "peer", 4);
        cp_post(r.m, 5, 0, 4, false);
        ASSERT_EQ(s.n[1], 4u);
        ASSERT(memcmp(s.bytes[1], "peer", 4) == 0);
        memcpy(vq_at(r.m, cp_base(1) + 0x3000u), "new", 3);
        cp_post(r.m, 1, 1, 3, false);
        ASSERT_EQ(s.n[0], 6u);
        ASSERT(memcmp(s.bytes[0], "oldnew", 6) == 0);
        PASS();
    } _test_next:;
    rvmachine_destroy(r.m); r.m = NULL;
    return failures;
}
static int t_conport_eight_ports(void)
{
    int failures = 0;
    static struct rmt_run r;
    static struct cp_sink_state s;
    static const uint8_t loop[4] = {0x6f, 0, 0, 0};
    TEST("rvmachine: the highest of eight ports progresses in each saturated round") {
        memset(&s, 0, sizeof s); s.limit = SIZE_MAX;
        ASSERT(rmt_machine_cfg(&r, RMT_REAL, loop, sizeof loop,
            (struct rvmachine_config){.ram_bytes = RMT_RAM, .conport_count = 8,
                .conport_names = {"p0", "p1", "p2", "p3", "p4", "p5", "p6", "p7"},
                .conport_sink = cp_sink, .conport_ctx = &s}) != NULL);
        cp_driver(r.m);
        for (unsigned p = 0; p < 8; p++) {
            unsigned tx = p == 0u ? 1u : 2u * (p + 1u) + 1u;
            memset(vq_at(r.m, cp_base(tx) + 0x3000u), (int)('a' + p), 12288);
            cp_post(r.m, tx, 0, 12288, false);
            ASSERT_EQ(s.n[p], 4096u);
        }
        /* Charge one aggregate unit per started4096 accepted bytes per round. */
        for (unsigned round = 0; round < 2; round++) {
            uint64_t before = r.m->device_work;
            ASSERT_EQ(rvmachine_run(r.m, 8, &r.res), RVMACHINE_OK);
            ASSERT_EQ(r.m->device_work - before, 8u);
            for (unsigned p = 0; p < 8; p++)
                ASSERT_EQ(s.n[p], (size_t)(round + 2u) * 4096u);
        }
        for (unsigned p = 0; p < 8; p++)
            for (size_t i = 0; i < s.n[p]; i++) ASSERT_EQ(s.bytes[p][i], 'a' + p);
        PASS();
    } _test_next:;
    rvmachine_destroy(r.m); r.m = NULL;
    return failures;
}
static int t_conport_stopped(void)
{
    int failures = 0;
    static struct rmt_run r;
    static struct cp_sink_state s;
    TEST("rvmachine: closed and stopped byte queues cannot advertise runnable work") {
        memset(&s, 0, sizeof s); s.limit = SIZE_MAX;
        ASSERT(cp_machine(&r, &s, false) != NULL);
        rvmachine_conport_resume(r.m, 0);
        ASSERT_EQ(rvmachine_conport_pending(r.m, 0) & RVMACHINE_PENDING_PORT, 0u);
        cp_driver(r.m);
        ASSERT_EQ(rvmachine_conport_input(r.m, 0, (const uint8_t *)"held", 4), 4u);
        rvvirtio_mmio_write(&r.m->con.dev, RVVIRTIO_REG_QUEUE_SEL, 0);
        rvvirtio_mmio_write(&r.m->con.dev, RVVIRTIO_REG_QUEUE_READY, 0);
        ASSERT_EQ(rvmachine_run(r.m, 10, &r.res), RVMACHINE_OK);
        ASSERT_EQ(rvmachine_conport_queued(r.m, 0), 4u);
        ASSERT_EQ(r.res.device_work, 0u);
        ASSERT_EQ(rvmachine_conport_pending(r.m, 0) & RVMACHINE_PENDING_PORT, 0u);
        ASSERT(rvmachine_conport_close(r.m, 0));
        rvmachine_conport_resume(r.m, 0);
        ASSERT_EQ(rvmachine_conport_pending(r.m, 0) & RVMACHINE_PENDING_PORT, 0u);
        ASSERT_EQ(rvmachine_run(r.m, 10, &r.res), RVMACHINE_OK);
        ASSERT_EQ(r.res.device_work, 0u);
        ASSERT_EQ(s.n[0], 0u);
        PASS();
    } _test_next:;
    rvmachine_destroy(r.m); r.m = NULL;
    return failures;
}
/* Reset revokes the device's queues; already consumed guest bytes require framing. */
static int t_conport_reset_suffix(void)
{
    int failures = 0;
    static struct rmt_run r;
    static struct cp_sink_state s;
    TEST("rvmachine: reset revokes queued RX and blocked TX before fresh reopen") {
        memset(&s, 0, sizeof s); s.limit = 0;
        ASSERT(cp_machine(&r, &s, false) != NULL);
        cp_driver(r.m);
        memcpy(vq_at(r.m, cp_base(1) + 0x3000u), "old", 3);
        cp_post(r.m, 1, 0, 3, false);
        ASSERT_EQ(s.n[0], 0u);
        ASSERT(r.m->conports[0].blocked);
        ASSERT_EQ(rvmachine_conport_input(r.m, 0, (const uint8_t *)"old", 3), 3u);
        uint32_t generation = rvmachine_conport_generation(r.m, 0);
        uint64_t addr = RVMACHINE_VIRTIO_BASE +
            RVMACHINE_VIRTIO_SLOT_CONSOLE * RVMACHINE_VIRTIO_STRIDE + RVVIRTIO_REG_STATUS;
        ASSERT_EQ(r.m->mem.io_store(r.m->mem.io_ctx, addr, 4, 0), 0);
        ASSERT(rvmachine_conport_generation(r.m, 0) > generation);
        ASSERT_EQ(rvmachine_conport_queued(r.m, 0), 0u);
        ASSERT_EQ(r.m->conports[0].discarded, 3u);
        ASSERT(!r.m->conports[0].blocked);
        ASSERT_EQ(r.m->con.ports[0].tx_off, 0u);
        cp_driver(r.m);
        s.limit = SIZE_MAX;
        rvmachine_conport_resume(r.m, 0);
        ASSERT_EQ(rvmachine_run(r.m, 10, &r.res), RVMACHINE_OK);
        ASSERT_EQ(s.n[0], 0u); /* old chain was not replayed */
        memcpy(vq_at(r.m, cp_base(1) + 0x3000u), "new", 3);
        cp_post(r.m, 1, 0, 3, false);
        ASSERT_EQ(s.n[0], 3u);
        ASSERT(memcmp(s.bytes[0], "new", 3) == 0);
        ASSERT_EQ(rvmachine_conport_input(r.m, 0, (const uint8_t *)"new", 3), 3u);
        memset(vq_at(r.m, cp_base(0) + 0x3000u), 0xa5, 3);
        cp_post(r.m, 0, 0, 3, true);
        ASSERT_EQ(rvmachine_run(r.m, 10, &r.res), RVMACHINE_OK);
        ASSERT(memcmp(vq_at(r.m, cp_base(0) + 0x3000u), "new", 3) == 0);
        ASSERT_EQ(zcl_read_u16_le(vq_at(r.m, cp_base(0) + 0x2000u) + 2), 1u);
        ASSERT_EQ(rvmachine_conport_queued(r.m, 0), 0u);
        PASS();
    } _test_next:;
    rvmachine_destroy(r.m); r.m = NULL;
    return failures;
}
struct entropy_fault_probe { unsigned calls, mode; };
static size_t entropy_fault_source(void *ctx, uint8_t *buf, size_t n)
{
    struct entropy_fault_probe *p = ctx;
    p->calls++;
    if (n != 0) buf[0] = 0x5a;
    return p->mode == 0 ? 0 : p->mode == 1 ? 1 : n + 1u;
}

static int t_entropy_fatal_boundary(void)
{
    int failures = 0;
    static struct rmt_run r;
    /* Actual MMIO QueueNotify, then a register sentinel, then a bounded loop. */
    static const uint8_t guest[] = {
        0x23, 0x28, 0x09, 0x04, 0x13, 0x0a, 0x10, 0x00, 0x6f, 0x00, 0x00, 0x00};
    TEST("rvmachine: fatal entropy notify stops before the next instruction and preserves default dry retry") {
        for (unsigned mode = 0; mode < 4u; mode++) {
            struct entropy_fault_probe p = {.mode = mode % 3u};
            ASSERT(rmt_machine_cfg(&r, RMT_REAL, guest, sizeof guest,
                (struct rvmachine_config){.ram_bytes = RMT_RAM,
                    .entropy = entropy_fault_source, .entropy_ctx = &p,
                    .entropy_fail_closed = mode < 3u}) != NULL);
            vq_up(&r.m->rng.dev);
            vq_desc(r.m, 0, VQ_DATA, 16, 2, 0);
            memset(vq_at(r.m, VQ_AVAIL), 0, 4u + 2u * VQ_NUM);
            zcl_write_u16_le(vq_at(r.m, VQ_AVAIL) + 2, 1);
            memset(vq_at(r.m, VQ_DATA), 0xa5, 16);
            r.m->hart.x[18] = RVMACHINE_VIRTIO_BASE +
                RVMACHINE_VIRTIO_SLOT_ENTROPY * RVMACHINE_VIRTIO_STRIDE;
            rmt_go(&r, RMT_REAL, 64);
            ASSERT_EQ(p.calls, 1u);
            if (mode < 3u) {
                ASSERT_EQ(r.st, RVMACHINE_ERR_ENTROPY);
                ASSERT_EQ(r.m->hart.x[20], 0u);
                ASSERT_EQ(r.res.retired, 1u);
                ASSERT_EQ(r.res.device_work, 0u);
                ASSERT_EQ(r.res.pc, RVMACHINE_KERNEL_BASE + 4u);
                ASSERT_EQ(vq_used(r.m), 0u);
                for (unsigned i = 0; i < 16u; i++) ASSERT_EQ(vq_at(r.m, VQ_DATA)[i], 0xa5);
                ASSERT_EQ(rvmachine_run(r.m, 64, &r.res), RVMACHINE_ERR_ENTROPY);
                ASSERT_EQ(p.calls, 1u);
                ASSERT_EQ(r.m->hart.retired, 1u);
            } else {
                ASSERT_EQ(r.st, RVMACHINE_OK);
                ASSERT_EQ(r.m->hart.x[20], 1u);
                ASSERT(!r.m->entropy_fault);
                ASSERT(r.m->entropy_dry);
                /* Resume the held request through pre-instruction service.
                 * This test host explicitly selects strict mode after dry. */
                uint64_t retired = r.res.retired;
                r.m->entropy_fail_closed = true;
                r.m->hart.x[20] = 0;
                r.m->hart.pc = RVMACHINE_KERNEL_BASE + 4u;
                rvmachine_entropy_ready(r.m);
                ASSERT_EQ(rvmachine_run(r.m, 64, &r.res), RVMACHINE_ERR_ENTROPY);
                ASSERT_EQ(p.calls, 2u);
                ASSERT_EQ(r.res.retired, retired);
                ASSERT_EQ(r.m->hart.x[20], 0u);
                ASSERT_EQ(r.res.pc, RVMACHINE_KERNEL_BASE + 4u);
                ASSERT_EQ(r.res.device_work, 0u);
            }
            rvmachine_destroy(r.m); r.m = NULL;
        }
        PASS();
    } _test_next:;
    rvmachine_destroy(r.m); r.m = NULL;
    return failures;
}

/* ---- 11c. the trap-storm count, owed device rounds, time reads and a mid-run
 * invalidation. The pinned numbers are those of the per-instruction run loop
 * of commit 441a8941e2, which these cases were run against. ---- */
/* the real entry, whose prototype the twin include renamed */
void rvmachine_enter(struct rvmachine *m);
#define RV_NOP 0x00000013u
#define RV_WFI 0x10500073u
#define RV_CSR_TIME 0xc01u
#define STORM_CYCLES_COMMON 1027u
#define STORM_CYCLES_REENTRY 1025u

static uint32_t rv_rdtime(uint32_t rd)
{
    return rv_i(RV_OP_SYSTEM, 2, rd, 0, RV_CSR_TIME);
}

static int t_sched_storm(void)
{
    int failures = 0;
    static struct rmt_run r;
    TEST("rvmachine: a trap storm stops after the steps the per-instruction loop took, also on re-entry") {
        static uint8_t image[64];
        struct rv_prog p = {.n = 0};
        for (unsigned i = 0; i < 3; i++) rv_emit(&p, RV_NOP);
        rv_emit(&p, 0u); /* illegal; the handler address 0 cannot be fetched */
        ASSERT(rmt_machine(&r, image, rv_image(&p, image), NULL) != NULL);
        rmt_go(&r, RMT_REAL, RMT_WORK);
        ASSERT_EQ(r.res.stop, RVMACHINE_STOP_FAULT);
        ASSERT_EQ(r.res.retired, 3u);
        ASSERT_EQ(r.m->hart.cycle, STORM_CYCLES_COMMON);
        rvmachine_destroy(r.m);
        r.m = NULL;
        /* the same machine entered again after a run that retired instructions,
         * its first instruction trapping for good */
        p.n = 0;
        for (unsigned i = 0; i < 3; i++) rv_emit(&p, RV_NOP);
        rv_shutdown(&p);
        ASSERT(rmt_machine(&r, image, rv_image(&p, image), NULL) != NULL);
        rmt_go(&r, RMT_REAL, RMT_WORK);
        ASSERT_EQ(r.res.stop, RVMACHINE_STOP_SHUTDOWN);
        memset(r.m->mem.bytes + (RVMACHINE_KERNEL_BASE - RVMACHINE_RAM_BASE), 0, sizeof image);
        rvmachine_enter(r.m);
        rmt_go(&r, RMT_REAL, RMT_WORK);
        ASSERT_EQ(r.res.stop, RVMACHINE_STOP_FAULT);
        ASSERT_EQ(r.res.retired, 0u);
        ASSERT_EQ(r.m->hart.cycle, STORM_CYCLES_REENTRY);
        PASS();
    } _test_next:;
    rvmachine_destroy(r.m); r.m = NULL;
    return failures;
}

#define OWED_RETIRED 21u
#define OWED_DEVICE_WORK 256u

static int t_sched_owed(void)
{
    int failures = 0;
    static struct rmt_run r;
    TEST("rvmachine: entropy work left by one notify is finished round by round with no further bus access") {
        enum { POSTED = RVVIRTIO_QUEUE_MAX };
        static uint8_t image[256];
        struct ent_src src = {.left = UINT64_MAX};
        struct rv_prog p = {.n = 0};
        rv_emit(&p, rv_u(0x17u, RV_T1, (uint32_t)((VQ_USED - RVMACHINE_KERNEL_BASE) >> 12)));
        rv_emit(&p, rv_u(0x37u, RV_T0, (uint32_t)((RVMACHINE_VIRTIO_BASE +
                                                  RVMACHINE_VIRTIO_STRIDE) >> 12)));
        rv_emit(&p, rv_i(RV_OP_IMM, 0, RV_T3, 0, POSTED));
        rv_emit(&p, rv_s(2, RV_T0, 0, RVVIRTIO_REG_QUEUE_NOTIFY));
        rv_emit(&p, rv_i(RV_OP_LOAD, 5, RV_T2, RV_T1, 2));
        rv_emit(&p, rv_bne_back(RV_T2, RV_T3, 4));
        rv_shutdown(&p);
        ASSERT(ent_machine(&r, RMT_REAL, image, rv_image(&p, image), &src) != NULL);
        /* 256 requests of 4096 bytes: the notify serves 16, a round 16 */
        vq_up(&r.m->rng.dev);
        vq_desc(r.m, 0, VQ_DATA, RVVIRTIO_RNG_REQ_BYTES_MAX, 2, 0);
        memset(vq_at(r.m, VQ_AVAIL), 0, 4u + 2u * VQ_NUM);
        zcl_write_u16_le(vq_at(r.m, VQ_AVAIL) + 2, POSTED);
        rmt_go(&r, RMT_REAL, RMT_WORK);
        ASSERT_EQ(r.st, RVMACHINE_OK);
        ASSERT_EQ(r.res.stop, RVMACHINE_STOP_SHUTDOWN);
        ASSERT_EQ(vq_used(r.m), (unsigned)POSTED);
        ASSERT_EQ(r.res.retired, OWED_RETIRED);
        ASSERT_EQ(r.res.device_work, OWED_DEVICE_WORK);
        PASS();
    } _test_next:;
    rvmachine_destroy(r.m); r.m = NULL;
    return failures;
}

#define TIME_AT_9 0u
#define TIME_AT_10 1u
#define TIME_AT_11 1u
#define TIME_AFTER_TIMER 1u
#define TIME_AFTER_WFI 100u

static int t_sched_time(void)
{
    int failures = 0;
    static struct rmt_run r;
    TEST("rvmachine: the time CSR reads what the per-instruction loop gave around a unit, a timer and a wfi skip") {
        static uint8_t image[128];
        struct rv_prog p = {.n = 0};
        for (unsigned i = 0; i < 9; i++) rv_emit(&p, RV_NOP);
        rv_emit(&p, rv_rdtime(5));                                    /* retired 9 */
        rv_emit(&p, rv_rdtime(6));                                    /* retired 10 */
        rv_emit(&p, rv_rdtime(7));                                    /* retired 11 */
        rv_emit(&p, rv_i(RV_OP_IMM, 0, 30, 0, 0x20));
        rv_emit(&p, rv_i(RV_OP_SYSTEM, 1, 0, 30, RV_CSR_SIE));        /* STIE, no SIE */
        rv_emit(&p, rv_i(RV_OP_IMM, 0, RV_A0, 0, 100));
        rv_emit(&p, rv_i(RV_OP_IMM, 0, RV_A7, 0, RV_SBI_SET_TIMER));
        rv_emit(&p, RV_ECALL);
        rv_emit(&p, rv_rdtime(28));
        rv_emit(&p, RV_WFI);
        rv_emit(&p, rv_rdtime(29));
        rv_shutdown(&p);
        ASSERT(rmt_machine(&r, image, rv_image(&p, image), NULL) != NULL);
        rmt_go(&r, RMT_REAL, RMT_WORK);
        ASSERT_EQ(r.res.stop, RVMACHINE_STOP_SHUTDOWN);
        ASSERT_EQ(r.m->hart.x[5], TIME_AT_9);
        ASSERT_EQ(r.m->hart.x[6], TIME_AT_10);
        ASSERT_EQ(r.m->hart.x[7], TIME_AT_11);
        ASSERT_EQ(r.m->hart.x[28], TIME_AFTER_TIMER);
        ASSERT_EQ(r.m->hart.x[29], TIME_AFTER_WFI);
        PASS();
    } _test_next:;
    rvmachine_destroy(r.m); r.m = NULL;
    return failures;
}

/* D2-BEGIN */
static uint64_t hart_digest(const struct rvmachine *m)
{
    uint64_t h = UINT64_C(0xcbf29ce484222325);
    const struct rvemu_hart *x = &m->hart;
    uint64_t words[6] = {x->pc, x->instret, x->cycle, x->retired, x->time, x->priv};
    const uint8_t *parts[3] = {(const uint8_t *)x->x, (const uint8_t *)words, (const uint8_t *)&x->csr};
    const size_t lens[3] = {sizeof x->x, sizeof words, sizeof x->csr};
    for (unsigned k = 0; k < 3; k++)
        for (size_t i = 0; i < lens[k]; i++) h = (h ^ parts[k][i]) * UINT64_C(0x100000001b3);
    return h;
}

static int t_sched_invalidate(void)
{
    int failures = 0;
    static struct rmt_run whole, cut;
    TEST("rvmachine: dropping the derived state between two runs changes nothing the guest sees") {
        static uint8_t image[RMT_IMAGE_MAX];
        size_t len = 0;
        ASSERT(rmt_fixture("paging", image, &len));
        ASSERT(rmt_machine(&whole, image, len, NULL) != NULL);
        rmt_go(&whole, RMT_REAL, RMT_WORK);
        ASSERT(rmt_machine(&cut, image, len, NULL) != NULL);
        rmt_go(&cut, RMT_REAL, 100);
        ASSERT_EQ(cut.res.stop, RVMACHINE_STOP_BUDGET);
        rvmachine_invalidate_derived(cut.m);
        rmt_go(&cut, RMT_REAL, 300);
        ASSERT_EQ(cut.res.stop, RVMACHINE_STOP_BUDGET);
        rvmachine_invalidate_derived(cut.m);
        rmt_go(&cut, RMT_REAL, RMT_WORK);
        ASSERT_EQ(whole.res.stop, RVMACHINE_STOP_SHUTDOWN);
        ASSERT(rmt_same(&whole, &cut));
        ASSERT_EQ(hart_digest(cut.m), hart_digest(whole.m));
        PASS();
    } _test_next:;
    rvmachine_destroy(whole.m); whole.m = NULL;
    rvmachine_destroy(cut.m); cut.m = NULL;
    return failures;
}
/* D2-END */

int test_rvmachine(void);
int rvmachine_secret_retirement_cases(void);
int test_rvmachine(void)
{
    return t_private_keyfile_config() + t_private_keyfile_public_target() + t_private_keyfile_consume() + t_private_keyfile_duplicate() + t_private_keyfile_retire() + t_private_keyfile_refusal() + t_private_keyfile_tx() + t_retained_disk() + t_retained_virtio() + rvmachine_secret_retirement_cases() + t_entropy_fatal_boundary() + t_conport_stopped() + t_conport_eight_ports() + t_conport_close_suffix() + t_conport_masked_wait() + t_conport_reset_suffix() + t_conport_polling() + t_conport_refusal() + t_conport_wait_reset() + t_tiny() + t_tiny_fetch() + t_paging() + t_budget() + t_idle_and_fault() + t_dtb() +
           t_entry_and_placement() + t_loader_places() + t_loader_refuses() +
           t_disk() + t_disk_cap() + t_input() + t_script() + t_user_clock() +
           t_remote_fence() + t_block_before_wait() + t_sched_timer() + t_sched_console() +
           t_sched_block() + t_sched_storm() + t_sched_owed() + t_sched_time() +
           t_sched_invalidate() + t_one_kernel() +
           t_clock_saturates() + t_device_work() + t_entropy() + t_entropy_dry() +
           t_entropy_with_disk() + t_wait_stop() + t_wait_equal() + t_wait_input() +
           t_wait_entropy() + t_wait_masked() + t_wait_held() + t_wait_past_deadline() +
           t_wait_lines() +
           t_wait_stopped_queue() +
           t_wait_hostile() + t_seed_layout() + t_seed_guest() +
           t_seed_source_refused() + t_seed_image_refused() + t_seed_metadata_alignment() +
           t_entropy_work();
}
