/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: proofs for the guest data disk: the machine's second block device
 * at virtio slot 3 (absent, capacity, routing, flush and error status), the
 * sparse owner-private file under <home>/.z23/guests/<name>/data.img, the
 * create, grow and status actions of dev.app.machine.data with their named
 * refusals, the exclusive lock, and the data_disk input of
 * dev.app.machine.boot with its persistent and not-repeatable receipt. */
#include "test/test_core.h"

#include "base/serialize_le.h"
#include "command/native_command.h"
#include "config/command_catalog.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "rvmachine/rvmachine.h"
#include "../../../tools/command/native_dev_machine_data.h"

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define MIB (UINT64_C(1) << 20)
#define RAM (UINT64_C(64) << 20)
#define WIRE 16384u

int rvmachine_io_load(void *ctx, uint64_t paddr, unsigned nbytes, uint64_t *out);
int rvmachine_io_store(void *ctx, uint64_t paddr, unsigned nbytes, uint64_t val);

/* ---- driving a block device the way a guest driver does ---- */
#define VQ_NUM 8u

struct vq {
    struct rvmachine *m;
    struct rvvirtio_dev *dev;
    uint64_t base;
    uint16_t avail;
};

static uint8_t *at(const struct vq *q, uint64_t off)
{
    return q->m->mem.bytes + (q->base + off - RVMACHINE_RAM_BASE);
}

#define DESC 0x0u
#define AVAIL 0x1000u
#define USED 0x2000u
#define HDR 0x4000u
#define STATUS 0x4100u
#define DATA 0x10000u

static void desc(const struct vq *q, unsigned i, uint64_t off, uint32_t len,
                 uint16_t flags, uint16_t next)
{
    uint8_t *d = at(q, DESC) + 16u * i;
    zcl_write_u64_le(d, q->base + off);
    zcl_write_u32_le(d + 8, len);
    zcl_write_u16_le(d + 12, flags);
    zcl_write_u16_le(d + 14, next);
}

static void vq_up(struct vq *q, struct rvmachine *m, struct rvvirtio_dev *d, uint64_t base)
{
    q->m = m;
    q->dev = d;
    q->base = base;
    q->avail = 0;
    rvvirtio_mmio_write(d, RVVIRTIO_REG_STATUS, 0);
    rvvirtio_mmio_write(d, RVVIRTIO_REG_STATUS, RVVIRTIO_STATUS_ACKNOWLEDGE | RVVIRTIO_STATUS_DRIVER);
    rvvirtio_mmio_write(d, RVVIRTIO_REG_DRIVER_FEATURES_SEL, 1);
    rvvirtio_mmio_write(d, RVVIRTIO_REG_DRIVER_FEATURES, 1);
    rvvirtio_mmio_write(d, RVVIRTIO_REG_DRIVER_FEATURES_SEL, 0);
    rvvirtio_mmio_write(d, RVVIRTIO_REG_DRIVER_FEATURES, 0);
    rvvirtio_mmio_write(d, RVVIRTIO_REG_STATUS, RVVIRTIO_STATUS_ACKNOWLEDGE |
                        RVVIRTIO_STATUS_DRIVER | RVVIRTIO_STATUS_FEATURES_OK);
    rvvirtio_mmio_write(d, RVVIRTIO_REG_QUEUE_SEL, 0);
    rvvirtio_mmio_write(d, RVVIRTIO_REG_QUEUE_NUM, VQ_NUM);
    rvvirtio_mmio_write(d, RVVIRTIO_REG_QUEUE_DESC_LOW, (uint32_t)(base + DESC));
    rvvirtio_mmio_write(d, RVVIRTIO_REG_QUEUE_DESC_HIGH, 0);
    rvvirtio_mmio_write(d, RVVIRTIO_REG_QUEUE_DRIVER_LOW, (uint32_t)(base + AVAIL));
    rvvirtio_mmio_write(d, RVVIRTIO_REG_QUEUE_DRIVER_HIGH, 0);
    rvvirtio_mmio_write(d, RVVIRTIO_REG_QUEUE_DEVICE_LOW, (uint32_t)(base + USED));
    rvvirtio_mmio_write(d, RVVIRTIO_REG_QUEUE_DEVICE_HIGH, 0);
    rvvirtio_mmio_write(d, RVVIRTIO_REG_QUEUE_READY, 1);
    rvvirtio_mmio_write(d, RVVIRTIO_REG_STATUS, RVVIRTIO_STATUS_ACKNOWLEDGE |
                        RVVIRTIO_STATUS_DRIVER | RVVIRTIO_STATUS_FEATURES_OK |
                        RVVIRTIO_STATUS_DRIVER_OK);
}

/* One request of the given type at a sector; the 512 data bytes are at DATA.
 * Returns the status byte the device wrote. */
static uint8_t vq_io(struct vq *q, uint32_t type, uint64_t sector)
{
    memset(at(q, HDR), 0, 16);
    zcl_write_u32_le(at(q, HDR), type);
    zcl_write_u64_le(at(q, HDR) + 8, sector);
    desc(q, 0, HDR, 16, 1, type == RVVIRTIO_BLK_T_FLUSH ? 2 : 1);
    if (type != RVVIRTIO_BLK_T_FLUSH)
        desc(q, 1, DATA, 512, 1 | (type == RVVIRTIO_BLK_T_IN ? 2 : 0), 2);
    desc(q, 2, STATUS, 1, 2, 0);
    *at(q, STATUS) = 0xa5;
    zcl_write_u16_le(at(q, AVAIL) + 4u + 2u * (q->avail % VQ_NUM), 0);
    q->avail++;
    zcl_write_u16_le(at(q, AVAIL) + 2, q->avail);
    rvvirtio_mmio_write(q->dev, RVVIRTIO_REG_QUEUE_NOTIFY, 0);
    return *at(q, STATUS);
}

/* ---- machines ---- */
struct mem_disk {
    uint8_t bytes[MIB];
};

static bool mem_read(void *ctx, uint64_t off, void *buf, size_t n)
{
    struct mem_disk *d = ctx;
    if (off > sizeof d->bytes || n > sizeof d->bytes - off) return false;
    memcpy(buf, d->bytes + off, n);
    return true;
}

static bool mem_write(void *ctx, uint64_t off, const void *buf, size_t n)
{
    struct mem_disk *d = ctx;
    if (off > sizeof d->bytes || n > sizeof d->bytes - off) return false;
    memcpy(d->bytes + off, buf, n);
    return true;
}

static bool mem_flush(void *ctx)
{
    (void)ctx;
    return true;
}

static void quiet(void *ctx, uint8_t byte)
{
    (void)ctx;
    (void)byte;
}

/* A machine with an optional memory disk at slot 0 and an optional data file
 * at slot 3. */
static struct rvmachine *machine(struct mem_disk *first, struct zcl_mb_data_file *data)
{
    static const uint8_t spin[4] = {0x6f, 0x00, 0x00, 0x00};
    struct rvmachine_config c = {.ram_bytes = RAM, .console = quiet};
    struct rvmachine *m = NULL;
    if (first != NULL &&
        rvmachine_disk_open_backend(&c.disk, MIB, mem_read, mem_write, mem_flush, first) != RVMACHINE_OK)
        return NULL;
    if (data != NULL &&
        rvmachine_disk_open_backend(&c.data_disk, data->bytes, zcl_mb_data_read_cb,
                                    zcl_mb_data_write_cb, zcl_mb_data_flush_cb, data) != RVMACHINE_OK)
        return NULL;
    if (rvmachine_create(&m, &c) != RVMACHINE_OK) return NULL;
    if (rvmachine_load_kernel(m, spin, sizeof spin) != RVMACHINE_OK) {
        rvmachine_destroy(m);
        return NULL;
    }
    return m;
}

static uint64_t slot_reg(struct rvmachine *m, unsigned slot, uint64_t reg)
{
    uint64_t v = UINT64_MAX;
    if (rvmachine_io_load(m, RVMACHINE_VIRTIO_BASE + slot * RVMACHINE_VIRTIO_STRIDE + reg, 4, &v) != 0)
        return UINT64_MAX;
    return v;
}

/* ---- command dispatch ---- */
struct call {
    struct json_value doc;
    enum zcl_command_exit exit_code;
    bool parsed;
};

static bool dispatch(struct call *c, const char *path, zcl_command_handler_fn handler,
                     const char *json)
{
    static char wire[WIRE];
    const struct zcl_command_spec *found =
        zcl_command_registry_find(zcl_command_catalog(), path, NULL);
    struct zcl_command_spec spec;
    struct json_value input;
    size_t len = 0;
    json_init(&c->doc);
    c->parsed = false;
    c->exit_code = ZCL_COMMAND_EXIT_INTERNAL;
    if (found == NULL) return false;
    spec = *found;
    spec.handler = handler;
    json_init(&input);
    if (json_read(&input, json, strlen(json)) && input.type == JSON_OBJ)
        len = zcl_command_registry_execute_json(zcl_command_catalog(), &spec, NULL, &input, false,
                                                path, NULL, 0, 0, NULL, wire, sizeof wire,
                                                &c->exit_code);
    json_free(&input);
    c->parsed = len > 0 && json_read(&c->doc, wire, len);
    return c->parsed;
}

static bool data_cmd(struct call *c, const char *home, const char *args)
{
    char json[1024];
    snprintf(json, sizeof json, "{\"home\":\"%s\",%s}", home, args);
    return dispatch(c, MD_PATH, zcl_native_handle_dev_machine_data, json);
}

static bool call_ok(const struct call *c)
{
    return c->parsed && json_get_bool(json_get(&c->doc, "ok")) && c->exit_code == ZCL_COMMAND_EXIT_OK;
}

static const char *call_error(const struct call *c)
{
    const char *s = json_get_str(json_get(json_get(&c->doc, "error"), "code"));
    return s != NULL ? s : "";
}

static int64_t call_int(const struct call *c, const char *key)
{
    const struct json_value *v = json_get(json_get(&c->doc, "data"), key);
    return v != NULL && v->type == JSON_INT ? json_get_int(v) : -1;
}

static bool call_flag(const struct call *c, const char *key)
{
    const struct json_value *v = json_get(json_get(&c->doc, "data"), key);
    return v != NULL && v->type == JSON_BOOL && json_get_bool(v);
}

static const char *call_str(const struct call *c, const char *key)
{
    const char *s = json_get_str(json_get(json_get(&c->doc, "data"), key));
    return s != NULL ? s : "";
}

static void call_end(struct call *c)
{
    json_free(&c->doc);
    c->parsed = false;
}

/* Runs a data command and reports whether it was refused with this code. */
static bool refused(const char *home, const char *args, const char *code)
{
    struct call c;
    bool ok = data_cmd(&c, home, args) && !call_ok(&c) && strcmp(call_error(&c), code) == 0;
    call_end(&c);
    return ok;
}

static bool image_path(char *out, size_t n, const char *home, const char *name)
{
    return snprintf(out, n, "%s/.z23/guests/%s/data.img", home, name) < (int)n;
}

/* ---- proofs ---- */
static int t_names(void)
{
    int failures = 0;
    TEST("rvmachine_data_disk: names are [a-z0-9][a-z0-9-]{0,31} and nothing else") {
        static const char *const good[] = {"a", "0", "work", "a-b-c", "9lives",
                                           "abcdefghijklmnopqrstuvwxyz012345"};
        static const char *const bad[] = {"", "..", ".", "a/b", "/abs", "-a", "A", "a_b", "a b",
                                          "abcdefghijklmnopqrstuvwxyz0123456", "a\n"};
        for (size_t i = 0; i < sizeof good / sizeof *good; i++) ASSERT(zcl_mb_data_name_valid(good[i]));
        for (size_t i = 0; i < sizeof bad / sizeof *bad; i++) ASSERT(!zcl_mb_data_name_valid(bad[i]));
        ASSERT(!zcl_mb_data_name_valid(NULL));
        PASS();
    } _test_next:;
    return failures;
}

static int t_commands(void)
{
    int failures = 0;
    char home[200], path[300];
    struct call c;
    struct stat sb;
    TEST("rvmachine_data_disk: create makes a sparse owner-private file; grow extends it; shrink is refused") {
        ASSERT(test_mkdtemp(home, sizeof home, "data_disk") != NULL);
        ASSERT(data_cmd(&c, home, "\"action\":\"create\",\"name\":\"work\",\"size_mib\":64"));
        ASSERT(call_ok(&c));
        ASSERT_EQ(call_int(&c, "bytes"), (int64_t)(64 * MIB));
        call_end(&c);
        ASSERT(image_path(path, sizeof path, home, "work"));
        ASSERT_EQ(stat(path, &sb), 0);
        ASSERT_EQ((uint64_t)sb.st_size, 64 * MIB);
        ASSERT_EQ(sb.st_mode & 0777, 0600);
        ASSERT((uint64_t)sb.st_blocks * 512u < MIB);
        snprintf(path, sizeof path, "%s/.z23/guests/work", home);
        ASSERT_EQ(stat(path, &sb), 0);
        ASSERT_EQ(sb.st_mode & 0777, 0700);
        snprintf(path, sizeof path, "%s/.z23/guests", home);
        ASSERT_EQ(stat(path, &sb), 0);
        ASSERT_EQ(sb.st_mode & 0777, 0700);

        ASSERT(data_cmd(&c, home, "\"action\":\"status\",\"name\":\"work\""));
        ASSERT(call_ok(&c));
        ASSERT_EQ(call_int(&c, "bytes"), (int64_t)(64 * MIB));
        ASSERT(call_int(&c, "allocated_bytes") >= 0 && call_int(&c, "allocated_bytes") < (int64_t)MIB);
        ASSERT(!call_flag(&c, "locked"));
        call_end(&c);

        ASSERT(refused(home, "\"action\":\"create\",\"name\":\"work\",\"size_mib\":8", "DATA_DISK_EXISTS"));
        ASSERT(refused(home, "\"action\":\"status\",\"name\":\"nope\"", "DATA_DISK_ABSENT"));
        ASSERT(refused(home, "\"action\":\"grow\",\"name\":\"nope\",\"size_mib\":8", "DATA_DISK_ABSENT"));
        ASSERT(refused(home, "\"action\":\"create\",\"name\":\"huge\",\"size_mib\":1048577", "DATA_DISK_TOO_LARGE"));
        ASSERT(refused(home, "\"action\":\"grow\",\"name\":\"work\",\"size_mib\":1048577", "DATA_DISK_TOO_LARGE"));

        ASSERT(data_cmd(&c, home, "\"action\":\"grow\",\"name\":\"work\",\"size_mib\":128"));
        ASSERT(call_ok(&c));
        ASSERT_EQ(call_int(&c, "bytes"), (int64_t)(128 * MIB));
        ASSERT_EQ(call_int(&c, "previous_bytes"), (int64_t)(64 * MIB));
        call_end(&c);
        ASSERT(image_path(path, sizeof path, home, "work"));
        ASSERT_EQ(stat(path, &sb), 0);
        ASSERT_EQ((uint64_t)sb.st_size, 128 * MIB);
        ASSERT(refused(home, "\"action\":\"grow\",\"name\":\"work\",\"size_mib\":32", "DATA_DISK_SHRINK_REFUSED"));
        ASSERT(refused(home, "\"action\":\"grow\",\"name\":\"work\",\"size_mib\":128", "DATA_DISK_SHRINK_REFUSED"));
        ASSERT_EQ(stat(path, &sb), 0);
        ASSERT_EQ((uint64_t)sb.st_size, 128 * MIB);
        PASS();
    } _test_next:;
    return failures;
}

static int t_bad_names(void)
{
    int failures = 0;
    char home[200], path[300];
    static const char *const bad[] = {"..", "a/b", "abcdefghijklmnopqrstuvwxyz0123456", "-x", "X"};
    TEST("rvmachine_data_disk: invalid names are refused by name and touch nothing") {
        ASSERT(test_mkdtemp(home, sizeof home, "data_disk") != NULL);
        for (size_t i = 0; i < sizeof bad / sizeof *bad; i++) {
            char args[160];
            snprintf(args, sizeof args, "\"action\":\"create\",\"name\":\"%s\",\"size_mib\":8", bad[i]);
            ASSERT(refused(home, args, "DATA_DISK_NAME_INVALID"));
        }
        /* the registry refuses an empty string before the leaf runs */
        ASSERT(refused(home, "\"action\":\"create\",\"name\":\"\",\"size_mib\":8", "INVALID_INPUT"));
        snprintf(path, sizeof path, "%s/.z23", home);
        ASSERT(access(path, F_OK) != 0);
        PASS();
    } _test_next:;
    return failures;
}

static int t_lock(void)
{
    int failures = 0;
    char home[200];
    struct call c;
    struct zcl_mb_data_file *held = NULL;
    TEST("rvmachine_data_disk: a disk held by a run refuses a second holder, grow and reports locked") {
        struct zcl_command_reply reply;
        ASSERT(test_mkdtemp(home, sizeof home, "data_disk") != NULL);
        ASSERT(data_cmd(&c, home, "\"action\":\"create\",\"name\":\"lk\",\"size_mib\":8"));
        ASSERT(call_ok(&c));
        call_end(&c);
        zcl_command_reply_init(&reply, "zcl.dev_machine_data.v1");
        held = zcl_mb_data_open(home, "lk", &reply);
        ASSERT(held != NULL);
        ASSERT_EQ(held->bytes, 8 * MIB);
        ASSERT(zcl_mb_data_open(home, "lk", &reply) == NULL);
        zcl_command_reply_free(&reply);
        ASSERT(refused(home, "\"action\":\"grow\",\"name\":\"lk\",\"size_mib\":16", "DATA_DISK_LOCKED"));
        ASSERT(data_cmd(&c, home, "\"action\":\"status\",\"name\":\"lk\""));
        ASSERT(call_ok(&c) && call_flag(&c, "locked"));
        call_end(&c);
        zcl_mb_data_close(held);
        held = NULL;
        ASSERT(data_cmd(&c, home, "\"action\":\"grow\",\"name\":\"lk\",\"size_mib\":16"));
        ASSERT(call_ok(&c));
        call_end(&c);
        PASS();
    } _test_next:;
    zcl_mb_data_close(held);
    return failures;
}

static int t_slot_absent(void)
{
    int failures = 0;
    static struct mem_disk first;
    struct rvmachine *m = NULL;
    TEST("rvmachine_data_disk: without a data disk slot 3 reads as an empty slot and the first disk is unchanged") {
        m = machine(&first, NULL);
        ASSERT(m != NULL);
        ASSERT_EQ(slot_reg(m, RVMACHINE_VIRTIO_SLOT_DISK1, RVVIRTIO_REG_MAGIC), RVVIRTIO_MAGIC);
        ASSERT_EQ(slot_reg(m, RVMACHINE_VIRTIO_SLOT_DISK1, RVVIRTIO_REG_DEVICE_ID), 0u);
        ASSERT_EQ(slot_reg(m, RVMACHINE_VIRTIO_SLOT_DISK, RVVIRTIO_REG_DEVICE_ID), 2u);
        /* a store into the empty slot is ignored: the status reads back zero */
        ASSERT_EQ(rvmachine_io_store(m, RVMACHINE_VIRTIO_BASE +
                  RVMACHINE_VIRTIO_SLOT_DISK1 * RVMACHINE_VIRTIO_STRIDE + RVVIRTIO_REG_STATUS,
                  4, RVVIRTIO_STATUS_ACKNOWLEDGE), 0);
        ASSERT_EQ(slot_reg(m, RVMACHINE_VIRTIO_SLOT_DISK1, RVVIRTIO_REG_STATUS), 0u);
        PASS();
    } _test_next:;
    rvmachine_destroy(m);
    return failures;
}

static int t_routing(void)
{
    int failures = 0;
    static struct mem_disk first;
    char home[200];
    struct call c;
    struct zcl_command_reply reply;
    struct zcl_mb_data_file *f = NULL;
    struct rvmachine *m = NULL;
    struct vq q0, q1;
    TEST("rvmachine_data_disk: slot 3 reports capacity; reads, writes and flush reach the data file and never the first disk") {
        ASSERT(test_mkdtemp(home, sizeof home, "data_disk") != NULL);
        ASSERT(data_cmd(&c, home, "\"action\":\"create\",\"name\":\"rt\",\"size_mib\":8"));
        call_end(&c);
        zcl_command_reply_init(&reply, "zcl.dev_machine_data.v1");
        f = zcl_mb_data_open(home, "rt", &reply);
        zcl_command_reply_free(&reply);
        ASSERT(f != NULL);
        memset(first.bytes, 0x11, sizeof first.bytes);
        m = machine(&first, f);
        ASSERT(m != NULL);
        ASSERT_EQ(slot_reg(m, RVMACHINE_VIRTIO_SLOT_DISK1, RVVIRTIO_REG_DEVICE_ID), 2u);
        ASSERT_EQ(slot_reg(m, RVMACHINE_VIRTIO_SLOT_DISK1, RVVIRTIO_REG_CONFIG), (8 * MIB) / 512u);
        ASSERT_EQ(slot_reg(m, RVMACHINE_VIRTIO_SLOT_DISK, RVVIRTIO_REG_CONFIG), MIB / 512u);
        vq_up(&q0, m, &m->blk.dev, UINT64_C(0x82000000));
        vq_up(&q1, m, &m->blk1.dev, UINT64_C(0x83000000));

        memset(at(&q1, DATA), 0x6d, 512);
        ASSERT_EQ(vq_io(&q1, RVVIRTIO_BLK_T_OUT, 3), RVVIRTIO_BLK_S_OK);
        ASSERT_EQ(vq_io(&q1, RVVIRTIO_BLK_T_FLUSH, 0), RVVIRTIO_BLK_S_OK);
        ASSERT_EQ(first.bytes[3 * 512], 0x11); /* the first disk never saw it */
        memset(at(&q1, DATA), 0, 512);
        ASSERT_EQ(vq_io(&q1, RVVIRTIO_BLK_T_IN, 3), RVVIRTIO_BLK_S_OK);
        ASSERT_EQ(at(&q1, DATA)[0], 0x6d);
        ASSERT_EQ(at(&q1, DATA)[511], 0x6d);

        memset(at(&q0, DATA), 0x22, 512);
        ASSERT_EQ(vq_io(&q0, RVVIRTIO_BLK_T_OUT, 5), RVVIRTIO_BLK_S_OK);
        ASSERT_EQ(first.bytes[5 * 512], 0x22);
        memset(at(&q1, DATA), 0x55, 512);
        ASSERT_EQ(vq_io(&q1, RVVIRTIO_BLK_T_IN, 5), RVVIRTIO_BLK_S_OK);
        ASSERT_EQ(at(&q1, DATA)[0], 0); /* the data disk still holds zeros there */

        ASSERT_EQ(vq_io(&q1, RVVIRTIO_BLK_T_IN, (8 * MIB) / 512u), RVVIRTIO_BLK_S_IOERR); /* past the end */
        PASS();
    } _test_next:;
    rvmachine_destroy(m);
    zcl_mb_data_close(f);
    return failures;
}

static int t_persistence(void)
{
    int failures = 0;
    char home[200];
    struct call c;
    struct zcl_command_reply reply;
    struct zcl_mb_data_file *f = NULL;
    struct rvmachine *m = NULL;
    struct vq q;
    TEST("rvmachine_data_disk: a block written and flushed by one machine is read back by the next") {
        ASSERT(test_mkdtemp(home, sizeof home, "data_disk") != NULL);
        ASSERT(data_cmd(&c, home, "\"action\":\"create\",\"name\":\"pr\",\"size_mib\":8"));
        call_end(&c);
        zcl_command_reply_init(&reply, "zcl.dev_machine_data.v1");
        f = zcl_mb_data_open(home, "pr", &reply);
        ASSERT(f != NULL);
        m = machine(NULL, f);
        ASSERT(m != NULL);
        vq_up(&q, m, &m->blk1.dev, UINT64_C(0x82000000));
        memset(at(&q, DATA), 0x7a, 512);
        ASSERT_EQ(vq_io(&q, RVVIRTIO_BLK_T_OUT, 9), RVVIRTIO_BLK_S_OK);
        ASSERT_EQ(vq_io(&q, RVVIRTIO_BLK_T_FLUSH, 0), RVVIRTIO_BLK_S_OK);
        rvmachine_destroy(m);
        m = NULL;
        zcl_mb_data_close(f);
        f = zcl_mb_data_open(home, "pr", &reply);
        ASSERT(f != NULL);
        m = machine(NULL, f);
        ASSERT(m != NULL);
        vq_up(&q, m, &m->blk1.dev, UINT64_C(0x82000000));
        memset(at(&q, DATA), 0, 512);
        ASSERT_EQ(vq_io(&q, RVVIRTIO_BLK_T_IN, 9), RVVIRTIO_BLK_S_OK);
        ASSERT_EQ(at(&q, DATA)[0], 0x7a);
        ASSERT_EQ(at(&q, DATA)[511], 0x7a);
        PASS();
    } _test_next:;
    zcl_command_reply_free(&reply);
    rvmachine_destroy(m);
    zcl_mb_data_close(f);
    return failures;
}

static int t_errors(void)
{
    int failures = 0;
    char home[200];
    struct call c;
    struct zcl_command_reply reply;
    struct zcl_mb_data_file *f = NULL;
    struct rvmachine *m = NULL;
    struct vq q;
    TEST("rvmachine_data_disk: with the host file unusable, flush and write return an I/O error to the guest") {
        ASSERT(test_mkdtemp(home, sizeof home, "data_disk") != NULL);
        ASSERT(data_cmd(&c, home, "\"action\":\"create\",\"name\":\"er\",\"size_mib\":8"));
        call_end(&c);
        zcl_command_reply_init(&reply, "zcl.dev_machine_data.v1");
        f = zcl_mb_data_open(home, "er", &reply);
        ASSERT(f != NULL);
        m = machine(NULL, f);
        ASSERT(m != NULL);
        vq_up(&q, m, &m->blk1.dev, UINT64_C(0x82000000));
        ASSERT_EQ(vq_io(&q, RVVIRTIO_BLK_T_FLUSH, 0), RVVIRTIO_BLK_S_OK);
        platform_private_file_close(&f->file);
        ASSERT_EQ(vq_io(&q, RVVIRTIO_BLK_T_FLUSH, 0), RVVIRTIO_BLK_S_IOERR);
        memset(at(&q, DATA), 1, 512);
        ASSERT_EQ(vq_io(&q, RVVIRTIO_BLK_T_OUT, 1), RVVIRTIO_BLK_S_IOERR);
        PASS();
    } _test_next:;
    zcl_command_reply_free(&reply);
    rvmachine_destroy(m);
    zcl_mb_data_close(f);
    return failures;
}

static bool copy_fixture(const char *dest)
{
    FILE *in = fopen("tests/fixtures/rvmachine/tiny.bin", "rb");
    FILE *out = fopen(dest, "wb");
    uint8_t buf[8192];
    size_t n = in != NULL ? fread(buf, 1, sizeof buf, in) : 0;
    bool ok = in != NULL && out != NULL && n != 0 && fwrite(buf, 1, n, out) == n;
    if (in != NULL) fclose(in);
    return (out == NULL || fclose(out) == 0) && ok;
}

static int t_boot(void)
{
    int failures = 0;
    char home[200], kernel[300], args[800];
    struct call c, plain;
    struct zcl_mb_data_file *held = NULL;
    struct zcl_command_reply reply;
    TEST("rvmachine_data_disk: boot with data_disk is persistent and not repeatable, refuses absent or held disks, and leaves the run itself unchanged") {
        ASSERT(test_mkdtemp(home, sizeof home, "data_disk") != NULL);
        snprintf(kernel, sizeof kernel, "%s/kernel.bin", home);
        ASSERT(copy_fixture(kernel));
        ASSERT(data_cmd(&c, home, "\"action\":\"create\",\"name\":\"bt\",\"size_mib\":8"));
        call_end(&c);
        snprintf(args, sizeof args, "{\"kernel\":\"%s\",\"max_instr\":1000000}", kernel);
        ASSERT(dispatch(&plain, "dev.app.machine.boot", zcl_native_handle_dev_machine_boot, args));
        ASSERT(call_ok(&plain));
        ASSERT(json_get(json_get(&plain.doc, "data"), "data_disk") == NULL);

        snprintf(args, sizeof args,
                 "{\"kernel\":\"%s\",\"max_instr\":1000000,\"data_disk\":\"bt\",\"home\":\"%s\"}",
                 kernel, home);
        ASSERT(dispatch(&c, "dev.app.machine.boot", zcl_native_handle_dev_machine_boot, args));
        ASSERT(call_ok(&c));
        {
            const struct json_value *row = json_get(json_get(&c.doc, "data"), "data_disk");
            ASSERT(row != NULL);
            ASSERT_STR_EQ(json_get_str(json_get(row, "name")), "bt");
            ASSERT_EQ(json_get_int(json_get(row, "bytes")), (int64_t)(8 * MIB));
            ASSERT(json_get_bool(json_get(row, "persistent")));
            ASSERT(!json_get_bool(json_get(row, "repeatable")));
        }
        ASSERT_STR_EQ(json_get_str(json_get(json_get(&c.doc, "data"), "transcript_sha256")),
                      json_get_str(json_get(json_get(&plain.doc, "data"), "transcript_sha256")));
        ASSERT_EQ(json_get_int(json_get(json_get(&c.doc, "data"), "retired")),
                  json_get_int(json_get(json_get(&plain.doc, "data"), "retired")));
        call_end(&c);
        call_end(&plain);

        zcl_command_reply_init(&reply, "zcl.dev_machine_data.v1");
        held = zcl_mb_data_open(home, "bt", &reply);
        zcl_command_reply_free(&reply);
        ASSERT(held != NULL);
        ASSERT(dispatch(&c, "dev.app.machine.boot", zcl_native_handle_dev_machine_boot, args));
        ASSERT(!call_ok(&c));
        ASSERT_STR_EQ(call_error(&c), "DATA_DISK_LOCKED");
        call_end(&c);
        zcl_mb_data_close(held);
        held = NULL;

        snprintf(args, sizeof args,
                 "{\"kernel\":\"%s\",\"max_instr\":1000000,\"data_disk\":\"zz\",\"home\":\"%s\"}",
                 kernel, home);
        ASSERT(dispatch(&c, "dev.app.machine.boot", zcl_native_handle_dev_machine_boot, args));
        ASSERT_STR_EQ(call_error(&c), "DATA_DISK_ABSENT");
        call_end(&c);
        snprintf(args, sizeof args,
                 "{\"kernel\":\"%s\",\"max_instr\":1000000,\"data_disk\":\"..\",\"home\":\"%s\"}",
                 kernel, home);
        ASSERT(dispatch(&c, "dev.app.machine.boot", zcl_native_handle_dev_machine_boot, args));
        ASSERT_STR_EQ(call_error(&c), "DATA_DISK_NAME_INVALID");
        call_end(&c);
        PASS();
    } _test_next:;
    zcl_mb_data_close(held);
    return failures;
}


/* ---- path integrity and the public-owner exclusion ---- */

static bool boot_refused(const char *home, const char *kernel, const char *name,
                         const char *code)
{
    char args[800];
    struct call c;
    bool ok;
    snprintf(args, sizeof args,
             "{\"kernel\":\"%s\",\"max_instr\":1000000,\"data_disk\":\"%s\",\"home\":\"%s\"}",
             kernel, name, home);
    ok = dispatch(&c, "dev.app.machine.boot", zcl_native_handle_dev_machine_boot, args) &&
         !call_ok(&c) && strcmp(call_error(&c), code) == 0;
    call_end(&c);
    return ok;
}

/* grow, status and a boot attach of disk "x" are all refused with this code. */
static bool every_path_refused(const char *home, const char *kernel, const char *code)
{
    return refused(home, "\"action\":\"grow\",\"name\":\"x\",\"size_mib\":64", code) &&
           refused(home, "\"action\":\"status\",\"name\":\"x\"", code) &&
           boot_refused(home, kernel, "x", code);
}

static bool make_disk(const char *home, const char *name)
{
    struct call c;
    char args[128];
    bool ok;
    snprintf(args, sizeof args, "\"action\":\"create\",\"name\":\"%s\",\"size_mib\":8", name);
    ok = data_cmd(&c, home, args) && call_ok(&c);
    call_end(&c);
    return ok;
}

/* A fresh home in which level 0 (.z23), 1 (.z23/guests) or 2 (.z23/guests/x)
 * is a symlink to the same level of the real home; the levels above are real. */
static bool link_under(char *home, size_t n, const char *real, int level)
{
    static const char *const rel[] = {"/.z23", "/.z23/guests", "/.z23/guests/x"};
    char from[400], target[400];
    if (test_mkdtemp(home, n, "data_disk") == NULL) return false;
    for (int i = 0; i < level; i++) {
        snprintf(from, sizeof from, "%s%s", home, rel[i]);
        if (mkdir(from, 0700) != 0) return false;
    }
    snprintf(from, sizeof from, "%s%s", home, rel[level]);
    snprintf(target, sizeof target, "%s%s", real, rel[level]);
    return symlink(target, from) == 0;
}

static int t_levels(void)
{
    int failures = 0;
    char real[200], kernel[300], home[200];
    TEST("rvmachine_data_disk: a symlinked .z23, guests or name directory is refused on create, grow, status and boot") {
        ASSERT(test_mkdtemp(real, sizeof real, "data_disk") != NULL);
        snprintf(kernel, sizeof kernel, "%s/kernel.bin", real);
        ASSERT(copy_fixture(kernel));
        ASSERT(make_disk(real, "x"));
        for (int level = 0; level < 3; level++) {
            ASSERT(link_under(home, sizeof home, real, level));
            ASSERT(every_path_refused(home, kernel, "DATA_DISK_DIRECTORY_REFUSED"));
            ASSERT(refused(home, "\"action\":\"create\",\"name\":\"x\",\"size_mib\":8",
                           "DATA_DISK_DIRECTORY_REFUSED"));
        }
        PASS();
    } _test_next:;
    return failures;
}

static int t_z23_mode(void)
{
    int failures = 0;
    char home[200], path[400];
    struct stat sb;
    TEST("rvmachine_data_disk: an existing real .z23 directory keeps its mode and is accepted") {
        ASSERT(test_mkdtemp(home, sizeof home, "data_disk") != NULL);
        snprintf(path, sizeof path, "%s/.z23", home);
        ASSERT(mkdir(path, 0755) == 0);
        ASSERT(chmod(path, 0755) == 0);  /* exact start mode under any umask */
        ASSERT(make_disk(home, "x"));
        ASSERT(stat(path, &sb) == 0 && (sb.st_mode & 0777) == 0755);
        ASSERT(refused(home, "\"action\":\"create\",\"name\":\"x\",\"size_mib\":8", "DATA_DISK_EXISTS"));
        PASS();
    } _test_next:;
    return failures;
}

static int t_files(void)
{
    int failures = 0;
    char home[200], kernel[300], img[400], other[400];
    struct call c;
    TEST("rvmachine_data_disk: a symlinked, hard-linked or FIFO data.img is refused as DATA_DISK_NOT_REGULAR") {
        ASSERT(test_mkdtemp(home, sizeof home, "data_disk") != NULL);
        snprintf(kernel, sizeof kernel, "%s/kernel.bin", home);
        ASSERT(copy_fixture(kernel));
        ASSERT(make_disk(home, "x") && make_disk(home, "o"));
        ASSERT(image_path(img, sizeof img, home, "x") && image_path(other, sizeof other, home, "o"));
        ASSERT(unlink(img) == 0 && symlink(other, img) == 0);
        ASSERT(every_path_refused(home, kernel, "DATA_DISK_NOT_REGULAR"));
        ASSERT(unlink(img) == 0 && mkfifo(img, 0600) == 0);
        ASSERT(every_path_refused(home, kernel, "DATA_DISK_NOT_REGULAR"));
        ASSERT(unlink(img) == 0 && link(other, img) == 0);
        ASSERT(every_path_refused(home, kernel, "DATA_DISK_NOT_REGULAR"));
        ASSERT(refused(home, "\"action\":\"grow\",\"name\":\"o\",\"size_mib\":64", "DATA_DISK_NOT_REGULAR"));
        ASSERT(unlink(img) == 0);
        ASSERT(refused(home, "\"action\":\"grow\",\"name\":\"x\",\"size_mib\":64", "DATA_DISK_ABSENT"));
        ASSERT(data_cmd(&c, home, "\"action\":\"grow\",\"name\":\"o\",\"size_mib\":64"));
        ASSERT(call_ok(&c));
        call_end(&c);
        PASS();
    } _test_next:;
    return failures;
}

static int t_status_state(void)
{
    int failures = 0;
    char home[200], img[400];
    struct call c;
    TEST("rvmachine_data_disk: status separates free, locked and unavailable; an unopenable disk is not reported locked") {
        struct zcl_command_reply reply;
        struct zcl_mb_data_file *held;
        ASSERT(test_mkdtemp(home, sizeof home, "data_disk") != NULL);
        ASSERT(make_disk(home, "x"));
        ASSERT(image_path(img, sizeof img, home, "x"));
        ASSERT(data_cmd(&c, home, "\"action\":\"status\",\"name\":\"x\""));
        ASSERT(call_ok(&c) && !call_flag(&c, "locked"));
        ASSERT_STR_EQ(call_str(&c, "state"), "free");
        call_end(&c);
        zcl_command_reply_init(&reply, "zcl.dev_machine_data.v1");
        held = zcl_mb_data_open(home, "x", &reply);
        zcl_command_reply_free(&reply);
        ASSERT(held != NULL);
        ASSERT(data_cmd(&c, home, "\"action\":\"status\",\"name\":\"x\""));
        ASSERT(call_ok(&c) && call_flag(&c, "locked"));
        ASSERT_STR_EQ(call_str(&c, "state"), "locked");
        call_end(&c);
        zcl_mb_data_close(held);
        if (geteuid() != 0) {
            ASSERT(chmod(img, 0) == 0);
            ASSERT(data_cmd(&c, home, "\"action\":\"status\",\"name\":\"x\""));
            ASSERT(call_ok(&c) && !call_flag(&c, "locked"));
            ASSERT_STR_EQ(call_str(&c, "state"), "unavailable");
            call_end(&c);
            ASSERT(refused(home, "\"action\":\"grow\",\"name\":\"x\",\"size_mib\":64",
                           "DATA_DISK_OPEN_FAILED"));
            ASSERT(chmod(img, 0600) == 0);
        }
        PASS();
    } _test_next:;
    return failures;
}

static int t_public_owner(void)
{
    int failures = 0;
    char home[200], kernel[300], args[900];
    struct call c;
    TEST("rvmachine_data_disk: data_disk with public_unlock is refused before the claim and a later data-disk boot still runs") {
        ASSERT(test_mkdtemp(home, sizeof home, "data_disk") != NULL);
        snprintf(kernel, sizeof kernel, "%s/kernel.bin", home);
        ASSERT(copy_fixture(kernel));
        ASSERT(make_disk(home, "x"));
        snprintf(args, sizeof args,
                 "{\"kernel\":\"%s\",\"max_instr\":1000000,\"data_disk\":\"x\",\"home\":\"%s\","
                 "\"public_unlock\":{}}", kernel, home);
        ASSERT(dispatch(&c, "dev.app.machine.boot", zcl_native_handle_dev_machine_boot, args));
        ASSERT(!call_ok(&c));
        ASSERT_STR_EQ(call_error(&c), "DATA_DISK_NOT_AVAILABLE");
        call_end(&c);
        snprintf(args, sizeof args,
                 "{\"kernel\":\"%s\",\"max_instr\":1000000,\"data_disk\":\"x\",\"home\":\"%s\"}",
                 kernel, home);
        ASSERT(dispatch(&c, "dev.app.machine.boot", zcl_native_handle_dev_machine_boot, args));
        ASSERT(call_ok(&c));
        call_end(&c);
        PASS();
    } _test_next:;
    return failures;
}

int test_rvmachine_data_disk(void);
int test_rvmachine_data_disk(void)
{
    return t_names() + t_commands() + t_bad_names() + t_lock() + t_slot_absent() +
           t_routing() + t_persistence() + t_errors() + t_boot() + t_levels() + t_z23_mode() + t_files() +
           t_status_state() + t_public_owner();
}
