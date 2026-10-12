/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: machine lifetime (RAM, disk, device tree placement), the console
 * sink and the console input offered to the firmware console and the serial
 * port. */
#include "rvmachine_priv.h"

#include "base/safe_alloc.h"
#include "base/cleanse.h"
#include "base/log_macros.h"

#include <string.h>

#define MIB2 (UINT64_C(2) << 20)

static bool ram_size_ok(uint64_t bytes)
{
    return bytes >= RVMACHINE_RAM_MIN && bytes <= RVMACHINE_RAM_MAX &&
           bytes % MIB2 == 0 && bytes <= SIZE_MAX;
}

static uint64_t config_ram_bytes(const struct rvmachine_config *c)
{
    return c->ram_bytes != 0 ? c->ram_bytes : RVMACHINE_RAM_DEFAULT;
}

static enum rvmachine_status config_ram_check(const struct rvmachine_config *c)
{
    if (ram_size_ok(config_ram_bytes(c))) return RVMACHINE_OK;
    LOG_WARN("rvmachine", "resource config refused: RAM size is outside bounds or alignment");
    return RVMACHINE_ERR_ARG;
}

static enum rvmachine_status config_bootargs_check(const struct rvmachine_config *c)
{
    if (c->bootargs == NULL || strlen(c->bootargs) < RVMACHINE_BOOTARGS_MAX)
        return RVMACHINE_OK;
    LOG_WARN("rvmachine", "resource config refused: boot arguments exceed the fixed bound");
    return RVMACHINE_ERR_ARG;
}

enum rvmachine_status rvmachine_config_resources_validate(
    const struct rvmachine_config *config)
{
    if (config == NULL) {
        LOG_WARN("rvmachine", "resource config refused: configuration is absent");
        return RVMACHINE_ERR_ARG;
    }
    enum rvmachine_status status = config_ram_check(config);
    return status == RVMACHINE_OK ? config_bootargs_check(config) : status;
}

/* RAM end minus 2 MiB, kept inside the first gigabyte of RAM. */
static uint64_t dtb_address(uint64_t ram_bytes)
{
    uint64_t window = ram_bytes < RVMACHINE_DTB_WINDOW ? ram_bytes
                                                       : RVMACHINE_DTB_WINDOW;
    return RVMACHINE_RAM_BASE + window - RVMACHINE_DTB_BELOW_END;
}

static enum rvmachine_status place_dtb(struct rvmachine *m)
{
    uint8_t *at;
    m->dtb_addr = dtb_address(m->ram_bytes);
    at = m->mem.bytes + (m->dtb_addr - RVMACHINE_RAM_BASE);
    return rvmachine_build_dtb(m->ram_bytes, m->bootargs, at, RVMACHINE_DTB_MAX,
                               &m->dtb_len);
}

static enum rvmachine_status machine_setup(struct rvmachine *m,
                                           const struct rvmachine_config *c)
{
    m->cleanse_on_destroy = c->cleanse_on_destroy;
    m->ram_bytes = config_ram_bytes(c);
    enum rvmachine_status resource_status = config_ram_check(c);
    if (resource_status != RVMACHINE_OK) return resource_status;
    if (!rvmachine_conport_configure(m, c)) return RVMACHINE_ERR_PORT;
    if (c->bootargs != NULL) {
        resource_status = config_bootargs_check(c);
        if (resource_status != RVMACHINE_OK) return resource_status;
        memcpy(m->bootargs, c->bootargs, strlen(c->bootargs) + 1u);
    }
    m->console = c->console;
    m->console_ctx = c->console_ctx;
    m->mem.base = RVMACHINE_RAM_BASE;
    m->mem.size = (size_t)m->ram_bytes;
    m->mem.bytes = zcl_calloc((size_t)m->ram_bytes, 1, "rvmachine_ram");
    if (m->mem.bytes == NULL) return RVMACHINE_ERR_NOMEM;
    m->disk = c->disk;
    m->data_disk = c->data_disk;
    m->entropy = c->entropy;
    m->entropy_ctx = c->entropy_ctx;
    m->entropy_fail_closed = c->entropy_fail_closed;
    m->wait_stops = c->wait_stops;
    m->boot_seed = c->boot_seed;
    m->boot_seed_ctx = c->boot_seed_ctx;
    if (!rvmachine_devices_init(m)) return RVMACHINE_ERR_DISK;
    return place_dtb(m);
}

enum rvmachine_status rvmachine_create(struct rvmachine **out,
                                       const struct rvmachine_config *config)
{
    struct rvmachine *m;
    enum rvmachine_status st;
    if (out == NULL) return RVMACHINE_ERR_ARG;
    *out = NULL;
    if (config == NULL) return RVMACHINE_ERR_ARG;
    m = zcl_calloc(1, sizeof *m, "rvmachine");
    if (m == NULL) return RVMACHINE_ERR_NOMEM;
    st = machine_setup(m, config);
    if (st != RVMACHINE_OK) {
        m->disk = NULL; /* still the caller's */
        m->data_disk = NULL;
        rvmachine_destroy(m);
        return st;
    }
    *out = m;
    return RVMACHINE_OK;
}

void rvmachine_destroy(struct rvmachine *m)
{
    if (m == NULL) return;
    uint8_t *ram = m->mem.bytes;
    size_t ram_size = m->mem.size;
    bool cleanse = m->cleanse_on_destroy;
    if (cleanse) {
        rvmachine_disk_cleanse(m->disk);
        rvmachine_disk_cleanse(m->data_disk);
        if (ram != NULL) memory_cleanse(ram, ram_size);
    }
    rvmachine_disk_close(m->disk);
    rvmachine_disk_close(m->data_disk);
    if (cleanse) memory_cleanse(m, sizeof *m);
    free(ram);
    free(m);
}

const uint8_t *rvmachine_dtb(const struct rvmachine *m, size_t *len)
{
    if (m == NULL || len == NULL) return NULL;
    *len = m->dtb_len;
    return m->mem.bytes + (m->dtb_addr - RVMACHINE_RAM_BASE);
}

void rvmachine_console_put(struct rvmachine *m, uint8_t byte)
{
    if (m->console != NULL) m->console(m->console_ctx, byte);
}

static int input_pop(struct rvmachine_input *q)
{
    uint8_t byte;
    if (q->count == 0) return -1;
    byte = q->bytes[q->head];
    q->head = (q->head + 1u) % RVMACHINE_INPUT_MAX;
    q->count--;
    return byte;
}

/* A full queue belongs to a reader that is not reading: drop its oldest byte. */
static void input_push(struct rvmachine_input *q, uint8_t byte)
{
    if (q->count == RVMACHINE_INPUT_MAX) (void)input_pop(q);
    q->bytes[(q->head + q->count) % RVMACHINE_INPUT_MAX] = byte;
    q->count++;
}

void rvmachine_input_pump(struct rvmachine *m, bool polled)
{
    if (!polled && (m->uart.ier & RVPLAT_UART_IER_RDA) == 0u) return;
    while (m->serial_in.count != 0 && m->uart.rx_count < RVPLAT_UART_FIFO_SIZE)
        rvplat_uart_rx(&m->uart, (uint8_t)input_pop(&m->serial_in));
}

size_t rvmachine_console_input(struct rvmachine *m, const uint8_t *bytes, size_t n)
{
    if (m == NULL || bytes == NULL) return 0;
    for (size_t i = 0; i < n; i++) {
        input_push(&m->firmware_in, bytes[i]);
        input_push(&m->serial_in, bytes[i]);
    }
    rvmachine_input_pump(m, false);
    rvmachine_irq_sync(m);
    /* Input the hart cannot be woken by leaves a waiting hart where it is, and
     * is no reason to run it. */
    rvmachine_wake_check(m);
    return n;
}

void rvmachine_entropy_ready(struct rvmachine *m)
{
    if (m == NULL || !m->entropy_dry) return;
    m->entropy_dry = false;
    rvmachine_wake_check(m); /* a request the source can serve again is work */
}

void rvmachine_request_stop(struct rvmachine *m)
{
    if (m != NULL) m->stop_requested = true;
}

void rvmachine_set_trace(struct rvmachine *m, uint64_t *ring, size_t cap)
{
    if (m == NULL) return;
    m->trace = cap != 0 ? ring : NULL;
    m->trace_cap = ring != NULL ? cap : 0;
    m->trace_count = 0;
}

uint64_t rvmachine_retired(const struct rvmachine *m)
{
    return machine_retired(m);
}

uint64_t rvmachine_time(const struct rvmachine *m)
{
    return machine_now(m);
}

const char *rvmachine_stop_name(enum rvmachine_stop stop)
{
    switch (stop) {
    case RVMACHINE_STOP_BUDGET: return "budget";
    case RVMACHINE_STOP_SHUTDOWN: return "shutdown";
    case RVMACHINE_STOP_REBOOT: return "reboot";
    case RVMACHINE_STOP_IDLE: return "idle";
    case RVMACHINE_STOP_FAULT: return "fault";
    case RVMACHINE_STOP_REQUESTED: return "requested";
    case RVMACHINE_STOP_WAIT: return "wait";
    }
    return "unknown";
}

const char *rvmachine_status_name(enum rvmachine_status status)
{
    static const char *const names[] = {
        [RVMACHINE_OK] = "ok",
        [RVMACHINE_ERR_ARG] = "bad argument",
        [RVMACHINE_ERR_NOMEM] = "out of memory",
        [RVMACHINE_ERR_IMAGE] = "not a loadable kernel image",
        [RVMACHINE_ERR_IMAGE_RANGE] = "kernel image does not fit",
        [RVMACHINE_ERR_FDT] = "device tree build failed",
        [RVMACHINE_ERR_DISK] = "disk image cannot be used",
        [RVMACHINE_ERR_STATE] = "machine is not runnable",
        [RVMACHINE_ERR_TIME_BACKWARDS] = "guest time cannot move backwards",
        [RVMACHINE_ERR_TIME_PAST_DEADLINE] = "guest time cannot pass the armed timer",
        [RVMACHINE_ERR_WAITING] = "the hart waits and nothing can wake it yet",
        [RVMACHINE_ERR_ENTRY] = "the kernel image has no loader entry to take a boot seed",
        [RVMACHINE_ERR_SEED_ABSENT] = "the boot seed source gave no bytes",
        [RVMACHINE_ERR_SEED_SHORT] = "the boot seed source gave too few bytes",
        [RVMACHINE_ERR_SEED_SOURCE] = "the boot seed source failed",
        [RVMACHINE_ERR_PORT] = "byte port configuration or sink refused",
        [RVMACHINE_ERR_ENTROPY] = "fail-closed entropy source refused",
    };
    static_assert(sizeof names / sizeof names[0] == RVMACHINE_ERR_ENTROPY + 1u,
                  "one name per status");
    size_t i = (size_t)status;
    if (i >= sizeof names / sizeof names[0] || names[i] == NULL) return "unknown";
    return names[i];
}

/* Firmware getchar: the next byte offered to the firmware console, or -1. */
int rvmachine_sbi_getchar(void *ctx)
{
    struct rvmachine *m = ctx;
    return input_pop(&m->firmware_in);
}
