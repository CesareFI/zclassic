/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: standalone package smoke test for the built-in RISC-V machine: a
 * five-instruction supervisor guest prints one byte through the firmware
 * console and powers off, with a small disk attached. The full proofs live in
 * tests/harness/src/test_rvmachine.c. */
#include "rvmachine/rvmachine.h"

#include <string.h>

static const uint8_t guest[] = {
    0x93, 0x08, 0x10, 0x00, /* li a7, 1    firmware console putchar */
    0x13, 0x05, 0xa0, 0x07, /* li a0, 'z' */
    0x73, 0x00, 0x00, 0x00, /* ecall */
    0x93, 0x08, 0x80, 0x00, /* li a7, 8    firmware shutdown */
    0x73, 0x00, 0x00, 0x00, /* ecall */
};

static char printed[8];
static size_t printed_len;

static void sink(void *ctx, uint8_t byte)
{
    (void)ctx;
    if (printed_len < sizeof printed) printed[printed_len++] = (char)byte;
}

static bool image_read(void *ctx, uint64_t off, void *buf, size_t n)
{
    (void)ctx;
    memset(buf, (int)(off & 0xffu), n);
    return true;
}

int main(void)
{
    struct rvmachine_config config = {.ram_bytes = RVMACHINE_RAM_MIN, .console = sink};
    struct rvmachine *m = NULL;
    struct rvmachine_result res;
    uint8_t byte = 0;
    if (rvmachine_disk_open(&config.disk, 8192, image_read, NULL) != RVMACHINE_OK) return 1;
    if (rvmachine_create(&m, &config) != RVMACHINE_OK) return 2;
    if (rvmachine_load_kernel(m, guest, sizeof guest) != RVMACHINE_OK) return 3;
    if (rvmachine_run(m, 1000, &res) != RVMACHINE_OK) return 4;
    if (res.stop != RVMACHINE_STOP_SHUTDOWN) return 5;
    if (res.retired != 3 || res.fw_calls != 2 || res.skip != 0) return 6;
    if (printed_len != 1 || printed[0] != 'z') return 7;
    if (!rvmachine_disk_write(m->disk, 4096, "w", 1)) return 8;
    if (!rvmachine_disk_read(m->disk, 4096, &byte, 1) || byte != 'w') return 9;
    if (rvmachine_disk_overlay_blocks(m->disk) != 1) return 10;
    rvmachine_destroy(m);
    return 0;
}
