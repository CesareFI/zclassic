/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
/* Purpose: isolated acceptance for the exact freestanding kernel image. */
#include "test/test_core.h"
#include "base/hex.h"
#include "crypto/sha256.h"
#include "rvmachine/rvmachine.h"
#include <limits.h>
#include <stdio.h>
#include <string.h>

#define KERNEL_CAP 65536u
#define KERNEL_WORK UINT64_C(1000000)
static uint8_t kernel[KERNEL_CAP];
static size_t kernel_size;
static unsigned long long probe_offset, resume_offset, image_end;
static const char expected[] =
    "Z23KERNEL v1\nfdt_header=ok\nillegal=1\ntimer=1\nshutdown\n";
struct kernel_run {
    char text[128];
    size_t count;
    bool overflow;
    struct rvmachine_result result;
    uint64_t timer;
};
static void kernel_console(void *ctx, uint8_t byte)
{
    struct kernel_run *run = ctx;
    if (run->count < sizeof run->text) run->text[run->count++] = (char)byte;
    else run->overflow = true;
}
static bool kernel_offsets_valid(unsigned long long probe, unsigned long long resume,
                                 unsigned long long end)
{
    bool ok = kernel_size >= 4 && probe <= kernel_size - 4 &&
        resume <= kernel_size - 4 && resume == probe + 4 &&
        end >= kernel_size && end < (UINT64_C(1) << 20);
    if (!ok) fprintf(stderr, "z23kernel: identity offset bounds refused\n");
    return ok;
}
static bool kernel_load(void)
{
    FILE *file = fopen("build/bin/z23kernel.bin", "rb");
    if (!file) { fprintf(stderr, "z23kernel: image unavailable\n"); return false; }
    kernel_size = fread(kernel, 1, sizeof kernel, file);
    bool ok = kernel_size >= 4 && kernel_size < sizeof kernel && !ferror(file);
    ok = fclose(file) == 0 && ok;
    file = fopen("build/bin/z23kernel.identity", "rb");
    char hash[65], extra; uint8_t want[32], actual[32];
    if (!file) { fprintf(stderr, "z23kernel: identity unavailable\n"); return false; }
    ok = fscanf(file, "%64s %llx %llx %llx", hash, &probe_offset,
                &resume_offset, &image_end) == 4 && ok;
    ok = fscanf(file, " %c", &extra) == EOF && !ferror(file) && ok;
    ok = fclose(file) == 0 && ok;
    struct sha256_ctx sha;
    sha256_init(&sha); sha256_write(&sha, kernel, kernel_size); sha256_finalize(&sha, actual);
    ok = ok && zcl_hex_decode(hash, want, sizeof want) &&
         memcmp(want, actual, sizeof want) == 0 &&
         kernel_offsets_valid(probe_offset, resume_offset, image_end);
    if (!ok) fprintf(stderr, "z23kernel: bounded image identity refused\n");
    return ok;
}
enum kernel_case { K_VALID, K_MAGIC, K_SMALL, K_LARGE, K_ALIGN, K_RANGE, K_TRAP, K_REPEAT };
static void kernel_corrupt(struct rvmachine *machine, enum kernel_case kind)
{
    uint8_t *header = machine->mem.bytes + (machine->dtb_addr - RVMACHINE_RAM_BASE);
    if (kind == K_MAGIC) header[0] ^= 1;
    if (kind == K_SMALL) memset(header + 4, 0, 4);
    if (kind == K_LARGE) memset(header + 4, 255, 4);
    if (kind == K_ALIGN) machine->hart.x[11]++;
    if (kind == K_RANGE) machine->hart.x[11] = UINT64_C(0x84000000) - 8;
    if (kind == K_TRAP || kind == K_REPEAT) {
        uint64_t offset = kind == K_TRAP ? probe_offset : resume_offset;
        uint8_t *instruction = machine->mem.bytes + RVMACHINE_KERNEL_BASE -
                               RVMACHINE_RAM_BASE + offset;
        static const uint8_t fault[4] = {0x73, 0, 0x10, 0};
        if (kind == K_REPEAT) { instruction[0] = 0x0b; memset(instruction + 1, 0, 3); return; }
        memcpy(instruction, fault, sizeof fault); /* ebreak: scause 3 */
    }
}
static bool kernel_execute(struct kernel_run *run, enum kernel_case kind, uint64_t work)
{
    memset(run, 0, sizeof *run);
    struct rvmachine_config config = {
        .ram_bytes = RVMACHINE_RAM_MIN, .console = kernel_console, .console_ctx = run
    };
    struct rvmachine *machine = NULL;
    bool ok = rvmachine_create(&machine, &config) == RVMACHINE_OK;
    if (ok) ok = rvmachine_load_kernel(machine, kernel, kernel_size) == RVMACHINE_OK;
    if (ok) {
        kernel_corrupt(machine, kind);
        ok = rvmachine_run(machine, work, &run->result) == RVMACHINE_OK;
        run->timer = machine->timer.deadline;
    }
    rvmachine_destroy(machine);
    if (!ok) fprintf(stderr, "z23kernel: isolated machine failed case=%d\n", kind);
    return ok && !run->overflow;
}
static bool kernel_refused(enum kernel_case kind)
{
    struct kernel_run run;
    bool ok = kernel_execute(&run, kind, KERNEL_WORK) &&
        run.result.stop == RVMACHINE_STOP_SHUTDOWN && run.result.reset_reason == 1 &&
        run.count == 5 && memcmp(run.text, "FAIL\n", 5) == 0;
    if (!ok) fprintf(stderr, "z23kernel: refusal witness failed case=%d\n", kind);
    return ok;
}
int test_z23kernel_boot(void);
int test_z23kernel_boot(void)
{
    int failures = 0;
    TEST("C23 kernel: exact image repeats trap, timer and shutdown on fresh machines") {
        struct kernel_run a, b;
        ASSERT(kernel_load());
        ASSERT(kernel_execute(&a, K_VALID, KERNEL_WORK));
        ASSERT(kernel_execute(&b, K_VALID, KERNEL_WORK));
        ASSERT_EQ(a.result.stop, RVMACHINE_STOP_SHUTDOWN);
        ASSERT_EQ(b.result.stop, RVMACHINE_STOP_SHUTDOWN);
        ASSERT_EQ(a.result.reset_type, 0); ASSERT_EQ(a.result.reset_reason, 0);
        ASSERT_EQ(b.result.reset_type, 0); ASSERT_EQ(b.result.reset_reason, 0);
        ASSERT_EQ(a.count, sizeof expected - 1); ASSERT_EQ(b.count, a.count);
        ASSERT(memcmp(a.text, expected, a.count) == 0);
        ASSERT(memcmp(a.text, b.text, a.count) == 0);
        ASSERT_EQ(a.timer, UINT64_MAX); ASSERT_EQ(b.timer, UINT64_MAX);
        ASSERT_EQ(a.result.retired, b.result.retired);
        ASSERT_EQ(a.result.fw_calls, b.result.fw_calls);
        ASSERT_EQ(a.result.device_work, 0); ASSERT_EQ(b.result.device_work, 0);
        ASSERT(a.result.retired + a.result.fw_calls <= KERNEL_WORK);
        PASS();
    }
    TEST("C23 kernel: malformed identity offsets refuse before mutation") {
        ASSERT(kernel_load());
        ASSERT(!kernel_offsets_valid(ULLONG_MAX - 3, 0, image_end));
        ASSERT(!kernel_offsets_valid(kernel_size - 4, kernel_size, image_end));
        ASSERT(!kernel_offsets_valid(probe_offset, resume_offset, 0));
        PASS();
    }
    TEST("C23 kernel: invalid FDT headers and unexpected traps refuse") {
        ASSERT(kernel_load());
        for (enum kernel_case kind = K_MAGIC; kind <= K_REPEAT; kind++)
            ASSERT(kernel_refused(kind));
        PASS();
    }
    TEST("C23 kernel: insufficient work cannot report shutdown acceptance") {
        struct kernel_run run;
        ASSERT(kernel_load());
        ASSERT(kernel_execute(&run, K_VALID, 100));
        ASSERT(run.result.stop != RVMACHINE_STOP_SHUTDOWN);
        ASSERT(run.count == 0);
        ASSERT(run.result.retired + run.result.fw_calls <= 100);
        PASS();
    }
_test_next:;
    return failures;
}
