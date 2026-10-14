/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
/* Purpose: bounded freestanding supervisor entry, header checks and trap proof. */
#include <stdint.h>
#include <stddef.h>
static volatile unsigned long illegal_count, timer_count;
extern const unsigned char illegal_probe[], illegal_resume[], trap_entry[];
void kernel_main(unsigned long hart, unsigned long tree);
void kernel_trap(void);
static long sbi(unsigned long extension, unsigned long argument)
{
    register unsigned long a0 __asm__("a0") = argument;
    register unsigned long a1 __asm__("a1") = 0;
    register unsigned long a6 __asm__("a6") = 0;
    register unsigned long a7 __asm__("a7") = extension;
    __asm__ volatile("ecall" : "+r"(a0), "+r"(a1) : "r"(a6), "r"(a7) : "memory");
    return (long)a0;
}
static void text(const char *s)
{
    while (*s) (void)sbi(1, (unsigned char)*s++);
}
[[noreturn]] static void stop(unsigned long reason)
{
    register unsigned long a0 __asm__("a0") = 0;
    register unsigned long a1 __asm__("a1") = reason;
    register unsigned long a6 __asm__("a6") = 0;
    register unsigned long a7 __asm__("a7") = 0x53525354;
    __asm__ volatile("ecall" : "+r"(a0), "+r"(a1) : "r"(a6), "r"(a7) : "memory");
    for (;;) __asm__ volatile("wfi");
}
[[noreturn]] static void fail(void)
{
    __asm__ volatile("csrci sstatus, 2");
    text("FAIL\n");
    stop(1);
}
static uint32_t big32(const unsigned char *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | p[3];
}
static int tree_valid(unsigned long address)
{
    const unsigned long begin = 0x80000000UL;
    const unsigned long end = 0x84000000UL;
    if ((address & 7UL) || address < begin || address > end - 40) return 0;
    const unsigned char *p = (const unsigned char *)(uintptr_t)address;
    if (big32(p) != 0xd00dfeedU) return 0;
    uint32_t size = big32(p + 4);
    return size >= 40 && size <= 65536 && size <= end - address;
}
void kernel_trap(void)
{
    unsigned long cause, pc;
    __asm__ volatile("csrr %0, scause" : "=r"(cause));
    __asm__ volatile("csrr %0, sepc" : "=r"(pc));
    if (cause == 2 && pc == (unsigned long)(uintptr_t)illegal_probe &&
        illegal_count == 0 && (unsigned long)(uintptr_t)illegal_resume == pc + 4) {
        illegal_count = 1;
        pc += 4;
        __asm__ volatile("csrw sepc, %0" : : "r"(pc) : "memory");
        return;
    }
    if (cause == (0x8000000000000000UL | 5UL) && timer_count == 0) {
        if (sbi(0x54494d45, UINT64_MAX) != 0) fail();
        timer_count = 1;
        return;
    }
    fail();
}
void kernel_main(unsigned long hart, unsigned long tree)
{
    __asm__ volatile("csrci sstatus, 2; csrw sie, zero");
    unsigned long vector = (unsigned long)(uintptr_t)trap_entry;
    if ((vector & 3UL) || hart != 0 || illegal_count || timer_count || !tree_valid(tree))
        fail();
    __asm__ volatile("csrw stvec, %0" : : "r"(vector) : "memory");
    __asm__ volatile(".globl illegal_probe\nillegal_probe:\n.4byte 0x0000000b\n"
                     ".globl illegal_resume\nillegal_resume:" : : : "memory");
    if (illegal_count != 1 || timer_count != 0) fail();
    unsigned long now;
    __asm__ volatile("csrr %0, time" : "=r"(now));
    if (now > UINT64_MAX - 100 || sbi(0x54494d45, now + 100) != 0) fail();
    __asm__ volatile("csrs sie, %0; csrsi sstatus, 2" : : "r"(32UL) : "memory");
    for (unsigned i = 0; i < 10000 && timer_count == 0; ++i) __asm__ volatile("nop" : : : "memory");
    for (unsigned i = 0; i < 1000; ++i) __asm__ volatile("nop" : : : "memory");
    if (timer_count != 1 || illegal_count != 1) fail();
    text("Z23KERNEL v1\nfdt_header=ok\nillegal=1\ntimer=1\nshutdown\n");
    stop(0);
}
