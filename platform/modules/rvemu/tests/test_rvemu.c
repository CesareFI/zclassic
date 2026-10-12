/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: package-local proof that the hart retires base-ISA instructions
 * and stops on ecall. The official riscv-tests live in the repository suite. */
#include "base/serialize_le.h"
#include "rvemu/rvemu.h"

#include <stdint.h>
#include <string.h>

int main(void)
{
    static uint8_t ram[64];
    /* addi x1,x0,5 ; addi x2,x1,7 ; ecall */
    static const uint32_t prog[] = {0x00500093u, 0x00708113u, 0x00000073u};
    for (size_t i = 0; i < 3; i++) {
        zcl_write_u32_le(&ram[i * 4], prog[i]);
    }
    struct rvemu_mem mem = {.base = 0x80000000ull, .size = sizeof(ram), .bytes = ram};
    struct rvemu_hart hart;
    enum rvemu_stop stop = RVEMU_STOP_NONE;
    rvemu_hart_init(&hart, mem.base);
    if (rvemu_run(&hart, &mem, 16, &stop) != 0)
        return 1;
    if (stop != RVEMU_STOP_ECALL || hart.x[1] != 5 || hart.x[2] != 12 ||
        hart.instret != 2)
        return 2;
    return 0;
}
