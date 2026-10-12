/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: minimal FreeBSD riscv64 program entry for the rvuser fixtures.
 * On entry a0 points at argc (FreeBSD lib/csu/riscv/crt1_s.S); argv follows. */
    .text
    .globl _start
_start:
    mv      a2, a0
    ld      a0, 0(a2)
    addi    a1, a2, 8
    call    main
    li      t0, 1           /* SYS_exit, number in t0 (FreeBSD riscv) */
    ecall
    ebreak                  /* exit never returns */
