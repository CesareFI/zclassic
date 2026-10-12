/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: static-PIE program entry for the rvuser fixtures. The loader applies no relocations
 * (as the FreeBSD kernel does not for a static PIE): this code self-relocates. It takes the load
 * base from __ehdr_start (the image is linked at 0, so its run-time address is the base), finds
 * DT_RELA/DT_RELASZ in _DYNAMIC and applies every R_RISCV_RELATIVE (type 3): *(base + r_offset)
 * = base + r_addend. Any other relocation type, or a DT_RELAENT other than 24, is an ebreak
 * (fail closed). Only then does it do what crt0.S does. Uses no stack and no C code. */
    .text
    .globl _start
_start:
    mv      s0, a0              /* initial stack: argc */
    lla     t0, __ehdr_start    /* load base (link address 0) */
    lla     t1, _DYNAMIC
    li      t2, 0               /* RELA table, once found */
    li      t3, 0               /* RELA bytes */
1:  ld      a3, 0(t1)           /* d_tag */
    ld      a4, 8(t1)           /* d_val / d_ptr */
    beqz    a3, 5f              /* DT_NULL */
    li      a5, 7               /* DT_RELA */
    bne     a3, a5, 2f
    add     t2, a4, t0
2:  li      a5, 8               /* DT_RELASZ */
    bne     a3, a5, 3f
    mv      t3, a4
3:  li      a5, 9               /* DT_RELAENT */
    bne     a3, a5, 4f
    li      a5, 24
    bne     a4, a5, 9f
4:  addi    t1, t1, 16
    j       1b
5:  beqz    t3, 8f
    ld      a3, 0(t2)           /* r_offset */
    ld      a4, 8(t2)           /* r_info */
    ld      a5, 16(t2)          /* r_addend */
    li      a6, 3               /* R_RISCV_RELATIVE */
    bne     a4, a6, 9f
    add     a3, a3, t0
    add     a5, a5, t0
    sd      a5, 0(a3)
    addi    t2, t2, 24
    addi    t3, t3, -24
    j       5b
8:  mv      a2, s0
    ld      a0, 0(a2)
    addi    a1, a2, 8
    call    main
    li      t0, 1               /* SYS_exit */
    ecall
9:  ebreak
