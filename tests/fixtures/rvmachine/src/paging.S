# Turns Sv39 on the way a kernel does: the root table maps only the high
# virtual address of the image, stvec holds the virtual address of the next
# instruction, and writing satp makes the following fetch at the physical pc
# fault into stvec. Prints what it finds and powers off.
    .option norvc
    .text
    .globl _start
_start:
    # root entry 256 (0xffffffc000000000): a 1 GiB leaf at 0x80000000, RWX A D
    lla   t0, root
    li    t1, (0x80000 << 10) | 0xcf
    li    t2, 256 * 8
    add   t2, t0, t2
    sd    t1, 0(t2)
    lla   t3, high
    li    t4, 0xffffffc000000000 - 0x80000000
    add   t3, t3, t4
    csrw  stvec, t3
    srli  t0, t0, 12
    li    t1, 8 << 60
    or    t0, t0, t1
    sfence.vma
    csrw  satp, t0

    .balign 4
high:
    csrr  s2, scause
    lla   s1, msg_on
    jal   puts
    li    t0, 12
    lla   s1, msg_cause_bad
    bne   s2, t0, 1f
    lla   s1, msg_cause
1:  jal   puts
    auipc t0, 0
    srli  t0, t0, 38
    li    t1, 0x3ffffff
    lla   s1, msg_pc_bad
    bne   t0, t1, 2f
    lla   s1, msg_pc
2:  jal   puts
    lla   t0, magic
    ld    t0, 0(t0)
    li    t1, 0x7a32336d61636800
    lla   s1, msg_data_bad
    bne   t0, t1, 3f
    lla   s1, msg_data
3:  jal   puts
    j     shutdown

    .include "common.inc"

    .balign 8
magic:  .quad 0x7a32336d61636800
msg_on:        .asciz "paging: running after the satp write\n"
msg_cause:     .asciz "paging: entered through an instruction page fault\n"
msg_cause_bad: .asciz "paging: WRONG trap cause\n"
msg_pc:        .asciz "paging: pc is in the high half\n"
msg_pc_bad:    .asciz "paging: pc is NOT in the high half\n"
msg_data:      .asciz "paging: data reads through the mapping\n"
msg_data_bad:  .asciz "paging: data read WRONG\n"

    .balign 4096
root:   .fill 512, 8, 0
