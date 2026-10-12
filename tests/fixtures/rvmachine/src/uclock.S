# Drops to user mode and reads the time CSR there, as a C library's clock
# does. The firmware leaves the counters readable from user mode, so the read
# succeeds and the following ecall reaches the supervisor handler with cause 8.
# If the read traps instead, the handler reports its cause.
    .option norvc
    .text
    .globl _start
_start:
    lla   t0, trap
    csrw  stvec, t0
    lla   t0, user
    csrw  sepc, t0
    li    t0, 0x100
    csrc  sstatus, t0
    sret

user:
    rdtime a0
    ecall
1:  j     1b

    .balign 4
trap:
    csrr  s2, scause
    li    t0, 8
    bne   s2, t0, 1f
    lla   s1, msg_ok
    jal   puts
    j     shutdown
1:  lla   s1, msg_trap
    jal   puts
    addi  a0, s2, '0'
    li    a7, 1
    ecall
    li    a0, '\n'
    li    a7, 1
    ecall
    j     shutdown

    .include "common.inc"

msg_ok:   .asciz "uclock: user mode read the time\n"
msg_trap: .asciz "uclock: the user clock read trapped, cause "
