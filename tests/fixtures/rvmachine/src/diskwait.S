# Waits in wfi for either the block device interrupt or a far timer deadline
# and reports which one ended the wait. Interrupts stay disabled in sstatus,
# so the wfi simply resumes when an enabled interrupt becomes pending.
    .option norvc
    .text
    .globl _start
_start:
    # PLIC: source 1 priority 1, enabled for the supervisor context, threshold 0
    li    t0, 0x0C000000
    li    t1, 1
    sw    t1, 4(t0)
    li    t0, 0x0C002080
    li    t1, 2
    sw    t1, 0(t0)
    li    t0, 0x0C201000
    sw    zero, 0(t0)
    # enable the external and timer interrupts, arm the timer far ahead
    li    t0, 0x220
    csrw  sie, t0
    rdtime a0
    li    t0, 1000000
    add   a0, a0, t0
    li    a6, 0
    li    a7, 0x54494D45
    ecall
    wfi
    csrr  s2, sip
    andi  t0, s2, 0x200
    lla   s1, msg_timer
    beqz  t0, 1f
    lla   s1, msg_disk
1:  jal   puts
    j     shutdown

    .include "common.inc"

msg_disk:  .asciz "diskwait: woke on the disk interrupt\n"
msg_timer: .asciz "diskwait: woke on the timer\n"
