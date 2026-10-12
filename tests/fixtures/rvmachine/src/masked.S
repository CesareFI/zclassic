# Serial input against each gate between the port and the hart. The embedder
# chooses the gates through registers before the guest runs:
#   s3  the hart's interrupt enables (sie)
#   s4  the serial port's interrupt enable register (1 = receive interrupt)
#   s5  the interrupt controller's enable word for the supervisor context
#       (0x400 = the serial port's source)
#   s2  nonzero: the timer is armed s2 time units ahead before the first wfi
# Interrupts stay globally off, so nothing traps and a wfi simply ends. After
# the first wfi the guest disarms the timer, opens every gate, waits once
# more, echoes what the port holds and powers off.
    .option norvc
    .text
    .globl _start
_start:
    # PLIC: source 10 (serial port) priority 1, threshold 0, enables from s5
    li    t0, 0x0C000000
    li    t1, 1
    sw    t1, 40(t0)
    li    t0, 0x0C002080
    sw    s5, 0(t0)
    li    t0, 0x0C201000
    sw    zero, 0(t0)
    li    t0, 0x10000000
    sb    s4, 1(t0)
    csrw  sie, s3
    lla   s1, msg_asleep
    jal   puts
    beqz  s2, 1f
    rdtime a0
    add   a0, a0, s2
    li    a6, 0
    li    a7, 0x54494D45
    ecall
1:  wfi
    lla   s1, msg_awake
    jal   puts
    li    a0, -1
    li    a6, 0
    li    a7, 0x54494D45
    ecall
    # every gate open: receive interrupt, source enabled, external interrupt
    li    t0, 0x10000000
    li    t1, 1
    sb    t1, 1(t0)
    li    t0, 0x0C002080
    li    t1, 0x400
    sw    t1, 0(t0)
    li    t0, 0x200
    csrs  sie, t0
    wfi
2:  li    t2, 0x10000000
    lbu   a0, 5(t2)
    andi  a0, a0, 1
    beqz  a0, 3f
    lbu   a0, 0(t2)
    li    a7, 1
    ecall
    j     2b
3:  j     shutdown

    .include "common.inc"

msg_asleep: .asciz "masked: asleep\n"
msg_awake:  .asciz "masked: awake\n"
