# Four timed sleeps with a serial echo. Prints "tick N", arms the timer
# N * 1000 time units ahead and waits in wfi until the timer interrupt, four
# times, then powers off. A byte arriving on the serial port interrupts
# whatever is running, is echoed through the firmware console, and the wait
# resumes on the same deadline.
    .option norvc
    .text
    .globl _start
_start:
    lla   t0, trap
    csrw  stvec, t0
    # PLIC: source 10 (serial port) priority 1, enabled for the supervisor
    # context, threshold 0
    li    t0, 0x0C000000
    li    t1, 1
    sw    t1, 40(t0)
    li    t0, 0x0C002080
    li    t1, 0x400
    sw    t1, 0(t0)
    li    t0, 0x0C201000
    sw    zero, 0(t0)
    # serial port: receive interrupt on
    li    t0, 0x10000000
    li    t1, 1
    sb    t1, 1(t0)
    # timer and external interrupts, taken as traps
    li    t0, 0x220
    csrw  sie, t0
    csrsi sstatus, 2
    li    s4, 1
1:  lla   s1, msg_tick
    jal   puts
    addi  a0, s4, '0'
    li    a7, 1
    ecall
    li    a0, '\n'
    li    a7, 1
    ecall
    lla   t0, fired
    sd    zero, 0(t0)
    rdtime a0
    li    t0, 1000
    mul   t0, t0, s4
    add   a0, a0, t0
    li    a6, 0
    li    a7, 0x54494D45
    ecall
2:  wfi
    lla   t0, fired
    ld    t1, 0(t0)
    beqz  t1, 2b
    addi  s4, s4, 1
    li    t0, 5
    bne   s4, t0, 1b
    lla   s1, msg_done
    jal   puts
    j     shutdown

    .include "common.inc"

# Interrupts arrive anywhere in the code above, so every register the handler
# uses is saved and restored.
    .balign 4
trap:
    csrw  sscratch, t0
    lla   t0, save
    sd    t1, 0(t0)
    sd    t2, 8(t0)
    sd    a0, 16(t0)
    sd    a1, 24(t0)
    sd    a6, 32(t0)
    sd    a7, 40(t0)
    csrr  t1, scause
    slli  t1, t1, 1
    srli  t1, t1, 1
    li    t2, 5
    bne   t1, t2, 3f
    # timer: disarm and record
    li    a0, -1
    li    a6, 0
    li    a7, 0x54494D45
    ecall
    lla   t1, fired
    li    t2, 1
    sd    t2, 0(t1)
    j     6f
3:  # external: claim, echo every received byte, complete
    li    t2, 0x0C201004
    lw    t1, 0(t2)
4:  li    t2, 0x10000000
    lbu   a0, 5(t2)
    andi  a0, a0, 1
    beqz  a0, 5f
    lbu   a0, 0(t2)
    li    a7, 1
    ecall
    j     4b
5:  li    t2, 0x0C201004
    sw    t1, 0(t2)
6:  ld    t1, 0(t0)
    ld    t2, 8(t0)
    ld    a0, 16(t0)
    ld    a1, 24(t0)
    ld    a6, 32(t0)
    ld    a7, 40(t0)
    csrr  t0, sscratch
    sret

msg_tick: .asciz "tick "
msg_done: .asciz "ticker: done\n"

    .data
    .balign 8
fired:  .quad 0
save:   .zero 48
