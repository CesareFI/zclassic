# Bounded binary echo through named virtio-console port0, with interrupts masked.
# The first two input bytes are the little-endian total stream length (2..32768).
# Every received byte, including that header, is echoed; the RX head is reposted
# after each TX completion so the host observes driver consumption.
    .option norvc
    .text
    .globl _start
_start:
    li s2, 0x10003000
    lw t0, 8(s2)
    li t1, 3
    bne t0, t1, bad
    sw zero, 0x70(s2)
    li t0, 3
    sw t0, 0x70(s2)
    li t0, 1
    sw t0, 0x24(s2)
    sw t0, 0x20(s2)
    sw zero, 0x24(s2)
    li t0, 2                    # MULTIPORT
    sw t0, 0x20(s2)
    li t0, 11
    sw t0, 0x70(s2)
    li s3, 0                    # initialize queues0..3
1:  sw s3, 0x30(s2)
    li t0, 16
    sw t0, 0x38(s2)
    slli t0, s3, 16
    li t1, 0x82000000
    add t0, t0, t1
    sw t0, 0x80(s2)
    sw zero, 0x84(s2)
    li t1, 0x1000
    add t0, t0, t1
    sd zero, 0(t0)             # fresh available ring header
    sw t0, 0x90(s2)
    sw zero, 0x94(s2)
    add t0, t0, t1
    sd zero, 0(t0)             # fresh used ring header after reset
    sw t0, 0xa0(s2)
    sw zero, 0xa4(s2)
    li t0, 1
    sw t0, 0x44(s2)
    addi s3, s3, 1
    li t0, 4
    blt s3, t0, 1b
    li t0, 15
    sw t0, 0x70(s2)
    # controlTX descriptor0 references one control message
    li t0, 0x82030000
    li t1, 0x82033000
    sd t1, 0(t0)
    li t2, 8
    sw t2, 8(t0)
    sh zero, 12(t0)
    sh zero, 14(t0)
    sw zero, 0(t1)             # id0
    sh zero, 4(t1)             # DEVICE_READY
    li t2, 1
    sh t2, 6(t1)
    li s4, 0                  # control avail count
    jal ctl
    li t0, 0x82033000
    li t1, 3                  # PORT_READY
    sh t1, 4(t0)
    jal ctl
    li t0, 0x82033000
    li t1, 6                  # PORT_OPEN
    sh t1, 4(t0)
    jal ctl
    # RX0 and TX1 share payload, but have separate rings/descriptors.
    li s6, 0x82100000
    li t0, 0x82000000
    sd s6, 0(t0)
    li t1, 4096
    sw t1, 8(t0)
    li t1, 2
    sh t1, 12(t0)
    li t0, 0x82010000
    sd s6, 0(t0)
    sh zero, 12(t0)
    li s7, 0                  # RX completed chunks
    li s8, 0                  # TX completed chunks
    li s9, 0                  # echoed bytes
    li s10, 0                 # total from header
    jal rx_post
    lla t0, reset_mode
    lbu t1, 0(t0)
    li t2, 2
    beq t1, t2, next           # reopened epoch deliberately has no readiness
    lla s1, mentioned
    jal puts
    lla s1, ready
    jal puts
    lla t0, reset_mode
    lbu t1, 0(t0)
    li t2, 1
    bne t1, t2, next
    li t1, 2
    sb t1, 0(t0)
    j _start                  # marker followed by reset/reopen without fresh marker
next:
    li t0, 0x82002000
2:  lhu t1, 2(t0)
    beq t1, s7, 2b
    andi t1, s7, 15
    slli t1, t1, 3
    add t0, t0, t1
    lw s11, 8(t0)             # RX used length
    beqz s11, bad
    bnez s9, send
    li t0, 2
    blt s11, t0, bad
    lhu s10, 0(s6)
    blt s10, t0, bad
    li t0, 32768
    blt t0, s10, bad
    lla t0, reset_mode
    lbu t1, 0(t0)
    li t2, 3
    bne t1, t2, send
    li t1, 2
    sb t1, 0(t0)
    j _start                  # reset after actual RX; never emit an old reply
send:
    add s9, s9, s11
    blt s10, s9, bad
    li t0, 0x82010000
    sw s11, 8(t0)
    li t0, 0x82011000
    andi t1, s8, 15
    slli t1, t1, 1
    add t1, t0, t1
    sh zero, 4(t1)
    addi s8, s8, 1
    sh s8, 2(t0)
    li t0, 1
    sw t0, 0x50(s2)
    li t0, 0x82012000
3:  lhu t1, 2(t0)
    bne t1, s8, 3b
    addi s7, s7, 1
    jal rx_post
    blt s9, s10, next
    lla s1, done
    jal puts
    j shutdown
ctl:
    li t0, 0x82031000
    andi t1, s4, 15
    slli t1, t1, 1
    add t1, t0, t1
    sh zero, 4(t1)
    addi s4, s4, 1
    sh s4, 2(t0)
    li t0, 3
    sw t0, 0x50(s2)
    ret
rx_post:
    li t0, 0x82001000
    andi t1, s7, 15
    slli t1, t1, 1
    add t1, t0, t1
    sh zero, 4(t1)
    addi t1, s7, 1
    sh t1, 2(t0)
    sw zero, 0x50(s2)
    ret
bad:
    lla s1, failed
    jal puts
    j shutdown
    .include "common.inc"
done: .asciz "PORT-DONE\n"
ready: .asciz "FIXTURE-READY\n"
mentioned: .asciz "echo FIXTURE-READY\n"
    .balign 4
reset_mode: .word 0xfeed0000   # 0normal;1resetaftermarker;3resetafteractualRX;2reopened
failed: .asciz "PORT-BAD\n"
