# Asks the virtio entropy device in slot 1 for forty bytes and prints them.
# The device is brought up as a driver does (reset, ACKNOWLEDGE, DRIVER,
# VERSION_1, FEATURES_OK, one queue, DRIVER_OK), one request with a single
# device-writable buffer is posted and notified, and the used ring is polled
# for the answer: a source that has nothing yet may answer later. Also reports
# whether the device raised its interrupt line (PLIC source 2).
    .option norvc
    .text
    .globl _start
_start:
    li    s2, 0x10002000          # virtio mmio slot 1
    lw    t0, 0(s2)               # MagicValue "virt"
    li    t1, 0x74726976
    bne   t0, t1, absent
    lw    t0, 8(s2)               # DeviceID: 4 = entropy
    li    t1, 4
    bne   t0, t1, absent
    # PLIC: source 2 priority 1, enabled for the supervisor context, threshold 0
    li    t0, 0x0C000000
    li    t1, 1
    sw    t1, 8(t0)
    li    t0, 0x0C002080
    li    t1, 4
    sw    t1, 0(t0)
    li    t0, 0x0C201000
    sw    zero, 0(t0)
    li    t0, 0x200
    csrw  sie, t0
    # Status: reset, ACKNOWLEDGE, DRIVER
    sw    zero, 0x70(s2)
    li    t0, 1
    sw    t0, 0x70(s2)
    li    t0, 3
    sw    t0, 0x70(s2)
    # features: VERSION_1 (bit 32) and nothing else
    li    t0, 1
    sw    t0, 0x24(s2)
    sw    t0, 0x20(s2)
    sw    zero, 0x24(s2)
    sw    zero, 0x20(s2)
    li    t0, 11
    sw    t0, 0x70(s2)            # FEATURES_OK
    # queue 0 with eight entries
    sw    zero, 0x30(s2)
    li    t0, 8
    sw    t0, 0x38(s2)
    lla   t0, vq_desc
    sw    t0, 0x80(s2)
    sw    zero, 0x84(s2)
    lla   t0, vq_avail
    sw    t0, 0x90(s2)
    sw    zero, 0x94(s2)
    lla   s3, vq_used
    sw    s3, 0xa0(s2)
    sw    zero, 0xa4(s2)
    li    t0, 1
    sw    t0, 0x44(s2)            # QueueReady
    li    t0, 15
    sw    t0, 0x70(s2)            # DRIVER_OK
    # one request: descriptor 0 is forty device-writable bytes
    lla   t0, vq_desc
    lla   s6, buf
    sd    s6, 0(t0)
    li    t1, 40
    sw    t1, 8(t0)
    li    t1, 2                   # VIRTQ_DESC_F_WRITE
    sh    t1, 12(t0)
    sh    zero, 14(t0)
    lla   t0, vq_avail
    sh    zero, 4(t0)             # ring[0] = descriptor 0
    li    t1, 1
    sh    t1, 2(t0)               # idx = 1
    sw    zero, 0x50(s2)          # QueueNotify 0
    # poll the used ring
    li    s4, 4096
1:  lhu   t0, 2(s3)
    bnez  t0, got
    addi  s4, s4, -1
    bnez  s4, 1b
    lla   s1, msg_dry
    jal   puts
    j     shutdown

got:
    lla   s1, msg_bytes
    jal   puts
    lw    s5, 8(s3)               # used.ring[0].len: bytes written
    mv    s9, s5
2:  beqz  s5, 3f
    lbu   s7, 0(s6)
    jal   hexbyte
    addi  s6, s6, 1
    addi  s5, s5, -1
    j     2b
3:  lla   s1, msg_len
    jal   puts
    mv    s7, s9
    jal   hexbyte
    lla   s1, msg_irq
    jal   puts
    csrr  t0, sip
    srli  t0, t0, 9
    andi  a0, t0, 1
    addi  a0, a0, '0'
    li    a7, 1
    ecall
    li    a0, '\n'
    li    a7, 1
    ecall
    j     shutdown

absent:
    lla   s1, msg_absent
    jal   puts
    j     shutdown

# prints the byte in s7 as two hex digits
hexbyte:
    mv    s8, ra
    srli  a0, s7, 4
    jal   nibble
    andi  a0, s7, 15
    jal   nibble
    jr    s8
nibble:
    li    t0, 10
    blt   a0, t0, 4f
    addi  a0, a0, 39              # 'a' - '0' - 10
4:  addi  a0, a0, '0'
    li    a7, 1
    ecall
    ret

    .include "common.inc"

msg_bytes:  .asciz "entropy: "
msg_len:    .asciz " len="
msg_irq:    .asciz " irq="
msg_dry:    .asciz "entropy: nothing yet\n"
msg_absent: .asciz "entropy: no device\n"

    .data
    .balign 16
vq_desc:  .zero 128
vq_avail: .zero 24
    .balign 4
vq_used:  .zero 72
    .balign 16
buf:      .zero 40
guard:    .zero 16
