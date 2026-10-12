# Entered two ways. At its first instruction, the firmware entry, it says so
# and powers off. At _start, 0x30 into the image, the loader entry, a0 is the
# kernel virtual address of a metadata list as a FreeBSD boot loader leaves
# it: records of a 32-bit type, a 32-bit payload size and the payload, each
# starting on an 8-byte boundary, ended by type 0 with size 0. The tests wrap
# this image as an ELF linked at 0xffffffc000000000, so with paging off a
# listed address is reached at (address - that base + where the image runs).
# Prints every record (type, size, then the string of a type 1 or 2 record or
# the value of any other), the first word of the device tree the list names
# (type 0x9001) and a checksum of the bytes of the last module (types 3 and 4:
# address and size), and overwrites those bytes with zeros, as a kernel does
# with a seed it has taken.
    .option norvc
    .text
    .globl _start
image:
    lla   s1, msg_firmware
    jal   puts
    j     shutdown
    .org  0x30
_start:
    lla   s2, image
    li    t0, 0xffffffc000000000
    sub   s2, s2, t0              # s2: add to a kernel virtual address
    add   s3, a0, s2              # s3: the record
    li    s4, 32                  # no list here is longer
    li    s9, 0                   # the device tree
    li    s10, 0                  # the last address
    li    s11, 0                  # the last size
record:
    lwu   s5, 0(s3)               # type
    lwu   s6, 4(s3)               # payload size
    or    t0, s5, s6
    beqz  t0, tree
    srli  s7, s5, 8
    andi  s7, s7, 255
    jal   hexbyte
    andi  s7, s5, 255
    jal   hexbyte
    li    a0, ' '
    li    a7, 1
    ecall
    andi  s7, s6, 255
    jal   hexbyte
    li    a0, ' '
    li    a7, 1
    ecall
    li    t0, 2
    bgtu  s5, t0, value
    addi  s1, s3, 8               # types 1 and 2: a string
    jal   puts
    j     next
value:
    lwu   s0, 8(s3)
    li    t0, 8
    bne   s6, t0, 1f
    ld    s0, 8(s3)
1:  jal   hexword
    li    t0, 3
    bne   s5, t0, 2f
    mv    s10, s0
2:  li    t0, 4
    bne   s5, t0, 3f
    mv    s11, s0
3:  li    t0, 0x9001
    bne   s5, t0, next
    mv    s9, s0
next:
    li    a0, '\n'
    li    a7, 1
    ecall
    addi  s6, s6, 7
    andi  s6, s6, -8
    add   s3, s3, s6
    addi  s3, s3, 8
    addi  s4, s4, -1
    bnez  s4, record
    lla   s1, msg_long
    jal   puts
    j     shutdown

tree:
    lla   s1, msg_tree
    jal   puts
    add   t0, s9, s2
    lwu   s0, 0(t0)
    jal   hexword
    lla   s1, msg_seed
    jal   puts
    add   s3, s10, s2             # the last module's bytes
    li    s0, 0                   # checksum = checksum * 31 + byte
4:  beqz  s11, 5f
    lbu   t0, 0(s3)
    slli  t1, s0, 5
    sub   s0, t1, s0
    add   s0, s0, t0
    sb    zero, 0(s3)
    addi  s3, s3, 1
    addi  s11, s11, -1
    j     4b
5:  jal   hexword
    li    a0, '\n'
    li    a7, 1
    ecall
    j     shutdown

# prints s0 as sixteen hex digits
hexword:
    mv    tp, ra
    li    gp, 56
6:  srl   s7, s0, gp
    andi  s7, s7, 255
    jal   hexbyte
    addi  gp, gp, -8
    bgez  gp, 6b
    jr    tp

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
    blt   a0, t0, 7f
    addi  a0, a0, 39              # 'a' - '0' - 10
7:  addi  a0, a0, '0'
    li    a7, 1
    ecall
    ret

    .include "common.inc"

msg_firmware: .asciz "preload: firmware entry\n"
msg_long:     .asciz "preload: no end of list\n"
msg_tree:     .asciz "tree "
msg_seed:     .asciz "\nseed "
