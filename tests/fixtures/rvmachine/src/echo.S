# Reads three bytes through the firmware console and echoes them there, then
# reads three bytes from the serial port and echoes them through it. The
# machine offers every input byte to both readers, so the same three bytes
# come out twice.
    .option norvc
    .text
    .globl _start
_start:
    li    s2, 3
1:  li    a7, 2
    ecall
    bltz  a0, 1b
    li    a7, 1
    ecall
    addi  s2, s2, -1
    bnez  s2, 1b
    li    s2, 3
    li    s3, 0x10000000
2:  lbu   t1, 5(s3)
    andi  t1, t1, 1
    beqz  t1, 2b
    lbu   t1, 0(s3)
    sb    t1, 0(s3)
    addi  s2, s2, -1
    bnez  s2, 2b
    j     shutdown

    .include "common.inc"
