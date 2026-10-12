# Tiny supervisor-mode smoke guest for the machine: prints through the legacy
# firmware console, arms the timer, waits in wfi, takes the timer interrupt,
# prints again, reads the serial port LSR and writes THR, then shuts down.
    .option norvc
    .text
    .globl _start
_start:
    lla   t0, trap
    csrw  stvec, t0
    lla   s1, msg1
    jal   puts
    # probe legacy putchar via base probe (eid 0x10 fid 3 arg 1)
    li    a0, 1
    li    a6, 3
    li    a7, 0x10
    ecall
    addi  a0, a1, '0'
    li    a7, 1
    ecall
    li    a0, '\n'
    ecall
    # arm the timer 1000 time units ahead, enable STIE and SIE, wait
    rdtime a0
    addi  a0, a0, 1000
    li    a6, 0
    li    a7, 0x54494D45
    ecall
    li    t0, 0x20
    csrs  sie, t0
    csrsi sstatus, 2
1:  wfi
    lla   t0, fired
    ld    t1, 0(t0)
    beqz  t1, 1b
    lla   s1, msg2
    jal   puts
    # serial port: write 'U' to THR
    li    t0, 0x10000000
    li    t1, 'U'
    sb    t1, 0(t0)
    li    t1, '\n'
    sb    t1, 0(t0)
    # shutdown through SRST
    li    a0, 0
    li    a1, 0
    li    a6, 0
    li    a7, 0x53525354
    ecall
2:  j     2b

# The firmware return writes a0 and a1 only, so one putchar id serves the string.
puts:
    li    a7, 1
1:  lbu   a0, 0(s1)
    beqz  a0, 2f
    ecall
    addi  s1, s1, 1
    j     1b
2:  ret

    .balign 4
trap:
    # timer interrupt: disarm, record, return
    li    a0, -1
    li    a6, 0
    li    a7, 0x54494D45
    ecall
    lla   t0, fired
    li    t1, 1
    sd    t1, 0(t0)
    sret

    .balign 8
fired:  .quad 0
msg1:   .asciz "tiny: hello from S-mode\nprobe putchar="
msg2:   .asciz "tiny: timer fired\n"
