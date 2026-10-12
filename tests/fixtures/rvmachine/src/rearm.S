# Arms the timer s1 time units ahead and waits in wfi, forever. s1 is zero
# unless the embedder set it, and then every deadline is already due when the
# wfi runs. The timer interrupt is enabled but not taken as a trap, so a due
# timer simply ends the wfi.
    .option norvc
    .text
    .globl _start
_start:
    li    t0, 0x20
    csrw  sie, t0
1:  rdtime a0
    add   a0, a0, s1
    li    a6, 0
    li    a7, 0x54494D45
    ecall
    wfi
    j     1b
