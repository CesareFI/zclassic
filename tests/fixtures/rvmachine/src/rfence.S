# Remaps one virtual page three times without executing sfence.vma and asks
# the firmware for a remote fence instead. The firmware call that selects this
# hart must make the new mapping visible; the call with an empty hart mask
# must not be needed for anything and may leave the old translation in place.
# Prints the first byte read through the page after each step.
    .option norvc
    .text
    .globl _start
    .equ  VPAGE, 0x40000000
    .equ  RFENCE, 0x52464E43

    # reg = leaf or pointer entry for the physical address in reg
    .macro mkpte reg, flags
    srli  \reg, \reg, 12
    slli  \reg, \reg, 10
    ori   \reg, \reg, \flags
    .endm

_start:
    # root[2]: identity 1 GiB leaf for the image; root[1] -> l1 -> l0
    lla   s4, root
    li    t1, (0x80000 << 10) | 0xcf
    sd    t1, 16(s4)
    lla   t0, l1
    mkpte t0, 1
    sd    t0, 8(s4)
    lla   t0, l0
    mkpte t0, 1
    lla   t1, l1
    sd    t0, 0(t1)
    lla   s5, l0
    lla   t0, page_a
    mkpte t0, 0xc7
    sd    t0, 0(s5)
    srli  t0, s4, 12
    li    t1, 8 << 60
    or    t0, t0, t1
    sfence.vma
    csrw  satp, t0
    lla   s1, msg
    jal   puts
    li    s6, VPAGE

    # 1: the first read goes through the table and is remembered
    jal   show
    # 2: remap to B; a fence for an empty hart set flushes nothing
    lla   t0, page_b
    mkpte t0, 0xc7
    sd    t0, 0(s5)
    li    a0, 0
    li    a6, 1
    jal   fence
    jal   show
    # 3: remote sfence.vma selecting this hart: B must be visible
    li    a0, 1
    li    a6, 1
    jal   fence
    jal   show
    # 4: remap to C; remote sfence.vma with an address-space id: C visible
    lla   t0, page_c
    mkpte t0, 0xc7
    sd    t0, 0(s5)
    li    a0, 1
    li    a6, 2
    jal   fence
    jal   show
    li    a0, '\n'
    li    a7, 1
    ecall
    j     shutdown

# a0 = hart mask, a6 = function; the whole address space, id 0
fence:
    li    a1, 0
    li    a2, 0
    li    a3, -1
    li    a4, 0
    li    a7, RFENCE
    ecall
    ret

# prints a space and the first byte of the virtual page
show:
    mv    s7, ra
    li    a0, ' '
    li    a7, 1
    ecall
    lbu   a0, 0(s6)
    li    a7, 1
    ecall
    mv    ra, s7
    ret

    .include "common.inc"

msg:    .asciz "rfence:"

    .balign 4096
root:   .fill 512, 8, 0
l1:     .fill 512, 8, 0
l0:     .fill 512, 8, 0
page_a: .fill 4096, 1, 'A'
page_b: .fill 4096, 1, 'B'
page_c: .fill 4096, 1, 'C'
