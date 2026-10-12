/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: Assemble a small arm64 Mach-O seed with code, constants, descriptor and discarded fixups. */
.text
.p2align 2
build:
 ret
caller:
 bl build
 adrp x0, constant@PAGE
 add x0, x0, constant@PAGEOFF
 ldr x1, [x0, constant@PAGEOFF]
 ret
.section __TEXT,__const
.p2align 3
constant:
 .quad 0, 0, 0
.section __DATA,__const
.p2align 3
.globl _sky_hud_part_v1
_sky_hud_part_v1:
 .long 1, 16
 .quad build
.section __DATA_CONST,__const
.p2align 3
 .quad build
 .quad build
