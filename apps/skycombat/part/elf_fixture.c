/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0 */
/* Purpose: compile consenting A/B and rejection parts for canonical ELF tests.
 * This file is not linked into the host; its sole export is the V1 descriptor. */
#include "recipe_abi.h"
#ifdef SKY_ELF_FIXTURE_B
static void label(struct sky_hud_recipe_v1 *out,unsigned percent)
{
    const char prefix[]="HULL ";
    unsigned used=0;
    for(unsigned i=0;i<5;++i)out->text[used++]=(uint8_t)prefix[i];
    if(percent==100)out->text[used++]='1';
    if(percent>=10)out->text[used++]=(uint8_t)('0'+percent/10%10);
    out->text[used++]=(uint8_t)('0'+percent%10);
    out->text[used++]='%';
    out->op_count=2;out->text_used=used;
    out->ops[1]=(struct sky_hud_op_v1){.kind=SKY_HUD_OP_TEXT,.x=360,
        .y=out->ops[0].y+5,.font_px=20,.rgba=0xffffffffu,
        .align=SKY_HUD_ALIGN_LEFT,.text_len=used};
}
#endif
static int32_t build(const struct sky_hud_snapshot_v1 *in,struct sky_hud_recipe_v1 *out)
{
    if(!in || !out || in->abi!=1 || in->size!=sizeof(*in) ||
       in->screen_h<INT32_MIN+150)return -1;
    for(unsigned i=0;i<sizeof(*out);++i)((uint8_t*)out)[i]=0;
    int32_t width=0;
    if(in->max_health_milli>0) {
        int32_t health=in->health_milli;
#ifdef SKY_ELF_FIXTURE_B
        if(health<0)health=0;
        if(health>in->max_health_milli)health=in->max_health_milli;
#endif
        width=(int32_t)((int64_t)health*100/in->max_health_milli);
    }
    out->op_count=1;
    out->ops[0]=(struct sky_hud_op_v1){.kind=SKY_HUD_OP_RECT,.x=360,
        .y=in->screen_h-150,.w=width,.h=20,.rgba=0xffffffffu};
#ifdef SKY_ELF_FIXTURE_B
    label(out,(unsigned)width);
#endif
#ifdef SKY_ELF_FIXTURE_BAD_OPS
    out->op_count=65;
#endif
#ifdef SKY_ELF_FIXTURE_BAD_TEXT
    out->text_used=1025;
#endif
#ifdef SKY_ELF_FIXTURE_BAD_RESULT
    return 17;
#else
    return 0;
#endif
}
const struct sky_hud_part_v1 sky_hud_part_v1={SKY_HUD_ABI_V1,sizeof(struct sky_hud_part_v1),build};
/* Compiler/assembler-produced assurance objects: never post-build byte patches.
 * These inert, deliberately disallowed variants are admitted only as data. */
#ifdef SKY_ELF_FIXTURE_WX
__asm__(".pushsection .assurance,\"awx\",@progbits\n.byte 0\n.popsection\n");
#endif
#ifdef SKY_ELF_FIXTURE_SYMBOL_EXTENT
__asm__(".pushsection .assurance,\"a\",@progbits\n.globl sky_assurance\n.type sky_assurance,@object\nsky_assurance: .quad 0\n.size sky_assurance,32\n.popsection\n");
#endif
#ifdef SKY_ELF_FIXTURE_ABSOLUTE
__asm__(".globl sky_assurance\n.set sky_assurance,1\n");
#endif
#ifdef SKY_ELF_FIXTURE_COMMON
__asm__(".comm sky_assurance,8,8\n");
#endif
#ifdef SKY_ELF_FIXTURE_DYNAMIC
__asm__(".pushsection .assurance,\"\",@6\n.quad 0,0\n.popsection\n");
#endif
#ifdef SKY_ELF_FIXTURE_UNSUPPORTED_RELOCATION
__asm__(".pushsection .assurance,\"a\",@progbits\nsky_assurance: .quad 0\n.reloc sky_assurance,R_X86_64_GOTPCREL,build\n.popsection\n");
#endif
#ifdef SKY_ELF_FIXTURE_RELOCATION_EXTENT
__asm__(".pushsection .assurance,\"a\",@progbits\nsky_assurance: .quad 0\n.reloc sky_assurance+8,R_X86_64_PC32,build\n.popsection\n");
#endif
#ifdef SKY_ELF_FIXTURE_RELOCATION_OVERLAP
__asm__(".pushsection .assurance,\"a\",@progbits\nsky_assurance: .quad 0\n.reloc sky_assurance,R_X86_64_PC32,build\n.reloc sky_assurance+2,R_X86_64_PC32,build\n.popsection\n");
#endif
#ifdef SKY_ELF_FIXTURE_DESCRIPTOR_WRITE
__asm__(".reloc sky_hud_part_v1,R_X86_64_PC32,sky_hud_part_v1+1\n");
#endif
#ifdef SKY_ELF_FIXTURE_RELOCATION_UNMAPPED
__asm__(".pushsection .assurance,\"\",@progbits\nsky_assurance: .quad 0\n.reloc sky_assurance,R_X86_64_PC32,build\n.popsection\n");
#endif
#ifdef SKY_ELF_FIXTURE_RELOCATION_END_SYMBOL
__asm__(".pushsection .assurance,\"a\",@progbits\nsky_assurance: .quad 0\nsky_assurance_end:\n.reloc sky_assurance,R_X86_64_PC32,sky_assurance_end\n.popsection\n");
#endif
#ifdef SKY_ELF_FIXTURE_RELOCATION_LIMIT
/* The normal descriptor and unwind data contribute two relocations. */
__asm__(".pushsection .assurance,\"a\",@progbits\n.rept 4094\n.long 0\n.reloc .-4,R_X86_64_PC32,build\n.endr\n.popsection\n");
#endif
#ifdef SKY_ELF_FIXTURE_RELOCATION_LIMIT_PLUS_ONE
__asm__(".pushsection .assurance,\"a\",@progbits\n.rept 4095\n.long 0\n.reloc .-4,R_X86_64_PC32,build\n.endr\n.popsection\n");
#endif
