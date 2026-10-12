/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0 */
/* Purpose: admit and load bounded Linux ELF HUD parts without importing node state. */
#include "elf_admit.h"
#include "zsha256/zsha256.h"
#include <stdbool.h>
#include <string.h>

#define SKY_ELF_PART_MAX_BYTES (16u * 1024u * 1024u)
#define SKY_ELF_PART_MAX_SECTIONS 4096u
struct image {
    const uint8_t *b; size_t n; uint64_t sh,descriptor_value;
    uint16_t count,descriptor_section;
};
static uint16_t u16(const uint8_t *p)
{ return (uint16_t)((uint16_t)p[0] | (uint16_t)p[1] << 8); }
static uint32_t u32(const uint8_t *p)
{ return (uint32_t)u16(p) | (uint32_t)u16(p + 2) << 16; }
static uint64_t u64(const uint8_t *p)
{ return (uint64_t)u32(p) | (uint64_t)u32(p + 4) << 32; }
static bool span(const struct image *im, uint64_t off, uint64_t len)
{ return off <= im->n && len <= im->n - off; }
static bool overlap(uint64_t a, uint64_t an, uint64_t b, uint64_t bn)
{ return an && bn && a < b + bn && b < a + an; }
static const uint8_t *section(const struct image *im, unsigned i)
{ return im->b + im->sh + (uint64_t)i * 64; }
static const char *name(const struct image *im, const uint8_t *table, uint32_t off)
{
    uint64_t n = u64(table + 32), start = u64(table + 24);
    if (u32(table + 4) != 3 || !span(im, start, n) || off >= n) return NULL;
    const char *p = (const char *)im->b + start + off;
    return memchr(p, 0, (size_t)(n - off)) ? p : NULL;
}
static bool startup_label(const char *label)
{
    static const char *const exact[]={".init",".fini",".preinit_array",".init_array",".ctors",".fini_array",".dtors"};
    static const char *const prefix[]={".init_array.",".fini_array.",".ctors.",".dtors."};
    for(unsigned i=0;i<sizeof(exact)/sizeof(*exact);++i)
        if(!strcmp(label,exact[i]))return true;
    for(unsigned i=0;i<sizeof(prefix)/sizeof(*prefix);++i)
        if(!strncmp(label,prefix[i],strlen(prefix[i])))return true;
    return false;
}
static bool tls_label(const char *label)
{
    return !strcmp(label,".tdata") || !strcmp(label,".tbss") ||
           !strncmp(label,".tdata.",7) || !strncmp(label,".tbss.",6);
}
static bool dynamic_section(uint32_t type)
{
    switch(type){
    case 5:case 6:case 10:case 11:
    case 0x6ffffff6u:case 0x6ffffffdu:case 0x6ffffffeu:case 0x6fffffffu:return true;
    default:return false;
    }
}
static bool section_attributes(const uint8_t *s)
{
    uint64_t flags=u64(s+8),align=u64(s+48);
    uint32_t type=u32(s+4);
    if((flags&5u)==5u || (align && (align&(align-1))))return false;
    if(!(flags&2u))return true;
    if(flags&~UINT64_C(0x37))return false;
    if(type!=1 && type!=8 && type!=7)return false;
    return type!=7 || !(flags&4u);
}
static enum sky_elf_part_verdict section_policy(const uint8_t *s,const char *label)
{
    uint32_t type=u32(s+4);
    uint64_t flags=u64(s+8);
    if(!strcmp(label,".note.GNU-stack") && (flags&4u))return SKY_ELF_PART_EXEC_STACK;
    if((flags&0x400u) || tls_label(label))return SKY_ELF_PART_TLS;
    if(type==14 || type==15 || type==16 || startup_label(label))return SKY_ELF_PART_STARTUP;
    if(dynamic_section(type) || !section_attributes(s))return SKY_ELF_PART_FORMAT;
    return SKY_ELF_PART_ADMIT;
}
static enum sky_elf_part_verdict section_span(const struct image *im,unsigned i)
{
    const uint8_t *s=section(im,i);
    uint64_t off=u64(s+24),n=u64(s+32);
    if(u32(s+4)==8)return SKY_ELF_PART_ADMIT;
    if(!span(im,off,n))return SKY_ELF_PART_BOUNDS;
    if(overlap(off,n,0,64) || overlap(off,n,im->sh,(uint64_t)im->count*64))return SKY_ELF_PART_OVERLAP;
    for(unsigned j=1;j<i;++j){
        const uint8_t *other=section(im,j);
        if(u32(other+4)!=8 && overlap(off,n,u64(other+24),u64(other+32)))return SKY_ELF_PART_OVERLAP;
    }
    return SKY_ELF_PART_ADMIT;
}
static enum sky_elf_part_verdict sections(const struct image *im, unsigned names)
{
    const uint8_t *strings = section(im, names);
    for (unsigned i = 1; i < im->count; ++i) {
        const uint8_t *s = section(im, i);
        const char *label = name(im, strings, u32(s));
        if (!label) return SKY_ELF_PART_BOUNDS;
        enum sky_elf_part_verdict verdict=section_policy(s,label);
        if(verdict!=SKY_ELF_PART_ADMIT)return verdict;
        verdict=section_span(im,i);
        if(verdict!=SKY_ELF_PART_ADMIT)return verdict;
    }
    return SKY_ELF_PART_ADMIT;
}
static bool relocation_target_valid(const struct image *im, unsigned target)
{
    return target && target < im->count && (u64(section(im,target)+8)&2u);
}
static bool relocation_table_valid(const struct image *im,const uint8_t *s)
{
    unsigned link=u32(s+40);
    if(!link || link>=im->count)return false;
    const uint8_t *symbols=section(im,link);
    if(u32(symbols+4)!=2 || u64(symbols+56)!=24 || u64(symbols+32)%24)return false;
    uint64_t bytes=u64(s+32),off=u64(s+24);
    return u32(s+4)==4 && u64(s+56)==24 && bytes%24==0 && span(im,off,bytes);
}
static enum sky_elf_part_verdict relocation_tables(const struct image *im)
{
    uint64_t total=0;
    for (unsigned i = 1; i < im->count; ++i) {
        const uint8_t *s = section(im, i);
        unsigned type = u32(s + 4);
        if (type != 4 && type != 9) continue;
        if (!relocation_target_valid(im, u32(s + 44))) return SKY_ELF_PART_RELOCATION_TARGET;
        if(!relocation_table_valid(im,s))return SKY_ELF_PART_RELOCATION_FORMAT;
        uint64_t entries=u64(s+32)/24;
        if(entries>SKY_ELF_PART_MAX_RELOCATIONS-total)return SKY_ELF_PART_RELOCATION_FORMAT;
        total+=entries;
    }
    return SKY_ELF_PART_ADMIT;
}
static bool admission_relocations_disjoint(const struct image *im,unsigned i,uint64_t k,
                                          unsigned target,uint64_t at,unsigned width)
{
    for(unsigned prior=1;prior<=i;++prior){
        const uint8_t *s=section(im,prior);
        if(u32(s+4)!=4 || u32(s+44)!=target)continue;
        uint64_t limit=prior==i?k:u64(s+32);
        for(uint64_t j=0;j<limit;j+=24){
            const uint8_t *r=im->b+u64(s+24)+j;
            uint64_t before=u64(r);
            unsigned earlier=sky_elf_part_relocation_width(u32(r+8));
            if(before<=at ? at-before<earlier : before-at<width)return false;
        }
    }
    return true;
}
static bool relocation_symbol_valid(const struct image *im,const uint8_t *table,uint64_t index)
{
    if(!index || index>=u64(table+32)/24)return false;
    const uint8_t *sym=im->b+u64(table+24)+index*24;
    unsigned owner=u16(sym+6);
    if(!relocation_target_valid(im,owner))return false;
    return u64(sym+8)<u64(section(im,owner)+32);
}
static enum sky_elf_part_verdict relocation_entry(const struct image *im,unsigned i,uint64_t k)
{
    const uint8_t *s=section(im,i),*r=im->b+u64(s+24)+k;
    uint64_t at=u64(r),info=u64(r+8);
    unsigned target=u32(s+44),type=(uint32_t)info;
    if(type==10 || type==11)return SKY_ELF_PART_ABSOLUTE_RELOCATION;
    unsigned width=sky_elf_part_relocation_width(type);
    if(!width)return SKY_ELF_PART_RELOCATION_FORMAT;
    if(!relocation_symbol_valid(im,section(im,u32(s+40)),info>>32))return SKY_ELF_PART_RELOCATION_TARGET;
    uint64_t extent=u64(section(im,target)+32);
    if(at>extent || width>extent-at)return SKY_ELF_PART_BOUNDS;
    if(target==im->descriptor_section &&
       (at<=im->descriptor_value ? im->descriptor_value-at<width : at-im->descriptor_value<8))return SKY_ELF_PART_ABI;
    return admission_relocations_disjoint(im,i,k,target,at,width)?SKY_ELF_PART_ADMIT:SKY_ELF_PART_OVERLAP;
}
static enum sky_elf_part_verdict relocations(const struct image *im)
{
    enum sky_elf_part_verdict verdict=relocation_tables(im);
    if(verdict!=SKY_ELF_PART_ADMIT)return verdict;
    for(unsigned i=1;i<im->count;++i){
        const uint8_t *s=section(im,i);
        if(u32(s+4)!=4)continue;
        for(uint64_t k=0;k<u64(s+32);k+=24){
            verdict=relocation_entry(im,i,k);
            if(verdict!=SKY_ELF_PART_ADMIT)return verdict;
        }
    }
    return SKY_ELF_PART_ADMIT;
}
static enum sky_elf_part_verdict descriptor_symbol(struct image *im,const uint8_t *sym)
{
    unsigned target=u16(sym+6),type=sym[4]&15u;
    if(type!=1 || sym[4]>>4!=1 || target>=im->count)return SKY_ELF_PART_ABI;
    const uint8_t *data=section(im,target);
    uint64_t value=u64(sym+8),size=u64(sym+16),bytes=u64(data+32);
    if(u32(data+4)!=1 || size<16 || value>bytes || size>bytes-value)return SKY_ELF_PART_ABI;
    if(u32(im->b+u64(data+24)+value)!=1)return SKY_ELF_PART_ABI;
    im->descriptor_section=(uint16_t)target;im->descriptor_value=value;
    return SKY_ELF_PART_ADMIT;
}
static bool file_symbol(const uint8_t *sym,const char *label)
{
    return sym[4]==4 && u16(sym+6)==0xfff1u && !u64(sym+8) && !u64(sym+16) && *label;
}
static bool symbol_extent(const struct image *im,const uint8_t *sym)
{
    unsigned target=u16(sym+6);
    if(target>=im->count || target>=0xff00u)return false;
    uint64_t extent=u64(section(im,target)+32),value=u64(sym+8);
    return value<=extent && u64(sym+16)<=extent-value;
}
static enum sky_elf_part_verdict nonnull_symbol(struct image *im,const uint8_t *sym,
                                              const char *label,unsigned *matches)
{
    unsigned target=u16(sym+6),type=sym[4]&15u;
    if(!target)return SKY_ELF_PART_UNDEFINED;
    if(type==6)return SKY_ELF_PART_TLS;
    if(type==10)return SKY_ELF_PART_IFUNC;
    if(file_symbol(sym,label))return SKY_ELF_PART_ADMIT;
    if(!symbol_extent(im,sym))return SKY_ELF_PART_BOUNDS;
    if(strcmp(label,"sky_hud_part_v1"))return SKY_ELF_PART_ADMIT;
    if(++*matches>1)return SKY_ELF_PART_DUPLICATE;
    return descriptor_symbol(im,sym);
}
static enum sky_elf_part_verdict symbol_table(struct image *im,const uint8_t *s,unsigned *matches)
{
    uint64_t n=u64(s+32),off=u64(s+24);
    unsigned link=u32(s+40);
    if(u64(s+56)!=24 || n<24 || n%24 || link>=im->count)return SKY_ELF_PART_BOUNDS;
    unsigned locals=u32(s+44);
    if(locals>n/24)return SKY_ELF_PART_FORMAT;
    for(uint64_t k=0;k<n;k+=24){
        const uint8_t *sym=im->b+off+k;
        const char *label=name(im,section(im,link),u32(sym));
        if(!label)return SKY_ELF_PART_BOUNDS;
        if((k/24<locals)!=(sym[4]>>4==0))return SKY_ELF_PART_FORMAT;
        if(!k){
            for(unsigned z=0;z<24;++z)if(sym[z])return SKY_ELF_PART_FORMAT;
            continue;
        }
        enum sky_elf_part_verdict verdict=nonnull_symbol(im,sym,label,matches);
        if(verdict!=SKY_ELF_PART_ADMIT)return verdict;
    }
    return SKY_ELF_PART_ADMIT;
}
static enum sky_elf_part_verdict symbols(struct image *im)
{
    unsigned matches = 0;
    for (unsigned i = 1; i < im->count; ++i) {
        const uint8_t *s = section(im, i);
        if (u32(s + 4) != 2) continue;
        enum sky_elf_part_verdict verdict=symbol_table(im,s,&matches);
        if(verdict!=SKY_ELF_PART_ADMIT)return verdict;
    }
    return matches == 1 ? SKY_ELF_PART_ADMIT : SKY_ELF_PART_MISSING;
}
static enum sky_elf_part_verdict header(struct image *im)
{
    if(im->n<64)return SKY_ELF_PART_BOUNDS;
    const uint8_t *h=im->b;
    if (memcmp(h, "\177ELF", 4) || h[6] != 1 || u32(h + 20) != 1 ||
        u16(h + 16) != 1) return SKY_ELF_PART_FORMAT;
    if (h[4] != 2 || h[5] != 1 || u16(h + 18) != 62) return SKY_ELF_PART_TARGET;
    if (u16(h + 52) != 64 || u16(h + 58) != 64 || u16(h + 56) ||
        u64(h + 32) || u64(h + 24)) return SKY_ELF_PART_FORMAT;
    im->sh = u64(h + 40); im->count = u16(h + 60);
    return SKY_ELF_PART_ADMIT;
}
static enum sky_elf_part_verdict section_headers(const struct image *im)
{
    const uint8_t *h=im->b;
    unsigned names = u16(h + 62);
    if (!im->count || im->count > SKY_ELF_PART_MAX_SECTIONS || !names || names >= im->count ||
        !span(im, im->sh, (uint64_t)im->count * 64)) return SKY_ELF_PART_BOUNDS;
    if (im->sh < 64) return SKY_ELF_PART_OVERLAP;
    for (unsigned z = 0; z < 64; ++z)
        if (section(im, 0)[z]) return SKY_ELF_PART_FORMAT;
    return sections(im,names);
}
enum sky_elf_part_verdict sky_elf_part_admit(const void *bytes, size_t length,
                                    const uint8_t expected[32])
{
    if (!bytes || !expected || length > SKY_ELF_PART_MAX_BYTES) return SKY_ELF_PART_ARGUMENT;
    uint8_t digest[32];
    zsha256(bytes, length, digest);
    if (zsha256_compare(digest, expected)) return SKY_ELF_PART_DIGEST;
    struct image im = { .b = bytes, .n = length };
    enum sky_elf_part_verdict verdict=header(&im);
    if(verdict!=SKY_ELF_PART_ADMIT)return verdict;
    verdict=section_headers(&im);
    if(verdict==SKY_ELF_PART_ADMIT)verdict=symbols(&im);
    return verdict==SKY_ELF_PART_ADMIT?relocations(&im):verdict;
}
