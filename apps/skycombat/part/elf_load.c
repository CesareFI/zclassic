/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0 */
/* Purpose: admit and load bounded Linux ELF HUD parts without importing node state. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "elf_load.h"
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#if defined(__linux__) && defined(__x86_64__)
#include <sys/mman.h>
#include <sys/personality.h>
#include <unistd.h>
#define MAX_SECTIONS 4096u
#define MAX_MAPPING (64u*1024u*1024u)
struct section_map { size_t offset,bytes,pages; bool present,executable; };
struct load_image {
    const uint8_t *bytes;
    size_t length,page,total;
    uint64_t table;
    unsigned count;
    struct section_map *sections;
    uint8_t *mapping;
    const struct sky_hud_part_v1 *part;
    unsigned part_section;
    uint64_t part_relative;
};
static uint16_t r16(const uint8_t *p) { return p[0]|(uint16_t)p[1]<<8; }
static uint32_t r32(const uint8_t *p) { return r16(p)|(uint32_t)r16(p+2)<<16; }
static uint64_t r64(const uint8_t *p) { return r32(p)|(uint64_t)r32(p+4)<<32; }
static const uint8_t *sh(const struct load_image *im,unsigned i)
{ return im->bytes+im->table+(uint64_t)i*64; }
static bool range(const struct load_image *im,uint64_t start,uint64_t length)
{ return start<=im->length && length<=im->length-start; }
static void write_le(uint8_t *p,uint64_t value,unsigned n)
{ for(unsigned i=0;i<n;++i) p[i]=(uint8_t)(value>>(i*8)); }
static bool add_signed(uint64_t value,int64_t add,uint64_t *out)
{
    if(add>=0) { if(value>UINT64_MAX-(uint64_t)add) return false; *out=value+(uint64_t)add; }
    else { uint64_t magnitude=(uint64_t)(-(add+1))+1; if(value<magnitude)return false;*out=value-magnitude; }
    return true;
}
static int64_t signed_word(uint64_t word)
{
    if(word<=INT64_MAX) return (int64_t)word;
    return -1-(int64_t)(UINT64_MAX-word);
}
static bool section_layout(const struct load_image *im,const uint8_t *s)
{
    uint64_t flags=r64(s+8),align=r64(s+48);
    unsigned type=r32(s+4);
    if((flags&5u)==5u || (flags&0x400u) || (flags&~UINT64_C(0x37)))return false;
    if(type!=1 && type!=8 && type!=7)return false;
    if(type==7 && (flags&4u))return false;
    return align<=im->page && (!align || !(align&(align-1)));
}
static bool prepare_sections(struct load_image *im)
{
    for(unsigned i=1;i<im->count;++i) {
        const uint8_t *s=sh(im,i);
        uint64_t flags=r64(s+8),bytes=r64(s+32);
        if(!(flags&2u))continue;
        if(!section_layout(im,s))return false;
        if(bytes>MAX_MAPPING || bytes>SIZE_MAX-(im->page-1))return false;
        size_t pages=((size_t)bytes+im->page-1)/im->page*im->page;
        if(pages>MAX_MAPPING-im->total)return false;
        im->sections[i]=(struct section_map){im->total,(size_t)bytes,pages,true,(flags&4u)!=0};
        im->total+=pages;
    }
    return im->total>0;
}
static bool resolve_symbol(const struct load_image *im,const uint8_t *table,
                           uint64_t index,uint64_t *value)
{
    uint64_t n=r64(table+32),off=r64(table+24);
    if(r32(table+4)!=2 || r64(table+56)!=24 || n%24 || index>=n/24 ||
       !range(im,off,n))return false;
    const uint8_t *s=im->bytes+off+index*24;
    unsigned section=r16(s+6);
    uint64_t relative=r64(s+8);
    if(!section || section>=im->count || !im->sections[section].present ||
       !im->sections[section].bytes || relative>=im->sections[section].bytes)return false;
    *value=(uintptr_t)(im->mapping+im->sections[section].offset)+relative;
    return true;
}
static bool relocation_value(unsigned type,uint64_t symbol,int64_t add,
                             uint64_t place,uint64_t *out,unsigned *width)
{
    uint64_t value;
    if(!add_signed(symbol,add,&value))return false;
    switch(type) {
    case 1: *width=8;*out=value;return true;
    case 2: case 4:
        *width=4;
        if(value>=place) { if(value-place>INT32_MAX)return false;*out=value-place; }
        else { uint64_t delta=place-value;if(delta>UINT64_C(2147483648))return false;*out=0u-delta; }
        return true;
    default:return false;
    }
}
static bool relocation_disjoint(const struct load_image *im,unsigned i,uint64_t j,
                                unsigned target,uint64_t at,unsigned width)
{
    for(unsigned prior=1;prior<=i;++prior){
        const uint8_t *ps=sh(im,prior);
        if(r32(ps+4)!=4 || r32(ps+44)!=target)continue;
        uint64_t limit=prior==i?j:r64(ps+32),po=r64(ps+24);
        if(!range(im,po,limit) || limit%24)return false;
        for(uint64_t k=0;k<limit;k+=24){
            const uint8_t *pr=im->bytes+po+k;
            unsigned pw=sky_elf_part_relocation_width((uint32_t)r64(pr+8));
            if(!pw)return false;
            uint64_t pa=r64(pr);
            if(pa<=at ? at-pa<pw : pa-at<width)return false;
        }
    }
    return true;
}
static bool apply_relocation(struct load_image *im,unsigned i,uint64_t j,
                             const uint8_t *r,unsigned target,unsigned link)
{
    uint64_t at=r64(r),info=r64(r+8),symbol,value;
    unsigned width=sky_elf_part_relocation_width((uint32_t)info);
    if(!width || at>im->sections[target].bytes || width>im->sections[target].bytes-at)return false;
    uintptr_t base=(uintptr_t)(im->mapping+im->sections[target].offset);
    if(at>UINTPTR_MAX-base)return false;
    if(!resolve_symbol(im,sh(im,link),info>>32,&symbol))return false;
    if(!relocation_value((uint32_t)info,symbol,signed_word(r64(r+16)),
        base+at,&value,&width))return false;
    if(target==im->part_section &&
       (at<=im->part_relative ? im->part_relative-at<width : at-im->part_relative<8))return false;
    if(!relocation_disjoint(im,i,j,target,at,width))return false;
    write_le(im->mapping+im->sections[target].offset+at,value,width);
    return true;
}
static bool relocate(struct load_image *im)
{
    for(unsigned i=1;i<im->count;++i) {
        const uint8_t *s=sh(im,i);
        unsigned type=r32(s+4),target=r32(s+44),link=r32(s+40);
        if(type!=4 && type!=9)continue;
        if(type!=4 || target>=im->count || link>=im->count ||
           !im->sections[target].present || r64(s+56)!=24)return false;
        uint64_t n=r64(s+32),off=r64(s+24);
        if(n%24 || !range(im,off,n))return false;
        for(uint64_t j=0;j<n;j+=24) {
            if(!apply_relocation(im,i,j,im->bytes+off+j,target,link))return false;
        }
    }
    return true;
}
static bool bind_descriptor(struct load_image *im,const uint8_t *sym)
{
    unsigned target=r16(sym+6);
    uint64_t value=r64(sym+8);
    if(target>=im->count || !im->sections[target].present ||
       im->sections[target].executable || value%_Alignof(struct sky_hud_part_v1))return false;
    if(value>im->sections[target].bytes || sizeof(struct sky_hud_part_v1)>im->sections[target].bytes-value)return false;
    im->part=(const struct sky_hud_part_v1*)(im->mapping+im->sections[target].offset+value);
    im->part_section=target;im->part_relative=value;
    return true;
}
static bool find_in_table(struct load_image *im,const uint8_t *s)
{
    unsigned link=r32(s+40);
    if(link>=im->count || r64(s+56)!=24 || r64(s+32)%24)return false;
    const uint8_t *strings=sh(im,link);
    uint64_t so=r64(strings+24),sn=r64(strings+32),off=r64(s+24),n=r64(s+32);
    if(r32(strings+4)!=3 || !range(im,so,sn) || !range(im,off,n))return false;
    for(uint64_t j=24;j<n;j+=24){
        const uint8_t *sym=im->bytes+off+j;
        uint32_t name=r32(sym);
        if(name>=sn || !memchr(im->bytes+so+name,0,(size_t)(sn-name)))return false;
        if(strcmp((const char*)im->bytes+so+name,"sky_hud_part_v1"))continue;
        if(!bind_descriptor(im,sym))return false;
    }
    return true;
}
static bool find_descriptor(struct load_image *im)
{
    for(unsigned i=1;i<im->count;++i) {
        const uint8_t *s=sh(im,i);
        if(r32(s+4)!=2)continue;
        if(!find_in_table(im,s))return false;
    }
    return im->part && im->part->abi==1 && im->part->size==sizeof(*im->part);
}
static bool descriptor(const struct load_image *im)
{
    if(!im->part || im->part->abi!=1 || im->part->size!=sizeof(*im->part) || !im->part->build)return false;
    uintptr_t function=0;
    _Static_assert(sizeof(function)==sizeof(im->part->build),"Linux x86-64 function pointer size");
    memcpy(&function,&im->part->build,sizeof(function));
    for(unsigned i=1;i<im->count;++i) {
        uintptr_t start=(uintptr_t)(im->mapping+im->sections[i].offset);
        if(im->sections[i].executable && function>=start && function-start<im->sections[i].bytes)return true;
    }
    return false;
}
static bool protect_sections(const struct load_image *im)
{
    if(mprotect(im->mapping,im->total,PROT_NONE))return false;
    for(unsigned i=1;i<im->count;++i) {
        const struct section_map *s=&im->sections[i];
        if(!s->pages)continue;
        int protection=PROT_READ|(s->executable?PROT_EXEC:0);
        if(mprotect(im->mapping+s->offset,s->pages,protection))return false;
    }
    return true;
}
static bool release_mapping(void *mapping,size_t bytes,const char *context)
{
    if(!munmap(mapping,bytes))return true;
    int error=errno;
    fprintf(stderr,"sky_elf_part_load: %s munmap failed errno=%d; retained mapping=%p bytes=%zu\n",
            context,error,mapping,bytes);
    return false;
}
static enum sky_elf_load_verdict map_generation(struct load_image *im)
{
    if(!prepare_sections(im))return SKY_ELF_LOAD_LAYOUT;
    im->mapping=mmap(NULL,im->total,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    if(im->mapping==MAP_FAILED){im->mapping=NULL;return SKY_ELF_LOAD_MEMORY;}
    for(unsigned i=1;i<im->count;++i){
        if(im->sections[i].present && im->sections[i].bytes && r32(sh(im,i)+4)!=8)
            memcpy(im->mapping+im->sections[i].offset,im->bytes+r64(sh(im,i)+24),im->sections[i].bytes);
    }
    if(!find_descriptor(im))return SKY_ELF_LOAD_DESCRIPTOR;
    if(!relocate(im))return SKY_ELF_LOAD_RELOCATION;
    if(!descriptor(im))return SKY_ELF_LOAD_DESCRIPTOR;
    if(!protect_sections(im))return SKY_ELF_LOAD_MEMORY;
    return SKY_ELF_LOAD_OK;
}
static enum sky_elf_load_verdict admitted_generation(uint8_t *copy,size_t n,
                                                    struct sky_elf_part_generation *out)
{
    struct load_image im={.bytes=copy,.length=n,.table=r64(copy+40),.count=r16(copy+60)};
    long page=sysconf(_SC_PAGESIZE);
    if(page<=0 || (unsigned long)page>MAX_MAPPING)return SKY_ELF_LOAD_PLATFORM;
    im.page=(size_t)page;
    im.sections=calloc(im.count,sizeof(*im.sections));
    if(!im.sections)return SKY_ELF_LOAD_MEMORY;
    enum sky_elf_load_verdict verdict=map_generation(&im);
    if(verdict==SKY_ELF_LOAD_OK){
        *out=(struct sky_elf_part_generation){0,im.part,im.mapping,im.total};
        im.mapping=NULL;
    }
    if(im.mapping && !release_mapping(im.mapping,im.total,"candidate cleanup"))verdict=SKY_ELF_LOAD_CLEANUP;
    free(im.sections);
    return verdict;
}
static enum sky_elf_load_verdict make_generation(const void *bytes,size_t n,
    const uint8_t expected[32],struct sky_elf_part_generation *out,enum sky_elf_part_verdict *admission)
{
    if(!bytes || !expected || n>16u*1024u*1024u)return SKY_ELF_LOAD_ARGUMENT;
    /* Must precede even allocator staging: READ_IMPLIES_EXEC could make a
     * large malloc's underlying writable mmap executable. Observe, no change. */
    int persona=personality(0xffffffffUL);
    if(persona<0 || ((unsigned)persona&READ_IMPLIES_EXEC))return SKY_ELF_LOAD_PLATFORM;
    uint8_t *copy=malloc(n?n:1);
    if(!copy)return SKY_ELF_LOAD_MEMORY;
    memcpy(copy,bytes,n);
    *admission=sky_elf_part_admit(copy,n,expected);
    if(*admission!=SKY_ELF_PART_ADMIT){free(copy);return SKY_ELF_LOAD_ADMISSION;}
    enum sky_elf_load_verdict verdict=admitted_generation(copy,n,out);
    free(copy);return verdict;
}
#endif

enum sky_elf_load_verdict sky_elf_part_load(struct sky_elf_part_host *host,const void *bytes,size_t n,
                                   const uint8_t expected[32],enum sky_elf_part_verdict *admission)
{
    if(admission)*admission=SKY_ELF_PART_ARGUMENT;
    if(!host || !admission)return SKY_ELF_LOAD_ARGUMENT;
    if(host->in_call)return SKY_ELF_LOAD_BUSY;
    if(host->last_id==UINT64_MAX)return SKY_ELF_LOAD_ID_EXHAUSTED;
#if defined(__linux__) && defined(__x86_64__)
    struct sky_elf_part_generation next={0};
    enum sky_elf_load_verdict verdict=make_generation(bytes,n,expected,&next,admission);
    if(verdict!=SKY_ELF_LOAD_OK)return verdict;
    if(host->current.mapping && !release_mapping(host->current.mapping,host->current.mapping_bytes,"current retirement")) {
        return release_mapping(next.mapping,next.mapping_bytes,"unpublished candidate cleanup")?
            SKY_ELF_LOAD_MEMORY:SKY_ELF_LOAD_CLEANUP;
    }
    next.id=++host->last_id;host->current=next;return SKY_ELF_LOAD_OK;
#else
    (void)bytes;(void)n;(void)expected;return SKY_ELF_LOAD_PLATFORM;
#endif
}
const struct sky_elf_part_generation *sky_elf_part_call_begin(struct sky_elf_part_host *host)
{
    if(!host || host->in_call || !host->current.part)return NULL;
    host->in_call=true;return &host->current;
}
bool sky_elf_part_call_end(struct sky_elf_part_host *host)
{
    if(!host || !host->in_call)return false;
    host->in_call=false;return true;
}
bool sky_elf_part_host_dispose(struct sky_elf_part_host *host)
{
    if(!host || host->in_call)return false;
#if defined(__linux__) && defined(__x86_64__)
    if(host->current.mapping && !release_mapping(host->current.mapping,host->current.mapping_bytes,"host disposal"))return false;
#endif
    memset(&host->current,0,sizeof(host->current));return true;
}
