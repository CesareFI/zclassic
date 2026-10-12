/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: Admit and open bounded Apple Silicon HUD parts with explicit host ownership. */
#include "macho_admission.h"
#include "zsha256/zsha256.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static uint32_t u32(const uint8_t *p) {return (uint32_t)p[0]|(uint32_t)p[1]<<8|(uint32_t)p[2]<<16|(uint32_t)p[3]<<24;}
static uint64_t u64(const uint8_t *p) {return u32(p)|(uint64_t)u32(p+4)<<32;}
static int64_t sx(uint64_t v,unsigned bits) {uint64_t mask=(UINT64_C(1)<<bits)-1;v&=mask;return (v&(UINT64_C(1)<<(bits-1)))?-1-(int64_t)(mask-v):(int64_t)v;}
static bool span(const struct image *im,uint64_t off,uint64_t n) {return off<=im->n && n<=im->n-off;}
static bool fail(struct image *im,enum sky_macho_verdict code) {im->failure=code;return false;}
static bool region(struct image *im,uint64_t off,uint64_t n) {
 if(!span(im,off,n))return fail(im,SKY_MACHO_BOUNDS);
 if(!n)return true;
 if(im->nr>=sizeof(im->reg)/sizeof(im->reg[0]))return false;
 for(unsigned i=0;i<im->nr;i++)if(off<im->reg[i].off+im->reg[i].size && im->reg[i].off<off+n)return fail(im,SKY_MACHO_OVERLAP);
 im->reg[im->nr++]=(struct region){(size_t)off,(size_t)n};return true;
}
static bool name(const uint8_t *p,const char *s) {size_t n=strlen(s);return n<=16 && !memcmp(p,s,n) && (n==16 || !p[n]);}
static bool contains(uint64_t base,uint64_t size,uint64_t at,uint64_t width)
{
 return at>=base && at-base<=size && width<=size-(at-base);
}
static bool segment_policy(struct image *im,const uint8_t *c)
{
 uint32_t max=u32(c+56),initial=u32(c+60);
 /* MH_OBJECT combines code and data in one declarative segment. Mapping
  * rights belong to the receiver's NONE -> RW -> RX publication lifecycle. */
 if((max|initial)&~7u || (initial&~max))return false;
 for(unsigned i=8;i<24;i++)if(c[i])return false;
 im->vmaddr=u64(c+24);im->vmsize=u64(c+32);
 im->fileoff=u64(c+40);im->filesize=u64(c+48);
 return im->vmaddr<=UINT64_MAX-im->vmsize && !u32(c+68) &&
  span(im,im->fileoff,im->filesize);
}
static bool section_in_segment(const struct image *im,const struct section *v)
{
 return contains(im->vmaddr,im->vmsize,v->old,v->size) &&
  (!v->size || contains(im->fileoff,im->filesize,v->off,v->size));
}
static bool section_type_allowed(struct image *im,uint32_t type)
{
 if(type==9 || type==10 || type==22)return fail(im,SKY_MACHO_STARTUP);
 if(type>=17 && type<=21)return fail(im,SKY_MACHO_TLS);
 return type==0 || type==2 || type==4 || type==14;
}
static bool section_dimensions(const uint8_t *s,const struct section *v,unsigned align)
{
 return !(v->old>UINT64_MAX-v->size || v->size>SLOT || align>14 ||
  u32(s+68) || u32(s+72) || u32(s+76));
}
static bool constant_section_name(const uint8_t *s)
{
 return name(s,"__const") || name(s,"__cstring") || name(s,"__literal4") ||
  name(s,"__literal8") || name(s,"__literal16");
}
static bool section_ownership(const uint8_t *s,struct section *v,bool *drop)
{
 bool textseg=name(s+16,"__TEXT");v->text=textseg && name(s,"__text");
 bool constant=textseg && constant_section_name(s);
 bool pointers=(name(s+16,"__DATA") || name(s+16,"__DATA_CONST")) && name(s,"__const");
 *drop=(name(s+16,"__LD") && name(s,"__compact_unwind")) || (textseg && name(s,"__eh_frame"));
 return v->text || constant || pointers || *drop;
}
static bool section_shape(const uint8_t *s,const struct section *v,uint32_t flags,uint32_t type)
{
 if(v->text ? type!=0 : name(s,"__cstring") ? type!=2 : name(s,"__literal4") ? type!=3 : name(s,"__literal8") ? type!=4 : name(s,"__literal16") ? type!=14 : type!=0)return false;
 if((flags&~UINT32_C(0x800004ff)) || (!v->text && (flags&UINT32_C(0x80000400))))return false;
 return true;
}
static bool section_extent_disjoint(const struct image *im,const struct section *v)
{
 for(unsigned j=0;j<im->ns;j++)
  if(v->size && im->sec[j].size && v->old<im->sec[j].old+im->sec[j].size && im->sec[j].old<v->old+v->size)return false;
 return true;
}
static bool section_mapping(struct image *im,struct section *v,unsigned align,bool drop)
{
 v->keep=!drop;if(!v->keep)return true;
 size_t a=(size_t)1<<align;if(a<16)a=16;
 size_t offset=(im->total+a-1)&~(a-1);
 if(offset>SLOT || v->size>SLOT-offset)return false;
 v->mapped=offset;im->total=offset+(size_t)v->size;return true;
}
static bool parse_section(struct image *im,const uint8_t *s)
{
 uint32_t flags=u32(s+64),type=flags&255,align=u32(s+52);
 struct section v={.type=type,.old=u64(s+32),.size=u64(s+40),.off=u32(s+48),.rel=u32(s+56),.nrel=u32(s+60)};
 if(!section_type_allowed(im,type))return false;
 if(!section_dimensions(s,&v,align))return false;
 bool drop=false;if(!section_ownership(s,&v,&drop))return false;
 if(!section_shape(s,&v,flags,type))return false;
 if(!region(im,v.off,v.size) || !region(im,v.rel,(uint64_t)v.nrel*8))return false;
 if(!section_in_segment(im,&v))return false;
 if(!section_extent_disjoint(im,&v))return false;
 if(!section_mapping(im,&v,align,drop))return false;
 im->sec[im->ns++]=v;return true;
}
static bool parse_segment(struct image *im,const uint8_t *c,uint32_t size)
{
 if(size<72 || im->segment_seen || !name(c+8,""))return false;
 im->segment_seen=true;
 uint32_t ns=u32(c+64);
 if(ns>MAX_SECTIONS || size!=72+(uint64_t)ns*80 || im->ns)return fail(im,SKY_MACHO_BOUNDS);
 if(!segment_policy(im,c))return false;
 for(uint32_t i=0;i<ns;i++)if(!parse_section(im,c+72+80*i))return false;
 return true;
}
static bool parse_symtab(struct image *im,const uint8_t *c,uint32_t size)
{
 if(size!=24 || im->syms)return false;
 im->syms=true;im->sym=u32(c+8);im->nsyms=u32(c+12);im->str=u32(c+16);im->nstr=u32(c+20);return true;
}
static bool parse_dysymtab(struct image *im,const uint8_t *c,uint32_t size)
{
 if(size!=80 || im->dysym)return false;
 im->dysym=true;
 for(unsigned k=0;k<6;k++)im->partitions[k]=u32(c+8+k*4);
 for(unsigned k=32;k<80;k+=4)if(u32(c+k))return false;
 return true;
}
static bool parse_build_version(const uint8_t *c,uint32_t size)
{
 return !(size<24 || size!=24+(uint64_t)u32(c+20)*8 || u32(c+8)!=1);
}
static bool parse_hint(struct image *im,const uint8_t *c,uint32_t size)
{
 return size==16 && region(im,u32(c+8),u32(c+12));
}
static bool parse_command(struct image *im,const uint8_t *c,uint32_t size,uint32_t cmd)
{
 switch(cmd){
 case 0x19:return parse_segment(im,c,size);
 case 2:return parse_symtab(im,c,size);
 case 0xb:return parse_dysymtab(im,c,size);
 case 0x32:return parse_build_version(c,size);
 case 0x2d:return fail(im,SKY_MACHO_LINKER_OPTION);
 case 0x2e:return parse_hint(im,c,size);
 default:return false;
 }
}
static bool parse_command_at(struct image *im,size_t *pos,size_t end)
{
 if(*pos>end || end-*pos<8)return fail(im,SKY_MACHO_BOUNDS);
 const uint8_t *c=im->b+*pos;uint32_t cmd=u32(c),size=u32(c+4);
 if(size<8 || size%8 || size>end-*pos)return fail(im,SKY_MACHO_BOUNDS);
 if(!parse_command(im,c,size,cmd))return false;
 *pos+=size;return true;
}
static bool table_bounds(struct image *im,size_t pos,size_t end)
{
 return !(pos!=end || !im->ns || !im->total || !im->syms || !im->nstr || im->nsyms>4096 ||
  !region(im,im->sym,(uint64_t)im->nsyms*16) || !region(im,im->str,im->nstr));
}
static bool table_partitions(const struct image *im)
{
 return !(im->dysym && (im->partitions[0]!=0 || im->partitions[1]>im->nsyms ||
  im->partitions[2]!=im->partitions[1] || im->partitions[3]!=im->nsyms-im->partitions[1] ||
  im->partitions[4]!=im->nsyms || im->partitions[5]!=0));
}
static bool descriptor_names(struct image *im)
{
 unsigned names=0;
 for(uint32_t i=0;i<im->nsyms;i++){
  const uint8_t *s=im->b+im->sym+(size_t)i*16;uint32_t off=u32(s);
  if(off>=im->nstr || !memchr(im->b+im->str+off,0,im->nstr-off))return fail(im,SKY_MACHO_BOUNDS);
  if(!strcmp((const char *)im->b+im->str+off,"_sky_hud_part_v1") && ++names>1)return fail(im,SKY_MACHO_DUPLICATE);
 }
 if(!names)return fail(im,SKY_MACHO_MISSING);
 return true;
}
static bool symbol_kind(struct image *im,unsigned type,uint32_t desc)
{
 if(desc&0x100)return fail(im,SKY_MACHO_RESOLVER);
 if((type&14)==0 || (desc&0x40))return fail(im,SKY_MACHO_UNDEFINED);
 if((type&14)==10)return fail(im,SKY_MACHO_INDIRECT);
 return true;
}
static bool symbol_shape(const struct image *im,uint32_t off,unsigned type,unsigned sect,uint32_t desc)
{
 return !(off>=im->nstr || !memchr(im->b+im->str+off,0,im->nstr-off) ||
  (type&0xe0) || (type&14)!=14 || (desc&0x1c0) || !sect || sect>im->ns);
}
static bool parse_descriptor(struct image *im,const struct section *sec,uint64_t value,
 unsigned type,unsigned sect,unsigned *matches)
{
 if(++*matches!=1 || !(type&1) || !sec->keep || sec->text || sec->type!=0 || value-sec->old>sec->size || sec->size-(value-sec->old)<16)return false;
 im->descriptor=sect-1;im->desc_offset=value-sec->old;
 /* Retained sections map at >=16-byte alignment; the arm64 descriptor needs 8. */
 if(im->desc_offset&7u)return fail(im,SKY_MACHO_ABI);
 const uint8_t *p=im->b+sec->off+(size_t)im->desc_offset;
 if(u32(p)!=1 || u32(p+4)!=16u)return fail(im,SKY_MACHO_ABI);
 return true;
}
static bool parse_symbol(struct image *im,uint32_t i,unsigned *matches)
{
 const uint8_t *s=im->b+im->sym+(size_t)i*16;uint32_t off=u32(s);unsigned type=s[4],sect=s[5];uint32_t desc=(uint32_t)s[6]|(uint32_t)s[7]<<8;
 if(!symbol_kind(im,type,desc))return false;
 if(!symbol_shape(im,off,type,sect,desc))return false;
 struct section *sec=&im->sec[sect-1];uint64_t value=u64(s+8);
 if(value<sec->old || value-sec->old>sec->size)return false;
 const char *sym=(const char *)im->b+im->str+off;bool descriptor=!strcmp(sym,"_sky_hud_part_v1");
 if((type&1) && !descriptor)return false;
 if(im->dysym && ((i<im->partitions[1])==((type&1)!=0)))return false;
 if(descriptor)return parse_descriptor(im,sec,value,type,sect,matches);
 return true;
}
static bool parse_header(struct image *im)
{
 if(im->n<32)return fail(im,SKY_MACHO_BOUNDS);
 if(u32(im->b)!=0xfeedfacfu || u32(im->b+12)!=1 || u32(im->b+28))return false;
 /* Only MH_SUBSECTIONS_VIA_SYMBOLS is supported; loader/dynamic flags refuse. */
 if(u32(im->b+24)&~UINT32_C(0x2000))return false;
 if(u32(im->b+4)!=0x100000cu || u32(im->b+8)!=0)return fail(im,SKY_MACHO_TARGET);
 return true;
}
static bool sky_macho_parse(struct image *im)
{
 if(!parse_header(im))return false;
 uint32_t count=u32(im->b+16),bytes=u32(im->b+20);
 if(count>64 || !region(im,0,32+(uint64_t)bytes))return false;
 size_t pos=32,end=32+(size_t)bytes;
 for(uint32_t i=0;i<count;i++)if(!parse_command_at(im,&pos,end))return false;
 if(!table_bounds(im,pos,end))return false;
 if(!table_partitions(im))return false;
 if(!descriptor_names(im))return false;
 unsigned matches=0;
 for(uint32_t i=0;i<im->nsyms;i++)if(!parse_symbol(im,i,&matches))return false;
 return matches==1;
}
static bool target(const struct image *im,uint32_t symbol,bool external,uint64_t *value,unsigned *section) {
 if(external) {
 if(symbol>=im->nsyms)return false;
 const uint8_t *s=im->b+im->sym+(size_t)symbol*16;
 *section=s[5]-1u;
 if(*section>=im->ns || !im->sec[*section].keep)return false;
 *value=(im->base+im->sec[*section].mapped)+(u64(s+8)-im->sec[*section].old);
 }else {
 if(!symbol || symbol>im->ns || !im->sec[symbol-1].keep)return false;
 *section=symbol-1;*value=(im->base+im->sec[*section].mapped);
 }
 return true;
}
static bool plus(uint64_t v,int64_t a,uint64_t *out) {
 if(a>=0){if(v>UINT64_MAX-(uint64_t)a)return false;*out=v+(uint64_t)a;}
 else {uint64_t n=(uint64_t)(-(a+1))+1;if(v<n)return false;*out=v-n;}
 return true;
}
static bool write_plan(struct image *im,size_t off,unsigned width,uint64_t value) {
 if(im->np==MAX_FIXUPS)return false;
 for(unsigned i=0;i<im->np;i++)if(off<im->plan[i].off+im->plan[i].width && im->plan[i].off<off+width)return false;
 im->plan[im->np++]=(struct fixup){off,value,width};return true;
}
/* Discarding unwind bytes does not waive strict structural relocation checks. */
static bool discarded_record(const struct image *,const struct section *,uint32_t);
static bool discarded_disjoint(const struct image *im,const struct section *sec,
 uint32_t j,uint32_t at,unsigned width)
{
 for(uint32_t k=0;k<j;k++) {
 const uint8_t *p=im->b+sec->rel+(size_t)k*8;
 uint32_t pa=u32(p),pw=1u<<((u32(p+4)>>25)&3);
 if(pa<=at ? at-pa<pw : pa-at<width)return false;
 }
 return true;
}
static bool discarded_relocations(const struct image *im,const struct section *sec)
{
 if(sec->nrel>MAX_FIXUPS)return false;
 for(uint32_t j=0;j<sec->nrel;j++){
  if(!discarded_record(im,sec,j))return false;
  const uint8_t *r=im->b+sec->rel+(size_t)j*8;
  uint32_t at=u32(r);unsigned width=1u<<((u32(r+4)>>25)&3);
  if(!discarded_disjoint(im,sec,j,at,width))return false;
 }
 return true;
}

struct macho_relocation {
 uint32_t at,info;unsigned type,length,width;
 bool ext,pc,addend;int64_t prefix;
};
static bool read_relocation(const struct image *im,const struct section *sec,
 uint32_t *j,struct macho_relocation *v)
{
 const uint8_t *r=im->b+sec->rel+(size_t)*j*8;
 uint32_t at=u32(r),info=u32(r+4);int64_t prefix=0;bool addend=false;
 if((info>>28)==10)return false;
 *v=(struct macho_relocation){.at=at,.info=info,.type=info>>28,
  .length=(info>>25)&3,.width=1u<<((info>>25)&3),
  .ext=(info&(1u<<27))!=0,.pc=(info&(1u<<24))!=0,
  .addend=addend,.prefix=prefix};
 return true;
}
static bool relocation_kind(const struct macho_relocation *r)
{
 return r->type==0 || r->type==2 || r->type==3 || r->type==4;
}
static bool relocation_shape(const struct section *sec,const struct macho_relocation *r)
{
 return !(r->type==0 ? (r->pc || r->length!=3 || sec->text) :
  (r->length!=2 || r->pc!=(r->type!=4) || !sec->text || (r->at&3)));
}
static bool descriptor_relocation(const struct image *im,unsigned i,
 const struct macho_relocation *r,unsigned *fixups)
{
 if(i==im->descriptor && r->at<im->desc_offset+16 && im->desc_offset<r->at+r->width){
  if(r->at!=im->desc_offset+8 || r->type!=0 || r->width!=8)return false;
  (*fixups)++;
 }
 return true;
}
static bool plan_unsigned(const struct image *im,unsigned i,
 uint32_t at,bool ext,uint64_t s,unsigned ts,const uint8_t *raw,uint64_t *out)
{
 uint64_t v=0;

 uint64_t original=u64(raw);
 if(ext){if(!plus(s,(original<=INT64_MAX?(int64_t)original:-1-(int64_t)(UINT64_MAX-original)),&v))return false;}
 else {if(original<im->sec[ts].old || original-im->sec[ts].old>=im->sec[ts].size)return false;v=s+(original-im->sec[ts].old);}
 if(v<(im->base+im->sec[ts].mapped) || v-(im->base+im->sec[ts].mapped)>=im->sec[ts].size)return false;
 if(i==im->descriptor && at==im->desc_offset+8 && (!im->sec[ts].text || (v&3)))return false;

 *out=v;return true;
}
static bool decode_pageoff(uint32_t op,int64_t *out)
{
 int64_t a=0;

 if((op&0x7f000000u)==0x11000000u){if(op&(1u<<22))return false;a=(int64_t)((op>>10)&4095u);}
 else if((op&0x3b000000u)==0x39000000u) {
 unsigned scale=op>>30;if((op&(1u<<26)) && (op&(1u<<23))) {if(scale)return false;scale=4;}
 a=(int64_t)(((op>>10)&4095u)<<scale);
 }else return false;

 *out=a;return true;
}
static bool decode_instruction(const struct image *im,unsigned ts,
 unsigned type,uint32_t op,int64_t *out)
{
 int64_t a=0;
 if(type==2) {
 if((op&0x7c000000u)!=0x14000000u || !im->sec[ts].text)return false;
 a=sx(op&0x3ffffffu,26)*4;
 }else if(type==3) {
 if((op&0x9f000000u)!=0x90000000u)return false;
 a=sx(((op>>29)&3u)|((uint64_t)((op>>5)&0x7ffffu)<<2),21)*4096;
 }else {
 if(!decode_pageoff(op,&a))return false;
 }

 *out=a;return true;
}
/* Resolve declared addresses even when either section is discarded. No mapped
 * destination or fixup is produced by this validation. */
static bool declared_target(const struct image *im,uint32_t symbol,bool external,
 uint64_t *value,unsigned *section)
{
 if(external){
  if(symbol>=im->nsyms)return false;
  const uint8_t *s=im->b+im->sym+(size_t)symbol*16;
  *section=s[5]-1u;*value=u64(s+8);
 }else{
  if(!symbol || symbol>im->ns)return false;
  *section=symbol-1;*value=im->sec[*section].old;
 }
 return *section<im->ns;
}
static bool declared_destination(const struct image *im,const struct section *sec,
 const struct macho_relocation *r)
{
 uint64_t start,dest;unsigned ts;
 if(!declared_target(im,r->info&0xffffffu,r->ext,&start,&ts))return false;
 const uint8_t *raw=im->b+sec->off+r->at;
 if(r->type==0){
  uint64_t value=u64(raw);
  if(r->ext){
   int64_t addend=value<=INT64_MAX?(int64_t)value:-1-(int64_t)(UINT64_MAX-value);
   if(!plus(start,addend,&dest))return false;
  }
  else dest=value;
 }else{
  int64_t addend;
  if(!r->ext || !decode_instruction(im,ts,r->type,u32(raw),&addend) || !plus(start,addend,&dest))return false;
  if(r->type==2 && ((sec->old+r->at)&3u || (dest&3u)))return false;
 }
 return dest>=im->sec[ts].old && dest-im->sec[ts].old<im->sec[ts].size;
}
static bool discarded_record(const struct image *im,const struct section *sec,uint32_t j)
{
 struct macho_relocation r;
 if(!read_relocation(im,sec,&j,&r))return false;
 if(r.at&0x80000000u || r.at>sec->size || r.width>sec->size-r.at)return false;
 if(r.type!=0 && r.type!=2)return false;
 if(r.type==0 ? (r.pc || r.length!=3) : (r.length!=2 || !r.pc || (r.at&3)))return false;
 return declared_destination(im,sec,&r);
}
static bool emit_branch(uint64_t dest,uint64_t p,uint32_t op,uint64_t *out)
{
 uint64_t v=0;

 int64_t d=(int64_t)dest-(int64_t)p;
 if((d%4)!=0 || d<-(INT64_C(1)<<27) || d>=(INT64_C(1)<<27))return false;
 v=(op&0xfc000000u)|((uint64_t)(d/4)&0x3ffffffu);

 *out=v;return true;
}
static bool emit_page(uint64_t dest,uint64_t p,uint32_t op,uint64_t *out)
{
 uint64_t v=0;

 int64_t d=((int64_t)(dest&~UINT64_C(4095))-(int64_t)(p&~UINT64_C(4095)))/4096;
 if(d<-(INT64_C(1)<<20) || d>=(INT64_C(1)<<20))return false;
 uint32_t imm=(uint32_t)((uint64_t)d&0x1fffffu);
 v=(op&~UINT32_C(0x60ffffe0))|((imm&3u)<<29)|((imm>>2)<<5);

 *out=v;return true;
}
static bool emit_pageoff(uint64_t dest,uint32_t op,uint64_t *out)
{
 uint64_t v=0;

 uint32_t low=(uint32_t)(dest&4095u);unsigned scale=0;
 if((op&0x3b000000u)==0x39000000u){scale=op>>30;if((op&(1u<<26)) && (op&(1u<<23)))scale=4;}
 if(low&((1u<<scale)-1u))return false;
 v=(op&~UINT32_C(0x003ffc00))|((low>>scale)<<10);

 *out=v;return true;
}
static bool emit_instruction(unsigned type,uint64_t dest,uint64_t p,uint32_t op,uint64_t *out)
{
 if(type==2)return emit_branch(dest,p,op,out);
 if(type==3)return emit_page(dest,p,op,out);
 return emit_pageoff(dest,op,out);
}
static bool plan_instruction(const struct image *im,const struct section *sec,
 uint32_t at,unsigned type,bool ext,bool addend,int64_t prefix,
 uint64_t s,unsigned ts,const uint8_t *raw,uint64_t *out)
{
 uint32_t op=u32(raw);int64_t a=0;
 uint64_t p=(im->base+sec->mapped+at);
 (void)addend;(void)prefix;
 if(!decode_instruction(im,ts,type,op,&a))return false;
 if(!ext)return false; /* Local instruction records lack symbol addend identity in this profile. */
 uint64_t dest;if(!plus(s,a,&dest))return false;
 if(dest<(im->base+im->sec[ts].mapped) || dest-(im->base+im->sec[ts].mapped)>=im->sec[ts].size)return false;

 return emit_instruction(type,dest,p,op,out);
}
static bool plan_relocation(struct image *im,unsigned i,const struct section *sec,
 const struct macho_relocation *r,unsigned *fixups)
{
 uint32_t at=r->at;
 if(at&0x80000000u || at>sec->size || r->width>sec->size-at)return false;
 if(!relocation_kind(r))return false;
 if(!relocation_shape(sec,r))return false;
 if(!declared_destination(im,sec,r))return false;
 if(!descriptor_relocation(im,i,r,fixups))return false;
 unsigned ts;uint64_t s,v=0;
 if(!target(im,r->info&0xffffffu,r->ext,&s,&ts))return false;
 const uint8_t *raw=im->b+sec->off+at;
 if(r->type==0){
  if(!plan_unsigned(im,i,at,r->ext,s,ts,raw,&v))return false;
 }else{
  if(!plan_instruction(im,sec,at,r->type,r->ext,r->addend,r->prefix,s,ts,raw,&v))return false;
 }
 return write_plan(im,sec->mapped+at,r->width,v);
}
static bool plan_section(struct image *im,unsigned i,const struct section *sec,unsigned *fixups)
{
 if(sec->nrel>MAX_FIXUPS)return false;
 for(uint32_t j=0;j<sec->nrel;j++){
  struct macho_relocation r;
  if(!read_relocation(im,sec,&j,&r))return false;
  if(!plan_relocation(im,i,sec,&r,fixups))return false;
 }
 return true;
}
static bool sky_macho_plan(struct image *im)
{
 unsigned descriptor_fixups=0;
 for(unsigned i=0;i<im->ns;i++){
  struct section *sec=&im->sec[i];
  if(!sec->keep){if(!discarded_relocations(im,sec))return false;continue;}
  if(!plan_section(im,i,sec,&descriptor_fixups))return false;
 }
 return descriptor_fixups==1;
}
/* Pure, bounded preparation used by both inert acceptance and the native loader.
 * Caller freezes bytes and initializes image before entry. base is the numeric
 * intended slot address, 16-KiB aligned; no mapped memory is accessed here. */
enum sky_macho_verdict sky_macho_prepare(struct image *im,const void *bytes,
 size_t n,const uint8_t expected[32],uint64_t base)
{
 if(!im || !bytes || !expected || !n || n>16u*1024u*1024u ||
    (base&16383u) || base>INT64_MAX-SLOT)return SKY_MACHO_ARGUMENT;
 memset(im,0,sizeof(*im));
 uint8_t digest[32];zsha256(bytes,n,digest);
 if(zsha256_compare(digest,expected))return SKY_MACHO_DIGEST;
 im->b=bytes;im->n=n;im->base=base;im->failure=SKY_MACHO_FORMAT;
 if(!sky_macho_parse(im))return im->failure;
 if(!sky_macho_plan(im))return SKY_MACHO_RELOCATION;
 return SKY_MACHO_ADMIT;
}
enum sky_macho_verdict sky_part_admit_macho(const void *bytes,size_t n,
 const uint8_t expected[32])
{
 struct image *im=calloc(1,sizeof(*im));
 if(!im){fprintf(stderr,"sky_part_admit_macho: image allocation failed\n");return SKY_MACHO_ARGUMENT;}
 enum sky_macho_verdict result=sky_macho_prepare(im,bytes,n,expected,UINT64_C(0x100000000));
 free(im);return result;
}
/* Only the loader's already-prepared private image may be rebased. */
bool sky_macho_rebase(struct image *im,uint64_t base)
{
 if(!im || (base&16383u) || base>INT64_MAX-SLOT)return false;
 im->base=base;im->np=0;return sky_macho_plan(im);
}
