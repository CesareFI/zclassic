/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: Verify exact Mach-O fixture admission and private-snapshot open gating in the canonical runner. */
#include "test/test_core.h"
static void *macho_image_allocate(size_t,size_t);
#define calloc macho_image_allocate
#include "../../../apps/skycombat/part/macho_admission.c"
#undef calloc
#include "../../../apps/skycombat/part/macho_fixture_a.h"
#include "../../../apps/skycombat/part/macho_fixture_b.h"
#include "../../../apps/skycombat/part/macho_fixture_b_tampered.h"
#include "../../../apps/skycombat/part/macho_fixture_strict_fixture.h"
#include "../../../apps/skycombat/part/macho_load.h"
/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: Preserve exact clang-assembled arm64 refusal seed bytes for portable registered tests. */
static const unsigned char macho_refusal_fixture[]={
207,250,237,254,12,0,0,1,0,0,0,0,1,0,0,0,
4,0,0,0,8,2,0,0,0,0,0,0,0,0,0,0,
25,0,0,0,136,1,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
80,0,0,0,0,0,0,0,40,2,0,0,0,0,0,0,
80,0,0,0,0,0,0,0,7,0,0,0,7,0,0,0,
4,0,0,0,0,0,0,0,95,95,116,101,120,116,0,0,
0,0,0,0,0,0,0,0,95,95,84,69,88,84,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
24,0,0,0,0,0,0,0,40,2,0,0,2,0,0,0,
120,2,0,0,3,0,0,0,0,4,0,128,0,0,0,0,
0,0,0,0,0,0,0,0,95,95,99,111,110,115,116,0,
0,0,0,0,0,0,0,0,95,95,84,69,88,84,0,0,
0,0,0,0,0,0,0,0,24,0,0,0,0,0,0,0,
24,0,0,0,0,0,0,0,64,2,0,0,3,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,95,95,99,111,110,115,116,0,
0,0,0,0,0,0,0,0,95,95,68,65,84,65,0,0,
0,0,0,0,0,0,0,0,48,0,0,0,0,0,0,0,
16,0,0,0,0,0,0,0,88,2,0,0,3,0,0,0,
144,2,0,0,1,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,95,95,99,111,110,115,116,0,
0,0,0,0,0,0,0,0,95,95,68,65,84,65,95,67,
79,78,83,84,0,0,0,0,64,0,0,0,0,0,0,0,
16,0,0,0,0,0,0,0,104,2,0,0,3,0,0,0,
152,2,0,0,2,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,50,0,0,0,24,0,0,0,
1,0,0,0,0,0,11,0,0,0,0,0,0,0,0,0,
2,0,0,0,24,0,0,0,168,2,0,0,8,0,0,0,
40,3,0,0,64,0,0,0,11,0,0,0,80,0,0,0,
0,0,0,0,7,0,0,0,7,0,0,0,1,0,0,0,
8,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,192,3,95,214,255,255,255,151,
0,0,0,144,0,0,0,145,1,0,64,249,192,3,95,214,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,1,0,0,0,16,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,16,0,0,0,3,0,0,76,
12,0,0,0,3,0,0,76,8,0,0,0,3,0,0,61,
8,0,0,0,1,0,0,14,8,0,0,0,1,0,0,14,
0,0,0,0,1,0,0,14,58,0,0,0,14,1,0,0,
0,0,0,0,0,0,0,0,17,0,0,0,14,1,0,0,
0,0,0,0,0,0,0,0,10,0,0,0,14,1,0,0,
4,0,0,0,0,0,0,0,1,0,0,0,14,2,0,0,
24,0,0,0,0,0,0,0,52,0,0,0,14,2,0,0,
24,0,0,0,0,0,0,0,29,0,0,0,14,3,0,0,
48,0,0,0,0,0,0,0,23,0,0,0,14,4,0,0,
64,0,0,0,0,0,0,0,35,0,0,0,15,3,0,0,
48,0,0,0,0,0,0,0,0,99,111,110,115,116,97,110,
116,0,99,97,108,108,101,114,0,98,117,105,108,100,0,108,
116,109,112,51,0,108,116,109,112,50,0,95,115,107,121,95,
104,117,100,95,112,97,114,116,95,118,49,0,108,116,109,112,
49,0,108,116,109,112,48,0,
};
static enum sky_load_verdict macho_test_loader(struct sky_part_host *,const void *,size_t,const uint8_t[32]);
/* Only the dispatch observation is substituted. Admission and the public
 * production gate below execute the exact application implementations. */
#define sky_part_load macho_test_loader
#define sky_part_open macho_test_open
#include "../../../apps/skycombat/part/part_open.c"
#undef sky_part_load
#undef sky_part_open
static unsigned tests,failed,calls;
static const uint8_t *wanted;
static size_t wanted_n;
static uint8_t wanted_hash[32];
static enum sky_load_verdict inject=SKY_LOAD_OK;
static bool deny_admission_image;
static void *macho_image_allocate(size_t count,size_t size)
{
 return deny_admission_image?NULL:calloc(count,size);
}
#define MACHO_CHECK(x) do { if(!(x)){fprintf(stderr,"FAIL %u: %s\n",(unsigned)__LINE__,#x);failed++;} } while(0)
static enum sky_load_verdict macho_test_loader(struct sky_part_host *h,const void *b,size_t n,const uint8_t d[32])
{
 calls++;MACHO_CHECK(h!=NULL);MACHO_CHECK(n==wanted_n);MACHO_CHECK(b!=wanted);
 if(n==wanted_n){MACHO_CHECK(!memcmp(b,wanted,n));}
 MACHO_CHECK(!memcmp(d,wanted_hash,32));return inject;
}
static uint32_t r32(const unsigned char *p)
{ return (uint32_t)p[0]|(uint32_t)p[1]<<8|(uint32_t)p[2]<<16|(uint32_t)p[3]<<24; }
static void w32(unsigned char *p,uint32_t v)
{ for(unsigned i=0;i<4;++i)p[i]=(unsigned char)(v>>(i*8)); }
static void w64(unsigned char *p,uint64_t v)
{ for(unsigned i=0;i<8;++i)p[i]=(unsigned char)(v>>(i*8)); }
static void check(const char *label,const unsigned char *b,size_t n,enum sky_macho_verdict want)
{
 unsigned char hash[32];zsha256(b,n,hash);
 enum sky_macho_verdict got=sky_part_admit_macho(b,n,hash);
 ++tests;if(got!=want)++failed;
 printf("%s %s got=%u expected=%u\n",got==want?"PASS":"FAIL",label,got,want);
}
struct strict_layout {size_t segment,section,symcmd,at,ds,other,data,str;unsigned index;};
static bool locate_strict_fixture(const unsigned char *original,size_t n,struct strict_layout *out)
{
 size_t segment=0,symcmd=0,at=32;
 for(unsigned i=0;i<r32(original+16);++i) {
  if(at+8>n)return false;
  if(r32(original+at)==0x19)segment=at;
  if(r32(original+at)==2)symcmd=at;
  at+=r32(original+at+4);
 }
 if(!segment || !symcmd || at>n)return false;
 size_t section=segment+72,sym=r32(original+symcmd+8),str=r32(original+symcmd+16);
 unsigned ns=r32(original+symcmd+12),descriptor=ns;
 for(unsigned i=0;i<ns;++i)
  if(!strcmp((const char *)original+str+r32(original+sym+i*16),"_sky_hud_part_v1"))descriptor=i;
 if(descriptor==ns || ns<2)return false;
 size_t ds=sym+descriptor*16,other=sym+(descriptor?0u:1u)*16;
 unsigned index=original[ds+5];
 size_t data=r32(original+section+(index-1)*80+48);
 *out=(struct strict_layout){segment,section,symcmd,at,ds,other,data,str,index};return true;
}
static int strict_cases(void)
{
 unsigned char original[4096],b[4096];size_t n=sizeof(macho_fixture_strict_fixture);
 if(n>sizeof(original) || n<32)return 2;
 memcpy(original,macho_fixture_strict_fixture,n);
 w32(original+88,5);w32(original+92,5);
 struct strict_layout layout;
 if(!locate_strict_fixture(original,n,&layout))return 2;
 size_t segment=layout.segment,section=layout.section,symcmd=layout.symcmd,at=layout.at;
 size_t ds=layout.ds,other=layout.other,data=layout.data,str=layout.str;
 unsigned index=layout.index;
 check("real arm64 part admitted",original,n,SKY_MACHO_ADMIT);
#define MUT(label,pos,value,want) do { memcpy(b,original,n);w32(b+(pos),(value));check((label),b,n,(want)); } while(0)
 MUT("fat magic",0,0xcafebabe,SKY_MACHO_FORMAT);
 MUT("non-arm64",4,0x1000007,SKY_MACHO_TARGET);
 MUT("arm64e",8,2,SKY_MACHO_TARGET);
 MUT("not MH_OBJECT",12,2,SKY_MACHO_FORMAT);
 memcpy(b,original,n);b[other+4]=1;check("undefined symbol",b,n,SKY_MACHO_UNDEFINED);
 memcpy(b,original,n);b[other+4]=11;check("indirect symbol",b,n,SKY_MACHO_INDIRECT);
 memcpy(b,original,n);b[other+7]|=1;check("symbol resolver",b,n,SKY_MACHO_RESOLVER);
 memcpy(b,original,n);b[other+6]|=0x40;check("weak import",b,n,SKY_MACHO_UNDEFINED);
 MUT("linker option",symcmd,0x2d,SKY_MACHO_LINKER_OPTION);
 unsigned startup[]={9,10,22};
 for(unsigned i=0;i<3;++i) {
  char label[64];snprintf(label,sizeof label,"startup type %u",startup[i]);
  MUT(label,section+64,startup[i],SKY_MACHO_STARTUP);
 }
 for(unsigned type=17;type<=21;++type) {
  char label[64];snprintf(label,sizeof label,"thread-local type %u",type);
  MUT(label,section+64,type,SKY_MACHO_TLS);
 }
 memcpy(b,original,n);b[str+r32(b+ds)]='X';check("missing descriptor",b,n,SKY_MACHO_MISSING);
 MUT("duplicate descriptor",other,r32(original+ds),SKY_MACHO_DUPLICATE);
 MUT("ABI word not one",data,2,SKY_MACHO_ABI);
 check("truncated header",original,31,SKY_MACHO_BOUNDS);
 check("truncated commands",original,at-1,SKY_MACHO_BOUNDS);
 MUT("section overlaps headers",section+48,0,SKY_MACHO_OVERLAP);
 MUT("symbol table overlaps headers",symcmd+8,0,SKY_MACHO_OVERLAP);
 MUT("command header too small",segment+4,4,SKY_MACHO_BOUNDS);
 MUT("section table overlaps next command",segment+64,3,SKY_MACHO_BOUNDS);
 MUT("oversized commands",20,0xffffffffu,SKY_MACHO_BOUNDS);
 for(unsigned type=3;type<=10;++type) {
  if(type==4 || type>=5 || type==3) {
   char label[64];snprintf(label,sizeof label,"unsupported pair/addend relocation %u",type);
   size_t rel=r32(original+section+(index-1)*80+56);
   MUT(label,rel+4,(r32(original+rel+4)&0x0fffffffu)|(type<<28),SKY_MACHO_RELOCATION);
  }
 }
 unsigned char hash[32]={0};++tests;
 if(sky_part_admit_macho(original,n,hash)!=SKY_MACHO_DIGEST)++failed;
 printf("%u cases, %u failures\n",tests,failed);return failed?1:0;
}
static void refused(struct sky_part_host *h,const uint8_t *b,size_t n,
 const uint8_t d[32],enum sky_open_verdict reason)
{
 unsigned before=calls;struct sky_part_host old=*h;
 struct sky_open_result r=macho_test_open(h,b,n,d);
 MACHO_CHECK(r.verdict==reason);MACHO_CHECK(calls==before);
 MACHO_CHECK(!memcmp(h,&old,sizeof(*h)));
 if(reason==SKY_OPEN_DIGEST){MACHO_CHECK(r.admission==SKY_MACHO_DIGEST);}
 if(reason==SKY_OPEN_ADMISSION){MACHO_CHECK(r.admission!=SKY_MACHO_ADMIT);}
}
/* Each transient mutation starts from the exact compiler-produced A bytes.
 * The strict profile's RX declarations are the only seed normalization. */
static void assurance_seed(uint8_t *b)
{
 memcpy(b,macho_fixture_a,sizeof(macho_fixture_a));
 w32(b+32+56,5);w32(b+32+60,5);
}
static void assurance_mutation(const char *label,size_t at,uint64_t value,
 unsigned width,enum sky_macho_verdict reason)
{
 uint8_t b[sizeof(macho_fixture_a)];assurance_seed(b);
 if(width==8)w64(b+at,value);else w32(b+at,(uint32_t)value);
 check(label,b,sizeof(b),reason);
 uint8_t hash[32];zsha256(b,sizeof(b),hash);
 struct sky_part_host h={0};refused(&h,b,sizeof(b),hash,SKY_OPEN_ADMISSION);
}
/* MH_OBJECT segment declarations describe the compiler's combined sections,
 * not receiver mapping rights. Keep exact unmodified compiler bytes. */
static void compiler_object_cases(void)
{
 const uint8_t *fixtures[]={macho_fixture_a,macho_fixture_b,macho_fixture_strict_fixture};
 const size_t sizes[]={sizeof(macho_fixture_a),sizeof(macho_fixture_b),sizeof(macho_fixture_strict_fixture)};
 const char *labels[]={"raw compiler A 7/7 admitted","raw compiler B 7/7 admitted","raw strict compiler 7/7 admitted"};
 for(unsigned i=0;i<3;i++){
  MACHO_CHECK(r32(fixtures[i]+88)==7 && r32(fixtures[i]+92)==7);
  check(labels[i],fixtures[i],sizes[i],SKY_MACHO_ADMIT);
  uint8_t digest[32];zsha256(fixtures[i],sizes[i],digest);
  wanted=fixtures[i];wanted_n=sizes[i];memcpy(wanted_hash,digest,32);
  struct sky_part_host h={0};unsigned before=calls;
  struct sky_open_result r=macho_test_open(&h,fixtures[i],sizes[i],digest);
  MACHO_CHECK(r.verdict==SKY_OPEN_OK && r.admission==SKY_MACHO_ADMIT);
  MACHO_CHECK(r.loader==SKY_LOAD_OK && calls==before+1);
 }
 uint8_t b[sizeof(macho_fixture_strict_fixture)];
 memcpy(b,macho_fixture_strict_fixture,sizeof(b));w32(b+92,5);
 check("segment 7/5 declarations admitted",b,sizeof(b),SKY_MACHO_ADMIT);
 w32(b+92,3);check("segment 7/3 declarations admitted",b,sizeof(b),SKY_MACHO_ADMIT);
 /* An RX segment seed isolates section refusal from segment metadata. */
 w32(b+88,5);w32(b+92,5);
 struct strict_layout layout;
 if(!locate_strict_fixture(b,sizeof(b),&layout)){MACHO_CHECK(false);return;}
 size_t section=layout.section+(layout.index-1u)*80;
 MACHO_CHECK(!memcmp(b+section+16,"__DATA",6));
 w32(b+section+64,0x80000000u);
 check("data section marked pure executable refuses",b,sizeof(b),SKY_MACHO_FORMAT);
 w32(b+section+64,0x400u);
 check("data section marked partly executable refuses",b,sizeof(b),SKY_MACHO_FORMAT);
 w32(b+section+64,0x80000400u);
 memset(b+section,0,16);memcpy(b+section,"__data",6);
 check("writable data plus executable section refuses",b,sizeof(b),SKY_MACHO_FORMAT);
}
static void assurance_cases(void)
{
 compiler_object_cases();
 assurance_mutation("G1 initprot beyond maxprot",88,1,4,SKY_MACHO_FORMAT);
 assurance_mutation("G1 unknown protection bits",88,13,4,SKY_MACHO_FORMAT);
 assurance_mutation("G2 unknown header flags",24,0x80002000u,4,SKY_MACHO_FORMAT);
 assurance_mutation("G2 dynamic-loader header claim",24,0x2004u,4,SKY_MACHO_FORMAT);
 assurance_mutation("G2 segment VM overflow",56,UINT64_MAX,8,SKY_MACHO_FORMAT);
 assurance_mutation("G2 section below segment",56,16,8,SKY_MACHO_FORMAT);
 assurance_mutation("G2 section beyond VM extent",64,1,8,SKY_MACHO_FORMAT);
 assurance_mutation("G2 section beyond file extent",80,1,8,SKY_MACHO_FORMAT);
 assurance_mutation("G2 nonzero segment flags",100,1,4,SKY_MACHO_FORMAT);
}
/* Shift the fixed compiler fixture's descriptor one byte inside its section.
 * Adjust all affected extents/tables, preserving valid ABI bytes and fixup. */
static void descriptor_alignment_case(void)
{
 const uint8_t *original=macho_fixture_strict_fixture;
 const size_t n=sizeof(macho_fixture_strict_fixture);
 uint8_t b[sizeof(macho_fixture_strict_fixture)+1];
 struct strict_layout layout;
 if(!locate_strict_fixture(original,n,&layout)){MACHO_CHECK(false);return;}
 size_t section=layout.section+(layout.index-1u)*80;
 size_t off=layout.data,rel=r32(original+section+56);
 memcpy(b,original,off);b[off]=0;
 memcpy(b+off+1,original+off,n-off);
 w32(b+layout.segment+56,5);w32(b+layout.segment+60,5);
 w64(b+layout.segment+32,(uint64_t)r32(original+layout.segment+32)+1);
 w64(b+layout.segment+48,(uint64_t)r32(original+layout.segment+48)+1);
 w64(b+section+40,(uint64_t)r32(original+section+40)+1);
 w32(b+section+56,(uint32_t)rel+1);
 w32(b+layout.symcmd+8,r32(original+layout.symcmd+8)+1);
 w32(b+layout.symcmd+16,r32(original+layout.symcmd+16)+1);
 w32(b+rel+1,r32(original+rel)+1);
 w64(b+layout.ds+1+8,(uint64_t)r32(original+layout.ds+8)+1);
 check("unaligned descriptor refuses before native mapping",b,sizeof(b),SKY_MACHO_ABI);
 uint8_t digest[32];zsha256(b,sizeof(b),digest);
 struct sky_part_host h={0};refused(&h,b,sizeof(b),digest,SKY_OPEN_ADMISSION);
}
static size_t discarded_seed(uint8_t b[4096],size_t *data,size_t *rel)
{
 struct strict_layout layout;
 const uint8_t *original=macho_fixture_strict_fixture;
 size_t n=sizeof(macho_fixture_strict_fixture);
 if(!locate_strict_fixture(original,n,&layout))return 0;
 size_t end=layout.segment+r32(original+layout.segment+4);
 memcpy(b,original,end);memcpy(b+end+80,original+end,n-end);
 memset(b+end,0,80);
 w32(b+20,r32(b+20)+80);w32(b+layout.segment+4,r32(b+layout.segment+4)+80);
 unsigned ns=r32(b+layout.segment+64);w32(b+layout.segment+64,ns+1);
 w64(b+layout.segment+40,r32(original+layout.segment+40)+80);
 w64(b+layout.segment+48,n+16-r32(original+layout.segment+40));
 w64(b+layout.segment+32,40);w32(b+layout.segment+56,5);w32(b+layout.segment+60,5);
 for(unsigned i=0;i<ns;i++){
  size_t s=layout.section+80*i;
  w32(b+s+48,r32(b+s+48)+80);
  if(r32(b+s+60))w32(b+s+56,r32(b+s+56)+80);
 }
 size_t symcmd=layout.symcmd+80;
 w32(b+symcmd+8,r32(b+symcmd+8)+80);w32(b+symcmd+16,r32(b+symcmd+16)+80);
 memcpy(b+end,"__eh_frame",11);memcpy(b+end+16,"__TEXT",7);
 w64(b+end+32,24);w64(b+end+40,16);w32(b+end+52,3);
 *data=n+80;*rel=*data+16;
 w32(b+end+48,(uint32_t)*data);w32(b+end+56,(uint32_t)*rel);w32(b+end+60,1);
 memset(b+*data,0,24);
 unsigned target=(unsigned)((layout.other-r32(original+layout.symcmd+8))/16);
 w32(b+*rel+4,0x0e000000u|target);
 return *rel+8;
}
static void discarded_cases(void)
{
 uint8_t original[4096],b[4096];size_t data,rel;
 size_t n=discarded_seed(original,&data,&rel);
 if(!n){MACHO_CHECK(false);return;}
 check("G3 derived compiler object with valid dropped relocation",original,n,SKY_MACHO_ADMIT);
#define DROP(label,pos,value,width) do {memcpy(b,original,n);if((width)==8)w64(b+(pos),(value));else w32(b+(pos),(uint32_t)(value));check((label),b,n,SKY_MACHO_RELOCATION);} while(0)
 DROP("G3 discarded effective destination overflow",data,INT64_MAX,8);
 DROP("G3 discarded effective destination underflow",data,UINT64_MAX,8);
 DROP("G3 discarded effective destination one-past",data,8,8);
 memcpy(b,original,n);w32(b+rel+4,0x2d000000u|(r32(b+rel+4)&0xffffffu));
 w32(b+rel,1);w32(b+data+1,0x14000000u);
 check("G3 discarded branch unaligned",b,n,SKY_MACHO_RELOCATION);
 DROP("G3 discarded branch wrong opcode",rel+4,0x2d000000u|(r32(original+rel+4)&0xffffffu),4);
 memcpy(b,original,n);w32(b+rel+4,0x06000003u);w64(b+data,24);
 check("G3 dropped source resolves dropped local target",b,n,SKY_MACHO_ADMIT);
 w64(b+data,40);check("G3 dropped target one-past refuses",b,n,SKY_MACHO_RELOCATION);
 memcpy(b,original,n);memcpy(b+264,"__compact_unwind",16);
 memset(b+280,0,16);memcpy(b+280,"__LD",5);
 check("G3 full-width compact_unwind name accepted",b,n,SKY_MACHO_ADMIT);
#undef DROP
}
int test_skycombat_macho_parts(void);
int macho_vm_cases(void);
static void direct_argument_cases(void)
{
 const uint8_t *b=macho_fixture_a;size_t n=sizeof(macho_fixture_a);
 uint8_t d[32];zsha256(b,n,d);
 struct image *im=calloc(1,sizeof(*im));
 if(!im){MACHO_CHECK(false);return;}
 MACHO_CHECK(sky_part_admit_macho(NULL,n,d)==SKY_MACHO_ARGUMENT);
 MACHO_CHECK(sky_part_admit_macho(b,n,NULL)==SKY_MACHO_ARGUMENT);
 MACHO_CHECK(sky_part_admit_macho(b,0,d)==SKY_MACHO_ARGUMENT);
 MACHO_CHECK(sky_part_admit_macho(b,16u*1024u*1024u+1u,d)==SKY_MACHO_ARGUMENT);
 MACHO_CHECK(sky_macho_prepare(NULL,b,n,d,UINT64_C(0x100000000))==SKY_MACHO_ARGUMENT);
 MACHO_CHECK(sky_macho_prepare(im,b,n,d,1)==SKY_MACHO_ARGUMENT);
 MACHO_CHECK(sky_macho_prepare(im,b,n,d,UINT64_C(0x8000000000000000))==SKY_MACHO_ARGUMENT);
 MACHO_CHECK(!sky_macho_rebase(NULL,UINT64_C(0x100000000)));
 MACHO_CHECK(!sky_macho_rebase(im,1));
 MACHO_CHECK(!sky_macho_rebase(im,UINT64_C(0x8000000000000000)));
 d[17]^=1;MACHO_CHECK(sky_part_admit_macho(b,n,d)==SKY_MACHO_DIGEST);
 deny_admission_image=true;MACHO_CHECK(sky_part_admit_macho(b,n,d)==SKY_MACHO_ARGUMENT);deny_admission_image=false;
 free(im);
 printf("direct admission NULL/zero/oversize/base/digest checks complete\n");
}
static void assembled_mutation(const char *label,size_t at,uint64_t value,
 unsigned width,enum sky_macho_verdict verdict)
{
 uint8_t b[sizeof(macho_refusal_fixture)];memcpy(b,macho_refusal_fixture,sizeof(b));
 if(width==8)w64(b+at,value);else if(width==1)b[at]=(uint8_t)value;else w32(b+at,(uint32_t)value);
 check(label,b,sizeof(b),verdict);
}
static size_t fixture_command(uint32_t kind)
{
 size_t at=32;
 for(unsigned i=0;i<r32(macho_refusal_fixture+16);i++){
  if(r32(macho_refusal_fixture+at)==kind)return at;
  at+=r32(macho_refusal_fixture+at+4);
 }
 MACHO_CHECK(false);return 0;
}
static void assembled_structure_cases(void)
{
 const uint8_t *b=macho_refusal_fixture;
 size_t seg=fixture_command(0x19),sym=fixture_command(2),dy=fixture_command(0xb),bv=fixture_command(0x32),s=seg+72;
 struct mutation {const char *label;size_t at;uint64_t value;unsigned width;enum sky_macho_verdict verdict;};
 const struct mutation cases[]={
  {"R segment hidden name byte",seg+12,1,4,SKY_MACHO_FORMAT},
  {"R segment file offset out of bounds",seg+40,sizeof(macho_refusal_fixture)+1,8,SKY_MACHO_FORMAT},
  {"R section VM addition overflow",s+32,UINT64_MAX,8,SKY_MACHO_FORMAT},
  {"R section start beyond segment",s+32,81,8,SKY_MACHO_FORMAT},
  {"R section exceeds slot",s+40,SLOT+1,8,SKY_MACHO_FORMAT},
  {"R section alignment exceeds cap",s+52,15,4,SKY_MACHO_FORMAT},
  {"R section reserved1",s+68,1,4,SKY_MACHO_FORMAT},
  {"R section reserved2",s+72,1,4,SKY_MACHO_FORMAT},
  {"R section reserved3",s+76,1,4,SKY_MACHO_FORMAT},
  {"R unknown section type",s+64,1,4,SKY_MACHO_FORMAT},
  {"R code cstring shape",s+64,2,4,SKY_MACHO_FORMAT},
  {"R unknown section attribute",s+64,0x80000800u,4,SKY_MACHO_FORMAT},
  {"R relocation table outside object",s+56,sizeof(macho_refusal_fixture)+1,4,SKY_MACHO_BOUNDS},
  {"R VM overlapping sections",s+80+32,0,8,SKY_MACHO_FORMAT},
  {"R segment too short",seg+4,64,4,SKY_MACHO_FORMAT},
  {"R named segment",seg+8,1,4,SKY_MACHO_FORMAT},
  {"R too many sections",seg+64,65,4,SKY_MACHO_BOUNDS},
  {"R symtab wrong size",sym+4,16,4,SKY_MACHO_FORMAT},
  {"R dysymtab wrong size",dy+4,72,4,SKY_MACHO_FORMAT},
  {"R dysymtab external metadata",dy+32,1,4,SKY_MACHO_FORMAT},
  {"R build version too short",bv+4,16,4,SKY_MACHO_FORMAT},
  {"R build version tool size",bv+20,1,4,SKY_MACHO_FORMAT},
  {"R build version wrong platform",bv+8,2,4,SKY_MACHO_FORMAT},
  {"R unknown command",bv,0x777,4,SKY_MACHO_FORMAT},
  {"R missing command header",16,r32(b+16)+1,4,SKY_MACHO_BOUNDS},
  {"R unaligned command size",seg+4,r32(b+seg+4)-1,4,SKY_MACHO_BOUNDS},
  {"R command exceeds table",seg+4,r32(b+20)+8,4,SKY_MACHO_BOUNDS},
  {"R trailing commands",16,r32(b+16)-1,4,SKY_MACHO_FORMAT},
  {"R zero string table",sym+20,0,4,SKY_MACHO_FORMAT},
  {"R excessive symbols",sym+12,4097,4,SKY_MACHO_FORMAT},
  {"R string table overlap",sym+16,0,4,SKY_MACHO_OVERLAP},
  {"R local partition start",dy+8,1,4,SKY_MACHO_FORMAT},
  {"R local partition count",dy+12,UINT32_MAX,4,SKY_MACHO_FORMAT},
  {"R external partition start",dy+16,UINT32_MAX,4,SKY_MACHO_FORMAT},
  {"R external partition count",dy+20,UINT32_MAX,4,SKY_MACHO_FORMAT},
  {"R undefined partition start",dy+24,UINT32_MAX,4,SKY_MACHO_FORMAT},
  {"R undefined partition count",dy+28,1,4,SKY_MACHO_FORMAT},
  {"R symbol name outside strings",r32(b+sym+8),UINT32_MAX,4,SKY_MACHO_BOUNDS},
  {"R nonzero header reserved",28,1,4,SKY_MACHO_FORMAT},
  {"R excessive command count",16,65,4,SKY_MACHO_FORMAT}
 };
 check("R raw assembler seed admitted",b,sizeof(macho_refusal_fixture),SKY_MACHO_ADMIT);
 for(unsigned i=0;i<sizeof(cases)/sizeof(cases[0]);i++)
  assembled_mutation(cases[i].label,cases[i].at,cases[i].value,cases[i].width,cases[i].verdict);
}
static void assembled_symbol_cases(void)
{
 const uint8_t *original=macho_refusal_fixture;size_t n=sizeof(macho_refusal_fixture);
 struct strict_layout l;
 if(!locate_strict_fixture(original,n,&l)){MACHO_CHECK(false);return;}
 size_t sym=r32(original+l.symcmd+8),s=l.section+(l.index-1u)*80;
#define SM(label,at,value,width,verdict) assembled_mutation(label,at,value,width,verdict)
 SM("R stab symbol",sym+4,0xee,1,SKY_MACHO_FORMAT);
 SM("R absolute symbol",sym+4,2,1,SKY_MACHO_FORMAT);
 SM("R weak definition",sym+6,0x80,1,SKY_MACHO_FORMAT);
 SM("R zero symbol section",sym+5,0,1,SKY_MACHO_FORMAT);
 SM("R out of range symbol section",sym+5,65,1,SKY_MACHO_FORMAT);
 SM("R symbol value beyond section",sym+8,UINT64_MAX,8,SKY_MACHO_FORMAT);
 SM("R undeclared export",sym+4,15,1,SKY_MACHO_FORMAT);
 SM("R local partition export mismatch",l.ds+4,14,1,SKY_MACHO_FORMAT);
 SM("R descriptor too short",l.ds+8,u64(original+s+32)+9,8,SKY_MACHO_FORMAT);
 SM("R descriptor wrong size word",l.data+4,15,4,SKY_MACHO_ABI);
 uint8_t b[sizeof(macho_refusal_fixture)];memcpy(b,original,n);
 b[l.ds+5]=1;w64(b+l.ds+8,0);
 check("R descriptor in code",b,n,SKY_MACHO_FORMAT);
 memcpy(b,original,n);
 /* All names start in range, but the last string has no terminator. */
 size_t str=r32(b+l.symcmd+16),len=r32(b+l.symcmd+20);
 memset(b+str,'X',len);check("R unterminated symbol names",b,n,SKY_MACHO_BOUNDS);
 memcpy(b,original,n);w32(b+fixture_command(0xb)+12,r32(b+l.symcmd+12));
 w32(b+fixture_command(0xb)+16,r32(b+l.symcmd+12));w32(b+fixture_command(0xb)+20,0);
 b[l.ds+4]=14;check("R nonexported descriptor",b,n,SKY_MACHO_FORMAT);
 /* A symbol before its own declared section is independently malformed. */
 memcpy(b,original,n);w64(b+l.ds+8,u64(b+s+32)-1);
 check("R symbol before section",b,n,SKY_MACHO_FORMAT);
#undef SM
}
static void assembled_relocation_mutation(const char *label,unsigned section,
 uint32_t at,uint32_t info,uint64_t raw,unsigned width)
{
 uint8_t b[sizeof(macho_refusal_fixture)];memcpy(b,macho_refusal_fixture,sizeof(b));
 size_t s=fixture_command(0x19)+72+section*80,rel=r32(b+s+56),data=r32(b+s+48);
 w32(b+rel,at);w32(b+rel+4,info);
 if(width==8)w64(b+data+at,raw);else if(width==4)w32(b+data+at,(uint32_t)raw);
 check(label,b,sizeof(b),SKY_MACHO_RELOCATION);
}
static void assembled_relocation_cases(void)
{
 const uint8_t *b=macho_refusal_fixture;size_t s=fixture_command(0x19)+72;
 size_t rel=r32(b+s+56),desc=s+160,dr=r32(b+desc+56);
 uint32_t ti=r32(b+rel+4),di=r32(b+dr+4);
#define RM(label,section,at,info,raw,width) assembled_relocation_mutation(label,section,at,info,raw,width)
 RM("R scattered relocation",0,0x80000000u,ti,0,0);
 RM("R relocation address past section",0,25,ti,0,0);
 RM("R relocation width past section",0,24,ti,0,0);
 RM("R unsigned PC-relative",2,8,di|0x01000000u,0,0);
 RM("R unsigned narrow width",2,8,di&~0x02000000u,0,0);
 RM("R unsigned fixup in text",0,0,di,0,8);
 RM("R instruction missing PC-relative",0,r32(b+rel),ti^0x01000000u,0,0);
 RM("R instruction fixup outside text",2,8,0x2d000001u,0x14000000u,4);
 RM("R instruction fixup misaligned",0,1,ti,0,0);
 RM("R invalid external relocation symbol",2,8,(di&0xff000000u)|0xffffffu,0,0);
 RM("R local relocation section zero",2,8,0x06000000u,0,0);
 RM("R local relocation section excessive",2,8,0x06000041u,0,0);
 RM("R local instruction relocation",0,r32(b+rel),(ti&0xf7000000u)|2u,0,0);
 RM("R unsigned effective destination below section",2,8,di,UINT64_MAX,8);
 RM("R unsigned checked add below target section",2,8,0x0e000003u,UINT64_MAX,8);
 RM("R unsigned negative in-range unaligned pointer",2,8,0x0e000002u,UINT64_MAX,8);
 RM("R unsigned effective destination beyond section",2,8,di,24,8);
 RM("R descriptor points at noncode",2,8,(di&0xff000000u)|3u,0,8);
 RM("R descriptor code pointer unaligned",2,8,di,1,8);
 RM("R ADRP wrong opcode",0,8,0x3d000003u,0xd503201fu,4);
 RM("R PAGEOFF wrong opcode",0,12,0x4c000003u,0xd503201fu,4);
 RM("R PAGEOFF shifted ADD",0,12,0x4c000003u,0x91400000u,4);
 RM("R PAGEOFF reserved SIMD scale",0,12,0x4c000003u,0x7d800000u,4);
 RM("R branch target noncode",0,4,0x2d000003u,0x14000000u,4);
 RM("R branch wrong opcode",0,4,0x2d000001u,0xd503201fu,4);
 /* Retarget the descriptor's only fixup into its ABI words. */
 RM("R descriptor fixup overlaps ABI",2,4,di,0,0);
 uint8_t m[sizeof(macho_refusal_fixture)];memcpy(m,b,sizeof(m));
 w32(m+desc+60,0);check("R descriptor fixup missing",m,sizeof(m),SKY_MACHO_RELOCATION);
 memcpy(m,b,sizeof(m));w32(m+s+60,4097);
 /* A well-bounded relocation count fixture is supplied separately below. */
 check("R excessive relocations out of file",m,sizeof(m),SKY_MACHO_BOUNDS);
#undef RM
}
static void assembled_drop_seed(uint8_t *b)
{
 memcpy(b,macho_refusal_fixture,sizeof(macho_refusal_fixture));
 size_t s=fixture_command(0x19)+72+240;
 memset(b+s,0,32);memcpy(b+s,"__compact_unwind",16);memcpy(b+s+16,"__LD",5);
}
static void assembled_dropped_cases(void)
{
 uint8_t b[sizeof(macho_refusal_fixture)],seed[sizeof(macho_refusal_fixture)];
 assembled_drop_seed(seed);size_t s=fixture_command(0x19)+72+240,rel=r32(seed+s+56);
 check("R assembler-derived dropped seed admitted",seed,sizeof(seed),SKY_MACHO_ADMIT);
 struct mutation {const char *label;size_t at;uint32_t value;};
 const struct mutation cases[]={
  {"R dropped scattered",rel,0x80000000u},
  {"R dropped address outside section",rel,17},
  {"R dropped width exceeds section",rel,16},
  {"R dropped ADDEND",rel+4,0xae000001u},
  {"R dropped unsupported relocation",rel+4,0x3d000001u},
  {"R dropped unsigned PC relative",rel+4,0x0f000001u},
  {"R dropped unsigned width",rel+4,0x0c000001u},
  {"R dropped branch width",rel+4,0x2f000001u},
  {"R dropped branch missing PC relative",rel+4,0x2c000001u},
  {"R dropped duplicate writes ascending",rel+8,8}
 };
 for(unsigned i=0;i<sizeof(cases)/sizeof(cases[0]);i++){
  memcpy(b,seed,sizeof(b));w32(b+cases[i].at,cases[i].value);
  check(cases[i].label,b,sizeof(b),SKY_MACHO_RELOCATION);
 }
 memcpy(b,seed,sizeof(b));w32(b+rel,8);w32(b+rel+8,0);
 check("R dropped disjoint reversed order",b,sizeof(b),SKY_MACHO_ADMIT);
 w32(b+rel+8,4);check("R dropped overlapping writes reversed",b,sizeof(b),SKY_MACHO_RELOCATION);
 memcpy(b,macho_refusal_fixture,sizeof(b));w32(b+rel+8,8);
 check("R retained duplicate fixups",b,sizeof(b),SKY_MACHO_RELOCATION);
 struct strict_layout l;
 if(!locate_strict_fixture(seed,sizeof(seed),&l)){MACHO_CHECK(false);return;}
 memcpy(b,seed,sizeof(b));b[l.ds+5]=4;w64(b+l.ds+8,u64(b+s+32));
 check("R descriptor in dropped section",b,sizeof(b),SKY_MACHO_FORMAT);
}
static void assembled_capacity_cases(void)
{
 size_t n=sizeof(macho_refusal_fixture),seg=fixture_command(0x19),s=seg+72;
 size_t count=4097,extra=count*8;
 uint8_t *b=calloc(1,n+SLOT+extra);
 if(!b){MACHO_CHECK(false);return;}
 memcpy(b,macho_refusal_fixture,n);w32(b+s+56,(uint32_t)n);w32(b+s+60,(uint32_t)count);
 check("R well-bounded retained relocation count",b,n+extra,SKY_MACHO_RELOCATION);
 assembled_drop_seed(b);w32(b+s+240+56,(uint32_t)n);w32(b+s+240+60,(uint32_t)count);
 check("R well-bounded dropped relocation count",b,n+extra,SKY_MACHO_RELOCATION);
 memcpy(b,macho_refusal_fixture,n);
 w32(b+s+80+48,(uint32_t)n);w64(b+s+80+40,SLOT);
 w64(b+seg+32,SLOT+24);w64(b+seg+48,n+SLOT-u64(b+seg+40));
 check("R aggregate mapped capacity",b,n+SLOT,SKY_MACHO_FORMAT);
 memcpy(b,macho_refusal_fixture,n);count=4096;
 size_t payload=n,records=payload+count*8,total=records+count*8;
 w64(b+s+240+40,count*8);w32(b+s+240+48,(uint32_t)payload);
 w32(b+s+240+56,(uint32_t)records);w32(b+s+240+60,(uint32_t)count);
 w64(b+seg+32,64+count*8);w64(b+seg+48,total-u64(b+seg+40));
 memset(b+payload,0,count*8);
 for(size_t i=0;i<count;i++){w32(b+records+i*8,(uint32_t)i*8);w32(b+records+i*8+4,0x0e000001u);}
 check("R aggregate fixup capacity",b,total,SKY_MACHO_RELOCATION);
 free(b);
}
/* Insert declarative commands, relocating existing file offsets and preserving
 * every original compiler-produced payload byte. No candidate is executed. */
static void assembled_insert_commands(uint8_t *b,size_t extra,unsigned count)
{
 size_t n=sizeof(macho_refusal_fixture),end=32+r32(macho_refusal_fixture+20);
 memcpy(b,macho_refusal_fixture,end);memset(b+end,0,extra);
 memcpy(b+end+extra,macho_refusal_fixture+end,n-end);
 w32(b+16,r32(b+16)+count);w32(b+20,r32(b+20)+(uint32_t)extra);
 size_t seg=fixture_command(0x19),sym=fixture_command(2),s=seg+72;
 w64(b+seg+40,u64(b+seg+40)+extra);
 for(unsigned i=0;i<r32(b+seg+64);i++){
  w32(b+s+i*80+48,r32(b+s+i*80+48)+(uint32_t)extra);
  if(r32(b+s+i*80+60))w32(b+s+i*80+56,r32(b+s+i*80+56)+(uint32_t)extra);
 }
 w32(b+sym+8,r32(b+sym+8)+(uint32_t)extra);
 w32(b+sym+16,r32(b+sym+16)+(uint32_t)extra);
}
static void assembled_command_cases(void)
{
 uint8_t b[sizeof(macho_refusal_fixture)+80];size_t n=sizeof(macho_refusal_fixture),end=32+r32(macho_refusal_fixture+20);
 const uint32_t kinds[]={0x19,2,0xb,0x2e};const unsigned sizes[]={72,24,80,24};
 const char *labels[]={"R duplicate segment","R duplicate symtab","R duplicate dysymtab","R hint wrong size"};
 for(unsigned i=0;i<4;i++){
  assembled_insert_commands(b,sizes[i],1);w32(b+end,kinds[i]);w32(b+end+4,sizes[i]);
  check(labels[i],b,n+sizes[i],SKY_MACHO_FORMAT);
 }
 assembled_insert_commands(b,16,1);w32(b+end,0x2e);w32(b+end+4,16);w32(b+end+12,1);
 check("R hint region overlap",b,n+16,SKY_MACHO_OVERLAP);
 w32(b+end+8,(uint32_t)n+17);check("R hint region outside object",b,n+16,SKY_MACHO_BOUNDS);
 size_t seg=fixture_command(0x19),sym=fixture_command(2);
 memcpy(b,macho_refusal_fixture,n);w32(b+seg,0x32);w32(b+seg+8,1);
 w32(b+seg+20,(r32(b+seg+4)-24)/8);
 check("R missing sections",b,n,SKY_MACHO_FORMAT);
 memcpy(b,macho_refusal_fixture,n);
 for(unsigned i=0;i<4;i++)w64(b+seg+72+i*80+40,0);
 check("R empty mapped image",b,n,SKY_MACHO_FORMAT);
 memcpy(b,macho_refusal_fixture,n);w32(b+sym,0x32);w32(b+sym+8,1);w32(b+sym+20,0);
 check("R missing symbol command",b,n,SKY_MACHO_FORMAT);
 struct strict_layout l;
 if(!locate_strict_fixture(macho_refusal_fixture,n,&l)){MACHO_CHECK(false);return;}
 memcpy(b,macho_refusal_fixture,n);size_t s=seg+72+(l.index-1u)*80;
 memset(b+s,0,32);memcpy(b+s,"__literal8",11);memcpy(b+s+16,"__TEXT",7);w32(b+s+64,4);
 check("R descriptor in typed literal section",b,n,SKY_MACHO_FORMAT);
}
static void assembled_region_capacity_case(void)
{
 /* Expand the assembler's constant-section record 64 times, then append
  * eight disjoint hint regions: 1 header + 128 section regions + 8 hints. */
 const size_t segsize=72+64*80,commands=segsize+8*16+24,head=32+commands,total=head+64*9+8;
 uint8_t *b=calloc(1,total);struct image *im=calloc(1,sizeof(*im));
 if(!b || !im){free(b);free(im);MACHO_CHECK(false);return;}
 memcpy(b,macho_refusal_fixture,32);w32(b+16,10);w32(b+20,(uint32_t)commands);
 memcpy(b+32,macho_refusal_fixture+fixture_command(0x19),72);
 w32(b+36,(uint32_t)segsize);w64(b+56,0);w64(b+64,64);
 w64(b+72,head);w64(b+80,total-head);w32(b+96,64);
 for(unsigned i=0;i<64;i++){
  size_t s=104+i*80;
  memcpy(b+s,macho_refusal_fixture+fixture_command(0x19)+152,80);
  w64(b+s+32,i);w64(b+s+40,1);w32(b+s+48,(uint32_t)head+i*9);
  w32(b+s+56,(uint32_t)head+i*9+1);w32(b+s+60,1);
 }
 for(unsigned i=0;i<8;i++){
  size_t at=32+segsize+i*16;
  w32(b+at,0x2e);w32(b+at+4,16);w32(b+at+8,(uint32_t)head+64*9+i);w32(b+at+12,1);
 }
 size_t sym=32+segsize+8*16;memcpy(b+sym,macho_refusal_fixture+fixture_command(2),24);
 uint8_t d[32];zsha256(b,total,d);
 MACHO_CHECK(sky_macho_prepare(im,b,total,d,UINT64_C(0x100000000))==SKY_MACHO_FORMAT);
 MACHO_CHECK(im->nr==sizeof(im->reg)/sizeof(im->reg[0]));
 printf("R bounded region-capacity refusal: registered=%u limit=%zu\n",im->nr,sizeof(im->reg)/sizeof(im->reg[0]));
 free(b);free(im);
}
static void assembled_target_cases(void)
{
 uint8_t b[sizeof(macho_refusal_fixture)];size_t n=sizeof(b),s=fixture_command(0x19)+72;
 size_t desc=s+160,rel=r32(macho_refusal_fixture+desc+56),drop=s+240;
 assembled_drop_seed(b);w32(b+rel+4,0x0e000006u);
 check("R external fixup targets dropped section",b,n,SKY_MACHO_RELOCATION);
 assembled_drop_seed(b);w32(b+rel+4,0x06000004u);w64(b+r32(b+desc+48)+8,64);
 check("R local fixup targets dropped section",b,n,SKY_MACHO_RELOCATION);
 memcpy(b,macho_refusal_fixture,n);w32(b+rel+4,0x06000001u);
 check("R retained local unsigned fixup admits",b,n,SKY_MACHO_ADMIT);
 size_t tr=r32(b+s+56);
 memcpy(b,macho_refusal_fixture,n);w32(b+tr,4);w32(b+tr+4,0x2d000001u);
 w32(b+r32(b+s+48)+4,0x17ffffffu);
 check("R branch addend underflow",b,n,SKY_MACHO_RELOCATION);
 struct strict_layout l;
 if(!locate_strict_fixture(macho_refusal_fixture,n,&l)){MACHO_CHECK(false);return;}
 memcpy(b,macho_refusal_fixture,n);size_t sym=r32(b+l.symcmd+8);
 w64(b+sym+16+8,1);w32(b+tr,4);w32(b+tr+4,0x2d000001u);w32(b+r32(b+s+48)+4,0x14000000u);
 check("R branch destination unaligned",b,n,SKY_MACHO_RELOCATION);
 memcpy(b,macho_refusal_fixture,n);w64(b+l.ds+8,u64(b+desc+32));
 w32(b+drop+64,4);memset(b+drop,0,32);memcpy(b+drop,"__literal16",12);memcpy(b+drop+16,"__TEXT",7);
 check("R literal type mismatch",b,n,SKY_MACHO_FORMAT);
 /* Scale alignment is checked after declared-target containment passes. */
 memcpy(b,macho_refusal_fixture,n);w64(b+sym+3*16+8,25);
 w32(b+tr,16);w32(b+tr+4,0x4c000003u);w32(b+r32(b+s+48)+16,0xf9400001u);
 check("R mapped PAGEOFF alignment",b,n,SKY_MACHO_RELOCATION);
}
static void assembled_declared_address_cases(void)
{
 uint8_t b[sizeof(macho_refusal_fixture)];size_t n=sizeof(b),seg=fixture_command(0x19),s=seg+72,symcmd=fixture_command(2);
 const uint64_t bases[]={1,UINT64_MAX-255};
 for(unsigned k=0;k<2;k++){
  memcpy(b,macho_refusal_fixture,n);uint64_t base=bases[k];w64(b+seg+24,base);
  for(unsigned i=0;i<4;i++)w64(b+s+i*80+32,u64(b+s+i*80+32)+base);
  size_t sym=r32(b+symcmd+8);
  for(unsigned i=0;i<r32(b+symcmd+12);i++)w64(b+sym+i*16+8,u64(b+sym+i*16+8)+base);
  size_t rel=r32(b+s+56),data=r32(b+s+48);
  w32(b+rel,4);w32(b+rel+4,0x2d000001u);w32(b+data+4,0x14000000u);
  if(!k)check("R declared branch source unaligned",b,n,SKY_MACHO_RELOCATION);
  else{
   size_t dd=r32(b+s+160+48);
   w64(b+dd+8,INT64_MAX);check("R declared unsigned addition overflow",b,n,SKY_MACHO_RELOCATION);
   w64(b+dd+8,0);w32(b+rel,8);w32(b+rel+4,0x3d000003u);w32(b+data+8,0xb0000000u);
   check("R declared instruction addition overflow",b,n,SKY_MACHO_RELOCATION);
  }
 }
}
static void assembled_literal_shape_cases(void)
{
 const char *names[]={"__cstring","__literal4","__literal8","__literal16"};
 uint8_t b[sizeof(macho_refusal_fixture)];size_t s=fixture_command(0x19)+152;
 for(unsigned i=0;i<4;i++){
  memcpy(b,macho_refusal_fixture,sizeof(b));memset(b+s,0,16);memcpy(b+s,names[i],strlen(names[i]));
  w32(b+s+64,0);char label[80];snprintf(label,sizeof(label),"R %s section type mismatch",names[i]);
  check(label,b,sizeof(b),SKY_MACHO_FORMAT);
 }
}
static void non_native_loader_cases(void)
{
#if !defined(__APPLE__) || !defined(__aarch64__)
 struct sky_part_host h={0};
 MACHO_CHECK(sky_part_call_begin(&h)==NULL);MACHO_CHECK(!sky_part_call_end(&h));
 MACHO_CHECK(!sky_part_host_dispose(NULL));
 h.arena=(void *)(uintptr_t)1;MACHO_CHECK(!sky_part_host_dispose(&h));h.arena=NULL;
 h.in_call=true;MACHO_CHECK(!sky_part_host_dispose(&h));h.in_call=false;
 h.current.id=1;MACHO_CHECK(!sky_part_host_dispose(&h));h.current.id=0;
 MACHO_CHECK(sky_part_host_dispose(&h));
#endif
}
static void assembled_cross_text_case(void)
{
 uint8_t b[sizeof(macho_refusal_fixture)];memcpy(b,macho_refusal_fixture,sizeof(b));
 size_t s=fixture_command(0x19)+72,other=s+80,symcmd=fixture_command(2),sym=r32(b+symcmd+8);
 memset(b+other,0,16);memcpy(b+other,"__text",7);
 w64(b+other+32,25);w64(b+other+40,23);
 for(unsigned i=0;i<r32(b+symcmd+12);i++)if(b[sym+i*16+5]==2)w64(b+sym+i*16+8,28);
 size_t rel=r32(b+s+56),data=r32(b+s+48);
 w32(b+rel,4);w32(b+rel+4,0x2d000003u);w32(b+data+4,0x14000000u);
 /* Declared site4 and destination28 align; mapped target offset3 does not. */
 check("R mapped cross-text branch displacement unaligned",b,sizeof(b),SKY_MACHO_RELOCATION);
}
int test_skycombat_macho_parts(void)
{
 int failures=0;tests=0;failed=0;calls=0;inject=SKY_LOAD_OK;
 TEST("Mach-O original 37 typed strict cases") {
  ASSERT_EQ(strict_cases(),0);ASSERT_EQ(tests,37u);
  assurance_cases();
  descriptor_alignment_case();
  discarded_cases();
  direct_argument_cases();
  assembled_structure_cases();
  assembled_symbol_cases();
  assembled_relocation_cases();
  assembled_dropped_cases();
  assembled_capacity_cases();
  assembled_command_cases();
  assembled_region_capacity_case();
  assembled_target_cases();
  assembled_declared_address_cases();
  assembled_literal_shape_cases();
  non_native_loader_cases();
  assembled_cross_text_case();
  MACHO_CHECK(macho_vm_cases()==0);
  if(failed){printf("FAIL %u assurance assertions\n",failed);failures++;}
  else printf("OK\n");
 }
 _test_next:;
 TEST("Mach-O private snapshot dispatch and typed refusal") {
  struct sky_part_host h={0};uint8_t bd[32];
  const uint8_t *fixtures[]={macho_fixture_a,macho_fixture_b,macho_fixture_b_tampered};
  const size_t sizes[]={sizeof(macho_fixture_a),sizeof(macho_fixture_b),sizeof(macho_fixture_b_tampered)};
  for(unsigned i=0;i<3;i++){
   uint8_t b[sizeof(macho_fixture_b)];size_t n=sizes[i];
   if(n>sizeof(b)){failed++;continue;}
   memcpy(b,fixtures[i],n);w32(b+88,5);w32(b+92,5);uint8_t d[32];zsha256(b,n,d);
   if(i==1)memcpy(bd,d,32);
   wanted=b;wanted_n=n;memcpy(wanted_hash,d,32);
   if(i<2){unsigned before=calls;struct sky_open_result r=macho_test_open(&h,b,n,d);
    MACHO_CHECK(r.verdict==SKY_OPEN_OK);MACHO_CHECK(r.admission==SKY_MACHO_ADMIT);
    MACHO_CHECK(r.loader==SKY_LOAD_OK);MACHO_CHECK(calls==before+1);
   }else refused(&h,b,n,bd,SKY_OPEN_DIGEST);
   uint8_t wrong[32]={0};refused(&h,b,n,wrong,SKY_OPEN_DIGEST);
   b[8]=2;zsha256(b,n,d);refused(&h,b,n,d,SKY_OPEN_ADMISSION);
  }
  MACHO_CHECK(macho_test_open(NULL,"",0,bd).verdict==SKY_OPEN_ARGUMENT);
  uint8_t admitted_a[sizeof(macho_fixture_a)];assurance_seed(admitted_a);
  wanted=admitted_a;wanted_n=sizeof(admitted_a);
  zsha256(wanted,wanted_n,wanted_hash);inject=SKY_LOAD_BUSY;
  unsigned before=calls;struct sky_open_result r=macho_test_open(&h,wanted,wanted_n,wanted_hash);
  MACHO_CHECK(r.verdict==SKY_OPEN_LOADER);MACHO_CHECK(r.loader==SKY_LOAD_BUSY);
  MACHO_CHECK(r.admission==SKY_MACHO_ADMIT);MACHO_CHECK(calls==before+1);
  inject=SKY_LOAD_OK;
#if !defined(__APPLE__) || !defined(__aarch64__)
  /* Call the actual non-native implementation, independent of the spy. */
  MACHO_CHECK(sky_part_load(&h,wanted,wanted_n,wanted_hash)==SKY_LOAD_PLATFORM);
  MACHO_CHECK(h.arena==NULL && h.current.id==0 && h.last_id==0);
  MACHO_CHECK(sky_part_host_dispose(&h));
#endif
  if(failed){printf("FAIL %u Mach-O assertions\n",failed);failures++;}
  else printf("OK\n");
 }
 return failures;
}
