/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: Publish admitted HUD generations through checked mapping-wide write-xor-execute transitions. */
#include "macho_load.h"
#include "macho_admission.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if (defined(__APPLE__) && defined(__aarch64__)) || defined(SKY_MACHO_VM_TEST)
#if !defined(SKY_MACHO_VM_TEST)
#include <sys/mman.h>
#include <libkern/OSCacheControl.h>
#endif
static enum sky_load_verdict refuse(enum sky_load_verdict v,const char *why)
{
 fprintf(stderr,"sky_part_load refusal %d: %s\n",(int)v,why);return v;
}
static enum sky_load_verdict validate_load_input(const struct sky_part_host *h,
 const void *bytes,size_t n,const uint8_t digest[32])
{
 if(!h || !bytes || !digest || !n || n>16u*1024u*1024u)return refuse(SKY_LOAD_ARGUMENT,"invalid bounded input");
 if(h->in_call)return refuse(SKY_LOAD_BUSY,"generation borrowed");
 if(h->failed)return refuse(SKY_LOAD_PLATFORM,"host requires disposal after cleanup failure");
 if(h->slot>1 || (h->current.id && (!h->arena || h->current.id!=h->last_id)))return refuse(SKY_LOAD_ARGUMENT,"invalid host lifecycle");
 if(h->last_id==UINT64_MAX)return refuse(SKY_LOAD_ID_EXHAUSTED,"id counter exhausted");
 return SKY_LOAD_OK;
}
static bool release_failed_arena(struct sky_part_host *h,void *arena)
{
 if(munmap(arena,2u*SLOT)){
  h->arena=arena;h->failed=true;
  fprintf(stderr,"sky_part_load: failed arena cleanup; host retained for disposal\n");
  return false;
 }
 return true;
}
static void write_generation(uint8_t *base,const struct image *im)
{
 memset(base,0,SLOT);
 for(unsigned i=0;i<im->ns;i++)if(im->sec[i].keep)
  memcpy(base+im->sec[i].mapped,im->b+im->sec[i].off,(size_t)im->sec[i].size);
 for(unsigned i=0;i<im->np;i++){
  const struct fixup *p=&im->plan[i];
  for(unsigned j=0;j<p->width;j++)base[p->off+j]=(uint8_t)(p->value>>(8*j));
 }
}
static enum sky_load_verdict stage_generation(struct sky_part_host *h,struct image *im)
{
 bool created=!h->arena;
 void *arena=created?mmap(NULL,2u*SLOT,PROT_NONE,MAP_PRIVATE|MAP_ANON,-1,0):h->arena;
 if(arena==MAP_FAILED)return refuse(SKY_LOAD_MEMORY,"non-executable arena reservation failed");
 unsigned slot=h->current.id?(h->slot^1u):0;
 uint8_t *base=(uint8_t *)arena+(size_t)slot*SLOT;
 enum sky_load_verdict result=SKY_LOAD_RELOCATION;
 const char *why="actual-base relocation planning refused";
 if((uintptr_t)arena>INT64_MAX-2u*SLOT || !sky_macho_rebase(im,(uint64_t)(uintptr_t)base))goto failed;
 result=SKY_LOAD_PLATFORM;why="RW staging protection refused";
 /* Whole-slot replacement removes X before enabling W. No aliases exist. */
 if(mprotect(base,SLOT,PROT_READ|PROT_WRITE))goto failed;
 write_generation(base,im);
 why="RX publication protection refused";
 if(mprotect(base,SLOT,PROT_READ|PROT_EXEC))goto failed;
 sys_icache_invalidate(base,SLOT);
 const struct sky_hud_part_v1 *part=(const void *)(base+im->sec[im->descriptor].mapped+(size_t)im->desc_offset);
 h->arena=arena;h->slot=slot;h->current=(struct sky_part_generation){++h->last_id,part};
 return SKY_LOAD_OK;
failed:
 if(created && !release_failed_arena(h,arena))why="arena cleanup failed; dispose host";
 return refuse(result,why);
}
enum sky_load_verdict sky_part_load(struct sky_part_host *h,const void *bytes,
 size_t n,const uint8_t digest[32])
{
 enum sky_load_verdict input=validate_load_input(h,bytes,n,digest);
 if(input!=SKY_LOAD_OK)return input;
 struct image *im=calloc(1,sizeof(*im));
 if(!im)return refuse(SKY_LOAD_MEMORY,"image allocation failed");
 uint8_t *snapshot=malloc(n);
 if(!snapshot){free(im);return refuse(SKY_LOAD_MEMORY,"candidate allocation failed");}
 uint8_t expected[32];memcpy(expected,digest,32);memcpy(snapshot,bytes,n);
 enum sky_macho_verdict admitted=sky_macho_prepare(im,snapshot,n,expected,UINT64_C(0x100000000));
 enum sky_load_verdict result;
 if(admitted!=SKY_MACHO_ADMIT)result=refuse(SKY_LOAD_ADMISSION,"shared digest, format or relocation policy refused");
 else result=stage_generation(h,im);
 free(snapshot);free(im);return result;
}
const struct sky_part_generation *sky_part_call_begin(struct sky_part_host *h)
{
 if(!h || h->failed || !h->current.id || h->in_call){
  fprintf(stderr,"sky_part_call_begin: unavailable, failed or borrowed\n");return NULL;
 }
 h->in_call=true;return &h->current;
}
bool sky_part_call_end(struct sky_part_host *h)
{
 if(!h || !h->in_call){fprintf(stderr,"sky_part_call_end: no borrow\n");return false;}
 h->in_call=false;return true;
}
bool sky_part_host_dispose(struct sky_part_host *h)
{
 if(!h || h->in_call){fprintf(stderr,"sky_part_host_dispose: invalid or borrowed\n");return false;}
 if(h->arena && munmap(h->arena,2u*SLOT)){
  h->failed=true;fprintf(stderr,"sky_part_host_dispose: munmap failed, arena retained\n");return false;
 }
 memset(h,0,sizeof(*h));return true;
}
#else
/* Inert admission is portable; production mapping is restricted to macOS arm64.
 * SKY_MACHO_VM_TEST substitutes inert observers, never executable allocations. */
enum sky_load_verdict sky_part_load(struct sky_part_host *h,const void *bytes,
 size_t n,const uint8_t digest[32])
{
 (void)h;(void)bytes;(void)n;(void)digest;
 fprintf(stderr,"sky_part_load refusal: native arm64 macOS W^X backend unavailable\n");
 return SKY_LOAD_PLATFORM;
}
const struct sky_part_generation *sky_part_call_begin(struct sky_part_host *h)
{
 (void)h;fprintf(stderr,"sky_part_call_begin: native arm64 macOS backend unavailable\n");return NULL;
}
bool sky_part_call_end(struct sky_part_host *h)
{
 (void)h;fprintf(stderr,"sky_part_call_end: native arm64 macOS backend unavailable\n");return false;
}
bool sky_part_host_dispose(struct sky_part_host *h)
{
 if(!h || h->arena || h->in_call || h->current.id){
  fprintf(stderr,"sky_part_host_dispose: invalid non-native host\n");return false;
 }
 memset(h,0,sizeof(*h));return true;
}
#endif
