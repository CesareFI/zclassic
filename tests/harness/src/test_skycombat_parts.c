/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0 */
/* Purpose: register source-bound HUD recipe and ELF admission regressions. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "test/test_core.h"
#include "util/spawn.h"
#include "../../../apps/skycombat/part/elf_admit.c"
#if defined(__linux__) && defined(__x86_64__)
#include <sys/mman.h>
#include <sys/personality.h>
static bool deny_personality,watch_allocations;
static unsigned staging_allocations,unmap_failures,protect_failures;
static void *unreleased_mapping;
static size_t unreleased_bytes;
static void *test_malloc(size_t bytes)
{
    if(watch_allocations)++staging_allocations;
    return malloc(bytes);
}
static int test_personality(unsigned long value)
{ return deny_personality?(int)READ_IMPLIES_EXEC:personality(value); }
static int test_munmap(void *mapping,size_t bytes)
{
    if(unmap_failures){
        --unmap_failures;unreleased_mapping=mapping;unreleased_bytes=bytes;errno=ENOMEM;return -1;
    }
    return munmap(mapping,bytes);
}
static int test_mprotect(void *mapping,size_t bytes,int protection)
{
    if(protect_failures){--protect_failures;errno=ENOMEM;return -1;}
    return mprotect(mapping,bytes,protection);
}
/* Test-only syscall interception; the actual loader body is compiled below.
 * No process personality change or claim of physical kernel/crash failure. */
#define malloc test_malloc
#define personality test_personality
#define munmap test_munmap
#define mprotect test_mprotect
#endif
#include "../../../apps/skycombat/part/elf_load.c"
#if defined(__linux__) && defined(__x86_64__)
#undef malloc
#undef personality
#undef munmap
#undef mprotect
#endif
#include "../../../apps/skycombat/part/recipe_validate.c"
#include <stdio.h>
#include <string.h>
#include <stdint.h>
static unsigned tests,failed;
static void expect(const char *name,const struct sky_hud_recipe_v1 *r,enum sky_hud_recipe_error expected)
{
    enum sky_hud_recipe_error actual=sky_hud_recipe_check(r);
    ++tests;
    bool valid=sky_hud_recipe_valid(r);
    if(actual!=expected || valid!=(expected==SKY_HUD_RECIPE_OK)){
        ++failed;printf("FAIL %s expected=%d actual=%d valid=%d\n",name,(int)expected,(int)actual,(int)valid);
    }else printf("PASS %s\n",name);
}
static int recipe_vectors(void)
{
    struct sky_hud_recipe_v1 r={0};
    expect("null",NULL,SKY_HUD_RECIPE_ABSENT);
    expect("empty",&r,SKY_HUD_RECIPE_OK);
    for(unsigned i=0;i<64;++i)r.ops[i]=(struct sky_hud_op_v1){.kind=SKY_HUD_OP_RECT,.w=1,.h=1};
    r.op_count=64;expect("64 valid ops",&r,SKY_HUD_RECIPE_OK);
    r.op_count=65;expect("65 ops",&r,SKY_HUD_RECIPE_OP_COUNT);
    r.op_count=UINT32_MAX;expect("max op count",&r,SKY_HUD_RECIPE_OP_COUNT);
    r.op_count=1;r.ops[0].kind=UINT32_MAX;expect("unknown kind",&r,SKY_HUD_RECIPE_KIND);
    r.ops[0].kind=0;expect("zero kind",&r,SKY_HUD_RECIPE_KIND);
    r.ops[0].kind=SKY_HUD_OP_RECT;
    memset(r.text,' ',sizeof(r.text));r.text_used=1024;expect("1024 text bytes",&r,SKY_HUD_RECIPE_OK);
    r.text_used=1025;expect("1025 text bytes",&r,SKY_HUD_RECIPE_TEXT_COUNT);
    r.text_used=UINT32_MAX;expect("max text count",&r,SKY_HUD_RECIPE_TEXT_COUNT);
    r.text_used=1;r.text[0]=0;expect("non printable text",&r,SKY_HUD_RECIPE_TEXT_BYTES);
    r.text[0]=0x7f;expect("DEL text",&r,SKY_HUD_RECIPE_TEXT_BYTES);
    r.text[0]='X';r.ops[0]=(struct sky_hud_op_v1){.kind=SKY_HUD_OP_TEXT,.font_px=20,.text_len=1};
    expect("exact text range",&r,SKY_HUD_RECIPE_OK);
    r.ops[0].text_off=UINT32_MAX;expect("overflow offset",&r,SKY_HUD_RECIPE_TEXT_RANGE);
    r.ops[0].text_off=1;r.ops[0].text_len=UINT32_MAX;expect("overflow length",&r,SKY_HUD_RECIPE_TEXT_RANGE);
    r.ops[0].text_len=1;expect("past used extent",&r,SKY_HUD_RECIPE_TEXT_RANGE);
    r.ops[0].text_len=0;expect("empty range at end",&r,SKY_HUD_RECIPE_OK);
    r.ops[0].font_px=0;expect("zero font",&r,SKY_HUD_RECIPE_FONT);
    r.ops[0].font_px=513;expect("font above bound",&r,SKY_HUD_RECIPE_FONT);
    r.ops[0].font_px=512;r.ops[0].align=3;expect("invalid alignment",&r,SKY_HUD_RECIPE_ALIGN);
    r.ops[0].align=0;r.ops[0].x=32769;expect("coordinate above bound",&r,SKY_HUD_RECIPE_GEOMETRY);
    r.ops[0].x=-32769;expect("coordinate below bound",&r,SKY_HUD_RECIPE_GEOMETRY);
    r.ops[0].x=-32768;expect("coordinate at bound",&r,SKY_HUD_RECIPE_OK);
    r.ops[0].w=1;expect("unused text width",&r,SKY_HUD_RECIPE_UNUSED);
    r.ops[0]=(struct sky_hud_op_v1){.kind=SKY_HUD_OP_RECT,.text_len=1};expect("unused rectangle text",&r,SKY_HUD_RECIPE_UNUSED);
    r.ops[0]=(struct sky_hud_op_v1){.kind=SKY_HUD_OP_TEXT_BOX,.w=-1,.font_px=20};expect("negative textbox width",&r,SKY_HUD_RECIPE_GEOMETRY);
    printf("tests=%u failed=%u\n",tests,failed);
    return failed?1:0;
}
static void part_expect(const char *label,bool passed)
{
    ++tests;
    if(!passed)++failed;
    printf("%s %s\n",passed?"PASS":"FAIL",label);
}
#if defined(__linux__) && defined(__x86_64__)
struct compiled_part { uint8_t *bytes; size_t length; uint8_t digest[32]; };
static bool read_part(const char *path,struct compiled_part *out)
{
    FILE *f=fopen(path,"rb");
    if(!f)return false;
    if(fseek(f,0,SEEK_END)){fclose(f);return false;}
    long n=ftell(f);
    if(n<64 || n>16*1024*1024 || fseek(f,0,SEEK_SET)){fclose(f);return false;}
    uint8_t *bytes=malloc((size_t)n);
    if(!bytes){fclose(f);return false;}
    size_t got=fread(bytes,1,(size_t)n,f);
    int closed=fclose(f);
    if(got!=(size_t)n || closed){free(bytes);return false;}
    out->bytes=bytes;out->length=(size_t)n;
    zsha256(bytes,out->length,out->digest);
    return true;
}
static bool compile_part(const char *path,const char *define,struct compiled_part *out)
{
    const char *const argv[]={"/usr/bin/cc","-std=c23","-O2","-Wall","-Wextra","-Werror","-pedantic","-fPIC","-ffreestanding",
        "-fno-stack-protector",define,"-Iapps/skycombat/part","-c",
        "apps/skycombat/part/elf_fixture.c","-o",path,NULL};
    char diagnostics[4096];struct zcl_spawn_binary_observation observation={0};
    struct zcl_result result=zcl_spawn_capture_binary_merged(argv,diagnostics,sizeof(diagnostics),30000,&observation);
    if(!result.ok){
        fprintf(stderr,"skycombat_parts compiler: %s\n",result.message);
        if(observation.output_len)fwrite(diagnostics,1,observation.output_len,stderr);
        return false;
    }
    return read_part(path,out);
}
static enum sky_elf_load_verdict load_part(struct sky_elf_part_host *host,const struct compiled_part *part)
{
    enum sky_elf_part_verdict admission=SKY_ELF_PART_ARGUMENT;
    return sky_elf_part_load(host,part->bytes,part->length,part->digest,&admission);
}
static bool build_part(struct sky_elf_part_host *host,struct sky_hud_recipe_v1 *out,int32_t *result)
{
    const struct sky_elf_part_generation *g=sky_elf_part_call_begin(host);
    if(!g)return false;
    const struct sky_hud_snapshot_v1 in={.abi=1,.size=sizeof(in),.screen_w=800,
        .screen_h=600,.health_milli=150000,.max_health_milli=100000};
    memset(out,0,sizeof(*out));
    *result=g->part->build(&in,out);
    return sky_elf_part_call_end(host);
}
static bool good_recipe(struct sky_elf_part_host *host,bool b)
{
    struct sky_hud_recipe_v1 recipe={0};int32_t result=0;
    if(!build_part(host,&recipe,&result) || result)return false;
    if(sky_hud_recipe_check(&recipe)!=SKY_HUD_RECIPE_OK)return false;
    if(recipe.ops[0].w!=(b?100:150) || recipe.op_count!=(b?2u:1u))return false;
    if(!b)return recipe.text_used==0;
    return recipe.text_used==9 && !memcmp(recipe.text,"HULL 100%",9);
}
static void admission_expect(const char *label,const uint8_t *bytes,size_t length,enum sky_elf_part_verdict expected)
{
    uint8_t digest[32];zsha256(bytes,length,digest);
    part_expect(label,sky_elf_part_admit(bytes,length,digest)==expected);
}
static uint64_t ordinary_symbol(const struct compiled_part *part)
{
    if(sky_elf_part_admit(part->bytes,part->length,part->digest)!=SKY_ELF_PART_ADMIT)
        return 0;
    uint64_t table=r64(part->bytes+40);unsigned count=r16(part->bytes+60);
    for(unsigned i=1;i<count;++i){
        const uint8_t *s=part->bytes+table+(uint64_t)i*64;
        if(r32(s+4)!=2 || r64(s+32)<48)continue;
        for(uint64_t j=24;j<r64(s+32);j+=24){
            uint64_t offset=r64(s+24)+j;
            unsigned target=r16(part->bytes+offset+6);
            if(target && target<count)return offset;
        }
    }
    return 0;
}
static void symbol_refusals(const struct compiled_part *part,uint8_t *copy)
{
    uint64_t offset=ordinary_symbol(part);
    part_expect("nonnull ordinary-section symbol witness present",offset!=0);
    if(!offset)return;
    memcpy(copy,part->bytes,part->length);copy[offset+4]=(uint8_t)((copy[offset+4]&0xf0u)|6u);
    admission_expect("independent ordinary-section TLS symbol refuses",copy,part->length,SKY_ELF_PART_TLS);
    memcpy(copy,part->bytes,part->length);write_le(copy+offset+6,0,2);
    admission_expect("undefined nonnull symbol refuses",copy,part->length,SKY_ELF_PART_UNDEFINED);
}
static bool startup_refusals(const struct compiled_part *part,uint8_t *copy)
{
    if(sky_elf_part_admit(part->bytes,part->length,part->digest)!=SKY_ELF_PART_ADMIT)
        return false;
    uint64_t table=r64(part->bytes+40);unsigned count=r16(part->bytes+60),names=r16(part->bytes+62);
    uint64_t strings=r64(part->bytes+table+(uint64_t)names*64+24);
    bool text=false,note=false;
    for(unsigned i=1;i<count;++i){
        const uint8_t *s=part->bytes+table+(uint64_t)i*64;
        uint64_t offset=strings+r32(s);
        if(!strcmp((const char*)part->bytes+offset,".text")){
            memcpy(copy,part->bytes,part->length);memcpy(copy+offset,".init",6);
            admission_expect("independent executable init refuses",copy,part->length,SKY_ELF_PART_STARTUP);
            memcpy(copy,part->bytes,part->length);memcpy(copy+offset,".fini",6);
            admission_expect("independent executable fini refuses",copy,part->length,SKY_ELF_PART_STARTUP);
            text=true;
        }
        if(!strcmp((const char*)part->bytes+offset,".note.GNU-stack")){
            memcpy(copy,part->bytes,part->length);memcpy(copy+offset,".preinit_array",15);
            admission_expect("independent PROGBITS preinit array refuses",copy,part->length,SKY_ELF_PART_STARTUP);
            note=true;
        }
    }
    part_expect("startup witness sections present",text && note);
    return true;
}
static void admission_vectors(const struct compiled_part *part)
{
    admission_expect("truncated ELF header refuses",part->bytes,63,SKY_ELF_PART_BOUNDS);
    admission_expect("truncated section table refuses",part->bytes,part->length-1,SKY_ELF_PART_BOUNDS);
    uint8_t wrong[32];memcpy(wrong,part->digest,sizeof(wrong));wrong[0]^=1;
    part_expect("wrong digest refuses",sky_elf_part_admit(part->bytes,part->length,wrong)==SKY_ELF_PART_DIGEST);
    uint8_t *copy=malloc(part->length);
    if(!copy){part_expect("mutation allocation",false);return;}
    memcpy(copy,part->bytes,part->length);write_le(copy+16,3,2);
    admission_expect("shared object refuses",copy,part->length,SKY_ELF_PART_FORMAT);
    memcpy(copy,part->bytes,part->length);write_le(copy+18,183,2);
    admission_expect("wrong machine refuses",copy,part->length,SKY_ELF_PART_TARGET);
    symbol_refusals(part,copy);
    part_expect("startup fixture structurally admitted",startup_refusals(part,copy));
    free(copy);
}
static uint64_t descriptor_symbol_offset(const struct compiled_part *part,unsigned *index)
{
    if(sky_elf_part_admit(part->bytes,part->length,part->digest)!=SKY_ELF_PART_ADMIT)
        return 0;
    uint64_t table=r64(part->bytes+40);unsigned count=r16(part->bytes+60);
    for(unsigned i=1;i<count;++i){
        const uint8_t *s=part->bytes+table+(uint64_t)i*64;
        if(r32(s+4)!=2)continue;
        uint64_t strings=r64(part->bytes+table+(uint64_t)r32(s+40)*64+24);
        for(uint64_t j=24;j<r64(s+32);j+=24){
            uint64_t offset=r64(s+24)+j;
            if(!strcmp((const char*)part->bytes+strings+r32(part->bytes+offset),"sky_hud_part_v1")){
                *index=(unsigned)(j/24);return offset;
            }
        }
    }
    return 0;
}
static bool preserving_abi_vector(const struct compiled_part *part,uint8_t *copy,unsigned type)
{
    unsigned symbol=0;uint64_t offset=descriptor_symbol_offset(part,&symbol);
    if(!offset)return false;
    unsigned target=r16(part->bytes+offset+6);
    uint64_t relative=r64(part->bytes+offset+8),table=r64(part->bytes+40);
    unsigned count=r16(part->bytes+60),names=r16(part->bytes+62);
    uint64_t strings=r64(part->bytes+table+(uint64_t)names*64+24);
    for(unsigned i=1;i<count;++i){
        const uint8_t *s=part->bytes+table+(uint64_t)i*64;
        if(strcmp((const char*)part->bytes+strings+r32(s),".rela.eh_frame"))continue;
        if(r32(s+4)!=4 || r64(s+32)!=24)return false;
        memcpy(copy,part->bytes,part->length);
        write_le(copy+table+(uint64_t)i*64+44,target,4);
        uint64_t entry=r64(s+24);
        write_le(copy+entry,relative,8);
        write_le(copy+entry+8,((uint64_t)symbol<<32)|type,8);
        write_le(copy+entry+16,1,8);
        return true;
    }
    return false;
}
static void loader_faults(struct sky_elf_part_host *host,const struct compiled_part *a)
{
    uint64_t previous=host->current.id;
    staging_allocations=0;watch_allocations=true;deny_personality=true;
    enum sky_elf_load_verdict guard=load_part(host,a);
    watch_allocations=false;deny_personality=false;
    part_expect("personality refusal precedes staging allocation",guard==SKY_ELF_LOAD_PLATFORM && staging_allocations==0 && host->current.id==previous);
    protect_failures=1;unmap_failures=1;unreleased_mapping=NULL;
    enum sky_elf_load_verdict refused=load_part(host,a);
    bool cleaned=unreleased_mapping && munmap(unreleased_mapping,unreleased_bytes)==0;
    part_expect("failed candidate cleanup reported",refused==SKY_ELF_LOAD_CLEANUP && cleaned && host->current.id==previous && good_recipe(host,true));
    unmap_failures=2;unreleased_mapping=NULL;
    enum sky_elf_load_verdict verdict=load_part(host,a);
    bool recovered=unreleased_mapping && unreleased_mapping!=host->current.mapping && munmap(unreleased_mapping,unreleased_bytes)==0;
    part_expect("retirement and cleanup double failure reported",verdict==SKY_ELF_LOAD_CLEANUP && recovered && host->current.id==previous && good_recipe(host,true));
    unmap_failures=0;
}
static void loader_refusals(struct sky_elf_part_host *host,const struct compiled_part *a)
{
    uint64_t previous=host->current.id;
    uint8_t *copy=malloc(a->length);
    if(!copy){part_expect("loader mutation allocation",false);return;}
    for(unsigned type=2;type<=4;type+=2){
        bool vector=preserving_abi_vector(a,copy,type);
        part_expect("value-preserving ABI relocation witness",vector);
        if(!vector)continue;
        struct compiled_part bad={.bytes=copy,.length=a->length};zsha256(copy,bad.length,bad.digest);
        admission_expect("ABI relocation now refuses in admission",copy,a->length,SKY_ELF_PART_ABI);
        part_expect(type==2?"PC32 ABI write refuses":"PLT32 ABI write refuses",
            load_part(host,&bad)==SKY_ELF_LOAD_ADMISSION && host->current.id==previous && good_recipe(host,true));
    }
    loader_faults(host,a);
    free(copy);
}
static void lifecycle_vectors(struct compiled_part parts[5])
{
    struct sky_elf_part_host host={0};
    part_expect("admit compiler A",sky_elf_part_admit(parts[0].bytes,parts[0].length,parts[0].digest)==SKY_ELF_PART_ADMIT);
    part_expect("load callable A",load_part(&host,&parts[0])==SKY_ELF_LOAD_OK && good_recipe(&host,false));
    uint64_t first=host.current.id;
    const struct sky_elf_part_generation *held=sky_elf_part_call_begin(&host);
    part_expect("borrow pins A",held && held->id==first);
    part_expect("borrow refuses swap",load_part(&host,&parts[1])==SKY_ELF_LOAD_BUSY && host.current.id==first);
    part_expect("borrow refuses dispose",!sky_elf_part_host_dispose(&host));
    part_expect("release borrow",sky_elf_part_call_end(&host));
    part_expect("load callable B",load_part(&host,&parts[1])==SKY_ELF_LOAD_OK && good_recipe(&host,true));
    uint64_t second=host.current.id;
    part_expect("generation increases",second>first);
    loader_refusals(&host,&parts[0]);
    for(unsigned i=2;i<5;++i){
        struct sky_elf_part_host candidate={0};struct sky_hud_recipe_v1 recipe={0};int32_t result=0;
        part_expect("bad recipe part admitted and loaded",load_part(&candidate,&parts[i])==SKY_ELF_LOAD_OK);
        bool built=build_part(&candidate,&recipe,&result);
        enum sky_hud_recipe_error expected=i==3?SKY_HUD_RECIPE_OP_COUNT:SKY_HUD_RECIPE_TEXT_COUNT;
        bool refused=i==2?result==17:result==0 && sky_hud_recipe_check(&recipe)==expected;
        part_expect("native bad result/recipe detected in candidate host",built && refused);
        part_expect("reject candidate disposal",sky_elf_part_host_dispose(&candidate));
        part_expect("previous good B remains callable",host.current.id==second && good_recipe(&host,true));
    }
    part_expect("restore A with fresh generation",load_part(&host,&parts[0])==SKY_ELF_LOAD_OK && host.current.id>second && good_recipe(&host,false));
    part_expect("dispose retains monotonic identity",sky_elf_part_host_dispose(&host) && host.last_id>second);
    part_expect("disposed host refuses borrow",sky_elf_part_call_begin(&host)==NULL);
    host.last_id=UINT64_MAX;
    part_expect("id exhaustion refuses",load_part(&host,&parts[0])==SKY_ELF_LOAD_ID_EXHAUSTED);
}
static bool compiler_file_metadata(const struct compiled_part *part)
{
    struct image im={.b=part->bytes,.n=part->length};
    bool found=false;
    if(sky_elf_part_admit(part->bytes,part->length,part->digest)!=SKY_ELF_PART_ADMIT ||
       header(&im)!=SKY_ELF_PART_ADMIT)return false;
    for(unsigned i=1;i<im.count;++i){
        const uint8_t *s=section(&im,i);
        if(u32(s+4)!=2)continue;
        for(uint64_t k=24;k<u64(s+32);k+=24){
            const uint8_t *sym=im.b+u64(s+24)+k;
            if(sym[4]==4 && u16(sym+6)==0xfff1u && !u64(sym+8) && !u64(sym+16))found=true;
        }
    }
    return found;
}
static void assurance_vectors(const char *directory)
{
    static const struct { const char *define,*label; enum sky_elf_part_verdict verdict; } cases[]={
        {"-DSKY_ELF_FIXTURE_WX","compiler W+X section refuses",SKY_ELF_PART_FORMAT},
        {"-DSKY_ELF_FIXTURE_SYMBOL_EXTENT","compiler ordinary symbol extent refuses",SKY_ELF_PART_BOUNDS},
        {"-DSKY_ELF_FIXTURE_ABSOLUTE","compiler address ABS symbol refuses",SKY_ELF_PART_BOUNDS},
        {"-DSKY_ELF_FIXTURE_COMMON","compiler COMMON symbol refuses",SKY_ELF_PART_BOUNDS},
        {"-DSKY_ELF_FIXTURE_DYNAMIC","compiler dynamic section refuses",SKY_ELF_PART_FORMAT},
        {"-DSKY_ELF_FIXTURE_UNSUPPORTED_RELOCATION","compiler unsupported relocation refuses",SKY_ELF_PART_RELOCATION_FORMAT},
        {"-DSKY_ELF_FIXTURE_RELOCATION_EXTENT","compiler relocation write extent refuses",SKY_ELF_PART_BOUNDS},
        {"-DSKY_ELF_FIXTURE_RELOCATION_OVERLAP","compiler relocation overlap refuses",SKY_ELF_PART_OVERLAP},
        {"-DSKY_ELF_FIXTURE_DESCRIPTOR_WRITE","compiler descriptor admission-field write refuses",SKY_ELF_PART_ABI},
        {"-DSKY_ELF_FIXTURE_RELOCATION_UNMAPPED","compiler unmapped relocation target refuses",SKY_ELF_PART_RELOCATION_TARGET},
        {"-DSKY_ELF_FIXTURE_RELOCATION_END_SYMBOL","compiler relocation end-symbol refuses",SKY_ELF_PART_RELOCATION_TARGET},
        {"-DSKY_ELF_FIXTURE_RELOCATION_LIMIT","compiler exact relocation limit admits",SKY_ELF_PART_ADMIT},
        {"-DSKY_ELF_FIXTURE_RELOCATION_LIMIT_PLUS_ONE","compiler relocation limit plus one refuses",SKY_ELF_PART_RELOCATION_FORMAT}
    };
    for(unsigned i=0;i<sizeof(cases)/sizeof(*cases);++i){
        char path[PATH_MAX];struct compiled_part part={0};
        int n=snprintf(path,sizeof(path),"%s/assurance%u.o",directory,i);
        bool built=n>0 && (size_t)n<sizeof(path) && compile_part(path,cases[i].define,&part);
        part_expect("compile assurance object without byte mutation",built);
        if(built){
            enum sky_elf_part_verdict actual=sky_elf_part_admit(part.bytes,part.length,part.digest);
            printf("assurance[%u] expected=%d actual=%d\n",i,(int)cases[i].verdict,(int)actual);
            part_expect(cases[i].label,actual==cases[i].verdict);
        }
        free(part.bytes);
    }
}
/* Every declared short view retains the complete compiler-produced allocation.
 * Removing a guard therefore fails assertions without requiring an invalid C
 * allocation read or relying on a segmentation fault. */
static bool helper_copy_untouched(const uint8_t *bytes,size_t length)
{
    for(size_t i=0;i<length;++i)if(bytes[i]!=0xa5)return false;
    return true;
}
static void malformed_helper_case(const struct compiled_part *part,size_t capacity)
{
    uint8_t *copy=malloc(capacity);
    if(!copy){part_expect("B1 helper copy allocation",false);return;}
    part_expect("B1 malformed control cannot admit",
        sky_elf_part_admit(part->bytes,part->length,part->digest)!=SKY_ELF_PART_ADMIT);
    part_expect("B1 ordinary symbol rejects unadmitted input",ordinary_symbol(part)==0);
    unsigned index=UINT_MAX;
    part_expect("B1 descriptor rejects unadmitted input without publishing index",
        descriptor_symbol_offset(part,&index)==0 && index==UINT_MAX);
    memset(copy,0xa5,capacity);
    part_expect("B1 startup rejects unadmitted input",!startup_refusals(part,copy));
    part_expect("B1 rejected startup leaves copy untouched",helper_copy_untouched(copy,capacity));
    memset(copy,0xa5,capacity);
    part_expect("B1 ABI vector rejects unadmitted input",!preserving_abi_vector(part,copy,2));
    part_expect("B1 rejected ABI vector leaves copy untouched",helper_copy_untouched(copy,capacity));
    part_expect("B1 metadata rejects unadmitted input",!compiler_file_metadata(part));
    free(copy);
}
static void malformed_helper_vectors(const struct compiled_part *part)
{
    if(sky_elf_part_admit(part->bytes,part->length,part->digest)!=SKY_ELF_PART_ADMIT){
        part_expect("B1 original compiler control structurally admitted",false);return;
    }
    uint64_t table=r64(part->bytes+40);unsigned count=r16(part->bytes+60);
    const size_t lengths[]={63,64,(size_t)(table+(uint64_t)count*64-1)};
    for(unsigned i=0;i<sizeof(lengths)/sizeof(*lengths);++i){
        struct compiled_part short_view=*part;short_view.length=lengths[i];
        zsha256(short_view.bytes,short_view.length,short_view.digest);
        printf("B1 short header/table case=%u declared_bytes=%zu\n",i,short_view.length);
        malformed_helper_case(&short_view,part->length);
    }
    uint8_t *bytes=malloc(part->length);
    if(!bytes){part_expect("B1 string control allocation",false);return;}
    memcpy(bytes,part->bytes,part->length);
    /* Read only the admitted original's section headers. Mutate the declared
     * string extents while retaining all underlying bytes for the removal test. */
    for(unsigned i=1;i<count;++i){
        const uint8_t *section_bytes=part->bytes+table+(uint64_t)i*64;
        if(r32(section_bytes+4)==3)write_le(bytes+table+(uint64_t)i*64+32,0,8);
    }
    struct compiled_part strings={.bytes=bytes,.length=part->length};
    zsha256(bytes,strings.length,strings.digest);
    printf("B1 malformed section/symbol string extents\n");
    malformed_helper_case(&strings,part->length);
    free(bytes);
}
static void snapshot_height_case(struct sky_elf_part_host *host,int32_t height,bool refused,bool b)
{
    const struct sky_elf_part_generation *generation=sky_elf_part_call_begin(host);
    if(!generation){part_expect("B2 snapshot generation borrowed",false);return;}
    struct sky_hud_snapshot_v1 snapshot={.abi=SKY_HUD_ABI_V1,.size=sizeof(snapshot),
        .screen_w=800,.screen_h=height,.health_milli=100000,.max_health_milli=100000};
    struct sky_hud_recipe_v1 recipe,before;
    memset(&recipe,0xa5,sizeof(recipe));before=recipe;
    int32_t result=generation->part->build(&snapshot,&recipe);
    printf("B2 fixture=%s screen_h=%" PRId32 " result=%" PRId32 "\n",b?"B":"A",height,result);
    if(refused){
        part_expect("B2 low height refuses before subtraction",result==-1);
        part_expect("B2 refused height leaves recipe untouched",!memcmp(&recipe,&before,sizeof(recipe)));
    }else{
        int64_t expected=(int64_t)height-150;
        part_expect("B2 representable height builds",result==0);
        part_expect("B2 rectangle ordinate is separately representable",recipe.ops[0].y==expected);
        if(b)part_expect("B2 label ordinate is representable",recipe.ops[1].y==expected+5);
    }
    part_expect("B2 snapshot borrow released",sky_elf_part_call_end(host));
}
static void snapshot_height_vectors(struct compiled_part parts[5])
{
    static const int32_t heights[]={INT32_MIN,INT32_MIN+149,INT32_MIN+150,INT32_MIN+151,INT32_MAX};
    for(unsigned variant=0;variant<2;++variant){
        struct sky_elf_part_host host={0};
        bool loaded=load_part(&host,&parts[variant])==SKY_ELF_LOAD_OK;
        part_expect("B2 actual A/B fixture loaded",loaded);
        if(loaded)for(unsigned i=0;i<sizeof(heights)/sizeof(*heights);++i)
            snapshot_height_case(&host,heights[i],i<2,variant!=0);
        part_expect("B2 snapshot host disposed",sky_elf_part_host_dispose(&host));
    }
}
static void elf_vectors(void)
{
    char directory[PATH_MAX];test_fmt_tmpdir(directory,sizeof(directory),"skycombat_parts","elf");
    if(mkdir(directory,0700)){part_expect("private ELF fixture directory",false);return;}
    static const char *const defines[]={"-DSKY_ELF_FIXTURE_A","-DSKY_ELF_FIXTURE_B",
        "-DSKY_ELF_FIXTURE_BAD_RESULT","-DSKY_ELF_FIXTURE_BAD_OPS","-DSKY_ELF_FIXTURE_BAD_TEXT"};
    struct compiled_part parts[5]={0};bool ready=true;
    for(unsigned i=0;i<5;++i){
        char path[PATH_MAX];int n=snprintf(path,sizeof(path),"%s/part%u.o",directory,i);
        bool built=n>0 && (size_t)n<sizeof(path) && compile_part(path,defines[i],&parts[i]);
        part_expect("compile ordinary consenting ELF source",built);
        if(!built){ready=false;break;}
    }
    if(ready){malformed_helper_vectors(&parts[0]);snapshot_height_vectors(parts);
        admission_vectors(&parts[0]);lifecycle_vectors(parts);
        part_expect("compiler emits local non-address STT_FILE ABS metadata",compiler_file_metadata(&parts[0]));
        assurance_vectors(directory);}
    for(unsigned i=0;i<5;++i)free(parts[i].bytes);
    test_cleanup_tmpdir(directory);
}
#endif
int test_skycombat_parts(void)
{
    tests=0;failed=0;
    (void)recipe_vectors();
#if defined(__linux__) && defined(__x86_64__)
    elf_vectors();
#else
    struct sky_elf_part_host host={0};uint8_t digest[32]={0};enum sky_elf_part_verdict admission;
    part_expect("unsupported native loader refuses",sky_elf_part_load(&host,"",0,digest,&admission)==SKY_ELF_LOAD_PLATFORM);
#endif
    printf("skycombat_parts tests=%u failed=%u\n",tests,failed);
    return (int)failed;
}
