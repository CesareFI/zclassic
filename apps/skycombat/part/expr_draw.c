/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: Assemble a validated HUD part into a bounded atomic draw recipe. */
#include "expr_format.h"
#include <base/serialize_le.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
struct draw_table {
 const uint8_t *bytes; size_t size,base[4]; unsigned count[4];
 const struct expr_values *values; unsigned expressions,op_capacity,text_capacity;
};
static enum expr_status draw_fail(struct expr_error *e,enum expr_status code,
 unsigned i,const char *reason)
{
 if(e)*e=(struct expr_error){code,i,reason};
 fprintf(stderr,"HUD draw assembly: code=%u record=%u: %s\n",code,i,reason);return code;
}
static enum expr_status draw_read(const struct draw_table *t,unsigned section,
 unsigned i,const uint8_t **r,struct expr_error *e)
{
 static const unsigned width[4]={8,12,24,1};
 if(section>=4 || i>=t->count[section])return draw_fail(e,EX_REFERENCE,i,"section index");
 size_t base=t->base[section],size=width[section];
 if(base>t->size || size>t->size-base || i>(t->size-base-size)/size)
  return draw_fail(e,EX_BOUNDS,i,"validated section byte extent");
 *r=t->bytes+base+(size_t)i*size;return EX_OK;
}
static enum expr_status draw_value(const struct draw_table *t,unsigned ref,
 int32_t *out,struct expr_error *e)
{
 if(ref>=t->expressions || ref>=t->values->count || ref>=256)return draw_fail(e,EX_REFERENCE,ref,"evaluated value index");
 *out=t->values->value[ref];return EX_OK;
}
static unsigned draw_decimal(int32_t value,uint8_t out[11])
{
 uint32_t v=value<0?0u-(uint32_t)value:(uint32_t)value;
 uint8_t reverse[10];unsigned n=0,at=0;
 do{reverse[n++]=(uint8_t)('0'+v%10u);v/=10u;}while(v);
 if(value<0)out[at++]='-';
 while(n)out[at++]=reverse[--n];
 return at;
}
static enum expr_status draw_append(const struct draw_table *t,
 struct sky_hud_recipe_v1 *r,const uint8_t *bytes,unsigned n,struct expr_error *e)
{
 if(r->text_used>t->text_capacity || n>t->text_capacity-r->text_used)
  return draw_fail(e,EX_OUTPUT,r->op_count,"text capacity");
 if(n)memcpy(r->text+r->text_used,bytes,n);
 r->text_used+=n;return EX_OK;
}
static enum expr_status draw_piece(const struct draw_table *t,unsigned i,
 struct sky_hud_recipe_v1 *r,struct expr_error *e)
{
 const uint8_t *p=NULL;enum expr_status status=draw_read(t,1,i,&p,e);
 if(status!=EX_OK)return status;
 if(p[0]==1) {
  unsigned off=zcl_read_u32_le(p+4),n=zcl_read_u32_le(p+8);size_t base=t->base[3];
  if(off>t->count[3] || n>t->count[3]-off)return draw_fail(e,EX_LITERAL,i,"canonical literal range");
  if(base>t->size || off>t->size-base || n>t->size-base-off)
   return draw_fail(e,EX_BOUNDS,i,"literal byte extent");
  return draw_append(t,r,t->bytes+base+off,n,e);
 }
 if(p[0]!=2)return draw_fail(e,EX_OPCODE,i,"text piece kind");
 int32_t value=0;status=draw_value(t,zcl_read_u16_le(p+2),&value,e);
 if(status!=EX_OK)return status;
 uint8_t number[11];unsigned n=draw_decimal(value,number);
 return draw_append(t,r,number,n,e);
}
static enum expr_status draw_text(const struct draw_table *t,unsigned id,
 struct sky_hud_recipe_v1 *r,struct sky_hud_op_v1 *op,struct expr_error *e)
{
 const uint8_t *p=NULL;enum expr_status status=draw_read(t,0,id,&p,e);
 if(status!=EX_OK)return status;
 unsigned first=zcl_read_u16_le(p),count=zcl_read_u16_le(p+2);
 if(first>t->count[1] || count>t->count[1]-first)return draw_fail(e,EX_REFERENCE,id,"text piece partition");
 op->text_off=r->text_used;
 for(unsigned j=0;j<count;j++) {
  status=draw_piece(t,first+j,r,e);if(status!=EX_OK)return status;
 }
 op->text_len=r->text_used-op->text_off;return EX_OK;
}
static bool draw_numeric(unsigned kind,const int32_t v[7])
{
 return v[2]>=0 && v[3]>=0 &&
  (kind<3 || (v[5]>=1 && v[5]<=4096 && v[6]>=0 && v[6]<=2));
}
static enum expr_status draw_emit(const struct draw_table *t,unsigned i,
 struct sky_hud_recipe_v1 *r,struct expr_error *e)
{
 const uint8_t *p=NULL;enum expr_status status=draw_read(t,2,i,&p,e);
 if(status!=EX_OK)return status;
 if(p[0]<1 || p[0]>4)return draw_fail(e,EX_SCHEMA,i,"draw kind");
 int32_t visible=0;status=draw_value(t,zcl_read_u16_le(p+2),&visible,e);
 if(status!=EX_OK)return status;
 if(visible!=0 && visible!=1)return draw_fail(e,EX_VALUES,i,"canonical Boolean visibility");
 if(!visible)return EX_OK;
 int32_t v[7]={0};
 for(unsigned j=0;j<7;j++) {
  status=draw_value(t,zcl_read_u16_le(p+4+2*j),&v[j],e);if(status!=EX_OK)return status;
 }
 if(!draw_numeric(p[0],v))
  return draw_fail(e,EX_RANGE,i,"drawing numeric range");
 if(r->op_count>=t->op_capacity)return draw_fail(e,EX_OUTPUT,i,"operation capacity");
 struct sky_hud_op_v1 *op=&r->ops[r->op_count++];
 *op=(struct sky_hud_op_v1){.kind=p[0],.x=v[0],.y=v[1],.w=v[2],.h=v[3],
  .rgba=(uint32_t)v[4],.font_px=(uint32_t)v[5],.align=(uint32_t)v[6]};
 return p[0]>=3?draw_text(t,zcl_read_u16_le(p+18),r,op,e):EX_OK;
}
enum expr_status expr_build_draws(const void *bytes,size_t n,const struct expr_values *v,
 unsigned ops,unsigned text,struct sky_hud_recipe_v1 *out,struct expr_error *e)
{
 if(!bytes || !v || !out)return draw_fail(e,EX_ARGUMENT,0,"null draw argument");
 if(ops>SKY_HUD_MAX_OPS || text>SKY_HUD_TEXT_BYTES)return draw_fail(e,EX_LIMIT,0,"recipe capacity ceiling");
 struct expr_info info;enum expr_status status=expr_validate(bytes,n,&info,e);
 if(status!=EX_OK)return status;
 if(v->count!=info.expressions || v->steps!=v->count)return draw_fail(e,EX_VALUES,0,"complete evaluated result required");
 size_t texts=32+16*(size_t)info.expressions,pieces=texts+8*(size_t)info.texts;
 size_t draws=pieces+12*(size_t)info.pieces,literals=draws+24*(size_t)info.draws;
 struct draw_table table={bytes,n,{texts,pieces,draws,literals},
  {info.texts,info.pieces,info.draws,info.literal_bytes},v,info.expressions,ops,text};
 struct sky_hud_recipe_v1 result={0};
 for(unsigned i=0;i<info.draws;i++) {
  status=draw_emit(&table,i,&result,e);if(status!=EX_OK)return status;
 }
 *out=result;if(e)*e=(struct expr_error){EX_OK,0,"assembled"};return EX_OK;
}
