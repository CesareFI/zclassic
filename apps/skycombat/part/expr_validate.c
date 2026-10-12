/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: Validate bounded HUD wire records without evaluating any expression. */
#include "expr_format.h"
#include <base/serialize_le.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
struct expr_scan {
 struct expr_info info;
 uint8_t types[256]; bool zeros[256];
 unsigned ends[64], worst[64];
};
static enum expr_status expr_fail(struct expr_error *e, enum expr_status code,
 unsigned index, const char *reason)
{
 if(e) *e=(struct expr_error){code,index,reason};
 fprintf(stderr,"HUD expression validation: code=%u record=%u: %s\n",
         (unsigned)code,index,reason);
 return code;
}
static unsigned expr_arity(unsigned op)
{
 if(op<=EX_FIELD) return 0;
 if(op==EX_NOT) return 1;
 if(op==EX_CLAMP || op==EX_MULDIV || op==EX_SELECT) return 3;
 return 2;
}
static unsigned expr_boolean(unsigned op, unsigned a, unsigned b)
{
 if(op==EX_NOT) return a==EX_BOOL ? EX_BOOL : 0;
 if(op==EX_AND || op==EX_OR) return a==EX_BOOL && b==EX_BOOL ? EX_BOOL : 0;
 return a==b ? EX_BOOL : 0;
}
static unsigned expr_result(unsigned op, unsigned a, unsigned b, unsigned c)
{
 if(op==EX_SELECT) return a==EX_BOOL && b==c ? b : 0;
 if(op>=EX_EQ && op<=EX_NOT) return expr_boolean(op,a,b);
 if(a!=EX_I32 || b!=EX_I32 || (expr_arity(op)==3 && c!=EX_I32)) return 0;
 return op==EX_LT || op==EX_LE ? EX_BOOL : EX_I32;
}
static enum expr_status expr_operands(unsigned op, unsigned i,
 const unsigned refs[3], struct expr_error *e)
{
 for(unsigned j=0;j<3;j++)
  if(j<expr_arity(op) ? refs[j]>=i : refs[j]!=EXPR_NONE)
   return expr_fail(e,EX_REFERENCE,i,"earlier active operand or NONE required");
 return EX_OK;
}
static unsigned expr_leaf_type(unsigned op, uint32_t immediate)
{
 return op==EX_FIELD && immediate>=XF_SHIELD ? EX_BOOL : EX_I32;
}
static enum expr_status expr_record(struct expr_scan *s, unsigned i,
 const uint8_t *r, struct expr_error *e)
{
 unsigned op=r[0], refs[3]={zcl_read_u16_le(r+2),zcl_read_u16_le(r+4),zcl_read_u16_le(r+6)};
 uint32_t imm=zcl_read_u32_le(r+8);
 if(r[1] || zcl_read_u32_le(r+12)) return expr_fail(e,EX_FORMAT,i,"expression reserved");
 if(op<EX_CONST_I32 || op>EX_SELECT) return expr_fail(e,EX_OPCODE,i,"expression opcode");
 unsigned arity=expr_arity(op);
 enum expr_status status=expr_operands(op,i,refs,e);
 if(status!=EX_OK) return status;
 if(op==EX_FIELD && imm>=XF_COUNT) return expr_fail(e,EX_FIELD_ID,i,"snapshot field");
 if(op<=EX_FIELD) s->types[i]=(uint8_t)expr_leaf_type(op,imm);
 else {
  if(imm) return expr_fail(e,EX_FORMAT,i,"unused immediate");
  unsigned a=s->types[refs[0]], b=arity>1?s->types[refs[1]]:0, c=arity>2?s->types[refs[2]]:0;
  s->types[i]=(uint8_t)expr_result(op,a,b,c);
  if(!s->types[i]) return expr_fail(e,EX_TYPE,i,"operand types");
 }
 s->zeros[i]=op==EX_CONST_I32 && imm==0;
 return EX_OK;
}
static enum expr_status expr_header(struct expr_scan *s, const uint8_t *b,
 size_t n, struct expr_error *e)
{
 if(n<32) return expr_fail(e,EX_BOUNDS,0,"header extent");
 if(memcmp(b,"HUDX",4) || zcl_read_u16_le(b+4) || zcl_read_u16_le(b+6)!=32 ||
    zcl_read_u32_le(b+8)!=1 || zcl_read_u32_le(b+24) || zcl_read_u32_le(b+28))
  return expr_fail(e,EX_FORMAT,0,"header identity/schema/reserved");
 s->info=(struct expr_info){zcl_read_u16_le(b+12),zcl_read_u16_le(b+14),
  zcl_read_u16_le(b+16),zcl_read_u16_le(b+18),zcl_read_u32_le(b+20),0,0};
 const struct expr_info *v=&s->info;
 if(v->expressions>256 || v->draws>64 || v->texts>64 || v->pieces>256 || v->literal_bytes>1024)
  return expr_fail(e,EX_LIMIT,0,"section counts");
 size_t size=32+16*(size_t)v->expressions+24*(size_t)v->draws+8*(size_t)v->texts+12*(size_t)v->pieces+v->literal_bytes;
 return size==n ? EX_OK : expr_fail(e,EX_BOUNDS,0,"exact section lengths");
}
static enum expr_status expr_piece(struct expr_scan *s, unsigned i, unsigned owner,
 const uint8_t *r, unsigned *pool, struct expr_error *e)
{
 unsigned ref=zcl_read_u16_le(r+2), length;
 uint32_t off=zcl_read_u32_le(r+4), len=zcl_read_u32_le(r+8);
 if(r[1]) return expr_fail(e,EX_FORMAT,i,"piece reserved");
 if(r[0]==1) {
  if(ref!=EXPR_NONE || off!=*pool || off>s->info.literal_bytes || len>s->info.literal_bytes-off)
   return expr_fail(e,EX_LITERAL,i,"literal range/NONE");
  *pool+=len; length=len;
 } else if(r[0]==2) {
  if(off || len || ref>=s->info.expressions || s->types[ref]!=EX_I32)
   return expr_fail(e,EX_TYPE,i,"DECIMAL reference/unused fields");
  length=11;
 } else return expr_fail(e,EX_OPCODE,i,"piece kind");
 s->worst[owner]+=length; s->info.worst_text+=length;
 return s->info.worst_text<=1024 ? EX_OK : expr_fail(e,EX_TEXT_BUDGET,i,"template text budget");
}
static enum expr_status expr_texts(struct expr_scan *s, const uint8_t *b,
 size_t *at, struct expr_error *e)
{
 unsigned next=0, owner=0, pool=0;
 for(unsigned i=0;i<s->info.texts;i++,*at+=8) {
  unsigned first=zcl_read_u16_le(b+*at), count=zcl_read_u16_le(b+*at+2);
  if(zcl_read_u32_le(b+*at+4)) return expr_fail(e,EX_FORMAT,i,"text reserved");
  if(!count || first!=next || count>s->info.pieces-next)
   return expr_fail(e,EX_REFERENCE,i,"contiguous nonempty text partition");
  next+=count; s->ends[i]=next;
 }
 if(next!=s->info.pieces) return expr_fail(e,EX_REFERENCE,next,"unowned pieces");
 for(unsigned i=0;i<s->info.pieces;i++,*at+=12) {
  while(i>=s->ends[owner]) owner++;
  enum expr_status status=expr_piece(s,i,owner,b+*at,&pool,e);
  if(status!=EX_OK) return status;
 }
 return pool==s->info.literal_bytes ? EX_OK : expr_fail(e,EX_LITERAL,0,"unowned literal bytes");
}
static bool expr_shape(const struct expr_scan *s, unsigned kind,
 const unsigned refs[7], unsigned text)
{
 if(kind<=2) return text==EXPR_NONE && s->zeros[refs[5]] && s->zeros[refs[6]];
 if(text>=s->info.texts) return false;
 if(kind==3) return s->zeros[refs[2]] && s->zeros[refs[3]];
 return s->zeros[refs[6]];
}
static enum expr_status expr_draw(struct expr_scan *s, unsigned i,
 const uint8_t *r, struct expr_error *e)
{
 unsigned kind=r[0], vis=zcl_read_u16_le(r+2), text=zcl_read_u16_le(r+18), refs[7];
 if(r[1] || zcl_read_u32_le(r+20)) return expr_fail(e,EX_FORMAT,i,"draw reserved");
 if(kind<1 || kind>4) return expr_fail(e,EX_SCHEMA,i,"draw kind");
 if(vis>=s->info.expressions || s->types[vis]!=EX_BOOL) return expr_fail(e,EX_TYPE,i,"Boolean visibility");
 for(unsigned j=0;j<7;j++) {
  refs[j]=zcl_read_u16_le(r+4+2*j);
  if(refs[j]>=s->info.expressions || s->types[refs[j]]!=EX_I32)
   return expr_fail(e,EX_TYPE,i,"integer draw field");
 }
 if(!expr_shape(s,kind,refs,text)) return expr_fail(e,EX_SCHEMA,i,"draw structural fields");
 if(kind>=3) s->info.worst_draw_text+=s->worst[text];
 return s->info.worst_draw_text<=1024 ? EX_OK : expr_fail(e,EX_TEXT_BUDGET,i,"draw text budget");
}
enum expr_status expr_validate(const void *bytes, size_t n,
 struct expr_info *info, struct expr_error *e)
{
 if(!bytes || !info) return expr_fail(e,EX_ARGUMENT,0,"null argument");
 if(n>EXPR_MAX_BYTES) return expr_fail(e,EX_LIMIT,0,"part byte limit");
 struct expr_scan s={0}; const uint8_t *b=bytes; size_t at=32;
 enum expr_status status=expr_header(&s,b,n,e);
 if(status!=EX_OK) return status;
 for(unsigned i=0;i<s.info.expressions;i++,at+=16) {
  status=expr_record(&s,i,b+at,e); if(status!=EX_OK) return status;
 }
 status=expr_texts(&s,b,&at,e); if(status!=EX_OK) return status;
 for(unsigned i=0;i<s.info.draws;i++,at+=24) {
  status=expr_draw(&s,i,b+at,e); if(status!=EX_OK) return status;
 }
 for(unsigned i=0;i<s.info.literal_bytes;i++)
  if(b[at+i]<32 || b[at+i]>126) return expr_fail(e,EX_LITERAL,i,"printable ASCII pool");
 *info=s.info; if(e) *e=(struct expr_error){EX_OK,0,"accepted"};
 return EX_OK;
}
