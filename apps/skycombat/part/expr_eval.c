/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: Evaluate bounded validated HUD expressions with stderr diagnostics as its only host effect. */
#include "expr_format.h"
#include <base/serialize_le.h>
#include <math.h>
#include <stdbool.h>
#include <stdio.h>
struct expr_eval_table { const uint8_t *bytes; size_t size,end; unsigned count; };
static enum expr_status eval_fail(struct expr_error *e,enum expr_status code,
 unsigned i,const char *reason)
{
 if(e)*e=(struct expr_error){code,i,reason};
 fprintf(stderr,"HUD expression evaluation: code=%u record=%u: %s\n",(unsigned)code,i,reason);
 return code;
}
static int32_t eval_saturate(int64_t value)
{
 return value<INT32_MIN?INT32_MIN:value>INT32_MAX?INT32_MAX:(int32_t)value;
}
static enum expr_status eval_snapshot(const double *fields,int32_t out[XF_COUNT],
 struct expr_error *e)
{
 for(unsigned i=0;i<XF_COUNT;i++) {
  double v=fields[i];
  if(!isfinite(v) || v<INT32_MIN || v>INT32_MAX)
   return eval_fail(e,EX_SNAPSHOT,i,"finite I32 snapshot field required");
  int32_t integer=(int32_t)v;
  if((double)integer!=v || (i>=XF_SHIELD && integer!=0 && integer!=1))
   return eval_fail(e,EX_SNAPSHOT,i,"integral field or canonical Boolean required");
  out[i]=integer;
 }
 return EX_OK;
}
static enum expr_status eval_record(const struct expr_eval_table *t,unsigned i,
 const uint8_t **r,struct expr_error *e)
{
 if(i>=t->count || i>=256)return eval_fail(e,EX_REFERENCE,i,"expression index");
 size_t at=32+16*(size_t)i;
 if(t->end>t->size || at>t->end || 16>t->end-at)
  return eval_fail(e,EX_BOUNDS,i,"validated expression section extent");
 *r=t->bytes+at;return EX_OK;
}
static unsigned eval_arity(unsigned op)
{
 if(op<=EX_FIELD)return 0;
 if(op==EX_NOT)return 1;
 if(op==EX_CLAMP || op==EX_MULDIV || op==EX_SELECT)return 3;
 return 2;
}
static enum expr_status eval_args(const struct expr_eval_table *t,unsigned i,
 const uint8_t *r,const int32_t values[256],int32_t args[3],struct expr_error *e)
{
 for(unsigned j=0;j<eval_arity(r[0]);j++) {
  unsigned ref=zcl_read_u16_le(r+2+2*j);
  if(ref>=i || ref>=t->count || ref>=256)
   return eval_fail(e,EX_REFERENCE,i,"earlier operand within expression table required");
  args[j]=values[ref];
 }
 return EX_OK;
}
static enum expr_status eval_math(unsigned op,const int32_t v[3],int32_t *out,
 unsigned i,struct expr_error *e)
{
 int32_t a=v[0],b=v[1],c=v[2];
 switch(op) {
 case EX_ADD_SAT:*out=eval_saturate((int64_t)a+b);break;
 case EX_SUB_SAT:*out=eval_saturate((int64_t)a-b);break;
 case EX_MIN:*out=a<b?a:b;break;
 case EX_MAX:*out=a>b?a:b;break;
 case EX_CLAMP:
  if(b>c)return eval_fail(e,EX_RANGE,i,"CLAMP lower bound exceeds upper");
  *out=a<b?b:a>c?c:a;break;
 case EX_MULDIV:
  if(!c)return eval_fail(e,EX_DIV_ZERO,i,"MULDIV divisor zero");
  *out=eval_saturate(((int64_t)a*b)/c);break;
 default:return eval_fail(e,EX_OPCODE,i,"arithmetic opcode");
 }
 return EX_OK;
}
static enum expr_status eval_logic(unsigned op,const int32_t v[3],int32_t *out,
 unsigned i,struct expr_error *e)
{
 switch(op) {
 case EX_LT:*out=v[0]<v[1];break;
 case EX_LE:*out=v[0]<=v[1];break;
 case EX_EQ:*out=v[0]==v[1];break;
 case EX_AND:*out=v[0] && v[1];break;
 case EX_OR:*out=v[0] || v[1];break;
 case EX_NOT:*out=!v[0];break;
 case EX_SELECT:*out=v[0]?v[1]:v[2];break;
 default:return eval_fail(e,EX_OPCODE,i,"Boolean/select opcode");
 }
 return EX_OK;
}
static enum expr_status eval_one(const struct expr_eval_table *t,unsigned i,
 const int32_t fields[XF_COUNT],int32_t values[256],struct expr_error *e)
{
 const uint8_t *r=NULL;enum expr_status status=eval_record(t,i,&r,e);
 if(status!=EX_OK)return status;
 if(r[0]==EX_CONST_I32){values[i]=zcl_read_i32_le(r+8);return EX_OK;}
 if(r[0]==EX_FIELD) {
  uint32_t field=zcl_read_u32_le(r+8);
  if(field>=XF_COUNT)return eval_fail(e,EX_FIELD_ID,i,"snapshot field index");
  values[i]=fields[field];return EX_OK;
 }
 int32_t args[3]={0};status=eval_args(t,i,r,values,args,e);
 if(status!=EX_OK)return status;
 return r[0]<=EX_MULDIV?eval_math(r[0],args,&values[i],i,e):
  eval_logic(r[0],args,&values[i],i,e);
}
enum expr_status expr_evaluate(const void *bytes,size_t n,const double fields[XF_COUNT],
 unsigned budget,struct expr_values *out,struct expr_error *e)
{
 if(!bytes || !fields || !out)return eval_fail(e,EX_ARGUMENT,0,"null evaluation argument");
 if(budget>256)return eval_fail(e,EX_LIMIT,0,"evaluation step cap");
 struct expr_info info;enum expr_status status=expr_validate(bytes,n,&info,e);
 if(status!=EX_OK)return status;
 if(info.expressions>budget)return eval_fail(e,EX_EVAL_BUDGET,0,"insufficient expression steps");
 int32_t snapshot[XF_COUNT];status=eval_snapshot(fields,snapshot,e);
 if(status!=EX_OK)return status;
 struct expr_eval_table table={bytes,n,32+16*(size_t)info.expressions,info.expressions};
 struct expr_values result={0};result.count=info.expressions;
 for(unsigned i=0;i<info.expressions;i++) {
  status=eval_one(&table,i,snapshot,result.value,e);
  if(status!=EX_OK)return status;
  result.steps++;
 }
 *out=result;if(e)*e=(struct expr_error){EX_OK,0,"evaluated"};return EX_OK;
}
