/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: Select, reload and switch one pinned HUD while retaining its admitted inert recipe. */
#ifndef SKY_EXPR_USE_H
#define SKY_EXPR_USE_H
#include "expr_format.h"
#include "base/hex.h"
#include <raylib.h>
#include "platform/positioned_file.h"
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <math.h>
struct sky_expr_option { const char *path,*pin_path; uint8_t pin[32]; };
struct sky_expr_hud { bool active,builtin_selected; struct expr_part part; };
static inline const char *sky_expr_pin_option(const char *arg)
{
 const char prefix[]="--hud-pin-file=";
 if(!arg || strncmp(arg,prefix,sizeof prefix-1) || !arg[sizeof prefix-1])return NULL;
 return arg+sizeof prefix-1;
}
static inline bool sky_expr_custom_selected(const struct sky_expr_hud *hud)
{ return hud->active && !hud->builtin_selected; }
static inline void sky_expr_toggle(struct sky_expr_hud *hud)
{ if(hud->active)hud->builtin_selected=!hud->builtin_selected; }
/* Host feedback is independent of the admitted HUD; no path or recipe mutation. */
struct sky_expr_notice { float remaining; enum expr_admit_status status; };
static inline void sky_expr_notice_set(struct sky_expr_notice *notice,enum expr_admit_status status)
{ notice->status=status;notice->remaining=5.0f; }
static inline void sky_expr_notice_tick(struct sky_expr_notice *notice,float dt)
{
 if(!isfinite(dt) || dt<=0.0f)return;
 notice->remaining=dt<notice->remaining?notice->remaining-dt:0.0f;
}
static inline const char *sky_expr_notice_message(const struct sky_expr_notice *notice,const struct sky_expr_hud *hud)
{
 switch(notice->status) {
 case EX_ADMIT_OK:return sky_expr_custom_selected(hud)?"HUD updated":"HUD updated (F7 to show)";
 case EX_ADMIT_READ:return "HUD kept: file could not be read";
 case EX_ADMIT_PIN:return "HUD kept: pin mismatch or invalid";
 case EX_ADMIT_VALIDATE:return "HUD kept: invalid HUD data";
 case EX_ADMIT_EVALUATE:return "HUD kept: values could not be evaluated";
 case EX_ADMIT_DRAW:return "HUD kept: drawing could not be assembled";
 default:return "HUD kept: invalid reload request";
 }
}
static inline void sky_expr_notice_render(const struct sky_expr_notice *notice,const struct sky_expr_hud *hud)
{
 if(notice->remaining<=0.0f)return;
 const char *message=sky_expr_notice_message(notice,hud);Font font=GetFontDefault();
 DrawTextEx(font,message,(Vector2){12.0f,67.0f},18.0f,1.0f,BLACK);
 DrawTextEx(font,message,(Vector2){10.0f,65.0f},18.0f,1.0f,notice->status==EX_ADMIT_OK?GREEN:ORANGE);
}
/* argv lives through startup; failure leaves out unchanged. No option is default. */
static inline bool sky_expr_option_parse(int argc,char *const argv[],struct sky_expr_option *out)
{
 if(!out || !argv || argc<1)return false;
 struct sky_expr_option candidate={0};
 if(argc==1){*out=candidate;return true;}
 const char prefix[]="--hud-part=";
 if((argc!=2 && argc!=3) || !argv[1] || strncmp(argv[1],prefix,sizeof prefix-1) ||
    strlen(argv[1])<sizeof prefix-1+66)return false;
 const char *value=argv[1]+sizeof prefix-1;
 if(value[64]!=':')return false;
 char hex[65];memcpy(hex,value,64);hex[64]=0;
 if(!zcl_hex_decode(hex,candidate.pin,32))return false;
 candidate.path=value+65;
 if(argc==3) {
  candidate.pin_path=sky_expr_pin_option(argv[2]);
  if(!candidate.pin_path)return false;
 }
 *out=candidate;return true;
}
/* Once at startup. Admission owns diagnostics; a refusal selects the baseline. */
static inline void sky_expr_start(const struct sky_expr_option *option,const double fields[XF_COUNT],struct sky_expr_hud *hud)
{
 hud->active=false;hud->builtin_selected=false;
 if(option->path)hud->active=expr_admit_file(option->path,option->pin,fields,256,
   SKY_HUD_MAX_OPS,SKY_HUD_TEXT_BYTES,&hud->part,NULL)==EX_ADMIT_OK;
}
static inline void sky_expr_draw_op(const struct sky_hud_recipe_v1 *recipe,const struct sky_hud_op_v1 *op)
{
 Color color={(unsigned char)(op->rgba>>24),(unsigned char)(op->rgba>>16),
  (unsigned char)(op->rgba>>8),(unsigned char)op->rgba};
 Rectangle rect={(float)op->x,(float)op->y,(float)op->w,(float)op->h};
 if(op->kind==SKY_HUD_OP_RECT){DrawRectangleRec(rect,color);return;}
 if(op->kind==SKY_HUD_OP_RECT_LINES){DrawRectangleLinesEx(rect,1.0f,color);return;}
 char text[SKY_HUD_TEXT_BYTES+1];memcpy(text,recipe->text+op->text_off,op->text_len);text[op->text_len]=0;
 Font font=GetFontDefault();float px=(float)op->font_px;
 const float spacing=1.0f;float raw=MeasureTextEx(font,text,px,spacing).x;
 int width=raw>=0.0f && raw<2147483648.0f?(int)raw:0;
 Vector2 at={(float)op->x,(float)op->y};
 if(op->kind==SKY_HUD_OP_TEXT_BOX) {
  rect.x=(float)((int64_t)op->x-width/2-op->w);rect.width=(float)((int64_t)width+2*(int64_t)op->w);
  DrawRectangleRec(rect,color);return;
 } else if(op->align==SKY_HUD_ALIGN_CENTER)at.x=(float)((int64_t)op->x-width/2);
 else if(op->align==SKY_HUD_ALIGN_RIGHT)at.x=(float)((int64_t)op->x-width);
 DrawTextEx(font,text,at,px,spacing,color);
}
/* Read at most65 bytes through one regular-file handle; no shared seek cursor. */
static inline bool sky_expr_pin_bytes(const struct platform_positioned_file *file,char hex[66],size_t n)
{
 size_t at=0;
 while(at<n) {
  int64_t got=platform_positioned_file_read(file,hex+at,n-at,at);
  if(got<=0 || (uint64_t)got>n-at)return false;
  at+=(size_t)got;
 }
 return true;
}
static inline enum expr_status sky_expr_pin_file(const char *path,uint8_t pin[32])
{
 struct platform_positioned_file file;platform_positioned_file_init(&file);
 if(!platform_positioned_file_open(&file,path))return EX_IO;
 struct platform_positioned_file_snapshot before,after;char hex[66]={0};
 enum expr_status status=EX_IO;
 if(platform_positioned_file_snapshot(&file,&before)) {
  status=EX_FORMAT;
  if(before.size==64 || before.size==65) {
   status=EX_IO;
   if(sky_expr_pin_bytes(&file,hex,(size_t)before.size) &&
      platform_positioned_file_snapshot(&file,&after) &&
      platform_positioned_file_snapshot_equal(&before,&after)) {
    status=EX_FORMAT;
    if(before.size==64 || hex[64]=='\n') {
     hex[64]=0;if(zcl_hex_decode(hex,pin,32))status=EX_OK;
    }
   }
  }
 }
 platform_positioned_file_close(&file);return status;
}
/* Admission publishes only on success; any refusal leaves the entire HUD intact. */
static inline enum expr_admit_status sky_expr_reload(const struct sky_expr_option *option,const double fields[XF_COUNT],struct sky_expr_hud *hud)
{
 uint8_t pin[32];enum expr_status detail=sky_expr_pin_file(option->pin_path,pin);
 if(detail!=EX_OK) {
  enum expr_admit_status stage=detail==EX_IO?EX_ADMIT_READ:EX_ADMIT_PIN;
  fprintf(stderr,"HUD reload pin: stage=%u code=%u: pin-file %s\n",
   (unsigned)stage,(unsigned)detail,detail==EX_IO?"read refused":"expected64hex and optional LF");
  return stage;
 }
 enum expr_admit_status stage=expr_admit_file(option->path,pin,fields,256,
  SKY_HUD_MAX_OPS,SKY_HUD_TEXT_BYTES,&hud->part,NULL);
 if(stage==EX_ADMIT_OK)hud->active=true;
 return stage;
}

/* Private admitted state stays immutable. Each frame draws the captured recipe. */
static inline void sky_expr_render(const struct sky_expr_hud *hud,void (*builtin)(void *),void *context)
{
 if(!sky_expr_custom_selected(hud)){builtin(context);return;}
 for(unsigned i=0;i<hud->part.recipe.op_count;i++)
  sky_expr_draw_op(&hud->part.recipe,&hud->part.recipe.ops[i]);
}
#endif
