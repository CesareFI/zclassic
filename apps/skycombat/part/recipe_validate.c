/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0 */
/* Purpose: validate complete bounded HUD recipes before any rendering. */
#include "recipe_validate.h"
static bool coordinate(int32_t v){return v>=-32768 && v<=32768;}
static bool geometry(const struct sky_hud_op_v1 *o)
{
    return coordinate(o->x) && coordinate(o->y) && coordinate(o->w) && coordinate(o->h);
}
static enum sky_hud_recipe_error text_op(const struct sky_hud_op_v1 *o,uint32_t used)
{
    if(!o->font_px || o->font_px>512)return SKY_HUD_RECIPE_FONT;
    if(o->align>SKY_HUD_ALIGN_RIGHT)return SKY_HUD_RECIPE_ALIGN;
    if(o->text_off>used || o->text_len>used-o->text_off)return SKY_HUD_RECIPE_TEXT_RANGE;
    if(o->kind==SKY_HUD_OP_TEXT && (o->w || o->h))return SKY_HUD_RECIPE_UNUSED;
    if(o->kind==SKY_HUD_OP_TEXT_BOX && (o->w<0 || o->h<0 || o->align))return SKY_HUD_RECIPE_GEOMETRY;
    return SKY_HUD_RECIPE_OK;
}
static enum sky_hud_recipe_error operation(const struct sky_hud_op_v1 *o,uint32_t used)
{
    if(o->kind!=SKY_HUD_OP_TEXT && o->kind!=SKY_HUD_OP_TEXT_BOX &&
       o->kind!=SKY_HUD_OP_RECT && o->kind!=SKY_HUD_OP_RECT_LINES)return SKY_HUD_RECIPE_KIND;
    if(!geometry(o))return SKY_HUD_RECIPE_GEOMETRY;
    if(o->kind==SKY_HUD_OP_TEXT || o->kind==SKY_HUD_OP_TEXT_BOX)return text_op(o,used);
    if(o->font_px || o->align || o->text_off || o->text_len)return SKY_HUD_RECIPE_UNUSED;
    return SKY_HUD_RECIPE_OK;
}
enum sky_hud_recipe_error sky_hud_recipe_check(const struct sky_hud_recipe_v1 *r)
{
    if(!r)return SKY_HUD_RECIPE_ABSENT;
    if(r->op_count>SKY_HUD_MAX_OPS)return SKY_HUD_RECIPE_OP_COUNT;
    if(r->text_used>SKY_HUD_TEXT_BYTES)return SKY_HUD_RECIPE_TEXT_COUNT;
    for(uint32_t i=0;i<r->text_used;++i)
        if(r->text[i]<0x20 || r->text[i]>0x7e)return SKY_HUD_RECIPE_TEXT_BYTES;
    for(uint32_t i=0;i<r->op_count;++i){
        enum sky_hud_recipe_error error=operation(&r->ops[i],r->text_used);
        if(error!=SKY_HUD_RECIPE_OK)return error;
    }
    return SKY_HUD_RECIPE_OK;
}
bool sky_hud_recipe_valid(const struct sky_hud_recipe_v1 *r)
{
    return sky_hud_recipe_check(r)==SKY_HUD_RECIPE_OK;
}
const char *sky_hud_recipe_reason(enum sky_hud_recipe_error e)
{
    switch(e){
    case SKY_HUD_RECIPE_OK:return "none";
    case SKY_HUD_RECIPE_ABSENT:return "recipe_absent";
    case SKY_HUD_RECIPE_OP_COUNT:return "op_count";
    case SKY_HUD_RECIPE_TEXT_COUNT:return "text_count";
    case SKY_HUD_RECIPE_TEXT_BYTES:return "text_bytes";
    case SKY_HUD_RECIPE_KIND:return "op_kind";
    case SKY_HUD_RECIPE_GEOMETRY:return "geometry";
    case SKY_HUD_RECIPE_FONT:return "font";
    case SKY_HUD_RECIPE_ALIGN:return "align";
    case SKY_HUD_RECIPE_TEXT_RANGE:return "text_range";
    case SKY_HUD_RECIPE_UNUSED:return "unused_fields";
    default:return "recipe_invalid";
    }
}
