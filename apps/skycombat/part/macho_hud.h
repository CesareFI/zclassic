/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: Admit and open bounded Apple Silicon HUD parts with explicit host ownership. */
#ifndef SKY_PART_STANDALONE_HUD_H
#define SKY_PART_STANDALONE_HUD_H
#include <stdint.h>
#define SKY_HUD_ABI_V1 1u
#define SKY_HUD_MAX_OPS 64u
#define SKY_HUD_TEXT_BYTES 1024u
#define SKY_HUD_MAX_TEAMS 4u
struct sky_hud_snapshot_v1 {
 uint32_t abi,size,tick; int32_t screen_w,screen_h;
 uint32_t elapsed_ms,team_count,team_score[4],score_limit;
 int32_t health_milli,max_health_milli;
 uint32_t boost_ms,weapon,flags;
};
struct sky_hud_op_v1 {
 uint32_t kind; int32_t x,y,w,h;
 uint32_t rgba,font_px,align,text_off,text_len;
};
struct sky_hud_recipe_v1 {
 uint32_t op_count,text_used;
 struct sky_hud_op_v1 ops[64]; uint8_t text[1024];
};
struct sky_hud_part_v1 {
 uint32_t abi,size;
 int32_t (*build)(const struct sky_hud_snapshot_v1 *,struct sky_hud_recipe_v1 *);
};
extern const struct sky_hud_part_v1 sky_hud_part_v1;
_Static_assert(sizeof(struct sky_hud_snapshot_v1)==68,"snapshot layout");
_Static_assert(sizeof(struct sky_hud_op_v1)==40,"op layout");
_Static_assert(sizeof(struct sky_hud_recipe_v1)==3592,"recipe layout");
#endif
