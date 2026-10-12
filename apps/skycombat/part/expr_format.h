/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: Define the bounded data-only HUD wire validator contract. */
#ifndef SKY_EXPR_FORMAT_H
#define SKY_EXPR_FORMAT_H
#include <stddef.h>
#include <stdint.h>
#define EXPR_NONE UINT16_MAX
#define EXPR_MAX_BYTES 10272u
enum expr_opcode { EX_CONST_I32=1, EX_FIELD, EX_ADD_SAT, EX_SUB_SAT,
 EX_MIN, EX_MAX, EX_CLAMP, EX_MULDIV, EX_LT, EX_LE, EX_EQ, EX_AND,
 EX_OR, EX_NOT, EX_SELECT };
enum expr_type { EX_I32=1, EX_BOOL };
enum expr_field { XF_SCREEN_W, XF_SCREEN_H, XF_ELAPSED_SECONDS, XF_TEAM_COUNT,
 XF_SCORE_0, XF_SCORE_1, XF_SCORE_2, XF_SCORE_3, XF_SCORE_LIMIT, XF_HEALTH_MILLI,
 XF_MAX_HEALTH_MILLI, XF_BOOST_MS, XF_WEAPON_INDEX, XF_SHIELD, XF_CONNECTED,
 XF_FLASH, XF_COUNT };
enum expr_status { EX_OK, EX_ARGUMENT, EX_FORMAT, EX_BOUNDS, EX_LIMIT,
 EX_OPCODE, EX_TYPE, EX_REFERENCE, EX_FIELD_ID, EX_SCHEMA, EX_LITERAL,
 EX_TEXT_BUDGET, EX_DIV_ZERO, EX_RANGE, EX_EVAL_BUDGET, EX_SNAPSHOT, EX_VALUES, EX_OUTPUT, EX_IO };
struct expr_info { unsigned expressions, draws, texts, pieces, literal_bytes,
 worst_text, worst_draw_text; };
struct expr_error { enum expr_status code; unsigned index; const char *reason; };
/* bytes must denote n valid immutable bytes for the call. No allocation or
 * input retention; info is required and changes only on success. error may be
 * NULL; its trusted reason/index describe the rejected record, not an offset. */
enum expr_status expr_validate(const void *bytes, size_t n,
 struct expr_info *info, struct expr_error *error);
struct expr_values { unsigned count, steps; int32_t value[256]; };
/* All inputs stay immutable; fields has XF_COUNT doubles representing exact
 * I32 values (BOOL fields 0 or 1). out changes only on complete success.
 * Validation precedes at most 256 eager expression steps; budget is 0..256. */
enum expr_status expr_evaluate(const void *bytes, size_t n,
 const double fields[XF_COUNT], unsigned budget, struct expr_values *out,
 struct expr_error *error);
#define SKY_HUD_MAX_OPS 64u
#define SKY_HUD_TEXT_BYTES 1024u
enum { SKY_HUD_OP_RECT=1, SKY_HUD_OP_RECT_LINES, SKY_HUD_OP_TEXT, SKY_HUD_OP_TEXT_BOX };
enum { SKY_HUD_ALIGN_LEFT, SKY_HUD_ALIGN_CENTER, SKY_HUD_ALIGN_RIGHT };
/* Data-only recipe ABI from the supplied SKY_HUD_PART v1.2 contract. */
struct sky_hud_op_v1 {
 uint32_t kind; int32_t x,y,w,h;
 uint32_t rgba,font_px,align,text_off,text_len;
};
struct sky_hud_recipe_v1 {
 uint32_t op_count,text_used;
 struct sky_hud_op_v1 ops[SKY_HUD_MAX_OPS]; uint8_t text[SKY_HUD_TEXT_BYTES];
};
_Static_assert(sizeof(struct sky_hud_op_v1)==40,"HUD op ABI");
_Static_assert(offsetof(struct sky_hud_recipe_v1,text)==2568,"HUD text offset");
_Static_assert(sizeof(struct sky_hud_recipe_v1)==3592,"HUD recipe ABI");
/* values must be the complete evaluation of this immutable part. Capacities
 * may reduce the fixed ABI limits. Whole output changes only on success. */
enum expr_status expr_build_draws(const void *bytes, size_t n,
 const struct expr_values *values, unsigned op_capacity, unsigned text_capacity,
 struct sky_hud_recipe_v1 *out, struct expr_error *error);
enum expr_admit_status { EX_ADMIT_OK, EX_ADMIT_ARGUMENT, EX_ADMIT_READ,
 EX_ADMIT_PIN, EX_ADMIT_VALIDATE, EX_ADMIT_EVALUATE, EX_ADMIT_DRAW };
struct expr_part {
 size_t length; uint8_t sha256[32],bytes[EXPR_MAX_BYTES];
 struct sky_hud_recipe_v1 recipe;
};
struct expr_admit_error {
 enum expr_admit_status stage; struct expr_error detail;
};
/* Caller supplies a raw 32-byte pin and normalized immutable snapshot.
 * Fixed-size current changes only after every stage succeeds. Error optional. */
enum expr_admit_status expr_admit_file(const char *path,const uint8_t pin[32],
 const double fields[XF_COUNT],unsigned budget,unsigned op_capacity,
 unsigned text_capacity,struct expr_part *current,struct expr_admit_error *error);
#endif
