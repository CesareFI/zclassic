/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0 */
/* Purpose: retain the portable V1 HUD snapshot, operation and recipe byte ABI. */
#ifndef SKY_RECIPE_ABI_H
#define SKY_RECIPE_ABI_H
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#define SKY_HUD_ABI_V1        1u
#define SKY_HUD_MAX_OPS       64u
#define SKY_HUD_TEXT_BYTES    1024u
#define SKY_HUD_MAX_TEAMS     4u

struct sky_hud_snapshot_v1 {        /* host -> part, read-only */
    uint32_t abi;                   /* SKY_HUD_ABI_V1 */
    uint32_t size;                  /* sizeof(struct sky_hud_snapshot_v1) */
    uint32_t tick;                  /* simulation tick of this frame */
    int32_t  screen_w, screen_h;    /* logical HUD space in pixels */
    uint32_t elapsed_ms;            /* match time */
    uint32_t team_count;            /* 0..SKY_HUD_MAX_TEAMS */
    uint32_t team_score[SKY_HUD_MAX_TEAMS];
    uint32_t score_limit;
    int32_t  health_milli;          /* health * 1000, may be <= 0 */
    int32_t  max_health_milli;      /* may be <= 0: part must not divide by it */
    uint32_t boost_ms;              /* 0 when inactive; full bar is 750 */
    uint32_t weapon;                /* index, part reduces modulo 4 */
    uint32_t flags;                 /* bit0 shield, bit1 controller connected,
                                       bit2 damage flash active */
};

enum { SKY_HUD_OP_RECT = 1, SKY_HUD_OP_RECT_LINES = 2, SKY_HUD_OP_TEXT = 3 };
enum { SKY_HUD_ALIGN_LEFT = 0, SKY_HUD_ALIGN_CENTER = 1, SKY_HUD_ALIGN_RIGHT = 2 };

struct sky_hud_op_v1 {
    uint32_t kind;
    int32_t  x, y, w, h;            /* TEXT: x,y anchor; w,h unused (0) */
    uint32_t rgba;                  /* 0xRRGGBBAA */
    uint32_t font_px;               /* TEXT only, else 0 */
    uint32_t align;                 /* TEXT only, else 0 */
    uint32_t text_off, text_len;    /* TEXT only: bytes in recipe text arena */
};

struct sky_hud_recipe_v1 {          /* host-allocated, part fills */
    uint32_t op_count;              /* <= SKY_HUD_MAX_OPS */
    uint32_t text_used;             /* <= SKY_HUD_TEXT_BYTES */
    struct sky_hud_op_v1 ops[SKY_HUD_MAX_OPS];
    uint8_t  text[SKY_HUD_TEXT_BYTES];   /* ASCII 0x20..0x7E only */
};

struct sky_hud_part_v1 {            /* the one exported object */
    uint32_t abi;                   /* SKY_HUD_ABI_V1, first member */
    uint32_t size;                  /* sizeof(struct sky_hud_part_v1) */
    int32_t (*build)(const struct sky_hud_snapshot_v1 *in,
                     struct sky_hud_recipe_v1 *out);
};
extern const struct sky_hud_part_v1 sky_hud_part_v1;   /* sole export */
enum { SKY_HUD_OP_TEXT_BOX = 4 };
static_assert(sizeof(struct sky_hud_snapshot_v1)==68);
static_assert(sizeof(struct sky_hud_op_v1)==40);
static_assert(sizeof(struct sky_hud_recipe_v1)==3592);
#endif
