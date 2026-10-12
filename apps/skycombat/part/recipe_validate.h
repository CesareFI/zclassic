/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0 */
/* Purpose: expose typed recipe refusals while preserving the V1 byte ABI. */
#ifndef SKY_RECIPE_VALIDATE_H
#define SKY_RECIPE_VALIDATE_H
#include "recipe_abi.h"
bool sky_hud_recipe_valid(const struct sky_hud_recipe_v1 *);
enum sky_hud_recipe_error {
    SKY_HUD_RECIPE_OK,SKY_HUD_RECIPE_ABSENT,SKY_HUD_RECIPE_OP_COUNT,
    SKY_HUD_RECIPE_TEXT_COUNT,SKY_HUD_RECIPE_TEXT_BYTES,SKY_HUD_RECIPE_KIND,
    SKY_HUD_RECIPE_GEOMETRY,SKY_HUD_RECIPE_FONT,SKY_HUD_RECIPE_ALIGN,
    SKY_HUD_RECIPE_TEXT_RANGE,SKY_HUD_RECIPE_UNUSED,SKY_HUD_RECIPE_INVALID
};
enum sky_hud_recipe_error sky_hud_recipe_check(const struct sky_hud_recipe_v1 *);
const char *sky_hud_recipe_reason(enum sky_hud_recipe_error);
#endif
