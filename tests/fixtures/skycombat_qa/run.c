/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: execute the actual game entrypoint against a bounded window/draw
 * fixture. No GPU, window system, live input or model correctness is claimed.
 * Missing QA loop bounds stop at 64 frames so regressions cannot hang tests. */
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
static unsigned qa_windows, qa_frames, qa_closed, qa_destroyed, qa_unloads;
static unsigned qa_close_after = 64;
static bool qa_window_failed;
static bool qa_hud_keys;
static int sky_qa_entry(int argc, char **argv);
/* Adapt only the entry signature for the pre-fix main(void) removal witness.
 * The entire production function body, argument admission and loop are used. */
#define main(...) sky_qa_entry([[maybe_unused]] int argc, [[maybe_unused]] char **argv)
#include "../../../apps/skycombat/src/sky_combat_multiplayer_ultimate.c"
#undef main

static aircraft_manager_t qa_aircraft;
static powerup_manager_t qa_powerups;
static match_state_t qa_match;
static cyberpunk_world_t qa_world;
static input_mvc_fast_t qa_input;
static effects_manager_t qa_effects;
static weapons_system_t qa_weapons;

void camera_update_responsive([[maybe_unused]] Camera3D* camera, [[maybe_unused]] Vector3 target, [[maybe_unused]] float yaw, [[maybe_unused]] float distance, [[maybe_unused]] float height, [[maybe_unused]] float dt) {  }
int GetScreenWidth(void) { return 640; }
int GetScreenHeight(void) { return 480; }
int GetRandomValue([[maybe_unused]] int min, [[maybe_unused]] int max) { return (int){0}; }
Color Fade([[maybe_unused]] Color color, [[maybe_unused]] float alpha) { return (Color){0}; }
void DrawLineEx([[maybe_unused]] Vector2 startPos, [[maybe_unused]] Vector2 endPos, [[maybe_unused]] float thick, [[maybe_unused]] Color color) {  }
void rlPushMatrix(void) {  }
void rlTranslatef([[maybe_unused]] float x, [[maybe_unused]] float y, [[maybe_unused]] float z) {  }
void rlRotatef([[maybe_unused]] float angle, [[maybe_unused]] float x, [[maybe_unused]] float y, [[maybe_unused]] float z) {  }
void DrawCube([[maybe_unused]] Vector3 position, [[maybe_unused]] float width, [[maybe_unused]] float height, [[maybe_unused]] float length, [[maybe_unused]] Color color) {  }
void DrawCubeWires([[maybe_unused]] Vector3 position, [[maybe_unused]] float width, [[maybe_unused]] float height, [[maybe_unused]] float length, [[maybe_unused]] Color color) {  }
void DrawSphere([[maybe_unused]] Vector3 centerPos, [[maybe_unused]] float radius, [[maybe_unused]] Color color) {  }
void DrawCircle3D([[maybe_unused]] Vector3 center, [[maybe_unused]] float radius, [[maybe_unused]] Vector3 rotationAxis, [[maybe_unused]] float rotationAngle, [[maybe_unused]] Color color) {  }
void rlPopMatrix(void) {  }
void effects_spawn_explosion([[maybe_unused]] effects_manager_t* manager, [[maybe_unused]] Vector3 pos, [[maybe_unused]] float radius, [[maybe_unused]] Color color) {  }
managed_aircraft_t* aircraft_manager_get([[maybe_unused]] aircraft_manager_t* manager, [[maybe_unused]] int id) { return NULL; }
void DrawFPS([[maybe_unused]] int posX, [[maybe_unused]] int posY) {  }
void DrawText([[maybe_unused]] const char *text, [[maybe_unused]] int posX, [[maybe_unused]] int posY, [[maybe_unused]] int fontSize, [[maybe_unused]] Color color) {  }
Font GetFontDefault(void) { return (Font){0}; }
Vector2 MeasureTextEx([[maybe_unused]] Font font, [[maybe_unused]] const char *text, [[maybe_unused]] float fontSize, [[maybe_unused]] float spacing) { return (Vector2){0}; }
void DrawTextEx([[maybe_unused]] Font font, const char *text, [[maybe_unused]] Vector2 position, [[maybe_unused]] float fontSize, [[maybe_unused]] float spacing, [[maybe_unused]] Color color) { printf("QA_HUD_TEXT frame=%u text=%s\n", qa_frames, text); }
void DrawRectangleRec(Rectangle rect, Color color) { printf("QA_HUD_RECT frame=%u rgba=%u,%u,%u,%u rect=%.0f,%.0f,%.0f,%.0f\n", qa_frames, color.r, color.g, color.b, color.a, (double)rect.x, (double)rect.y, (double)rect.width, (double)rect.height); }
void DrawRectangleLinesEx([[maybe_unused]] Rectangle rect, [[maybe_unused]] float thickness, [[maybe_unused]] Color color) { }
int MeasureText([[maybe_unused]] const char *text, [[maybe_unused]] int fontSize) { return (int){0}; }
void DrawRectangle([[maybe_unused]] int posX, [[maybe_unused]] int posY, [[maybe_unused]] int width, [[maybe_unused]] int height, [[maybe_unused]] Color color) {  }
const char * TextFormat([[maybe_unused]] const char *text, ...) { return ""; }
void DrawRectangleLines([[maybe_unused]] int posX, [[maybe_unused]] int posY, [[maybe_unused]] int width, [[maybe_unused]] int height, [[maybe_unused]] Color color) {  }
bool match_state_finish([[maybe_unused]] match_state_t* state) { return (bool){0}; }
void input_mvc_fast_destroy([[maybe_unused]] input_mvc_fast_t* mvc) { qa_destroyed |= 1u; }
void cyberpunk_world_destroy([[maybe_unused]] cyberpunk_world_t* world) { qa_destroyed |= 2u; }
void match_state_destroy([[maybe_unused]] match_state_t* state) { qa_destroyed |= 4u; }
void powerup_manager_destroy([[maybe_unused]] powerup_manager_t* manager) { qa_destroyed |= 8u; }
void aircraft_manager_destroy([[maybe_unused]] aircraft_manager_t* manager) { qa_destroyed |= 16u; }
void effects_destroy([[maybe_unused]] effects_manager_t* manager) { qa_destroyed |= 32u; }
void weapons_destroy([[maybe_unused]] weapons_system_t* weapons) { qa_destroyed |= 64u; }
bool match_state_set_team_scores([[maybe_unused]] match_state_t* state, [[maybe_unused]] const int scores[4]) { return true; }
void match_state_update([[maybe_unused]] match_state_t* state, [[maybe_unused]] float dt) {  }
void SetConfigFlags([[maybe_unused]] unsigned int flags) {  }
void InitWindow([[maybe_unused]] int width, [[maybe_unused]] int height, [[maybe_unused]] const char *title) { ++qa_windows; }
void SetTargetFPS([[maybe_unused]] int fps) {  }
aircraft_manager_t* aircraft_manager_create(void) { return &qa_aircraft; }
powerup_manager_t* powerup_manager_create(void) { return &qa_powerups; }
match_state_t* match_state_create([[maybe_unused]] match_type_t type) { return &qa_match; }
cyberpunk_world_t* cyberpunk_world_create(void) { return &qa_world; }
input_mvc_fast_t* input_mvc_fast_create(void) { qa_input.view.model = &qa_input.model; return &qa_input; }
effects_manager_t* effects_create([[maybe_unused]] int max_effects, [[maybe_unused]] int max_particles) { return &qa_effects; }
weapons_system_t* weapons_create(void) { return &qa_weapons; }
bool match_state_begin([[maybe_unused]] match_state_t* state) { return true; }
void CloseWindow(void) { ++qa_closed; }
int aircraft_manager_add_with_team([[maybe_unused]] aircraft_manager_t* manager, [[maybe_unused]] const char* name, [[maybe_unused]] Color color, [[maybe_unused]] bool is_ai, [[maybe_unused]] bool is_local, [[maybe_unused]] int team_id) { return (int){0}; }
void powerup_manager_add_spawn_point([[maybe_unused]] powerup_manager_t* manager, [[maybe_unused]] Vector3 position, [[maybe_unused]] powerup_type_t type, [[maybe_unused]] float respawn_time) {  }
void cyberpunk_world_generate([[maybe_unused]] cyberpunk_world_t* world, [[maybe_unused]] int seed) {  }
void cyberpunk_set_theme_blade_runner([[maybe_unused]] cyberpunk_world_t* world) {  }
RenderTexture2D LoadRenderTexture([[maybe_unused]] int width, [[maybe_unused]] int height) { return (RenderTexture2D){0}; }
bool WindowShouldClose(void) { return qa_frames >= qa_close_after; }
float GetFrameTime(void) { return 1.0f / 60.0f; }
bool IsKeyDown([[maybe_unused]] int key) { return (bool){0}; }
void aircraft_update_responsive([[maybe_unused]] aircraft_t* aircraft, [[maybe_unused]] float stick_x, [[maybe_unused]] float stick_y, [[maybe_unused]] float dt) {  }
bool IsKeyPressed(int key) {
    return qa_hud_keys && ((key == KEY_F6 && qa_frames == 1) ||
        (key == KEY_F7 && (qa_frames == 2 || qa_frames == 3)));
}
void effects_sonic_boom([[maybe_unused]] effects_manager_t* manager, [[maybe_unused]] Vector3 pos, [[maybe_unused]] Vector3 direction) {  }
Vector3 aircraft_get_forward_vector([[maybe_unused]] aircraft_t* aircraft) { return (Vector3){0}; }
void effects_screen_shake([[maybe_unused]] effects_manager_t* manager, [[maybe_unused]] float intensity, [[maybe_unused]] float duration) {  }
void effects_screen_flash([[maybe_unused]] effects_manager_t* manager, [[maybe_unused]] Color color, [[maybe_unused]] float duration) {  }
void effects_spawn_powerup_collect([[maybe_unused]] effects_manager_t* manager, [[maybe_unused]] Vector3 pos, [[maybe_unused]] Color color) {  }
void aircraft_manager_fire_weapon([[maybe_unused]] aircraft_manager_t* manager, [[maybe_unused]] int aircraft_id) {  }
void weapons_fire_bullet([[maybe_unused]] weapons_system_t* weapons, [[maybe_unused]] Vector3 position, [[maybe_unused]] Vector3 direction, [[maybe_unused]] float yaw) {  }
void effects_spawn_laser_hit([[maybe_unused]] effects_manager_t* manager, [[maybe_unused]] Vector3 pos, [[maybe_unused]] Vector3 normal, [[maybe_unused]] Color color) {  }
void aircraft_manager_update([[maybe_unused]] aircraft_manager_t* manager, [[maybe_unused]] float dt) {  }
void powerup_manager_update([[maybe_unused]] powerup_manager_t* manager, [[maybe_unused]] float dt) {  }
void weapons_update([[maybe_unused]] weapons_system_t* weapons, [[maybe_unused]] float dt) {  }
void effects_update([[maybe_unused]] effects_manager_t* manager, [[maybe_unused]] float dt) {  }
bool powerup_manager_check_collection([[maybe_unused]] powerup_manager_t* manager, [[maybe_unused]] Vector3 position, [[maybe_unused]] float radius, [[maybe_unused]] powerup_type_t* collected_type) { return (bool){0}; }
void effects_show_achievement([[maybe_unused]] effects_manager_t* manager, [[maybe_unused]] const char* text) {  }
void BeginTextureMode([[maybe_unused]] RenderTexture2D target) {  }
void ClearBackground([[maybe_unused]] Color color) {  }
void BeginMode3D([[maybe_unused]] Camera3D camera) {  }
void cyberpunk_world_draw([[maybe_unused]] cyberpunk_world_t* world, [[maybe_unused]] Camera3D camera) {  }
void weapons_draw([[maybe_unused]] weapons_system_t* weapons) {  }
void effects_draw([[maybe_unused]] effects_manager_t* manager, [[maybe_unused]] Camera3D camera) {  }
void EndMode3D(void) {  }
void EndTextureMode(void) {  }
void BeginDrawing(void) {  }
void DrawTextureRec([[maybe_unused]] Texture2D texture, [[maybe_unused]] Rectangle rec, [[maybe_unused]] Vector2 position, [[maybe_unused]] Color tint) {  }
void effects_draw_ui([[maybe_unused]] effects_manager_t* manager, [[maybe_unused]] int screen_width, [[maybe_unused]] int screen_height) {  }
void EndDrawing(void) { ++qa_frames; }
void UnloadRenderTexture([[maybe_unused]] RenderTexture2D target) { ++qa_unloads; }
void input_controller_fast_update([[maybe_unused]] input_controller_fast_t* controller) {  }
bool IsWindowReady(void) { return !qa_window_failed; }

int main(int argc, char **argv)
{
    if (argc > 1 && strcmp(argv[1], "--fixture-hud-keys") == 0) {
        qa_hud_keys = true; --argc; ++argv;
    } else if (argc > 1 && strcmp(argv[1], "--fixture-close=2") == 0) {
        qa_close_after = 2; --argc; ++argv;
    } else if (argc > 1 && strcmp(argv[1], "--fixture-window-fails") == 0) {
        qa_window_failed = true; --argc; ++argv;
    }
    int result = sky_qa_entry(argc, argv);
    printf("QA_TEST status=%d windows=%u frames=%u closed=%u destroyed=%u unloads=%u\n",
        result, qa_windows, qa_frames, qa_closed, qa_destroyed, qa_unloads);
    return result;
}
