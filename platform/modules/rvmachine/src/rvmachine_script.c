/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: the console script. It watches the console output for markers,
 * types the scripted text when one appears and requests a stop at the stop
 * marker. It keeps only the tail of the output, enough for the longest
 * marker. */
#include "rvmachine/rvmachine.h"

#include <string.h>

void rvmachine_script_init(struct rvmachine_script *script)
{
    if (script != NULL) memset(script, 0, sizeof *script);
}

bool rvmachine_script_add(struct rvmachine_script *script, const char *marker,
                          size_t marker_len, const char *text, size_t text_len)
{
    struct rvmachine_script_step *step;
    if (script == NULL || marker == NULL || (text == NULL && text_len != 0))
        return false;
    if (script->count == RVMACHINE_SCRIPT_STEPS || marker_len == 0 ||
        marker_len > RVMACHINE_SCRIPT_MARKER_MAX ||
        text_len > RVMACHINE_SCRIPT_TEXT_MAX)
        return false;
    step = &script->steps[script->count++];
    memcpy(step->marker, marker, marker_len);
    step->marker[marker_len] = '\0';
    step->marker_len = marker_len;
    if (text_len != 0) memcpy(step->text, text, text_len);
    step->text[text_len] = '\0';
    step->text_len = text_len;
    return true;
}

bool rvmachine_script_until(struct rvmachine_script *script, const char *marker,
                            size_t marker_len)
{
    if (script == NULL || marker == NULL || marker_len == 0 ||
        marker_len > RVMACHINE_SCRIPT_MARKER_MAX)
        return false;
    memcpy(script->until, marker, marker_len);
    script->until[marker_len] = '\0';
    script->until_len = marker_len;
    return true;
}

static bool tail_ends_with(const struct rvmachine_script *s, const char *text,
                           size_t len)
{
    return len != 0 && s->tail_len >= len &&
           memcmp(s->tail + s->tail_len - len, text, len) == 0;
}

/* Keeps the newest half when the tail is full; a marker is at most half. */
static void tail_push(struct rvmachine_script *s, uint8_t byte)
{
    if (s->tail_len == RVMACHINE_SCRIPT_TAIL) {
        memmove(s->tail, s->tail + RVMACHINE_SCRIPT_TAIL / 2u,
                RVMACHINE_SCRIPT_TAIL / 2u);
        s->tail_len = RVMACHINE_SCRIPT_TAIL / 2u;
    }
    s->tail[s->tail_len++] = (char)byte;
}

void rvmachine_script_console(struct rvmachine_script *script, struct rvmachine *m,
                              uint8_t byte)
{
    if (script == NULL) return;
    script->console_bytes++;
    tail_push(script, byte);
    if (script->fired < script->count) {
        const struct rvmachine_script_step *step = &script->steps[script->fired];
        if (!tail_ends_with(script, step->marker, step->marker_len)) return;
        (void)rvmachine_console_input(m, (const uint8_t *)step->text, step->text_len);
        script->fired++;
        script->tail_len = 0;
        return;
    }
    if (!script->until_seen &&
        tail_ends_with(script, script->until, script->until_len)) {
        script->until_seen = true;
        rvmachine_request_stop(m);
    }
}

bool rvmachine_script_met(const struct rvmachine_script *script)
{
    if (script == NULL) return false;
    return script->fired == script->count &&
           (script->until_len == 0 || script->until_seen);
}
