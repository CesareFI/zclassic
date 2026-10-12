/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0 */
/* purpose: parse a bounded canonical QA frame count without changing output on refusal. */
#ifndef SKY_COMBAT_QA_FRAMES_H
#define SKY_COMBAT_QA_FRAMES_H
#include <stdbool.h>
#include <string.h>
/* At 60 fps the ceiling is one minute; external watchdogs still bound hangs. */
#define SKY_COMBAT_QA_FRAMES_MAX 3600u
/* Zero selects the unchanged interactive path. Failure leaves output unchanged. */
static inline bool sky_combat_qa_frames_parse(int argc, char *const argv[],
                                             unsigned *frames)
{
    const char prefix[] = "--qa-frames=";
    if (!frames || !argv || argc < 1) return false;
    if (argc == 1) { *frames = 0; return true; }
    if (argc != 2 || !argv[1] ||
        strncmp(argv[1], prefix, sizeof(prefix) - 1) != 0) return false;
    const char *digits = argv[1] + sizeof(prefix) - 1;
    if (*digits < '1' || *digits > '9') return false;
    unsigned count = 0;
    for (; *digits; ++digits) {
        if (*digits < '0' || *digits > '9') return false;
        unsigned digit = (unsigned)(*digits - '0');
        if (count > (SKY_COMBAT_QA_FRAMES_MAX - digit) / 10u) return false;
        count = count * 10u + digit;
    }
    *frames = count;
    return true;
}
#endif
