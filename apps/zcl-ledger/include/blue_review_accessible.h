/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#ifndef ZCL_BLUE_REVIEW_ACCESSIBLE_H
#define ZCL_BLUE_REVIEW_ACCESSIBLE_H

#include <stdbool.h>

/* Wraps one 31-character review detail at BAGL's 22-pixel font width. */
bool blue_review_accessible_wrap(const char *source, char destination[40]);

#endif
