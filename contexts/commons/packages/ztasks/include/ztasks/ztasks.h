/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0 */
/* Purpose: value-only task state; storage and process authority stay with the host. */
#ifndef ZTASKS_H
#define ZTASKS_H
#include <stdbool.h>
#include <stdint.h>
#define TA_MAX_TASKS 32u
#define TA_TITLE 96u
#define TA_PAYLOAD 4096u
#define TA_SCHEMA 1u
struct ta_task { uint64_t id; uint32_t done; char title[TA_TITLE]; };
struct ta_state { uint64_t revision, last_write; uint32_t count; struct ta_task tasks[TA_MAX_TASKS]; };
bool ta_title_valid(const char *);
/* Output buffer has TA_PAYLOAD bytes. Canonical schema rejects lossy migration. */
bool ta_state_encode(const struct ta_state *, unsigned char *, uint32_t *);
bool ta_state_decode(const unsigned char *, uint32_t, struct ta_state *);
#endif
