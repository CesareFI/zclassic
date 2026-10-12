/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: deterministic timer: time derives from a caller tick count, with
 * one compare register and wfi fast-forward arithmetic. No host clock. */
#ifndef RVPLAT_TIMER_H
#define RVPLAT_TIMER_H

#include <stdbool.h>
#include <stdint.h>

/* Compare value meaning "disarmed" (SBI TIME: writing all-ones clears the
 * pending timer interrupt). */
#define RVPLAT_TIMER_DISARMED UINT64_MAX

struct rvplat_timer {
    uint64_t ticks_per_time; /* caller ticks (retired instructions) per time unit */
    uint64_t deadline;
};

/* ticks_per_time of 0 is treated as 1. The timer starts disarmed. */
void rvplat_timer_init(struct rvplat_timer *timer, uint64_t ticks_per_time);

/* time = ticks / ticks_per_time. */
uint64_t rvplat_timer_time(const struct rvplat_timer *timer, uint64_t ticks);

/* First tick count at which time reaches `time`, saturating at UINT64_MAX. */
uint64_t rvplat_timer_ticks_for_time(const struct rvplat_timer *timer,
                                     uint64_t time);

void rvplat_timer_set_timer(struct rvplat_timer *timer, uint64_t deadline);

/* Pending exactly when now >= deadline and the timer is armed. */
bool rvplat_timer_pending(const struct rvplat_timer *timer, uint64_t now);

/* Time units from now until the timer fires: 0 when already pending,
 * UINT64_MAX when disarmed. Never overflows. */
uint64_t rvplat_timer_next_event(const struct rvplat_timer *timer,
                                 uint64_t now);

/* Tick count at which the timer fires for a wfi fast-forward: `ticks` when
 * already pending, UINT64_MAX when disarmed or unreachable. */
uint64_t rvplat_timer_next_event_ticks(const struct rvplat_timer *timer,
                                       uint64_t ticks);

#endif
