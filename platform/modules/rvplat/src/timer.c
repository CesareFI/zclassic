/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: tick-driven deterministic timer with a compare register. */
#include "rvplat/timer.h"

void rvplat_timer_init(struct rvplat_timer *timer, uint64_t ticks_per_time)
{
    timer->ticks_per_time = ticks_per_time == 0u ? 1u : ticks_per_time;
    timer->deadline = RVPLAT_TIMER_DISARMED;
}

uint64_t rvplat_timer_time(const struct rvplat_timer *timer, uint64_t ticks)
{
    return ticks / timer->ticks_per_time;
}

uint64_t rvplat_timer_ticks_for_time(const struct rvplat_timer *timer,
                                     uint64_t time)
{
    if (time > UINT64_MAX / timer->ticks_per_time)
        return UINT64_MAX;
    return time * timer->ticks_per_time;
}

void rvplat_timer_set_timer(struct rvplat_timer *timer, uint64_t deadline)
{
    timer->deadline = deadline;
}

bool rvplat_timer_pending(const struct rvplat_timer *timer, uint64_t now)
{
    return timer->deadline != RVPLAT_TIMER_DISARMED && now >= timer->deadline;
}

uint64_t rvplat_timer_next_event(const struct rvplat_timer *timer,
                                 uint64_t now)
{
    if (timer->deadline == RVPLAT_TIMER_DISARMED)
        return UINT64_MAX;
    if (now >= timer->deadline)
        return 0u;
    return timer->deadline - now;
}

uint64_t rvplat_timer_next_event_ticks(const struct rvplat_timer *timer,
                                       uint64_t ticks)
{
    uint64_t now = rvplat_timer_time(timer, ticks);
    if (timer->deadline == RVPLAT_TIMER_DISARMED)
        return UINT64_MAX;
    if (now >= timer->deadline)
        return ticks;
    return rvplat_timer_ticks_for_time(timer, timer->deadline);
}
