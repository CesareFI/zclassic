/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * Purpose: token-bucket and sliding-window rate limiting.
 */
#include "zrate/zrate.h"

#include <math.h>
#include <string.h>

/* --- Token bucket ---------------------------------------------------- */

static void refill(zrate_bucket *b, uint64_t now_ms)
{
    if (now_ms <= b->last_ms) return; /* clock must not go backwards */
    double elapsed_s = (double)(now_ms - b->last_ms) / 1000.0;
    b->tokens += b->rate_per_sec * elapsed_s;
    if (b->tokens > b->capacity) b->tokens = b->capacity;
    b->last_ms = now_ms;
}

void zrate_bucket_init(zrate_bucket *b, double capacity,
                       double rate_per_sec, uint64_t now_ms)
{
    if (!b) return;
    if (!isfinite(capacity) || capacity < 0) capacity = 0;
    if (!isfinite(rate_per_sec) || rate_per_sec < 0) rate_per_sec = 0;
    b->capacity = capacity;
    b->tokens = capacity;
    b->rate_per_sec = rate_per_sec;
    b->last_ms = now_ms;
}

bool zrate_bucket_take(zrate_bucket *b, double n, uint64_t now_ms)
{
    if (!b || !isfinite(n) || n < 0) return false;
    refill(b, now_ms);
    if (n > b->tokens) return false;
    b->tokens -= n;
    return true;
}

uint64_t zrate_bucket_wait_ms(zrate_bucket *b, double n, uint64_t now_ms)
{
    if (!b || !isfinite(n) || n < 0 || n > b->capacity) return UINT64_MAX;
    refill(b, now_ms);
    if (n <= b->tokens) return 0;
    if (b->rate_per_sec <= 0) return UINT64_MAX;
    double missing = n - b->tokens;
    double secs = missing / b->rate_per_sec;
    uint64_t ms = (uint64_t)(secs * 1000.0);
    /* Round up so the wait is never too short. */
    if ((double)ms < secs * 1000.0) ms++;
    return ms;
}

double zrate_bucket_peek(const zrate_bucket *b, uint64_t now_ms)
{
    if (!b) return 0;
    zrate_bucket tmp = *b;
    refill(&tmp, now_ms);
    return tmp.tokens;
}

/* --- Sliding-window counter ------------------------------------------ */

void zrate_window_init(zrate_window *w, uint64_t *events,
                       uint32_t limit, uint64_t interval_ms)
{
    if (!w) return;
    w->events = events;
    w->limit = limit;
    w->count = 0;
    w->head = 0;
    w->interval_ms = interval_ms;
}

static void expire(zrate_window *w, uint64_t now_ms)
{
    while (w->count > 0) {
        uint64_t oldest = w->events[w->head];
        if (now_ms - oldest < w->interval_ms && now_ms >= oldest)
            break;
        w->head = (w->head + 1) % w->limit;
        w->count--;
    }
}

bool zrate_window_hit(zrate_window *w, uint64_t now_ms)
{
    if (!w || !w->events || w->limit == 0) return false;
    expire(w, now_ms);
    if (w->count >= w->limit) return false;
    uint32_t slot = (w->head + w->count) % w->limit;
    w->events[slot] = now_ms;
    w->count++;
    return true;
}

static bool window_enabled(const zrate_window *w)
{
    return w && w->events && w->limit != 0;
}

static uint64_t unavailable_wait(const zrate_window *w)
{
    return w ? UINT64_MAX : 0;
}

uint32_t zrate_window_count(const zrate_window *w, uint64_t now_ms)
{
    if (!window_enabled(w)) return 0;
    zrate_window tmp = *w;
    expire(&tmp, now_ms);
    return tmp.count;
}

uint64_t zrate_window_wait_ms(const zrate_window *w, uint64_t now_ms)
{
    if (!window_enabled(w)) return unavailable_wait(w);
    zrate_window tmp = *w;
    expire(&tmp, now_ms);
    if (tmp.count < tmp.limit) return 0;
    uint64_t oldest = tmp.events[tmp.head];
    if (now_ms < oldest) return 0; /* clock skew: treat as available */
    uint64_t age = now_ms - oldest;
    if (age >= tmp.interval_ms) return 0;
    return tmp.interval_ms - age;
}
