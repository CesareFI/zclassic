/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: Define serialized HUD generation ownership and checked mapping-wide write-xor-execute publication. */
#ifndef SKY_PART_LOAD_H
#define SKY_PART_LOAD_H
#ifndef SKY_PART_HUD_HEADER
#define SKY_PART_HUD_HEADER "macho_hud.h"
#endif
#include SKY_PART_HUD_HEADER
#include <stdbool.h>
#include <stddef.h>
/* Initialize with {0}; one receiver-authorized render-thread owner, outside
 * signal handlers. Never copy/mutate the host or use it concurrently.
 *
 * load copies stable readable bytes and the raw SHA256 digest into private
 * storage, applies the shared strict Mach-O policy, and completes a numeric
 * relocation plan before reserving memory. It never calls candidate code.
 * An arm64 Mac backend reserves one two-slot arena with no permissions.
 * It replans at the checked actual inactive-slot address, changes the whole
 * slot to RW/non-X, writes the generation, then checks RW->RX and flushes the
 * instruction cache before publishing {id,part}. It never requests RWX,
 * MAP_JIT, a writable executable alias or per-thread protection toggles.
 * Unsupported reservation/protection policy refuses; no fallback exists.
 * Native macOS support requires separate qualification on the intended host.
 *
 * Only successful publication increments ids, starting at 1, without wrap.
 * Refusal preserves current/id. A failed existing-slot RX transition may
 * leave only the inactive slot RW/non-X; the current slot remains RX.
 * Failed cleanup retains arena/state and sets failed: loads and borrows
 * refuse until successful disposal. Other platforms refuse without mapping.
 *
 * call_begin pins one current generation. Call its build function only
 * within that borrow and always call_end, then validate the complete recipe
 * independently. Borrowed pointers must not escape or be cached. A borrow
 * blocks load and disposal; neither load nor disposal invokes the candidate.
 *
 * dispose unmaps the complete arena and clears state on success. On failure
 * it retains the mapping/current/id, marks failed, and requires the owner to
 * stop using this host and resolve disposal. Reinitialization after successful
 * disposal starts a new lifecycle. Native execution is a separate receiver
 * authorization: format checks and W^X do not prove code safety or isolation.
 * Limits/profile are in macho_contract.md and shared with macho_admit.h.
 * SKY_PART_HUD_HEADER may name a receiver-owned, layout-compatible ABI header.
 */
enum sky_load_verdict {SKY_LOAD_OK,SKY_LOAD_ARGUMENT,SKY_LOAD_ADMISSION,SKY_LOAD_PLATFORM,SKY_LOAD_MEMORY,SKY_LOAD_LAYOUT,SKY_LOAD_RELOCATION,SKY_LOAD_DESCRIPTOR,SKY_LOAD_BUSY,SKY_LOAD_ID_EXHAUSTED};
struct sky_part_generation {uint64_t id;const struct sky_hud_part_v1 *part;};
struct sky_part_host {struct sky_part_generation current;void *arena;uint64_t last_id;unsigned slot;bool in_call,failed;};
enum sky_load_verdict sky_part_load(struct sky_part_host *,const void *,size_t,const uint8_t digest[32]);
const struct sky_part_generation *sky_part_call_begin(struct sky_part_host *);
bool sky_part_call_end(struct sky_part_host *);
bool sky_part_host_dispose(struct sky_part_host *);
#endif
