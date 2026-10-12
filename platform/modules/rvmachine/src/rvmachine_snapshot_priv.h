/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: internal seams of the snapshot encoder: a bounded little-endian
 * writer and reader over a memory block, and the per-structure codecs. */
#ifndef ZCL_RVMACHINE_SNAPSHOT_PRIV_H
#define ZCL_RVMACHINE_SNAPSHOT_PRIV_H

#include "rvmachine_priv.h"
#include "rvmachine/rvmachine_snapshot.h"

/* The meta block (header fields and all small state) never exceeds this. */
#define SNAP_META_MAX (64u * 1024u)
#define SNAP_MAGIC "Z23SNAP"
#define SNAP_PREFIX 32u /* magic[8] version u32 flags u32 total u64 meta_len u64 */

enum snap_slot_kind { SNAP_SLOT_EMPTY = 0, SNAP_SLOT_BLOCK = 2, SNAP_SLOT_ENTROPY = 4 };

struct snap_wr {
    uint8_t *p;
    size_t cap, pos;
    bool bad;
};

struct snap_rd {
    const uint8_t *p;
    size_t n, pos;
    bool bad;
};

void snap_put8(struct snap_wr *w, uint8_t v);
void snap_put32(struct snap_wr *w, uint32_t v);
void snap_put64(struct snap_wr *w, uint64_t v);
void snap_putn(struct snap_wr *w, const void *src, size_t n);
uint8_t snap_get8(struct snap_rd *r);
uint32_t snap_get32(struct snap_rd *r);
uint64_t snap_get64(struct snap_rd *r);
bool snap_getb(struct snap_rd *r);
void snap_getn(struct snap_rd *r, void *dst, size_t n);

/* A section is a u32 tag, a u32 length and its payload. */
size_t snap_section_begin(struct snap_wr *w, uint32_t tag);
void snap_section_end(struct snap_wr *w, size_t mark);
bool snap_section_open(struct snap_rd *r, uint32_t tag, struct snap_rd *body);
bool snap_section_close(struct snap_rd *r, const struct snap_rd *body);

enum snap_tag {
    SNAP_TAG_MACHINE = 1, SNAP_TAG_HART, SNAP_TAG_PLIC, SNAP_TAG_TIMER,
    SNAP_TAG_UART, SNAP_TAG_SBI, SNAP_TAG_FWIN, SNAP_TAG_SERIN, SNAP_TAG_SLOTS
};

/* rvmachine_snapshot_state.c: each pair writes or reads one structure's
 * fields. A reader returns false on a malformed or inconsistent value. */
void snap_hart_put(struct snap_wr *w, const struct rvemu_hart *h);
bool snap_hart_get(struct snap_rd *r, struct rvemu_hart *h);
void snap_plic_put(struct snap_wr *w, const struct rvplat_plic *p);
bool snap_plic_get(struct snap_rd *r, struct rvplat_plic *p);
void snap_timer_put(struct snap_wr *w, const struct rvplat_timer *t);
bool snap_timer_get(struct snap_rd *r, struct rvplat_timer *t);
void snap_uart_put(struct snap_wr *w, const struct rvplat_uart *u);
bool snap_uart_get(struct snap_rd *r, struct rvplat_uart *u);
void snap_sbi_put(struct snap_wr *w, const struct rvplat_sbi *s);
bool snap_sbi_get(struct snap_rd *r, struct rvplat_sbi *s);
void snap_input_put(struct snap_wr *w, const struct rvmachine_input *q);
bool snap_input_get(struct snap_rd *r, struct rvmachine_input *q);
void snap_machine_put(struct snap_wr *w, const struct rvmachine *m);
bool snap_machine_get(struct snap_rd *r, struct rvmachine *m);

/* The device table: one row per virtio slot (kind, payload). */
enum snap_slot_kind snap_slot_kind_of(const struct rvmachine *m, unsigned slot);
void snap_slots_put(struct snap_wr *w, const struct rvmachine *m);
/* Verifies every row against the freshly configured machine, then loads it. */
enum rvmachine_snapshot_status snap_slots_get(struct snap_rd *r, struct rvmachine *m);

/* Whether the machine's state in RAM and fields is one a snapshot may hold. */
enum rvmachine_snapshot_status snap_machine_check(const struct rvmachine *m);

#endif
