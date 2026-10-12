/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: internal seams between the rvmachine translation units. */
#ifndef ZCL_RVMACHINE_PRIV_H
#define ZCL_RVMACHINE_PRIV_H

#include "rvmachine/rvmachine.h"

/* The disk: a read-only image (or a retained backend when write is set) with a
 * copy-on-write overlay. Shared with the snapshot encoder. */
struct rvmachine_disk {
    rvmachine_disk_read_fn read;
    rvmachine_disk_write_fn write;
    rvmachine_disk_flush_fn flush;
    void *ctx;
    uint64_t size;    /* bytes */
    uint64_t nblocks; /* size rounded up to whole blocks */
    uint32_t *slot;   /* per block: 0 = read the image, else overlay index + 1 */
    uint8_t **overlay;
    uint32_t used;
};

/* Clear written private overlay blocks without modifying the source image. */
void rvmachine_disk_cleanse(struct rvmachine_disk *disk);

/* rvmachine_run.c: reset the hart to the contract entry state and hook the
 * device callbacks into the engine's memory. */
void rvmachine_enter(struct rvmachine *m);

/* rvmachine_preload.c: the loader entry that carries a boot seed. The plan
 * holds guest physical addresses, each on a page boundary above the image. */
struct rvmachine_preload {
    uint64_t dtb, seed, list, end; /* tree copy, seed, metadata list, end of all */
    uint64_t va_base;              /* kernel virtual address of RVMACHINE_KERNEL_BASE */
    uint64_t image_end;
};
/* Lays the three out above image_end; `ceiling` is the first address the
 * image may not reach. RVMACHINE_ERR_IMAGE_RANGE when they do not fit. */
enum rvmachine_status rvmachine_preload_plan(const struct rvmachine *m, uint64_t image_end,
                                             uint64_t va_base, uint64_t ceiling,
                                             struct rvmachine_preload *plan);
/* Asks the source for the seed, into m->seed_scratch; wiped on any refusal. */
enum rvmachine_status rvmachine_preload_seed(struct rvmachine *m);
/* Writes the plan and the fetched seed into guest memory, wipes the host
 * copy and sets the entry registers. Cannot fail. */
void rvmachine_preload_write(struct rvmachine *m, const struct rvmachine_preload *plan,
                             uint64_t entry_pc);

/* rvmachine_dev.c: device dispatch for every physical access outside RAM.
 * Non-zero means access fault. */
int rvmachine_io_load(void *ctx, uint64_t paddr, unsigned nbytes, uint64_t *out);
int rvmachine_io_store(void *ctx, uint64_t paddr, unsigned nbytes, uint64_t val);
/* Wire the PLIC, the serial port, the block device (with a disk) and the
 * entropy device (with a source) into the machine. */
bool rvmachine_devices_init(struct rvmachine *m);
bool rvmachine_conport_configure(struct rvmachine *m,
                                const struct rvmachine_config *config);
/* Recompute the serial source and the supervisor external interrupt line. */
void rvmachine_irq_sync(struct rvmachine *m);

/* Whether a wfi ends now on one of the interrupts in `lines` (mip bits):
 * pending and enabled in mie. */
bool rvmachine_hart_wakes(const struct rvmachine *m, uint64_t lines);
/* Lifts the refusal a wait or idle stop left behind once something can move:
 * an interrupt that wakes the hart, or device work. Called after everything a
 * caller does to a stopped machine. */
void rvmachine_wake_check(struct rvmachine *m);
/* One capped round of each device with requests left; what it moved is charged. */
void rvmachine_devices_service(struct rvmachine *m);
/* True while a capped notify or round left requests the machine can serve. */
bool rvmachine_devices_pending(const struct rvmachine *m);

/* rvmachine.c: console sink and the shared input queue. */
void rvmachine_console_put(struct rvmachine *m, uint8_t byte);
/* The firmware console getchar callback (ctx is the machine). */
int rvmachine_sbi_getchar(void *ctx);
/* Move serial input into the receive FIFO while it has room. When polled is
 * false this happens only if the receive interrupt is enabled; a polled read
 * of the port always pulls. */
void rvmachine_input_pump(struct rvmachine *m, bool polled);

/* The clock: the engine's host-only count of retired instructions, which the
 * guest cannot write. time = retired / 10 + the wfi fast-forwards. */
static inline uint64_t machine_retired(const struct rvmachine *m)
{
    return m->hart.retired;
}


/* Guest time never wraps: a guest that sleeps to a deadline near the top of
 * the range and keeps running sees the clock stay at the top. */
static inline uint64_t machine_time_add(uint64_t a, uint64_t b)
{
    return b > UINT64_MAX - a ? UINT64_MAX : a + b;
}

static inline uint64_t machine_now(const struct rvmachine *m)
{
    return machine_time_add(machine_retired(m) / RVMACHINE_TICKS_PER_TIME, m->time_skip);
}

/* Makes the next instruction boundary do every piece of scheduled work
 * (struct rvmachine_sched). */
static inline void machine_sched_reset(struct rvmachine *m)
{
    m->sched.service_owed = true;
    m->sched.sync_at = 0;
}

#endif
