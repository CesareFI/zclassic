/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: the built-in RISC-V machine. One RV64 IMAFDC hart in S and U modes
 * with Sv39, no firmware image (supervisor ecalls are answered by the host),
 * RAM, an interrupt controller, an ns16550 serial port, eight virtio mmio
 * slots (slot 0 a block device when a disk is given, slot 1 an entropy device
 * when an entropy source is given), a device tree and a kernel loader. Time
 * is retired instructions divided by ten; nothing reads a host clock or host
 * randomness, so a run is repeatable bit for bit. */
#ifndef ZCL_RVMACHINE_RVMACHINE_H
#define ZCL_RVMACHINE_RVMACHINE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "rvemu/rvemu.h"
#include "rvplat/plic.h"
#include "rvplat/sbi.h"
#include "rvplat/timer.h"
#include "rvplat/uart.h"
#include "rvvirtio/rvvirtio.h"

/* Machine contract v1: the memory map and the entry state. */
#define RVMACHINE_RAM_BASE UINT64_C(0x80000000)
#define RVMACHINE_RAM_DEFAULT (UINT64_C(1) << 30)
#define RVMACHINE_RAM_MIN (UINT64_C(64) << 20)
#define RVMACHINE_RAM_MAX (UINT64_C(64) << 30)
#define RVMACHINE_KERNEL_BASE UINT64_C(0x80200000)
/* An image may not end above this many bytes into RAM. */
#define RVMACHINE_IMAGE_LIMIT (UINT64_C(768) << 20)
/* The device tree sits this far below the end of RAM. The boot page tables of
 * the supported kernels identity-map only the first gigabyte of RAM, so for a
 * larger RAM the blob stays this far below RAM base + 1 GiB. */
#define RVMACHINE_DTB_BELOW_END (UINT64_C(2) << 20)
#define RVMACHINE_DTB_WINDOW (UINT64_C(1) << 30)
#define RVMACHINE_DTB_MAX 16384u

#define RVMACHINE_PLIC_BASE UINT64_C(0x0C000000)
#define RVMACHINE_PLIC_SIZE UINT64_C(0x600000)
#define RVMACHINE_PLIC_NDEV 31u
#define RVMACHINE_UART_BASE UINT64_C(0x10000000)
#define RVMACHINE_UART_SIZE UINT64_C(0x100)
#define RVMACHINE_UART_IRQ 10u
#define RVMACHINE_UART_CLOCK 3686400u
#define RVMACHINE_UART_SPEED 115200u
#define RVMACHINE_VIRTIO_BASE UINT64_C(0x10001000)
#define RVMACHINE_VIRTIO_STRIDE UINT64_C(0x1000)
#define RVMACHINE_VIRTIO_SLOTS 8u
#define RVMACHINE_VIRTIO_IRQ0 1u /* slot n raises source 1 + n */
#define RVMACHINE_VIRTIO_SLOT_DISK 0u
#define RVMACHINE_VIRTIO_SLOT_ENTROPY 1u
#define RVMACHINE_VIRTIO_SLOT_DISK1 3u
#define RVMACHINE_TIMEBASE_HZ 10000000u
#define RVMACHINE_TICKS_PER_TIME 10u /* retired instructions per time unit */
/* The machine model version recorded in snapshots: bump when interpreter or
 * device model behaviour changes. */
#define RVMACHINE_MODEL_VERSION 1u
#define RVMACHINE_SCOUNTEREN UINT64_C(7) /* entry scounteren: CY, TM, IR */

#define RVMACHINE_BOOTARGS_MAX 512u
#define RVMACHINE_INPUT_MAX 4096u
#define RVMACHINE_VIRTIO_SLOT_CONSOLE 2u
#define RVMACHINE_CONPORT_QUEUE 4096u
#define RVMACHINE_CONPORT_ROUND_BYTES 4096u
#define RVMACHINE_CONPORT_MAX RVVIRTIO_CONSOLE_PORTS_MAX
/* This many consecutive steps that trap without retiring an instruction end
 * the run as a fault (a trap handler that itself cannot be fetched). */
#define RVMACHINE_TRAP_STORM 1024u
/* Device data movement is work: disk data read or written and entropy
 * delivered, one unit per started 4096 bytes moved by each queue notification
 * or service round. */
#define RVMACHINE_DEVICE_WORK_BYTES 4096u
/* The timer deadline of a machine whose timer is not armed. */
#define RVMACHINE_NO_DEADLINE UINT64_MAX

/* Copy-on-write overlay of the disk: 4 KiB blocks, at most 256 MiB. An image
 * may be at most 1 TiB. */
#define RVMACHINE_DISK_BLOCK 4096u
#define RVMACHINE_DISK_OVERLAY_BLOCKS 65536u
#define RVMACHINE_DISK_BYTES_MAX (UINT64_C(1) << 40)

enum rvmachine_status {
    RVMACHINE_OK = 0,
    RVMACHINE_ERR_ARG,
    RVMACHINE_ERR_NOMEM,
    RVMACHINE_ERR_IMAGE,       /* not a loadable RV64 ELF and too short to be flat */
    RVMACHINE_ERR_IMAGE_RANGE, /* ends above the limit or overlaps the device tree */
    RVMACHINE_ERR_FDT,
    RVMACHINE_ERR_DISK,
    RVMACHINE_ERR_STATE,
    RVMACHINE_ERR_TIME_BACKWARDS,     /* rvmachine_advance_time: target before now */
    RVMACHINE_ERR_TIME_PAST_DEADLINE, /* rvmachine_advance_time: target after the armed timer */
    RVMACHINE_ERR_WAITING, /* wait_stops: the hart waits and nothing can wake it yet */
    RVMACHINE_ERR_ENTRY,       /* boot seed: the image has no loader entry to take it */
    RVMACHINE_ERR_SEED_ABSENT, /* boot seed: the source gave no bytes */
    RVMACHINE_ERR_SEED_SHORT,  /* boot seed: the source gave fewer than asked */
    RVMACHINE_ERR_SEED_SOURCE, /* boot seed: the source failed */
    RVMACHINE_ERR_PORT,        /* byte-port configuration or sink refused */
    RVMACHINE_ERR_ENTROPY      /* fail-closed entropy source refused */
};

/* Why rvmachine_run returned. */
enum rvmachine_stop {
    RVMACHINE_STOP_BUDGET = 0, /* the work budget ran out (see rvmachine_run) */
    RVMACHINE_STOP_SHUTDOWN,   /* the guest asked the firmware to power off */
    RVMACHINE_STOP_REBOOT,     /* the guest asked the firmware to reset */
    RVMACHINE_STOP_IDLE,       /* wfi and nothing that can wake the hart */
    RVMACHINE_STOP_FAULT,      /* the engine could not continue: pc, cause, tval */
    RVMACHINE_STOP_REQUESTED,  /* rvmachine_request_stop was called */
    RVMACHINE_STOP_WAIT        /* wait_stops only: wfi until timer_deadline, nothing pending */
};

struct rvmachine_result {
    enum rvmachine_stop stop;
    uint64_t retired;    /* instructions retired since the kernel was loaded */
    uint64_t skip;       /* time units added by wfi fast-forwards (saturating) */
    uint64_t fw_calls;   /* firmware calls answered (an ecall does not retire) */
    uint64_t device_work; /* device data moved, in RVMACHINE_DEVICE_WORK_BYTES units */
    uint64_t guest_time; /* the time CSR: retired / 10 + skip (saturating), RVMACHINE_TIMEBASE_HZ */
    uint64_t pc;
    uint64_t cause;      /* scause at the stop */
    uint64_t tval;       /* stval at the stop */
    unsigned engine_stop; /* enum rvemu_stop behind a FAULT; 0 for a trap storm */
    uint32_t reset_type;  /* SHUTDOWN / REBOOT: firmware reset type and reason */
    uint32_t reset_reason;
    /* What rvmachine_timer_deadline returns at the stop. Filled on every stop. */
    uint64_t timer_deadline;
    /* Instruction fetches since the kernel was loaded. A hit reused a decode
     * whose bits still matched guest memory and skipped translation. A miss
     * translated and decoded. Their sum is every completed fetch. */
    uint64_t fetch_hits;
    uint64_t fetch_misses;
};

/* The byte sink for everything the guest prints, from the firmware console
 * calls and from the serial port alike. */
typedef void (*rvmachine_console_fn)(void *ctx, uint8_t byte);

/* The source of the entropy device: writes up to n bytes into buf and returns
 * how many (0 = nothing now). It is the device's only source: the machine
 * reads no host randomness and no clock, so a run fed the same bytes repeats
 * exactly, and what the bytes are worth is the caller's business. It runs
 * inside a device access and must not call back into the machine. */
typedef size_t (*rvmachine_entropy_fn)(void *ctx, uint8_t *buf, size_t n);

/* The seed a kernel takes at its loader entry, before its first use of
 * randomness; exactly this many bytes (see rvmachine_load_kernel). */
#define RVMACHINE_BOOT_SEED_BYTES 2048u

/* The source of the boot seed, asked once, during rvmachine_load_kernel, for
 * n = RVMACHINE_BOOT_SEED_BYTES bytes. It writes at most n bytes into buf,
 * sets *got to how many and returns true, or returns false when it failed.
 * As with the entropy device, the machine has no other source and what the
 * bytes are worth is the caller's business. It must not call back into the
 * machine. */
typedef bool (*rvmachine_boot_seed_fn)(void *ctx, uint8_t *buf, size_t n, size_t *got);
/* Return only bytes accepted; the guest retains every unaccepted suffix. */
typedef size_t (*rvmachine_conport_fn)(void *ctx, unsigned port,
                                      const uint8_t *bytes, size_t n);

struct rvmachine_config {
    uint64_t ram_bytes;   /* 0 = RVMACHINE_RAM_DEFAULT; a multiple of 2 MiB */
    /* Required for secret-bearing launches. Clears RAM, machine state and
     * private disk overlays before normal destruction; may touch lazy pages.
     * Does not cover crashes, live host inspection or caller-owned buffers. */
    bool cleanse_on_destroy;
    const char *bootargs; /* chosen/bootargs; NULL = none */
    /* The block device's disk, from rvmachine_disk_open; NULL = no block
     * device. The machine owns it from a successful create and closes it on
     * destroy; after a failed create it is still the caller's. */
    struct rvmachine_disk *disk;
    /* An optional second block device at RVMACHINE_VIRTIO_SLOT_DISK1, with the
     * same ownership rules as disk; NULL = slot 3 answers as empty. */
    struct rvmachine_disk *data_disk;
    rvmachine_console_fn console;
    void *console_ctx;
    /* The entropy device's source; NULL = no entropy device, and slot 1 then
     * answers as empty like every other unused slot. */
    rvmachine_entropy_fn entropy;
    void *entropy_ctx;
    /* Opt-in all-or-nothing source: nonempty short/overfilled requests stop
     * execution before another instruction. Default preserves dry retry. */
    bool entropy_fail_closed;
    /* false (the default): a wfi with the timer armed and nothing pending
     * jumps guest time to the deadline. true: rvmachine_run returns
     * RVMACHINE_STOP_WAIT there instead and the caller moves time with
     * rvmachine_advance_time, so a host loop can sleep while the guest does. */
    bool wait_stops;
    /* The boot seed's source; NULL = none, and the kernel is entered the
     * firmware way exactly as without this field. With a source the kernel
     * is entered at its loader entry with the seed (rvmachine_load_kernel). */
    rvmachine_boot_seed_fn boot_seed;
    void *boot_seed_ctx;
    unsigned conport_count; /* 0: absent; otherwise 1..8 named byte ports */
    /* 0 disables private bootstrap. Otherwise index+1 names one dedicated
     * input-only fixed-32-byte keyfile port, requiring cleanse_on_destroy.
     * This grants no credential, enrollment, entropy or activation authority. */
    unsigned private_keyfile_port_plus_one;
    const char *conport_names[RVMACHINE_CONPORT_MAX];
    rvmachine_conport_fn conport_sink; /* required when ports are present */
    void *conport_ctx;
};

/* One reader's view of the console input: the most recent RVMACHINE_INPUT_MAX
 * unread bytes. */
struct rvmachine_input {
    uint8_t bytes[RVMACHINE_INPUT_MAX];
    size_t head;
    size_t count;
};

struct rvmachine_disk; /* read-only image file plus the in-memory overlay */

struct rvmachine_conport {
    uint8_t bytes[RVMACHINE_CONPORT_QUEUE];
    size_t head, count, tx_left;
    uint32_t generation, seen_generation;
    uint64_t discarded;
    bool stalled, writable, blocked, tx_more, retired;
    bool private_keyfile, private_sealed, private_failed;
};

/* Run-loop schedule. Derived: rebuilt on demand, never serialised. It lets
 * rvmachine_run skip work that cannot have changed since the previous
 * instruction: a device service round is owed after a bus access outside RAM
 * and while a device still has work pending, and guest time changes only
 * when the retired count crosses a time unit. rvmachine_invalidate_derived
 * resets it. */
struct rvmachine_sched {
    uint64_t io_events;  /* bus accesses outside RAM so far (wraps) */
    uint64_t io_seen;    /* io_events when the last service round was decided */
    uint64_t sync_at;    /* retired count at which guest time is next brought up to date */
    bool service_owed;   /* a device still had work after the last round */
};

struct rvmachine;
/* Binds one block device's callbacks to its machine and disk slot. */
struct rvmachine_blkctx {
    struct rvmachine *m;
    bool data; /* false: the first disk, true: the data disk */
};

struct rvmachine {
    struct rvemu_hart hart;
    struct rvemu_mem mem;
    struct rvplat_plic plic;
    struct rvplat_timer timer;
    struct rvplat_sbi sbi;
    struct rvplat_uart uart;
    struct rvvirtio_blk blk;
    struct rvmachine_disk *disk; /* NULL when no disk is attached */
    struct rvvirtio_blk blk1;    /* live only when data_disk is not NULL */
    struct rvmachine_disk *data_disk;
    struct rvmachine_blkctx blkctx[2];
    struct rvvirtio_rng rng;      /* live only when entropy is not NULL */
    rvmachine_entropy_fn entropy;
    void *entropy_ctx;
    bool entropy_dry; /* the source returned 0; waiting for rvmachine_entropy_ready */
    bool entropy_fail_closed;
    bool entropy_fault;
    bool wait_stops;  /* config: stop at a timed wfi instead of jumping time */
    bool wait_latched; /* the hart waits and nothing has become able to wake it */
    struct rvvirtio_console con;
    struct rvmachine_conport conports[RVMACHINE_CONPORT_MAX];
    unsigned conport_count;
    char conport_names[RVMACHINE_CONPORT_MAX][RVVIRTIO_CONSOLE_NAME_MAX];
    rvmachine_conport_fn conport_sink;
    void *conport_ctx;
    bool conport_fault;
    bool cleanse_on_destroy;

    uint64_t ram_bytes;
    uint64_t dtb_addr;
    size_t dtb_len;
    uint64_t image_end; /* first address above the loaded kernel */
    uint64_t entry_pc, entry_a0, entry_a1; /* the entry state the load chose */
    rvmachine_boot_seed_fn boot_seed;
    void *boot_seed_ctx;
    uint64_t seed_addr; /* where the boot seed was written; 0 = no seed */
    /* The fetched seed on its way into guest memory; zero outside a load. */
    uint8_t seed_scratch[RVMACHINE_BOOT_SEED_BYTES];
    char bootargs[RVMACHINE_BOOTARGS_MAX];
    bool loaded;

    /* Time = retired instructions / 10 + time_skip. time_skip is the sum of
     * the wfi fast-forwards, in time units. */
    uint64_t time_skip;
    uint64_t fw_calls; /* firmware calls answered since the kernel was loaded */
    uint64_t device_work;  /* settled device work units since the kernel was loaded */
    uint64_t device_moved; /* backend bytes not yet settled into device_work */
    uint64_t work_limit;   /* the running call ends when the work reaches this */
    bool timer_raised;       /* the supervisor timer interrupt is up */
    bool wfi_stalled;        /* the last wfi stop found nothing to wait for */
    uint64_t wfi_instret;    /* retired count at that stop */
    uint64_t storm_instret;  /* retired count when a step last retired */
    uint32_t storm_steps;    /* consecutive steps that retired nothing */

    rvmachine_console_fn console;
    void *console_ctx;
    struct rvmachine_input firmware_in; /* read by the firmware getchar call */
    struct rvmachine_input serial_in;   /* read by the serial receive path */

    bool stop_requested;
    bool halted; /* a SHUTDOWN or REBOOT was accepted; cleared by a load */
    enum rvmachine_stop halt_stop;
    uint32_t reset_type;
    uint32_t reset_reason;

    /* Optional ring of the most recent pcs, for a fault report. */
    uint64_t *trace;
    size_t trace_cap;
    uint64_t trace_count;

    struct rvmachine_sched sched; /* derived: see rvmachine_invalidate_derived */
};

/* Checks only RAM default/bounds/alignment and boot argument length. No
 * allocation, callback, disk, image, launch or execution acceptance occurs.
 * Other machine configuration and environment checks remain at creation. */
enum rvmachine_status rvmachine_config_resources_validate(
    const struct rvmachine_config *config);

/* Allocates the machine and its RAM, attaches the disk when one is given and
 * writes the device tree into RAM. *out is NULL on any failure. */
enum rvmachine_status rvmachine_create(struct rvmachine **out,
                                       const struct rvmachine_config *config);
void rvmachine_destroy(struct rvmachine *m);

/* Loads a kernel image and puts the hart at the entry state: S-mode, satp 0,
 * interrupts off, a0 = 0, a1 = device tree address, pc = RVMACHINE_KERNEL_BASE,
 * scounteren = RVMACHINE_SCOUNTEREN.
 * An ELF64 RISC-V image has its PT_LOAD segments placed at p_paddr when every
 * one lies in RAM with the lowest at RVMACHINE_KERNEL_BASE, otherwise at
 * RVMACHINE_KERNEL_BASE + (p_vaddr - lowest p_vaddr); memsz above filesz is
 * zeroed. Anything else is a flat binary placed at RVMACHINE_KERNEL_BASE.
 * Refuses an image that ends above RVMACHINE_IMAGE_LIMIT into RAM or reaches
 * the device tree. The image bytes are only read. A machine takes one kernel:
 * once a load has succeeded, another returns RVMACHINE_ERR_STATE and changes
 * nothing (a reload would not be a fresh machine).
 *
 * With a boot seed source in the config the kernel is entered the way the
 * FreeBSD boot loader enters it, because that is the one entry at which such
 * a kernel takes a seed before its first use of randomness; a seed offered
 * through the firmware entry or the device tree is read by nobody. The image
 * must be an ELF. The hart starts at the physical address of e_entry, which
 * must lie in the file bytes of an executable segment, with a0 = the kernel
 * virtual address of a metadata list and a1 = 0. Above the image end, each
 * on a page boundary, the machine writes a copy of the device tree, the seed
 * (RVMACHINE_BOOT_SEED_BYTES bytes from the source) and the list: a module
 * "kernel" of type "elf kernel" with its address, size, device tree, end of
 * everything, verbose boot flag and boot hart 0, and a module "entropy" of
 * type "boot_entropy_platform" with the seed's address and size. Every
 * address in the list is a kernel virtual address, taken from the image's
 * own segment headers: p_vaddr of the lowest segment stands for
 * RVMACHINE_KERNEL_BASE. Refused by name, before anything is written to
 * guest memory and with the fetched bytes wiped from host memory:
 *   RVMACHINE_ERR_ENTRY        a flat image; e_entry outside the file bytes
 *                              of an executable segment, or loaded at an
 *                              odd address (no instruction starts there);
 *                              segments that do not share one virtual
 *                              offset;
 *   RVMACHINE_ERR_IMAGE_RANGE  the tree copy, seed and list do not fit in
 *                              RAM below the limits above, or within the
 *                              gigabyte from RVMACHINE_KERNEL_BASE that such
 *                              a kernel maps while it boots;
 *   RVMACHINE_ERR_SEED_ABSENT  the source gave no bytes;
 *   RVMACHINE_ERR_SEED_SHORT   it gave fewer than asked;
 *   RVMACHINE_ERR_SEED_SOURCE  it failed, claimed more than asked, or left
 *                              the whole buffer zero (bytes claimed and
 *                              none written; a buffer written in part
 *                              is not detected). */
enum rvmachine_status rvmachine_load_kernel(struct rvmachine *m,
                                            const uint8_t *image, size_t len);

/* Public exporters must refuse false. No private machine belongs to a public
 * console/byte fixture or snapshot. This is not a protection against its host. */
bool rvmachine_public_export_allowed(const struct rvmachine *m);
/* One attempt only, including refusal. Exactly 32 bytes, matching current
 * generation and a host-opened, guest-opened empty private port. The caller owns/cleanses
 * its span; queue copies cleanse on consumption/discard/close/reset.
 * Never rearms after close/reset/reopen. Guest TX never reaches public sink.
 * Admitted private refusal clears its queue and latches machine ERR_PORT.
 * Absent/invalid/retired/reentrant machine/index entries and ordinary-port
 * targets refuse without mutation and are not admitted private attempts. */
bool rvmachine_keyfile_deliver(struct rvmachine *m, unsigned port,
    uint32_t generation, const uint8_t *bytes, size_t n);

/* True when a boot seed was written and the guest has since overwritten all
 * of it with zeros, which is what a kernel does once it has consumed it. */
bool rvmachine_boot_seed_cleared(const struct rvmachine *m);

/* The device tree blob as placed in RAM. The machine only writes a tree: the
 * one tree its reader ever checks is the one it has just built, never one
 * supplied by a guest or read from a file. */
const uint8_t *rvmachine_dtb(const struct rvmachine *m, size_t *len);

/* Builds the contract-v1 device tree into buf (RVMACHINE_DTB_MAX is enough).
 * Every virtio slot is described whether or not a disk is attached. */
enum rvmachine_status rvmachine_build_dtb(uint64_t ram_bytes, const char *bootargs,
                                          uint8_t *buf, size_t cap, size_t *len);

/* Queues console input for the guest. Every byte is offered to both readers,
 * the firmware getchar call and the serial receive path (with its interrupt),
 * so a guest gets its input on whichever one it uses and a driver that drains
 * the other cannot take it away. A reader that falls RVMACHINE_INPUT_MAX bytes
 * behind loses its oldest bytes. Returns n. */
size_t rvmachine_console_input(struct rvmachine *m, const uint8_t *bytes, size_t n);

/* All operations are bounded and nonblocking. Input queues only the accepted
 * prefix; the embedder retains the suffix. No callback may reenter these APIs. */
size_t rvmachine_conport_input(struct rvmachine *m, unsigned port,
                              const uint8_t *bytes, size_t n);
void rvmachine_conport_resume(struct rvmachine *m, unsigned port);
size_t rvmachine_conport_discard(struct rvmachine *m, unsigned port);
bool rvmachine_conport_close(struct rvmachine *m, unsigned port);
bool rvmachine_conport_open(struct rvmachine *m, unsigned port);
bool rvmachine_conport_guest_open(const struct rvmachine *m, unsigned port);
size_t rvmachine_conport_queued(const struct rvmachine *m, unsigned port);
uint32_t rvmachine_conport_generation(const struct rvmachine *m, unsigned port);
unsigned rvmachine_conport_pending(const struct rvmachine *m, unsigned port);
/* Driver-consumed receive bytes, never a claim that the guest application read. */
size_t rvmachine_conport_consumed(struct rvmachine *m, unsigned port);

/* Tells the machine that its entropy source has bytes again. A source that
 * returns 0 leaves the guest's request waiting and is not asked again until
 * the guest notifies the device or this is called; the waiting requests are
 * then served before the next instruction. No effect without the device or
 * when the source has not come up empty. */
void rvmachine_entropy_ready(struct rvmachine *m);

/* Drops everything the machine derives from its state and can rebuild: the
 * run-loop schedule and, through the engine, the translation cache. Call it
 * after the state of a machine was rewritten from outside (a restore). */
void rvmachine_invalidate_derived(struct rvmachine *m);

/* Makes the running rvmachine_run return RVMACHINE_STOP_REQUESTED at the next
 * instruction boundary. Safe to call from the console sink. */
void rvmachine_request_stop(struct rvmachine *m);

/* Records the pc of every executed step into ring (cap entries, the newest at
 * (trace_count - 1) % cap). ring NULL or cap 0 turns tracing off. */
void rvmachine_set_trace(struct rvmachine *m, uint64_t *ring, size_t cap);

/* Runs until max_work more units of work are done, or until another stop
 * reason arrives first. Work is everything the host does for the guest:
 *     work = retired instructions + answered firmware calls + device work
 * where device work is the disk data moved and the entropy delivered, one unit
 * per started RVMACHINE_DEVICE_WORK_BYTES moved by each queue notification or
 * service round. A guest can therefore neither spin through firmware calls
 * nor make the host copy device data for free. The budget is looked at
 * between instruction steps and between service rounds, so a run passes it by
 * at most one step and one capped round of each device.
 * Returns RVMACHINE_ERR_STATE before a kernel is loaded or after a shutdown,
 * and RVMACHINE_ERR_WAITING while a waiting hart cannot be woken yet
 * (see wait_stops below);
 * otherwise RVMACHINE_OK with *result filled. */
enum rvmachine_status rvmachine_run(struct rvmachine *m, uint64_t max_work,
                                    struct rvmachine_result *result);

/* ---- letting the host sleep while the guest does (config wait_stops) ----
 *
 * By default a guest that waits for its timer costs no host time: the machine
 * jumps guest time to the deadline. With wait_stops the machine does not jump.
 * When the hart waits in wfi, the timer is armed for a later time and nothing
 * the machine can serve is pending, rvmachine_run returns RVMACHINE_STOP_WAIT
 * with the deadline in result->timer_deadline. That stop does no work. The
 * caller then decides how guest time passes: it calls rvmachine_advance_time
 * (to the deadline, or to an earlier time if something else woke it), queues
 * console input or signals entropy, and runs again.
 *
 * A waiting hart is run again only when something can move. After a wait
 * stop, and with wait_stops after an idle stop too, rvmachine_run is refused
 * with RVMACHINE_ERR_WAITING, doing no work and leaving the result alone,
 * until a call by the caller makes the hart able to wake or gives a device
 * work: time advanced to a timer whose interrupt is enabled, console input
 * that raises an enabled interrupt, or a dry entropy source reported ready
 * with a request waiting. What counts is the wfi rule itself, an interrupt
 * both pending in mip and enabled in mie; that something merely arrived does
 * not. None of these lifts the refusal, however often it is repeated:
 *   - console input while the hart has the external interrupt masked (mie);
 *   - console input while the serial port's receive interrupt is off;
 *   - console input while the interrupt controller holds the port's
 *     interrupt back: source disabled or without priority for the context,
 *     at or under the context threshold, or claimed and not yet completed;
 *   - console input a guest could only read with a firmware getchar call;
 *   - time advanced short of the deadline, or to a deadline whose timer
 *     interrupt is masked;
 *   - an entropy signal with no request waiting or no source that was dry.
 * A guest cannot produce wait stops for free either: a timer armed at or
 * before the present is not a wait (a due timer ends the wfi: the hart takes
 * the interrupt, or goes on if it has interrupts off, or idles if it has the
 * timer interrupt masked), and to arm a new deadline it must make a firmware
 * call, which is a unit of work.
 *
 * A run driven this way, with time advanced exactly to each returned
 * deadline, retires the same instructions, reports the same skip and guest
 * time and prints the same console as the default mode on the same inputs.
 * Every target time given to rvmachine_advance_time is an input of the run:
 * recorded and replayed, it reproduces the run. */

/* Moves guest time forward to guest_time (the absolute time CSR value, in
 * units of 1 / RVMACHINE_TIMEBASE_HZ); the difference is added to skip.
 * Works in either mode and whether or not the hart is waiting. Refused, with
 * nothing changed:
 *   RVMACHINE_ERR_TIME_BACKWARDS      guest_time is before the present;
 *   RVMACHINE_ERR_TIME_PAST_DEADLINE  guest_time is after
 *                                     rvmachine_timer_deadline (a timer that
 *                                     is due and can wake the hart allows no
 *                                     advance at all);
 *   RVMACHINE_ERR_STATE               no kernel loaded, or after a shutdown.
 * The present time is accepted and does nothing. With no deadline any later
 * time is accepted. */
enum rvmachine_status rvmachine_advance_time(struct rvmachine *m, uint64_t guest_time);

/* The guest time a caller may wait for and advance to: that of the armed
 * timer, or RVMACHINE_NO_DEADLINE. A deadline at or before rvmachine_time is
 * due, and is reported only while the timer interrupt is enabled in mie, so
 * that the hart wakes on it. A timer that has passed with its interrupt
 * masked is not a deadline: nothing is left to wait for, and a caller
 * sleeping until the deadline does not wake for it again and again. A hart
 * that reaches wfi with such a timer gets the idle stop. A hart that was
 * already waiting when a masked deadline passed (the caller advanced time to
 * it after a wait stop) stays refused with RVMACHINE_ERR_WAITING. For a
 * waiting hart, no deadline and no runnable flag mean: asleep until input. */
uint64_t rvmachine_timer_deadline(const struct rvmachine *m);

/* What is queued for the guest right now, as a set of the flags below.
 *   CONSOLE       input for the serial port that ends a wfi now: bytes queued
 *                 or in its receive buffer, the port's receive interrupt on,
 *                 and the hart with an external interrupt pending and enabled
 *                 (mip and mie; the global enable plays no part, as for wfi).
 *   ENTROPY       an entropy request is waiting, the source has not said it
 *                 is empty and the driver runs the queue.
 *   BLOCK         block requests left over from a capped notify or round,
 *                 and the driver runs the queue.
 *   CONSOLE_HELD  input for the serial port that cannot wake the hart as
 *                 things stand: the port's receive interrupt is off, or the
 *                 interrupt is masked at the interrupt controller or in the
 *                 hart. A guest that polls the port still reads it.
 * The first three are RVMACHINE_PENDING_RUNNABLE: a run made while one of
 * them is set acts on it (it does work, or finds the entropy source empty
 * and drops the flag). None of them is set when rvmachine_run returns a
 * wait stop or an idle stop, and none appears afterwards until the caller
 * does something that can change that, so a loop may run again while
 * (rvmachine_pending(m) & RVMACHINE_PENDING_RUNNABLE) != 0 and sleep
 * otherwise. CONSOLE_HELD is for telling only; it is no reason to run.
 * Bytes waiting for a firmware getchar call are not reported: every input
 * byte is offered to that call too, only the guest's own asking takes it,
 * and a guest that reads the serial port never asks. */
#define RVMACHINE_PENDING_CONSOLE 0x1u
#define RVMACHINE_PENDING_ENTROPY 0x2u
#define RVMACHINE_PENDING_BLOCK 0x4u
#define RVMACHINE_PENDING_CONSOLE_HELD 0x8u
#define RVMACHINE_PENDING_PORT 0x10u
#define RVMACHINE_PENDING_PORT_HELD 0x20u
#define RVMACHINE_PENDING_PORT_BLOCKED 0x40u
#define RVMACHINE_PENDING_RUNNABLE \
    (RVMACHINE_PENDING_CONSOLE | RVMACHINE_PENDING_ENTROPY | RVMACHINE_PENDING_BLOCK | \
     RVMACHINE_PENDING_PORT)
unsigned rvmachine_pending(const struct rvmachine *m);

/* Instructions retired since the kernel was loaded, and the guest time. */
uint64_t rvmachine_retired(const struct rvmachine *m);
uint64_t rvmachine_time(const struct rvmachine *m);

const char *rvmachine_stop_name(enum rvmachine_stop stop);
const char *rvmachine_status_name(enum rvmachine_status status);

/* ---- disk: a read-only image with a copy-on-write overlay ---- */

/* Reads exactly n bytes of the image at byte offset off into buf; false on
 * any failure. The range is always inside the size given at open. */
typedef bool (*rvmachine_disk_read_fn)(void *ctx, uint64_t off, void *buf, size_t n);
typedef bool (*rvmachine_disk_write_fn)(void *ctx, uint64_t off, const void *buf, size_t n);
typedef bool (*rvmachine_disk_flush_fn)(void *ctx);

/* A disk over size bytes of image reached through read. The image is never
 * written, this module has no way to: guest writes land in an in-memory
 * overlay of RVMACHINE_DISK_BLOCK blocks, and once
 * RVMACHINE_DISK_OVERLAY_BLOCKS are in use a write to a new block fails, which
 * the guest sees as an I/O error. read and ctx must stay valid until the disk
 * is closed. A size of zero or above RVMACHINE_DISK_BYTES_MAX is refused. */
enum rvmachine_status rvmachine_disk_open(struct rvmachine_disk **out, uint64_t size,
                                          rvmachine_disk_read_fn read, void *ctx);
/* Explicit retained backend: reads and writes reach the caller directly,
 * without a private overlay. All three callbacks are required, bounded and
 * nonblocking; false reports failure to the guest. flush must report its
 * real durability result. The caller owns ctx and its storage, keeps them
 * valid until close, and quiesces machine execution before closing. Close
 * neither flushes nor releases ctx. This API grants no encryption guarantee. */
enum rvmachine_status rvmachine_disk_open_backend(struct rvmachine_disk **out,
    uint64_t size, rvmachine_disk_read_fn read, rvmachine_disk_write_fn write,
    rvmachine_disk_flush_fn flush, void *ctx);
void rvmachine_disk_close(struct rvmachine_disk *disk);
uint64_t rvmachine_disk_size(const struct rvmachine_disk *disk);
bool rvmachine_disk_read(struct rvmachine_disk *disk, uint64_t off, void *buf,
                         size_t n);
bool rvmachine_disk_write(struct rvmachine_disk *disk, uint64_t off,
                          const void *buf, size_t n);
/* The default private RAM overlay needs no durability operation. */
bool rvmachine_disk_flush(struct rvmachine_disk *disk);
/* Overlay blocks in use. */
uint32_t rvmachine_disk_overlay_blocks(const struct rvmachine_disk *disk);

/* ---- console script: typed input on a marker, and a stop marker ---- */

#define RVMACHINE_SCRIPT_STEPS 32u
#define RVMACHINE_SCRIPT_MARKER_MAX 255u
#define RVMACHINE_SCRIPT_TEXT_MAX 511u
#define RVMACHINE_SCRIPT_TAIL 512u

struct rvmachine_script_step {
    char marker[RVMACHINE_SCRIPT_MARKER_MAX + 1u];
    size_t marker_len;
    char text[RVMACHINE_SCRIPT_TEXT_MAX + 1u];
    size_t text_len;
};

/* Steps fire in order, each once, when the console output ends with the
 * step's marker; its text is then queued as console input and matching starts
 * afresh. The stop marker is armed only after the last step has fired, and
 * seeing it requests a stop. Matching happens at the instruction boundary the
 * byte was printed at, so a scripted run is as repeatable as an unscripted
 * one. */
struct rvmachine_script {
    struct rvmachine_script_step steps[RVMACHINE_SCRIPT_STEPS];
    unsigned count;
    unsigned fired;
    char until[RVMACHINE_SCRIPT_MARKER_MAX + 1u];
    size_t until_len;
    bool until_seen;
    char tail[RVMACHINE_SCRIPT_TAIL];
    size_t tail_len;
    uint64_t console_bytes; /* every byte fed to rvmachine_script_console */
};

void rvmachine_script_init(struct rvmachine_script *script);
/* Appends a step. False when the table is full, the marker is empty or either
 * text is too long; the text may be empty (a marker that must be seen). */
bool rvmachine_script_add(struct rvmachine_script *script, const char *marker,
                          size_t marker_len, const char *text, size_t text_len);
/* Sets the stop marker. False when it is empty or too long. */
bool rvmachine_script_until(struct rvmachine_script *script, const char *marker,
                            size_t marker_len);
/* Feed every console byte here, from the console sink of machine m. */
void rvmachine_script_console(struct rvmachine_script *script, struct rvmachine *m,
                              uint8_t byte);
/* True when every step has fired and the stop marker, when one is set, was
 * seen. */
bool rvmachine_script_met(const struct rvmachine_script *script);

#endif
