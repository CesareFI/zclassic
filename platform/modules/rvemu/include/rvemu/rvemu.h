/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: RV64IMAFDC hart core (base integer, M multiply/divide, A atomics, C
 * compressed, F and D floating point with fcsr) with M, S and U privilege modes:
 * Zicsr, the machine and supervisor CSRs, real traps, delegation and interrupts.
 * Caller-owned state and memory; no allocation, no I/O, no globals. Every guest
 * access is bounds-checked. Three profiles: STOP (user runner), MACHINE, and SBI
 * (supervisor guest with the firmware in the host). The MACHINE and SBI profiles
 * translate S and U addresses with Sv39 (satp MODE 8; hardware A and D update;
 * no ASIDs). PMP state is held but NOT enforced: every physical access passes. */
#ifndef ZCL_RVEMU_RVEMU_H
#define ZCL_RVEMU_RVEMU_H

#include <stddef.h>
#include <stdint.h>

/* Why a step did not retire an instruction. RVEMU_STOP_NONE means it did.
 * ECALL, EBREAK and the faults leave pc at the stopping instruction. */
enum rvemu_stop {
    RVEMU_STOP_NONE = 0,
    RVEMU_STOP_ECALL,
    RVEMU_STOP_EBREAK,
    RVEMU_STOP_ILLEGAL,
    RVEMU_STOP_MISALIGNED,
    RVEMU_STOP_OUT_OF_RANGE,
    RVEMU_STOP_STEP_LIMIT,
    RVEMU_STOP_WFI /* MACHINE and SBI profiles: idle after wfi, nothing pending */
};

/* Execution profile, chosen at hart init. STOP is the user-runner profile:
 * ecall, ebreak and every fault return an rvemu_stop to the caller, pc stays
 * on the stopping instruction, privilege is fixed at M, mret is a plain jump
 * to mepc and no interrupt is ever taken. MACHINE is the architectural
 * profile: exceptions and interrupts trap through medeleg/mideleg and the
 * mtvec/stvec vectors, and mret, sret, wfi and sfence.vma follow the
 * privileged spec.
 *
 * SBI is the firmware-in-host profile: the guest is a supervisor (plus its
 * user programs) and there is no guest M-mode. The hart starts in S and never
 * enters M. An ecall executed in S returns RVEMU_STOP_ECALL to the caller
 * without trapping, without advancing pc and without counting the step: the
 * host answers the call and resumes with rvemu_ecall_return. An ecall in U
 * traps to S (cause 8) through stvec. Every other synchronous exception and
 * the supervisor interrupts SSIP, STIP and SEIP are taken in S as if fully
 * delegated; the machine-level lines are never taken. mcounteren reads as all
 * ones (time, cycle and instret are readable in S; U is gated by scounteren),
 * a machine-level CSR access is an illegal instruction delivered to S, and
 * mret is illegal. The host drives SSIP, STIP and SEIP with rvemu_set_irq and
 * sets hart->time. */
enum rvemu_profile {
    RVEMU_PROFILE_STOP = 0,
    RVEMU_PROFILE_MACHINE = 1,
    RVEMU_PROFILE_SBI = 2
};

/* Privilege modes (the encodings of mstatus.MPP). */
enum rvemu_priv { RVEMU_PRIV_U = 0, RVEMU_PRIV_S = 1, RVEMU_PRIV_M = 3 };

/* Interrupt cause numbers for rvemu_set_irq (bit positions in mip). */
enum rvemu_irq {
    RVEMU_IRQ_SSIP = 1,
    RVEMU_IRQ_MSIP = 3,
    RVEMU_IRQ_STIP = 5,
    RVEMU_IRQ_MTIP = 7,
    RVEMU_IRQ_SEIP = 9,
    RVEMU_IRQ_MEIP = 11
};

#define RVEMU_PMP_ENTRIES 16u
#define RVEMU_TLB_ENTRIES 256u
#define RVEMU_ICACHE_ENTRIES 32u

/* One decoded instruction, keyed by pc, satp and privilege. len is 2 or 4.
 * valid is 0 when the slot is empty. pa is the physical address of the
 * first parcel, so a later store of those bytes can drop the line. epoch is
 * the hart store epoch observed when this line last matched guest RAM. */
struct rvemu_icache_entry {
    uint64_t tag_pc;
    uint64_t tag_satp;
    uint64_t pa;
    uint64_t epoch;
    uint32_t raw;
    uint8_t len;
    uint8_t priv;
    uint8_t valid;
    uint8_t pad;
};

/* One cached Sv39 translation. tag is the virtual page plus the context it was
 * made in (privilege, SUM, MXR); zero is empty. page is the guest-physical
 * page: no host pointer is kept, so a hit still goes through the bounds check
 * of the bus and the hart stays a plain copyable value. */
struct rvemu_tlb_entry {
    uint64_t tag;
    uint64_t page;
};

/* CSR storage. Fields are raw; the WARL masks live in the CSR file. mip holds
 * only the software-writable bits (SSIP, STIP, SEIP); the machine-level lines
 * live in rvemu_hart.irq_in. */
struct rvemu_csrs {
    uint64_t mstatus;
    uint64_t mtvec;
    uint64_t mepc;
    uint64_t mcause;
    uint64_t mtval;
    uint64_t mscratch;
    uint64_t mie;
    uint64_t mip;
    uint64_t medeleg;
    uint64_t mideleg;
    uint64_t satp;
    uint64_t stvec;
    uint64_t sepc;
    uint64_t scause;
    uint64_t stval;
    uint64_t sscratch;
    uint64_t mcounteren;
    uint64_t scounteren;
    uint64_t menvcfg;
    uint64_t senvcfg;
    uint64_t mcountinhibit;
    uint64_t pmpcfg[2]; /* pmpcfg0 and pmpcfg2: eight 8-bit entries each */
    uint64_t pmpaddr[RVEMU_PMP_ENTRIES];
    uint64_t mnstatus;
};

struct rvemu_hart {
    uint64_t x[32];
    uint64_t f[32]; /* F/D registers; singles are NaN-boxed */
    uint32_t fcsr;  /* fflags in bits 4:0, frm in bits 7:5 */
    uint64_t pc;
    uint64_t instret;
    struct rvemu_csrs csr;
    /* lr/sc reservation: resv_bytes is 0 when none is held. */
    uint64_t resv_addr;
    unsigned resv_bytes;
    unsigned profile;     /* enum rvemu_profile */
    unsigned priv;        /* enum rvemu_priv; always M in the STOP profile */
    unsigned idle;        /* set by wfi, cleared once an interrupt is pending */
    unsigned cnt_written; /* internal: a counter CSR was written by this step */
    uint64_t cycle;       /* mcycle: one per executed step, trapped steps included */
    uint64_t irq_in;      /* machine-level lines MSIP, MTIP, MEIP (rvemu_set_irq) */
    uint64_t time;        /* the time CSR; the platform advances it */
    /* Host-only clock source: instructions retired since init. It advances
     * exactly when an instruction retires (wfi retires once; a trap, an
     * interrupt entry and an ecall answered by the host do not), and no guest
     * CSR write and no counter inhibit touches it, unlike instret. */
    uint64_t retired;
    /* internal: the memory fault of the current step (architectural cause and
     * the faulting virtual address), valid while fault_set is non-zero */
    unsigned fault_set;
    unsigned fault_cause;
    uint64_t fault_tval;
    /* internal: the translation cache, one direct-mapped table per access kind
     * (fetch, load, store), holding translations made under satp == tlb_satp */
    uint64_t tlb_satp;
    struct rvemu_tlb_entry tlb[3][RVEMU_TLB_ENTRIES];
    /* internal: decoded instruction cache. A hit matches pc, satp and
     * privilege. When the line's store epoch matches mem_epoch and is not
     * zero, the hit skips the guest-memory re-read. Otherwise the cached
     * bits must still be at pa. A store that overlaps a cached parcel,
     * fence.i, and every translation flush drop the matching lines. */
    struct rvemu_icache_entry icache[RVEMU_ICACHE_ENTRIES];
    uint64_t icache_hit;
    uint64_t icache_miss;
    uint64_t icache_fast; /* hits that did not re-read guest memory */
    /* 0 forces the next hit to re-read. Init sets 1. Each noted store
     * increments it, and a wrap back from the top flushes the cache. */
    uint64_t mem_epoch;
};

/* The physical bus. bytes[0..size) is guest RAM at physical addresses
 * [base, base + size). An access wholly inside RAM uses RAM. Any other data
 * access goes to the device callbacks when they are set: one call per access,
 * never split and never cached, nbytes is 1, 2, 4 or 8, the value is
 * little-endian in the low bytes, and a non-zero return is an access fault.
 * With a null callback the access faults, so a zero-initialised tail behaves
 * as RAM only. Instructions and page tables are read from RAM only. */
struct rvemu_mem {
    uint64_t base;
    size_t size;
    uint8_t *bytes;
    void *io_ctx;
    int (*io_load)(void *ctx, uint64_t paddr, unsigned nbytes, uint64_t *out);
    int (*io_store)(void *ctx, uint64_t paddr, unsigned nbytes, uint64_t val);
};

/* Expand one 16-bit RV64C encoding (low two bits not 0b11) to the 32-bit
 * base-ISA instruction it names. Returns 0, or -1 for a reserved encoding,
 * which includes the all-zero halfword. */
int rvemu_rvc_expand(uint16_t c, uint32_t *out);

/* Zero every register and CSR, then set pc. The hart starts in the STOP
 * profile at privilege M. */
void rvemu_hart_init(struct rvemu_hart *hart, uint64_t entry_pc);

/* The same, in the MACHINE profile at privilege M (reset state). */
void rvemu_hart_init_machine(struct rvemu_hart *hart, uint64_t entry_pc);

/* The same, in the SBI profile at privilege S. */
void rvemu_hart_init_sbi(struct rvemu_hart *hart, uint64_t entry_pc);

/* Resumes an SBI-profile hart stopped on an S-mode ecall (RVEMU_STOP_ECALL):
 * writes the two SBI return registers a0 and a1 and advances pc past the
 * ecall. Nothing is counted: an ecall is a trap, it never retires, so instret,
 * cycle and retired are the same before the ecall and after this call, exactly
 * as when firmware in M-mode answers the call and returns with mepc + 4. */
void rvemu_ecall_return(struct rvemu_hart *hart, uint64_t a0, uint64_t a1);

/* Drops every cached address translation. The hart does this itself on
 * sfence.vma (every form) and on every satp write, and it notices a satp that
 * the host changed directly in the struct. Cached translations are keyed by
 * access kind, effective privilege, SUM and MXR, cover RAM pages only, and a
 * store is cached only once its page is dirty; as on hardware, a guest that
 * edits a page table must sfence.vma before the change is guaranteed visible.
 * A host that rewrites guest page tables itself calls this. */
void rvemu_tlb_flush(struct rvemu_hart *hart);

/* Guest RAM at [pa, pa + n) changed outside the store that the hart itself
 * just performed. Drops any decoded line whose parcel overlaps that range.
 * A range wider than 8 bytes, or one that would wrap the address space,
 * drops every line. n == 0 and a null hart do nothing. Every accepted call
 * also makes the next fetch of each surviving line re-read guest memory. */
void rvemu_icache_note_store(struct rvemu_hart *hart, uint64_t pa, unsigned n);

/* Drops every cache the hart derives from guest-visible state. A host that
 * rewrites the hart or guest memory from outside (a restore) calls this. */
void rvemu_invalidate_derived(struct rvemu_hart *hart);

/* Drives a platform interrupt line. cause is RVEMU_IRQ_*; level non-zero
 * raises it, zero lowers it. SSIP, STIP and SEIP set or clear the matching mip
 * bit (software also writes them through the CSR); MSIP, MTIP and MEIP are
 * read-only lines. Returns 0, or -1 for a null hart or any other cause. */
int rvemu_set_irq(struct rvemu_hart *hart, unsigned cause, int level);

/* Retire one instruction. Returns RVEMU_STOP_NONE on success. Null hart or
 * memory, or a fetch outside mem, returns RVEMU_STOP_OUT_OF_RANGE. */
enum rvemu_stop rvemu_step(struct rvemu_hart *hart, struct rvemu_mem *mem);

/* Step at most max_steps times, stopping early on any non-NONE reason, which
 * is written to *stop (RVEMU_STOP_STEP_LIMIT when the budget runs out).
 * Returns 0, or -1 when stop is null or hart or mem is null. */
int rvemu_run(struct rvemu_hart *hart, struct rvemu_mem *mem, uint64_t max_steps,
              enum rvemu_stop *stop);

#endif
