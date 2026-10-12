/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: the CSR file. One table maps each address to its storage or to a
 * handler; the WARL masks, the privilege/read-only rule from the address bits,
 * the counter-enable gates and the TVM check live here.
 *
 * Choices (the next slice and the platform must know):
 *  - satp: MODE 0 (Bare) and MODE 8 (Sv39) are accepted, Sv39 only in the
 *    trapping profiles; a write with any other MODE leaves satp unchanged, so
 *    probing a larger mode reads back the old value. The ASID field is
 *    hardwired to zero. Every write drops the translation cache. Translation
 *    itself is rvemu_vm.c.
 *  - time: reads hart->time, which the platform sets; gated by counteren.
 *  - cycle/mcycle count executed steps (traps included); instret/minstret count
 *    retired instructions. mcountinhibit CY and IR are honoured.
 *  - misa is read-only in effect (writes accepted, ignored). menvcfg/senvcfg
 *    are WARL zero. The trigger CSRs read zero and ignore writes (no triggers).
 *  - PMP: 16 entries, pmpcfg0/pmpcfg2 and pmpaddr0-15 hold WARL state with the
 *    lock bit honoured; access checks are NOT enforced (every access passes). */
#include "rvemu_internal.h"
#include <stddef.h>

#define MISA_RV64IMAFDCSU 0x800000000014112Dull
#define SATP_MODE_SV39 8u
#define SATP_WMASK 0xf0000fffffffffffull /* MODE and the 44-bit PPN; ASID reads zero */
#define PMPADDR_MASK 0x003fffffffffffffull
#define PMPCFG_ENTRY_MASK 0x9fu
#define PMPCFG_LOCK 0x80u
#define PMPCFG_W 2u
#define PMPCFG_R 1u
#define PMPCFG_A_SHIFT 3u
#define PMPCFG_A_TOR 1u

#define MSTATUS_WMASK                                                                       \
    (MSTATUS_SIE | MSTATUS_MIE | MSTATUS_SPIE | MSTATUS_MPIE | MSTATUS_SPP | MSTATUS_MPP | \
     MSTATUS_FS | MSTATUS_MPRV | MSTATUS_SUM | MSTATUS_MXR | MSTATUS_TVM | MSTATUS_TW |     \
     MSTATUS_TSR)
#define SSTATUS_WMASK \
    (MSTATUS_SIE | MSTATUS_SPIE | MSTATUS_SPP | MSTATUS_FS | MSTATUS_SUM | MSTATUS_MXR)
#define SSTATUS_VIEW (SSTATUS_WMASK | MSTATUS_UXL | MSTATUS_SD)

#define CSR_SSTATUS 0x100u
#define CSR_SIE 0x104u
#define CSR_STVEC 0x105u
#define CSR_SIP 0x144u
#define CSR_MSTATUS 0x300u
#define CSR_MTVEC 0x305u
#define CSR_MIP 0x344u
#define CSR_MCYCLE 0xb00u
#define CSR_MINSTRET 0xb02u
#define CSR_CYCLE 0xc00u
#define CSR_TIME 0xc01u
#define CSR_INSTRET 0xc02u
#define CSR_PMPCFG0 0x3a0u
#define CSR_PMPADDR0 0x3b0u

typedef int (*csr_rd_fn)(struct rvemu_hart *h, unsigned addr, uint64_t *out);
typedef int (*csr_wr_fn)(struct rvemu_hart *h, unsigned addr, uint64_t val);

struct csr_row {
    unsigned addr;
    size_t off;     /* plain storage: offset in struct rvemu_csrs */
    uint64_t wmask; /* plain storage: writable bits */
    csr_rd_fn rd;   /* non-null: handler instead of plain storage */
    csr_wr_fn wr;
};

/* mstatus with UXL/SXL forced to 64-bit and SD derived from FS. */
static uint64_t mstatus_view(uint64_t m)
{
    m = (m & ~(MSTATUS_UXL | MSTATUS_SXL | MSTATUS_SD)) | MSTATUS_XL_FIXED;
    if ((m & MSTATUS_FS) == MSTATUS_FS) m |= MSTATUS_SD;
    return m;
}

static int mstatus_rd(struct rvemu_hart *h, unsigned addr, uint64_t *out)
{
    uint64_t m = mstatus_view(h->csr.mstatus);
    *out = addr == CSR_SSTATUS ? (m & SSTATUS_VIEW) : m;
    return 0;
}

static int mstatus_wr(struct rvemu_hart *h, unsigned addr, uint64_t val)
{
    uint64_t mask = addr == CSR_SSTATUS ? SSTATUS_WMASK : MSTATUS_WMASK;
    uint64_t old = h->csr.mstatus, m = (old & ~mask) | (val & mask);
    /* MPP = 2 is reserved: keep the old field. */
    if ((m & MSTATUS_MPP) == (2ull << MSTATUS_MPP_SHIFT)) m = (m & ~MSTATUS_MPP) | (old & MSTATUS_MPP);
    h->csr.mstatus = mstatus_view(m);
    return 0;
}

static int mip_rd(struct rvemu_hart *h, unsigned addr, uint64_t *out)
{
    uint64_t mip = rvemu_mip_effective(h);
    *out = addr == CSR_SIP ? (mip & h->csr.mideleg & IRQ_S_MASK) : mip;
    return 0;
}

/* mip: M writes SSIP, STIP, SEIP. sip: S writes SSIP, only when delegated. */
static int mip_wr(struct rvemu_hart *h, unsigned addr, uint64_t val)
{
    uint64_t mask = addr == CSR_SIP ? (h->csr.mideleg & (1ull << RVEMU_IRQ_SSIP)) : IRQ_S_MASK;
    h->csr.mip = (h->csr.mip & ~mask) | (val & mask);
    return 0;
}

static int sie_rd(struct rvemu_hart *h, unsigned addr, uint64_t *out)
{
    (void)addr;
    *out = h->csr.mie & h->csr.mideleg & IRQ_S_MASK;
    return 0;
}

static int sie_wr(struct rvemu_hart *h, unsigned addr, uint64_t val)
{
    (void)addr;
    uint64_t mask = h->csr.mideleg & IRQ_S_MASK;
    h->csr.mie = (h->csr.mie & ~mask) | (val & mask);
    return 0;
}

static int tvec_rd(struct rvemu_hart *h, unsigned addr, uint64_t *out)
{
    *out = addr == CSR_MTVEC ? h->csr.mtvec : h->csr.stvec;
    return 0;
}

/* MODE 0 direct, 1 vectored; a reserved MODE keeps the old one. */
static int tvec_wr(struct rvemu_hart *h, unsigned addr, uint64_t val)
{
    uint64_t *slot = addr == CSR_MTVEC ? &h->csr.mtvec : &h->csr.stvec;
    uint64_t mode = (val & 3u) <= 1u ? (val & 3u) : (*slot & 3u);
    *slot = (val & ~(uint64_t)3) | mode;
    return 0;
}

static int satp_denied(const struct rvemu_hart *h)
{
    return h->priv == RVEMU_PRIV_S && (h->csr.mstatus & MSTATUS_TVM) != 0;
}

static int satp_rd(struct rvemu_hart *h, unsigned addr, uint64_t *out)
{
    (void)addr;
    if (satp_denied(h)) return -1;
    *out = h->csr.satp;
    return 0;
}

static int satp_wr(struct rvemu_hart *h, unsigned addr, uint64_t val)
{
    (void)addr;
    if (satp_denied(h)) return -1;
    uint64_t mode = val >> 60;
    int sv39 = mode == SATP_MODE_SV39 && h->profile != RVEMU_PROFILE_STOP;
    if (mode == 0 || sv39) h->csr.satp = val & SATP_WMASK;
    rvemu_tlb_flush(h); /* every write, also one that changed nothing */
    return 0;
}

static int misa_rd(struct rvemu_hart *h, unsigned addr, uint64_t *out)
{
    (void)h, (void)addr;
    *out = MISA_RV64IMAFDCSU;
    return 0;
}

static int zero_rd(struct rvemu_hart *h, unsigned addr, uint64_t *out)
{
    (void)h, (void)addr;
    *out = 0;
    return 0;
}

static int ignore_wr(struct rvemu_hart *h, unsigned addr, uint64_t val)
{
    (void)h, (void)addr, (void)val;
    return 0;
}

static int counter_rd(struct rvemu_hart *h, unsigned addr, uint64_t *out)
{
    switch (addr) {
    case CSR_MCYCLE: case CSR_CYCLE: *out = h->cycle; return 0;
    case CSR_TIME: *out = h->time; return 0;
    default: *out = h->instret; return 0;
    }
}

static int counter_wr(struct rvemu_hart *h, unsigned addr, uint64_t val)
{
    if (addr == CSR_MCYCLE) {
        h->cycle = val;
        h->cnt_written |= 1u;
    } else {
        h->instret = val;
        h->cnt_written |= 2u;
    }
    return 0;
}

/* Bit offset of PMP entry i's configuration byte inside its pmpcfg register. */
static unsigned pmp_shift(unsigned i) { return (i & 7u) << 3; }

static unsigned pmp_cfg_byte(const struct rvemu_hart *h, unsigned i)
{
    return (unsigned)((h->csr.pmpcfg[i >> 3] >> pmp_shift(i)) & 0xffu);
}

static int pmp_locked(const struct rvemu_hart *h, unsigned i)
{
    if (pmp_cfg_byte(h, i) & PMPCFG_LOCK) return 1;
    if (i + 1u >= RVEMU_PMP_ENTRIES) return 0;
    unsigned next = pmp_cfg_byte(h, i + 1u);
    return (next & PMPCFG_LOCK) && ((next >> PMPCFG_A_SHIFT) & 3u) == PMPCFG_A_TOR;
}

static int pmpaddr_rd(struct rvemu_hart *h, unsigned addr, uint64_t *out)
{
    *out = h->csr.pmpaddr[addr - CSR_PMPADDR0];
    return 0;
}

static int pmpaddr_wr(struct rvemu_hart *h, unsigned addr, uint64_t val)
{
    unsigned i = addr - CSR_PMPADDR0;
    if (!pmp_locked(h, i)) h->csr.pmpaddr[i] = val & PMPADDR_MASK;
    return 0;
}

static int pmpcfg_rd(struct rvemu_hart *h, unsigned addr, uint64_t *out)
{
    *out = h->csr.pmpcfg[(addr - CSR_PMPCFG0) >> 1];
    return 0;
}

/* Per byte: a locked entry keeps its byte, reserved bits read zero, and the
 * reserved W-without-R combination keeps the old byte. */
static int pmpcfg_wr(struct rvemu_hart *h, unsigned addr, uint64_t val)
{
    unsigned reg = (addr - CSR_PMPCFG0) >> 1;
    for (unsigned k = 0; k < 8u; k++) {
        unsigned i = reg * 8u + k, old = pmp_cfg_byte(h, i), sh = pmp_shift(i);
        unsigned nb = (unsigned)(val >> sh) & PMPCFG_ENTRY_MASK;
        if ((old & PMPCFG_LOCK) || ((nb & PMPCFG_W) && !(nb & PMPCFG_R))) continue;
        h->csr.pmpcfg[reg] = (h->csr.pmpcfg[reg] & ~(0xffull << sh)) | ((uint64_t)nb << sh);
    }
    return 0;
}

#define PLAIN(a, field, mask) {a, offsetof(struct rvemu_csrs, field), mask, NULL, NULL}
#define ALL 0xffffffffffffffffull

static const struct csr_row CSR_TABLE[] = {
    {CSR_MSTATUS, 0, 0, mstatus_rd, mstatus_wr},
    {CSR_SSTATUS, 0, 0, mstatus_rd, mstatus_wr},
    {0x301u, 0, 0, misa_rd, ignore_wr},
    PLAIN(0x302u, medeleg, 0xb3ffull),
    PLAIN(0x303u, mideleg, IRQ_S_MASK),
    PLAIN(0x304u, mie, IRQ_S_MASK | IRQ_M_MASK),
    {CSR_MTVEC, 0, 0, tvec_rd, tvec_wr},
    PLAIN(0x306u, mcounteren, 0xffffffffull),
    PLAIN(0x30au, menvcfg, 0),
    PLAIN(0x320u, mcountinhibit, 0xfffffffdull),
    PLAIN(0x340u, mscratch, ALL),
    PLAIN(0x341u, mepc, ~1ull),
    PLAIN(0x342u, mcause, ALL),
    PLAIN(0x343u, mtval, ALL),
    {CSR_MIP, 0, 0, mip_rd, mip_wr},
    PLAIN(0x744u, mnstatus, ALL),
    {CSR_SIE, 0, 0, sie_rd, sie_wr},
    {CSR_STVEC, 0, 0, tvec_rd, tvec_wr},
    PLAIN(0x106u, scounteren, 0xffffffffull),
    PLAIN(0x10au, senvcfg, 0),
    PLAIN(0x140u, sscratch, ALL),
    PLAIN(0x141u, sepc, ~1ull),
    PLAIN(0x142u, scause, ALL),
    PLAIN(0x143u, stval, ALL),
    {CSR_SIP, 0, 0, mip_rd, mip_wr},
    {0x180u, 0, 0, satp_rd, satp_wr},
    {CSR_PMPCFG0, 0, 0, pmpcfg_rd, pmpcfg_wr},
    {CSR_PMPCFG0 + 2u, 0, 0, pmpcfg_rd, pmpcfg_wr},
    {0xf11u, 0, 0, zero_rd, ignore_wr}, /* mvendorid */
    {0xf12u, 0, 0, zero_rd, ignore_wr}, /* marchid */
    {0xf13u, 0, 0, zero_rd, ignore_wr}, /* mimpid */
    {0xf14u, 0, 0, zero_rd, ignore_wr}, /* mhartid */
    {0xf15u, 0, 0, zero_rd, ignore_wr}, /* mconfigptr */
    {0x7a0u, 0, 0, zero_rd, ignore_wr}, /* tselect: no triggers */
    {0x7a1u, 0, 0, zero_rd, ignore_wr}, /* tdata1 */
    {0x7a2u, 0, 0, zero_rd, ignore_wr}, /* tdata2 */
    {0x7a3u, 0, 0, zero_rd, ignore_wr}, /* tdata3 */
    {CSR_MCYCLE, 0, 0, counter_rd, counter_wr},
    {CSR_MINSTRET, 0, 0, counter_rd, counter_wr},
    {CSR_CYCLE, 0, 0, counter_rd, ignore_wr},
    {CSR_TIME, 0, 0, counter_rd, ignore_wr},
    {CSR_INSTRET, 0, 0, counter_rd, ignore_wr},
};

static const struct csr_row HPM_ROW = {0, 0, 0, zero_rd, ignore_wr};
static const struct csr_row PMPADDR_ROW = {0, 0, 0, pmpaddr_rd, pmpaddr_wr};

static int in_range(unsigned addr, unsigned lo, unsigned n) { return addr >= lo && addr - lo < n; }

static const struct csr_row *find_row(unsigned addr)
{
    for (size_t i = 0; i < sizeof(CSR_TABLE) / sizeof(CSR_TABLE[0]); i++)
        if (CSR_TABLE[i].addr == addr) return &CSR_TABLE[i];
    if (in_range(addr, 0xb03u, 29u) || in_range(addr, 0xc03u, 29u) || in_range(addr, 0x323u, 29u))
        return &HPM_ROW; /* mhpmcounter3-31, hpmcounter3-31, mhpmevent3-31: hardwired 0 */
    if (in_range(addr, CSR_PMPADDR0, RVEMU_PMP_ENTRIES)) return &PMPADDR_ROW;
    return NULL;
}

/* Unprivileged counters 0xc00-0xc1f are gated by mcounteren (which the SBI
 * profile, having no M-mode to trap to, treats as all ones), and in U also by
 * scounteren. */
static int counter_ok(const struct rvemu_hart *h, unsigned bit)
{
    int below_m = h->priv != RVEMU_PRIV_M && h->profile != RVEMU_PROFILE_SBI;
    if (below_m && !((h->csr.mcounteren >> bit) & 1u)) return 0;
    return h->priv != RVEMU_PRIV_U || ((h->csr.scounteren >> bit) & 1u) != 0;
}

/* Privilege from address bits 9:8 (00 U, 01 S, 11 M; 10 is the absent
 * hypervisor level) and read-only from bits 11:10 == 11. */
static int access_ok(const struct rvemu_hart *h, unsigned addr, int write)
{
    unsigned level = (addr >> 8) & 3u;
    if (level == 2u || h->priv < level) return 0;
    if (write && (addr >> 10) == 3u) return 0;
    if (in_range(addr, CSR_CYCLE, 32u) && !counter_ok(h, addr & 31u)) return 0;
    return 1;
}

int rvemu_csr_read(struct rvemu_hart *hart, unsigned addr, uint64_t *out)
{
    int fp = rvemu_fpu_csr_read(hart, addr, out);
    if (fp <= 0) return fp;
    const struct csr_row *row = find_row(addr);
    if (!row || !access_ok(hart, addr, 0)) return -1;
    if (row->rd) return row->rd(hart, addr, out);
    *out = *(const uint64_t *)((const unsigned char *)&hart->csr + row->off);
    return 0;
}

int rvemu_csr_write(struct rvemu_hart *hart, unsigned addr, uint64_t val)
{
    int fp = rvemu_fpu_csr_write(hart, addr, val);
    if (fp <= 0) return fp;
    const struct csr_row *row = find_row(addr);
    if (!row || !access_ok(hart, addr, 1)) return -1;
    if (row->wr) return row->wr(hart, addr, val);
    uint64_t *slot = (uint64_t *)((unsigned char *)&hart->csr + row->off);
    *slot = (*slot & ~row->wmask) | (val & row->wmask);
    return 0;
}
