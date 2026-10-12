/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: field-by-field little-endian codecs for the state a snapshot
 * holds. Every structure is written and read from one field list, so the two
 * directions cannot drift. Host pointers, callbacks, scratch buffers and the
 * engine's derived caches are never written. */
#include "rvmachine_snapshot_priv.h"

#include "base/serialize_le.h"

#include <string.h>

/* Each structure below is serialised field by field. Its size is pinned on
 * LP64 targets: a new field changes the size and stops the build until the
 * codec is extended and RVMACHINE_MODEL_VERSION and RVMACHINE_SNAPSHOT_VERSION
 * are reviewed. */
#if UINTPTR_MAX == UINT64_MAX && !defined(_WIN32)
static_assert(sizeof(struct rvplat_plic) == 332, "rvplat_plic changed: update the snapshot codec");
static_assert(sizeof(struct rvplat_timer) == 16, "rvplat_timer changed: update the snapshot codec");
static_assert(sizeof(struct rvplat_uart) == 48, "rvplat_uart changed: update the snapshot codec");
static_assert(sizeof(struct rvplat_sbi) == 48, "rvplat_sbi changed: update the snapshot codec");
static_assert(sizeof(struct rvmachine_input) == 4112, "rvmachine_input changed: update the snapshot codec");
static_assert(sizeof(struct rvvirtio_queue) == 40, "rvvirtio_queue changed: update the snapshot codec");
static_assert(sizeof(struct rvvirtio_dev) == 4992, "rvvirtio_dev changed: update the snapshot codec");
static_assert(sizeof(struct rvvirtio_blk) == 9152, "rvvirtio_blk changed: update the snapshot codec");
static_assert(sizeof(struct rvvirtio_rng) == 5560, "rvvirtio_rng changed: update the snapshot codec");
static_assert(sizeof(struct rvemu_hart) == 14544, "rvemu_hart changed: update the snapshot codec");
static_assert(sizeof(struct rvmachine) == 97688, "rvmachine changed: update the snapshot codec");
#endif

/* ---- bounded writer and reader ---- */

void snap_putn(struct snap_wr *w, const void *src, size_t n)
{
    if (w->bad || n > w->cap - w->pos) {
        w->bad = true;
        return;
    }
    if (n != 0) memcpy(w->p + w->pos, src, n);
    w->pos += n;
}

void snap_put8(struct snap_wr *w, uint8_t v) { snap_putn(w, &v, 1); }

void snap_put32(struct snap_wr *w, uint32_t v)
{
    uint8_t b[4];
    zcl_write_u32_le(b, v);
    snap_putn(w, b, sizeof b);
}

void snap_put64(struct snap_wr *w, uint64_t v)
{
    uint8_t b[8];
    zcl_write_u64_le(b, v);
    snap_putn(w, b, sizeof b);
}

void snap_getn(struct snap_rd *r, void *dst, size_t n)
{
    if (r->bad || n > r->n - r->pos) {
        r->bad = true;
        if (n != 0) memset(dst, 0, n);
        return;
    }
    if (n != 0) memcpy(dst, r->p + r->pos, n);
    r->pos += n;
}

uint8_t snap_get8(struct snap_rd *r)
{
    uint8_t v = 0;
    snap_getn(r, &v, 1);
    return v;
}

uint32_t snap_get32(struct snap_rd *r)
{
    uint8_t b[4];
    snap_getn(r, b, sizeof b);
    return zcl_read_u32_le(b);
}

uint64_t snap_get64(struct snap_rd *r)
{
    uint8_t b[8];
    snap_getn(r, b, sizeof b);
    return zcl_read_u64_le(b);
}

/* A boolean is exactly 0 or 1. */
bool snap_getb(struct snap_rd *r)
{
    uint8_t v = snap_get8(r);
    if (v > 1u) r->bad = true;
    return v == 1u;
}

static void snap_putb(struct snap_wr *w, bool v) { snap_put8(w, v ? 1u : 0u); }

size_t snap_section_begin(struct snap_wr *w, uint32_t tag)
{
    snap_put32(w, tag);
    snap_put32(w, 0);
    return w->pos;
}

void snap_section_end(struct snap_wr *w, size_t mark)
{
    uint8_t b[4];
    if (w->bad) return;
    zcl_write_u32_le(b, (uint32_t)(w->pos - mark));
    memcpy(w->p + mark - 4u, b, sizeof b);
}

bool snap_section_open(struct snap_rd *r, uint32_t tag, struct snap_rd *body)
{
    uint32_t got = snap_get32(r);
    uint32_t len = snap_get32(r);
    if (r->bad || got != tag || len > r->n - r->pos) return false;
    *body = (struct snap_rd){.p = r->p + r->pos, .n = len};
    return true;
}

/* The section must have been read exactly; the outer reader moves past it. */
bool snap_section_close(struct snap_rd *r, const struct snap_rd *body)
{
    if (body->bad || body->pos != body->n) return false;
    r->pos += body->n;
    return true;
}

/* ---- hart ---- */

#define CSR_FIELDS(X) \
    X(mstatus) X(mtvec) X(mepc) X(mcause) X(mtval) X(mscratch) X(mie) X(mip) \
    X(medeleg) X(mideleg) X(satp) X(stvec) X(sepc) X(scause) X(stval) \
    X(sscratch) X(mcounteren) X(scounteren) X(menvcfg) X(senvcfg) \
    X(mcountinhibit) X(mnstatus)

#define HART_U64_FIELDS(X) \
    X(pc) X(instret) X(resv_addr) X(cycle) X(irq_in) X(time) X(retired) X(fault_tval)

#define HART_U32_FIELDS(X) \
    X(resv_bytes) X(profile) X(priv) X(idle) X(cnt_written) X(fault_set) X(fault_cause)

#define ONE(f) +1u
static_assert(sizeof(struct rvemu_csrs) ==
                  sizeof(uint64_t) * (0u CSR_FIELDS(ONE) + 2u + RVEMU_PMP_ENTRIES),
              "a new CSR field needs a codec row");
#undef ONE

void snap_hart_put(struct snap_wr *w, const struct rvemu_hart *h)
{
    for (unsigned i = 0; i < 32u; i++) snap_put64(w, h->x[i]);
    for (unsigned i = 0; i < 32u; i++) snap_put64(w, h->f[i]);
    snap_put32(w, h->fcsr);
#define PUT64(f) snap_put64(w, h->f);
#define PUT32(f) snap_put32(w, (uint32_t)h->f);
#define PUTCSR(f) snap_put64(w, h->csr.f);
    HART_U64_FIELDS(PUT64)
    HART_U32_FIELDS(PUT32)
    CSR_FIELDS(PUTCSR)
#undef PUT64
#undef PUT32
#undef PUTCSR
    for (unsigned i = 0; i < 2u; i++) snap_put64(w, h->csr.pmpcfg[i]);
    for (unsigned i = 0; i < RVEMU_PMP_ENTRIES; i++) snap_put64(w, h->csr.pmpaddr[i]);
}

/* The engine's states a machine can be in; anything else is malformed. */
static bool hart_valid(const struct rvemu_hart *h)
{
    return h->profile == RVEMU_PROFILE_SBI &&
           (h->priv == RVEMU_PRIV_U || h->priv == RVEMU_PRIV_S) && h->idle <= 1u &&
           h->fault_set <= 1u && h->resv_bytes <= 8u;
}

bool snap_hart_get(struct snap_rd *r, struct rvemu_hart *h)
{
    for (unsigned i = 0; i < 32u; i++) h->x[i] = snap_get64(r);
    for (unsigned i = 0; i < 32u; i++) h->f[i] = snap_get64(r);
    h->fcsr = snap_get32(r);
#define GET64(f) h->f = snap_get64(r);
#define GET32(f) h->f = snap_get32(r);
#define GETCSR(f) h->csr.f = snap_get64(r);
    HART_U64_FIELDS(GET64)
    HART_U32_FIELDS(GET32)
    CSR_FIELDS(GETCSR)
#undef GET64
#undef GET32
#undef GETCSR
    for (unsigned i = 0; i < 2u; i++) h->csr.pmpcfg[i] = snap_get64(r);
    for (unsigned i = 0; i < RVEMU_PMP_ENTRIES; i++) h->csr.pmpaddr[i] = snap_get64(r);
    return !r->bad && hart_valid(h);
}

/* ---- interrupt controller, timer, serial port, firmware ---- */

static void put_words(struct snap_wr *w, const uint32_t *v, unsigned n)
{
    for (unsigned i = 0; i < n; i++) snap_put32(w, v[i]);
}

static void get_words(struct snap_rd *r, uint32_t *v, unsigned n)
{
    for (unsigned i = 0; i < n; i++) v[i] = snap_get32(r);
}

void snap_plic_put(struct snap_wr *w, const struct rvplat_plic *p)
{
    snap_put32(w, p->nsources);
    put_words(w, p->priority, RVPLAT_PLIC_MAX_SOURCES + 1u);
    put_words(w, p->level, RVPLAT_PLIC_WORDS);
    put_words(w, p->pending, RVPLAT_PLIC_WORDS);
    put_words(w, p->inflight, RVPLAT_PLIC_WORDS);
    for (unsigned c = 0; c < RVPLAT_PLIC_CONTEXTS; c++)
        put_words(w, p->enable[c], RVPLAT_PLIC_WORDS);
    put_words(w, p->threshold, RVPLAT_PLIC_CONTEXTS);
}

bool snap_plic_get(struct snap_rd *r, struct rvplat_plic *p)
{
    uint32_t nsources = snap_get32(r);
    get_words(r, p->priority, RVPLAT_PLIC_MAX_SOURCES + 1u);
    get_words(r, p->level, RVPLAT_PLIC_WORDS);
    get_words(r, p->pending, RVPLAT_PLIC_WORDS);
    get_words(r, p->inflight, RVPLAT_PLIC_WORDS);
    for (unsigned c = 0; c < RVPLAT_PLIC_CONTEXTS; c++)
        get_words(r, p->enable[c], RVPLAT_PLIC_WORDS);
    get_words(r, p->threshold, RVPLAT_PLIC_CONTEXTS);
    return !r->bad && nsources == p->nsources;
}

void snap_timer_put(struct snap_wr *w, const struct rvplat_timer *t)
{
    snap_put64(w, t->ticks_per_time);
    snap_put64(w, t->deadline);
}

bool snap_timer_get(struct snap_rd *r, struct rvplat_timer *t)
{
    uint64_t ticks = snap_get64(r);
    t->deadline = snap_get64(r);
    return !r->bad && ticks == t->ticks_per_time;
}

void snap_uart_put(struct snap_wr *w, const struct rvplat_uart *u)
{
    snap_putn(w, u->rx, sizeof u->rx);
    snap_put8(w, u->rx_head);
    snap_put8(w, u->rx_count);
    snap_put8(w, u->ier);
    snap_put8(w, u->lcr);
    snap_put8(w, u->mcr);
    snap_put8(w, u->scr);
    snap_put8(w, u->fcr);
    snap_put8(w, u->dll);
    snap_put8(w, u->dlm);
    snap_putb(w, u->overrun);
    snap_putb(w, u->thre_irq);
}

bool snap_uart_get(struct snap_rd *r, struct rvplat_uart *u)
{
    snap_getn(r, u->rx, sizeof u->rx);
    u->rx_head = snap_get8(r);
    u->rx_count = snap_get8(r);
    u->ier = snap_get8(r);
    u->lcr = snap_get8(r);
    u->mcr = snap_get8(r);
    u->scr = snap_get8(r);
    u->fcr = snap_get8(r);
    u->dll = snap_get8(r);
    u->dlm = snap_get8(r);
    u->overrun = snap_getb(r);
    u->thre_irq = snap_getb(r);
    return !r->bad && u->rx_head < RVPLAT_UART_FIFO_SIZE &&
           u->rx_count <= RVPLAT_UART_FIFO_SIZE;
}

void snap_sbi_put(struct snap_wr *w, const struct rvplat_sbi *s)
{
    snap_put64(w, s->mvendorid);
    snap_put64(w, s->marchid);
    snap_put64(w, s->mimpid);
    snap_put32(w, (uint32_t)s->hart0);
}

bool snap_sbi_get(struct snap_rd *r, struct rvplat_sbi *s)
{
    s->mvendorid = snap_get64(r);
    s->marchid = snap_get64(r);
    s->mimpid = snap_get64(r);
    uint32_t state = snap_get32(r);
    s->hart0 = (enum rvplat_sbi_hart_state)state;
    return !r->bad && state <= RVPLAT_SBI_HART_STOPPED;
}

void snap_input_put(struct snap_wr *w, const struct rvmachine_input *q)
{
    snap_put32(w, (uint32_t)q->count);
    for (size_t i = 0; i < q->count; i++)
        snap_put8(w, q->bytes[(q->head + i) % RVMACHINE_INPUT_MAX]);
}

/* The queue is stored unwrapped, oldest byte first. */
bool snap_input_get(struct snap_rd *r, struct rvmachine_input *q)
{
    uint32_t count = snap_get32(r);
    if (r->bad || count > RVMACHINE_INPUT_MAX) return false;
    memset(q, 0, sizeof *q);
    snap_getn(r, q->bytes, count);
    q->count = count;
    return !r->bad;
}

/* ---- machine scalars ---- */

#define MACHINE_U64_FIELDS(X) \
    X(image_end) X(entry_pc) X(entry_a0) X(entry_a1) X(seed_addr) X(time_skip) \
    X(fw_calls) X(device_work) X(device_moved) X(wfi_instret) \
    X(storm_instret)

#define MACHINE_U32_FIELDS(X) \
    X(storm_steps) X(reset_type) X(reset_reason)

#define MACHINE_BOOL_FIELDS(X) \
    X(entropy_dry) X(wait_latched) X(timer_raised) X(wfi_stalled)

void snap_machine_put(struct snap_wr *w, const struct rvmachine *m)
{
#define PUT64(f) snap_put64(w, m->f);
#define PUT32(f) snap_put32(w, m->f);
#define PUTB(f) snap_putb(w, m->f);
    MACHINE_U64_FIELDS(PUT64)
    MACHINE_U32_FIELDS(PUT32)
    MACHINE_BOOL_FIELDS(PUTB)
#undef PUT64
#undef PUT32
#undef PUTB
}

/* The saved boot seed address is 0 or a place in RAM that holds a whole seed. */
static bool seed_addr_ok(const struct rvmachine *m)
{
    return m->seed_addr == 0 ||
           (m->seed_addr >= RVMACHINE_RAM_BASE &&
            m->seed_addr - RVMACHINE_RAM_BASE <= m->ram_bytes - RVMACHINE_BOOT_SEED_BYTES);
}

bool snap_machine_get(struct snap_rd *r, struct rvmachine *m)
{
#define GET64(f) m->f = snap_get64(r);
#define GET32(f) m->f = snap_get32(r);
#define GETB(f) m->f = snap_getb(r);
    MACHINE_U64_FIELDS(GET64)
    MACHINE_U32_FIELDS(GET32)
    MACHINE_BOOL_FIELDS(GETB)
#undef GET64
#undef GET32
#undef GETB
    m->loaded = true;
    m->halted = false;
    return !r->bad && m->storm_steps <= RVMACHINE_TRAP_STORM && seed_addr_ok(m) &&
           m->image_end >= RVMACHINE_KERNEL_BASE &&
           m->image_end - RVMACHINE_RAM_BASE <= m->ram_bytes;
}

enum rvmachine_snapshot_status snap_machine_check(const struct rvmachine *m)
{
    if (!m->loaded || m->halted || m->entropy_fault || m->conport_fault)
        return RVMACHINE_SNAPSHOT_ERR_NOT_RUNNABLE;
    if (m->conport_count != 0u) return RVMACHINE_SNAPSHOT_ERR_BYTE_PORTS;
    if (m->cleanse_on_destroy || !rvmachine_public_export_allowed(m))
        return RVMACHINE_SNAPSHOT_ERR_PRIVATE;
    if ((m->disk != NULL && m->disk->write != NULL) || m->data_disk != NULL)
        return RVMACHINE_SNAPSHOT_ERR_DISK_RETAINED;
    if (m->seed_addr != 0u && !rvmachine_boot_seed_cleared(m))
        return RVMACHINE_SNAPSHOT_ERR_SEED_LIVE;
    return RVMACHINE_SNAPSHOT_OK;
}

/* ---- virtio devices: the slot table ---- */

#define QUEUE_COUNT_BOUND (RVVIRTIO_QUEUES_MAX)

static void dev_put(struct snap_wr *w, const struct rvvirtio_dev *d)
{
    snap_put32(w, d->device_id);
    snap_put64(w, d->device_features);
    snap_put32(w, d->nqueues);
    snap_put32(w, d->config_len);
    snap_putn(w, d->config, sizeof d->config);
    snap_put32(w, d->status);
    snap_put64(w, d->driver_features);
    snap_put32(w, d->device_features_sel);
    snap_put32(w, d->driver_features_sel);
    snap_put32(w, d->queue_sel);
    snap_put32(w, d->interrupt_status);
    snap_put32(w, d->config_generation);
    snap_putb(w, d->irq_level);
    for (unsigned i = 0; i < QUEUE_COUNT_BOUND; i++) {
        const struct rvvirtio_queue *q = &d->queues[i];
        snap_put64(w, q->desc);
        snap_put64(w, q->driver);
        snap_put64(w, q->device);
        snap_put32(w, q->num);
        snap_putb(w, q->ready);
        snap_put32(w, q->last_avail);
        snap_put32(w, q->used_idx);
    }
}

static bool dev_identity_get(struct snap_rd *r, const struct rvvirtio_dev *d)
{
    uint8_t config[RVVIRTIO_CONFIG_MAX];
    uint32_t id = snap_get32(r);
    uint64_t features = snap_get64(r);
    uint32_t nqueues = snap_get32(r);
    uint32_t config_len = snap_get32(r);
    snap_getn(r, config, sizeof config);
    return !r->bad && id == d->device_id && features == d->device_features &&
           nqueues == d->nqueues && config_len == d->config_len &&
           memcmp(config, d->config, sizeof config) == 0;
}

static bool queue_get(struct snap_rd *r, struct rvvirtio_queue *q)
{
    q->desc = snap_get64(r);
    q->driver = snap_get64(r);
    q->device = snap_get64(r);
    q->num = snap_get32(r);
    q->ready = snap_getb(r);
    uint32_t last = snap_get32(r);
    uint32_t used = snap_get32(r);
    q->last_avail = (uint16_t)last;
    q->used_idx = (uint16_t)used;
    return !r->bad && q->num <= RVVIRTIO_QUEUE_MAX && last <= UINT16_MAX &&
           used <= UINT16_MAX && (!q->ready || rvvirtio_queue_valid(q));
}

static bool dev_get(struct snap_rd *r, struct rvvirtio_dev *d)
{
    if (!dev_identity_get(r, d)) return false;
    d->status = snap_get32(r);
    d->driver_features = snap_get64(r);
    d->device_features_sel = snap_get32(r);
    d->driver_features_sel = snap_get32(r);
    d->queue_sel = snap_get32(r);
    d->interrupt_status = snap_get32(r);
    d->config_generation = snap_get32(r);
    d->irq_level = snap_getb(r);
    for (unsigned i = 0; i < QUEUE_COUNT_BOUND; i++)
        if (!queue_get(r, &d->queues[i])) return false;
    return !r->bad;
}

/* The next u32 without consuming it. */
static uint32_t snap_peek32(struct snap_rd *r)
{
    if (r->bad || r->n - r->pos < 4u) {
        r->bad = true;
        return 0;
    }
    return zcl_read_u32_le(r->p + r->pos);
}

enum snap_slot_kind snap_slot_kind_of(const struct rvmachine *m, unsigned slot)
{
    if (slot == RVMACHINE_VIRTIO_SLOT_DISK && m->disk != NULL) return SNAP_SLOT_BLOCK;
    if (slot == RVMACHINE_VIRTIO_SLOT_ENTROPY && m->entropy != NULL) return SNAP_SLOT_ENTROPY;
    return SNAP_SLOT_EMPTY;
}

static void blk_put(struct snap_wr *w, const struct rvvirtio_blk *b)
{
    dev_put(w, &b->dev);
    snap_putb(w, b->pending);
    snap_putb(w, b->read_only);
    snap_put64(w, b->capacity_sectors);
}

static bool blk_get(struct snap_rd *r, struct rvvirtio_blk *b)
{
    if (!dev_get(r, &b->dev)) return false;
    b->pending = snap_getb(r);
    bool read_only = snap_getb(r);
    uint64_t sectors = snap_get64(r);
    return !r->bad && read_only == b->read_only && sectors == b->capacity_sectors;
}

static void rng_put(struct snap_wr *w, const struct rvvirtio_rng *g)
{
    dev_put(w, &g->dev);
    snap_putb(w, g->pending);
    snap_put64(w, g->counters.requests);
    snap_put64(w, g->counters.bytes);
    snap_put64(w, g->counters.empty_fills);
    snap_put64(w, g->counters.malformed);
}

static bool rng_get(struct snap_rd *r, struct rvvirtio_rng *g)
{
    if (!dev_get(r, &g->dev)) return false;
    g->pending = snap_getb(r);
    g->counters.requests = snap_get64(r);
    g->counters.bytes = snap_get64(r);
    g->counters.empty_fills = snap_get64(r);
    g->counters.malformed = snap_get64(r);
    return !r->bad;
}

void snap_slots_put(struct snap_wr *w, const struct rvmachine *m)
{
    for (unsigned slot = 0; slot < RVMACHINE_VIRTIO_SLOTS; slot++) {
        enum snap_slot_kind kind = snap_slot_kind_of(m, slot);
        size_t mark = snap_section_begin(w, (uint32_t)kind);
        if (kind == SNAP_SLOT_BLOCK) blk_put(w, &m->blk);
        if (kind == SNAP_SLOT_ENTROPY) rng_put(w, &m->rng);
        snap_section_end(w, mark);
    }
}

static bool slot_payload_get(struct snap_rd *body, struct rvmachine *m,
                             enum snap_slot_kind kind)
{
    if (kind == SNAP_SLOT_BLOCK) return blk_get(body, &m->blk);
    if (kind == SNAP_SLOT_ENTROPY) return rng_get(body, &m->rng);
    return true;
}

enum rvmachine_snapshot_status snap_slots_get(struct snap_rd *r, struct rvmachine *m)
{
    for (unsigned slot = 0; slot < RVMACHINE_VIRTIO_SLOTS; slot++) {
        struct snap_rd body;
        uint32_t kind = snap_peek32(r);
        if (r->bad) return RVMACHINE_SNAPSHOT_ERR_FORMAT;
        if (kind != SNAP_SLOT_EMPTY && kind != SNAP_SLOT_BLOCK && kind != SNAP_SLOT_ENTROPY)
            return RVMACHINE_SNAPSHOT_ERR_SLOT_UNKNOWN;
        if (kind != (uint32_t)snap_slot_kind_of(m, slot))
            return RVMACHINE_SNAPSHOT_ERR_SLOT_MISMATCH;
        if (!snap_section_open(r, kind, &body)) return RVMACHINE_SNAPSHOT_ERR_FORMAT;
        if (!slot_payload_get(&body, m, (enum snap_slot_kind)kind) ||
            !snap_section_close(r, &body))
            return RVMACHINE_SNAPSHOT_ERR_FORMAT;
    }
    return RVMACHINE_SNAPSHOT_OK;
}
