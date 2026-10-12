/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: snapshot file layout, save and restore.
 *
 * File layout (all integers little-endian; every region starts at a multiple
 * of 4096 bytes except the trailer):
 *   meta          prefix {magic[8] "Z23SNAP\0", version u32, flags u32,
 *                 total_size u64, meta_len u64}, header bindings, then the
 *                 state sections; zero padded to meta_len
 *   page index    page_count x u64 ascending RAM page numbers, zero padded
 *   page data     page_count x 4096 bytes, the non-zero pages in index order
 *   overlay index overlay_count x u64 disk block numbers in write order, padded
 *   overlay data  overlay_count x 4096 bytes
 *   trailer       SHA-256 of every byte before it
 * Restore reads the file once and verifies version, size and trailer on that
 * copy before it reads any state. */
#include "rvmachine_snapshot_priv.h"

#include "base/cleanse.h"
#include "base/safe_alloc.h"
#include "base/serialize_le.h"

#include <string.h>

#define SNAP_IO_CHUNK (UINT32_C(1) << 20)
#define SNAP_OUT_CAP (256u * 1024u)
#define SNAP_INDEX_BATCH 1024u
#define SNAP_RUN_PAGES 256u
#define SNAP_PAGE RVMACHINE_SNAPSHOT_PAGE
#define SNAP_DIGEST RVMACHINE_SNAPSHOT_DIGEST

typedef enum rvmachine_snapshot_status snap_status;

const char *rvmachine_snapshot_status_name(snap_status status)
{
    static const char *const names[] = {
        [RVMACHINE_SNAPSHOT_OK] = "ok",
        [RVMACHINE_SNAPSHOT_ERR_ARG] = "bad argument",
        [RVMACHINE_SNAPSHOT_ERR_IO] = "snapshot input or output failed",
        [RVMACHINE_SNAPSHOT_ERR_NOMEM] = "out of memory",
        [RVMACHINE_SNAPSHOT_ERR_NOT_RUNNABLE] = "machine is not loaded, halted or faulted",
        [RVMACHINE_SNAPSHOT_ERR_PRIVATE] = "private machines are never snapshotted",
        [RVMACHINE_SNAPSHOT_ERR_BYTE_PORTS] = "named byte ports are not captured",
        [RVMACHINE_SNAPSHOT_ERR_DISK_RETAINED] = "a retained writable disk is not captured",
        [RVMACHINE_SNAPSHOT_ERR_SEED_LIVE] = "the boot seed is still in guest memory",
        [RVMACHINE_SNAPSHOT_ERR_ENTROPY_UNDECLARED] = "entropy mode is not declared or inconsistent",
        [RVMACHINE_SNAPSHOT_ERR_BAD_MAGIC] = "not a snapshot",
        [RVMACHINE_SNAPSHOT_ERR_VERSION] = "unsupported snapshot format version",
        [RVMACHINE_SNAPSHOT_ERR_TRUNCATED] = "snapshot is truncated",
        [RVMACHINE_SNAPSHOT_ERR_TRAILER] = "snapshot trailer digest does not match",
        [RVMACHINE_SNAPSHOT_ERR_FORMAT] = "snapshot is malformed",
        [RVMACHINE_SNAPSHOT_ERR_RAM_SIZE] = "snapshot RAM size differs from the configuration",
        [RVMACHINE_SNAPSHOT_ERR_CONFIG] = "snapshot machine configuration differs",
        [RVMACHINE_SNAPSHOT_ERR_SLOT_UNKNOWN] = "snapshot holds an unknown device slot kind",
        [RVMACHINE_SNAPSHOT_ERR_SLOT_MISMATCH] = "snapshot device slots differ from the configuration",
        [RVMACHINE_SNAPSHOT_ERR_KERNEL_HASH] = "snapshot was taken with a different kernel",
        [RVMACHINE_SNAPSHOT_ERR_DISK_BINDING] = "snapshot was taken with a different disk",
        [RVMACHINE_SNAPSHOT_ERR_DISK_NOT_FRESH] = "the disk already holds overlay blocks",
        [RVMACHINE_SNAPSHOT_ERR_ENTROPY_MODE] = "snapshot entropy mode differs from the expected one, or replay was asked of a host-entropy snapshot",
        [RVMACHINE_SNAPSHOT_ERR_FRESH_UNAVAILABLE] = "fresh restore needs a snapshot of a host-entropy device and a host entropy source",
        [RVMACHINE_SNAPSHOT_ERR_MODEL] = "snapshot was taken with a different machine model version",
        [RVMACHINE_SNAPSHOT_ERR_TOO_LARGE] = "snapshot file exceeds the size limit",
    };
    static_assert(sizeof names / sizeof names[0] == RVMACHINE_SNAPSHOT_ERR_TOO_LARGE + 1u,
                  "one name per status");
    size_t i = (size_t)status;
    return i < sizeof names / sizeof names[0] ? names[i] : "unknown";
}

/* Buffers that held guest memory or registers are wiped before release. */
static void free_secret(void *p, size_t n)
{
    if (p == NULL) return;
    memory_cleanse(p, n);
    free(p);
}

static uint64_t align_page(uint64_t v) { return (v + SNAP_PAGE - 1u) & ~(uint64_t)(SNAP_PAGE - 1u); }

/* Region offsets from the meta length and the two counts. */
struct snap_layout {
    uint64_t index_off, data_off, oindex_off, odata_off, total;
};

static struct snap_layout layout_of(uint64_t meta_len, uint64_t pages, uint64_t blocks)
{
    struct snap_layout l;
    l.index_off = meta_len;
    l.data_off = align_page(l.index_off + pages * 8u);
    l.oindex_off = l.data_off + pages * SNAP_PAGE;
    l.odata_off = align_page(l.oindex_off + blocks * 8u);
    l.total = l.odata_off + blocks * SNAP_PAGE + SNAP_DIGEST;
    return l;
}

/* ---- the header fields that follow the prefix ---- */

struct snap_header {
    uint64_t ram_bytes, dtb_addr, dtb_len, retired, guest_time;
    uint64_t page_count, overlay_count, disk_size;
    uint32_t model_version, timebase_hz, ticks_per_time, source_len;
    bool wait_stops, disk_present;
    uint8_t entropy, nslots;
    char bootargs[RVMACHINE_BOOTARGS_MAX];
    uint8_t kernel_sha[SNAP_DIGEST], disk_sha[SNAP_DIGEST];
    uint8_t source_state[RVMACHINE_SNAPSHOT_SOURCE_STATE_MAX];
};

static void header_put(struct snap_wr *w, const struct snap_header *h)
{
    uint32_t blen = (uint32_t)strlen(h->bootargs);
    snap_put32(w, h->model_version);
    snap_put64(w, h->ram_bytes);
    snap_put64(w, h->dtb_addr);
    snap_put64(w, h->dtb_len);
    snap_put32(w, h->timebase_hz);
    snap_put32(w, h->ticks_per_time);
    snap_put8(w, h->wait_stops ? 1u : 0u);
    snap_put8(w, h->disk_present ? 1u : 0u);
    snap_put8(w, h->entropy);
    snap_put8(w, h->nslots);
    snap_put32(w, blen);
    snap_putn(w, h->bootargs, blen);
    snap_putn(w, h->kernel_sha, SNAP_DIGEST);
    snap_put64(w, h->disk_size);
    snap_putn(w, h->disk_sha, SNAP_DIGEST);
    snap_put64(w, h->retired);
    snap_put64(w, h->guest_time);
    snap_put32(w, h->source_len);
    snap_putn(w, h->source_state, h->source_len);
    snap_put64(w, h->page_count);
    snap_put64(w, h->overlay_count);
}

static bool header_get(struct snap_rd *r, struct snap_header *h)
{
    uint32_t blen;
    memset(h, 0, sizeof *h);
    h->model_version = snap_get32(r);
    h->ram_bytes = snap_get64(r);
    h->dtb_addr = snap_get64(r);
    h->dtb_len = snap_get64(r);
    h->timebase_hz = snap_get32(r);
    h->ticks_per_time = snap_get32(r);
    h->wait_stops = snap_getb(r);
    h->disk_present = snap_getb(r);
    h->entropy = snap_get8(r);
    h->nslots = snap_get8(r);
    blen = snap_get32(r);
    if (r->bad || blen >= RVMACHINE_BOOTARGS_MAX) return false;
    snap_getn(r, h->bootargs, blen);
    snap_getn(r, h->kernel_sha, SNAP_DIGEST);
    h->disk_size = snap_get64(r);
    snap_getn(r, h->disk_sha, SNAP_DIGEST);
    h->retired = snap_get64(r);
    h->guest_time = snap_get64(r);
    h->source_len = snap_get32(r);
    if (r->bad || h->source_len > RVMACHINE_SNAPSHOT_SOURCE_STATE_MAX) return false;
    snap_getn(r, h->source_state, h->source_len);
    h->page_count = snap_get64(r);
    h->overlay_count = snap_get64(r);
    return !r->bad;
}

/* ---- save ---- */

struct snap_out {
    const struct rvmachine_snapshot_params *params;
    const struct rvmachine_snapshot_sink *sink;
    uint8_t *buf;
    size_t len;
    bool bad;
};

static void out_flush(struct snap_out *o)
{
    if (o->bad || o->len == 0) return;
    o->params->hash.write(o->params->hash.ctx, o->buf, o->len);
    if (!o->sink->write(o->sink->ctx, o->buf, o->len)) o->bad = true;
    o->len = 0;
}

static void out_put(struct snap_out *o, const void *data, size_t n)
{
    const uint8_t *p = data;
    while (n != 0 && !o->bad) {
        size_t take = SNAP_OUT_CAP - o->len;
        if (take > n) take = n;
        memcpy(o->buf + o->len, p, take);
        o->len += take;
        p += take;
        n -= take;
        if (o->len == SNAP_OUT_CAP) out_flush(o);
    }
}

static void out_zero(struct snap_out *o, size_t n)
{
    static const uint8_t zeros[256];
    while (n != 0 && !o->bad) {
        size_t take = n < sizeof zeros ? n : sizeof zeros;
        out_put(o, zeros, take);
        n -= take;
    }
}

static bool page_zero(const uint8_t *p)
{
    uint64_t acc = 0, v;
    for (size_t i = 0; i < SNAP_PAGE; i += sizeof v) {
        memcpy(&v, p + i, sizeof v);
        acc |= v;
    }
    return acc == 0;
}

/* One bit per RAM page: set when the page holds a non-zero byte. */
static uint8_t *page_map(const struct rvmachine *m, uint64_t *count)
{
    uint64_t pages = m->ram_bytes / SNAP_PAGE;
    uint8_t *map = zcl_calloc((size_t)(pages / 8u + 1u), 1, "snapshot_page_map");
    if (map == NULL) return NULL;
    *count = 0;
    for (uint64_t i = 0; i < pages; i++) {
        if (page_zero(m->mem.bytes + i * SNAP_PAGE)) continue;
        map[i / 8u] |= (uint8_t)(1u << (i % 8u));
        (*count)++;
    }
    return map;
}

static bool map_has(const uint8_t *map, uint64_t i) { return (map[i / 8u] >> (i % 8u) & 1u) != 0; }

/* Disk blocks in overlay (write) order; NULL with *n == 0 when there are none. */
static uint64_t *overlay_order(const struct rvmachine *m, uint64_t *n, bool *nomem)
{
    const struct rvmachine_disk *d = m->disk;
    uint64_t *order;
    *n = d != NULL ? d->used : 0;
    *nomem = false;
    if (*n == 0) return NULL;
    order = zcl_calloc((size_t)*n, sizeof *order, "snapshot_overlay_order");
    if (order == NULL) {
        *nomem = true;
        return NULL;
    }
    for (uint64_t b = 0; b < d->nblocks; b++)
        if (d->slot[b] != 0) order[d->slot[b] - 1u] = b;
    return order;
}

static void header_fill(struct snap_header *h, const struct rvmachine *m,
                        const struct rvmachine_snapshot_params *p)
{
    memset(h, 0, sizeof *h);
    h->model_version = RVMACHINE_MODEL_VERSION;
    h->ram_bytes = m->ram_bytes;
    h->dtb_addr = m->dtb_addr;
    h->dtb_len = m->dtb_len;
    h->timebase_hz = RVMACHINE_TIMEBASE_HZ;
    h->ticks_per_time = RVMACHINE_TICKS_PER_TIME;
    h->wait_stops = m->wait_stops;
    h->disk_present = m->disk != NULL;
    h->entropy = (uint8_t)p->entropy;
    h->nslots = RVMACHINE_VIRTIO_SLOTS;
    memcpy(h->bootargs, m->bootargs, sizeof h->bootargs);
    memcpy(h->kernel_sha, p->kernel_sha256, SNAP_DIGEST);
    h->disk_size = rvmachine_disk_size(m->disk);
    if (m->disk != NULL) memcpy(h->disk_sha, p->disk_sha256, SNAP_DIGEST);
    h->retired = machine_retired(m);
    h->guest_time = machine_now(m);
    h->source_len = p->source_state_len;
    memcpy(h->source_state, p->source_state, p->source_state_len);
}

/* Builds the meta block into w; its length is rounded up to a page. */
static void meta_build(struct snap_wr *w, const struct snap_header *h, const struct rvmachine *m)
{
    uint8_t prefix[SNAP_PREFIX] = SNAP_MAGIC;
    size_t mark;
    snap_putn(w, prefix, sizeof prefix);
    header_put(w, h);
#define SECTION(tag, call) mark = snap_section_begin(w, tag); call; snap_section_end(w, mark);
    SECTION(SNAP_TAG_MACHINE, snap_machine_put(w, m))
    SECTION(SNAP_TAG_HART, snap_hart_put(w, &m->hart))
    SECTION(SNAP_TAG_PLIC, snap_plic_put(w, &m->plic))
    SECTION(SNAP_TAG_TIMER, snap_timer_put(w, &m->timer))
    SECTION(SNAP_TAG_UART, snap_uart_put(w, &m->uart))
    SECTION(SNAP_TAG_SBI, snap_sbi_put(w, &m->sbi))
    SECTION(SNAP_TAG_FWIN, snap_input_put(w, &m->firmware_in))
    SECTION(SNAP_TAG_SERIN, snap_input_put(w, &m->serial_in))
    SECTION(SNAP_TAG_SLOTS, snap_slots_put(w, m))
#undef SECTION
}

/* Rounds the block to a page and writes the total and meta length into the
 * prefix; returns the padded length, or 0 when it does not fit. */
static size_t meta_seal(struct snap_wr *w, uint64_t pages, uint64_t blocks)
{
    size_t padded = (size_t)align_page(w->pos);
    if (w->bad || padded > w->cap) return 0;
    memset(w->p + w->pos, 0, padded - w->pos);
    memcpy(w->p, SNAP_MAGIC, sizeof SNAP_MAGIC);
    zcl_write_u32_le(w->p + 8, RVMACHINE_SNAPSHOT_VERSION);
    zcl_write_u32_le(w->p + 12, 0);
    zcl_write_u64_le(w->p + 16, layout_of(padded, pages, blocks).total);
    zcl_write_u64_le(w->p + 24, padded);
    return padded;
}

static snap_status entropy_check(const struct rvmachine *m,
                                 const struct rvmachine_snapshot_params *p)
{
    bool source = m->entropy != NULL || m->boot_seed != NULL;
    if (p->entropy < RVMACHINE_SNAPSHOT_ENTROPY_NONE ||
        p->entropy > RVMACHINE_SNAPSHOT_ENTROPY_HOST)
        return RVMACHINE_SNAPSHOT_ERR_ENTROPY_UNDECLARED;
    if ((p->entropy == RVMACHINE_SNAPSHOT_ENTROPY_NONE) == source)
        return RVMACHINE_SNAPSHOT_ERR_ENTROPY_UNDECLARED;
    if (p->source_state_len > RVMACHINE_SNAPSHOT_SOURCE_STATE_MAX ||
        (p->source_state_len != 0 && p->entropy != RVMACHINE_SNAPSHOT_ENTROPY_TEST_STREAM))
        return RVMACHINE_SNAPSHOT_ERR_ARG;
    return RVMACHINE_SNAPSHOT_OK;
}

static snap_status save_checks(const struct rvmachine *m,
                               const struct rvmachine_snapshot_params *p,
                               const struct rvmachine_snapshot_sink *sink)
{
    if (m == NULL || p == NULL || sink == NULL || sink->write == NULL ||
        p->hash.begin == NULL || p->hash.write == NULL || p->hash.finish == NULL)
        return RVMACHINE_SNAPSHOT_ERR_ARG;
    snap_status st = snap_machine_check(m);
    return st != RVMACHINE_SNAPSHOT_OK ? st : entropy_check(m, p);
}

static void emit_pages(struct snap_out *o, const struct rvmachine *m, const uint8_t *map,
                       uint64_t index_bytes_pad)
{
    uint64_t pages = m->ram_bytes / SNAP_PAGE;
    uint8_t b[8];
    for (uint64_t i = 0; i < pages; i++) {
        if (!map_has(map, i)) continue;
        zcl_write_u64_le(b, i);
        out_put(o, b, sizeof b);
    }
    out_zero(o, (size_t)index_bytes_pad);
    for (uint64_t i = 0; i < pages; i++)
        if (map_has(map, i)) out_put(o, m->mem.bytes + i * SNAP_PAGE, SNAP_PAGE);
}

static void emit_overlay(struct snap_out *o, const struct rvmachine *m, const uint64_t *order,
                         uint64_t n)
{
    uint8_t b[8];
    for (uint64_t i = 0; i < n; i++) {
        zcl_write_u64_le(b, order[i]);
        out_put(o, b, sizeof b);
    }
    out_zero(o, (size_t)(align_page(n * 8u) - n * 8u));
    for (uint64_t i = 0; i < n; i++)
        out_put(o, m->disk->overlay[i], SNAP_PAGE);
}

struct snap_plan {
    uint8_t *meta, *map;
    uint64_t *order;
    uint64_t pages, blocks;
    size_t meta_len;
};

static void plan_free(struct snap_plan *pl)
{
    free_secret(pl->meta, SNAP_META_MAX);
    free(pl->map);
    free(pl->order);
}

static snap_status plan_make(struct snap_plan *pl, const struct rvmachine *m,
                             const struct rvmachine_snapshot_params *p)
{
    struct snap_header h;
    bool nomem;
    struct snap_wr w = {.cap = SNAP_META_MAX};
    memset(pl, 0, sizeof *pl);
    pl->map = page_map(m, &pl->pages);
    pl->order = overlay_order(m, &pl->blocks, &nomem);
    pl->meta = zcl_malloc(SNAP_META_MAX, "snapshot_meta");
    if (pl->map == NULL || nomem || pl->meta == NULL) return RVMACHINE_SNAPSHOT_ERR_NOMEM;
    w.p = pl->meta;
    header_fill(&h, m, p);
    h.page_count = pl->pages;
    h.overlay_count = pl->blocks;
    meta_build(&w, &h, m);
    pl->meta_len = meta_seal(&w, pl->pages, pl->blocks);
    return pl->meta_len != 0 ? RVMACHINE_SNAPSHOT_OK : RVMACHINE_SNAPSHOT_ERR_FORMAT;
}

static snap_status plan_emit(const struct snap_plan *pl, const struct rvmachine *m,
                             const struct rvmachine_snapshot_params *p,
                             const struct rvmachine_snapshot_sink *sink,
                             struct rvmachine_snapshot_info *info)
{
    struct snap_out o = {.params = p, .sink = sink};
    uint8_t digest[SNAP_DIGEST];
    o.buf = zcl_malloc(SNAP_OUT_CAP, "snapshot_out");
    if (o.buf == NULL) return RVMACHINE_SNAPSHOT_ERR_NOMEM;
    p->hash.begin(p->hash.ctx);
    out_put(&o, pl->meta, pl->meta_len);
    emit_pages(&o, m, pl->map, align_page(pl->pages * 8u) - pl->pages * 8u);
    emit_overlay(&o, m, pl->order, pl->blocks);
    out_flush(&o);
    p->hash.finish(p->hash.ctx, digest);
    if (!o.bad && !sink->write(sink->ctx, digest, sizeof digest)) o.bad = true;
    free_secret(o.buf, SNAP_OUT_CAP);
    if (o.bad) return RVMACHINE_SNAPSHOT_ERR_IO;
    memcpy(info->digest, digest, sizeof digest);
    info->file_size = layout_of(pl->meta_len, pl->pages, pl->blocks).total;
    return RVMACHINE_SNAPSHOT_OK;
}

snap_status rvmachine_snapshot_save(const struct rvmachine *m,
                                    const struct rvmachine_snapshot_params *params,
                                    const struct rvmachine_snapshot_sink *sink,
                                    struct rvmachine_snapshot_info *info)
{
    struct rvmachine_snapshot_info local;
    struct snap_plan pl;
    snap_status st = save_checks(m, params, sink);
    if (st != RVMACHINE_SNAPSHOT_OK) return st;
    if (info == NULL) info = &local;
    memset(info, 0, sizeof *info);
    st = plan_make(&pl, m, params);
    if (st == RVMACHINE_SNAPSHOT_OK) st = plan_emit(&pl, m, params, sink, info);
    if (st == RVMACHINE_SNAPSHOT_OK) {
        info->retired = machine_retired(m);
        info->guest_time = machine_now(m);
        info->pages = pl.pages;
        info->overlay_blocks = pl.blocks;
        info->entropy = params->entropy;
        info->source_state_len = params->source_state_len;
        memcpy(info->source_state, params->source_state, params->source_state_len);
    }
    plan_free(&pl);
    return st;
}

/* ---- restore ---- */

static bool read_exact(const struct rvmachine_snapshot_source *s, uint64_t off, void *buf,
                       size_t n)
{
    return n == 0 || (off <= s->size && n <= s->size - off && s->read(s->ctx, off, buf, n));
}

/* The prefix: magic, version, flags, sizes. */
static snap_status prefix_check(const struct rvmachine_snapshot_source *s, uint64_t *meta_len)
{
    uint8_t p[SNAP_PREFIX];
    if (s->size < SNAP_PREFIX) return RVMACHINE_SNAPSHOT_ERR_TRUNCATED;
    if (!read_exact(s, 0, p, sizeof p)) return RVMACHINE_SNAPSHOT_ERR_IO;
    if (memcmp(p, SNAP_MAGIC, sizeof SNAP_MAGIC) != 0) return RVMACHINE_SNAPSHOT_ERR_BAD_MAGIC;
    if (zcl_read_u32_le(p + 8) != RVMACHINE_SNAPSHOT_VERSION)
        return RVMACHINE_SNAPSHOT_ERR_VERSION;
    uint64_t total = zcl_read_u64_le(p + 16);
    *meta_len = zcl_read_u64_le(p + 24);
    if (zcl_read_u32_le(p + 12) != 0 || total <= SNAP_PREFIX + SNAP_DIGEST)
        return RVMACHINE_SNAPSHOT_ERR_FORMAT;
    if (total > s->size) return RVMACHINE_SNAPSHOT_ERR_TRUNCATED;
    if (total != s->size || *meta_len % SNAP_PAGE != 0 || *meta_len == 0 ||
        *meta_len > SNAP_META_MAX || *meta_len > total - SNAP_DIGEST)
        return RVMACHINE_SNAPSHOT_ERR_FORMAT;
    return RVMACHINE_SNAPSHOT_OK;
}

/* Hashes every byte before the trailer and compares. */
static snap_status trailer_check(const struct rvmachine_snapshot_source *s,
                                 const struct rvmachine_snapshot_params *p, uint8_t *digest)
{
    uint8_t want[SNAP_DIGEST];
    uint8_t *buf = zcl_malloc(SNAP_IO_CHUNK, "snapshot_hash");
    uint64_t off = 0, end = s->size - SNAP_DIGEST;
    snap_status st = RVMACHINE_SNAPSHOT_OK;
    if (buf == NULL) return RVMACHINE_SNAPSHOT_ERR_NOMEM;
    p->hash.begin(p->hash.ctx);
    while (off < end && st == RVMACHINE_SNAPSHOT_OK) {
        size_t n = end - off < SNAP_IO_CHUNK ? (size_t)(end - off) : SNAP_IO_CHUNK;
        if (!read_exact(s, off, buf, n)) st = RVMACHINE_SNAPSHOT_ERR_IO;
        else p->hash.write(p->hash.ctx, buf, n);
        off += n;
    }
    free_secret(buf, SNAP_IO_CHUNK);
    p->hash.finish(p->hash.ctx, digest);
    if (st != RVMACHINE_SNAPSHOT_OK) return st;
    if (!read_exact(s, end, want, sizeof want)) return RVMACHINE_SNAPSHOT_ERR_IO;
    return memcmp(want, digest, SNAP_DIGEST) == 0 ? RVMACHINE_SNAPSHOT_OK
                                                  : RVMACHINE_SNAPSHOT_ERR_TRAILER;
}

static uint64_t config_ram(const struct rvmachine_config *c)
{
    return c->ram_bytes != 0 ? c->ram_bytes : RVMACHINE_RAM_DEFAULT;
}

static snap_status bind_machine(const struct snap_header *h, const struct rvmachine_config *c)
{
    const char *args = c->bootargs != NULL ? c->bootargs : "";
    if (h->model_version != RVMACHINE_MODEL_VERSION) return RVMACHINE_SNAPSHOT_ERR_MODEL;
    if (h->ram_bytes != config_ram(c)) return RVMACHINE_SNAPSHOT_ERR_RAM_SIZE;
    if (h->timebase_hz != RVMACHINE_TIMEBASE_HZ || h->ticks_per_time != RVMACHINE_TICKS_PER_TIME ||
        h->wait_stops != c->wait_stops || strcmp(h->bootargs, args) != 0)
        return RVMACHINE_SNAPSHOT_ERR_CONFIG;
    if (h->nslots != RVMACHINE_VIRTIO_SLOTS || c->conport_count != 0u)
        return RVMACHINE_SNAPSHOT_ERR_SLOT_MISMATCH;
    return RVMACHINE_SNAPSHOT_OK;
}

static snap_status bind_images(const struct snap_header *h, const struct rvmachine_config *c,
                               const struct rvmachine_snapshot_params *p)
{
    if (memcmp(h->kernel_sha, p->kernel_sha256, SNAP_DIGEST) != 0)
        return RVMACHINE_SNAPSHOT_ERR_KERNEL_HASH;
    if (h->disk_present != (c->disk != NULL)) return RVMACHINE_SNAPSHOT_ERR_DISK_BINDING;
    if (c->disk == NULL) return RVMACHINE_SNAPSHOT_OK;
    if (h->disk_size != rvmachine_disk_size(c->disk) ||
        (p->disk_hash_known && memcmp(h->disk_sha, p->disk_sha256, SNAP_DIGEST) != 0))
        return RVMACHINE_SNAPSHOT_ERR_DISK_BINDING;
    return rvmachine_disk_overlay_blocks(c->disk) == 0 ? RVMACHINE_SNAPSHOT_OK
                                                      : RVMACHINE_SNAPSHOT_ERR_DISK_NOT_FRESH;
}

static snap_status bind_entropy(const struct snap_header *h, const struct rvmachine_snapshot_params *p)
{
    if (h->entropy < RVMACHINE_SNAPSHOT_ENTROPY_NONE || h->entropy > RVMACHINE_SNAPSHOT_ENTROPY_HOST)
        return RVMACHINE_SNAPSHOT_ERR_FORMAT;
    if (p->entropy != RVMACHINE_SNAPSHOT_ENTROPY_UNDECLARED && p->entropy != h->entropy)
        return RVMACHINE_SNAPSHOT_ERR_ENTROPY_MODE;
    return RVMACHINE_SNAPSHOT_OK;
}

/* Every check that needs only the header and the configuration. */
static snap_status bind_header(const struct snap_header *h, const struct rvmachine_config *c,
                               const struct rvmachine_snapshot_params *p, uint64_t meta_len,
                               uint64_t total)
{
    snap_status st = bind_machine(h, c);
    if (st == RVMACHINE_SNAPSHOT_OK) st = bind_images(h, c, p);
    if (st == RVMACHINE_SNAPSHOT_OK) st = bind_entropy(h, p);
    if (st != RVMACHINE_SNAPSHOT_OK) return st;
    if (h->page_count > h->ram_bytes / SNAP_PAGE || h->overlay_count > RVMACHINE_DISK_OVERLAY_BLOCKS ||
        (h->overlay_count != 0 && !h->disk_present) ||
        layout_of(meta_len, h->page_count, h->overlay_count).total != total)
        return RVMACHINE_SNAPSHOT_ERR_FORMAT;
    return RVMACHINE_SNAPSHOT_OK;
}

/* Hooks the host side of a freshly created machine: the callbacks the load
 * path binds, the timer and the firmware handler. */
static void bind_host(struct rvmachine *m)
{
    rvplat_timer_init(&m->timer, RVMACHINE_TICKS_PER_TIME);
    rvplat_sbi_init(&m->sbi);
    m->sbi.getchar = rvmachine_sbi_getchar;
    m->sbi.ctx = m;
    m->mem.io_ctx = m;
    m->mem.io_load = rvmachine_io_load;
    m->mem.io_store = rvmachine_io_store;
}

/* The single place restore drops everything derived from the saved state. */
static void invalidate_derived_state(struct rvmachine *m)
{
    rvmachine_invalidate_derived(m);
}

static bool sections_core(struct snap_rd *r, struct rvmachine *m)
{
    struct snap_rd b;
    return snap_section_open(r, SNAP_TAG_MACHINE, &b) && snap_machine_get(&b, m) &&
           snap_section_close(r, &b) &&
           snap_section_open(r, SNAP_TAG_HART, &b) && snap_hart_get(&b, &m->hart) &&
           snap_section_close(r, &b) &&
           snap_section_open(r, SNAP_TAG_PLIC, &b) && snap_plic_get(&b, &m->plic) &&
           snap_section_close(r, &b);
}

static bool sections_io(struct snap_rd *r, struct rvmachine *m)
{
    struct snap_rd b;
    return snap_section_open(r, SNAP_TAG_TIMER, &b) && snap_timer_get(&b, &m->timer) &&
           snap_section_close(r, &b) &&
           snap_section_open(r, SNAP_TAG_UART, &b) && snap_uart_get(&b, &m->uart) &&
           snap_section_close(r, &b) &&
           snap_section_open(r, SNAP_TAG_SBI, &b) && snap_sbi_get(&b, &m->sbi) &&
           snap_section_close(r, &b);
}

static bool sections_input(struct snap_rd *r, struct rvmachine *m)
{
    struct snap_rd b;
    return snap_section_open(r, SNAP_TAG_FWIN, &b) && snap_input_get(&b, &m->firmware_in) &&
           snap_section_close(r, &b) &&
           snap_section_open(r, SNAP_TAG_SERIN, &b) && snap_input_get(&b, &m->serial_in) &&
           snap_section_close(r, &b);
}

static snap_status sections_get(struct snap_rd *r, struct rvmachine *m)
{
    struct snap_rd b;
    if (!sections_core(r, m) || !sections_io(r, m) || !sections_input(r, m))
        return RVMACHINE_SNAPSHOT_ERR_FORMAT;
    if (!snap_section_open(r, SNAP_TAG_SLOTS, &b)) return RVMACHINE_SNAPSHOT_ERR_FORMAT;
    snap_status st = snap_slots_get(&b, m);
    if (st == RVMACHINE_SNAPSHOT_OK && !snap_section_close(r, &b)) st = RVMACHINE_SNAPSHOT_ERR_FORMAT;
    return st;
}

/* RAM pages: ascending indexes, read in runs straight into guest memory. */
static snap_status pages_apply(struct rvmachine *m, const struct rvmachine_snapshot_source *s,
                               const struct snap_layout *l, uint64_t count)
{
    uint8_t raw[SNAP_INDEX_BATCH * 8u];
    uint64_t ram_pages = m->ram_bytes / SNAP_PAGE, prev = 0, done = 0;
    while (done < count) {
        uint64_t idx[SNAP_INDEX_BATCH];
        size_t k = count - done < SNAP_INDEX_BATCH ? (size_t)(count - done) : SNAP_INDEX_BATCH;
        if (!read_exact(s, l->index_off + done * 8u, raw, k * 8u)) return RVMACHINE_SNAPSHOT_ERR_IO;
        for (size_t j = 0; j < k; j++) {
            idx[j] = zcl_read_u64_le(raw + j * 8u);
            if (idx[j] >= ram_pages || (done + j != 0 && idx[j] <= prev))
                return RVMACHINE_SNAPSHOT_ERR_FORMAT;
            prev = idx[j];
        }
        for (size_t j = 0; j < k;) {
            size_t run = 1;
            while (j + run < k && run < SNAP_RUN_PAGES && idx[j + run] == idx[j] + run) run++;
            if (!read_exact(s, l->data_off + (done + j) * SNAP_PAGE,
                            m->mem.bytes + idx[j] * SNAP_PAGE, run * SNAP_PAGE))
                return RVMACHINE_SNAPSHOT_ERR_IO;
            j += run;
        }
        done += k;
    }
    return RVMACHINE_SNAPSHOT_OK;
}

/* Overlay blocks go through the disk's own write path, in write order. */
static snap_status overlay_apply(struct rvmachine *m, const struct rvmachine_snapshot_source *s,
                                 const struct snap_layout *l, uint64_t count)
{
    uint8_t block[SNAP_PAGE], raw[8];
    struct rvmachine_disk *d = m->disk;
    for (uint64_t i = 0; i < count; i++) {
        if (!read_exact(s, l->oindex_off + i * 8u, raw, sizeof raw))
            return RVMACHINE_SNAPSHOT_ERR_IO;
        uint64_t b = zcl_read_u64_le(raw);
        if (b >= d->nblocks || d->slot[b] != 0) return RVMACHINE_SNAPSHOT_ERR_FORMAT;
        if (!read_exact(s, l->odata_off + i * SNAP_PAGE, block, sizeof block))
            return RVMACHINE_SNAPSHOT_ERR_IO;
        uint64_t off = b * SNAP_PAGE, left = d->size - off;
        size_t n = left < SNAP_PAGE ? (size_t)left : SNAP_PAGE;
        if (!rvmachine_disk_write(d, off, block, n)) return RVMACHINE_SNAPSHOT_ERR_IO;
    }
    return RVMACHINE_SNAPSHOT_OK;
}

/* The tree rvmachine_create wrote is replaced by the saved pages. */
static void tree_clear(struct rvmachine *m)
{
    uint64_t first = (m->dtb_addr - RVMACHINE_RAM_BASE) / SNAP_PAGE * SNAP_PAGE;
    memset(m->mem.bytes + first, 0, (size_t)align_page(m->dtb_addr - RVMACHINE_RAM_BASE + m->dtb_len - first));
}

static snap_status build_machine(struct rvmachine **out, const struct rvmachine_config *c,
                                 const struct snap_header *h)
{
    enum rvmachine_status st = rvmachine_create(out, c);
    if (st != RVMACHINE_OK)
        return st == RVMACHINE_ERR_NOMEM ? RVMACHINE_SNAPSHOT_ERR_NOMEM : RVMACHINE_SNAPSHOT_ERR_CONFIG;
    if ((*out)->dtb_addr != h->dtb_addr || (*out)->dtb_len != h->dtb_len) {
        (*out)->disk = NULL;
        rvmachine_destroy(*out);
        *out = NULL;
        return RVMACHINE_SNAPSHOT_ERR_CONFIG;
    }
    return RVMACHINE_SNAPSHOT_OK;
}

static snap_status fill_machine(struct rvmachine *m, const struct rvmachine_snapshot_source *s,
                                const struct snap_header *h, struct snap_rd *rd,
                                const struct snap_layout *l)
{
    bind_host(m);
    snap_status st = sections_get(rd, m);
    if (st != RVMACHINE_SNAPSHOT_OK) return st;
    tree_clear(m);
    st = pages_apply(m, s, l, h->page_count);
    if (st == RVMACHINE_SNAPSHOT_OK) st = overlay_apply(m, s, l, h->overlay_count);
    if (st == RVMACHINE_SNAPSHOT_OK) invalidate_derived_state(m);
    return st;
}

static void info_fill(struct rvmachine_snapshot_info *info, const struct snap_header *h,
                      const struct rvmachine_snapshot_params *p, const uint8_t *digest,
                      uint64_t size, enum rvmachine_snapshot_mode mode)
{
    memset(info, 0, sizeof *info);
    memcpy(info->digest, digest, SNAP_DIGEST);
    info->file_size = size;
    info->retired = h->retired;
    info->guest_time = h->guest_time;
    info->pages = h->page_count;
    info->overlay_blocks = h->overlay_count;
    info->entropy = (enum rvmachine_snapshot_entropy)h->entropy;
    info->source_state_len = h->source_len;
    memcpy(info->source_state, h->source_state, h->source_len);
    info->disk_hash_checked = h->disk_present && p->disk_hash_known;
    info->mode = mode;
}

/* The prefix, the trailer and the header fields; rd continues at the first
 * state section. meta must hold SNAP_META_MAX bytes. */
static snap_status source_header(const struct rvmachine_snapshot_source *s,
                                 const struct rvmachine_snapshot_params *p, uint8_t *meta,
                                 uint8_t *digest, struct snap_header *h, struct snap_rd *rd,
                                 uint64_t *meta_len)
{
    snap_status st = prefix_check(s, meta_len);
    if (st == RVMACHINE_SNAPSHOT_OK) st = trailer_check(s, p, digest);
    if (st != RVMACHINE_SNAPSHOT_OK) return st;
    if (!read_exact(s, 0, meta, (size_t)*meta_len)) return RVMACHINE_SNAPSHOT_ERR_IO;
    *rd = (struct snap_rd){.p = meta, .n = (size_t)*meta_len, .pos = SNAP_PREFIX};
    return header_get(rd, h) ? RVMACHINE_SNAPSHOT_OK : RVMACHINE_SNAPSHOT_ERR_FORMAT;
}

/* Everything that precedes the machine: the header and its bindings. */
static snap_status verify_source(const struct rvmachine_snapshot_source *s,
                                 const struct rvmachine_config *c,
                                 const struct rvmachine_snapshot_params *p, uint8_t *meta,
                                 uint8_t *digest, struct snap_header *h, struct snap_rd *rd,
                                 struct snap_layout *l)
{
    uint64_t meta_len;
    snap_status st = source_header(s, p, meta, digest, h, rd, &meta_len);
    if (st != RVMACHINE_SNAPSHOT_OK) return st;
    st = bind_header(h, c, p, meta_len, s->size);
    *l = layout_of(meta_len, h->page_count, h->overlay_count);
    return st;
}

static bool restore_args_ok(struct rvmachine **out, const struct rvmachine_config *c,
                            const struct rvmachine_snapshot_params *p,
                            const struct rvmachine_snapshot_source *s)
{
    return out != NULL && c != NULL && p != NULL && s != NULL && s->read != NULL &&
           p->hash.begin != NULL && p->hash.write != NULL && p->hash.finish != NULL;
}

/* A snapshot that drew on host entropy continues with new host bytes, so it is
 * never a bit-exact replay; FRESH needs that host source to be present. */
static snap_status mode_check(enum rvmachine_snapshot_mode mode, const struct snap_header *h,
                              const struct rvmachine_config *c)
{
    bool host = h->entropy == RVMACHINE_SNAPSHOT_ENTROPY_HOST;
    if (mode == RVMACHINE_SNAPSHOT_REPLAY) return host ? RVMACHINE_SNAPSHOT_ERR_ENTROPY_MODE : RVMACHINE_SNAPSHOT_OK;
    return host && c->entropy != NULL ? RVMACHINE_SNAPSHOT_OK : RVMACHINE_SNAPSHOT_ERR_FRESH_UNAVAILABLE;
}

static snap_status restore_buffered(struct rvmachine **out, const struct rvmachine_config *config,
                                    const struct rvmachine_snapshot_params *params,
                                    enum rvmachine_snapshot_mode mode,
                                    const struct rvmachine_snapshot_source *source,
                                    struct rvmachine_snapshot_info *info)
{
    struct rvmachine_snapshot_info local;
    struct snap_header h;
    struct snap_layout l;
    struct snap_rd rd;
    uint8_t digest[SNAP_DIGEST];
    struct rvmachine *m = NULL;
    uint8_t *meta;
    if (info == NULL) info = &local;
    meta = zcl_malloc(SNAP_META_MAX, "snapshot_meta");
    if (meta == NULL) return RVMACHINE_SNAPSHOT_ERR_NOMEM;
    snap_status st = verify_source(source, config, params, meta, digest, &h, &rd, &l);
    if (st == RVMACHINE_SNAPSHOT_OK) st = mode_check(mode, &h, config);
    if (st == RVMACHINE_SNAPSHOT_OK) st = build_machine(&m, config, &h);
    if (st == RVMACHINE_SNAPSHOT_OK) {
        st = fill_machine(m, source, &h, &rd, &l);
        if (st != RVMACHINE_SNAPSHOT_OK) {
            m->disk = NULL; /* still the caller's */
            rvmachine_destroy(m);
            m = NULL;
        }
    }
    free_secret(meta, SNAP_META_MAX);
    if (st == RVMACHINE_SNAPSHOT_OK) {
        info_fill(info, &h, params, digest, source->size, mode);
        *out = m;
    }
    return st;
}

struct snap_mem {
    uint8_t *p;
    uint64_t n;
};

static bool snap_mem_read(void *ctx, uint64_t off, void *buf, size_t n)
{
    const struct snap_mem *m = ctx;
    if (off > m->n || n > m->n - off) return false;
    memcpy(buf, m->p + off, n);
    return true;
}

/* Reads the whole source exactly once. Every later check and every byte of
 * state comes from this one copy, so what is verified is what is used. */
static snap_status source_load(const struct rvmachine_snapshot_source *s, struct snap_mem *mem)
{
    uint64_t off = 0;
    if (s->size > RVMACHINE_SNAPSHOT_FILE_MAX) return RVMACHINE_SNAPSHOT_ERR_TOO_LARGE;
    mem->p = zcl_malloc((size_t)s->size + 1u, "snapshot_file");
    if (mem->p == NULL) return RVMACHINE_SNAPSHOT_ERR_NOMEM;
    mem->n = s->size;
    while (off < s->size) {
        uint64_t left = s->size - off;
        size_t n = left < SNAP_IO_CHUNK ? (size_t)left : SNAP_IO_CHUNK;
        if (!s->read(s->ctx, off, mem->p + off, n)) {
            free_secret(mem->p, (size_t)s->size + 1u);
            mem->p = NULL;
            return RVMACHINE_SNAPSHOT_ERR_IO;
        }
        off += n;
    }
    return RVMACHINE_SNAPSHOT_OK;
}

snap_status rvmachine_snapshot_restore(struct rvmachine **out, const struct rvmachine_config *config,
                                       const struct rvmachine_snapshot_params *params,
                                       enum rvmachine_snapshot_mode mode,
                                       const struct rvmachine_snapshot_source *source,
                                       struct rvmachine_snapshot_info *info)
{
    struct snap_mem mem = {0};
    struct rvmachine_snapshot_source copy;
    if (out != NULL) *out = NULL;
    if (!restore_args_ok(out, config, params, source) ||
        (mode != RVMACHINE_SNAPSHOT_REPLAY && mode != RVMACHINE_SNAPSHOT_FRESH))
        return RVMACHINE_SNAPSHOT_ERR_ARG;
    snap_status st = source_load(source, &mem);
    if (st != RVMACHINE_SNAPSHOT_OK) return st;
    copy = (struct rvmachine_snapshot_source){&mem, mem.n, snap_mem_read};
    st = restore_buffered(out, config, params, mode, &copy, info);
    free_secret(mem.p, (size_t)mem.n + 1u);
    return st;
}
/* ---- inspection ---- */

/* Whether slot 1 (the entropy device) is present, from the slot table. */
static bool inspect_entropy_device(struct snap_rd *rd)
{
    struct snap_rd body;
    uint32_t tag;
    while (rd->pos + 8u <= rd->n) {
        tag = zcl_read_u32_le(rd->p + rd->pos);
        if (!snap_section_open(rd, tag, &body)) return false;
        if (tag == SNAP_TAG_SLOTS) break;
        rd->pos += body.n;
    }
    for (unsigned slot = 0; slot < RVMACHINE_VIRTIO_SLOTS && rd->pos + 8u <= rd->n; slot++) {
        tag = zcl_read_u32_le(rd->p + rd->pos);
        if (!snap_section_open(rd, tag, &body)) return false;
        if (slot == RVMACHINE_VIRTIO_SLOT_ENTROPY) return tag == SNAP_SLOT_ENTROPY;
        rd->pos += body.n;
    }
    return false;
}

static void inspection_fill(struct rvmachine_snapshot_inspection *out, const struct snap_header *h,
                            const uint8_t *digest, uint64_t size)
{
    memset(out, 0, sizeof *out);
    out->ram_bytes = h->ram_bytes;
    out->retired = h->retired;
    out->guest_time = h->guest_time;
    out->file_size = size;
    out->pages = h->page_count;
    out->overlay_blocks = h->overlay_count;
    out->disk_size = h->disk_size;
    memcpy(out->bootargs, h->bootargs, sizeof out->bootargs);
    out->wait_stops = h->wait_stops;
    out->disk_present = h->disk_present;
    out->entropy = (enum rvmachine_snapshot_entropy)h->entropy;
    out->source_state_len = h->source_len;
    memcpy(out->source_state, h->source_state, h->source_len);
    memcpy(out->kernel_sha256, h->kernel_sha, SNAP_DIGEST);
    memcpy(out->disk_sha256, h->disk_sha, SNAP_DIGEST);
    memcpy(out->digest, digest, SNAP_DIGEST);
}

snap_status rvmachine_snapshot_inspect(const struct rvmachine_snapshot_source *source,
                                       const struct rvmachine_snapshot_hash *hash,
                                       struct rvmachine_snapshot_inspection *out)
{
    struct rvmachine_snapshot_params p = {.hash = hash != NULL ? *hash : (struct rvmachine_snapshot_hash){0}};
    struct snap_header h;
    struct snap_rd rd;
    uint8_t digest[SNAP_DIGEST];
    uint64_t meta_len;
    uint8_t *meta;
    if (source == NULL || source->read == NULL || out == NULL || hash == NULL ||
        hash->begin == NULL || hash->write == NULL || hash->finish == NULL)
        return RVMACHINE_SNAPSHOT_ERR_ARG;
    struct snap_mem mem = {0};
    snap_status st = source_load(source, &mem);
    if (st != RVMACHINE_SNAPSHOT_OK) return st;
    struct rvmachine_snapshot_source copy = {&mem, mem.n, snap_mem_read};
    meta = zcl_malloc(SNAP_META_MAX, "snapshot_meta");
    if (meta == NULL) {
        free_secret(mem.p, (size_t)mem.n + 1u);
        return RVMACHINE_SNAPSHOT_ERR_NOMEM;
    }
    st = source_header(&copy, &p, meta, digest, &h, &rd, &meta_len);
    if (st == RVMACHINE_SNAPSHOT_OK) {
        inspection_fill(out, &h, digest, mem.n);
        out->entropy_device = inspect_entropy_device(&rd);
    }
    free_secret(meta, SNAP_META_MAX);
    free_secret(mem.p, (size_t)mem.n + 1u);
    return st;
}
