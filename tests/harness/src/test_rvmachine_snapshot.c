/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: proofs for machine snapshots. The core proof is determinism: a
 * machine run uninterrupted and a machine saved at a point, destroyed and
 * restored into a fresh machine agree on the console transcript, the retired
 * and work counts, an independent digest of hart and RAM, and the snapshot
 * trailer of the final state. Save points include a pending console input
 * queue, a timer-armed wfi, an entropy request in flight and block requests
 * left by a capped notify. The refusals are named: truncation, a flipped byte,
 * a wrong kernel, disk or RAM size, a wrong version, an unknown slot kind. */
#include "test/test_core.h"

#include "base/serialize_le.h"
#include "crypto/sha256.h"
#include "rvmachine/rvmachine.h"
#include "rvmachine/rvmachine_snapshot.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SS_DIR "tests/fixtures/rvmachine"
#define SS_IMAGE_MAX ((size_t)1 << 16)
#define SS_RAM (UINT64_C(64) << 20)
#define SS_WORK UINT64_C(1000000)
#define SS_OUT_MAX 1024u
#define SS_DISK_BYTES (2u * 1024u * 1024u)
#define SS_MIB (UINT64_C(1) << 20)

typedef enum rvmachine_snapshot_status ss_status;

/* ---- fixtures ---- */

static bool ss_read_file(const char *path, uint8_t *buf, size_t cap, size_t *len)
{
    FILE *f = fopen(path, "rb");
    if (f == NULL) return false;
    *len = fread(buf, 1, cap, f);
    bool whole = feof(f) != 0 && ferror(f) == 0;
    fclose(f);
    return whole;
}

static void ss_hex(const uint8_t *digest, char out[2 * SHA256_OUTPUT_SIZE + 1])
{
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < SHA256_OUTPUT_SIZE; i++) {
        out[2 * i] = digits[digest[i] >> 4];
        out[2 * i + 1] = digits[digest[i] & 15u];
    }
    out[2 * SHA256_OUTPUT_SIZE] = '\0';
}

static void ss_sha(const void *data, size_t n, uint8_t out[SHA256_OUTPUT_SIZE])
{
    struct sha256_ctx c;
    sha256_init(&c);
    sha256_write(&c, data, n);
    sha256_finalize(&c, out);
}

/* The fixture image, after its sha256 matched the MANIFEST line. */
static bool ss_fixture(const char *name, uint8_t *buf, size_t *len, uint8_t sha[32])
{
    static uint8_t manifest[8192];
    char path[128], hex[2 * SHA256_OUTPUT_SIZE + 1], want[160];
    size_t n = 0;
    snprintf(path, sizeof path, SS_DIR "/%s.bin", name);
    if (!ss_read_file(path, buf, SS_IMAGE_MAX, len) || *len == 0) return false;
    ss_sha(buf, *len, sha);
    ss_hex(sha, hex);
    if (!ss_read_file(SS_DIR "/MANIFEST", manifest, sizeof manifest - 1u, &n)) return false;
    manifest[n] = '\0';
    snprintf(want, sizeof want, "\n%s %s\n", name, hex);
    return strstr((const char *)manifest, want) != NULL;
}

/* ---- snapshot plumbing: SHA-256 operations, memory sink and source ---- */

static void op_begin(void *ctx) { sha256_init(ctx); }
static void op_write(void *ctx, const uint8_t *d, size_t n) { sha256_write(ctx, d, n); }
static void op_finish(void *ctx, uint8_t out[32]) { sha256_finalize(ctx, out); }

struct membuf {
    uint8_t *p;
    size_t len, cap;
};

static bool mem_write(void *ctx, const void *buf, size_t n)
{
    struct membuf *b = ctx;
    if (b->len + n > b->cap) {
        size_t cap = b->cap != 0 ? b->cap : 4096u;
        while (cap < b->len + n) cap *= 2u;
        uint8_t *p = realloc(b->p, cap);
        if (p == NULL) return false;
        b->p = p;
        b->cap = cap;
    }
    memcpy(b->p + b->len, buf, n);
    b->len += n;
    return true;
}

static bool null_write(void *ctx, const void *buf, size_t n)
{
    (void)buf;
    *(uint64_t *)ctx += n;
    return true;
}

static bool mem_read(void *ctx, uint64_t off, void *buf, size_t n)
{
    const struct membuf *b = ctx;
    if (off > b->len || n > b->len - off) return false;
    memcpy(buf, b->p + off, n);
    return true;
}

struct ss_ctx {
    struct sha256_ctx sha;
    struct rvmachine_snapshot_params params;
};

static void ss_params_base(struct ss_ctx *c, const uint8_t kernel[32],
                           enum rvmachine_snapshot_entropy e)
{
    memset(c, 0, sizeof *c);
    c->params.hash = (struct rvmachine_snapshot_hash){&c->sha, op_begin, op_write, op_finish};
    memcpy(c->params.kernel_sha256, kernel, 32);
    c->params.entropy = e;
}

static ss_status ss_save(const struct rvmachine *m, struct ss_ctx *c, struct membuf *out,
                         struct rvmachine_snapshot_info *info)
{
    struct rvmachine_snapshot_sink sink = {out, mem_write};
    return rvmachine_snapshot_save(m, &c->params, &sink, info);
}

static ss_status ss_restore(struct rvmachine **m, const struct rvmachine_config *cfg,
                            struct ss_ctx *c, const struct membuf *in,
                            struct rvmachine_snapshot_info *info)
{
    struct rvmachine_snapshot_source src = {(void *)in, in->len, mem_read};
    return rvmachine_snapshot_restore(m, cfg, &c->params, RVMACHINE_SNAPSHOT_REPLAY, &src, info);
}

/* ---- one run: machine, console transcript, entropy source ---- */

struct ent_src {
    uint64_t pos, left;
};

struct ss_run {
    struct rvmachine *m;
    uint8_t out[SS_OUT_MAX];
    size_t n;
    struct ent_src src;
    uint8_t kernel[SS_IMAGE_MAX];
    size_t kernel_len;
    uint8_t kernel_sha[32];
    bool wait_stops, disk, entropy;
};

static void ss_console(void *ctx, uint8_t byte)
{
    struct ss_run *r = ctx;
    if (r->n < sizeof r->out) r->out[r->n++] = byte;
}

static size_t ss_fill(void *ctx, uint8_t *buf, size_t n)
{
    struct ent_src *s = ctx;
    size_t k = (uint64_t)n < s->left ? n : (size_t)s->left;
    for (size_t i = 0; i < k; i++) buf[i] = (uint8_t)(0xa0u + 7u * s->pos++);
    s->left -= k;
    return k;
}

static bool ss_image_read(void *ctx, uint64_t off, void *buf, size_t n)
{
    (void)ctx;
    uint8_t *p = buf;
    for (size_t i = 0; i < n; i++) p[i] = (uint8_t)((off + i) * 31u + 5u);
    return true;
}

static struct rvmachine_config ss_config(struct ss_run *r)
{
    struct rvmachine_config c = {.ram_bytes = SS_RAM, .console = ss_console,
                                 .console_ctx = r, .wait_stops = r->wait_stops};
    if (r->entropy) {
        c.entropy = ss_fill;
        c.entropy_ctx = &r->src;
    }
    if (r->disk && rvmachine_disk_open(&c.disk, SS_DISK_BYTES, ss_image_read, NULL) != RVMACHINE_OK)
        c.disk = NULL;
    return c;
}

static enum rvmachine_snapshot_entropy ss_mode(const struct ss_run *r)
{
    return r->entropy ? RVMACHINE_SNAPSHOT_ENTROPY_TEST_STREAM : RVMACHINE_SNAPSHOT_ENTROPY_NONE;
}

/* The parameters of the machine r holds: kernel, declared mode and, for a test
 * stream, its position. */
static void ss_params(struct ss_ctx *c, const struct ss_run *r)
{
    ss_params_base(c, r->kernel_sha, ss_mode(r));
    if (r->entropy) {
        zcl_write_u64_le(c->params.source_state, r->src.pos);
        c->params.source_state_len = 8;
    }
}

static bool ss_boot(struct ss_run *r, const char *fixture, const char *input)
{
    struct rvmachine_config c = ss_config(r);
    if (!ss_fixture(fixture, r->kernel, &r->kernel_len, r->kernel_sha)) return false;
    if (rvmachine_create(&r->m, &c) != RVMACHINE_OK) return false;
    if (rvmachine_load_kernel(r->m, r->kernel, r->kernel_len) != RVMACHINE_OK) return false;
    if (input != NULL) rvmachine_console_input(r->m, (const uint8_t *)input, strlen(input));
    return true;
}

static uint64_t ss_work(const struct rvmachine *m)
{
    return rvmachine_retired(m) + m->fw_calls + m->device_work;
}

/* Runs to a stop that is final; time is advanced to each wait deadline. */
static bool ss_drive(struct ss_run *r)
{
    struct rvmachine_result res;
    for (unsigned i = 0; i < 64u; i++) {
        enum rvmachine_status st = rvmachine_run(r->m, SS_WORK, &res);
        bool wait = st == RVMACHINE_ERR_WAITING || (st == RVMACHINE_OK && res.stop == RVMACHINE_STOP_WAIT);
        if (!wait) return st == RVMACHINE_OK && res.stop == RVMACHINE_STOP_SHUTDOWN;
        uint64_t deadline = rvmachine_timer_deadline(r->m);
        if (deadline == RVMACHINE_NO_DEADLINE ||
            rvmachine_advance_time(r->m, deadline) != RVMACHINE_OK)
            return false;
    }
    return false;
}

/* ---- the outcome of a run: everything the proof compares ---- */

struct outcome {
    uint64_t retired, time, work;
    uint8_t console[32], state[32], trailer[32];
};

/* Hart registers and RAM hashed directly, not through the snapshot encoder. */
static void ss_state_digest(const struct rvmachine *m, uint8_t out[32])
{
    struct sha256_ctx c;
    sha256_init(&c);
    sha256_write(&c, (const uint8_t *)m->hart.x, sizeof m->hart.x);
    sha256_write(&c, (const uint8_t *)m->hart.f, sizeof m->hart.f);
    sha256_write(&c, (const uint8_t *)&m->hart.csr, sizeof m->hart.csr);
    sha256_write(&c, (const uint8_t *)&m->hart.pc, sizeof m->hart.pc);
    sha256_write(&c, (const uint8_t *)&m->hart.retired, sizeof m->hart.retired);
    sha256_write(&c, m->mem.bytes, m->mem.size);
    sha256_finalize(&c, out);
}

static bool ss_outcome(struct ss_run *r, struct outcome *o)
{
    struct ss_ctx c;
    uint64_t discarded = 0;
    struct rvmachine_snapshot_sink sink = {&discarded, null_write};
    struct rvmachine_snapshot_info info;
    memset(o, 0, sizeof *o);
    o->retired = rvmachine_retired(r->m);
    o->time = rvmachine_time(r->m);
    o->work = ss_work(r->m);
    ss_sha(r->out, r->n, o->console);
    ss_state_digest(r->m, o->state);
    /* the end state of a finished guest is halted, which save refuses */
    bool halted = r->m->halted;
    r->m->halted = false;
    ss_params(&c, r);
    bool saved = rvmachine_snapshot_save(r->m, &c.params, &sink, &info) == RVMACHINE_SNAPSHOT_OK;
    r->m->halted = halted;
    if (saved) memcpy(o->trailer, info.digest, 32);
    return saved;
}

static bool ss_same(const struct outcome *a, const struct outcome *b)
{
    return a->retired == b->retired && a->time == b->time && a->work == b->work &&
           memcmp(a->console, b->console, 32) == 0 && memcmp(a->state, b->state, 32) == 0 &&
           memcmp(a->trailer, b->trailer, 32) == 0;
}

/* ---- run B: boot, run N work, save, destroy, restore, drive on ---- */

static void ss_reset(struct ss_run *r)
{
    rvmachine_destroy(r->m);
    r->m = NULL;
}

/* Saves r->m to buf and replaces it by a restored machine. */
static ss_status ss_cycle(struct ss_run *r, struct membuf *buf)
{
    struct ss_ctx c;
    struct rvmachine_snapshot_info info;
    struct rvmachine_config cfg;
    ss_params(&c, r);
    memset(buf, 0, sizeof *buf);
    ss_status st = ss_save(r->m, &c, buf, &info);
    if (st != RVMACHINE_SNAPSHOT_OK) return st;
    ss_reset(r);
    r->src.pos = UINT64_C(0xdeadbeef); /* a new process knows nothing of the old stream */
    cfg = ss_config(r);
    st = ss_restore(&r->m, &cfg, &c, buf, &info);
    if (st != RVMACHINE_SNAPSHOT_OK && cfg.disk != NULL) rvmachine_disk_close(cfg.disk);
    if (st == RVMACHINE_SNAPSHOT_OK && r->entropy) {
        if (info.source_state_len != 8u) return RVMACHINE_SNAPSHOT_ERR_FORMAT;
        r->src.pos = zcl_read_u64_le(info.source_state); /* a replay continues the stream */
    }
    return st;
}

struct scen {
    const char *fixture, *input;
    bool wait_stops, disk, entropy;
};

static void ss_init(struct ss_run *r, const struct scen *s)
{
    memset(r, 0, sizeof *r);
    r->wait_stops = s->wait_stops;
    r->disk = s->disk;
    r->entropy = s->entropy;
    r->src.left = UINT64_MAX;
}

static bool ss_run_a(const struct scen *s, struct outcome *o)
{
    static struct ss_run r;
    ss_init(&r, s);
    bool ok = ss_boot(&r, s->fixture, s->input) && ss_drive(&r) && ss_outcome(&r, o);
    ss_reset(&r);
    return ok;
}

/* The save point: the first n work units. False when the guest ended first. */
static bool ss_run_b(const struct scen *s, uint64_t n, struct outcome *o, bool *saved)
{
    static struct ss_run r;
    static struct membuf buf;
    struct rvmachine_result res;
    ss_init(&r, s);
    *saved = false;
    if (!ss_boot(&r, s->fixture, s->input)) return false;
    enum rvmachine_status st = rvmachine_run(r.m, n, &res);
    if (st != RVMACHINE_OK || res.stop == RVMACHINE_STOP_SHUTDOWN) {
        ss_reset(&r);
        return st == RVMACHINE_OK; /* ended before the save point: nothing to compare */
    }
    free(buf.p);
    if (ss_cycle(&r, &buf) != RVMACHINE_SNAPSHOT_OK) return false;
    *saved = true;
    bool ok = ss_drive(&r) && ss_outcome(&r, o);
    ss_reset(&r);
    free(buf.p);
    buf.p = NULL;
    return ok;
}

/* Every save point of a scenario, a few of them exhaustive, against run A. */
static bool ss_sweep(const struct scen *s, unsigned points, unsigned *saved_count)
{
    struct outcome a, b;
    bool saved;
    *saved_count = 0;
    if (!ss_run_a(s, &a) || a.work == 0) return false;
    uint64_t step = a.work / points + 1u;
    for (uint64_t n = 1; n < a.work; n += (n < 8u ? 1u : step)) {
        if (!ss_run_b(s, n, &b, &saved)) return false;
        if (!saved) continue;
        (*saved_count)++;
        if (!ss_same(&a, &b)) {
            printf("\n    diverged at save point %llu of %llu: retired %d time %d work %d console %d state %d trailer %d\n    ",
                   (unsigned long long)n, (unsigned long long)a.work, a.retired == b.retired,
                   a.time == b.time, a.work == b.work, !memcmp(a.console, b.console, 32),
                   !memcmp(a.state, b.state, 32), !memcmp(a.trailer, b.trailer, 32));
            return false;
        }
    }
    return true;
}

static int t_determinism(void)
{
    int failures = 0;
    static const struct scen scens[] = {
        {"tiny", NULL, false, false, false},
        {"echo", "xyz", false, false, false},
        {"ticker", NULL, false, false, false},
        {"ticker", NULL, true, false, false},
        {"entropy", NULL, false, false, true},
        {"diskwait", NULL, false, true, false},
    };
    TEST("rvmachine snapshot: A (uninterrupted) and B (saved, destroyed, restored) agree at every save point") {
        for (size_t i = 0; i < sizeof scens / sizeof scens[0]; i++) {
            unsigned count = 0;
            ASSERT(ss_sweep(&scens[i], 48u, &count));
            ASSERT(count >= 8u);
            printf("\n    %-8s wait_stops=%d: %u save points, console, counts, hart+RAM digest and trailer equal",
                   scens[i].fixture, scens[i].wait_stops, count);
        }
        printf("\n    ");
        PASS();
    } _test_next:;
    return failures;
}
/* ---- mid-I/O save points ---- */

/* The entropy guest has asked and the source is empty: the request is in
 * flight at the save point; the source then gets bytes. */
static bool ss_dry_run(bool split, struct outcome *o, bool *in_flight)
{
    static struct ss_run r;
    static struct membuf buf;
    struct rvmachine_result res;
    ss_init(&r, &(struct scen){"entropy", NULL, false, false, true});
    r.src.left = 0;
    if (!ss_boot(&r, "entropy", NULL)) return false;
    if (rvmachine_run(r.m, 4000, &res) != RVMACHINE_OK || res.stop != RVMACHINE_STOP_BUDGET) return false;
    *in_flight = r.m->entropy_dry && rvvirtio_rng_pending(&r.m->rng);
    memset(&buf, 0, sizeof buf);
    if (split && ss_cycle(&r, &buf) != RVMACHINE_SNAPSHOT_OK) return false;
    r.src.left = UINT64_MAX;
    rvmachine_entropy_ready(r.m);
    bool ok = ss_drive(&r) && ss_outcome(&r, o);
    ss_reset(&r);
    free(buf.p);
    return ok;
}

static int t_entropy_in_flight(void)
{
    int failures = 0;
    TEST("rvmachine snapshot: an entropy request in flight survives a save and is served after restore") {
        struct outcome a, b;
        bool flight_a = false, flight_b = false;
        ASSERT(ss_dry_run(false, &a, &flight_a));
        ASSERT(ss_dry_run(true, &b, &flight_b));
        ASSERT(flight_a && flight_b);
        ASSERT(ss_same(&a, &b));
        ASSERT(a.work > 4000u);
        PASS();
    } _test_next:;
    return failures;
}

#define VQ_DESC UINT64_C(0x82000000)
#define VQ_AVAIL UINT64_C(0x82001000)
#define VQ_USED UINT64_C(0x82002000)
#define VQ_HDR UINT64_C(0x82004000)
#define VQ_STATUS UINT64_C(0x82004100)
#define VQ_DATA UINT64_C(0x82100000)
#define VQ_NUM 256u
#define VQ_REQUESTS 200u

static uint8_t *vq_at(struct rvmachine *m, uint64_t gpa)
{
    return m->mem.bytes + (gpa - RVMACHINE_RAM_BASE);
}

static void vq_desc(struct rvmachine *m, unsigned i, uint64_t addr, uint32_t len,
                    uint16_t flags, uint16_t next)
{
    uint8_t *d = vq_at(m, VQ_DESC) + 16u * i;
    zcl_write_u64_le(d, addr);
    zcl_write_u32_le(d + 8, len);
    zcl_write_u16_le(d + 12, flags);
    zcl_write_u16_le(d + 14, next);
}

/* Brings the block device up as a driver would, queue 0 at the VQ_ addresses. */
static void vq_up(struct rvvirtio_dev *d)
{
    static const uint32_t steps[][2] = {
        {RVVIRTIO_REG_STATUS, 0},
        {RVVIRTIO_REG_STATUS, RVVIRTIO_STATUS_ACKNOWLEDGE | RVVIRTIO_STATUS_DRIVER},
        {RVVIRTIO_REG_DRIVER_FEATURES_SEL, 1},
        {RVVIRTIO_REG_DRIVER_FEATURES, 1},
        {RVVIRTIO_REG_DRIVER_FEATURES_SEL, 0},
        {RVVIRTIO_REG_DRIVER_FEATURES, 0},
        {RVVIRTIO_REG_STATUS, RVVIRTIO_STATUS_ACKNOWLEDGE | RVVIRTIO_STATUS_DRIVER |
                                  RVVIRTIO_STATUS_FEATURES_OK},
        {RVVIRTIO_REG_QUEUE_SEL, 0},
        {RVVIRTIO_REG_QUEUE_NUM, VQ_NUM},
        {RVVIRTIO_REG_QUEUE_DESC_LOW, (uint32_t)VQ_DESC},
        {RVVIRTIO_REG_QUEUE_DESC_HIGH, 0},
        {RVVIRTIO_REG_QUEUE_DRIVER_LOW, (uint32_t)VQ_AVAIL},
        {RVVIRTIO_REG_QUEUE_DRIVER_HIGH, 0},
        {RVVIRTIO_REG_QUEUE_DEVICE_LOW, (uint32_t)VQ_USED},
        {RVVIRTIO_REG_QUEUE_DEVICE_HIGH, 0},
        {RVVIRTIO_REG_QUEUE_READY, 1},
        {RVVIRTIO_REG_STATUS, RVVIRTIO_STATUS_ACKNOWLEDGE | RVVIRTIO_STATUS_DRIVER |
                                  RVVIRTIO_STATUS_FEATURES_OK | RVVIRTIO_STATUS_DRIVER_OK},
    };
    for (size_t i = 0; i < sizeof steps / sizeof steps[0]; i++)
        rvvirtio_mmio_write(d, steps[i][0], steps[i][1]);
}

/* count reads of the largest admitted request, all naming one chain. */
static void vq_post_reads(struct rvmachine *m, unsigned count)
{
    vq_up(&m->blk.dev);
    memset(vq_at(m, VQ_HDR), 0, 16);
    zcl_write_u64_le(vq_at(m, VQ_HDR) + 8, 1);
    vq_desc(m, 0, VQ_HDR, 16, 1, 1);
    vq_desc(m, 1, VQ_DATA, (uint32_t)RVVIRTIO_BLK_REQ_BYTES_MAX, 1 | 2, 2);
    vq_desc(m, 2, VQ_STATUS, 1, 2, 0);
    memset(vq_at(m, VQ_AVAIL), 0, 4u + 2u * VQ_NUM);
    zcl_write_u16_le(vq_at(m, VQ_AVAIL) + 2, (uint16_t)count);
    rvvirtio_mmio_write(&m->blk.dev, RVVIRTIO_REG_QUEUE_NOTIFY, 0);
}

static unsigned vq_used(struct rvmachine *m)
{
    return zcl_read_u16_le(vq_at(m, VQ_USED) + 2);
}

/* Steps the machine one budget unit at a time until every request is used. */
static bool ss_block_finish(struct ss_run *r)
{
    struct rvmachine_result res;
    for (unsigned i = 0; i < 100000u; i++) {
        if (vq_used(r->m) == VQ_REQUESTS && !r->m->blk.pending) return true;
        if (rvmachine_run(r->m, 1, &res) != RVMACHINE_OK) return false;
    }
    return false;
}

/* A guest loop, a disk with host-written overlay blocks, and 200 requests of
 * which the first capped notify serves only part. */
static bool ss_block_run(bool split, struct outcome *o, unsigned *used_at_save)
{
    static struct ss_run r;
    static struct membuf buf;
    static const uint8_t loop[4] = {0x6f, 0, 0, 0};
    uint8_t pattern[100];
    ss_init(&r, &(struct scen){NULL, NULL, false, true, false});
    memcpy(r.kernel, loop, sizeof loop);
    r.kernel_len = sizeof loop;
    ss_sha(loop, sizeof loop, r.kernel_sha);
    struct rvmachine_config c = ss_config(&r);
    if (rvmachine_create(&r.m, &c) != RVMACHINE_OK ||
        rvmachine_load_kernel(r.m, loop, sizeof loop) != RVMACHINE_OK)
        return false;
    memset(pattern, 0x6d, sizeof pattern);
    if (!rvmachine_disk_write(r.m->disk, 3u * 4096u + 7u, pattern, sizeof pattern) ||
        !rvmachine_disk_write(r.m->disk, SS_DISK_BYTES - 50u, pattern, 50u))
        return false;
    vq_post_reads(r.m, VQ_REQUESTS);
    *used_at_save = r.m->blk.pending ? vq_used(r.m) : 0; /* the capped notify left work */
    memset(&buf, 0, sizeof buf);
    if (split && ss_cycle(&r, &buf) != RVMACHINE_SNAPSHOT_OK) return false;
    bool ok = ss_block_finish(&r) && ss_outcome(&r, o);
    ss_reset(&r);
    free(buf.p);
    return ok;
}

static int t_block_in_flight(void)
{
    int failures = 0;
    TEST("rvmachine snapshot: block requests left by a capped notify and overlay blocks survive a save") {
        struct outcome a, b;
        unsigned used_a = 0, used_b = 0;
        ASSERT(ss_block_run(false, &a, &used_a));
        ASSERT(ss_block_run(true, &b, &used_b));
        ASSERT(used_a > 0 && used_a < VQ_REQUESTS); /* part of the queue was served at the save */
        ASSERT_EQ(used_a, used_b);
        ASSERT(ss_same(&a, &b));
        PASS();
    } _test_next:;
    return failures;
}

/* ---- refusals ---- */

static void ss_trailer_fix(struct membuf *b)
{
    struct sha256_ctx c;
    sha256_init(&c);
    sha256_write(&c, b->p, b->len - 32u);
    sha256_finalize(&c, b->p + b->len - 32u);
}

/* The offset of the first slot row (its kind field) in the meta block: the
 * slot section tag, its length, then a first row of the given kind. */
static size_t ss_slot_row(const struct membuf *b, uint32_t first_kind)
{
    for (size_t i = 32; i + 16u <= 4096u && i + 16u <= b->len; i++)
        if (zcl_read_u32_le(b->p + i) == 9u && zcl_read_u32_le(b->p + i + 8) == first_kind &&
            zcl_read_u32_le(b->p + i + 4) < 4096u - i)
            return i + 8u;
    return 0;
}

struct ss_case {
    struct ss_run run;
    struct membuf good;
    uint64_t pages, blocks;
};

/* A snapshot of the named fixture after `work` units. */
static bool ss_case_make(struct ss_case *k, const char *fixture, bool disk, uint64_t work)
{
    struct rvmachine_result res;
    struct ss_ctx c;
    struct rvmachine_snapshot_info info;
    memset(k, 0, sizeof *k);
    k->run.disk = disk;
    k->run.src.left = UINT64_MAX;
    if (!ss_boot(&k->run, fixture, NULL) || rvmachine_run(k->run.m, work, &res) != RVMACHINE_OK) return false;
    ss_params(&c, &k->run);
    if (ss_save(k->run.m, &c, &k->good, &info) != RVMACHINE_SNAPSHOT_OK) return false;
    k->pages = info.pages;
    k->blocks = info.overlay_blocks;
    return true;
}

static ss_status ss_try(struct ss_case *k, const struct membuf *file, struct rvmachine **out,
                        void (*tweak)(struct ss_ctx *, struct rvmachine_config *))
{
    struct ss_ctx c;
    struct rvmachine_snapshot_info info;
    struct ss_run *r = &k->run;
    ss_params(&c, r);
    struct rvmachine_config cfg = ss_config(r);
    if (tweak != NULL) tweak(&c, &cfg);
    *out = NULL;
    ss_status st = ss_restore(out, &cfg, &c, file, &info);
    if (st != RVMACHINE_SNAPSHOT_OK && cfg.disk != NULL) rvmachine_disk_close(cfg.disk);
    return st;
}

static void tw_kernel(struct ss_ctx *c, struct rvmachine_config *g) { (void)g; c->params.kernel_sha256[0] ^= 1u; }
static void tw_ram(struct ss_ctx *c, struct rvmachine_config *g) { (void)c; g->ram_bytes = 2u * SS_RAM; }
static void tw_mode(struct ss_ctx *c, struct rvmachine_config *g) { (void)g; c->params.entropy = RVMACHINE_SNAPSHOT_ENTROPY_HOST; }
static void tw_args(struct ss_ctx *c, struct rvmachine_config *g) { (void)c; g->bootargs = "console=comconsole"; }
static void tw_disk_hash(struct ss_ctx *c, struct rvmachine_config *g)
{
    (void)g;
    c->params.disk_hash_known = true;
    c->params.disk_sha256[3] = 9;
}
static void tw_disk_size(struct ss_ctx *c, struct rvmachine_config *g)
{
    (void)c;
    rvmachine_disk_close(g->disk);
    rvmachine_disk_open(&g->disk, SS_DISK_BYTES + 4096u, ss_image_read, NULL);
}
static void tw_disk_used(struct ss_ctx *c, struct rvmachine_config *g)
{
    (void)c;
    (void)rvmachine_disk_write(g->disk, 0, "x", 1);
}
static void tw_wait(struct ss_ctx *c, struct rvmachine_config *g) { (void)c; g->wait_stops = true; }

static int t_restore_refusals(void)
{
    int failures = 0;
    static struct ss_case k, kd;
    TEST("rvmachine snapshot: bindings are named refusals and no machine is returned") {
        struct rvmachine *m = (struct rvmachine *)1;
        ASSERT(ss_case_make(&k, "tiny", false, 20));
        ASSERT(ss_case_make(&kd, "diskwait", true, 20));
        ASSERT_EQ(ss_try(&k, &k.good, &m, NULL), RVMACHINE_SNAPSHOT_OK);
        ASSERT(m != NULL);
        rvmachine_destroy(m);
        ASSERT_EQ(ss_try(&k, &k.good, &m, tw_kernel), RVMACHINE_SNAPSHOT_ERR_KERNEL_HASH);
        ASSERT(m == NULL);
        ASSERT_EQ(ss_try(&k, &k.good, &m, tw_ram), RVMACHINE_SNAPSHOT_ERR_RAM_SIZE);
        ASSERT_EQ(ss_try(&k, &k.good, &m, tw_mode), RVMACHINE_SNAPSHOT_ERR_ENTROPY_MODE);
        ASSERT_EQ(ss_try(&k, &k.good, &m, tw_args), RVMACHINE_SNAPSHOT_ERR_CONFIG);
        ASSERT_EQ(ss_try(&k, &k.good, &m, tw_wait), RVMACHINE_SNAPSHOT_ERR_CONFIG);
        ASSERT_EQ(ss_try(&kd, &kd.good, &m, tw_disk_hash), RVMACHINE_SNAPSHOT_ERR_DISK_BINDING);
        ASSERT_EQ(ss_try(&kd, &kd.good, &m, tw_disk_size), RVMACHINE_SNAPSHOT_ERR_DISK_BINDING);
        ASSERT_EQ(ss_try(&kd, &kd.good, &m, tw_disk_used), RVMACHINE_SNAPSHOT_ERR_DISK_NOT_FRESH);
        ASSERT(m == NULL);
        /* size-only binding accepts a disk whose hash is unknown */
        ASSERT_EQ(ss_try(&kd, &kd.good, &m, NULL), RVMACHINE_SNAPSHOT_OK);
        rvmachine_destroy(m);
        /* a snapshot of a diskless machine does not restore onto one with a disk */
        ASSERT_EQ(ss_try(&k, &k.good, &m, tw_disk_size), RVMACHINE_SNAPSHOT_ERR_DISK_BINDING);
        PASS();
    } _test_next:;
    free(k.good.p);
    free(kd.good.p);
    ss_reset(&k.run);
    ss_reset(&kd.run);
    return failures;
}

/* ---- hostile content under a valid trailer ---- */

/* The offset of the little-endian pair (a, b) in the header area. */
static size_t ss_find_pair(const struct membuf *b, uint64_t a, uint64_t c)
{
    size_t meta = (size_t)zcl_read_u64_le(b->p + 24);
    for (size_t i = 32; i + 16u <= meta; i++)
        if (zcl_read_u64_le(b->p + i) == a && zcl_read_u64_le(b->p + i + 8) == c) return i;
    return 0;
}

static size_t ss_find64(const struct membuf *b, uint64_t v)
{
    size_t meta = (size_t)zcl_read_u64_le(b->p + 24);
    for (size_t i = 32; i + 8u <= meta; i++)
        if (zcl_read_u64_le(b->p + i) == v) return i;
    return 0;
}

static struct membuf ss_copy(const struct membuf *src)
{
    struct membuf c = {malloc(src->len), src->len, src->len};
    if (c.p != NULL) memcpy(c.p, src->p, src->len);
    return c;
}

static size_t ss_page_index_off(const struct membuf *b) { return (size_t)zcl_read_u64_le(b->p + 24); }

static size_t ss_overlay_index_off(const struct membuf *b, uint64_t pages)
{
    uint64_t data = (ss_page_index_off(b) + pages * 8u + 4095u) & ~UINT64_C(4095);
    return (size_t)(data + pages * 4096u);
}

/* A snapshot of the entropy fixture whose device queue the host forged. */
static bool ss_forged_queue(struct ss_case *k, uint32_t num, uint64_t desc)
{
    struct rvmachine_result res;
    struct ss_ctx c;
    struct rvmachine_snapshot_info info;
    memset(k, 0, sizeof *k);
    ss_init(&k->run, &(struct scen){"entropy", NULL, false, false, true});
    if (!ss_boot(&k->run, "entropy", NULL) || rvmachine_run(k->run.m, 30, &res) != RVMACHINE_OK)
        return false;
    k->run.m->rng.dev.queues[0].ready = true;
    k->run.m->rng.dev.queues[0].num = num;
    k->run.m->rng.dev.queues[0].desc = desc;
    k->run.m->rng.dev.queues[0].driver = desc + 0x1000u;
    k->run.m->rng.dev.queues[0].device = desc + 0x2000u;
    ss_params(&c, &k->run);
    return ss_save(k->run.m, &c, &k->good, &info) == RVMACHINE_SNAPSHOT_OK;
}

/* A loop kernel on a disk whose overlay holds two host-written blocks. */
static bool ss_overlay_case(struct ss_case *k)
{
    static const uint8_t loop[4] = {0x6f, 0, 0, 0};
    uint8_t pattern[100];
    struct ss_ctx c;
    struct rvmachine_snapshot_info info;
    memset(k, 0, sizeof *k);
    ss_init(&k->run, &(struct scen){NULL, NULL, false, true, false});
    memcpy(k->run.kernel, loop, sizeof loop);
    k->run.kernel_len = sizeof loop;
    ss_sha(loop, sizeof loop, k->run.kernel_sha);
    struct rvmachine_config cfg = ss_config(&k->run);
    if (rvmachine_create(&k->run.m, &cfg) != RVMACHINE_OK ||
        rvmachine_load_kernel(k->run.m, loop, sizeof loop) != RVMACHINE_OK)
        return false;
    memset(pattern, 0x6d, sizeof pattern);
    if (!rvmachine_disk_write(k->run.m->disk, 3u * 4096u + 7u, pattern, sizeof pattern) ||
        !rvmachine_disk_write(k->run.m->disk, 5u * 4096u, pattern, sizeof pattern))
        return false;
    ss_params(&c, &k->run);
    if (ss_save(k->run.m, &c, &k->good, &info) != RVMACHINE_SNAPSHOT_OK) return false;
    k->blocks = info.overlay_blocks;
    return k->blocks == 2u;
}

static ss_status ss_try_bad(struct ss_case *k, struct membuf *bad, struct rvmachine **m)
{
    ss_trailer_fix(bad);
    return ss_try(k, bad, m, NULL);
}

/* Restore reads every byte of the file once, so what is verified is what is used. */
struct ss_counting {
    const struct membuf *file;
    uint64_t bytes;
};

static bool counting_read(void *ctx, uint64_t off, void *buf, size_t n)
{
    struct ss_counting *c = ctx;
    c->bytes += n;
    return mem_read((void *)c->file, off, buf, n);
}

static bool ss_hostile_pages(struct ss_case *k, struct rvmachine **m)
{
    struct membuf bad = ss_copy(&k->good);
    size_t at = ss_page_index_off(&k->good);
    bool ok = bad.p != NULL && k->pages >= 2u;
    uint64_t i0 = zcl_read_u64_le(bad.p + at), i1 = zcl_read_u64_le(bad.p + at + 8);
    uint64_t ram_pages = SS_RAM / 4096u;
    zcl_write_u64_le(bad.p + at + 8, i0); /* duplicate */
    ok = ok && ss_try_bad(k, &bad, m) == RVMACHINE_SNAPSHOT_ERR_FORMAT && *m == NULL;
    zcl_write_u64_le(bad.p + at, i1); /* descending */
    zcl_write_u64_le(bad.p + at + 8, i0);
    ok = ok && ss_try_bad(k, &bad, m) == RVMACHINE_SNAPSHOT_ERR_FORMAT && *m == NULL;
    zcl_write_u64_le(bad.p + at, i0); /* beyond RAM */
    zcl_write_u64_le(bad.p + at + 8, ram_pages);
    ok = ok && ss_try_bad(k, &bad, m) == RVMACHINE_SNAPSHOT_ERR_FORMAT && *m == NULL;
    zcl_write_u64_le(bad.p + at + 8, i1); /* count above the RAM pages */
    size_t cnt = ss_find_pair(&k->good, k->pages, k->blocks);
    ok = ok && cnt != 0;
    if (ok) zcl_write_u64_le(bad.p + cnt, ram_pages + 1u);
    ok = ok && ss_try_bad(k, &bad, m) == RVMACHINE_SNAPSHOT_ERR_FORMAT && *m == NULL;
    free(bad.p);
    return ok;
}

static bool ss_hostile_overlay(struct ss_case *k, struct rvmachine **m)
{
    struct membuf bad = ss_copy(&k->good);
    size_t at = ss_overlay_index_off(&k->good, k->pages);
    bool ok = bad.p != NULL;
    uint64_t b0 = zcl_read_u64_le(bad.p + at);
    zcl_write_u64_le(bad.p + at + 8, b0); /* the same block twice */
    ok = ok && ss_try_bad(k, &bad, m) == RVMACHINE_SNAPSHOT_ERR_FORMAT && *m == NULL;
    zcl_write_u64_le(bad.p + at + 8, UINT64_C(1) << 40); /* beyond the disk */
    ok = ok && ss_try_bad(k, &bad, m) == RVMACHINE_SNAPSHOT_ERR_FORMAT && *m == NULL;
    free(bad.p);
    return ok;
}

static bool ss_hostile_header(struct ss_case *k, struct rvmachine **m)
{
    struct membuf bad = ss_copy(&k->good);
    size_t cnt = ss_find_pair(&k->good, k->pages, k->blocks);
    uint64_t meta = zcl_read_u64_le(k->good.p + 24);
    bool ok = bad.p != NULL && cnt != 0;
    if (ok) { /* only the prefix and header: no sections, no pages */
        memset(bad.p + cnt, 0, (size_t)meta - cnt);
        bad.len = (size_t)meta + 32u;
        zcl_write_u64_le(bad.p + 16, meta + 32u);
        ok = ss_try_bad(k, &bad, m) == RVMACHINE_SNAPSHOT_ERR_FORMAT && *m == NULL;
    }
    free(bad.p);
    bad = ss_copy(&k->good); /* a machine model this build does not implement */
    zcl_write_u32_le(bad.p + 32, RVMACHINE_MODEL_VERSION + 1u);
    ok = ok && ss_try_bad(k, &bad, m) == RVMACHINE_SNAPSHOT_ERR_MODEL && *m == NULL;
    free(bad.p);
    return ok;
}

static bool ss_hostile_machine(struct ss_case *k, struct rvmachine **m)
{
    struct ss_ctx c;
    struct rvmachine_snapshot_info info;
    const uint64_t good_seed = RVMACHINE_RAM_BASE + 0x123450u;
    struct membuf seeded = {0};
    bool ok = true;
    k->run.m->seed_addr = good_seed; /* zero bytes there: a cleared seed */
    ss_params(&c, &k->run);
    ok = ss_save(k->run.m, &c, &seeded, &info) == RVMACHINE_SNAPSHOT_OK;
    size_t at = ok ? ss_find64(&seeded, good_seed) : 0;
    const uint64_t evil[] = {1u, RVMACHINE_RAM_BASE - 1u, RVMACHINE_RAM_BASE + SS_RAM - 8u,
                             RVMACHINE_RAM_BASE + SS_RAM, UINT64_MAX - 7u};
    ok = ok && at != 0 && ss_try_bad(k, &(struct membuf){seeded.p, seeded.len, seeded.len}, m) == RVMACHINE_SNAPSHOT_OK;
    if (ok) rvmachine_destroy(*m);
    for (size_t i = 0; ok && i < sizeof evil / sizeof evil[0]; i++) {
        zcl_write_u64_le(seeded.p + at, evil[i]);
        ok = ss_try_bad(k, &seeded, m) == RVMACHINE_SNAPSHOT_ERR_FORMAT && *m == NULL;
    }
    k->run.m->seed_addr = 0;
    free(seeded.p);
    return ok;
}

#define HOSTILE(name, expr) do { bool ok_ = (expr); printf("\n    hostile %-28s %s", name, ok_ ? "refused or accepted as required" : "WRONG"); wrong |= !ok_; } while (0)

static int t_hostile(void)
{
    int failures = 0;
    bool wrong = false;
    static struct ss_case k, ko, kq;
    TEST("rvmachine snapshot: crafted content under a valid trailer is a named refusal") {
        struct rvmachine *m = (struct rvmachine *)1;
        struct ss_counting cnt = {0};
        struct ss_ctx c;
        struct rvmachine_snapshot_info info;
        ASSERT(ss_case_make(&k, "tiny", false, 20));
        ASSERT(ss_overlay_case(&ko));
        HOSTILE("page index", ss_hostile_pages(&k, &m));
        HOSTILE("overlay index", ss_hostile_overlay(&ko, &m));
        HOSTILE("header and model version", ss_hostile_header(&k, &m));
        HOSTILE("seed address", ss_hostile_machine(&k, &m));
        /* a ready queue the transport would reject, and the same queue made valid */
        ASSERT(ss_forged_queue(&kq, 0, 0x80100000u));
        HOSTILE("ready queue, size 0", ss_try(&kq, &kq.good, &m, NULL) == RVMACHINE_SNAPSHOT_ERR_FORMAT && m == NULL);
        if (m != NULL) { rvmachine_destroy(m); m = NULL; }
        free(kq.good.p);
        ss_reset(&kq.run);
        ASSERT(ss_forged_queue(&kq, 3, 0x80100000u));
        HOSTILE("ready queue, size 3", ss_try(&kq, &kq.good, &m, NULL) == RVMACHINE_SNAPSHOT_ERR_FORMAT);
        if (m != NULL) { rvmachine_destroy(m); m = NULL; }
        free(kq.good.p);
        ss_reset(&kq.run);
        ASSERT(ss_forged_queue(&kq, 8, 0x80100000u));
        ASSERT_EQ(ss_try(&kq, &kq.good, &m, NULL), RVMACHINE_SNAPSHOT_OK);
        rvmachine_destroy(m);
        /* every byte of the file is read once */
        cnt.file = &k.good;
        ss_params(&c, &k.run);
        struct rvmachine_config cfg = ss_config(&k.run);
        struct rvmachine_snapshot_source src = {&cnt, k.good.len, counting_read};
        ASSERT_EQ(rvmachine_snapshot_restore(&m, &cfg, &c.params, RVMACHINE_SNAPSHOT_REPLAY, &src, &info),
                  RVMACHINE_SNAPSHOT_OK);
        rvmachine_destroy(m);
        HOSTILE("each byte read once", cnt.bytes == k.good.len);
        /* a file over the size limit is refused before it is read */
        cnt.bytes = 0;
        src = (struct rvmachine_snapshot_source){&cnt, RVMACHINE_SNAPSHOT_FILE_MAX + 1u, counting_read};
        HOSTILE("file over the limit", rvmachine_snapshot_restore(&m, &cfg, &c.params, RVMACHINE_SNAPSHOT_REPLAY, &src, &info) == RVMACHINE_SNAPSHOT_ERR_TOO_LARGE && cnt.bytes == 0u);
        ASSERT(!wrong);
        PASS();
    } _test_next:;
    free(k.good.p);
    free(ko.good.p);
    free(kq.good.p);
    ss_reset(&k.run);
    ss_reset(&ko.run);
    ss_reset(&kq.run);
    return failures;
}


static int t_file_refusals(void)
{
    int failures = 0;
    static struct ss_case k, kd;
    TEST("rvmachine snapshot: truncation, a flipped byte, version and slot kind are named refusals") {
        struct rvmachine *m = (struct rvmachine *)1;
        struct membuf bad;
        ASSERT(ss_case_make(&k, "tiny", false, 20));
        ASSERT(ss_case_make(&kd, "diskwait", true, 20));
        /* truncated at several lengths, down to nothing */
        for (size_t cut = 1; cut < k.good.len; cut += k.good.len / 7u + 1u) {
            bad = (struct membuf){k.good.p, k.good.len - cut, k.good.len};
            ASSERT_EQ(ss_try(&k, &bad, &m, NULL), RVMACHINE_SNAPSHOT_ERR_TRUNCATED);
            ASSERT(m == NULL);
        }
        bad = (struct membuf){k.good.p, 0, 0};
        ASSERT_EQ(ss_try(&k, &bad, &m, NULL), RVMACHINE_SNAPSHOT_ERR_TRUNCATED);
        /* one flipped bit anywhere: the first fields have names of their own,
         * every later byte is caught by the trailer */
        bad = (struct membuf){malloc(k.good.len), k.good.len, k.good.len};
        ASSERT(bad.p != NULL);
        for (size_t at = 0; at < k.good.len; at += (at < 40u ? 1u : k.good.len / 97u + 1u)) {
            memcpy(bad.p, k.good.p, k.good.len);
            bad.p[at] ^= 0x10u;
            ss_status st = ss_try(&k, &bad, &m, NULL);
            ASSERT(st != RVMACHINE_SNAPSHOT_OK && m == NULL);
            if (at >= 32u) ASSERT_EQ(st, RVMACHINE_SNAPSHOT_ERR_TRAILER);
        }
        memcpy(bad.p, k.good.p, k.good.len);
        bad.p[bad.len - 1u] ^= 1u; /* the trailer itself */
        ASSERT_EQ(ss_try(&k, &bad, &m, NULL), RVMACHINE_SNAPSHOT_ERR_TRAILER);
        /* a new format version with a valid trailer */
        memcpy(bad.p, k.good.p, k.good.len);
        bad.p[8] = (uint8_t)(RVMACHINE_SNAPSHOT_VERSION + 1u);
        ss_trailer_fix(&bad);
        ASSERT_EQ(ss_try(&k, &bad, &m, NULL), RVMACHINE_SNAPSHOT_ERR_VERSION);
        /* an unknown slot kind and a known one the configuration lacks, valid trailers */
        memcpy(bad.p, k.good.p, k.good.len);
        size_t row = ss_slot_row(&k.good, 0);
        ASSERT(row != 0);
        bad.p[row] = 7;
        ss_trailer_fix(&bad);
        ASSERT_EQ(ss_try(&k, &bad, &m, NULL), RVMACHINE_SNAPSHOT_ERR_SLOT_UNKNOWN);
        bad.p[row] = 2;
        ss_trailer_fix(&bad);
        ASSERT_EQ(ss_try(&k, &bad, &m, NULL), RVMACHINE_SNAPSHOT_ERR_SLOT_MISMATCH);
        free(bad.p);
        /* a refusal after the machine was made leaves the disk with its caller */
        bad = (struct membuf){malloc(kd.good.len), kd.good.len, kd.good.len};
        memcpy(bad.p, kd.good.p, kd.good.len);
        row = ss_slot_row(&kd.good, 2);
        ASSERT(row != 0);
        bad.p[row] = 7;
        ss_trailer_fix(&bad);
        {
            struct ss_ctx c;
            struct rvmachine_snapshot_info info;
            ss_params(&c, &kd.run);
            struct rvmachine_config cfg = ss_config(&kd.run);
            ASSERT_EQ(ss_restore(&m, &cfg, &c, &bad, &info), RVMACHINE_SNAPSHOT_ERR_SLOT_UNKNOWN);
            ASSERT(m == NULL);
            uint8_t b[16];
            ASSERT(rvmachine_disk_read(cfg.disk, 0, b, sizeof b)); /* still open */
            ASSERT_EQ(rvmachine_disk_overlay_blocks(cfg.disk), 0u);
            rvmachine_disk_close(cfg.disk);
        }
        free(bad.p);
        PASS();
    } _test_next:;
    free(k.good.p);
    free(kd.good.p);
    ss_reset(&k.run);
    ss_reset(&kd.run);
    return failures;
}

static int t_save_refusals(void)
{
    int failures = 0;
    static struct ss_run r;
    static struct membuf out;
    TEST("rvmachine snapshot: a machine that cannot be captured honestly is refused by name") {
        struct ss_ctx c;
        struct rvmachine_result res;
        ss_init(&r, &(struct scen){"entropy", NULL, false, false, true});
        ASSERT(ss_boot(&r, "entropy", NULL));
        ASSERT_EQ(rvmachine_run(r.m, 30, &res), RVMACHINE_OK);
        ss_params_base(&c, r.kernel_sha, RVMACHINE_SNAPSHOT_ENTROPY_UNDECLARED);
        ASSERT_EQ(ss_save(r.m, &c, &out, NULL), RVMACHINE_SNAPSHOT_ERR_ENTROPY_UNDECLARED);
        ss_params_base(&c, r.kernel_sha, RVMACHINE_SNAPSHOT_ENTROPY_NONE); /* has a device */
        ASSERT_EQ(ss_save(r.m, &c, &out, NULL), RVMACHINE_SNAPSHOT_ERR_ENTROPY_UNDECLARED);
        ss_params_base(&c, r.kernel_sha, RVMACHINE_SNAPSHOT_ENTROPY_HOST);
        c.params.source_state_len = 8; /* only a test stream carries a position */
        ASSERT_EQ(ss_save(r.m, &c, &out, NULL), RVMACHINE_SNAPSHOT_ERR_ARG);
        ASSERT_EQ(out.len, 0u);
        r.m->seed_addr = RVMACHINE_KERNEL_BASE + 0x10000u; /* a boot seed the guest left in RAM */
        r.m->mem.bytes[0x210000u] = 0x42;
        ss_params(&c, &r);
        ASSERT_EQ(ss_save(r.m, &c, &out, NULL), RVMACHINE_SNAPSHOT_ERR_SEED_LIVE);
        r.m->mem.bytes[0x210000u] = 0;
        ASSERT_EQ(ss_save(r.m, &c, &out, NULL), RVMACHINE_SNAPSHOT_OK);
        free(out.p);
        out = (struct membuf){0};
        r.m->cleanse_on_destroy = true;
        ASSERT_EQ(ss_save(r.m, &c, &out, NULL), RVMACHINE_SNAPSHOT_ERR_PRIVATE);
        r.m->cleanse_on_destroy = false;
        r.m->halted = true;
        ASSERT_EQ(ss_save(r.m, &c, &out, NULL), RVMACHINE_SNAPSHOT_ERR_NOT_RUNNABLE);
        r.m->halted = false;
        r.m->conport_count = 1;
        ASSERT_EQ(ss_save(r.m, &c, &out, NULL), RVMACHINE_SNAPSHOT_ERR_BYTE_PORTS);
        r.m->conport_count = 0;
        ASSERT_EQ(out.len, 0u);
        PASS();
    } _test_next:;
    free(out.p);
    out = (struct membuf){0};
    ss_reset(&r);
    return failures;
}

static bool ss_backend_read(void *ctx, uint64_t off, void *buf, size_t n)
{
    return ss_image_read(ctx, off, buf, n);
}

static bool ss_backend_write(void *ctx, uint64_t off, const void *buf, size_t n)
{
    (void)ctx; (void)off; (void)buf; (void)n;
    return true;
}

static bool ss_backend_flush(void *ctx)
{
    (void)ctx;
    return true;
}

static int t_retained_disk_refused(void)
{
    int failures = 0;
    static struct ss_run r;
    TEST("rvmachine snapshot: a machine with a retained writable disk backend is refused") {
        struct ss_ctx c;
        struct membuf out = {0};
        struct rvmachine_config cfg = {.ram_bytes = SS_RAM};
        static const uint8_t loop[4] = {0x6f, 0, 0, 0};
        ss_init(&r, &(struct scen){NULL, NULL, false, false, false});
        ASSERT_EQ(rvmachine_disk_open_backend(&cfg.disk, SS_DISK_BYTES, ss_backend_read,
                                              ss_backend_write, ss_backend_flush, NULL), RVMACHINE_OK);
        ASSERT_EQ(rvmachine_create(&r.m, &cfg), RVMACHINE_OK);
        ASSERT_EQ(rvmachine_load_kernel(r.m, loop, sizeof loop), RVMACHINE_OK);
        ss_params_base(&c, r.kernel_sha, RVMACHINE_SNAPSHOT_ENTROPY_NONE);
        ASSERT_EQ(ss_save(r.m, &c, &out, NULL), RVMACHINE_SNAPSHOT_ERR_DISK_RETAINED);
        ASSERT_EQ(out.len, 0u);
        PASS();
    } _test_next:;
    ss_reset(&r);
    return failures;
}

/* True when the n bytes of pat appear anywhere in the file. */
static bool ss_contains(const struct membuf *b, const uint8_t *pat, size_t n)
{
    for (size_t i = 0; i + n <= b->len; i++)
        if (b->p[i] == pat[0] && memcmp(b->p + i, pat, n) == 0) return true;
    return false;
}

static int t_secrets_excluded(void)
{
    int failures = 0;
    static struct ss_case k;
    TEST("rvmachine snapshot: the boot seed scratch buffer is not in the file and not restored") {
        uint8_t seed[RVMACHINE_BOOT_SEED_BYTES];
        struct rvmachine_result res;
        struct ss_ctx c;
        struct rvmachine_snapshot_info info;
        struct rvmachine *m = NULL;
        memset(&k, 0, sizeof k);
        for (size_t i = 0; i < sizeof seed; i++) seed[i] = (uint8_t)(0x5au ^ (i * 13u + 1u));
        ASSERT(ss_boot(&k.run, "tiny", NULL));
        ASSERT_EQ(rvmachine_run(k.run.m, 30, &res), RVMACHINE_OK);
        memcpy(k.run.m->seed_scratch, seed, sizeof seed);
        ss_params(&c, &k.run);
        ASSERT_EQ(ss_save(k.run.m, &c, &k.good, &info), RVMACHINE_SNAPSHOT_OK);
        for (size_t off = 0; off + 32u <= sizeof seed; off += 64u)
            ASSERT(!ss_contains(&k.good, seed + off, 32u)); /* no 32-byte window of it */
        ASSERT_EQ(ss_try(&k, &k.good, &m, NULL), RVMACHINE_SNAPSHOT_OK);
        for (size_t i = 0; i < sizeof m->seed_scratch; i++) ASSERT_EQ(m->seed_scratch[i], 0u);
        rvmachine_destroy(m);
        /* control: the search does find bytes that are in the file */
        ASSERT(ss_contains(&k.good, (const uint8_t *)"Z23SNAP", 7));
        PASS();
    } _test_next:;
    free(k.good.p);
    ss_reset(&k.run);
    return failures;
}

static int t_fresh_modes(void)
{
    int failures = 0;
    static struct ss_case k;
    static struct ss_run r;
    static struct membuf host;
    TEST("rvmachine snapshot: fresh needs a host-entropy snapshot and source; replay refuses one") {
        struct ss_ctx c;
        struct rvmachine_result res;
        struct rvmachine_snapshot_info info;
        struct rvmachine *m = (struct rvmachine *)1;
        struct rvmachine_snapshot_source src;
        ASSERT(ss_case_make(&k, "tiny", false, 20));
        ss_params(&c, &k.run);
        struct rvmachine_config cfg = ss_config(&k.run);
        src = (struct rvmachine_snapshot_source){&k.good, k.good.len, mem_read};
        ASSERT_EQ(rvmachine_snapshot_restore(&m, &cfg, &c.params, RVMACHINE_SNAPSHOT_FRESH, &src, &info),
                  RVMACHINE_SNAPSHOT_ERR_FRESH_UNAVAILABLE);
        ASSERT(m == NULL);
        ss_init(&r, &(struct scen){"entropy", NULL, false, false, true});
        ASSERT(ss_boot(&r, "entropy", NULL));
        ASSERT_EQ(rvmachine_run(r.m, 30, &res), RVMACHINE_OK);
        ss_params_base(&c, r.kernel_sha, RVMACHINE_SNAPSHOT_ENTROPY_HOST);
        ASSERT_EQ(ss_save(r.m, &c, &host, &info), RVMACHINE_SNAPSHOT_OK);
        cfg = ss_config(&r);
        src = (struct rvmachine_snapshot_source){&host, host.len, mem_read};
        ASSERT_EQ(rvmachine_snapshot_restore(&m, &cfg, &c.params, RVMACHINE_SNAPSHOT_REPLAY, &src, &info),
                  RVMACHINE_SNAPSHOT_ERR_ENTROPY_MODE);
        ASSERT(m == NULL);
        ASSERT_EQ(rvmachine_snapshot_restore(&m, &cfg, &c.params, RVMACHINE_SNAPSHOT_FRESH, &src, &info),
                  RVMACHINE_SNAPSHOT_OK);
        ASSERT(m != NULL);
        rvmachine_destroy(m);
        cfg.entropy = NULL;
        ASSERT_EQ(rvmachine_snapshot_restore(&m, &cfg, &c.params, RVMACHINE_SNAPSHOT_FRESH, &src, &info),
                  RVMACHINE_SNAPSHOT_ERR_FRESH_UNAVAILABLE);
        PASS();
    } _test_next:;
    free(k.good.p);
    free(host.p);
    ss_reset(&k.run);
    ss_reset(&r);
    return failures;
}

static unsigned ss_icache_lines(const struct rvmachine *m)
{
    unsigned n = 0;
    for (unsigned i = 0; i < RVEMU_ICACHE_ENTRIES; i++) n += m->hart.icache[i].valid != 0;
    return n;
}

/* The decoded-instruction cache is derived state: it is not in the file, and
 * a restored machine executes the bytes that are in its RAM. */
static int t_icache_derived(void)
{
    int failures = 0;
    static struct ss_run r;
    static struct membuf buf;
    TEST("rvmachine snapshot: a restore leaves the decoded-instruction cache empty") {
        const uint32_t addi_x5 = 0x12300293u; /* addi x5, x0, 0x123 */
        struct rvmachine_result res;
        uint64_t misses;
        ss_init(&r, &(struct scen){"tiny", NULL, false, false, false});
        ASSERT(ss_boot(&r, "tiny", NULL));
        ASSERT_EQ(rvmachine_run(r.m, 100, &res), RVMACHINE_OK);
        ASSERT(res.stop == RVMACHINE_STOP_BUDGET);
        ASSERT(ss_icache_lines(r.m) > 0u);
        misses = r.m->hart.icache_miss;
        ASSERT(misses > 0u);
        rvmachine_invalidate_derived(r.m); /* the call a host makes after rewriting state */
        ASSERT_EQ(ss_icache_lines(r.m), 0u);
        ASSERT_EQ(r.m->hart.icache_miss, misses);
        ASSERT_EQ(rvmachine_run(r.m, 20, &res), RVMACHINE_OK);
        ASSERT(ss_icache_lines(r.m) > 0u);
        memset(&buf, 0, sizeof buf);
        ASSERT_EQ(ss_cycle(&r, &buf), RVMACHINE_SNAPSHOT_OK);
        ASSERT_EQ(ss_icache_lines(r.m), 0u);
        ASSERT_EQ(r.m->hart.icache_hit, 0u);
        ASSERT_EQ(r.m->hart.icache_miss, 0u);
        ASSERT_EQ(r.m->hart.icache_fast, 0u);
        /* the restored machine fetches from its RAM: rewrite the next instruction */
        uint64_t pc = r.m->hart.pc;
        ASSERT(pc >= r.m->mem.base && pc + 4u <= r.m->mem.base + r.m->mem.size);
        zcl_write_u32_le(r.m->mem.bytes + (pc - r.m->mem.base), addi_x5);
        r.m->hart.x[5] = 0;
        ASSERT_EQ(rvmachine_run(r.m, 1, &res), RVMACHINE_OK);
        ASSERT_EQ(r.m->hart.x[5], 0x123u);
        ASSERT_EQ(r.m->hart.pc, pc + 4u);
        ASSERT_EQ(ss_icache_lines(r.m), 1u);
        ASSERT_EQ(r.m->hart.icache_miss, 1u); /* the first fetch after a restore is a miss */
        ASSERT_EQ(r.m->hart.icache_hit, 0u);
        ASSERT_EQ(r.m->hart.icache_fast, 0u);
        PASS();
    } _test_next:;
    free(buf.p);
    buf.p = NULL;
    ss_reset(&r);
    return failures;
}

int test_rvmachine_snapshot(void);
int test_rvmachine_snapshot(void)
{
    return t_determinism() + t_entropy_in_flight() + t_block_in_flight() + t_restore_refusals() +
           t_file_refusals() + t_save_refusals() + t_retained_disk_refused() + t_secrets_excluded() +
           t_fresh_modes() + t_hostile() + t_icache_derived();
}
