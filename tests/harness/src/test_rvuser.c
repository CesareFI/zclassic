/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: rvuser proofs. Runs the freestanding riscv64 FreeBSD fixtures from
 * tests/fixtures/rvuser (MANIFEST holds each ELF's sha256), checks stdout and
 * exit status, the loader's fail-closed rejections, the three budgets,
 * determinism, and a red twin that reads the syscall number from a7 (the
 * Linux register) and must make hello fail. */
#include "test/test_core.h"
#include "rvuser/rvuser.h"
#include "base/serialize_le.h"
#include "crypto/sha256.h"
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define RUT_DIR "tests/fixtures/rvuser"
#define RUT_ELF_MAX ((size_t)1 << 14)
#define RUT_MEM ((size_t)1 << 20)
#define RUT_WORK 100000ull
#define RUT_PATH_MAX 256u
#define RUT_NAMES 5u

struct rut_store;
struct rut_sink {
    uint8_t buf[512];
    size_t n;
    struct rut_store *st;
    unsigned calls; /* should_stop hook calls */
};

struct rut_run {
    struct rvuser_result res;
    struct rut_sink out;
};

/* In-memory file store with the grant policy: this is the CALLER side. rvuser
 * only copies the path and calls open; every decision below is the test's. */
#define RUT_FILES 8u
#define RUT_FILE_CAP 256u

struct rut_file {
    char path[64];
    uint8_t data[RUT_FILE_CAP];
    size_t n;
    int64_t fake_size; /* nonzero: fsize reports this instead of n */
    bool used;
};

struct rut_store {
    struct rut_file f[RUT_FILES];
    const char *const *rd; /* component-prefix read grants, NULL-terminated */
    const char *const *wr; /* component-prefix write grants */
    bool lax_dots;         /* red twin: skip the "." / ".." / "//" refusal */
    unsigned live;         /* handles opened and not closed */
    unsigned xfer_calls;   /* pread + pwrite callback invocations */
};

enum { RUT_EPERM_ACCES = 13, RUT_ENOENT = 2, RUT_EEXIST = 17, RUT_ENOSPC = 28, RUT_EFBIG = 27 };

/* Absolute paths only; no empty, "." or ".." component (so no doubled or trailing slash). */
static bool rut_clean(const char *p)
{
    if (p[0] != '/') return false;
    const char *c = p + 1;
    for (;;) {
        const char *e = c;
        while (*e && *e != '/') e++;
        size_t len = (size_t)(e - c);
        if (len == 0 || (len == 1 && c[0] == '.') || (len == 2 && c[0] == '.' && c[1] == '.'))
            return false;
        if (!*e) break;
        c = e + 1;
    }
    return true;
}

/* "/data" grants "/data" and "/data/x" but not "/database". */
static bool rut_under(const char *path, const char *prefix)
{
    size_t n = strlen(prefix);
    return strncmp(path, prefix, n) == 0 && (path[n] == '\0' || path[n] == '/');
}

static bool rut_granted(const char *path, const char *const *list)
{
    for (; list && *list; list++)
        if (rut_under(path, *list)) return true;
    return false;
}

static struct rut_file *rut_find(struct rut_store *s, const char *path)
{
    for (unsigned i = 0; i < RUT_FILES; i++)
        if (s->f[i].used && strcmp(s->f[i].path, path) == 0) return &s->f[i];
    return NULL;
}

static void rut_put(struct rut_store *s, const char *path, const char *data, size_t n)
{
    for (unsigned i = 0; i < RUT_FILES; i++)
        if (!s->f[i].used) {
            s->f[i].used = true;
            snprintf(s->f[i].path, sizeof(s->f[i].path), "%s", path);
            s->f[i].n = n;
            memcpy(s->f[i].data, data, n);
            return;
        }
}

static int rut_open(void *ctx, const char *path, const struct rvuser_open_req *req, uint64_t *h)
{
    struct rut_store *s = ((struct rut_sink *)ctx)->st;
    if (!s->lax_dots && !rut_clean(path)) return RUT_EPERM_ACCES;
    if ((req->read && !rut_granted(path, s->rd)) || (req->write && !rut_granted(path, s->wr)))
        return RUT_EPERM_ACCES;
    struct rut_file *f = rut_find(s, path);
    if (f && req->create && req->excl) return RUT_EEXIST;
    if (!f && !req->create) return RUT_ENOENT;
    if (!f) {
        rut_put(s, path, "", 0);
        f = rut_find(s, path);
        if (!f) return RUT_ENOSPC;
    }
    if (req->trunc) f->n = 0;
    *h = (uint64_t)(f - s->f) + 1u;
    s->live++;
    return 0;
}

static struct rut_file *rut_handle(void *ctx, uint64_t h)
{
    struct rut_store *s = ((struct rut_sink *)ctx)->st;
    return (h >= 1 && h <= RUT_FILES) ? &s->f[h - 1] : NULL;
}

static int64_t rut_pread(void *ctx, uint64_t h, uint8_t *buf, size_t n, uint64_t off)
{
    struct rut_file *f = rut_handle(ctx, h);
    ((struct rut_sink *)ctx)->st->xfer_calls++;
    if (!f || off >= f->n) return 0;
    size_t take = f->n - (size_t)off < n ? f->n - (size_t)off : n;
    memcpy(buf, f->data + off, take);
    return (int64_t)take;
}

static int64_t rut_pwrite(void *ctx, uint64_t h, const uint8_t *buf, size_t n, uint64_t off)
{
    struct rut_file *f = rut_handle(ctx, h);
    ((struct rut_sink *)ctx)->st->xfer_calls++;
    if (!f || off > RUT_FILE_CAP || n > RUT_FILE_CAP - off) return -RUT_EFBIG;
    if (off > f->n) memset(f->data + f->n, 0, (size_t)off - f->n);
    memcpy(f->data + off, buf, n);
    if (off + n > f->n) f->n = (size_t)off + n;
    return (int64_t)n;
}

static void rut_close(void *ctx, uint64_t h)
{
    if (rut_handle(ctx, h)) ((struct rut_sink *)ctx)->st->live--;
}

static int64_t rut_fsize(void *ctx, uint64_t h)
{
    struct rut_file *f = rut_handle(ctx, h);
    if (f && f->fake_size) return f->fake_size;
    return f ? (int64_t)f->n : -9;
}

static unsigned rut_checks;
/* Print guest stdout on one line, newlines shown as '|', for failure diagnostics. */
static void rut_dump(const char *tag, const struct rut_run *r)
{
    printf("FAIL rvuser: %s: stop %s status %d out=", tag, rvuser_stop_name(r->res.stop),
           r->res.exit_status);
    for (size_t i = 0; i < r->out.n; i++) putchar(r->out.buf[i] == '\n' ? '|' : r->out.buf[i]);
    putchar('\n');
}


static int rut_chk(int ok, const char *what)
{
    rut_checks++;
    if (!ok) printf("FAIL rvuser: %s\n", what);
    return ok ? 0 : 1;
}

static size_t rut_write(void *ctx, int fd, const uint8_t *buf, size_t n)
{
    struct rut_sink *s = ctx;
    (void)fd;
    size_t room = sizeof(s->buf) - s->n, take = n < room ? n : room;
    memcpy(s->buf + s->n, buf, take);
    s->n += take;
    return take;
}

static int rut_clock(void *ctx, uint32_t id, uint64_t *ns)
{
    (void)ctx; (void)id;
    *ns = 0;
    return 0;
}

static struct rvuser_limits rut_limits(void)
{
    struct rvuser_limits lim = {RUT_WORK, 1000, RUT_MEM, 0};
    return lim;
}

/* Host abort hook wiring for the next rut_exec: off unless a test turns it on. */
static bool rut_hook_on;
static unsigned rut_hook_at; /* 0 = never stop; else true from this call on */
static uint64_t rut_hook_interval;

static bool rut_should_stop(void *ctx)
{
    struct rut_sink *s = ctx;
    s->calls++;
    return rut_hook_at != 0 && s->calls >= rut_hook_at;
}

/* Run with the granted-file callbacks wired to st, or with a null open when st is null. */
static void rut_exec_st(const uint8_t *elf, size_t len, const char *const *argv,
                        const struct rvuser_limits *lim, struct rut_store *st, struct rut_run *r)
{
    struct rvuser_io io = {.ctx = &r->out, .write = rut_write, .clock_ns = rut_clock};
    const char *const env[] = {"Z23=1", NULL};
    memset(r, 0, sizeof(*r));
    r->out.st = st;
    if (rut_hook_on) {
        io.should_stop = rut_should_stop;
        io.stop_check_interval = rut_hook_interval;
    }
    if (st) {
        io.open = rut_open;
        io.pread = rut_pread;
        io.pwrite = rut_pwrite;
        io.close = rut_close;
        io.fsize = rut_fsize;
    }
    if (rvuser_run(elf, len, argv, env, &io, lim, &r->res) != 0) r->res.stop = RVUSER_STOP_NOMEM;
}

static void rut_exec(const uint8_t *elf, size_t len, const char *const *argv,
                     const struct rvuser_limits *lim, struct rut_run *r)
{
    rut_exec_st(elf, len, argv, lim, NULL, r);
}

static int rut_hex_eq(const uint8_t *data, size_t len, const char *hex)
{
    static const char digits[] = "0123456789abcdef";
    struct sha256_ctx ctx;
    unsigned char h[SHA256_OUTPUT_SIZE];
    char out[2 * SHA256_OUTPUT_SIZE + 1];
    sha256_init(&ctx);
    sha256_write(&ctx, data, len);
    sha256_finalize(&ctx, h);
    for (size_t i = 0; i < SHA256_OUTPUT_SIZE; i++) {
        out[2 * i] = digits[h[i] >> 4];
        out[2 * i + 1] = digits[h[i] & 15u];
    }
    out[2 * SHA256_OUTPUT_SIZE] = '\0';
    return strcmp(out, hex) == 0;
}

/* Looks name up in the MANIFEST, reads name.elf, checks its sha256. */
static long rut_load(const char *name, uint8_t *dst)
{
    char path[RUT_PATH_MAX], line[256], row[64], sha[65];
    snprintf(path, sizeof(path), "%s/MANIFEST", RUT_DIR);
    FILE *m = fopen(path, "r");
    if (!m) return -1;
    int found = 0;
    while (fgets(line, sizeof(line), m))
        if (line[0] != '#' && sscanf(line, "%63s %64s", row, sha) == 2 && strcmp(row, name) == 0) {
            found = 1;
            break;
        }
    fclose(m);
    if (!found) return -1;
    snprintf(path, sizeof(path), "%s/%s.elf", RUT_DIR, name);
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    size_t n = fread(dst, 1, RUT_ELF_MAX, f);
    int more = fgetc(f) != EOF;
    fclose(f);
    return (more || !rut_hex_eq(dst, n, sha)) ? -1 : (long)n;
}

static int rut_hello_ok(const struct rut_run *r)
{
    return r->res.stop == RVUSER_STOP_EXIT && r->res.exit_status == 0 && r->out.n == 6 &&
           memcmp(r->out.buf, "hello\n", 6) == 0;
}

/* Run fixture name and require a clean exit with this status and stdout. */
static int rut_expect(const char *name, const char *const *argv, int status, const char *out,
                      uint8_t *elf)
{
    struct rut_run r;
    struct rvuser_limits lim = rut_limits();
    long n = rut_load(name, elf);
    if (n <= 0) return rut_chk(0, "fixture missing or sha256 mismatch");
    rut_exec(elf, (size_t)n, argv, &lim, &r);
    size_t want = strlen(out);
    int ok = r.res.stop == RVUSER_STOP_EXIT && r.res.exit_status == status && r.out.n == want &&
             memcmp(r.out.buf, out, want) == 0;
    if (!ok) printf("  %s: stop %s status %d, %zu bytes\n", name, rvuser_stop_name(r.res.stop),
                    r.res.exit_status, r.out.n);
    return rut_chk(ok, name);
}

static int rut_fixtures(uint8_t *elf, size_t *hello_len)
{
    struct rut_run r;
    static uint8_t other[RUT_ELF_MAX];
    const char *const args[] = {"prog", "one", "two", NULL};
    const char *const none[] = {"p", NULL};
    struct rvuser_limits lim = rut_limits();
    int bad = 0;
    long n = rut_load("hello", elf);
    bad += rut_chk(n > 0, "hello.elf missing or sha256 mismatch");
    if (n <= 0) return bad;
    *hello_len = (size_t)n;
    rut_exec(elf, (size_t)n, none, &lim, &r);
    bad += rut_chk(rut_hello_ok(&r), "hello stdout and exit 0");
    bad += rut_chk(r.res.syscalls == 2 && r.res.instret > 0, "hello made write and exit");
    bad += rut_chk(r.res.work == r.res.instret + r.res.syscalls, "work = retired + syscalls");
    bad += rut_expect("args", args, 0, "argc=3\nprog\none\ntwo\n", other);
    bad += rut_expect("mmap", none, 45, "", other);
    bad += rut_expect("exit7", none, 7, "", other);
    bad += rut_expect("badsys", none, 78, "", other);
    return bad;
}

/* Run a patched copy of hello and expect the typed error and stop. */
static int rut_reject(const uint8_t *hello, size_t len, size_t patch_at, uint64_t value,
                      unsigned width, size_t run_len, enum rvuser_error want, const char *what)
{
    uint8_t copy[RUT_ELF_MAX];
    struct rut_run r;
    struct rvuser_limits lim = rut_limits();
    const char *const none[] = {"p", NULL};
    memcpy(copy, hello, len);
    for (unsigned i = 0; i < width; i++) copy[patch_at + i] = (uint8_t)(value >> (8 * i));
    rut_exec(copy, run_len, none, &lim, &r);
    int ok = r.res.error == want && r.res.stop != RVUSER_STOP_EXIT && r.out.n == 0 &&
             r.res.instret == 0;
    if (!ok) printf("  %s: got error %s stop %s\n", what, rvuser_error_name(r.res.error),
                    rvuser_stop_name(r.res.stop));
    return rut_chk(ok, what);
}

/* hello.elf program header table: phoff 64, entries of 56 bytes. */
#define RUT_PH(i, field) (64u + 56u * (i) + (field))

static int rut_rejections(const uint8_t *hello, size_t len)
{
    int bad = 0;
    bad += rut_reject(hello, len, 0, 0, 0, 20, RVUSER_ERR_TRUNCATED, "truncated header");
    bad += rut_reject(hello, len, 0, 0, 0, 100, RVUSER_ERR_TRUNCATED, "truncated program headers");
    bad += rut_reject(hello, len, 0, 0x7e, 1, len, RVUSER_ERR_MAGIC, "bad magic");
    bad += rut_reject(hello, len, 4, 1, 1, len, RVUSER_ERR_CLASS, "32-bit class");
    bad += rut_reject(hello, len, 5, 2, 1, len, RVUSER_ERR_ENDIAN, "big-endian");
    bad += rut_reject(hello, len, 18, 62, 2, len, RVUSER_ERR_MACHINE, "wrong machine (x86-64)");
    bad += rut_reject(hello, len, 16, 1, 2, len, RVUSER_ERR_TYPE, "ET_REL");
    bad += rut_reject(hello, len, 48, 7, 4, len, RVUSER_ERR_FLAGS, "quad-float ABI flags");
    bad += rut_reject(hello, len, 48, 9, 4, len, RVUSER_ERR_FLAGS, "RVE flags");
    bad += rut_reject(hello, len, RUT_PH(0, 0), 3, 4, len, RVUSER_ERR_INTERP, "PT_INTERP");
    bad += rut_reject(hello, len, RUT_PH(0, 0), 2, 4, len, RVUSER_ERR_DYNAMIC, "PT_DYNAMIC");
    bad += rut_reject(hello, len, RUT_PH(1, 32), 0x4000, 8, len, RVUSER_ERR_SEGMENT,
                      "segment file range past the file");
    bad += rut_reject(hello, len, RUT_PH(1, 40), 1, 8, len, RVUSER_ERR_SEGMENT, "filesz above memsz");
    bad += rut_reject(hello, len, 24, 0x10, 8, len, RVUSER_ERR_ENTRY, "entry outside executable segment");
    return bad;
}

/* Moving the code segment (and the entry) keeps hello valid but wrong-shaped. */
static int rut_layout_rejections(const uint8_t *hello, size_t len)
{
    uint8_t copy[RUT_ELF_MAX];
    struct rut_run r;
    struct rvuser_limits lim = rut_limits();
    const char *const none[] = {"p", NULL};
    int bad = 0;
    memcpy(copy, hello, len);
    zcl_write_u64_le(copy + RUT_PH(2, 16), 0x10000010ull + 0x11160ull);
    zcl_write_u64_le(copy + 24, 0x10000010ull + 0x11160ull);
    rut_exec(copy, len, none, &lim, &r);
    bad += rut_chk(r.res.error == RVUSER_ERR_SEGMENT_RANGE && r.res.stop == RVUSER_STOP_MEMORY_CAP,
                   "segment outside guest memory");
    memcpy(copy, hello, len);
    zcl_write_u64_le(copy + RUT_PH(2, 16), 0x10010ull);
    zcl_write_u64_le(copy + 24, 0x10010ull);
    rut_exec(copy, len, none, &lim, &r);
    bad += rut_chk(r.res.error == RVUSER_ERR_OVERLAP, "overlapping PT_LOAD segments");
    return bad;
}

static int rut_budgets(const uint8_t *hello, size_t len)
{
    struct rut_run r;
    struct rvuser_limits lim = rut_limits();
    const char *const none[] = {"p", NULL};
    int bad = 0;
    lim.max_work = 5;
    rut_exec(hello, len, none, &lim, &r);
    bad += rut_chk(r.res.stop == RVUSER_STOP_WORK_BUDGET && r.res.instret == 5 && r.out.n == 0,
                   "work budget 5 stops hello");
    lim = rut_limits();
    lim.max_syscalls = 1;
    rut_exec(hello, len, none, &lim, &r);
    bad += rut_chk(r.res.stop == RVUSER_STOP_SYSCALL_CAP && r.res.syscalls == 1 && r.out.n == 6,
                   "call cap 1 lets write through, refuses exit");
    lim = rut_limits();
    lim.mem_bytes = 2 * 4096;
    lim.stack_bytes = 4096;
    rut_exec(hello, len, none, &lim, &r);
    bad += rut_chk(r.res.stop == RVUSER_STOP_MEMORY_CAP && r.res.error == RVUSER_ERR_NO_STACK,
                   "memory cap 8 KiB leaves no stack");
    lim = rut_limits();
    lim.max_work = 0;
    rut_exec(hello, len, none, &lim, &r);
    bad += rut_chk(r.res.stop == RVUSER_STOP_SETUP && r.res.error == RVUSER_ERR_LIMITS,
                   "zero work budget refused");
    return bad;
}

static int rut_determinism_and_twin(const uint8_t *hello, size_t len)
{
    struct rut_run a, b, twin;
    struct rvuser_limits lim = rut_limits();
    const char *const none[] = {"p", NULL};
    int bad = 0;
    rut_exec(hello, len, none, &lim, &a);
    rut_exec(hello, len, none, &lim, &b);
    bad += rut_chk(a.res.instret == b.res.instret && a.res.work == b.res.work &&
                       a.out.n == b.out.n && memcmp(a.out.buf, b.out.buf, a.out.n) == 0,
                   "hello twice: identical retired count and output");
#ifdef ZCL_TESTING
    rvuser_test_set_syscall_reg(17); /* red twin: a7 instead of t0 */
    rut_exec(hello, len, none, &lim, &twin);
    rvuser_test_set_syscall_reg(0);
#else
    memset(&twin, 0, sizeof(twin));
#endif
    bad += rut_chk(rut_hello_ok(&a) && !rut_hello_ok(&twin),
                   "red twin: number from a7 makes hello fail");
    printf("rvuser red twin (syscall number from a7): hello %s, stop=%s stdout=%zu bytes\n",
           rut_hello_ok(&twin) ? "PASSED (bad)" : "FAILED as required", rvuser_stop_name(twin.res.stop),
           twin.out.n);
    return bad;
}

/* e_flags float ABI: soft (the fixtures), single and double run; the patched hello keeps its
 * integer-only code, so only the loader decision is under test. */
static int rut_float_abi(const uint8_t *hello, size_t len)
{
    uint8_t copy[RUT_ELF_MAX];
    struct rut_run r;
    struct rvuser_limits lim = rut_limits();
    const char *const none[] = {"p", NULL};
    int bad = 0;
    memcpy(copy, hello, len);
    zcl_write_u32_le(copy + 48, 3); /* RVC | single */
    rut_exec(copy, len, none, &lim, &r);
    bad += rut_chk(rut_hello_ok(&r), "single-float ABI flags accepted");
    zcl_write_u32_le(copy + 48, 5); /* RVC | double */
    rut_exec(copy, len, none, &lim, &r);
    bad += rut_chk(rut_hello_ok(&r), "double-float ABI flags accepted");
    return bad;
}

/* lp64d: double sqrt, fdiv, fmul, conversions on the hard-float hart (-march=rv64imafdc). */
static int rut_lp64d(uint8_t *elf)
{
    static const char want[] = "int=1414213\nfrac=562373\nbits=3ff6a09e667f3bcd\n"
                               "newton=3ff6a09e667f3bcc\n";
    const char *const none[] = {"fp", NULL};
    int bad = rut_expect("fp", none, 0, want, elf);
    struct rut_run r;
    struct rvuser_limits lim = rut_limits();
    long n = rut_load("fp", elf);
    if (n <= 0) return bad + rut_chk(0, "fp.elf missing");
    zcl_write_u32_le(elf + 48, 7); /* same program, quad ABI flags: refused */
    rut_exec(elf, (size_t)n, none, &lim, &r);
    return bad + rut_chk(r.res.error == RVUSER_ERR_FLAGS && r.out.n == 0, "fp with quad flags refused");
}


static const char *const rut_rd[] = {"/data", "/out", NULL};
static const char *const rut_wr[] = {"/out", NULL};

static void rut_fill(struct rut_store *st)
{
    memset(st, 0, sizeof(*st));
    st->rd = rut_rd;
    st->wr = rut_wr;
    rut_put(st, "/data/in.txt", "0123456789abcd", 14);
    rut_put(st, "/data/../etc/x", "secret", 6);
    rut_put(st, "/database", "nope", 4);
    rut_put(st, "/etc/secret", "x", 1);
}

/* cat argv[1] argv[2]: expected exit status and stdout; leaves the run in *r. */
static int rut_cat(uint8_t *elf, struct rut_store *st, const char *in, const char *out, int status,
                   const char *want, struct rut_run *r)
{
    struct rvuser_limits lim = rut_limits();
    const char *const argv[] = {"cat", in, out, NULL};
    long n = rut_load("cat", elf);
    if (n <= 0) return rut_chk(0, "cat.elf missing");
    rut_exec_st(elf, (size_t)n, argv, &lim, st, r);
    int ok = r->res.stop == RVUSER_STOP_EXIT && r->res.exit_status == status &&
             r->out.n == strlen(want) && memcmp(r->out.buf, want, r->out.n) == 0;
    if (!ok) printf("  cat %s: stop %s status %d, %zu bytes\n", in, rvuser_stop_name(r->res.stop),
                    r->res.exit_status, r->out.n);
    return rut_chk(ok, in);
}

static int rut_grants(uint8_t *elf)
{
    struct rut_store st;
    struct rut_run r;
    int bad = 0;
    rut_fill(&st);
    bad += rut_cat(elf, &st, "/data/in.txt", "/out/count", 0, "0123456789abcd", &r);
    struct rut_file *c = rut_find(&st, "/out/count");
    bad += rut_chk(c && c->n == 3 && memcmp(c->data, "14\n", 3) == 0 && st.live == 0,
                   "granted read copied, byte count written, no handle left open");
    bad += rut_cat(elf, &st, "/etc/secret", "/out/c", 13, "", &r);
    bad += rut_cat(elf, &st, "/data/../etc/x", "/out/c", 13, "", &r);
    bad += rut_cat(elf, &st, "/database", "/out/c", 13, "", &r);
    bad += rut_cat(elf, &st, "/data//in.txt", "/out/c", 13, "", &r);
    bad += rut_cat(elf, &st, "/data/./in.txt", "/out/c", 13, "", &r);
    bad += rut_cat(elf, &st, "data/in.txt", "/out/c", 13, "", &r);
    bad += rut_cat(elf, &st, "/data/missing", "/out/c", 2, "", &r);
    bad += rut_cat(elf, &st, "/data/in.txt", "/data/o", 113, "0123456789abcd", &r);
    bad += rut_chk(rut_find(&st, "/data/o") == NULL, "write to a read-only grant created nothing");
    bad += rut_cat(elf, &st, "/data/in.txt", "/out/count", 0, "0123456789abcd", &r);
    /* null open callback: EACCES, today's behaviour */
    bad += rut_cat(elf, NULL, "/data/in.txt", "/out/c", 13, "", &r);
    /* red twin: a policy that skips the dot-component refusal lets /data/../etc/x through */
    st.lax_dots = true;
    bad += rut_cat(elf, &st, "/data/../etc/x", "/out/c", 0, "secret", &r);
    printf("rvuser red twin (policy without dot refusal): /data/../etc/x read %zu bytes, status %d\n",
           r.out.n, r.res.exit_status);
    return bad;
}

static int rut_fd_limits(uint8_t *elf)
{
    struct rut_store st;
    struct rut_run r;
    struct rvuser_limits lim = rut_limits();
    const char *const hog[] = {"fdhog", "/data/in.txt", NULL};
    const char *const bp[] = {"badpath", NULL};
    int bad = 0;
    rut_fill(&st);
    long n = rut_load("fdhog", elf);
    if (n <= 0) return rut_chk(0, "fdhog.elf missing");
    rut_exec_st(elf, (size_t)n, hog, &lim, &st, &r);
    bad += rut_chk(r.res.stop == RVUSER_STOP_EXIT && r.res.exit_status == 24 && r.out.n == 18 &&
                       memcmp(r.out.buf, "opened=16\nreuse=3\n", 18) == 0,
                   "17th open is EMFILE, freed slot reused");
    bad += rut_chk(st.live == 0, "handles left open at exit are closed by rvuser");
    n = rut_load("badpath", elf);
    if (n <= 0) return bad + rut_chk(0, "badpath.elf missing");
    rut_exec_st(elf, (size_t)n, bp, &lim, &st, &r);
    bad += rut_chk(r.res.stop == RVUSER_STOP_EXIT && r.res.exit_status == 14,
                   "unterminated path at the end of guest memory is EFAULT");
    return bad;
}

static int rut_file_ops(uint8_t *elf)
{
    static const char want[] = "fd=3\nsize=14\nmode=33152\nend=11\ntail=bcd\ncur=14\npread=2345\n"
                               "cur2=14\nbadfd=9\nbadflag=22\nbadwhence=22\nnegseek=22\nrowrite=9\n"
                               "spipe=29\nclosed=9\nwoff=2\nwsize=6\n";
    struct rut_store st;
    struct rut_run r;
    struct rvuser_limits lim = rut_limits();
    const char *const argv[] = {"fileops", "/data/in.txt", "/out/w", NULL};
    rut_fill(&st);
    long n = rut_load("fileops", elf);
    if (n <= 0) return rut_chk(0, "fileops.elf missing");
    rut_exec_st(elf, (size_t)n, argv, &lim, &st, &r);
    int ok = r.res.stop == RVUSER_STOP_EXIT && r.res.exit_status == 0 && r.out.n == strlen(want) &&
             memcmp(r.out.buf, want, r.out.n) == 0;
    if (!ok) rut_dump("fileops", &r);
    struct rut_file *w = rut_find(&st, "/out/w");
    return rut_chk(ok, "openat/fstat/lseek/read/pread/pwrite/close results") +
           rut_chk(w && w->n == 6 && memcmp(w->data, "AB\0\0\0Z", 6) == 0 && st.live == 0,
                   "pwrite past the end zero-fills; handles closed");
}

/* ---- static PIE ---- */

/* The loader's documented fixed static-PIE load bias (rvuser_internal.h RU_PIE_BIAS). */
#define RUT_PIE_BIAS 0x100000ull

static uint64_t rut_rd64(const uint8_t *p) { return zcl_read_u64_le(p); }

/* File offset of the first program header of this type, or 0. */
static size_t rut_ph_of(const uint8_t *elf, uint8_t type)
{
    unsigned phnum = (unsigned)(elf[56] | (elf[57] << 8));
    for (unsigned i = 0; i < phnum; i++)
        if (elf[rut_rd64(elf + 32) + 56u * i] == type) return (size_t)(rut_rd64(elf + 32) + 56u * i);
    return 0;
}

/* File offset of the PT_DYNAMIC table, or 0. */
static size_t rut_dyn_off(const uint8_t *elf)
{
    uint64_t phoff = rut_rd64(elf + 32);
    unsigned phnum = (unsigned)(elf[56] | (elf[57] << 8));
    for (unsigned i = 0; i < phnum; i++) {
        const uint8_t *ph = elf + phoff + 56u * i;
        if (ph[0] == 2) return (size_t)rut_rd64(ph + 8);
    }
    return 0;
}

static int rut_pie_runs(uint8_t *elf)
{
    static const char want_data[] = "alpha\nbeta\ngamma\nfa\nfb\n";
    char want[160];
    const char *const none[] = {"p", NULL};
    int bad = 0;
    long n = rut_load("pie_hello", elf);
    if (n <= 0) return rut_chk(0, "pie_hello.elf missing or sha256 mismatch");
    unsigned phnum = (unsigned)(elf[56] | (elf[57] << 8));
    snprintf(want, sizeof(want), "pie hello\n3=%llu\n4=56\n5=%u\n7=0\n9=%llu\n",
             (unsigned long long)(RUT_PIE_BIAS + 64u), phnum,
             (unsigned long long)(RUT_PIE_BIAS + rut_rd64(elf + 24)));
    bad += rut_chk(elf[16] == 3, "pie_hello is ET_DYN");
    bad += rut_expect("pie_hello", none, 0, want, elf);
    bad += rut_expect("pie_data", none, 5, want_data, elf);
    return bad;
}

static int rut_pie_refusals(uint8_t *elf)
{
    int bad = 0;
    long n = rut_load("pie_data", elf);
    if (n <= 0) return rut_chk(0, "pie_data.elf missing");
    size_t dyn = rut_dyn_off(elf);
    bad += rut_chk(dyn != 0, "pie_data has PT_DYNAMIC");
    if (dyn == 0) return bad;
    bad += rut_reject(elf, (size_t)n, dyn, 1, 8, (size_t)n, RVUSER_ERR_SHARED, "PIE with DT_NEEDED");
    bad += rut_reject(elf, (size_t)n, dyn, 22, 8, (size_t)n, RVUSER_ERR_TEXTREL, "PIE with DT_TEXTREL");
    bad += rut_reject(elf, (size_t)n, 64, 3, 4, (size_t)n, RVUSER_ERR_INTERP, "PIE with PT_INTERP");
    bad += rut_reject(elf, (size_t)n, rut_ph_of(elf, 1) + 16, 0xfffffffffffffff0ull, 8, (size_t)n,
                      RVUSER_ERR_SEGMENT, "PIE segment address past the bias headroom");
    return bad;
}

static int rut_pie_determinism(uint8_t *elf)
{
    struct rut_run a, b;
    struct rvuser_limits lim = rut_limits();
    const char *const none[] = {"p", NULL};
    long n = rut_load("pie_data", elf);
    if (n <= 0) return rut_chk(0, "pie_data.elf missing");
    rut_exec(elf, (size_t)n, none, &lim, &a);
    rut_exec(elf, (size_t)n, none, &lim, &b);
    return rut_chk(a.res.stop == RVUSER_STOP_EXIT && a.res.instret > 0 &&
                       a.res.instret == b.res.instret && a.res.work == b.res.work &&
                       a.out.n == b.out.n && memcmp(a.out.buf, b.out.buf, a.out.n) == 0,
                   "pie_data twice: identical instret, work and output");
}

/* ---- host abort hook ---- */

static int rut_exec_hooked(const uint8_t *elf, size_t len, const struct rvuser_limits *lim,
                           unsigned stop_at, uint64_t interval, struct rut_run *r)
{
    rut_hook_on = true;
    rut_hook_at = stop_at;
    rut_hook_interval = interval;
    const char *const none[] = {"p", NULL};
    rut_exec(elf, len, none, lim, r);
    rut_hook_on = false;
    return 0;
}

static int rut_same_result(const struct rut_run *a, const struct rut_run *b)
{
    return a->res.stop == b->res.stop && a->res.exit_status == b->res.exit_status &&
           a->res.instret == b->res.instret && a->res.work == b->res.work &&
           a->res.syscalls == b->res.syscalls && a->out.n == b->out.n &&
           memcmp(a->out.buf, b->out.buf, a->out.n) == 0;
}

static int rut_not_aborted(const char *name, uint8_t *elf)
{
    struct rut_run plain, hooked;
    struct rvuser_limits lim = rut_limits();
    const char *const none[] = {"p", NULL};
    long n = rut_load(name, elf);
    if (n <= 0) return rut_chk(0, "fixture missing");
    rut_exec(elf, (size_t)n, none, &lim, &plain);
    rut_exec_hooked(elf, (size_t)n, &lim, 0, 3, &hooked); /* asked every 3 instructions, never stops */
    int ok = rut_same_result(&plain, &hooked) && hooked.out.calls > 0 &&
             plain.res.stop == RVUSER_STOP_EXIT;
    if (!ok) printf("  %s: plain instret %llu hooked %llu calls %u\n", name,
                    (unsigned long long)plain.res.instret, (unsigned long long)hooked.res.instret,
                    hooked.out.calls);
    return rut_chk(ok, "a hook that never stops leaves output, instret and work unchanged");
}

static int rut_host_abort(uint8_t *elf)
{
    struct rut_run r, plain;
    struct rvuser_limits lim = rut_limits();
    int bad = 0;
    long n = rut_load("spin", elf);
    if (n <= 0) return rut_chk(0, "spin.elf missing");
    lim.max_work = 1000000;
    rut_exec_hooked(elf, (size_t)n, &lim, 3, 1000, &r);
    bad += rut_chk(r.res.stop == RVUSER_STOP_HOST_ABORT && r.out.calls == 3 &&
                       r.res.instret == 3000 && r.res.instret % 1000 == 0,
                   "spin: hook true on its third call stops with HOST_ABORT at 3 intervals");
    lim.max_work = 5000000;
    rut_exec_hooked(elf, (size_t)n, &lim, 2, 0, &r); /* interval 0 selects 1,000,000 */
    bad += rut_chk(r.res.stop == RVUSER_STOP_HOST_ABORT && r.res.instret == 2000000,
                   "interval 0 selects 1,000,000 instructions");
    lim.max_work = 5000;
    rut_exec(elf, (size_t)n, (const char *const[]){"p", NULL}, &lim, &plain);
    rut_exec_hooked(elf, (size_t)n, &lim, 0, 1000, &r);
    bad += rut_chk(plain.res.stop == RVUSER_STOP_WORK_BUDGET && rut_same_result(&plain, &r) &&
                       plain.res.instret == 5000,
                   "work budget still ends a spin when the hook never stops");
    bad += rut_not_aborted("hello", elf);
    bad += rut_not_aborted("pie_data", elf);
    return bad;
}

/* ---- crafted raw instruction words: guest-triggerable host UB checks ---- */

#define RUT_RAW_CODE 120u

/* One RX PT_LOAD at vaddr holding the headers and the code; entry at vaddr + RUT_RAW_CODE. */
static size_t rut_mkelf_at(uint8_t *e, const uint32_t *code, unsigned n, uint64_t vaddr)
{
    size_t len = RUT_RAW_CODE + 4u * n;
    memset(e, 0, len);
    e[0] = 0x7f; e[1] = 'E'; e[2] = 'L'; e[3] = 'F'; e[4] = 2; e[5] = 1; e[6] = 1;
    zcl_write_u16_le(e + 16, 2);
    zcl_write_u16_le(e + 18, 243);
    zcl_write_u32_le(e + 20, 1);
    zcl_write_u64_le(e + 24, vaddr + RUT_RAW_CODE);
    zcl_write_u64_le(e + 32, 64);
    zcl_write_u16_le(e + 52, 64);
    zcl_write_u16_le(e + 54, 56);
    zcl_write_u16_le(e + 56, 1);
    zcl_write_u32_le(e + 64, 1);      /* PT_LOAD */
    zcl_write_u32_le(e + 68, 5);      /* R+X */
    zcl_write_u64_le(e + 80, vaddr);  /* p_vaddr */
    zcl_write_u64_le(e + 96, len);    /* filesz */
    zcl_write_u64_le(e + 104, len);   /* memsz */
    for (unsigned i = 0; i < n; i++) zcl_write_u32_le(e + RUT_RAW_CODE + 4u * i, code[i]);
    return len;
}

static size_t rut_mkelf(uint8_t *e, const uint32_t *code, unsigned n)
{
    return rut_mkelf_at(e, code, n, 0);
}

static void rut_raw(const uint32_t *code, unsigned n, struct rut_run *r)
{
    uint8_t elf[512];
    struct rvuser_limits lim = rut_limits();
    const char *const none[] = {"p", NULL};
    size_t len = rut_mkelf(elf, code, n);
    rut_exec(elf, len, none, &lim, r);
}

#define RUT_N(a) ((unsigned)(sizeof(a) / sizeof((a)[0])))

static int rut_raw_ub(void)
{
    /* lui a0,0x80000; sd a0,0(sp); write(1, sp, 8); exit(0) */
    static const uint32_t lui[] = {0x80000537, 0x00a13023, 0x00010593, 0x00100513, 0x00800613,
                                   0x00400293, 0x00000073, 0x00100293, 0x00000513, 0x00000073};
    static const uint8_t lui_want[8] = {0, 0, 0, 0x80, 0xff, 0xff, 0xff, 0xff};
    /* a0 = INT64_MAX (addi -1; srli 1); jalr x0,8(a0) */
    static const uint32_t jalr[] = {0xfff00513, 0x00155513, 0x00850067};
    static const uint32_t jal_back[] = {0x800e006f}; /* jal x0,-0x20000 from pc 120: below 0 */
    static const uint32_t br_back[] = {0x80000063};  /* beq x0,x0,-4096 from pc 120: below 0 */
    /* lui a1,0xffff0; li a0,1; li a2,N; li t0,4; ecall; li t0,1; ecall (exit(a0)) */
    static const uint32_t w0[] = {0xffff05b7, 0x00100513, 0x00000613, 0x00400293, 0x00000073,
                                  0x00100293, 0x00000073};
    static const uint32_t w8[] = {0xffff05b7, 0x00100513, 0x00800613, 0x00400293, 0x00000073,
                                  0x00100293, 0x00000073};
    /* a1 = 5; getpid; exit(a1): a successful call clears a1 (FreeBSD td_retval[1] = 0) */
    static const uint32_t a1clr[] = {0x00500593, 0x01400293, 0x00000073, 0x00058513, 0x00100293,
                                     0x00000073};
    struct rut_run r;
    int bad = 0;
    rut_raw(lui, RUT_N(lui), &r);
    bad += rut_chk(r.res.stop == RVUSER_STOP_EXIT && r.out.n == 8 &&
                       memcmp(r.out.buf, lui_want, 8) == 0,
                   "lui a0,0x80000 gives 0xffffffff80000000 (sign-extended, no signed-shift UB)");
    rut_raw(jalr, RUT_N(jalr), &r);
    bad += rut_chk(r.res.stop == RVUSER_STOP_FAULT && r.out.n == 0,
                   "jalr INT64_MAX+8 is a typed FAULT");
    rut_raw(jal_back, 1, &r);
    bad += rut_chk(r.res.stop == RVUSER_STOP_FAULT && r.out.n == 0,
                   "jal target below zero wraps to a typed FAULT");
    rut_raw(br_back, 1, &r);
    bad += rut_chk(r.res.stop == RVUSER_STOP_FAULT && r.out.n == 0,
                   "taken branch target below zero wraps to a typed FAULT");
    /* FreeBSD: a zero-length write never touches the buffer, so it returns 0 (no EFAULT). */
    rut_raw(a1clr, RUT_N(a1clr), &r);
    bad += rut_chk(r.res.stop == RVUSER_STOP_EXIT && r.res.exit_status == 0,
                   "a successful system call clears a1");
    rut_raw(w0, RUT_N(w0), &r);
    bad += rut_chk(r.res.stop == RVUSER_STOP_EXIT && r.res.exit_status == 0 && r.out.n == 0,
                   "write(1, 0xffffffffffff0000, 0) returns 0, no host pointer formed");
    rut_raw(w8, RUT_N(w8), &r);
    bad += rut_chk(r.res.stop == RVUSER_STOP_EXIT && r.res.exit_status == 14 && r.out.n == 0,
                   "write(1, 0xffffffffffff0000, 8) is EFAULT");
    return bad;
}

/* Offset range guard: 1-byte read, write, pread, pwrite and append at INT64_MAX are EINVAL, reach
 * no pread/pwrite callback, and leave every fd closeable. */
static int rut_off_guard(uint8_t *elf)
{
    static const char want[] =
        "lseek_r=9223372036854775807\nlseek_w=9223372036854775807\nread=22\nwrite=22\npread=22\n"
        "pwrite=22\nappend=22\nclose_r=0\nclose_w=0\nclose_a=0\n";
    struct rut_store st;
    struct rut_run r;
    struct rvuser_limits lim = rut_limits();
    const char *const argv[] = {"offguard", "/data/in.txt", "/out/w", "/out/big", NULL};
    rut_fill(&st);
    rut_put(&st, "/out/big", "", 0);
    struct rut_file *big = rut_find(&st, "/out/big");
    if (big) big->fake_size = INT64_MAX;
    long n = rut_load("offguard", elf);
    if (n <= 0) return rut_chk(0, "offguard.elf missing");
    rut_exec_st(elf, (size_t)n, argv, &lim, &st, &r);
    int ok = r.res.stop == RVUSER_STOP_EXIT && r.res.exit_status == 0 && r.out.n == strlen(want) &&
             memcmp(r.out.buf, want, r.out.n) == 0;
    if (!ok) rut_dump("offguard", &r);
    return rut_chk(ok, "I/O at offset INT64_MAX is EINVAL, fds still close") +
           rut_chk(st.xfer_calls == 0 && st.live == 0,
                   "offset guard: zero pread/pwrite callbacks, no handle left open");
}

/* ---- hostile program images: address-range wrap, loader bounds, stack, null arguments ---- */

#define RUT_HOSTILE_VADDR 0xFFFFFFFFFFF01000ull
static const uint32_t rut_spin4[4] = {0x0000006f, 0x0000006f, 0x0000006f, 0x0000006f};

static void rut_run_img(const uint8_t *elf, size_t len, uint64_t work, struct rut_run *r)
{
    struct rvuser_limits lim = {work, 1000, RUT_MEM, 0};
    const char *const none[] = {"p", NULL};
    rut_exec(elf, len, none, &lim, r);
}

/* The 136-byte reviewer image: one RX segment, filesz 136, memsz 0x1000, entry inside it. */
static int rut_hostile_vaddr(void)
{
    uint8_t elf[136];
    struct rut_run r;
    int bad = 0;
    size_t len = rut_mkelf_at(elf, rut_spin4, 4, RUT_HOSTILE_VADDR);
    bad += rut_chk(len == 136, "hostile image is 136 bytes");
    rut_run_img(elf, len, 1000, &r);
    bad += rut_chk(r.res.error == RVUSER_ERR_SEGMENT_RANGE && r.res.stop == RVUSER_STOP_MEMORY_CAP &&
                       r.res.instret == 0 && r.res.work == 0,
                   "segment at 0xFFFFFFFFFFF01000 is a typed SEGMENT_RANGE refusal, no guest work");
    len = rut_mkelf_at(elf, rut_spin4, 4, 0x10000);
    rut_run_img(elf, len, 1000, &r);
    bad += rut_chk(r.res.error == RVUSER_ERR_NONE && r.res.stop == RVUSER_STOP_WORK_BUDGET &&
                       r.res.work == 1000,
                   "control: the same image at 0x10000 runs to its work budget");
    /* Edge of the checked range: the highest page-aligned base whose base + memory size fits below
     * 2^64 runs; the next page up is refused. */
    len = rut_mkelf_at(elf, rut_spin4, 4, UINT64_MAX - (uint64_t)RUT_MEM - 0xFFFu);
    rut_run_img(elf, len, 1000, &r);
    bad += rut_chk(r.res.error == RVUSER_ERR_NONE && r.res.stop == RVUSER_STOP_WORK_BUDGET,
                   "highest base whose base + size fits below 2^64 still runs");
    len = rut_mkelf_at(elf, rut_spin4, 4, UINT64_MAX - (uint64_t)RUT_MEM + 1u);
    rut_run_img(elf, len, 1000, &r);
    bad += rut_chk(r.res.error == RVUSER_ERR_SEGMENT_RANGE, "next page up, where base + size would reach 2^64, is refused");
    return bad;
}

/* mutate fixes up the 136-byte image in place; every mutation must be a typed setup error. */
static int rut_mutated(const char *what, enum rvuser_error want, uint16_t phentsize, uint16_t phnum,
                       uint64_t phoff, uint64_t vaddr, uint64_t memsz, uint64_t offset)
{
    uint8_t elf[136];
    struct rut_run r;
    size_t len = rut_mkelf(elf, rut_spin4, 4);
    zcl_write_u64_le(elf + 32, phoff);
    zcl_write_u16_le(elf + 54, phentsize);
    zcl_write_u16_le(elf + 56, phnum);
    zcl_write_u64_le(elf + 72, offset);
    zcl_write_u64_le(elf + 80, vaddr);
    zcl_write_u64_le(elf + 104, memsz);
    rut_run_img(elf, len, 1000, &r);
    return rut_chk(r.res.error == want && r.res.work == 0 && r.res.instret == 0, what);
}

static int rut_loader_bounds(void)
{
    enum { PH = 56 };
    int bad = 0;
    bad += rut_mutated("program-header offset beyond the file is TRUNCATED", RVUSER_ERR_TRUNCATED,
                       PH, 1, 137, 0, 136, 0);
    bad += rut_mutated("program-header offset near 2^64 is TRUNCATED", RVUSER_ERR_TRUNCATED, PH, 1,
                       UINT64_MAX - 8u, 0, 136, 0);
    bad += rut_mutated("program-header table running past the file is TRUNCATED",
                       RVUSER_ERR_TRUNCATED, PH, 64, 64, 0, 136, 0);
    bad += rut_mutated("program-header count 0xFFFF is refused", RVUSER_ERR_PHDR, PH, 0xFFFF, 64,
                       0, 136, 0);
    bad += rut_mutated("wrong program-header entry size is PHDR", RVUSER_ERR_PHDR, PH + 1, 1, 64, 0,
                       136, 0);
    bad += rut_mutated("segment address + memory size wrapping 2^64 is SEGMENT", RVUSER_ERR_SEGMENT,
                       PH, 1, 64, 0xFFFFFFFFFFFFF000ull, 0x2000, 0);
    bad += rut_mutated("segment file offset + file size wrapping 2^64 is SEGMENT",
                       RVUSER_ERR_SEGMENT, PH, 1, 64, 0, 136, UINT64_MAX - 10u);
    return bad;
}

/* argv strings larger than the stack: typed NO_STACK, and the guest memory is not exceeded
 * (the string area is checked against the stack before any copy; under ASan an overrun aborts). */
static int rut_stack_no_fit(void)
{
    static char big[3 * 4096];
    uint8_t elf[136];
    struct rut_run r;
    struct rvuser_limits lim = {1000, 1000, RUT_MEM, 8192};
    int bad = 0;
    memset(big, 'a', sizeof(big) - 1);
    const char *const argv[] = {"p", big, NULL};
    size_t len = rut_mkelf(elf, rut_spin4, 4);
    rut_exec(elf, len, argv, &lim, &r);
    bad += rut_chk(r.res.error == RVUSER_ERR_NO_STACK && r.res.stop == RVUSER_STOP_MEMORY_CAP &&
                       r.res.instret == 0,
                   "argv strings larger than the stack are a typed NO_STACK refusal");
    const char *const small[] = {"p", "q", NULL};
    rut_exec(elf, len, small, &lim, &r);
    bad += rut_chk(r.res.error == RVUSER_ERR_NONE && r.res.stop == RVUSER_STOP_WORK_BUDGET,
                   "control: small argv in the same stack runs");
    return bad;
}

/* Documented contract: -1 only when elf, io, lim or out is null (no result written then). */
static int rut_null_args(void)
{
    uint8_t elf[136];
    struct rvuser_io io = {0};
    struct rvuser_limits lim = rut_limits();
    struct rvuser_result res;
    size_t len = rut_mkelf(elf, rut_spin4, 4);
    int bad = 0;
    bad += rut_chk(rvuser_run(NULL, len, NULL, NULL, &io, &lim, &res) == -1, "null elf returns -1");
    bad += rut_chk(rvuser_run(elf, len, NULL, NULL, NULL, &lim, &res) == -1, "null io returns -1");
    bad += rut_chk(rvuser_run(elf, len, NULL, NULL, &io, NULL, &res) == -1, "null limits return -1");
    bad += rut_chk(rvuser_run(elf, len, NULL, NULL, &io, &lim, NULL) == -1, "null result returns -1");
    bad += rut_chk(rvuser_run(elf, len, NULL, NULL, &io, &lim, &res) == 0 &&
                       res.stop == RVUSER_STOP_WORK_BUDGET,
                   "all pointers given: returns 0 and a typed stop");
    return bad;
}

/* pread(fd, buf, INT64_MAX - 1000, 2000): the requested length overflows the offset range, so
 * it is EINVAL (22) with no callback, not a short transfer clamped to 64 KiB (the file has 14
 * bytes, so a short transfer would exit 14). */
static int rut_pread_huge_len(void)
{
    static const uint32_t code[] = {0x10000513, 0x00000593, 0x00500293, 0x00000073, 0x20000593,
                                    0xFFF00613, 0x00165613, 0xC1860613, 0x7D000693, 0x1DB00293,
                                    0x00000073, 0x00100293, 0x00000073};
    uint8_t elf[512];
    struct rut_store st;
    struct rut_run r;
    struct rvuser_limits lim = rut_limits();
    const char *const none[] = {"p", NULL};
    size_t len = rut_mkelf(elf, code, RUT_N(code));
    memset(elf + len, 0, sizeof(elf) - len);
    memcpy(elf + 256, "/data/in.txt", 13); /* open(256, O_RDONLY) reads the path from here */
    zcl_write_u64_le(elf + 96, 272);
    zcl_write_u64_le(elf + 104, 0x1000);
    rut_fill(&st);
    rut_exec_st(elf, 272, none, &lim, &st, &r);
    return rut_chk(r.res.stop == RVUSER_STOP_EXIT && r.res.exit_status == 22 && st.xfer_calls == 0,
                   "pread with a length beyond the offset range is EINVAL, not a short transfer");
}

static int rut_hostile(void)
{
    return rut_hostile_vaddr() + rut_loader_bounds() + rut_stack_no_fit() + rut_null_args() +
           rut_pread_huge_len();
}

int test_rvuser(void)
{
    static uint8_t hello[RUT_ELF_MAX];
    static uint8_t other[RUT_ELF_MAX];
    size_t len = 0;
    int bad = rut_fixtures(hello, &len);
    if (len > 0) {
        bad += rut_rejections(hello, len);
        bad += rut_layout_rejections(hello, len);
        bad += rut_budgets(hello, len);
        bad += rut_determinism_and_twin(hello, len);
        bad += rut_float_abi(hello, len);
        bad += rut_lp64d(other);
        bad += rut_grants(other);
        bad += rut_fd_limits(other);
        bad += rut_file_ops(other);
        bad += rut_off_guard(other);
        bad += rut_pie_runs(other);
        bad += rut_pie_refusals(other);
        bad += rut_pie_determinism(other);
        bad += rut_host_abort(other);
        bad += rut_raw_ub();
        bad += rut_hostile();
    }
    printf("rvuser: %u checks, %d failed\n", rut_checks, bad);
    return bad;
}
