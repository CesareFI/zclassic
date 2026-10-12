/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: RV64IMAFDC hart proofs. Runs the official riscv-tests rv64ui-p,
 * rv64um-p, rv64ua-p, rv64uc-p, rv64uf-p and rv64ud-p images from tests/fixtures/riscv-tests
 * (MANIFEST names each image,
 * its sha256, load and tohost address), then checks direct instruction
 * semantics that the suites do not isolate. */
#include "test/test_core.h"
#include "rvemu/rvemu.h"
#include "base/serialize_le.h"
#include "crypto/sha256.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define RVT_FIXTURE_DIR "tests/fixtures/riscv-tests"
#define RVT_MEM_BASE 0x80000000ull
#define RVT_MEM_SIZE ((size_t)1 << 20)
#define RVT_IMAGE_MAX ((size_t)1 << 16)
#define RVT_STEP_BUDGET 1000000ull
#define RVT_ROWS_MAX 192u
#define RVT_ROWS_EXPECTED 134u
#define RVT_USER_EXPECTED 110u
#define RVT_EXCLUDED_EXPECTED 0u
#define RVT_LINE_MAX 256u
#define RVT_PATH_MAX 512u
#define RVT_HART_SCRATCH 0x100ull

struct rvt_row {
    char name[64];
    char sha256[65];
    uint64_t load;
    uint64_t tohost;
    int machine; /* rv64mi-p and rv64si-p: run in the machine profile */
};

static uint8_t rvt_mem_bytes[RVT_MEM_SIZE];
static uint8_t rvt_image[RVT_IMAGE_MAX];

static int rvt_parse_row(const char *line, struct rvt_row *row)
{
    unsigned long long load = 0, tohost = 0;
    if (sscanf(line, "%63s %64s %llx %llx", row->name, row->sha256, &load, &tohost) != 4)
        return -1;
    row->load = load;
    row->tohost = tohost;
    row->machine = strncmp(row->name, "rv64mi-", 7) == 0 || strncmp(row->name, "rv64si-", 7) == 0;
    if (row->load != RVT_MEM_BASE || row->tohost < RVT_MEM_BASE) return -1;
    return row->tohost - RVT_MEM_BASE + 8u <= RVT_MEM_SIZE ? 0 : -1;
}

static int rvt_read_manifest(struct rvt_row *rows, unsigned *count, unsigned *excluded)
{
    char line[RVT_LINE_MAX], path[RVT_PATH_MAX];
    snprintf(path, sizeof(path), "%s/MANIFEST", RVT_FIXTURE_DIR);
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    *count = 0;
    *excluded = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "# excluded rv64", 15) == 0) (*excluded)++;
        if (line[0] == '#' || line[0] == '\n') continue;
        if (*count >= RVT_ROWS_MAX || rvt_parse_row(line, &rows[*count]) != 0) {
            fclose(f);
            return -1;
        }
        (*count)++;
    }
    fclose(f);
    return 0;
}

static long rvt_read_image(const char *name)
{
    char path[RVT_PATH_MAX];
    snprintf(path, sizeof(path), "%s/%s.bin", RVT_FIXTURE_DIR, name);
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    size_t n = fread(rvt_image, 1, sizeof(rvt_image), f);
    int more = fgetc(f) != EOF;
    fclose(f);
    return more ? -1 : (long)n;
}

static int rvt_image_matches(const char *expect_hex, size_t len)
{
    static const char digits[] = "0123456789abcdef";
    struct sha256_ctx ctx;
    unsigned char hash[SHA256_OUTPUT_SIZE];
    char hex[2 * SHA256_OUTPUT_SIZE + 1];
    sha256_init(&ctx);
    sha256_write(&ctx, rvt_image, len);
    sha256_finalize(&ctx, hash);
    for (size_t i = 0; i < SHA256_OUTPUT_SIZE; i++) {
        hex[2 * i] = digits[hash[i] >> 4];
        hex[2 * i + 1] = digits[hash[i] & 15u];
    }
    hex[2 * SHA256_OUTPUT_SIZE] = '\0';
    return strcmp(hex, expect_hex) == 0;
}

/* Host side of the HTIF convention: the image's ecall with a7 = 93 is the end
 * marker. The value written to tohost is a0 when a0 is odd (failure encodes
 * the test number as (n << 1) | 1), else gp (1 on a pass). */
static uint64_t rvt_collect_tohost(const struct rvemu_hart *hart, const struct rvt_row *row)
{
    uint64_t v = (hart->x[10] & 1u) ? hart->x[10] : hart->x[3];
    uint64_t off = row->tohost - RVT_MEM_BASE, back = 0;
    zcl_write_u64_le(&rvt_mem_bytes[off], v);
    back = zcl_read_u64_le(&rvt_mem_bytes[off]);
    return back;
}

/* Returns 1 when the image reached its end marker, writing tohost to *value. */
static int rvt_run_user(const struct rvt_row *row, size_t len, uint64_t *value,
                        enum rvemu_stop *stop, uint64_t *pc)
{
    struct rvemu_hart hart;
    struct rvemu_mem mem = {.base = RVT_MEM_BASE, .size = RVT_MEM_SIZE, .bytes = rvt_mem_bytes};
    memset(rvt_mem_bytes, 0, sizeof(rvt_mem_bytes));
    memcpy(rvt_mem_bytes, rvt_image, len);
    rvemu_hart_init(&hart, row->load);
    if (rvemu_run(&hart, &mem, RVT_STEP_BUDGET, stop) != 0) return 0;
    *pc = hart.pc;
    if (*stop != RVEMU_STOP_ECALL || hart.x[17] != 93) return 0;
    *value = rvt_collect_tohost(&hart, row);
    return 1;
}

/* The privileged images run in the machine profile, where their own trap
 * vector handles ecall and writes the result to tohost. */
static int rvt_run_machine(const struct rvt_row *row, size_t len, uint64_t *value,
                           enum rvemu_stop *stop, uint64_t *pc)
{
    struct rvemu_hart hart;
    struct rvemu_mem mem = {.base = RVT_MEM_BASE, .size = RVT_MEM_SIZE, .bytes = rvt_mem_bytes};
    const uint64_t off = row->tohost - RVT_MEM_BASE;
    memset(rvt_mem_bytes, 0, sizeof(rvt_mem_bytes));
    memcpy(rvt_mem_bytes, rvt_image, len);
    rvemu_hart_init_machine(&hart, row->load);
    *stop = RVEMU_STOP_NONE;
    for (uint64_t n = 0; n < RVT_STEP_BUDGET && *stop == RVEMU_STOP_NONE; n++) {
        *stop = rvemu_step(&hart, &mem);
        *value = zcl_read_u64_le(&rvt_mem_bytes[off]);
        if (*value != 0) return 1;
    }
    *pc = hart.pc;
    return 0;
}

static int rvt_run_image(const struct rvt_row *row, size_t len, uint64_t *value,
                         enum rvemu_stop *stop, uint64_t *pc)
{
    if (row->machine) return rvt_run_machine(row, len, value, stop, pc);
    return rvt_run_user(row, len, value, stop, pc);
}

static int rvt_check_image(const struct rvt_row *row)
{
    long len = rvt_read_image(row->name);
    if (len <= 0 || !rvt_image_matches(row->sha256, (size_t)len)) {
        printf("FAIL %s: image missing or sha256 mismatch\n", row->name);
        return 1;
    }
    uint64_t value = 0, pc = 0;
    enum rvemu_stop stop = RVEMU_STOP_NONE;
    if (!rvt_run_image(row, (size_t)len, &value, &stop, &pc)) {
        printf("FAIL %s: stop=%d pc=0x%llx (no end marker)\n", row->name, (int)stop,
               (unsigned long long)pc);
        return 1;
    }
    if (value == 1) return 0;
    printf("FAIL %s: tohost=%llu names test %llu\n", row->name, (unsigned long long)value,
           (unsigned long long)(value >> 1));
    return 1;
}

static int rvt_conformance(void)
{
    struct rvt_row rows[RVT_ROWS_MAX];
    unsigned count = 0, excluded = 0, failed_user = 0, failed_priv = 0, n_user = 0, n_priv = 0;
    if (rvt_read_manifest(rows, &count, &excluded) != 0 || count != RVT_ROWS_EXPECTED ||
        excluded != RVT_EXCLUDED_EXPECTED) {
        printf("FAIL manifest: expected %u rows and %u excluded\n", RVT_ROWS_EXPECTED,
               RVT_EXCLUDED_EXPECTED);
        return 1;
    }
    for (unsigned i = 0; i < count; i++) {
        unsigned bad = (unsigned)rvt_check_image(&rows[i]);
        if (rows[i].machine) { n_priv++; failed_priv += bad; }
        else { n_user++; failed_user += bad; }
    }
    if (n_user != RVT_USER_EXPECTED) {
        printf("FAIL manifest: expected %u user images\n", RVT_USER_EXPECTED);
        return 1;
    }
    printf("rvemu riscv-tests rv64ui-p, rv64um-p, rv64ua-p, rv64uc-p, rv64uf-p, rv64ud-p: %u/%u passed, 0 skipped\n",
           n_user - failed_user, n_user);
    printf("rvemu riscv-tests rv64mi-p, rv64si-p (machine profile, Sv39 images included): %u/%u passed, %u excluded\n",
           n_priv - failed_priv, n_priv, excluded);
    return (int)(failed_user + failed_priv);
}

static uint32_t rvt_r_insn(unsigned f7, unsigned f3, unsigned opc)
{
    return (f7 << 25) | (3u << 20) | (2u << 15) | (f3 << 12) | (3u << 7) | opc;
}

static void rvt_put32(struct rvemu_hart *hart, uint64_t addr, uint32_t insn)
{
    uint64_t off = addr - RVT_MEM_BASE;
    zcl_write_u32_le(&rvt_mem_bytes[off], insn);
    rvemu_icache_note_store(hart, addr, 4u);
}

/* Runs one register-form instruction (rs1 = x2, rs2 = x3, rd = x3). */
static int rvt_rr_kat(uint32_t insn, uint64_t a, uint64_t b, uint64_t expect)
{
    struct rvemu_hart hart;
    struct rvemu_mem mem = {.base = RVT_MEM_BASE, .size = RVT_MEM_SIZE, .bytes = rvt_mem_bytes};
    memset(rvt_mem_bytes, 0, sizeof(rvt_mem_bytes));
    rvemu_hart_init(&hart, RVT_MEM_BASE + RVT_HART_SCRATCH);
    hart.x[2] = a;
    hart.x[3] = b;
    rvt_put32(&hart, hart.pc, insn);
    if (rvemu_step(&hart, &mem) != RVEMU_STOP_NONE) return 0;
    return hart.x[3] == expect;
}

static int rvt_arith_kat(void)
{
    const uint64_t min64 = 0x8000000000000000ull, ones = UINT64_MAX;
    int ok = 1;
    ok &= rvt_rr_kat(rvt_r_insn(1, 4, 0x33), min64, ones, min64);
    ok &= rvt_rr_kat(rvt_r_insn(1, 4, 0x33), 77, 0, ones);
    ok &= rvt_rr_kat(rvt_r_insn(1, 5, 0x33), 77, 0, ones);
    ok &= rvt_rr_kat(rvt_r_insn(1, 6, 0x33), 1234, 0, 1234);
    ok &= rvt_rr_kat(rvt_r_insn(1, 1, 0x33), ones, ones, 0);
    ok &= rvt_rr_kat(rvt_r_insn(1, 3, 0x33), ones, ones, ones - 1u);
    ok &= rvt_rr_kat(rvt_r_insn(1, 0, 0x3b), 0x7fffffffu, 2, ones - 1u);
    ok &= rvt_rr_kat(rvt_r_insn(1, 4, 0x3b), 0x80000000u, ones, 0xffffffff80000000ull);
    if (!ok) printf("FAIL rvemu arithmetic known answers\n");
    return ok ? 0 : 1;
}

static int rvt_stop_kat(void)
{
    struct rvemu_hart hart;
    struct rvemu_mem mem = {.base = RVT_MEM_BASE, .size = RVT_MEM_SIZE, .bytes = rvt_mem_bytes};
    int ok = 1;
    memset(rvt_mem_bytes, 0, sizeof(rvt_mem_bytes));
    rvemu_hart_init(&hart, RVT_MEM_BASE + RVT_HART_SCRATCH);
    rvt_put32(&hart, hart.pc, 0x00000073u);
    ok &= rvemu_step(&hart, &mem) == RVEMU_STOP_ECALL && hart.pc == RVT_MEM_BASE + RVT_HART_SCRATCH;
    rvt_put32(&hart, hart.pc, 0x00100073u);
    ok &= rvemu_step(&hart, &mem) == RVEMU_STOP_EBREAK;
    rvt_put32(&hart, hart.pc, 0x00000000u);
    ok &= rvemu_step(&hart, &mem) == RVEMU_STOP_ILLEGAL;
    rvt_put32(&hart, hart.pc, 0x00002503u);

    ok &= rvemu_step(&hart, &mem) == RVEMU_STOP_OUT_OF_RANGE;
    hart.pc = RVT_MEM_BASE + 1u;
    ok &= rvemu_step(&hart, &mem) == RVEMU_STOP_MISALIGNED;
    hart.pc = RVT_MEM_BASE + 2u;
    ok &= rvemu_step(&hart, &mem) == RVEMU_STOP_ILLEGAL;
    if (!ok) printf("FAIL rvemu stop reasons\n");
    return ok ? 0 : 1;
}

/* OP-AMO word: funct5 in bits 31:27, funct3 2 selects .w. */
static uint32_t rvt_amo_insn(unsigned f5, unsigned rd, unsigned rs1, unsigned rs2)
{
    return (f5 << 27) | (rs2 << 20) | (rs1 << 15) | (2u << 12) | (rd << 7) | 0x2fu;
}

/* lr.w / sc.w pairing, a plain store clearing the reservation, and the
 * sign-extended .w result of an AMO. x5 holds the data address. */
static int rvt_amo_kat(void)
{
    struct rvemu_hart hart;
    struct rvemu_mem mem = {.base = RVT_MEM_BASE, .size = RVT_MEM_SIZE, .bytes = rvt_mem_bytes};
    const uint64_t data = RVT_MEM_BASE + 0x800u;
    int ok = 1;
    memset(rvt_mem_bytes, 0, sizeof(rvt_mem_bytes));
    rvemu_hart_init(&hart, RVT_MEM_BASE + RVT_HART_SCRATCH);
    hart.x[5] = data;
    hart.x[6] = 7;
    zcl_write_u32_le(&rvt_mem_bytes[data - RVT_MEM_BASE], 5);
    rvt_put32(&hart, hart.pc, rvt_amo_insn(0x02u, 7, 5, 0));
    ok &= rvemu_step(&hart, &mem) == RVEMU_STOP_NONE;
    rvt_put32(&hart, hart.pc, 0x0062a023u); /* sw x6, 0(x5) clears the reservation */
    ok &= rvemu_step(&hart, &mem) == RVEMU_STOP_NONE;
    rvt_put32(&hart, hart.pc, rvt_amo_insn(0x03u, 8, 5, 6));
    ok &= rvemu_step(&hart, &mem) == RVEMU_STOP_NONE && hart.x[8] == 1;
    ok &= zcl_read_u32_le(&rvt_mem_bytes[data - RVT_MEM_BASE]) == 7u;
    rvt_put32(&hart, hart.pc, rvt_amo_insn(0x02u, 7, 5, 0));
    ok &= rvemu_step(&hart, &mem) == RVEMU_STOP_NONE;
    rvt_put32(&hart, hart.pc, rvt_amo_insn(0x03u, 8, 5, 6));
    ok &= rvemu_step(&hart, &mem) == RVEMU_STOP_NONE && hart.x[8] == 0;
    ok &= zcl_read_u32_le(&rvt_mem_bytes[data - RVT_MEM_BASE]) == 7u;
    zcl_write_u32_le(&rvt_mem_bytes[data - RVT_MEM_BASE], 0x80000000u);
    rvt_put32(&hart, hart.pc, rvt_amo_insn(0x00u, 9, 5, 6));
    ok &= rvemu_step(&hart, &mem) == RVEMU_STOP_NONE && hart.x[9] == 0xffffffff80000000ull;
    ok &= zcl_read_u32_le(&rvt_mem_bytes[data - RVT_MEM_BASE]) == 0x80000007u;
    if (!ok) printf("FAIL rvemu atomic known answers\n");
    return ok ? 0 : 1;
}

static int rvt_csr_kat(void)
{
    struct rvemu_hart hart;
    struct rvemu_mem mem = {.base = RVT_MEM_BASE, .size = RVT_MEM_SIZE, .bytes = rvt_mem_bytes};
    int ok = 1;
    memset(rvt_mem_bytes, 0, sizeof(rvt_mem_bytes));
    rvemu_hart_init(&hart, RVT_MEM_BASE + RVT_HART_SCRATCH);
    rvt_put32(&hart, hart.pc, (0x340u << 20) | (5u << 15) | (5u << 12) | 0x73u);
    ok &= rvemu_step(&hart, &mem) == RVEMU_STOP_NONE && hart.csr.mscratch == 5;
    rvt_put32(&hart, hart.pc, (0x340u << 20) | (2u << 12) | (2u << 7) | 0x73u);
    ok &= rvemu_step(&hart, &mem) == RVEMU_STOP_NONE && hart.x[2] == 5;
    rvt_put32(&hart, hart.pc, (0x7c0u << 20) | (2u << 12) | (2u << 7) | 0x73u);
    ok &= rvemu_step(&hart, &mem) == RVEMU_STOP_ILLEGAL;
    hart.csr.mepc = RVT_MEM_BASE + 0x200u;
    rvt_put32(&hart, hart.pc, 0x30200073u);
    ok &= rvemu_step(&hart, &mem) == RVEMU_STOP_NONE && hart.pc == RVT_MEM_BASE + 0x200u;
    if (!ok) printf("FAIL rvemu csr and mret\n");
    return ok ? 0 : 1;
}

/* Zicsr: csrrs/csrrc (and the immediate forms) skip the write only when the ENCODED source field
 * is zero (x0 or uimm 0), not when the register's value happens to be 0. mhartid is read-only,
 * so an attempted write is ILLEGAL and must leave rd, pc and instret untouched. */
static int rvt_csr_case(uint32_t insn, int want_ok)
{
    struct rvemu_hart hart;
    struct rvemu_mem mem = {.base = RVT_MEM_BASE, .size = RVT_MEM_SIZE, .bytes = rvt_mem_bytes};
    const uint64_t sentinel = 0x5a5a5a5a5a5a5a5aull;
    memset(rvt_mem_bytes, 0, sizeof(rvt_mem_bytes));
    rvemu_hart_init(&hart, RVT_MEM_BASE + RVT_HART_SCRATCH);
    uint64_t pc = hart.pc;
    hart.x[1] = 0;
    hart.x[2] = sentinel;
    rvt_put32(&hart, pc, insn);
    enum rvemu_stop stop = rvemu_step(&hart, &mem);
    if (want_ok)
        return stop == RVEMU_STOP_NONE && hart.x[2] == 0 && hart.pc == pc + 4u && hart.instret == 1;
    return stop == RVEMU_STOP_ILLEGAL && hart.x[2] == sentinel && hart.pc == pc && hart.instret == 0;
}

static int rvt_csr_zero_source_kat(void)
{
    int ok = 1;
    ok &= rvt_csr_case(0xf140a173u, 0); /* csrrs x2,mhartid,x1 with x1 == 0: the write is encoded */
    ok &= rvt_csr_case(0xf140b173u, 0); /* csrrc x2,mhartid,x1 with x1 == 0 */
    ok &= rvt_csr_case(0xf1402173u, 1); /* csrrs x2,mhartid,x0: no write */
    ok &= rvt_csr_case(0xf1403173u, 1); /* csrrc x2,mhartid,x0 */
    ok &= rvt_csr_case(0xf1406173u, 1); /* csrrsi uimm 0 */
    ok &= rvt_csr_case(0xf1407173u, 1); /* csrrci uimm 0 */
    ok &= rvt_csr_case(0xf140e173u, 0); /* csrrsi uimm 1 */
    ok &= rvt_csr_case(0xf140f173u, 0); /* csrrci uimm 1 */
    if (!ok) printf("FAIL rvemu csr write suppression follows the encoded source field\n");
    return ok ? 0 : 1;
}

static void rvt_put16(struct rvemu_hart *hart, uint64_t addr, uint16_t half)
{
    zcl_write_u16_le(&rvt_mem_bytes[addr - RVT_MEM_BASE], half);
    rvemu_icache_note_store(hart, addr, 2u);
}

/* Twenty hand-picked RV64C encodings, each with its 32-bit expansion as the
 * GNU/LLVM assemblers emit it, plus four reserved encodings. */
static int rvt_rvc_table(void)
{
    static const struct {
        uint16_t c;
        uint32_t insn;
    } rows[20] = {
        {0x0808u, 0x01010513u}, {0x41c8u, 0x0045a503u}, {0x6690u, 0x0086b603u},
        {0xeb98u, 0x00e7b823u}, {0x1541u, 0xff050513u}, {0x2585u, 0x0015859bu},
        {0x57c1u, 0xff000793u}, {0x7405u, 0xfffe1437u}, {0x617du, 0x1f010113u},
        {0x8031u, 0x00c45413u}, {0x8431u, 0x40c45413u}, {0x983du, 0xfef47413u},
        {0x8c89u, 0x40a484b3u}, {0x9c89u, 0x40a484bbu}, {0x0412u, 0x00441413u},
        {0x8082u, 0x00008067u}, {0x9282u, 0x000280e7u}, {0x952eu, 0x00b50533u},
        {0x4532u, 0x00c12503u}, {0xe42au, 0x00a13423u},
    };
    static const uint16_t reserved[4] = {0x0000u, 0x4002u, 0x6101u, 0x8002u};
    int ok = 1;
    uint32_t out = 0;
    for (unsigned k = 0; k < 20u; k++)
        ok &= rvemu_rvc_expand(rows[k].c, &out) == 0 && out == rows[k].insn;
    for (unsigned k = 0; k < 4u; k++) ok &= rvemu_rvc_expand(reserved[k], &out) != 0;
    if (!ok) printf("FAIL rvemu compressed expansion table\n");
    return ok ? 0 : 1;
}

/* Compressed fetch advances pc by 2, mixes with 32-bit fetch, and c.jalr
 * links pc + 2. An all-zero halfword is illegal and leaves pc in place. */
static int rvt_rvc_step_kat(void)
{
    struct rvemu_hart hart;
    struct rvemu_mem mem = {.base = RVT_MEM_BASE, .size = RVT_MEM_SIZE, .bytes = rvt_mem_bytes};
    const uint64_t at = RVT_MEM_BASE + RVT_HART_SCRATCH;
    int ok = 1;
    memset(rvt_mem_bytes, 0, sizeof(rvt_mem_bytes));
    rvemu_hart_init(&hart, at);
    rvt_put16(&hart, at, 0x4515u);
    rvt_put16(&hart, at + 2u, 0x0505u);
    rvt_put32(&hart, at + 4u, 0x00150513u);
    ok &= rvemu_step(&hart, &mem) == RVEMU_STOP_NONE && hart.pc == at + 2u && hart.x[10] == 5;
    ok &= rvemu_step(&hart, &mem) == RVEMU_STOP_NONE && hart.pc == at + 4u && hart.x[10] == 6;
    ok &= rvemu_step(&hart, &mem) == RVEMU_STOP_NONE && hart.pc == at + 8u && hart.x[10] == 7;
    rvt_put16(&hart, hart.pc, 0x0000u);
    ok &= rvemu_step(&hart, &mem) == RVEMU_STOP_ILLEGAL && hart.pc == at + 8u;
    rvt_put16(&hart, hart.pc, 0x9282u);
    hart.x[5] = RVT_MEM_BASE + 0x400u;
    ok &= rvemu_step(&hart, &mem) == RVEMU_STOP_NONE && hart.x[1] == at + 10u;
    ok &= hart.pc == RVT_MEM_BASE + 0x400u;
    if (!ok) printf("FAIL rvemu compressed fetch\n");
    return ok ? 0 : 1;
}

/* addi a0, a0, 1. Two fetches of that parcel with no store between them
 * count one fast hit. A store elsewhere forces one re-read. A host edit of
 * the parcel, followed by an unrelated store, is the instruction that runs. */
static int rvt_icache_fast_kat(void)
{
    struct rvemu_hart hart;
    struct rvemu_mem mem = {.base = RVT_MEM_BASE, .size = RVT_MEM_SIZE, .bytes = rvt_mem_bytes};
    const uint64_t at = RVT_MEM_BASE + RVT_HART_SCRATCH;
    const uint32_t addi = 0x00150513u;
    const uint32_t nop = 0x00000013u;
    uint64_t fast = 0;
    int ok = 1;
    memset(rvt_mem_bytes, 0, sizeof(rvt_mem_bytes));
    rvemu_hart_init(&hart, at);
    hart.x[10] = 0;
    rvt_put32(&hart, at, addi);
    ok &= rvemu_step(&hart, &mem) == RVEMU_STOP_NONE && hart.x[10] == 1;
    fast = hart.icache_fast;
    hart.pc = at;
    ok &= rvemu_step(&hart, &mem) == RVEMU_STOP_NONE && hart.x[10] == 2;
    ok &= hart.icache_fast == fast + 1u;
    fast = hart.icache_fast;
    rvemu_icache_note_store(&hart, at + 64u, 4u);
    hart.pc = at;
    ok &= rvemu_step(&hart, &mem) == RVEMU_STOP_NONE && hart.x[10] == 3;
    ok &= hart.icache_fast == fast;
    hart.pc = at;
    ok &= rvemu_step(&hart, &mem) == RVEMU_STOP_NONE && hart.x[10] == 4;
    ok &= hart.icache_fast == fast + 1u;
    zcl_write_u32_le(&rvt_mem_bytes[at - RVT_MEM_BASE], nop);
    rvemu_icache_note_store(&hart, at + 64u, 4u);
    hart.pc = at;
    ok &= rvemu_step(&hart, &mem) == RVEMU_STOP_NONE && hart.x[10] == 4;
    if (!ok) printf("FAIL rvemu decode fast path re-reads after a store\n");
    else printf("    rvemu icache_fast=%llu\n", (unsigned long long)hart.icache_fast);
    return ok ? 0 : 1;
}

/* F and D known answers: f1 and f2 are the sources, f3 or x3 the result. */
#define RVT_FS_INITIAL (1ull << 13)
#define RVT_NX 1u
#define RVT_NV 16u
#define RVT_QNAN_S 0xffffffff7fc00000ull
#define RVT_QNAN_D 0x7ff8000000000000ull

static uint32_t rvt_fp_insn(unsigned f7, unsigned rs2, unsigned rm, unsigned opc)
{
    return (f7 << 25) | (rs2 << 20) | (1u << 15) | (rm << 12) | (3u << 7) | opc;
}

static void rvt_fp_prep(struct rvemu_hart *hart, uint64_t f1, uint64_t f2)
{
    memset(rvt_mem_bytes, 0, sizeof(rvt_mem_bytes));
    rvemu_hart_init(hart, RVT_MEM_BASE + RVT_HART_SCRATCH);
    hart->csr.mstatus = RVT_FS_INITIAL;
    hart->f[1] = f1;
    hart->f[2] = f2;
    hart->f[0] = f1;
}

/* Runs insn (rs1 = f1 or x1, rs2 = f2, rd = f3 or x3); true when it retired
 * with the wanted destination (f3, or x3 when to_x) and fflags. */
static int rvt_fp_case(uint64_t f1, uint64_t f2, uint32_t insn, int to_x, uint64_t want,
                       unsigned flags)
{
    struct rvemu_hart hart;
    struct rvemu_mem mem = {.base = RVT_MEM_BASE, .size = RVT_MEM_SIZE, .bytes = rvt_mem_bytes};
    rvt_fp_prep(&hart, f1, f2);
    rvt_put32(&hart, hart.pc, insn);
    if (rvemu_step(&hart, &mem) != RVEMU_STOP_NONE) return 0;
    uint64_t got = to_x ? hart.x[3] : hart.f[3];
    return got == want && (hart.fcsr & 31u) == flags;
}

#define RVT_FADD_S 0x00u
#define RVT_FADD_D 0x01u
#define RVT_FSQRT_S 0x2cu
#define RVT_FCVT_W_D 0x61u
#define RVT_FCVT_WU_D 0x61u
#define RVT_FMV_X_W 0x70u
#define RVT_FSGNJ_S 0x10u
#define RVT_RNE 0u
#define RVT_RMM 4u
#define RVT_RUP 3u
#define RVT_DYN 7u

static int rvt_fp_rmm_kat(void)
{
    const uint64_t one = 0x3ff0000000000000ull, tiny = 0x3ca0000000000000ull; /* 1.0, 2^-53 */
    int ok = 1;
    ok &= rvt_fp_case(one, tiny, rvt_fp_insn(RVT_FADD_D, 2, RVT_RMM, 0x53), 0,
                      0x3ff0000000000001ull, RVT_NX);
    ok &= rvt_fp_case(one, tiny, rvt_fp_insn(RVT_FADD_D, 2, RVT_RNE, 0x53), 0, one, RVT_NX);
    ok &= rvt_fp_case(0xffffffff3f800000ull, 0xffffffff33800000ull,
                      rvt_fp_insn(RVT_FADD_S, 2, RVT_RMM, 0x53), 0, 0xffffffff3f800001ull, RVT_NX);
    ok &= rvt_fp_case(0xffffffff3f800000ull, 0xffffffff33800000ull,
                      rvt_fp_insn(RVT_FADD_S, 2, RVT_RUP, 0x53), 0, 0xffffffff3f800001ull, RVT_NX);
    ok &= rvt_fp_case(0x4004000000000000ull, 0, rvt_fp_insn(RVT_FCVT_W_D, 0, RVT_RMM, 0x53), 1, 3, RVT_NX);
    ok &= rvt_fp_case(0x4004000000000000ull, 0, rvt_fp_insn(RVT_FCVT_W_D, 0, RVT_RNE, 0x53), 1, 2, RVT_NX);
    ok &= rvt_fp_case(0xc004000000000000ull, 0, rvt_fp_insn(RVT_FCVT_W_D, 0, RVT_RMM, 0x53), 1,
                      0xfffffffffffffffdull, RVT_NX);
    return ok;
}

static int rvt_fp_nan_kat(void)
{
    const uint64_t one = 0x3ff0000000000000ull, pinf = 0x7ff0000000000000ull;
    int ok = 1;
    ok &= rvt_fp_case(0x7ff8000000000123ull, one, rvt_fp_insn(RVT_FADD_D, 2, RVT_RNE, 0x53), 0,
                      RVT_QNAN_D, 0);
    ok &= rvt_fp_case(0x7ff0000000000001ull, one, rvt_fp_insn(RVT_FADD_D, 2, RVT_RNE, 0x53), 0,
                      RVT_QNAN_D, RVT_NV);
    ok &= rvt_fp_case(pinf, pinf ^ (1ull << 63), rvt_fp_insn(RVT_FADD_D, 2, RVT_RNE, 0x53), 0,
                      RVT_QNAN_D, RVT_NV);
    ok &= rvt_fp_case(0xffffffffbf800000ull, 0, rvt_fp_insn(RVT_FSQRT_S, 0, RVT_RNE, 0x53), 0,
                      RVT_QNAN_S, RVT_NV);
    return ok;
}

static int rvt_fp_box_kat(void)
{
    const uint64_t one_s = 0xffffffff3f800000ull, two_s = 0xffffffff40000000ull;
    int ok = 1;
    /* A properly boxed 1.0 + 1.0 is 2.0; an unboxed operand reads as the canonical NaN. */
    ok &= rvt_fp_case(one_s, one_s, rvt_fp_insn(RVT_FADD_S, 2, RVT_RNE, 0x53), 0, two_s, 0);
    ok &= rvt_fp_case(0x000000003f800000ull, one_s, rvt_fp_insn(RVT_FADD_S, 2, RVT_RNE, 0x53), 0,
                      RVT_QNAN_S, 0);
    ok &= rvt_fp_case(0xfffffffe3f800000ull, one_s, rvt_fp_insn(RVT_FSGNJ_S, 2, 0, 0x53), 0,
                      RVT_QNAN_S, 0);
    /* fmv.x.w moves the raw low word, sign-extended, with no box check. */
    ok &= rvt_fp_case(0x00000000bf800000ull, 0, rvt_fp_insn(RVT_FMV_X_W, 0, 0, 0x53), 1,
                      0xffffffffbf800000ull, 0);
    return ok;
}

static int rvt_fp_cvt_kat(void)
{
    const uint64_t nan = 0x7ff8000000000000ull, pinf = 0x7ff0000000000000ull;
    int ok = 1;
    ok &= rvt_fp_case(nan, 0, rvt_fp_insn(RVT_FCVT_W_D, 0, RVT_RNE, 0x53), 1, 0x7fffffffull, RVT_NV);
    ok &= rvt_fp_case(pinf, 0, rvt_fp_insn(RVT_FCVT_W_D, 0, RVT_RNE, 0x53), 1, 0x7fffffffull, RVT_NV);
    ok &= rvt_fp_case(pinf | (1ull << 63), 0, rvt_fp_insn(RVT_FCVT_W_D, 0, RVT_RNE, 0x53), 1,
                      0xffffffff80000000ull, RVT_NV);
    ok &= rvt_fp_case(nan, 0, rvt_fp_insn(RVT_FCVT_WU_D, 1, RVT_RNE, 0x53), 1, UINT64_MAX, RVT_NV);
    return ok;
}

/* Dynamic rounding reads frm; FS Off makes FP and the FP CSRs illegal; any FP
 * write sets FS to Dirty. */
static int rvt_fp_state_kat(void)
{
    struct rvemu_hart hart;
    struct rvemu_mem mem = {.base = RVT_MEM_BASE, .size = RVT_MEM_SIZE, .bytes = rvt_mem_bytes};
    int ok = 1;
    rvt_fp_prep(&hart, 0x3ff0000000000000ull, 0x3ca0000000000000ull);
    hart.fcsr = RVT_RMM << 5;
    rvt_put32(&hart, hart.pc, rvt_fp_insn(RVT_FADD_D, 2, RVT_DYN, 0x53));
    ok &= rvemu_step(&hart, &mem) == RVEMU_STOP_NONE && hart.f[3] == 0x3ff0000000000001ull;
    ok &= (hart.csr.mstatus >> 13 & 3u) == 3u && (hart.csr.mstatus >> 63) == 1u;
    rvt_fp_prep(&hart, 0, 0);
    hart.csr.mstatus = 0;
    rvt_put32(&hart, hart.pc, rvt_fp_insn(RVT_FADD_D, 2, RVT_RNE, 0x53));
    ok &= rvemu_step(&hart, &mem) == RVEMU_STOP_ILLEGAL;
    rvt_put32(&hart, hart.pc, (0x003u << 20) | (2u << 12) | (3u << 7) | 0x73u);
    ok &= rvemu_step(&hart, &mem) == RVEMU_STOP_ILLEGAL;
    return ok;
}

static int rvt_fp_kat(void)
{
    int ok = rvt_fp_rmm_kat() & rvt_fp_nan_kat() & rvt_fp_box_kat() & rvt_fp_cvt_kat() &
             rvt_fp_state_kat();
    if (!ok) printf("FAIL rvemu F and D known answers\n");
    return ok ? 0 : 1;
}

/* Privileged architecture known answers. Each case starts a MACHINE-profile
 * hart at a chosen privilege, puts one instruction at pc and steps once. */
#define RVT_PC (RVT_MEM_BASE + RVT_HART_SCRATCH)
#define RVT_MTVEC (RVT_MEM_BASE + 0x800u)
#define RVT_STVEC (RVT_MEM_BASE + 0x400u)
#define RVT_SIE_BIT (1ull << 1)
#define RVT_MIE_BIT (1ull << 3)
#define RVT_SPIE_BIT (1ull << 5)
#define RVT_MPIE_BIT (1ull << 7)
#define RVT_SPP_BIT (1ull << 8)
#define RVT_MPP_S (1ull << 11)
#define RVT_MPP_M (3ull << 11)
#define RVT_MPP_MASK (3ull << 11)
#define RVT_MPRV_BIT (1ull << 17)
#define RVT_TVM_BIT (1ull << 20)
#define RVT_TW_BIT (1ull << 21)
#define RVT_TSR_BIT (1ull << 22)
#define RVT_IRQ_BIT (1ull << 63)
#define RVT_ECALL 0x00000073u
#define RVT_MRET 0x30200073u
#define RVT_SRET 0x10200073u
#define RVT_WFI 0x10500073u
#define RVT_NOP 0x00000013u
#define RVT_CAUSE_ILLEGAL 2u

static void rvt_mach(struct rvemu_hart *h, unsigned priv, uint32_t insn)
{
    memset(rvt_mem_bytes, 0, sizeof(rvt_mem_bytes));
    rvemu_hart_init_machine(h, RVT_PC);
    h->priv = priv;
    h->csr.stvec = RVT_STVEC;
    h->csr.mtvec = RVT_MTVEC;
    rvt_put32(h, RVT_PC, insn);
}

static enum rvemu_stop rvt_mstep(struct rvemu_hart *h)
{
    struct rvemu_mem mem = {.base = RVT_MEM_BASE, .size = RVT_MEM_SIZE, .bytes = rvt_mem_bytes};
    return rvemu_step(h, &mem);
}

static uint32_t rvt_csr_insn(unsigned f3, unsigned csr, unsigned rd, unsigned rs1)
{
    return (csr << 20) | (rs1 << 15) | (f3 << 12) | (rd << 7) | 0x73u;
}

/* The trap landed in S: privilege, vector, epc, cause, tval and SPP/SPIE/SIE. */
static int rvt_trapped_s(const struct rvemu_hart *h, uint64_t cause, uint64_t tval, int spp)
{
    return h->priv == RVEMU_PRIV_S && h->csr.scause == cause && h->csr.stval == tval &&
           h->csr.sepc == RVT_PC && ((h->csr.mstatus & RVT_SPP_BIT) != 0) == spp &&
           h->csr.mepc == 0 && h->csr.mcause == 0;
}

static int rvt_trapped_m(const struct rvemu_hart *h, uint64_t cause, uint64_t tval, uint64_t mpp)
{
    return h->priv == RVEMU_PRIV_M && h->pc == RVT_MTVEC && h->csr.mcause == cause &&
           h->csr.mtval == tval && h->csr.mepc == RVT_PC &&
           (h->csr.mstatus & RVT_MPP_MASK) == mpp && h->csr.scause == 0;
}

/* ecall from U with medeleg bit 8 set lands in S; without it, in M. */
static int rvt_deleg_ecall_kat(void)
{
    struct rvemu_hart h;
    int ok = 1;
    rvt_mach(&h, RVEMU_PRIV_U, RVT_ECALL);
    h.csr.medeleg = 1u << 8;
    ok &= rvt_mstep(&h) == RVEMU_STOP_NONE && h.pc == RVT_STVEC && rvt_trapped_s(&h, 8, 0, 0);
    rvt_mach(&h, RVEMU_PRIV_U, RVT_ECALL);
    ok &= rvt_mstep(&h) == RVEMU_STOP_NONE && rvt_trapped_m(&h, 8, 0, 0);
    rvt_mach(&h, RVEMU_PRIV_S, RVT_ECALL);
    h.csr.medeleg = 1u << 9;
    ok &= rvt_mstep(&h) == RVEMU_STOP_NONE && h.pc == RVT_STVEC && rvt_trapped_s(&h, 9, 0, 1);
    rvt_mach(&h, RVEMU_PRIV_M, RVT_ECALL);
    h.csr.medeleg = UINT64_MAX;
    ok &= rvt_mstep(&h) == RVEMU_STOP_NONE && rvt_trapped_m(&h, 11, 0, RVT_MPP_M);
    rvt_mach(&h, RVEMU_PRIV_S, 0x00000000u); /* reserved encoding: illegal, tval is the bits */
    ok &= rvt_mstep(&h) == RVEMU_STOP_NONE && rvt_trapped_m(&h, RVT_CAUSE_ILLEGAL, 0, RVT_MPP_S);
    if (!ok) printf("FAIL rvemu delegated ecall\n");
    return ok ? 0 : 1;
}

/* mret and sret restore privilege and the interrupt-enable stack, and are
 * illegal below their level or under TSR. */
static int rvt_xret_kat(void)
{
    struct rvemu_hart h;
    int ok = 1;
    rvt_mach(&h, RVEMU_PRIV_M, RVT_MRET);
    h.csr.mstatus |= RVT_MPP_S | RVT_MPIE_BIT | RVT_MPRV_BIT;
    h.csr.mepc = RVT_MEM_BASE + 0x300u;
    ok &= rvt_mstep(&h) == RVEMU_STOP_NONE && h.priv == RVEMU_PRIV_S && h.pc == RVT_MEM_BASE + 0x300u;
    ok &= (h.csr.mstatus & (RVT_MIE_BIT | RVT_MPIE_BIT | RVT_MPP_MASK | RVT_MPRV_BIT)) ==
          (RVT_MIE_BIT | RVT_MPIE_BIT);
    rvt_mach(&h, RVEMU_PRIV_S, RVT_SRET);
    h.csr.mstatus |= RVT_SPIE_BIT;
    h.csr.sepc = RVT_MEM_BASE + 0x340u;
    ok &= rvt_mstep(&h) == RVEMU_STOP_NONE && h.priv == RVEMU_PRIV_U && h.pc == RVT_MEM_BASE + 0x340u;
    ok &= (h.csr.mstatus & (RVT_SIE_BIT | RVT_SPIE_BIT | RVT_SPP_BIT)) == (RVT_SIE_BIT | RVT_SPIE_BIT);
    rvt_mach(&h, RVEMU_PRIV_M, RVT_SRET); /* sret from M with SPP set returns to S */
    h.csr.mstatus |= RVT_SPP_BIT;
    h.csr.sepc = RVT_MEM_BASE + 0x340u;
    ok &= rvt_mstep(&h) == RVEMU_STOP_NONE && h.priv == RVEMU_PRIV_S;
    rvt_mach(&h, RVEMU_PRIV_S, RVT_MRET);
    ok &= rvt_mstep(&h) == RVEMU_STOP_NONE && rvt_trapped_m(&h, RVT_CAUSE_ILLEGAL, RVT_MRET, RVT_MPP_S);
    rvt_mach(&h, RVEMU_PRIV_S, RVT_SRET);
    h.csr.mstatus |= RVT_TSR_BIT;
    ok &= rvt_mstep(&h) == RVEMU_STOP_NONE && rvt_trapped_m(&h, RVT_CAUSE_ILLEGAL, RVT_SRET, RVT_MPP_S);
    rvt_mach(&h, RVEMU_PRIV_U, RVT_SRET);
    ok &= rvt_mstep(&h) == RVEMU_STOP_NONE && rvt_trapped_m(&h, RVT_CAUSE_ILLEGAL, RVT_SRET, 0);
    if (!ok) printf("FAIL rvemu mret and sret\n");
    return ok ? 0 : 1;
}

/* A supervisor timer interrupt delegated by mideleg is taken in S after
 * rvemu_set_irq, before the next instruction, honouring SIE, mie, the vector
 * mode and the M-over-S priority. */
static int rvt_timer_irq_kat(void)
{
    struct rvemu_hart h;
    const uint64_t stip = 1ull << RVEMU_IRQ_STIP;
    int ok = 1;
    rvt_mach(&h, RVEMU_PRIV_S, RVT_NOP);
    h.csr.mideleg = stip;
    h.csr.mie = stip;
    h.csr.mstatus |= RVT_SIE_BIT;
    ok &= rvemu_set_irq(&h, RVEMU_IRQ_STIP, 1) == 0;
    ok &= rvt_mstep(&h) == RVEMU_STOP_NONE && h.instret == 0 && h.pc == RVT_STVEC;
    ok &= rvt_trapped_s(&h, RVT_IRQ_BIT | RVEMU_IRQ_STIP, 0, 1);
    ok &= (h.csr.mstatus & (RVT_SIE_BIT | RVT_SPIE_BIT)) == RVT_SPIE_BIT;
    rvt_mach(&h, RVEMU_PRIV_S, RVT_NOP); /* SIE clear in S: not taken */
    h.csr.mideleg = stip;
    h.csr.mie = stip;
    rvemu_set_irq(&h, RVEMU_IRQ_STIP, 1);
    ok &= rvt_mstep(&h) == RVEMU_STOP_NONE && h.instret == 1 && h.pc == RVT_PC + 4u;
    rvt_mach(&h, RVEMU_PRIV_U, RVT_NOP); /* in U a delegated interrupt is always enabled */
    h.csr.mideleg = stip;
    h.csr.mie = stip;
    h.csr.stvec = RVT_STVEC | 1u; /* vectored */
    rvemu_set_irq(&h, RVEMU_IRQ_STIP, 1);
    ok &= rvt_mstep(&h) == RVEMU_STOP_NONE && h.priv == RVEMU_PRIV_S &&
          h.pc == RVT_STVEC + 4u * RVEMU_IRQ_STIP;
    rvt_mach(&h, RVEMU_PRIV_M, RVT_NOP); /* a delegated interrupt never fires in M */
    h.csr.mideleg = stip;
    h.csr.mie = stip;
    h.csr.mstatus |= RVT_MIE_BIT | RVT_SIE_BIT;
    rvemu_set_irq(&h, RVEMU_IRQ_STIP, 1);
    ok &= rvt_mstep(&h) == RVEMU_STOP_NONE && h.priv == RVEMU_PRIV_M && h.instret == 1;
    rvt_mach(&h, RVEMU_PRIV_S, RVT_NOP); /* MTIP (not delegated) beats STIP and ignores SIE */
    h.csr.mideleg = stip;
    h.csr.mie = stip | (1ull << RVEMU_IRQ_MTIP);
    h.csr.mstatus |= RVT_SIE_BIT;
    rvemu_set_irq(&h, RVEMU_IRQ_STIP, 1);
    rvemu_set_irq(&h, RVEMU_IRQ_MTIP, 1);
    ok &= rvt_mstep(&h) == RVEMU_STOP_NONE && h.priv == RVEMU_PRIV_M &&
          h.csr.mcause == (RVT_IRQ_BIT | RVEMU_IRQ_MTIP) && h.pc == RVT_MTVEC;
    ok &= rvemu_set_irq(&h, 2u, 1) == -1 && rvemu_set_irq(NULL, RVEMU_IRQ_STIP, 1) == -1;
    if (!ok) printf("FAIL rvemu timer interrupt in S\n");
    return ok ? 0 : 1;
}

/* wfi: illegal in U, illegal below M under TW, otherwise it retires and the
 * hart idles (STOP_WFI) until an enabled interrupt is pending, taken or not. */
static int rvt_wfi_kat(void)
{
    struct rvemu_hart h;
    int ok = 1;
    rvt_mach(&h, RVEMU_PRIV_S, RVT_WFI);
    h.csr.mstatus |= RVT_TW_BIT;
    ok &= rvt_mstep(&h) == RVEMU_STOP_NONE && rvt_trapped_m(&h, RVT_CAUSE_ILLEGAL, RVT_WFI, RVT_MPP_S);
    rvt_mach(&h, RVEMU_PRIV_U, RVT_WFI);
    ok &= rvt_mstep(&h) == RVEMU_STOP_NONE && rvt_trapped_m(&h, RVT_CAUSE_ILLEGAL, RVT_WFI, 0);
    rvt_mach(&h, RVEMU_PRIV_M, RVT_WFI);
    h.csr.mstatus |= RVT_TW_BIT;
    ok &= rvt_mstep(&h) == RVEMU_STOP_NONE && h.idle == 1 && h.pc == RVT_PC + 4u;
    ok &= rvt_mstep(&h) == RVEMU_STOP_WFI && h.pc == RVT_PC + 4u;
    h.csr.mie = 1ull << RVEMU_IRQ_SSIP;
    rvemu_set_irq(&h, RVEMU_IRQ_SSIP, 1); /* pending and enabled, MIE clear: wakes, no trap */
    ok &= rvt_mstep(&h) == RVEMU_STOP_NONE && h.idle == 0 && h.priv == RVEMU_PRIV_M;
    if (!ok) printf("FAIL rvemu wfi\n");
    return ok ? 0 : 1;
}

/* One CSR instruction at the given privilege: true when it trapped illegal. */
static int rvt_csr_illegal(unsigned priv, uint32_t insn, uint64_t mstatus_set, uint64_t counteren)
{
    struct rvemu_hart h;
    rvt_mach(&h, priv, insn);
    h.csr.mstatus |= mstatus_set;
    h.csr.mcounteren = counteren;
    h.csr.scounteren = counteren;
    return rvt_mstep(&h) == RVEMU_STOP_NONE && h.csr.mcause == RVT_CAUSE_ILLEGAL &&
           h.csr.mtval == insn && h.pc == RVT_MTVEC;
}

static int rvt_csr_ok(unsigned priv, uint32_t insn, uint64_t counteren)
{
    struct rvemu_hart h;
    rvt_mach(&h, priv, insn);
    h.csr.mcounteren = counteren;
    h.csr.scounteren = counteren;
    return rvt_mstep(&h) == RVEMU_STOP_NONE && h.pc == RVT_PC + 4u && h.csr.mcause == 0;
}

static int rvt_csr_priv_kat(void)
{
    const uint32_t rd_mstatus = rvt_csr_insn(2, 0x300, 5, 0), rd_sstatus = rvt_csr_insn(2, 0x100, 5, 0);
    const uint32_t wr_cycle = rvt_csr_insn(1, 0xc00, 5, 0), rd_cycle = rvt_csr_insn(2, 0xc00, 5, 0);
    const uint32_t wr_mhartid = rvt_csr_insn(1, 0xf14, 5, 0), rd_satp = rvt_csr_insn(2, 0x180, 5, 0);
    const uint32_t rd_hyp = rvt_csr_insn(2, 0x600, 5, 0);
    int ok = 1;
    ok &= rvt_csr_illegal(RVEMU_PRIV_U, rd_mstatus, 0, 0) && rvt_csr_illegal(RVEMU_PRIV_S, rd_mstatus, 0, 0);
    ok &= rvt_csr_illegal(RVEMU_PRIV_U, rd_sstatus, 0, 0) && rvt_csr_ok(RVEMU_PRIV_S, rd_sstatus, 0);
    ok &= rvt_csr_ok(RVEMU_PRIV_M, rd_mstatus, 0);
    ok &= rvt_csr_illegal(RVEMU_PRIV_M, wr_cycle, 0, 1) && rvt_csr_illegal(RVEMU_PRIV_M, wr_mhartid, 0, 0);
    ok &= rvt_csr_ok(RVEMU_PRIV_M, rd_cycle, 0) && rvt_csr_illegal(RVEMU_PRIV_S, rd_cycle, 0, 0);
    ok &= rvt_csr_ok(RVEMU_PRIV_S, rd_cycle, 1) && rvt_csr_ok(RVEMU_PRIV_U, rd_cycle, 1);
    ok &= rvt_csr_ok(RVEMU_PRIV_S, rd_satp, 0) && rvt_csr_illegal(RVEMU_PRIV_S, rd_satp, RVT_TVM_BIT, 0);
    ok &= rvt_csr_ok(RVEMU_PRIV_M, rd_satp, 0) && rvt_csr_illegal(RVEMU_PRIV_M, rd_hyp, 0, 0);
    if (!ok) printf("FAIL rvemu csr privilege violations\n");
    return ok ? 0 : 1;
}

/* Reads one CSR through a csrrs at M and returns its value in x5. */
static uint64_t rvt_csr_val(struct rvemu_hart *h, unsigned csr)
{
    rvt_put32(h, h->pc, rvt_csr_insn(2, csr, 5, 0));
    return rvt_mstep(h) == RVEMU_STOP_NONE ? h->x[5] : UINT64_MAX;
}

static void rvt_csr_set(struct rvemu_hart *h, unsigned csr, uint64_t val)
{
    h->x[6] = val;
    rvt_put32(h, h->pc, rvt_csr_insn(1, csr, 0, 6));
    (void)rvt_mstep(h);
}

/* WARL behaviour: fixed UXL/SXL, the sstatus view, reserved MPP and MODE
 * values, mtvec modes, misa, mideleg/medeleg masks, mip/sip write rules. */
static int rvt_warl_kat(void)
{
    struct rvemu_hart h;
    const uint64_t xl = (2ull << 32) | (2ull << 34);
    int ok = 1;
    rvt_mach(&h, RVEMU_PRIV_M, RVT_NOP);
    ok &= (rvt_csr_val(&h, 0x300) & ~(3ull << 13)) == xl;
    rvt_csr_set(&h, 0x300, UINT64_MAX);
    ok &= (rvt_csr_val(&h, 0x300) & (RVT_MPP_MASK | (3ull << 32) | (3ull << 34))) == (RVT_MPP_M | xl);
    ok &= (rvt_csr_val(&h, 0x300) >> 63) == 1u && (rvt_csr_val(&h, 0x100) & RVT_MIE_BIT) == 0;
    ok &= (rvt_csr_val(&h, 0x100) & (3ull << 32)) == (2ull << 32);
    rvt_csr_set(&h, 0x300, 2ull << 11); /* MPP = 2 is reserved: the old field (3) stays */
    ok &= (rvt_csr_val(&h, 0x300) & RVT_MPP_MASK) == RVT_MPP_M;
    rvt_csr_set(&h, 0x305, RVT_MTVEC | 3u); /* mode 3 reserved: mode stays direct */
    ok &= rvt_csr_val(&h, 0x305) == RVT_MTVEC;
    rvt_csr_set(&h, 0x305, RVT_MTVEC | 1u);
    ok &= rvt_csr_val(&h, 0x305) == (RVT_MTVEC | 1u);
    rvt_csr_set(&h, 0x180, (9ull << 60) | 0x1234u); /* any MODE but Bare and Sv39: unchanged */
    ok &= rvt_csr_val(&h, 0x180) == 0;
    rvt_csr_set(&h, 0x180, UINT64_MAX & ~(7ull << 60)); /* Sv39: MODE and PPN stick, ASID is zero */
    ok &= rvt_csr_val(&h, 0x180) == ((8ull << 60) | 0xfffffffffffull);
    rvt_csr_set(&h, 0x180, (10ull << 60) | 0x77u); /* a probe of a larger mode reads back the old value */
    ok &= rvt_csr_val(&h, 0x180) == ((8ull << 60) | 0xfffffffffffull);
    rvt_csr_set(&h, 0x180, 0x55u); /* back to Bare */
    ok &= rvt_csr_val(&h, 0x180) == 0x55u;
    rvt_csr_set(&h, 0x180, 0);
    rvt_csr_set(&h, 0x301, 0);
    ok &= rvt_csr_val(&h, 0x301) == 0x800000000014112Dull;
    rvt_csr_set(&h, 0x303, UINT64_MAX);
    rvt_csr_set(&h, 0x302, UINT64_MAX);
    ok &= rvt_csr_val(&h, 0x303) == 0x222u && rvt_csr_val(&h, 0x302) == 0xb3ffu;
    rvt_csr_set(&h, 0x344, UINT64_MAX); /* M writes SSIP, STIP, SEIP only */
    ok &= rvt_csr_val(&h, 0x344) == 0x222u && rvt_csr_val(&h, 0x144) == 0x222u;
    rvt_csr_set(&h, 0x302, 0);
    rvt_csr_set(&h, 0x303, 0);
    ok &= rvt_csr_val(&h, 0x144) == 0; /* sip shows only delegated bits */
    rvt_csr_set(&h, 0x144, UINT64_MAX); /* and a write to an undelegated bit is dropped */
    ok &= rvt_csr_val(&h, 0x344) == 0x222u;
    if (!ok) printf("FAIL rvemu WARL masks\n");
    return ok ? 0 : 1;
}

/* Access faults and the counters. A load past the end of RAM is cause 5 with
 * the address in tval; instret skips trapped steps but cycle counts them. */
static int rvt_fault_kat(void)
{
    struct rvemu_hart h;
    int ok = 1;
    rvt_mach(&h, RVEMU_PRIV_S, 0x00033283u); /* ld t0, 0(t1) with t1 = x6 */
    h.x[6] = RVT_MEM_BASE + RVT_MEM_SIZE;
    ok &= rvt_mstep(&h) == RVEMU_STOP_NONE && rvt_trapped_m(&h, 5, RVT_MEM_BASE + RVT_MEM_SIZE, RVT_MPP_S);
    ok &= h.instret == 0 && h.cycle == 1;
    rvt_mach(&h, RVEMU_PRIV_S, 0x00533023u); /* sd t0, 0(t1) */
    h.x[6] = RVT_MEM_BASE + RVT_MEM_SIZE + 8u;
    ok &= rvt_mstep(&h) == RVEMU_STOP_NONE && rvt_trapped_m(&h, 7, RVT_MEM_BASE + RVT_MEM_SIZE + 8u, RVT_MPP_S);
    rvt_mach(&h, RVEMU_PRIV_M, RVT_NOP);
    h.pc = RVT_MEM_BASE + RVT_MEM_SIZE; /* fetch fault */
    ok &= rvt_mstep(&h) == RVEMU_STOP_NONE && h.csr.mcause == 1 && h.csr.mtval == RVT_MEM_BASE + RVT_MEM_SIZE;
    rvt_mach(&h, RVEMU_PRIV_M, RVT_NOP);
    h.time = 777;
    ok &= rvt_csr_val(&h, 0xc01) == 777u;
    if (!ok) printf("FAIL rvemu access faults and counters\n");
    return ok ? 0 : 1;
}

static int rvt_priv_kat(void)
{
    return rvt_deleg_ecall_kat() + rvt_xret_kat() + rvt_timer_irq_kat() + rvt_wfi_kat() +
           rvt_csr_priv_kat() + rvt_warl_kat() + rvt_fault_kat();
}

/* Direct RV64 Zbb cases exercise the existing instruction executor/counters. */
static uint32_t rvt_zbb_r(unsigned f7,unsigned f3,int word,unsigned rd,unsigned rs2)
{ return (f7<<25)|(rs2<<20)|(5u<<15)|(f3<<12)|(rd<<7)|(word?0x3bu:0x33u); }
static uint32_t rvt_zbb_i(unsigned imm,unsigned f3,int word,unsigned rd)
{ return (imm<<20)|(5u<<15)|(f3<<12)|(rd<<7)|(word?0x1bu:0x13u); }
static int rvt_zbb_legal_state(const struct rvemu_hart *h,uint64_t pc,
    unsigned rd,uint64_t expected,enum rvemu_stop stop)
{
 return stop==RVEMU_STOP_NONE && h->x[rd]==(rd?expected:0) && h->x[0]==0 &&
     h->pc==pc+4 && h->instret==1 && h->retired==1 && h->cycle==1;
}
static int rvt_zbb_illegal_state(const struct rvemu_hart *h,uint64_t pc,
    unsigned rd,uint64_t prior,enum rvemu_stop stop)
{
 return stop==RVEMU_STOP_ILLEGAL && h->x[rd]==prior && h->x[0]==0 && h->pc==pc &&
     h->instret==0 && h->retired==0 && h->cycle==0;
}
static int rvt_zbb_case(uint32_t insn,uint64_t a,uint64_t b,uint64_t expected,int legal)
{
 struct rvemu_hart h;struct rvemu_mem mem={.base=RVT_MEM_BASE,.size=RVT_MEM_SIZE,.bytes=rvt_mem_bytes};
 rvemu_hart_init(&h,RVT_MEM_BASE+RVT_HART_SCRATCH);
 unsigned rd=(insn>>7)&31u;h.x[rd]=UINT64_C(0x5a5a5a5a5a5a5a5a);h.x[0]=0;
 h.x[5]=a;h.x[6]=b;uint64_t prior=h.x[rd],pc=h.pc;rvt_put32(&h,pc,insn);
 enum rvemu_stop stop=rvemu_step(&h,&mem);
 return legal?rvt_zbb_legal_state(&h,pc,rd,expected,stop):
     rvt_zbb_illegal_state(&h,pc,rd,prior,stop);
}
static uint64_t rvt_zbb_sext32(uint64_t a)
{ return (a&UINT64_C(0xffffffff)) | ((a&UINT64_C(0x80000000))?UINT64_C(0xffffffff00000000):0); }
/* Independent bit-position oracle avoids sharing the production shift/OR. */
static uint64_t rvt_zbb_rot_ref(uint64_t a,unsigned n,unsigned width,int left)
{
 uint64_t out=0;n%=width;
 for(unsigned bit=0;bit<width;bit++)if(a&(UINT64_C(1)<<bit)){
  unsigned dst=left?(bit+n)%width:(bit+width-n)%width;
  out|=UINT64_C(1)<<dst;
 }
 return width==32?rvt_zbb_sext32(out):out;
}
static int rvt_zbb_known_answers(void)
{
 int ok=1;
 struct {unsigned f7,f3;int word;unsigned rs2;uint64_t a,b,want;} rows[]={
  {0x20,7,0,6,0x0f,0xf0,0x0f},
  {0x20,6,0,6,0x0f,0xf0,UINT64_C(0xffffffffffffff0f)},
  {0x20,4,0,6,0xaa,0x55,UINT64_C(0xffffffffffffff00)},
  {0x05,4,0,6,UINT64_C(0x8000000000000000),1,UINT64_C(0x8000000000000000)},
  {0x05,5,0,6,UINT64_C(0x8000000000000000),1,1},
  {0x05,6,0,6,UINT64_C(0x8000000000000000),1,1},
  {0x05,7,0,6,UINT64_C(0x8000000000000000),1,UINT64_C(0x8000000000000000)},
  {0x04,4,1,0,UINT64_C(0xffffffff1234fedc),0,0xfedc},
  {0x30,1,0,6,UINT64_C(0x8000000000000001),1,3},
  {0x30,5,0,6,UINT64_C(0x8000000000000001),1,UINT64_C(0xc000000000000000)},
  {0x30,1,1,6,UINT64_C(0x1234567880000001),1,3},
  {0x30,5,1,6,UINT64_C(0x1234567880000001),1,UINT64_C(0xffffffffc0000000)}
 };
 for(unsigned i=0;i<sizeof rows/sizeof *rows;i++){
  uint32_t insn=rvt_zbb_r(rows[i].f7,rows[i].f3,rows[i].word,7,rows[i].rs2);
  ok&=rvt_zbb_case(insn,rows[i].a,rows[i].b,rows[i].want,1);
 }
 struct {unsigned imm,f3;int word;uint64_t a,want;} unary[]={
  {0x600,1,0,0,64},{0x601,1,0,0,64},{0x602,1,0,UINT64_MAX,64},
  {0x600,1,1,UINT64_C(0xdeadbeef00000001),31},
  {0x601,1,1,UINT64_C(0xdeadbeef00000000),32},
  {0x602,1,1,UINT64_C(0xdeadbeefffffffff),32},
  {0x604,1,0,0x80,UINT64_C(0xffffffffffffff80)},
  {0x605,1,0,0x8000,UINT64_C(0xffffffffffff8000)},
  {0x287,5,0,UINT64_C(0x0001008000000100),UINT64_C(0x00ff00ff0000ff00)},
  {0x6b8,5,0,UINT64_C(0x0123456789abcdef),UINT64_C(0xefcdab8967452301)},
  {0x601,5,0,UINT64_C(0x8000000000000001),UINT64_C(0xc000000000000000)},
  {0x601,5,1,UINT64_C(0xdeadbeef80000001),UINT64_C(0xffffffffc0000000)}
 };
 for(unsigned i=0;i<sizeof unary/sizeof *unary;i++)
  ok&=rvt_zbb_case(rvt_zbb_i(unary[i].imm,unary[i].f3,unary[i].word,7),unary[i].a,0,unary[i].want,1);
 if(!ok)printf("FAIL rvemu Zbb all24 known answers\n");
 return ok?0:1;
}
static int rvt_zbb_rotate_answers(void)
{
 int ok=1;const uint64_t inputs[]={0,UINT64_MAX,UINT64_C(0x0123456789abcdef),UINT64_C(0xdeadbeef80000001)};
 for(unsigned word=0;word<2;word++)for(unsigned j=0;j<sizeof inputs/sizeof *inputs;j++)for(unsigned n=0;n<64;n++){
  uint64_t a=inputs[j],right=rvt_zbb_rot_ref(a,n,word?32:64,0),left=rvt_zbb_rot_ref(a,n,word?32:64,1);
  ok&=rvt_zbb_case(rvt_zbb_r(0x30,5,word,7,6),a,n+64,right,1);
  ok&=rvt_zbb_case(rvt_zbb_r(0x30,1,word,7,6),a,n+64,left,1);
  if(!word || n<32)ok&=rvt_zbb_case(rvt_zbb_i(0x600+n,5,word,7),a,0,right,1);
 }
 for(unsigned rd=0;rd<8;rd++)if(rd==0 || rd==5 || rd==6 || rd==7){
  ok&=rvt_zbb_case(rvt_zbb_r(0x30,5,1,rd,6),UINT64_C(0x80000001),1,UINT64_C(0xffffffffc0000000),1);
  ok&=rvt_zbb_case(rvt_zbb_i(0x600,5,1,rd),UINT64_C(0x80000001),0,UINT64_C(0xffffffff80000001),1);
 }
 if(!ok)printf("FAIL rvemu Zbb rotate boundaries alias and retirement\n");
 return ok?0:1;
}
static int rvt_zbb_count_answers(void)
{
 int ok=1;
 for(unsigned word=0;word<2;word++){
  unsigned width=word?32:64;
  ok&=rvt_zbb_case(rvt_zbb_i(0x600,1,word,7),0,0,width,1);
  ok&=rvt_zbb_case(rvt_zbb_i(0x601,1,word,7),0,0,width,1);
  ok&=rvt_zbb_case(rvt_zbb_i(0x602,1,word,7),0,0,0,1);
  ok&=rvt_zbb_case(rvt_zbb_i(0x600,1,word,7),UINT64_MAX,0,0,1);
  ok&=rvt_zbb_case(rvt_zbb_i(0x601,1,word,7),UINT64_MAX,0,0,1);
  for(unsigned bit=0;bit<width;bit++){
   uint64_t a=(UINT64_C(1)<<bit)|(word?UINT64_C(0xa5a5a5a500000000):0);
   ok&=rvt_zbb_case(rvt_zbb_i(0x600,1,word,7),a,0,width-1-bit,1);
   ok&=rvt_zbb_case(rvt_zbb_i(0x601,1,word,7),a,0,bit,1);
   ok&=rvt_zbb_case(rvt_zbb_i(0x602,1,word,7),a,0,1,1);
  }
 }
 ok&=rvt_zbb_case(rvt_zbb_i(0x287,5,0,7),0,0,0,1);
 ok&=rvt_zbb_case(rvt_zbb_i(0x287,5,0,7),UINT64_MAX,0,UINT64_MAX,1);
 ok&=rvt_zbb_case(rvt_zbb_i(0x6b8,5,0,7),0,0,0,1);
 ok&=rvt_zbb_case(rvt_zbb_i(0x6b8,5,0,7),UINT64_MAX,0,UINT64_MAX,1);
 for(unsigned i=0;i<8;i++){
  uint64_t a=UINT64_C(1)<<(8*i+7);
  ok&=rvt_zbb_case(rvt_zbb_i(0x287,5,0,7),a,0,UINT64_C(255)<<(8*i),1);
  ok&=rvt_zbb_case(rvt_zbb_i(0x6b8,5,0,7),a,0,UINT64_C(128)<<(8*(7-i)),1);
 }
 ok&=rvt_zbb_case(rvt_zbb_i(0x604,1,0,7),0x7f,0,0x7f,1);
 ok&=rvt_zbb_case(rvt_zbb_i(0x604,1,0,7),UINT64_MAX,0,UINT64_MAX,1);
 ok&=rvt_zbb_case(rvt_zbb_i(0x605,1,0,7),0x7fff,0,0x7fff,1);
 ok&=rvt_zbb_case(rvt_zbb_i(0x605,1,0,7),UINT64_MAX,0,UINT64_MAX,1);
 if(!ok)printf("FAIL rvemu Zbb count extension and byte boundaries\n");
 return ok?0:1;
}
static int rvt_zbb_illegal_immediate_answers(void)
{
 int ok=1;
 for(unsigned n=32;n<64;n++)ok&=rvt_zbb_case(rvt_zbb_i(0x600+n,5,1,7),UINT64_MAX,0,0,0);
 const unsigned bad_unary[]={0x603,0x606,0x607,0x610,0x620};
 for(unsigned i=0;i<sizeof bad_unary/sizeof *bad_unary;i++)for(unsigned word=0;word<2;word++)
  ok&=rvt_zbb_case(rvt_zbb_i(bad_unary[i],1,word,7),UINT64_MAX,0,0,0);
 ok&=rvt_zbb_case(rvt_zbb_i(0x604,1,1,7),1,0,0,0);
 ok&=rvt_zbb_case(rvt_zbb_i(0x605,1,1,7),1,0,0,0);
 ok&=rvt_zbb_case(rvt_zbb_i(0x286,5,0,7),1,0,0,0);
 ok&=rvt_zbb_case(rvt_zbb_i(0x288,5,0,7),1,0,0,0);
 ok&=rvt_zbb_case(rvt_zbb_i(0x698,5,0,7),1,0,0,0); /* RV32 rev8 is reserved in RV64. */
 ok&=rvt_zbb_case(rvt_zbb_i(0x6b9,5,0,7),1,0,0,0);
 ok&=rvt_zbb_case(rvt_zbb_i(0x287,5,1,7),1,0,0,0);
 ok&=rvt_zbb_case(rvt_zbb_i(0x6b8,5,1,7),1,0,0,0);
 if(!ok)printf("FAIL rvemu Zbb reserved immediate encodings\n");
 return ok?0:1;
}
static int rvt_zbb_illegal_register_answers(void)
{
 int ok=1;
 ok&=rvt_zbb_case(rvt_zbb_r(0x04,4,0,7,0),1,0,0,0);
 for(unsigned rs2=1;rs2<32;rs2++)ok&=rvt_zbb_case(rvt_zbb_r(0x04,4,1,7,rs2),1,0,0,0);
 for(unsigned word=0;word<2;word++)ok&=rvt_zbb_case(rvt_zbb_r(0x31,5,word,7,6),1,0,0,0);
 for(unsigned f3=0;f3<8;f3++){
  if(f3!=1 && f3!=5)for(unsigned word=0;word<2;word++)ok&=rvt_zbb_case(rvt_zbb_r(0x30,f3,word,7,6),1,0,0,0);
  if(f3>=4)ok&=rvt_zbb_case(rvt_zbb_r(0x05,f3,1,7,6),1,0,0,0);
  if(f3==4 || f3==6 || f3==7)ok&=rvt_zbb_case(rvt_zbb_r(0x20,f3,1,7,6),1,0,0,0);
 }
 if(!ok)printf("FAIL rvemu Zbb reserved encodings preserve registers PC and retirement\n");
 return ok?0:1;
}
static int rvt_zbb_illegal_answers(void)
{ return rvt_zbb_illegal_immediate_answers()+rvt_zbb_illegal_register_answers(); }
static int rvt_zbb_baseline_answers(void)
{
 int ok=1;
 for(unsigned word=0;word<2;word++){
  ok&=rvt_zbb_case(rvt_zbb_i(1,0,word,7),7,0,8,1);
  ok&=rvt_zbb_case(rvt_zbb_i(0x600,0,word,7),7,0,1543,1);
  ok&=rvt_zbb_case(rvt_zbb_i(1,1,word,7),7,0,14,1);
  ok&=rvt_zbb_case(rvt_zbb_i(1,5,word,7),8,0,4,1);
  ok&=rvt_zbb_case(rvt_zbb_i(0x401,5,word,7),UINT64_MAX,0,UINT64_MAX,1);
  ok&=rvt_zbb_case(rvt_zbb_r(0x20,0,word,7,6),9,2,7,1);
  ok&=rvt_zbb_case(rvt_zbb_r(0,0,word,7,6),9,2,11,1);
  ok&=rvt_zbb_case(rvt_zbb_r(0x20,5,word,7,6),UINT64_MAX,1,UINT64_MAX,1);
 }
 if(!ok)printf("FAIL rvemu Zbb retains base integer encodings\n");
 return ok?0:1;
}
static int rvt_zbb_answers(void)
{
 return rvt_zbb_known_answers()+rvt_zbb_rotate_answers()+rvt_zbb_count_answers()+
     rvt_zbb_illegal_answers()+rvt_zbb_baseline_answers();
}
int rvemu_translate_known_answers(void);
int rvemu_sys_known_answers(void);
int rvemu_vm_known_answers(void);

int test_rvemu(void)
{
    return rvt_zbb_answers() + rvt_conformance() + rvt_arith_kat() + rvt_stop_kat() + rvt_csr_kat() +
           rvt_csr_zero_source_kat() +
           rvt_amo_kat() + rvt_rvc_table() + rvt_rvc_step_kat() + rvt_icache_fast_kat() + rvt_fp_kat() + rvt_priv_kat() + rvemu_translate_known_answers() +
           rvemu_sys_known_answers() + rvemu_vm_known_answers();
}
