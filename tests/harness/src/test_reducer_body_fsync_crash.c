/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_reducer_body_fsync_crash — DETERMINISTIC kill -9 fault injection
 * INSIDE the R1 catch-up round-cadence window
 * (engine/reducer/services/src/reducer_body_fsync.c): the process is
 * SIGKILLed after batch commits whose body+event_log fdatasync was DEMOTED
 * (skipped by the cadence) and BEFORE the next round flush could cover them.
 *
 * Four proofs (owner safety bar for the R1 demotion):
 *
 *   (1) WINDOW: the crasher dies deterministically inside the cadence
 *       window — the per-commit flush report must show exactly ONE
 *       flush-covered commit (the round flush at commit 8 of
 *       ZCL_CATCHUP_FSYNC_COMMIT_INTERVAL=8) among the ten commits that
 *       ran before the kill, so commits 9 and 10 committed with their
 *       durability barrier demoted and no later flush ever ran.
 *   (2) ACKNOWLEDGED WRITES SURVIVE: after the kill, every flush-covered
 *       (acknowledged-durable) commit is durable in the reopened store —
 *       the durable stage cursor covers it and its body record is intact
 *       on disk.
 *   (3) FRONTIER NEVER PRECEDES DATA: the durable cursor C read back after
 *       the crash never exceeds the count R of intact body records on
 *       disk (C <= R), and records 1..C are all present and correct.
 *       Cycle B additionally EMULATES the power-loss tail by truncating
 *       the blk file back to the last flush-covered record (the exact
 *       bytes the demotion left un-fdatasynced), observes the bounded lag
 *       (C > R by at most INTERVAL-1 commits), and has the resumer DETECT
 *       and REPAIR it (re-write the missing bodies — the fixture-level
 *       analog of requeue_body_for_refetch / the boot rescan keyed on the
 *       same fail-closed body read) before continuing.
 *   (4) IDENTICAL FINAL STATE: after resume, the crash-truncated datadir's
 *       durable state — stage cursor AND blk*.dat bytes — is byte-identical
 *       to an uninterrupted golden run's.
 *
 * PROCESS MODEL (mirrors test_fold_inram_crash_proof.c): every leg that
 * touches a store runs in its own fork()ed child; the parent never holds
 * a store open across a fork. The crasher reports per-commit flush
 * coverage over a pipe (dprintf, unbuffered) and then raise(SIGKILL)s
 * itself INSIDE the batched scope — mid-scope, after demoted commits,
 * before any covering flush — so the kill point is ordinal-deterministic,
 * never wall-clock.
 *
 * The fixture drives the REAL seams: stage_batch_begin/end with the REAL
 * reducer_batched_durability_precommit hook (registered by
 * reducer_enter_batched_body_sync), REAL stage_run_once cursor writes,
 * REAL write_block_to_disk in deferred mode, and the REAL catch-up gate
 * (connman fixture identical to test_reducer_drive_watchdog.c case g).
 *
 * make t ONLY=reducer_body_fsync_crash
 */

#define _POSIX_C_SOURCE 200809L  /* dprintf, truncate */

#include "test/test_core.h"

#include "chain/chainparams.h"
#include "core/serialize.h"     /* stream_init/stream_free */
#include "jobs/catchup_cadence.h"
#include "net/connman.h"
#include "net/protocol.h"
#include "primitives/block.h"
#include "services/reducer_ingest_service.h"
#include "services/sync_monitor.h"
#include "storage/disk_block_io.h"
#include "storage/progress_store.h"
#include "sync/stage.h"
#include "util/sync.h"
#include "util/util.h"

#include <errno.h>
#include <inttypes.h>
#include <signal.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#define BFC_N_COMMITS 12   /* golden target: heights 1..12               */
#define BFC_KILL_AFTER 10  /* crasher commits 1..10, then dies mid-scope */
#define BFC_FLUSH_AT 8     /* round flush with interval 8 (the default)  */
#define BFC_STAGE_NAME "bfcrash_fold"

#define BFC_CHECK(name, expr) do {                              \
    printf("reducer_body_fsync_crash: %s... ", (name));          \
    if ((expr)) printf("OK\n");                                  \
    else { printf("FAIL\n"); failures++; }                       \
} while (0)

/* 8-byte height tag stamped into hashPrevBlock so every fixture block's
 * serialized bytes are deterministic and height-identifiable. */
static void bfc_tag(uint64_t h, unsigned char tag[8])
{
    tag[0] = 0xBF; tag[1] = 0xCA;
    for (int i = 0; i < 6; i++)
        tag[2 + i] = (unsigned char)((h >> (8 * i)) & 0xFF);
}

static void bfc_build_block(struct block *b, uint64_t h)
{
    memset(b, 0, sizeof(*b));
    b->header.nVersion = 4;
    bfc_tag(h, b->header.hashPrevBlock.data);
    b->header.nTime = (uint32_t)(1000 + h);
    b->header.nBits = 0x207fffff;
}

/* The trivial stage step: one cursor advance per invocation — the same
 * cursor-write seam every reducer stage funnels through. */
static job_result_t bfc_step(struct stage_step_ctx *ctx)
{
    ctx->cursor_out = ctx->cursor_in + 1;
    return JOB_ADVANCED;
}

/* Open the catch-up gate exactly like test_reducer_drive_watchdog.c's R1
 * case: one active peer at height 100000, log head overridden to 0. */
static bool bfc_gate_open(void)
{
    static struct connman cm;
    static struct p2p_node peer;
    static struct p2p_node *peers[1];
    memset(&cm, 0, sizeof(cm));
    zcl_mutex_init(&cm.manager.cs_nodes);
    memset(&peer, 0, sizeof(peer));
    peer.id = 1;
    peer.starting_height = 100000;
    peer.state = PEER_ACTIVE;
    peer.services = NODE_NETWORK;
    peers[0] = &peer;
    cm.manager.nodes = peers;
    cm.manager.num_nodes = 1;
    sync_monitor_set_context(&cm, NULL, NULL);
    catchup_cadence_test_set_log_head_override(0);
    return catchup_cadence_active();
}

/* Shared child setup: fresh store on `dir`, regtest params, stage table,
 * catch-up gate forced open, real precommit hook armed. Returns the stage
 * on success (NULL on failure). Fills netdir. */
static stage_t *bfc_setup(const char *dir, char *netdir, size_t netdir_cap)
{
    chain_params_select(CHAIN_REGTEST);  /* BEFORE GetDataDir: same suffix
                                          * in every leg and the parent */
    SetDataDir(dir);
    GetDataDir(true, netdir, netdir_cap);
    if (mkdir(netdir, 0700) != 0 && errno != EEXIST)
        return NULL;
    char blocksdir[700];
    snprintf(blocksdir, sizeof(blocksdir), "%s/blocks", netdir);
    if (mkdir(blocksdir, 0700) != 0 && errno != EEXIST)
        return NULL;
    if (!progress_store_open(dir))
        return NULL;
    if (!stage_table_ensure(progress_store_db()))
        return NULL;
    if (!bfc_gate_open())
        return NULL;
    reducer_body_fsync_test_reset();
    reducer_enter_batched_body_sync();   /* real hook + deferred mode */
    return stage_create(BFC_STAGE_NAME, bfc_step, NULL);
}

/* Write body `h` deferred (fflush, no fdatasync — the R1 shape). */
static bool bfc_write_body(uint64_t h, const char *netdir,
                           const unsigned char ms[4])
{
    struct block b;
    bfc_build_block(&b, h);
    struct disk_block_pos pos;
    disk_block_pos_init(&pos);
    return write_block_to_disk(&b, &pos, netdir, ms);
}

static uint64_t bfc_read_cursor(sqlite3 *db)
{
    sqlite3_stmt *st = NULL;
    uint64_t c = 0;
    if (sqlite3_prepare_v2(db,
            "SELECT cursor FROM stage_cursor WHERE name='" BFC_STAGE_NAME "'",
            -1, &st, NULL) == SQLITE_OK) {
        if (sqlite3_step(st) == SQLITE_ROW)  // raw-sql-ok:crash-cursor-read
            c = (uint64_t)sqlite3_column_int64(st, 0);
    }
    sqlite3_finalize(st);
    return c;
}

/* Drive commits from the DURABLE cursor up to `target`, one stage batch
 * (one outer COMMIT) per height, body written BEFORE its batch opens — the
 * same bodies-then-commit ordering the real pipeline has. The durable
 * cursor is read from the store directly: a fresh stage_t's cached cursor
 * is 0 until the first stage_run_once reloads it, which is exactly the
 * resumer case. When report_fd >= 0, dprintfs "commit <h> flushed <0|1>"
 * per commit (the flush coverage the parent proves the window shape from).
 * Returns heights committed. */
static int bfc_drive(stage_t *st, const char *netdir, uint64_t target,
                     int report_fd)
{
    const struct chain_params *cp = chain_params_get();
    sqlite3 *db = progress_store_db();
    uint64_t prev_flush = 0, fu = 0;
    reducer_body_fsync_totals_snapshot(&prev_flush, &fu);
    int done = 0;
    for (;;) {
        uint64_t cur = bfc_read_cursor(db);
        if (cur >= target)
            break;
        uint64_t h = cur + 1;
        if (!bfc_write_body(h, netdir, cp->pchMessageStart))
            return -done - 1;
        progress_store_tx_lock();
        bool ok = stage_batch_begin(db) &&
                  stage_run_once(st, db) == JOB_ADVANCED &&
                  stage_batch_end(db, true);
        progress_store_tx_unlock();
        if (!ok)
            return -done - 1;
        done++;
        uint64_t fc = 0;
        reducer_body_fsync_totals_snapshot(&fc, &fu);
        if (report_fd >= 0)
            dprintf(report_fd, "commit %" PRIu64 " flushed %d\n",
                    h, fc > prev_flush ? 1 : 0);
        prev_flush = fc;
    }
    return done;
}

/* Count the CONSECUTIVE intact body records in blk00000.dat: correct
 * regtest message start, sane size, and the bfc tag for sequence position
 * k at the hashPrevBlock offset. Stops at the first gap/corruption. -1 on
 * a framing error (partial record header). */
static int bfc_count_records(const char *netdir,
                             const unsigned char ms[4])
{
    char path[800];
    snprintf(path, sizeof(path), "%s/blocks/blk00000.dat", netdir);
    FILE *f = fopen(path, "rb");
    if (!f)
        return 0;
    int n = 0;
    for (;;) {
        unsigned char hdr[8];
        if (fread(hdr, 1, 8, f) != 8)
            break;                       /* clean EOF or truncated tail  */
        if (memcmp(hdr, ms, 4) != 0)
            break;
        uint32_t sz = (uint32_t)hdr[4] | ((uint32_t)hdr[5] << 8) |
                      ((uint32_t)hdr[6] << 16) | ((uint32_t)hdr[7] << 24);
        if (sz < 12 || sz > 4 * 1000 * 1000)
            break;
        unsigned char payload[12];
        if (fread(payload, 1, 12, f) != 12)
            break;
        unsigned char want[8];
        bfc_tag((uint64_t)(n + 1), want);
        if (memcmp(payload + 4, want, 8) != 0)
            break;
        if (fseek(f, (long)(sz - 12), SEEK_CUR) != 0)
            break;
        n++;
    }
    fclose(f);
    return n;
}

/* Resumer repair pass (proof 3's repair clause): any cursor-covered
 * height whose body record is missing gets re-written — the fixture-level
 * analog of requeue_body_for_refetch keyed on the same fail-closed body
 * read (a missing record IS the detection signal). Deterministic bodies
 * make the re-write byte-identical to the lost original. */
static bool bfc_repair_missing_bodies(const char *netdir)
{
    const struct chain_params *cp = chain_params_get();
    uint64_t c = bfc_read_cursor(progress_store_db());
    int r = bfc_count_records(netdir, cp->pchMessageStart);
    if (r < 0 || (uint64_t)r > c)
        return false;
    for (uint64_t h = (uint64_t)r + 1; h <= c; h++) {
        if (!bfc_write_body(h, netdir, cp->pchMessageStart))
            return false;
    }
    return true;
}

/* ── Child legs ───────────────────────────────────────────────────────
 * Each _exit()s; the clean legs close the store like a real shutdown, the
 * crasher dies mid-scope by SIGKILL. */

static void bfc_leg_golden(const char *dir)
{
    char netdir[512];
    stage_t *st = bfc_setup(dir, netdir, sizeof(netdir));
    int rc = st ? bfc_drive(st, netdir, BFC_N_COMMITS, -1) : -1;
    if (rc == BFC_N_COMMITS) {
        reducer_exit_batched_body_sync();  /* final flush, as every exit */
        progress_store_close();
    }
    _exit(rc == BFC_N_COMMITS ? 0 : 1);
}

static void bfc_leg_crasher(const char *dir, int report_fd)
{
    char netdir[512];
    stage_t *st = bfc_setup(dir, netdir, sizeof(netdir));
    int rc = st ? bfc_drive(st, netdir, BFC_KILL_AFTER, report_fd) : -1;
    if (rc != BFC_KILL_AFTER)
        _exit(1);
    /* Mid-scope, commits 9..10 demoted, no covering flush — die here. */
    raise(SIGKILL);
    _exit(3);
}

static void bfc_leg_resumer(const char *dir)
{
    char netdir[512];
    stage_t *st = bfc_setup(dir, netdir, sizeof(netdir));
    bool ok = st && bfc_repair_missing_bodies(netdir) &&
              bfc_drive(st, netdir, BFC_N_COMMITS, -1) >= 0 &&
              bfc_read_cursor(progress_store_db()) == BFC_N_COMMITS;
    if (ok) {
        reducer_exit_batched_body_sync();
        progress_store_close();
    }
    _exit(ok ? 0 : 1);
}

/* ── Parent helpers ─────────────────────────────────────────────────── */

static bool bfc_wait_ok(pid_t pid, bool *sigkill)
{
    int stt = 0;
    if (waitpid(pid, &stt, 0) != pid)
        return false;
    if (sigkill) {
        *sigkill = WIFSIGNALED(stt) && WTERMSIG(stt) == SIGKILL;
        return true;
    }
    return WIFEXITED(stt) && WEXITSTATUS(stt) == 0;
}

/* Read the crasher's per-commit flush report into flushed[1..BFC_N_COMMITS]
 * (1 = the pre-commit flush ran for that commit). */
static int bfc_read_reports(int fd, int flushed[BFC_N_COMMITS + 1])
{
    memset(flushed, 0, sizeof(int) * (BFC_N_COMMITS + 1));
    char buf[1024];
    ssize_t got = 0;
    size_t off = 0;
    while ((got = read(fd, buf + off, sizeof(buf) - 1 - off)) > 0)
        off += (size_t)got;
    buf[off] = '\0';
    int lines = 0;
    uint64_t h;
    int fl;
    char *p = buf;
    while (sscanf(p, "commit %" SCNu64 " flushed %d", &h, &fl) == 2) {
        if (h >= 1 && h <= BFC_N_COMMITS) {
            flushed[h] = fl;
            lines++;
        }
        p = strchr(p, '\n');
        if (!p)
            break;
        p++;
    }
    return lines;
}

/* Byte-compare the durable bodies of two datadirs (proof 4). */
static bool bfc_bodies_identical(const char *netdir_a, const char *netdir_b)
{
    char pa[800], pb[800];
    snprintf(pa, sizeof(pa), "%s/blocks/blk00000.dat", netdir_a);
    snprintf(pb, sizeof(pb), "%s/blocks/blk00000.dat", netdir_b);
    FILE *fa = fopen(pa, "rb"), *fb = fopen(pb, "rb");
    if (!fa || !fb) {
        if (fa) fclose(fa);
        if (fb) fclose(fb);
        return false;
    }
    bool same = true;
    for (;;) {
        unsigned char ba[4096], bb[4096];
        size_t ra = fread(ba, 1, sizeof(ba), fa);
        size_t rb = fread(bb, 1, sizeof(bb), fb);
        if (ra != rb || memcmp(ba, bb, ra) != 0) {
            same = false;
            break;
        }
        if (ra == 0)
            break;
    }
    fclose(fa);
    fclose(fb);
    return same;
}

/* Reopen a crash datadir in the parent (no store was open across the
 * fork) and return the durable cursor; fills netdir for body checks. */
static uint64_t bfc_parent_reopen_cursor(const char *dir, char *netdir,
                                         size_t cap)
{
    chain_params_select(CHAIN_REGTEST);  /* BEFORE GetDataDir (see setup) */
    SetDataDir(dir);
    GetDataDir(true, netdir, cap);
    if (!progress_store_open(dir))
        return UINT64_MAX;
    uint64_t c = bfc_read_cursor(progress_store_db());
    progress_store_close();
    return c;
}

/* One full crash cycle on `dir`: crasher -> parent window/durability
 * checks -> optional truncate-to-flush-covered tail (emulated power loss)
 * -> resumer -> final-state compare against the golden netdir. */
static int bfc_crash_cycle(const char *dir, const char *golden_netdir,
                           bool emulate_power_loss)
{
    int failures = 0;
    char netdir[512];
    const struct chain_params *cp;

    int fds[2];
    if (pipe(fds) != 0) {
        BFC_CHECK("pipe for crasher report", false);
        return failures;
    }
    pid_t pid = fork();
    if (pid == 0) {
        close(fds[0]);
        bfc_leg_crasher(dir, fds[1]);
    }
    close(fds[1]);
    int flushed[BFC_N_COMMITS + 1];
    int lines = bfc_read_reports(fds[0], flushed);
    close(fds[0]);
    bool sigkill = false;
    bool waited = bfc_wait_ok(pid, &sigkill);

    BFC_CHECK("crasher died by SIGKILL mid-scope", waited && sigkill);
    BFC_CHECK("crasher reported all pre-kill commits",
              lines == BFC_KILL_AFTER);
    int nflushes = 0;
    for (int i = 1; i <= BFC_KILL_AFTER; i++)
        nflushes += flushed[i];
    BFC_CHECK("kill landed inside the R1 window (only the round flush at "
              "commit 8 covered; 9..10 demoted)",
              nflushes == 1 && flushed[BFC_FLUSH_AT] == 1);

    uint64_t c = bfc_parent_reopen_cursor(dir, netdir, sizeof(netdir));
    cp = chain_params_get();
    int r = bfc_count_records(netdir, cp->pchMessageStart);
    BFC_CHECK("(3) durable frontier never precedes durable body data "
              "(cursor <= intact records)",
              c != UINT64_MAX && (int64_t)c <= r);
    BFC_CHECK("(2) every acknowledged (flush-covered) write survived "
              "(cursor covers commit 8, records 1..8 intact)",
              c != UINT64_MAX && c >= BFC_FLUSH_AT && r >= BFC_FLUSH_AT);

    if (emulate_power_loss) {
        /* Drop exactly the bytes the demotion left un-fdatasynced:
         * truncate to the first BFC_FLUSH_AT records. Record sizes are
         * fixture-uniform, so recompute the prefix by re-serializing. */
        char path[800];
        snprintf(path, sizeof(path), "%s/blocks/blk00000.dat", netdir);
        long prefix = 0;
        for (int i = 1; i <= BFC_FLUSH_AT; i++) {
            struct block b;
            bfc_build_block(&b, (uint64_t)i);
            struct byte_stream s;
            stream_init(&s, 4096);
            if (!block_serialize(&b, &s)) {
                stream_free(&s);
                BFC_CHECK("re-serialize for truncation", false);
                return failures;
            }
            prefix += 8 + (long)s.size;
            stream_free(&s);
        }
        BFC_CHECK("emulated power loss truncated the demoted tail",
                  truncate(path, (off_t)prefix) == 0);
        int r2 = bfc_count_records(netdir, cp->pchMessageStart);
        BFC_CHECK("bounded lag is observable (cursor ahead of bodies by "
                  "at most INTERVAL-1 commits)",
                  (int64_t)c > r2 && (int64_t)c - r2 <= BFC_FLUSH_AT - 1);
    }

    pid_t rpid = fork();
    if (rpid == 0)
        bfc_leg_resumer(dir);
    BFC_CHECK("resumer ran to completion", bfc_wait_ok(rpid, NULL));

    uint64_t c2 = bfc_parent_reopen_cursor(dir, netdir, sizeof(netdir));
    BFC_CHECK("(4) resumed cursor reaches the golden target",
              c2 == BFC_N_COMMITS);
    BFC_CHECK("(4) resumed durable bodies byte-identical to golden",
              bfc_bodies_identical(netdir, golden_netdir));
    return failures;
}

int test_reducer_body_fsync_crash(void);
int test_reducer_body_fsync_crash(void)
{
    int failures = 0;
    setenv("ZCL_CATCHUP_FSYNC_COMMIT_INTERVAL", "8", 1);

    char dirG[512], dirA[512], dirB[512];
    test_make_tmpdir(dirG, sizeof(dirG), "bfcrash", "g");
    test_make_tmpdir(dirA, sizeof(dirA), "bfcrash", "a");
    test_make_tmpdir(dirB, sizeof(dirB), "bfcrash", "b");

    /* Golden: uninterrupted run, clean shutdown. */
    pid_t g = fork();
    if (g == 0)
        bfc_leg_golden(dirG);
    BFC_CHECK("golden run completed cleanly", bfc_wait_ok(g, NULL));
    char golden_netdir[512];
    chain_params_select(CHAIN_REGTEST);  /* BEFORE GetDataDir (see setup) */
    SetDataDir(dirG);
    GetDataDir(true, golden_netdir, sizeof(golden_netdir));

    /* Cycle A: kill in the R1 window; bodies survive under kill -9. */
    failures += bfc_crash_cycle(dirA, golden_netdir, false);
    /* Cycle B: same kill, then the demoted tail is dropped (emulated
     * power loss); the resumer detects + repairs the bounded lag. */
    failures += bfc_crash_cycle(dirB, golden_netdir, true);

    unsetenv("ZCL_CATCHUP_FSYNC_COMMIT_INTERVAL");
    SetDataDir("");
    ClearDataDirCache();
    chain_params_select(CHAIN_MAIN);
    test_cleanup_tmpdir(dirG);
    test_cleanup_tmpdir(dirA);
    test_cleanup_tmpdir(dirB);

    printf("=== reducer_body_fsync_crash: %d failures ===\n", failures);
    return failures;
}
