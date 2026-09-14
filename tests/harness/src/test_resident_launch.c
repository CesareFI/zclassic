/* Copyright 2026 Rhett Creighton - Apache 2.0 */
/*
 * Exact resident-launch acceptance. Proves the four invariants the seam
 * sells: a live image that differs from the accepted record is refused
 * before any process exists; a result frame from another launch is refused
 * by name; a failed candidate leaves an already-serving launch intact; a
 * full launch/cancel cycle leaves neither descriptors nor children behind.
 * The real spawn path runs on POSIX (Linux fexecve proof, macOS suspended
 * CodeDirectory proof); Windows asserts the named refusal.
 */
#include "test/test_core.h"

#include "base/hex.h"
#include "platform/positioned_file.h"
#include "platform/resident_launch.h"
#include "sha3/sha3.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#if !defined(_WIN32)
#include <signal.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

#define RL_CHECK(name, expr) do {                                         \
    printf("resident_launch: %s... ", (name));                            \
    fflush(stdout);                                                       \
    if (expr) printf("OK\n");                                             \
    else { printf("FAIL\n"); failures++; }                                \
} while (0)

/* A tiny executable fixture: enough for prepare()'s digest/triple checks
 * (no exec happens on the refusal paths). */
static const char rl_script[] = "#!/bin/sh\nexit 0\n";

static bool rl_write_fixture(const char *path)
{
    FILE *f = fopen(path, "wb");
    if (!f) return false;
    bool ok = fwrite(rl_script, 1, sizeof(rl_script) - 1, f) ==
              sizeof(rl_script) - 1;
    if (fclose(f) != 0) ok = false;
    if (ok && chmod(path, 0755) != 0) ok = false;
    return ok;
}

/* Capture the acceptance record for a file as it stands right now. */
static bool rl_accept_of(const char *path, struct resident_launch_accepted *a)
{
    struct platform_positioned_file file;
    struct platform_positioned_file_snapshot snap;
    platform_positioned_file_init(&file);
    if (!platform_positioned_file_open(&file, path) ||
        !platform_positioned_file_snapshot(&file, &snap)) {
        platform_positioned_file_close(&file);
        return false;
    }
    unsigned char digest[32];
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    unsigned char chunk[4096];
    uint64_t offset = 0;
    for (;;) {
        int64_t got = platform_positioned_file_read(&file, chunk, sizeof(chunk),
                                                    offset);
        if (got < 0) { platform_positioned_file_close(&file); return false; }
        if (got == 0) break;
        sha3_256_write(&ctx, chunk, (size_t)got);
        offset += (uint64_t)got;
    }
    sha3_256_finalize(&ctx, digest);
    platform_positioned_file_close(&file);
    zcl_hex_encode(digest, sizeof(digest), a->image_sha3_hex);
    a->image_volume = snap.volume;
    a->image_low = snap.file_low;
    a->image_high = snap.file_high;
    a->image_size = snap.size;
    return true;
}

#if defined(_WIN32)
int test_resident_launch(void)
{
    int failures = 0;
    struct resident_launch wrong;
    struct resident_launch_accepted accepted = {{0}, 0, 0, 0, 0};
    char error[RESIDENT_LAUNCH_ERROR_MAX];
    resident_launch_init(&wrong);
    RL_CHECK("prepare refuses on a platform without descriptor-bound exec",
             !resident_launch_prepare(&wrong, "no-such-image", &accepted,
                                      error, sizeof(error)) &&
             errno == ENOTSUP && error[0]);
    resident_launch_close(&wrong);
    printf("resident_launch: %s (%d failure(s))\n",
           failures ? "FAIL" : "PASS", failures);
    return failures;
}
#else /* POSIX */

static int rl_open_fd_count(void)
{
    int count = 0;
    for (int fd = 3; fd < 1024; fd++) {
        if (fcntl(fd, F_GETFD) != -1) count++;
    }
    return count;
}

static bool rl_wait_reaped(uint64_t pid)
{
    return waitpid((pid_t)pid, NULL, WNOHANG) == -1 && errno == ECHILD;
}

/* Everything prepare() must refuse, before any process exists. */
static int rl_refusal_checks(const char *fixture,
                             const struct resident_launch_accepted *accepted)
{
    int failures = 0;
    char error[RESIDENT_LAUNCH_ERROR_MAX];
    struct resident_launch wrong;
    struct resident_launch_accepted tampered = *accepted;
    tampered.image_sha3_hex[0] = tampered.image_sha3_hex[0] == '0' ? '1' : '0';
    resident_launch_init(&wrong);
    error[0] = '\0';
    RL_CHECK("prepare refuses a tampered digest before any process exists",
             !resident_launch_prepare(&wrong, fixture, &tampered, error,
                                      sizeof(error)) &&
             errno == ESTALE &&
             strstr(error, "accepted record") != NULL);
    resident_launch_close(&wrong);

    struct resident_launch_accepted wrong_triple = *accepted;
    wrong_triple.image_low ^= 1;
    resident_launch_init(&wrong);
    error[0] = '\0';
    RL_CHECK("prepare refuses a replaced positioned-file identity",
             !resident_launch_prepare(&wrong, fixture, &wrong_triple, error,
                                      sizeof(error)) &&
             errno == ESTALE);
    resident_launch_close(&wrong);

    /* Mutate the file AFTER capturing acceptance: the live bytes must not
     * match the accepted record even though the digest field claims it. */
    FILE *swap = fopen(fixture, "wb");
    bool swapped = swap &&
        fputs("#!/bin/sh\nexit 3\n", swap) >= 0 && fclose(swap) == 0 &&
        chmod(fixture, 0755) == 0;
    RL_CHECK("mutate the fixture on disk", swapped);
    struct resident_launch stale_live;
    resident_launch_init(&stale_live);
    error[0] = '\0';
    RL_CHECK("prepare refuses mutated live bytes against the old record",
             !resident_launch_prepare(&stale_live, fixture, accepted, error,
                                      sizeof(error)) &&
             errno == ESTALE);
    resident_launch_close(&stale_live);
    (void)rl_write_fixture(fixture);
    return failures;
}

/* The frame codec: current-nonce results accepted, stale-nonce refused by
 * name. No child process is needed — the peer end of the channel is driven
 * from this test. */
static int rl_codec_checks(const char *fixture,
                           const struct resident_launch_accepted *accepted)
{
    int failures = 0;
    char error[RESIDENT_LAUNCH_ERROR_MAX];
    struct resident_launch codec;
    resident_launch_init(&codec);
    RL_CHECK("prepare accepts the intact image",
             resident_launch_prepare(&codec, fixture, accepted, error,
                                     sizeof(error)));
    int peer[2] = {-1, -1};
    RL_CHECK("codec test channel",
             socketpair(AF_UNIX, SOCK_STREAM, 0, peer) == 0);
    codec.ipc_native = (uintptr_t)peer[0];
    codec.spawned = true;
    struct resident_result_header header;
    unsigned char payload[64];
    struct resident_result_header frame;
    memset(&frame, 0, sizeof(frame));
    (void)snprintf(frame.magic, sizeof(frame.magic), "%s", "z23-res-run-v1");
    (void)snprintf(frame.nonce, sizeof(frame.nonce), "%s", codec.nonce);
    frame.payload_len = 3;
    error[0] = '\0';
    (void)send(peer[1], &frame, sizeof(frame), 0);
    (void)send(peer[1], "ok!", 3, 0);
    RL_CHECK("current-nonce result frame is accepted",
             resident_result_read(&codec, &header, payload, sizeof(payload),
                                  2000, error, sizeof(error)) &&
             header.payload_len == 3 && memcmp(payload, "ok!", 3) == 0);
    memset(&frame, 0, sizeof(frame));
    (void)snprintf(frame.magic, sizeof(frame.magic), "%s", "z23-res-run-v1");
    memset(frame.nonce, 'f', RESIDENT_LAUNCH_NONCE_HEX);
    frame.payload_len = 0;
    (void)send(peer[1], &frame, sizeof(frame), 0);
    error[0] = '\0';
    RL_CHECK("stale-nonce result frame is refused by name",
             !resident_result_read(&codec, &header, payload, sizeof(payload),
                                   2000, error, sizeof(error)) &&
             errno == ESTALE && strstr(error, "result_stale_launch") != NULL);
    close(peer[0]);
    close(peer[1]);
    codec.ipc_native = (uintptr_t)-1;
    codec.spawned = false;
    resident_launch_close(&codec);
    return failures;
}

/* A real, long-lived executable: the receipt's start_token and the
 * /proc/<pid>/exe re-proof are only observable while the child lives, and
 * the cancel path must prove real reaping of a live process. Then a failed
 * candidate against the steady state, and the no-leak proof. */
static int rl_cycle_checks(void)
{
    int failures = 0;
    char error[RESIDENT_LAUNCH_ERROR_MAX];
    struct resident_launch_accepted sleeper;
    RL_CHECK("capture sleeper acceptance record",
             rl_accept_of("/bin/sleep", &sleeper));
    int fds_before = rl_open_fd_count();
    struct resident_launch serving;
    resident_launch_init(&serving);
    error[0] = '\0';
    RL_CHECK("prepare the serving launch",
             resident_launch_prepare(&serving, "/bin/sleep", &sleeper, error,
                                     sizeof(error)));
    struct resident_receipt receipt;
    memset(&receipt, 0, sizeof(receipt));
    char *const argv[] = {"sleep", "30", NULL};
    char *const envp[] = {NULL};
    bool spawned_serving = resident_launch_spawn(
        &serving, argv, envp, &receipt, error, sizeof(error));
    if (!spawned_serving)
        printf("resident_launch: spawn error: %s (errno=%d)\n",
               error[0] ? error : "<none>", errno);
    RL_CHECK("spawn proves the exact mapped image and issues a receipt",
             spawned_serving && receipt.pid > 0 &&
             receipt.image_sha3_hex[0] &&
             (strcmp(receipt.mapped_proof, "fexecve_inode") == 0 ||
              strcmp(receipt.mapped_proof, "proc_exe_triple") == 0 ||
              strcmp(receipt.mapped_proof, "cdhash_suspended") == 0) &&
             receipt.start_token > 0);
#if defined(__linux__)
    /* Regression: the post-exec re-proof must actually RUN. The no-follow
     * content-path open on /proc/<pid>/exe always refused the kernel magic
     * link with ELOOP, so this proof silently never executed on Linux and
     * the receipt could never carry "proc_exe_triple" — the fallback name
     * "fexecve_inode" here means the second proof was skipped, not that it
     * passed. */
    RL_CHECK("the /proc/<pid>/exe re-proof ran and named itself on the"
             " receipt",
             strcmp(receipt.mapped_proof, "proc_exe_triple") == 0);
#endif

    int fds_steady = rl_open_fd_count();
    struct resident_launch candidate;
    struct resident_launch_accepted bad_candidate = sleeper;
    bad_candidate.image_high ^= 1;
    resident_launch_init(&candidate);
    error[0] = '\0';
    RL_CHECK("failed candidate is refused before any process exists",
             !resident_launch_prepare(&candidate, "/bin/sleep",
                                      &bad_candidate, error, sizeof(error)) &&
             errno == ESTALE);
    resident_launch_close(&candidate);
    RL_CHECK("refused candidate leaked no descriptors",
             rl_open_fd_count() == fds_steady);
    RL_CHECK("the serving launch is still current after the refusal",
             serving.spawned && serving.pid == receipt.pid);

    error[0] = '\0';
    RL_CHECK("cancel stops and reaps the resident",
             resident_launch_cancel(&serving, 300, error, sizeof(error)));
    RL_CHECK("the resident left no child behind", rl_wait_reaped(receipt.pid));
    resident_launch_close(&serving);
    RL_CHECK("full cycle leaked no descriptors",
             rl_open_fd_count() == fds_before);
    return failures;
}

/* Stream `in` into the already-open `out`, recording the byte count. */
static bool rl_copy_stream(FILE *in, FILE *out, size_t *size_out)
{
    unsigned char buf[4096];
    size_t total = 0;
    for (;;) {
        size_t got = fread(buf, 1, sizeof(buf), in);
        if (got > 0 && fwrite(buf, 1, got, out) != got) return false;
        total += got;
        if (got < sizeof(buf)) {
            *size_out = total;
            return !ferror(in);
        }
    }
}

/* Copy `src` to `dst`, append `pad` zero bytes (trailing bytes past the
 * ELF's own layout do not change how it executes), and record the original
 * byte count so the caller can flip a byte inside the padding: that yields
 * a same-inode, same-size, different-bytes image that still runs. */
static bool rl_copy_padded(const char *src, const char *dst, size_t pad,
                           size_t *plain_size_out)
{
    FILE *in = fopen(src, "rb");
    if (!in) return false;
    FILE *out = fopen(dst, "wb");
    if (!out) { (void)fclose(in); return false; }
    bool ok = rl_copy_stream(in, out, plain_size_out);
    unsigned char zeros[512] = {0};
    size_t left = pad;
    while (ok && left > 0) {
        size_t chunk = left < sizeof(zeros) ? left : sizeof(zeros);
        if (fwrite(zeros, 1, chunk, out) != chunk) { ok = false; break; }
        left -= chunk;
    }
    if (fclose(out) != 0) ok = false;
    (void)fclose(in);
    if (ok && chmod(dst, 0755) != 0) ok = false;
    return ok;
}

/* Overwrite one byte IN PLACE at `offset`: same inode, same size, changed
 * content — exactly the swap a metadata-only check cannot reliably see on
 * a multigrain-timestamp kernel. */
static bool rl_flip_byte(const char *path, size_t offset)
{
    FILE *f = fopen(path, "r+b");
    if (!f) return false;
    bool ok = fseek(f, (long)offset, SEEK_SET) == 0 && fputc('X', f) == 'X';
    if (fclose(f) != 0) ok = false;
    return ok;
}

/* Regression: a same-size, same-inode content swap between prepare and
 * spawn must refuse BEFORE fork — ESTALE, a named byte change, and no
 * child. Between prepare and spawn there was previously no content proof
 * at all, and a metadata triple cannot see a same-jiffy swap on
 * multigrain-timestamp kernels (>=6.6): the wrong bytes were exec'd. The
 * flipped byte sits in zero padding appended past the ELF layout, so the
 * swapped image is still perfectly executable — if the refusal ever
 * regresses, spawn visibly succeeds instead of failing for an unrelated
 * exec reason. */
static int rl_swap_refusal_checks(const char *dir)
{
    int failures = 0;
    char error[RESIDENT_LAUNCH_ERROR_MAX];
    char image[512];
    (void)snprintf(image, sizeof(image), "%s/padded-true", dir);
    size_t plain_size = 0;
    RL_CHECK("stage a padded executable image",
             rl_copy_padded("/bin/true", image, 4096, &plain_size));
    struct resident_launch_accepted accepted;
    RL_CHECK("capture the padded image acceptance record",
             rl_accept_of(image, &accepted));
    int fds_before = rl_open_fd_count();
    struct resident_launch swap;
    resident_launch_init(&swap);
    error[0] = '\0';
    RL_CHECK("prepare accepts the padded image",
             resident_launch_prepare(&swap, image, &accepted, error,
                                     sizeof(error)));
    RL_CHECK("swap same-size bytes in place after prepare",
             rl_flip_byte(image, plain_size + 100));
    struct resident_receipt receipt;
    memset(&receipt, 0, sizeof(receipt));
    char *const argv[] = {"true", NULL};
    char *const envp[] = {NULL};
    error[0] = '\0';
    bool spawned = resident_launch_spawn(&swap, argv, envp, &receipt, error,
                                         sizeof(error));
    RL_CHECK("spawn refuses a same-size content swap before fork",
             !spawned && errno == ESTALE && !swap.spawned && swap.pid == 0 &&
             strstr(error, "bytes changed") != NULL);
    if (spawned) {
        /* Unfixed launchers exec the wrong bytes here: reap the child so
         * the regression leaves no process behind. */
        char cleanup_error[RESIDENT_LAUNCH_ERROR_MAX];
        (void)resident_launch_cancel(&swap, 300, cleanup_error,
                                     sizeof(cleanup_error));
    }
    resident_launch_close(&swap);
    RL_CHECK("the pre-fork refusal leaked no descriptors",
             rl_open_fd_count() == fds_before);
    return failures;
}

int test_resident_launch(void)
{
    int failures = 0;
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "resident_launch", "x");
    char fixture[512];
    (void)snprintf(fixture, sizeof(fixture), "%s/app.sh", dir);
    RL_CHECK("write executable fixture", rl_write_fixture(fixture));
    struct resident_launch_accepted accepted;
    RL_CHECK("capture the acceptance record",
             rl_accept_of(fixture, &accepted));
    failures += rl_refusal_checks(fixture, &accepted);
    failures += rl_codec_checks(fixture, &accepted);
    failures += rl_swap_refusal_checks(dir);
    failures += rl_cycle_checks();
    test_rm_rf(dir);
    printf("resident_launch: %s (%d failure(s))\n",
           failures ? "FAIL" : "PASS", failures);
    return failures;
}
#endif /* POSIX */
