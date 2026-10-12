/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0.
 * Isolated PUBLIC-credential guest storage acceptance; never a launcher. */
#include "config/mesh_guest_private_volume.h"
#include "base/cleanse.h"
#include "base/hex.h"
#include "base/log_macros.h"
#include "crypto/sha256.h"
#include "platform/rng.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FG_KERNEL_SHA "fae34637f859502e4bcc529fe8591b08ad5cbb72b0e3c82f0570e394bda70a48"
#define FG_VOLUME_BYTES (UINT64_C(16) << 20)
#define FG_MAX_WORK UINT64_C(1000000000)
#define FG_CONSOLE_MAX 65536u
#define FG_DATA_BYTE UINT64_C(544)

struct fg_state {
    struct rvmachine *m;
    struct rvmachine_script script;
    struct rvmachine_disk *inner;
    struct zcl_machine_private_volume volume;
    uint64_t seq, write_seq, flush_seq, flushes, entropy_bytes;
    bool entropy_failed, console_full, mapped_read, mapped_write;
    size_t console_len;
    char console[FG_CONSOLE_MAX + 1u];
};

static bool fg_refuse(const char *phase)
{
    LOG_WARN("fixture.geli", "PUBLIC storage fixture refused during %s", phase);
    return false;
}

static bool fg_read(void *ctx, uint64_t off, void *buf, size_t n)
{
    struct fg_state *s = ctx;
    bool ok = rvmachine_disk_read(s->inner, off, buf, n);
    if (ok && off <= FG_DATA_BYTE && n > FG_DATA_BYTE - off) s->mapped_read = true;
    return ok;
}

static bool fg_write(void *ctx, uint64_t off, const void *buf, size_t n)
{
    struct fg_state *s = ctx;
    bool ok = rvmachine_disk_write(s->inner, off, buf, n);
    if (ok && n != 0) s->write_seq = ++s->seq;
    if (ok && off <= FG_DATA_BYTE && n > FG_DATA_BYTE - off) s->mapped_write = true;
    return ok;
}

static bool fg_flush(void *ctx)
{
    struct fg_state *s = ctx;
    if (!rvmachine_disk_flush(s->inner)) return fg_refuse("guest durability barrier");
    s->flush_seq = ++s->seq;
    s->flushes++;
    return true;
}

static size_t fg_entropy(void *ctx, uint8_t *buf, size_t n)
{
    struct fg_state *s = ctx;
    if (s->entropy_failed) { memory_cleanse(buf, n); return 0; }
    for (size_t off = 0; off < n;) {
        size_t chunk = n - off < 4096u ? n - off : 4096u;
        if (!rng_host_fill(buf + off, chunk)) {
            memory_cleanse(buf, n);
            s->entropy_failed = true;
            return 0;
        }
        off += chunk;
    }
    s->entropy_bytes += n;
    return n;
}

static bool fg_seed(void *ctx, uint8_t *buf, size_t n, size_t *got)
{
    *got = fg_entropy(ctx, buf, n);
    return *got == n;
}

static void fg_console(void *ctx, uint8_t byte)
{
    struct fg_state *s = ctx;
    if (s->console_len == FG_CONSOLE_MAX) {
        s->console_full = true;
        rvmachine_request_stop(s->m);
        return;
    }
    s->console[s->console_len++] = (char)byte;
    s->console[s->console_len] = '\0';
    rvmachine_script_console(&s->script, s->m, byte);
}

/* One already-open descriptor binds the public kernel bytes before execution. */
static uint8_t *fg_kernel(const char *path, size_t *len, const char *expected)
{
    struct platform_positioned_file f;
    struct platform_positioned_file_snapshot before, after;
    uint8_t *bytes = NULL;
    platform_positioned_file_init(&f);
    if (!platform_positioned_file_open(&f, path)) goto out;
    if (!platform_positioned_file_snapshot(&f, &before)) goto out;
    if (before.size == 0 || before.size > (UINT64_C(64) << 20)) goto out;
    bytes = malloc((size_t)before.size);
    if (bytes == NULL) goto out;
    size_t off = 0;
    while (off < before.size) {
        int64_t n = platform_positioned_file_read(&f, bytes + off,
                                                   (size_t)before.size - off, off);
        if (n <= 0) { free(bytes); bytes = NULL; goto out; }
        off += (size_t)n;
    }
    struct sha256_ctx sha;
    uint8_t digest[SHA256_OUTPUT_SIZE];
    char hex[65];
    sha256_init(&sha);
    sha256_write(&sha, bytes, off);
    sha256_finalize(&sha, digest);
    zcl_hex_encode(digest, sizeof digest, hex);
    if (strcmp(hex, expected) != 0) { free(bytes); bytes = NULL; goto out; }
    if (!platform_positioned_file_snapshot(&f, &after) ||
        !platform_positioned_file_snapshot_equal(&before, &after)) {
        free(bytes); bytes = NULL; goto out;
    }
    *len = off;
out:
    platform_positioned_file_close(&f);
    if (bytes == NULL) (void)fg_refuse("exact public kernel descriptor");
    return bytes;
}

static const char *fg_phase(const char *phase)
{
    if (strcmp(phase, "write") == 0)
        return "geli detach vtbd0.eli && /sbin/geli-public-flush && ";
    if (strcmp(phase, "read") == 0)
        return "geli detach vtbd0.eli && ";
    if (strcmp(phase, "wrong") == 0)
        return "printf '\\107\\105\\114\\111\\055\\127\\122\\117\\116\\107\\055\\122\\103\\072%s\\n' \"$public_rc\" && ";
    if (strcmp(phase, "tamper") == 0)
        return "printf '\\107\\105\\114\\111\\055\\111\\117\\105\\122\\122\\055\\122\\103\\072%s\\n' \"$public_rc\" && ";
    return NULL;
}

static bool fg_echo_guard(const char *command)
{
    const char *goal = "FIXTURE-GELI-PHASE-OK\r\n";
    struct rvmachine_script *observer = calloc(1, sizeof *observer);
    if (observer == NULL) return fg_refuse("echo observer allocation");
    rvmachine_script_init(observer);
    bool ok = rvmachine_script_until(observer, goal, strlen(goal));
    for (size_t i = 0; ok && command[i] != '\0'; i++)
        rvmachine_script_console(observer, NULL, (uint8_t)command[i]);
    ok = ok && !rvmachine_script_met(observer);
    for (size_t i = 0; ok && goal[i] != '\0'; i++)
        rvmachine_script_console(observer, NULL, (uint8_t)goal[i]);
    ok = ok && rvmachine_script_met(observer);
    free(observer);
    return ok || fg_refuse("echo-only marker negative control");
}

static bool fg_add_step(struct fg_state *s, const char *marker, const char *body, bool final)
{
    char command[RVMACHINE_SCRIPT_TEXT_MAX + 1u];
    int n = snprintf(command, sizeof command,
        "%s printf '%s\\n'\n", body,
        final ? "\\106\\111\\130\\124\\125\\122\\105\\055\\107\\105\\114\\111\\055\\120\\110\\101\\123\\105\\055\\117\\113" :
                "\\106\\107\\055\\116\\105\\130\\124");
    if (n <= 0 || (size_t)n >= sizeof command) return fg_refuse("script bound");
    if (!fg_echo_guard(command)) return false;
    return rvmachine_script_add(&s->script, marker, strlen(marker), command, (size_t)n);
}

static bool fg_phase_steps(struct fg_state *s, const char *phase)
{
    const char *next = "FG-NEXT\r\n";
    if (strcmp(phase, "wrong") == 0)
        return fg_add_step(s, next,
            "geli attach -p -k /PUBLIC_TEST_WRONG.key /dev/vtbd0; public_rc=$?; "
            "[ \"$public_rc\" -ne 0 ] && [ ! -e /dev/vtbd0.eli ] && ", false);
    if (!fg_add_step(s, next,
        "geli attach -p -k /PUBLIC_TEST_ONLY.key /dev/vtbd0 && geli list vtbd0.eli && ", false))
        return false;
    /* Prove the pinned guest shell propagates a failed pipeline producer;
     * then require both dd's exact read and cmp's equality to succeed. */
    if (!fg_add_step(s, next,
        "set -o pipefail && { false | true; [ \"$?\" -ne 0 ]; } && ", false))
        return false;
    if (strcmp(phase, "write") == 0 && !fg_add_step(s, next,
        "dd if=/PUBLIC_PAYLOAD.bin of=/dev/vtbd0.eli bs=4096 count=1 conv=fsync && ", false))
        return false;
    if (strcmp(phase, "tamper") == 0)
        return fg_add_step(s, next,
            "dd if=/dev/vtbd0.eli of=/dev/null bs=4096 count=1; public_rc=$?; "
            "[ \"$public_rc\" -ne 0 ] && ", false);
    return fg_add_step(s, next,
        "dd if=/dev/vtbd0.eli bs=4096 count=1 | cmp /PUBLIC_PAYLOAD.bin - && ", false);
}

static bool fg_script(struct fg_state *s, const char *phase)
{
    const char *body = fg_phase(phase);
    if (body == NULL) return fg_refuse("unknown phase");
    rvmachine_script_init(&s->script);
    if (!rvmachine_script_add(&s->script, "Enter full pathname", 19, "\n", 1))
        return fg_refuse("shell entry script");
    if (!fg_add_step(s, "# ",
        "[ \"$(sysctl -n kern.random.initial_seeding.bypass_before_seeding)\" = 0 ] && "
        "[ \"$(sysctl -n kern.random.initial_seeding.read_random_bypassed_before_seeding)\" = 0 ] && "
        "[ \"$(sysctl -n kern.random.initial_seeding.arc4random_bypassed_before_seeding)\" = 0 ] && ", false))
        return fg_refuse("bypass policy script");
    if (!fg_add_step(s, "FG-NEXT\r\n",
        "{ read -r -t 2 PUBLIC_RANDOM < /dev/random; public_rc=$?; unset PUBLIC_RANDOM; [ \"$public_rc\" = 0 ]; } && ", false))
        return fg_refuse("random readiness script");
    if (strcmp(phase, "write") == 0 && !fg_add_step(s, "FG-NEXT\r\n",
        "geli init -B none -P -K /PUBLIC_TEST_ONLY.key -a HMAC/SHA256 -e AES-XTS -l 256 -s 4096 /dev/vtbd0 && ", false))
        return fg_refuse("authenticated initialization script");
    if (!fg_phase_steps(s, phase) || !fg_add_step(s, "FG-NEXT\r\n", body, true))
        return fg_refuse("public phase script");
    return rvmachine_script_until(&s->script, "FIXTURE-GELI-PHASE-OK\r\n", 23);
}

static bool fg_work(const struct rvmachine_result *r, uint64_t *used)
{
    if (r->retired > FG_MAX_WORK || r->fw_calls > FG_MAX_WORK - r->retired)
        return fg_refuse("global work overflow");
    *used = r->retired + r->fw_calls;
    if (r->device_work > FG_MAX_WORK - *used) return fg_refuse("global work limit");
    *used += r->device_work;
    return true;
}

static bool fg_run(struct fg_state *s, struct rvmachine_result *result)
{
    for (;;) {
        uint64_t used;
        if (!fg_work(result, &used)) return false;
        if (used >= FG_MAX_WORK) return fg_refuse("global work limit");
        if (s->entropy_failed || s->volume.failed) return fg_refuse("source/backend latch");
        uint64_t left = FG_MAX_WORK - used;
        if (rvmachine_run(s->m, left < 4096u ? left : 4096u, result) != RVMACHINE_OK)
            return fg_refuse("machine execution");
        if (s->console_full) return fg_refuse("console limit");
        if (!fg_work(result, &used)) return false;
        if (s->entropy_failed || s->volume.failed) return fg_refuse("final source/backend latch");
        if (rvmachine_script_met(&s->script)) return true;
        if (result->stop != RVMACHINE_STOP_BUDGET) return fg_refuse("incomplete script stop");
    }
}

static bool fg_observed(const struct fg_state *s, const char *phase)
{
    if (strcmp(phase, "wrong") == 0)
        return strstr(s->console, "Wrong key for") != NULL &&
               strstr(s->console, "GELI-WRONG-RC:") != NULL;
    if (strstr(s->console, "AuthenticationAlgorithm: HMAC/SHA256") == NULL)
        return fg_refuse("observed authenticated provider");
    if (strcmp(phase, "tamper") == 0)
        return s->mapped_read &&
               (strstr(s->console, "Input/output error") != NULL ||
                strstr(s->console, "Integrity check failed") != NULL) &&
               strstr(s->console, "GELI-IOERR-RC:") != NULL;
    if (strcmp(phase, "write") == 0 &&
        (!s->mapped_write || s->write_seq == 0 || s->flushes == 0 || s->flush_seq <= s->write_seq)) {
        LOG_WARN("fixture.geli", "PUBLIC barrier counts writes=%llu flushes=%llu last_flush=%llu mapped=%u",
            (unsigned long long)s->write_seq, (unsigned long long)s->flushes,
            (unsigned long long)s->flush_seq, s->mapped_write ? 1u : 0u);
        return fg_refuse("actual guest flush after writes");
    }
    return true;
}

static bool fg_bind(struct fg_state *s, struct platform_private_file *owner,
                    struct rvmachine_disk **outer, const char *kernel_path,
                    const char *volume_path, uint8_t **kernel, size_t *kernel_len,
                    const char *expected)
{
    *kernel = fg_kernel(kernel_path, kernel_len, expected);
    if (*kernel == NULL) return false;
    if (!platform_private_file_open_locked(volume_path, owner)) return fg_refuse("volume open");
    if (!zcl_machine_private_volume_bind(&s->volume, owner, &s->inner)) return false;
    if (s->volume.initial.size != FG_VOLUME_BYTES) return fg_refuse("volume size");
    if (rvmachine_disk_open_backend(outer, FG_VOLUME_BYTES, fg_read, fg_write,
                                   fg_flush, s) != RVMACHINE_OK) return fg_refuse("outer backend");
    return true;
}

static bool fg_create(struct fg_state *s, struct rvmachine_disk **outer,
                      const uint8_t *kernel, size_t kernel_len)
{
    struct rvmachine_config config = {
        .ram_bytes = RVMACHINE_RAM_DEFAULT, .disk = *outer, .cleanse_on_destroy = true,
        .bootargs = "-s kern.random.initial_seeding.bypass_before_seeding=0",
        .console = fg_console, .console_ctx = s, .entropy = fg_entropy, .entropy_ctx = s,
        .entropy_fail_closed = true, .boot_seed = fg_seed, .boot_seed_ctx = s
    };
    if (rvmachine_create(&s->m, &config) != RVMACHINE_OK) return fg_refuse("machine create");
    *outer = NULL; /* successful machine creation owns the outer wrapper */
    return rvmachine_load_kernel(s->m, kernel, kernel_len) == RVMACHINE_OK ||
        fg_refuse("kernel load");
}

static bool fg_emit(struct fg_state *s, const struct rvmachine_result *result,
                    const char *phase, bool ran)
{
    if (fwrite(s->console, 1, s->console_len, stdout) != s->console_len) return false;
    if (!ran || !fg_observed(s, phase)) return false;
    if (!rvmachine_boot_seed_cleared(s->m) || s->entropy_failed || s->volume.failed)
        return fg_refuse("final source/seed state");
    if (printf("PUBLIC_GELI_PROOF phase=%s flushes=%llu write_seq=%llu flush_seq=%llu work=%llu mapped_byte=544 read=%u write=%u\n",
           phase, (unsigned long long)s->flushes, (unsigned long long)s->write_seq,
           (unsigned long long)s->flush_seq,
           (unsigned long long)(result->retired + result->fw_calls + result->device_work),
           s->mapped_read ? 1u : 0u, s->mapped_write ? 1u : 0u) < 0 || fflush(stdout) != 0)
        return false;
    return true;
}

#include "machine_geli_bootstrap.c"

int main(int argc, char **argv)
{
    if (argc >= 2 && strncmp(argv[1], "mounted-", 8) == 0) return fm_main(argc, argv);
    if (argc != 4 || fg_phase(argv[1]) == NULL) return 2;
    struct platform_private_file owner;
    struct rvmachine_disk *outer = NULL;
    struct fg_state *s = calloc(1, sizeof *s);
    struct rvmachine_result result = {0};
    size_t kernel_len = 0;
    uint8_t *kernel = NULL;
    int rc = 1;
    platform_private_file_init(&owner);
    if (s == NULL) { (void)fg_refuse("allocation"); goto out; }
    if (!fg_bind(s, &owner, &outer, argv[2], argv[3], &kernel, &kernel_len, FG_KERNEL_SHA)) goto out;
    if (!fg_script(s, argv[1]) || !fg_create(s, &outer, kernel, kernel_len)) goto out;
    bool ran = fg_run(s, &result);
    if (fg_emit(s, &result, argv[1], ran)) rc = 0;
out:
    if (rc != 0) (void)fg_refuse("final public fixture acceptance");
    if (s != NULL) rvmachine_destroy(s->m);
    rvmachine_disk_close(outer);
    if (s != NULL) rvmachine_disk_close(s->inner);
    platform_private_file_close(&owner);
    free(kernel);
    if (s != NULL) memory_cleanse(s, sizeof *s);
    free(s);
    return rc;
}
