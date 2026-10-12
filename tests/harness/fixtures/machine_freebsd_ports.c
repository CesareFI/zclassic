/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0.
 * PUBLIC real-tty byte fixture; no SSH, credential, or deployment authority. */
#include "rvmachine/rvmachine.h"
#include "platform/positioned_file.h"
#include "platform/rng.h"
#include "platform/clock.h"
#include "base/cleanse.h"
#include "base/hex.h"
#include "base/log_macros.h"
#include "crypto/sha256.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Exact create-only PUBLIC image, including the guest fixture and raw header. */
#define PP_KERNEL_SHA "464e0c3d10c110746b20a588625857f1943d7533085c370b600b909c2380c142"
#define PP_BYTES 4097u
#define PP_WORK UINT64_C(1000000000)
#define PP_CONSOLE 65536u

struct pp_state {
    struct rvmachine *m;
    struct rvmachine_script script;
    bool active[2], ready[2], failed, entropy_failed, short_input, short_sink;
    uint32_t epoch[2];
    bool closing;
    unsigned close_phase, close_unread;
    uint64_t close_completed;
    size_t offered[2], received[2], quota[2], console_len, max_line;
    char console[PP_CONSOLE + 1u];
};

static bool pp_refuse(const char *why)
{
    LOG_WARN("fixture.ports", "PUBLIC FreeBSD ports refused: %s", why);
    return false;
}

static unsigned pp_bias(const struct pp_state *s, unsigned port)
{
    return s->closing && s->close_phase >= 2 ? 53u : port * 31u;
}

static size_t pp_entropy(void *ctx, uint8_t *bytes, size_t n)
{
    struct pp_state *s = ctx;
    if (s->entropy_failed) { memory_cleanse(bytes, n); return 0; }
    for (size_t off = 0; off < n;) {
        size_t take = n - off < 4096u ? n - off : 4096u;
        if (!rng_host_fill(bytes + off, take)) {
            memory_cleanse(bytes, n);
            s->entropy_failed = true;
            return 0;
        }
        off += take;
    }
    return n;
}

static bool pp_seed(void *ctx, uint8_t *bytes, size_t n, size_t *got)
{
    *got = pp_entropy(ctx, bytes, n);
    return *got == n;
}

static void pp_console(void *ctx, uint8_t byte)
{
    struct pp_state *s = ctx;
    if (s->console_len == PP_CONSOLE) { s->failed = true; return; }
    s->console[s->console_len++] = (char)byte;
    s->console[s->console_len] = '\0';
    const char *markers[2] = {"PUBLIC_PORT_RAW_READY_T\r\n", "PUBLIC_PORT_RAW_READY_P\r\n"};
    for (unsigned p = 0; p < 2; p++) {
        size_t n = strlen(markers[p]);
        if (s->console_len >= n && !memcmp(s->console + s->console_len - n, markers[p], n)) {
            s->ready[p] = true;
            s->epoch[p] = s->m->conports[p].generation; /* Read-only callback snapshot. */
        }
    }
    rvmachine_script_console(&s->script, s->m, byte);
}

static bool pp_ram_expected(const struct pp_state *s, unsigned port, size_t i, uint8_t expected)
{
    const struct rvvirtio_chain *c = &s->m->con.dev.chain;
    uint64_t off = s->m->con.ports[port].tx_off + i;
    for (uint32_t j = 0; j < c->nsegs; j++) {
        const struct rvvirtio_seg *seg = &c->segs[j];
        if (seg->write) continue;
        if (off >= seg->len) { off -= seg->len; continue; }
        if (seg->gpa < s->m->mem.base || off > UINT64_MAX - seg->gpa) return false;
        uint64_t addr = seg->gpa + off - s->m->mem.base;
        return addr < s->m->mem.size && s->m->mem.bytes[addr] == expected;
    }
    return false;
}

static void pp_public_prefix(const struct pp_state *s, unsigned port,
                             const uint8_t *bytes, size_t n)
{
    uint8_t expected[8];
    char actual_hex[17], expected_hex[17];
    size_t take = n < sizeof expected ? n : sizeof expected;
    for (size_t i = 0; i < take; i++) expected[i] = (uint8_t)((s->received[port] + i) * 73u + 19u + pp_bias(s, port)) ^ 0xa5u;
    zcl_hex_encode(bytes, take, actual_hex);
    zcl_hex_encode(expected, take, expected_hex);
    const char *marker = port == 0 ? "PUBLIC_PORT_RX_EXACT_T:4097\r\n" : "PUBLIC_PORT_RX_EXACT_P:4097\r\n";
    LOG_WARN("fixture.ports", "fixed PUBLIC prefix len=%zu observed=%s expected=%s rx_exact_seen=%u tx_offset=%llu",
        take, actual_hex, expected_hex, strstr(s->console, marker) ? 1u : 0u, (unsigned long long)s->m->con.ports[port].tx_off);
}

static size_t pp_sink(void *ctx, unsigned p, const uint8_t *bytes, size_t n)
{
    struct pp_state *s = ctx;
    if (p >= 2 || !s->active[p] || !s->ready[p] ||
        s->m->conports[p].generation != s->epoch[p]) {
        (void)pp_refuse("unexpected port/epoch output"); s->failed = true; return 0;
    }
    size_t take = n < s->quota[p] ? n : s->quota[p];
    if (take < n) s->short_sink = true;
    if (take > PP_BYTES - s->received[p]) { (void)pp_refuse("extra port output"); s->failed = true; return 0; }
    for (size_t i = 0; i < take; i++) {
        uint8_t expected = (uint8_t)((s->received[p] + i) * 73u + 19u + pp_bias(s, p)) ^ 0xa5u;
        if (bytes[i] != expected) {
            uint8_t original = (uint8_t)((s->received[p] + i) * 73u + 19u + pp_bias(s, p));
            LOG_WARN("fixture.ports", "PUBLIC response mismatch port=%u offset=%zu original_pattern=%u offered_chunk=%zu ram_matches_expected=%u segments=%u",
                p, s->received[p] + i, bytes[i] == original ? 1u : 0u, n,
                pp_ram_expected(s, p, i, expected) ? 1u : 0u, s->m->con.dev.chain.nsegs);
            pp_public_prefix(s, p, bytes, n);
            (void)pp_refuse("PUBLIC response mismatch"); s->failed = true; return 0;
        }
    }
    s->received[p] += take;
    s->quota[p] -= take;
    return take;
}

static uint8_t *pp_kernel(const char *path, size_t *len)
{
    struct platform_positioned_file f;
    struct platform_positioned_file_snapshot a, b;
    platform_positioned_file_init(&f);
    uint8_t *bytes = NULL;
    if (!platform_positioned_file_open(&f, path) || !platform_positioned_file_snapshot(&f, &a)) goto out;
    if (!a.size || a.size > (UINT64_C(64) << 20)) goto out;
    bytes = malloc((size_t)a.size);
    if (!bytes) goto out;
    for (size_t off = 0; off < a.size;) {
        int64_t got = platform_positioned_file_read(&f, bytes + off, (size_t)a.size - off, off);
        if (got <= 0) { free(bytes); bytes = NULL; goto out; }
        off += (size_t)got;
    }
    struct sha256_ctx sha;
    uint8_t digest[32];
    char hex[65];
    sha256_init(&sha); sha256_write(&sha, bytes, (size_t)a.size); sha256_finalize(&sha, digest);
    zcl_hex_encode(digest, sizeof digest, hex);
    if (strcmp(hex, PP_KERNEL_SHA) || !platform_positioned_file_snapshot(&f, &b) ||
        !platform_positioned_file_snapshot_equal(&a, &b)) { free(bytes); bytes = NULL; goto out; }
    *len = (size_t)a.size;
out:
    platform_positioned_file_close(&f);
    if (!bytes) (void)pp_refuse("exact public kernel descriptor");
    return bytes;
}

static bool pp_feed(struct pp_state *s)
{
    uint8_t bytes[PP_BYTES];
    for (unsigned p = 0; p < 2; p++) {
        if (!s->active[p] || !s->ready[p]) continue;
        if (rvmachine_conport_generation(s->m, p) != s->epoch[p]) return pp_refuse("readiness epoch");
        s->quota[p] = 97;
        rvmachine_conport_resume(s->m, p);
        if (s->offered[p] == PP_BYTES || !rvmachine_conport_guest_open(s->m, p)) continue;
        size_t left = PP_BYTES - s->offered[p];
        for (size_t i = 0; i < left; i++) bytes[i] = (uint8_t)((s->offered[p] + i) * 73u + 19u + pp_bias(s, p));
        size_t accepted = rvmachine_conport_input(s->m, p, bytes, left);
        if (accepted > left) return pp_refuse("input overaccept");
        if (accepted && accepted < left) s->short_input = true;
        s->offered[p] += accepted;
    }
    return true;
}

static bool pp_close_snapshot(struct pp_state *s)
{
    size_t consumed = rvmachine_conport_consumed(s->m, 0);
    const struct rvvirtio_queue *q = &s->m->con.dev.queues[0];
    uint8_t index[2];
    if (!q->ready || !q->num || q->num > RVVIRTIO_QUEUE_MAX || q->driver > UINT64_MAX - 2u ||
        !s->m->con.dev.mem.read(s->m->con.dev.mem.ctx, q->driver + 2u, index, 2))
        return pp_refuse("close receive ring snapshot");
    uint64_t completed = 0;
    for (unsigned i = 0; i < q->num; i++) completed += s->m->con.ports[0].delivered[i];
    if (!completed || completed > PP_BYTES || consumed != PP_BYTES - completed)
        return pp_refuse("close completed-not-reposted setup unobserved");
    s->close_completed = completed;
    LOG_WARN("fixture.ports", "PUBLIC close setup read=1 unread=%u accepted=%zu queued=0 completed_not_reposted=%llu consumed=%zu used=%u last_avail=%u avail=%u",
        s->close_unread, s->offered[0], (unsigned long long)completed, consumed,
        q->used_idx, q->last_avail, (unsigned)(index[0] | (unsigned)index[1] << 8));
    return true;
}

static bool pp_close_setup(struct pp_state *s)
{
        const char *marker = strstr(s->console, "PUBLIC_PORT_CLOSE_SETUP read=1 unread=");
        if (!marker || !strchr(marker, '\n') || s->offered[0] != PP_BYTES ||
            rvmachine_conport_queued(s->m, 0) != 0) return true;
        if (sscanf(marker, "PUBLIC_PORT_CLOSE_SETUP read=1 unread=%u", &s->close_unread) != 1 ||
            !s->close_unread || s->close_unread > PP_BYTES || !pp_close_snapshot(s))
            return pp_refuse("close public tty setup");
        s->ready[0] = false;
        s->close_phase = 1;
        return rvmachine_console_input(s->m, (const uint8_t *)"g\n", 2) == 2 || pp_refuse("close console gate");
}

static bool pp_close_rebind(struct pp_state *s)
{
    if (!strstr(s->console, "PUBLIC_PORT_CLOSED_T\r\n")) return true;
    if (rvmachine_conport_guest_open(s->m, 0) || !rvmachine_conport_close(s->m, 0) ||
        !rvmachine_conport_open(s->m, 0) || rvmachine_conport_generation(s->m, 0) == s->epoch[0])
        return pp_refuse("close fresh host generation");
    s->offered[0] = s->received[0] = 0;
    s->close_phase = 2;
    return rvmachine_console_input(s->m, (const uint8_t *)"r\n", 2) == 2 || pp_refuse("reopen console gate");
}

static bool pp_close_progress(struct pp_state *s)
{
    if (!s->closing || s->close_phase >= 2) return true;
    return s->close_phase == 0 ? pp_close_setup(s) : pp_close_rebind(s);
}

static bool pp_work(const struct rvmachine_result *r, uint64_t *used)
{
    if (r->retired > PP_WORK || r->fw_calls > PP_WORK - r->retired) return false;
    *used = r->retired + r->fw_calls;
    if (r->device_work > PP_WORK - *used) return false;
    *used += r->device_work;
    return true;
}

static bool pp_final(const struct pp_state *s, const struct rvmachine_result *r,
                     int64_t end, uint64_t *used)
{
    int64_t now = clock_now_monotonic_ns();
    return !s->failed && !s->entropy_failed && pp_work(r, used) &&
        now > 0 && now < end;
}

static bool pp_run_valid(const struct pp_state *s, const struct rvmachine_result *r,
                         enum rvmachine_status err, int64_t end, uint64_t *used)
{
    if (err == RVMACHINE_OK && pp_final(s, r, end, used)) return true;
    LOG_WARN("fixture.ports", "status=%s stop=%s failed=%u entropy_failed=%u T=%zu/%zu P=%zu/%zu ready=%u/%u",
        rvmachine_status_name(err), rvmachine_stop_name(r->stop), s->failed ? 1u : 0u,
        s->entropy_failed ? 1u : 0u, s->offered[0], s->received[0], s->offered[1],
        s->received[1], s->ready[0] ? 1u : 0u, s->ready[1] ? 1u : 0u);
    return pp_refuse("final machine/source/work state");
}

static bool pp_run(struct pp_state *s, struct rvmachine_result *r)
{
    int64_t now = clock_now_monotonic_ns();
    if (now <= 0 || now > INT64_MAX - INT64_C(90000000000)) return pp_refuse("clock bound");
    int64_t end = now + INT64_C(90000000000);
    for (;;) {
        uint64_t used;
        if (clock_now_monotonic_ns() >= end || !pp_work(r, &used) || used >= PP_WORK)
            return pp_refuse("global work/time bound");
        if (s->failed || s->entropy_failed || !pp_close_progress(s) || !pp_feed(s)) return pp_refuse("source/byte latch");
        uint64_t left = PP_WORK - used;
        enum rvmachine_status err = rvmachine_run(s->m, left < 4096u ? left : 4096u, r);
        if (!pp_run_valid(s, r, err, end, &used)) return false;
        if (rvmachine_script_met(&s->script)) return true;
        if (r->stop != RVMACHINE_STOP_BUDGET) return pp_refuse("incomplete guest stop");
    }
}

static bool pp_echo_guard(const char *command)
{
    const char *goal = "PUBLIC_PORT_PHASE_OK\r\n";
    struct rvmachine_script *observer = calloc(1, sizeof *observer);
    if (!observer) return pp_refuse("echo observer allocation");
    rvmachine_script_init(observer);
    bool ok = rvmachine_script_until(observer, goal, strlen(goal));
    for (size_t i = 0; ok && command[i]; i++) rvmachine_script_console(observer, NULL, (uint8_t)command[i]);
    ok = ok && !rvmachine_script_met(observer);
    for (size_t i = 0; ok && goal[i]; i++) rvmachine_script_console(observer, NULL, (uint8_t)goal[i]);
    ok = ok && rvmachine_script_met(observer);
    free(observer);
    return ok || pp_refuse("echo-only goal negative");
}

static bool pp_step(struct pp_state *s, const char *after, const char *body,
                    const char *octal)
{
    char command[256];
    int n = snprintf(command, sizeof command, "%sprintf '%s\\n'\n", body, octal);
    if (n <= 0 || (size_t)n >= sizeof command) return pp_refuse("short console line bound");
    if ((size_t)n > s->max_line) s->max_line = (size_t)n;
    if (!pp_echo_guard(command)) return false;
    return rvmachine_script_add(&s->script, after, strlen(after), command, (size_t)n);
}

static bool pp_script(struct pp_state *s, const char *role)
{
    const char *next = "\\120\\120\\055\\116\\105\\130\\124";
    const char *final = "\\120\\125\\102\\114\\111\\103\\137\\120\\117\\122\\124\\137\\120\\110\\101\\123\\105\\137\\117\\113";
    rvmachine_script_init(&s->script);
    if (!rvmachine_script_add(&s->script, "Enter full pathname", 19, "\n", 1)) return false;
    if (!pp_step(s, "# ", "[ \"$(sysctl -n kern.random.initial_seeding.bypass_before_seeding)\" = 0 ] && ", next)) return false;
    if (!pp_step(s, "PP-NEXT\r\n", "[ \"$(sysctl -n kern.random.initial_seeding.read_random_bypassed_before_seeding)\" = 0 ] && ", next)) return false;
    if (!pp_step(s, "PP-NEXT\r\n", "[ \"$(sysctl -n kern.random.initial_seeding.arc4random_bypassed_before_seeding)\" = 0 ] && ", next)) return false;
    if (!pp_step(s, "PP-NEXT\r\n", "{ read -r -t 2 PUBLIC_RANDOM < /dev/random; public_rc=$?; unset PUBLIC_RANDOM; [ \"$public_rc\" = 0 ]; } && ",
        "\\120\\120\\055\\110\\105\\101\\114\\124\\110")) return false;
    if (!strcmp(role, "BOTH")) {
        if (!pp_step(s, "PP-HEALTH\r\n", "/sbin/public-port-bytes T & public_pid=$!; ", next)) return false;
        if (!pp_step(s, "PP-NEXT\r\n", "/sbin/public-port-bytes P; public_rc=$?; wait \"$public_pid\"; public_other=$?; [ \"$public_rc\" = 0 ] && [ \"$public_other\" = 0 ] && ", final)) return false;
    } else {
        const char *body = !strcmp(role, "CLOSE") ? "/sbin/public-port-bytes CLOSE && " :
            (!strcmp(role, "T") ? "/sbin/public-port-bytes T && " : "/sbin/public-port-bytes P && ");
        if (!pp_step(s, "PP-HEALTH\r\n", body, final)) return false;
    }
    return rvmachine_script_until(&s->script, "PUBLIC_PORT_PHASE_OK\r\n", 22);
}

static bool pp_close_proof(const struct pp_state *s)
{
    if (s->closing && (s->close_phase != 2 || !s->close_completed || !s->close_unread))
        return pp_refuse("completed old suffix close proof");
    return true;
}

static bool pp_proof(struct pp_state *s, const struct rvmachine_result *r, const char *role)
{
    if (!pp_close_proof(s)) return false;
    if (!s->short_input || !s->short_sink || !rvmachine_boot_seed_cleared(s->m))
        return pp_refuse("partial transfer/seed evidence");
    for (unsigned p = 0; p < 2; p++) {
        if (s->active[p]) {
            if (s->offered[p] != PP_BYTES || s->received[p] != PP_BYTES ||
                rvmachine_conport_queued(s->m, p) != 0) return pp_refuse("exact counts/queue");
        } else if (s->offered[p] || s->received[p]) return pp_refuse("inactive port isolation");
    }
    uint64_t work;
    if (!pp_work(r, &work)) return false;
    return printf("PUBLIC_FREEBSD_PORT_PROOF role=%s T=%zu/%zu P=%zu/%zu short_input=1 short_sink=1 max_console_line=%zu work=%llu\n",
        role, s->offered[0], s->received[0], s->offered[1], s->received[1],
        s->max_line, (unsigned long long)work) >= 0 && fflush(stdout) == 0;
}

static bool pp_role(const char *role)
{
    return !strcmp(role, "T") || !strcmp(role, "P") || !strcmp(role, "BOTH") || !strcmp(role, "CLOSE");
}

int main(int argc, char **argv)
{
    if (argc != 3 || !pp_role(argv[1])) return 2;
    struct pp_state *s = calloc(1, sizeof *s);
    struct rvmachine_result result = {0};
    uint8_t *kernel = NULL;
    size_t len = 0;
    int rc = 1;
    if (!s) { (void)pp_refuse("allocation"); return 1; }
    s->active[0] = strcmp(argv[1], "P") != 0;
    s->closing = !strcmp(argv[1], "CLOSE");
    s->active[1] = !s->closing && strcmp(argv[1], "T") != 0;
    kernel = pp_kernel(argv[2], &len);
    if (!kernel || !pp_script(s, argv[1])) goto out;
    struct rvmachine_config config = {
        .ram_bytes = RVMACHINE_RAM_DEFAULT, .cleanse_on_destroy = true,
        .bootargs = "-s kern.random.initial_seeding.bypass_before_seeding=0",
        .console = pp_console, .console_ctx = s, .entropy = pp_entropy, .entropy_ctx = s,
        .entropy_fail_closed = true, .boot_seed = pp_seed, .boot_seed_ctx = s,
        .conport_count = 2, .conport_names = {"z23.l0.t", "z23.l0.p"},
        .conport_sink = pp_sink, .conport_ctx = s
    };
    if (rvmachine_create(&s->m, &config) != RVMACHINE_OK ||
        rvmachine_load_kernel(s->m, kernel, len) != RVMACHINE_OK) goto out;
    bool ran = pp_run(s, &result);
    if (fwrite(s->console, 1, s->console_len, stdout) != s->console_len || fflush(stdout) != 0) goto out;
    if (ran && pp_proof(s, &result, argv[1])) rc = 0;
out:
    if (rc) (void)pp_refuse("final actual guest byte acceptance");
    rvmachine_destroy(s->m);
    free(kernel);
    memory_cleanse(s, sizeof *s);
    free(s);
    return rc;
}
