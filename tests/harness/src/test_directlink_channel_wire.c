/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * directlink channel over two real UDP sockets on 127.0.0.1.
 *
 * The punch machine refuses loopback sources by design, so this test runs
 * below it: directlink_channel_open_at supplies the peer address, and the
 * address confirmation, sealing, replay window and source check are the same
 * as after a punch. The handshake secret is a fixed test value; the pairing
 * secret is a fixed test value too.
 *
 * Z23_DIRECTLINK_BENCH_S=<seconds> sets the duration of each throughput
 * measurement (default 0.2 s). The result lines carry the compiler, the CPU
 * model and the UTC date. */

#include "test/test_core.h"

#include "gamelink/directlink_channel.h"
#include "test/directlink_udp.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

struct wire {
    uint8_t hs[2][32];
    struct udp_end end[2];
    struct directlink_channel ch[2];
    uint64_t received[2];
    uint64_t received_bytes[2];
    uint8_t last[16];
    size_t last_len;
};

static void wire_collect(void *user, const uint8_t *payload, size_t len)
{
    struct wire *w = user;
    w->received[1]++;
    w->received_bytes[1] += len;
    w->last_len = len < sizeof w->last ? len : sizeof w->last;
    memcpy(w->last, payload, w->last_len);
}

static void wire_collect_a(void *user, const uint8_t *payload, size_t len)
{
    struct wire *w = user;
    (void)payload;
    w->received[0]++;
    w->received_bytes[0] += len;
}

static void wire_secrets(struct directlink_channel_secrets *s, uint8_t hs[32])
{
    memset(s, 0, sizeof *s);
    memset(hs, 7, 32);
    s->scope = DIRECTLINK_SCOPE_INTRA_FLEET;
    s->handshake = hs;
    s->handshake_len = 32;
    memset(s->psk, 0x5A, sizeof s->psk);
    memset(s->initiator_id, 0x01, 32);
    memset(s->responder_id, 0x02, 32);
    memset(s->attempt, 0x03, sizeof s->attempt);
}

static void wire_poll(struct wire *w)
{
    (void)directlink_channel_poll(&w->ch[0], wire_collect_a, w);
    (void)directlink_channel_poll(&w->ch[1], wire_collect, w);
}

static bool wire_is_open(const struct wire *w)
{
    return directlink_channel_state(&w->ch[0]) == DIRECTLINK_CHANNEL_OPEN &&
           directlink_channel_state(&w->ch[1]) == DIRECTLINK_CHANNEL_OPEN;
}

static bool wire_has_hello(const struct wire *w)
{
    return w->received[1] > 0;
}

/* Poll both ends until `done` holds, pausing 1 ms between idle polls. The
 * bound is a count of polls, not a reading of the clock. */
static void wire_pump(struct wire *w, bool (*done)(const struct wire *))
{
    for (unsigned i = 0; i < 2000u && !done(w); i++) {
        wire_poll(w);
        struct timespec pause = {0, 1000000};
        (void)nanosleep(&pause, NULL); /* real-clock: kernel loopback, no injected clock */
    }
}

static bool wire_open(struct wire *w)
{
    memset(w, 0, sizeof *w);
    if (!udp_end_open(&w->end[0]) || !udp_end_open(&w->end[1]))
        return false;
    for (int i = 0; i < 2; i++) {
        struct directlink_channel_config cfg;
        memset(&cfg, 0, sizeof cfg);
        wire_secrets(&cfg.secrets, w->hs[i]);
        cfg.allow_loopback = true;
        cfg.initiator = i == 0;
        cfg.net = udp_ops(&w->end[i]);
        struct directlink_addr peer;
        memset(&peer, 0, sizeof peer);
        peer.family = DIRECTLINK_V4;
        peer.ip[0] = 127;
        peer.ip[3] = 1;
        peer.port = w->end[1 - i].port;
        if (directlink_channel_open_at(&w->ch[i], &cfg, &peer) !=
            DIRECTLINK_CHANNEL_OK)
            return false;
    }
    wire_pump(w, wire_is_open);
    return wire_is_open(w);
}

static void wire_close(struct wire *w)
{
    directlink_channel_close(&w->ch[0]);
    directlink_channel_close(&w->ch[1]);
    udp_end_close(&w->end[0]);
    udp_end_close(&w->end[1]);
}

static void print_environment(void)
{
    char cpu[128] = "unknown";
    FILE *f = fopen("/proc/cpuinfo", "r");
    char line[256];
    while (f && fgets(line, sizeof line, f)) {
        if (strncmp(line, "model name", 10) == 0) {
            const char *colon = strchr(line, ':');
            if (colon) {
                snprintf(cpu, sizeof cpu, "%s", colon + 2);
                cpu[strcspn(cpu, "\n")] = 0;
            }
            break;
        }
    }
    if (f)
        fclose(f);
    time_t now = time(NULL);
    struct tm utc;
    char date[32] = "unknown";
    if (gmtime_r(&now, &utc))
        strftime(date, sizeof date, "%Y-%m-%dT%H:%M:%SZ", &utc);
    printf("directlink_channel_wire: compiler=%s cpu=%s date=%s\n", __VERSION__,
           cpu, date);
}

static double bench_seconds(void)
{
    const char *text = getenv("Z23_DIRECTLINK_BENCH_S");
    double value = text ? atof(text) : 0.0;
    return value > 0.0 && value <= 60.0 ? value : 0.2;
}

/* Send full-size payloads from side 0 for `seconds`, draining side 1 as we go.
 * `capped` keeps the session's default byte cap; otherwise the cap is lifted
 * to measure the path itself. */
static void bench_run(struct wire *w, double seconds, bool capped)
{
    uint8_t payload[DIRECTLINK_CHANNEL_MAX_PAYLOAD];
    memset(payload, 0xA5, sizeof payload);
    if (!capped) {
        w->ch[0].link.rate_bytes_per_s = UINT32_MAX;
        w->ch[0].link.burst_bytes = UINT32_MAX;
        w->ch[0].link.bucket_bytes = UINT32_MAX;
    }
    uint64_t sent = 0, base_rx = w->received[1], base_bytes = w->received_bytes[1];
    int64_t start = clock_now_monotonic_ns();
    int64_t end = start + (int64_t)(seconds * 1e9);
    int64_t now = start;
    while (now < end) {
        enum directlink_channel_status st =
            directlink_channel_send(&w->ch[0], payload, sizeof payload);
        if (st == DIRECTLINK_CHANNEL_OK) {
            sent++;
        } else {
            /* Back off on the byte cap: the session refills its bucket in
             * whole bytes per call, so a spinning caller would starve it. */
            struct timespec pause = {0, 200000};
            (void)nanosleep(&pause, NULL);
        }
        if ((sent & 7u) == 0)
            wire_poll(w);
        now = clock_now_monotonic_ns();
    }
    for (int i = 0; i < 64; i++)
        wire_poll(w);
    double elapsed = (double)(now - start) / 1e9;
    uint64_t rx = w->received[1] - base_rx;
    double mbit = (double)(w->received_bytes[1] - base_bytes) * 8.0 / elapsed / 1e6;
    printf("directlink_channel_wire: %s payload=%zu sent=%llu delivered=%llu "
           "seconds=%.2f goodput=%.1f Mbit/s\n",
           capped ? "default_cap" : "uncapped", sizeof payload,
           (unsigned long long)sent, (unsigned long long)rx, elapsed, mbit);
}

static int dcw_case_hello(void)
{
    int failures = 0;
    TEST_CASE("channel wire: hello crosses real loopback sockets sealed") {
        static struct wire w;
        ASSERT(wire_open(&w));
        uint64_t before = w.ch[0].link.stats.sent_bytes;
        uint64_t sent_before = w.ch[0].link.stats.sent;
        ASSERT_EQ(directlink_channel_send(&w.ch[0], (const uint8_t *)"hello", 5),
                  DIRECTLINK_CHANNEL_OK);
        wire_pump(&w, wire_has_hello);
        ASSERT_EQ(w.received[1], (uint64_t)1);
        ASSERT_EQ((int)w.last_len, 5);
        ASSERT(memcmp(w.last, "hello", 5) == 0);
        ASSERT_EQ(w.ch[0].link.stats.sent - sent_before, (uint64_t)1);
        ASSERT_EQ(w.ch[0].link.stats.sent_bytes - before,
                  (uint64_t)(5u + DIRECTLINK_CHANNEL_OVERHEAD));
        printf("directlink_channel_wire: hello payload=5 sealed_datagram=%u "
               "channel_overhead=%u with_ip_udp=%u\n",
               5u + DIRECTLINK_CHANNEL_OVERHEAD, DIRECTLINK_CHANNEL_OVERHEAD,
               DIRECTLINK_CHANNEL_OVERHEAD + 28u);
        wire_close(&w);
    } TEST_END;
    return failures;
}

static int dcw_case_throughput(void)
{
    int failures = 0;
    TEST_CASE("channel wire: throughput on loopback") {
        static struct wire w;
        ASSERT(wire_open(&w));
        print_environment();
        bench_run(&w, bench_seconds(), true);
        bench_run(&w, bench_seconds(), false);
        ASSERT(w.received[1] > 0);
        wire_close(&w);
    } TEST_END;
    return failures;
}

int test_directlink_channel_wire(void)
{
    int failures = 0;
    failures += dcw_case_hello();
    failures += dcw_case_throughput();
    return failures;
}
