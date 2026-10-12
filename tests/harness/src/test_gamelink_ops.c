/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * gamelink over the datagram seam: two sessions on the deterministic network
 * exchange sealed datagrams with no socket and no wall clock. */

#include "test/test_core.h"

#include "test/directlink_simnet.h"

#include <string.h>

struct glo_sink {
    uint32_t count;
    uint8_t last[16];
    size_t last_len;
};

static void glo_collect(void *user, uint64_t seq, const uint8_t *payload,
                        size_t len)
{
    struct glo_sink *sink = user;
    (void)seq;
    sink->count++;
    sink->last_len = len < sizeof sink->last ? len : sizeof sink->last;
    memcpy(sink->last, payload, sink->last_len);
}

static const uint8_t k_material[32] = {1, 2, 3, 4, 5, 6, 7, 8};

static int glo_case_exchange(void)
{
    int failures = 0;
    TEST_CASE("gamelink ops: hello crosses the simulated network sealed") {
        struct ns net;
        ns_init(&net, 7, 0);
        int na = ns_add_public(&net, ns_ip4(45, 10, 100, 1, 5000), 10);
        int nb = ns_add_public(&net, ns_ip4(45, 10, 100, 2, 5000), 10);
        struct simnet_end ea = {.net = &net, .node = na};
        struct simnet_end eb = {.net = &net, .node = nb};
        struct gamelink_ops oa = simnet_ops(&ea);
        struct gamelink_ops ob = simnet_ops(&eb);
        clock_iface_t clock = simnet_clock(&net);
        const uint8_t addr_a[4] = {45, 10, 100, 1};
        const uint8_t addr_b[4] = {45, 10, 100, 2};
        struct gamelink a, b;
        ASSERT_EQ(gamelink_open_ops(&a, k_material, sizeof k_material, true,
                                    addr_b, 5000, &oa, &clock),
                  GAMELINK_OK);
        ASSERT_EQ(gamelink_open_ops(&b, k_material, sizeof k_material, false,
                                    addr_a, 5000, &ob, &clock),
                  GAMELINK_OK);
        ASSERT_EQ(gamelink_send(&a, (const uint8_t *)"hello", 5, NULL),
                  GAMELINK_OK);
        ns_advance(&net, 20);
        struct glo_sink sink;
        memset(&sink, 0, sizeof sink);
        ASSERT_EQ((int)gamelink_poll(&b, glo_collect, &sink), 1);
        ASSERT_EQ((int)sink.last_len, 5);
        ASSERT(memcmp(sink.last, "hello", 5) == 0);
        ASSERT_EQ(ea.sent, (uint32_t)1);
        ASSERT_EQ(eb.received, (uint32_t)1);
        /* The datagram on the wire is header + payload + tag, not plaintext. */
        ASSERT_EQ((int)b.stats.recv_bytes,
                  (int)(GAMELINK_HEADER_BYTES + 5 + GAMELINK_TAG_BYTES));
        /* Ping and pong measure an exact round trip on the simulated clock. */
        ASSERT_EQ(gamelink_ping(&a), GAMELINK_OK);
        ns_advance(&net, 40);
        (void)gamelink_poll(&b, NULL, NULL);
        ns_advance(&net, 60);
        (void)gamelink_poll(&a, NULL, NULL);
        ASSERT_EQ(a.stats.pongs_recv, (uint64_t)1);
        ASSERT_EQ((int)a.rtt_us, 40000);
        gamelink_close(&a);
        ASSERT_EQ(gamelink_send(&a, (const uint8_t *)"x", 1, NULL),
                  GAMELINK_CLOSED);
        ASSERT_EQ((int)gamelink_poll(&a, NULL, NULL), 0);
    } TEST_END;
    return failures;
}

static int glo_case_wrong_key_and_peer(void)
{
    int failures = 0;
    TEST_CASE("gamelink ops: a wrong key is dropped and a peer is learned") {
        struct ns net;
        ns_init(&net, 7, 0);
        int na = ns_add_public(&net, ns_ip4(45, 10, 100, 1, 5000), 5);
        int nb = ns_add_public(&net, ns_ip4(45, 10, 100, 2, 5000), 5);
        struct simnet_end ea = {.net = &net, .node = na};
        struct simnet_end eb = {.net = &net, .node = nb};
        struct gamelink_ops oa = simnet_ops(&ea);
        struct gamelink_ops ob = simnet_ops(&eb);
        clock_iface_t clock = simnet_clock(&net);
        const uint8_t addr_b[4] = {45, 10, 100, 2};
        uint8_t other[32] = {9};
        struct gamelink a, b;
        ASSERT_EQ(gamelink_open_ops(&a, other, sizeof other, true, addr_b, 5000,
                                    &oa, &clock),
                  GAMELINK_OK);
        ASSERT_EQ(gamelink_open_ops(&b, k_material, sizeof k_material, false,
                                    NULL, 0, &ob, &clock),
                  GAMELINK_OK);
        ASSERT_EQ(gamelink_send(&a, (const uint8_t *)"hello", 5, NULL),
                  GAMELINK_OK);
        ns_advance(&net, 20);
        ASSERT_EQ((int)gamelink_poll(&b, NULL, NULL), 0);
        ASSERT_EQ(b.stats.dropped_malformed + b.stats.dropped_auth,
                  (uint64_t)1);
        ASSERT_EQ((int)b.peer_port, 0); /* nothing authenticated: no peer */
        ASSERT_EQ(gamelink_open_ops(&a, NULL, 0, true, addr_b, 5000, &oa, &clock),
                  GAMELINK_ARGUMENT);
        struct gamelink_ops bare = {0};
        ASSERT_EQ(gamelink_open_ops(&a, k_material, sizeof k_material, true,
                                    addr_b, 5000, &bare, &clock),
                  GAMELINK_ARGUMENT);
    } TEST_END;
    return failures;
}

/* A seam that also hands every datagram back to the sender. */
struct glo_mirror {
    struct simnet_end end;
    uint8_t self[4];
    uint16_t self_port;
};

static int glo_mirror_send(void *ctx, const uint8_t addr[4], uint16_t port,
                           const void *data, size_t len)
{
    struct glo_mirror *m = ctx;
    (void)simnet_send(&m->end, m->self, m->self_port, data, len);
    return simnet_send(&m->end, addr, port, data, len);
}

static int glo_mirror_recv(void *ctx, void *data, size_t cap, uint8_t addr[4],
                           uint16_t *port)
{
    struct glo_mirror *m = ctx;
    return simnet_recv(&m->end, data, cap, addr, port);
}

static int glo_case_reflection(void)
{
    int failures = 0;
    TEST_CASE("gamelink ops: a datagram reflected to its sender is dropped") {
        struct ns net;
        ns_init(&net, 7, 0);
        int na = ns_add_public(&net, ns_ip4(45, 10, 100, 1, 5000), 5);
        (void)ns_add_public(&net, ns_ip4(45, 10, 100, 2, 5000), 5);
        struct glo_mirror m = {.end = {.net = &net, .node = na},
                               .self = {45, 10, 100, 1}, .self_port = 5000};
        struct gamelink_ops ops = {glo_mirror_send, glo_mirror_recv, &m};
        clock_iface_t clock = simnet_clock(&net);
        const uint8_t peer[4] = {45, 10, 100, 2};
        struct gamelink a;
        ASSERT_EQ(gamelink_open_ops(&a, k_material, sizeof k_material, true, peer, 5000, &ops, &clock), GAMELINK_OK);
        ASSERT_EQ(gamelink_send(&a, (const uint8_t *)"hello", 5, NULL), GAMELINK_OK);
        ns_advance(&net, 20);
        struct glo_sink sink;
        memset(&sink, 0, sizeof sink);
        ASSERT_EQ((int)gamelink_poll(&a, glo_collect, &sink), 0);
        ASSERT_EQ(a.stats.dropped_auth, (uint64_t)1);
        ASSERT_EQ(a.stats.recv, (uint64_t)0);
    } TEST_END;
    return failures;
}

struct glo_ticks {
    int64_t ns;
};

static int64_t glo_ticks_now(void *self)
{
    return ((struct glo_ticks *)self)->ns;
}

static int glo_case_sub_byte_refill(void)
{
    int failures = 0;
    TEST_CASE("gamelink ops: a fast caller still accrues the byte cap") {
        struct ns net;
        ns_init(&net, 7, 0);
        int na = ns_add_public(&net, ns_ip4(45, 10, 100, 1, 5000), 5);
        struct simnet_end ea = {.net = &net, .node = na};
        struct gamelink_ops oa = simnet_ops(&ea);
        struct glo_ticks ticks = {0};
        clock_iface_t clock = {.now_monotonic_ns = glo_ticks_now, .now_wall_ms = simnet_wall_ms, .self = &ticks};
        const uint8_t peer[4] = {45, 10, 100, 2};
        struct gamelink a;
        ASSERT_EQ(gamelink_open_ops(&a, k_material, sizeof k_material, true, peer, 5000, &oa, &clock), GAMELINK_OK);
        a.rate_bytes_per_s = 1000;
        a.burst_bytes = 100;
        a.bucket_bytes = 0;
        int sent_at = -1;
        for (int i = 1; i <= 2000 && sent_at < 0; i++) {
            ticks.ns += 100000; /* 0.1 byte of credit per call */
            if (gamelink_send(&a, (const uint8_t *)"hello", 5, NULL) == GAMELINK_OK)
                sent_at = i;
        }
        ASSERT(sent_at >= 545 && sent_at <= 560); /* 55 bytes at 1000 B/s */
    } TEST_END;
    return failures;
}

static int glo_case_pong_budget(void)
{
    int failures = 0;
    TEST_CASE("gamelink ops: pings cannot spend the byte cap or exceed the pong budget") {
        struct ns net;
        ns_init(&net, 7, 0);
        int na = ns_add_public(&net, ns_ip4(45, 10, 100, 1, 5000), 1);
        int nb = ns_add_public(&net, ns_ip4(45, 10, 100, 2, 5000), 1);
        struct simnet_end ea = {.net = &net, .node = na};
        struct simnet_end eb = {.net = &net, .node = nb};
        struct gamelink_ops oa = simnet_ops(&ea);
        struct gamelink_ops ob = simnet_ops(&eb);
        clock_iface_t clock = simnet_clock(&net);
        const uint8_t addr_a[4] = {45, 10, 100, 1};
        const uint8_t addr_b[4] = {45, 10, 100, 2};
        struct gamelink a, b;
        ASSERT_EQ(gamelink_open_ops(&a, k_material, sizeof k_material, true, addr_b, 5000, &oa, &clock), GAMELINK_OK);
        ASSERT_EQ(gamelink_open_ops(&b, k_material, sizeof k_material, false, addr_a, 5000, &ob, &clock), GAMELINK_OK);
        for (int i = 0; i < 100; i++) {
            ASSERT_EQ(gamelink_ping(&a), GAMELINK_OK);
            ns_advance(&net, net.now_ms + 1);
            (void)gamelink_poll(&b, NULL, NULL);
        }
        ASSERT_EQ(b.stats.sent, (uint64_t)GAMELINK_PONG_PER_S);
        ASSERT_EQ(b.stats.pongs_suppressed, b.stats.recv - GAMELINK_PONG_PER_S);
        ASSERT_EQ(b.bucket_bytes, (int64_t)b.burst_bytes);
    } TEST_END;
    return failures;
}

int test_gamelink_ops(void)
{
    int failures = 0;
    failures += glo_case_reflection();
    failures += glo_case_sub_byte_refill();
    failures += glo_case_pong_budget();
    failures += glo_case_exchange();
    failures += glo_case_wrong_key_and_peer();
    return failures;
}
