/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * directlink channel: key derivation known answers (values computed
 * independently with OpenSSL HKDF over SHA3-256, recipe below), the pairing-secret rules,
 * and channels opened across the NAT models of the deterministic network,
 * with forged, replayed, reordered, lost and post-close datagrams. */

#include "test/test_core.h"

#include "gamelink/directlink_channel.h"
#include "test/directlink_simnet.h"

#include <string.h>

/* Re-deriving the known answers with `openssl kdf` (all inputs are byte fills):
 *   PS = HKDF(salt "z23/directlink/v1/psk", ikm psk, info attempt)
 *   material = HKDF(salt "z23/directlink/v1/channel", ikm handshake || PS,
 *                   info scope || attempt || initiator_id || responder_id)
 *   probe    = the same with salt "z23/directlink/v1/probe"
 * HKDF is extract-then-expand over HMAC-SHA3-256, 32 output bytes; scope is
 * one byte (intra_fleet 0, inter_fleet 1); handshake 32 x 0x11, psk 32 x 0x22
 * (0x23 for the second vector), initiator_id 32 x 0x33, responder_id 32 x
 * 0x44, attempt 16 x 0x55. */

#define STEP_MS 10
#define RUN_LIMIT_MS 8000

enum tap_mode { TAP_PASS = 0, TAP_FORGE_FROM_THIRD, TAP_REPLAY, TAP_HOLD };

#define HELD_MAX 8u

struct tap {
    struct simnet_end end;
    enum tap_mode mode;
    int third;
    uint8_t held[HELD_MAX][NS_PKT];
    size_t held_len[HELD_MAX];
    uint8_t held_ip[HELD_MAX][4];
    uint16_t held_port[HELD_MAX];
    size_t held_n;
};

static int tap_send(void *ctx, const uint8_t addr[4], uint16_t port,
                    const void *data, size_t len)
{
    struct tap *t = ctx;
    if (t->mode == TAP_HOLD && t->held_n < HELD_MAX && len <= NS_PKT) {
        memcpy(t->held[t->held_n], data, len);
        memcpy(t->held_ip[t->held_n], addr, 4);
        t->held_port[t->held_n] = port;
        t->held_len[t->held_n++] = len;
        return (int)len;
    }
    int rc = simnet_send(&t->end, addr, port, data, len);
    if (t->mode == TAP_REPLAY)
        (void)simnet_send(&t->end, addr, port, data, len);
    if (t->mode == TAP_FORGE_FROM_THIRD) {
        struct directlink_addr to = ns_ip4(addr[0], addr[1], addr[2], addr[3], port);
        (void)ns_send(t->end.net, t->third, &to, data, len);
    }
    return rc;
}

static int tap_recv(void *ctx, void *data, size_t cap, uint8_t addr[4],
                    uint16_t *port)
{
    struct tap *t = ctx;
    return simnet_recv(&t->end, data, cap, addr, port);
}

static void tap_flush_reversed(struct tap *t)
{
    for (size_t i = t->held_n; i > 0; i--)
        (void)simnet_send(&t->end, t->held_ip[i - 1], t->held_port[i - 1],
                          t->held[i - 1], t->held_len[i - 1]);
    t->held_n = 0;
    t->mode = TAP_PASS;
}

struct sink {
    uint32_t count;
    uint8_t last[32];
    size_t last_len;
    uint8_t order[HELD_MAX];
};

static void sink_collect(void *user, const uint8_t *payload, size_t len)
{
    struct sink *s = user;
    if (s->count < HELD_MAX && len > 0)
        s->order[s->count] = payload[len - 1];
    s->count++;
    s->last_len = len < sizeof s->last ? len : sizeof s->last;
    memcpy(s->last, payload, s->last_len);
}

struct world {
    struct ns net;
    clock_iface_t clock;
    struct tap tap[2];
    uint8_t hs[2][32];
    struct directlink_channel ch[2];
    struct sink sink[2];
    int64_t keepalive_ms;
    struct directlink_addr host[2];
    struct directlink_addr reflex[2];
};

static const uint8_t k_hs[32] = {0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
                                 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
                                 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
                                 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11};

static void fill_secrets(struct directlink_channel_secrets *s,
                         enum directlink_scope scope, uint8_t psk_fill,
                         uint8_t hs[32])
{
    memset(s, 0, sizeof *s);
    memcpy(hs, k_hs, sizeof k_hs);
    s->scope = scope;
    s->handshake = hs;
    s->handshake_len = sizeof k_hs;
    memset(s->psk, psk_fill, sizeof s->psk);
    memset(s->initiator_id, 0x33, 32);
    memset(s->responder_id, 0x44, 32);
    memset(s->attempt, 0x55, sizeof s->attempt);
}

static void world_init(struct world *w, uint64_t seed, enum ns_nat_kind ka,
                       enum ns_nat_kind kb)
{
    memset(w, 0, sizeof *w);
    ns_init(&w->net, seed, 0);
    w->clock = simnet_clock(&w->net);
    enum ns_nat_kind kinds[2] = {ka, kb};
    for (int i = 0; i < 2; i++) {
        uint8_t id = (uint8_t)(10 + 10 * i);
        uint8_t ext[4] = {45, 20, 113, id};
        if (kinds[i] == NS_NAT_NONE) {
            w->host[i] = ns_ip4(45, 10, 100, id, 5000);
            w->reflex[i] = w->host[i];
            w->tap[i].end.node = ns_add_public(&w->net, w->host[i], 20);
        } else {
            w->host[i] = ns_ip4(10, 0, id, 2, 5000);
            /* A symmetric mapping is a fresh port per destination, so the port a
             * discovery observer saw is not the one the peer will be seen on. */
            w->reflex[i] = ns_ip4(45, 20, 113, id,
                                  kinds[i] == NS_NAT_SYMMETRIC
                                      ? NS_FIRST_EXT_PORT + 500
                                      : NS_FIRST_EXT_PORT);
            w->tap[i].end.node =
                ns_add_natted(&w->net, w->host[i], 20, kinds[i], ext, 30000);
        }
        w->tap[i].end.net = &w->net;
    }
    w->tap[0].third = w->tap[1].third =
        ns_add_public(&w->net, ns_ip4(45, 66, 6, 6, 5000), 20);
}

static struct directlink_channel_config make_cfg(struct world *w, int who,
                                                 enum directlink_scope scope,
                                                 uint8_t psk_fill)
{
    struct directlink_channel_config cfg;
    memset(&cfg, 0, sizeof cfg);
    fill_secrets(&cfg.secrets, scope, psk_fill, w->hs[who]);
    cfg.initiator = who == 0;
    cfg.remote[0] = w->reflex[1 - who];
    cfg.remote_count = 1;
    cfg.net = (struct gamelink_ops){tap_send, tap_recv, &w->tap[who]};
    cfg.clock = &w->clock;
    cfg.keepalive_ms = w->keepalive_ms;
    return cfg;
}

static void step(struct world *w)
{
    for (int i = 0; i < 2; i++)
        (void)directlink_channel_poll(&w->ch[i], sink_collect, &w->sink[i]);
    ns_advance(&w->net, w->net.now_ms + STEP_MS);
}

static bool settled(const struct world *w)
{
    for (int i = 0; i < 2; i++) {
        enum directlink_channel_state s = directlink_channel_state(&w->ch[i]);
        if (s == DIRECTLINK_CHANNEL_PUNCHING || s == DIRECTLINK_CHANNEL_CONFIRMING)
            return false;
    }
    return true;
}

static void run_until_settled(struct world *w)
{
    int64_t end = w->net.now_ms + RUN_LIMIT_MS;
    while (!settled(w) && w->net.now_ms < end)
        step(w);
    for (int i = 0; i < 8; i++)
        step(w); /* let the last confirmation land */
}

static void run_for(struct world *w, int64_t ms)
{
    int64_t end = w->net.now_ms + ms;
    while (w->net.now_ms < end)
        step(w);
}

static bool both_open(const struct world *w)
{
    return directlink_channel_state(&w->ch[0]) == DIRECTLINK_CHANNEL_OPEN &&
           directlink_channel_state(&w->ch[1]) == DIRECTLINK_CHANNEL_OPEN;
}

static enum directlink_channel_status open_both(struct world *w,
                                                enum directlink_scope scope,
                                                uint8_t psk_a, uint8_t psk_b,
                                                bool punch)
{
    enum directlink_channel_status st = DIRECTLINK_CHANNEL_OK;
    uint8_t psk[2] = {psk_a, psk_b};
    for (int i = 0; i < 2 && st == DIRECTLINK_CHANNEL_OK; i++) {
        struct directlink_channel_config cfg = make_cfg(w, i, scope, psk[i]);
        st = punch ? directlink_channel_open(&w->ch[i], &cfg)
                   : directlink_channel_open_at(&w->ch[i], &cfg, &w->host[1 - i]);
    }
    return st;
}

/* ── derivation ──────────────────────────────────────────────────────── */

static bool hex_eq(const uint8_t *bytes, const char *hex)
{
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < 32; i++)
        if (hex[2 * i] != digits[bytes[i] >> 4] ||
            hex[2 * i + 1] != digits[bytes[i] & 15u])
            return false;
    return true;
}

static int dlc_case_derive(void)
{
    int failures = 0;
    TEST_CASE("channel: key derivation known answers and pairing secret rules") {
        struct directlink_channel_secrets s;
        struct directlink_channel_keys k, k2;
        uint8_t hs[32];
        fill_secrets(&s, DIRECTLINK_SCOPE_INTRA_FLEET, 0x22, hs);
        ASSERT_EQ(directlink_channel_derive(&s, &k), DIRECTLINK_CHANNEL_OK);
        ASSERT(hex_eq(k.material, "323b18a50003517640b0d0f3dcc35983a5679cb51ef41abae1516dfc7b958fc5"));
        ASSERT(hex_eq(k.probe_key, "a0667592c01ebc4283e0822667386b952f4562509b926db4518aaea9a2483333"));
        /* (a) a different pairing secret gives different keys. */
        fill_secrets(&s, DIRECTLINK_SCOPE_INTRA_FLEET, 0x23, hs);
        ASSERT_EQ(directlink_channel_derive(&s, &k2), DIRECTLINK_CHANNEL_OK);
        ASSERT(hex_eq(k2.material, "deeb3a15ee47e275fb458ed96e6c96032e49d5525b2c6867a54e63053cff4ae0"));
        ASSERT(memcmp(k.probe_key, k2.probe_key, 32) != 0);
        /* Every bound input changes the keys. */
        fill_secrets(&s, DIRECTLINK_SCOPE_INTRA_FLEET, 0x22, hs);
        s.attempt[0] ^= 1;
        ASSERT_EQ(directlink_channel_derive(&s, &k2), DIRECTLINK_CHANNEL_OK);
        ASSERT(memcmp(k.material, k2.material, 32) != 0);
        ASSERT(memcmp(k.probe_key, k2.probe_key, 32) != 0);
        fill_secrets(&s, DIRECTLINK_SCOPE_INTRA_FLEET, 0x22, hs);
        s.initiator_id[0] ^= 1;
        ASSERT_EQ(directlink_channel_derive(&s, &k2), DIRECTLINK_CHANNEL_OK);
        ASSERT(memcmp(k.material, k2.material, 32) != 0);
        fill_secrets(&s, DIRECTLINK_SCOPE_INTRA_FLEET, 0x22, hs);
        uint8_t other[32];
        memcpy(other, k_hs, 32);
        other[31] ^= 1;
        s.handshake = other;
        ASSERT_EQ(directlink_channel_derive(&s, &k2), DIRECTLINK_CHANNEL_OK);
        ASSERT(memcmp(k.material, k2.material, 32) != 0);
        /* (c) intra_fleet without a pairing secret is refused by name. */
        fill_secrets(&s, DIRECTLINK_SCOPE_INTRA_FLEET, 0, hs);
        ASSERT_EQ(directlink_channel_derive(&s, &k2), DIRECTLINK_CHANNEL_NO_PSK);
        ASSERT_STR_EQ(directlink_channel_status_label(DIRECTLINK_CHANNEL_NO_PSK),
                      "pairing_secret_required");
        /* inter_fleet may run without one, and gets different keys. */
        fill_secrets(&s, DIRECTLINK_SCOPE_INTER_FLEET, 0, hs);
        ASSERT_EQ(directlink_channel_derive(&s, &k2), DIRECTLINK_CHANNEL_OK);
        ASSERT(memcmp(k.material, k2.material, 32) != 0);
        /* The scope is part of the key context. */
        fill_secrets(&s, DIRECTLINK_SCOPE_INTER_FLEET, 0x22, hs);
        ASSERT_EQ(directlink_channel_derive(&s, &k2), DIRECTLINK_CHANNEL_OK);
        ASSERT(hex_eq(k2.material, "31184690a66eaa8c2a51696e777f35fcbdc23d7043ad5dd213dcd0729b922abf"));
        /* An all-zero handshake secret is a consumed one. */
        fill_secrets(&s, DIRECTLINK_SCOPE_INTER_FLEET, 0x22, hs);
        memset(hs, 0, sizeof hs);
        ASSERT_EQ(directlink_channel_derive(&s, &k2), DIRECTLINK_CHANNEL_SECRET_USED);
        /* Handshake secret bounds. */
        fill_secrets(&s, DIRECTLINK_SCOPE_INTER_FLEET, 0, hs);
        s.handshake_len = 31;
        ASSERT_EQ(directlink_channel_derive(&s, &k2), DIRECTLINK_CHANNEL_ARGUMENT);
        s.handshake_len = DIRECTLINK_CHANNEL_HANDSHAKE_MAX + 1u;
        ASSERT_EQ(directlink_channel_derive(&s, &k2), DIRECTLINK_CHANNEL_ARGUMENT);
        ASSERT_EQ(directlink_channel_derive(NULL, &k2), DIRECTLINK_CHANNEL_ARGUMENT);
    } TEST_END;
    return failures;
}

/* ── opening across NAT models ───────────────────────────────────────── */

static void exchange_hello(struct world *w, bool *ok)
{
    *ok = directlink_channel_send(&w->ch[0], (const uint8_t *)"hello", 5) ==
              DIRECTLINK_CHANNEL_OK &&
          directlink_channel_send(&w->ch[1], (const uint8_t *)"world", 5) ==
              DIRECTLINK_CHANNEL_OK;
    run_for(w, 200);
}

static bool open_and_hello(uint64_t seed, enum ns_nat_kind ka,
                           enum ns_nat_kind kb, enum directlink_scope scope)
{
    static struct world w;
    world_init(&w, seed, ka, kb);
    if (open_both(&w, scope, 0x22, 0x22, true) != DIRECTLINK_CHANNEL_OK)
        return false;
    run_until_settled(&w);
    bool sent = false;
    if (!both_open(&w))
        return false;
    uint64_t before = w.ch[0].link.stats.sent_bytes;
    exchange_hello(&w, &sent);
    return sent && w.sink[1].count == 1 && w.sink[0].count == 1 &&
           memcmp(w.sink[1].last, "hello", 5) == 0 &&
           memcmp(w.sink[0].last, "world", 5) == 0 &&
           w.ch[0].link.stats.sent_bytes - before ==
               5u + DIRECTLINK_CHANNEL_OVERHEAD;
}

static int dlc_case_nat_models(void)
{
    int failures = 0;
    TEST_CASE("channel: hello crosses every connectable NAT pairing sealed") {
        ASSERT(open_and_hello(1, NS_NAT_FULL_CONE, NS_NAT_FULL_CONE,
                              DIRECTLINK_SCOPE_INTRA_FLEET));
        ASSERT(open_and_hello(2, NS_NAT_PORT_RESTRICTED, NS_NAT_PORT_RESTRICTED,
                              DIRECTLINK_SCOPE_INTRA_FLEET));
        ASSERT(open_and_hello(3, NS_NAT_NONE, NS_NAT_PORT_RESTRICTED,
                              DIRECTLINK_SCOPE_INTER_FLEET));
        ASSERT(open_and_hello(4, NS_NAT_SYMMETRIC, NS_NAT_FULL_CONE,
                              DIRECTLINK_SCOPE_INTRA_FLEET));
    } TEST_END;
    return failures;
}

static int dlc_case_nat_models_2(void)
{
    int failures = 0;
    TEST_CASE("channel: 20% loss still opens and carries data") {
        for (uint64_t seed = 1; seed <= 6; seed++) {
            static struct world w;
            world_init(&w, seed, NS_NAT_PORT_RESTRICTED, NS_NAT_FULL_CONE);
            w.net.loss_ppm = 200000;
            ASSERT_EQ(open_both(&w, DIRECTLINK_SCOPE_INTRA_FLEET, 0x22, 0x22, true),
                      DIRECTLINK_CHANNEL_OK);
            run_until_settled(&w);
            ASSERT(both_open(&w));
        }
    } TEST_END;
    return failures;
}

static int dlc_case_nat_models_3(void)
{
    int failures = 0;
    TEST_CASE("channel: two symmetric NATs fall back and refuse data") {
        static struct world w;
        world_init(&w, 5, NS_NAT_SYMMETRIC, NS_NAT_SYMMETRIC);
        ASSERT_EQ(open_both(&w, DIRECTLINK_SCOPE_INTRA_FLEET, 0x22, 0x22, true),
                  DIRECTLINK_CHANNEL_OK);
        run_until_settled(&w);
        ASSERT_EQ(directlink_channel_state(&w.ch[0]), DIRECTLINK_CHANNEL_FALLBACK);
        ASSERT_EQ(directlink_channel_state(&w.ch[1]), DIRECTLINK_CHANNEL_FALLBACK);
        ASSERT_EQ(directlink_channel_send(&w.ch[0], (const uint8_t *)"x", 1),
                  DIRECTLINK_CHANNEL_NOT_OPEN);
    } TEST_END;
    return failures;
}

/* ── pairing secret on the wire ──────────────────────────────────────── */

static int dlc_case_psk(void)
{
    int failures = 0;
    TEST_CASE("channel: a wrong pairing secret never opens a path") {
        static struct world w;
        world_init(&w, 8, NS_NAT_FULL_CONE, NS_NAT_FULL_CONE);
        ASSERT_EQ(open_both(&w, DIRECTLINK_SCOPE_INTRA_FLEET, 0x22, 0x23, true),
                  DIRECTLINK_CHANNEL_OK);
        run_until_settled(&w);
        ASSERT_EQ(directlink_channel_state(&w.ch[0]), DIRECTLINK_CHANNEL_FALLBACK);
        ASSERT_EQ(directlink_channel_state(&w.ch[1]), DIRECTLINK_CHANNEL_FALLBACK);
        ASSERT(w.ch[0].punch.stats.dropped_mac > 0);
    } TEST_END;
    return failures;
}

static int dlc_case_psk_2(void)
{
    int failures = 0;
    TEST_CASE("channel: a wrong pairing secret fails the address confirmation") {
        static struct world w;
        world_init(&w, 9, NS_NAT_NONE, NS_NAT_NONE);
        ASSERT_EQ(open_both(&w, DIRECTLINK_SCOPE_INTRA_FLEET, 0x22, 0x23, false),
                  DIRECTLINK_CHANNEL_OK);
        run_until_settled(&w);
        ASSERT_EQ(directlink_channel_state(&w.ch[0]), DIRECTLINK_CHANNEL_FALLBACK);
        ASSERT_EQ(directlink_channel_state(&w.ch[1]), DIRECTLINK_CHANNEL_FALLBACK);
        ASSERT_EQ(w.sink[0].count + w.sink[1].count, (uint32_t)0);
    } TEST_END;
    return failures;
}

static int dlc_case_psk_3(void)
{
    int failures = 0;
    TEST_CASE("channel: intra_fleet without a pairing secret does not open") {
        static struct world w;
        world_init(&w, 10, NS_NAT_NONE, NS_NAT_NONE);
        ASSERT_EQ(open_both(&w, DIRECTLINK_SCOPE_INTRA_FLEET, 0, 0, true),
                  DIRECTLINK_CHANNEL_NO_PSK);
        ASSERT_EQ(directlink_channel_state(&w.ch[0]), DIRECTLINK_CHANNEL_CLOSED);
        ASSERT_EQ(open_both(&w, DIRECTLINK_SCOPE_INTER_FLEET, 0, 0, true),
                  DIRECTLINK_CHANNEL_OK);
    } TEST_END;
    return failures;
}

/* ── hostile and lossy datagram paths ────────────────────────────────── */

static void open_known(struct world *w, uint64_t seed)
{
    world_init(w, seed, NS_NAT_NONE, NS_NAT_NONE);
    (void)open_both(w, DIRECTLINK_SCOPE_INTRA_FLEET, 0x22, 0x22, false);
    run_until_settled(w);
}

static int dlc_case_hostile(void)
{
    int failures = 0;
    TEST_CASE("channel: a datagram from another address is dropped") {
        static struct world w;
        open_known(&w, 11);
        ASSERT(both_open(&w));
        w.tap[0].mode = TAP_FORGE_FROM_THIRD;
        ASSERT_EQ(directlink_channel_send(&w.ch[0], (const uint8_t *)"hello", 5),
                  DIRECTLINK_CHANNEL_OK);
        run_for(&w, 100);
        ASSERT_EQ(w.sink[1].count, (uint32_t)1);
        ASSERT_EQ(w.ch[1].stats.dropped_source, (uint32_t)1);
    } TEST_END;
    return failures;
}

static int dlc_case_hostile_2(void)
{
    int failures = 0;
    TEST_CASE("channel: a replayed datagram is delivered once") {
        static struct world w;
        open_known(&w, 12);
        w.tap[0].mode = TAP_REPLAY;
        ASSERT_EQ(directlink_channel_send(&w.ch[0], (const uint8_t *)"hello", 5),
                  DIRECTLINK_CHANNEL_OK);
        run_for(&w, 100);
        ASSERT_EQ(w.sink[1].count, (uint32_t)1);
        ASSERT_EQ(w.ch[1].link.stats.dropped_old, (uint64_t)1);
    } TEST_END;
    return failures;
}

static int dlc_case_hostile_3(void)
{
    int failures = 0;
    TEST_CASE("channel: reordered datagrams are all delivered") {
        static struct world w;
        open_known(&w, 13);
        w.tap[0].mode = TAP_HOLD;
        for (uint8_t i = 0; i < 4; i++)
            ASSERT_EQ(directlink_channel_send(&w.ch[0], &i, 1), DIRECTLINK_CHANNEL_OK);
        tap_flush_reversed(&w.tap[0]);
        run_for(&w, 100);
        ASSERT_EQ(w.sink[1].count, (uint32_t)4);
        ASSERT_EQ((int)w.sink[1].order[0], 3);
        ASSERT_EQ((int)w.sink[1].order[3], 0);
    } TEST_END;
    return failures;
}

static int dlc_case_hostile_4(void)
{
    int failures = 0;
    TEST_CASE("channel: after close nothing is sent or delivered") {
        static struct world w;
        open_known(&w, 14);
        directlink_channel_close(&w.ch[1]);
        ASSERT_EQ(directlink_channel_send(&w.ch[0], (const uint8_t *)"hello", 5),
                  DIRECTLINK_CHANNEL_OK);
        run_for(&w, 100);
        ASSERT_EQ(w.sink[1].count, (uint32_t)0);
        ASSERT_EQ(directlink_channel_send(&w.ch[1], (const uint8_t *)"x", 1),
                  DIRECTLINK_CHANNEL_NOT_OPEN);
        directlink_channel_close(&w.ch[1]);
    } TEST_END;
    return failures;
}

static int dlc_case_limits(void)
{
    int failures = 0;
    TEST_CASE("channel: payload cap, rekey limit and no data before confirmation") {
        static struct world w;
        open_known(&w, 15);
        uint8_t big[DIRECTLINK_CHANNEL_MAX_PAYLOAD + 1] = {0};
        ASSERT_EQ(directlink_channel_send(&w.ch[0], big, sizeof big),
                  DIRECTLINK_CHANNEL_TOO_LARGE);
        w.ch[0].link.send_seq = DIRECTLINK_CHANNEL_REKEY_DATAGRAMS - 1u;
        ASSERT_EQ(directlink_channel_send(&w.ch[0], big, 1), DIRECTLINK_CHANNEL_OK);
        ASSERT_EQ(directlink_channel_send(&w.ch[0], big, 1), DIRECTLINK_CHANNEL_REKEY);
        static struct world v;
        world_init(&v, 16, NS_NAT_NONE, NS_NAT_NONE);
        (void)open_both(&v, DIRECTLINK_SCOPE_INTRA_FLEET, 0x22, 0x22, false);
        ASSERT_EQ(directlink_channel_state(&v.ch[0]), DIRECTLINK_CHANNEL_CONFIRMING);
        ASSERT_EQ(directlink_channel_send(&v.ch[0], big, 1), DIRECTLINK_CHANNEL_NOT_OPEN);
    } TEST_END;
    return failures;
}

/* ── single use, address policy, liveness ────────────────────────────── */

static bool all_zero_bytes(const uint8_t *p, size_t n)
{
    uint8_t acc = 0;
    for (size_t i = 0; i < n; i++)
        acc |= p[i];
    return acc == 0;
}

static int dlc_case_single_use(void)
{
    int failures = 0;
    TEST_CASE("channel: open consumes the secrets; reopening with them is refused") {
        static struct world w;
        world_init(&w, 20, NS_NAT_NONE, NS_NAT_NONE);
        struct directlink_channel_config cfg =
            make_cfg(&w, 0, DIRECTLINK_SCOPE_INTRA_FLEET, 0x22);
        ASSERT_EQ(directlink_channel_open_at(&w.ch[0], &cfg, &w.host[1]),
                  DIRECTLINK_CHANNEL_OK);
        ASSERT(all_zero_bytes(w.hs[0], 32));
        ASSERT(all_zero_bytes(cfg.secrets.psk, 32));
        ASSERT(all_zero_bytes(w.ch[0].material, 32)); /* destroyed once the session has its keys */
        directlink_channel_close(&w.ch[0]);
        ASSERT_EQ(directlink_channel_open_at(&w.ch[0], &cfg, &w.host[1]),
                  DIRECTLINK_CHANNEL_SECRET_USED);
        ASSERT_EQ(directlink_channel_state(&w.ch[0]), DIRECTLINK_CHANNEL_CLOSED);
        ASSERT_STR_EQ(directlink_channel_status_label(DIRECTLINK_CHANNEL_SECRET_USED),
                      "secret_consumed");
        ASSERT_EQ(directlink_channel_open(&w.ch[0], &cfg), DIRECTLINK_CHANNEL_SECRET_USED);
    } TEST_END;
    return failures;
}

static int dlc_case_wipe_on_failure(void)
{
    int failures = 0;
    TEST_CASE("channel: secrets are wiped on a failed open too") {
        static struct world w;
        world_init(&w, 21, NS_NAT_NONE, NS_NAT_NONE);
        struct directlink_channel_config cfg =
            make_cfg(&w, 0, DIRECTLINK_SCOPE_INTER_FLEET, 0x22);
        struct directlink_addr loop = ns_ip4(127, 0, 0, 1, 5000);
        ASSERT_EQ(directlink_channel_open_at(&w.ch[0], &cfg, &loop),
                  DIRECTLINK_CHANNEL_ADDRESS);
        ASSERT(all_zero_bytes(w.hs[0], 32));
        ASSERT(all_zero_bytes(cfg.secrets.psk, 32));
        ASSERT_EQ(directlink_channel_state(&w.ch[0]), DIRECTLINK_CHANNEL_CLOSED);
        struct directlink_channel_config bad =
            make_cfg(&w, 0, DIRECTLINK_SCOPE_INTRA_FLEET, 0);
        ASSERT_EQ(directlink_channel_open(&w.ch[0], &bad), DIRECTLINK_CHANNEL_NO_PSK);
        ASSERT(all_zero_bytes(w.hs[0], 32));
        struct directlink_channel zeroed;
        memset(&zeroed, 0, sizeof zeroed);
        directlink_channel_close(&zeroed);
        ASSERT_EQ(directlink_channel_state(&zeroed), DIRECTLINK_CHANNEL_CLOSED);
    } TEST_END;
    return failures;
}

static enum directlink_channel_status try_at(struct world *w,
                                             enum directlink_scope scope,
                                             bool loopback,
                                             struct directlink_addr at)
{
    struct directlink_channel_config cfg = make_cfg(w, 0, scope, 0x22);
    cfg.allow_loopback = loopback;
    enum directlink_channel_status st = directlink_channel_open_at(&w->ch[0], &cfg, &at);
    directlink_channel_close(&w->ch[0]);
    return st;
}

static int dlc_case_address_policy(void)
{
    int failures = 0;
    TEST_CASE("channel: open_at applies the punch layer's address classes") {
        static struct world w;
        world_init(&w, 22, NS_NAT_NONE, NS_NAT_NONE);
        const enum directlink_scope intra = DIRECTLINK_SCOPE_INTRA_FLEET;
        const enum directlink_scope inter = DIRECTLINK_SCOPE_INTER_FLEET;
        ASSERT_EQ(try_at(&w, inter, false, ns_ip4(45, 10, 100, 9, 5000)), DIRECTLINK_CHANNEL_OK);
        ASSERT_EQ(try_at(&w, inter, false, ns_ip4(127, 0, 0, 1, 5000)), DIRECTLINK_CHANNEL_ADDRESS);
        ASSERT_EQ(try_at(&w, intra, false, ns_ip4(127, 0, 0, 1, 5000)), DIRECTLINK_CHANNEL_ADDRESS);
        ASSERT_EQ(try_at(&w, intra, true, ns_ip4(127, 0, 0, 1, 5000)), DIRECTLINK_CHANNEL_OK);
        ASSERT_EQ(try_at(&w, intra, false, ns_ip4(10, 0, 0, 5, 5000)), DIRECTLINK_CHANNEL_OK);
        ASSERT_EQ(try_at(&w, inter, false, ns_ip4(10, 0, 0, 5, 5000)), DIRECTLINK_CHANNEL_ADDRESS);
        ASSERT_EQ(try_at(&w, intra, true, ns_ip4(0, 0, 0, 0, 5000)), DIRECTLINK_CHANNEL_ADDRESS);
        ASSERT_EQ(try_at(&w, intra, true, ns_ip4(224, 0, 0, 1, 5000)), DIRECTLINK_CHANNEL_ADDRESS);
        ASSERT(try_at(&w, intra, true, ns_ip4(45, 10, 100, 9, 0)) != DIRECTLINK_CHANNEL_OK);
    } TEST_END;
    return failures;
}

static int dlc_case_liveness(void)
{
    int failures = 0;
    TEST_CASE("channel: an idle OPEN channel stays up on keepalives") {
        static struct world w;
        world_init(&w, 23, NS_NAT_NONE, NS_NAT_NONE);
        w.keepalive_ms = 200;
        (void)open_both(&w, DIRECTLINK_SCOPE_INTRA_FLEET, 0x22, 0x22, false);
        run_until_settled(&w);
        ASSERT(both_open(&w));
        run_for(&w, 3000);
        ASSERT(both_open(&w));
        ASSERT(w.ch[0].link.stats.pings_sent >= 10);
    } TEST_END;
    return failures;
}

static int dlc_case_rebinding(void)
{
    int failures = 0;
    TEST_CASE("channel: a NAT rebinding mid-session ends in fallback") {
        static struct world w;
        world_init(&w, 24, NS_NAT_FULL_CONE, NS_NAT_FULL_CONE);
        w.keepalive_ms = 200;
        ASSERT_EQ(open_both(&w, DIRECTLINK_SCOPE_INTRA_FLEET, 0x22, 0x22, true),
                  DIRECTLINK_CHANNEL_OK);
        run_until_settled(&w);
        ASSERT(both_open(&w));
        /* The NAT forgets B's mapping: B is next seen on a fresh port. */
        struct ns_node *b = &w.net.node[w.tap[1].end.node];
        for (int i = 0; i < NS_MAPS; i++)
            b->map[i].used = false;
        ASSERT_EQ(directlink_channel_send(&w.ch[1], (const uint8_t *)"x", 1), DIRECTLINK_CHANNEL_OK);
        run_for(&w, 1500);
        ASSERT_EQ(directlink_channel_state(&w.ch[0]), DIRECTLINK_CHANNEL_FALLBACK);
        ASSERT_EQ(directlink_channel_state(&w.ch[1]), DIRECTLINK_CHANNEL_FALLBACK);
        ASSERT(w.ch[0].stats.dropped_source > 0); /* the new source is not accepted */
        ASSERT_EQ(w.ch[0].stats.path_lost, (uint32_t)1);
        ASSERT_EQ(directlink_channel_send(&w.ch[0], (const uint8_t *)"x", 1), DIRECTLINK_CHANNEL_NOT_OPEN);
        ASSERT(all_zero_bytes(w.ch[0].material, 32));
        ASSERT(all_zero_bytes(w.ch[0].punch.cfg.key, 32));
    } TEST_END;
    return failures;
}

static int dlc_case_same_role(void)
{
    int failures = 0;
    TEST_CASE("channel: two ends claiming the same role never open") {
        static struct world w;
        world_init(&w, 25, NS_NAT_NONE, NS_NAT_NONE);
        for (int i = 0; i < 2; i++) {
            struct directlink_channel_config cfg =
                make_cfg(&w, i, DIRECTLINK_SCOPE_INTRA_FLEET, 0x22);
            cfg.initiator = true;
            ASSERT_EQ(directlink_channel_open_at(&w.ch[i], &cfg, &w.host[1 - i]),
                      DIRECTLINK_CHANNEL_OK);
        }
        run_until_settled(&w);
        ASSERT_EQ(directlink_channel_state(&w.ch[0]), DIRECTLINK_CHANNEL_FALLBACK);
        ASSERT_EQ(directlink_channel_state(&w.ch[1]), DIRECTLINK_CHANNEL_FALLBACK);
        ASSERT(w.ch[0].link.stats.dropped_auth + w.ch[0].link.stats.dropped_malformed > 0);
    } TEST_END;
    return failures;
}

static int over_recv(void *ctx, void *data, size_t cap, uint8_t addr[4],
                     uint16_t *port)
{
    int *calls = ctx;
    (void)data;
    memset(addr, 0, 4);
    *port = 1;
    return (*calls)++ == 0 ? (int)cap + 500 : 0;
}

static int over_send(void *ctx, const uint8_t addr[4], uint16_t port,
                     const void *data, size_t len)
{
    (void)ctx; (void)addr; (void)port; (void)data;
    return (int)len;
}

static int dlc_case_overreporting_seam(void)
{
    int failures = 0;
    TEST_CASE("channel: a seam reporting more than the buffer is ignored") {
        static struct world w;
        world_init(&w, 26, NS_NAT_NONE, NS_NAT_NONE);
        int calls = 0;
        struct directlink_channel_config cfg =
            make_cfg(&w, 0, DIRECTLINK_SCOPE_INTRA_FLEET, 0x22);
        cfg.net = (struct gamelink_ops){over_send, over_recv, &calls};
        ASSERT_EQ(directlink_channel_open_at(&w.ch[0], &cfg, &w.host[1]), DIRECTLINK_CHANNEL_OK);
        ASSERT_EQ((int)directlink_channel_poll(&w.ch[0], sink_collect, &w.sink[0]), 0);
        ASSERT_EQ(w.ch[0].stats.dropped_early, (uint32_t)1);
    } TEST_END;
    return failures;
}

int test_directlink_channel(void)
{
    int failures = 0;
    failures += dlc_case_derive();
    failures += dlc_case_nat_models();
    failures += dlc_case_nat_models_2();
    failures += dlc_case_nat_models_3();
    failures += dlc_case_psk();
    failures += dlc_case_psk_2();
    failures += dlc_case_psk_3();
    failures += dlc_case_hostile();
    failures += dlc_case_hostile_2();
    failures += dlc_case_hostile_3();
    failures += dlc_case_hostile_4();
    failures += dlc_case_limits();
    failures += dlc_case_single_use();
    failures += dlc_case_wipe_on_failure();
    failures += dlc_case_address_policy();
    failures += dlc_case_liveness();
    failures += dlc_case_rebinding();
    failures += dlc_case_same_role();
    failures += dlc_case_overreporting_seam();
    return failures;
}
