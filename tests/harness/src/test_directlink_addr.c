/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * directlink observed-address codec (known answers, strict decode) and the
 * reflexive-address aggregator (agreement of two distinct peers, NAT
 * behaviour classes, a lying peer). */

#include "test/test_core.h"

#include "gamelink/directlink_offer.h"
#include "gamelink/directlink_reflexive.h"

#include <stdlib.h>
#include <string.h>

static struct directlink_addr v4(uint8_t a, uint8_t b, uint8_t c, uint8_t d,
                                 uint16_t port)
{
    struct directlink_addr addr;
    memset(&addr, 0, sizeof addr);
    addr.family = DIRECTLINK_V4;
    addr.ip[0] = a;
    addr.ip[1] = b;
    addr.ip[2] = c;
    addr.ip[3] = d;
    addr.port = port;
    return addr;
}

static struct directlink_observed obs(struct directlink_addr addr)
{
    return (struct directlink_observed){.proto = DIRECTLINK_PROTO_UDP,
                                        .addr = addr};
}

static int dla_case_known_answer(void)
{
    int failures = 0;
    TEST_CASE("directlink observed: known-answer encodings round-trip") {
        static const uint8_t kat4[] = {0x01, 0x01, 0x04, 0x92, 0x10,
                                       0x2D, 0x14, 0x71, 0x07};
        struct directlink_observed o = obs(v4(45, 20, 113, 7, 4242));
        uint8_t out[DIRECTLINK_OBSERVED_MAX_BYTES];
        size_t len = 99;
        ASSERT_EQ((int)directlink_observed_encode(&o, out, sizeof out, &len),
                  (int)DIRECTLINK_OK);
        ASSERT_EQ(len, sizeof kat4);
        ASSERT(memcmp(out, kat4, sizeof kat4) == 0);
        struct directlink_observed back;
        ASSERT_EQ((int)directlink_observed_decode(kat4, sizeof kat4, &back),
                  (int)DIRECTLINK_OK);
        ASSERT_EQ((int)back.proto, (int)DIRECTLINK_PROTO_UDP);
        ASSERT(directlink_addr_equal(&back.addr, &o.addr));

        static const uint8_t kat6[] = {0x01, 0x02, 0x06, 0xBB, 0x01, 0x26, 0x06,
                                       0x47, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                       0, 0x01};
        struct directlink_observed six;
        memset(&six, 0, sizeof six);
        six.proto = DIRECTLINK_PROTO_TCP;
        six.addr.family = DIRECTLINK_V6;
        six.addr.port = 443;
        six.addr.ip[0] = 0x26;
        six.addr.ip[1] = 0x06;
        six.addr.ip[2] = 0x47;
        six.addr.ip[3] = 0x00;
        six.addr.ip[15] = 0x01;
        ASSERT_EQ((int)directlink_observed_encode(&six, out, sizeof out, &len),
                  (int)DIRECTLINK_OK);
        ASSERT_EQ(len, sizeof kat6);
        ASSERT(memcmp(out, kat6, sizeof kat6) == 0);
        ASSERT_EQ((int)directlink_observed_decode(kat6, sizeof kat6, &back),
                  (int)DIRECTLINK_OK);
        ASSERT_EQ((int)back.proto, (int)DIRECTLINK_PROTO_TCP);
        ASSERT(directlink_addr_equal(&back.addr, &six.addr));
        /* A private address is a valid observation (a LAN peer's view). */
        struct directlink_observed lan = obs(v4(192, 168, 1, 5, 7000));
        ASSERT_EQ((int)directlink_observed_encode(&lan, out, sizeof out, &len),
                  (int)DIRECTLINK_OK);
    } TEST_END;
    return failures;
}

static enum directlink_status decode_bytes(const uint8_t *b, size_t n)
{
    struct directlink_observed sink;
    return directlink_observed_decode(b, n, &sink);
}

/* Decode the first `n` bytes held in an exact-size heap buffer, so a read past
 * the end is visible to the sanitizers. */
static enum directlink_status decode_prefix(const uint8_t *b, size_t n)
{
    uint8_t *copy = malloc(n ? n : 1u);
    if (!copy)
        return DIRECTLINK_ERR_ARGUMENT;
    if (n)
        memcpy(copy, b, n);
    enum directlink_status st = decode_bytes(copy, n);
    free(copy);
    return st;
}

static int dla_case_malformed(void)
{
    int failures = 0;
    TEST_CASE("directlink observed: malformed input is rejected") {
        static const uint8_t good[] = {0x01, 0x01, 0x04, 0x92, 0x10,
                                       0x2D, 0x14, 0x71, 0x07};
        /* Every proper prefix is truncated. */
        for (size_t n = 0; n < sizeof good; n++)
            ASSERT(decode_prefix(good, n) != DIRECTLINK_OK);
        ASSERT_EQ((int)decode_bytes(good, sizeof good), (int)DIRECTLINK_OK);
        /* Trailing byte. */
        uint8_t longer[sizeof good + 1];
        memcpy(longer, good, sizeof good);
        longer[sizeof good] = 0;
        ASSERT_EQ((int)decode_bytes(longer, sizeof longer),
                  (int)DIRECTLINK_ERR_TRAILING);
        uint8_t m[sizeof good];
        memcpy(m, good, sizeof good);
        m[0] = 0;
        ASSERT_EQ((int)decode_bytes(m, sizeof m), (int)DIRECTLINK_ERR_VERSION);
        m[0] = 2;
        ASSERT_EQ((int)decode_bytes(m, sizeof m), (int)DIRECTLINK_ERR_VERSION);
        memcpy(m, good, sizeof good);
        m[1] = 0;
        ASSERT_EQ((int)decode_bytes(m, sizeof m), (int)DIRECTLINK_ERR_FIELD);
        m[1] = 3;
        ASSERT_EQ((int)decode_bytes(m, sizeof m), (int)DIRECTLINK_ERR_FIELD);
        memcpy(m, good, sizeof good);
        m[2] = 5;
        ASSERT_EQ((int)decode_bytes(m, sizeof m), (int)DIRECTLINK_ERR_FIELD);
        memcpy(m, good, sizeof good);
        m[3] = 0;
        m[4] = 0;
        ASSERT_EQ((int)decode_bytes(m, sizeof m), (int)DIRECTLINK_ERR_PORT);
    } TEST_END;
    return failures;
}

static enum directlink_status decode_v4(uint8_t a, uint8_t b, uint8_t c,
                                        uint8_t d)
{
    uint8_t wire[] = {0x01, 0x01, 0x04, 0x92, 0x10, a, b, c, d};
    return decode_bytes(wire, sizeof wire);
}

static int dla_case_forbidden_addresses(void)
{
    int failures = 0;
    TEST_CASE("directlink observed: unspecified, loopback, multicast refused") {
        ASSERT_EQ((int)decode_v4(0, 0, 0, 0), (int)DIRECTLINK_ERR_ADDRESS);
        ASSERT_EQ((int)decode_v4(127, 0, 0, 1), (int)DIRECTLINK_ERR_ADDRESS);
        ASSERT_EQ((int)decode_v4(224, 0, 0, 1), (int)DIRECTLINK_ERR_ADDRESS);
        ASSERT_EQ((int)decode_v4(239, 255, 255, 250),
                  (int)DIRECTLINK_ERR_ADDRESS);
        ASSERT_EQ((int)decode_v4(255, 255, 255, 255),
                  (int)DIRECTLINK_ERR_ADDRESS);
        ASSERT_EQ((int)decode_v4(45, 20, 113, 7), (int)DIRECTLINK_OK);
        /* IPv6: ::, ::1, ff02::1 and ::ffff:1.2.3.4. */
        uint8_t w6[3 + 2 + 16] = {0x01, 0x01, 0x06, 0x92, 0x10};
        ASSERT_EQ((int)decode_bytes(w6, sizeof w6), (int)DIRECTLINK_ERR_ADDRESS);
        w6[sizeof w6 - 1] = 1;
        ASSERT_EQ((int)decode_bytes(w6, sizeof w6), (int)DIRECTLINK_ERR_ADDRESS);
        w6[sizeof w6 - 1] = 0;
        w6[5] = 0xFF;
        w6[6] = 0x02;
        w6[sizeof w6 - 1] = 1;
        ASSERT_EQ((int)decode_bytes(w6, sizeof w6), (int)DIRECTLINK_ERR_ADDRESS);
        memset(w6 + 5, 0, 16);
        w6[15] = 0xFF;
        w6[16] = 0xFF;
        w6[17] = 1;
        w6[18] = 2;
        w6[19] = 3;
        w6[20] = 4;
        ASSERT_EQ((int)decode_bytes(w6, sizeof w6), (int)DIRECTLINK_ERR_ADDRESS);
        /* The encoder refuses the same inputs and emits nothing. */
        struct directlink_observed bad = obs(v4(127, 0, 0, 1, 80));
        uint8_t out[DIRECTLINK_OBSERVED_MAX_BYTES];
        memset(out, 0x5A, sizeof out);
        size_t len = 7;
        ASSERT_EQ((int)directlink_observed_encode(&bad, out, sizeof out, &len),
                  (int)DIRECTLINK_ERR_ADDRESS);
        ASSERT_EQ(len, (size_t)0);
        ASSERT_EQ((int)out[0], 0x5A);
        bad = obs(v4(45, 20, 113, 7, 0));
        ASSERT_EQ((int)directlink_observed_encode(&bad, out, sizeof out, &len),
                  (int)DIRECTLINK_ERR_PORT);
        bad = obs(v4(45, 20, 113, 7, 80));
        ASSERT_EQ((int)directlink_observed_encode(&bad, out, 4, &len),
                  (int)DIRECTLINK_ERR_CAPACITY);
        ASSERT_EQ(len, (size_t)0);
    } TEST_END;
    return failures;
}

static const uint8_t *peer_id(uint8_t n)
{
    static uint8_t id[32];
    memset(id, n, sizeof id);
    return id;
}

static void report_as(struct directlink_reflexive *r, uint8_t peer,
                      enum directlink_scope scope, struct directlink_addr addr,
                      int64_t at)
{
    struct directlink_observed o = obs(addr);
    (void)directlink_reflexive_observe(r, peer_id(peer), scope, &o, at);
}

static void report(struct directlink_reflexive *r, uint8_t peer,
                   struct directlink_addr addr, int64_t at)
{
    report_as(r, peer, DIRECTLINK_SCOPE_INTRA_FLEET, addr, at);
}

static struct directlink_reflexive_report eval(
    const struct directlink_reflexive *r, int64_t at,
    const struct directlink_addr *local, size_t n)
{
    struct directlink_reflexive_report out;
    directlink_reflexive_evaluate(r, DIRECTLINK_PROTO_UDP, at, local, n, &out);
    return out;
}

static int dla_case_independent_and_dependent(void)
{
    int failures = 0;
    TEST_CASE("directlink reflexive: same port is independent, distinct dependent") {
        struct directlink_reflexive r;
        directlink_reflexive_init(&r, 0);
        struct directlink_reflexive_report rep = eval(&r, 0, NULL, 0);
        ASSERT_EQ((int)rep.nat_class, (int)DIRECTLINK_NAT_UNKNOWN);
        ASSERT(!rep.address_trusted);
        report(&r, 1, v4(45, 10, 100, 5, 40000), 0);
        rep = eval(&r, 1, NULL, 0);
        ASSERT_EQ((int)rep.nat_class, (int)DIRECTLINK_NAT_UNKNOWN);
        ASSERT(!rep.address_trusted);
        report(&r, 2, v4(45, 10, 100, 5, 40000), 1);
        rep = eval(&r, 2, NULL, 0);
        ASSERT_EQ((int)rep.nat_class, (int)DIRECTLINK_NAT_ENDPOINT_INDEPENDENT);
        ASSERT(rep.address_trusted);
        ASSERT_EQ((int)rep.address.port, 40000);
        ASSERT_EQ((int)rep.address.ip[3], 5);
        ASSERT_EQ(rep.host_peers, (uint32_t)2);

        struct directlink_reflexive s;
        directlink_reflexive_init(&s, 0);
        report(&s, 1, v4(45, 10, 100, 5, 40001), 0);
        report(&s, 2, v4(45, 10, 100, 5, 40002), 0);
        report(&s, 3, v4(45, 10, 100, 5, 40003), 0);
        rep = eval(&s, 1, NULL, 0);
        ASSERT_EQ((int)rep.nat_class, (int)DIRECTLINK_NAT_ENDPOINT_DEPENDENT);
        ASSERT(rep.address_trusted);
        ASSERT_EQ((int)rep.address.port, 0);
        ASSERT_EQ(rep.host_peers, (uint32_t)3);
    } TEST_END;
    return failures;
}

static int dla_case_open(void)
{
    int failures = 0;
    TEST_CASE("directlink reflexive: an address that is our own is open") {
        struct directlink_reflexive r;
        directlink_reflexive_init(&r, 0);
        report(&r, 1, v4(45, 10, 100, 5, 7000), 0);
        report(&r, 2, v4(45, 10, 100, 5, 7000), 0);
        struct directlink_addr local[2] = {v4(10, 0, 0, 4, 0),
                                           v4(45, 10, 100, 5, 0)};
        struct directlink_reflexive_report rep = eval(&r, 1, local, 2);
        ASSERT_EQ((int)rep.nat_class, (int)DIRECTLINK_NAT_OPEN);
        ASSERT(rep.address_trusted);
        ASSERT_EQ((int)rep.address.port, 7000);
        rep = eval(&r, 1, local, 1);
        ASSERT_EQ((int)rep.nat_class, (int)DIRECTLINK_NAT_ENDPOINT_INDEPENDENT);
    } TEST_END;
    return failures;
}

static int dla_case_liar(void)
{
    int failures = 0;
    TEST_CASE("directlink reflexive: one lying peer cannot set the address") {
        struct directlink_reflexive r;
        directlink_reflexive_init(&r, 0);
        /* A lone liar sets nothing. */
        report(&r, 9, v4(45, 20, 113, 99, 9999), 0);
        struct directlink_reflexive_report rep = eval(&r, 1, NULL, 0);
        ASSERT(!rep.address_trusted);
        ASSERT_EQ((int)rep.nat_class, (int)DIRECTLINK_NAT_UNKNOWN);
        /* One honest peer and one liar disagree on the host: nothing trusted. */
        report(&r, 1, v4(45, 10, 100, 5, 40000), 0);
        rep = eval(&r, 1, NULL, 0);
        ASSERT(!rep.address_trusted);
        /* A second honest peer outvotes the liar's host. */
        report(&r, 2, v4(45, 10, 100, 5, 40000), 0);
        rep = eval(&r, 1, NULL, 0);
        ASSERT(rep.address_trusted);
        ASSERT_EQ((int)rep.address.ip[0], 45);
        ASSERT_EQ((int)rep.address.port, 40000);
        /* A liar on the right host but the wrong port is outvoted too. */
        report(&r, 9, v4(45, 10, 100, 5, 1234), 1);
        rep = eval(&r, 2, NULL, 0);
        ASSERT_EQ((int)rep.nat_class, (int)DIRECTLINK_NAT_ENDPOINT_INDEPENDENT);
        ASSERT_EQ((int)rep.address.port, 40000);
        ASSERT_EQ(rep.port_peers, (uint32_t)2);
        /* With only two peers, a port liar cannot make the port trusted. */
        struct directlink_reflexive two;
        directlink_reflexive_init(&two, 0);
        report(&two, 1, v4(45, 10, 100, 5, 40000), 0);
        report(&two, 9, v4(45, 10, 100, 5, 1234), 0);
        rep = eval(&two, 1, NULL, 0);
        ASSERT_EQ((int)rep.nat_class, (int)DIRECTLINK_NAT_ENDPOINT_DEPENDENT);
        ASSERT_EQ((int)rep.address.port, 0);
        /* Two hosts each backed by two peers: no trust. */
        struct directlink_reflexive split;
        directlink_reflexive_init(&split, 0);
        report(&split, 1, v4(45, 10, 100, 5, 4000), 0);
        report(&split, 2, v4(45, 10, 100, 5, 4000), 0);
        report(&split, 3, v4(45, 20, 113, 8, 4000), 0);
        report(&split, 4, v4(45, 20, 113, 8, 4000), 0);
        rep = eval(&split, 1, NULL, 0);
        ASSERT(!rep.address_trusted);
        ASSERT_EQ((int)rep.nat_class, (int)DIRECTLINK_NAT_UNKNOWN);
    } TEST_END;
    return failures;
}

static int dla_case_one_peer_counts_once(void)
{
    int failures = 0;
    TEST_CASE("directlink reflexive: repeats from one peer, expiry, bounds") {
        struct directlink_reflexive r;
        directlink_reflexive_init(&r, 1000);
        for (int i = 0; i < 5; i++)
            report(&r, 1, v4(45, 10, 100, 5, 40000), i);
        ASSERT(!eval(&r, 5, NULL, 0).address_trusted);
        report(&r, 2, v4(45, 10, 100, 5, 40000), 5);
        ASSERT(eval(&r, 6, NULL, 0).address_trusted);
        /* Reports expire after the lifetime. */
        ASSERT(!eval(&r, 1005, NULL, 0).address_trusted);
        /* Invalid addresses are not recorded. */
        struct directlink_observed bad = obs(v4(127, 0, 0, 1, 80));
        ASSERT(!directlink_reflexive_observe(&r, peer_id(3), DIRECTLINK_SCOPE_INTRA_FLEET,
                                          &bad, 0));
        bad = obs(v4(45, 20, 113, 7, 0));
        ASSERT(!directlink_reflexive_observe(&r, peer_id(3), DIRECTLINK_SCOPE_INTRA_FLEET,
                                          &bad, 0));
        ASSERT(!directlink_reflexive_observe(NULL, peer_id(3), DIRECTLINK_SCOPE_INTRA_FLEET,
                                           &bad, 0));
        /* A full table replaces its oldest slot and stays bounded. */
        struct directlink_reflexive big;
        directlink_reflexive_init(&big, 0);
        for (uint8_t p = 1; p <= 40; p++)
            report(&big, p, v4(45, 10, 100, 5, (uint16_t)(2000 + p)), p);
        size_t used = 0;
        for (size_t i = 0; i < DIRECTLINK_REFLEXIVE_SLOTS; i++)
            used += big.slot[i].used ? 1u : 0u;
        ASSERT_EQ(used, (size_t)DIRECTLINK_REFLEXIVE_SLOTS);
        ASSERT_STR_EQ(directlink_nat_class_label(DIRECTLINK_NAT_OPEN), "open");
        ASSERT_STR_EQ(
            directlink_nat_class_label(DIRECTLINK_NAT_ENDPOINT_DEPENDENT),
            "endpoint_dependent");
    } TEST_END;
    return failures;
}

struct range_row {
    uint8_t family;
    uint8_t ip[16];
};

#define R4(a, b, c, d) {DIRECTLINK_V4, {a, b, c, d}}
#define R6(...) {DIRECTLINK_V6, {__VA_ARGS__}}

static const struct range_row k_reserved[] = {
    R4(192, 0, 0, 1),     R4(192, 0, 0, 255),  R4(192, 0, 2, 1),
    R4(198, 18, 0, 1),    R4(198, 19, 255, 254), R4(198, 51, 100, 7),
    R4(203, 0, 113, 7),   R4(192, 88, 99, 1),
    R6(0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1),
    R6(0x20, 0x01, 0, 0, 0x41, 0x36, 0xE3, 0x78, 0x80, 0, 0x63, 0xBF, 0x3F, 0xFF,
       0xFD, 0xD2),
    R6(0x20, 0x02, 0xC0, 0x00, 0x02, 0x04, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1),
    R6(0x00, 0x64, 0xFF, 0x9B, 0, 0, 0, 0, 0, 0, 0, 0, 0xC0, 0, 0x02, 0x01),
    R6(0x00, 0x64, 0xFF, 0x9B, 0, 0x01, 0, 0, 0, 0, 0, 0, 0xC0, 0, 0x02, 0x01),
    R6(0xFE, 0xC0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1),
};

static const struct range_row k_routable[] = {
    R4(192, 0, 1, 1),     R4(192, 0, 3, 1),    R4(198, 17, 255, 255),
    R4(198, 20, 0, 1),    R4(198, 51, 99, 1),  R4(198, 51, 101, 1),
    R4(203, 0, 112, 1),   R4(203, 0, 114, 1),  R4(192, 88, 98, 1),
    R4(192, 88, 100, 1),
    R6(0x20, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1),
    R6(0x20, 0x01, 0x0D, 0xB9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1),
    R6(0x20, 0x03, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1),
    R6(0x00, 0x64, 0xFF, 0x9A, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1),
    R6(0x26, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1),
};

static size_t row_len(const struct range_row *r)
{
    return r->family == DIRECTLINK_V4 ? 4u : 16u;
}

static enum directlink_status observed_row(const struct range_row *r)
{
    uint8_t wire[5 + 16] = {1, 1, r->family, 0x92, 0x10};
    memcpy(wire + 5, r->ip, row_len(r));
    return decode_bytes(wire, 5 + row_len(r));
}

static enum directlink_status offer_row(const struct range_row *r)
{
    uint8_t wire[35 + 4 + 16];
    memset(wire, 0, sizeof wire);
    wire[0] = 1;
    wire[1] = DIRECTLINK_SCOPE_INTRA_FLEET;
    memset(wire + 2, 0xAB, 16);
    wire[26] = 0x88; /* ttl 5000 */
    wire[27] = 0x13;
    wire[30] = 0x64; /* delay 100 */
    wire[34] = 1;
    wire[35] = 1; /* host candidate */
    wire[36] = r->family;
    wire[37] = 0x92;
    wire[38] = 0x10;
    memcpy(wire + 39, r->ip, row_len(r));
    struct directlink_policy pol;
    directlink_policy_default(&pol);
    pol.scope_setting[DIRECTLINK_SCOPE_INTRA_FLEET] =
        DIRECTLINK_SETTING_DIRECT_ALLOWED;
    struct directlink_peer peer = {.scope = DIRECTLINK_SCOPE_INTRA_FLEET,
                                   .paired = true};
    peer.identity[0] = 1;
    struct directlink_offer sink;
    return directlink_offer_decode(&pol, &peer, wire, 39 + row_len(r), &sink,
                                   NULL);
}

static int dla_case_reserved_ranges(void)
{
    int failures = 0;
    TEST_CASE("directlink address: special-purpose ranges are refused on both codec paths") {
        for (size_t i = 0; i < sizeof k_reserved / sizeof k_reserved[0]; i++) {
            ASSERT_EQ((int)observed_row(&k_reserved[i]),
                      (int)DIRECTLINK_ERR_ADDRESS);
            ASSERT_EQ((int)offer_row(&k_reserved[i]), (int)DIRECTLINK_ERR_ADDRESS);
        }
        /* The neighbours of each range stay routable. */
        for (size_t i = 0; i < sizeof k_routable / sizeof k_routable[0]; i++) {
            ASSERT_EQ((int)observed_row(&k_routable[i]), (int)DIRECTLINK_OK);
            ASSERT_EQ((int)offer_row(&k_routable[i]), (int)DIRECTLINK_OK);
        }
    } TEST_END;
    return failures;
}

static int dla_case_inter_observers(void)
{
    int failures = 0;
    TEST_CASE("directlink reflexive: inter_fleet reports alone never set the address") {
        struct directlink_reflexive r;
        directlink_reflexive_init(&r, 0);
        report_as(&r, 1, DIRECTLINK_SCOPE_INTER_FLEET, v4(45, 10, 100, 5, 40000), 0);
        report_as(&r, 2, DIRECTLINK_SCOPE_INTER_FLEET, v4(45, 10, 100, 5, 40000), 0);
        report_as(&r, 3, DIRECTLINK_SCOPE_INTER_FLEET, v4(45, 10, 100, 5, 40000), 0);
        struct directlink_reflexive_report rep = eval(&r, 1, NULL, 0);
        ASSERT(!rep.address_trusted);
        ASSERT_EQ((int)rep.nat_class, (int)DIRECTLINK_NAT_UNKNOWN);
        /* One intra_fleet observer lets the corroborated address stand. */
        report_as(&r, 4, DIRECTLINK_SCOPE_INTRA_FLEET, v4(45, 10, 100, 5, 40000), 1);
        rep = eval(&r, 2, NULL, 0);
        ASSERT(rep.address_trusted);
        ASSERT_EQ((int)rep.address.port, 40000);
        /* An intra_fleet observer that disagrees does not help the others. */
        struct directlink_reflexive s;
        directlink_reflexive_init(&s, 0);
        report_as(&s, 1, DIRECTLINK_SCOPE_INTER_FLEET, v4(45, 10, 100, 5, 40000), 0);
        report_as(&s, 2, DIRECTLINK_SCOPE_INTER_FLEET, v4(45, 10, 100, 5, 40000), 0);
        report_as(&s, 3, DIRECTLINK_SCOPE_INTRA_FLEET, v4(45, 10, 100, 9, 40000), 0);
        ASSERT(!eval(&s, 1, NULL, 0).address_trusted);
        struct directlink_observed o = obs(v4(45, 10, 100, 5, 40000));
        ASSERT(!directlink_reflexive_observe(&s, peer_id(7),
                                             (enum directlink_scope)5, &o, 0));
    } TEST_END;
    return failures;
}

static int dla_case_inter_port(void)
{
    int failures = 0;
    TEST_CASE("directlink reflexive: inter_fleet reports cannot choose the port") {
        struct directlink_reflexive r;
        directlink_reflexive_init(&r, 0);
        report_as(&r, 1, DIRECTLINK_SCOPE_INTRA_FLEET, v4(45, 10, 100, 5, 40001), 0);
        report_as(&r, 2, DIRECTLINK_SCOPE_INTER_FLEET, v4(45, 10, 100, 5, 40002), 0);
        report_as(&r, 3, DIRECTLINK_SCOPE_INTER_FLEET, v4(45, 10, 100, 5, 40002), 0);
        struct directlink_reflexive_report rep = eval(&r, 1, NULL, 0);
        ASSERT(rep.address_trusted);
        ASSERT(rep.address.port != 40002);
        ASSERT_EQ((int)rep.address.port, 0);
        ASSERT_EQ((int)rep.nat_class, (int)DIRECTLINK_NAT_ENDPOINT_DEPENDENT);
        /* Once an intra_fleet peer reports the port, the majority stands. */
        report_as(&r, 4, DIRECTLINK_SCOPE_INTRA_FLEET, v4(45, 10, 100, 5, 40002), 1);
        rep = eval(&r, 2, NULL, 0);
        ASSERT_EQ((int)rep.address.port, 40002);
    } TEST_END;
    return failures;
}

int test_directlink_addr(void)
{
    int failures = 0;
    failures += dla_case_known_answer();
    failures += dla_case_malformed();
    failures += dla_case_forbidden_addresses();
    failures += dla_case_independent_and_dependent();
    failures += dla_case_open();
    failures += dla_case_liar();
    failures += dla_case_one_peer_counts_once();
    failures += dla_case_reserved_ranges();
    failures += dla_case_inter_observers();
    failures += dla_case_inter_port();
    return failures;
}
