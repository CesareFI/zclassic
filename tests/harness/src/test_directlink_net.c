/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The deterministic datagram network (tests/harness/include/test/
 * directlink_netsim.h): latency, loss, and the mapping and filtering
 * behaviour of the three NAT models, checked on their own before the punch
 * state machine relies on them. */

#include "test/test_core.h"

#include "test/directlink_netsim.h"

#include <string.h>

static const uint8_t k_ext[4] = {45, 20, 113, 10};
static const uint8_t k_byte[1] = {0x7E};

static bool recv_from(struct ns *s, int node, struct directlink_addr *from)
{
    struct ns_dgram d;
    if (!ns_recv(s, node, &d))
        return false;
    *from = d.from;
    return true;
}

static int dln_case_latency_and_loss(void)
{
    int failures = 0;
    TEST_CASE("netsim: fixed latency, total loss, no loss, unroutable") {
        struct ns s;
        ns_init(&s, 1, 0);
        int a = ns_add_public(&s, ns_ip4(45, 10, 100, 1, 5000), 15);
        int b = ns_add_public(&s, ns_ip4(45, 10, 100, 2, 5000), 25);
        struct directlink_addr to = ns_ip4(45, 10, 100, 2, 5000);
        struct directlink_addr from;
        ASSERT(ns_send(&s, a, &to, k_byte, 1));
        ns_advance(&s, 39);
        ASSERT(!recv_from(&s, b, &from));
        ns_advance(&s, 40);
        ASSERT(recv_from(&s, b, &from));
        ASSERT_EQ((int)from.port, 5000);
        ASSERT_EQ((int)from.ip[3], 1);
        /* Wrong port on a public node is unroutable. */
        struct directlink_addr nowhere = ns_ip4(45, 10, 100, 2, 5001);
        ASSERT(ns_send(&s, a, &nowhere, k_byte, 1));
        ns_advance(&s, 1000);
        ASSERT(!recv_from(&s, b, &from));
        ASSERT_EQ(s.dropped_route, (uint32_t)1);
        /* Loss is a seeded draw: 100% drops all, 0% drops none. */
        struct ns lossy;
        ns_init(&lossy, 2, 1000000);
        a = ns_add_public(&lossy, ns_ip4(45, 10, 100, 1, 5000), 1);
        b = ns_add_public(&lossy, ns_ip4(45, 10, 100, 2, 5000), 1);
        for (int i = 0; i < 20; i++)
            ASSERT(ns_send(&lossy, a, &to, k_byte, 1));
        ns_advance(&lossy, 100);
        ASSERT_EQ(lossy.dropped_loss, (uint32_t)20);
        ASSERT_EQ(lossy.delivered, (uint32_t)0);
        lossy.loss_ppm = 0;
        for (int i = 0; i < 20; i++)
            ASSERT(ns_send(&lossy, a, &to, k_byte, 1));
        ns_advance(&lossy, 200);
        ASSERT_EQ(lossy.delivered, (uint32_t)20);
    } TEST_END;
    return failures;
}

static int dln_case_full_cone(void)
{
    int failures = 0;
    TEST_CASE("netsim: full cone admits any remote once a mapping exists") {
        struct ns s;
        ns_init(&s, 1, 0);
        int n = ns_add_natted(&s, ns_ip4(10, 0, 0, 2, 5000), 1, NS_NAT_FULL_CONE,
                              k_ext, 30000);
        int h1 = ns_add_public(&s, ns_ip4(45, 10, 100, 1, 5000), 1);
        int h2 = ns_add_public(&s, ns_ip4(45, 10, 100, 2, 5000), 1);
        struct directlink_addr mapped = ns_ip4(45, 20, 113, 10, NS_FIRST_EXT_PORT);
        struct directlink_addr h1a = ns_ip4(45, 10, 100, 1, 5000);
        struct directlink_addr from;
        /* No mapping yet: unsolicited traffic is dropped. */
        ASSERT(ns_send(&s, h2, &mapped, k_byte, 1));
        ns_advance(&s, 10);
        ASSERT(!recv_from(&s, n, &from));
        ASSERT_EQ(s.dropped_nat, (uint32_t)1);
        ASSERT(ns_send(&s, n, &h1a, k_byte, 1));
        ns_advance(&s, 20);
        ASSERT(recv_from(&s, h1, &from));
        ASSERT(directlink_addr_equal(&from, &mapped));
        /* A host the node never contacted now gets through. */
        ASSERT(ns_send(&s, h2, &mapped, k_byte, 1));
        ns_advance(&s, 30);
        ASSERT(recv_from(&s, n, &from));
        ASSERT_EQ((int)from.ip[3], 2);
    } TEST_END;
    return failures;
}

static int dln_case_port_restricted(void)
{
    int failures = 0;
    TEST_CASE("netsim: port-restricted needs an outbound packet to that port") {
        struct ns s;
        ns_init(&s, 1, 0);
        int n = ns_add_natted(&s, ns_ip4(10, 0, 0, 2, 5000), 1,
                              NS_NAT_PORT_RESTRICTED, k_ext, 30000);
        int h1 = ns_add_public(&s, ns_ip4(45, 10, 100, 1, 5000), 1);
        int h1b = ns_add_public(&s, ns_ip4(45, 10, 100, 1, 6000), 1);
        int h2 = ns_add_public(&s, ns_ip4(45, 10, 100, 2, 5000), 1);
        struct directlink_addr h1a = ns_ip4(45, 10, 100, 1, 5000);
        struct directlink_addr mapped = ns_ip4(45, 20, 113, 10, NS_FIRST_EXT_PORT);
        struct directlink_addr from;
        ASSERT(ns_send(&s, n, &h1a, k_byte, 1));
        ns_advance(&s, 10);
        ASSERT(recv_from(&s, h1, &from));
        /* The mapping is the same toward every destination. */
        struct directlink_addr h2a = ns_ip4(45, 10, 100, 2, 5000);
        ASSERT(ns_send(&s, n, &h2a, k_byte, 1));
        ns_advance(&s, 20);
        ASSERT(recv_from(&s, h2, &from));
        ASSERT(directlink_addr_equal(&from, &mapped));
        /* Same address, other port: dropped. Contacted address: delivered. */
        struct ns_dgram unused;
        ASSERT(ns_send(&s, h1b, &mapped, k_byte, 1));
        ns_advance(&s, 30);
        ASSERT(!ns_recv(&s, n, &unused));
        ASSERT(ns_send(&s, h1, &mapped, k_byte, 1));
        ns_advance(&s, 40);
        ASSERT(ns_recv(&s, n, &unused));
        ASSERT_EQ(s.dropped_nat, (uint32_t)1);
    } TEST_END;
    return failures;
}

static int dln_case_symmetric(void)
{
    int failures = 0;
    TEST_CASE("netsim: symmetric picks a port per destination") {
        struct ns s;
        ns_init(&s, 1, 0);
        int n = ns_add_natted(&s, ns_ip4(10, 0, 0, 2, 5000), 1, NS_NAT_SYMMETRIC,
                              k_ext, 30000);
        int h1 = ns_add_public(&s, ns_ip4(45, 10, 100, 1, 5000), 1);
        int h2 = ns_add_public(&s, ns_ip4(45, 10, 100, 2, 5000), 1);
        struct directlink_addr h1a = ns_ip4(45, 10, 100, 1, 5000);
        struct directlink_addr h2a = ns_ip4(45, 10, 100, 2, 5000);
        struct directlink_addr f1, f2, from;
        ASSERT(ns_send(&s, n, &h1a, k_byte, 1));
        ASSERT(ns_send(&s, n, &h2a, k_byte, 1));
        ns_advance(&s, 10);
        ASSERT(recv_from(&s, h1, &f1));
        ASSERT(recv_from(&s, h2, &f2));
        ASSERT(f1.port != f2.port);
        /* h1 may not use the port that was opened toward h2. */
        ASSERT(ns_send(&s, h1, &f2, k_byte, 1));
        ns_advance(&s, 20);
        ASSERT(!recv_from(&s, n, &from));
        ASSERT(ns_send(&s, h2, &f2, k_byte, 1));
        ns_advance(&s, 30);
        ASSERT(recv_from(&s, n, &from));
        /* Repeated sends to one destination reuse its mapping. */
        ASSERT(ns_send(&s, n, &h1a, k_byte, 1));
        ns_advance(&s, 40);
        ASSERT(recv_from(&s, h1, &from));
        ASSERT_EQ((int)from.port, (int)f1.port);
    } TEST_END;
    return failures;
}

static int dln_case_timeout(void)
{
    int failures = 0;
    TEST_CASE("netsim: an unrefreshed mapping expires, a refreshed one lives") {
        struct ns s;
        ns_init(&s, 1, 0);
        int n = ns_add_natted(&s, ns_ip4(10, 0, 0, 2, 5000), 1, NS_NAT_FULL_CONE,
                              k_ext, 1000);
        int h = ns_add_public(&s, ns_ip4(45, 10, 100, 1, 5000), 1);
        struct directlink_addr ha = ns_ip4(45, 10, 100, 1, 5000);
        struct directlink_addr mapped = ns_ip4(45, 20, 113, 10, NS_FIRST_EXT_PORT);
        struct ns_dgram d;
        ASSERT(ns_send(&s, n, &ha, k_byte, 1));
        ns_advance(&s, 900);
        ASSERT(ns_recv(&s, h, &d));
        ASSERT(ns_send(&s, h, &mapped, k_byte, 1));
        ns_advance(&s, 1000);
        ASSERT(ns_recv(&s, n, &d)); /* 900 ms after the last outbound: alive */
        ASSERT(ns_send(&s, n, &ha, k_byte, 1)); /* refresh at t=1000 */
        ns_advance(&s, 1950);
        ASSERT(ns_send(&s, h, &mapped, k_byte, 1));
        ns_advance(&s, 2000);
        ASSERT(ns_recv(&s, n, &d)); /* refresh kept it alive past t=1900 */
        ns_advance(&s, 3000);
        ASSERT(ns_send(&s, h, &mapped, k_byte, 1));
        ns_advance(&s, 3100);
        ASSERT(!ns_recv(&s, n, &d)); /* idle for 2000 ms: expired */
    } TEST_END;
    return failures;
}

static int dln_case_permission_timeout(void)
{
    int failures = 0;
    TEST_CASE("netsim: a port-restricted permission expires on its own") {
        struct ns s;
        ns_init(&s, 1, 0);
        int n = ns_add_natted(&s, ns_ip4(10, 0, 0, 2, 5000), 1,
                              NS_NAT_PORT_RESTRICTED, k_ext, 1000);
        int h1 = ns_add_public(&s, ns_ip4(45, 10, 100, 1, 5000), 1);
        int h2 = ns_add_public(&s, ns_ip4(45, 10, 100, 2, 5000), 1);
        struct directlink_addr h1a = ns_ip4(45, 10, 100, 1, 5000);
        struct directlink_addr h2a = ns_ip4(45, 10, 100, 2, 5000);
        struct directlink_addr mapped = ns_ip4(45, 20, 113, 10, NS_FIRST_EXT_PORT);
        struct ns_dgram d;
        ASSERT(ns_send(&s, n, &h1a, k_byte, 1)); /* permission for h1 at t=0 */
        ns_advance(&s, 800);
        ASSERT(ns_send(&s, n, &h2a, k_byte, 1)); /* keeps the mapping alive */
        ns_advance(&s, 1100);
        ASSERT(ns_recv(&s, h2, &d));
        ASSERT(ns_send(&s, h2, &mapped, k_byte, 1));
        ASSERT(ns_send(&s, h1, &mapped, k_byte, 1));
        ns_advance(&s, 1200);
        ASSERT(ns_recv(&s, n, &d)); /* h2 permitted at t=800 */
        ASSERT(!ns_recv(&s, n, &d)); /* h1 permitted at t=0, 1100 ms ago */
    } TEST_END;
    return failures;
}

int test_directlink_net(void)
{
    int failures = 0;
    failures += dln_case_latency_and_loss();
    failures += dln_case_full_cone();
    failures += dln_case_port_restricted();
    failures += dln_case_symmetric();
    failures += dln_case_timeout();
    failures += dln_case_permission_timeout();
    return failures;
}
