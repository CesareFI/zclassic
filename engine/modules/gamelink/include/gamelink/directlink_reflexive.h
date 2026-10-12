/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * directlink reflexive-address aggregator: from the observed-address reports
 * of several paired peers, the external address this node most likely has and
 * the mapping behaviour of the NAT in front of it. Pure state, injected time,
 * no I/O.
 *
 * Rule (per protocol, over reports no older than the report lifetime; one
 * slot per peer, the newest report of a peer replaces its older one):
 *
 *   1. Trusted host. A host (ip) is trusted when at least two distinct peers
 *      report it and at least one of them is an intra_fleet peer: identities
 *      of another owner's fleet may corroborate an address but cannot
 *      establish it, because one owner can present many identities. The
 *      same holds for a port: a port is considered only when an intra_fleet
 *      peer reports it. If two different hosts each reach two peers, nothing
 *      is trusted (class unknown). A single peer, however it reports, never
 *      sets the address.
 *   2. Class, over the peers that reported the trusted host:
 *        open                  the trusted address is one of this node's own
 *                              interface addresses (no translation);
 *        endpoint_independent  one port is reported by at least two peers and
 *                              by more than half of them: the NAT maps this
 *                              socket to the same port whatever the
 *                              destination, so the address is usable by a
 *                              third party;
 *        endpoint_dependent    at least two peers and every one reports a
 *                              different port: the NAT picks a port per
 *                              destination (symmetric), so punching is
 *                              unlikely and only the host is reported;
 *        unknown               anything else, including no agreement.
 *   3. With two peers one of which misreports only the port, the result is
 *      endpoint_dependent. That is the safe error: it suppresses punching and
 *      never advertises a port a single peer chose.
 */

#ifndef ZCL_GAMELINK_DIRECTLINK_REFLEXIVE_H
#define ZCL_GAMELINK_DIRECTLINK_REFLEXIVE_H

#include "gamelink/directlink_addr.h"
#include "gamelink/directlink_policy.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define DIRECTLINK_REFLEXIVE_SLOTS 16u
#define DIRECTLINK_REFLEXIVE_DEFAULT_LIFETIME_MS (10 * 60 * 1000)

enum directlink_nat_class {
    DIRECTLINK_NAT_UNKNOWN = 0,
    DIRECTLINK_NAT_OPEN,
    DIRECTLINK_NAT_ENDPOINT_INDEPENDENT,
    DIRECTLINK_NAT_ENDPOINT_DEPENDENT
};

const char *directlink_nat_class_label(enum directlink_nat_class nat_class);

struct directlink_reflexive_slot {
    bool used;
    enum directlink_proto proto;
    uint8_t peer[32];
    enum directlink_scope scope;
    struct directlink_addr addr;
    int64_t at_ms;
};

struct directlink_reflexive {
    int64_t lifetime_ms;
    struct directlink_reflexive_slot slot[DIRECTLINK_REFLEXIVE_SLOTS];
};

struct directlink_reflexive_report {
    enum directlink_nat_class nat_class;
    /* True when `address` is a host this node may advertise. For
     * endpoint_dependent the port is 0: only the host is trusted. */
    bool address_trusted;
    struct directlink_addr address;
    uint32_t host_peers; /* distinct peers reporting the trusted host */
    uint32_t port_peers; /* distinct peers reporting the advertised port */
};

void directlink_reflexive_init(struct directlink_reflexive *state,
                               int64_t lifetime_ms);

/* Record one report from an authenticated peer. A full table replaces its
 * oldest slot. Returns false for NULL arguments or an invalid address. */
bool directlink_reflexive_observe(struct directlink_reflexive *state,
                                  const uint8_t peer[32],
                                  enum directlink_scope scope,
                                  const struct directlink_observed *observed,
                                  int64_t now_ms);

/* Evaluate the rule for one protocol. `local` lists this node's own interface
 * addresses (may be NULL with `local_count` 0). */
void directlink_reflexive_evaluate(const struct directlink_reflexive *state,
                                   enum directlink_proto proto, int64_t now_ms,
                                   const struct directlink_addr *local,
                                   size_t local_count,
                                   struct directlink_reflexive_report *out);

#endif /* ZCL_GAMELINK_DIRECTLINK_REFLEXIVE_H */
