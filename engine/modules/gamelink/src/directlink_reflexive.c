/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * directlink reflexive-address aggregator. The rule is stated in
 * gamelink/directlink_reflexive.h. */

#include "gamelink/directlink_reflexive.h"

#include <string.h>

const char *directlink_nat_class_label(enum directlink_nat_class nat_class)
{
    switch (nat_class) {
    case DIRECTLINK_NAT_UNKNOWN: return "unknown";
    case DIRECTLINK_NAT_OPEN: return "open";
    case DIRECTLINK_NAT_ENDPOINT_INDEPENDENT: return "endpoint_independent";
    case DIRECTLINK_NAT_ENDPOINT_DEPENDENT: return "endpoint_dependent";
    }
    return "unknown";
}

void directlink_reflexive_init(struct directlink_reflexive *state,
                               int64_t lifetime_ms)
{
    if (!state)
        return;
    memset(state, 0, sizeof *state);
    state->lifetime_ms =
        lifetime_ms > 0 ? lifetime_ms : DIRECTLINK_REFLEXIVE_DEFAULT_LIFETIME_MS;
}

static struct directlink_reflexive_slot *pick_slot(
    struct directlink_reflexive *state, const uint8_t peer[32],
    enum directlink_proto proto)
{
    struct directlink_reflexive_slot *victim = &state->slot[0];
    for (size_t i = 0; i < DIRECTLINK_REFLEXIVE_SLOTS; i++) {
        struct directlink_reflexive_slot *s = &state->slot[i];
        if (s->used && s->proto == proto && memcmp(s->peer, peer, 32) == 0)
            return s;
        if (!s->used)
            victim = s;
        else if (victim->used && s->at_ms < victim->at_ms)
            victim = s;
    }
    return victim;
}

bool directlink_reflexive_observe(struct directlink_reflexive *state,
                                  const uint8_t peer[32],
                                  enum directlink_scope scope,
                                  const struct directlink_observed *observed,
                                  int64_t now_ms)
{
    if (!state || !peer || !observed || (unsigned)scope >= DIRECTLINK_SCOPE_COUNT)
        return false;
    if (observed->addr.port == 0 ||
        directlink_addr_classify(&observed->addr) == DIRECTLINK_ADDR_INVALID ||
        directlink_addr_classify(&observed->addr) == DIRECTLINK_ADDR_LOOPBACK)
        return false;
    struct directlink_reflexive_slot *s = pick_slot(state, peer, observed->proto);
    s->used = true;
    s->proto = observed->proto;
    memcpy(s->peer, peer, 32);
    s->scope = scope;
    s->addr = observed->addr;
    s->at_ms = now_ms;
    return true;
}

static bool slot_fresh(const struct directlink_reflexive *state,
                       const struct directlink_reflexive_slot *s,
                       enum directlink_proto proto, int64_t now_ms)
{
    return s->used && s->proto == proto && now_ms >= s->at_ms &&
           now_ms - s->at_ms <= state->lifetime_ms;
}

/* Number of fresh slots whose host equals `host`. */
static uint32_t count_host(const struct directlink_reflexive *state,
                           enum directlink_proto proto, int64_t now_ms,
                           const struct directlink_addr *host)
{
    uint32_t n = 0;
    for (size_t i = 0; i < DIRECTLINK_REFLEXIVE_SLOTS; i++) {
        const struct directlink_reflexive_slot *s = &state->slot[i];
        if (slot_fresh(state, s, proto, now_ms) &&
            directlink_addr_same_host(&s->addr, host))
            n++;
    }
    return n;
}

/* The single host reported by at least two peers; false when there is none or
 * when two different hosts both qualify. */
/* True when a fresh intra_fleet slot reports `host`. */
static bool has_intra_observer(const struct directlink_reflexive *state,
                               enum directlink_proto proto, int64_t now_ms,
                               const struct directlink_addr *host)
{
    for (size_t i = 0; i < DIRECTLINK_REFLEXIVE_SLOTS; i++) {
        const struct directlink_reflexive_slot *s = &state->slot[i];
        if (slot_fresh(state, s, proto, now_ms) &&
            s->scope == DIRECTLINK_SCOPE_INTRA_FLEET &&
            directlink_addr_same_host(&s->addr, host))
            return true;
    }
    return false;
}

static bool find_trusted_host(const struct directlink_reflexive *state,
                              enum directlink_proto proto, int64_t now_ms,
                              struct directlink_addr *host, uint32_t *peers)
{
    bool found = false;
    for (size_t i = 0; i < DIRECTLINK_REFLEXIVE_SLOTS; i++) {
        const struct directlink_reflexive_slot *s = &state->slot[i];
        if (!slot_fresh(state, s, proto, now_ms))
            continue;
        uint32_t n = count_host(state, proto, now_ms, &s->addr);
        if (n < 2 || (found && directlink_addr_same_host(host, &s->addr)) ||
            !has_intra_observer(state, proto, now_ms, &s->addr))
            continue;
        if (found)
            return false;
        found = true;
        *host = s->addr;
        *peers = n;
    }
    return found;
}

static bool is_local(const struct directlink_addr *addr,
                     const struct directlink_addr *local, size_t count)
{
    for (size_t i = 0; local && i < count; i++)
        if (directlink_addr_same_host(addr, &local[i]))
            return true;
    return false;
}

/* Peers on `host` reporting exactly `port`. */
static uint32_t count_port(const struct directlink_reflexive *state,
                           enum directlink_proto proto, int64_t now_ms,
                           const struct directlink_addr *host, uint16_t port)
{
    uint32_t n = 0;
    for (size_t i = 0; i < DIRECTLINK_REFLEXIVE_SLOTS; i++) {
        const struct directlink_reflexive_slot *s = &state->slot[i];
        if (slot_fresh(state, s, proto, now_ms) &&
            directlink_addr_same_host(&s->addr, host) && s->addr.port == port)
            n++;
    }
    return n;
}

/* True when a fresh intra_fleet slot reports exactly `host`:`port`. */
static bool port_has_intra(const struct directlink_reflexive *state,
                           enum directlink_proto proto, int64_t now_ms,
                           const struct directlink_addr *host, uint16_t port)
{
    for (size_t i = 0; i < DIRECTLINK_REFLEXIVE_SLOTS; i++) {
        const struct directlink_reflexive_slot *s = &state->slot[i];
        if (slot_fresh(state, s, proto, now_ms) &&
            s->scope == DIRECTLINK_SCOPE_INTRA_FLEET &&
            directlink_addr_same_host(&s->addr, host) && s->addr.port == port)
            return true;
    }
    return false;
}

static void classify_ports(const struct directlink_reflexive *state,
                           enum directlink_proto proto, int64_t now_ms,
                           struct directlink_reflexive_report *out)
{
    uint16_t best_port = 0;
    uint32_t best = 0;
    for (size_t i = 0; i < DIRECTLINK_REFLEXIVE_SLOTS; i++) {
        const struct directlink_reflexive_slot *s = &state->slot[i];
        if (!slot_fresh(state, s, proto, now_ms) ||
            !directlink_addr_same_host(&s->addr, &out->address) ||
            !port_has_intra(state, proto, now_ms, &out->address, s->addr.port))
            continue;
        uint32_t n = count_port(state, proto, now_ms, &out->address, s->addr.port);
        if (n > best) {
            best = n;
            best_port = s->addr.port;
        }
    }
    out->port_peers = best;
    if (best >= 2 && best * 2u > out->host_peers) {
        out->nat_class = DIRECTLINK_NAT_ENDPOINT_INDEPENDENT;
        out->address.port = best_port;
    } else if (best == 1) {
        out->nat_class = DIRECTLINK_NAT_ENDPOINT_DEPENDENT;
        out->address.port = 0;
    } else {
        out->nat_class = DIRECTLINK_NAT_UNKNOWN;
        out->address.port = 0;
    }
}

void directlink_reflexive_evaluate(const struct directlink_reflexive *state,
                                   enum directlink_proto proto, int64_t now_ms,
                                   const struct directlink_addr *local,
                                   size_t local_count,
                                   struct directlink_reflexive_report *out)
{
    if (!out)
        return;
    memset(out, 0, sizeof *out);
    if (!state)
        return;
    if (!find_trusted_host(state, proto, now_ms, &out->address, &out->host_peers)) {
        memset(&out->address, 0, sizeof out->address);
        out->host_peers = 0;
        return;
    }
    out->address_trusted = true;
    classify_ports(state, proto, now_ms, out);
    if (out->nat_class == DIRECTLINK_NAT_UNKNOWN)
        out->address_trusted = false;
    if (is_local(&out->address, local, local_count)) {
        out->nat_class = DIRECTLINK_NAT_OPEN;
        out->address_trusted = out->address.port != 0;
    }
}
