/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * directlink policy: whether this node may offer a direct (non-onion) path to
 * one paired peer. Direct links are an optimization over the onion channel
 * (docs/work/NAT_AND_ONION_TRANSPORT.md, "Link policy"); they are never
 * required and never the way a peer is first joined.
 *
 * Two scopes, each with its own setting:
 *   intra_fleet  machines of one owner, paired with each other;
 *   inter_fleet  machines of a different owner's fleet, under separate
 *                consent.
 * Both settings default to off. A zeroed struct directlink_policy is the
 * default, so an uninitialised policy refuses everything.
 *
 * The decision is pure: it reads three facts about the peer and one setting
 * and returns allow or a named refusal. Refusals are checked in a fixed
 * order (join in progress, not paired, scope off) so the reason is stable.
 */

#ifndef ZCL_GAMELINK_DIRECTLINK_POLICY_H
#define ZCL_GAMELINK_DIRECTLINK_POLICY_H

#include <stdbool.h>
#include <stdint.h>

enum directlink_scope {
    DIRECTLINK_SCOPE_INTRA_FLEET = 0,
    DIRECTLINK_SCOPE_INTER_FLEET = 1
};
#define DIRECTLINK_SCOPE_COUNT 2u

enum directlink_setting {
    DIRECTLINK_SETTING_OFF = 0,
    DIRECTLINK_SETTING_DIRECT_ALLOWED = 1
};

struct directlink_policy {
    enum directlink_setting scope_setting[DIRECTLINK_SCOPE_COUNT];
};

/* Facts about one peer, taken from the authenticated paired session by the
 * caller. `identity` is the peer's authenticated static key. */
struct directlink_peer {
    uint8_t identity[32];
    enum directlink_scope scope;
    bool paired;
    bool join_in_progress;
};

enum directlink_refusal {
    DIRECTLINK_ALLOW = 0,
    DIRECTLINK_REFUSE_JOIN_IN_PROGRESS,
    DIRECTLINK_REFUSE_NOT_PAIRED,
    DIRECTLINK_REFUSE_SCOPE_OFF,
    DIRECTLINK_REFUSE_INVALID
};

const char *directlink_refusal_label(enum directlink_refusal refusal);

/* Every scope off. Equivalent to zero-initialising the struct. */
void directlink_policy_default(struct directlink_policy *policy);

/* The pure decision for one scope, pairing state and setting. An
 * out-of-range scope or setting refuses with DIRECTLINK_REFUSE_INVALID. */
enum directlink_refusal directlink_may_offer_direct(
    enum directlink_scope scope, bool paired, bool join_in_progress,
    enum directlink_setting setting);

/* The decision for a peer under a policy. NULL arguments refuse. */
enum directlink_refusal directlink_policy_decide(
    const struct directlink_policy *policy, const struct directlink_peer *peer);

#endif /* ZCL_GAMELINK_DIRECTLINK_POLICY_H */
