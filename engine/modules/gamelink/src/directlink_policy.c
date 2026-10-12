/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * directlink policy decision. See gamelink/directlink_policy.h. */

#include "gamelink/directlink_policy.h"

#include <string.h>

const char *directlink_refusal_label(enum directlink_refusal refusal)
{
    switch (refusal) {
    case DIRECTLINK_ALLOW: return "allow";
    case DIRECTLINK_REFUSE_JOIN_IN_PROGRESS: return "join_in_progress";
    case DIRECTLINK_REFUSE_NOT_PAIRED: return "not_paired";
    case DIRECTLINK_REFUSE_SCOPE_OFF: return "scope_off";
    case DIRECTLINK_REFUSE_INVALID: return "invalid";
    }
    return "unknown";
}

void directlink_policy_default(struct directlink_policy *policy)
{
    if (policy)
        memset(policy, 0, sizeof *policy);
}

enum directlink_refusal directlink_may_offer_direct(
    enum directlink_scope scope, bool paired, bool join_in_progress,
    enum directlink_setting setting)
{
    if ((unsigned)scope >= DIRECTLINK_SCOPE_COUNT ||
        ((unsigned)setting != (unsigned)DIRECTLINK_SETTING_OFF &&
         (unsigned)setting != (unsigned)DIRECTLINK_SETTING_DIRECT_ALLOWED))
        return DIRECTLINK_REFUSE_INVALID;
    if (join_in_progress)
        return DIRECTLINK_REFUSE_JOIN_IN_PROGRESS;
    if (!paired)
        return DIRECTLINK_REFUSE_NOT_PAIRED;
    if (setting != DIRECTLINK_SETTING_DIRECT_ALLOWED)
        return DIRECTLINK_REFUSE_SCOPE_OFF;
    return DIRECTLINK_ALLOW;
}

enum directlink_refusal directlink_policy_decide(
    const struct directlink_policy *policy, const struct directlink_peer *peer)
{
    if (!policy || !peer || (unsigned)peer->scope >= DIRECTLINK_SCOPE_COUNT)
        return DIRECTLINK_REFUSE_INVALID;
    return directlink_may_offer_direct(
        peer->scope, peer->paired, peer->join_in_progress,
        policy->scope_setting[peer->scope]);
}
