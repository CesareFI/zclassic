/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: The fleet root as a ZID anchor — pure verdicts over an anchor
 *          fact the adapter read from the zid_identities projection.
 *          See the "fleet root as a ZID anchor" block of
 *          tools/dev/fleet_enrol.h for the contract (ZRC 0012 step 1).
 *
 * No I/O, no clock, no allocation, no logging of key material: a refusal is
 * a token the caller reports. */

#include "fleet_enrol.h"

#include <string.h>

const char *fleet_anchor_state_name(enum fleet_anchor_state state)
{
    switch (state) {
    case FLEET_ANCHOR_UNCHECKED: return "unchecked";
    case FLEET_ANCHOR_UNREADABLE: return "unreadable";
    case FLEET_ANCHOR_NOT_ANCHORED: return "not_anchored";
    case FLEET_ANCHOR_ACTIVE: return "active";
    case FLEET_ANCHOR_ROTATED: return "rotated";
    case FLEET_ANCHOR_REVOKED: return "revoked";
    }
    return "unchecked";
}

const char *fleet_root_anchor_refusal(const struct fleet_anchor_fact *anchor,
                                      bool require)
{
    if (!require)
        return NULL;
    if (!anchor)
        return FLEET_ENROL_WHY_ROOT_UNVERIFIABLE;
    switch (anchor->state) {
    case FLEET_ANCHOR_ACTIVE: return NULL;
    case FLEET_ANCHOR_NOT_ANCHORED: return FLEET_ENROL_WHY_ROOT_NOT_ANCHORED;
    case FLEET_ANCHOR_ROTATED: return FLEET_ENROL_WHY_ROOT_ROTATED;
    case FLEET_ANCHOR_REVOKED: return FLEET_ENROL_WHY_ROOT_REVOKED;
    case FLEET_ANCHOR_UNCHECKED:
    case FLEET_ANCHOR_UNREADABLE: break;
    }
    return FLEET_ENROL_WHY_ROOT_UNVERIFIABLE;
}

bool fleet_root_line_verify(const char *line,
                            const uint8_t root[FLEET_ENROL_PUBKEY_BYTES],
                            const struct fleet_anchor_fact *anchor,
                            bool require, struct fleet_machine *out,
                            const char **why)
{
    const char *refusal = NULL;
    if (why)
        *why = NULL;
    if (!line || !root || !out) {
        if (why)
            *why = FLEET_ENROL_WHY_ARGUMENTS;
        return false;
    }
    if (!fleet_machine_parse(line, root, out, NULL)) {
        if (why)
            *why = FLEET_ENROL_WHY_ROSTER_SIGNATURE;
        return false;
    }
    refusal = fleet_root_anchor_refusal(anchor, require);
    if (refusal) {
        if (why)
            *why = refusal;
        return false;
    }
    return true;
}
