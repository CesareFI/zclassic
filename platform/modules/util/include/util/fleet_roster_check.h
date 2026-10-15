/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: The ROSTER SEAM (ZRC 0012 step 2) — the calls the fleet board
 * makes to learn which fleet root this node trusts and whether one
 * operator-sealed roster line is genuinely sealed by it, and the setter the
 * top layer uses to install what answers.
 *
 * The sealed machine line, its codec and the anchor verdict live in
 * tools/dev (fleet_enrol.h, fleet_enrol_anchor.c). The fleet board that
 * consults them lives under engine/, which may not include a tools/ header.
 * This is the same shape as util/fleet_role_check.h: a function-pointer
 * vtable in a platform module both sides may include, filled in by
 * tools/dev/fleet_roster_gate.c and installed from engine/entry/main.c.
 *
 * Nothing here decides membership. It answers three narrow questions: which
 * key is the root, did that root seal this line, and what is the line's
 * signing key. The engine (config/boot_fleet_roster.h) holds the roster and
 * the verdict.
 *
 * With no provider installed the root is "not present": the roster gate is
 * unarmed and the fleet board behaves exactly as it did before step 2.
 * That is the only default, and it is the old behaviour, never a wider one.
 */

#ifndef ZCL_UTIL_FLEET_ROSTER_CHECK_H
#define ZCL_UTIL_FLEET_ROSTER_CHECK_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Longest sealed roster line the board will carry as a roster row. It is the
 * wire ceiling of one fleet_machine line (tools/dev/fleet_enrol.h) rounded
 * up; a longer string is not a roster row. */
#define ZCL_FLEET_ROSTER_LINE_MAX 2400u

/* What the chain's zid_identities projection said about the root. The values
 * match tools/dev's enum fleet_anchor_state one for one (the provider
 * asserts it), so the verdict function there is the only one. */
enum zcl_fleet_root_state {
    ZCL_FLEET_ROOT_UNCHECKED = 0,
    ZCL_FLEET_ROOT_UNREADABLE,
    ZCL_FLEET_ROOT_NOT_ANCHORED,
    ZCL_FLEET_ROOT_ACTIVE,
    ZCL_FLEET_ROOT_ROTATED,
    ZCL_FLEET_ROOT_REVOKED,
};

struct zcl_fleet_roster_provider {
    /* The operator root this node trusts. `present` false means this box
     * has no fleet root, which is a state and not an error; the function
     * returns false only when a recorded root cannot be read. `manager` is
     * true when the root is this box's own key, i.e. the box that admits
     * machines and therefore publishes the roster. */
    bool (*root)(uint8_t root[32], bool *present, bool *manager, void *ctx);
    /* One sealed line against `root` and the root's anchor verdict. True
     * only when the seal verifies AND the anchor verdict (under `require`)
     * accepts; `signer` then holds the line's board signing key (all zero
     * when the receipt named none). On false `why` is the typed token:
     * fleetboard.roster_signature_invalid for a bad seal, else one of the
     * fleet_root_* refusals, and `sealed` says whether the seal itself
     * verified (so a revoked root is not confused with a forged row). */
    bool (*verify)(const char *line, const uint8_t root[32],
                   enum zcl_fleet_root_state state, bool require,
                   uint8_t signer[32], bool *sealed, const char **why,
                   void *ctx);
    /* Visit every line of this box's own machine roster, in file order.
     * The manager publishes these onto the board. False when unreadable. */
    bool (*each_line)(void (*visit)(const char *line, void *user),
                      void *user, void *ctx);
    void *ctx;
    const char *name;
};

/* Install the provider this process asks, copied by value. NULL, or a
 * provider with no `root`, uninstalls and returns the gate to unarmed. */
void zcl_fleet_roster_provider_install(
    const struct zcl_fleet_roster_provider *p);
bool zcl_fleet_roster_provider_installed(void);

/* The wrappers the engine calls. With no provider: root is absent, verify
 * refuses, each_line visits nothing. */
bool zcl_fleet_roster_root(uint8_t root[32], bool *present, bool *manager);
bool zcl_fleet_roster_verify(const char *line, const uint8_t root[32],
                             enum zcl_fleet_root_state state, bool require,
                             uint8_t signer[32], bool *sealed,
                             const char **why);
bool zcl_fleet_roster_each_line(void (*visit)(const char *line, void *user),
                                void *user);

#endif /* ZCL_UTIL_FLEET_ROSTER_CHECK_H */
