/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Catalog-shape checks for zcl_command_registry_validate(), split so the
 * dispatcher and each predicate stay at or under cyclomatic 15. Why-strings
 * are unchanged from the original inline chain. */

#include "kernel/command_registry.h"

#include "command_registry_internal.h"

#include "base/safe_alloc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Open-addressed names of paths and aliases already accepted. The boot
 * catalog is unique, so the success path inserts once instead of comparing
 * every command with every earlier command. A miss, a full table, or a
 * failed allocation falls back to cr_validate_collisions, which still owns
 * the refusal text. Branch paths are recorded the same way so a parent
 * check does not scan the whole catalog. A miss there falls back to the
 * scan, and the missing-parent text stays in cr_validate_parent_exists. */
enum { CR_NAME_CAP = 8192 };

struct cr_name_slot {
    const char *s;
    uint32_t len;
    uint32_t hash;
};

struct cr_name_table {
    struct cr_name_slot *slots;
    bool usable;
};

static uint32_t cr_name_hash(const char *s, uint32_t n)
{
    uint32_t h = 2166136261u;
    for (uint32_t i = 0; i < n; i++) {
        h ^= (unsigned char)s[i];
        h *= 16777619u;
    }
    return h ? h : 1u;
}

/* 1 present, 0 empty, -1 full. */
static int cr_name_probe(const struct cr_name_table *t, const char *s,
                         uint32_t n, uint32_t h, uint32_t *slot_out)
{
    uint32_t i = h & (CR_NAME_CAP - 1);
    for (uint32_t k = 0; k < CR_NAME_CAP; k++) {
        const struct cr_name_slot *slot = &t->slots[i];
        if (!slot->s) {
            *slot_out = i;
            return 0;
        }
        if (slot->hash == h && slot->len == n && memcmp(slot->s, s, n) == 0)
            return 1;
        i = (i + 1) & (CR_NAME_CAP - 1);
    }
    return -1;
}

static bool cr_name_absent(struct cr_name_table *t, const char *s, uint32_t n)
{
    uint32_t slot = 0;
    int found = cr_name_probe(t, s, n, cr_name_hash(s, n), &slot);
    if (found < 0)
        t->usable = false;
    return found == 0;
}

static bool cr_name_hold(struct cr_name_table *t, const char *s, uint32_t n)
{
    uint32_t h = cr_name_hash(s, n);
    uint32_t slot = 0;
    int found = cr_name_probe(t, s, n, h, &slot);
    if (found < 0)
        t->usable = false;
    if (found != 0)
        return false;
    t->slots[slot].s = s;
    t->slots[slot].len = n;
    t->slots[slot].hash = h;
    return true;
}

static bool cr_csv_absent(struct cr_name_table *t, const char *csv)
{
    if (!csv || !csv[0])
        return true;
    const char *at = csv;
    while (*at) {
        const char *end = strchr(at, ',');
        uint32_t len = end ? (uint32_t)(end - at) : (uint32_t)strlen(at);
        if (!cr_name_absent(t, at, len))
            return false;
        if (!end)
            break;
        at = end + 1;
    }
    return t->usable;
}

static void cr_csv_hold(struct cr_name_table *t, const char *csv)
{
    if (!t->usable || !csv || !csv[0])
        return;
    const char *at = csv;
    while (*at && t->usable) {
        const char *end = strchr(at, ',');
        uint32_t len = end ? (uint32_t)(end - at) : (uint32_t)strlen(at);
        (void)cr_name_hold(t, at, len);
        if (!end)
            break;
        at = end + 1;
    }
}

/* True only when this command's path and aliases are new and recorded.
 * A repeated alias on the same command is not a cross-command collision. */
static bool cr_names_fast_clear(struct cr_name_table *t,
                                const struct zcl_command_spec *spec)
{
    uint32_t path_len;
    if (!t || !t->usable || !t->slots || !spec->path)
        return false;
    path_len = (uint32_t)strlen(spec->path);
    if (!cr_name_absent(t, spec->path, path_len))
        return false;
    if (!cr_csv_absent(t, spec->aliases))
        return false;
    if (!t->usable)
        return false;
    (void)cr_name_hold(t, spec->path, path_len);
    cr_csv_hold(t, spec->aliases);
    return t->usable;
}

static bool cr_validate_shape(const struct zcl_command_spec *spec, size_t i,
                              char *why, size_t why_size)
{
    if (!command_registry_path_valid(spec->path) || !spec->summary ||
        !spec->summary[0] || !command_registry_enum_values_valid(spec) ||
        !command_registry_csv_valid_paths(spec->aliases)) {
        if (why)
            snprintf(why, why_size, "malformed command at index %zu", i);
        return false;
    }
    return true;
}

static bool cr_validate_parent_path(const struct zcl_command_spec *spec,
                                    char *why, size_t why_size)
{
    if (spec->parent && spec->parent[0] &&
        !command_registry_path_valid(spec->parent)) {
        if (why)
            snprintf(why, why_size, "invalid parent for %s", spec->path);
        return false;
    }
    return true;
}

static bool cr_validate_leaf_schema(const struct zcl_command_spec *spec,
                                    char *why, size_t why_size)
{
    if (!spec->input_schema || !spec->input_schema[0] || !spec->output_schema ||
        !spec->output_schema[0] || !spec->example || !spec->example[0]) {
        if (why)
            snprintf(why, why_size, "leaf %s lacks schema/example", spec->path);
        return false;
    }
    return true;
}

static bool cr_validate_leaf_handler(const struct zcl_command_spec *spec,
                                     char *why, size_t why_size)
{
    if (spec->availability == ZCL_COMMAND_READY && !spec->handler) {
        if (why)
            snprintf(why, why_size, "ready leaf %s lacks handler", spec->path);
        return false;
    }
    if (spec->availability == ZCL_COMMAND_PLANNED && spec->handler) {
        if (why)
            snprintf(why, why_size, "planned leaf %s has handler", spec->path);
        return false;
    }
    return true;
}

static bool cr_validate_leaf_semantics(const struct zcl_command_spec *spec,
                                       char *why, size_t why_size)
{
    if (spec->availability == ZCL_COMMAND_READY &&
        (!spec->semantics || !spec->semantics[0] ||
         strcmp(spec->semantics, spec->summary) == 0)) {
        if (why)
            snprintf(why, why_size, "ready leaf %s lacks distinct semantics",
                     spec->path);
        return false;
    }
    return true;
}

static bool cr_validate_leaf(const struct zcl_command_spec *spec, char *why,
                             size_t why_size)
{
    if (!cr_validate_leaf_schema(spec, why, why_size))
        return false;
    if (!cr_validate_leaf_handler(spec, why, why_size))
        return false;
    return cr_validate_leaf_semantics(spec, why, why_size);
}

static bool cr_validate_branch_or_leaf(const struct zcl_command_spec *spec,
                                       char *why, size_t why_size)
{
    if (command_registry_is_branch(spec)) {
        if (spec->handler || spec->availability != ZCL_COMMAND_READY) {
            if (why)
                snprintf(why, why_size,
                         "branch %s must be ready without handler", spec->path);
            return false;
        }
        return true;
    }
    return cr_validate_leaf(spec, why, why_size);
}

static bool cr_validate_budget_reason(const struct zcl_command_spec *spec,
                                      char *why, size_t why_size)
{
    if (spec->budget_bytes != 0 &&
        (spec->budget_bytes < 256 || spec->budget_bytes > 65536)) {
        if (why)
            snprintf(why, why_size, "leaf %s budget_bytes out of range",
                     spec->path);
        return false;
    }
    if (spec->availability != ZCL_COMMAND_READY &&
        (!spec->availability_reason || !spec->availability_reason[0])) {
        if (why)
            snprintf(why, why_size, "non-ready %s lacks reason", spec->path);
        return false;
    }
    return true;
}

static bool cr_validate_effect_traits(const struct zcl_command_spec *spec,
                                      char *why, size_t why_size)
{
    if (spec->effect == ZCL_COMMAND_EFFECT_READ &&
        spec->risk != ZCL_COMMAND_RISK_READ) {
        if (why)
            snprintf(why, why_size, "read effect/risk conflict for %s",
                     spec->path);
        return false;
    }
    const uint32_t known_traits =
        ZCL_COMMAND_TRAIT_DETERMINISTIC | ZCL_COMMAND_TRAIT_REVERSIBLE |
        ZCL_COMMAND_TRAIT_IDEMPOTENT | ZCL_COMMAND_TRAIT_DRY_RUN |
        ZCL_COMMAND_TRAIT_DEV_ONLY | ZCL_COMMAND_TRAIT_DISPLAY_ONLY |
        ZCL_COMMAND_TRAIT_SECRET_OUTPUT;
    if ((spec->traits & ~(known_traits | ZCL_COMMAND_TRAIT_PROSE)) != 0) {
        if (why)
            snprintf(why, why_size, "unknown command trait for %s", spec->path);
        return false;
    }
    if ((spec->traits & ZCL_COMMAND_TRAIT_DISPLAY_ONLY) != 0 &&
        (spec->effect != ZCL_COMMAND_EFFECT_MUTATE ||
         spec->risk != ZCL_COMMAND_RISK_APP_WRITE ||
         spec->confirmation != ZCL_COMMAND_CONFIRM_NONE ||
         spec->required_capabilities != ZCL_COMMAND_CAP_NONE)) {
        if (why)
            snprintf(why, why_size, "display-only contract conflict for %s",
                     spec->path);
        return false;
    }
    return true;
}

static bool cr_validate_collisions(const struct zcl_command_registry *registry,
                                   const struct zcl_command_spec *spec,
                                   size_t i, char *why, size_t why_size)
{
    for (size_t j = 0; j < i; j++) {
        const struct zcl_command_spec *other = &registry->commands[j];
        if (strcmp(spec->path, other->path) == 0 ||
            command_registry_csv_token_equal(spec->aliases, other->path) ||
            command_registry_csv_token_equal(other->aliases, spec->path)) {
            if (why)
                snprintf(why, why_size, "path/alias collision for %s",
                         spec->path);
            return false;
        }
        const char *at = spec->aliases;
        while (at && *at) {
            const char *end = strchr(at, ',');
            size_t len = end ? (size_t)(end - at) : strlen(at);
            char token[ZCL_COMMAND_MAX_PATH];
            memcpy(token, at, len);
            token[len] = 0;
            if (command_registry_csv_token_equal(other->aliases, token)) {
                if (why)
                    snprintf(why, why_size, "duplicate alias %s", token);
                return false;
            }
            if (!end)
                break;
            at = end + 1;
        }
    }
    return true;
}

static void cr_branch_hold(struct cr_name_table *branches,
                           const struct zcl_command_spec *spec)
{
    uint32_t n;
    if (!branches->usable || !command_registry_is_branch(spec))
        return;
    if (!spec->path || !spec->path[0])
        return;
    n = (uint32_t)strlen(spec->path);
    (void)cr_name_hold(branches, spec->path, n);
}

static void cr_branches_fill(struct cr_name_table *branches,
                             const struct zcl_command_registry *registry)
{
    branches->slots = zcl_calloc((size_t)CR_NAME_CAP, sizeof(branches->slots[0]),
                                 "cr_branch_table");
    branches->usable = branches->slots != NULL;
    if (!branches->usable)
        return;
    for (size_t i = 0; i < registry->count; i++)
        cr_branch_hold(branches, &registry->commands[i]);
}

/* 1 present, 0 absent, -1 scan the registry. */
static int cr_branch_lookup(const struct cr_name_table *branches,
                            const char *parent)
{
    uint32_t n;
    uint32_t slot = 0;
    int found;
    if (!branches || !branches->usable || !branches->slots)
        return -1;
    n = (uint32_t)strlen(parent);
    found = cr_name_probe(branches, parent, n, cr_name_hash(parent, n), &slot);
    return found < 0 ? -1 : found;
}

static bool cr_parent_missing(const struct zcl_command_spec *spec, char *why,
                              size_t why_size)
{
    if (why)
        snprintf(why, why_size, "missing branch parent %s for %s",
                 spec->parent, spec->path);
    return false;
}

static bool cr_validate_parent_exists(
    const struct zcl_command_registry *registry,
    const struct zcl_command_spec *spec, char *why, size_t why_size,
    const struct cr_name_table *branches)
{
    int fast;
    if (!spec->parent || !spec->parent[0])
        return true;
    fast = cr_branch_lookup(branches, spec->parent);
    if (fast == 1)
        return true;
    if (fast == 0)
        return cr_parent_missing(spec, why, why_size);
    for (size_t j = 0; j < registry->count; j++) {
        if (strcmp(registry->commands[j].path, spec->parent) == 0 &&
            command_registry_is_branch(&registry->commands[j]))
            return true;
    }
    return cr_parent_missing(spec, why, why_size);
}

static bool cr_validate_one(const struct zcl_command_registry *registry,
                            const struct zcl_command_spec *spec, size_t i,
                            char *why, size_t why_size,
                            struct cr_name_table *names,
                            const struct cr_name_table *branches)
{
    if (!cr_validate_shape(spec, i, why, why_size))
        return false;
    if (!cr_validate_parent_path(spec, why, why_size))
        return false;
    if (!cr_validate_branch_or_leaf(spec, why, why_size))
        return false;
    if (!cr_validate_budget_reason(spec, why, why_size))
        return false;
    if (!cr_validate_effect_traits(spec, why, why_size))
        return false;
    if (!cr_names_fast_clear(names, spec) &&
        !cr_validate_collisions(registry, spec, i, why, why_size))
        return false;
    return cr_validate_parent_exists(registry, spec, why, why_size, branches);
}

bool zcl_command_registry_validate(const struct zcl_command_registry *registry,
                                   char *why, size_t why_size)
{
    if (why && why_size)
        why[0] = 0;
    if (!registry || !registry->commands || registry->count == 0) {
        if (why)
            snprintf(why, why_size, "empty registry");
        return false;
    }
    struct cr_name_table names = { 0 };
    struct cr_name_table branches = { 0 };
    names.slots = zcl_calloc((size_t)CR_NAME_CAP, sizeof(names.slots[0]),
                             "cr_name_table");
    names.usable = names.slots != NULL;
    cr_branches_fill(&branches, registry);
    bool ok = true;
    for (size_t i = 0; i < registry->count; i++) {
        if (!cr_validate_one(registry, &registry->commands[i], i, why,
                             why_size, &names, &branches)) {
            ok = false;
            break;
        }
    }
    free(names.slots);
    free(branches.slots);
    return ok;
}
