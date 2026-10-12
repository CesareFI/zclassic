/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Registry-driven discovery for the `dev` tree (Wave 2.2). These two entry
 * points used to walk a hardcoded node table; they now delegate to the single
 * canonical command registry (engine/composition/src/command_catalog.c via
 * engine/modules/kernel/command_registry). The registry owns the dev subtree's shape,
 * summaries, availability, and budgets, so menu/help/search here can never
 * drift from the leaves the dispatcher actually serves.
 *
 * Only menu/help/search are registry-driven; the devloop DISPATCH
 * (cycle/watch/focused/status) stays in tools/dev/devloop_cli.c. This file is
 * read-only and release-safe. */

#include "devloop.h"

#include "config/command_catalog.h"
#include "kernel/command_registry.h"
#include "json/json.h"
#include "zutf8/zutf8.h"

#include <stdio.h>
#include <string.h>

/* Count the serialized bytes without entering the writer on truncation. */
static bool unknown_path_fits(const char *path, size_t capacity)
{
    size_t needed = sizeof("{\"schema\":\"zcl.command_menu.v1\","
                           "\"error\":\"unknown_path\",\"path\":\"\","
                           "\"agent_next_action\":"
                           "\"z23-dev dev search <intent>\"}") - 1;
    if (needed >= capacity)
        return false;
    for (const unsigned char *p = (const unsigned char *)path; *p; p++) {
        size_t extra = 1;
        if (strchr("\"\\\010\f\n\r\t", *p))
            extra = 2;
        else if (*p < 0x20)
            extra = 6;
        if (extra >= capacity - needed)
            return false;
        needed += extra;
    }
    return true;
}

/* Emit the compact unknown-path error document. Keeps the `"error"` marker the
 * devloop CLI uses to map an unknown branch to a non-zero exit code. */
static size_t emit_unknown_path(const char *path, char *out, size_t out_sz)
{
    const char *wanted = path && path[0] ? path : "dev";
    out[0] = '\0';
    if (!zutf8_validate(wanted))
        return 0; /* Invalid encoding is refused without a partial document. */
    if (!unknown_path_fits(wanted, out_sz))
        return 0;
    struct json_value doc;
    json_init(&doc);
    json_set_object(&doc);
    bool ok = json_push_kv_str(&doc, "schema", "zcl.command_menu.v1") &&
              json_push_kv_str(&doc, "error", "unknown_path") &&
              json_push_kv_str(&doc, "path", wanted) &&
              json_push_kv_str(&doc, "agent_next_action",
                               "z23-dev dev search <intent>");
    const char *keys[] = { "schema", "error", "path", "agent_next_action" };
    for (size_t i = 0; ok && i < sizeof(keys) / sizeof(keys[0]); i++) {
        const struct json_value *v = json_get(&doc, keys[i]);
        ok = v && v->type == JSON_STR; /* Refuse allocation degradation. */
    }
    size_t n = ok ? json_write(&doc, out, out_sz) : 0;
    json_free(&doc);
    if (!n || n >= out_sz) {
        out[0] = '\0';
        return 0;
    }
    return n;
}

size_t zcl_devloop_menu_json(const char *path, char *out, size_t out_sz)
{
    if (!out || out_sz == 0)
        return 0;
    const char *wanted = (path && path[0]) ? path : "dev";
    const struct zcl_command_registry *reg = zcl_command_catalog();
    /* menu_json renders a branch menu, or transparently the leaf spec when the
     * path resolves to a leaf; 0 means no such path (or a budget overflow). */
    size_t n = zcl_command_registry_menu_json(reg, wanted, out, out_sz);
    if (n == 0)
        return emit_unknown_path(wanted, out, out_sz);
    return n;
}

size_t zcl_devloop_menu_search_json(const char *query, char *out, size_t out_sz)
{
    if (!out || out_sz == 0 || !query || !query[0])
        return 0;
    const struct zcl_command_registry *reg = zcl_command_catalog();
    size_t n = zcl_command_registry_search_json(reg, query, out, out_sz);
    if (n == 0) {
        int m = snprintf(out, out_sz,
                         "{\"schema\":\"zcl.command_search.v1\",\"query\":\"\","
                         "\"matches\":[],\"count\":0,\"total_matches\":0,"
                         "\"truncated\":false}");
        if (m <= 0 || (size_t)m >= out_sz)
            return 0;
        return (size_t)m;
    }
    return n;
}
