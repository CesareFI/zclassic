/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: plugin.install, plugin.list, plugin.switch and plugin.rollback —
 *          the signed plugin store under ~/.z23/plugins. Every refusal
 *          carries a stable PLUGIN_* code and the command that resolves it.
 *          The daemon is not contacted. */

#include "command/native_command.h"

#include "json/json.h"
#include "plugin/plugin_store.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void plg_refuse(struct zcl_command_reply *reply, enum plugin_status st,
                       const char *what, const char *evidence)
{
    char message[192];
    (void)snprintf(message, sizeof(message), "plugin %s refused: %s", what,
                   plugin_status_code(st));
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                           st == PLUGIN_ERR_IO ? ZCL_COMMAND_EXIT_FAILED
                                               : ZCL_COMMAND_EXIT_INVALID,
                           plugin_status_code(st), what, false, false, message,
                           evidence ? evidence : "");
    (void)snprintf(reply->error.next_action, sizeof(reply->error.next_action),
                   "%s", plugin_status_next_action(st));
    reply->error.human_action_required = true;
}

static const char *plg_str(const struct zcl_command_request *request,
                           const char *key)
{
    const struct json_value *v = request->input ? json_get(request->input, key)
                                                : NULL;
    return v && v->type == JSON_STR ? json_get_str(v) : NULL;
}

static bool plg_root(char *out, size_t cap)
{
    const char *home = getenv("HOME");
    if (!home || home[0] != '/')
        return false;
    int n = snprintf(out, cap, "%s/.z23/plugins", home);
    return n > 0 && (size_t)n < cap;
}

static bool plg_begin(const struct zcl_command_request *request,
                      struct zcl_command_reply *reply, const char *what,
                      char *root, size_t cap)
{
    if (!request || !reply)
        return false;
    if (!plg_root(root, cap)) {
        plg_refuse(reply, PLUGIN_ERR_ARGUMENT, what, "HOME is not absolute");
        return false;
    }
    return true;
}

static void plg_push_capabilities(struct json_value *obj, unsigned mask)
{
    struct json_value caps;
    json_init(&caps);
    json_set_array(&caps);
    for (unsigned i = 0; plugin_capability_name(i); i++) {
        struct json_value s;
        json_init(&s);
        if (mask & (1u << i)) {
            json_set_str(&s, plugin_capability_name(i));
            (void)json_push_back(&caps, &s);
        }
        json_free(&s);
    }
    (void)json_push_kv(obj, "capabilities", &caps);
    json_free(&caps);
}

void zcl_native_handle_plugin_install(const struct zcl_command_request *request,
                                      struct zcl_command_reply *reply)
{
    char root[PATH_MAX];
    if (!plg_begin(request, reply, "install", root, sizeof(root)))
        return;
    const char *path = plg_str(request, "manifest");
    struct plugin_manifest m;
    int present = 0;
    enum plugin_status st = plugin_store_install(root, path, &m, &present);
    if (st != PLUGIN_OK) {
        plg_refuse(reply, st, "install", path);
        return;
    }
    json_set_object(&reply->data);
    (void)json_push_kv_str(&reply->data, "schema", "zcl.plugin_install.v1");
    (void)json_push_kv_str(&reply->data, "name", m.name);
    (void)json_push_kv_str(&reply->data, "version", m.version);
    (void)json_push_kv_int(&reply->data, "interface_version", m.interface_version);
    (void)json_push_kv_str(&reply->data, "generation", m.exe_sha3);
    (void)json_push_kv_bool(&reply->data, "already_present", present != 0);
    plg_push_capabilities(&reply->data, m.capabilities);
    reply->error.mutated = present == 0;
    char input[256];
    (void)snprintf(input, sizeof(input), "{\"name\":\"%s\",\"generation\":\"%s\"}",
                   m.name, m.exe_sha3);
    (void)zcl_command_reply_add_next(reply, "plugin.switch", input,
                                     "make this generation current");
}

static void plg_push_info(struct json_value *plugins, const struct plugin_info *info)
{
    struct json_value row, gens;
    json_init(&row);
    json_init(&gens);
    json_set_object(&row);
    json_set_array(&gens);
    (void)json_push_kv_str(&row, "name", info->name);
    (void)json_push_kv_str(&row, "current", info->current);
    (void)json_push_kv_str(&row, "last_good", info->last_good);
    for (size_t g = 0; g < info->generation_count; g++) {
        struct json_value s;
        json_init(&s);
        json_set_str(&s, info->generations[g]);
        (void)json_push_back(&gens, &s);
        json_free(&s);
    }
    (void)json_push_kv(&row, "generations", &gens);
    (void)json_push_back(plugins, &row);
    json_free(&gens);
    json_free(&row);
}

void zcl_native_handle_plugin_list(const struct zcl_command_request *request,
                                   struct zcl_command_reply *reply)
{
    char root[PATH_MAX];
    if (!plg_begin(request, reply, "list", root, sizeof(root)))
        return;
    struct plugin_info *infos = NULL;
    size_t count = 0;
    enum plugin_status st = plugin_store_list(root, &infos, &count);
    if (st != PLUGIN_OK) {
        plg_refuse(reply, st, "list", root);
        return;
    }
    struct json_value plugins;
    json_init(&plugins);
    json_set_array(&plugins);
    for (size_t i = 0; i < count; i++)
        plg_push_info(&plugins, &infos[i]);
    json_set_object(&reply->data);
    (void)json_push_kv_str(&reply->data, "schema", "zcl.plugin_list.v1");
    (void)json_push_kv_int(&reply->data, "count", (int64_t)count);
    (void)json_push_kv(&reply->data, "plugins", &plugins);
    json_free(&plugins);
    plugin_store_list_free(infos, count);
}

void zcl_native_handle_plugin_switch(const struct zcl_command_request *request,
                                     struct zcl_command_reply *reply)
{
    char root[PATH_MAX];
    if (!plg_begin(request, reply, "switch", root, sizeof(root)))
        return;
    const char *name = plg_str(request, "name");
    const char *generation = plg_str(request, "generation");
    enum plugin_status st = plugin_store_switch(root, name, generation);
    if (st != PLUGIN_OK) {
        plg_refuse(reply, st, "switch", name);
        return;
    }
    json_set_object(&reply->data);
    (void)json_push_kv_str(&reply->data, "schema", "zcl.plugin_switch.v1");
    (void)json_push_kv_str(&reply->data, "name", name);
    (void)json_push_kv_str(&reply->data, "current", generation);
    reply->error.mutated = true;
}

void zcl_native_handle_plugin_rollback(const struct zcl_command_request *request,
                                       struct zcl_command_reply *reply)
{
    char root[PATH_MAX], restored[PLUGIN_HEX_SHA3_512 + 1];
    if (!plg_begin(request, reply, "rollback", root, sizeof(root)))
        return;
    const char *name = plg_str(request, "name");
    enum plugin_status st = plugin_store_rollback(root, name, restored);
    if (st != PLUGIN_OK) {
        plg_refuse(reply, st, "rollback", name);
        return;
    }
    json_set_object(&reply->data);
    (void)json_push_kv_str(&reply->data, "schema", "zcl.plugin_rollback.v1");
    (void)json_push_kv_str(&reply->data, "name", name);
    (void)json_push_kv_str(&reply->data, "current", restored);
    reply->error.mutated = true;
}
