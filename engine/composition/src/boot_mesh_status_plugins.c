/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: The "plugins" block of the mesh-status capsule: which signed
 * plugins this machine has installed and which generation is current. Read
 * only, from the responder's own HOME store, with no lock held. The block can
 * only ever be shed to protect the identity capsule, never displace it. */

#include "config/boot_mesh_status.h"
#include "boot_mesh_status_internal.h"

#include "json/json.h"
#include "plugin/plugin_store.h"
#include "session/mesh_status_proto.h"
#include "platform/time_compat.h"
#include "util/log_macros.h"
#include "util/sync.h"
#include "util/util.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

/* Same derivation as the plugin CLI (plg_root): an absolute HOME, then
 * HOME/.z23/plugins, so the node and the operator read one store. */
static bool plugins_root(const char *home, char *out, size_t cap)
{
    if (!home || home[0] != '/')
        return false;
    int n = snprintf(out, cap, "%s/.z23/plugins", home);
    return n > 0 && (size_t)n < cap;
}

static void plugins_prefix(char out[MESH_STATUS_PLUGIN_PREFIX + 1],
                           const char *id)
{
    size_t n = strnlen(id, MESH_STATUS_PLUGIN_PREFIX);
    memcpy(out, id, n);
    out[n] = '\0';
}

void mesh_status_plugins_read(const char *home,
                              struct mesh_status_plugins *out)
{
    memset(out, 0, sizeof(*out));
    char root[PATH_MAX];
    if (!plugins_root(home, root, sizeof(root))) {
        out->reason = "home_unset";
        return;
    }
    struct stat st;
    if (stat(root, &st) != 0) {
        out->reason = errno == ENOENT ? "store_absent" : "store_unreadable";
        return;
    }
    struct plugin_info *infos = NULL;
    size_t count = 0;
    if (!S_ISDIR(st.st_mode) ||
        plugin_store_list(root, &infos, &count) != PLUGIN_OK) {
        out->reason = "store_unreadable";
        return;
    }
    out->available = true;
    out->count = count;
    out->listed = count < MESH_STATUS_PLUGINS_MAX_ITEMS
                      ? count : MESH_STATUS_PLUGINS_MAX_ITEMS;
    for (size_t i = 0; i < out->listed; i++) {
        snprintf(out->items[i].name, sizeof(out->items[i].name), "%s",
                 infos[i].name);
        plugins_prefix(out->items[i].current, infos[i].current);
        plugins_prefix(out->items[i].last_good, infos[i].last_good);
    }
    plugin_store_list_free(infos, count);
}

static bool plugins_json(const struct mesh_status_plugins *p, size_t items,
                         struct json_value *out)
{
    json_set_object(out);
    bool ok = json_push_kv_str(out, "schema", "zcl.mesh_status_plugins.v1") &&
              json_push_kv_bool(out, "available", p->available);
    if (ok && !p->available)
        ok = json_push_kv_str(out, "reason", p->reason ? p->reason
                                                       : "store_unreadable");
    if (ok) {
        struct json_value arr;
        json_init(&arr);
        json_set_array(&arr);
        ok = json_push_kv_int(out, "count", (int64_t)p->count) &&
             json_push_kv_int(out, "listed", (int64_t)items) &&
             json_push_kv_bool(out, "truncated", items < p->count);
        for (size_t i = 0; ok && i < items; i++) {
            struct json_value row;
            json_init(&row);
            json_set_object(&row);
            ok = json_push_kv_str(&row, "name", p->items[i].name) &&
                 json_push_kv_str(&row, "current", p->items[i].current) &&
                 json_push_kv_str(&row, "last_good", p->items[i].last_good) &&
                 json_push_back(&arr, &row);
            json_free(&row);
        }
        ok = ok && json_push_kv(out, "items", &arr);
        json_free(&arr);
    }
    return ok;
}

/* Render the plugins block with `items` rows into buf; returns its length or
 * 0 when it cannot be rendered or does not fit. */
static size_t plugins_text(const struct mesh_status_plugins *p, size_t items,
                           char *buf, size_t cap)
{
    struct json_value obj;
    json_init(&obj);
    size_t n = 0;
    if (plugins_json(p, items, &obj)) {
        n = json_write(&obj, NULL, 0);
        if (n == 0 || n >= cap || json_write(&obj, buf, cap) != n)
            n = 0;
    }
    json_free(&obj);
    return n;
}

bool mesh_status_capsule_with_plugins(const char *base, size_t base_len,
                                      const struct mesh_status_plugins *p,
                                      uint8_t out[MESH_STATUS_CAPSULE_MAX],
                                      size_t *out_len)
{
    *out_len = 0;
    if (!base || base_len < 2 || base_len > MESH_STATUS_CAPSULE_MAX ||
        base[base_len - 1] != '}')
        LOG_FAIL("net.mesh_status", "capsule base is not a JSON object");
    memcpy(out, base, base_len);
    *out_len = base_len;
    if (!p)
        return true;
    static const char key[] = ",\"plugins\":";
    bool empty_base = base_len == 2; /* "{}" takes no leading comma */
    size_t lead = empty_base ? sizeof(key) - 2 : sizeof(key) - 1;
    char local[MESH_STATUS_CAPSULE_MAX + 1];
    for (size_t items = p->available ? p->listed : 0;; items--) {
        size_t n = plugins_text(p, items, local, sizeof(local));
        if (n != 0 && base_len - 1 + lead + n + 1 <= MESH_STATUS_CAPSULE_MAX) {
            size_t off = base_len - 1;
            memcpy(out + off, key + (empty_base ? 1 : 0), lead);
            off += lead;
            memcpy(out + off, local, n);
            off += n;
            out[off++] = '}';
            *out_len = off;
            return true;
        }
        if (items == 0)
            break;
    }
    return true; /* nothing fits: the old capsule, byte for byte */
}

/* ── Cache: the responder never touches the store ────────────────────────
 * -meshstatusplugins (default off) arms the lane. The status responder runs
 * on the p2p message path, so it only copies this snapshot under a short
 * mutex; the supervised refresh tick (boot_mesh_status_refresh.c) re-reads
 * the store at most once per MESH_STATUS_PLUGINS_REFRESH_S. */

static zcl_mutex_t g_plugins_lock;
static zcl_once_t g_plugins_once = ZCL_ONCE_INIT;
static struct mesh_status_plugins g_plugins_cache;
static int64_t g_plugins_last;

static void plugins_lock_init(void)
{
    zcl_mutex_init(&g_plugins_lock);
}

static void plugins_lock(void)
{
    (void)zcl_once_call(&g_plugins_once, plugins_lock_init);
    zcl_mutex_lock(&g_plugins_lock);
}

bool mesh_status_plugins_enabled(void)
{
    return GetBoolArg("-meshstatusplugins", false);
}

void mesh_status_plugins_cache_set(const struct mesh_status_plugins *snapshot,
                                   int64_t now)
{
    plugins_lock();
    g_plugins_cache = *snapshot;
    g_plugins_last = now;
    zcl_mutex_unlock(&g_plugins_lock);
}

void mesh_status_plugins_cache_reset(void)
{
    plugins_lock();
    memset(&g_plugins_cache, 0, sizeof(g_plugins_cache));
    g_plugins_last = 0;
    zcl_mutex_unlock(&g_plugins_lock);
}

void mesh_status_plugins_cache_snapshot(struct mesh_status_plugins *out)
{
    plugins_lock();
    *out = g_plugins_cache;
    zcl_mutex_unlock(&g_plugins_lock);
    if (!out->available && !out->reason)
        out->reason = "not_yet_read";
}

void mesh_status_plugins_cache_refresh(const char *home, int64_t now)
{
    if (now <= 0 || !mesh_status_plugins_enabled())
        return;
    plugins_lock();
    int64_t last = g_plugins_last;
    zcl_mutex_unlock(&g_plugins_lock);
    if (last != 0 && now >= last && now - last < MESH_STATUS_PLUGINS_REFRESH_S)
        return;
    struct mesh_status_plugins fresh;
    mesh_status_plugins_read(home, &fresh); /* file I/O, no lock held */
    mesh_status_plugins_cache_set(&fresh, now);
}

void mesh_status_plugins_cache_tick(void)
{
    mesh_status_plugins_cache_refresh(getenv("HOME"),
                                      (int64_t)platform_time_wall_time_t());
}

void mesh_status_capsule_finish(const char *base, size_t base_len,
                                uint8_t out[MESH_STATUS_CAPSULE_MAX],
                                size_t *out_len)
{
    if (mesh_status_plugins_enabled()) {
        struct mesh_status_plugins snapshot;
        mesh_status_plugins_cache_snapshot(&snapshot);
        if (mesh_status_capsule_with_plugins(base, base_len, &snapshot, out,
                                             out_len))
            return;
    }
    memcpy(out, base, base_len);
    *out_len = base_len;
}
