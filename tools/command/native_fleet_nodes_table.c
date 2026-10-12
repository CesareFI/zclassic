/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: fleet.nodes.table - the pairings recorded in this node's pairing
 *          store, grouped by full peer master fingerprint.
 *
 * Read-only and local. The store is opened through the shared read-only seam
 * (never node_db_open), counted and listed inside one read transaction, and
 * closed before the reply is built. Nothing is dialled and nothing is joined
 * from another store.
 *
 * INPUT (zcl.fleet_nodes_table_input.v1)
 *   datadir   optional string; defaults to the CLI's resolved datadir.
 *
 * OUTPUT (zcl.fleet_nodes_table.v1) on ok=true
 *   schema, source, selection, observed_at, pairing_count, node_count,
 *   rows[] {peer_master_fingerprint, pairings[] {pairing_id,
 *   peer_noise_fingerprint, state, capability_mask, delegation_sequence,
 *   paired_at, expires_at, revoked_at, revocation_generation}}
 *
 * One row is one recorded peer master, not proof of one machine. Rows are
 * sorted by full fingerprint; pairings keep the store order (paired_at,
 * pairing_id). Capability masks are reported per pairing and never combined.
 * An existing table with no pairing is a success with zero rows; a missing,
 * corrupt or unreadable store is a refusal.
 *
 * REFUSALS. NODES_TABLE_READ_FAILED, NODES_TABLE_TOO_LARGE (more than 64
 * recorded pairings), NODES_TABLE_DATA_INVALID (a record or count that does
 * not hold together), NODES_TABLE_ALLOC and NODES_TABLE_BUDGET. No row
 * survives a refusal. */

/* budget_bytes in the manifest below equals NODES_TABLE_ENVELOPE_BYTES. */
/* Z23_TOOL_V1
{
  "profile": "readonly-local-v1",
  "path": "fleet.nodes.table",
  "parent": "fleet.nodes",
  "branch_summary": "Inspect the recorded peers",
  "handler": "zcl_native_handle_fleet_nodes_table",
  "summary": "The pairings recorded on this box, grouped by peer master fingerprint",
  "semantics": [
    "Reads the local pairing store through the read-only seam in one ",
    "transaction: at most 64 recorded pairings, each with its state, ",
    "capability mask, delegation sequence and timestamps, grouped under the ",
    "full peer master fingerprint. Active, expired and revoked pairings stay ",
    "distinct, and masks are never combined. A row is a recorded peer ",
    "identity, not proof of a machine or that it is online. An existing empty ",
    "store answers with zero rows; a missing or unreadable store, or more ",
    "than 64 pairings, is refused. It contacts no peer and writes nothing."
  ],
  "input_schema": "zcl.fleet_nodes_table_input.v1",
  "output_schema": "zcl.fleet_nodes_table.v1",
  "input_keys": ["datadir"],
  "example": "z23 fleet nodes table",
  "tags": ["fleet", "nodes", "table", "pairings", "peers", "master",
           "fingerprint", "owner"],
  "authority": "owner",
  "budget_bytes": 65536,
  "latency": "fast",
  "cost": "low",
  "test_group": "fleet_nodes_table"
}
*/

#include "command/native_command.h"
#include "command/native_fleet.h"

#include "models/database.h"
#include "services/mesh_pairing_service.h"

#include "json/json.h"
#include "platform/time_compat.h"

#include <stdint.h>
#include <string.h>

#define NODES_TABLE_MAX MESH_PAIRING_LIST_MAX
/* Equals budget_bytes in the Z23_TOOL_V1 manifest above. */
#define NODES_TABLE_ENVELOPE_BYTES 65536u
#define NODES_TABLE_ENVELOPE_RESERVE 8192u

struct nodes_group {
    struct json_value row;
    struct json_value pairs;
    bool open;
};

static void nodes_fail(struct zcl_command_reply *reply, const char *code,
                       const char *message)
{
    json_free(&reply->data);
    json_init(&reply->data);
    json_set_object(&reply->data);
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                           ZCL_COMMAND_EXIT_FAILED, code, "read", false, false,
                           message, "");
}

static bool nodes_hex64(const char *s)
{
    if (strlen(s) != 64)
        return false;
    for (size_t i = 0; i < 64; i++)
        if (!((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f')))
            return false;
    return true;
}

static bool nodes_state_valid(const char *state)
{
    return strcmp(state, "active") == 0 || strcmp(state, "expired") == 0 ||
           strcmp(state, "revoked") == 0;
}

static bool nodes_view_valid(const struct mesh_pairing_public_view *v)
{
    return nodes_hex64(v->pairing_id) &&
           nodes_hex64(v->peer_master_fingerprint) &&
           nodes_hex64(v->peer_noise_fingerprint) &&
           nodes_state_valid(v->state) && v->capability_mask <= INT64_MAX &&
           v->delegation_sequence <= INT64_MAX &&
           v->revocation_generation <= INT64_MAX;
}

static bool nodes_views_valid(const struct mesh_pairing_public_view *views,
                              size_t count)
{
    for (size_t i = 0; i < count; i++)
        if (!nodes_view_valid(&views[i]))
            return false;
    return true;
}

/* Orders pairing indexes by full master fingerprint, then store position. */
static void nodes_sort(const struct mesh_pairing_public_view *views,
                       size_t count, size_t order[NODES_TABLE_MAX])
{
    for (size_t i = 0; i < count; i++) {
        size_t at = i;
        while (at > 0 &&
               strcmp(views[order[at - 1]].peer_master_fingerprint,
                      views[i].peer_master_fingerprint) > 0) {
            order[at] = order[at - 1];
            at--;
        }
        order[at] = i;
    }
}

static bool nodes_pairing_json(const struct mesh_pairing_public_view *v,
                               struct json_value *out)
{
    json_init(out);
    json_set_object(out);
    return json_push_kv_str(out, "pairing_id", v->pairing_id) &&
           json_push_kv_str(out, "peer_noise_fingerprint",
                            v->peer_noise_fingerprint) &&
           json_push_kv_str(out, "state", v->state) &&
           json_push_kv_int(out, "capability_mask",
                            (int64_t)v->capability_mask) &&
           json_push_kv_int(out, "delegation_sequence",
                            (int64_t)v->delegation_sequence) &&
           json_push_kv_int(out, "paired_at", v->paired_at) &&
           json_push_kv_int(out, "expires_at", v->expires_at) &&
           json_push_kv_int(out, "revoked_at", v->revoked_at) &&
           json_push_kv_int(out, "revocation_generation",
                            (int64_t)v->revocation_generation);
}

static bool nodes_group_start(struct nodes_group *g, const char *master)
{
    json_init(&g->row);
    json_set_object(&g->row);
    json_init(&g->pairs);
    json_set_array(&g->pairs);
    g->open = true;
    return json_push_kv_str(&g->row, "peer_master_fingerprint", master);
}

static bool nodes_group_finish(struct nodes_group *g, struct json_value *rows)
{
    bool ok = true;
    if (g->open)
        ok = json_push_kv(&g->row, "pairings", &g->pairs) &&
             json_push_back(rows, &g->row);
    if (g->open) {
        json_free(&g->pairs);
        json_free(&g->row);
        g->open = false;
    }
    return ok;
}

static bool nodes_group_add(struct nodes_group *g,
                            const struct mesh_pairing_public_view *v)
{
    struct json_value pairing;
    bool ok = nodes_pairing_json(v, &pairing) &&
              json_push_back(&g->pairs, &pairing);
    json_free(&pairing);
    return ok;
}

/* Builds rows[] from the validated views; *nodes is the number of masters. */
static bool nodes_build_rows(const struct mesh_pairing_public_view *views,
                             size_t count, struct json_value *rows,
                             size_t *nodes)
{
    size_t order[NODES_TABLE_MAX];
    struct nodes_group group = { .open = false };
    const char *previous = NULL;
    bool ok = true;

    *nodes = 0;
    nodes_sort(views, count, order);
    for (size_t i = 0; ok && i < count; i++) {
        const struct mesh_pairing_public_view *v = &views[order[i]];
        if (!previous || strcmp(previous, v->peer_master_fingerprint) != 0) {
            ok = nodes_group_finish(&group, rows) &&
                 nodes_group_start(&group, v->peer_master_fingerprint);
            (*nodes)++;
        }
        ok = ok && nodes_group_add(&group, v);
        previous = v->peer_master_fingerprint;
    }
    ok = nodes_group_finish(&group, rows) && ok;
    return ok;
}

static bool nodes_emit(struct zcl_command_reply *reply, int64_t now,
                       const struct mesh_pairing_public_view *views,
                       size_t count)
{
    struct json_value rows;
    size_t nodes = 0;
    json_init(&rows);
    json_set_array(&rows);
    bool ok = nodes_build_rows(views, count, &rows, &nodes) &&
              json_push_kv_str(&reply->data, "schema",
                               "zcl.fleet_nodes_table.v1") &&
              json_push_kv_str(&reply->data, "source", "local_pairing_store") &&
              json_push_kv_str(&reply->data, "selection", "recorded_pairings") &&
              json_push_kv_int(&reply->data, "observed_at", now) &&
              json_push_kv_int(&reply->data, "pairing_count", (int64_t)count) &&
              json_push_kv_int(&reply->data, "node_count", (int64_t)nodes) &&
              json_push_kv(&reply->data, "rows", &rows);
    json_free(&rows);
    return ok;
}

/* Reads the counts and the listing inside one read transaction. */
static bool nodes_read(struct node_db *ndb, int64_t now,
                       struct mesh_pairing_public_view *views, size_t *count,
                       struct db_mesh_pairing_counts *counts)
{
    if (!node_db_begin(ndb))
        return false;
    bool ok = mesh_pairing_service_list_after(ndb, now, 0, views,
                                              NODES_TABLE_MAX, count, counts);
    (void)node_db_rollback(ndb);
    return ok;
}

static const char *nodes_datadir(const struct zcl_command_request *request)
{
    const struct json_value *arg =
        request && request->input ? json_get(request->input, "datadir") : NULL;
    const char *datadir = arg && arg->type == JSON_STR ? json_get_str(arg) : NULL;
    return datadir && datadir[0] ? datadir : zcl_native_command_datadir();
}

/* Refuses unless the listing is exactly the counted table and fits. */
static bool nodes_checked(struct zcl_command_reply *reply,
                          const struct mesh_pairing_public_view *views,
                          size_t count,
                          const struct db_mesh_pairing_counts *counts)
{
    if (counts->total > (int64_t)NODES_TABLE_MAX) {
        nodes_fail(reply, "NODES_TABLE_TOO_LARGE",
                   "more than 64 pairings are recorded; page them with "
                   "ops.mesh.roster");
        return false;
    }
    if (counts->total < 0 || (size_t)counts->total != count ||
        !nodes_views_valid(views, count)) {
        nodes_fail(reply, "NODES_TABLE_DATA_INVALID",
                   "the pairing store did not return a consistent table");
        return false;
    }
    return true;
}

static bool nodes_within_budget(struct zcl_command_reply *reply)
{
    size_t bytes = json_write(&reply->data, NULL, 0);
    if (bytes + NODES_TABLE_ENVELOPE_RESERVE <= NODES_TABLE_ENVELOPE_BYTES)
        return true;
    nodes_fail(reply, "NODES_TABLE_BUDGET",
               "the table does not fit the reply envelope");
    return false;
}

void zcl_native_handle_fleet_nodes_table(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    struct mesh_pairing_public_view views[NODES_TABLE_MAX];
    struct db_mesh_pairing_counts counts = {0};
    struct node_db ndb;
    sqlite3 *db = NULL;
    size_t count = 0;

    if (!reply)
        return;
    if (!zcl_native_node_db_require_readonly(nodes_datadir(request), reply,
                                             "the mesh pairing store", &db,
                                             &ndb))
        return;
    int64_t now = platform_time_wall_unix();
    bool read = nodes_read(&ndb, now, views, &count, &counts);
    zcl_native_node_db_close_readonly(&db, &ndb);
    if (!read) {
        nodes_fail(reply, "NODES_TABLE_READ_FAILED",
                   "the mesh pairing store could not be read");
        return;
    }
    if (!nodes_checked(reply, views, count, &counts))
        return;
    if (!nodes_emit(reply, now, views, count)) {
        nodes_fail(reply, "NODES_TABLE_ALLOC",
                   "the table could not be built");
        return;
    }
    (void)nodes_within_budget(reply);
}
