/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Read signed historical VITALS rows without loading private keys. */
/* Z23_TOOL_V1
{
  "profile": "readonly-local-v1",
  "path": "fleet.vitals.history",
  "parent": "fleet.vitals",
  "handler": "zcl_native_handle_fleet_vitals_history",
  "summary": "Read a verified sequence page of recorded vitals",
  "semantics": [
    "Reads one box's recorded VITALS in ascending sequence order, not clock order. ",
    "The page scans at most 64 sequence positions; verifying the entire local ",
    "ledger is not bounded by 64. No key, row, directory or service is created. ",
    "Signature and chain verification do not establish delegated identity or ",
    "current pairing authority. Missing measurements are null, not zero."
  ],
  "input_schema": "zcl.fleet_vitals_history.input.v1",
  "output_schema": "zcl.fleet_vitals_history.v1",
  "input_keys": ["box", "metric", "after_seq", "limit", "datadir"],
  "example": "z23 fleet vitals history --box=<64-lowercase-hex>",
  "tags": ["fleet", "vitals", "history"],
  "authority": "operator",
  "budget_bytes": 65536,
  "latency": "foreground",
  "cost": "low",
  "test_group": "fleet_vitals_history"
}
*/
#include "command/native_command.h"
#include "command/native_fleet.h"
#include "base/hex.h"
#include "fleetledger/fleet_ledger.h"
#include "json/json.h"
#include "platform/time_compat.h"
#include "vcs/zcode_dht_identity.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>

struct history_input {
    uint8_t box[32];
    int subject;
    uint64_t after;
    size_t limit;
};

static const char *history_datadir(const struct zcl_command_request *request)
{
    const struct json_value *v = json_get(request->input, "datadir");
    if (!v) return zcl_native_command_datadir();
    return v->type == JSON_STR ? json_get_str(v) : NULL;
}

static void history_refuse(struct zcl_command_reply *reply, const char *code,
                           const char *why)
{
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
        ZCL_COMMAND_EXIT_FAILED, code, "history", false, false, why, "");
}

static bool history_number(const struct json_value *input, const char *key,
                            int64_t fallback, int64_t max, int64_t *out)
{
    const struct json_value *v = json_get(input, key);
    *out = fallback;
    if (!v) return true;
    if (v->type != JSON_INT) return false;
    *out = json_get_int(v);
    return *out >= 0 && *out <= max;
}

static bool history_input_parse(const struct zcl_command_request *request,
                                 struct history_input *out)
{
    const struct json_value *input = request ? request->input : NULL;
    if (!input || input->type != JSON_OBJ) return false;
    const struct json_value *box = json_get(input, "box");
    const char *hex = box && box->type == JSON_STR ? json_get_str(box) : NULL;
    if (!hex || strlen(hex) != 64 || !zcl_hex_decode_lower(hex, out->box, 32))
        return false;
    out->subject = -1;
    const struct json_value *metric = json_get(input, "metric");
    if (metric) {
        uint16_t subject = 0;
        if (metric->type != JSON_STR || !zcl_fleet_subject_from_name(
            ZCL_FLEET_KIND_VITALS, json_get_str(metric), &subject)) return false;
        out->subject = subject;
    }
    int64_t after = 0, limit = 64;
    if (!history_number(input, "after_seq", 0, INT64_MAX, &after) ||
        !history_number(input, "limit", 64, 64, &limit) || limit == 0)
        return false;
    out->after = (uint64_t)after;
    out->limit = (size_t)limit;
    return true;
}

static bool history_null(struct json_value *out, const char *key)
{
    struct json_value null = {0};
    json_set_null(&null);
    return json_push_kv(out, key, &null);
}

/* Subtraction is unsigned after ordering, so even INT64_MIN cannot overflow.
 * A negative wall timestamp is retained but has unknown freshness. */
static bool history_age(struct json_value *out, int64_t timestamp, int64_t now)
{
    const char *state = "unknown";
    bool age_known = timestamp >= 0 && now >= timestamp;
    if (timestamp >= 0 && now >= 0) state = timestamp > now ? "future" : "observed";
    if (!json_push_kv_str(out, "freshness", state)) return false;
    if (age_known)
        return json_push_kv_int(out, "age_s", (int64_t)((uint64_t)now - (uint64_t)timestamp));
    return history_null(out, "age_s");
}

static bool history_row_json(struct json_value *rows,
                              const struct zcl_fleet_row *r, int64_t now)
{
    char signer[65];
    zcl_hex_encode(r->signer, 32, signer);
    struct json_value row = {0};
    json_set_object(&row);
    bool ok = json_push_kv_int(&row, "seq", (int64_t)r->seq) &&
        json_push_kv_int(&row, "timestamp", r->ts_unix) &&
        json_push_kv_str(&row, "signer", signer) &&
        json_push_kv_str(&row, "metric", zcl_fleet_vital_id(r->subject)) &&
        history_age(&row, r->ts_unix, now);
    ok = ok && json_push_kv_str(&row, "unit", zcl_fleet_vital_unit(r->subject)) &&
        json_push_kv_int(&row, "cadence_s", zcl_fleet_vital_cadence_s(r->subject));
    bool present = false;
    for (size_t i = 0; i < r->pair_count; i++) {
        if (r->pair[i].key != ZCL_FLEET_PAIR_VALUE) continue;
        present = true;
        ok = ok && json_push_kv_int(&row, "value", r->pair[i].value);
    }
    if (!present) ok = ok && history_null(&row, "value");
    ok = ok && json_push_kv_bool(&row, "present", present) && json_push_back(rows, &row);
    json_free(&row);
    return ok;
}

static bool history_provenance(struct json_value *data, bool have_self)
{
    return json_push_kv_str(data, "order", "sequence_ascending") &&
        json_push_kv_str(data, "verification", "signature_chain_only") &&
        json_push_kv_str(data, "delegation", "not_evaluated") &&
        json_push_kv_str(data, "freshness_acceptance", "not_evaluated") &&
        json_push_kv_bool(data, "self_identity_available", have_self) &&
        json_push_kv_str(data, "coverage", have_self ? "self_and_peer_chains" : "peer_chains_only") &&
        json_push_kv_bool(data, "full_replay_bounded_by_page", false);
}

static bool history_render(struct json_value *data,
                             const struct zcl_fleet_vitals_history *page,
                             const struct history_input *input, bool have_self)
{
    char hash[65], box[65];
    zcl_hex_encode(page->snapshot_hash, 32, hash);
    zcl_hex_encode(input->box, 32, box);
    struct json_value rows = {0};
    json_set_array(&rows);
    int64_t now = (int64_t)platform_time_wall_time_t();
    bool ok = true;
    for (size_t i = 0; ok && i < page->count; i++)
        ok = history_row_json(&rows, &page->rows[i], now);
    ok = ok && json_push_kv(data, "rows", &rows);
    json_free(&rows);
    return ok && json_push_kv_int(data, "observed_at", now) &&
        json_push_kv_str(data, "box", box) &&
        json_push_kv_bool(data, "found", page->found) &&
        json_push_kv_bool(data, "more", page->more) &&
        json_push_kv_int(data, "next_seq", (int64_t)page->next_seq) &&
        json_push_kv_int(data, "snapshot_head", (int64_t)page->snapshot_head) &&
        json_push_kv_str(data, "snapshot_hash", hash) && history_provenance(data, have_self);
}

void zcl_native_handle_fleet_vitals_history(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!reply) return;
    zcl_command_reply_init(reply, "zcl.fleet_vitals_history.v1");
    struct history_input input;
    if (!history_input_parse(request, &input)) {
        history_refuse(reply, "HISTORY_INPUT", "box, metric, after_seq or limit is invalid");
        return;
    }
    const char *datadir = history_datadir(request);
    char dir[512];
    if (!datadir || datadir[0] != '/' ||
        (size_t)snprintf(dir, sizeof dir, "%s/fleet_ledger", datadir) >= sizeof dir) {
        history_refuse(reply, "HISTORY_DATADIR", "an absolute bounded datadir is required");
        return;
    }
    struct vcs_zcode_dht_delegation delegation;
    char error[160];
    bool have_self = vcs_zcode_dht_delegation_load(datadir, &delegation, error, sizeof error);
    struct zcl_fleet_report report;
    struct zcl_fleet_vitals_history page;
    enum zcl_fleet_status status = zcl_fleet_ledger_vitals_history_readonly(
        dir, have_self ? delegation.doc.master_pubkey : NULL,
        have_self ? delegation.online_pubkey : NULL, input.box, input.subject,
        input.after, input.limit, &page, &report);
    if (status != ZCL_FLEET_OK) {
        history_refuse(reply, "HISTORY_LEDGER", zcl_fleet_status_label(status));
        return;
    }
    if (page.next_seq > INT64_MAX || page.snapshot_head > INT64_MAX) {
        history_refuse(reply, "HISTORY_SEQUENCE_RANGE", "sequence exceeds JSON signed integer range");
        return;
    }
    if (!history_render(&reply->data, &page, &input, have_self)) {
        history_refuse(reply, "HISTORY_ALLOC", "history response allocation failed");
        return;
    }
    reply->status = ZCL_COMMAND_STATUS_PASSED;
    reply->exit_code = ZCL_COMMAND_EXIT_OK;
}
