/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: registered VITALS history reads with public delegation only. */
#include "test/test_core.h"
#include "base/hex.h"
#include "base/safe_alloc.h"
#include "chainlog/chainlog.h"
#include "command/native_command.h"
#include "command/native_fleet.h"
#include "config/command_catalog.h"
#include "controllers/agent_impact_rules.h"
#include "crypto/ed25519.h"
#include "fleetledger/fleet_ledger.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "sha3/sha3.h"
#include "vcs/zcode_dht_identity.h"
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

struct vh_fixture {
    char datadir[512];
    char ledger_dir[640];
    char box_hex[65];
    uint8_t online_seed[32];
    struct vcs_zcode_dht_delegation delegation;
};
static char vh_wire[65536];

static bool vh_fixture_make(struct vh_fixture *f)
{
    uint8_t master_seed[32] = {0x41}, online[32], secret[32];
    uint8_t genesis[32] = {0x42}, noise[32] = {0x43}, beacon[32] = {0x44};
    f->online_seed[0] = 0x45;
    zcl_ed25519_keypair(online, secret, f->online_seed);
    if (!test_mkdtemp(f->datadir, sizeof f->datadir, "vitals_history")) return false;
    if (vcs_zcode_dht_delegation_sign(&f->delegation, genesis, online, noise,
        1, beacon, 1, 4000, 1, master_seed) != VCS_ZCODE_DHT_DELEGATION_OK)
        return false;
    char error[160];
    if (!vcs_zcode_dht_delegation_save(f->datadir, &f->delegation, error, sizeof error))
        return false;
    zcl_hex_encode(f->delegation.doc.master_pubkey, 32, f->box_hex);
    return (size_t)snprintf(f->ledger_dir, sizeof f->ledger_dir,
        "%s/fleet_ledger", f->datadir) < sizeof f->ledger_dir;
}

static bool vh_rows_make(struct vh_fixture *f)
{
    struct zcl_fleet_report report;
    struct zcl_fleet_ledger *l = zcl_fleet_ledger_open(f->ledger_dir,
        f->delegation.doc.master_pubkey, f->delegation.online_pubkey, &report);
    if (!l) return false;
    uint16_t subject = 0;
    bool ok = zcl_fleet_subject_from_name(ZCL_FLEET_KIND_VITALS, "box.load1", &subject);
    struct zcl_fleet_pair zero = {ZCL_FLEET_PAIR_VALUE, 0};
    if (ok) ok = zcl_fleet_ledger_append(l, ZCL_FLEET_KIND_VITALS, subject,
        &zero, 1, NULL, NULL, f->online_seed, NULL) == ZCL_FLEET_OK;
    if (ok) ok = zcl_fleet_ledger_append(l, ZCL_FLEET_KIND_VITALS, subject,
        NULL, 0, NULL, NULL, f->online_seed, NULL) == ZCL_FLEET_OK;
    zcl_fleet_ledger_close(l);
    return ok;
}

static bool vh_raw_tail(struct vh_fixture *f, int64_t timestamp, bool valid)
{
    struct zcl_fleet_vitals_history page;
    struct zcl_fleet_report report;
    if (zcl_fleet_ledger_vitals_history_readonly(f->ledger_dir,
        f->delegation.doc.master_pubkey, f->delegation.online_pubkey,
        f->delegation.doc.master_pubkey, -1, 0, 64, &page, &report) != ZCL_FLEET_OK)
        return false;
    if (!page.count || page.snapshot_head == UINT64_MAX) return false;
    struct zcl_fleet_row row = page.rows[0];
    row.seq = page.snapshot_head + 1;
    row.ts_unix = timestamp;
    memcpy(row.prev_hash, page.snapshot_hash, sizeof row.prev_hash);
    if (zcl_fleet_row_sign(&row, f->online_seed) != ZCL_FLEET_OK) return false;
    if (!valid) row.sig[0] ^= 1;
    uint8_t bytes[ZCL_FLEET_ROW_MAX_BYTES], stream[32];
    size_t n = zcl_fleet_row_encode(&row, bytes, sizeof bytes);
    struct sha3_256_ctx hash;
    sha3_256_init(&hash);
    sha3_256_write(&hash, (const unsigned char *)"zcl.fleet_ledger.chain.v1",
                   sizeof("zcl.fleet_ledger.chain.v1"));
    sha3_256_write(&hash, f->delegation.doc.master_pubkey, 32);
    sha3_256_finalize(&hash, stream);
    char path[768];
    if ((size_t)snprintf(path, sizeof path, "%s/self.chainlog", f->ledger_dir) >= sizeof path)
        return false;
    struct zcl_chainlog_report lower;
    struct zcl_chainlog *log = zcl_chainlog_open(path, stream, &lower);
    if (!log) return false;
    bool ok = n > 0 && zcl_chainlog_append(log, 1, bytes, n, NULL, NULL) == ZCL_CHAINLOG_OK;
    zcl_chainlog_close(log);
    return ok;
}

static bool vh_execute(const struct json_value *input, struct json_value *root)
{
    const struct zcl_command_registry *reg = zcl_command_catalog();
    const struct zcl_command_spec *spec = zcl_command_registry_find(reg, "fleet.vitals.history", NULL);
    if (!spec) return false;
    struct zcl_command_context ctx = {.registry = reg,
        .granted_capabilities = ~(uint64_t)0, .authority_ceiling = ZCL_COMMAND_AUTH_OWNER};
    enum zcl_command_exit rc;
    size_t n = zcl_command_registry_execute_json(reg, spec, &ctx, input, false,
        "fleet.vitals.history", "full", 0, 0, NULL, vh_wire, sizeof vh_wire, &rc);
    bool parsed = n > 0 && n < sizeof vh_wire && json_read(root, vh_wire, n);
    const struct json_value *ok = parsed ? json_get(root, "ok") : NULL;
    if (!ok || ok->type != JSON_BOOL || !json_get_bool(ok))
        printf("history registry reply rc=%d bytes=%zu parsed=%d: %.*s\n",
               (int)rc, n, (int)parsed, (int)(n < 2048 ? n : 2048), vh_wire);
    return parsed;
}

static bool vh_string(const struct json_value *obj, const char *key, const char *expected)
{
    const struct json_value *v = obj ? json_get(obj, key) : NULL;
    return v && v->type == JSON_STR && strcmp(json_get_str(v), expected) == 0;
}

static bool vh_passed(const struct json_value *root)
{
    const struct json_value *v = json_get(root, "ok");
    return v && v->type == JSON_BOOL && json_get_bool(v);
}

static bool vh_input(struct json_value *input, const char *box, int64_t after, int64_t limit)
{
    json_set_object(input);
    return json_push_kv_str(input, "box", box) &&
        json_push_kv_int(input, "after_seq", after) && json_push_kv_int(input, "limit", limit);
}

static int vh_public_only(struct vh_fixture *f)
{
    int failures = 0;
    struct json_value input = {0}, root = {0};
    TEST("vitals history: public delegation without online key reads zero and absence") {
        char key[640];
        ASSERT((size_t)snprintf(key, sizeof key, "%s/zcode/dht/online_ed25519.key", f->datadir) < sizeof key);
        struct stat info;
        ASSERT(lstat(key, &info) != 0);
        char ledger[768];
        ASSERT((size_t)snprintf(ledger, sizeof ledger, "%s/self.chainlog", f->ledger_dir) < sizeof ledger);
        struct stat before, after;
        ASSERT(stat(ledger, &before) == 0);
        ASSERT(vh_input(&input, f->box_hex, 0, 64));
        ASSERT(json_push_kv_str(&input, "datadir", f->datadir));
        ASSERT(vh_execute(&input, &root));
        ASSERT(vh_passed(&root));
        const struct json_value *data = json_get(&root, "data");
        ASSERT(vh_string(data, "verification", "signature_chain_only"));
        ASSERT(vh_string(data, "delegation", "not_evaluated"));
        const struct json_value *self = json_get(data, "self_identity_available");
        ASSERT(self && self->type == JSON_BOOL && json_get_bool(self));
        const struct json_value *rows = json_get(data, "rows");
        ASSERT(rows && rows->type == JSON_ARR && rows->num_children == 4);
        const struct json_value *zero = json_get(&rows->children[0], "value");
        ASSERT(zero && zero->type == JSON_INT && json_get_int(zero) == 0);
        const struct json_value *absent = json_get(&rows->children[1], "value");
        ASSERT(absent && absent->type == JSON_NULL);
        ASSERT(vh_string(&rows->children[2], "freshness", "future"));
        ASSERT(vh_string(&rows->children[3], "freshness", "unknown"));
        const struct json_value *age = json_get(&rows->children[3], "age_s");
        ASSERT(age && age->type == JSON_NULL);
        ASSERT(lstat(key, &info) != 0);
        ASSERT(stat(ledger, &after) == 0);
        ASSERT_EQ(before.st_size, after.st_size);
        ASSERT_EQ(before.st_mtime, after.st_mtime);
        ASSERT_EQ(before.st_mode, after.st_mode);
        PASS();
    }
_test_next:
    json_free(&input);
    json_free(&root);
    return failures;
}

static int vh_refusals(struct vh_fixture *f)
{
    int failures = 0;
    struct json_value input = {0}, root = {0};
    TEST("vitals history: malformed bounds, box and metric refuse") {
        ASSERT(vh_input(&input, f->box_hex, -1, 64));
        ASSERT(vh_execute(&input, &root));
        ASSERT(!vh_passed(&root));
        json_free(&root); json_free(&input);
        ASSERT(vh_input(&input, "not-a-box", 0, 1));
        ASSERT(vh_execute(&input, &root));
        ASSERT(!vh_passed(&root));
        json_free(&root); json_free(&input);
        ASSERT(vh_input(&input, f->box_hex, 0, 1));
        ASSERT(json_push_kv_str(&input, "metric", "unknown.metric"));
        ASSERT(vh_execute(&input, &root));
        ASSERT(!vh_passed(&root));
        json_free(&root); json_free(&input);
        ASSERT(vh_input(&input, f->box_hex, 0, 65));
        ASSERT(vh_execute(&input, &root));
        ASSERT(!vh_passed(&root));
        PASS();
    }
_test_next:
    json_free(&input);
    json_free(&root);
    return failures;
}

static int vh_alloc_refusal(struct vh_fixture *f)
{
    int failures = 0;
    struct json_value input = {0};
    struct zcl_command_reply reply = {0};
    TEST("vitals history: checked response-copy allocation failure refuses") {
        ASSERT(vh_input(&input, f->box_hex, 0, 64));
        struct zcl_command_request request = {.input = &input};
        zcl_alloc_fault_fail_next("json_copy_str");
        zcl_native_handle_fleet_vitals_history(&request, &reply);
        ASSERT_EQ(reply.status, ZCL_COMMAND_STATUS_FAILED);
        ASSERT(zcl_alloc_fault_armed_label() == NULL);
        ASSERT_STR_EQ(reply.error.code, "HISTORY_ALLOC");
        PASS();
    }
_test_next:
    zcl_alloc_fault_clear();
    json_free(&input);
    zcl_command_reply_free(&reply);
    return failures;
}

static int vh_page_and_corruption(struct vh_fixture *f)
{
    int failures = 0;
    struct json_value input = {0}, root = {0};
    TEST("vitals history: cursor page and corrupt signature preserve recorded file") {
        ASSERT(vh_input(&input, f->box_hex, 1, 1));
        ASSERT(vh_execute(&input, &root));
        ASSERT(vh_passed(&root));
        const struct json_value *data = json_get(&root, "data");
        const struct json_value *next = json_get(data, "next_seq");
        ASSERT(next && next->type == JSON_INT && json_get_int(next) == 2);
        const struct json_value *rows = json_get(data, "rows");
        ASSERT(rows && rows->type == JSON_ARR && rows->num_children == 1);
        json_free(&root);
        ASSERT(vh_raw_tail(f, 1, false));
        char path[768];
        ASSERT((size_t)snprintf(path, sizeof path, "%s/self.chainlog", f->ledger_dir) < sizeof path);
        struct stat before, after;
        ASSERT(stat(path, &before) == 0);
        ASSERT(vh_execute(&input, &root));
        ASSERT(!vh_passed(&root));
        ASSERT(stat(path, &after) == 0);
        ASSERT_EQ(before.st_size, after.st_size);
        ASSERT_EQ(before.st_mtime, after.st_mtime);
        ASSERT_EQ(before.st_mode, after.st_mode);
        PASS();
    }
_test_next:
    json_free(&input);
    json_free(&root);
    return failures;
}

static int vh_missing_public(struct vh_fixture *f)
{
    int failures = 0;
    struct json_value input = {0}, root = {0};
    char public_path[768], saved[768];
    bool moved = false;
    TEST("vitals history: missing public identity reports peer-only coverage") {
        ASSERT((size_t)snprintf(public_path, sizeof public_path,
            "%s/zcode/dht/delegation.v1", f->datadir) < sizeof public_path);
        ASSERT((size_t)snprintf(saved, sizeof saved, "%s.saved", public_path) < sizeof saved);
        ASSERT(rename(public_path, saved) == 0);
        moved = true;
        ASSERT(vh_input(&input, f->box_hex, 0, 64));
        ASSERT(vh_execute(&input, &root));
        ASSERT(vh_passed(&root));
        const struct json_value *data = json_get(&root, "data");
        ASSERT(vh_string(data, "coverage", "peer_chains_only"));
        const struct json_value *self = json_get(data, "self_identity_available");
        ASSERT(self && self->type == JSON_BOOL && !json_get_bool(self));
        PASS();
    }
_test_next:
    if (moved && rename(saved, public_path) != 0) failures++;
    json_free(&input);
    json_free(&root);
    return failures;
}

static int vh_missing_ledger(struct vh_fixture *f)
{
    int failures = 0;
    char empty[512] = {0}, path[640];
    struct json_value input = {0}, root = {0};
    TEST("vitals history: missing ledger refuses without creating it") {
        ASSERT(test_mkdtemp(empty, sizeof empty, "vitals_history_absent"));
        ASSERT(vh_input(&input, f->box_hex, 0, 64));
        ASSERT(json_push_kv_str(&input, "datadir", empty));
        ASSERT(vh_execute(&input, &root));
        ASSERT(!vh_passed(&root));
        ASSERT((size_t)snprintf(path, sizeof path, "%s/fleet_ledger", empty) < sizeof path);
        struct stat info;
        ASSERT(lstat(path, &info) != 0);
        PASS();
    }
_test_next:
    json_free(&input);
    json_free(&root);
    if (empty[0]) test_rm_rf_recursive(empty);
    return failures;
}

static int vh_impact_case(void)
{
    int failures = 0;
    TEST("vitals history: handler-only changes select history and lint gates") {
        struct agent_impact_acc impact = {0};
        ASSERT(agent_impact_apply_shared_rules(
            "tools/command/native_fleet_vitals_history.c", &impact));
        ASSERT(!impact.groups_lost);
        bool history = false, lint = false;
        for (size_t i = 0; i < impact.groups_len; i++) {
            history |= strcmp(impact.groups[i], "fleet_vitals_history") == 0;
            lint |= strcmp(impact.groups[i], "make_lint_gates") == 0;
        }
        ASSERT(history);
        ASSERT(lint);
        PASS();
    }
_test_next:
    return failures;
}

static int vh_descriptor_case(void)
{
    int failures = 0;
    struct json_value input = {0};
    TEST("vitals history: registry describes and accepts bounded integer cursor") {
        const struct zcl_command_spec *spec = zcl_command_registry_find(
            zcl_command_catalog(), "fleet.vitals.history", NULL);
        ASSERT(spec);
        struct zcl_command_input_descriptor descriptor;
        ASSERT(zcl_command_registry_input_descriptor(spec, "after_seq", &descriptor));
        ASSERT_EQ(descriptor.type, JSON_INT);
        ASSERT_EQ(descriptor.minimum, INT64_C(0));
        ASSERT_EQ(descriptor.maximum, INT64_MAX);
        ASSERT(zcl_command_registry_input_descriptor(spec, "limit", &descriptor));
        ASSERT_EQ(descriptor.type, JSON_INT);
        ASSERT_EQ(descriptor.minimum, INT64_C(1));
        ASSERT_EQ(descriptor.maximum, INT64_C(64));
        char why[128];
        ASSERT(vh_input(&input,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", INT64_MAX, 64));
        ASSERT(zcl_command_registry_input_validate(spec, &input, why, sizeof why));
        json_free(&input);
        ASSERT(vh_input(&input,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 0, 65));
        ASSERT(!zcl_command_registry_input_validate(spec, &input, why, sizeof why));
        json_free(&input);
        json_set_object(&input);
        ASSERT(json_push_kv_str(&input, "box",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
        ASSERT(json_push_kv_str(&input, "after_seq", "0"));
        ASSERT(!zcl_command_registry_input_validate(spec, &input, why, sizeof why));
        PASS();
    }
_test_next:
    json_free(&input);
    return failures;
}

int test_fleet_vitals_history(void)
{
    int failures = 0;
    struct vh_fixture fixture = {0};
    char previous[512];
    int previous_port = zcl_native_command_rpc_port();
    failures += vh_impact_case();
    failures += vh_descriptor_case();
    snprintf(previous, sizeof previous, "%s", zcl_native_command_datadir());
    TEST("vitals history: isolated public-only fixture") {
        ASSERT(vh_fixture_make(&fixture));
        ASSERT(vh_rows_make(&fixture));
        ASSERT(vh_raw_tail(&fixture, INT64_MAX, true));
        ASSERT(vh_raw_tail(&fixture, INT64_MIN, true));
        zcl_native_bridge_bind_rpc(fixture.datadir, 0);
        PASS();
        failures += vh_public_only(&fixture);
        failures += vh_refusals(&fixture);
        failures += vh_alloc_refusal(&fixture);
        failures += vh_missing_public(&fixture);
        failures += vh_missing_ledger(&fixture);
        failures += vh_page_and_corruption(&fixture);
    }
_test_next:
    zcl_native_bridge_bind_rpc(previous, previous_port);
    if (fixture.datadir[0]) test_rm_rf_recursive(fixture.datadir);
    return failures;
}
