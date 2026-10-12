/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: run one exact installed native binary to exit inside the OS sandbox. */
#include "command/native_command.h"
#include "base/hex.h"
#include "base/safe_alloc.h"
#include "json/json.h"
#include "services/package_resident.h"
#include "services/package_resident_manifest.h"
#include "util/log_macros.h"

#include <stdlib.h>
#include <string.h>

#define NCR_DEFAULT_TIMEOUT_MS 30000u

static void ncr_fail(struct zcl_command_reply *reply, const char *message)
{
    LOG_ERROR("app.run.confined", "%s", message);
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
        ZCL_COMMAND_EXIT_INVALID, "CONFINED_RUN_REFUSED", "execute",
        false, false, message, "app.run.confined");
}

static const char *ncr_str(const struct json_value *input, const char *key)
{
    const struct json_value *v = json_get(input, key);
    return v && v->type == JSON_STR ? json_get_str(v) : NULL;
}

/* Copy a bounded array of strings into `out` (pointers into `input`). */
static struct zcl_result ncr_str_array(const struct json_value *input,
    const char *key, const char **out, size_t cap, size_t *n)
{
    const struct json_value *v = json_get(input, key);
    *n = 0;
    if (!v) return ZCL_OK;
    if (v->type != JSON_ARR || v->num_children > cap)
        return ZCL_ERR(-1, "confined-input: %s must be a bounded array of strings", key);
    for (size_t i = 0; i < v->num_children; ++i) {
        if (v->children[i].type != JSON_STR)
            return ZCL_ERR(-1, "confined-input: %s entries must be strings", key);
        out[i] = json_get_str(&v->children[i]);
    }
    *n = v->num_children;
    return ZCL_OK;
}

static struct zcl_result ncr_limit(const struct json_value *input,
                                   const char *key, uint64_t *slot)
{
    const struct json_value *v = json_get(input, key);
    if (!v) return ZCL_OK;
    if (v->type != JSON_INT || json_get_int(v) < 0)
        return ZCL_ERR(-1, "confined-input: %s must be a non-negative integer", key);
    *slot = (uint64_t)json_get_int(v);
    return ZCL_OK;
}

static struct zcl_result ncr_manifest(const struct json_value *input,
                                      struct package_resident_manifest *m)
{
    package_resident_manifest_init(m);
    ZCL_CHECK(ncr_str_array(input, "read_paths", m->read_paths,
        PACKAGE_RESIDENT_MANIFEST_PATHS, &m->n_read));
    ZCL_CHECK(ncr_str_array(input, "write_paths", m->write_paths,
        PACKAGE_RESIDENT_MANIFEST_PATHS, &m->n_write));
    ZCL_CHECK(ncr_limit(input, "as_bytes", &m->rlimits.as_bytes));
    ZCL_CHECK(ncr_limit(input, "cpu_seconds", &m->rlimits.cpu_seconds));
    ZCL_CHECK(ncr_limit(input, "nproc", &m->rlimits.nproc));
    ZCL_CHECK(ncr_limit(input, "fsize_bytes", &m->rlimits.fsize_bytes));
    ZCL_CHECK(ncr_limit(input, "nofile", &m->rlimits.nofile));
    return ZCL_OK;
}

static struct zcl_result ncr_identity(const struct json_value *input,
                                      struct package_resident_artifact *artifact)
{
    const char *datadir = ncr_str(input, "datadir");
    const char *root = ncr_str(input, "package_root");
    const char *receipt = ncr_str(input, "receipt_id");
    const char *digest = ncr_str(input, "artifact_sha3");
    const char *program = ncr_str(input, "program");
    uint8_t root_b[32], receipt_b[32], digest_b[32];
    if (!datadir || !root || !receipt || !digest || !program ||
        !zcl_hex_decode_lower(root, root_b, 32) ||
        !zcl_hex_decode_lower(receipt, receipt_b, 32) ||
        !zcl_hex_decode_lower(digest, digest_b, 32))
        return ZCL_ERR(-1, "confined-input: datadir, program and exact lowercase package_root, receipt_id, artifact_sha3 are required");
    ZCL_CHECK(package_resident_artifact_read(datadir, root_b, receipt_b, program, artifact));
    if (strcmp(artifact->accepted.image_sha3_hex, digest) != 0)
        return ZCL_ERR(-1, "confined-input: explicitly accepted artifact digest differs from installed receipt");
    return ZCL_OK;
}

static struct zcl_result ncr_timeout(const struct json_value *input, uint32_t *ms)
{
    const struct json_value *v = json_get(input, "timeout_ms");
    *ms = NCR_DEFAULT_TIMEOUT_MS;
    if (!v) return ZCL_OK;
    if (v->type != JSON_INT || json_get_int(v) <= 0 ||
        json_get_int(v) > PACKAGE_RESIDENT_RUN_TIMEOUT_MAX_MS)
        return ZCL_ERR(-1, "confined-input: timeout_ms must be 1..%u", PACKAGE_RESIDENT_RUN_TIMEOUT_MAX_MS);
    *ms = (uint32_t)json_get_int(v);
    return ZCL_OK;
}

static struct zcl_result ncr_execute(const struct json_value *input,
                                     struct package_resident_exit *exit_out)
{
    struct package_resident_manifest manifest;
    const char *args[PACKAGE_RESIDENT_MANIFEST_ARGS];
    size_t n_args = 0;
    uint32_t timeout_ms = 0;
    ZCL_CHECK(ncr_manifest(input, &manifest));
    ZCL_CHECK(ncr_str_array(input, "args", args, PACKAGE_RESIDENT_MANIFEST_ARGS, &n_args));
    ZCL_CHECK(ncr_timeout(input, &timeout_ms));
    struct package_resident *app = zcl_calloc(1, sizeof(*app), "package.confined");
    if (!app) return ZCL_ERR(-1, "confined-run allocation failed");
    package_resident_init(app);
    struct package_resident_artifact artifact;
    struct zcl_result result = ncr_identity(input, &artifact);
    if (result.ok) result = package_resident_prepare(app, &artifact);
    if (result.ok)
        result = package_resident_run_confined(app, &manifest, args, n_args, timeout_ms, exit_out);
    struct zcl_result closed = package_resident_close(app);
    if (!closed.ok) result = closed;
    free(app);
    return result;
}

void zcl_native_handle_confined_run(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    const struct json_value *input = request ? request->input : NULL;
    const struct json_value *grant = input ? json_get(input, "accept_execution") : NULL;
    if (!grant || grant->type != JSON_BOOL || !json_get_bool(grant)) {
        ncr_fail(reply, "accept_execution must be JSON boolean true; no execution acceptance was granted");
        return;
    }
    struct package_resident_exit result = {0};
    struct zcl_result ran = ncr_execute(input, &result);
    if (!ran.ok) {
        ncr_fail(reply, ran.message);
        return;
    }
    json_set_object(&reply->data);
    if (!json_push_kv_bool(&reply->data, "exited", result.exited) ||
        !json_push_kv_int(&reply->data, "exit_code", result.exited ? result.code : -1) ||
        !json_push_kv_bool(&reply->data, "signaled", result.signaled) ||
        !json_push_kv_int(&reply->data, "signal", result.signaled ? result.signal : 0) ||
        !json_push_kv_bool(&reply->data, "timed_out", result.timed_out) ||
        !json_push_kv_str(&reply->data, "confinement", "landlock_seccomp_rlimits"))
        ncr_fail(reply, "confined run result allocation failed after completed run");
}
