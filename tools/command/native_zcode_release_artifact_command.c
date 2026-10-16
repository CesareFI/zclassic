/* purpose: Prepare and admit bounded inert release artifacts without signing or execution. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "command/native_zcode_release_artifact_command.h"
#include "command/native_package_artifact.h"
#include "base/hex.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "config/command_catalog.h"
#include "util/safe_alloc.h"
#include "vcs/release_artifact.h"
#include "vcs/package_release.h"

#include <stdlib.h>
#include <string.h>

struct release_inputs {
    struct vcs_release_artifact labels;
    uint8_t *program;
    size_t program_len;
    uint8_t *license;
    size_t license_len;
};

static const char *release_string(const struct json_value *input, const char *key)
{
    const struct json_value *v = json_get(input, key);
    return v && v->type == JSON_STR ? json_get_str(v) : NULL;
}

static void release_fail(struct zcl_command_reply *reply, const char *code,
    const char *detail, bool mutated)
{
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
        ZCL_COMMAND_EXIT_INVALID, code, "validate", false, mutated,
        detail, "zcode.release.artifact");
    json_free(&reply->data);
    json_set_object(&reply->data);
}

static bool release_label(const struct json_value *input, const char *key,
    char *out, size_t capacity)
{
    const char *s = release_string(input, key);
    if (!s || !s[0] || strlen(s) >= capacity) return false;
    memcpy(out, s, strlen(s) + 1u);
    return true;
}

static bool release_read(const struct json_value *input,
    struct release_inputs *in)
{
    memset(in, 0, sizeof(*in));
    if (!release_label(input, "name", in->labels.name, sizeof(in->labels.name)) ||
        !release_label(input, "version", in->labels.version, sizeof(in->labels.version)) ||
        !release_label(input, "os", in->labels.os, sizeof(in->labels.os)) ||
        !release_label(input, "arch", in->labels.arch, sizeof(in->labels.arch)) ||
        !release_label(input, "abi", in->labels.abi, sizeof(in->labels.abi)) ||
        !release_label(input, "isa", in->labels.isa, sizeof(in->labels.isa)) ||
        !release_string(input, "program_file") ||
        !release_string(input, "license_file"))
        return false;
    return zcl_native_package_artifact_read_file(input, "program_file",
        "program_sha3_256", VCS_PACKAGE_STORE_MAX_PACKAGE_BYTES,
        &in->program, &in->program_len) &&
        zcl_native_package_artifact_read_file(input, "license_file",
            "license_sha3_256", VCS_PACKAGE_RELEASE_LICENSE_TEXT_MAX_BYTES,
            &in->license, &in->license_len);
}

static bool release_hex(struct json_value *out, const char *key,
    const uint8_t *bytes, size_t len)
{
    if (len > (SIZE_MAX - 1u) / 2u) return false;
    char *hex = zcl_malloc(len * 2u + 1u, "release-artifact-reply-hex");
    if (!hex) return false;
    zcl_hex_encode(bytes, len, hex);
    bool ok = json_push_kv_str(out, key, hex);
    const char *observed = release_string(out, key);
    ok = ok && observed && strcmp(observed, hex) == 0;
    free(hex);
    return ok;
}

static bool release_output(struct json_value *out, const struct release_inputs *in,
    const struct vcs_package_manifest *manifest, const uint8_t root[32], bool admit)
{
    struct vcs_release_artifact a = in->labels;
    zcl_native_package_artifact_digest(a.program_digest, in->program, in->program_len);
    a.size = in->program_len;
    uint8_t *metadata = NULL, *wire = NULL;
    size_t metadata_len = 0, wire_len = 0;
    bool ok = vcs_release_artifact_serialize(&a, &metadata, &metadata_len) &&
        vcs_package_manifest_serialize(manifest, &wire, &wire_len) &&
        release_hex(out, "manifest_root", root, 32) &&
        release_hex(out, "manifest_hex", wire, wire_len) &&
        json_push_kv_str(out, "metadata", (const char *)metadata) &&
        release_hex(out, "program_sha3_256", a.program_digest, 32) &&
        json_push_kv_int(out, "program_bytes", (int64_t)a.size) &&
        json_push_kv_int(out, "metadata_bytes", (int64_t)metadata_len) &&
        json_push_kv_str(out, "stage", admit ? "admitted" : "prepared") &&
        json_push_kv_bool(out, "public_serveable", false);
    free(metadata);
    free(wire);
    return ok;
}

static void release_handle(const struct zcl_command_request *request,
    struct zcl_command_reply *reply, bool admit, const char *datadir)
{
    if (!reply) return;
    struct release_inputs in = {0};
    struct vcs_package_manifest manifest;
    vcs_package_manifest_init(&manifest);
    uint8_t root[32], admitted[32];
    struct vcs_package_store *store = NULL;
    const struct json_value *input = request ? request->input : NULL;
    if (!input || !release_read(input, &in)) {
        release_fail(reply, "ARTIFACT_INPUT_REFUSED",
            "Provide bounded target labels and stable program_file/license_file snapshots with exact lowercase SHA3-256 digests", false);
        goto done;
    }
    if (!vcs_release_artifact_prepare(&in.labels, in.program, in.program_len,
        in.license, in.license_len, &manifest, root)) {
        release_fail(reply, "ARTIFACT_PREPARE_REFUSED",
            "Program, license, target labels or total package size are invalid", false);
        goto done;
    }
    if (!release_output(&reply->data, &in, &manifest, root, admit)) {
        release_fail(reply, "ARTIFACT_OUTPUT_REFUSED",
            "Bounded artifact output could not be rendered before admission", false);
        goto done;
    }
    if (admit) {
        if (!datadir || !datadir[0]) {
            release_fail(reply, "ARTIFACT_DATADIR_REQUIRED",
                "Admission requires an explicit package-store datadir", false);
            goto done;
        }
        reply->error.mutated = true;
        store = vcs_package_store_open(datadir, vcs_package_store_quota_bytes());
        if (!store || !vcs_release_artifact_admit(store, &in.labels, in.program,
            in.program_len, in.license, in.license_len, admitted) ||
            memcmp(root, admitted, 32) != 0) {
            release_fail(reply, "ARTIFACT_ADMISSION_REFUSED",
                "CAS admission or exact verified readback failed; staging may remain resumable", true);
            goto done;
        }
    }
done:
    vcs_package_store_close(store);
    vcs_package_manifest_free(&manifest);
    free(in.program);
    free(in.license);
}

/* Direct callers obey the same closed input contract as registry dispatch. */
static bool release_input_validate(const struct zcl_command_request *request,
    struct zcl_command_reply *reply, const char *path)
{
    const struct zcl_command_spec *spec =
        zcl_command_registry_find(zcl_command_catalog(), path, NULL);
    char why[512] = {0};
    if (request && spec && zcl_command_registry_input_validate(spec,
            request->input, why, sizeof(why)))
        return true;
    release_fail(reply, "ARTIFACT_INPUT_REFUSED",
        "Input must match the declared release artifact command schema", false);
    return false;
}

void zcl_native_handle_zcode_release_artifact_prepare(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!reply || !release_input_validate(request, reply,
            "zcode.release.artifact.prepare")) return;
    release_handle(request, reply, false, NULL);
}

void zcl_native_handle_zcode_release_artifact_admit(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!reply || !release_input_validate(request, reply,
            "zcode.release.artifact.admit")) return;
    const char *datadir = release_string(request->input, "datadir");
    release_handle(request, reply, true, datadir);
}
