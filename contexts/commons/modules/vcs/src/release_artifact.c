/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "vcs/release_artifact.h"

#include "base/hex.h"
#include "json/json.h"
#include "sha3/sha3.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"
#include "vcs/package_release.h"

#include <stdlib.h>
#include <string.h>

#define ARTIFACT_LOG "vcs.release_artifact"

static bool artifact_target_byte(unsigned char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
        (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '+' || c == '-';
}

static bool artifact_label(const char *s, size_t cap, bool target)
{
    const char *end = memchr(s, 0, cap);
    if (!end || end == s)
        return false;
    for (const char *p = s; p < end; ++p) {
        unsigned char c = (unsigned char)*p;
        bool allowed = target ? artifact_target_byte(c) : c >= 0x20 && c <= 0x7e;
        if (!allowed)
            return false;
    }
    return true;
}

static bool artifact_valid(const struct vcs_release_artifact *a)
{
    return a && artifact_label(a->name, sizeof(a->name), false) &&
        artifact_label(a->version, sizeof(a->version), false) &&
        artifact_label(a->os, sizeof(a->os), true) &&
        artifact_label(a->arch, sizeof(a->arch), true) &&
        artifact_label(a->abi, sizeof(a->abi), true) &&
        artifact_label(a->isa, sizeof(a->isa), true) &&
        a->size > 0 && a->size <= VCS_PACKAGE_STORE_MAX_PACKAGE_BYTES;
}

static bool artifact_json(const struct vcs_release_artifact *a,
    struct json_value *doc)
{
    struct json_value target = {0}, program = {0};
    char digest[65];
    zcl_hex_encode(a->program_digest, 32, digest);
    json_set_object(doc);
    json_set_object(&target);
    json_set_object(&program);
    bool ok = json_push_kv_str(doc, "schema", VCS_RELEASE_ARTIFACT_SCHEMA) &&
        json_push_kv_str(doc, "name", a->name) &&
        json_push_kv_str(doc, "version", a->version) &&
        json_push_kv_str(&target, "os", a->os) &&
        json_push_kv_str(&target, "arch", a->arch) &&
        json_push_kv_str(&target, "abi", a->abi) &&
        json_push_kv_str(&target, "isa", a->isa) &&
        json_push_kv(doc, "target", &target) &&
        json_push_kv_str(&program, "path", VCS_RELEASE_ARTIFACT_PROGRAM_PATH) &&
        json_push_kv_int(&program, "size", (int64_t)a->size) &&
        json_push_kv_str(&program, "sha3_256", digest) &&
        json_push_kv(doc, "artifact", &program);
    json_free(&target);
    json_free(&program);
    return ok;
}

bool vcs_release_artifact_serialize(const struct vcs_release_artifact *a,
    uint8_t **out, size_t *out_len)
{
    if (out) *out = NULL;
    if (out_len) *out_len = 0;
    if (!out || !out_len || !artifact_valid(a))
        LOG_FAIL(ARTIFACT_LOG, "invalid release artifact metadata");
    struct json_value doc = {0};
    bool ok = artifact_json(a, &doc);
    size_t len = ok ? json_write(&doc, NULL, 0) : 0;
    uint8_t *bytes = len && len <= VCS_RELEASE_ARTIFACT_METADATA_MAX
        ? zcl_malloc(len + 1u, "release-artifact-json") : NULL;
    ok = bytes && json_write(&doc, (char *)bytes, len + 1u) == len;
    json_free(&doc);
    if (!ok) {
        free(bytes);
        LOG_FAIL(ARTIFACT_LOG, "release artifact serialization refused");
    }
    *out = bytes;
    *out_len = len;
    return true;
}

static bool artifact_string(const struct json_value *obj, const char *key,
    char *out, size_t cap)
{
    const struct json_value *v = json_get(obj, key);
    if (!v || v->type != JSON_STR || !v->val.s)
        return false;
    size_t len = strlen(v->val.s);
    if (len >= cap)
        return false;
    memcpy(out, v->val.s, len + 1u);
    return true;
}

static bool artifact_decode_labels(const struct json_value *doc,
    struct vcs_release_artifact *a)
{
    const struct json_value *target = json_get(doc, "target");
    return artifact_string(doc, "name", a->name, sizeof(a->name)) &&
        artifact_string(doc, "version", a->version, sizeof(a->version)) &&
        artifact_string(target, "os", a->os, sizeof(a->os)) &&
        artifact_string(target, "arch", a->arch, sizeof(a->arch)) &&
        artifact_string(target, "abi", a->abi, sizeof(a->abi)) &&
        artifact_string(target, "isa", a->isa, sizeof(a->isa));
}

static bool artifact_decode(const struct json_value *doc,
    struct vcs_release_artifact *a)
{
    const struct json_value *program = json_get(doc, "artifact");
    const struct json_value *size = json_get(program, "size");
    const struct json_value *schema = json_get(doc, "schema");
    const struct json_value *path = json_get(program, "path");
    char digest[65];
    if (!schema || schema->type != JSON_STR ||
        strcmp(schema->val.s, VCS_RELEASE_ARTIFACT_SCHEMA) != 0 ||
        !path || path->type != JSON_STR ||
        strcmp(path->val.s, VCS_RELEASE_ARTIFACT_PROGRAM_PATH) != 0 ||
        !size || size->type != JSON_INT || size->val.i <= 0)
        return false;
    a->size = (uint64_t)size->val.i;
    return artifact_decode_labels(doc, a) &&
        artifact_string(program, "sha3_256", digest, sizeof(digest)) &&
        strlen(digest) == 64 && zcl_hex_decode_lower(digest, a->program_digest, 32);
}

bool vcs_release_artifact_parse(const uint8_t *bytes, size_t len,
    struct vcs_release_artifact *out)
{
    if (out) memset(out, 0, sizeof(*out));
    if (!bytes || !out || !len || len > VCS_RELEASE_ARTIFACT_METADATA_MAX ||
        memchr(bytes, 0, len))
        LOG_FAIL(ARTIFACT_LOG, "invalid release artifact JSON input");
    struct json_value doc = {0};
    struct vcs_release_artifact a = {0};
    uint8_t *canonical = NULL;
    size_t canonical_len = 0;
    bool ok = json_read(&doc, (const char *)bytes, len) &&
        artifact_decode(&doc, &a) &&
        vcs_release_artifact_serialize(&a, &canonical, &canonical_len) &&
        canonical_len == len && memcmp(canonical, bytes, len) == 0;
    free(canonical);
    json_free(&doc);
    if (!ok)
        LOG_FAIL(ARTIFACT_LOG, "noncanonical release artifact metadata");
    *out = a;
    return true;
}

static bool artifact_metadata(const struct vcs_release_artifact *labels,
    const uint8_t *program, size_t program_len,
    const uint8_t *license, size_t license_len,
    uint8_t **metadata, size_t *metadata_len)
{
    if (!labels || !program || !program_len || !license ||
        !vcs_package_release_license_text_allowed(license, license_len) ||
        program_len > VCS_PACKAGE_STORE_MAX_PACKAGE_BYTES ||
        license_len > VCS_PACKAGE_STORE_MAX_PACKAGE_BYTES - program_len)
        LOG_FAIL(ARTIFACT_LOG, "invalid program/license snapshot");
    struct vcs_release_artifact a = *labels;
    a.size = program_len;
    sha3_256(program, program_len, a.program_digest);
    if (!vcs_release_artifact_serialize(&a, metadata, metadata_len))
        return false;
    if (*metadata_len > VCS_PACKAGE_STORE_MAX_PACKAGE_BYTES -
        program_len - license_len) {
        free(*metadata);
        *metadata = NULL;
        *metadata_len = 0;
        LOG_FAIL(ARTIFACT_LOG, "release artifact exceeds package cap");
    }
    return true;
}

bool vcs_release_artifact_prepare(const struct vcs_release_artifact *labels,
    const uint8_t *program, size_t program_len,
    const uint8_t *license, size_t license_len,
    struct vcs_package_manifest *manifest, uint8_t root[32])
{
    if (manifest) vcs_package_manifest_init(manifest);
    if (root) memset(root, 0, 32);
    if (!manifest || !root)
        LOG_FAIL(ARTIFACT_LOG, "null release artifact preparation output");
    uint8_t *metadata = NULL;
    size_t metadata_len = 0;
    if (!artifact_metadata(labels, program, program_len, license, license_len,
        &metadata, &metadata_len))
        return false;
    bool ok = vcs_package_content_add_file(manifest, "LICENSE",
        VCS_PACKAGE_MODE_FILE, license, license_len) &&
        vcs_package_content_add_file(manifest, VCS_RELEASE_ARTIFACT_PROGRAM_PATH,
            VCS_PACKAGE_MODE_EXECUTABLE, program, program_len) &&
        vcs_package_content_add_file(manifest, VCS_RELEASE_ARTIFACT_METADATA_PATH,
            VCS_PACKAGE_MODE_FILE, metadata, metadata_len) &&
        vcs_package_manifest_root(manifest, root);
    free(metadata);
    if (!ok)
        LOG_FAIL(ARTIFACT_LOG, "release artifact manifest preparation refused");
    return true;
}

static bool artifact_shape(const struct vcs_package_manifest *m)
{
    return m->count == 3 &&
        strcmp(m->files[0].path, "LICENSE") == 0 &&
        m->files[0].mode == VCS_PACKAGE_MODE_FILE &&
        m->files[0].size <= VCS_PACKAGE_RELEASE_LICENSE_TEXT_MAX_BYTES &&
        strcmp(m->files[1].path, VCS_RELEASE_ARTIFACT_PROGRAM_PATH) == 0 &&
        m->files[1].mode == VCS_PACKAGE_MODE_EXECUTABLE &&
        m->files[1].size > 0 &&
        m->files[1].size <= VCS_PACKAGE_STORE_MAX_PACKAGE_BYTES &&
        strcmp(m->files[2].path, VCS_RELEASE_ARTIFACT_METADATA_PATH) == 0 &&
        m->files[2].mode == VCS_PACKAGE_MODE_FILE &&
        m->files[2].size <= VCS_RELEASE_ARTIFACT_METADATA_MAX;
}

static bool artifact_files_match(uint8_t *const files[3], const size_t sizes[3],
    struct vcs_release_artifact *out)
{
    struct vcs_release_artifact a = {0};
    uint8_t digest[32];
    sha3_256(files[1], sizes[1], digest);
    bool ok = vcs_release_artifact_parse(files[2], sizes[2], &a) &&
        vcs_package_release_license_text_allowed(files[0], sizes[0]) &&
        a.size == sizes[1] && memcmp(a.program_digest, digest, 32) == 0;
    if (ok) *out = a;
    return ok;
}

bool vcs_release_artifact_verify(struct vcs_package_store *store,
    const uint8_t root[32], struct vcs_release_artifact *out,
    uint8_t **program, size_t *program_len)
{
    if (out) memset(out, 0, sizeof(*out));
    if (program) *program = NULL;
    if (program_len) *program_len = 0;
    if (!store || !root || !out || !program || !program_len)
        LOG_FAIL(ARTIFACT_LOG, "null release artifact verification input");
    struct vcs_package_manifest m;
    vcs_package_manifest_init(&m);
    uint8_t *wire = NULL, *files[3] = {0};
    size_t wire_len = 0, sizes[3] = {0};
    struct vcs_release_artifact a = {0};
    bool ok = vcs_package_store_get_manifest_wire(store, root, &wire,
        &wire_len) == VCS_PACKAGE_STORE_OK &&
        vcs_package_manifest_parse(wire, wire_len, &m) && artifact_shape(&m);
    for (uint32_t i = 0; ok && i < 3; ++i)
        ok = vcs_package_content_get_file_at(store, root, &m, i,
            &files[i], &sizes[i]) == VCS_PACKAGE_STORE_OK;
    if (ok)
        ok = artifact_files_match(files, sizes, &a);
    free(wire);
    vcs_package_manifest_free(&m);
    free(files[0]);
    free(files[2]);
    if (!ok) {
        free(files[1]);
        LOG_FAIL(ARTIFACT_LOG, "release artifact verification refused");
    }
    *out = a;
    *program = files[1];
    *program_len = sizes[1];
    return true;
}

bool vcs_release_artifact_admit(struct vcs_package_store *store,
    const struct vcs_release_artifact *labels,
    const uint8_t *program, size_t program_len,
    const uint8_t *license, size_t license_len, uint8_t root[32])
{
    if (root) memset(root, 0, 32);
    if (!store || !root)
        LOG_FAIL(ARTIFACT_LOG, "null release artifact admission input");
    struct vcs_package_manifest m;
    uint8_t prepared[32], admitted[32], *wire = NULL, *metadata = NULL;
    size_t wire_len = 0, metadata_len = 0;
    bool ok = vcs_release_artifact_prepare(labels, program, program_len,
        license, license_len, &m, prepared) &&
        artifact_metadata(labels, program, program_len, license, license_len,
            &metadata, &metadata_len) &&
        vcs_package_manifest_serialize(&m, &wire, &wire_len) &&
        vcs_package_store_put_manifest(store, wire, wire_len, admitted) ==
            VCS_PACKAGE_STORE_OK && memcmp(prepared, admitted, 32) == 0 &&
        vcs_package_content_put_file(store, prepared, "LICENSE", license,
            license_len) == VCS_PACKAGE_STORE_OK &&
        vcs_package_content_put_file(store, prepared,
            VCS_RELEASE_ARTIFACT_PROGRAM_PATH, program, program_len) ==
                VCS_PACKAGE_STORE_OK &&
        vcs_package_content_put_file(store, prepared,
            VCS_RELEASE_ARTIFACT_METADATA_PATH, metadata, metadata_len) ==
                VCS_PACKAGE_STORE_OK;
    free(wire);
    free(metadata);
    vcs_package_manifest_free(&m);
    struct vcs_release_artifact verified;
    uint8_t *readback = NULL;
    size_t readback_len = 0;
    ok = ok && vcs_release_artifact_verify(store, prepared, &verified,
        &readback, &readback_len) && readback_len == program_len &&
        memcmp(readback, program, program_len) == 0;
    free(readback);
    if (!ok)
        LOG_FAIL(ARTIFACT_LOG, "release artifact CAS admission/readback refused");
    memcpy(root, prepared, 32);
    return true;
}
