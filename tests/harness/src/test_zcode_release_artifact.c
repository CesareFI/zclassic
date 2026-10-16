/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "test/test_core.h"
#include "test/public_shape_fixture.h"
#include "sha3/sha3.h"
#include "base/hex.h"
#include "command/native_zcode_release_artifact_command.h"
#include "config/command_catalog.h"
#include "platform/private_file.h"
#include "base/safe_alloc.h"
#include "util/util.h"
#include "vcs/release_artifact.h"
#include "vcs/package_public_shape.h"
#include "vcs/package_service.h"
#include "vcs/package_swarm_node.h"

static const uint8_t artifact_program[] = {0x7f, 'E', 'L', 'F', 0, 1, 2, 0xff};
static const uint8_t artifact_license[] = TEST_LICENSE_TEXT_MIT;

static struct vcs_release_artifact artifact_labels(void)
{
    return (struct vcs_release_artifact){
        .name = "z23", .version = "1.0.0", .os = "linux", .arch = "x86_64",
        .abi = "gnu", .isa = "x86-64-v3", .size = sizeof(artifact_program)
    };
}

static int artifact_codec_tests(void)
{
    int failures = 0;
    struct vcs_release_artifact a = artifact_labels(), parsed;
    uint8_t *wire = NULL;
    size_t len = 0;
    TEST_CASE("release artifact canonical metadata rejects alternate encodings") {
        sha3_256(artifact_program, sizeof(artifact_program), a.program_digest);
        ASSERT(vcs_release_artifact_serialize(&a, &wire, &len));
        ASSERT(vcs_release_artifact_parse(wire, len, &parsed));
        ASSERT_EQ(parsed.size, sizeof(artifact_program));
        ASSERT(memcmp(a.program_digest, parsed.program_digest, 32) == 0);
        uint8_t altered[VCS_RELEASE_ARTIFACT_METADATA_MAX + 128u];
        ASSERT(len + 100u < sizeof(altered));
        memcpy(altered, wire, len);
        altered[len] = ' ';
        ASSERT(!vcs_release_artifact_parse(altered, len + 1u, &parsed));
        memcpy(altered, wire, len);
        altered[4] = 0;
        ASSERT(!vcs_release_artifact_parse(altered, len, &parsed));
        memcpy(altered, wire, len);
        altered[4] = 0xff;
        ASSERT(!vcs_release_artifact_parse(altered, len, &parsed));
        static const char *const extra[] = {
            ",\"name\":\"z23\"}", ",\"unknown\":1}",
            ",\"size\":18446744073709551616}"
        };
        for (size_t i = 0; i < sizeof(extra) / sizeof(extra[0]); ++i) {
            memcpy(altered, wire, len - 1u);
            size_t suffix = strlen(extra[i]);
            memcpy(altered + len - 1u, extra[i], suffix);
            ASSERT(!vcs_release_artifact_parse(altered, len - 1u + suffix,
                &parsed));
        }
        memcpy(altered, wire, len);
        char *size = strstr((char *)wire, "\"size\":8");
        ASSERT(size != NULL);
        size_t pos = (size_t)(size - (char *)wire) + strlen("\"size\":");
        memcpy(altered + pos, "18446744073709551616", 20);
        memcpy(altered + pos + 20, wire + pos + 1, len - pos - 1u);
        ASSERT(!vcs_release_artifact_parse(altered, len + 19u, &parsed));
        memset(a.os, 'x', sizeof(a.os));
        uint8_t *invalid = NULL;
        size_t invalid_len = 0;
        ASSERT(!vcs_release_artifact_serialize(&a, &invalid, &invalid_len));
        ASSERT(invalid == NULL && invalid_len == 0);
    } TEST_END
    free(wire);
    return failures;
}

static int artifact_root_tests(void)
{
    int failures = 0;
    struct vcs_release_artifact a = artifact_labels();
    struct vcs_package_manifest first, second;
    vcs_package_manifest_init(&first);
    vcs_package_manifest_init(&second);
    uint8_t root[32], changed[32], program[sizeof(artifact_program)];
    memcpy(program, artifact_program, sizeof(program));
    TEST_CASE("release artifact root binds program and declared target") {
        ASSERT(vcs_release_artifact_prepare(&a, program, sizeof(program),
            artifact_license, sizeof(artifact_license) - 1u, &first, root));
        a.size = UINT64_MAX;
        memset(a.program_digest, 0x33, 32);
        ASSERT(vcs_release_artifact_prepare(&a, program, sizeof(program),
            artifact_license, sizeof(artifact_license) - 1u, &second, changed));
        ASSERT(memcmp(root, changed, 32) == 0);
        vcs_package_manifest_free(&second);
        program[7] ^= 1;
        ASSERT(vcs_release_artifact_prepare(&a, program, sizeof(program),
            artifact_license, sizeof(artifact_license) - 1u, &second, changed));
        ASSERT(memcmp(root, changed, 32) != 0);
        vcs_package_manifest_free(&second);
        snprintf(a.isa, sizeof(a.isa), "%s", "baseline");
        ASSERT(vcs_release_artifact_prepare(&a, artifact_program,
            sizeof(artifact_program), artifact_license,
            sizeof(artifact_license) - 1u, &second, changed));
        ASSERT(memcmp(root, changed, 32) != 0);
    } TEST_END
    vcs_package_manifest_free(&first);
    vcs_package_manifest_free(&second);
    return failures;
}

static uint64_t artifact_score(const uint8_t key[33], void *ctx)
{
    (void)key;
    (void)ctx;
    return 100;
}

static bool artifact_public_want_refuses(struct vcs_swarm_engine *engine,
    const uint8_t root[32], const uint8_t chunk_hash[32], uint8_t kind)
{
    struct vcs_package_swarm_message want = {0};
    want.type = VCS_PACKAGE_SWARM_WANT;
    memcpy(want.body.want.package_root, root, 32);
    want.body.want.object_kind = kind;
    want.body.want.request_id = (uint64_t)kind;
    if (kind == VCS_PACKAGE_SWARM_OBJECT_CHUNK)
        memcpy(want.body.want.expected_hash, chunk_hash, 32);
    want.body.want.file_index = kind == VCS_PACKAGE_SWARM_OBJECT_MANIFEST
        ? UINT32_MAX : 1u;
    want.body.want.chunk_index = kind == VCS_PACKAGE_SWARM_OBJECT_MANIFEST
        ? UINT32_MAX : 0u;
    uint8_t frame[256];
    size_t frame_len = 0;
    if (!vcs_package_swarm_serialize(&want, frame, sizeof(frame), &frame_len))
        return false;
    struct vcs_swarm_frame_result r = vcs_swarm_engine_handle_frame(engine,
        77, frame, frame_len, 20500, kind);
    bool ok = r.reply == NULL && r.reply_len == 0 && !r.disconnect_peer &&
        r.penalty == VCS_SWARM_PENALTY_NONE && r.rule != NULL &&
        strcmp(r.rule, "no-verified-release") == 0;
    free(r.reply);
    return ok;
}

static bool artifact_public_refuses(struct vcs_package_store *store,
    const char *datadir, const uint8_t root[32], const uint8_t chunk_hash[32])
{
    char directory[1200];
    int n = snprintf(directory, sizeof(directory), "%s/zcode", datadir);
    if (n <= 0 || (size_t)n >= sizeof(directory)) return false;
    struct vcs_service_book *book = vcs_service_book_load(directory);
    struct vcs_swarm_engine *engine = book
        ? vcs_swarm_engine_create(store, book, directory, artifact_score, NULL)
        : NULL;
    uint8_t key[33] = {2};
    key[32] = 7;
    bool ok = engine && vcs_swarm_engine_peer_add(engine, 77, key) &&
        vcs_swarm_engine_announce_to(engine, 77) == 0;
    for (uint8_t kind = VCS_PACKAGE_SWARM_OBJECT_MANIFEST; ok &&
        kind <= VCS_PACKAGE_SWARM_OBJECT_CHUNK; ++kind)
        ok = artifact_public_want_refuses(engine, root, chunk_hash, kind);
    vcs_swarm_engine_free(engine);
    vcs_service_book_free(book);
    return ok;
}

static int artifact_store_tests(void)
{
    int failures = 0;
    char datadir[1024];
    test_make_tmpdir(datadir, sizeof(datadir), "zcode_release_artifact", "cas");
    struct vcs_package_store *store = vcs_package_store_open(datadir,
        VCS_PACKAGE_STORE_DEFAULT_QUOTA_BYTES);
    struct vcs_package_manifest manifest;
    vcs_package_manifest_init(&manifest);
    struct vcs_release_artifact a = artifact_labels(), verified;
    uint8_t root[32], repeated[32], *program = NULL;
    size_t program_len = 0;
    TEST_CASE("release artifact CAS admission is exact idempotent and private") {
        ASSERT(store != NULL);
        ASSERT(vcs_release_artifact_prepare(&a, artifact_program,
            sizeof(artifact_program), artifact_license,
            sizeof(artifact_license) - 1u, &manifest, root));
        ASSERT(vcs_release_artifact_admit(store, &a, artifact_program,
            sizeof(artifact_program), artifact_license,
            sizeof(artifact_license) - 1u, root));
        ASSERT(vcs_release_artifact_admit(store, &a, artifact_program,
            sizeof(artifact_program), artifact_license,
            sizeof(artifact_license) - 1u, repeated));
        ASSERT(memcmp(root, repeated, 32) == 0);
        ASSERT(vcs_release_artifact_verify(store, root, &verified, &program,
            &program_len));
        ASSERT_EQ(program_len, sizeof(artifact_program));
        ASSERT(memcmp(program, artifact_program, program_len) == 0);
        free(program); program = NULL;
        struct vcs_package_public_verdict verdict;
        ASSERT(vcs_package_public_shape_classify(store, root, &verdict) ==
            VCS_PACKAGE_PUBLIC_REFUSED);
        ASSERT(artifact_public_refuses(store, datadir, root, manifest.files[1].chunk_hashes));
        vcs_package_store_close(store);
        store = vcs_package_store_open(datadir,
            VCS_PACKAGE_STORE_DEFAULT_QUOTA_BYTES);
        ASSERT(store != NULL);
        ASSERT(vcs_release_artifact_verify(store, root, &verified, &program,
            &program_len));
        ASSERT_EQ(program_len, sizeof(artifact_program));
        ASSERT(memcmp(program, artifact_program, program_len) == 0);
    } TEST_END
    free(program);
    vcs_package_manifest_free(&manifest);
    vcs_package_store_close(store);
    test_rm_rf_recursive(datadir);
    return failures;
}

static int artifact_partial_tests(void)
{
    int failures = 0;
    char datadir[1024];
    test_make_tmpdir(datadir, sizeof(datadir), "zcode_release_artifact", "partial");
    struct vcs_package_store *store = vcs_package_store_open(datadir, VCS_PACKAGE_STORE_DEFAULT_QUOTA_BYTES);
    struct vcs_release_artifact a = artifact_labels(), verified;
    struct vcs_package_manifest manifest;
    vcs_package_manifest_init(&manifest);
    uint8_t root[32], admitted[32], *wire = NULL, *program = NULL;
    size_t wire_len = 0, program_len = 0;
    TEST_CASE("incomplete and quota-refused carriers cannot verify as complete") {
        ASSERT(store != NULL);
        ASSERT(vcs_release_artifact_prepare(&a, artifact_program,
            sizeof(artifact_program), artifact_license,
            sizeof(artifact_license) - 1u, &manifest, root));
        ASSERT(vcs_package_manifest_serialize(&manifest, &wire, &wire_len));
        ASSERT(vcs_package_store_put_manifest(store, wire, wire_len, admitted)
            == VCS_PACKAGE_STORE_OK);
        ASSERT(memcmp(root, admitted, 32) == 0);
        ASSERT(!vcs_release_artifact_verify(store, root, &verified, &program,
            &program_len));
        ASSERT(program == NULL && program_len == 0);
        vcs_package_store_close(store);
        store = vcs_package_store_open(datadir, 0);
        ASSERT(store != NULL);
        ASSERT(!vcs_release_artifact_admit(store, &a, artifact_program,
            sizeof(artifact_program), artifact_license,
            sizeof(artifact_license) - 1u, admitted));
        uint8_t zero[32] = {0};
        ASSERT(memcmp(admitted, zero, 32) == 0);
        struct vcs_package_store_status status;
        ASSERT(vcs_package_store_package_status(store, root, &status));
        ASSERT(!status.complete);
    } TEST_END
    free(wire);
    free(program);
    vcs_package_manifest_free(&manifest);
    vcs_package_store_close(store);
    test_rm_rf_recursive(datadir);
    return failures;
}

static int artifact_chunk_test(void)
{
    int failures = 0;
    char datadir[1024];
    test_make_tmpdir(datadir, sizeof(datadir), "zcode_release_artifact", "chunks");
    struct vcs_package_store *store = vcs_package_store_open(datadir,
        VCS_PACKAGE_STORE_DEFAULT_QUOTA_BYTES);
    size_t len = VCS_PACKAGE_CHUNK_BYTES + 1u;
    uint8_t *source = zcl_malloc(len, "release-artifact-test-chunks"), *readback = NULL;
    size_t readback_len = 0;
    struct vcs_release_artifact a = artifact_labels(), verified;
    uint8_t root[32];
    TEST_CASE("release artifact reconstructs across exact chunk boundary") {
        ASSERT(store != NULL && source != NULL);
        for (size_t i = 0; i < len; ++i) source[i] = (uint8_t)(i * 13u);
        ASSERT(vcs_release_artifact_admit(store, &a, source, len,
            artifact_license, sizeof(artifact_license) - 1u, root));
        ASSERT(vcs_release_artifact_verify(store, root, &verified, &readback,
            &readback_len));
        ASSERT_EQ(readback_len, len);
        ASSERT(memcmp(source, readback, len) == 0);
        ASSERT_EQ(verified.size, len);
    } TEST_END
    free(source);
    free(readback);
    vcs_package_store_close(store);
    test_rm_rf_recursive(datadir);
    return failures;
}

static int artifact_corruption_test(uint32_t index)
{
    int failures = 0;
    char datadir[1024];
    test_make_tmpdir(datadir, sizeof(datadir), "zcode_release_artifact",
        index == 1 ? "bad-program" : "bad-metadata");
    struct vcs_package_store *store = vcs_package_store_open(datadir,
        VCS_PACKAGE_STORE_DEFAULT_QUOTA_BYTES);
    struct vcs_release_artifact a = artifact_labels(), verified;
    struct vcs_package_manifest manifest;
    vcs_package_manifest_init(&manifest);
    uint8_t root[32], prepared[32], *readback = NULL;
    size_t readback_len = 0;
    TEST_CASE("stored program or metadata corruption refuses verified artifact") {
        ASSERT(store != NULL);
        ASSERT(vcs_release_artifact_admit(store, &a, artifact_program,
            sizeof(artifact_program), artifact_license,
            sizeof(artifact_license) - 1u, root));
        ASSERT(vcs_release_artifact_prepare(&a, artifact_program,
            sizeof(artifact_program), artifact_license,
            sizeof(artifact_license) - 1u, &manifest, prepared));
        ASSERT(memcmp(root, prepared, 32) == 0);
        char hex[65], path[1200];
        zcl_hex_encode(manifest.files[index].chunk_hashes, 32, hex);
        int n = snprintf(path, sizeof(path), "%s/zcode/cas/sha3/%.2s/%s",
            datadir, hex, hex);
        ASSERT(n > 0 && (size_t)n < sizeof(path));
        vcs_package_store_close(store); store = NULL;
        FILE *file = fopen(path, "r+b");
        ASSERT(file != NULL);
        int byte = fgetc(file);
        bool changed = byte != EOF && fseek(file, 0, SEEK_SET) == 0 &&
            fputc(byte ^ 1, file) != EOF;
        int closed = fclose(file);
        ASSERT(changed && closed == 0);
        store = vcs_package_store_open(datadir,
            VCS_PACKAGE_STORE_DEFAULT_QUOTA_BYTES);
        ASSERT(store != NULL);
        ASSERT(!vcs_release_artifact_verify(store, root, &verified, &readback,
            &readback_len));
        ASSERT(readback == NULL && readback_len == 0);
    } TEST_END
    free(readback);
    vcs_package_manifest_free(&manifest);
    vcs_package_store_close(store);
    test_rm_rf_recursive(datadir);
    return failures;
}

static bool artifact_write_snapshot(const char *path, const uint8_t *bytes,
    size_t len)
{
    struct platform_private_file file;
    platform_private_file_init(&file);
    bool ok = platform_private_file_create_locked(path, &file) &&
        platform_private_file_write_at(&file, bytes, len, 0) &&
        platform_private_file_flush(&file);
    platform_private_file_close(&file);
    return ok;
}

static bool artifact_command_input(struct json_value *input, const char *datadir,
    const char *program_path, const char *license_path)
{
    uint8_t digest[32];
    char program_hex[65], license_hex[65];
    sha3_256(artifact_program, sizeof(artifact_program), digest);
    zcl_hex_encode(digest, 32, program_hex);
    sha3_256(artifact_license, sizeof(artifact_license) - 1u, digest);
    zcl_hex_encode(digest, 32, license_hex);
    json_set_object(input);
    bool ok = json_push_kv_str(input, "name", "z23") &&
        json_push_kv_str(input, "version", "1.0.0") &&
        json_push_kv_str(input, "os", "linux") &&
        json_push_kv_str(input, "arch", "x86_64") &&
        json_push_kv_str(input, "abi", "gnu") &&
        json_push_kv_str(input, "isa", "x86-64-v3") &&
        json_push_kv_str(input, "program_file", program_path) &&
        json_push_kv_str(input, "program_sha3_256", program_hex) &&
        json_push_kv_str(input, "license_file", license_path) &&
        json_push_kv_str(input, "license_sha3_256", license_hex) &&
        (!datadir || json_push_kv_str(input, "datadir", datadir));
    return ok;
}

static bool artifact_command_call(const struct json_value *input, bool admit,
    const char *expected_error, uint8_t root[32])
{
    struct zcl_command_request request = {.input = input};
    struct zcl_command_reply reply;
    zcl_command_reply_init(&reply, "zcl.zcode_release_artifact.v1");
    if (admit) zcl_native_handle_zcode_release_artifact_admit(&request, &reply);
    else zcl_native_handle_zcode_release_artifact_prepare(&request, &reply);
    bool ok;
    if (expected_error) {
        ok = reply.status == ZCL_COMMAND_STATUS_FAILED &&
            strcmp(reply.error.code, expected_error) == 0 &&
            reply.error.mutated == (strcmp(expected_error, "ARTIFACT_ADMISSION_REFUSED") == 0) &&
            json_size(&reply.data) == 0;
    } else {
        const char *hex = json_get_str(json_get(&reply.data, "manifest_root"));
        const char *stage = json_get_str(json_get(&reply.data, "stage"));
        ok = reply.status == ZCL_COMMAND_STATUS_PASSED &&
            reply.exit_code == ZCL_COMMAND_EXIT_OK && reply.error.mutated == admit && hex &&
            zcl_hex_decode_lower(hex, root, 32) && stage &&
            strcmp(stage, admit ? "admitted" : "prepared") == 0;
    }
    zcl_command_reply_free(&reply);
    return ok;
}

static bool artifact_registry_call(const struct json_value *input, bool admit,
    uint8_t root[32])
{
    const struct zcl_command_registry *registry = zcl_command_catalog();
    const struct zcl_command_spec *spec = zcl_command_registry_find(registry,
        admit ? "zcode.release.artifact.admit" : "zcode.release.artifact.prepare", NULL);
    if (!spec) return false;
    struct zcl_command_context context = {.registry = registry,
        .granted_capabilities = UINT64_MAX, .authority_ceiling = ZCL_COMMAND_AUTH_OWNER};
    char wire[16384];
    enum zcl_command_exit code = ZCL_COMMAND_EXIT_INTERNAL;
    size_t len = zcl_command_registry_execute_json(registry, spec, &context,
        input, false, spec->path, "normal", 0, 0, NULL, wire, sizeof(wire), &code);
    struct json_value envelope = {0};
    bool ok = len > 0 && len < sizeof(wire) && code == ZCL_COMMAND_EXIT_OK &&
        json_read(&envelope, wire, len);
    const struct json_value *data = json_get(&envelope, "data");
    const char *hex = json_get_str(json_get(data, "manifest_root"));
    const char *stage = json_get_str(json_get(data, "stage"));
    ok = ok && hex && zcl_hex_decode_lower(hex, root, 32) && stage &&
        strcmp(stage, admit ? "admitted" : "prepared") == 0;
    if (!ok) fprintf(stderr, "artifact registry dispatch code=%d response=%.512s\n",
        (int)code, len ? wire : "no response");
    json_free(&envelope);
    return ok;
}

static int artifact_command_test(void)
{
    int failures = 0;
    char directory[1024], program_path[1200], license_path[1200], datadir[1200];
    test_make_tmpdir(directory, sizeof(directory), "zcode_release_artifact", "command");
    snprintf(program_path, sizeof(program_path), "%s/program", directory);
    snprintf(license_path, sizeof(license_path), "%s/LICENSE", directory);
    snprintf(datadir, sizeof(datadir), "%s/store", directory);
    struct json_value input = {0};
    uint8_t prepared[32], admitted[32];
    TEST_CASE("native artifact preparation does not create CAS and admission reads back exact root") {
        ASSERT(artifact_write_snapshot(program_path, artifact_program,
            sizeof(artifact_program)));
        ASSERT(artifact_write_snapshot(license_path, artifact_license,
            sizeof(artifact_license) - 1u));
        ASSERT(artifact_command_input(&input, NULL, program_path, license_path));
        ASSERT(artifact_registry_call(&input, false, prepared));
        ASSERT(artifact_command_call(&input, false, NULL, admitted));
        ASSERT(memcmp(prepared, admitted, 32) == 0);
        ASSERT(json_push_kv_str(&input, "datadir", datadir));
        struct stat st;
        ASSERT(stat(datadir, &st) != 0 && errno == ENOENT);
        zcl_alloc_fault_fail_next("release-artifact-reply-hex");
        ASSERT(artifact_command_call(&input, true, "ARTIFACT_OUTPUT_REFUSED", admitted));
        zcl_alloc_fault_clear();
        ASSERT(stat(datadir, &st) != 0 && errno == ENOENT);
        ASSERT(mkdir(datadir, 0700) == 0);
        const char *zero_quota[] = {"z23-test", "-packagequota=0"};
        ParseParameters(2, zero_quota);
        ASSERT(artifact_command_call(&input, true, "ARTIFACT_ADMISSION_REFUSED", admitted));
        const char *reset[] = {"z23-test"};
        ParseParameters(1, reset);
        ASSERT(artifact_command_call(&input, true, NULL, admitted));
        ASSERT(memcmp(prepared, admitted, 32) == 0);
        ASSERT(artifact_registry_call(&input, true, admitted));
        ASSERT(memcmp(prepared, admitted, 32) == 0);
        json_free(&input);
        ASSERT(artifact_command_input(&input, datadir, program_path, license_path));
        struct json_value *digest = (struct json_value *)json_get(&input,
            "program_sha3_256");
        ASSERT(digest != NULL);
        json_set_str(digest,
            "0000000000000000000000000000000000000000000000000000000000000000");
        ASSERT(artifact_command_call(&input, false, "ARTIFACT_INPUT_REFUSED", prepared));
    } TEST_END
    zcl_alloc_fault_clear();
    const char *reset[] = {"z23-test"};
    ParseParameters(1, reset);
    json_free(&input);
    test_rm_rf_recursive(directory);
    return failures;
}

static int artifact_metadata_mismatch_test(bool wrong_size)
{
    int failures = 0;
    char datadir[1024];
    test_make_tmpdir(datadir, sizeof(datadir), "zcode_release_artifact",
        wrong_size ? "wrong-size" : "wrong-digest");
    struct vcs_package_store *store = vcs_package_store_open(datadir,
        VCS_PACKAGE_STORE_DEFAULT_QUOTA_BYTES);
    struct vcs_release_artifact a = artifact_labels(), verified;
    sha3_256(artifact_program, sizeof(artifact_program), a.program_digest);
    if (wrong_size) ++a.size;
    else a.program_digest[0] ^= 1;
    struct vcs_package_manifest manifest;
    vcs_package_manifest_init(&manifest);
    uint8_t *metadata = NULL, *wire = NULL, *program = NULL, root[32];
    size_t metadata_len = 0, wire_len = 0, program_len = 0;
    TEST_CASE("hash-consistent carrier refuses wrong whole-program metadata") {
        ASSERT(store != NULL);
        ASSERT(vcs_release_artifact_serialize(&a, &metadata, &metadata_len));
        ASSERT(vcs_package_content_add_file(&manifest, "LICENSE",
            VCS_PACKAGE_MODE_FILE, artifact_license, sizeof(artifact_license) - 1u));
        ASSERT(vcs_package_content_add_file(&manifest, VCS_RELEASE_ARTIFACT_PROGRAM_PATH,
            VCS_PACKAGE_MODE_EXECUTABLE, artifact_program, sizeof(artifact_program)));
        ASSERT(vcs_package_content_add_file(&manifest, VCS_RELEASE_ARTIFACT_METADATA_PATH,
            VCS_PACKAGE_MODE_FILE, metadata, metadata_len));
        ASSERT(vcs_package_manifest_serialize(&manifest, &wire, &wire_len));
        ASSERT(vcs_package_store_put_manifest(store, wire, wire_len, root) ==
            VCS_PACKAGE_STORE_OK);
        ASSERT(vcs_package_content_put_file(store, root, "LICENSE", artifact_license,
            sizeof(artifact_license) - 1u) == VCS_PACKAGE_STORE_OK);
        ASSERT(vcs_package_content_put_file(store, root, VCS_RELEASE_ARTIFACT_PROGRAM_PATH,
            artifact_program, sizeof(artifact_program)) == VCS_PACKAGE_STORE_OK);
        ASSERT(vcs_package_content_put_file(store, root, VCS_RELEASE_ARTIFACT_METADATA_PATH,
            metadata, metadata_len) == VCS_PACKAGE_STORE_OK);
        struct vcs_package_store_status status;
        ASSERT(vcs_package_store_package_status(store, root, &status) && status.complete);
        ASSERT(!vcs_release_artifact_verify(store, root, &verified, &program, &program_len));
        ASSERT(program == NULL && program_len == 0);
    } TEST_END
    free(metadata);
    free(wire);
    free(program);
    vcs_package_manifest_free(&manifest);
    vcs_package_store_close(store);
    test_rm_rf_recursive(datadir);
    return failures;
}

int test_zcode_release_artifact(void)
{
    return artifact_codec_tests() + artifact_root_tests() + artifact_store_tests()
        + artifact_partial_tests() + artifact_chunk_test()
        + artifact_corruption_test(1) + artifact_corruption_test(2)
        + artifact_command_test() + artifact_metadata_mismatch_test(false)
        + artifact_metadata_mismatch_test(true);
}
