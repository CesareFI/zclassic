/* Copyright 2026 Rhett Creighton - Apache License 2.0 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "test/component_receiver_fixture.h"
#include "devloop_reflex_runner_wire.h"
#include "vcs/build_action.h"
#include "vcs/package_manifest.h"
#include "../fixtures/reflex_runner_fixture.h"
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#if defined(__linux__) && defined(__x86_64__) && (defined(ZCL_DEV_BUILD) || defined(ZCL_TESTING))
/* These local codec fixtures test receiver admission, not an attestation that
 * their synthetic toolchain/policy roots describe independently reproduced
 * compilation. The pure fixture images are actual component-only Clang
 * builds; the caller supplies its expectations before reading the carrier. */


bool rr_component_read(const char *path, uint8_t **bytes, size_t *len)
{
    FILE *f = fopen(path, "rb");
    if (!f) return false;
    bool ok = fseek(f, 0, SEEK_END) == 0;
    long size = ok ? ftell(f) : -1;
    ok = size > 0 && size <= VCS_PACKAGE_CHUNK_BYTES &&
        fseek(f, 0, SEEK_SET) == 0;
    *bytes = ok ? malloc((size_t)size) : NULL;
    ok = ok && *bytes && fread(*bytes, 1, (size_t)size, f) == (size_t)size;
    if (ok) *len = (size_t)size;
    (void)fclose(f);
    return ok;
}

static bool rr_component_action(struct rr_component *c, const char *target)
{
    struct vcs_action_env_v2 env[32];
    size_t count = 0;
    const char *const *names = vcs_action_v2_env_allowlist(&count);
    if (count > 32) return false;
    for (size_t i = 0; i < count; ++i)
        env[i] = (struct vcs_action_env_v2){names[i], false, NULL};
    const char *const argv[] = { "clang", "-target", target, "-shared" };
    const char *const mixed[] = { "clang", "-target", ZCL_COMPONENT_TARGET,
        "-target", "aarch64-linux-gnu", "-shared" };
    bool ambiguous = strcmp(target, "ambiguous") == 0;
    const char *const link[] = { "ld", "-shared", "@out/component.so" };
    struct vcs_action_abi_v2 abi = { "zcl_hotfork_capsule", 1 };
    struct vcs_action_preimage_v2 a = {
        .stage_kind = ZCL_COMPONENT_STAGE, .stage_version = 1,
        .argv = ambiguous ? mixed : argv, .argc = ambiguous ? 6 : 4,
        .env = env, .env_count = count,
        .abi_generation = 1, .abi = &abi, .abi_count = 1,
        .linker = { .links = true, .ld = "@sys/usr/bin/ld",
                    .argv = link, .argc = 3 },
        .harness.present = true, .fixtures.present = true,
        .policy.present = true,
    };
    memcpy(a.toolchain_root, c->request.toolchain_root, 32);
    memcpy(a.sysroot.objects_sha3, c->request.sysroot_root, 32);
    memcpy(a.linker.ld_sha3, c->request.toolchain_root, 32);
    memcpy(a.harness.root, c->request.harness_root, 32);
    memcpy(a.fixtures.root, c->request.fixtures_root, 32);
    memcpy(a.policy.root, c->request.policy_root, 32);
    char why[192];
    return vcs_action_preimage_v2_encode(&a, &c->action, &c->action_len,
        why, sizeof(why)) && vcs_action_root_v2_from_bytes(c->action,
        c->action_len, c->request.action_root, why, sizeof(why));
}

static bool rr_component_artifact(struct rr_component *c, bool wrong_action)
{
    struct vcs_build_artifact_manifest_v1 m = {
        .total_bytes = c->image_len,
        .chunk_bytes = VCS_PACKAGE_CHUNK_BYTES, .chunk_count = 1,
    };
    memcpy(m.action_sha3, c->request.action_root, 32);
    if (wrong_action) m.action_sha3[0] ^= 1;
    return vcs_package_chunk_hash(c->image, c->image_len, m.chunk_sha3[0]) &&
        vcs_build_artifact_manifest_v1_serialize(&m, c->artifact,
            sizeof(c->artifact), &c->artifact_len) &&
        vcs_build_artifact_manifest_v1_root(&m, c->request.artifact_root);
}

static bool rr_component_image(struct rr_component *c, unsigned revision)
{
    char path[256], object[280];
    (void)snprintf(path, sizeof(path),
        "build/fixtures/reflex_runner/zcl_reflex_pure_%u.so", revision);
    (void)snprintf(object, sizeof(object), "%s.story.o", path);
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    bool ok = fd >= 0 && zcl_reflex_sha256_fd(fd, c->image_sha);
    if (fd >= 0) (void)close(fd);
    fd = open(object, O_RDONLY | O_CLOEXEC);
    ok = ok && fd >= 0 && zcl_reflex_sha256_fd(fd, c->object_sha);
    if (fd >= 0) (void)close(fd);
    if (!ok || !rr_component_read(path, &c->image, &c->image_len)) return false;
    c->request.execution = (struct zcl_reflex_runner_spec){
        .mode = ZCL_REFLEX_MODE_HOT_FORK, .artifact_path = path,
        .artifact_sha256 = c->image_sha, .owner_id = ZCL_REFLEX_FIXTURE_OWNER,
        .source_tu = ZCL_REFLEX_FIXTURE_SOURCE,
        .candidate_object_root = c->object_sha,
        .story_id = ZCL_REFLEX_FIXTURE_STORY,
        .story_root = ZCL_REFLEX_FIXTURE_STORY_ROOT,
        .story_fixture_root = ZCL_REFLEX_FIXTURE_FIXTURE_ROOT,
        .timeout_ms = 1000,
    };
    /* Descriptor execution is FD-only; this deliberately unusable locator
     * ensures no pathname reconstruction can supply the candidate. */
    c->request.execution.artifact_path = "absent-receiver-component.so";
    return true;
}

static bool rr_component_package(struct vcs_package_store *store,
    struct rr_component *c, bool wrong_shape)
{
    const char *paths[] = { ZCL_COMPONENT_ACTION_PATH,
        ZCL_COMPONENT_MANIFEST_PATH, ZCL_COMPONENT_IMAGE_PATH };
    const uint8_t *bytes[] = {c->action, c->artifact, c->image};
    const size_t lengths[] = {c->action_len, c->artifact_len, c->image_len};
    if (wrong_shape) paths[2] = "other.so";
    struct vcs_package_manifest m;
    vcs_package_manifest_init(&m);
    bool ok = true;
    for (size_t i = 0; ok && i < 3; ++i) {
        uint8_t hash[32];
        ok = vcs_package_chunk_hash(bytes[i], lengths[i], hash) &&
            vcs_package_manifest_add(&m, paths[i], VCS_PACKAGE_MODE_FILE,
                lengths[i], hash, 1);
    }
    uint8_t *wire = NULL;
    size_t len = 0;
    ok = ok && vcs_package_manifest_serialize(&m, &wire, &len) &&
        vcs_package_store_put_manifest(store, wire, len,
            c->request.package_root) == VCS_PACKAGE_STORE_OK;
    for (size_t i = 0; ok && i < 3; ++i)
        ok = vcs_package_store_put_chunk(store, c->request.package_root,
            paths[i], 0, bytes[i], lengths[i]) == VCS_PACKAGE_STORE_OK;
    free(wire);
    vcs_package_manifest_free(&m);
    return ok;
}

bool rr_component_assemble(struct vcs_package_store *store,
    struct rr_component *c, const char *target, bool wrong_action,
    bool wrong_shape)
{
    memset(c->request.toolchain_root, 1, 32);
    memset(c->request.sysroot_root, 2, 32);
    memset(c->request.harness_root, 3, 32);
    memset(c->request.fixtures_root, 4, 32);
    memset(c->request.policy_root, 5, 32);
    c->request.execution.artifact_path = "absent-receiver-component.so";
    c->request.execution.artifact_sha256 = c->image_sha;
    c->request.execution.candidate_object_root = c->object_sha;
    return rr_component_action(c, target) &&
        rr_component_artifact(c, wrong_action) &&
        rr_component_package(store, c, wrong_shape);
}

bool rr_component_prepare_pure(struct vcs_package_store *store,
    struct rr_component *c, unsigned revision, const char *target,
    bool wrong_action, bool wrong_shape)
{
    return rr_component_image(c, revision) && rr_component_assemble(store,
        c, target, wrong_action, wrong_shape);
}

static void rr_component_public_bounds(enum rr_component_public_shape shape,
    const char **paths, size_t *begin, size_t *end)
{
    *begin = shape == RR_COMPONENT_PUBLIC_NO_LICENSE ? 1u : 0u;
    *end = shape == RR_COMPONENT_PUBLIC_EXTRA || shape == RR_COMPONENT_PUBLIC_DUPLICATE ? 5u : 4u;
    if (shape == RR_COMPONENT_PUBLIC_WRONG_PATH) paths[3] = "other.so";
    if (shape == RR_COMPONENT_PUBLIC_DUPLICATE) paths[4] = "LICENSE";
}

bool rr_component_public_variant(struct vcs_package_store *store,
    const struct rr_component *c, const uint8_t *license, size_t license_len,
    enum rr_component_public_shape shape,
    struct zcl_component_receiver_public_request *public_request)
{
    const char *paths[] = { "LICENSE", ZCL_COMPONENT_ACTION_PATH,
        ZCL_COMPONENT_MANIFEST_PATH, ZCL_COMPONENT_IMAGE_PATH, "extra" };
    const uint8_t *bytes[] = {license, c->action, c->artifact, c->image, license};
    const size_t lengths[] = {license_len, c->action_len, c->artifact_len, c->image_len, license_len};
    size_t begin = 0, end = 0;
    rr_component_public_bounds(shape, paths, &begin, &end);
    struct vcs_package_manifest m;
    vcs_package_manifest_init(&m);
    bool ok = true;
    for (size_t i = begin; ok && i < end; ++i) {
        uint8_t hash[32];
        ok = lengths[i] > 0 && lengths[i] <= VCS_PACKAGE_CHUNK_BYTES &&
            vcs_package_chunk_hash(bytes[i], lengths[i], hash) &&
            vcs_package_manifest_add(&m, paths[i], VCS_PACKAGE_MODE_FILE,
                                     lengths[i], hash, 1);
    }
    uint8_t *wire = NULL;
    size_t len = 0;
    public_request->component = c->request;
    public_request->allow_release_admission = true;
    ok = ok && vcs_package_manifest_serialize(&m, &wire, &len) &&
        vcs_package_store_put_manifest(store, wire, len,
            public_request->component.package_root) == VCS_PACKAGE_STORE_OK;
    for (size_t i = begin; ok && i < end; ++i)
        ok = vcs_package_store_put_chunk(store, public_request->component.package_root,
            paths[i], 0, bytes[i], lengths[i]) == VCS_PACKAGE_STORE_OK;
    free(wire);
    vcs_package_manifest_free(&m);
    return ok;
}

bool rr_component_public_package(struct vcs_package_store *store,
    const struct rr_component *c, const uint8_t *license, size_t license_len,
    struct zcl_component_receiver_public_request *request)
{
    return rr_component_public_variant(store, c, license, license_len,
                                      RR_COMPONENT_PUBLIC_EXACT, request);
}

void rr_component_free(struct rr_component *c)
{
    free(c->image);
    free(c->action);
    c->image = NULL;
    c->action = NULL;
    c->image_len = 0;
    c->action_len = 0;
    memset(&c->request, 0, sizeof(c->request));
}

#endif
