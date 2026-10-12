/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * Receiver policy inputs and measured outcomes for fetched native components. */
#ifndef ZCL_DEV_COMPONENT_RECEIVER_H
#define ZCL_DEV_COMPONENT_RECEIVER_H

#include "devloop_reflex_runner.h"
#include "vcs/package_store.h"

#define ZCL_COMPONENT_ACTION_PATH "action-preimage.v2"
#define ZCL_COMPONENT_MANIFEST_PATH "artifact-manifest.v1"
#define ZCL_COMPONENT_IMAGE_PATH "component.so"
#define ZCL_COMPONENT_TARGET "x86_64-linux-gnu"
#define ZCL_COMPONENT_STAGE "c23.component.link"

/* Expectations belong to the receiving caller's explicit local policy. None
 * may be populated by trusting the objects being received. This development
 * fixture adapter grants no signature, reproduction, installation or release
 * authority. candidate_object_root retains the input TU's SHA-256 meaning. */
struct zcl_component_receiver_request {
    uint8_t package_root[32];
    uint8_t action_root[32];
    uint8_t artifact_root[32];
    uint8_t toolchain_root[32];
    uint8_t sysroot_root[32];
    uint8_t harness_root[32];
    uint8_t fixtures_root[32];
    /* Compile/action policy committed by action-v2. Receiver execution
     * grants remain separate local authority, outside these identities. */
    uint8_t policy_root[32];
    struct zcl_reflex_runner_spec execution;
};

struct zcl_component_receiver_outcome {
    uint64_t manifest_bytes_read;
    uint64_t cas_chunk_bytes_read;
    uint64_t artifact_chunk_bytes_verified;
    uint64_t assembly_bytes_written;
    uint64_t sealed_copy_bytes;
    uint64_t component_bytes;
    bool admitted; /* Bound identity/profile only; no execution grant. */
    char reason[192];
    struct zcl_reflex_runner_outcome runner;
};

/* Read an already fetched ordinary content.v2 package, verify its exact
 * action-v2/build-manifest/ELF bindings, then execute only in the existing
 * confined disposable runner. No network, compiler or linker is invoked.
 * Counters describe successful explicit reads/copies, not kernel page faults
 * or an exhaustive hash census. The runner's additional copy/hash is excluded
 * from these byte counters; its sealing time is reported in runner.seal_us. */
bool zcl_component_receiver_run(struct vcs_package_store *store,
    const struct zcl_component_receiver_request *request,
    struct zcl_component_receiver_outcome *out);

/* Release-state mutation is a separate local grant from execution. Both
 * public entries may persist/touch release state, including duplicates. */
struct zcl_component_receiver_public_request {
    struct zcl_component_receiver_request component;
    uint8_t release_blob_root[32];
    bool allow_release_admission;
};
struct zcl_component_receiver_public_outcome {
    struct zcl_component_receiver_outcome component;
    bool admission_attempted;
    bool release_stored;
    enum vcs_package_accept_result acceptance;
    uint8_t release_id[32];
};
/* Admit received release bytes and a licensed exact four-file package.
 * This is inert receiver-store mutation, never an execution grant. */
bool zcl_component_receiver_public_admit(struct vcs_package_store *store,
    const struct zcl_component_receiver_public_request *request,
    struct zcl_component_receiver_public_outcome *out);
/* Re-admit the selected release, require DUPLICATE, then use the existing
 * explicit execution grant. First-time OK persists but refuses execution;
 * a historical release below the current publisher cursor remains stale. */
bool zcl_component_receiver_run_public(struct vcs_package_store *store,
    const struct zcl_component_receiver_public_request *request,
    struct zcl_component_receiver_public_outcome *out);

#endif
