/* Copyright 2026 Rhett Creighton - Apache License 2.0 */
#ifndef ZCL_TEST_COMPONENT_RECEIVER_FIXTURE_H
#define ZCL_TEST_COMPONENT_RECEIVER_FIXTURE_H
#include "component_receiver.h"
#include "vcs/build_artifact_manifest.h"
/* Zero-initialize before first use; free before preparing again. Do not copy
 * or move this state: execution pointers refer to its inline digest arrays.
 * Image/action buffers remain owned on failure; free is idempotent. The CAS
 * store is caller-owned and may retain partial inert objects after failure.
 * Synthetic codec roots establish no observed compiler/linker provenance. */
struct rr_component {
    struct zcl_component_receiver_request request;
    char image_sha[65];
    char object_sha[65];
    uint8_t *image;
    size_t image_len;
    uint8_t *action;
    size_t action_len;
    uint8_t artifact[VCS_BUILD_ARTIFACT_WIRE_MAX];
    size_t artifact_len;
};
bool rr_component_read(const char *, uint8_t **, size_t *);
bool rr_component_assemble(struct vcs_package_store *, struct rr_component *,
    const char *, bool, bool);
bool rr_component_prepare_pure(struct vcs_package_store *, struct rr_component *,
    unsigned, const char *, bool, bool);
/* Add a distinct licensed public package; retain the original local root.
 * Execution digest pointers continue to borrow the unmoved carrier. */
enum rr_component_public_shape {
    RR_COMPONENT_PUBLIC_EXACT, RR_COMPONENT_PUBLIC_EXTRA,
    RR_COMPONENT_PUBLIC_WRONG_PATH, RR_COMPONENT_PUBLIC_NO_LICENSE,
    RR_COMPONENT_PUBLIC_DUPLICATE,
};
bool rr_component_public_variant(struct vcs_package_store *,
    const struct rr_component *, const uint8_t *, size_t,
    enum rr_component_public_shape, struct zcl_component_receiver_public_request *);
bool rr_component_public_package(struct vcs_package_store *,
    const struct rr_component *, const uint8_t *, size_t,
    struct zcl_component_receiver_public_request *);
void rr_component_free(struct rr_component *);
#endif
