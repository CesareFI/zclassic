/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * guest_image_admission — local copied image reader under independent current policy. */
#ifndef ZCL_SERVICES_GUEST_IMAGE_ADMISSION_H
#define ZCL_SERVICES_GUEST_IMAGE_ADMISSION_H
#include "base/result.h"
#include "vcs/guest_image_observation.h"
struct guest_image_admission;
/* Null observation is the pre-read root-only check. Later checks bind the
 * decoded statement. The owner independently fixes purpose/revision/image;
 * unsigned metadata never grants execution. Callback/context outlive handle. */
typedef bool (*guest_image_current_grant_fn)(
    void *context, const uint8_t observation_root[32],
    const struct vcs_guest_image_observation *observation);
/* Local existing CAS only; reads/re-hashes exact image and three opaque BLOBs.
 * Does not validate inventory semantics, reproduction, licensing or installation.
 * Initializes *out=NULL; caller owns handle only on success. */
struct zcl_result guest_image_admission_open(const char *repo, const uint8_t root[32],
    uint64_t max_image_bytes, uint64_t max_verification_bytes,
    guest_image_current_grant_fn current_grant, void *context,
    struct guest_image_admission **out);
/* Borrowed immutable copy valid until close. Requires current policy now;
 * this check does not make a future invocation or namespace immutable. */
struct zcl_result guest_image_admission_bytes(const struct guest_image_admission *handle,
                                const uint8_t **image, size_t *bytes);
struct zcl_result guest_image_admission_current(const struct guest_image_admission *handle);
void guest_image_admission_close(struct guest_image_admission **handle);
#endif
