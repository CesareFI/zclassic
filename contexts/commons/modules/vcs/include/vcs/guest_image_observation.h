/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * guest_image_observation — unsigned copied-byte identities, never execution authority. */
#ifndef ZCL_VCS_GUEST_IMAGE_OBSERVATION_H
#define ZCL_VCS_GUEST_IMAGE_OBSERVATION_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#define VCS_GUEST_IMAGE_WIRE_BYTES 208u
#define VCS_GUEST_IMAGE_MAX_BYTES (64u * 1024u * 1024u)
#define VCS_GUEST_EVIDENCE_MAX_BYTES (1024u * 1024u)
#define VCS_GUEST_IMAGE_EVIDENCE_COUNT 3u
struct vcs_guest_image_blob { uint8_t root[32]; uint64_t bytes; };
struct vcs_guest_image_observation {
    struct vcs_guest_image_blob image;
    uint8_t image_sha256[32];
    /* Original provenance, license inventory, source inventory; opaque. */
    struct vcs_guest_image_blob evidence[VCS_GUEST_IMAGE_EVIDENCE_COUNT];
};
/* Fixed v1 COPIED_BYTES_ONLY/RV64LE; exact length and reserved bytes required. */
bool vcs_guest_image_observation_encode(const struct vcs_guest_image_observation *o,
                                       uint8_t out[VCS_GUEST_IMAGE_WIRE_BYTES]);
bool vcs_guest_image_observation_decode(const uint8_t *wire, size_t bytes,
                                       struct vcs_guest_image_observation *out);
/* Checked complete load demand, including observation208; before payload reads. */
bool vcs_guest_image_observation_budget(const struct vcs_guest_image_observation *o,
                                       uint64_t max_image, uint64_t max_total);
#endif
