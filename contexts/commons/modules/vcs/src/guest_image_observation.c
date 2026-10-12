/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * guest_image_observation — bounded unsigned copied-byte codec and load budget. */
#include "vcs/guest_image_observation.h"
#include "vcs_priv.h"
#include "base/log_macros.h"
#include <string.h>

static const uint8_t gio_header[16] = {'Z','2','3','G','I','O','0','1',1,1,1,0,0,0,0,0};
static bool gio_nonzero(const uint8_t p[32])
{
    uint8_t bits = 0;
    for (size_t i = 0; i < 32; ++i) bits |= p[i];
    return bits != 0;
}
static bool gio_shape(const struct vcs_guest_image_observation *o)
{
    if (!o || !gio_nonzero(o->image.root) || !gio_nonzero(o->image_sha256) ||
        !o->image.bytes || o->image.bytes > VCS_GUEST_IMAGE_MAX_BYTES)
        LOG_FAIL("guest-image", "invalid copied image identity/size");
    for (size_t i = 0; i < VCS_GUEST_IMAGE_EVIDENCE_COUNT; ++i) {
        if (!gio_nonzero(o->evidence[i].root) || !o->evidence[i].bytes ||
            o->evidence[i].bytes > VCS_GUEST_EVIDENCE_MAX_BYTES)
            LOG_FAIL("guest-image", "invalid opaque evidence identity/size index=%zu", i);
    }
    return true;
}
static void gio_write_blob(uint8_t *p, const struct vcs_guest_image_blob *b)
{
    memcpy(p, b->root, 32);
    vcs_wr_u64le(p + 32, b->bytes);
}
static void gio_read_blob(const uint8_t *p, struct vcs_guest_image_blob *b)
{
    memcpy(b->root, p, 32);
    b->bytes = vcs_rd_u64le(p + 32);
}
bool vcs_guest_image_observation_encode(const struct vcs_guest_image_observation *o,
                                       uint8_t out[VCS_GUEST_IMAGE_WIRE_BYTES])
{
    if (!out || !gio_shape(o))
        LOG_FAIL("guest-image", "observation encode refused");
    memcpy(out, gio_header, sizeof(gio_header));
    memcpy(out + 16, o->image.root, 32);
    memcpy(out + 48, o->image_sha256, 32);
    vcs_wr_u64le(out + 80, o->image.bytes);
    for (size_t i = 0; i < VCS_GUEST_IMAGE_EVIDENCE_COUNT; ++i)
        gio_write_blob(out + 88 + 40 * i, &o->evidence[i]);
    return true;
}
bool vcs_guest_image_observation_decode(const uint8_t *wire, size_t bytes,
                                       struct vcs_guest_image_observation *out)
{
    if (out) memset(out, 0, sizeof(*out));
    if (!wire || !out || bytes != VCS_GUEST_IMAGE_WIRE_BYTES ||
        memcmp(wire, gio_header, sizeof(gio_header)) != 0)
        LOG_FAIL("guest-image", "unknown/malformed copied observation");
    struct vcs_guest_image_observation parsed = {0};
    memcpy(parsed.image.root, wire + 16, 32);
    memcpy(parsed.image_sha256, wire + 48, 32);
    parsed.image.bytes = vcs_rd_u64le(wire + 80);
    for (size_t i = 0; i < VCS_GUEST_IMAGE_EVIDENCE_COUNT; ++i)
        gio_read_blob(wire + 88 + 40 * i, &parsed.evidence[i]);
    if (!gio_shape(&parsed))
        LOG_FAIL("guest-image", "decoded observation shape refused");
    *out = parsed;
    return true;
}
bool vcs_guest_image_observation_budget(const struct vcs_guest_image_observation *o,
                                       uint64_t max_image, uint64_t max_total)
{
    if (!gio_shape(o) || o->image.bytes > max_image)
        LOG_FAIL("guest-image", "image exceeds caller bound");
    uint64_t sum = VCS_GUEST_IMAGE_WIRE_BYTES;
    if (o->image.bytes > UINT64_MAX - sum)
        LOG_FAIL("guest-image", "image load budget overflow");
    sum += o->image.bytes;
    for (size_t i = 0; i < VCS_GUEST_IMAGE_EVIDENCE_COUNT; ++i) {
        if (o->evidence[i].bytes > UINT64_MAX - sum)
            LOG_FAIL("guest-image", "evidence load budget overflow");
        sum += o->evidence[i].bytes;
    }
    if (sum > max_total)
        LOG_FAIL("guest-image", "aggregate load budget refused");
    return true;
}
