/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * guest_image_admission — bounded CAS copied bytes with independent grant checks. */
#include "services/guest_image_admission.h"
#include "vcs/vcs_object.h"
#include "base/cleanse.h"
#include "base/result.h"
#include "base/safe_alloc.h"
#include "crypto/sha256.h"
#include "sha3/sha3.h"
#include <stdlib.h>
#include <string.h>

struct guest_image_admission {
    uint8_t root[32];
    struct vcs_guest_image_observation observation;
    uint8_t *image;
    size_t bytes;
    guest_image_current_grant_fn grant;
    void *context;
};
static bool gia_root_nonzero(const uint8_t root[32])
{
    if (!root) return false;
    uint8_t bits = 0;
    for (size_t i = 0; i < 32; ++i) bits |= root[i];
    return bits != 0;
}
static struct zcl_result gia_blob(const char *repo, const uint8_t root[32], uint64_t expected,
                     uint8_t **out, size_t *bytes)
{
    *out = NULL;
    *bytes = 0;
    if (expected > SIZE_MAX ||
        vcs_object_load_raw_bounded(repo, root, (size_t)expected, out, bytes) != 0)
        return ZCL_ERR(-1, "bounded CAS load refused");
    struct sha3_256_ctx hash;
    uint8_t digest[32], tag = VCS_TAG_BLOB;
    sha3_256_init(&hash);
    sha3_256_write(&hash, &tag, 1);
    sha3_256_write(&hash, *out, *bytes);
    sha3_256_finalize(&hash, digest);
    if (*bytes != expected || memcmp(digest, root, 32) != 0) {
        memory_cleanse(*out, *bytes);
        free(*out);
        *out = NULL;
        *bytes = 0;
        return ZCL_ERR(-1, "CAS copied size/root mismatch");
    }
    return ZCL_OK;
}
static struct zcl_result gia_evidence(const char *repo, const struct vcs_guest_image_observation *o)
{
    for (size_t i = 0; i < VCS_GUEST_IMAGE_EVIDENCE_COUNT; ++i) {
        uint8_t *content = NULL;
        size_t bytes = 0;
        if (!gia_blob(repo, o->evidence[i].root, o->evidence[i].bytes, &content, &bytes).ok)
            return ZCL_ERR(-1, "opaque evidence copy refused index=%zu", i);
        free(content);
    }
    return ZCL_OK;
}
static struct zcl_result gia_image_digest(const struct guest_image_admission *h)
{
    struct sha256_ctx hash;
    uint8_t digest[32];
    sha256_init(&hash);
    sha256_write(&hash, h->image, h->bytes);
    sha256_finalize(&hash, digest);
    if (memcmp(digest, h->observation.image_sha256, 32) != 0)
        return ZCL_ERR(-1, "copied image SHA256 mismatch");
    return ZCL_OK;
}
void guest_image_admission_close(struct guest_image_admission **handle)
{
    if (!handle || !*handle) return;
    struct guest_image_admission *h = *handle;
    if (h->image) memory_cleanse(h->image, h->bytes);
    free(h->image);
    memory_cleanse(h, sizeof(*h));
    free(h);
    *handle = NULL;
}
struct zcl_result guest_image_admission_current(const struct guest_image_admission *h)
{
    if (!h || !h->grant || !h->grant(h->context, h->root, &h->observation))
        return ZCL_ERR(-1, "current independent image grant refused");
    return ZCL_OK;
}
static struct zcl_result gia_observation(const char *repo, const uint8_t root[32],
                            struct vcs_guest_image_observation *out)
{
    uint8_t *wire = NULL;
    size_t bytes = 0;
    if (!gia_blob(repo, root, VCS_GUEST_IMAGE_WIRE_BYTES, &wire, &bytes).ok)
        return ZCL_ERR(-1, "observation CAS copy refused");
    bool ok = vcs_guest_image_observation_decode(wire, bytes, out);
    free(wire);
    if (!ok) return ZCL_ERR(-1, "observation decode refused");
    return ZCL_OK;
}
static struct zcl_result gia_pre_read(const char *repo, const uint8_t root[32],
    uint64_t max_total, guest_image_current_grant_fn grant, void *context,
    struct guest_image_admission **out)
{
    if (!repo || !*repo || !out || !gia_root_nonzero(root) || !grant ||
        max_total < VCS_GUEST_IMAGE_WIRE_BYTES || !grant(context, root, NULL))
        return ZCL_ERR(-1, "local image pre-read policy/input refused");
    return ZCL_OK;
}
struct zcl_result guest_image_admission_open(const char *repo, const uint8_t root[32],
    uint64_t max_image, uint64_t max_total,
    guest_image_current_grant_fn grant, void *context,
    struct guest_image_admission **out)
{
    if (out) *out = NULL;
    struct zcl_result pre_read = gia_pre_read(repo, root, max_total, grant, context, out);
    if (!pre_read.ok) return pre_read;
    struct vcs_guest_image_observation observation;
    if (!gia_observation(repo, root, &observation).ok ||
        !vcs_guest_image_observation_budget(&observation, max_image, max_total) ||
        !grant(context, root, &observation))
        return ZCL_ERR(-1, "decoded image policy/budget refused");
    struct guest_image_admission *h = zcl_calloc(1, sizeof(*h), "guest-image-admission");
    if (!h) return ZCL_ERR(-1, "image handle allocation refused");
    memcpy(h->root, root, 32);
    h->observation = observation;
    h->grant = grant;
    h->context = context;
    bool ok = gia_blob(repo, observation.image.root, observation.image.bytes,
                       &h->image, &h->bytes).ok &&
              gia_image_digest(h).ok && gia_evidence(repo, &observation).ok &&
              guest_image_admission_current(h).ok;
    if (!ok) {
        guest_image_admission_close(&h);
        return ZCL_ERR(-1, "local copied image verification refused");
    }
    *out = h;
    return ZCL_OK;
}
struct zcl_result guest_image_admission_bytes(const struct guest_image_admission *h,
                                const uint8_t **image, size_t *bytes)
{
    if (image) *image = NULL;
    if (bytes) *bytes = 0;
    if (!image || !bytes || !guest_image_admission_current(h).ok)
        return ZCL_ERR(-1, "copied image access refused");
    *image = h->image;
    *bytes = h->bytes;
    return ZCL_OK;
}
