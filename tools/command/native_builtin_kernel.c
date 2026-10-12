/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Verified in-memory unpacking of the built-in guest kernel. */
#include "command/native_builtin_kernel.h"

#include "base/hex.h"
#include "base/safe_alloc.h"
#include "crypto/sha256.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>

static const struct zcl_builtin_kernel_pin bk_release_pin = {
    ZCL_BUILTIN_KERNEL_BYTES, ZCL_BUILTIN_KERNEL_SHA256};

const struct zcl_builtin_kernel_pin *zcl_builtin_kernel_release_pin(void)
{
    return &bk_release_pin;
}

const char *zcl_builtin_kernel_status_name(enum zcl_builtin_kernel_status status)
{
    switch (status) {
    case ZCL_BUILTIN_KERNEL_OK: return "ok";
    case ZCL_BUILTIN_KERNEL_ABSENT: return "builtin_kernel_absent";
    case ZCL_BUILTIN_KERNEL_INFLATE_FAILED: return "builtin_kernel_inflate_failed";
    case ZCL_BUILTIN_KERNEL_LENGTH_MISMATCH: return "builtin_kernel_length_mismatch";
    case ZCL_BUILTIN_KERNEL_HASH_MISMATCH: return "builtin_kernel_hash_mismatch";
    case ZCL_BUILTIN_KERNEL_TOO_LARGE: return "builtin_kernel_too_large";
    case ZCL_BUILTIN_KERNEL_NO_MEMORY: return "builtin_kernel_no_memory";
    }
    return "builtin_kernel_unknown";
}

/* Inflates one gzip member into buf (capacity cap = pinned length + 1).
 * *produced is the byte count. Returns OK when the stream ended cleanly with
 * no input left, TOO_LARGE when the output reached cap, else INFLATE_FAILED. */
static enum zcl_builtin_kernel_status bk_inflate(const uint8_t *gz, size_t gz_size,
                                                 uint8_t *buf, size_t cap, size_t *produced)
{
    z_stream zs = {0};
    enum zcl_builtin_kernel_status status = ZCL_BUILTIN_KERNEL_INFLATE_FAILED;
    int rc;
    if (gz_size > UINT_MAX || cap > UINT_MAX || inflateInit2(&zs, 16 + 15) != Z_OK)
        return status;
    zs.next_in = (Bytef *)(uintptr_t)gz;
    zs.avail_in = (uInt)gz_size;
    zs.next_out = buf;
    zs.avail_out = (uInt)cap;
    rc = inflate(&zs, Z_FINISH);
    *produced = (size_t)zs.total_out;
    if (rc == Z_STREAM_END && zs.avail_in == 0) status = ZCL_BUILTIN_KERNEL_OK;
    else if (zs.avail_out == 0 && rc != Z_DATA_ERROR) status = ZCL_BUILTIN_KERNEL_TOO_LARGE;
    (void)inflateEnd(&zs);
    return status;
}

static bool bk_hash_matches(const uint8_t *data, size_t length, const char *expected_hex)
{
    struct sha256_ctx ctx;
    uint8_t digest[SHA256_OUTPUT_SIZE];
    char hex[2 * SHA256_OUTPUT_SIZE + 1];
    sha256_init(&ctx);
    sha256_write(&ctx, data, length);
    sha256_finalize(&ctx, digest);
    zcl_hex_encode(digest, sizeof digest, hex);
    return strcmp(hex, expected_hex) == 0;
}

static enum zcl_builtin_kernel_status bk_check(uint8_t *buf, size_t produced,
                                               const struct zcl_builtin_kernel_pin *pin)
{
    if (produced > pin->length) return ZCL_BUILTIN_KERNEL_TOO_LARGE;
    if (produced != pin->length) return ZCL_BUILTIN_KERNEL_LENGTH_MISMATCH;
    if (!bk_hash_matches(buf, produced, pin->sha256_hex)) return ZCL_BUILTIN_KERNEL_HASH_MISMATCH;
    return ZCL_BUILTIN_KERNEL_OK;
}

enum zcl_builtin_kernel_status zcl_builtin_kernel_unpack(
    const uint8_t *gz, size_t gz_size, const struct zcl_builtin_kernel_pin *pin,
    uint8_t **out, size_t *out_length)
{
    enum zcl_builtin_kernel_status status;
    size_t produced = 0;
    uint8_t *buf;
    *out = NULL;
    *out_length = 0;
    if (gz == NULL || gz_size == 0) return ZCL_BUILTIN_KERNEL_ABSENT;
    if (pin->length == 0 || pin->length > ZCL_BUILTIN_KERNEL_MAX_BYTES ||
        strlen(pin->sha256_hex) != 2u * SHA256_OUTPUT_SIZE)
        return ZCL_BUILTIN_KERNEL_TOO_LARGE;
    buf = zcl_malloc((size_t)pin->length + 1u, "builtin_guest_kernel");
    if (buf == NULL) return ZCL_BUILTIN_KERNEL_NO_MEMORY;
    status = bk_inflate(gz, gz_size, buf, (size_t)pin->length + 1u, &produced);
    if (status == ZCL_BUILTIN_KERNEL_OK) status = bk_check(buf, produced, pin);
    if (status != ZCL_BUILTIN_KERNEL_OK) {
        free(buf);
        return status;
    }
    *out = buf;
    *out_length = produced;
    return ZCL_BUILTIN_KERNEL_OK;
}

enum zcl_builtin_kernel_status zcl_builtin_kernel_load(uint8_t **out, size_t *out_length)
{
    return zcl_builtin_kernel_unpack(zcl_builtin_kernel_gz, zcl_builtin_kernel_gz_size,
                                     &bk_release_pin, out, out_length);
}
