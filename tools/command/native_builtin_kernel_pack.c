/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Deterministic gzip packing of the built-in guest kernel. */
#include "command/native_builtin_kernel.h"

#include "base/safe_alloc.h"
#include "base/serialize_le.h"

#include <stdlib.h>
#include <zlib.h>

#define BK_HEADER 10u
#define BK_TRAILER 8u
#define BK_CHUNK ((size_t)1 << 30)

/* Feeds src to the stream in chunks and finishes it. True on Z_STREAM_END. */
static bool bk_deflate(z_stream *zs, const uint8_t *src, size_t length)
{
    size_t done = 0;
    for (;;) {
        size_t take = length - done < BK_CHUNK ? length - done : BK_CHUNK;
        zs->next_in = (Bytef *)(uintptr_t)(src + done);
        zs->avail_in = (uInt)take;
        done += take;
        int rc = deflate(zs, done == length ? Z_FINISH : Z_NO_FLUSH);
        if (rc != Z_OK && rc != Z_STREAM_END) return false;
        if (done == length) return rc == Z_STREAM_END;
    }
}

uint8_t *zcl_builtin_kernel_pack(const uint8_t *src, size_t length, size_t *out_size)
{
    static const uint8_t header[BK_HEADER] = {0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 2, 255};
    z_stream zs = {0};
    uint32_t crc = (uint32_t)crc32(0L, Z_NULL, 0);
    uint8_t *out;
    size_t bound;
    if ((uint64_t)length > ZCL_BUILTIN_KERNEL_MAX_BYTES) return NULL;
    if (deflateInit2(&zs, Z_BEST_COMPRESSION, Z_DEFLATED, -15, 9, Z_DEFAULT_STRATEGY) != Z_OK)
        return NULL;
    bound = (size_t)deflateBound(&zs, (uLong)length) + BK_HEADER + BK_TRAILER;
    out = zcl_malloc(bound, "builtin_kernel_pack");
    if (out == NULL) {
        (void)deflateEnd(&zs);
        return NULL;
    }
    for (size_t at = 0; at < length;) {
        size_t take = length - at < BK_CHUNK ? length - at : BK_CHUNK;
        crc = (uint32_t)crc32(crc, src + at, (uInt)take);
        at += take;
    }
    for (unsigned i = 0; i < BK_HEADER; i++) out[i] = header[i];
    zs.next_out = out + BK_HEADER;
    zs.avail_out = (uInt)(bound - BK_HEADER - BK_TRAILER);
    if (!bk_deflate(&zs, src, length)) {
        (void)deflateEnd(&zs);
        free(out);
        return NULL;
    }
    *out_size = BK_HEADER + (size_t)zs.total_out + BK_TRAILER;
    zcl_write_u32_le(out + *out_size - BK_TRAILER, crc);
    zcl_write_u32_le(out + *out_size - 4u, (uint32_t)length);
    (void)deflateEnd(&zs);
    return out;
}
