/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Compile the real command entry point with a deterministic failed reader.
 * Keep this source outside the manifest directories read by the ledger.
 */
#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif
#include "clang_manifest.h"

static bool smt_root_failed_read(const char *path, uint8_t **out, size_t *len)
{
    /* The real reader owns the allocation; force refusal only after setup.
     * A failed setup adds stderr so it cannot match the expected diagnostic. */
    if (!cm_read_file(path, out, len))
        fprintf(stderr, "root-fixture: setup read failed\n");
    return false;
}

#define cm_read_file smt_root_failed_read
#include "../../../tools/sensors/clang_manifest.c"
