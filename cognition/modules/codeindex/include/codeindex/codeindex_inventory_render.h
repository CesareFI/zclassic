/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Render the capability inventory artifact and compare it with a
 * committed copy, without storing any aggregate digest of the source bytes. */
#ifndef ZCL_CODEINDEX_INVENTORY_RENDER_H
#define ZCL_CODEINDEX_INVENTORY_RENDER_H

#include "codeindex/codeindex_inventory.h"

#include <stdbool.h>
#include <stdio.h>

/* Write the complete JSON Lines artifact for `report` to `out`. Returns false
 * when the stream reports an error. Deterministic: the same report always
 * yields the same bytes. */
bool codeindex_inventory_render(FILE *out,
                                const struct ci_inventory_report *report);

/* Decide whether the file at `artifact_path` is byte-identical to the render
 * of `report`. Returns false only on a failure to render or read (context is
 * logged); an absent or different file sets *identical=false and returns
 * true. */
bool codeindex_inventory_artifact_identical(
    const struct ci_inventory_report *report, const char *artifact_path,
    bool *identical);

#endif /* ZCL_CODEINDEX_INVENTORY_RENDER_H */
