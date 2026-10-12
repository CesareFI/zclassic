/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Resolve the BUILD needs of the groups a test selector runs. */

#ifndef ZCL_TEST_SELECTION_BUILD_NEEDS_H
#define ZCL_TEST_SELECTION_BUILD_NEEDS_H

#include "test_group_host_need.h"

#include <stdbool.h>
#include <stddef.h>

/* A gate a run applies on top of its selector (the runner's params-heavy
 * opt-in): true leaves the group out. NULL gates nothing. */
typedef bool (*zcl_test_selection_gate_fn)(const char *group);

/* Collect into needs[0..*n) the BUILD needs (tools/dev/test_group_host_needs.def)
 * of every catalog group that `only` selects -- NULL selects every group,
 * `only_exact` reads a comma-separated set of full ids, otherwise `only` is
 * the runner's --only substring -- and `gated` does not leave out. Each Make
 * target is named once, in catalog order. A selection whose groups declare
 * none leaves *n == 0. False is a refusal: an invalid table, or more targets
 * than `cap`. */
bool zcl_test_selection_build_needs(const char *only, bool only_exact,
                                    zcl_test_selection_gate_fn gated,
                                    struct zcl_test_group_host_need *needs,
                                    size_t cap, size_t *n);

#endif /* ZCL_TEST_SELECTION_BUILD_NEEDS_H */
