/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: CLI shim that regenerates tools/dev/test_group_weights.tsv from a
 *          full cold run's .cache/test-timing/last-run.json. */

#include "test_group_weights.h"

#include <stdio.h>
#include <string.h>

static const char *arg_value(const char *arg, const char *prefix)
{
    size_t n = strlen(prefix);
    return strncmp(arg, prefix, n) == 0 ? arg + n : NULL;
}

int main(int argc, char **argv)
{
    const char *timing = ".cache/test-timing/last-run.json";
    const char *out = ZCL_TEST_GROUP_WEIGHTS_PATH;
    for (int i = 1; i < argc; i++) {
        const char *v = NULL;
        if ((v = arg_value(argv[i], "--timing=")) != NULL) {
            timing = v;
        } else if ((v = arg_value(argv[i], "--out=")) != NULL) {
            out = v;
        } else {
            fprintf(stderr,
                    "usage: test-group-weights [--timing=PATH] [--out=PATH]\n");
            return 2;
        }
    }
    char why[256] = "";
    size_t rows = 0;
    if (!zcl_test_group_weights_render(timing, out, &rows, why, sizeof(why))) {
        fprintf(stderr, "test-group-weights: refused %s: %s\n", timing, why);
        return 1;
    }
    printf("test-group-weights: wrote %zu rows (>= %u s) to %s from %s\n",
           rows, ZCL_TEST_GROUP_WEIGHT_MIN_SECONDS, out, timing);
    return 0;
}
