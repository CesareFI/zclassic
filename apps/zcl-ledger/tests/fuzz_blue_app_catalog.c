/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "blue_app_catalog.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    blue_app_entry entries[16] = {0};
    size_t count = 0;
    if (blue_app_catalog_parse(data, size, entries, 16, &count) < 0)
        return 0;
    if (count > 16) abort();
    for (size_t i = 0; i < count; ++i) {
        size_t length = 0;
        while (length < ZCL_BLUE_APP_NAME_SIZE && entries[i].name[length]) {
            if (entries[i].name[length] < 0x20 ||
                entries[i].name[length] > 0x7e) abort();
            ++length;
        }
        if (!length || length == ZCL_BLUE_APP_NAME_SIZE) abort();
    }
    return 0;
}
