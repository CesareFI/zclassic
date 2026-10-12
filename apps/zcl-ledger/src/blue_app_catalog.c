/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "blue_app_catalog.h"

#include <stdbool.h>
#include <string.h>

static bool valid_name(const uint8_t *bytes, size_t length) {
    if (!length || length >= ZCL_BLUE_APP_NAME_SIZE) return false;
    for (size_t i = 0; i < length; ++i)
        if (bytes[i] < 0x20 || bytes[i] > 0x7e) return false;
    return true;
}

int blue_app_catalog_parse(const uint8_t *page, size_t length,
                           blue_app_entry *entries, size_t capacity,
                           size_t *count) {
    if (!page || !entries || !count) return -1;
    *count = 0;
    if (!length) return 0;
    if (page[0] != 1) return -1;
    size_t offset = 1;
    while (offset < length) {
        if (*count == capacity || length - offset < 70) return -1;
        size_t entry_length = page[offset++];
        if (entry_length < 70 || entry_length > length - offset) return -1;
        size_t entry_end = offset + entry_length;
        blue_app_entry *entry = &entries[*count];
        uint32_t flags = 0;
        for (unsigned i = 0; i < 4; ++i)
            flags = (flags << 8) | page[offset++];
        memcpy(entry->hash_code_data, page + offset, 32);
        offset += 32;
        memcpy(entry->hash, page + offset, 32);
        offset += 32;
        size_t name_length = page[offset++];
        if (name_length != entry_end - offset ||
            !valid_name(page + offset, name_length)) return -1;
        memcpy(entry->name, page + offset, name_length);
        entry->name[name_length] = 0;
        entry->flags = flags;
        offset += name_length;
        ++*count;
    }
    return 0;
}

bool blue_app_catalog_unique_hash(const blue_app_entry *entries,
    size_t count, const char *name, const uint8_t expected[32]) {
    if (!entries || !name || !expected) return false;
    size_t found = 0;
    for (size_t i = 0; i < count; ++i) {
        if (strcmp(entries[i].name, name)) continue;
        if (memcmp(entries[i].hash, expected, 32)) return false;
        ++found;
    }
    return found == 1;
}
