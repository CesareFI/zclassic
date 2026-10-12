/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: validate the fixed inert ELF byte profile without host loader effects. */
#include "platform/resident_capability_image.h"
#include "base/serialize_le.h"
#include <stdbool.h>
#include <string.h>

#define RCI_REASON(name) RESIDENT_CAPABILITY_IMAGE_V1_##name

static bool rci_extent(uint64_t offset, uint64_t size, uint64_t limit)
{
    return offset <= limit && size <= limit - offset;
}

static enum resident_capability_image_v1_status rci_dynamic(
    const uint8_t *bytes, uint64_t offset, uint64_t size)
{
    if (!size || size % 16 || size / 16 > RESIDENT_CAPABILITY_IMAGE_V1_MAX_DYNAMIC_ENTRIES)
        return RCI_REASON(DYNAMIC);
    for (uint64_t i = 0; i < size; i += 16) {
        uint64_t tag = zcl_read_u64_le(bytes + (size_t)(offset + i));
        if (tag == 0) return RCI_REASON(OK);
        if (tag == 1) return RCI_REASON(DEPENDENCY);
    }
    return RCI_REASON(DYNAMIC);
}

static enum resident_capability_image_v1_status rci_load(
    const uint8_t *p, uint64_t entry, bool *contains_entry)
{
    uint64_t offset = zcl_read_u64_le(p + 8), address = zcl_read_u64_le(p + 16);
    uint64_t file = zcl_read_u64_le(p + 32), memory = zcl_read_u64_le(p + 40);
    uint64_t align = zcl_read_u64_le(p + 48);
    if (file > memory || memory > UINT64_MAX - address)
        return RCI_REASON(SEGMENT);
    if (align > 1 && ((align & (align - 1)) || offset % align != address % align))
        return RCI_REASON(SEGMENT);
    if ((zcl_read_u32_le(p + 4) & 1) && entry >= address && entry - address < memory)
        *contains_entry = true;
    return RCI_REASON(OK);
}

static enum resident_capability_image_v1_status rci_programs(
    const uint8_t *bytes, size_t length, uint64_t table, unsigned count, uint64_t entry)
{
    bool contains_entry = false;
    for (unsigned i = 0; i < count; ++i) {
        const uint8_t *p = bytes + (size_t)table + (size_t)i * 56;
        uint64_t type = zcl_read_u32_le(p), offset = zcl_read_u64_le(p + 8);
        uint64_t size = zcl_read_u64_le(p + 32);
        enum resident_capability_image_v1_status status = RCI_REASON(OK);
        if (type == 3) return RCI_REASON(INTERPRETER);
        if (!rci_extent(offset, size, length)) return RCI_REASON(SEGMENT);
        if (type == 1) status = rci_load(p, entry, &contains_entry);
        if (type == 2) status = rci_dynamic(bytes, offset, size);
        if (status != RCI_REASON(OK)) return status;
    }
    return contains_entry ? RCI_REASON(OK) : RCI_REASON(ENTRY);
}

static enum resident_capability_image_v1_status rci_header(const uint8_t *bytes)
{
    if (memcmp(bytes, "\177ELF", 4) || bytes[4] != 2 || bytes[5] != 1 || bytes[6] != 1)
        return RCI_REASON(IDENTIFICATION);
    uint64_t type = zcl_read_u16_le(bytes + 16);
    if ((type != 2 && type != 3) || zcl_read_u16_le(bytes + 18) != 62 ||
        zcl_read_u32_le(bytes + 20) != 1 || zcl_read_u16_le(bytes + 52) != 64)
        return RCI_REASON(HEADER);
    return RCI_REASON(OK);
}

enum resident_capability_image_v1_status resident_capability_image_validate_v1(
    const uint8_t *bytes, size_t length, struct resident_capability_image_v1_info *out)
{
    if (!out) return RCI_REASON(ARGUMENT);
    memset(out, 0, sizeof(*out));
    if (!bytes) return RCI_REASON(ARGUMENT);
    if (length < 64 || length > RESIDENT_CAPABILITY_IMAGE_V1_MAX_BYTES)
        return RCI_REASON(LENGTH);
    enum resident_capability_image_v1_status header_status = rci_header(bytes);
    if (header_status != RCI_REASON(OK)) return header_status;
    uint64_t table = zcl_read_u64_le(bytes + 32), count = zcl_read_u16_le(bytes + 56);
    if (!count || count > RESIDENT_CAPABILITY_IMAGE_V1_MAX_PROGRAM_HEADERS ||
        zcl_read_u16_le(bytes + 54) != 56 || !rci_extent(table, count * 56, length))
        return RCI_REASON(PROGRAM_TABLE);
    uint64_t entry = zcl_read_u64_le(bytes + 24);
    enum resident_capability_image_v1_status status = rci_programs(bytes, length, table,
                                                                  (unsigned)count, entry);
    if (status != RCI_REASON(OK)) return status;
    out->image_bytes = length;
    out->entry = entry;
    out->elf_type = (uint16_t)zcl_read_u16_le(bytes + 16);
    out->machine = (uint16_t)zcl_read_u16_le(bytes + 18);
    out->program_headers = (uint16_t)count;
    return RCI_REASON(OK);
}

const char *resident_capability_image_status_name_v1(enum resident_capability_image_v1_status status)
{
    static const char *const names[] = {
        "ok", "argument", "length", "identification", "header", "program_table",
        "segment", "interpreter", "dynamic", "dependency", "entry"
    };
    return (unsigned)status < sizeof(names) / sizeof(names[0]) ? names[status] : "unknown";
}
