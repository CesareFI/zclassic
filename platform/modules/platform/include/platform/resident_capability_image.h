/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: declare the fixed pure resident ELF image v1 byte profile. */
/* Proposed immutable consumer API; implementation and qualification pending. */
#ifndef ZCL_PLATFORM_RESIDENT_CAPABILITY_IMAGE_H
#define ZCL_PLATFORM_RESIDENT_CAPABILITY_IMAGE_H
#include <stddef.h>
#include <stdint.h>
#define RESIDENT_CAPABILITY_IMAGE_V1_MAX_BYTES (16u * 1024u * 1024u)
#define RESIDENT_CAPABILITY_IMAGE_V1_MAX_PROGRAM_HEADERS 128u
#define RESIDENT_CAPABILITY_IMAGE_V1_MAX_DYNAMIC_ENTRIES 1024u
/* Only ELF64 little-endian x86-64 ET_EXEC/static ET_DYN, no PT_INTERP or
 * DT_NEEDED. Complete bounded header/segment extents, valid LOAD sizes and
 * alignment, executable LOAD containing entry, terminated bounded dynamic
 * tables. No I/O, host execution availability, provenance, grants or safety
 * verdict. Fixed v1 profile; no caller acceptance callback. */
enum resident_capability_image_v1_status {
    RESIDENT_CAPABILITY_IMAGE_V1_OK = 0,
    RESIDENT_CAPABILITY_IMAGE_V1_ARGUMENT,
    RESIDENT_CAPABILITY_IMAGE_V1_LENGTH,
    RESIDENT_CAPABILITY_IMAGE_V1_IDENTIFICATION,
    RESIDENT_CAPABILITY_IMAGE_V1_HEADER,
    RESIDENT_CAPABILITY_IMAGE_V1_PROGRAM_TABLE,
    RESIDENT_CAPABILITY_IMAGE_V1_SEGMENT,
    RESIDENT_CAPABILITY_IMAGE_V1_INTERPRETER,
    RESIDENT_CAPABILITY_IMAGE_V1_DYNAMIC,
    RESIDENT_CAPABILITY_IMAGE_V1_DEPENDENCY,
    RESIDENT_CAPABILITY_IMAGE_V1_ENTRY
};
struct resident_capability_image_v1_info {
    uint64_t image_bytes;
    uint64_t entry;
    uint16_t elf_type;
    uint16_t machine;
    uint16_t program_headers;
};
/* out is required and disjoint from immutable input. Output zeroed on refusal.
 * Must support unaligned bytes. No borrowed pointers or allocated resources. */
enum resident_capability_image_v1_status resident_capability_image_validate_v1(
    const uint8_t *bytes, size_t length, struct resident_capability_image_v1_info *out);
const char *resident_capability_image_status_name_v1(
    enum resident_capability_image_v1_status status);
#endif
