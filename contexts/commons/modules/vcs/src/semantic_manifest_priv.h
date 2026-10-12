/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Private cursor and record-parse helpers shared by the semantic manifest reader, builder and diff. */
#ifndef ZCL_VCS_SEMANTIC_MANIFEST_PRIV_H
#define ZCL_VCS_SEMANTIC_MANIFEST_PRIV_H

#include "vcs/semantic_manifest.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define SM_REC_MAX 16

struct sm_cur {
    const uint8_t *p;
    size_t len;
    size_t off;
};

struct sm_span {
    const uint8_t *p;
    size_t len;
};

/* Previous element of a strictly increasing sequence. */
struct sm_elem {
    bool have;
    const uint8_t *p;
    size_t len;
    uint32_t num;
};

/* Scalar fields and top-level texts of one parsed record, in schema order
 * (list counts are captured as numbers; list elements are not). */
struct sm_rec {
    struct sm_span text[SM_REC_MAX];
    size_t ntext;
    uint64_t num[SM_REC_MAX];
    size_t nnum;
    /* Top-level 32-byte digests (h fields), in schema order. */
    const uint8_t *digest[2];
    size_t ndigest;
    /* Bytes covered by the first two fields: the record's key. */
    size_t key_len;
};

bool sm_take(struct sm_cur *c, size_t n, const uint8_t **out);
bool sm_u32(struct sm_cur *c, uint32_t *v);
bool sm_text(struct sm_cur *c, const uint8_t **s, size_t *n);
bool sm_path_ok(const uint8_t *s, size_t n, bool allow_dir_root);
bool sm_argv_ok(const uint8_t *s, size_t n);
bool sm_parse_record(const uint8_t *p, size_t n,
                     enum vcs_semantic_section_v1 section, struct sm_rec *r);
/* Split a manifest into its section payloads (framing only). */
bool sm_sections(const uint8_t *bytes, size_t len,
                 struct sm_span out[VCS_SEMANTIC_SECTION_V1_COUNT]);
/* True when the optional facts extension block is present. */
bool sm_has_facts(const struct sm_span sec[VCS_SEMANTIC_SECTION_V1_COUNT]);
/* The field-code schema of one section (see semantic_manifest.c). */
const char *sm_schema(enum vcs_semantic_section_v1 section);

#endif /* ZCL_VCS_SEMANTIC_MANIFEST_PRIV_H */
