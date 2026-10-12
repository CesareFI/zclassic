/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Canonical semantic manifest v1 of one C23 translation unit: builder, strict decoder, roots and section diff. */

#ifndef ZCL_VCS_SEMANTIC_MANIFEST_H
#define ZCL_VCS_SEMANTIC_MANIFEST_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "sha3/sha3.h"

/* A semantic manifest records what a compiler front end saw in one
 * translation unit: its compiler/target/argv/search-list identity, every
 * file it read (by content), include lookups with their negative probes,
 * repo macros, declarations, record layouts, enum values, function
 * definitions (by token hash) and their source spans. The optional facts
 * extension (sections 10-15) adds canonical symbols, direct reference edges,
 * explicit UNKNOWN effects, snapshot namespace probes and truncation records.
 * Any producer (the libclang sensor in tools/sensors/, or a future native
 * Z23 front end) emits the same bytes;
 * this module is the only reader and has no compiler dependency. The byte
 * format is specified in docs/work/SEMANTIC_MANIFEST.md:
 *
 *   manifest = MAGIC || section(1) || ... || section(9)
 *              [ || section(10) || ... || section(15) ]   (facts extension)
 *   section  = u8 tag || u32le payload_len || payload
 *   payload  = u32le record_count || record*
 *   record   = u32le record_len || record_bytes
 *   root         = SHA3-256(VCS_SEMANTIC_ROOT_V1_DOMAIN || manifest)
 *   section_root = SHA3-256(VCS_SEMANTIC_SECTION_ROOT_V1_DOMAIN || u8 tag
 *                           || payload)
 *
 * Every section is present exactly once in tag order. Records inside a
 * section are strictly increasing by memcmp over record_bytes (a proper
 * prefix sorts first), so a duplicate is refused, never normalized. The
 * identity section holds exactly one record. Paths are repo-relative or
 * "@sys/..." (system/sysroot); no absolute host path, mtime, hostname or
 * uid can be represented. */
#define VCS_SEMANTIC_MANIFEST_V1_MAGIC "zcl.semantic_manifest.v1"
#define VCS_SEMANTIC_ROOT_V1_DOMAIN "zcl.semantic_root.v1"
#define VCS_SEMANTIC_SECTION_ROOT_V1_DOMAIN "zcl.semantic_section_root.v1"
#define VCS_SEMANTIC_FN_TOKENS_V1_DOMAIN "zcl.semantic_fn_tokens.v1"
#define VCS_SEMANTIC_HINT_ROOT_V1_DOMAIN "zcl.semantic_hint_root.v1"
#define VCS_SEMANTIC_MANIFEST_V1_MAX_BYTES (256u * 1024u * 1024u)
#define VCS_SEMANTIC_MANIFEST_V1_MAX_RECORDS (1u << 22)
#define VCS_SEMANTIC_MANIFEST_V1_MAX_TEXT (1u << 20)
/* The closed environment allowlist, sorted; the identity names all of it. */
#define VCS_SEMANTIC_ENV_V1_ALLOWLIST "CPATH", "C_INCLUDE_PATH"

enum vcs_semantic_section_v1 {
    VCS_SEMANTIC_SECTION_V1_NONE = 0,
    VCS_SEMANTIC_SECTION_V1_IDENTITY = 1,
    VCS_SEMANTIC_SECTION_V1_FILES = 2,
    VCS_SEMANTIC_SECTION_V1_LOOKUPS = 3,
    VCS_SEMANTIC_SECTION_V1_MACROS = 4,
    VCS_SEMANTIC_SECTION_V1_DECLS = 5,
    VCS_SEMANTIC_SECTION_V1_LAYOUTS = 6,
    VCS_SEMANTIC_SECTION_V1_ENUMS = 7,
    VCS_SEMANTIC_SECTION_V1_FUNCTIONS = 8,
    VCS_SEMANTIC_SECTION_V1_SPANS = 9,
    /* The optional facts extension (zcl.semantic_facts.v1): present as a
     * block of all six sections, in tag order, after SPANS, or absent. A
     * manifest without it is byte-identical to a plain v1 manifest. */
    VCS_SEMANTIC_SECTION_V1_FACTS = 10,
    VCS_SEMANTIC_SECTION_V1_SYMBOLS = 11,
    VCS_SEMANTIC_SECTION_V1_REFS = 12,
    VCS_SEMANTIC_SECTION_V1_UNKNOWNS = 13,
    VCS_SEMANTIC_SECTION_V1_PROBES = 14,
    VCS_SEMANTIC_SECTION_V1_TRUNCATED = 15,
    VCS_SEMANTIC_SECTION_V1_COUNT = 16,
};

/* Last section of the base format; FACTS..TRUNCATED form the extension. */
#define VCS_SEMANTIC_SECTION_V1_BASE_LAST VCS_SEMANTIC_SECTION_V1_SPANS
#define VCS_SEMANTIC_FACTS_V1_NAME "zcl.semantic_facts.v1"
/* Revision 2 of the extension: the same six sections and schemas, plus two
 * kinds of pseudo-site in REFS whose presence the name promises:
 *   "@scope:<path>" -MACRO-> "m:<defpath>:<name>"  a macro expanded in
 *       <path> outside every function definition (file scope: a global's
 *       initializer, a declaration, a layout);
 *   "@cond:<path>"  -MACRO-> "m:<name>"  an identifier tested by an #if,
 *       #elif, #ifdef, #ifndef, #elifdef or #elifndef line of <path>,
 *       defined or not (for a system file: only names some repo file of the
 *       TU defines).
 * and a member access through an anonymous struct or union names the
 * nearest named enclosing record. A revision-1 manifest makes none of these
 * claims, so a consumer cannot attribute a macro change with it. */
#define VCS_SEMANTIC_FACTS_V2_NAME "zcl.semantic_facts.v2"
#define VCS_SEMANTIC_FACTS_SCOPE_SITE "@scope:"
#define VCS_SEMANTIC_FACTS_COND_SITE "@cond:"
/* Revision 3: revision 2, plus a third pseudo-site whose presence the name
 * promises:
 *   "@assert:<path>" -KIND-> <id>  every entity the condition of a
 *       static_assert written in <path> outside every function definition
 *       names (at file scope or in a struct or union's member list): its
 *       types, sizeof and offsetof operands, enumerators, functions,
 *       variables, and each macro expanded inside it (MACRO refs to
 *       "m:<defpath>:<name>").
 * An assertion emits no bytes, but a change to what it reads can stop it
 * holding, and so stop every reader of <path> compiling. A revision-2
 * manifest makes no such claim: a consumer cannot tell that no assertion
 * reads a changed entity. */
#define VCS_SEMANTIC_FACTS_V3_NAME "zcl.semantic_facts.v3"
#define VCS_SEMANTIC_FACTS_ASSERT_SITE "@assert:"
/* Revision 4: revision 3, plus LOOKUPS records for the conditional lookups
 * earlier revisions left without a negative claim whenever the producer can
 * resolve them:
 *   __has_include(M) and its GNU spelling, where M is a macro the front end
 *       expanded to a string literal: one HAS_INCLUDE record per literal
 *       the TU's definitions of M give, replayed like a literal operand;
 *   __has_include_next from a file entered through a known search slot:
 *       one HAS_INCLUDE record per entry, replayed from the slot after it,
 *       in the quoted slot numbering, with every slot before the search's
 *       start listed among the record's present (unclaimed) slots; from the
 *       main file, or a file found relative to its includer, a plain
 *       __has_include replay.
 * What stays unresolvable (another macro, __has_embed, #embed, an entry the
 * producer does not know, a probe in a #define body or a -D value) keeps its
 * MISS_V1_NONE record. A revision-3 manifest makes none of these claims: a
 * consumer must read its unbound records as reaching any created or
 * deleted path. */
#define VCS_SEMANTIC_FACTS_V4_NAME "zcl.semantic_facts.v4"
/* Default producer caps: records per section and payload bytes per section. */
#define VCS_SEMANTIC_FACTS_V1_DEFAULT_MAX_RECORDS 65536u
#define VCS_SEMANTIC_FACTS_V1_DEFAULT_MAX_SECTION_BYTES (16u * 1024u * 1024u)

/* REFS kind byte: one direct reference edge from a definition. */
enum {
    VCS_SEMANTIC_REF_V1_CALL = 1,       /* direct call of a function */
    VCS_SEMANTIC_REF_V1_ADDRESS = 2,    /* a function named outside a call */
    VCS_SEMANTIC_REF_V1_VARIABLE = 3,   /* a file-scope variable */
    VCS_SEMANTIC_REF_V1_TYPE = 4,       /* a typedef or named tag */
    VCS_SEMANTIC_REF_V1_ENUMERATOR = 5, /* an enumeration constant */
    VCS_SEMANTIC_REF_V1_MACRO = 6,      /* a macro expanded inside */
};

/* UNKNOWNS kind byte: an effect the producer could not resolve. Each is a
 * record; the producer never omits one. */
enum {
    VCS_SEMANTIC_UNKNOWN_V1_INDIRECT_CALL = 1, /* call through a pointer */
    VCS_SEMANTIC_UNKNOWN_V1_INLINE_ASM = 2,
    /* call of a function declared in no repo file of the TU */
    VCS_SEMANTIC_UNKNOWN_V1_EXTERNAL_CALL = 3,
    VCS_SEMANTIC_UNKNOWN_V1_VOLATILE = 4,      /* volatile-qualified access */
    VCS_SEMANTIC_UNKNOWN_V1_ATOMIC = 5,        /* _Atomic-typed access */
    VCS_SEMANTIC_UNKNOWN_V1_UNRESOLVED = 6,    /* anything else unresolved */
};

/* PROBES reason byte: why one absence-claimed probe slot is UNKNOWN rather
 * than proved absent from the snapshot's immutable namespace. */
enum {
    VCS_SEMANTIC_PROBE_V1_NO_SNAPSHOT = 1,   /* no snapshot evidence given */
    VCS_SEMANTIC_PROBE_V1_OUTSIDE = 2,       /* dir outside the checkout */
    VCS_SEMANTIC_PROBE_V1_EXCLUDED = 3,      /* snapshot policy excludes it */
    VCS_SEMANTIC_PROBE_V1_STALE = 4,         /* snapshot disagrees with disk */
    VCS_SEMANTIC_PROBE_V1_NOT_DIRECTORY = 5, /* a prefix is a file or link */
    VCS_SEMANTIC_PROBE_V1_UNRESOLVED = 6,    /* name escapes or is invalid */
};

/* Sections bound by the hint root (bit 1u << tag): identity, lookups,
 * macros, decls, layouts, enums, functions. Never files or spans. */
#define VCS_SEMANTIC_HINT_SECTIONS_V1                                         \
    ((1u << VCS_SEMANTIC_SECTION_V1_IDENTITY) |                               \
     (1u << VCS_SEMANTIC_SECTION_V1_LOOKUPS) |                                \
     (1u << VCS_SEMANTIC_SECTION_V1_MACROS) |                                 \
     (1u << VCS_SEMANTIC_SECTION_V1_DECLS) |                                  \
     (1u << VCS_SEMANTIC_SECTION_V1_LAYOUTS) |                                \
     (1u << VCS_SEMANTIC_SECTION_V1_ENUMS) |                                  \
     (1u << VCS_SEMANTIC_SECTION_V1_FUNCTIONS))

/* FILES origin byte. */
enum {
    VCS_SEMANTIC_ORIGIN_V1_MAIN = 1,
    VCS_SEMANTIC_ORIGIN_V1_REPO = 2,
    VCS_SEMANTIC_ORIGIN_V1_SYSTEM = 3,
};

/* LOOKUPS form, kind and miss-evidence bytes. */
enum {
    VCS_SEMANTIC_FORM_V1_QUOTED = 1,
    VCS_SEMANTIC_FORM_V1_ANGLED = 2,
    VCS_SEMANTIC_LOOKUP_V1_INCLUDE = 1,
    VCS_SEMANTIC_LOOKUP_V1_HAS_INCLUDE = 2,
    VCS_SEMANTIC_LOOKUP_V1_INCLUDE_NEXT = 3,
    /* No negative claim is made (include_next). */
    VCS_SEMANTIC_MISS_V1_NONE = 0,
    /* Hit reported by the compiler; misses derived from the compiler's own
     * printed search list and each confirmed absent by stat. */
    VCS_SEMANTIC_MISS_V1_DERIVED_STAT = 1,
    /* Directive found by text scan; the producer replayed the compiler's
     * search list itself and confirmed every probe by stat. */
    VCS_SEMANTIC_MISS_V1_REPLAYED_STAT = 2,
};

/* "identity", "files", "lookups", "macros", "decls", "layouts", "enums",
 * "functions", "spans"; NULL for anything else. */
const char *vcs_semantic_section_v1_name(enum vcs_semantic_section_v1 s);

/* ---- builder (any producer) ------------------------------------------- */

/* One record under construction. Append fields in the section's schema
 * order; a failed append latches `failed` and later appends are no-ops. */
struct vcs_semantic_record_v1 {
    uint8_t *bytes;
    size_t len;
    size_t cap;
    bool failed;
};

void vcs_semantic_record_v1_reset(struct vcs_semantic_record_v1 *rec);
void vcs_semantic_record_v1_free(struct vcs_semantic_record_v1 *rec);
void vcs_semantic_record_v1_text(struct vcs_semantic_record_v1 *rec,
                                 const char *s, size_t len);
void vcs_semantic_record_v1_cstr(struct vcs_semantic_record_v1 *rec,
                                 const char *s);
void vcs_semantic_record_v1_u8(struct vcs_semantic_record_v1 *rec, uint8_t v);
void vcs_semantic_record_v1_u32(struct vcs_semantic_record_v1 *rec,
                                uint32_t v);
void vcs_semantic_record_v1_u64(struct vcs_semantic_record_v1 *rec,
                                uint64_t v);
void vcs_semantic_record_v1_i64(struct vcs_semantic_record_v1 *rec,
                                int64_t v);
void vcs_semantic_record_v1_digest(struct vcs_semantic_record_v1 *rec,
                                   const uint8_t digest[32]);
/* A sorted, deduplicated text list: u32le count || text*, ordered by memcmp
 * over each encoded text. The input order does not matter. */
void vcs_semantic_record_v1_sorted_texts(struct vcs_semantic_record_v1 *rec,
                                         const char *const *items,
                                         size_t count);

struct vcs_semantic_builder_v1;

struct vcs_semantic_builder_v1 *vcs_semantic_builder_v1_new(void);
void vcs_semantic_builder_v1_free(struct vcs_semantic_builder_v1 *b);
/* Copy one finished record into a section. */
bool vcs_semantic_builder_v1_add(struct vcs_semantic_builder_v1 *b,
                                 enum vcs_semantic_section_v1 section,
                                 const struct vcs_semantic_record_v1 *rec);
/* Sort and deduplicate every section, emit the manifest into a fresh
 * zcl_malloc buffer (free() it), then validate it with the strict decoder.
 * Anything the decoder would refuse is refused here with a reason. */
/* Turn on the facts extension for this manifest. finish() then applies the
 * caps to every section but IDENTITY, after sorting and deduplication: a
 * section keeps its longest canonical prefix that fits both max_records and
 * max_section_bytes of payload. Every cut section gets one TRUNCATED record
 * (section name, kept, dropped) and the FACTS record's complete byte is 0,
 * which makes the manifest non-authoritative for impact. finish() writes the
 * FACTS and TRUNCATED sections itself; a producer never adds to them. */
struct vcs_semantic_facts_v1 {
    uint8_t namespace_root[32]; /* ZVCS tree hash, or all zero for none */
    /* The producer's own identity (docs/work/SEMANTIC_MANIFEST.md,
     * "Producer digest"): the front end and extraction code that wrote the
     * facts, or all zero when the producer could not name itself. Two
     * manifests with different producers never narrow against each other. */
    uint8_t producer[32];
    uint32_t max_records;       /* >= 1 */
    uint64_t max_section_bytes; /* >= 4 */
    /* 0 or 1 writes VCS_SEMANTIC_FACTS_V1_NAME, 2 VCS_SEMANTIC_FACTS_V2_NAME,
     * 3 VCS_SEMANTIC_FACTS_V3_NAME and 4 VCS_SEMANTIC_FACTS_V4_NAME (the
     * producer then emits the sites and lookups that revision names). */
    uint8_t revision;
};
bool vcs_semantic_builder_v1_enable_facts(struct vcs_semantic_builder_v1 *b,
                                          const struct vcs_semantic_facts_v1 *f);

/* Canonical, compiler-neutral identity of one C entity (docs/work/
 * SEMANTIC_MANIFEST.md, "Canonical identities"): prefix ':' name for
 * external linkage, prefix ':' path ':' name otherwise. Prefixes: f
 * function, v variable, t typedef, s struct, u union, e enum, k enumerator,
 * m macro. False when out is too small. */
bool vcs_semantic_id_v1(char prefix, const char *path, const char *name,
                        bool external, char *out, size_t out_len);

bool vcs_semantic_builder_v1_finish(struct vcs_semantic_builder_v1 *b,
                                    uint8_t **out, size_t *out_len,
                                    char *why, size_t why_len);

/* SHA3-256 over VCS_SEMANTIC_FN_TOKENS_V1_DOMAIN || (u32le len || token)*:
 * the body identity of one function, independent of comments and layout. */
struct vcs_semantic_token_hash_v1 {
    struct sha3_256_ctx ctx;
};
void vcs_semantic_token_hash_v1_init(struct vcs_semantic_token_hash_v1 *h);
void vcs_semantic_token_hash_v1_add(struct vcs_semantic_token_hash_v1 *h,
                                    const char *token, size_t len);
void vcs_semantic_token_hash_v1_final(struct vcs_semantic_token_hash_v1 *h,
                                      uint8_t out[32]);

/* ---- reader (Z23) ------------------------------------------------------ */

/* Strictly parse every section and record against its schema. */
/* True when a path spelled at text[i] would start a path: the start of the
 * text, after one of `=,:;"' ` or after a glued option such as -I or
 * -isystem. A '/' there must be a virtual root; producers rewrite host
 * paths to @root/@sys by exactly this rule. */
bool vcs_semantic_argv_path_boundary_v1(const char *text, size_t i);

bool vcs_semantic_manifest_v1_validate(const uint8_t *bytes, size_t len,
                                       char *why, size_t why_len);
/* Validate, then SHA3-256(root domain || bytes). */
bool vcs_semantic_root_v1(const uint8_t *bytes, size_t len, uint8_t out[32],
                          char *why, size_t why_len);
/* CANDIDATE-MATCH HINT ONLY. Validate, then
 *   SHA3-256(VCS_SEMANTIC_HINT_ROOT_V1_DOMAIN || (u8 tag || section_root)*)
 * over the sections in VCS_SEMANTIC_HINT_SECTIONS_V1, in tag order. It omits
 * FILES (content bytes) and SPANS (positions), so a comment-only or
 * whitespace-only edit leaves it equal while the exact root changes. It is
 * NOT an identity: system headers enter it only through the identity and
 * lookups, and token hashes are not a proof of equal object code. A hint
 * match may only nominate a reuse candidate; acceptance still needs the
 * exact root (vcs_semantic_root_v1) or a stronger equivalence check. */
bool vcs_semantic_hint_root_v1(const uint8_t *bytes, size_t len,
                               uint8_t out[32], char *why, size_t why_len);
/* Validate, then the section root of one section. */
bool vcs_semantic_section_root_v1(const uint8_t *bytes, size_t len,
                                  enum vcs_semantic_section_v1 section,
                                  uint8_t out[32]);
/* Render a valid manifest as text, one line per record:
 * "<section> <field> <field> ...". Texts are quoted with \\ and \" escaped
 * and bytes outside 0x20..0x7e written as \xNN; numbers are decimal;
 * digests are hex; lists are [a,b]. Returns false for an invalid manifest. */
bool vcs_semantic_manifest_v1_dump(const uint8_t *bytes, size_t len,
                                   FILE *out);

/* Record count of one section of a valid manifest; false otherwise. */
bool vcs_semantic_section_count_v1(const uint8_t *bytes, size_t len,
                                   enum vcs_semantic_section_v1 section,
                                   uint32_t *out);

enum vcs_semantic_fn_change_v1 {
    VCS_SEMANTIC_FN_V1_ADDED = '+',
    VCS_SEMANTIC_FN_V1_REMOVED = '-',
    VCS_SEMANTIC_FN_V1_CHANGED = '~',
};

/* Called once per function whose FUNCTIONS record differs, keyed by
 * (path, name), in record order. Texts are not NUL-terminated. */
typedef void (*vcs_semantic_fn_change_cb_v1)(
    void *ctx, enum vcs_semantic_fn_change_v1 change, const char *path,
    size_t path_len, const char *name, size_t name_len);

struct vcs_semantic_diff_v1 {
    /* Bit (1u << tag) set for every section whose payload differs. */
    uint32_t changed_sections;
    /* Exact roots equal (bytes equal); hint roots equal (no section in
     * VCS_SEMANTIC_HINT_SECTIONS_V1 changed). */
    bool exact_equal;
    bool hint_equal;
    uint32_t functions_added;
    uint32_t functions_removed;
    uint32_t functions_changed;
    uint32_t functions_same;
};

/* Section-level and function-level difference of two valid manifests.
 * False when either input is not a valid manifest. cb may be NULL. */
/* ---- facts extension reader --------------------------------------------- */

struct vcs_semantic_facts_info_v1 {
    bool present;               /* the extension block is in the manifest */
    bool complete;              /* no section was cut by a cap */
    uint8_t namespace_root[32];
    uint8_t producer[32]; /* all zero: the producer is unknown */
    uint8_t revision;     /* 1 to 4: which extension name the FACTS record carries */
    uint32_t max_records;
    uint64_t max_section_bytes;
};

/* False for an invalid manifest; a valid manifest without the extension
 * gives present = false. */
bool vcs_semantic_facts_v1_info(const uint8_t *bytes, size_t len,
                                struct vcs_semantic_facts_info_v1 *out);

/* The fields of one record, in schema order: top-level texts (paths and
 * texts), top-level numbers (u8/u32/u64/i64 and list counts) and 32-byte
 * digests. Texts are not NUL-terminated. */
#define VCS_SEMANTIC_FIELDS_V1_MAX 16
struct vcs_semantic_fields_v1 {
    const char *text[VCS_SEMANTIC_FIELDS_V1_MAX];
    size_t text_len[VCS_SEMANTIC_FIELDS_V1_MAX];
    size_t ntext;
    uint64_t num[VCS_SEMANTIC_FIELDS_V1_MAX];
    size_t nnum;
    /* Top-level 32-byte digests (FILES content, FUNCTIONS token hash). */
    const uint8_t *digest[2];
    size_t ndigest;
};
typedef bool (*vcs_semantic_record_cb_v1)(
    void *ctx, const struct vcs_semantic_fields_v1 *fields);

/* Call cb for every record of one section of a valid manifest, in record
 * order; stops early (returning false) when cb returns false. A section that
 * is absent (the extension of a plain manifest) has no records. */
bool vcs_semantic_section_v1_each(const uint8_t *bytes, size_t len,
                                  enum vcs_semantic_section_v1 section,
                                  vcs_semantic_record_cb_v1 cb, void *ctx);

/* Every record of every section of a valid manifest, validated once, in
 * section then record order, with its parsed fields and its exact encoded
 * bytes (raw, raw_len: the record body, without its length prefix). A
 * consumer that hashes records hashes raw, which carries every list element
 * the fields view does not expose. Stops early when cb returns false. */
typedef bool (*vcs_semantic_raw_cb_v1)(
    void *ctx, enum vcs_semantic_section_v1 section,
    const struct vcs_semantic_fields_v1 *fields, const uint8_t *raw,
    size_t raw_len);
bool vcs_semantic_manifest_v1_each(const uint8_t *bytes, size_t len,
                                   vcs_semantic_raw_cb_v1 cb, void *ctx);

/* The negative half of a compile's include resolution, so a consumer can
 * check it against a later namespace. cb is called with:
 *   - (dir, name) for every LOOKUPS slot below the hit that present_slots
 *     does not list: the compile saw no dir/name there. Slot 0 of a quoted
 *     lookup is the includer's directory ("." at the top), then the quote
 *     dirs, then the angled dirs; an angled lookup has the angled dirs only.
 *   - (dir, NULL) for every IDENTITY ignored dir: it did not exist.
 *   - (NULL, name) for a lookup that makes no negative claim (include_next,
 *     a computed or an absolute include): nothing about it can be checked.
 * Dirs are manifest paths ("." , repo-relative or "@sys/..."); texts are not
 * NUL-terminated. False for an invalid manifest, a slot outside the search
 * list, or when cb returns false. */
typedef bool (*vcs_semantic_absent_cb_v1)(void *ctx, const char *dir,
                                          size_t dir_len, const char *name,
                                          size_t name_len);
bool vcs_semantic_absent_v1_each(const uint8_t *bytes, size_t len,
                                 vcs_semantic_absent_cb_v1 cb, void *ctx);

bool vcs_semantic_manifest_v1_diff(const uint8_t *a, size_t a_len,
                                   const uint8_t *b, size_t b_len,
                                   struct vcs_semantic_diff_v1 *out,
                                   vcs_semantic_fn_change_cb_v1 cb,
                                   void *ctx);

#endif /* ZCL_VCS_SEMANTIC_MANIFEST_H */
