/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: The semantic facts fixture: a four-file C tree, its edit table and the narrowing verdict each edit must produce. */
#ifndef ZCL_TEST_SEMANTIC_FACTS_FIXTURE_H
#define ZCL_TEST_SEMANTIC_FACTS_FIXTURE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define SFT_HEADER "engine/modules/fxn/include/fx.h"
#define SFT_CORE "engine/modules/fxn/src/fx_core.c"
#define SFT_CALLER_A "engine/modules/fxn/src/fx_a.c"
#define SFT_CALLER_B "engine/modules/fxn/src/fx_b.c"
/* A header beside fx_core.c: `#include "fx.h"` searches the includer's
 * directory first, so a file here shadows the include/ copy. */
#define SFT_SHADOW_PATH "engine/modules/fxn/src/fx.h"
#define SFT_FIXTURES "tests/fixtures/semantic_facts"
#define SFT_FILE_COUNT 4
/* The fixture compiles name the host `cc` as their object compiler and
 * this stand-in for Make's $(BUILD_COMPILER_ID) as its toolchain identity:
 * the tests run no Make parse, and the value only has to be one known,
 * fixed identity on both sides of a pair. */
#define SFT_OBJECT_CC "cc"
#define SFT_TOOLCHAIN_ID \
    "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a"

/* base is the tree as written; every other variant is base plus one edit,
 * and its manifest is the "after" of a (base, variant) pair. */
enum sft_variant {
    SFT_BASE,
    SFT_BODY,      /* one function body: narrows to that function */
    SFT_COMMENT,   /* comments and blank lines only: narrows to nothing */
    SFT_LAYOUT,    /* a struct gains a field in the header */
    SFT_MACRO,     /* a header macro changes value */
    SFT_DECL,      /* the header gains a declaration */
    SFT_INDIRECT,  /* the edited function calls through a pointer */
    SFT_ASM,       /* the edited function holds inline asm */
    SFT_ADDRESS,   /* the edited function's address is taken */
    SFT_SCOPE,     /* a file-scope initializer changes */
    SFT_TYPE,      /* a header field's type changes, the layout does not */
    SFT_INCLUDE,   /* the include changes form: "fx.h" becomes <fx.h> */
    SFT_SHADOW,    /* a byte-identical fx.h appears beside fx_core.c */
    SFT_SEARCH,    /* a search directory is prepended (-Iengine/modules/fxn) */
    SFT_CTOR,      /* a caller-less function becomes a constructor */
    SFT_WEAK,      /* a called function becomes weak */
    SFT_VISIBILITY, /* a function gains hidden visibility */
    SFT_C23ATTR,   /* a function gains a C23 [[gnu::cold]] attribute */
    SFT_TYPEDEF,   /* a header typedef changes its type */
    SFT_SPACE,     /* whitespace only, inside and around one function */
    SFT_HDRCOMMENT, /* a comment line in the header, no semantic change */
    SFT_COUNTER,   /* a body expands __COUNTER__, which counts across the TU */
    SFT_TRUNCATED, /* base again, under a two-record producer cap */
    SFT_VARIANT_COUNT
};

struct sft_edit {
    const char *name;        /* fixture basename: <name>.zsm */
    const char *file;        /* the edited file, NULL when none */
    const char *from, *to;   /* one exact replacement in `file` */
    const char *reason;      /* expected verdict: "" narrows */
    const char *seed;        /* the one expected seed, NULL for none */
    uint32_t max_records;    /* producer cap; 0 for the default */
    const char *add_path;    /* a file this variant adds, NULL for none */
    const char *add_body;    /* ...and its bytes */
    const char *extra_flag;  /* a compile flag put before k_sft_flags */
};

extern const struct sft_edit k_sft_edits[SFT_VARIANT_COUNT];
extern const char *const k_sft_paths[SFT_FILE_COUNT];
/* The compile flags every producer run uses (after the source). */
extern const char *const k_sft_flags[];
extern const size_t k_sft_nflags;

/* The bytes of `path` in variant v (heap, NUL-terminated; caller frees). */
char *sft_text(enum sft_variant v, const char *path, size_t *len);
/* Write every fixture file of variant v under `root`. */
bool sft_write_tree(const char *root, enum sft_variant v);
/* Read a whole file (heap; caller frees). */
bool sft_read(const char *path, uint8_t **out, size_t *len);
/* The 32-byte producer digest inside a manifest's FACTS record (so a test
 * can compare two producers' manifests on everything else, or forge a
 * producer change); NULL when the manifest carries no facts. */
uint8_t *sft_producer_at(uint8_t *m, size_t n);

#endif /* ZCL_TEST_SEMANTIC_FACTS_FIXTURE_H */
