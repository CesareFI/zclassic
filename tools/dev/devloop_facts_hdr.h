/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Changed-header text evidence for the facts consumer: the dirty line region, and every top-level chunk that changed with the names it spells. */
#ifndef ZCL_TOOLS_DEV_DEVLOOP_FACTS_HDR_H
#define ZCL_TOOLS_DEV_DEVLOOP_FACTS_HDR_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* A header's records cannot see everything its text says: a declaration's
 * attributes, a variable's initializer, a #pragma, the position of a
 * declaration the debug information records. This module compares the two
 * texts directly.
 *
 * Chunks: the text is cut at top level into directive lines and
 * declarations (up to a ';' outside brackets, or a function definition's
 * closing brace), each with comments and whitespace collapsed. A chunk that
 * appears in only one of the two texts is changed. The consumer attributes a
 * changed chunk to the ids its names spell, or broadens.
 *
 * Region: the lines between the texts' common prefix and common suffix;
 * when the line count changed, every line after the prefix (a position
 * below it moved). */

enum fxh_kind {
    FXH_TEXT = 1,     /* a declaration, typedef, layout or initializer */
    FXH_FUNCTION = 2, /* a function definition: its declarator's name */
    FXH_DEFINE = 3,   /* #define: the macro's name */
    FXH_COND = 4,     /* #if #ifdef #ifndef #elif #else #endif ... */
    FXH_INCLUDE = 5,  /* #include #include_next #embed */
    FXH_OTHER = 6,    /* #undef #pragma #line #error ... */
};

struct fxh_chunk {
    uint8_t kind;
    char **names;
    size_t nnames;
};

struct fxh_diff {
    uint32_t b_lo, b_hi; /* region in the before text, 1-based; empty lo > hi */
    uint32_t a_lo, a_hi; /* ...and in the after text */
    struct fxh_chunk *changed;
    size_t nchanged;
    const uint8_t *before, *after; /* borrowed */
    size_t blen, alen;
};

/* Compare two texts; false only when memory runs out. */
bool fxh_diff(const uint8_t *before, size_t blen, const uint8_t *after,
              size_t alen, struct fxh_diff *out);
void fxh_free(struct fxh_diff *d);

/* The identifier `name` occurs on a region line of either text, or occurs
 * in neither (a declaration a macro spells). */
bool fxh_position_dirty(const struct fxh_diff *d, const char *name);
/* Lines [lo, hi] of one side's text meet its region. */
bool fxh_span_dirty(const struct fxh_diff *d, uint32_t lo, uint32_t hi,
                    bool after);
/* A region line of either text holds a token outside comments: a
 * declaration there may have moved, its line or its column. Directive
 * lines count only when `directives` (-g3 records each #define's line). */
bool fxh_region_has_code(const struct fxh_diff *d, bool directives);

#endif /* ZCL_TOOLS_DEV_DEVLOOP_FACTS_HDR_H */
