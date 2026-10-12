/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * gate_flag_registry_priv — the seam between gate_flag_registry.c (the
 * flags.def parser, read-site scanner, and check-flag-registry gate body)
 * and gate_flag_registry_first_use.c (the first-use pointer check: does
 * the <path>:<line> a row cites actually read that flag's name) and
 * gate_flag_registry_lex.c (is a recognized read real code, not a mention).
 * NOT a public header: nothing outside tools/lint/lintc/ includes this.
 */

#ifndef ZCL_LINTC_GATE_FLAG_REGISTRY_PRIV_H
#define ZCL_LINTC_GATE_FLAG_REGISTRY_PRIV_H

#include <stdio.h>

enum {
    FR_NAME = 96,
    FR_FU_PATH = 256,
};

struct fr_row {
    char name[FR_NAME];
    char kind[24];
    char def[64];
    char exp[64];
    char fu_path[FR_FU_PATH];
    int fu_line;
    int fu_present;
    /* The scan saw a scanner-recognized REAL read of name (C: outside
     * every comment, literal and #if 0 region; shell/Makefile: before any
     * comment-opening '#') in fu_path itself. Proves a ":auto" pointer; decides whether
     * --auto-pointers may rebind a numeric one. */
    int fu_read_seen;
    int used;
};

/* gate_flag_registry_first_use.c: parses the "first use <path>:<line>"
 * clause out of a row's why_ string (returns 0 with *line left untouched
 * when the string carries no such clause — e.g. "first use Makefile
 * deploy: recipe", which is prose, not a pointer), and verifies every
 * fu_present row's cited line actually reads the flag's name. */
int fru_parse_pointer(const char *why, char *path, size_t pathcap, int *line);
int fru_check_rows(const struct fr_row *rows, int n, FILE *out, int *verified);

/* fru_pointer_status: proves (or disproves) one row's cited "first use
 * <path>:<line>" the same way fru_check_rows does, but hands the verdict
 * back instead of formatting a FAIL line — the seam --fix-pointers repairs
 * from. Returns 0 when the cited line already reads the flag (nothing to
 * fix), 1 when it is drifted but some OTHER line in the same file still
 * reads the same flag (*near left at that line — the repair target), 2
 * when it is drifted and no line in the file reads the flag at all (*near
 * left at 0 — not fixable, still a human's problem), or -1 when the cited
 * file exists but can't be opened (die-worthy, same as fru_check_rows). */
int fru_pointer_status(const char *path, int line, const char *name, int *near);

/* gate_flag_registry_lex.c: is a regex-recognized read a REAL read? The
 * scanner feeds each line with the C lexer state it entered in (FR_CODE at
 * a file's start) and its `#if 0` depth, and advances both per line. */
enum { FR_CODE, FR_BLOCK, FR_LINE, FR_STR, FR_CHR };

struct fr_line {
    const char *path;
    const char *text;
    int lineno;
    int is_c;
    int c_state;   /* C lexer state at the line's first byte */
    int if0;       /* `#if 0` nesting depth; nonzero = dead code */
};

/* The C lexer state the line after `line` starts in. */
int frl_c_state_after(const char *line, int st);
/* The `#if 0` depth after a line that begins in code (0 = live code). */
int frl_c_if0(const char *line, int depth);
/* True when the match starting at ln->text[off] is code: for C, outside
 * every comment, literal and #if 0 region; for shell and Makefile text,
 * before any comment-opening '#'. name is the flag the match captured. */
int frl_read_is_real(const struct fr_line *ln, size_t off, const char *name);

#endif
