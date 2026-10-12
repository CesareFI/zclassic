/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Shared rig for the semantic_build_inputs tests: one consume run
 *          against a throwaway root holding a Makefile, and the verdicts a
 *          case asserts (narrowed or widened). */

#ifndef ZCL_TEST_SEMANTIC_BUILD_INPUTS_FIXTURE_H
#define ZCL_TEST_SEMANTIC_BUILD_INPUTS_FIXTURE_H

#include "devloop.h"
#include "devloop_facts.h"

#include <stdbool.h>
#include <stddef.h>

/* The one candidate TU every root holds. */
#define SBI_TU "src/a.c"
#define SBI_GEN_RULE ".PHONY: gen\ngen:\n\tsh tools/x.sh > gen.h\n"
#define SBI_OBJ_RULE "build/a.o: " SBI_TU "\n\t$(CC) -c $< -o $@\n"
#define SBI_COUNT(a) (sizeof(a) / sizeof((a)[0]))
/* An optional include build/gen.mk a rule makes, whose recipe (r) writes
 * text that names gen only once the shell has run it. */
#define SBI_GEN_INCLUDE(r)                                                     \
    "all: build/a.o\n" SBI_OBJ_RULE "-include build/gen.mk\nbuild/gen.mk:\n" \
    r SBI_GEN_RULE

/* One consume run over `nchanged` paths (each written with `body`, except
 * a doc path, written the same) against a root holding `makefile`. The
 * plain plan's path groups are kept in *plain so a caller can check none
 * was dropped. */
struct sbi_run {
    struct zcl_devloop_plan plain, plan;
    struct zcl_devloop_facts_verdict v;
    struct zcl_devloop_facts_report rep;
};

/* One makefile where GNU make runs the recipe that reads tools/x.sh, but the
 * text never spells that goal as a literal word an object rule reaches.
 * `extra` (if not NULL) is an included makefile written with `body`. */
struct sbi_case {
    const char *id, *makefile, *extra, *body;
};

/* A consume run whose root also holds files[] (path, text pairs up to a
 * NULL path). */
bool sbi_consume_files(const char *tag, const char *makefile,
                       const char *const *files,
                       const char *const *changed, size_t nchanged,
                       struct sbi_run *r);
/* The same with one more file, `extra`, holding `body` (none when NULL). */
bool sbi_consume_with(const char *tag, const char *makefile,
                      const char *extra, const char *body,
                      const char *const *changed, size_t nchanged,
                      struct sbi_run *r);
bool sbi_consume(const char *tag, const char *makefile,
                 const char *const *changed, size_t nchanged,
                 struct sbi_run *r);
/* The narrow verdict (the TU keeps its plan) and the widened one. */
bool sbi_narrowed(const struct sbi_run *r);
bool sbi_widened(const struct sbi_run *r);
/* Every case widens a changed tools/x.sh; each that does not is named. */
bool sbi_cases_widen(const struct sbi_case *cases, size_t n);

/* The parse-time command, guarded include and plan premise cases
 * (semantic_build_inputs_guards.c). */
int sbi_guard_suite(void);

#endif
