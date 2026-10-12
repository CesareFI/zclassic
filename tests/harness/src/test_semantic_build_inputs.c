/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: ACCEPTANCE BAR for fxc_build_inputs() (tools/dev/devloop_facts_consumer.c),
 * the non-C/H build-input rule: (a) a TU-included path routes through the
 * existing header path; (b) a path the Makefile text names where make can
 * change an object with it (by name, pattern or sub-make, in a definition,
 * directive, file rule, the default goal, a .PHONY rule an object rule
 * reaches or a recipe line that runs make; tools/dev/devloop_facts_make*.c)
 * widens to the whole catalog; (c) a path no TU reads and no such position
 * names (a .PHONY-only recipe, an echo, an $(if) condition, a doc)
 * narrows the compile, but the plain plan's own path groups for it are
 * still selected as a test obligation; (d) a path the include graph cannot
 * answer for (here: deleted/never-created) widens too; (e) a TU whose
 * manifests predate facts revision 3 is affected by a created path.
 *
 * Each test hand-builds a minimal identity+files manifest (no libclang) for
 * one candidate TU and drives zcl_devloop_facts_consume() directly against a
 * throwaway root, so it needs no compiler and no checked-in fixture.
 */
#include "test/test_core.h"

#include "base/safe_alloc.h"
#include "devloop.h"
#include "devloop_facts.h"
#include "test/semantic_build_inputs_fixture.h"
#include "test/semantic_facts_fixture.h"
#include "vcs/semantic_manifest.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

static bool sbi_mkdirs(char *full)
{
    for (char *p = full + 1; *p; p++) {
        if (*p != '/')
            continue;
        *p = '\0';
        if (mkdir(full, 0755) != 0 && errno != EEXIST) {
            *p = '/';
            return false;
        }
        *p = '/';
    }
    return true;
}

static bool sbi_write(const char *root, const char *rel, const char *body)
{
    char full[4096];
    FILE *fp;
    bool ok;
    size_t n = strlen(body);
    if (snprintf(full, sizeof(full), "%s/%s", root, rel) >= (int)sizeof(full))
        return false;
    ok = sbi_mkdirs(full);
    fp = ok ? fopen(full, "wb") : NULL;
    ok = fp != NULL && fwrite(body, 1, n, fp) == n;
    if (fp != NULL && fclose(fp) != 0)
        ok = false;
    return ok;
}

/* A minimal, valid manifest for `main_path` at facts `revision`: identity +
 * FILES (the main file and, when given, one more repo file read). No
 * lookups/macros/decls/layouts/enums/functions/spans: every one of those
 * sections is legally empty, which from revision 3 on says the TU makes
 * no conditional lookup. */
static const char *const k_sbi_env[] = {VCS_SEMANTIC_ENV_V1_ALLOWLIST};
#define SBI_ENV_COUNT (sizeof(k_sbi_env) / sizeof(k_sbi_env[0]))

static bool sbi_manifest(const char *main_path, const char *extra_file,
                         uint8_t revision,
                         uint8_t **out, size_t *out_len)
{
    struct vcs_semantic_builder_v1 *b = vcs_semantic_builder_v1_new();
    struct vcs_semantic_record_v1 r = {0};
    uint8_t digest[32] = {0};
    char why[128] = {0};
    bool ok = b != NULL;
    if (ok) {
        /* fxi_object_cc_known() requires "; object-cc " followed by
         * something other than "unknown" (see
         * tools/dev/devloop_facts_codegen.c): without it, an otherwise
         * byte-identical before/after pair still reports identity-drift.
         * SFT_OBJECT_CC/SFT_TOOLCHAIN_ID are the same fixed, known stand-in
         * identity test_semantic_facts_live.c passes to the real sensor. */
        vcs_semantic_record_v1_cstr(
            &r, "test-cc 1.0; object-cc " SFT_OBJECT_CC
                " sha3-256 "
                "0000000000000000000000000000000000000000000000000000"
                "000000000000 toolchain " SFT_TOOLCHAIN_ID);
        vcs_semantic_record_v1_cstr(&r, "");
        vcs_semantic_record_v1_cstr(&r, "x86_64-pc-linux-gnu");
        vcs_semantic_record_v1_cstr(&r, main_path);
        vcs_semantic_record_v1_u32(&r, 0); /* argv */
        vcs_semantic_record_v1_u32(&r, 0); /* quote_dirs */
        vcs_semantic_record_v1_u32(&r, 0); /* angled_dirs */
        vcs_semantic_record_v1_u32(&r, 0); /* ignored_dirs */
        vcs_semantic_record_v1_u32(&r, (uint32_t)SBI_ENV_COUNT); /* env */
        for (size_t k = 0; k < SBI_ENV_COUNT; k++) {
            vcs_semantic_record_v1_cstr(&r, k_sbi_env[k]);
            vcs_semantic_record_v1_u8(&r, 0);
            vcs_semantic_record_v1_cstr(&r, "");
        }
        ok = vcs_semantic_builder_v1_add(b, VCS_SEMANTIC_SECTION_V1_IDENTITY,
                                         &r);
    }
    if (ok) {
        vcs_semantic_record_v1_reset(&r);
        vcs_semantic_record_v1_cstr(&r, main_path);
        vcs_semantic_record_v1_digest(&r, digest);
        vcs_semantic_record_v1_u8(&r, VCS_SEMANTIC_ORIGIN_V1_MAIN);
        ok = vcs_semantic_builder_v1_add(b, VCS_SEMANTIC_SECTION_V1_FILES, &r);
    }
    if (ok && extra_file != NULL) {
        vcs_semantic_record_v1_reset(&r);
        vcs_semantic_record_v1_cstr(&r, extra_file);
        vcs_semantic_record_v1_digest(&r, digest);
        vcs_semantic_record_v1_u8(&r, VCS_SEMANTIC_ORIGIN_V1_REPO);
        ok = vcs_semantic_builder_v1_add(b, VCS_SEMANTIC_SECTION_V1_FILES, &r);
    }
    if (ok) {
        struct vcs_semantic_facts_v1 facts = {
            .max_records = 64, .max_section_bytes = 65536, .revision = revision};
        ok = vcs_semantic_builder_v1_enable_facts(b, &facts);
    }
    ok = ok && vcs_semantic_builder_v1_finish(b, out, out_len, why, sizeof why);
    vcs_semantic_record_v1_free(&r);
    vcs_semantic_builder_v1_free(b);
    return ok;
}

/* Write a.c's before/after manifest pair (byte-identical: the TU itself
 * never changes in these tests) at facts `revision`, plus the candidate
 * scan marker. */
static bool sbi_write_tu_rev(const char *root, const char *extra_file,
                             uint8_t revision)
{
    uint8_t *m = NULL;
    size_t n = 0;
    bool ok = sbi_manifest(SBI_TU, extra_file, revision, &m, &n);
    char full[4096];
    FILE *fp;
    if (!ok)
        return false;
    for (int pass = 0; ok && pass < 2; pass++) {
        if (snprintf(full, sizeof(full), "%s/facts/%s%s", root, SBI_TU,
                     pass == 0 ? ".before.zsm" : ".after.zsm") >=
            (int)sizeof(full)) {
            ok = false;
            break;
        }
        ok = sbi_mkdirs(full);
        fp = ok ? fopen(full, "wb") : NULL;
        ok = fp != NULL && fwrite(m, 1, n, fp) == n;
        if (fp != NULL && fclose(fp) != 0)
            ok = false;
    }
    free(m);
    /* A depfile naming only its own .c gives codeindex zero include edges,
     * which is globally indistinguishable from "no include graph built"
     * (CODEINDEX_INCLUDE_DIM_UNAVAILABLE for every path, not just this
     * one): a second, in-tree prerequisite gives it a real edge so a path
     * with no readers gets answered COMPLETE instead. */
    return ok && sbi_write(root, SBI_TU, "int a(void) { return 0; }\n") &&
           sbi_write(root, "src/a.h", "\n") &&
           sbi_write(root, "build/a.d",
                     "build/a.o: " SBI_TU " src/a.h\n");
}

/* The current producer's revision. */
static bool sbi_write_tu(const char *root, const char *extra_file)
{
    return sbi_write_tu_rev(root, extra_file, 4);
}

static bool sbi_has_group(const struct zcl_devloop_plan *p, const char *g)
{
    for (size_t k = 0; k < p->path_groups_len; k++)
        if (strcmp(p->path_groups[k], g) == 0)
            return true;
    for (size_t k = 0; k < p->closure_groups_len; k++)
        if (strcmp(p->closure_groups[k], g) == 0)
            return true;
    return false;
}

static bool sbi_tu_affected(const struct zcl_devloop_facts_report *r,
                            const char *why)
{
    for (size_t k = 0; k < r->ntus; k++)
        if (strcmp(r->tus[k].path, SBI_TU) == 0)
            return r->tus[k].affected &&
                  (why == NULL || strcmp(r->tus[k].reason, why) == 0);
    return false;
}

/* (c): a changed .def no TU reads and no Makefile names narrows the compile
 * (the TU is not widened into the universe by it), and the plain plan's own
 * path groups for that path still become a test obligation: not dropped by
 * the narrow walk. */
static int sbit_t_narrow(void)
{
    int failures = 0;
    TEST_CASE("semantic_build_inputs: an unread, unmentioned .def narrows "
             "the compile and keeps the path's own test groups") {
        char root[4096];
        const char *changed = "tools/dev/test_group_catalog.def";
        struct zcl_devloop_plan plan = {0};
        struct zcl_devloop_facts_verdict v = {0};
        struct zcl_devloop_facts_report rep = {0};
        ASSERT(test_mkdtemp(root, sizeof(root), "sbi_narrow") != NULL);
        ASSERT(sbi_write_tu(root, NULL));
        ASSERT(sbi_write(root, "Makefile", "all:\n\t@true\n"));
        ASSERT(sbi_write(root, changed, ""));
        ASSERT(zcl_devloop_plan_files(&changed, 1, &plan));
        ASSERT(zcl_devloop_facts_consume(root, &changed, 1, "facts", NULL,
                                         &plan, &v, &rep));
        ASSERT(rep.complete);
        ASSERT(!sbi_tu_affected(&rep, "build-input-changed"));
        ASSERT(!plan.closure_universal);
        /* the path itself matches a real shared impact rule
         * (test_group_catalog.def -> test_group_selector, ...): its group
         * must still be an obligation even though nothing compiles it. */
        ASSERT(sbi_has_group(&plan, "test_group_selector"));
        zcl_devloop_facts_report_free(&rep);
    } TEST_END
    return failures;
}

/* (b): a changed path the root Makefile text names (even though no TU or
 * depfile reads it) is a make input: the whole catalog widens. */
static int sbit_t_makefile_mention(void)
{
    int failures = 0;
    TEST_CASE("semantic_build_inputs: a path the Makefile text names widens "
             "to the whole catalog") {
        char root[4096];
        const char *changed = "cfg/flags.def";
        struct zcl_devloop_plan plan = {0};
        struct zcl_devloop_facts_verdict v = {0};
        struct zcl_devloop_facts_report rep = {0};
        ASSERT(test_mkdtemp(root, sizeof(root), "sbi_makefile") != NULL);
        ASSERT(sbi_write_tu(root, NULL));
        ASSERT(sbi_write(root, "Makefile",
                         "build/a.o: " SBI_TU " cfg/flags.def\n"
                         "\t$(CC) -c $< -o $@\n"));
        ASSERT(sbi_write(root, changed, ""));
        ASSERT(zcl_devloop_plan_files(&changed, 1, &plan));
        ASSERT(zcl_devloop_facts_consume(root, &changed, 1, "facts", NULL,
                                         &plan, &v, &rep));
        ASSERT(!rep.complete);
        ASSERT(strcmp(rep.reason, "build-input-changed") == 0);
        ASSERT(sbi_tu_affected(&rep, "build-input-changed"));
        ASSERT(plan.closure_universal);
        zcl_devloop_facts_report_free(&rep);
    } TEST_END
    return failures;
}

/* (b, bare directory): a recipe hands a tool a directory the changed file
 * lives under, with no trailing '/' and no wildcard naming the extension
 * (the common `tool $(DIR) out` form: the tool globs $(DIR) itself, and the
 * Makefile text never spells the file or its pattern). This still widens:
 * a scanner that requires a trailing slash to recognize a directory mention
 * would narrow wrongly here, since make (via the tool it runs) does read
 * every file under that directory. */
static int sbit_t_bare_dir(void)
{
    int failures = 0;
    TEST_CASE("semantic_build_inputs: a bare directory argument (no "
             "trailing slash, no wildcard) still widens for a file under "
             "it") {
        char root[4096];
        const char *changed = "contexts/wallet/views/foo.chtml";
        struct zcl_devloop_plan plan = {0};
        struct zcl_devloop_facts_verdict v = {0};
        struct zcl_devloop_facts_report rep = {0};
        ASSERT(test_mkdtemp(root, sizeof(root), "sbi_baredir") != NULL);
        ASSERT(sbi_write_tu(root, NULL));
        ASSERT(sbi_write(root, "Makefile",
                         "build/a.o: " SBI_TU "\n"
                         "\t$(CC) -c $< -o $@\n"
                         "\n"
                         "gen.h: tools/gen_templates\n"
                         "\ttools/gen_templates contexts/wallet/views gen.h\n"));
        ASSERT(sbi_write(root, changed, ""));
        ASSERT(zcl_devloop_plan_files(&changed, 1, &plan));
        ASSERT(zcl_devloop_facts_consume(root, &changed, 1, "facts", NULL,
                                         &plan, &v, &rep));
        ASSERT(!rep.complete);
        ASSERT(strcmp(rep.reason, "build-input-changed") == 0);
        ASSERT(sbi_tu_affected(&rep, "build-input-changed"));
        ASSERT(plan.closure_universal);
        zcl_devloop_facts_report_free(&rep);
    } TEST_END
    return failures;
}

/* (b, $(wildcard $(VAR)/ *.ext)): a variable holding a bare directory, used
 * inside $(wildcard ...) to build the glob. Confirms the macro-expansion
 * path already widens this common generated-header pattern. */
static int sbit_t_wildcard_var(void)
{
    int failures = 0;
    TEST_CASE("semantic_build_inputs: $(wildcard $(VAR)/*.ext) widens for a "
             "file the glob matches") {
        char root[4096];
        const char *changed = "cfg/data/x.dat";
        struct zcl_devloop_plan plan = {0};
        struct zcl_devloop_facts_verdict v = {0};
        struct zcl_devloop_facts_report rep = {0};
        ASSERT(test_mkdtemp(root, sizeof(root), "sbi_wildvar") != NULL);
        ASSERT(sbi_write_tu(root, NULL));
        ASSERT(sbi_write(root, "Makefile",
                         "DATADIR := cfg/data\n"
                         "DATASRC := $(wildcard $(DATADIR)/*.dat)\n"
                         "build/a.o: " SBI_TU " $(DATASRC)\n"
                         "\t$(CC) -c $< -o $@\n"));
        ASSERT(sbi_write(root, changed, ""));
        ASSERT(zcl_devloop_plan_files(&changed, 1, &plan));
        ASSERT(zcl_devloop_facts_consume(root, &changed, 1, "facts", NULL,
                                         &plan, &v, &rep));
        ASSERT(!rep.complete);
        ASSERT(sbi_tu_affected(&rep, "build-input-changed"));
        ASSERT(plan.closure_universal);
        zcl_devloop_facts_report_free(&rep);
    } TEST_END
    return failures;
}

/* (b, $(shell find ... -name '*.ext')): a dynamic directory listing built
 * at parse time. Confirms the raw shell-argument text (including the glob)
 * is still tokenized and matched. */
static int sbit_t_shell_find(void)
{
    int failures = 0;
    TEST_CASE("semantic_build_inputs: $(shell find ... -name PATTERN) "
             "widens for a file the pattern matches") {
        char root[4096];
        const char *changed = "cfg/gen/x.tpl";
        struct zcl_devloop_plan plan = {0};
        struct zcl_devloop_facts_verdict v = {0};
        struct zcl_devloop_facts_report rep = {0};
        ASSERT(test_mkdtemp(root, sizeof(root), "sbi_shellfind") != NULL);
        ASSERT(sbi_write_tu(root, NULL));
        ASSERT(sbi_write(root, "Makefile",
                         "TPLSRC := $(shell find cfg/gen -name '*.tpl')\n"
                         "build/a.o: " SBI_TU " $(TPLSRC)\n"
                         "\t$(CC) -c $< -o $@\n"));
        ASSERT(sbi_write(root, changed, ""));
        ASSERT(zcl_devloop_plan_files(&changed, 1, &plan));
        ASSERT(zcl_devloop_facts_consume(root, &changed, 1, "facts", NULL,
                                         &plan, &v, &rep));
        ASSERT(!rep.complete);
        ASSERT(sbi_tu_affected(&rep, "build-input-changed"));
        ASSERT(plan.closure_universal);
        zcl_devloop_facts_report_free(&rep);
    } TEST_END
    return failures;
}

/* (b, pattern rule `%.gen: %.src`): a static pattern rule names no
 * particular path, only a suffix pattern. Confirms the whole-line scan
 * (not just var definitions) matches target/prerequisite lines too. */
static int sbit_t_pattern_rule(void)
{
    int failures = 0;
    TEST_CASE("semantic_build_inputs: a pattern rule prerequisite widens "
             "for a file its suffix matches") {
        char root[4096];
        const char *changed = "cfg/thing.src";
        struct zcl_devloop_plan plan = {0};
        struct zcl_devloop_facts_verdict v = {0};
        struct zcl_devloop_facts_report rep = {0};
        ASSERT(test_mkdtemp(root, sizeof(root), "sbi_patrule") != NULL);
        ASSERT(sbi_write_tu(root, NULL));
        ASSERT(sbi_write(root, "Makefile",
                         "build/a.o: " SBI_TU "\n"
                         "\t$(CC) -c $< -o $@\n"
                         "\n"
                         "%.gen: %.src\n"
                         "\ttools/gen $< $@\n"));
        ASSERT(sbi_write(root, changed, ""));
        ASSERT(zcl_devloop_plan_files(&changed, 1, &plan));
        ASSERT(zcl_devloop_facts_consume(root, &changed, 1, "facts", NULL,
                                         &plan, &v, &rep));
        ASSERT(!rep.complete);
        ASSERT(sbi_tu_affected(&rep, "build-input-changed"));
        ASSERT(plan.closure_universal);
        zcl_devloop_facts_report_free(&rep);
    } TEST_END
    return failures;
}

/* (d): a changed path the include graph refuses to answer for (it does not
 * exist on disk, so codeindex will not vouch for its reverse-includes)
 * keeps today's full fallback, exactly like a Makefile mention. */
static int sbit_t_truncated(void)
{
    int failures = 0;
    TEST_CASE("semantic_build_inputs: a path the include graph cannot "
             "answer for keeps the full fallback") {
        char root[4096];
        const char *changed = "cfg/ghost.def";
        struct zcl_devloop_plan plan = {0};
        struct zcl_devloop_facts_verdict v = {0};
        struct zcl_devloop_facts_report rep = {0};
        ASSERT(test_mkdtemp(root, sizeof(root), "sbi_trunc") != NULL);
        ASSERT(sbi_write_tu(root, NULL));
        ASSERT(sbi_write(root, "Makefile", "all:\n\t@true\n"));
        /* changed is never written to root: codeindex cannot verify it. */
        ASSERT(zcl_devloop_plan_files(&changed, 1, &plan));
        ASSERT(zcl_devloop_facts_consume(root, &changed, 1, "facts", NULL,
                                         &plan, &v, &rep));
        ASSERT(!rep.complete);
        ASSERT(strcmp(rep.reason, "build-input-changed") == 0);
        ASSERT(sbi_tu_affected(&rep, "build-input-changed"));
        ASSERT(plan.closure_universal);
        zcl_devloop_facts_report_free(&rep);
    } TEST_END
    return failures;
}

/* (e): a TU whose manifests predate facts revision 3 records none of its
 * conditional lookups, so a created path may answer one it made: the TU is
 * a member, affected whole, though it reads nothing that changed.
 * At revision 3 on, the same empty LOOKUPS say it makes none. */
static int sbit_t_old_revision_created(void)
{
    int failures = 0;
    for (uint8_t rev = 2; rev <= 3; rev++) {
        TEST_CASE("semantic_build_inputs: a path created beside a TU read at "
                  "an old facts revision affects it") {
            char root[4096];
            const char *changed = "src/new_opt.h";
            struct zcl_devloop_plan plan = {0};
            struct zcl_devloop_facts_verdict v = {0};
            struct zcl_devloop_facts_report rep = {0};
            ASSERT(test_mkdtemp(root, sizeof(root), "sbi_oldrev") != NULL);
            ASSERT(sbi_write_tu_rev(root, NULL, rev));
            ASSERT(sbi_write(root, "Makefile", "all:\n\t@true\n"));
            ASSERT(sbi_write(root, changed, "#define NEW_OPT 1\n"));
            ASSERT(zcl_devloop_plan_files(&changed, 1, &plan));
            ASSERT(zcl_devloop_facts_consume(root, &changed, 1, "facts", NULL,
                                             &plan, &v, &rep));
            ASSERT(rep.complete);
            /* a member; the hand-built manifests name no producer, so its
             * verdict is producer-unknown, which already widens it whole */
            ASSERT(sbi_tu_affected(&rep, NULL) == (rev < 3));
            zcl_devloop_facts_report_free(&rep);
        } TEST_END
    }
    return failures;
}

/* (a): a changed .def some TU's manifest lists as a file it read routes
 * through the existing header path (it is never classified as a build
 * input candidate at all, make-mentioned or not). */
static int sbit_t_header_path(void)
{
    int failures = 0;
    TEST_CASE("semantic_build_inputs: a .def a TU includes goes through "
             "the header path, not the build-input widening") {
        char root[4096];
        const char *changed = "cfg/read.def";
        struct zcl_devloop_plan plan = {0};
        struct zcl_devloop_facts_verdict v = {0};
        struct zcl_devloop_facts_report rep = {0};
        ASSERT(test_mkdtemp(root, sizeof(root), "sbi_header") != NULL);
        ASSERT(sbi_write_tu(root, changed));
        ASSERT(sbi_write(root, "Makefile",
                         "build/a.o: " SBI_TU " cfg/read.def\n"
                         "\t$(CC) -c $< -o $@\n"));
        ASSERT(sbi_write(root, changed, "X\n"));
        ASSERT(sbi_write(root, "facts/cfg/read.def.before", "X\n"));
        ASSERT(zcl_devloop_plan_files(&changed, 1, &plan));
        ASSERT(zcl_devloop_facts_consume(root, &changed, 1, "facts", NULL,
                                         &plan, &v, &rep));
        /* Read by a.c's manifest: never the build-input reason, even though
         * the Makefile also names it (the header path decides first). */
        ASSERT(!sbi_tu_affected(&rep, "build-input-changed"));
        zcl_devloop_facts_report_free(&rep);
    } TEST_END
    return failures;
}


/* ---- which Makefile positions can change an object -------------------------------- */

/* sbi_consume with more files in the root: files[] holds path, text pairs
 * up to a NULL path. */
bool sbi_consume_files(const char *tag, const char *makefile,
                       const char *const *files,
                       const char *const *changed, size_t nchanged,
                       struct sbi_run *r)
{
    char root[4096];
    bool ok = test_mkdtemp(root, sizeof(root), tag) != NULL &&
              sbi_write_tu(root, NULL) && sbi_write(root, "Makefile", makefile);
    for (size_t k = 0; ok && files != NULL && files[k] != NULL; k += 2)
        ok = sbi_write(root, files[k], files[k + 1]);
    for (size_t k = 0; ok && k < nchanged; k++)
        ok = sbi_write(root, changed[k], "#!/bin/sh\n");
    ok = ok && zcl_devloop_plan_files(changed, nchanged, &r->plain);
    if (ok)
        memcpy(&r->plan, &r->plain, sizeof(r->plan));
    return ok && zcl_devloop_facts_consume(root, changed, nchanged, "facts",
                                           NULL, &r->plan, &r->v, &r->rep);
}

/* sbi_consume with one more file in the root (an included makefile), when
 * `extra` is not NULL: `extra` is its path and `body` its text. */
bool sbi_consume_with(const char *tag, const char *makefile,
                      const char *extra, const char *body,
                      const char *const *changed, size_t nchanged,
                      struct sbi_run *r)
{
    const char *const files[] = {extra, body, NULL};
    return sbi_consume_files(tag, makefile, extra != NULL ? files : NULL,
                             changed, nchanged, r);
}

bool sbi_consume(const char *tag, const char *makefile,
                 const char *const *changed, size_t nchanged,
                 struct sbi_run *r)
{
    return sbi_consume_with(tag, makefile, NULL, NULL, changed, nchanged, r);
}

/* Every path group the plain plan selected is still selected. */
static bool sbi_kept_groups(const struct sbi_run *r)
{
    for (size_t k = 0; k < r->plain.path_groups_len; k++)
        if (!sbi_has_group(&r->plan, r->plain.path_groups[k]))
            return false;
    return true;
}

/* The narrow verdict: the universe is complete, the TU is not widened, the
 * closure is not universal, and the changed paths keep their test groups. */
bool sbi_narrowed(const struct sbi_run *r)
{
    return r->rep.complete && !sbi_tu_affected(&r->rep, NULL) &&
           !r->plan.closure_universal && sbi_kept_groups(r);
}

bool sbi_widened(const struct sbi_run *r)
{
    return !r->rep.complete &&
           strcmp(r->rep.reason, "build-input-changed") == 0 &&
           sbi_tu_affected(&r->rep, "build-input-changed") &&
           r->plan.closure_universal;
}

/* The shape of the real Makefile's false widenings: printf's '%s' in a
 * $(shell) definition and in a file rule's recipe (shell text, not a make
 * pattern); goal names an object rule only tests or prints (an $(if)
 * condition, a $(filter) pattern, an $(error) message, an echo, a
 * --coverage flag); and a coverage and a lint recipe of .PHONY rules no
 * object rule reaches naming tools/ and tools/verify/<glob>. */
#define SBI_INERT_MAKEFILE                                                     \
    "TOOLCHAIN_RC := $(shell printf '%s' 0)\n"                                 \
    "PROFILES := coverage\n"                                                   \
    "LEASES = $(if $(filter coverage,$(PROFILES)),-DLEASE)\n"                  \
    "COV_CFLAGS = --coverage -O1\n"                                            \
    "ifneq ($(TOOLCHAIN_RC),0)\n"                                              \
    "$(error toolchain: run make coverage)\n"                                  \
    "endif\n"                                                                  \
    "build/a.o: " SBI_TU "\n"                                                  \
    "\t@command -v cc >/dev/null || { echo \"no cc: run make ci\" >&2; "      \
    "exit 2; }\n"                                                              \
    "\t@printf '%s %s\\n' cc a > build/a.cmd\n"                                \
    "\t$(CC) $(LEASES) $(if $(COV),$(COV_CFLAGS)) -c $< -o $@\n"               \
    "\n"                                                                       \
    ".PHONY: ci coverage lint\n"                                               \
    "ci:\n"                                                                    \
    "\t$(MAKE) coverage lint\n"                                                \
    "coverage:\n"                                                              \
    "\t@echo \"== coverage ==\"\n"                                             \
    "\tgcovr --root . --filter 'tools/' --print-summary\n"                     \
    "lint: build/a.o\n"                                                        \
    "\tfor s in tools/verify/*_probe.sh; do sh \"$$s\" tools/verify/*.args; done\n"

/* A changed script and .args file no compile reads, named only by those
 * recipes and patterns: the compile set is empty and precise, and the
 * paths' own test groups stay selected. */
static int sbit_t_inert_positions(void)
{
    int failures = 0;
    TEST_CASE("semantic_build_inputs: a script and an .args file named only "
             "by .PHONY recipes and shell '%s' narrow to an empty compile "
             "set") {
        static const char *const changed[] = {
            "tools/verify/fixed_result_x_probe.sh",
            "tools/verify/fixed_result_x.args"};
        struct sbi_run r = {0};
        ASSERT(sbi_consume("sbi_inert", SBI_INERT_MAKEFILE, changed, 2, &r));
        ASSERT(sbi_narrowed(&r));
        ASSERT(r.rep.naffected == 0);
        zcl_devloop_facts_report_free(&r.rep);
    } TEST_END
    return failures;
}

/* Docs: a .md (never a build input) and a prose .txt under a directory a
 * .PHONY coverage recipe names. Neither can change an object. */
static int sbit_t_doc(void)
{
    int failures = 0;
    TEST_CASE("semantic_build_inputs: a changed doc narrows to an empty "
             "compile set") {
        static const char *const changed[] = {
            "tools/verify/README.fixed-result.txt", "docs/work/verifier.md"};
        struct sbi_run r = {0};
        ASSERT(sbi_consume("sbi_doc", SBI_INERT_MAKEFILE, changed, 2, &r));
        ASSERT(sbi_narrowed(&r));
        ASSERT(r.rep.naffected == 0);
        zcl_devloop_facts_report_free(&r.rep);
    } TEST_END
    return failures;
}

/* A script that is a prerequisite of a generated header a TU reads: the
 * header's readers must compile (the whole catalog does). */
static int sbit_t_generated_header(void)
{
    int failures = 0;
    TEST_CASE("semantic_build_inputs: a script a generated header depends on "
             "compiles the header's readers") {
        static const char *const changed[] = {"tools/gen_a.sh"};
        struct sbi_run r = {0};
        ASSERT(sbi_consume("sbi_genhdr",
                           "build/a.o: " SBI_TU " src/a.h\n"
                           "\t$(CC) -c $< -o $@\n"
                           "src/a.h: tools/gen_a.sh\n"
                           "\tsh tools/gen_a.sh > $@\n",
                           changed, 1, &r));
        ASSERT(sbi_widened(&r));
        zcl_devloop_facts_report_free(&r.rep);
    } TEST_END
    return failures;
}

/* An .args file read by $(shell cat ...) into CFLAGS changes every compile
 * that uses CFLAGS. */
static int sbit_t_args_cflags(void)
{
    int failures = 0;
    TEST_CASE("semantic_build_inputs: an .args file $(shell cat)'d into "
             "CFLAGS widens to the whole catalog") {
        static const char *const changed[] = {"cfg/strict.args"};
        struct sbi_run r = {0};
        ASSERT(sbi_consume("sbi_cflags",
                           "CFLAGS += $(shell cat cfg/strict.args)\n"
                           "build/a.o: " SBI_TU "\n"
                           "\t$(CC) $(CFLAGS) -c $< -o $@\n",
                           changed, 1, &r));
        ASSERT(sbi_widened(&r));
        zcl_devloop_facts_report_free(&r.rep);
    } TEST_END
    return failures;
}

/* A file only a $(wildcard) in a compile source list names, compiled by a
 * static pattern rule: covered. */
static int sbit_t_wildcard_sources(void)
{
    int failures = 0;
    TEST_CASE("semantic_build_inputs: a file a compile source list's "
             "$(wildcard) matches widens") {
        static const char *const changed[] = {"cfg/tpl/x.inc"};
        struct sbi_run r = {0};
        ASSERT(sbi_consume("sbi_wildsrc",
                           "SRCS := " SBI_TU " $(wildcard cfg/tpl/*.inc)\n"
                           "OBJS := $(SRCS:%=build/%.o)\n"
                           "$(OBJS): build/%.o: %\n"
                           "\t$(CC) -c $< -o $@\n",
                           changed, 1, &r));
        ASSERT(sbi_widened(&r));
        zcl_devloop_facts_report_free(&r.rep);
    } TEST_END
    return failures;
}

/* A .PHONY rule an object rule depends on (order-only) runs as part of
 * building the object: its recipe's inputs widen. */
static int sbit_t_phony_prerequisite(void)
{
    int failures = 0;
    TEST_CASE("semantic_build_inputs: a .PHONY prerequisite of an object "
             "rule keeps its recipe's inputs") {
        static const char *const changed[] = {"tools/gen/headers.sh"};
        struct sbi_run r = {0};
        ASSERT(sbi_consume("sbi_phonypre",
                           "build/a.o: " SBI_TU " | gen-headers\n"
                           "\t$(CC) -c $< -o $@\n"
                           ".PHONY: gen-headers\n"
                           "gen-headers:\n"
                           "\tsh tools/gen/headers.sh\n",
                           changed, 1, &r));
        ASSERT(sbi_widened(&r));
        zcl_devloop_facts_report_free(&r.rep);
    } TEST_END
    return failures;
}

/* A .PHONY name listed in a variable an object rule expands: the name's
 * rule is reached, and so are its recipe's inputs. */
static int sbit_t_phony_via_variable(void)
{
    int failures = 0;
    TEST_CASE("semantic_build_inputs: a .PHONY name in a variable an object "
             "rule uses keeps its recipe's inputs") {
        static const char *const changed[] = {"tools/gen/a.sh"};
        struct sbi_run r = {0};
        ASSERT(sbi_consume("sbi_phonyvar",
                           "PRE := gen-a gen-b\n"
                           "build/a.o: " SBI_TU " $(PRE)\n"
                           "\t$(CC) -c $< -o $@\n"
                           ".PHONY: gen-a gen-b\n"
                           "gen-a:\n"
                           "\tsh tools/gen/a.sh\n"
                           "gen-b:\n"
                           "\t@true\n",
                           changed, 1, &r));
        ASSERT(sbi_widened(&r));
        zcl_devloop_facts_report_free(&r.rep);
    } TEST_END
    return failures;
}

/* A .PHONY recipe line that runs make builds objects with whatever it
 * passes: its inputs widen. */
static int sbit_t_phony_submake(void)
{
    int failures = 0;
    TEST_CASE("semantic_build_inputs: a .PHONY recipe line that runs make "
             "keeps its inputs") {
        static const char *const changed[] = {"cfg/strict.args"};
        struct sbi_run r = {0};
        ASSERT(sbi_consume("sbi_submake",
                           "build/a.o: " SBI_TU "\n"
                           "\t$(CC) $(EXTRA) -c $< -o $@\n"
                           ".PHONY: strict\n"
                           "strict:\n"
                           "\t$(MAKE) EXTRA=\"$$(cat cfg/strict.args)\" "
                           "build/a.o\n",
                           changed, 1, &r));
        ASSERT(sbi_widened(&r));
        zcl_devloop_facts_report_free(&r.rep);
    } TEST_END
    return failures;
}

/* A recipe after a conditional whose branches declare different rules
 * belongs to whichever branch make took: it cannot be placed, so it
 * widens. */
static int sbit_t_conditional_recipe(void)
{
    int failures = 0;
    TEST_CASE("semantic_build_inputs: a recipe a conditional leaves between "
             "an object rule and a .PHONY rule widens") {
        static const char *const changed[] = {"tools/v/x.sh"};
        struct sbi_run r = {0};
        ASSERT(sbi_consume("sbi_cond",
                           "ifeq ($(MODE),obj)\n"
                           "build/a.o: " SBI_TU "\n"
                           "else\n"
                           ".PHONY: lint\n"
                           "lint:\n"
                           "endif\n"
                           "\tsh tools/v/x.sh\n",
                           changed, 1, &r));
        ASSERT(sbi_widened(&r));
        zcl_devloop_facts_report_free(&r.rep);
    } TEST_END
    return failures;
}

/* The first rule of a makefile is what a bare make builds: a .PHONY rule
 * there is reached, and so are its recipe's inputs. */
static int sbit_t_default_goal(void)
{
    int failures = 0;
    TEST_CASE("semantic_build_inputs: a .PHONY default goal keeps its "
             "recipe's inputs") {
        static const char *const changed[] = {"tools/gen/h.sh"};
        struct sbi_run r = {0};
        ASSERT(sbi_consume("sbi_goal",
                           ".PHONY: headers\n"
                           "headers:\n"
                           "\tsh tools/gen/h.sh > build/gen.h\n"
                           "build/a.o: " SBI_TU "\n"
                           "\t$(CC) -c $< -o $@\n",
                           changed, 1, &r));
        ASSERT(sbi_widened(&r));
        zcl_devloop_facts_report_free(&r.rep);
    } TEST_END
    return failures;
}

/* A prerequisite spelled under a root the makefile does not define
 * ($(CURDIR)/...) still names the repo path. */
static int sbit_t_rooted_prerequisite(void)
{
    int failures = 0;
    TEST_CASE("semantic_build_inputs: a $(CURDIR)/ prerequisite of a "
             "generated header widens") {
        static const char *const changed[] = {"tools/gen/h.sh"};
        struct sbi_run r = {0};
        ASSERT(sbi_consume("sbi_rooted",
                           "build/gen.h: $(CURDIR)/tools/gen/h.sh\n"
                           "\tsh $< > $@\n",
                           changed, 1, &r));
        ASSERT(sbi_widened(&r));
        zcl_devloop_facts_report_free(&r.rep);
    } TEST_END
    return failures;
}

/* An echo only prints, but one piped into a shell runs what it prints: a
 * goal it names is reached. */
static int sbit_t_echo_into_shell(void)
{
    int failures = 0;
    TEST_CASE("semantic_build_inputs: an echo piped into sh reaches the goal "
             "it names") {
        static const char *const changed[] = {"tools/gen/h.sh"};
        struct sbi_run r = {0};
        ASSERT(sbi_consume("sbi_echo_sh",
                           "build/a.o: " SBI_TU "\n"
                           "\techo \"make headers\" | sh\n"
                           "\t$(CC) -c $< -o $@\n"
                           ".PHONY: headers\n"
                           "headers:\n"
                           "\tsh tools/gen/h.sh > build/gen.h\n",
                           changed, 1, &r));
        ASSERT(sbi_widened(&r));
        zcl_devloop_facts_report_free(&r.rep);
    } TEST_END
    return failures;
}

/* ---- makefiles GNU make reads wider than their literal text ---------------------- */

/* Every case widens a changed tools/x.sh; each that does not is named. */
bool sbi_cases_widen(const struct sbi_case *cases, size_t n)
{
    static const char *const changed[] = {"tools/x.sh"};
    bool all = true;
    for (size_t k = 0; k < n; k++) {
        struct sbi_run r = {0};
        char tag[64];
        bool ok;
        (void)snprintf(tag, sizeof(tag), "sbi_case_%s", cases[k].id);
        ok = sbi_consume_with(tag, cases[k].makefile, cases[k].extra,
                              cases[k].body, changed, 1, &r) &&
             sbi_widened(&r);
        zcl_devloop_facts_report_free(&r.rep);
        if (!ok) {
            printf("[case %s narrowed] ", cases[k].id);
            all = false;
        }
    }
    return all;
}

#define SBI_GEN_A_RULE ".PHONY: gen-a\ngen-a:\n\tsh tools/x.sh > gen.h\n"

/* The default goal is the first rule that is neither a pattern rule nor a
 * special target: a leading %.o rule does not take it. */
static int sbit_t_default_goal_skips_patterns(void)
{
    int failures = 0;
    static const struct sbi_case cases[] = {
        {"20", "%.o: %.c\n\t$(CC) -c $< -o $@\n"
               ".PHONY: all\nall:\n\tsh tools/x.sh > gen.h\n" SBI_OBJ_RULE,
         NULL, NULL},
        {"20b", "build/%.o: src/%.c\n\t$(CC) -c $< -o $@\n"
                ".PHONY: all\nall: headers build/a.o\n"
                ".PHONY: headers\nheaders:\n\tsh tools/x.sh > gen.h\n",
         NULL, NULL},
    };
    TEST_CASE("semantic_build_inputs: a pattern rule first in the makefile "
             "leaves the default goal to the next rule") {
        ASSERT(sbi_cases_widen(cases, SBI_COUNT(cases)));
    } TEST_END
    return failures;
}

/* A prerequisite a transforming call computes can name any .PHONY goal. */
static int sbit_t_computed_prerequisite(void)
{
    int failures = 0;
    static const struct sbi_case cases[] = {
        {"28", "build/a.o: " SBI_TU " $(patsubst x%,%,xgen)\n"
               "\t$(CC) -c $< -o $@\n" SBI_GEN_RULE,
         NULL, NULL},
        {"30", "build/a.o: " SBI_TU " $(addprefix g,en)\n"
               "\t$(CC) -c $< -o $@\n" SBI_GEN_RULE,
         NULL, NULL},
    };
    TEST_CASE("semantic_build_inputs: a prerequisite spelled through "
             "$(patsubst) or $(addprefix) reaches the goal it computes") {
        ASSERT(sbi_cases_widen(cases, SBI_COUNT(cases)));
    } TEST_END
    return failures;
}

/* An automatic variable in a make command names a goal only make knows
 * when it runs, and a shell escape in a goal word is undone by the shell:
 * either can be any .PHONY goal. */
static int sbit_t_computed_goal_word(void)
{
    int failures = 0;
    static const struct sbi_case cases[] = {
        {"60", "build/%.o: src/%.c\n\t$(MAKE) gen-$*\n\t$(CC) -c $< -o $@\n"
               SBI_GEN_A_RULE, NULL, NULL},
        {"61", "build/a.o: " SBI_TU "\n\t$(MAKE) $(@:build/%.o=gen-%)\n"
               "\t$(CC) -c $< -o $@\n" SBI_GEN_A_RULE, NULL, NULL},
        {"62", "build/a.o: " SBI_TU "\n\t$(MAKE) gen-$(basename $(@F))\n"
               "\t$(CC) -c $< -o $@\n" SBI_GEN_A_RULE, NULL, NULL},
        {"67", "build/a.o: " SBI_TU "\n\t$(MAKE) gen\\-a\n"
               "\t$(CC) -c $< -o $@\n" SBI_GEN_A_RULE, NULL, NULL},
        {"41", "build/a.o: " SBI_TU "\n\tprintf \"make gen\\n\" | sh\n"
               "\t$(CC) -c $< -o $@\n" SBI_GEN_RULE, NULL, NULL},
    };
    TEST_CASE("semantic_build_inputs: a make goal spelled with an automatic "
             "variable or a shell escape reaches any .PHONY goal") {
        ASSERT(sbi_cases_widen(cases, SBI_COUNT(cases)));
    } TEST_END
    return failures;
}

/* An echo inside a { } or ( ) group is piped when the group is. */
static int sbit_t_grouped_echo_pipe(void)
{
    int failures = 0;
    static const struct sbi_case cases[] = {
        {"70", "build/a.o: " SBI_TU "\n\t{ echo gen; } | xargs $(MAKE)\n"
               "\t$(CC) -c $< -o $@\n" SBI_GEN_RULE, NULL, NULL},
        {"71", "build/a.o: " SBI_TU "\n"
               "\t( echo gen; echo other ) | xargs $(MAKE)\n"
               "\t$(CC) -c $< -o $@\n" SBI_GEN_RULE, NULL, NULL},
    };
    TEST_CASE("semantic_build_inputs: an echo in a group piped into make "
             "reaches the goal it prints") {
        ASSERT(sbi_cases_widen(cases, SBI_COUNT(cases)));
    } TEST_END
    return failures;
}

/* A sub-make runs its goals whether or not its own rule is reached, and
 * $(MAKE_COMMAND) is make. */
static int sbit_t_submake_goals(void)
{
    int failures = 0;
    static const struct sbi_case cases[] = {
        {"95", SBI_OBJ_RULE ".PHONY: strict gen\nstrict:\n"
               "\t$(MAKE) gen build/a.o\ngen:\n\tsh tools/x.sh > gen.h\n",
         NULL, NULL},
        {"97", "build/a.o: " SBI_TU "\n\t$(MAKE_COMMAND) gen\n"
               "\t$(CC) -c $< -o $@\n" SBI_GEN_RULE, NULL, NULL},
    };
    TEST_CASE("semantic_build_inputs: a sub-make that also builds an object "
             "reaches its other goals, and $(MAKE_COMMAND) runs make") {
        ASSERT(sbi_cases_widen(cases, SBI_COUNT(cases)));
    } TEST_END
    return failures;
}

/* A recipe written after the rule line's ';' is a recipe line of the rule:
 * its sub-make naming a file goal reaches its other goals, as a tab-led
 * one does (95). */
static int sbit_t_submake_inline(void)
{
    int failures = 0;
    static const struct sbi_case cases[] = {
        {"inline_file", SBI_OBJ_RULE ".PHONY: gen ci\n"
                        "gen:\n\tsh tools/x.sh > gen.h\n"
                        "ci: ; $(MAKE) gen build/a.o\n", NULL, NULL},
        {"inline_static", SBI_OBJ_RULE ".PHONY: gen ci\n"
                          "gen:\n\tsh tools/x.sh > gen.h\n"
                          "ci:: ; $(MAKE) gen build/a.o\n", NULL, NULL},
    };
    TEST_CASE("semantic_build_inputs: a sub-make in a recipe after the rule "
             "line's ';' that builds an object reaches its other goals") {
        ASSERT(sbi_cases_widen(cases, SBI_COUNT(cases)));
    } TEST_END
    return failures;
}

/* Text the scanner cannot read to its end widens everything: an unclosed
 * reference, an unclosed conditional. */
static int sbit_t_unreadable_text(void)
{
    int failures = 0;
    static const struct sbi_case cases[] = {
        {"80", SBI_OBJ_RULE ".PHONY: lint\nlint:\n\tsh tools/x.sh $(FOO\n",
         NULL, NULL},
        {"81", SBI_OBJ_RULE "ifeq (1,1)\n.PHONY: lint\nlint:\n"
               "\tsh tools/x.sh\n", NULL, NULL},
        {"82", "X := $(shell cat tools/x.sh\n" SBI_OBJ_RULE, NULL, NULL},
    };
    TEST_CASE("semantic_build_inputs: an unclosed reference or conditional "
             "widens everything") {
        ASSERT(sbi_cases_widen(cases, SBI_COUNT(cases)));
    } TEST_END
    return failures;
}

/* An optional include of a computed word can read any makefile, and one
 * of a variable reads the files it lists. */
static int sbit_t_optional_include(void)
{
    int failures = 0;
    static const struct sbi_case cases[] = {
        {"90b", "all: build/a.o\n-include $(wildcard mk/*.mk)\n" SBI_GEN_RULE,
         "mk/objs.mk", "build/a.o: " SBI_TU " | gen\n\t$(CC) -c $< -o $@\n"},
        {"91", "MK := mk/extra.mk mk/other.mk\n-include $(MK)\n" SBI_OBJ_RULE
               SBI_GEN_RULE, "mk/extra.mk", "build/a.o: | gen\n"},
    };
    TEST_CASE("semantic_build_inputs: an optional include of a computed or "
             "variable word reads what it names") {
        ASSERT(sbi_cases_widen(cases, SBI_COUNT(cases)));
    } TEST_END
    return failures;
}

/* A missing optional include a rule makes: make runs that rule first and
 * reads what it wrote. A rule it prints reaches its goals; a copy of
 * another file or a program's output is text no line holds. */
static int sbit_t_generated_include(void)
{
    int failures = 0;
    static const struct sbi_case cases[] = {
        {"gen_printf", "-include build/gen.mk\nbuild/gen.mk:\n"
                       "\tprintf '%s\\n' 'build/a.o: | gen' > $@\n"
                       SBI_OBJ_RULE SBI_GEN_RULE, NULL, NULL},
        {"gen_copy", "-include build/gen.mk\nbuild/gen.mk: mk/tmpl.mk\n"
                     "\tcp mk/tmpl.mk $@\n" SBI_OBJ_RULE SBI_GEN_RULE,
         "mk/tmpl.mk", "build/a.o: | gen\n"},
        {"gen_program", "-include build/gen.mk\nbuild/gen.mk:\n"
                        "\ttools/mk/emit > $@\n" SBI_OBJ_RULE SBI_GEN_RULE,
         NULL, NULL},
    };
    TEST_CASE("semantic_build_inputs: a generated optional include reaches "
             "the goals its recipe writes, and a copy or program output "
             "widens") {
        ASSERT(sbi_cases_widen(cases, SBI_COUNT(cases)));
    } TEST_END
    return failures;
}

/* The real Makefile's identity markers: a rule that writes only a comment
 * into an optional include. Missing, make writes it before it reads the
 * rest: UNKNOWN. Present, it is read as it stands and names nothing. */
#define SBI_MARKER_RULE                                                        \
    "-include build/ready.mk\nbuild/ready.mk:\n"                              \
    "\t@set -eu; tmp=\"$$(mktemp \"$@.XXXXXX\")\"; "                          \
    "trap 'rm -f \"$$tmp\"' EXIT; SID='$(SID)' tools/dev/sid.sh drop; "       \
    "printf '%s\\n' '# ready' > \"$$tmp\"; mv -f -- \"$$tmp\" \"$@\"\n"

static int sbit_t_generated_marker(void)
{
    int failures = 0;
    static const struct sbi_case missing[] = {
        {"marker_missing", SBI_MARKER_RULE SBI_OBJ_RULE SBI_GEN_RULE, NULL, NULL},
    };
    TEST_CASE("semantic_build_inputs: a missing optional include a rule "
             "makes widens, even one that writes only a comment") {
        ASSERT(sbi_cases_widen(missing, SBI_COUNT(missing)));
    } TEST_END
    return failures;
}

static int sbit_t_generated_comment(void)
{
    int failures = 0;
    static const char *const changed[] = {"tools/x.sh"};
    struct sbi_run r = {0};
    TEST_CASE("semantic_build_inputs: an optional include that exists is "
             "read as it stands, and a comment in it narrows") {
        ASSERT(sbi_consume_with("sbi_gen_comment",
                                SBI_MARKER_RULE SBI_OBJ_RULE SBI_GEN_RULE,
                                "build/ready.mk", "# ready\n", changed, 1, &r));
        ASSERT(sbi_narrowed(&r));
    } TEST_END
    zcl_devloop_facts_report_free(&r.rep);
    return failures;
}

static int sbit_t_generated_joins(void)
{
    int failures = 0;
    static const struct sbi_case cases[] = {
        {"g02", SBI_GEN_INCLUDE("\tprintf 'build/a.o: | g%sn\\n' e > $@\n"),
         NULL, NULL},
        {"g03b", SBI_GEN_INCLUDE("\tprintf 'build/a.o: | ge%c\\n' n > $@\n"),
         NULL, NULL},
        {"g13", SBI_GEN_INCLUDE("\tprintf 'build/a.o: | %s%s\\n' ge n > $@\n"),
         NULL, NULL},
        {"g04", SBI_GEN_INCLUDE("\tprintf 'build/a.o: | g' > $@; "
                                "printf 'en\\n' >> $@\n"), NULL, NULL},
        {"g05", SBI_GEN_INCLUDE("\techo -n 'build/a.o: | ge' > $@ && "
                                "echo n >> $@\n"), NULL, NULL},
    };
    TEST_CASE("semantic_build_inputs: a generated include's text joined by "
             "a printf conversion or by two writes reaches the goal it "
             "joins") {
        ASSERT(sbi_cases_widen(cases, SBI_COUNT(cases)));
    } TEST_END
    return failures;
}

static int sbit_t_generated_unreadable(void)
{
    int failures = 0;
    static const struct sbi_case cases[] = {
        {"g10", SBI_GEN_INCLUDE("\ttrue $(shell printf 'build/a.o: | gen\\n' "
                                "> $@)\n"), NULL, NULL},
        {"g12", SBI_GEN_INCLUDE("\ttools/genmk.sh $@\n"), "tools/genmk.sh",
         "#!/bin/sh\nprintf 'build/a.o: | gen\\n' > \"$1\"\n"},
        {"g15", "all: build/a.o\n" SBI_OBJ_RULE "-include build/gen.mk\n"
                "%:\n\tprintf 'build/a.o: | gen\\n' > $@\n" SBI_GEN_RULE,
         NULL, NULL},
        {"g15_default", "all: build/a.o\n" SBI_OBJ_RULE
                        "-include build/gen.mk\n.DEFAULT:\n"
                        "\tprintf 'build/a.o: | gen\\n' > $@\n" SBI_GEN_RULE,
         NULL, NULL},
    };
    TEST_CASE("semantic_build_inputs: a generated include written by "
             "$(shell), by a program handed its name, or by a match-anything "
             "or .DEFAULT rule widens") {
        ASSERT(sbi_cases_widen(cases, SBI_COUNT(cases)));
    } TEST_END
    return failures;
}

/* The third review's cases (A: a make reference expanded into what
 * printf or echo writes; B: '%' in the written text; C: another rule's
 * recipe writing the include; E: the target handed to a program through
 * a variable): each makes a missing optional include, so each widens
 * whatever its recipe writes. */
#define SBI_GENMK "tools/genmk.sh"
static int sbit_t_generated_reviewed(void)
{
    int failures = 0;
    static const struct sbi_case cases[] = {
        {"h01", "GN := ge n\n" SBI_GEN_INCLUDE("\tprintf 'build/a.o: | %s%s\\n' "
                                              "$(GN) > $@\n"), NULL, NULL},
        {"h02", "FMT := 'build/a.o: | %s\\n'\n"
                SBI_GEN_INCLUDE("\tprintf $(FMT) gen > $@\n"), NULL, NULL},
        {"h03", "CONV := %s\n" SBI_GEN_INCLUDE("\tprintf 'build/a.o: | "
                                              "$(CONV)\\n' gen > $@\n"),
         NULL, NULL},
        {"h04", "all: build/a.o\n" SBI_OBJ_RULE "-include build/gen.mk\n"
                "build/gen.mk:\n\tprintf 'build/a.o: build/%%.o: | gen-%%\\n' "
                "> $@\n" SBI_GEN_A_RULE, NULL, NULL},
        {"h04_pct", SBI_GEN_INCLUDE("\tprintf 'build/a.o: build/%%.o: | g%%\\n' "
                                    "> $@\n"), NULL, NULL},
        {"h05", "OCT := ge\\\\0156\n" SBI_GEN_INCLUDE("\techo \"build/a.o: | "
                                                     "$(OCT)\" > $@\n"),
         NULL, NULL},
        {"h06", "all: build/a.o\n" SBI_OBJ_RULE "-include build/gen.mk\n"
                "build/gen.mk:: " SBI_TU "\n\tprintf 'build/a.o: | g' > $@\n"
                "build/gen.mk:: " SBI_TU "\n\tprintf 'en\\n' >> $@\n" SBI_GEN_RULE,
         NULL, NULL},
        {"h07", "all: build/a.o\n" SBI_OBJ_RULE "-include build/gen.mk\n"
                "build/gen.mk: build/part.txt\n\tprintf 'en\\n' >> $@\n"
                "build/part.txt:\n\tprintf 'build/a.o: | g' > build/gen.mk; "
                "touch $@\n" SBI_GEN_RULE, NULL, NULL},
        {"h08", "all: build/a.o\n" SBI_OBJ_RULE "-include build/gen.mk\n"
                "build/gen.mk: build/stamp\n\ttouch $@\nbuild/stamp:\n"
                "\tprintf 'build/a.o: | gen\\n' > build/gen.mk; touch $@\n"
                SBI_GEN_RULE, NULL, NULL},
        {"h10", "GEN_MK := build/gen.mk\nall: build/a.o\n" SBI_OBJ_RULE
                "-include $(GEN_MK)\n$(GEN_MK):\n\t" SBI_GENMK " $(GEN_MK)\n"
                SBI_GEN_RULE, SBI_GENMK,
         "#!/bin/sh\nprintf \"build/a.o: | gen\\n\" > \"$1\"\n"},
        {"h11", "OUT := build/gen.mk\n"
                SBI_GEN_INCLUDE("\tZOUT=$(OUT) " SBI_GENMK "\n"), SBI_GENMK,
         "#!/bin/sh\nprintf \"build/a.o: | gen\\n\" > \"$ZOUT\"\n"},
        {"h14", SBI_GEN_INCLUDE("\t/usr/bin/printf 'build/a.o: | %s\\n' gen "
                                "> $@\n"), NULL, NULL},
        {"h15", "all: build/a.o\n" SBI_OBJ_RULE "-include build/gen.mk\n"
                "build/gen.mk:\n\tprintf '%s\\n' 'build/a.o: build/%.o: | "
                "gen-%' > $@\n" SBI_GEN_A_RULE, NULL, NULL},
        {"h16", SBI_GEN_INCLUDE("\tprintf 'build/a.o: | %s%s\\n' g e n > $@\n"),
         NULL, NULL},
    };
    TEST_CASE("semantic_build_inputs: a missing optional include a rule "
             "makes widens whatever its recipe writes") {
        ASSERT(sbi_cases_widen(cases, SBI_COUNT(cases)));
    } TEST_END
    return failures;
}

int test_semantic_build_inputs(void)
{
    return sbit_t_narrow() | sbit_t_makefile_mention() | sbit_t_bare_dir() |
          sbit_t_wildcard_var() | sbit_t_shell_find() | sbit_t_pattern_rule() |
          sbit_t_truncated() | sbit_t_old_revision_created() |
          sbit_t_header_path() |
          sbit_t_inert_positions() | sbit_t_doc() |
          sbit_t_generated_header() | sbit_t_args_cflags() |
          sbit_t_wildcard_sources() | sbit_t_phony_prerequisite() |
          sbit_t_phony_via_variable() | sbit_t_phony_submake() |
          sbit_t_conditional_recipe() | sbit_t_default_goal() |
          sbit_t_rooted_prerequisite() | sbit_t_echo_into_shell() |
          sbit_t_default_goal_skips_patterns() |
          sbit_t_computed_prerequisite() | sbit_t_computed_goal_word() |
          sbit_t_grouped_echo_pipe() | sbit_t_submake_goals() |
          sbit_t_submake_inline() |
          sbit_t_unreadable_text() | sbit_t_optional_include() |
          sbit_t_generated_include() | sbit_t_generated_marker() |
          sbit_t_generated_comment() |
          sbit_t_generated_joins() | sbit_t_generated_unreadable() |
          sbit_t_generated_reviewed() | sbi_guard_suite();
}
