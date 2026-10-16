/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: selftest of the capability-closure gate. Each case builds a fixture
 * tree in a throwaway directory, with a build epoch of real compiled objects,
 * and requires the gate to refuse what it must refuse and accept the positive
 * controls with the same status and the same words as the script it replaces.
 * Fixtures need no build epoch of this checkout.
 */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "gate_capability_closure_priv.h"
#include "lintc.h"
#include "lintc_proc.h"
#include "lintc_sig.h"

enum { CGS_CASES = 7, CGS_FILLER = 500 };

static const char k_fx0[] = "build/dev-obj/epochs/fx0";

static const char k_use[] = "extern int connect(int, int, int);\nint use_it(void) { return connect(1, 2, 3); }\n";

struct cgs_res { char *text; int rc; };

/* The host's gate setup with every ambient knob pinned for the fixture. */
static void cgs_cfg(struct ccg_cfg *cfg)
{
    ccg_host_cfg(cfg);
    cfg->symmetry = 1;
    cfg->baseline = 0;
}

static int cgs_cc_once(const char *src, const char *obj, const char *flag, int c23)
{
    char *argv[8] = { (char *)"cc" };
    int k = 1, code = 1;
    struct lcp_spec sp = { argv, NULL, NULL, LCP_QUIET, 1000 };
    if (c23)
        argv[k++] = (char *)"-std=c23";
    if (flag)
        argv[k++] = (char *)flag;
    argv[k++] = (char *)"-c";
    argv[k++] = (char *)src;
    argv[k++] = (char *)"-o";
    argv[k++] = (char *)obj;
    argv[k] = NULL;
    return lcp_run(&sp, NULL, &code) == 0 && code == 0;
}

/* Compiles fx/src_rel to fx/obj_rel as C23, else as the compiler's default. */
static int cgs_cc(const struct ccs_fx *fx, const char *src_rel, const char *obj_rel, const char *flag)
{
    char src[CCD_PATH], obj[CCD_PATH], dir[CCD_PATH];
    ccs_path(fx, src_rel, src);
    ccs_path(fx, obj_rel, obj);
    snprintf(dir, sizeof dir, "%s", obj);
    *strrchr(dir, '/') = '\0';
    return csr_mkdirs(dir) == 0 && (cgs_cc_once(src, obj, flag, 1) || cgs_cc_once(src, obj, flag, 0)) ? 0 : -1;
}

/* The unit every filler shares: no undefined symbol. */
static int cgs_filler(const struct ccs_fx *fx)
{
    return ccs_put(fx, ".filler.c", "static int filler_fn(int x) { return x + 1; }\n"
                                    "int filler_export(int x) { return filler_fn(x) + 1; }\n") == 0
           && cgs_cc(fx, ".filler.c", ".filler.o", NULL) == 0 ? 0 : -1;
}

/* Hard links filler_1..N of one compiled unit under fx/dir_rel. */
static int cgs_links(const struct ccs_fx *fx, const char *from_rel, const char *dir_rel, const char *ext)
{
    char from[CCD_PATH], to[CCD_PATH], rel[CCD_PATH];
    ccs_path(fx, from_rel, from);
    ccs_path(fx, dir_rel, to);
    if (csr_mkdirs(to) != 0)
        return -1;
    for (int i = 1; i <= CGS_FILLER; i++) {
        snprintf(rel, sizeof rel, "%s/filler_%d.%s", dir_rel, i, ext);
        ccs_path(fx, rel, to);
        if (link(from, to) != 0)
            return -1;
    }
    return 0;
}

/* The anti-hollow floor of filler objects, each with its source: an object
 * without a source in the tree is foreign and not graded. */
static int cgs_epoch(const struct ccs_fx *fx, const char *dir)
{
    char objs[CCD_PATH], srcs[CCD_PATH];
    snprintf(objs, sizeof objs, "%s/%s/filler", dir, k_fx0);
    snprintf(srcs, sizeof srcs, "%s/filler", dir);
    return cgs_links(fx, ".filler.o", objs, "o") == 0 && cgs_links(fx, ".filler.c", srcs, "c") == 0 ? 0 : -1;
}

/* A fixture root: the filler epoch, the one classified symbol (connect is
 * CAP_NETWORK) and exactly the given module rows. */
static int cgs_base(const struct ccs_fx *fx, const char *dir, const char *rows)
{
    char rel[CCD_PATH];
    int bad = cgs_epoch(fx, dir);
    snprintf(rel, sizeof rel, "%s/engine/composition/capability_symbols.def", dir);
    bad |= ccs_put(fx, rel, "ZCL_CAPABILITY_SYMBOL(\"connect\", CAP_NETWORK, \"\")\n");
    snprintf(rel, sizeof rel, "%s/engine/composition/module_capabilities.def", dir);
    return bad | ccs_put(fx, rel, rows);
}

/* Writes dir/src and compiles it to its epoch object, .c becoming .o. */
static int cgs_unit(const struct ccs_fx *fx, const char *dir, const char *src, const char *code, const char *flag)
{
    char s[CCD_PATH], o[CCD_PATH];
    snprintf(s, sizeof s, "%s/%s", dir, src);
    snprintf(o, sizeof o, "%s/%s/%.*s.o", dir, k_fx0, (int)(strlen(src) - 2), src);
    return ccs_put(fx, s, code) == 0 && cgs_cc(fx, s, o, flag) == 0 ? 0 : -1;
}

/* A pre-formatted module row. */
static const char *cgs_row(char *buf, size_t cap, const char *path, const char *caps)
{
    snprintf(buf, cap, "ZCL_MODULE_CAPABILITY(\"%s\", %s, \"test\")\n", path, caps);
    return buf;
}

static int cgs_run(const struct ccs_fx *fx, const char *dir, const struct ccg_cfg *base, struct cgs_res *r)
{
    struct ccg_cfg cfg = *base;
    char root[CCD_PATH];
    size_t n = 0;
    FILE *m;
    ccs_path(fx, dir, root);
    r->text = NULL;
    if (!(m = open_memstream(&r->text, &n)))
        return r->rc = -1;
    cfg.out = cfg.err = m;
    r->rc = ccg_check_root(&cfg, root);
    fclose(m);
    return r->rc;
}

/* The gate text a failed case leaves for the reader. */
static void cgs_show(const char *text)
{
    for (const char *p = text ? text : ""; *p;) {
        const char *nl = strchr(p, '\n');
        size_t n = nl ? (size_t)(nl - p) : strlen(p);
        printf("    %.*s\n", (int)n, p);
        p += n + (nl != NULL);
    }
}

/* The gate ended with status want (any nonzero when want is negative) and its
 * text holds every needle. */
static int cgs_verdict(struct cgs_res *r, int want, const char *const *needles, const char *label)
{
    char name[600] = "";
    int ok = want < 0 ? r->rc > 0 : r->rc == want;
    for (; ok && needles && *needles; needles++)
        ok = r->text && strstr(r->text, *needles);
    if (want < 0)
        snprintf(name, sizeof name, "%s (rc=%d)", label, r->rc);
    if (!ok)
        cgs_show(r->text);
    free(r->text);
    return ccs_say(ok, want < 0 ? name : label);
}

/* Runs the gate on fx/dir and judges it. */
static int cgs_check(const struct ccs_fx *fx, const char *dir, const struct ccg_cfg *cfg, int want,
                     const char *const *needles, const char *label)
{
    struct cgs_res r;
    cgs_run(fx, dir, cfg, &r);
    return cgs_verdict(&r, want, needles, label);
}

/* A. an undeclared strong-undefined reach is the core property. */
static int cgs_case_a(const struct ccs_fx *fx)
{
    struct ccg_cfg cfg;
    const char *const need[] = { "undeclared reach", NULL };
    cgs_cfg(&cfg);
    if (cgs_base(fx, "a", "") != 0 || cgs_unit(fx, "a", "fixture_src/undeclared_user.c", k_use, NULL) != 0)
        return ccs_say(0, "A: fixture");
    return cgs_check(fx, "a", &cfg, -1, need, "A: undeclared strong-undefined reach to a classified symbol");
}

/* D. a correct fixture passes; restart-base.o, a relocatable aggregate of the
 * same objects, carries an unclassified edge and must stay unscanned. */
static int cgs_case_d(const struct ccs_fx *fx)
{
    struct ccg_cfg cfg;
    char row[CCD_PATH];
    cgs_cfg(&cfg);
    if (cgs_base(fx, "d", cgs_row(row, sizeof row, "fixture_src/declared_user.c", "CAP_NETWORK")) != 0
        || cgs_unit(fx, "d", "fixture_src/declared_user.c", k_use, NULL) != 0
        || ccs_put(fx, "d/.restart-base.c", "extern int aggregate_only_unknown(void);\n"
                                           "int aggregate_edge(void) { return aggregate_only_unknown(); }\n") != 0
        || cgs_cc(fx, "d/.restart-base.c", "d/build/dev-obj/epochs/fx0/restart-base.o", NULL) != 0)
        return ccs_say(0, "D: fixture");
    return cgs_check(fx, "d", &cfg, 0, NULL, "D: a correctly declared, fully-used fixture passes (positive control)");
}

/* E. an epoch below the object floor is UNPROVEN, never a clean pass. */
static int cgs_case_e(const struct ccs_fx *fx)
{
    struct ccg_cfg cfg;
    const char *const need[] = { "UNPROVEN", NULL };
    char rel[CCD_PATH];
    cgs_cfg(&cfg);
    ccs_path(fx, "e/build/dev-obj/epochs/fx0", rel);
    if (csr_mkdirs(rel) != 0 || ccs_put(fx, "e/engine/composition/capability_symbols.def",
                                        "ZCL_CAPABILITY_SYMBOL(\"connect\", CAP_NETWORK, \"\")\n") != 0
        || ccs_put(fx, "e/engine/composition/module_capabilities.def", "") != 0)
        return ccs_say(0, "E: fixture");
    return cgs_check(fx, "e", &cfg, 2, need, "E: an epoch below the object floor is UNPROVEN, exit 2, never 0");
}

/* C. a WEAK-undefined reach is still a reach: the regression case for an
 * extraction that kept only strong references. */
static int cgs_case_c(const struct ccs_fx *fx)
{
    struct ccg_cfg cfg;
    const char *const need[] = { "undeclared reach", NULL };
    cgs_cfg(&cfg);
    if (cgs_base(fx, "c", "") != 0
        || cgs_unit(fx, "c", "fixture_src/weak_undeclared_user.c",
                    "extern __attribute__((weak)) int connect(int, int, int);\n"
                    "int use_weak(void) { return connect(1, 2, 3); }\n", NULL) != 0)
        return ccs_say(0, "C: fixture");
    return cgs_check(fx, "c", &cfg, -1, need, "C: undeclared WEAK-undefined reach to a classified symbol (regression)");
}

/* F. a declared row with no compiled object, above the baseline, is a scan
 * that did not happen: the partial-epoch regression that the object floor
 * cannot see. */
static int cgs_case_f(const struct ccs_fx *fx)
{
    struct ccg_cfg cfg;
    char row[CCD_PATH];
    const char *const need[] = { "UNPROVEN", "phantom_tool.c", NULL };
    cgs_cfg(&cfg);
    if (cgs_base(fx, "f", cgs_row(row, sizeof row, "fixture_src/phantom_tool.c", "CAP_NETWORK")) != 0
        || ccs_put(fx, "f/fixture_src/phantom_tool.c", "int phantom_export(int x) { return x + 1; }\n") != 0)
        return ccs_say(0, "F: fixture");
    return cgs_check(fx, "f", &cfg, 2, need,
                     "F: a partial epoch missing a declared file (above the coverage baseline) is UNPROVEN, exit 2, never 0 or 1");
}

/* M. a valid object with no symbols is still compiled evidence: nm prints no
 * row for it, so coverage must come from the frozen object list. */
static int cgs_case_m(const struct ccs_fx *fx)
{
    struct ccg_cfg cfg;
    char row[CCD_PATH];
    cgs_cfg(&cfg);
    cfg.os = CCD_LINUX;
    if (cgs_base(fx, "m", cgs_row(row, sizeof row, "fixture_src/empty_user.c", "CAP_NONE")) != 0
        || cgs_unit(fx, "m", "fixture_src/empty_user.c", "typedef int empty_user_not_on_this_platform;\n", NULL) != 0)
        return ccs_say(0, "M: fixture");
    return cgs_check(fx, "m", &cfg, 0, NULL, "M: a symbol-free object is present coverage evidence");
}

/* R. the leftover object of a failed candidate has no source in this tree: it is
 * foreign, counted and not graded. Case A is the other half. */
static int cgs_case_r(const struct ccs_fx *fx)
{
    struct ccg_cfg cfg;
    const char *const need[] = { "foreign-objects=1", NULL };
    cgs_cfg(&cfg);
    if (cgs_base(fx, "r", "") != 0 || ccs_put(fx, ".foreign_verify_attest.c", k_use) != 0
        || cgs_cc(fx, ".foreign_verify_attest.c", "r/build/dev-obj/epochs/fx0/tools/dev/verify_attest.o", NULL) != 0)
        return ccs_say(0, "R: fixture");
    return cgs_check(fx, "r", &cfg, 0, need, "R: an object whose source is absent is foreign, counted, and not graded");
}

static int cgs_cases(const struct ccs_fx *fx)
{
    return cgs_case_a(fx) + cgs_case_c(fx) + cgs_case_d(fx) + cgs_case_e(fx) + cgs_case_f(fx) + cgs_case_m(fx) +
           cgs_case_r(fx);
}

int check_capability_closure_selftest(void)
{
    struct ccs_fx fx;
    int fails;
    if (lsc_install() != 0 || ccs_scratch(&fx) != 0) {
        fputs("check_capability_closure selftest: cannot prepare the scratch directory\n", stderr);
        return 2;
    }
    if (cgs_filler(&fx) != 0) {
        fputs("check_capability_closure --selftest: FATAL \xe2\x80\x94 cannot compile fixture objects with cc\n", stderr);
        lsc_unblock();
        rap_rm_rf(fx.base);
        return 2;
    }
    puts("== check_capability_closure selftest ==");
    fails = cgs_cases(&fx);
    lsc_unblock();
    rap_rm_rf(fx.base);
    if (fails == 0)
        printf("== selftest: PASS (%d/%d) ==\n", CGS_CASES, CGS_CASES);
    else
        puts("== selftest: FAIL ==");
    return fails == 0 ? 0 : 1;
}
