/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Write the declaration-identity consumer fixture tree, its variants and their depfiles for the checked-in and live consumer tests. */
#include "test/semantic_consumer_fixture.h"

#include "base/safe_alloc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static const char k_scx_header[] =
    "#ifndef CX_H\n"
    "#define CX_H\n"
    "#define CX_CAP 64\n"
    "#define CX_MODE 1\n"
    "#define CX_BASE 3\n"
    "#define CX_SCALE (CX_BASE * 2)\n"
    "#define CX_PAD 4\n"
    "typedef int cx_count;\n"
    "struct cx_big { int a; char buf[CX_CAP]; };\n"
    "struct cx_small { char pad[CX_PAD]; int n; };\n"
    "typedef struct cx_big cx_big_t;\n"
    "int cx_fill(struct cx_big *b);\n"
    "int cx_count_of(cx_count c);\n"
    "int cx_sum(int v);\n"
    "int cx_hook(int v);\n"
    "#endif\n";

static const char k_scx_a[] =
    "#include \"cx.h\"\n"
    "int cx_fill(struct cx_big *b) { b->a = 1; return (int)sizeof(b->buf); }\n"
    "static int cx_twice(int v) { return v * 2; }\n"
    "int cx_top_a(void);\n"
    "int cx_top_a(void) { return cx_twice(cx_sum(1)); }\n";

static const char k_scx_b[] =
    "#include \"cx.h\"\n"
    "#if CX_MODE > 1\n"
    "int cx_count_of(cx_count c) { return (int)c * 2; }\n"
    "#else\n"
    "int cx_count_of(cx_count c) { return (int)c; }\n"
    "#endif\n"
    "static int cx_twice(int v) { return v + v; }\n"
    "int cx_top_b(void);\n"
    "int cx_top_b(void) { return cx_twice(cx_count_of(2)); }\n";

static const char k_scx_c[] =
    "#include \"cx.h\"\n"
    "int cx_sum(int v) { struct cx_small s = {.n = v};"
    " return s.n + (int)sizeof(s) + CX_SCALE; }\n"
    "int cx_hook(int v) { return v - 1; }\n";

static const char k_scx_d[] =
    "#include \"cx.h\"\n"
    "int (*const cx_hook_ref)(int) = cx_hook;\n"
    "int cx_top_d(void);\n"
    "int cx_top_d(void) { return cx_sum(3); }\n"
    "int cx_size_d(void);\n"
    "int cx_size_d(void) { return (int)sizeof(cx_big_t); }\n";

static const char k_scx_e[] =
    "#include \"cx.h\"\n"
    "int cx_top_e(void);\n"
    "int cx_top_e(void) { return 5; }\n";

const char *const k_scx_paths[SCX_FILE_COUNT] = {SCX_HEADER, SCX_A, SCX_B,
                                                 SCX_C,      SCX_D, SCX_E};
const char *const k_scx_tus[SCX_TU_COUNT] = {SCX_A, SCX_B, SCX_C, SCX_D,
                                             SCX_E};
static const char *const k_scx_bodies[SCX_FILE_COUNT] = {
    k_scx_header, k_scx_a, k_scx_b, k_scx_c, k_scx_d, k_scx_e};

const char *const k_scx_flags[] = {"-std=c23", "-g1", "-O1",
                                   "-I" SCX_DIR "/include"};
const size_t k_scx_nflags = sizeof(k_scx_flags) / sizeof(k_scx_flags[0]);

#define SCX_HOOK_END "int cx_hook(int v);\n#endif"
#define SCX_B_END "cx_count_of(2)); }\n"
#define SCX_C_END " return s.n + (int)sizeof(s) + CX_SCALE; }\n" \
                  "int cx_hook(int v) { return v - 1; }\n"
#define SCX_TICK "static inline int cx_tick(int v) { return v + 1"
#define SCX_CTR_B SCX_B_END "int cx_ctr_b(void);\n" \
                  "int cx_ctr_b(void) { return __COUNTER__; }\n"
#define SCX_STATE_B(n) SCX_B_END "void cx_set_b(void);\n" \
                       "void cx_set_b(void) { cx_state = " n "; }\n" \
                       "int cx_get_b(void);\n" \
                       "int cx_get_b(void) { return cx_state; }\n"
#define SCX_ALIAS_C(tail) " return s.n + (int)sizeof(s) + CX_SCALE" tail "; }\n" \
                          "int cx_hook(int v) { return v - 1; }\n" \
                          "int cx_sum_alias(int v) " \
                          "__attribute__((alias(\"cx_sum\")));\n"
#define SCX_OPT_H "int cx_hook(int v);\n#if __has_include(\"cx_opt.h\")\n" \
                  "#define CX_OPT 1\n#else\n#define CX_OPT 0\n#endif\n#endif"
#define SCX_OPT_B SCX_B_END "int cx_opt_b(void);\n" \
                  "int cx_opt_b(void) { return CX_OPT; }\n"
#define SCX_E_END "int cx_top_e(void) { return 5; }\n"
#define SCX_CLEANUP_E(n) SCX_E_END "static int cx_seen;\n" \
                         "static void cx_rel(int *p) { cx_seen = *p + " n \
                         "; }\nint cx_work(int x);\nint cx_work(int x)\n" \
                         "{\n    __attribute__((cleanup(cx_rel))) int v = x;\n" \
                         "    return v + 3;\n}\n"
/* The includer renames every external cx_c.c may define, so no symbol is
 * defined in two TUs. */
#define SCX_UNITY_E SCX_E_END "#define cx_sum cx_e_sum\n" \
                    "#define cx_hook cx_e_hook\n#define cx_get cx_e_get\n" \
                    "#define cx_tail cx_e_tail\n#include \"cx_c.c\"\n" \
                    "#undef cx_sum\n#undef cx_hook\n#undef cx_get\n" \
                    "#undef cx_tail\nint cx_use_e(int x);\n" \
                    "int cx_use_e(int x) { return cx_e_sum(x) + 2; }\n"
#define SCX_HOOK_C "CX_SCALE; }\nint cx_hook(int v) { return v - 1; }\n"
#define SCX_SUM2_C "int cx_sum2(void);\nint cx_sum2(void) { return __LINE__; }\n"
#define SCX_UNITY2_E SCX_E_END "#define cx_sum cx_e_sum\n" \
                     "#define cx_sum2 cx_e_sum2\n#define cx_hook cx_e_hook\n" \
                     "#include \"cx_c.c\"\n" \
                     "#undef cx_sum\n#undef cx_sum2\n#undef cx_hook\n"
#define SCX_TAIL_C(gap) "extern int cx_tail;\nint cx_get(void);\n" \
                        "int cx_get(void) { return cx_tail; }\n" gap \
                        "int cx_tail = 1;\n"
#define SCX_D_END "int cx_size_d(void) { return (int)sizeof(cx_big_t); }\n"
#define SCX_CALL_D(fn) SCX_D_END "int " fn "(int v);\nint cx_call_d(void);\n" \
                       "int cx_call_d(void) { return " fn "(4); }\n"
#define SCX_CTR_UNITY_E SCX_UNITY_E "int cx_ctr_e(void);\n" \
                        "int cx_ctr_e(void) { return __COUNTER__; }\n"
#define SCX_UNITY_AB_E SCX_E_END "#define cx_sum cx_e_sum\n" \
                       "#define cx_hook cx_e_hook\n#include \"cx_c.c\"\n" \
                       "#undef cx_sum\n#undef cx_hook\n" \
                       "#define cx_fill cx_e_fill\n#define cx_top_a cx_e_top_a\n" \
                       "#include \"cx_a.c\"\n#undef cx_fill\n#undef cx_top_a\n"
#define SCX_TOP_A "int cx_top_a(void) { return cx_twice(cx_sum(1)); }"
#define SCX_HOOKREF_D SCX_D_END "int cx_e_hook(int v);\n" \
                      "int (*const cx_e_hook_ref)(int) = cx_e_hook;\n"
#define SCX_INL_H(body) "int cx_hook(int v);\nstatic inline int cx_inl(int v)" \
                        " { return " body "; }\n#endif"
#define SCX_INL_B SCX_B_END "int cx_inl_b(int v);\n" \
                  "int cx_inl_b(int v) { return cx_inl(v) + 9; }\n"
#define SCX_INL_D SCX_D_END "int (*cx_inl_get(void))(int);\n" \
                  "int (*cx_inl_get(void))(int) { return cx_inl; }\n"
/* Every reader defines its own copy of the header's static: each is
 * affected and seeds it, whether or not its own code calls it. */
#define SCX_ALL_IFACE {"interface", "interface", "interface", "interface", \
                       "interface"}
#define SCX_ALL {true, true, true, true, true}
#define SCX_SMALL_E SCX_E_END "int cx_small_e(void);\n" \
                    "int cx_small_e(void) { struct cx_small s = {0}; " \
                    "return s.n; }\n"
#define SCX_ALL_POS {"position-dependent", "position-dependent", \
                     "position-dependent", "position-dependent", \
                     "position-dependent"}
#define SCX_ALL_INC {"include-resolution-change", "include-resolution-change", \
                     "include-resolution-change", "include-resolution-change", \
                     "include-resolution-change"}
/* At the fixture's -g1 a reader of a changed header that no other rule
 * reaches is in the compile set only: clang's DWARF 5 line table records
 * the header's MD5, which any byte of it changes, a comment too. */
#define SCX_DBG "debug-position"
#define SCX_ALL_DBG {SCX_DBG, SCX_DBG, SCX_DBG, SCX_DBG, SCX_DBG}

const struct scx_edit k_scx_edits[SCX_VARIANT_COUNT] = {
    [SCX_BASE] = {.name = "base"},
    [SCX_LAYOUT] = {.name = "layout", .file = SCX_HEADER,
                    .from = "char buf[CX_CAP]; };",
                    .to = "char buf[CX_CAP]; int extra; };",
                    .changed = {SCX_HEADER},
                    .affected = SCX_ALL,
                    .reason = {"interface", SCX_DBG, SCX_DBG,
                               "interface", SCX_DBG},
                    .obligations = ""},
    [SCX_MACRO] = {.name = "macro", .file = SCX_HEADER,
                   .from = "#define CX_CAP 64", .to = "#define CX_CAP 65",
                   .changed = {SCX_HEADER},
                   .affected = SCX_ALL,
                   .reason = {"interface", SCX_DBG, SCX_DBG,
                              "interface", SCX_DBG},
                   .obligations = ""},
    [SCX_COND] = {.name = "cond", .file = SCX_HEADER,
                  .from = "#define CX_MODE 1", .to = "#define CX_MODE 2",
                  .changed = {SCX_HEADER},
                  .affected = SCX_ALL,
                  .reason = {SCX_DBG, "macro-conditional", SCX_DBG,
                             SCX_DBG, SCX_DBG},
                  .obligations = ""},
    [SCX_NESTED] = {.name = "nested", .file = SCX_HEADER,
                    .from = "#define CX_BASE 3", .to = "#define CX_BASE 4",
                    .changed = {SCX_HEADER},
                    .affected = SCX_ALL,
                    .reason = {SCX_DBG, SCX_DBG, "interface",
                               SCX_DBG, SCX_DBG},
                    .obligations = ""},
    [SCX_TYPEDEF] = {.name = "typedef", .file = SCX_HEADER,
                     .from = "typedef int cx_count;",
                     .to = "typedef long cx_count;",
                     .changed = {SCX_HEADER},
                     .affected = SCX_ALL,
                     .reason = {SCX_DBG, "interface", SCX_DBG,
                                SCX_DBG, SCX_DBG},
                     .obligations = ""},
    /* A comment that moves no declaration: at -g1 every reader still
     * recompiles, since the header's MD5 in each line table changes. */
    [SCX_TAIL] = {.name = "tail", .file = SCX_HEADER,
                  .from = "int cx_hook(int v);\n#endif",
                  .to = "int cx_hook(int v);\n/* tail */\n#endif",
                  .changed = {SCX_HEADER}, .affected = SCX_ALL,
                  .reason = SCX_ALL_DBG, .obligations = ""},
    /* A-D each reach only a bare header prototype (cx.h defines none of
     * cx_fill/cx_count_of/cx_sum/cx_hook): their moved declaration cannot
     * itself carry code, so they join the compile set with no test
     * obligation (fxc_position_safe, devloop_facts_tu.c). E reaches none of
     * them by name and stays on the debug-position fallback. */
    [SCX_TOP] = {.name = "top", .file = SCX_HEADER,
                 .from = "#define CX_H\n", .to = "#define CX_H\n/* top */\n",
                 .changed = {SCX_HEADER},
                 .affected = SCX_ALL,
                 .reason = {"position", "position", "position", "position",
                            SCX_DBG},
                 .compile_only = {true, true, true, true, false},
                 .obligations = ""},
    [SCX_SIGNATURE] = {.name = "signature", .file = SCX_HEADER,
                       .from = "int cx_sum(int v);",
                       .to = "int cx_sum(long v);", .file2 = SCX_C,
                       .from2 = "int cx_sum(int v) {",
                       .to2 = "int cx_sum(long v) {",
                       .changed = {SCX_HEADER, SCX_C},
                       .affected = SCX_ALL,
                       .reason = {"interface", SCX_DBG, "source-changed",
                                  "interface", SCX_DBG},
                       .obligations = ""},
    [SCX_STATIC] = {.name = "static", .file = SCX_A,
                    .from = "return v * 2; }", .to = "return v * 3; }",
                    .changed = {SCX_A},
                    .affected = {true, false, false, false, false},
                    .reason = {"source-changed", NULL, NULL, NULL, NULL},
                    .obligations = "",
                    /* cx_top_a calls cx_twice: -O1 may inline it */
                    .seeds = {"cx_twice", "cx_top_a"}},
    [SCX_ADDRESS] = {.name = "address", .file = SCX_C,
                     .from = "return v - 1; }", .to = "return v - 2; }",
                     .changed = {SCX_C},
                     .affected = {false, false, true, false, false},
                     .reason = {NULL, NULL, "source-changed", NULL, NULL},
                     .obligations = "address-taken"},
    [SCX_SHADOWED] = {.name = "shadowed", .add_path = SCX_SHADOW,
                      .changed = {SCX_SHADOW},
                      .affected = {true, true, true, true, true},
                      .reason = {"include-resolution-change",
                                 "include-resolution-change",
                                 "include-resolution-change",
                                 "include-resolution-change",
                                 "include-resolution-change"},
                      /* the module's include/cx.h still exists and no
                       * depfile lists it, but the include graph keeps a
                       * quoted include the depfile omits as an edge
                       * (be2e35e22b), so the graph answer is complete: no
                       * truncation, no fallback, no incompleteness. Each
                       * TU's own manifests broaden it on shadowing, and the
                       * graph edge only adds more. */
                      .obligations = "", .incomplete = NULL},
    [SCX_DRIFT] = {.name = "drift", .file = SCX_HEADER,
                   .from = "int cx_hook(int v);\n#endif",
                   .to = "int cx_hook(int v);\n/* drift */\n#endif",
                   .extra_flag = "-DCX_DRIFT=1", .changed = {SCX_HEADER},
                   .affected = {true, true, true, true, true},
                   .reason = {"identity-drift", "identity-drift",
                              "identity-drift", "identity-drift",
                              "identity-drift"},
                   .obligations = ""},
    [SCX_LOCAL] = {.name = "local", .file = SCX_HEADER,
                   .from = "#define CX_PAD 4", .to = "#define CX_PAD 8",
                   .changed = {SCX_HEADER},
                   .affected = SCX_ALL,
                   .reason = {SCX_DBG, SCX_DBG, "interface",
                              SCX_DBG, SCX_DBG},
                   .obligations = "", .seeds = {"cx_sum"}},
    [SCX_BUILD] = {.name = "makefile", .changed = {SCX_MAKEFILE},
                   .affected = {true, true, true, true, true},
                   .reason = {"build-input-changed", "build-input-changed",
                              "build-input-changed", "build-input-changed",
                              "build-input-changed"},
                   .obligations = "build-input-changed",
                   .incomplete = "build-input-changed", .universal = true},
    [SCX_TOOL] = {.name = "tool", .extra_flag = "-DCX_DRIFT=1",
                  .changed = {SCX_MAKEFILE},
                  .affected = {true, true, true, true, true},
                  .reason = {"identity-drift", "identity-drift",
                             "identity-drift", "identity-drift",
                             "identity-drift"},
                  .obligations = "identity-drift",
                  .incomplete = "identity-drift", .universal = true},
    [SCX_BODY] = {.name = "body", .file = SCX_C,
                  .from = "(int)sizeof(s) + CX_SCALE; }",
                  .to = "(int)sizeof(s) + CX_SCALE + 1; }",
                  .changed = {SCX_C},
                  .affected = {false, false, true, false, false},
                  .reason = {NULL, NULL, "source-changed", NULL, NULL},
                  .obligations = "", .seeds = {"cx_sum"}},
    /* F2: __COUNTER__ numbers expansions across the TU. */
    [SCX_P_COUNTER] = {.name = "p_counter", .pre = true,
                       .file = SCX_HEADER, .from = SCX_HOOK_END,
                       .to = "int cx_hook(int v);\n" SCX_TICK "; }\n#endif",
                       .file2 = SCX_B, .from2 = SCX_B_END, .to2 = SCX_CTR_B},
    [SCX_COUNTER] = {.name = "counter", .before = SCX_P_COUNTER,
                     .file = SCX_HEADER, .from = SCX_HOOK_END,
                     .to = "int cx_hook(int v);\n" SCX_TICK
                           " + 0 * __COUNTER__; }\n#endif",
                     .file2 = SCX_B, .from2 = SCX_B_END, .to2 = SCX_CTR_B,
                     .changed = {SCX_HEADER},
                     .affected = {true, true, true, true, true},
                     .reason = SCX_ALL_POS, .obligations = ""},
    /* F5: a static the header defines is internal to its includer. */
    [SCX_P_HSTATIC] = {.name = "p_hstatic", .pre = true,
                       .file = SCX_HEADER, .from = SCX_HOOK_END,
                       .to = "int cx_hook(int v);\nstatic int cx_state;\n#endif",
                       .file2 = SCX_B, .from2 = SCX_B_END,
                       .to2 = SCX_STATE_B("5")},
    [SCX_HSTATIC] = {.name = "hstatic", .before = SCX_P_HSTATIC,
                     .file = SCX_HEADER, .from = SCX_HOOK_END,
                     .to = "int cx_hook(int v);\nstatic int cx_state;\n#endif",
                     .file2 = SCX_B, .from2 = SCX_B_END,
                     .to2 = SCX_STATE_B("6"), .changed = {SCX_B},
                     .affected = {false, true, false, false, false},
                     .reason = {NULL, "source-changed", NULL, NULL, NULL},
                     .obligations = "", .seeds = {"cx_set_b", "cx_get_b"}},
    /* F6: an alias is a second entry no expression names. */
    [SCX_P_ALIAS] = {.name = "p_alias", .pre = true, .file = SCX_C,
                     .from = SCX_C_END, .to = SCX_ALIAS_C("")},
    [SCX_ALIAS] = {.name = "alias", .before = SCX_P_ALIAS, .file = SCX_C,
                   .from = SCX_C_END, .to = SCX_ALIAS_C(" + 1"),
                   .changed = {SCX_C},
                   .affected = {false, false, true, false, false},
                   .reason = {NULL, NULL, "source-changed", NULL, NULL},
                   .obligations = "address-taken"},
    /* F4: a header only a __has_include names, created then deleted. */
    [SCX_P_HASINC] = {.name = "p_hasinc", .pre = true, .file = SCX_HEADER,
                      .from = SCX_HOOK_END, .to = SCX_OPT_H, .file2 = SCX_B,
                      .from2 = SCX_B_END, .to2 = SCX_OPT_B},
    [SCX_HASINC] = {.name = "hasinc", .before = SCX_P_HASINC,
                    .file = SCX_HEADER, .from = SCX_HOOK_END, .to = SCX_OPT_H,
                    .file2 = SCX_B, .from2 = SCX_B_END, .to2 = SCX_OPT_B,
                    .add_path = SCX_OPT, .add_body = "/* cx_opt */\n",
                    .changed = {SCX_OPT},
                    .affected = {true, true, true, true, true},
                    .reason = SCX_ALL_INC, .obligations = ""},
    [SCX_HASDEL] = {.name = "hasdel", .before = SCX_HASINC,
                    .file = SCX_HEADER, .from = SCX_HOOK_END, .to = SCX_OPT_H,
                    .file2 = SCX_B, .from2 = SCX_B_END, .to2 = SCX_OPT_B,
                    .changed = {SCX_OPT},
                    .affected = {true, true, true, true, true},
                    .reason = SCX_ALL_INC,
                    /* cx_opt.h no longer exists, and the include graph
                     * refuses to call a deleted input's reader list complete
                     * (2facc931f3, "Refuse narrow include impact for missing
                     * inputs"): its old readers are unknown, so the plan
                     * falls back to the file-seeded closure */
                    .obligations = "include-graph-truncated",
                    .incomplete = "include-graph-truncated"},
    /* F7: a cleanup handler runs, inlined, where no expression names it. */
    [SCX_P_CLEANUP] = {.name = "p_cleanup", .pre = true, .file = SCX_E,
                       .from = SCX_E_END, .to = SCX_CLEANUP_E("1")},
    [SCX_CLEANUP] = {.name = "cleanup", .before = SCX_P_CLEANUP,
                     .file = SCX_E, .from = SCX_E_END,
                     .to = SCX_CLEANUP_E("7"), .changed = {SCX_E},
                     .affected = {false, false, false, false, true},
                     .reason = {NULL, NULL, NULL, NULL, "source-changed"},
                     .obligations = "", .seeds = {"cx_rel", "cx_work"}},
    /* F8: another TU compiles a changed .c, under another name. */
    [SCX_P_UNITY] = {.name = "p_unity", .pre = true, .file = SCX_E,
                     .from = SCX_E_END, .to = SCX_UNITY_E},
    [SCX_UNITY] = {.name = "unity", .before = SCX_P_UNITY, .file = SCX_C,
                   .from = "(int)sizeof(s) + CX_SCALE; }",
                   .to = "(int)sizeof(s) + CX_SCALE + 1; }",
                   .file2 = SCX_E, .from2 = SCX_E_END, .to2 = SCX_UNITY_E,
                   .changed = {SCX_C},
                   .affected = {false, false, true, false, true},
                   .reason = {NULL, NULL, "source-changed", NULL,
                              "header-unattributed"},
                   .obligations = "",
                   .seeds = {"cx_sum", "cx_e_sum", "cx_use_e"}},
    /* Review: an includer whose only reach is a moved declaration. */
    [SCX_P_UNITY_MOVE] = {.name = "p_unity_move", .pre = true, .file = SCX_C,
                          .from = SCX_HOOK_C, .to = SCX_HOOK_C SCX_TAIL_C(""),
                          .file2 = SCX_E, .from2 = SCX_E_END,
                          .to2 = SCX_UNITY_E},
    [SCX_UNITY_MOVE] = {.name = "unity_move", .before = SCX_P_UNITY_MOVE,
                        .file = SCX_C, .from = SCX_HOOK_C,
                        .to = SCX_HOOK_C SCX_TAIL_C("/* moved */\n"),
                        .file2 = SCX_E, .from2 = SCX_E_END,
                        .to2 = SCX_UNITY_E, .changed = {SCX_C},
                        .affected = {false, false, true, false, true},
                        .reason = {NULL, NULL, "source-changed", NULL,
                                   "position"},
                        .obligations = ""},
    /* Review: a broadened includer seeds every function of the changed .c
     * it compiles, not only those the first chunk names. */
    [SCX_P_UNITY2] = {.name = "p_unity2", .pre = true, .file = SCX_C,
                      .from = SCX_HOOK_C, .to = SCX_HOOK_C SCX_SUM2_C,
                      .file2 = SCX_E, .from2 = SCX_E_END, .to2 = SCX_UNITY2_E},
    [SCX_UNITY2] = {.name = "unity2", .before = SCX_P_UNITY2, .file = SCX_C,
                    .from = SCX_HOOK_C,
                    .to = "CX_SCALE + 1; }\nint cx_hook(int v) { return v - 1; }"
                          "\n/* moves cx_sum2 */\n" SCX_SUM2_C,
                    .file2 = SCX_E, .from2 = SCX_E_END, .to2 = SCX_UNITY2_E,
                    .changed = {SCX_C},
                    .affected = {false, false, true, false, true},
                    .reason = {NULL, NULL, "source-changed", NULL,
                               "header-unattributed"},
                    .obligations = "",
                    .seeds = {"cx_sum2", "cx_e_sum2", "cx_e_sum"}},
    /* Re-review A: an includer broadened by a whole-TU rule still seeds. */
    [SCX_P_CTR_UNITY] = {.name = "p_ctr_unity", .pre = true, .file = SCX_E,
                         .from = SCX_E_END, .to = SCX_CTR_UNITY_E,
                         .file2 = SCX_D, .from2 = SCX_D_END,
                         .to2 = SCX_CALL_D("cx_e_sum")},
    [SCX_CTR_UNITY] = {.name = "ctr_unity", .before = SCX_P_CTR_UNITY,
                       .file = SCX_C, .from = "(int)sizeof(s) + CX_SCALE; }",
                       .to = "(int)sizeof(s) + CX_SCALE + 1; }",
                       .file2 = SCX_E, .from2 = SCX_E_END,
                       .to2 = SCX_CTR_UNITY_E, .file3 = SCX_D,
                       .from3 = SCX_D_END, .to3 = SCX_CALL_D("cx_e_sum"),
                       .changed = {SCX_C},
                       .affected = {false, false, true, false, true},
                       .reason = {NULL, NULL, "source-changed", NULL,
                                  "position-dependent"},
                       .obligations = "", .seeds = {"cx_sum", "cx_e_sum"}},
    /* Re-review B: every changed .c an includer reads seeds it. */
    [SCX_P_UNITY_AB] = {.name = "p_unity_ab", .pre = true, .file = SCX_E,
                        .from = SCX_E_END, .to = SCX_UNITY_AB_E},
    [SCX_UNITY_AB] = {.name = "unity_ab", .before = SCX_P_UNITY_AB,
                      .file = SCX_C, .from = "(int)sizeof(s) + CX_SCALE; }",
                      .to = "(int)sizeof(s) + CX_SCALE + 1; }",
                      .file2 = SCX_A, .from2 = SCX_TOP_A,
                      .to2 = "int cx_top_a(void) { return cx_twice(cx_sum(2)); }",
                      .file3 = SCX_E, .from3 = SCX_E_END,
                      .to3 = SCX_UNITY_AB_E, .changed = {SCX_C, SCX_A},
                      .affected = {true, false, true, false, true},
                      .reason = {"source-changed", NULL, "source-changed", NULL,
                                 "header-unattributed"},
                      .obligations = "",
                      .seeds = {"cx_e_sum", "cx_e_top_a"}},
    /* Re-review E: a function seeded from an includer is address-taken. */
    [SCX_P_UNITY_ADDR] = {.name = "p_unity_addr", .pre = true, .file = SCX_E,
                          .from = SCX_E_END, .to = SCX_UNITY_E,
                          .file2 = SCX_D, .from2 = SCX_D_END,
                          .to2 = SCX_HOOKREF_D},
    [SCX_UNITY_ADDR] = {.name = "unity_addr", .before = SCX_P_UNITY_ADDR,
                        .file = SCX_C,
                        .from = "(int)sizeof(s) + CX_SCALE; }",
                        .to = "(int)sizeof(s) + CX_SCALE + 1; }",
                        .file2 = SCX_E, .from2 = SCX_E_END,
                        .to2 = SCX_UNITY_E, .file3 = SCX_D,
                        .from3 = SCX_D_END, .to3 = SCX_HOOKREF_D,
                        .changed = {SCX_C},
                        .affected = {false, false, true, false, true},
                        .reason = {NULL, NULL, "source-changed", NULL,
                                   "header-unattributed"},
                        .obligations = "address-taken"},
    /* Final review: an includer whose own evidence cannot be trusted names
     * nothing it compiles from the changed .c: the universe is incomplete. */
    [SCX_UNITY_TRUNC] = {.name = "unity_trunc", .before = SCX_P_UNITY,
                         .file = SCX_C, .from = "(int)sizeof(s) + CX_SCALE; }",
                         .to = "(int)sizeof(s) + CX_SCALE + 1; }",
                         .file2 = SCX_E, .from2 = SCX_E_END,
                         .to2 = SCX_UNITY_E, .truncate = SCX_E,
                         .changed = {SCX_C},
                         .affected = {false, false, true, false, true},
                         .reason = {NULL, NULL, "source-changed", NULL,
                                    "truncated"},
                         .obligations = "truncated", .incomplete = "truncated"},
    [SCX_UNITY_NOBEFORE] = {.name = "unity_nobefore", .before = SCX_P_UNITY,
                            .file = SCX_C,
                            .from = "(int)sizeof(s) + CX_SCALE; }",
                            .to = "(int)sizeof(s) + CX_SCALE + 1; }",
                            .file2 = SCX_E, .from2 = SCX_E_END,
                            .to2 = SCX_UNITY_E, .withhold = SCX_E,
                            .withhold_before = true, .changed = {SCX_C},
                            .affected = {false, false, true, false, true},
                            .reason = {NULL, NULL, "source-changed", NULL,
                                       "facts-missing"},
                            .obligations = "facts-missing",
                            .incomplete = "facts-missing"},
    /* ...and one the depfile graph alone says reads the changed .c: a
     * static there has no header a facts-less reader could name. */
    [SCX_UNITY_NOFACTS] = {.name = "unity_nofacts", .before = SCX_P_UNITY_AB,
                           .file = SCX_A,
                           .from = "static int cx_twice(int v) { return v * 2; }",
                           .to = "static int cx_twice(int v) { return v * 3; }",
                           .file2 = SCX_E, .from2 = SCX_E_END,
                           .to2 = SCX_UNITY_AB_E, .withhold = SCX_E,
                           .changed = {SCX_A},
                           .affected = {true, false, false, false, true},
                           .reason = {"source-changed", NULL, NULL, NULL,
                                      "facts-missing"},
                           .obligations = "facts-missing",
                           .incomplete = "facts-missing"},
    /* Final review: the includer gains the #include in the same change; its
     * own include set changed, so the .c path widens. */
    [SCX_UNITY_ADD] = {.name = "unity_add", .file = SCX_C,
                       .from = "(int)sizeof(s) + CX_SCALE; }",
                       .to = "(int)sizeof(s) + CX_SCALE + 1; }",
                       .file2 = SCX_E, .from2 = SCX_E_END, .to2 = SCX_UNITY_E,
                       .changed = {SCX_C, SCX_E},
                       .affected = {false, false, true, false, true},
                       .reason = {NULL, NULL, "source-changed", NULL,
                                  "include-resolution-change"},
                       .obligations = "include-resolution-changed"},
    /* F12: a header static inline's body. Each reader compiles its own
     * copy under the header's id: the caller that inlines it is not the
     * only code that changes (-O0 emits it out of line; so does any level
     * where it is not inlined everywhere). */
    [SCX_P_HINL] = {.name = "p_hinl", .pre = true, .file = SCX_HEADER,
                    .from = SCX_HOOK_END, .to = SCX_INL_H("v * 3"),
                    .file2 = SCX_B, .from2 = SCX_B_END, .to2 = SCX_INL_B},
    [SCX_HINL] = {.name = "hinl", .before = SCX_P_HINL, .file = SCX_HEADER,
                  .from = SCX_HOOK_END, .to = SCX_INL_H("v * 3 + 1"),
                  .file2 = SCX_B, .from2 = SCX_B_END, .to2 = SCX_INL_B,
                  .changed = {SCX_HEADER}, .affected = SCX_ALL,
                  .reason = SCX_ALL_IFACE, .obligations = "",
                  .seeds = {"cx_inl", "cx_inl_b"}},
    [SCX_P_HINL0] = {.name = "p_hinl0", .pre = true, .opt = "-O0",
                     .file = SCX_HEADER, .from = SCX_HOOK_END,
                     .to = SCX_INL_H("v * 3"), .file2 = SCX_B,
                     .from2 = SCX_B_END, .to2 = SCX_INL_B},
    [SCX_HINL0] = {.name = "hinl0", .before = SCX_P_HINL0, .opt = "-O0",
                   .file = SCX_HEADER, .from = SCX_HOOK_END,
                   .to = SCX_INL_H("v * 3 + 1"), .file2 = SCX_B,
                   .from2 = SCX_B_END, .to2 = SCX_INL_B,
                   .changed = {SCX_HEADER}, .affected = SCX_ALL,
                   .reason = SCX_ALL_IFACE, .obligations = "",
                   .seeds = {"cx_inl", "cx_inl_b"}},
    [SCX_P_HINL_ADDR] = {.name = "p_hinl_addr", .pre = true,
                         .file = SCX_HEADER, .from = SCX_HOOK_END,
                         .to = SCX_INL_H("v * 3"), .file2 = SCX_B,
                         .from2 = SCX_B_END, .to2 = SCX_INL_B,
                         .file3 = SCX_D, .from3 = SCX_D_END,
                         .to3 = SCX_INL_D},
    [SCX_HINL_ADDR] = {.name = "hinl_addr", .before = SCX_P_HINL_ADDR,
                       .file = SCX_HEADER, .from = SCX_HOOK_END,
                       .to = SCX_INL_H("v * 3 + 1"), .file2 = SCX_B,
                       .from2 = SCX_B_END, .to2 = SCX_INL_B, .file3 = SCX_D,
                       .from3 = SCX_D_END, .to3 = SCX_INL_D,
                       .changed = {SCX_HEADER}, .affected = SCX_ALL,
                       .reason = SCX_ALL_IFACE,
                       .obligations = "address-taken"},
    /* Replay of 45fb85e113: lines inserted above a header struct moved its
     * DW_AT_decl_line in a reader whose code names nothing else there. At
     * -g the reader joins the compile set with no test obligation; at -g0
     * nothing records the line and the verdict is the old one. */
    [SCX_P_GLINE] = {.name = "p_gline", .pre = true, .debug = "-g",
                     .file = SCX_E, .from = SCX_E_END, .to = SCX_SMALL_E},
    [SCX_GLINE] = {.name = "gline", .before = SCX_P_GLINE, .debug = "-g",
                   .file = SCX_HEADER, .from = "#define CX_H\n",
                   .to = "#define CX_H\n/* top */\n", .file2 = SCX_E,
                   .from2 = SCX_E_END, .to2 = SCX_SMALL_E,
                   .changed = {SCX_HEADER},
                   .affected = SCX_ALL,
                   .reason = {"position", "position", "position", "position",
                              "debug-position"},
                   .compile_only = {true, true, true, true, false},
                   .obligations = ""},
    [SCX_P_GLINE0] = {.name = "p_gline0", .pre = true, .debug = "-g0",
                      .file = SCX_E, .from = SCX_E_END, .to = SCX_SMALL_E},
    [SCX_GLINE0] = {.name = "gline0", .before = SCX_P_GLINE0, .debug = "-g0",
                    .file = SCX_HEADER, .from = "#define CX_H\n",
                    .to = "#define CX_H\n/* top */\n", .file2 = SCX_E,
                    .from2 = SCX_E_END, .to2 = SCX_SMALL_E,
                    .changed = {SCX_HEADER},
                    .affected = {true, true, true, true, false},
                    .reason = {"position", "position", "position", "position",
                               "unaffected"},
                    .compile_only = {true, true, true, true, false},
                    .obligations = ""},
    /* Adversary: a header static inline that expands __LINE__ moves. Every
     * reader defines its own copy (F12, as SCX_HINL) with a span recorded
     * at the header's own path, and that span now overlaps the moved
     * region (fxc_mark_positions, devloop_facts_tu.c): its FUNCTIONS token
     * hash is not what catches this (it hashes token spelling, so a bare
     * "__LINE__" token reads the same before and after a pure move), but
     * fxc_semantic folds every reader in as "code-moved" (FXI_DIRTY_SPAN)
     * before fxc_position ever runs, on the conservative assumption that a
     * moved span's code, not only its debug lines, may differ. It must
     * stay fully affected with a test obligation, never compile-only,
     * however this file's position rule evolves. */
    [SCX_P_LINEINL] = {.name = "p_lineinl", .pre = true, .file = SCX_HEADER,
                       .from = SCX_HOOK_END,
                       .to = "int cx_hook(int v);\nstatic inline int "
                             "cx_lineinl(int v) { return v + __LINE__; }\n"
                             "#endif",
                       .file2 = SCX_B, .from2 = SCX_B_END,
                       .to2 = SCX_B_END "int cx_lineinl_b(void);\n"
                             "int cx_lineinl_b(void) { return cx_lineinl(2); }\n"},
    [SCX_LINEINL] = {.name = "lineinl", .before = SCX_P_LINEINL,
                     .file = SCX_HEADER, .from = SCX_HOOK_END,
                     .to = "int cx_hook(int v);\n/* shift */\nstatic inline "
                           "int cx_lineinl(int v) { return v + __LINE__; }\n"
                           "#endif",
                     .file2 = SCX_B, .from2 = SCX_B_END,
                     .to2 = SCX_B_END "int cx_lineinl_b(void);\n"
                           "int cx_lineinl_b(void) { return cx_lineinl(2); }\n",
                     .changed = {SCX_HEADER},
                     .affected = SCX_ALL,
                     .reason = {"code-moved", "code-moved", "code-moved",
                                "code-moved", "code-moved"},
                     .obligations = "",
                     .seeds = {"cx_lineinl", "cx_lineinl_b"}},
};

const char *scx_flag(enum scx_variant v, size_t i)
{
    const struct scx_edit *e = &k_scx_edits[v];
    if (e->opt != NULL && strcmp(k_scx_flags[i], "-O1") == 0)
        return e->opt;
    if (e->debug != NULL && strcmp(k_scx_flags[i], "-g1") == 0)
        return e->debug;
    return k_scx_flags[i];
}

static char *scx_replace(const char *body, const char *from, const char *to,
                         size_t *len)
{
    const char *at = strstr(body, from);
    size_t head, n;
    char *out;
    if (at == NULL || strstr(at + 1, from) != NULL)
        return NULL; /* the edit must name exactly one place */
    head = (size_t)(at - body);
    n = strlen(body) - strlen(from) + strlen(to);
    out = zcl_malloc(n + 1, "scx.text");
    if (out == NULL)
        return NULL;
    memcpy(out, body, head);
    memcpy(out + head, to, strlen(to));
    memcpy(out + head + strlen(to), at + strlen(from),
           strlen(at + strlen(from)) + 1);
    *len = n;
    return out;
}

static const char *scx_base_body(const char *path)
{
    if (strcmp(path, SCX_SHADOW) == 0)
        return k_scx_header;
    for (size_t k = 0; k < SCX_FILE_COUNT; k++)
        if (strcmp(k_scx_paths[k], path) == 0)
            return k_scx_bodies[k];
    return NULL;
}

char *scx_text(enum scx_variant v, const char *path, size_t *len)
{
    const struct scx_edit *e = &k_scx_edits[v];
    const char *body = scx_base_body(path);
    if (e->add_path != NULL && e->add_body != NULL &&
        strcmp(path, e->add_path) == 0) {
        *len = strlen(e->add_body);
        return zcl_strdup(e->add_body, "scx.text");
    }
    if (body == NULL ||
        (strcmp(path, SCX_SHADOW) == 0 &&
         (e->add_path == NULL || strcmp(e->add_path, path) != 0)))
        return NULL;
    if (e->file != NULL && strcmp(e->file, path) == 0)
        return scx_replace(body, e->from, e->to, len);
    if (e->file2 != NULL && strcmp(e->file2, path) == 0)
        return scx_replace(body, e->from2, e->to2, len);
    if (e->file3 != NULL && strcmp(e->file3, path) == 0)
        return scx_replace(body, e->from3, e->to3, len);
    *len = strlen(body);
    return zcl_strdup(body, "scx.text");
}

static bool scx_mkdirs(char *full)
{
    for (char *p = full + 1; *p; p++) {
        if (*p != '/')
            continue;
        *p = '\0';
        if (!scx_mkdir(full)) {
            *p = '/';
            return false;
        }
        *p = '/';
    }
    return true;
}

static bool scx_put(const char *root, const char *rel, const char *body,
                    size_t n)
{
    char full[4096];
    FILE *fp;
    bool ok;
    if (snprintf(full, sizeof(full), "%s/%s", root, rel) >= (int)sizeof(full))
        return false;
    fp = scx_mkdirs(full) ? fopen(full, "wb") : NULL;
    ok = fp != NULL && fwrite(body, 1, n, fp) == n;
    if (fp != NULL && fclose(fp) != 0)
        ok = false;
    return ok;
}

static bool scx_write_one(const char *root, enum scx_variant v,
                          const char *path)
{
    size_t n = 0;
    char *body = scx_text(v, path, &n);
    bool ok = body != NULL && scx_put(root, path, body, n);
    free(body);
    return ok;
}

bool scx_write_tree(const char *root, enum scx_variant v)
{
    static const char *const extras[] = {SCX_SHADOW, SCX_OPT};
    const char *add = k_scx_edits[v].add_path;
    char full[4096];
    for (size_t k = 0; k < SCX_FILE_COUNT; k++)
        if (!scx_write_one(root, v, k_scx_paths[k]))
            return false;
    /* A variant inherits no file another one added. */
    for (size_t k = 0; k < sizeof(extras) / sizeof(extras[0]); k++) {
        if (add != NULL && strcmp(add, extras[k]) == 0) {
            if (!scx_write_one(root, v, add))
                return false;
            continue;
        }
        (void)snprintf(full, sizeof(full), "%s/%s", root, extras[k]);
        if (unlink(full) != 0 && access(full, F_OK) == 0)
            return false;
    }
    return true;
}

bool scx_write_depfiles(const char *root, enum scx_variant v)
{
    const char *add = k_scx_edits[v].add_path;
    const char *hdr =
        add != NULL && strcmp(add, SCX_SHADOW) == 0 ? SCX_SHADOW : SCX_HEADER;
    for (size_t k = 0; k < SCX_TU_COUNT; k++) {
        char rel[256], body[512];
        const char *base = strrchr(k_scx_tus[k], '/') + 1;
        size_t len;
        char *text = scx_text(v, k_scx_tus[k], &len);
        /* a TU that includes cx_c.c or cx_a.c reads it too */
        bool unity = text != NULL && strstr(text, "#include \"cx_c.c\"") != NULL;
        bool unity_a = text != NULL && strstr(text, "#include \"cx_a.c\"") != NULL;
        int n = snprintf(body, sizeof(body), "build/scx/%.*s.o: %s \\\n %s%s%s\n",
                         (int)(strlen(base) - 2), base, k_scx_tus[k], hdr,
                         unity ? " \\\n " SCX_C : "",
                         unity_a ? " \\\n " SCX_A : "");
        free(text);
        (void)snprintf(rel, sizeof(rel), "build/scx/%.*s.d",
                       (int)(strlen(base) - 2), base);
        if (n <= 0 || (size_t)n >= sizeof(body) ||
            !scx_put(root, rel, body, (size_t)n))
            return false;
    }
    return true;
}

bool scx_mkdir(const char *path)
{
    return mkdir(path, 0755) == 0 || access(path, F_OK) == 0;
}
