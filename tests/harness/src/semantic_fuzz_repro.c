/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: The semantic-facts fuzzer's fixed reproducers: each minimized project pair a differential run found (F<n>) or that pins a shape the consumer must keep planning safely (pass_*, and D<n> for edits that change only data a function addresses or an object defines). */
#include "test/semantic_fuzz.h"

#include "base/log_macros.h"

#include <string.h>

/* The after text of a file the edit leaves alone. */
static const char k_sfz_same[] = "";
#define SFZ_SAME k_sfz_same

static const struct sfz_file k_f1_flag[] = {
    {"inc2/h.h",
         "#ifndef H_H\n"
         "#define H_H\n"
         "int t0_mode(void);\n"
         "#endif\n",
         SFZ_SAME},
    {"Makefile",
         "# p\n"
         "CFLAGS_EXTRA = \n",
         "# p\n"
         "CFLAGS_EXTRA = -DPROJ_MODE=1\n"},
    {"src/t0.c",
         "#include \"h.h\"\n"
         "int t0_mode(void)\n"
         "{\n"
         "#ifdef PROJ_MODE\n"
         "    return 1;\n"
         "#else\n"
         "    return 2;\n"
         "#endif\n"
         "}\n",
         SFZ_SAME},
};

static const struct sfz_file k_f2_counter_c[] = {
    {"inc2/h.h",
         "#ifndef H_H\n"
         "#define H_H\n"
         "int t0_a(int x);\n"
         "int t0_b(void);\n"
         "#endif\n",
         SFZ_SAME},
    {"Makefile",
         "# p\n"
         "CFLAGS_EXTRA = \n",
         SFZ_SAME},
    {"src/t0.c",
         "#include \"h.h\"\n"
         "int t0_a(int x)\n"
         "{\n"
         "    return x + 1;\n"
         "}\n"
         "int t0_b(void)\n"
         "{\n"
         "    return __COUNTER__;\n"
         "}\n",
         "#include \"h.h\"\n"
         "int t0_a(int x)\n"
         "{\n"
         "    return x + 1 + 0 * __COUNTER__;\n"
         "}\n"
         "int t0_b(void)\n"
         "{\n"
         "    return __COUNTER__;\n"
         "}\n"},
};

static const struct sfz_file k_f2_counter_header[] = {
    {"inc2/h.h",
         "#ifndef H_H\n"
         "#define H_H\n"
         "static inline int h_inl(int x)\n"
         "{\n"
         "    return x + 1;\n"
         "}\n"
         "#endif\n",
         "#ifndef H_H\n"
         "#define H_H\n"
         "static inline int h_inl(int x)\n"
         "{\n"
         "    return x + 1 + 0 * __COUNTER__;\n"
         "}\n"
         "#endif\n"},
    {"Makefile",
         "# p\n"
         "CFLAGS_EXTRA = \n",
         SFZ_SAME},
    {"src/t0.c",
         "#include \"h.h\"\n"
         "int t0_inl(int x)\n"
         "{\n"
         "    return h_inl(x);\n"
         "}\n"
         "int t0_ctr(void)\n"
         "{\n"
         "    return __COUNTER__;\n"
         "}\n",
         SFZ_SAME},
    {"src/t1.c",
         "#include \"h.h\"\n"
         "int t1_ctr(void)\n"
         "{\n"
         "    return __COUNTER__;\n"
         "}\n",
         SFZ_SAME},
};

static const struct sfz_file k_f3_line_c[] = {
    {"inc2/h.h",
         "#ifndef H_H\n"
         "#define H_H\n"
         "int t0_a(int x);\n"
         "int t0_b(void);\n"
         "#endif\n",
         SFZ_SAME},
    {"Makefile",
         "# p\n"
         "CFLAGS_EXTRA = \n",
         SFZ_SAME},
    {"src/t0.c",
         "#include \"h.h\"\n"
         "int t0_a(int x)\n"
         "{\n"
         "    return x + 1;\n"
         "}\n"
         "int t0_b(void)\n"
         "{\n"
         "    return __LINE__;\n"
         "}\n",
         "#include \"h.h\"\n"
         "int t0_a(int x)\n"
         "{\n"
         "\n"
         "    return x + 1;\n"
         "}\n"
         "int t0_b(void)\n"
         "{\n"
         "    return __LINE__;\n"
         "}\n"},
};

static const struct sfz_file k_f4_hasinc_create_gccdeps[] = {
    {"inc1/opt.h",
         NULL,
         "/* optional feature */\n"},
    {"inc2/h.h",
         "#ifndef H_H\n"
         "#define H_H\n"
         "#if __has_include(\"opt.h\")\n"
         "#define H_V 1\n"
         "#else\n"
         "#define H_V 2\n"
         "#endif\n"
         "#endif\n",
         SFZ_SAME},
    {"Makefile",
         "# p\n"
         "CFLAGS_EXTRA = \n",
         SFZ_SAME},
    {"src/t0.c",
         "#include \"h.h\"\n"
         "int t0_f(void)\n"
         "{\n"
         "    return H_V + 10;\n"
         "}\n",
         SFZ_SAME},
    {"src/t1.c",
         "int t1_g(void)\n"
         "{\n"
         "    return 7;\n"
         "}\n",
         SFZ_SAME},
};

static const struct sfz_file k_f4_hasinc_delete[] = {
    {"inc1/opt.h",
         "/* optional feature */\n",
         NULL},
    {"inc2/h.h",
         "#ifndef H_H\n"
         "#define H_H\n"
         "#if __has_include(\"opt.h\")\n"
         "#define H_V 1\n"
         "#else\n"
         "#define H_V 2\n"
         "#endif\n"
         "#endif\n",
         SFZ_SAME},
    {"Makefile",
         "# p\n"
         "CFLAGS_EXTRA = \n",
         SFZ_SAME},
    {"src/t0.c",
         "#include \"h.h\"\n"
         "int t0_f(void)\n"
         "{\n"
         "    return H_V + 10;\n"
         "}\n",
         SFZ_SAME},
    {"src/t1.c",
         "int t1_g(void)\n"
         "{\n"
         "    return 7;\n"
         "}\n",
         SFZ_SAME},
};

static const struct sfz_file k_f5_header_static[] = {
    {"inc2/h.h",
         "#ifndef H_H\n"
         "#define H_H\n"
         "static int h_state;\n"
         "#endif\n",
         SFZ_SAME},
    {"Makefile",
         "# p\n"
         "CFLAGS_EXTRA = \n",
         SFZ_SAME},
    {"src/t0.c",
         "#include \"h.h\"\n"
         "void t0_set(void)\n"
         "{\n"
         "    h_state = 5;\n"
         "}\n"
         "int t0_get(void)\n"
         "{\n"
         "    return h_state;\n"
         "}\n",
         "#include \"h.h\"\n"
         "void t0_set(void)\n"
         "{\n"
         "    h_state = 6;\n"
         "}\n"
         "int t0_get(void)\n"
         "{\n"
         "    return h_state;\n"
         "}\n"},
};

static const struct sfz_file k_f6_alias[] = {
    {"inc2/h.h",
         "#ifndef H_H\n"
         "#define H_H\n"
         "int h_api(int x);\n"
         "int h_api_compat(int x);\n"
         "#endif\n",
         SFZ_SAME},
    {"Makefile",
         "# p\n"
         "CFLAGS_EXTRA = \n",
         SFZ_SAME},
    {"src/t0.c",
         "#include \"h.h\"\n"
         "int h_api(int x)\n"
         "{\n"
         "    return x * 3 + 1;\n"
         "}\n"
         "int h_api_compat(int x) __attribute__((alias(\"h_api\")));\n",
         "#include \"h.h\"\n"
         "int h_api(int x)\n"
         "{\n"
         "    return x * 3 + 2;\n"
         "}\n"
         "int h_api_compat(int x) __attribute__((alias(\"h_api\")));\n"},
    {"src/t1.c",
         "#include \"h.h\"\n"
         "int t1_use(int x)\n"
         "{\n"
         "    return h_api_compat(x) + 2;\n"
         "}\n",
         SFZ_SAME},
};

static const struct sfz_file k_f7_cleanup_handler[] = {
    {"inc2/h.h",
         "#ifndef H_H\n"
         "#define H_H\n"
         "int t0_work(int x);\n"
         "#endif\n",
         SFZ_SAME},
    {"Makefile",
         "# p\n"
         "CFLAGS_EXTRA = \n",
         SFZ_SAME},
    {"src/t0.c",
         "#include \"h.h\"\n"
         "int t0_sink;\n"
         "static void t0_release(int *p)\n"
         "{\n"
         "    t0_sink = *p + 1;\n"
         "}\n"
         "int t0_work(int x)\n"
         "{\n"
         "    __attribute__((cleanup(t0_release))) int v = x * 2;\n"
         "    return v + 3;\n"
         "}\n",
         "#include \"h.h\"\n"
         "int t0_sink;\n"
         "static void t0_release(int *p)\n"
         "{\n"
         "    t0_sink = *p + 7;\n"
         "}\n"
         "int t0_work(int x)\n"
         "{\n"
         "    __attribute__((cleanup(t0_release))) int v = x * 2;\n"
         "    return v + 3;\n"
         "}\n"},
};

/* F7 behind a same-name seed: t0's external work() inlines a cleanup()
 * handler whose body changed, and t1's own static work() changed too. A
 * seed matched by bare name would let t1's seed cover t0's work. */
static const struct sfz_file k_f7_cleanup_same_name[] = {
    {"inc2/h.h",
         "#ifndef H_H\n"
         "#define H_H\n"
         "int t1_run(int x);\n"
         "#endif\n",
         SFZ_SAME},
    {"Makefile",
         "# p\n"
         "CFLAGS_EXTRA = \n",
         SFZ_SAME},
    {"src/t0.c",
         "#include \"h.h\"\n"
         "int t0_sink;\n"
         "static void t0_release(int *p)\n"
         "{\n"
         "    t0_sink = *p + 1;\n"
         "}\n"
         "int work(int x)\n"
         "{\n"
         "    __attribute__((cleanup(t0_release))) int v = x * 2;\n"
         "    return v + 3;\n"
         "}\n",
         "#include \"h.h\"\n"
         "int t0_sink;\n"
         "static void t0_release(int *p)\n"
         "{\n"
         "    t0_sink = *p + 7;\n"
         "}\n"
         "int work(int x)\n"
         "{\n"
         "    __attribute__((cleanup(t0_release))) int v = x * 2;\n"
         "    return v + 3;\n"
         "}\n"},
    {"src/t1.c",
         "#include \"h.h\"\n"
         "static int work(int x)\n"
         "{\n"
         "    return x * 5 + 1;\n"
         "}\n"
         "int t1_run(int x)\n"
         "{\n"
         "    return work(x) + 2;\n"
         "}\n",
         "#include \"h.h\"\n"
         "static int work(int x)\n"
         "{\n"
         "    return x * 5 + 4;\n"
         "}\n"
         "int t1_run(int x)\n"
         "{\n"
         "    return work(x) + 2;\n"
         "}\n"},
};

static const struct sfz_file k_f8_c_includes_c[] = {
    {"Makefile",
         "# p\n"
         "CFLAGS_EXTRA = \n",
         SFZ_SAME},
    {"src/b.c",
         "static int b_k(int x)\n"
         "{\n"
         "    return x * 3 + 1;\n"
         "}\n"
         "int b_api(int x)\n"
         "{\n"
         "    return b_k(x);\n"
         "}\n",
         "static int b_k(int x)\n"
         "{\n"
         "    return x * 3 + 5;\n"
         "}\n"
         "int b_api(int x)\n"
         "{\n"
         "    return b_k(x);\n"
         "}\n"},
    {"src/test_b.c",
         "#include \"b.c\"\n"
         "int test_b_k(void)\n"
         "{\n"
         "    return b_k(4) == 13;\n"
         "}\n",
         SFZ_SAME},
};

static const struct sfz_file k_f8_c_includes_c_renamed[] = {
    {"Makefile",
         "# p\n"
         "CFLAGS_EXTRA = \n",
         SFZ_SAME},
    {"src/a.c",
         "#define b_api a_b_api\n"
         "#include \"b.c\"\n"
         "#undef b_api\n"
         "int a_use(int x)\n"
         "{\n"
         "    return b_k(x) + 2;\n"
         "}\n",
         SFZ_SAME},
    {"src/b.c",
         "static int b_k(int x)\n"
         "{\n"
         "    return x * 3 + 1;\n"
         "}\n"
         "int b_api(int x)\n"
         "{\n"
         "    return b_k(x);\n"
         "}\n",
         "static int b_k(int x)\n"
         "{\n"
         "    return x * 3 + 5;\n"
         "}\n"
         "int b_api(int x)\n"
         "{\n"
         "    return b_k(x);\n"
         "}\n"},
};

static const struct sfz_file k_pass_hd[] = {
    {"inc2/h.h",
         "#ifndef H_H\n"
         "#define H_H\n"
         "#define H_A 1\n"
         "#if H_A > 2\n"
         "#define H_D 100\n"
         "#else\n"
         "#define H_D 200\n"
         "#endif\n"
         "#endif\n",
         "#ifndef H_H\n"
         "#define H_H\n"
         "#define H_A 3\n"
         "#if H_A > 2\n"
         "#define H_D 100\n"
         "#else\n"
         "#define H_D 200\n"
         "#endif\n"
         "#endif\n"},
    {"Makefile",
         "# p\n"
         "CFLAGS_EXTRA = \n",
         SFZ_SAME},
    {"src/t0.c",
         "#include \"h.h\"\n"
         "int t0_d(void)\n"
         "{\n"
         "    return H_D;\n"
         "}\n",
         SFZ_SAME},
};

static const struct sfz_file k_pass_hdrproto[] = {
    {"inc2/h.h",
         "#ifndef H_H\n"
         "#define H_H\n"
         "static int t0_k(int a);\n"
         "#endif\n",
         SFZ_SAME},
    {"Makefile",
         "# p\n"
         "CFLAGS_EXTRA = \n",
         SFZ_SAME},
    {"src/t0.c",
         "#include \"h.h\"\n"
         "static int t0_k(int a)\n"
         "{\n"
         "    return a * 3 + 7;\n"
         "}\n"
         "int t0_e(int x)\n"
         "{\n"
         "    return t0_k(x) + 1;\n"
         "}\n",
         "#include \"h.h\"\n"
         "static int t0_k(int a)\n"
         "{\n"
         "    return a * 3 + 8;\n"
         "}\n"
         "int t0_e(int x)\n"
         "{\n"
         "    return t0_k(x) + 1;\n"
         "}\n"},
};

static const struct sfz_file k_pass_undef[] = {
    {"inc2/h.h",
         "#ifndef H_H\n"
         "#define H_H\n"
         "#define H_TMP 5\n"
         "static inline int h_tmp(void)\n"
         "{\n"
         "    return H_TMP;\n"
         "}\n"
         "#undef H_TMP\n"
         "#endif\n",
         "#ifndef H_H\n"
         "#define H_H\n"
         "#define H_TMP 6\n"
         "static inline int h_tmp(void)\n"
         "{\n"
         "    return H_TMP;\n"
         "}\n"
         "#undef H_TMP\n"
         "#endif\n"},
    {"Makefile",
         "# p\n"
         "CFLAGS_EXTRA = \n",
         SFZ_SAME},
    {"src/t0.c",
         "#include \"h.h\"\n"
         "int t0_f(void)\n"
         "{\n"
         "    return h_tmp() + 1;\n"
         "}\n",
         SFZ_SAME},
    {"src/t1.c",
         "#include \"h.h\"\n"
         "int t1_g(void)\n"
         "{\n"
         "    return 7;\n"
         "}\n",
         SFZ_SAME},
};

static const struct sfz_file k_pass_undefbody[] = {
    {"Makefile",
         "# p\n"
         "CFLAGS_EXTRA = \n",
         SFZ_SAME},
    {"src/t0.c",
         "#define T0_Q 3\n"
         "int t0_f(void)\n"
         "{\n"
         "    int r = T0_Q;\n"
         "    return r;\n"
         "}\n"
         "int t0_g(void)\n"
         "{\n"
         "#ifdef T0_Q\n"
         "    return 1;\n"
         "#else\n"
         "    return 2;\n"
         "#endif\n"
         "}\n",
         "#define T0_Q 3\n"
         "int t0_f(void)\n"
         "{\n"
         "    int r = T0_Q;\n"
         "#undef T0_Q\n"
         "    return r;\n"
         "}\n"
         "int t0_g(void)\n"
         "{\n"
         "#ifdef T0_Q\n"
         "    return 1;\n"
         "#else\n"
         "    return 2;\n"
         "#endif\n"
         "}\n"},
};

/* The data shapes: each edit changes only data a function addresses
 * through a relocation, or data the object defines. */

static const struct sfz_file k_d1_string_literal[] = {
    {"inc2/h.h",
         "#ifndef H_H\n"
         "#define H_H\n"
         "const char *t0_name(void);\n"
         "#endif\n",
         SFZ_SAME},
    {"Makefile",
         "# p\n"
         "CFLAGS_EXTRA = \n",
         SFZ_SAME},
    {"src/t0.c",
         "#include \"h.h\"\n"
         "const char *t0_name(void)\n"
         "{\n"
         "    return \"alpha\";\n"
         "}\n"
         "const char *t0_tail(void)\n"
         "{\n"
         "    return \"omega\";\n"
         "}\n",
         "#include \"h.h\"\n"
         "const char *t0_name(void)\n"
         "{\n"
         "    return \"alphabet\";\n"
         "}\n"
         "const char *t0_tail(void)\n"
         "{\n"
         "    return \"omega\";\n"
         "}\n"},
};

static const struct sfz_file k_d2_static_const_table[] = {
    {"inc2/h.h",
         "#ifndef H_H\n"
         "#define H_H\n"
         "int t0_pick(int i);\n"
         "#endif\n",
         SFZ_SAME},
    {"Makefile",
         "# p\n"
         "CFLAGS_EXTRA = \n",
         SFZ_SAME},
    {"src/t0.c",
         "#include \"h.h\"\n"
         "static const int t0_tab[4] = {3, 5, 7, 9};\n"
         "int t0_pick(int i)\n"
         "{\n"
         "    return t0_tab[i & 3];\n"
         "}\n",
         "#include \"h.h\"\n"
         "static const int t0_tab[4] = {3, 5, 8, 9};\n"
         "int t0_pick(int i)\n"
         "{\n"
         "    return t0_tab[i & 3];\n"
         "}\n"},
};

static const struct sfz_file k_d3_header_const_table[] = {
    {"inc2/h.h",
         "#ifndef H_H\n"
         "#define H_H\n"
         "static const int h_ctab[3] = {10, 20, 30};\n"
         "int t0_get(int i);\n"
         "#endif\n",
         "#ifndef H_H\n"
         "#define H_H\n"
         "static const int h_ctab[3] = {10, 21, 30};\n"
         "int t0_get(int i);\n"
         "#endif\n"},
    {"Makefile",
         "# p\n"
         "CFLAGS_EXTRA = \n",
         SFZ_SAME},
    {"src/t0.c",
         "#include \"h.h\"\n"
         "int t0_get(int i)\n"
         "{\n"
         "    return h_ctab[i % 3];\n"
         "}\n",
         SFZ_SAME},
    {"src/t1.c",
         "#include \"h.h\"\n"
         "int t1_get(int i)\n"
         "{\n"
         "    return t0_get(i) + h_ctab[i & 1];\n"
         "}\n",
         SFZ_SAME},
};

static const struct sfz_file k_d4_header_index_macro[] = {
    {"inc2/h.h",
         "#ifndef H_H\n"
         "#define H_H\n"
         "#define H_IDX 1\n"
         "extern int h_arr[4];\n"
         "#endif\n",
         "#ifndef H_H\n"
         "#define H_H\n"
         "#define H_IDX 2\n"
         "extern int h_arr[4];\n"
         "#endif\n"},
    {"Makefile",
         "# p\n"
         "CFLAGS_EXTRA = \n",
         SFZ_SAME},
    {"src/t0.c",
         "#include \"h.h\"\n"
         "int h_arr[4] = {2, 4, 6, 8};\n",
         SFZ_SAME},
    {"src/t1.c",
         "#include \"h.h\"\n"
         "int t1_at(void)\n"
         "{\n"
         "    return h_arr[H_IDX];\n"
         "}\n",
         SFZ_SAME},
};

static const struct sfz_file k_d5_extern_const_init[] = {
    {"inc2/h.h",
         "#ifndef H_H\n"
         "#define H_H\n"
         "#define H_LIMIT 40\n"
         "extern const int h_limit;\n"
         "#endif\n",
         "#ifndef H_H\n"
         "#define H_H\n"
         "#define H_LIMIT 41\n"
         "extern const int h_limit;\n"
         "#endif\n"},
    {"Makefile",
         "# p\n"
         "CFLAGS_EXTRA = \n",
         SFZ_SAME},
    {"src/t0.c",
         "#include \"h.h\"\n"
         "const int h_limit = H_LIMIT;\n",
         SFZ_SAME},
    {"src/t1.c",
         "#include \"h.h\"\n"
         "int t1_lim(void)\n"
         "{\n"
         "    return h_limit + 1;\n"
         "}\n",
         SFZ_SAME},
};

static const struct sfz_file k_d6_function_static_table[] = {
    {"inc2/h.h",
         "#ifndef H_H\n"
         "#define H_H\n"
         "int t0_pick(int i);\n"
         "#endif\n",
         SFZ_SAME},
    {"Makefile",
         "# p\n"
         "CFLAGS_EXTRA = \n",
         SFZ_SAME},
    {"src/t0.c",
         "#include \"h.h\"\n"
         "int t0_pick(int i)\n"
         "{\n"
         "    static const int tab[4] = {3, 5, 7, 9};\n"
         "    return tab[i & 3];\n"
         "}\n",
         "#include \"h.h\"\n"
         "int t0_pick(int i)\n"
         "{\n"
         "    static const int tab[4] = {3, 5, 8, 9};\n"
         "    return tab[i & 3];\n"
         "}\n"},
};

/* ---- the path kinds: a file only a probe names, and links ------------------ */

/* An unrelated TU, so the universe has a TU the edit leaves alone. */
#define SFZ_T1_ALONE                                                         \
    {"src/t1.c",                                                             \
     "int t1_a(int x)\n"                                                     \
     "{\n"                                                                   \
     "    return x + 1;\n"                                                   \
     "}\n",                                                                  \
     SFZ_SAME}

#define SFZ_HAS_EMBED_T0(path)                                               \
    {"src/t0.c",                                                             \
     "#if __has_embed(\"../" path "\")\n"                                    \
     "#define T0_BANNER 1\n"                                                 \
     "#else\n"                                                               \
     "#define T0_BANNER 0\n"                                                 \
     "#endif\n"                                                              \
     "int t0_banner(int x)\n"                                                \
     "{\n"                                                                   \
     "    return x + T0_BANNER * 7;\n"                                       \
     "}\n",                                                                  \
     SFZ_SAME}

static const struct sfz_file k_f13_has_embed_deleted[] = {
    {"Makefile", "# p\nCFLAGS_EXTRA = \n", SFZ_SAME},
    {"docs/banner.txt", "Z23\n", NULL},
    SFZ_HAS_EMBED_T0("docs/banner.txt"),
    SFZ_T1_ALONE,
};

static const struct sfz_file k_has_embed_created[] = {
    {"Makefile", "# p\nCFLAGS_EXTRA = \n", SFZ_SAME},
    {"docs/banner.txt", NULL, "Z23\n"},
    SFZ_HAS_EMBED_T0("docs/banner.txt"),
    SFZ_T1_ALONE,
};

static const struct sfz_file k_has_embed_data_deleted[] = {
    {"Makefile", "# p\nCFLAGS_EXTRA = \n", SFZ_SAME},
    {"data/banner.bin", "Z23\n", NULL},
    SFZ_HAS_EMBED_T0("data/banner.bin"),
    SFZ_T1_ALONE,
};

#define SFZ_CFG_T0                                                           \
    {"src/t0.c",                                                             \
     "#include \"cfg.h\"\n"                                                  \
     "int t0_local(int x)\n"                                                 \
     "{\n"                                                                   \
     "    return x + CFG_HAVE_LOCAL * 5;\n"                                  \
     "}\n",                                                                  \
     SFZ_SAME}

#define SFZ_CFG_H(probe)                                                     \
    {"inc1/cfg.h",                                                           \
     "#ifndef CFG_H\n"                                                       \
     "#define CFG_H\n"                                                       \
     probe                                                                   \
     "#define CFG_HAVE_LOCAL 1\n"                                            \
     "#else\n"                                                               \
     "#define CFG_HAVE_LOCAL 0\n"                                            \
     "#endif\n"                                                              \
     "#endif\n",                                                             \
     SFZ_SAME}
#define SFZ_CFG_MACRO                                                        \
    SFZ_CFG_H("#define CFG_LOCAL \"cfg_local.h\"\n"                          \
              "#if __has_include(CFG_LOCAL)\n")
#define SFZ_CFG_NEXT SFZ_CFG_H("#if __has_include_next(<cfg_local.h>)\n")

static const struct sfz_file k_f14_has_include_macro[] = {
    {"Makefile", "# p\nCFLAGS_EXTRA = \n", SFZ_SAME},
    SFZ_CFG_MACRO,
    {"inc2/cfg_local.h", "/* site overrides */\n", NULL},
    SFZ_CFG_T0,
    SFZ_T1_ALONE,
};

static const struct sfz_file k_f14_has_include_next[] = {
    {"Makefile", "# p\nCFLAGS_EXTRA = \n", SFZ_SAME},
    SFZ_CFG_NEXT,
    {"inc2/cfg_local.h", "/* site overrides */\n", NULL},
    SFZ_CFG_T0,
    SFZ_T1_ALONE,
};

/* F15: the same probes when the file is created, with gcc's depfiles */
static const struct sfz_file k_f15_has_include_macro[] = {
    {"Makefile", "# p\nCFLAGS_EXTRA = \n", SFZ_SAME},
    SFZ_CFG_MACRO,
    {"inc2/cfg_local.h", NULL, "/* site overrides */\n"},
    SFZ_CFG_T0,
    SFZ_T1_ALONE,
};

static const struct sfz_file k_f15_has_include_next[] = {
    {"Makefile", "# p\nCFLAGS_EXTRA = \n", SFZ_SAME},
    SFZ_CFG_NEXT,
    {"inc2/cfg_local.h", NULL, "/* site overrides */\n"},
    SFZ_CFG_T0,
    SFZ_T1_ALONE,
};

#define SFZ_LINKED_HDR(v)                                                    \
    "#ifndef H_H\n"                                                          \
    "#define H_H\n"                                                          \
    "#define H_V " v "\n"                                                    \
    "static inline int h_v(int x)\n"                                         \
    "{\n"                                                                    \
    "    return x * H_V;\n"                                                  \
    "}\n"                                                                    \
    "#endif\n"

#define SFZ_LINK_T0                                                          \
    {"src/t0.c",                                                             \
     "#include \"h.h\"\n"                                                    \
     "int t0_a(int x)\n"                                                     \
     "{\n"                                                                   \
     "    return h_v(x) + 1;\n"                                              \
     "}\n",                                                                  \
     SFZ_SAME}

/* inc1/h.h names hdr/b.h instead of hdr/a.h; neither file changes */
static const struct sfz_file k_link_retarget[] = {
    {"Makefile", "# p\nCFLAGS_EXTRA = \n", SFZ_SAME},
    {"hdr/a.h", SFZ_LINKED_HDR("3"), SFZ_SAME},
    {"hdr/b.h", SFZ_LINKED_HDR("4"), SFZ_SAME},
    {"inc1/h.h", SFZ_LINK("../hdr/a.h"), SFZ_LINK("../hdr/b.h")},
    SFZ_LINK_T0,
    SFZ_T1_ALONE,
};

/* hdr/a.h changes; t0 reads it only through the link inc1/h.h */
static const struct sfz_file k_link_target_edit[] = {
    {"Makefile", "# p\nCFLAGS_EXTRA = \n", SFZ_SAME},
    {"hdr/a.h", SFZ_LINKED_HDR("3"), SFZ_LINKED_HDR("5")},
    {"inc1/h.h", SFZ_LINK("../hdr/a.h"), SFZ_SAME},
    SFZ_LINK_T0,
    SFZ_T1_ALONE,
};
#define SFZ_FILES(a) a, sizeof(a) / sizeof((a)[0])

/* F13, F14: a file that only a probe names is deleted, and the TU that
 * probed it compiles the other branch; F15: the file such a probe names is
 * created, and the depfiles are gcc's, as the dev compile's are (gcc's
 * depfile omits __has_include probes). All five were known-RED until the
 * consumer read the lookups that make no negative claim: the sensor
 * records a probe it cannot replay (__has_embed, #embed, a macro operand
 * it cannot expand, __has_include_next from a file whose search start it
 * does not know) with no claim, and nothing then named the path. Now a TU
 * with such a lookup is a member, affected whole (lookup-unbound), when the
 * change creates or deletes any path, or changes any path for an embed
 * (fxc_unbound_path, tools/dev/devloop_facts_tu.c); a macro operand and
 * __has_include_next the sensor can resolve are replayed like a literal
 * __has_include (revision 4). A deleted path's plan still falls back on
 * the include graph, which refuses a path the tree no longer holds; the
 * facts universe, which the case judges, holds t0 by these rules alone.
 * Creating the __has_embed file passes too (pass_has_embed_created), and a
 * data/ path is a build input (pass_has_embed_build_input). */

/* #embed of a file the edit creates, behind __has_embed (gcc 14 has
 * neither, so the depfiles are clang's). */
#define SFZ_EMBED_T0(path)                                                   \
    {"src/t0.c",                                                             \
     "static const unsigned char t0_blob[] = {\n"                            \
     "#if __has_embed(\"../" path "\")\n"                                    \
     "#embed \"../" path "\"\n"                                              \
     ",\n"                                                                   \
     "#endif\n"                                                              \
     "0};\n"                                                                 \
     "int t0_blob_len(int x)\n"                                              \
     "{\n"                                                                   \
     "    return x + (int)sizeof(t0_blob);\n"                                \
     "}\n",                                                                  \
     SFZ_SAME}

static const struct sfz_file k_embed_created[] = {
    {"Makefile", "# p\nCFLAGS_EXTRA = \n", SFZ_SAME},
    {"docs/blob.txt", NULL, "Z23\n"},
    SFZ_EMBED_T0("docs/blob.txt"),
    SFZ_T1_ALONE,
};

/* Probes the text scan once missed (all but the last), each of inc1/opt.h,
 * which the edit creates; gcc writes the depfiles, which omit a probe.
 * t0's value flips. */
#define SFZ_OPT_TAIL                                                         \
    "#define T0_V 1\n"                                                       \
    "#else\n"                                                                \
    "#define T0_V 0\n"                                                       \
    "#endif\n"                                                               \
    "int t0_opt(int x)\n"                                                    \
    "{\n"                                                                    \
    "    return x + T0_V;\n"                                                 \
    "}\n"
#define SFZ_OPT_CREATED {"inc1/opt.h", NULL, "/* site */\n"}

/* the probe is a -D value's macro, which no file holds */
static const struct sfz_file k_probe_dash_d[] = {
    {"Makefile", "# p\nCFLAGS_EXTRA = -DHAS(x)=__has_include(x)\n", SFZ_SAME},
    SFZ_OPT_CREATED,
    {"src/t0.c", "#if HAS(<opt.h>)\n" SFZ_OPT_TAIL, SFZ_SAME},
    SFZ_T1_ALONE,
};

/* before C23 the apostrophe opens a character literal holding a comment
 * opener */
static const struct sfz_file k_probe_c17_apostrophe[] = {
    {"Makefile", "# p\nCFLAGS_EXTRA = -std=c17\n", SFZ_SAME},
    SFZ_OPT_CREATED,
    {"src/t0.c",
     "#if 0\n"
     "int t0_k = 1'a/*';\n"
     "#endif\n"
     "#if __has_include(\"opt.h\")\n" SFZ_OPT_TAIL "/* end */\n",
     SFZ_SAME},
    SFZ_T1_ALONE,
};

/* in an ISO C mode before C23 a trigraph splices the word's two lines */
static const struct sfz_file k_probe_trigraph[] = {
    {"Makefile", "# p\nCFLAGS_EXTRA = -std=c17\n", SFZ_SAME},
    SFZ_OPT_CREATED,
    {"src/t0.c", "#if __has_in?\?/\nclude(<opt.h>)\n" SFZ_OPT_TAIL,
     SFZ_SAME},
    SFZ_T1_ALONE,
};

/* a comment sits between the word and a header name holding a comment
 * opener: that probe is unbound, and the scan must not lex the opener as a
 * comment that hides the probe after it (semantic_sensor_probe.c checks
 * the record; the unbound first probe widens t0 either way) */
static const struct sfz_file k_probe_comment_hdr[] = {
    {"Makefile", "# p\nCFLAGS_EXTRA = \n", SFZ_SAME},
    SFZ_OPT_CREATED,
    {"src/t0.c",
     "#if __has_include(/**/<x/*y.h>)\n"
     "#endif\n"
     "#if __has_include(\"opt.h\")\n" SFZ_OPT_TAIL "/* end */\n",
     SFZ_SAME},
    SFZ_T1_ALONE,
};

/* A literal __has_include(<opt.h>) finds inc2/opt.h; the edit creates
 * inc1/opt.h, searched first, with another value: the probe's answer stays
 * true, but the include it guards now reads the new file. */
static const struct sfz_file k_has_include_shadow[] = {
    {"Makefile", "# p\nCFLAGS_EXTRA = \n", SFZ_SAME},
    {"inc2/opt.h", "#define OPT_V 5\n", SFZ_SAME},
    {"inc1/opt.h", NULL, "#define OPT_V 9\n"},
    {"src/t0.c",
     "#if __has_include(<opt.h>)\n"
     "#include <opt.h>\n"
     "#else\n"
     "#define OPT_V 0\n"
     "#endif\n"
     "int t0_opt(int x)\n"
     "{\n"
     "    return x + OPT_V;\n"
     "}\n",
     SFZ_SAME},
    SFZ_T1_ALONE,
};

/* The __has_embed is a header's, relative to the header's own dir. */
static const struct sfz_file k_has_embed_header_deleted[] = {
    {"Makefile", "# p\nCFLAGS_EXTRA = \n", SFZ_SAME},
    {"docs/banner.txt", "Z23\n", NULL},
    {"inc1/banner.h",
     "#ifndef BANNER_H\n"
     "#define BANNER_H\n"
     "#if __has_embed(\"../docs/banner.txt\")\n"
     "#define T0_BANNER 1\n"
     "#else\n"
     "#define T0_BANNER 0\n"
     "#endif\n"
     "#endif\n",
     SFZ_SAME},
    {"src/t0.c",
     "#include \"banner.h\"\n"
     "int t0_banner(int x)\n"
     "{\n"
     "    return x + T0_BANNER * 7;\n"
     "}\n",
     SFZ_SAME},
    SFZ_T1_ALONE,
};

/* A probe word in a comment or a string literal is no lookup: creating the
 * path it names leaves note.h's reader alone. */
static const struct sfz_file k_probe_word_in_comment[] = {
    {"Makefile", "# p\nCFLAGS_EXTRA = \n", SFZ_SAME},
    {"docs/notes.txt", NULL, "N\n"},
    {"inc1/note.h",
     "#ifndef NOTE_H\n"
     "#define NOTE_H\n"
     "/* __has_embed(\"../docs/notes.txt\") and #embed <notes.txt> */\n"
     "// __has_include_next(<notes.txt>)\n"
     "static const char note_word[] = \"__has_embed(x)\";\n"
     "#define NOTE_V 3\n"
     "#endif\n",
     SFZ_SAME},
    {"src/t0.c",
     "#include \"note.h\"\n"
     "int t0_note(int x)\n"
     "{\n"
     "    return x + NOTE_V + (int)sizeof(note_word);\n"
     "}\n",
     SFZ_SAME},
    SFZ_T1_ALONE,
};

/* The real __has_embed follows a line whose C23 digit separator a lexer
 * that took it for a quote would pair with the string's quote, and then
 * read the string's comment opener as a comment covering the probe. */
static const struct sfz_file k_probe_after_separator[] = {
    {"Makefile", "# p\nCFLAGS_EXTRA = \n", SFZ_SAME},
    {"docs/banner.txt", "Z23\n", NULL},
    {"src/t0.c",
     "static const int t0_big = 1'0; static const char t0_s[] = \"'/*\";\n"
     "static const unsigned char t0_blob[] = {\n"
     "#if __has_embed(\"../docs/banner.txt\")\n"
     "#embed \"../docs/banner.txt\"\n"
     ",\n"
     "#endif\n"
     "0};\n"
     "int t0_blob_len(int x)\n"
     "{\n"
     "    return x + t0_big + (int)sizeof(t0_s) + (int)sizeof(t0_blob);\n"
     "}\n",
     SFZ_SAME},
    SFZ_T1_ALONE,
};

/* The macro-operand probe resolves to inc2/cfg_local.h; the edit creates
 * a path no search of it can reach. A replayed probe bounds the change:
 * t0 stays unaffected (an unbound one would widen it on any created path). */
static const struct sfz_file k_has_include_macro_elsewhere[] = {
    {"Makefile", "# p\nCFLAGS_EXTRA = \n", SFZ_SAME},
    SFZ_CFG_MACRO,
    {"inc2/cfg_local.h", "/* site overrides */\n", SFZ_SAME},
    {"docs/notes.txt", NULL, "notes\n"},
    SFZ_CFG_T0,
    SFZ_T1_ALONE,
};

/* ---- negative-lookup and ordering families ---------------------------------- */

/* N1a: a quoted #include falls through t0's own dir to -Iinc2's qx.h. The
 * edit creates inc1/qx.h (searched before inc2) with a different value;
 * inc2/qx.h, the file t0 read before, is untouched. */
static const struct sfz_file k_n1a_quoted_shadow[] = {
    {"Makefile", "# p\nCFLAGS_EXTRA = \n", SFZ_SAME},
    {"inc2/qx.h", "#define QX_V 5\n", SFZ_SAME},
    {"inc1/qx.h", NULL, "#define QX_V 9\n"},
    {"src/t0.c",
         "#include \"qx.h\"\n"
         "int t0_qx(void)\n"
         "{\n"
         "    return QX_V;\n"
         "}\n",
         SFZ_SAME},
    SFZ_T1_ALONE,
};

/* N1b: #if __has_include(<sx.h>) is false; the edit creates sx.h in an
 * -isystem dir the probe searches. */
static const struct sfz_file k_n1b_isystem_lookup[] = {
    {"Makefile", "# p\nCFLAGS_EXTRA = -isystem sys\n", SFZ_SAME},
    {"sys/sx.h", NULL, "#define SX_V 1\n"},
    {"src/t0.c",
         "#if __has_include(<sx.h>)\n"
         "#include <sx.h>\n"
         "#define T0_HAS SX_V\n"
         "#else\n"
         "#define T0_HAS 0\n"
         "#endif\n"
         "int t0_sx(void)\n"
         "{\n"
         "    return T0_HAS;\n"
         "}\n",
         SFZ_SAME},
    SFZ_T1_ALONE,
};

/* N1c: an #include_next chain (inc1/chain.h -> inc3/chain.h, reached via
 * CFLAGS_EXTRA -Iinc3). The edit creates inc2/chain.h, a new step between
 * the two search-path positions the chain used before: inc1's
 * include_next now finds inc2's copy instead of jumping straight to
 * inc3's. */
static const struct sfz_file k_n1c_include_next_chain[] = {
    {"Makefile", "# p\nCFLAGS_EXTRA = -Iinc3\n", SFZ_SAME},
    {"inc1/chain.h",
         "#define CHAIN_STEP1 1\n"
         "#include_next <chain.h>\n",
         SFZ_SAME},
    {"inc3/chain.h", "#define CHAIN_FINAL 100\n", SFZ_SAME},
    {"inc2/chain.h", NULL, "#define CHAIN_MID 50\n"},
    {"src/t0.c",
         "#include <chain.h>\n"
         "int t0_chain(void)\n"
         "{\n"
         "    int v = CHAIN_STEP1;\n"
         "#ifdef CHAIN_MID\n"
         "    v += CHAIN_MID;\n"
         "#endif\n"
         "#ifdef CHAIN_FINAL\n"
         "    v += CHAIN_FINAL;\n"
         "#endif\n"
         "    return v;\n"
         "}\n",
         SFZ_SAME},
    SFZ_T1_ALONE,
};

/* N2a: an X-macro header included twice in one TU with a different XM(...)
 * defined between the two #includes. The edit changes one entry's value in
 * the shared header, which both expansions (an enum and a value table)
 * must reseed. */
static const struct sfz_file k_n2a_xmacro_reinclude[] = {
    {"Makefile", "# p\nCFLAGS_EXTRA = \n", SFZ_SAME},
    {"inc1/xm.h",
         "XM(A, 1)\n"
         "XM(B, 2)\n"
         "XM(C, 3)\n",
         "XM(A, 1)\n"
         "XM(B, 20)\n"
         "XM(C, 3)\n"},
    {"src/t0.c",
         "#define XM(name, val) name = val,\n"
         "enum { XM_BASE = 0,\n"
         "#include \"xm.h\"\n"
         "XM_END };\n"
         "#undef XM\n"
         "#define XM(name, val) val,\n"
         "static const int xm_vals[] = {\n"
         "#include \"xm.h\"\n"
         "};\n"
         "int t0_sum(void)\n"
         "{\n"
         "    int s = 0;\n"
         "    for (unsigned i = 0; i < sizeof(xm_vals) / sizeof(xm_vals[0]); i++)\n"
         "        s += xm_vals[i];\n"
         "    return s + XM_END;\n"
         "}\n",
         SFZ_SAME},
    SFZ_T1_ALONE,
};

/* N2b: two headers each guard a typedef and a value macro behind
 * #ifndef ORD_TYPE, so whichever includes first wins. The edit is inside
 * t0.c itself: it swaps the #include order, with neither header changing a
 * byte. */
static const struct sfz_file k_n2b_order_typedef_swap[] = {
    {"Makefile", "# p\nCFLAGS_EXTRA = \n", SFZ_SAME},
    {"inc1/ord_a.h",
         "#ifndef ORD_A_H\n"
         "#define ORD_A_H\n"
         "#ifndef ORD_TYPE\n"
         "typedef int ord_t;\n"
         "#define ORD_TYPE 1\n"
         "#endif\n"
         "#endif\n",
         SFZ_SAME},
    {"inc2/ord_b.h",
         "#ifndef ORD_B_H\n"
         "#define ORD_B_H\n"
         "#ifndef ORD_TYPE\n"
         "typedef long ord_t;\n"
         "#define ORD_TYPE 2\n"
         "#endif\n"
         "#endif\n",
         SFZ_SAME},
    {"src/t0.c",
         "#include \"ord_a.h\"\n"
         "#include \"ord_b.h\"\n"
         "int t0_ord(void)\n"
         "{\n"
         "    ord_t v = (ord_t)ORD_TYPE;\n"
         "    return (int)v;\n"
         "}\n",
         "#include \"ord_b.h\"\n"
         "#include \"ord_a.h\"\n"
         "int t0_ord(void)\n"
         "{\n"
         "    ord_t v = (ord_t)ORD_TYPE;\n"
         "    return (int)v;\n"
         "}\n"},
    SFZ_T1_ALONE,
};

/* N2c: inc2/undef_b.h #undefs the macro inc1/def_a.h defines, and
 * redefines it. The edit adds that #undef/#define pair to inc2's own
 * (previously no-op) guarded body: a header change, as D-family cases, but
 * through #undef rather than a fresh #define. */
static const struct sfz_file k_n2c_undef_between[] = {
    {"Makefile", "# p\nCFLAGS_EXTRA = \n", SFZ_SAME},
    {"inc1/def_a.h",
         "#ifndef DEF_A_H\n"
         "#define DEF_A_H\n"
         "#define UNDF_V 7\n"
         "#endif\n",
         SFZ_SAME},
    {"inc2/undef_b.h",
         "#ifndef UNDF_B_H\n"
         "#define UNDF_B_H\n"
         "#endif\n",
         "#ifndef UNDF_B_H\n"
         "#define UNDF_B_H\n"
         "#undef UNDF_V\n"
         "#define UNDF_V 42\n"
         "#endif\n"},
    {"src/t0.c",
         "#include \"def_a.h\"\n"
         "#include \"undef_b.h\"\n"
         "int t0_undef(void)\n"
         "{\n"
         "    return UNDF_V;\n"
         "}\n",
         SFZ_SAME},
    SFZ_T1_ALONE,
};

/* ---- static assertions: a compile-time check over a changed entity ---------- */

/* inc2/guard.h asserts over struct shape (inc2/shape.h) and over a macro
 * chain ending in SHAPE_MAX. t1 and t2 include guard.h and name nothing of
 * shape.h themselves; t0 reads shape.h directly. An assertion emits no
 * bytes, so when its operands change the readers' objects stay the same,
 * but their compile can now fail: each is affected, compile only (pinned
 * over-selection, one per reader). A change the assertions do not name
 * leaves them alone. */
#define SFZ_SA_GUARD                                                         \
    "#ifndef GUARD_H\n"                                                      \
    "#define GUARD_H\n"                                                      \
    "#include \"shape.h\"\n"                                                 \
    "#define GUARD_LIMIT (SHAPE_MAX * 2)\n"                                  \
    "static_assert(sizeof(struct shape) >= 8, \"shape size\");\n"            \
    "static_assert(GUARD_LIMIT <= 64, \"shape limit\");\n"                   \
    "#endif\n"
#define SFZ_SA_SHAPE(field, max, ret)                                        \
    "#ifndef SHAPE_H\n"                                                      \
    "#define SHAPE_H\n"                                                      \
    "struct shape { int a; int b;" field " };\n"                             \
    "#define SHAPE_MAX " max "\n"                                            \
    ret " shape_unrel(int x);\n"                                             \
    "#endif\n"
#define SFZ_SA_T0                                                            \
    {"src/t0.c",                                                             \
     "#include \"shape.h\"\n"                                                \
     "unsigned long t0_sz(void)\n"                                           \
     "{\n"                                                                   \
     "    return sizeof(struct shape);\n"                                    \
     "}\n"                                                                   \
     "long t0_u(void)\n"                                                     \
     "{\n"                                                                   \
     "    return shape_unrel(1);\n"                                          \
     "}\n",                                                                  \
     SFZ_SAME}
#define SFZ_SA_READER(path, fn, v)                                           \
    {path,                                                                   \
     "#include \"guard.h\"\n"                                                \
     "int " fn "(void)\n"                                                    \
     "{\n"                                                                   \
     "    return " v ";\n"                                                   \
     "}\n",                                                                  \
     SFZ_SAME}
#define SFZ_SA_COMMON                                                        \
    {"Makefile", "# p\nCFLAGS_EXTRA = \n", SFZ_SAME}, SFZ_SA_T0,             \
        SFZ_SA_READER("src/t1.c", "t1_v", "7"),                              \
        SFZ_SA_READER("src/t2.c", "t2_v", "9")

/* SA1: struct shape gains a field; sizeof(struct shape) >= 8 still holds. */
static const struct sfz_file k_sa1_struct_grows[] = {
    {"inc2/guard.h", SFZ_SA_GUARD, SFZ_SAME},
    {"inc2/shape.h", SFZ_SA_SHAPE("", "16", "int"),
     SFZ_SA_SHAPE(" int c;", "16", "int")},
    SFZ_SA_COMMON,
};

/* SA2: SHAPE_MAX, which the assertion reaches through GUARD_LIMIT, moves
 * from 16 to 24; the limit still holds. */
static const struct sfz_file k_sa2_macro_chain[] = {
    {"inc2/guard.h", SFZ_SA_GUARD, SFZ_SAME},
    {"inc2/shape.h", SFZ_SA_SHAPE("", "16", "int"),
     SFZ_SA_SHAPE("", "24", "int")},
    SFZ_SA_COMMON,
};

/* SA3: shape_unrel, which no assertion names, returns long; only t0, which
 * calls it, is affected. */
static const struct sfz_file k_sa3_unrelated_fn[] = {
    {"inc2/guard.h", SFZ_SA_GUARD, SFZ_SAME},
    {"inc2/shape.h", SFZ_SA_SHAPE("", "16", "int"),
     SFZ_SA_SHAPE("", "16", "long")},
    SFZ_SA_COMMON,
};

/* SA4: the assertion's own bound changes in guard.h. */
static const struct sfz_file k_sa4_assert_edited[] = {
    {"inc2/guard.h", SFZ_SA_GUARD,
     "#ifndef GUARD_H\n"
     "#define GUARD_H\n"
     "#include \"shape.h\"\n"
     "#define GUARD_LIMIT (SHAPE_MAX * 2)\n"
     "static_assert(sizeof(struct shape) >= 4, \"shape size\");\n"
     "static_assert(GUARD_LIMIT <= 64, \"shape limit\");\n"
     "#endif\n"},
    {"inc2/shape.h", SFZ_SA_SHAPE("", "16", "int"), SFZ_SAME},
    SFZ_SA_COMMON,
};

const struct sfz_repro k_sfz_repros[] = {
    {"F1_flag", "flag", "Makefile CFLAGS_EXTRA gains -DPROJ_MODE=1", false,
     NULL, SFZ_FILES(k_f1_flag), NULL, false, 0},
    {"F2_counter_c", "counter_c",
     "t0_a gains a __COUNTER__ expansion; t0_b, below it and unchanged, now "
     "returns 1",
     false, NULL, SFZ_FILES(k_f2_counter_c), NULL, false, 0},
    {"F2_counter_header", "header_inline",
     "h_inl gains one __COUNTER__ expansion; every later __COUNTER__ in each "
     "reader shifts by one",
     false, NULL, SFZ_FILES(k_f2_counter_header), NULL, false, 0},
    {"F3_line_c", "comment_ws",
     "a blank line inside t0_a moves t0_b down one line; __LINE__ in t0_b "
     "changes",
     false, NULL, SFZ_FILES(k_f3_line_c), NULL, false, 0},
    {"F4_hasinc_create_gccdeps", "shadow",
     "new inc1/opt.h flips a __has_include in inc2/h.h; gcc depfiles omit "
     "the probe",
     true, NULL, SFZ_FILES(k_f4_hasinc_create_gccdeps), NULL, false, 0},
    {"F4_hasinc_delete", "hasinc",
     "deleting inc1/opt.h flips a __has_include in inc2/h.h", false, NULL,
     SFZ_FILES(k_f4_hasinc_delete), NULL, false, 0},
    {"F5_header_static", "body_extern",
     "t0_set stores 6 not 5 into a header-defined static; t0_get folds it",
     false, NULL, SFZ_FILES(k_f5_header_static), NULL, false, 0},
    {"F6_alias", "body_extern", "body of h_api, which h_api_compat aliases",
     false, NULL, SFZ_FILES(k_f6_alias), NULL, false, 0},
    {"F7_cleanup_handler", "body_static",
     "body of a cleanup() handler that t0_work inlines (fixed by f6b50b90fd: "
     "the handler's runner is seeded)",
     false, NULL, SFZ_FILES(k_f7_cleanup_handler), NULL, false, 0},
    {"F7_cleanup_same_name", "body_static",
     "t0's work() inlines a cleanup() handler whose body changed; t1's own "
     "static work() changed too; a seed matched by bare name would hide a "
     "miss behind t1's static work",
     false, NULL, SFZ_FILES(k_f7_cleanup_same_name), NULL, false, 0},
    {"F8_c_includes_c", "body_static",
     "test_b.c #includes b.c to reach its statics; b_k body changes (fixed "
     "by f6b50b90fd: the includer's functions are seeded)",
     false, NULL, SFZ_FILES(k_f8_c_includes_c), NULL, false, 0},
    {"F8_c_includes_c_renamed", "body_static",
     "a.c #includes b.c (unity build); b_k body changes; a_b_api and a_use "
     "are seeded",
     false, NULL, SFZ_FILES(k_f8_c_includes_c_renamed), NULL, false, 0},
    {"pass_hd", "macro_value", "H_A 1->3 flips H_D", false, NULL,
     SFZ_FILES(k_pass_hd), NULL, false, 0},
    {"pass_hdrproto", "body_static",
     "body of a static declared in a header, defined in the main file", false,
     NULL, SFZ_FILES(k_pass_hdrproto), NULL, false, 0},
    {"pass_undef", "macro_value", "H_TMP 5->6, #undef after use", false, NULL,
     SFZ_FILES(k_pass_undef), NULL, false, 0},
    {"pass_undefbody", "body_extern", "#undef inside t0_f changes #ifdef in t0_g",
     false, NULL, SFZ_FILES(k_pass_undefbody), NULL, false, 0},
    {"D1_string_literal", "data_string",
     "t0_name returns a longer literal; t0_tail's literal moves in the "
     "merged string section",
     false, NULL, SFZ_FILES(k_d1_string_literal), NULL, false, 0},
    {"D2_static_const_table", "data_table",
     "one entry of a file-scope static const table that t0_pick indexes",
     false, NULL, SFZ_FILES(k_d2_static_const_table), NULL, false, 0},
    {"D3_header_const_table", "data_hconst",
     "one entry of a header static const table that t0 and t1 index",
     false, NULL, SFZ_FILES(k_d3_header_const_table), NULL, false, 0},
    {"D4_header_index_macro", "data_index",
     "H_IDX 1->2 moves t1_at's read of the global array t0 defines", false,
     NULL, SFZ_FILES(k_d4_header_index_macro), NULL, false, 0},
    {"D5_extern_const_init", "header_const",
     "H_LIMIT 40->41 initializes the global const t0 defines, which t1 reads",
     false, NULL, SFZ_FILES(k_d5_extern_const_init), NULL, false, 0},
    {"D6_function_static_table", "data_table",
     "one entry of a static const table inside t0_pick", false, NULL,
     SFZ_FILES(k_d6_function_static_table), NULL, false, 0},
    {"F13_has_embed_deleted", "hasembed",
     "docs/banner.txt, which only t0's __has_embed probes, is deleted (fixed: "
     "an unbound lookup reaches a deleted path)",
     false, NULL, SFZ_FILES(k_f13_has_embed_deleted), NULL, true, 0},
    {"pass_has_embed_created", "hasembed",
     "docs/banner.txt, which only t0's __has_embed probes, is created", false,
     NULL, SFZ_FILES(k_has_embed_created), NULL, false, 0},
    {"pass_has_embed_build_input", "hasembed",
     "data/banner.bin, which only t0's __has_embed probes, is deleted", false,
     NULL, SFZ_FILES(k_has_embed_data_deleted), NULL, false, 0},
    {"pass_has_embed_header_deleted", "hasembed",
     "docs/banner.txt, which only inc1/banner.h's __has_embed probes, is "
     "deleted; t0 reads banner.h",
     false, NULL, SFZ_FILES(k_has_embed_header_deleted), NULL, true, 0},
    {"pass_embed_created", "hasembed",
     "docs/blob.txt, which t0 #embeds behind __has_embed, is created", false,
     NULL, SFZ_FILES(k_embed_created), NULL, true, 0},
    {"pass_probe_word_in_comment", "hasembed",
     "docs/notes.txt, which only a comment and a string in note.h name, is "
     "created: no TU is affected",
     false, NULL, SFZ_FILES(k_probe_word_in_comment), NULL, true, 0},
    {"pass_probe_after_separator", "hasembed",
     "docs/banner.txt, which t0 probes after a digit separator and a string "
     "holding a comment opener, is deleted",
     false, NULL, SFZ_FILES(k_probe_after_separator), NULL, true, 0},
    {"F14_has_include_macro", "hasinc_macro",
     "inc2/cfg_local.h, which cfg.h probes as __has_include(CFG_LOCAL), is "
     "deleted (fixed: the sensor replays the expanded operand)",
     false, NULL, SFZ_FILES(k_f14_has_include_macro), NULL, true, 0},
    {"F14_has_include_next", "hasinc_macro",
     "inc2/cfg_local.h, which cfg.h probes with __has_include_next, is "
     "deleted (fixed: the sensor replays the search from cfg.h's slot on)",
     false, NULL, SFZ_FILES(k_f14_has_include_next), NULL, true, 0},
    {"F15_has_include_macro_gcc_deps", "hasinc_macro",
     "inc2/cfg_local.h, which cfg.h probes as __has_include(CFG_LOCAL), is "
     "created; gcc writes the depfiles (fixed as F14)",
     true, NULL, SFZ_FILES(k_f15_has_include_macro), NULL, true, 0},
    {"F15_has_include_next_gcc_deps", "hasinc_macro",
     "inc2/cfg_local.h, which cfg.h probes with __has_include_next, is "
     "created; gcc writes the depfiles (fixed as F14)",
     true, NULL, SFZ_FILES(k_f15_has_include_next), NULL, true, 0},
    {"pass_has_include_macro_elsewhere", "hasinc_macro",
     "docs/notes.txt, which no search of cfg.h's __has_include(CFG_LOCAL) "
     "can reach, is created: t0 stays unaffected",
     false, NULL, SFZ_FILES(k_has_include_macro_elsewhere), NULL, true, 0},
    {"pass_has_include_shadow_gcc_deps", "shadow",
     "inc1/opt.h, searched before the inc2/opt.h t0's literal "
     "__has_include(<opt.h>) finds, is created with another OPT_V; gcc "
     "writes the depfiles",
     true, NULL, SFZ_FILES(k_has_include_shadow), NULL, true, 0},
    {"pass_probe_dash_d_gcc_deps", "hasinc",
     "inc1/opt.h, which t0 probes through a -D value's macro, is created; "
     "gcc writes the depfiles. t1 compiles with the same -D, so it is "
     "affected too (pinned over-selection 1)",
     true, NULL, SFZ_FILES(k_probe_dash_d), NULL, true, 1},
    {"pass_probe_c17_apostrophe_gcc_deps", "hasinc",
     "inc1/opt.h, which t0 probes after a -std=c17 character literal "
     "holding a comment opener, is created; gcc writes the depfiles",
     true, NULL, SFZ_FILES(k_probe_c17_apostrophe), NULL, true, 0},
    {"pass_probe_trigraph_gcc_deps", "hasinc",
     "inc1/opt.h, which t0 probes with a word a -std=c17 trigraph splices, "
     "is created; gcc writes the depfiles",
     true, NULL, SFZ_FILES(k_probe_trigraph), NULL, true, 0},
    {"pass_probe_comment_hdr_gcc_deps", "hasinc",
     "inc1/opt.h, which t0 probes after a probe whose comment-led header "
     "name holds a comment opener, is created; gcc writes the depfiles",
     true, NULL, SFZ_FILES(k_probe_comment_hdr), NULL, true, 0},
    {"pass_link_retarget", "symlink_retarget",
     "inc1/h.h, a link t0 includes, names hdr/b.h instead of hdr/a.h", false,
     NULL, SFZ_FILES(k_link_retarget), NULL, false, 0},
    {"pass_link_target_edit", "symlink_retarget",
     "hdr/a.h changes; t0 reads it only through the link inc1/h.h", false,
     NULL, SFZ_FILES(k_link_target_edit), NULL, false, 0},
    {"N1a_quoted_shadow", "neg_quoted_shadow",
     "inc1/qx.h, searched before inc2/qx.h (unedited), is created with a "
     "different QX_V",
     false, NULL, SFZ_FILES(k_n1a_quoted_shadow), NULL, true, 0},
    {"N1b_isystem_lookup", "neg_isystem_lookup",
     "sys/sx.h, an -isystem dir __has_include(<sx.h>) probes, is created "
     "(sys comes into existence, so every TU's search list changes; t1's "
     "lookups all resolve as before, so only t0 is affected)",
     false, NULL, SFZ_FILES(k_n1b_isystem_lookup), NULL, true, 0},
    {"N1c_include_next_chain", "neg_include_next_chain",
     "inc2/chain.h, a new step between inc1's include_next and inc3's "
     "final header, is created",
     false, NULL, SFZ_FILES(k_n1c_include_next_chain), NULL, true, 0},
    {"N2a_xmacro_reinclude", "xmacro_reinclude",
     "inc1/xm.h's XM(B,2) becomes XM(B,20); xm.h is #included twice in "
     "t0.c with a different XM(...) defined each time",
     false, NULL, SFZ_FILES(k_n2a_xmacro_reinclude), NULL, true, 0},
    {"N2b_order_typedef_swap", "order_typedef_swap",
     "t0.c swaps the order it includes ord_a.h and ord_b.h, each guarding "
     "a typedef and a value macro behind #ifndef ORD_TYPE; neither header "
     "changes",
     false, NULL, SFZ_FILES(k_n2b_order_typedef_swap), NULL, true, 0},
    {"N2c_undef_between", "order_undef",
     "inc2/undef_b.h, previously a no-op, gains an #undef and redefine of "
     "UNDF_V, which inc1/def_a.h defines first",
     false, NULL, SFZ_FILES(k_n2c_undef_between), NULL, true, 0},
    {"SA1_assert_struct_grows", "static_assert",
     "struct shape gains a field; inc2/guard.h asserts over its size, so "
     "t1 and t2, which name nothing of shape.h, compile (pinned "
     "over-selection 2: their objects do not change)",
     false, NULL, SFZ_FILES(k_sa1_struct_grows), NULL, true, 2},
    {"SA2_assert_macro_chain", "static_assert",
     "SHAPE_MAX, which guard.h's assertion reaches through GUARD_LIMIT, "
     "moves from 16 to 24: t1 and t2 compile (pinned over-selection 2)",
     false, NULL, SFZ_FILES(k_sa2_macro_chain), NULL, true, 2},
    {"SA3_assert_unrelated_fn", "static_assert",
     "shape_unrel, which no assertion names, returns long: only t0 is "
     "affected",
     false, NULL, SFZ_FILES(k_sa3_unrelated_fn), NULL, true, 0},
    {"SA4_assert_edited", "static_assert",
     "guard.h's size bound changes from 8 to 4: t1 and t2 compile (pinned "
     "over-selection 2)",
     false, NULL, SFZ_FILES(k_sa4_assert_edited), NULL, true, 2},
};
const size_t k_sfz_nrepros = sizeof(k_sfz_repros) / sizeof(k_sfz_repros[0]);

/* ---- toolchain reproducers: the compiler or its optimizer, not the text ---- */

/* A comment inside t0_a; t1.c is untouched. Built with another compiler
 * after the edit, every object changes while every manifest stays the
 * same: the sensor records its own libclang version and the argv, never
 * the compiler that builds the object. */
static const struct sfz_file k_f9_cc_drift[] = {
    {"inc2/h.h",
         "#ifndef H_H\n"
         "#define H_H\n"
         "int t0_a(int x);\n"
         "int t1_a(int x);\n"
         "#endif\n",
         SFZ_SAME},
    {"Makefile", "# p\nCFLAGS_EXTRA = \n", SFZ_SAME},
    {"src/t0.c",
         "#include \"h.h\"\n"
         "int t0_a(int x)\n"
         "{\n"
         "    return x * 3 + 1;\n"
         "}\n",
         "#include \"h.h\"\n"
         "int t0_a(int x)\n"
         "{\n"
         "    /* scaled */\n"
         "    return x * 3 + 1;\n"
         "}\n"},
    {"src/t1.c",
         "#include \"h.h\"\n"
         "int t1_a(int x)\n"
         "{\n"
         "    return x * 5 + 2;\n"
         "}\n",
         SFZ_SAME},
};

/* t0_f passes 8, not 7, to a noinline static. gcc reads "-O02" and
 * "--optimize=2" as -O2 and specializes the static for its one caller
 * (t0_s.constprop.0); the consumer reads -O02 as -O0 and --optimize=2 as
 * no optimizer, and seeds only t0_f and its callers. */
static const struct sfz_file k_f10_opt_spelling[] = {
    {"inc2/h.h",
         "#ifndef H_H\n"
         "#define H_H\n"
         "int t0_f(void);\n"
         "#endif\n",
         SFZ_SAME},
    {"Makefile", "# p\nCFLAGS_EXTRA = \n", SFZ_SAME},
    {"src/t0.c",
         "#include \"h.h\"\n"
         "static __attribute__((noinline)) int t0_s(int x)\n"
         "{\n"
         "    int r = 0;\n"
         "    for (int i = 0; i < x; i++)\n"
         "        r += i * x;\n"
         "    return r;\n"
         "}\n"
         "int t0_f(void)\n"
         "{\n"
         "    return t0_s(7);\n"
         "}\n",
         "#include \"h.h\"\n"
         "static __attribute__((noinline)) int t0_s(int x)\n"
         "{\n"
         "    int r = 0;\n"
         "    for (int i = 0; i < x; i++)\n"
         "        r += i * x;\n"
         "    return r;\n"
         "}\n"
         "int t0_f(void)\n"
         "{\n"
         "    return t0_s(8);\n"
         "}\n"},
};

/* k_f10_opt_spelling's edit under a Makefile whose CFLAGS_EXTRA, appended
 * last to the argv, spells an optimizer level that is no optimizer flag:
 * a macro value or a linker option. */
#define SFZ_DECOY_FILES(extra)                                               \
    {"inc2/h.h",                                                             \
         "#ifndef H_H\n"                                                     \
         "#define H_H\n"                                                     \
         "int t0_f(void);\n"                                                 \
         "#endif\n",                                                         \
         SFZ_SAME},                                                          \
    {"Makefile", "# p\nCFLAGS_EXTRA = " extra "\n", SFZ_SAME},              \
    {"src/t0.c",                                                             \
         "#include \"h.h\"\n"                                                \
         "static __attribute__((noinline)) int t0_s(int x)\n"                \
         "{\n"                                                               \
         "    int r = 0;\n"                                                  \
         "    for (int i = 0; i < x; i++)\n"                                 \
         "        r += i * x;\n"                                             \
         "    return r;\n"                                                   \
         "}\n"                                                               \
         "int t0_f(void)\n"                                                  \
         "{\n"                                                               \
         "    return t0_s(7);\n"                                             \
         "}\n",                                                              \
         "#include \"h.h\"\n"                                                \
         "static __attribute__((noinline)) int t0_s(int x)\n"                \
         "{\n"                                                               \
         "    int r = 0;\n"                                                  \
         "    for (int i = 0; i < x; i++)\n"                                 \
         "        r += i * x;\n"                                             \
         "    return r;\n"                                                   \
         "}\n"                                                               \
         "int t0_f(void)\n"                                                  \
         "{\n"                                                               \
         "    return t0_s(8);\n"                                             \
         "}\n"}

static const struct sfz_file k_decoy_define_last[] = {
    SFZ_DECOY_FILES("-DLVL=-O0")};
static const struct sfz_file k_decoy_linker_last[] = {
    SFZ_DECOY_FILES("-Wl,-O0")};

/* t0_a passes 8, not 7, to an external noinline function t0_b also calls.
 * gcc at -O3 (and -O5, which it reads as -O3) clones the callee for each
 * constant (t0_w.constprop.N); the consumer reads -O5 as the -O1
 * component model, which never seeds an external callee. */
static const struct sfz_file k_f10_extern_clone[] = {
    {"inc2/h.h",
         "#ifndef H_H\n"
         "#define H_H\n"
         "int t0_w(int x);\n"
         "int t0_a(void);\n"
         "int t0_b(void);\n"
         "#endif\n",
         SFZ_SAME},
    {"Makefile", "# p\nCFLAGS_EXTRA = \n", SFZ_SAME},
    {"src/t0.c",
         "#include \"h.h\"\n"
         "__attribute__((noinline)) int t0_w(int x)\n"
         "{\n"
         "    int r = 0;\n"
         "    for (int i = 0; i < x; i++)\n"
         "        r += i * x;\n"
         "    return r;\n"
         "}\n"
         "int t0_a(void)\n"
         "{\n"
         "    return t0_w(7);\n"
         "}\n"
         "int t0_b(void)\n"
         "{\n"
         "    return t0_w(7);\n"
         "}\n",
         "#include \"h.h\"\n"
         "__attribute__((noinline)) int t0_w(int x)\n"
         "{\n"
         "    int r = 0;\n"
         "    for (int i = 0; i < x; i++)\n"
         "        r += i * x;\n"
         "    return r;\n"
         "}\n"
         "int t0_a(void)\n"
         "{\n"
         "    return t0_w(8);\n"
         "}\n"
         "int t0_b(void)\n"
         "{\n"
         "    return t0_w(7);\n"
         "}\n"},
};

/* t0_p's body becomes t0_q's. At -O2 gcc folds the identical statics
 * (ipa-icf), so t0_q now names t0_p's bytes; the manifest says -Og, as
 * the facts rule's argv does for the dev build's -O2 hot objects, and the
 * component model never relates t0_q to t0_p. */
static const struct sfz_file k_f11_hot_icf[] = {
    {"inc2/h.h",
         "#ifndef H_H\n"
         "#define H_H\n"
         "int t0_ep(int x);\n"
         "int t0_eq(int x);\n"
         "#endif\n",
         SFZ_SAME},
    {"Makefile", "# p\nCFLAGS_EXTRA = \n", SFZ_SAME},
    {"src/t0.c",
         "#include \"h.h\"\n"
         "static __attribute__((noinline)) int t0_p(int x)\n"
         "{\n"
         "    int r = 0;\n"
         "    for (int i = 0; i < x; i++)\n"
         "        r += i * x + 3;\n"
         "    return r;\n"
         "}\n"
         "static __attribute__((noinline)) int t0_q(int x)\n"
         "{\n"
         "    int r = 0;\n"
         "    for (int i = 0; i < x; i++)\n"
         "        r += i * x + 5;\n"
         "    return r;\n"
         "}\n"
         "int t0_ep(int x)\n"
         "{\n"
         "    return t0_p(x) + 1;\n"
         "}\n"
         "int t0_eq(int x)\n"
         "{\n"
         "    return t0_q(x) + 2;\n"
         "}\n",
         "#include \"h.h\"\n"
         "static __attribute__((noinline)) int t0_p(int x)\n"
         "{\n"
         "    int r = 0;\n"
         "    for (int i = 0; i < x; i++)\n"
         "        r += i * x + 5;\n"
         "    return r;\n"
         "}\n"
         "static __attribute__((noinline)) int t0_q(int x)\n"
         "{\n"
         "    int r = 0;\n"
         "    for (int i = 0; i < x; i++)\n"
         "        r += i * x + 5;\n"
         "    return r;\n"
         "}\n"
         "int t0_ep(int x)\n"
         "{\n"
         "    return t0_p(x) + 1;\n"
         "}\n"
         "int t0_eq(int x)\n"
         "{\n"
         "    return t0_q(x) + 2;\n"
         "}\n"},
};


/* The body of a header's static inline function t0_a calls. At -O1 the
 * call is inlined and only t0_a changes; at -O0 each reader emits the
 * function out of line, and its new bytes are no seed: it is not a
 * main-file function and, having internal linkage, not a root that would
 * broaden the TU. */
static const struct sfz_file k_f12_header_static_inline[] = {
    {"inc2/h.h",
         "#ifndef H_H\n"
         "#define H_H\n"
         "static inline int h_inl(int x)\n"
         "{\n"
         "    return x * 3 + 0;\n"
         "}\n"
         "int t0_a(int x);\n"
         "#endif\n",
         "#ifndef H_H\n"
         "#define H_H\n"
         "static inline int h_inl(int x)\n"
         "{\n"
         "    return x * 3 + 1;\n"
         "}\n"
         "int t0_a(int x);\n"
         "#endif\n"},
    {"Makefile", "# p\nCFLAGS_EXTRA = \n", SFZ_SAME},
    {"src/t0.c",
         "#include \"h.h\"\n"
         "int t0_a(int x)\n"
         "{\n"
         "    return h_inl(x) + 9;\n"
         "}\n",
         SFZ_SAME},
};

/* ---- search-dir deltas: -I/-iquote/-isystem/-idirafter only --------------- */

/* The argv adds, drops or reorders search dirs between the sides (the
 * case's optimizer flags carry them, so no Makefile edit makes every TU a
 * build-input change); one .c is edited so the change set is not empty.
 * The consumer replays each TU's recorded lookups under both search lists:
 * a TU whose every lookup hits the same file through the same dir, whose
 * probes answer the same and whose file set is the same is not affected;
 * any other is, alone (exact over-selection pins). */
#define SFZ_SD_Q1 {"inc1/q1.h", "#define Q1_V 3\n", SFZ_SAME}
#define SFZ_SD_T1                                                            \
    {"src/t1.c",                                                             \
     "#include <q1.h>\n"                                                     \
     "int t1_q(void)\n"                                                      \
     "{\n"                                                                   \
     "    return Q1_V;\n"                                                    \
     "}\n",                                                                  \
     SFZ_SAME}
#define SFZ_SD_T2_EDIT                                                       \
    {"src/t2.c",                                                             \
     "int t2_a(void)\n"                                                      \
     "{\n"                                                                   \
     "    return 1;\n"                                                       \
     "}\n",                                                                  \
     "int t2_a(void)\n"                                                      \
     "{\n"                                                                   \
     "    return 2;\n"                                                       \
     "}\n"}

/* SD1: -isystem sysx is added; sysx holds no name any TU looks up. Only
 * the edited t0 is affected. */
static const struct sfz_file k_sd1_isystem_inert[] = {
    {"Makefile", "# p\nCFLAGS_EXTRA = \n", SFZ_SAME},
    {"sysx/other.h", "#define OTHER_V 1\n", SFZ_SAME},
    SFZ_SD_Q1,
    {"src/t0.c",
         "#include \"q1.h\"\n"
         "int t0_a(void)\n"
         "{\n"
         "    return Q1_V + 1;\n"
         "}\n",
         "#include \"q1.h\"\n"
         "int t0_a(void)\n"
         "{\n"
         "    return Q1_V + 2;\n"
         "}\n"},
    SFZ_SD_T1,
};

/* SD2: -Ishad is added ahead of inc1; shad/qx.h shadows inc1/qx.h for
 * t0's quoted include (src/ holds no qx.h). */
static const struct sfz_file k_sd2_shadow_quoted[] = {
    {"Makefile", "# p\nCFLAGS_EXTRA = \n", SFZ_SAME},
    {"shad/qx.h", "#define QX_V 9\n", SFZ_SAME},
    {"inc1/qx.h", "#define QX_V 5\n", SFZ_SAME},
    SFZ_SD_Q1,
    {"src/t0.c",
         "#include \"qx.h\"\n"
         "int t0_qx(void)\n"
         "{\n"
         "    return QX_V;\n"
         "}\n",
         SFZ_SAME},
    SFZ_SD_T1,
    SFZ_SD_T2_EDIT,
};

/* SD3: -Iextra is added; extra/px.h turns t0's __has_include(<px.h>) from
 * false to true, and t0 reads no new file. */
static const struct sfz_file k_sd3_probe_satisfied[] = {
    {"Makefile", "# p\nCFLAGS_EXTRA = \n", SFZ_SAME},
    {"extra/px.h", "#define PX_V 7\n", SFZ_SAME},
    SFZ_SD_Q1,
    {"src/t0.c",
         "#if __has_include(<px.h>)\n"
         "#define T0_PX 1\n"
         "#else\n"
         "#define T0_PX 0\n"
         "#endif\n"
         "int t0_px(void)\n"
         "{\n"
         "    return T0_PX;\n"
         "}\n",
         SFZ_SAME},
    SFZ_SD_T1,
    SFZ_SD_T2_EDIT,
};

/* SD4: -Ira -Irb becomes -Irb -Ira; both hold rh.h, with other values. */
static const struct sfz_file k_sd4_pair_reordered[] = {
    {"Makefile", "# p\nCFLAGS_EXTRA = \n", SFZ_SAME},
    {"ra/rh.h", "#define RH_V 1\n", SFZ_SAME},
    {"rb/rh.h", "#define RH_V 2\n", SFZ_SAME},
    SFZ_SD_Q1,
    {"src/t0.c",
         "#include <rh.h>\n"
         "int t0_rh(void)\n"
         "{\n"
         "    return RH_V;\n"
         "}\n",
         SFZ_SAME},
    SFZ_SD_T1,
    SFZ_SD_T2_EDIT,
};

/* SD5: -Iold is dropped; t0's <rm.h> now falls through to inc2/rm.h. */
static const struct sfz_file k_sd5_dir_removed[] = {
    {"Makefile", "# p\nCFLAGS_EXTRA = \n", SFZ_SAME},
    {"old/rm.h", "#define RM_V 4\n", SFZ_SAME},
    {"inc2/rm.h", "#define RM_V 6\n", SFZ_SAME},
    SFZ_SD_Q1,
    {"src/t0.c",
         "#include <rm.h>\n"
         "int t0_rm(void)\n"
         "{\n"
         "    return RM_V;\n"
         "}\n",
         SFZ_SAME},
    SFZ_SD_T1,
    SFZ_SD_T2_EDIT,
};

/* SD6: as SD1, but t1 reads a system header. The sensor records no lookup
 * a system header makes (its includes, its __has_include probes), so
 * nothing proves an added dir shadows none of them: t1 widens. */
static const struct sfz_file k_sd6_system_header[] = {
    {"Makefile", "# p\nCFLAGS_EXTRA = \n", SFZ_SAME},
    {"sysx/other.h", "#define OTHER_V 1\n", SFZ_SAME},
    SFZ_SD_Q1,
    {"src/t0.c",
         "#include \"q1.h\"\n"
         "int t0_a(void)\n"
         "{\n"
         "    return Q1_V + 1;\n"
         "}\n",
         "#include \"q1.h\"\n"
         "int t0_a(void)\n"
         "{\n"
         "    return Q1_V + 2;\n"
         "}\n"},
    {"src/t1.c",
         "#include <stddef.h>\n"
         "int t1_s(void)\n"
         "{\n"
         "    return (int)sizeof(size_t);\n"
         "}\n",
         SFZ_SAME},
};

const struct sfz_tool_repro k_sfz_tool_repros[] = {
    {.r = {.name = "F9_cc_drift", .kind = "comment_ws",
           .detail = "a comment in t0_a; the object compiler changes from "
                     "clang to gcc between the sides, the argv does not "
                     "(fixed by ff12233071: the IDENTITY record names the "
                     "object compiler's realpath and byte SHA3-256)",
           .files = SFZ_FILES(k_f9_cc_drift)},
     .cc_before = "clang", .cc_after = "gcc"},
    {.r = {.name = "F10_opt_spelling_O02", .kind = "body_extern",
           .detail = "t0_f passes 8, not 7, to a noinline static; gcc at "
                     "-O02 (fixed by 3eb2f44f3a: the digits after -O and "
                     "--optimize are read numerically instead of matched "
                     "by prefix, and an unrecognized spelling widens "
                     "instead of falling to -O0/no optimizer)",
           .files = SFZ_FILES(k_f10_opt_spelling)},
     .cc_before = "gcc", .cc_after = "gcc", .opt = "-O02"},
    {.r = {.name = "F10_opt_spelling_long", .kind = "body_extern",
           .detail = "t0_f passes 8, not 7, to a noinline static; gcc at "
                     "--optimize=2 (fixed by 3eb2f44f3a, as "
                     "F10_opt_spelling_O02)",
           .files = SFZ_FILES(k_f10_opt_spelling)},
     .cc_before = "gcc", .cc_after = "gcc", .opt = "--optimize=2"},
    {.r = {.name = "pass_opt_O1_gcc", .kind = "body_extern",
           .detail = "t0_f passes 8, not 7, to a noinline static; gcc at -O1",
           .files = SFZ_FILES(k_f10_opt_spelling)},
     .cc_before = "gcc", .cc_after = "gcc"},
    {.r = {.name = "pass_opt_O2_gcc", .kind = "body_extern",
           .detail = "t0_f passes 8, not 7, to a noinline static; gcc at -O2",
           .files = SFZ_FILES(k_f10_opt_spelling)},
     .cc_before = "gcc", .cc_after = "gcc", .opt = "-O2"},
    {.r = {.name = "F10_opt_spelling_O5", .kind = "body_extern",
           .detail = "t0_a passes 8, not 7, to an external noinline t0_w; "
                     "gcc at -O5 (fixed by 3eb2f44f3a, as "
                     "F10_opt_spelling_O02)",
           .files = SFZ_FILES(k_f10_extern_clone)},
     .cc_before = "gcc", .cc_after = "gcc", .opt = "-O5"},
    {.r = {.name = "pass_extern_clone_O3", .kind = "body_extern",
           .detail = "t0_a passes 8, not 7, to an external noinline t0_w; "
                     "gcc at -O3",
           .files = SFZ_FILES(k_f10_extern_clone)},
     .cc_before = "gcc", .cc_after = "gcc", .opt = "-O3"},
    {.r = {.name = "F11_hot_icf", .kind = "body_static",
           .detail = "t0_p's body becomes t0_q's; objects at gcc -O2, the "
                     "sensor told -Og",
           .known_red = "a facts rule that senses each TU with its object's"
                        " own argv: a sensor deliberately handed other"
                        " optimizer flags than the compile (OPT"
                        " COMPILE/SENSOR) models the wrong codegen no matter"
                        " what the real Makefile rule passes; ff12233071"
                        " (F9) fixed the real rule's own drift, not a"
                        " sensor forced away from it",
           .files = SFZ_FILES(k_f11_hot_icf),
           .known_red_why = "src/t0.c t0_q alias-of-t0_p ALIAS-NOT-COVERED\n"
                            "src/t0.c t0_eq NOT-COVERED\n"},
     .cc_before = "gcc", .cc_after = "gcc", .opt = "-O2/-Og"},
    {.r = {.name = "pass_hot_icf_O2", .kind = "body_static",
           .detail = "t0_p's body becomes t0_q's; objects and sensor at gcc "
                     "-O2",
           .files = SFZ_FILES(k_f11_hot_icf)},
     .cc_before = "gcc", .cc_after = "gcc", .opt = "-O2"},
    {.r = {.name = "F12_header_static_inline_O0", .kind = "header_inline",
           .detail = "the body of a header static inline t0_a calls; clang "
                     "at -O0 emits it out of line (fixed by e1497f368f: a "
                     "TU's own copy of another file's internal function "
                     "seeds like a main-file function and is a root of "
                     "its TU)",
           .files = SFZ_FILES(k_f12_header_static_inline)},
     .opt = "-O0"},
    {.r = {.name = "F12_header_static_inline_O0_gcc", .kind = "header_inline",
           .detail = "the body of a header static inline t0_a calls; gcc "
                     "at -O0 emits it out of line (fixed by e1497f368f, as "
                     "F12_header_static_inline_O0)",
           .files = SFZ_FILES(k_f12_header_static_inline)},
     .cc_before = "gcc", .cc_after = "gcc", .opt = "-O0"},
    {.r = {.name = "pass_header_static_inline_O1", .kind = "header_inline",
           .detail = "the body of a header static inline t0_a calls; "
                     "inlined at -O1",
           .files = SFZ_FILES(k_f12_header_static_inline)},
     .cc_before = "gcc", .cc_after = "gcc"},
    /* Decoy optimizer spellings: the compile is at the level of its real
     * -O flag while the argv also carries "-O0" or "-O1" in a position
     * that is no optimizer flag (a macro value, an include directory, a
     * linker option), some of them last. A reader of the argv that takes
     * the last "-O" substring for the level sees -O0 and models no clone
     * of t0_s, which gcc at -O2 emits as t0_s.constprop.0. Each must plan
     * as the real level does (pass_opt_O2_gcc, pass_opt_O1_gcc). */
    {.r = {.name = "pass_opt_decoy_define", .kind = "body_extern",
           .detail = "t0_f passes 8, not 7, to a noinline static; gcc at "
                     "-O2 then -DMODE=-O0",
           .files = SFZ_FILES(k_f10_opt_spelling)},
     .cc_before = "gcc", .cc_after = "gcc", .opt = "-O2,-DMODE=-O0"},
    {.r = {.name = "pass_opt_decoy_include_dir", .kind = "body_extern",
           .detail = "t0_f passes 8, not 7, to a noinline static; gcc at "
                     "-O2 then -Ix-O0",
           .files = SFZ_FILES(k_f10_opt_spelling)},
     .cc_before = "gcc", .cc_after = "gcc", .opt = "-O2,-Ix-O0"},
    {.r = {.name = "pass_opt_decoy_define_last", .kind = "body_extern",
           .detail = "t0_f passes 8, not 7, to a noinline static; gcc at "
                     "-O2, CFLAGS_EXTRA -DLVL=-O0 last",
           .files = SFZ_FILES(k_decoy_define_last)},
     .cc_before = "gcc", .cc_after = "gcc", .opt = "-O2"},
    {.r = {.name = "pass_opt_decoy_linker_last", .kind = "body_extern",
           .detail = "t0_f passes 8, not 7, to a noinline static; gcc at "
                     "-O2, CFLAGS_EXTRA -Wl,-O0 last",
           .files = SFZ_FILES(k_decoy_linker_last)},
     .cc_before = "gcc", .cc_after = "gcc", .opt = "-O2"},
    {.r = {.name = "pass_opt_decoy_xlinker_O0", .kind = "body_extern",
           .detail = "t0_f passes 8, not 7, to a noinline static; gcc at "
                     "-O0 then -Xlinker -O1",
           .files = SFZ_FILES(k_f10_opt_spelling)},
     .cc_before = "gcc", .cc_after = "gcc", .opt = "-O0,-Xlinker,-O1"},
    {.r = {.name = "pass_opt_decoy_clang_define_last", .kind = "body_extern",
           .detail = "t0_f passes 8, not 7, to a noinline static; clang at "
                     "-O2, CFLAGS_EXTRA -DLVL=-O0 last",
           .files = SFZ_FILES(k_decoy_define_last)},
     .opt = "-O2"},
    /* The real level flips between the sides while the decoy stays last
     * and unchanged: the after side must plan at its own level. */
    {.r = {.name = "pass_opt_decoy_flip_up", .kind = "body_extern",
           .detail = "t0_f passes 8, not 7, to a noinline static; gcc -O0 "
                     "before, -O2 after, CFLAGS_EXTRA -DLVL=-O0 last",
           .files = SFZ_FILES(k_decoy_define_last)},
     .cc_before = "gcc", .cc_after = "gcc", .opt = "-O0>-O2"},
    {.r = {.name = "pass_opt_decoy_flip_down", .kind = "body_extern",
           .detail = "t0_f passes 8, not 7, to a noinline static; gcc -O2 "
                     "before, -O0 after, CFLAGS_EXTRA -DLVL=-O0 last",
           .files = SFZ_FILES(k_decoy_define_last)},
     .cc_before = "gcc", .cc_after = "gcc", .opt = "-O2>-O0"},
    /* search-dir deltas: the argv's search dirs alone drift */
    {.r = {.name = "SD1_isystem_inert", .kind = "sdir_inert",
           .detail = "-isystem sysx is added and shadows nothing; t0's body "
                     "changes: only t0 is affected",
           .files = SFZ_FILES(k_sd1_isystem_inert), .over_pinned = true,
           .over_want = 0},
     .opt = "-O1>-O1,-isystem,sysx"},
    {.r = {.name = "SD2_I_shadows_quoted", .kind = "sdir_shadow",
           .detail = "-Ishad is added and shadows inc1/qx.h for t0's quoted "
                     "include; t2 is edited: t0 and t2 are affected",
           .files = SFZ_FILES(k_sd2_shadow_quoted), .over_pinned = true,
           .over_want = 0},
     .opt = "-O1>-O1,-Ishad"},
    {.r = {.name = "SD3_dir_satisfies_probe", .kind = "sdir_shadow",
           .detail = "-Iextra is added and satisfies t0's false "
                     "__has_include(<px.h>); t2 is edited: t0 and t2 are "
                     "affected",
           .files = SFZ_FILES(k_sd3_probe_satisfied), .over_pinned = true,
           .over_want = 0},
     .opt = "-O1>-O1,-Iextra"},
    {.r = {.name = "SD4_I_pair_reordered", .kind = "sdir_shadow",
           .detail = "-Ira -Irb becomes -Irb -Ira, both holding t0's rh.h; "
                     "t2 is edited: t0 and t2 are affected",
           .files = SFZ_FILES(k_sd4_pair_reordered), .over_pinned = true,
           .over_want = 0},
     .opt = "-O1,-Ira,-Irb>-O1,-Irb,-Ira"},
    {.r = {.name = "SD5_dir_removed", .kind = "sdir_shadow",
           .detail = "-Iold, which t0's <rm.h> resolved through, is dropped; "
                     "t2 is edited: t0 and t2 are affected",
           .files = SFZ_FILES(k_sd5_dir_removed), .over_pinned = true,
           .over_want = 0},
     .opt = "-O1,-Iold>-O1"},
    {.r = {.name = "SD6_system_header_widens", .kind = "sdir_inert",
           .detail = "-isystem sysx is added; t1 reads <stddef.h>, whose own "
                     "lookups no manifest records, so t1 widens (pinned "
                     "over-selection 1)",
           .files = SFZ_FILES(k_sd6_system_header), .over_pinned = true,
           .over_want = 1},
     .opt = "-O1>-O1,-isystem,sysx"},
};
const size_t k_sfz_ntool_repros =
    sizeof(k_sfz_tool_repros) / sizeof(k_sfz_tool_repros[0]);

static bool write_side(const struct sfz_repro *r, const char *dir, bool after)
{
    for (size_t k = 0; k < r->nfiles; k++) {
        const struct sfz_file *f = &r->files[k];
        const char *text = after && f->after != SFZ_SAME ? f->after : f->before;
        size_t mark = strlen(SFZ_LINK_MARK);
        bool link = text != NULL && strncmp(text, SFZ_LINK_MARK, mark) == 0;
        if (link && !sfz_symlink(dir, f->path, text + mark))
            LOG_FAIL("sfz", "%s: cannot link %s/%s", r->name, dir, f->path);
        if (text != NULL && !link && !sfz_put(dir, f->path, text, strlen(text)))
            LOG_FAIL("sfz", "%s: cannot write %s/%s", r->name, dir, f->path);
    }
    /* keep both -I dirs present, as the generator does */
    return sfz_put(dir, "inc1/.keep", "keep\n", 5) &&
           sfz_put(dir, "inc2/.keep", "keep\n", 5);
}

bool sfz_write_repro(const struct sfz_repro *r, const char *dir)
{
    char side[4096];
    if (snprintf(side, sizeof(side), "%s/before", dir) >= (int)sizeof(side))
        LOG_FAIL("sfz", "path too long: %s", dir);
    if (!write_side(r, side, false))
        return false;
    (void)snprintf(side, sizeof(side), "%s/after", dir);
    return write_side(r, side, true);
}
