/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Render the semantic-facts fuzz generator's project text: each header's macros, types and inline functions, and each TU's function templates. */
#include "semantic_fuzz_gen_priv.h"

#include <stdio.h>

const char *const k_sfz_types[6] = {"int",      "long",      "short",
                                    "unsigned", "long long", "signed char"};

/* ---- headers --------------------------------------------------------------- */

static void hdr_macros(const struct sfz_model *m, int k, const struct sfz_hdr *h,
                       struct sfz_buf *b)
{
    sfz_bp(b, "#define H%d_A %d%s\n", k, h->A, h->comment == 5 ? "   " : "");
    sfz_bp(b, "#define H%d_B (H%d_A + %d)\n", k, k, h->Bplus);
    sfz_bp(b, "#define H%d_F(x) ((x) * H%d_B + %d%s)\n", k, k, h->Fadd,
           h->comment == 4 ? " /* scaled */" : "");
    sfz_bp(b, "#define H%d_G(x) _Generic((x), int: 11, long: 22, short: 33, "
              "unsigned: 44, long long: 55, default: 66)\n", k);
    if (h->opt_defined)
        sfz_bp(b, "#define H%d_OPT 1\n", k);
    sfz_bp(b, "#ifdef H%d_OPT\n#define H%d_C %d\n#else\n#define H%d_C %d\n#endif\n",
           k, k, h->C_opt, k, h->C_else);
    sfz_bp(b, "#if H%d_A > %d\n#define H%d_D 100\n#elif defined(PROJ_MODE)\n"
              "#define H%d_D 150\n#else\n#define H%d_D 200\n#endif\n",
           k, h->D_thr, k, k, k);
    if (m->noctr)
        sfz_bp(b, "#define H%d_CTR (%d)\n", k, h->ctr_add);
    else if (h->ctr_macro_n == 2)
        sfz_bp(b, "#define H%d_CTR (__COUNTER__ * 0 + __COUNTER__ + %d)\n", k,
               h->ctr_add);
    else
        sfz_bp(b, "#define H%d_CTR (__COUNTER__ + %d)\n", k, h->ctr_add);
    if (h->inc_prev)
        sfz_bp(b, "#if H%d_A > %d\n#define H%d_X 1000\n#else\n#define H%d_X 2000\n#endif\n",
               k - 1, h->X_thr, k, k);
    else
        sfz_bp(b, "#define H%d_X 3000\n", k);
    if (h->new_lim)
        sfz_bp(b, "#define T_LIM %d\n", h->new_lim);
}

static void hdr_types(int k, const struct sfz_hdr *h, struct sfz_buf *b)
{
    sfz_bp(b, "typedef %s h%d_i0;\ntypedef h%d_i0 h%d_i1;\ntypedef h%d_i1 h%d_i2;\n",
           k_sfz_types[h->i0type], k, k, k, k, k);
    sfz_bp(b, "enum h%d_e { H%d_E0 = %d, H%d_E1, H%d_E2 = %d };\n", k, k, h->E0, k,
           k, h->E2);
    sfz_bp(b, "typedef struct h%d_s {\n", k);
    if (h->swap_fields)
        sfz_bp(b, "    enum h%d_e e;\n    h%d_i1 a;\n", k, k);
    else
        sfz_bp(b, "    h%d_i1 a;\n    enum h%d_e e;\n", k, k);
    if (h->has_union)
        sfz_bp(b, "    union { int u; float f; };\n");
    sfz_bp(b, "    struct { char c; %s s; } in;\n", k_sfz_types[h->in_type]);
    if (h->has_anon)
        sfz_bp(b, "    struct { int p; int q; };\n");
    if (h->extra_field)
        sfz_bp(b, "    long extra;\n");
    sfz_bp(b, "} h%d_s;\n", k);
    sfz_bp(b, "#define H%d_SZ (sizeof(h%d_s) + alignof(h%d_s))\n", k, k, k);
    sfz_bp(b, "typedef int (*h%d_cb)(int);\n", k);
    sfz_bp(b, "extern int h%d_var;\nextern const int h%d_cvar;\n", k, k);
    sfz_bp(b, "%s h%d_fn(int x);\n", h->fn_long ? "long" : "int", k);
    sfz_bp(b, "int h%d_fn2(%s x);\n", k, k_sfz_types[h->fn2_param]);
}

static void hdr_inlines(int k, const struct sfz_hdr *h, struct sfz_buf *b)
{
    if (h->comment == 3)
        sfz_bp(b, "\n\n");
    sfz_bp(b, "static inline int h%d_inl(int x)\n{\n", k);
    if (h->comment == 2)
        sfz_bp(b, "    /* inline body comment */\n");
    sfz_bp(b, "    return H%d_F(x) + (int)sizeof(h%d_s) + H%d_C + %d", k, k, k,
           h->inl_add);
    for (int c = 0; c < h->inl_ctr; c++)
        sfz_bp(b, " + 0 * __COUNTER__");
    sfz_bp(b, ";\n}\n");
    sfz_bp(b, "static inline h%d_i2 h%d_inl2(const h%d_s *s)\n{\n"
              "    return (h%d_i2)(s->a + s->in.s + s->in.c + %d);\n}\n",
           k, k, k, k, h->inl2_add);
}

static void hdr_tail(const struct sfz_model *m, int k, const struct sfz_hdr *h,
                     struct sfz_buf *b)
{
    if (h->opt_file && h->opt_inc)
        sfz_bp(b, "#if __has_include(\"h%d_opt.h\")\n#include \"h%d_opt.h\"\n#endif\n",
               k, k);
    sfz_bp(b, "#if __has_include(\"h%d_opt.h\")\n#define H%d_HAS 1\n#else\n#define H%d_HAS 0\n#endif\n",
           k, k, k);
    sfz_bp(b, "static inline int h%d_gi(int x)\n{\n    return x + 1;\n}\n"
              "static inline int h%d_gl(long x)\n{\n    return (int)x + 2;\n}\n",
           k, k);
    sfz_bp(b, "#define H%d_GC(v) _Generic((v), long: h%d_gl, long long: h%d_gl, default: h%d_gi)(v)\n",
           k, k, k, k);
    sfz_bp(b, "constexpr int h%d_K = %d;\n", k, h->K);
    sfz_bp(b, "static int h%d_st;\n", k);
    sfz_bp(b, "static const int h%d_tab[3] = {1, %d, 3};\n", k, h->tab1);
    if (!m->noline)
        sfz_bp(b, "static inline int h%d_here(void)\n{\n    return __LINE__;\n}\n", k);
    sfz_bp(b, "static_assert(sizeof(h%d_s) >= %d, \"h%d_s is too small\");\n", k,
           h->sa_min, k);
}

/* ---- the data layer (the data_* kinds) --------------------------------------- */

/* An index macro, a static const table read at a runtime index, and a
 * global array its owner defines. */
static void hdr_data(int k, const struct sfz_hdr *h, struct sfz_buf *b)
{
    sfz_bp(b, "#define H%d_IDX %d\n", k, h->idx);
    sfz_bp(b, "static const int h%d_dtab[4] = {1, %d, 3, 4};\n", k, h->dtab1);
    sfz_bp(b, "extern int h%d_garr[4];\n", k);
}

/* Two string literals (the second moves when the first grows), a static
 * const table, and a reader of its first header's data. */
static void tu_data(const struct sfz_model *m, int i, struct sfz_buf *b)
{
    const struct sfz_tu *t = &m->t[i];
    int k = -1;
    sfz_bp(b, "const char *t%d_str(void)\n{\n    return \"s%d-%d%.*s\";\n}\n",
           i, i, t->str_n, t->str_pad, "xxxxxxxxxxxxxxxx");
    sfz_bp(b, "const char *t%d_str2(void)\n{\n    return \"tail%d\";\n}\n", i, i);
    sfz_bp(b, "static const int t%d_dt[4] = {%d, %d, %d, %d};\n"
              "int t%d_dtab(int x)\n{\n    return t%d_dt[x & 3];\n}\n",
           i, t->dt[0], t->dt[1], t->dt[2], t->dt[3], i, i);
    for (int q = 0; k < 0 && q < m->nh; q++)
        k = t->inc[q] ? q : -1;
    if (k >= 0)
        sfz_bp(b, "int t%d_hd(int x)\n{\n    return h%d_dtab[x & 3] + "
                  "h%d_garr[H%d_IDX];\n}\n",
               i, k, k, k);
    for (int q = 0; q < m->nh; q++)
        if (m->h[q].owner == i)
            sfz_bp(b, "int h%d_garr[4] = {5, 6, 7, 8};\n", q);
    sfz_bp(b, "\n");
}

/* ---- the path layer (the path kinds) ----------------------------------------- */

void sfz_emb_path(char *out, size_t cap, int place, const char *stem)
{
    static const char *const fmt[3] = {"data/%s.bin", "docs/%s.txt", "res/%s.md"};
    (void)snprintf(out, cap, fmt[place % 3], stem);
}

/* The spelled path of header k's text as its readers see it. */
static void hdr_where(int k, struct sfz_buf *b)
{
    sfz_bp(b, "static inline const char *h%d_where(void)\n{\n    return __FILE__;\n}\n"
              "static inline const char *h%d_base(void)\n{\n"
              "    return __FILE_NAME__;\n}\n",
           k, k);
}

static void tu_path_includes(const struct sfz_tu *t, struct sfz_buf *b)
{
    static const char *const order[5][2] = {
        {NULL, NULL}, {"pz.h", NULL}, {"pa.h", NULL}, {"pz.h", "pa.h"},
        {"pa.h", "pz.h"}};
    for (int q = 0; q < 2; q++)
        if (t->pz > 0 && t->pz < 5 && order[t->pz][q] != NULL)
            sfz_bp(b, "#include \"%s\"\n", order[t->pz][q]);
    if (t->sel)
        sfz_bp(b, "#include \"sel.h\"\n#include SEL_HDR\n");
    if (t->hm)
        sfz_bp(b, "#include \"hm_cfg.h\"\n");
}

static void tu_embed(const struct sfz_model *m, int i, struct sfz_buf *b)
{
    char stem[16], path[64];
    (void)snprintf(stem, sizeof(stem), "e%d", m->t[i].emb - 1);
    sfz_emb_path(path, sizeof(path), m->p.emb_place, stem);
    sfz_bp(b, "static const unsigned char t%d_emb[] = {\n#embed \"../%s\"\n};\n"
              "int t%d_embv(int x)\n{\n"
              "    return t%d_emb[(unsigned)x %% sizeof t%d_emb] + "
              "(int)sizeof t%d_emb;\n}\n",
           i, path, i, i, i, i);
}

static void tu_has_embed(const struct sfz_model *m, int i, struct sfz_buf *b)
{
    char path[64];
    sfz_emb_path(path, sizeof(path), m->p.hemb_place, "probe");
    if (m->t[i].hemb == 1) {
        sfz_bp(b, "#if __has_embed(\"../%s\")\n#define T%d_HE 1\n#else\n"
                  "#define T%d_HE 0\n#endif\n"
                  "int t%d_hev(int x)\n{\n    return x + T%d_HE * 7;\n}\n",
               path, i, i, i, i);
        return;
    }
    sfz_bp(b, "#if __has_embed(\"../%s\")\n"
              "static const unsigned char t%d_he[] = {\n#embed \"../%s\"\n};\n"
              "int t%d_hev(int x)\n{\n    return x + t%d_he[0];\n}\n#else\n"
              "int t%d_hev(int x)\n{\n    return x + 1;\n}\n#endif\n",
           path, i, path, i, i, i);
}

/* TU i's path-layer functions: each reads what its paths resolve to. */
static void tu_path_code(const struct sfz_model *m, int i, struct sfz_buf *b)
{
    const struct sfz_tu *t = &m->t[i];
    int w = m->p.where_k;
    if (w >= 0 && t->inc[w])
        sfz_bp(b, "const char *t%d_where(int b)\n{\n"
                  "    return b ? h%d_base() : h%d_where();\n}\n",
               i, w, w);
    if (t->pz)
        sfz_bp(b, "int t%d_pz(void)\n{\n#ifdef PZ_TWICE\n    return PZ_V * 10 + 1;\n"
                  "#else\n    return PZ_V * 10;\n#endif\n}\n",
               i);
    if (t->sel)
        sfz_bp(b, "int t%d_sel(int x)\n{\n    return sel_f(x) + SEL_V;\n}\n", i);
    if (t->emb)
        tu_embed(m, i, b);
    if (t->hemb)
        tu_has_embed(m, i, b);
    if (t->hm)
        sfz_bp(b, "int t%d_hm(int x)\n{\n    return x + HM_HAVE * 5 + HM_OPT_V;\n}\n",
               i);
}

void sfz_render_header(const struct sfz_model *m, int k, const struct sfz_hdr *h,
                       struct sfz_buf *b)
{
    if (h->comment == 1)
        sfz_bp(b, "/* header %d: a leading comment\n   that spans lines */\n", k);
    sfz_bp(b, "#ifndef H%d_H\n#define H%d_H\n", k, k);
    if (h->inc_prev)
        sfz_bp(b, "#include \"h%d.h\"\n", k - 1);
    hdr_macros(m, k, h, b);
    hdr_types(k, h, b);
    hdr_inlines(k, h, b);
    hdr_tail(m, k, h, b);
    if (m->data)
        hdr_data(k, h, b);
    if (m->p.where_k == k)
        hdr_where(k, b);
    sfz_bp(b, "#endif\n");
}

/* ---- templates ------------------------------------------------------------- */

/* One template instance: TU i's template j over header k with constant c. */
struct tx {
    const struct sfz_model *m;
    const struct sfz_tu *t;
    int i, j, k, c;
    const char *bc;  /* a comment in the body, or "" */
    const char *bb;  /* blank lines in the body, or "" */
    const char *sp;  /* the space between return type and name */
    const char *ctr; /* a __COUNTER__ term the body gains, or "" */
};

static void tp_helper(const struct tx *x, struct sfz_buf *b)
{
    sfz_bp(b, "static int helper(int x)\n{\n%s%s    return %sx * %d + 1;\n}\n\n",
           x->bc, x->bb, x->ctr, x->c);
}

static void tp_s1(const struct tx *x, struct sfz_buf *b)
{
    sfz_bp(b, "static int t%d_s1(int x)\n{\n%s%s    return %shelper(x) + %d;\n}\n\n",
           x->i, x->bc, x->bb, x->ctr, x->c);
}

static void tp_e1(const struct tx *x, struct sfz_buf *b)
{
    sfz_bp(b, "int%st%d_e1(int x)\n{\n%s%s    return %st%d_s1(x) * 2 + %d;\n}\n\n",
           x->sp, x->i, x->bc, x->bb, x->ctr, x->i, x->c);
}

static void tp_inl(const struct tx *x, struct sfz_buf *b)
{
    sfz_bp(b, "int%st%d_inl(int x)\n{\n%s%s    return h%d_inl(x) + %d;\n}\n\n",
           x->sp, x->i, x->bc, x->bb, x->k, x->c);
}

static void tp_mac(const struct tx *x, struct sfz_buf *b)
{
    sfz_bp(b, "int%st%d_mac(int x)\n{\n%s%s    return H%d_F(x) + H%d_B + H%d_D + %d;\n}\n\n",
           x->sp, x->i, x->bc, x->bb, x->k, x->k, x->k, x->c);
}

static void tp_gen(const struct tx *x, struct sfz_buf *b)
{
    sfz_bp(b, "int%st%d_gen(void)\n{\n%s%s    h%d_i2 v = %d;\n    return H%d_G(v);\n}\n\n",
           x->sp, x->i, x->bc, x->bb, x->k, x->c, x->k);
}

static void tp_lay(const struct tx *x, struct sfz_buf *b)
{
    sfz_bp(b, "int%st%d_lay(h%d_s *s)\n{\n%s%s    return (int)s->a + s->in.c + "
              "(int)sizeof(*s) + (int)offsetof(h%d_s, in) + %d;\n}\n\n",
           x->sp, x->i, x->k, x->bc, x->bb, x->k, x->c);
}

static void tp_enum(const struct tx *x, struct sfz_buf *b)
{
    sfz_bp(b, "int%st%d_enum(enum h%d_e e)\n{\n%s%s    switch (e) {\n    case H%d_E0:\n"
              "        return %d;\n    case H%d_E2:\n        return 2;\n"
              "    default:\n        return 3;\n    }\n}\n\n",
           x->sp, x->i, x->k, x->bc, x->bb, x->k, x->c, x->k);
}

static void tp_ptr(const struct tx *x, struct sfz_buf *b)
{
    sfz_bp(b, "static int (*const t%d_tbl[])(int) = {helper, t%d_s1};\n"
              "int%st%d_ptr(int i, int x)\n{\n%s%s    return t%d_tbl[i & 1](x) + %d;\n}\n\n",
           x->i, x->i, x->sp, x->i, x->bc, x->bb, x->i, x->c);
}

static void tp_weak(const struct tx *x, struct sfz_buf *b)
{
    sfz_bp(b, "__attribute__((weak)) int t%d_w(int x)\n{\n%s%s    return x + %d;\n}\n\n",
           x->i, x->bc, x->bb, x->c);
}

static void tp_ctor(const struct tx *x, struct sfz_buf *b)
{
    sfz_bp(b, "static int t%d_state;\n__attribute__((constructor)) static void "
              "t%d_ctor(void)\n{\n%s%s    t%d_state = H%d_E1 + %d;\n}\n"
              "int t%d_state_get(void)\n{\n    return t%d_state;\n}\n\n",
           x->i, x->i, x->bc, x->bb, x->i, x->k, x->c, x->i, x->i);
}

static void tp_line(const struct tx *x, struct sfz_buf *b)
{
    sfz_bp(b, "int%st%d_line(void)\n{\n%s%s    return %s%s%d;\n}\n\n", x->sp, x->i,
           x->bc, x->bb, x->m->noline ? "" : "__LINE__ * 100 + ",
           x->m->noctr ? "" : "__COUNTER__ + ", x->c);
}

static void tp_sz(const struct tx *x, struct sfz_buf *b)
{
    sfz_bp(b, "static const unsigned long t%d_sz = H%d_SZ;\n"
              "static_assert(H%d_SZ > 0, \"size\");\n"
              "int%st%d_sz_get(void)\n{\n%s%s    return (int)t%d_sz + %d;\n}\n\n",
           x->i, x->k, x->k, x->sp, x->i, x->bc, x->bb, x->i, x->c);
}

static void tp_typeof(const struct tx *x, struct sfz_buf *b)
{
    sfz_bp(b, "typeof(h%d_var) t%d_tv(void)\n{\n%s%s    return h%d_var + %d;\n}\n\n",
           x->k, x->i, x->bc, x->bb, x->k, x->c);
}

static void tp_cross(const struct tx *x, struct sfz_buf *b)
{
    sfz_bp(b, "int t%d_e1(int x);\nint%st%d_cross(int x)\n{\n%s%s    return t%d_e1(x) + %d;\n}\n\n",
           x->t->cross, x->sp, x->i, x->bc, x->bb, x->t->cross, x->c);
}

static void tp_cond(const struct tx *x, struct sfz_buf *b)
{
    sfz_bp(b, "#if H%d_A > %d\n#define T%d_M %d\n#else\n#define T%d_M %d\n#endif\n"
              "int%st%d_cond(void)\n{\n%s%s    return T%d_M;\n}\n\n",
           x->k, x->t->m_thr, x->i, x->c, x->i, x->c + 7, x->sp, x->i, x->bc,
           x->bb, x->i);
}

static void tp_hfn(const struct tx *x, struct sfz_buf *b)
{
    sfz_bp(b, "int%st%d_hfn(int x)\n{\n%s%s    return (int)h%d_fn(x) + %d;\n}\n\n",
           x->sp, x->i, x->bc, x->bb, x->k, x->c);
}

static void tp_s2(const struct tx *x, struct sfz_buf *b)
{
    sfz_bp(b, "static int t%d_s2(int x)\n{\n%s%s    return t%d_s1(x) + H%d_C + %d;\n}\n"
              "int t%d_e2(int x)\n{\n    return t%d_s2(x) - 1;\n}\n\n",
           x->i, x->bc, x->bb, x->i, x->k, x->c, x->i, x->i);
}

static void tp_opt(const struct tx *x, struct sfz_buf *b)
{
    sfz_bp(b, "int%st%d_opt(void)\n{\n%s%s#ifdef H%d_OPT\n    return %d;\n#else\n"
              "    return %d;\n#endif\n}\n\n",
           x->sp, x->i, x->bc, x->bb, x->k, x->c, x->c + 3);
}

static void tp_ctr(const struct tx *x, struct sfz_buf *b)
{
    sfz_bp(b, "int%st%d_ctr(void)\n{\n%s%s    return H%d_CTR + %d;\n}\n\n", x->sp,
           x->i, x->bc, x->bb, x->k, x->c);
}

static void tp_inl2(const struct tx *x, struct sfz_buf *b)
{
    sfz_bp(b, "int%st%d_inl2(void)\n{\n%s%s    h%d_s s = {0};\n    s.a = %d;\n"
              "    return (int)h%d_inl2(&s);\n}\n\n",
           x->sp, x->i, x->bc, x->bb, x->k, x->c, x->k);
}

static void tp_fn2(const struct tx *x, struct sfz_buf *b)
{
    sfz_bp(b, "int%st%d_fn2(void)\n{\n%s%s    return h%d_fn2(%d);\n}\n\n", x->sp,
           x->i, x->bc, x->bb, x->k, x->c);
}

static void tp_sv(const struct tx *x, struct sfz_buf *b)
{
    sfz_bp(b, "static int t%d_sv = %d;\nint%st%d_svget(void)\n{\n%s%s    return t%d_sv++;\n}\n\n",
           x->i, x->c, x->sp, x->i, x->bc, x->bb, x->i);
}

static void tp_dcond(const struct tx *x, struct sfz_buf *b)
{
    sfz_bp(b, "#if H%d_D == 100\nstatic const int t%d_dv = %d;\n#else\n"
              "static const int t%d_dv = %d;\n#endif\n"
              "int%st%d_dcond(void)\n{\n%s%s    return t%d_dv;\n}\n\n",
           x->k, x->i, x->c, x->i, x->c + 1, x->sp, x->i, x->bc, x->bb, x->i);
}

static void tp_cvar(const struct tx *x, struct sfz_buf *b)
{
    sfz_bp(b, "int%st%d_cvar(void)\n{\n%s%s    return h%d_cvar + h%d_var + %d;\n}\n\n",
           x->sp, x->i, x->bc, x->bb, x->k, x->k, x->c);
}

static void tp_align(const struct tx *x, struct sfz_buf *b)
{
    sfz_bp(b, "static _Alignas(h%d_s) unsigned char t%d_pool[4 * sizeof(h%d_s)];\n"
              "int%st%d_align(void)\n{\n%s%s    return (int)sizeof(t%d_pool) + %d;\n}\n\n",
           x->k, x->i, x->k, x->sp, x->i, x->bc, x->bb, x->i, x->c);
}

static void tp_f(const struct tx *x, struct sfz_buf *b)
{
    sfz_bp(b, "int%st%d_f(int x)\n{\n%s%s    return H%d_F(x) + %d;\n}\n\n", x->sp,
           x->i, x->bc, x->bb, x->k, x->c);
}

static void tp_d(const struct tx *x, struct sfz_buf *b)
{
    sfz_bp(b, "int%st%d_d(void)\n{\n%s%s    return H%d_D + %d;\n}\n\n", x->sp, x->i,
           x->bc, x->bb, x->k, x->c);
}

static void tp_here(const struct tx *x, struct sfz_buf *b)
{
    if (!x->m->noline)
        sfz_bp(b, "int%st%d_here(void)\n{\n%s%s    return h%d_here() + %d;\n}\n\n",
               x->sp, x->i, x->bc, x->bb, x->k, x->c);
}

static void tp_gv(const struct tx *x, struct sfz_buf *b)
{
    sfz_bp(b, "static int t%d_gv;\nvoid t%d_gset(void)\n{\n%s%s    t%d_gv = %d;\n}\n"
              "int t%d_gget(void)\n{\n    return t%d_gv;\n}\n\n",
           x->i, x->i, x->bc, x->bb, x->i, x->c, x->i, x->i);
}

static void tp_util(const struct tx *x, struct sfz_buf *b)
{
    if (x->m->util_owner == x->i)
        sfz_bp(b, "int util(int x)\n{\n%s%s    return x + %d;\n}\n", x->bc, x->bb,
               x->c);
    else
        sfz_bp(b, "static int util(int x)\n{\n%s%s    return x - %d;\n}\n", x->bc,
               x->bb, x->c);
    sfz_bp(b, "int t%d_util(int x)\n{\n    return util(x) * 3;\n}\n\n", x->i);
}

static void tp_xd(const struct tx *x, struct sfz_buf *b)
{
    sfz_bp(b, "int%st%d_xd(void)\n{\n%s%s    return H%d_X + %d;\n}\n\n", x->sp,
           x->i, x->bc, x->bb, x->k, x->c);
}

static void tp_tab(const struct tx *x, struct sfz_buf *b)
{
    sfz_bp(b, "int%st%d_tab(void)\n{\n%s%s    return h%d_tab[1] + %d;\n}\n\n", x->sp,
           x->i, x->bc, x->bb, x->k, x->c);
}

static void tp_lim(const struct tx *x, struct sfz_buf *b)
{
    sfz_bp(b, "#ifndef T_LIM\n#define T_LIM %d\n#endif\nint%st%d_lim(void)\n{\n%s%s"
              "    return T_LIM + 1;\n}\n\n",
           x->c, x->sp, x->i, x->bc, x->bb);
}

static void tp_clean(const struct tx *x, struct sfz_buf *b)
{
    sfz_bp(b, "int t%d_sink;\nstatic void t%d_rel(int *p)\n{\n%s%s    t%d_sink = *p + %d;\n}\n"
              "int%st%d_cl(int x)\n{\n    __attribute__((cleanup(t%d_rel))) int v = x * 2;\n"
              "    return v + 3;\n}\n\n",
           x->i, x->i, x->bc, x->bb, x->i, x->c, x->sp, x->i, x->i);
}

static void tp_hst(const struct tx *x, struct sfz_buf *b)
{
    sfz_bp(b, "void t%d_hset(void)\n{\n%s%s    h%d_st = %d;\n}\nint t%d_hget(void)\n{\n"
              "    return h%d_st;\n}\n\n",
           x->i, x->bc, x->bb, x->k, x->c, x->i, x->k);
}

static void tp_alias(const struct tx *x, struct sfz_buf *b)
{
    sfz_bp(b, "int t%d_impl(int x)\n{\n%s%s    return x * %d + 1;\n}\n"
              "int t%d_alias(int x) __attribute__((alias(\"t%d_impl\")));\n\n",
           x->i, x->bc, x->bb, x->c, x->i, x->i);
}

/* A caller of the first other TU's alias. */
static void tp_ualias(const struct tx *x, struct sfz_buf *b)
{
    for (int o = 0; o < x->m->nt; o++) {
        if (o == x->i || !x->m->t[o].on[T_ALIAS])
            continue;
        sfz_bp(b, "int t%d_alias(int x);\nint%st%d_ua(int x)\n{\n%s%s    return t%d_alias(x) + %d;\n}\n\n",
               o, x->sp, x->i, x->bc, x->bb, o, x->c);
        return;
    }
}

static void tp_has(const struct tx *x, struct sfz_buf *b)
{
    sfz_bp(b, "int%st%d_has(void)\n{\n%s%s    return H%d_HAS + %d;\n}\n\n", x->sp,
           x->i, x->bc, x->bb, x->k, x->c);
}

static void tp_gc(const struct tx *x, struct sfz_buf *b)
{
    sfz_bp(b, "int%st%d_gc(void)\n{\n%s%s    h%d_i2 v = %d;\n    return H%d_GC(v);\n}\n\n",
           x->sp, x->i, x->bc, x->bb, x->k, x->c, x->k);
}

static void tp_k(const struct tx *x, struct sfz_buf *b)
{
    sfz_bp(b, "int%st%d_kk(void)\n{\n%s%s    static int a[h%d_K + 1];\n"
              "    return (int)sizeof a + h%d_K * %d;\n}\n\n",
           x->sp, x->i, x->bc, x->bb, x->k, x->k, x->c);
}

static void tp_kc(const struct tx *x, struct sfz_buf *b)
{
    sfz_bp(b, "static int t%d_k(int a)\n{\n    return a * 3 + 7;\n}\n"
              "int%st%d_kc(void)\n{\n%s%s    return t%d_k(%d);\n}\n"
              "int t%d_kd(int x)\n{\n    return t%d_k(x) + 1;\n}\n\n",
           x->i, x->sp, x->i, x->bc, x->bb, x->i, x->c, x->i, x->i);
}

struct templ_def {
    void (*fn)(const struct tx *x, struct sfz_buf *b);
    bool needs_hdr; /* skipped when the TU includes no header */
    bool ctr;       /* the body can gain a __COUNTER__ term (counter_c) */
};

static const struct templ_def k_templ[SFZ_NTEMPL] = {
    [T_HELPER] = {tp_helper, false, true}, [T_S1] = {tp_s1, false, true},
    [T_E1] = {tp_e1, false, true},         [T_INL] = {tp_inl, true, false},
    [T_MAC] = {tp_mac, true, false},       [T_GEN] = {tp_gen, true, false},
    [T_LAY] = {tp_lay, true, false},       [T_ENUM] = {tp_enum, true, false},
    [T_PTR] = {tp_ptr, false, false},      [T_WEAK] = {tp_weak, false, false},
    [T_CTOR] = {tp_ctor, true, false},     [T_LINE] = {tp_line, false, false},
    [T_SZ] = {tp_sz, true, false},         [T_TYPEOF] = {tp_typeof, true, false},
    [T_CROSS] = {tp_cross, false, false},  [T_COND] = {tp_cond, true, false},
    [T_HFN] = {tp_hfn, true, false},       [T_S2] = {tp_s2, true, false},
    [T_OPT] = {tp_opt, true, false},       [T_CTR] = {tp_ctr, true, false},
    [T_INL2] = {tp_inl2, true, false},     [T_FN2] = {tp_fn2, true, false},
    [T_SV] = {tp_sv, false, false},        [T_DCOND] = {tp_dcond, true, false},
    [T_CVAR] = {tp_cvar, true, false},     [T_ALIGN] = {tp_align, true, false},
    [T_F] = {tp_f, true, false},           [T_D] = {tp_d, true, false},
    [T_HERE] = {tp_here, true, false},     [T_GV] = {tp_gv, false, false},
    [T_UTIL] = {tp_util, false, false},    [T_XD] = {tp_xd, true, false},
    [T_TAB] = {tp_tab, true, false},       [T_LIM] = {tp_lim, false, false},
    [T_KC] = {tp_kc, false, false},        [T_ALIAS] = {tp_alias, false, false},
    [T_UALIAS] = {tp_ualias, false, false}, [T_HAS] = {tp_has, true, false},
    [T_GC] = {tp_gc, true, false},         [T_K] = {tp_k, true, false},
    [T_HST] = {tp_hst, true, false},       [T_CLEAN] = {tp_clean, false, false},
};

static void templ(const struct sfz_model *m, int i, int j, struct sfz_buf *b)
{
    const struct sfz_tu *t = &m->t[i];
    bool mine = t->comment_t == j;
    struct tx x = {
        .m = m, .t = t, .i = i, .j = j, .k = t->k[j], .c = t->c[j],
        .bc = mine && t->comment == 1 ? "    /* a comment in the body */\n" : "",
        .bb = mine && t->comment == 5 ? "\n\n" : "",
        .sp = mine && t->comment == 4 ? "  " : " ",
        .ctr = k_templ[j].ctr && t->ctr_j == j ? "0 * __COUNTER__ + " : "",
    };
    if (x.k < 0 && k_templ[j].needs_hdr)
        return;
    k_templ[j].fn(&x, b);
}

static void tu_owned(const struct sfz_model *m, int i, struct sfz_buf *b)
{
    for (int k = 0; k < m->nh; k++) {
        const struct sfz_hdr *h = &m->h[k];
        if (h->owner != i)
            continue;
        sfz_bp(b, "int h%d_var = %d;\nconst int h%d_cvar = %d;\n", k, h->var_init,
               k, h->cvar_init);
        sfz_bp(b, "%s%s h%d_fn(int x)\n{\n    return x + H%d_A + %d;\n}\n",
               h->weak_fn ? "__attribute__((weak)) " : "",
               h->fn_long ? "long" : "int", k, k, h->var_init % 7);
        sfz_bp(b, "int h%d_fn2(%s x)\n{\n    return (int)x * H%d_B;\n}\n\n", k,
               k_sfz_types[h->fn2_param], k);
    }
}

void sfz_render_tu(const struct sfz_model *m, int i, struct sfz_buf *b)
{
    const struct sfz_tu *t = &m->t[i];
    if (t->comment == 2)
        sfz_bp(b, "\n\n\n");
    if (t->comment == 3)
        sfz_bp(b, "/* file-scope comment in t%d */\n", i);
    sfz_bp(b, "#include <stddef.h>\n");
    for (int k = 0; k < m->nh; k++) {
        if (t->inc[k] == 1)
            sfz_bp(b, "#include \"h%d.h\"\n", k);
        else if (t->inc[k] == 2)
            sfz_bp(b, "#include <h%d.h>\n", k);
    }
    tu_path_includes(t, b);
    sfz_bp(b, "\n");
    for (int j = 0; j < SFZ_NTEMPL; j++)
        if (t->on[j])
            templ(m, i, j, b);
    /* each header this TU owns: its function and variable definitions */
    tu_owned(m, i, b);
    if (m->data)
        tu_data(m, i, b);
    tu_path_code(m, i, b);
}
