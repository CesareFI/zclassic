/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Write the semantic facts fixture tree and apply its edits for the C23-side and live-compiler facts tests. */
#include "test/semantic_facts_fixture.h"

#include "base/safe_alloc.h"
#include "base/serialize_le.h"
#include "vcs/semantic_manifest.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static const char k_sft_header[] =
    "#ifndef FX_H\n"
    "#define FX_H\n"
    "#define FX_SCALE 2\n"
    "#define FX_WHERE() (__LINE__ + 0)\n"
    "typedef int fx_num;\n"
    "struct fx_pair { int a; int b; };\n"
    "int fx_helper(int v);\n"
    "int fx_other(int v);\n"
    "int fx_run(int (*cb)(int), int v);\n"
    "#endif\n";

/* fx_helper is called from fx_a.c, fx_other from fx_b.c: a file-seeded
 * closure of fx_core.c reaches both callers, a closure seeded by fx_helper
 * alone reaches only fx_a.c. fx_where expands __LINE__ through FX_WHERE:
 * an edit above it that moves its lines changes its code. */
static const char k_sft_core[] =
    "#include \"fx.h\"\n"
    "static int fx_table[2] = {1, 2};\n"
    "int fx_helper(int v) { return v * FX_SCALE; }\n"
    "int fx_other(int v) { fx_num t = fx_table[0]; return v + t; }\n"
    "int fx_run(int (*cb)(int), int v) { return cb(v); }\n"
    "static int fx_cb(int v) { return v - 1; }\n"
    "int fx_use(void) { return fx_run(fx_cb, 1); }\n"
    "int fx_spin(void) { __asm__ volatile(\"\" ::: \"memory\"); return 0; }\n"
    "int fx_size(void) { return (int)sizeof(struct fx_pair); }\n"
    "int fx_where(void) { return FX_WHERE(); }\n";

static const char k_sft_a[] =
    "#include \"fx.h\"\n"
    "int fx_top_a(void);\n"
    "int fx_top_a(void) { return fx_helper(1); }\n";

static const char k_sft_b[] =
    "#include \"fx.h\"\n"
    "int fx_top_b(void);\n"
    "int fx_top_b(void) { return fx_other(2); }\n";

const char *const k_sft_paths[SFT_FILE_COUNT] = {SFT_HEADER, SFT_CORE,
                                                 SFT_CALLER_A, SFT_CALLER_B};
static const char *const k_sft_bodies[SFT_FILE_COUNT] = {k_sft_header,
                                                         k_sft_core, k_sft_a,
                                                         k_sft_b};

const char *const k_sft_flags[] = {"-std=c23", "-Iengine/modules/fxn/include"};
const size_t k_sft_nflags = sizeof(k_sft_flags) / sizeof(k_sft_flags[0]);

const struct sft_edit k_sft_edits[SFT_VARIANT_COUNT] = {
    [SFT_BASE] = {"base", NULL, NULL, NULL, "", NULL, 0,
                    NULL, NULL, NULL},
    [SFT_BODY] = {"body", SFT_CORE, "return v * FX_SCALE; }",
                  "return v * FX_SCALE + 1; }", "", "fx_helper", 0,
                    NULL, NULL, NULL},
    [SFT_COMMENT] = {"comment", SFT_CORE, "int fx_helper(int v) { return",
                     "\n/* scaled */\nint fx_helper(int v) { /* x2 */ return",
                     "", "fx_where", 0,
                    NULL, NULL, NULL},
    [SFT_LAYOUT] = {"layout", SFT_HEADER, "int a; int b; };",
                    "int a; int b; int c; };", "layout-changed", NULL, 0,
                    NULL, NULL, NULL},
    [SFT_MACRO] = {"macro", SFT_HEADER, "#define FX_SCALE 2",
                   "#define FX_SCALE 3", "macro-changed", NULL, 0,
                    NULL, NULL, NULL},
    [SFT_DECL] = {"decl", SFT_HEADER, "#endif\n",
                  "int fx_new(void);\n#endif\n", "declaration-changed", NULL,
                  0,
                    NULL, NULL, NULL},
    [SFT_INDIRECT] = {"indirect", SFT_CORE, "return cb(v); }",
                      "return cb(v) + 1; }", "unknown-effect", NULL, 0,
                    NULL, NULL, NULL},
    [SFT_ASM] = {"asm", SFT_CORE, "return 0; }\nint fx_size",
                 "return 1; }\nint fx_size", "unknown-effect", NULL, 0,
                    NULL, NULL, NULL},
    [SFT_ADDRESS] = {"address", SFT_CORE, "return v - 1; }",
                     "return v - 2; }", "address-taken", NULL, 0,
                    NULL, NULL, NULL},
    [SFT_SCOPE] = {"scope", SFT_CORE, "{1, 2};", "{1, 3};",
                   "file-scope-changed", NULL, 0,
                    NULL, NULL, NULL},
    [SFT_TYPE] = {"type", SFT_HEADER, "struct fx_pair { int a;",
                  "struct fx_pair { unsigned a;", "layout-changed", NULL, 0,
                    NULL, NULL, NULL},
    [SFT_INCLUDE] = {"include", SFT_CORE, "#include \"fx.h\"\nstatic",
                     "#include <fx.h>\nstatic", "include-resolution-changed",
                     NULL, 0,
                    NULL, NULL, NULL},
    [SFT_SHADOW] = {"shadow", NULL, NULL, NULL, "include-resolution-changed",
                    NULL, 0, SFT_SHADOW_PATH, k_sft_header, NULL},
    [SFT_SEARCH] = {"search", NULL, NULL, NULL, "identity-changed", NULL, 0,
                    NULL, NULL, "-Iengine/modules/fxn"},
    [SFT_CTOR] = {"ctor", SFT_CORE, "int fx_size(void) {",
                  "__attribute__((constructor)) int fx_size(void) {",
                  "function-head-changed", NULL, 0,
                    NULL, NULL, NULL},
    [SFT_WEAK] = {"weak", SFT_CORE, "int fx_helper(int v) {",
                  "__attribute__((weak)) int fx_helper(int v) {",
                  "function-head-changed", NULL, 0,
                    NULL, NULL, NULL},
    [SFT_VISIBILITY] = {"visibility", SFT_CORE, "int fx_use(void) {",
                        "__attribute__((visibility(\"hidden\"))) int "
                        "fx_use(void) {",
                        "function-head-changed", NULL, 0,
                    NULL, NULL, NULL},
    [SFT_C23ATTR] = {"c23attr", SFT_CORE, "int fx_other(int v) {",
                     "[[gnu::cold]] int fx_other(int v) {",
                     "file-scope-changed", NULL, 0,
                    NULL, NULL, NULL},
    [SFT_TYPEDEF] = {"typedef", SFT_HEADER, "typedef int fx_num;",
                     "typedef long fx_num;", "declaration-changed", NULL, 0,
                    NULL, NULL, NULL},
    [SFT_SPACE] = {"space", SFT_CORE,
                   "int fx_run(int (*cb)(int), int v) { return cb(v); }",
                   "int fx_run(int (*cb)(int),\n           int v)\n{\n"
                   "    return  cb(v);\n}\n",
                   "", "fx_where", 0,
                    NULL, NULL, NULL},
    /* No fact changes, but the header's bytes do: an included file is
     * never narrowed through. */
    [SFT_HDRCOMMENT] = {"hdrcomment", SFT_HEADER, "#define FX_SCALE 2",
                        "/* doubling */\n#define FX_SCALE 2",
                        "facts-changed-outside-seeds", NULL, 0,
                    NULL, NULL, NULL},
    /* Differential fuzzing (F2): __COUNTER__ numbers every expansion in
     * the TU, so no body that reaches it can be narrowed to. */
    [SFT_COUNTER] = {"counter", SFT_CORE, "return v + t; }",
                     "return v + t + 0 * __COUNTER__; }",
                     "position-dependent", NULL, 0,
                    NULL, NULL, NULL},
    [SFT_TRUNCATED] = {"truncated", NULL, NULL, NULL, "manifest-truncated",
                       NULL, 2,
                    NULL, NULL, NULL},
};

static char *sft_replace(const char *body, const char *from, const char *to,
                         size_t *len)
{
    const char *at = strstr(body, from);
    size_t head, n;
    char *out;
    if (at == NULL || strstr(at + 1, from) != NULL)
        return NULL; /* the edit must name exactly one place */
    head = (size_t)(at - body);
    n = strlen(body) - strlen(from) + strlen(to);
    out = zcl_malloc(n + 1, "sft.text");
    if (out == NULL)
        return NULL;
    memcpy(out, body, head);
    memcpy(out + head, to, strlen(to));
    strcpy(out + head + strlen(to), at + strlen(from));
    *len = n;
    return out;
}

char *sft_text(enum sft_variant v, const char *path, size_t *len)
{
    const struct sft_edit *e = &k_sft_edits[v];
    if (e->add_path != NULL && strcmp(e->add_path, path) == 0) {
        *len = strlen(e->add_body);
        return zcl_strdup(e->add_body, "sft.text");
    }
    for (size_t k = 0; k < SFT_FILE_COUNT; k++) {
        if (strcmp(k_sft_paths[k], path) != 0)
            continue;
        if (e->file != NULL && strcmp(e->file, path) == 0)
            return sft_replace(k_sft_bodies[k], e->from, e->to, len);
        *len = strlen(k_sft_bodies[k]);
        return zcl_strdup(k_sft_bodies[k], "sft.text");
    }
    return NULL;
}

static bool sft_mkdirs(char *full)
{
    for (char *p = full + 1; *p; p++) {
        if (*p != '/')
            continue;
        *p = '\0';
        if (mkdir(full, 0755) != 0 && access(full, F_OK) != 0) {
            *p = '/';
            return false;
        }
        *p = '/';
    }
    return true;
}

static bool sft_write_one(const char *root, enum sft_variant v,
                          const char *path)
{
    char full[4096];
    size_t n = 0;
    char *body = sft_text(v, path, &n);
    FILE *fp;
    bool ok;
    (void)snprintf(full, sizeof(full), "%s/%s", root, path);
    fp = body != NULL && sft_mkdirs(full) ? fopen(full, "wb") : NULL;
    ok = fp != NULL && fwrite(body, 1, n, fp) == n;
    if (fp != NULL && fclose(fp) != 0)
        ok = false;
    free(body);
    return ok;
}

bool sft_write_tree(const char *root, enum sft_variant v)
{
    const char *add = k_sft_edits[v].add_path;
    for (size_t k = 0; k < SFT_FILE_COUNT; k++)
        if (!sft_write_one(root, v, k_sft_paths[k]))
            return false;
    return add == NULL || sft_write_one(root, v, add);
}

bool sft_read(const char *path, uint8_t **out, size_t *len)
{
    FILE *fp = fopen(path, "rb");
    long size;
    bool ok = false;
    *out = NULL;
    *len = 0;
    if (fp == NULL)
        return false;
    if (fseek(fp, 0, SEEK_END) == 0 && (size = ftell(fp)) >= 0 &&
        fseek(fp, 0, SEEK_SET) == 0) {
        *out = zcl_malloc((size_t)size + 1, "sft.read");
        ok = *out != NULL && fread(*out, 1, (size_t)size, fp) == (size_t)size;
        *len = (size_t)size;
    }
    (void)fclose(fp);
    if (!ok) {
        free(*out);
        *out = NULL;
    }
    return ok;
}

/* MAGIC || (u8 tag || u32le len || payload)*; the FACTS payload is
 * u32le count(1) || u32le record_len || text name || namespace || producer. */
uint8_t *sft_producer_at(uint8_t *m, size_t n)
{
    size_t off = strlen(VCS_SEMANTIC_MANIFEST_V1_MAGIC);
    while (m != NULL && off + 5 <= n) {
        uint8_t tag = m[off];
        uint32_t len = zcl_read_u32_le(m + off + 1);
        size_t at = off + 5;
        if (len > n - at)
            return NULL;
        if (tag == VCS_SEMANTIC_SECTION_V1_FACTS) {
            uint32_t name_len;
            if (len < 12)
                return NULL;
            name_len = zcl_read_u32_le(m + at + 8);
            if ((size_t)12 + name_len + 64 > len)
                return NULL;
            return m + at + 12 + name_len + 32;
        }
        off = at + len;
    }
    return NULL;
}
