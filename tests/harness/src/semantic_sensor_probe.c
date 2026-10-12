/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: semantic_sensor checks that the conditional-lookup scan sees every probe the front end evaluates, a system header's own included, and that the sensor refuses the options it cannot read (every -X pass-through but -Xlinker, -Wp, plugins and MSVC compatibility), whatever option values spell like -std.
 *
 * Each case emits one TU whose __has_include, __has_embed or #embed the
 * scan could miss and reads its LOOKUPS back: the probe must be there,
 * replayed against its search slots or recorded with no negative claim,
 * so the facts consumer widens on a created or deleted path. Each refusal
 * case must fail the emit with its reason. A raw string, #embed, or
 * __has_embed case skips when this front end's own emit rejects that
 * syntax; every case the emit accepts still requires its probe. Part of
 * the semantic_sensor group (test_semantic_manifest.c); runs only where
 * build/bin/z23-clang-manifest is built. */

#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif

#include "test/test_core.h"
#include "test/semantic_sensor_session.h"

#include "util/spawn.h"
#include "vcs/semantic_manifest.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define SSP_SENSOR "build/bin/z23-clang-manifest"

int semantic_sensor_probe_tests(void);

/* The T0 tail every case's main.c ends with. */
#define SSP_TAIL                                                              \
    "#define T 1\n"                                                           \
    "#else\n"                                                                 \
    "#define T 0\n"                                                           \
    "#endif\n"                                                                \
    "int f(void) { return T; }\n"

/* A main.c whose raw string literal, spelled with `prefix`, holds a quote
 * and a comment opener; the probe after it is live. */
#define SSP_RAW(prefix)                                                       \
    "static const void *s = " prefix "\"d( \" /* )d\";\n"                     \
    "#if __has_include(<opt.h>)\n" SSP_TAIL "/* end */\n"

/* What a matching record must be. */
enum ssp_want {
    SSP_ANY,     /* replayed or unbound */
    SSP_UNBOUND, /* no negative claim */
    SSP_BOUND,   /* replayed, and the TU records no unbound lookup at all */
};

struct ssp_case {
    const char *name;
    const char *main;
    const char *flags[3];
    const char *sys_header;  /* probe.h in an -isystem dir outside the root */
    const char *sys_header2; /* probe2.h there */
    bool repo_inc;           /* add -I <root>/inc, a repo dir */
    const char *want;        /* a substring of the probe's recorded name */
    enum ssp_want kind;
};

static const struct ssp_case k_ssp_cases[] = {
    {"a -D value's macro",
     "#if HAS(<opt.h>)\n" SSP_TAIL,
     {"-std=c23", "-DHAS(x)=__has_include(x)", NULL}, NULL, NULL, false,
     "__has_include", SSP_UNBOUND},
    {"a system header's macro body",
     "#include <probe.h>\n"
     "#if SYS_HAS(<opt.h>)\n" SSP_TAIL,
     {"-std=c23", NULL, NULL}, "#define SYS_HAS(x) __has_include(x)\n", NULL,
     false, "__has_include", SSP_UNBOUND},
    {"after an apostrophe that opens a character literal before C23",
     "#if 0\n"
     "int k = 1'a/*';\n"
     "#endif\n"
     "#if __has_include(\"opt.h\")\n" SSP_TAIL "/* end */\n",
     {"-std=c17", NULL, NULL}, NULL, NULL, false, "opt.h", SSP_ANY},
    {"a word a trigraph line splice joins",
     "#if __has_in?\?/\n"
     "clude(<opt.h>)\n" SSP_TAIL,
     {"-std=c17", NULL, NULL}, NULL, NULL, false, "opt.h", SSP_ANY},
    {"after a comment between the word and a header name holding /*",
     "#if __has_include(/**/<x/*y.h>)\n"
     "#endif\n"
     "#if __has_include(\"opt.h\")\n" SSP_TAIL "/* end */\n",
     {"-std=c23", NULL, NULL}, NULL, NULL, false, "opt.h", SSP_ANY},
    {"in a system header's own conditional, searching a repo -I dir first",
     "#include <probe.h>\n"
     "int f(void) { return 0; }\n",
     {"-std=c23", NULL, NULL}, "#if __has_include(<x.h>)\n#endif\n", NULL,
     true, "x.h", SSP_BOUND},
    {"in a system header behind #ifdef __has_include, as glibc guards it",
     "#include <probe.h>\n"
     "int f(void) { return 0; }\n",
     {"-std=c23", NULL, NULL},
     "#ifdef __has_include\n"
     "# if __has_include (\"x.h\")\n"
     "# endif\n"
     "#endif\n"
     "#if defined(__has_include) && defined __has_include_next\n"
     "#endif\n",
     NULL, true, "x.h", SSP_BOUND},
    {"as a __has_include_next in a system header another one includes",
     "#include <probe.h>\n"
     "int f(void) { return 0; }\n",
     {"-std=c23", NULL, NULL}, "#include <probe2.h>\n",
     "#if __has_include_next(<probe2.h>)\n#endif\n", true, "probe2.h",
     SSP_BOUND},
    {"after a macro named ifndef, which no #ifndef directive reads",
     "#define ifndef !\n"
     "#if ifndef __has_include(<opt.h>)\n" SSP_TAIL,
     {"-std=c23", NULL, NULL}, NULL, NULL, false, "opt.h", SSP_ANY},
    {"after an empty macro named elifdef",
     "#define elifdef\n"
     "#if elifdef __has_include(<opt.h>)\n" SSP_TAIL,
     {"-std=c23", NULL, NULL}, NULL, NULL, false, "opt.h", SSP_ANY},
    {"after a defined a macro call pastes into another identifier",
     "#define Xdefined !\n"
     "#define FN(a) X ## a\n"
     "#if FN(defined __has_include(<opt.h>))\n" SSP_TAIL,
     {"-std=c23", NULL, NULL}, NULL, NULL, false, "opt.h", SSP_ANY},
    {"after a defined an object-like macro opens a call around",
     "#define OPEN FN(\n"
     "#define Xdefined !\n"
     "#define FN(a) X ## a\n"
     "#if OPEN defined __has_include(<opt.h>))\n" SSP_TAIL,
     {"-std=c23", NULL, NULL}, NULL, NULL, false, "opt.h", SSP_ANY},
    {"after a ?\?/ comment, with -std=c17 only an -I value",
     "// note ?\?/\n"
     "#if __has_include(<opt.h>)\n" SSP_TAIL,
     {"-std=c23", "-I", "-std=c17"}, NULL, NULL, false, "opt.h", SSP_ANY},
    {"after a ?\?/ comment, with -std=c17 only an -Xlinker value",
     "// note ?\?/\n"
     "#if __has_include(<opt.h>)\n" SSP_TAIL,
     {"-Xlinker", "-std=c17", NULL}, NULL, NULL, false, "opt.h", SSP_ANY},
    {"a word a trigraph joins, with -std=c23 only an -iquote value",
     "#if __has_in?\?/\n"
     "clude(<opt.h>)\n" SSP_TAIL,
     {"-std=c17", "-iquote", "-std=c23"}, NULL, NULL, false, "opt.h", SSP_ANY},
    {"after an apostrophe, with -std=c23 only an -I value",
     "#if 0\n"
     "int k = 1'a/*';\n"
     "#endif\n"
     "#if __has_include(\"opt.h\")\n" SSP_TAIL "/* end */\n",
     {"-std=c17", "-I", "-std=c23"}, NULL, NULL, false, "opt.h", SSP_ANY},
    {"after an apostrophe before C23, with __STDC_VERSION__ set by -D",
     "#if 0\n"
     "int k = 1'a/*';\n"
     "#endif\n"
     "#if __has_include(\"opt.h\")\n" SSP_TAIL "/* end */\n",
     {"-std=c17", "-D__STDC_VERSION__=202311L", NULL}, NULL, NULL, false,
     "opt.h", SSP_ANY},
    {"after a raw string holding \" /*, under -std=gnu23",
     SSP_RAW("R"), {"-std=gnu23", NULL, NULL}, NULL, NULL, false, "opt.h",
     SSP_ANY},
    {"after a raw string holding \" /*, with no -std",
     SSP_RAW("R"), {NULL, NULL, NULL}, NULL, NULL, false, "opt.h", SSP_ANY},
    {"after a raw string holding \" /*, under -std=c23 -fraw-string-literals",
     SSP_RAW("R"), {"-std=c23", "-fraw-string-literals", NULL}, NULL, NULL,
     false, "opt.h", SSP_ANY},
    {"after a u8R raw string holding \" /*",
     SSP_RAW("u8R"), {"-std=gnu23", NULL, NULL}, NULL, NULL, false, "opt.h",
     SSP_ANY},
    {"after an LR raw string holding \" /*",
     SSP_RAW("LR"), {"-std=gnu23", NULL, NULL}, NULL, NULL, false, "opt.h",
     SSP_ANY},
    {"after uR and UR raw strings holding \" /*",
     "static const void *u = uR\"d( \" /* )d\";\n"
     "static const void *w = UR\"d( \" /* )d\";\n"
     "#if __has_include(<opt.h>)\n" SSP_TAIL "/* end */\n",
     {"-std=gnu23", NULL, NULL}, NULL, NULL, false, "opt.h", SSP_ANY},
    {"after a raw string whose second line holds /* \"",
     "static const char *s = R\"d(\n"
     "/* \" )d\";\n"
     "#if __has_include(<opt.h>)\n" SSP_TAIL "/* end */\n",
     {"-std=gnu23", NULL, NULL}, NULL, NULL, false, "opt.h", SSP_ANY},
    {"after a #warning line holding /*, which opens no comment",
     "#warning note /* here\n"
     "#if __has_include(<opt.h>)\n" SSP_TAIL "/* end */\n",
     {"-std=c23", NULL, NULL}, NULL, NULL, false, "opt.h", SSP_ANY},
    {"after a line splice, as the first word of the next line",
     "#define G(x) x \\\n"
     "+ 1\n"
     "#if G(0) || \\\n"
     "__has_include(<opt.h>)\n" SSP_TAIL,
     {"-std=c23", NULL, NULL}, NULL, NULL, false, "opt.h", SSP_ANY},
    {"in a system header's macro body, its #define after a comment",
     "#include <probe.h>\n"
     "#if SYS_HAS\n" SSP_TAIL,
     {"-std=c23", NULL, NULL}, "/**/ #define SYS_HAS __has_include(\"opt.h\")\n",
     NULL, false, "opt.h", SSP_UNBOUND},
    {"after a C23 digit separator, with __STDC_VERSION__ dropped by -U",
     "#if 0\n"
     "int k = 1'a'/*;\n"
     "#endif\n"
     "#if __has_include(\"opt.h\")\n" SSP_TAIL "/* end */\n",
     {"-std=c23", "-U__STDC_VERSION__", NULL}, NULL, NULL, false, "opt.h",
     SSP_ANY},
    {"after a C23 digit separator, with __STDC_VERSION__ dropped by an "
     "-include file",
     "#if 0\n"
     "int k = 1'a'/*;\n"
     "#endif\n"
     "#if __has_include(\"opt.h\")\n" SSP_TAIL "/* end */\n",
     {"-std=c23", "-include", "probe.h"}, "#undef __STDC_VERSION__\n", NULL,
     false, "opt.h", SSP_ANY},
    {"after a ?\?/ comment, with sizeof redefined by -D",
     "// note ?\?/\n"
     "#if __has_include(<opt.h>)\n" SSP_TAIL,
     {"-std=c23", "-Dsizeof(x)=2", NULL}, NULL, NULL, false, "opt.h",
     SSP_ANY},
    {"after a skipped #error line holding /*",
     "#if 0\n"
     "#error /*\n"
     "\"*/\" /*\n"
     "#endif\n"
     "#if __has_include(\"opt.h\")\n" SSP_TAIL "// */\n",
     {"-std=c23", NULL, NULL}, NULL, NULL, false, "opt.h", SSP_BOUND},
    {"after a skipped %:error line holding /*",
     "#if 0\n"
     "%:error /*\n"
     "\"*/\" /*\n"
     "#endif\n"
     "#if __has_include(\"opt.h\")\n" SSP_TAIL "// */\n",
     {"-std=c23", NULL, NULL}, NULL, NULL, false, "opt.h", SSP_BOUND},
    {"after a skipped #warning line holding /*",
     "#if 0\n"
     "#warning /*\n"
     "\"*/\" /*\n"
     "#endif\n"
     "#if __has_include(\"opt.h\")\n" SSP_TAIL "// */\n",
     {"-std=c23", NULL, NULL}, NULL, NULL, false, "opt.h", SSP_BOUND},
    {"after a skipped #include whose header name holds /*",
     "#if 0\n"
     "#include <a/*>\n"
     "\"*/\" /*\n"
     "#endif\n"
     "#if __has_include(\"opt.h\")\n" SSP_TAIL "// */\n",
     {"-std=c23", NULL, NULL}, NULL, NULL, false, "opt.h", SSP_BOUND},
    {"as an #embed after a skipped #error line holding /*",
     "#if 0\n"
     "#error /*\n"
     "\"*/\" /*\n"
     "#endif\n"
     "static const unsigned char d[] = {\n"
     "#embed \"d.bin\"\n"
     "};\n"
     "int f(void) { return (int)sizeof d; }\n"
     "// */\n",
     {"-std=c23", NULL, NULL}, NULL, NULL, false, "#embed \"d.bin\"",
     SSP_UNBOUND},
    {"across a splice with a form feed before its newline",
     "#if __has_in\\\f\n"
     "clude(\"opt.h\")\n" SSP_TAIL,
     {"-std=c23", NULL, NULL}, NULL, NULL, false,
     "#embed? __has_include(\"opt.h\")", SSP_UNBOUND},
    {"across a splice ended by a lone carriage return",
     "#if __has_in\\\rclude(\"opt.h\")\n" SSP_TAIL,
     {"-std=c23", NULL, NULL}, NULL, NULL, false,
     "#embed? __has_include(\"opt.h\")", SSP_UNBOUND},
    {"across a splice ended by a newline and a carriage return",
     "#if __has_in\\\n"
     "\rclude(\"opt.h\")\n" SSP_TAIL,
     {"-std=c23", NULL, NULL}, NULL, NULL, false,
     "#embed? __has_include(\"opt.h\")", SSP_UNBOUND},
    {"as a word a macro call pastes together",
     "#define CAT(a, b) a##b\n"
     "#if CAT(__has_, include)(\"opt.h\")\n" SSP_TAIL,
     {"-std=c23", NULL, NULL}, NULL, NULL, false,
     "#embed? pasted from __has_", SSP_UNBOUND},
    {"as a __has_embed",
     "#if __has_embed(\"d.bin\") == 1\n" SSP_TAIL "// */\n",
     {"-std=c23", NULL, NULL}, NULL, NULL, false, "__has_embed(\"d.bin\")",
     SSP_UNBOUND},
    {"as a __has_embed after an alias of __has_include called on <x/*>",
     "#define HI __has_include\n"
     "#if HI(<nope.h/*>)\n"
     "#endif\n"
     "#if __has_embed(\"d.bin\") == 1\n" SSP_TAIL "// */\n",
     {"-std=c23", NULL, NULL}, NULL, NULL, false, "__has_embed(\"d.bin\")",
     SSP_UNBOUND},
    {"on the #elif line that closes a skipped group",
     "#if 0\n"
     "#ifdef __has_include\n"
     "#endif\n"
     "#elif __has_include(\"opt.h\")\n" SSP_TAIL,
     {"-std=c23", NULL, NULL}, NULL, NULL, false, "opt.h", SSP_BOUND},
    {"on the line after the #else that closes a skipped group",
     "#if 0\n"
     "#ifdef __has_include\n"
     "#endif\n"
     "#else\n"
     "#if __has_include(\"opt.h\")\n"
     "#define T 1\n"
     "#else\n"
     "#define T 0\n"
     "#endif\n"
     "#endif\n"
     "int f(void) { return T; }\n",
     {"-std=c23", NULL, NULL}, NULL, NULL, false, "opt.h", SSP_BOUND},
    {"in a header whose first entry skips it and whose second does not",
     "#include <probe.h>\n"
     "#define SECOND 1\n"
     "#include <probe.h>\n"
     "int f(void) { return TW; }\n",
     {"-std=c23", NULL, NULL},
     "#if defined(SECOND)\n"
     "#if __has_include(\"opt.h\")\n"
     "#define TW 1\n"
     "#else\n"
     "#define TW 0\n"
     "#endif\n"
     "#endif\n",
     NULL, false, "opt.h", SSP_BOUND},
    {"on an #if line a block comment carries past its first newline",
     "#if 0 /*\n"
     "*/ || __has_include(\"opt.h\")\n" SSP_TAIL,
     {"-std=c23", NULL, NULL}, NULL, NULL, false, "opt.h", SSP_BOUND},
    {"on an #elif line a block comment carries past its first newline",
     "#if 0\n"
     "#define T 2\n"
     "#elif 0 /*\n"
     "*/ || __has_include(\"opt.h\")\n"
     "#define T 1\n"
     "#else\n"
     "#define T 0\n"
     "#endif\n"
     "int f(void) { return T; }\n",
     {"-std=c23", NULL, NULL}, NULL, NULL, false, "opt.h", SSP_BOUND},
    {"after a skipped group nested in a live one",
     "#if 1\n"
     "#if 0\n"
     "#ifdef __has_include\n"
     "#endif\n"
     "#endif\n"
     "#if __has_include(\"opt.h\")\n"
     "#define T 1\n"
     "#else\n"
     "#define T 0\n"
     "#endif\n"
     "#endif\n"
     "int f(void) { return T; }\n",
     {"-std=c23", NULL, NULL}, NULL, NULL, false, "opt.h", SSP_BOUND},
};

/* Options the scan cannot read: the emit must refuse with `why`. */
struct ssp_refusal {
    const char *name;
    const char *main;
    const char *flags[3];
    const char *why;
};

static const struct ssp_refusal k_ssp_refusals[] = {
    {"a -D value passed through -Wp,",
     "#if HAS(<opt.h>)\n" SSP_TAIL,
     {"-std=c23", "-Wp,-DHAS(x)=__has_include(x)", NULL},
     "indirect compiler options"},
    {"a -std passed through -Wp,",
     "#if __has_in?\?/\n"
     "clude(<opt.h>)\n" SSP_TAIL,
     {"-Wp,-std=c17", NULL, NULL}, "indirect compiler options"},
    {"-fms-compatibility, which turns trigraphs off",
     "// note ?\?/\n"
     "#if __has_include(<opt.h>)\n" SSP_TAIL,
     {"-std=c17", "-fms-compatibility", NULL}, "MSVC compatibility"},
    {"an MSVC target, which turns MSVC compatibility on",
     "// note ?\?/\n"
     "#if __has_include(<opt.h>)\n" SSP_TAIL,
     {"-std=c17", "--target=x86_64-pc-windows-msvc", NULL}, "MSVC target"},
    {"a -D value passed through -Xclang=",
     "#if HAS(<opt.h>)\n" SSP_TAIL,
     {"-std=c23", "-Xclang=-DHAS(x)=__has_include(x)", NULL},
     "indirect compiler options"},
    {"a -std passed through -Xclang=",
     "#if __has_in?\?/\n"
     "clude(<opt.h>)\n" SSP_TAIL,
     {"-Xclang=-std=c17", NULL, NULL}, "indirect compiler options"},
    {"-fms-compatibility passed through -Xclang=",
     "// note ?\?/\n"
     "#if __has_include(<opt.h>)\n" SSP_TAIL,
     {"-std=c17", "-Xclang=-fms-compatibility", NULL},
     "indirect compiler options"},
    {"a -D value passed through -Xclang",
     "#if HAS(<opt.h>)\n" SSP_TAIL,
     {"-std=c23", "-Xclang", "-DHAS(x)=__has_include(x)"},
     "indirect compiler options"},
    {"a -D value passed through -Xpreprocessor",
     "#if HAS(<opt.h>)\n" SSP_TAIL,
     {"-std=c23", "-Xpreprocessor", "-DHAS(x)=__has_include(x)"},
     "indirect compiler options"},
    {"a -D value passed through -Xarch_host",
     "#if HAS(<opt.h>)\n" SSP_TAIL,
     {"-std=c23", "-Xarch_host", "-DHAS(x)=__has_include(x)"},
     "indirect compiler options"},
    {"a -D value passed through -Xcompiler",
     "#if HAS(<opt.h>)\n" SSP_TAIL,
     {"-std=c23", "-Xcompiler", "-DHAS(x)=__has_include(x)"},
     "indirect compiler options"},
    {"a -D value passed through -Xparser",
     "#if HAS(<opt.h>)\n" SSP_TAIL,
     {"-std=c23", "-Xparser", "-DHAS(x)=__has_include(x)"},
     "indirect compiler options"},
    {"a -D value passed through -Xopenmp-target=",
     "#if HAS(<opt.h>)\n" SSP_TAIL,
     {"-Xopenmp-target=x86_64-pc-linux-gnu", "-DHAS(x)=__has_include(x)",
      NULL},
     "indirect compiler options"},
    {"a front-end plugin",
     "#if __has_include(<opt.h>)\n" SSP_TAIL,
     {"-std=c23", "-fplugin=/nonexistent/probe-plugin.so", NULL},
     "indirect compiler options"},
    {"a #pragma '<' whose raw tokens open a comment inside it",
     "#pragma probe <a/*b>\n"
     "*/\n"
     "#if __has_include(<opt.h>)\n" SSP_TAIL,
     {"-std=c23", NULL, NULL}, "a #pragma header name could hide text"},
};

static bool ssp_write(const char *dir, const char *rel, const char *body)
{
    char path[PATH_MAX];
    FILE *fp;
    bool ok;
    if (snprintf(path, sizeof(path), "%s/%s", dir, rel) >= (int)sizeof(path))
        return false;
    fp = fopen(path, "wb");
    if (fp == NULL)
        return false;
    ok = fwrite(body, 1, strlen(body), fp) == strlen(body);
    return fclose(fp) == 0 && ok;
}

static bool ssp_read(const char *path, uint8_t **out, size_t *len)
{
    FILE *fp = fopen(path, "rb");
    long n;
    bool ok;
    *out = NULL;
    *len = 0;
    if (fp == NULL)
        return false;
    ok = fseek(fp, 0, SEEK_END) == 0 && (n = ftell(fp)) > 0 &&
         fseek(fp, 0, SEEK_SET) == 0 && (*out = malloc((size_t)n)) != NULL &&
         fread(*out, 1, (size_t)n, fp) == (size_t)n;
    if (ok)
        *len = (size_t)n;
    (void)fclose(fp);
    return ok;
}

struct ssp_seen {
    const char *want;
    enum ssp_want kind;
    size_t hits;
    size_t unbound; /* every unbound record, matching or not */
};

static bool ssp_absent_cb(void *ctx, const char *dir, size_t dir_len,
                          const char *name, size_t name_len)
{
    struct ssp_seen *s = ctx;
    char spelled[PATH_MAX];
    bool match;
    (void)dir_len;
    (void)snprintf(spelled, sizeof(spelled), "%.*s", (int)name_len, name);
    match = strstr(spelled, s->want) != NULL;
    if (dir == NULL)
        s->unbound++;
    if (match && (s->kind == SSP_ANY ||
                  (s->kind == SSP_UNBOUND) == (dir == NULL)))
        s->hits++;
    return true;
}

/* A case's tree: base/fakehome/root holds main.c, base/sys an -isystem dir.
 * The sensor runs with HOME=base/fakehome, so base/sys is outside both the
 * checkout and the home and spells as @sys, as a real system dir does. */
struct ssp_tree {
    char base[PATH_MAX];
    char home[PATH_MAX + 8];
    char root[PATH_MAX + 16];
    char inc[PATH_MAX + 24];
    char sys[PATH_MAX + 8];
    char env_home[PATH_MAX + 16];
};

static bool ssp_layout(struct ssp_tree *t)
{
    if (test_mkdtemp(t->base, sizeof(t->base), "semsensor_probe") == NULL)
        return false;
    (void)snprintf(t->home, sizeof(t->home), "%s/fakehome", t->base);
    (void)snprintf(t->root, sizeof(t->root), "%s/root", t->home);
    (void)snprintf(t->inc, sizeof(t->inc), "%s/inc", t->root);
    (void)snprintf(t->sys, sizeof(t->sys), "%s/sys", t->base);
    (void)snprintf(t->env_home, sizeof(t->env_home), "HOME=%s", t->home);
    return mkdir(t->home, 0700) == 0 && mkdir(t->root, 0700) == 0 &&
           mkdir(t->inc, 0700) == 0 && mkdir(t->sys, 0700) == 0;
}

/* Run the sensor on main.c under flags (and -I <root>/inc when repo_inc);
 * out receives the manifest, message the merged output. */
static int ssp_run(const struct ssp_tree *t, const char *const flags[3],
                   bool repo_inc, const char *out, char *message,
                   size_t message_len)
{
    const char *argv[24] = {"env",      "-u",   "HOME",  t->env_home,
                            SSP_SENSOR, "emit", "--root", t->root,
                            "--source", "main.c", "--out", out, "--"};
    size_t n = 13;
    bool timed_out = false;
    int rc;
    if (repo_inc) {
        argv[n++] = "-I";
        argv[n++] = t->inc;
    }
    argv[n++] = "-isystem";
    argv[n++] = t->sys;
    for (size_t f = 0; f < 3 && flags[f] != NULL; f++)
        argv[n++] = flags[f];
    argv[n] = NULL;
    rc = zcl_spawn_capture_merged_observed(argv, message, message_len, 60000,
                                           &timed_out);
    return timed_out ? -1 : rc;
}

/* Emit main.c under the case's flags; the matching probe records. */
static bool ssp_emit(const struct ssp_tree *t, const struct ssp_case *k,
                     struct ssp_seen *seen)
{
    char out[PATH_MAX + 32], message[4096];
    size_t len = 0;
    uint8_t *m = NULL;
    int rc;
    bool ok;
    (void)snprintf(out, sizeof(out), "%s/main.zsm", t->base);
    rc = ssp_run(t, k->flags, k->repo_inc, out, message, sizeof(message));
    ok = rc == 0 && ssp_read(out, &m, &len) &&
         vcs_semantic_absent_v1_each(m, len, ssp_absent_cb, seen);
    if (!ok)
        printf("  probe %s: rc=%d: %s\n", k->name, rc, message);
    free(m);
    return ok;
}

static bool ssp_write_case(const struct ssp_tree *t, const struct ssp_case *k)
{
    return ssp_write(t->root, "main.c", k->main) &&
           ssp_write(t->root, "d.bin", "x") &&
           (k->sys_header == NULL ||
            ssp_write(t->sys, "probe.h", k->sys_header)) &&
           (k->sys_header2 == NULL ||
            ssp_write(t->sys, "probe2.h", k->sys_header2));
}

static int ssp_t_case(const struct ssp_case *k)
{
    static const char *const kinds[] = {"lookup", "unbound", "replayed"};
    int failures = 0;
    struct ssp_tree t = {0};
    struct ssp_seen seen = {.want = k->want, .kind = k->kind};
    printf("semantic_sensor: the scan records a probe written %s", k->name);
    TEST_CASE("") {
        ASSERT(ssp_layout(&t));
        ASSERT(ssp_write_case(&t, k));
        ASSERT(ssp_emit(&t, k, &seen));
        if (seen.hits == 0)
            printf("  probe %s: no %s record naming \"%s\"\n", k->name,
                   kinds[k->kind], k->want);
        ASSERT(seen.hits > 0);
        if (k->kind == SSP_BOUND && seen.unbound != 0)
            printf("  probe %s: %zu unbound records\n", k->name, seen.unbound);
        ASSERT(k->kind != SSP_BOUND || seen.unbound == 0);
    } TEST_END
    if (t.base[0] != '\0')
        (void)test_rm_rf_recursive(t.base);
    return failures;
}

static int ssp_t_refusal(const struct ssp_refusal *k)
{
    int failures = 0;
    struct ssp_tree t = {0};
    char out[PATH_MAX + 32], message[4096] = "";
    int rc = 0;
    printf("semantic_sensor: the sensor refuses %s", k->name);
    TEST_CASE("") {
        ASSERT(ssp_layout(&t));
        ASSERT(ssp_write(t.root, "main.c", k->main));
        (void)snprintf(out, sizeof(out), "%s/main.zsm", t.base);
        rc = ssp_run(&t, k->flags, false, out, message, sizeof(message));
        if (rc == 0 || strstr(message, k->why) == NULL)
            printf("  refusal %s: rc=%d, want \"%s\": %s\n", k->name, rc,
                   k->why, message);
        ASSERT(rc > 0);
        ASSERT(strstr(message, k->why) != NULL);
    } TEST_END
    if (t.base[0] != '\0')
        (void)test_rm_rf_recursive(t.base);
    return failures;
}

/* One cold emit. *accepted is the front end's parse, and the return is
 * whether that emit actually ran. A missing tree is not a syntax refusal. */
static bool ssp_front_accepts(const char *main, const char *const flags[3],
                              bool *accepted)
{
    struct ssp_tree t = {0};
    char out[PATH_MAX + 32];
    char message[4096];
    bool wrote;
    *accepted = false;
    if (!ssp_layout(&t))
        return false;
    wrote = ssp_write(t.root, "main.c", main) &&
            ssp_write(t.root, "d.bin", "x");
    if (wrote) {
        int rc;
        (void)snprintf(out, sizeof(out), "%s/main.zsm", t.base);
        rc = ssp_run(&t, flags, false, out, message, sizeof(message));
        *accepted = rc == 0;
    }
    (void)test_rm_rf_recursive(t.base);
    return wrote;
}

/* Asked through the shipped sensor, not a side compiler. Cached so the
 * session cases and the probe cases share one answer. */
int semantic_sensor_front_end_features(void)
{
    static int cached = -1;
    static const char *const raw_flags[3] = {"-std=gnu23", NULL, NULL};
    static const char *const c23[3] = {"-std=c23", NULL, NULL};
    bool raw = false;
    bool embed = false;
    bool has = false;
    if (cached >= 0)
        return cached;
    if (!ssp_front_accepts("static const char *s = R\"d(x)d\";\n"
                           "int f(void) { return s != 0; }\n",
                           raw_flags, &raw) ||
        !ssp_front_accepts("static const unsigned char d[] = {\n"
                           "#embed \"d.bin\"\n"
                           "};\n"
                           "int f(void) { return (int)sizeof d; }\n",
                           c23, &embed) ||
        !ssp_front_accepts("#if __has_embed(\"d.bin\") == 1\n"
                           "int f(void) { return 1; }\n"
                           "#else\n"
                           "int f(void) { return 0; }\n"
                           "#endif\n",
                           c23, &has))
        return -1;
    cached = (raw ? SEMANTIC_SENSOR_FEAT_RAW : 0) |
             (embed ? SEMANTIC_SENSOR_FEAT_EMBED : 0) |
             (has ? SEMANTIC_SENSOR_FEAT_HAS_EMBED : 0);
    printf("semantic_sensor: front end accepts raw=%d #embed=%d "
           "__has_embed=%d\n",
           (int)raw, (int)embed, (int)has);
    return cached;
}

/* NULL when this case must run. A name or a live directive this front end
 * cannot parse is the only skip; a `#embed?` replay label is not one. */
static const char *ssp_skip_why(const struct ssp_case *k, int features)
{
    if (strstr(k->name, "raw string") != NULL &&
        (features & SEMANTIC_SENSOR_FEAT_RAW) == 0)
        return "raw string";
    if (strstr(k->main, "#embed") != NULL &&
        (features & SEMANTIC_SENSOR_FEAT_EMBED) == 0)
        return "#embed";
    if (strstr(k->main, "__has_embed") != NULL &&
        (features & SEMANTIC_SENSOR_FEAT_HAS_EMBED) == 0)
        return "__has_embed";
    return NULL;
}

int semantic_sensor_probe_tests(void)
{
    int failures = 0;
    int features = semantic_sensor_front_end_features();
    if (features < 0) {
        printf("semantic_sensor: SKIP probe list refused "
               "(front-end emit did not run)\n");
        return 1;
    }
    for (size_t k = 0; k < sizeof(k_ssp_cases) / sizeof(k_ssp_cases[0]); k++) {
        const struct ssp_case *c = &k_ssp_cases[k];
        const char *why = ssp_skip_why(c, features);
        if (why != NULL) {
            printf("semantic_sensor: SKIP probe \"%s\" "
                   "(this front end rejects %s)\n",
                   c->name, why);
            continue;
        }
        failures += ssp_t_case(c);
    }
    for (size_t k = 0; k < sizeof(k_ssp_refusals) / sizeof(k_ssp_refusals[0]);
         k++)
        failures += ssp_t_refusal(&k_ssp_refusals[k]);
    return failures;
}
