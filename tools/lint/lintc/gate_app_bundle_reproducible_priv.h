/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: private interface of the check-app-bundle-reproducible gate family
 * (gate_app_bundle_reproducible*.c): the run context, the exit-status codes
 * and the helpers the proof, the manifest and the selftest files share.
 */
#ifndef GATE_APP_BUNDLE_REPRODUCIBLE_PRIV_H
#define GATE_APP_BUNDLE_REPRODUCIBLE_PRIV_H

#include <stdio.h>
#include <stddef.h>
#include "lintc_proc.h"
#include "zsha256/zsha256.h"

#define ABR_GATE "check_app_bundle_reproducible"
#define ABR_BUNDLER "tools/scripts/make_app_bundle.sh"
#define ABR_PROBE_EXPECT "hello-bundle"
#define ABR_PROBE_JSON "{\"a\":{\"b\":\"hello-bundle\"}}"
#define ABR_PATH 4096
#define ABR_NAME 256
#define ABR_GRACE_MS 2000

/* Step results; ABR_SIG means a termination signal stopped a child and the
 * main path must clean up and re-raise it. */
enum { ABR_OK = 0, ABR_FAIL = 1, ABR_FATAL = 2, ABR_SIG = 3 };

struct abr_ctx {
    char tmp[ABR_PATH];
    char app[ABR_NAME];
    const char *bin;          /* prebuilt subject under proof, or NULL for jsonq */
    const char *probe_args;   /* --bin mode: whitespace-separated flag list */
    const char *probe_expect; /* required output (substring in --bin mode) */
    int lines;                /* files in the content manifest */
    char sha[ZSHA256_HEX_LEN];
};

struct abr_list {
    char **v;
    size_t n, cap;
};

struct abr_text {
    char *p;
    size_t n, cap;
};

/* gate_app_bundle_reproducible.c */
int abr_fatal(const char *fmt, ...);
int abr_pathf(char *out, const char *fmt, ...);
void abr_note(FILE *err, const char *fmt, ...);
int abr_exec(char *const argv[], enum lcp_mode mode, const char *in,
             struct lcp_buf *out, int *code);
int abr_copy_tree(const char *from, const char *to);
int abr_guard_tools(void);

/* gate_app_bundle_reproducible_manifest.c */
void abr_text_free(struct abr_text *t);
int abr_text_addf(struct abr_text *t, const char *fmt, ...);
int abr_write_file(const char *path, const char *data, size_t len);
void abr_mode_string(unsigned mode, char out[11]);
int abr_manifest_tree(const char *root, const char *tmp, const char *tag,
                      int *lines, char sha[ZSHA256_HEX_LEN]);
int abr_content_manifest(const char *root, struct abr_text *out);
int abr_compare(const char *label, const char *a, const char *b, FILE *err);
int abr_same_file(const char *a, const char *b);
int abr_copy_file(const char *from, const char *to);

/* gate_app_bundle_reproducible_proof.c */
int abr_compile_subject(const char *out);
int abr_verify_signature(const char *bundle, FILE *err);
int abr_probe(const struct abr_ctx *c, const char *exe, const char *json_file,
              FILE *err);
int abr_bundle(const struct abr_ctx *c, const char *bin, const char *outdir,
               char bundle[ABR_PATH], const char *which);
int abr_prove(struct abr_ctx *c);

/* gate_app_bundle_reproducible_selftest.c */
int abr_selftest_darwin(struct abr_ctx *c);
int abr_unit_checks(void);

#endif
