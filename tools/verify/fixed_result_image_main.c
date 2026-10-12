/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0.
 * purpose: z23-fixed-result-image, the CLI root runs to build the three
 *          verifier images into /var/lib/z23verify/images/fixed_result and
 *          print the manifest and the pins-file roots, and a developer runs
 *          to predict those roots and prove the tool image complete. It
 *          prints attest_eligible=0: an image root is an input to review,
 *          never an attestation. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "fixed_result_image.h"
#include "tree_closure.h"

#include "base/hex.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct fri_cli {
    const char *repo, *profile, *out, *scratch, *tool;
    bool static_only;
    char **specs;
    size_t spec_count;
};

static int fri_refuse(const char *why, const char *path)
{
    fprintf(stderr, "fixed_result_image_refuse=%s path=%s\n", why,
            path ? path : "");
    return 2;
}

static bool fri_value(int argc, char **argv, int *i, const char *flag,
                      const char **out)
{
    if (strcmp(argv[*i], flag) != 0) return false;
    if (*i + 1 >= argc || argv[*i + 1][0] != '/') return false;
    *out = argv[++*i];
    return true;
}

static bool fri_parse(int argc, char **argv, struct fri_cli *c)
{
    for (int i = 2; i < argc; i++) {
        if (fri_value(argc, argv, &i, "--repo", &c->repo) ||
            fri_value(argc, argv, &i, "--profile", &c->profile) ||
            fri_value(argc, argv, &i, "--out", &c->out) ||
            fri_value(argc, argv, &i, "--scratch", &c->scratch) ||
            fri_value(argc, argv, &i, "--tool", &c->tool)) continue;
        if (strcmp(argv[i], "--static") == 0) { c->static_only = true; continue; }
        if (argv[i][0] == '-' || !strchr(argv[i], '=')) return false;
        if (!c->specs) c->specs = &argv[i];
        if (c->specs + c->spec_count != &argv[i]) return false;
        c->spec_count++;
    }
    return true;
}

/* Installed images are built by root under root-owned, non-writable
 * ancestors; a developer build is a prediction and says so. */
static bool fri_out_safe(const char *out, bool *checked)
{
    char parent[PATH_MAX];
    snprintf(parent, sizeof(parent), "%s", out);
    char *slash = strrchr(parent, '/');
    if (!slash || slash == parent) return false;
    *slash = '\0';
    *checked = geteuid() == 0;
    return !*checked || zcl_tree_closure_root_safe(parent, 0);
}

static void fri_hex(const uint8_t in[32], char out[65])
{
    zcl_hex_encode(in, 32u, out);
}

static int fri_emit(const struct zcl_fri_image *img, const char *kind,
                    const struct zcl_fri_roots *r, bool checked,
                    const struct zcl_fri_discovery *d)
{
    char tree[65], content[65], root_tree[65];
    fri_hex(r->tree_sha3, tree);
    fri_hex(r->content_sha3, content);
    fri_hex(r->root_tree_sha3, root_tree);
    if (!zcl_fri_manifest_write(img, kind, r, stdout))
        return fri_refuse(ZCL_FRI_WHY_WRITE, "stdout");
    if (d)
        printf("discovery traced=%d trace_present=%u trace_absent=%u "
               "static_files=%u static_only=%u trace_only=%u specs=%s\n",
               d->traced ? 1 : 0, d->trace_present, d->trace_absent,
               d->static_files, d->static_only, d->trace_only,
               d->specs_builtin ? "builtin" : "file");
    if (d && d->static_only) printf("static_only_first=%s\n", d->static_only_first);
    if (d && d->trace_only) printf("trace_only_first=%s\n", d->trace_only_first);
    if (strcmp(kind, "source") == 0)
        printf("pin source_content_sha3=%s\npin source_image_sha3=%s\n",
               content, root_tree);
    else printf("pin %s_image_sha3=%s\n", kind, root_tree);
    if (strcmp(kind, "tool") == 0)
        printf("toolchain_id=z23.gcc14.fast_result.v2:%s\n", root_tree);
    printf("fixed_result_image kind=%s entries=%u bytes=%llu tree_sha3=%s "
           "content_sha3=%s root_tree_sha3=%s owner_uid=%u "
           "ancestors_checked=%d attest_eligible=0\n", kind, r->entries,
           (unsigned long long)r->bytes, tree, content, root_tree,
           (unsigned)r->owner, checked ? 1 : 0);
    return fflush(stdout) == 0 ? 0 : 2;
}

static bool fri_fill(struct zcl_fri_image *img, const char *kind,
                     const struct fri_cli *c, struct zcl_fri_discovery *d)
{
    if (strcmp(kind, "source") == 0)
        return c->repo && c->profile &&
               zcl_fri_build_source(img, c->repo, c->profile);
    if (strcmp(kind, "tool") == 0)
        return c->repo && c->profile && c->scratch &&
               zcl_fri_build_tool(img, c->profile, c->repo, c->scratch,
                                  !c->static_only, d);
    return zcl_fri_build_check(img, c->specs, c->spec_count);
}

static int fri_build(const char *kind, const struct fri_cli *c)
{
    bool checked = false;
    if (!c->out || !fri_out_safe(c->out, &checked))
        return fri_refuse(ZCL_FRI_WHY_ROOT_UNSAFE, c->out);
    struct zcl_fri_image img;
    struct zcl_fri_roots roots;
    struct zcl_fri_discovery d;
    bool tool = strcmp(kind, "tool") == 0;
    bool ok = zcl_fri_image_begin(&img, c->out, NULL) &&
              fri_fill(&img, kind, c, &d) &&
              zcl_fri_image_finish(&img, &roots);
    int rc = ok ? fri_emit(&img, kind, &roots, checked, tool ? &d : NULL)
                : fri_refuse(img.why ? img.why : ZCL_FRI_WHY_ARGS, img.why_path);
    zcl_fri_image_free(&img);
    return rc;
}

static void fri_names(const char *label, char list[][PATH_MAX], unsigned n)
{
    for (unsigned i = 0; i < n && i < ZCL_FRI_NAMED; i++)
        printf("%s=%s\n", label, list[i]);
}

static int fri_prove(const struct fri_cli *c)
{
    if (!c->tool || !c->repo || !c->profile || !c->scratch)
        return fri_refuse(ZCL_FRI_WHY_ARGS, "prove");
    struct zcl_fri_proof p;
    if (!zcl_fri_prove(c->tool, c->repo, c->profile, c->scratch, &p))
        return fri_refuse(p.why ? p.why : ZCL_FRI_WHY_ARGS, p.why_path);
    char img[65], ref[65];
    fri_hex(p.image_object, img);
    fri_hex(p.reference_object, ref);
    bool complete = p.object_equal && p.dep_equal && p.stderr_equal &&
                    p.traced && p.leaks == 0 && p.eq_mismatch == 0;
    printf("fixed_result_image_proof object_sha3=%s reference_sha3=%s "
           "object_bytes=%llu object_equal=%d dep_equal=%d stderr_equal=%d\n",
           img, ref, (unsigned long long)p.object_size, p.object_equal,
           p.dep_equal, p.stderr_equal);
    printf("fixed_result_image_proof traced=%d image_reads=%u ancestors=%u "
           "leaks=%u absent_outside=%u\n", p.traced, p.image_reads,
           p.ancestors, p.leaks, p.absent_outside);
    fri_names("leak", p.leak, p.leaks);
    fri_names("absent_outside", p.absent, p.absent_outside);
    printf("fixed_result_image_proof equivalence present=%u absent=%u "
           "mismatches=%u excluded=/etc/ld.so.cache\n", p.eq_present,
           p.eq_absent, p.eq_mismatch);
    fri_names("mismatch", p.mismatch, p.eq_mismatch);
    printf("complete=%d attest_eligible=0\n", complete ? 1 : 0);
    return complete ? 0 : 2;
}

int main(int argc, char **argv)
{
    struct fri_cli c = {0};
    if (argc < 2 || !fri_parse(argc, argv, &c)) {
        fprintf(stderr,
                "usage: z23-fixed-result-image source --repo R --profile P --out DIR\n"
                "       z23-fixed-result-image tool --repo R --profile P "
                "--scratch S --out DIR [--static]\n"
                "       z23-fixed-result-image check --out DIR NAME=/abs/path...\n"
                "       z23-fixed-result-image prove --tool DIR --repo R "
                "--profile P --scratch S\n");
        return 2;
    }
    if (strcmp(argv[1], "prove") == 0) return fri_prove(&c);
    if (strcmp(argv[1], "source") == 0 || strcmp(argv[1], "tool") == 0 ||
        strcmp(argv[1], "check") == 0) return fri_build(argv[1], &c);
    return fri_refuse(ZCL_FRI_WHY_ARGS, argv[1]);
}
