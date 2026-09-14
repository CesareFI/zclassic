/* Copyright 2026 Rhett Creighton - Apache 2.0 */
/*
 * Product acceptance contract for the resident-launch consumer.
 *
 * platform/resident_launch.h (9bc54830ad, "the launcher half of the app-run
 * path") is covered at the platform seam by test_resident_launch.c. The
 * consumer half is fleet peer C's production slice: the composition leaf
 * app.invoke.package (engine/composition/commands/apps.def →
 * tools/command/native_package_resident_command.c), its accepted-artifact
 * authority (contexts/commons/services/src/package_resident.c over the zcode
 * package lifecycle), its snapshot/launch owner
 * (contexts/commons/services/src/package_resident_launch.c), and the shipped
 * resident app contexts/commons/packages/ztasks. This group drives that REAL
 * product path end to end:
 *
 *   a. an accepted-artifact record (installed receipt → positioned-file
 *      triple + image SHA3) is produced by the production lifecycle and
 *      re-derived from product state at invocation time;
 *   b. a resident launch of that exact record verifies the mapped image;
 *   c. the child speaks z23-res-run-v1 frames on fd 3 (READY gate + one
 *      bounded input frame + one bounded result frame);
 *   d. the child's result is observable through the product reply;
 *   e. cancel/reap works (an unresponsive resident is refused inside the
 *      consumer's own bound and leaves no child behind);
 *   f. rollback restores the prior accepted version after a failed
 *      candidate — NOT WIRED in C's slice: the leaf is one bounded explicit
 *      invocation with no product-held serving-generation record, so there
 *      is nothing to supersede or atomically restore. Stage f stays RED and
 *      names that missing wiring (see the stage f block below).
 *
 * Stage 0 is NOT the contract: it validates this file's reference child
 * fixture through the platform seam alone, speaking exactly the wire of C's
 * shipped ztasks child, so the bytes the consumer exchanges are proven
 * bytes, not guesses.
 */
#include "test/test_core.h"

#include "base/hex.h"
#include "config/command_catalog.h"
#include "core/uint256.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "keys/key.h"
#include "keys/pubkey.h"
#include "platform/positioned_file.h"
#include "platform/resident_launch.h"
#include "services/package_lifecycle.h"
#include "services/package_resident.h"
#include "sha3/sha3.h"
#include "vcs/package_build.h"
#include "vcs/package_manifest.h"
#include "vcs/package_recipe.h"
#include "vcs/package_release.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#if !defined(_WIN32)
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

/* ── THE ADAPTER SEAM ─────────────────────────────────────────────────────
 * RLC_LEAF is the ONE name this contract depends on: the composition command
 * leaf that is the product consumer of platform/resident_launch.h. Per fleet
 * agreement 2026-09-14 (C mail 397/399, A ACK 400) the consumer is
 * app.invoke.package, owned by C, and it LANDED in this integration lane
 * (C patch 277ee6a3…, grant fix e7cf550e…). If the consumer ever moves,
 * change THIS ONE CONSTANT — no other product name is hardcoded here.
 *
 * The invocation contract is C's CONCRETE schema (renegotiated here per the
 * fleet agreement, replacing this file's original placeholder keys):
 *   input keys:  datadir (string: the zcode lifecycle datadir that owns the
 *                installed receipt), package_root (string, 64 lower-hex),
 *                receipt_id (string, 64 lower-hex: the exact installed build
 *                receipt), artifact_sha3 (string, 64 lower-hex: the receipt
 *                output digest the operator explicitly accepts), program
 *                (string: the exact install-relative receipt output, must be
 *                under bin/), input_text (string, ≤1024: the one bounded
 *                command frame), accept_execution (JSON boolean true — a
 *                string/number is refused by the registry's leaf-scoped bool
 *                rule; building or installing never grants execution).
 *   child side:  the launch nonce reaches the child as argv[2]
 *                (`<snapshot> --resident <nonce>`, empty environment); the
 *                child answers one READY frame, reads one z23-res-run-v1
 *                input frame, and answers one z23-res-run-v1 result frame on
 *                fd 3 (RESIDENT_LAUNCH_CHILD_FD).
 *   reply data:  artifact_sha3, program, result (the child's payload),
 *                mapped_proof, nonce, pid, start_token, verification_us,
 *                first_result_us, completed_us, child_reaped, next_action.
 *                Failure replies carry NO data.pid: the bounded invocation
 *                cancels and reaps BEFORE replying, so stage e proves the
 *                reap process-level (no waitable child remains), never from
 *                a reply field.
 *   semantics:   ONE bounded invocation — verify, snapshot, spawn, READY,
 *                one frame in, one frame out, cancel/reap. There is no
 *                long-lived resident and no product-held accepted-version
 *                record: every invocation names its exact receipt. Rollback
 *                today is the OPERATOR explicitly invoking a prior accepted
 *                receipt (next_action says so); serving-generation
 *                supersession and atomic rollback are NOT WIRED (stage f). */
#define RLC_LEAF "app.invoke.package"

#define RLC_CHECK(name, expr) do {                                        \
    printf("resident_launch_contract: %s... ", (name));                   \
    fflush(stdout);                                                       \
    if (expr) printf("OK\n");                                             \
    else { printf("FAIL\n"); failures++; }                                \
} while (0)

/* The one root-cause line printed when every stage fails for the same
 * reason: the product consumer does not exist in this tree. */
static void rlc_explain_absent(void)
{
    printf("resident_launch_contract: MISSING PRODUCT CONSUMER — no "
           "composition leaf '" RLC_LEAF "' is registered in the command "
           "catalog, so resident_launch has no product path: stages a–f "
           "above name the acceptance contract the consumer must satisfy "
           "(see the ADAPTER SEAM block in "
           "tests/harness/src/test_resident_launch_contract.c)\n");
}

/* False (and one named FAIL line) when the consumer leaf is absent, so a
 * blocked stage still reports which contract stage is unproven. */
static bool rlc_have_leaf(const struct zcl_command_spec *spec,
                          const char *stage)
{
    if (spec && spec->handler) return true;
    printf("resident_launch_contract: stage %s... FAIL (blocked: consumer "
           "leaf '" RLC_LEAF "' absent from the composition catalog)\n",
           stage);
    return false;
}

/* ── one in-process leaf invocation (the test_dev_orient idiom) ────────── */

struct rlc_call {
    struct json_value input;
    struct zcl_command_request request;
    struct zcl_command_reply reply;
};

static void rlc_begin(struct rlc_call *c, const struct zcl_command_spec *spec)
{
    memset(c, 0, sizeof(*c));
    json_set_object(&c->input);
    c->request.input = &c->input;
    c->request.spec = spec;
    zcl_command_reply_init(&c->reply, "zcl.package_resident.v1");
}

/* Crosses the REAL registry validator first: an input key the leaf never
 * declared fails here with the leaf's own reason, not in a shell later. */
static bool rlc_invoke(struct rlc_call *c)
{
    char why[192];
    if (!zcl_command_registry_input_validate(c->request.spec, &c->input,
                                             why, sizeof(why))) {
        printf("[contract input rejected by the leaf's own validator: %s] ",
               why);
        return false;
    }
    c->request.spec->handler(&c->request, &c->reply);
    return true;
}

static void rlc_end(struct rlc_call *c)
{
    zcl_command_reply_free(&c->reply);
    json_free(&c->input);
}

static bool rlc_ok(const struct rlc_call *c)
{
    return c->reply.status == ZCL_COMMAND_STATUS_PASSED;
}

/* ── stage a: production accepted-artifact producer ────────────────────── */

static int rlc_stage_a(const struct zcl_command_spec *spec)
{
    int failures = 0;
    RLC_CHECK("stage a: production accepted-artifact producer — leaf '"
              RLC_LEAF "' registered with a native handler",
              spec && spec->handler);
    return failures;
}

#if !defined(_WIN32)

static const char *rlc_str(const struct rlc_call *c, const char *key)
{
    const struct json_value *v = json_get(&c->reply.data, key);
    return v && v->type == JSON_STR && json_get_str(v) ? json_get_str(v) : "";
}

static long long rlc_int(const struct rlc_call *c, const char *key)
{
    const struct json_value *v = json_get(&c->reply.data, key);
    return v && v->type == JSON_INT ? (long long)json_get_int(v) : -1;
}

static bool rlc_bool(const struct rlc_call *c, const char *key)
{
    const struct json_value *v = json_get(&c->reply.data, key);
    return v && v->type == JSON_BOOL && json_get_bool(v);
}

static bool rlc_hex64(const char *s)
{
    if (strlen(s) != 64) return false;
    for (size_t i = 0; i < 64; i++) {
        char ch = s[i];
        if ((ch < '0' || ch > '9') && (ch < 'a' || ch > 'f')) return false;
    }
    return true;
}

/* ── reference fixtures ─────────────────────────────────────────────────── */

/* The reference children are REAL ELF images built by the Makefile from
 * tests/harness/fixtures/resident_launch_contract_child.c and carried as
 * order-only prerequisites of every test binary, so a missing image is a
 * broken build, never a skip. A script cannot be the resident image: the
 * pinned descriptor is O_CLOEXEC, and fexecve of a shebang script re-opens
 * /dev/fd/N for the interpreter AFTER exec closed it (ENOENT on Linux).
 * rlc_child_v1 speaks exactly the landed consumer's wire (nonce as argv[2],
 * READY, one run frame round-trip; argv[3] "park" parks forever as the
 * cancel target); rlc_child_broken exits 1 without framing — the candidate
 * the READY gate must refuse. Paths are relative to the repository root,
 * the runner's cwd (the RB_SO_A idiom in test_hotswap_rollback.c). */
#define RLC_FIXTURE_CHILD "build/fixtures/rlc_child_v1"
#define RLC_FIXTURE_BROKEN "build/fixtures/rlc_child_broken"

static bool rlc_executable(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0 && (st.st_mode & 0111) != 0;
}

/* Capture the acceptance record for a file as it stands right now (the
 * test_resident_launch.c idiom: positioned-file triple + SHA3 through the
 * handle). */
static bool rlc_accept_of(const char *path, struct resident_launch_accepted *a)
{
    struct platform_positioned_file file;
    struct platform_positioned_file_snapshot snap;
    platform_positioned_file_init(&file);
    if (!platform_positioned_file_open(&file, path) ||
        !platform_positioned_file_snapshot(&file, &snap)) {
        platform_positioned_file_close(&file);
        return false;
    }
    unsigned char digest[32];
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    unsigned char chunk[4096];
    uint64_t offset = 0;
    for (;;) {
        int64_t got = platform_positioned_file_read(&file, chunk,
                                                    sizeof(chunk), offset);
        if (got < 0) { platform_positioned_file_close(&file); return false; }
        if (got == 0) break;
        sha3_256_write(&ctx, chunk, (size_t)got);
        offset += (uint64_t)got;
    }
    sha3_256_finalize(&ctx, digest);
    platform_positioned_file_close(&file);
    zcl_hex_encode(digest, sizeof(digest), a->image_sha3_hex);
    a->image_volume = snap.volume;
    a->image_low = snap.file_low;
    a->image_high = snap.file_high;
    a->image_size = snap.size;
    return true;
}

static bool rlc_wait_reaped(uint64_t pid)
{
    return waitpid((pid_t)pid, NULL, WNOHANG) == -1 && errno == ECHILD;
}

/* No child of this process remains, alive or zombie: the process-level reap
 * proof for the consumer's bounded invocation (failure replies carry no
 * data.pid by design — see the ADAPTER SEAM). */
static bool rlc_no_children(void)
{
    return waitpid(-1, NULL, WNOHANG) == -1 && errno == ECHILD;
}

/* Parent-side write of one z23-res-run-v1 frame, mirroring the consumer's
 * npr_exchange (header + payload, nonce-bound). */
static bool rlc_send_frame(struct resident_launch *launch, const char *text)
{
    struct resident_result_header header;
    memset(&header, 0, sizeof(header));
    (void)snprintf(header.magic, sizeof(header.magic), "%s", "z23-res-run-v1");
    (void)snprintf(header.nonce, sizeof(header.nonce), "%s", launch->nonce);
    header.payload_len = (uint32_t)strlen(text);
    int fd = (int)launch->ipc_native;
    const unsigned char *parts[2] = { (const unsigned char *)&header,
                                      (const unsigned char *)text };
    size_t sizes[2] = { sizeof(header), header.payload_len };
    for (size_t p = 0; p < 2; p++) {
        for (size_t done = 0; done < sizes[p];) {
            ssize_t n = write(fd, parts[p] + done, sizes[p] - done);
            if (n < 0 && errno == EINTR) continue;
            if (n <= 0) return false;
            done += (size_t)n;
        }
    }
    return true;
}

/* ── the smallest real installed package fixtures ─────────────────────────
 * The consumer binds ONLY an exact installed receipt: the artifact digest
 * comes from the verified install receipt, never from whichever bytes occupy
 * a pathname. So the contract installs REAL packages through the production
 * zcode lifecycle (publish → plan → commit), exactly like test_zcode_add.c:
 *   - ztasks, C's shipped resident app, from its REAL bytes under
 *     contexts/commons/packages/ztasks/ (the same package C's Mac factory
 *     run installed; tarball sha256 304a984e… matches the patch bytes);
 *   - rlc/parker, a minimal resident program that answers READY then parks
 *     forever — the unresponsive candidate stage e must see refused inside
 *     the consumer's own bound with nothing left behind.
 * The e2e lane forks build/bin/zclassic23-package-verify-dev — it MUST
 * exist; a missing binary is a loud failure, never a silent skip. */

#define RLC_ZTASKS_DIR "contexts/commons/packages/ztasks"
#define RLC_ZTASKS_PROGRAM "bin/ztasks"
#define RLC_PARKER_PROGRAM "bin/parker"

static bool rlc_mkdir_p(const char *path)
{
    char buf[4096];
    size_t len = strlen(path);
    if (len == 0 || len >= sizeof(buf))
        return false;
    memcpy(buf, path, len + 1);
    for (char *p = buf + 1; *p; p++) {
        if (*p != '/')
            continue;
        *p = '\0';
        if (mkdir(buf, 0700) != 0 && errno != EEXIST)
            return false;
        *p = '/';
    }
    return mkdir(buf, 0700) == 0 || errno == EEXIST;
}

static bool rlc_write_file(const char *path, const void *data, size_t len)
{
    FILE *f = fopen(path, "wb");
    if (!f)
        return false;
    bool ok = len == 0 || fwrite(data, 1, len, f) == len;
    if (fclose(f) != 0)
        ok = false;
    if (ok && chmod(path, 0600) != 0)
        ok = false;
    return ok;
}

static char *rlc_slurp(const char *path, size_t *len_out)
{
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
    long size = ftell(f);
    if (size < 0 || fseek(f, 0, SEEK_SET) != 0) { fclose(f); return NULL; }
    char *buf = malloc((size_t)size + 1u);
    if (!buf) { fclose(f); return NULL; }
    bool ok = size == 0 || fread(buf, 1, (size_t)size, f) == (size_t)size;
    if (fclose(f) != 0) ok = false;
    if (!ok) { free(buf); return NULL; }
    buf[size] = '\0';
    *len_out = (size_t)size;
    return buf;
}

struct rlc_file {
    const char *path;
    const char *content;
    size_t len;
};

/* Publish one package (manifest + CAS chunks + recipe + signed release)
 * into <datadir>/zcode — the za_publish_ex idiom of test_zcode_add.c. */
static bool rlc_publish(const char *zcode, const char *name,
                        const char *semver, uint64_t sequence,
                        const struct rlc_file *files, size_t file_count,
                        const char *header_path, const char *source_path,
                        const char *test_path, const char *include_dir,
                        const char *program_path, uint8_t root_out[32])
{
    char dir[4400];
    const char *subs[] = { "manifests", "releases", "recipes", "cas/sha3" };
    for (size_t i = 0; i < 4; i++) {
        (void)snprintf(dir, sizeof(dir), "%s/%s", zcode, subs[i]);
        if (!rlc_mkdir_p(dir))
            return false;
    }

    struct vcs_package_manifest m;
    vcs_package_manifest_init(&m);
    bool ok = true;
    for (size_t i = 0; i < file_count && ok; i++) {
        uint8_t hash[32];
        struct sha3_256_ctx c;
        sha3_256_init(&c);
        sha3_256_write(&c, (const uint8_t *)files[i].content, files[i].len);
        sha3_256_finalize(&c, hash);
        ok = vcs_package_manifest_add(&m, files[i].path,
                                      VCS_PACKAGE_MODE_FILE, files[i].len,
                                      hash, 1);
        if (ok) {
            char hex[65];
            zcl_hex_encode(hash, 32, hex);
            char cdir[4400];
            char cpath[4500];
            (void)snprintf(cdir, sizeof(cdir), "%s/cas/sha3/%.2s", zcode, hex);
            (void)snprintf(cpath, sizeof(cpath), "%s/%s", cdir, hex);
            ok = rlc_mkdir_p(cdir) &&
                 rlc_write_file(cpath, files[i].content, files[i].len);
        }
    }
    if (ok)
        ok = vcs_package_manifest_root(&m, root_out);
    uint8_t *mwire = NULL;
    size_t mlen = 0;
    if (ok)
        ok = vcs_package_manifest_serialize(&m, &mwire, &mlen);
    vcs_package_manifest_free(&m);
    if (!ok)
        return false;
    char root_hex[65];
    zcl_hex_encode(root_out, 32, root_hex);
    char path[4500];
    (void)snprintf(path, sizeof(path), "%s/manifests/%s", zcode, root_hex);
    ok = rlc_write_file(path, mwire, mlen);
    free(mwire);
    if (!ok)
        return false;

    struct vcs_package_recipe r;
    vcs_package_recipe_init(&r);
    ok = vcs_package_recipe_add_header(&r, header_path, NULL);
    for (size_t i = 0; i < file_count && ok; i++) {
        size_t path_len = strlen(files[i].path);
        if (strcmp(files[i].path, header_path) != 0 && path_len > 2u &&
            strcmp(files[i].path + path_len - 2u, ".h") == 0)
            ok = vcs_package_recipe_add_header(&r, files[i].path, NULL);
    }
    ok = ok &&
         vcs_package_recipe_add_source(&r, source_path, NULL) &&
         vcs_package_recipe_add_test_source(&r, test_path, NULL) &&
         vcs_package_recipe_add_include_dir(&r, include_dir, NULL) &&
         vcs_package_recipe_add_library(&r, VCS_PACKAGE_RECIPE_LIB_LIBC,
                                        NULL) &&
         (!program_path ||
          vcs_package_recipe_add_program(&r, program_path, NULL));
    vcs_package_recipe_set_test_limits(&r, 0, 60,
                                       UINT64_C(64) * 1024u * 1024u);
    uint8_t recipe_root[32];
    uint8_t *rwire = NULL;
    size_t rlen = 0;
    if (ok)
        ok = vcs_package_recipe_root(&r, recipe_root) ==
                 VCS_PACKAGE_RECIPE_OK &&
             vcs_package_recipe_serialize(&r, &rwire, &rlen) ==
                 VCS_PACKAGE_RECIPE_OK;
    vcs_package_recipe_free(&r);
    if (!ok)
        return false;
    char rhex[65];
    zcl_hex_encode(recipe_root, 32, rhex);
    (void)snprintf(path, sizeof(path), "%s/recipes/%s", zcode, rhex);
    ok = rlc_write_file(path, rwire, rlen);
    free(rwire);
    if (!ok)
        return false;

    struct privkey sk;
    struct pubkey pk;
    memset(sk.vch, 0x11, 32);
    sk.fValid = true;
    sk.fCompressed = true;
    if (!privkey_get_pubkey(&sk, &pk))
        return false;
    struct vcs_package_release rel;
    memset(&rel, 0, sizeof(rel));
    rel.schema_version = VCS_PACKAGE_RELEASE_VERSION;
    (void)snprintf(rel.name, sizeof(rel.name), "%s", name);
    (void)snprintf(rel.semver, sizeof(rel.semver), "%s", semver);
    memcpy(rel.package_root, root_out, 32);
    memcpy(rel.publisher_pubkey, pk.vch, COMPRESSED_PUBLIC_KEY_SIZE);
    rel.publisher_sequence = sequence;
    (void)snprintf(rel.reward_address, sizeof(rel.reward_address), "t1fixture");
    (void)snprintf(rel.license, sizeof(rel.license), "Apache-2.0");
    memcpy(rel.recipe_root, recipe_root, 32);
    (void)snprintf(rel.chain_id, sizeof(rel.chain_id), "zclassic-main");
    uint8_t id[VCS_PACKAGE_RELEASE_ID_BYTES];
    if (vcs_package_release_id(&rel, id) != VCS_PACKAGE_RELEASE_OK)
        return false;
    struct uint256 h;
    memcpy(h.data, id, 32);
    unsigned char compact[COMPACT_SIGNATURE_SIZE];
    if (!privkey_sign_compact(&sk, &h, compact))
        return false;
    memcpy(rel.signature, compact + 1, VCS_PACKAGE_RELEASE_SIGNATURE_BYTES);
    uint8_t *relwire = NULL;
    size_t rellen = 0;
    if (vcs_package_release_serialize(&rel, &relwire, &rellen) !=
        VCS_PACKAGE_RELEASE_OK)
        return false;
    char id_hex[65];
    zcl_hex_encode(id, 32, id_hex);
    (void)snprintf(path, sizeof(path), "%s/releases/%s", zcode, id_hex);
    ok = rlc_write_file(path, relwire, rellen);
    free(relwire);
    return ok;
}

/* Plan + commit one published package through the REAL production lifecycle,
 * then bind the exact installed receipt: installed_inspect names the filed
 * receipt id and receipt_read re-derives the accepted program digest. This
 * is the production accepted-artifact producer the contract asserts on. */
static bool rlc_install(const char *base, const char *name,
                        const uint8_t root[32], const char *program,
                        uint8_t receipt_id_out[32],
                        char artifact_sha3_out[65])
{
    const int64_t t0 = 1700000000;
    struct package_lifecycle_plan_report plan;
    struct zcl_result r = package_lifecycle_plan(base, name, t0, &plan);
    if (!r.ok || !plan.ready) {
        printf("[plan for %s failed: rule=%s msg=%s] ", name, plan.rule,
               r.ok ? "<none>" : r.message);
        return false;
    }
    struct package_lifecycle_commit_report commit;
    struct zcl_result cr =
        package_lifecycle_commit(base, plan.plan_id, t0 + 1, &commit);
    if (!cr.ok || !commit.installed) {
        printf("[commit for %s failed: rule=%s detail=%s msg=%s] ", name,
               commit.rule, commit.detail, cr.ok ? "<none>" : cr.message);
        return false;
    }
    struct package_lifecycle_step step;
    bool installed = false;
    struct zcl_result ir =
        package_lifecycle_installed_inspect(base, root, &step, &installed);
    if (!ir.ok || !installed || !step.has_receipt)
        return false;
    memcpy(receipt_id_out, step.receipt_id, 32);
    struct vcs_package_build_receipt receipt;
    memset(&receipt, 0, sizeof(receipt));
    struct zcl_result rr =
        package_lifecycle_receipt_read(base, receipt_id_out, &receipt);
    if (!rr.ok || !vcs_package_build_installable(&receipt))
        return false;
    for (size_t i = 0; i < receipt.output_count; ++i) {
        if (strcmp(receipt.outputs[i].path, program) == 0) {
            zcl_hex_encode(receipt.outputs[i].sha3, 32, artifact_sha3_out);
            return true;
        }
    }
    return false;
}

/* The parker's resident program: answers READY under the nonce, then parks
 * forever — the unresponsive candidate the consumer's bounded result wait
 * must refuse, leaving no child behind. */
#define RLC_PARKER_MAIN \
    "#include <stdint.h>\n" \
    "#include <string.h>\n" \
    "#include <unistd.h>\n" \
    "struct parker_frame { char magic[16]; char nonce[65]; uint32_t len; };\n" \
    "int main(int argc, char **argv) {\n" \
    "  if (argc != 3 || strcmp(argv[1], \"--resident\") != 0) return 2;\n" \
    "  if (strlen(argv[2]) != 64) return 2;\n" \
    "  struct parker_frame frame;\n" \
    "  memset(&frame, 0, sizeof(frame));\n" \
    "  memcpy(frame.magic, \"z23-res-run-v1\", sizeof(\"z23-res-run-v1\"));\n" \
    "  memcpy(frame.nonce, argv[2], 64);\n" \
    "  frame.len = 5;\n" \
    "  if (write(3, &frame, sizeof(frame)) != (ssize_t)sizeof(frame)) return 3;\n" \
    "  if (write(3, \"READY\", 5) != 5) return 3;\n" \
    "  for (;;) pause();\n" \
    "}\n"

#define RLC_PARKER_H \
    "#pragma once\n" \
    "int parker_answer(void);\n"

#define RLC_PARKER_C \
    "#include \"parker.h\"\n" \
    "int parker_answer(void){ return 42; }\n"

#define RLC_PARKER_TEST \
    "#include \"parker.h\"\n" \
    "int main(void){ return parker_answer() == 42 ? 0 : 1; }\n"

#define RLC_LICENSE "Apache License 2.0\n\nLicensed under the Apache License...\n"

/* Publish + install both fixture packages into one zcode store. Returns the
 * ztasks binding the run stages invoke. */
static bool rlc_install_fixtures(const char *base, const char *zcode,
                                 uint8_t ztasks_root[32],
                                 uint8_t ztasks_receipt[32],
                                 char ztasks_sha3[65],
                                 uint8_t parker_root[32],
                                 uint8_t parker_receipt[32],
                                 char parker_sha3[65])
{
    if (!rlc_mkdir_p(zcode)) {
        printf("[cannot create the fixture zcode store] ");
        return false;
    }
    if (!rlc_executable("build/bin/zclassic23-package-verify-dev")) {
        printf("[build/bin/zclassic23-package-verify-dev missing "
               "(make dev-bin) — loud failure, never a skip] ");
        return false;
    }

    const char *const ztasks_paths[] = {
        "LICENSE", "README.md", "app/main.c", "include/ztasks/ztasks.h",
        "src/ztasks.c", "tests/test_ztasks.c",
    };
    struct rlc_file ztasks_files[6];
    for (size_t i = 0; i < 6; i++) {
        char path[512];
        (void)snprintf(path, sizeof(path), "%s/%s", RLC_ZTASKS_DIR,
                       ztasks_paths[i]);
        ztasks_files[i].path = ztasks_paths[i];
        ztasks_files[i].content = rlc_slurp(path, &ztasks_files[i].len);
        if (!ztasks_files[i].content) {
            printf("[cannot read the real ztasks package byte %s] ", path);
            for (size_t j = 0; j < i; j++)
                free((void *)ztasks_files[j].content);
            return false;
        }
    }
    bool published = rlc_publish(zcode, "ztasks/ztasks", "0.2.0", 1,
                                 ztasks_files, 6, "include/ztasks/ztasks.h",
                                 "src/ztasks.c", "tests/test_ztasks.c",
                                 "include", "app/main.c", ztasks_root);
    for (size_t i = 0; i < 6; i++)
        free((void *)ztasks_files[i].content);
    if (!published) {
        printf("[ztasks publish failed] ");
        return false;
    }
    if (!rlc_install(base, "ztasks/ztasks", ztasks_root, RLC_ZTASKS_PROGRAM,
                     ztasks_receipt, ztasks_sha3)) {
        printf("[ztasks install/bind failed] ");
        return false;
    }

    const struct rlc_file parker_files[] = {
        { "LICENSE", RLC_LICENSE, sizeof(RLC_LICENSE) - 1u },
        { "src/parker.h", RLC_PARKER_H, sizeof(RLC_PARKER_H) - 1u },
        { "src/parker.c", RLC_PARKER_C, sizeof(RLC_PARKER_C) - 1u },
        { "test/test_parker.c", RLC_PARKER_TEST, sizeof(RLC_PARKER_TEST) - 1u },
        { "app/main.c", RLC_PARKER_MAIN, sizeof(RLC_PARKER_MAIN) - 1u },
    };
    if (!rlc_publish(zcode, "rlc/parker", "0.1.0", 2, parker_files, 5,
                     "src/parker.h", "src/parker.c", "test/test_parker.c",
                     "src", "app/main.c", parker_root)) {
        printf("[parker publish failed] ");
        return false;
    }
    if (!rlc_install(base, "rlc/parker", parker_root, RLC_PARKER_PROGRAM,
                     parker_receipt, parker_sha3)) {
        printf("[parker install/bind failed] ");
        return false;
    }
    return true;
}

/* One explicit consumer invocation under C's concrete schema (see the
 * ADAPTER SEAM): every key named, accept_execution a JSON boolean. */
static void rlc_call_package(struct rlc_call *c,
                             const struct zcl_command_spec *spec,
                             const char *datadir, const char *root_hex,
                             const char *receipt_hex, const char *sha3_hex,
                             const char *program, const char *input_text)
{
    rlc_begin(c, spec);
    (void)json_push_kv_str(&c->input, "datadir", datadir);
    (void)json_push_kv_str(&c->input, "package_root", root_hex);
    (void)json_push_kv_str(&c->input, "receipt_id", receipt_hex);
    (void)json_push_kv_str(&c->input, "artifact_sha3", sha3_hex);
    (void)json_push_kv_str(&c->input, "program", program);
    (void)json_push_kv_str(&c->input, "input_text", input_text);
    (void)json_push_kv_bool(&c->input, "accept_execution", true);
}

/* ── stage 0: reference-child fixture self-check (platform seam only) ─────
 * Green today: proves the fixture above speaks the exact wire bytes of the
 * landed consumer (READY gate, one nonce-bound run frame round-trip,
 * cancel/reap) through the real resident_launch seam. NOT part of the
 * product contract. */
static int rlc_fixture_selfcheck(const char *child,
                                 const struct resident_launch_accepted *acc)
{
    int failures = 0;
    char error[RESIDENT_LAUNCH_ERROR_MAX];
    struct resident_launch launch;
    resident_launch_init(&launch);
    error[0] = '\0';
    RLC_CHECK("stage 0 (fixture): prepare the reference child",
              resident_launch_prepare(&launch, child, acc, error,
                                      sizeof(error)));
    char *const argv[] = {(char *)child, (char *)"--resident",
                          launch.nonce, NULL};
    char *const envp[] = {NULL};
    struct resident_receipt receipt;
    memset(&receipt, 0, sizeof(receipt));
    error[0] = '\0';
    bool spawned = resident_launch_spawn(&launch, argv, envp, &receipt, error,
                                         sizeof(error));
    if (!spawned)
        printf("[spawn error: %s (errno=%d)] ", error[0] ? error : "<none>",
               errno);
    RLC_CHECK("stage 0 (fixture): spawn maps the exact accepted image",
              spawned);
    struct resident_result_header header;
    unsigned char payload[128];
    error[0] = '\0';
    RLC_CHECK("stage 0 (fixture): READY frame accepted under the nonce",
              resident_result_read(&launch, &header, payload, sizeof(payload),
                                   5000, error, sizeof(error)) &&
              header.payload_len == 5 &&
              memcmp(payload, "READY", 5) == 0);
    error[0] = '\0';
    RLC_CHECK("stage 0 (fixture): one run frame round-trips the exact "
              "payload",
              rlc_send_frame(&launch, "fixture-roundtrip") &&
              resident_result_read(&launch, &header, payload, sizeof(payload),
                                   5000, error, sizeof(error)) &&
              header.payload_len == strlen("fixture-roundtrip") &&
              memcmp(payload, "fixture-roundtrip",
                     strlen("fixture-roundtrip")) == 0);
    error[0] = '\0';
    RLC_CHECK("stage 0 (fixture): cancel reaps the reference child",
              resident_launch_cancel(&launch, 300, error, sizeof(error)) &&
              rlc_wait_reaped(receipt.pid));
    resident_launch_close(&launch);

    /* The parking variant: READY, then unresponsive — cancel must still
     * reap it inside the budget. */
    resident_launch_init(&launch);
    error[0] = '\0';
    bool parked = resident_launch_prepare(&launch, child, acc, error,
                                          sizeof(error));
    char *const park_argv[] = {(char *)child, (char *)"--resident",
                               launch.nonce, (char *)"park", NULL};
    error[0] = '\0';
    parked = parked &&
        resident_launch_spawn(&launch, park_argv, envp, &receipt, error,
                              sizeof(error)) &&
        resident_result_read(&launch, &header, payload, sizeof(payload),
                             5000, error, sizeof(error)) &&
        header.payload_len == 5 && memcmp(payload, "READY", 5) == 0;
    RLC_CHECK("stage 0 (fixture): the parking child passes the READY gate",
              parked);
    error[0] = '\0';
    RLC_CHECK("stage 0 (fixture): cancel reaps an unresponsive resident",
              resident_launch_cancel(&launch, 300, error, sizeof(error)) &&
              rlc_wait_reaped(receipt.pid));
    resident_launch_close(&launch);

    /* The broken candidate: exits without framing, so the READY gate must
     * refuse it — the wire-level refusal the consumer's READY read applies
     * to any installed program that does not speak the protocol. */
    struct resident_launch_accepted broken_acc;
    bool have_broken = rlc_accept_of(RLC_FIXTURE_BROKEN, &broken_acc);
    resident_launch_init(&launch);
    error[0] = '\0';
    bool broken_refused = have_broken &&
        resident_launch_prepare(&launch, RLC_FIXTURE_BROKEN, &broken_acc,
                                error, sizeof(error));
    char *const broken_argv[] = {(char *)RLC_FIXTURE_BROKEN,
                                 (char *)"--resident", launch.nonce, NULL};
    error[0] = '\0';
    broken_refused = broken_refused &&
        resident_launch_spawn(&launch, broken_argv, envp, &receipt, error,
                              sizeof(error));
    error[0] = '\0';
    broken_refused = broken_refused &&
        !resident_result_read(&launch, &header, payload, sizeof(payload),
                              5000, error, sizeof(error));
    RLC_CHECK("stage 0 (fixture): the READY gate refuses a child that "
              "never frames",
              broken_refused);
    error[0] = '\0';
    RLC_CHECK("stage 0 (fixture): cancel reaps the refused child",
              resident_launch_cancel(&launch, 300, error, sizeof(error)) &&
              rlc_wait_reaped(receipt.pid));
    resident_launch_close(&launch);
    return failures;
}

/* ── stages b/c/d: verified launch, fd-3 frame, observable result ──────── */

static int rlc_stage_run(const struct zcl_command_spec *spec,
                         const char *datadir, const char *root_hex,
                         const char *receipt_hex, const char *sha3_hex)
{
    int failures = 0;
    if (!rlc_have_leaf(spec, "b/c/d: verified launch, fd-3 frame protocol, "
                       "observable result"))
        return 1;
    struct rlc_call c;
    rlc_call_package(&c, spec, datadir, root_hex, receipt_hex, sha3_hex,
                     RLC_ZTASKS_PROGRAM, "list");
    bool ran = rlc_invoke(&c);
    if (ran && !rlc_ok(&c))
        printf("[invocation refused: code=%s message=%s] ",
               c.reply.error.code, c.reply.error.message);
    RLC_CHECK("stage b: the launch verified the mapped image (accepted "
              "digest + mapped proof + launch nonce in the receipt)",
              ran && rlc_ok(&c) &&
              strcmp(rlc_str(&c, "artifact_sha3"), sha3_hex) == 0 &&
              (strcmp(rlc_str(&c, "mapped_proof"), "fexecve_inode") == 0 ||
               strcmp(rlc_str(&c, "mapped_proof"), "proc_exe_triple") == 0 ||
               strcmp(rlc_str(&c, "mapped_proof"), "cdhash_suspended") == 0) &&
              rlc_hex64(rlc_str(&c, "nonce")) &&
              rlc_int(&c, "start_token") > 0);
    RLC_CHECK("stage c: the child spoke z23-res-run-v1 on fd 3 (READY gate "
              "+ one bounded frame round-trip: empty list renders exactly)",
              ran && rlc_ok(&c) &&
              strcmp(rlc_str(&c, "result"), "No tasks yet.\n") == 0);
    RLC_CHECK("stage d: the result is observable through the product reply "
              "(payload + resident pid + bounded timings + reaped child)",
              ran && rlc_ok(&c) && rlc_str(&c, "result")[0] &&
              strcmp(rlc_str(&c, "program"), RLC_ZTASKS_PROGRAM) == 0 &&
              rlc_int(&c, "pid") > 0 &&
              rlc_int(&c, "verification_us") >= 0 &&
              rlc_int(&c, "first_result_us") >= 0 &&
              rlc_int(&c, "completed_us") >= 0 &&
              rlc_bool(&c, "child_reaped") &&
              rlc_str(&c, "next_action")[0]);
    if (ran && rlc_ok(&c))
        printf("resident_launch_contract: invocation timings "
               "verification_us=%lld first_result_us=%lld "
               "completed_us=%lld mapped_proof=%s\n",
               rlc_int(&c, "verification_us"),
               rlc_int(&c, "first_result_us"),
               rlc_int(&c, "completed_us"), rlc_str(&c, "mapped_proof"));
    rlc_end(&c);

    /* A second explicit one-shot: state is per-invocation by design, so
     * "add" renders exactly its own fresh state. */
    struct rlc_call add;
    rlc_call_package(&add, spec, datadir, root_hex, receipt_hex, sha3_hex,
                     RLC_ZTASKS_PROGRAM, "add ship the consumer");
    bool ran_add = rlc_invoke(&add);
    RLC_CHECK("stage d: a second bounded invocation returns its own exact "
              "render (no hidden cross-invocation state)",
              ran_add && rlc_ok(&add) &&
              strcmp(rlc_str(&add, "result"),
                     "1 [TODO] ship the consumer\n") == 0);
    rlc_end(&add);
    return failures;
}

/* ── stage f: rollback restores the prior accepted version ───────────────
 * NOT WIRED in C's slice, and this stage stays RED until it is. C's leaf is
 * ONE bounded explicit invocation: the operator names the exact package,
 * receipt and digest every time. There is no product-held serving
 * generation, so after a failed candidate there is nothing the product can
 * supersede or atomically restore — rollback today is the OPERATOR
 * explicitly invoking a prior accepted receipt (the reply's next_action
 * says exactly that). Per C's own warning, re-invoking a prior root is NOT
 * atomic rollback proof, so this stage does not accept one: the two RED
 * checks below name the missing wiring, and the one green check is labeled
 * for exactly what it is — a failed candidate changing no installed
 * receipt. */
static int rlc_stage_rollback(const struct zcl_command_spec *spec,
                              const char *datadir, const char *root_hex,
                              const char *receipt_hex, const char *sha3_hex,
                              const struct rlc_call *failed_candidate)
{
    int failures = 0;
    if (!rlc_have_leaf(spec, "f: rollback to the prior accepted version"))
        return 1;

    /* RED — missing wiring #1: no serving-generation record. The product
     * cannot run "the currently accepted version" because it holds no
     * accepted-version record at all: an invocation that names no exact
     * package/receipt/program is refused by the leaf's own input rule.
     * When supersession lands, an invocation naming only the app must
     * serve the product-held current accepted record. */
    struct rlc_call current;
    rlc_begin(&current, spec);
    (void)json_push_kv_str(&current.input, "datadir", datadir);
    (void)json_push_kv_bool(&current.input, "accept_execution", true);
    bool ran_current = rlc_invoke(&current);
    printf("resident_launch_contract: MISSING WIRING (stage f, red by "
           "contract): serving-generation supersession — the consumer holds "
           "no accepted-version record; it binds only an explicitly named "
           "receipt, so 'run the current accepted version' is refused "
           "(code=%s). Rollback today = the operator explicitly invokes a "
           "prior accepted receipt.\n",
           ran_current ? current.reply.error.code : "<validator>");
    RLC_CHECK("stage f: the product serves its held current accepted "
              "version without re-naming the receipt (serving-generation "
              "supersession — NOT WIRED)",
              ran_current && rlc_ok(&current));
    rlc_end(&current);

    /* RED — missing wiring #2: atomic rollback evidence. A failed
     * candidate's refusal cannot name the still-accepted prior digest:
     * with no generation record there is no "prior" for the evidence to
     * reference. */
    printf("resident_launch_contract: MISSING WIRING (stage f, red by "
           "contract): atomic rollback — a failed candidate's evidence does "
           "not name the prior accepted digest, and no product state was "
           "superseded or restored; rerunning a prior root by hand is not "
           "atomic rollback proof (C's own warning).\n");
    RLC_CHECK("stage f: a failed candidate is refused naming the "
              "still-accepted version (atomic rollback evidence — NOT "
              "WIRED)",
              failed_candidate && !rlc_ok(failed_candidate) &&
              strstr(failed_candidate->reply.error.evidence, sha3_hex) !=
                  NULL);

    /* GREEN, labeled for exactly what it is: C's bounded invocation never
     * mutates package state, so the failed candidate left the ztasks
     * install bit-identical — proven by re-deriving the accepted artifact
     * from the installed receipt and by an EXPLICIT re-invocation naming
     * the same receipt. This is not rollback: nothing rolled. */
    uint8_t root_bin[32], receipt_bin[32];
    bool bound = zcl_hex_decode_lower(root_hex, root_bin, 32) &&
                 zcl_hex_decode_lower(receipt_hex, receipt_bin, 32);
    struct package_resident_artifact artifact;
    struct zcl_result ar = bound
        ? package_resident_artifact_read(datadir, root_bin, receipt_bin,
                                         RLC_ZTASKS_PROGRAM, &artifact)
        : ZCL_ERR(-1, "fixture hex");
    RLC_CHECK("stage f (labeled): a failed candidate changes no installed "
              "receipt — the accepted artifact re-derives from product "
              "state with the same digest (NOT rollback proof)",
              bound && ar.ok &&
              strcmp(artifact.accepted.image_sha3_hex, sha3_hex) == 0);
    struct rlc_call again;
    rlc_call_package(&again, spec, datadir, root_hex, receipt_hex, sha3_hex,
                     RLC_ZTASKS_PROGRAM, "list");
    bool ran_again = rlc_invoke(&again);
    RLC_CHECK("stage f (labeled): the prior receipt still explicitly "
              "invokes after the failed candidate (operator re-invocation, "
              "NOT rollback proof)",
              ran_again && rlc_ok(&again) &&
              strcmp(rlc_str(&again, "result"), "No tasks yet.\n") == 0);
    rlc_end(&again);
    return failures;
}

#endif /* !defined(_WIN32) */

int test_resident_launch_contract(void)
{
    int failures = 0;
    const struct zcl_command_spec *spec =
        zcl_command_registry_find(zcl_command_catalog(), RLC_LEAF, NULL);
#if defined(_WIN32)
    /* No descriptor-bound exec on Windows: the leaf exists, so every run
     * stage must refuse by name there, exactly like resident_launch_prepare. */
    failures += rlc_stage_a(spec);
    if (!rlc_have_leaf(spec, "b–f: platform-refused on Windows, blocked on "
                       "the absent consumer leaf")) {
        failures += 5;
    } else {
        struct rlc_call c;
        rlc_begin(&c, spec);
        (void)json_push_kv_str(&c.input, "datadir", "no-such-datadir");
        (void)json_push_kv_str(&c.input, "package_root",
            "0000000000000000000000000000000000000000000000000000000000000000");
        (void)json_push_kv_str(&c.input, "receipt_id",
            "0000000000000000000000000000000000000000000000000000000000000000");
        (void)json_push_kv_str(&c.input, "artifact_sha3",
            "0000000000000000000000000000000000000000000000000000000000000000");
        (void)json_push_kv_str(&c.input, "program", "bin/x");
        (void)json_push_kv_str(&c.input, "input_text", "list");
        (void)json_push_kv_bool(&c.input, "accept_execution", true);
        bool ran = rlc_invoke(&c);
        RLC_CHECK("stages b–f: Windows refuses the resident launch by name",
                  ran && !rlc_ok(&c) && c.reply.error.code[0]);
        rlc_end(&c);
    }
#else
    const char *child = RLC_FIXTURE_CHILD;
    const char *broken = RLC_FIXTURE_BROKEN;
    RLC_CHECK("the fixture children are built (Makefile order-only "
              "prerequisite, never a skip)",
              rlc_executable(child) && rlc_executable(broken));
    struct resident_launch_accepted child_acc;
    RLC_CHECK("capture the reference child's accepted record",
              rlc_accept_of(child, &child_acc));

    /* The fixture datadir is the zcode lifecycle store the consumer binds
     * its accepted-artifact records from; the reference ELF fixtures
     * themselves live in build/. */
    char base[256];
    test_make_tmpdir(base, sizeof(base), "resident_launch_contract", "x");
    char zcode[4400];
    (void)snprintf(zcode, sizeof(zcode), "%s/zcode", base);
    failures += rlc_fixture_selfcheck(child, &child_acc);
    failures += rlc_stage_a(spec);

    uint8_t ztasks_root[32], ztasks_receipt[32];
    uint8_t parker_root[32], parker_receipt[32];
    char ztasks_sha3[65] = {0}, parker_sha3[65] = {0};
    char ztasks_root_hex[65] = {0}, ztasks_receipt_hex[65] = {0};
    char parker_root_hex[65] = {0}, parker_receipt_hex[65] = {0};
    bool installed =
        rlc_install_fixtures(base, zcode, ztasks_root, ztasks_receipt,
                             ztasks_sha3, parker_root, parker_receipt,
                             parker_sha3);
    RLC_CHECK("stage a (deep): the production lifecycle installed REAL "
              "packages and filed their accepted receipts (product state, "
              "never test scaffolding)",
              installed);
    if (installed) {
        zcl_hex_encode(ztasks_root, 32, ztasks_root_hex);
        zcl_hex_encode(ztasks_receipt, 32, ztasks_receipt_hex);
        zcl_hex_encode(parker_root, 32, parker_root_hex);
        zcl_hex_encode(parker_receipt, 32, parker_receipt_hex);

        struct package_resident_artifact artifact;
        struct zcl_result ar = package_resident_artifact_read(
            base, ztasks_root, ztasks_receipt, RLC_ZTASKS_PROGRAM, &artifact);
        struct stat st;
        RLC_CHECK("stage a: the accepted-artifact record re-derives from the "
                  "installed receipt (receipt-bound digest + locator triple)",
                  ar.ok &&
                  strcmp(artifact.accepted.image_sha3_hex, ztasks_sha3) == 0 &&
                  artifact.accepted.image_size > 0 &&
                  stat(artifact.locator, &st) == 0 &&
                  (st.st_mode & 0111) != 0);

        failures += rlc_stage_run(spec, base, ztasks_root_hex,
                                  ztasks_receipt_hex, ztasks_sha3);

        /* The failed candidate for stages e and f: ONE parker invocation,
         * whose refusal both proves bounded cancel/reap and stands as the
         * failed candidate that rollback would have to recover from. */
        struct rlc_call park;
        rlc_call_package(&park, spec, base, parker_root_hex,
                         parker_receipt_hex, parker_sha3, RLC_PARKER_PROGRAM,
                         "list");
        bool ran_park = rlc_invoke(&park);
        RLC_CHECK("stage e: an unresponsive resident is refused inside the "
                  "consumer's own bounded result wait",
                  ran_park && !rlc_ok(&park));
        if (ran_park && !rlc_ok(&park))
            printf("[bounded refusal: code=%s message=%s] ",
                   park.reply.error.code, park.reply.error.message);
        RLC_CHECK("stage e: cancel reaped the resident — no live or zombie "
                  "child remains (process-level proof; failure replies "
                  "carry no data.pid by design)",
                  ran_park && rlc_no_children());

        failures += rlc_stage_rollback(spec, base, ztasks_root_hex,
                                       ztasks_receipt_hex, ztasks_sha3,
                                       ran_park ? &park : NULL);
        rlc_end(&park);
    } else {
        printf("resident_launch_contract: fixture install failed — stages "
               "b–f blocked (1 counted failure above)\n");
    }
    test_rm_rf(base);
#endif
    if (!spec || !spec->handler) rlc_explain_absent();
    printf("resident_launch_contract: %s (%d failure(s))\n",
           failures ? "FAIL" : "PASS", failures);
    return failures;
}
