/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: proofs for dev.app.machine.boot (alias dev.machine.boot), through
 * the command dispatcher (input validation, the handler, the reply contract
 * and the bounded envelope). The guests are the committed images of
 * tests/fixtures/rvmachine, copied into a temporary directory first so that
 * no refusal under test can reach a fixture.
 *
 * Covered: the receipt of a known guest and its repeat; the console script;
 * every failure that must not look like success (goal missed, budget, guest
 * fault, console limit, input changed, transcript not written), each with the
 * receipt in the error; the file rules (inputs opened first and never through
 * a symlink, the transcript created exclusively and refused when it names an
 * input by path or hard link or exists in any form, a symlink included, the
 * input bytes unchanged); the typed input rules; and the command's canonical
 * path, its alias and its release-shape row.
 *
 * Three cases need something the real leaf cannot be asked for. They
 * recompile the leaf in this translation unit with its policy points under
 * test control: an after-run hook that changes the kernel file or breaks the
 * transcript descriptor, and a console limit of a few bytes. */
#include "test/test_core.h"

#include "base/serialize_le.h"
#include "command/native_command.h"
#include "config/command_catalog.h"
#include "crypto/sha256.h"
#include "crypto/sha3.h"
#include "keys/key.h"
#include "keys/pubkey.h"
#include "services/package_lifecycle.h"
#include "vcs/package_manifest.h"
#include "vcs/package_recipe.h"
#include "vcs/package_release.h"

#include "json/json.h"
#include "kernel/command_registry.h"
#include "platform/rng.h"
#include "config/mesh_guest_private_volume.h"
#include "util/spawn.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
int test_dev_machine_boot(void);
int test_dev_machine_boot(void)
{
    printf("test_dev_machine_boot: skipped on Windows\n");
    return 0;
}
#else
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

/* ---- the leaf again, with its policy points under test control ---- */
struct mb_state;
static void tmb_after_run(struct mb_state *st);
static uint64_t tmb_console_max = UINT64_C(64) << 20; /* the real limit */
static unsigned tmb_host_calls;
static unsigned tmb_host_fail_call;
static bool tmb_host_fill(uint8_t *out, size_t n)
{
    tmb_host_calls++;
    memset(out, 0x5a, tmb_host_calls == tmb_host_fail_call && n > 3u ? 3u : n);
    return tmb_host_calls != tmb_host_fail_call;
}
void mbtwin_handle(const struct zcl_command_request *request,
                   struct zcl_command_reply *reply);

/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0 */
/* INERT test_dev_machine_boot source-twin-only seams, before owner include.
 * Existing platform has no global TESTING fault injection API. This reuses
 * the sanctioned local macro-wrapper pattern (test_chainlog.c92 and this
 * test's private-volume seam). No production policy/function is changed.
 * Include actual headers BEFORE these definitions/macros. */
#include "platform/private_file.h"
#include "platform/positioned_file.h"
enum tmb_provision_fault { TMB_PF_NONE,TMB_PF_WRITE,TMB_PF_AUTHORITY,TMB_PF_PARENT,TMB_PF_LATE_SNAPSHOT };
static enum tmb_provision_fault tmb_provision_fault;
static struct platform_private_file *tmb_provision_target;
static const char *tmb_provision_parent;
static unsigned tmb_provision_write_calls,tmb_provision_authority_calls;
static unsigned tmb_provision_parent_calls,tmb_provision_snapshot_calls;
static bool tmb_provision_snapshot_mutated;
static bool tmb_provision_write(struct platform_private_file *file,const void *bytes,size_t size,uint64_t off)
{
    if(file!=tmb_provision_target)return platform_private_file_write_at(file,bytes,size,off);
    tmb_provision_write_calls++;
    if(tmb_provision_fault==TMB_PF_WRITE){
        /* Real partial PUBLIC write, followed by a reported failure. */
        if(size<3)return false;
        (void)platform_private_file_write_at(file,bytes,3,off);return false;
    }
    return platform_private_file_write_at(file,bytes,size,off);
}
static bool tmb_provision_authority(struct platform_private_file *file)
{
    if(file!=tmb_provision_target)return platform_private_file_authority_flush(file);
    tmb_provision_authority_calls++;
    if(tmb_provision_fault==TMB_PF_AUTHORITY)return false; /* Explicit barrier refusal; never fake success. */
    return platform_private_file_authority_flush(file);
}
static bool tmb_provision_parent_flush(const char *parent)
{
    if(!tmb_provision_parent||strcmp(parent,tmb_provision_parent))return platform_private_parent_flush(parent);
    tmb_provision_parent_calls++;
    if(tmb_provision_fault==TMB_PF_PARENT)return false;
    return platform_private_parent_flush(parent);
}
static bool tmb_provision_snapshot(const struct platform_positioned_file *file,
    struct platform_positioned_file_snapshot *snapshot)
{
    if(!tmb_provision_target||file->native!=tmb_provision_target->native)
        return platform_positioned_file_snapshot(file,snapshot);
    tmb_provision_snapshot_calls++;
    if(tmb_provision_fault==TMB_PF_LATE_SNAPSHOT&&tmb_provision_snapshot_calls==2){
        /* Actually change held PUBLIC file AFTER readback, before second
         * snapshot. Return the real current snapshot, not invented metadata. */
        tmb_provision_snapshot_mutated=platform_private_file_truncate(tmb_provision_target,33);
        if(!tmb_provision_snapshot_mutated)return false;
    }
    return platform_positioned_file_snapshot(file,snapshot);
}
#include "../../../tools/command/native_dev_machine_data.h"
static unsigned tmb_data_parse_calls;
static bool tmb_data_parse(const void *owner,const struct json_value *in,struct zcl_command_reply *reply)
{tmb_data_parse_calls++;return zcl_mb_data_parse(owner,in,reply);}
#define zcl_mb_data_parse tmb_data_parse
/* Scope these macros only around the EXISTING native boot/owner source twin;
 * undef all four immediately afterward. Do not wrap linked production APIs. */
#define platform_private_file_write_at tmb_provision_write
#define platform_private_file_authority_flush tmb_provision_authority
#define platform_private_parent_flush tmb_provision_parent_flush
#define platform_positioned_file_snapshot(...) tmb_provision_snapshot(__VA_ARGS__)

#define MB_TWIN_BUILD 1
#define MB_POLICY_AFTER_RUN(st) tmb_after_run(st)
#define MB_POLICY_CONSOLE_MAX tmb_console_max
#define zcl_native_handle_dev_machine_boot mbtwin_handle
#define rng_host_fill tmb_host_fill
#define zcl_mb_boot_fail tmb_boot_fail
#define zcl_mb_boot_bad_input tmb_boot_bad_input
#define zcl_mb_boot_opt_str tmb_boot_opt_str
#define zcl_mb_boot_opt_int tmb_boot_opt_int
#define zcl_mb_boot_host_entropy tmb_boot_host_entropy
#define zcl_mb_boot_host_boot_seed tmb_boot_host_boot_seed
#define zcl_mb_boot_accepted_read tmb_boot_accepted_read
#define zcl_mb_owner_parse tmb_owner_parse
#define zcl_mb_owner_image_grant tmb_owner_image_grant
#define zcl_mb_owner_called tmb_owner_called
#define zcl_mb_owner_dispose tmb_owner_dispose
#include "../../../tools/command/native_dev_machine_boot.c"
#include "../../../tools/command/native_dev_machine_boot_owner.c"
#undef zcl_mb_data_parse
#undef platform_private_file_write_at
#undef platform_private_file_authority_flush
#undef platform_private_parent_flush
#undef platform_positioned_file_snapshot
#undef zcl_mb_owner_dispose
#undef zcl_mb_owner_called
#undef zcl_mb_owner_parse
#undef zcl_mb_owner_image_grant
#undef zcl_mb_boot_accepted_read
#undef zcl_mb_boot_host_boot_seed
#undef zcl_mb_boot_host_entropy
#undef zcl_mb_boot_opt_int
#undef zcl_mb_boot_opt_str
#undef zcl_mb_boot_bad_input
#undef zcl_mb_boot_fail
#undef rng_host_fill
#undef zcl_native_handle_dev_machine_boot

static bool tmb_volume_flush_fail;
static bool tmb_volume_owner_fail;
static bool tmb_volume_owner(const struct platform_positioned_file *file)
{
    return !tmb_volume_owner_fail && platform_positioned_file_is_current_user_only(file);
}
static unsigned tmb_volume_flush_calls;
static bool tmb_volume_flush(struct platform_private_file *file)
{
    tmb_volume_flush_calls++;
    return !tmb_volume_flush_fail && platform_private_file_authority_flush(file);
}
bool tmb_volume_bind(struct zcl_machine_private_volume *volume,
    struct platform_private_file *file, struct rvmachine_disk **disk);
#define zcl_machine_private_volume_bind tmb_volume_bind
#define platform_private_file_authority_flush tmb_volume_flush
#define platform_positioned_file_is_current_user_only tmb_volume_owner
#include "../../../engine/composition/src/mesh_guest_private_volume.c"
#undef platform_positioned_file_is_current_user_only
#undef platform_private_file_authority_flush
#undef zcl_machine_private_volume_bind

enum tmb_after { TMB_AFTER_NOTHING = 0, TMB_AFTER_GROW_KERNEL, TMB_AFTER_BREAK_TRANSCRIPT };
static enum tmb_after tmb_after_mode;
static const char *tmb_after_path;
static bool tmb_after_done;

static void tmb_after_run(struct mb_state *st)
{
    int fd;
    if (tmb_after_mode == TMB_AFTER_GROW_KERNEL) {
        fd = open(tmb_after_path, O_WRONLY | O_APPEND);
        tmb_after_done = fd >= 0 && write(fd, "x", 1) == 1;
        if (fd >= 0) close(fd);
    } else if (tmb_after_mode == TMB_AFTER_BREAK_TRANSCRIPT && st->out_fd >= 0) {
        /* the transcript descriptor now refuses writes */
        fd = open("/dev/null", O_RDONLY);
        tmb_after_done = fd >= 0 && dup2(fd, st->out_fd) == st->out_fd;
        if (fd >= 0) close(fd);
    }
}

/* ---- helpers ---- */
#define TMB_PATH "dev.app.machine.boot"
#define TMB_ALIAS "dev.machine.boot"
#define TMB_FIXTURES "tests/fixtures/rvmachine"
#define TMB_WIRE 16384u
#define TMB_FILE_MAX 65536u
#define TMB_TINY_SHA "3cbce45f847a34606550eca184e332ce43b5370b3b597ef7f5a6aebf48e9cd4c"
#define TMB_TINY_TEXT "tiny: hello from S-mode\nprobe putchar=1\ntiny: timer fired\nU\n"

struct tmb_dir {
    char dir[200];
    char kernel[240];
    char disk[240];
    char out[240];
    char link[240];
};

struct tmb_call {
    struct json_value doc; /* the parsed envelope */
    bool parsed;
    enum zcl_command_exit exit_code;
};

static bool tmb_read(const char *path, uint8_t *buf, size_t cap, size_t *len)
{
    FILE *f = fopen(path, "rb");
    if (f == NULL) return false;
    *len = fread(buf, 1, cap, f);
    bool whole = fgetc(f) == EOF;
    return fclose(f) == 0 && whole;
}

static bool tmb_write(const char *path, const void *bytes, size_t len)
{
    FILE *f = fopen(path, "wb");
    if (f == NULL) return false;
    bool ok = fwrite(bytes, 1, len, f) == len;
    return fclose(f) == 0 && ok;
}

/* Inert test proposal: reuse test_zcode_add typed publish/plan/commit rail.
 * kernel.h is deliberately binary PUBLIC fixture data, not a usable C header,
 * and is copied by the recipe, never compiled. No RV reproduction claim. */
struct tmb_pkg_file { const char *path; const void *content; size_t length; };

static bool tmb_pkg_mkdirs(const char *path)
{
    char buf[4096];
    size_t len = strlen(path);
    if (!len || len >= sizeof buf) return false;
    memcpy(buf, path, len + 1u);
    for (char *p = buf + 1; *p; p++) {
        if (*p != '/') continue;
        *p = 0;
        if (mkdir(buf, 0700) != 0 && errno != EEXIST) return false;
        *p = '/';
    }
    return mkdir(buf, 0700) == 0 || errno == EEXIST;
}

static bool tmb_pkg_object(const char *zcode, const char *kind,
                            const uint8_t id[32], const void *wire, size_t len)
{
    char dir[4400], path[4500], hex[65];
    zcl_hex_encode(id, 32, hex);
    int n = snprintf(dir, sizeof dir, "%s/%s", zcode, kind);
    if (n <= 0 || (size_t)n >= sizeof dir || !tmb_pkg_mkdirs(dir)) return false;
    n = snprintf(path, sizeof path, "%s/%s", dir, hex);
    return n > 0 && (size_t)n < sizeof path && tmb_write(path, wire, len);
}

static bool tmb_pkg_blob(const char *zcode, struct vcs_package_manifest *m,
                         const struct tmb_pkg_file *file)
{
    struct sha3_256_ctx sha;
    uint8_t digest[32];
    char hex[65], kind[16];
    sha3_256_init(&sha);
    sha3_256_write(&sha, file->content, file->length);
    sha3_256_finalize(&sha, digest);
    zcl_hex_encode(digest, 32, hex);
    snprintf(kind, sizeof kind, "cas/sha3/%.2s", hex);
    return vcs_package_manifest_add(m, file->path, VCS_PACKAGE_MODE_FILE,
               file->length, digest, 1) &&
           tmb_pkg_object(zcode, kind, digest, file->content, file->length);
}

static bool tmb_pkg_manifest(const char *zcode, const struct tmb_pkg_file *files,
                             size_t count, uint8_t root[32])
{
    struct vcs_package_manifest m;
    uint8_t *wire = NULL;
    size_t length = 0;
    vcs_package_manifest_init(&m);
    bool ok = true;
    for (size_t i = 0; i < count && ok; i++) ok = tmb_pkg_blob(zcode, &m, &files[i]);
    ok = ok && vcs_package_manifest_root(&m, root) &&
         vcs_package_manifest_serialize(&m, &wire, &length);
    vcs_package_manifest_free(&m);
    ok = ok && tmb_pkg_object(zcode, "manifests", root, wire, length);
    free(wire);
    return ok;
}

static bool tmb_pkg_recipe(const char *zcode, uint8_t root[32])
{
    struct vcs_package_recipe r;
    uint8_t *wire = NULL;
    size_t length = 0;
    vcs_package_recipe_init(&r);
    bool ok = vcs_package_recipe_add_header(&r, "src/kernel.h", NULL) &&
        vcs_package_recipe_add_source(&r, "src/fixture.c", NULL) &&
        vcs_package_recipe_add_test_source(&r, "test/test_fixture.c", NULL) &&
        vcs_package_recipe_add_include_dir(&r, "src", NULL) &&
        vcs_package_recipe_add_library(&r, VCS_PACKAGE_RECIPE_LIB_LIBC, NULL);
    vcs_package_recipe_set_test_limits(&r, 0, 60, UINT64_C(64) * 1024u * 1024u);
    ok = ok && vcs_package_recipe_root(&r, root) == VCS_PACKAGE_RECIPE_OK &&
        vcs_package_recipe_serialize(&r, &wire, &length) == VCS_PACKAGE_RECIPE_OK;
    vcs_package_recipe_free(&r);
    ok = ok && tmb_pkg_object(zcode, "recipes", root, wire, length);
    free(wire);
    return ok;
}

static bool tmb_pkg_release(const char *zcode, const uint8_t root[32],
                            const uint8_t recipe[32])
{
    /* Fixed public test signing key; no operator credentials are accessed. */
    struct privkey sk = {0};
    struct pubkey pk;
    memset(sk.vch, 0x11, 32); sk.fValid = true; sk.fCompressed = true;
    if (!privkey_get_pubkey(&sk, &pk)) return false;
    struct vcs_package_release rel = {0};
    rel.schema_version = VCS_PACKAGE_RELEASE_VERSION;
    snprintf(rel.name, sizeof rel.name, "fixture/rv64-copy");
    snprintf(rel.semver, sizeof rel.semver, "1.0.0");
    memcpy(rel.package_root, root, 32);
    memcpy(rel.recipe_root, recipe, 32);
    memcpy(rel.publisher_pubkey, pk.vch, COMPRESSED_PUBLIC_KEY_SIZE);
    rel.publisher_sequence = 1;
    snprintf(rel.reward_address, sizeof rel.reward_address, "t1fixture");
    snprintf(rel.license, sizeof rel.license, "MIT");
    snprintf(rel.chain_id, sizeof rel.chain_id, "zclassic-main");
    uint8_t id[VCS_PACKAGE_RELEASE_ID_BYTES];
    if (vcs_package_release_id(&rel, id) != VCS_PACKAGE_RELEASE_OK) return false;
    struct uint256 h;
    memcpy(h.data, id, 32);
    unsigned char compact[COMPACT_SIGNATURE_SIZE];
    if (!privkey_sign_compact(&sk, &h, compact)) return false;
    memcpy(rel.signature, compact + 1, VCS_PACKAGE_RELEASE_SIGNATURE_BYTES);
    uint8_t *wire = NULL;
    size_t length = 0;
    if (vcs_package_release_serialize(&rel, &wire, &length) != VCS_PACKAGE_RELEASE_OK)
        return false;
    bool ok = tmb_pkg_object(zcode, "releases", id, wire, length);
    free(wire);
    return ok;
}

static bool tmb_pkg_receipt_log(const char *base, const uint8_t id[32])
{
    struct vcs_package_build_receipt receipt;
    struct zcl_result read = package_lifecycle_receipt_read(base, id, &receipt);
    if (!read.ok) return false;
    uint8_t *wire = NULL;
    size_t length = 0;
    if (vcs_package_build_serialize(&receipt, &wire, &length) != VCS_PACKAGE_BUILD_OK)
        return false;
    if (length > VCS_PACKAGE_BUILD_MAX_WIRE_BYTES || length > (SIZE_MAX - 1u) / 2u) {
        free(wire);
        return false;
    }
    char *hex = zcl_malloc(length * 2u + 1u, "PUBLIC copied-kernel receipt log");
    if (!hex) { free(wire); return false; }
    zcl_hex_encode(wire, length, hex);
    bool ok = printf("\nPUBLIC_COPY_FIXTURE_RECEIPT_HEX=%s\n", hex) > 0;
    free(hex); free(wire);
    return ok;
}

static bool tmb_pkg_install(const struct tmb_dir *d, uint8_t root[32],
                            uint8_t receipt[32], size_t *kernel_bytes)
{
    static uint8_t kernel[TMB_FILE_MAX];
    static const char source[] = "int fixture_value(void) { return 7; }\n";
    static const char test[] = "int fixture_value(void); int main(void) { return fixture_value() != 7; }\n";
    static const char license[] = "SPDX-License-Identifier: MIT\nPUBLIC binary guest test fixture, copied not compiled.\n";
    if (!tmb_read(d->kernel, kernel, sizeof kernel, kernel_bytes) || !*kernel_bytes)
        return false;
    const struct tmb_pkg_file files[] = {
        {"LICENSE", license, sizeof license - 1u},
        {"src/kernel.h", kernel, *kernel_bytes},
        {"src/fixture.c", source, sizeof source - 1u},
        {"test/test_fixture.c", test, sizeof test - 1u}
    };
    char zcode[256];
    int n = snprintf(zcode, sizeof zcode, "%s/zcode", d->dir);
    uint8_t recipe[32];
    if (n <= 0 || (size_t)n >= sizeof zcode ||
        !tmb_pkg_manifest(zcode, files, 4u, root) ||
        !tmb_pkg_recipe(zcode, recipe) || !tmb_pkg_release(zcode, root, recipe)) return false;
    struct package_lifecycle_plan_report plan;
    struct package_lifecycle_commit_report committed;
    struct zcl_result planned = package_lifecycle_plan(d->dir, "fixture/rv64-copy", 1700000000, &plan);
    if (!planned.ok || !plan.ready) return false;
    struct zcl_result result = package_lifecycle_commit(d->dir, plan.plan_id, 1700000001, &committed);
    if (!result.ok || !committed.installed || committed.step_count != 1u) return false;
    memcpy(receipt, committed.steps[0].receipt_id, 32);
    return tmb_pkg_receipt_log(d->dir, receipt);
}

static bool tmb_sha(const char *path, char hex[2 * SHA256_OUTPUT_SIZE + 1])
{
    static uint8_t buf[TMB_FILE_MAX];
    static const char digits[] = "0123456789abcdef";
    unsigned char hash[SHA256_OUTPUT_SIZE];
    struct sha256_ctx ctx;
    size_t len = 0;
    if (!tmb_read(path, buf, sizeof buf, &len)) return false;
    sha256_init(&ctx);
    sha256_write(&ctx, buf, len);
    sha256_finalize(&ctx, hash);
    for (size_t i = 0; i < SHA256_OUTPUT_SIZE; i++) {
        hex[2 * i] = digits[hash[i] >> 4];
        hex[2 * i + 1] = digits[hash[i] & 15u];
    }
    hex[2 * SHA256_OUTPUT_SIZE] = '\0';
    return true;
}

static bool tmb_same_sha(const char *path, const char *want)
{
    char hex[2 * SHA256_OUTPUT_SIZE + 1];
    return tmb_sha(path, hex) && strcmp(hex, want) == 0;
}

/* A fresh directory holding a copy of one fixture image as the kernel. */
static bool tmb_setup(struct tmb_dir *d, const char *fixture)
{
    static uint8_t buf[TMB_FILE_MAX];
    char src[128];
    size_t len = 0;
    if (test_mkdtemp(d->dir, sizeof d->dir, "machine_boot") == NULL) return false;
    snprintf(d->kernel, sizeof d->kernel, "%s/kernel.bin", d->dir);
    snprintf(d->disk, sizeof d->disk, "%s/disk.img", d->dir);
    snprintf(d->out, sizeof d->out, "%s/transcript", d->dir);
    snprintf(d->link, sizeof d->link, "%s/link", d->dir);
    snprintf(src, sizeof src, TMB_FIXTURES "/%s.bin", fixture);
    return tmb_read(src, buf, sizeof buf, &len) && len != 0 &&
           tmb_write(d->kernel, buf, len);
}

/* Dispatches one JSON input to a leaf row and parses the envelope. */
static bool tmb_dispatch(struct tmb_call *c, const struct zcl_command_spec *spec,
                         const char *json)
{
    static char wire[TMB_WIRE];
    struct json_value input;
    size_t len = 0;
    json_init(&c->doc);
    c->parsed = false;
    c->exit_code = ZCL_COMMAND_EXIT_INTERNAL;
    json_init(&input);
    if (json_read(&input, json, strlen(json)) && input.type == JSON_OBJ)
        len = zcl_command_registry_execute_json(zcl_command_catalog(), spec, NULL,
                                                &input, false, TMB_PATH, NULL, 0, 0,
                                                NULL, wire, sizeof wire, &c->exit_code);
    json_free(&input);
    c->parsed = len > 0 && json_read(&c->doc, wire, len);
    return c->parsed;
}

/* Runs the leaf on a JSON input through the dispatcher. The row (keys,
 * schemas, budget) is the catalog's own. The test binary is a release-shape
 * build, where the catalog lists a development leaf without binding it
 * (t_command_row proves that), so the handler the dev build binds is bound here,
 * or the twin when one is given. */
static bool tmb_go(struct tmb_call *c, zcl_command_handler_fn handler, const char *json)
{
    const struct zcl_command_spec *found =
        zcl_command_registry_find(zcl_command_catalog(), TMB_PATH, NULL);
    struct zcl_command_spec spec;
    c->parsed = false;
    json_init(&c->doc);
    if (found == NULL) return false;
    spec = *found;
    spec.handler = handler != NULL ? handler : zcl_native_handle_dev_machine_boot;
    return tmb_dispatch(c, &spec, json);
}

static void tmb_end(struct tmb_call *c)
{
    json_free(&c->doc);
    c->parsed = false;
}

static bool tmb_ok(const struct tmb_call *c)
{
    return c->parsed && json_get_bool(json_get(&c->doc, "ok")) &&
           c->exit_code == ZCL_COMMAND_EXIT_OK;
}

static int64_t tmb_int(const struct tmb_call *c, const char *key)
{
    const struct json_value *v = json_get(json_get(&c->doc, "data"), key);
    return v != NULL && v->type == JSON_INT ? json_get_int(v) : -1;
}

static const char *tmb_str(const struct tmb_call *c, const char *key)
{
    const char *s = json_get_str(json_get(json_get(&c->doc, "data"), key));
    return s != NULL ? s : "";
}

static bool tmb_flag(const struct tmb_call *c, const char *key)
{
    const struct json_value *v = json_get(json_get(&c->doc, "data"), key);
    return v != NULL && v->type == JSON_BOOL && json_get_bool(v);
}

static const char *tmb_error(const struct tmb_call *c, const char *key)
{
    const char *s = json_get_str(json_get(json_get(&c->doc, "error"), key));
    return s != NULL ? s : "";
}

/* True when the call failed with this code and no success data. */
static bool tmb_failed(const struct tmb_call *c, const char *code)
{
    return c->parsed && !json_get_bool(json_get(&c->doc, "ok")) &&
           c->exit_code != ZCL_COMMAND_EXIT_OK && json_get(&c->doc, "data") == NULL &&
           strcmp(tmb_error(c, "code"), code) == 0;
}

static bool tmb_evidence_has(const struct tmb_call *c, const char *text)
{
    return strstr(tmb_error(c, "evidence"), text) != NULL;
}

static bool tmb_absent(const char *path)
{
    struct stat sb;
    return lstat(path, &sb) != 0;
}

/* ---- 1. the receipt ---- */
static int t_receipt(void)
{
    int failures = 0;
    TEST("dev.app.machine.boot: a known guest gives its receipt and transcript, twice") {
        struct tmb_dir d;
        struct tmb_call a, b;
        char json[1024], before[65];
        const struct json_value *kernel;
        ASSERT(tmb_setup(&d, "tiny"));
        ASSERT(tmb_sha(d.kernel, before));
        snprintf(json, sizeof json,
                 "{\"kernel\":\"%s\",\"ram_mib\":64,\"max_instr\":100000,"
                 "\"transcript\":\"%s\"}", d.kernel, d.out);
        ASSERT(tmb_go(&a, NULL, json));
        ASSERT(tmb_ok(&a));
        ASSERT_STR_EQ(tmb_str(&a, "stop"), "shutdown");
        ASSERT(!tmb_flag(&a, "marker_seen"));
        ASSERT_EQ(tmb_int(&a, "retired"), 279);
        ASSERT_EQ(tmb_int(&a, "skip"), 999);
        ASSERT_EQ(tmb_int(&a, "fw_calls"), 62);
        ASSERT_EQ(tmb_int(&a, "device_work"), 0); /* no disk, nothing moved */
        ASSERT_EQ(tmb_int(&a, "guest_time"), 279 / 10 + 999);
        ASSERT_EQ(tmb_int(&a, "timebase_hz"), 10000000);
        ASSERT_EQ(tmb_int(&a, "console_bytes"), 60);
        ASSERT_STR_EQ(tmb_str(&a, "transcript_sha256"), TMB_TINY_SHA);
        ASSERT_EQ(tmb_int(&a, "script_fired"), 0);
        ASSERT_EQ(tmb_int(&a, "script_total"), 0);
        ASSERT_EQ(tmb_int(&a, "ram_mib"), 64);
        ASSERT_EQ(tmb_int(&a, "overlay_blocks"), 0);
        ASSERT_STR_EQ(tmb_str(&a, "console_tail"), TMB_TINY_TEXT);
        kernel = json_get(json_get(json_get(&a.doc, "data"), "inputs"), "kernel");
        ASSERT(kernel != NULL);
        ASSERT(json_get_int(json_get(kernel, "size")) > 0);
        ASSERT(json_get(kernel, "changed")->type == JSON_BOOL);
        ASSERT(!json_get_bool(json_get(kernel, "changed")));
        ASSERT(json_get(json_get(json_get(&a.doc, "data"), "inputs"), "disk") == NULL);
        /* the transcript file is the hashed bytes, and the kernel is untouched */
        ASSERT(tmb_same_sha(d.out, TMB_TINY_SHA));
        ASSERT(tmb_same_sha(d.kernel, before));
        /* again without a transcript: the same receipt, nothing else written */
        snprintf(json, sizeof json,
                 "{\"kernel\":\"%s\",\"ram_mib\":64,\"max_instr\":100000}", d.kernel);
        ASSERT(tmb_go(&b, NULL, json));
        ASSERT(tmb_ok(&b));
        ASSERT_EQ(tmb_int(&b, "retired"), tmb_int(&a, "retired"));
        ASSERT_EQ(tmb_int(&b, "skip"), tmb_int(&a, "skip"));
        ASSERT_EQ(tmb_int(&b, "fw_calls"), tmb_int(&a, "fw_calls"));
        ASSERT_STR_EQ(tmb_str(&b, "transcript_sha256"), TMB_TINY_SHA);
        /* a larger machine runs this guest to the same counts */
        tmb_end(&b);
        snprintf(json, sizeof json, "{\"kernel\":\"%s\",\"max_instr\":100000}", d.kernel);
        ASSERT(tmb_go(&b, NULL, json));
        ASSERT(tmb_ok(&b));
        ASSERT_EQ(tmb_int(&b, "ram_mib"), 1024);
        ASSERT_EQ(tmb_int(&b, "retired"), 279);
        ASSERT_STR_EQ(tmb_str(&b, "transcript_sha256"), TMB_TINY_SHA);
        tmb_end(&a);
        tmb_end(&b);
        test_cleanup_tmpdir(d.dir);
        PASS();
    } _test_next:;
    return failures;
}

static int boot_fetch_reused(const struct tmb_call *a, const struct tmb_call *b)
{
    int64_t hits = tmb_int(a, "fetch_hits");
    int64_t misses = tmb_int(a, "fetch_misses");
    if (hits < misses || misses <= 0) return 0;
    if (tmb_int(b, "fetch_hits") != hits || tmb_int(b, "fetch_misses") != misses) return 0;
    if (tmb_int(a, "retired") != 279 || tmb_int(b, "retired") != 279) return 0;
    printf("    machine boot fetch_hits=%lld fetch_misses=%lld\n",
           (long long)hits, (long long)misses);
    return 1;
}

static int t_fetch_cache(void)
{
    int failures = 0;
    TEST("dev.app.machine.boot: the tiny guest reuses decoded instructions") {
        struct tmb_dir d;
        struct tmb_call a, b;
        char json[1024];
        ASSERT(tmb_setup(&d, "tiny"));
        snprintf(json, sizeof json, "{\"kernel\":\"%s\",\"max_instr\":100000}", d.kernel);
        ASSERT(tmb_go(&a, NULL, json));
        ASSERT(tmb_ok(&a));
        ASSERT(tmb_go(&b, NULL, json));
        ASSERT(tmb_ok(&b));
        ASSERT(boot_fetch_reused(&a, &b));
        tmb_end(&a);
        tmb_end(&b);
        test_cleanup_tmpdir(d.dir);
        PASS();
    } _test_next:;
    return failures;
}

/* ---- 2. the console script ---- */
static int t_script(void)
{
    int failures = 0;
    TEST("dev.app.machine.boot: typed steps fire on their markers and the stop text ends the run") {
        struct tmb_dir d;
        struct tmb_call c;
        char json[1024];
        ASSERT(tmb_setup(&d, "tiny"));
        snprintf(json, sizeof json,
                 "{\"kernel\":\"%s\",\"ram_mib\":64,\"max_instr\":100000,"
                 "\"type_after\":[[\"from S-mode\\n\",\"x\"],[\"putchar=1\\n\",\"\"]],"
                 "\"until\":\"timer fired\"}", d.kernel);
        ASSERT(tmb_go(&c, NULL, json));
        ASSERT(tmb_ok(&c));
        ASSERT_STR_EQ(tmb_str(&c, "stop"), "requested");
        ASSERT(tmb_flag(&c, "marker_seen"));
        ASSERT_EQ(tmb_int(&c, "script_fired"), 2);
        ASSERT_EQ(tmb_int(&c, "script_total"), 2);
        /* stopped at the byte that completed the text, before the rest */
        ASSERT_STR_EQ(tmb_str(&c, "console_tail"),
                      "tiny: hello from S-mode\nprobe putchar=1\ntiny: timer fired");
        ASSERT_EQ(tmb_int(&c, "console_bytes"), 57);
        tmb_end(&c);
        /* the stop text is armed only after the last step: here it is printed
         * before the step's marker, so the guest runs to its own end */
        snprintf(json, sizeof json,
                 "{\"kernel\":\"%s\",\"ram_mib\":64,\"max_instr\":100000,"
                 "\"type_after\":[[\"timer fired\\n\",\"\"]],\"until\":\"U\\n\"}", d.kernel);
        ASSERT(tmb_go(&c, NULL, json));
        ASSERT(tmb_ok(&c));
        ASSERT(tmb_flag(&c, "marker_seen"));
        ASSERT_EQ(tmb_int(&c, "console_bytes"), 60);
        tmb_end(&c);
        test_cleanup_tmpdir(d.dir);
        PASS();
    } _test_next:;
    return failures;
}

/* ---- 3. a missed goal is a failure that still carries the receipt ---- */
static int t_goal_missed(void)
{
    int failures = 0;
    TEST("dev.app.machine.boot: a missed marker, stop text or budget fails with the receipt") {
        struct tmb_dir d;
        struct tmb_call c;
        char json[1024];
        ASSERT(tmb_setup(&d, "tiny"));
        /* the stop text never appears: the guest powers off first */
        snprintf(json, sizeof json,
                 "{\"kernel\":\"%s\",\"ram_mib\":64,\"max_instr\":100000,"
                 "\"until\":\"never printed\",\"transcript\":\"%s\"}", d.kernel, d.out);
        ASSERT(tmb_go(&c, NULL, json));
        ASSERT(tmb_failed(&c, "GOAL_MISSED"));
        ASSERT_EQ(c.exit_code, ZCL_COMMAND_EXIT_FAILED);
        ASSERT_STR_EQ(tmb_error(&c, "current_state"), "shutdown");
        ASSERT(tmb_evidence_has(&c, "stop=shutdown marker_seen=0 retired=279 skip=999 "
                                    "fw_calls=62 device_work=0 console_bytes=60 script=0/0 "
                                    "sha256=" TMB_TINY_SHA));
        ASSERT(tmb_same_sha(d.out, TMB_TINY_SHA)); /* the transcript is still evidence */
        tmb_end(&c);
        /* a step whose marker never appears */
        snprintf(json, sizeof json,
                 "{\"kernel\":\"%s\",\"ram_mib\":64,\"max_instr\":100000,"
                 "\"type_after\":[[\"hello\",\"a\"],[\"login:\",\"root\\n\"]]}", d.kernel);
        ASSERT(tmb_go(&c, NULL, json));
        ASSERT(tmb_failed(&c, "GOAL_MISSED"));
        ASSERT(tmb_evidence_has(&c, "script=1/2"));
        tmb_end(&c);
        /* the budget ends the run before the stop text */
        snprintf(json, sizeof json,
                 "{\"kernel\":\"%s\",\"ram_mib\":64,\"max_instr\":50,"
                 "\"until\":\"timer fired\"}", d.kernel);
        ASSERT(tmb_go(&c, NULL, json));
        ASSERT(tmb_failed(&c, "GOAL_MISSED"));
        ASSERT_STR_EQ(tmb_error(&c, "current_state"), "budget");
        ASSERT(tmb_evidence_has(&c, "stop=budget marker_seen=0"));
        tmb_end(&c);
        /* a budget stop with no goal stated is a plain receipt */
        snprintf(json, sizeof json,
                 "{\"kernel\":\"%s\",\"ram_mib\":64,\"max_instr\":50}", d.kernel);
        ASSERT(tmb_go(&c, NULL, json));
        ASSERT(tmb_ok(&c));
        ASSERT_STR_EQ(tmb_str(&c, "stop"), "budget");
        ASSERT_EQ(tmb_int(&c, "retired") + tmb_int(&c, "fw_calls") +
                      tmb_int(&c, "device_work"), 50);
        tmb_end(&c);
        test_cleanup_tmpdir(d.dir);
        PASS();
    } _test_next:;
    return failures;
}

/* ---- 4. a guest that cannot continue ---- */
static int t_fault(void)
{
    int failures = 0;
    TEST("dev.app.machine.boot: a guest fault fails with pc, cause and tval") {
        static const uint8_t wild[4] = {0x67, 0x00, 0x00, 0x00}; /* jalr x0, 0(x0) */
        struct tmb_dir d;
        struct tmb_call c;
        char json[1024];
        ASSERT(tmb_setup(&d, "tiny"));
        ASSERT(tmb_write(d.kernel, wild, sizeof wild));
        snprintf(json, sizeof json,
                 "{\"kernel\":\"%s\",\"ram_mib\":64,\"max_instr\":100000}", d.kernel);
        ASSERT(tmb_go(&c, NULL, json));
        ASSERT(tmb_failed(&c, "GUEST_FAULT"));
        ASSERT_STR_EQ(tmb_error(&c, "current_state"), "fault");
        ASSERT(tmb_evidence_has(&c, "stop=fault"));
        ASSERT(tmb_evidence_has(&c, "retired=1 "));
        ASSERT(tmb_evidence_has(&c, " pc=0x0 cause=0x1 tval=0x0"));
        tmb_end(&c);
        /* an image the loader refuses never runs */
        ASSERT(tmb_write(d.kernel, "\x7f" "ELF" "\x01\x01\x01", 7));
        ASSERT(tmb_go(&c, NULL, json));
        ASSERT(tmb_failed(&c, "MACHINE_REFUSED"));
        ASSERT_STR_EQ(tmb_error(&c, "phase"), "load");
        tmb_end(&c);
        test_cleanup_tmpdir(d.dir);
        PASS();
    } _test_next:;
    return failures;
}

/* ---- 5. the transcript can never be an input ---- */
static int t_transcript_rules(void)
{
    int failures = 0;
    TEST("dev.app.machine.boot: a transcript that names an input or exists is refused, nothing written") {
        struct tmb_dir d;
        struct tmb_call c;
        char json[1024], kernel_sha[65], disk_sha[65];
        static uint8_t disk[8192];
        ASSERT(tmb_setup(&d, "tiny"));
        for (size_t i = 0; i < sizeof disk; i++) disk[i] = (uint8_t)(i * 13u);
        ASSERT(tmb_write(d.disk, disk, sizeof disk));
        ASSERT(tmb_sha(d.kernel, kernel_sha));
        ASSERT(tmb_sha(d.disk, disk_sha));
        /* the kernel's own path */
        snprintf(json, sizeof json,
                 "{\"kernel\":\"%s\",\"ram_mib\":64,\"transcript\":\"%s\"}", d.kernel,
                 d.kernel);
        ASSERT(tmb_go(&c, NULL, json));
        ASSERT(tmb_failed(&c, "TRANSCRIPT_IS_AN_INPUT"));
        ASSERT_EQ(c.exit_code, ZCL_COMMAND_EXIT_INVALID);
        ASSERT(tmb_same_sha(d.kernel, kernel_sha));
        tmb_end(&c);
        /* a hard link to the kernel */
        ASSERT(link(d.kernel, d.link) == 0);
        snprintf(json, sizeof json,
                 "{\"kernel\":\"%s\",\"ram_mib\":64,\"transcript\":\"%s\"}", d.kernel,
                 d.link);
        ASSERT(tmb_go(&c, NULL, json));
        ASSERT(tmb_failed(&c, "TRANSCRIPT_IS_AN_INPUT"));
        ASSERT(tmb_same_sha(d.kernel, kernel_sha));
        ASSERT(tmb_same_sha(d.link, kernel_sha));
        tmb_end(&c);
        ASSERT(unlink(d.link) == 0);
        /* a symlink to the kernel: the transcript path is never followed, so
         * it is refused as existing, like the dangling one below */
        ASSERT(symlink(d.kernel, d.link) == 0);
        ASSERT(tmb_go(&c, NULL, json));
        ASSERT(tmb_failed(&c, "TRANSCRIPT_EXISTS"));
        ASSERT_EQ(c.exit_code, ZCL_COMMAND_EXIT_INVALID);
        ASSERT(tmb_same_sha(d.kernel, kernel_sha));
        tmb_end(&c);
        ASSERT(unlink(d.link) == 0);
        /* the disk image's path */
        snprintf(json, sizeof json,
                 "{\"kernel\":\"%s\",\"disk\":\"%s\",\"ram_mib\":64,\"transcript\":\"%s\"}",
                 d.kernel, d.disk, d.disk);
        ASSERT(tmb_go(&c, NULL, json));
        ASSERT(tmb_failed(&c, "TRANSCRIPT_IS_AN_INPUT"));
        ASSERT(tmb_same_sha(d.disk, disk_sha));
        tmb_end(&c);
        /* an unrelated file that already exists is not overwritten */
        ASSERT(tmb_write(d.out, "keep me", 7));
        snprintf(json, sizeof json,
                 "{\"kernel\":\"%s\",\"ram_mib\":64,\"transcript\":\"%s\"}", d.kernel, d.out);
        ASSERT(tmb_go(&c, NULL, json));
        ASSERT(tmb_failed(&c, "TRANSCRIPT_EXISTS"));
        tmb_end(&c);
        {
            static uint8_t got[16];
            size_t len = 0;
            ASSERT(tmb_read(d.out, got, sizeof got, &len));
            ASSERT(len == 7 && memcmp(got, "keep me", 7) == 0);
        }
        ASSERT(unlink(d.out) == 0);
        /* a dangling symlink is not followed into a new file */
        ASSERT(symlink(d.out, d.link) == 0);
        snprintf(json, sizeof json,
                 "{\"kernel\":\"%s\",\"ram_mib\":64,\"transcript\":\"%s\"}", d.kernel,
                 d.link);
        ASSERT(tmb_go(&c, NULL, json));
        ASSERT(tmb_failed(&c, "TRANSCRIPT_EXISTS"));
        ASSERT(tmb_absent(d.out));
        tmb_end(&c);
        ASSERT(unlink(d.link) == 0);
        /* a directory that does not exist */
        snprintf(json, sizeof json,
                 "{\"kernel\":\"%s\",\"ram_mib\":64,\"transcript\":\"%s/none/t\"}", d.kernel,
                 d.dir);
        ASSERT(tmb_go(&c, NULL, json));
        ASSERT(tmb_failed(&c, "TRANSCRIPT_UNWRITABLE"));
        tmb_end(&c);
        /* a kernel the loader refuses leaves no transcript behind */
        ASSERT(tmb_write(d.disk, "\x7f" "ELF" "\x01\x01\x01", 7));
        snprintf(json, sizeof json,
                 "{\"kernel\":\"%s\",\"ram_mib\":64,\"transcript\":\"%s\"}", d.disk, d.out);
        ASSERT(tmb_go(&c, NULL, json));
        ASSERT(tmb_failed(&c, "MACHINE_REFUSED"));
        ASSERT(tmb_absent(d.out));
        tmb_end(&c);
        test_cleanup_tmpdir(d.dir);
        PASS();
    } _test_next:;
    return failures;
}

/* ---- 6. inputs: regular files, opened read-only, never through a symlink ---- */
static int t_input_files(void)
{
    int failures = 0;
    TEST("dev.app.machine.boot: inputs must be regular files and a disk is only read") {
        struct tmb_dir d;
        struct tmb_call c;
        char json[1024];
        static uint8_t disk[2u * 1024u * 1024u];
        const struct json_value *row;
        ASSERT(tmb_setup(&d, "diskwait"));
        /* a symlink to a good kernel */
        ASSERT(symlink(d.kernel, d.link) == 0);
        snprintf(json, sizeof json, "{\"kernel\":\"%s\",\"ram_mib\":64}", d.link);
        ASSERT(tmb_go(&c, NULL, json));
        ASSERT(tmb_failed(&c, "INPUT_UNREADABLE"));
        ASSERT(tmb_evidence_has(&c, "kernel: "));
        tmb_end(&c);
        /* a directory, a missing file, an empty file */
        snprintf(json, sizeof json, "{\"kernel\":\"%s\",\"ram_mib\":64}", d.dir);
        ASSERT(tmb_go(&c, NULL, json));
        ASSERT(tmb_failed(&c, "INPUT_UNREADABLE"));
        tmb_end(&c);
        snprintf(json, sizeof json, "{\"kernel\":\"%s\",\"ram_mib\":64}", d.out);
        ASSERT(tmb_go(&c, NULL, json));
        ASSERT(tmb_failed(&c, "INPUT_UNREADABLE"));
        tmb_end(&c);
        ASSERT(tmb_write(d.disk, "", 0));
        snprintf(json, sizeof json, "{\"kernel\":\"%s\",\"disk\":\"%s\",\"ram_mib\":64}",
                 d.kernel, d.disk);
        ASSERT(tmb_go(&c, NULL, json));
        ASSERT(tmb_failed(&c, "INPUT_UNREADABLE"));
        ASSERT(tmb_evidence_has(&c, "disk: "));
        tmb_end(&c);
        /* a real disk: the guest finds the block device's interrupt source and
         * waits; the image is identified, attached and left as it was */
        for (size_t i = 0; i < sizeof disk; i++) disk[i] = (uint8_t)(i * 7u + (i >> 8));
        {
            FILE *f = fopen(d.disk, "wb");
            ASSERT(f != NULL);
            ASSERT(fwrite(disk, 1, sizeof disk, f) == sizeof disk);
            ASSERT(fclose(f) == 0);
        }
        snprintf(json, sizeof json,
                 "{\"kernel\":\"%s\",\"disk\":\"%s\",\"ram_mib\":64,\"max_instr\":100000}",
                 d.kernel, d.disk);
        ASSERT(tmb_go(&c, NULL, json));
        ASSERT(tmb_ok(&c));
        ASSERT_STR_EQ(tmb_str(&c, "stop"), "shutdown");
        ASSERT_STR_EQ(tmb_str(&c, "console_tail"), "diskwait: woke on the timer\n");
        ASSERT_EQ(tmb_int(&c, "overlay_blocks"), 0);
        row = json_get(json_get(json_get(&c.doc, "data"), "inputs"), "disk");
        ASSERT(row != NULL);
        ASSERT_EQ(json_get_int(json_get(row, "size")), (int64_t)sizeof disk);
        ASSERT(!json_get_bool(json_get(row, "changed")));
        tmb_end(&c);
        {
            static uint8_t back[sizeof disk];
            FILE *f = fopen(d.disk, "rb");
            ASSERT(f != NULL);
            ASSERT(fread(back, 1, sizeof back, f) == sizeof back);
            ASSERT(fgetc(f) == EOF);
            ASSERT(fclose(f) == 0);
            ASSERT(memcmp(back, disk, sizeof disk) == 0);
        }
        test_cleanup_tmpdir(d.dir);
        PASS();
    } _test_next:;
    return failures;
}

/* ---- 7. things that happen during the run (the hooked twin) ---- */
static int t_during_run(void)
{
    int failures = 0;
    TEST("dev.app.machine.boot: an input that changes or a transcript that fails is a failure (twin)") {
        struct tmb_dir d;
        struct tmb_call c;
        char json[1024];
        ASSERT(tmb_setup(&d, "tiny"));
        snprintf(json, sizeof json,
                 "{\"kernel\":\"%s\",\"ram_mib\":64,\"max_instr\":100000,"
                 "\"transcript\":\"%s\"}", d.kernel, d.out);
        /* the hooked build with the hook idle is the real leaf */
        tmb_after_mode = TMB_AFTER_NOTHING;
        ASSERT(tmb_go(&c, mbtwin_handle, json));
        ASSERT(tmb_ok(&c));
        ASSERT_STR_EQ(tmb_str(&c, "transcript_sha256"), TMB_TINY_SHA);
        tmb_end(&c);
        ASSERT(unlink(d.out) == 0);
        /* the kernel file grows while the machine runs */
        tmb_after_mode = TMB_AFTER_GROW_KERNEL;
        tmb_after_path = d.kernel;
        tmb_after_done = false;
        ASSERT(tmb_go(&c, mbtwin_handle, json));
        tmb_after_mode = TMB_AFTER_NOTHING;
        ASSERT(tmb_after_done);
        ASSERT(tmb_failed(&c, "INPUT_CHANGED"));
        ASSERT_STR_EQ(tmb_error(&c, "phase"), "verify");
        ASSERT(tmb_evidence_has(&c, "retired=279"));
        ASSERT(tmb_evidence_has(&c, "sha256=" TMB_TINY_SHA));
        tmb_end(&c);
        ASSERT(unlink(d.out) == 0);
        /* the transcript stops taking bytes */
        tmb_after_mode = TMB_AFTER_BREAK_TRANSCRIPT;
        tmb_after_done = false;
        ASSERT(tmb_go(&c, mbtwin_handle, json));
        tmb_after_mode = TMB_AFTER_NOTHING;
        ASSERT(tmb_after_done);
        ASSERT(tmb_failed(&c, "TRANSCRIPT_WRITE_FAILED"));
        ASSERT(tmb_evidence_has(&c, "console_bytes=60"));
        tmb_end(&c);
        printf("\n    dev.app.machine.boot twin: idle hook passes, a grown kernel and a "
               "broken transcript are caught\n    ");
        test_cleanup_tmpdir(d.dir);
        PASS();
    } _test_next:;
    tmb_after_mode = TMB_AFTER_NOTHING;
    return failures;
}

/* ---- 8. the console limit (the twin with a limit of a few bytes) ---- */
static int t_console_limit(void)
{
    int failures = 0;
    TEST("dev.app.machine.boot: a guest that prints up to the console limit is stopped there (twin)") {
        struct tmb_dir d;
        struct tmb_call c;
        char json[1024], want[160], cut_sha[65];
        static uint8_t got[64];
        size_t len = 0;
        ASSERT_EQ(MB_CONSOLE_MAX, UINT64_C(64) << 20);
        ASSERT_EQ(tmb_console_max, (uint64_t)MB_CONSOLE_MAX);
        ASSERT(tmb_setup(&d, "tiny"));
        snprintf(json, sizeof json,
                 "{\"kernel\":\"%s\",\"ram_mib\":64,\"max_instr\":100000,"
                 "\"transcript\":\"%s\"}", d.kernel, d.out);
        /* 16 of the guest's 60 bytes: the run ends on the sixteenth */
        tmb_console_max = 16;
        ASSERT(tmb_go(&c, mbtwin_handle, json));
        tmb_console_max = MB_CONSOLE_MAX;
        ASSERT(tmb_failed(&c, "CONSOLE_LIMIT"));
        ASSERT_EQ(c.exit_code, ZCL_COMMAND_EXIT_FAILED);
        ASSERT_STR_EQ(tmb_error(&c, "phase"), "run");
        ASSERT_STR_EQ(tmb_error(&c, "current_state"), "requested");
        ASSERT(tmb_read(d.out, got, sizeof got, &len));
        ASSERT(len == 16 && memcmp(got, TMB_TINY_TEXT, 16) == 0);
        ASSERT(tmb_sha(d.out, cut_sha));
        snprintf(want, sizeof want, "console_bytes=16 script=0/0 sha256=%s", cut_sha);
        ASSERT(tmb_evidence_has(&c, want));
        ASSERT(tmb_evidence_has(&c, "stop=requested"));
        tmb_end(&c);
        ASSERT(unlink(d.out) == 0);
        /* a limit the output only just reaches still fails: the guest was cut */
        tmb_console_max = 60;
        ASSERT(tmb_go(&c, mbtwin_handle, json));
        tmb_console_max = MB_CONSOLE_MAX;
        ASSERT(tmb_failed(&c, "CONSOLE_LIMIT"));
        ASSERT(tmb_evidence_has(&c, "console_bytes=60"));
        ASSERT(tmb_same_sha(d.out, TMB_TINY_SHA));
        tmb_end(&c);
        ASSERT(unlink(d.out) == 0);
        /* one byte of room: the whole run, as the real leaf gives it */
        tmb_console_max = 61;
        ASSERT(tmb_go(&c, mbtwin_handle, json));
        tmb_console_max = MB_CONSOLE_MAX;
        ASSERT(tmb_ok(&c));
        ASSERT_STR_EQ(tmb_str(&c, "stop"), "shutdown");
        ASSERT_EQ(tmb_int(&c, "retired"), 279);
        ASSERT_STR_EQ(tmb_str(&c, "transcript_sha256"), TMB_TINY_SHA);
        tmb_end(&c);
        printf("\n    dev.app.machine.boot twin: a console limit of 16 and of 60 bytes "
               "stops the 60-byte guest, 61 lets it finish\n    ");
        test_cleanup_tmpdir(d.dir);
        PASS();
    } _test_next:;
    tmb_console_max = MB_CONSOLE_MAX;
    return failures;
}

/* ---- 9. typed input ---- */
static bool tmb_refused_input(const char *json)
{
    struct tmb_call c;
    bool refused = tmb_go(&c, NULL, json) && tmb_failed(&c, "INVALID_INPUT") &&
                   c.exit_code == ZCL_COMMAND_EXIT_INVALID;
    tmb_end(&c);
    return refused;
}

static int t_port_goal_refused(void)
{
    int failures = 0;
    TEST("dev.app.machine.boot: unopened byte port refuses despite a console goal or budget") {
        struct tmb_dir d;
        struct tmb_call c;
        char json[1600];
        char before[2u * SHA256_OUTPUT_SIZE + 1u];
        static const uint8_t bytes[3] = {'a', 0, 'b'};
        ASSERT(tmb_setup(&d, "tiny"));
        ASSERT(tmb_sha(d.kernel, before));
        ASSERT(tmb_write(d.disk, bytes, sizeof bytes));
        snprintf(json, sizeof json,
                 "{\"kernel\":\"%s\",\"ram_mib\":64,\"max_instr\":50,"
                 "\"ports\":[{\"name\":\"P\",\"input\":\"%s\",\"expect\":\"%s\"}]}",
                 d.kernel, d.disk, d.disk);
        ASSERT(tmb_go(&c, NULL, json));
        if (!tmb_failed(&c, "PORT_GOAL_MISSED"))
            printf("port refusal: code=%s message=%s evidence=%s\n", tmb_error(&c, "code"),
                   tmb_error(&c, "message"), tmb_error(&c, "evidence"));
        ASSERT(tmb_failed(&c, "PORT_GOAL_MISSED"));
        ASSERT(tmb_evidence_has(&c, "stop=budget"));
        char stop[32];
        int marker;
        unsigned long long retired, skip, firmware, device;
        ASSERT_EQ(sscanf(tmb_error(&c, "evidence"),
                        "stop=%31s marker_seen=%d retired=%llu skip=%llu fw_calls=%llu device_work=%llu",
                        stop, &marker, &retired, &skip, &firmware, &device), 6);
        ASSERT_EQ(retired + firmware + device, 50u);
        tmb_end(&c);
        snprintf(json, sizeof json,
                 "{\"kernel\":\"%s\",\"ram_mib\":64,\"max_instr\":100000,"
                 "\"until\":\"tiny: hello from S-mode\","
                 "\"ports\":[{\"name\":\"P\",\"input\":\"%s\",\"expect\":\"%s\"}]}",
                 d.kernel, d.disk, d.disk);
        ASSERT(tmb_go(&c, NULL, json));
        ASSERT(tmb_failed(&c, "PORT_GOAL_MISSED"));
        ASSERT(tmb_evidence_has(&c, "marker_seen=1"));
        tmb_end(&c);
        ASSERT(tmb_same_sha(d.kernel, before));
        test_cleanup_tmpdir(d.dir);
        PASS();
    } _test_next:;
    return failures;
}

static int t_port_guest_bytes(void)
{
    int failures = 0;
    TEST("dev.app.machine.boot: guest virtqueues echo exact binary bytes across partial feeds") {
        struct tmb_dir d;
        struct tmb_call c;
        static uint8_t bytes[8192];
        char json[1600], before[2u * SHA256_OUTPUT_SIZE + 1u];
        ASSERT(tmb_setup(&d, "conport"));
        for (unsigned trial = 0; trial < 2; trial++) {
            size_t n = trial == 0u ? 16u : sizeof bytes;
            for (size_t i = 0; i < n; i++) bytes[i] = (uint8_t)(i * 37u);
            zcl_write_u16_le(bytes, (uint16_t)n);
            ASSERT(tmb_write(d.disk, bytes, n));
            ASSERT(tmb_sha(d.disk, before));
            snprintf(json, sizeof json,
                     "{\"kernel\":\"%s\",\"ram_mib\":64,\"max_instr\":100000,"
                     "\"ports\":[{\"name\":\"fixture.echo\",\"input\":\"%s\",\"expect\":\"%s\"%s}]}",
                     d.kernel, d.disk, d.disk,
                     trial == 0u ? ",\"after\":\"FIXTURE-READY\\n\"" : "");
            ASSERT(tmb_go(&c, NULL, json));
            if (!tmb_ok(&c))
                printf("port exchange: code=%s message=%s evidence=%s\n", tmb_error(&c, "code"),
                       tmb_error(&c, "message"), tmb_error(&c, "evidence"));
            ASSERT(tmb_ok(&c));
            const struct json_value *ports = json_get(json_get(&c.doc, "data"), "ports");
            ASSERT(ports != NULL && ports->type == JSON_ARR && ports->num_children == 1u);
            const struct json_value *p = &ports->children[0];
            ASSERT_EQ(json_get_int(json_get(p, "accepted")), (int64_t)n);
            ASSERT_EQ(json_get_int(json_get(p, "received")), (int64_t)n);
            ASSERT_EQ(json_get_int(json_get(p, "driver_consumed")), (int64_t)n);
            ASSERT_EQ(json_get_int(json_get(p, "queued")), 0);
            ASSERT(json_get_bool(json_get(p, "matched")));
            ASSERT_STR_EQ(json_get_str(json_get(p, "accepted_output_sha256")), before);
            ASSERT(tmb_int(&c, "retired") + tmb_int(&c, "fw_calls") +
                   tmb_int(&c, "device_work") <= 100000);
            tmb_end(&c);
            ASSERT(tmb_same_sha(d.disk, before));
        }
        test_cleanup_tmpdir(d.dir);
        PASS();
    } _test_next:;
    return failures;
}

static int t_port_negative_bytes(void)
{
    int failures = 0;
    TEST("dev.app.machine.boot: wrong and extra binary replies and input mutation refuse") {
        struct tmb_dir d;
        struct tmb_call c;
        uint8_t bytes[17] = {16, 0, 0, 1, 2, 3, 4, 5};
        char json[1600];
        ASSERT(tmb_setup(&d, "conport"));
        ASSERT(tmb_write(d.disk, bytes, 16));
        for (unsigned trial = 0; trial < 4; trial++) {
            bytes[3] = trial == 0u ? 9u : 1u;
            ASSERT(tmb_write(d.link, bytes, trial == 1u ? 17u : trial == 3u ? 15u : 16u));
            snprintf(json, sizeof json,
                     "{\"kernel\":\"%s\",\"ram_mib\":64,\"max_instr\":100000,"
                     "\"ports\":[{\"name\":\"fixture.echo\",\"input\":\"%s\",\"expect\":\"%s\"}]}",
                     d.kernel, d.disk, d.link);
            tmb_after_mode = trial == 2u ? TMB_AFTER_GROW_KERNEL : TMB_AFTER_NOTHING;
            tmb_after_path = d.disk; tmb_after_done = false;
            ASSERT(tmb_go(&c, trial == 2u ? mbtwin_handle : NULL, json));
            ASSERT(tmb_failed(&c, trial == 2u ? "INPUT_CHANGED" : "PORT_GOAL_MISSED"));
            if (trial == 2u) ASSERT(tmb_after_done);
            tmb_end(&c);
        }
        tmb_after_mode = TMB_AFTER_NOTHING;
        test_cleanup_tmpdir(d.dir);
        PASS();
    } _test_next:;
    tmb_after_mode = TMB_AFTER_NOTHING;
    return failures;
}

static int t_port_ready_line(void)
{
    int failures = 0;
    TEST("dev.app.machine.boot: mentioning a readiness marker cannot release port input") {
        struct tmb_dir d;
        struct tmb_call c;
        static uint8_t image[TMB_FILE_MAX];
        uint8_t bytes[16] = {16, 0};
        size_t len = 0, replaced = 0;
        char json[1600];
        ASSERT(tmb_setup(&d, "conport"));
        ASSERT(tmb_read(d.kernel, image, sizeof image, &len));
        static const char marker[] = "FIXTURE-READY\n";
        for (size_t i = 1; i + sizeof marker <= len; i++) {
            if (image[i - 1u] == 0u && memcmp(image + i, marker, sizeof marker) == 0) {
                image[i] = 'X'; replaced++;
            }
        }
        ASSERT_EQ(replaced, 1u); /* preserve the echoed command mentioning the marker */
        ASSERT(tmb_write(d.kernel, image, len));
        ASSERT(tmb_write(d.disk, bytes, sizeof bytes));
        snprintf(json, sizeof json,
                 "{\"kernel\":\"%s\",\"ram_mib\":64,\"max_instr\":100000,"
                 "\"ports\":[{\"name\":\"fixture.echo\",\"input\":\"%s\",\"expect\":\"%s\","
                 "\"after\":\"FIXTURE-READY\\n\"}]}", d.kernel, d.disk, d.disk);
        ASSERT(tmb_go(&c, NULL, json));
        ASSERT(tmb_failed(&c, "PORT_GOAL_MISSED"));
        ASSERT(tmb_evidence_has(&c, "stop=budget"));
        tmb_end(&c);
        test_cleanup_tmpdir(d.dir);
        PASS();
    } _test_next:;
    return failures;
}

static int t_port_ready_epoch(void)
{
    int failures = 0;
    TEST("dev.app.machine.boot: readiness before reset cannot feed a reopened epoch") {
        struct tmb_dir d;
        struct tmb_call c;
        static uint8_t image[TMB_FILE_MAX];
        uint8_t bytes[16] = {16, 0};
        size_t len = 0, replaced = 0, mode_at = 0;
        char json[1600];
        ASSERT(tmb_setup(&d, "conport"));
        ASSERT(tmb_read(d.kernel, image, sizeof image, &len));
        for (size_t i = 0; i + 4u <= len; i++) {
            if (zcl_read_u32_le(image + i) == UINT32_C(0xfeed0000)) {
                mode_at = i; replaced++;
            }
        }
        ASSERT_EQ(replaced, 1u);
        ASSERT(tmb_write(d.disk, bytes, sizeof bytes));
        snprintf(json, sizeof json,
                 "{\"kernel\":\"%s\",\"ram_mib\":64,\"max_instr\":100000,"
                 "\"ports\":[{\"name\":\"fixture.echo\",\"input\":\"%s\",\"expect\":\"%s\","
                 "\"after\":\"FIXTURE-READY\\n\"}]}", d.kernel, d.disk, d.disk);
        for (unsigned mode = 1; mode <= 3; mode += 2) {
            image[mode_at] = (uint8_t)mode;
            ASSERT(tmb_write(d.kernel, image, len));
            ASSERT(tmb_go(&c, NULL, json));
            ASSERT(tmb_failed(&c, "PORT_GOAL_MISSED"));
            ASSERT(tmb_evidence_has(&c, mode == 1u ? "p0=0/0/0/0@" : "p0=16/0/0/0@"));
            tmb_end(&c);
        }
        test_cleanup_tmpdir(d.dir);
        PASS();
    } _test_next:;
    return failures;
}

static int t_port_hard_failure(void)
{
    int failures = 0;
    TEST("dev.app.machine.boot: guest faults retain their specific error with port evidence") {
        struct tmb_dir d;
        struct tmb_call c;
        static const uint8_t wild[4] = {0x67, 0, 0, 0};
        static const uint8_t input[3] = {3, 0, 1};
        char json[1600];
        ASSERT(tmb_setup(&d, "conport"));
        ASSERT(tmb_write(d.kernel, wild, sizeof wild));
        ASSERT(tmb_write(d.disk, input, sizeof input));
        snprintf(json, sizeof json,
                 "{\"kernel\":\"%s\",\"ram_mib\":64,\"max_instr\":100000,"
                 "\"ports\":[{\"name\":\"fixture.echo\",\"input\":\"%s\",\"expect\":\"%s\"}]}",
                 d.kernel, d.disk, d.disk);
        ASSERT(tmb_go(&c, NULL, json));
        ASSERT(tmb_failed(&c, "GUEST_FAULT"));
        ASSERT(tmb_evidence_has(&c, "pc=0x0"));
        ASSERT(tmb_evidence_has(&c, "p0=0/0/0/0@"));
        tmb_end(&c);
        test_cleanup_tmpdir(d.dir);
        PASS();
    } _test_next:;
    return failures;
}

static int t_port_alias_and_limit(void)
{
    int failures = 0;
    TEST("dev.app.machine.boot: port transcript aliases and aggregate byte overflow refuse") {
        struct tmb_dir d;
        struct tmb_call c;
        static uint8_t input[65536];
        char json[1600], before[2u * SHA256_OUTPUT_SIZE + 1u];
        ASSERT(tmb_setup(&d, "conport"));
        ASSERT(tmb_write(d.disk, input, 16));
        ASSERT(tmb_sha(d.disk, before));
        snprintf(json, sizeof json,
                 "{\"kernel\":\"%s\",\"ram_mib\":64,\"max_instr\":100000,"
                 "\"transcript\":\"%s\",\"ports\":[{\"name\":\"fixture.echo\",\"input\":\"%s\",\"expect\":\"%s\"}]}",
                 d.kernel, d.disk, d.disk, d.disk);
        ASSERT(tmb_go(&c, NULL, json));
        ASSERT(tmb_failed(&c, "TRANSCRIPT_IS_INPUT"));
        ASSERT(tmb_same_sha(d.disk, before));
        tmb_end(&c);
        ASSERT(tmb_write(d.disk, input, sizeof input));
        ASSERT(tmb_write(d.link, input, 1));
        snprintf(json, sizeof json,
                 "{\"kernel\":\"%s\",\"ram_mib\":64,\"max_instr\":100000,"
                 "\"ports\":[{\"name\":\"fixture.echo\",\"input\":\"%s\",\"expect\":\"%s\"}]}",
                 d.kernel, d.disk, d.link);
        ASSERT(tmb_go(&c, NULL, json));
        ASSERT(tmb_failed(&c, "INVALID_INPUT"));
        tmb_end(&c);
        test_cleanup_tmpdir(d.dir);
        PASS();
    } _test_next:;
    return failures;
}

static int t_port_atomic_budget(void)
{
    int failures = 0;
    TEST("dev.app.machine.boot: atomic port work cannot qualify above the requested budget") {
        struct tmb_dir d;
        struct tmb_call c;
        uint8_t input[16] = {16, 0};
        char json[1600];
        bool observed = false;
        ASSERT(tmb_setup(&d, "conport"));
        ASSERT(tmb_write(d.disk, input, sizeof input));
        snprintf(json, sizeof json,
                 "{\"kernel\":\"%s\",\"ram_mib\":64,\"max_instr\":100000,"
                 "\"ports\":[{\"name\":\"fixture.echo\",\"input\":\"%s\",\"expect\":\"%s\"}]}",
                 d.kernel, d.disk, d.disk);
        ASSERT(tmb_go(&c, NULL, json));
        ASSERT(tmb_ok(&c));
        int64_t total = tmb_int(&c, "retired") + tmb_int(&c, "fw_calls") + tmb_int(&c, "device_work");
        tmb_end(&c);
        ASSERT(total > 192);
        /* Bounded discovery around this exact guest's final device operation. */
        for (int64_t budget = total - 192; budget < total && !observed; budget++) {
            snprintf(json, sizeof json,
                     "{\"kernel\":\"%s\",\"ram_mib\":64,\"max_instr\":%lld,"
                     "\"ports\":[{\"name\":\"fixture.echo\",\"input\":\"%s\",\"expect\":\"%s\"}]}",
                     d.kernel, (long long)budget, d.disk, d.disk);
            ASSERT(tmb_go(&c, NULL, json));
            if (tmb_failed(&c, "PORT_BUDGET_EXCEEDED")) {
                char stop[32]; int marker;
                unsigned long long retired, skip, firmware, device;
                ASSERT_EQ(sscanf(tmb_error(&c, "evidence"),
                    "stop=%31s marker_seen=%d retired=%llu skip=%llu fw_calls=%llu device_work=%llu",
                    stop, &marker, &retired, &skip, &firmware, &device), 6);
                ASSERT(retired + firmware + device > (uint64_t)budget);
                observed = true;
            }
            tmb_end(&c);
        }
        ASSERT(observed);
        test_cleanup_tmpdir(d.dir);
        PASS();
    } _test_next:;
    return failures;
}

static int t_input_rules(void)
{
    int failures = 0;
    TEST("dev.app.machine.boot: input keys are typed and bounded before anything is opened") {
        const struct zcl_command_spec *spec =
            zcl_command_registry_find(zcl_command_catalog(), TMB_PATH, NULL);
        ASSERT(spec != NULL);
        ASSERT_STR_EQ(spec->output_schema, "zcl.dev_machine_boot.v1");
        ASSERT(tmb_refused_input("{}"));
        ASSERT(tmb_refused_input("{\"kernel\":\"\"}"));
        ASSERT(tmb_refused_input("{\"kernel\":7}"));
        ASSERT(tmb_refused_input("{\"kernel\":\"k\",\"surprise\":1}"));
        ASSERT(tmb_refused_input("{\"kernel\":\"k\",\"ram_mib\":\"64\"}"));
        ASSERT(tmb_refused_input("{\"kernel\":\"k\",\"ram_mib\":62}"));
        ASSERT(tmb_refused_input("{\"kernel\":\"k\",\"ram_mib\":65}"));
        ASSERT(tmb_refused_input("{\"kernel\":\"k\",\"ram_mib\":65538}"));
        ASSERT(tmb_refused_input("{\"kernel\":\"k\",\"max_instr\":0}"));
        ASSERT(tmb_refused_input("{\"kernel\":\"k\",\"max_instr\":\"many\"}"));
        ASSERT(tmb_refused_input("{\"kernel\":\"k\",\"entropy\":7}"));
        ASSERT(tmb_refused_input("{\"kernel\":\"k\",\"entropy\":\"test\"}"));
        ASSERT(tmb_refused_input("{\"kernel\":\"k\",\"entropy\":\"host\",\"test_entropy_seed\":7}"));
        ASSERT(tmb_refused_input("{\"kernel\":\"k\",\"until\":\"\"}"));
        ASSERT(tmb_refused_input("{\"kernel\":\"k\",\"type_after\":\"# \"}"));
        ASSERT(tmb_refused_input("{\"kernel\":\"k\",\"type_after\":[\"# \"]}"));
        ASSERT(tmb_refused_input("{\"kernel\":\"k\",\"type_after\":[[\"# \"]]}"));
        ASSERT(tmb_refused_input("{\"kernel\":\"k\",\"type_after\":[[\"# \",1]]}"));
        ASSERT(tmb_refused_input("{\"kernel\":\"k\",\"type_after\":[[\"\",\"x\"]]}"));
        ASSERT(tmb_refused_input("{\"kernel\":\"k\",\"transcript\":\"\"}"));
        ASSERT(tmb_refused_input("{\"kernel\":\"k\",\"ports\":{}}"));
        ASSERT(tmb_refused_input("{\"kernel\":\"k\",\"ports\":[]}"));
        ASSERT(tmb_refused_input("{\"kernel\":\"k\",\"ports\":[\"text\"]}"));
        ASSERT(tmb_refused_input("{\"kernel\":\"k\",\"ports\":[{}]}"));
        ASSERT(tmb_refused_input("{\"kernel\":\"k\",\"ports\":[{\"name\":\"T\",\"input\":\"i\",\"expect\":\"e\",\"extra\":1}]}"));
        ASSERT(tmb_refused_input("{\"kernel\":\"k\",\"ports\":[{\"name\":\"T\",\"name\":\"P\",\"input\":\"i\"}]}"));
        ASSERT(tmb_refused_input("{\"kernel\":\"k\",\"ports\":[{\"name\":\"T\",\"input\":\"i\",\"expect\":\"e\"},{\"name\":\"T\",\"input\":\"i\",\"expect\":\"e\"}]}"));

        PASS();
    } _test_next:;
    return failures;
}

/* ---- 10. the test entropy source ---- */
/* The first forty bytes of the seed-7 stream, worked out outside this tree:
 * sha256("z23 dev.app.machine.boot test entropy v1" || le64(7) || le64(block))
 * for block 0, then the first eight bytes of block 1. */
#define TMB_SEED7_TEXT                                                          \
    "entropy: 4d50b6adc143669eadf00cd7ec7531158c3efe2d18064e69bc7ba693f4435c31" \
    "93666d8ed35b05e9 len=28 irq=1\n"

static const struct json_value *tmb_entropy(const struct tmb_call *c, const char *key)
{
    return json_get(json_get(json_get(&c->doc, "data"), "entropy"), key);
}

static int t_entropy_seed(void)
{
    int failures = 0;
    TEST("dev.app.machine.boot: test_entropy_seed feeds the guest a fixed stream named as not secure") {
        struct tmb_dir d;
        struct tmb_call a, b, other, none;
        char json[1024];
        ASSERT(tmb_setup(&d, "entropy"));
        snprintf(json, sizeof json,
                 "{\"kernel\":\"%s\",\"ram_mib\":64,\"max_instr\":100000,"
                 "\"test_entropy_seed\":7}", d.kernel);
        ASSERT(tmb_go(&a, NULL, json));
        ASSERT(tmb_ok(&a));
        ASSERT_STR_EQ(tmb_str(&a, "stop"), "shutdown");
        ASSERT_STR_EQ(tmb_str(&a, "console_tail"), TMB_SEED7_TEXT);
        ASSERT_EQ(tmb_int(&a, "device_work"), 1);
        ASSERT_STR_EQ(json_get_str(tmb_entropy(&a, "source")), "test_seed");
        ASSERT(tmb_entropy(&a, "secure") != NULL);
        ASSERT(tmb_entropy(&a, "secure")->type == JSON_BOOL);
        ASSERT(!json_get_bool(tmb_entropy(&a, "secure")));
        ASSERT_EQ(json_get_int(tmb_entropy(&a, "bytes")), 40);
        /* the same seed: the same receipt */
        ASSERT(tmb_go(&b, NULL, json));
        ASSERT(tmb_ok(&b));
        ASSERT_STR_EQ(tmb_str(&b, "transcript_sha256"), tmb_str(&a, "transcript_sha256"));
        ASSERT_EQ(tmb_int(&b, "retired"), tmb_int(&a, "retired"));
        /* another seed: other bytes, the same amount of work */
        snprintf(json, sizeof json,
                 "{\"kernel\":\"%s\",\"ram_mib\":64,\"max_instr\":100000,"
                 "\"test_entropy_seed\":8}", d.kernel);
        ASSERT(tmb_go(&other, NULL, json));
        ASSERT(tmb_ok(&other));
        ASSERT(strstr(tmb_str(&other, "console_tail"),
                      "entropy: 31574a4ac2dbea97d5c23812dc78c79e") != NULL);
        ASSERT(strcmp(tmb_str(&other, "transcript_sha256"),
                      tmb_str(&a, "transcript_sha256")) != 0);
        ASSERT_EQ(tmb_int(&other, "device_work"), 1);
        /* no seed: no entropy device, and the receipt names none */
        snprintf(json, sizeof json,
                 "{\"kernel\":\"%s\",\"ram_mib\":64,\"max_instr\":100000}", d.kernel);
        ASSERT(tmb_go(&none, NULL, json));
        ASSERT(tmb_ok(&none));
        ASSERT_STR_EQ(tmb_str(&none, "console_tail"), "entropy: no device\n");
        ASSERT(json_get(json_get(&none.doc, "data"), "entropy") == NULL);
        ASSERT_EQ(tmb_int(&none, "device_work"), 0);
        tmb_end(&a);
        tmb_end(&b);
        tmb_end(&other);
        tmb_end(&none);
        /* a seeded run that fails still names its entropy source */
        snprintf(json, sizeof json,
                 "{\"kernel\":\"%s\",\"ram_mib\":64,\"max_instr\":100000,"
                 "\"test_entropy_seed\":7,\"until\":\"never printed\"}", d.kernel);
        ASSERT(tmb_go(&a, NULL, json));
        ASSERT(tmb_failed(&a, "GOAL_MISSED"));
        ASSERT_STR_EQ(tmb_error(&a, "current_state"),
                      "shutdown entropy=test_seed,not_secure");
        ASSERT(tmb_evidence_has(&a, "device_work=1 "));
        tmb_end(&a);
        /* the seed is a non-negative integer */
        ASSERT(tmb_refused_input("{\"kernel\":\"k\",\"test_entropy_seed\":-1}"));
        ASSERT(tmb_refused_input("{\"kernel\":\"k\",\"test_entropy_seed\":\"7\"}"));
        ASSERT(tmb_refused_input("{\"kernel\":\"k\",\"test_entropy_seed\":true}"));
        test_cleanup_tmpdir(d.dir);
        PASS();
    } _test_next:;
    return failures;
}

/* ---- 11. the boot seed ---- */
#define TMB_ELF_TEXT 0x1000u /* file offset of the image inside the wrapper */

/* Replaces the kernel in the directory by the preload fixture wrapped as an
 * ELF: one readable and executable segment linked at 0xffffffc000000000,
 * loaded at 0x80200000, entered 0x30 into it. */
static bool tmb_setup_elf(struct tmb_dir *d)
{
    static uint8_t text[TMB_FILE_MAX], elf[TMB_ELF_TEXT + TMB_FILE_MAX];
    static const uint8_t ident[8] = {0x7f, 'E', 'L', 'F', 2, 1, 1, 0};
    const uint64_t vaddr = UINT64_C(0xffffffc000000000);
    uint8_t *ph = elf + 64;
    size_t len = 0;
    if (!tmb_setup(d, "preload") || !tmb_read(d->kernel, text, sizeof text, &len))
        return false;
    memset(elf, 0, TMB_ELF_TEXT);
    memcpy(elf, ident, sizeof ident);
    zcl_write_u16_le(elf + 16, 2);   /* ET_EXEC */
    zcl_write_u16_le(elf + 18, 243); /* EM_RISCV */
    zcl_write_u32_le(elf + 20, 1);
    zcl_write_u64_le(elf + 24, vaddr + 0x30u); /* e_entry */
    zcl_write_u64_le(elf + 32, 64);            /* e_phoff */
    zcl_write_u16_le(elf + 52, 64);
    zcl_write_u16_le(elf + 54, 56);
    zcl_write_u16_le(elf + 56, 1);
    zcl_write_u32_le(ph, 1);     /* PT_LOAD */
    zcl_write_u32_le(ph + 4, 5); /* read, execute */
    zcl_write_u64_le(ph + 8, TMB_ELF_TEXT);
    zcl_write_u64_le(ph + 16, vaddr);
    zcl_write_u64_le(ph + 24, UINT64_C(0x80200000));
    zcl_write_u64_le(ph + 32, len);
    zcl_write_u64_le(ph + 40, len);
    memcpy(elf + TMB_ELF_TEXT, text, len);
    return tmb_write(d->kernel, elf, TMB_ELF_TEXT + len);
}

/* What the preload fixture prints at its loader entry in a 64 MiB machine.
 * The last line is the checksum (sum = sum * 31 + byte) of the 2048 bytes of
 * the seed-7 boot seed stream, worked out outside this tree: blocks 0..63 of
 * sha256("z23 dev.app.machine.boot test early seed v1" || le64(7) || le64(block)).
 * The entropy device's stream of the same seed would give 07c38298381f9c3d. */
#define TMB_PRELOAD_TEXT            \
    "0001 07 kernel\n"              \
    "0002 0b elf kernel\n"          \
    "0003 08 ffffffc000000000\n"    \
    "0004 08 000000000000024f\n"    \
    "9001 08 ffffffc000001000\n"    \
    "8008 08 ffffffc000004000\n"    \
    "8007 04 0000000000000800\n"    \
    "9004 08 0000000000000000\n"    \
    "0001 08 entropy\n"             \
    "0002 16 boot_entropy_platform\n" \
    "0003 08 ffffffc000002000\n"    \
    "0004 08 0000000000000800\n"    \
    "tree 00000000edfe0dd0\n"       \
    "seed 486d2fb7715f80b0\n"

static const struct json_value *tmb_early(const struct tmb_call *c, const char *key)
{
    return json_get(json_get(json_get(&c->doc, "data"), "early_seed"), key);
}

static bool tmb_file_is(const char *path, const char *text)
{
    static uint8_t buf[TMB_FILE_MAX];
    size_t len = 0;
    return tmb_read(path, buf, sizeof buf, &len) && len == strlen(text) &&
           memcmp(buf, text, len) == 0;
}

static int t_early_seed(void)
{
    int failures = 0;
    TEST("dev.app.machine.boot: early_seed enters the kernel at its loader entry with a boot seed from the test stream") {
        struct tmb_dir d;
        struct tmb_call a, plain;
        char json[1024];
        ASSERT(tmb_setup_elf(&d));
        snprintf(json, sizeof json,
                 "{\"kernel\":\"%s\",\"ram_mib\":64,\"max_instr\":100000,"
                 "\"test_entropy_seed\":7,\"early_seed\":\"test\",\"transcript\":\"%s\"}",
                 d.kernel, d.out);
        ASSERT(tmb_go(&a, NULL, json));
        ASSERT(tmb_ok(&a));
        ASSERT_STR_EQ(tmb_str(&a, "stop"), "shutdown");
        ASSERT(tmb_file_is(d.out, TMB_PRELOAD_TEXT));
        ASSERT_STR_EQ(json_get_str(tmb_early(&a, "source")), "test_seed");
        ASSERT(tmb_early(&a, "secure") != NULL);
        ASSERT(tmb_early(&a, "secure")->type == JSON_BOOL);
        ASSERT(!json_get_bool(tmb_early(&a, "secure")));
        ASSERT_EQ(json_get_int(tmb_early(&a, "bytes")), 2048);
        ASSERT(tmb_early(&a, "cleared") != NULL);
        ASSERT(json_get_bool(tmb_early(&a, "cleared"))); /* the guest zeroed the seed */
        /* the entropy device of the same seed is there too and gave nothing */
        ASSERT_EQ(json_get_int(tmb_entropy(&a, "bytes")), 0);
        tmb_end(&a);
        /* without the key the same file is entered the firmware way */
        ASSERT(unlink(d.out) == 0);
        snprintf(json, sizeof json,
                 "{\"kernel\":\"%s\",\"ram_mib\":64,\"max_instr\":100000,"
                 "\"test_entropy_seed\":7,\"transcript\":\"%s\"}", d.kernel, d.out);
        ASSERT(tmb_go(&plain, NULL, json));
        ASSERT(tmb_ok(&plain));
        ASSERT(tmb_file_is(d.out, "preload: firmware entry\n"));
        ASSERT(json_get(json_get(&plain.doc, "data"), "early_seed") == NULL);
        tmb_end(&plain);
        /* a seeded run that fails still names both test sources */
        ASSERT(unlink(d.out) == 0);
        snprintf(json, sizeof json,
                 "{\"kernel\":\"%s\",\"ram_mib\":64,\"max_instr\":100000,"
                 "\"test_entropy_seed\":7,\"early_seed\":\"test\","
                 "\"until\":\"never printed\"}", d.kernel);
        ASSERT(tmb_go(&a, NULL, json));
        ASSERT(tmb_failed(&a, "GOAL_MISSED"));
        ASSERT_STR_EQ(tmb_error(&a, "current_state"),
                      "shutdown entropy+early_seed=test_seed,not_secure");
        tmb_end(&a);
        test_cleanup_tmpdir(d.dir);
        PASS();
    } _test_next:;
    return failures;
}

static int t_early_seed_refused(void)
{
    int failures = 0;
    TEST("dev.app.machine.boot: early_seed requires its selected source and refuses a kernel without a loader entry") {
        struct tmb_dir d;
        struct tmb_call c;
        char json[1024];
        /* host mode is explicit, before anything is opened */
        ASSERT(tmb_go(&c, NULL, "{\"kernel\":\"k\",\"test_entropy_seed\":7,"
                                "\"early_seed\":\"host\"}"));
        ASSERT(tmb_failed(&c, "SEED_SOURCE_NOT_OFFERED"));
        ASSERT_EQ(c.exit_code, ZCL_COMMAND_EXIT_INVALID);
        ASSERT_STR_EQ(tmb_error(&c, "phase"), "input");
        ASSERT(strstr(tmb_error(&c, "message"),
                      "early_seed host requires entropy host") != NULL);
        tmb_end(&c);
        /* the test stream needs its seed; no other word is a source */
        ASSERT(tmb_refused_input("{\"kernel\":\"k\",\"early_seed\":\"test\"}"));
        ASSERT(tmb_refused_input("{\"kernel\":\"k\",\"test_entropy_seed\":7,"
                                 "\"early_seed\":\"urandom\"}"));
        ASSERT(tmb_refused_input("{\"kernel\":\"k\",\"test_entropy_seed\":7,"
                                 "\"early_seed\":\"\"}"));
        ASSERT(tmb_refused_input("{\"kernel\":\"k\",\"test_entropy_seed\":7,"
                                 "\"early_seed\":true}"));
        ASSERT(tmb_refused_input("{\"kernel\":\"k\",\"test_entropy_seed\":7,"
                                 "\"early_seed\":2048}"));
        /* a flat image has no loader entry: refused by name, no guest, no transcript */
        ASSERT(tmb_setup(&d, "tiny"));
        snprintf(json, sizeof json,
                 "{\"kernel\":\"%s\",\"ram_mib\":64,\"max_instr\":100000,"
                 "\"test_entropy_seed\":7,\"early_seed\":\"test\",\"transcript\":\"%s\"}",
                 d.kernel, d.out);
        ASSERT(tmb_go(&c, NULL, json));
        ASSERT(tmb_failed(&c, "MACHINE_REFUSED"));
        ASSERT_STR_EQ(tmb_error(&c, "phase"), "load");
        ASSERT_STR_EQ(tmb_error(&c, "message"),
                      "the kernel image has no loader entry to take a boot seed");
        ASSERT(tmb_absent(d.out));
        tmb_end(&c);
        test_cleanup_tmpdir(d.dir);
        PASS();
    } _test_next:;
    return failures;
}

/* ---- 12. the command row: canonical path, alias, development surface ---- */
static int t_command_row(void)
{
    int failures = 0;
    TEST("dev.app.machine.boot: the alias dev.machine.boot is the same row, and only the development build binds it") {
        static const char *const canonical[] = {"dev", "app", "machine", "boot", "extra"};
        static const char *const alias[] = {"dev", "machine", "boot", "extra"};
        const struct zcl_command_registry *catalog = zcl_command_catalog();
        const struct zcl_command_spec *spec, *branch;
        char invoked[ZCL_COMMAND_MAX_PATH];
        size_t consumed = 0;
        bool was_alias = true;
        spec = zcl_command_registry_find(catalog, TMB_PATH, &was_alias);
        ASSERT(spec != NULL);
        ASSERT(!was_alias);
        ASSERT_STR_EQ(spec->path, "dev.app.machine.boot");
        ASSERT_STR_EQ(spec->parent, "dev.app.machine");
        ASSERT_STR_EQ(spec->aliases, "dev.machine.boot");
        ASSERT_STR_EQ(spec->output_schema, "zcl.dev_machine_boot.v1");
        branch = zcl_command_registry_find(catalog, "dev.app.machine", NULL);
        ASSERT(branch != NULL);
        ASSERT_STR_EQ(branch->parent, "dev.app");
        /* the old path is an alias of the leaf, not a second command or branch */
        ASSERT(zcl_command_registry_find(catalog, TMB_ALIAS, &was_alias) == spec);
        ASSERT(was_alias);
        ASSERT(zcl_command_registry_find(catalog, "dev.machine", NULL) == NULL);
        /* command-line words reach the leaf both ways and stop at it */
        ASSERT(zcl_command_registry_resolve_words(catalog, canonical, 5, &consumed,
                                                  &was_alias, invoked,
                                                  sizeof invoked) == spec);
        ASSERT_EQ(consumed, 4u);
        ASSERT(!was_alias);
        ASSERT_STR_EQ(invoked, TMB_PATH);
        ASSERT(zcl_command_registry_resolve_words(catalog, alias, 4, &consumed,
                                                  &was_alias, invoked,
                                                  sizeof invoked) == spec);
        ASSERT_EQ(consumed, 3u);
        ASSERT(was_alias);
        ASSERT_STR_EQ(invoked, TMB_ALIAS);
#ifdef ZCL_DEV_BUILD
        ASSERT(spec->handler == zcl_native_handle_dev_machine_boot);
#else
        struct tmb_dir d;
        struct tmb_call c;
        char json[1024];
        /* a release-shape build lists the leaf, names where it runs and runs
         * nothing, under either name */
        ASSERT(spec->handler == NULL);
        ASSERT_STR_EQ(spec->compat_target, "z23-dev dev app machine boot");
        ASSERT(tmb_setup(&d, "tiny"));
        snprintf(json, sizeof json,
                 "{\"kernel\":\"%s\",\"ram_mib\":64,\"max_instr\":100000,"
                 "\"transcript\":\"%s\"}", d.kernel, d.out);
        ASSERT(tmb_dispatch(&c, spec, json));
        ASSERT(tmb_failed(&c, "COMMAND_COMPAT_ONLY"));
        ASSERT_EQ(c.exit_code, ZCL_COMMAND_EXIT_BLOCKED);
        ASSERT(tmb_absent(d.out));
        tmb_end(&c);
        ASSERT(tmb_dispatch(&c, zcl_command_registry_find(catalog, TMB_ALIAS, NULL),
                            json));
        ASSERT(tmb_failed(&c, "COMMAND_COMPAT_ONLY"));
        ASSERT_EQ(c.exit_code, ZCL_COMMAND_EXIT_BLOCKED);
        ASSERT(tmb_absent(d.out));
        tmb_end(&c);
        /* the test entropy key belongs to the same unbound row: a seeded input
         * is turned away the same way and starts no guest */
        snprintf(json, sizeof json,
                 "{\"kernel\":\"%s\",\"ram_mib\":64,\"max_instr\":100000,"
                 "\"test_entropy_seed\":7,\"transcript\":\"%s\"}", d.kernel, d.out);
        ASSERT(tmb_dispatch(&c, spec, json));
        ASSERT(tmb_failed(&c, "COMMAND_COMPAT_ONLY"));
        ASSERT_EQ(c.exit_code, ZCL_COMMAND_EXIT_BLOCKED);
        ASSERT(tmb_absent(d.out));
        tmb_end(&c);
        test_cleanup_tmpdir(d.dir);
#endif
        PASS();
    } _test_next:;
    return failures;
}

static int t_host_entropy_run(void)
{
    int failures = 0;
    TEST("dev.app.machine.boot: native entropy delivery is explicit and source failure refuses the run") {
        struct tmb_dir d;
        struct tmb_call c;
        char input[1024];
        ASSERT(tmb_setup(&d, "entropy"));
        snprintf(input, sizeof input,
                 "{\"kernel\":\"%s\",\"ram_mib\":64,\"max_instr\":100000,"
                 "\"entropy\":\"host\"}", d.kernel);
        tmb_host_calls = 0;
        tmb_host_fail_call = 0;
        ASSERT(tmb_go(&c, mbtwin_handle, input));
        ASSERT(tmb_ok(&c));
        ASSERT_EQ(tmb_host_calls, 1);
        ASSERT_STR_EQ(json_get_str(tmb_entropy(&c, "source")), "host_os_csprng");
        ASSERT_EQ(json_get_int(tmb_entropy(&c, "bytes")), 40);
        ASSERT(tmb_entropy(&c, "secure") == NULL);
        ASSERT_STR_EQ(json_get_str(tmb_entropy(&c, "guest_rng_health")), "unobserved");
        tmb_end(&c);
        tmb_host_calls = 0;
        tmb_host_fail_call = 1;
        ASSERT(tmb_go(&c, mbtwin_handle, input));
        ASSERT(tmb_failed(&c, "ENTROPY_SOURCE_FAILED"));
        ASSERT_EQ(tmb_host_calls, 1);
        ASSERT(strstr(tmb_error(&c, "current_state"), "source_failed=1 bytes=0 early_bytes=0") != NULL);
        tmb_end(&c);
        test_cleanup_tmpdir(d.dir);
        PASS();
    } _test_next:;
    tmb_host_fail_call = 0;
    return failures;
}

static int t_host_work_budget(void)
{
    int failures = 0;
    TEST("dev.app.machine.boot: host entropy atomic work cannot qualify above its requested budget") {
        struct tmb_dir d;
        struct tmb_call c;
        char input[1024];
        ASSERT(tmb_setup(&d, "entropy"));
        snprintf(input, sizeof input,
                 "{\"kernel\":\"%s\",\"ram_mib\":64,\"max_instr\":100000,\"entropy\":\"host\"}", d.kernel);
        tmb_host_fail_call = 0;
        ASSERT(tmb_go(&c, mbtwin_handle, input));
        ASSERT(tmb_ok(&c));
        uint64_t low = 1;
        uint64_t high = (uint64_t)(tmb_int(&c, "retired") + tmb_int(&c, "fw_calls") +
                                   tmb_int(&c, "device_work"));
        ASSERT(high < 100000);
        tmb_end(&c);
        bool observed = false;
        for (unsigned turn = 0; turn < 64u && low <= high && !observed; turn++) {
            uint64_t budget = low + (high - low) / 2u;
            snprintf(input, sizeof input,
                     "{\"kernel\":\"%s\",\"ram_mib\":64,\"max_instr\":%llu,\"entropy\":\"host\"}",
                     d.kernel, (unsigned long long)budget);
            ASSERT(tmb_go(&c, mbtwin_handle, input));
            if (tmb_failed(&c, "WORK_BUDGET_EXCEEDED")) {
                char stop[32]; int marker;
                unsigned long long retired, skip, firmware, device;
                ASSERT_EQ(sscanf(tmb_error(&c, "evidence"),
                    "stop=%31s marker_seen=%d retired=%llu skip=%llu fw_calls=%llu device_work=%llu",
                    stop, &marker, &retired, &skip, &firmware, &device), 6);
                ASSERT(retired + firmware + device > budget);
                ASSERT(device > 0);
                observed = true;
            } else {
                ASSERT(tmb_ok(&c));
                if (tmb_int(&c, "device_work") != 0) high = budget - 1u;
                else low = budget + 1u;
            }
            tmb_end(&c);
        }
        ASSERT(observed);
        test_cleanup_tmpdir(d.dir);
        PASS();
    } _test_next:;
    return failures;
}

static int t_host_early_seed(void)
{
    int failures = 0;
    TEST("dev.app.machine.boot: early host seed is fresh and source failure never enters the guest") {
        struct tmb_dir d;
        struct tmb_call c;
        char input[1024];
        ASSERT(tmb_setup_elf(&d));
        snprintf(input, sizeof input,
                 "{\"kernel\":\"%s\",\"ram_mib\":64,\"max_instr\":100000,"
                 "\"entropy\":\"host\",\"early_seed\":\"host\",\"transcript\":\"%s\"}",
                 d.kernel, d.out);
        tmb_host_calls = 0;
        tmb_host_fail_call = 1;
        ASSERT(tmb_go(&c, mbtwin_handle, input));
        ASSERT(tmb_failed(&c, "MACHINE_REFUSED"));
        ASSERT_STR_EQ(tmb_error(&c, "phase"), "load");
        ASSERT_STR_EQ(tmb_error(&c, "message"), "the boot seed source failed");
        ASSERT_EQ(tmb_host_calls, 1);
        ASSERT(tmb_absent(d.out));
        tmb_end(&c);
        tmb_host_calls = 0;
        tmb_host_fail_call = 0;
        ASSERT(tmb_go(&c, mbtwin_handle, input));
        ASSERT(tmb_ok(&c));
        ASSERT_STR_EQ(json_get_str(tmb_early(&c, "source")), "host_os_csprng");
        ASSERT_EQ(json_get_int(tmb_early(&c, "bytes")), 2048);
        ASSERT_EQ(json_get_int(tmb_entropy(&c, "bytes")), 0);
        ASSERT_EQ(tmb_host_calls, 1);
        tmb_end(&c);
        test_cleanup_tmpdir(d.dir);
        PASS();
    } _test_next:;
    tmb_host_fail_call = 0;
    return failures;
}

static bool tmb_private_fixture(const char *path, struct platform_private_file *file)
{
    platform_private_file_init(file);
    return platform_private_file_open_locked_create(path, file) &&
        platform_private_file_truncate(file, 4096) &&
        platform_private_file_authority_flush(file);
}

static int t_private_volume_restart(void)
{
    int failures = 0;
    struct platform_private_file file;
    platform_private_file_init(&file);
    TEST("dev.app.machine.boot: a nonsecret retained private volume survives an independent process restart") {
        struct tmb_dir d;
        ASSERT(tmb_setup(&d, "tiny"));
        ASSERT(tmb_private_fixture(d.out, &file));
        platform_private_file_close(&file);
        const char *modes[] = {"write", "read"};
        const char *markers[] = {"VOLUME_WRITER_DURABLE\n", "VOLUME_RESTART_READ_MATCH\n"};
        for (unsigned i = 0; i < 2u; i++) {
            const char *argv[] = {"build/bin/z23-machine-volume-fixture", modes[i], d.out, NULL};
            char output[128];
            struct zcl_spawn_binary_observation observed = {0};
            struct zcl_result result = zcl_spawn_capture_binary(argv, output, sizeof output,
                                                               5000, &observed);
            if (!result.ok)
                fprintf(stderr, "PUBLIC volume restart mode=%s code=%d message=%s "
                    "timeout=%d overflow=%d eof=%d exit_observed=%d exit=%d bytes=%zu\n",
                    modes[i], result.code, result.message, observed.timed_out,
                    observed.overflow, observed.eof, observed.exit_observed,
                    observed.exit_code, observed.output_len);
            ASSERT(result.ok);
            ASSERT(!observed.timed_out && !observed.overflow);
            ASSERT(observed.eof && observed.exit_observed);
            ASSERT_EQ(observed.exit_code, 0);
            ASSERT_EQ(observed.output_len, strlen(markers[i]));
            ASSERT(memcmp(output, markers[i], observed.output_len) == 0);
        }
        test_cleanup_tmpdir(d.dir);
        PASS();
    } _test_next:;
    platform_private_file_close(&file);
    return failures;
}

static int t_private_volume_refusals(void)
{
    int failures = 0;
    struct platform_private_file file;
    struct rvmachine_disk *disk = NULL;
    platform_private_file_init(&file);
    TEST("dev.app.machine.boot: private volume mode and size mutation latch refusal on the retained descriptor") {
        struct tmb_dir d;
        struct zcl_machine_private_volume v;
        uint8_t byte = 0x61;
        ASSERT(tmb_setup(&d, "tiny"));
        ASSERT(tmb_private_fixture(d.out, &file));
        ASSERT(chmod(d.out, 0640) == 0);
        ASSERT(!zcl_machine_private_volume_bind(&v, &file, &disk));
        ASSERT(disk == NULL);
        ASSERT(chmod(d.out, 0600) == 0);
        ASSERT(zcl_machine_private_volume_bind(&v, &file, &disk));
        ASSERT(chmod(d.out, 0640) == 0);
        ASSERT(!rvmachine_disk_write(disk, 0, &byte, 1));
        ASSERT(v.failed);
        ASSERT(chmod(d.out, 0600) == 0);
        ASSERT(!rvmachine_disk_write(disk, 0, &byte, 1));
        ASSERT(!rvmachine_disk_read(disk, 0, &byte, 1));
        ASSERT(!rvmachine_disk_flush(disk));
        rvmachine_disk_close(disk); disk = NULL;
        ASSERT(file.locked); /* borrowed validation never released the owner */
        ASSERT(zcl_machine_private_volume_bind(&v, &file, &disk));
        ASSERT(platform_private_file_truncate(&file, 2048));
        ASSERT(!rvmachine_disk_flush(disk));
        ASSERT(v.failed);
        rvmachine_disk_close(disk); disk = NULL;
        platform_private_file_close(&file);
        test_cleanup_tmpdir(d.dir);
        PASS();
    } _test_next:;
    rvmachine_disk_close(disk);
    platform_private_file_close(&file);
    return failures;
}

static int t_private_volume_path_replacement(void)
{
    int failures = 0;
    struct platform_private_file file, replacement;
    struct rvmachine_disk *disk = NULL;
    platform_private_file_init(&file);
    platform_private_file_init(&replacement);
    TEST("dev.app.machine.boot: pathname replacement never redirects a retained private volume") {
        struct tmb_dir d;
        struct zcl_machine_private_volume v;
        uint8_t original = 0x31, fresh = 0x72, got = 0;
        ASSERT(tmb_setup(&d, "tiny"));
        ASSERT(tmb_private_fixture(d.out, &file));
        ASSERT(zcl_machine_private_volume_bind(&v, &file, &disk));
        ASSERT(rvmachine_disk_write(disk, 0, &original, 1));
        ASSERT(rename(d.out, d.link) == 0);
        ASSERT(tmb_private_fixture(d.out, &replacement));
        ASSERT(platform_private_file_write_at(&replacement, &fresh, 1, 0));
        ASSERT(rvmachine_disk_read(disk, 0, &got, 1));
        ASSERT_EQ(got, original);
        original = 0x42;
        ASSERT(rvmachine_disk_write(disk, 0, &original, 1));
        ASSERT(rvmachine_disk_flush(disk));
        ASSERT(platform_private_file_read_at(&file, &got, 1, 0));
        ASSERT_EQ(got, original);
        ASSERT(platform_private_file_read_at(&replacement, &got, 1, 0));
        ASSERT_EQ(got, fresh);
        ASSERT(!v.failed);
        rvmachine_disk_close(disk); disk = NULL;
        platform_private_file_close(&file);
        platform_private_file_close(&replacement);
        test_cleanup_tmpdir(d.dir);
        PASS();
    } _test_next:;
    rvmachine_disk_close(disk);
    platform_private_file_close(&file);
    platform_private_file_close(&replacement);
    return failures;
}

static int t_private_volume_flush_failure(void)
{
    int failures = 0;
    struct platform_private_file file;
    struct rvmachine_disk *disk = NULL;
    platform_private_file_init(&file);
    TEST("dev.app.machine.boot: a private volume durability failure forbids subsequent backend work") {
        struct tmb_dir d;
        struct zcl_machine_private_volume v;
        uint8_t byte = 0x63;
        ASSERT(tmb_setup(&d, "tiny"));
        ASSERT(tmb_private_fixture(d.out, &file));
        tmb_volume_owner_fail = true;
        ASSERT(!tmb_volume_bind(&v, &file, &disk));
        ASSERT(disk == NULL);
        tmb_volume_owner_fail = false;
        ASSERT(tmb_volume_bind(&v, &file, &disk));
        tmb_volume_owner_fail = true;
        ASSERT(!rvmachine_disk_read(disk, 0, &byte, 1));
        ASSERT(v.failed);
        tmb_volume_owner_fail = false;
        ASSERT(!rvmachine_disk_write(disk, 0, &byte, 1));
        ASSERT(!rvmachine_disk_flush(disk));
        rvmachine_disk_close(disk); disk = NULL;
        ASSERT(tmb_volume_bind(&v, &file, &disk));
        ASSERT(rvmachine_disk_write(disk, 0, &byte, 1));
        tmb_volume_flush_calls = 0;
        tmb_volume_flush_fail = true;
        ASSERT(!rvmachine_disk_flush(disk));
        ASSERT(v.failed);
        ASSERT_EQ(v.flush_sequence, UINT64_C(0));
        ASSERT_EQ(v.write_sequence, UINT64_C(1));
        tmb_volume_flush_fail = false;
        ASSERT(!rvmachine_disk_flush(disk));
        ASSERT(!rvmachine_disk_write(disk, 1, &byte, 1));
        ASSERT_EQ(tmb_volume_flush_calls, 1u);
        rvmachine_disk_close(disk); disk = NULL;
        ASSERT(tmb_volume_bind(&v, &file, &disk));
        ASSERT(rvmachine_disk_flush(disk));
        ASSERT(v.flush_sequence > v.write_sequence);
        v.sequence = UINT64_MAX;
        byte = 0x7a;
        ASSERT(!rvmachine_disk_write(disk, 0, &byte, 1));
        ASSERT(v.failed);
        ASSERT(platform_private_file_read_at(&file, &byte, 1, 0));
        ASSERT_EQ(byte, 0x63);
        ASSERT(!rvmachine_disk_flush(disk));
        rvmachine_disk_close(disk); disk = NULL;
        ASSERT(tmb_volume_bind(&v, &file, &disk));
        v.sequence = UINT64_MAX;
        tmb_volume_flush_calls = 0;
        ASSERT(!rvmachine_disk_flush(disk));
        ASSERT_EQ(tmb_volume_flush_calls, 0u);
        ASSERT(v.failed && v.flush_sequence == 0);
        rvmachine_disk_close(disk); disk = NULL;
        ASSERT(file.locked);
        platform_private_file_close(&file);
        test_cleanup_tmpdir(d.dir);
        PASS();
    } _test_next:;
    tmb_volume_owner_fail = false;
    tmb_volume_flush_fail = false;
    rvmachine_disk_close(disk);
    platform_private_file_close(&file);
    return failures;
}

static int t_private_public_capture(void)
{
    int failures = 0;
    static struct mb_state st;
    static struct rvmachine machine;
    struct sha256_ctx before;
    struct zcl_command_reply reply = {0};
    const uint8_t byte = 0x6b; /* PUBLIC fixture byte, no credential. */
    TEST("public boot capture refuses private and absent machines before copying bytes") {
        memset(&st, 0, sizeof st);
        memset(&machine, 0, sizeof machine);
        sha256_init(&st.sha); before = st.sha;
        st.m = &machine; machine.conport_count = 1;
        machine.conports[0].private_keyfile = true;
        st.port_count = 1; st.ports[0].started = true;
        st.ports[0].expect.before.size = 1;
        st.ports[0].expected_bytes[0] = byte;
        mb_console(&st, byte);
        ASSERT_EQ(mb_port_sink(&st, 0, &byte, 1), (size_t)0);
        ASSERT(st.private_export_failed);
        ASSERT_EQ(st.buf_len, (size_t)0); ASSERT_EQ(st.tail_len, (size_t)0);
        ASSERT_EQ(st.script.console_bytes, (uint64_t)0);
        ASSERT_EQ(st.ports[0].received, (size_t)0);
        ASSERT(memcmp(&st.sha, &before, sizeof before) == 0);
        mb_emit(&st, &reply);
        ASSERT_STR_EQ(reply.error.code, "PRIVATE_EXPORT_REFUSED");
        ASSERT(json_get(&reply.data, "console_tail") == NULL);
        mb_run_fail(&st, &reply, "GUEST_FAULT", "run", "public fault");
        ASSERT_STR_EQ(reply.error.code, "PRIVATE_EXPORT_REFUSED");
        ASSERT(strstr(reply.error.evidence, "sha256=") == NULL);
        mb_verdict(&st, &reply);
        ASSERT_STR_EQ(reply.error.code, "PRIVATE_EXPORT_REFUSED");
        ASSERT_EQ(reply.exit_code, ZCL_COMMAND_EXIT_FAILED);
        machine.conports[0].private_keyfile = false;
        mb_console(&st, byte); /* Refusal cannot be cleared by changing mode. */
        ASSERT_EQ(st.buf_len, (size_t)0);
        memset(&st, 0, sizeof st); sha256_init(&st.sha);
        mb_console(&st, byte);
        ASSERT(st.private_export_failed); ASSERT_EQ(st.buf_len, (size_t)0);
        memset(&st, 0, sizeof st); sha256_init(&st.sha); st.m = &machine;
        mb_console(&st, byte);
        ASSERT(!st.private_export_failed); ASSERT_EQ(st.buf_len, (size_t)1);
        ASSERT_EQ(st.buf[0], byte); ASSERT_EQ(st.tail_len, (size_t)1);
        ASSERT_EQ(st.script.console_bytes, (uint64_t)1);
        PASS();
    } _test_next:;
    json_free(&reply.data);
    return failures;
}

static int t_host_failure_state_bound(void)
{
    int failures = 0;
    TEST("dev.app.machine.boot: host failure counters fit the complete bounded state line") {
        static struct mb_state st;
        struct zcl_command_reply reply = {0};
        memset(&st, 0, sizeof st);
        st.host_entropy = true;
        st.entropy_failed = true;
        st.ent_given = UINT64_MAX;
        st.early_given = RVMACHINE_BOOT_SEED_BYTES;
        mb_run_fail(&st, &reply, "ENTROPY_SOURCE_FAILED", "run", "source refused");
        ASSERT_STR_EQ(reply.error.current_state,
                      "source_failed=1 bytes=18446744073709551615 early_bytes=2048");
        PASS();
    } _test_next:;
    return failures;
}

static int t_host_entropy_callbacks(void)
{
    int failures = 0;
    static struct mb_state st;
    uint8_t span[5002];
    TEST("dev.app.machine.boot: host entropy chunks fresh requests and latches cleaned failures") {
        memset(&st, 0, sizeof st);
        memset(span, 0xa5, sizeof span);
        tmb_host_calls = 0;
        tmb_host_fail_call = 0;
        ASSERT_EQ(tmb_boot_host_entropy(&st, span + 1, 5000), 5000);
        ASSERT_EQ(tmb_host_calls, 2);
        ASSERT_EQ(st.ent_given, 5000);
        size_t got = 0;
        ASSERT(tmb_boot_host_boot_seed(&st, span + 1, 2048, &got));
        ASSERT_EQ(got, 2048);
        ASSERT_EQ(tmb_host_calls, 3);
        ASSERT_EQ(st.ent_given, 5000);
        ASSERT_EQ(st.early_given, 2048);
        tmb_host_fail_call = 5;
        ASSERT_EQ(tmb_boot_host_entropy(&st, span + 1, 5000), 0);
        ASSERT(st.entropy_failed);
        for (size_t i = 1; i <= 5000; i++) ASSERT_EQ(span[i], 0);
        ASSERT_EQ(span[0], 0xa5);
        ASSERT_EQ(span[5001], 0xa5);
        ASSERT_EQ(tmb_boot_host_entropy(&st, span + 1, 16), 0);
        ASSERT_EQ(tmb_host_calls, 5);
        got = 7;
        ASSERT(!tmb_boot_host_boot_seed(&st, span + 1, 16, &got));
        ASSERT_EQ(got, 0);
        ASSERT_EQ(tmb_host_calls, 5);
        PASS();
    } _test_next:;
    tmb_host_fail_call = 0;
    return failures;
}

/* One real install reused by the consequence and refusal controls. */
static const struct json_value *tmb_accepted_row(const struct tmb_call *c)
{
    return json_get(json_get(json_get(&c->doc, "data"), "inputs"), "accepted_kernel");
}

static bool tmb_accepted_input(char *wire, size_t capacity, const struct tmb_dir *d,
                               const char *root, size_t kernel_bytes, unsigned mode)
{
    char selector[1200];
    if (mode == 6u)
        root = "0000000000000000000000000000000000000000000000000000000000000000";
    const char *output = mode == 1u ? "include/undeclared.h" : "include/kernel.h";
    size_t artifact = mode == 2u ? kernel_bytes - 1u : TMB_FILE_MAX;
    unsigned verification = mode == 3u ? 1u : 16777216u;
    int n = snprintf(selector, sizeof selector,
        "{\"datadir\":\"%s\",\"package_root\":\"%s\",\"output\":\"%s\","
        "\"max_artifact_bytes\":%zu,\"max_verification_bytes\":%u%s}",
        d->dir, root, output, artifact, verification,
        mode == 5u ? ",\"unknown\":0" : "");
    if (n <= 0 || (size_t)n >= sizeof selector) return false;
    const char *raw = mode == 4u ? ",\"kernel\":\"refused-raw-fallback\"" : "";
    n = snprintf(wire, capacity,
        "{\"accepted_kernel\":%s%s,\"ram_mib\":64,\"max_instr\":100000,\"transcript\":\"%s\"}",
        selector, raw, d->out);
    return n > 0 && (size_t)n < capacity;
}

static int t_accepted_kernel(void)
{
    int failures = 0;
    struct tmb_dir d;
    struct tmb_call c;
    uint8_t root[32], receipt_id[32];
    char root_hex[65], expected_sha[65], json[2000], report[400];
    size_t kernel_bytes = 0;
    TEST("dev.app.machine.boot: genuine installed PUBLIC copied kernel bytes reach the RV64 guest") {
        ASSERT(tmb_setup(&d, "tiny"));
        ASSERT(tmb_sha(d.kernel, expected_sha));
        ASSERT(tmb_pkg_install(&d, root, receipt_id, &kernel_bytes));
        struct vcs_package_build_receipt receipt;
        struct zcl_result filed = package_lifecycle_receipt_read(d.dir, receipt_id, &receipt);
        ASSERT(filed.ok);
        ASSERT(memcmp(receipt.package_root, root, 32) == 0);
        struct package_lifecycle_step inspected;
        bool installed = false;
        struct zcl_result current = package_lifecycle_installed_inspect(d.dir, root, &inspected, &installed);
        ASSERT(current.ok);
        ASSERT(installed);
        ASSERT(inspected.has_receipt);
        ASSERT(memcmp(inspected.receipt_id, receipt_id, 32) == 0);
        zcl_hex_encode(root, 32, root_hex);
        ASSERT(tmb_accepted_input(json, sizeof json, &d, root_hex, kernel_bytes, 0));
        ASSERT(tmb_go(&c, NULL, json));
        ASSERT(tmb_ok(&c));
        ASSERT_EQ(tmb_int(&c, "retired"), 279);
        ASSERT_STR_EQ(tmb_str(&c, "transcript_sha256"), TMB_TINY_SHA);
        const struct json_value *accepted = tmb_accepted_row(&c);
        ASSERT(accepted != NULL);
        ASSERT_EQ(json_get_int(json_get(accepted, "bytes")), (int64_t)kernel_bytes);
        ASSERT_STR_EQ(json_get_str(json_get(accepted, "copied_sha256")), expected_sha);
        ASSERT(json_get_bool(json_get(accepted, "current_after_run")));
        tmb_end(&c);
        ASSERT(unlink(d.out) == 0);
        for (unsigned mode = 1; mode <= 6; mode++) {
            ASSERT(tmb_accepted_input(json, sizeof json, &d, root_hex, kernel_bytes, mode));
            ASSERT(tmb_go(&c, NULL, json));
            ASSERT(tmb_failed(&c, mode <= 3u || mode == 6u ? "ACCEPTED_KERNEL_REFUSED" : "INVALID_INPUT"));
            ASSERT(access(d.out, F_OK) != 0);
            tmb_end(&c);
        }
        snprintf(report, sizeof report, "%s/zcode/installed/%s/build-report", d.dir, root_hex);
        ASSERT(tmb_accepted_input(json, sizeof json, &d, root_hex, kernel_bytes, 0));
        tmb_after_mode = TMB_AFTER_GROW_KERNEL;
        tmb_after_path = report; tmb_after_done = false;
        ASSERT(tmb_go(&c, mbtwin_handle, json));
        ASSERT(tmb_after_done);
        ASSERT(tmb_failed(&c, "ACCEPTED_KERNEL_CHANGED"));
        ASSERT(tmb_evidence_has(&c, "retired=279"));
        ASSERT(tmb_evidence_has(&c, TMB_TINY_SHA));
        tmb_end(&c);
        tmb_after_mode = TMB_AFTER_NOTHING;
        ASSERT(tmb_refused_input("{\"accepted_kernel\":null}"));
        ASSERT(tmb_refused_input("{\"accepted_kernel\":{\"datadir\":\"d\",\"package_root\":\"r\",\"output\":\"o\",\"max_artifact_bytes\":null,\"max_verification_bytes\":1}}"));
        ASSERT(tmb_refused_input("{\"accepted_kernel\":{\"datadir\":\"d\",\"datadir\":\"duplicate\",\"package_root\":\"r\",\"output\":\"o\",\"max_artifact_bytes\":1,\"max_verification_bytes\":1}}"));
        test_cleanup_tmpdir(d.dir);
        PASS();
    } _test_next:;
    tmb_after_mode = TMB_AFTER_NOTHING;
    return failures;
}

static int t_accepted_wrong_arch(void)
{
    int failures = 0;
    TEST("dev.app.machine.boot: accepted output still reaches actual RV64 ELF architecture refusal") {
        struct tmb_dir d;
        struct tmb_call c;
        uint8_t root[32], receipt[32], elf[64] = {0};
        char root_hex[65], json[2000];
        size_t bytes = 0;
        ASSERT(tmb_setup(&d, "tiny"));
        memcpy(elf, "\177ELF\2\1\1", 7);
        elf[16] = 2; elf[18] = 62; elf[20] = 1;
        ASSERT(tmb_write(d.kernel, elf, sizeof elf));
        ASSERT(tmb_pkg_install(&d, root, receipt, &bytes));
        zcl_hex_encode(root, 32, root_hex);
        ASSERT(tmb_accepted_input(json, sizeof json, &d, root_hex, bytes, 0));
        ASSERT(tmb_go(&c, NULL, json));
        ASSERT(tmb_failed(&c, "MACHINE_REFUSED"));
        ASSERT_STR_EQ(tmb_error(&c, "phase"), "load");
        ASSERT(access(d.out, F_OK) != 0);
        tmb_end(&c);
        test_cleanup_tmpdir(d.dir);
        PASS();
    } _test_next:;
    return failures;
}

static int t_public_image_policy(void)
{
    int failures = 0;
    static struct mb_state st;
    struct zcl_command_reply reply = {0};
    struct json_value input;
    json_init(&input);
    const char *valid = "{\"datadir\":\"PUBLIC.cas\","
        "\"observation_root\":\"1111111111111111111111111111111111111111111111111111111111111111\","
        "\"max_artifact_bytes\":43407928,\"max_verification_bytes\":50000000}";
    TEST("PUBLIC copied image selection alone grants no execution or file creation") {
        memset(&st, 0, sizeof st);
        ASSERT(json_read(&input, valid, strlen(valid)));
        ASSERT(mb_parse_public_kernel(&input, &st));
        json_free(&input); json_init(&input);
        ASSERT(json_read(&input, "{}", 2));
        ASSERT(!tmb_owner_parse(&input, &st, &reply));
        ASSERT(!st.owner.enabled && !st.owner.manager && !st.accepted.public_reader);
        char request[1024];
        int length = snprintf(request, sizeof request, "{\"public_kernel\":%s}", valid);
        ASSERT(length > 0 && (size_t)length < sizeof request);
        ASSERT(tmb_refused_input(request));
        PASS();
    }
    TEST("PUBLIC owner fixes image identity independently of the selected unsigned observation") {
        struct vcs_guest_image_observation observation = {0};
        uint8_t selected[32], changed[32];
        memset(&st, 0, sizeof st);
        memset(selected, 0x11, sizeof selected);
        memcpy(changed, selected, sizeof changed); changed[0]++;
        memcpy(st.accepted.root, selected, sizeof selected);
        st.owner.enabled = st.accepted.public_observation = true;
        st.owner.profile_revision = 1;
        ASSERT(zcl_hex_decode_lower("2445a0ca747bb28eac52c8c2bb861ee9be06f3c7353587d88e3c3fcbb832b2f4",
            st.owner.authorized_kernel, 32));
        observation.image.bytes = 43407928;
        memcpy(observation.image_sha256, st.owner.authorized_kernel, 32);
        ASSERT(tmb_owner_image_grant(&st, selected, NULL));
        ASSERT(tmb_owner_image_grant(&st, selected, &observation));
        ASSERT(!tmb_owner_image_grant(&st, changed, &observation));
        observation.image.bytes++;
        ASSERT(!tmb_owner_image_grant(&st, selected, &observation));
        observation.image.bytes--;
        observation.image_sha256[0]++;
        ASSERT(!tmb_owner_image_grant(&st, selected, &observation));
        observation.image_sha256[0]--;
        st.owner.authorized_kernel[0]++;
        memcpy(observation.image_sha256, st.owner.authorized_kernel, 32);
        ASSERT(!tmb_owner_image_grant(&st, selected, &observation));
        st.owner.authorized_kernel[0]--;
        memcpy(observation.image_sha256, st.owner.authorized_kernel, 32);
        st.owner.failed = true;
        ASSERT(!tmb_owner_image_grant(&st, selected, &observation));
        st.owner.failed = false; st.entropy_failed = true;
        ASSERT(!tmb_owner_image_grant(&st, selected, NULL));
        st.entropy_failed = false; st.owner.enabled = false;
        ASSERT(!tmb_owner_image_grant(&st, selected, &observation));
        PASS();
    }
    TEST("PUBLIC image selector rejects coexistence and malformed bounded selections") {
        static const char *const bad[] = {
            "{\"public_kernel\":null}",
            "{\"public_kernel\":{},\"kernel\":\"unused\"}",
            "{\"public_kernel\":{},\"accepted_kernel\":{}}",
            "{\"public_kernel\":{\"datadir\":\"unused\",\"observation_root\":\"0000000000000000000000000000000000000000000000000000000000000000\",\"max_artifact_bytes\":1,\"max_verification_bytes\":1}}",
            "{\"public_kernel\":{\"datadir\":\"unused\",\"datadir\":\"duplicate\",\"max_artifact_bytes\":1,\"max_verification_bytes\":1}}",
            "{\"public_kernel\":{\"datadir\":\"unused\",\"observation_root\":\"1111111111111111111111111111111111111111111111111111111111111111\",\"max_artifact_bytes\":0,\"max_verification_bytes\":1}}"
        };
        for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) ASSERT(tmb_refused_input(bad[i]));
        PASS();
    } _test_next:;
    json_free(&input); json_free(&reply.data);
    return failures;
}

static int t_public_owner_policy(void)
{
    int failures = 0;
    static struct mb_state st;
    struct zcl_command_reply reply = {0};
    struct json_value input;
    json_init(&input);
    const char *fixed = "2445a0ca747bb28eac52c8c2bb861ee9be06f3c7353587d88e3c3fcbb832b2f4";
    TEST("PUBLIC owner policy requires every exact local field independently of accepted metadata") {
        for (unsigned mode = 0; mode < 8; mode++) {
            char text[1024];
            int n = snprintf(text, sizeof text,
                "{\"public_unlock\":{\"policy\":\"%s\",\"purpose\":\"%s\",\"%s\":%u,"
                "\"mode\":\"%s\",\"authorized_kernel_sha256\":\"%s\","
                "\"volume\":\"PUBLIC.volume\",\"record\":\"PUBLIC.record\",\"credential\":\"PUBLIC.input\"}}",
                mode == 1 ? "private_object_receive" : "public_keyfile_fixture",
                mode == 2 ? "ssh_key" : "public_geli_keyfile",
                mode == 3 ? "absent_revision" : "receiver_revision", mode == 4 ? 2u : 1u,
                mode == 5 ? "automatic_rekey" : "initial",
                mode == 6 ? "0445a0ca747bb28eac52c8c2bb861ee9be06f3c7353587d88e3c3fcbb832b2f4" : fixed);
            ASSERT(n > 0 && (size_t)n < sizeof text);
            json_free(&input); json_init(&input);
            ASSERT(json_read(&input, text, (size_t)n));
            memset(&st, 0, sizeof st);
            st.accepted.datadir = "PUBLIC.accepted"; st.host_entropy = true; st.early = true;
            if (mode == 7) st.transcript = "forbidden.public.dump";
            ASSERT(tmb_owner_parse(&input, &st, &reply) == (mode == 0));
            ASSERT(st.owner.enabled == (mode == 0));
            ASSERT(!st.owner.attempted && !st.owner.delivered && !st.owner.manager);
        }
        PASS();
    } _test_next:;
    json_free(&input); json_free(&reply.data);
    return failures;
}

static bool tmb_public_identity_lines(char key[114], char fingerprint[84])
{
    uint8_t wire[51] = {0}, digest[32];
    zcl_write_u32_be(wire, 11); memcpy(wire + 4, "ssh-ed25519", 11);
    zcl_write_u32_be(wire + 15, 32);
    for (size_t i = 0; i < 32; i++) wire[19 + i] = (uint8_t)(i * 19u + 1u);
    char encoded[69], hash_text[45];
    struct sha256_ctx hash;
    sha256_init(&hash); sha256_write(&hash, wire, sizeof wire); sha256_finalize(&hash, digest);
    if (!zbase64_encode(wire, sizeof wire, encoded, sizeof encoded) ||
        !zbase64_encode(digest, sizeof digest, hash_text, sizeof hash_text)) return false;
    hash_text[43] = 0;
    return snprintf(key, 114, "PUBLIC_V2_KEY:ssh-ed25519 %s z23-fixture-host\r\n", encoded) == 113 &&
        snprintf(fingerprint, 84, "256 SHA256:%s z23-fixture-host (ED25519)\r\n", hash_text) == 83;
}
static int t_public_identity_parser(void)
{
    int failures = 0;
    TEST("PUBLIC identity grammar binds exact canonical SSH wire to its fingerprint") {
        char key[114], fp[84], changed[228];
        struct mb_public_identity identity, rejected;
        uint8_t received[32];
        ASSERT(tmb_public_identity_lines(key, fp));
        ASSERT(mb_owner_public_wire_line((const uint8_t *)key, 113, &identity));
        ASSERT(mb_owner_fingerprint_line((const uint8_t *)fp, 83, identity.fingerprint, received));
        ASSERT(memcmp(received, identity.fingerprint, 32) == 0);
        /* Valid base64 is insufficient: reject a different embedded algorithm
         * or either SSH length even when the outer text remains unchanged. */
        const size_t wire_offsets[] = {3, 4, 18};
        for (size_t i = 0; i < sizeof wire_offsets / sizeof wire_offsets[0]; i++) {
            uint8_t wire[51]; char encoded[69];
            memcpy(wire, identity.wire, sizeof wire); wire[wire_offsets[i]] ^= 1;
            ASSERT(zbase64_encode(wire, sizeof wire, encoded, sizeof encoded));
            const size_t prefix_n = sizeof("PUBLIC_V2_KEY:ssh-ed25519 ") - 1;
            memcpy(changed, key, sizeof key); memcpy(changed + prefix_n, encoded, 68);
            ASSERT(memcmp(changed, key, prefix_n) == 0);
            ASSERT(memcmp(changed + prefix_n + 68, key + prefix_n + 68,
                sizeof key - prefix_n - 68) == 0);
            memset(&rejected, 0xa5, sizeof rejected);
            ASSERT(!mb_owner_public_wire_line((const uint8_t *)changed, 113, &rejected));
            for (size_t j = 0; j < sizeof rejected.wire; j++) ASSERT_EQ(rejected.wire[j], 0);
            for (size_t j = 0; j < sizeof rejected.fingerprint; j++) ASSERT_EQ(rejected.fingerprint[j], 0);
        }
        const size_t changed_key[] = {14, 26, 95};
        for (size_t i = 0; i < sizeof changed_key / sizeof changed_key[0]; i++) {
            memcpy(changed, key, sizeof key); changed[changed_key[i]] = '-';
            ASSERT(!mb_owner_public_wire_line((const uint8_t *)changed, 113, &rejected));
        }
        memcpy(changed, key, 113); memcpy(changed + 113, key, 113);
        ASSERT(!mb_owner_public_wire_line((const uint8_t *)changed, 226, &rejected));
        ASSERT(!mb_owner_public_wire_line((const uint8_t *)key, 112, &rejected));
        memcpy(changed, fp, sizeof fp);
        const char *alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        const char *last = strchr(alphabet, changed[53]);
        ASSERT(last != NULL);
        changed[53] = alphabet[(size_t)(last - alphabet) | 1u];
        ASSERT(!mb_owner_fingerprint_line((const uint8_t *)changed, 83, identity.fingerprint, received));
        identity.fingerprint[0] ^= 1;
        ASSERT(!mb_owner_fingerprint_line((const uint8_t *)fp, 83, identity.fingerprint, received));
        for (size_t i = 0; i < sizeof received; i++) ASSERT_EQ(received[i], 0);
        PASS();
    } _test_next:;
    return failures;
}
static void tmb_public_identity_observer(struct mb_state *st, struct rvmachine *machine)
{
    memset(st, 0, sizeof *st); memset(machine, 0, sizeof *machine);
    machine->conport_count = 5; machine->conports[4].generation = 7;
    machine->con.ports[4].generation = 9;
    st->owner.profile_revision = 2;
    st->owner.health = st->owner.delivered = st->owner.child = true;
    st->owner.instance = st->owner.health_instance = 11;
    st->owner.ready_epoch = st->owner.health_epoch = 7;
    st->owner.ready_device_epoch = st->owner.health_device_epoch = 9;
    st->owner.command_step = MB_OWNER_KEY_COMMAND + 1;
}
/* Qualified metadata guard model, as in the existing PUBLIC identity tests.
 * Actual console/parser and phase helpers run; this does not establish a
 * guest, provider delivery, phase6 completion or identity publication. */
static bool tmb_protected_identity_model(struct mb_state *st,struct rvmachine *machine,
    struct mb_protected_owner *p)
{
    memset(st,0,sizeof(*st));memset(machine,0,sizeof(*machine));memset(p,0,sizeof(*p));
    machine->conport_count=5;
    machine->con.nports=5; /* The guard model includes the device's port bound. */
    memcpy(machine->conport_names[4],"z23.protected.bootstrap.v1",sizeof("z23.protected.bootstrap.v1"));
    if(!rvmachine_conport_open(machine,4))return false;
    machine->con.dev.status=RVVIRTIO_STATUS_DRIVER_OK;
    machine->conports[4].private_keyfile=true;machine->conports[4].private_sealed=true;
    uint32_t host=machine->conports[4].generation,device=machine->con.ports[4].generation;
    p->health=true;p->health_instance=11;p->health_host_epoch=host;p->health_device_epoch=device;
    p->proof.ready=true;p->proof.ready_machine=machine;p->proof.ready_instance=11;
    p->proof.ready_host_epoch=host;p->proof.ready_device_epoch=device;
    p->proof.delivered=true;p->proof.delivery_instance=11;
    p->proof.delivery_host_epoch=host;p->proof.delivery_device_epoch=device;
    p->proof.phase6_accepted=true;p->proof.consumed_verified=true;p->proof.child=true;
    st->owner.protected=p;st->m=machine;st->owner.command_step=15;
    return mb_command_begin(&st->owner.command,14,11,host,device) &&
        mb_protected_identity_current(st,11,host,device);
}
static bool tmb_protected_identity_lines(char key[119],char fp[86],char public_fp[84])
{
    char public_key[114];
    if(!tmb_public_identity_lines(public_key,public_fp))return false;
    return snprintf(key,119,"PROTECTED_V1_KEY:ssh-ed25519 %.68s z23-protected-host\r\n",public_key+26)==118 &&
        snprintf(fp,86,"256 SHA256:%.43s z23-protected-host (ED25519)\r\n",public_fp+11)==85;
}
/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0 */
/* INERT test_dev_machine_boot source-twin controls. Insert after its helpers;
 * call tmb_provision_controls from existing registered group AFTER actual
 * protected owner/provisioning symbols are composed. No extra source twin.
 * Existing #define rng_host_fill tmb_host_fill wraps the owner include.
 * Host entropy here is PUBLIC deterministic test data, NOT real RNG evidence. */
static void tmb_provision_init(struct mb_state *st,struct mb_protected_owner *p,
    const char *path)
{
    memset(st,0,sizeof(*st));memset(p,0,sizeof(*p));
    platform_private_file_init(&st->owner.credential);
    st->owner.protected=p;st->owner.credential_path=path;
    tmb_host_calls=0;tmb_host_fail_call=0;
}
static bool tmb_provision_directory(char dir[200],char path[240])
{
    if(!test_mkdtemp(dir,200,"protected_provision"))return false;
    int n=snprintf(path,240,"%s/credential",dir);
    return n>0 && n<240;
}
static bool tmb_provision_public_bytes(struct platform_private_file *file)
{
    uint8_t bytes[32]={0};
    bool ok=platform_private_file_read_at(file,bytes,sizeof(bytes),0);
    for(size_t i=0;i<sizeof bytes;i++)if(bytes[i]!=0x5a)ok=false;
    memory_cleanse(bytes,sizeof bytes);return ok;
}
static int tmb_provision_success(void)
{
    int failures=0;char dir[200]={0},path[240];
    struct mb_state st;struct mb_protected_owner p;tmb_provision_init(&st,&p,NULL);
    TEST("protected host provisioning: actual private32 retained descriptor and exact snapshot") {
        ASSERT(tmb_provision_directory(dir,path));st.owner.credential_path=path;
        ASSERT(mb_protected_create_credential(&st));
        ASSERT_EQ(tmb_host_calls,1);ASSERT(st.owner.mutated);ASSERT(st.owner.credential.locked);
        struct platform_positioned_file view={.native=st.owner.credential.native};
        struct platform_positioned_file_snapshot current;
        ASSERT(platform_positioned_file_is_private(&view));
        ASSERT(platform_positioned_file_is_current_user_only(&view));
        ASSERT(platform_positioned_file_snapshot(&view,&current));ASSERT_EQ(current.size,32);
        ASSERT(platform_positioned_file_snapshot_equal(&current,&st.owner.credential_snapshot));
        ASSERT(tmb_provision_public_bytes(&st.owner.credential));
        PASS();
    } _test_next:;
    platform_private_file_close(&st.owner.credential);
    tmb_host_fail_call=0;if(dir[0])test_cleanup_tmpdir(dir);return failures;
}
static int tmb_provision_rng_refusal(void)
{
    int failures=0;char dir[200]={0},path[240];
    struct mb_state st;struct mb_protected_owner p;tmb_provision_init(&st,&p,NULL);
    TEST("protected host provisioning: partial host RNG refusal creates no credential") {
        ASSERT(tmb_provision_directory(dir,path));st.owner.credential_path=path;tmb_host_fail_call=1;
        ASSERT(!mb_protected_create_credential(&st));ASSERT_EQ(tmb_host_calls,1);
        ASSERT(platform_private_path_absent(path));ASSERT(!st.owner.mutated);
        ASSERT(!st.owner.credential.locked);ASSERT_EQ(st.owner.credential.native,(uintptr_t)-1);
        ASSERT_EQ(st.owner.credential_snapshot.size,0);PASS();
    } _test_next:;
    platform_private_file_close(&st.owner.credential);
    tmb_host_fail_call=0;if(dir[0])test_cleanup_tmpdir(dir);return failures;
}
static int tmb_provision_existing_refusal(void)
{
    int failures=0;char dir[200]={0},path[240];uint8_t before[7]={1,3,5,7,9,11,13},after[8]={0};size_t len=0;
    struct mb_state st;struct mb_protected_owner p;tmb_provision_init(&st,&p,NULL);
    TEST("protected host provisioning: existing ordinary credential never overwritten or credited") {
        ASSERT(tmb_provision_directory(dir,path));ASSERT(tmb_write(path,before,sizeof before));
        st.owner.credential_path=path;ASSERT(!mb_protected_create_credential(&st));
        ASSERT_EQ(tmb_host_calls,0);ASSERT(!st.owner.mutated);ASSERT(!st.owner.credential.locked);
        ASSERT(tmb_read(path,after,sizeof after,&len));ASSERT_EQ(len,sizeof before);
        ASSERT(memcmp(before,after,sizeof before)==0);PASS();
    } _test_next:;
    platform_private_file_close(&st.owner.credential);memory_cleanse(before,sizeof before);memory_cleanse(after,sizeof after);
    if (dir[0])
        test_cleanup_tmpdir(dir);
    return failures;
}
static int tmb_provision_symlink_refusal(void)
{
    int failures=0;char dir[200]={0},path[240],target[240];uint8_t before[3]={2,4,6},after[4]={0};size_t len=0;
    struct mb_state st;struct mb_protected_owner p;tmb_provision_init(&st,&p,NULL);
    TEST("protected host provisioning: symlink target untouched and no host RNG requested") {
        ASSERT(tmb_provision_directory(dir,path));ASSERT(snprintf(target,sizeof target,"%s/target",dir)>0);
        ASSERT(tmb_write(target,before,sizeof before));ASSERT(symlink(target,path)==0);
        st.owner.credential_path=path;ASSERT(!mb_protected_create_credential(&st));
        ASSERT_EQ(tmb_host_calls,0);ASSERT(!st.owner.mutated);ASSERT(!st.owner.credential.locked);
        ASSERT(tmb_read(target,after,sizeof after,&len));ASSERT_EQ(len,sizeof before);
        ASSERT(memcmp(before,after,sizeof before)==0);PASS();
    } _test_next:;
    platform_private_file_close(&st.owner.credential);memory_cleanse(before,sizeof before);memory_cleanse(after,sizeof after);
    if (dir[0])
        test_cleanup_tmpdir(dir);
    return failures;
}
static int tmb_provision_mode_refusal(void)
{
    int failures=0;char dir[200]={0},path[240];
    struct mb_state st;struct mb_protected_owner p;tmb_provision_init(&st,&p,NULL);
    TEST("protected host provisioning: RECOVER cannot create host credential") {
        ASSERT(tmb_provision_directory(dir,path));st.owner.credential_path=path;st.owner.recover=true;
        ASSERT(!mb_protected_create_credential(&st));ASSERT_EQ(tmb_host_calls,0);
        ASSERT(platform_private_path_absent(path));ASSERT(!st.owner.mutated);PASS();
    } _test_next:;
    platform_private_file_close(&st.owner.credential);
    if (dir[0])
        test_cleanup_tmpdir(dir);
    return failures;
}
static int tmb_provision_file_controls(void)
{
    return tmb_provision_success()+tmb_provision_rng_refusal()+tmb_provision_existing_refusal()+
        tmb_provision_symlink_refusal()+tmb_provision_mode_refusal();
}
/* Typed parse only: these lexical paths confer no filesystem/image/grant authority. */
static bool tmb_provision_request(const char *mode,const char *credential_mode,
    struct mb_protected_request *request)
{
    char text[2048];struct json_value doc;json_init(&doc);
    int n=snprintf(text,sizeof text,
        "{\"policy\":\"protected_host\",\"purpose\":\"protected_geli_keyfile\","
        "\"receiver_revision\":1,\"authorized_kernel_sha256\":\"a5080bb076351c5b5e058a81e5bf6ad3a0f748e97423d2214af5602a5f90097c\","
        "\"credential_mode\":\"%s\",\"mode\":\"%s\",\"volume\":\"volume\",\"record\":\"record\","
        "\"credential\":\"credential\",\"extension\":\"extension\",\"reserve_stage\":\"reserve\",\"ready_stage\":\"ready\"}",
        credential_mode,mode);
    bool ok=n>0&&(size_t)n<sizeof text&&json_read(&doc,text,(size_t)n)&&mb_protected_request_parse(&doc,request);
    json_free(&doc);return ok;
}
static int tmb_provision_mode_controls(void)
{
    int failures=0;struct mb_protected_request request;
    TEST("protected provisioning typed modes: INITIAL create and explicit existing; no RECOVER create or unknown mode") {
        ASSERT(tmb_provision_request("initial","create_new_host",&request));
        ASSERT(request.create_credential);ASSERT(!request.recover);
        ASSERT(!tmb_provision_request("recover","create_new_host",&request));
        ASSERT(!tmb_provision_request("other","create_new_host",&request));
        ASSERT(!tmb_provision_request("initial","other",&request));
        ASSERT(tmb_provision_request("initial","existing_locked_host",&request));
        ASSERT(!request.create_credential);ASSERT(!request.recover);
        ASSERT(tmb_provision_request("recover","existing_locked_host",&request));
        ASSERT(!request.create_credential);ASSERT(request.recover);PASS();
    } _test_next:;
    return failures;
}
static bool tmb_provision_initial_paths(struct mb_state *st,struct mb_protected_owner *p,
    const char *dir,char paths[6][240])
{
    static const char *const names[]={"credential","record","volume","extension","reserve","ready"};
    for(size_t i=0;i<6;i++){
        int n=snprintf(paths[i],240,"%s/%s",dir,names[i]);
        if(n<=0||n>=240)return false;
    }
    tmb_provision_init(st,p,paths[0]);p->create_credential=true;
    st->owner.record_path=paths[1];st->owner.volume_path=paths[2];
    p->extension_path=paths[3];p->reserve_stage_path=paths[4];p->ready_stage_path=paths[5];
    return true;
}
static int tmb_provision_preflight_controls(void)
{
    int failures=0;char dir[200]={0},paths[6][240];
    struct mb_state st;struct mb_protected_owner p;tmb_provision_init(&st,&p,NULL);
    TEST("protected provisioning actual output preflight: record volume extension and stages refuse before credential RNG/create") {
        for(size_t occupied=1;occupied<6;occupied++){
            ASSERT(test_mkdtemp(dir,sizeof dir,"protected_preflight")!=NULL);
            ASSERT(tmb_provision_initial_paths(&st,&p,dir,paths));
            struct platform_private_file present;platform_private_file_init(&present);
            ASSERT(platform_private_file_create_locked(paths[occupied],&present));
            platform_private_file_close(&present);
            /* Actual production credential-files entry: refusal precedes path
             * copies, host entropy and either create/open credential operation. */
            ASSERT(!mb_protected_credential_files(&st));ASSERT_EQ(tmb_host_calls,0);
            ASSERT(platform_private_path_absent(paths[0]));ASSERT(!st.owner.mutated);
            ASSERT(!st.owner.credential.locked);ASSERT_EQ(st.owner.credential.native,(uintptr_t)-1);
            struct stat metadata;
            ASSERT(lstat(paths[occupied],&metadata)==0);ASSERT_EQ(metadata.st_size,0);
            test_cleanup_tmpdir(dir);dir[0]=0;
        }
        PASS();
    } _test_next:;
    platform_private_file_close(&st.owner.credential);
    if (dir[0])
        test_cleanup_tmpdir(dir);
    return failures;
}
static int tmb_provision_controls(void)
{
    return tmb_provision_file_controls()+tmb_provision_mode_controls()+tmb_provision_preflight_controls();
}

/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0 */
/* Insert after provisioning controls helpers; append this function to the
 * existing tmb_provision_controls registered call. PUBLIC sentinel only. */
static int tmb_provision_fault_controls(void)
{
    int failures=0;char dir[200]={0},path[240];
    struct mb_state st;struct mb_protected_owner p;tmb_provision_init(&st,&p,NULL);
    TEST("protected provisioning persistence refusals preserve uncertain real file and no accepted credential snapshot") {
        for(unsigned fault=TMB_PF_WRITE;fault<=TMB_PF_LATE_SNAPSHOT;fault++){
            ASSERT(tmb_provision_directory(dir,path));tmb_provision_init(&st,&p,path);
            tmb_provision_target=&st.owner.credential;tmb_provision_parent=dir;
            tmb_provision_write_calls=0;tmb_provision_authority_calls=0;
            tmb_provision_parent_calls=0;tmb_provision_snapshot_calls=0;tmb_provision_snapshot_mutated=false;
            tmb_provision_fault=(enum tmb_provision_fault)fault;
            ASSERT(!mb_protected_create_credential(&st));ASSERT_EQ(tmb_host_calls,1);
            ASSERT(st.owner.mutated);ASSERT(st.owner.credential.locked);
            ASSERT_EQ(st.owner.credential_snapshot.size,0);
            struct stat metadata;ASSERT(lstat(path,&metadata)==0);
            ASSERT_EQ(metadata.st_size,fault==TMB_PF_WRITE?3:fault==TMB_PF_LATE_SNAPSHOT?33:32);
            ASSERT_EQ(tmb_provision_write_calls,1);
            ASSERT_EQ(tmb_provision_authority_calls,fault==TMB_PF_WRITE?0:1);
            ASSERT_EQ(tmb_provision_parent_calls,fault<=TMB_PF_AUTHORITY?0:1);
            ASSERT_EQ(tmb_provision_snapshot_calls,fault==TMB_PF_LATE_SNAPSHOT?2:0);
            ASSERT_EQ(tmb_provision_snapshot_mutated,fault==TMB_PF_LATE_SNAPSHOT);
            ASSERT(!mb_protected_create_credential(&st));ASSERT_EQ(tmb_host_calls,1);
            tmb_provision_fault=TMB_PF_NONE;tmb_provision_target=NULL;tmb_provision_parent=NULL;
            platform_private_file_close(&st.owner.credential);test_cleanup_tmpdir(dir);dir[0]=0;
        }
        PASS();
    } _test_next:;
    tmb_provision_fault=TMB_PF_NONE;tmb_provision_target=NULL;tmb_provision_parent=NULL;
    platform_private_file_close(&st.owner.credential);tmb_host_fail_call=0;
    if (dir[0])
        test_cleanup_tmpdir(dir);
    return failures;
}

static int t_protected_identity_comment(void)
{
    int failures=0;static struct mb_state st;static struct rvmachine machine;static struct mb_protected_owner p;
    TEST("protected console identity phase accepts its own comment and keeps PUBLIC grammar separate") {
        char key[119],fp[86],public_fp[84];uint8_t decoded[32];
        ASSERT(tmb_protected_identity_lines(key,fp,public_fp));
        ASSERT(tmb_protected_identity_model(&st,&machine,&p));
        mb_owner_console(&st,&machine,11,(const uint8_t *)key,118);
        ASSERT(st.owner.public_key_seen && !st.owner.failed);
        ASSERT(mb_command_begin(&st.owner.command,15,11,machine.conports[4].generation,machine.con.ports[4].generation)==false);
        /* Qualified model starts the next phase after the preceding successful
         * command; no fake guest/provider completion is asserted here. */
        st.owner.command.next_seen=true;
        ASSERT(mb_command_begin(&st.owner.command,15,11,machine.conports[4].generation,machine.con.ports[4].generation));
        st.owner.command_step=16;
        mb_owner_console(&st,&machine,11,(const uint8_t *)fp,85);
        ASSERT(st.owner.fingerprint_seen && !st.owner.failed);
        ASSERT(mb_owner_fingerprint_line((const uint8_t *)public_fp,83,st.owner.identity.fingerprint,decoded));
        ASSERT(!mb_owner_fingerprint_line((const uint8_t *)fp,85,st.owner.identity.fingerprint,decoded));
        PASS();
    } _test_next:;
    st.owner.protected=NULL;
    return failures;
}
static int t_protected_identity_wrong_comment(void)
{
    int failures=0;static struct mb_state st;static struct rvmachine machine;static struct mb_protected_owner p;
    TEST("protected console fingerprint rejects the PUBLIC comment at the actual fingerprint phase") {
        char key[119],fp[86],public_fp[84];
        ASSERT(tmb_protected_identity_lines(key,fp,public_fp));
        ASSERT(tmb_protected_identity_model(&st,&machine,&p));
        mb_owner_console(&st,&machine,11,(const uint8_t *)key,118);
        ASSERT(st.owner.public_key_seen && !st.owner.failed);
        st.owner.command.next_seen=true;
        ASSERT(mb_command_begin(&st.owner.command,15,11,machine.conports[4].generation,machine.con.ports[4].generation));
        st.owner.command_step=16;
        mb_owner_console(&st,&machine,11,(const uint8_t *)public_fp,83);
        ASSERT(st.owner.failed && !st.owner.fingerprint_seen);PASS();
    } _test_next:;
    st.owner.protected=NULL;
    return failures;
}
static int t_public_identity_observer(void)
{
    int failures = 0;
    static struct mb_state st;
    static struct rvmachine machine;
    TEST("PUBLIC identity observer refuses duplicates, wrong phases and split provenance") {
        char key[114], fp[84];
        ASSERT(tmb_public_identity_lines(key, fp));
        tmb_public_identity_observer(&st, &machine);
        mb_owner_console(&st, &machine, 11, (const uint8_t *)key, 113);
        ASSERT(st.owner.public_key_seen && !st.owner.failed && !st.owner.fingerprint_seen);
        st.owner.command_step = MB_OWNER_FINGERPRINT_COMMAND + 1;
        mb_owner_console(&st, &machine, 11, (const uint8_t *)fp, 83);
        ASSERT(st.owner.fingerprint_seen && !st.owner.failed && !st.owner.done);
        mb_owner_console(&st, &machine, 11, (const uint8_t *)fp, 83);
        ASSERT(st.owner.failed);
        tmb_public_identity_observer(&st, &machine);
        mb_owner_console(&st, &machine, 11, (const uint8_t *)key, 113);
        mb_owner_console(&st, &machine, 11, (const uint8_t *)key, 113);
        ASSERT(st.owner.failed && !st.owner.fingerprint_seen);
        tmb_public_identity_observer(&st, &machine);
        mb_owner_console(&st, &machine, 12, (const uint8_t *)key, 113);
        ASSERT(st.owner.failed && !st.owner.public_key_seen);
        tmb_public_identity_observer(&st, &machine);
        mb_owner_console(&st, &machine, 11, (const uint8_t *)key, 20);
        machine.conports[4].generation++;
        mb_owner_console(&st, &machine, 11, (const uint8_t *)key + 20, 93);
        ASSERT(st.owner.failed && !st.owner.public_key_seen);
        tmb_public_identity_observer(&st, &machine);
        st.owner.command_step--;
        mb_owner_console(&st, &machine, 11, (const uint8_t *)key, 113);
        ASSERT(st.owner.failed && !st.owner.public_key_seen);
        tmb_public_identity_observer(&st, &machine);
        mb_owner_console(&st, &machine, 11, (const uint8_t *)key, 20);
        machine.con.ports[4].generation++;
        mb_owner_console(&st, &machine, 11, (const uint8_t *)key + 20, 93);
        ASSERT(st.owner.failed && !st.owner.public_key_seen && !st.owner.fingerprint_seen);
        PASS();
    } _test_next:;
    return failures;
}

static int t_public_v3_newfs_done(void)
{
    int failures=0; static struct mb_state st; static struct rvmachine machine;
    TEST("PUBLIC V3 newfs completion is unique tuple-bound diagnostic evidence") {
        static const char marker[]="PUBLIC_V3_NEWFS_DONE\r\n";
        for (unsigned mode=0;mode<10;mode++) {
            tmb_public_identity_observer(&st,&machine);
            st.owner.profile_revision=3; st.owner.command_step=8;
            st.owner.prepared20k_seen=true;
            ASSERT(mb_command_begin(&st.owner.command,7,11,7,9));
            if (mode==1) st.owner.recover=true;
            if (mode==2) st.owner.prepared20k_seen=false;
            if (mode==3) st.owner.child=false;
            if (mode==4) st.owner.delivered=false;
            if (mode==5) st.owner.command.phase=6;
            if (mode==6) st.owner.command.rc_seen=true;
            mb_owner_console(&st,&machine,11,(const uint8_t *)marker,10);
            if (mode==7) machine.conports[4].generation++;
            if (mode==8) machine.con.ports[4].generation++;
            mb_owner_console(&st,&machine,11,(const uint8_t *)marker+10,sizeof marker-11);
            if (mode==9)
                mb_owner_console(&st,&machine,11,(const uint8_t *)marker,sizeof marker-1);
            ASSERT(st.owner.failed==(mode!=0));
            ASSERT(!st.owner.command_pending && !st.owner.done);
            ASSERT(!st.owner.phase7_dd_done && !st.owner.phase7_newfs_done);
            if (mode==0) {
                ASSERT(st.owner.v3_newfs_done);
                ASSERT(!strcmp(mb_owner_v3_newfs_summary(&st)," newfs=1"));
                struct zcl_command_reply reply={0};
                ASSERT(!mb_owner_refusal(&st,&reply,NULL));
                ASSERT(strstr(reply.error.evidence," newfs=1"));
                ASSERT(strlen(reply.error.evidence)<sizeof reply.error.evidence);
                json_free(&reply.data);
            }
        }
        tmb_public_identity_observer(&st,&machine);
        ASSERT(!strcmp(mb_owner_v3_newfs_summary(&st),""));
        st.owner.profile_revision=3;
        ASSERT(!strcmp(mb_owner_v3_newfs_summary(&st)," newfs=0"));
        PASS();
    } _test_next:;
    return failures;
}

static int t_public_v3_prepare_marker_extra(void)
{
    int failures=0; static struct mb_state st; static struct rvmachine machine;
    TEST("PUBLIC V3 preparation console preserves split and RC tuple boundaries") {
        static const char marker[]="PUBLIC_BOOTSTRAP_PREPARED20K\r\n";
        static const char rc[]="PUBLIC_V2_RC:6:0\r\n";
        static const char *const malformed[]={
            "printf 'PUBLIC_BOOTSTRAP_PREPARED20K'\r\n",
            "PUBLIC_BOOTSTRAP_PREPARED20K\n",
            "PUBLIC_BOOTSTRAP_PREPARED20X\r\n"
        };
        for (unsigned mode=0;mode<7;mode++) {
            tmb_public_identity_observer(&st,&machine);
            st.owner.profile_revision=3; st.owner.command_step=7;
            ASSERT(mb_command_begin(&st.owner.command,6,11,7,9));
            if (mode>=4) {
                const char *line=malformed[mode-4];
                mb_owner_console(&st,&machine,11,(const uint8_t *)line,strlen(line));
                ASSERT(!st.owner.prepared20k_seen);
                mb_owner_console(&st,&machine,11,(const uint8_t *)rc,sizeof rc-1);
            } else {
                mb_owner_console(&st,&machine,11,(const uint8_t *)marker,10);
                if (mode==1) machine.con.ports[4].generation++;
                mb_owner_console(&st,&machine,11,(const uint8_t *)marker+10,sizeof marker-11);
                if (mode!=1) ASSERT(st.owner.prepared20k_seen && !st.owner.failed);
                if (mode==2)
                    mb_owner_console(&st,&machine,11,(const uint8_t *)marker,sizeof marker-1);
                if (mode==3) machine.con.ports[4].generation++;
                if (mode==0 || mode==3)
                    mb_owner_console(&st,&machine,11,(const uint8_t *)rc,sizeof rc-1);
            }
            ASSERT(st.owner.failed==(mode!=0));
            ASSERT(st.owner.command.rc_seen==(mode==0));
            ASSERT(!st.owner.command_pending);
            ASSERT(!st.owner.phase7_dd_done && !st.owner.phase7_newfs_done);
        }
        PASS();
    } _test_next:;
    return failures;
}

static int t_public_v3_prepare_marker(void)
{
    int failures=t_public_v3_prepare_marker_extra(); static struct mb_state st; static struct rvmachine machine;
    TEST("PUBLIC V3 phase6 preparation requires unique current child-bound evidence") {
        static const char marker[]="PUBLIC_BOOTSTRAP_PREPARED20K\r\n";
        static const char rc[]="PUBLIC_V2_RC:6:0\r\n";
        for (unsigned mode=0;mode<10;mode++) {
            tmb_public_identity_observer(&st,&machine);
            st.owner.profile_revision=3; st.owner.command_step=7;
            ASSERT(mb_command_begin(&st.owner.command,6,11,7,9));
            if (mode==1) st.owner.recover=true;
            if (mode==2) st.owner.child=false;
            if (mode==3) st.owner.delivered=false;
            if (mode==4) st.owner.command.phase=5;
            if (mode==5) st.owner.command.rc_seen=true;
            if (mode==6) st.owner.prepared20k_seen=true;
            if (mode==7) {
                mb_owner_console(&st,&machine,11,(const uint8_t *)rc,sizeof rc-1);
            } else if (mode>=8) {
                mb_owner_console(&st,&machine,11,(const uint8_t *)marker,10);
                if (mode==8) machine.conports[4].generation++;
                mb_owner_console(&st,&machine,mode==9 ? 12 : 11,
                    (const uint8_t *)marker+10,sizeof marker-11);
            } else {
                mb_owner_console(&st,&machine,11,(const uint8_t *)marker,sizeof marker-1);
            }
            ASSERT(st.owner.failed==(mode!=0));
            if (mode==0) {
                ASSERT(st.owner.prepared20k_seen);
                mb_owner_console(&st,&machine,11,(const uint8_t *)rc,sizeof rc-1);
                ASSERT(!st.owner.failed && st.owner.command.rc_seen);
                mb_owner_console(&st,&machine,11,
                    (const uint8_t *)"PUBLIC_OWNER_NEXT\r\n",19);
                ASSERT(!st.owner.failed && st.owner.command_pending);
            }
        }
        PASS();
    } _test_next:;
    return failures;
}

static bool tmb_phase7_start(struct mb_state *st, struct rvmachine *machine)
{
    tmb_public_identity_observer(st,machine); st->owner.command_step=8;
    return mb_command_begin(&st->owner.command,7,11,7,9);
}
/* Metadata-only sampler fixture. This byte is never loaded or executed. */
static bool tmb_pc_scope_start(struct mb_state *st, struct rvmachine *machine)
{
    static uint8_t image;
    if (!tmb_phase7_start(st, machine)) return false;
    st->owner.enabled = true;
    st->accepted.public_observation = true;
    st->accepted.image = &image;
    st->accepted.length = UINT64_C(43407928);
    return zcl_hex_decode_lower(mb_owner_profile(2)->kernel,
        st->owner.authorized_kernel, 32);
}
static int t_public_v2_phase7_console_controls(void)
{
    int failures=0; static struct mb_state st; static struct rvmachine machine;
    TEST("PUBLIC phase7 console refuses echo, phase, duplicate and split epoch") {
        struct zcl_command_reply reply={0};
        ASSERT(tmb_phase7_start(&st,&machine));
        const uint8_t echo[]="printf '\\1207A\\n' &&\r\n";
        mb_owner_console(&st,&machine,11,echo,sizeof echo-1);
        ASSERT(!st.owner.failed && !st.owner.done && !st.owner.command_pending);
        ASSERT(!mb_owner_refusal(&st,&reply,NULL));
        ASSERT(strstr(reply.error.evidence,"p7=0:0") != NULL);
        mb_owner_console(&st,&machine,11,(const uint8_t *)"P7A\r\n",5);
        mb_owner_console(&st,&machine,11,(const uint8_t *)"P7B\r\n",5);
        ASSERT(!st.owner.failed && !st.owner.done && !st.owner.command_pending);
        ASSERT(!mb_owner_refusal(&st,&reply,NULL));
        ASSERT(strstr(reply.error.evidence,"p7=1:1") != NULL);
        mb_owner_console(&st,&machine,11,(const uint8_t *)"P7B\r\n",5);
        ASSERT(st.owner.failed && !st.owner.done && !st.owner.command_pending);
        ASSERT(tmb_phase7_start(&st,&machine)); st.owner.command.phase=6;
        mb_owner_console(&st,&machine,11,(const uint8_t *)"P7A\r\n",5);
        ASSERT(st.owner.failed);
        ASSERT(!mb_owner_refusal(&st,&reply,NULL));
        ASSERT(strstr(reply.error.evidence,"p7=0:0") != NULL);
        ASSERT(tmb_phase7_start(&st,&machine));
        mb_owner_console(&st,&machine,11,(const uint8_t *)"P7",2);
        machine.con.ports[4].generation++;
        mb_owner_console(&st,&machine,11,(const uint8_t *)"A\r\n",3);
        ASSERT(st.owner.failed && st.owner.line_length==0);
        ASSERT(!mb_owner_refusal(&st,&reply,NULL));
        ASSERT(strstr(reply.error.evidence,"p7=0:0") != NULL);
        PASS();
    } _test_next:;
    return failures;
}
static int t_public_v2_refusal_evidence_width(void)
{
    int failures=0; static struct mb_state st; static struct rvmachine machine;
    TEST("PUBLIC refusal retains full cumulative counters within evidence width") {
        struct zcl_command_reply reply={0};
        ASSERT(tmb_phase7_start(&st,&machine));
        mb_owner_console(&st,&machine,11,(const uint8_t *)"P7A\r\n",5);
        mb_owner_console(&st,&machine,11,(const uint8_t *)"P7B\r\n",5);
        st.owner.command_step=SIZE_MAX;
        st.owner.health=st.owner.ready=st.owner.attempted=st.owner.delivered=true;
        st.owner.child=st.owner.done=true;
        st.owner.last_retired=st.owner.last_fw_calls=st.owner.last_device_work=UINT64_MAX;
        ASSERT(!mb_owner_refusal(&st,&reply,NULL));
        ASSERT(strlen(reply.error.evidence)<sizeof reply.error.evidence);
        ASSERT(strstr(reply.error.evidence,"work=18446744073709551615/18446744073709551615/18446744073709551615") != NULL);
        ASSERT(strstr(reply.error.evidence,"work=18446744073709551615/18446744073709551615/18446744073709551615") != NULL);
        ASSERT(strstr(reply.error.evidence,"p7=1:1") != NULL);
        PASS();
    } _test_next:;
    return failures;
}
static int t_public_v2_phase7_diagnostics(void)
{
    int failures=0;
    TEST("PUBLIC V2 filesystem progress survives refusal without implying completion") {
        static struct mb_state st;
        static struct rvmachine machine;
        struct zcl_command_reply reply = {0};
        ASSERT(tmb_pc_scope_start(&st, &machine));
        mb_owner_console(&st, &machine, 11, (const uint8_t *)"P7A\r\n", 5);
        ASSERT(!st.owner.failed && !st.owner.done && !st.owner.command_pending);
        ASSERT(!mb_owner_refusal(&st, &reply, NULL));
        ASSERT(strstr(reply.error.evidence, "p7=1") != NULL);
        ASSERT(strstr(reply.error.evidence, "k=0:0/0 u=0") != NULL);
        static const uint8_t geometry[]=
            "\tusing 4 cylinder groups of 3.56MB, 114 blks, 256 inodes.\r\n";
        mb_owner_console(&st, &machine, 11, geometry, sizeof geometry-1);
        ASSERT(!st.owner.failed && !st.owner.done && !st.owner.command_pending);
        ASSERT(!mb_owner_refusal(&st, &reply, NULL));
        ASSERT(strstr(reply.error.evidence, "g=4:114:256") != NULL);
        ASSERT(strstr(reply.error.evidence, "a=unknown") != NULL);
        PASS();
    } _test_next:;
    return failures;
}
/* Pure classification checks grant no image admission or execution authority. */
static int tmb_public_pc_classifier_controls(void)
{
    int failures=0;
    TEST("Fixed PUBLIC HIGH kernel buckets are exact halfopen sample labels") {
        for (size_t i=0;i<sizeof mb_pc_ranges/sizeof mb_pc_ranges[0];i++) {
            const struct mb_pc_range *range=&mb_pc_ranges[i];
            ASSERT(range->lo<range->hi);
            ASSERT_EQ(mb_pc_bucket(range->lo),range->bucket);
            ASSERT_EQ(mb_pc_bucket(range->hi-1),range->bucket);
            ASSERT(!mb_pc_within(range->hi,range->lo,range->hi));
        }
        ASSERT_EQ(mb_pc_bucket(UINT64_C(0xffffffc0000ce54e)),MB_PC_KERNEL_OTHER);
        ASSERT_EQ(mb_pc_bucket(UINT64_C(0xffffffc000257556)),MB_PC_GELI_WRITE);
        ASSERT_EQ(mb_pc_bucket(UINT64_C(0xffffffc0002577d4)),MB_PC_GELI_READ);
        ASSERT_EQ(mb_pc_bucket(UINT64_C(0xffffffc000257b2c)),MB_PC_KERNEL_OTHER);
        ASSERT_EQ(mb_pc_bucket(UINT64_C(0xffffffc000000000)),MB_PC_KERNEL_OTHER);
        ASSERT_EQ(mb_pc_bucket(UINT64_C(0xffffffc0005841be)),MB_PC_UNKNOWN);
        ASSERT_EQ(mb_pc_bucket(UINT64_C(0xffffffc0026e0480)),MB_PC_KERNEL_OTHER);
        ASSERT_EQ(mb_pc_bucket(UINT64_C(0xffffffc0026e04df)),MB_PC_KERNEL_OTHER);
        ASSERT_EQ(mb_pc_bucket(UINT64_C(0xffffffc0026e04e0)),MB_PC_UNKNOWN);
        ASSERT_EQ(mb_pc_bucket(UINT64_C(0x80200000)),MB_PC_UNKNOWN);
        ASSERT_EQ(mb_pc_bucket(UINT64_C(0x100001000)),MB_PC_UNKNOWN);
        ASSERT_EQ(mb_pc_bucket(UINT64_C(0xffffffc0005841c0)),MB_PC_UNKNOWN);
        ASSERT_EQ(mb_pc_bucket(UINT64_MAX),MB_PC_UNKNOWN);
        struct mb_pc_counts counts={0}, before;
        ASSERT_EQ(mb_pc_top(&counts),0u);
        ASSERT(mb_pc_count(&counts,MB_PC_UNKNOWN));
        ASSERT_EQ(mb_pc_top(&counts),0u);
        ASSERT(mb_pc_count(&counts,MB_PC_AES));
        ASSERT(mb_pc_count(&counts,MB_PC_SHA256));
        ASSERT_EQ(mb_pc_top(&counts),MB_PC_SHA256);
        ASSERT_EQ(counts.total,3u);
        counts.total=UINT32_MAX; before=counts;
        ASSERT(!mb_pc_count(&counts,MB_PC_SHA256));
        ASSERT_EQ(memcmp(&counts,&before,sizeof counts),0);
        counts=(struct mb_pc_counts){0}; before=counts;
        ASSERT(!mb_pc_count(&counts,MB_PC_BUCKETS));
        ASSERT_EQ(memcmp(&counts,&before,sizeof counts),0);
        PASS();
    } _test_next:;
    return failures;
}
/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0 */
/* tmb_pc_scope_start is
 * metadata-only; no artifact read, manager creation, guest or credential. */
static int tmb_public_pc_context_controls(void)
{
    int failures=0; static struct rvmachine one,two;
    TEST("PUBLIC returned-PC context requires same owned identity and positive monotone work") {
        struct mb_pc_context a={.machine=&one,.instance=11,.host_epoch=7,.device_epoch=9,
            .retired=10,.fw_calls=20,.device_work=30,.valid=true};
        struct mb_pc_context b=a;
        ASSERT(mb_pc_same(&a,&b));
        b.valid=false; ASSERT(!mb_pc_same(&a,&b));
        b=a; b.machine=&two; ASSERT(!mb_pc_same(&a,&b));
        b=a; b.instance++; ASSERT(!mb_pc_same(&a,&b));
        b=a; b.host_epoch++; ASSERT(!mb_pc_same(&a,&b));
        b=a; b.device_epoch++; ASSERT(!mb_pc_same(&a,&b));
        struct rvmachine_result r={.retired=10,.fw_calls=20,.device_work=30};
        ASSERT(!mb_pc_positive(&a,&r));
        r.retired++; ASSERT(mb_pc_positive(&a,&r));
        r.retired=10; r.fw_calls++; ASSERT(mb_pc_positive(&a,&r));
        r.fw_calls=20; r.device_work++; ASSERT(mb_pc_positive(&a,&r));
        r.retired=9; ASSERT(!mb_pc_positive(&a,&r));
        r.retired=10; r.fw_calls=19; ASSERT(!mb_pc_positive(&a,&r));
        r.fw_calls=20; r.device_work=29; r.retired=11;
        ASSERT(!mb_pc_positive(&a,&r));
        PASS();
    } _test_next:;
    return failures;
}
/* Source-twin guard model, not guest attribution proof. Uses live hart
 * fields/producing-PC equality; no machine or manager invariant stubs. */
static bool tmb_privilege_scope(struct mb_state *st,struct rvmachine *machine)
{
    if(!tmb_pc_scope_start(st,machine))return false;
    st->owner.profile_revision=7;st->owner.prepared20k_seen=true;
    st->accepted.length=UINT64_C(43412608);st->m=machine;
    return zcl_hex_decode_lower(mb_owner_profile(7)->kernel,st->owner.authorized_kernel,32);
}
static int tmb_privilege_answers(void)
{
    int failures=0;static struct mb_state st;static struct rvmachine machine;
    TEST("profile7 privilege counts read matched live U S M and unknown hart modes") {
        ASSERT(tmb_privilege_scope(&st,&machine));
        struct mb_pc_context a={.machine=&machine,.instance=11,.host_epoch=7,.device_epoch=9,.valid=true};
        st.res.retired=1;st.res.pc=machine.hart.pc=0x1234;
        static const unsigned modes[]={RVEMU_PRIV_U,RVEMU_PRIV_S,RVEMU_PRIV_M,2};
        for(unsigned i=0;i<4;i++){
            machine.hart.priv=modes[i];mb_owner_pc_privilege_observe(&st,&a,&a);
            ASSERT_EQ(st.owner.pc_privileges.hit[i],1u);
            ASSERT(mb_pc_count(&st.owner.pc_counts,MB_PC_UNKNOWN));
        }
        char out[24];mb_owner_pc_privilege_summary(&st,out);
        ASSERT(!strcmp(out," p=0001/0001/0001/0001"));PASS();
    } _test_next:;
    return failures;
}
static int tmb_privilege_refusals(void)
{
    int failures=0;static struct mb_state st;static struct rvmachine machine;
    TEST("profile7 privilege attribution refuses stale machine instance epochs and mismatched PC") {
        for(unsigned i=0;i<5;i++){
            ASSERT(tmb_privilege_scope(&st,&machine));
            struct mb_pc_context a={.machine=&machine,.instance=11,.host_epoch=7,.device_epoch=9,.valid=true},b=a;
            st.res.retired=1;st.res.pc=machine.hart.pc=0x1234;
            switch(i){
            case 0:b.machine=NULL;break;
            case 1:b.instance++;break;
            case 2:b.host_epoch++;break;
            case 3:b.device_epoch++;break;
            default:machine.hart.pc+=2;break;
            }
            mb_owner_pc_privilege_observe(&st,&a,&b);
            ASSERT(st.owner.pc_privileges.unavailable);
            ASSERT_EQ(st.owner.pc_privileges.hit[0],0u);
            mb_owner_pc_privilege_observe(&st,&a,&a);
            ASSERT(st.owner.pc_privileges.unavailable);
        }PASS();
    } _test_next:;
    return failures;
}
static int tmb_privilege_zero_and_overflow(void)
{
    int failures=0;static struct mb_state st;static struct rvmachine machine;
    TEST("profile7 privilege zero result and counter overflow have no fabricated attribution") {
        ASSERT(tmb_privilege_scope(&st,&machine));
        struct mb_pc_context a={.machine=&machine,.instance=11,.host_epoch=7,.device_epoch=9,.valid=true};
        st.res.pc=machine.hart.pc=0x1234;machine.hart.priv=RVEMU_PRIV_U;
        mb_owner_pc_privilege_observe(&st,&a,&a);
        ASSERT_EQ(st.owner.pc_privileges.hit[0],0u);
        ASSERT(!st.owner.pc_privileges.unavailable);
        st.res.retired=1;st.owner.pc_privileges.hit[0]=UINT16_MAX;
        mb_owner_pc_privilege_observe(&st,&a,&a);
        ASSERT_EQ(st.owner.pc_privileges.hit[0],UINT16_MAX);
        ASSERT(st.owner.pc_privileges.unavailable);PASS();
    } _test_next:;
    return failures;
}
static int tmb_privilege_old_profile(void)
{
    int failures=0;static struct mb_state st;static struct rvmachine machine;
    TEST("old profiles preserve privilege output absence and existing unknown bucket") {
        ASSERT(tmb_pc_scope_start(&st,&machine));st.m=&machine;
        struct mb_pc_context a={.machine=&machine,.instance=11,.host_epoch=7,.device_epoch=9,.valid=true};
        st.res.retired=1;st.res.pc=machine.hart.pc=0x1234;machine.hart.priv=RVEMU_PRIV_U;
        mb_owner_pc_privilege_observe(&st,&a,&a);
        ASSERT_EQ(st.owner.pc_privileges.hit[0],0u);
        char out[24];mb_owner_pc_privilege_summary(&st,out);ASSERT(out[0]==0);
        ASSERT_EQ(mb_pc_bucket_profile(2,st.res.pc),MB_PC_UNKNOWN);PASS();
    } _test_next:;
    return failures;
}
static bool tmb_privilege_manager_start(struct mb_state *st,struct rvmachine *machine,
    struct mb_pc_context *before,struct guest_gov_decision *decision)
{
    static const uint8_t loop[]={0x6f,0,0,0};
    if(!tmb_privilege_scope(st,machine))return false;
    struct mesh_guest_service_launch_config config={
        .policy=MESH_GUEST_LAUNCH_EPHEMERAL_FIXTURE,.disk_mode=MESH_GUEST_DISK_NONE,
        .service={.kernel=loop,.kernel_length=sizeof loop,.binding=mb_owner_deny_peer,
            .binding_context=st,.machine={.ram_bytes=UINT64_C(64)<<20,.wait_stops=true}}};
    config.service.limits=guest_limits_default();config.service.limits.slice_work=GUEST_GOV_SLICE_WORK_MIN;
    if(!mesh_guest_service_manager_create(&st->owner.manager,&config))return false;
    struct guest_action action;
    if(!mesh_guest_service_manager_event(st->owner.manager,&(struct guest_event){.kind=GUEST_EV_ENABLE,.enable=true},0,&action)||
        !mesh_guest_service_manager_event(st->owner.manager,&(struct guest_event){.kind=GUEST_EV_OPERATOR_START},0,&action))return false;
    uint64_t i=mesh_guest_service_manager_instance(st->owner.manager);
    st->owner.instance=st->owner.health_instance=st->owner.command.instance=i;
    machine->con.nports=5;machine->conports[4].seen_generation=9;
    *before=mb_owner_pc_context(st);
    st->owner.v3_dispatch=(struct mb_v3_dispatch){.machine=machine,.instance=i,
        .host_epoch=7,.device_epoch=9,.seen=true,.valid=true};
    enum rvmachine_status status=mesh_guest_service_manager_drive(st->owner.manager,1000,1,decision,&st->res);
    machine->hart.pc=st->res.pc;machine->hart.priv=RVEMU_PRIV_U;
    return before->valid&&status==RVMACHINE_OK&&decision->kind==GUEST_GOV_RUN_SLICE;
}
static int tmb_privilege_production_observe(void)
{
    int failures=0;static struct mb_state st;static struct rvmachine machine;
    TEST("profile7 production sampler rejects no-run and mismatched PC without borrowing last result") {
        struct mb_pc_context before;struct guest_gov_decision decision;
        ASSERT(tmb_privilege_manager_start(&st,&machine,&before,&decision));
        /* As existing manager sampler fixture: real tiny result, separate
         * hart metadata guard model; NOT actual FreeBSD process attribution. */
        mb_owner_pc_observe(&st,&before,RVMACHINE_OK,&decision);
        ASSERT_EQ(st.owner.pc_privileges.hit[0],1u);
        struct zcl_command_reply reply={0};ASSERT(!mb_owner_refusal(&st,&reply,NULL));
        ASSERT(strstr(reply.error.evidence," p=0001/0000/0000/0000")!=NULL);
        struct rvmachine_result saved=st.res;st.res=(struct rvmachine_result){0};
        mb_owner_pc_observe(&st,&before,RVMACHINE_OK,&decision);
        ASSERT_EQ(st.owner.pc_privileges.hit[0],1u);
        st.res=saved;struct guest_gov_decision sleep={.kind=GUEST_GOV_SLEEP};
        mb_owner_pc_observe(&st,&before,RVMACHINE_OK,&sleep);
        ASSERT_EQ(st.owner.pc_privileges.hit[0],1u);
        machine.hart.pc+=2;mb_owner_pc_observe(&st,&before,RVMACHINE_OK,&decision);
        ASSERT(st.owner.pc_privileges.unavailable);PASS();
    } _test_next:;
    if(st.owner.manager){if(!mesh_guest_service_manager_destroy(st.owner.manager,1002))failures++;st.owner.manager=NULL;}
    return failures;
}
static int tmb_privilege_production_tuple(void)
{
    int failures=0;static struct mb_state st;static struct rvmachine machine;
    TEST("profile7 production sampler refuses stale instance and each receiver epoch") {
        struct mb_pc_context before;struct guest_gov_decision decision;
        ASSERT(tmb_privilege_manager_start(&st,&machine,&before,&decision));
        struct mb_pc_context stale=before;stale.instance++;
        mb_owner_pc_observe(&st,&stale,RVMACHINE_OK,&decision);
        ASSERT_EQ(st.owner.pc_privileges.hit[0],0u);
        stale=before;stale.host_epoch++;
        mb_owner_pc_observe(&st,&stale,RVMACHINE_OK,&decision);
        ASSERT_EQ(st.owner.pc_privileges.hit[0],0u);
        stale=before;stale.device_epoch++;
        mb_owner_pc_observe(&st,&stale,RVMACHINE_OK,&decision);
        ASSERT_EQ(st.owner.pc_privileges.hit[0],0u);
        mb_owner_pc_observe(&st,&before,RVMACHINE_ERR_STATE,&decision);
        ASSERT_EQ(st.owner.pc_privileges.hit[0],0u);PASS();
    } _test_next:;
    if(st.owner.manager){if(!mesh_guest_service_manager_destroy(st.owner.manager,1002))failures++;st.owner.manager=NULL;}
    return failures;
}
static bool tmb_history_complete(struct mb_state *st,struct rvmachine *machine)
{
    struct mb_pc_context before;
    struct guest_gov_decision decision;
    if(!tmb_privilege_manager_start(st,machine,&before,&decision))return false;
    memcpy(machine->conport_names[4],"z23.bootstrap.keyfile",sizeof "z23.bootstrap.keyfile");
    if(!rvmachine_conport_open(machine,4))return false;
    uint32_t host=machine->conports[4].generation,device=machine->con.ports[4].generation;
    st->owner.ready_epoch=st->owner.health_epoch=st->owner.command.host_epoch=host;
    st->owner.ready_device_epoch=st->owner.health_device_epoch=st->owner.command.device_epoch=device;
    st->owner.v3_dispatch.host_epoch=host;st->owner.v3_dispatch.device_epoch=device;
    st->owner.attempted=true; /* Existing fixture models already-delivered/child, no key operation. */
    before=mb_owner_pc_context(st);
    st->owner.line_instance=st->owner.instance;
    struct mb_pc_context transition_before=mb_owner_transition_context(st);
    mb_owner_pc_observe(st,&before,RVMACHINE_OK,&decision);
    mb_owner_result_remember(st,&decision,RVMACHINE_OK);
    struct mb_pc_context transition_after=mb_owner_transition_context(st);
    mb_trace_actual_result_observe(&st->owner.transition_actual,&transition_before,
        &transition_after,&decision,RVMACHINE_OK,&st->res);
    static const uint8_t proof[]="PUBLIC_V3_NEWFS_DONE\r\nPUBLIC_V2_RC:7:0\r\nPUBLIC_OWNER_NEXT\r\n";
    mb_owner_console(st,machine,st->owner.instance,proof,sizeof proof-1);
    if(st->owner.failed || !st->owner.command.rc_seen || !st->owner.command.next_seen)return false;
    return mb_owner_dispatch_progress(st,1001) && st->owner.command_step==9;
}
static int tmb_history_message_red(void)
{
    int failures=0;static struct mb_state st;static struct rvmachine machine;
    TEST("completed phase7 retains explicitly historical privilege after real phase8 enqueue") {
        ASSERT(tmb_history_complete(&st,&machine));
        struct zcl_command_reply reply={0};ASSERT(!mb_owner_refusal(&st,&reply,NULL));
        ASSERT(strstr(reply.error.evidence," p7priv=0001/0000/0000/0000")!=NULL);
        ASSERT(strstr(reply.error.evidence," p=0001")==NULL);PASS();
    } _test_next:;
    if(st.owner.manager){if(!mesh_guest_service_manager_destroy(st.owner.manager,1002))failures++;st.owner.manager=NULL;}
    return failures;
}
static int tmb_history_join_message_red(void)
{
    int failures=0;static struct mb_state st;static struct rvmachine machine;
    TEST("actual owner join preserves qualified historical formatting diagnostic for refusal") {
        ASSERT(tmb_history_complete(&st,&machine));
        struct zcl_command_reply reply={0};
        ASSERT(mb_owner_join(&st,&reply));
        ASSERT(st.owner.manager==NULL);
        ASSERT(st.m==NULL);
        ASSERT(!mb_owner_refusal(&st,&reply,NULL));
        ASSERT(strstr(reply.error.evidence," p7priv=0001/0000/0000/0000")!=NULL);
        ASSERT(strstr(reply.error.evidence," p=0001")==NULL);PASS();
    } _test_next:;
    if(st.owner.manager){if(!mb_owner_join(&st,&(struct zcl_command_reply){0}))failures++;}
    return failures;
}
static int tmb_history_deadline_stop_controls(void)
{
    int failures=0;static struct mb_state st;static struct rvmachine machine;
    TEST("actual manager deadline stop retains historical diagnostic before and after join") {
        ASSERT(tmb_history_complete(&st,&machine));
        uint64_t instance=mesh_guest_service_manager_instance(st.owner.manager);
        ASSERT(instance!=0);
        struct guest_gov_decision decision;struct rvmachine_result result;
        uint64_t stopped_at=GUEST_SERVICE_START_DEADLINE_MS+UINT64_C(1001);
        (void)mesh_guest_service_manager_drive(st.owner.manager,stopped_at,1,&decision,&result);
        ASSERT_EQ(mesh_guest_service_manager_instance(st.owner.manager),0u);
        struct guest_service_snapshot snapshot;
        ASSERT(mesh_guest_service_manager_snapshot(st.owner.manager,stopped_at,&snapshot));
        ASSERT_EQ(snapshot.state,GUEST_STATE_ABSENT);
        /* Same returned-drive borrowed-pointer retirement as mb_owner_round.
         * Absence is observed from the actual manager, never injected. */
        st.m=NULL;
        struct zcl_command_reply reply={0};ASSERT(!mb_owner_refusal(&st,&reply,&snapshot));
        ASSERT(strstr(reply.error.evidence," p7priv=0001/0000/0000/0000")!=NULL);
        ASSERT(mb_owner_join(&st,&reply));ASSERT(st.owner.manager==NULL);
        ASSERT(!mb_owner_refusal(&st,&reply,&snapshot));
        ASSERT(strstr(reply.error.evidence," p7priv=0001/0000/0000/0000")!=NULL);PASS();
    } _test_next:;
    if(st.owner.manager){if(!mb_owner_join(&st,&(struct zcl_command_reply){0}))failures++;}
    return failures;
}
static int tmb_history_epoch_controls(void)
{
    int failures=0;static struct mb_state st;static struct rvmachine machine;
    TEST("historical phase7 privilege becomes sticky unavailable after each epoch changes") {
        for(unsigned side=0;side<2;side++){
            ASSERT(tmb_history_complete(&st,&machine));
            uint32_t *epoch=side ? &machine.con.ports[4].generation : &machine.conports[4].generation;
            (*epoch)++;char out[32];mb_owner_p7_privilege_history(&st,out);
            ASSERT(!strcmp(out," p7priv=unavailable"));(*epoch)--;
            mb_owner_p7_privilege_history(&st,out);ASSERT(!strcmp(out," p7priv=unavailable"));
            ASSERT(mesh_guest_service_manager_destroy(st.owner.manager,1002));st.owner.manager=NULL;
        }PASS();
    } _test_next:;
    if(st.owner.manager){if(!mesh_guest_service_manager_destroy(st.owner.manager,1002))failures++;st.owner.manager=NULL;}
    return failures;
}
static int tmb_history_binding_controls(void)
{
    int failures=0;static struct mb_state st;static struct rvmachine machine;
    TEST("historical privilege refuses changed image and completed dispatch without restoring credit") {
        for(unsigned side=0;side<3;side++){
            ASSERT(tmb_history_complete(&st,&machine));
            if(side==0)st.owner.authorized_kernel[0]^=1;
            if(side==1)st.accepted.root[0]^=1;
            if(side==2)st.owner.phase_dispatch[8].work++;
            char out[32];mb_owner_p7_privilege_history(&st,out);
            ASSERT(!strcmp(out," p7priv=unavailable"));
            if(side==0)st.owner.authorized_kernel[0]^=1;
            if(side==1)st.accepted.root[0]^=1;
            if(side==2)st.owner.phase_dispatch[8].work--;
            mb_owner_p7_privilege_history(&st,out);
            ASSERT(!strcmp(out," p7priv=unavailable"));
            ASSERT(mesh_guest_service_manager_destroy(st.owner.manager,1002));st.owner.manager=NULL;
        }PASS();
    } _test_next:;
    if(st.owner.manager){if(!mesh_guest_service_manager_destroy(st.owner.manager,1002))failures++;st.owner.manager=NULL;}
    return failures;
}
static int tmb_privilege_evidence_width(void)
{
    int failures=0;static struct mb_state st;static struct rvmachine machine;
    TEST("profile7 maximum diagnostic widths retain old tail and complete privilege suffix") {
        ASSERT(tmb_privilege_scope(&st,&machine));
        st.owner.pc_counts.hit[MB_PC_KERNEL_OTHER]=UINT32_C(2147483647);
        st.owner.pc_counts.hit[MB_PC_UNKNOWN]=UINT32_C(2147483648);
        st.owner.pc_counts.total=UINT32_MAX;
        st.owner.last_retired=st.owner.last_fw_calls=st.owner.last_device_work=UINT64_MAX;
        st.owner.geometry_seen=true;st.owner.geometry=(struct mb_newfs_geometry){UINT16_MAX,UINT16_MAX,UINT16_MAX};
        st.owner.v3_dispatch=(struct mb_v3_dispatch){.seen=true,.valid=true,.work=UINT32_MAX};
        struct zcl_command_reply reply={0};ASSERT(!mb_owner_refusal(&st,&reply,NULL));
        ASSERT(strstr(reply.error.evidence,"work=18446744073709551615/18446744073709551615/18446744073709551615")!=NULL);
        ASSERT(strstr(reply.error.evidence,"k=8:2147483647/4294967295 u=2147483648")!=NULL);
        ASSERT(strstr(reply.error.evidence,"g=65535:65535:65535")!=NULL);
        ASSERT(strstr(reply.error.evidence,"newfs=0 d=4294967295 p=unavailable")!=NULL);
        ASSERT(strlen(reply.error.evidence)<sizeof reply.error.evidence);
        memset(&st.owner.pc_counts,0,sizeof st.owner.pc_counts);
        st.owner.pc_counts.hit[MB_PC_KERNEL_OTHER]=st.owner.pc_counts.hit[MB_PC_UNKNOWN]=UINT32_C(131070);
        st.owner.pc_counts.total=UINT32_C(262140);
        for(unsigned i=0;i<4;i++)st.owner.pc_privileges.hit[i]=UINT16_MAX;
        ASSERT(!mb_owner_refusal(&st,&reply,NULL));
        ASSERT(strstr(reply.error.evidence,"newfs=0 d=4294967295 p=ffff/ffff/ffff/ffff")!=NULL);
        ASSERT(strlen(reply.error.evidence)<sizeof reply.error.evidence);PASS();
    } _test_next:;
    return failures;
}
static int tmb_public_pc_summary_controls(void)
{
    int failures=0; static struct mb_state st; static struct rvmachine machine;
    TEST("PUBLIC PC summary preserves UNKNOWN and unavailable without fabricated kernel hits") {
        char out[48]; ASSERT(tmb_pc_scope_start(&st,&machine));
        ASSERT(mb_owner_pc_scope(&st));
        ASSERT(mb_pc_count(&st.owner.pc_counts,MB_PC_UNKNOWN));
        ASSERT(mb_pc_count(&st.owner.pc_counts,MB_PC_UNKNOWN));
        mb_owner_pc_summary(&st,out); ASSERT(!strcmp(out," k=0:0/2 u=2"));
        st.owner.pc_counts.total++; mb_owner_pc_summary(&st,out);
        ASSERT(!strcmp(out," k=unavailable"));
        st.owner.pc_counts.total--; st.owner.pc_unqualified=true;
        mb_owner_pc_summary(&st,out); ASSERT(!strcmp(out," k=unavailable"));
        st.owner.enabled=false; mb_owner_pc_summary(&st,out); ASSERT(out[0]==0);
        ASSERT(tmb_pc_scope_start(&st,&machine)); st.owner.recover=true;
        mb_owner_pc_summary(&st,out); ASSERT(out[0]==0);
        ASSERT(tmb_pc_scope_start(&st,&machine)); st.owner.command_step=9;
        mb_owner_pc_summary(&st,out); ASSERT(out[0]==0);
        ASSERT(tmb_pc_scope_start(&st,&machine)); st.owner.public_key_seen=true;
        mb_owner_pc_summary(&st,out); ASSERT(out[0]==0);
        ASSERT(tmb_pc_scope_start(&st,&machine)); st.owner.authorized_kernel[0]^=1;
        mb_owner_pc_summary(&st,out); ASSERT(out[0]==0);
        ASSERT(tmb_pc_scope_start(&st,&machine)); st.accepted.public_observation=false;
        mb_owner_pc_summary(&st,out); ASSERT(out[0]==0);
        ASSERT(tmb_pc_scope_start(&st,&machine));
        st.owner.pc_counts.hit[MB_PC_KERNEL_OTHER]=UINT32_MAX-1;
        st.owner.pc_counts.hit[MB_PC_UNKNOWN]=1;
        st.owner.pc_counts.total=UINT32_MAX;
        st.owner.last_retired=st.owner.last_fw_calls=st.owner.last_device_work=UINT64_MAX;
        struct zcl_command_reply reply={0};
        ASSERT(!mb_owner_refusal(&st,&reply,NULL));
        ASSERT(strstr(reply.error.evidence,"k=8:4294967294/4294967295 u=1") != NULL);
        ASSERT(strstr(reply.error.evidence,"work=18446744073709551615/18446744073709551615/18446744073709551615") != NULL);
        PASS();
    } _test_next:;
    return failures;
}
/* Additional minimal integrated zero-run/revocation checks can call observe with
 * before.valid=true and the above counters, res unchanged, RUN_SLICE: no count;
 * SLEEP with positive delta: no count. To prove post-context guard separately,
 * use a REAL existing owned-manager fixture before+after actual instance epoch
 * mutation; a fabricated manager pointer/invalid positive baseline would make
 * such negatives vacuous or unsafe. No extra guest invocation is proposed. */
/* Source-twin sampler lifetime fixture.
 * Real ephemeral tiny manager supplies instance/run/stop accounting ONLY.
 * Static separate machine/image/phase metadata is a sampler guard model;
 * it is NOT loaded V6, private receiver, actual image admission or guest proof.
 * Reuse existing tmb_pc_scope_start; do not duplicate that helper. */
static int tmb_public_pc_manager_controls(void)
{
    int failures=0;
    static struct mb_state st;
    static struct rvmachine metadata;
    static const uint8_t loop[]={0x6f,0,0,0};
    TEST("Sampler model binds real manager run and stopped-instance lifetime") {
        ASSERT(tmb_pc_scope_start(&st,&metadata));
        struct mesh_guest_service_launch_config config={
            .policy=MESH_GUEST_LAUNCH_EPHEMERAL_FIXTURE,.disk_mode=MESH_GUEST_DISK_NONE,
            .service={.kernel=loop,.kernel_length=sizeof loop,
                .binding=mb_owner_deny_peer,.binding_context=&st,
                .machine={.ram_bytes=UINT64_C(64)<<20,.wait_stops=true}}};
        config.service.limits=guest_limits_default();
        config.service.limits.slice_work=GUEST_GOV_SLICE_WORK_MIN;
        ASSERT(mesh_guest_service_manager_create(&st.owner.manager,&config));
        struct guest_action action;
        ASSERT(mesh_guest_service_manager_event(st.owner.manager,
            &(struct guest_event){.kind=GUEST_EV_ENABLE,.enable=true},0,&action));
        ASSERT(mesh_guest_service_manager_event(st.owner.manager,
            &(struct guest_event){.kind=GUEST_EV_OPERATOR_START},0,&action));
        uint64_t instance=mesh_guest_service_manager_instance(st.owner.manager);
        ASSERT(instance!=0);
        st.owner.instance=st.owner.health_instance=st.owner.command.instance=instance;
        st.owner.phase7_dd_done=true; st.m=&metadata;
        metadata.con.nports=5; metadata.conports[4].seen_generation=9;
        struct mb_pc_context before=mb_owner_pc_context(&st);
        ASSERT(before.valid);
        ASSERT(!mb_owner_p7_context(&st).valid);
        struct guest_gov_decision decision;
        enum rvmachine_status status=mesh_guest_service_manager_drive(st.owner.manager,
            1000,1,&decision,&st.res);
        ASSERT(status==RVMACHINE_OK && decision.kind==GUEST_GOV_RUN_SLICE);
        ASSERT(st.res.retired>0 && mb_pc_positive(&before,&st.res));
        mb_owner_pc_observe(&st,&before,status,&decision);
        ASSERT_EQ(st.owner.pc_counts.total,1u);
        ASSERT_EQ(st.owner.pc_counts.hit[MB_PC_UNKNOWN],1u); /* Actual tiny LOW PC. */
        mb_owner_result_remember(&st,&decision,status);
        ASSERT(st.owner.last_result_valid && mb_owner_p7_context(&st).valid);
        struct mb_pc_context zero=before;
        zero.retired=st.res.retired; zero.fw_calls=st.res.fw_calls;
        zero.device_work=st.res.device_work;
        mb_owner_pc_observe(&st,&zero,status,&decision);
        ASSERT_EQ(st.owner.pc_counts.total,1u);
        metadata.conports[4].seen_generation=8;
        mb_owner_pc_observe(&st,&before,status,&decision);
        ASSERT_EQ(st.owner.pc_counts.total,1u);
        metadata.conports[4].seen_generation=9;
        metadata.con.busy=true;
        mb_owner_pc_observe(&st,&before,status,&decision);
        ASSERT_EQ(st.owner.pc_counts.total,1u);
        metadata.con.busy=false;
        metadata.conports[4].generation++;
        mb_owner_pc_observe(&st,&before,status,&decision);
        ASSERT_EQ(st.owner.pc_counts.total,1u);
        metadata.conports[4].generation--;
        metadata.con.ports[4].generation++;
        metadata.conports[4].seen_generation++;
        mb_owner_pc_observe(&st,&before,status,&decision);
        ASSERT_EQ(st.owner.pc_counts.total,1u);
        metadata.con.ports[4].generation--;
        metadata.conports[4].seen_generation--;
        st.owner.phase7_dd_done=false;
        st.owner.command_step=7;
        st.owner.command.phase=6;
        st.owner.command_pending=true;
        metadata.con.ports[4].host_open=true;
        /* Exercise the production successful-enqueue hook before any next drive. */
        ASSERT(!mb_owner_p7_context(&st).valid);
        ASSERT(!mb_owner_dispatch_progress(&st,1000)); /* Prior phase has no NEXT yet. */
        ASSERT(!st.owner.p7_bracket.dispatch_seen && st.owner.command_step==7);
        st.owner.command.next_seen=true;
        ASSERT(mb_owner_dispatch_progress(&st,1000));
        ASSERT_EQ(st.owner.command_step,8u);
        ASSERT(st.owner.p7_bracket.dispatch_valid);
        ASSERT_EQ(st.owner.p7_bracket.dispatch,
            st.owner.last_retired+st.owner.last_fw_calls+st.owner.last_device_work);
        struct mb_command_observation saved_command=st.owner.command;
        size_t saved_serial_count=metadata.serial_in.count;
        st.owner.profile_revision=3; st.owner.command_step=7;
        st.owner.command.phase=6; st.owner.command.rc_seen=true;
        st.owner.command.next_seen=true; st.owner.command_pending=true;
        metadata.serial_in.count=RVMACHINE_INPUT_MAX;
        ASSERT(!mb_owner_dispatch_progress(&st,1000));
        ASSERT(st.owner.phase_dispatch_attempted==0 && st.owner.command_step==7);
        metadata.serial_in.count=saved_serial_count;
        st.owner.profile_revision=2; st.owner.command_step=8;
        st.owner.command=saved_command; st.owner.command_pending=false;
        struct mb_pc_context p7_before=mb_owner_p7_context(&st);
        ASSERT(p7_before.valid && !mb_owner_pc_context(&st).valid);
        mb_owner_console(&st,&metadata,instance,(const uint8_t *)"P7A\r\n",5);
        ASSERT(st.owner.phase7_dd_done && !st.owner.failed);
        /* Real parser/context; synthetic positive counters test only observation. */
        struct rvmachine_result p7_result=st.res;
        p7_result.retired++;
        struct mb_pc_context p7_after=mb_owner_p7_context(&st);
        mb_p7_observe(&st.owner.p7_bracket,&p7_before,&p7_after,false,true,
            status,&decision,&p7_result);
        ASSERT(st.owner.p7_bracket.valid);
        ASSERT_EQ(st.owner.p7_bracket.upper,st.owner.p7_bracket.lower+1);
        uint64_t retained=st.owner.last_retired;
        st.res=(struct rvmachine_result){0};
        struct guest_gov_decision sleeping={.kind=GUEST_GOV_SLEEP};
        mb_owner_result_remember(&st,&sleeping,RVMACHINE_OK);
        ASSERT(st.owner.last_result_valid && st.owner.last_retired==retained);
        ASSERT(mesh_guest_service_manager_event(st.owner.manager,
            &(struct guest_event){.kind=GUEST_EV_ENABLE,.enable=false},1001,&action));
        ASSERT_EQ(mesh_guest_service_manager_instance(st.owner.manager),0u);
        st.m=(struct rvmachine *)(uintptr_t)1; /* Must NOT dereference after real stop. */
        ASSERT(!mb_owner_pc_context(&st).valid);
        ASSERT(!mb_owner_p7_context(&st).valid);
        mb_owner_pc_observe(&st,&before,status,&decision);
        ASSERT_EQ(st.owner.pc_counts.total,1u);
        ASSERT(mesh_guest_service_manager_destroy(st.owner.manager,1002));
        st.owner.manager=NULL; st.m=NULL;
        PASS();
    } _test_next:;
    /* On assertion failure retain static callback/kernel lifetime if cleanup
     * refuses; never pretend destruction or free the metadata-only image. */
    if (st.owner.manager) {
        if (mesh_guest_service_manager_destroy(st.owner.manager,1003)) {
            st.owner.manager=NULL; st.m=NULL;
        } else failures++;
    }
    return failures;
}
static int tmb_geometry_parser_controls(void)
{
    int failures=0;
    TEST("PUBLIC geometry accepts only canonical whole-line planned counts") {
        struct mb_newfs_geometry v={91,92,93};
        static const char good[]="\tusing 4 cylinder groups of 3.56MB, 114 blks, 512 inodes.\r\n";
        ASSERT(mb_newfs_geometry_line((const uint8_t *)good,sizeof good-1,&v));
        ASSERT(v.groups==4 && v.blocks==114 && v.inodes==512);
        static const char spaces[]="        using 4 cylinder groups of 3.56MB, 912 blks, 464 inodes.\r\n";
        ASSERT(mb_newfs_geometry_line((const uint8_t *)spaces,sizeof spaces-1,&v));
        static const char *bad[]={
            " using 4 cylinder groups of 3.56MB, 114 blks, 512 inodes.\r\n",
            "\tusing 04 cylinder groups of 3.56MB, 114 blks, 512 inodes.\r\n",
            "\tusing 4294967296 cylinder groups of 3.56MB, 114 blks, 512 inodes.\r\n",
            "\tusing 0 cylinder groups of 3.56MB, 114 blks, 512 inodes.\r\n",
            "\tusing 4 cylinder groups of 3.5MB, 114 blks, 512 inodes.\r\n",
            "\tusing 4 cylinder groups of 3.560MB, 114 blks, 512 inodes.\r\n",
            "\tusing 4 cylinder groups of 03.56MB, 114 blks, 512 inodes.\r\n",
            "\tusing 4 cylinder groups of -3.56MB, 114 blks, 512 inodes.\r\n",
            "\tusing 4 cylinder groups of 3.56MB, 114 blks, 512 inodes.\n",
            "\tusing 4 cylinder groups of 3.56MB, 114 blks, 512 inodes.\r\nX"
        };
        for (size_t i=0;i<sizeof bad/sizeof bad[0];i++) {
            v=(struct mb_newfs_geometry){91,92,93};
            ASSERT(!mb_newfs_geometry_line((const uint8_t *)bad[i],strlen(bad[i]),&v));
            ASSERT(v.groups==91 && v.blocks==92 && v.inodes==93);
        }
        ASSERT(!mb_newfs_geometry_line(NULL,0,&v));
        ASSERT(!mb_newfs_geometry_line((const uint8_t *)good,sizeof good-1,NULL));
        PASS();
    } _test_next:;
    return failures;
}
static int tmb_geometry_observer_controls(void)
{
    int failures=0; static struct mb_state st; static struct rvmachine machine;
    static const uint8_t good[]="\tusing 4 cylinder groups of 3.56MB, 114 blks, 512 inodes.\r\n";
    TEST("PUBLIC geometry is phase-bound diagnostic with duplicates and large counts unavailable") {
        struct zcl_command_reply reply={0};
        ASSERT(tmb_pc_scope_start(&st,&machine)); st.owner.phase7_dd_done=true;
        mb_owner_console(&st,&machine,11,good,sizeof good-1);
        ASSERT(st.owner.geometry_seen && !st.owner.geometry_unqualified);
        mb_owner_console(&st,&machine,11,good,sizeof good-1);
        ASSERT(st.owner.geometry_unqualified && !st.owner.failed && !st.owner.done);
        ASSERT(!mb_owner_refusal(&st,&reply,NULL));
        ASSERT(strstr(reply.error.evidence,"g=unavailable") != NULL);
        static const uint8_t large[]="\tusing 4 cylinder groups of 3.56MB, 114 blks, 65536 inodes.\r\n";
        ASSERT(tmb_pc_scope_start(&st,&machine)); st.owner.phase7_dd_done=true;
        mb_owner_console(&st,&machine,11,large,sizeof large-1);
        ASSERT(st.owner.geometry_unqualified && !st.owner.geometry_seen && !st.owner.failed);
        PASS();
    } _test_next:;
    return failures;
}
static int tmb_geometry_scope_controls(void)
{
    int failures=0; static struct mb_state st; static struct rvmachine machine;
    static const uint8_t good[]="\tusing 4 cylinder groups of 3.56MB, 114 blks, 512 inodes.\r\n";
    TEST("PUBLIC geometry refuses private, recovery, wrong phase and split epochs") {
        for (unsigned mode=0;mode<5;mode++) {
            ASSERT(tmb_pc_scope_start(&st,&machine)); st.owner.phase7_dd_done=true;
            if (mode==0) st.owner.phase7_dd_done=false;
            if (mode==1) st.owner.phase7_newfs_done=true;
            if (mode==2) st.owner.recover=true;
            if (mode==3) st.accepted.public_observation=false;
            if (mode==4) st.owner.command_step=9;
            mb_owner_console(&st,&machine,11,good,sizeof good-1);
            ASSERT(!st.owner.geometry_seen && !st.owner.geometry_unqualified && !st.owner.failed);
        }
        ASSERT(tmb_pc_scope_start(&st,&machine)); st.owner.phase7_dd_done=true;
        mb_owner_console(&st,&machine,11,good,10);
        machine.con.ports[4].generation++;
        mb_owner_console(&st,&machine,11,good+10,sizeof good-11);
        ASSERT(st.owner.failed && !st.owner.geometry_seen && !st.owner.done);
        PASS();
    } _test_next:;
    return failures;
}
static int tmb_geometry_evidence_width(void)
{
    int failures=0; static struct mb_state st; static struct rvmachine machine;
    TEST("PUBLIC geometry and sampled counters fit complete refusal evidence") {
        ASSERT(tmb_pc_scope_start(&st,&machine)); st.owner.phase7_dd_done=true;
        static const uint8_t maximum[]="\tusing 65535 cylinder groups of 3.56MB, 65535 blks, 65535 inodes.\r\n";
        mb_owner_console(&st,&machine,11,maximum,sizeof maximum-1);
        ASSERT(st.owner.geometry_seen && !st.owner.geometry_unqualified);
        st.owner.last_retired=st.owner.last_fw_calls=st.owner.last_device_work=UINT64_MAX;
        st.owner.pc_counts.total=UINT32_MAX;
        st.owner.pc_counts.hit[0]=UINT32_MAX-1;
        st.owner.pc_counts.hit[8]=1;
        st.owner.p7_bracket=(struct mb_p7_bracket){
            .seen=true,.valid=true,.lower=UINT64_MAX-1,.upper=UINT64_MAX};
        struct zcl_command_reply reply={0};
        ASSERT(!mb_owner_refusal(&st,&reply,NULL));
        ASSERT(strstr(reply.error.evidence,"g=65535:65535:65535") != NULL);
        ASSERT(strstr(reply.error.evidence,
            " a=unavailable") != NULL);
        ASSERT(strlen(reply.error.evidence)<sizeof reply.error.evidence);
        ASSERT(strstr(reply.error.evidence,"k=8:1/4294967295 u=4294967294") != NULL);
        ASSERT(strstr(reply.error.evidence,"work=18446744073709551615/18446744073709551615/18446744073709551615") != NULL);
        ASSERT(!st.owner.done && !st.owner.command.rc_seen && !st.owner.identity_ready);
        st.owner.pc_counts.hit[0]=0;
        st.owner.pc_counts.hit[8]=UINT32_MAX;
        ASSERT(!mb_owner_refusal(&st,&reply,NULL));
        ASSERT(strstr(reply.error.evidence,"k=8:4294967295/4294967295 u=0") != NULL);
        ASSERT(strstr(reply.error.evidence,"g=65535:65535:65535") != NULL);
        PASS();
    } _test_next:;
    return failures;
}
/* Include in existing actual owner source-twin TU after production helper.
 * Pure context/value controls; not manager lifetime or V6 admission evidence.
 * Real-context integration belongs existing tmb_public_pc_manager_controls. */
/* Metadata-only diagnostic controls. No V7 kernel/manager execution. */
static bool tmb_v3_pc_scope_start(struct mb_state *st, struct rvmachine *machine)
{
    if (!tmb_pc_scope_start(st,machine)) return false;
    st->owner.profile_revision=3; st->owner.prepared20k_seen=true;
    return zcl_hex_decode_lower(mb_owner_profile(3)->kernel,st->owner.authorized_kernel,32);
}
static int tmb_v3_pc_scope_controls(void)
{
    int failures=0; static struct mb_state st; static struct rvmachine machine;
    TEST("V3 kernel-location diagnostics require exact initial formatting scope") {
        for(unsigned mode=0;mode<8;mode++) {
            ASSERT(tmb_v3_pc_scope_start(&st,&machine));
            ASSERT(mb_owner_pc_scope(&st));
            if(mode==0) st.owner.recover=true;
            if(mode==1) st.owner.prepared20k_seen=false;
            if(mode==2) st.owner.v3_newfs_done=true;
            if(mode==3) st.owner.profile_revision=4;
            if(mode==4) st.owner.command_step=9;
            if(mode==5) st.owner.command.rc_seen=true;
            if(mode==6) st.owner.authorized_kernel[0]^=1;
            if(mode==7) st.accepted.length++;
            ASSERT(!mb_owner_pc_scope(&st));
        }
        ASSERT(tmb_v3_pc_scope_start(&st,&machine));
        ASSERT(mb_owner_pc_phase7_current(&st,11,7,9));
        ASSERT(!mb_owner_pc_phase7_current(&st,12,7,9));
        ASSERT(!mb_owner_pc_phase7_current(&st,11,8,9));
        ASSERT(!mb_owner_pc_phase7_current(&st,11,7,10));
        ASSERT(!mb_owner_p7_context(&st).valid); /* V6 DD bracket remains V6-only. */
        PASS();
    }
    TEST("paired image PC diagnostics require their own image and current formatting scope") {
        for (unsigned revision=4;revision<=5;revision++) {
            ASSERT(tmb_v3_pc_scope_start(&st,&machine));
            st.owner.profile_revision=revision;
            st.accepted.length=revision==4 ? 43408024 : 43406744;
            ASSERT(!mb_owner_pc_scope(&st)); /* Old V3 digest cannot qualify. */
            ASSERT(zcl_hex_decode_lower(mb_owner_profile(revision)->kernel,
                st.owner.authorized_kernel,32));
            ASSERT(mb_owner_pc_scope(&st));
            ASSERT(mb_owner_pc_phase7_current(&st,11,7,9));
            ASSERT(!mb_owner_pc_phase7_current(&st,12,7,9));
            ASSERT(!mb_owner_pc_phase7_current(&st,11,8,9));
            ASSERT(!mb_owner_pc_phase7_current(&st,11,7,10));
            st.accepted.length++;
            ASSERT(!mb_owner_pc_scope(&st)); st.accepted.length--;
            st.owner.recover=true;
            ASSERT(!mb_owner_pc_scope(&st)); st.owner.recover=false;
            st.owner.prepared20k_seen=false;
            ASSERT(!mb_owner_pc_scope(&st)); st.owner.prepared20k_seen=true;
            st.owner.v3_newfs_done=true;
            ASSERT(!mb_owner_pc_scope(&st)); st.owner.v3_newfs_done=false;
            uint64_t sha_end=revision==4 ? UINT64_C(0xffffffc0000ce54e) : UINT64_C(0xffffffc0000ce08a);
            uint64_t plt=revision==4 ? UINT64_C(0xffffffc0026e0510) : UINT64_C(0xffffffc0026e0030);
            ASSERT_EQ(mb_pc_bucket_profile(revision,sha_end-1),MB_PC_SHA256);
            ASSERT_EQ(mb_pc_bucket_profile(revision,sha_end),MB_PC_KERNEL_OTHER);
            ASSERT_EQ(mb_pc_bucket_profile(revision,plt),MB_PC_KERNEL_OTHER);
            ASSERT_EQ(mb_pc_bucket_profile(revision,plt+95),MB_PC_KERNEL_OTHER);
            ASSERT_EQ(mb_pc_bucket_profile(revision,plt+96),MB_PC_UNKNOWN);
            ASSERT_EQ(mb_pc_bucket_profile(revision,UINT64_C(0xffffffc0026e0480)),MB_PC_UNKNOWN);
        }
        PASS();
    } _test_next:;
    return failures;
}
static int tmb_v3_dispatch_controls(void)
{
    int failures=0; static struct rvmachine machine,replacement;
    TEST("V3 formatting dispatch retains checked prior work and exact tuple") {
        struct mb_pc_context c={.machine=&machine,.instance=11,.host_epoch=7,
            .device_epoch=9,.retired=100,.fw_calls=2,.device_work=3,.valid=true};
        struct mb_v3_dispatch d={0};
        mb_v3_dispatch_observe(&d,7,7,&c); ASSERT(!d.seen);
        mb_v3_dispatch_observe(&d,7,8,&c);
        ASSERT(d.seen && d.valid && d.work==105 && mb_v3_dispatch_same(&d,&c));
        for(unsigned mode=0;mode<5;mode++) {
            struct mb_pc_context changed=c;
            if(mode==0) changed.machine=&replacement;
            if(mode==1) changed.instance++;
            if(mode==2) changed.host_epoch++;
            if(mode==3) changed.device_epoch++;
            if(mode==4) changed.valid=false;
            ASSERT(!mb_v3_dispatch_same(&d,&changed));
        }
        d=(struct mb_v3_dispatch){0}; c.valid=false;
        mb_v3_dispatch_observe(&d,7,8,&c); ASSERT(d.seen && !d.valid);
        c.valid=true; mb_v3_dispatch_observe(&d,7,8,&c); ASSERT(!d.valid);
        d=(struct mb_v3_dispatch){0}; c.retired=UINT64_MAX;
        mb_v3_dispatch_observe(&d,7,8,&c); ASSERT(d.seen && !d.valid);
        PASS();
    } _test_next:;
    return failures;
}
static int tmb_v3_diagnostic_evidence_controls(void)
{
    int failures=0; static struct mb_state st; static struct rvmachine machine;
    TEST("V3 retains geometry and bounded dispatch without V6 DD evidence") {
        ASSERT(tmb_v3_pc_scope_start(&st,&machine));
        static const uint8_t line[]="\tusing 65535 cylinder groups of 3.56MB, 65535 blks, 65535 inodes.\r\n";
        mb_owner_console(&st,&machine,11,line,sizeof line-1);
        ASSERT(st.owner.geometry_seen && !st.owner.geometry_unqualified);
        st.owner.pc_counts.total=st.owner.pc_counts.hit[8]=UINT32_MAX;
        st.owner.last_retired=st.owner.last_fw_calls=st.owner.last_device_work=UINT64_MAX;
        st.owner.v3_dispatch=(struct mb_v3_dispatch){.seen=true,.valid=true,.work=UINT32_MAX};
        struct zcl_command_reply reply={0};
        ASSERT(!mb_owner_refusal(&st,&reply,NULL));
        ASSERT(strstr(reply.error.evidence,"work=18446744073709551615/18446744073709551615/18446744073709551615"));
        ASSERT(strstr(reply.error.evidence,"k=8:4294967295/4294967295 u=0"));
        ASSERT(strstr(reply.error.evidence,"g=65535:65535:65535"));
        ASSERT(strstr(reply.error.evidence,"newfs=0 d=4294967295"));
        ASSERT(strstr(reply.error.evidence," a=")==NULL);
        st.owner.v3_dispatch.work=UINT64_C(4294967296);
        ASSERT(!mb_owner_refusal(&st,&reply,NULL));
        ASSERT(strstr(reply.error.evidence," d=unavailable"));
        st.owner.v3_newfs_done=true;
        ASSERT(!mb_owner_pc_scope(&st));
        ASSERT(!mb_owner_refusal(&st,&reply,NULL));
        ASSERT(strstr(reply.error.evidence,"newfs=1 d=unavailable"));
        PASS();
    } _test_next:;
    return failures;
}
static int tmb_trace_origin_controls(void)
{
 int failures=0;static struct rvmachine machine,other;
 TEST("V3 transition origin binds actual run tuple including unopened epochs") {
  struct mb_pc_context before={.machine=&machine,.instance=11,.retired=100,.fw_calls=2,.device_work=3,.valid=true};
  struct mb_pc_context after=before;after.retired=110;
  struct guest_gov_decision decision={.kind=GUEST_GOV_RUN_SLICE};
  struct mb_v3_dispatch origin={0};
  mb_trace_actual_observe(&origin,&before,&after,&decision,RVMACHINE_OK);
  ASSERT(origin.seen);
  ASSERT(origin.valid);
  ASSERT_EQ(origin.work,115u);
  ASSERT_EQ(origin.host_epoch,0u);
  ASSERT_EQ(origin.device_epoch,0u);
  decision.kind=GUEST_GOV_SLEEP;
  mb_trace_actual_observe(&origin,&before,&(struct mb_pc_context){0},&decision,RVMACHINE_OK);
  ASSERT(origin.valid && origin.work==115);
  decision.kind=GUEST_GOV_RUN_SLICE;
  struct mb_pc_context stale=after;stale.host_epoch=91;stale.device_epoch=92;
  mb_trace_actual_result_observe(&origin,&stale,&stale,&decision,RVMACHINE_OK,
      &(struct rvmachine_result){0});
  ASSERT(origin.valid && origin.work==115 && origin.host_epoch==0 && origin.device_epoch==0);
  for(unsigned mode=0;mode<7;mode++) {
   struct mb_pc_context changed=after;origin=(struct mb_v3_dispatch){0};
   switch(mode){case 0:changed.machine=&other;break;case 1:changed.instance++;break;case 2:changed.host_epoch++;break;case 3:changed.device_epoch++;break;case 4:changed.valid=false;break;case 5:changed.retired=99;break;default:changed.retired=UINT64_MAX;changed.fw_calls=1;break;}
   mb_trace_actual_observe(&origin,&before,&changed,&decision,RVMACHINE_OK);
   ASSERT(origin.seen && !origin.valid);
  }
  PASS();
 } _test_next:;
 return failures;
}
static int tmb_trace_enqueue_controls(void)
{
 int failures=0;static struct rvmachine machine,other;
 TEST("V3 preformat enqueue observes once and refuses absent stale or decreasing work") {
  struct mb_pc_context context={.machine=&machine,.instance=11,.host_epoch=7,.device_epoch=9,.retired=100,.fw_calls=2,.device_work=3,.valid=true};
  struct mb_v3_dispatch origin={.machine=&machine,.instance=11,.host_epoch=7,.device_epoch=9,.work=105,.seen=true,.valid=true};
  struct mb_v3_dispatch trace[17]={0};uint32_t attempted=0;
  mb_trace_dispatch_observe(trace,&attempted,0,0,&origin,&context);
  ASSERT(attempted==0);
  mb_trace_dispatch_observe(trace,&attempted,0,1,&origin,&context);
  ASSERT(attempted==1 && trace[0].valid && trace[0].work==105);
  for(unsigned mode=0;mode<7;mode++) {
   struct mb_pc_context changed=context;memset(trace,0,sizeof trace);attempted=0;
   switch(mode){case 0:changed.machine=&other;break;case 1:changed.instance++;break;case 2:changed.host_epoch++;break;case 3:changed.device_epoch++;break;case 4:changed.valid=false;break;case 5:changed.retired++;break;default:changed.retired=UINT64_MAX;changed.fw_calls=1;break;}
   mb_trace_dispatch_observe(trace,&attempted,0,1,&origin,&changed);
   ASSERT(attempted==1 && trace[0].seen && !trace[0].valid);
   mb_trace_dispatch_observe(trace,&attempted,0,1,&origin,&context);
   ASSERT(!trace[0].valid);
  }
  memset(trace,0,sizeof trace);attempted=0;
  mb_trace_dispatch_observe(trace,&attempted,0,1,&(struct mb_v3_dispatch){0},&context);
  ASSERT(attempted==1 && !trace[0].seen);
  mb_trace_dispatch_observe(trace,&attempted,0,1,&origin,&context);ASSERT(!trace[0].seen);
  memset(trace,0,sizeof trace);attempted=0;trace[0]=origin;trace[0].work=106;
  mb_trace_dispatch_observe(trace,&attempted,1,2,&origin,&context);ASSERT(trace[1].seen && !trace[1].valid);
  attempted=0;mb_trace_dispatch_observe(trace,&attempted,7,12,&origin,&context);ASSERT(attempted==0);
  PASS();
 } _test_next:;
 return failures;
}
static int tmb_trace_message_controls(void)
{
 int failures=0;static struct mb_state st;
 TEST("V3 preformat trace retains all eight explicit values within message bound") {
  char out[192];memset(&st,0,sizeof st);st.owner.profile_revision=3;st.owner.command_step=8;
  mb_owner_trace_message(&st,out);ASSERT(strstr(out,"dispatch[0..7]=unknown:unknown:unknown:unknown:unknown:unknown:unknown:unknown")!=NULL);
  for(unsigned i=0;i<8;i++)st.owner.phase_dispatch[i]=(struct mb_v3_dispatch){.seen=true,.valid=true,.work=UINT32_MAX};
  mb_owner_trace_message(&st,out);ASSERT(strstr(out,"dispatch[0..7]=4294967295:4294967295:4294967295:4294967295:4294967295:4294967295:4294967295:4294967295")!=NULL);
  for(unsigned i=0;i<8;i++)st.owner.phase_dispatch[i].work=(uint64_t)UINT32_MAX+1;
  mb_owner_trace_message(&st,out);ASSERT(strlen(out)==183);
  ASSERT(strstr(out,"dispatch[0..7]=unavailable:unavailable:unavailable:unavailable:unavailable:unavailable:unavailable:unavailable")!=NULL);
  struct zcl_command_reply reply={0};
  st.owner.last_retired=st.owner.last_fw_calls=st.owner.last_device_work=UINT64_MAX;
  ASSERT(!mb_owner_refusal(&st,&reply,NULL));
  ASSERT(strcmp(reply.error.message,out)==0);
  ASSERT(strstr(reply.error.evidence,"work=18446744073709551615/18446744073709551615/18446744073709551615")!=NULL);
  st.owner.profile_revision=2;mb_owner_trace_message(&st,out);ASSERT(strstr(out,"dispatch[")==NULL);
  st.owner.profile_revision=3;st.owner.recover=true;mb_owner_trace_message(&st,out);ASSERT(strstr(out,"dispatch[")==NULL);
  ASSERT(!mb_owner_transition_context(&st).valid);
  st.owner.recover=false;st.owner.command_step=7;mb_owner_trace_message(&st,out);ASSERT(strstr(out,"dispatch[")==NULL);
  memset(&st,0,sizeof st);st.owner.profile_revision=5;st.owner.command_step=10;
  mb_owner_trace_message(&st,out);
  ASSERT(strstr(out,"phase=9 dispatch=unknown format_dispatch=unknown")!=NULL);
  PASS();
 } _test_next:;
 return failures;
}
static int tmb_trace_late_controls(void)
{
 int failures=0;static struct rvmachine machine;
 TEST("prepared INITIAL late dispatch trace is bounded sticky and tuple bound") {
  struct mb_state st={0};char out[192];st.owner.profile_revision=5;
  for(size_t step=9;step<=17;step++) {
   st.owner.command_step=step;mb_owner_trace_message(&st,out);
   char expected[64];snprintf(expected,sizeof expected,"phase=%zu dispatch=unknown",step-1);
   ASSERT(strstr(out,expected)!=NULL);
  }
  st.owner.command_step=10;
  st.owner.phase_dispatch[9]=(struct mb_v3_dispatch){.seen=true,.valid=true,.work=UINT32_MAX};
  st.owner.phase_dispatch[7]=st.owner.phase_dispatch[9];mb_owner_trace_message(&st,out);
  ASSERT(strstr(out,"phase=9 dispatch=4294967295 format_dispatch=4294967295")!=NULL);
  ASSERT(strlen(out)<192);
  st.owner.phase_dispatch[9].work=(uint64_t)UINT32_MAX+1;
  mb_owner_trace_message(&st,out);ASSERT(strstr(out,"dispatch=unavailable")!=NULL);
  struct mb_v3_dispatch trace[17]={0},origin={.machine=&machine,.instance=11,.host_epoch=7,.device_epoch=9,.work=105,.seen=true,.valid=true};
  struct mb_pc_context context={.machine=&machine,.instance=11,.host_epoch=7,.device_epoch=9,.retired=100,.fw_calls=2,.device_work=3,.valid=true};uint32_t attempted=0;
  mb_trace_dispatch_observe(trace,&attempted,16,17,&origin,&context);
  ASSERT(attempted==(1u<<16) && trace[16].valid);
  mb_trace_dispatch_observe(trace,&attempted,17,18,&origin,&context);ASSERT(attempted==(1u<<16));
  for(unsigned mode=0;mode<2;mode++) {
   memset(trace,0,sizeof trace);attempted=0;trace[7]=origin;
   struct mb_pc_context changed=context;
   if(mode==0)changed.host_epoch++;else changed.device_epoch++;
   mb_trace_dispatch_observe(trace,&attempted,9,10,&origin,&changed);
   ASSERT(trace[9].seen && !trace[9].valid);
   trace[7]=origin;mb_trace_dispatch_observe(trace,&attempted,9,10,&origin,&context);
   ASSERT(!trace[9].valid);
  }
  memset(trace,0,sizeof trace);attempted=0;trace[7]=origin;
  trace[7].host_epoch=0;trace[7].device_epoch=0;
  mb_trace_dispatch_observe(trace,&attempted,9,10,&origin,&context);
  ASSERT(trace[9].valid && trace[9].host_epoch==7 && trace[9].device_epoch==9);
  st.owner.recover=true;mb_owner_trace_message(&st,out);ASSERT(strstr(out,"format_dispatch=")==NULL);
  PASS();
 } _test_next:;
 return failures;
}
static int tmb_v3_trace_refusal_contract(void)
{
 int failures=0;static struct mb_state st;
 TEST("V3 INITIAL refusal exposes eight unknown preformat dispatch boundaries") {
  memset(&st,0,sizeof st);st.owner.profile_revision=3;st.owner.command_step=8;
  struct zcl_command_reply reply={0};
  ASSERT(!mb_owner_refusal(&st,&reply,NULL));
  ASSERT(strstr(reply.error.message,"dispatch[0..7]=unknown:unknown:unknown:unknown:unknown:unknown:unknown:unknown")!=NULL);
  PASS();
 } _test_next:;
 return failures;
}
static int tmb_p7_sum_controls(void)
{
    int failures=tmb_v3_pc_scope_controls() + tmb_v3_dispatch_controls() +
        tmb_v3_diagnostic_evidence_controls() + tmb_v3_trace_refusal_contract() + tmb_trace_origin_controls() + tmb_trace_enqueue_controls() + tmb_trace_message_controls() + tmb_trace_late_controls();
    TEST("P7 checked totals preserve exact boundary and refuse overflow") {
        uint64_t out=77;
        ASSERT(mb_p7_sum(100,2,3,&out)); ASSERT_EQ(out,105u);
        ASSERT(mb_p7_sum(UINT64_MAX-2,1,1,&out)); ASSERT_EQ(out,UINT64_MAX);
        out=77; ASSERT(!mb_p7_sum(UINT64_MAX,1,0,&out)); ASSERT_EQ(out,77u);
        ASSERT(!mb_p7_sum(UINT64_MAX-1,0,2,&out)); ASSERT_EQ(out,77u);
        PASS();
    } _test_next:;
    return failures;
}
static int tmb_p7_observe_controls(void)
{
    int failures=0;
    TEST("P7 crossing brackets positive current context exactly once") {
        static struct rvmachine metadata;
        struct mb_pc_context before={.machine=&metadata,.instance=11,
            .host_epoch=7,.device_epoch=9,.retired=100,.fw_calls=2,.device_work=3,.valid=true};
        struct mb_pc_context after=before;
        struct guest_gov_decision decision={.kind=GUEST_GOV_RUN_SLICE};
        struct rvmachine_result result={.retired=200,.fw_calls=4,.device_work=6};
        struct mb_p7_bracket b={0};
        mb_p7_dispatch_observe(&b,7,8,&before);
        mb_p7_observe(&b,&before,&after,false,true,RVMACHINE_OK,&decision,&result);
        ASSERT(b.seen && b.valid); ASSERT_EQ(b.lower,105u); ASSERT_EQ(b.upper,210u);
        result.retired=300;
        mb_p7_observe(&b,&before,&after,false,true,RVMACHINE_OK,&decision,&result);
        ASSERT_EQ(b.upper,210u); /* Sticky first observation; no overwrite. */
        PASS();
    } _test_next:;
    return failures;
}
static int tmb_p7_refusal_controls(void)
{
    int failures=0;
    TEST("P7 zero, regression, overflow, status, decision and stale context refuse") {
        static struct rvmachine metadata, replacement;
        for(unsigned mode=0;mode<11;mode++) {
            struct mb_pc_context before={.machine=&metadata,.instance=11,
                .host_epoch=7,.device_epoch=9,.retired=100,.fw_calls=2,.device_work=3,.valid=true};
            struct mb_pc_context after=before;
            struct guest_gov_decision decision={.kind=GUEST_GOV_RUN_SLICE};
            struct rvmachine_result result={.retired=200,.fw_calls=4,.device_work=6};
            enum rvmachine_status status=RVMACHINE_OK;
            if(mode==0) result=(struct rvmachine_result){.retired=100,.fw_calls=2,.device_work=3};
            if(mode==1) result.fw_calls=1; /* Aggregate can rise, component regression still fails. */
            if(mode==2) result.retired=UINT64_MAX;
            if(mode==3) status=RVMACHINE_ERR_STATE;
            if(mode==4) decision.kind=GUEST_GOV_SLEEP;
            if(mode==5) after.valid=false;
            if(mode==6) before.valid=false;
            if(mode==7) after.instance++;
            if(mode==8) after.host_epoch++;
            if(mode==9) after.device_epoch++;
            if(mode==10) after.machine=&replacement;
            struct mb_p7_bracket b={0};
        mb_p7_dispatch_observe(&b,7,8,&before);
            mb_p7_observe(&b,&before,&after,false,true,status,&decision,&result);
            ASSERT(b.seen && !b.valid); ASSERT_EQ(b.lower,0u); ASSERT_EQ(b.upper,0u);
            before.valid=after.valid=true; after=before; decision.kind=GUEST_GOV_RUN_SLICE;
            result=(struct rvmachine_result){.retired=200,.fw_calls=4,.device_work=6};
            mb_p7_observe(&b,&before,&after,false,true,RVMACHINE_OK,&decision,&result);
            ASSERT(!b.valid); /* Restored context cannot silently re-arm. */
        }
        PASS();
    } _test_next:;
    return failures;
}
static int tmb_p7_non_crossing_controls(void)
{
    int failures=0;
    TEST("P7 absent/already-seen marker cannot invent a crossing") {
        struct mb_pc_context before={0},after={0};
        struct guest_gov_decision decision={.kind=GUEST_GOV_RUN_SLICE};
        struct rvmachine_result result={0}; struct mb_p7_bracket b={0};
        mb_p7_observe(&b,&before,&after,false,false,RVMACHINE_OK,&decision,&result);
        ASSERT(!b.seen && !b.valid);
        mb_p7_observe(&b,&before,&after,true,true,RVMACHINE_OK,&decision,&result);
        ASSERT(!b.seen && !b.valid);
        PASS();
    } _test_next:;
    return failures;
}

static int tmb_p7_dispatch_tuple_controls(void)
{
    int failures=0;
    TEST("P7 crossing stays bound to dispatch machine instance and dual epochs") {
        static struct rvmachine machine,replacement;
        struct mb_pc_context c={.machine=&machine,.instance=11,
            .host_epoch=7,.device_epoch=9,.retired=100,.fw_calls=2,.device_work=3,.valid=true};
        struct mb_p7_bracket b={0};
        mb_p7_dispatch_observe(&b,7,8,&c);
        ASSERT(b.dispatch_valid && mb_p7_dispatch_same(&b,&c));
        for(unsigned mode=0;mode<5;mode++) {
            struct mb_pc_context changed=c;
            if(mode==0) changed.machine=&replacement;
            if(mode==1) changed.instance++;
            if(mode==2) changed.host_epoch++;
            if(mode==3) changed.device_epoch++;
            if(mode==4) changed.valid=false;
            ASSERT(!mb_p7_dispatch_same(&b,&changed));
            ASSERT(mb_p7_dispatch_same(&b,&c)); /* Purecomparison nevermutates. */
        }
        b.dispatch_machine=(const struct rvmachine *)(uintptr_t)1;
        ASSERT(!mb_p7_dispatch_same(&b,&c)); /* Storedpointer NEVERdereferenced. */
        PASS();
    } _test_next:;
    return failures;
}
static int tmb_p7_dispatch_invalid_tuple_controls(void)
{
    int failures=0;
    TEST("P7 invalid dispatch cannot rearm after identity restoration") {
        static struct rvmachine machine;
        for(unsigned mode=0;mode<5;mode++) {
            struct mb_pc_context c={.machine=&machine,.instance=11,
                .host_epoch=7,.device_epoch=9,.retired=100,.valid=true};
            if(mode==0) c.machine=NULL;
            if(mode==1) c.instance=0;
            if(mode==2) c.host_epoch=0;
            if(mode==3) c.device_epoch=0;
            if(mode==4) c.valid=false;
            struct mb_p7_bracket b={0}; mb_p7_dispatch_observe(&b,7,8,&c);
            ASSERT(b.dispatch_seen && !b.dispatch_valid);
            c=(struct mb_pc_context){.machine=&machine,.instance=11,
                .host_epoch=7,.device_epoch=9,.retired=100,.valid=true};
            mb_p7_dispatch_observe(&b,7,8,&c); ASSERT(!b.dispatch_valid);
        }
        PASS();
    } _test_next:;
    return failures;
}

static int tmb_p7_dispatch_crossing_controls(void)
{
    int failures=0;
    TEST("P7 matching crossing snapshots cannot replace their original dispatch") {
        static struct rvmachine machine, replacement;
        for(unsigned mode=0;mode<5;mode++) {
            struct mb_pc_context original={.machine=&machine,.instance=11,
                .host_epoch=7,.device_epoch=9,.retired=100,.valid=true};
            struct mb_p7_bracket b={0};
            mb_p7_dispatch_observe(&b,7,8,&original);
            struct mb_pc_context changed=original;
            if(mode==0) changed.machine=&replacement;
            if(mode==1) changed.instance++;
            if(mode==2) changed.host_epoch++;
            if(mode==3) changed.device_epoch++;
            if(mode==4) changed.retired=99;
            struct guest_gov_decision decision={.kind=GUEST_GOV_RUN_SLICE};
            struct rvmachine_result result={.retired=200};
            mb_p7_observe(&b,&changed,&changed,false,true,RVMACHINE_OK,&decision,&result);
            ASSERT(b.seen && !b.valid);
            mb_p7_observe(&b,&original,&original,false,true,RVMACHINE_OK,&decision,&result);
            ASSERT(!b.valid);
        }
        PASS();
    } _test_next:;
    return failures;
}
static int tmb_p7_dispatch_bounds(void)
{
    int failures=0;
    TEST("P7 dispatch refuses false transitions and overflowing first observation") {
        static struct rvmachine machine;
        struct mb_pc_context c={.machine=&machine,.instance=11,
            .host_epoch=7,.device_epoch=9,.retired=UINT64_MAX,.fw_calls=1,.valid=true};
        struct mb_p7_bracket b={0};
        mb_p7_dispatch_observe(&b,7,7,&c);
        mb_p7_dispatch_observe(&b,7,13,&c);
        mb_p7_dispatch_observe(&b,8,9,&c);
        ASSERT(!b.dispatch_seen);
        mb_p7_dispatch_observe(&b,7,8,&c);
        ASSERT(b.dispatch_seen && !b.dispatch_valid);
        c.retired=100;
        mb_p7_dispatch_observe(&b,7,8,&c);
        ASSERT(!b.dispatch_valid);
        PASS();
    } _test_next:;
    return failures;
}
static int tmb_p7_dispatch_reporting(void)
{
    int failures=0;
    TEST("P7 dispatch triplet refuses wide or unordered evidence without truncation") {
        static struct mb_state st; static struct rvmachine machine;
        ASSERT(tmb_pc_scope_start(&st,&machine));
        struct mb_p7_bracket valid={.seen=true,.valid=true,.dispatch_seen=true,
            .dispatch_valid=true,.dispatch=UINT32_MAX-2,.lower=UINT32_MAX-1,.upper=UINT32_MAX};
        st.owner.p7_bracket=valid;
        st.owner.last_retired=st.owner.last_fw_calls=st.owner.last_device_work=UINT64_MAX;
        struct zcl_command_reply reply={0};
        ASSERT(!mb_owner_refusal(&st,&reply,NULL));
        ASSERT(strstr(reply.error.evidence," a=4294967293:4294967294:4294967295") != NULL);
        for(unsigned mode=0;mode<6;mode++) {
            st.owner.p7_bracket=valid;
            if(mode==0) st.owner.p7_bracket.dispatch=UINT64_C(4294967296);
            if(mode==1) st.owner.p7_bracket.lower=UINT64_C(4294967296);
            if(mode==2) st.owner.p7_bracket.upper=UINT64_C(4294967296);
            if(mode==3) st.owner.p7_bracket.dispatch=UINT32_MAX;
            if(mode==4) st.owner.p7_bracket.upper=UINT32_MAX-1;
            if(mode==5) st.owner.p7_bracket.dispatch_valid=false;
            ASSERT(!mb_owner_refusal(&st,&reply,NULL));
            ASSERT(strstr(reply.error.evidence," a=unavailable") != NULL);
        }
        PASS();
    } _test_next:;
    return failures;
}
static int t_public_v2_command_observer(void)
{
    int failures = tmb_privilege_answers()+tmb_privilege_refusals()+tmb_privilege_zero_and_overflow()+tmb_privilege_old_profile()+
        tmb_privilege_production_observe()+tmb_privilege_production_tuple()+tmb_privilege_evidence_width()+
        tmb_history_message_red()+tmb_history_join_message_red()+tmb_history_deadline_stop_controls()+tmb_history_epoch_controls()+tmb_history_binding_controls()+
        tmb_p7_dispatch_crossing_controls() + tmb_p7_dispatch_bounds() + tmb_p7_dispatch_reporting() +
        tmb_p7_dispatch_tuple_controls() + tmb_p7_dispatch_invalid_tuple_controls() + tmb_p7_sum_controls() + tmb_p7_observe_controls() +
        tmb_p7_refusal_controls() + tmb_p7_non_crossing_controls() + tmb_geometry_parser_controls() + tmb_geometry_observer_controls() +
        tmb_geometry_scope_controls() +
        tmb_geometry_evidence_width() + tmb_public_pc_manager_controls() +
        tmb_public_pc_context_controls() + tmb_public_pc_summary_controls() +
        tmb_public_pc_classifier_controls() + t_public_v2_phase7_diagnostics() +
        t_public_v2_phase7_console_controls() + t_public_v2_refusal_evidence_width();
    TEST("PUBLIC V2 command RC and completion bind phase and independent epochs") {
        static const char *const invalid[] = {
            "PUBLIC_V2_RC:1:1\r\n", "PUBLIC_V2_RC:2:0\r\n",
            "PUBLIC_V2_RC:01:0\r\n", "PUBLIC_V2_RC:1:256\r\n",
            "PUBLIC_V2_RC:1:0:0\r\n", "PUBLIC_V2_RC:1:0\n"
        };
        struct mb_command_observation s={0}; bool pending=false,done=false;
        for (size_t i=0;i<sizeof invalid/sizeof invalid[0];i++) {
            memset(&s,0,sizeof s);
            ASSERT(mb_command_begin(&s,1,100,7,9));
            ASSERT(!mb_command_observe(&s,(const uint8_t *)invalid[i],strlen(invalid[i]),
                1,100,7,9,false,false,false,&pending,&done));
            ASSERT(!pending && !done && !s.rc_seen);
        }
        ASSERT(mb_command_rc((const uint8_t *)"PUBLIC_V2_RC:16:255\r\n",21,
                            &(unsigned){0},&(unsigned){0}));
        ASSERT(!mb_command_observe(&s,(const uint8_t *)"PUBLIC_OWNER_NEXT\r\n",19,
            1,100,7,9,false,false,false,&pending,&done));
        ASSERT(!mb_command_observe(&s,(const uint8_t *)"PUBLIC_V2_RC:1:0\r\n",18,
            1,101,7,9,false,false,false,&pending,&done));
        ASSERT(!mb_command_observe(&s,(const uint8_t *)"PUBLIC_V2_RC:1:0\r\n",18,
            1,100,8,9,false,false,false,&pending,&done));
        ASSERT(mb_command_observe(&s,(const uint8_t *)"PUBLIC_V2_RC:1:0\r\n",18,
            1,100,7,9,false,false,false,&pending,&done));
        ASSERT(!mb_command_observe(&s,(const uint8_t *)"PUBLIC_V2_RC:1:0\r\n",18,
            1,100,7,9,false,false,false,&pending,&done));
        ASSERT(mb_command_observe(&s,(const uint8_t *)"PUBLIC_OWNER_NEXT\r\n",19,
            1,100,7,9,false,false,false,&pending,&done));
        ASSERT(!mb_command_observe(&s,(const uint8_t *)"PUBLIC_OWNER_NEXT\r\n",19,
            1,100,7,9,false,false,false,&pending,&done));
        memset(&s,0,sizeof s); pending=false;
        ASSERT(mb_command_begin(&s,16,100,8,10));
        ASSERT(mb_command_observe(&s,(const uint8_t *)"PUBLIC_V2_RC:16:0\r\n",19,
            16,100,8,10,true,true,true,&pending,&done));
        ASSERT(!mb_command_observe(&s,(const uint8_t *)"PUBLIC_OWNER_DONE\r\n",19,
            16,100,8,10,true,true,false,&pending,&done));
        ASSERT(mb_command_observe(&s,(const uint8_t *)"PUBLIC_OWNER_DONE\r\n",19,
            16,100,8,10,true,true,true,&pending,&done));
        ASSERT(done && !pending);
        ASSERT(!mb_command_observe(&s,(const uint8_t *)"PUBLIC_OWNER_DONE\r\n",19,
            16,100,8,10,true,true,true,&pending,&done));
        PASS();
    } _test_next:;
    return failures;
}
/* DONE is only a console_done latch. Outside manager drive, mb_owner_proof
 * must freshly verify storage_synced, original image currentness, credential,
 * record and original deadline before identity_finish/READY. No cached barrier. */
static int t_public_v2_command_identity_phases(void)
{
    int failures=0;
    TEST("PUBLIC V2 identity phases and device epoch are required") {
        struct mb_command_observation s={0}; bool pending=false,done=false;
        ASSERT(mb_command_begin(&s,14,100,7,9));
        const uint8_t *key_rc=(const uint8_t *)"PUBLIC_V2_RC:14:0\r\n";
        ASSERT(!mb_command_observe(&s,key_rc,19,14,100,7,10,true,false,true,&pending,&done));
        ASSERT(!mb_command_observe(&s,key_rc,19,14,100,7,9,false,false,true,&pending,&done));
        ASSERT(mb_command_observe(&s,key_rc,19,14,100,7,9,true,false,true,&pending,&done));
        ASSERT(mb_command_observe(&s,(const uint8_t *)"PUBLIC_OWNER_NEXT\r\n",19,
            14,100,7,9,true,false,true,&pending,&done));
        ASSERT(mb_command_begin(&s,15,100,7,9)); pending=false;
        const uint8_t *fp_rc=(const uint8_t *)"PUBLIC_V2_RC:15:0\r\n";
        ASSERT(!mb_command_observe(&s,fp_rc,19,15,100,7,9,true,false,true,&pending,&done));
        ASSERT(mb_command_observe(&s,fp_rc,19,15,100,7,9,true,true,true,&pending,&done));
        ASSERT(!done && !pending);
        PASS();
    } _test_next:;
    return failures;
}

#include "dev_machine_boot_prepare_controls.inc"

static bool tmb_replace_once(char *out, size_t cap, const char *text,
    const char *from, const char *to)
{
    const char *at=strstr(text,from);
    if (!at || strstr(at+strlen(from),from) || (size_t)(at-text)>INT_MAX) return false;
    int n=snprintf(out,cap,"%.*s%s%s",(int)(at-text),text,to,at+strlen(from));
    return n>=0 && (size_t)n<cap;
}
/* Host shell semantics of the actual fixed command; not guest attach proof. */
static int t_public_v2_provider_check(void)
{
    int failures=0;
    struct tmb_dir d={0};
    TEST("PUBLIC V2 provider check requires helper success and a character device") {
        static struct mb_state st;
        memset(&st,0,sizeof st); st.owner.profile_revision=2;
        size_t step=6;
        const char *command=mb_owner_command_text(&st,&step);
        ASSERT(command && strstr(command,"&& [ -c /dev/vtbd0.eli ]\n"));
        ASSERT(tmb_setup(&d,"tiny"));
        ASSERT_EQ(mkfifo(d.link,0600),0);
        const char *paths[]={"/dev/null","/dev/null",d.disk,d.kernel,d.link};
        for(unsigned mode=0;mode<5;mode++) {
            char stage[512], mapped[512], output[128]={0};
            ASSERT(tmb_replace_once(stage,sizeof stage,command,
                "/sbin/geli-bootstrap-public",mode==1 ? "false" : "true"));
            ASSERT(tmb_replace_once(mapped,sizeof mapped,stage,
                "/dev/vtbd0.eli","\"$1\""));
            const char *argv[]={"/bin/sh","-c",mapped,"provider-fixture",paths[mode],NULL};
            struct zcl_spawn_binary_observation observed={0};
            struct zcl_result result=zcl_spawn_capture_binary(argv,output,sizeof output,5000,&observed);
            ASSERT(result.ok == (mode==0));
            ASSERT(observed.eof && observed.exit_observed && !observed.timed_out && !observed.overflow);
            ASSERT_EQ(observed.exit_code,mode==0 ? 0 : 1);
            const char *expected=mode==0 ? "PUBLIC_V2_RC:6:0\nPUBLIC_OWNER_NEXT\n" : "PUBLIC_V2_RC:6:1\n";
            ASSERT_EQ(observed.output_len,strlen(expected));
            ASSERT(memcmp(output,expected,observed.output_len)==0);
        }
        PASS();
    } _test_next:;
    if (d.dir[0]) test_cleanup_tmpdir(d.dir);
    return failures;
}
static int t_public_v3_newfs_script(void)
{
    int failures = 0;
    static struct mb_state st;
    TEST("PUBLIC V3 emits one formatter success marker before mount only in INITIAL") {
        for (unsigned revision = 2; revision <= 3; revision++) {
            for (unsigned recover = 0; recover < 2; recover++) {
                memset(&st, 0, sizeof st);
                st.owner.profile_revision = revision; st.owner.recover = recover != 0;
                size_t step = 7;
                const char *text = mb_owner_command_text(&st, &step);
                ASSERT(text != NULL);
                const char *marker = strstr(text, "PUBLIC_V3_NEWFS_DONE");
                /* The leading P is octal-escaped so console echo cannot qualify. */
                ASSERT(marker == NULL);
                marker = strstr(text, "\\120UBLIC_V3_NEWFS_DONE");
                bool expected = revision == 3 && !recover;
                ASSERT((marker != NULL) == expected);
                if (expected) {
                    const char *format = strstr(text, "newfs -U");
                    const char *mount = strstr(text, "mount -t ufs");
                    ASSERT(format && mount);
                    ASSERT(format < marker && marker < mount);
                    ASSERT(strstr(marker + 1, "\\120UBLIC_V3_NEWFS_DONE") == NULL);
                }
            }
        }
        PASS();
    } _test_next:;
    return failures;
}
static int t_public_v3_command_selection(void)
{
    int failures = t_public_v3_newfs_script();
    static struct mb_state st;
    TEST("PUBLIC prepared profiles preserve INITIAL preparation and attach-only recovery") {
        for (unsigned revision = 2; revision <= 5; revision++) {
            for (unsigned recover = 0; recover < 2; recover++) {
                memset(&st, 0, sizeof st);
                st.owner.profile_revision = revision;
                st.owner.recover = recover != 0;
                size_t step = 6;
                const char *attach = mb_owner_command_text(&st, &step);
                ASSERT(attach != NULL);
                ASSERT_EQ(step, 6u);
                ASSERT((strstr(attach, "--public-initial-prepare") != NULL) ==
                    (revision >= 3 && !recover));
                ASSERT(strstr(attach, "[ -c /dev/vtbd0.eli ]") != NULL);
                step = 7;
                const char *format = mb_owner_command_text(&st, &step);
                ASSERT(format != NULL);
                ASSERT_EQ(step, recover ? 12u : 7u);
                ASSERT((strstr(format, "newfs -U") != NULL) == !recover);
                ASSERT((strstr(format, "dd if=/dev/zero") != NULL) ==
                    (revision == 2 && !recover));
                ASSERT(mb_owner_command_lines(attach, strlen(attach)));
                ASSERT(mb_owner_command_lines(format, strlen(format)));
                size_t total = 0, count = 0;
                step = 0;
                while (step < 17) {
                    size_t selected = step;
                    const char *text = mb_owner_command_text(&st, &selected);
                    ASSERT(text != NULL);
                    size_t n = strlen(text);
                    ASSERT(mb_owner_command_lines(text, n));
                    ASSERT(n <= RVMACHINE_INPUT_MAX - total);
                    total += n; count++;
                    if (recover) {
                        ASSERT(strstr(text, "--public-initial-prepare") == NULL);
                        ASSERT(strstr(text, "dd if=/dev/zero") == NULL);
                        st.owner.profile_revision = 2;
                        size_t old_step = step;
                        const char *old = mb_owner_command_text(&st, &old_step);
                        ASSERT(old && selected == old_step && !strcmp(text, old));
                        st.owner.profile_revision = revision;
                    }
                    step = selected + 1;
                }
                ASSERT_EQ(count, recover ? 12u : 17u);
                ASSERT_EQ(total, recover ? MB_OWNER_V2_RECOVER_BYTES :
                    revision >= 3 ? MB_OWNER_V3_INITIAL_BYTES : MB_OWNER_V2_INITIAL_BYTES);
            }
        }
        PASS();
    } _test_next:;
    return failures;
}

static int t_public_v2_command_table(void)
{
    int failures = t_public_prepare_controls() + t_public_v2_provider_check() +
        t_public_v3_command_selection();
    static struct mb_state st;
    TEST("PUBLIC V2 fixed commands fit both queues and recovery omits all initialization") {
        for (unsigned recover = 0; recover < 2; recover++) {
            memset(&st, 0, sizeof st);
            st.owner.profile_revision = 2; st.owner.recover = recover != 0;
            size_t total = 0, next = 0, count = 0;
            while (next < 17) {
                size_t selected = next;
                const char *text = mb_owner_command_text(&st, &selected);
                ASSERT(text != NULL);
                ASSERT(selected == (recover && next == 7 ? 12 : next));
                size_t n = strlen(text);
                if (!recover && selected == 7) {
                    ASSERT(strstr(text, "seek=2 count=2 conv=fsync &&") != NULL);
                    ASSERT(strstr(text, "seek=15 count=3 conv=notrunc,fsync &&") != NULL);
                }
                ASSERT(mb_owner_command_lines(text, n));
                ASSERT(n <= RVMACHINE_INPUT_MAX - total);
                total += n; count++;
                if (recover) {
                    ASSERT(strstr(text, "newfs") == NULL);
                    ASSERT(strstr(text, "chmod") == NULL);
                    ASSERT(strstr(text, "ssh-keygen -q") == NULL);
                    ASSERT(strstr(text, "geli init") == NULL);
                }
                next = selected + 1;
            }
            ASSERT_EQ(count, recover ? 12u : 17u);
            ASSERT_EQ(total, recover ? MB_OWNER_V2_RECOVER_BYTES : MB_OWNER_V2_INITIAL_BYTES);
            ASSERT(mb_owner_command_text(&st, &next) == NULL);
        }
        PASS();
    } _test_next:;
    return failures;
}

static int t_public_owner_paired_policy(void)
{
    int failures = 0;
    static struct mb_state st;
    static const char *const kernels[] = {
        "fca910590d9b3171712883285fb30743b30f7715a4b8fb41c17a51bfdcca6a6e",
        "c7df418c75c63125a6ea77edba7b654486c5912bc1fd60c53fcc39778dbb1bf7"
    };
    static const uint64_t lengths[] = {43408024, 43406744};
    struct zcl_command_reply reply = {0};
    struct json_value input;
    json_init(&input);
    TEST("paired PUBLIC profiles bind exact image size and reject crossed image authority") {
        for (unsigned side = 0; side < 2; ++side) {
            struct vcs_guest_image_observation o = {0};
            memset(&st, 0, sizeof st);
            st.owner.enabled = st.accepted.public_observation = true;
            st.owner.profile_revision = side + 4;
            memset(st.accepted.root, 0x11, 32);
            ASSERT(zcl_hex_decode_lower(kernels[side], st.owner.authorized_kernel, 32));
            memcpy(o.image_sha256, st.owner.authorized_kernel, 32);
            o.image.bytes = lengths[side];
            ASSERT(tmb_owner_image_grant(&st, st.accepted.root, &o));
            o.image.bytes++;
            ASSERT(!tmb_owner_image_grant(&st, st.accepted.root, &o));
            o.image.bytes -= 2;
            ASSERT(!tmb_owner_image_grant(&st, st.accepted.root, &o));
            o.image.bytes = lengths[1-side];
            ASSERT(!tmb_owner_image_grant(&st, st.accepted.root, &o));
            o.image.bytes = lengths[side];
            o.image_sha256[0] ^= 1;
            ASSERT(!tmb_owner_image_grant(&st, st.accepted.root, &o));
            o.image_sha256[0] ^= 1;
            for (unsigned revision = 1; revision <= 6; ++revision) {
                st.owner.profile_revision = revision;
                ASSERT(tmb_owner_image_grant(&st, st.accepted.root, &o) == (revision == side+4));
            }
        }
        PASS();
    }
    TEST("paired PUBLIC parse accepts only its own explicit profile in INITIAL and RECOVER") {
        for (unsigned side = 0; side < 2; ++side) {
            for (unsigned revision = 2; revision <= 6; ++revision) {
                for (unsigned recover = 0; recover < 2; ++recover) {
                    char text[1200];
                    int n = snprintf(text, sizeof text,
                        "{\"public_unlock\":{\"policy\":\"public_keyfile_fixture\","
                        "\"purpose\":\"public_geli_keyfile\",\"receiver_revision\":1,"
                        "\"mode\":\"%s\",\"authorized_kernel_sha256\":\"%s\","
                        "\"volume\":\"PUBLIC.volume\",\"record\":\"PUBLIC.record\","
                        "\"credential\":\"PUBLIC.input\",\"profile_revision\":%u}}",
                        recover ? "recover" : "initial", kernels[side], revision);
                    ASSERT(n > 0 && (size_t)n < sizeof text);
                    json_free(&input); json_init(&input);
                    ASSERT(json_read(&input, text, (size_t)n));
                    memset(&st, 0, sizeof st);
                    st.accepted.datadir = "PUBLIC.accepted"; st.host_entropy = st.early = true;
                    ASSERT(tmb_owner_parse(&input, &st, &reply) == (revision == side+4));
                    ASSERT(!st.owner.manager && !st.owner.attempted && !st.owner.delivered);
                }
            }
        }
        PASS();
    } _test_next:;
    json_free(&input); json_free(&reply.data);
    return failures;
}

static int t_public_owner_combined_policy(void)
{
    int failures = 0;
    static struct mb_state st;
    static const char *const kernels[] = {
        "82d6598d9669339eb9890d9c8b5152597beac22cbfc5c86200a23f1dc2cd3562",
        "f7e7379fb08fd0035cf67bd98d5896376e103ab80851363d2c1f1a16a53e675d"
    };
    static const uint64_t length = 43412608;
    struct zcl_command_reply reply = {0};
    struct json_value input;
    json_init(&input);
    TEST("combined PUBLIC profiles bind exact image size and reject crossed image authority") {
        for (unsigned side = 0; side < 2; ++side) {
            struct vcs_guest_image_observation o = {0};
            memset(&st, 0, sizeof st);
            st.owner.enabled = st.accepted.public_observation = true;
            st.owner.profile_revision = side + 6;
            memset(st.accepted.root, 0x11, 32);
            ASSERT(zcl_hex_decode_lower(kernels[side], st.owner.authorized_kernel, 32));
            memcpy(o.image_sha256, st.owner.authorized_kernel, 32);
            o.image.bytes = length;
            ASSERT(tmb_owner_image_grant(&st, st.accepted.root, &o));
            o.image.bytes++;
            ASSERT(!tmb_owner_image_grant(&st, st.accepted.root, &o));
            o.image.bytes -= 2;
            ASSERT(!tmb_owner_image_grant(&st, st.accepted.root, &o));
            o.image.bytes = 43406744;
            ASSERT(!tmb_owner_image_grant(&st, st.accepted.root, &o));
            o.image.bytes = length;
            o.image_sha256[0] ^= 1;
            ASSERT(!tmb_owner_image_grant(&st, st.accepted.root, &o));
            o.image_sha256[0] ^= 1;
            for (unsigned revision = 1; revision <= 8; ++revision) {
                st.owner.profile_revision = revision;
                ASSERT(tmb_owner_image_grant(&st, st.accepted.root, &o) == (revision == side + 6));
            }
        }
        PASS();
    }
    TEST("combined PUBLIC parse accepts only its own explicit profile in INITIAL and RECOVER") {
        for (unsigned side = 0; side < 2; ++side) {
            for (unsigned revision = 2; revision <= 8; ++revision) {
                for (unsigned recover = 0; recover < 2; ++recover) {
                    char text[1200];
                    int n = snprintf(text, sizeof text,
                        "{\"public_unlock\":{\"policy\":\"public_keyfile_fixture\","
                        "\"purpose\":\"public_geli_keyfile\",\"receiver_revision\":1,"
                        "\"mode\":\"%s\",\"authorized_kernel_sha256\":\"%s\","
                        "\"volume\":\"PUBLIC.volume\",\"record\":\"PUBLIC.record\","
                        "\"credential\":\"PUBLIC.input\",\"profile_revision\":%u}}",
                        recover ? "recover" : "initial", kernels[side], revision);
                    ASSERT(n > 0 && (size_t)n < sizeof text);
                    json_free(&input); json_init(&input);
                    ASSERT(json_read(&input, text, (size_t)n));
                    memset(&st, 0, sizeof st);
                    st.accepted.datadir = "PUBLIC.accepted"; st.host_entropy = st.early = true;
                    ASSERT(tmb_owner_parse(&input, &st, &reply) == (revision == side + 6));
                    ASSERT(!st.owner.manager && !st.owner.attempted && !st.owner.delivered);
                }
            }
        }
        PASS();
    } _test_next:;
    json_free(&input); json_free(&reply.data);
    return failures;
}

static int tmb_combined_pc_commands(void)
{
    int failures=0;static struct mb_state st;
    TEST("combined profile uses actual PC intervals and INITIAL only preparation") {
        static const struct mb_pc_range ranges[]={
            {UINT64_C(0xffffffc0000cd668),UINT64_C(0xffffffc0000cf874),MB_PC_SHA256},
            {UINT64_C(0xffffffc0000cb254),UINT64_C(0xffffffc0000cb700),MB_PC_AES},
            {UINT64_C(0xffffffc0000cb700),UINT64_C(0xffffffc0000cbbac),MB_PC_AES},
            {UINT64_C(0xffffffc0002584fa),UINT64_C(0xffffffc00025887c),MB_PC_GELI_RUN},
            {UINT64_C(0xffffffc00025887c),UINT64_C(0xffffffc000258afa),MB_PC_GELI_WRITE},
            {UINT64_C(0xffffffc000258afa),UINT64_C(0xffffffc000258e52),MB_PC_GELI_READ},
            {UINT64_C(0xffffffc000261a68),UINT64_C(0xffffffc000261d48),MB_PC_BIO},
            {UINT64_C(0xffffffc0001a542e),UINT64_C(0xffffffc0001a54e0),MB_PC_VIRTQUEUE}
        };
        for (unsigned revision=6;revision<=7;revision++) {
        for(size_t i=0;i<sizeof ranges/sizeof ranges[0];i++) {
            ASSERT_EQ(mb_pc_bucket_profile(revision,ranges[i].lo),ranges[i].bucket);
            ASSERT_EQ(mb_pc_bucket_profile(revision,ranges[i].hi-1),ranges[i].bucket);
        }
        ASSERT_EQ(mb_pc_bucket_profile(revision,UINT64_C(0xffffffc0000cf874)),MB_PC_KERNEL_OTHER);
        ASSERT_EQ(mb_pc_bucket_profile(revision,UINT64_C(0xffffffc0005854dd)),MB_PC_KERNEL_OTHER);
        ASSERT_EQ(mb_pc_bucket_profile(revision,UINT64_C(0xffffffc0005854de)),MB_PC_UNKNOWN);
        ASSERT_EQ(mb_pc_bucket_profile(revision,UINT64_C(0xffffffc0026e1730)),MB_PC_KERNEL_OTHER);
        ASSERT_EQ(mb_pc_bucket_profile(revision,UINT64_C(0xffffffc0026e178f)),MB_PC_KERNEL_OTHER);
        ASSERT_EQ(mb_pc_bucket_profile(revision,UINT64_C(0xffffffc0026e1790)),MB_PC_UNKNOWN);
        ASSERT_EQ(mb_pc_bucket_profile(revision,UINT64_C(0xffffffc0026e0030)),MB_PC_UNKNOWN);
        ASSERT_EQ(mb_pc_bucket_profile(revision,UINT64_C(0x802cd668)),MB_PC_UNKNOWN);
        memset(&st,0,sizeof st);st.owner.profile_revision=revision;
        size_t step=6;
        ASSERT(strstr(mb_owner_command_text(&st,&step),"--public-initial-prepare")!=NULL);
        st.owner.recover=true;step=6;
        ASSERT(strstr(mb_owner_command_text(&st,&step),"--public-initial-prepare")==NULL);
        step=7;ASSERT(mb_owner_command_text(&st,&step)!=NULL);ASSERT_EQ(step,12u);
        }
        PASS();
    } _test_next:;
    return failures;
}
static int t_public_owner_v2_policy(void)
{
    int failures = t_public_owner_paired_policy();
    failures += t_public_owner_combined_policy();
    failures += tmb_combined_pc_commands();
    static struct mb_state st;
    struct zcl_command_reply reply = {0};
    struct json_value input;
    json_init(&input);
    const char *v5 = "f4cad5bba8ad562996b5bd781b3debb2286a910f5aae70014927c6aea1980d4d";
    const char *v6 = "db2440c0ce534decbac8aac94fade789c8978e5d145f1795fa216603a7404af5";
    const char *v1 = "2445a0ca747bb28eac52c8c2bb861ee9be06f3c7353587d88e3c3fcbb832b2f4";
    TEST("PUBLIC mounted identity requires explicit V2 profile and its exact new image") {
        for (unsigned recover = 0; recover < 2; recover++) {
        for (unsigned mode = 0; mode < 8; mode++) {
            char text[1200];
            const char *profile = mode == 1 ? "" : mode == 3 ?
                ",\"profile_revision\":1" : (mode == 4 || mode == 6) ?
                ",\"profile_revision\":3" : ",\"profile_revision\":2";
            int n = snprintf(text, sizeof text,
                "{\"public_unlock\":{\"policy\":\"public_keyfile_fixture\","
                "\"purpose\":\"public_geli_keyfile\",\"receiver_revision\":1,"
                "\"mode\":\"%s\",\"authorized_kernel_sha256\":\"%s\","
                "\"volume\":\"PUBLIC.volume\",\"record\":\"PUBLIC.record\","
                "\"credential\":\"PUBLIC.input\"%s}}", recover ? "recover" : "initial", mode >= 6 ?
                "ac1dd2f5260aa64d2ba9cf30c13927709ff7f427709571dd65521051cf44b57c" :
                mode == 2 ? v1 : mode == 5 ? v5 : v6, profile);
            ASSERT(n > 0 && (size_t)n < sizeof text);
            json_free(&input); json_init(&input);
            ASSERT(json_read(&input, text, (size_t)n));
            memset(&st, 0, sizeof st);
            st.accepted.datadir = "PUBLIC.accepted"; st.host_entropy = st.early = true;
            bool accepted = mode == 0 || mode == 6;
            ASSERT(tmb_owner_parse(&input, &st, &reply) == accepted);
            ASSERT(st.owner.enabled == accepted);
            ASSERT(!st.owner.manager && !st.owner.attempted && !st.owner.delivered);
        }
        }
        PASS();
    } _test_next:;
    json_free(&input); json_free(&reply.data);
    return failures;
}

static int t_public_owner_shell_prompt(void)
{
    int failures = 0;
    static struct mb_state st;
    static struct rvmachine machine;
    const char *prompt = "Enter full pathname";
    TEST("PUBLIC owner answers the single-user shell entry before health commands") {
        memset(&st, 0, sizeof st); memset(&machine, 0, sizeof machine);
        machine.conport_count = 5; machine.conports[4].generation = 7;
        machine.con.ports[4].generation = 9;
        machine.con.ports[4].host_open = machine.con.ports[4].guest_open = true;
        mb_owner_console(&st, &machine, 11, (const uint8_t *)prompt, 10);
        ASSERT(!st.owner.command_pending);
        mb_owner_console(&st, &machine, 11, (const uint8_t *)prompt + 10, strlen(prompt) - 10);
        ASSERT(st.owner.command_pending);
        ASSERT_EQ(st.owner.command_step, 0u);
        ASSERT(mb_owner_command(&st));
        ASSERT_EQ(st.owner.command_step, 1u);
        ASSERT_EQ(machine.firmware_in.count, 1u);
        ASSERT_EQ(machine.serial_in.count, 1u);
        ASSERT_EQ(machine.firmware_in.bytes[machine.firmware_in.head], '\n');
        ASSERT_EQ(machine.serial_in.bytes[machine.serial_in.head], '\n');
        ASSERT(!st.owner.command_pending);
        ASSERT(mb_owner_command(&st));
        ASSERT_EQ(machine.firmware_in.count, 1u);
        /* Simulate the shell consuming its UART view of the entry newline. */
        machine.serial_in.head = 1; machine.serial_in.count = 0;
        mb_owner_console(&st, &machine, 11, (const uint8_t *)"\r\n# ", 4);
        ASSERT(st.owner.command_pending);
        ASSERT(mb_owner_command(&st));
        ASSERT_EQ(st.owner.command_step, 2u);
        ASSERT(machine.firmware_in.count > 1u);
        ASSERT(!st.owner.health && !st.owner.ready && !st.owner.delivered);
        ASSERT(st.buf_len == 0 && st.tail_len == 0 && st.script.console_bytes == 0);
        /* Unqualified prompts and split provenance cannot advance entry. */
        memset(&st, 0, sizeof st);
        mb_owner_console(&st, &machine, 11, (const uint8_t *)"# ", 2);
        ASSERT(!st.owner.command_pending);
        mb_owner_console(&st, &machine, 11, (const uint8_t *)prompt, strlen(prompt));
        ASSERT(!st.owner.command_pending);
        memset(&st, 0, sizeof st);
        mb_owner_console(&st, &machine, 11, (const uint8_t *)prompt, 10);
        machine.con.ports[4].generation++;
        mb_owner_console(&st, &machine, 11, (const uint8_t *)prompt + 10, strlen(prompt) - 10);
        ASSERT(st.owner.failed && !st.owner.command_pending);
        memset(&st, 0, sizeof st);
        mb_owner_console(&st, &machine, 11, (const uint8_t *)prompt, 10);
        mb_owner_console(&st, &machine, 12, (const uint8_t *)prompt + 10, strlen(prompt) - 10);
        ASSERT(st.owner.failed && !st.owner.command_pending);
        PASS();
    } _test_next:;
    return failures;
}

static int t_public_owner_command_capacity(void)
{
    int failures = 0;
    static struct mb_state st;
    static struct rvmachine machine;
    TEST("PUBLIC command admission preserves unread bytes and refuses pending serial input") {
        for (unsigned mode = 0; mode < 5; mode++) {
            memset(&st, 0, sizeof st); memset(&machine, 0, sizeof machine);
            st.m = &machine; st.owner.command_pending = true;
            machine.firmware_in.count = mode == 0 ? RVMACHINE_INPUT_MAX - 1 :
                mode == 1 ? RVMACHINE_INPUT_MAX : mode == 2 ? RVMACHINE_INPUT_MAX + 1 : 0;
            machine.firmware_in.bytes[0] = 0x59;
            machine.serial_in.count = mode == 3 ? 1 : 0;
            machine.uart.rx_count = mode == 4 ? 1 : 0;
            struct rvmachine_input firmware = machine.firmware_in, serial = machine.serial_in;
            ASSERT(mb_owner_command(&st) == (mode == 0));
            if (mode == 0) {
                ASSERT_EQ(machine.firmware_in.count, RVMACHINE_INPUT_MAX);
                ASSERT_EQ(machine.firmware_in.bytes[0], 0x59);
                ASSERT_EQ(st.owner.command_step, 1u);
            } else {
                ASSERT(memcmp(&firmware, &machine.firmware_in, sizeof firmware) == 0);
                ASSERT(memcmp(&serial, &machine.serial_in, sizeof serial) == 0);
                ASSERT_EQ(st.owner.command_step, 0u);
                ASSERT(st.owner.command_pending);
            }
        }
        PASS();
    } _test_next:;
    return failures;
}

static int t_public_owner_observer(void)
{
    int failures = 0;
    static struct mb_state st;
    static struct rvmachine machine;
    const char *health = "PUBLIC_OWNER_HEALTH\r\n";
    const char *ready = "PUBLIC_BOOTSTRAP_RAW_READY\r\n";
    const char *child = "PUBLIC_BOOTSTRAP_CHILD delivered32=1 eof=1 reaped=1 timely=1 exited=1 status=0\r\n";
    TEST("PUBLIC internal observer binds complete lines and health to both current epochs without export") {
        memset(&st, 0, sizeof st); memset(&machine, 0, sizeof machine);
        machine.conport_count = 5; machine.conports[4].generation = 7;
        machine.con.ports[4].generation = 9;
        machine.con.ports[4].host_open = machine.con.ports[4].guest_open = true;
        st.early_given = 32;
        mb_owner_console(&st, &machine, 11, (const uint8_t *)health, strlen(health));
        mb_owner_console(&st, &machine, 11, (const uint8_t *)ready, strlen(ready));
        ASSERT(mb_owner_receiver_current(&st, &machine, 11, 7));
        ASSERT(!mb_owner_receiver_current(&st, &machine, 12, 7));
        ASSERT(!mb_owner_receiver_current(&st, &machine, 11, 8));
        mb_owner_console(&st, &machine, 11, (const uint8_t *)child, strlen(child));
        ASSERT(!st.owner.child); /* Console text cannot prove unperformed delivery. */
        st.owner.delivered = true;
        mb_owner_console(&st, &machine, 11, (const uint8_t *)child, strlen(child));
        ASSERT(st.owner.child);
        ASSERT(st.buf_len == 0 && st.tail_len == 0 && st.script.console_bytes == 0);
        for (size_t i = 0; i < sizeof st.owner.line; i++) ASSERT(st.owner.line[i] == 0);
        memset(&st, 0, sizeof st);
        mb_owner_console(&st, &machine, 11, (const uint8_t *)ready, 12);
        machine.con.ports[4].generation++;
        mb_owner_console(&st, &machine, 11, (const uint8_t *)ready + 12, strlen(ready) - 12);
        ASSERT(st.owner.failed && !st.owner.ready);
        ASSERT(st.owner.line_length == 0 && !st.owner.child && !st.owner.delivered);
        PASS();
    } _test_next:;
    return failures;
}

static void tmb_owner_files_close(struct mb_state *st)
{
    platform_private_file_close(&st->owner.credential);
    platform_private_file_close(&st->owner.record);
    platform_private_file_close(&st->owner.volume);
    free(st->owner.owned_credential_path); free(st->owner.owned_record_path);
    free(st->owner.owned_volume_path);
    memset(&st->owner, 0, sizeof st->owner);
}
static int t_public_owner_files(void)
{
    int failures = 0;
    struct tmb_dir d;
    static struct mb_state st;
    char volume[512], record[512], credential[512];
    TEST("PUBLIC owner initial is exclusive and recovery never creates missing state") {
        ASSERT(tmb_setup(&d, "tiny"));
        snprintf(volume, sizeof volume, "%s/PUBLIC-volume", d.dir);
        snprintf(record, sizeof record, "%s/PUBLIC-record", d.dir);
        snprintf(credential, sizeof credential, "%s/PUBLIC-input", d.dir);
        for (unsigned mode = 0; mode < 3; mode++) {
            memset(&st, 0, sizeof st);
            platform_private_file_init(&st.owner.volume);
            platform_private_file_init(&st.owner.record);
            platform_private_file_init(&st.owner.credential);
            st.owner.enabled = true; st.owner.recover = mode == 1;
            st.owner.volume_path = volume; st.owner.record_path = record;
            st.owner.credential_path = credential;
            if (mode == 0) {
                ASSERT(tmb_write(volume, "PUBLIC-original", 15));
                ASSERT(!mb_owner_files(&st));
                struct platform_positioned_file file;
                platform_positioned_file_init(&file);
                ASSERT(platform_positioned_file_open(&file, volume));
                uint8_t bytes[15];
                ASSERT_EQ(platform_positioned_file_read(&file, bytes, sizeof bytes, 0), (int64_t)sizeof bytes);
                ASSERT(memcmp(bytes, "PUBLIC-original", sizeof bytes) == 0);
                platform_positioned_file_close(&file);
                ASSERT(access(credential, F_OK) != 0);
                ASSERT(unlink(volume) == 0);
            } else if (mode == 1) {
                ASSERT(!mb_owner_files(&st));
                ASSERT(access(volume, F_OK) != 0 && access(record, F_OK) != 0 && access(credential, F_OK) != 0);
            } else {
                ASSERT(mb_owner_files(&st));
                ASSERT(st.owner.volume.locked && st.owner.credential.locked);
                ASSERT(mb_owner_keyfile_current(&st, &st.owner.credential));
                ASSERT(access(record, F_OK) != 0); /* No fabricated identity publication. */
                struct platform_positioned_file view = {.native = st.owner.credential.native};
                uint8_t bytes[32], extra = 0;
                ASSERT_EQ(platform_positioned_file_read(&view, bytes, sizeof bytes, 0), (int64_t)sizeof bytes);
                for (size_t i = 0; i < sizeof bytes; i++) ASSERT_EQ(bytes[i], (uint8_t)(i + 1));
                ASSERT_EQ(platform_positioned_file_read(&view, &extra, 1, 32), (int64_t)0);
                memory_cleanse(bytes, sizeof bytes);
            }
            ASSERT(st.owner.mutated == (mode == 2));
            struct zcl_command_reply refusal = {0};
            struct guest_service_snapshot snapshot = {
                .state = GUEST_STATE_FAILED, .last_failure = GUEST_REASON_STARTUP_DEADLINE
            };
            st.owner.command_step = 4;
            st.owner.last_retired = 123;
            ASSERT(!mb_owner_refusal(&st, &refusal, &snapshot));
            ASSERT(refusal.error.mutated == (mode == 2));
            ASSERT(strstr(refusal.error.current_state, "startup_deadline") != NULL);
            ASSERT(strstr(refusal.error.evidence, "step=4") != NULL);
            ASSERT(strstr(refusal.error.evidence, "work=123/0/0") != NULL);
            ASSERT(strstr(refusal.error.evidence, credential) == NULL);
            json_free(&refusal.data);
            tmb_owner_files_close(&st);
        }
        test_cleanup_tmpdir(d.dir);
        PASS();
    } _test_next:;
    tmb_owner_files_close(&st);
    return failures;
}

static const clock_iface_t *tmb_owner_real_clock;
static unsigned tmb_owner_clock_calls;
static int64_t tmb_owner_join_clock(void *context)
{
    (void)context;
    tmb_owner_clock_calls++;
    if (tmb_owner_clock_calls == 2) return -INT64_C(1000000000);
    return tmb_owner_real_clock->now_monotonic_ns(tmb_owner_real_clock->self);
}
static int64_t tmb_owner_join_wall(void *context)
{
    (void)context;
    return tmb_owner_real_clock->now_wall_ms(tmb_owner_real_clock->self);
}
static int t_public_owner_join(void)
{
    int failures = 0;
    struct tmb_dir d;
    static struct mb_state *st;
    static struct mb_state other;
    struct zcl_command_reply reply = {0}, refused = {0};
    static const clock_iface_t clock = {.now_monotonic_ns = tmb_owner_join_clock,
        .now_wall_ms = tmb_owner_join_wall};
    char volume[512], record[512], credential[512];
    TEST("called PUBLIC cleanup retains the real manager and complete heap capsule on measured join refusal") {
        ASSERT(tmb_setup(&d, "tiny"));
        st = zcl_calloc(1, sizeof *st, "PUBLIC cleanup fixture capsule");
        ASSERT(st != NULL);
        platform_private_file_init(&st->owner.volume);
        platform_private_file_init(&st->owner.record);
        platform_private_file_init(&st->owner.credential);
        snprintf(volume, sizeof volume, "%s/PUBLIC-volume", d.dir);
        snprintf(record, sizeof record, "%s/PUBLIC-record", d.dir);
        snprintf(credential, sizeof credential, "%s/PUBLIC-input", d.dir);
        st->owner.enabled = true; st->owner.volume_path = volume;
        st->owner.record_path = record; st->owner.credential_path = credential;
        ASSERT(mb_owner_files(st));
        st->accepted.length = 4;
        st->accepted.image = zcl_malloc(4, "PUBLIC native loop");
        ASSERT(st->accepted.image != NULL);
        memcpy(st->accepted.image, "\157\000\000\000", 4);
        /* Real legacy loop only for cleanup accounting, not receiver qualification. */
        struct mesh_guest_service_launch_config config = {
            .policy = MESH_GUEST_LAUNCH_EPHEMERAL_FIXTURE, .disk_mode = MESH_GUEST_DISK_NONE,
            .service = {.kernel = st->accepted.image, .kernel_length = 4,
                .binding = mb_owner_deny_peer, .binding_context = st,
                .machine = {.ram_bytes = UINT64_C(64) << 20, .wait_stops = true}}
        };
        config.service.limits = guest_limits_default();
        config.service.limits.slice_work = GUEST_GOV_SLICE_WORK_MIN;
        ASSERT(mesh_guest_service_manager_create(&st->owner.manager, &config));
        struct guest_action action;
        ASSERT(mesh_guest_service_manager_event(st->owner.manager,
            &(struct guest_event){.kind = GUEST_EV_ENABLE, .enable = true}, 0, &action));
        ASSERT(mesh_guest_service_manager_event(st->owner.manager,
            &(struct guest_event){.kind = GUEST_EV_OPERATOR_START}, 0, &action));
        struct guest_gov_decision decision;
        struct rvmachine_result result;
        ASSERT(mesh_guest_service_manager_drive(st->owner.manager, 1000, 1, &decision, &result) == RVMACHINE_OK);
        ASSERT(result.retired > 0);
        uint64_t instance = mesh_guest_service_manager_instance(st->owner.manager);
        ASSERT(instance != 0);
        ASSERT(!atomic_exchange(&mb_public_owner_busy, true)); st->owner.admitted = true;
        tmb_owner_real_clock = clock_default(); tmb_owner_clock_calls = 0;
        clock_set_default(&clock);
        ASSERT(!mb_owner_join(st, &reply));
        clock_set_default(tmb_owner_real_clock);
        ASSERT(tmb_owner_clock_calls >= 2);
        ASSERT(st->owner.retained && mb_public_owner_retained == st);
        ASSERT(st->owner.manager && mesh_guest_service_manager_instance(st->owner.manager) == instance);
        ASSERT(st->owner.credential.locked && st->owner.volume.locked);
        ASSERT(mb_owner_keyfile_current(st, &st->owner.credential));
        ASSERT(memcmp(st->accepted.image, "\157\000\000\000", 4) == 0);
        ASSERT_STR_EQ(reply.error.code, "PUBLIC_OWNER_CLEANUP_UNOBSERVED");
        memset(&other, 0, sizeof other);
        ASSERT(!tmb_owner_called(&other, &refused));
        ASSERT_STR_EQ(refused.error.code, "PUBLIC_OWNER_BUSY");
        ASSERT(!other.owner.admitted && !other.owner.manager && !other.owner.owned_credential_path);
        ASSERT(mb_owner_join(st, &reply));
        ASSERT(st->owner.manager == NULL && st->m == NULL);
        st->owner.retained = false; mb_public_owner_retained = NULL;
        ASSERT(tmb_owner_dispose(st));
        memory_cleanse(st->accepted.image, st->accepted.length); free(st->accepted.image);
        free(st); st = NULL;
        ASSERT(!atomic_load(&mb_public_owner_busy));
        test_cleanup_tmpdir(d.dir);
        PASS();
    } _test_next:;
    if (tmb_owner_real_clock) clock_set_default(tmb_owner_real_clock);
    if (st) {
        if (!mb_owner_join(st, &reply)) return failures + 1; /* Keep actual live heap ownership. */
        st->owner.retained = false; mb_public_owner_retained = NULL;
        (void)tmb_owner_dispose(st);
        if (st->accepted.image) memory_cleanse(st->accepted.image, st->accepted.length);
        free(st->accepted.image); free(st); st = NULL;
    }
    json_free(&reply.data); json_free(&refused.data);
    return failures;
}

/* Input-boundary controls: presence of a called owner must refuse these
 * combinations BEFORE data parsing, image opening or private provisioning.
 * Empty owner objects intentionally test the earlier combination guard, not
 * later owner validation or protected image admission. */
static int tmb_called_owner_combinations(void)
{
    int failures=0;
    TEST("called unlock owners and mixed builtin selectors refuse before data entry or host RNG") {
        static const char *const inputs[]={
            "{\"builtin_kernel\":true,\"public_kernel\":{}}",
            "{\"builtin_kernel\":true,\"protected_kernel\":{}}",
            "{\"builtin_kernel\":true,\"public_unlock\":{}}",
            "{\"builtin_kernel\":true,\"protected_unlock\":{}}",
            "{\"kernel\":\"test-tmp/not-opened\",\"public_unlock\":{},\"data_disk\":\"test\"}",
            "{\"kernel\":\"test-tmp/not-opened\",\"protected_unlock\":{},\"data_disk\":\"test\"}",
            "{\"kernel\":\"test-tmp/not-opened\",\"public_unlock\":{},\"home\":\"test-tmp/not-opened\"}",
            "{\"kernel\":\"test-tmp/not-opened\",\"protected_unlock\":{},\"home\":\"test-tmp/not-opened\"}"
        };
        for(size_t i=0;i<sizeof inputs/sizeof inputs[0];i++){
            struct tmb_call c;tmb_data_parse_calls=0;unsigned rng_before=tmb_host_calls;
            bool ran=tmb_go(&c,mbtwin_handle,inputs[i]);
            bool refused=ran&&tmb_failed(&c,i==4?"DATA_DISK_NOT_AVAILABLE":"INVALID_INPUT")&&c.exit_code==ZCL_COMMAND_EXIT_INVALID;
            bool reason=strcmp(tmb_error(&c,"message"),i<2?
                "exactly one of kernel, accepted_kernel, public_kernel, protected_kernel or builtin_kernel is required":
                i==2?"PUBLIC unlock requires an installed or fixed PUBLIC image and host seed with no public export or script options":
                i==4?"data_disk is not attached under the PUBLIC owner":
                "called unlock owners refuse builtin_kernel, data_disk and home")==0;
            tmb_end(&c);
            ASSERT(refused);ASSERT(reason);ASSERT_EQ(tmb_data_parse_calls,0u);
            ASSERT_EQ(tmb_host_calls,rng_before);
        }
        PASS();
    } _test_next:;
    return failures;
}
int test_dev_machine_boot(void);
/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0 */
/* PUBLIC memory fixture for actual virtio descriptor accounting. No manager
 * admission/provider commit is supplied by this fixture. */
struct tmb_protected_ring { uint8_t bytes[8192]; };
static size_t tmb_pr_sink(void *ctx,uint32_t port,const uint8_t *bytes,size_t n)
{(void)ctx;(void)port;(void)bytes;(void)n;return 0;}
static bool tmb_pr_read(void *ctx,uint64_t a,void *out,size_t n)
{
    struct tmb_protected_ring *r=ctx;
    if(a>sizeof r->bytes||n>sizeof r->bytes-(size_t)a)return false;
    memcpy(out,r->bytes+(size_t)a,n);return true;
}
static bool tmb_pr_write(void *ctx,uint64_t a,const void *in,size_t n)
{
    struct tmb_protected_ring *r=ctx;
    if(a>sizeof r->bytes||n>sizeof r->bytes-(size_t)a)return false;
    memcpy(r->bytes+(size_t)a,in,n);return true;
}
static void tmb_pr_queue(struct rvvirtio_dev *d,unsigned q,uint32_t base)
{
    rvvirtio_mmio_write(d,RVVIRTIO_REG_QUEUE_SEL,q);
    rvvirtio_mmio_write(d,RVVIRTIO_REG_QUEUE_NUM,16);
    rvvirtio_mmio_write(d,RVVIRTIO_REG_QUEUE_DESC_LOW,base);
    rvvirtio_mmio_write(d,RVVIRTIO_REG_QUEUE_DESC_HIGH,0);
    rvvirtio_mmio_write(d,RVVIRTIO_REG_QUEUE_DRIVER_LOW,base+512);
    rvvirtio_mmio_write(d,RVVIRTIO_REG_QUEUE_DRIVER_HIGH,0);
    rvvirtio_mmio_write(d,RVVIRTIO_REG_QUEUE_DEVICE_LOW,base+1024);
    rvvirtio_mmio_write(d,RVVIRTIO_REG_QUEUE_DEVICE_HIGH,0);
    rvvirtio_mmio_write(d,RVVIRTIO_REG_QUEUE_READY,1);
}
static void tmb_pr_post(struct tmb_protected_ring *r,uint32_t base,uint32_t n,bool write)
{
    zcl_write_u64_le(r->bytes+base,base+1536);
    zcl_write_u32_le(r->bytes+base+8,n);
    zcl_write_u16_le(r->bytes+base+12,write?2:0);
    zcl_write_u16_le(r->bytes+base+14,0);
    uint8_t *a=r->bytes+base+512;
    uint16_t pos=zcl_read_u16_le(a+2);
    zcl_write_u16_le(a+4+2*(pos%16),0);
    zcl_write_u16_le(a+2,(uint16_t)(pos+1));
}
static void tmb_pr_control(struct rvmachine *m,struct tmb_protected_ring *r,
    unsigned port,unsigned event,unsigned value)
{
    uint8_t *b=r->bytes+1536;
    zcl_write_u32_le(b,port);zcl_write_u16_le(b+4,(uint16_t)event);
    zcl_write_u16_le(b+6,(uint16_t)value);
    tmb_pr_post(r,0,8,false);
    rvvirtio_mmio_write(&m->con.dev,RVVIRTIO_REG_QUEUE_NOTIFY,3);
}
static bool tmb_pr_init(struct rvmachine *m,struct tmb_protected_ring *r)
{
    memset(r,0,sizeof *r);
    struct rvvirtio_mem mem={.ctx=r,.read=tmb_pr_read,.write=tmb_pr_write};
    struct rvvirtio_console_ops ops={.from_guest=tmb_pr_sink};
    if(!rvvirtio_console_init(&m->con,&mem,&ops,5))return false;
    struct rvvirtio_dev *d=&m->con.dev;
    rvvirtio_mmio_write(d,RVVIRTIO_REG_STATUS,1);
    rvvirtio_mmio_write(d,RVVIRTIO_REG_STATUS,3);
    rvvirtio_mmio_write(d,RVVIRTIO_REG_DRIVER_FEATURES_SEL,0);
    rvvirtio_mmio_write(d,RVVIRTIO_REG_DRIVER_FEATURES,2);
    rvvirtio_mmio_write(d,RVVIRTIO_REG_DRIVER_FEATURES_SEL,1);
    rvvirtio_mmio_write(d,RVVIRTIO_REG_DRIVER_FEATURES,1);
    rvvirtio_mmio_write(d,RVVIRTIO_REG_STATUS,11);
    tmb_pr_queue(d,3,0);tmb_pr_queue(d,10,4096);
    rvvirtio_mmio_write(d,RVVIRTIO_REG_STATUS,15);
    if(!rvvirtio_console_port_open(&m->con,4,"z23.protected.bootstrap.v1"))return false;
    tmb_pr_control(m,r,0,0,1);tmb_pr_control(m,r,4,3,1);
    tmb_pr_control(m,r,4,6,1);
    return m->con.ports[4].guest_open;
}
static int tmb_protected_real_ring_controls(void)
{
    int failures=0;static struct rvmachine m;static struct tmb_protected_ring r;
    static const uint8_t public_sentinel[32]={0x51};
    TEST("protected proof fixture accounts actual RX repost after normal guest close") {
        memset(&m,0,sizeof m);m.conport_count=5;ASSERT(tmb_pr_init(&m,&r));
        tmb_pr_post(&r,4096,32,true);
        ASSERT_EQ(rvvirtio_console_port_write(&m.con,4,public_sentinel,32),32u);
        ASSERT_EQ(m.con.ports[4].consumed,0u);
        ASSERT_EQ(rvmachine_conport_consumed(&m,4),0u);
        uint32_t epoch=m.con.ports[4].generation;
        tmb_pr_post(&r,4096,32,true);
        tmb_pr_control(&m,&r,4,6,0);
        ASSERT(!m.con.ports[4].guest_open);
        ASSERT_EQ(m.con.ports[4].generation,epoch);
        ASSERT_EQ(m.con.ports[4].consumed,0u);
        ASSERT_EQ(rvmachine_conport_consumed(&m,4),32u);
        ASSERT_EQ(rvmachine_conport_consumed(&m,4),32u);PASS();
    } _test_next:;
    return failures;
}
struct tmb_protected_case { struct mb_state st;struct rvmachine machine;struct mb_protected_child_observation p; };
static const char tmb_pc_ready[]="PROTECTED_V1_RECEIVER_READY\r\n";
static const char tmb_pc_init[]="PROTECTED_V1_CHILD phase=init delivered32=1 eof=1 reaped=1 timely=1 exited=1 status=0\r\n";
static const char tmb_pc_attach[]="PROTECTED_V1_CHILD phase=attach delivered32=1 eof=1 reaped=1 timely=1 exited=1 status=0\r\n";
static const char tmb_pc_final[]="PROTECTED_V1_ATTACH_EXACT32\r\n";
static bool tmb_protected_setup(struct tmb_protected_case *f,bool recover)
{
    memset(f,0,sizeof *f);f->st.m=&f->machine;f->st.owner.recover=recover;f->st.owner.command_step=7;
    f->machine.conport_count=5;f->machine.conports[4].generation=7;
    f->machine.con.dev.status=RVVIRTIO_STATUS_DRIVER_OK;
    f->machine.conports[4].seen_generation=9;f->machine.conports[4].private_keyfile=true;
    struct rvvirtio_console_port *port=&f->machine.con.ports[4];
    static const char name[]="z23.protected.bootstrap.v1";
    memcpy(port->name,name,sizeof name);port->name_len=sizeof name-1;port->generation=9;
    port->host_open=port->guest_open=true;f->p.consumer=MB_CHILD_PROTECTED_V1;f->p.image_bound=true;
    return zcl_hex_decode("194bd9c2977dcab3c340472d10f8291c266bdc6fff463d0223f130886c396c4e",f->p.helper_sha256,32)&&
        mb_command_begin(&f->st.owner.command,6,11,7,9);
}
static bool tmb_protected_line(struct tmb_protected_case *f,const char *line,
    const struct rvmachine *m,uint64_t instance,uint32_t host,uint32_t device)
{
    size_t n=strlen(line);if(n>=sizeof f->st.owner.line)return false;
    memcpy(f->st.owner.line,line,n+1);f->st.owner.line_length=n;
    return mb_owner_protected_child_line(&f->st,&f->p,m,instance,host,device);
}
static bool tmb_protected_pending_ring(struct tmb_protected_case *f,
    struct tmb_protected_ring *ring,unsigned n,bool recover,bool next)
{
    static const uint8_t sentinel[33]={0x51};
    if(!tmb_protected_setup(f,recover)||!tmb_pr_init(&f->machine,ring))return false;
    f->machine.conports[4].seen_generation=1;
    memset(&f->st.owner.command,0,sizeof f->st.owner.command);
    if(!mb_command_begin(&f->st.owner.command,6,11,7,1))return false;
    if(!tmb_protected_line(f,tmb_pc_ready,&f->machine,11,7,1))return false;
    f->p.delivered=true;f->p.delivery_instance=11;f->p.delivery_host_epoch=7;f->p.delivery_device_epoch=1;
    f->machine.conports[4].private_sealed=true;
    if(n){
        tmb_pr_post(ring,4096,n,true);
        if(rvvirtio_console_port_write(&f->machine.con,4,sentinel,n)!=n)return false;
        tmb_pr_post(ring,4096,n,true);
    }
    tmb_pr_control(&f->machine,ring,4,6,0);
    if(!recover&&!tmb_protected_line(f,tmb_pc_init,&f->machine,11,7,1))return false;
    return tmb_protected_line(f,tmb_pc_attach,&f->machine,11,7,1)&&
        tmb_protected_line(f,tmb_pc_final,&f->machine,11,7,1)&&
        tmb_protected_line(f,"PROTECTED_V1_RC:6:0\r\n",&f->machine,11,7,1)&&
        (!next||tmb_protected_line(f,"PROTECTED_V1_NEXT\r\n",&f->machine,11,7,1));
}
/* Actual parser/ring mechanism only: readiness/delivery metadata is modeled,
 * not a provider commit, credential or accepted protected guest invocation. */
static int tmb_protected_returned_fragment_controls(void)
{
    int failures=0;static struct tmb_protected_case f;static struct tmb_protected_ring ring;
    TEST("protected parser returned boundary: RC before later NEXT gives no early credit") {
        ASSERT(tmb_protected_pending_ring(&f,&ring,32,false,false));
        ASSERT(mb_owner_protected_phase6_finish(&f.st,&f.p,&f.machine,11,7,1));
        ASSERT(!f.p.phase6_accepted&&!f.st.owner.command_pending&&!f.st.owner.command.rc_seen);
        ASSERT(tmb_protected_line(&f,"PROTECTED_V1_NEXT\r\n",&f.machine,11,7,1));
        ASSERT(mb_owner_protected_phase6_finish(&f.st,&f.p,&f.machine,11,7,1));
        ASSERT(f.p.phase6_accepted&&f.p.consumed_verified&&f.st.owner.command_pending);
        ASSERT_EQ(rvmachine_conport_consumed(&f.machine,4),32u);PASS();
    } _test_next:;
    return failures;
}
static int tmb_protected_returned_refusals(void)
{
    int failures=0;static struct tmb_protected_case f;static struct tmb_protected_ring ring;
    static const unsigned counts[]={0,31,33};
    TEST("protected parser returned boundary: actual wrong consumption and revoked delivery refuse sticky") {
        for(size_t i=0;i<sizeof counts/sizeof counts[0];i++){
            ASSERT(tmb_protected_pending_ring(&f,&ring,counts[i],false,true));
            ASSERT(!mb_owner_protected_phase6_finish(&f.st,&f.p,&f.machine,11,7,1));
            ASSERT(f.st.owner.failed&&!f.st.owner.command_pending);
        }
        ASSERT(tmb_protected_pending_ring(&f,&ring,32,false,true));f.p.delivered=false;
        ASSERT(!mb_owner_protected_phase6_finish(&f.st,&f.p,&f.machine,11,7,1));
        f.p.delivered=true;
        ASSERT(!mb_owner_protected_phase6_finish(&f.st,&f.p,&f.machine,11,7,1));
        ASSERT(f.st.owner.failed&&!f.st.owner.command_pending);PASS();
    } _test_next:;
    return failures;
}
/* Explicit post-admission PUBLIC metadata model, not an image/provider grant.
 * Real owner clock helper and actual native grant predicate; no fake true
 * callback, keyfile, provider read, guest execution or image override. */
static int64_t tmb_prepare_clock_ms;
static int64_t tmb_prepare_clock_ns(void *context)
{(void)context;return tmb_prepare_clock_ms*INT64_C(1000000);}
static int64_t tmb_prepare_wall_ms(void *context)
{(void)context;return 0;}
static const clock_iface_t tmb_prepare_clock={
    .now_monotonic_ns=tmb_prepare_clock_ns,.now_wall_ms=tmb_prepare_wall_ms};
static void tmb_prepare_grant_model(struct mb_state *st,struct mb_protected_owner *p)
{
    memset(st,0,sizeof(*st));memset(p,0,sizeof(*p));st->owner.protected=p;
    p->grant_live=true;p->admitted_ms=950;p->last_decision=950;
    p->delivery_deadline_ms=2000;p->authority_expires_ms=3000;
    p->grant.generation=1;p->grant.volume_bytes=UINT64_C(16)<<20;
    p->grant.owner_grant[0]=0x51;
}
static int tmb_postprepare_fresh_clock(void)
{
    int failures=0;
    TEST("protected owner refreshes post-prepare time before real generation grant") {
        struct mb_state st;struct mb_protected_owner p;tmb_prepare_grant_model(&st,&p);
        const clock_iface_t *saved=clock_default();tmb_prepare_clock_ms=1000;
        clock_set_default(&tmb_prepare_clock);
        bool stale=mb_protected_grant_current(&st,&p.grant,900);
        uint64_t start=0;bool fresh=mb_owner_postprepare_time(&st,900,&start);
        bool actual=fresh&&mb_protected_grant_current(&st,&p.grant,start);
        clock_set_default(saved);
        ASSERT(!stale);ASSERT(fresh);ASSERT_EQ(start,UINT64_C(1000));ASSERT(actual);
        ASSERT_EQ(p.admitted_ms,UINT64_C(950));
        ASSERT_EQ(p.delivery_deadline_ms,UINT64_C(2000));
        ASSERT_EQ(p.authority_expires_ms,UINT64_C(3000));PASS();
    } _test_next:;
    return failures;
}
static int tmb_postprepare_clock_refusals(void)
{
    int failures=0;
    TEST("protected post-prepare clock rollback missing expiry and revoked grant refuse") {
        static const int64_t times[]={0,899,949,2000,3000,1000,1000};
        for(size_t i=0;i<sizeof times/sizeof times[0];i++){
            struct mb_state st;struct mb_protected_owner p;tmb_prepare_grant_model(&st,&p);
            if(i==5)p.grant_live=false;
            if(i==6)p.last_decision=1001;
            const clock_iface_t *saved=clock_default();tmb_prepare_clock_ms=times[i];
            clock_set_default(&tmb_prepare_clock);
            uint64_t start=99;bool accepted=mb_owner_postprepare_time(&st,900,&start);
            clock_set_default(saved);
            ASSERT(!accepted);ASSERT_EQ(start,UINT64_C(0));
            ASSERT_EQ(p.delivery_deadline_ms,UINT64_C(2000));
            ASSERT_EQ(p.authority_expires_ms,UINT64_C(3000));
        }
        PASS();
    } _test_next:;
    return failures;
}

/* PUBLIC metadata model; actual shared trace, production completion predicate
 * and refusal formatter. No guest/provider admission or fake manager calls. */
static int tmb_protected_work_completion(void)
{
    int failures=0;static struct mb_state st;static struct mb_protected_owner p;
    TEST("protected work: enqueue is not format completion and historical upper bound survives no machine") {
        memset(&st,0,sizeof st);memset(&p,0,sizeof p);st.owner.protected=&p;
        st.owner.authorized_kernel[0]=0x51;st.accepted.root[0]=0x52;
        char early[96];mb_protected_work_summary(&st,early);
        ASSERT(strstr(early,"format_dispatch=unknown format_return=unknown"));
        p.trace_bound=true;memcpy(p.trace_kernel,st.owner.authorized_kernel,32);
        memcpy(p.trace_root,st.accepted.root,32);
        st.owner.command_step=8;st.owner.command.phase=7;p.newfs_done=true;
        ASSERT(!mb_protected_format_command_completed(&st));
        st.owner.command.rc_seen=true;ASSERT(!mb_protected_format_command_completed(&st));
        st.owner.command.next_seen=true;ASSERT(mb_protected_format_command_completed(&st));
        st.owner.phase_dispatch[7]=(struct mb_v3_dispatch){.seen=true,.valid=true,.work=100};
        st.owner.phase_dispatch[8]=(struct mb_v3_dispatch){.seen=true,.valid=true,.work=300};
        st.owner.command_step=9;
        ASSERT(!mb_protected_format_command_completed(&st));
        mb_protected_format_observe(&st,true);
        struct zcl_command_reply reply;zcl_command_reply_init(&reply,"zcl.dev_machine_boot.v1");
        bool refused=mb_owner_refusal(&st,&reply,NULL);
        bool correct=strstr(reply.error.evidence,"phase=8 format_dispatch=100 format_return=300")!=NULL;
        zcl_command_reply_free(&reply);
        ASSERT(!refused);ASSERT(correct);ASSERT(p.format_completed);ASSERT(!st.m);
        st.accepted.root[0]^=1;char changed[96];mb_protected_work_summary(&st,changed);
        ASSERT(strstr(changed,"format_dispatch=unavailable format_return=unavailable"));
        st.accepted.root[0]^=1;
        ASSERT(p.trace_invalid);char summary[96];mb_protected_work_summary(&st,summary);
        ASSERT(strstr(summary,"format_dispatch=unavailable format_return=unavailable"));
        PASS();
    } _test_next:;
    return failures;
}
static int tmb_protected_work_origin(void)
{
    int failures=0;static struct rvmachine machine;
    TEST("protected work: actual result no-run and stale tuple cannot earn a dispatch boundary") {
        struct mb_pc_context before={.machine=&machine,.instance=11,.host_epoch=7,.device_epoch=9,
            .retired=100,.valid=true},after=before;after.retired=200;
        struct guest_gov_decision decision={.kind=GUEST_GOV_RUN_SLICE};
        struct mb_v3_dispatch origin={0},trace[17]={0};uint32_t attempted=0;
        mb_trace_actual_result_observe(&origin,&before,&after,&decision,RVMACHINE_OK,
            &(struct rvmachine_result){0});ASSERT(!origin.seen);
        mb_trace_dispatch_observe(trace,&attempted,7,8,&origin,&after);ASSERT(!trace[7].seen);
        attempted=0;
        mb_trace_actual_result_observe(&origin,&before,&after,&decision,RVMACHINE_OK,
            &(struct rvmachine_result){.retired=200});ASSERT(origin.valid);
        struct mb_pc_context stale=after;stale.device_epoch++;
        mb_trace_dispatch_observe(trace,&attempted,7,8,&origin,&stale);
        ASSERT(trace[7].seen&&!trace[7].valid);
        mb_trace_dispatch_observe(trace,&attempted,7,8,&origin,&after);ASSERT(!trace[7].valid);
        memset(trace,0,sizeof trace);attempted=0;
        mb_trace_dispatch_observe(trace,&attempted,7,8,&origin,&after);ASSERT(trace[7].valid);
        decision.kind=GUEST_GOV_SLEEP;memset(&origin,0,sizeof origin);
        mb_trace_actual_result_observe(&origin,&before,&after,&decision,RVMACHINE_OK,
            &(struct rvmachine_result){.retired=200});ASSERT(!origin.seen);
        PASS();
    } _test_next:;
    return failures;
}
int test_dev_machine_boot(void)
{
    return tmb_protected_work_completion()+tmb_protected_work_origin()+tmb_called_owner_combinations()+tmb_postprepare_fresh_clock()+tmb_postprepare_clock_refusals()+tmb_protected_real_ring_controls()+tmb_protected_returned_fragment_controls()+tmb_protected_returned_refusals()+tmb_provision_controls()+tmb_provision_fault_controls()+t_protected_identity_comment()+t_protected_identity_wrong_comment()+t_public_v3_newfs_done() + t_public_v3_prepare_marker() + t_public_v2_command_table() + t_public_v2_command_observer() + t_public_v2_command_identity_phases() + t_public_owner_command_capacity() + t_public_identity_parser() + t_public_identity_observer() + t_public_owner_v2_policy() + t_public_owner_shell_prompt() + t_public_image_policy() + t_public_owner_join() + t_public_owner_files() + t_public_owner_policy() + t_public_owner_observer() + t_accepted_kernel() + t_accepted_wrong_arch() + t_private_public_capture() + t_private_volume_path_replacement() + t_private_volume_restart() + t_private_volume_refusals() + t_private_volume_flush_failure() + t_host_failure_state_bound() + t_host_work_budget() + t_host_early_seed() + t_host_entropy_run() + t_host_entropy_callbacks() + t_port_atomic_budget() + t_port_alias_and_limit() + t_port_hard_failure() + t_port_ready_epoch() + t_port_ready_line() + t_port_negative_bytes() + t_port_guest_bytes() + t_port_goal_refused() + t_receipt() + t_script() + t_goal_missed() + t_fault() +
           t_transcript_rules() + t_input_files() + t_during_run() +
           t_console_limit() + t_input_rules() + t_entropy_seed() + t_early_seed() +
           t_early_seed_refused() + t_command_row() + t_fetch_cache();
}
#endif /* !defined(_WIN32) */
