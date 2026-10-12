/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tests for the hot-swap IMAGE COMMIT (which module image is live for a
 * source and which superseded mapping may be released) and the depth-1
 * rollback SHELF built on it (hotswap/hotswap_shelf.h).
 *
 * The race: a swap is two steps. hotswap_module_publish() makes the
 * registry dispatch into the new image and assigns a generation; the
 * loader then records the image against its source and retires the
 * previous one. Publish runs resident callbacks, so it holds no loader
 * lock, and two activations of one source can publish in one order and
 * commit in the other. The loser hands the WINNER's image to the retire
 * path; drain-only quiescence cannot see it (the ACTIVE snapshot is
 * skipped by design), so the live image's code would be unmapped.
 *
 * Determinism without instrumenting production: the registry commit
 * callback is a caller-supplied hook (see test_hotswap_module_v2.c and
 * zcl_native_hotswap_publish_hooks()). This file's hook parks the slow
 * publisher right after zcl_command_registry_replace_batch() returns and
 * its generation is read, and releases it once the fast publisher has
 * completed both steps.
 *
 * Driven for real: the hotswap_module_publish() gauntlet (admit -> probe ->
 * ONE batch commit) into the real kernel command-registry override layer,
 * lock-free snapshots, refcount drain, zcl_command_registry_execute_json()
 * dispatch from other threads, and hotswap_commit_image(). Not real: dlopen.
 * An "image" is a test-owned token and the unmap seam is a test observer
 * that can ask, at the instant of unmap, whether the live snapshot still
 * resolves a leaf to that image.
 *
 * Unverified here: a real dlopen'd .so being unmapped; rollback COMPLETING
 * (it needs the dev datadir, -hotswap-activate and ZCL_HOTSWAP_ACTIVATE=1),
 * so every rollback is driven to a refusal, proving its claim, shelf
 * accounting and descriptor discipline; and the rollback toggle.
 */

#include "test/test_helpers.h"

#include "hotswap/hotswap.h"
#include "hotswap/hotswap_module.h"
#include "hotswap/hotswap_retire_blocker.h"
#include "hotswap/hotswap_shelf.h"
#include "platform/os_proc.h"
#include "kernel/command_registry.h"
#include "json/json.h"
#include "util/blocker.h"

#include <fcntl.h>
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* The status controller row of engine/composition/hotswap_swappable.def
 * (probe leaf core.status in hotswap_eligible.def). Both leaves below are
 * on that row, so hotswap_module_admit() accepts them. */
#define SHELF_TU      "engine/controllers/src/status_native_handlers.c"
#define LEAF_PROBE    "core.status"
#define LEAF_SECOND   "core.sync.diagnose"
/* A different allowlisted row, touched by nothing here. */
#define SHELF_TU_META "engine/controllers/src/meta_native_handlers.c"
/* Never allowlisted at all (a consensus TU). */
#define SHELF_TU_UNKNOWN "lib/consensus/src/pow.c"

/* ── The image pool ───────────────────────────────────────────────────────
 * One handler per image, never shared, so a dispatch can say WHICH image
 * it landed in. `unmapped` is set by the unmap seam; a handler running
 * with it set is a dispatch into released code. */
#define IMG_MAX 16

struct img {
    _Atomic bool unmapped;
    _Atomic int  inflight;
    uint32_t     generation;
    uint32_t     leaf_count;
    const char  *leaf[2];
    zcl_command_handler_fn fn;
    int          fd;
};
static struct img g_img[IMG_MAX];
static _Atomic uint64_t g_dispatch_into_unmapped;
static _Atomic uint64_t g_unmap_calls;
/* The unmap seam saw the live snapshot still resolving a leaf to this
 * image's handler: the race caught in the act. */
static _Atomic uint64_t g_unmap_of_live_image;
/* The unmap seam saw a dispatch still inside a handler of an image that is
 * not live for any leaf: the drain gate failing. */
static _Atomic uint64_t g_unmap_with_dispatch_inside;

#define IMG_HANDLER(i)                                                       \
static void h_img##i(const struct zcl_command_request *rq,                   \
                     struct zcl_command_reply *rp)                           \
{                                                                            \
    (void)rq;                                                                \
    struct img *im = &g_img[i];                                              \
    atomic_fetch_add(&im->inflight, 1);                                      \
    if (atomic_load(&im->unmapped))                                          \
        atomic_fetch_add(&g_dispatch_into_unmapped, 1);                      \
    (void)json_push_kv_str(&rp->data, "who", "img" #i);                      \
    atomic_fetch_sub(&im->inflight, 1);                                      \
}

IMG_HANDLER(0)  IMG_HANDLER(1)  IMG_HANDLER(2)  IMG_HANDLER(3)
IMG_HANDLER(4)  IMG_HANDLER(5)  IMG_HANDLER(6)  IMG_HANDLER(7)
IMG_HANDLER(8)  IMG_HANDLER(9)  IMG_HANDLER(10) IMG_HANDLER(11)
IMG_HANDLER(12) IMG_HANDLER(13) IMG_HANDLER(14) IMG_HANDLER(15)

static const zcl_command_handler_fn k_img_fn[IMG_MAX] = {
    h_img0,  h_img1,  h_img2,  h_img3,  h_img4,  h_img5,  h_img6,  h_img7,
    h_img8,  h_img9,  h_img10, h_img11, h_img12, h_img13, h_img14, h_img15,
};

/* ── A registry the override layer can validate against ──────────────────
 * The override commit re-checks READY + read-only + resolvable, so the
 * bound registry carries the real leaf paths. */
static void h_resident(const struct zcl_command_request *rq,
                       struct zcl_command_reply *rp)
{
    (void)rq;
    (void)json_push_kv_str(&rp->data, "who", "resident");
}

static const struct zcl_command_spec g_specs[] = {
    { .path = LEAF_PROBE, .summary = "swappable read leaf",
      .layer = ZCL_COMMAND_LAYER_CORE, .effect = ZCL_COMMAND_EFFECT_READ,
      .availability = ZCL_COMMAND_READY, .mode = ZCL_COMMAND_MODE_SYNC,
      .allowed_lanes = ZCL_COMMAND_LANE_LOCAL,
      .output_schema = "zcl.core_status.v2", .handler = h_resident },
    { .path = LEAF_SECOND, .summary = "swappable read leaf",
      .layer = ZCL_COMMAND_LAYER_CORE, .effect = ZCL_COMMAND_EFFECT_READ,
      .availability = ZCL_COMMAND_READY, .mode = ZCL_COMMAND_MODE_SYNC,
      .allowed_lanes = ZCL_COMMAND_LANE_LOCAL,
      .output_schema = "zcl.sync_diagnose.v1", .handler = h_resident },
};
static const struct zcl_command_registry g_reg = {
    .commands = g_specs,
    .count = sizeof(g_specs) / sizeof(g_specs[0]),
};

static const struct zcl_command_spec *find_spec(const char *path)
{
    for (size_t i = 0; i < g_reg.count; i++)
        if (strcmp(g_reg.commands[i].path, path) == 0)
            return &g_reg.commands[i];
    return NULL;
}

/* Dispatch a leaf through the real registry entry point, so the override
 * snapshot is acquired and released as in the node. */
static enum zcl_command_exit exec_path(const char *path, char *out,
                                       size_t out_size)
{
    const struct zcl_command_spec *spec = find_spec(path);
    struct json_value input;
    json_init(&input);
    json_set_object(&input);
    enum zcl_command_exit exit_code = ZCL_COMMAND_EXIT_INTERNAL;
    (void)zcl_command_registry_execute_json(&g_reg, spec, NULL, &input, false,
                                            path, "normal", 0, 0, NULL, out,
                                            out_size, &exit_code);
    json_free(&input);
    return exit_code;
}

/* ── The unmap seam: the oracle ──────────────────────────────────────────
 * Called by the retire path when it decides a mapping may be released;
 * asking the registry here makes a wrong decision observable. */
static bool handler_is_live_anywhere(zcl_command_handler_fn fn)
{
    for (size_t i = 0; i < g_reg.count; i++) {
        if (zcl_command_registry_effective_handler(&g_reg.commands[i]) == fn)
            return true;
    }
    return false;
}

static void test_unmap(void *handle)
{
    struct img *im = (struct img *)handle;
    atomic_fetch_add(&g_unmap_calls, 1);
    if (!im)
        return;
    for (uint32_t k = 0; k < im->leaf_count; k++) {
        const struct zcl_command_spec *spec = find_spec(im->leaf[k]);
        if (spec && zcl_command_registry_effective_handler(spec) == im->fn) {
            /* The live snapshot still resolves this leaf to this image:
             * recorded and carried out, so dispatch threads see it too. */
            atomic_fetch_add(&g_unmap_of_live_image, 1);
            break;
        }
    }
    if (!handler_is_live_anywhere(im->fn) && atomic_load(&im->inflight) != 0)
        atomic_fetch_add(&g_unmap_with_dispatch_inside, 1);
    atomic_store(&im->unmapped, true);
}

/* ── Publish hooks ───────────────────────────────────────────────────────
 * Same shape as the resident's (tools/command/native_dev_hotswap.c): commit
 * publishes into the real registry and reports the generation. */
static pthread_mutex_t g_sync_m = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  g_sync_c = PTHREAD_COND_INITIALIZER;
static bool g_slow_published;      /* guarded by g_sync_m */
static bool g_fast_done;           /* guarded by g_sync_m */
static pthread_t g_slow_tid;
static _Atomic bool g_park_armed;

static bool t_commit(void *ctx, const struct zcl_hotswap_leaf *leaves,
                     size_t leaf_count, uint32_t *out_gen, char *why,
                     size_t why_sz)
{
    (void)ctx;
    if (!leaves || leaf_count == 0 ||
        leaf_count > ZCL_COMMAND_HANDLER_OVERRIDE_MAX) {
        if (why && why_sz) snprintf(why, why_sz, "bad batch size %zu", leaf_count);
        return false;
    }
    struct zcl_command_handler_override ovr[ZCL_COMMAND_HANDLER_OVERRIDE_MAX];
    for (size_t i = 0; i < leaf_count; i++) {
        ovr[i].path = leaves[i].name;
        ovr[i].handler = leaves[i].fn;
    }
    /* Take the generation from the publish itself; re-reading the active
     * generation would race a concurrent publisher. */
    if (!zcl_command_registry_replace_batch(0, ovr, leaf_count, why, why_sz,
                                            out_gen))
        return false;

    /* THE WINDOW: registry published, loader commit not yet reached.
     * Parking the slow publisher here reproduces the interleaving. */
    if (atomic_load(&g_park_armed) && pthread_equal(pthread_self(), g_slow_tid)) {
        pthread_mutex_lock(&g_sync_m);
        g_slow_published = true;
        pthread_cond_broadcast(&g_sync_c);
        while (!g_fast_done)
            pthread_cond_wait(&g_sync_c, &g_sync_m);
        pthread_mutex_unlock(&g_sync_m);
    }
    return true;
}

static bool t_probe(void *ctx, const char *leaf, zcl_hotswap_handler_fn fn,
                    char *why, size_t why_sz)
{
    (void)ctx;
    (void)leaf;
    if (!fn) {
        if (why && why_sz) snprintf(why, why_sz, "probe handler is NULL");
        return false;
    }
    return true;
}

static bool t_quiesced(void *ctx)
{
    (void)ctx;
    return zcl_command_registry_all_retired_quiesced();
}

static void t_hooks(struct hotswap_publish_hooks *h)
{
    memset(h, 0, sizeof(*h));
    h->commit = t_commit;
    h->probe = t_probe;
    h->quiesced = t_quiesced;
}

static bool selftest_true(char *err, size_t cap)
{
    (void)err;
    (void)cap;
    return true;
}

/* ── Driving one image through publish + commit, in the loader's order ── */
static bool drive_image(int idx, const char *source_tu,
                        const char *const *leaves, uint32_t leaf_count,
                        const char *sha, const char *datadir,
                        struct hotswap_activate_report *report)
{
    struct img *im = &g_img[idx];
    struct zcl_hotswap_leaf leafv[2];
    for (uint32_t i = 0; i < leaf_count; i++) {
        leafv[i].name = leaves[i];
        leafv[i].fn = k_img_fn[idx];
        im->leaf[i] = leaves[i];
    }
    im->leaf_count = leaf_count;
    im->fn = k_img_fn[idx];

    struct zcl_hotswap_module mod = {
        .abi_version = ZCL_HOTSWAP_MODULE_ABI_V3,
        .core_sections = hotswap_core_sections_self(),
        .source_tu = source_tu,
        .leaves = leafv,
        .leaf_count = leaf_count,
        .self_test = selftest_true,
    };
    struct hotswap_publish_hooks hooks;
    t_hooks(&hooks);

    if (!hotswap_module_publish(&mod, /*request_activate=*/true, &hooks,
                                report))
        return false;
    im->generation = report->generation;

    struct hotswap_commit_image req = {
        .source_tu = source_tu,
        .handle = im,
        .fd = im->fd,
        .leaves = leafv,
        .leaf_count = leaf_count,
        .generation = report->generation,
        .artifact_sha256 = sha,
        .resolved_datadir = datadir,
        .unmap = test_unmap,
        .hooks = &hooks,
    };
    /* hotswap_commit_image takes the descriptor on every path. */
    im->fd = -1;
    (void)hotswap_commit_image(&req);
    return true;
}

static size_t open_fd_count(void)
{
    size_t n = 0;
    /* Through the platform shim so the census excludes the counting handle. */
    if (!os_proc_open_fd_count(&n))
        return 0;
    return n;
}

static void reset_fixture(void)
{
    hotswap_activation_reset_for_testing();
    hotswap_retire_blocker_reset_for_testing();
    blocker_reset_for_testing();
    zcl_command_registry_reset_overrides();
    zcl_command_registry_set_active(&g_reg);
    memset(g_img, 0, sizeof(g_img));
    for (int i = 0; i < IMG_MAX; i++)
        g_img[i].fd = -1;
    atomic_store(&g_dispatch_into_unmapped, 0);
    atomic_store(&g_unmap_calls, 0);
    atomic_store(&g_unmap_of_live_image, 0);
    atomic_store(&g_unmap_with_dispatch_inside, 0);
    atomic_store(&g_park_armed, false);
    g_slow_published = false;
    g_fast_done = false;
}

static void give_image_an_fd(int idx)
{
    g_img[idx].fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
}

static bool close_prepared_fds(void)
{
    bool ok = true;
    for (int i = 0; i < IMG_MAX; i++) {
        int fd = g_img[i].fd;
        g_img[i].fd = -1;
        if (fd >= 0 && close(fd) != 0) {
            printf("prepared image %d close failed: errno=%d\n", i, errno);
            ok = false;
        }
    }
    return ok;
}

/* Shared with the depth-one test: refusal settles fixture ownership before
 * the caller can return a failure or reset the activation fixture. */
static bool prepare_depth_one(const char *sha,
                              struct hotswap_activate_report *r)
{
    const char *leaves[1] = { LEAF_PROBE };
    for (int i = 0; i < 3; i++) {
        give_image_an_fd(i);
        if (g_img[i].fd < 0) {
            int saved_errno = errno;
            snprintf(r->stage, sizeof(r->stage), "fixture_open");
            snprintf(r->error, sizeof(r->error), "image %d open: errno=%d", i, saved_errno);
            (void)close_prepared_fds();
            return false;
        }
    }
    if (!drive_image(0, SHELF_TU, leaves, 1, sha, "/nonexistent", r)) {
        (void)close_prepared_fds();
        return false;
    }
    return true;
}

static void release_fixture(void)
{
    hotswap_activation_reset_for_testing();
    zcl_command_registry_reset_overrides();
    zcl_command_registry_set_active(NULL);
    hotswap_retire_blocker_reset_for_testing();
    blocker_reset_for_testing();
}

/* ── 1. An untouched process has an empty shelf ─────────────────────────── */
static int t_shelf_starts_empty(void)
{
    int failures = 0;
    TEST("shelf starts empty and answers for sources it never saw") {
        reset_fixture();
        struct hotswap_shelf_entry e;
        ASSERT_EQ(hotswap_shelf_list(NULL, 0), (size_t)0);
        ASSERT(!hotswap_shelf_peek(SHELF_TU, &e));
        ASSERT(!hotswap_shelf_peek(SHELF_TU_META, &e));
        ASSERT(!hotswap_shelf_peek(SHELF_TU_UNKNOWN, &e));
        ASSERT(!hotswap_shelf_peek(NULL, &e));
        ASSERT(!hotswap_shelf_peek("", &e));
        ASSERT(!e.present);
        release_fixture();
        PASS();
    } _test_next:;
    return failures;
}

/* ── 2. The pure gauntlet alone shelves NOTHING ──────────────────────────
 * hotswap_module_publish() compiles into every build; if it could populate
 * the shelf, rollback would be a second way to publish live handlers
 * without datadir confinement, activation gate, seal or consensus pin. */
static int t_pure_publish_never_shelves(void)
{
    int failures = 0;
    TEST("publishing without an image commit shelves nothing, ever") {
        reset_fixture();
        const char *leaves[1] = { LEAF_PROBE };
        struct zcl_hotswap_leaf leafv[1] = { { LEAF_PROBE, h_img0 } };
        struct zcl_hotswap_module mod = {
            .abi_version = ZCL_HOTSWAP_MODULE_ABI_V3,
            .core_sections = hotswap_core_sections_self(),
            .source_tu = SHELF_TU,
            .leaves = leafv,
            .leaf_count = 1,
            .self_test = selftest_true,
        };
        (void)leaves;
        struct hotswap_publish_hooks hooks;
        t_hooks(&hooks);
        struct hotswap_activate_report report;
        for (int i = 0; i < 5; i++) {
            ASSERT(hotswap_module_publish(&mod, true, &hooks, &report));
            ASSERT(report.ok);
        }
        ASSERT_EQ(hotswap_shelf_list(NULL, 0), (size_t)0);
        struct hotswap_shelf_entry e;
        ASSERT(!hotswap_shelf_peek(SHELF_TU, &e));
        ASSERT_EQ(hotswap_stale_commit_count(), (uint64_t)0);
        release_fixture();
        PASS();
    } _test_next:;
    return failures;
}

/* ── 3. Rollback refuses cleanly when there is nothing to put back ─────── */
static int t_rollback_refuses_unknown_source(void)
{
    int failures = 0;
    TEST("rollback of a source with nothing shelved refuses and changes nothing") {
        reset_fixture();
        struct hotswap_publish_hooks hooks;
        t_hooks(&hooks);
        struct hotswap_activate_report report;

        ASSERT(!hotswap_rollback(NULL, &hooks, &report));
        ASSERT_STR_EQ(report.stage, "precheck");
        ASSERT(!hotswap_rollback("", &hooks, &report));
        ASSERT_STR_EQ(report.stage, "precheck");

        uint32_t gen_before = zcl_command_registry_active_generation();
        ASSERT(!hotswap_rollback(SHELF_TU, &hooks, &report));
        ASSERT(!report.ok);
        ASSERT(report.rolled_back);
        ASSERT_STR_EQ(report.stage, "shelf");
        ASSERT(report.error[0] != '\0');
        ASSERT(!hotswap_rollback(SHELF_TU_UNKNOWN, &hooks, &report));
        ASSERT_STR_EQ(report.stage, "shelf");
        ASSERT_EQ((unsigned)zcl_command_registry_active_generation(),
                  (unsigned)gen_before);
        release_fixture();
        PASS();
    } _test_next:;
    return failures;
}

/* ── 4. A commit shelves its predecessor, at depth exactly one ─────────── */
static int t_commit_shelves_predecessor_at_depth_one(void)
{
    int failures = 0;
    size_t before = 0, after = 0;
    bool measured = false;
    TEST("each commit shelves the image it superseded, keeping exactly one") {
        reset_fixture();
        ASSERT(os_proc_open_fd_count(&before));
        measured = true;
        const char *leaves[1] = { LEAF_PROBE };
        struct hotswap_activate_report r;
        struct hotswap_shelf_entry e;
        static const char sha0[65] =
            "0000000000000000000000000000000000000000000000000000000000000000";
        static const char sha1[65] =
            "1111111111111111111111111111111111111111111111111111111111111111";
        static const char sha2[65] =
            "2222222222222222222222222222222222222222222222222222222222222222";

        /* First image: nothing is superseded, so nothing is shelved. */
        ASSERT(prepare_depth_one(sha0, &r));
        ASSERT(!hotswap_shelf_peek(SHELF_TU, &e));
        ASSERT_EQ(hotswap_shelf_list(NULL, 0), (size_t)0);

        /* Second: image 0 is shelved, named by ITS digest and generation. */
        ASSERT(drive_image(1, SHELF_TU, leaves, 1, sha1, "/nonexistent", &r));
        ASSERT(hotswap_shelf_peek(SHELF_TU, &e));
        ASSERT(e.present);
        ASSERT_STR_EQ(e.source_tu, SHELF_TU);
        ASSERT_STR_EQ(e.artifact_sha256, sha0);
        ASSERT_EQ((unsigned)e.generation, (unsigned)g_img[0].generation);
        ASSERT_EQ(hotswap_shelf_list(NULL, 0), (size_t)1);

        /* Third: depth is 1, so image 0 leaves the shelf and image 1 takes
         * its place. The count never grows. */
        int live_fd = g_img[2].fd;
        ASSERT(drive_image(2, SHELF_TU, leaves, 1, sha2, "/nonexistent", &r));
        ASSERT(hotswap_shelf_peek(SHELF_TU, &e));
        ASSERT_STR_EQ(e.artifact_sha256, sha1);
        ASSERT_EQ(hotswap_shelf_list(NULL, 0), (size_t)1);

        /* count-only mode is the true count, not what was written */
        struct hotswap_shelf_entry one;
        ASSERT_EQ(hotswap_shelf_list(&one, 1), (size_t)1);
        ASSERT_STR_EQ(one.artifact_sha256, sha1);

        /* Nothing raced, so nothing was stale and nothing was held back. */
        ASSERT_EQ(hotswap_stale_commit_count(), (uint64_t)0);
        ASSERT_EQ(hotswap_reference_hold_count(), (uint64_t)0);
        ASSERT_EQ(atomic_load(&g_unmap_of_live_image), (uint64_t)0);
        ASSERT(close_prepared_fds());
        ASSERT(fcntl(live_fd, F_GETFD) >= 0);
    } _test_next:;
    if (!close_prepared_fds()) failures++;
    release_fixture();
    if (measured && (!os_proc_open_fd_count(&after) || after != before)) {
        printf("depth-one cleanup descriptor census failed\n");
        failures++;
    }
    if (!failures) PASS();
    return failures;
}

static int t_depth_one_preparation_refusal(void)
{
    int failures = 0;
    reset_fixture();
    TEST("first publication refusal closes all prepared descriptors before reset") {
        size_t before = 0, after = 0;
        ASSERT(os_proc_open_fd_count(&before));
        struct hotswap_activate_report r = {0};
        zcl_alloc_fault_fail_next("command handler override snapshot");
        ASSERT(!prepare_depth_one(NULL, &r));
        ASSERT_STR_EQ(r.stage, "commit");
        ASSERT_STR_EQ(r.error, "snapshot allocation failed");
        ASSERT(!r.ok && !r.activated);
        ASSERT_EQ(zcl_command_registry_active_generation(), (uint32_t)0);
        ASSERT_EQ(hotswap_shelf_list(NULL, 0), (size_t)0);
        ASSERT(os_proc_open_fd_count(&after));
        ASSERT_EQ(after, before);
        for (int i = 0; i < 3; i++) ASSERT_EQ(g_img[i].fd, -1);
    } _test_next:;
    zcl_alloc_fault_clear();
    if (!close_prepared_fds()) failures++;
    release_fixture();
    if (!failures) PASS();
    return failures;
}

/* ── 5. THE RETIREMENT RACE ──────────────────────────────────────────────
 *
 *   SLOW publishes  -> generation 2, registry dispatches into image SLOW
 *   FAST publishes  -> generation 3, registry dispatches into image FAST
 *   FAST commits    -> records FAST live, retires the image that was live (OLD)
 *   SLOW commits    -> arrives LAST with the OLDER generation
 *
 * Without the ordering check SLOW's commit would overwrite the slot and
 * hand FAST (the live image) to the retire path.
 *
 * Discrimination:
 *   - deleting the `req->generation > slot->generation` test in
 *     hotswap_commit_image() fails stale_commit_count == 1 and
 *     reference_hold_count == 0;
 *   - deleting the reference proof as well fails
 *     g_unmap_of_live_image == 0.
 */
struct race_ctx {
    int  fast_idx;
    bool fast_ok;
};

static _Atomic bool g_dispatch_stop;

static void *race_dispatch_thread(void *arg)
{
    (void)arg;
    char out[4096];
    while (!atomic_load(&g_dispatch_stop)) {
        (void)exec_path(LEAF_PROBE, out, sizeof(out));
        (void)exec_path(LEAF_SECOND, out, sizeof(out));
    }
    return NULL;
}

static void *race_fast_thread(void *arg)
{
    struct race_ctx *c = (struct race_ctx *)arg;
    static const char sha_fast[65] =
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    const char *leaves[1] = { LEAF_PROBE };
    struct hotswap_activate_report r;

    pthread_mutex_lock(&g_sync_m);
    while (!g_slow_published)
        pthread_cond_wait(&g_sync_c, &g_sync_m);
    pthread_mutex_unlock(&g_sync_m);

    c->fast_ok = drive_image(c->fast_idx, SHELF_TU, leaves, 1, sha_fast,
                             "/nonexistent", &r);

    pthread_mutex_lock(&g_sync_m);
    g_fast_done = true;
    pthread_cond_broadcast(&g_sync_c);
    pthread_mutex_unlock(&g_sync_m);
    return NULL;
}

static int t_retirement_race_never_unmaps_the_live_image(void)
{
    int failures = 0;
    TEST("a commit that lost the registry race never retires the live image") {
        reset_fixture();
        const char *leaves[1] = { LEAF_PROBE };
        struct hotswap_activate_report r;
        static const char sha_old[65] =
            "0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d";
        static const char sha_slow[65] =
            "5105105105105105105105105105105105105105105105105105105105105105";
        const int OLD = 0, SLOW = 1, FAST = 2;
        for (int i = 0; i < 3; i++)
            give_image_an_fd(i);

        /* A first, uncontended image so there is something to supersede. */
        ASSERT(drive_image(OLD, SHELF_TU, leaves, 1, sha_old, "/nonexistent",
                           &r));
        ASSERT_EQ((unsigned)zcl_command_registry_active_generation(), 1u);

        atomic_store(&g_dispatch_stop, false);
        pthread_t dispatchers[3];
        for (int i = 0; i < 3; i++)
            ASSERT_EQ(pthread_create(&dispatchers[i], NULL,
                                     race_dispatch_thread, NULL), 0);

        /* Arm the park for THIS thread: it becomes the slow publisher. */
        g_slow_tid = pthread_self();
        atomic_store(&g_park_armed, true);

        struct race_ctx ctx = { .fast_idx = FAST, .fast_ok = false };
        pthread_t fast;
        ASSERT_EQ(pthread_create(&fast, NULL, race_fast_thread, &ctx), 0);

        /* Parks in the commit hook after its generation is assigned and
         * resumes once FAST has published AND committed. */
        bool slow_ok = drive_image(SLOW, SHELF_TU, leaves, 1, sha_slow,
                                   "/nonexistent", &r);
        pthread_join(fast, NULL);
        atomic_store(&g_dispatch_stop, true);
        for (int i = 0; i < 3; i++)
            pthread_join(dispatchers[i], NULL);
        atomic_store(&g_park_armed, false);
        /* With traffic stopped, finish any retirement whose drain was left
         * unconfirmed, so this tests the retirement decision. */
        (void)hotswap_reclaim_retained_now();

        ASSERT(slow_ok);
        ASSERT(ctx.fast_ok);

        /* Asserted first: the image the live snapshot dispatches into was
         * never handed to the unmap. */
        ASSERT(!atomic_load(&g_img[FAST].unmapped));
        ASSERT_EQ(atomic_load(&g_unmap_of_live_image), (uint64_t)0);
        ASSERT_EQ(atomic_load(&g_dispatch_into_unmapped), (uint64_t)0);
        ASSERT_EQ(atomic_load(&g_unmap_with_dispatch_inside), (uint64_t)0);
        ASSERT(zcl_command_registry_effective_handler(find_spec(LEAF_PROBE)) ==
               k_img_fn[FAST]);

        /* Dispatch still answers, and answers as the live image. */
        char out[4096];
        ASSERT_EQ((int)exec_path(LEAF_PROBE, out, sizeof(out)),
                  (int)ZCL_COMMAND_EXIT_OK);
        ASSERT(strstr(out, "\"who\":\"img2\"") != NULL);

        /* The slot names the live image, so the shelf holds the image the
         * registry actually superseded, not the loser. */
        struct hotswap_shelf_entry e;
        ASSERT(hotswap_shelf_peek(SHELF_TU, &e));
        ASSERT_STR_EQ(e.artifact_sha256, sha_old);

        /* The interleaving actually happened; else the above is vacuous. */
        ASSERT_EQ(hotswap_stale_commit_count(), (uint64_t)1);
        ASSERT(g_img[SLOW].generation < g_img[FAST].generation);

        /* The two images really superseded WERE released. */
        ASSERT(atomic_load(&g_img[OLD].unmapped));
        ASSERT(atomic_load(&g_img[SLOW].unmapped));
        ASSERT_EQ(hotswap_reference_hold_count(), (uint64_t)0);
        release_fixture();
        PASS();
    } _test_next:;
    return failures;
}

/* ── 6. A module that drops a leaf must not have its predecessor unmapped ─
 *
 * hotswap_module_admit() requires every declared leaf be on the allowlist
 * row but not that a module declare all of them. A v2 that drops a leaf
 * leaves v1's handler live in the merged snapshot; releasing v1 would be a
 * use-after-free on the dropped leaf.
 *
 * Discrimination: deleting the reference proof fails !g_img[V1].unmapped
 * and lands the LEAF_SECOND dispatch in a released image.
 */
static int t_shrinking_leaf_set_keeps_the_old_image_mapped(void)
{
    int failures = 0;
    TEST("an image is kept mapped while the live snapshot still reaches it") {
        reset_fixture();
        const char *both[2] = { LEAF_PROBE, LEAF_SECOND };
        const char *just_probe[1] = { LEAF_PROBE };
        struct hotswap_activate_report r;
        static const char sha[65] =
            "abababababababababababababababababababababababababababababababab";
        const int V1 = 0, V2 = 1, V3 = 2;
        for (int i = 0; i < 3; i++)
            give_image_an_fd(i);

        ASSERT(drive_image(V1, SHELF_TU, both, 2, sha, "/nonexistent", &r));
        ASSERT(drive_image(V2, SHELF_TU, just_probe, 1, sha, "/nonexistent",
                           &r));

        /* V1 still owns LEAF_SECOND in the live snapshot: keep it mapped. */
        ASSERT(!atomic_load(&g_img[V1].unmapped));
        ASSERT_EQ(atomic_load(&g_unmap_of_live_image), (uint64_t)0);
        ASSERT(zcl_command_registry_effective_handler(find_spec(LEAF_SECOND)) ==
               k_img_fn[V1]);
        ASSERT_EQ(hotswap_reference_hold_count(), (uint64_t)1);

        char out[4096];
        ASSERT_EQ((int)exec_path(LEAF_SECOND, out, sizeof(out)),
                  (int)ZCL_COMMAND_EXIT_OK);
        ASSERT(strstr(out, "\"who\":\"img0\"") != NULL);
        ASSERT_EQ(atomic_load(&g_dispatch_into_unmapped), (uint64_t)0);

        /* A later image taking BOTH leaves releases V2 and makes V1
         * reclaimable. */
        ASSERT(drive_image(V3, SHELF_TU, both, 2, sha, "/nonexistent", &r));
        ASSERT(atomic_load(&g_img[V2].unmapped));
        ASSERT(!atomic_load(&g_img[V1].unmapped));   /* not retried yet */
        ASSERT(hotswap_reclaim_retained_now());
        ASSERT(atomic_load(&g_img[V1].unmapped));
        ASSERT_EQ(atomic_load(&g_unmap_of_live_image), (uint64_t)0);
        release_fixture();
        PASS();
    } _test_next:;
    return failures;
}

/* ── 7. Rollback claims, racing forward swaps and each other ─────────────
 *
 * Rollback cannot COMPLETE in a test process, so what is driven is its
 * CLAIM: the dup() of the shelved descriptor, the in-flight flag, the
 * refusal, and the release of both. Against concurrent forward swaps and
 * dispatch, no descriptor leaks, the shelf never empties or doubles, and
 * nothing is unmapped while live.
 */
static _Atomic bool g_rb_stop;
static _Atomic uint64_t g_rb_attempts;
static _Atomic uint64_t g_rb_busy_refusals;
static _Atomic uint64_t g_rb_bad_stage;

static void *rollback_thread(void *arg)
{
    (void)arg;
    struct hotswap_publish_hooks hooks;
    t_hooks(&hooks);
    while (!atomic_load(&g_rb_stop)) {
        struct hotswap_activate_report r;
        bool ok = hotswap_rollback(SHELF_TU, &hooks, &r);
        atomic_fetch_add(&g_rb_attempts, 1);
        if (ok) {
            atomic_fetch_add(&g_rb_bad_stage, 1);  /* cannot pass the gate here */
            continue;
        }
        /* Every refusal is a stage this path can reach: the shelf claim or
         * the re-checked resident gate. */
        if (strcmp(r.stage, "shelf") != 0 &&
            strcmp(r.stage, "precheck") != 0 &&
            strcmp(r.stage, "authorize") != 0)
            atomic_fetch_add(&g_rb_bad_stage, 1);
        if (strcmp(r.stage, "shelf") == 0 && strstr(r.error, "in flight"))
            atomic_fetch_add(&g_rb_busy_refusals, 1);
    }
    return NULL;
}

static void *forward_swap_thread(void *arg)
{
    int *base = (int *)arg;
    static const char sha[65] =
        "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd";
    const char *leaves[1] = { LEAF_PROBE };
    int idx = *base;
    while (!atomic_load(&g_rb_stop)) {
        struct hotswap_activate_report r;
        give_image_an_fd(idx);
        (void)drive_image(idx, SHELF_TU, leaves, 1, sha, "/nonexistent", &r);
        idx++;
        if (idx >= IMG_MAX)
            break;
    }
    return NULL;
}

static int t_rollback_races_forward_swaps(void)
{
    int failures = 0;
    TEST("rollback claims racing forward swaps leak no descriptor and no image") {
        reset_fixture();
        const char *leaves[1] = { LEAF_PROBE };
        struct hotswap_activate_report r;
        static const char sha[65] =
            "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";

        /* Two commits so the shelf is genuinely populated. */
        give_image_an_fd(0);
        give_image_an_fd(1);
        ASSERT(drive_image(0, SHELF_TU, leaves, 1, sha, "/nonexistent", &r));
        ASSERT(drive_image(1, SHELF_TU, leaves, 1, sha, "/nonexistent", &r));
        struct hotswap_shelf_entry e;
        ASSERT(hotswap_shelf_peek(SHELF_TU, &e));

        size_t fds_before = open_fd_count();

        atomic_store(&g_rb_stop, false);
        atomic_store(&g_rb_attempts, 0);
        atomic_store(&g_rb_busy_refusals, 0);
        atomic_store(&g_rb_bad_stage, 0);
        atomic_store(&g_dispatch_stop, false);

        pthread_t rb[2], dispatchers[2], fwd;
        int fwd_base = 2;
        for (int i = 0; i < 2; i++)
            ASSERT_EQ(pthread_create(&rb[i], NULL, rollback_thread, NULL), 0);
        for (int i = 0; i < 2; i++)
            ASSERT_EQ(pthread_create(&dispatchers[i], NULL,
                                     race_dispatch_thread, NULL), 0);
        ASSERT_EQ(pthread_create(&fwd, NULL, forward_swap_thread, &fwd_base), 0);

        /* The forward thread stops on its own once it runs out of images. */
        pthread_join(fwd, NULL);
        /* Give the rollback threads a bounded amount of contention past that. */
        while (atomic_load(&g_rb_attempts) < 2000)
            sched_yield();
        atomic_store(&g_rb_stop, true);
        atomic_store(&g_dispatch_stop, true);
        for (int i = 0; i < 2; i++)
            pthread_join(rb[i], NULL);
        for (int i = 0; i < 2; i++)
            pthread_join(dispatchers[i], NULL);

        (void)hotswap_reclaim_retained_now();

        ASSERT_EQ(atomic_load(&g_rb_bad_stage), (uint64_t)0);
        ASSERT_EQ(atomic_load(&g_unmap_of_live_image), (uint64_t)0);
        ASSERT_EQ(atomic_load(&g_dispatch_into_unmapped), (uint64_t)0);
        ASSERT_EQ(atomic_load(&g_unmap_with_dispatch_inside), (uint64_t)0);

        /* The shelf holds exactly one entry for this source, still. */
        ASSERT_EQ(hotswap_shelf_list(NULL, 0), (size_t)1);
        ASSERT(hotswap_shelf_peek(SHELF_TU, &e));

        /* No descriptor leaked; the live slot and its shelf entry account
         * for the small fixed delta. */
        size_t fds_after = open_fd_count();
        ASSERT(fds_after <= fds_before + 4);

        /* A rollback issued alone afterwards must not be told one is already
         * in flight: every claim released its flag. */
        struct hotswap_publish_hooks hooks;
        t_hooks(&hooks);
        struct hotswap_activate_report solo;
        ASSERT(!hotswap_rollback(SHELF_TU, &hooks, &solo));
        ASSERT(strstr(solo.error, "in flight") == NULL);

        printf("[rollback attempts=%llu busy_refusals=%llu] ",
               (unsigned long long)atomic_load(&g_rb_attempts),
               (unsigned long long)atomic_load(&g_rb_busy_refusals));
        release_fixture();
        PASS();
    } _test_next:;
    return failures;
}

int test_hotswap_shelf(void)
{
    int failures = 0;
    failures += t_shelf_starts_empty();
    failures += t_pure_publish_never_shelves();
    failures += t_rollback_refuses_unknown_source();
    failures += t_commit_shelves_predecessor_at_depth_one();
    failures += t_depth_one_preparation_refusal();
    failures += t_retirement_race_never_unmaps_the_live_image();
    failures += t_shrinking_leaf_set_keeps_the_old_image_mapped();
    failures += t_rollback_races_forward_swaps();
    return failures;
}
