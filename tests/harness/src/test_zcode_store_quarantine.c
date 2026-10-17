/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * zcode_store scenario checks: a persisted release record that is provably
 * not a valid release is moved into <store>/quarantine/releases and counted,
 * while an I/O error on a record still refuses the open and nothing is ever
 * deleted. */

#include "test/test_core.h"

#include "vcs/package_release.h"
#include "vcs/package_store.h"

#include "chain/chainparams.h"

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "test/test_zcode_store_priv.h"

struct zsq_fixture {
    char dd[256];
    char path_a[512];
    char path_b[512];
    struct vcs_package_release a;
    struct vcs_package_release b;
};

static bool zsq_release_path(const char *dd, const struct vcs_package_release *r,
                             char *out, size_t n)
{
    uint8_t id[VCS_PACKAGE_RELEASE_ID_BYTES];
    char hex[65], suffix[160];
    if (vcs_package_release_id(r, id) != VCS_PACKAGE_RELEASE_OK) return false;
    zs_hex32(id, hex);
    snprintf(suffix, sizeof(suffix), "releases/%s", hex);
    zs_store_path(out, n, dd, suffix);
    return true;
}

/* Two releases from different publishers, persisted, store closed. */
static bool zsq_setup(struct zsq_fixture *fx, const char *tag)
{
    chain_params_select(CHAIN_MAIN);
    struct vcs_package_store *s = zs_open(fx->dd, sizeof(fx->dd), tag,
                                          1000000u);
    enum vcs_package_accept_result ar = VCS_PACKAGE_ACCEPT_ERR_NULL;
    bool ok = s && zs_release(&fx->a, 0x31, 1u, "alpha/keep") &&
        zs_release(&fx->b, 0x32, 1u, "beta/damaged") &&
        vcs_package_store_put_release(s, &fx->a, &ar) ==
            VCS_PACKAGE_STORE_OK &&
        vcs_package_store_put_release(s, &fx->b, &ar) ==
            VCS_PACKAGE_STORE_OK &&
        zsq_release_path(fx->dd, &fx->a, fx->path_a, sizeof(fx->path_a)) &&
        zsq_release_path(fx->dd, &fx->b, fx->path_b, sizeof(fx->path_b));
    if (s) vcs_package_store_close(s);
    return ok;
}

static size_t zsq_count_entries(const char *dir)
{
    DIR *d = opendir(dir);
    if (!d) return 0;
    size_t count = 0;
    for (struct dirent *e = readdir(d); e; e = readdir(d))
        if (strcmp(e->d_name, ".") != 0 && strcmp(e->d_name, "..") != 0)
            count++;
    closedir(d);
    return count;
}

static bool zsq_rewrite(const char *path, const uint8_t *data, size_t len)
{
    FILE *f = fopen(path, "wb");
    bool ok = f && (len == 0 || fwrite(data, 1, len, f) == len);
    if (f && fclose(f) != 0) ok = false;
    return ok;
}

/* The one quarantined record must be named <release id>.<timestamp>. */
static bool zsq_quarantined_as(const char *dd, const char *path_b)
{
    char dir[512];
    zs_store_path(dir, sizeof(dir), dd, "quarantine/releases");
    DIR *d = opendir(dir);
    if (!d) return false;
    const char *id = strrchr(path_b, '/') + 1;
    size_t id_len = strlen(id);
    size_t found = 0;
    for (struct dirent *e = readdir(d); e; e = readdir(d))
        if (strncmp(e->d_name, id, id_len) == 0 && e->d_name[id_len] == '.')
            found++;
    closedir(d);
    return found == 1;
}

static int zsq_case_damage(const char *label, bool zero_length)
{
    int failures = 0;
    struct zsq_fixture fx;
    ZS_CHECK(label, zsq_setup(&fx, zero_length ? "quarzero" : "quardigest"));
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    bool written = vcs_package_release_serialize(&fx.a, &wire, &wire_len) ==
        VCS_PACKAGE_RELEASE_OK;
    written = written && (zero_length ? zsq_rewrite(fx.path_b, NULL, 0)
                                      : zsq_rewrite(fx.path_b, wire, wire_len));
    free(wire);
    ZS_CHECK("quarantine: damage fixture written", written);
    struct vcs_package_store *s = vcs_package_store_open(fx.dd, 1000000u);
    ZS_CHECK("quarantine: damaged release no longer refuses open", s != NULL);
    if (!s) return failures;
    enum vcs_package_accept_result ar = VCS_PACKAGE_ACCEPT_ERR_NULL;
    ZS_CHECK("quarantine: remaining history replays",
             vcs_package_store_put_release(s, &fx.a, &ar) ==
                 VCS_PACKAGE_STORE_OK && ar == VCS_PACKAGE_ACCEPT_DUPLICATE);
    ZS_CHECK("quarantine: reason is counted",
             vcs_package_store_quarantined_releases(s) == 1u);
    ZS_CHECK("quarantine: record moved aside, not deleted",
             !zs_path_exists(fx.path_b) &&
             zsq_quarantined_as(fx.dd, fx.path_b));
    char rel_dir[512];
    zs_store_path(rel_dir, sizeof(rel_dir), fx.dd, "releases");
    ZS_CHECK("quarantine: healthy record untouched",
             zs_path_exists(fx.path_a) && zsq_count_entries(rel_dir) == 1u);
    ZS_CHECK("quarantine: damaged release is treated as never published",
             vcs_package_store_put_release(s, &fx.b, &ar) ==
                 VCS_PACKAGE_STORE_OK && ar == VCS_PACKAGE_ACCEPT_OK);
    vcs_package_store_close(s);
    test_rm_rf_recursive(fx.dd);
    return failures;
}

static int zsq_case_io_refuses(bool use_mode)
{
    int failures = 0;
    struct zsq_fixture fx;
    ZS_CHECK("quarantine: io fixture prepares",
             zsq_setup(&fx, use_mode ? "quarmode" : "quardir"));
    bool ready = use_mode ? chmod(fx.path_b, 0) == 0
                          : (unlink(fx.path_b) == 0 &&
                             mkdir(fx.path_b, 0700) == 0);
    ZS_CHECK("quarantine: io fault injected", ready);
    struct vcs_package_store *s = vcs_package_store_open(fx.dd, 1000000u);
    ZS_CHECK(use_mode ? "quarantine: unreadable release still refuses open"
                      : "quarantine: nonregular release still refuses open",
             s == NULL);
    if (s) vcs_package_store_close(s);
    char quarantine[512];
    zs_store_path(quarantine, sizeof(quarantine), fx.dd,
                  "quarantine/releases");
    ZS_CHECK("quarantine: io fault is not hidden by quarantine",
             zs_path_exists(fx.path_b) && zsq_count_entries(quarantine) == 0u);
    if (use_mode) (void)chmod(fx.path_b, 0600);
    test_rm_rf_recursive(fx.dd);
    return failures;
}

int t_store_release_quarantine(void)
{
    int failures = 0;
    failures += zsq_case_damage("quarantine: zero-length fixture", true);
    failures += zsq_case_damage("quarantine: digest-mismatch fixture", false);
    failures += zsq_case_io_refuses(false);
    if (geteuid() == 0)
        printf("  zcode_store: quarantine: chmod 000 case needs a non-root "
               "user... SKIP (1 skipped)\n");
    else
        failures += zsq_case_io_refuses(true);
    return failures;
}
