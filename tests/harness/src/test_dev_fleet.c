/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Pin the deliberately narrow owner boundary in dev.fleet. */

#include "test/test_core.h"

#include "base/hex.h"
#include "command/native_dev_fleet.h"
#include "command/native_dev_fleet_internal.h"
#include "json/json.h"
#include "sha3/sha3.h"
#include "util/spawn.h"

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

/* ── receipt numeric fields, through the production receipts projection ─── */

#define FRX_HEAD "0123456789abcdef0123456789abcdef01234567"
#define FRX_HASH64 \
    "00000000000000000000000000000000000000000000000000000000000000aa"

static bool frx_git(const char *dir, const char *const args[])
{
    const char *argv[24] = {"git", "-C", dir};
    size_t n = 3;
    for (size_t i = 0; args[i] && n + 1 < 24; i++) argv[n++] = args[i];
    argv[n] = NULL;
    char out[4096];
    return zcl_spawn_capture(argv, out, sizeof(out), 60000) == 0;
}

/* Writes one sealed receipt: the body, then receipt_sha3 over the body. */
static bool frx_write_receipt(const char *dir, const char *index,
                              const char *exit_status, const char *expect,
                              const char *forbid)
{
    char body[1024], seal[65], digest_hex[65], path[1024], file[2200];
    int n = snprintf(body, sizeof(body),
                     "chain_index=%s\nprev_receipt_sha3=GENESIS\ngate=other\n"
                     "branch=lane/x\nworktree_path=%s\nhead_sha=%s\n"
                     "head_sha_after=%s\ntree_status_sha3=%s\n"
                     "tree_diff_sha3_after=%s\noutput_path=out.log\n"
                     "output_sha3=%s\nverdict=PASS\nexit_status=%s\n"
                     "expect_missing=%s\nforbid_present=%s\n",
                     index, dir, FRX_HEAD, FRX_HEAD, FRX_HASH64, FRX_HASH64,
                     FRX_HASH64, exit_status, expect, forbid);
    if (n <= 0 || (size_t)n >= sizeof(body)) return false;
    unsigned char digest[32];
    sha3_256((const unsigned char *)body, (size_t)n, digest);
    zcl_hex_encode(digest, sizeof(digest), digest_hex);
    (void)snprintf(seal, sizeof(seal), "%s", digest_hex);
    int m = snprintf(file, sizeof(file), "%sreceipt_sha3=%s\n", body, seal);
    if (m <= 0 || (size_t)m >= sizeof(file)) return false;
    (void)snprintf(path, sizeof(path), "%s/.cache/agent-receipts/0.receipt",
                   dir);
    FILE *f = fopen(path, "wb");
    if (!f) return false;
    bool wrote = fwrite(file, 1, (size_t)m, f) == (size_t)m;
    return fclose(f) == 0 && wrote;
}

/* The lint_status the projection reports for this receipt, or "" when the
 * projection itself failed. A receipt the reader refuses reads "invalid". */
static bool frx_status(const char *dir, const char *index,
                       const char *exit_status, const char *expect,
                       const char *forbid, char *state, size_t cap)
{
    state[0] = 0;
    if (!frx_write_receipt(dir, index, exit_status, expect, forbid))
        return false;
    struct zcl_fleet_worktree wt = {0};
    wt.present = true;
    (void)snprintf(wt.path, sizeof(wt.path), "%s", dir);
    struct json_value lane;
    json_init(&lane);
    json_set_object(&lane);
    size_t owner_red = 0;
    char why[256] = "";
    bool ok = zcl_dev_fleet_receipts_json(&wt, &lane, &owner_red, why,
                                          sizeof(why));
    const char *s = json_get_str(json_get(&lane, "lint_status"));
    if (ok && s) (void)snprintf(state, cap, "%s", s);
    json_free(&lane);
    return ok && s;
}

static bool frx_fixture(char *dir, size_t cap)
{
    if (!test_mkdtemp(dir, cap, "fleet_receipt")) return false;
    char out[4096];
    const char *argv[] = {"git", "-c", "init.defaultBranch=main", "init", "-q",
                          dir, NULL};
    if (zcl_spawn_capture(argv, out, sizeof(out), 60000) != 0) return false;
    const char *commit[] = {"-c", "user.name=Z23 Test", "-c",
                            "user.email=z23-test@example.invalid", "-c",
                            "commit.gpgsign=false", "commit", "-q",
                            "--allow-empty", "-m", "base", NULL};
    char cache[1100];
    (void)snprintf(cache, sizeof(cache), "%s/.cache", dir);
    if (!frx_git(dir, commit) || mkdir(cache, 0700) != 0) return false;
    (void)snprintf(cache, sizeof(cache), "%s/.cache/agent-receipts", dir);
    return mkdir(cache, 0700) == 0;
}

static int frx_run(void)
{
    int failures = 0;
    char dir[512], state[32];
    bool built = frx_fixture(dir, sizeof(dir));

    TEST("fleet receipts: fixture repository builds") { ASSERT(built); PASS(); }

    TEST("fleet receipts: a well-formed receipt is accepted") {
        ASSERT(frx_status(dir, "0", "0", "0", "0", state, sizeof(state)));
        ASSERT(strcmp(state, "unobserved") == 0);
        PASS();
    }

    TEST("fleet receipts: valid maxima are accepted") {
        ASSERT(frx_status(dir, "18446744073709551615",
                          "18446744073709551615", "18446744073709551615",
                          "18446744073709551615", state, sizeof(state)));
        /* Accepted by the reader; only the chain (index != 0) refuses. */
        ASSERT(strcmp(state, "invalid") == 0);
        ASSERT(frx_status(dir, "0", "18446744073709551615", "0", "0", state,
                          sizeof(state)));
        ASSERT(strcmp(state, "unobserved") == 0);
        ASSERT(frx_status(dir, "0", "0", "18446744073709551615", "0", state,
                          sizeof(state)));
        ASSERT(strcmp(state, "unobserved") == 0);
        ASSERT(frx_status(dir, "0", "0", "0", "18446744073709551615", state,
                          sizeof(state)));
        ASSERT(strcmp(state, "unobserved") == 0);
        PASS();
    }

    static const char *const bad[] = {
        "", "-1", "+5", " 5", "5 ", "1x", "00000000000000000000000",
        "123456789012345678901", "18446744073709551616",
    };
    static const char *const names[] = {"chain_index", "exit_status",
                                        "expect_missing", "forbid_present"};
    for (size_t field = 0; field < 4; field++) {
        for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
            const char *v[4] = {"0", "0", "0", "0"};
            v[field] = bad[i];
            TEST("fleet receipts: a malformed numeric field is refused") {
                bool ok = frx_status(dir, v[0], v[1], v[2], v[3], state,
                                     sizeof(state));
                if (!ok || strcmp(state, "invalid") != 0)
                    printf("  not refused: %s=\"%s\" state=%s\n", names[field],
                           bad[i], state);
                ASSERT(ok);
                ASSERT(strcmp(state, "invalid") == 0);
                PASS();
            }
        }
    }
_test_next:;
    if (built) (void)test_rm_rf_recursive(dir);
    return failures;
}

int test_dev_fleet(void);
int test_dev_fleet(void)
{
    int failures = 0;

    TEST("fleet: the consensus seal is owner-only") {
        ASSERT(zcl_dev_fleet_gate_owner_only("check-core-seal"));
        PASS();
    }

    TEST("fleet: repository hooks are owner-only") {
        ASSERT(zcl_dev_fleet_gate_owner_only("check-git-hooks-installed"));
        PASS();
    }

    TEST("fleet: ordinary source gates remain worker-fixable") {
        ASSERT(!zcl_dev_fleet_gate_owner_only("check-format"));
        ASSERT(!zcl_dev_fleet_gate_owner_only("check-command-registry"));
        ASSERT(!zcl_dev_fleet_gate_owner_only(NULL));
        PASS();
    }

    failures += frx_run();

_test_next:;
    if (failures == 0) printf("test_dev_fleet: all passed\n");
    else printf("test_dev_fleet: %d FAILED\n", failures);
    return failures;
}
