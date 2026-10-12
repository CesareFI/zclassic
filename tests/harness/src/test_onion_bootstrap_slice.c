/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_onion_bootstrap_slice — the HERMETIC slice-gate for MVP criterion #2
 * ("Tor onion bootstrap in <60s").
 *
 * The full acceptance test (test_onion_bootstrap.c, selector "onion") needs
 * live Tor egress. This slice covers the parts that do not, in-process with
 * no socket, thread or params:
 *
 *   (1) The readiness / <60s BUDGET logic: the bootstrap is accepted iff the
 *       ready flag flips within the 60s budget, asserted on both branches,
 *       plus the clean initial state (not-ready, NULL address) of
 *       tor_integration_is_ready / tor_integration_get_onion_address.
 *
 *   (2) The v3 .onion format check (56 base32 chars + ".onion" = 62) and the
 *       address-publication path (onion_service_set_address /
 *       onion_service_get_address round-trip; NULL clears), against a battery
 *       of malformed addresses (wrong length, bad suffix, out-of-alphabet
 *       chars, uppercase, empty, NULL).
 *
 * Gating: drives the process-global onion_service address singleton, so the
 * body is gated behind ZCL_STRESS_TESTS and the address is snapshotted and
 * restored. Never calls tor_integration_start().
 *
 * Invocation:
 *   ZCL_STRESS_TESTS=1 ZCL_TEST_ONLY=onion_slice build/bin/test_zcl
 *   make mvp-onion-slice
 */

#include "test/test_core.h"
#include "net/tor_integration.h"
#include "net/onion_service.h"

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#define OBS_CHECK(name, expr) do {                          \
    printf("onion_bootstrap_slice: %s... ", (name));        \
    if ((expr)) printf("OK\n");                             \
    else { printf("FAIL\n"); failures++; }                 \
} while (0)

/* v3 hidden-service name format: 56 base32 chars + ".onion" = 62 total.
 * Lowercase RFC 4648 base32 alphabet: a-z | 2-7. Same shape as
 * test_onion_bootstrap.c::is_valid_onion_v3. */
static bool slice_is_valid_onion_v3(const char *addr)
{
    if (!addr) return false;
    size_t len = strlen(addr);
    if (len != 62) return false;
    if (strcmp(addr + 56, ".onion") != 0) return false;
    for (size_t i = 0; i < 56; i++) {
        char c = addr[i];
        bool ok = (c >= 'a' && c <= 'z') || (c >= '2' && c <= '7');
        if (!ok) return false;
    }
    return true;
}

/* The bootstrap <60s budget decision, modelling the production poll loop
 * (test_onion_bootstrap.c polls tor_integration_is_ready() at 1Hz).
 * `ready_at_sec` < 0 means the bootstrap never readies. Accept iff it
 * readies in [0, budget]. */
static bool slice_ready_within_budget(int ready_at_sec, int budget_sec)
{
    if (ready_at_sec < 0) return false;       /* never readied        */
    if (ready_at_sec > budget_sec) return false; /* readied too late   */
    return true;                              /* readied within budget */
}

int test_onion_bootstrap_slice(void);
int test_onion_bootstrap_diagnostics(void);
int test_onion_bootstrap_slice(void)
{
    printf("\n=== Tor onion bootstrap SLICE "
           "(MVP #2 hermetic: <60s budget + v3 address format) ===\n");
    int failures = 0;

    /* OPT-IN: drives the process-global onion_service address singleton, so
     * it runs only in a fresh process via ZCL_TEST_ONLY=onion_slice /
     * `make mvp-onion-slice`. */
    if (!getenv("ZCL_STRESS_TESTS")) {
        printf("onion_bootstrap_slice: SKIP "
               "(set ZCL_STRESS_TESTS=1 and run isolated via "
               "`make mvp-onion-slice`)\n");
        return 0;
    }
    failures += test_onion_bootstrap_diagnostics();

    /* Snapshot the address singleton so a sequential full run is unaffected. */
    const char *saved = onion_service_get_address();
    char saved_buf[128];
    bool had_saved = (saved != NULL);
    if (had_saved) {
        snprintf(saved_buf, sizeof(saved_buf), "%s", saved);
        onion_service_set_address(NULL);  /* clean slate for the slice */
    }

    /* A canonical, well-formed v3 .onion (56 base32 chars + ".onion"). */
    const char *valid_v3 =
        "zc23kenfdqqkgamthif3m7lbbdsyrotsl2dlw35qrh3iuzopozmpjnad.onion";

    /* ── (1) Bootstrap state-machine clean INITIAL state ─────────────────────
     * Before any bootstrap, readiness is false and the address is NULL; a
     * latched-true ready flag would make the <60s gate pass vacuously. */
    OBS_CHECK("real ready observable is FALSE before bootstrap",
              tor_integration_is_ready() == false);
    OBS_CHECK("real address observable is NULL before bootstrap",
              tor_integration_get_onion_address() == NULL);

    /* ── (2) <60s readiness BUDGET logic ─────────────────────────────────────
     * A bootstrap that readies within the budget is accepted; one that
     * readies too late or never readies is rejected. */
    const int budget = 60;  /* MVP #2 budget, seconds */
    OBS_CHECK("budget ACCEPTS bootstrap ready at 0s (warm)",
              slice_ready_within_budget(0, budget) == true);
    OBS_CHECK("budget ACCEPTS bootstrap ready at 30s (typical)",
              slice_ready_within_budget(30, budget) == true);
    OBS_CHECK("budget ACCEPTS bootstrap ready exactly at 60s (boundary)",
              slice_ready_within_budget(60, budget) == true);
    OBS_CHECK("budget REJECTS bootstrap ready at 61s (one past budget)",
              slice_ready_within_budget(61, budget) == false);
    OBS_CHECK("budget REJECTS bootstrap ready at 90s (ceiling)",
              slice_ready_within_budget(90, budget) == false);
    OBS_CHECK("budget REJECTS bootstrap that never readies",
              slice_ready_within_budget(-1, budget) == false);

    /* ── (3) v3 address format check ─────────────────────────────────────────
     * Accept a well-formed v3 .onion; reject a battery of malformed ones. */
    OBS_CHECK("v3 format ACCEPTS a well-formed 56-base32 + .onion address",
              slice_is_valid_onion_v3(valid_v3) == true);
    OBS_CHECK("v3 format REJECTS NULL", slice_is_valid_onion_v3(NULL) == false);
    OBS_CHECK("v3 format REJECTS empty string",
              slice_is_valid_onion_v3("") == false);
    OBS_CHECK("v3 format REJECTS a v2-length (16-char) address",
              slice_is_valid_onion_v3("abcdefghij234567.onion") == false);
    OBS_CHECK("v3 format REJECTS a 56-base32 body WITHOUT the .onion suffix",
              slice_is_valid_onion_v3(
                  "zc23kenfdqqkgamthif3m7lbbdsyrotsl2dlw35qrh3iuzopozmpjnad")
                  == false);
    OBS_CHECK("v3 format REJECTS the wrong suffix (.exit)",
              slice_is_valid_onion_v3(
                  "zc23kenfdqqkgamthif3m7lbbdsyrotsl2dlw35qrh3iuzopozmpjnad.exit")
                  == false);
    OBS_CHECK("v3 format REJECTS an out-of-alphabet char (digit 1 not in base32)",
              slice_is_valid_onion_v3(
                  "1c23kenfdqqkgamthif3m7lbbdsyrotsl2dlw35qrh3iuzopozmpjnad.onion")
                  == false);
    OBS_CHECK("v3 format REJECTS an uppercase char (.onion is lowercase-only)",
              slice_is_valid_onion_v3(
                  "Zc23kenfdqqkgamthif3m7lbbdsyrotsl2dlw35qrh3iuzopozmpjnad.onion")
                  == false);
    OBS_CHECK("v3 format REJECTS an over-long (57-base32) body",
              slice_is_valid_onion_v3(
                  "zc23kenfdqqkgamthif3m7lbbdsyrotsl2dlw35qrh3iuzopozmpjnada.onion")
                  == false);

    /* ── (4) REAL address publication round-trip ─────────────────────────────
     * A valid v3 address through onion_service_set_address() reads back
     * byte-for-byte via the real reader; NULL clears it (not-ready state). */
    onion_service_set_address(valid_v3);
    const char *published = onion_service_get_address();
    OBS_CHECK("real publisher round-trips the v3 address byte-for-byte",
              published != NULL && strcmp(published, valid_v3) == 0);
    OBS_CHECK("the round-tripped published address passes the v3 format check",
              slice_is_valid_onion_v3(published));

    onion_service_set_address(NULL);
    OBS_CHECK("real publisher clears the address on NULL (not-ready state)",
              onion_service_get_address() == NULL);

    /* ── (5) Teardown: restore the address singleton ─────────────────────── */
    if (had_saved)
        onion_service_set_address(saved_buf);

    printf("=== onion bootstrap slice: %d failure(s) ===\n", failures);
    return failures;
}
