/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: input-boundary and verdict-vocabulary coverage for
 * boot_mesh_status_begin(), the entry through which an operator asks one
 * paired peer for a bounded status snapshot. The deeper arms (not_paired,
 * revoked, expired, routing, send) need a composed boot context the unit
 * harness does not inject (mesh_status_service() has no test seam); what
 * IS reachable and load-bearing: the pairing-id boundary refuses malformed
 * input before any service state is touched, a valid id in a context-free
 * process degrades to UNAVAILABLE, and the closed verdict enum maps every
 * value to a stable wire-safe name. Zero test references existed. */

#include "test/test_core.h"

#include "config/boot_mesh_status.h"

#include <string.h>

#define MSB_HEX_64 \
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

static int test_msb_argument_boundary(void)
{
    int failures = 0;
    TEST("mesh status begin: malformed pairing ids refuse bad_argument") {
        uint8_t request_id[32];
        ASSERT(boot_mesh_status_begin(NULL, request_id) ==
               MESH_STATUS_BEGIN_BAD_ARGUMENT);
        /* wrong length */
        ASSERT(boot_mesh_status_begin(
                   "0123456789abcdef0123456789abcdef0123456789abcdef0123456",
                   request_id) == MESH_STATUS_BEGIN_BAD_ARGUMENT);
        ASSERT(boot_mesh_status_begin(
                   "0123456789abcdef0123456789abcdef0123456789abcdef012345678"
                   "9",
                   request_id) == MESH_STATUS_BEGIN_BAD_ARGUMENT);
        /* non-hex */
        ASSERT(boot_mesh_status_begin(
                   "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdeg",
                   request_id) == MESH_STATUS_BEGIN_BAD_ARGUMENT);
        /* uppercase is not lowercase-hex */
        ASSERT(boot_mesh_status_begin(
                   "0123456789ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef",
                   request_id) == MESH_STATUS_BEGIN_BAD_ARGUMENT);
        /* null out-param */
        ASSERT(boot_mesh_status_begin(MSB_HEX_64, NULL) ==
               MESH_STATUS_BEGIN_BAD_ARGUMENT);
        PASS();
    } _test_next:;
    return failures;
}

static int test_msb_no_service_unavailable(void)
{
    int failures = 0;
    TEST("mesh status begin: a valid id without boot context is "
         "unavailable") {
        uint8_t request_id[32];
        memset(request_id, 0xA5, sizeof(request_id));
        ASSERT(boot_mesh_status_begin(MSB_HEX_64, request_id) ==
               MESH_STATUS_BEGIN_UNAVAILABLE);
        PASS();
    } _test_next:;
    return failures;
}

static int test_msb_verdict_vocabulary(void)
{
    int failures = 0;
    TEST("mesh status begin: every verdict has a stable wire-safe name") {
        ASSERT(strcmp(boot_mesh_status_begin_result_string(
                          MESH_STATUS_BEGIN_OK), "ok") == 0);
        ASSERT(strcmp(boot_mesh_status_begin_result_string(
                          MESH_STATUS_BEGIN_BAD_ARGUMENT),
                      "bad_argument") == 0);
        ASSERT(strcmp(boot_mesh_status_begin_result_string(
                          MESH_STATUS_BEGIN_UNAVAILABLE),
                      "unavailable") == 0);
        ASSERT(strcmp(boot_mesh_status_begin_result_string(
                          MESH_STATUS_BEGIN_NOISE_DISABLED),
                      "noise_transport_disabled") == 0);
        ASSERT(strcmp(boot_mesh_status_begin_result_string(
                          MESH_STATUS_BEGIN_NOT_PAIRED), "not_paired") == 0);
        ASSERT(strcmp(boot_mesh_status_begin_result_string(
                          MESH_STATUS_BEGIN_REVOKED), "revoked") == 0);
        ASSERT(strcmp(boot_mesh_status_begin_result_string(
                          MESH_STATUS_BEGIN_EXPIRED), "expired") == 0);
        ASSERT(strcmp(boot_mesh_status_begin_result_string(
                          MESH_STATUS_BEGIN_PEER_NOT_CONNECTED),
                      "peer_not_connected") == 0);
        ASSERT(strcmp(boot_mesh_status_begin_result_string(
                          MESH_STATUS_BEGIN_ROUTE_PENDING),
                      "route_pending") == 0);
        ASSERT(strcmp(boot_mesh_status_begin_result_string(
                          MESH_STATUS_BEGIN_ROUTE_IDENTITY_MISMATCH),
                      "route_identity_mismatch") == 0);
        ASSERT(strcmp(boot_mesh_status_begin_result_string(
                          MESH_STATUS_BEGIN_ROUTE_DOWNGRADE),
                      "route_plaintext_downgrade") == 0);
        ASSERT(strcmp(boot_mesh_status_begin_result_string(
                          MESH_STATUS_BEGIN_IDENTITY_UNAVAILABLE),
                      "identity_unavailable") == 0);
        ASSERT(strcmp(boot_mesh_status_begin_result_string(
                          MESH_STATUS_BEGIN_PEER_IDENTITY_UNAVAILABLE),
                      "peer_identity_unavailable") == 0);
        ASSERT(strcmp(boot_mesh_status_begin_result_string(
                          MESH_STATUS_BEGIN_BUSY), "busy") == 0);
        ASSERT(strcmp(boot_mesh_status_begin_result_string(
                          MESH_STATUS_BEGIN_SEND_FAILED),
                      "send_failed") == 0);
        /* Out-of-range verdicts degrade to bad_argument, never to a
         * fabricated name. */
        ASSERT(strcmp(boot_mesh_status_begin_result_string(
                          (enum boot_mesh_status_begin_result)9999),
                      "bad_argument") == 0);
        PASS();
    } _test_next:;
    return failures;
}

int test_mesh_status_begin(void)
{
    int failures = 0;
    failures += test_msb_argument_boundary();
    failures += test_msb_no_service_unavailable();
    failures += test_msb_verdict_vocabulary();
    printf("=== mesh_status_begin: %d failures ===\n", failures);
    return failures;
}
