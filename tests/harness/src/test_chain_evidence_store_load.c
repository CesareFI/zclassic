/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: refusal-and-mapping matrix for chain_evidence_store_load(),
 * the typed loader chain-evidence consumers use at boot. Its contract is
 * precise and load-bearing: *out is zeroed on every failure path (missing
 * key is the COMMON boot case and must not leave caller-visible garbage),
 * a null out is rejected before any clearing, and malformed records are
 * named by code. The v1 wire mapping (16-byte legacy record: magic,
 * version, eight flag bytes) drives legacy source-class inference.
 * These cases cover behavior already implemented by the parent loader;
 * they do not demonstrate a production defect corrected by this change. */

#include "test/test_core.h"

#include "services/chain_evidence_persistence_service.h"
#include "services/chain_evidence_authority_service.h"
#include "models/database.h"

#include <string.h>

/* Mirror of the file-static wire constants in
 * engine/services/src/chain_evidence_persistence_service.c (CEC magic
 * "CECE", v1 record: magic u32, version u32, eight flag bytes = 16 B). */
#define CEC_TEST_MAGIC 0x43454345u
#define CEC_TEST_V1_BYTES 16u

static void cec_poison(struct chain_evidence_record *out)
{
    memset(out, 0xA5, sizeof(*out));
}

static bool cec_all_zero(const struct chain_evidence_record *out)
{
    static const struct chain_evidence_record zero;
    return memcmp(out, &zero, sizeof(*out)) == 0;
}

static bool cec_put_v1(struct node_db *ndb, const char *key,
                       const uint8_t flags[8])
{
    uint8_t wire[CEC_TEST_V1_BYTES];
    uint32_t magic = CEC_TEST_MAGIC;
    uint32_t version = 1;
    memcpy(wire, &magic, sizeof(magic));
    memcpy(wire + sizeof(magic), &version, sizeof(version));
    memcpy(wire + 8, flags, 8);
    return node_db_state_set(ndb, key, wire, sizeof(wire));
}

static int test_cec_null_out_refuses(void)
{
    int failures = 0;
    TEST("chain evidence load: null out refuses before clearing") {
        struct node_db ndb;
        memset(&ndb, 0, sizeof(ndb));
        struct zcl_result r =
            chain_evidence_store_load(&ndb, "cec.block_evidence.aa", NULL);
        ASSERT(!r.ok && r.code == -1);
        PASS();
    } _test_next:;
    return failures;
}

static int test_cec_null_ndb_zeroes_out(void)
{
    int failures = 0;
    TEST("chain evidence load: null ndb refuses with out zeroed") {
        struct chain_evidence_record out;
        cec_poison(&out);
        struct zcl_result r = chain_evidence_store_load(NULL, "k", &out);
        ASSERT(!r.ok && r.code == -2);
        ASSERT(cec_all_zero(&out));
        PASS();
    } _test_next:;
    return failures;
}

static int test_cec_missing_key_zeroes_out(void)
{
    int failures = 0;
    struct node_db ndb = {0};
    TEST("chain evidence load: missing key is typed and zeroed") {
        ASSERT(node_db_open(&ndb, ":memory:"));
        struct chain_evidence_record out;
        cec_poison(&out);
        struct zcl_result r =
            chain_evidence_store_load(&ndb, "cec.block_evidence.absent",
                                      &out);
        ASSERT(!r.ok && r.code == -3);
        ASSERT(cec_all_zero(&out));
        PASS();
    } _test_next:;
    node_db_close(&ndb);
    return failures;
}

static int test_cec_malformed_records_refuse_zeroed(void)
{
    int failures = 0;
    struct node_db ndb = {0};
    TEST("chain evidence load: short, bad-magic and bad-version refuse") {
        ASSERT(node_db_open(&ndb, ":memory:"));
        uint8_t short_wire[8] = {0};
        ASSERT(node_db_state_set(&ndb, "cec.bad.short", short_wire,
                                 sizeof(short_wire)));
        uint8_t bad_magic[CEC_TEST_V1_BYTES] = {0};
        uint32_t legacy_version = 1;
        memcpy(bad_magic + sizeof(uint32_t), &legacy_version,
               sizeof(legacy_version));
        ASSERT(node_db_state_set(&ndb, "cec.bad.magic", bad_magic,
                                 sizeof(bad_magic)));
        uint8_t bad_version[CEC_TEST_V1_BYTES] = {0};
        uint32_t magic = CEC_TEST_MAGIC;
        memcpy(bad_version, &magic, sizeof(magic));
        uint32_t version = 9;
        memcpy(bad_version + sizeof(magic), &version, sizeof(version));
        ASSERT(node_db_state_set(&ndb, "cec.bad.version", bad_version,
                                 sizeof(bad_version)));

        struct chain_evidence_record out;
        struct zcl_result r;
        cec_poison(&out);
        r = chain_evidence_store_load(&ndb, "cec.bad.short", &out);
        ASSERT(!r.ok && r.code == -4 && cec_all_zero(&out));
        cec_poison(&out);
        r = chain_evidence_store_load(&ndb, "cec.bad.magic", &out);
        ASSERT(!r.ok && r.code == -4 && cec_all_zero(&out));
        cec_poison(&out);
        r = chain_evidence_store_load(&ndb, "cec.bad.version", &out);
        ASSERT(!r.ok && r.code == -4 && cec_all_zero(&out));
        PASS();
    } _test_next:;
    node_db_close(&ndb);
    return failures;
}

static int test_cec_v1_full_flags_map_snapshot(void)
{
    int failures = 0;
    struct node_db ndb = {0};
    TEST("chain evidence load: v1 full flags map to SNAPSHOT class") {
        ASSERT(node_db_open(&ndb, ":memory:"));
        uint8_t flags[8] = {1, 1, 1, 0, 1, 1, 1, 0};
        ASSERT(cec_put_v1(&ndb, "cec.v1.snapshot", flags));
        struct chain_evidence_record out;
        cec_poison(&out);
        struct zcl_result r =
            chain_evidence_store_load(&ndb, "cec.v1.snapshot", &out);
        ASSERT(r.ok);
        ASSERT(out.publish_state == CEC_PUBLISH_LOCAL_EVIDENCE);
        ASSERT(out.header_ancestry_linked);
        ASSERT(out.chainwork_recomputed);
        ASSERT(out.nakamoto_selected_best_work);
        ASSERT(!out.block_bytes_hash_checked);
        ASSERT(out.utxo_sha3_verified);
        ASSERT(out.mmb_flyclient_proof_verified);
        ASSERT(out.chunk_hash_coverage_verified);
        ASSERT(!out.full_validation_complete);
        ASSERT(out.source_class == CEC_SOURCE_CLASS_SNAPSHOT);
        PASS();
    } _test_next:;
    node_db_close(&ndb);
    return failures;
}

static int test_cec_v1_source_class_cascade(void)
{
    int failures = 0;
    struct node_db ndb = {0};
    TEST("chain evidence load: v1 source class cascade and empty flags") {
        ASSERT(node_db_open(&ndb, ":memory:"));
        uint8_t p2p[8] = {0};
        p2p[3] = 1; /* block_bytes_hash_checked only */
        ASSERT(cec_put_v1(&ndb, "cec.v1.p2p", p2p));
        uint8_t none[8] = {0};
        ASSERT(cec_put_v1(&ndb, "cec.v1.none", none));

        struct chain_evidence_record out;
        struct zcl_result r =
            chain_evidence_store_load(&ndb, "cec.v1.p2p", &out);
        ASSERT(r.ok && out.source_class == CEC_SOURCE_CLASS_NATIVE_P2P &&
               out.block_bytes_hash_checked);
        r = chain_evidence_store_load(&ndb, "cec.v1.none", &out);
        ASSERT(r.ok && out.source_class == CEC_SOURCE_CLASS_UNKNOWN &&
               out.publish_state == CEC_PUBLISH_LOCAL_EVIDENCE);
        PASS();
    } _test_next:;
    node_db_close(&ndb);
    return failures;
}

int test_chain_evidence_store_load(void)
{
    int failures = 0;
    failures += test_cec_null_out_refuses();
    failures += test_cec_null_ndb_zeroes_out();
    failures += test_cec_missing_key_zeroes_out();
    failures += test_cec_malformed_records_refuse_zeroed();
    failures += test_cec_v1_full_flags_map_snapshot();
    failures += test_cec_v1_source_class_cascade();
    printf("=== chain_evidence_store_load: %d failures ===\n", failures);
    return failures;
}
