/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "test/test_core.h"

#include "config/boot_flyclient.h"
#include "models/database.h"
#include "models/utxo.h"
#include "crypto/sha3.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define BFC_CHECK(name, expr) do {                                      \
    printf("boot_flyclient: %s... ", (name));                         \
    if (expr) printf("OK\n");                                         \
    else { printf("FAIL\n"); failures++; }                            \
} while (0)

static bool snapshot_matches_fixture(const char *path, const uint8_t sha3[32])
{
    /* One full chunk followed by the existing empty chunk marker. */
    uint8_t expected[59] = {0};
    expected[0] = 1;
    memset(expected + 4, 0x42, 32);
    expected[40] = 1; /* value */
    expected[48] = 1; /* height */
    expected[53] = 1; /* compact script length */
    expected[54] = 0x51;
    uint8_t actual[60];
    FILE *fp = fopen(path, "rb");
    if (!fp) {
        fprintf(stderr, "snapshot fixture could not open %s\n", path);
        return false;
    }
    size_t bytes = fread(actual, 1, sizeof(actual), fp);
    bool read_ok = !ferror(fp);
    int closed = fclose(fp);

    /* Commitment uses script_len before script and height after script. */
    uint8_t commitment_input[54] = {0};
    memset(commitment_input, 0x42, 32);
    commitment_input[36] = 1;
    commitment_input[44] = 1;
    commitment_input[48] = 0x51;
    commitment_input[49] = 1;
    uint8_t commitment[32];
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    sha3_256_write(&ctx, commitment_input, sizeof(commitment_input));
    sha3_256_finalize(&ctx, commitment);
    return read_ok && closed == 0 && bytes == sizeof(expected) &&
           memcmp(actual, expected, sizeof(expected)) == 0 &&
           memcmp(sha3, commitment, sizeof(commitment)) == 0;
}

static int snapshot_write_checks(void)
{
    int failures = 0;
    struct node_db ndb;
    struct db_utxo utxo;
    uint8_t script[] = {0x51};
    uint8_t sha3[32];
    char snapshot_path[PATH_MAX];
    bool opened = node_db_open(&ndb, ":memory:");

    memset(&utxo, 0, sizeof(utxo));
    memset(utxo.txid, 0x42, sizeof(utxo.txid));
    utxo.value = 1;
    utxo.script = script;
    utxo.script_len = sizeof(script);
    utxo.script_type = SCRIPT_OTHER;
    utxo.height = 1;

    bool saved = opened && db_utxo_save(&ndb, &utxo);
    int snapshot_fd = test_mkstemp(snapshot_path, sizeof(snapshot_path),
                                   "boot_flyclient_snapshot");
    bool ready = snapshot_fd >= 0;
    if (ready)
        ready = close(snapshot_fd) == 0;
    BFC_CHECK("utxo snapshot serializer writes complete output",
              saved && ready &&
              boot_serialize_utxo_snapshot(&ndb, snapshot_path, 1,
                                           sha3) == 1 &&
              snapshot_matches_fixture(snapshot_path, sha3));
    if (snapshot_fd >= 0)
        BFC_CHECK("snapshot fixture cleanup", unlink(snapshot_path) == 0);

    if (opened)
        node_db_close(&ndb);
    return failures;
}

static int snapshot_output_failure_checks(void)
{
    int failures = 0;
#if defined(__linux__)
    struct node_db ndb;
    bool opened = node_db_open(&ndb, ":memory:");
    uint8_t sha3[32];
    const uint8_t zero[32] = {0};
    memset(sha3, 0xa5, sizeof(sha3));
    BFC_CHECK("empty snapshot serializer reports close failure",
              opened &&
              boot_serialize_utxo_snapshot(&ndb, "/dev/full", 500, sha3) == -1 &&
              memcmp(sha3, zero, sizeof(sha3)) == 0);

    struct db_utxo utxo = {0};
    uint8_t script[] = {0x51};
    memset(utxo.txid, 0x42, sizeof(utxo.txid));
    utxo.value = 1;
    utxo.script = script;
    utxo.script_len = sizeof(script);
    utxo.script_type = SCRIPT_OTHER;
    utxo.height = 1;
    bool saved = opened && db_utxo_save(&ndb, &utxo);
    memset(sha3, 0xa5, sizeof(sha3));
    BFC_CHECK("utxo snapshot serializer reports write failure",
              saved &&
              boot_serialize_utxo_snapshot(&ndb, "/dev/full", 1, sha3) == -1 &&
              memcmp(sha3, zero, sizeof(sha3)) == 0);
    if (opened)
        node_db_close(&ndb);
#endif
    return failures;
}

static int snapshot_refusal_checks(void)
{
    int failures = 0;
    uint8_t sha3[32];
    const uint8_t zero[32] = {0};
    memset(sha3, 0xa5, sizeof(sha3));
    BFC_CHECK("utxo snapshot serializer rejects missing db",
              boot_serialize_utxo_snapshot(NULL, NULL, 500, sha3) == -1 &&
              memcmp(sha3, zero, sizeof(sha3)) == 0);
    memset(sha3, 0xa5, sizeof(sha3));
    BFC_CHECK("model snapshot serializer clears output before refusal",
              db_utxo_serialize_snapshot(NULL, NULL, 500, sha3) == -1 &&
              memcmp(sha3, zero, sizeof(sha3)) == 0);
    struct node_db ndb;
    bool opened = node_db_open(&ndb, ":memory:");
    char directory[PATH_MAX];
    test_make_tmpdir(directory, sizeof(directory), "boot_snapshot_refusal",
                     "directory");
    memset(sha3, 0xa5, sizeof(sha3));
    BFC_CHECK("utxo snapshot serializer clears output on open failure",
              opened &&
              boot_serialize_utxo_snapshot(&ndb, directory, 500, sha3) == -1 &&
              memcmp(sha3, zero, sizeof(sha3)) == 0);
    BFC_CHECK("snapshot directory cleanup", rmdir(directory) == 0);
    if (opened)
        node_db_close(&ndb);
    return failures;
}

int test_boot_flyclient(void)
{
    int failures = 0;
    uint8_t hash_out[1][32];
    uint8_t sha3[32];
    uint64_t count = 0;

    BFC_CHECK("proof builder rejects missing args",
              !boot_build_flyclient_proof(NULL, NULL, NULL, NULL));

    BFC_CHECK("block hash loader rejects missing context",
              boot_load_block_hashes_range(0, 1, hash_out, 1, NULL) == 0);

    BFC_CHECK("block hash loader rejects missing output",
              boot_load_block_hashes_range(0, 1, NULL, 1, NULL) == 0);

    BFC_CHECK("utxo sha3 provider rejects missing context",
              !boot_compute_utxo_sha3(sha3, &count, NULL));

    failures += snapshot_write_checks();
    failures += snapshot_output_failure_checks();
    failures += snapshot_refusal_checks();

    BFC_CHECK("mmb leaf store prepare rejects missing service",
              !boot_prepare_mmb_leaf_store(NULL, NULL, NULL));

    return failures;
}
