/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Reject converted reservation identities through the read-only probe. */
#include "test/test_core.h"
#include "models/database.h"
#include "models/wallet_tx.h"
#include "controllers/sync_controller.h"
#include "controllers/vault_intent_publish.h"
#include "controllers/wallet_helpers.h"
#include "json/json.h"
#include "wallet/wallet.h"
#include <stdio.h>
#include <string.h>

#define WFS_CHECK(name, expr) do { \
    printf("wallet_reservation_stored_class: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)
static bool wfs_save_note(struct node_db *ndb, uint8_t txid_seed,
                          const uint8_t ivk[32], int64_t value,
                          int block_height, uint8_t nf_seed)
{
    uint8_t txid[32], rcm[32], div[11], pk_d[32], cm[32], nf[32], memo[512];
    memset(txid, txid_seed, 32);
    memset(rcm, 0x05, 32);
    memset(div, 0x07, 11);
    memset(pk_d, 0x08, 32);
    memset(cm, txid_seed, 32);   /* distinct cm per note */
    memset(nf, nf_seed, 32);
    memset(memo, 0xF6, 512);
    return node_db_sync_sapling_note(ndb, txid, 0, value, rcm, memo, 512,
                                     ivk, div, pk_d, cm, nf, block_height);
}
static bool wfs_store_text_reservation(struct node_db *ndb,
                                     const uint8_t nf[32],
                                     const uint8_t spending_txid[32])
{
    sqlite3_stmt *s = NULL;
    bool changed = sqlite3_prepare_v2(ndb->db,
        "UPDATE wallet_sapling_notes SET spent_txid=? WHERE nullifier=? "
        "RETURNING typeof(spent_txid),length(spent_txid)",
        -1, &s, NULL) == SQLITE_OK;
    changed = changed && sqlite3_bind_text(s, 1, (const char *)spending_txid,
                                          32, SQLITE_TRANSIENT) == SQLITE_OK;
    changed = changed && sqlite3_bind_blob(s, 2, nf, 32,
                                          SQLITE_TRANSIENT) == SQLITE_OK;
    changed = changed && sqlite3_step(s) == SQLITE_ROW;
    if (changed) {
        const unsigned char *type = sqlite3_column_text(s, 0);
        changed = type && strcmp((const char *)type, "text") == 0 &&
                  sqlite3_column_int(s, 1) == 32;
    }
    changed = changed && sqlite3_step(s) == SQLITE_DONE;
    int finalized = sqlite3_finalize(s);
    return changed && finalized == SQLITE_OK;
}

static int wfs_text_publish_conflict(struct node_db *ndb,
                                     const uint8_t nf[32],
                                     const uint8_t spending_txid[32])
{
    int failures = 0;
    static struct wallet wallet;
    wallet_init(&wallet);
    struct spend_description spend = {0};
    memcpy(spend.nullifier.data, nf, 32);
    struct wallet_tx wtx = {0};
    transaction_init(&wtx.tx);
    wtx.tx.v_shielded_spend = &spend;
    wtx.tx.num_shielded_spend = 1;
    memcpy(wtx.tx.hash.data, spending_txid, 32);
    struct wallet_rpc_context ctx = {0};
    ctx.wallet = &wallet;
    ctx.node_db = ndb;
    uint8_t id[32] = {0x97};
    struct json_value result;
    json_init(&result);
    bool published = vault_intent_publish_prepared(
        &ctx, id, &wtx, 1713000000, &result);
    WFS_CHECK("production publication rejects TEXT reservation", !published);
    const char *code = json_get_str(json_get(&result, "code"));
    WFS_CHECK("production rejection is the reservation conflict",
        code && strcmp(code, "PREPARED_NOTE_CONFLICT") == 0);
    json_free(&result);
    /* spend is borrowed stack storage, never transaction_free() it. */
    wtx.tx.v_shielded_spend = NULL;
    wtx.tx.num_shielded_spend = 0;
    transaction_free(&wtx.tx);
    wallet_free(&wallet);
    return failures;
}

static int wfs_reservation_stored_class(struct node_db *ndb)
{
    int failures = 0;
    uint8_t ivk[32], nf[32], spending_txid[32], other_txid[32];
    memset(ivk, 0x95, sizeof(ivk));
    memset(nf, 0x94, sizeof(nf));
    memset(spending_txid, 'a', sizeof(spending_txid));
    memset(other_txid, 'b', sizeof(other_txid));
    bool saved = wfs_save_note(ndb, 0x96, ivk, 7000, 200, 0x94);
    WFS_CHECK("seeded stored-class reservation fixture", saved);
    if (!saved) return failures;
    WFS_CHECK("NULL reservation remains available",
        db_sapling_note_reservation_probe(ndb, nf, spending_txid) ==
            DB_NOTE_RESERVATION_AVAILABLE);
    WFS_CHECK("reserve exact BLOB identity",
        db_sapling_note_mark_spent(ndb, nf, spending_txid) == DB_MARK_SPENT_OK);
    WFS_CHECK("exact BLOB reservation permits retry",
        db_sapling_note_reservation_probe(ndb, nf, spending_txid) ==
            DB_NOTE_RESERVATION_SAME_TX);
    WFS_CHECK("different BLOB reservation conflicts",
        db_sapling_note_reservation_probe(ndb, nf, other_txid) ==
            DB_NOTE_RESERVATION_CONFLICT);

    bool changed = wfs_store_text_reservation(ndb, nf, spending_txid);
    WFS_CHECK("stored reservation is exactly 32 ASCII TEXT bytes", changed);
    if (changed) {
        failures += wfs_text_publish_conflict(ndb, nf, spending_txid);
        enum db_sapling_note_reservation_state state =
            db_sapling_note_reservation_probe(ndb, nf, spending_txid);
        WFS_CHECK("TEXT reservation refuses matching retry and availability",
            state == DB_NOTE_RESERVATION_CONFLICT);
    }
    return failures;
}


int test_wallet_reservation_stored_class(void);
int test_wallet_reservation_stored_class(void)
{
    int failures = 0;
    char dbdir[256], dbpath[320];
    test_make_tmpdir(dbdir, sizeof(dbdir),
                     "wallet_reservation_stored_class", "main");
    snprintf(dbpath, sizeof(dbpath), "%s/node.db", dbdir);
    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));
    bool opened = node_db_open(&ndb, dbpath);
    WFS_CHECK("node.db opened", opened);
    if (opened) failures += wfs_reservation_stored_class(&ndb);
    node_db_close(&ndb);
    (void)test_rm_rf_recursive(dbdir);
    return failures;
}
