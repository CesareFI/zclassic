/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Wallet scan state in node_state.
 *
 * 'wallet_scan_height' is the height through which the wallet has read every
 * block. While a boot catch-up's range is unread it is written as
 * wallet_scanned_through_height(), never as best_block_height, and the
 * 'wallet_scan_incomplete' row records the unread start, the blocker, when it
 * was first seen, and the depth height: the best_block_height every stored
 * confirmation depth is measured from. Both rows are written by the flush in
 * its transaction, so the marker is cleared only together with the tx rows
 * of the rescan that read the range. The row is an additive key: a build
 * that does not know it reads the lower scan height and rescans from there. */

#include "wallet/wallet_sqlite.h"
#include "wallet/wallet.h"
#include "util/ar_step_readonly.h"
#include "util/log_macros.h"
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define WSS_MARKER_WRITE_SQL \
    "INSERT OR REPLACE INTO node_state(key,value)" \
    " VALUES('wallet_scan_incomplete',?)"
#define WSS_MARKER_CLEAR_SQL \
    "DELETE FROM node_state WHERE key='wallet_scan_incomplete'"
#define WSS_MARKER_READ_SQL \
    "SELECT value FROM node_state WHERE key='wallet_scan_incomplete'"
#define WSS_MARKER_UNREADABLE "WALLET_SCAN_MARKER_UNREADABLE"

static bool wss_write_marker(struct wallet_sqlite *ws, const struct wallet *w)
{
    char text[160];
    int n = snprintf(text, sizeof(text),
                     "from=%d depth=%d since=%" PRId64 " blocker=%s",
                     w->scan_retry.from, w->best_block_height,
                     w->scan_retry.since,
                     w->scan_retry.blocker[0] ? w->scan_retry.blocker : "-");
    sqlite3_stmt *s = NULL;
    if (n <= 0 || (size_t)n >= sizeof(text) ||
        sqlite3_prepare_v2(ws->db, w->scan_retry.pending
                               ? WSS_MARKER_WRITE_SQL : WSS_MARKER_CLEAR_SQL,
                           -1, &s, NULL) != SQLITE_OK || !s) {
        sqlite3_finalize(s);
        LOG_FAIL("wallet_sqlite", "write_scan_marker: prepare failed: %s",
                 sqlite3_errmsg(ws->db));
    }
    if (w->scan_retry.pending)
        sqlite3_bind_text(s, 1, text, n, SQLITE_TRANSIENT);
    bool ok = AR_STEP_WRITE(s) == SQLITE_DONE;
    sqlite3_finalize(s);
    if (!ok)
        LOG_FAIL("wallet_sqlite", "write_scan_marker: step failed: %s",
                 sqlite3_errmsg(ws->db));
    return true;
}

bool wallet_sqlite_write_scan_state(struct wallet_sqlite *ws,
                                    const struct wallet *w)
{
    if (!ws || !ws->open || !w)
        LOG_FAIL("wallet_sqlite", "write_scan_state: not open");
    return wallet_sqlite_write_scan_height(
               ws, wallet_scanned_through_height(w)) &&
           wss_write_marker(ws, w);
}

/* A present row that does not parse still means "incomplete": report it
 * from height 0 with no depth height, so the caller rescans rather than
 * trusting a scan height the marker was written to qualify. */
static void wss_parse_marker(const unsigned char *text,
                             struct wallet_scan_marker *out)
{
    int64_t since = 0;
    if (text && sscanf((const char *)text,
                       "from=%d depth=%d since=%" SCNd64 " blocker=%47s",
                       &out->from, &out->depth_height, &since,
                       out->blocker) == 4) {
        out->since = since;
        return;
    }
    out->from = 0;
    out->depth_height = -1;
    out->since = 0;
    snprintf(out->blocker, sizeof(out->blocker), "%s", WSS_MARKER_UNREADABLE);
}

bool wallet_sqlite_read_scan_marker(struct wallet_sqlite *ws,
                                    struct wallet_scan_marker *out)
{
    if (!ws || !ws->open || !out)
        return false;
    memset(out, 0, sizeof(*out));
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(ws->db, WSS_MARKER_READ_SQL, -1, &s, NULL) !=
            SQLITE_OK || !s) {
        LOG_WARN("wallet_sqlite", "read_scan_marker: prepare failed: %s",
                 sqlite3_errmsg(ws->db));
        sqlite3_finalize(s);
        return false;
    }
    bool present = AR_STEP_ROW_READONLY(s) == SQLITE_ROW;
    if (present)
        wss_parse_marker(sqlite3_column_text(s, 0), out);
    sqlite3_finalize(s);
    return present;
}

bool wallet_sqlite_read_scan_state(struct wallet_sqlite *ws, struct wallet *w)
{
    if (!w)
        return false;
    int height = 0;
    bool have_height = wallet_sqlite_read_scan_height(ws, &height);
    if (have_height)
        w->best_block_height = height;
    memset(&w->scan_retry, 0, sizeof(w->scan_retry));
    struct wallet_scan_marker m;
    if (!wallet_sqlite_read_scan_marker(ws, &m))
        return have_height;
    w->scan_retry.pending = true;
    w->scan_retry.from = m.from > 0 ? m.from : 0;
    w->scan_retry.since = m.since;
    snprintf(w->scan_retry.blocker, sizeof(w->scan_retry.blocker), "%s",
             m.blocker);
    /* Stored depths are measured from the depth height, which this build
     * writes only while the scan height sits below `from`. A scan height at
     * or past `from` came from a build that does not know the marker, and
     * its depths follow that scan height. */
    if (height < w->scan_retry.from && m.depth_height > height)
        w->best_block_height = m.depth_height;
    LOG_WARN("wallet", "%s: wallet scanned through %d only since %" PRId64
             "; this boot rescans from %d", w->scan_retry.blocker,
             wallet_scanned_through_height(w), w->scan_retry.since,
             w->scan_retry.from);
    return have_height;
}
