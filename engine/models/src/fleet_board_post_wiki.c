/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Fleet board store: the wiki budget's read-only half. The per-key wiki
 * ceilings (and the test seam that lowers them), the decision under the
 * board write lock of whether a key at its stored ceiling may replace one of
 * its own superseded revisions, and the bound that keeps all wiki rows
 * within half of the store's byte cap. See models/fleet_board_post.h. The
 * replacement itself, like every write, is in fleet_board_post.c.
 *
 * ar-validate-skip:read-only-queries — this file never writes a row. */

#include "models/fleet_board_post.h"
#include "models/fleet_board_post_internal.h"

#include "models/activerecord.h"
#include "models/query_builder.h"
#include "util/log_macros.h"

#include <stdio.h>
#include <string.h>

#ifdef ZCL_TESTING
static int64_t s_test_wiki_window_max;
static int64_t s_test_wiki_stored_max;

void db_fleet_board_test_set_wiki_limits(int64_t window_max,
                                         int64_t stored_max)
{
    s_test_wiki_window_max = window_max > 0 ? window_max : 0;
    s_test_wiki_stored_max = stored_max > 0 ? stored_max : 0;
}
#endif

int64_t fleet_board_wiki_window_max(void)
{
#ifdef ZCL_TESTING
    if (s_test_wiki_window_max > 0)
        return s_test_wiki_window_max;
#endif
    return FLEET_BOARD_WIKI_QUOTA_WINDOW_MAX;
}

static int64_t board_wiki_stored_max(void)
{
#ifdef ZCL_TESTING
    if (s_test_wiki_stored_max > 0)
        return s_test_wiki_stored_max;
#endif
    return FLEET_BOARD_WIKI_QUOTA_STORED_MAX;
}

/* One stored wiki revision of one key, as much as the eviction rule reads. */
struct board_wiki_row {
    uint8_t id[32];
    char slug[FLEET_BOARD_SLUG_MAX + 1];
    int64_t created_at;
};
enum { BOARD_WIKI_SCAN_MAX = FLEET_BOARD_PUBLIC_QUOTA_STORED_MAX };

static const enum qb_column k_board_wiki_cols[] = {
    QB_C_fleet_board_posts_id,
    QB_C_fleet_board_posts_slug,
    QB_C_fleet_board_posts_created_at,
};

/* This key's wiki rows in this scope, oldest first. Returns the count, or -1
 * when the scan failed or the key holds more rows than the buffer, in which
 * case nobody can name a safe victim. Caller holds the board write lock. */
static int board_wiki_rows(struct node_db *ndb,
                           const struct fleet_board_post *post,
                           struct board_wiki_row *rows)
{
    struct qb q;
    qb_select(&q, QB_T_fleet_board_posts);
    qb_select_columns(&q, k_board_wiki_cols, 3);
    qb_where_blob(&q, QB_C_fleet_board_posts_host_pubkey, QB_EQ,
                  post->host_pubkey, 32);
    qb_where_int(&q, QB_C_fleet_board_posts_scope, QB_EQ, post->scope);
    qb_where_int(&q, QB_C_fleet_board_posts_kind, QB_EQ,
                 FLEET_BOARD_KIND_WIKI);
    qb_order_by(&q, QB_C_fleet_board_posts_created_at, QB_ASC);
    qb_order_by(&q, QB_C_fleet_board_posts_id, QB_ASC);
    sqlite3_stmt *s = NULL;
    if (!QB_PREPARE(ndb, &q, s))
        return -1;
    int n = 0;
    while (AR_STEP_ROW(s)) {
        if (n >= BOARD_WIKI_SCAN_MAX || sqlite3_column_bytes(s, 0) != 32) {
            sqlite3_finalize(s);
            return -1;
        }
        memcpy(rows[n].id, sqlite3_column_blob(s, 0), 32);
        (void)snprintf(rows[n].slug, sizeof(rows[n].slug), "%s",
                       (const char *)sqlite3_column_text(s, 1));
        rows[n].created_at = sqlite3_column_int64(s, 2);
        n++;
    }
    sqlite3_finalize(s);
    return n;
}

/* True when `other` is a later revision than (created_at, id): the same
 * order db_fleet_board_wiki_read resolves a page by. */
static bool board_wiki_later(const struct board_wiki_row *other,
                             int64_t created_at, const uint8_t id[32])
{
    return other->created_at > created_at ||
           (other->created_at == created_at &&
            memcmp(other->id, id, 32) > 0);
}

/* Row i is superseded when the incoming revision shares its slug (the
 * caller has already proven the incoming one is the newest of that slug) or
 * a later stored revision of the same slug exists. */
static bool board_wiki_superseded(const struct board_wiki_row *rows, int n,
                                  int i, const char *incoming_slug)
{
    if (strcmp(rows[i].slug, incoming_slug) == 0)
        return true;
    for (int j = 0; j < n; j++)
        if (j != i && strcmp(rows[j].slug, rows[i].slug) == 0 &&
            board_wiki_later(&rows[j], rows[i].created_at, rows[i].id))
            return true;
    return false;
}

/* The oldest superseded revision of this key, or false when every stored
 * revision is the newest of its slug, or when the incoming revision is
 * itself older than a stored revision of its slug (accepting it would only
 * churn the store). The newest revision of a slug is never named. */
static bool board_wiki_pick_victim(const struct board_wiki_row *rows, int n,
                                   const struct fleet_board_post *post,
                                   uint8_t victim[32])
{
    for (int i = 0; i < n; i++)
        if (strcmp(rows[i].slug, post->slug) == 0 &&
            board_wiki_later(&rows[i], (int64_t)post->created_at, post->id))
            return false;
    for (int i = 0; i < n; i++) {
        if (board_wiki_superseded(rows, n, i, post->slug)) {
            memcpy(victim, rows[i].id, 32);
            return true;
        }
    }
    return false;
}

/* The wiki stored leg, decided under the board write lock: room, or the id
 * of this key's own oldest superseded revision to replace, or the final
 * refusal. Only this key's rows in this scope are ever read, so an
 * incoming revision can never name another key's row. */
enum fleet_board_result fleet_board_wiki_room(
    struct node_db *ndb, const struct fleet_board_post *post, bool *evict,
    uint8_t victim[32])
{
    *evict = false;
    if (post->kind != FLEET_BOARD_KIND_WIKI ||
        post->scope == FLEET_BOARD_SCOPE_LEGACY_PUBLIC)
        return FLEET_BOARD_OK;
    int64_t resident = 0;
    if (!fleet_board_key_count(ndb, post->host_pubkey, post->scope, true, -1,
                               &resident)) {
        LOG_WARN("fleet.board", "wiki resident aggregate failed");
        return FLEET_BOARD_ERR_WIKI_QUOTA;
    }
    if (resident < board_wiki_stored_max())
        return FLEET_BOARD_OK;
    static struct board_wiki_row rows[BOARD_WIKI_SCAN_MAX];
    int n = board_wiki_rows(ndb, post, rows);
    if (n < 0 || !board_wiki_pick_victim(rows, n, post, victim))
        return FLEET_BOARD_ERR_WIKI_FULL;
    *evict = true;
    return FLEET_BOARD_OK;
}

/* Wiki rows are permanent, so together they may use at most half the
 * store's byte cap: they can never fill the store and block ordinary posts.
 * Caller holds the board write lock; a query error refuses. */
bool fleet_board_wiki_bytes_fit(struct node_db *ndb, int64_t body_bytes)
{
    struct qb q;
    int64_t bytes = 0;
    qb_select(&q, QB_T_fleet_board_posts);
    qb_select_agg(&q, QB_SUM, QB_C_fleet_board_posts_body_bytes, true);
    qb_where_int(&q, QB_C_fleet_board_posts_kind, QB_EQ,
                 FLEET_BOARD_KIND_WIKI);
    if (!fleet_board_aggregate_checked(ndb, &q, &bytes)) {
        LOG_WARN("fleet.board", "wiki byte-sum aggregate failed");
        return false;
    }
    int64_t half = fleet_board_max_bytes() / 2;
    return body_bytes <= half && bytes <= half - body_bytes;
}


/* Times of the last replacements, node-wide. Guarded by the board write
 * lock. */
static int64_t s_evict_at[FLEET_BOARD_WIKI_EVICT_MAX];
static unsigned s_evict_used;
static unsigned s_evict_next;

bool fleet_board_wiki_evict_allowed(int64_t now)
{
    unsigned recent = 0;
    for (unsigned i = 0; i < s_evict_used; i++)
        if (s_evict_at[i] > now - FLEET_BOARD_WIKI_EVICT_SECONDS)
            recent++;
    return recent < FLEET_BOARD_WIKI_EVICT_MAX;
}

void fleet_board_wiki_evict_note(int64_t now)
{
    s_evict_at[s_evict_next] = now;
    s_evict_next = (s_evict_next + 1u) % FLEET_BOARD_WIKI_EVICT_MAX;
    if (s_evict_used < FLEET_BOARD_WIKI_EVICT_MAX)
        s_evict_used++;
}

#ifdef ZCL_TESTING
void db_fleet_board_test_reset_wiki_evictions(void)
{
    s_evict_used = 0;
    s_evict_next = 0;
}
#endif
