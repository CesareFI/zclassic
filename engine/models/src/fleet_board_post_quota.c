/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Fleet board store: the per-key quota counts. Read-only queries that say
 * which of a key's two ceilings (rolling window, stored rows) a new post
 * would exceed. See models/fleet_board_post.h. The decisions they feed, and
 * every write, are in fleet_board_post.c.
 *
 * ar-validate-skip:read-only-queries — this file never writes a row. */

#include "models/fleet_board_post.h"
#include "models/fleet_board_post_internal.h"

#include "models/query_builder.h"
#include "util/log_macros.h"

/* One capped count of this key's rows in one scope. `since < 0` drops the
 * time floor. Neither leg filters on TTL: the window leg counts every
 * arrival because a burst is a burst even if every post in it expires in a
 * minute, and the resident leg counts every stored row because an expired
 * row this node has not reclaimed yet is still bytes this node is carrying
 * for the key. Caller holds the board lock; a query error refuses rather
 * than reporting an empty count. */
bool fleet_board_key_count(struct node_db *ndb,
                            const uint8_t host_pubkey[32], uint16_t scope,
                            bool wiki, int64_t since, int64_t *out)
{
    struct qb q;
    qb_select(&q, QB_T_fleet_board_posts);
    qb_select_count_star(&q);
    qb_where_blob(&q, QB_C_fleet_board_posts_host_pubkey, QB_EQ, host_pubkey,
                 32);
    qb_where_int(&q, QB_C_fleet_board_posts_scope, QB_EQ, scope);
    qb_where_int(&q, QB_C_fleet_board_posts_kind, wiki ? QB_EQ : QB_NE,
                 FLEET_BOARD_KIND_WIKI);
    if (since >= 0)
        qb_where_int(&q, QB_C_fleet_board_posts_received_at, QB_GT, since);
    return fleet_board_aggregate_checked(ndb, &q, out);
}

/* Two independent per-key ceilings, a rolling-window rate and a resident
 * stored-row count, counted over the key's rows in the post's own scope.
 * For a PUBLIC post, which carries no role grant at all, this is the only
 * anti-flood check it gets. A FLEET post passes the role gate first and
 * then this too: a grant says the key may write here, not that it may fill
 * the store every other key shares — and a paired peer's pull carries
 * other keys' posts in bulk. `received_at` drives the window, not the
 * post's own signed `created_at` — the signer chooses the latter, this
 * node chooses the former, so a flood cannot buy a fresh window by lying
 * about its clock.
 *
 * The two legs ask different questions on purpose. The window leg asks "is
 * this key bursting?" and counts every arrival inside the window. The
 * resident leg asks "how much of this node's finite, forever-carried store
 * is this key holding?" — which is every row still on disk for that key,
 * expired or not, because an unreclaimed row costs this node exactly what
 * a live one costs it. db_fleet_board_reclaim_expired is what hands those
 * slots back; this ceiling does not depend on it having run, so a node
 * that opts out of boot maintenance is still bounded.
 *
 * A wiki revision is counted against the wiki ceilings over the key's wiki
 * rows alone; every other kind is counted against the FLEET_BOARD_PUBLIC_
 * QUOTA_* ceilings over the key's non-wiki rows. The wiki stored leg is not
 * decided here: it is decided under the board write lock by
 * fleet_board_wiki_room, because a key at its ceiling may still replace its
 * own superseded revisions. */
enum board_quota fleet_board_key_quota(struct node_db *ndb,
                                        const struct fleet_board_post *post,
                                        int64_t now)
{
    const bool wiki = post->kind == FLEET_BOARD_KIND_WIKI;
    const int64_t window_max = wiki ? fleet_board_wiki_window_max()
                                    : FLEET_BOARD_PUBLIC_QUOTA_WINDOW_MAX;
    int64_t windowed = 0;
    int64_t since = now - (int64_t)FLEET_BOARD_PUBLIC_QUOTA_WINDOW_SECONDS;
    if (!fleet_board_key_count(ndb, post->host_pubkey, post->scope, wiki,
                               since, &windowed)) {
        LOG_WARN("fleet.board", "key quota window aggregate failed");
        return BOARD_QUOTA_ERROR;
    }
    if (windowed >= window_max)
        return BOARD_QUOTA_WINDOW;
    if (wiki)
        return BOARD_QUOTA_OK;
    int64_t resident = 0;
    if (!fleet_board_key_count(ndb, post->host_pubkey, post->scope, false,
                               -1, &resident)) {
        LOG_WARN("fleet.board", "key quota resident aggregate failed");
        return BOARD_QUOTA_ERROR;
    }
    return resident >= FLEET_BOARD_PUBLIC_QUOTA_STORED_MAX
               ? BOARD_QUOTA_STORED
               : BOARD_QUOTA_OK;
}
