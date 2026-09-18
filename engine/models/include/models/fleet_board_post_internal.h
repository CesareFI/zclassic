/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Internal helper contract shared between the fleet board store's source
 * files (fleet_board_post.c, fleet_board_post_scan.c). NOT part of the
 * public model API — callers must include models/fleet_board_post.h.
 *
 * The row layout is derived once, in fleet_board_post.c, from the field
 * list; these three helpers are how its sibling reads a whole row without
 * spelling that layout a second time. */

#ifndef ZCL_DB_MODEL_FLEET_BOARD_POST_INTERNAL_H
#define ZCL_DB_MODEL_FLEET_BOARD_POST_INTERNAL_H

#include "models/fleet_board_post.h"
#include "models/query_builder.h"

#include <sqlite3.h>
#include <stdbool.h>
#include <stdint.h>

/* Start `q` as a SELECT of every stored column of fleet_board_posts, in
 * the order fleet_board_row_read decodes them. */
void fleet_board_select_row(struct qb *q);

/* Decode the current row of a statement started by fleet_board_select_row
 * and verify the post's id and signature again. A row that fails is logged
 * and zeroed except for its arrival number, and false is returned. */
bool fleet_board_row_read(sqlite3_stmt *s, struct db_fleet_board_post *out);

/* Narrow `q` to rows still discoverable at `now`: TTL not run out, or a
 * wiki revision. */
void fleet_board_where_discoverable(struct qb *q, int64_t now);

#endif /* ZCL_DB_MODEL_FLEET_BOARD_POST_INTERNAL_H */
