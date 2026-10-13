/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Structured fleet wiki entries (`zcl.fleet_wiki_entry.v1`): the JSON form a
 * wiki page body may take so an agent can find a lesson without reading prose.
 *
 *   { "schema":     "zcl.fleet_wiki_entry.v1",
 *     "topic":      slug-like, 1..64 bytes of [a-z0-9-],
 *     "summary":    1..200 bytes,
 *     "lessons":    1..16 of { "rule": 1..200, "why": 0..400,
 *                              "evidence": 0..400 } bytes each,
 *     "applies_to": 0..16 strings of 1..64 bytes,
 *     "updated":    "YYYY-MM-DDTHH:MM:SSZ" }
 *
 * Every string is well-formed UTF-8 without control bytes. Only the keys
 * above are accepted, each at most once.
 * A page whose body is not such an entry stays a plain text page. */

#ifndef ZCL_SESSION_FLEET_WIKI_ENTRY_H
#define ZCL_SESSION_FLEET_WIKI_ENTRY_H

#include "json/json.h"

#include <stdbool.h>
#include <stddef.h>

#define FLEET_WIKI_ENTRY_SCHEMA "zcl.fleet_wiki_entry.v1"
#define FLEET_WIKI_DISCOVERY_IDENTITY_SCHEMA "zcl.fleet_wiki_revision.v1"

enum {
    FLEET_WIKI_ENTRY_SUMMARY_MAX = 200,
    FLEET_WIKI_ENTRY_RULE_MAX = 200,
    FLEET_WIKI_ENTRY_WHY_MAX = 400,
    FLEET_WIKI_ENTRY_EVIDENCE_MAX = 400,
    FLEET_WIKI_ENTRY_LESSONS_MAX = 16,
    FLEET_WIKI_ENTRY_APPLIES_MAX = 16,
    FLEET_WIKI_ENTRY_APPLIES_LEN_MAX = 64,
};

/* Parse and validate `text[0..len)`. On success returns true and `out`
 * (caller-initialised or fresh) owns the parsed object; free it with
 * json_free. On failure returns false, leaves `out` JSON_NULL, and
 * `*why_out` (optional) names the first violated rule as a static string. */
bool fleet_wiki_entry_parse(const char *text, size_t len,
                            struct json_value *out, const char **why_out);

/* True when `needle` is a substring of the entry's topic, summary or any
 * applies_to string. Case is folded for ASCII letters only. An empty needle
 * matches every entry. */
bool fleet_wiki_entry_matches(const struct json_value *entry,
                              const char *needle);

#endif
