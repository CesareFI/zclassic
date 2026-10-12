/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Structured fleet wiki entries. See session/fleet_wiki_entry.h. */

#include "session/fleet_wiki_entry.h"

#include "session/fleet_board_proto.h"
#include "zutf8/zutf8.h"

#include <ctype.h>
#include <string.h>

static bool entry_fail(const char **why_out, const char *why)
{
    if (why_out)
        *why_out = why;
    return false;
}

/* A string value of min_len..max_len bytes with no control bytes. */
static bool entry_text_ok(const struct json_value *v, size_t min_len,
                          size_t max_len)
{
    if (!v || v->type != JSON_STR || !v->val.s)
        return false;
    size_t n = strlen(v->val.s);
    if (n < min_len || n > max_len || !zutf8_validate_n(v->val.s, n))
        return false;
    for (size_t i = 0; i < n; i++)
        if ((unsigned char)v->val.s[i] < 0x20u ||
            (unsigned char)v->val.s[i] == 0x7fu)
            return false;
    return true;
}

static bool entry_keys_in(const struct json_value *obj,
                         const char *const *allowed, size_t count)
{
    size_t present = 0;
    for (size_t k = 0; k < count; k++)
        if (json_get(obj, allowed[k]))
            present++;
    /* Every member is one of the allowed keys exactly once: an unknown key
     * or a repeated one makes the member count exceed the keys present. */
    return present == obj->num_children;
}

/* YYYY-MM-DDTHH:MM:SSZ with in-range fields. */
static bool entry_updated_ok(const struct json_value *v)
{
    static const char shape[] = "dddd-dd-ddTdd:dd:ddZ";
    if (!entry_text_ok(v, 20, 20))
        return false;
    const char *s = v->val.s;
    for (size_t i = 0; i < 20; i++) {
        bool digit = shape[i] == 'd';
        if (digit ? !isdigit((unsigned char)s[i]) : s[i] != shape[i])
            return false;
    }
    int month = (s[5] - '0') * 10 + (s[6] - '0');
    int day = (s[8] - '0') * 10 + (s[9] - '0');
    int hour = (s[11] - '0') * 10 + (s[12] - '0');
    int minute = (s[14] - '0') * 10 + (s[15] - '0');
    int second = (s[17] - '0') * 10 + (s[18] - '0');
    return month >= 1 && month <= 12 && day >= 1 && day <= 31 &&
           hour <= 23 && minute <= 59 && second <= 59;
}

static bool entry_lesson_ok(const struct json_value *lesson)
{
    static const char *const keys[] = {"rule", "why", "evidence"};
    return lesson && lesson->type == JSON_OBJ &&
           entry_keys_in(lesson, keys, 3) &&
           entry_text_ok(json_get(lesson, "rule"), 1,
                         FLEET_WIKI_ENTRY_RULE_MAX) &&
           entry_text_ok(json_get(lesson, "why"), 0,
                         FLEET_WIKI_ENTRY_WHY_MAX) &&
           entry_text_ok(json_get(lesson, "evidence"), 0,
                         FLEET_WIKI_ENTRY_EVIDENCE_MAX);
}

static bool entry_lessons_ok(const struct json_value *lessons)
{
    if (!lessons || lessons->type != JSON_ARR)
        return false;
    size_t n = json_size(lessons);
    if (n < 1 || n > FLEET_WIKI_ENTRY_LESSONS_MAX)
        return false;
    for (size_t i = 0; i < n; i++)
        if (!entry_lesson_ok(json_at(lessons, i)))
            return false;
    return true;
}

static bool entry_applies_ok(const struct json_value *applies)
{
    if (!applies || applies->type != JSON_ARR)
        return false;
    size_t n = json_size(applies);
    if (n > FLEET_WIKI_ENTRY_APPLIES_MAX)
        return false;
    for (size_t i = 0; i < n; i++)
        if (!entry_text_ok(json_at(applies, i), 1,
                           FLEET_WIKI_ENTRY_APPLIES_LEN_MAX))
            return false;
    return true;
}

/* Name of the first violated rule, or NULL when the object is a valid
 * entry. */
static const char *entry_violation(const struct json_value *root)
{
    static const char *const keys[] = {"schema", "topic", "summary",
                                       "lessons", "applies_to", "updated"};
    if (!root || root->type != JSON_OBJ || !entry_keys_in(root, keys, 6))
        return "entry must be a JSON object with only the schema's keys";
    const struct json_value *schema = json_get(root, "schema");
    if (!entry_text_ok(schema, 1, 64) ||
        strcmp(schema->val.s, FLEET_WIKI_ENTRY_SCHEMA) != 0)
        return "schema must be zcl.fleet_wiki_entry.v1";
    const struct json_value *topic = json_get(root, "topic");
    if (!entry_text_ok(topic, 1, FLEET_BOARD_SLUG_MAX) ||
        !fleet_board_slug_valid(topic->val.s))
        return "topic must be 1..64 bytes of [a-z0-9-]";
    if (!entry_text_ok(json_get(root, "summary"), 1,
                       FLEET_WIKI_ENTRY_SUMMARY_MAX))
        return "summary must be 1..200 printable bytes";
    if (!entry_lessons_ok(json_get(root, "lessons")))
        return "lessons must be 1..16 objects of rule, why, evidence "
               "within their byte limits";
    if (!entry_applies_ok(json_get(root, "applies_to")))
        return "applies_to must be at most 16 strings of 1..64 bytes";
    if (!entry_updated_ok(json_get(root, "updated")))
        return "updated must be ISO-8601 UTC, YYYY-MM-DDTHH:MM:SSZ";
    return NULL;
}

bool fleet_wiki_entry_parse(const char *text, size_t len,
                            struct json_value *out, const char **why_out)
{
    if (!text || !out)
        return entry_fail(why_out, "no entry text");
    json_init(out);
    if (len == 0 || text[0] != '{' || !json_read(out, text, len)) {
        json_free(out);
        json_init(out);
        return entry_fail(why_out, "entry is not a JSON object");
    }
    const char *why = entry_violation(out);
    if (why) {
        json_free(out);
        json_init(out);
        return entry_fail(why_out, why);
    }
    return true;
}

static unsigned char ascii_fold(unsigned char c)
{
    return c >= 'A' && c <= 'Z' ? (unsigned char)(c + ('a' - 'A')) : c;
}

/* Case-insensitive substring over ASCII letters only; every other byte
 * compares exactly. */
static bool contains_folded(const char *hay, const char *needle)
{
    size_t nl = strlen(needle);
    if (nl == 0)
        return true;
    for (; *hay; hay++) {
        size_t i = 0;
        while (i < nl && hay[i] &&
               ascii_fold((unsigned char)hay[i]) ==
                   ascii_fold((unsigned char)needle[i]))
            i++;
        if (i == nl)
            return true;
    }
    return false;
}

bool fleet_wiki_entry_matches(const struct json_value *entry,
                              const char *needle)
{
    if (!entry || !needle)
        return false;
    if (contains_folded(json_get_str(json_get(entry, "topic")), needle) ||
        contains_folded(json_get_str(json_get(entry, "summary")), needle))
        return true;
    const struct json_value *applies = json_get(entry, "applies_to");
    for (size_t i = 0; applies && i < json_size(applies); i++)
        if (contains_folded(json_get_str(json_at(applies, i)), needle))
            return true;
    return false;
}
