/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Parse and validate one Z23_TOOL_V1 manifest for the
 *          readonly-local-v1 profile. A key the profile does not define is a
 *          refusal; nothing is inferred or widened. */

#include "toolgen.h"

#include "json/json.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>

enum key_kind { K_STR, K_INT, K_ARR };

struct keydef {
    const char *name;
    enum key_kind kind;
    bool required;
};

static const struct keydef k_keys[] = {
    {"profile", K_STR, true},          {"path", K_STR, true},
    {"parent", K_STR, true},           {"branch_summary", K_STR, false},
    {"handler", K_STR, true},          {"summary", K_STR, true},
    {"semantics", K_ARR, true},        {"input_schema", K_STR, true},
    {"output_schema", K_STR, true},    {"input_keys", K_ARR, true},
    {"positional_keys", K_ARR, false}, {"example", K_STR, true},
    {"tags", K_ARR, true},             {"authority", K_STR, true},
    {"dispatch_capabilities", K_ARR, false},
    {"budget_bytes", K_INT, true},     {"latency", K_STR, true},
    {"cost", K_STR, true},             {"test_group", K_STR, true},
};

/* Fields the profile fixes. A manifest naming one is refused by name. */
static const char *const k_fixed[] = {
    "effect", "risk", "scope", "lane", "lanes", "allowed_lanes", "mode",
    "confirmation", "confirm", "transport", "transports", "remote",
    "remote_class", "traits", "availability", "layer", "capabilities",
    "required_capabilities", "module_capabilities", NULL,
};

struct enum_row {
    const char *word;
    const char *symbol;
};

static const struct enum_row k_authority[] = {
    {"owner", "ZCL_COMMAND_AUTH_OWNER"},
    {"operator", "ZCL_COMMAND_AUTH_OPERATOR"},
    {NULL, NULL},
};
static const struct enum_row k_latency[] = {
    {"instant", "ZCL_COMMAND_LATENCY_INSTANT"},
    {"fast", "ZCL_COMMAND_LATENCY_FAST"},
    {"foreground", "ZCL_COMMAND_LATENCY_FOREGROUND"},
    {NULL, NULL},
};
static const struct enum_row k_cost[] = {
    {"tiny", "ZCL_COMMAND_COST_TINY"},
    {"low", "ZCL_COMMAND_COST_LOW"},
    {"moderate", "ZCL_COMMAND_COST_MODERATE"},
    {NULL, NULL},
};
static const struct enum_row k_caps[] = {
    {"chain_read", "ZCL_COMMAND_CAP_CHAIN_READ"},
    {"app_manifest_read", "ZCL_COMMAND_CAP_APP_MANIFEST_READ"},
    {"checkout_read", "ZCL_COMMAND_CAP_CHECKOUT_READ"},
    {"dev_state_read", "ZCL_COMMAND_CAP_DEV_STATE_READ"},
    {NULL, NULL},
};

static const struct keydef *find_def(const char *name)
{
    for (size_t i = 0; i < sizeof k_keys / sizeof k_keys[0]; i++)
        if (strcmp(k_keys[i].name, name) == 0)
            return &k_keys[i];
    return NULL;
}

static bool check_keys(const struct json_value *o, struct tg_err *e)
{
    if (o->type != JSON_OBJ)
        return tg_fail(e, "MANIFEST_NOT_OBJECT", "the manifest is not an object");
    for (size_t i = 0; i < o->num_children; i++) {
        const char *key = o->keys[i];
        for (size_t j = 0; j < i; j++)
            if (strcmp(o->keys[j], key) == 0)
                return tg_fail(e, "KEY_DUPLICATE", "key \"%s\" appears twice", key);
        if (find_def(key))
            continue;
        for (size_t f = 0; k_fixed[f]; f++)
            if (strcmp(k_fixed[f], key) == 0)
                return tg_fail(e, "KEY_OUTSIDE_PROFILE",
                               "\"%s\" is not settable under %s", key, TG_PROFILE);
        return tg_fail(e, "KEY_UNKNOWN", "key \"%s\" is not defined", key);
    }
    return true;
}

static bool check_shapes(const struct json_value *o, struct tg_err *e)
{
    for (size_t i = 0; i < sizeof k_keys / sizeof k_keys[0]; i++) {
        const struct keydef *d = &k_keys[i];
        const struct json_value *v = json_get(o, d->name);
        if (!v) {
            if (d->required)
                return tg_fail(e, "KEY_MISSING", "key \"%s\" is required", d->name);
            continue;
        }
        bool ok = (d->kind == K_STR && v->type == JSON_STR) ||
                  (d->kind == K_INT && v->type == JSON_INT) ||
                  (d->kind == K_ARR && v->type == JSON_ARR);
        if (!ok)
            return tg_fail(e, "VALUE_BAD_TYPE", "key \"%s\" has the wrong JSON type",
                           d->name);
    }
    return true;
}

static bool printable(const char *s)
{
    for (; *s; s++)
        if ((unsigned char)*s < 0x20u || (unsigned char)*s > 0x7eu)
            return false;
    return true;
}

static bool copy_text(const char *key, const char *s, size_t max, char *dst,
                      size_t cap, struct tg_err *e)
{
    size_t n = strlen(s);
    if (n == 0 || n > max || n >= cap || !printable(s))
        return tg_fail(e, "VALUE_BAD", "\"%s\" must be 1..%zu printable ASCII bytes",
                       key, max);
    memcpy(dst, s, n + 1u);
    return true;
}

static const char *str_of(const struct json_value *o, const char *key)
{
    const char *s = json_get_str(json_get(o, key));
    return s ? s : "";
}

static bool name_ok(const char *s, size_t max, bool dots)
{
    size_t n = strlen(s);
    if (n == 0 || n > max || !islower((unsigned char)s[0]) || s[n - 1u] == '.')
        return false;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        bool dot = dots && c == '.' && islower((unsigned char)s[i + 1u]);
        if (!(islower(c) || isdigit(c) || c == '_' || dot))
            return false;
    }
    return true;
}

static const struct tg_family *family_of(const char *path)
{
    for (size_t i = 0; i < tg_family_count; i++) {
        size_t n = strlen(tg_families[i].root);
        if (strncmp(path, tg_families[i].root, n) == 0 && path[n] == '.')
            return &tg_families[i];
    }
    return NULL;
}

static bool take_path(const struct json_value *o, struct tg_manifest *m,
                      struct tg_err *e)
{
    const char *path = str_of(o, "path");
    const char *parent = str_of(o, "parent");
    if (!name_ok(path, 96, true) || !strchr(path, '.'))
        return tg_fail(e, "PATH_BAD", "command path \"%s\" is not dotted lowercase names",
                       path);
    m->family = family_of(path);
    if (!m->family)
        return tg_fail(e, "PATH_FAMILY_UNSUPPORTED",
                       "no generated blocks exist for the root of \"%s\"", path);
    const char *dot = strrchr(path, '.');
    size_t plen = (size_t)(dot - path);
    if (strlen(parent) != plen || strncmp(parent, path, plen) != 0)
        return tg_fail(e, "PARENT_MISMATCH", "parent \"%s\" is not the parent of \"%s\"",
                       parent, path);
    return copy_text("path", path, 96, m->path, sizeof m->path, e) &&
           copy_text("parent", parent, 96, m->parent, sizeof m->parent, e);
}

static bool take_symbols(const struct json_value *o, struct tg_manifest *m,
                         struct tg_err *e)
{
    static const char prefix[] = "zcl_native_handle_";
    const char *h = str_of(o, "handler");
    const char *g = str_of(o, "test_group");
    if (strncmp(h, prefix, sizeof prefix - 1u) != 0 || !name_ok(h, 80, false))
        return tg_fail(e, "SYMBOL_BAD", "handler \"%s\" must be %s<lowercase_name>", h,
                       prefix);
    if (!name_ok(g, 64, false))
        return tg_fail(e, "TEST_GROUP_BAD", "test_group \"%s\" is not a lowercase name", g);
    return copy_text("handler", h, 80, m->handler, sizeof m->handler, e) &&
           copy_text("test_group", g, 64, m->test_group, sizeof m->test_group, e);
}

static bool schema_ok(const char *s)
{
    if (strncmp(s, "zcl.", 4) != 0 || strlen(s) > 96)
        return false;
    for (const char *p = s; *p; p++)
        if (!(islower((unsigned char)*p) || isdigit((unsigned char)*p) ||
              *p == '_' || *p == '.'))
            return false;
    const char *v = strrchr(s, '.');
    if (!v || v[1] != 'v' || !isdigit((unsigned char)v[2]))
        return false;
    for (const char *p = v + 2; *p; p++)
        if (!isdigit((unsigned char)*p))
            return false;
    return true;
}

static bool take_texts(const struct json_value *o, struct tg_manifest *m,
                       struct tg_err *e)
{
    const char *in = str_of(o, "input_schema");
    const char *out = str_of(o, "output_schema");
    const char *ex = str_of(o, "example");
    if (!schema_ok(in) || !schema_ok(out))
        return tg_fail(e, "SCHEMA_BAD", "schema names must look like zcl.<name>.v<N>");
    if (strncmp(ex, "z23 ", 4) != 0)
        return tg_fail(e, "VALUE_BAD", "\"example\" must begin with \"z23 \"");
    if (!copy_text("summary", str_of(o, "summary"), 160, m->summary, sizeof m->summary, e) ||
        !copy_text("input_schema", in, 96, m->input_schema, sizeof m->input_schema, e) ||
        !copy_text("output_schema", out, 96, m->output_schema, sizeof m->output_schema, e))
        return false;
    if (json_get(o, "branch_summary")) {
        m->has_branch = true;
        if (!copy_text("branch_summary", str_of(o, "branch_summary"), 120,
                       m->branch_summary, sizeof m->branch_summary, e))
            return false;
    }
    return copy_text("example", ex, 160, m->example, sizeof m->example, e);
}

static bool take_semantics(const struct json_value *o, struct tg_manifest *m,
                           struct tg_err *e)
{
    const struct json_value *a = json_get(o, "semantics");
    size_t used = 0;
    for (size_t i = 0; i < json_size(a); i++) {
        const struct json_value *piece = json_at(a, i);
        const char *s = piece && piece->type == JSON_STR ? json_get_str(piece) : NULL;
        size_t n = s ? strlen(s) : 0;
        if (!s || !printable(s) || used + n >= sizeof m->semantics)
            return tg_fail(e, "VALUE_BAD",
                           "\"semantics\" must be printable ASCII strings under %zu bytes",
                           sizeof m->semantics - 1u);
        memcpy(m->semantics + used, s, n);
        used += n;
    }
    m->semantics[used] = '\0';
    if (used == 0)
        return tg_fail(e, "VALUE_BAD", "\"semantics\" must not be empty");
    return true;
}

static bool tag_ok(const char *s)
{
    size_t n = strlen(s);
    if (n == 0 || n > 24 || !(islower((unsigned char)s[0]) || isdigit((unsigned char)s[0])))
        return false;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if (!(islower(c) || isdigit(c) || c == '_' || c == '-'))
            return false;
    }
    return true;
}

/* Joins an array of short names with commas; each entry is checked. */
static bool join_names(const struct json_value *o, const char *key, size_t max_items,
                       char *dst, size_t cap, struct tg_err *e)
{
    const struct json_value *a = json_get(o, key);
    size_t n = json_size(a);
    dst[0] = '\0';
    if (n > max_items)
        return tg_fail(e, "VALUE_BAD", "\"%s\" has more than %zu entries", key, max_items);
    for (size_t i = 0; i < n; i++) {
        const struct json_value *v = json_at(a, i);
        const char *s = v && v->type == JSON_STR ? json_get_str(v) : "";
        bool shape_ok = strcmp(key, "tags") == 0 ? tag_ok(s) : name_ok(s, 24, false);
        size_t used = strlen(dst);
        if (!shape_ok || used + strlen(s) + 2u >= cap)
            return tg_fail(e, "VALUE_BAD", "\"%s\" entry %zu is not a short lowercase name",
                           key, i);
        if (i)
            dst[used++] = ',';
        memcpy(dst + used, s, strlen(s) + 1u);
        for (size_t j = 0; j < i; j++) {
            const char *prev = json_get_str(json_at(a, j));
            if (prev && strcmp(prev, s) == 0)
                return tg_fail(e, "VALUE_BAD", "\"%s\" repeats \"%s\"", key, s);
        }
    }
    return true;
}

static bool lookup(const struct enum_row *rows, const char *key, const char *word,
                   const char **symbol, struct tg_err *e)
{
    for (size_t i = 0; rows[i].word; i++)
        if (strcmp(rows[i].word, word) == 0) {
            *symbol = rows[i].symbol;
            return true;
        }
    return tg_fail(e, "VALUE_BAD", "\"%s\" value \"%s\" is not allowed by %s", key, word,
                   TG_PROFILE);
}

static bool take_enums(const struct json_value *o, struct tg_manifest *m,
                       struct tg_err *e)
{
    const char *sym = NULL;
    if (!lookup(k_authority, "authority", str_of(o, "authority"), &sym, e))
        return false;
    snprintf(m->authority, sizeof m->authority, "%s", sym);
    if (!lookup(k_latency, "latency", str_of(o, "latency"), &sym, e))
        return false;
    snprintf(m->latency, sizeof m->latency, "%s", sym);
    if (!lookup(k_cost, "cost", str_of(o, "cost"), &sym, e))
        return false;
    snprintf(m->cost, sizeof m->cost, "%s", sym);
    return true;
}

static bool take_caps(const struct json_value *o, struct tg_manifest *m,
                      struct tg_err *e)
{
    const struct json_value *a = json_get(o, "dispatch_capabilities");
    size_t n = json_size(a);
    if (n > 4u)
        return tg_fail(e, "VALUE_BAD", "\"dispatch_capabilities\" lists too many entries");
    m->caps[0] = '\0';
    for (size_t i = 0; i < n; i++) {
        const struct json_value *v = json_at(a, i);
        const char *sym = NULL;
        if (!v || v->type != JSON_STR ||
            !lookup(k_caps, "dispatch_capabilities", json_get_str(v), &sym, e))
            return tg_fail(e, "VALUE_BAD", "\"dispatch_capabilities\" entry %zu is invalid", i);
        if (strstr(m->caps, sym))
            return tg_fail(e, "VALUE_BAD", "\"dispatch_capabilities\" repeats %s", sym);
        size_t used = strlen(m->caps);
        snprintf(m->caps + used, sizeof m->caps - used, "%s%s", i ? " | " : "", sym);
    }
    if (n == 0)
        snprintf(m->caps, sizeof m->caps, "ZCL_COMMAND_CAP_NONE");
    return true;
}

static bool subset_ok(const struct tg_manifest *m, struct tg_err *e)
{
    char copy[sizeof m->positional_keys];
    snprintf(copy, sizeof copy, "%s", m->positional_keys);
    for (char *tok = strtok(copy, ","); tok; tok = strtok(NULL, ",")) {
        char want[40];
        snprintf(want, sizeof want, ",%s,", tok);
        char hay[sizeof m->input_keys + 2];
        snprintf(hay, sizeof hay, ",%s,", m->input_keys);
        if (!strstr(hay, want))
            return tg_fail(e, "POSITIONAL_NOT_INPUT",
                           "positional key \"%s\" is not an input key", tok);
    }
    return true;
}

static bool take_lists(const struct json_value *o, struct tg_manifest *m,
                       struct tg_err *e)
{
    if (!join_names(o, "input_keys", 16, m->input_keys, sizeof m->input_keys, e) ||
        !join_names(o, "positional_keys", 16, m->positional_keys, sizeof m->positional_keys, e) ||
        !join_names(o, "tags", 16, m->tags, sizeof m->tags, e) || !subset_ok(m, e))
        return false;
    if (m->tags[0] == '\0')
        return tg_fail(e, "VALUE_BAD", "\"tags\" must not be empty");
    char hay[sizeof m->input_keys + 2];
    snprintf(hay, sizeof hay, ",%s,", m->input_keys);
    m->has_datadir = strstr(hay, ",datadir,") != NULL;
    int64_t budget = json_get_int(json_get(o, "budget_bytes"));
    if (budget < 1024 || budget > 4194304)
        return tg_fail(e, "VALUE_BAD", "\"budget_bytes\" must be 1024..4194304");
    m->budget_bytes = (unsigned)budget;
    return take_caps(o, m, e);
}

bool tg_manifest_parse(const char *body, size_t len, struct tg_manifest *m,
                       struct tg_err *e)
{
    struct json_value o;
    json_init(&o);
    bool ok = json_read(&o, body, len);
    if (!ok)
        return tg_fail(e, "MANIFEST_BAD_JSON", "the manifest is not valid JSON");
    ok = check_keys(&o, e) && check_shapes(&o, e);
    if (ok && strcmp(str_of(&o, "profile"), TG_PROFILE) != 0)
        ok = tg_fail(e, "PROFILE_UNSUPPORTED", "profile \"%s\" is not supported; use %s",
                     str_of(&o, "profile"), TG_PROFILE);
    ok = ok && take_path(&o, m, e) && take_symbols(&o, m, e) && take_texts(&o, m, e) &&
         take_semantics(&o, m, e) && take_enums(&o, m, e) && take_lists(&o, m, e);
    json_free(&o);
    return ok;
}
