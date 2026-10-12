/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * z23-sem-replay plan side; see sem_replay_plan.h. */
#include "sem_replay_plan.h"

#include "base/safe_alloc.h"
#include "zutf8/zutf8.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SR_PLAN_MAX_PAGES 4096

/* path ends with name at a '.' boundary (or is name). */
static bool key_is(const char *path, const char *name)
{
    size_t pl = strlen(path), nl = strlen(name);
    if (pl < nl || strcmp(path + pl - nl, name) != 0)
        return false;
    return pl == nl || path[pl - nl - 1] == '.';
}

static bool in_facts(const char *path)
{
    return strncmp(path, "facts.", 6) == 0 || strstr(path, ".facts.") != NULL;
}

static long to_long(const char *v)
{
    return strcmp(v, "null") == 0 ? -1 : strtol(v, NULL, 10);
}

static bool copy_str(char *dst, size_t cap, const char *v)
{
    int n = snprintf(dst, cap, "%s", v);
    return n >= 0 && (size_t)n < cap;
}

static bool copy_tu(char *dst, size_t cap, const char *v)
{
    if (strlen(v) < cap) {
        copy_str(dst, cap, v);
        return true;
    }
    dst[0] = '\0';
    fprintf(stderr, "sem-replay: planner TU field exceeds capacity %zu\n", cap);
    return false;
}

struct pctx {
    struct sr_plan *p;
    bool first_page;
    bool row_open;
    bool failed;
    char row_path[1024];
    char row_aff[8], row_br[8], row_reason[128];
};

static void row_flush(struct pctx *c)
{
    if (!c->row_open || c->failed)
        return;
    char line[1400];
    snprintf(line, sizeof(line), "%s\t%s\t%s\t%s", c->row_path, c->row_aff,
             c->row_br, c->row_reason);
    (void)sr_strv_push(&c->p->tu_rows, line);
    if (strcmp(c->row_aff, "true") == 0)
        (void)sr_strv_push(&c->p->tus_affected, c->row_path);
    c->row_open = false;
}

/* Publish a TU after its object has been fully decoded. */
static void on_container_close(void *ctx, const char *path)
{
    struct pctx *c = ctx;
    if (in_facts(path) && key_is(path, "tus[]"))
        row_flush(c);
}

static bool on_tu(struct pctx *c, const char *path, const char *v)
{
    if (strstr(path, "tus[].") == NULL)
        return false;
    if (key_is(path, "tus[].path")) {
        c->failed |= !copy_tu(c->row_path, sizeof(c->row_path), v);
        c->row_open = !c->failed;
        copy_str(c->row_aff, sizeof(c->row_aff), "?");
        copy_str(c->row_br, sizeof(c->row_br), "?");
        c->row_reason[0] = '\0';
    } else if (key_is(path, "tus[].affected")) {
        c->failed |= !copy_tu(c->row_aff, sizeof(c->row_aff), v);
    } else if (key_is(path, "tus[].broadened")) {
        c->failed |= !copy_tu(c->row_br, sizeof(c->row_br), v);
    } else if (key_is(path, "tus[].reason")) {
        c->failed |= !copy_tu(c->row_reason, sizeof(c->row_reason), v);
    }
    return true;
}

static bool on_universe(struct sr_plan *p, const char *path, const char *v)
{
    if (strstr(path, "universe.") == NULL)
        return false;
    if (key_is(path, "universe.applied"))
        p->uni_applied = strcmp(v, "true") == 0;
    else if (key_is(path, "universe.complete"))
        p->uni_complete = strcmp(v, "true") == 0;
    else if (key_is(path, "universe.reason"))
        copy_str(p->uni_reason, sizeof(p->uni_reason), v);
    else if (key_is(path, "universe.detail"))
        copy_str(p->uni_detail, sizeof(p->uni_detail), v);
    else if (key_is(path, "universe.total"))
        p->uni_total = to_long(v);
    else if (key_is(path, "universe.affected"))
        p->uni_affected = to_long(v);
    else if (key_is(path, "universe.next_offset"))
        p->next_offset = to_long(v);
    return true;
}

static bool on_obligations(struct sr_plan *p, const char *path, const char *v)
{
    if (strstr(path, "obligations.") == NULL)
        return false;
    if (key_is(path, "obligations.reason"))
        copy_str(p->obl_reason, sizeof(p->obl_reason), v);
    else if (key_is(path, "obligations.plain"))
        p->obl_plain = to_long(v);
    else if (key_is(path, "obligations.facts"))
        p->obl_facts = to_long(v);
    else if (key_is(path, "obligations.plain_universal"))
        p->obl_plain_universal = strcmp(v, "true") == 0;
    else if (key_is(path, "obligations.groups[].group"))
        (void)sr_strv_push(&p->obl_groups, v);
    return true;
}

static void on_verdict(struct sr_plan *p, const char *path, const char *v)
{
    p->has_facts = true;
    if (key_is(path, "facts.narrowed"))
        p->narrowed = strcmp(v, "true") == 0;
    else if (key_is(path, "facts.reason"))
        copy_str(p->reason, sizeof(p->reason), v);
    else if (key_is(path, "facts.detail"))
        copy_str(p->detail, sizeof(p->detail), v);
    else if (key_is(path, "facts.seeds_total"))
        p->seeds_total = to_long(v);
}

static void on_plain(struct sr_plan *p, const char *path, const char *v)
{
    if (strncmp(path, "data.", 5) == 0)
        path += 5;
    if (strcmp(path, "closure_universal") == 0)
        p->closure_universal = strcmp(v, "true") == 0;
    if (strcmp(path, "execution_groups_total") == 0)
        p->groups_total = to_long(v);
    else if (strcmp(path, "execution_selector") == 0)
        copy_str(p->selector, sizeof(p->selector), v);
    else if (strcmp(path, "execution_groups[]") == 0)
        (void)sr_strv_push(&p->groups, v);
}

static void on_value(void *ctx, const char *path, const char *v)
{
    struct pctx *c = ctx;
    if (c->failed)
        return;
    if (!in_facts(path)) {
        if (c->first_page)
            on_plain(c->p, path, v);
        return;
    }
    if (on_tu(c, path, v) || on_universe(c->p, path, v))
        return;
    if (!c->first_page)
        return;
    if (!on_obligations(c->p, path, v))
        on_verdict(c->p, path, v);
}

static bool append(char **buf, size_t *n, size_t *cap, const char *s)
{
    size_t l = strlen(s);
    if (*n == SIZE_MAX || l > SIZE_MAX - *n - 1) {
        fprintf(stderr, "sem-replay: request size overflow\n");
        return false;
    }
    size_t need = *n + l + 1;
    if (need > *cap) {
        size_t nc = need > SIZE_MAX / 2 ? need : need * 2;
        char *nb = zcl_realloc(*buf, nc, "sem_replay_plan_request");
        if (nb == NULL) {
            fprintf(stderr, "sem-replay: out of memory building a request\n");
            return false;
        }
        *buf = nb;
        *cap = nc;
    }
    memcpy(*buf + *n, s, l + 1);
    *n += l;
    return true;
}

static bool append_string(char **buf, size_t *n, size_t *cap, const char *s)
{
    if (!zutf8_validate(s)) {
        fprintf(stderr, "sem-replay: invalid UTF-8 in request string\n");
        return false;
    }
    bool ok = append(buf, n, cap, "\"");
    for (const unsigned char *p = (const unsigned char *)s; ok && *p; p++) {
        char text[8] = {(char)*p, '\0'};
        if (*p == '"' || *p == '\\') {
            text[0] = '\\'; text[1] = (char)*p; text[2] = '\0';
        } else if (*p < 0x20)
            (void)snprintf(text, sizeof(text), "\\u%04x", (unsigned)*p);
        ok = append(buf, n, cap, text);
    }
    return ok && append(buf, n, cap, "\"");
}

static char *request_json(const struct sr_strv *files, const char *facts,
                          long offset)
{
    char *buf = NULL, tail[64];
    size_t n = 0, cap = 0;
    bool ok = append(&buf, &n, &cap, "--input={\"files\":[");
    for (size_t i = 0; ok && i < files->n; i++) {
        ok = append(&buf, &n, &cap, i ? "," : "") &&
             append_string(&buf, &n, &cap, files->v[i]);
    }
    ok = ok && append(&buf, &n, &cap, "]");
    if (ok && facts != NULL) {
        snprintf(tail, sizeof(tail), ",\"facts_offset\":%ld", offset);
        ok = append(&buf, &n, &cap, ",\"facts\":") &&
             append_string(&buf, &n, &cap, facts) &&
             append(&buf, &n, &cap, tail);
    }
    ok = ok && append(&buf, &n, &cap, "}");
    if (!ok) {
        free(buf);
        return NULL;
    }
    return buf;
}

static bool plan_page(const char *planner, const char *repo,
                      const struct sr_strv *files, const char *facts,
                      long offset, const char *raw, struct pctx *c)
{
    char *input = request_json(files, facts, offset);
    char *argv[] = {(char *)planner, "dev", "change", "plan", input, NULL};
    char *out = NULL;
    size_t len = 0;
    int rc = input ? sr_capture(argv, repo, NULL, &out, &len) : -1;
    if (raw != NULL && out != NULL)
        (void)sr_write_file(raw, out, len);
    c->p->next_offset = -1;
    bool ok = rc == 0 && out != NULL &&
        sr_json_flatten_with_close(out, len, on_value, on_container_close, c);
    c->row_open = false;
    ok = ok && !c->failed;
    if (!ok)
        snprintf(c->p->error, sizeof(c->p->error), "planner exit %d at offset %ld",
                 rc, offset);
    if (c->failed)
        snprintf(c->p->error, sizeof(c->p->error), "planner TU field overflow at offset %ld",
                 offset);
    free(out);
    free(input);
    return ok;
}

bool sr_plan_run(const char *planner, const char *repo,
                 const struct sr_strv *files, const char *facts,
                 const char *raw_prefix, struct sr_plan *out)
{
    memset(out, 0, sizeof(*out));
    out->groups_total = out->obl_plain = out->obl_facts = -1;
    out->uni_total = out->uni_affected = out->seeds_total = -1;
    struct pctx c = {.p = out, .first_page = true};
    long offset = 0;
    bool ok = true;
    for (int page = 0; ok && page < SR_PLAN_MAX_PAGES; page++) {
        char raw[SR_PATH];
        snprintf(raw, sizeof(raw), "%s.%d.json", raw_prefix ? raw_prefix : "", page);
        ok = plan_page(planner, repo, files, facts, offset,
                       raw_prefix ? raw : NULL, &c);
        c.first_page = false;
        if (!ok || facts == NULL || out->next_offset <= offset)
            break;
        offset = out->next_offset;
    }
    sr_strv_sort_unique(&out->tus_affected);
    out->ok = ok;
    return ok;
}

void sr_plan_free(struct sr_plan *p)
{
    sr_strv_free(&p->groups);
    sr_strv_free(&p->obl_groups);
    sr_strv_free(&p->tus_affected);
    sr_strv_free(&p->tu_rows);
}
