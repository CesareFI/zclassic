/* ztemplate tests: parsing, rendering, lookup failures, overflow
 * size reporting, comments, whitespace trimming, var enumeration,
 * and a randomized differential test against a reference renderer. */
#include "ztemplate/ztemplate.h"

#include <stdint.h>
#include <stdckdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(cond) \
    if (!(cond)) { \
        fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
        exit(1); \
    } \
    ((void)0)

/* Simple map lookup over (name, value) pairs. */
struct kv { const char *k; const char *v; };

static bool kv_lookup(const char *name, size_t name_len,
                      const char **value, size_t *value_len, void *ctx)
{
    const struct kv *kvs = ctx;
    for (size_t i = 0; kvs[i].k; i++) {
        if (strlen(kvs[i].k) == name_len &&
            memcmp(kvs[i].k, name, name_len) == 0) {
            *value = kvs[i].v;
            *value_len = strlen(kvs[i].v);
            return true;
        }
    }
    return false;
}

static void test_basic_render(void)
{
    const char *t = "Hello {{name}}, you have {{count}} messages.";
    ztemplate *tp = ztemplate_parse(t, strlen(t), NULL);
    CHECK(tp != NULL);
    struct kv kvs[] = { { "name", "Ada" }, { "count", "3" }, { 0, 0 } };
    char out[128];
    size_t n = 0;
    CHECK(ztemplate_render(tp, kv_lookup, kvs, out, sizeof out, &n)
          == ZTEMPLATE_OK);
    CHECK(strcmp(out, "Hello Ada, you have 3 messages.") == 0);
    CHECK(n == strlen(out));
    ztemplate_free(tp);
}

static void test_whitespace_and_reuse(void)
{
    const char *t = "{{  x  }}+{{x}}={{x}}";
    ztemplate *tp = ztemplate_parse(t, strlen(t), NULL);
    CHECK(tp != NULL);
    struct kv kvs[] = { { "x", "1" }, { 0, 0 } };
    char out[32];
    size_t n = 0;
    CHECK(ztemplate_render(tp, kv_lookup, kvs, out, sizeof out, &n)
          == ZTEMPLATE_OK);
    CHECK(strcmp(out, "1+1=1") == 0);
    CHECK(ztemplate_var_count(tp) == 1);
    ztemplate_free(tp);
}

static void test_comments(void)
{
    const char *t = "a{{! this is a comment }}b{{!}}{{x}}";
    ztemplate *tp = ztemplate_parse(t, strlen(t), NULL);
    CHECK(tp != NULL);
    struct kv kvs[] = { { "x", "!" }, { 0, 0 } };
    char out[16];
    size_t n = 0;
    CHECK(ztemplate_render(tp, kv_lookup, kvs, out, sizeof out, &n)
          == ZTEMPLATE_OK);
    CHECK(strcmp(out, "ab!") == 0);
    ztemplate_free(tp);
}

static void test_parse_errors(void)
{
    size_t err = 0;
    CHECK(ztemplate_parse("open {{var", 10, &err) == NULL);
    CHECK(err == 5);
    CHECK(ztemplate_parse("empty {{}}", 10, &err) == NULL);
    CHECK(ztemplate_parse("blank {{  }}", 12, &err) == NULL);
    CHECK(ztemplate_parse("bad {{na me}}", 13, &err) == NULL);
    CHECK(ztemplate_parse("bad {{na$me}}", 13, &err) == NULL);
    /* a lone } or single { is literal text */
    ztemplate *tp = ztemplate_parse("a}b{c", 5, NULL);
    CHECK(tp != NULL);
    struct kv kvs[] = { { 0, 0 } };
    char out[8];
    size_t n = 0;
    CHECK(ztemplate_render(tp, kv_lookup, kvs, out, sizeof out, &n)
          == ZTEMPLATE_OK);
    CHECK(strcmp(out, "a}b{c") == 0);
    ztemplate_free(tp);
}

static void test_unknown_var_fails_closed(void)
{
    const char *t = "v={{missing}}";
    ztemplate *tp = ztemplate_parse(t, strlen(t), NULL);
    CHECK(tp != NULL);
    struct kv kvs[] = { { 0, 0 } };
    char out[64];
    size_t n = 0;
    CHECK(ztemplate_render(tp, kv_lookup, kvs, out, sizeof out, &n)
          == ZTEMPLATE_UNKNOWN_VAR);
    ztemplate_free(tp);
}

static void test_overflow_reports_size(void)
{
    const char *t = "[{{big}}]";
    ztemplate *tp = ztemplate_parse(t, strlen(t), NULL);
    CHECK(tp != NULL);
    struct kv kvs[] = { { "big", "0123456789" }, { 0, 0 } };
    size_t need = 0;
    CHECK(ztemplate_render(tp, kv_lookup, kvs, NULL, 0, &need)
          == ZTEMPLATE_OVERFLOW);
    CHECK(need == 12);
    char small[5];
    size_t n = 0;
    CHECK(ztemplate_render(tp, kv_lookup, kvs, small, sizeof small, &n)
          == ZTEMPLATE_OVERFLOW);
    CHECK(n == 12);
    CHECK(small[4] == '\0'); /* truncated output stays terminated */
    char boundary[12];
    CHECK(ztemplate_render(tp, kv_lookup, kvs, boundary, sizeof boundary, &n)
          == ZTEMPLATE_OVERFLOW);
    char *exact = malloc(need + 1);
    CHECK(exact != NULL);
    CHECK(ztemplate_render(tp, kv_lookup, kvs, exact, need + 1, &n)
          == ZTEMPLATE_OK);
    CHECK(strcmp(exact, "[0123456789]") == 0);
    free(exact);
    ztemplate_free(tp);
}

struct collect { char names[16][32]; size_t n; };

static bool collect_one(const char *name, size_t len, void *ctx)
{
    struct collect *c = ctx;
    CHECK(c->n < 16);
    memcpy(c->names[c->n], name, len);
    c->names[c->n][len] = '\0';
    c->n++;
    return true;
}

static void test_foreach_dedup(void)
{
    const char *t = "{{a}}{{b}}{{a}}{{c}}{{b}}";
    ztemplate *tp = ztemplate_parse(t, strlen(t), NULL);
    CHECK(tp != NULL);
    struct collect c = { .n = 0 };
    CHECK(ztemplate_foreach_var(tp, collect_one, &c));
    CHECK(c.n == 3);
    CHECK(strcmp(c.names[0], "a") == 0);
    CHECK(strcmp(c.names[1], "b") == 0);
    CHECK(strcmp(c.names[2], "c") == 0);
    ztemplate_free(tp);
}

/* Differential: build random templates from a fragment alphabet,
 * render with the library and with a naive reference, compare. */
static unsigned long long rng_state;

static unsigned long long rng_next(void)
{
    rng_state ^= rng_state << 13;
    rng_state ^= rng_state >> 7;
    rng_state ^= rng_state << 17;
    return rng_state;
}

/* reference renderer: left-to-right scan */
static void ref_render(const char *t, const struct kv *kvs,
                       char *out, size_t cap)
{
    size_t o = 0;
    for (size_t p = 0; t[p];) {
        if (t[p] == '{' && t[p + 1] == '{') {
            const char *close = strstr(t + p + 2, "}}");
            CHECK(close != NULL);
            size_t nb = p + 2, ne = (size_t)(close - t);
            size_t next = ne + 2;
            if (t[nb] == '!') { p = next; continue; }
            while (nb < ne && (t[nb] == ' ' || t[nb] == '\t')) nb++;
            while (ne > nb && (t[ne - 1] == ' ' || t[ne - 1] == '\t')) ne--;
            for (size_t i = 0; kvs[i].k; i++) {
                if (strlen(kvs[i].k) == ne - nb &&
                    memcmp(kvs[i].k, t + nb, ne - nb) == 0) {
                    for (const char *v = kvs[i].v; *v && o + 1 < cap;)
                        out[o++] = *v++;
                    break;
                }
            }
            p = next;
        } else {
            if (o + 1 < cap) out[o++] = t[p];
            p++;
        }
    }
    out[o] = '\0';
}

static void test_differential(void)
{
    rng_state = 0xDEADBEEFCAFEF00Dull;
    static const char *frags[] = {
        "lit ", "{{a}}", "{{ b }}", "{{c}}", "{{! note }}",
        "{}", "} }", "x", "\t", "end."
    };
    struct kv kvs[] = {
        { "a", "A" }, { "b", "bee" }, { "c", "" }, { 0, 0 }
    };
    for (int iter = 0; iter < 3000; iter++) {
        char t[256];
        t[0] = '\0';
        size_t parts = rng_next() % 8;
        for (size_t i = 0; i < parts; i++)
            strcat(t, frags[rng_next() % 10]);
        ztemplate *tp = ztemplate_parse(t, strlen(t), NULL);
        CHECK(tp != NULL);
        char got[1024], want[1024];
        size_t n = 0;
        CHECK(ztemplate_render(tp, kv_lookup, kvs, got, sizeof got, &n)
              == ZTEMPLATE_OK);
        ref_render(t, kvs, want, sizeof want);
        if (strcmp(got, want) != 0) {
            fprintf(stderr, "iter %d got='%s' want='%s'\nt=", iter, got, want);
            for (const char *q = t; *q; q++) fprintf(stderr, "%02x ", (unsigned char)*q);
            fprintf(stderr, "\n");
            exit(1);
        }
        ztemplate_free(tp);
    }
}

static void test_parse_size_overflow(void)
{
    CHECK(ztemplate_parse("", SIZE_MAX, NULL) == NULL);
}

static bool huge_lookup(const char *name, size_t name_len,
                        const char **value, size_t *value_len, void *ctx)
{
    (void)name;
    (void)name_len;
    (void)ctx;
    /* Synthetic length metadata exercises arithmetic without allocating
     * an impossible span. Size-only rendering never reads this value. */
    *value = "v";
    *value_len = SIZE_MAX;
    return true;
}

static void test_render_size_overflow(void) {
    ztemplate *tp = ztemplate_parse("p{{big}}x", 9, NULL);
    CHECK(tp != NULL);
    size_t n = 99;
    CHECK(ztemplate_render(tp, huge_lookup, NULL, NULL, 0, &n)
          == ZTEMPLATE_OVERFLOW && n == SIZE_MAX);
    char out[6];
    memset(out, '!', sizeof out);
    CHECK(ztemplate_render(tp, huge_lookup, NULL, out, 4, &n)
          == ZTEMPLATE_OVERFLOW && n == SIZE_MAX &&
          out[0] == 'p' && out[1] == '\0' &&
          out[2] == '!' && out[3] == '!' &&
          out[4] == '!' && out[5] == '!');
    ztemplate_free(tp);
}

static void test_owned_text_allocation(void)
{
    CHECK(ztemplate_parse("x", SIZE_MAX, NULL) == NULL);
}

/* Exercise the real parser with deterministic successful zero-size allocation. */
static unsigned template_allocation_calls;
static size_t template_allocation_request;
static unsigned template_realloc_calls;
static bool template_refuse_realloc;

static void *template_fixture_malloc(size_t bytes) {
    size_t request = bytes ? bytes : 1;
    template_allocation_calls++;
    template_allocation_request = request;
    return malloc(request);
}

/* Boundary probes refuse before touching their artificial pointer; the only
 * successful fixture growth is initial allocation from NULL. */
static void *template_fixture_realloc(void *ptr, size_t bytes) {
    template_realloc_calls++;
    if (template_refuse_realloc) return NULL;
    CHECK(ptr == NULL);
    return template_fixture_malloc(bytes);
}

static void *template_fixture_calloc(size_t count, size_t bytes) {
    size_t total;
    if (ckd_mul(&total, count, bytes)) return NULL;
    void *memory = template_fixture_malloc(total);
    if (memory) memset(memory, 0, total);
    return memory;
}

void fixture_template_free(ztemplate *tp);
#define ztemplate_parse fixture_template_parse
#define ztemplate_free fixture_template_free
#define ztemplate_render fixture_template_render
#define ztemplate_var_count fixture_template_var_count
#define ztemplate_foreach_var fixture_template_foreach_var
#define malloc template_fixture_malloc
#define calloc template_fixture_calloc
#define realloc template_fixture_realloc
#include "../src/ztemplate.c"
#undef realloc
#undef calloc
#undef malloc
#undef ztemplate_parse
#undef ztemplate_free
#undef ztemplate_render
#undef ztemplate_var_count
#undef ztemplate_foreach_var

static void test_allocation_free_extent_refusal(void) {
    template_allocation_calls = 0;
    size_t position = 17;
    CHECK(fixture_template_parse("x", SIZE_MAX, &position) == NULL);
    CHECK(template_allocation_calls == 0);
    CHECK(position == 17);
    template_allocation_request = 0;
    void *zero = template_fixture_malloc(0);
    CHECK(zero != NULL);
    CHECK(template_allocation_request == 1);
    free(zero);
    template_allocation_calls = 0;
    ztemplate *empty = fixture_template_parse(NULL, 0, NULL);
    CHECK(empty != NULL);
    CHECK(template_allocation_calls == 2);
    fixture_template_free(empty);
}

static void test_segment_growth_bounds(void) {
    static const size_t capacities[] = {
        SIZE_MAX / 2 + 1, SIZE_MAX / (2 * sizeof(segment)) + 1};
    for (size_t i = 0; i < sizeof capacities / sizeof capacities[0]; i++) {
        segment marker = {SEG_VAR, 3, 7};
        ztemplate tp = {NULL, &marker, capacities[i], capacities[i]};
        template_realloc_calls = 0;
        template_refuse_realloc = true;
        CHECK(!seg_push(&tp, SEG_VAR, 4, 1));
        template_refuse_realloc = false;
        CHECK(template_realloc_calls == 0);
        CHECK(tp.segs == &marker && tp.nsegs == capacities[i] &&
              tp.cap_segs == capacities[i]);
        CHECK(marker.kind == SEG_VAR && marker.off == 3 && marker.len == 7);
    }
    ztemplate tp = {0};
    template_realloc_calls = 0;
    CHECK(seg_push(&tp, SEG_VAR, 3, 7));
    CHECK(template_realloc_calls == 1 && tp.nsegs == 1 && tp.cap_segs == 16);
    CHECK(tp.segs != NULL);
    CHECK(tp.segs[0].kind == SEG_VAR && tp.segs[0].off == 3 && tp.segs[0].len == 7);
    free(tp.segs);
}


int main(void)
{
    test_allocation_free_extent_refusal();
    test_segment_growth_bounds();
    test_owned_text_allocation();
    test_render_size_overflow();
    test_parse_size_overflow();
    test_basic_render();
    test_whitespace_and_reuse();
    test_comments();
    test_parse_errors();
    test_unknown_var_fails_closed();
    test_overflow_reports_size();
    test_foreach_dedup();
    test_differential();
    puts("test_ztemplate: all groups passed (basic ws comments parseerr unknown overflow foreach diff)");
    return 0;
}
