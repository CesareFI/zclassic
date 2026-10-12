/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: coverage for codeindex_is_stale(), the freshness verdict the
 * rebuild/refresh lanes consult before trusting an on-disk store. Its
 * contract: compare the live source digest AND depfile stats AND the
 * store format/schema metadata against what the store recorded; *stale
 * reports the verdict, the out-param is optional, and a null codeindex
 * fails closed with a stale verdict. */

#include "test/test_core.h"

#include "codeindex/codeindex.h"
#include "codeindex/codeindex_build.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static bool cis_write(const char *root, const char *rel, const char *content)
{
    char full[512];
    int n = snprintf(full, sizeof(full), "%s/%s", root, rel);
    if (n <= 0 || (size_t)n >= sizeof(full)) {
        fprintf(stderr, "codeindex stale: fixture path too long: %s/%s\n",
                root, rel);
        return false;
    }
    for (char *p = full + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(full, 0755) != 0 && errno != EEXIST) {
                perror(full);
                return false;
            }
            *p = '/';
        }
    }
    FILE *f = fopen(full, "wb");
    if (!f) {
        perror(full);
        return false;
    }
    size_t len = strlen(content);
    bool ok = fwrite(content, 1, len, f) == len;
    bool closed = fclose(f) == 0;
    if (!ok || !closed)
        fprintf(stderr, "codeindex stale: fixture write/close failed: %s\n",
                full);
    return closed && ok;
}

static bool cis_seed(const char *root)
{
    return cis_write(root, "core/modules/net/src/foo.c",
                     "int foo(void) { return 1; }\n") &&
           cis_write(root, "core/modules/net/include/net/foo.h",
                     "#ifndef FOO_H\n#define FOO_H\nint foo(void);\n#endif\n");
}

static int test_cis_null_refuses(void)
{
    int failures = 0;
    TEST("codeindex stale: null codeindex fails closed") {
        bool stale = false;
        ASSERT(!codeindex_is_stale(NULL, &stale));
        ASSERT(stale);
        ASSERT(!codeindex_is_stale(NULL, NULL));
        PASS();
    } _test_next:;
    return failures;
}

static int test_cis_fresh_index_is_current(void)
{
    int failures = 0;
    char dir[256] = {0};
    struct codeindex *ci = NULL;
    TEST("codeindex stale: a freshly built index is current") {
        test_make_tmpdir(dir, sizeof(dir), "cistale", "fresh");
        ASSERT(cis_seed(dir));
        ci = codeindex_open(dir);
        ASSERT(ci != NULL);
        bool stale = true;
        ASSERT(codeindex_is_stale(ci, &stale));
        ASSERT(!stale);
        /* The out-param is documented optional. */
        ASSERT(codeindex_is_stale(ci, NULL));
        PASS();
    } _test_next:;
    codeindex_close(ci);
    if (dir[0]) test_rm_rf_recursive(dir);
    return failures;
}

static int test_cis_source_edit_stales_then_rebuild_clears(void)
{
    int failures = 0;
    char dir[256] = {0};
    struct codeindex *ci = NULL;
    TEST("codeindex stale: a source edit stales; rebuild clears") {
        test_make_tmpdir(dir, sizeof(dir), "cistale", "edit");
        ASSERT(cis_seed(dir));
        ci = codeindex_open(dir);
        ASSERT(ci != NULL);
        bool stale = false;
        ASSERT(codeindex_is_stale(ci, &stale) && !stale);
        ASSERT(cis_write(dir, "core/modules/net/src/foo.c",
                         "int foo(void) { return 200; }\n"));
        ASSERT(codeindex_is_stale(ci, &stale));
        ASSERT(stale);
        ASSERT(codeindex_rebuild(ci));
        ASSERT(codeindex_is_stale(ci, &stale));
        ASSERT(!stale);
        PASS();
    } _test_next:;
    codeindex_close(ci);
    if (dir[0]) test_rm_rf_recursive(dir);
    return failures;
}

static int test_cis_deleted_source_stales(void)
{
    int failures = 0;
    char dir[256] = {0};
    struct codeindex *ci = NULL;
    TEST("codeindex stale: deleting a watched source stales the store") {
        test_make_tmpdir(dir, sizeof(dir), "cistale", "delete");
        ASSERT(cis_seed(dir));
        ci = codeindex_open(dir);
        ASSERT(ci != NULL);
        char header[512];
        int n = snprintf(header, sizeof(header),
                         "%s/core/modules/net/include/net/foo.h", dir);
        ASSERT(n > 0 && (size_t)n < sizeof(header));
        ASSERT(unlink(header) == 0);
        bool stale = false;
        ASSERT(codeindex_is_stale(ci, &stale));
        ASSERT(stale);
        PASS();
    } _test_next:;
    codeindex_close(ci);
    if (dir[0]) test_rm_rf_recursive(dir);
    return failures;
}

int test_codeindex_stale(void)
{
    int failures = 0;
    failures += test_cis_null_refuses();
    failures += test_cis_fresh_index_is_current();
    failures += test_cis_source_edit_stales_then_rebuild_clears();
    failures += test_cis_deleted_source_stales();
    printf("=== codeindex_stale: %d failures ===\n", failures);
    return failures;
}
