/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: the command-line side of check-command-input-keys: the settings
 * from the environment, the sorted list of .def files under the scan root,
 * the git search that names the C files defining a registered handler, and
 * the termination-signal contract. The handler only records the signal; the
 * run stops at the next stage boundary, frees its memory and re-raises it.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <dirent.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include "gate_command_input_keys_priv.h"
#include "lintc.h"
#include "lintc_proc.h"
#include "lintc_sig.h"

enum { CIK_GRACE_MS = 2000 };

static bool cik_is_def(const char *path)
{
    const char *base = strrchr(path, '/');
    size_t n;
    base = base ? base + 1 : path;
    n = strlen(base);
    return n >= 4 && strcmp(base + n - 4, ".def") == 0;
}

/* The files `find ROOT -type f -name '*.def'` would print: symbolic links
 * are not followed and unreadable directories are skipped. */
static void cik_walk(const char *path, struct cik_list *out)
{
    struct stat st;
    DIR *d;
    struct dirent *e;
    if (lstat(path, &st) != 0)
        return;
    if (S_ISREG(st.st_mode) && cik_is_def(path))
        cik_list_add(out, path, strlen(path));
    if (!S_ISDIR(st.st_mode) || !(d = opendir(path)))
        return;
    while ((e = readdir(d))) {
        struct cik_buf child = { 0 };
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
            continue;
        cik_buf_puts(&child, path);
        if (path[strlen(path) - 1] != '/')
            cik_buf_putc(&child, '/');
        cik_buf_puts(&child, e->d_name);
        cik_walk(child.p, out);
        cik_buf_free(&child);
    }
    closedir(d);
}

static int cik_cmp_path(const void *a, const void *b)
{
    return strcmp(*(char *const *)a, *(char *const *)b);
}

/* Splits NUL-separated paths into the list. */
static void cik_split_paths(const char *data, size_t len, struct cik_list *out)
{
    for (size_t i = 0; i < len;) {
        size_t n = strlen(data + i);
        if (n)
            cik_list_add(out, data + i, n);
        i += n + 1;
    }
}

/* Repeats a failed search to pass git's own diagnostic through on stderr. */
static void cik_relay_error(struct lcp_spec spec)
{
    struct lcp_buf buf = { 0 };
    int code = 0;
    spec.mode = LCP_ERR;
    if (lcp_run(&spec, &buf, &code) == 0 && buf.data)
        fputs(buf.data, stderr);
    lcp_buf_free(&buf);
}

/* git grep -lzF over the tracked .c files for any of the patterns. Returns
 * the exit status of git grep; 127 when it cannot start, 2 when its output
 * could not be kept whole. A recorded signal ends the run here. */
static int cik_git_grep(void *ctx, const struct cik_list *pats,
                        struct cik_list *out)
{
    static char *const head[] = { "git", "grep", "-lzF" };
    static char *const tail[] = { "--", "*.c", NULL };
    char **argv = cik_mem(NULL, (pats->n * 2 + 6) * sizeof *argv, "cik_argv");
    struct lcp_spec spec = { .argv = argv, .mode = LCP_OUT,
                             .grace_ms = CIK_GRACE_MS };
    struct lcp_buf buf = { 0 };
    size_t k = 0;
    int code = 127, rc;
    (void)ctx;
    for (size_t i = 0; i < sizeof head / sizeof head[0]; i++)
        argv[k++] = head[i];
    for (size_t i = 0; i < pats->n; i++) {
        argv[k++] = "-e";
        argv[k++] = pats->v[i];
    }
    for (size_t i = 0; i < sizeof tail / sizeof tail[0]; i++)
        argv[k++] = tail[i];
    rc = lcp_run(&spec, &buf, &code);
    if (rc == 0 && !buf.lost)
        cik_split_paths(buf.data ? buf.data : "", buf.len, out);
    code = rc == 0 ? (buf.lost ? 2 : code) : 127;
    if (code >= 2 && !lsc_pending())
        cik_relay_error(spec);
    lcp_buf_free(&buf);
    free(argv);
    return code;
}

static struct cik_cfg cik_env_cfg(void)
{
    return (struct cik_cfg){
        .def_dir = env_or("ZCL_COMMAND_INPUT_KEYS_DEF_DIR",
                          "engine/composition/commands"),
        .baseline = env_or("ZCL_COMMAND_INPUT_KEYS_BASELINE",
                           "tools/lint/command_input_keys_baseline.txt"),
        .mode = env_or("ZCL_LINT_MODE", "FAIL"),
        .verbose = env_or("ZCL_COMMAND_INPUT_KEYS_VERBOSE", "0"),
        .leaf_floor = env_or("ZCL_COMMAND_INPUT_KEYS_LEAF_FLOOR", "160"),
        .fn_floor = env_or("ZCL_COMMAND_INPUT_KEYS_FN_FLOOR", "400"),
        .bound_floor = env_or("ZCL_COMMAND_INPUT_KEYS_BOUND_FLOOR", "150"),
        .resolved_floor = env_or("ZCL_COMMAND_INPUT_KEYS_RESOLVED_FLOOR", "100")
    };
}

int check_command_input_keys_run(int argc, char **argv)
{
    struct cik_cfg cfg = cik_env_cfg();
    struct cik_list defs = { 0 };
    int rc;
    (void)argc;
    (void)argv;
    if (lsc_install() != 0)
        return die("z23-lint: cannot install signal handlers\n", "");
    lsc_unblock();
    cik_walk(cfg.def_dir, &defs);
    qsort(defs.v, defs.n, sizeof *defs.v, cik_cmp_path);
    rc = cik_check(&cfg, &defs, cik_git_grep, NULL, stdout, stderr);
    cik_list_free(&defs);
    if (rc < 0)
        lsc_finish(lsc_pending());
    return rc < 0 ? 2 : rc;
}
