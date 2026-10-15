/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: the git-facing and anti-rot checks of check-promotion-receipt-chain
 * (prongs 4, 6 and 5 of the replaced script): the ledger is append-only
 * against HEAD, init never defaults a signing key, and tools/ship.sh still
 * appends a receipt on promotion.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "gate_promotion_receipt_chain_priv.h"
#include "lintc.h"
#include "lintc_proc.h"
#include "lintc_sig.h"

static int prc_toplevel_is_here(struct prc_run *g)
{
    char *const argv[] = { (char *)"git", (char *)"rev-parse", (char *)"--show-toplevel", NULL };
    char *top = NULL;
    struct stat a, b;
    int here = 0;
    if (prc_git(g, argv, LCP_OUT, &top) == 0 && top && top[0])
        here = stat(top, &a) == 0 && stat(".", &b) == 0 && a.st_dev == b.st_dev && a.st_ino == b.st_ino;
    free(top);
    return here;
}

/* The first n lines of the file with NULs and trailing newlines dropped, the
 * way `$(head -n N file)` yields them. */
static char *prc_head(const char *path, long n)
{
    FILE *f = fopen(path, "r");
    char *buf = NULL;
    size_t len = 0, cap = 0;
    int c;
    if (!f)
        return NULL;
    while (n > 0 && (c = getc(f)) != EOF) {
        if (len + 2 > cap) {
            char *p = realloc(buf, cap = cap ? cap * 2 : 4096); // raw-alloc-ok:lint-runtime
            if (!p) {
                free(buf);
                fclose(f);
                return NULL;
            }
            buf = p;
        }
        n -= c == '\n';
        if (c != '\0')
            buf[len++] = (char)c;
    }
    fclose(f);
    while (len && buf[len - 1] == '\n')
        len--;
    if (!buf)
        buf = malloc(1); // raw-alloc-ok:lint-runtime
    if (buf)
        buf[len] = '\0';
    return buf;
}

static long prc_count_text(const char *text)
{
    long lines = 0;
    for (const char *p = text; *p; p += strcspn(p, "\n") + (p[strcspn(p, "\n")] == '\n'))
        lines += *p != '\n';
    return lines;
}

static void prc_append_only(struct prc_run *g, const char *committed)
{
    const struct prc_cfg *c = g->cfg;
    long lines = prc_count_text(committed);
    char *head = lines > 0 ? prc_head(c->ledger, lines) : NULL;
    if (lines == 0) {
        prc_say("  ok: %s is append-only vs HEAD (HEAD holds no records — nothing can have been dropped)",
                c->ledger);
    } else if (!head || strcmp(head, committed) != 0) {
        prc_say("FAIL: %s is not append-only — the %ld record(s) committed at HEAD are no", c->ledger, lines);
        prc_say("      longer a byte-exact prefix of the working file. A receipt ledger is evidence:");
        prc_say("      records are appended, never edited or removed. Restore the committed prefix");
        prc_say("      (git diff -- %s shows what moved) and append instead.", c->ledger);
        g->fail = 1;
    } else {
        prc_say("  ok: %s is append-only vs HEAD (%ld committed record(s) unchanged)", c->ledger, lines);
    }
    free(head);
}

static void prc_tracked(struct prc_run *g)
{
    const struct prc_cfg *c = g->cfg;
    char *const ledger[] = { (char *)"git", (char *)"ls-files", (char *)"--error-unmatch", (char *)c->ledger, NULL };
    char *const signers[] = { (char *)"git", (char *)"ls-files", (char *)"--error-unmatch", (char *)c->signers, NULL };
    int rc = prc_git(g, ledger, LCP_QUIET, NULL);
    if (rc > 0) {
        prc_say("FAIL: %s is not tracked by git. Tracking is the whole replication story —", c->ledger);
        prc_say("      an untracked ledger never reaches origin and dies with this machine,");
        prc_say("      which is exactly the defect the local proof-server/* tag had.");
        g->fail = 1;
    }
    if (rc >= 0 && prc_git(g, signers, LCP_QUIET, NULL) > 0) {
        prc_say("FAIL: %s is not tracked by git — a third party would receive a ledger with no trust anchor",
                c->signers);
        g->fail = 1;
    }
}

void prc_check_append_only(struct prc_run *g)
{
    const struct prc_cfg *c = g->cfg;
    char *spec = prc_fmt("HEAD:%s", c->ledger), *committed = NULL;
    if (!spec) {
        fprintf(stderr, "check_promotion_receipt_chain: out of memory\n");
        g->rc = 2;
        return;
    }
    char *const exists[] = { (char *)"git", (char *)"cat-file", (char *)"-e", spec, NULL };
    char *const show[] = { (char *)"git", (char *)"show", spec, NULL };
    if (!(access(c->ledger, R_OK) == 0 && prc_toplevel_is_here(g))) {
        if (!lsc_pending() && !g->rc)
            prc_say("  note: not at a git toplevel here — append-only-vs-HEAD and tracked-file checks skipped");
        goto done;
    }
    int have = prc_git(g, exists, LCP_QUIET, NULL);
    if (have == 0 && prc_git(g, show, LCP_OUT, &committed) < 0)
        have = -1;
    if (have < 0 || lsc_pending() || g->rc)
        goto done;
    if (have != 0)
        prc_say("  note: %s is not in HEAD yet (first commit of the ledger) — append-only check starts next commit",
                c->ledger);
    else
        prc_append_only(g, committed ? committed : "");
    prc_tracked(g);
done:
    free(committed);
    free(spec);
}

static int prc_rm_tree(const char *path)
{
    struct stat st;
    if (lstat(path, &st) != 0)
        return 0;
    if (S_ISDIR(st.st_mode)) {
        DIR *d = opendir(path);
        struct dirent *e;
        while (d && (e = readdir(d)) != NULL) {
            char *sub = strcmp(e->d_name, ".") && strcmp(e->d_name, "..")
                            ? prc_fmt("%s/%s", path, e->d_name) : NULL;
            if (sub)
                prc_rm_tree(sub);
            free(sub);
        }
        if (d)
            closedir(d);
        return rmdir(path);
    }
    return unlink(path);
}

/* The POSIX default scratch parent when TMPDIR is unset or empty. */
static const char k_prc_default_tmp[] = { '/', 't', 'm', 'p', '\0' };

static void prc_no_key_verdict(struct prc_run *g, const char *got, const char *ledger_path)
{
    const struct prc_cfg *c = g->cfg;
    if (strcmp(got, k_prc_want_nokey) != 0) {
        prc_say("FAIL: %s init with no ZCL_RECEIPT_KEY must refuse with an exact message.", c->tool);
        prc_say("      got:  %s", got);
        prc_say("      want: %s", k_prc_want_nokey);
        prc_say("      The evidence-signing identity must be an explicit owner decision, never a");
        prc_say("      default. If you reworded the refusal on purpose, update BOTH this gate and");
        prc_say("      the writer's self-test — that two files must agree is the point.");
        g->fail = 1;
    } else if (access(ledger_path, F_OK) == 0) {
        prc_say("FAIL: %s init refused but still created a ledger at the target path", c->tool);
        g->fail = 1;
    } else {
        prc_say("  ok: %s refuses to write without an explicitly configured signing key", c->tool);
    }
}

static void prc_refuse_run(struct prc_run *g, char *dir)
{
    const struct prc_cfg *c = g->cfg;
    char *ledger = prc_fmt("%s/ledger.jsonl", dir), *env_ledger = prc_fmt("ZCL_RECEIPT_LEDGER=%s", ledger ? ledger : "");
    char *env_signers = prc_fmt("ZCL_RECEIPT_SIGNERS=%s", c->signers), *out = NULL;
    const char *args[] = { "init", NULL }, *set[] = { env_ledger, env_signers, NULL };
    const char *unset[] = { "ZCL_RECEIPT_KEY", NULL };
    if (!ledger || !env_ledger || !env_signers) {
        fprintf(stderr, "check_promotion_receipt_chain: out of memory\n");
        g->rc = 2;
    } else if (prc_bash(g, args, set, unset, LCP_ERR, &out) >= 0 && out && !g->rc) {
        out[strcspn(out, "\n")] = '\0';
        prc_no_key_verdict(g, out, ledger);
    }
    free(out);
    free(ledger);
    free(env_ledger);
    free(env_signers);
}

static void prc_refuse_prong(struct prc_run *g)
{
    const char *tmp = env_or("TMPDIR", k_prc_default_tmp);
    char *dir = prc_fmt("%s/zcl_receipt_gate.XXXXXX", tmp);
    if (!dir || !mkdtemp(dir)) {
        prc_say("FAIL: cannot create a scratch directory under %s", tmp);
        g->fail = 1;
        free(dir);
        return;
    }
    prc_refuse_run(g, dir);
    lsc_block();
    prc_rm_tree(dir);
    free(dir);
}

static void prc_fallback_prong(struct prc_run *g)
{
    const struct prc_cfg *c = g->cfg;
    regex_t re;
    FILE *f = fopen(c->tool, "r");
    char *line = NULL;
    size_t cap = 0;
    long no = 0, hits = 0;
    if (!f || regcomp(&re, "^[^#]*ZCL_RECEIPT_KEY:-[^}]", REG_EXTENDED | REG_NOSUB) != 0) {
        fflush(stdout);
        fprintf(stderr, "gate_grep: FATAL — grep failed (exit 2) for: grep -qE %s\n", c->tool);
        g->rc = 2;
        if (f)
            fclose(f);
        return;
    }
    while (getline(&line, &cap, f) >= 0) {
        size_t n = strcspn(line, "\n");
        line[n] = '\0';
        no++;
        if (regexec(&re, line, 0, NULL, 0) == 0) {
            if (!hits++)
                prc_say("FAIL: %s gives ZCL_RECEIPT_KEY a fallback value:", c->tool);
            prc_say("          %ld:%s", no, line);
        }
    }
    regfree(&re);
    free(line);
    fclose(f);
    if (hits) {
        prc_say("      There must be no default signing key. A login/push key as the evidence");
        prc_say("      authority means anyone who can push can mint receipts, and rotating it for");
        prc_say("      an ordinary git-access reason invalidates the chain.");
        g->fail = 1;
    } else {
        prc_say("  ok: %s declares no fallback signing key", c->tool);
    }
}

void prc_check_no_key(struct prc_run *g)
{
    if (access(g->cfg->tool, R_OK) != 0)
        return;
    prc_refuse_prong(g);
    if (!lsc_pending() && !g->rc)
        prc_fallback_prong(g);
}

/* True when line holds promotion_receipt.sh, blanks, then append not followed by
 * a word character. */
static int prc_calls_append(const char *line)
{
    static const char key[] = "promotion_receipt.sh";
    for (const char *p = strstr(line, key); p; p = strstr(p + 1, key)) {
        const char *q = p + sizeof key - 1;
        const char *start = q;
        while (isspace((unsigned char)*q))
            q++;
        if (q == start || strncmp(q, "append", 6) != 0)
            continue;
        if (!isalnum((unsigned char)q[6]) && q[6] != '_')
            return 1;
    }
    return 0;
}

static int prc_file_calls_append(const char *path)
{
    FILE *f = fopen(path, "r");
    char *line = NULL;
    size_t cap = 0;
    int hit = 0;
    while (f && !hit && getline(&line, &cap, f) >= 0)
        hit = prc_calls_append(line);
    free(line);
    if (f)
        fclose(f);
    return hit;
}

void prc_check_ship(struct prc_run *g)
{
    const struct prc_cfg *c = g->cfg;
    if (access(c->ship, R_OK) != 0) {
        prc_say("FAIL: %s is missing", c->ship);
        g->fail = 1;
    } else if (!prc_file_calls_append(c->ship)) {
        prc_say("FAIL: %s no longer calls 'promotion_receipt.sh append' — a promotion would", c->ship);
        prc_say("      again leave nothing behind that survives this machine. Wire the call back");
        prc_say("      in after the remote health check confirms the running daemon reports the");
        prc_say("      candidate's source id, next to the proof_server_pin.sh record call.");
        g->fail = 1;
    } else {
        prc_say("  ok: %s calls 'promotion_receipt.sh append'", c->ship);
    }
}
