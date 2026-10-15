/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: selftest of check-promotion-receipt-chain. Builds throwaway
 * repository roots whose promotion_receipt.sh is a shell fixture and proves
 * every verdict of the gate with its exit status and message: a clean chain,
 * each failure class, the exit-2 hollow scan, the append-only comparison
 * against HEAD, the exact refusal text, the fallback-key scan and the
 * ship.sh word-boundary match. SIGINT (once and twice), SIGTERM and SIGHUP
 * delivered after a readiness handshake over a pipe stop the fixture group,
 * including one that ignores the signal, remove the init scratch directory
 * and re-raise the signal.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <dirent.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include "gate_promotion_receipt_chain_priv.h"
#include "lintc.h"

enum { PRS_BUF = 16384, PRS_GRACE_MS = 300 };

struct prs_fx {
    char base[PRC_PATH];
    char root[PRC_PATH + 16];
    char out[PRC_PATH + 16];
    char calls[PRC_PATH + 16];
};

struct prs_case {
    const char *name;
    const char *ledger;     /* working ledger, NULL leaves it absent */
    const char *committed;  /* ledger committed at HEAD, NULL commits nothing */
    const char *signers;    /* NULL leaves it absent */
    const char *ship;       /* NULL leaves it absent */
    int git;                /* 0 no repository, 1 ledger and signers tracked, 2 nothing tracked */
    const char *tool_tail;  /* text after the fixture's final exit, never executed */
    const char *env_name;
    const char *env_value;
    int want;
    const char *needle;
    const char *needle2;
    const char *absent;     /* must not appear in the output */
};

static const char k_prs_tool[] =
    "if [ \"$1\" = \"$PRC_HOLD\" ]; then\n"
    "  [ -n \"$PRC_STUBBORN\" ] && trap '' INT TERM HUP\n"
    "  echo \"$$\" >&\"$PRC_READY_FD\"\n"
    "  [ -n \"$PRC_STUBBORN\" ] && while :; do sleep 1; done\n"
    "  exec sleep 30\n"
    "fi\n"
    "case \"$1\" in\n"
    "--self-test) case \"$PRC_SELF\" in\n"
    "    fail) echo 'self-test broke'; exit 1;;\n"
    "    nopass) echo 'quiet'; exit 0;;\n"
    "    *) echo 'PROMOTION RECEIPT SELF-TEST: PASS'; exit 0;; esac;;\n"
    "verify) printf '%s\\n' \"$ZCL_RECEIPT_KEY\" > \"$PRC_CALLS\"\n"
    "  echo 'chain intact (0 records)'; echo 'unrelated line'; exit \"${PRC_VERIFY_RC:-0}\";;\n"
    "init) [ \"$PRC_INIT\" = create ] && : > \"$ZCL_RECEIPT_LEDGER\"\n"
    "  if [ -z \"${ZCL_RECEIPT_KEY+x}\" ]; then printf '%s\\n' \"$PRC_INITMSG\" >&2; exit 1; fi\n"
    "  exit 0;;\n"
    "esac\n"
    "exit 0\n";

static const char k_prs_head[] = "# allowed signers\n";
static const char k_prs_key[] = "# allowed signers\nops ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA\n";
static const char k_prs_ship[] = "tools/scripts/promotion_receipt.sh \tappend --x\n";
static const char k_prs_rec1[] = "{\"seq\":1}\n";
static const char k_prs_rec2[] = "{\"seq\":1}\n{\"seq\":2}\n";

static int prs_fail(const char *what)
{
    fprintf(stderr, "check_promotion_receipt_chain selftest: FAIL - %s\n", what);
    return 1;
}

static int prs_put(const struct prs_fx *fx, const char *rel, const char *text)
{
    char path[PRC_PATH * 2];
    if (snprintf(path, sizeof path, "%s/%s", fx->root, rel) >= (int)sizeof path)
        return -1;
    if (!text)
        return unlink(path) != 0 && errno != ENOENT ? -1 : 0;
    return csr_write(path, text);
}

static int prs_scratch_parent(char *out, size_t cap)
{
    const char *tmp = getenv("TMPDIR");
    char root[PRC_PATH], probe[PRC_PATH + 32];
    if (tmp && tmp[0] == '/')
        return snprintf(out, cap, "%s", tmp) >= (int)cap ? -1 : 0;
    if (cic_repo_root(root, sizeof root)
        || snprintf(probe, sizeof probe, "%s/test-tmp/x", root) >= (int)sizeof probe
        || csr_mkdirs(probe) != 0)
        return -1;
    return snprintf(out, cap, "%s/test-tmp", root) >= (int)cap ? -1 : 0;
}

static int prs_sh(const struct prs_fx *fx, const char *script)
{
    char cmd[PRC_PATH * 3], q[PRC_PATH * 2], out[PRS_BUF];
    int code = 0;
    if (sh_single_quote(fx->root, q, sizeof q)
        || snprintf(cmd, sizeof cmd,
                    "cd %s && env -u GIT_DIR -u GIT_INDEX_FILE -u GIT_WORK_TREE "
                    "GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null "
                    "sh -c '%s' 2>&1", q, script) >= (int)sizeof cmd)
        return -1;
    return capture_cmd(cmd, out, sizeof out, &code) == 0 && code == 0 ? 0 : -1;
}

static int prs_repo(const struct prs_fx *fx, const struct prs_case *c)
{
    char script[1024];
    static const char commit[] = "git -c user.name=t -c user.email=t@t -c commit.gpgsign=false commit -q -m x";
    if (prs_sh(fx, "rm -rf .git") != 0 || c->git == 0)
        return c->git == 0 ? 0 : -1;
    snprintf(script, sizeof script, "git init -q . && %s%s%s",
             c->git == 1 && c->ledger ? "git add platform/deploy/promotion-receipts.jsonl && " : "",
             c->git == 1 && c->signers ? "git add platform/deploy/promotion-signers && " : "",
             c->committed ? commit : "true");
    if (c->committed && !(c->git == 1 && c->ledger))
        return -1;
    return prs_sh(fx, script);
}

static int prs_prepare(const struct prs_fx *fx, const struct prs_case *c)
{
    char tool[PRS_BUF];
    snprintf(tool, sizeof tool, "%s%s", k_prs_tool, c->tool_tail ? c->tool_tail : "");
    if (prs_put(fx, "tools/scripts/promotion_receipt.sh", tool)
        || prs_put(fx, "platform/deploy/promotion-signers", c->signers)
        || prs_put(fx, "tools/ship.sh", c->ship)
        || prs_put(fx, "platform/deploy/promotion-receipts.jsonl", c->committed ? c->committed : c->ledger)
        || prs_repo(fx, c))
        return -1;
    return c->committed ? prs_put(fx, "platform/deploy/promotion-receipts.jsonl", c->ledger) : 0;
}

static struct prc_cfg prs_cfg(const struct prs_fx *fx)
{
    return (struct prc_cfg){ .root = fx->root, .tool = "tools/scripts/promotion_receipt.sh",
                             .ledger = "platform/deploy/promotion-receipts.jsonl",
                             .signers = "platform/deploy/promotion-signers", .ship = "tools/ship.sh",
                             .grace_ms = PRS_GRACE_MS };
}

static void prs_child_env(const struct prs_fx *fx, const struct prs_case *c, const char *hold, int stubborn,
                          const int ready[2])
{
    char fd[16];
    snprintf(fd, sizeof fd, "%d", ready ? ready[1] : -1);
    unsetenv("GIT_DIR");
    unsetenv("GIT_INDEX_FILE");
    unsetenv("GIT_WORK_TREE");
    unsetenv("ZCL_RECEIPT_KEY");
    setenv("TMPDIR", fx->base, 1);
    setenv("PRC_CALLS", fx->calls, 1);
    setenv("PRC_HOLD", hold, 1);
    setenv("PRC_STUBBORN", stubborn ? "1" : "", 1);
    setenv("PRC_READY_FD", fd, 1);
    setenv("PRC_INITMSG", k_prc_want_nokey, 1);
    if (c && c->env_name)
        setenv(c->env_name, c->env_value, 1);
}

static pid_t prs_fork(const struct prs_fx *fx, const struct prs_case *c, const char *hold, int stubborn,
                      int ready[2])
{
    pid_t pid = fork();
    if (pid != 0)
        return pid;
    const struct prc_cfg cfg = prs_cfg(fx);
    if (freopen(fx->out, "w", stdout) == NULL || dup2(1, 2) < 0)
        _exit(125);
    if (ready)
        close(ready[0]);
    prs_child_env(fx, c, hold, stubborn, ready);
    _exit(prc_gate(&cfg));
}

static int prs_slurp(const char *path, char *buf, size_t cap)
{
    FILE *f = fopen(path, "r");
    size_t n = f ? fread(buf, 1, cap - 1, f) : 0;
    if (f)
        fclose(f);
    buf[n] = '\0';
    return f ? 0 : -1;
}

static int prs_judge(const struct prs_case *c, int st, const char *out)
{
    char what[PRS_BUF + 256];
    int bad = !WIFEXITED(st) || WEXITSTATUS(st) != c->want || (c->needle && !strstr(out, c->needle))
              || (c->needle2 && !strstr(out, c->needle2)) || (c->absent && strstr(out, c->absent));
    if (!bad)
        return 0;
    snprintf(what, sizeof what, "%s (exit %d, want %d)\n%s", c->name, WIFEXITED(st) ? WEXITSTATUS(st) : -1,
             c->want, out);
    return prs_fail(what);
}

static int prs_case(const struct prs_fx *fx, const struct prs_case *c)
{
    char out[PRS_BUF];
    int st = 0;
    if (prs_prepare(fx, c) != 0)
        return prs_fail("cannot prepare the fixture root");
    pid_t pid = prs_fork(fx, c, "", 0, NULL);
    if (pid < 0 || waitpid(pid, &st, 0) != pid || prs_slurp(fx->out, out, sizeof out) != 0)
        return prs_fail("the gate child did not finish");
    return prs_judge(c, st, out);
}

#define PRS_OK(name) name, k_prs_rec2, k_prs_rec2, k_prs_key, k_prs_ship, 1, NULL, NULL, NULL, 0

static int prs_good_cases(const struct prs_fx *fx)
{
    const struct prs_case cases[] = {
        { "an empty shipped ledger", "", "", k_prs_head, k_prs_ship, 1, NULL, NULL, NULL, 0,
          "lists no key yet and platform/deploy/promotion-receipts.jsonl holds no records",
          "append-only vs HEAD (HEAD holds no records", NULL },
        { PRS_OK("a signed chain"), "names 1 signing identity/identities for 2 record(s)",
          "(2 committed record(s) unchanged)", "FAIL" },
        { "an appended record", k_prs_rec2, k_prs_rec1, k_prs_key, k_prs_ship, 1, NULL, NULL, NULL, 0,
          "(1 committed record(s) unchanged)", "check_promotion_receipt_chain: clean", "FAIL" },
        { "no repository here", k_prs_rec2, NULL, k_prs_key, k_prs_ship, 0, NULL, NULL, NULL, 0,
          "note: not at a git toplevel here", "check_promotion_receipt_chain: clean", "FAIL" },
        { "a comment is not a fallback key", k_prs_rec2, k_prs_rec2, k_prs_key, k_prs_ship, 1,
          "# x=${ZCL_RECEIPT_KEY:-no}\n", NULL, NULL, 0, "declares no fallback signing key", NULL, "FAIL" },
    };
    char calls[256];
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        if (prs_case(fx, &cases[i]))
            return 1;
    }
    if (prs_slurp(fx->calls, calls, sizeof calls) != 0 || !strstr(calls, "/nonexistent/no-private-key-here"))
        return prs_fail("verify must run with the private key pointed at a missing path");
    return 0;
}

static int prs_bad_cases(const struct prs_fx *fx)
{
    const struct prs_case cases[] = {
        { "records without a signer", k_prs_rec1, k_prs_rec1, k_prs_head, k_prs_ship, 1, NULL, NULL, NULL, 1,
          "holds 1 record(s) but platform/deploy/promotion-signers lists no public key.", NULL, NULL },
        { "an empty signers file", "", "", "", k_prs_ship, 1, NULL, NULL, NULL, 2,
          "FATAL — scan set is '0' (< floor 1).", "promotion-signers read as empty", NULL },
        { "a missing signers file", "", "", NULL, k_prs_ship, 1, NULL, NULL, NULL, 1,
          "is missing — nothing could verify a receipt's authorship", NULL, NULL },
        { "a missing ledger", NULL, NULL, k_prs_head, k_prs_ship, 1, NULL, NULL, NULL, 1,
          "does not exist. The ledger file itself is the replication", NULL, NULL },
        { "a self-test that fails", "", "", k_prs_head, k_prs_ship, 1, NULL, "PRC_SELF", "fail", 1,
          "--self-test (rc=1; no 'PROMOTION RECEIPT SELF-TEST: PASS' line)", "self-test broke", NULL },
        { "a self-test without the pass line", "", "", k_prs_head, k_prs_ship, 1, NULL, "PRC_SELF", "nopass", 1,
          "--self-test (rc=0; no 'PROMOTION RECEIPT SELF-TEST: PASS' line)", NULL, NULL },
        { "a ledger that does not verify", "", "", k_prs_head, k_prs_ship, 1, NULL, "PRC_VERIFY_RC", "3", 1,
          "verify on the in-tree ledger (rc=3)", NULL, NULL },
        { "a rewritten record", "{\"seq\":9}\n", k_prs_rec1, k_prs_key, k_prs_ship, 1, NULL, NULL, NULL, 1,
          "is not append-only — the 1 record(s) committed at HEAD are no", NULL, NULL },
        { "a ledger that was never committed", k_prs_rec1, NULL, k_prs_key, k_prs_ship, 2, NULL, NULL, NULL, 1,
          "is not in HEAD yet (first commit of the ledger)", "is not tracked by git. Tracking is the whole", NULL },
    };
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        if (prs_case(fx, &cases[i]))
            return 1;
    }
    return 0;
}

static int prs_prong_cases(const struct prs_fx *fx)
{
    const struct prs_case cases[] = {
        { "a reworded refusal", k_prs_rec2, k_prs_rec2, k_prs_key, k_prs_ship, 1, NULL, "PRC_INITMSG",
          "refuse differently", 1, "init with no ZCL_RECEIPT_KEY must refuse with an exact message.",
          "got:  refuse differently", NULL },
        { "an init that creates the ledger", k_prs_rec2, k_prs_rec2, k_prs_key, k_prs_ship, 1, NULL,
          "PRC_INIT", "create", 1, "init refused but still created a ledger at the target path", NULL, NULL },
        { "a fallback signing key", k_prs_rec2, k_prs_rec2, k_prs_key, k_prs_ship, 1,
          "# x=${ZCL_RECEIPT_KEY:-no}\nK=\"${ZCL_RECEIPT_KEY:-$HOME/k}\"\n", NULL, NULL, 1,
          "gives ZCL_RECEIPT_KEY a fallback value:", ":K=\"${ZCL_RECEIPT_KEY:-$HOME/k}\"",
          "# x=" },
        { "a missing ship script", k_prs_rec2, k_prs_rec2, k_prs_key, NULL, 1, NULL, NULL, NULL, 1,
          "tools/ship.sh is missing", NULL, NULL },
        { "a ship script that stopped recording", k_prs_rec2, k_prs_rec2, k_prs_key, "echo hi\n", 1, NULL, NULL,
          NULL, 1, "no longer calls 'promotion_receipt.sh append'", NULL, NULL },
        { "append as a word prefix", k_prs_rec2, k_prs_rec2, k_prs_key, "promotion_receipt.sh appendix\n", 1,
          NULL, NULL, NULL, 1, "no longer calls 'promotion_receipt.sh append'", NULL, NULL },
    };
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        if (prs_case(fx, &cases[i]))
            return 1;
    }
    return 0;
}

static int prs_read_ready(int rfd)
{
    char line[64];
    size_t used = 0;
    while (used + 1 < sizeof line) {
        ssize_t n = read(rfd, line + used, 1);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0 || line[used] == '\n')
            break;
        used++;
    }
    line[used] = '\0';
    return atoi(line) > 0 ? 0 : -1;
}

/* True once every holder of the pipe's write end, the fixture group, is gone. */
static int prs_group_gone(int rfd)
{
    for (int tries = 0; tries < 100; tries++) {
        fd_set rd;
        struct timeval tv = { 0, 100000 };
        char c;
        FD_ZERO(&rd);
        FD_SET(rfd, &rd);
        if (select(rfd + 1, &rd, NULL, NULL, &tv) > 0 && read(rfd, &c, 1) == 0)
            return 1;
    }
    return 0;
}

static int prs_scratch_left(const char *base)
{
    DIR *d = opendir(base);
    struct dirent *e;
    int left = 0;
    while (d && (e = readdir(d)) != NULL)
        left += strncmp(e->d_name, "zcl_receipt_gate.", 17) == 0;
    if (d)
        closedir(d);
    return left;
}

static int prs_signal(const struct prs_fx *fx, const char *hold, int stubborn, int sig, int times)
{
    const struct prs_case good = { PRS_OK("signal"), NULL, NULL, NULL };
    int ready[2], st = 0;
    if (prs_prepare(fx, &good) != 0 || pipe(ready) != 0)
        return prs_fail("cannot prepare the signal case");
    pid_t gate = prs_fork(fx, &good, hold, stubborn, ready);
    close(ready[1]);
    int up = gate > 0 ? prs_read_ready(ready[0]) : -1;
    for (int i = 0; up == 0 && i < times; i++)
        kill(gate, sig);
    if (gate < 0 || waitpid(gate, &st, 0) != gate || up != 0) {
        close(ready[0]);
        return prs_fail("the gate never reached the fixture command");
    }
    int gone = prs_group_gone(ready[0]);
    close(ready[0]);
    if (!WIFSIGNALED(st) || WTERMSIG(st) != sig)
        return prs_fail("the gate did not re-raise the signal");
    if (prs_scratch_left(fx->base))
        return prs_fail("the init scratch directory outlived the signal");
    return gone ? 0 : prs_fail("the fixture command outlived the gate");
}

static int prs_signals(const struct prs_fx *fx)
{
    return prs_signal(fx, "--self-test", 0, SIGINT, 1) || prs_signal(fx, "--self-test", 0, SIGINT, 2)
        || prs_signal(fx, "init", 0, SIGINT, 1) || prs_signal(fx, "init", 0, SIGINT, 2)
        || prs_signal(fx, "init", 0, SIGTERM, 1) || prs_signal(fx, "init", 0, SIGHUP, 1)
        || prs_signal(fx, "init", 1, SIGTERM, 1) || prs_signal(fx, "verify", 1, SIGHUP, 1);
}

static int prs_build(struct prs_fx *fx)
{
    char parent[PRC_PATH];
    if (prs_scratch_parent(parent, sizeof parent) != 0
        || snprintf(fx->base, sizeof fx->base, "%s/receipt-gate-selftest.XXXXXX", parent) >= (int)sizeof fx->base
        || !mkdtemp(fx->base))
        return -1;
    snprintf(fx->root, sizeof fx->root, "%s/root", fx->base);
    snprintf(fx->out, sizeof fx->out, "%s/out.txt", fx->base);
    snprintf(fx->calls, sizeof fx->calls, "%s/calls.txt", fx->base);
    return csr_mkdirs(fx->root);
}

int check_promotion_receipt_chain_selftest(void)
{
    struct prs_fx fx = { { 0 }, { 0 }, { 0 }, { 0 } };
    int rc = prs_build(&fx) != 0 ? prs_fail("cannot build the fixture root") : 0;
    if (rc == 0)
        rc = prs_good_cases(&fx) || prs_bad_cases(&fx) || prs_prong_cases(&fx) || prs_signals(&fx);
    if (fx.base[0] && access(fx.base, F_OK) == 0)
        rap_rm_rf(fx.base);
    if (rc == 0)
        puts("check_promotion_receipt_chain selftest: ok (verdicts, exit statuses, append-only, "
             "refusal text, signal cleanup)");
    return rc;
}
