/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The `--metaverse-broker` argv mode: the operator-side entry point that stands
 * the whole boundary up in one process, so it can be driven by a test, a demo,
 * or a service unit without any of them re-implementing the choreography.
 *
 * THE ORDER OF THE FIRST THREE STEPS IS THE SECURITY PROPERTY, not a style
 * choice — see the ordering note atop agent_broker.c:
 *
 *   spawn the confined child   <- the child's address space is COW-copied HERE
 *   open the audit log         <- mints the signing key, AFTER the copy
 *   bind the authority         <- loads/mints the grant, AFTER the copy
 *
 * Moving either of the last two above the spawn would put a secret into the
 * child's inherited image. execve() then discards that image anyway, but the
 * ordering is what makes the property hold without depending on it.
 *
 * The provider is REGISTERED before this function is even entered (the
 * composition root runs from engine/entry/main.c), and registration is deliberately
 * inert: it installs static callbacks and non-secret configuration and loads
 * nothing. The authority appears only at `bind`, which is called below, after
 * the fork.
 */

#define _GNU_SOURCE

#include "session/agent_broker.h"

#include "base/hex.h"
#include "base/log_macros.h"
#include "json/json.h"
#include "platform/os_proc.h"
#include "platform/os_sandbox.h"
#include "platform/rng.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if !defined(_WIN32)
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

#define MODES_TAG "agent.broker.mode"

static const char *arg_value(int argc, char **argv, const char *prefix)
{
    size_t n = strlen(prefix);
    for (int i = 1; i < argc; i++)
        if (strncmp(argv[i], prefix, n) == 0)
            return argv[i] + n;
    return NULL;
}

static bool arg_present(int argc, char **argv, const char *flag)
{
    for (int i = 1; i < argc; i++)
        if (strcmp(argv[i], flag) == 0)
            return true;
    return false;
}

#if !defined(_WIN32)
static bool parse_identity(const char *text, unsigned long long limit,
                           unsigned long long *out)
{
    *out = 0;
    if (!text)
        return true;
    if (!text[0] || strspn(text, "0123456789") != strlen(text))
        LOG_FAIL(MODES_TAG, "identity must be nonempty decimal digits");
    errno = 0;
    char *end = NULL;
    unsigned long long value = strtoull(text, &end, 10);
    if (errno == ERANGE || *end || value > limit)
        LOG_FAIL(MODES_TAG, "identity is outside the supported range");
    *out = value;
    return true;
}

static bool parse_identities(const char *agent, const char *expected,
                             unsigned long long *agent_id,
                             unsigned long long *expected_id)
{
    unsigned long long uid_max = (uid_t)-1, gid_max = (gid_t)-1;
    unsigned long long agent_max = uid_max < gid_max ? uid_max : gid_max;
    if (!parse_identity(agent, agent_max, agent_id) ||
        !parse_identity(expected, uid_max, expected_id))
        LOG_FAIL(MODES_TAG, "refusing invalid broker identity option");
    return true;
}

static bool ensure_dir(const char *path)
{
    if (mkdir(path, 0700) == 0 || errno == EEXIST)
        return true;
    LOG_FAIL(MODES_TAG, "mkdir %s failed: %s", path, strerror(errno));
}

static bool prepare_broker_dir(const char *dir, char *scratch, size_t cap)
{
    int n = snprintf(scratch, cap, "%s/agent-scratch", dir);
    if (n < 0 || (size_t)n >= cap) {
        (void)fputs("broker: scratch pathname too long\n", stderr); // obs-ok:argv-mode-cli
        return false;
    }
    return ensure_dir(dir);
}

/* The child writes its ACHIEVED posture into its own scratch directory; the
 * broker reads it back. A hostile child could of course lie here — which is
 * why the fields that matter to the operator (Landlock ABI, whether the domain
 * was built at all) are the BROKER's own observations, recorded below, and the
 * child's self-report is only used for what only it can see (its own uid, and
 * whether its stage-2 filter landed). */
static void read_child_report(const char *scratch_dir,
                              struct agent_confine_report *out)
{
    char path[512];
    snprintf(path, sizeof(path), "%s/agent_report.json", scratch_dir);
    FILE *f = fopen(path, "re");
    if (!f)
        return;
    char buf[8192];
    size_t got = fread(buf, 1, sizeof(buf) - 1, f);
    (void)fclose(f);
    if (got == 0)
        return;
    buf[got] = '\0';

    struct json_value v;
    json_init(&v);
    if (json_read(&v, buf, got)) {
        out->ran_as_uid = (uid_t)json_get_int(json_get(&v, "uid"));
        out->ran_as_gid = (gid_t)json_get_int(json_get(&v, "gid"));
        out->landlock_applied = json_get_bool(json_get(&v, "landlock_applied"));
        out->seccomp_applied  = json_get_bool(json_get(&v, "seccomp_applied"));
        out->rlimits_applied  = json_get_bool(json_get(&v, "rlimits_applied"));
        const char *m = json_get_str(json_get(&v, "seccomp_method"));
        if (m)
            snprintf(out->seccomp_method, sizeof(out->seccomp_method), "%s", m);
        const char *p = json_get_str(json_get(&v, "uid_posture"));
        if (p && strcmp(p, "separate_uid") == 0)
            out->uid_posture = AGENT_CONFINE_SEPARATE_UID;
        else if (p && strcmp(p, "same_uid") == 0)
            out->uid_posture = AGENT_CONFINE_SAME_UID;
    }
    json_free(&v);
}
#endif

/* WHERE THE AUTHORITY COMES FROM.
 *
 * The grant and the property surface come from a registered provider (the
 * composition root wires the real property catalog and property grant
 * service). With none registered the broker binds NO authority and gets NO
 * seam, so it refuses every request with a named refusal; it still opens its
 * socket.
 *
 * REGISTRATION IS NOT PROVISIONING. A registered provider that was handed no
 * explicit grant source refuses to bind, and the broker is then exactly as
 * ungranted as one with no provider at all.
 *
 * The fixture provider exists only in a -DZCL_TESTING build and only when
 * `--fixture` is passed; in a production binary its symbol is not compiled or
 * declared. */
#if !defined(_WIN32)
static const struct agent_broker_provider *
resolve_provider(int argc, char **argv, const char **why)
{
    *why = NULL;
    if (arg_present(argc, argv, "--fixture")) {
#ifdef ZCL_TESTING
        agent_broker_install_fixture_provider();
#else
        *why = "--fixture names a fixture catalog that is not compiled into "
               "this binary (it exists only in a -DZCL_TESTING build)";
        return NULL;
#endif
    }
    const struct agent_broker_provider *p = agent_broker_provider_get();
    if (!p)
        *why = "no property provider is registered: this broker has no real "
               "catalog and no real grant, and will not substitute one";
    return p;
}
#endif

#if !defined(_WIN32)
static int broker_listen(struct agent_broker_session *s, const char *dir,
                         uid_t expected_uid, char *sockpath, size_t sockcap,
                         int *served)
{
    /* The listening surface: any local process can reach it, which is
     * exactly why the credential check is the first thing that runs. */
    snprintf(sockpath, sockcap, "%s/agent.sock", dir);
    s->expect.require_uid = true;
    s->expect.uid = expected_uid;

    int lfd = agent_broker_listen(sockpath);
    if (lfd < 0) {
        (void)fprintf(stderr, "broker: cannot listen on %s\n", sockpath);  // obs-ok:argv-mode-cli
        return 6;
    }
    printf("broker: listening on %s expecting uid=%u\n", sockpath,
           (unsigned)s->expect.uid);
    (void)fflush(stdout);
    int r = agent_broker_accept_once(s, lfd, 15000);
    *served = r > 0 ? 1 : 0;
    (void)close(lfd);
    (void)unlink(sockpath);
    return 0;
}

static int broker_pair(struct agent_broker_session *s,
                       const struct agent_spawn_result *spawned,
                       uid_t expected_uid, const char *reqs
#ifdef ZCL_TESTING
                       , const char *revoke_s
#endif
                       , int *served)
{
    /* The socketpair surface: the peer must be the EXACT process we
     * spawned. pid plus uid, not uid alone — on a host where no uid switch
     * was possible, uid alone would admit any process of the operator. */
    s->expect.require_pid = true;
    s->expect.pid = spawned->pid;
    s->expect.require_uid = true;
    s->expect.uid = expected_uid;

    uint64_t max = reqs ? strtoull(reqs, NULL, 10) : 0;
#ifdef ZCL_TESTING
    uint64_t revoke_after = revoke_s ? strtoull(revoke_s, NULL, 10) : 0;
    bool revoked_once = false;
#endif

    if (!agent_broker_identify_peer(spawned->sock, &s->peer)) {
        (void)fprintf(stderr, "broker: no peer credentials on the pair\n");  // obs-ok:argv-mode-cli
        return 7;
    }
    char why[160];
    if (!agent_broker_peer_authorized(&s->peer, &s->expect, why,
                                      sizeof(why))) {
        (void)fprintf(stderr, "broker: refusing my own child: %s\n", why);  // obs-ok:argv-mode-cli
        return 8;
    }
    printf("broker: peer verified pid=%d uid=%u gid=%u\n", (int)s->peer.pid,
           (unsigned)s->peer.uid, (unsigned)s->peer.gid);
    (void)fflush(stdout);

    for (;;) {
#ifdef ZCL_TESTING
        /* The revocation half of the vertical slice: after N served
         * requests the LIVE authority is revoked, and every later action
         * the agent attempts is refused with DENIED_REVOKED. It is revoked
         * where it lives — the broker cannot revoke a grant it does not
         * hold, which is the point. */
        if (revoke_after && (uint64_t)*served == revoke_after &&
            !revoked_once) {
            agent_broker_fixture_revoke();
            revoked_once = true;
            printf("broker: grant %s REVOKED after %d request(s)\n",
                   s->authority->canonical_grant_id, *served);
            (void)fflush(stdout);
        }
#endif
        int r = agent_broker_serve_once(s, spawned->sock);
        if (r <= 0)
            break;
        (*served)++;
        if (max && (uint64_t)*served >= max)
            break;
    }
    (void)close(spawned->sock);
    return 0;
}

static void broker_bind(int argc, char **argv,
                        struct agent_broker_session *s,
                        struct agent_authority_ref *authority)
{
    const char *no_provider_why = NULL;
    const struct agent_broker_provider *provider =
        resolve_provider(argc, argv, &no_provider_why);
    if (!provider) {
        (void)fprintf(stderr, "broker: %s\n",  // obs-ok:argv-mode-cli
                      no_provider_why ? no_provider_why : "no provider");
    } else {
        char why[192];
        if (!agent_broker_session_bind(s, authority, why, sizeof(why)))
            (void)fprintf(stderr,  // obs-ok:argv-mode-cli
                "broker: provider '%s' bound no authority (%s); every request "
                "will be refused\n",
                provider->name ? provider->name : "(unnamed)",
                why[0] ? why : "no reason given");
        else
            printf("broker: authority %s via provider '%s'\n",
                   authority->canonical_grant_id,
                   provider->name ? provider->name : "(unnamed)");
        printf("broker: property provider '%s'\n",
               provider->name ? provider->name : "(unnamed)");
    }
}

static void broker_finish(const char *dir, const char *scratch,
                          struct agent_broker_session *s,
                          const struct agent_spawn_result *spawned,
                          const char *sockpath, int served, int landlock_abi)
{
    if (spawned->pid > 0) {
        read_child_report(scratch, &s->child);
        s->child.landlock_abi = landlock_abi;
        int st = 0;
        if (waitpid(spawned->pid, &st, 0) == spawned->pid) {
            if (WIFSIGNALED(st))
                printf("broker: agent pid=%d killed by signal %d\n",
                       (int)spawned->pid, WTERMSIG(st));
            else
                printf("broker: agent pid=%d exited %d\n", (int)spawned->pid,
                       WEXITSTATUS(st));
        }
    }

    agent_broker_write_status(dir, s, spawned->pid,
                              sockpath[0] ? sockpath : NULL);

    struct agent_audit_verdict v;
    if (agent_audit_verify_dir(dir, &v))
        printf("broker: served=%d denied=%llu receipts=%llu "
               "audit_rows=%llu chain_breaks=%llu bad_sigs=%llu ok=%s\n",
               served, (unsigned long long)s->requests_denied,
               (unsigned long long)s->receipts_written,
               (unsigned long long)v.rows,
               (unsigned long long)v.chain_breaks,
               (unsigned long long)v.bad_signatures, v.ok ? "yes" : "no");
    else
        printf("broker: served=%d denied=%llu receipts=%llu (no audit rows)\n",
               served, (unsigned long long)s->requests_denied,
               (unsigned long long)s->receipts_written);
    (void)fflush(stdout);
}

static int broker_run(int argc, char **argv, const char *dir,
                      const char *script, const char *canary,
                      const char *reqs, const char *euid_s, const char *auid_s,
                      bool listen_mode
#ifdef ZCL_TESTING
                      , const char *revoke_s
#endif
                      )
{
    unsigned long long agent_id = 0, expected_id = 0;
    if (!parse_identities(auid_s, euid_s, &agent_id, &expected_id))
        return 2;
    char scratch[448];
    if (!prepare_broker_dir(dir, scratch, sizeof(scratch)) || !ensure_dir(scratch))
        return 3;

    /* The broker must exec ITSELF; os_proc_exe_path() is the platform shim for
     * naming this exact binary. */
    char self[PATH_MAX];
    if (!os_proc_exe_path(self, sizeof(self))) {
        (void)fprintf(stderr, "broker: cannot resolve my own executable\n");  // obs-ok:argv-mode-cli
        return 3;
    }

    /* The Landlock ABI is recorded HERE, in the broker, because the confined
     * child cannot probe it without being killed by its own filter. */
    int landlock_abi = os_sandbox_landlock_abi();

    /* ── 1. spawn FIRST (nothing secret exists yet) ─────────────────────── */
    struct agent_spawn_request sreq = {
        .self_exe     = self,
        .scratch_dir  = scratch,
        .script       = script,
        .canary       = canary,
        .confined_uid = (uid_t)agent_id,
        .confined_gid = (gid_t)agent_id,
    };
    struct agent_spawn_result spawned;
    if (listen_mode) {
        memset(&spawned, 0, sizeof(spawned));
        spawned.sock = -1;
    } else if (!agent_broker_spawn_confined(&sreq, &spawned)) {
        (void)fprintf(stderr, "broker: could not spawn the confined agent\n");  // obs-ok:argv-mode-cli
        return 4;
    }

    /* ── 2. audit log, then 3. the grant — both AFTER the fork ──────────── */
    struct agent_audit_log audit;
    if (!agent_audit_open(&audit, dir)) {
        (void)fprintf(stderr, "broker: could not open the audit log in %s\n",  // obs-ok:argv-mode-cli
                      dir);
        return 5;
    }
    /* The authority, from the provider — never minted here, and never COPIED
     * into the session. `authority` lives for the whole function and the
     * session points at it; the session holds no grant of its own, so nothing
     * it carries can survive a revoke. A broker whose provider refuses to bind
     * keeps `authority.bound` false and therefore refuses every request with a
     * named reason. The socket still comes up, so an operator gets that
     * refusal per request instead of a process that vanished. */
    struct agent_authority_ref authority;
    memset(&authority, 0, sizeof(authority));
    struct agent_broker_session s;
    memset(&s, 0, sizeof(s));
    s.authority = &authority;
    broker_bind(argc, argv, &s, &authority);
    s.audit = &audit;
    s.child.landlock_abi = landlock_abi;

    int served = 0;
    char sockpath[512] = { 0 };

    int rc = listen_mode
        ? broker_listen(&s, dir, euid_s ? (uid_t)expected_id : getuid(),
                        sockpath, sizeof(sockpath), &served)
        : broker_pair(&s, &spawned, auid_s ? (uid_t)agent_id : getuid(), reqs
#ifdef ZCL_TESTING
                      , revoke_s
#endif
                      , &served);
    if (rc)
        return rc;

    broker_finish(dir, scratch, &s, &spawned, sockpath, served, landlock_abi);
    return 0;
}
#endif

int agent_broker_mode_main(int argc, char **argv)
{
    const char *dir     = arg_value(argc, argv, "--broker-dir=");
    const char *script  = arg_value(argc, argv, "--script=");
    const char *canary  = arg_value(argc, argv, "--canary=");
    const char *reqs    = arg_value(argc, argv, "--requests=");
    const char *euid_s  = arg_value(argc, argv, "--expect-uid=");
    const char *auid_s  = arg_value(argc, argv, "--agent-uid=");
    bool listen_mode    = arg_present(argc, argv, "--listen");
#ifdef ZCL_TESTING
    const char *revoke_s = arg_value(argc, argv, "--revoke-after=");
#endif

    /* The fixture flag is only listed in a build that HAS a fixture catalog,
     * so the shipped binary's own usage text does not advertise a surface it
     * cannot reach.
     *
     * --grant-id / --grant-spec are read by the COMPOSITION ROOT
     * (services/agent_broker_provider.h), not here, because the authority is
     * the provider's and this mode owns none. They are listed because this is
     * the usage text an operator reads, and because WITHOUT ONE OF THEM THE
     * BROKER IS UNGRANTED and refuses every request — registration alone
     * grants nothing.
     *
     * --revoke-after mutates the authority mid-session, which the broker no
     * longer holds and must not reach around to. It is a demo instrument and
     * exists only in a -DZCL_TESTING build. */
    static const char k_usage[] =
        "usage: zclassic23 --metaverse-broker --broker-dir=DIR "
        "[--script=NAME] [--canary=PATH] [--requests=N] [--listen] "
        "[--expect-uid=N] [--agent-uid=N]\n"
        "  authority (one is REQUIRED; without it the broker serves nothing):\n"
        "    --grant-id=ID          bind to a canonical grant already in the "
        "property grant store\n"
        "    --grant-spec=PATH      read a bounded grant specification, mint "
        "it AFTER the child is spawned, and bind to it\n"
        "  the store is IN-PROCESS and EPHEMERAL: a restart leaves the broker "
        "ungranted until it is\n"
        "  reprovisioned, and nothing here implies a durable revocation or a "
        "durable receipt.\n"
#ifdef ZCL_TESTING
        "  test-build only: [--fixture] [--revoke-after=N]\n"
#endif
        ;

    if (!dir || !dir[0]) {
        (void)fputs(k_usage, stderr);  // obs-ok:argv-mode-cli
        return 2;
    }
    if (!script || !script[0])
        script = "inspect";
    if (!canary)
        canary = "";

#if defined(_WIN32)
    (void)script;
    (void)canary;
    (void)reqs;
    (void)euid_s;
    (void)auid_s;
    (void)listen_mode;
#ifdef ZCL_TESTING
    (void)revoke_s;
#endif
    (void)fprintf(stderr,
        "broker: Windows agent execution is disabled until restricted-token, "
        "Job Object, low-integrity, resource-limit, and network-denial "
        "sandbox qualification passes\n"); // obs-ok:argv-mode-cli
    return 78;
#else
    return broker_run(argc, argv, dir, script, canary, reqs, euid_s, auid_s,
                      listen_mode
#ifdef ZCL_TESTING
                      , revoke_s
#endif
                      );
#endif
}
