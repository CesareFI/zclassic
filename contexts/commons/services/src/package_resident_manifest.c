/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: manifest-to-sandbox translator and confined run-to-exit for pinned native images. */
#include "services/package_resident_manifest.h"
#include "platform/time_compat.h"
#include "util/log_macros.h"

#include <errno.h>
#include <string.h>
#if !defined(_WIN32)
#include <signal.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#endif
#if defined(__linux__)
#include <sys/syscall.h>
#endif

#if defined(__linux__)
#ifdef __NR_clone3
#define PRM_NR_CLONE3 __NR_clone3
#else
#define PRM_NR_CLONE3 435 /* clone3: kernel ABI number, x86_64 and generic */
#endif
#ifdef __NR_io_uring_setup
#define PRM_NR_URING_SETUP __NR_io_uring_setup
#define PRM_NR_URING_ENTER __NR_io_uring_enter
#define PRM_NR_URING_REGISTER __NR_io_uring_register
#else
#define PRM_NR_URING_SETUP 425
#define PRM_NR_URING_ENTER 426
#define PRM_NR_URING_REGISTER 427
#endif
/* Network, tracing, namespace and kernel-surface calls. execve stays
 * allowed (the pinned fexecve is the last call before the image runs) and fd 3
 * stays usable with read/write/sendmsg/recvmsg. */
static const int prm_denied[] = {
    __NR_socket,
#ifdef __NR_socketcall
    __NR_socketcall,
#endif
    __NR_socketpair, __NR_connect, __NR_bind, __NR_listen, __NR_accept,
    __NR_accept4, __NR_ptrace, __NR_process_vm_readv, __NR_process_vm_writev,
    __NR_mount, __NR_umount2, __NR_pivot_root, __NR_setns, __NR_unshare,
    __NR_bpf, __NR_kexec_load, __NR_kexec_file_load,
    /* Descendants and detaching: no fork or vfork, no new session or process
     * group. clone is NOT listed here: the profile admits it only with
     * CLONE_THREAD (threads die with the group kill) and clone3 answers ENOSYS
     * so libc falls back to clone. io_uring can issue socket and connect
     * operations with no syscall seccomp can see, so it is denied outright. */
#ifdef __NR_fork
    __NR_fork,
#endif
#ifdef __NR_vfork
    __NR_vfork,
#endif
    __NR_setsid, __NR_setpgid,
    PRM_NR_URING_SETUP, PRM_NR_URING_ENTER, PRM_NR_URING_REGISTER,
};
static const int prm_enosys[] = { PRM_NR_CLONE3 };
#define PRM_ENOSYS_COUNT (sizeof(prm_enosys) / sizeof(prm_enosys[0]))
#define PRM_DENIED_COUNT (sizeof(prm_denied) / sizeof(prm_denied[0]))
#else
static const int prm_denied[] = { 0 };
#define PRM_DENIED_COUNT 0u
static const int prm_enosys[] = { 0 };
#define PRM_ENOSYS_COUNT 0u
#endif

void package_resident_manifest_init(struct package_resident_manifest *m)
{
    if (!m) return;
    memset(m, 0, sizeof(*m));
    m->rlimits = (struct os_sandbox_rlimits){
        .as_bytes = PACKAGE_RESIDENT_DEFAULT_AS_BYTES,
        .cpu_seconds = PACKAGE_RESIDENT_DEFAULT_CPU_SECONDS,
        .nproc = OS_SANDBOX_RLIMIT_KEEP, /* per-uid; exempt by name, see the header */
        .fsize_bytes = PACKAGE_RESIDENT_DEFAULT_FSIZE_BYTES,
        .nofile = PACKAGE_RESIDENT_DEFAULT_NOFILE,
        .core_bytes = OS_SANDBOX_RLIMIT_KEEP, /* KEEP is mapped to 0 below */
    };
}

static bool prm_has_dotdot(const char *path)
{
    for (const char *p = path; *p;) {
        const char *end = strchr(p, '/');
        size_t len = end ? (size_t)(end - p) : strlen(p);
        if (len == 2 && p[0] == '.' && p[1] == '.') return true;
        p += len;
        if (*p == '/') ++p;
    }
    return false;
}

static struct zcl_result prm_path_check(const char *path, const char *what)
{
    if (!path || path[0] != '/' || strlen(path) >= PACKAGE_RESIDENT_MANIFEST_PATH_MAX)
        return ZCL_ERR(-1, "resident-manifest: %s path must be absolute and bounded", what);
    if (prm_has_dotdot(path))
        return ZCL_ERR(-1, "resident-manifest: %s path may not contain '..'", what);
#if !defined(_WIN32)
    struct stat st;
    if (stat(path, &st) != 0)
        return ZCL_ERR(-1, "resident-manifest: %s path does not exist: %s", what, path);
#endif
    return ZCL_OK;
}

static struct zcl_result prm_paths_check(const char *const *paths, size_t n,
                                         const char *what)
{
    if (n > PACKAGE_RESIDENT_MANIFEST_PATHS)
        return ZCL_ERR(-1, "resident-manifest: too many %s paths", what);
    for (size_t i = 0; i < n; ++i)
        ZCL_CHECK(prm_path_check(paths[i], what));
    return ZCL_OK;
}

static size_t prm_add_manifest_rules(struct os_sandbox_path_rule *rules, size_t n,
                                     const struct package_resident_manifest *m)
{
    for (size_t i = 0; i < m->n_read; ++i)
        rules[n++] = (struct os_sandbox_path_rule){
            .path = m->read_paths[i], .allow_read = true};
    for (size_t i = 0; i < m->n_write; ++i)
        rules[n++] = (struct os_sandbox_path_rule){
            .path = m->write_paths[i], .allow_read = true, .allow_write = true,
            .allow_create = true};
    return n;
}

/* NPROC is deliberately not tested here: it defaults to KEEP (see the header). */
/* Thread budget: NPROC is per-uid, so the child's ceiling is the uid's live task
 * count plus the thread allowance, clamped to the hard limit. A count that cannot
 * be read (0) refuses: a ceiling that cannot be computed is not skipped. */
static struct zcl_result prm_thread_budget(struct os_sandbox_rlimits *limits)
{
    if (limits->nproc != OS_SANDBOX_RLIMIT_KEEP) return ZCL_OK; /* explicit value */
    uint64_t tasks = os_sandbox_uid_task_count();
    if (tasks == 0)
        return ZCL_ERR(-1, "resident-manifest: the uid task count cannot be read; refusing to run without a thread budget");
    uint64_t budget = tasks + PACKAGE_RESIDENT_DEFAULT_THREADS;
    uint64_t hard = os_sandbox_nproc_hard_limit();
    limits->nproc = hard != OS_SANDBOX_RLIMIT_KEEP && budget > hard ? hard : budget;
    return ZCL_OK;
}

static bool prm_limits_unbounded(const struct os_sandbox_rlimits *l)
{
    return l->as_bytes == OS_SANDBOX_RLIMIT_KEEP ||
           l->cpu_seconds == OS_SANDBOX_RLIMIT_KEEP ||
           l->fsize_bytes == OS_SANDBOX_RLIMIT_KEEP ||
           l->nofile == OS_SANDBOX_RLIMIT_KEEP;
}

/* Finite limits are mandatory; leaving one untouched is an explicit, logged
 * opt-out or a refusal. Children are refused outright (no containment yet). */
static struct zcl_result prm_policy_check(const struct package_resident_manifest *m)
{
    if (m->allow_children)
        return ZCL_ERR(-1, "resident-manifest: allow_children refused: descendant containment (cgroup or subreaper kill-all) is not implemented");
    if (!prm_limits_unbounded(&m->rlimits)) return ZCL_OK;
    if (!m->allow_unbounded_limits)
        return ZCL_ERR(-1, "resident-manifest: an rlimit left at KEEP (unbounded) needs allow_unbounded_limits; finite limits are mandatory");
    LOG_ERROR("app.run.confined", "opt-out: manifest runs with at least one unbounded rlimit (allow_unbounded_limits)");
    return ZCL_OK;
}

void package_resident_confinement_release(struct package_resident_confinement *c)
{
    if (!c) return;
#if !defined(_WIN32)
    for (size_t i = 0; i < c->n_grant_fds; ++i)
        if (c->grant_fds[i] >= 0) close(c->grant_fds[i]);
#endif
    c->n_grant_fds = 0;
}

#ifdef ZCL_TESTING
static bool g_prm_force_unpinned;
void package_resident_manifest_force_unpinned_grants_for_testing(bool on)
{
    g_prm_force_unpinned = on;
}
#endif

static int prm_open_grant(const char *path)
{
#ifdef ZCL_TESTING
    if (g_prm_force_unpinned) { errno = ENOTSUP; return -1; } /* test seam */
#endif
    return os_sandbox_open_grant(path);
}

/* Open every grant object here, in the parent, and bind the rule to the exact
 * descriptor. A symlink anywhere in the path (ELOOP) is refused, so the path
 * the child is confined to cannot be redirected after validation. Where the
 * platform has no such primitive (ENOTSUP) the profile is REFUSED, never a path
 * rule that Landlock would reopen by name. */
static struct zcl_result prm_bind_grants(struct package_resident_confinement *out, size_t n)
{
    for (size_t i = 0; i < n; ++i) {
        struct os_sandbox_path_rule *rule = &out->rules[i];
        int fd = prm_open_grant(rule->path);
        if (fd < 0 && errno == ENOTSUP) {
            package_resident_confinement_release(out);
            return ZCL_ERR(-1, "resident-manifest: grant-pinning-unavailable: descriptor pinning cannot be provided (no path-rule fallback): %s", rule->path);
        }
        if (fd < 0) {
            int why = errno;
            package_resident_confinement_release(out);
            return ZCL_ERR(-1, why == ELOOP
                ? "resident-manifest: grant path is a symlink or crosses one; refused: %s"
                : "resident-manifest: grant path cannot be opened stably: %s", rule->path);
        }
        rule->has_fd = true;
        rule->fd = fd;
        out->grant_fds[out->n_grant_fds++] = fd;
    }
    return ZCL_OK;
}

struct zcl_result package_resident_manifest_profile(
    const struct package_resident_manifest *m, const char *image_path,
    struct package_resident_confinement *out)
{
    if (!m || !out) return ZCL_ERR(-1, "resident-manifest: manifest and output required");
    ZCL_CHECK(prm_path_check(image_path, "image"));
    ZCL_CHECK(prm_paths_check(m->read_paths, m->n_read, "read"));
    ZCL_CHECK(prm_paths_check(m->write_paths, m->n_write, "write"));
    ZCL_CHECK(prm_policy_check(m));
    struct os_sandbox_rlimits limits = m->rlimits;
    ZCL_CHECK(prm_thread_budget(&limits));
    memset(out, 0, sizeof(*out));
    (void)snprintf(out->image_path, sizeof(out->image_path), "%s", image_path);
    size_t n = 0;
    out->rules[n++] = (struct os_sandbox_path_rule){
        .path = out->image_path, .allow_read = true, .allow_execute = true};
    n = prm_add_manifest_rules(out->rules, n, m);
    ZCL_CHECK(prm_bind_grants(out, n));
    out->profile = (struct os_sandbox_profile){
        .name = "resident_confined_run",
        .no_new_privs = true,
        .apply_rlimits = true,
        .rlimits = limits,
        .landlock = true,
        .fs_rules = out->rules,
        .n_fs_rules = n,
        .seccomp = true,
        .denied_syscalls = prm_denied,
        .n_denied = PRM_DENIED_COUNT,
        .enosys_syscalls = prm_enosys,
        .n_enosys = PRM_ENOSYS_COUNT,
        .seccomp_clone_threads_only = true,
    };
    if (out->profile.rlimits.core_bytes == OS_SANDBOX_RLIMIT_KEEP)
        out->profile.rlimits.core_bytes = 0;
    return ZCL_OK;
}

#if !defined(_WIN32)
static void prm_classify(int status, struct package_resident_exit *out)
{
    if (WIFEXITED(status)) {
        out->exited = true;
        out->code = WEXITSTATUS(status);
    } else if (WIFSIGNALED(status)) {
        out->signaled = true;
        out->signal = WTERMSIG(status);
    }
}

/* Monotonic ns; false on a clock error (callers refuse or treat the deadline
 * as expired - a failed clock never extends a deadline). */
static bool prm_now_ns(uint64_t *ns)
{
    int64_t us = platform_time_monotonic_us();
    if (us <= 0) return false;
    *ns = (uint64_t)us * UINT64_C(1000);
    return true;
}

/* Poll-reap the child against the ONE absolute deadline the spawn already
 * ran under; past it, kill the whole process group (the child called setsid,
 * so its pid is its group id) and the child, and reap within a bounded grace. */
static struct zcl_result prm_wait(pid_t pid, uint64_t deadline_ns, struct package_resident_exit *out)
{
    for (;;) {
        int status = 0;
        pid_t got = waitpid(pid, &status, WNOHANG);
        if (got == pid) { prm_classify(status, out); return ZCL_OK; }
        if (got < 0 && errno != EINTR)
            return ZCL_ERR(-1, "resident-confined: waitpid failed for pid %lld", (long long)pid);
        uint64_t now = 0;
        if (!prm_now_ns(&now) || now >= deadline_ns) break; /* clock error = expired */
        struct timespec nap = {0, 500000};
        nanosleep(&nap, NULL);
    }
    out->timed_out = true;
    int status = 0;
    if (!resident_launch_kill_reap((uint64_t)pid, RESIDENT_REAP_GRACE_MS, &status))
        return ZCL_ERR(-1, "resident-confined-reap-failed: timed-out child pid %lld survived SIGKILL within the reap grace", (long long)pid);
    prm_classify(status, out);
    return ZCL_OK;
}

/* Spawn under the shared deadline. The run is reported only once the spawn
 * reached CONFIRMED (the /proc exe re-proof matched the pinned image); any
 * other state is a typed exec-uncertain refusal with the child already killed
 * and reaped, and no exit status is ever attributed to the app. */
static struct zcl_result prm_spawn(struct package_resident *app,
                                   struct package_resident_confinement *conf,
                                   const char *const *args, size_t n_args)
{
    char *argv[PACKAGE_RESIDENT_MANIFEST_ARGS + 2u];
    argv[0] = app->snapshot_image;
    for (size_t i = 0; i < n_args; ++i) argv[i + 1] = (char *)(uintptr_t)args[i];
    argv[n_args + 1] = NULL;
    char *envp[] = {NULL};
    char error[RESIDENT_LAUNCH_ERROR_MAX] = {0};
    bool spawned = resident_launch_spawn_confined(&app->launch, argv, envp, &conf->profile,
                                                  &app->receipt, error, sizeof(error));
    package_resident_confinement_release(conf); /* grants are consumed: the child holds its own copies */
    if (!spawned) {
        LOG_ERROR("app.run.confined", "refused: %s", error);
        return ZCL_ERR(-1, "resident-confined-refused: %s", error);
    }
    if (app->launch.exec_state != RESIDENT_EXEC_CONFIRMED) {
        bool reaped = resident_launch_kill_reap(app->launch.pid, RESIDENT_REAP_GRACE_MS, NULL);
        app->launch.spawned = false;
        LOG_ERROR("app.run.confined", "exec not confirmed (state %d) for pid %llu", (int)app->launch.exec_state, (unsigned long long)app->launch.pid);
        return ZCL_ERR(-1, "resident-confined-exec-uncertain: pid %llu was armed but its exec was not confirmed; killed%s",
                       (unsigned long long)app->launch.pid, reaped ? " and reaped" : "; REAP FAILED");
    }
    return ZCL_OK;
}
#endif

struct zcl_result package_resident_run_confined(
    struct package_resident *app, const struct package_resident_manifest *m,
    const char *const *args, size_t n_args, uint32_t timeout_ms,
    struct package_resident_exit *out)
{
#if defined(_WIN32)
    (void)app; (void)m; (void)args; (void)n_args; (void)timeout_ms; (void)out;
    return ZCL_ERR(-1, "resident-unavailable: confined launch is not qualified on Windows");
#else
    if (!app || !out || app->launch.spawned || !app->snapshot_image[0] ||
        n_args > PACKAGE_RESIDENT_MANIFEST_ARGS || (n_args && !args) ||
        timeout_ms == 0 || timeout_ms > PACKAGE_RESIDENT_RUN_TIMEOUT_MAX_MS)
        return ZCL_ERR(-1, "resident-confined: prepared unused app, bounded args and timeout required");
    memset(out, 0, sizeof(*out));
    uint64_t began_ns = 0;
    if (!prm_now_ns(&began_ns)) {
        LOG_ERROR("app.run.confined", "monotonic clock failed; refusing to run without a deadline");
        return ZCL_ERR(-1, "resident-confined: monotonic clock failed; no deadline can be enforced");
    }
    struct package_resident_confinement conf;
    struct zcl_result built = package_resident_manifest_profile(m, app->snapshot_image, &conf);
    if (!built.ok) {
        LOG_ERROR("app.run.confined", "%s", built.message);
        return built;
    }
    /* One absolute deadline covers spawn, handshake and the run itself. */
    uint64_t deadline_ns = began_ns + (uint64_t)timeout_ms * UINT64_C(1000000);
    app->launch.spawn_deadline_ns = deadline_ns;
    ZCL_CHECK(prm_spawn(app, &conf, args, n_args));
    struct zcl_result waited = prm_wait((pid_t)app->launch.pid, deadline_ns, out);
    if (!waited.ok) {
        LOG_ERROR("app.run.confined", "%s", waited.message);
        return waited;
    }
    app->launch.spawned = false; /* reaped here: close must not cancel */
    return ZCL_OK;
#endif
}
