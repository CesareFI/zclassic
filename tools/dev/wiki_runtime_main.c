/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: finite owner-invoked native wiki propagation coordinator. */
/* Usage: z23-wiki-runtime PLAN.json. participants[].argv is exactly the
 * owner-qualified absolute z23/z23-dev/zclassic23 path, -datadir=/tmp/zcl23-...
 * and -rpcport=39xxx. No ssh/shell prefix is supported. Cross-host tests need
 * previously qualified owner-established loopback RPC routes/auth fixtures.
 * No nodes, tunnels, keys or lifecycle workers are created by this executable. */
#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif
#include "wiki_runtime.h"
#include "platform/private_file.h"
#include "base/safe_alloc.h"
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef _WIN32
#include <sys/stat.h>
#include <unistd.h>
#endif
/* Standalone node-tool linkage uses the same shutdown flag type as main.c. */
volatile sig_atomic_t g_shutdown_requested = 0;
static volatile sig_atomic_t wr_cancelled;
static void wr_signal(int signal_number)
{
    (void)signal_number;
    wr_cancelled = 1;
    g_shutdown_requested = 1;
}
static int64_t wr_cli_now(void *ctx) { (void)ctx; return wr_monotonic_ms(); }
#ifndef _WIN32
static bool wr_cli_marker(const char *marker, const char *run)
{
    struct platform_private_file file; platform_private_file_init(&file);
    if (!platform_private_file_open_observation(marker, &file)) return false;
    uint64_t n = 0; char value[64]; struct stat st;
    bool ok = fstat((int)file.native, &st) == 0 && st.st_uid == getuid() &&
        platform_private_file_size(&file, &n) && n == strlen(run) && n < sizeof(value) &&
        platform_private_file_read_at(&file, value, (size_t)n, 0) && !memcmp(value, run, (size_t)n);
    platform_private_file_close(&file);
    return ok;
}
#endif
static bool wr_cli_owned(const struct wr_participant *peer, const char *run)
{
#ifdef _WIN32
    (void)peer; (void)run; return false;
#else
    const char *dd = peer->argv[1]+9;
    char marker[WR_ARG_CAP];
    struct stat st;
    char *resolved = realpath(dd, NULL);
    bool canonical = resolved && !strcmp(resolved, dd);
    free(resolved);
    if (!canonical || stat(dd, &st) != 0 || !S_ISDIR(st.st_mode) ||
        st.st_uid != getuid() || (st.st_mode & 077)) return false;
    int used = snprintf(marker, sizeof(marker), "%s/wiki-runtime-owner", dd);
    if (used < 0 || (size_t)used >= sizeof(marker)) return false;
    return wr_cli_marker(marker, run);
#endif
}
static enum wr_call_state wr_cli_call(void *ctx, const struct wr_participant *peer,
    const char *operation, const char *run, const struct json_value *input,
    int64_t deadline, struct json_value *reply)
{
    (void)ctx;
    json_init(reply);
    if (wr_cancelled) return WR_CANCELLED;
    if (!wr_cli_owned(peer, run)) return WR_LAUNCH_FAILED;
    int64_t now = wr_monotonic_ms();
    if (now < 0 || now >= deadline) return WR_TIMEOUT;
    char json[2048], argument[2080], command[64];
    size_t n = json_write(input, json, sizeof(json));
    if (n >= sizeof(json)) return WR_TRUNCATED;
    int used = snprintf(argument, sizeof(argument), "--input=%s", json);
    if (used < 0 || (size_t)used >= sizeof(argument)) return WR_TRUNCATED;
    used = snprintf(command, sizeof(command), "fleet.wiki.%s", operation);
    if (used < 0 || (size_t)used >= sizeof(command)) return WR_LAUNCH_FAILED;
    const char *args[WR_ARGS+3];
    for (size_t i = 0; i < peer->argc; i++) args[i] = peer->argv[i];
    args[peer->argc] = command; args[peer->argc+1] = argument;
    args[peer->argc+2] = NULL;
    int remaining = deadline-now > INT_MAX ? INT_MAX : (int)(deadline-now);
    /* Cancellation is cooperative at capture return, bounded by the shared
     * remaining <=10s plus the existing process-group reap grace. No immediate
     * cancellation guarantee, sandbox, or escaped-descendant claim is made. */
    enum wr_call_state state = wr_capture(args, remaining, reply);
    if (wr_cancelled) return WR_CANCELLED; /* wr_invoke owns the returned reply. */
    return state;
}
static bool wr_cli_read_plan(const char *path, struct wr_plan *plan, const char **why)
{
    char *raw = zcl_malloc(65537, "wiki-runtime.plan-bytes");
    if (!raw) { *why = "plan-allocation"; return false; }
    size_t n = 0;
    struct json_value input; json_init(&input);
    bool valid = wr_read_regular(path, raw, 65536, &n) && json_read(&input, raw, n) &&
        wr_plan_read(&input, plan, why);
    free(raw); json_free(&input);
    return valid;
}
static void wr_cli_refusal(struct json_value *receipt, const char *why)
{
    json_set_object(receipt);
    if (!json_push_kv_bool(receipt, "propagation_verified", false) ||
        !json_push_kv_bool(receipt, "full_qualification", false) ||
        !json_push_kv_str(receipt, "reason", why ? why : "invalid-plan")) {
        json_free(receipt); json_init(receipt);
    }
}
static bool wr_cli_export(const struct json_value *receipt)
{
    int64_t export_start = wr_monotonic_ms();
    size_t length = json_write(receipt, NULL, 0);
    char *rendered = zcl_malloc(length+1, "wiki-runtime.export-receipt");
    bool exported = receipt->type == JSON_OBJ && rendered &&
        json_write(receipt, rendered, length+1) == length &&
        fwrite(rendered, 1, length, stdout) == length && fputc('\n', stdout) != EOF &&
        fflush(stdout) == 0;
    free(rendered);
    int64_t export_end = wr_monotonic_ms();
    fprintf(stderr, "wiki-runtime: receipt-export-elapsed-ms=%lld (stdout flush, not durable-storage proof)\n",
        (long long)(export_start >= 0 && export_end >= export_start ? export_end-export_start : -1));
    return exported;
}
int main(int argc, char **argv)
{
    if (argc != 2) {
        fputs("usage: z23-wiki-runtime PLAN.json (propagation only; lifecycle required)\n", stderr);
        return 2;
    }
    (void)signal(SIGINT, wr_signal); (void)signal(SIGTERM, wr_signal);
    struct json_value receipt; json_init(&receipt);
    struct wr_plan *plan = zcl_calloc(1, sizeof(*plan), "wiki-runtime.plan");
    const char *why = NULL;
    bool valid = plan && wr_cli_read_plan(argv[1], plan, &why);
    bool passed = false;
    if (valid) {
        struct wr_backend backend = {.now_ms=wr_cli_now, .call=wr_cli_call};
        passed = wr_run(plan, &backend, &receipt, &why);
    } else wr_cli_refusal(&receipt, why);
    free(plan);
    bool exported = wr_cli_export(&receipt); json_free(&receipt);
    if (!exported) { fputs("wiki-runtime: receipt export failed; qualification refused\n", stderr); return 2; }
    if (!passed) fprintf(stderr, "wiki-runtime: %s\n", why ? why : "propagation refused");
    /* Zero means only the explicitly named propagation dependency passed.
     * The receipt ALWAYS refuses full lifecycle/runtime qualification. */
    return passed ? 0 : 1;
}
