/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Purpose: `z23 ops mesh terminal serve` — a confined shell served on a
 * loopback port for the PSK device-host tunnel to carry, and `serve
 * --init-key`. `connect` lives in native_mesh_terminal_hub_connect.c. This
 * file owns argv, the key file, the listener and the audit sink. */

#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif

#include "command/native_command.h"
#include "native_mesh_terminal_hub.h"

#include "session/mesh_terminal_hub.h"
#include "session/mesh_terminal_worker.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const struct {
    const char *flag;
    size_t offset;
    bool number;
} hub_flags[] = {
    { "--key_file=", offsetof(struct hub_args, key_file), false },
    { "--shell=", offsetof(struct hub_args, shell), false },
    { "--workdir=", offsetof(struct hub_args, workdir), false },
    { "--audit_file=", offsetof(struct hub_args, audit_file), false },
    { "--route_input=", offsetof(struct hub_args, route_input), false },
    { "--name=", offsetof(struct hub_args, name), false },
    { "--exec=", offsetof(struct hub_args, exec), false },
    { "--listen_port=", offsetof(struct hub_args, listen_port), true },
    { "--direct_port=", offsetof(struct hub_args, direct_port), true },
    { "--max_active=", offsetof(struct hub_args, max_active), true },
    /* a connection-attempt limit: counted at accept, before authentication */
    { "--max_sessions=", offsetof(struct hub_args, max_sessions), true },
    { "--idle_s=", offsetof(struct hub_args, idle_s), true },
    { "--lifetime_s=", offsetof(struct hub_args, lifetime_s), true },
    { "--max_bytes_in=", offsetof(struct hub_args, max_in), true },
    { "--max_bytes_out=", offsetof(struct hub_args, max_out), true },
};

static bool hub_number(const char *text, uint64_t *out)
{
    char *end = NULL;
    errno = 0;
    unsigned long long v = strtoull(text, &end, 10);
    if (!*text || *end || errno || *text == '-')
        return false;
    *out = v;
    return true;
}

static bool hub_one_flag(const char *word, struct hub_args *out)
{
    if (!strcmp(word, "--init-key")) {
        out->init_key = true;
        return true;
    }
    for (size_t i = 0; i < sizeof hub_flags / sizeof hub_flags[0]; i++) {
        size_t n = strlen(hub_flags[i].flag);
        if (strncmp(word, hub_flags[i].flag, n))
            continue;
        char *field = (char *)out + hub_flags[i].offset;
        if (!hub_flags[i].number) {
            *(const char **)field = word + n;
            return word[n] != '\0';
        }
        out->have_direct_port = out->have_direct_port || !strcmp(hub_flags[i].flag, "--direct_port=");
        return hub_number(word + n, (uint64_t *)field);
    }
    return false;
}

bool zcl_native_hub_args_parse(const char *const *words, size_t count,
                               size_t from, struct hub_args *out)
{
    memset(out, 0, sizeof(*out));
    out->max_active = MESH_TERMINAL_HUB_DEFAULT_ACTIVE;
    out->idle_s = 600;
    out->lifetime_s = 3600;
    out->max_in = UINT64_C(16) << 20;
    out->max_out = UINT64_C(1) << 30;
    for (size_t i = from; i < count; i++) {
        if (!words[i] || !hub_one_flag(words[i], out)) {
            fprintf(stderr, "z23: refused: INVALID_ARGUMENTS: unknown or malformed argument '%s'\n",
                    words[i] ? words[i] : "(null)");
            return false;
        }
    }
    if (out->max_sessions > UINT32_MAX) { /* it is cast to unsigned for the listener */
        fprintf(stderr, "z23: refused: INVALID_ARGUMENTS: --max_sessions (a connection-attempt limit) must be at most %lu\n",
                (unsigned long)UINT32_MAX);
        return false;
    }
    return true;
}

static int hub_refuse(int rc, const char *code, const char *why)
{
    fprintf(stderr, "z23: refused: %s: %s\n", code, why);
    return rc;
}

static int hub_init_key(const struct hub_args *a)
{
    char fp[MESH_TERMINAL_HUB_FINGERPRINT_HEX + 1], why[96];
    if (!a->key_file)
        return hub_refuse(ZCL_COMMAND_EXIT_INVALID, "INVALID_ARGUMENTS",
                          "usage: z23 ops mesh terminal serve --init-key --key_file=<path>");
    if (!mesh_terminal_hub_key_init(a->key_file, fp, why, sizeof why))
        return hub_refuse(ZCL_COMMAND_EXIT_INVALID, "KEY_FILE_REFUSED", why);
    printf("event=TERMINAL_HUB_KEY_CREATED key_fingerprint=%s path=%s\n", fp, a->key_file);
    return ZCL_COMMAND_EXIT_OK;
}

#if !defined(_WIN32)
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

static bool hub_dir_ok(const char *path)
{
    struct stat st;
    return path && path[0] == '/' && stat(path, &st) == 0 && S_ISDIR(st.st_mode);
}

static int hub_serve_check(const struct hub_args *a, struct mesh_terminal_hub_listen_cfg *cfg)
{
    char why[96];
    const char *blocked = mesh_terminal_confinement_refusal(MESH_TERMINAL_PLATFORM_NATIVE, false);
    if (blocked)
        return hub_refuse(ZCL_COMMAND_EXIT_BLOCKED, "CONFINEMENT_UNAVAILABLE", blocked);
    if (!a->key_file || !a->shell || !a->workdir)
        return hub_refuse(ZCL_COMMAND_EXIT_INVALID, "INVALID_ARGUMENTS",
                          "usage: z23 ops mesh terminal serve --key_file=<path> --shell=<abs path> --workdir=<abs dir> [--listen_port=N]");
    if (!mesh_terminal_shell_path_valid(MESH_TERMINAL_PLATFORM_NATIVE, a->shell) || access(a->shell, X_OK) != 0)
        return hub_refuse(ZCL_COMMAND_EXIT_INVALID, "SHELL_REFUSED", "the shell must be an absolute path to an executable");
    if (!hub_dir_ok(a->workdir))
        return hub_refuse(ZCL_COMMAND_EXIT_INVALID, "WORKDIR_REFUSED", "the workdir must be an existing absolute directory");
    if (!mesh_terminal_hub_key_load(a->key_file, cfg->serve.key, why, sizeof why))
        return hub_refuse(ZCL_COMMAND_EXIT_INVALID, "KEY_FILE_REFUSED", why);
    if (a->listen_port > UINT16_MAX || a->max_active < 1 || a->max_active > MESH_TERMINAL_HUB_ACTIVE_MAX ||
        !a->max_in || !a->max_out || !a->lifetime_s)
        return hub_refuse(ZCL_COMMAND_EXIT_INVALID, "INVALID_ARGUMENTS", "a limit is out of range");
    return ZCL_COMMAND_EXIT_OK;
}

static int hub_serve(const struct hub_args *a)
{
    struct mesh_terminal_hub_listen_cfg cfg;
    memset(&cfg, 0, sizeof cfg);
    int rc = hub_serve_check(a, &cfg);
    if (rc != ZCL_COMMAND_EXIT_OK)
        return rc;
    cfg.serve.shell_path = a->shell;
    cfg.serve.workdir = a->workdir;
    cfg.serve.max_bytes_in = a->max_in;
    cfg.serve.max_bytes_out = a->max_out;
    cfg.serve.lifetime_seconds = a->lifetime_s;
    cfg.serve.idle_seconds = a->idle_s;
    cfg.serve.stop_fd = -1;
    cfg.max_active = (unsigned)a->max_active;
    cfg.max_sessions = (unsigned)a->max_sessions;
    cfg.audit_fd = a->audit_file ? open(a->audit_file, O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC, 0600)
                                 : STDERR_FILENO;
    uint16_t port = 0;
    int listener = cfg.audit_fd < 0 ? -1 : mesh_terminal_hub_listen((uint16_t)a->listen_port, &port);
    if (listener < 0)
        return hub_refuse(ZCL_COMMAND_EXIT_TRANSIENT, "LISTEN_FAILED", "cannot open the audit file or bind 127.0.0.1");
    char fp[MESH_TERMINAL_HUB_FINGERPRINT_HEX + 1];
    mesh_terminal_hub_key_fingerprint(cfg.serve.key, fp);
    fprintf(stderr, "event=TERMINAL_HUB_LISTENING listen_port=%u key_fingerprint=%s\n", (unsigned)port, fp);
    fflush(stderr);
    return mesh_terminal_hub_listen_run(listener, &cfg) == 0 ? ZCL_COMMAND_EXIT_OK : ZCL_COMMAND_EXIT_INTERNAL;
}

#else
static int hub_serve(const struct hub_args *a)
{
    (void)a;
    return hub_refuse(ZCL_COMMAND_EXIT_BLOCKED, "PLATFORM_UNSUPPORTED",
                      "the terminal hub needs a POSIX host");
}
#endif

static bool hub_try_arm(const char *const *words, size_t count,
                                      size_t consumed, int *rc)
{
    struct hub_args a;
    bool serve = consumed < count && words[consumed] && !strcmp(words[consumed], "serve");
    bool connect = consumed < count && words[consumed] && !strcmp(words[consumed], "connect");
    if (!serve && !connect)
        return false;
    if (!zcl_native_hub_args_parse(words, count, consumed + 1, &a))
        *rc = ZCL_COMMAND_EXIT_INVALID;
    else if (connect)
        *rc = zcl_native_hub_connect(&a);
    else
        *rc = a.init_key ? hub_init_key(&a) : hub_serve(&a);
    return true;
}

bool zcl_native_mesh_terminal_hub_try(const char *const *words, size_t count,
                                      size_t consumed, int *rc)
{
    return hub_try_arm(words, count, consumed, rc);
}
