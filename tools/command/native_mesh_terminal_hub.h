/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: shared pieces of `z23 ops mesh terminal serve|connect` — the
 * argument table and the two entry points. Internal to tools/command. */

#ifndef ZCL_TOOLS_COMMAND_NATIVE_MESH_TERMINAL_HUB_H
#define ZCL_TOOLS_COMMAND_NATIVE_MESH_TERMINAL_HUB_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct hub_args {
    const char *key_file, *shell, *workdir, *audit_file, *route_input, *name, *exec;
    uint64_t listen_port, direct_port, max_active, max_sessions;
    uint64_t idle_s, lifetime_s, max_in, max_out;
    bool init_key, have_direct_port;
};

/* Parses words[from..count); false (with one stderr line) on any unknown or
 * malformed argument. */
bool zcl_native_hub_args_parse(const char *const *words, size_t count,
                               size_t from, struct hub_args *out);

/* True when words[consumed] names a hub subcommand; *rc is then the exit. */
bool zcl_native_mesh_terminal_hub_try(const char *const *words, size_t count,
                                      size_t consumed, int *rc);

int zcl_native_hub_connect(const struct hub_args *args);

#endif
