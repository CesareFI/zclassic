/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Purpose: the interactive attach client for the mesh terminal lane. It
 * bridges a caller's terminal to one confined terminal session on a paired
 * peer by driving the local node's mesh_terminal_open / poll / read /
 * write / resize / close RPCs. The bridge has no node, socket, termios or
 * signal knowledge: the RPC transport and the terminal are injected, so a
 * test drives the exact production loop against a scripted fake.
 *
 * Exit codes (the zcl_command_exit values):
 *   0  detached by the escape, or the remote shell exited 0 (worker-exited)
 *   N  the remote shell exited with status N (0..255), or 128 + S when
 *      signal S killed it (SIGTERM gives 143), like ssh. This shares
 *      numbers with the classes below: the stderr line says which it was
 *      ("reason=worker-exited exit_code=N"). A node that predates the
 *      status fields sends none, and a missing status exits 0.
 *   1  refused or ended for a reason with no more specific class
 *   2  invalid request            3  blocked (no confinement, no transport)
 *   4  denied (pairing, capability, delegation, revocation, expiry)
 *   5  transient (peer not connected, busy, concurrency or session limit,
 *      node unreachable)         6  internal
 *   130 interrupted by SIGINT, SIGTERM or SIGHUP while attached
 */

#ifndef ZCL_TOOLS_COMMAND_MESH_TERMINAL_ATTACH_H
#define ZCL_TOOLS_COMMAND_MESH_TERMINAL_ATTACH_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* One JSON-RPC call to the local node: params is a JSON array holding one
 * object. Returns a heap string the caller frees, or NULL when the node did
 * not answer. */
typedef char *(*mesh_terminal_attach_rpc_fn)(void *ctx, const char *method,
                                             const char *params);

/* The caller's terminal. read_input waits at most timeout_ms: it returns
 * the byte count, 0 on timeout, or a negative value at end of input. */
struct mesh_terminal_attach_tty {
    void *ctx;
    long (*read_input)(void *ctx, uint8_t *buf, size_t cap, int timeout_ms);
    bool (*write_output)(void *ctx, const uint8_t *buf, size_t len);
    bool (*window)(void *ctx, uint16_t *cols, uint16_t *rows);
    bool (*take_resize)(void *ctx);
    bool (*stop_requested)(void *ctx);
    void (*raw)(void *ctx, bool on);
    void (*pause_ms)(void *ctx, int ms);
    int64_t (*now_ms)(void *ctx);
    void (*diagnostic)(void *ctx, const char *line);
};

struct mesh_terminal_attach_config {
    const char *pairing_id; /* 64 lowercase hex */
    bool interactive;       /* tty mode: raw input, resize, detach escape */
};

/* Runs one attached session to its end and returns the process exit code.
 * Remote output goes only to write_output; every diagnostic goes to
 * diagnostic. Raw mode is on only while the loop runs. */
int mesh_terminal_attach_run(const struct mesh_terminal_attach_config *config,
                             mesh_terminal_attach_rpc_fn rpc, void *rpc_ctx,
                             const struct mesh_terminal_attach_tty *tty);

#endif /* ZCL_TOOLS_COMMAND_MESH_TERMINAL_ATTACH_H */
