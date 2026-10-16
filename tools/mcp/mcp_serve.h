/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * `z23 mcp serve`: the local stdio MCP adapter. */

#ifndef ZCL_TOOLS_MCP_SERVE_H
#define ZCL_TOOLS_MCP_SERVE_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* argv is the full process argv; argv[1] is "mcp" and argv[2] "serve".
 * Reads newline-delimited JSON-RPC from stdin and writes replies to stdout
 * until EOF; logs go to stderr. Requires --checkout=<git toplevel>; optional
 * --datadir=<dir> and --rpcport=<n> aim node-backed leaves. Returns 0 on EOF,
 * 2 for a refused start (a typed JSON error is printed on stderr). */
int zcl_mcp_serve_main(int argc, char **argv);

/* True when argv selects `mcp serve` (argv[1] == "mcp"). */
bool zcl_mcp_serve_selected(int argc, char **argv);

#ifdef __cplusplus
}
#endif

#endif
