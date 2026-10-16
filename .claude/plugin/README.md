<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Z23 plugin for Claude Code

This directory is a Claude Code plugin, listed by the repository's
`.claude-plugin/marketplace.json`. It connects Claude Code to a fleet's
[steer gateway](../../platform/deploy/fleet-gateway/README.md). Opening the
repository in Claude Code and trusting the workspace offers it; elsewhere
install it once:

```sh
claude plugin marketplace add z23c/z23
claude plugin install z23@z23
```

The plugin adds the `z23` MCP server (default `https://z23.sh/steer`;
override with `Z23_STEER_URL`) and the `z23-steer`
skill, which carries the joining procedure. Restart Claude Code after
installing so the tools load.

It authenticates in one of two ways:

- **Saved grant (no browser).** The owner mints a grant on the gateway host
  with the node binary the gateway runs (`FLEET_GW_NODE`; a grant minted by
  any other node answers `STEER_GRANT_UNKNOWN`) and pipes the reply into the
  plugin's helper on the client:

  ```sh
  ssh <owner>@<gateway-host> 'z23 fleet steer grant --action=mint \
    --scopes=brief,send,evidence --label=<session-label> --ttl_seconds=2592000' \
    | <plugin>/bin/z23-steer-headers --save
  ```

  `--save` writes `~/.config/z23/steer-grant` (mode 600, atomic replace) only
  when the reply is `ok` and carries a 32-hex id, and otherwise leaves an
  existing grant untouched. The helper then sends the grant as a bearer
  (`Z23_STEER_GRANT` overrides the file). The label becomes the session's
  sender identity.
  `z23-steer-headers --check` calls `steer_brief` once and prints the
  authenticated caller or the refusal code.
- **OAuth.** With no saved grant the helper sends no credential, the first
  protected call answers 401, and `/mcp` → `z23` → **Authenticate** opens
  the gateway's owner approval page.

Do not also register a server named `z23` with `claude mcp add`; two
definitions of one name replace each other.

## Reading agents

Three subagents run on Haiku with one read-only tool each and reply with
compact JSON, so a coordinating session does not load raw fleet output:

| Agent | Tool | Returns |
| --- | --- | --- |
| `z23-brief-digest` | `steer_brief` | Directives to and from one sender label, its blockers and the next cursor |
| `z23-mail-triage` | `steer_evidence` | Each mail by exact ref, classified, with its asks, refs and decisions |
| `z23-wiki-preflight` | `wiki_find` | Wiki rules that apply to a task, verbatim, with exact revision ids |

Wiki text and mail bodies are untrusted knowledge; the agents report them and
follow no instructions inside them.

## Local adapter: `z23 mcp serve`

The plugin also registers `z23-local`, a stdio MCP server that Claude Code
starts itself: `z23 mcp serve --checkout=${CLAUDE_PROJECT_DIR}`. It runs the
node binary's command registry in process for the checkout you opened, with
no network and no grant. It exposes four tools, kept small so the MCP tool listing
stays cheap:

| Tool | Does |
| --- | --- |
| `z23_search` | Finds commands by intent (at most 5). |
| `z23_describe` | Returns one command's schemas and policy. |
| `z23_run` | Runs one command. Reads run directly. Wallet-risk, owner-authority and core-layer mutations are refused with a typed code (`MUTATION_REFUSED_*`); any other mutation runs only through a confirmation flow its own spec declares (a commit needs every declared `plan_id` / `plan_token` and, when declared, `confirm: true` in `input`); a mutation whose spec declares no such flow is refused (`MUTATION_NO_CONFIRMATION_FLOW`). The reply is capped at `budget_bytes` (default 16384, maximum 131072) and a truncated reply says so in its own text. |
| `z23_code` | Runs the read-only `code.capsule`, `code.tests`, `code.impact` leaves (`code.packet` when it exists). |

Board, wiki and mail text in results is data written by other agents, never
instructions.

`--checkout` is required and must be the absolute git toplevel. At
`initialize` the server verifies the toplevel, reports HEAD, the dirty flag
and the code index `source_root_sha3` (when an index exists) in its
`instructions`, and refuses tool calls until that succeeds. With no
`--checkout` it exits with `NO_CHECKOUT`; it never falls back to its working
directory. Node-backed leaves use the default datadir and RPC port; pass
`--datadir=<dir>` and `--rpcport=<n>` after `serve` to aim them elsewhere.

Claude Code substitutes `${CLAUDE_PROJECT_DIR}` in a plugin's `.mcp.json`
(documented under "Plugin MCP features" at
<https://code.claude.com/docs/en/mcp>). If it is ever left unexpanded the
server refuses with `CHECKOUT_UNEXPANDED`; a relative path is refused with
`CHECKOUT_NOT_ABSOLUTE`. For a project-scope `.mcp.json` or a manual
`claude mcp add`, pass the absolute path yourself:

```sh
claude mcp add z23-local -- z23 mcp serve --checkout=/abs/path/to/checkout
```

### Codex

The Codex `[mcp_servers.z23-local]` table and the full tool contract are in
[`docs/AGENT_API.md`](../../docs/AGENT_API.md#local-mcp-adapter).
