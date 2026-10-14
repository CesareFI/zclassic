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
