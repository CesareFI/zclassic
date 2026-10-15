<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Gateway directed-mail acceptance

Base: `890771c49a40a51ebe3ebd116d1176db91130b44`.
Observed on 2026-10-15 in isolated HTTP fixtures on a maintainer x86-64 host.

The gateway exposes `fleet.steer.mailbox` as its eighth tool,
`steer_mailbox`. It reuses credential forwarding and native recipient
binding. The schema requires `to`, accepts the native cursor as `since`,
and advertises read-only semantics. Native typed refusals and truncation
markers pass through unchanged.

## Witnesses

Test-only source against the previous gateway produced runtime RED:

- The actual tools/list response failed the eight-tool assertion.
- A bearer-only mailbox request failed the successful-tool-response assertion.
- The focused shard exited 2.

An initial test compile failed because the new test lacked its failure label;
that is not behavioral RED. After implementation, a diagnostic run exposed an
invalid empty first-page `since` in the fixture. The fixture now omits it,
as required by the native input contract; no server assertion was weakened.

The focused HTTP tests verify bearer-only own-label access, three pages with
exact expected references and increasing sequence values, an empty terminal
page with a stable cursor, exclusion of foreign mail, and the exact 480-byte
body/700-byte original-length truncation markers. A foreign-label request
returns `STEER_MAILBOX_FOREIGN` and echoes neither bearer nor selectors.
The handshake checks all eight tools and the required recipient schema.

Reproduce through the installed admission rail:

```sh
env VENDOR_CC=gcc devbuild --wait make t-fast-exact ONLY=fleet_gateway,fleet_gateway_shard_01,fleet_gateway_shard_02
env VENDOR_CC=gcc devbuild --wait make lint-land
```

Retain logs under `build/scratch/gateway-mailbox`. `red-runtime.log`
is the behavioral RED; `diagnostic.log` records the corrected fixture input.
The final focused and lint verdicts are recorded in the candidate handoff.

These fixtures do not establish deployment, hosted connector metadata refresh,
or qualification of an independently rebuilt gateway/node pair. Those remain
separate acceptance steps.
