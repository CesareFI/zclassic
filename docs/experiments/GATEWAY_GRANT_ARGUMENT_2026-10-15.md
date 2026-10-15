<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Gateway credential argument guidance

Source base: `0f9325278ade90be99ad5203ebbef865b5403996`.

The connector carries its credential through Authorization. Supplying a sender
label as the optional `grant` argument conflicts with that credential. Every
advertised tool now describes `grant` as an optional credential token and tells
the caller to omit it when Authorization supplies the credential. Initialization
instructions distinguish the secret credential from `caller.sender` and `from`.

Unequal header and argument credentials still refuse before node forwarding,
with JSON-RPC code `-32002` and the `conflicting grants` prefix. The explanation
adds `GRANT_ARGUMENT_CONFLICT` and corrective guidance. It performs no sender
lookup and echoes neither credential nor label. The opaque bearer alphabet is
unchanged.

## Reproduction and observations

Run in the assigned isolated checkout through the host admission rail:

```bash
devbuild --wait make t-fast-exact ONLY=fleet_gateway_shard_01
devbuild --wait make t-fast-exact ONLY=fleet_gateway_shard_02
devbuild --wait make t-fast-exact ONLY=fleet_gateway_shard_01,fleet_gateway_shard_02
VENDOR_CC=gcc devbuild --wait make lint-land
```

The unsharded `fleet_gateway` group checks the partition inventory. Its passing
result does not execute the HTTP handshake or authentication cases.

Retained logs are in `build/scratch/gateway-label-token/`:

- `red-shard01.log`: test-only guidance assertion failed in `gw_t_handshake`;
  exit 2. The implementation had not yet changed.
- `green-metadata-shard01.log`: handshake and remaining shard cases passed;
  exit 0.
- `red-conflict-shard02.log`: a real header credential with `grant=GW_SENDER`
  refused, but the test failed on the missing `GRANT_ARGUMENT_CONFLICT`
  explanation; exit 2.
- `green-shards.log`: both registered shards passed, two groups run, zero
  failures, zero skipped; exit 0. Authentication and OAuth cases remain covered.
  The label-conflict case verifies the refusal code, explanation and absence of
  either input value in the response.

Environment: maintainer x86-64 host, AMD Ryzen 9 7950X3D, Ubuntu Clang 20.1.8. Observations
were made on 2026-10-15. These are isolated HTTP fixture results. They do not
establish production rollout, connector catalog refresh or live wiki acceptance.

Final integration lint: `VENDOR_CC=gcc devbuild --wait make lint-land` passed
all 60 gates, `lint-land: OK`, exit 0. Log: `lint-land.log` in the same
retained directory.
