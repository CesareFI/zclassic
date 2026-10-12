<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Owner-supplied receipt attempt correlation

## Contract

The standalone engine runner accepts optional `--attempt-id` correlation.
A supplied identifier must contain exactly 64 lowercase hexadecimal bytes.
An absent identifier serializes as JSON null. The identifier is allocated by
the caller's existing owner; the runner neither allocates it nor establishes
its authority, uniqueness or complete task-cost attribution.

The additive `attempt_id` field preserves the historical v1 `unit_id`
derivation. Same-second task/engine dispatches can retain identical legacy
unit IDs while carrying different supplied attempt bindings. Ordinary receipt
chain verification continues to cover the serialized records.

Both receipt sizing and append reject malformed supplied identifiers.
The executable checks the option before probe or provider effects, including
the probe path that does not perform receipt-capacity admission.

## Qualification

Source base: `de584186e9a6043b193cf5869592b11e9b1cad91`.
The isolated Linux development lane used GCC 14.2.0 on an AMD Ryzen 9 7950X3D;
environment identity was observed at 2026-10-08T23:11:38Z.
The canonical host-admitted command was
`devbuild --wait make -j28 t-fast-exact ONLY=engine`.

The fixed candidate passed with one executed group, zero failed groups and
zero skips (7532 ms test body). Bypassing the executable's attempt-ID guard
at argument parsing produced ten assertion failures and make exit 2
(6699 ms test body).
Reversing that mutation restored the exact source hash; the same registered
group passed again with zero failures and zero skips (5331 ms test body).
The fixture exercises malformed IDs through normal and probe invocation,
requires zero fake-executor calls on refusal, and checks exact successful
binding propagation. No paid provider was invoked by these fixtures.

Restored executable-source SHA-256:
`2987e2b75a09aa8284e2ef33a902145eedccdc98e38ef4652fb5b25d8a0ef7d1`.
Receipt implementation SHA-256:
`75368ae7b6c29b27033110d1b9a1c1ce9601a3902cdf57d4034f7bae20f8c195`.
Fixture SHA-256:
`0d4aac10c9f5dec38ab01b411ba73b0c81cc011d959bf550a0b606b245a7eeef`.

The original candidate exceeded the existing complexity ratchet. Splitting
the fixtures and moving option validation into argument parsing preserved
the assertions and passed `make check-cyclomatic-complexity` without changing
its baseline or cap. The results above apply to this repaired candidate,
not to the earlier candidate's separate fixed/mutated/restored sequence.
Generated capability inventory was refreshed and `make -j28 lint-fast`
passed on the same host. These are focused development checks; publication
still requires the existing exact commit/base proof gate.

The fixed, mutated and restored logs are retained in the candidate handoff as
`repaired-fixed.log`, `repaired-mutation.log` and `repaired-restored.log`.
Independent source review
accepted the four-file code candidate. These focused results do not qualify
funding, lease ownership, cross-host runtime behavior, full workflow accounting
or publication of a subsequent integration pair.
