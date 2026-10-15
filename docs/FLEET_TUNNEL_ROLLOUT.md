<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Fleet HOST tunnel rollout

Status: preparation; no host is approved for deployment by this document.
Source under qualification: `74bdde92b7926fab5cee262212c23464750396db`.
Run one host at a time after an explicit owner GO naming that host, source,
image hash, peer, permitted target and lifetime. Keep the existing pinned
SSH route available for rollback. Do not change a canonical node or firewall.

The outer transport is backend 2 SHAKE256-Wrap with a static pairwise PSK.
It has no forward secrecy. Inner OpenSSH must negotiate hybrid PQ KEX and
verify the existing pinned server identity. Ed25519 host authentication is
classical. This combination does not claim post-quantum host signatures.
See [the forward-secrecy design](TUNNEL_PQ_FORWARD_SECRECY.md).

## Host readiness and order

Read-only probes on 2026-10-15 observed:

| Host alias | System | SSH hybrid KEX | HOST rollout |
| --- | --- | --- | --- |
| z23-r1 | Linux x86_64, OpenSSH 9.6p1 | sntrup761x25519-sha512@openssh.com | First client (port 28022 receiver unit on z23-r2) |
| z23-r2 | Linux x86_64, OpenSSH 9.6p1 | same | Persistent hub receiver (one supervised user unit per client) |
| z23-r3 | Linux x86_64, OpenSSH 9.6p1 | same | Second client (port 28023) after r1 acceptance |
| z23-r4 | Linux x86_64, OpenSSH 9.6p1 | same | After r3 acceptance |
| z23-mac | Darwin arm64, OpenSSH 10.0p2 | sntrup and mlkem768x25519-sha256 | Blocked pending native HOST qualification |

Each host uses the commands below with its own owner-approved public input
files. Inputs must identify exact profiles, keys, grant roots, literal route
addresses, ports and image hashes. Those values are not yet a deployment
packet. Do not substitute remembered endpoints or guessed roots.
Mac SSH capability does not qualify the Linux-only HOST entry or package
runner. Astra confirmed this gap in board evidence seq 21287: Darwin strict
descendant cleanup is not qualified; observing a direct child exit does not
prove escaped descendants are gone. Platform RNG and pipe changes alone do
not close this gap. No Linux binary installation on Mac.

Previous retained R1-to-R2 evidence includes ten alternating measurements,
but package client shutdown reported signal_queue_failed in seven of twelve
sessions. Both old grants are revoked. A new package-client rollout requires
the reviewed wrapper fix and fresh acceptance; do not reuse those profiles.
See [retained evidence](experiments/GATEWAY_REPRODUCTION_2026-10-15.md).

## Retained qualification

Run two fresh trains sequentially under admission, at the same exact SHA:

```sh
env VENDOR_CC=gcc DEVBUILD_KEEP_SCRATCH=1 devbuild --wait \
  bash tools/scripts/qualify_fleet_gateway_front.sh \
  --sha "$SOURCE_SHA" --train "$TRAIN_A" --keep-worktree
env VENDOR_CC=gcc DEVBUILD_KEEP_SCRATCH=1 devbuild --wait \
  bash tools/scripts/qualify_fleet_gateway_front.sh \
  --sha "$SOURCE_SHA" --train "$TRAIN_B" --keep-worktree
```

Retain raw stdout/stderr and exit status without a status-masking pipe.
Keep all three images, their SHA256 values, exact source, compiler/version,
vendor pins and provenance. Compare the node images; if unequal, inspect
ELF sections, build ID, debuglink, comments and embedded build paths before
making a reproducibility claim. A gateway qualification PASS does not prove
a two-host tunnel or authorize a rollout.

## Pairing and private PSK

Use a separate owner-private HOST profile, never the canonical node datadir.
Read an existing identity first. Create an absent profile only when the
approved rollout packet requires a new identity:

```sh
"$Z23" ops mesh device identity --directory="$PROFILE"
# New profile only:
"$Z23" ops mesh device init --directory="$NEW_PROFILE"
"$Z23" ops mesh device prepare-secret --input="$(cat prepare-secret.json)"
"$Z23" ops mesh device plan --input="$(cat grant-plan.json)"
"$Z23" ops mesh device commit --input="$(cat grant-commit.json)"
```

`prepare-secret.json` has directory, peer_key, capability="host-forward",
backend=2, destination and confirm=true. Destination is absent in an existing
owner-private directory. The output contains the public credential ID,
not the secret. Move the exact32 secret only by the already authenticated,
owner-approved private delivery route; never put its bytes or hash on the
board, wiki, argv or logs.

The plan includes directory, peer_key, capability="host-forward", backend=2,
credential_id, key_epoch, inbound_port, outbound_port, paired_at, expires_at,
and expected_root. Zero denies a direction. Reverse the directional ports
for the other endpoint. Retain each endpoint's own observed root; do not
assume the roots are identical. Commit adds fingerprint, secret_file and
the independently confirmed_proposal_root. Use expected_root="absent" only
for an absent grant; upgrades use the exact inspected prior root.
Reconcile any uncertain mutation before retrying. Revocation is sticky.

## Install and run after the host's GO

Use an immutable, owner-selected release directory and verified image.
Do not overwrite a running binary or change a global symlink:

```sh
test ! -e "$RELEASE_DIR" &&
  install -d -m 700 "$RELEASE_DIR" &&
  install -m 700 "$QUALIFIED_Z23" "$RELEASE_DIR/z23"
printf '%s  %s\n' "$Z23_SHA256" "$RELEASE_DIR/z23" | sha256sum -c -
Z23="$RELEASE_DIR/z23"
"$Z23" ops mesh device host receiver \
  --input="$(cat receiver.json)" >receiver.stdout 2>receiver.stderr &
RECEIVER_PID=$!
```

Receiver input is exactly:
directory, peer_key, expected_root, target_port, route_id, listen_address,
listen_port, allow_external, lifetime_ms, handshake_ms, session_ms, idle_ms,
max_active, max_sessions, confirm.
Use confirm=true, max_active=1, max_sessions=32, lifetime_ms=600000,
handshake_ms=10000, session_ms=60000 and idle_ms=30000 for the bounded trial.
A nonloopback listener requires explicit allow_external=true.
The target is loopback and must be the approved SSH service; access remains
limited by its existing account/key policy. No automatic service is installed.

On the paired client, `client.json` has directory, peer_key, expected_root,
target_port, route_id, route_address, route_port, connect_ms=10000,
handshake_ms=10000, session_ms=60000, idle_ms=30000 and confirm=true.
Use the literal approved IPv4 route. A shell variable below contains only
the nonsecret JSON; the binary/profile paths must have no shell metacharacters.

```sh
CLIENT_JSON=$(cat client.json)
ssh -vv -o BatchMode=yes -o StrictHostKeyChecking=yes \
  -o ControlMaster=no -o ControlPath=none \
  -o KexAlgorithms=sntrup761x25519-sha512@openssh.com \
  -o "ProxyCommand=$Z23 ops mesh device host client --input='$CLIENT_JSON'" \
  "$PINNED_PEER_ALIAS" "$PERMITTED_COMMAND" \
  >verify.stdout 2>verify.stderr
```

Use the existing alias and host-key pin; never bypass host verification.
Record exact output, exit status, negotiated KEX and both terminal tokens.
Prove a bounded permitted command and exact-object transfer in both
directions. Compare direct hybrid SSH with the tunnel for at least ten
alternating runs per arm; retain every failure and raw timing observation.

## Refusals and rollback

Run adversarial cases only in disposable paired profiles and isolated targets:

| Check | Action and required evidence |
| --- | --- |
| Wrong key | Commit an independently generated secret at one fixture endpoint with otherwise matching public binding; connection must refuse before target data is released. |
| Downgrade | Repeat verification with KexAlgorithms=curve25519-sha256 against an isolated SSH server configured to permit only hybrid KEX; require SSH negotiation refusal. A permissive production sshd is not a downgrade-refusal fixture. |
| Revoked access | Inspect with `ops mesh device revoke`, then supply the returned exact root and peer fingerprint to revoke the fixture grant. New connections must refuse; active streams must close. |
| Interrupted transport | Terminate only the recorded fixture carrier process before authenticated FIN. Require nonzero outcome and no successful complete-transfer claim; compare the retained received bytes with the source. |

Public HOST tokens are `HOST_RUNTIME_INPUT_REFUSED` (invalid input/profile),
`HOST_RUNTIME_FAILURE` (runtime failure), and
`HOST_RUNTIME_UNSUPPORTED platform=unqualified` (unqualified platform).
`HOST_RECEIVER_LISTENING` proves binding only.
`HOST_RUNTIME_TERMINAL` includes result, cleanup_complete, accepted,
completed, refused and preauth_refused. Results include eof, refused,
deadline, io_error, cancelled and unsupported. A generic refused token alone
does not distinguish wrong-key, expired or revoked authority; retain the
specific test input and observation. Raw carrier EOF without authenticated
FIN is truncation, not successful completion.

Rollback stops only the receiver started by this rollout:

```sh
kill -TERM "$RECEIVER_PID"
wait "$RECEIVER_PID"
```

Verify owned children and listener are gone. Leave retained images, receipts
and profiles intact. Use the unchanged pinned SSH route. Revoke only the
new rollout grant, with its current inspected root, if the owner requests
permanent withdrawal; do not restore an old revoked grant or restart a
canonical service.

## Publication gate

Post the exact retained source/image identities and per-host acceptance on
the board. Request GO for the next host only after the prior host's outcome
is recorded. Publish the public wiki how-to after a real host pair passes,
with commands and observed refusal meanings. Keep credentials, private
profile locators and network endpoints out of public evidence.

The public wiki page `agent-host-tunnel-howto` was published on 2026-10-15
using the independently checked earlier one-pair evidence. Revision
`f3de07fa5716d7ecfc35675f654b8ce179af6347d21bf5c75e9979604e8495d5`
was discovered and read back in 13 chunks, totaling 6,996 bytes; its SHA3-256
matched the write receipt:
`c64cee59697fd351777bbbcd9828405d5703f838a569d00acf778a3b626fdb6b`.
It records the known shutdown defect and approval boundaries. Publication
does not establish a currently approved route or authorize deployment.
