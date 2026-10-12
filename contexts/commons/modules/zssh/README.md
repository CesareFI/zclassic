# zclassic23/zssh

Allocation-free, sans-IO SSH-2 engine for C23: transport (key exchange,
packet protection, rekey refusal), public-key user authentication and one
`direct-tcpip` channel, implemented in `src/` and tested by the registered
`zssh` group. The caller owns every socket, clock and random source.

It is not yet wired into a guest. Running it inside the Z23 emulator guest to
carry an outer session between two guests and forward a device port is the
intended use, but no guest integration exists, and no FreeBSD guest route or
runtime has been accepted.

| Object | Value |
| --- | --- |
| Max packet (RFC 4253 6.1) | 35000 bytes |
| Channel window / max data packet | 32768 / 16384 bytes |
| Connection storage (`struct zssh_conn`) | 163840 bytes, caller-owned |
| Host / user key | Ed25519 (`ssh-ed25519`, RFC 8709) |
| Cipher | `chacha20-poly1305@openssh.com` only |
| Key exchange | `mlkem768x25519-sha256`, `curve25519-sha256` |

## Interface

`zssh_init`, `zssh_input`, `zssh_output_peek` / `zssh_output_consume`,
`zssh_pump`, `zssh_channel_send` / `_recv` / `_send_eof` / `_close`,
`zssh_state`, `zssh_error`, `zssh_session_info_get`, `zssh_wipe`. The engine
never reads a socket, clock or random device: the caller feeds bytes, drains
bytes and supplies a `rand` callback. `zssh_input` and `zssh_pump` return
`NEED_INPUT`, `NEED_OUTPUT`, `CHANNEL_READY`, `CLOSED` or `STATUS_FAILED` with
exact consumed and produced counts. A packet that cannot be fully written stays
queued across partial output consumes; input fragmented to one byte per call
gives the same result as one call.

## Contract summary (details in `zssh.h`)

- Error model: misuse returns `ZSSH_BAD_CALL` / `ZSSH_STATUS_BAD_CALL` and
  changes nothing; protocol, crypto and RNG failure is sticky `ZSSH_FAILED`.
  Output drain (`peek`/`consume`) and all getters keep working after FAILED and
  CLOSED, so the final DISCONNECT can be sent. The per-operation terminal table
  in `zssh.h` is the rule: after CLOSED, `recv` still returns unread data (then
  EOF), `send` is EOF, `send_eof`/`close` are OK no-ops; after FAILED the
  mutators return FAILED with counts 0 and `recv` returns FAILED. `zssh_wipe`
  keeps CLOSED and any existing first error. A multi-packet `channel_send` (or
  a `channel_recv` whose WINDOW_ADJUST fails to seal: RNG or REKEY_LIMIT)
  reports the exact committed prefix and then fails the session.
- Output: packets are committed to the queue whole; the transport may take any
  prefix, the rest is retained. Status is computed after the drain.
  `zssh_input(n = 0)` resumes deferred work; it is not an EOF.
- `zssh_channel_send` reports accepted bytes (maybe 0) with OK / AGAIN / EOF /
  BAD_CALL / FAILED and never charges the window for unqueued bytes. Window,
  EOF and CLOSE state change only when the message is queued.
- A peer CHANNEL_CLOSE is answered automatically with one CLOSE; received data
  stays readable until drained.
- Strict KEX: new keys switch at the queue commit of our NEWKEYS and at the
  processing of the peer NEWKEYS, sequence numbers reset to zero there.
- The caller reports a physical transport end with `zssh_transport_eof`; it is
  never a clean close unless the state is CLOSED.
- Authentication: an unsigned probe with the one authorized key gets
  `USERAUTH_PK_OK` and stays unauthenticated; every probe counts toward the
  3-attempt limit. Only a verified signature authenticates.
- Queue arithmetic: sealed worst case 16480 bytes (reserved 16485); reply
  reserve 4 x 2085 = 8340; queue 65536 admits at least one maximal packet
  beside the reserve.
- The `device.invalid:1` label carries no authority. The caller must bind the
  authenticated peer to the real device port P. Guest-route integration is not
  part of this module and is not implemented.

## Scope

- Roles: CLIENT and SERVER, one connection per `struct zssh_conn`.
- Channel contract: RFC 4254 7.2 `direct-tcpip` to the fixed target
  `device.invalid:1` (RFC 6761 reserved name, never resolved). Chosen over a
  named subsystem because every OpenSSH client can open it (`ssh -W`), so
  interop tests need no private extension; the target carries no authority and
  the server binds the channel to port P itself. `forwarded-tcpip`, `session`,
  `exec`, `shell`, `subsystem`, `pty-req`, `env`, `x11`, global requests and a
  second channel are refused. Guest sockets do not exist; both ends are byte
  pipes owned by the caller.
- Authentication: `ssh-userauth` with `publickey` / `ssh-ed25519` (RFC 4252 7),
  signature mandatory. An unsigned probe with the authorized key is answered
  with PK_OK (60) but is never success. At most 3 publickey requests (probes
  included) are evaluated.
- Host key: pinned in the client configuration; no trust-on-first-use. There is
  no asynchronous approval API. Any future one must carry the current
  `kex_generation` and session id and reject a stale approval.
- Strict KEX is mandatory (`kex-strict-c-v00@openssh.com` /
  `kex-strict-s-v00@openssh.com`, CVE-2023-48795): first binary packet must be
  KEXINIT, no other message before NEWKEYS completes, sequence numbers reset to
  zero per direction at each NEWKEYS. A peer without the marker fails with
  `ZSSH_E_STRICT_KEX_REQUIRED`.
- Fail closed: a `rand` failure moves the session to FAILED and nothing derived
  from the failed draw is emitted. On failure, close and `zssh_wipe`, every
  secret in the struct is wiped. On a layer failure no secret is written to a
  caller buffer.
- Post-quantum policy: with `require_pq`, the KEXINIT lists only
  `mlkem768x25519-sha256`; there is no classical fallback. `zssh_session_info`
  reports the algorithm actually negotiated.

## Non-goals

No shell, no pty, no exec, no SFTP, no agent or X11 forwarding, no password or
keyboard-interactive auth, no host-based auth, no compression, no extension
negotiation (RFC 8308), no `first_kex_packet_follows` guess handling, no
`curve25519-sha256@libssh.org` alias, no ciphers other than the one above, no
more than one channel.

## Rekey limit

There is no rekey. A peer `SSH_MSG_KEXINIT` after the first NEWKEYS is refused:
the engine queues DISCONNECT (key exchange failed) and fails with
`ZSSH_E_REKEY_UNSUPPORTED`. The session also fails with `ZSSH_E_REKEY_LIMIT`
before a sequence number could wrap or 1 GiB (RFC 4253 9) have been exchanged.
A later writer adds rekey behind these two errors and increments
`kex_generation`. This is an interim limit, not acceptance for persistent
sessions: a session has a hard lifetime bound and the caller must reconnect.

## Layout

| File | Layer | Owner |
| --- | --- | --- |
| `zssh_packet.c` | wire helpers, binary packet, cipher (a) | packet writer |
| `zssh_kex.c` | KEXINIT, negotiation, KEX, H, key derivation (b) | kex writer |
| `zssh_auth.c` | host key/signature, ssh-userauth (c) | auth writer |
| `zssh_channel.c` | the single channel (d) | channel writer |
| `zssh_conn.c` | public API and state machine (e) | merge writer |

## Open protocol points

Every uncertain detail is a `TODO(verify)` in the headers. In brief: the hybrid
KEX wire format, combiner and encoding of K in H (must match openssh-portable
`kexmlkem768x25519.c`; client init is the 1184-byte ML-KEM-768 encapsulation key
followed by the 32-byte X25519 key, server reply is the 1088-byte ciphertext
followed by the 32-byte X25519 key, K = SHA-256(mlkem_ss || x25519_ss));
curve25519 encodes K as an mpint of the unreversed X25519 output and is not
interchangeable. Resolved against OpenSSH V_10_0_P2: message numbers 30/31, the
hybrid layout and string-encoded K, the chacha20-poly1305 key halves, the
64-bit sequence nonce and the alignment rule (AEAD: packet_length % 8; none:
(4 + packet_length) % 8; minimums 8 and 12). Still open: the MAC name
placeholder and an OpenSSH-captured KAT.

## Required controls

Tests the implementation must pass before the module is considered done: real
OpenSSH interop (both roles), wrong pin, wrong host signature, KEX mismatch,
pre-KEX extra packet, tag tampering and length-prefix tampering, 1-byte
fragmented I/O, blocked consumer (partial output consumes), forced rekey
refusal, exact binary transfer over the channel, RNG failure, EOF and CLOSE
half-close directions, window overrun.

## Post-quantum claims

Post-quantum claims wait for the in-tree ML-KEM correction to land. Until
then the hybrid is a negotiated option, not a security statement.

## Resources

No heap allocation and no global mutable state. Dependencies: `crypto`
(chacha20, poly1305, ed25519, x25519_safe, sha256, sha512), `mlkem`, `base`
(`memory_cleanse`, logging).

## References

RFC 4251, RFC 4252, RFC 4253, RFC 4254, RFC 6761, RFC 7748, RFC 8032, RFC 8709,
RFC 8731, OpenSSH `PROTOCOL.chacha20poly1305`, openssh-portable
`kexmlkem768x25519.c`, the OpenSSH strict-KEX extension (`PROTOCOL`,
"transport: strict key exchange extensions"), draft-ietf-sshm-mlkem-hybrid-kex,
NIST FIPS 203.
