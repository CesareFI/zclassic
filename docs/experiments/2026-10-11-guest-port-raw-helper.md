<!-- Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0 -->
# Guest held-port raw helper

Native assignment 8580 owns the standalone `tools/guest_port.c` helper and its
isolated PTY fixture. Invoke `guest-port T_PATH P_PATH` with caller-selected
named tty paths; no device enumeration or role index is assumed. Both ports
are opened once, configured and read back as raw with echo disabled before
forwarding. The helper retains those descriptors throughout the session.

The serialized successor also accepts `guest-port PORT_PATH`. This mode opens
one raw port once and retains that same descriptor for both directions, then
closes it once. After raw readback, stream setup and signal setup succeed, it
emits `guest-port: RAW_READY` on stderr before forwarding. Failure to report
readiness refuses forwarding. The caller must keep stderr separate from the
payload and consume readiness before sending input. The two-path mode keeps
its existing silent setup.

Input bytes flow to T; P bytes flow to output. Each direction has a fixed
4096-byte buffer. Input EOF drains pending input without closing either port;
P EOF drains pending output and succeeds only when no buffered T bytes remain;
otherwise it reports `T_TRUNCATED`. A write failure retains the named
`T_WRITE_REFUSED` error; this error does not promise to drain received output.
The caller owns idle T closure/session-loss observation; the helper observes T
write failures when input is pending. There is no frame parser,
half-close, key generation, or sshd launch. Setup failures
produce named refusals on stderr and no forwarded bytes. The caller must own
stdin/stdout exclusively because their nonblocking flags are temporarily set.
TTY raw mode intentionally remains set after the session.

Qualify with `devbuild --wait make -j2 test-guest-port`. The native
PTY fixture observes raw mode, exercises every byte in both directions,
replaces a path alias to establish descriptor retention, and proves P output
continues after input EOF until host port closure. This is host PTY evidence,
not FreeBSD guest execution or an authenticated guest-to-Linux route. The extended fixture stops each consumer while a 128 KiB producer is blocked, then verifies the exact resumed bytes in each direction. A regular file supplied as P produces a named refusal and no T or stdout bytes. Actual FreeBSD image qualification remains unverified.

The successor fixture runs both the executable and a source-inclusion observer
that performs real native I/O. It checks single-port byte preservation,
backpressure, alias retention, readiness before traffic, readiness failure
without forwarding, and one open/close. A blocked stdout plus observed port read
establishes buffered receive data before hangup and verifies its exact drain.

No production keys, wallet state, node services, or real sshd are involved.

## Inert disposable SSH fixture launcher

`tools/guest_ssh_fixture.c` composes the same private raw-port setup from
`tools/guest_port.h`. It takes no arguments. It opens the fixed P device once,
relocates a descriptor below 3 with `F_DUPFD_CLOEXEC`, clears and reads back
nonblocking status, maps the held descriptor onto stdin/stdout, and closes the
held original before fixed `execve`. A relocated descriptor has two ownership
transitions and two closes; the ordinary case has one. Closed, read-only or
close-on-exec stderr refuses before opening P. Setup failure never launches SSH.

The executable and configuration paths are fixed to `/usr/bin/ssh` and
`/usr/local/etc/z23-fixture/ssh_config`. The destination is the fixed
`z23-fixture` alias and the remote command is `/bin/cat`. The command line pins
the known-hosts file, requires strict host verification, disables agent,
password and interactive authentication, forwarding, multiplexing and local
commands, and requests only `mlkem768x25519-sha256` key exchange. Its fixed
ProxyCommand runs `/usr/local/libexec/z23-guest-port /dev/vtcon/z23.l0.t`.
P carries application bytes; T carries SSH ciphertext. The explicit environment
contains only `LANG=C` and `LC_ALL=C`.

The isolated fixture owner must supply and verify immutable configuration and
local identity inputs before launching: exact target/user, fixture-only
IdentityFile, approved pinned classical host-key algorithm, and known-hosts
bytes. Configuration must contain no Include, Match exec, alternate proxy,
local command or ambient identity extensions. The launcher is not a config
parser or file-integrity verifier. The caller must provide a distinct writable
diagnostic stderr and only stdio or close-on-exec additional descriptors; this
helper does not implement an inherited-descriptor sandbox. Generate disposable
fixture identities only after initialized guest entropy and never publish key
bytes in logs, receipts, source or CAS. Hybrid key exchange is not a claim of
post-quantum host authentication.

Qualify native setup with
`devbuild --wait make -j2 test-guest-ssh-fixture`. The Make target
compiles the real launcher but executes only the source-inclusion observer.
The observer uses real PTYs, descriptor duplication and all 256 byte values;
it substitutes the final exec call. Cases cover closed stdin/stdout, alias
replacement after open, raw-mode readback, blocking stdio, fixed argv/environment,
descriptor closes, and injected relocation, flag, dup2, console and exec failures.
Removing the console close-on-exec refusal must fail its no-exec witness.

These cases do not qualify actual SSH, FreeBSD execution, host-key pinning,
negotiated KEX or tunnel recovery. Those require the actual guest and consenting
native peer, wrong-pin/downgrade refusal, exact bidirectional bytes and bounded
reconnect. First qualify T and P independently through helper readiness and
byte counters. Quiesce the previous SSH/P owner before changing peer generation
or pin. The fixed cat command is a streaming witness terminated by the fixture
owner; no half-close or bounded remote EOF completion is claimed.

The relay validates that stdin is readable and stdout is writable before any
port open. Otherwise a closed standard descriptor could be reused by the port
and mistaken for a valid payload stream. Real exec-child regressions close each
of stdin and stdout in both single-port and legacy two-port modes. They require
`STREAM_SETUP_REFUSED`, empty output, no port traffic, and a PTY that has not
entered raw mode. The original helper times out in this regression; the correction refuses
before port setup. This is native descriptor evidence, not guest SSH acceptance.

Raw setup also clears `IMAXBEL` and, where defined, `PENDIN`, and refuses a
readback that retains either flag. FreeBSD requires `PENDIN` visibility at
compile time. The
relay fixture explicitly seeds and verifies this flag on the cooked PTY before
launch, then requires it absent at readiness. A separate flag-predicate witness
rejects otherwise valid raw configurations containing only `IMAXBEL` or,
where defined, only `PENDIN`; the PTY baseline also seeds and verifies `PENDIN`.
The original setup fails the seeded readiness check. Darwin translation units
enable the native terminal extensions so this flag is visible alongside the
POSIX interfaces; FreeBSD uses its default feature environment to expose its
native terminal flags. These checks establish flag handling only: guest driver
overflow handling and the actual 4097-byte burst still need guest acceptance.
