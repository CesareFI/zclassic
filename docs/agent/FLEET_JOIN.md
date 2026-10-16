<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Joining a computer to a fleet

This is the page an owner points an AI agent at when they want a new
computer added to their fleet. It contains no hostnames, no addresses and
no ports: everything specific to a particular fleet arrives in the token
the owner pastes.

## Check your setup

Not sure where this computer is in the setup? Run `z23 fleet doctor --datadir=<node-datadir>`. It
reads only (it changes nothing and prints public fingerprints, never keys)
and lists eight checks in order: node, identity, membership, delegation,
transport, pairing, mail, wiki. Each is `ok`, `missing`, `blocked` or
`unknown`, with one sentence and the command to run next; the top-level
`next` is the first one to run. The mail check is marked `informational`
and never changes either.

## What you are doing

A fleet is a set of computers one owner runs. Joining one adds a **machine
record**: a signed statement that this owner admitted this computer under a
name they chose. It is an inventory entry, not a permission. It grants no
shell, no remote execution, and no authority over anything.

There are two pasted strings and three commands.

| Step | Where | Command |
|---|---|---|
| 1 | The manager computer | `z23 fleet invite --name=<name>` |
| 2 | The new computer | `z23 fleet join <token>` |
| 3 | The manager computer | `z23 fleet admit <receipt>` |

Step 1 prints step 2's command. Step 2 prints step 3's command. The owner
carries each line between the two machines by hand — nothing is sent over a
network, so no port has to be open and neither machine has to be reachable
from the other.

## The name

Every machine has one **required, unique, human name**, chosen by the owner
at step 1. It is 2 to 24 characters of `a-z`, `0-9` and interior dashes:
`studio`, `node-4`, `workshop`. It is the handle every command prints first
and every refusal names, because it is how people talk about a computer.

A machine's onion address, Noise fingerprint and ZID are a different kind
of thing. They are observed, they can rotate, and none of them is ever used
as the name. See "The onion column" below for the one of those the record
carries today.

Renaming is not supported. The name is bound inside the signature the new
computer makes over its own enrolment receipt, so nobody — including the
owner — can rewrite it in place. Pick a name you will still want later.

## Prerequisites on the new computer

You need a C23 toolchain, `git`, and enough disk for a build.

**Linux.** A recent gcc or clang, `make`, and the usual build headers.

**macOS.** Xcode command line tools (`xcode-select --install`).

**Windows.** The Windows path is the **native MSYS2 UCRT64 build** — install
MSYS2, open the UCRT64 shell, and follow `docs/WINDOWS.md`. Enrolment is
native Windows code: it reads the computer's own facts through the Win32
calls and writes its key under the Windows state root, with no Linux layer
underneath.

The mesh terminal worker has a Windows arm (ConPTY, with the shell's process
tree held in a kill-on-close Job Object), described in
`docs/WINDOWS.md`. The terminal lane is refused on Windows by default,
because the shell has no confined identity there: a Windows machine enrols,
appears in `fleet machines` and holds a name like any other, and answers
terminal opens with `CONFINEMENT_UNAVAILABLE`. The owner can start the node
with `-terminalacceptunconfined` to turn the lane on anyway: the remote shell
then runs as your Windows user with all its rights, and only peers you paired
with the terminal capability can open it. A paired machine connects with
`z23 ops mesh terminal --pairing_id=<64hex>`. A
restricted-identity launch remains the intended follow-up. Without the flag this
is a missing capability on a real member, not a reason to join from somewhere
else.

## What the AI agent on the new computer does

```sh
git clone https://github.com/z23c/z23.git
cd z23
make -j8 build/bin/z23-dev
build/bin/z23-dev fleet join <token>          # add --onion=<v3>.onion if this box has one
```

Then hand the printed `z23 fleet admit …` line back to the owner.

## What is in each string

**The invite token** carries the name, an expiry, a one-time random nonce,
an optional relay endpoint, the operator's Ed25519 public key, and a
signature by that key over all of it. Nothing private is in it. A leaked
token can enrol one computer under that one name, once, before it expires —
and the resulting machine still has to be admitted on the manager.

**The enrolment receipt** carries the whole invite unchanged, what the new
computer says about itself, its own new Ed25519 public key, an ssh public
key if it has the dedicated one described below, and a signature by the new
computer's key over all of it. Nothing private is in it either.

Everything a computer says about itself — hostname, OS, architecture, core
count, memory, free disk, toolchain, source commit — is **self-reported**.
The computer signed it, so it is authenticated; nobody measured it, so it is
not verified. `z23 fleet machines` keeps self-reported facts in their own
object, separate from what the operator's signature actually attests (the
name, the public key, the assigned port, the time).

## The onion column

A machine may also carry an **onion** — the persistent v3 onion hostname it
says it will answer on. Pass it at step 2:

```sh
z23 fleet join <token> --onion=<56-characters>.onion
```

It is optional. A computer with no persistent onion yet joins without one
and the column is empty.

It is **self-reported**, exactly like the hardware facts. The joining
computer signs the string, so the record proves that computer claimed that
address; nobody has dialled it, so the record proves nothing about whether
it answers. `fleet machines` prints it in the `self_reported` object beside
the hostname, never in the `verified` object beside the name. A later change
that actually dials the address and gets the machine's key back is what
would move it.

It is a column, not a handle. Two machines that rotate their onions are
still the same two names, and a refusal still says the name.

The grammar is closed: 56 characters of `a-z` and `2-7`, then `.onion`, with
an optional `:port`. A v2 address, an uppercase spelling, a plain hostname
and an IP literal are all refused as `join_onion_invalid` on the computer
that typed it — where somebody can fix the typo — rather than signed into a
record nobody can use.

## The ssh bridge

If the new computer has a **dedicated** public key at
`~/.ssh/z23_fleet.pub`, `fleet admit` adds exactly one line to the
operator's `~/.ssh/authorized_keys`:

```
restrict,port-forwarding,permitlisten="127.0.0.1:<port>" <key> z23-fleet-<name>
```

`restrict` denies everything sshd knows how to deny — no shell, no command,
no agent forwarding, no X11, no pty — and denies future restrictions by
default too. The single re-grant is one loopback listen port. The line is
added once per name; re-admitting the same computer adds nothing.

Create the key with `ssh-keygen -t ed25519 -f ~/.ssh/z23_fleet` before
joining. Use a key you use for nothing else: this line narrows exactly the
key it names, and a key you also use for shell access would be narrowed
wherever sshd matched this line first. `fleet admit --bridge=no` skips the
line entirely, and a computer with no such key simply gets a machine record
and no bridge.

The bridge needs an sshd running on the computer being reached, and
`~/.ssh` must already exist on the manager. Neither is created for you: a
fleet command guessing at an owner's ssh layout is not a thing this
repository does.

## What comes next

The bridge is a bridge. The native path is mesh pairing over the node's own
Noise transport — `ops mesh pair plan` and `ops mesh pair commit` — which
needs the new computer to be running a node with an on-chain identity
delegation. `fleet join` prints that as its `next_step` rather than
pretending it already happened. See `docs/work/SOVEREIGN_MACHINE_MESH_PLAN.md`.

Once a pairing carries the terminal capability (`ops mesh pair commit` with
its `terminal` input set to true), the paired machine's confined shell is one command away:

```sh
z23 ops mesh terminal --pairing_id=<64hex>
```

The command talks to the local node's `mesh_terminal_*` RPCs over the
established Noise session; it never dials. On a terminal it puts the local tty
in raw mode, sends the window size, follows resizes, and restores the tty on
every exit path. `~.` at the start of a line detaches (`~~` sends one `~`).
When stdin is not a terminal it sends stdin, writes only remote output to
stdout, ends the input with one end-of-transmission byte (finish the last line
with a newline), and prints every diagnostic on stderr:

```sh
printf 'uname -a\nexit\n' | z23 ops mesh terminal --pairing_id=<64hex>
```

Refusals print `z23: refused: <name>: <words>` (`not-paired`,
`capability-unavailable`, `confinement-unavailable`, `concurrency-limit`: 4
terminals per node); a node that stops answering after attach prints `z23:
connection lost: ...`. A session end prints `z23: terminal closed: reason=<name>
... - <words>`: `worker-exited`, `idle-timeout` (600 s), `lifetime-limit`
(3600 s), `byte-limit` (default 1 GiB out, 16 MiB in), `session-lost` (peer
dropped), `shutdown`, `revoked`, `expired`, `peer-closed` (no close report:
the stream ended without one and prints `z23: terminal ended:
reason=peer-closed ...`, exit `5`).

The remote exit status is carried. The signed close report
(`zcl.terminal_close_evidence.v1`) holds `bytes_in`, `bytes_out`,
`duration_s`, `reason`, and for `worker-exited` exactly one optional key:
`exit_code` (0-255) when the shell exited, or `signal` (1-64) when a signal
killed it. The line then reads `reason=worker-exited exit_code=3` or
`... signal=15`. The two keys are optional additions to the same signed
capsule, which is hashed as opaque bytes: a node that predates them sends
neither (a missing status exits `0`), and an older client ignores them. Exit
codes: `0` detached or the remote shell exited 0; `N` (1-255) the remote
shell exited with status N, `128+S` when signal S killed it (SIGTERM gives
`143`), like ssh; and the local classes `2` invalid, `3` blocked, `4` denied,
`5` transient or any limit or loss, `6` internal, `130` interrupted. A remote
status that equals a local class number is told apart by the stderr line
(`reason=worker-exited exit_code=3` versus `refused:` or `reason=<limit>`).

Limits per session: 600 s idle, 3600 s lifetime, 16 MiB in, and 1 GiB out
unless the node sets `-terminalmaxbytesout=<bytes>` (1048576 to 68719476736;
anything else keeps the default). The byte budgets are a runaway backstop;
the rate is bounded separately at 16 reads of 4 KiB per 100 ms drain tick
(about 640 KiB/s ceiling, measured near 480 KiB/s end to end) and by the
64 KiB stream credit window. Memory per session does not grow with the
budget: one 4 KiB read buffer on the responder, at most 64 KiB in flight, and
one 64 KiB screen FIFO on the requester; at most 4 sessions per node.

In raw mode Ctrl-C and the other control keys go to the remote shell; only
`~.` or an external SIGINT, SIGTERM, SIGHUP or SIGQUIT ends the command, and
the local tty is then restored. Modes the remote program set by escape
sequence (alternate screen, mouse reporting, bracketed paste) are not reset;
run `reset` locally if a remote program left one on. Remote output is shown
with nothing filtered, but the command's own diagnostics replace control bytes
in node and responder text with `?`. For a Windows peer, piped input must use
CR line ends and the trailing end-of-transmission byte is not end-of-file
there; there is no option for it yet.

## Where the state lives

Under the owner-private state root, never inside a checkout:

| File | What it is |
|---|---|
| `fleet/box.ed25519` | This computer's own key, mode 0600, created on first use |
| `fleet/operator.pub` | The operator key this computer was told to trust |
| `fleet/machines.roster` | One operator-sealed line per admitted machine |
| `fleet/invites.spent` | One line per invite nonce already used |

Every roster line is re-verified against the operator key on every read. A
line that key did not seal is counted and never listed, so editing the file
by hand can remove a machine but cannot invent one.

## Typed refusals

Each of these is the exact evidence string a refusal carries.

| Refusal | Meaning |
|---|---|
| `invite_name_invalid` | The name is not 2-24 characters of `a-z`, `0-9` and interior dashes |
| `invite_ttl_invalid` | `--ttl-hours` is outside 1 to 168 |
| `invite_relay_invalid` | `--relay` has a character a host or `host:port` cannot contain |
| `invite_malformed` | The pasted token is not a token — usually a copy that lost its tail |
| `invite_signature_invalid` | The token's bytes and its signature disagree |
| `invite_expired` | The invite's expiry has passed |
| `invite_not_ours` | The invite was minted by some other key, so this manager will not honour it |
| `invite_replayed` | That invite has already enrolled a computer |
| `invite_name_taken` | Another computer already holds that name |
| `receipt_malformed` | The pasted receipt is not a receipt |
| `box_signature_invalid` | The receipt's facts and the joining computer's signature disagree |
| `box_key_unwritable` | The state root is unreachable or the key file is not this user's alone |
| `roster_full` | Every assignable relay port is taken |
| `roster_unreadable` / `roster_unwritable` | The roster could not be read or appended to |
| `join_onion_invalid` | `--onion` is not a v3 onion hostname with an optional port |
| `authorized_keys_unwritable` | `~/.ssh` does not exist, or the file cannot be written |
