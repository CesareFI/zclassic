<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Fleet roles

Which key may call which fleet leaf, decided by this node alone.

Every fleet leaf that acts on a signed request — a board post, an
experiment row, a row a peer replicates in — already checks that request's
signature, and a board post's SCOPE. Neither of those says which LEAVES a
key may reach. This is that missing map, and it is local: **there is no
central referee**. What this node trusts is this node's own decision,
recorded in this node's own signed store, never a fact carried in from a
peer.

## What is enforced today

Ledger replication and fleet/legacy board ingress check this store before
they keep foreign-signed bytes: `zcl_fleet_ledger_replicate()`
(engine/modules/fleetledger/src/fleet_ledger.c) and
`db_fleet_board_post_ingest()` (engine/models/src/fleet_board_post.c). Public
board posts need no role grant and still undergo ordinary admission checks.
A missing checker refuses role-gated ingress. See **Enforcement** at the end
of this page for the leaves, kinds, refusal counters and bootstrap limits.

Local operator CLI calls run without a role lookup. The paired board
stream additionally checks the peer's grant for `fleet.board.list` before
serving fleet-private rows.

## The roles

Declared once, in `engine/composition/roles.def`, as a closed set:

| role       | may do |
|------------|--------|
| `operator` | everything on this node. This node's own key, **implicit** — it is never stored anywhere, and unsigned local CLI use by this node's operator is unaffected by anything below. |
| `worker`   | post fleet-private board rows of kind `note`, `result`, `claim`, `problem` or `need`; the catalog also names `chat`, which the board codec does not accept; replicate its own ledger rows into this box; write experiment `predict`/`result` rows; read the catalogued board, wiki and ledger status leaves. |
| `observer` | read-only leaves. |
| `landing`  | the landing machine's key: post board `result` rows about trains, read the ledger. |

Each role's exact grants — which `fleet.<a>.<b>` leaf (an exact name, or a
`prefix.*` wildcard) and, for a board post, which kinds — are the
`Z23_ROLE_GRANT` rows in the same file. Role-gated ingress refuses a foreign
key with no active matching grant; a missing checker also refuses it. Public
board posts are the grant-free exception.

## The store

`tools/dev/fleet_roles.h` / `fleet_roles_store.c` hold one signed chainlog
per node, at `<datadir>/fleet_roles/roles.chain`. A row grants or revokes
one role to one key's SHA3-256 fingerprint, signed by **this node's own
operator key** — a grant is always this node's own decision, never a
statement accepted from elsewhere. Nothing is ever deleted: a revoke is its
own row, and the newest row for a (fingerprint, role) pair wins on the next
check.

## The leaves

```
z23 fleet roles list                                   # up to 96 current fingerprint/role entries, including revokes
z23 fleet roles grant  --fp=<64-hex> --role=worker      # sign a grant row
z23 fleet roles revoke --fp=<64-hex> --role=worker      # sign a revoke row
z23 fleet roles check  --fp=<64-hex> --leaf=fleet.board.post --kind=result
```

`check` reports `allowed` and, on a refusal, the exact typed reason a caller
would have seen, e.g.:

```
REFUSED role: key ab3f9c12 has no role granting fleet.board.post kind=result
```

`roles check` recognises the implicit operator fingerprint only when the
online key matches this node's filed delegation. Ingress separately
recognises the node's loaded online key.

## What this is not

It is not consensus and it grants no authority beyond this one node: a
grant row here changes what THIS box will accept from that key, and
nothing else. A different box makes its own decision about the same key,
independently, from its own store. See `docs/FLEET_LEDGER.md` and
`docs/FLEET_BOARD.md` for the leaves this feature restricts.

## Enforcement

A role is only a role where something asks. These two storage paths check
foreign-signed bytes, except public-scope board posts:

| ingress | leaf asked | kind asked |
|---------|------------|------------|
| `zcl_fleet_ledger_replicate()` — one batch a peer replicates into this box's copy of its chain | `fleet.ledger.replicate` | the ROW kind: `usage`, `task`, `attest`, `reward`, `vitals`, `experiment` |
| `db_fleet_board_post_ingest()` — one fleet/legacy board post | `fleet.board.post` | the POST kind: `problem`, `need`, `offer`, `claim`, `result`, `note`, `wiki`, `agents` |

`worker` is granted both, with every kind on the ledger side and its
declared list of post kinds on the board side. `observer` is granted
neither: reading is not writing. `landing` may post `result` and nothing
else, exactly as before.

A ledger batch is refused WHOLE — replication was already all-or-nothing,
and one ungranted row does not get to carry the rest of the batch in with
it. The refusal is `ledger_role_refused`, counted in `fleet ledger status`
as `role_refused`. Role-refused board posts are never stored; `fleet board
status`'s `role_refused` counts ordinary P2P POST refusals, while paired-pull
role failures enter the retryable deferred path. Refusal logs name the
fingerprint, leaf and kind, but do not print the row payload or post body.

**There is no default-permit path for role-gated ingress.** The engine asks through a seam
(`platform/modules/util/include/util/fleet_role_check.h`) that the top of
the tree fills in at node start, because the catalog and the store live in
`tools/dev` and nothing under `engine/` may include a `tools/` header. When
NOTHING is installed to answer — a process that has not reached that wiring,
or one that never runs it — role-gated ingress REFUSES and says so once. A
gate that is only closed when somebody remembered to close it is not a gate.

### Bootstrap

Enforcement must not stop a fleet that was replicating happily the day
before, and it must not need the operator to grant anything by hand. Three
paths mint the role that a decision already made implies. All three are
idempotent, so every one of them is safe to run at every boot.

* **What this node already accepted.** At node start, bounded walks collect
  signer keys from stored foreign ledger chains and stored board posts. Each
  collected key is granted `worker` if it lacks an active worker grant, even
  after a revoke.
  This bootstrap grants worker to stored signers, including authors of
  grant-free public posts; accepting a public post did not itself require
  that fleet-private authority.
  A key not collected by these stored-history walks gets no grant from them,
  but may still post publicly. Newly granted keys are logged by fingerprint.
* **What enrolment says.** `z23 fleet join` names, in its receipt, the key
  the box will actually SIGN with — its node's online key — and signs the
  receipt with that key too, so naming it proves possession of it. `z23
  fleet admit` grants `worker` to that key AND to the box key, and says in
  its reply whether each grant landed.
* **The roster.** At every node start, every key in the machine roster that
  lacks an active worker grant is granted `worker` — both the box key and, when the
  receipt named one, the signing key.

The two boot walks are bounded — 64 signer keys and 64 reads per chain
on the ledger side, 64 distinct posting keys on the board side. A fleet
that exceeds a bound does not get a silent prefix: the walk logs one
WARN naming the count and the bound, and counts it as
`grandfather_truncated` in `fleet ledger status` and `fleet board
status`. Above zero there, a refusal may be a key nobody looked at
rather than a decision anybody made, and `z23 fleet roles grant` names
the rest.

A box that has never started a node has no signing key yet, so its receipt
names none and `fleet admit` says so. Running `z23 fleet join` again after
that box's first node start produces a receipt that does name it; admitting
that receipt grants it. Until then the box's rows are refused, and the count
in `fleet ledger status` / `fleet board status` says how many.

**On a node with no filed delegation**, grant minting refuses because the
operator identity cannot be established. Role-gated ingress still checks existing active grants;
public board posts need none. The node's loaded online key remains implicit
operator, recognised by identity rather than a stored grant.

**A roster key is not a host key.** The roster records the box key from
`fleet join` (`box.ed25519` under the state root); a node signs board posts
and ledger rows with its DHT ONLINE key, in its datadir. They are two
different keys on purpose, which is why the receipt now carries both and why
the first two paths above exist: nothing on an upgraded fleet has to be
granted by hand.
