<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# ZCL Wallet for Ledger Blue

The target is **one C23 ZCL Wallet app** on the dedicated Blue, controlled by
Z23's C23 host. It should handle address confirmation and supported ZCL
payments from one device interface. Probe, Fixture, Review, and Sign Test are
separate development images used to test USB, display, parsing, and key
access; they are not four apps required for a payment. A second production
app would be justified only by a measured Blue firmware or memory limit.

The host selects coins and notes, obtains consensus data from the Z23 node,
constructs transactions and Sapling proofs, and checks completed signatures.
The Blue derives authorized keys, independently checks the transaction facts
it can verify, displays the recipient, amount, network, fee, and signing
account, and signs only after the owner approves those exact facts. An opaque
digest with host-supplied display text is insufficient for payment approval.

## Agent-facing control

Z23's current safe automation sequence is device discovery, exact app identity,
offline transaction parsing, offline app-controller simulation, and an optional
read-only Blue comparison after the owner opens the Review app. JSON keeps
`app_simulated` and `blue_parsed` separate. Neither status grants payment
authority; `signing_ready` remains false. A timeout or mismatched reply ends
that attempt and requires a fresh device-state check before another command.
The agent must not infer permission to install, delete, enroll a certificate,
or sign from a successful simulation or structural review. Future payment
signing requires a purpose-built approval screen and the owner's confirmation
on the Blue for the exact transaction facts.

| Capability | Proven today | Required before payment use |
| --- | --- | --- |
| USB and app management | Authenticated CA install and app catalog on BOLOS 2.1.1; catalog parser retains manager-reported app hashes and checks record lengths; Wallet 0.3.4 was deleted after a physical freeze and its exact image is blocked | Match a corrected installed image hash to a pinned build, then repeat install, open, exit, and recovery checks |
| Screen accessibility | C23 offline screenshots, word-wrapped 22-pixel text, and light/dark controls in the uninstalled Shielded Review 0.5.11 candidate; Wallet 0.3.46 has pixel-pinned 320×480 output, fee, totals, and final signing pages with separate chain/branch warnings; Wallet 0.3.4 froze on opening and was deleted | Physical font, color, tap, page, EXIT, fee, and USB checks on a corrected image |
| Transparent addresses | Public-key fixture and fixed-message seed-derived signing test; Wallet 0.2.1 opened to a steady receive screen with working EXIT, and its 35-character address matched the host result; the app was later deleted after a review freeze | Selectable path and account, repeated receive and interruption checks |
| Transparent payments | The host preflights up to 16 hash-bound v1-v4 P2PKH inputs and compares device ZIP-243 digests. Uninstalled Wallet 0.3.46 binds previous wires to captured outpoints, calculates the fee, distinguishes its two fixed addresses, and routes ordered signing only after a separate final `SIGN ZCL` tap. A C23 host collector requests protocol-12 signatures in order, verifies each reply, and clears partial results on failure; synthetic end-to-end tests assemble a transparent v4 wire. A separate host planner classifies hash-bound inputs against both fixed device paths and rejects unknown or ambiguous hashes. The host checks a local node's UTXO view; independent peer synchronization and authenticated retrieval of both device public keys remain unchecked. Physical Wallet 0.2.1 review froze before an output was confirmed | Pass exact-image BOLOS USB, touch, signing, fee, digest, and recovery tests; qualify the existing live test CLI against a catalog-verified image, prove independent chain state, and authenticate the installed image before payment use |
| Sapling payments | Z23 has C23 ZIP32, Jubjub, note, prover, and ZIP-243 code; host and Review compute shielded digests and a synthetic mixed fixture checks output binding. Wallet 0.3.46 explicitly rejects nonzero shielded counts and has no Sapling keys or signing. Existing six-generator RedJubjub storage alone needs 768 bytes of the 1,024-byte SRAM headroom; the existing scalar multiply also needs a 2,368-byte frame against a 2,048-byte stack reservation, and `fr.c` does not compile unchanged for Cortex-M3. An isolated C23 Fr/Fs and low-memory Jubjub path passes host differential tests, a known SpendAuth `ask` to `ak` vector, three public RedJubjub signing-equation cases, and an ARM Cortex-M3 run under QEMU. C23 challenge and entropy-seeded nonce helpers match independently calculated BLAKE2b vectors on host and ARM. An isolated complete ZIP32 master derivation matches Z23's expanded-key, chain-code, and diversifier-key reference fields on host and ARM, with a 1,332-byte QEMU stack peak for that case. A separate full-viewing-key projection matches Z23's `ak`, `nk`, and parent fingerprint vector; the separate FVK QEMU case peaks at 1,500 bytes with its output in test BSS. The ARM public fixture derives nonce, encodes its own points, checks the response equation, and rejects changed response and message bytes. A host fixed public signature passes an independent group-equation check and rejects altered response, altered message, and noncanonical response. Separately measured QEMU cases peak at 1,500 bytes of the 2 KiB test stack and pass a 512-byte margin gate; they do not include BOLOS, USB, or screen frames. A Ledger-specific seed bridge, account-child derivation, and BOLOS RNG adapter pass stub and emulator checks, but recovery compatibility, target timing, side-channel behavior, and physical Blue signing remain unverified | Define a recoverable device seed and account derivation, measure full image and stack with BOLOS and screen frames, bind signing to device-verified notes, outputs, memos, and approval, then prove end-to-end test transactions |
| Sapling memos | Z23 wallet stores 512-byte decrypted note memos; isolated C23 Blue paths classify memo bytes and verify a fixture's ephemeral key and note commitment on host and ARM emulators; Review sees only encrypted transaction bytes | Combine authenticated ciphertext, device-derived viewing authority, ephemeral key, recipient, and commitment checks; then show text or explicit opaque, reserved, or invalid-data warnings before signing |
| Transparent multisig | Host recognizes P2SH scripts but cannot infer a threshold | Redeem-script and cosigner validation, device confirmation, and independently verified signatures |
| ZSLP | Host detects an output-zero marker | Token parser, input lineage and supply validation, token-aware display, and test transactions |
| Shielded multisig | No threshold signing | Verify ZCL compatibility and implement a multiple-party Sapling signing protocol with nonce safety and test vectors |
| Legacy Sprout | Structural JoinSplit count only | Determine whether current ZCL consensus permits the intended spend and whether the Blue can safely review and authorize it |

Memo reading and sending belong in the single Wallet app. For reading, Z23
must supply the encrypted transaction output and chain context; the Blue must
derive the relevant viewing authority, decrypt on device, verify the note
commitment and ephemeral key, and show amount, account, and memo pages. No
memo text is sent back over USB by default. For sending, the Blue must verify
every outgoing shielded output against the exact transaction digest before it
shows recipient, amount, and memo, then require a distinct final signing tap.
Text pages need explicit length, page position, and visible treatment of
embedded zero bytes. Opaque, invalid, and reserved memos need a warning and
a full-field digest rather than guessed text. A host-provided memo label
never becomes a device-verified fact. Isolated C23 verifiers reproduce the
fixture ephemeral key and note commitment on host and ARM. The commitment
binds value and recipient data, but not memo bytes; the authenticated note
ciphertext binds the memo. Neither check is linked into Wallet yet. The next
experiment must combine these checks with device-derived viewing authority and
bounded memo screens before enabling either memo flow.

The release sequence is: reliable catalog and review; transparent receive and
payment signing on synthetic fixtures; test-network transactions; Sapling
spends and receives; token-aware and multisig flows. Every signing path must
reject a transaction type it cannot fully review. The Blue has 6 KiB of app
SRAM, including its reserved stack, so larger transactions require bounded
streaming and measured stack use. The Wallet 0.3.45 offline candidate
uses one BLAKE2b context and a SHA-256 commitment across three identical
uploads, then reuses that SHA-256 context to verify previous wires. Its
5,120-byte `.bss` includes the 2 KiB stack reservation and leaves 1,024
bytes above the section. Wallet 0.3.4 had 5,476 bytes of `.bss`, froze on
opening, and is blocked by the installer. The 0.3.45 image has not been
installed or tested on the Blue.
The reviewer and signer build without OpenSSL or
PNG on the device; the installer and certificate tools still use OpenSSL.
The final touchscreen approval is simulated but has not been exercised on
the physical Blue. Independently verified chain state, active branch, and
complete change/account policy remain open.
The fixture-only CLI now prepares a public-key-derived one-input v4 spend
and has a bounded live review/signature route. Offline construction and
simulation pass; this CLI has not signed on the physical Blue. It has no
transaction save or broadcast path.
The C23 simulator also completes a two-input transparent review through the
external and internal paths, verifies both signatures against their distinct
public keys, and assembles the signed wire. This uses synthetic previous
transactions and generated test keys; it establishes no chain provenance.
The 0.3.45 candidate clears an unconsumed final signing approval after a
30-second SDK ticker interval in the host-side UI simulation. Its actual
timer cadence, USB reset delivery, and expired approval refusal require
physical Blue checks.
Protocol version and capability bytes are not installed-image
authentication. The authenticated BOLOS catalog hash must be checked
against the pinned image and bound to the subsequent app session before
payment signing can be considered ready.
The [Wallet 0.2.15 experiment](../../docs/experiments/2026-09-27-ledger-blue-local-sha-and-readonly-approval.md)
records the host tests, image hash, and SDK patch gate.
Device tests start on the dedicated test
Blue and use test transactions before any real ZCL.

Sapling shielded multisig is a separate research gate. [ZIP 312](https://zips.z.cash/zip-0312)
specifies a FROST variant designed to verify as ordinary RedJubjub Sapling
spend authorization signatures. Its coordinator generates the proof and can
learn private transaction details. Compatibility with ZCL's deployed
consensus, BOLOS Jubjub support, nonce storage, and the Ledger Blue's RAM and
timing remains unestablished. First create reproducible ZIP 312 vectors and
verify their signatures against ZCL consensus in C23, then measure a bounded
two-round participant prototype
on the Blue. No threshold or Sapling payment signer is ready today.

[ZIP 302](https://zips.z.cash/zip-0302) distinguishes padded UTF-8 text,
the no-memo marker, reserved encodings, and opaque binary memos within the
512-byte encrypted Sapling memo field. A receiving wallet can classify a
memo only after note decryption. An outgoing signing screen must bind the
displayed memo or explicit opaque-data digest to the transaction before the
device releases a signature; host-supplied display text alone is insufficient.
