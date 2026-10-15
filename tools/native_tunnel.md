# Optional native HOST tunnel

This is a foreground Linux program using the same qualified runtime entry as
Z23. It does not boot a node, create a secret/profile/grant, launch a shell,
select an automatic backup, or install/start a service.

Run `tunnel client --input='<object>'` or `tunnel receiver --input='<object>'`.
The object has the exact fields listed by Z23 `discover schema
ops.mesh.device.host.client` or `.receiver`, with every runtime field supplied.
Only one object, at most4096 bytes, is accepted. Duplicate/unknown keys,
NUL escapes, trailing text, invalid types and out-of-range values refuse.
Public key/root/route fields identify an already owner-approved backend2 grant;
no private key or pairwise secret belongs in argv or JSON. The existing trusted
owner-private profile and explicit exact current grant remain prerequisites.
Stdout is raw stream data; status and errors use independent stderr.

The client supports pipe/socket stdio such as an OpenSSH ProxyCommand. Signal
and descriptor flags are restored by the shared entry; the caller retains the
exclusive signal/stdio and trusted ancestor/profile binding obligations. An
Established client SIGHUP requests ordinary EOF/authenticated FIN drain within
a nonrefreshable one-second bound capped by existing admitted deadlines.
Pre-handshake client HUP and receiver HUP cancel; INT/TERM remain hard
cancellation. Grace never invents FIN: raw carrier EOF remains truncation.

Export with `make export-native-tunnel TUNNEL_EXPORT_DIR=/absolute/new/path`.
The owning C23 helper binds its compiled allowlist to the descriptor SHA256
and refuses a stale build before creating output. It uses retained handles,
bounded copied-byte hashes and final source/output namespace checks.
The destination must be absent beneath trusted ancestors. The exact allowlist
copies canonical bytes, namespaces and per-file licenses; `SOURCE.sha256` and
`PROVENANCE.txt` identify the snapshot. An interrupted export preserves partial
files for inspection. After marker removal a failure reports completion
unconfirmed; the marker may already be absent. Absence alone proves neither
durability nor package acceptance. No keys, binaries, caches or fixture profiles
are exported. Common C sources are under src/, headers under include/, and only
app/tunnel.c contains main. Metadata declares this program for the existing
Commons prepare/build/verification lifecycle; export is not publication or
execution authority.

Licenses are per-file Apache-2.0 and MIT; retain LICENSE, COPYING and licenses/.
The copied SQLite declaration header retains its public-domain blessing; no
SQLite implementation or SQL library is linked.
Package metadata declares the project assembly's Apache-2.0 license, matching
root LICENSE and the frozen v1 vocabulary. Per-file notices retain precedence;
this does not relicense MIT files or public-domain declarations.
Hash-PSK traffic uses the fixed SHAKE256-Wrap backend2 profile. X25519 code is
linked for existing identity-label/private-public consistency; the existing
v2 identity loader is also present, but this entry never calls creation or that
legacy loader. No lattice or Noise-handshake object is linked. This is not a
whole-binary hash-only cryptography claim, forward secrecy or a formal proof.

Canonical recipe linking currently produces a dynamically linked executable;
sealing its top-level image alone does not verify loader/shared-library bytes.
Static/static-PIE local qualification, accepted package install/reproduction,
loader/runtime policy, receiver launch authority and live fleet lifecycle are
separate acceptance steps. This export changes none of those authorities.
